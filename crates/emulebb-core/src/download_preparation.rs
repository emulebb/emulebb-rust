//! Bounded waiting-job discovery and availability before hydration.
use crate::{
    EmulebbCore, OwnSourceIdentity, download_attempts::DownloadAttemptGuard, drop_self_sources,
    ed2k_source_batch::DownloadSourceTarget, found_source_from_endpoint,
};
use anyhow::Result;
use emulebb_ed2k::{
    ed2k_server::Ed2kFoundSource,
    ed2k_tcp::{
        Ed2kPeerDownloadReport, Ed2kPeerProbeOptions, Ed2kPeerProbeOutcome, Ed2kPreparedPeer,
        probe_file_from_peer,
    },
};
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub(crate) struct PreparedSourceReservation {
    pub source: Ed2kFoundSource,
    pub token: emulebb_metadata::JobToken,
    pub hash: emulebb_kad_proto::Ed2kHash,
    pub lease: crate::download_source_registry::DownloadSourceLeaseId,
}

pub(crate) struct PreparedDownloadSource {
    pub reservation: PreparedSourceReservation,
    pub peer: Box<Ed2kPreparedPeer>,
    pub admission_deadline: tokio::time::Instant,
}

pub(crate) enum DownloadPreparation {
    Waiting,
    Direct(PreparedDownloadSource),
    Callback(Box<crate::download_callback::PreparedCallbackSource>),
    Finalization,
}

impl EmulebbCore {
    /// Settle only this probe's reservation. Local admission refusal does not
    /// consume the peer's reask interval, even after a successful wire probe.
    pub(crate) async fn settle_source_reservation(
        &self,
        reservation: &PreparedSourceReservation,
        deferred: bool,
        error: Option<&anyhow::Error>,
    ) {
        let local_capacity = error.is_some_and(|error| {
            matches!(
                error.downcast_ref(),
                Some(
                    emulebb_ed2k::ed2k_transfer::LocalMutationError::Busy
                        | emulebb_ed2k::ed2k_transfer::LocalMutationError::Closing
                )
            )
        });
        // WHY: refused availability persistence is our capacity problem, not a
        // failed source. Keep the exact lease fence and ordinary network cooldown.
        self.finish_download_probe_lease(
            reservation.token,
            &reservation.source,
            &reservation.hash.to_string(),
            reservation.lease,
            deferred || local_capacity,
        )
        .await;
    }

    /// Transfer the exact source reservation only after Begin has selected its
    /// generation. A cancelled Begin may have advanced the guard without this handoff.
    pub(crate) async fn rebind_prepared_source(
        &self,
        reservation: &mut PreparedSourceReservation,
        token: emulebb_metadata::JobToken,
    ) -> bool {
        let mut state = self.state.lock().await;
        let endpoint = crate::source_endpoint_key(&reservation.source);
        if token.job_id != reservation.token.job_id
            || state.active_download_peer_endpoints.get(&endpoint) != Some(&reservation.token)
            || state
                .download_source_registry
                .source_lease_id(&reservation.source, &reservation.hash.to_string())
                != Some(reservation.lease)
        {
            return false;
        }
        state.active_download_peer_endpoints.insert(endpoint, token);
        reservation.token = token;
        true
    }

    /// Dispose of an unused socket before making its reservation available again.
    pub(crate) async fn discard_prepared_source(&self, ready: PreparedDownloadSource) {
        let PreparedDownloadSource {
            reservation, peer, ..
        } = ready;
        drop(peer);
        self.settle_source_reservation(&reservation, true, None)
            .await;
    }

    /// Settle raw local refusals before the direct runner aggregates peer errors.
    /// The awaited producer (and its socket/permit) is dropped before settlement.
    pub(crate) async fn run_prepared_source<F>(
        &self,
        reservation: &PreparedSourceReservation,
        operation: F,
    ) -> Result<Ed2kPeerDownloadReport>
    where
        F: std::future::Future<Output = Result<Ed2kPeerDownloadReport>>,
    {
        let result = operation.await;
        if let Err(error) = &result {
            self.settle_source_reservation(reservation, false, Some(error))
                .await;
        }
        result
    }

    /// Round bookkeeping must not reinterpret a later metadata refusal as a
    /// producer refusal, or release a connection already owned by UDP reask.
    pub(crate) async fn settle_prepared_round(
        &self,
        reservation: &PreparedSourceReservation,
        outcome: &Result<crate::ed2k_direct_download_types::DirectDownloadOutcome>,
    ) {
        let detached = outcome.as_ref().is_ok_and(|outcome| {
            outcome
                .detached_reask_endpoints
                .contains(&crate::source_endpoint_key(&reservation.source))
        });
        if !detached {
            self.settle_source_reservation(reservation, false, None)
                .await;
        }
    }

    pub(crate) async fn prepare_download_sources(
        &self,
        guard: &DownloadAttemptGuard,
        shutdown: &CancellationToken,
    ) -> Result<DownloadPreparation> {
        let cancel = guard.cancellation();
        let Some(network) = self.ed2k_network.as_ref() else {
            return Ok(DownloadPreparation::Waiting);
        };
        let Some(parts) = self
            .ed2k_transfers
            .download_verified_parts(guard.token())
            .await?
        else {
            return Ok(DownloadPreparation::Waiting);
        };
        if parts.verified_parts.iter().all(|verified| *verified) {
            return Ok(DownloadPreparation::Finalization);
        }
        let target = DownloadSourceTarget {
            token: guard.token(),
            hash: guard.hash().to_string(),
            size_bytes: parts.file_size_bytes,
        };
        // Fresh direct discoveries are persisted by the common acquisition path.
        // Read them with old hints in pages, never an all-endpoints accumulator.
        let mut discovered = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(DownloadPreparation::Waiting),
            () = cancel.cancelled() => return Ok(DownloadPreparation::Waiting),
            result = self.acquire_ed2k_sources(network, &target, guard.hash(), target.size_bytes, true, false) => result?,
        };
        discovered.retain(|source| !source.is_direct_dialable());
        if !guard.preparation_has_headroom(crate::download_admission::construction_starts(
            self.ed2k_transfers.download_resource_snapshot(),
        )) {
            return Ok(DownloadPreparation::Waiting);
        }
        let reachability = self.ed2k_reachability.snapshot();
        let mut endpoints = vec![(network.bind_ip, network.listen_port)];
        if let Some(ip) = reachability.public_ip() {
            endpoints.push((ip, reachability.advertised_tcp_port(network.listen_port)));
        }
        let own = OwnSourceIdentity {
            user_hash: network.user_hash,
            endpoints,
        };
        let bans = self.ed2k_transfers.ban_store();
        let mut after = 0;
        loop {
            if shutdown.is_cancelled() || cancel.is_cancelled() {
                return Ok(DownloadPreparation::Waiting);
            }
            let page = self
                .ed2k_transfers
                .download_source_endpoints_after(guard.token(), after, 256)
                .await?;
            if page.is_empty() {
                break;
            }
            after = page.last().expect("nonempty endpoint page").id;
            let hash = guard.hash();
            let sources = page.try_project(64 * 1024, |page| {
                let mut sources = page
                    .iter()
                    .map(|endpoint| found_source_from_endpoint(hash, endpoint))
                    .collect::<Vec<_>>();
                drop_self_sources(&mut sources, &own);
                sources.retain(|source| {
                    !network.ip_filter.is_filtered(source.ip)
                        && !bans.is_banned(Some(source.ip), source.user_hash.as_ref())
                });
                Ok(sources)
            })?;
            for source in sources.iter() {
                if shutdown.is_cancelled() || cancel.is_cancelled() {
                    return Ok(DownloadPreparation::Waiting);
                }
                self.register_download_source_candidates(&target, std::slice::from_ref(source))
                    .await;
                let (leased, _, _) = self
                    .acquire_direct_download_source_leases(
                        guard.token(),
                        &target.hash,
                        std::slice::from_ref(source),
                    )
                    .await;
                if leased.is_empty() {
                    continue;
                }
                let Some(lease_id) = self
                    .capture_download_probe_lease(guard.token(), source, &target.hash)
                    .await
                else {
                    continue;
                };
                let reservation = PreparedSourceReservation {
                    source: source.clone(),
                    token: guard.token(),
                    hash: guard.hash(),
                    lease: lease_id,
                };
                let mut not_started = false;
                let result: Result<DownloadPreparation> = async {
                    let outcome = tokio::select! {
                        biased;
                        () = shutdown.cancelled() => return Ok(DownloadPreparation::Waiting),
                        () = cancel.cancelled() => return Ok(DownloadPreparation::Waiting),
                        result = probe_file_from_peer(Ed2kPeerProbeOptions {
                            bind_ip: network.bind_ip, egress_route: network.egress_route,
                            peer: source, hello_identity: self.ed2k_hello_identity(network),
                            secure_ident: std::sync::Arc::clone(&network.secure_ident),
                            transfer_runtime: std::sync::Arc::clone(&self.ed2k_transfers),
                            file_size: target.size_bytes, verified_parts: &parts.verified_parts,
                            timeout: Duration::from_secs(network.ed2k.connect_timeout_secs.max(10)),
                        }) => result?,
                    };
                    match outcome {
                        Ed2kPeerProbeOutcome::Available(peer) => {
                            peer.remember_availability(guard.token()).await?;
                            if cancel.is_cancelled() || shutdown.is_cancelled() {
                                return Ok(DownloadPreparation::Waiting);
                            }
                            if peer
                                .availability()
                                .available_parts
                                .iter()
                                .zip(&parts.verified_parts)
                                .any(|(available, verified)| *available && !*verified)
                            {
                                return Ok(DownloadPreparation::Direct(PreparedDownloadSource {
                                    reservation: reservation.clone(),
                                    peer,
                                    admission_deadline: tokio::time::Instant::now()
                                        + Duration::from_secs(
                                            network.ed2k.connect_timeout_secs.max(10),
                                        ),
                                }));
                            }
                            self.hold_no_needed_parts_sources(
                                guard.token(),
                                &target.hash,
                                std::slice::from_ref(source),
                            )
                            .await;
                        }
                        Ed2kPeerProbeOutcome::FileNotFound => {
                            self.dead_list_file_not_found_sources(
                                guard.token(),
                                &target.hash,
                                std::slice::from_ref(source),
                            )
                            .await;
                        }
                        Ed2kPeerProbeOutcome::Deferred => not_started = true,
                    }
                    Ok(DownloadPreparation::Waiting)
                }
                .await;
                if let Ok(DownloadPreparation::Direct(_)) = &result {
                    return result;
                }
                self.settle_source_reservation(&reservation, not_started, result.as_ref().err())
                    .await;
                if let Err(error) = result {
                    tracing::debug!(job_id = %guard.token().job_id, %error, "source preparation deferred");
                }
            }
        }
        drop_self_sources(&mut discovered, &own);
        discovered.retain(|source| {
            !network.ip_filter.is_filtered(source.ip)
                && !bans.is_banned(Some(source.ip), source.user_hash.as_ref())
        });
        for source in discovered {
            if cancel.is_cancelled() || shutdown.is_cancelled() {
                break;
            }
            if let Some(prepared) = self
                .prepare_callback_source(guard, &source, &parts.verified_parts, shutdown)
                .await?
            {
                return Ok(DownloadPreparation::Callback(Box::new(prepared)));
            }
        }
        Ok(DownloadPreparation::Waiting)
    }
}
