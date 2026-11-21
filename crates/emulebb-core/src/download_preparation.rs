//! Bounded waiting-job discovery and direct availability before hydration.
use crate::{
    EmulebbCore, OwnSourceIdentity, download_attempts::DownloadAttemptGuard, drop_self_sources,
    ed2k_source_batch::DownloadSourceTarget, found_source_from_endpoint, source_endpoint_key,
};
use anyhow::Result;
use emulebb_ed2k::{
    ed2k_server::Ed2kFoundSource,
    ed2k_tcp::{
        Ed2kPeerProbeOptions, Ed2kPeerProbeOutcome, Ed2kPreparedPeer, probe_file_from_peer,
    },
};
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;

pub(crate) struct PreparedDownloadSource {
    pub source: Ed2kFoundSource,
    pub peer: Box<Ed2kPreparedPeer>,
}

pub(crate) enum DownloadPreparation {
    Waiting,
    Direct(PreparedDownloadSource),
    /// Inbound callback preparation is not yet connected to the listener owner.
    Callback,
    Finalization,
}

impl EmulebbCore {
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
            needed_parts: parts
                .verified_parts
                .iter()
                .filter(|verified| !**verified)
                .count() as u32,
        };
        // Fresh direct discoveries are persisted by the common acquisition path.
        // Read them with old hints in pages, never an all-endpoints accumulator.
        let discovered = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(DownloadPreparation::Waiting),
            () = cancel.cancelled() => return Ok(DownloadPreparation::Waiting),
            result = self.acquire_ed2k_sources(network, &target, guard.hash(), target.size_bytes, true, false) => result?,
        };
        let has_callback = discovered.iter().any(|source| !source.is_direct_dialable());
        drop(discovered);
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
                                    source: source.clone(),
                                    peer,
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
                        Ed2kPeerProbeOutcome::Deferred => {}
                    }
                    Ok(DownloadPreparation::Waiting)
                }
                .await;
                if let Ok(DownloadPreparation::Direct(_)) = &result {
                    return result;
                }
                self.release_direct_download_source_leases(
                    guard.token(),
                    &[source_endpoint_key(source)],
                )
                .await;
                if let Err(error) = result {
                    tracing::debug!(job_id = %guard.token().job_id, %error, "source preparation deferred");
                }
            }
        }
        Ok(if has_callback {
            DownloadPreparation::Callback
        } else {
            DownloadPreparation::Waiting
        })
    }
}
