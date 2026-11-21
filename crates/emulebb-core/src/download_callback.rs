//! Scalar callback authority shared by selected and waiting downloads.
use emulebb_ed2k::{
    ed2k_server::Ed2kFoundSource,
    ed2k_transfer::{Ed2kCallbackDownload, Ed2kCallbackPreparationId, Ed2kSourceHint},
};
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::JobToken;

/// Callback dispatch needs content and execution authority, not a hydrated transfer.
pub(crate) struct CallbackDownloadTarget {
    pub token: JobToken,
    pub hash: Ed2kHash,
    pub name: String,
    pub size_bytes: u64,
    pub preparation_id: Option<Ed2kCallbackPreparationId>,
}

impl CallbackDownloadTarget {
    pub(crate) fn download_for_source(&self, source: &Ed2kFoundSource) -> Ed2kCallbackDownload {
        Ed2kCallbackDownload {
            preparation_id: self.preparation_id,
            job_token: self.token,
            file_hash: self.hash,
            display_name: self.name.clone(),
            file_size: self.size_bytes,
            source: Ed2kSourceHint {
                ip: source.ip.to_string(),
                tcp_port: source.tcp_port,
                user_hash: source.user_hash.map(hex::encode),
                connect_options: source.obfuscation_options,
                file_comment: String::new(),
                file_rating: 0,
            },
        }
    }
}

use crate::{
    Ed2kBackgroundCallbackDispatchOutcome, Ed2kCallbackReservation, Ed2kCallbackTicketRequest,
    Ed2kNetworkConfig, Ed2kRuntimeConfig, Ed2kServerCallbackRoute, Ed2kUdpCallbackRequestOptions,
    EmulebbCore, cancel_ed2k_server_callback_request, claim_ed2k_server_callback_request,
    commit_ed2k_server_callback_request, ed2k_server_callback_permitted,
    ed2k_server_callback_route, request_callback_via_background_session,
    request_callback_via_udp_server,
};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

enum Ed2kServerCallbackDispatch {
    Sent,
    KnownNotSent(String),
    DeliveryUnknown(anyhow::Error),
}

impl EmulebbCore {
    /// Share route authority, cooldown and dispatch settlement before or after hydration.
    pub(crate) async fn send_ed2k_server_callback(
        &self,
        network: &Ed2kNetworkConfig,
        target: &CallbackDownloadTarget,
        source: &Ed2kFoundSource,
        callback_window: Duration,
        cancel: &CancellationToken,
        config: &Ed2kRuntimeConfig,
    ) {
        if cancel.is_cancelled()
            || !source.low_id
            || source.has_kad_buddy_reask_target()
            || source.is_direct_callback_source()
        {
            return;
        }
        // Oracle CanDoCallback forbids a firewalled requester asking its server
        // to relay to another LowID peer. Apply the same gate to both routes.
        let self_tcp_firewalled = self.ed2k_self_tcp_firewalled().await;
        let connected_server_route = self.connected_ed2k_server_route().await;
        let connected_server_endpoint = connected_server_route.map(|(endpoint, _)| endpoint);
        let connected_search_handle = self.connected_ed2k_search_handle().await;
        let Some(source_server) = source.source_server else {
            tracing::debug!(
                "ED2K server callback unavailable file_hash={} client_id={} source_server=-",
                target.hash,
                source.client_id,
            );
            return;
        };
        let callback_route =
            ed2k_server_callback_route(Some(source_server), connected_server_endpoint);
        // Both TCP server callback and cross-server global UDP
        // callback require us to be HighID/reachable.
        if !ed2k_server_callback_permitted(
            self_tcp_firewalled,
            Some(source_server),
            connected_server_endpoint,
        ) {
            tracing::debug!(
                "ED2K server callback unavailable file_hash={} client_id={} self_firewalled={} source_server={} connected_server={}",
                target.hash,
                source.client_id,
                self_tcp_firewalled,
                source_server,
                connected_server_endpoint
                    .map_or_else(|| "-".to_string(), |endpoint| endpoint.to_string())
            );
            return;
        }
        let callback_download = target.download_for_source(source);
        let callback_ticket = match Ed2kCallbackTicketRequest::server(
            source_server,
            source.client_id,
            source.user_hash,
            source.tcp_port,
            callback_download,
            callback_window,
        ) {
            Ok(ticket) => ticket,
            Err(error) => {
                tracing::warn!(
                    "ED2K server callback ticket rejected file_hash={} client_id={} source_server={}: {error}",
                    target.hash,
                    source.client_id,
                    source_server,
                );
                return;
            }
        };
        let callback_dispatch_permit = match self
            .ed2k_transfers
            .reserve_callback_ticket(callback_ticket)
            .await
        {
            Ok(Ed2kCallbackReservation::Dispatch(permit)) => permit,
            Ok(Ed2kCallbackReservation::Joined { .. }) => {
                tracing::debug!(
                    "ED2K server callback joined pending peer session file_hash={} client_id={} source_server={}",
                    target.hash,
                    source.client_id,
                    source_server,
                );
                return;
            }
            Err(error) => {
                tracing::warn!(
                    "ED2K server callback reservation failed file_hash={} client_id={} source_server={}: {error}",
                    target.hash,
                    source.client_id,
                    source_server,
                );
                return;
            }
        };
        let callback_cooldown_permit = {
            let mut state = self.state.lock().await;
            claim_ed2k_server_callback_request(
                &mut state.ed2k_server_callback_last_sent,
                source_server,
                source.client_id,
                Instant::now(),
            )
        };
        let Some(callback_cooldown_permit) = callback_cooldown_permit else {
            let _ = self
                .ed2k_transfers
                .cancel_callback_ticket(callback_dispatch_permit)
                .await;
            tracing::debug!(
                "ED2K server callback suppressed by cooldown file_hash={} client_id={} source_server={}",
                target.hash,
                source.client_id,
                source_server,
            );
            return;
        };
        let Some(callback_dispatch_guard) = self
            .ed2k_transfers
            .begin_callback_ticket_dispatch(callback_dispatch_permit)
        else {
            let cooldown_cancelled = {
                let mut state = self.state.lock().await;
                cancel_ed2k_server_callback_request(
                    &mut state.ed2k_server_callback_last_sent,
                    callback_cooldown_permit,
                )
            };
            tracing::debug!(
                "ED2K server callback settled before dispatch file_hash={} client_id={} source_server={} cooldown_cancelled={}",
                target.hash,
                source.client_id,
                source_server,
                cooldown_cancelled,
            );
            return;
        };
        let callback_deadline = callback_dispatch_guard.expires_at();
        let callback_dispatch = if Instant::now() >= callback_deadline {
            Ed2kServerCallbackDispatch::KnownNotSent(
                "ED2K callback ticket expired before route dispatch".to_string(),
            )
        } else {
            match callback_route {
                Ed2kServerCallbackRoute::BackgroundSession => {
                    if let (
                        Some(handle),
                        Some((expected_server_endpoint, expected_session_generation)),
                    ) = (connected_search_handle.as_ref(), connected_server_route)
                    {
                        match request_callback_via_background_session(
                            handle,
                            expected_server_endpoint,
                            expected_session_generation,
                            source.client_id,
                            callback_deadline,
                            cancel,
                        )
                        .await
                        {
                            Ok(Ed2kBackgroundCallbackDispatchOutcome::Sent) => {
                                Ed2kServerCallbackDispatch::Sent
                            }
                            Ok(Ed2kBackgroundCallbackDispatchOutcome::NotSent { reason }) => {
                                Ed2kServerCallbackDispatch::KnownNotSent(reason)
                            }
                            Err(error) => Ed2kServerCallbackDispatch::DeliveryUnknown(error),
                        }
                    } else {
                        Ed2kServerCallbackDispatch::KnownNotSent(
                            "ED2K callback needs a connected background server session".to_string(),
                        )
                    }
                }
                Ed2kServerCallbackRoute::GlobalUdp => {
                    let reachability = self.ed2k_reachability.snapshot();
                    match reachability.public_ip() {
                        Some(requester_public_ip) => {
                            match request_callback_via_udp_server(Ed2kUdpCallbackRequestOptions {
                                bind_ip: network.bind_ip,
                                config,
                                requester_public_ip,
                                requester_tcp_port: reachability
                                    .advertised_tcp_port(network.listen_port),
                                server_endpoint: source_server,
                                target_client_id: source.client_id,
                            })
                            .await
                            {
                                Ok(()) => Ed2kServerCallbackDispatch::Sent,
                                Err(error) => {
                                    Ed2kServerCallbackDispatch::KnownNotSent(error.to_string())
                                }
                            }
                        }
                        None => Ed2kServerCallbackDispatch::KnownNotSent(
                            "ED2K global callback requires a known public IPv4".to_string(),
                        ),
                    }
                }
                Ed2kServerCallbackRoute::Unavailable => Ed2kServerCallbackDispatch::KnownNotSent(
                    "ED2K server callback route became unavailable".to_string(),
                ),
            }
        };
        match callback_dispatch {
            Ed2kServerCallbackDispatch::Sent => {
                let ticket_outcome = callback_dispatch_guard.mark_dispatched();
                let cooldown_committed = {
                    let mut state = self.state.lock().await;
                    commit_ed2k_server_callback_request(
                        &mut state.ed2k_server_callback_last_sent,
                        callback_cooldown_permit,
                        Instant::now(),
                    )
                };
                tracing::debug!(
                    "ED2K callback requested file_hash={} client_id={} tcp_port={} source_server={} ticket_outcome={ticket_outcome:?} cooldown_committed={cooldown_committed}",
                    target.hash,
                    source.client_id,
                    source.tcp_port,
                    source_server,
                );
            }
            Ed2kServerCallbackDispatch::KnownNotSent(reason) => {
                let ticket_cancelled = callback_dispatch_guard.cancel();
                let cooldown_cancelled = {
                    let mut state = self.state.lock().await;
                    cancel_ed2k_server_callback_request(
                        &mut state.ed2k_server_callback_last_sent,
                        callback_cooldown_permit,
                    )
                };
                tracing::warn!(
                    "ED2K callback request not sent file_hash={} client_id={} source_server={} ticket_cancelled={} cooldown_cancelled={}: {reason}",
                    target.hash,
                    source.client_id,
                    source_server,
                    ticket_cancelled,
                    cooldown_cancelled,
                );
            }
            Ed2kServerCallbackDispatch::DeliveryUnknown(error) => {
                // The command may have reached the server. Conservatively
                // arm admission and retain the cooldown instead of sending
                // a duplicate callback or deleting a fast inbound claim.
                let ticket_outcome = callback_dispatch_guard.mark_dispatched();
                let cooldown_committed = {
                    let mut state = self.state.lock().await;
                    commit_ed2k_server_callback_request(
                        &mut state.ed2k_server_callback_last_sent,
                        callback_cooldown_permit,
                        Instant::now(),
                    )
                };
                tracing::warn!(
                    "ED2K callback delivery unknown file_hash={} client_id={} source_server={} ticket_outcome={ticket_outcome:?} cooldown_committed={cooldown_committed}: {error}",
                    target.hash,
                    source.client_id,
                    source_server,
                );
            }
        }
    }
}
