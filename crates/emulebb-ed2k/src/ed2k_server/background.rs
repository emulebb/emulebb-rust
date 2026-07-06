use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{
    sync::{RwLock, mpsc, oneshot},
    time::Instant as TokioInstant,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use emulebb_kad_proto::Ed2kHash;

use super::{
    Ed2kFoundSource, Ed2kSearchFile, Ed2kServerState, OP_CALLBACKREQUEST, OP_GLOBFOUNDSOURCES,
    OP_GLOBSEARCHRES, OP_GLOBSERVSTATRES, OP_SEARCHREQUEST, OfferFilesPublishStats,
    ResolvedServerEntry, SearchCriteria, ServerSession, ServerSessionPhase, ServerUdpPacket,
    decode_udp_found_source_sets, decode_udp_search_result_pages,
    encode_search_request_with_criteria, encode_source_request, merge_found_sources,
    send_offer_files_advertisement, source_request_opcode, validate_found_sources,
    wait_for_offer_files_settle,
};
use crate::ed2k_transfer::Ed2kSharedCatalog;

type BackgroundKeywordSearchResponse = std::result::Result<Vec<Ed2kSearchFile>, BackgroundSearchFailure>;
type BackgroundSourceSearchResponse = std::result::Result<Vec<Ed2kFoundSource>, BackgroundSearchFailure>;
type BackgroundCallbackRequestResponse = std::result::Result<(), BackgroundSearchFailure>;
type BackgroundPublishResponse = std::result::Result<OfferFilesPublishStats, BackgroundSearchFailure>;

/// Marker error surfaced by the background-session request wrappers when the
/// request never ran to completion on a live connected server session: the
/// request channel was closed (stale handle after a runtime teardown), the
/// responder was dropped, or the session shut down / rotated / reconnected /
/// lost the connection mid-flight. Callers must treat the search as
/// NOT-ATTEMPTED (e.g. requeue it for a fresh session), never as a
/// completed-empty result - that silent-empty mapping is exactly the failure
/// mode the connection-aware search queue exists to remove. Detect it with
/// `anyhow::Error::downcast_ref::<Ed2kBackgroundSearchInterrupted>()`.
#[derive(Debug)]
pub struct Ed2kBackgroundSearchInterrupted(String);

impl std::fmt::Display for Ed2kBackgroundSearchInterrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Ed2kBackgroundSearchInterrupted {}

/// Failure detail carried on the background response channels. `interrupted`
/// separates session-transition failures (the request never completed on a
/// live session; retryable, see [`Ed2kBackgroundSearchInterrupted`]) from a
/// genuine on-session wait that timed out (the server just never answered).
#[derive(Debug, Clone)]
pub(super) struct BackgroundSearchFailure {
    message: String,
    interrupted: bool,
}

impl BackgroundSearchFailure {
    pub(super) fn interrupted(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            interrupted: true,
        }
    }

    pub(super) fn timed_out(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            interrupted: false,
        }
    }

    fn into_anyhow(self) -> anyhow::Error {
        if self.interrupted {
            anyhow::Error::new(Ed2kBackgroundSearchInterrupted(self.message))
        } else {
            anyhow::Error::msg(self.message)
        }
    }
}

fn interrupted_error(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Ed2kBackgroundSearchInterrupted(message.into()))
}

/// Handle used by active jobs to execute a keyword search through the
/// long-lived ED2K background session.
#[derive(Clone)]
pub struct Ed2kServerSearchHandle {
    sender: mpsc::Sender<BackgroundServerSearchRequest>,
}

/// Inbox owned by the long-lived ED2K background server task.
pub struct Ed2kServerSearchInbox {
    pub(super) receiver: mpsc::Receiver<BackgroundServerSearchRequest>,
}

#[derive(Debug)]
pub(super) enum BackgroundServerSearchRequest {
    Keyword {
        query: String,
        criteria: SearchCriteria,
        timeout: Duration,
        response: oneshot::Sender<BackgroundKeywordSearchResponse>,
    },
    Source {
        file_hash: Ed2kHash,
        file_size: u64,
        timeout: Duration,
        response: oneshot::Sender<BackgroundSourceSearchResponse>,
    },
    Callback {
        client_id: u32,
        response: oneshot::Sender<BackgroundCallbackRequestResponse>,
    },
    Publish {
        response: oneshot::Sender<BackgroundPublishResponse>,
    },
}

pub(super) struct BackgroundServerSearchContext<'a> {
    pub(super) server: &'a ResolvedServerEntry,
    pub(super) connect_options: u8,
    pub(super) shared_catalog: &'a Ed2kSharedCatalog,
    pub(super) bind_ip: Ipv4Addr,
    pub(super) tcp_port: u16,
}

#[derive(Debug)]
pub(super) enum PendingBackgroundServerSearch {
    Keyword {
        query: String,
        deadline: TokioInstant,
        results: Vec<Ed2kSearchFile>,
        page_count: u32,
        response: oneshot::Sender<BackgroundKeywordSearchResponse>,
    },
    Source {
        file_hash: Ed2kHash,
        deadline: TokioInstant,
        response: oneshot::Sender<BackgroundSourceSearchResponse>,
    },
}

use PendingBackgroundServerSearch::{Keyword, Source};

/// Creates a bounded request channel for background-session ED2K server searches.
#[must_use]
pub fn new_ed2k_server_search_channel(
    capacity: usize,
) -> (Ed2kServerSearchHandle, Ed2kServerSearchInbox) {
    let (sender, receiver) = mpsc::channel(capacity.max(1));
    (
        Ed2kServerSearchHandle { sender },
        Ed2kServerSearchInbox { receiver },
    )
}

/// Requests a keyword search on the already-connected ED2K background session.
///
/// This keeps active jobs on the same server TCP session shape as the oracle
/// whenever that long-lived session is healthy.
pub async fn search_keyword_via_background_session(
    handle: &Ed2kServerSearchHandle,
    query: &str,
    criteria: SearchCriteria,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<Ed2kSearchFile>> {
    let (response, receive_response) = oneshot::channel();
    handle
        .sender
        .send(BackgroundServerSearchRequest::Keyword {
            query: query.to_string(),
            criteria,
            timeout,
            response,
        })
        .await
        // WHY: a failed send means the background runtime is gone (stale
        // handle) - the search never reached any session, so it must be
        // retryable-interrupted, not a terminal search failure.
        .map_err(|_| interrupted_error("ED2K background search channel is closed"))?;

    tokio::select! {
        _ = cancel.cancelled() => Ok(Vec::new()),
        result = tokio::time::timeout(timeout, receive_response) => {
            let response = result
                .with_context(|| format!("timed out waiting for ED2K background search response after {timeout:?}"))?
                // WHY: a dropped responder means the session task died before
                // answering - also never-completed, so retryable-interrupted.
                .map_err(|_| interrupted_error("ED2K background search responder dropped"))?;
            response.map_err(BackgroundSearchFailure::into_anyhow)
        }
    }
}

/// Requests a source search on the already-connected ED2K background session.
///
/// This keeps active source lookups on the same server TCP session shape as the
/// oracle whenever that long-lived session is healthy.
pub async fn search_source_via_background_session(
    handle: &Ed2kServerSearchHandle,
    file_hash: Ed2kHash,
    file_size: u64,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<Ed2kFoundSource>> {
    let (response, receive_response) = oneshot::channel();
    handle
        .sender
        .send(BackgroundServerSearchRequest::Source {
            file_hash,
            file_size,
            timeout,
            response,
        })
        .await
        .context("ED2K background search channel is closed")?;

    tokio::select! {
        _ = cancel.cancelled() => Ok(Vec::new()),
        response = receive_response => {
            let response = response.context("ED2K background source responder dropped")?;
            response.map_err(BackgroundSearchFailure::into_anyhow)
        }
    }
}

/// Requests an ED2K server callback for a LowID peer on the current
/// background server session.
pub async fn request_callback_via_background_session(
    handle: &Ed2kServerSearchHandle,
    client_id: u32,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<()> {
    let (response, receive_response) = oneshot::channel();
    handle
        .sender
        .send(BackgroundServerSearchRequest::Callback {
            client_id,
            response,
        })
        .await
        .context("ED2K background callback channel is closed")?;

    tokio::select! {
        _ = cancel.cancelled() => Ok(()),
        result = tokio::time::timeout(timeout, receive_response) => {
            let response = result
                .with_context(|| format!("timed out waiting for ED2K background callback response after {timeout:?}"))?
                .context("ED2K background callback responder dropped")?;
            response.map_err(BackgroundSearchFailure::into_anyhow)
        }
    }
}

/// Requests an immediate offer-files refresh on the connected ED2K server session.
pub async fn publish_shared_catalog_via_background_session(
    handle: &Ed2kServerSearchHandle,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<OfferFilesPublishStats> {
    let (response, receive_response) = oneshot::channel();
    handle
        .sender
        .send(BackgroundServerSearchRequest::Publish { response })
        .await
        .context("ED2K background publish channel is closed")?;

    tokio::select! {
        _ = cancel.cancelled() => Ok(OfferFilesPublishStats {
            wrapped: true,
            skipped_duplicate_batch: true,
            ..OfferFilesPublishStats::default()
        }),
        result = tokio::time::timeout(timeout, receive_response) => {
            let response = result
                .with_context(|| format!("timed out waiting for ED2K background publish response after {timeout:?}"))?
                .context("ED2K background publish responder dropped")?;
            response.map_err(BackgroundSearchFailure::into_anyhow)
        }
    }
}

pub(super) fn handle_background_udp_packet(
    server: &ResolvedServerEntry,
    packet: &ServerUdpPacket,
    pending_background_search: &mut Option<PendingBackgroundServerSearch>,
    state: &Arc<RwLock<Ed2kServerState>>,
    server_status_challenge: &mut Option<u32>,
) -> Result<()> {
    if packet.from.ip() != IpAddr::V4(server.ip) {
        return Ok(());
    }
    match packet.opcode {
        OP_GLOBSEARCHRES => {
            let Some(Keyword {
                query,
                deadline,
                mut results,
                page_count,
                response,
            }) = pending_background_search.take()
            else {
                return Ok(());
            };
            let pages = match decode_udp_search_result_pages(&packet.payload) {
                Ok(pages) => pages,
                Err(error) => {
                    // WHY: public ED2K UDP search replies are untrusted. Keep the pending
                    // search alive so a later valid packet or the normal timeout decides it.
                    warn!(
                        "discarding malformed ED2K background UDP keyword-search response query={:?} endpoint={}: {error}",
                        query,
                        server.base_endpoint()
                    );
                    *pending_background_search = Some(Keyword {
                        query,
                        deadline,
                        results,
                        response,
                        page_count,
                    });
                    return Ok(());
                }
            };
            for page in pages {
                log_search_result_page(server.base_endpoint(), &page.files);
                results.extend(page.files);
            }
            info!(
                "completed ED2K background UDP keyword search query={:?} endpoint={} source=udp result_count={}",
                query,
                server.base_endpoint(),
                results.len()
            );
            let _ = response.send(Ok(results));
        }
        OP_GLOBFOUNDSOURCES => {
            let Some(Source {
                file_hash,
                deadline,
                response,
            }) = pending_background_search.take()
            else {
                return Ok(());
            };
            let mut aggregated_results = Vec::new();
            let source_sets = match decode_udp_found_source_sets(&packet.payload) {
                Ok(source_sets) => source_sets,
                Err(error) => {
                    // WHY: public ED2K UDP source replies are untrusted. Keep the pending
                    // search alive so a later valid packet or the normal timeout decides it.
                    warn!(
                        "discarding malformed ED2K background UDP source-search response file_hash={} endpoint={}: {error}",
                        file_hash,
                        server.base_endpoint()
                    );
                    *pending_background_search = Some(Source {
                        file_hash,
                        deadline,
                        response,
                    });
                    return Ok(());
                }
            };
            for results in source_sets {
                let results = super::annotate_found_sources_server(results, server.base_endpoint());
                if let Err(error) = validate_found_sources(&results, file_hash) {
                    warn!(
                        "discarding mismatched ED2K background UDP source-search response file_hash={} endpoint={}: {error}",
                        file_hash,
                        server.base_endpoint()
                    );
                    *pending_background_search = Some(Source {
                        file_hash,
                        deadline,
                        response,
                    });
                    return Ok(());
                }
                merge_found_sources(&mut aggregated_results, results);
            }
            info!(
                "completed ED2K background UDP source search file_hash={} endpoint={} source=udp source_count={}",
                file_hash,
                server.base_endpoint(),
                aggregated_results.len()
            );
            let _ = response.send(Ok(aggregated_results));
        }
        OP_GLOBSERVSTATRES => {
            // eMule discards a status reply whose echoed challenge does not match
            // the one we issued (replay/unsolicited guard, `UDPSocket.cpp`).
            let Some(expected) = *server_status_challenge else {
                return Ok(());
            };
            let Some(status) =
                super::server_status::decode_server_status_response(&packet.payload, expected)
            else {
                return Ok(());
            };
            *server_status_challenge = None;
            if let Ok(mut guard) = state.try_write() {
                guard.server_users = Some(status.users);
                guard.server_files = Some(status.files);
                if let Some(udp_flags) = status.udp_flags {
                    guard.server_udp_flags = Some(udp_flags);
                }
            }
            tracing::debug!(
                "ED2K server UDP status from {} users={} files={} udp_flags={:?}",
                packet.from,
                status.users,
                status.files,
                status.udp_flags
            );
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn fail_background_search_request(
    request: &mut Option<BackgroundServerSearchRequest>,
    failure: &BackgroundSearchFailure,
) {
    if let Some(request) = request.take() {
        match request {
            BackgroundServerSearchRequest::Keyword { response, .. } => {
                let _ = response.send(Err(failure.clone()));
            }
            BackgroundServerSearchRequest::Source { response, .. } => {
                let _ = response.send(Err(failure.clone()));
            }
            BackgroundServerSearchRequest::Callback { response, .. } => {
                let _ = response.send(Err(failure.clone()));
            }
            BackgroundServerSearchRequest::Publish { response } => {
                let _ = response.send(Err(failure.clone()));
            }
        }
    }
}

pub(super) fn fail_pending_background_search(
    request: &mut Option<PendingBackgroundServerSearch>,
    failure: &BackgroundSearchFailure,
) {
    if let Some(request) = request.take() {
        match request {
            Keyword { response, .. } => {
                let _ = response.send(Err(failure.clone()));
            }
            Source { response, .. } => {
                let _ = response.send(Err(failure.clone()));
            }
        }
    }
}

#[allow(clippy::cognitive_complexity)]
pub(super) async fn start_background_server_search(
    session: &mut ServerSession,
    context: BackgroundServerSearchContext<'_>,
    request: BackgroundServerSearchRequest,
) -> Result<Option<PendingBackgroundServerSearch>> {
    match request {
        BackgroundServerSearchRequest::Keyword {
            query,
            criteria,
            timeout,
            response,
        } => {
            let search_payload = encode_search_request_with_criteria(&query, &criteria)?;
            if search_payload.is_empty() {
                let _ = response.send(Ok(Vec::new()));
                anyhow::bail!("ED2K background keyword search payload was unexpectedly empty");
            }
            wait_for_offer_files_settle(session).await;
            session.set_phase(
                ServerSessionPhase::SearchActive,
                format!("dispatching background keyword search query={query:?}"),
            );
            session
                .send_packet(OP_SEARCHREQUEST, &search_payload)
                .await?;
            info!(
                "sent ED2K background keyword search query={:?} endpoint={} trace_id={} role={}",
                query, session.endpoint, session.trace_id, session.trace_role
            );
            Ok(Some(Keyword {
                query,
                deadline: TokioInstant::now() + timeout,
                results: Vec::new(),
                page_count: 0,
                response,
            }))
        }
        BackgroundServerSearchRequest::Source {
            file_hash,
            file_size,
            timeout,
            response,
        } => {
            wait_for_offer_files_settle(session).await;
            session.set_phase(
                ServerSessionPhase::SearchActive,
                format!("dispatching background source search file_hash={file_hash}"),
            );
            let source_request = encode_source_request(file_hash, file_size);
            let opcode = source_request_opcode(context.connect_options, session.server_flags);
            session.send_packet(opcode, &source_request).await?;
            info!(
                "sent ED2K background source search file_hash={} endpoint={} trace_id={} role={} opcode=0x{:02X}",
                file_hash, session.endpoint, session.trace_id, session.trace_role, opcode
            );
            Ok(Some(Source {
                file_hash,
                deadline: TokioInstant::now() + timeout,
                response,
            }))
        }
        BackgroundServerSearchRequest::Callback {
            client_id,
            response,
        } => {
            wait_for_offer_files_settle(session).await;
            session.set_phase(
                ServerSessionPhase::SearchActive,
                format!("dispatching background callback request client_id={client_id}"),
            );
            session
                .send_packet(OP_CALLBACKREQUEST, &client_id.to_le_bytes())
                .await?;
            info!(
                "sent ED2K background callback request client_id={} endpoint={} trace_id={} role={}",
                client_id, session.endpoint, session.trace_id, session.trace_role
            );
            let _ = response.send(Ok(()));
            Ok(None)
        }
        BackgroundServerSearchRequest::Publish { response } => {
            let stats = send_offer_files_advertisement(
                session,
                context.shared_catalog,
                context.bind_ip,
                context.tcp_port,
            )
            .await?;
            let _ = response.send(Ok(stats));
            Ok(None)
        }
    }
}

pub(super) fn log_search_result_page(endpoint: SocketAddr, results: &[Ed2kSearchFile]) {
    let sample_hits = results
        .iter()
        .take(5)
        .map(|file| {
            let file_name = file.file_name.as_deref().unwrap_or("-");
            let file_size = file
                .file_size
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string());
            format!("{file_name} [hash={} size={}]", file.file_hash, file_size)
        })
        .collect::<Vec<_>>();
    info!(
        "ED2K search results from {}: count={} sample_hits={}",
        endpoint,
        results.len(),
        if sample_hits.is_empty() {
            "-".to_string()
        } else {
            sample_hits.join(" | ")
        }
    );
}
