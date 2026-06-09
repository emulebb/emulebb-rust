use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{
    net::UdpSocket,
    sync::{RwLock, mpsc, oneshot},
    time::Instant as TokioInstant,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use emulebb_kad_proto::Ed2kHash;

use super::{
    Ed2kFoundSource, Ed2kSearchFile, Ed2kServerState, OP_CALLBACKREQUEST, OP_GLOBFOUNDSOURCES,
    OP_GLOBSEARCHRES, OP_GLOBSERVSTATRES, OP_SEARCHREQUEST, ResolvedServerEntry, ServerSession,
    ServerSessionPhase, ServerUdpPacket, decode_udp_found_source_sets,
    decode_udp_search_result_pages, encode_search_request, encode_source_request,
    merge_found_sources, send_udp_keyword_search, send_udp_source_search, source_request_opcode,
    validate_found_sources, wait_for_offer_files_settle,
};

type BackgroundKeywordSearchResponse = std::result::Result<Vec<Ed2kSearchFile>, String>;
type BackgroundSourceSearchResponse = std::result::Result<Vec<Ed2kFoundSource>, String>;
type BackgroundCallbackRequestResponse = std::result::Result<(), String>;

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
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<Ed2kSearchFile>> {
    let (response, receive_response) = oneshot::channel();
    handle
        .sender
        .send(BackgroundServerSearchRequest::Keyword {
            query: query.to_string(),
            timeout,
            response,
        })
        .await
        .context("ED2K background search channel is closed")?;

    tokio::select! {
        _ = cancel.cancelled() => Ok(Vec::new()),
        result = tokio::time::timeout(timeout, receive_response) => {
            let response = result
                .with_context(|| format!("timed out waiting for ED2K background search response after {timeout:?}"))?
                .context("ED2K background search responder dropped")?;
            response.map_err(anyhow::Error::msg)
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
        result = tokio::time::timeout(timeout, receive_response) => {
            let response = result
                .with_context(|| format!("timed out waiting for ED2K background source response after {timeout:?}"))?
                .context("ED2K background source responder dropped")?;
            response.map_err(anyhow::Error::msg)
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
            response.map_err(anyhow::Error::msg)
        }
    }
}

pub(super) fn handle_background_udp_packet(
    server: &ResolvedServerEntry,
    packet: &ServerUdpPacket,
    pending_background_search: &mut Option<PendingBackgroundServerSearch>,
    state: &Arc<RwLock<Ed2kServerState>>,
) -> Result<()> {
    if packet.from.ip() != IpAddr::V4(server.ip) {
        return Ok(());
    }
    match packet.opcode {
        OP_GLOBSEARCHRES => {
            let Some(Keyword {
                query,
                mut results,
                response,
                ..
            }) = pending_background_search.take()
            else {
                return Ok(());
            };
            for page in decode_udp_search_result_pages(&packet.payload)? {
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
                response,
                ..
            }) = pending_background_search.take()
            else {
                return Ok(());
            };
            let mut aggregated_results = Vec::new();
            for results in decode_udp_found_source_sets(&packet.payload)? {
                let results = super::annotate_found_sources_server(results, server.base_endpoint());
                validate_found_sources(&results, file_hash)?;
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
            if packet.payload.len() >= 8 {
                let users = u32::from_le_bytes(packet.payload[..4].try_into().unwrap());
                let files = u32::from_le_bytes(packet.payload[4..8].try_into().unwrap());
                if let Ok(mut guard) = state.try_write() {
                    guard.server_users = Some(users);
                    guard.server_files = Some(files);
                }
                tracing::debug!(
                    "ED2K server UDP status from {} users={} files={}",
                    packet.from,
                    users,
                    files
                );
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn fail_background_search_request(
    request: &mut Option<BackgroundServerSearchRequest>,
    error: &str,
) {
    if let Some(request) = request.take() {
        match request {
            BackgroundServerSearchRequest::Keyword { response, .. } => {
                let _ = response.send(Err(error.to_string()));
            }
            BackgroundServerSearchRequest::Source { response, .. } => {
                let _ = response.send(Err(error.to_string()));
            }
            BackgroundServerSearchRequest::Callback { response, .. } => {
                let _ = response.send(Err(error.to_string()));
            }
        }
    }
}

pub(super) fn fail_pending_background_search(
    request: &mut Option<PendingBackgroundServerSearch>,
    error: &str,
) {
    if let Some(request) = request.take() {
        match request {
            Keyword { response, .. } => {
                let _ = response.send(Err(error.to_string()));
            }
            Source { response, .. } => {
                let _ = response.send(Err(error.to_string()));
            }
        }
    }
}

pub(super) async fn start_background_server_search(
    session: &mut ServerSession,
    server: &ResolvedServerEntry,
    server_udp_socket: Option<&UdpSocket>,
    connect_options: u8,
    request: BackgroundServerSearchRequest,
) -> Result<Option<PendingBackgroundServerSearch>> {
    match request {
        BackgroundServerSearchRequest::Keyword {
            query,
            timeout,
            response,
        } => {
            let search_payload = encode_search_request(&query)?;
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
            if let Some(socket) = server_udp_socket
                && let Err(error) = send_udp_keyword_search(socket, server, &search_payload).await
            {
                warn!(
                    "failed to send ED2K background UDP keyword search query={:?} endpoint={}: {error}",
                    query,
                    server.base_endpoint()
                );
            }
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
            let opcode = source_request_opcode(connect_options, session.server_flags);
            session.send_packet(opcode, &source_request).await?;
            if let Some(socket) = server_udp_socket
                && let Err(error) =
                    send_udp_source_search(socket, server, file_hash, file_size).await
            {
                warn!(
                    "failed to send ED2K background UDP source search file_hash={} endpoint={}: {error}",
                    file_hash,
                    server.base_endpoint()
                );
            }
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
