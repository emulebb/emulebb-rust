use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{config::Ed2kConfig, ed2k_tcp::Ed2kHelloIdentity, ed2k_transfer::Ed2kSharedEntry};

use super::packet_handler::decode_id_change_payload;
use super::{
    Ed2kSearchFile, Ed2kServerState, OP_IDCHANGE, OP_LOGINREQUEST, OP_QUERY_MORE_RESULT, OP_REJECT,
    OP_SEARCHREQUEST, OP_SEARCHRESULT, ResolvedServerEntry, ServerSession, ServerSessionPhase,
    configured_server_entries, decode_search_result_page, encode_login_request, encode_packet,
    encode_search_request, login_identity_for_server_transport, resolve_server_entry,
    send_connected_server_startup, should_use_server_obfuscation, wait_for_offer_files_settle,
};

/// Inputs for a one-shot ED2K keyword search across configured servers.
pub struct Ed2kKeywordSearchOptions<'a> {
    pub bind_ip: Ipv4Addr,
    pub config: &'a Ed2kConfig,
    pub hello_identity: Ed2kHelloIdentity,
    pub shared_catalog: &'a [Ed2kSharedEntry],
    pub preferred_endpoint: Option<SocketAddr>,
    pub max_attempts: usize,
    pub query: &'a str,
    pub cancel: &'a CancellationToken,
}

/// Executes a one-shot ED2K keyword search against the configured servers.
///
/// This is a staging path used by active `SearchJob`s before the fuller ED2K
/// server connection pool exists. The function prefers the currently connected
/// background server when one is available, caps how many configured servers it
/// will probe, and returns the first non-empty result page it receives.
pub async fn search_keyword_servers(
    options: Ed2kKeywordSearchOptions<'_>,
) -> Result<Vec<Ed2kSearchFile>> {
    let Ed2kKeywordSearchOptions {
        bind_ip,
        config,
        hello_identity,
        shared_catalog,
        preferred_endpoint,
        max_attempts,
        query,
        cancel,
    } = options;
    let mut configured_servers = configured_server_entries(config)?;
    if configured_servers.is_empty() {
        anyhow::bail!("ED2K keyword search requires at least one configured server");
    }
    if let Some(preferred_endpoint) = preferred_endpoint
        && let Some(index) = configured_servers.iter().position(|entry| {
            entry.host == preferred_endpoint.ip().to_string()
                && entry.port == preferred_endpoint.port()
        })
    {
        let preferred = configured_servers.remove(index);
        configured_servers.insert(0, preferred);
    }

    let search_payload = encode_search_request(query)?;
    if search_payload.is_empty() {
        return Ok(Vec::new());
    }

    // Live servers regularly take around 10 seconds to emit the LowID warning
    // plus OP_IDCHANGE before any source search can even start, so the generic
    // connect timeout floor is too short for real-world GETSOURCES sessions.
    let idle_timeout = Duration::from_secs(config.connect_timeout_secs.max(15));
    let mut last_error = None;

    for (attempt_index, configured_server) in configured_servers
        .into_iter()
        .take(max_attempts.max(1))
        .enumerate()
    {
        if cancel.is_cancelled() {
            return Ok(Vec::new());
        }

        let resolved_server = match resolve_server_entry(&configured_server).await {
            Ok(server) => server,
            Err(error) => {
                warn!(
                    "failed to resolve ED2K search server {} name={}: {error}",
                    configured_server.base_endpoint_text(),
                    configured_server.display_name()
                );
                last_error = Some(error);
                continue;
            }
        };
        info!(
            "ED2K keyword search attempt={}/{} endpoint={} name={}",
            attempt_index + 1,
            max_attempts.max(1),
            resolved_server.base_endpoint(),
            resolved_server.entry.display_name()
        );

        match search_keyword_on_server(
            bind_ip,
            &resolved_server,
            hello_identity,
            shared_catalog,
            &search_payload,
            idle_timeout,
            cancel,
        )
        .await
        {
            Ok(results) if !results.is_empty() => return Ok(results),
            Ok(_) => continue,
            Err(error) => {
                warn!(
                    "ED2K keyword search failed for {} name={}: {error}",
                    resolved_server.base_endpoint(),
                    resolved_server.entry.display_name()
                );
                last_error = Some(error);
            }
        }
    }

    if let Some(error) = last_error {
        return Err(error);
    }

    Ok(Vec::new())
}

async fn search_keyword_on_server(
    bind_ip: Ipv4Addr,
    server: &ResolvedServerEntry,
    hello_identity: Ed2kHelloIdentity,
    shared_catalog: &[Ed2kSharedEntry],
    search_payload: &[u8],
    idle_timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<Ed2kSearchFile>> {
    let use_server_obfuscation =
        should_use_server_obfuscation(hello_identity.connect_options, server);
    let login_identity =
        login_identity_for_server_transport(hello_identity, use_server_obfuscation);
    let transport_endpoint = server.transport_endpoint(use_server_obfuscation);
    let mut session = ServerSession::connect(
        bind_ip,
        transport_endpoint,
        Arc::new(RwLock::new(Ed2kServerState::default())),
        "active_search",
        idle_timeout,
    )
    .await?;
    info!(
        "ED2K active search session connected trace_id={} endpoint={} transport={} query_len={}",
        session.trace_id,
        transport_endpoint,
        if use_server_obfuscation {
            "obfuscated"
        } else {
            "plaintext"
        },
        search_payload.len()
    );
    let login_request = encode_packet(
        OP_LOGINREQUEST,
        &encode_login_request(login_identity),
        false,
    )?;
    if use_server_obfuscation {
        session
            .negotiate_obfuscation_and_send(&login_request)
            .await
            .with_context(|| {
                format!(
                    "failed to negotiate ED2K server obfuscation with {}",
                    transport_endpoint
                )
            })?;
    } else {
        session
            .send_encoded_packet(
                &login_request,
                format!("failed to send ED2K server login request to {transport_endpoint}"),
            )
            .await?;
    }
    session.set_phase(
        ServerSessionPhase::AwaitingIdChange,
        "login request sent; awaiting OP_IDCHANGE",
    );

    let mut results = Vec::new();
    let mut page_count = 0u32;

    loop {
        if cancel.is_cancelled() {
            return Ok(Vec::new());
        }

        let packet = tokio::time::timeout(idle_timeout, session.read_packet())
            .await
            .with_context(|| {
                format!("timed out waiting for ED2K server search reply from {transport_endpoint}")
            })??;
        let Some(packet) = packet else {
            break;
        };

        match packet.opcode {
            OP_IDCHANGE => {
                let id_change = decode_id_change_payload(&packet.payload)
                    .with_context(|| format!("invalid OP_IDCHANGE from {transport_endpoint}"))?;
                session.server_flags = id_change.server_flags;
                if id_change.client_id == 0 {
                    anyhow::bail!(
                        "ED2K server {transport_endpoint} returned zero client_id in OP_IDCHANGE"
                    );
                }
                session.assigned_client_id = Some(id_change.client_id);
                let active_catalog = Arc::new(RwLock::new(shared_catalog.to_vec()));
                send_connected_server_startup(
                    &mut session,
                    &active_catalog,
                    hello_identity.tcp_port,
                )
                .await?;
                wait_for_offer_files_settle(&session).await;
                session.set_phase(
                    ServerSessionPhase::SearchActive,
                    "dispatching active keyword search request",
                );
                session
                    .send_packet(OP_SEARCHREQUEST, search_payload)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to send ED2K keyword search request to {transport_endpoint}"
                        )
                    })?;
            }
            OP_SEARCHRESULT => {
                let page = decode_search_result_page(&packet.payload)?;
                page_count += 1;
                results.extend(page.files);
                if page.more_results_available {
                    session.set_phase(
                        ServerSessionPhase::AwaitingMore,
                        format!("received active result page {page_count}; requesting more"),
                    );
                    session.send_packet(OP_QUERY_MORE_RESULT, &[]).await?;
                } else {
                    session.set_phase(
                        ServerSessionPhase::Completed,
                        format!(
                            "completed active keyword search pages={page_count} results={}",
                            results.len()
                        ),
                    );
                    break;
                }
            }
            OP_REJECT => {
                anyhow::bail!("ED2K server {transport_endpoint} rejected the search session");
            }
            _ => {}
        }
    }

    Ok(results)
}
