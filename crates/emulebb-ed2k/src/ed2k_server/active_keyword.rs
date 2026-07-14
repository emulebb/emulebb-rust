use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{sync::RwLock, time::Instant as TokioInstant};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    config::Ed2kRuntimeConfig,
    ed2k_tcp::Ed2kHelloIdentity,
    ed2k_transfer::{Ed2kSharedEntry, IndexedSharedCatalog},
};

use super::packet_handler::decode_id_change_payload;
use super::{
    Ed2kSearchFile, Ed2kServerState, OP_GLOBSEARCHRES, OP_IDCHANGE, OP_LOGINREQUEST,
    OP_QUERY_MORE_RESULT, OP_REJECT, OP_SEARCHREQUEST, OP_SEARCHRESULT, ResolvedServerEntry,
    ServerSession, ServerSessionPhase, bind_server_udp_socket, configured_server_entries,
    decode_search_result_page, decode_udp_search_result_pages, encode_login_request, encode_packet,
    encode_search_request, login_identity_for_server_transport, read_server_udp_packet,
    resolve_server_entry, retain_live_servers, send_connected_server_startup,
    send_udp_keyword_search, should_use_server_obfuscation, wait_for_offer_files_settle,
};

/// Inputs for a one-shot ED2K keyword search across configured servers.
pub struct Ed2kKeywordSearchOptions<'a> {
    pub bind_ip: Ipv4Addr,
    pub config: &'a Ed2kRuntimeConfig,
    pub hello_identity: Ed2kHelloIdentity,
    pub shared_catalog: &'a [Ed2kSharedEntry],
    pub preferred_endpoint: Option<SocketAddr>,
    pub max_attempts: usize,
    pub query: &'a str,
    pub cancel: &'a CancellationToken,
}

/// Inputs for a stock-style global ED2K UDP keyword search.
pub struct Ed2kUdpKeywordSearchOptions<'a> {
    pub bind_ip: Ipv4Addr,
    pub config: &'a Ed2kRuntimeConfig,
    pub excluded_endpoint: Option<SocketAddr>,
    /// Servers at/over the dead-server retry threshold, skipped like eMule's UDP
    /// keyword/stat walk (`GetFailedCount() >= GetDeadServerRetries()`).
    pub dead_server_endpoints: &'a [SocketAddr],
    pub max_attempts: usize,
    pub query: &'a str,
    pub timeout: Duration,
    pub cancel: &'a CancellationToken,
}

/// Executes ED2K global UDP keyword searches across configured servers.
///
/// Stock eMule sends the local keyword search through the connected server TCP
/// session and sends `OP_GLOBSEARCHREQ*` over UDP only to other servers. This
/// helper implements that global UDP part without opening any extra TCP server
/// login sessions.
#[expect(
    clippy::cognitive_complexity,
    reason = "linear protocol orchestration flow"
)]
pub async fn search_keyword_udp_servers(
    options: Ed2kUdpKeywordSearchOptions<'_>,
) -> Result<Vec<Ed2kSearchFile>> {
    let Ed2kUdpKeywordSearchOptions {
        bind_ip,
        config,
        excluded_endpoint,
        dead_server_endpoints,
        max_attempts,
        query,
        timeout,
        cancel,
    } = options;
    let mut configured_servers = configured_server_entries(config)?;
    // eMule skips servers at/over the dead-server retry threshold in the UDP
    // keyword/stat walk (ServerList.cpp:265); drop them before the walk.
    retain_live_servers(&mut configured_servers, dead_server_endpoints);
    if let Some(excluded_endpoint) = excluded_endpoint {
        configured_servers.retain(|entry| {
            entry.host != excluded_endpoint.ip().to_string()
                || entry.port != excluded_endpoint.port()
        });
    }
    if configured_servers.is_empty() {
        return Ok(Vec::new());
    }

    let search_payload = encode_search_request(query)?;
    if search_payload.is_empty() {
        return Ok(Vec::new());
    }

    let socket = bind_server_udp_socket(bind_ip).await?;
    let mut results = Vec::new();
    let mut last_error = None;
    let mut queried_servers = Vec::new();
    let per_server_timeout = Duration::from_millis(750);
    let overall_deadline = TokioInstant::now() + timeout.max(per_server_timeout);

    for (attempt_index, configured_server) in configured_servers
        .into_iter()
        .take(max_attempts.max(1))
        .enumerate()
    {
        if cancel.is_cancelled() {
            return Ok(Vec::new());
        }
        let Some(overall_remaining) = overall_deadline.checked_duration_since(TokioInstant::now())
        else {
            break;
        };
        if overall_remaining.is_zero() {
            break;
        }
        let resolved_server = match resolve_server_entry(&configured_server).await {
            Ok(server) => server,
            Err(error) => {
                warn!(
                    "failed to resolve ED2K UDP keyword-search server {} name={}: {error}",
                    configured_server.base_endpoint_text(),
                    configured_server.display_name()
                );
                last_error = Some(error);
                continue;
            }
        };
        info!(
            "ED2K UDP keyword search attempt={}/{} endpoint={} name={}",
            attempt_index + 1,
            max_attempts.max(1),
            resolved_server.base_endpoint(),
            resolved_server.entry.display_name()
        );
        if let Err(error) =
            send_udp_keyword_search(&socket, &resolved_server, &search_payload).await
        {
            warn!(
                "failed to send ED2K UDP keyword search endpoint={}: {error}",
                resolved_server.base_endpoint()
            );
            last_error = Some(error);
            continue;
        }
        queried_servers.push(resolved_server.clone());

        let per_server_deadline = TokioInstant::now() + overall_remaining.min(per_server_timeout);
        loop {
            if cancel.is_cancelled() {
                return Ok(Vec::new());
            }
            let Some(remaining) = per_server_deadline.checked_duration_since(TokioInstant::now())
            else {
                break;
            };
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, read_server_udp_packet(&socket, &resolved_server))
                .await
            {
                Ok(Ok(Some(packet))) => {
                    let Some(response_server) =
                        queried_udp_response_server(&queried_servers, packet.from)
                    else {
                        continue;
                    };
                    if packet.opcode != OP_GLOBSEARCHRES {
                        continue;
                    }
                    let pages = match decode_udp_search_result_pages(&packet.payload) {
                        Ok(pages) => pages,
                        Err(error) => {
                            // WHY: public ED2K UDP search replies are untrusted. Stock eMule
                            // drops malformed datagrams and continues the global server walk.
                            warn!(
                                "discarding malformed ED2K UDP keyword-search response endpoint={}: {error}",
                                response_server.base_endpoint()
                            );
                            continue;
                        }
                    };
                    for page in pages {
                        results.extend(page.files);
                    }
                }
                Ok(Ok(None)) => continue,
                Ok(Err(error)) => {
                    last_error = Some(error);
                    break;
                }
                Err(_) => break,
            }
        }
    }

    if results.is_empty()
        && let Some(error) = last_error
    {
        return Err(error);
    }
    Ok(results)
}

fn queried_udp_response_server(
    queried_servers: &[ResolvedServerEntry],
    response_endpoint: SocketAddr,
) -> Option<&ResolvedServerEntry> {
    // WHY: eMuleBB MFC accepts UDP search answers from any server IP that was
    // requested for the active search, even after the timer has advanced to the
    // next server. Do not tie valid late datagrams to only the current wait slot.
    queried_servers
        .iter()
        .find(|server| response_endpoint.ip() == IpAddr::V4(server.ip))
}

/// Executes a one-shot ED2K keyword search against the configured servers.
///
/// This is a staging path used by active `SearchJob`s before the fuller ED2K
/// server connection pool exists. The function prefers the currently connected
/// background server when one is available, caps how many configured servers it
/// will probe, and returns the first non-empty result page it receives.
#[expect(
    clippy::cognitive_complexity,
    reason = "linear protocol orchestration flow"
)]
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
                let active_catalog = Arc::new(RwLock::new(IndexedSharedCatalog::from_entries(
                    shared_catalog.to_vec(),
                )));
                // Ephemeral keyword-query session: never solicit the server list
                // (stock issues OP_GETSERVERLIST only from its persistent
                // ServerConnect, gated on AddServersFromServer).
                send_connected_server_startup(
                    &mut session,
                    &active_catalog,
                    bind_ip,
                    hello_identity.tcp_port,
                    false,
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::super::{ConfiguredServerEntry, ResolvedServerEntry};
    use super::queried_udp_response_server;

    fn resolved(ip: Ipv4Addr, port: u16) -> ResolvedServerEntry {
        ResolvedServerEntry {
            entry: ConfiguredServerEntry {
                host: ip.to_string(),
                port,
                name: None,
                description: None,
                udp_flags: 0,
                udp_key: 0,
                udp_key_ip: 0,
                obfuscation_port_tcp: 0,
                obfuscation_port_udp: 0,
                soft_files: 0,
                hard_files: 0,
            },
            ip,
        }
    }

    #[test]
    fn udp_keyword_search_accepts_replies_from_any_queried_server_ip() {
        let first = resolved(Ipv4Addr::new(192, 0, 2, 10), 4661);
        let second = resolved(Ipv4Addr::new(192, 0, 2, 20), 4661);
        let queried = vec![first, second];

        let matched = queried_udp_response_server(
            &queried,
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10), 4665)),
        )
        .expect("queried server accepted");

        assert_eq!(matched.ip, Ipv4Addr::new(192, 0, 2, 10));
        assert!(
            queried_udp_response_server(
                &queried,
                SocketAddr::from((Ipv4Addr::new(198, 51, 100, 10), 4665)),
            )
            .is_none()
        );
    }
}
