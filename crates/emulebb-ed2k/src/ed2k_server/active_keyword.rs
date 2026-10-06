use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{sync::RwLock, time::Instant as TokioInstant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    config::Ed2kRuntimeConfig,
    ed2k_tcp::Ed2kHelloIdentity,
    ed2k_transfer::{Ed2kSharedEntry, IndexedSharedCatalog},
};

use super::packet_handler::decode_id_change_payload;
use super::server_entry::ConfiguredServerEntry;
use super::{
    Ed2kSearchFile, Ed2kServerSearchObservation, Ed2kServerState, OP_GLOBSEARCHRES, OP_IDCHANGE,
    OP_LOGINREQUEST, OP_QUERY_MORE_RESULT, OP_REJECT, OP_SEARCHREQUEST, OP_SEARCHRESULT,
    ResolvedServerEntry, SERVER_UDP_FLAG_LARGEFILES, SearchCriteria, ServerSession,
    ServerSessionPhase, bind_server_udp_socket, configured_server_entries,
    decode_search_result_page, decode_udp_search_result_pages, encode_login_request, encode_packet,
    encode_search_request, encode_search_request_with_criteria,
    login_identity_for_server_transport, read_server_udp_packet_from_any, resolve_server_entry,
    retain_live_servers, send_connected_server_startup, send_udp_keyword_search,
    should_use_server_obfuscation, wait_for_offer_files_settle,
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
    pub query: &'a str,
    pub criteria: &'a SearchCriteria,
    /// Optional live-result sink. The terminal return value remains the full
    /// result set; this sink lets callers present pages during a long sweep.
    pub result_sink: Option<&'a (dyn Fn(Ed2kServerSearchObservation) + Send + Sync + 'a)>,
    /// Optional `(completed, total)` server-walk progress sink.
    pub progress_sink: Option<&'a (dyn Fn(usize, usize) + Send + Sync + 'a)>,
    pub cancel: &'a CancellationToken,
}

struct UdpKeywordSearchPayloads {
    legacy: Vec<u8>,
    large_file: Vec<u8>,
}

/// eMule advances the global UDP server walk every 750 ms
/// (`SearchResultsWnd::TimerGlobalSearch`).
const UDP_KEYWORD_SERVER_WALK_INTERVAL: Duration = Duration::from_millis(750);

/// Keep the per-search socket alive until replies have been quiet for this long
/// after the last paced send. Stock eMule's shared UDP listener continues
/// accepting replies for the current search after the walk timer stops; a
/// one-shot socket otherwise loses late replies or the tail of a multi-datagram
/// response.
const UDP_KEYWORD_RESPONSE_GRACE: Duration = Duration::from_secs(5);

fn encode_udp_keyword_search_payloads(
    query: &str,
    criteria: &SearchCriteria,
) -> Result<UdpKeywordSearchPayloads> {
    Ok(UdpKeywordSearchPayloads {
        legacy: encode_search_request_with_criteria(query, criteria, false)?,
        large_file: encode_search_request_with_criteria(query, criteria, true)?,
    })
}

fn eligible_udp_keyword_search_servers(
    config: &Ed2kRuntimeConfig,
    excluded_endpoint: Option<SocketAddr>,
    dead_server_endpoints: &[SocketAddr],
) -> Result<Vec<ConfiguredServerEntry>> {
    let mut servers = configured_server_entries(config)?;
    // eMule skips servers at/over the dead-server retry threshold in the UDP
    // keyword/stat walk (ServerList.cpp:265); drop them before the walk.
    retain_live_servers(&mut servers, dead_server_endpoints);
    if let Some(excluded_endpoint) = excluded_endpoint {
        servers.retain(|entry| {
            entry.host != excluded_endpoint.ip().to_string()
                || entry.port != excluded_endpoint.port()
        });
    }
    Ok(servers)
}

/// Drain global-search replies from any server already contacted until
/// `deadline`. Returns a fatal socket error, if any; malformed or unrelated
/// public datagrams are discarded without ending the search.
async fn drain_keyword_udp_responses(
    socket: &tokio::net::UdpSocket,
    queried_servers: &[ResolvedServerEntry],
    mut deadline: TokioInstant,
    response_quiet_grace: Option<Duration>,
    result_sink: Option<&(dyn Fn(Ed2kServerSearchObservation) + Send + Sync + '_)>,
    results: &mut Vec<Ed2kServerSearchObservation>,
    cancel: &CancellationToken,
) -> Option<anyhow::Error> {
    if queried_servers.is_empty() {
        return None;
    }
    loop {
        let remaining = deadline.checked_duration_since(TokioInstant::now())?;
        let received = tokio::select! {
            () = cancel.cancelled() => return None,
            received = tokio::time::timeout(
                remaining,
                read_server_udp_packet_from_any(socket, queried_servers),
            ) => received,
        };
        match received {
            Ok(Ok(Some((response_server, packet)))) => {
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
                if let Some(response_quiet_grace) = response_quiet_grace {
                    deadline = TokioInstant::now() + response_quiet_grace;
                }
                for page in pages {
                    for file in page.files {
                        let observation = Ed2kServerSearchObservation {
                            server_endpoint: response_server.base_endpoint(),
                            file,
                        };
                        if let Some(result_sink) = result_sink {
                            result_sink(observation.clone());
                        }
                        results.push(observation);
                    }
                }
            }
            Ok(Ok(None)) => continue,
            Ok(Err(error)) => return Some(error),
            Err(_) => return None,
        }
    }
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
) -> Result<Vec<Ed2kServerSearchObservation>> {
    let Ed2kUdpKeywordSearchOptions {
        bind_ip,
        config,
        excluded_endpoint,
        dead_server_endpoints,
        query,
        criteria,
        result_sink,
        progress_sink,
        cancel,
    } = options;
    let configured_servers =
        eligible_udp_keyword_search_servers(config, excluded_endpoint, dead_server_endpoints)?;
    if let Some(progress_sink) = progress_sink {
        progress_sink(0, configured_servers.len());
    }
    if configured_servers.is_empty() {
        return Ok(Vec::new());
    }

    // The configured server list can mix legacy and LARGEFILES-capable nodes.
    // Build both stock wire variants once, then select per destination instead
    // of either dropping criteria or sending an unsupported uint64 leaf.
    let search_payloads = encode_udp_keyword_search_payloads(query, criteria)?;
    if search_payloads.legacy.is_empty() {
        return Ok(Vec::new());
    }

    let socket = bind_server_udp_socket(bind_ip).await?;
    let mut results = Vec::new();
    let mut last_error = None;
    let mut queried_servers = Vec::new();
    let server_count = configured_servers.len();

    for (attempt_index, configured_server) in configured_servers.into_iter().enumerate() {
        if let Some(progress_sink) = progress_sink {
            progress_sink(attempt_index, server_count);
        }
        if cancel.is_cancelled() {
            return Ok(Vec::new());
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
        debug!(
            "ED2K UDP keyword search attempt={}/{} endpoint={} name={}",
            attempt_index + 1,
            server_count,
            resolved_server.base_endpoint(),
            resolved_server.entry.display_name()
        );
        let search_payload = if resolved_server.entry.udp_flags & SERVER_UDP_FLAG_LARGEFILES != 0 {
            &search_payloads.large_file
        } else {
            &search_payloads.legacy
        };
        if let Err(error) = send_udp_keyword_search(&socket, &resolved_server, search_payload).await
        {
            warn!(
                "failed to send ED2K UDP keyword search endpoint={}: {error}",
                resolved_server.base_endpoint()
            );
            last_error = Some(error);
            continue;
        }
        queried_servers.push(resolved_server.clone());

        let pacing_deadline = TokioInstant::now() + UDP_KEYWORD_SERVER_WALK_INTERVAL;
        if let Some(error) = drain_keyword_udp_responses(
            &socket,
            &queried_servers,
            pacing_deadline,
            None,
            result_sink,
            &mut results,
            cancel,
        )
        .await
        {
            last_error = Some(error);
        }
    }

    if let Some(progress_sink) = progress_sink {
        progress_sink(server_count, server_count);
    }

    // The stock client leaves the current search's requested-server allowlist
    // installed after its send timer stops. Preserve a bounded equivalent for
    // this one-shot socket, resetting the quiet window after every valid reply
    // so the tail of a multi-datagram result train still lands.
    let response_deadline = TokioInstant::now() + UDP_KEYWORD_RESPONSE_GRACE;
    if let Some(error) = drain_keyword_udp_responses(
        &socket,
        &queried_servers,
        response_deadline,
        Some(UDP_KEYWORD_RESPONSE_GRACE),
        result_sink,
        &mut results,
        cancel,
    )
    .await
    {
        last_error = Some(error);
    }
    if cancel.is_cancelled() {
        return Ok(Vec::new());
    }

    if results.is_empty()
        && let Some(error) = last_error
    {
        return Err(error);
    }
    Ok(results)
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
    let nickname = config.server_nickname();
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
        debug!(
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
            &nickname,
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

#[expect(
    clippy::too_many_arguments,
    reason = "single-call-site protocol session inputs stay explicit"
)]
async fn search_keyword_on_server(
    bind_ip: Ipv4Addr,
    server: &ResolvedServerEntry,
    hello_identity: Ed2kHelloIdentity,
    nickname: &str,
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
    debug!(
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
        &encode_login_request(login_identity, nickname),
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
    use std::{
        net::{Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use crate::config::Ed2kRuntimeConfig;
    use tokio::{net::UdpSocket, time::Instant as TokioInstant};
    use tokio_util::sync::CancellationToken;

    use super::{
        SearchCriteria, drain_keyword_udp_responses, eligible_udp_keyword_search_servers,
        encode_search_request_with_criteria, encode_udp_keyword_search_payloads,
    };

    #[test]
    fn udp_keyword_search_builds_capability_specific_criteria_payloads() {
        let criteria = SearchCriteria {
            file_type: Some("Video".to_string()),
            min_size: Some(u64::from(u32::MAX) + 1),
            min_complete_sources: Some(3),
            ..SearchCriteria::default()
        };

        let payloads = encode_udp_keyword_search_payloads("sample", &criteria).unwrap();

        assert_eq!(
            payloads.legacy,
            encode_search_request_with_criteria("sample", &criteria, false).unwrap()
        );
        assert_eq!(
            payloads.large_file,
            encode_search_request_with_criteria("sample", &criteria, true).unwrap()
        );
        assert_ne!(payloads.legacy, payloads.large_file);
    }

    #[test]
    fn udp_keyword_search_walk_keeps_every_eligible_server() {
        let config = Ed2kRuntimeConfig {
            server_endpoints: (1_u8..=100)
                .map(|host| format!("192.0.2.{host}:4661"))
                .collect(),
            ..Ed2kRuntimeConfig::default()
        };
        let excluded = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 40), 4661));
        let dead = [SocketAddr::from((Ipv4Addr::new(192, 0, 2, 70), 4661))];

        let servers = eligible_udp_keyword_search_servers(&config, Some(excluded), &dead).unwrap();

        assert_eq!(servers.len(), 98);
        assert_eq!(servers.first().unwrap().host, "192.0.2.1");
        assert_eq!(servers.last().unwrap().host, "192.0.2.100");
    }

    #[tokio::test]
    async fn udp_keyword_search_tail_accepts_delayed_queried_server_reply() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let server = super::super::ResolvedServerEntry {
            entry: super::super::ConfiguredServerEntry::from_endpoint_text("127.0.0.1:4661")
                .unwrap(),
            ip: Ipv4Addr::LOCALHOST,
        };
        let mut datagram = vec![super::super::OP_EDONKEYPROT, super::super::OP_GLOBSEARCHRES];
        datagram.extend_from_slice(&[0x44; 16]);
        datagram.extend_from_slice(&0x0102_0304_u32.to_le_bytes());
        datagram.extend_from_slice(&4662_u16.to_le_bytes());
        datagram.extend_from_slice(&0_u32.to_le_bytes());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            sender.send_to(&datagram, destination).await.unwrap();
        });

        let mut results = Vec::new();
        let cancel = CancellationToken::new();
        let error = drain_keyword_udp_responses(
            &receiver,
            &[server],
            TokioInstant::now() + Duration::from_millis(100),
            None,
            None,
            &mut results,
            &cancel,
        )
        .await;

        assert!(error.is_none());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file.file_hash.0, [0x44; 16]);
        assert_eq!(results[0].file.client_id, 0x0102_0304);
        assert_eq!(results[0].file.client_port, 4662);
    }

    #[tokio::test]
    async fn udp_keyword_search_tail_resets_after_each_valid_reply() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let server = super::super::ResolvedServerEntry {
            entry: super::super::ConfiguredServerEntry::from_endpoint_text("127.0.0.1:4661")
                .unwrap(),
            ip: Ipv4Addr::LOCALHOST,
        };
        let response = |hash_byte| {
            let mut datagram = vec![super::super::OP_EDONKEYPROT, super::super::OP_GLOBSEARCHRES];
            datagram.extend_from_slice(&[hash_byte; 16]);
            datagram.extend_from_slice(&0x0102_0304_u32.to_le_bytes());
            datagram.extend_from_slice(&4662_u16.to_le_bytes());
            datagram.extend_from_slice(&0_u32.to_le_bytes());
            datagram
        };
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            sender.send_to(&response(0x44), destination).await.unwrap();
            tokio::time::sleep(Duration::from_millis(125)).await;
            sender.send_to(&response(0x55), destination).await.unwrap();
        });

        let mut results = Vec::new();
        let cancel = CancellationToken::new();
        let error = drain_keyword_udp_responses(
            &receiver,
            &[server],
            TokioInstant::now() + Duration::from_millis(100),
            Some(Duration::from_millis(200)),
            None,
            &mut results,
            &cancel,
        )
        .await;

        assert!(error.is_none());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].file.file_hash.0, [0x44; 16]);
        assert_eq!(results[1].file.file_hash.0, [0x55; 16]);
    }
}
