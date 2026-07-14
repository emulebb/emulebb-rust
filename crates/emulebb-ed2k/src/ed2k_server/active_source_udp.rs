use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::Result;
use tokio::time::Instant as TokioInstant;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::Ed2kRuntimeConfig;
use emulebb_kad_proto::Ed2kHash;

use super::{
    Ed2kFoundSource, OP_GLOBFOUNDSOURCES, annotate_found_sources_server, bind_server_udp_socket,
    configured_server_entries, decode_udp_found_source_sets, merge_found_sources,
    read_server_udp_packet, read_server_udp_packet_from_any, resolve_server_entry,
    retain_live_servers, send_udp_source_search, send_udp_source_search_batch,
    validate_found_sources,
};

/// Inputs for an ED2K server UDP source search.
pub struct Ed2kUdpSourceSearchOptions<'a> {
    /// Local IPv4 address to bind for outbound server UDP traffic.
    pub bind_ip: Ipv4Addr,
    /// ED2K server configuration and search limits.
    pub config: &'a Ed2kRuntimeConfig,
    /// Server endpoint to try first when it is present in the configured list.
    pub preferred_endpoint: Option<SocketAddr>,
    /// Server endpoint to skip, usually because another source-search path is already using it.
    pub excluded_endpoint: Option<SocketAddr>,
    /// Servers at/over the dead-server retry threshold, skipped like eMule's UDP
    /// source walk (`GetFailedCount() >= GetDeadServerRetries()`).
    pub dead_server_endpoints: &'a [SocketAddr],
    /// Maximum number of configured servers to try.
    pub max_attempts: usize,
    /// Target ED2K file hash.
    pub file_hash: Ed2kHash,
    /// Target file size in bytes.
    pub file_size: u64,
    /// Per-server response wait budget.
    pub timeout: Duration,
    /// Cancellation signal for the owning search/download job.
    pub cancel: &'a CancellationToken,
}

/// One file included in an ED2K global UDP source-search batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ed2kUdpSourceBatchTarget {
    pub file_hash: Ed2kHash,
    pub file_size: u64,
}

/// Inputs for an ED2K server UDP source search over several file hashes.
pub struct Ed2kUdpSourceBatchSearchOptions<'a> {
    /// Local IPv4 address to bind for outbound server UDP traffic.
    pub bind_ip: Ipv4Addr,
    /// ED2K server configuration and search limits.
    pub config: &'a Ed2kRuntimeConfig,
    /// Server endpoint to try first when it is present in the configured list.
    pub preferred_endpoint: Option<SocketAddr>,
    /// Server endpoint to skip, usually because another source-search path is already using it.
    pub excluded_endpoint: Option<SocketAddr>,
    /// Servers at/over the dead-server retry threshold, skipped like eMule's UDP
    /// source walk (`GetFailedCount() >= GetDeadServerRetries()`).
    pub dead_server_endpoints: &'a [SocketAddr],
    /// Maximum number of configured servers to try.
    pub max_attempts: usize,
    /// Target ED2K files.
    pub targets: &'a [Ed2kUdpSourceBatchTarget],
    /// Per-server response wait budget.
    pub timeout: Duration,
    /// Cancellation signal for the owning search/download job.
    pub cancel: &'a CancellationToken,
}

/// Executes ED2K server UDP source searches for one file hash and size.
///
/// LowID live sessions can receive a server warning and disconnect before a
/// fresh TCP source-search login reaches `OP_IDCHANGE`. eMule can still use the
/// server UDP `GlobGetSources` family, so keep that path available as a
/// first-class source acquisition fallback.
#[expect(
    clippy::cognitive_complexity,
    reason = "linear protocol orchestration flow"
)]
pub async fn search_source_udp_servers(
    options: Ed2kUdpSourceSearchOptions<'_>,
) -> Result<Vec<Ed2kFoundSource>> {
    let Ed2kUdpSourceSearchOptions {
        bind_ip,
        config,
        preferred_endpoint,
        excluded_endpoint,
        dead_server_endpoints,
        max_attempts,
        file_hash,
        file_size,
        timeout,
        cancel,
    } = options;
    let mut configured_servers = configured_server_entries(config)?;
    // eMule skips servers at/over the dead-server retry threshold in the UDP
    // source walk (DownloadQueue.cpp:1798); drop them before the walk.
    retain_live_servers(&mut configured_servers, dead_server_endpoints);
    if configured_servers.is_empty() {
        anyhow::bail!("ED2K UDP source search requires at least one configured server");
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
    if let Some(excluded_endpoint) = excluded_endpoint {
        configured_servers.retain(|entry| {
            entry.host != excluded_endpoint.ip().to_string()
                || entry.port != excluded_endpoint.port()
        });
    }
    if configured_servers.is_empty() {
        return Ok(Vec::new());
    }

    let socket = bind_server_udp_socket(bind_ip).await?;
    let mut aggregated_results = Vec::new();
    let mut last_error = None;
    let per_server_timeout = timeout.max(Duration::from_secs(5));

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
                    "failed to resolve ED2K UDP source-search server {} name={}: {error}",
                    configured_server.base_endpoint_text(),
                    configured_server.display_name()
                );
                last_error = Some(error);
                continue;
            }
        };
        if resolved_server_matches_endpoint(&resolved_server, excluded_endpoint) {
            info!(
                "skipping ED2K UDP source-search connected server endpoint={} file_hash={}",
                resolved_server.base_endpoint(),
                file_hash
            );
            continue;
        }
        info!(
            "ED2K UDP source search attempt={}/{} endpoint={} name={} file_hash={}",
            attempt_index + 1,
            max_attempts.max(1),
            resolved_server.base_endpoint(),
            resolved_server.entry.display_name(),
            file_hash
        );
        if let Err(error) =
            send_udp_source_search(&socket, &resolved_server, file_hash, file_size).await
        {
            warn!(
                "failed to send ED2K UDP source search file_hash={} endpoint={}: {error}",
                file_hash,
                resolved_server.base_endpoint()
            );
            last_error = Some(error);
            continue;
        }

        let deadline = TokioInstant::now() + per_server_timeout;
        loop {
            if cancel.is_cancelled() {
                return Ok(Vec::new());
            }
            let Some(remaining) = deadline.checked_duration_since(TokioInstant::now()) else {
                break;
            };
            match tokio::time::timeout(remaining, read_server_udp_packet(&socket, &resolved_server))
                .await
            {
                Ok(Ok(Some(packet))) => {
                    if packet.from.ip() != IpAddr::V4(resolved_server.ip) {
                        continue;
                    }
                    if packet.opcode != OP_GLOBFOUNDSOURCES {
                        continue;
                    }
                    let source_sets = match decode_udp_found_source_sets(&packet.payload) {
                        Ok(source_sets) => source_sets,
                        Err(error) => {
                            // WHY: public ED2K UDP source replies are untrusted. Stock eMule
                            // drops malformed datagrams and keeps probing other servers.
                            warn!(
                                "discarding malformed ED2K UDP source-search response file_hash={} endpoint={}: {error}",
                                file_hash,
                                resolved_server.base_endpoint()
                            );
                            break;
                        }
                    };
                    for results in source_sets {
                        let results =
                            annotate_found_sources_server(results, resolved_server.base_endpoint());
                        if let Err(error) = validate_found_sources(&results, file_hash) {
                            warn!(
                                "discarding mismatched ED2K UDP source-search response file_hash={} endpoint={}: {error}",
                                file_hash,
                                resolved_server.base_endpoint()
                            );
                            continue;
                        }
                        merge_found_sources(&mut aggregated_results, results);
                    }
                    info!(
                        "completed ED2K UDP source search file_hash={} endpoint={} source_count={} aggregated_source_count={}",
                        file_hash,
                        resolved_server.base_endpoint(),
                        aggregated_results.len(),
                        aggregated_results.len()
                    );
                    break;
                }
                Ok(Ok(None)) => continue,
                Ok(Err(error)) => {
                    last_error = Some(error);
                    break;
                }
                Err(_) => break,
            }
        }

        if !aggregated_results.is_empty() {
            return Ok(aggregated_results);
        }
    }

    if let Some(error) = last_error {
        return Err(error);
    }
    Ok(Vec::new())
}

/// Interval between successive per-server `OP_GLOBGETSOURCES*` sends during one UDP
/// source walk. Oracle `CDownloadQueue::SendNextUDPPacket` trickles exactly one server
/// per ~1s `Process` tick (driven by `m_udcounter >= 10`), never fanning out to every
/// configured server within a single tick. rust previously sent to all servers
/// back-to-back (a ~one-datagram-per-server burst); pacing at the oracle cadence
/// removes that spike while the socket keeps receiving replies in between.
const UDP_SOURCE_SERVER_WALK_INTERVAL: Duration = Duration::from_secs(1);

/// Drain inbound `OP_GLOBFOUNDSOURCES` datagrams from any already-queried server into
/// `results_by_hash` until `deadline`, discarding malformed / unrequested / mismatched
/// responses. Extracted so the server walk can interleave a paced send with response
/// collection (the OS keeps buffering replies for servers already queried while the walk
/// waits out the per-server interval). Returns a fatal socket-read error if one occurs.
async fn drain_source_udp_responses(
    socket: &tokio::net::UdpSocket,
    queried_servers: &[super::ResolvedServerEntry],
    deadline: TokioInstant,
    requested_hashes: &HashSet<Ed2kHash>,
    results_by_hash: &mut HashMap<Ed2kHash, Vec<Ed2kFoundSource>>,
    cancel: &CancellationToken,
) -> Option<anyhow::Error> {
    if queried_servers.is_empty() {
        return None;
    }
    loop {
        if cancel.is_cancelled() {
            return None;
        }
        let remaining = deadline.checked_duration_since(TokioInstant::now())?;
        match tokio::time::timeout(
            remaining,
            read_server_udp_packet_from_any(socket, queried_servers),
        )
        .await
        {
            Ok(Ok(Some((response_server, packet)))) => {
                if packet.opcode != OP_GLOBFOUNDSOURCES {
                    continue;
                }
                let source_sets = match decode_udp_found_source_sets(&packet.payload) {
                    Ok(source_sets) => source_sets,
                    Err(error) => {
                        warn!(
                            "discarding malformed ED2K UDP source batch-search response endpoint={}: {error}",
                            response_server.base_endpoint()
                        );
                        continue;
                    }
                };
                for results in source_sets {
                    let Some(file_hash) = results.first().map(|source| source.file_hash) else {
                        continue;
                    };
                    if !requested_hashes.contains(&file_hash) {
                        warn!(
                            "discarding unrequested ED2K UDP source batch-search response file_hash={} endpoint={}",
                            file_hash,
                            response_server.base_endpoint()
                        );
                        continue;
                    }
                    let results =
                        annotate_found_sources_server(results, response_server.base_endpoint());
                    if let Err(error) = validate_found_sources(&results, file_hash) {
                        warn!(
                            "discarding mismatched ED2K UDP source batch-search response file_hash={} endpoint={}: {error}",
                            file_hash,
                            response_server.base_endpoint()
                        );
                        continue;
                    }
                    merge_found_sources(results_by_hash.entry(file_hash).or_default(), results);
                }
            }
            Ok(Ok(None)) => continue,
            Ok(Err(error)) => return Some(error),
            Err(_) => return None,
        }
    }
}

/// Executes ED2K server UDP source searches for several file hashes at once.
///
/// eMule's global source walk fills each `OP_GLOBGETSOURCES*` datagram with
/// multiple file IDs for the current server before rotating to the next server,
/// pacing one server per ~1s tick. This API preserves that packet shape *and*
/// cadence for callers that can coalesce scarce active transfers before issuing
/// the UDP walk.
#[expect(
    clippy::cognitive_complexity,
    reason = "linear protocol orchestration flow"
)]
pub async fn search_source_udp_server_batches(
    options: Ed2kUdpSourceBatchSearchOptions<'_>,
) -> Result<HashMap<Ed2kHash, Vec<Ed2kFoundSource>>> {
    let Ed2kUdpSourceBatchSearchOptions {
        bind_ip,
        config,
        preferred_endpoint,
        excluded_endpoint,
        dead_server_endpoints,
        max_attempts,
        targets,
        timeout,
        cancel,
    } = options;
    if targets.is_empty() {
        return Ok(HashMap::new());
    }
    let mut configured_servers = configured_server_entries(config)?;
    // eMule skips servers at/over the dead-server retry threshold in the UDP
    // source walk (DownloadQueue.cpp:1798); drop them before the walk.
    retain_live_servers(&mut configured_servers, dead_server_endpoints);
    if configured_servers.is_empty() {
        anyhow::bail!("ED2K UDP source batch search requires at least one configured server");
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
    if let Some(excluded_endpoint) = excluded_endpoint {
        configured_servers.retain(|entry| {
            entry.host != excluded_endpoint.ip().to_string()
                || entry.port != excluded_endpoint.port()
        });
    }
    if configured_servers.is_empty() {
        return Ok(HashMap::new());
    }

    let requested_hashes = targets
        .iter()
        .map(|target| target.file_hash)
        .collect::<HashSet<_>>();
    let request_targets = targets
        .iter()
        .map(|target| super::Ed2kUdpSourceRequestTarget {
            file_hash: target.file_hash,
            file_size: target.file_size,
        })
        .collect::<Vec<_>>();
    let socket = bind_server_udp_socket(bind_ip).await?;
    let mut results_by_hash: HashMap<Ed2kHash, Vec<Ed2kFoundSource>> = HashMap::new();
    let mut last_error = None;
    let per_server_timeout = timeout.max(Duration::from_secs(5));
    let mut queried_servers = Vec::new();

    // Oracle `CDownloadQueue::SendNextUDPPacket`: trickle one server's batched request
    // per interval instead of fanning out to every configured server at once. After each
    // send, drain replies for the pacing window (the OS keeps buffering responses from the
    // servers already queried), then advance to the next server. This removes the previous
    // simultaneous per-server burst without dropping any reply.
    for (attempt_index, configured_server) in configured_servers
        .into_iter()
        .take(max_attempts.max(1))
        .enumerate()
    {
        if cancel.is_cancelled() {
            return Ok(HashMap::new());
        }
        let resolved_server = match resolve_server_entry(&configured_server).await {
            Ok(server) => server,
            Err(error) => {
                warn!(
                    "failed to resolve ED2K UDP source batch-search server {} name={}: {error}",
                    configured_server.base_endpoint_text(),
                    configured_server.display_name()
                );
                last_error = Some(error);
                continue;
            }
        };
        if resolved_server_matches_endpoint(&resolved_server, excluded_endpoint) {
            info!(
                "skipping ED2K UDP source batch-search connected server endpoint={} target_count={}",
                resolved_server.base_endpoint(),
                targets.len()
            );
            continue;
        }
        info!(
            "ED2K UDP source batch search attempt={}/{} endpoint={} name={} target_count={}",
            attempt_index + 1,
            max_attempts.max(1),
            resolved_server.base_endpoint(),
            resolved_server.entry.display_name(),
            targets.len()
        );
        if let Err(error) =
            send_udp_source_search_batch(&socket, &resolved_server, &request_targets).await
        {
            warn!(
                "failed to send ED2K UDP source batch search endpoint={}: {error}",
                resolved_server.base_endpoint()
            );
            last_error = Some(error);
            continue;
        }
        queried_servers.push(resolved_server);
        // Pace before the next server, draining any replies that arrive meanwhile so no
        // early-server response is lost while we wait out the per-server interval.
        let pacing_deadline = TokioInstant::now() + UDP_SOURCE_SERVER_WALK_INTERVAL;
        if let Some(error) = drain_source_udp_responses(
            &socket,
            &queried_servers,
            pacing_deadline,
            &requested_hashes,
            &mut results_by_hash,
            cancel,
        )
        .await
        {
            last_error = Some(error);
        }
    }

    if queried_servers.is_empty() {
        if let Some(error) = last_error {
            return Err(error);
        }
        return Ok(HashMap::new());
    }

    // Final listen tail after the last server was queried (the reask response window is
    // independent of the send cadence).
    let deadline = TokioInstant::now() + per_server_timeout;
    if let Some(error) = drain_source_udp_responses(
        &socket,
        &queried_servers,
        deadline,
        &requested_hashes,
        &mut results_by_hash,
        cancel,
    )
    .await
    {
        last_error = Some(error);
    }

    if !results_by_hash.is_empty() {
        return Ok(results_by_hash);
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    Ok(HashMap::new())
}

fn resolved_server_matches_endpoint(
    server: &super::ResolvedServerEntry,
    endpoint: Option<SocketAddr>,
) -> bool {
    endpoint.is_some_and(|endpoint| server.base_endpoint() == endpoint)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;

    #[test]
    fn resolved_endpoint_exclusion_matches_ip_even_when_configured_host_differs() {
        let resolved = super::super::ResolvedServerEntry {
            entry: super::super::ConfiguredServerEntry {
                host: "server.example.invalid".to_string(),
                port: 5687,
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
            ip: Ipv4Addr::new(203, 0, 113, 10),
        };

        assert!(resolved_server_matches_endpoint(
            &resolved,
            Some(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 5687)))
        ));
        assert!(!resolved_server_matches_endpoint(
            &resolved,
            Some(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 5687)))
        ));
    }
}
