use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::Result;
use tokio::time::Instant as TokioInstant;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::Ed2kConfig;
use emulebb_kad_proto::Ed2kHash;

use super::{
    Ed2kFoundSource, OP_GLOBFOUNDSOURCES, annotate_found_sources_server, bind_server_udp_socket,
    configured_server_entries, decode_udp_found_source_sets, merge_found_sources,
    read_server_udp_packet, read_server_udp_packet_from_any, resolve_server_entry,
    send_udp_source_search, send_udp_source_search_batch, validate_found_sources,
};

/// Inputs for an ED2K server UDP source search.
pub struct Ed2kUdpSourceSearchOptions<'a> {
    /// Local IPv4 address to bind for outbound server UDP traffic.
    pub bind_ip: Ipv4Addr,
    /// ED2K server configuration and search limits.
    pub config: &'a Ed2kConfig,
    /// Server endpoint to try first when it is present in the configured list.
    pub preferred_endpoint: Option<SocketAddr>,
    /// Server endpoint to skip, usually because another source-search path is already using it.
    pub excluded_endpoint: Option<SocketAddr>,
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
    pub config: &'a Ed2kConfig,
    /// Server endpoint to try first when it is present in the configured list.
    pub preferred_endpoint: Option<SocketAddr>,
    /// Server endpoint to skip, usually because another source-search path is already using it.
    pub excluded_endpoint: Option<SocketAddr>,
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
#[allow(clippy::cognitive_complexity)]
pub async fn search_source_udp_servers(
    options: Ed2kUdpSourceSearchOptions<'_>,
) -> Result<Vec<Ed2kFoundSource>> {
    let Ed2kUdpSourceSearchOptions {
        bind_ip,
        config,
        preferred_endpoint,
        excluded_endpoint,
        max_attempts,
        file_hash,
        file_size,
        timeout,
        cancel,
    } = options;
    let mut configured_servers = configured_server_entries(config)?;
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

/// Executes ED2K server UDP source searches for several file hashes at once.
///
/// eMule's global source walk fills each `OP_GLOBGETSOURCES*` datagram with
/// multiple file IDs for the current server before rotating to the next server.
/// This API preserves that packet shape for callers that can coalesce scarce
/// active transfers before issuing the UDP walk.
#[allow(clippy::cognitive_complexity)]
pub async fn search_source_udp_server_batches(
    options: Ed2kUdpSourceBatchSearchOptions<'_>,
) -> Result<HashMap<Ed2kHash, Vec<Ed2kFoundSource>>> {
    let Ed2kUdpSourceBatchSearchOptions {
        bind_ip,
        config,
        preferred_endpoint,
        excluded_endpoint,
        max_attempts,
        targets,
        timeout,
        cancel,
    } = options;
    if targets.is_empty() {
        return Ok(HashMap::new());
    }
    let mut configured_servers = configured_server_entries(config)?;
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
    }

    if queried_servers.is_empty() {
        if let Some(error) = last_error {
            return Err(error);
        }
        return Ok(HashMap::new());
    }

    let deadline = TokioInstant::now() + per_server_timeout;
    loop {
        if cancel.is_cancelled() {
            return Ok(HashMap::new());
        }
        let Some(remaining) = deadline.checked_duration_since(TokioInstant::now()) else {
            break;
        };
        match tokio::time::timeout(
            remaining,
            read_server_udp_packet_from_any(&socket, &queried_servers),
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
            Ok(Err(error)) => {
                last_error = Some(error);
                break;
            }
            Err(_) => break,
        }
    }

    if !results_by_hash.is_empty() {
        return Ok(results_by_hash);
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    Ok(HashMap::new())
}
