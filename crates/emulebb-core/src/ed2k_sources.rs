//! eD2k download-source and learned-metadata helpers.
//!
//! Pure (plus two Kad-lookup async) helpers that build/normalize/merge
//! `Ed2kFoundSource` candidates and the `LearnedEd2kMetadata` learned from
//! keyword results, plus the small source-requery/callback-route decision
//! predicates that drive the download orchestration. Moved verbatim out of
//! `lib.rs` during the maintainability restructuring; they carry no behavior
//! beyond what they had inline. Re-exported `pub(crate)` from the crate root so
//! the `EmulebbCore` impl, the download runtime free fns, and the test module
//! reach them by their bare names.

use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use emulebb_ed2k::{
    config::Ed2kConfig,
    ed2k_server::{Ed2kFoundSource, Ed2kSearchFile},
    ed2k_transfer::{Ed2kResumeManifest, Ed2kSourceHint},
};
use emulebb_kad_dht::{DhtNode, RpcWorkClass, SearchResult as KadSearchResult, SourceResult};
use emulebb_kad_proto::{Ed2kHash, NodeId};
use md4::{Digest, Md4};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::{
    ED2K_DOWNLOAD_KAD_SOURCE_CAP, ED2K_DOWNLOAD_KAD_SOURCE_QUIET_DELAY_MS,
    ED2K_DOWNLOAD_KAD_SOURCE_RETRY_DELAY_MS, ED2K_HASH_ONLY_QUERY_PREFIX, Transfer,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ed2kServerCallbackRoute {
    BackgroundSession,
    Unavailable,
}

pub(crate) const ED2K_SERVER_CALLBACK_COOLDOWN: Duration = Duration::from_secs(20 * 60);

pub(crate) type Ed2kServerCallbackKey = (u32, String);

pub(crate) fn claim_ed2k_server_callback_request(
    last_sent: &mut HashMap<Ed2kServerCallbackKey, Instant>,
    client_id: u32,
    file_hash: &str,
    now: Instant,
) -> bool {
    last_sent.retain(|_, sent_at| {
        now.saturating_duration_since(*sent_at) < ED2K_SERVER_CALLBACK_COOLDOWN
    });
    let key = (client_id, file_hash.to_string());
    if last_sent.get(&key).is_some_and(|sent_at| {
        now.saturating_duration_since(*sent_at) < ED2K_SERVER_CALLBACK_COOLDOWN
    }) {
        return false;
    }
    last_sent.insert(key, now);
    true
}

pub(crate) fn source_key(
    source: &Ed2kFoundSource,
) -> (Ipv4Addr, u16, Option<[u8; 16]>, Option<u8>) {
    (
        source.ip,
        source.tcp_port,
        source.user_hash,
        source.obfuscation_options,
    )
}

pub(crate) fn found_source_from_hint(
    file_hash: Ed2kHash,
    hint: &Ed2kSourceHint,
) -> Result<Ed2kFoundSource> {
    let ip = hint
        .ip
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid remembered source IP {}", hint.ip))?;
    let user_hash = hint
        .user_hash
        .as_deref()
        .map(|value| -> Result<[u8; 16]> {
            let bytes = hex::decode(value)
                .with_context(|| format!("invalid remembered source user hash {value}"))?;
            let user_hash: [u8; 16] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("remembered source user hash has wrong length"))?;
            Ok(user_hash)
        })
        .transpose()?;
    Ok(Ed2kFoundSource {
        file_hash,
        ip,
        tcp_port: hint.tcp_port,
        client_id: u32::from_be_bytes(ip.octets()),
        low_id: false,
        obfuscated: user_hash.is_some(),
        obfuscation_options: None,
        user_hash,
        source_server: None,
        buddy_id: None,
        buddy_endpoint: None,
        source_udp_port: None,
    })
}

pub(crate) fn configured_server_attempts(config: &Ed2kConfig) -> usize {
    config
        .server_entries
        .len()
        .max(config.server_endpoints.len())
        .max(1)
}

pub(crate) fn global_udp_source_batch_server_attempts(config: &Ed2kConfig) -> usize {
    // WHY: MFC's UDP source walk uses the server list, not the tiny diagnostic
    // budget. Batched Rust sends selected packets before waiting for replies.
    configured_server_attempts(config)
}

pub(crate) fn exact_ed2k_hash_query_token(query: &str) -> Option<String> {
    let trimmed = query.trim();
    let candidate = trimmed
        .strip_prefix(ED2K_HASH_ONLY_QUERY_PREFIX)
        .unwrap_or(trimmed)
        .trim();
    if candidate.len() == 32 && candidate.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(candidate.to_ascii_lowercase())
    } else {
        None
    }
}

#[cfg(test)]
pub(crate) fn ed2k_keyword_server_attempts(config: &Ed2kConfig, query: &str) -> usize {
    let requested_budget = if exact_ed2k_hash_query_token(query).is_some() {
        config.exact_hash_keyword_server_attempt_budget
    } else {
        config.keyword_server_attempt_budget
    };
    requested_budget
        .max(1)
        .min(configured_server_attempts(config))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LearnedEd2kMetadata {
    pub(crate) canonical_name: Option<String>,
    pub(crate) file_size: Option<u64>,
}

impl LearnedEd2kMetadata {
    pub(crate) fn merge_missing_from(&mut self, other: Self) {
        if self.canonical_name.is_none() {
            self.canonical_name = other.canonical_name;
        }
        if self.file_size.is_none() {
            self.file_size = other.file_size;
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.canonical_name.is_some() && self.file_size.is_some()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.canonical_name.is_none() && self.file_size.is_none()
    }
}

pub(crate) fn normalized_optional_canonical_name(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) fn hash_only_ed2k_search_query(file_hash: Ed2kHash) -> String {
    format!("{ED2K_HASH_ONLY_QUERY_PREFIX}{file_hash}")
}

pub(crate) fn select_ed2k_keyword_metadata(
    results: &[Ed2kSearchFile],
    file_hash: Ed2kHash,
) -> Option<LearnedEd2kMetadata> {
    results
        .iter()
        .filter(|result| result.file_hash == file_hash)
        .filter_map(|result| {
            let metadata = LearnedEd2kMetadata {
                canonical_name: normalized_optional_canonical_name(result.file_name.as_deref()),
                file_size: result.file_size.filter(|file_size| *file_size != 0),
            };
            (!metadata.is_empty()).then_some((
                metadata.file_size.is_some(),
                metadata.canonical_name.is_some(),
                result.source_count.unwrap_or_default(),
                metadata,
            ))
        })
        .max_by_key(|(has_size, has_name, source_count, _)| (*has_size, *has_name, *source_count))
        .map(|(_, _, _, metadata)| metadata)
}

pub(crate) fn select_kad_keyword_metadata(
    result: &KadSearchResult,
    file_hash: Ed2kHash,
) -> Option<LearnedEd2kMetadata> {
    if result.hash != file_hash {
        return None;
    }
    let metadata = LearnedEd2kMetadata {
        canonical_name: result
            .names
            .iter()
            .find_map(|name| normalized_optional_canonical_name(Some(name))),
        file_size: result.size.filter(|file_size| *file_size != 0),
    };
    (!metadata.is_empty()).then_some(metadata)
}

pub(crate) fn significant_keyword_words(query: &str) -> Vec<String> {
    let words = query
        .split(|char: char| !char.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(|word| word.to_lowercase())
        .filter(|word| word.len() >= 3)
        .collect::<Vec<_>>();
    if words.is_empty() {
        vec![query.to_lowercase()]
    } else {
        words
    }
}

pub(crate) fn significant_keyword_words_unique(query: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    significant_keyword_words(query)
        .into_iter()
        .filter(|word| seen.insert(word.clone()))
        .collect()
}

pub(crate) fn keyword_target(query: &str) -> NodeId {
    let first_word = exact_ed2k_hash_query_token(query).unwrap_or_else(|| {
        significant_keyword_words(query)
            .into_iter()
            .next()
            .unwrap_or_else(|| query.to_lowercase())
    });
    let mut hasher = Md4::new();
    hasher.update(first_word.as_bytes());
    let digest: [u8; 16] = hasher.finalize().into();
    NodeId::from_be_bytes(digest)
}

pub(crate) fn sort_download_sources(sources: &mut [Ed2kFoundSource]) {
    sources.sort_by_key(|source| {
        (
            !source.is_direct_dialable(),
            source.user_hash.is_none(),
            source.obfuscation_options.is_none(),
        )
    });
}

pub(crate) fn source_endpoint_key(source: &Ed2kFoundSource) -> (Ipv4Addr, u16) {
    (source.ip, source.tcp_port)
}

pub(crate) fn direct_download_candidate_sources(
    sources: &[Ed2kFoundSource],
    attempted_direct_endpoints: &HashSet<(Ipv4Addr, u16)>,
) -> Vec<Ed2kFoundSource> {
    let mut seen_endpoints = HashSet::new();
    sources
        .iter()
        .filter(|source| {
            if !source.is_direct_dialable() {
                return false;
            }
            let endpoint = source_endpoint_key(source);
            !attempted_direct_endpoints.contains(&endpoint) && seen_endpoints.insert(endpoint)
        })
        .cloned()
        .collect()
}

pub(crate) fn new_direct_ed2k_source_count(
    sources: &[Ed2kFoundSource],
    attempted_direct_endpoints: &HashSet<(Ipv4Addr, u16)>,
) -> usize {
    direct_download_candidate_sources(sources, attempted_direct_endpoints).len()
}

pub(crate) fn manifest_has_ed2k_transfer_progress(manifest: &Ed2kResumeManifest) -> bool {
    manifest.completed
        || manifest.md4_hashset_acquired
        || !manifest.verified_ranges.is_empty()
        || manifest.pieces.iter().any(|piece| piece.bytes_written != 0)
}

pub(crate) fn should_skip_no_progress_source_requery(
    had_direct_sources: bool,
    manifest_has_progress: bool,
    new_direct_source_count: usize,
    completed_source_requery_rounds: usize,
) -> bool {
    had_direct_sources
        && !manifest_has_progress
        && new_direct_source_count == 0
        && completed_source_requery_rounds != 0
}

pub(crate) fn should_refresh_ed2k_server_sources(source_requery_round: usize) -> bool {
    // WHY: eMule's local ED2K server source request is per-file paced by
    // SERVERREASKTIME (15 minutes). Rust's short retry rounds are only seconds
    // apart, so they may reuse remembered/Kad sources but must not hit servers.
    source_requery_round == 0
}

pub(crate) fn should_query_server_udp_source_supplement(
    existing_source_count: usize,
    udp_source_cap: usize,
) -> bool {
    // Oracle CPartFile::Process keeps the global UDP server source walk active
    // while the file holds fewer sources than GetMaxSourcePerFileUDP()
    // (= min(maxSources * 3/4, 100)). 0 = uncapped.
    udp_source_cap == 0 || existing_source_count < udp_source_cap
}

pub(crate) fn global_udp_source_search_excluded_endpoint(
    has_background_search: bool,
    connected_endpoint: Option<SocketAddr>,
) -> Option<SocketAddr> {
    // WHY: eMule queries the connected server over its long-lived TCP session and
    // skips it during global UDP source walks. Querying it again over UDP wastes
    // scarce live-server budget and drifts from the stock source-search cadence.
    has_background_search
        .then_some(connected_endpoint)
        .flatten()
}

pub(crate) fn should_adopt_hash_only_metadata_name(transfer: &Transfer) -> bool {
    let name = transfer.name.trim();
    name.is_empty() || name.eq_ignore_ascii_case(&transfer.hash)
}

pub(crate) fn ed2k_server_callback_route(
    source_server: Option<SocketAddr>,
    connected_server: Option<SocketAddr>,
) -> Ed2kServerCallbackRoute {
    // WHY: stock eMule only sends OP_CALLBACKREQUEST through the currently
    // connected server when the LowID source is registered there. It does not
    // open ad-hoc TCP logins to another server just to relay a callback.
    match (source_server, connected_server) {
        (Some(source_server), Some(connected_server)) if source_server == connected_server => {
            Ed2kServerCallbackRoute::BackgroundSession
        }
        _ => Ed2kServerCallbackRoute::Unavailable,
    }
}

/// Whether we may emit a server `OP_CALLBACKREQUEST` for a LowID source,
/// mirroring `CanDoCallback` (emule.cpp:2952-2969) restricted to the
/// server-callback branch that `TryToConnect` reaches (BaseClient.cpp:1507-1516,
/// `CCS_SERVERCALLBACK`). That branch is only entered for a source registered on
/// our currently connected server, and `CanDoCallback` forbids it entirely
/// unless WE are HighID on the ed2k server (`ed2k && !eLow`). A firewalled
/// (LowID) node asking its own server to relay a callback to a same-server LowID
/// source "breaks the protocol and will get us banned", so we suppress it.
pub(crate) fn ed2k_server_callback_permitted(
    self_tcp_firewalled: bool,
    source_server: Option<SocketAddr>,
    connected_server: Option<SocketAddr>,
) -> bool {
    !self_tcp_firewalled
        && matches!(
            ed2k_server_callback_route(source_server, connected_server),
            Ed2kServerCallbackRoute::BackgroundSession
        )
}

pub(crate) fn should_query_kad_source_supplement(
    existing_source_count: usize,
    udp_source_cap: usize,
) -> bool {
    // Oracle CPartFile::Process gates the Kad file-source search on the same
    // GetMaxSourcePerFileUDP() cap as the UDP server walk. 0 = uncapped.
    udp_source_cap == 0 || existing_source_count < udp_source_cap
}

pub(crate) fn kad_source_result_to_ed2k_found_source(
    result: SourceResult,
) -> Option<Ed2kFoundSource> {
    // Oracle `CDownloadQueue::KademliaSearchFile`: types 3/5 are firewalled LowID
    // sources reachable only through their Kad buddy (server-/buddy-assisted
    // callback). For those we carry the buddy id + buddy relay endpoint so the
    // source can be reasked via its buddy (OP_REASKCALLBACKUDP) rather than dialed.
    // Type 2 is never used ("Some clients will process it wrong"); type 6 is a
    // firewalled peer reachable ONLY via a direct UDP callback and is dropped
    // when its connect options lack the direct-callback bit (0x08), both
    // mirroring the oracle switch.
    match result.source_type {
        2 => return None,
        6 if result.obfuscation_options.is_none_or(|options| options & 0x08 == 0) => {
            tracing::debug!(
                "dropping Kad source type 6 without the direct-callback connect-options bit"
            );
            return None;
        }
        _ => {}
    }
    let direct_callback_only = result.source_type == 6;
    let firewalled_buddy = result.is_firewalled_buddy_source();
    let buddy_endpoint = match (result.buddy_ip, result.buddy_port) {
        (Some(buddy_ip), buddy_port) if firewalled_buddy && buddy_port != 0 => {
            Some((buddy_ip, buddy_port))
        }
        _ => None,
    };
    let buddy_id = if firewalled_buddy {
        result.buddy_id
    } else {
        None
    };
    Some(Ed2kFoundSource {
        file_hash: result.file_hash,
        ip: result.ip,
        tcp_port: result.tcp_port,
        client_id: u32::from(result.ip),
        // Buddy-relayed (3/5) and direct-callback (6) sources are firewalled:
        // never direct-dial them.
        low_id: firewalled_buddy || direct_callback_only,
        obfuscated: result.obfuscation_options.is_some(),
        obfuscation_options: result.obfuscation_options,
        user_hash: Some(result.source_id.0),
        source_server: None,
        buddy_id,
        buddy_endpoint,
        source_udp_port: (result.udp_port != 0).then_some(result.udp_port),
    })
}

pub(crate) async fn collect_kad_ed2k_metadata(
    dht: &DhtNode,
    query: &str,
    file_hash: Ed2kHash,
    timeout: Duration,
) -> Option<LearnedEd2kMetadata> {
    let cancel = CancellationToken::new();
    let mut stream = dht.search_keywords_with_cancel_and_class(
        keyword_target(query),
        cancel.clone(),
        RpcWorkClass::Interactive,
    );
    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);
    let mut learned = LearnedEd2kMetadata::default();
    let mut result_count: u32 = 0;

    loop {
        tokio::select! {
            _ = &mut sleep => break,
            result = stream.next() => {
                let Some(result) = result else {
                    break;
                };
                result_count = result_count.saturating_add(1);
                if let Some(candidate) = select_kad_keyword_metadata(&result, file_hash) {
                    learned.merge_missing_from(candidate);
                    if learned.is_complete() {
                        break;
                    }
                }
            }
        }
    }

    cancel.cancel();
    // kad_event lookup_complete (uniform-diagnostics-v2 §3.3): keyword lookup done.
    crate::diag_kad_event::lookup_complete(
        crate::diag_kad_event::KAD_SEARCH_TYPE_KEYWORD,
        result_count,
    );
    (!learned.is_empty()).then_some(learned)
}

#[allow(clippy::cognitive_complexity)]
pub(crate) async fn collect_kad_ed2k_sources(
    dht: &DhtNode,
    file_hash: Ed2kHash,
    file_size: u64,
    timeout: Duration,
) -> Vec<Ed2kFoundSource> {
    let mut sources = Vec::new();
    let deadline = Instant::now() + timeout;
    let retry_delay = Duration::from_millis(ED2K_DOWNLOAD_KAD_SOURCE_RETRY_DELAY_MS);
    let mut attempts = 0usize;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        attempts += 1;
        let cancel = CancellationToken::new();
        let mut stream = dht.search_sources_with_cancel(file_hash, file_size, cancel.clone());

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                cancel.cancel();
                break;
            }
            let wait = if sources.is_empty() {
                remaining
            } else {
                remaining.min(Duration::from_millis(
                    ED2K_DOWNLOAD_KAD_SOURCE_QUIET_DELAY_MS,
                ))
            };
            match tokio::time::timeout(wait, stream.next()).await {
                Ok(Some(result)) => {
                    merge_download_sources(
                        &mut sources,
                        kad_source_result_to_ed2k_found_source(result)
                            .into_iter()
                            .collect(),
                    );
                    if sources.len() >= ED2K_DOWNLOAD_KAD_SOURCE_CAP {
                        cancel.cancel();
                        tracing::info!(
                            "ED2K Kad source lookup reached cap file_hash={} attempts={} source_count={}",
                            file_hash,
                            attempts,
                            sources.len()
                        );
                        // kad_event lookup_complete (uniform-diagnostics-v2 §3.3).
                        crate::diag_kad_event::lookup_complete(
                            crate::diag_kad_event::KAD_SEARCH_TYPE_FILE,
                            sources.len() as u32,
                        );
                        return sources;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    cancel.cancel();
                    break;
                }
            }
        }

        cancel.cancel();
        if !sources.is_empty() {
            tracing::info!(
                "ED2K Kad source lookup produced file_hash={} attempts={} source_count={}",
                file_hash,
                attempts,
                sources.len()
            );
            // kad_event lookup_complete (uniform-diagnostics-v2 §3.3).
            crate::diag_kad_event::lookup_complete(
                crate::diag_kad_event::KAD_SEARCH_TYPE_FILE,
                sources.len() as u32,
            );
            return sources;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining <= retry_delay {
            break;
        }
        tokio::time::sleep(retry_delay).await;
    }

    tracing::info!(
        "ED2K Kad source lookup exhausted file_hash={} attempts={} source_count=0",
        file_hash,
        attempts
    );
    // kad_event lookup_complete (uniform-diagnostics-v2 §3.3): exhausted = 0 found.
    crate::diag_kad_event::lookup_complete(
        crate::diag_kad_event::KAD_SEARCH_TYPE_FILE,
        sources.len() as u32,
    );
    sources
}

/// Identity used to recognize and drop our own client from a learned source set
/// (eMule `CDownloadQueue::CheckAndAddSource`: a source whose user-hash equals
/// ours, or whose IP/client-id + port equals ours, is never added as a source).
#[derive(Debug, Clone)]
pub(crate) struct OwnSourceIdentity {
    /// Our advertised user hash.
    pub(crate) user_hash: [u8; 16],
    /// Our advertised public endpoints `(ip, tcp_port)` that a peer could report
    /// us as. Both the externally-advertised endpoint and the local bind endpoint
    /// are checked so a self-source is dropped regardless of which one a server or
    /// Kad reflected back.
    pub(crate) endpoints: Vec<(Ipv4Addr, u16)>,
}

impl OwnSourceIdentity {
    /// `true` when `source` is us (same user-hash, or same `(ip, tcp_port)`),
    /// mirroring eMule's self-source rejection in `CheckAndAddSource`.
    pub(crate) fn matches(&self, source: &Ed2kFoundSource) -> bool {
        if source.user_hash == Some(self.user_hash) {
            return true;
        }
        self.endpoints
            .iter()
            .any(|(ip, port)| *ip == source.ip && *port == source.tcp_port && *port != 0)
    }
}

/// Drop sources that are our own client (self-source) — eMule never adds a source
/// whose user-hash or `(ip, port)` is ours. A user-hash-less source whose port is
/// zero is left untouched here (it is not a meaningful endpoint match).
pub(crate) fn drop_self_sources(
    sources: &mut Vec<Ed2kFoundSource>,
    identity: &OwnSourceIdentity,
) -> usize {
    let before = sources.len();
    sources.retain(|source| !identity.matches(source));
    before - sources.len()
}

pub(crate) fn merge_download_sources(
    target: &mut Vec<Ed2kFoundSource>,
    incoming: Vec<Ed2kFoundSource>,
) {
    let mut seen =
        target
            .iter()
            .map(source_key)
            .collect::<HashSet<(Ipv4Addr, u16, Option<[u8; 16]>, Option<u8>)>>();
    for source in incoming {
        if seen.insert(source_key(&source)) {
            target.push(source);
        } else if let Some(existing) = target
            .iter_mut()
            .find(|existing| source_key(existing) == source_key(&source))
            && existing.source_server.is_none()
            && source.source_server.is_some()
        {
            existing.source_server = source.source_server;
        }
    }
}

#[cfg(test)]
mod tests;
