//! REST-facing data-transfer structs and their serde helpers.
//! Re-exported from the crate root so existing `emulebb_core::...` paths keep
//! working unchanged.

use std::sync::{Arc, atomic::AtomicBool};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
};

use chrono::{DateTime, Utc};
use emulebb_ed2k::{
    NatConfig, config::Ed2kRuntimeConfig, ed2k_tcp::Ed2kSecureIdent, ipfilter::IpFilter,
    normalize_ed2k_file_name,
};
use emulebb_index::{KadLocalStoreConfig, SnoopQueueConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub api_version: String,
    pub lifecycle: AppLifecycle,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppLifecycle {
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub lifecycle: AppLifecycle,
    pub uptime_secs: u64,
    pub kad: NetworkStatus,
    pub ed2k: NetworkStatus,
    pub indexing: IndexingStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkStatus {
    pub running: bool,
    pub connected: bool,
    pub peer_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewalled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrapping: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_progress: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lan_mode: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<u64>,
    /// Local Kad index size: total source publish entries we store (oracle
    /// `CIndexed::m_uTotalIndexSource`). `None` when Kad is not running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexed_sources: Option<u64>,
    /// Local Kad index size: total keyword publish entries we store (oracle
    /// `CIndexed::m_uTotalIndexKeyword`). `None` when Kad is not running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexed_keywords: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_queued: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub already_running: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub address: String,
    pub port: u16,
    pub endpoint: String,
    pub name: String,
    pub priority: String,
    #[serde(rename = "static")]
    pub static_server: bool,
    pub enabled: bool,
    pub connected: bool,
    pub connecting: bool,
    pub current: bool,
    pub description: String,
    pub dyn_ip: String,
    #[serde(default)]
    pub auxiliary_ports: Vec<u16>,
    pub failed_count: u32,
    pub hard_files: u64,
    pub ip: String,
    pub ping: u32,
    pub soft_files: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_files_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_files_batch_max: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_files_min_interval_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_files_fallback_reason: Option<String>,
    pub offer_files_published_entries: usize,
    pub offer_files_pending_entries: usize,
    pub version: String,
    pub obfuscation_tcp_port: Option<u16>,
    pub udp_flags: Option<u32>,
    /// Internal persisted server-UDP obfuscation state. These fields are kept
    /// out of the public REST contract but feed the next runtime configuration.
    #[serde(default, skip)]
    pub obfuscation_udp_port: Option<u16>,
    #[serde(default, skip)]
    pub udp_key: Option<u32>,
    #[serde(default, skip)]
    pub udp_key_ip: Option<u32>,
    #[serde(default, skip)]
    pub max_users: u64,
    #[serde(default, skip)]
    pub low_id_users: u64,
    pub users: u64,
    pub files: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    pub host_name_resolved_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostNameResolution {
    pub host_name: Option<String>,
    pub host_name_status: String,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    pub host_name_resolved_at: Option<DateTime<Utc>>,
    pub host_name_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KadNode {
    pub node_id: String,
    pub ip: String,
    pub host_name: Option<String>,
    pub host_name_status: String,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    pub host_name_resolved_at: Option<DateTime<Utc>>,
    pub host_name_error: Option<String>,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub kad_version: u8,
    pub verified: bool,
    pub contact_type: String,
    pub probe_type: u8,
    pub udp_key_known: bool,
    pub hello_source_udp_port: Option<u16>,
    pub udp_firewalled: bool,
    pub tcp_firewalled: bool,
    pub received_hello_packet: bool,
    pub bootstrap: bool,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexingStatus {
    pub enabled: bool,
    pub backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferStats {
    pub resources: DownloadResources,
    pub completed: usize,
    pub total: usize,
}

/// Approximate runtime observations, not admission authority or total daemon RAM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadResources {
    pub active: usize,
    pub preparing: usize,
    pub waiting: u64,
    pub concurrency: DownloadConcurrency,
    pub resident_memory: DownloadResidentMemory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadConcurrency {
    pub mode: DownloadConcurrencyMode,
    pub configured_limit: Option<u32>,
    pub target: usize,
    pub burst_active: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DownloadConcurrencyMode {
    Automatic,
    Fixed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadResidentMemory {
    pub used_bytes: usize,
    pub soft_target_bytes: usize,
    pub limit_bytes: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchSpec {
    #[serde(default, with = "crate::rest_model_serde::optional_decimal_id")]
    pub parent_search_id: Option<i64>,
    pub query: String,
    #[serde(default = "default_search_method")]
    pub method: String,
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub extension: String,
    #[serde(default)]
    pub min_size_bytes: Option<u64>,
    #[serde(default)]
    pub max_size_bytes: Option<u64>,
    #[serde(default)]
    pub min_availability: Option<u32>,
    #[serde(default)]
    pub min_complete_sources: Option<u32>,
    #[serde(default)]
    pub min_bitrate_kbps: Option<u32>,
    #[serde(default)]
    pub min_length_seconds: Option<u32>,
    #[serde(default)]
    pub codec: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub album: String,
    #[serde(default)]
    pub artist: String,
}

impl SearchSpec {
    /// Canonicalize equivalent public search inputs before they are queued,
    /// persisted, compared, or encoded for the wire.
    pub fn canonicalize(&mut self) {
        self.query = self
            .query
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        self.method = self.method.trim().to_ascii_lowercase();
        if self.method.is_empty() {
            self.method = default_search_method();
        }
        self.r#type = self.r#type.trim().to_ascii_lowercase();
        self.extension = self
            .extension
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase();
        self.min_size_bytes = self.min_size_bytes.filter(|value| *value != 0);
        self.max_size_bytes = self.max_size_bytes.filter(|value| *value != 0);
        self.min_availability = self.min_availability.filter(|value| *value != 0);
        self.min_complete_sources = self.min_complete_sources.filter(|value| *value != 0);
        self.min_bitrate_kbps = self.min_bitrate_kbps.filter(|value| *value != 0);
        self.min_length_seconds = self.min_length_seconds.filter(|value| *value != 0);
        self.codec = self.codec.trim().to_string();
        self.title = self.title.trim().to_string();
        self.album = self.album.trim().to_string();
        self.artist = self.artist.trim().to_string();
    }

    /// Validate transport-independent search invariants at the core boundary.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.parent_search_id.is_none_or(|id| id > 0),
            "parentSearchId must be positive"
        );
        anyhow::ensure!(!self.query.is_empty(), "query must not be empty");
        anyhow::ensure!(
            !self.query.chars().any(char::is_control),
            "query must be valid UTF-8 without control characters"
        );
        anyhow::ensure!(
            self.query.encode_utf16().count() <= 160,
            "query must be at most 160 characters"
        );
        anyhow::ensure!(
            matches!(
                self.method.as_str(),
                "automatic" | "server" | "global" | "kad"
            ),
            "search method must be one of automatic, server, global, kad"
        );
        anyhow::ensure!(
            matches!(
                self.r#type.as_str(),
                "" | "arc"
                    | "audio"
                    | "iso"
                    | "image"
                    | "pro"
                    | "video"
                    | "doc"
                    | "emulecollection"
            ),
            "type is not supported"
        );
        if let (Some(min_size), Some(max_size)) = (self.min_size_bytes, self.max_size_bytes) {
            anyhow::ensure!(
                max_size >= min_size,
                "maxSizeBytes must be greater than or equal to minSizeBytes"
            );
        }
        anyhow::ensure!(
            self.min_availability.is_none_or(|value| value <= 1_000_000),
            "minAvailability must be an unsigned number in the range 0..1000000"
        );
        anyhow::ensure!(
            self.min_complete_sources
                .is_none_or(|value| value <= 1_000_000),
            "minCompleteSources must be an unsigned number in the range 0..1000000"
        );
        for (field, value) in [
            ("extension", self.extension.as_str()),
            ("codec", self.codec.as_str()),
            ("title", self.title.as_str()),
            ("album", self.album.as_str()),
            ("artist", self.artist.as_str()),
        ] {
            anyhow::ensure!(
                !value.chars().any(char::is_control),
                "{field} must not contain control characters"
            );
            anyhow::ensure!(
                value.chars().count() <= 256,
                "{field} must be at most 256 characters"
            );
        }
        Ok(())
    }
}

/// The create-search payload is the immutable specification stored with the
/// resulting search session.
pub type SearchCreate = SearchSpec;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchProgress {
    /// Stable machine-readable phase token.
    pub phase: String,
    /// Completed work units for phases with measurable progress.
    pub completed_units: u32,
    /// Total work units when knowable. Kad traversal intentionally leaves this
    /// absent because its contact frontier changes as replies arrive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_units: Option<u32>,
    /// Human-readable unit label such as `servers`; empty for unbounded phases.
    pub unit: String,
}

impl SearchProgress {
    pub(crate) fn new(
        phase: impl Into<String>,
        completed_units: usize,
        total_units: Option<usize>,
        unit: impl Into<String>,
    ) -> Self {
        Self {
            phase: phase.into(),
            completed_units: u32::try_from(completed_units).unwrap_or(u32::MAX),
            total_units: total_units.map(|value| u32::try_from(value).unwrap_or(u32::MAX)),
            unit: unit.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Search {
    pub id: String,
    pub spec: SearchSpec,
    /// Concrete backend selected for network execution. `None` means no
    /// network backend has been selected yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_method: Option<String>,
    pub status: String,
    /// Honest reason for a non-completed status (additive REST field
    /// `statusReason`): e.g. `waiting-for-server-connection` while `queued`,
    /// or the explicit failure reason when `error`. `None` when completed or
    /// running normally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_reason: Option<String>,
    #[serde(default)]
    pub progress: SearchProgress,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResultMedia {
    pub artist: String,
    pub album: String,
    pub title: String,
    pub length_seconds: u32,
    pub bitrate_kbps: u32,
    pub codec: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub id: String,
    pub search_id: String,
    pub r#type: String,
    pub hash: String,
    pub name: String,
    pub size_bytes: Option<u64>,
    pub sources: u32,
    pub complete_sources: u32,
    /// ED2K source identity embedded in a server search result. Kept internal
    /// so downloading that result can seed the transfer immediately.
    #[serde(default, skip_serializing)]
    pub source_client_id: Option<u32>,
    /// TCP port paired with `source_client_id`.
    #[serde(default, skip_serializing)]
    pub source_client_port: Option<u16>,
    pub file_type: String,
    #[serde(default)]
    pub media: SearchResultMedia,
    #[serde(default)]
    pub rating: u8,
    /// AICH search-result metadata retained for integrity evidence and future
    /// corroboration. The REST response projection exposes this deliberately
    /// as `aichHash`; generic serialization remains private-by-default.
    #[serde(default, skip_serializing)]
    pub aich_hash: String,
    pub complete: bool,
    pub directory: String,
    /// Every distinct observation that contributed to this hash-level result.
    /// The top-level fields are a deterministic presentation aggregate; these
    /// rows retain alternate names, availability claims, integrity metadata,
    /// and immediately usable source identities without conflating them.
    #[serde(default)]
    pub observations: Vec<SearchResultObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResultObservation {
    /// Backend that produced this observation (`server`, `global`, or `kad`). A later transport-specific locator can refine this
    /// without changing the hash-level result identity.
    pub origin: String,
    /// Endpoint of the server or Kad node that reported this observation.
    /// Absent when no reporting endpoint was captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reporter_endpoint: Option<String>,
    pub name: String,
    pub size_bytes: Option<u64>,
    pub sources: u32,
    pub complete_sources: u32,
    #[serde(default, skip_serializing)]
    pub source_client_id: Option<u32>,
    #[serde(default, skip_serializing)]
    pub source_client_port: Option<u16>,
    pub file_type: String,
    #[serde(default)]
    pub media: SearchResultMedia,
    #[serde(default)]
    pub rating: u8,
    /// Exact AICH identity claimed by this observation. The REST projection
    /// exposes it as `aichHash` so conflicting server claims stay inspectable.
    #[serde(default, skip_serializing)]
    pub aich_hash: String,
    pub complete: bool,
    pub directory: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub observed_at: DateTime<Utc>,
}

impl SearchResult {
    pub(crate) fn from_observation(
        search_id: String,
        r#type: String,
        hash: String,
        observation: SearchResultObservation,
    ) -> Self {
        Self {
            id: String::new(),
            search_id,
            r#type,
            hash,
            name: normalize_ed2k_file_name(&observation.name),
            size_bytes: observation.size_bytes,
            sources: observation.sources,
            complete_sources: observation.complete_sources,
            source_client_id: observation.source_client_id,
            source_client_port: observation.source_client_port,
            file_type: observation.file_type.clone(),
            media: observation.media.clone(),
            rating: observation.rating,
            aich_hash: observation.aich_hash.clone(),
            complete: observation.complete,
            directory: observation.directory.clone(),
            observations: vec![observation],
        }
    }

    pub(crate) fn from_observations(
        search_id: String,
        r#type: String,
        hash: String,
        first: SearchResultObservation,
        observations: impl IntoIterator<Item = SearchResultObservation>,
    ) -> Self {
        let mut result = Self::from_observation(search_id, r#type, hash, first);
        for observation in observations {
            if !result
                .observations
                .iter()
                .any(|existing| observations_are_equivalent(existing, &observation))
            {
                result.observations.push(observation);
            }
        }
        result.recompute_observation_aggregate();
        result
    }

    fn recompute_observation_aggregate(&mut self) {
        let Some(display) = self.observations.iter().max_by(|left, right| {
            observation_quality(left, &self.hash)
                .cmp(&observation_quality(right, &self.hash))
                // Stable, arrival-order-independent tie breaker: prefer the
                // lexicographically smaller case-folded display name.
                .then_with(|| right.name.to_lowercase().cmp(&left.name.to_lowercase()))
        }) else {
            return;
        };
        self.name = majority_observation_name(&self.observations, &self.hash)
            .unwrap_or_else(|| normalize_ed2k_file_name(&display.name));
        self.sources =
            aggregate_observation_count(&self.observations, |observation| observation.sources);
        self.complete_sources = aggregate_observation_count(&self.observations, |observation| {
            observation.complete_sources
        });
        self.rating = self
            .observations
            .iter()
            .map(|observation| observation.rating)
            .max()
            .unwrap_or_default();
        self.complete = self
            .observations
            .iter()
            .any(|observation| observation.complete);

        let source = self
            .observations
            .iter()
            .filter(|observation| {
                observation
                    .source_client_id
                    .zip(observation.source_client_port)
                    .is_some()
            })
            .max_by_key(|observation| observation_quality(observation, &self.hash));
        self.source_client_id = source.and_then(|observation| observation.source_client_id);
        self.source_client_port = source.and_then(|observation| observation.source_client_port);

        if let Some(file_type) = self
            .observations
            .iter()
            .filter(|observation| {
                !observation.file_type.is_empty()
                    && !observation.file_type.eq_ignore_ascii_case("unknown")
            })
            .max_by_key(|observation| observation_quality(observation, &self.hash))
            .map(|observation| observation.file_type.clone())
        {
            self.file_type = file_type;
        }
        self.media.artist = best_media_observation(&self.observations, &self.hash, |media| {
            !media.artist.is_empty()
        })
        .map(|observation| observation.media.artist.clone())
        .unwrap_or_default();
        self.media.album = best_media_observation(&self.observations, &self.hash, |media| {
            !media.album.is_empty()
        })
        .map(|observation| observation.media.album.clone())
        .unwrap_or_default();
        self.media.title = best_media_observation(&self.observations, &self.hash, |media| {
            !media.title.is_empty()
        })
        .map(|observation| observation.media.title.clone())
        .unwrap_or_default();
        self.media.length_seconds =
            best_media_observation(&self.observations, &self.hash, |media| {
                media.length_seconds != 0
            })
            .map(|observation| observation.media.length_seconds)
            .unwrap_or_default();
        self.media.bitrate_kbps = best_media_observation(&self.observations, &self.hash, |media| {
            media.bitrate_kbps != 0
        })
        .map(|observation| observation.media.bitrate_kbps)
        .unwrap_or_default();
        self.media.codec = best_media_observation(&self.observations, &self.hash, |media| {
            !media.codec.is_empty()
        })
        .map(|observation| observation.media.codec.clone())
        .unwrap_or_default();
        self.aich_hash = self
            .observations
            .iter()
            .filter(|observation| !observation.aich_hash.is_empty())
            .max_by_key(|observation| observation_quality(observation, &self.hash))
            .map(|observation| observation.aich_hash.clone())
            .unwrap_or_default();
        self.directory = self
            .observations
            .iter()
            .filter(|observation| !observation.directory.is_empty())
            .max_by_key(|observation| observation_quality(observation, &self.hash))
            .map(|observation| observation.directory.clone())
            .unwrap_or_default();
    }
}

fn majority_observation_name(
    observations: &[SearchResultObservation],
    hash: &str,
) -> Option<String> {
    type Candidate<'a> = (
        std::collections::HashSet<(Option<&'a str>, Option<&'a str>)>,
        (bool, u32, u32, bool, u8),
    );
    let mut candidates = HashMap::<String, Candidate<'_>>::new();
    for observation in observations {
        let normalized = normalize_ed2k_file_name(&observation.name);
        if normalized.is_empty() {
            continue;
        }
        let reporter = observation.reporter_endpoint.as_deref();
        let unknown_origin = reporter.is_none().then_some(observation.origin.as_str());
        let candidate = candidates.entry(normalized).or_default();
        candidate.0.insert((reporter, unknown_origin));
        candidate.1 = candidate.1.max(observation_quality(observation, hash));
    }
    candidates
        .into_iter()
        .max_by(|(left_name, left), (right_name, right)| {
            left.0
                .len()
                .cmp(&right.0.len())
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| right_name.cmp(left_name))
        })
        .map(|(name, _)| name)
}

/// Aggregate availability without conflating incompatible network estimates.
///
/// Each eD2K server reports its own independent population, so its strongest
/// observation is summed with the strongest observation from every other
/// server. Kad observations are estimates of an overlapping
/// population; their strongest value competes with (rather than adds to) the
/// eD2K total.
fn aggregate_observation_count(
    observations: &[SearchResultObservation],
    count: impl Fn(&SearchResultObservation) -> u32,
) -> u32 {
    let mut ed2k_by_server = HashMap::<(bool, &str), u32>::new();
    let mut non_ed2k_max = 0_u32;

    for observation in observations {
        let value = count(observation);
        if matches!(observation.origin.as_str(), "server" | "global") {
            // A canonical endpoint unifies connected and global observations
            // from the same server. Unknown reporters share a conservative
            // bucket per origin rather than being summed blindly.
            let key = observation
                .reporter_endpoint
                .as_deref()
                .map_or((false, observation.origin.as_str()), |endpoint| {
                    (true, endpoint)
                });
            ed2k_by_server
                .entry(key)
                .and_modify(|current| *current = (*current).max(value))
                .or_insert(value);
        } else {
            non_ed2k_max = non_ed2k_max.max(value);
        }
    }

    ed2k_by_server
        .into_values()
        .fold(0_u32, u32::saturating_add)
        .max(non_ed2k_max)
}

fn best_media_observation<'a>(
    observations: &'a [SearchResultObservation],
    hash: &str,
    has_value: impl Fn(&SearchResultMedia) -> bool,
) -> Option<&'a SearchResultObservation> {
    observations
        .iter()
        .filter(|observation| has_value(&observation.media))
        .max_by_key(|observation| observation_quality(observation, hash))
}

pub(crate) fn observation_quality(
    observation: &SearchResultObservation,
    hash: &str,
) -> (bool, u32, u32, bool, u8) {
    (
        !observation.name.trim().is_empty() && !observation.name.eq_ignore_ascii_case(hash),
        observation.sources,
        observation.complete_sources,
        observation.size_bytes.is_some(),
        observation.rating,
    )
}

fn observations_are_equivalent(
    left: &SearchResultObservation,
    right: &SearchResultObservation,
) -> bool {
    left.origin == right.origin
        && left.reporter_endpoint == right.reporter_endpoint
        && left.name == right.name
        && left.size_bytes == right.size_bytes
        && left.sources == right.sources
        && left.complete_sources == right.complete_sources
        && left.source_client_id == right.source_client_id
        && left.source_client_port == right.source_client_port
        && left.file_type == right.file_type
        && left.media == right.media
        && left.rating == right.rating
        && left.aich_hash == right.aich_hash
        && left.complete == right.complete
        && left.directory == right.directory
}

#[cfg(test)]
mod search_result_name_tests {
    use super::{SearchResult, SearchResultMedia, SearchResultObservation};
    use chrono::Utc;

    fn observation(name: &str, origin: &str) -> SearchResultObservation {
        SearchResultObservation {
            origin: origin.to_string(),
            reporter_endpoint: None,
            name: name.to_string(),
            size_bytes: Some(1024),
            sources: 1,
            complete_sources: 0,
            source_client_id: None,
            source_client_port: None,
            file_type: "doc".to_string(),
            media: SearchResultMedia::default(),
            rating: 0,
            aich_hash: String::new(),
            complete: false,
            directory: String::new(),
            observed_at: Utc::now(),
        }
    }

    #[test]
    fn search_display_name_uses_normalized_majority_and_retains_raw_observations() {
        let result = SearchResult::from_observations(
            "search".to_string(),
            "doc".to_string(),
            "00112233445566778899aabbccddeeff".to_string(),
            observation("Wrong.bin", "server"),
            [
                observation("Caf%C3%A9.bin", "global"),
                observation("Cafe\u{301}.bin", "kad"),
            ],
        );

        assert_eq!(result.name, "Café.bin");
        assert_eq!(result.observations.len(), 3);
        assert!(
            result
                .observations
                .iter()
                .any(|observation| observation.name == "Caf%C3%A9.bin")
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DownloadCreate {
    pub source: DownloadCreateSource,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(
        default = "crate::rest_model_serde::download_intent::default",
        with = "crate::rest_model_serde::download_intent"
    )]
    pub intent: emulebb_metadata::DownloadIntent,
    #[serde(default)]
    pub redownload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DownloadCreateSource {
    Ed2kLink {
        link: String,
    },
    Content {
        hash: String,
        name: String,
        size_bytes: Option<u64>,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DownloadUpdate {
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_nullable_category",
        skip_serializing_if = "Option::is_none"
    )]
    pub category: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchResultDownloadCreate {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(
        default = "crate::rest_model_serde::download_intent::default",
        with = "crate::rest_model_serde::download_intent"
    )]
    pub intent: emulebb_metadata::DownloadIntent,
    #[serde(default)]
    pub redownload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Category {
    #[serde(skip)]
    pub id: i64,
    pub name: String,
    pub temp_dir: Option<String>,
    pub destination_dir: Option<String>,
    pub comment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CategoryCreate {
    pub name: String,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_nullable_string_field"
    )]
    pub temp_dir: NullableStringField,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_nullable_string_field"
    )]
    pub destination_dir: NullableStringField,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CategoryUpdate {
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_nullable_string_field"
    )]
    pub temp_dir: NullableStringField,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_nullable_string_field"
    )]
    pub destination_dir: NullableStringField,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NullableStringField {
    #[default]
    Missing,
    Null(()),
    Value(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Friend {
    pub user_hash: String,
    pub name: String,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    pub last_seen: Option<DateTime<Utc>>,
    pub address: Option<String>,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FriendCreate {
    pub user_hash: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalShareCreate {
    pub path: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalShare {
    pub hash: String,
    pub name: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub part_count: u32,
    pub ed2k_link: String,
    pub aich_root: String,
    pub path: String,
    pub priority: String,
    pub auto_upload_priority: bool,
    pub all_time_uploaded_bytes: u64,
    pub all_time_upload_requests: u64,
    pub all_time_upload_accepts: u64,
    pub comment: String,
    pub rating: u8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SharedFilePublishState {
    #[default]
    Unavailable,
    Waiting,
    Queued,
    Publishing,
    Partial,
    Published,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedFilePublishLane {
    pub state: SharedFilePublishState,
    pub last_success_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedFileKadKeywordPublish {
    pub state: SharedFilePublishState,
    pub published_keywords: usize,
    pub total_keywords: usize,
    pub last_success_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedFilePublicationStatus {
    pub ed2k: SharedFilePublishLane,
    pub kad_keyword: SharedFileKadKeywordPublish,
    pub kad_source: SharedFilePublishLane,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LibraryFileUpdate {
    #[serde(default)]
    pub upload_priority: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub rating: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transfer {
    #[serde(with = "crate::rest_model_serde::job_id")]
    pub id: emulebb_metadata::JobId,
    /// Internal execution authority; response deserialization never queues work.
    #[serde(skip)]
    pub(crate) execution_generation: u64,
    pub hash: String,
    #[serde(rename = "displayName")]
    pub name: String,
    pub path: String,
    /// Absolute path the completed payload was delivered to by its canonical
    /// name (under a category path or the global incoming dir), or `None` until
    /// the transfer completes and is delivered.
    pub delivered_path: Option<String>,
    /// Last finished-file delivery failure. Present while a verified download
    /// remains in `completing`; cleared after a successful retry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_error: Option<String>,
    pub size_bytes: u64,
    pub completed_bytes: u64,
    pub state: String,
    pub progress: f64,
    pub sources: u32,
    /// Sources currently transferring payload to us (live session count).
    pub sources_transferring: u32,
    pub download_speed_ki_bps: f64,
    /// Upload rate for this file; downloads do not serve from the transfer view
    /// so this is 0 (uploads are tracked under the upload queue).
    pub upload_speed_ki_bps: f64,
    /// Whether the transfer is stopped (master IsStopped): emitted alongside a
    /// `paused` state, matching the master contract's separate stopped flag.
    pub stopped: bool,
    pub ed2k_link: String,
    #[serde(skip)]
    pub category_id: Option<i64>,
    #[serde(rename = "category")]
    pub category_name: Option<String>,
    /// Estimated seconds to completion, or None when idle/complete.
    pub eta: Option<u64>,
    /// Unix ms when the transfer was created, when persisted.
    pub added_at: Option<i64>,
    /// Unix ms when the transfer completed, when persisted.
    pub completed_at: Option<i64>,
    /// Total ED2K parts (9.28 MB each) for the file.
    pub parts_total: u32,
    /// Parts fully downloaded and verified.
    pub parts_obtained: u32,
    /// One char per part: '#' obtained, '0' missing.
    pub parts_progress_text: String,
    /// Parts available from at least one live source (live session count).
    pub parts_available: u32,
    /// Whether this transfer's file lives in an incoming/download directory (so
    /// it is a file WE downloaded), as opposed to a file that is only shared from
    /// a configured shared directory. Lets a UI separate "completed downloads"
    /// from the static shared library even when a shared dir doubles as the
    /// incoming dir. Incomplete (still downloading) transfers are always true.
    pub in_incoming: bool,
}

impl Transfer {
    pub(crate) fn job_token(&self) -> emulebb_metadata::JobToken {
        emulebb_metadata::JobToken {
            job_id: self.id,
            generation: self.execution_generation,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadFileNameObservation {
    pub raw_name: String,
    pub normalized_name: String,
    pub origin: String,
    pub reporter_endpoint: Option<String>,
    pub observed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpFilterStatus {
    pub configured: bool,
    pub reloadable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub level: u32,
    pub range_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loaded_sha256: Option<String>,
}

/// One remembered ED2K peer source for a transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadSource {
    pub client_id: String,
    // The next four are internal-only; not in the eMuleBB `DownloadSource`
    // contract (peer is conveyed via `address`), so they are never serialized.
    #[serde(skip_serializing)]
    pub hash: String,
    #[serde(skip_serializing)]
    pub ip: String,
    #[serde(skip_serializing)]
    pub tcp_port: u16,
    pub port: u16,
    #[serde(skip_serializing)]
    pub endpoint: String,
    /// Per-source file description received through OP_FILEDESC. Exposed via
    /// the dedicated transfer-comments collection, not the source contract.
    #[serde(skip_serializing)]
    pub file_comment: String,
    #[serde(skip_serializing)]
    pub file_rating: u8,
    pub user_hash: Option<String>,
    pub user_name: String,
    pub client_software: String,
    pub reported_file_names: Vec<DownloadFileNameObservation>,
    pub reported_file_names_has_more: bool,
    pub download_state: String,
    pub download_rate_bytes_per_second: u64,
    pub available_parts: u32,
    pub part_count: u32,
    pub address: String,
    pub server_ip: String,
    pub server_port: u16,
    pub low_id: bool,
    pub queue_rank: u32,
    pub view_shared_files: bool,
    pub shared_files_request_pending: bool,
    // Internal-only; not in the contract, so never serialized.
    #[serde(skip_serializing)]
    pub banned: bool,
    #[serde(skip_serializing)]
    pub status: String,
}

/// One remote source's persisted file comment/rating for a transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferComment {
    pub source: String,
    pub user_name: Option<String>,
    pub file_name: String,
    pub comment: String,
    pub rating: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Upload {
    pub id: String,
    pub user_hash: Option<String>,
    pub client_software: Option<String>,
    pub upload_state: String,
    pub upload_rate_bytes_per_sec: u64,
    pub session_uploaded_bytes: u64,
    pub wait_time_seconds: u64,
    pub upload_duration_seconds: Option<u64>,
    pub address: String,
    pub port: u16,
    pub low_id: Option<bool>,
    pub friend_slot: bool,
    pub connected: bool,
    pub requested_file_hash: String,
    pub requested_file_name: Option<String>,
    pub requested_file_size_bytes: Option<u64>,
    pub file_parts_available: Option<u32>,
    pub file_parts_total: Option<u32>,
    /// Per-client upload score diagnostics, fetched through detail resources.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_breakdown: Option<UploadScoreBreakdown>,
    pub queue_rank: Option<usize>,
}

/// Upload-score modifier breakdown (eMuleBB `UploadScoreBreakdown` shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadScoreBreakdown {
    pub score: f64,
    pub credit_ratio: f64,
    pub file_priority_score: f64,
    pub low_ratio_applied: bool,
    pub low_ratio_bonus: u32,
    pub low_id_penalty_applied: bool,
    pub low_id_divisor: u32,
    pub old_client_penalty_applied: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadPolicyMetrics {
    pub base_slots: usize,
    pub elastic_slots: usize,
    pub active_slots: usize,
    pub active_sessions: usize,
    pub waiting_sessions: usize,
    pub upload_rate_bytes_per_sec: u64,
    pub upload_limit_bytes_per_sec: u64,
    pub elastic_underfill_bytes_per_sec: u64,
    pub elastic_underfill: bool,
    pub underfill_since_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadSourceMetrics {
    pub candidates: usize,
    pub a4af_candidates: usize,
    pub leased_peers: usize,
}

/// Live transfer throughput roll-up for the REST `stats` surface (oracle
/// `CDownloadQueue::GetDatarate` + `theStats.sessionReceivedBytes`/`sessionSentBytes`).
#[derive(Debug, Clone, Default)]
pub struct TransferThroughputStats {
    /// Aggregate live download rate across all active files, bytes/sec.
    pub download_rate_bytes_per_sec: u64,
    /// Payload bytes received since the runtime started.
    pub session_downloaded_bytes: u64,
    /// Payload bytes sent since the runtime started.
    pub session_uploaded_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Ed2kNetworkConfig {
    /// Original operator routing intent, independent of the resolved source address.
    pub egress_route: emulebb_ed2k::networking::EgressRoute,
    pub bind_ip: Ipv4Addr,
    pub kad_bind_addr: SocketAddr,
    pub listen_port: u16,
    pub user_hash: [u8; 16],
    pub secure_ident: Arc<Ed2kSecureIdent>,
    pub kad_local_store: KadLocalStoreConfig,
    pub kad_snoop_queue: SnoopQueueConfig,
    pub kad_passive_replay_enabled: bool,
    pub kad_bootstrap_endpoints: Vec<String>,
    pub kad_bootstrap_min_routing_contacts: usize,
    pub kad_publish_shared_files: bool,
    pub kad_republish_interval_secs: u64,
    pub kad_publish_contact_fanout: usize,
    /// Whether the periodic routing-table maintenance loop runs (oracle
    /// `CRoutingZone` OnBigTimer/OnSmallTimer: bucket refresh + dead-contact
    /// expiry + stale-contact HELLO re-probe). Default on.
    pub kad_routing_maintenance_enabled: bool,
    /// Whether the requester-side Kad UDP firewall self-check is driven.
    pub kad_udp_firewall_check_enabled: bool,
    /// Seconds between Kad UDP firewall self-check rounds (gentle cadence).
    pub kad_udp_firewall_check_interval_secs: u64,
    /// Whether the requester-side Kad TCP firewall recheck is driven (oracle
    /// FIREWALLED2_REQ / FIREWALLED_RES + TCP connect-back ack). Default on.
    pub kad_tcp_firewall_check_enabled: bool,
    /// Seconds between Kad TCP firewall recheck rounds (gentle cadence).
    pub kad_tcp_firewall_check_interval_secs: u64,
    /// Whether the Kad LowID buddy/firewalled-callback subsystem is active.
    /// Default on (per operator policy): when we are firewalled we seek a buddy,
    /// and we answer buddy requests from firewalled peers when we are reachable.
    pub kad_buddy_enabled: bool,
    pub nat_config: NatConfig,
    pub ed2k: Ed2kRuntimeConfig,
    /// Optional configured P2P bind IP. `None` is valid when the bind came from
    /// `p2pBindInterface` only; `bind_ip` carries the resolved runtime address.
    pub p2p_bind_ip: Option<Ipv4Addr>,
    /// Optional configured P2P bind interface name for runtime VPN Guard checks.
    pub p2p_bind_interface: Option<String>,
    /// Configured VPN-binding guard.
    pub vpn_guard: VpnGuardConfig,
    /// Whether the effective P2P bind IP is confirmed to belong to a named bind
    /// interface or a detected VPN-looking interface.
    pub vpn_interface_bound: bool,
    /// Runtime-updated VPN binding confirmation, overriding the startup snapshot.
    pub vpn_interface_bound_runtime: Option<Arc<AtomicBool>>,
    /// IPv4 range filter (ipfilter.dat). Empty when no filter is configured.
    /// Shares its backing across clones so a reload is observed live.
    pub ip_filter: IpFilter,
    /// Configured `ipfilter.dat` path, retained so [`EmulebbCore::reload_ip_filter`]
    /// can re-read it on demand (`CIPFilter::Reload`). `None` when no file is
    /// configured (the filter is then immutable-empty).
    pub ip_filter_path: Option<std::path::PathBuf>,
    /// Filter level threshold used when (re)parsing `ip_filter_path`.
    pub ip_filter_level: u32,
}

/// Configured VPN-binding guard. When enabled in `block` mode the client
/// refuses to start public P2P unless the bind is VPN-confirmed.
#[derive(Debug, Clone, Default)]
pub struct VpnGuardConfig {
    pub enabled: bool,
    pub mode: String,
    pub allowed_public_ip_cidrs: String,
}

/// One bound egress-probe outcome surfaced over REST (eMuleBB
/// `SBoundPublicIpv4ProbeResult` subset): the STUN (UDP) or HTTP (TCP) egress
/// public-IP check the VPN Guard runs, source-bound + pinned to the tunnel.
#[derive(Debug, Clone, Default)]
pub struct VpnGuardProbeStatus {
    pub attempted: bool,
    pub succeeded: bool,
    pub public_ip: Option<String>,
    pub provider: String,
    pub error: Option<String>,
}

/// Resolved VPN-guard state surfaced through the REST status surfaces.
#[derive(Debug, Clone, Default)]
pub struct VpnGuardStatus {
    pub enabled: bool,
    pub mode: String,
    pub allowed_public_ip_cidrs: String,
    pub startup_blocked: bool,
    pub startup_block_reason: String,
    /// The probe-confirmed public egress IPv4 (from the HTTP/STUN probes), when known.
    pub public_ip: Option<String>,
    /// Whether a bound egress probe resolved an allowlisted public IP with no observed leak.
    pub egress_verified: bool,
    /// Why the egress is not verified (empty when verified or no CIDR gate).
    pub egress_block_reason: String,
    /// The UDP/STUN bound egress-probe outcome.
    pub stun_probe: VpnGuardProbeStatus,
    /// The TCP/HTTP bound egress-probe outcome.
    pub http_probe: VpnGuardProbeStatus,
}

impl VpnGuardStatus {
    /// Disabled guard with the master "off" REST mode token.
    pub fn off() -> Self {
        Self {
            mode: "off".to_string(),
            ..Self::default()
        }
    }
}

pub(crate) fn default_search_method() -> String {
    "automatic".to_string()
}

impl Default for SearchResultDownloadCreate {
    fn default() -> Self {
        Self {
            category: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            redownload: false,
        }
    }
}
