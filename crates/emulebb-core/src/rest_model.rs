//! REST-facing data-transfer structs and their serde helpers.
//! Re-exported from the crate root so existing `emulebb_core::...` paths keep
//! working unchanged.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, atomic::AtomicBool};

use chrono::{DateTime, Utc};
use emulebb_ed2k::{
    NatConfig, config::Ed2kRuntimeConfig, ed2k_tcp::Ed2kSecureIdent, ipfilter::IpFilter,
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
pub struct DiagnosticDumpResult {
    pub ok: bool,
    pub path: String,
    pub full_memory: bool,
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
    pub transfers: TransferStats,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
    pub host_name_resolved_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostNameResolution {
    pub host_name: Option<String>,
    pub host_name_status: String,
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
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerCreate {
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default, rename = "static")]
    pub static_server: Option<bool>,
    #[serde(default)]
    pub connect: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default, rename = "static")]
    pub static_server: Option<bool>,
    #[serde(default)]
    pub enabled: Option<bool>,
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
    pub active: usize,
    pub completed: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchSpec {
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
}

/// The create-search payload is the immutable specification stored with the
/// resulting search session.
pub type SearchCreate = SearchSpec;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Search {
    pub id: String,
    pub spec: SearchSpec,
    /// Concrete backend selected for network execution. `None` means no
    /// network backend has been selected (yet, or because the search stayed
    /// local-only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_method: Option<String>,
    pub status: String,
    /// Honest reason for a non-completed status (additive REST field
    /// `statusReason`): e.g. `waiting-for-server-connection` while `queued`,
    /// or the explicit failure reason when `error`. `None` when completed or
    /// running normally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub results: Vec<SearchResult>,
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
    pub search_id: String,
    pub r#type: String,
    pub hash: String,
    pub name: String,
    pub size_bytes: u64,
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
    /// corroboration, but not exposed as an undocumented top-level REST key.
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
    /// Backend that produced this observation (`local_index`, `server`,
    /// `global`, or `kad`). A later transport-specific locator can refine this
    /// without changing the hash-level result identity.
    pub origin: String,
    pub name: String,
    pub size_bytes: u64,
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
    #[serde(default, skip_serializing)]
    pub aich_hash: String,
    pub complete: bool,
    pub directory: String,
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
            search_id,
            r#type,
            hash,
            name: observation.name.clone(),
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

    pub(crate) fn merge_observations(&mut self, mut other: SearchResult) {
        debug_assert_eq!(self.hash, other.hash);
        self.ensure_aggregate_observation();
        other.ensure_aggregate_observation();
        for observation in other.observations {
            if !self
                .observations
                .iter()
                .any(|existing| observations_are_equivalent(existing, &observation))
            {
                self.observations.push(observation);
            }
        }
        self.recompute_observation_aggregate();
    }

    fn ensure_aggregate_observation(&mut self) {
        if !self.observations.is_empty() {
            return;
        }
        self.observations.push(SearchResultObservation {
            origin: "unknown".to_string(),
            name: self.name.clone(),
            size_bytes: self.size_bytes,
            sources: self.sources,
            complete_sources: self.complete_sources,
            source_client_id: self.source_client_id,
            source_client_port: self.source_client_port,
            file_type: self.file_type.clone(),
            media: self.media.clone(),
            rating: self.rating,
            aich_hash: self.aich_hash.clone(),
            complete: self.complete,
            directory: self.directory.clone(),
            observed_at: Utc::now(),
        });
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
        self.name = display.name.clone();
        self.size_bytes = self
            .observations
            .iter()
            .filter(|observation| observation.size_bytes != 0)
            .max_by_key(|observation| observation_quality(observation, &self.hash))
            .map_or(display.size_bytes, |observation| observation.size_bytes);
        self.sources = self
            .observations
            .iter()
            .map(|observation| observation.sources)
            .max()
            .unwrap_or_default();
        self.complete_sources = self
            .observations
            .iter()
            .map(|observation| observation.complete_sources)
            .max()
            .unwrap_or_default();
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

fn observation_quality(
    observation: &SearchResultObservation,
    hash: &str,
) -> (bool, bool, u32, u32, bool, u8) {
    (
        !observation.name.trim().is_empty() && !observation.name.eq_ignore_ascii_case(hash),
        observation.origin != "local_index",
        observation.sources,
        observation.complete_sources,
        observation.size_bytes != 0,
        observation.rating,
    )
}

fn observations_are_equivalent(
    left: &SearchResultObservation,
    right: &SearchResultObservation,
) -> bool {
    left.origin == right.origin
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferCreate {
    pub link: Option<String>,
    #[serde(default)]
    pub links: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_optional_category_id"
    )]
    pub category_id: Option<u32>,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_optional_category_name"
    )]
    pub category_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_optional_paused_field"
    )]
    pub paused: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_optional_category_id"
    )]
    pub category_id: Option<u32>,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_optional_category_name"
    )]
    pub category_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchResultDownloadCreate {
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_optional_category_id"
    )]
    pub category_id: Option<u32>,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_optional_category_name"
    )]
    pub category_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_optional_paused_field"
    )]
    pub paused: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Category {
    pub id: u32,
    pub name: String,
    pub path: Option<String>,
    pub comment: String,
    pub priority: u32,
    pub color: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CategoryCreate {
    pub name: String,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_nullable_string_field"
    )]
    pub path: NullableStringField,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_nullable_u32_field"
    )]
    pub color: NullableU32Field,
    #[serde(default)]
    pub priority: Option<CategoryPriorityValue>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CategoryUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_nullable_string_field"
    )]
    pub path: NullableStringField,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::rest_model_serde::deserialize_nullable_u32_field"
    )]
    pub color: NullableU32Field,
    #[serde(default)]
    pub priority: Option<CategoryPriorityValue>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NullableStringField {
    #[default]
    Missing,
    Null(()),
    Value(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NullableU32Field {
    #[default]
    Missing,
    Null(()),
    Value(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CategoryPriorityValue {
    Number(u32),
    Name(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Friend {
    pub user_hash: String,
    pub name: String,
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
    pub transfer_dir: String,
    #[serde(default)]
    pub source_path: Option<String>,
    pub priority: String,
    pub auto_upload_priority: bool,
    pub all_time_uploaded_bytes: u64,
    pub all_time_upload_requests: u64,
    pub all_time_upload_accepts: u64,
    pub comment: String,
    pub rating: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharedFileUpdate {
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub rating: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transfer {
    pub hash: String,
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
    pub priority: String,
    pub category_id: u32,
    pub category_name: String,
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
    /// Whether download priority is auto-managed (not modeled yet -> false).
    pub auto_priority: bool,
    /// Whether this transfer's file lives in an incoming/download directory (so
    /// it is a file WE downloaded), as opposed to a file that is only shared from
    /// a configured shared directory. Lets a UI separate "completed downloads"
    /// from the static shared library even when a shared dir doubles as the
    /// incoming dir. Incomplete (still downloading) transfers are always true.
    pub in_incoming: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferEventType {
    #[serde(rename = "transfer.added")]
    Added,
    #[serde(rename = "transfer.updated")]
    Updated,
    #[serde(rename = "transfer.removed")]
    Removed,
    #[serde(rename = "sync.reset")]
    SyncReset,
}

impl TransferEventType {
    pub fn as_sse_name(self) -> &'static str {
        match self {
            Self::Added => "transfer.added",
            Self::Updated => "transfer.updated",
            Self::Removed => "transfer.removed",
            Self::SyncReset => "sync.reset",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferEventResetReason {
    #[serde(rename = "lagged")]
    Lagged,
    #[serde(rename = "last-event-id")]
    LastEventId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TransferEvent {
    #[serde(rename = "transfer.added")]
    Added { id: u64, transfer: Transfer },
    #[serde(rename = "transfer.updated")]
    Updated { id: u64, transfer: Transfer },
    #[serde(rename = "transfer.removed")]
    Removed { id: u64, hash: String },
    #[serde(rename = "sync.reset")]
    SyncReset {
        id: u64,
        reason: TransferEventResetReason,
        #[serde(skip_serializing_if = "Option::is_none")]
        missed: Option<u64>,
        #[serde(rename = "lastEventId", skip_serializing_if = "Option::is_none")]
        last_event_id: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferEventDiagnostics {
    pub enabled: bool,
    pub stream: String,
    pub channel_capacity: usize,
    pub queued_event_count: usize,
    pub subscriber_count: usize,
    pub latest_event_id: u64,
    pub next_event_id: u64,
    pub resume_behavior: String,
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
}

impl TransferEvent {
    pub fn added(id: u64, transfer: Transfer) -> Self {
        Self::Added { id, transfer }
    }

    pub fn updated(id: u64, transfer: Transfer) -> Self {
        Self::Updated { id, transfer }
    }

    pub fn removed(id: u64, hash: impl Into<String>) -> Self {
        Self::Removed {
            id,
            hash: hash.into(),
        }
    }

    pub fn reset_lagged(id: u64, missed: u64) -> Self {
        Self::SyncReset {
            id,
            reason: TransferEventResetReason::Lagged,
            missed: Some(missed),
            last_event_id: None,
        }
    }

    pub fn reset_last_event_id(id: u64, last_event_id: impl Into<String>) -> Self {
        Self::SyncReset {
            id,
            reason: TransferEventResetReason::LastEventId,
            missed: None,
            last_event_id: Some(last_event_id.into()),
        }
    }

    pub fn id(&self) -> u64 {
        match self {
            Self::Added { id, .. }
            | Self::Updated { id, .. }
            | Self::Removed { id, .. }
            | Self::SyncReset { id, .. } => *id,
        }
    }

    pub fn event_type(&self) -> TransferEventType {
        match self {
            Self::Added { .. } => TransferEventType::Added,
            Self::Updated { .. } => TransferEventType::Updated,
            Self::Removed { .. } => TransferEventType::Removed,
            Self::SyncReset { .. } => TransferEventType::SyncReset,
        }
    }
}

/// One remembered ED2K peer source for a transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSource {
    pub client_id: String,
    // The next four are internal-only; not in the eMuleBB `TransferSource`
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
    pub download_state: String,
    pub download_speed_ki_bps: f64,
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

/// One ED2K part's live download geometry/progress for the transfer details view.
/// Mirrors the master `BuildTransferPartsJson` `TransferPart` shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferPart {
    pub index: u32,
    pub start: u64,
    pub end: u64,
    pub size: u64,
    pub completed_bytes: u64,
    pub gap_bytes: u64,
    pub complete: bool,
    pub requested: bool,
    pub corrupted: bool,
    pub available_sources: u32,
}

/// Transfer details envelope: the transfer plus its per-part breakdown and live
/// source list. Mirrors the master `BuildTransferDetailsJson` shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferDetails {
    pub transfer: Transfer,
    pub parts: Vec<TransferPart>,
    pub sources: Vec<TransferSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Upload {
    pub client_id: String,
    pub user_name: String,
    pub user_hash: Option<String>,
    pub client_software: String,
    pub client_mod: String,
    pub upload_state: String,
    pub upload_speed_ki_bps: f64,
    pub uploaded_bytes: u64,
    pub queue_session_uploaded: u64,
    pub payload_buffered: u64,
    pub wait_time_ms: u64,
    pub wait_started_tick: u64,
    pub score: u64,
    pub address: String,
    pub port: u16,
    pub server_ip: String,
    pub server_port: u16,
    pub low_id: bool,
    pub friend_slot: bool,
    pub uploading: bool,
    pub waiting_queue: bool,
    pub requested_file_hash: Option<String>,
    pub requested_file_name: Option<String>,
    pub requested_file_size_bytes: Option<u64>,
    pub requested_parts_obtained: u32,
    pub requested_parts_total: u32,
    pub requested_parts_progress_text: String,
    /// Optional per-client upload score diagnostics. Like master, attached only
    /// when the caller opts in (single-client lookups always; `/upload-queue`
    /// list only with `includeScoreBreakdown=true`; `/uploads` list never).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_breakdown: Option<UploadScoreBreakdown>,
    // Internal-only: queue position is not in the `Upload` contract (it belongs
    // to source JSON); waiting position is conveyed via score/waitTimeMs.
    #[serde(skip_serializing)]
    pub queue_rank: Option<u16>,
}

/// Upload-score modifier breakdown (eMuleBB `UploadScoreBreakdown` shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadScoreBreakdown {
    pub availability: String,
    pub base_score: u32,
    pub effective_score: u32,
    pub core_score: f64,
    pub effective_score_float: f64,
    pub credit_ratio: f64,
    pub file_priority: i64,
    pub low_ratio_applied: bool,
    pub low_ratio_bonus: u32,
    pub low_id_penalty_applied: bool,
    pub low_id_divisor: u32,
    pub old_client_penalty_applied: bool,
    pub cooldown_remaining_ms: u64,
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
    pub bind_ip: Ipv4Addr,
    pub kad_bind_addr: SocketAddr,
    pub listen_port: u16,
    pub user_hash: [u8; 16],
    pub secure_ident: Arc<Ed2kSecureIdent>,
    pub kad_local_store: KadLocalStoreConfig,
    pub kad_snoop_queue: SnoopQueueConfig,
    /// Validated persisted `nodes.dat` bytes used to seed a new Kad runtime.
    pub kad_nodes_dat: Option<Vec<u8>>,
    /// Destination for the live routing sample written atomically on Kad
    /// shutdown. `None` disables runtime persistence (primarily test fixtures).
    pub kad_nodes_dat_path: Option<std::path::PathBuf>,
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
