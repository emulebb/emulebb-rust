//! REST-facing data-transfer structs and their serde helpers.
//!
//! These are the request/response shapes the REST layer (`emulebb-rest`) and the
//! daemon serialize over `/api/v1`; they are pure data definitions with no
//! behavior beyond serde. They are re-exported from the crate root so existing
//! paths (`emulebb_core::Transfer`, etc.) keep working unchanged.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use chrono::{DateTime, Utc};
use emulebb_ed2k::{
    NatConfig, config::Ed2kConfig, ed2k_tcp::Ed2kSecureIdent, ipfilter::IpFilter,
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
    pub kind: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppLifecycle {
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preferences {
    pub upload_limit_ki_bps: u32,
    pub download_limit_ki_bps: u32,
    pub max_connections: u32,
    pub max_connections_per_five_seconds: u32,
    pub max_sources_per_file: u32,
    pub upload_client_data_rate: u32,
    pub max_upload_slots: u32,
    pub upload_slot_elastic_percent: u32,
    pub queue_size: u32,
    pub auto_connect: bool,
    pub new_auto_up: bool,
    pub new_auto_down: bool,
    pub credit_system: bool,
    pub safe_server_connect: bool,
    pub network_kademlia: bool,
    pub network_ed2k: bool,
    pub download_auto_broadband_io: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreferencesUpdate {
    #[serde(default)]
    pub upload_limit_ki_bps: Option<u32>,
    #[serde(default)]
    pub download_limit_ki_bps: Option<u32>,
    #[serde(default)]
    pub max_connections: Option<u32>,
    #[serde(default)]
    pub max_connections_per_five_seconds: Option<u32>,
    #[serde(default)]
    pub max_sources_per_file: Option<u32>,
    #[serde(default)]
    pub upload_client_data_rate: Option<u32>,
    #[serde(default)]
    pub max_upload_slots: Option<u32>,
    #[serde(default)]
    pub upload_slot_elastic_percent: Option<u32>,
    #[serde(default)]
    pub queue_size: Option<u32>,
    #[serde(default)]
    pub auto_connect: Option<bool>,
    #[serde(default)]
    pub new_auto_up: Option<bool>,
    #[serde(default)]
    pub new_auto_down: Option<bool>,
    #[serde(default)]
    pub credit_system: Option<bool>,
    #[serde(default)]
    pub safe_server_connect: Option<bool>,
    #[serde(default)]
    pub network_kademlia: Option<bool>,
    #[serde(default)]
    pub network_ed2k: Option<bool>,
    #[serde(default)]
    pub download_auto_broadband_io: Option<bool>,
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
    pub connected: bool,
    pub connecting: bool,
    pub current: bool,
    pub description: String,
    pub dyn_ip: String,
    pub failed_count: u32,
    pub hard_files: u64,
    pub ip: String,
    pub ping: u32,
    pub soft_files: u64,
    pub version: String,
    pub users: u64,
    pub files: u64,
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchCreate {
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Search {
    pub id: String,
    pub query: String,
    pub method: String,
    pub r#type: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub results: Vec<SearchResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub search_id: String,
    pub method: String,
    pub r#type: String,
    pub hash: String,
    pub name: String,
    pub size_bytes: u64,
    pub sources: u32,
    pub complete_sources: u32,
    pub file_type: String,
    pub complete: bool,
    pub known_type: String,
    pub directory: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferCreate {
    pub link: Option<String>,
    #[serde(default)]
    pub links: Option<Vec<String>>,
    #[serde(default)]
    pub category_id: Option<u32>,
    #[serde(default)]
    pub category_name: Option<String>,
    #[serde(default)]
    pub paused: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub category_id: Option<u32>,
    #[serde(default)]
    pub category_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchResultDownloadCreate {
    #[serde(default)]
    pub category_id: Option<u32>,
    #[serde(default)]
    pub category_name: Option<String>,
    #[serde(default)]
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
    #[serde(default, deserialize_with = "deserialize_nullable_string_field")]
    pub path: NullableStringField,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nullable_u32_field")]
    pub color: NullableU32Field,
    #[serde(default)]
    pub priority: Option<CategoryPriorityValue>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CategoryUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nullable_string_field")]
    pub path: NullableStringField,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nullable_u32_field")]
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
    pub priority: String,
    pub auto_upload_priority: bool,
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

/// Upload-score modifier breakdown (eMuleBB `UploadScoreBreakdown` shape). The
/// Rust upload scorer is base waiting-time x file-priority x credit-ratio; it
/// does not apply the master's low-ratio bonus, low-ID divisor, old-client
/// penalty, or slow-upload cooldown, so those report as not-applied.
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
    pub elastic_underfill: bool,
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
    pub kad_bootstrap_nodes: Vec<String>,
    pub kad_bootstrap_min_routing_contacts: usize,
    pub kad_publish_shared_files: bool,
    pub kad_republish_interval_secs: u64,
    pub kad_publish_contact_fanout: usize,
    pub kad_hello_intro_interval_secs: u64,
    pub kad_hello_intro_fanout: usize,
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
    pub config: Ed2kConfig,
    /// Configured VPN-binding guard.
    pub vpn_guard: VpnGuardConfig,
    /// Whether the P2P bind was resolved from a named interface (e.g. the VPN
    /// adapter) rather than a raw address — the guard's confirmation signal.
    pub vpn_interface_bound: bool,
    /// IPv4 range filter (ipfilter.dat). Empty when no filter is configured.
    pub ip_filter: IpFilter,
}

/// Configured VPN-binding guard. When enabled in `enforce` mode the client
/// refuses to start public P2P unless the bind is VPN-confirmed.
#[derive(Debug, Clone, Default)]
pub struct VpnGuardConfig {
    pub enabled: bool,
    pub mode: String,
    pub allowed_public_ip_cidrs: String,
}

/// Resolved VPN-guard state surfaced through the REST status surfaces.
#[derive(Debug, Clone, Default)]
pub struct VpnGuardStatus {
    pub enabled: bool,
    pub mode: String,
    pub allowed_public_ip_cidrs: String,
    pub startup_blocked: bool,
    pub startup_block_reason: String,
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

pub(crate) fn deserialize_nullable_string_field<'de, D>(
    deserializer: D,
) -> std::result::Result<NullableStringField, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Null => Ok(NullableStringField::Null(())),
        serde_json::Value::String(value) => Ok(NullableStringField::Value(value)),
        _ => Err(serde::de::Error::custom("path must be a string or null")),
    }
}

pub(crate) fn deserialize_nullable_u32_field<'de, D>(
    deserializer: D,
) -> std::result::Result<NullableU32Field, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Null => Ok(NullableU32Field::Null(())),
        serde_json::Value::Number(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(NullableU32Field::Value)
            .ok_or_else(|| serde::de::Error::custom("color must be null or an RGB integer")),
        _ => Err(serde::de::Error::custom(
            "color must be null or an RGB integer",
        )),
    }
}
