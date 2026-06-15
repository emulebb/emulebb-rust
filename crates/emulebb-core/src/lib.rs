use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fmt, fs,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use emulebb_ed2k::{
    MappedEndpoint, MappingExposure, MappingSpec, NatConfig, NatManager, NatManagerBuilder,
    ReaskSourceHandle, TransportProtocol,
    buddy_socket::{BuddySocketRegistry, ExpectedInboundBuddy},
    built_in_upnp_port_mapping_providers,
    config::{Ed2kConfig, Ed2kUploadQueuePolicyConfig},
    ed2k_server::{
        Ed2kCallbackRequestOptions, Ed2kFoundSource, Ed2kKeywordSearchOptions, Ed2kSearchFile,
        Ed2kServerLoopOptions, Ed2kServerSearchHandle, Ed2kServerState, Ed2kSourceSearchOptions,
        Ed2kUdpSourceSearchOptions, new_ed2k_server_search_channel, parse_server_met,
        publish_shared_catalog_via_background_session, request_callback_on_server,
        request_callback_via_background_session, run_ed2k_server_loop, search_keyword_servers,
        search_keyword_via_background_session, search_source_servers, search_source_udp_servers,
        search_source_via_background_session,
    },
    ed2k_tcp::{
        Ed2kHelloIdentity, Ed2kListenerOptions, Ed2kPeerDownloadOptions, Ed2kPeerDownloadOutcome,
        Ed2kSecureIdent, HelloBuddySnapshot, OutboundBuddyLinkOptions, download_file_from_peer, emule_connect_options,
        encode_kad_callback_relay_frame, enrich_hello_identity, run_ed2k_listener, run_outbound_buddy_link,
        send_kad_firewall_tcp_ack, set_hello_buddy_snapshot, set_publish_rust_identity,
    },
    ed2k_transfer::{
        ED2K_PART_SIZE, Ed2kCallbackIntent, Ed2kLiveSource, Ed2kResumeManifest, Ed2kSourceHint,
        Ed2kTransferRuntime, Ed2kTransferState, Ed2kUploadQueueCapacitySnapshot,
        Ed2kUploadQueueSnapshotEntry, Ed2kUploadSessionPhaseSnapshot, new_transfer_job,
    },
    ipfilter::IpFilter,
    kad_firewall::{FirewallUdpPacketOutcome, FirewalledResponseOutcome, KadFirewallState},
    reachability::ExternalReachability,
    reask_command_channel, reask_event_channel, run_ed2k_udp_reask_loop,
};
use emulebb_ed2k::{ReaskEvent, ReaskEventReceiver};
use emulebb_ed2k::stun::{
    DEFAULT_STUN_TIMEOUT, NatMappingBehavior, stun_probe, stun_probe_mapping_behavior,
};
use emulebb_index::{
    FileIndex, IndexedFile, KadLocalStore, KadLocalStoreConfig, ScheduledSnoopRequest, SnoopEntry,
    SnoopQueue, SnoopQueueConfig, SnoopQueueFamilyCounts, metadata_from_publish_snapshot,
    publish_snapshot_from_metadata,
};
use emulebb_kad_dht::{
    DhtConfig, DhtNode, NoteResult as KadNoteResult, PublishAttemptStats, ReceivedKadPacket,
    RpcWorkClass, SearchResult as KadSearchResult, SourceResult,
};
use emulebb_kad_proto::{
    CallbackReq, Ed2kHash, FindBuddyReq, FindBuddyRes, Firewalled2Req, FirewalledRes, HelloReq,
    HelloRes, HelloResAck, KAD_VERSION, KadPacket, NodeId, PublishRes, SearchKeyReq, SearchNotesReq,
    SearchRes, SearchResultEntry, SearchSourceReq, Tag, TagValue, constants::K,
    packet::ContactEntry, tag_name,
};
use emulebb_metadata::MetadataStore;
use md4::{Digest, Md4};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    net::{TcpListener, TcpSocket},
    sync::{Mutex, RwLock},
    task::{JoinHandle, JoinSet},
};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod download_source_registry;
mod kad_buddy;
mod kad_snoop_entry;
mod kad_tcp_firewall_check;
mod kad_udp_firewall_check;
mod profile_state;
mod search_query;
mod search_state;
mod shared_directories;
use download_source_registry::{DownloadSourceCandidate, DownloadSourceRegistry};
use kad_buddy::{
    BuddyNeedInput, FindBuddyReqRefusal, IncomingBuddy, KadBuddyState, OutgoingBuddy,
    buddy_search_target, find_buddy_res_matches,
};
use kad_snoop_entry::{
    build_keyword_snoop_entry, build_notes_snoop_entry, build_source_snoop_entry,
};
use search_query::{apply_search_filters, search_result_from_ed2k, search_result_from_indexed};

pub use shared_directories::{
    SharedDirectories, SharedDirectoriesUpdate, SharedDirectoryRoot, SharedDirectoryRootUpdate,
};
use shared_directories::{
    collect_shared_directory_files, refresh_shared_directory_row, shared_directory_from_index,
    shared_directory_to_index, shared_directory_update_parts,
};

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

const LOCAL_KEYWORD_SEARCH_RESPONSE_LIMIT: usize = 300;
const LOCAL_SOURCE_SEARCH_RESPONSE_LIMIT: usize = 300;
const LOCAL_NOTES_SEARCH_RESPONSE_LIMIT: usize = 150;
const LOCAL_SEARCH_RESPONSE_MAX_PACKET_BYTES: usize = 1420;
const PASSIVE_GENERAL_CRAWL_SECS: u64 = 45;
const PASSIVE_SOURCE_CRAWL_SECS: u64 = 15;
const PASSIVE_KEYWORD_RESULT_TARGET: usize = 10;
const PASSIVE_NOTES_RESULT_TARGET: usize = 3;
const KAD_SHARED_FILE_PUBLISH_RETRY_SECS: u64 = 5;
const KAD_FIREWALLED_TCP_PROBE_TIMEOUT_SECS: u64 = 20;
/// Max oracle freshness type returned to a KADEMLIA2_REQ (oracle passes 2 to
/// `GetClosestTo`), filtering out contacts staler than two age buckets.
const KAD_REQ_MAX_TYPE: u8 = 2;
const EMULE_LARGE_FILE_SIZE_THRESHOLD: u64 = u32::MAX as u64;
const ED2K_HASH_ONLY_QUERY_PREFIX: &str = "ed2k::";

type DirectDownloadJoin = (SocketAddr, Ed2kFoundSource, Result<Ed2kPeerDownloadOutcome>);

#[derive(Debug)]
struct DirectDownloadOutcome {
    completed: bool,
    accepted_incomplete_peers: u32,
    last_error: Option<anyhow::Error>,
    /// Endpoints that detached their TCP socket onto the UDP reask loop. Their
    /// source leases are deliberately NOT released so the next download cycle
    /// does not re-connect them over TCP while the reask loop holds them (the
    /// loop owns re-engagement; on UDP failure it drops them back to TCP).
    detached_reask_endpoints: Vec<(Ipv4Addr, u16)>,
}

struct DirectDownloadOptions {
    bind_ip: Ipv4Addr,
    hello_identity: Ed2kHelloIdentity,
    secure_ident: Arc<Ed2kSecureIdent>,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    file_hash_hex: String,
    file_name: String,
    file_size: u64,
    sources: Vec<Ed2kFoundSource>,
    connect_timeout: Duration,
    max_parallel_download_peers: usize,
}

struct DirectDownloadSpawnContext<'a, DownloadFn> {
    bind_ip: Ipv4Addr,
    hello_identity: Ed2kHelloIdentity,
    secure_ident: &'a Arc<Ed2kSecureIdent>,
    transfer_runtime: &'a Arc<Ed2kTransferRuntime>,
    file_hash_hex: &'a str,
    file_name: &'a str,
    file_size: u64,
    connect_timeout: Duration,
    retry_round: u32,
    download_peer: &'a DownloadFn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ed2kServerCallbackRoute {
    BackgroundSession,
    SourceServer(SocketAddr),
}

#[derive(Debug)]
struct CoreState {
    searches: HashMap<String, Search>,
    transfers: HashMap<String, Transfer>,
    preferences: Preferences,
    categories: BTreeMap<u32, Category>,
    next_category_id: u32,
    friends: BTreeMap<String, Friend>,
    servers: HashMap<String, ServerInfo>,
    server_overrides: HashMap<String, ServerUpdate>,
    disabled_servers: HashSet<String>,
    banned_source_clients: HashSet<String>,
    active_download_attempts: HashSet<String>,
    active_download_peer_endpoints: HashSet<(Ipv4Addr, u16)>,
    download_source_registry: DownloadSourceRegistry,
    shared_directories: Vec<SharedDirectoryRoot>,
    unshared_hashes: HashSet<String>,
    kad_running: bool,
}

struct Ed2kRuntime {
    search_handle: Ed2kServerSearchHandle,
    server_state: Arc<RwLock<Ed2kServerState>>,
    dht: DhtNode,
    kad_bootstrap_configured: bool,
    nat: Arc<NatManager>,
    shutdown: Arc<AtomicBool>,
    /// Trigger to run a Kad UDP firewall self-check round on demand. `None` when
    /// the firewall check is disabled in config.
    kad_firewall_recheck: Option<Arc<tokio::sync::Notify>>,
    tasks: Vec<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct EmulebbCore {
    started_at: Instant,
    version: String,
    metadata_store: MetadataStore,
    index: Arc<Mutex<FileIndex>>,
    ed2k_transfers: Arc<Ed2kTransferRuntime>,
    transfer_root: PathBuf,
    ed2k_network: Option<Ed2kNetworkConfig>,
    kad_local_store: Option<Arc<Mutex<KadLocalStore>>>,
    kad_snoop_queue: Option<Arc<Mutex<SnoopQueue>>>,
    ed2k_runtime: Arc<Mutex<Option<Ed2kRuntime>>>,
    /// Handle for detaching queued download sources onto the UDP reask loop.
    /// `Some` only while connected with `enable_udp_reask`; read by the direct
    /// download driver to detach queued sources. `std::sync::Mutex` so the
    /// download closure can read it without `.await`.
    ed2k_reask_handle: Arc<std::sync::Mutex<Option<ReaskSourceHandle>>>,
    /// Single source of truth for our external reachability (public IP + advertised
    /// external eD2k TCP/UDP ports), read at hello/login-encode time. Fed by the
    /// server (OP_IDCHANGE), the STUN fallback, and the NAT-mapping sync.
    ed2k_reachability: ExternalReachability,
    state: Arc<Mutex<CoreState>>,
}

impl EmulebbCore {
    pub fn new(
        version: impl Into<String>,
        index: FileIndex,
        transfer_root: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::new_with_network(version, index, transfer_root, None)
    }

    pub fn new_with_network(
        version: impl Into<String>,
        index: FileIndex,
        transfer_root: impl AsRef<Path>,
        ed2k_network: Option<Ed2kNetworkConfig>,
    ) -> Result<Self> {
        let transfer_root = transfer_root.as_ref().to_path_buf();
        let metadata_store = index.metadata_store();
        let has_persisted_preferences = profile_state::has_persisted_preferences(&metadata_store)?;
        let shared_directories = index
            .shared_directory_roots()?
            .into_iter()
            .map(shared_directory_from_index)
            .collect::<Vec<_>>();
        let core_state = profile_state::load_core_state(&metadata_store, shared_directories)?;
        let upload_queue_policy = initial_ed2k_upload_queue_policy(
            ed2k_network
                .as_ref()
                .map(|network| &network.config.upload_queue),
            has_persisted_preferences,
            &core_state.preferences,
        );
        let ed2k_transfers = if ed2k_network.is_some() {
            Ed2kTransferRuntime::load_or_create_with_metadata_and_config(
                &transfer_root,
                metadata_store.clone(),
                &Ed2kConfig {
                    upload_queue: upload_queue_policy,
                    ..Ed2kConfig::default()
                },
            )?
        } else {
            Ed2kTransferRuntime::load_or_create_with_metadata_and_config(
                &transfer_root,
                metadata_store.clone(),
                &Ed2kConfig {
                    upload_queue: upload_queue_policy,
                    ..Ed2kConfig::default()
                },
            )?
        };
        let kad_local_store = ed2k_network.as_ref().map(|network| {
            let mut store = KadLocalStore::new(network.kad_local_store);
            match metadata_store
                .load_kad_publish_cache()
                .and_then(publish_snapshot_from_metadata)
            {
                Ok(snapshot) => store.merge_publish_snapshot(snapshot, Utc::now()),
                Err(error) => {
                    tracing::warn!("failed to hydrate Kad publish cache from metadata: {error:#}");
                }
            }
            Arc::new(Mutex::new(store))
        });
        let kad_snoop_queue = ed2k_network
            .as_ref()
            .map(|network| Arc::new(Mutex::new(SnoopQueue::new(network.kad_snoop_queue.clone()))));
        Ok(Self {
            started_at: Instant::now(),
            version: version.into(),
            metadata_store,
            index: Arc::new(Mutex::new(index)),
            ed2k_transfers: Arc::new(ed2k_transfers),
            transfer_root,
            ed2k_network,
            kad_local_store,
            kad_snoop_queue,
            ed2k_runtime: Arc::new(Mutex::new(None)),
            ed2k_reask_handle: Arc::new(std::sync::Mutex::new(None)),
            ed2k_reachability: ExternalReachability::new(),
            state: Arc::new(Mutex::new(core_state)),
        })
    }

    pub fn new_in_memory(version: impl Into<String>, index: FileIndex) -> Result<Self> {
        Self::new(version, index, unique_runtime_dir("emulebb-core-transfers"))
    }

    pub fn app_info(&self) -> AppInfo {
        AppInfo {
            name: "eMuleBB Rust".to_string(),
            version: self.version.clone(),
            api_version: "1".to_string(),
            lifecycle: AppLifecycle {
                state: "running".to_string(),
            },
            capabilities: vec![
                "client.headless".to_string(),
                "network.ed2k".to_string(),
                "network.kad".to_string(),
                "rest.emulebb.v1".to_string(),
                "search.keyword".to_string(),
                "transfer.downloads".to_string(),
                "share.localFiles".to_string(),
                "indexing.localFts".to_string(),
            ],
        }
    }

    pub async fn capture_diagnostic_dump(&self, full_memory: bool) -> Result<DiagnosticDumpResult> {
        let dump_dir = self
            .transfer_root
            .parent()
            .unwrap_or(self.transfer_root.as_path())
            .join("diagnostics");
        fs::create_dir_all(&dump_dir).with_context(|| {
            format!(
                "failed to create diagnostics directory {}",
                dump_dir.display()
            )
        })?;

        let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
        let path = dump_dir.join(format!(
            "emulebb-rust-diagnostic-dump-{stamp}-{}.json",
            Uuid::new_v4()
        ));
        let payload = serde_json::to_vec_pretty(&json!({
            "app": self.app_info(),
            "status": self.status().await,
            "fullMemory": full_memory,
            "kind": "json",
            "capturedAt": Utc::now(),
        }))?;
        fs::write(&path, &payload)
            .with_context(|| format!("failed to write diagnostic dump {}", path.display()))?;
        Ok(DiagnosticDumpResult {
            ok: true,
            path: path.display().to_string(),
            full_memory,
            kind: "json".to_string(),
            size_bytes: payload.len() as u64,
        })
    }

    pub async fn preferences(&self) -> Preferences {
        self.state.lock().await.preferences.clone()
    }

    pub async fn update_preferences(&self, request: PreferencesUpdate) -> Result<Preferences> {
        ensure!(
            !preferences_update_is_empty(&request),
            "preferences PATCH requires at least one preference"
        );
        let preferences = {
            let mut state = self.state.lock().await;
            let mut preferences = state.preferences.clone();
            apply_preferences_update(&mut preferences, request)?;
            profile_state::persist_preferences(&self.metadata_store, &preferences)?;
            state.preferences = preferences.clone();
            preferences
        };
        self.ed2k_transfers
            .apply_upload_queue_policy(&ed2k_upload_queue_policy_from_preferences(
                self.ed2k_network
                    .as_ref()
                    .map(|network| &network.config.upload_queue),
                &preferences,
            ))
            .await;
        Ok(preferences)
    }

    pub async fn status(&self) -> Status {
        if let Err(error) = self.refresh_transfers_from_manifests().await {
            tracing::warn!("failed to refresh ED2K transfers from manifests: {error}");
        }
        let state = self.state.lock().await;
        let completed = state
            .transfers
            .values()
            .filter(|transfer| transfer.state == "completed")
            .count();
        let active = state.transfers.len().saturating_sub(completed);
        let kad_running = state.kad_running;
        drop(state);

        Status {
            lifecycle: AppLifecycle {
                state: "running".to_string(),
            },
            uptime_secs: self.started_at.elapsed().as_secs(),
            kad: self.kad_status(kad_running).await,
            ed2k: self.ed2k_status().await,
            indexing: IndexingStatus {
                enabled: true,
                backend: "sqlite-fts5".to_string(),
            },
            transfers: TransferStats { active, completed },
        }
    }

    pub async fn set_kad_running(&self, running: bool) {
        self.state.lock().await.kad_running = running;
    }

    pub async fn bootstrap_kad(&self, address: &str, port: u16) -> Result<NetworkStatus> {
        ensure!(!address.trim().is_empty(), "address must not be empty");
        ensure!(port != 0, "port must be between 1 and 65535");
        self.set_kad_running(true).await;
        Ok(kad_status_from_running(self.state.lock().await.kad_running))
    }

    pub async fn import_kad_nodes_url(&self, url: &str) -> Result<bool> {
        let url = validate_url_import(url)?;
        match fetch_url_bytes(&url).await {
            Ok(bytes) => Ok(self.import_kad_nodes_bytes(&bytes).await.unwrap_or(0) > 0),
            Err(error) => {
                tracing::warn!("nodes.dat import fetch failed url={url}: {error:#}");
                Ok(false)
            }
        }
    }

    /// Parse a `nodes.dat` payload and add its contacts to the running Kad node.
    pub async fn import_kad_nodes_bytes(&self, data: &[u8]) -> Result<usize> {
        let Some(dht) = self.ed2k_dht_node().await else {
            anyhow::bail!("Kad is not running");
        };
        dht.import_nodes_dat(data)
            .await
            .map_err(|error| anyhow::anyhow!("nodes.dat import failed: {error}"))
    }

    pub async fn import_server_met_url(&self, url: &str) -> Result<bool> {
        let url = validate_url_import(url)?;
        match fetch_url_bytes(&url).await {
            Ok(bytes) => Ok(self.import_server_met_bytes(&bytes).await.unwrap_or(0) > 0),
            Err(error) => {
                tracing::warn!("server.met import fetch failed url={url}: {error:#}");
                Ok(false)
            }
        }
    }

    /// Parse a `server.met` payload and add its servers to the server list.
    pub async fn import_server_met_bytes(&self, data: &[u8]) -> Result<usize> {
        let servers = parse_server_met(data)?;
        let mut added = 0usize;
        for server in servers {
            let request = ServerCreate {
                address: server.ip.to_string(),
                port: server.port,
                name: server.name,
                priority: None,
                static_server: None,
                connect: None,
            };
            if self.add_server(request).await.is_ok() {
                added += 1;
            }
        }
        Ok(added)
    }

    pub async fn recheck_kad_firewall(&self) -> NetworkStatus {
        // Trigger an immediate Kad UDP firewall self-check round when the driver
        // is running, so the REST recheck actually drives a fresh probe instead of
        // only reporting status (oracle CUDPFirewallTester::ReCheckFirewallUDP).
        let triggered = {
            let runtime = self.ed2k_runtime.lock().await;
            match runtime.as_ref().and_then(|rt| rt.kad_firewall_recheck.as_ref()) {
                Some(signal) => {
                    signal.notify_one();
                    true
                }
                None => false,
            }
        };
        let mut status = kad_status_from_running(self.state.lock().await.kad_running);
        status.operation_queued = Some(triggered);
        status.already_running = Some(false);
        status
    }

    /// Resolved VPN-guard state for the REST status surfaces.
    pub fn vpn_guard_status(&self) -> VpnGuardStatus {
        let Some(network) = self.ed2k_network.as_ref() else {
            return VpnGuardStatus::off();
        };
        let guard = &network.vpn_guard;
        // Master parity (GetVpnGuardModeRestToken): the REST mode token is "block"
        // when guarding is enabled in a blocking mode, otherwise "off".
        let blocking = guard.enabled
            && (guard.mode.eq_ignore_ascii_case("block")
                || guard.mode.eq_ignore_ascii_case("enforce"));
        let startup_blocked = blocking && !network.vpn_interface_bound;
        VpnGuardStatus {
            enabled: guard.enabled,
            mode: if blocking { "block" } else { "off" }.to_string(),
            allowed_public_ip_cidrs: guard.allowed_public_ip_cidrs.clone(),
            startup_blocked,
            startup_block_reason: if startup_blocked {
                "public P2P bind is not VPN-confirmed (no VPN interface bind)".to_string()
            } else {
                String::new()
            },
        }
    }

    pub async fn connect_ed2k(&self) -> Result<NetworkStatus> {
        self.connect_ed2k_to_server(None).await
    }

    pub async fn connect_ed2k_server(&self, endpoint: &str) -> Result<Option<NetworkStatus>> {
        if self.server(endpoint).await.is_none() {
            return Ok(None);
        }
        self.connect_ed2k_to_server(Some(endpoint)).await.map(Some)
    }

    async fn connect_ed2k_to_server(&self, endpoint: Option<&str>) -> Result<NetworkStatus> {
        let guard = self.vpn_guard_status();
        if guard.startup_blocked {
            anyhow::bail!("blocked by VPN guard: {}", guard.startup_block_reason);
        }
        let Some(network) = self.ed2k_network.clone() else {
            anyhow::bail!("ED2K network is not configured");
        };
        let config = self
            .effective_ed2k_config(&network.config, endpoint)
            .await?;
        if config.server_entries.is_empty() && config.server_endpoints.is_empty() {
            anyhow::bail!("ED2K connect requires at least one configured server");
        }

        let mut runtime_guard = self.ed2k_runtime.lock().await;
        if runtime_guard.is_some() {
            drop(runtime_guard);
            return Ok(self.ed2k_status().await);
        }

        let (search_handle, search_inbox) = new_ed2k_server_search_channel(32);
        let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let kad_buddy = Arc::new(Mutex::new(KadBuddyState::new()));
        // Persistent Kad buddy-socket registry: holds the held inbound buddy
        // session writer (so callbacks can be relayed) and tracks the outbound
        // buddy link, shared by the inbound dispatch, the listener, and the
        // buddy-management loop.
        let buddy_registry = BuddySocketRegistry::new();
        let shutdown = Arc::new(AtomicBool::new(false));
        let configured_bootstrap_nodes_text =
            configured_kad_bootstrap_nodes_text(&network.kad_bootstrap_nodes);
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(network.kad_bind_addr),
            obfuscation_enabled: network.config.obfuscation_enabled,
            bootstrap_min_routing_contacts: network.kad_bootstrap_min_routing_contacts.max(1),
            nodes_text: configured_bootstrap_nodes_text.clone(),
            // Pin Kad UDP egress to the VPN bind interface (IP_UNICAST_IF).
            bind_if_index: emulebb_ed2k::networking::resolve_bind_if_index(network.bind_ip),
            ..DhtConfig::default()
        })
        .await
        .context("failed to initialize Kad runtime for ED2K listener")?;
        let ed2k_bind_addr = SocketAddr::new(IpAddr::V4(network.bind_ip), network.listen_port);
        let ed2k_listener =
            Arc::new(TcpListener::bind(ed2k_bind_addr).await.with_context(|| {
                format!("failed to bind eD2k TCP listener on {ed2k_bind_addr}")
            })?);
        let hello_identity = self.ed2k_hello_identity(&network);
        let nat = Arc::new(
            NatManagerBuilder::new(network.nat_config.clone())
                .with_mappings(ed2k_nat_mappings(&network))
                .with_providers(built_in_upnp_port_mapping_providers())
                .build(),
        );
        nat.start().await?;
        let mut tasks = Vec::new();
        tasks.push(dht.clone().start());
        // "Reconnect now" signal: the advertised-ports sync fires it when the
        // external port changes (UPnP ready / remapped) so the server loop re-logs
        // in with the new HighID callback port instead of waiting for a reconnect.
        let server_reconnect_signal = Arc::new(tokio::sync::Notify::new());
        // Keep the advertised external eD2k TCP + UDP ports in sync with the NAT
        // mappings so peers/servers can reach us (incoming TCP + HighID callback)
        // and locate us for UDP source-reask by (ip, udp_port) even when the
        // gateway remaps the external ports.
        tasks.push(tokio::spawn(run_advertised_ports_sync(
            Arc::clone(&nat),
            self.ed2k_reachability.clone(),
            Arc::clone(&server_reconnect_signal),
            network.listen_port,
            network.kad_bind_addr.port(),
            Arc::clone(&shutdown),
        )));
        if configured_bootstrap_nodes_text.is_some() {
            tasks.push(tokio::spawn(run_configured_kad_bootstrap(
                dht.clone(),
                Arc::clone(&shutdown),
            )));
        }
        if network.kad_publish_shared_files {
            tasks.push(tokio::spawn(run_kad_shared_file_publish_loop(
                dht.clone(),
                Arc::clone(&self.ed2k_transfers),
                network.clone(),
                Arc::clone(&shutdown),
            )));
        }
        if network.kad_hello_intro_fanout > 0 {
            tasks.push(tokio::spawn(run_kad_hello_intro_loop(
                dht.clone(),
                Arc::clone(&ed2k_listener),
                Arc::clone(&server_state),
                Arc::clone(&kad_firewall),
                network.clone(),
                Arc::clone(&shutdown),
            )));
        }
        if let (Some(kad_local_store), Some(kad_snoop_queue)) = (
            self.kad_local_store.as_ref().map(Arc::clone),
            self.kad_snoop_queue.as_ref().map(Arc::clone),
        ) {
            tasks.push(tokio::spawn(run_kad_local_store_loop(
                KadLocalStoreRuntime {
                    dht: dht.clone(),
                    local_store: kad_local_store,
                    metadata_store: self.metadata_store.clone(),
                    snoop_queue: Arc::clone(&kad_snoop_queue),
                    ed2k_listener: Arc::clone(&ed2k_listener),
                    server_state: Arc::clone(&server_state),
                    kad_firewall: Arc::clone(&kad_firewall),
                    reachability: self.ed2k_reachability.clone(),
                    kad_buddy: Arc::clone(&kad_buddy),
                    buddy_registry: buddy_registry.clone(),
                    transfer_runtime: Arc::clone(&self.ed2k_transfers),
                    network: network.clone(),
                },
                Arc::clone(&shutdown),
            )));
            tasks.push(tokio::spawn(run_kad_passive_replay_loop(
                dht.clone(),
                Arc::clone(&kad_snoop_queue),
                Arc::clone(&self.index),
                Arc::clone(&self.ed2k_transfers),
                Arc::clone(&shutdown),
                PassiveReplayWorker::Source,
            )));
            tasks.push(tokio::spawn(run_kad_passive_replay_loop(
                dht.clone(),
                kad_snoop_queue,
                Arc::clone(&self.index),
                Arc::clone(&self.ed2k_transfers),
                Arc::clone(&shutdown),
                PassiveReplayWorker::General,
            )));
        }
        // Kad LowID buddy/firewalled-callback driver (default on). It seeks a
        // buddy when we are firewalled; inbound FINDBUDDY/CALLBACK packets are
        // dispatched by the local-store loop above, which owns the same
        // `kad_buddy` state.
        if network.kad_buddy_enabled {
            tasks.push(tokio::spawn(run_kad_buddy_loop(
                KadBuddyRuntime {
                    dht: dht.clone(),
                    ed2k_listener: Arc::clone(&ed2k_listener),
                    server_state: Arc::clone(&server_state),
                    kad_firewall: Arc::clone(&kad_firewall),
                    kad_buddy: Arc::clone(&kad_buddy),
                    buddy_registry: buddy_registry.clone(),
                    network: network.clone(),
                },
                Arc::clone(&shutdown),
            )));
        }
        tasks.push(tokio::spawn(run_ed2k_listener(Ed2kListenerOptions {
            listener: Arc::clone(&ed2k_listener),
            dht: dht.clone(),
            server_state: Arc::clone(&server_state),
            kad_firewall: Arc::clone(&kad_firewall),
            secure_ident: Arc::clone(&network.secure_ident),
            transfer_runtime: Arc::clone(&self.ed2k_transfers),
            hello_identity,
            shutdown: Arc::clone(&shutdown),
            ip_filter: network.ip_filter.clone(),
            reachability: self.ed2k_reachability.clone(),
            buddy_registry: buddy_registry.clone(),
        })));
        // Learned public-IP cell (eMule theApp public IP), shared by the server
        // loop (sets it from OP_IDCHANGE) and the UDP reask loop (obfuscation key).
        let ed2k_public_ip = self.ed2k_reachability.clone();
        // Select the advertised eD2k client identity (eMule Community by default,
        // or the real emule-rust mod when the operator opts in). Process-wide;
        // read lazily when each hello is encoded.
        set_publish_rust_identity(config.publish_emule_rust_identity);
        let enable_udp_reask = config.enable_udp_reask;
        let reask_user_hash = network.user_hash;
        tasks.push(tokio::spawn(run_ed2k_server_loop(Ed2kServerLoopOptions {
            bind_ip: network.bind_ip,
            nat: Arc::clone(&nat),
            config,
            hello_identity,
            shared_catalog: self.ed2k_transfers.shared_catalog(),
            state: Arc::clone(&server_state),
            search_inbox,
            kad_firewall: Arc::clone(&kad_firewall),
            shutdown: Arc::clone(&shutdown),
            public_ip: ed2k_public_ip.clone(),
            reconnect_signal: server_reconnect_signal,
        })));
        if enable_udp_reask {
            // Off by default; wire-validate before enabling. udp_version 4 matches
            // our advertised hello ET_UDPVER. The handle lets the direct download
            // driver detach queued sources onto the loop over the command channel.
            let (reask_handle, reask_commands) = reask_command_channel();
            *self.ed2k_reask_handle.lock().unwrap() = Some(reask_handle);
            // Typed loop->core event channel (libtorrent-alert style) for re-engage.
            let (reask_events_tx, reask_events_rx) = reask_event_channel();
            tasks.push(tokio::spawn(run_ed2k_udp_reask_loop(
                dht.clone(),
                Arc::clone(&self.ed2k_transfers),
                reask_commands,
                reask_events_tx,
                reask_user_hash,
                4,
                ed2k_public_ip.clone(),
                network.ip_filter.clone(),
                Arc::clone(&shutdown),
            )));
            // Re-engage consumer: when a reask reports a low queue rank, the loop
            // hands the source back and signals here to reconnect over TCP now.
            tasks.push(tokio::spawn(run_ed2k_reask_reengage(
                self.clone(),
                reask_events_rx,
                Arc::clone(&shutdown),
            )));
            // Public-IP fallback (H2): the reask obfuscation key is our public IP
            // (eMule EncryptSendClient). It is normally learned from the server
            // (OP_IDCHANGE), but in Kad-only / pre-connect / LowID it is unknown,
            // which would block obfuscated reasks. STUN-probe the data-plane egress
            // and fill it only when still unknown (set_if_unset), so the server
            // path keeps precedence (eMule GetPublicIP order: server, then Kad/STUN).
            tasks.push(tokio::spawn(run_ed2k_public_ip_probe(
                network.bind_ip,
                ed2k_public_ip.clone(),
                Arc::clone(&shutdown),
            )));
            // One-shot NAT-type health signal (STUN mapping-behavior): logs whether
            // our advertised UDP port will match what peers observe (cone) or is
            // fragile (symmetric). Informational; reask degrades to TCP either way.
            tasks.push(tokio::spawn(run_ed2k_nat_type_probe(
                network.bind_ip,
                Arc::clone(&shutdown),
            )));
        }
        // Requester-side Kad UDP firewall self-check driver (oracle CUDPFirewallTester).
        // Drives FIREWALLED2_REQ-independent OP_FWCHECKUDPREQ rounds against open
        // v6+ helpers and feeds the peer-confirmed external UDP port back into
        // reachability. Off only when the operator disables it.
        let kad_firewall_recheck = if network.kad_udp_firewall_check_enabled {
            let recheck_signal = Arc::new(tokio::sync::Notify::new());
            tasks.push(tokio::spawn(
                kad_udp_firewall_check::run_kad_udp_firewall_check_loop(
                    kad_udp_firewall_check::KadUdpFirewallCheckOptions {
                        dht: dht.clone(),
                        ed2k_listener: Arc::clone(&ed2k_listener),
                        server_state: Arc::clone(&server_state),
                        kad_firewall: Arc::clone(&kad_firewall),
                        reachability: self.ed2k_reachability.clone(),
                        network: network.clone(),
                        recheck_signal: Arc::clone(&recheck_signal),
                        shutdown: Arc::clone(&shutdown),
                    },
                ),
            ));
            Some(recheck_signal)
        } else {
            None
        };
        // Requester-side Kad TCP firewall recheck driver (oracle FirewalledCheck
        // / GetRecheckIP). Asks open v6+ helpers to TCP connect-back via
        // KADEMLIA2_FIREWALLED2_REQ and derives a TCP-firewalled verdict from the
        // open acks + FIREWALLED_RES, so a pure-Kad node (no eD2k server) still
        // detects LowID and seeks a buddy. Off only when the operator disables it.
        if network.kad_tcp_firewall_check_enabled {
            tasks.push(tokio::spawn(
                kad_tcp_firewall_check::run_kad_tcp_firewall_check_loop(
                    kad_tcp_firewall_check::KadTcpFirewallCheckOptions {
                        dht: dht.clone(),
                        ed2k_listener: Arc::clone(&ed2k_listener),
                        server_state: Arc::clone(&server_state),
                        kad_firewall: Arc::clone(&kad_firewall),
                        network: network.clone(),
                        shutdown: Arc::clone(&shutdown),
                    },
                ),
            ));
        }
        *runtime_guard = Some(Ed2kRuntime {
            search_handle,
            server_state,
            dht,
            kad_bootstrap_configured: configured_bootstrap_nodes_text.is_some(),
            nat,
            shutdown,
            kad_firewall_recheck,
            tasks,
        });
        drop(runtime_guard);
        Ok(self.ed2k_status().await)
    }

    pub async fn disconnect_ed2k(&self) -> NetworkStatus {
        // Drop the reask detach handle so post-disconnect downloads stay on TCP
        // and the closed command channel lets the (aborted) loop wind down.
        *self.ed2k_reask_handle.lock().unwrap() = None;
        if let Some(runtime) = self.ed2k_runtime.lock().await.take() {
            runtime.shutdown.store(true, Ordering::SeqCst);
            for task in runtime.tasks {
                task.abort();
            }
            // WHY: REST disconnect must not hang behind network cleanup after a failed
            // server dial; the runtime has already been removed and tasks aborted.
            let _ = tokio::time::timeout(Duration::from_secs(2), runtime.nat.stop()).await;
        }
        self.ed2k_status().await
    }

    pub async fn servers(&self) -> Vec<ServerInfo> {
        let connected_endpoint = self.ed2k_connected_endpoint().await;
        let state = self.state.lock().await;
        let mut server_map = BTreeMap::<String, ServerInfo>::new();
        if let Some(network) = self.ed2k_network.as_ref() {
            for entry in &network.config.server_entries {
                let endpoint = format!("{}:{}", entry.host, entry.port);
                if state.disabled_servers.contains(&endpoint) {
                    continue;
                }
                let mut server = server_info_from_parts(
                    &entry.host,
                    entry.port,
                    entry.name.as_deref(),
                    entry.description.as_deref(),
                    true,
                    connected_endpoint.as_deref(),
                );
                apply_server_update(&mut server, state.server_overrides.get(&endpoint));
                server_map.insert(endpoint, server);
            }
            for endpoint in &network.config.server_endpoints {
                if state.disabled_servers.contains(endpoint) || server_map.contains_key(endpoint) {
                    continue;
                }
                if let Ok((address, port)) = parse_server_endpoint(endpoint) {
                    let mut server = server_info_from_parts(
                        &address,
                        port,
                        None,
                        None,
                        true,
                        connected_endpoint.as_deref(),
                    );
                    apply_server_update(&mut server, state.server_overrides.get(endpoint));
                    server_map.insert(endpoint.clone(), server);
                }
            }
        }
        for (endpoint, server) in &state.servers {
            if !state.disabled_servers.contains(endpoint) {
                let mut server = server.clone();
                server.current = connected_endpoint
                    .as_deref()
                    .is_some_and(|connected| connected == endpoint);
                server.connected = server.current;
                apply_server_update(&mut server, state.server_overrides.get(endpoint));
                server_map.insert(endpoint.clone(), server);
            }
        }
        drop(state);
        server_map.into_values().collect::<Vec<_>>()
    }

    pub async fn server(&self, endpoint: &str) -> Option<ServerInfo> {
        self.servers()
            .await
            .into_iter()
            .find(|server| server.endpoint.eq_ignore_ascii_case(endpoint))
    }

    pub async fn add_server(&self, request: ServerCreate) -> Result<ServerInfo> {
        let endpoint = server_endpoint_from_create(&request)?;
        let connected_endpoint = self.ed2k_connected_endpoint().await;
        let mut server = server_info_from_parts(
            &request.address,
            request.port,
            request.name.as_deref(),
            None,
            request.static_server.unwrap_or(false),
            connected_endpoint.as_deref(),
        );
        if let Some(priority) = request.priority.as_deref() {
            server.priority = validate_server_priority(priority)?.to_string();
        }
        profile_state::persist_server(&self.metadata_store, &server, true)?;
        let mut state = self.state.lock().await;
        state.disabled_servers.remove(&endpoint);
        state.servers.insert(endpoint, server.clone());
        drop(state);
        if request.connect.unwrap_or(false) {
            let _ = self.connect_ed2k_server(&server.endpoint).await?;
        }
        Ok(server)
    }

    pub async fn update_server(
        &self,
        endpoint: &str,
        request: ServerUpdate,
    ) -> Result<Option<ServerInfo>> {
        let Some(mut server) = self.server(endpoint).await else {
            return Ok(None);
        };
        validate_server_update(&request)?;
        apply_server_update(&mut server, Some(&request));
        profile_state::persist_server(&self.metadata_store, &server, true)?;
        let mut state = self.state.lock().await;
        if let Some(dynamic) = state.servers.get_mut(&server.endpoint) {
            apply_server_update(dynamic, Some(&request));
        }
        state
            .server_overrides
            .insert(server.endpoint.clone(), request);
        Ok(Some(server))
    }

    pub async fn remove_server(&self, endpoint: &str) -> Result<Option<ServerInfo>> {
        let Some(server) = self.server(endpoint).await else {
            return Ok(None);
        };
        profile_state::persist_server(&self.metadata_store, &server, false)?;
        let mut state = self.state.lock().await;
        state.servers.remove(&server.endpoint);
        state.server_overrides.remove(&server.endpoint);
        state.disabled_servers.insert(server.endpoint.clone());
        Ok(Some(server))
    }

    pub async fn create_search(&self, request: SearchCreate) -> Result<Search> {
        let search_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        // Local index results are cheap, so include them immediately.
        let mut results = Vec::new();
        let indexed = self.index.lock().await.search(&request.query, 200)?;
        results.extend(
            indexed
                .into_iter()
                .map(|file| search_result_from_indexed(&search_id, &request, file)),
        );
        apply_search_filters(&mut results, &request);
        // Create the search as "running" and return immediately; the slow ED2K
        // network search runs in the background and flips status to "completed".
        // This follows the eMuleBB contract's running->complete search lifecycle
        // so controllers (e.g. aMuTorrent) get a prompt POST and poll GET for
        // results instead of blocking the create call until the network replies.
        let search = Search {
            id: search_id.clone(),
            query: request.query.clone(),
            method: request.method.clone(),
            r#type: request.r#type.clone(),
            status: "running".to_string(),
            created_at: now,
            updated_at: now,
            results,
        };
        search_state::persist_search(&self.metadata_store, &search)?;
        self.state
            .lock()
            .await
            .searches
            .insert(search_id.clone(), search.clone());
        let core = self.clone();
        tokio::spawn(async move {
            core.run_background_search(search_id, request).await;
        });
        Ok(search)
    }

    /// Runs the ED2K network search for an already-created "running" search,
    /// merges any results with the local-index ones, and marks it completed.
    async fn run_background_search(&self, search_id: String, request: SearchCreate) {
        let outcome = self.search_ed2k_servers(&search_id, &request).await;
        let mut state = self.state.lock().await;
        let Some(search) = state.searches.get_mut(&search_id) else {
            return;
        };
        match outcome {
            Ok(ed2k_results) => {
                if let Some(mut ed2k_results) = ed2k_results {
                    apply_search_filters(&mut ed2k_results, &request);
                    let seen: std::collections::HashSet<String> = search
                        .results
                        .iter()
                        .map(|result| result.hash.clone())
                        .collect();
                    search.results.extend(
                        ed2k_results
                            .into_iter()
                            .filter(|result| !seen.contains(&result.hash)),
                    );
                }
                search.status = "completed".to_string();
            }
            Err(error) => {
                tracing::warn!("ED2K background search failed for {search_id}: {error:#}");
                search.status = "error".to_string();
            }
        }
        search.updated_at = Utc::now();
        let snapshot = search.clone();
        drop(state);
        if let Err(error) = search_state::persist_search(&self.metadata_store, &snapshot) {
            tracing::warn!("failed to persist completed search {search_id}: {error}");
        }
    }

    pub async fn searches(&self) -> Vec<Search> {
        self.state.lock().await.searches.values().cloned().collect()
    }

    pub async fn search(&self, search_id: &str) -> Option<Search> {
        self.state.lock().await.searches.get(search_id).cloned()
    }

    pub async fn delete_search(&self, search_id: &str) -> Result<bool> {
        let persisted = self.metadata_store.delete_search(search_id)?;
        let cached = self.state.lock().await.searches.remove(search_id).is_some();
        Ok(persisted || cached)
    }

    pub async fn clear_searches(&self) -> Result<()> {
        self.metadata_store.clear_searches()?;
        self.state.lock().await.searches.clear();
        Ok(())
    }

    pub async fn categories(&self) -> Vec<Category> {
        self.state
            .lock()
            .await
            .categories
            .values()
            .cloned()
            .collect()
    }

    pub async fn category(&self, category_id: u32) -> Option<Category> {
        self.state
            .lock()
            .await
            .categories
            .get(&category_id)
            .cloned()
    }

    pub async fn create_category(&self, request: CategoryCreate) -> Result<Category> {
        let mut category = Category {
            id: 0,
            name: String::new(),
            path: None,
            comment: String::new(),
            priority: PR_NORMAL,
            color: None,
        };
        apply_category_create(&mut category, request)?;
        let mut state = self.state.lock().await;
        let category_id = state.next_category_id;
        state.next_category_id = state.next_category_id.saturating_add(1).max(1);
        category.id = category_id;
        profile_state::persist_category(&self.metadata_store, &category)?;
        state.categories.insert(category_id, category.clone());
        Ok(category)
    }

    pub async fn update_category(
        &self,
        category_id: u32,
        request: CategoryUpdate,
    ) -> Result<Option<Category>> {
        ensure!(category_id != 0, "default category cannot be updated");
        let mut state = self.state.lock().await;
        let Some(category) = state.categories.get_mut(&category_id) else {
            return Ok(None);
        };
        let mut updated = category.clone();
        apply_category_update(&mut updated, request)?;
        profile_state::persist_category(&self.metadata_store, &updated)?;
        *category = updated.clone();
        Ok(Some(updated))
    }

    pub async fn delete_category(&self, category_id: u32) -> Result<Option<Category>> {
        ensure!(category_id != 0, "default category cannot be deleted");
        let mut state = self.state.lock().await;
        let Some(category) = state.categories.get(&category_id).cloned() else {
            return Ok(None);
        };
        self.metadata_store.delete_category(category_id)?;
        state.categories.remove(&category_id);
        Ok(Some(category))
    }

    pub async fn friends(&self) -> Vec<Friend> {
        self.state.lock().await.friends.values().cloned().collect()
    }

    pub async fn add_friend(&self, request: FriendCreate) -> Result<Friend> {
        let user_hash = normalize_user_hash(&request.user_hash)?;
        let name = normalize_friend_name(request.name.as_deref())?;
        let mut state = self.state.lock().await;
        if let Some(friend) = state.friends.get(&user_hash) {
            return Ok(friend.clone());
        }
        let friend = Friend {
            user_hash: user_hash.clone(),
            name,
            last_seen: None,
            address: None,
            port: 0,
        };
        profile_state::persist_friend(&self.metadata_store, &friend)?;
        state.friends.insert(user_hash, friend.clone());
        Ok(friend)
    }

    pub async fn delete_friend(&self, user_hash: &str) -> Result<Option<Friend>> {
        let user_hash = normalize_user_hash(user_hash)?;
        let mut state = self.state.lock().await;
        let Some(friend) = state.friends.get(&user_hash).cloned() else {
            return Ok(None);
        };
        self.metadata_store.delete_friend(&user_hash)?;
        state.friends.remove(&user_hash);
        Ok(Some(friend))
    }

    pub async fn download_search_result(
        &self,
        search_id: &str,
        hash: &str,
        request: SearchResultDownloadCreate,
    ) -> Result<Option<Transfer>> {
        ensure_category_selector_is_unambiguous(
            request.category_id,
            request.category_name.as_deref(),
        )?;
        let category = self
            .resolve_transfer_category(request.category_id, request.category_name.as_deref())
            .await?;
        let result = {
            let state = self.state.lock().await;
            state
                .searches
                .get(search_id)
                .and_then(|search| search.results.iter().find(|result| result.hash == hash))
                .cloned()
        };
        let Some(result) = result else {
            return Ok(None);
        };
        self.upsert_transfer_from_parts(
            result.hash,
            result.name,
            result.size_bytes,
            transfer_create_state_name(request.paused),
            Some(category),
        )
        .await
        .map(Some)
    }

    pub async fn create_transfer(&self, request: TransferCreate) -> Result<Transfer> {
        let mut transfers = self.create_transfers(request).await?;
        ensure!(
            transfers.len() == 1,
            "create_transfer requires exactly one transfer link"
        );
        Ok(transfers.remove(0))
    }

    pub async fn create_transfers(&self, request: TransferCreate) -> Result<Vec<Transfer>> {
        ensure_category_selector_is_unambiguous(
            request.category_id,
            request.category_name.as_deref(),
        )?;
        let category = self
            .resolve_transfer_category(request.category_id, request.category_name.as_deref())
            .await?;
        let state_name = transfer_create_state_name(request.paused);
        let links = transfer_create_links(request)?;
        let mut transfers = Vec::with_capacity(links.len());
        for link in links {
            let parsed = parse_ed2k_link(&link)?;
            transfers.push(
                self.upsert_transfer_from_parts(
                    parsed.0,
                    parsed.1,
                    parsed.2,
                    state_name,
                    Some(category.clone()),
                )
                .await?,
            );
        }
        Ok(transfers)
    }

    pub async fn transfers(&self) -> Vec<Transfer> {
        if let Err(error) = self.refresh_transfers_from_manifests().await {
            tracing::warn!("failed to refresh ED2K transfers from manifests: {error}");
        }
        self.state
            .lock()
            .await
            .transfers
            .values()
            .cloned()
            .collect()
    }

    pub async fn share_local_file(&self, request: LocalShareCreate) -> Result<LocalShare> {
        let source_path = Path::new(&request.path);
        let canonical_name = match request.name {
            Some(name) => name,
            None => source_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow::anyhow!("local share path has no valid file name"))?
                .to_string(),
        };
        let summary = self
            .ed2k_transfers
            .ingest_local_file(source_path, &canonical_name)
            .await?;
        self.metadata_store
            .unmark_unshared_file(&summary.file_hash)?;
        self.state
            .lock()
            .await
            .unshared_hashes
            .remove(&summary.file_hash);
        self.index.lock().await.upsert_file(&IndexedFile {
            ed2k_hash: summary.file_hash.clone(),
            name: summary.canonical_name.clone(),
            size_bytes: summary.file_size,
            content_type: ed2k_file_type_search_term(&summary.canonical_name)
                .unwrap_or("unknown")
                .to_string(),
            availability_score: 1,
        })?;
        self.refresh_transfer_from_manifest(&summary.file_hash, "completed")
            .await?;
        if let Err(error) = self.publish_ed2k_shared_catalog().await {
            tracing::warn!("failed to refresh ED2K shared catalog advertisement: {error}");
        }
        Ok(local_share_from_summary(summary))
    }

    pub async fn shares(&self) -> Vec<LocalShare> {
        let unshared_hashes = self.state.lock().await.unshared_hashes.clone();
        match self.ed2k_transfers.manifests().await {
            Ok(manifests) => manifests
                .into_iter()
                .filter(|manifest| {
                    manifest.completed && !unshared_hashes.contains(&manifest.file_hash)
                })
                .map(|manifest| LocalShare {
                    hash: manifest.file_hash.clone(),
                    name: manifest.canonical_name.clone(),
                    size_bytes: manifest.file_size,
                    part_count: ed2k_part_count(manifest.file_size),
                    ed2k_link: format!(
                        "ed2k://|file|{}|{}|{}|/",
                        manifest.canonical_name, manifest.file_size, manifest.file_hash
                    ),
                    aich_root: manifest.aich_root.clone().unwrap_or_default(),
                    transfer_dir: self
                        .ed2k_transfers
                        .transfer_dir_path(&manifest.file_hash)
                        .display()
                        .to_string(),
                    priority: manifest.upload_priority.clone(),
                    auto_upload_priority: manifest.auto_upload_priority,
                    comment: manifest.comment.clone(),
                    rating: manifest.rating,
                })
                .collect(),
            Err(error) => {
                tracing::warn!("failed to enumerate ED2K shared-file manifests: {error}");
                Vec::new()
            }
        }
    }

    pub async fn share(&self, hash: &str) -> Option<LocalShare> {
        self.shares()
            .await
            .into_iter()
            .find(|share| share.hash.eq_ignore_ascii_case(hash))
    }

    pub async fn update_shared_file(
        &self,
        hash: &str,
        request: SharedFileUpdate,
    ) -> Result<Option<LocalShare>> {
        let Some(_share) = self.share(hash).await else {
            return Ok(None);
        };
        let priority = request
            .priority
            .as_deref()
            .map(validate_shared_upload_priority)
            .transpose()?
            .map(|priority| (priority.0.to_string(), priority.1));
        let comment_rating = validate_shared_file_comment_rating(&request)?;
        if priority.is_none() && comment_rating.is_none() {
            anyhow::bail!("shared-file PATCH requires priority, comment, or rating");
        }
        self.ed2k_transfers
            .update_shared_file_metadata(
                hash,
                priority
                    .as_ref()
                    .map(|(priority, auto)| (priority.as_str(), *auto)),
                comment_rating
                    .as_ref()
                    .map(|(comment, rating)| (comment.as_str(), *rating)),
            )
            .await?;
        Ok(self.share(hash).await)
    }

    pub async fn unshare_file(&self, hash: &str) -> Result<Option<LocalShare>> {
        let Some(share) = self.share(hash).await else {
            return Ok(None);
        };
        self.ed2k_transfers
            .remove_completed_transfer_row(&share.hash)
            .await?;
        ensure!(
            self.metadata_store
                .mark_unshared_file(&share.hash, "manual")?,
            "shared file metadata row is missing"
        );
        let mut state = self.state.lock().await;
        state.transfers.remove(&share.hash);
        state.unshared_hashes.insert(share.hash.clone());
        Ok(Some(share))
    }

    pub async fn shared_directories(&self) -> SharedDirectories {
        let roots = self
            .state
            .lock()
            .await
            .shared_directories
            .iter()
            .map(refresh_shared_directory_row)
            .collect::<Vec<_>>();
        SharedDirectories {
            roots: roots.clone(),
            items: roots,
            monitor_owned: Vec::new(),
            hashing_count: 0,
        }
    }

    pub async fn set_shared_directories(
        &self,
        request: SharedDirectoriesUpdate,
    ) -> Result<SharedDirectories> {
        ensure!(
            request.confirm_replace_roots,
            "confirmReplaceRoots must be true"
        );
        let mut seen = HashSet::new();
        let mut roots = Vec::new();
        for root in request.roots {
            let (path, recursive) = shared_directory_update_parts(root);
            let path = path.trim();
            ensure!(!path.is_empty(), "path must not be empty");
            let canonical =
                fs::canonicalize(path).with_context(|| format!("failed to resolve {path}"))?;
            let metadata = fs::metadata(&canonical)
                .with_context(|| format!("failed to inspect {}", canonical.display()))?;
            ensure!(metadata.is_dir(), "path is not a directory");
            let canonical_path = canonical.display().to_string();
            if seen.insert(canonical_path.clone()) {
                roots.push(SharedDirectoryRoot {
                    path: canonical_path,
                    recursive,
                    monitor_owned: false,
                    shareable: true,
                    accessible: true,
                });
            }
        }
        self.index.lock().await.replace_shared_directory_roots(
            &roots
                .iter()
                .map(shared_directory_to_index)
                .collect::<Vec<_>>(),
        )?;
        self.state.lock().await.shared_directories = roots;
        Ok(self.shared_directories().await)
    }

    pub async fn reload_shared_directories(&self) -> Result<Vec<LocalShare>> {
        let roots = self.state.lock().await.shared_directories.clone();
        let mut file_paths = Vec::new();
        for root in roots {
            collect_shared_directory_files(Path::new(&root.path), root.recursive, &mut file_paths)
                .with_context(|| format!("failed to scan shared directory {}", root.path))?;
        }
        file_paths.sort();
        file_paths.dedup();

        let mut shares = Vec::new();
        for path in file_paths {
            shares.push(
                self.share_local_file(LocalShareCreate {
                    path: path.display().to_string(),
                    name: None,
                })
                .await?,
            );
        }
        Ok(shares)
    }

    pub async fn uploads(&self) -> Vec<Upload> {
        self.uploads_by_queue_state(false).await
    }

    pub async fn upload_queue(&self) -> Vec<Upload> {
        self.uploads_by_queue_state(true).await
    }

    pub async fn upload_policy_metrics(&self) -> UploadPolicyMetrics {
        upload_policy_metrics_from_capacity(
            self.ed2k_transfers.upload_queue_capacity_snapshot().await,
        )
    }

    pub async fn download_source_metrics(&self) -> DownloadSourceMetrics {
        let state = self.state.lock().await;
        DownloadSourceMetrics {
            candidates: state.download_source_registry.candidate_count(),
            a4af_candidates: state.download_source_registry.a4af_candidate_count(),
            leased_peers: state.download_source_registry.leased_peer_count(),
        }
    }

    /// Live transfer throughput roll-up for the REST `stats` surface.
    pub fn transfer_throughput_stats(&self) -> TransferThroughputStats {
        TransferThroughputStats {
            download_rate_bytes_per_sec: self
                .ed2k_transfers
                .aggregate_download_speed_bytes_per_sec(),
            session_downloaded_bytes: self.ed2k_transfers.session_downloaded_bytes(),
            session_uploaded_bytes: self.ed2k_transfers.session_uploaded_bytes(),
        }
    }

    pub async fn upload(&self, client_id: &str, waiting_queue: bool) -> Option<Upload> {
        self.uploads_by_queue_state(waiting_queue)
            .await
            .into_iter()
            .find(|upload| upload.client_id == client_id)
    }

    pub async fn add_upload_client_friend(&self, client_id: &str) -> Result<Option<Friend>> {
        let Some(upload) = self.upload_client_for_control(client_id).await else {
            return Ok(None);
        };
        let Some(user_hash) = upload.user_hash.as_deref() else {
            anyhow::bail!("upload client does not expose a userHash");
        };
        self.add_friend(FriendCreate {
            user_hash: user_hash.to_string(),
            name: Some(upload.user_name),
        })
        .await
        .map(Some)
    }

    pub async fn remove_upload_client_friend(&self, client_id: &str) -> Result<Option<Friend>> {
        let Some(upload) = self.upload_client_for_control(client_id).await else {
            return Ok(None);
        };
        let Some(user_hash) = upload.user_hash.as_deref() else {
            return Ok(None);
        };
        self.delete_friend(user_hash).await
    }

    pub async fn ban_upload_client(&self, client_id: &str) -> Result<Option<bool>> {
        let Some(upload) = self.upload_client_for_control(client_id).await else {
            return Ok(None);
        };
        self.state
            .lock()
            .await
            .banned_source_clients
            .insert(upload.client_id);
        Ok(Some(true))
    }

    pub async fn unban_upload_client(&self, client_id: &str) -> Result<Option<bool>> {
        let Some(upload) = self.upload_client_for_control(client_id).await else {
            return Ok(None);
        };
        self.state
            .lock()
            .await
            .banned_source_clients
            .remove(&upload.client_id);
        Ok(Some(false))
    }

    pub async fn remove_upload_client(&self, client_id: &str) -> Result<Option<&'static str>> {
        if self
            .ed2k_transfers
            .release_upload_client(client_id, true)
            .await
        {
            return Ok(Some("queue"));
        }
        if self
            .ed2k_transfers
            .release_upload_client(client_id, false)
            .await
        {
            return Ok(Some("slot"));
        }
        if self.upload_client_for_control(client_id).await.is_none() {
            return Ok(None);
        }
        anyhow::bail!("upload client is not active or queued");
    }

    pub async fn release_upload_slot(&self, client_id: &str) -> Result<Option<()>> {
        if self.upload(client_id, false).await.is_some() {
            if self
                .ed2k_transfers
                .release_upload_client(client_id, false)
                .await
            {
                return Ok(Some(()));
            }
            return Ok(None);
        }
        if self.upload(client_id, true).await.is_some() {
            anyhow::bail!("client does not currently hold an upload slot");
        }
        Ok(None)
    }

    pub async fn transfer(&self, hash: &str) -> Option<Transfer> {
        if let Some(transfer) = self.state.lock().await.transfers.get(hash).cloned() {
            return Some(transfer);
        }
        match self.refresh_transfer_from_manifest_default(hash).await {
            Ok(transfer) => transfer,
            Err(error) => {
                tracing::warn!("failed to refresh ED2K transfer {hash} from manifest: {error}");
                None
            }
        }
    }

    pub async fn update_transfer(
        &self,
        hash: &str,
        request: TransferUpdate,
    ) -> Result<Option<Transfer>> {
        validate_transfer_update_family(&request)?;
        if self.transfer(hash).await.is_none() {
            return Ok(None);
        }
        if let Some(priority) = request.priority.as_deref() {
            let priority = validate_transfer_priority(priority)?.to_string();
            let mut state = self.state.lock().await;
            let Some(transfer) = state.transfers.get_mut(hash) else {
                return Ok(None);
            };
            transfer.priority = priority;
            return Ok(Some(transfer.clone()));
        }
        if request.category_id.is_some() || request.category_name.is_some() {
            let (category_id, category_name) = self
                .resolve_transfer_category(request.category_id, request.category_name.as_deref())
                .await?;
            let mut state = self.state.lock().await;
            let Some(transfer) = state.transfers.get_mut(hash) else {
                return Ok(None);
            };
            transfer.category_id = category_id;
            transfer.category_name = category_name;
            return Ok(Some(transfer.clone()));
        }
        let name = normalize_transfer_name(request.name)?;
        let current = self.state.lock().await.transfers.get(hash).cloned();
        if current
            .as_ref()
            .is_some_and(|transfer| matches!(transfer.state.as_str(), "completed" | "completing"))
        {
            anyhow::bail!("completed transfers cannot be renamed through this endpoint");
        }
        let manifest = self
            .ed2k_transfers
            .reconcile_job_metadata(hash, Some(&name), None)
            .await?;
        let state_name = current
            .as_ref()
            .map(|transfer| transfer.state.as_str())
            .unwrap_or_else(|| manifest_default_state_name(&manifest));
        let mut transfer = self.transfer_from_manifest(&manifest, state_name);
        if let Some(existing) = current.as_ref() {
            preserve_transfer_public_metadata(&mut transfer, existing);
        }
        transfer.name = name;
        transfer.ed2k_link = format!(
            "ed2k://|file|{}|{}|{}|/",
            transfer.name, transfer.size_bytes, transfer.hash
        );
        self.state
            .lock()
            .await
            .transfers
            .insert(transfer.hash.clone(), transfer.clone());
        Ok(Some(transfer))
    }

    pub async fn transfer_sources(&self, hash: &str) -> Result<Option<Vec<TransferSource>>> {
        if self.transfer(hash).await.is_none() {
            return Ok(None);
        }
        let manifest = self.ed2k_transfers.manifest(hash).await?;
        let banned = self.state.lock().await.banned_source_clients.clone();
        let mut sources = transfer_sources_from_manifest(&manifest, &banned);
        enrich_sources_with_live(
            &mut sources,
            &self.ed2k_transfers.live_download_sources(hash),
            manifest.pieces.len() as u32,
        );
        Ok(Some(sources))
    }

    /// Transfer details: the transfer plus its per-part breakdown and source
    /// list, mirroring the master `BuildTransferDetailsJson` shape.
    pub async fn transfer_details(&self, hash: &str) -> Result<Option<TransferDetails>> {
        let Some(transfer) = self.transfer(hash).await else {
            return Ok(None);
        };
        let manifest = self.ed2k_transfers.manifest(hash).await?;
        let banned = self.state.lock().await.banned_source_clients.clone();
        let part_total = manifest.pieces.len() as u32;
        let mut sources = transfer_sources_from_manifest(&manifest, &banned);
        enrich_sources_with_live(
            &mut sources,
            &self.ed2k_transfers.live_download_sources(hash),
            part_total,
        );
        let available_sources_per_part = self
            .ed2k_transfers
            .available_sources_per_part(hash, part_total);
        let parts = transfer_parts_from_manifest(&manifest, &available_sources_per_part);
        Ok(Some(TransferDetails {
            transfer,
            parts,
            sources,
        }))
    }

    pub async fn transfer_source(
        &self,
        hash: &str,
        client_id: &str,
    ) -> Result<Option<TransferSource>> {
        validate_source_client_id(client_id)?;
        Ok(self
            .transfer_sources(hash)
            .await?
            .and_then(|sources| source_by_client_id(sources, client_id)))
    }

    pub async fn browse_transfer_source(&self, hash: &str, client_id: &str) -> Result<bool> {
        let Some(source) = self.transfer_source(hash, client_id).await? else {
            return Ok(false);
        };
        ensure!(
            source.view_shared_files,
            "transfer source does not support shared-file browsing"
        );
        Ok(true)
    }

    pub async fn add_transfer_source_friend(
        &self,
        hash: &str,
        client_id: &str,
    ) -> Result<Option<Friend>> {
        let Some(source) = self.transfer_source(hash, client_id).await? else {
            return Ok(None);
        };
        let Some(user_hash) = source.user_hash.as_deref() else {
            anyhow::bail!("transfer source does not expose a userHash");
        };
        self.add_friend(FriendCreate {
            user_hash: user_hash.to_string(),
            name: Some(source_friend_name(&source)),
        })
        .await
        .map(Some)
    }

    pub async fn remove_transfer_source_friend(
        &self,
        hash: &str,
        client_id: &str,
    ) -> Result<Option<Friend>> {
        let Some(source) = self.transfer_source(hash, client_id).await? else {
            return Ok(None);
        };
        let Some(user_hash) = source.user_hash.as_deref() else {
            return Ok(None);
        };
        self.delete_friend(user_hash).await
    }

    pub async fn ban_transfer_source(&self, hash: &str, client_id: &str) -> Result<Option<bool>> {
        let Some(source) = self.transfer_source(hash, client_id).await? else {
            return Ok(None);
        };
        self.state
            .lock()
            .await
            .banned_source_clients
            .insert(source.client_id);
        Ok(Some(true))
    }

    pub async fn unban_transfer_source(&self, hash: &str, client_id: &str) -> Result<Option<bool>> {
        let Some(source) = self.transfer_source(hash, client_id).await? else {
            return Ok(None);
        };
        self.state
            .lock()
            .await
            .banned_source_clients
            .remove(&source.client_id);
        Ok(Some(false))
    }

    pub async fn remove_transfer_source(&self, hash: &str, client_id: &str) -> Result<Option<()>> {
        validate_source_client_id(client_id)?;
        if self.transfer(hash).await.is_none() {
            return Ok(None);
        }
        if !self.ed2k_transfers.remove_source(hash, client_id).await? {
            return Ok(None);
        }
        self.state
            .lock()
            .await
            .banned_source_clients
            .remove(client_id);
        Ok(Some(()))
    }

    pub async fn pause_transfer(&self, hash: &str) -> Result<Option<Transfer>> {
        self.set_transfer_control_state(hash, "paused").await
    }

    pub async fn stop_transfer(&self, hash: &str) -> Result<Option<Transfer>> {
        self.set_transfer_control_state(hash, "stopped").await
    }

    pub async fn recheck_transfer(&self, hash: &str) -> Result<Option<()>> {
        let Some(current) = self.transfer(hash).await else {
            return Ok(None);
        };
        ensure!(
            !matches!(current.state.as_str(), "hashing" | "completing"),
            "transfer is already being hashed or completed"
        );
        Ok(Some(()))
    }

    pub async fn preview_transfer(&self, hash: &str) -> Result<Option<Transfer>> {
        let Some(transfer) = self.transfer(hash).await else {
            return Ok(None);
        };
        ensure!(
            transfer.state == "completed",
            "transfer is not ready for preview"
        );
        Ok(Some(transfer))
    }

    pub async fn delete_transfer_files(&self, hash: &str) -> Result<Option<Transfer>> {
        let transfer = if let Some(transfer) = self.transfer(hash).await {
            transfer
        } else {
            let Ok(manifest) = self.ed2k_transfers.manifest(hash).await else {
                return Ok(None);
            };
            let state_name = manifest_default_state_name(&manifest);
            self.transfer_from_manifest(&manifest, state_name)
        };
        if !self.ed2k_transfers.delete_transfer_files(hash).await? {
            return Ok(None);
        }
        self.metadata_store.unmark_unshared_file(hash)?;
        let mut state = self.state.lock().await;
        state.transfers.remove(hash);
        state.unshared_hashes.remove(hash);
        Ok(Some(transfer))
    }

    pub async fn delete_completed_transfer_row(&self, hash: &str) -> Result<Option<Transfer>> {
        let Some(transfer) = self.transfer(hash).await else {
            return Ok(None);
        };
        self.ed2k_transfers
            .remove_completed_transfer_row(hash)
            .await?;
        self.state.lock().await.transfers.remove(hash);
        Ok(Some(transfer))
    }

    pub async fn clear_completed_transfer_rows(&self) -> Result<()> {
        let hashes = {
            let state = self.state.lock().await;
            state
                .transfers
                .values()
                .filter(|transfer| transfer.state == "completed")
                .map(|transfer| transfer.hash.clone())
                .collect::<Vec<_>>()
        };
        for hash in hashes {
            self.ed2k_transfers
                .remove_completed_transfer_row(&hash)
                .await?;
            self.state.lock().await.transfers.remove(&hash);
        }
        Ok(())
    }

    async fn uploads_by_queue_state(&self, waiting_queue: bool) -> Vec<Upload> {
        let manifests = match self.ed2k_transfers.manifests().await {
            Ok(manifests) => manifests
                .into_iter()
                .map(|manifest| (manifest.file_hash.clone(), manifest))
                .collect::<HashMap<_, _>>(),
            Err(error) => {
                tracing::warn!("failed to enumerate ED2K manifests for upload snapshot: {error}");
                HashMap::new()
            }
        };
        self.ed2k_transfers
            .upload_queue_snapshot()
            .await
            .into_iter()
            .filter(|entry| {
                matches!(entry.phase, Ed2kUploadSessionPhaseSnapshot::Waiting) == waiting_queue
            })
            .map(|entry| {
                let manifest = manifests.get(&entry.file_hash);
                upload_from_snapshot(entry, manifest)
            })
            .collect()
    }

    async fn upload_client_for_control(&self, client_id: &str) -> Option<Upload> {
        if let Some(upload) = self.upload(client_id, false).await {
            return Some(upload);
        }
        self.upload(client_id, true).await
    }

    fn transfer_from_manifest(&self, manifest: &Ed2kResumeManifest, state_name: &str) -> Transfer {
        let parts_total = manifest.pieces.len() as u32;
        let mut transfer = transfer_from_manifest(
            manifest,
            state_name,
            self.ed2k_transfers
                .payload_path(&manifest.file_hash)
                .display()
                .to_string(),
            self.ed2k_transfers
                .download_speed_bytes_per_sec(&manifest.file_hash),
            self.ed2k_transfers
                .transferring_source_count(&manifest.file_hash),
            self.ed2k_transfers
                .available_part_count(&manifest.file_hash, parts_total),
        );
        // Surface persisted addedAt/completedAt from the metadata store.
        if let Ok(Some((created_ms, completed_ms))) = self
            .metadata_store
            .transfer_timestamps_by_hash(&manifest.file_hash)
        {
            transfer.added_at = Some(created_ms);
            transfer.completed_at = completed_ms;
        }
        transfer
    }

    async fn set_transfer_state(&self, hash: &str, state_name: &str) -> Option<Transfer> {
        let mut state = self.state.lock().await;
        let transfer = state.transfers.get_mut(hash)?;
        transfer.state = state_name.to_string();
        Some(transfer.clone())
    }

    async fn set_transfer_control_state(
        &self,
        hash: &str,
        state_name: &str,
    ) -> Result<Option<Transfer>> {
        if self.transfer(hash).await.is_none() {
            return Ok(None);
        }
        let manifest = self
            .ed2k_transfers
            .set_control_state(hash, Some(state_name))
            .await?;
        let transfer = self.transfer_from_manifest(&manifest, state_name);
        self.state
            .lock()
            .await
            .transfers
            .insert(transfer.hash.clone(), transfer.clone());
        Ok(Some(transfer))
    }

    pub async fn resume_transfer(&self, hash: &str) -> Result<Option<Transfer>> {
        let Some(current) = self.transfer(hash).await else {
            return Ok(None);
        };
        if current.state == "completed" {
            return Ok(Some(current));
        }
        anyhow::ensure!(!current.stopped, "stopped transfer cannot be resumed");
        self.ed2k_transfers.set_control_state(hash, None).await?;
        let Some(transfer) = self.set_transfer_state(hash, "downloading").await else {
            return Ok(None);
        };
        self.queue_ed2k_download_attempt(transfer.clone()).await;
        Ok(Some(transfer))
    }

    pub async fn index_file(&self, file: IndexedFile) -> Result<()> {
        self.index.lock().await.upsert_file(&file)
    }

    async fn effective_ed2k_config(
        &self,
        base: &Ed2kConfig,
        target_endpoint: Option<&str>,
    ) -> Result<Ed2kConfig> {
        if let Some(target) = target_endpoint {
            let _ = parse_server_endpoint(target)?;
        }
        let mut config = base.clone();
        let state = self.state.lock().await;
        config.server_entries.retain(|entry| {
            let endpoint = format!("{}:{}", entry.host, entry.port);
            !state.disabled_servers.contains(&endpoint)
                && target_endpoint.is_none_or(|target| target.eq_ignore_ascii_case(&endpoint))
        });
        config.server_endpoints.retain(|endpoint| {
            !state.disabled_servers.contains(endpoint)
                && target_endpoint.is_none_or(|target| target.eq_ignore_ascii_case(endpoint))
        });
        for (endpoint, server) in &state.servers {
            if state.disabled_servers.contains(endpoint)
                || target_endpoint.is_some_and(|target| !target.eq_ignore_ascii_case(endpoint))
            {
                continue;
            }
            let exists = config.server_entries.iter().any(|entry| {
                format!("{}:{}", entry.host, entry.port).eq_ignore_ascii_case(endpoint)
            }) || config
                .server_endpoints
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(endpoint));
            if !exists {
                config
                    .server_endpoints
                    .push(format!("{}:{}", server.address, server.port));
            }
        }
        Ok(config)
    }

    async fn upsert_transfer_from_parts(
        &self,
        hash: String,
        name: String,
        size_bytes: u64,
        state_name: &str,
        category: Option<(u32, String)>,
    ) -> Result<Transfer> {
        let file_hash = hash.parse()?;
        let job = new_transfer_job(file_hash, name, size_bytes);
        let mut manifest = self.ed2k_transfers.ensure_job(&job).await?;
        if manifest.transfer_row_removed {
            manifest = self
                .ed2k_transfers
                .restore_transfer_row(&manifest.file_hash)
                .await?;
        }
        if matches!(state_name, "paused" | "stopped") {
            manifest = self
                .ed2k_transfers
                .set_control_state(&manifest.file_hash, Some(state_name))
                .await?;
        } else {
            // Active create: clear any prior paused/stopped control so the
            // download driver runs (matches resume_transfer).
            manifest = self
                .ed2k_transfers
                .set_control_state(&manifest.file_hash, None)
                .await?;
        }
        let mut transfer = self.transfer_from_manifest(&manifest, state_name);
        if let Some(existing) = self
            .state
            .lock()
            .await
            .transfers
            .get(&transfer.hash)
            .cloned()
        {
            preserve_transfer_public_metadata(&mut transfer, &existing);
        }
        if let Some((category_id, category_name)) = category {
            transfer.category_id = category_id;
            transfer.category_name = category_name;
        }
        self.state
            .lock()
            .await
            .transfers
            .insert(transfer.hash.clone(), transfer.clone());
        // Non-paused downloads start immediately: kick the download driver so
        // ED2K source acquisition begins without requiring an explicit resume.
        if !matches!(state_name, "paused" | "stopped") {
            self.queue_ed2k_download_attempt(transfer.clone()).await;
        }
        Ok(transfer)
    }

    async fn refresh_transfers_from_manifests(&self) -> Result<()> {
        let manifests = self.ed2k_transfers.manifests().await?;
        let mut state = self.state.lock().await;
        for manifest in manifests {
            if manifest.transfer_row_removed {
                state.transfers.remove(&manifest.file_hash);
                continue;
            }
            let state_name = state
                .transfers
                .get(&manifest.file_hash)
                .map(|transfer| transfer.state.clone())
                .unwrap_or_else(|| manifest_default_state_name(&manifest).to_string());
            let mut transfer = self.transfer_from_manifest(&manifest, &state_name);
            if let Some(existing) = state.transfers.get(&manifest.file_hash) {
                preserve_transfer_public_metadata(&mut transfer, existing);
            }
            state.transfers.insert(transfer.hash.clone(), transfer);
        }
        Ok(())
    }

    async fn refresh_transfer_from_manifest(
        &self,
        hash: &str,
        state_name: &str,
    ) -> Result<Option<Transfer>> {
        let manifest = self.ed2k_transfers.manifest(hash).await?;
        let mut transfer = self.transfer_from_manifest(&manifest, state_name);
        let mut state = self.state.lock().await;
        if let Some(existing) = state.transfers.get(&transfer.hash) {
            preserve_transfer_public_metadata(&mut transfer, existing);
        }
        state
            .transfers
            .insert(transfer.hash.clone(), transfer.clone());
        Ok(Some(transfer))
    }

    async fn refresh_transfer_from_manifest_default(&self, hash: &str) -> Result<Option<Transfer>> {
        let manifest = self.ed2k_transfers.manifest(hash).await?;
        if manifest.transfer_row_removed {
            self.state
                .lock()
                .await
                .transfers
                .remove(&manifest.file_hash);
            return Ok(None);
        }
        let state_name = manifest_default_state_name(&manifest);
        let mut transfer = self.transfer_from_manifest(&manifest, state_name);
        let mut state = self.state.lock().await;
        if let Some(existing) = state.transfers.get(&transfer.hash) {
            preserve_transfer_public_metadata(&mut transfer, existing);
        }
        state
            .transfers
            .insert(transfer.hash.clone(), transfer.clone());
        Ok(Some(transfer))
    }

    async fn resolve_transfer_category(
        &self,
        category_id: Option<u32>,
        category_name: Option<&str>,
    ) -> Result<(u32, String)> {
        let state = self.state.lock().await;
        if let Some(category_id) = category_id {
            let Some(category) = state.categories.get(&category_id) else {
                anyhow::bail!("category is out of range");
            };
            return Ok((category.id, category.name.clone()));
        }
        let Some(category_name) = category_name.map(str::trim) else {
            let category = state
                .categories
                .get(&0)
                .expect("default category must exist");
            return Ok((category.id, category.name.clone()));
        };
        ensure!(!category_name.is_empty(), "categoryName must not be empty");
        if category_name.eq_ignore_ascii_case("Default")
            || category_name.eq_ignore_ascii_case("All")
        {
            let category = state
                .categories
                .get(&0)
                .expect("default category must exist");
            return Ok((category.id, category.name.clone()));
        }
        let Some(category) = state
            .categories
            .values()
            .find(|category| category.name.eq_ignore_ascii_case(category_name))
        else {
            anyhow::bail!("categoryName does not match a configured category");
        };
        Ok((category.id, category.name.clone()))
    }

    async fn search_ed2k_servers(
        &self,
        search_id: &str,
        request: &SearchCreate,
    ) -> Result<Option<Vec<SearchResult>>> {
        let Some(network) = self.ed2k_network.as_ref() else {
            return Ok(None);
        };
        let config = self.effective_ed2k_config(&network.config, None).await?;
        if config.server_entries.is_empty() && config.server_endpoints.is_empty() {
            return Ok(None);
        }

        let cancel = CancellationToken::new();
        let mut background_search_available = false;
        if let Some(handle) = self.connected_ed2k_search_handle().await {
            background_search_available = true;
            let timeout = Duration::from_secs(config.connect_timeout_secs.max(15));
            match search_keyword_via_background_session(&handle, &request.query, timeout, &cancel)
                .await
            {
                Ok(files) if !files.is_empty() => {
                    return Ok(Some(
                        files
                            .into_iter()
                            .map(|file| search_result_from_ed2k(search_id, request, file))
                            .collect(),
                    ));
                }
                Ok(_) => tracing::warn!(
                    "ED2K background keyword search returned no results query={:?}; falling back to one-shot search",
                    request.query
                ),
                Err(error) => tracing::warn!(
                    "ED2K background keyword search failed query={:?} error={error}; falling back to one-shot search",
                    request.query
                ),
            }
        }
        let hello_identity = Ed2kHelloIdentity {
            user_hash: network.user_hash,
            client_id: 0,
            tcp_port: self.ed2k_reachability.advertised_tcp_port(network.listen_port),
            udp_port: self
                .ed2k_reachability
                .advertised_udp_port(network.kad_bind_addr.port()),
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(config.obfuscation_enabled),
            direct_udp_callback: false,
        };
        let shared_catalog = self.ed2k_transfers.shared_catalog();
        let shared_catalog_snapshot = shared_catalog.read().await.clone();
        let preferred_endpoint = if background_search_available {
            self.connected_ed2k_server_endpoint().await
        } else {
            None
        };
        let max_attempts = ed2k_keyword_server_attempts(&config, &request.query);
        let files = search_keyword_servers(Ed2kKeywordSearchOptions {
            bind_ip: network.bind_ip,
            config: &config,
            hello_identity,
            shared_catalog: &shared_catalog_snapshot,
            preferred_endpoint,
            max_attempts,
            query: &request.query,
            cancel: &cancel,
        })
        .await?;
        Ok(Some(
            files
                .into_iter()
                .map(|file| search_result_from_ed2k(search_id, request, file))
                .collect(),
        ))
    }

    #[allow(clippy::cognitive_complexity)]
    async fn run_ed2k_download_attempt(&self, transfer: &Transfer) -> Result<Option<&'static str>> {
        let Some(network) = self.ed2k_network.as_ref() else {
            return Ok(Some("queued"));
        };
        if network.config.server_entries.is_empty() && network.config.server_endpoints.is_empty() {
            return Ok(Some("queued"));
        }
        let file_hash: Ed2kHash = transfer
            .hash
            .parse()
            .with_context(|| format!("invalid ED2K transfer hash {}", transfer.hash))?;
        let mut transfer = transfer.clone();
        if transfer.size_bytes == 0 {
            if let Some(metadata) = self
                .resolve_hash_only_ed2k_metadata(network, file_hash)
                .await?
            {
                let learned_name = should_adopt_hash_only_metadata_name(&transfer)
                    .then_some(metadata.canonical_name.as_deref())
                    .flatten();
                let manifest = self
                    .ed2k_transfers
                    .reconcile_job_metadata(&transfer.hash, learned_name, metadata.file_size)
                    .await?;
                let mut updated = self.transfer_from_manifest(&manifest, &transfer.state);
                preserve_transfer_public_metadata(&mut updated, &transfer);
                self.state
                    .lock()
                    .await
                    .transfers
                    .insert(updated.hash.clone(), updated.clone());
                transfer = updated;
            }
            if transfer.size_bytes == 0 {
                return Ok(Some("queued"));
            }
        }
        let mut sources = self
            .acquire_ed2k_sources(network, file_hash, transfer.size_bytes)
            .await?;
        if !network.ip_filter.is_empty() {
            sources.retain(|source| !network.ip_filter.is_filtered(source.ip));
        }
        if sources.is_empty() {
            return Ok(Some("downloading"));
        }
        self.register_download_source_candidates(&transfer, &sources)
            .await;
        let hello_identity = self.ed2k_hello_identity(network);
        let timeout = Duration::from_secs(network.config.connect_timeout_secs.max(10));
        let callback_timeout = Duration::from_secs(network.config.connect_timeout_secs.max(30));
        let max_peers = network.config.max_parallel_download_peers.max(1);
        let shared_catalog = self.ed2k_transfers.shared_catalog();
        let shared_catalog_snapshot = shared_catalog.read().await.clone();
        let connected_server_endpoint = self.connected_ed2k_server_endpoint().await;
        let connected_search_handle = self.connected_ed2k_search_handle().await;

        let mut attempted_direct_endpoints = HashSet::new();
        let mut requested_callback_sources = HashSet::new();
        let mut had_direct_sources = false;
        let mut accepted_incomplete_peers = 0u32;
        let mut last_direct_error: Option<anyhow::Error> = None;
        let mut deferred_active_direct_sources = false;
        let mut source_requery_round = 0usize;
        loop {
            sort_download_sources(&mut sources);
            let callback_only_sources = sources
                .iter()
                .filter(|source| source.low_id)
                .cloned()
                .collect::<Vec<_>>();
            let callback_cancel = CancellationToken::new();
            for source in callback_only_sources {
                if !requested_callback_sources.insert(source_key(&source)) {
                    continue;
                }
                self.ed2k_transfers
                    .register_callback_intent(Ed2kCallbackIntent {
                        client_id: source.client_id,
                        file_hash: transfer.hash.clone(),
                        canonical_name: transfer.name.clone(),
                        file_size: transfer.size_bytes,
                        source: Ed2kSourceHint {
                            ip: source.ip.to_string(),
                            tcp_port: source.tcp_port,
                            user_hash: source.user_hash.map(hex::encode),
                        },
                    })
                    .await;
                tracing::info!(
                    "ED2K callback requested file_hash={} client_id={} tcp_port={} source_server={} requery_round={}",
                    transfer.hash,
                    source.client_id,
                    source.tcp_port,
                    source
                        .source_server
                        .map_or_else(|| "-".to_string(), |endpoint| endpoint.to_string()),
                    source_requery_round
                );
                let callback_result = match ed2k_server_callback_route(
                    source.source_server,
                    connected_server_endpoint,
                ) {
                    Ed2kServerCallbackRoute::BackgroundSession => {
                        if let Some(handle) = connected_search_handle.as_ref() {
                            request_callback_via_background_session(
                                handle,
                                source.client_id,
                                callback_timeout,
                                &callback_cancel,
                            )
                            .await
                        } else {
                            Err(anyhow::anyhow!(
                                "ED2K callback needs a connected background server session"
                            ))
                        }
                    }
                    Ed2kServerCallbackRoute::SourceServer(source_server) => {
                        request_callback_on_server(Ed2kCallbackRequestOptions {
                            bind_ip: network.bind_ip,
                            config: &network.config,
                            hello_identity,
                            shared_catalog: &shared_catalog_snapshot,
                            server_endpoint: source_server,
                            client_id: source.client_id,
                            timeout: callback_timeout,
                            cancel: &callback_cancel,
                        })
                        .await
                    }
                };
                if let Err(error) = callback_result {
                    tracing::warn!(
                        "ED2K callback request failed file_hash={} client_id={} source_server={}: {error}",
                        transfer.hash,
                        source.client_id,
                        source
                            .source_server
                            .map_or_else(|| "-".to_string(), |endpoint| endpoint.to_string())
                    );
                }
            }

            let candidate_direct_sources =
                direct_download_candidate_sources(&sources, &attempted_direct_endpoints);
            had_direct_sources |= !candidate_direct_sources.is_empty();
            let (direct_sources, deferred_count) = self
                .acquire_direct_download_source_leases(&transfer.hash, &candidate_direct_sources)
                .await;
            deferred_active_direct_sources |= deferred_count != 0;
            for source in &direct_sources {
                attempted_direct_endpoints.insert(source_endpoint_key(source));
            }

            if !direct_sources.is_empty() {
                let leased_endpoints = direct_sources
                    .iter()
                    .map(source_endpoint_key)
                    .collect::<Vec<_>>();
                // Captured per-call into each peer attempt so a queued + UDP-eligible
                // source can detach onto the reask loop (None when reask is off).
                let reask_register = self.ed2k_reask_handle.lock().unwrap().clone();
                let outcome = run_ed2k_direct_downloads(
                    DirectDownloadOptions {
                        bind_ip: network.bind_ip,
                        hello_identity,
                        secure_ident: Arc::clone(&network.secure_ident),
                        transfer_runtime: Arc::clone(&self.ed2k_transfers),
                        file_hash_hex: transfer.hash.clone(),
                        file_name: transfer.name.clone(),
                        file_size: transfer.size_bytes,
                        sources: direct_sources,
                        connect_timeout: timeout,
                        max_parallel_download_peers: max_peers,
                    },
                    move |bind_ip,
                          source,
                          hello_identity,
                          secure_ident,
                          transfer_runtime,
                          file_name,
                          file_size,
                          connect_timeout| {
                        let reask_register = reask_register.clone();
                        async move {
                            download_file_from_peer(Ed2kPeerDownloadOptions {
                                bind_ip,
                                peer: &source,
                                hello_identity,
                                secure_ident: &secure_ident,
                                transfer_runtime: transfer_runtime.as_ref(),
                                canonical_name: file_name,
                                file_size,
                                timeout: connect_timeout,
                                reask_register,
                            })
                            .await
                        }
                    },
                )
                .await;
                // Release every leased endpoint EXCEPT those that detached onto the
                // UDP reask loop: the loop now owns re-engagement for them, so
                // releasing the lease would let the next cycle re-connect them over
                // TCP (the reask churn). On error, detached is empty -> release all.
                let detached_endpoints: std::collections::HashSet<(Ipv4Addr, u16)> = match &outcome
                {
                    Ok(outcome) => outcome.detached_reask_endpoints.iter().copied().collect(),
                    Err(_) => std::collections::HashSet::new(),
                };
                let endpoints_to_release: Vec<(Ipv4Addr, u16)> = leased_endpoints
                    .iter()
                    .copied()
                    .filter(|endpoint| !detached_endpoints.contains(endpoint))
                    .collect();
                self.release_direct_download_source_leases(&endpoints_to_release)
                    .await;
                let outcome = outcome?;
                if outcome.completed {
                    return Ok(Some("completed"));
                }
                accepted_incomplete_peers =
                    accepted_incomplete_peers.saturating_add(outcome.accepted_incomplete_peers);
                if let Some(error) = outcome.last_error {
                    last_direct_error = Some(error);
                }
            }

            let manifest = self.ed2k_transfers.manifest(&transfer.hash).await?;
            if manifest.completed {
                return Ok(Some("completed"));
            }
            if source_requery_round < ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS {
                let known_new_direct_source_count =
                    new_direct_ed2k_source_count(&sources, &attempted_direct_endpoints);
                if should_skip_no_progress_source_requery(
                    had_direct_sources,
                    manifest_has_ed2k_transfer_progress(&manifest),
                    known_new_direct_source_count,
                    source_requery_round,
                ) {
                    tracing::info!(
                        "ED2K source refresh skipped file_hash={} reason=no_progress_repeated_endpoints attempted_direct_endpoints={} known_new_direct_source_count={}",
                        transfer.hash,
                        attempted_direct_endpoints.len(),
                        known_new_direct_source_count
                    );
                    break;
                }

                source_requery_round += 1;
                tracing::info!(
                    "ED2K source refresh starting file_hash={} requery_round={} attempted_direct_endpoints={}",
                    transfer.hash,
                    source_requery_round,
                    attempted_direct_endpoints.len()
                );
                if source_requery_round > 1 {
                    tokio::time::sleep(Duration::from_secs(
                        ED2K_DOWNLOAD_SOURCE_REQUERY_DELAY_SECS,
                    ))
                    .await;
                }

                match self
                    .acquire_ed2k_sources(network, file_hash, transfer.size_bytes)
                    .await
                {
                    Ok(refreshed_sources) => {
                        let refreshed_source_count = refreshed_sources.len();
                        let previous_source_count = sources.len();
                        self.register_download_source_candidates(&transfer, &refreshed_sources)
                            .await;
                        merge_download_sources(&mut sources, refreshed_sources);
                        let added_source_count =
                            sources.len().saturating_sub(previous_source_count);
                        let new_direct_source_count =
                            new_direct_ed2k_source_count(&sources, &attempted_direct_endpoints);
                        tracing::info!(
                            "ED2K source refresh completed file_hash={} requery_round={} refreshed_source_count={} added_source_count={} aggregated_source_count={} new_direct_source_count={}",
                            transfer.hash,
                            source_requery_round,
                            refreshed_source_count,
                            added_source_count,
                            sources.len(),
                            new_direct_source_count
                        );
                        let manifest = self.ed2k_transfers.manifest(&transfer.hash).await?;
                        if manifest_has_ed2k_transfer_progress(&manifest)
                            || new_direct_source_count != 0
                            || (!had_direct_sources
                                && source_requery_round < ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS)
                        {
                            continue;
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            "ED2K source refresh failed file_hash={} requery_round={}: {error}",
                            transfer.hash,
                            source_requery_round
                        );
                        if source_requery_round < ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS {
                            continue;
                        }
                    }
                }
            }
            break;
        }

        let manifest = self.ed2k_transfers.manifest(&transfer.hash).await?;
        if manifest.completed {
            return Ok(Some("completed"));
        }
        if manifest_has_ed2k_transfer_progress(&manifest) {
            return Ok(Some("downloading"));
        }
        if !requested_callback_sources.is_empty() {
            return Ok(Some("downloading"));
        }
        if deferred_active_direct_sources {
            return Ok(Some("downloading"));
        }
        if accepted_incomplete_peers != 0 {
            return Ok(Some("downloading"));
        }
        if let Some(error) = last_direct_error {
            return Err(error).context("ED2K direct download did not complete");
        }
        Ok(Some("queued"))
    }

    async fn acquire_direct_download_source_leases(
        &self,
        file_hash: &str,
        sources: &[Ed2kFoundSource],
    ) -> (Vec<Ed2kFoundSource>, usize) {
        let mut state = self.state.lock().await;
        let mut acquired = Vec::new();
        let mut deferred = 0usize;
        for source in sources {
            let endpoint = source_endpoint_key(source);
            let registry_lease = state
                .download_source_registry
                .lease_best_for_file(source, file_hash);
            if registry_lease.is_some() && state.active_download_peer_endpoints.insert(endpoint) {
                acquired.push(source.clone());
            } else {
                state.download_source_registry.release_peer(source);
                deferred = deferred.saturating_add(1);
            }
        }
        (acquired, deferred)
    }

    async fn release_direct_download_source_leases(&self, endpoints: &[(Ipv4Addr, u16)]) {
        let mut state = self.state.lock().await;
        for endpoint in endpoints {
            state.active_download_peer_endpoints.remove(endpoint);
            state.download_source_registry.release_endpoint(*endpoint);
        }
    }

    async fn register_download_source_candidates(
        &self,
        transfer: &Transfer,
        sources: &[Ed2kFoundSource],
    ) {
        let mut state = self.state.lock().await;
        let file_priority = download_priority_score(&transfer.priority);
        let needed_parts = transfer.parts_total.saturating_sub(transfer.parts_obtained);
        for source in sources {
            state
                .download_source_registry
                .add_candidate(DownloadSourceCandidate {
                    file_hash: transfer.hash.clone(),
                    file_priority,
                    needed_parts,
                    rare_parts: 0,
                    source: source.clone(),
                });
        }
    }

    async fn queue_ed2k_download_attempt(&self, transfer: Transfer) {
        let hash = transfer.hash.clone();
        {
            let mut state = self.state.lock().await;
            // WHY: REST resume returns before the peer transfer finishes, so repeated
            // resume requests must not start duplicate writers for the same part file.
            if !state.active_download_attempts.insert(hash.clone()) {
                return;
            }
        }

        let core = self.clone();
        tokio::spawn(async move {
            let result = core.run_ed2k_download_attempt(&transfer).await;
            let mut retry_downloading = false;
            match result {
                Ok(Some(next_state)) => {
                    retry_downloading = next_state == "downloading";
                    if let Err(error) = core.refresh_transfer_from_manifest(&hash, next_state).await
                    {
                        tracing::warn!(
                            "failed to refresh ED2K transfer {hash} after download attempt: {error}"
                        );
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!("ED2K background download attempt failed for {hash}: {error:#}");
                    if let Err(refresh_error) =
                        core.refresh_transfer_from_manifest(&hash, "queued").await
                    {
                        tracing::warn!(
                            "failed to refresh ED2K transfer {hash} after failed download attempt: {refresh_error}"
                        );
                    }
                }
            }
            core.state
                .lock()
                .await
                .active_download_attempts
                .remove(&hash);
            if retry_downloading {
                core.queue_ed2k_download_retry(hash);
            }
        });
    }

    fn queue_ed2k_download_retry(&self, hash: String) {
        let core = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(ED2K_DOWNLOAD_BACKGROUND_RETRY_SECS)).await;
            let Some(transfer) = core.transfer(&hash).await else {
                return;
            };
            if transfer.state != "downloading" {
                return;
            }
            core.queue_ed2k_download_attempt(transfer).await;
        });
    }

    #[allow(clippy::cognitive_complexity)]
    async fn resolve_hash_only_ed2k_metadata(
        &self,
        network: &Ed2kNetworkConfig,
        file_hash: Ed2kHash,
    ) -> Result<Option<LearnedEd2kMetadata>> {
        let cancel = CancellationToken::new();
        let timeout = Duration::from_secs(network.config.connect_timeout_secs.max(15));
        let query = hash_only_ed2k_search_query(file_hash);
        let shared_catalog = self.ed2k_transfers.shared_catalog();
        let shared_catalog_snapshot = shared_catalog.read().await.clone();
        let mut learned = LearnedEd2kMetadata::default();
        let (preferred_endpoint, background_search) =
            if let Some(handle) = self.connected_ed2k_search_handle().await {
                (self.connected_ed2k_server_endpoint().await, Some(handle))
            } else {
                (None, None)
            };
        let has_background_search = background_search.is_some();

        if let Some(handle) = background_search {
            match search_keyword_via_background_session(&handle, &query, timeout, &cancel).await {
                Ok(results) => {
                    if let Some(candidate) = select_ed2k_keyword_metadata(&results, file_hash) {
                        learned.merge_missing_from(candidate);
                        tracing::info!(
                            "ED2K hash-only metadata learned from background search file_hash={} file_name={} file_size={}",
                            file_hash,
                            learned.canonical_name.as_deref().unwrap_or("-"),
                            learned.file_size.unwrap_or_default()
                        );
                    }
                }
                Err(error) => tracing::warn!(
                    "ED2K background metadata search failed file_hash={} error={error}",
                    file_hash
                ),
            }
        }

        if !learned.is_complete() {
            match search_keyword_servers(Ed2kKeywordSearchOptions {
                bind_ip: network.bind_ip,
                config: &network.config,
                hello_identity: self.ed2k_hello_identity(network),
                shared_catalog: &shared_catalog_snapshot,
                preferred_endpoint: (!has_background_search)
                    .then_some(preferred_endpoint)
                    .flatten(),
                max_attempts: ed2k_keyword_server_attempts(&network.config, &query),
                query: &query,
                cancel: &cancel,
            })
            .await
            {
                Ok(results) => {
                    if let Some(candidate) = select_ed2k_keyword_metadata(&results, file_hash) {
                        learned.merge_missing_from(candidate);
                        tracing::info!(
                            "ED2K hash-only metadata learned from active search file_hash={} file_name={} file_size={}",
                            file_hash,
                            learned.canonical_name.as_deref().unwrap_or("-"),
                            learned.file_size.unwrap_or_default()
                        );
                    }
                }
                Err(error) => tracing::warn!(
                    "ED2K active metadata search failed file_hash={} error={error}",
                    file_hash
                ),
            }
        }

        if !learned.is_complete()
            && let Some(dht) = self.ed2k_dht_node().await
            && let Some(candidate) =
                collect_kad_ed2k_metadata(&dht, &query, file_hash, timeout).await
        {
            learned.merge_missing_from(candidate);
            tracing::info!(
                "ED2K hash-only metadata learned from Kad search file_hash={} file_name={} file_size={}",
                file_hash,
                learned.canonical_name.as_deref().unwrap_or("-"),
                learned.file_size.unwrap_or_default()
            );
        }

        Ok((!learned.is_empty()).then_some(learned))
    }

    #[allow(clippy::cognitive_complexity)]
    async fn acquire_ed2k_sources(
        &self,
        network: &Ed2kNetworkConfig,
        file_hash: Ed2kHash,
        file_size: u64,
    ) -> Result<Vec<Ed2kFoundSource>> {
        let cancel = CancellationToken::new();
        let shared_catalog = self.ed2k_transfers.shared_catalog();
        let shared_catalog_snapshot = shared_catalog.read().await.clone();
        let attempts = configured_server_attempts(&network.config)
            .min(network.config.source_server_attempt_budget.max(1));
        let mut sources = Vec::new();
        let (preferred_endpoint, background_search) =
            if let Some(handle) = self.connected_ed2k_search_handle().await {
                (self.connected_ed2k_server_endpoint().await, Some(handle))
            } else {
                (None, None)
            };
        let has_background_search = background_search.is_some();
        if let Some(handle) = background_search {
            let timeout = Duration::from_secs(network.config.connect_timeout_secs.max(15));
            match search_source_via_background_session(
                &handle, file_hash, file_size, timeout, &cancel,
            )
            .await
            {
                Ok(results) => merge_download_sources(&mut sources, results),
                Err(error) => tracing::warn!(
                    "ED2K background source search failed file_hash={} error={error}",
                    file_hash
                ),
            }
        }
        let exclude_preferred_endpoint =
            should_exclude_background_source_endpoint(has_background_search, sources.len());
        let excluded_endpoint = if exclude_preferred_endpoint {
            preferred_endpoint
        } else {
            None
        };
        if exclude_preferred_endpoint && attempts <= 1 {
            // The connected background session already queried the only server in budget.
            self.remember_ed2k_sources(file_hash, &sources).await?;
            return Ok(sources);
        }
        match search_source_servers(Ed2kSourceSearchOptions {
            bind_ip: network.bind_ip,
            config: &network.config,
            hello_identity: self.ed2k_hello_identity(network),
            shared_catalog: &shared_catalog_snapshot,
            preferred_endpoint,
            excluded_endpoint,
            max_attempts: attempts,
            file_hash,
            file_size,
            cancel: &cancel,
        })
        .await
        {
            Ok(results) => merge_download_sources(&mut sources, results),
            Err(error) => tracing::warn!(
                "ED2K TCP source search failed file_hash={} error={error}",
                file_hash
            ),
        }
        if sources.is_empty() {
            match search_source_udp_servers(Ed2kUdpSourceSearchOptions {
                bind_ip: network.bind_ip,
                config: &network.config,
                preferred_endpoint,
                excluded_endpoint: None,
                max_attempts: attempts,
                file_hash,
                file_size,
                timeout: Duration::from_secs(network.config.connect_timeout_secs.max(15)),
                cancel: &cancel,
            })
            .await
            {
                Ok(results) => merge_download_sources(&mut sources, results),
                Err(error) => tracing::warn!(
                    "ED2K UDP source search failed file_hash={} error={error}",
                    file_hash
                ),
            }
        }
        if file_size != 0
            && should_query_kad_source_supplement(
                sources.len(),
                network.config.kad_source_supplement_max_existing_sources,
            )
            && let Some(dht) = self.ed2k_dht_node().await
        {
            let timeout = Duration::from_secs(
                network
                    .config
                    .connect_timeout_secs
                    .max(ED2K_DOWNLOAD_KAD_SOURCE_TIMEOUT_FLOOR_SECS),
            );
            let existing_source_count = sources.len();
            let kad_sources = collect_kad_ed2k_sources(&dht, file_hash, file_size, timeout).await;
            let kad_source_count = kad_sources.len();
            merge_download_sources(&mut sources, kad_sources);
            tracing::info!(
                "ED2K Kad source supplement completed file_hash={} existing_source_count={} kad_source_count={} aggregated_source_count={}",
                file_hash,
                existing_source_count,
                kad_source_count,
                sources.len()
            );
        }
        if sources.is_empty() {
            merge_download_sources(&mut sources, self.remembered_ed2k_sources(file_hash).await?);
        }
        for source in &sources {
            self.remember_ed2k_sources(file_hash, std::slice::from_ref(source))
                .await?;
        }
        Ok(sources)
    }

    async fn remember_ed2k_sources(
        &self,
        file_hash: Ed2kHash,
        sources: &[Ed2kFoundSource],
    ) -> Result<()> {
        for source in sources {
            if !source.is_direct_dialable() {
                continue;
            }
            self.ed2k_transfers
                .remember_source(
                    &file_hash.to_string(),
                    Ed2kSourceHint {
                        ip: source.ip.to_string(),
                        tcp_port: source.tcp_port,
                        user_hash: source.user_hash.map(hex::encode),
                    },
                )
                .await?;
        }
        Ok(())
    }

    async fn remembered_ed2k_sources(&self, file_hash: Ed2kHash) -> Result<Vec<Ed2kFoundSource>> {
        let manifest = match self.ed2k_transfers.manifest(&file_hash.to_string()).await {
            Ok(manifest) => manifest,
            Err(error) => {
                tracing::warn!("failed to read remembered ED2K sources for {file_hash}: {error}");
                return Ok(Vec::new());
            }
        };
        let sources = manifest
            .sources
            .iter()
            .filter_map(|hint| match found_source_from_hint(file_hash, hint) {
                Ok(source) => Some(source),
                Err(error) => {
                    tracing::warn!(
                        "skipping invalid remembered ED2K source for {file_hash}: {error}"
                    );
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(sources)
    }

    fn ed2k_hello_identity(&self, network: &Ed2kNetworkConfig) -> Ed2kHelloIdentity {
        Ed2kHelloIdentity {
            user_hash: network.user_hash,
            client_id: 0,
            // Advertise the externally-reachable ports (UPnP-mapped when known,
            // else the internal port), like eMule: peers/servers reach us for
            // incoming connections + HighID callback on tcp_port, and locate us for
            // UDP source-reask by the (ip, udp_port) we advertise; the gateway can
            // remap either external port (see advertised_ports).
            tcp_port: self.ed2k_reachability.advertised_tcp_port(network.listen_port),
            udp_port: self
                .ed2k_reachability
                .advertised_udp_port(network.kad_bind_addr.port()),
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(network.config.obfuscation_enabled),
            direct_udp_callback: false,
        }
    }

    async fn connected_ed2k_search_handle(&self) -> Option<Ed2kServerSearchHandle> {
        let (handle, server_state) = {
            let runtime_guard = self.ed2k_runtime.lock().await;
            let runtime = runtime_guard.as_ref()?;
            (
                runtime.search_handle.clone(),
                Arc::clone(&runtime.server_state),
            )
        };
        server_state.read().await.connected.then_some(handle)
    }

    async fn ed2k_dht_node(&self) -> Option<DhtNode> {
        self.ed2k_runtime
            .lock()
            .await
            .as_ref()
            .map(|runtime| runtime.dht.clone())
    }

    #[cfg(test)]
    async fn kad_local_store_config_for_tests(&self) -> Option<KadLocalStoreConfig> {
        Some(self.kad_local_store.as_ref()?.lock().await.config())
    }

    #[cfg(test)]
    async fn kad_snoop_queue_config_for_tests(&self) -> Option<SnoopQueueConfig> {
        Some(self.kad_snoop_queue.as_ref()?.lock().await.config().clone())
    }

    #[cfg(test)]
    async fn kad_snoop_queue_snapshot_for_tests(&self) -> Option<Vec<SnoopEntry>> {
        Some(self.kad_snoop_queue.as_ref()?.lock().await.snapshot())
    }

    #[cfg(test)]
    async fn kad_publish_cache_snapshot_for_tests(
        &self,
    ) -> Option<emulebb_index::KadPublishCacheSnapshot> {
        Some(
            self.kad_local_store
                .as_ref()?
                .lock()
                .await
                .publish_snapshot(Utc::now()),
        )
    }

    async fn connected_ed2k_server_endpoint(&self) -> Option<SocketAddr> {
        let server_state = {
            let runtime_guard = self.ed2k_runtime.lock().await;
            Arc::clone(&runtime_guard.as_ref()?.server_state)
        };
        let state = server_state.read().await;
        state.connected.then_some(state.endpoint).flatten()
    }

    async fn publish_ed2k_shared_catalog(&self) -> Result<()> {
        let Some(network) = self.ed2k_network.as_ref() else {
            return Ok(());
        };
        let Some(handle) = self.connected_ed2k_search_handle().await else {
            return Ok(());
        };
        let timeout = Duration::from_secs(network.config.connect_timeout_secs.max(10));
        publish_shared_catalog_via_background_session(&handle, timeout, &CancellationToken::new())
            .await
    }

    async fn ed2k_connected_endpoint(&self) -> Option<String> {
        let server_state = {
            let runtime_guard = self.ed2k_runtime.lock().await;
            Arc::clone(&runtime_guard.as_ref()?.server_state)
        };
        let state = server_state.read().await;
        state
            .connected
            .then(|| state.endpoint.map(|endpoint| endpoint.to_string()))?
    }

    async fn ed2k_status(&self) -> NetworkStatus {
        let server_state = {
            let runtime_guard = self.ed2k_runtime.lock().await;
            let Some(runtime) = runtime_guard.as_ref() else {
                return NetworkStatus {
                    running: false,
                    connected: false,
                    peer_count: 0,
                    firewalled: None,
                    bootstrapping: None,
                    bootstrap_progress: None,
                    contact_count: None,
                    lan_mode: None,
                    users: None,
                    files: None,
                    indexed_sources: None,
                    indexed_keywords: None,
                    operation_queued: None,
                    already_running: None,
                };
            };
            Arc::clone(&runtime.server_state)
        };
        let state = server_state.read().await;
        NetworkStatus {
            running: true,
            connected: state.connected,
            peer_count: u32::from(state.connected),
            firewalled: None,
            bootstrapping: None,
            bootstrap_progress: None,
            contact_count: None,
            lan_mode: None,
            users: None,
            files: None,
            indexed_sources: None,
            indexed_keywords: None,
            operation_queued: None,
            already_running: None,
        }
    }

    async fn kad_status(&self, manual_running: bool) -> NetworkStatus {
        let runtime_snapshot = {
            let runtime_guard = self.ed2k_runtime.lock().await;
            runtime_guard
                .as_ref()
                .map(|runtime| (runtime.dht.clone(), runtime.kad_bootstrap_configured))
        };
        let Some((dht, kad_bootstrap_configured)) = runtime_snapshot else {
            return kad_status_from_running(manual_running);
        };
        let contact_count = dht.routing_table_size() as u32;
        let connected = dht.is_bootstrapped();
        // Local Kad index sizes (oracle m_uTotalIndexSource / m_uTotalIndexKeyword).
        let (indexed_sources, indexed_keywords) = match self.kad_local_store.as_ref() {
            Some(store) => {
                let store = store.lock().await;
                (
                    store.source_entry_count() as u64,
                    store.keyword_entry_count() as u64,
                )
            }
            None => (0, 0),
        };
        NetworkStatus {
            running: true,
            connected,
            peer_count: contact_count,
            firewalled: Some(false),
            bootstrapping: Some(kad_bootstrap_configured && !connected),
            bootstrap_progress: Some(if connected { 100 } else { 0 }),
            contact_count: Some(contact_count),
            lan_mode: Some(false),
            users: Some(0),
            files: Some(0),
            indexed_sources: Some(indexed_sources),
            indexed_keywords: Some(indexed_keywords),
            operation_queued: None,
            already_running: None,
        }
    }
}

impl fmt::Debug for EmulebbCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmulebbCore")
            .field("started_at", &self.started_at)
            .field("version", &self.version)
            .field("ed2k_network_configured", &self.ed2k_network.is_some())
            .field(
                "kad_local_store_configured",
                &self.kad_local_store.is_some(),
            )
            .field(
                "kad_snoop_queue_configured",
                &self.kad_snoop_queue.is_some(),
            )
            .finish_non_exhaustive()
    }
}

async fn run_configured_kad_bootstrap(dht: DhtNode, shutdown: Arc<AtomicBool>) {
    if shutdown.load(Ordering::SeqCst) {
        return;
    }
    match dht.bootstrap().await {
        Ok(()) => tracing::info!(
            "configured Kad bootstrap completed contacts={}",
            dht.routing_table_size()
        ),
        Err(error) => {
            if !shutdown.load(Ordering::SeqCst) {
                tracing::warn!("configured Kad bootstrap failed: {error}");
            }
        }
    }
}

#[allow(clippy::cognitive_complexity)]
async fn run_kad_hello_intro_loop(
    dht: DhtNode,
    ed2k_listener: Arc<TcpListener>,
    server_state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    network: Ed2kNetworkConfig,
    shutdown: Arc<AtomicBool>,
) {
    let interval = Duration::from_secs(network.kad_hello_intro_interval_secs.max(1));
    let fanout = network.kad_hello_intro_fanout.max(1);
    let mut introduced = HashSet::new();

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(interval).await;
        if shutdown.load(Ordering::SeqCst) || !dht.is_bootstrapped() {
            continue;
        }

        let local_ip = match dht.bind_addr() {
            Ok(bind_addr) => bind_addr.ip(),
            Err(error) => {
                tracing::debug!("kad hello intro skipped: failed to resolve bind addr: {error}");
                continue;
            }
        };
        let contacts = dht
            .routing_contacts()
            .await
            .into_iter()
            .filter_map(|contact| {
                let addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.udp_port);
                (contact.udp_port != 0
                    && contact.kad_version >= 6
                    && IpAddr::V4(contact.ip) != local_ip
                    && !introduced.contains(&addr))
                .then_some((contact, addr))
            })
            .take(fanout)
            .collect::<Vec<_>>();

        for (contact, addr) in contacts {
            let hello = match build_kad_hello_request(
                &dht,
                &ed2k_listener,
                &server_state,
                &kad_firewall,
                false,
            )
            .await
            {
                Ok(hello) => hello,
                Err(error) => {
                    tracing::debug!("failed to build Kad hello request for {addr}: {error}");
                    continue;
                }
            };
            tracing::debug!(
                "sending Kad hello request to={} contact_id={} contact_version={} request_ack=false",
                addr,
                contact.id,
                contact.kad_version
            );
            if let Err(error) = dht
                .send_packet_with_class(
                    addr,
                    &KadPacket::HelloReq(hello),
                    RpcWorkClass::Maintenance,
                )
                .await
            {
                tracing::debug!("failed to send Kad hello request to {addr}: {error}");
                continue;
            }
            introduced.insert(addr);
        }
    }
}

async fn run_kad_shared_file_publish_loop(
    dht: DhtNode,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    network: Ed2kNetworkConfig,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::SeqCst) {
        if !dht.is_bootstrapped() {
            tokio::time::sleep(Duration::from_secs(KAD_SHARED_FILE_PUBLISH_RETRY_SECS)).await;
            continue;
        }

        if let Err(error) = publish_kad_shared_files(&dht, &transfer_runtime, &network).await {
            tracing::debug!("Kad shared-file publish cycle failed: {error:#}");
        }

        let republish_secs = network.kad_republish_interval_secs.max(1);
        for _ in 0..republish_secs {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

#[allow(clippy::cognitive_complexity)]
async fn publish_kad_shared_files(
    dht: &DhtNode,
    transfer_runtime: &Ed2kTransferRuntime,
    network: &Ed2kNetworkConfig,
) -> Result<usize> {
    let manifests = kad_publishable_manifests(transfer_runtime.manifests().await?);
    if manifests.is_empty() {
        return Ok(0);
    }

    let bind_addr = network.kad_bind_addr;
    let source_publish_identity = source_publish_client_hash(network.user_hash);
    let source_publish_settings = SourcePublishSettings {
        tcp_port: network.listen_port,
        obfuscation_enabled: network.config.obfuscation_enabled,
    };
    let mut keyword_totals = PublishAttemptStats::default();
    let mut source_totals = PublishAttemptStats::default();
    let item_count = manifests.len();

    for manifest in manifests {
        let file_hash: Ed2kHash = manifest.file_hash.parse()?;
        let keyword_hash = keyword_target(&manifest.canonical_name);
        let mut keyword_tags = vec![
            Tag::filename(manifest.canonical_name.clone()),
            Tag::filesize(manifest.file_size),
            Tag::sources(1),
        ];
        if let Some(file_type) = ed2k_file_type_search_term(&manifest.canonical_name) {
            keyword_tags.push(Tag::filetype(file_type));
        }
        let aich_hash = manifest
            .aich_root
            .as_deref()
            .and_then(decode_aich_root_hex_for_publish);
        match dht
            .publish_keyword_with_class_and_fanout(
                keyword_hash,
                file_hash,
                keyword_tags,
                aich_hash,
                RpcWorkClass::Publish,
                network.kad_publish_contact_fanout,
            )
            .await
        {
            Ok(stats) => accumulate_publish_stats(&mut keyword_totals, stats),
            Err(error) => {
                tracing::debug!(
                    file_hash = %manifest.file_hash,
                    name = manifest.canonical_name,
                    "Kad keyword publish failed: {error:#}"
                );
            }
        }

        let source_tags =
            build_source_publish_tags(bind_addr, source_publish_settings, manifest.file_size);
        match dht
            .publish_source_with_class_and_fanout(
                file_hash,
                source_publish_identity,
                source_tags,
                RpcWorkClass::Publish,
                network.kad_publish_contact_fanout,
            )
            .await
        {
            Ok(stats) => accumulate_publish_stats(&mut source_totals, stats),
            Err(error) => {
                tracing::debug!(
                    file_hash = %manifest.file_hash,
                    name = manifest.canonical_name,
                    "Kad source publish failed: {error:#}"
                );
            }
        }
    }

    tracing::info!(
        "Kad shared-file publish completed items={} keyword_attempted={} keyword_acked={} source_attempted={} source_acked={}",
        item_count,
        keyword_totals.attempted_contacts,
        keyword_totals.acked_contacts,
        source_totals.attempted_contacts,
        source_totals.acked_contacts,
    );

    Ok(item_count)
}

fn kad_publishable_manifests(manifests: Vec<Ed2kResumeManifest>) -> Vec<Ed2kResumeManifest> {
    manifests
        .into_iter()
        .filter(|manifest| manifest.completed && !manifest.transfer_row_removed)
        .collect()
}

fn decode_aich_root_hex_for_publish(value: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(value).ok()?;
    bytes.try_into().ok()
}

fn accumulate_publish_stats(total: &mut PublishAttemptStats, stats: PublishAttemptStats) {
    total.closest_contacts_considered += stats.closest_contacts_considered;
    total.attempted_contacts += stats.attempted_contacts;
    total.acked_contacts += stats.acked_contacts;
    total.timed_out_contacts += stats.timed_out_contacts;
}

fn configured_kad_bootstrap_nodes_text(nodes: &[String]) -> Option<String> {
    let valid_nodes = nodes
        .iter()
        .filter_map(|node| match node.trim().parse::<SocketAddr>() {
            Ok(addr) if matches!(addr.ip(), IpAddr::V4(_)) && addr.port() != 0 => {
                Some(addr.to_string())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if valid_nodes.is_empty() {
        None
    } else {
        Some(valid_nodes.join("\n"))
    }
}

struct KadLocalStoreRuntime {
    dht: DhtNode,
    local_store: Arc<Mutex<KadLocalStore>>,
    metadata_store: MetadataStore,
    snoop_queue: Arc<Mutex<SnoopQueue>>,
    ed2k_listener: Arc<TcpListener>,
    server_state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    reachability: ExternalReachability,
    kad_buddy: Arc<Mutex<KadBuddyState>>,
    buddy_registry: BuddySocketRegistry,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    network: Ed2kNetworkConfig,
}

async fn run_kad_local_store_loop(runtime: KadLocalStoreRuntime, shutdown: Arc<AtomicBool>) {
    let mut packets = runtime.dht.subscribe_packets();
    while !shutdown.load(Ordering::SeqCst) {
        match tokio::time::timeout(Duration::from_millis(250), packets.recv()).await {
            Ok(Ok(received)) => {
                if let Err(error) = handle_kad_local_store_packet(&runtime, received).await {
                    tracing::warn!("failed to handle unsolicited Kad packet: {error:#}");
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped))) => {
                tracing::warn!("Kad local-store packet receiver lagged; skipped {skipped} packets");
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            Err(_) => {}
        }
    }
}

/// Shared inputs for the buddy-management task.
struct KadBuddyRuntime {
    dht: DhtNode,
    ed2k_listener: Arc<TcpListener>,
    server_state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    kad_buddy: Arc<Mutex<KadBuddyState>>,
    buddy_registry: BuddySocketRegistry,
    network: Ed2kNetworkConfig,
}

/// Poll cadence for the buddy-management task. The actual search rate is gated by
/// the oracle-style cooldown inside [`KadBuddyState::should_search`]; this only
/// bounds how often we re-evaluate the firewall/bootstrap conditions.
const KAD_BUDDY_TICK_SECS: u64 = 30;

/// Connect/IO timeout for the persistent outbound buddy TCP link.
const KAD_BUDDY_LINK_TIMEOUT: Duration = Duration::from_secs(10);

/// Buddy-management driver (oracle `ClientList` buddy upkeep + `Kademlia`
/// find-buddy timer): when we are TCP-firewalled (LowID) with a verified-
/// firewalled UDP status and Kad is bootstrapped, search Kad near our derived
/// buddy target and ask a reachable candidate to be our buddy
/// (`KADEMLIA_FINDBUDDY_REQ`). The `FINDBUDDY_RES` reply is recorded by the
/// inbound dispatch. Re-search resumes automatically after a buddy is lost.
async fn run_kad_buddy_loop(runtime: KadBuddyRuntime, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_secs(KAD_BUDDY_TICK_SECS)).await;
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        let need = current_buddy_need(&runtime).await;
        let now = Utc::now();
        {
            let mut state = runtime.kad_buddy.lock().await;
            // Drop buddies we no longer need (became reachable / firewalled),
            // mirroring the oracle ClientList buddy upkeep.
            if state.release_buddies_if_unneeded(need) {
                tracing::debug!("released a Kad buddy relationship (conditions changed)");
                // Mirror the state drop onto the held sockets: if we became
                // firewalled we can no longer serve an incoming buddy, and if we
                // became reachable we no longer need our outbound buddy.
                if need.tcp_firewalled {
                    runtime.buddy_registry.clear_inbound();
                }
                if !need.needs_buddy() {
                    runtime.buddy_registry.evict_outbound();
                    set_hello_buddy_snapshot(None); // no outgoing buddy: stop advertising
                }
            }
            if !state.should_search(need, now) {
                continue;
            }
            state.mark_search_started(now);
        }
        if let Err(error) = run_kad_buddy_search(&runtime).await {
            tracing::debug!("Kad buddy search failed: {error:#}");
        }
    }
}

/// Evaluate the current "do we need a buddy?" inputs from live state.
async fn current_buddy_need(runtime: &KadBuddyRuntime) -> BuddyNeedInput {
    let tcp_firewalled = current_tcp_firewalled(
        &runtime.ed2k_listener,
        &runtime.server_state,
        &runtime.kad_firewall,
    )
    .await;
    let udp_firewalled_verified = {
        let firewall = runtime.kad_firewall.lock().await;
        firewall.udp_verified && !firewall.udp_open
    };
    BuddyNeedInput {
        tcp_firewalled,
        udp_firewalled_verified,
        kad_connected: runtime.dht.is_bootstrapped(),
    }
}

/// Run one buddy search: look up Kad nodes near our derived buddy target and
/// send `KADEMLIA_FINDBUDDY_REQ` to the closest reachable candidate.
async fn run_kad_buddy_search(runtime: &KadBuddyRuntime) -> Result<()> {
    let own_id = runtime.dht.own_id();
    let target = buddy_search_target(own_id);
    let candidates = runtime
        .dht
        .lookup_nodes(&target)
        .await
        .context("Kad buddy lookup failed")?;

    let our_tcp_port = runtime
        .ed2k_listener
        .local_addr()
        .context("failed to read eD2K listener address for Kad buddy request")?
        .port();
    let request = FindBuddyReq {
        buddy_id: target,
        client_hash: Ed2kHash::from_bytes(runtime.network.user_hash),
        tcp_port: our_tcp_port,
    };

    // The buddy must not be ourselves; pick the closest other candidate.
    let Some(candidate) = candidates.into_iter().find(|contact| contact.id != own_id) else {
        tracing::debug!("Kad buddy search found no candidate near {target}");
        return Ok(());
    };
    runtime
        .dht
        .send_packet(candidate.addr, &KadPacket::FindBuddyReq(request))
        .await
        .with_context(|| format!("failed to send Kad FINDBUDDY_REQ to {}", candidate.addr))?;
    tracing::info!(
        "sent Kad FINDBUDDY_REQ to candidate {} (we are firewalled, seeking a buddy)",
        candidate.addr
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassiveReplayWorker {
    General,
    Source,
}

#[derive(Debug)]
enum PassiveReplaySelection {
    Keyword(ScheduledSnoopRequest<SearchKeyReq>),
    Source(ScheduledSnoopRequest<SearchSourceReq>),
    Notes(ScheduledSnoopRequest<SearchNotesReq>),
}

async fn run_kad_passive_replay_loop(
    dht: DhtNode,
    snoop_queue: Arc<Mutex<SnoopQueue>>,
    index: Arc<Mutex<FileIndex>>,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    shutdown: Arc<AtomicBool>,
    worker: PassiveReplayWorker,
) {
    let interval = match worker {
        PassiveReplayWorker::General => Duration::from_secs(PASSIVE_GENERAL_CRAWL_SECS),
        PassiveReplayWorker::Source => Duration::from_secs(PASSIVE_SOURCE_CRAWL_SECS),
    };
    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(interval).await;
        if shutdown.load(Ordering::SeqCst) || !dht.is_bootstrapped() {
            continue;
        }
        let selected = match worker {
            PassiveReplayWorker::General => next_passive_replay_request(&snoop_queue).await,
            PassiveReplayWorker::Source => next_passive_replay_source_request(&snoop_queue)
                .await
                .map(PassiveReplaySelection::Source),
        };
        let Some(selected) = selected else {
            continue;
        };
        run_selected_passive_replay(&dht, &snoop_queue, &index, &transfer_runtime, selected).await;
    }
}

async fn next_passive_replay_request(
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
) -> Option<PassiveReplaySelection> {
    let mut queue = snoop_queue.lock().await;
    let now = Utc::now();
    for family in preferred_passive_replay_families(queue.family_counts()) {
        let selected = match family {
            PassiveReplayFamily::Keyword => queue
                .select_next_keyword_request(now)
                .map(PassiveReplaySelection::Keyword),
            PassiveReplayFamily::Source => queue
                .select_next_source_request(now)
                .map(PassiveReplaySelection::Source),
            PassiveReplayFamily::Notes => queue
                .select_next_notes_request(now)
                .map(PassiveReplaySelection::Notes),
        };
        if selected.is_some() {
            return selected;
        }
    }
    None
}

async fn next_passive_replay_source_request(
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
) -> Option<ScheduledSnoopRequest<SearchSourceReq>> {
    snoop_queue
        .lock()
        .await
        .select_next_source_request(Utc::now())
}

async fn run_selected_passive_replay(
    dht: &DhtNode,
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
    index: &Arc<Mutex<FileIndex>>,
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    selected: PassiveReplaySelection,
) {
    let (logical_key, result_count) = match selected {
        PassiveReplaySelection::Keyword(selected) => {
            let logical_key = selected.logical_key;
            let result_count = run_passive_keyword_replay(dht, index, selected.request).await;
            (logical_key, result_count)
        }
        PassiveReplaySelection::Source(selected) => {
            let source_stop_after_results = {
                snoop_queue
                    .lock()
                    .await
                    .config()
                    .source_stop_after_results
                    .max(1)
            };
            let logical_key = selected.logical_key;
            let source_results =
                run_passive_source_replay(dht, selected.request, source_stop_after_results).await;
            remember_passive_source_results(transfer_runtime, &source_results).await;
            (logical_key, source_results.len())
        }
        PassiveReplaySelection::Notes(selected) => {
            let logical_key = selected.logical_key;
            let note_results = run_passive_notes_replay(dht, selected.request).await;
            remember_passive_note_results(transfer_runtime, &note_results).await;
            (logical_key, note_results.len())
        }
    };
    snoop_queue
        .lock()
        .await
        .record_replay_outcome(&logical_key, Utc::now(), result_count);
}

async fn run_passive_keyword_replay(
    dht: &DhtNode,
    index: &Arc<Mutex<FileIndex>>,
    request: SearchKeyReq,
) -> usize {
    let cancel = CancellationToken::new();
    let mut stream = dht.search_keyword_request_with_cancel_and_class(
        request.clone(),
        cancel.clone(),
        RpcWorkClass::Harvest,
    );
    let mut seen_hashes = HashSet::new();
    let mut result_count = 0usize;
    while let Some(result) = stream.next().await {
        if !seen_hashes.insert(result.hash) {
            continue;
        }
        result_count += 1;
        index_passive_keyword_result(index, &result).await;
        if result_count >= PASSIVE_KEYWORD_RESULT_TARGET {
            cancel.cancel();
            break;
        }
    }
    tracing::debug!(
        target = %request.target,
        start_position = request.start_position,
        result_count,
        "completed Kad passive keyword replay"
    );
    result_count
}

async fn run_passive_source_replay(
    dht: &DhtNode,
    request: SearchSourceReq,
    source_stop_after_results: usize,
) -> Vec<SourceResult> {
    let cancel = CancellationToken::new();
    let mut stream = dht.search_source_request_with_cancel_and_class(
        request.clone(),
        cancel.clone(),
        RpcWorkClass::Harvest,
    );
    let mut seen_sources = HashSet::new();
    let mut results = Vec::new();
    while let Some(result) = stream.next().await {
        let source_key = (result.ip, result.tcp_port, result.udp_port);
        if !seen_sources.insert(source_key) {
            continue;
        }
        results.push(result);
        if results.len() >= source_stop_after_results {
            cancel.cancel();
            break;
        }
    }
    tracing::debug!(
        target = %request.target,
        start_position = request.start_position,
        size = request.size,
        result_count = results.len(),
        "completed Kad passive source replay"
    );
    results
}

async fn remember_passive_source_results(
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    results: &[SourceResult],
) {
    for result in results {
        let source = kad_source_result_to_ed2k_found_source(result.clone());
        if !source.is_direct_dialable() {
            continue;
        }
        let hint = Ed2kSourceHint {
            ip: source.ip.to_string(),
            tcp_port: source.tcp_port,
            user_hash: source.user_hash.map(hex::encode),
        };
        if let Err(error) = transfer_runtime
            .remember_source(&result.file_hash.to_string(), hint)
            .await
        {
            tracing::debug!(
                file_hash = %result.file_hash,
                source = %SocketAddr::new(IpAddr::V4(result.ip), result.tcp_port),
                "skipping passive Kad source memory: {error:#}"
            );
        }
    }
}

async fn run_passive_notes_replay(dht: &DhtNode, request: SearchNotesReq) -> Vec<KadNoteResult> {
    let cancel = CancellationToken::new();
    let file_hash = Ed2kHash::from_bytes(request.target.to_be_bytes());
    let mut stream = dht.search_notes_with_cancel_and_class(
        file_hash,
        request.size,
        cancel.clone(),
        RpcWorkClass::Harvest,
    );
    let mut seen_notes = HashSet::new();
    let mut results = Vec::new();
    while let Some(result) = stream.next().await {
        if !seen_notes.insert(note_result_key(&result)) {
            continue;
        }
        results.push(result);
        if results.len() >= PASSIVE_NOTES_RESULT_TARGET {
            cancel.cancel();
            break;
        }
    }
    tracing::debug!(
        target = %request.target,
        size = request.size,
        result_count = results.len(),
        "completed Kad passive notes replay"
    );
    results
}

/// The current TCP-firewalled (LowID) verdict, in oracle priority order:
/// the eD2k server's authoritative LowID flag first, then the Kad TCP firewall
/// recheck verdict (so a pure-Kad node with no server still detects it), then a
/// last-resort "listener port is unusable" fallback.
pub(crate) async fn current_tcp_firewalled(
    ed2k_listener: &TcpListener,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
) -> bool {
    if let Some(tcp_firewalled) = server_state.read().await.tcp_firewalled() {
        return tcp_firewalled;
    }
    if let Some(tcp_firewalled) = kad_firewall.lock().await.tcp_firewalled() {
        return tcp_firewalled;
    }
    ed2k_listener
        .local_addr()
        .map(|addr| addr.port() == 0)
        .unwrap_or(true)
}

/// Decide whether an inbound Kad HELLO (req/res) should request a
/// `HELLO_RES_ACK` to complete the three-way IP-verification handshake.
///
/// Mirrors the oracle `bAddedOrUpdated && !bValidReceiverKey` predicate in
/// `Process_KADEMLIA2_HELLO_REQ`: only request the ACK when the contact was
/// added or updated and the peer has not already proven a valid receiver key.
fn should_request_hello_res_ack(added_or_updated: bool, receiver_verify_key_valid: bool) -> bool {
    added_or_updated && !receiver_verify_key_valid
}

/// Mask a KADEMLIA2_REQ type byte to its low 5 bits and reject the malformed
/// type 0, mirroring `Process_KADEMLIA2_REQ` (`byType &= 0x1F`, throw on 0).
///
/// Returns the masked type (which doubles as the max contact count to return)
/// or `None` when the request must be dropped.
fn kad_req_masked_count(type_byte: u8) -> Option<u8> {
    match type_byte & 0x1F {
        0 => None,
        masked => Some(masked),
    }
}

fn build_kad_hello_response_tags(
    kad_udp_port: u16,
    udp_firewalled: bool,
    tcp_firewalled: bool,
    request_ack: bool,
) -> Vec<Tag> {
    let mut tags = vec![Tag::new_short(
        tag_name::SOURCEUPORT,
        TagValue::U16(kad_udp_port),
    )];
    let misc_options =
        u8::from(udp_firewalled) | (u8::from(tcp_firewalled) << 1) | (u8::from(request_ack) << 2);
    tags.push(Tag::new_short(
        tag_name::KADMISCOPTIONS,
        TagValue::U8(misc_options),
    ));
    tags
}

fn build_kad_hello_request_tags(
    kad_udp_port: u16,
    can_advertise_source_udp_port: bool,
    udp_firewalled: bool,
    tcp_firewalled: bool,
    request_ack: bool,
) -> Vec<Tag> {
    // Mirror the oracle SendMyDetails (KademliaUDPListener.cpp:146-169): the two
    // tags are independent and additive, not mutually exclusive. SOURCEUPORT is
    // written whenever we advertise our intern Kad port (!GetUseExternKadPort),
    // and KADMISCOPTIONS is written (v8+) whenever we request an ACK or are
    // firewalled. A firewalled node on its intern port therefore emits BOTH.
    let mut tags = Vec::new();
    if can_advertise_source_udp_port {
        tags.push(Tag::new_short(
            tag_name::SOURCEUPORT,
            TagValue::U16(kad_udp_port),
        ));
    }
    if request_ack || udp_firewalled || tcp_firewalled {
        let misc_options = u8::from(udp_firewalled)
            | (u8::from(tcp_firewalled) << 1)
            | (u8::from(request_ack) << 2);
        tags.push(Tag::new_short(
            tag_name::KADMISCOPTIONS,
            TagValue::U8(misc_options),
        ));
    }
    tags
}

async fn build_kad_hello_request(
    dht: &DhtNode,
    ed2k_listener: &TcpListener,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    request_ack: bool,
) -> Result<HelloReq> {
    let bind_addr = dht.bind_addr()?;
    let tcp_port = ed2k_listener
        .local_addr()
        .context("failed to read eD2K listener address while building Kad HELLO request")?
        .port();
    let firewall = kad_firewall.lock().await;
    let tcp_firewalled = resolve_tcp_firewalled_with_firewall(
        ed2k_listener,
        server_state,
        firewall.tcp_firewalled(),
    )
    .await;

    Ok(HelloReq {
        node_id: dht.own_id(),
        tcp_port,
        version: KAD_VERSION,
        tags: build_kad_hello_request_tags(
            bind_addr.port(),
            firewall.udp_verified && firewall.udp_open,
            firewall.udp_verified && !firewall.udp_open,
            tcp_firewalled,
            request_ack,
        ),
    })
}

/// Resolve the TCP-firewalled verdict when the Kad firewall verdict has already
/// been read from a held [`KadFirewallState`] guard, avoiding a re-lock (the
/// tokio mutex is not reentrant). Same priority as [`current_tcp_firewalled`]:
/// server first, then the supplied Kad verdict, then the listener fallback.
async fn resolve_tcp_firewalled_with_firewall(
    ed2k_listener: &TcpListener,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_verdict: Option<bool>,
) -> bool {
    if let Some(tcp_firewalled) = server_state.read().await.tcp_firewalled() {
        return tcp_firewalled;
    }
    if let Some(tcp_firewalled) = kad_verdict {
        return tcp_firewalled;
    }
    ed2k_listener
        .local_addr()
        .map(|addr| addr.port() == 0)
        .unwrap_or(true)
}

async fn build_kad_hello_response(
    dht: &DhtNode,
    ed2k_listener: &TcpListener,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    request_ack: bool,
) -> Result<HelloRes> {
    let bind_addr = dht.bind_addr()?;
    let tcp_port = ed2k_listener
        .local_addr()
        .context("failed to read eD2K listener address while building Kad HELLO response")?
        .port();
    let firewall = kad_firewall.lock().await;
    let tcp_firewalled = resolve_tcp_firewalled_with_firewall(
        ed2k_listener,
        server_state,
        firewall.tcp_firewalled(),
    )
    .await;

    Ok(HelloRes {
        node_id: dht.own_id(),
        tcp_port,
        version: KAD_VERSION,
        tags: build_kad_hello_response_tags(
            bind_addr.port(),
            firewall.udp_verified && !firewall.udp_open,
            tcp_firewalled,
            request_ack,
        ),
    })
}

fn firewalled_response_ip_for_sender(from: SocketAddr) -> Option<u32> {
    match from.ip() {
        IpAddr::V4(ip) => Some(u32::from_be_bytes(ip.octets())),
        IpAddr::V6(_) => None,
    }
}

async fn send_kad_firewalled_response(dht: &DhtNode, from: SocketAddr) -> Result<()> {
    let Some(ip) = firewalled_response_ip_for_sender(from) else {
        tracing::debug!("ignoring Kad FIREWALLED request from non-IPv4 peer {from}");
        return Ok(());
    };

    dht.send_packet(from, &KadPacket::FirewalledRes(FirewalledRes { ip }))
        .await
        .with_context(|| format!("failed to send Kad FIREWALLED_RES to {from}"))?;
    Ok(())
}

async fn probe_kad_firewalled_tcp(
    bind_ip: Ipv4Addr,
    peer_addr: SocketAddr,
    timeout: Duration,
) -> Result<()> {
    let socket = match peer_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => {
            anyhow::bail!("cannot probe IPv6 Kad TCP peer from IPv4 bind address {bind_ip}");
        }
    }
    .context("failed to create Kad TCP firewall probe socket")?;
    socket
        .bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
        .with_context(|| format!("failed to bind Kad TCP firewall probe socket to {bind_ip}"))?;
    tokio::time::timeout(timeout, socket.connect(peer_addr))
        .await
        .with_context(|| format!("timed out probing Kad TCP firewall peer {peer_addr}"))?
        .with_context(|| format!("failed to connect Kad TCP firewall probe to {peer_addr}"))?;
    Ok(())
}

fn spawn_kad_firewalled_response(dht: DhtNode, bind_ip: Ipv4Addr, from: SocketAddr, tcp_port: u16) {
    tokio::spawn(async move {
        if let Err(error) = send_kad_firewalled_response(&dht, from).await {
            tracing::debug!("Kad FIREWALLED_RES failed for {from}: {error:#}");
            return;
        }
        if tcp_port == 0 {
            return;
        }

        let peer_addr = SocketAddr::new(from.ip(), tcp_port);
        let timeout = Duration::from_secs(KAD_FIREWALLED_TCP_PROBE_TIMEOUT_SECS);
        match probe_kad_firewalled_tcp(bind_ip, peer_addr, timeout).await {
            Ok(()) => {
                if let Err(error) = dht.send_packet(from, &KadPacket::FirewalledAckRes).await {
                    tracing::debug!("Kad FIREWALLED_ACK_RES failed for {from}: {error:#}");
                }
            }
            Err(error) => {
                tracing::debug!("Kad TCP firewall probe failed for {peer_addr}: {error:#}");
            }
        }
    });
}

async fn kad_firewall_ack_hello_identity(
    dht: &DhtNode,
    listener_addr: SocketAddr,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    network: &Ed2kNetworkConfig,
) -> Result<Ed2kHelloIdentity> {
    let identity = Ed2kHelloIdentity {
        user_hash: network.user_hash,
        client_id: 0,
        tcp_port: listener_addr.port(),
        udp_port: dht
            .bind_addr()
            .context("failed to resolve Kad bind address for firewall ACK hello")?
            .port(),
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(network.config.obfuscation_enabled),
        direct_udp_callback: false,
    };
    Ok(enrich_hello_identity(identity, server_state, kad_firewall).await)
}

fn spawn_modern_kad_firewalled_response(
    dht: DhtNode,
    listener_addr: SocketAddr,
    server_state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    network: Ed2kNetworkConfig,
    from: SocketAddr,
    req: Firewalled2Req,
) {
    tokio::spawn(async move {
        if let Err(error) = send_kad_firewalled_response(&dht, from).await {
            tracing::debug!("Kad FIREWALLED_RES failed for modern request from {from}: {error:#}");
            return;
        }
        if req.tcp_port == 0 {
            return;
        }

        let peer_addr = SocketAddr::new(from.ip(), req.tcp_port);
        let timeout = Duration::from_secs(KAD_FIREWALLED_TCP_PROBE_TIMEOUT_SECS);
        let hello_identity = match kad_firewall_ack_hello_identity(
            &dht,
            listener_addr,
            &server_state,
            &kad_firewall,
            &network,
        )
        .await
        {
            Ok(identity) => identity,
            Err(error) => {
                tracing::debug!(
                    "failed to build Kad firewall ACK hello for {peer_addr}: {error:#}"
                );
                return;
            }
        };

        match send_kad_firewall_tcp_ack(
            network.bind_ip,
            peer_addr,
            hello_identity,
            req.user_hash.0,
            req.connect_options,
            timeout,
        )
        .await
        {
            Ok(mode) => tracing::debug!(
                transport = mode.as_str(),
                "sent Kad TCP firewall ACK to {peer_addr}"
            ),
            Err(error) => {
                tracing::debug!("Kad modern TCP firewall ACK failed for {peer_addr}: {error:#}");
            }
        }
    });
}

async fn remember_passive_note_results(
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    results: &[KadNoteResult],
) {
    for result in results {
        let file_hash = result.file_hash.to_string();
        let Ok(manifest) = transfer_runtime.manifest(&file_hash).await else {
            tracing::debug!(
                file_hash,
                "skipping passive Kad note memory for unknown transfer"
            );
            continue;
        };
        if !manifest.comment.is_empty() || manifest.rating != 0 {
            continue;
        }
        let comment = result.comment.clone().unwrap_or_default();
        let rating = result.rating.unwrap_or(0).min(5);
        if comment.is_empty() && rating == 0 {
            continue;
        }
        if let Err(error) = transfer_runtime
            .update_shared_file_metadata(&file_hash, None, Some((&comment, rating)))
            .await
        {
            tracing::debug!(
                file_hash,
                source_id = %result.source_id,
                "skipping passive Kad note memory: {error:#}"
            );
        }
    }
}

async fn index_passive_keyword_result(index: &Arc<Mutex<FileIndex>>, result: &KadSearchResult) {
    let Some(size_bytes) = result.size.filter(|size| *size > 0) else {
        return;
    };
    if result.names.is_empty() {
        return;
    }
    let availability_score = result.source_count.unwrap_or(1).max(1) as i64;
    let mut index = index.lock().await;
    for name in &result.names {
        if name.trim().is_empty() {
            continue;
        }
        if let Err(error) = index.upsert_file(&IndexedFile {
            ed2k_hash: result.hash.to_string(),
            name: name.clone(),
            size_bytes,
            content_type: "unknown".to_string(),
            availability_score,
        }) {
            tracing::debug!(
                file_hash = %result.hash,
                name,
                "failed to index passive Kad keyword result: {error:#}"
            );
        }
    }
}

fn note_result_key(result: &KadNoteResult) -> (Ed2kHash, Ed2kHash, Option<u8>, Option<String>) {
    (
        result.file_hash,
        result.source_id,
        result.rating,
        result.comment.clone(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassiveReplayFamily {
    Keyword,
    Source,
    Notes,
}

fn preferred_passive_replay_families(counts: SnoopQueueFamilyCounts) -> [PassiveReplayFamily; 3] {
    let mut families = [
        (PassiveReplayFamily::Keyword, counts.keyword, 0u8),
        (PassiveReplayFamily::Source, counts.source, 1u8),
        (PassiveReplayFamily::Notes, counts.notes, 2u8),
    ];
    families.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.2.cmp(&right.2)));
    [families[0].0, families[1].0, families[2].0]
}

#[allow(clippy::cognitive_complexity)]
async fn handle_kad_local_store_packet(
    runtime: &KadLocalStoreRuntime,
    received: ReceivedKadPacket,
) -> Result<()> {
    let dht = &runtime.dht;
    let local_store = &runtime.local_store;
    let snoop_queue = &runtime.snoop_queue;
    let ed2k_listener = &runtime.ed2k_listener;
    let server_state = &runtime.server_state;
    let kad_firewall = &runtime.kad_firewall;
    let kad_buddy = &runtime.kad_buddy;
    let buddy_registry = &runtime.buddy_registry;
    let network = &runtime.network;
    let ReceivedKadPacket {
        packet,
        from,
        receiver_verify_key_valid,
        ..
    } = received;
    if let IpAddr::V4(ip) = from.ip() {
        if network.ip_filter.is_filtered(ip) {
            tracing::trace!("dropping Kad packet from IP-filtered peer {from}");
            return Ok(());
        }
    }
    match packet {
        KadPacket::HelloReq(req) => {
            // Oracle Process_KADEMLIA2_HELLO_REQ: request the ACK (three-way
            // handshake to verify the remote's IP) only when the contact was
            // added/updated and the peer did not already prove a valid receiver
            // key. Mirrors SendMyDetails(..., bAddedOrUpdated && !bValidReceiverKey).
            let added_or_updated = match dht
                .add_contact_from_hello(from, req.node_id, req.tcp_port, req.version, &req.tags)
                .await
            {
                Ok(_) => true,
                Err(error) => {
                    tracing::debug!(
                        "failed to record Kad HELLO_REQ contact from {from}: {error:#}"
                    );
                    false
                }
            };
            let request_ack =
                should_request_hello_res_ack(added_or_updated, receiver_verify_key_valid);
            let response = build_kad_hello_response(
                dht,
                ed2k_listener,
                server_state,
                kad_firewall,
                request_ack,
            )
            .await?;
            dht.send_packet(from, &KadPacket::HelloRes(response))
                .await?;
        }
        KadPacket::HelloRes(res) => {
            match dht
                .add_contact_from_hello(from, res.node_id, res.tcp_port, res.version, &res.tags)
                .await
            {
                Ok(metadata) if metadata.requests_hello_res_ack => {
                    dht.send_packet(
                        from,
                        &KadPacket::HelloResAck(HelloResAck {
                            node_id: dht.own_id(),
                            tags: Vec::new(),
                        }),
                    )
                    .await?;
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::debug!(
                        "failed to record Kad HELLO_RES contact from {from}: {error:#}"
                    );
                }
            }
        }
        KadPacket::HelloResAck(ack) => {
            // Final leg of the three-way handshake (oracle
            // Process_KADEMLIA2_HELLO_RES_ACK -> VerifyContact). The remote
            // returns its Kad ID inside a packet that only a node actually
            // reachable at the source IP could have produced, so the receiver
            // key must be valid. We then mark the contact verified, proving its
            // source IP is not spoofed. The receive loop already enforced that we
            // had sent a HELLO_RES to this IP (HELLO_RES is out-tracked).
            if !receiver_verify_key_valid {
                tracing::debug!(
                    "ignoring Kad HELLO_RES_ACK from {from}: receiver key is invalid"
                );
            } else if let IpAddr::V4(ip) = from.ip() {
                if dht.verify_contact(&ack.node_id, ip).await {
                    tracing::debug!("verified Kad contact {} via HELLO_RES_ACK", ack.node_id);
                } else {
                    tracing::debug!(
                        "Kad HELLO_RES_ACK from {from}: no matching contact to verify"
                    );
                }
            }
        }
        KadPacket::Ping => {
            dht.send_packet(
                from,
                &KadPacket::Pong(emulebb_kad_proto::Pong {
                    udp_port: from.port(),
                }),
            )
            .await?;
        }
        KadPacket::FirewalledReq(req) => {
            spawn_kad_firewalled_response(dht.clone(), network.bind_ip, from, req.tcp_port);
        }
        KadPacket::Firewalled2Req(req) => {
            spawn_modern_kad_firewalled_response(
                dht.clone(),
                ed2k_listener.local_addr().context(
                    "failed to read eD2K listener address while handling Kad FIREWALLED2_REQ",
                )?,
                Arc::clone(server_state),
                Arc::clone(kad_firewall),
                network.clone(),
                from,
                req,
            );
        }
        KadPacket::FirewalledRes(res) => {
            // A helper we probed in our TCP firewall recheck reports our
            // externally observed IP (oracle Process_KADEMLIA_FIREWALLED_RES).
            // Accept it only from an IP we actually probed (IsKadFirewallCheckIP)
            // and record it against the active recheck round.
            let now = Utc::now();
            let reported_ip = IpAddr::V4(Ipv4Addr::from(res.ip.to_be_bytes()));
            let outcome = {
                let mut firewall = kad_firewall.lock().await;
                if !firewall.is_tcp_firewall_check_ip(from.ip(), now) {
                    tracing::debug!(
                        "ignoring unrequested Kad FIREWALLED_RES from {from}"
                    );
                    FirewalledResponseOutcome::Ignored
                } else {
                    firewall.record_firewalled_response(from.ip(), reported_ip, now)
                }
            };
            match outcome {
                FirewalledResponseOutcome::Completed => tracing::debug!(
                    "Kad TCP firewall recheck IP window completed (external IP {reported_ip})"
                ),
                FirewalledResponseOutcome::Recorded => tracing::debug!(
                    "recorded Kad FIREWALLED_RES from {from} (external IP {reported_ip})"
                ),
                FirewalledResponseOutcome::Ignored => {}
            }
        }
        KadPacket::FirewallUdp(packet) => {
            let outcome = kad_firewall.lock().await.record_firewall_udp_packet(
                from.ip(),
                packet.error_code,
                packet.udp_port,
                Utc::now(),
            );
            match outcome {
                FirewallUdpPacketOutcome::Open(summary) => {
                    // An open result that discovered a distinct external UDP port
                    // is the most authoritative reachability fact; pin it over the
                    // UPnP mapping. (The driver loop also applies this on finish;
                    // doing it here too means a fast inbound completion is reflected
                    // immediately.)
                    if let Some(external_udp_port) = summary.external_udp_port {
                        runtime.reachability.set_peer_confirmed_udp_port(external_udp_port);
                    }
                    tracing::info!(
                        helpers_selected = summary.helpers_selected,
                        helpers_requested = summary.helpers_requested,
                        helpers_succeeded = summary.helpers_succeeded,
                        external_udp_port = summary.external_udp_port.unwrap_or_default(),
                        "Kad UDP firewall check completed from {from}"
                    );
                }
                FirewallUdpPacketOutcome::Recorded => tracing::debug!(
                    error_code = packet.error_code,
                    udp_port = packet.udp_port,
                    "recorded Kad UDP firewall packet from {from}"
                ),
                FirewallUdpPacketOutcome::Ignored => tracing::debug!(
                    error_code = packet.error_code,
                    udp_port = packet.udp_port,
                    "ignored unrelated Kad UDP firewall packet from {from}"
                ),
            }
        }
        KadPacket::BootstrapReq => {
            let bind_addr = dht.bind_addr()?;
            let contacts = dht
                .closest_contacts(&dht.own_id(), K)
                .await
                .into_iter()
                .map(|contact| ContactEntry {
                    node_id: contact.id,
                    ip: u32::from_be_bytes(contact.ip.octets()),
                    udp_port: contact.udp_port,
                    tcp_port: contact.tcp_port,
                    version: contact.kad_version,
                })
                .collect();
            dht.send_packet(
                from,
                &KadPacket::BootstrapRes(emulebb_kad_proto::BootstrapRes {
                    sender_id: dht.own_id(),
                    sender_tcp_port: bind_addr.port(),
                    sender_version: KAD_VERSION,
                    contacts,
                }),
            )
            .await?;
        }
        KadPacket::Req(req) => {
            // Oracle Process_KADEMLIA2_REQ (KademliaUDPListener.cpp:706-755):
            // mask the type to its low 5 bits, reject type 0 as malformed, and
            // only respond when the recipient-ID sanity check matches our own
            // Kad ID (the requester proves it is talking to the node it thinks
            // it is, not a stale/recycled ID). The masked type doubles as the
            // max number of contacts to return.
            let Some(max_required) = kad_req_masked_count(req.count) else {
                tracing::debug!("dropping malformed Kad REQ (type 0) from {from}");
                return Ok(());
            };
            if req.recipient_id != dht.own_id() {
                tracing::debug!(
                    "dropping Kad REQ from {from}: recipient-id mismatch (mistaken identity)"
                );
            } else {
                let contacts = dht
                    .closest_contacts_max_type(&req.target, max_required as usize, KAD_REQ_MAX_TYPE)
                    .await
                    .into_iter()
                    .map(|contact| ContactEntry {
                        node_id: contact.id,
                        ip: u32::from_be_bytes(contact.ip.octets()),
                        udp_port: contact.udp_port,
                        tcp_port: contact.tcp_port,
                        version: contact.kad_version,
                    })
                    .collect();
                dht.send_packet(
                    from,
                    &KadPacket::Res(emulebb_kad_proto::Res {
                        target: req.target,
                        contacts,
                    }),
                )
                .await?;
            }
        }
        KadPacket::SearchKeyReq(req) => {
            let now = Utc::now();
            record_kad_snoop_entry(snoop_queue, build_keyword_snoop_entry(&req, now)).await;
            let response = {
                let mut store = local_store.lock().await;
                store.keyword_search_response(
                    dht.own_id(),
                    &req,
                    LOCAL_KEYWORD_SEARCH_RESPONSE_LIMIT,
                    now,
                )
            };
            send_local_search_response(dht, from, response).await;
        }
        KadPacket::SearchSourceReq(req) => {
            let now = Utc::now();
            record_kad_snoop_entry(snoop_queue, build_source_snoop_entry(&req, now)).await;
            let response = {
                let mut store = local_store.lock().await;
                store.source_search_response(
                    dht.own_id(),
                    &req,
                    LOCAL_SOURCE_SEARCH_RESPONSE_LIMIT,
                    now,
                )
            };
            send_local_search_response(dht, from, response).await;
        }
        KadPacket::SearchNotesReq(req) => {
            let now = Utc::now();
            record_kad_snoop_entry(snoop_queue, build_notes_snoop_entry(&req, now)).await;
            let response = {
                let mut store = local_store.lock().await;
                store.notes_search_response(
                    dht.own_id(),
                    &req,
                    LOCAL_NOTES_SEARCH_RESPONSE_LIMIT,
                    now,
                )
            };
            send_local_search_response(dht, from, response).await;
        }
        KadPacket::PublishKeyReq(req) => {
            let load = {
                let mut store = local_store.lock().await;
                store.record_keyword_publish_batch(req.target, &req.entries, Utc::now())
            };
            if network.kad_local_store.enabled {
                persist_kad_publish_cache(&runtime.metadata_store, local_store).await;
            }
            let _ = dht
                .send_packet(
                    from,
                    &KadPacket::PublishRes(PublishRes {
                        target: req.target,
                        load,
                        options: None,
                    }),
                )
                .await;
        }
        KadPacket::PublishSourceReq(req) => {
            let load = if let IpAddr::V4(source_ip) = from.ip() {
                let mut store = local_store.lock().await;
                store.record_source_publish(
                    req.target,
                    req.publisher_id,
                    source_ip,
                    from.port(),
                    &req.tags,
                    Utc::now(),
                )
            } else {
                None
            };
            if let Some(load) = load {
                persist_kad_publish_cache(&runtime.metadata_store, local_store).await;
                let _ = dht
                    .send_packet(
                        from,
                        &KadPacket::PublishRes(PublishRes {
                            target: req.target,
                            load,
                            options: None,
                        }),
                    )
                    .await;
            }
        }
        KadPacket::PublishNotesReq(req) => {
            let load = if let IpAddr::V4(publisher_ip) = from.ip() {
                let mut store = local_store.lock().await;
                store.record_notes_publish(
                    req.target,
                    req.publisher_id,
                    publisher_ip,
                    &req.tags,
                    Utc::now(),
                )
            } else {
                None
            };
            if let Some(load) = load {
                persist_kad_publish_cache(&runtime.metadata_store, local_store).await;
                let _ = dht
                    .send_packet(
                        from,
                        &KadPacket::PublishRes(PublishRes {
                            target: req.target,
                            load,
                            options: None,
                        }),
                    )
                    .await;
            }
        }
        KadPacket::FindBuddyReq(req) => {
            handle_kad_find_buddy_req(
                dht,
                ed2k_listener,
                server_state,
                kad_firewall,
                kad_buddy,
                buddy_registry,
                network,
                from,
                req,
            )
            .await?;
        }
        KadPacket::FindBuddyRes(res) => {
            handle_kad_find_buddy_res(
                dht,
                kad_buddy,
                buddy_registry,
                &runtime.reachability,
                &runtime.transfer_runtime,
                network,
                from,
                res,
            )
            .await;
        }
        KadPacket::CallbackReq(req) => {
            handle_kad_callback_req(kad_buddy, buddy_registry, from, &req).await;
        }
        _ => {}
    }
    Ok(())
}

/// Inbound `KADEMLIA_FINDBUDDY_REQ` (a firewalled peer asks us to be its buddy).
///
/// Mirrors `Process_KADEMLIA_FINDBUDDY_REQ`: only answer when we are reachable
/// (not TCP- or UDP-firewalled) and do not already serve a buddy. On acceptance
/// we register the requester and reply `FINDBUDDY_RES` echoing its `buddy_id`,
/// our eD2k client hash, and our TCP port (plus our connect options).
async fn handle_kad_find_buddy_req(
    dht: &DhtNode,
    ed2k_listener: &TcpListener,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    kad_buddy: &Arc<Mutex<KadBuddyState>>,
    buddy_registry: &BuddySocketRegistry,
    network: &Ed2kNetworkConfig,
    from: SocketAddr,
    req: FindBuddyReq,
) -> Result<()> {
    // We cannot relay for others while firewalled ourselves (oracle refuses with
    // GetFirewalled() || IsFirewalledUDP(true) || !IsVerified()). IsFirewalledUDP
    // is "verified AND not open"; an unverified UDP status is also a refusal.
    let self_firewalled = current_tcp_firewalled(ed2k_listener, server_state, kad_firewall).await
        || {
            let firewall = kad_firewall.lock().await;
            !firewall.udp_verified || !firewall.udp_open
        };
    let tcp_port = ed2k_listener
        .local_addr()
        .context("failed to read eD2K listener address while handling Kad FINDBUDDY_REQ")?
        .port();

    let buddy = IncomingBuddy {
        client_hash: req.client_hash,
        buddy_id: req.buddy_id,
        tcp_addr: SocketAddr::new(from.ip(), req.tcp_port),
        udp_addr: from,
        registered_at: Utc::now(),
    };

    {
        let mut state = kad_buddy.lock().await;
        match state.accept_incoming_buddy(self_firewalled, buddy.clone()) {
            Ok(()) => {}
            Err(FindBuddyReqRefusal::SelfFirewalled) => {
                tracing::debug!("ignoring Kad FINDBUDDY_REQ from {from}: we are firewalled");
                return Ok(());
            }
            Err(FindBuddyReqRefusal::AlreadyHaveBuddy) => {
                tracing::debug!("ignoring Kad FINDBUDDY_REQ from {from}: already serving a buddy");
                return Ok(());
            }
        }
    }

    let response = FindBuddyRes {
        // Echo the requester's buddy-search id so it can verify the response
        // against its own Kad id (it XORs with all-ones).
        buddy_id: req.buddy_id,
        client_hash: Ed2kHash::from_bytes(network.user_hash),
        tcp_port,
        connect_options: Some(emule_connect_options(network.config.obfuscation_enabled)),
    };
    // The oracle establishes the buddy relationship only as part of replying;
    // if the send fails, release the slot we optimistically claimed (and skip
    // the registry expectation) so the buddy is not held forever (later requests
    // would hit `AlreadyHaveBuddy` with no callback path to ever satisfy it).
    if let Err(error) = dht
        .send_packet(from, &KadPacket::FindBuddyRes(response))
        .await
    {
        kad_buddy.lock().await.release_incoming_buddy(&buddy);
        return Err(error)
            .with_context(|| format!("failed to send Kad FINDBUDDY_RES to {from}"));
    }

    // Record the firewalled client we expect to connect to us so the listener
    // session can recognize it and hold the buddy socket open for callback relay
    // (oracle KS_INCOMING_BUDDY). We are IPv4-only; a non-IPv4 source cannot be
    // matched on connect, so skip the expectation in that (unreachable) case.
    if let IpAddr::V4(buddy_ip) = from.ip() {
        buddy_registry.set_expected_inbound(ExpectedInboundBuddy {
            ip: buddy_ip,
            user_hash: req.client_hash.0,
            buddy_id: req.buddy_id,
        });
    }
    tracing::info!("accepted Kad buddy request from {from}; replied FINDBUDDY_RES");
    Ok(())
}

/// Inbound `KADEMLIA_FINDBUDDY_RES` (a candidate accepted our buddy request).
///
/// Mirrors `Process_KADEMLIA_FINDBUDDY_RES`: verify the echoed `buddy_id`
/// against our own Kad id, then record the buddy (oracle `RequestBuddy`). The
/// buddy-management task keeps the TCP connection.
async fn handle_kad_find_buddy_res(
    dht: &DhtNode,
    kad_buddy: &Arc<Mutex<KadBuddyState>>,
    buddy_registry: &BuddySocketRegistry,
    reachability: &ExternalReachability,
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    network: &Ed2kNetworkConfig,
    from: SocketAddr,
    res: FindBuddyRes,
) {
    if !find_buddy_res_matches(dht.own_id(), res.buddy_id) {
        tracing::debug!("dropping Kad FINDBUDDY_RES from {from}: buddy_id echo mismatch");
        return;
    }
    // We are IPv4-only; a non-IPv4 buddy source cannot be connected.
    let IpAddr::V4(buddy_ip) = from.ip() else {
        tracing::debug!("dropping Kad FINDBUDDY_RES from {from}: non-IPv4 buddy source");
        return;
    };
    let connect_options = res.connect_options.unwrap_or(0);
    let buddy = OutgoingBuddy {
        client_hash: res.client_hash,
        tcp_addr: SocketAddr::new(from.ip(), res.tcp_port),
        udp_addr: from,
        connect_options,
        acquired_at: Utc::now(),
    };
    {
        let mut state = kad_buddy.lock().await;
        // The oracle keeps a single buddy; ignore a second concurrent response.
        if state.has_outgoing_buddy() {
            tracing::debug!("ignoring Kad FINDBUDDY_RES from {from}: already hold a buddy");
            return;
        }
        state.set_outgoing_buddy(buddy);
    }
    set_hello_buddy_snapshot(Some(HelloBuddySnapshot { ip: buddy_ip, udp_port: from.port() }));
    tracing::info!("acquired Kad buddy {from} (tcp_port={})", res.tcp_port);

    // Establish + hold the persistent buddy TCP link so callbacks can be relayed
    // back to us, then ping it at the oracle cadence. When the link drops, clear
    // our acquired buddy so the buddy-management loop re-searches (oracle
    // buddy-loss SetFindBuddy).
    let bind_ip = network.bind_ip;
    let hello_identity = buddy_hello_identity(network, reachability);
    let buddy_user_hash = res.client_hash.0;
    let buddy_addr = SocketAddr::new(from.ip(), res.tcp_port);
    let registry = buddy_registry.clone();
    let kad_buddy = Arc::clone(kad_buddy);
    let own_kad_id = dht.own_id().0;
    let transfer_runtime = Arc::clone(transfer_runtime);
    let lost = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(async move {
        if let Err(error) = run_outbound_buddy_link(OutboundBuddyLinkOptions {
            bind_ip,
            buddy_addr,
            buddy_user_hash,
            buddy_connect_options: connect_options,
            hello_identity,
            own_kad_id,
            transfer_runtime,
            registry,
            timeout: KAD_BUDDY_LINK_TIMEOUT,
            lost,
        })
        .await
        {
            tracing::debug!("outbound Kad buddy link to {buddy_addr} failed: {error:#}");
        }
        // On any exit (connect failure or link drop), drop the acquired buddy so
        // the next upkeep re-searches.
        kad_buddy.lock().await.clear_outgoing_buddy();
        set_hello_buddy_snapshot(None);
    });
}

/// Build the hello identity used by buddy links / callback completion, mirroring
/// the listener/server hello (advertised external ports + obfuscation options).
fn buddy_hello_identity(
    network: &Ed2kNetworkConfig,
    reachability: &ExternalReachability,
) -> Ed2kHelloIdentity {
    Ed2kHelloIdentity {
        user_hash: network.user_hash,
        client_id: 0,
        tcp_port: reachability.advertised_tcp_port(network.listen_port),
        udp_port: reachability.advertised_udp_port(network.kad_bind_addr.port()),
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(network.config.obfuscation_enabled),
        direct_udp_callback: false,
    }
}

/// Inbound `KADEMLIA_CALLBACK_REQ` (a peer wants us to relay a callback to the
/// firewalled client we are a buddy for).
///
/// Mirrors `Process_KADEMLIA_CALLBACK_REQ`: relay an `OP_CALLBACK` to the
/// buddied client over the persistent buddy TCP connection
/// (`pBuddy->socket->SendPacket`). We encode the relay frame
/// `[uCheck u128][uFile u128][uIP u32][uTCP u16]` — `uCheck` is the inbound
/// check id echoed verbatim, `uIP` is the callback requester's UDP source IP,
/// `uTCP` its advertised TCP port — and push it down the held inbound buddy
/// socket via the buddy-socket registry.
async fn handle_kad_callback_req(
    kad_buddy: &Arc<Mutex<KadBuddyState>>,
    buddy_registry: &BuddySocketRegistry,
    from: SocketAddr,
    req: &CallbackReq,
) {
    // Confirm the request is for the firewalled client we serve as a buddy (the
    // echoed check id must match the buddy we registered). The oracle relays to
    // its single buddy; matching the registered id is strictly safer.
    let buddy_tcp_addr = {
        let state = kad_buddy.lock().await;
        match state.callback_relay_target(req.buddy_id) {
            Some(buddy) => buddy.tcp_addr,
            None => {
                tracing::debug!(
                    "dropping Kad CALLBACK_REQ from {from}: no buddied client matches buddy_id"
                );
                return;
            }
        }
    };

    // The callback requester's IP is the UDP source of this request; we are
    // IPv4-only.
    let IpAddr::V4(requester_ip) = from.ip() else {
        tracing::debug!("dropping Kad CALLBACK_REQ from {from}: non-IPv4 requester");
        return;
    };

    let frame = encode_kad_callback_relay_frame(
        req.buddy_id.0,
        &req.file_hash,
        requester_ip,
        req.tcp_port,
    );
    if buddy_registry.relay_to_inbound(req.buddy_id, frame) {
        tracing::info!(
            "relayed Kad OP_CALLBACK to buddied client {buddy_tcp_addr} for requester \
             {requester_ip}:{} (file_hash={})",
            req.tcp_port,
            req.file_hash
        );
    } else {
        tracing::debug!(
            "Kad CALLBACK_REQ from {from} matched buddy {buddy_tcp_addr} but no held buddy socket \
             is attached yet; dropping (buddy will reconnect)"
        );
    }
}

async fn persist_kad_publish_cache(
    metadata_store: &MetadataStore,
    local_store: &Arc<Mutex<KadLocalStore>>,
) {
    let snapshot = local_store.lock().await.publish_snapshot(Utc::now());
    let result = metadata_from_publish_snapshot(&snapshot)
        .and_then(|cache| metadata_store.replace_kad_publish_cache(&cache));
    if let Err(error) = result {
        tracing::warn!("failed to persist Kad publish cache: {error:#}");
    }
}

async fn record_kad_snoop_entry(snoop_queue: &Arc<Mutex<SnoopQueue>>, entry: SnoopEntry) {
    let logical_key = entry.logical_key().to_string();
    let outcome = snoop_queue.lock().await.record(entry);
    if outcome.is_new || outcome.hit_count <= 3 || outcome.hit_count % 10 == 0 {
        tracing::debug!(
            logical_key,
            hit_count = outcome.hit_count,
            queue_depth = outcome.queue_depth,
            family_queue_depth = outcome.family_queue_depth,
            "recorded Kad search demand"
        );
    }
}

async fn send_local_search_response(dht: &DhtNode, to: SocketAddr, response: Option<SearchRes>) {
    let Some(response) = response else {
        return;
    };
    for response in split_stock_search_responses(response, LOCAL_SEARCH_RESPONSE_MAX_PACKET_BYTES) {
        let _ = dht.send_packet(to, &KadPacket::SearchRes(response)).await;
    }
}

fn split_stock_search_responses(response: SearchRes, max_packet_bytes: usize) -> Vec<SearchRes> {
    if max_packet_bytes == 0 || response.results.len() <= 1 {
        return vec![response];
    }

    let SearchRes {
        sender_id,
        target,
        results,
    } = response;
    let mut pages = Vec::new();
    let mut current = Vec::new();

    for result in results {
        if current.is_empty() {
            current.push(result);
            continue;
        }

        let mut candidate = current.clone();
        candidate.push(result.clone());
        if encoded_search_response_len(sender_id, target, &candidate) > max_packet_bytes {
            pages.push(SearchRes {
                sender_id,
                target,
                results: current,
            });
            current = vec![result];
        } else {
            current = candidate;
        }
    }

    if !current.is_empty() {
        pages.push(SearchRes {
            sender_id,
            target,
            results: current,
        });
    }

    pages
}

fn encoded_search_response_len(
    sender_id: emulebb_kad_proto::NodeId,
    target: emulebb_kad_proto::NodeId,
    results: &[SearchResultEntry],
) -> usize {
    KadPacket::SearchRes(SearchRes {
        sender_id,
        target,
        results: results.to_vec(),
    })
    .encode()
    .map(|packet| packet.len())
    .unwrap_or(usize::MAX)
}

fn transfer_from_manifest(
    manifest: &Ed2kResumeManifest,
    state_name: &str,
    payload_path: String,
    download_speed_bytes_per_sec: u64,
    sources_transferring: u32,
    parts_available: u32,
) -> Transfer {
    let completed_bytes = manifest
        .pieces
        .iter()
        .map(|piece| piece.bytes_written)
        .sum::<u64>()
        .min(manifest.file_size);
    let progress = if manifest.file_size == 0 {
        0.0
    } else {
        completed_bytes as f64 / manifest.file_size as f64
    };
    // ED2K parts (9.28 MB each) map 1:1 to manifest pieces (piece_size ==
    // ED2K_PART_SIZE). A part is "obtained" once verified.
    let parts_progress_text: String = manifest
        .pieces
        .iter()
        .map(|piece| {
            if piece.state == Ed2kTransferState::Verified {
                '#'
            } else {
                '0'
            }
        })
        .collect();
    let parts_total = manifest.pieces.len() as u32;
    let parts_obtained = parts_progress_text.bytes().filter(|&c| c == b'#').count() as u32;
    let remaining = manifest.file_size.saturating_sub(completed_bytes);
    let eta = if download_speed_bytes_per_sec > 0 && remaining > 0 {
        Some(remaining / download_speed_bytes_per_sec)
    } else {
        None
    };
    // Master parity (GetTransferStateName + IsStopped): a stopped transfer is
    // reported with the `paused` state plus a separate `stopped` flag, not a
    // distinct `stopped` state token (which is not in the TransferState enum).
    let stopped = state_name == "stopped";
    let emitted_state = if stopped { "paused" } else { state_name };
    Transfer {
        ed2k_link: format!(
            "ed2k://|file|{}|{}|{}|/",
            manifest.canonical_name, manifest.file_size, manifest.file_hash
        ),
        hash: manifest.file_hash.clone(),
        name: manifest.canonical_name.clone(),
        path: payload_path,
        size_bytes: manifest.file_size,
        completed_bytes,
        state: emitted_state.to_string(),
        progress,
        sources: manifest.sources.len() as u32,
        sources_transferring,
        download_speed_ki_bps: download_speed_bytes_per_sec as f64 / 1024.0,
        upload_speed_ki_bps: 0.0,
        stopped,
        priority: "normal".to_string(),
        category_id: 0,
        category_name: default_transfer_category_name().to_string(),
        eta,
        added_at: None,
        completed_at: None,
        parts_total,
        parts_obtained,
        parts_progress_text,
        parts_available,
        auto_priority: false,
    }
}

fn kad_status_from_running(running: bool) -> NetworkStatus {
    NetworkStatus {
        running,
        connected: running,
        peer_count: 0,
        firewalled: if running { Some(false) } else { None },
        bootstrapping: Some(false),
        bootstrap_progress: Some(0),
        contact_count: if running { Some(0) } else { None },
        lan_mode: Some(false),
        users: if running { Some(0) } else { None },
        files: if running { Some(0) } else { None },
        indexed_sources: if running { Some(0) } else { None },
        indexed_keywords: if running { Some(0) } else { None },
        operation_queued: None,
        already_running: None,
    }
}

fn preserve_transfer_public_metadata(transfer: &mut Transfer, existing: &Transfer) {
    transfer.priority = existing.priority.clone();
    transfer.category_id = existing.category_id;
    transfer.category_name = existing.category_name.clone();
}

fn manifest_default_state_name(manifest: &Ed2kResumeManifest) -> &str {
    if manifest.completed {
        "completed"
    } else if let Some(control_state) = manifest.control_state.as_deref() {
        control_state
    } else if manifest.pieces.iter().any(|piece| piece.bytes_written != 0) {
        "downloading"
    } else {
        "queued"
    }
}

fn transfer_create_state_name(paused: Option<bool>) -> &'static str {
    if paused.unwrap_or(false) {
        "paused"
    } else {
        // A newly added, non-paused download starts immediately (eMule/aMule
        // parity), so it is created active rather than waiting in "queued".
        "downloading"
    }
}

fn validate_transfer_update_family(request: &TransferUpdate) -> Result<()> {
    let mut mutation_family_count = 0;
    if request.priority.is_some() {
        mutation_family_count += 1;
    }
    if request.category_id.is_some() || request.category_name.is_some() {
        mutation_family_count += 1;
    }
    if request.name.is_some() {
        mutation_family_count += 1;
    }
    ensure!(
        mutation_family_count != 0,
        "transfer PATCH requires priority, categoryId, categoryName, or name"
    );
    ensure!(
        mutation_family_count == 1,
        "transfer PATCH accepts only one mutation family"
    );
    if let Some(priority) = request.priority.as_deref() {
        let _ = validate_transfer_priority(priority)?;
    }
    Ok(())
}

fn validate_transfer_priority(priority: &str) -> Result<&str> {
    match priority {
        "auto" | "verylow" | "low" | "normal" | "high" | "veryhigh" => Ok(priority),
        _ => Err(anyhow::anyhow!(
            "priority must be one of auto, verylow, low, normal, high, veryhigh"
        )),
    }
}

fn download_priority_score(priority: &str) -> u32 {
    match priority {
        "verylow" => 1,
        "low" => 3,
        "high" => 7,
        "veryhigh" => 9,
        "auto" | "normal" => 5,
        _ => 5,
    }
}

fn normalize_transfer_name(name: Option<String>) -> Result<String> {
    let Some(name) = name else {
        anyhow::bail!("name must be a string");
    };
    let name = name.trim();
    ensure!(!name.is_empty(), "name must not be empty");
    ensure!(
        !name.chars().any(|character| matches!(
            character,
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
        ) || character.is_control()),
        "name must be a valid eD2K filename"
    );
    Ok(name.to_string())
}

fn default_transfer_category_name() -> &'static str {
    "All"
}

fn ensure_category_selector_is_unambiguous(
    category_id: Option<u32>,
    category_name: Option<&str>,
) -> Result<()> {
    ensure!(
        category_id.is_none() || category_name.is_none(),
        "categoryId and categoryName are mutually exclusive"
    );
    ensure!(
        category_name
            .map(|value| !value.trim().is_empty())
            .unwrap_or(true),
        "categoryName must not be empty"
    );
    Ok(())
}

fn transfer_create_links(request: TransferCreate) -> Result<Vec<String>> {
    match (request.link, request.links) {
        (Some(link), None) => {
            ensure!(!link.trim().is_empty(), "link is required");
            Ok(vec![link])
        }
        (None, Some(links)) => {
            ensure!(!links.is_empty(), "links must contain at least one entry");
            for link in &links {
                ensure!(
                    !link.trim().is_empty(),
                    "links must not contain empty entries"
                );
            }
            Ok(links)
        }
        (Some(_), Some(_)) => Err(anyhow::anyhow!("link and links are mutually exclusive")),
        (None, None) => Err(anyhow::anyhow!("link or links is required")),
    }
}

fn transfer_sources_from_manifest(
    manifest: &Ed2kResumeManifest,
    banned_clients: &HashSet<String>,
) -> Vec<TransferSource> {
    manifest
        .sources
        .iter()
        .map(|source| {
            let endpoint = format!("{}:{}", source.ip, source.tcp_port);
            let client_id = source.user_hash.clone().unwrap_or_else(|| endpoint.clone());
            let banned = banned_clients.contains(&client_id);
            TransferSource {
                client_id,
                hash: manifest.file_hash.clone(),
                endpoint: endpoint.clone(),
                ip: source.ip.clone(),
                tcp_port: source.tcp_port,
                port: source.tcp_port,
                user_hash: source.user_hash.clone(),
                user_name: endpoint.clone(),
                client_software: "unknown".to_string(),
                download_state: if banned { "banned" } else { "remembered" }.to_string(),
                download_speed_ki_bps: 0.0,
                available_parts: 0,
                part_count: manifest.pieces.len() as u32,
                address: source.ip.clone(),
                server_ip: String::new(),
                server_port: 0,
                low_id: false,
                queue_rank: 0,
                view_shared_files: false,
                shared_files_request_pending: false,
                banned,
                status: "remembered".to_string(),
            }
        })
        .collect()
}

/// Overlays live download-session state from the F1 registry onto the remembered
/// source list: matching a remembered source by `ip:tcp_port`, set its live
/// download state, speed, and advertised part availability. Sources with no live
/// session keep their "remembered" defaults.
fn enrich_sources_with_live(
    sources: &mut [TransferSource],
    live: &[Ed2kLiveSource],
    part_count: u32,
) {
    let live_by_endpoint: HashMap<String, &Ed2kLiveSource> = live
        .iter()
        .map(|source| (source.endpoint.to_string(), source))
        .collect();
    for source in sources.iter_mut() {
        let Some(live_source) = live_by_endpoint.get(&source.endpoint) else {
            continue;
        };
        source.download_speed_ki_bps = live_source.download_speed_bytes_per_sec as f64 / 1024.0;
        source.available_parts = live_source.available_parts;
        source.part_count = part_count;
        let state = if live_source.transferring {
            "downloading"
        } else {
            "connected"
        };
        source.download_state = state.to_string();
        source.status = state.to_string();
    }
}

/// Builds the per-part download breakdown from the resume manifest. ED2K parts
/// map 1:1 to manifest pieces (piece_size == ED2K_PART_SIZE). Geometry and
/// completion are real (per-piece `bytes_written`/`state`); `availableSources`
/// and `corrupted` are live-session-only signals the persistent manifest does
/// not track, so they are honestly reported as 0/false rather than fabricated.
fn transfer_parts_from_manifest(
    manifest: &Ed2kResumeManifest,
    available_sources_per_part: &[u32],
) -> Vec<TransferPart> {
    let part_size = manifest.piece_size.max(1);
    let file_size = manifest.file_size;
    manifest
        .pieces
        .iter()
        .map(|piece| {
            let start = u64::from(piece.piece_index) * part_size;
            let end_exclusive = (start + part_size).min(file_size).max(start);
            let size = end_exclusive - start;
            let end = end_exclusive.saturating_sub(1);
            let verified = matches!(piece.state, Ed2kTransferState::Verified);
            let completed_bytes = if verified {
                size
            } else {
                piece.bytes_written.min(size)
            };
            let gap_bytes = size - completed_bytes;
            TransferPart {
                index: piece.piece_index,
                start,
                end,
                size,
                completed_bytes,
                gap_bytes,
                complete: size > 0 && gap_bytes == 0,
                requested: matches!(piece.state, Ed2kTransferState::Requested),
                corrupted: false,
                available_sources: available_sources_per_part
                    .get(piece.piece_index as usize)
                    .copied()
                    .unwrap_or(0),
            }
        })
        .collect()
}

fn source_by_client_id(sources: Vec<TransferSource>, client_id: &str) -> Option<TransferSource> {
    sources.into_iter().find(|source| {
        source.client_id == client_id
            || source.endpoint == client_id
            || source.user_hash.as_deref() == Some(client_id)
    })
}

fn validate_source_client_id(client_id: &str) -> Result<()> {
    if client_id.len() == 32
        && client_id
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Ok(());
    }
    let Some((address, port)) = client_id.rsplit_once(':') else {
        anyhow::bail!("clientId must be a 32-character lowercase hex string or address:port");
    };
    ensure!(
        !address.trim().is_empty(),
        "clientId must be a 32-character lowercase hex string or address:port"
    );
    let port = port.parse::<u16>().map_err(|_| {
        anyhow::anyhow!("clientId must be a 32-character lowercase hex string or address:port")
    })?;
    ensure!(
        port != 0,
        "clientId must be a 32-character lowercase hex string or address:port"
    );
    Ok(())
}

fn source_friend_name(source: &TransferSource) -> String {
    if source.user_name.trim().is_empty() {
        source.client_id.clone()
    } else {
        source.user_name.clone()
    }
}

fn validate_url_import(url: &str) -> Result<String> {
    let trimmed = url.trim();
    ensure!(!trimmed.is_empty(), "url must not be empty");
    ensure!(
        !trimmed.chars().any(char::is_control),
        "url must be valid UTF-8 without control characters"
    );
    ensure!(
        trimmed.chars().count() <= 2048,
        "url must be at most 2048 characters"
    );
    Ok(trimmed.to_string())
}

/// Fetches a URL body for server.met / nodes.dat import. A browser User-Agent
/// is required: public eMule list mirrors reject or redirect the default agent.
async fn fetch_url_bytes(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        )
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let response = client.get(url).send().await?.error_for_status()?;
    Ok(response.bytes().await?.to_vec())
}

fn validate_shared_upload_priority(priority: &str) -> Result<(&str, bool)> {
    match priority {
        "auto" => Ok((priority, true)),
        "verylow" | "low" | "normal" | "high" | "release" => Ok((priority, false)),
        _ => Err(anyhow::anyhow!(
            "priority must be one of auto, verylow, low, normal, high, release"
        )),
    }
}

fn validate_shared_file_comment_rating(request: &SharedFileUpdate) -> Result<Option<(String, u8)>> {
    match (&request.comment, request.rating) {
        (None, None) => Ok(None),
        (Some(comment), Some(rating)) if rating <= 5 => Ok(Some((comment.clone(), rating))),
        (None, Some(_)) => anyhow::bail!("comment must be a string"),
        (Some(_), Some(_)) | (Some(_), None) => {
            anyhow::bail!("rating must be an integer between 0 and 5")
        }
    }
}

fn server_info_from_parts(
    address: &str,
    port: u16,
    name: Option<&str>,
    description: Option<&str>,
    static_server: bool,
    connected_endpoint: Option<&str>,
) -> ServerInfo {
    let endpoint = format!("{address}:{port}");
    let current = connected_endpoint.is_some_and(|connected| connected == endpoint);
    ServerInfo {
        address: address.to_string(),
        port,
        endpoint,
        name: name.unwrap_or_default().to_string(),
        priority: "normal".to_string(),
        static_server,
        connected: current,
        connecting: false,
        current,
        description: description.unwrap_or_default().to_string(),
        dyn_ip: String::new(),
        failed_count: 0,
        hard_files: 0,
        ip: String::new(),
        ping: 0,
        soft_files: 0,
        version: String::new(),
        users: 0,
        files: 0,
    }
}

fn apply_server_update(server: &mut ServerInfo, update: Option<&ServerUpdate>) {
    let Some(update) = update else {
        return;
    };
    if let Some(name) = update.name.as_ref() {
        server.name = name.clone();
    }
    if let Some(priority) = update.priority.as_ref() {
        server.priority = priority.clone();
    }
    if let Some(static_server) = update.static_server {
        server.static_server = static_server;
    }
}

fn validate_server_update(update: &ServerUpdate) -> Result<()> {
    if let Some(priority) = update.priority.as_deref() {
        let _ = validate_server_priority(priority)?;
    }
    Ok(())
}

fn validate_server_priority(priority: &str) -> Result<&str> {
    match priority {
        "low" | "normal" | "high" => Ok(priority),
        _ => Err(anyhow::anyhow!("priority must be one of low, normal, high")),
    }
}

fn server_endpoint_from_create(request: &ServerCreate) -> Result<String> {
    ensure!(!request.address.trim().is_empty(), "address is required");
    ensure!(request.port != 0, "port must be in the range 1..65535");
    if let Some(priority) = request.priority.as_deref() {
        let _ = validate_server_priority(priority)?;
    }
    Ok(format!("{}:{}", request.address, request.port))
}

/// Re-probe public IP via STUN while still unknown (gentle cadence).
const ED2K_PUBLIC_IP_PROBE_UNKNOWN_SECS: u64 = 120;
/// Re-check cadence once a public IP is known (in case it clears / the tunnel
/// rotates), so the fallback can refill it.
const ED2K_PUBLIC_IP_PROBE_KNOWN_SECS: u64 = 600;
/// Minimum spacing between reactive server re-logins triggered by an advertised
/// external-port change, so a flapping UPnP mapping cannot spam server reconnects
/// (server-ban-safe, in the spirit of the live-wire ≤1-connect/5min guard).
const ED2K_RELOGIN_MIN_INTERVAL: Duration = Duration::from_secs(300);

/// STUN-probe the data-plane egress and record the reflexive public IP when it is
/// otherwise unknown. The reask obfuscation key is our public IP (eMule
/// `EncryptSendClient`), normally learned from the server `OP_IDCHANGE`; in
/// Kad-only / pre-connect / LowID it is unknown, which blocks obfuscated reasks.
/// `set_if_unset` keeps the server path authoritative (eMule `GetPublicIP` order:
/// cached server/peer value, then the Kad/STUN fallback). Gentle: one STUN race
/// per interval, more often only while still unknown.
async fn run_ed2k_public_ip_probe(
    bind_ip: Ipv4Addr,
    public_ip: ExternalReachability,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        let known = public_ip.is_known();
        if !known
            && let Ok(ip) = stun_probe(bind_ip, DEFAULT_STUN_TIMEOUT).await
            && public_ip.set_if_unset(ip)
        {
            tracing::info!("ED2K public IP learned via STUN fallback: {ip}");
        }
        let secs = if known {
            ED2K_PUBLIC_IP_PROBE_KNOWN_SECS
        } else {
            ED2K_PUBLIC_IP_PROBE_UNKNOWN_SECS
        };
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }
}

/// One-shot NAT mapping-behavior probe (STUN, two servers) logged as a reachability
/// health signal at startup. Endpoint-independent (cone) → our advertised UDP port
/// matches what peers observe, so eD2k reask/HighID reachability is solid; symmetric
/// → each peer sees a different source port, so inbound reask is fragile and peers
/// fall back to TCP. Informational only (no behavior change): STUN reports the probe
/// socket's source-port mapping, not a listen port, so it is never used to advertise
/// a port — the advertised port stays UPnP-mapped / Kad-observed.
async fn run_ed2k_nat_type_probe(bind_ip: Ipv4Addr, shutdown: Arc<AtomicBool>) {
    if shutdown.load(Ordering::Relaxed) {
        return;
    }
    match stun_probe_mapping_behavior(bind_ip, DEFAULT_STUN_TIMEOUT).await {
        NatMappingBehavior::EndpointIndependent => tracing::info!(
            "NAT mapping behavior: endpoint-independent (cone) — eD2k reask/HighID reachability is solid"
        ),
        NatMappingBehavior::Symmetric => tracing::warn!(
            "NAT mapping behavior: symmetric — peers see a varying UDP source port; inbound reask is fragile (TCP fallback) and HighID may be unreliable"
        ),
        NatMappingBehavior::Inconclusive => tracing::debug!(
            "NAT mapping behavior: inconclusive (STUN mapping-behavior probe incomplete)"
        ),
    }
}

/// Keep the advertised external eD2k TCP + UDP ports (`advertised_ports`) in sync
/// with the live NAT mappings. eMule advertises the externally reachable ports,
/// not the internal ones: a UPnP gateway may grant different external ports, and
/// (a) a peer answers a UDP source-reask only when it can locate us by the
/// `(ip, udp_port)` we advertised (matching the reask datagram's source port, which
/// the gateway rewrites to the external port), and (b) peers/servers reach us for
/// incoming TCP connections + HighID callback on the advertised tcp_port. Polling
/// the NAT status reflects a mapping that appears after startup — or is remapped on
/// lease renewal — into subsequent hellos.
async fn run_advertised_ports_sync(
    nat: Arc<NatManager>,
    reachability: ExternalReachability,
    reconnect_signal: Arc<tokio::sync::Notify>,
    internal_tcp_port: u16,
    internal_udp_port: u16,
    shutdown: Arc<AtomicBool>,
) {
    // Baseline = the internal port the first login used before UPnP was ready; a
    // later external port (or a remap) is a change worth re-logging for to refresh
    // HighID, rate-limited so a flapping mapping cannot spam server reconnects.
    let mut last_advertised_tcp = internal_tcp_port;
    let mut last_relogin: Option<std::time::Instant> = None;
    while !shutdown.load(Ordering::Relaxed) {
        let status = nat.status().await;
        let external_for = |proto: TransportProtocol, internal: u16| -> Option<u16> {
            status.mappings.iter().find_map(|mapping: &MappedEndpoint| {
                (mapping.protocol == proto
                    && mapping.local_addr.port() == internal
                    && mapping.external_addr.port() != 0)
                    .then(|| mapping.external_addr.port())
            })
        };
        if let Some(external) = external_for(TransportProtocol::Tcp, internal_tcp_port) {
            reachability.set_external_tcp_port(external);
        }
        if let Some(external) = external_for(TransportProtocol::Udp, internal_udp_port) {
            reachability.set_external_udp_port(external);
        }
        // Reactive re-login: if the advertised TCP port (the HighID callback port)
        // changed and the rate limit allows, signal the server loop to reconnect.
        let advertised_tcp = reachability.advertised_tcp_port(internal_tcp_port);
        if advertised_tcp != last_advertised_tcp {
            let now = std::time::Instant::now();
            let allowed = last_relogin
                .is_none_or(|previous| now.duration_since(previous) >= ED2K_RELOGIN_MIN_INTERVAL);
            if allowed {
                tracing::info!(
                    "ED2K advertised TCP port changed {last_advertised_tcp} -> {advertised_tcp}; requesting server re-login"
                );
                reconnect_signal.notify_one();
                last_relogin = Some(now);
                last_advertised_tcp = advertised_tcp;
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// Re-engage consumer: drains [`ReaskEvent`]s the reask loop raises and reconnects
/// the named transfer over TCP *now*, reusing the normal download attempt (whose
/// `active_download_attempts` guard debounces duplicates). The loop only raises
/// `SourceReady` when a source's queue rank is imminent, so this claims the slot
/// instead of waiting for the periodic download cycle.
async fn run_ed2k_reask_reengage(
    core: EmulebbCore,
    mut events: ReaskEventReceiver,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        let Some(event) = events.recv().await else {
            break;
        };
        match event {
            ReaskEvent::SourceReleased { endpoint } => {
                // The reask loop dropped a detached source: free the lease it kept
                // (active_download_peer_endpoints + the registry) so the next
                // download cycle — or the SourceReady that follows — can re-acquire
                // and reconnect this endpoint over TCP. Without this the endpoint
                // stays leased forever and acquire_direct_download_source_leases
                // defers it, leaking the lease and killing re-engage.
                core.release_direct_download_source_leases(&[endpoint]).await;
            }
            ReaskEvent::SourceReady { file_hash } => {
                let hash = file_hash.to_string();
                let Some(transfer) = core.transfer(&hash).await else {
                    continue;
                };
                if transfer.state == "downloading" {
                    core.queue_ed2k_download_attempt(transfer).await;
                }
            }
        }
    }
}

fn ed2k_nat_mappings(network: &Ed2kNetworkConfig) -> Vec<MappingSpec> {
    vec![
        MappingSpec {
            name: "ed2k_tcp".to_string(),
            local_addr: SocketAddr::new(IpAddr::V4(network.bind_ip), network.listen_port),
            protocol: TransportProtocol::Tcp,
            exposure: MappingExposure::Required,
            preferred_external_port: Some(network.listen_port),
        },
        MappingSpec {
            name: "kad_udp".to_string(),
            local_addr: network.kad_bind_addr,
            protocol: TransportProtocol::Udp,
            exposure: MappingExposure::Preferred,
            preferred_external_port: Some(network.kad_bind_addr.port()),
        },
    ]
}

fn parse_server_endpoint(endpoint: &str) -> Result<(String, u16)> {
    let Some((address, port)) = endpoint.rsplit_once(':') else {
        anyhow::bail!("server id must use address:port");
    };
    ensure!(
        !address.trim().is_empty(),
        "server id must use address:port"
    );
    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid server endpoint port in {endpoint}"))?;
    ensure!(port != 0, "port must be in the range 1..65535");
    Ok((address.to_string(), port))
}

fn upload_from_snapshot(
    entry: Ed2kUploadQueueSnapshotEntry,
    manifest: Option<&Ed2kResumeManifest>,
) -> Upload {
    let user_hash = entry.user_hash.map(hex::encode);
    let client_id = user_hash
        .clone()
        .unwrap_or_else(|| format!("{}:{}", entry.ip, entry.tcp_port));
    let requested_parts_total = manifest
        .map(|manifest| manifest.pieces.len() as u32)
        .unwrap_or_default();
    let requested_parts_obtained = manifest.map(upload_obtained_part_count).unwrap_or_default();
    let requested_parts_progress_text = if requested_parts_total == 0 {
        String::new()
    } else {
        format!("{requested_parts_obtained}/{requested_parts_total}")
    };
    let upload_state = upload_state_name(entry.phase).to_string();
    let waiting_queue = matches!(entry.phase, Ed2kUploadSessionPhaseSnapshot::Waiting);
    let uploading = matches!(
        entry.phase,
        Ed2kUploadSessionPhaseSnapshot::Granted | Ed2kUploadSessionPhaseSnapshot::Uploading
    );
    let score = entry.score.clamp(0, i128::from(u32::MAX)) as u32;
    let availability = if entry.friend_slot {
        "friendSlot"
    } else if uploading || waiting_queue {
        "available"
    } else {
        "unavailable"
    };
    let score_breakdown = UploadScoreBreakdown {
        availability: availability.to_string(),
        base_score: score,
        effective_score: score,
        core_score: entry.score as f64,
        effective_score_float: entry.score as f64,
        credit_ratio: entry.credit_score_permille as f64 / 1000.0,
        file_priority: entry.file_priority_score as i64,
        // The Rust scorer applies none of the master's modifiers.
        low_ratio_applied: false,
        low_ratio_bonus: 0,
        low_id_penalty_applied: false,
        low_id_divisor: 1,
        old_client_penalty_applied: false,
        cooldown_remaining_ms: 0,
    };
    Upload {
        client_id,
        user_name: format!("{}:{}", entry.ip, entry.tcp_port),
        user_hash,
        client_software: "unknown".to_string(),
        client_mod: String::new(),
        upload_state,
        upload_speed_ki_bps: entry.upload_speed_bytes_per_sec as f64 / 1024.0,
        uploaded_bytes: entry.uploaded_bytes,
        queue_session_uploaded: entry.uploaded_bytes,
        payload_buffered: 0,
        wait_time_ms: entry.wait_time_ms,
        wait_started_tick: 0,
        score: u64::from(score),
        score_breakdown: Some(score_breakdown),
        address: entry.ip.to_string(),
        port: entry.tcp_port,
        server_ip: String::new(),
        server_port: 0,
        low_id: entry.client_id.is_some_and(is_low_id_client_id),
        friend_slot: entry.friend_slot,
        uploading,
        waiting_queue,
        requested_file_hash: Some(entry.file_hash),
        requested_file_name: manifest.map(|manifest| manifest.canonical_name.clone()),
        requested_file_size_bytes: manifest.map(|manifest| manifest.file_size),
        requested_parts_obtained,
        requested_parts_total,
        requested_parts_progress_text,
        queue_rank: entry.queue_rank,
    }
}

fn upload_policy_metrics_from_capacity(
    capacity: Ed2kUploadQueueCapacitySnapshot,
) -> UploadPolicyMetrics {
    UploadPolicyMetrics {
        base_slots: capacity.base_slots,
        elastic_slots: capacity.elastic_slots,
        active_slots: capacity.active_slots,
        active_sessions: capacity.active_sessions,
        waiting_sessions: capacity.waiting_sessions,
        upload_rate_bytes_per_sec: capacity.upload_rate_bytes_per_sec,
        elastic_underfill: capacity.elastic_underfill,
    }
}

fn upload_state_name(phase: Ed2kUploadSessionPhaseSnapshot) -> &'static str {
    match phase {
        Ed2kUploadSessionPhaseSnapshot::Waiting => "queued",
        Ed2kUploadSessionPhaseSnapshot::Granted => "connecting",
        Ed2kUploadSessionPhaseSnapshot::Uploading => "uploading",
    }
}

fn upload_obtained_part_count(manifest: &Ed2kResumeManifest) -> u32 {
    if manifest.completed {
        return manifest.pieces.len() as u32;
    }
    manifest
        .pieces
        .iter()
        .filter(|piece| {
            piece.bytes_written >= upload_expected_piece_length(manifest, piece.piece_index)
        })
        .count() as u32
}

fn upload_expected_piece_length(manifest: &Ed2kResumeManifest, piece_index: u32) -> u64 {
    let start = u64::from(piece_index).saturating_mul(manifest.piece_size);
    if start >= manifest.file_size {
        return 0;
    }
    manifest
        .file_size
        .saturating_sub(start)
        .min(manifest.piece_size)
}

fn is_low_id_client_id(client_id: u32) -> bool {
    client_id != 0 && client_id < 0x0100_0000
}

fn is_retryable_direct_download_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|inner| inner.kind() == std::io::ErrorKind::ConnectionRefused)
    })
}

#[allow(clippy::cognitive_complexity)]
async fn run_ed2k_direct_downloads<DownloadFn, DownloadFuture>(
    options: DirectDownloadOptions,
    download_peer: DownloadFn,
) -> Result<DirectDownloadOutcome>
where
    DownloadFn: Fn(
            Ipv4Addr,
            Ed2kFoundSource,
            Ed2kHelloIdentity,
            Arc<Ed2kSecureIdent>,
            Arc<Ed2kTransferRuntime>,
            String,
            u64,
            Duration,
        ) -> DownloadFuture
        + Clone
        + Send
        + Sync
        + 'static,
    DownloadFuture: Future<Output = Result<Ed2kPeerDownloadOutcome>> + Send + 'static,
{
    let DirectDownloadOptions {
        bind_ip,
        hello_identity,
        secure_ident,
        transfer_runtime,
        file_hash_hex,
        file_name,
        file_size,
        sources,
        connect_timeout,
        max_parallel_download_peers,
    } = options;
    let max_parallel_download_peers = max_parallel_download_peers.max(1);
    let retry_deadline =
        if !sources.is_empty() && sources.iter().all(|source| source.ip.is_loopback()) {
            Some(tokio::time::Instant::now() + Duration::from_secs(360))
        } else {
            None
        };
    let retry_sources = sources;
    let mut retry_round = 0u32;
    let mut last_error: Option<anyhow::Error> = None;
    // Endpoints that detached onto UDP reask across all retry rounds; their leases
    // are kept (not released) so the next cycle does not re-TCP them.
    let mut detached_reask_endpoints: Vec<(Ipv4Addr, u16)> = Vec::new();

    loop {
        let mut accepted_incomplete_peers = 0u32;
        let mut retryable_error_seen = false;
        let mut pending_sources = VecDeque::from(retry_sources.clone());
        let mut active_downloads = JoinSet::new();
        let spawn_context = DirectDownloadSpawnContext {
            bind_ip,
            hello_identity,
            secure_ident: &secure_ident,
            transfer_runtime: &transfer_runtime,
            file_hash_hex: &file_hash_hex,
            file_name: &file_name,
            file_size,
            connect_timeout,
            retry_round,
            download_peer: &download_peer,
        };

        spawn_pending_ed2k_direct_downloads(
            &mut active_downloads,
            &mut pending_sources,
            &spawn_context,
            max_parallel_download_peers,
        );

        while let Some(joined) = active_downloads.join_next().await {
            let (peer_addr, source, result) =
                joined.context("ED2K direct download worker panicked")?;
            match result {
                Ok(Ed2kPeerDownloadOutcome::Completed) => {
                    let manifest = transfer_runtime.manifest(&file_hash_hex).await?;
                    tracing::info!(
                        "ED2K direct download peer completed file_hash={} peer={} manifest_completed={} verified_ranges={} file_size={}",
                        file_hash_hex,
                        peer_addr,
                        manifest.completed,
                        manifest.verified_ranges.len(),
                        manifest.file_size
                    );
                    if manifest.completed {
                        active_downloads.abort_all();
                        while active_downloads.join_next().await.is_some() {}
                        return Ok(DirectDownloadOutcome {
                            completed: true,
                            accepted_incomplete_peers,
                            last_error: last_error
                                .as_ref()
                                .map(|error| anyhow::anyhow!(error.to_string())),
                            detached_reask_endpoints: detached_reask_endpoints.clone(),
                        });
                    }
                }
                Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete) => {
                    accepted_incomplete_peers = accepted_incomplete_peers.saturating_add(1);
                    tracing::info!(
                        "ED2K direct download peer accepted incomplete file_hash={} peer={}",
                        file_hash_hex,
                        peer_addr
                    );
                }
                Ok(Ed2kPeerDownloadOutcome::QueuedDetachedForUdpReask) => {
                    // The source detached its TCP socket onto the UDP reask loop,
                    // which now keeps its queue slot warm and re-engages over TCP
                    // on UDP failure. Count it like an accepted-incomplete peer.
                    accepted_incomplete_peers = accepted_incomplete_peers.saturating_add(1);
                    detached_reask_endpoints.push(source_endpoint_key(&source));
                    tracing::info!(
                        "ED2K direct download peer detached to UDP reask file_hash={} peer={}",
                        file_hash_hex,
                        peer_addr
                    );
                }
                Err(error) => {
                    retryable_error_seen |= is_retryable_direct_download_error(&error);
                    tracing::warn!(
                        "ED2K direct download peer failed file_hash={} peer={}: {error}",
                        file_hash_hex,
                        peer_addr
                    );
                    last_error = Some(error);
                    if let Some(fallback_source) = plaintext_fallback_for_obfuscated_source(&source)
                    {
                        tracing::info!(
                            "ED2K direct download scheduling plaintext fallback file_hash={} peer={}:{}",
                            file_hash_hex,
                            source.ip,
                            source.tcp_port
                        );
                        pending_sources.push_front(fallback_source);
                    }
                }
            }

            spawn_pending_ed2k_direct_downloads(
                &mut active_downloads,
                &mut pending_sources,
                &spawn_context,
                max_parallel_download_peers,
            );
        }

        let outcome = DirectDownloadOutcome {
            completed: transfer_runtime.manifest(&file_hash_hex).await?.completed,
            accepted_incomplete_peers,
            last_error: last_error
                .as_ref()
                .map(|error| anyhow::anyhow!(error.to_string())),
            detached_reask_endpoints: detached_reask_endpoints.clone(),
        };
        if outcome.completed || outcome.accepted_incomplete_peers != 0 {
            return Ok(outcome);
        }

        let Some(deadline) = retry_deadline else {
            return Ok(outcome);
        };
        if !retryable_error_seen || tokio::time::Instant::now() >= deadline {
            return Ok(outcome);
        }

        retry_round = retry_round.saturating_add(1);
        tracing::info!(
            "ED2K direct download retrying loopback sources file_hash={} retry_round={}",
            file_hash_hex,
            retry_round
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

fn spawn_pending_ed2k_direct_downloads<DownloadFn, DownloadFuture>(
    active_downloads: &mut JoinSet<DirectDownloadJoin>,
    pending_sources: &mut VecDeque<Ed2kFoundSource>,
    context: &DirectDownloadSpawnContext<'_, DownloadFn>,
    max_parallel_download_peers: usize,
) where
    DownloadFn: Fn(
            Ipv4Addr,
            Ed2kFoundSource,
            Ed2kHelloIdentity,
            Arc<Ed2kSecureIdent>,
            Arc<Ed2kTransferRuntime>,
            String,
            u64,
            Duration,
        ) -> DownloadFuture
        + Clone
        + Send
        + Sync
        + 'static,
    DownloadFuture: Future<Output = Result<Ed2kPeerDownloadOutcome>> + Send + 'static,
{
    while active_downloads.len() < max_parallel_download_peers {
        let Some(source) = pending_sources.pop_front() else {
            break;
        };
        let transfer_runtime = Arc::clone(context.transfer_runtime);
        let secure_ident = Arc::clone(context.secure_ident);
        let download_peer = context.download_peer.clone();
        let file_name = context.file_name.to_string();
        let file_hash_hex = context.file_hash_hex.to_string();
        let peer_addr = SocketAddr::new(IpAddr::V4(source.ip), source.tcp_port);
        tracing::info!(
            "ED2K direct download attempt file_hash={} peer={} client_id={} obfuscated={} has_user_hash={} retry_round={}",
            file_hash_hex,
            peer_addr,
            source.client_id,
            source.obfuscated,
            source.user_hash.is_some(),
            context.retry_round
        );
        let bind_ip = context.bind_ip;
        let hello_identity = context.hello_identity;
        let file_size = context.file_size;
        let connect_timeout = context.connect_timeout;
        active_downloads.spawn(async move {
            let result = download_peer(
                bind_ip,
                source.clone(),
                hello_identity,
                secure_ident,
                transfer_runtime,
                file_name,
                file_size,
                connect_timeout,
            )
            .await;
            (peer_addr, source, result)
        });
    }
}

fn found_source_from_hint(file_hash: Ed2kHash, hint: &Ed2kSourceHint) -> Result<Ed2kFoundSource> {
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
    })
}

fn configured_server_attempts(config: &Ed2kConfig) -> usize {
    config
        .server_entries
        .len()
        .max(config.server_endpoints.len())
        .max(1)
}

fn exact_ed2k_hash_query_token(query: &str) -> Option<String> {
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

fn ed2k_keyword_server_attempts(config: &Ed2kConfig, query: &str) -> usize {
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
struct LearnedEd2kMetadata {
    canonical_name: Option<String>,
    file_size: Option<u64>,
}

impl LearnedEd2kMetadata {
    fn merge_missing_from(&mut self, other: Self) {
        if self.canonical_name.is_none() {
            self.canonical_name = other.canonical_name;
        }
        if self.file_size.is_none() {
            self.file_size = other.file_size;
        }
    }

    fn is_complete(&self) -> bool {
        self.canonical_name.is_some() && self.file_size.is_some()
    }

    fn is_empty(&self) -> bool {
        self.canonical_name.is_none() && self.file_size.is_none()
    }
}

fn normalized_optional_canonical_name(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn hash_only_ed2k_search_query(file_hash: Ed2kHash) -> String {
    format!("{ED2K_HASH_ONLY_QUERY_PREFIX}{file_hash}")
}

fn select_ed2k_keyword_metadata(
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

fn select_kad_keyword_metadata(
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

fn significant_keyword_words(query: &str) -> Vec<String> {
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

fn keyword_target(query: &str) -> NodeId {
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

fn sort_download_sources(sources: &mut [Ed2kFoundSource]) {
    sources.sort_by_key(|source| {
        (
            !source.is_direct_dialable(),
            source.user_hash.is_none(),
            source.obfuscation_options.is_none(),
        )
    });
}

fn source_endpoint_key(source: &Ed2kFoundSource) -> (Ipv4Addr, u16) {
    (source.ip, source.tcp_port)
}

fn direct_download_candidate_sources(
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

fn new_direct_ed2k_source_count(
    sources: &[Ed2kFoundSource],
    attempted_direct_endpoints: &HashSet<(Ipv4Addr, u16)>,
) -> usize {
    direct_download_candidate_sources(sources, attempted_direct_endpoints).len()
}

fn manifest_has_ed2k_transfer_progress(manifest: &Ed2kResumeManifest) -> bool {
    manifest.completed
        || manifest.md4_hashset_acquired
        || !manifest.verified_ranges.is_empty()
        || manifest.pieces.iter().any(|piece| piece.bytes_written != 0)
}

fn should_skip_no_progress_source_requery(
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

fn should_exclude_background_source_endpoint(
    has_background_search: bool,
    aggregated_source_count: usize,
) -> bool {
    has_background_search && aggregated_source_count != 0
}

fn should_adopt_hash_only_metadata_name(transfer: &Transfer) -> bool {
    let name = transfer.name.trim();
    name.is_empty() || name.eq_ignore_ascii_case(&transfer.hash)
}

fn ed2k_server_callback_route(
    source_server: Option<SocketAddr>,
    connected_server: Option<SocketAddr>,
) -> Ed2kServerCallbackRoute {
    match (source_server, connected_server) {
        (Some(source_server), Some(connected_server)) if source_server == connected_server => {
            Ed2kServerCallbackRoute::BackgroundSession
        }
        (Some(source_server), _) => Ed2kServerCallbackRoute::SourceServer(source_server),
        (None, _) => Ed2kServerCallbackRoute::BackgroundSession,
    }
}

fn should_query_kad_source_supplement(
    existing_source_count: usize,
    supplement_threshold: usize,
) -> bool {
    existing_source_count == 0 || existing_source_count <= supplement_threshold
}

fn kad_source_result_to_ed2k_found_source(result: SourceResult) -> Ed2kFoundSource {
    Ed2kFoundSource {
        file_hash: result.file_hash,
        ip: result.ip,
        tcp_port: result.tcp_port,
        client_id: u32::from(result.ip),
        low_id: false,
        obfuscated: result.obfuscation_options.is_some(),
        obfuscation_options: result.obfuscation_options,
        user_hash: Some(result.source_id.0),
        source_server: None,
    }
}

async fn collect_kad_ed2k_metadata(
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

    loop {
        tokio::select! {
            _ = &mut sleep => break,
            result = stream.next() => {
                let Some(result) = result else {
                    break;
                };
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
    (!learned.is_empty()).then_some(learned)
}

#[allow(clippy::cognitive_complexity)]
async fn collect_kad_ed2k_sources(
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
                        vec![kad_source_result_to_ed2k_found_source(result)],
                    );
                    if sources.len() >= ED2K_DOWNLOAD_KAD_SOURCE_CAP {
                        cancel.cancel();
                        tracing::info!(
                            "ED2K Kad source lookup reached cap file_hash={} attempts={} source_count={}",
                            file_hash,
                            attempts,
                            sources.len()
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
    sources
}

fn plaintext_fallback_for_obfuscated_source(source: &Ed2kFoundSource) -> Option<Ed2kFoundSource> {
    let options = source.obfuscation_options?;
    if options & ED2K_SOURCE_OBFUSCATION_REQUIRES_CRYPT != 0 {
        return None;
    }
    let mut fallback = source.clone();
    fallback.obfuscated = false;
    fallback.obfuscation_options = None;
    fallback.user_hash = None;
    Some(fallback)
}

fn merge_download_sources(target: &mut Vec<Ed2kFoundSource>, incoming: Vec<Ed2kFoundSource>) {
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

fn local_share_from_summary(
    summary: emulebb_ed2k::ed2k_transfer::Ed2kLocalIngestSummary,
) -> LocalShare {
    LocalShare {
        ed2k_link: format!(
            "ed2k://|file|{}|{}|{}|/",
            summary.canonical_name, summary.file_size, summary.file_hash
        ),
        hash: summary.file_hash,
        name: summary.canonical_name,
        size_bytes: summary.file_size,
        part_count: ed2k_part_count(summary.file_size),
        aich_root: summary.aich_root,
        transfer_dir: summary.transfer_dir,
        priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
    }
}

fn default_preferences() -> Preferences {
    Preferences {
        upload_limit_ki_bps: 1024,
        download_limit_ki_bps: 4096,
        max_connections: 500,
        max_connections_per_five_seconds: 20,
        max_sources_per_file: 400,
        upload_client_data_rate: 32,
        max_upload_slots: 8,
        upload_slot_elastic_percent: 80,
        queue_size: 5000,
        auto_connect: false,
        new_auto_up: true,
        new_auto_down: true,
        credit_system: true,
        safe_server_connect: true,
        network_kademlia: true,
        network_ed2k: true,
        download_auto_broadband_io: true,
    }
}

fn preferences_update_is_empty(update: &PreferencesUpdate) -> bool {
    update.upload_limit_ki_bps.is_none()
        && update.download_limit_ki_bps.is_none()
        && update.max_connections.is_none()
        && update.max_connections_per_five_seconds.is_none()
        && update.max_sources_per_file.is_none()
        && update.upload_client_data_rate.is_none()
        && update.max_upload_slots.is_none()
        && update.upload_slot_elastic_percent.is_none()
        && update.queue_size.is_none()
        && update.auto_connect.is_none()
        && update.new_auto_up.is_none()
        && update.new_auto_down.is_none()
        && update.credit_system.is_none()
        && update.safe_server_connect.is_none()
        && update.network_kademlia.is_none()
        && update.network_ed2k.is_none()
        && update.download_auto_broadband_io.is_none()
}

fn apply_preferences_update(
    preferences: &mut Preferences,
    update: PreferencesUpdate,
) -> Result<()> {
    if let Some(value) = update.upload_limit_ki_bps {
        ensure_finite_kibps(value, "uploadLimitKiBps")?;
        preferences.upload_limit_ki_bps = value;
    }
    if let Some(value) = update.download_limit_ki_bps {
        ensure_finite_kibps(value, "downloadLimitKiBps")?;
        preferences.download_limit_ki_bps = value;
    }
    if let Some(value) = update.max_connections {
        ensure_positive_u32(value, "maxConnections")?;
        preferences.max_connections = value;
    }
    if let Some(value) = update.max_connections_per_five_seconds {
        ensure_positive_u32(value, "maxConnectionsPerFiveSeconds")?;
        preferences.max_connections_per_five_seconds = value;
    }
    if let Some(value) = update.max_sources_per_file {
        ensure_positive_u32(value, "maxSourcesPerFile")?;
        preferences.max_sources_per_file = value;
    }
    if let Some(value) = update.upload_client_data_rate {
        ensure!(
            value > 0,
            "uploadClientDataRate must be an unsigned number in the range 1..4294967295"
        );
        preferences.upload_client_data_rate = value;
        preferences.max_upload_slots = derive_upload_slots(preferences.upload_limit_ki_bps, value);
    }
    if let Some(value) = update.max_upload_slots {
        ensure!(
            (1..=64).contains(&value),
            "maxUploadSlots must be an unsigned number in the range 1..64"
        );
        preferences.max_upload_slots = value;
    }
    if let Some(value) = update.upload_slot_elastic_percent {
        ensure!(
            value <= 100,
            "uploadSlotElasticPercent must be an unsigned number in the range 0..100"
        );
        preferences.upload_slot_elastic_percent = value;
    }
    if let Some(value) = update.queue_size {
        ensure!(
            (2000..=10000).contains(&value),
            "queueSize must be an unsigned number in the range 2000..10000"
        );
        preferences.queue_size = value;
    }
    if let Some(value) = update.auto_connect {
        preferences.auto_connect = value;
    }
    if let Some(value) = update.new_auto_up {
        preferences.new_auto_up = value;
    }
    if let Some(value) = update.new_auto_down {
        preferences.new_auto_down = value;
    }
    if let Some(value) = update.credit_system {
        preferences.credit_system = value;
    }
    if let Some(value) = update.safe_server_connect {
        preferences.safe_server_connect = value;
    }
    if let Some(value) = update.network_kademlia {
        preferences.network_kademlia = value;
    }
    if let Some(value) = update.network_ed2k {
        preferences.network_ed2k = value;
    }
    if let Some(value) = update.download_auto_broadband_io {
        preferences.download_auto_broadband_io = value;
    }
    Ok(())
}

fn ed2k_upload_queue_policy_from_preferences(
    base: Option<&Ed2kUploadQueuePolicyConfig>,
    preferences: &Preferences,
) -> Ed2kUploadQueuePolicyConfig {
    let mut policy = base.cloned().unwrap_or_default();
    policy.active_slots = preferences.max_upload_slots as usize;
    policy.elastic_percent = preferences.upload_slot_elastic_percent.min(100);
    policy.upload_limit_bytes_per_sec = u64::from(preferences.upload_limit_ki_bps) * 1024;
    policy.elastic_underfill_bytes_per_sec =
        u64::from(preferences.upload_client_data_rate.max(1)) * 1024;
    policy.elastic_underfill_secs = policy.elastic_underfill_secs.max(10);
    policy.waiting_capacity = preferences.queue_size as usize;
    policy
}

fn initial_ed2k_upload_queue_policy(
    base: Option<&Ed2kUploadQueuePolicyConfig>,
    has_persisted_preferences: bool,
    preferences: &Preferences,
) -> Ed2kUploadQueuePolicyConfig {
    if has_persisted_preferences || base.is_none() {
        ed2k_upload_queue_policy_from_preferences(base, preferences)
    } else {
        base.cloned().unwrap_or_default()
    }
}

fn ensure_finite_kibps(value: u32, name: &str) -> Result<()> {
    ensure!(
        value > 0 && value < u32::MAX,
        "{name} must be an unsigned number in the range 1..4294967294"
    );
    Ok(())
}

fn ensure_positive_u32(value: u32, name: &str) -> Result<()> {
    ensure!(
        value > 0 && value <= i32::MAX as u32,
        "{name} must be an unsigned number in the range 1..2147483647"
    );
    Ok(())
}

fn derive_upload_slots(upload_limit_ki_bps: u32, upload_client_data_rate: u32) -> u32 {
    upload_limit_ki_bps
        .div_ceil(upload_client_data_rate)
        .clamp(1, 64)
}

const PR_LOW: u32 = 0;
const PR_NORMAL: u32 = 1;
const PR_HIGH: u32 = 2;
const PR_VERYHIGH: u32 = 3;
const PR_VERYLOW: u32 = 4;
const ED2K_DOWNLOAD_KAD_SOURCE_CAP: usize = 64;
const ED2K_DOWNLOAD_KAD_SOURCE_TIMEOUT_FLOOR_SECS: u64 = 45;
const ED2K_DOWNLOAD_KAD_SOURCE_RETRY_DELAY_MS: u64 = 500;
const ED2K_DOWNLOAD_KAD_SOURCE_QUIET_DELAY_MS: u64 = 750;
const ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS: usize = 2;
const ED2K_DOWNLOAD_SOURCE_REQUERY_DELAY_SECS: u64 = 5;
const ED2K_DOWNLOAD_BACKGROUND_RETRY_SECS: u64 = 5;
const ED2K_SOURCE_OBFUSCATION_REQUIRES_CRYPT: u8 = 0x04;

fn default_categories() -> BTreeMap<u32, Category> {
    BTreeMap::from([(
        0,
        Category {
            id: 0,
            name: "All".to_string(),
            path: None,
            comment: String::new(),
            priority: PR_NORMAL,
            color: None,
        },
    )])
}

fn apply_category_create(category: &mut Category, request: CategoryCreate) -> Result<()> {
    category.name = normalize_category_name(Some(request.name))?;
    apply_category_path(category, request.path)?;
    if let Some(comment) = request.comment {
        category.comment = comment;
    }
    apply_category_color(category, request.color)?;
    if let Some(priority) = request.priority {
        category.priority = parse_category_priority(priority)?;
    }
    Ok(())
}

fn deserialize_nullable_string_field<'de, D>(
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

fn deserialize_nullable_u32_field<'de, D>(
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

fn apply_category_update(category: &mut Category, request: CategoryUpdate) -> Result<()> {
    if request.name.is_some() {
        category.name = normalize_category_name(request.name)?;
    }
    apply_category_path(category, request.path)?;
    if let Some(comment) = request.comment {
        category.comment = comment;
    }
    apply_category_color(category, request.color)?;
    if let Some(priority) = request.priority {
        category.priority = parse_category_priority(priority)?;
    }
    Ok(())
}

fn normalize_category_name(name: Option<String>) -> Result<String> {
    let name = name
        .ok_or_else(|| anyhow::anyhow!("name must be a non-empty string"))?
        .trim()
        .to_string();
    ensure!(!name.is_empty(), "name must not be empty");
    Ok(name)
}

fn apply_category_path(category: &mut Category, path: NullableStringField) -> Result<()> {
    category.path = match path {
        NullableStringField::Missing => return Ok(()),
        NullableStringField::Value(path) => {
            let path = path.trim();
            ensure!(!path.is_empty(), "path must not be empty");
            let canonical =
                fs::canonicalize(path).with_context(|| format!("failed to resolve {path}"))?;
            ensure!(canonical.is_dir(), "path is not a directory");
            Some(canonical.display().to_string())
        }
        NullableStringField::Null(()) => None,
    };
    Ok(())
}

fn apply_category_color(category: &mut Category, color: NullableU32Field) -> Result<()> {
    match color {
        NullableU32Field::Missing => {}
        NullableU32Field::Value(color) => {
            ensure!(color <= 0x00ff_ffff, "color must be null or an RGB integer");
            category.color = Some(color);
        }
        NullableU32Field::Null(()) => {
            category.color = None;
        }
    }
    Ok(())
}

fn parse_category_priority(priority: CategoryPriorityValue) -> Result<u32> {
    match priority {
        CategoryPriorityValue::Number(value) => Ok(value),
        CategoryPriorityValue::Name(value) => match value.trim().to_ascii_lowercase().as_str() {
            "verylow" => Ok(PR_VERYLOW),
            "low" => Ok(PR_LOW),
            "normal" => Ok(PR_NORMAL),
            "high" => Ok(PR_HIGH),
            "veryhigh" => Ok(PR_VERYHIGH),
            _ => anyhow::bail!("priority must be one of verylow, low, normal, high, veryhigh"),
        },
    }
}

fn normalize_user_hash(user_hash: &str) -> Result<String> {
    ensure!(
        user_hash.len() == 32
            && user_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "userHash must be a 32-character lowercase hex string"
    );
    Ok(user_hash.to_string())
}

fn normalize_friend_name(name: Option<&str>) -> Result<String> {
    let name = name.unwrap_or_default();
    ensure!(
        !name.chars().any(char::is_control),
        "name must be valid UTF-8 without control characters"
    );
    ensure!(
        name.encode_utf16().count() <= 128,
        "name must be at most 128 characters"
    );
    Ok(name.to_string())
}

fn ed2k_part_count(size_bytes: u64) -> u32 {
    if size_bytes == 0 {
        0
    } else {
        size_bytes.div_ceil(ED2K_PART_SIZE) as u32
    }
}

fn source_key(source: &Ed2kFoundSource) -> (Ipv4Addr, u16, Option<[u8; 16]>, Option<u8>) {
    (
        source.ip,
        source.tcp_port,
        source.user_hash,
        source.obfuscation_options,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourcePublishSettings {
    tcp_port: u16,
    obfuscation_enabled: bool,
}

fn emule_high_id_source_type(file_size: u64) -> u32 {
    if file_size > EMULE_LARGE_FILE_SIZE_THRESHOLD {
        4
    } else {
        1
    }
}

fn emule_kad_chunk_order(bytes: [u8; 16]) -> [u8; 16] {
    let mut ordered = [0u8; 16];
    for (dst, src) in ordered.chunks_exact_mut(4).zip(bytes.chunks_exact(4)) {
        dst.copy_from_slice(&[src[3], src[2], src[1], src[0]]);
    }
    ordered
}

fn source_publish_client_hash(ed2k_user_hash: [u8; 16]) -> NodeId {
    NodeId::from_bytes(emule_kad_chunk_order(ed2k_user_hash))
}

fn emule_source_encryption_options(obfuscation_enabled: bool) -> u8 {
    emule_connect_options(obfuscation_enabled)
}

fn build_source_publish_tags(
    bind_addr: SocketAddr,
    source_publish_settings: SourcePublishSettings,
    file_size: u64,
) -> Vec<Tag> {
    let mut tags = vec![
        Tag::new_short(
            tag_name::SOURCETYPE,
            TagValue::UInt(u64::from(emule_high_id_source_type(file_size))),
        ),
        Tag::new_short(
            tag_name::SOURCEPORT,
            TagValue::UInt(u64::from(source_publish_settings.tcp_port)),
        ),
    ];
    if let SocketAddr::V4(addr) = bind_addr {
        tags.push(Tag::new_short(
            tag_name::SOURCEIP,
            TagValue::U32(u32::from_be_bytes(addr.ip().octets())),
        ));
    }
    tags.push(Tag::new_short(
        tag_name::SOURCEUPORT,
        TagValue::U16(bind_addr.port()),
    ));
    tags.push(Tag::filesize(file_size));
    tags.push(Tag::new_short(
        tag_name::ENCRYPTION,
        TagValue::U8(emule_source_encryption_options(
            source_publish_settings.obfuscation_enabled,
        )),
    ));
    tags
}

fn ed2k_file_type_search_term(name: &str) -> Option<&'static str> {
    let extension = Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())?
        .to_ascii_lowercase();
    match extension.as_str() {
        "aac" | "aif" | "aiff" | "ape" | "flac" | "m4a" | "mp3" | "ogg" | "opus" | "wav"
        | "wma" => Some("Audio"),
        "avi" | "flv" | "m2ts" | "m4v" | "mkv" | "mov" | "mp4" | "mpeg" | "mpg" | "ogm" | "ts"
        | "vob" | "webm" | "wmv" => Some("Video"),
        "bmp" | "gif" | "jpeg" | "jpg" | "png" | "svg" | "tif" | "tiff" | "webp" => Some("Image"),
        "cbz" | "chm" | "doc" | "docx" | "epub" | "mobi" | "pdf" | "rtf" | "txt" => Some("Doc"),
        "emulecollection" => Some("EmuleCollection"),
        "7z" | "apk" | "appx" | "bin" | "deb" | "dmg" | "exe" | "iso" | "msi" | "rar" | "rpm"
        | "tar" | "zip" => Some("Pro"),
        _ => None,
    }
}

fn default_search_method() -> String {
    "automatic".to_string()
}

fn parse_ed2k_link(link: &str) -> Result<(String, String, u64)> {
    let parts = link
        .strip_prefix("ed2k://|file|")
        .and_then(|rest| rest.strip_suffix("|/"))
        .ok_or_else(|| anyhow::anyhow!("invalid ED2K link"))?
        .split('|')
        .collect::<Vec<_>>();
    anyhow::ensure!(parts.len() >= 3, "invalid ED2K file link");
    Ok((
        parts[2].to_ascii_lowercase(),
        parts[0].to_string(),
        parts[1].parse()?,
    ))
}

fn unique_runtime_dir(name: &str) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let path = rust_test_tmp_root().join(format!(
        "emulebb-rust-{name}-{}-{stamp}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create runtime dir");
    path
}

fn rust_test_tmp_root() -> std::path::PathBuf {
    std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT")
        .map(std::path::PathBuf::from)
        .map(|root| root.join("tmp").join("emulebb-rust-tests"))
        .unwrap_or_else(|| std::env::temp_dir().join("emulebb-rust-tests"))
}

#[cfg(test)]
mod tests {
    use emulebb_index::IndexedFile;
    use emulebb_kad_proto::{NodeId, Tag, TagValue};

    use super::*;

    fn test_network_config_with_store(
        transfer_root: &Path,
        kad_local_store: KadLocalStoreConfig,
        kad_snoop_queue: SnoopQueueConfig,
    ) -> Ed2kNetworkConfig {
        Ed2kNetworkConfig {
            bind_ip: Ipv4Addr::new(198, 51, 100, 10),
            kad_bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 4665),
            listen_port: 4662,
            user_hash: [0x44; 16],
            secure_ident: Arc::new(
                Ed2kSecureIdent::load_or_create(&transfer_root.join("secure-ident.der")).unwrap(),
            ),
            kad_local_store,
            kad_snoop_queue,
            kad_bootstrap_nodes: Vec::new(),
            kad_bootstrap_min_routing_contacts: 10,
            kad_publish_shared_files: true,
            kad_republish_interval_secs: 1_800,
            kad_publish_contact_fanout: 4,
            kad_hello_intro_interval_secs: 300,
            kad_hello_intro_fanout: 2,
            kad_udp_firewall_check_enabled: true,
            kad_udp_firewall_check_interval_secs: 600,
            kad_tcp_firewall_check_enabled: true,
            kad_tcp_firewall_check_interval_secs: 600,
            kad_buddy_enabled: true,
            nat_config: NatConfig::default(),
            config: Ed2kConfig::default(),
            vpn_guard: VpnGuardConfig::default(),
            vpn_interface_bound: false,
            ip_filter: IpFilter::default(),
        }
    }

    #[tokio::test]
    async fn kad_callback_req_relays_op_callback_down_held_buddy_socket() {
        use emulebb_ed2k::buddy_socket::BuddySocketRegistry;
        use tokio::sync::mpsc;

        let buddy_id = NodeId::from_bytes([0x77; 16]);
        let file_hash = Ed2kHash::from_bytes([0xC4; 16]);
        let requester_ip = Ipv4Addr::new(203, 0, 113, 9);
        let requester_tcp = 4662u16;
        let firewalled_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30)), 4662);

        let mut state = KadBuddyState::new();
        state
            .accept_incoming_buddy(
                false,
                IncomingBuddy {
                    client_hash: Ed2kHash::from_bytes([0x11; 16]),
                    buddy_id,
                    tcp_addr: firewalled_addr,
                    udp_addr: firewalled_addr,
                    registered_at: Utc::now(),
                },
            )
            .unwrap();
        let kad_buddy = Arc::new(Mutex::new(state));

        // Simulate the held inbound buddy session: attach a relay writer.
        let registry = BuddySocketRegistry::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(registry.attach_inbound(buddy_id, tx));

        // The callback requester (UDP source) wants the firewalled client; its
        // CALLBACK_REQ echoes the buddy check id (== registered buddy_id).
        let req = CallbackReq {
            buddy_id,
            file_hash,
            tcp_port: requester_tcp,
        };
        let from = SocketAddr::new(IpAddr::V4(requester_ip), 5000);

        handle_kad_callback_req(&kad_buddy, &registry, from, &req).await;

        // The exact OP_CALLBACK relay frame must be pushed down the held socket.
        let relayed = rx.try_recv().expect("relay frame delivered to held buddy socket");
        let expected =
            encode_kad_callback_relay_frame(buddy_id.0, &file_hash, requester_ip, requester_tcp);
        assert_eq!(relayed, expected);
    }

    #[tokio::test]
    async fn kad_callback_req_without_held_socket_does_not_relay() {
        use emulebb_ed2k::buddy_socket::BuddySocketRegistry;

        let buddy_id = NodeId::from_bytes([0x88; 16]);
        let firewalled_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31)), 4662);
        let mut state = KadBuddyState::new();
        state
            .accept_incoming_buddy(
                false,
                IncomingBuddy {
                    client_hash: Ed2kHash::from_bytes([0x22; 16]),
                    buddy_id,
                    tcp_addr: firewalled_addr,
                    udp_addr: firewalled_addr,
                    registered_at: Utc::now(),
                },
            )
            .unwrap();
        let kad_buddy = Arc::new(Mutex::new(state));
        // No inbound socket attached -> the matched callback cannot be relayed.
        let registry = BuddySocketRegistry::new();
        let req = CallbackReq {
            buddy_id,
            file_hash: Ed2kHash::from_bytes([0xC5; 16]),
            tcp_port: 4662,
        };
        let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 5000);
        // Must not panic and must not relay (no attached socket).
        handle_kad_callback_req(&kad_buddy, &registry, from, &req).await;
        assert!(!registry.has_inbound());
    }

    #[test]
    fn upload_queue_policy_uses_preferences_for_slot_and_queue_limits() {
        let mut preferences = default_preferences();
        preferences.max_upload_slots = 11;
        preferences.queue_size = 6_000;
        let base = Ed2kUploadQueuePolicyConfig {
            active_slots: 3,
            elastic_percent: 15,
            upload_limit_bytes_per_sec: 512 * 1024,
            elastic_underfill_bytes_per_sec: 16 * 1024,
            elastic_underfill_secs: 10,
            waiting_capacity: 512,
            waiting_timeout_secs: 44,
            granted_timeout_secs: 22,
            upload_timeout_secs: 88,
        };

        let policy = ed2k_upload_queue_policy_from_preferences(Some(&base), &preferences);

        assert_eq!(policy.active_slots, 11);
        assert_eq!(
            policy.elastic_percent,
            preferences.upload_slot_elastic_percent
        );
        assert_eq!(
            policy.upload_limit_bytes_per_sec,
            u64::from(preferences.upload_limit_ki_bps) * 1024
        );
        assert_eq!(
            policy.elastic_underfill_bytes_per_sec,
            u64::from(preferences.upload_client_data_rate) * 1024
        );
        assert_eq!(policy.waiting_capacity, 6_000);
        assert_eq!(policy.waiting_timeout_secs, 44);
        assert_eq!(policy.granted_timeout_secs, 22);
        assert_eq!(policy.upload_timeout_secs, 88);
    }

    #[test]
    fn initial_upload_queue_policy_preserves_config_for_fresh_profiles() {
        let preferences = default_preferences();
        let base = Ed2kUploadQueuePolicyConfig {
            active_slots: 3,
            elastic_percent: 15,
            upload_limit_bytes_per_sec: 512 * 1024,
            elastic_underfill_bytes_per_sec: 16 * 1024,
            elastic_underfill_secs: 10,
            waiting_capacity: 512,
            waiting_timeout_secs: 44,
            granted_timeout_secs: 22,
            upload_timeout_secs: 88,
        };

        let policy = initial_ed2k_upload_queue_policy(Some(&base), false, &preferences);

        assert_eq!(policy, base);
    }

    #[tokio::test]
    async fn persisted_preferences_configure_upload_queue_on_startup() {
        let transfer_root = unique_runtime_dir("emulebb-core-upload-queue-startup-preferences");
        let metadata = MetadataStore::open(transfer_root.join("metadata.sqlite")).unwrap();
        let mut preferences = default_preferences();
        preferences.max_upload_slots = 2;
        preferences.queue_size = 3_000;
        profile_state::persist_preferences(&metadata, &preferences).unwrap();
        let index = FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap();

        let core = EmulebbCore::new("test", index, transfer_root.join("transfers")).unwrap();
        let policy = core.ed2k_transfers.upload_queue_policy_snapshot().await;

        assert_eq!(policy.active_slots, 2);
        assert_eq!(policy.waiting_capacity, 3_000);
    }

    #[tokio::test]
    async fn preferences_update_reconfigures_live_upload_queue() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();

        let preferences = core
            .update_preferences(PreferencesUpdate {
                max_upload_slots: Some(4),
                queue_size: Some(4_000),
                ..PreferencesUpdate::default()
            })
            .await
            .unwrap();
        let policy = core.ed2k_transfers.upload_queue_policy_snapshot().await;

        assert_eq!(preferences.max_upload_slots, 4);
        assert_eq!(preferences.queue_size, 4_000);
        assert_eq!(policy.active_slots, 4);
        assert_eq!(policy.waiting_capacity, 4_000);
    }

    #[test]
    fn ed2k_nat_mappings_follow_configured_listener_addresses() {
        let transfer_root = unique_runtime_dir("emulebb-core-nat-mappings");
        let network = test_network_config_with_store(
            &transfer_root,
            KadLocalStoreConfig::default(),
            SnoopQueueConfig::default(),
        );

        let mappings = ed2k_nat_mappings(&network);

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].name, "ed2k_tcp");
        assert_eq!(
            mappings[0].local_addr,
            "198.51.100.10:4662".parse().unwrap()
        );
        assert_eq!(mappings[0].protocol, TransportProtocol::Tcp);
        assert_eq!(mappings[0].exposure, MappingExposure::Required);
        assert_eq!(mappings[1].name, "kad_udp");
        assert_eq!(
            mappings[1].local_addr,
            "198.51.100.10:4665".parse().unwrap()
        );
        assert_eq!(mappings[1].protocol, TransportProtocol::Udp);
        assert_eq!(mappings[1].exposure, MappingExposure::Preferred);
    }

    #[test]
    fn kad_firewalled_response_ip_uses_sender_ipv4_bytes() {
        let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 4672);

        assert_eq!(
            firewalled_response_ip_for_sender(from),
            Some(u32::from_be_bytes([203, 0, 113, 9]))
        );
    }

    #[tokio::test]
    async fn network_config_initializes_kad_local_store() {
        let transfer_root = unique_runtime_dir("emulebb-core-kad-local-store-config");
        let expected = KadLocalStoreConfig {
            enabled: true,
            keyword_ttl: Duration::from_secs(11),
            source_ttl: Duration::from_secs(22),
            notes_ttl: Duration::from_secs(33),
            keyword_capacity: 44,
            source_capacity: 55,
            notes_capacity: 66,
            source_per_file_capacity: 77,
            notes_per_file_capacity: 88,
        };
        let core = EmulebbCore::new_with_network(
            "test",
            FileIndex::in_memory().unwrap(),
            &transfer_root,
            Some(test_network_config_with_store(
                &transfer_root,
                expected,
                SnoopQueueConfig::default(),
            )),
        )
        .unwrap();

        assert_eq!(
            core.kad_local_store_config_for_tests().await,
            Some(expected)
        );
    }

    #[tokio::test]
    async fn network_config_hydrates_kad_publish_cache() {
        let transfer_root = unique_runtime_dir("emulebb-core-kad-publish-cache-hydrate");
        let metadata_store = MetadataStore::in_memory().unwrap();
        let target = NodeId::from_bytes([1; 16]);
        let file_hash = Ed2kHash::from_bytes([2; 16]);
        let snapshot = emulebb_index::KadPublishCacheSnapshot {
            keyword_publishes: vec![emulebb_index::KadKeywordPublishSnapshot {
                observed_at: Utc::now(),
                target,
                file_hash,
                tags: vec![
                    Tag::filename("Sample Publish Cache.bin"),
                    Tag::filesize(123),
                ],
                load: None,
            }],
            source_publishes: Vec::new(),
            note_publishes: Vec::new(),
        };
        metadata_store
            .replace_kad_publish_cache(&metadata_from_publish_snapshot(&snapshot).unwrap())
            .unwrap();

        let core = EmulebbCore::new_with_network(
            "test",
            FileIndex::from_metadata_store(metadata_store),
            &transfer_root,
            Some(test_network_config_with_store(
                &transfer_root,
                KadLocalStoreConfig {
                    enabled: true,
                    ..KadLocalStoreConfig::default()
                },
                SnoopQueueConfig::default(),
            )),
        )
        .unwrap();

        let hydrated = core.kad_publish_cache_snapshot_for_tests().await.unwrap();
        assert_eq!(hydrated.keyword_publishes.len(), 1);
        assert_eq!(hydrated.keyword_publishes[0].file_hash, file_hash);
    }

    #[tokio::test]
    async fn network_config_initializes_kad_snoop_queue() {
        let transfer_root = unique_runtime_dir("emulebb-core-kad-snoop-queue-config");
        let expected = SnoopQueueConfig {
            dedup_window_secs: 7,
            general_max_queries_per_600s: 8,
            general_drain_cooldown_secs: 9,
            source_max_queries_per_600s: 10,
            source_drain_cooldown_secs: 11,
            source_stop_after_results: 12,
        };
        let core = EmulebbCore::new_with_network(
            "test",
            FileIndex::in_memory().unwrap(),
            &transfer_root,
            Some(test_network_config_with_store(
                &transfer_root,
                KadLocalStoreConfig::default(),
                expected.clone(),
            )),
        )
        .unwrap();

        assert_eq!(
            core.kad_snoop_queue_config_for_tests().await,
            Some(expected)
        );
        assert_eq!(
            core.kad_snoop_queue_snapshot_for_tests().await,
            Some(vec![])
        );
    }

    #[tokio::test]
    async fn status_reports_live_dht_runtime_kad_contacts() {
        let transfer_root = unique_runtime_dir("emulebb-core-kad-status-runtime");
        let core =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
        let (search_handle, _search_inbox) = new_ed2k_server_search_channel(1);
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some("0.0.0.0:0".parse().unwrap()),
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let dht_task = dht.start();

        *core.ed2k_runtime.lock().await = Some(Ed2kRuntime {
            search_handle,
            server_state: Arc::new(RwLock::new(Ed2kServerState::default())),
            dht,
            kad_bootstrap_configured: true,
            nat: Arc::new(NatManager::default()),
            shutdown: Arc::clone(&shutdown),
            kad_firewall_recheck: None,
            tasks: vec![dht_task],
        });

        let status = core.status().await;

        assert!(status.kad.running);
        assert!(!status.kad.connected);
        assert_eq!(status.kad.contact_count, Some(0));
        assert_eq!(status.kad.bootstrapping, Some(true));
        shutdown.store(true, Ordering::SeqCst);
        let _ = core.disconnect_ed2k().await;
    }

    #[test]
    fn kad_snoop_entry_builders_preserve_passive_search_shapes() {
        let target = NodeId::from_bytes([
            0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x0c, 0x0b, 0x0a, 0x09, 0x10, 0x0f,
            0x0e, 0x0d,
        ]);
        let now = Utc::now();

        let keyword = build_keyword_snoop_entry(
            &SearchKeyReq {
                target,
                start_position: 0x8002,
                restrictive_payload: vec![0xaa, 0xbb],
            },
            now,
        );
        let source = build_source_snoop_entry(
            &SearchSourceReq {
                target,
                start_position: 0x0011,
                size: 123_456,
            },
            now,
        );
        let notes = build_notes_snoop_entry(
            &SearchNotesReq {
                target,
                size: 654_321,
            },
            now,
        );

        assert_eq!(
            keyword.logical_key(),
            "keyword:0102030405060708090a0b0c0d0e0f10:8002:aabb"
        );
        assert_eq!(keyword.restrictive_payload_hex(), Some("aabb"));
        assert_eq!(
            source.logical_key(),
            "source:0102030405060708090a0b0c0d0e0f10:0011:123456"
        );
        assert_eq!(
            notes.logical_key(),
            "notes:0102030405060708090a0b0c0d0e0f10:654321"
        );
    }

    #[test]
    fn configured_kad_bootstrap_nodes_text_keeps_only_valid_ipv4_nodes() {
        let nodes = vec![
            "192.0.2.20:4665".to_string(),
            " ".to_string(),
            "[2001:db8::1]:4665".to_string(),
            "not-an-address".to_string(),
            "192.0.2.21:4666".to_string(),
        ];

        assert_eq!(
            configured_kad_bootstrap_nodes_text(&nodes).as_deref(),
            Some("192.0.2.20:4665\n192.0.2.21:4666")
        );
        assert_eq!(
            configured_kad_bootstrap_nodes_text(&["bad".to_string()]),
            None
        );
    }

    #[test]
    fn source_publish_tags_match_oracle_plaintext_shape() {
        let tags = build_source_publish_tags(
            "10.54.206.206:41000".parse().unwrap(),
            SourcePublishSettings {
                tcp_port: 41001,
                obfuscation_enabled: false,
            },
            2_097_152,
        );

        assert_eq!(
            tags,
            vec![
                Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
                Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(41001)),
                Tag::new_short(tag_name::SOURCEIP, TagValue::U32(0x0A36_CECE)),
                Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
                Tag::filesize(2_097_152),
                Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0)),
            ]
        );
    }

    #[test]
    fn source_publish_tags_set_obfuscated_encryption_bits() {
        let tags = build_source_publish_tags(
            "10.54.206.206:41000".parse().unwrap(),
            SourcePublishSettings {
                tcp_port: 41001,
                obfuscation_enabled: true,
            },
            2_097_152,
        );

        assert_eq!(
            tags.last(),
            Some(&Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(3)))
        );
    }

    #[test]
    fn kad_hello_request_tags_advertise_source_udp_port_when_verified_open() {
        let tags = build_kad_hello_request_tags(41000, true, false, false, false);

        assert_eq!(
            tags,
            vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))]
        );
    }

    #[test]
    fn kad_hello_request_tags_emit_source_port_and_misc_bits_additively() {
        // Oracle SendMyDetails writes SOURCEUPORT (intern port) AND KADMISCOPTIONS
        // (firewalled/ack) together, not one or the other.
        let tags = build_kad_hello_request_tags(41000, true, true, false, true);

        assert_eq!(
            tags,
            vec![
                Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
                Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05)),
            ]
        );
    }

    #[test]
    fn kad_req_masks_type_to_low_five_bits_and_rejects_zero() {
        // Oracle: byType &= 0x1F; throw on 0.
        assert_eq!(kad_req_masked_count(0x00), None);
        assert_eq!(kad_req_masked_count(0x20), None); // high bits only -> 0
        assert_eq!(kad_req_masked_count(0x02), Some(2));
        assert_eq!(kad_req_masked_count(0xE2), Some(2)); // high bits masked off
        assert_eq!(kad_req_masked_count(0x1F), Some(0x1F));
    }

    #[test]
    fn hello_res_ack_requested_only_when_added_and_key_unverified() {
        // Oracle: SendMyDetails(..., bAddedOrUpdated && !bValidReceiverKey).
        assert!(should_request_hello_res_ack(true, false));
        assert!(!should_request_hello_res_ack(true, true));
        assert!(!should_request_hello_res_ack(false, false));
        assert!(!should_request_hello_res_ack(false, true));
    }

    #[test]
    fn kad_hello_request_tags_emit_only_misc_bits_when_on_extern_port() {
        // When we advertise our extern Kad port (GetUseExternKadPort), the oracle
        // omits SOURCEUPORT but still emits KADMISCOPTIONS while firewalled.
        let tags = build_kad_hello_request_tags(41000, false, true, false, true);

        assert_eq!(
            tags,
            vec![Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05))]
        );
    }

    #[test]
    fn kad_hello_response_tags_include_source_udp_port_and_misc_bits() {
        let tags = build_kad_hello_response_tags(41000, true, true, true);

        assert_eq!(
            tags,
            vec![
                Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
                Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x07)),
            ]
        );
    }

    #[test]
    fn source_publish_identity_uses_emule_kad_chunk_order() {
        let user_hash = [
            0xB4, 0x22, 0xCF, 0x1A, 0x44, 0x0E, 0x71, 0x6B, 0xD2, 0xE1, 0xDD, 0x6E, 0x77, 0x21,
            0x6F, 0xE4,
        ];

        let publisher_id = source_publish_client_hash(user_hash);

        assert_eq!(
            publisher_id.0,
            [
                0x1A, 0xCF, 0x22, 0xB4, 0x6B, 0x71, 0x0E, 0x44, 0x6E, 0xDD, 0xE1, 0xD2, 0xE4, 0x6F,
                0x21, 0x77,
            ]
        );
        assert_eq!(publisher_id.to_be_bytes(), user_hash);
    }

    #[test]
    fn kad_publishable_manifests_skip_incomplete_and_removed_rows() {
        let mut shared = Ed2kResumeManifest::new(&new_transfer_job(
            Ed2kHash::from_bytes([0x11; 16]),
            "shared.bin".to_string(),
            128,
        ));
        shared.completed = true;
        let incomplete = Ed2kResumeManifest::new(&new_transfer_job(
            Ed2kHash::from_bytes([0x22; 16]),
            "incomplete.bin".to_string(),
            128,
        ));
        let mut removed = Ed2kResumeManifest::new(&new_transfer_job(
            Ed2kHash::from_bytes([0x33; 16]),
            "removed.bin".to_string(),
            128,
        ));
        removed.completed = true;
        removed.transfer_row_removed = true;

        let publishable = kad_publishable_manifests(vec![incomplete, removed, shared.clone()]);

        assert_eq!(publishable, vec![shared]);
    }

    #[test]
    fn ed2k_file_type_search_term_matches_oracle_families() {
        assert_eq!(
            ed2k_file_type_search_term("ubuntu-linux-oracle-sample.iso"),
            Some("Pro")
        );
        assert_eq!(ed2k_file_type_search_term("album.flac"), Some("Audio"));
        assert_eq!(ed2k_file_type_search_term("movie.mkv"), Some("Video"));
        assert_eq!(ed2k_file_type_search_term("scan.png"), Some("Image"));
        assert_eq!(ed2k_file_type_search_term("manual.pdf"), Some("Doc"));
        assert_eq!(
            ed2k_file_type_search_term("bundle.emulecollection"),
            Some("EmuleCollection")
        );
        assert_eq!(ed2k_file_type_search_term("README"), None);
    }

    #[test]
    fn passive_replay_family_preference_follows_deepest_queue_with_stable_tie_breaks() {
        assert_eq!(
            preferred_passive_replay_families(SnoopQueueFamilyCounts {
                keyword: 1,
                source: 4,
                notes: 2,
            }),
            [
                PassiveReplayFamily::Source,
                PassiveReplayFamily::Notes,
                PassiveReplayFamily::Keyword,
            ]
        );
        assert_eq!(
            preferred_passive_replay_families(SnoopQueueFamilyCounts {
                keyword: 2,
                source: 2,
                notes: 2,
            }),
            [
                PassiveReplayFamily::Keyword,
                PassiveReplayFamily::Source,
                PassiveReplayFamily::Notes,
            ]
        );
    }

    #[tokio::test]
    async fn passive_keyword_result_indexes_searchable_file_metadata() {
        let index = Arc::new(Mutex::new(FileIndex::in_memory().unwrap()));
        index_passive_keyword_result(
            &index,
            &KadSearchResult {
                hash: Ed2kHash::from_bytes([0x31; 16]),
                names: vec!["Passive Replay Result.iso".to_string(), "   ".to_string()],
                size: Some(4096),
                source_count: Some(7),
                tags: vec![],
            },
        )
        .await;

        let results = index.lock().await.search("passive replay", 10).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ed2k_hash, "31313131313131313131313131313131");
        assert_eq!(results[0].size_bytes, 4096);
        assert_eq!(results[0].availability_score, 7);
    }

    #[tokio::test]
    async fn passive_source_results_are_remembered_for_existing_transfer() {
        let transfer_root = unique_runtime_dir("emulebb-core-passive-source-memory");
        let transfer_runtime =
            Arc::new(Ed2kTransferRuntime::load_or_create(&transfer_root).unwrap());
        let file_hash = Ed2kHash::from_bytes([0x41; 16]);
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "passive-source-target.bin".to_string(),
                4096,
            ))
            .await
            .unwrap();

        remember_passive_source_results(
            &transfer_runtime,
            &[SourceResult {
                file_hash,
                source_id: Ed2kHash::from_bytes([0x52; 16]),
                ip: Ipv4Addr::new(198, 51, 100, 22),
                tcp_port: 4662,
                udp_port: 4672,
                obfuscation_options: Some(0x03),
            }],
        )
        .await;

        let manifest = transfer_runtime
            .manifest(&file_hash.to_string())
            .await
            .unwrap();

        assert_eq!(manifest.sources.len(), 1);
        assert_eq!(manifest.sources[0].ip, "198.51.100.22");
        assert_eq!(manifest.sources[0].tcp_port, 4662);
        assert_eq!(
            manifest.sources[0].user_hash.as_deref(),
            Some("52525252525252525252525252525252")
        );
    }

    #[tokio::test]
    async fn passive_note_results_update_empty_existing_transfer_metadata() {
        let transfer_root = unique_runtime_dir("emulebb-core-passive-note-memory");
        let transfer_runtime =
            Arc::new(Ed2kTransferRuntime::load_or_create(&transfer_root).unwrap());
        let file_hash = Ed2kHash::from_bytes([0x42; 16]);
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "passive-note-target.bin".to_string(),
                4096,
            ))
            .await
            .unwrap();

        remember_passive_note_results(
            &transfer_runtime,
            &[KadNoteResult {
                file_hash,
                source_id: Ed2kHash::from_bytes([0x53; 16]),
                rating: Some(4),
                comment: Some("clean release".to_string()),
                source_tags: vec![],
            }],
        )
        .await;

        let manifest = transfer_runtime
            .manifest(&file_hash.to_string())
            .await
            .unwrap();

        assert_eq!(manifest.comment, "clean release");
        assert_eq!(manifest.rating, 4);
    }

    #[tokio::test]
    async fn passive_note_results_do_not_replace_local_transfer_metadata() {
        let transfer_root = unique_runtime_dir("emulebb-core-passive-note-preserve");
        let transfer_runtime =
            Arc::new(Ed2kTransferRuntime::load_or_create(&transfer_root).unwrap());
        let file_hash = Ed2kHash::from_bytes([0x43; 16]);
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "passive-note-preserve.bin".to_string(),
                4096,
            ))
            .await
            .unwrap();
        transfer_runtime
            .update_shared_file_metadata(&file_hash.to_string(), None, Some(("local note", 2)))
            .await
            .unwrap();

        remember_passive_note_results(
            &transfer_runtime,
            &[KadNoteResult {
                file_hash,
                source_id: Ed2kHash::from_bytes([0x54; 16]),
                rating: Some(5),
                comment: Some("remote note".to_string()),
                source_tags: vec![],
            }],
        )
        .await;

        let manifest = transfer_runtime
            .manifest(&file_hash.to_string())
            .await
            .unwrap();

        assert_eq!(manifest.comment, "local note");
        assert_eq!(manifest.rating, 2);
    }

    #[test]
    fn split_stock_search_responses_keeps_pages_under_fragment_limit() {
        let sender_id = NodeId::from_bytes([1; 16]);
        let target = NodeId::from_bytes([2; 16]);
        let results = (0..12)
            .map(|index| SearchResultEntry {
                entry_id: Ed2kHash::from_bytes([index; 16]),
                tags: vec![Tag::filename(format!(
                    "ubuntu-linux-parity-result-{index:02}-{}",
                    "x".repeat(220)
                ))],
            })
            .collect::<Vec<_>>();
        let response = SearchRes {
            sender_id,
            target,
            results: results.clone(),
        };

        let pages = split_stock_search_responses(response, 1420);

        assert!(pages.len() > 1);
        assert_eq!(
            pages.iter().map(|page| page.results.len()).sum::<usize>(),
            results.len()
        );
        assert!(
            pages
                .iter()
                .all(|page| { KadPacket::SearchRes(page.clone()).encode().unwrap().len() <= 1420 })
        );
        assert_eq!(
            pages
                .into_iter()
                .flat_map(|page| page.results)
                .map(|result| result.entry_id)
                .collect::<Vec<_>>(),
            results
                .into_iter()
                .map(|result| result.entry_id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn split_stock_search_responses_keeps_single_oversized_result_like_stock() {
        let sender_id = NodeId::from_bytes([1; 16]);
        let target = NodeId::from_bytes([2; 16]);
        let response = SearchRes {
            sender_id,
            target,
            results: vec![SearchResultEntry {
                entry_id: Ed2kHash::from_bytes([3; 16]),
                tags: vec![Tag::filename("x".repeat(1600))],
            }],
        };

        let pages = split_stock_search_responses(response, 1420);

        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].results.len(), 1);
        assert!(
            KadPacket::SearchRes(pages[0].clone())
                .encode()
                .unwrap()
                .len()
                > 1420
        );
    }

    #[tokio::test]
    async fn search_uses_local_index() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        core.index_file(IndexedFile {
            ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Local.Indexed.File.iso".to_string(),
            size_bytes: 2048,
            content_type: "iso".to_string(),
            availability_score: 3,
        })
        .await
        .unwrap();

        let search = core
            .create_search(SearchCreate {
                query: "indexed file".to_string(),
                method: "automatic".to_string(),
                r#type: String::new(),
                ..Default::default()
            })
            .await
            .unwrap();
        // Local index results are present immediately while the search starts
        // "running"; it flips to "completed" once the background pass finishes.
        assert_eq!(search.status, "running");
        assert_eq!(search.results.len(), 1);
        let mut completed = search;
        for _ in 0..100 {
            if completed.status == "completed" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            completed = core.search(&completed.id).await.unwrap();
        }
        assert_eq!(completed.status, "completed");
        assert_eq!(completed.results.len(), 1);
    }

    #[tokio::test]
    async fn import_server_met_bytes_adds_servers() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        // version 0x0E + count 1 + (ip 45.82.80.155, port 5687, 0 tags)
        let mut met = vec![0x0Eu8];
        met.extend_from_slice(&1u32.to_le_bytes());
        met.extend_from_slice(&[45, 82, 80, 155]);
        met.extend_from_slice(&5687u16.to_le_bytes());
        met.extend_from_slice(&0u32.to_le_bytes());

        let added = core.import_server_met_bytes(&met).await.unwrap();
        assert_eq!(added, 1);
        let servers = core.servers().await;
        assert!(
            servers
                .iter()
                .any(|server| server.address == "45.82.80.155" && server.port == 5687)
        );
    }

    #[test]
    fn exact_ed2k_hash_query_token_extracts_hash_only_queries() {
        let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

        assert_eq!(
            exact_ed2k_hash_query_token(&format!("ed2k::{exact_hash}")),
            Some(exact_hash.clone())
        );
        assert_eq!(
            exact_ed2k_hash_query_token(&exact_hash.to_ascii_uppercase()),
            Some(exact_hash)
        );
        assert_eq!(exact_ed2k_hash_query_token("ed2k::torino train"), None);
    }

    #[test]
    fn significant_words_ignore_short_tokens() {
        assert_eq!(
            significant_keyword_words("A torino x train"),
            vec!["torino".to_string(), "train".to_string()]
        );
    }

    #[test]
    fn keyword_target_is_stable() {
        assert_eq!(
            hex::encode(keyword_target("Torino Train").0),
            "b2bc3aa39f375069e7c27eb83ce6baf3"
        );
    }

    #[test]
    fn keyword_target_uses_hash_token_for_exact_ed2k_hash_queries() {
        let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

        assert_eq!(
            keyword_target(&format!("ed2k::{exact_hash}")),
            keyword_target(&exact_hash.to_ascii_uppercase())
        );
    }

    #[test]
    fn exact_ed2k_hash_queries_use_configured_server_budget() {
        let mut config = Ed2kConfig {
            server_endpoints: vec![
                "192.0.2.1:4661".to_string(),
                "192.0.2.2:4661".to_string(),
                "192.0.2.3:4661".to_string(),
                "192.0.2.4:4661".to_string(),
                "192.0.2.5:4661".to_string(),
            ],
            keyword_server_attempt_budget: 2,
            exact_hash_keyword_server_attempt_budget: 4,
            ..Ed2kConfig::default()
        };
        let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

        assert_eq!(
            ed2k_keyword_server_attempts(&config, &format!("ed2k::{exact_hash}")),
            4
        );
        assert_eq!(ed2k_keyword_server_attempts(&config, "ubuntu linux"), 2);

        config.exact_hash_keyword_server_attempt_budget = 99;
        assert_eq!(
            ed2k_keyword_server_attempts(&config, &exact_hash.to_ascii_uppercase()),
            5
        );
    }

    #[test]
    fn select_ed2k_keyword_metadata_prefers_exact_hash_with_size_and_name() {
        let exact_hash = Ed2kHash::from_bytes([0x44; 16]);
        let other_hash = Ed2kHash::from_bytes([0xAA; 16]);
        let metadata = select_ed2k_keyword_metadata(
            &[
                Ed2kSearchFile {
                    file_hash: exact_hash,
                    file_name: Some(String::new()),
                    file_size: Some(0),
                    file_type: None,
                    source_count: Some(100),
                },
                Ed2kSearchFile {
                    file_hash: other_hash,
                    file_name: Some("wrong.bin".to_string()),
                    file_size: Some(123),
                    file_type: None,
                    source_count: Some(5),
                },
                Ed2kSearchFile {
                    file_hash: exact_hash,
                    file_name: Some("resolved.bin".to_string()),
                    file_size: Some(4_294_967_299),
                    file_type: Some("Pro".to_string()),
                    source_count: Some(12),
                },
            ],
            exact_hash,
        )
        .unwrap();

        assert_eq!(metadata.canonical_name.as_deref(), Some("resolved.bin"));
        assert_eq!(metadata.file_size, Some(4_294_967_299));
    }

    #[test]
    fn kad_search_result_exposes_exact_hash_metadata() {
        let exact_hash = Ed2kHash::from_bytes([0x44; 16]);
        let metadata = select_kad_keyword_metadata(
            &KadSearchResult {
                hash: exact_hash,
                names: vec!["resolved.bin".to_string()],
                size: Some(5_000),
                source_count: Some(3),
                tags: Vec::new(),
            },
            exact_hash,
        )
        .unwrap();

        assert_eq!(metadata.canonical_name.as_deref(), Some("resolved.bin"));
        assert_eq!(metadata.file_size, Some(5_000));
    }

    #[tokio::test]
    async fn download_search_result_creates_transfer() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        core.index_file(IndexedFile {
            ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Download.Me.bin".to_string(),
            size_bytes: 4096,
            content_type: "archive".to_string(),
            availability_score: 1,
        })
        .await
        .unwrap();
        let search = core
            .create_search(SearchCreate {
                query: "download me".to_string(),
                method: "automatic".to_string(),
                r#type: String::new(),
                ..Default::default()
            })
            .await
            .unwrap();

        let transfer = core
            .download_search_result(
                &search.id,
                "00112233445566778899aabbccddeeff",
                SearchResultDownloadCreate::default(),
            )
            .await
            .unwrap()
            .unwrap();
        // A non-paused download starts immediately (eMule/aMule parity).
        assert_eq!(transfer.state, "downloading");
    }

    #[tokio::test]
    async fn create_transfer_uses_canonical_link_and_paused_state() {
        let runtime_dir = unique_runtime_dir("emulebb-core-paused-transfer-create");
        let transfer_root = runtime_dir.join("transfers");
        let metadata_path = runtime_dir.join("metadata.sqlite");
        let core = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap();

        let transfer = core
            .create_transfer(TransferCreate {
                link: Some(
                    "ed2k://|file|Paused.Create.bin|4096|00112233445566778899aabbccddeeff|/"
                        .to_string(),
                ),
                links: None,
                category_id: None,
                category_name: None,
                paused: Some(true),
            })
            .await
            .unwrap();

        assert_eq!(transfer.state, "paused");
        let reloaded = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap();
        assert_eq!(
            reloaded
                .transfer("00112233445566778899aabbccddeeff")
                .await
                .unwrap()
                .state,
            "paused"
        );
    }

    #[test]
    fn transfer_create_rejects_legacy_ed2k_link_field() {
        let error = serde_json::from_str::<TransferCreate>(
            r#"{"ed2kLink":"ed2k://|file|Legacy.bin|1|00112233445566778899aabbccddeeff|/"}"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("unknown field `ed2kLink`"));
    }

    #[tokio::test]
    async fn delete_transfer_files_removes_manifest_and_transfer_row() {
        let runtime_dir = unique_runtime_dir("emulebb-core-delete-transfer-files");
        let transfer_root = runtime_dir.join("transfers");
        let core =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
        let transfer = core
            .create_transfer(TransferCreate {
                link: Some(
                    "ed2k://|file|Delete.Me.bin|4096|00112233445566778899aabbccddeeff|/"
                        .to_string(),
                ),
                links: None,
                category_id: None,
                category_name: None,
                paused: None,
            })
            .await
            .unwrap();
        let transfer_dir = transfer_root.join(&transfer.hash);
        assert!(transfer_dir.is_dir());

        let deleted = core
            .delete_transfer_files(&transfer.hash)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(deleted.hash, transfer.hash);
        assert!(!transfer_dir.exists());
        assert!(core.transfer(&transfer.hash).await.is_none());
    }

    #[tokio::test]
    async fn delete_completed_transfer_row_preserves_files_and_survives_restart() {
        let runtime_dir = unique_runtime_dir("emulebb-core-delete-completed-transfer-row");
        let transfer_root = runtime_dir.join("transfers");
        let metadata_path = runtime_dir.join("metadata.sqlite");
        let payload_path = runtime_dir.join("Completed.Row.bin");
        std::fs::write(&payload_path, b"completed row removal payload").unwrap();
        let core = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap();
        let share = core
            .share_local_file(LocalShareCreate {
                path: payload_path.display().to_string(),
                name: Some("Completed.Row.bin".to_string()),
            })
            .await
            .unwrap();
        let transfer_dir = std::path::Path::new(&share.transfer_dir);
        assert!(transfer_dir.is_dir());
        assert!(core.transfer(&share.hash).await.is_some());

        let deleted = core
            .delete_completed_transfer_row(&share.hash)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(deleted.hash, share.hash);
        assert!(transfer_dir.is_dir());
        assert!(core.transfer(&share.hash).await.is_none());
        assert!(
            core.shares()
                .await
                .iter()
                .any(|entry| entry.hash == share.hash)
        );

        let reloaded = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap();
        assert!(reloaded.transfer(&share.hash).await.is_none());
        assert!(reloaded.transfers().await.is_empty());
        assert!(
            reloaded
                .shares()
                .await
                .iter()
                .any(|entry| entry.hash == share.hash
                    && std::path::Path::new(&entry.transfer_dir).is_dir())
        );

        let restored = reloaded
            .create_transfer(TransferCreate {
                link: Some(share.ed2k_link.clone()),
                links: None,
                category_id: None,
                category_name: None,
                paused: None,
            })
            .await
            .unwrap();
        assert_eq!(restored.hash, share.hash);
        assert!(reloaded.transfer(&share.hash).await.is_some());
    }

    #[tokio::test]
    async fn delete_completed_transfer_row_rejects_incomplete_transfer() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        let transfer = core
            .create_transfer(TransferCreate {
                link: Some(
                    "ed2k://|file|Incomplete.Row.bin|4096|00112233445566778899aabbccddeeff|/"
                        .to_string(),
                ),
                links: None,
                category_id: None,
                category_name: None,
                paused: None,
            })
            .await
            .unwrap();

        let error = core
            .delete_completed_transfer_row(&transfer.hash)
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("only completed transfers can be removed without deleting files")
        );
        assert!(core.transfer(&transfer.hash).await.is_some());
    }

    #[tokio::test]
    async fn stopped_transfer_cannot_be_resumed() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        let transfer = core
            .create_transfer(TransferCreate {
                link: Some(
                    "ed2k://|file|Stopped.bin|4096|00112233445566778899aabbccddeeff|/".to_string(),
                ),
                links: None,
                category_id: None,
                category_name: None,
                paused: None,
            })
            .await
            .unwrap();
        let stopped_transfer = core.stop_transfer(&transfer.hash).await.unwrap().unwrap();
        // Master parity: stopped is reported as the `paused` state + stopped flag.
        assert_eq!(stopped_transfer.state, "paused");
        assert!(stopped_transfer.stopped);

        let error = core.resume_transfer(&transfer.hash).await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("stopped transfer cannot be resumed")
        );
    }

    #[tokio::test]
    async fn stopped_transfer_state_survives_restart() {
        let runtime_dir = unique_runtime_dir("emulebb-core-stopped-transfer");
        let transfer_root = runtime_dir.join("transfers");
        let metadata_path = runtime_dir.join("metadata.sqlite");
        let core = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap();
        let transfer = core
            .create_transfer(TransferCreate {
                link: Some(
                    "ed2k://|file|Stopped.Restart.bin|4096|00112233445566778899aabbccddeeff|/"
                        .to_string(),
                ),
                links: None,
                category_id: None,
                category_name: None,
                paused: None,
            })
            .await
            .unwrap();
        core.stop_transfer(&transfer.hash).await.unwrap().unwrap();

        let reloaded = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap();
        let reloaded_transfer = reloaded.transfer(&transfer.hash).await.unwrap();

        // Master parity: a stopped transfer reports the `paused` state plus a
        // separate `stopped` flag (not a distinct `stopped` state token).
        assert_eq!(reloaded_transfer.state, "paused");
        assert!(reloaded_transfer.stopped);
        let error = reloaded.resume_transfer(&transfer.hash).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("stopped transfer cannot be resumed")
        );
    }

    #[tokio::test]
    async fn transfers_reload_from_persisted_manifests() {
        let runtime_dir = unique_runtime_dir("emulebb-core-persisted-manifests");
        let transfer_root = runtime_dir.join("transfers");
        let metadata_path = runtime_dir.join("metadata.sqlite");
        let payload_path = runtime_dir.join("Shared.Payload.bin");
        let payload = b"persisted transfer payload";
        std::fs::write(&payload_path, payload).unwrap();
        let core = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap();
        let share = core
            .share_local_file(LocalShareCreate {
                path: payload_path.display().to_string(),
                name: Some("Shared.Payload.bin".to_string()),
            })
            .await
            .unwrap();

        let reloaded = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap();
        let transfers = reloaded.transfers().await;

        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].hash, share.hash);
        assert_eq!(transfers[0].state, "completed");
        assert_eq!(transfers[0].completed_bytes, payload.len() as u64);
        assert_eq!(transfers[0].progress, 1.0);
        assert!(!transfers[0].path.is_empty());
        assert_eq!(std::fs::read(&transfers[0].path).unwrap(), payload);
    }

    async fn completed_ed2k_transfer_runtime(
        test_name: &str,
    ) -> (
        Arc<Ed2kTransferRuntime>,
        Arc<Ed2kSecureIdent>,
        String,
        String,
        u64,
    ) {
        let runtime_dir = unique_runtime_dir(test_name);
        let payload_path = runtime_dir.join("fixture.bin");
        let payload = b"completed direct download scheduler payload".repeat(64);
        std::fs::write(&payload_path, &payload).unwrap();
        let transfer_runtime =
            Arc::new(Ed2kTransferRuntime::load_or_create(&runtime_dir.join("transfers")).unwrap());
        let summary = transfer_runtime
            .ingest_local_file(&payload_path, "fixture.bin")
            .await
            .unwrap();
        let secure_ident = Arc::new(
            Ed2kSecureIdent::load_or_create(&runtime_dir.join("secure-ident.der")).unwrap(),
        );
        (
            transfer_runtime,
            secure_ident,
            summary.file_hash,
            summary.canonical_name,
            summary.file_size,
        )
    }

    fn direct_test_source(file_hash: Ed2kHash, ip: Ipv4Addr, tcp_port: u16) -> Ed2kFoundSource {
        Ed2kFoundSource {
            file_hash,
            ip,
            tcp_port,
            client_id: u32::from_be_bytes(ip.octets()),
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
        }
    }

    fn direct_download_options(
        transfer_runtime: Arc<Ed2kTransferRuntime>,
        secure_ident: Arc<Ed2kSecureIdent>,
        file_hash_hex: String,
        file_name: String,
        file_size: u64,
        sources: Vec<Ed2kFoundSource>,
    ) -> DirectDownloadOptions {
        DirectDownloadOptions {
            bind_ip: Ipv4Addr::new(192, 0, 2, 10),
            hello_identity: Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            secure_ident,
            transfer_runtime,
            file_hash_hex,
            file_name,
            file_size,
            sources,
            connect_timeout: Duration::from_secs(1),
            max_parallel_download_peers: 1,
        }
    }

    #[tokio::test]
    async fn direct_download_scheduler_retries_other_peer_after_failure() {
        let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size) =
            completed_ed2k_transfer_runtime("emulebb-core-direct-download-retry").await;
        let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let outcome = run_ed2k_direct_downloads(
            direct_download_options(
                transfer_runtime,
                secure_ident,
                file_hash_hex,
                file_name,
                file_size,
                vec![
                    direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001),
                    direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 11), 41002),
                ],
            ),
            {
                let attempts = Arc::clone(&attempts);
                move |_bind_ip,
                      source,
                      _hello_identity,
                      _secure_ident,
                      _transfer_runtime,
                      _file_name,
                      _file_size,
                      _connect_timeout| {
                    let attempts = Arc::clone(&attempts);
                    async move {
                        attempts.lock().await.push(source.tcp_port);
                        if source.tcp_port == 41001 {
                            anyhow::bail!("simulated first peer failure");
                        }
                        Ok(Ed2kPeerDownloadOutcome::Completed)
                    }
                }
            },
        )
        .await
        .unwrap();

        assert!(outcome.completed);
        assert_eq!(outcome.accepted_incomplete_peers, 0);
        assert!(outcome.last_error.is_some());
        assert_eq!(*attempts.lock().await, vec![41001, 41002]);
    }

    #[tokio::test]
    async fn direct_download_scheduler_retries_loopback_peer_after_connection_refused() {
        let runtime_dir = unique_runtime_dir("emulebb-core-loopback-refused-retry");
        let transfer_runtime =
            Arc::new(Ed2kTransferRuntime::load_or_create(&runtime_dir.join("transfers")).unwrap());
        let secure_ident = Arc::new(
            Ed2kSecureIdent::load_or_create(&runtime_dir.join("secure-ident.der")).unwrap(),
        );
        let payload = Arc::new(b"captured small file payload".repeat(32));
        let file_name = "captured.epub".to_string();
        let payload_path = runtime_dir.join("payload.bin");
        std::fs::write(&payload_path, payload.as_slice()).unwrap();
        let hash_runtime =
            Ed2kTransferRuntime::load_or_create(&runtime_dir.join("hash-transfers")).unwrap();
        let summary = hash_runtime
            .ingest_local_file(&payload_path, &file_name)
            .await
            .unwrap();
        let file_hash: Ed2kHash = summary.file_hash.parse().unwrap();
        let file_hash_hex = summary.file_hash;
        let file_size = summary.file_size;
        transfer_runtime
            .ensure_job(&new_transfer_job(file_hash, file_name.clone(), file_size))
            .await
            .unwrap();
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let success_after_attempt = 3usize;
        let outcome = run_ed2k_direct_downloads(
            direct_download_options(
                transfer_runtime,
                secure_ident,
                file_hash_hex.clone(),
                file_name,
                file_size,
                vec![direct_test_source(file_hash, Ipv4Addr::LOCALHOST, 41001)],
            ),
            {
                let attempts = Arc::clone(&attempts);
                let payload = Arc::clone(&payload);
                let file_hash_hex = file_hash_hex.clone();
                move |_bind_ip,
                      source,
                      _hello_identity,
                      _secure_ident,
                      transfer_runtime,
                      _file_name,
                      _file_size,
                      _connect_timeout| {
                    let attempts = Arc::clone(&attempts);
                    let payload = Arc::clone(&payload);
                    let file_hash_hex = file_hash_hex.clone();
                    async move {
                        attempts.lock().await.push(source.tcp_port);
                        if attempts.lock().await.len() < success_after_attempt {
                            return Err(anyhow::Error::new(std::io::Error::from(
                                std::io::ErrorKind::ConnectionRefused,
                            )));
                        }
                        transfer_runtime
                            .store_md4_hashset(&file_hash_hex, Vec::new())
                            .await?;
                        transfer_runtime
                            .store_piece_data(&file_hash_hex, 0, payload.as_slice())
                            .await?;
                        Ok(Ed2kPeerDownloadOutcome::Completed)
                    }
                }
            },
        )
        .await
        .unwrap();

        assert!(outcome.completed);
        assert_eq!(outcome.accepted_incomplete_peers, 0);
        assert!(outcome.last_error.is_some());
        assert_eq!(*attempts.lock().await, vec![41001, 41001, 41001]);
    }

    #[tokio::test]
    async fn direct_download_scheduler_tracks_accepted_incomplete_peer() {
        let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size) =
            completed_ed2k_transfer_runtime("emulebb-core-direct-download-incomplete").await;
        let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let outcome = run_ed2k_direct_downloads(
            direct_download_options(
                transfer_runtime,
                secure_ident,
                file_hash_hex,
                file_name,
                file_size,
                vec![
                    direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001),
                    direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 11), 41002),
                ],
            ),
            {
                let attempts = Arc::clone(&attempts);
                move |_bind_ip,
                      source,
                      _hello_identity,
                      _secure_ident,
                      _transfer_runtime,
                      _file_name,
                      _file_size,
                      _connect_timeout| {
                    let attempts = Arc::clone(&attempts);
                    async move {
                        attempts.lock().await.push(source.tcp_port);
                        if source.tcp_port == 41001 {
                            return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                        }
                        Ok(Ed2kPeerDownloadOutcome::Completed)
                    }
                }
            },
        )
        .await
        .unwrap();

        assert!(outcome.completed);
        assert_eq!(outcome.accepted_incomplete_peers, 1);
        assert!(outcome.last_error.is_none());
        assert_eq!(*attempts.lock().await, vec![41001, 41002]);
    }

    #[tokio::test]
    async fn direct_download_scheduler_tries_plaintext_after_optional_obfuscated_failure() {
        let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size) =
            completed_ed2k_transfer_runtime("emulebb-core-direct-download-plaintext-fallback")
                .await;
        let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let mut source = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
        source.obfuscated = true;
        source.obfuscation_options = Some(0x03);
        source.user_hash = Some([0x22; 16]);
        let outcome = run_ed2k_direct_downloads(
            direct_download_options(
                transfer_runtime,
                secure_ident,
                file_hash_hex,
                file_name,
                file_size,
                vec![source],
            ),
            {
                let attempts = Arc::clone(&attempts);
                move |_bind_ip,
                      source,
                      _hello_identity,
                      _secure_ident,
                      _transfer_runtime,
                      _file_name,
                      _file_size,
                      _connect_timeout| {
                    let attempts = Arc::clone(&attempts);
                    async move {
                        attempts.lock().await.push((
                            source.tcp_port,
                            source.obfuscated,
                            source.user_hash.is_some(),
                        ));
                        if source.obfuscated {
                            anyhow::bail!("simulated obfuscated peer close");
                        }
                        Ok(Ed2kPeerDownloadOutcome::Completed)
                    }
                }
            },
        )
        .await
        .unwrap();

        assert!(outcome.completed);
        assert_eq!(
            *attempts.lock().await,
            vec![(41001, true, true), (41001, false, false)]
        );
    }

    #[test]
    fn plaintext_fallback_preserves_crypt_required_sources() {
        let file_hash = Ed2kHash::from_bytes([0x33; 16]);
        let mut source = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
        source.obfuscated = true;
        source.obfuscation_options = Some(0x07);
        source.user_hash = Some([0x22; 16]);

        assert!(plaintext_fallback_for_obfuscated_source(&source).is_none());
    }

    #[test]
    fn direct_download_candidates_deduplicate_same_endpoint_in_one_round() {
        let file_hash = Ed2kHash::from_bytes([0x45; 16]);
        let mut obfuscated = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
        obfuscated.obfuscated = true;
        obfuscated.obfuscation_options = Some(0x03);
        obfuscated.user_hash = Some([0x11; 16]);
        let plaintext = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);

        let candidates =
            direct_download_candidate_sources(&[obfuscated.clone(), plaintext], &HashSet::new());

        assert_eq!(candidates, vec![obfuscated]);
    }

    #[test]
    fn direct_download_candidates_skip_attempted_endpoint_family() {
        let file_hash = Ed2kHash::from_bytes([0x47; 16]);
        let mut attempted_endpoints = HashSet::new();
        attempted_endpoints.insert((Ipv4Addr::new(192, 0, 2, 10), 41001));
        let mut obfuscated = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
        obfuscated.obfuscated = true;
        obfuscated.obfuscation_options = Some(0x03);
        obfuscated.user_hash = Some([0x11; 16]);
        let next_endpoint = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 11), 41002);

        let candidates = direct_download_candidate_sources(
            &[
                obfuscated,
                direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001),
                next_endpoint.clone(),
            ],
            &attempted_endpoints,
        );

        assert_eq!(candidates, vec![next_endpoint]);
    }

    #[tokio::test]
    async fn direct_download_source_leases_defer_peer_to_better_file_candidate() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        let lower_hash = Ed2kHash::from_bytes([0x48; 16]).to_string();
        let higher_hash = Ed2kHash::from_bytes([0x49; 16]).to_string();
        let source = direct_test_source(
            Ed2kHash::from_bytes([0x48; 16]),
            Ipv4Addr::new(192, 0, 2, 12),
            41003,
        );
        {
            let mut state = core.state.lock().await;
            state
                .download_source_registry
                .add_candidate(DownloadSourceCandidate {
                    file_hash: lower_hash.clone(),
                    file_priority: 1,
                    needed_parts: 8,
                    rare_parts: 0,
                    source: source.clone(),
                });
            state
                .download_source_registry
                .add_candidate(DownloadSourceCandidate {
                    file_hash: higher_hash.clone(),
                    file_priority: 9,
                    needed_parts: 1,
                    rare_parts: 0,
                    source: source.clone(),
                });
        }

        let (lower_sources, lower_deferred) = core
            .acquire_direct_download_source_leases(&lower_hash, std::slice::from_ref(&source))
            .await;
        let (higher_sources, higher_deferred) = core
            .acquire_direct_download_source_leases(&higher_hash, std::slice::from_ref(&source))
            .await;

        assert!(lower_sources.is_empty());
        assert_eq!(lower_deferred, 1);
        assert_eq!(higher_sources, vec![source.clone()]);
        assert_eq!(higher_deferred, 0);
        core.release_direct_download_source_leases(&[source_endpoint_key(&source)])
            .await;
    }

    #[test]
    fn source_requery_skip_waits_for_one_refresh_round_without_progress() {
        assert!(!should_skip_no_progress_source_requery(true, false, 0, 0));
        assert!(should_skip_no_progress_source_requery(true, false, 0, 1));
        assert!(!should_skip_no_progress_source_requery(true, true, 0, 1));
        assert!(!should_skip_no_progress_source_requery(true, false, 1, 1));
        assert!(!should_skip_no_progress_source_requery(false, false, 0, 1));
    }

    #[test]
    fn zero_source_background_lookup_keeps_connected_server_eligible() {
        assert!(!should_exclude_background_source_endpoint(false, 0));
        assert!(!should_exclude_background_source_endpoint(true, 0));
        assert!(should_exclude_background_source_endpoint(true, 1));
    }

    #[test]
    fn callback_route_reuses_background_session_for_connected_server() {
        let connected_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 4661));
        let other_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 4661));

        assert_eq!(
            ed2k_server_callback_route(Some(connected_server), Some(connected_server)),
            Ed2kServerCallbackRoute::BackgroundSession
        );
        assert_eq!(
            ed2k_server_callback_route(Some(other_server), Some(connected_server)),
            Ed2kServerCallbackRoute::SourceServer(other_server)
        );
        assert_eq!(
            ed2k_server_callback_route(None, Some(connected_server)),
            Ed2kServerCallbackRoute::BackgroundSession
        );
    }

    #[test]
    fn manifest_progress_includes_hashset_and_partial_piece_bytes() {
        let file_hash = Ed2kHash::from_bytes([0x48; 16]);
        let job = new_transfer_job(file_hash, "partial.bin".to_string(), 4096);
        let mut manifest = Ed2kResumeManifest::new(&job);
        assert!(!manifest_has_ed2k_transfer_progress(&manifest));

        manifest.md4_hashset_acquired = true;
        assert!(manifest_has_ed2k_transfer_progress(&manifest));
        manifest.md4_hashset_acquired = false;

        manifest.pieces[0].bytes_written = 512;
        assert!(manifest_has_ed2k_transfer_progress(&manifest));
    }

    #[test]
    fn kad_source_supplement_runs_for_empty_or_scarce_server_sources() {
        assert!(should_query_kad_source_supplement(0, 2));
        assert!(should_query_kad_source_supplement(1, 2));
        assert!(should_query_kad_source_supplement(2, 2));
        assert!(!should_query_kad_source_supplement(3, 2));
    }

    #[test]
    fn kad_source_result_maps_to_direct_ed2k_source() {
        let file_hash = Ed2kHash::from_bytes([0x49; 16]);
        let source_id = Ed2kHash::from_bytes([0x4a; 16]);
        let source = kad_source_result_to_ed2k_found_source(SourceResult {
            file_hash,
            source_id,
            ip: Ipv4Addr::new(192, 0, 2, 55),
            tcp_port: 4662,
            udp_port: 4672,
            obfuscation_options: Some(0x03),
        });

        assert_eq!(source.file_hash, file_hash);
        assert_eq!(source.ip, Ipv4Addr::new(192, 0, 2, 55));
        assert_eq!(source.tcp_port, 4662);
        assert_eq!(source.client_id, u32::from(Ipv4Addr::new(192, 0, 2, 55)));
        assert!(!source.low_id);
        assert!(source.obfuscated);
        assert_eq!(source.obfuscation_options, Some(0x03));
        assert_eq!(source.user_hash, Some(source_id.0));
        assert_eq!(source.source_server, None);
    }

    #[test]
    fn merge_download_sources_preserves_later_server_provenance() {
        let file_hash = Ed2kHash::from_bytes([0x46; 16]);
        let source_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 4661));
        let mut sources = vec![direct_test_source(
            file_hash,
            Ipv4Addr::new(192, 0, 2, 10),
            41001,
        )];
        let mut sourced = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
        sourced.source_server = Some(source_server);

        merge_download_sources(&mut sources, vec![sourced]);

        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].source_server, Some(source_server));
    }

    #[test]
    fn remembered_source_hint_becomes_direct_dial_source() {
        let file_hash: Ed2kHash = "00112233445566778899aabbccddeeff".parse().unwrap();
        let source = found_source_from_hint(
            file_hash,
            &Ed2kSourceHint {
                ip: "192.0.2.10".to_string(),
                tcp_port: 4662,
                user_hash: Some("0102030405060708090a0b0c0d0e0f10".to_string()),
            },
        )
        .unwrap();

        assert_eq!(source.file_hash, file_hash);
        assert_eq!(source.ip, "192.0.2.10".parse::<Ipv4Addr>().unwrap());
        assert_eq!(source.tcp_port, 4662);
        assert!(source.is_direct_dialable());
        assert!(source.obfuscated);
        assert_eq!(
            source.user_hash,
            Some([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        );
    }
}
