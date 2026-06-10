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
    MappingExposure, MappingSpec, NatConfig, NatManager, NatManagerBuilder, TransportProtocol,
    config::Ed2kConfig,
    ed2k_server::{
        Ed2kCallbackRequestOptions, Ed2kFoundSource, Ed2kKeywordSearchOptions, Ed2kSearchFile,
        Ed2kServerLoopOptions, Ed2kServerSearchHandle, Ed2kServerState, Ed2kSourceSearchOptions,
        Ed2kUdpSourceSearchOptions, new_ed2k_server_search_channel,
        publish_shared_catalog_via_background_session, request_callback_on_server,
        request_callback_via_background_session, run_ed2k_server_loop, search_keyword_servers,
        search_keyword_via_background_session, search_source_servers, search_source_udp_servers,
        search_source_via_background_session,
    },
    ed2k_tcp::{
        Ed2kHelloIdentity, Ed2kListenerOptions, Ed2kPeerDownloadOptions, Ed2kPeerDownloadOutcome,
        Ed2kSecureIdent, download_file_from_peer, emule_connect_options, run_ed2k_listener,
    },
    ed2k_transfer::{
        ED2K_PART_SIZE, Ed2kCallbackIntent, Ed2kResumeManifest, Ed2kSourceHint,
        Ed2kTransferRuntime, Ed2kUploadQueueSnapshotEntry, Ed2kUploadSessionPhaseSnapshot,
        new_transfer_job,
    },
    kad_firewall::KadFirewallState,
};
use emulebb_index::{
    FileIndex, IndexedFile, KadLocalStore, KadLocalStoreConfig, ScheduledSnoopRequest, SnoopEntry,
    SnoopQueue, SnoopQueueConfig, SnoopQueueFamilyCounts,
};
use emulebb_kad_dht::{
    DhtConfig, DhtNode, NoteResult as KadNoteResult, ReceivedKadPacket, RpcWorkClass,
    SearchResult as KadSearchResult, SourceResult,
};
use emulebb_kad_proto::{
    Ed2kHash, KAD_VERSION, KadPacket, PublishRes, SearchKeyReq, SearchNotesReq, SearchRes,
    SearchResultEntry, SearchSourceReq, constants::K, packet::ContactEntry,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
    task::{JoinHandle, JoinSet},
};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchCreate {
    pub query: String,
    #[serde(default = "default_search_method")]
    pub method: String,
    #[serde(default)]
    pub r#type: String,
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
pub struct SharedDirectoryRoot {
    pub path: String,
    pub recursive: bool,
    pub monitor_owned: bool,
    pub shareable: bool,
    pub accessible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedDirectories {
    pub roots: Vec<SharedDirectoryRoot>,
    pub items: Vec<SharedDirectoryRoot>,
    pub monitor_owned: Vec<String>,
    pub hashing_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharedDirectoriesUpdate {
    pub roots: Vec<SharedDirectoryRootUpdate>,
    pub confirm_replace_roots: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SharedDirectoryRootUpdate {
    Path(String),
    Object {
        path: String,
        #[serde(default)]
        recursive: bool,
    },
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
    pub download_speed_bytes_per_sec: u64,
    pub ed2k_link: String,
    pub priority: String,
    pub category_id: u32,
    pub category_name: String,
}

/// One remembered ED2K peer source for a transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSource {
    pub client_id: String,
    pub hash: String,
    pub ip: String,
    pub tcp_port: u16,
    pub port: u16,
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
    pub banned: bool,
    pub status: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_rank: Option<u16>,
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
    pub nat_config: NatConfig,
    pub config: Ed2kConfig,
}

const LOCAL_KEYWORD_SEARCH_RESPONSE_LIMIT: usize = 300;
const LOCAL_SOURCE_SEARCH_RESPONSE_LIMIT: usize = 300;
const LOCAL_NOTES_SEARCH_RESPONSE_LIMIT: usize = 150;
const LOCAL_SEARCH_RESPONSE_MAX_PACKET_BYTES: usize = 1420;
const PASSIVE_GENERAL_CRAWL_SECS: u64 = 45;
const PASSIVE_SOURCE_CRAWL_SECS: u64 = 15;
const PASSIVE_KEYWORD_RESULT_TARGET: usize = 10;
const PASSIVE_NOTES_RESULT_TARGET: usize = 3;

type DirectDownloadJoin = (SocketAddr, Ed2kFoundSource, Result<Ed2kPeerDownloadOutcome>);

#[derive(Debug)]
struct DirectDownloadOutcome {
    completed: bool,
    accepted_incomplete_peers: u32,
    last_error: Option<anyhow::Error>,
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
    tasks: Vec<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct EmulebbCore {
    started_at: Instant,
    version: String,
    index: Arc<Mutex<FileIndex>>,
    ed2k_transfers: Arc<Ed2kTransferRuntime>,
    transfer_root: PathBuf,
    ed2k_network: Option<Ed2kNetworkConfig>,
    kad_local_store: Option<Arc<Mutex<KadLocalStore>>>,
    kad_snoop_queue: Option<Arc<Mutex<SnoopQueue>>>,
    ed2k_runtime: Arc<Mutex<Option<Ed2kRuntime>>>,
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
        let ed2k_transfers = Ed2kTransferRuntime::load_or_create(&transfer_root)?;
        let kad_local_store = ed2k_network
            .as_ref()
            .map(|network| Arc::new(Mutex::new(KadLocalStore::new(network.kad_local_store))));
        let kad_snoop_queue = ed2k_network
            .as_ref()
            .map(|network| Arc::new(Mutex::new(SnoopQueue::new(network.kad_snoop_queue.clone()))));
        Ok(Self {
            started_at: Instant::now(),
            version: version.into(),
            index: Arc::new(Mutex::new(index)),
            ed2k_transfers: Arc::new(ed2k_transfers),
            transfer_root,
            ed2k_network,
            kad_local_store,
            kad_snoop_queue,
            ed2k_runtime: Arc::new(Mutex::new(None)),
            state: Arc::new(Mutex::new(CoreState {
                searches: HashMap::new(),
                transfers: HashMap::new(),
                preferences: default_preferences(),
                categories: default_categories(),
                next_category_id: 1,
                friends: BTreeMap::new(),
                servers: HashMap::new(),
                server_overrides: HashMap::new(),
                disabled_servers: HashSet::new(),
                banned_source_clients: HashSet::new(),
                active_download_attempts: HashSet::new(),
                shared_directories: Vec::new(),
                unshared_hashes: HashSet::new(),
                kad_running: false,
            })),
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
        let mut state = self.state.lock().await;
        apply_preferences_update(&mut state.preferences, request)?;
        Ok(state.preferences.clone())
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
        validate_url_import(url)?;
        Ok(false)
    }

    pub async fn import_server_met_url(&self, url: &str) -> Result<bool> {
        validate_url_import(url)?;
        Ok(false)
    }

    pub async fn recheck_kad_firewall(&self) -> NetworkStatus {
        let mut status = kad_status_from_running(self.state.lock().await.kad_running);
        status.operation_queued = Some(status.running);
        status.already_running = Some(false);
        status
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
        let shutdown = Arc::new(AtomicBool::new(false));
        let configured_bootstrap_nodes_text =
            configured_kad_bootstrap_nodes_text(&network.kad_bootstrap_nodes);
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(network.kad_bind_addr),
            obfuscation_enabled: network.config.obfuscation_enabled,
            bootstrap_min_routing_contacts: network.kad_bootstrap_min_routing_contacts.max(1),
            nodes_text: configured_bootstrap_nodes_text.clone(),
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
                .build(),
        );
        nat.start().await?;
        let mut tasks = Vec::new();
        tasks.push(dht.clone().start());
        if configured_bootstrap_nodes_text.is_some() {
            tasks.push(tokio::spawn(run_configured_kad_bootstrap(
                dht.clone(),
                Arc::clone(&shutdown),
            )));
        }
        if let (Some(kad_local_store), Some(kad_snoop_queue)) = (
            self.kad_local_store.as_ref().map(Arc::clone),
            self.kad_snoop_queue.as_ref().map(Arc::clone),
        ) {
            tasks.push(tokio::spawn(run_kad_local_store_loop(
                dht.clone(),
                kad_local_store,
                Arc::clone(&kad_snoop_queue),
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
        tasks.push(tokio::spawn(run_ed2k_listener(Ed2kListenerOptions {
            listener: ed2k_listener,
            dht: dht.clone(),
            server_state: Arc::clone(&server_state),
            kad_firewall: Arc::clone(&kad_firewall),
            secure_ident: Arc::clone(&network.secure_ident),
            transfer_runtime: Arc::clone(&self.ed2k_transfers),
            hello_identity,
            shutdown: Arc::clone(&shutdown),
        })));
        tasks.push(tokio::spawn(run_ed2k_server_loop(Ed2kServerLoopOptions {
            bind_ip: network.bind_ip,
            nat: Arc::clone(&nat),
            config,
            hello_identity,
            shared_catalog: self.ed2k_transfers.shared_catalog(),
            state: Arc::clone(&server_state),
            search_inbox,
            kad_firewall,
            shutdown: Arc::clone(&shutdown),
        })));
        *runtime_guard = Some(Ed2kRuntime {
            search_handle,
            server_state,
            dht,
            kad_bootstrap_configured: configured_bootstrap_nodes_text.is_some(),
            nat,
            shutdown,
            tasks,
        });
        drop(runtime_guard);
        Ok(self.ed2k_status().await)
    }

    pub async fn disconnect_ed2k(&self) -> NetworkStatus {
        if let Some(runtime) = self.ed2k_runtime.lock().await.take() {
            runtime.shutdown.store(true, Ordering::SeqCst);
            let _ = runtime.nat.stop().await;
            for task in runtime.tasks {
                task.abort();
            }
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
        let servers = server_map.into_values().collect::<Vec<_>>();
        servers
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
        let mut state = self.state.lock().await;
        state.servers.remove(&server.endpoint);
        state.server_overrides.remove(&server.endpoint);
        state.disabled_servers.insert(server.endpoint.clone());
        Ok(Some(server))
    }

    pub async fn create_search(&self, request: SearchCreate) -> Result<Search> {
        let search_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let mut results = Vec::new();
        if let Some(ed2k_results) = self.search_ed2k_servers(&search_id, &request).await? {
            results.extend(ed2k_results);
        }
        let indexed = self.index.lock().await.search(&request.query, 200)?;
        results.extend(
            indexed
                .into_iter()
                .map(|file| search_result_from_indexed(&search_id, &request, file)),
        );
        let search = Search {
            id: search_id.clone(),
            query: request.query,
            method: request.method,
            r#type: request.r#type,
            status: "completed".to_string(),
            created_at: now,
            updated_at: now,
            results,
        };
        self.state
            .lock()
            .await
            .searches
            .insert(search_id, search.clone());
        Ok(search)
    }

    pub async fn searches(&self) -> Vec<Search> {
        self.state.lock().await.searches.values().cloned().collect()
    }

    pub async fn search(&self, search_id: &str) -> Option<Search> {
        self.state.lock().await.searches.get(search_id).cloned()
    }

    pub async fn delete_search(&self, search_id: &str) -> bool {
        self.state.lock().await.searches.remove(search_id).is_some()
    }

    pub async fn clear_searches(&self) {
        self.state.lock().await.searches.clear();
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
        apply_category_update(category, request)?;
        Ok(Some(category.clone()))
    }

    pub async fn delete_category(&self, category_id: u32) -> Result<Option<Category>> {
        ensure!(category_id != 0, "default category cannot be deleted");
        Ok(self.state.lock().await.categories.remove(&category_id))
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
        state.friends.insert(user_hash, friend.clone());
        Ok(friend)
    }

    pub async fn delete_friend(&self, user_hash: &str) -> Result<Option<Friend>> {
        let user_hash = normalize_user_hash(user_hash)?;
        Ok(self.state.lock().await.friends.remove(&user_hash))
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
        self.state
            .lock()
            .await
            .unshared_hashes
            .remove(&summary.file_hash);
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
                        .payload_path(&manifest.file_hash)
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
        let mut transfer = transfer_from_manifest(&manifest, state_name);
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
        Ok(Some(transfer_sources_from_manifest(&manifest, &banned)))
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
            transfer_from_manifest(&manifest, state_name)
        };
        if !self.ed2k_transfers.delete_transfer_files(hash).await? {
            return Ok(None);
        }
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
        let transfer = transfer_from_manifest(&manifest, state_name);
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
        anyhow::ensure!(
            current.state != "stopped",
            "stopped transfer cannot be resumed"
        );
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
        }
        let mut transfer = transfer_from_manifest(&manifest, state_name);
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
            let mut transfer = transfer_from_manifest(&manifest, &state_name);
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
        let mut transfer = transfer_from_manifest(&manifest, state_name);
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
        let mut transfer = transfer_from_manifest(&manifest, state_name);
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
        if let Some(handle) = self.connected_ed2k_search_handle().await {
            let timeout = Duration::from_secs(config.connect_timeout_secs.max(15));
            match search_keyword_via_background_session(&handle, &request.query, timeout, &cancel)
                .await
            {
                Ok(files) => {
                    return Ok(Some(
                        files
                            .into_iter()
                            .map(|file| search_result_from_ed2k(search_id, request, file))
                            .collect(),
                    ));
                }
                Err(error) => tracing::warn!(
                    "ED2K background keyword search failed query={:?} error={error}",
                    request.query
                ),
            }
        }
        let hello_identity = Ed2kHelloIdentity {
            user_hash: network.user_hash,
            client_id: 0,
            tcp_port: network.listen_port,
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(config.obfuscation_enabled),
            direct_udp_callback: false,
        };
        let shared_catalog = self.ed2k_transfers.shared_catalog();
        let shared_catalog_snapshot = shared_catalog.read().await.clone();
        let max_attempts = config.keyword_server_attempt_budget.max(1).min(
            config
                .server_entries
                .len()
                .max(config.server_endpoints.len())
                .max(1),
        );
        let files = search_keyword_servers(Ed2kKeywordSearchOptions {
            bind_ip: network.bind_ip,
            config: &config,
            hello_identity,
            shared_catalog: &shared_catalog_snapshot,
            preferred_endpoint: None,
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

    async fn run_ed2k_download_attempt(&self, transfer: &Transfer) -> Result<Option<&'static str>> {
        let Some(network) = self.ed2k_network.as_ref() else {
            return Ok(Some("queued"));
        };
        if network.config.server_entries.is_empty() && network.config.server_endpoints.is_empty() {
            return Ok(Some("queued"));
        }
        if transfer.size_bytes == 0 {
            return Ok(Some("queued"));
        }

        let file_hash: Ed2kHash = transfer
            .hash
            .parse()
            .with_context(|| format!("invalid ED2K transfer hash {}", transfer.hash))?;
        let mut sources = self
            .acquire_ed2k_sources(network, file_hash, transfer.size_bytes)
            .await?;
        if sources.is_empty() {
            return Ok(Some("queued"));
        }
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

            let direct_sources =
                direct_download_candidate_sources(&sources, &attempted_direct_endpoints);
            had_direct_sources |= !direct_sources.is_empty();
            for source in &direct_sources {
                attempted_direct_endpoints.insert(source_endpoint_key(source));
            }

            if !direct_sources.is_empty() {
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
                    |bind_ip,
                     source,
                     hello_identity,
                     secure_ident,
                     transfer_runtime,
                     file_name,
                     file_size,
                     connect_timeout| async move {
                        download_file_from_peer(Ed2kPeerDownloadOptions {
                            bind_ip,
                            peer: &source,
                            hello_identity,
                            secure_ident: &secure_ident,
                            transfer_runtime: transfer_runtime.as_ref(),
                            canonical_name: file_name,
                            file_size,
                            timeout: connect_timeout,
                        })
                        .await
                    },
                )
                .await?;
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
        if accepted_incomplete_peers != 0 {
            return Ok(Some("downloading"));
        }
        if let Some(error) = last_direct_error {
            return Err(error).context("ED2K direct download did not complete");
        }
        Ok(Some("queued"))
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
            match result {
                Ok(Some(next_state)) => {
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
        });
    }

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
        if let Some(handle) = self.connected_ed2k_search_handle().await {
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
        if !sources.is_empty() {
            self.remember_ed2k_sources(file_hash, &sources).await?;
            return Ok(sources);
        }
        match search_source_servers(Ed2kSourceSearchOptions {
            bind_ip: network.bind_ip,
            config: &network.config,
            hello_identity: self.ed2k_hello_identity(network),
            shared_catalog: &shared_catalog_snapshot,
            preferred_endpoint: None,
            excluded_endpoint: None,
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
                preferred_endpoint: None,
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
            tcp_port: network.listen_port,
            udp_port: 0,
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

async fn run_kad_local_store_loop(
    dht: DhtNode,
    local_store: Arc<Mutex<KadLocalStore>>,
    snoop_queue: Arc<Mutex<SnoopQueue>>,
    shutdown: Arc<AtomicBool>,
) {
    let mut packets = dht.subscribe_packets();
    while !shutdown.load(Ordering::SeqCst) {
        match tokio::time::timeout(Duration::from_millis(250), packets.recv()).await {
            Ok(Ok(received)) => {
                if let Err(error) =
                    handle_kad_local_store_packet(&dht, &local_store, &snoop_queue, received).await
                {
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

async fn handle_kad_local_store_packet(
    dht: &DhtNode,
    local_store: &Arc<Mutex<KadLocalStore>>,
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
    received: ReceivedKadPacket,
) -> Result<()> {
    let ReceivedKadPacket { packet, from, .. } = received;
    match packet {
        KadPacket::Ping => {
            dht.send_packet(
                from,
                &KadPacket::Pong(emulebb_kad_proto::Pong {
                    udp_port: from.port(),
                }),
            )
            .await?;
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
            let contacts = dht
                .closest_contacts(&req.target, req.count as usize)
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
        _ => {}
    }
    Ok(())
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

fn build_keyword_snoop_entry(req: &SearchKeyReq, now: DateTime<Utc>) -> SnoopEntry {
    let restrictive_payload_hex =
        (!req.restrictive_payload.is_empty()).then(|| hex::encode(&req.restrictive_payload));
    SnoopEntry::Keyword {
        logical_key: keyword_logical_key(req),
        target: req.target.to_string(),
        start_position: req.start_position,
        restrictive_payload_hex,
        hit_count: 1,
        first_seen: now,
        last_seen: now,
        last_drained_at: None,
    }
}

fn build_source_snoop_entry(req: &SearchSourceReq, now: DateTime<Utc>) -> SnoopEntry {
    SnoopEntry::Source {
        logical_key: source_logical_key(req),
        target: req.target.to_string(),
        start_position: req.start_position,
        size: req.size,
        hit_count: 1,
        first_seen: now,
        last_seen: now,
        last_drained_at: None,
    }
}

fn build_notes_snoop_entry(req: &SearchNotesReq, now: DateTime<Utc>) -> SnoopEntry {
    SnoopEntry::Notes {
        logical_key: notes_logical_key(req),
        target: req.target.to_string(),
        size: req.size,
        hit_count: 1,
        first_seen: now,
        last_seen: now,
        last_drained_at: None,
    }
}

fn keyword_logical_key(req: &SearchKeyReq) -> String {
    let payload_hex = if req.restrictive_payload.is_empty() {
        String::new()
    } else {
        hex::encode(&req.restrictive_payload)
    };
    format!(
        "keyword:{}:{:04x}:{}",
        req.target, req.start_position, payload_hex
    )
}

fn source_logical_key(req: &SearchSourceReq) -> String {
    format!(
        "source:{}:{:04x}:{}",
        req.target, req.start_position, req.size
    )
}

fn notes_logical_key(req: &SearchNotesReq) -> String {
    format!("notes:{}:{}", req.target, req.size)
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

fn transfer_from_manifest(manifest: &Ed2kResumeManifest, state_name: &str) -> Transfer {
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
    Transfer {
        ed2k_link: format!(
            "ed2k://|file|{}|{}|{}|/",
            manifest.canonical_name, manifest.file_size, manifest.file_hash
        ),
        hash: manifest.file_hash.clone(),
        name: manifest.canonical_name.clone(),
        path: String::new(),
        size_bytes: manifest.file_size,
        completed_bytes,
        state: state_name.to_string(),
        progress,
        sources: manifest.sources.len() as u32,
        download_speed_bytes_per_sec: 0,
        priority: "normal".to_string(),
        category_id: 0,
        category_name: default_transfer_category_name().to_string(),
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
        "queued"
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
    Upload {
        client_id,
        user_name: format!("{}:{}", entry.ip, entry.tcp_port),
        user_hash,
        client_software: "unknown".to_string(),
        client_mod: String::new(),
        upload_state,
        upload_speed_ki_bps: 0.0,
        uploaded_bytes: 0,
        queue_session_uploaded: 0,
        payload_buffered: 0,
        wait_time_ms: entry.wait_time_ms,
        wait_started_tick: 0,
        score: 0,
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

fn search_result_from_indexed(
    search_id: &str,
    request: &SearchCreate,
    file: IndexedFile,
) -> SearchResult {
    SearchResult {
        search_id: search_id.to_string(),
        method: request.method.clone(),
        r#type: request.r#type.clone(),
        hash: file.ed2k_hash,
        name: file.name,
        size_bytes: file.size_bytes,
        sources: file.availability_score.max(0) as u32,
        complete_sources: 0,
        file_type: file.content_type.clone(),
        complete: false,
        known_type: file.content_type,
        directory: String::new(),
    }
}

fn search_result_from_ed2k(
    search_id: &str,
    request: &SearchCreate,
    file: Ed2kSearchFile,
) -> SearchResult {
    let file_type = file.file_type.unwrap_or_else(|| "unknown".to_string());
    SearchResult {
        search_id: search_id.to_string(),
        method: request.method.clone(),
        r#type: request.r#type.clone(),
        hash: file.file_hash.to_string(),
        name: file.file_name.unwrap_or_else(|| file.file_hash.to_string()),
        size_bytes: file.file_size.unwrap_or_default(),
        sources: file.source_count.unwrap_or_default(),
        complete_sources: 0,
        file_type: file_type.clone(),
        complete: false,
        known_type: file_type,
        directory: String::new(),
    }
}

fn configured_server_attempts(config: &Ed2kConfig) -> usize {
    config
        .server_entries
        .len()
        .max(config.server_endpoints.len())
        .max(1)
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
        let sleep = tokio::time::sleep(remaining);
        tokio::pin!(sleep);

        loop {
            tokio::select! {
                _ = &mut sleep => {
                    cancel.cancel();
                    break;
                }
                result = stream.next() => {
                    let Some(result) = result else {
                        break;
                    };
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
        upload_slot_elastic_percent: 25,
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
const ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS: usize = 2;
const ED2K_DOWNLOAD_SOURCE_REQUERY_DELAY_SECS: u64 = 5;
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

fn shared_directory_update_parts(root: SharedDirectoryRootUpdate) -> (String, bool) {
    match root {
        SharedDirectoryRootUpdate::Path(path) => (path, false),
        SharedDirectoryRootUpdate::Object { path, recursive } => (path, recursive),
    }
}

fn refresh_shared_directory_row(root: &SharedDirectoryRoot) -> SharedDirectoryRoot {
    let path = Path::new(&root.path);
    let accessible = path.is_dir();
    SharedDirectoryRoot {
        path: root.path.clone(),
        recursive: root.recursive,
        monitor_owned: root.monitor_owned,
        shareable: accessible,
        accessible,
    }
}

fn collect_shared_directory_files(
    root: &Path,
    recursive: bool,
    output: &mut Vec<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_file() {
            output.push(path);
        } else if recursive && file_type.is_dir() {
            collect_shared_directory_files(&path, recursive, output)?;
        }
    }
    Ok(())
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
    let path = std::env::temp_dir().join(format!(
        "emulebb-rust-{name}-{}-{stamp}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create runtime dir");
    path
}

#[cfg(test)]
mod tests {
    use emulebb_index::IndexedFile;
    use emulebb_kad_proto::{NodeId, Tag};

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
            nat_config: NatConfig::default(),
            config: Ed2kConfig::default(),
        }
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
            })
            .await
            .unwrap();
        assert_eq!(search.status, "completed");
        assert_eq!(search.results.len(), 1);
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
        assert_eq!(transfer.state, "queued");
    }

    #[tokio::test]
    async fn create_transfer_uses_canonical_link_and_paused_state() {
        let runtime_dir = unique_runtime_dir("emulebb-core-paused-transfer-create");
        let transfer_root = runtime_dir.join("transfers");
        let core =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();

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
        let reloaded =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
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
        let payload_path = runtime_dir.join("Completed.Row.bin");
        std::fs::write(&payload_path, b"completed row removal payload").unwrap();
        let core =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
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

        let reloaded =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
        assert!(reloaded.transfer(&share.hash).await.is_none());
        assert!(reloaded.transfers().await.is_empty());
        assert!(
            reloaded
                .shares()
                .await
                .iter()
                .any(|entry| entry.hash == share.hash)
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
        assert_eq!(
            core.stop_transfer(&transfer.hash)
                .await
                .unwrap()
                .unwrap()
                .state,
            "stopped"
        );

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
        let core =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
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

        let reloaded =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
        let reloaded_transfer = reloaded.transfer(&transfer.hash).await.unwrap();

        assert_eq!(reloaded_transfer.state, "stopped");
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
        let payload_path = runtime_dir.join("Shared.Payload.bin");
        let payload = b"persisted transfer payload";
        std::fs::write(&payload_path, payload).unwrap();
        let core =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
        let share = core
            .share_local_file(LocalShareCreate {
                path: payload_path.display().to_string(),
                name: Some("Shared.Payload.bin".to_string()),
            })
            .await
            .unwrap();

        let reloaded =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
        let transfers = reloaded.transfers().await;

        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].hash, share.hash);
        assert_eq!(transfers[0].state, "completed");
        assert_eq!(transfers[0].completed_bytes, payload.len() as u64);
        assert_eq!(transfers[0].progress, 1.0);
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

    #[test]
    fn source_requery_skip_waits_for_one_refresh_round_without_progress() {
        assert!(!should_skip_no_progress_source_requery(true, false, 0, 0));
        assert!(should_skip_no_progress_source_requery(true, false, 0, 1));
        assert!(!should_skip_no_progress_source_requery(true, true, 0, 1));
        assert!(!should_skip_no_progress_source_requery(true, false, 1, 1));
        assert!(!should_skip_no_progress_source_requery(false, false, 0, 1));
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
