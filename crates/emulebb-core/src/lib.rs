use std::{
    collections::{BTreeMap, HashSet, VecDeque},
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

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
#[cfg(test)]
use emulebb_ed2k::config::Ed2kUploadQueuePolicyConfig;
#[cfg(test)]
use emulebb_ed2k::ed2k_server::Ed2kSearchFile;
#[cfg(test)]
use emulebb_ed2k::{MappingExposure, TransportProtocol};
use emulebb_ed2k::{
    DirectCallbackArgs, NatManager, NatManagerBuilder, ReaskSourceHandle,
    buddy_socket::{BuddySocketRegistry, ExpectedInboundBuddy},
    built_in_upnp_port_mapping_providers,
    config::Ed2kConfig,
    ed2k_server::{
        Ed2kBackgroundSearchInterrupted, Ed2kFoundSource, Ed2kServerLoopOptions,
        Ed2kServerSearchHandle, Ed2kServerState, Ed2kUdpKeywordSearchOptions,
        Ed2kUdpSourceBatchSearchOptions, OfferFilesPublishStats, SearchCriteria,
        ed2k_server_list_event_channel, new_ed2k_server_search_channel, parse_server_met,
        publish_shared_catalog_via_background_session, request_callback_via_background_session,
        run_ed2k_server_loop, search_keyword_udp_servers, search_keyword_via_background_session,
        search_source_batch_via_background_session, search_source_udp_server_batches,
    },
    ed2k_tcp::{
        Ed2kHelloIdentity, Ed2kListenerOptions, Ed2kPeerDownloadOptions, Ed2kPeerDownloadOutcome,
        Ed2kSecureIdent, HelloBuddySnapshot, OutboundBuddyLinkOptions, download_file_from_peer,
        emule_connect_options, encode_kad_callback_relay_frame, run_ed2k_listener,
        run_outbound_buddy_link, set_hello_buddy_snapshot, set_publish_rust_identity,
    },
    ed2k_transfer::{
        ED2K_PART_SIZE, Ed2kCallbackIntent, Ed2kResumeManifest, Ed2kSharedEntry,
        Ed2kSharedPublishDemandSignal, Ed2kSourceHint, Ed2kTransferRuntime,
        Ed2kUploadSessionPhaseSnapshot, new_transfer_job,
    },
    kad_firewall::{FirewallUdpPacketOutcome, FirewalledResponseOutcome, KadFirewallState},
    long_path::long_path,
    reachability::ExternalReachability,
    reask_command_channel, reask_event_channel, run_ed2k_udp_reask_loop,
    shared_publish_rank::{
        SharedPublishRankInput, compare_shared_publish_rank, shared_publish_rank,
    },
};
use emulebb_index::{
    FileIndex, IndexedFile, KadLocalStore, SnoopEntry, SnoopQueue, metadata_from_publish_snapshot,
    publish_snapshot_from_metadata,
};
#[cfg(test)]
use emulebb_index::{KadLocalStoreConfig, SnoopQueueConfig, SnoopQueueFamilyCounts};
use emulebb_kad_dht::{
    DhtConfig, DhtError, DhtNode, KeywordPublishEntry, PublishAttemptStats, ReceivedKadPacket,
    RpcClassBudgetConfig, RpcWorkClass,
};
#[cfg(test)]
use emulebb_kad_dht::{NoteResult as KadNoteResult, SearchResult as KadSearchResult, SourceResult};
#[cfg(test)]
use emulebb_kad_proto::tag_name;
use emulebb_kad_proto::{
    CallbackReq, Ed2kHash, FindBuddyReq, FindBuddyRes, HelloResAck, KAD_VERSION, KadPacket,
    PublishRes, Tag, constants::K, packet::ContactEntry,
};
#[cfg(test)]
use emulebb_kad_proto::{
    SearchKeyReq, SearchNotesReq, SearchRes, SearchResultEntry, SearchSourceReq,
};
use emulebb_metadata::{
    MetadataKadOutboundPublish, MetadataKadOutboundPublishKind, MetadataStore,
    MetadataTransferCounts, MetadataTransferPublishEntry, MetadataTransferShareEntry,
};
use serde_json::json;
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod categories;
mod category_runtime;
mod core_state;
mod delivery;
mod diag_kad_event;
mod diag_sched;
mod disk_guard;
mod download_source_registry;
mod ed2k_buddy_reask;
mod ed2k_direct_download_types;
mod ed2k_download_retry;
mod ed2k_net_drivers;
mod ed2k_publish_diagnostics;
mod ed2k_source_batch;
mod ed2k_sources;
mod kad_buddy;
mod kad_callback_initiator;
mod kad_control;
mod kad_hello;
mod kad_passive_replay;
mod kad_public_search;
mod kad_publish_diagnostics;
mod kad_publish_schedule;
mod kad_routing_maintenance;
mod kad_snoop_entry;
mod kad_tcp_firewall_check;
mod kad_udp_firewall_check;
mod lifecycle;
mod local_search_response;
mod network_binding;
mod physical_disk;
mod preferences;
mod profile_state;
mod search_query;
mod search_queue;
mod search_queue_runtime;
mod search_state;
mod server_list;
mod shared_dir_monitor;
mod shared_directories;
mod source_publish;
mod upload_view;
mod views;
pub mod vpn_guard;
use categories::default_categories;
pub(crate) use core_state::CoreState;
use download_source_registry::DownloadSourceCandidate;
use ed2k_buddy_reask::detach_kad_buddy_sources_for_reask;
use ed2k_direct_download_types::{
    DirectDownloadJoin, DirectDownloadOptions, DirectDownloadOutcome, DirectDownloadSpawnContext,
};
use ed2k_net_drivers::{
    ed2k_nat_mappings, fetch_url_bytes, run_advertised_ports_sync, run_ed2k_nat_type_probe,
    run_ed2k_public_ip_probe, run_ed2k_reask_reengage, run_ed2k_server_list_events,
};
pub use ed2k_publish_diagnostics::Ed2kPublishDiagnostics;
use ed2k_source_batch::{
    claim_connected_server_source_batch, claim_ed2k_udp_source_batch, claim_kad_source_refresh,
};
use ed2k_sources::{
    Ed2kServerCallbackRoute, LearnedEd2kMetadata, OwnSourceIdentity,
    claim_ed2k_server_callback_request, collect_kad_ed2k_metadata, collect_kad_ed2k_sources,
    configured_server_attempts, direct_download_candidate_sources, drop_self_sources,
    ed2k_server_callback_route, found_source_from_hint, global_udp_source_batch_server_attempts,
    global_udp_source_search_excluded_endpoint, hash_only_ed2k_search_query,
    kad_source_result_to_ed2k_found_source, keyword_target, manifest_has_ed2k_transfer_progress,
    merge_download_sources, new_direct_ed2k_source_count, select_ed2k_keyword_metadata,
    should_adopt_hash_only_metadata_name, should_query_kad_source_supplement,
    should_query_server_udp_source_supplement, should_refresh_ed2k_server_sources,
    should_skip_no_progress_source_requery, significant_keyword_words_unique,
    sort_download_sources, source_endpoint_key, source_key,
};
#[cfg(test)]
use ed2k_sources::{
    ed2k_keyword_server_attempts, exact_ed2k_hash_query_token, select_kad_keyword_metadata,
    significant_keyword_words,
};
use kad_buddy::{
    BuddyNeedInput, FindBuddyReqRefusal, IncomingBuddy, KadBuddyState, OutgoingBuddy,
    buddy_search_target, find_buddy_res_matches,
};
use kad_callback_initiator::{
    KAD_CALLBACK_INITIATOR_COOLDOWN, build_kad_callback_req, is_direct_kad_callback_candidate,
    kad_callback_key, should_send_kad_callback,
};
use kad_hello::{
    build_kad_hello_response, kad_publish_within_tolerance, kad_req_masked_count,
    should_request_hello_res_ack, spawn_kad_firewalled_response,
    spawn_modern_kad_firewalled_response,
};
#[cfg(test)]
use kad_hello::{
    build_kad_hello_request_tags, build_kad_hello_response_tags, firewalled_response_ip_for_sender,
};
#[cfg(test)]
use kad_passive_replay::{
    PassiveReplayFamily, index_passive_keyword_result, preferred_passive_replay_families,
    remember_passive_note_results, remember_passive_source_results,
};
use kad_passive_replay::{PassiveReplayWorker, run_kad_passive_replay_loop};
use kad_public_search::search_kad_keywords;
pub use kad_publish_diagnostics::KadPublishDiagnostics;
use kad_snoop_entry::{
    build_keyword_snoop_entry, build_notes_snoop_entry, build_source_snoop_entry,
};
use local_search_response::send_local_search_response;
#[cfg(test)]
use local_search_response::split_stock_search_responses;
pub use network_binding::NetworkBindingStatus;
use preferences::{
    apply_preferences_update, default_preferences,
    ed2k_download_coordinator_config_from_preferences,
    ed2k_download_limit_bytes_per_sec_from_preferences, ed2k_upload_queue_policy_from_preferences,
    initial_ed2k_upload_queue_policy, preferences_update_is_empty,
};
use search_query::{
    SearchNetworkMethod, apply_search_filters, resolve_search_network_method,
    search_criteria_from_request, search_result_from_ed2k, search_result_from_indexed,
};
use search_queue::{SearchQueue, SearchQueueLane};
use search_queue_runtime::Ed2kServerSearchOutcome;
use source_publish::{
    SourcePublishReachability, SourcePublishSettings, build_source_publish_tags,
    source_publish_client_hash,
};
use upload_view::{upload_from_snapshot, upload_policy_metrics_from_capacity};

use shared_dir_monitor::SharedDirMonitor;
pub use shared_directories::{
    SharedDirectories, SharedDirectoriesUpdate, SharedDirectoryRoot, SharedDirectoryRootUpdate,
    SharedReloadDiagnostics,
};
use shared_directories::{
    refresh_shared_directory_row, reload_diagnostics_snapshot, shared_directory_from_index,
    shared_directory_items, shared_directory_to_index, shared_directory_update_parts,
};

mod rest_model;
mod rest_model_serde;
pub use rest_model::{
    AppInfo, AppLifecycle, Category, CategoryCreate, CategoryPriorityValue, CategoryUpdate,
    DiagnosticDumpResult, DownloadSourceMetrics, Ed2kNetworkConfig, Friend, FriendCreate,
    IndexingStatus, LocalShare, LocalShareCreate, NetworkStatus, NullableStringField,
    NullableU32Field, Preferences, PreferencesUpdate, Search, SearchCreate, SearchResult,
    SearchResultDownloadCreate, ServerCreate, ServerInfo, ServerUpdate, SharedFileUpdate, Status,
    Transfer, TransferCreate, TransferDetails, TransferPart, TransferSource, TransferStats,
    TransferThroughputStats, TransferUpdate, Upload, UploadPolicyMetrics, UploadScoreBreakdown,
    VpnGuardConfig, VpnGuardProbeStatus, VpnGuardStatus,
};
use views::{
    ServerLiveDetails, apply_server_update, default_transfer_category_name,
    download_priority_score, enrich_sources_with_live, ensure_category_selector_is_unambiguous,
    kad_status_from_running, manifest_default_state_name, normalize_transfer_name,
    preserve_transfer_public_metadata, server_endpoint_from_create, server_info_from_parts,
    source_by_client_id, source_friend_name, transfer_create_links, transfer_create_state_name,
    transfer_from_manifest, transfer_parts_from_manifest, transfer_sources_from_manifest,
    validate_server_priority, validate_server_update, validate_shared_file_comment_rating,
    validate_shared_upload_priority, validate_source_client_id, validate_transfer_priority,
    validate_transfer_update_family, validate_url_import,
};

const LOCAL_KEYWORD_SEARCH_RESPONSE_LIMIT: usize = 300;
const LOCAL_SOURCE_SEARCH_RESPONSE_LIMIT: usize = 300;
const LOCAL_NOTES_SEARCH_RESPONSE_LIMIT: usize = 150;
const KAD_SHARED_FILE_PUBLISH_RETRY_SECS: u64 = 5;
const ED2K_LOCAL_SERVER_SEARCH_TIMEOUT_SECS: u64 = 50;
/// Max oracle freshness type returned to a KADEMLIA2_REQ (oracle passes 2 to
/// `GetClosestTo`), filtering out contacts staler than two age buckets.
const KAD_REQ_MAX_TYPE: u8 = 2;
/// Oracle `OLD_MAX_EMULE_FILE_SIZE` (Opcodes.h): `(4294967295/PARTSIZE)*PARTSIZE`,
/// the pre-large-file limit. Kad source types switch to their large-file
/// variants (4/5) strictly above this, NOT above the raw u32 ceiling.
const EMULE_LARGE_FILE_SIZE_THRESHOLD: u64 = 4_290_048_000;
const ED2K_HASH_ONLY_QUERY_PREFIX: &str = "ed2k::";
/// Upper bound on awaiting the initial UPnP reconcile before the first eD2k server
/// login (connection ordering: bind -> VPN guard -> UPnP await -> connect). Covers
/// SSDP discovery + AddPortMapping for both eD2k TCP and Kad UDP with headroom over
/// the 5s default discovery timeout, while bounding startup if the gateway is slow
/// or absent.
const ED2K_UPNP_INITIAL_RECONCILE_TIMEOUT: Duration = Duration::from_secs(20);

struct Ed2kRuntime {
    search_handle: Ed2kServerSearchHandle,
    server_state: Arc<RwLock<Ed2kServerState>>,
    dht: DhtNode,
    /// Shared Kad firewall verification state, read by `kad_status` to report the
    /// real UDP-firewall verdict (oracle `CUDPFirewallTester::IsFirewalledUDP`).
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    nat: Arc<NatManager>,
    shutdown: Arc<AtomicBool>,
    server_reconnect_signal: Arc<tokio::sync::Notify>,
    target_server_endpoint: Arc<RwLock<Option<String>>>,
    /// Trigger to run a Kad UDP firewall self-check round on demand. `None` when
    /// the firewall check is disabled in config.
    kad_firewall_recheck: Option<Arc<tokio::sync::Notify>>,
    tasks: Vec<JoinHandle<()>>,
    /// Detached per-transfer background download tasks for this session (FIX B3).
    /// Aborted by `disconnect_ed2k`; a fresh handle is created per connect so a
    /// later reconnect's tasks are never aborted by an earlier disconnect.
    download_tasks: Arc<Mutex<JoinSet<()>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ed2kSharedCatalogPublishOutcome {
    Published(OfferFilesPublishStats),
    NoNetwork,
    NotConnected,
}

/// RAII guard that removes a transfer hash from `active_download_attempts` (and
/// its `download_cancels` entry) on drop, so the dedup slot and the per-hash
/// cancel signal are freed on every exit path of a background download attempt —
/// normal return, early return, *or* a panic that unwinds the task (FIX B2). The
/// maps live behind an async mutex, so the cleanup is performed by a short
/// detached task spawned from `Drop`.
///
/// The guard carries the generation id of the `download_cancels` entry it
/// installed and only removes that entry when the stored id still matches: a
/// delete or recreate of the same hash may have replaced the entry with a newer
/// attempt's token, and this (now-cancelled, exiting) attempt must not clobber
/// the live one. Removing the dedup slot is unconditional (one attempt per hash
/// at a time by construction).
struct DownloadAttemptGuard {
    core: EmulebbCore,
    hash: String,
    cancel_id: u64,
}

impl Drop for DownloadAttemptGuard {
    fn drop(&mut self) {
        let core = self.core.clone();
        let hash = std::mem::take(&mut self.hash);
        let cancel_id = self.cancel_id;
        tokio::spawn(async move {
            let mut state = core.state.lock().await;
            state.active_download_attempts.remove(&hash);
            if state
                .download_cancels
                .get(&hash)
                .is_some_and(|(id, _)| *id == cancel_id)
            {
                state.download_cancels.remove(&hash);
            }
        });
    }
}

#[derive(Clone)]
pub struct EmulebbCore {
    started_at: Instant,
    version: String,
    metadata_store: MetadataStore,
    index: Arc<Mutex<FileIndex>>,
    ed2k_transfers: Arc<Ed2kTransferRuntime>,
    transfer_root: PathBuf,
    /// Default destination for finished-file delivery: a completed transfer
    /// without a category path is materialized by name into this directory
    /// (eMule global Incoming folder). Defaults next to the transfer root; the
    /// daemon overrides it from `incomingDir` config via [`with_incoming_dir`].
    incoming_dir: PathBuf,
    /// Process lifecycle state surfaced by `GET /api/v1/app` (the `lifecycle`
    /// module maps it to the REST token). Starts `running`; the daemon flips it
    /// to `stopping` when graceful teardown begins so a polling controller sees
    /// the shutdown instead of a hardcoded `running`.
    lifecycle: Arc<std::sync::atomic::AtomicU8>,
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
    /// Latest bound dual-plane egress-probe report (STUN UDP + HTTP TCP) that the
    /// VPN Guard monitor runs to verify the public egress (eMuleBB PublicIpProbe).
    /// Read by `vpn_guard_status`; refreshed by `run_vpn_guard_egress_probe`.
    vpn_guard_egress: Arc<std::sync::Mutex<vpn_guard::EgressProbeReport>>,
    /// Tracks the detached per-transfer background download tasks for the current
    /// connected session, so `disconnect_ed2k` can abort them (they are otherwise
    /// untracked detached tasks that survive disconnect and orphan on shutdown).
    /// Reset to a fresh `JoinSet` on each connect; the same handle is stored in
    /// the session `Ed2kRuntime` and aborted on disconnect (FIX B3).
    ed2k_download_tasks: Arc<Mutex<JoinSet<()>>>,
    /// Live shared-directory auto-pickup monitor (eMule directory auto-monitor
    /// parity); rebuilt on reconfigure, torn down on `disconnect_ed2k`. See the
    /// `shared_dir_monitor` module. `std::sync::Mutex` so start/stop is await-free.
    shared_dir_monitor: Arc<std::sync::Mutex<Option<SharedDirMonitor>>>,
    /// Files still pending the initial hash in the detached background reload
    /// worker; surfaced as `hashingCount` on `GET /shared-directories`. Await-free
    /// atomic shared by the sync primitive and the worker (see `shared_directories`).
    shared_hashing_count: Arc<std::sync::atomic::AtomicI64>,
    /// Path-free live counters for the latest shared-directory reload plan.
    /// This is deliberately separate from tracing so REST can report why hashing
    /// is active without exposing operator file paths or names.
    shared_reload_diagnostics: Arc<std::sync::Mutex<SharedReloadDiagnostics>>,
    /// Serializes detached shared-directory reloads. A controller may request
    /// reload while a prior scan/hash job is still pruning stale shares; coalesce
    /// such requests and run one follow-up pass instead of overlapping jobs.
    shared_reload_running: Arc<AtomicBool>,
    shared_reload_pending: Arc<AtomicBool>,
    /// Coalesces ED2K server shared-catalog refreshes caused by share/hash
    /// completion. Large startup reloads can complete many files quickly; waiting
    /// for a server publish per file would serialize hashing behind network I/O.
    shared_catalog_publish_dirty: Arc<AtomicBool>,
    shared_catalog_publish_worker: Arc<AtomicBool>,
    shared_catalog_publish_last: Arc<Mutex<Option<Instant>>>,
    ed2k_publish_diagnostics: ed2k_publish_diagnostics::SharedEd2kPublishDiagnostics,
    kad_publish_diagnostics: kad_publish_diagnostics::SharedKadPublishDiagnostics,
    /// Connection-aware queue for network searches (`search_queue.rs` state
    /// machine + `search_queue_runtime.rs` drain task). `std::sync::Mutex` by
    /// design: guards are held for short sync sections only — never across an
    /// `.await` and never while acquiring the `state` lock — so the create
    /// path (state → queue) cannot deadlock against the drain path.
    search_queue: Arc<std::sync::Mutex<SearchQueue>>,
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
        let download_limit_bytes_per_sec =
            ed2k_download_limit_bytes_per_sec_from_preferences(&core_state.preferences);
        let ed2k_transfers = Ed2kTransferRuntime::load_or_create_with_metadata_and_config(
            &transfer_root,
            metadata_store.clone(),
            &Ed2kConfig {
                upload_queue: upload_queue_policy,
                download_limit_bytes_per_sec,
                ..Ed2kConfig::default()
            },
        )?;
        // Drive the shared download coordinator from the live REST preferences
        // (maxConnections / maxConnectionsPerFiveSeconds / maxSourcesPerFile),
        // like the download throttle, so REST preference changes apply to the
        // global connection budget + per-file source caps.
        ed2k_transfers.apply_download_coordinator_config(
            ed2k_download_coordinator_config_from_preferences(&core_state.preferences),
        );
        // Apply the credit-system toggle at startup too (eMule
        // thePrefs.GetCreditSystem()); update_preferences keeps it live thereafter.
        ed2k_transfers.set_credit_system_enabled(core_state.preferences.credit_system);
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
        // Default incoming directory: a sibling of the transfer root (i.e.
        // `<runtime_dir>/incoming` when the transfer root is `<runtime_dir>/
        // transfers`). The daemon overrides this from `incomingDir` config.
        let incoming_dir = transfer_root
            .parent()
            .map(|parent| parent.join("incoming"))
            .unwrap_or_else(|| transfer_root.join("incoming"));
        Ok(Self {
            started_at: Instant::now(),
            version: version.into(),
            metadata_store,
            index: Arc::new(Mutex::new(index)),
            ed2k_transfers: Arc::new(ed2k_transfers),
            transfer_root,
            incoming_dir,
            lifecycle: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            ed2k_network,
            kad_local_store,
            kad_snoop_queue,
            ed2k_runtime: Arc::new(Mutex::new(None)),
            ed2k_reask_handle: Arc::new(std::sync::Mutex::new(None)),
            ed2k_reachability: ExternalReachability::new(),
            vpn_guard_egress: Arc::new(std::sync::Mutex::new(
                vpn_guard::EgressProbeReport::default(),
            )),
            ed2k_download_tasks: Arc::new(Mutex::new(JoinSet::new())),
            shared_dir_monitor: Arc::new(std::sync::Mutex::new(None)),
            shared_hashing_count: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            shared_reload_diagnostics: Arc::new(std::sync::Mutex::new(
                SharedReloadDiagnostics::default(),
            )),
            shared_reload_running: Arc::new(AtomicBool::new(false)),
            shared_reload_pending: Arc::new(AtomicBool::new(false)),
            shared_catalog_publish_dirty: Arc::new(AtomicBool::new(false)),
            shared_catalog_publish_worker: Arc::new(AtomicBool::new(false)),
            shared_catalog_publish_last: Arc::new(Mutex::new(None)),
            ed2k_publish_diagnostics: ed2k_publish_diagnostics::new_shared(),
            kad_publish_diagnostics: kad_publish_diagnostics::new_shared(),
            search_queue: Arc::new(std::sync::Mutex::new(SearchQueue::new())),
            state: Arc::new(Mutex::new(core_state)),
        })
    }

    pub fn new_in_memory(version: impl Into<String>, index: FileIndex) -> Result<Self> {
        Self::new(version, index, unique_runtime_dir("emulebb-core-transfers"))
    }

    pub fn app_info(&self) -> AppInfo {
        AppInfo {
            name: "eMuleBB".to_string(),
            version: self.version.clone(),
            api_version: "v1".to_string(),
            lifecycle: AppLifecycle {
                state: self.lifecycle_state_name().to_string(),
            },
            capabilities: vec![
                "transfers".to_string(),
                "searches".to_string(),
                "servers".to_string(),
                "sharedFiles".to_string(),
                "sharedDirectories".to_string(),
                "uploads".to_string(),
                "logs".to_string(),
                "categoriesRead".to_string(),
                "categoryAssignment".to_string(),
                "categoryCrud".to_string(),
                "renameFile".to_string(),
                "transferDetails".to_string(),
                "fileRatingComment".to_string(),
                "friends".to_string(),
                "peerControls".to_string(),
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
        self.ed2k_transfers
            .apply_download_limit(ed2k_download_limit_bytes_per_sec_from_preferences(
                &preferences,
            ))
            .await;
        // Apply the global connection budget + per-file source caps live, like
        // the download limit (eMule GetMaxConnections / GetMaxConperFive /
        // GetConfiguredMaxSourcesPerFile preference changes take effect at once).
        self.ed2k_transfers.apply_download_coordinator_config(
            ed2k_download_coordinator_config_from_preferences(&preferences),
        );
        // Apply the credit-system toggle live (eMule thePrefs.GetCreditSystem()):
        // when off, upload scoring uses the neutral 1.0 credit ratio for everyone.
        self.ed2k_transfers
            .set_credit_system_enabled(preferences.credit_system);
        Ok(preferences)
    }

    pub async fn status(&self) -> Status {
        let transfer_counts = self.ed2k_transfers.try_transfer_counts();
        let state = self.state.lock().await;
        let kad_running = state.kad_running;
        let transfer_counts = transfer_counts.unwrap_or_else(|error| {
            tracing::warn!("failed to read persisted ED2K transfer counts: {error}");
            None
        });
        let transfer_counts = transfer_counts.unwrap_or_else(|| {
            tracing::debug!("metadata transfer counts are busy; using in-memory status counts");
            let total = state.transfers.len();
            let mut active = 0;
            let mut completed = 0;
            for transfer in state.transfers.values() {
                match transfer.state.as_str() {
                    "downloading" | "queued" => active += 1,
                    "completed" => completed += 1,
                    _ => {}
                }
            }
            MetadataTransferCounts {
                active,
                completed,
                total,
            }
        });
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
            transfers: TransferStats {
                active: transfer_counts.active,
                completed: transfer_counts.completed,
                total: transfer_counts.total,
            },
        }
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
        {
            let runtime = self.ed2k_runtime.lock().await;
            if let Some(signal) = runtime
                .as_ref()
                .and_then(|rt| rt.kad_firewall_recheck.as_ref())
            {
                signal.notify_one();
            }
        }
        // Master parity (kad/recheck_firewall -> PostWebGuiInteraction): the recheck
        // request is "queued" whenever Kad is running, independent of whether the
        // live ed2k networking runtime is up (the GUI accepts the interaction post).
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
        // The eD2k network must be enabled (eMule thePrefs.GetNetworkED2K()); when
        // off, the server connect is refused and no eD2k auto-ops run.
        ensure!(
            self.state.lock().await.preferences.network_ed2k,
            "eD2k network is disabled in preferences (networkEd2k=false)"
        );
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
        if let Some(runtime) = runtime_guard.as_ref() {
            let mut reconnect_needed = false;
            if let Some(endpoint) = endpoint {
                let requested_endpoint = endpoint.parse::<SocketAddr>().ok();
                let same_live_endpoint = {
                    let server_state = runtime.server_state.read().await;
                    requested_endpoint.is_some_and(|requested| {
                        server_state.endpoint == Some(requested)
                            && (server_state.connected || server_state.connecting)
                    })
                };
                *runtime.target_server_endpoint.write().await = Some(endpoint.to_string());
                // WHY: an explicit REST/UI server connect must interrupt the
                // current background session and make the loop try that endpoint
                // next, matching MFC's directed ConnectToServer behavior. Asking
                // for the already-live endpoint is a status-confirming no-op; do
                // not drop a healthy persistent server session just because a
                // controller re-sent the same connect command.
                reconnect_needed = !same_live_endpoint;
            }
            let server_state = runtime.server_state.read().await;
            if !server_state.connected && !server_state.connecting {
                // WHY: REST connect must behave like eMule's explicit connect button.
                // A disconnected background session can otherwise sit in its normal
                // reconnect backoff while the controller observes a no-op response.
                reconnect_needed = true;
            }
            drop(server_state);
            if reconnect_needed {
                runtime.server_reconnect_signal.notify_one();
            }
            drop(runtime_guard);
            return Ok(self.ed2k_status().await);
        }

        // Start this session's background-download task set from empty (FIX B3):
        // any handles left from a previous session were aborted on disconnect, so
        // a fresh JoinSet keeps the per-session abort scoped and reconnect-safe.
        {
            let mut download_tasks = self.ed2k_download_tasks.lock().await;
            download_tasks.abort_all();
            *download_tasks = JoinSet::new();
        }

        let (search_handle, search_inbox) = new_ed2k_server_search_channel(32);
        let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let kad_buddy = Arc::new(Mutex::new(KadBuddyState::new()));
        // Persistent Kad buddy-socket registry shared by inbound dispatch,
        // listener, outbound buddy link, and buddy-management loop.
        let buddy_registry = BuddySocketRegistry::new();
        let shutdown = Arc::new(AtomicBool::new(false));
        let nat = Arc::new(
            NatManagerBuilder::new(network.nat_config.clone())
                .with_mappings(ed2k_nat_mappings(&network))
                .with_providers(built_in_upnp_port_mapping_providers())
                .build(),
        );
        nat.start().await?;
        // Connection ordering (VPN guard -> UPnP await -> P2P sockets -> connect):
        // the eD2k server login must announce an already-forwarded listen port to
        // win HighID on the FIRST connect, and when UPnP is active the public P2P
        // sockets should not exist before the mapping gate completes. NAT mapping
        // only needs the intended ports, so await one reconcile now (bounded) and
        // copy the gateway-granted external ports into reachability before binding
        // Kad UDP or the eD2K TCP listener. Profiles that intentionally run
        // best-effort can set nat.requireInitialMapping=false.
        if network.nat_config.enabled {
            match tokio::time::timeout(ED2K_UPNP_INITIAL_RECONCILE_TIMEOUT, nat.reconcile_now())
                .await
            {
                Ok(Ok(())) => {
                    let status = nat.status().await;
                    crate::ed2k_net_drivers::sync_advertised_ports_from_nat(
                        &status,
                        &self.ed2k_reachability,
                        network.listen_port,
                        network.kad_bind_addr.port(),
                    );
                    tracing::info!(
                        "UPnP initial reconcile complete before ED2K login: advertised_tcp_port={} advertised_udp_port={}",
                        self.ed2k_reachability
                            .advertised_tcp_port(network.listen_port),
                        self.ed2k_reachability
                            .advertised_udp_port(network.kad_bind_addr.port()),
                    );
                }
                Ok(Err(error)) => {
                    if network.nat_config.require_initial_mapping {
                        let _ = nat.stop().await;
                        bail!("UPnP initial reconcile failed before ED2K/Kad startup: {error:#}");
                    }
                    tracing::warn!(
                        "UPnP initial reconcile failed before ED2K login; connecting with internal ports (may be LowID until UPnP succeeds): {error:#}"
                    );
                }
                Err(_) => {
                    if network.nat_config.require_initial_mapping {
                        let _ = nat.stop().await;
                        bail!(
                            "UPnP initial reconcile timed out after {}s before ED2K/Kad startup",
                            ED2K_UPNP_INITIAL_RECONCILE_TIMEOUT.as_secs()
                        );
                    }
                    tracing::warn!(
                        "UPnP initial reconcile timed out after {}s before ED2K login; connecting with internal ports (may be LowID until UPnP succeeds)",
                        ED2K_UPNP_INITIAL_RECONCILE_TIMEOUT.as_secs(),
                    );
                }
            }
        }
        let configured_bootstrap_nodes_text =
            configured_kad_bootstrap_nodes_text(&network.kad_bootstrap_nodes);
        let kad_bind_if_index =
            emulebb_ed2k::networking::require_bind_if_index(network.bind_ip, "Kad UDP")?;
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(network.kad_bind_addr),
            obfuscation_enabled: network.config.obfuscation_enabled,
            bootstrap_min_routing_contacts: network.kad_bootstrap_min_routing_contacts.max(1),
            max_concurrent_searches: KAD_SHARED_FILE_PUBLISH_DHT_SEARCH_CAP,
            nodes_text: configured_bootstrap_nodes_text.clone(),
            class_budgets: kad_rpc_class_budgets(),
            // Pin Kad UDP egress to the VPN bind interface (IP_UNICAST_IF).
            bind_if_index: Some(kad_bind_if_index),
            ..DhtConfig::default()
        })
        .await
        .context("failed to initialize Kad runtime for ED2K listener")?;
        // Bridge the live ed2k IpFilter into the Kad traversal layer so per-RES
        // contacts from filtered/banned IPs are dropped (oracle
        // KademliaUDPListener.cpp:830-857). The IpFilter lives in emulebb-ed2k
        // which depends on emulebb-kad-dht, so core (depending on both) bridges it
        // via a closure hook rather than moving the filter across the boundary.
        {
            let kad_ip_filter = network.ip_filter.clone();
            dht.set_ip_filter(std::sync::Arc::new(move |ip| kad_ip_filter.is_filtered(ip)));
        }
        let ed2k_bind_addr = SocketAddr::new(IpAddr::V4(network.bind_ip), network.listen_port);
        let ed2k_listener =
            Arc::new(TcpListener::bind(ed2k_bind_addr).await.with_context(|| {
                format!("failed to bind eD2k TCP listener on {ed2k_bind_addr}")
            })?);
        let hello_identity = self.ed2k_hello_identity(&network);
        let mut tasks = Vec::new();
        tasks.push(dht.clone().start());
        // "Reconnect now" signal: the advertised-ports sync fires it when the
        // external port changes (UPnP ready / remapped) so the server loop re-logs
        // in with the new HighID callback port instead of waiting for a reconnect.
        let server_reconnect_signal = Arc::new(tokio::sync::Notify::new());
        let target_server_endpoint = Arc::new(RwLock::new(endpoint.map(str::to_string)));
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
        // Always drive the bootstrap self-lookup, not only when explicit bootstrap
        // nodes are configured: the routing table can be populated from an imported
        // nodes.dat alone, and eMule (`CKademlia::Process`) bootstraps off the
        // table itself. Gating this on configured nodes left a nodes.dat-only node
        // permanently unbootstrapped, so every downstream loop (firewall check,
        // routing maintenance, hello-intro, publish) stayed dormant behind their
        // `is_bootstrapped()` guards and Kad never reached connected.
        tasks.push(tokio::spawn(run_configured_kad_bootstrap(
            dht.clone(),
            Arc::clone(&shutdown),
        )));
        if network.kad_publish_shared_files {
            tasks.push(tokio::spawn(run_kad_shared_file_publish_loop(
                KadPublishLoopRuntime {
                    dht: dht.clone(),
                    transfer_runtime: Arc::clone(&self.ed2k_transfers),
                    metadata_store: self.metadata_store.clone(),
                    diagnostics: Arc::clone(&self.kad_publish_diagnostics),
                    ed2k_listener: Arc::clone(&ed2k_listener),
                    server_state: Arc::clone(&server_state),
                    kad_firewall: Arc::clone(&kad_firewall),
                    kad_buddy: Arc::clone(&kad_buddy),
                    network: network.clone(),
                },
                Arc::clone(&shutdown),
            )));
        }
        // Periodic routing-table maintenance (oracle CRoutingZone timers): bucket
        // refresh (OnBigTimer -> RandomLookup) + dead-contact expiry and
        // stale-contact HELLO re-probe (OnSmallTimer).
        if network.kad_routing_maintenance_enabled {
            tasks.push(tokio::spawn(
                kad_routing_maintenance::run_kad_routing_maintenance_loop(
                    dht.clone(),
                    Arc::clone(&ed2k_listener),
                    Arc::clone(&server_state),
                    Arc::clone(&kad_firewall),
                    Arc::clone(&shutdown),
                ),
            ));
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
                    reask_handle: Arc::clone(&self.ed2k_reask_handle),
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
        // Server-list feedback channel (eMule `CServerSocket`/`CServerList`): the
        // session reports discovered servers (OP_SERVERLIST) and connect/ping
        // outcomes; this consumer applies them to the core's persisted store.
        let dead_server_retries = config.dead_server_retries;
        let (server_list_events_tx, server_list_events_rx) = ed2k_server_list_event_channel();
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
            reconnect_signal: Arc::clone(&server_reconnect_signal),
            target_server_endpoint: Arc::clone(&target_server_endpoint),
            server_list_events: Some(server_list_events_tx),
        })));
        tasks.push(tokio::spawn(
            Self::run_ed2k_shared_catalog_demand_publish_loop(
                self.clone(),
                self.ed2k_transfers.shared_publish_demand_signal(),
                Arc::clone(&shutdown),
            ),
        ));
        tasks.push(tokio::spawn(run_ed2k_server_list_events(
            self.clone(),
            server_list_events_rx,
            dead_server_retries,
            Arc::clone(&shutdown),
        )));
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
                buddy_registry.clone(),
                Arc::clone(&shutdown),
            )));
            // Re-engage consumer: when a reask reports a low queue rank, the loop
            // hands the source back and signals here to reconnect over TCP now.
            tasks.push(tokio::spawn(run_ed2k_reask_reengage(
                self.clone(),
                reask_events_rx,
                crate::ed2k_net_drivers::ReaskReengageContext {
                    bind_ip: network.bind_ip,
                    hello_identity,
                    ed2k_listener: Arc::clone(&ed2k_listener),
                    server_state: Arc::clone(&server_state),
                    kad_firewall: Arc::clone(&kad_firewall),
                },
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
            kad_firewall: Arc::clone(&kad_firewall),
            nat,
            shutdown,
            server_reconnect_signal,
            target_server_endpoint,
            kad_firewall_recheck,
            tasks,
            download_tasks: Arc::clone(&self.ed2k_download_tasks),
        });
        drop(runtime_guard);
        self.queue_ed2k_shared_catalog_publish();
        Ok(self.ed2k_status().await)
    }

    pub async fn disconnect_ed2k(&self) -> NetworkStatus {
        // Drop the reask detach handle so post-disconnect downloads stay on TCP
        // and the closed command channel lets the (aborted) loop wind down.
        *self.ed2k_reask_handle.lock().unwrap() = None;
        // FIX (detached-reask lease leak): release every outstanding download
        // source lease. Sources detached onto the reask loop free their lease only
        // via a SourceReleased event, which is never emitted when the loop breaks
        // on shutdown / command-channel close; without this reset those endpoints
        // would stay leased across reconnect and acquire_*_leases would defer them
        // forever. Safe (no race): disconnect fully tears the stack down before any
        // reconnect rebuilds it.
        {
            let mut state = self.state.lock().await;
            for endpoint in state.download_source_registry.reset_leases() {
                state.active_download_peer_endpoints.remove(&endpoint);
            }
        }
        if let Some(runtime) = self.ed2k_runtime.lock().await.take() {
            runtime.shutdown.store(true, Ordering::SeqCst);
            for task in runtime.tasks {
                task.abort();
            }
            // Abort this session's detached background-download tasks (FIX B3) so
            // downloads do not survive disconnect or orphan on shutdown.
            runtime.download_tasks.lock().await.abort_all();
            // WHY: REST disconnect must not hang behind network cleanup after a failed
            // server dial; the runtime has already been removed and tasks aborted.
            let _ = tokio::time::timeout(Duration::from_secs(2), runtime.nat.stop()).await;
        }
        self.ed2k_status().await
    }

    pub async fn server(&self, endpoint: &str) -> Option<ServerInfo> {
        self.servers()
            .await
            .into_iter()
            .find(|server| server.endpoint.eq_ignore_ascii_case(endpoint))
    }

    pub async fn add_server(&self, request: ServerCreate) -> Result<ServerInfo> {
        let endpoint = server_endpoint_from_create(&request)?;
        let connection = self.ed2k_server_connection_view().await;
        let mut server = server_info_from_parts(
            &request.address,
            request.port,
            request.name.as_deref(),
            None,
            request.static_server.unwrap_or(false),
            connection.0.as_deref(),
            connection.1.as_deref(),
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
        {
            let mut state = self.state.lock().await;
            state.servers.remove(&server.endpoint);
            state.server_overrides.remove(&server.endpoint);
            state.disabled_servers.insert(server.endpoint.clone());
        }
        if server.current {
            self.disconnect_ed2k().await;
        }
        Ok(Some(server))
    }

    /// Merge servers discovered from an `OP_SERVERLIST` reply into the server
    /// store (eMule `CServerSocket::ProcessPacket` OP_SERVERLIST -> AddServer).
    /// New `(ip, port)` servers are added at low priority; existing ones (by
    /// endpoint, including config + dynamic + disabled) are skipped. A
    /// previously dead-dropped server is NOT silently re-added: it stays in
    /// `disabled_servers` so we do not re-add what we just dropped.
    async fn merge_discovered_ed2k_servers(&self, servers: Vec<(Ipv4Addr, u16)>) {
        if servers.is_empty() {
            return;
        }
        // eMule `CServerSocket::ProcessPacket` OP_SERVERLIST adds advertised
        // servers only when `thePrefs.GetAddServersFromServer()` is set (default
        // on). Honor the same preference so an operator can turn auto-add off.
        if !self.state.lock().await.preferences.add_servers_from_server {
            return;
        }
        let existing: HashSet<String> = self
            .servers()
            .await
            .into_iter()
            .map(|server| server.endpoint)
            .collect();
        let disabled: HashSet<String> = {
            let state = self.state.lock().await;
            state.disabled_servers.clone()
        };
        let connection = self.ed2k_server_connection_view().await;
        let mut added = 0usize;
        for (ip, port) in servers {
            if port == 0 {
                continue;
            }
            let endpoint = format!("{ip}:{port}");
            if existing.contains(&endpoint) || disabled.contains(&endpoint) {
                continue;
            }
            let mut server = server_info_from_parts(
                &ip.to_string(),
                port,
                None,
                None,
                false,
                connection.0.as_deref(),
                connection.1.as_deref(),
            );
            server.priority = "low".to_string();
            if profile_state::persist_server(&self.metadata_store, &server, true).is_err() {
                continue;
            }
            let mut state = self.state.lock().await;
            state.disabled_servers.remove(&endpoint);
            state.servers.insert(endpoint, server);
            drop(state);
            added += 1;
        }
        if added > 0 {
            tracing::info!("added {added} ED2K server(s) discovered via OP_SERVERLIST");
        }
    }

    /// Resolve a feedback-event endpoint (which may be the configured host:port
    /// or the resolved ip:port) to the matching stored server endpoint key.
    async fn resolve_server_event_endpoint(&self, endpoint: &str) -> Option<String> {
        let servers = self.servers().await;
        // Exact endpoint match first.
        if let Some(server) = servers
            .iter()
            .find(|server| server.endpoint.eq_ignore_ascii_case(endpoint))
        {
            return Some(server.endpoint.clone());
        }
        // Fall back to matching the resolved host:port against each server's
        // configured address (handles a DNS-named server whose event carries the
        // resolved IP, or vice versa, when the literal forms differ).
        let (event_host, event_port) = parse_server_endpoint(endpoint).ok()?;
        servers
            .into_iter()
            .find(|server| {
                server.port == event_port
                    && (server.address == event_host || server.ip == event_host)
            })
            .map(|server| server.endpoint)
    }

    /// Increment a server's consecutive-failure count and drop a non-static dead
    /// server at the `dead_server_retries` threshold (eMule
    /// `CServerList::ServerStats`: `IncFailedCount` + RemoveServer when
    /// `GetFailedCount() >= GetDeadServerRetries()`). Static servers are kept.
    async fn note_ed2k_server_connect_failed(&self, endpoint: &str, dead_server_retries: u32) {
        let Some(stored_endpoint) = self.resolve_server_event_endpoint(endpoint).await else {
            return;
        };
        let Some(mut server_info) = self.server(&stored_endpoint).await else {
            return;
        };
        let threshold = dead_server_retries.max(1);
        let (fail_count, reached) = {
            let mut state = self.state.lock().await;
            let count = state
                .server_fail_counts
                .entry(stored_endpoint.clone())
                .or_insert(0);
            *count += 1;
            let fail_count = *count;
            // Reflect the live fail-count in the dynamic store / REST view.
            if let Some(server) = state.servers.get_mut(&stored_endpoint) {
                server.failed_count = fail_count;
            }
            (fail_count, fail_count >= threshold)
        };
        if reached && !server_info.static_server {
            // eMule drops a dead non-static server from the list.
            server_info.failed_count = fail_count;
            let _ = profile_state::persist_server(&self.metadata_store, &server_info, false);
            let mut state = self.state.lock().await;
            state.servers.remove(&stored_endpoint);
            state.server_overrides.remove(&stored_endpoint);
            state.server_fail_counts.remove(&stored_endpoint);
            state.disabled_servers.insert(stored_endpoint.clone());
            drop(state);
            tracing::info!(
                "dropped dead ED2K server {stored_endpoint} (fail_count={fail_count} >= dead_server_retries={threshold})"
            );
        } else {
            tracing::debug!(
                "ED2K server {stored_endpoint} connect failed (fail_count={fail_count}, static={})",
                server_info.static_server
            );
        }
    }

    /// Clear a server's failure count after a successful connect (eMule resets the
    /// count on a successful response/connect).
    async fn note_ed2k_server_connect_succeeded(&self, endpoint: &str) {
        let Some(stored_endpoint) = self.resolve_server_event_endpoint(endpoint).await else {
            return;
        };
        let mut state = self.state.lock().await;
        state.server_fail_counts.remove(&stored_endpoint);
        if let Some(server) = state.servers.get_mut(&stored_endpoint) {
            server.failed_count = 0;
        }
    }

    pub async fn create_search(&self, request: SearchCreate) -> Result<Search> {
        let now = Utc::now();
        // Local index results are cheap, so include them immediately.
        let indexed = self.index.lock().await.search(&request.query, 200)?;
        let mut state = self.state.lock().await;
        let (search_id, next_search_id) =
            search_state::allocate_search_id(&state.searches, state.next_search_id)?;
        state.next_search_id = next_search_id;
        let mut results = Vec::new();
        results.extend(
            indexed
                .into_iter()
                .map(|file| search_result_from_indexed(&search_id, &request, file)),
        );
        apply_search_filters(&mut results, &request);
        // Network methods go through the connection-aware queue (operator
        // directive 2026-07-06): a search submitted while its backend is still
        // connecting/absent is QUEUED with an honest status+reason and drains
        // automatically when the backend is ready — it is never fired into a
        // stale handle and never silently "completed" with local-only results.
        // Non-network methods (or no eD2k network configured at all) keep the
        // immediate running->completed local-index path.
        let queue_lane = self
            .ed2k_network
            .as_ref()
            .and_then(|_| SearchQueueLane::for_method(&request.method));
        let mut spawn_drain = false;
        if let Some(lane) = queue_lane {
            let mut queue = self.search_queue.lock().unwrap();
            if let Err(error) =
                queue.enqueue(search_id.clone(), request.clone(), lane, Instant::now())
            {
                // Explicit POST rejection (duplicate / queue full) — the
                // allocated id is simply skipped, never inserted.
                crate::diag_sched::keyword_search_queue(
                    "rejected",
                    &request.method,
                    Some(match error {
                        search_queue::SearchEnqueueError::DuplicateQueued => "duplicate-queued",
                        search_queue::SearchEnqueueError::QueueFull => "queue-full",
                    }),
                    0,
                );
                bail!("{error}");
            }
            spawn_drain = queue.claim_drain_task();
            crate::diag_sched::keyword_search_queue(
                "queued",
                &request.method,
                Some(lane.waiting_reason()),
                0,
            );
        }
        // Create the search and return immediately; the network part runs via
        // the queue drain (or the legacy background task) and flips the status
        // queued->running->completed. This keeps the eMuleBB contract's
        // running->complete lifecycle: controllers (e.g. aMuTorrent) get a
        // prompt POST and poll GET for results; "queued" is an additive state
        // consumers treat like running (poll until "complete").
        let (status, status_reason) = match queue_lane {
            Some(lane) => ("queued", Some(lane.waiting_reason().to_string())),
            None => ("running", None),
        };
        let search = Search {
            id: search_id.clone(),
            query: request.query.clone(),
            method: request.method.clone(),
            r#type: request.r#type.clone(),
            status: status.to_string(),
            status_reason,
            created_at: now,
            updated_at: now,
            results,
        };
        search_state::persist_search(&self.metadata_store, &search)?;
        state.searches.insert(search_id.clone(), search.clone());
        drop(state);
        if queue_lane.is_some() {
            if spawn_drain {
                self.spawn_search_queue_drain();
            }
        } else {
            let core = self.clone();
            tokio::spawn(async move {
                core.run_background_search(search_id, request).await;
            });
        }
        Ok(search)
    }

    /// Legacy immediate path for NON-QUEUED searches (unknown methods, or no
    /// eD2k network configured): resolves the live network method, runs any
    /// applicable network search, and completes the search with whatever the
    /// local index already provided. Network methods never reach this path —
    /// they go through the connection-aware queue (`search_queue_runtime`).
    async fn run_background_search(&self, search_id: String, request: SearchCreate) {
        let ed2k_connected = self.connected_ed2k_search_handle().await.is_some();
        let kad_connected = self
            .ed2k_dht_node()
            .await
            .is_some_and(|dht| dht.is_bootstrapped());
        let network_method =
            resolve_search_network_method(&request.method, ed2k_connected, kad_connected);
        let method_str = match network_method {
            Some(SearchNetworkMethod::Ed2kServer) => "server",
            Some(SearchNetworkMethod::Ed2kGlobal) => "global",
            Some(SearchNetworkMethod::Kad) => "kad",
            None => "none",
        };
        let outcome = match network_method {
            Some(SearchNetworkMethod::Ed2kServer | SearchNetworkMethod::Ed2kGlobal) => self
                .search_ed2k_servers(&search_id, &request, network_method)
                .await
                .map(|outcome| match outcome {
                    Ed2kServerSearchOutcome::Completed(results) => Some(results),
                    Ed2kServerSearchOutcome::Unavailable
                    | Ed2kServerSearchOutcome::NotConnected => None,
                }),
            Some(SearchNetworkMethod::Kad) => match self.ed2k_dht_node().await {
                Some(dht) => search_kad_keywords(dht, &search_id, &request).await,
                None => Ok(None),
            },
            None => Ok(None),
        };
        match outcome {
            Ok(network_results) => {
                self.complete_search_with_results(
                    &search_id,
                    &request,
                    method_str,
                    network_results,
                )
                .await;
            }
            Err(error) => {
                tracing::warn!("background search failed for {search_id}: {error:#}");
                self.fail_search(&search_id, &request, method_str, "network-search-failed")
                    .await;
            }
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
        category_runtime::categories(&self.state).await
    }

    pub async fn category(&self, category_id: u32) -> Option<Category> {
        category_runtime::category(&self.state, category_id).await
    }

    pub async fn create_category(&self, request: CategoryCreate) -> Result<Category> {
        category_runtime::create_category(&self.state, &self.metadata_store, request).await
    }

    pub async fn update_category(
        &self,
        category_id: u32,
        request: CategoryUpdate,
    ) -> Result<Option<Category>> {
        category_runtime::update_category(&self.state, &self.metadata_store, category_id, request)
            .await
    }

    pub async fn delete_category(&self, category_id: u32) -> Result<Option<Category>> {
        category_runtime::delete_category(
            &self.state,
            &self.metadata_store,
            &self.ed2k_transfers,
            category_id,
        )
        .await
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
        self.ed2k_transfers
            .remove_completed_transfer_row(&summary.file_hash)
            .await?;
        self.state.lock().await.transfers.remove(&summary.file_hash);
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
        self.queue_ed2k_shared_catalog_publish();
        Ok(local_share_from_summary(summary))
    }

    pub async fn shares(&self) -> Vec<LocalShare> {
        match self.ed2k_transfers.share_entries().await {
            Ok(entries) => entries
                .into_iter()
                .map(|entry| self.local_share_from_entry(entry))
                .collect(),
            Err(error) => {
                tracing::warn!("failed to enumerate ED2K shared-file summaries: {error}");
                Vec::new()
            }
        }
    }

    pub async fn shares_page(&self, offset: usize, limit: usize) -> (Vec<LocalShare>, usize) {
        match self.ed2k_transfers.share_entries_page(offset, limit).await {
            Ok((entries, total)) => (
                entries
                    .into_iter()
                    .map(|entry| self.local_share_from_entry(entry))
                    .collect(),
                total,
            ),
            Err(error) => {
                tracing::warn!("failed to enumerate ED2K shared-file summary page: {error}");
                (Vec::new(), 0)
            }
        }
    }

    fn local_share_from_entry(&self, entry: MetadataTransferShareEntry) -> LocalShare {
        LocalShare {
            hash: entry.file_hash.clone(),
            name: entry.canonical_name.clone(),
            size_bytes: entry.file_size,
            part_count: entry.part_count,
            ed2k_link: format!(
                "ed2k://|file|{}|{}|{}|/",
                entry.canonical_name, entry.file_size, entry.file_hash
            ),
            aich_root: entry.aich_root.clone().unwrap_or_default(),
            transfer_dir: self
                .ed2k_transfers
                .transfer_dir_path(&entry.file_hash)
                .display()
                .to_string(),
            source_path: entry.source_path.clone(),
            priority: entry.upload_priority.clone(),
            auto_upload_priority: entry.auto_upload_priority,
            all_time_uploaded_bytes: entry.all_time_uploaded_bytes,
            all_time_upload_requests: entry.all_time_upload_requests,
            all_time_upload_accepts: entry.all_time_upload_accepts,
            comment: entry.comment.clone(),
            rating: entry.rating,
        }
    }

    pub async fn shared_catalog_count(&self) -> usize {
        self.ed2k_transfers.shared_catalog_count().await
    }

    pub fn kad_publish_diagnostics(&self) -> KadPublishDiagnostics {
        kad_publish_diagnostics::snapshot(&self.kad_publish_diagnostics)
    }

    pub fn ed2k_publish_diagnostics(&self) -> Ed2kPublishDiagnostics {
        ed2k_publish_diagnostics::snapshot(&self.ed2k_publish_diagnostics)
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
        self.queue_ed2k_shared_catalog_publish();
        Ok(self.share(hash).await)
    }

    pub async fn unshare_file(&self, hash: &str) -> Result<Option<LocalShare>> {
        let Some(share) = self.share(hash).await else {
            return Ok(None);
        };
        self.ed2k_transfers
            .remove_completed_transfer_row(&share.hash)
            .await?;
        self.ed2k_transfers
            .remove_verified_catalog_entry(&share.hash)
            .await;
        ensure!(
            self.metadata_store
                .mark_unshared_file(&share.hash, "manual")?,
            "shared file metadata row is missing"
        );
        let mut state = self.state.lock().await;
        state.transfers.remove(&share.hash);
        state.unshared_hashes.insert(share.hash.clone());
        self.queue_ed2k_shared_catalog_publish();
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
        let items = shared_directory_items(roots.clone()).await;
        let monitor_owned = items
            .iter()
            .filter(|item| item.monitor_owned)
            .map(|item| item.path.clone())
            .collect::<Vec<_>>();
        SharedDirectories {
            roots,
            items,
            monitor_owned,
            // Files still pending the initial hash in the background reload worker.
            hashing_count: shared_directories::hashing_count_snapshot(self),
            reload: reload_diagnostics_snapshot(self),
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
        // Re-establish the live auto-pickup watch set for the new roots (it stops
        // the previous monitor first), matching eMule re-monitoring on reconfigure.
        // The monitor only auto-picks-up *newly arriving* files; files already
        // present under the new roots still need the initial hash, so kick a
        // detached background scan + hash (progress in `hashingCount`).
        self.start_shared_directory_monitor().await;
        self.reload_shared_directories_detached().await?;
        Ok(self.shared_directories().await)
    }

    /// Synchronous core primitive: scan + hash + share the whole library, blocking
    /// until fully indexed. Thin entry to `shared_directories`.
    pub async fn reload_shared_directories(&self) -> Result<Vec<LocalShare>> {
        shared_directories::reload_shared_directories(self).await
    }

    /// Kick the full scan + hash on a detached background task; returns the queued
    /// file count immediately. Thin entry to `shared_directories`.
    pub async fn reload_shared_directories_detached(&self) -> Result<usize> {
        shared_directories::reload_shared_directories_detached(self).await
    }

    /// (Re)start the live shared-directory auto-pickup monitor (eMule directory
    /// auto-monitor parity); thin entry to `shared_dir_monitor`. Must run inside
    /// a tokio runtime (it spawns the consumer task).
    pub async fn start_shared_directory_monitor(&self) {
        shared_dir_monitor::start_shared_directory_monitor(self).await;
    }

    /// Stop the live shared-directory monitor (if running). Idempotent.
    pub fn stop_shared_directory_monitor(&self) {
        shared_dir_monitor::stop_shared_directory_monitor(self);
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

    /// Re-read the configured `ipfilter.dat` and swap it into the live shared
    /// `IpFilter`, mirroring `CIPFilter::Reload`. Because the `IpFilter` backing
    /// is shared across every clone (listener, Kad traversal closure, UDP reask
    /// loop, source-add gate), the new ranges take effect immediately without a
    /// restart. Returns the number of ranges loaded, or `None` when no eD2k
    /// network / ipfilter path is configured.
    pub fn reload_ip_filter(&self) -> Result<Option<usize>> {
        let Some(network) = self.ed2k_network.as_ref() else {
            return Ok(None);
        };
        let Some(path) = network.ip_filter_path.as_ref() else {
            return Ok(None);
        };
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read ipfilter.dat at {}", path.display()))?;
        network
            .ip_filter
            .reload_from(&body, network.ip_filter_level);
        Ok(Some(network.ip_filter.len()))
    }

    pub async fn ban_upload_client(&self, client_id: &str) -> Result<Option<bool>> {
        let Some(upload) = self.upload_client_for_control(client_id).await else {
            return Ok(None);
        };
        // Back the manual ban with the enforced ban store (IP + user hash, 4h
        // CLIENTBANTIME TTL) so it is actually rejected at accept/connect/source
        // add, mirroring eMule's `CUpDownClient::Ban` (UploadClient.cpp:1042 ->
        // CClientList::AddBannedClient).
        self.ed2k_transfers.ban_client(
            parse_ban_ip(&upload.address),
            parse_ban_hash(upload.user_hash.as_deref()),
        );
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
        let hash = parse_ban_hash(upload.user_hash.as_deref());
        self.ed2k_transfers
            .ban_store()
            .unban(parse_ban_ip(&upload.address), hash.as_ref());
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
            self.ed2k_transfers
                .set_category_id(hash, category_id)
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
        // Back the manual source ban with the enforced ban store (IP + user
        // hash, 4h TTL) so the source is rejected on the next connect / source
        // add (eMule CUpDownClient::Ban).
        self.ed2k_transfers.ban_client(
            parse_ban_ip(&source.ip),
            parse_ban_hash(source.user_hash.as_deref()),
        );
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
        let user_hash = parse_ban_hash(source.user_hash.as_deref());
        self.ed2k_transfers
            .ban_store()
            .unban(parse_ban_ip(&source.ip), user_hash.as_ref());
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
        // Cancel any in-flight download attempt before re-verifying so the recheck
        // does not race a live piece write for the same hash (state flap; the
        // manifest IO is serialized so there is no corruption, but the recheck
        // must observe a settled on-disk state). The attempt stops at its next
        // cancel check; if recheck finds the transfer still wants data it re-queues
        // a fresh attempt below.
        self.cancel_download_attempt(hash).await;
        // Mark hashing while the on-disk parts are re-verified (oracle forces a
        // full part re-hash on recheck; CPartFile::HashSinglePart per part).
        self.set_transfer_state(hash, "hashing").await;
        // Drive the real re-verification: re-read every part from disk and
        // MD4-check it against the hashset, rewriting piece states + verified
        // ranges + the completed flag (and demoting any corrupted part to Missing
        // so it is re-downloaded). The piece store owns the manifest lock + IO.
        let recheck = self.ed2k_transfers.recheck_transfer(hash).await;
        // Re-derive the public transfer state from the freshly-rewritten manifest
        // (completed -> "completed"; otherwise downloading/queued), regardless of
        // success, so the transfer never gets stuck in "hashing".
        let refreshed = self.refresh_transfer_from_manifest_default(hash).await;
        recheck?;
        match refreshed? {
            Some(transfer) => {
                // If the recheck found corruption (now not complete but with
                // progress), re-engage the download so the demoted parts refetch.
                if transfer.state == "downloading" {
                    self.queue_ed2k_download_attempt(transfer);
                } else if transfer.state == "completed" {
                    // A recheck that confirms a complete file delivers it by name
                    // (covers a manually-rechecked transfer that was never driven
                    // through the download-completion path).
                    self.deliver_completed_transfer(hash).await;
                }
                Ok(Some(()))
            }
            None => Ok(None),
        }
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
        self.delete_delivered_transfer_file(hash, &transfer).await?;
        if !self.ed2k_transfers.delete_transfer_files(hash).await? {
            return Ok(None);
        }
        self.metadata_store.unmark_unshared_file(hash)?;
        // Cancel any in-flight attempt and free everything it holds for this hash
        // (candidates, leases, active endpoints, the dedup + cancel slots) so the
        // orphan attempt stops churning peers and the hash can be re-created and
        // re-download immediately instead of early-returning on a stale dedup slot.
        self.teardown_download_for_delete(hash).await;
        let mut state = self.state.lock().await;
        state.transfers.remove(hash);
        state.unshared_hashes.remove(hash);
        Ok(Some(transfer))
    }

    async fn delete_delivered_transfer_file(&self, hash: &str, transfer: &Transfer) -> Result<()> {
        let delivered_path = match self.ed2k_transfers.manifest(hash).await {
            Ok(manifest) => {
                if manifest.source_path.is_some() {
                    None
                } else {
                    manifest.delivered_path
                }
            }
            Err(_) => transfer.delivered_path.clone(),
        };
        let Some(path) = delivered_path.as_deref() else {
            return Ok(());
        };
        let path = Path::new(path);
        let long = long_path(path);
        match tokio::fs::remove_file(&long).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to delete delivered transfer file {}",
                    path.display()
                )
            }),
        }
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
        let snapshots = self
            .ed2k_transfers
            .upload_queue_snapshot()
            .await
            .into_iter()
            .filter(|entry| {
                matches!(entry.phase, Ed2kUploadSessionPhaseSnapshot::Waiting) == waiting_queue
            })
            .collect::<Vec<_>>();
        let mut uploads = Vec::with_capacity(snapshots.len());
        for entry in snapshots {
            let manifest = match self.ed2k_transfers.manifest(&entry.file_hash).await {
                Ok(manifest) => Some(manifest),
                Err(error) => {
                    tracing::warn!(
                        hash = %entry.file_hash,
                        "failed to hydrate ED2K manifest for upload snapshot: {error}"
                    );
                    None
                }
            };
            uploads.push(upload_from_snapshot(entry, manifest.as_ref()));
        }
        uploads
    }

    async fn upload_client_for_control(&self, client_id: &str) -> Option<Upload> {
        if let Some(upload) = self.upload(client_id, false).await {
            return Some(upload);
        }
        self.upload(client_id, true).await
    }

    fn transfer_from_manifest(&self, manifest: &Ed2kResumeManifest, state_name: &str) -> Transfer {
        let parts_total = manifest.pieces.len() as u32;
        // A share-in-place file lives at (and is served from) its original path;
        // a real download reports its internal piece-store payload path.
        let mut transfer = transfer_from_manifest(
            manifest,
            state_name,
            manifest.source_path.clone().unwrap_or_else(|| {
                self.ed2k_transfers
                    .payload_path(&manifest.file_hash)
                    .display()
                    .to_string()
            }),
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
        // Classify "completed download" vs "shared-only file" by directory (eMule
        // semantics, unlike qBittorrent where every complete torrent is also a
        // share). A transfer is a download if it is still downloading, was
        // delivered to an incoming/category dir (`delivered_path` set), or its
        // file resides in the global incoming dir -- which may itself double as a
        // configured shared dir (e.g. the eMule Incoming folder). A file that is
        // only shared from a shared dir (and never downloaded) stays false.
        transfer.in_incoming = !manifest.completed
            || manifest.delivered_path.is_some()
            || path_is_within(&transfer.path, &self.incoming_dir);
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
        // Pause/stop must stop the transfer NOW: the driver does not read
        // control_state mid-attempt, so without this an in-flight attempt keeps
        // connecting peers and writing pieces through the rest of the current
        // round and only the next retry is suppressed. Cancel the in-flight
        // attempt so it stops at its next loop-top/mid-round check. Resume
        // re-queues a fresh attempt (its cancel token is recreated then).
        self.cancel_download_attempt(hash).await;
        let mut transfer = self.transfer_from_manifest(&manifest, state_name);
        let mut state = self.state.lock().await;
        apply_persisted_transfer_category(&mut transfer, &manifest, &state.categories);
        if let Some(existing) = state.transfers.get(&transfer.hash) {
            preserve_transfer_public_metadata(&mut transfer, existing);
        }
        state
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
        self.queue_ed2k_download_attempt(transfer.clone());
        Ok(Some(transfer))
    }

    /// Startup download hydration: load persisted INCOMPLETE downloads into the
    /// in-memory transfer set and queue a download attempt for each, so in-progress
    /// downloads resume after a restart. Mirrors the fact that the MFC oracle's
    /// `CDownloadQueue` resumes every incomplete `.part` file on launch. Without
    /// this, `state.transfers` starts empty (`profile_state.rs`) and every persisted
    /// partial download is abandoned across restarts (evidence: 39 multi-GB partials
    /// stranded on a single restart). Returns the number resumed.
    ///
    /// Skips: completed transfers (delivered/shared, not downloads), user
    /// paused/stopped transfers (`control_state`), share-in-place shared files
    /// (`source_path` set — served from their original path, not downloaded), and
    /// any transfer already present in memory (a REST resume racing startup).
    pub async fn resume_persisted_downloads(&self) -> usize {
        // Load ONLY the incomplete rows, off the async runtime (spawn_blocking) — see
        // `incomplete_manifests`. Loading the full library inline (`manifests`) blocks
        // a tokio worker and starves REST at startup.
        let manifests = match self.ed2k_transfers.incomplete_manifests().await {
            Ok(manifests) => manifests,
            Err(error) => {
                tracing::warn!(
                    "startup download hydration: failed to list persisted transfers: {error:#}"
                );
                return 0;
            }
        };
        // Resume GRADUALLY. Queuing dozens of downloads at once (39 observed on the
        // soak profile) thunder-herds the state lock and the source coordinator on
        // top of the large-library shared reload, starving REST at startup (the
        // control plane wedged in a live test). Let the post-connect startup burst
        // settle, then stagger each resume — eMule's CDownloadQueue likewise drives
        // incomplete files a few at a time, not all in one tick.
        tokio::time::sleep(Duration::from_secs(RESUME_DOWNLOADS_INITIAL_DELAY_SECS)).await;
        let mut resumed = 0usize;
        for manifest in manifests {
            if manifest.completed
                || manifest.source_path.is_some()
                || matches!(
                    manifest.control_state.as_deref(),
                    Some("paused") | Some("stopped")
                )
            {
                continue;
            }
            let mut transfer = self.transfer_from_manifest(&manifest, "downloading");
            {
                let mut state = self.state.lock().await;
                if state.transfers.contains_key(&transfer.hash) {
                    continue;
                }
                apply_persisted_transfer_category(&mut transfer, &manifest, &state.categories);
                state
                    .transfers
                    .insert(transfer.hash.clone(), transfer.clone());
            }
            self.queue_ed2k_download_attempt(transfer);
            resumed = resumed.saturating_add(1);
            tokio::time::sleep(Duration::from_millis(RESUME_DOWNLOADS_STAGGER_MS)).await;
        }
        if resumed > 0 {
            tracing::info!(
                "startup download hydration: resumed {resumed} persisted incomplete downloads (staggered)"
            );
        }
        resumed
    }

    pub async fn index_file(&self, file: IndexedFile) -> Result<()> {
        self.index.lock().await.upsert_file(&file)
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
        if let Some((category_id, _)) = category.as_ref() {
            manifest = self
                .ed2k_transfers
                .set_category_id(&manifest.file_hash, *category_id)
                .await?;
        }
        let effective_state_name = if manifest.completed {
            manifest_default_state_name(&manifest)
        } else {
            state_name
        };
        let mut transfer = self.transfer_from_manifest(&manifest, effective_state_name);
        let mut state = self.state.lock().await;
        apply_persisted_transfer_category(&mut transfer, &manifest, &state.categories);
        if let Some(existing) = state.transfers.get(&transfer.hash) {
            preserve_transfer_public_metadata(&mut transfer, existing);
        }
        if let Some((category_id, category_name)) = category {
            transfer.category_id = category_id;
            transfer.category_name = category_name;
        }
        state
            .transfers
            .insert(transfer.hash.clone(), transfer.clone());
        drop(state);
        // Non-paused downloads start immediately: kick the download driver so
        // ED2K source acquisition begins without requiring an explicit resume.
        if !manifest.completed && !matches!(effective_state_name, "paused" | "stopped") {
            self.queue_ed2k_download_attempt(transfer.clone());
        }
        Ok(transfer)
    }

    async fn refresh_transfer_from_manifest(
        &self,
        hash: &str,
        state_name: &str,
    ) -> Result<Option<Transfer>> {
        let manifest = self.ed2k_transfers.manifest(hash).await?;
        let mut transfer = self.transfer_from_manifest(&manifest, state_name);
        let mut state = self.state.lock().await;
        apply_persisted_transfer_category(&mut transfer, &manifest, &state.categories);
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
        apply_persisted_transfer_category(&mut transfer, &manifest, &state.categories);
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
        ensure!(
            !category_name.is_empty(),
            "categoryName does not match a configured category"
        );
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
        network_method: Option<SearchNetworkMethod>,
    ) -> Result<Ed2kServerSearchOutcome> {
        if !matches!(
            network_method,
            Some(SearchNetworkMethod::Ed2kServer | SearchNetworkMethod::Ed2kGlobal)
        ) {
            return Ok(Ed2kServerSearchOutcome::Unavailable);
        }
        let Some(network) = self.ed2k_network.as_ref() else {
            return Ok(Ed2kServerSearchOutcome::Unavailable);
        };
        let config = self.effective_ed2k_config(&network.config, None).await?;
        if config.server_entries.is_empty() && config.server_endpoints.is_empty() {
            return Ok(Ed2kServerSearchOutcome::Unavailable);
        }

        let cancel = CancellationToken::new();
        // WHY: stock eMule/eMuleBB sends keyword searches through the current
        // server connection; opening ad-hoc TCP logins here creates non-stock
        // public-server traffic and repeats the source-search storm pattern.
        let Some(handle) = self.connected_ed2k_search_handle().await else {
            // WHY: distinct from Unavailable so the queued path can retry when
            // a session comes back — the old Ok(None) here is exactly what let
            // a search "complete" in <100ms with zero wire traffic.
            return Ok(Ed2kServerSearchOutcome::NotConnected);
        };
        let connected_server_endpoint = self.connected_ed2k_server_endpoint().await;
        let timeout = connected_server_keyword_search_timeout(&config);
        let criteria = search_criteria_from_request(request);
        let mut files = Vec::new();
        match search_keyword_via_background_session(
            &handle,
            &request.query,
            criteria,
            timeout,
            &cancel,
        )
        .await
        {
            Ok(background_files) => {
                if background_files.is_empty() {
                    tracing::warn!(
                        "ED2K background keyword search returned no results query={:?}",
                        request.query
                    );
                } else {
                    files.extend(background_files);
                }
            }
            // WHY: an interrupted send (stale handle / session dropped before
            // answering) must PROPAGATE so the queue re-queues the search; the
            // old warn-and-continue path reported it completed-empty instead.
            Err(error)
                if error
                    .downcast_ref::<Ed2kBackgroundSearchInterrupted>()
                    .is_some() =>
            {
                return Err(error);
            }
            Err(error) => tracing::warn!(
                "ED2K background keyword search failed query={:?} error={error}",
                request.query
            ),
        }
        if matches!(network_method, Some(SearchNetworkMethod::Ed2kGlobal)) {
            match search_keyword_udp_servers(Ed2kUdpKeywordSearchOptions {
                bind_ip: network.bind_ip,
                config: &config,
                excluded_endpoint: connected_server_endpoint,
                max_attempts: configured_server_attempts(&config),
                query: &request.query,
                timeout,
                cancel: &cancel,
            })
            .await
            {
                Ok(global_files) => files.extend(global_files),
                Err(error) => tracing::warn!(
                    "ED2K global UDP keyword search failed query={:?} error={error}",
                    request.query
                ),
            }
        }
        let mut seen_hashes = HashSet::new();
        Ok(Ed2kServerSearchOutcome::Completed(
            files
                .into_iter()
                .filter(|file| seen_hashes.insert(file.file_hash))
                .map(|file| search_result_from_ed2k(search_id, request, file))
                .collect(),
        ))
    }

    #[allow(clippy::cognitive_complexity)]
    async fn run_ed2k_download_attempt(
        &self,
        transfer: &Transfer,
        cancel: &CancellationToken,
    ) -> Result<Option<&'static str>> {
        // Already cancelled before any work started (delete/pause raced the
        // queue): do nothing, don't touch state, don't retry.
        if cancel.is_cancelled() {
            return Ok(None);
        }
        let Some(network) = self.ed2k_network.as_ref() else {
            return Ok(Some("queued"));
        };
        if network.config.server_entries.is_empty() && network.config.server_endpoints.is_empty() {
            return Ok(Some("queued"));
        }
        // Disk free-space floor: pause before engaging sources when the transfer
        // volume cannot hold the remaining payload, instead of failing late
        // mid-write and churn-retrying.
        if self
            .should_pause_download_for_disk_space(&transfer.hash)
            .await
        {
            tracing::warn!(
                "ED2K download paused: insufficient free space for {} on {}",
                transfer.hash,
                self.transfer_root.display()
            );
            return Ok(Some("paused"));
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
            .acquire_ed2k_sources(
                network,
                &transfer,
                file_hash,
                transfer.size_bytes,
                should_refresh_ed2k_server_sources(0),
            )
            .await?;
        if !network.ip_filter.is_empty() {
            sources.retain(|source| !network.ip_filter.is_filtered(source.ip));
        }
        // Drop banned sources before connecting (eMule CDownloadQueue::CheckAndAddSource
        // / PartFile.cpp:3239,4812 IsBannedClient gate on source add/merge), keyed by
        // both the source IP and its advertised user hash with the 4h TTL.
        let ban_store = self.ed2k_transfers.ban_store();
        sources.retain(|source| !ban_store.is_banned(Some(source.ip), source.user_hash.as_ref()));
        if sources.is_empty() {
            return Ok(Some("downloading"));
        }
        self.register_download_source_candidates(&transfer, &sources)
            .await;
        let hello_identity = self.ed2k_hello_identity(network);
        // Direct peer connect stays conservative (~15s); the LowID callback wait
        // gets eMule's full reach (ClientList.cpp:1059 SEC2MS(45)) so a firewalled
        // source has time to connect back.
        let timeout = Duration::from_secs(network.config.connect_timeout_secs.max(10));
        let callback_timeout = Duration::from_secs(
            network
                .config
                .callback_timeout_secs
                .max(network.config.connect_timeout_secs),
        );
        let max_peers = network.config.max_parallel_download_peers.max(1);
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
            // Per-hash cancel check at the top of each requery round: delete /
            // pause / stop / recheck signal this token to stop the in-flight
            // attempt promptly (rather than running to the end of the current
            // round and only suppressing the next retry). Return Ok(None) so the
            // queued-attempt wrapper neither rewrites the transfer state nor
            // re-queues a retry; the attempt's own per-endpoint lease release on
            // exit is idempotent with any release the cancelling caller did.
            if cancel.is_cancelled() {
                return Ok(None);
            }
            sort_download_sources(&mut sources);
            // A firewalled LowID Kad source whose Kad buddy is known is reasked via
            // its buddy (OP_REASKCALLBACKUDP), not through an eD2k-server callback:
            // detach it straight onto the UDP reask loop (oracle
            // CDownloadQueue::KademliaSearchFile types 3/5). Server-callback LowID
            // sources (no Kad buddy) keep the OP_CALLBACKREQUEST path below.
            detach_kad_buddy_sources_for_reask(
                self.ed2k_reask_handle.lock().unwrap().clone().as_ref(),
                file_hash,
                &sources,
                &mut requested_callback_sources,
            );
            // Originate the outbound Kad callback for firewalled buddy sources whose
            // buddy relay endpoint is known (oracle BaseClient.cpp CCS_KADCALLBACK):
            // the buddy relays an OP_CALLBACK so the source connects back to us. This
            // is the connection-establishing counterpart to the reask detach above
            // (which only keeps polling source availability over UDP). Its own
            // per-(source,file) cooldown map dedups it independently of the
            // requested_callback_sources set the reask/server-callback paths share.
            self.send_kad_buddy_callbacks(network, &transfer, file_hash, &sources)
                .await;
            // Originate direct UDP callbacks for firewalled type-6 sources
            // (oracle CCS_DIRECTCALLBACK, the first-preference LowID connect
            // path): send OP_DIRECTCALLBACKREQ to the source's Kad UDP endpoint
            // so it TCP-connects back to us. This precedes and excludes the
            // server-callback path below, exactly as MFC's TryToConnect orders
            // direct callback (5) before server callback (6).
            self.send_ed2k_direct_callbacks(network, &transfer, &sources)
                .await;
            let callback_only_sources = sources
                .iter()
                .filter(|source| {
                    source.low_id
                        && !source.has_kad_buddy_reask_target()
                        && !source.is_direct_callback_source()
                })
                .cloned()
                .collect::<Vec<_>>();
            let callback_cancel = CancellationToken::new();
            for source in callback_only_sources {
                if !requested_callback_sources.insert(source_key(&source)) {
                    continue;
                }
                let callback_route =
                    ed2k_server_callback_route(source.source_server, connected_server_endpoint);
                if matches!(callback_route, Ed2kServerCallbackRoute::Unavailable) {
                    tracing::debug!(
                        "ED2K server callback unavailable file_hash={} client_id={} source_server={} connected_server={}",
                        transfer.hash,
                        source.client_id,
                        source
                            .source_server
                            .map_or_else(|| "-".to_string(), |endpoint| endpoint.to_string()),
                        connected_server_endpoint
                            .map_or_else(|| "-".to_string(), |endpoint| endpoint.to_string())
                    );
                    continue;
                }
                let callback_claimed = {
                    let mut state = self.state.lock().await;
                    claim_ed2k_server_callback_request(
                        &mut state.ed2k_server_callback_last_sent,
                        source.client_id,
                        &transfer.hash,
                        Instant::now(),
                    )
                };
                if !callback_claimed {
                    tracing::debug!(
                        "ED2K server callback suppressed by cooldown file_hash={} client_id={} source_server={}",
                        transfer.hash,
                        source.client_id,
                        source
                            .source_server
                            .map_or_else(|| "-".to_string(), |endpoint| endpoint.to_string())
                    );
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
                let callback_result = match callback_route {
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
                    Ed2kServerCallbackRoute::Unavailable => Ok(()),
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
            let (direct_sources, deferred_count, deferred_retry_delay) = self
                .acquire_direct_download_source_leases(&transfer.hash, &candidate_direct_sources)
                .await;
            let acquired_direct_source_count = direct_sources.len();
            deferred_active_direct_sources |= deferred_count != 0;
            for source in &direct_sources {
                attempted_direct_endpoints.insert(source_endpoint_key(source));
            }

            if acquired_direct_source_count != 0 {
                let source_exchange_source_count = {
                    let mut state = self.state.lock().await;
                    let now = Instant::now();
                    state.download_source_registry.prune_stale_candidates(now);
                    state
                        .download_source_registry
                        .candidate_count_for_file(now, &transfer.hash)
                };
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
                                current_source_count: source_exchange_source_count,
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
                // A4AF-lite NNP swap (eMuleBB CUpDownClient::SwapToAnotherFile):
                // a source that has No Needed Parts for THIS file but serves
                // another wanted file in the registry is moved to that file
                // (its transfer is re-driven so leg-1 selection reuses the peer)
                // instead of being dropped. Sources with no other wanted file
                // fall through and stay dropped (the lease was just released).
                if !outcome.no_needed_parts_sources.is_empty() {
                    self.swap_no_needed_parts_sources(
                        &transfer.hash,
                        &outcome.no_needed_parts_sources,
                    )
                    .await;
                }
                accepted_incomplete_peers =
                    accepted_incomplete_peers.saturating_add(outcome.accepted_incomplete_peers);
                if let Some(error) = outcome.last_error {
                    last_direct_error = Some(error);
                }
            }

            // Mid-round cancel check (after the direct-download leg, before the
            // requery sleep): stop promptly on delete/pause/stop/recheck instead
            // of sleeping then requerying for a transfer that is going away.
            if cancel.is_cancelled() {
                return Ok(None);
            }
            if ed2k_download_retry::should_wait_for_deferred_direct_sources(
                acquired_direct_source_count,
                deferred_count,
            ) {
                if let Some(delay) = deferred_retry_delay {
                    tracing::info!(
                        "ED2K direct source retry deferred file_hash={} deferred_direct_sources={} retry_delay_ms={}",
                        transfer.hash,
                        deferred_count,
                        delay.as_millis()
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = cancel.cancelled() => return Ok(None),
                    }
                    continue;
                }
                break;
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
                    .acquire_ed2k_sources(
                        network,
                        &transfer,
                        file_hash,
                        transfer.size_bytes,
                        should_refresh_ed2k_server_sources(source_requery_round),
                    )
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
        let has_progress = manifest_has_ed2k_transfer_progress(&manifest);
        let retry_on_error = last_direct_error.is_some()
            && ed2k_download_retry::should_retry_after_exhausted_direct_sources(
                had_direct_sources,
                true,
            );
        // Evidence instrumentation: record WHY this attempt ended before returning,
        // so the persistent-reask behaviour is judged from the diag stream, not
        // inferred. The state string mirrors the return ladder below exactly.
        let outcome_state = if manifest.completed {
            "completed"
        } else if has_progress
            || !requested_callback_sources.is_empty()
            || deferred_active_direct_sources
            || accepted_incomplete_peers != 0
            || retry_on_error
        {
            "downloading"
        } else if last_direct_error.is_some() {
            "error"
        } else {
            "queued"
        };
        crate::diag_sched::download_attempt_outcome(
            &transfer.hash,
            outcome_state,
            sources.len(),
            had_direct_sources,
            accepted_incomplete_peers,
            requested_callback_sources.len(),
            deferred_active_direct_sources,
            has_progress,
            source_requery_round,
        );
        if manifest.completed {
            return Ok(Some("completed"));
        }
        if has_progress {
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
            if retry_on_error {
                return Ok(Some("downloading"));
            }
            return Err(error).context("ED2K direct download did not complete");
        }
        Ok(Some("queued"))
    }

    async fn acquire_direct_download_source_leases(
        &self,
        file_hash: &str,
        sources: &[Ed2kFoundSource],
    ) -> (Vec<Ed2kFoundSource>, usize, Option<Duration>) {
        let mut state = self.state.lock().await;
        let mut acquired = Vec::new();
        let mut deferred = 0usize;
        let mut deferred_retry_delay: Option<Duration> = None;
        // Opportunistic prune so the per-file count (and the candidate map) reflect
        // only live sources: stale candidates age out of the soft-cap check and the
        // map stays bounded over many requery rounds.
        let now = Instant::now();
        state.download_source_registry.prune_stale_candidates(now);
        // Per-file source cap (eMule GetMaxSourcePerFileSoft > GetSourceCount):
        // a file stops engaging new sources past its soft cap. The coordinator
        // (on the transfer runtime) owns the cap; the per-file source count
        // comes from the registry (live candidates only).
        for source in sources {
            let endpoint = source_endpoint_key(source);
            if state.active_download_peer_endpoints.contains(&endpoint) {
                // Candidate already engaged this round: a dedup skip, NOT a source
                // drop. The MFC oracle emits source_dropped only on genuine srclist
                // removal, so these skips are not surfaced (they inflated the count).
                deferred = deferred.saturating_add(1);
                continue;
            }
            let file_source_count = state
                .download_source_registry
                .candidate_count_for_file(now, file_hash);
            if !self
                .ed2k_transfers
                .can_engage_file_source(file_source_count)
            {
                // Soft cap reached: the file has enough live sources, so this
                // candidate is left un-engaged (lease released, candidate retained).
                // Not a drop — no source_dropped (oracle emits it only on removal).
                state.download_source_registry.release_peer(source);
                deferred = deferred.saturating_add(1);
                continue;
            }
            let registry_lease = state.download_source_registry.lease_best_for_file(
                now,
                ed2k_download_retry::ED2K_DIRECT_SOURCE_RETRY_COOLDOWN,
                source,
                file_hash,
            );
            if registry_lease.is_some() && state.active_download_peer_endpoints.insert(endpoint) {
                acquired.push(source.clone());
                crate::diag_sched::source_engaged(file_hash, source);
            } else {
                if let Some(delay) = state.download_source_registry.endpoint_retry_delay(
                    now,
                    ed2k_download_retry::ED2K_DIRECT_SOURCE_RETRY_COOLDOWN,
                    source,
                    file_hash,
                ) {
                    deferred_retry_delay =
                        Some(deferred_retry_delay.map_or(delay, |current| current.min(delay)));
                }
                // Lease unavailable (busy/cooldown): candidate stays for a later
                // retry, so this is a deferral, not a drop — no source_dropped.
                state.download_source_registry.release_peer(source);
                deferred = deferred.saturating_add(1);
            }
        }
        // Periodic download-source snapshot (MFC sched:source_count parity),
        // throttled to roughly the master snapshot cadence rather than firing on
        // every acquisition round. Field mapping is documented on the emitter.
        const SOURCE_COUNT_EMIT_INTERVAL: Duration = Duration::from_secs(8);
        if state
            .last_source_count_emit_at
            .is_none_or(|last| now.duration_since(last) >= SOURCE_COUNT_EMIT_INTERVAL)
        {
            let source_count = state.download_source_registry.candidate_count();
            let valid_source_count = state.download_source_registry.leased_peer_count();
            let a4af_file_count = state.download_source_registry.a4af_file_count();
            let transferring_source_count = state.active_download_peer_endpoints.len();
            crate::diag_sched::source_count(
                source_count,
                valid_source_count,
                0,
                a4af_file_count,
                transferring_source_count,
            );
            state.last_source_count_emit_at = Some(now);
        }
        (acquired, deferred, deferred_retry_delay)
    }

    async fn release_direct_download_source_leases(&self, endpoints: &[(Ipv4Addr, u16)]) {
        let mut state = self.state.lock().await;
        for endpoint in endpoints {
            state.active_download_peer_endpoints.remove(endpoint);
            state.download_source_registry.release_endpoint(*endpoint);
        }
    }

    /// Signal the in-flight background download attempt for `hash` to stop. Quick
    /// lock, no await held: clones nothing across `.await`. Idempotent and
    /// race-safe with a natural completion — if no attempt is running (or it just
    /// finished and its guard removed the entry) this is a no-op; cancelling an
    /// already-finished token has no effect. Returns whether a live cancel token
    /// was signalled (only for diagnostics/tests; callers don't depend on it).
    async fn cancel_download_attempt(&self, hash: &str) -> bool {
        let state = self.state.lock().await;
        if let Some((_, token)) = state.download_cancels.get(hash) {
            token.cancel();
            true
        } else {
            false
        }
    }

    /// Tear down all download bookkeeping for `hash` (used by `delete`): cancel the
    /// in-flight attempt, forget the hash's source candidates and release its
    /// leases via [`DownloadSourceRegistry::release_file`], drop the matching
    /// `active_download_peer_endpoints`, and clear the `active_download_attempts`
    /// dedup slot + cancel entry so the hash can be immediately re-created and
    /// re-download. The orphan attempt, on its next loop-top cancel check, exits;
    /// its own per-endpoint release is then idempotent with the release done here.
    async fn teardown_download_for_delete(&self, hash: &str) {
        let mut state = self.state.lock().await;
        if let Some((_, token)) = state.download_cancels.get(hash) {
            token.cancel();
        }
        let cleared = state.download_source_registry.release_file(hash);
        for endpoint in cleared {
            state.active_download_peer_endpoints.remove(&endpoint);
        }
        state.active_download_attempts.remove(hash);
        state.download_cancels.remove(hash);
    }

    async fn register_download_source_candidates(
        &self,
        transfer: &Transfer,
        sources: &[Ed2kFoundSource],
    ) {
        let mut state = self.state.lock().await;
        let file_priority = download_priority_score(&transfer.priority);
        let needed_parts = transfer.parts_total.saturating_sub(transfer.parts_obtained);
        let now = Instant::now();
        for source in sources {
            state.download_source_registry.add_candidate(
                now,
                DownloadSourceCandidate {
                    file_hash: transfer.hash.clone(),
                    file_priority,
                    needed_parts,
                    rare_parts: 0,
                    source: source.clone(),
                    last_seen: now,
                },
            );
        }
    }

    /// A4AF-lite NNP swap (eMuleBB `CUpDownClient::SwapToAnotherFile`). For each
    /// source that reported No Needed Parts on `current_file_hash`, consult the
    /// cross-transfer registry for the best OTHER wanted file the same peer
    /// serves. When such a file exists and is still an active (non-terminal)
    /// transfer, re-drive that transfer's download attempt so the registry-driven
    /// source selection (leg 1) re-engages this peer on the swap-target file
    /// instead of dropping it. Sources whose only registered file was the current
    /// one (no swap target) are left dropped, exactly as before. Returns the
    /// number of sources actually swapped (target queued).
    async fn swap_no_needed_parts_sources(
        &self,
        current_file_hash: &str,
        sources: &[Ed2kFoundSource],
    ) -> usize {
        // Collect distinct swap-target transfers under the state lock, then queue
        // their attempts after releasing it (queue_ed2k_download_attempt also
        // takes the lock).
        let mut swap_targets: Vec<Transfer> = Vec::new();
        {
            let state = self.state.lock().await;
            let mut seen_targets: HashSet<String> = HashSet::new();
            for source in sources {
                let Some(candidate) = state
                    .download_source_registry
                    .swap_target_for_peer(source, current_file_hash)
                else {
                    continue;
                };
                crate::diag_sched::source_swapped(current_file_hash, &candidate.file_hash, source);
                if !seen_targets.insert(candidate.file_hash.clone()) {
                    continue;
                }
                // The swap target must still be a wanted (active) transfer.
                if let Some(target) = state.transfers.get(&candidate.file_hash)
                    && !matches!(
                        target.state.as_str(),
                        "completed" | "completing" | "paused" | "stopped"
                    )
                {
                    swap_targets.push(target.clone());
                }
            }
        }
        let swapped = swap_targets.len();
        for target in swap_targets {
            tracing::info!(
                "ED2K A4AF-lite swap source from file_hash={} to wanted file_hash={}",
                current_file_hash,
                target.hash
            );
            // Spawn the target attempt rather than awaiting it inline: the swap is
            // reached from within a download attempt, so awaiting the recursive
            // attempt future here would make the spawned driver task's future
            // self-referential (non-`Send`). Detaching also matches the master,
            // where SwapToAnotherFile only re-files the source and the swap target
            // is driven by its own download loop.
            // The swap target is driven by its own download loop (master
            // SwapToAnotherFile only re-files the source); queue_ed2k_download_attempt
            // spawns the attempt and dedups against any already running for that file.
            self.queue_ed2k_download_attempt(target);
        }
        swapped
    }

    /// Spawn a background download attempt for `transfer`. Synchronous (returns
    /// immediately after spawning) so it carries no opaque async return type:
    /// an attempt may run the A4AF-lite NNP swap, which re-queues another attempt
    /// (run_attempt -> swap -> queue -> run_attempt); keeping this a plain `fn`
    /// severs that type-inference cycle while the spawn breaks the recursion at
    /// runtime. The dedup guard runs inside the spawned task.
    fn queue_ed2k_download_attempt(&self, transfer: Transfer) {
        let core = self.clone();
        let task_core = self.clone();
        let mut tasks = match self.ed2k_download_tasks.try_lock() {
            Ok(tasks) => tasks,
            Err(_) => {
                // Contended only momentarily (connect reset / disconnect abort);
                // block briefly on the async lock from a fresh spawn instead.
                let spawn_core = self.clone();
                tokio::spawn(async move {
                    spawn_core
                        .ed2k_download_tasks
                        .lock()
                        .await
                        .spawn(Self::run_queued_ed2k_download_attempt(task_core, transfer));
                });
                return;
            }
        };
        tasks.spawn(Self::run_queued_ed2k_download_attempt(core, transfer));
    }

    fn queue_ed2k_download_retry(&self, hash: String) {
        let core = self.clone();
        let task_core = self.clone();
        let mut tasks = match self.ed2k_download_tasks.try_lock() {
            Ok(tasks) => tasks,
            Err(_) => {
                let spawn_core = self.clone();
                tokio::spawn(async move {
                    spawn_core
                        .ed2k_download_tasks
                        .lock()
                        .await
                        .spawn(Self::run_queued_ed2k_download_retry(task_core, hash));
                });
                return;
            }
        };
        tasks.spawn(Self::run_queued_ed2k_download_retry(core, hash));
    }

    /// Body of one background download attempt, run as a tracked task.
    ///
    /// The dedup entry in `active_download_attempts` is inserted via an RAII guard
    /// ([`DownloadAttemptGuard`]) so it is removed on every exit path — including a
    /// panic that unwinds the task. Without the guard, a panic mid-attempt left the
    /// hash in the set forever, permanently blocking the transfer from restarting
    /// (FIX B2).
    async fn run_queued_ed2k_download_attempt(core: EmulebbCore, transfer: Transfer) {
        let hash = transfer.hash.clone();
        // WHY: REST resume returns before the peer transfer finishes, so repeated
        // resume requests must not start duplicate writers for the same part file.
        let (guard, cancel) = {
            let mut state = core.state.lock().await;
            if !state.active_download_attempts.insert(hash.clone()) {
                crate::diag_sched::download_attempt_started(&hash, true);
                return;
            }
            crate::diag_sched::download_attempt_started(&hash, false);
            // Install a fresh per-hash cancel token for this attempt; the loop
            // checks it each round and delete/pause/stop/recheck signal it to stop
            // the attempt promptly. The guard removes it on exit (only when its
            // generation id still matches, so a recreate's token is not clobbered).
            let cancel = CancellationToken::new();
            let cancel_id = state.next_download_cancel_id;
            state.next_download_cancel_id = state.next_download_cancel_id.wrapping_add(1);
            state
                .download_cancels
                .insert(hash.clone(), (cancel_id, cancel.clone()));
            (
                DownloadAttemptGuard {
                    core: core.clone(),
                    hash: hash.clone(),
                    cancel_id,
                },
                cancel,
            )
        };

        let result = core.run_ed2k_download_attempt(&transfer, &cancel).await;
        let mut retry_downloading = false;
        let settled_state: &str;
        match result {
            Ok(Some(next_state)) => {
                settled_state = next_state;
                retry_downloading = next_state == "downloading";
                // Materialize the finished file by name (eMule move-to-Incoming)
                // BEFORE refreshing the in-memory transfer, so the refreshed view
                // surfaces the deliveredPath in the same step.
                if next_state == "completed" {
                    core.deliver_completed_transfer(&hash).await;
                }
                if let Err(error) = core.refresh_transfer_from_manifest(&hash, next_state).await {
                    tracing::warn!(
                        "failed to refresh ED2K transfer {hash} after download attempt: {error}"
                    );
                }
            }
            Ok(None) => {
                settled_state = "cancelled";
            }
            Err(error) => {
                settled_state = "error";
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
        // Release the dedup slot before re-queueing so the retry can re-acquire it.
        drop(guard);
        // Evidence instrumentation: make the task-exit decision (and whether it
        // re-drives) visible. Today `willReask` is only ever true for "downloading";
        // a "queued" exit dies here — which is exactly the defect under investigation.
        crate::diag_sched::download_task_settled(&hash, settled_state, retry_downloading);
        if retry_downloading {
            core.queue_ed2k_download_retry(hash);
        }
    }

    /// Body of one delayed background download retry, run as a tracked task.
    async fn run_queued_ed2k_download_retry(core: EmulebbCore, hash: String) {
        tokio::time::sleep(Duration::from_secs(ED2K_DOWNLOAD_BACKGROUND_RETRY_SECS)).await;
        let Some(transfer) = core.transfer(&hash).await else {
            crate::diag_sched::download_retry_outcome(&hash, "missing", false);
            return;
        };
        if transfer.state != "downloading" {
            crate::diag_sched::download_retry_outcome(&hash, &transfer.state, false);
            return;
        }
        crate::diag_sched::download_retry_outcome(&hash, &transfer.state, true);
        core.queue_ed2k_download_attempt(transfer);
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
        let mut learned = LearnedEd2kMetadata::default();
        let background_search = self.connected_ed2k_search_handle().await;

        // WHY: hash-only metadata resolution shares the same keyword-search
        // server path; do not create extra one-shot TCP logins when the stock
        // client would use the connected server and then fall back to Kad data.
        if let Some(handle) = background_search {
            match search_keyword_via_background_session(
                &handle,
                &query,
                SearchCriteria::default(),
                timeout,
                &cancel,
            )
            .await
            {
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
        transfer: &Transfer,
        file_hash: Ed2kHash,
        file_size: u64,
        allow_server_source_refresh: bool,
    ) -> Result<Vec<Ed2kFoundSource>> {
        let cancel = CancellationToken::new();
        let config = self.effective_ed2k_config(&network.config, None).await?;
        let mut sources = Vec::new();
        let (preferred_endpoint, background_search) =
            if let Some(handle) = self.connected_ed2k_search_handle().await {
                (self.connected_ed2k_server_endpoint().await, Some(handle))
            } else {
                (None, None)
            };
        let has_background_search = background_search.is_some();
        if allow_server_source_refresh
            && has_background_search
            && let Some(handle) = background_search.as_ref()
        {
            let claimed_batch = {
                let mut state = self.state.lock().await;
                claim_connected_server_source_batch(&mut state, transfer, file_hash, Instant::now())
            };
            if !claimed_batch.targets.is_empty() {
                let timeout = Duration::from_secs(config.connect_timeout_secs.max(15));
                match search_source_batch_via_background_session(
                    handle,
                    &claimed_batch.targets,
                    timeout,
                    &cancel,
                )
                .await
                {
                    Ok(results_by_hash) => {
                        for (result_hash, mut results) in results_by_hash {
                            if !network.ip_filter.is_empty() {
                                results.retain(|source| !network.ip_filter.is_filtered(source.ip));
                            }
                            let ban_store = self.ed2k_transfers.ban_store();
                            results.retain(|source| {
                                !ban_store.is_banned(Some(source.ip), source.user_hash.as_ref())
                            });
                            if result_hash == file_hash {
                                merge_download_sources(&mut sources, results);
                            } else if let Some(batch_transfer) =
                                claimed_batch.transfers.get(&result_hash)
                            {
                                self.register_download_source_candidates(batch_transfer, &results)
                                    .await;
                                self.remember_ed2k_sources(result_hash, &results).await?;
                            }
                        }
                    }
                    Err(error) => tracing::warn!(
                        "ED2K background source batch search failed file_hash={} target_count={} error={error}",
                        file_hash,
                        claimed_batch.targets.len()
                    ),
                }
            }
        }
        // Stock eMule obtains server sources through the connected server TCP
        // session and global UDP walks. Do not open fresh TCP server login
        // sessions for ordinary source refreshes: live packet captures showed
        // hundreds of OP_LOGINREQUEST attempts and server closes before
        // OP_IDCHANGE, which is both non-stock and hostile to public servers.
        if allow_server_source_refresh
            && has_background_search
            && should_query_server_udp_source_supplement(
                sources.len(),
                config.max_source_per_file_udp(),
            )
        {
            let claimed_batch = {
                let mut state = self.state.lock().await;
                claim_ed2k_udp_source_batch(
                    &mut state,
                    transfer,
                    file_hash,
                    sources.len(),
                    config.max_source_per_file_udp(),
                    Instant::now(),
                )
            };
            if !claimed_batch.targets.is_empty() {
                match search_source_udp_server_batches(Ed2kUdpSourceBatchSearchOptions {
                    bind_ip: network.bind_ip,
                    config: &config,
                    preferred_endpoint,
                    excluded_endpoint: global_udp_source_search_excluded_endpoint(
                        has_background_search,
                        preferred_endpoint,
                    ),
                    max_attempts: global_udp_source_batch_server_attempts(&config),
                    targets: &claimed_batch.targets,
                    timeout: Duration::from_secs(config.connect_timeout_secs.max(15)),
                    cancel: &cancel,
                })
                .await
                {
                    Ok(results_by_hash) => {
                        for (result_hash, mut results) in results_by_hash {
                            if !network.ip_filter.is_empty() {
                                results.retain(|source| !network.ip_filter.is_filtered(source.ip));
                            }
                            let ban_store = self.ed2k_transfers.ban_store();
                            results.retain(|source| {
                                !ban_store.is_banned(Some(source.ip), source.user_hash.as_ref())
                            });
                            if result_hash == file_hash {
                                merge_download_sources(&mut sources, results);
                            } else if let Some(batch_transfer) =
                                claimed_batch.transfers.get(&result_hash)
                            {
                                self.register_download_source_candidates(batch_transfer, &results)
                                    .await;
                                self.remember_ed2k_sources(result_hash, &results).await?;
                            }
                        }
                    }
                    Err(error) => tracing::warn!(
                        "ED2K UDP source batch search failed file_hash={} target_count={} error={error}",
                        file_hash,
                        claimed_batch.targets.len()
                    ),
                }
            }
        }
        if file_size != 0
            && should_query_kad_source_supplement(
                sources.len(),
                config.max_source_per_file_udp(),
            )
            && {
                let mut state = self.state.lock().await;
                claim_kad_source_refresh(&mut state, &transfer.hash, Instant::now())
            }
            && let Some(dht) = self.ed2k_dht_node().await
        {
            let timeout = Duration::from_secs(
                config
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
        // MFC keeps sources attached to the part file across later source
        // searches, so fresh non-empty lookups must not hide older direct
        // endpoints that remain valid candidates for the same file.
        merge_download_sources(&mut sources, self.remembered_ed2k_sources(file_hash).await?);
        // Self-source exclusion (eMule `CDownloadQueue::CheckAndAddSource`): never
        // treat our own client as a download source. A server or Kad lookup can
        // reflect our own (ip, tcp_port) or user-hash back to us, which would
        // otherwise waste a connect slot dialing ourselves.
        let own_identity = OwnSourceIdentity {
            user_hash: network.user_hash,
            endpoints: {
                let advertised_tcp = self
                    .ed2k_reachability
                    .advertised_tcp_port(network.listen_port);
                let mut endpoints = vec![(network.bind_ip, network.listen_port)];
                if let Some(public_ip) = self.ed2k_reachability.get() {
                    endpoints.push((public_ip, advertised_tcp));
                }
                endpoints
            },
        };
        let dropped = drop_self_sources(&mut sources, &own_identity);
        if dropped > 0 {
            tracing::debug!(
                "ED2K dropped {dropped} self-source(s) for file_hash={file_hash} (own user-hash or endpoint)"
            );
        }
        // WHY: ban + IP-filter at the acquisition chokepoint. eMule
        // `CDownloadQueue::CheckAndAddSource` gates EVERY added source, but the
        // connected-server, Kad, and remembered merge legs above add sources
        // without filtering (only the UDP-batch leg pre-filters). Apply it once
        // over the fully-merged set before any source is remembered, returned, or
        // dialed, so a banned / ip-filtered peer reflected back by a server or Kad
        // on an initial OR requery lookup can never be leased. Invariant: no
        // banned/filtered endpoint leaves acquire_ed2k_sources.
        if !network.ip_filter.is_empty() {
            sources.retain(|source| !network.ip_filter.is_filtered(source.ip));
        }
        let acquire_ban_store = self.ed2k_transfers.ban_store();
        sources.retain(|source| {
            !acquire_ban_store.is_banned(Some(source.ip), source.user_hash.as_ref())
        });
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
            tcp_port: self
                .ed2k_reachability
                .advertised_tcp_port(network.listen_port),
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

    /// Our own TCP-firewalled (LowID) verdict from the live session state, in the
    /// oracle priority order (server authoritative flag, then Kad TCP recheck).
    /// Used to gate the outbound Kad callback: a firewalled requester cannot accept
    /// the source's connect-back (oracle `CanDoCallback` lowid2lowid). When neither
    /// signal is known we assume reachable (permissive), matching the common HighID
    /// case where no LowID flag was ever set.
    async fn ed2k_self_tcp_firewalled(&self) -> bool {
        let (server_state, kad_firewall) = {
            let runtime_guard = self.ed2k_runtime.lock().await;
            let Some(runtime) = runtime_guard.as_ref() else {
                return false;
            };
            (
                Arc::clone(&runtime.server_state),
                Arc::clone(&runtime.kad_firewall),
            )
        };
        if let Some(tcp_firewalled) = server_state.read().await.tcp_firewalled() {
            return tcp_firewalled;
        }
        if let Some(tcp_firewalled) = kad_firewall.lock().await.tcp_firewalled() {
            return tcp_firewalled;
        }
        false
    }

    /// Originate `OP_DIRECTCALLBACKREQ` to firewalled type-6 Kad sources (oracle
    /// `BaseClient.cpp` `CCS_DIRECTCALLBACK`): send our TCP port + userhash +
    /// connect options to the source's Kad UDP endpoint so it TCP-connects back
    /// to us. This is the first-preference LowID connect path, ahead of the
    /// server/Kad-buddy callbacks. A firewalled requester cannot receive the
    /// connect-back, so it is skipped exactly like the Kad-buddy path.
    async fn send_ed2k_direct_callbacks(
        &self,
        network: &Ed2kNetworkConfig,
        transfer: &Transfer,
        sources: &[Ed2kFoundSource],
    ) {
        if !sources.iter().any(Ed2kFoundSource::is_direct_callback_source) {
            return;
        }
        if self.ed2k_self_tcp_firewalled().await {
            return;
        }
        let Some(handle) = self.ed2k_reask_handle.lock().unwrap().clone() else {
            return;
        };
        let our_tcp_port = self
            .ed2k_reachability
            .advertised_tcp_port(network.listen_port);
        let our_user_hash = network.user_hash;
        let our_connect_options = emule_connect_options(network.config.obfuscation_enabled);
        for source in sources
            .iter()
            .filter(|source| source.is_direct_callback_source())
        {
            let Some(source_udp_port) = source.source_udp_port else {
                continue;
            };
            let file_hash = match transfer.hash.parse::<Ed2kHash>() {
                Ok(hash) => hash,
                Err(_) => continue,
            };
            let key = (source.ip, source.tcp_port, file_hash);
            let now = Instant::now();
            {
                let mut state = self.state.lock().await;
                let last_sent = state.ed2k_direct_callback_last_sent.get(&key).copied();
                if !should_send_kad_callback(last_sent, now, KAD_CALLBACK_INITIATOR_COOLDOWN) {
                    continue;
                }
                state.ed2k_direct_callback_last_sent.insert(key, now);
            }
            // Register the callback intent so the source's inbound TCP connect-back
            // (it hellos with its LowID client-id) is claimed as this download.
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
            let dest = SocketAddr::new(IpAddr::V4(source.ip), source_udp_port);
            // Obfuscate toward the source when it advertised crypt support and we
            // hold its user hash (oracle `ShouldReceiveCryptUDPPackets`).
            let obfuscate = source
                .obfuscation_options
                .is_some_and(|options| options & 0x01 != 0)
                && source.user_hash.is_some();
            let queued = handle.send_direct_callback(DirectCallbackArgs {
                dest,
                our_tcp_port,
                our_user_hash,
                connect_options: our_connect_options,
                dest_user_hash: source.user_hash,
                obfuscate,
            });
            if queued {
                tracing::info!(
                    "sent OP_DIRECTCALLBACKREQ file_hash={} source={dest} our_tcp_port={our_tcp_port}",
                    transfer.hash
                );
            }
        }
    }

    /// Originate outbound Kad callbacks (`KADEMLIA_CALLBACK_REQ`, oracle
    /// `BaseClient.cpp` `CCS_KADCALLBACK`) for firewalled buddy sources of this
    /// file whose buddy relay endpoint is known. The source's buddy relays an
    /// `OP_CALLBACK`, prompting the firewalled source to TCP-connect back to us so
    /// the download can start; the inbound listener correlates the connect-back to
    /// the registered callback intent by the source's client-id.
    ///
    /// Preconditions mirror the oracle: Kad connected, we are not ourselves LowID
    /// (lowid2lowid can never connect), and the source is a direct-callback
    /// candidate. Each (source, file) is rate-limited by
    /// [`KAD_CALLBACK_INITIATOR_COOLDOWN`] via the per-core last-sent map.
    async fn send_kad_buddy_callbacks(
        &self,
        network: &Ed2kNetworkConfig,
        transfer: &Transfer,
        file_hash: Ed2kHash,
        sources: &[Ed2kFoundSource],
    ) {
        // Cheap pre-filter: nothing to do without direct-callback candidates.
        if !sources.iter().any(is_direct_kad_callback_candidate) {
            return;
        }
        // A firewalled requester cannot receive the connect-back (lowid2lowid).
        if self.ed2k_self_tcp_firewalled().await {
            return;
        }
        let Some(dht) = self.ed2k_dht_node().await else {
            return;
        };
        if !dht.is_bootstrapped() {
            return;
        }
        // The source connects back to our externally-advertised eD2k TCP port.
        let our_tcp_port = self
            .ed2k_reachability
            .advertised_tcp_port(network.listen_port);
        // Also register a callback intent so the inbound connect-back is claimed as
        // this download (the source hellos with its LowID client-id).
        for source in sources
            .iter()
            .filter(|s| is_direct_kad_callback_candidate(s))
        {
            let (Some(buddy_id), Some((buddy_ip, buddy_port))) =
                (source.buddy_id, source.buddy_endpoint)
            else {
                continue;
            };
            let Some(key) = kad_callback_key(source, file_hash) else {
                continue;
            };
            let now = Instant::now();
            {
                let mut state = self.state.lock().await;
                let last_sent = state.ed2k_kad_callback_last_sent.get(&key).copied();
                if !should_send_kad_callback(last_sent, now, KAD_CALLBACK_INITIATOR_COOLDOWN) {
                    continue;
                }
                // Record the attempt up-front so a concurrent requery round cannot
                // race a second send within the cooldown.
                state.ed2k_kad_callback_last_sent.insert(key, now);
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
            let buddy_peer = SocketAddr::new(IpAddr::V4(buddy_ip), buddy_port);
            let source_peer = SocketAddr::new(IpAddr::V4(source.ip), source.tcp_port);
            let request = build_kad_callback_req(buddy_id, file_hash, our_tcp_port);
            // MFC sends this unencrypted because the buddy's Kad version/key is
            // unknown; rust's plain send_packet likewise carries no obfuscation for
            // a contact we hold no verify key for.
            match dht
                .send_packet(buddy_peer, &KadPacket::CallbackReq(request))
                .await
            {
                Ok(()) => {
                    tracing::info!(
                        "sent Kad KADEMLIA_CALLBACK_REQ file_hash={} source={source_peer} buddy={buddy_peer} our_tcp_port={our_tcp_port}",
                        transfer.hash
                    );
                    crate::diag_kad_event::callback(
                        "sent",
                        buddy_peer,
                        source_peer,
                        &transfer.hash,
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        "Kad KADEMLIA_CALLBACK_REQ send failed file_hash={} source={source_peer} buddy={buddy_peer}: {error}",
                        transfer.hash
                    );
                    crate::diag_kad_event::callback(
                        "send_failed",
                        buddy_peer,
                        source_peer,
                        &transfer.hash,
                    );
                }
            }
        }
    }

    async fn publish_ed2k_shared_catalog(&self) -> Result<Ed2kSharedCatalogPublishOutcome> {
        let Some(network) = self.ed2k_network.as_ref() else {
            return Ok(Ed2kSharedCatalogPublishOutcome::NoNetwork);
        };
        let (handle, server_state) = {
            let runtime_guard = self.ed2k_runtime.lock().await;
            let Some(runtime) = runtime_guard.as_ref() else {
                return Ok(Ed2kSharedCatalogPublishOutcome::NoNetwork);
            };
            (
                runtime.search_handle.clone(),
                Arc::clone(&runtime.server_state),
            )
        };
        if !server_state.read().await.connected {
            return Ok(Ed2kSharedCatalogPublishOutcome::NotConnected);
        }
        let timeout = Duration::from_secs(network.config.connect_timeout_secs.max(10));
        let stats = publish_shared_catalog_via_background_session(
            &handle,
            timeout,
            &CancellationToken::new(),
        )
        .await?;
        Ok(Ed2kSharedCatalogPublishOutcome::Published(stats))
    }

    fn queue_ed2k_shared_catalog_publish(&self) {
        self.shared_catalog_publish_dirty
            .store(true, Ordering::Release);
        ed2k_publish_diagnostics::record(&self.ed2k_publish_diagnostics, |diagnostics| {
            diagnostics.phase = "queued".to_string();
            diagnostics.running = true;
            diagnostics.dirty = true;
            diagnostics.queued_count = diagnostics.queued_count.saturating_add(1);
        });
        if self
            .shared_catalog_publish_worker
            .swap(true, Ordering::AcqRel)
        {
            return;
        }
        let core = self.clone();
        tokio::spawn(async move {
            core.run_queued_ed2k_shared_catalog_publisher().await;
        });
    }

    async fn run_queued_ed2k_shared_catalog_publisher(self) {
        const ED2K_SHARED_CATALOG_PUBLISH_DEBOUNCE: Duration = Duration::from_secs(2);
        const ED2K_SHARED_CATALOG_PUBLISH_MIN_INTERVAL: Duration = Duration::from_secs(60);
        const ED2K_SHARED_CATALOG_PUBLISH_NOT_CONNECTED_RETRY: Duration = Duration::from_secs(10);

        loop {
            ed2k_publish_diagnostics::record(&self.ed2k_publish_diagnostics, |diagnostics| {
                diagnostics.phase = "debouncing".to_string();
                diagnostics.running = true;
                diagnostics.dirty = self.shared_catalog_publish_dirty.load(Ordering::Acquire);
            });
            tokio::time::sleep(ED2K_SHARED_CATALOG_PUBLISH_DEBOUNCE).await;
            let wait = {
                let last = self.shared_catalog_publish_last.lock().await;
                last.and_then(|last| {
                    ED2K_SHARED_CATALOG_PUBLISH_MIN_INTERVAL.checked_sub(last.elapsed())
                })
            };
            if let Some(wait) = wait {
                ed2k_publish_diagnostics::record(&self.ed2k_publish_diagnostics, |diagnostics| {
                    diagnostics.phase = "waitingInterval".to_string();
                    diagnostics.running = true;
                    diagnostics.dirty = self.shared_catalog_publish_dirty.load(Ordering::Acquire);
                });
                tokio::time::sleep(wait).await;
            }
            // Clear before the network publish. If hashing completes another
            // shared file while the advertisement is in flight, queueing sets
            // dirty again and this loop performs a follow-up publish.
            self.shared_catalog_publish_dirty
                .store(false, Ordering::Release);
            ed2k_publish_diagnostics::record(&self.ed2k_publish_diagnostics, |diagnostics| {
                diagnostics.phase = "publishing".to_string();
                diagnostics.running = true;
                diagnostics.dirty = false;
                diagnostics.last_attempt_at_ms = Utc::now().timestamp_millis();
            });
            match self.publish_ed2k_shared_catalog().await {
                Ok(Ed2kSharedCatalogPublishOutcome::Published(stats)) => {
                    *self.shared_catalog_publish_last.lock().await = Some(Instant::now());
                    ed2k_publish_diagnostics::record(
                        &self.ed2k_publish_diagnostics,
                        |diagnostics| {
                            diagnostics.phase = "published".to_string();
                            diagnostics.running = true;
                            diagnostics.dirty =
                                self.shared_catalog_publish_dirty.load(Ordering::Acquire);
                            diagnostics.entries_sent = stats.entries_sent;
                            diagnostics.total_entries = stats.total_entries;
                            diagnostics.published_entries = stats.published_entries;
                            diagnostics.pending_entries = stats.pending_entries;
                            diagnostics.next_cursor = stats.next_cursor;
                            diagnostics.wrapped = stats.wrapped;
                            diagnostics.skipped_duplicate_batch = stats.skipped_duplicate_batch;
                            diagnostics.last_error = None;
                            diagnostics.last_success_at_ms = Utc::now().timestamp_millis();
                        },
                    );
                    tracing::debug!(
                        entries_sent = stats.entries_sent,
                        total_entries = stats.total_entries,
                        published_entries = stats.published_entries,
                        pending_entries = stats.pending_entries,
                        next_cursor = stats.next_cursor,
                        wrapped = stats.wrapped,
                        skipped_duplicate_batch = stats.skipped_duplicate_batch,
                        "refreshed ED2K shared catalog advertisement"
                    );
                    if !stats.wrapped && !stats.skipped_duplicate_batch {
                        self.shared_catalog_publish_dirty
                            .store(true, Ordering::Release);
                        ed2k_publish_diagnostics::record(
                            &self.ed2k_publish_diagnostics,
                            |diagnostics| {
                                diagnostics.dirty = true;
                            },
                        );
                    }
                }
                Ok(Ed2kSharedCatalogPublishOutcome::NoNetwork) => {
                    ed2k_publish_diagnostics::record(
                        &self.ed2k_publish_diagnostics,
                        |diagnostics| {
                            diagnostics.phase = "noNetwork".to_string();
                            diagnostics.running = true;
                            diagnostics.dirty =
                                self.shared_catalog_publish_dirty.load(Ordering::Acquire);
                            diagnostics.no_network_count =
                                diagnostics.no_network_count.saturating_add(1);
                        },
                    );
                }
                Ok(Ed2kSharedCatalogPublishOutcome::NotConnected) => {
                    self.shared_catalog_publish_dirty
                        .store(true, Ordering::Release);
                    ed2k_publish_diagnostics::record(
                        &self.ed2k_publish_diagnostics,
                        |diagnostics| {
                            diagnostics.phase = "notConnected".to_string();
                            diagnostics.running = true;
                            diagnostics.dirty = true;
                            diagnostics.not_connected_count =
                                diagnostics.not_connected_count.saturating_add(1);
                        },
                    );
                    tokio::time::sleep(ED2K_SHARED_CATALOG_PUBLISH_NOT_CONNECTED_RETRY).await;
                    continue;
                }
                Err(error) => {
                    *self.shared_catalog_publish_last.lock().await = Some(Instant::now());
                    self.shared_catalog_publish_dirty
                        .store(true, Ordering::Release);
                    ed2k_publish_diagnostics::record(
                        &self.ed2k_publish_diagnostics,
                        |diagnostics| {
                            diagnostics.phase = "failed".to_string();
                            diagnostics.running = true;
                            diagnostics.dirty = true;
                            diagnostics.failure_count = diagnostics.failure_count.saturating_add(1);
                            diagnostics.last_error = Some(error.to_string());
                        },
                    );
                    tracing::warn!("failed to refresh ED2K shared catalog advertisement: {error}");
                }
            }
            if !self.shared_catalog_publish_dirty.load(Ordering::Acquire) {
                self.shared_catalog_publish_worker
                    .store(false, Ordering::Release);
                if !self.shared_catalog_publish_dirty.load(Ordering::Acquire) {
                    ed2k_publish_diagnostics::record(
                        &self.ed2k_publish_diagnostics,
                        |diagnostics| {
                            diagnostics.phase = "idle".to_string();
                            diagnostics.running = false;
                            diagnostics.dirty = false;
                        },
                    );
                    break;
                }
                if self
                    .shared_catalog_publish_worker
                    .swap(true, Ordering::AcqRel)
                {
                    ed2k_publish_diagnostics::record(
                        &self.ed2k_publish_diagnostics,
                        |diagnostics| {
                            diagnostics.running = true;
                            diagnostics.dirty = true;
                        },
                    );
                    break;
                }
            }
        }
    }

    async fn run_ed2k_shared_catalog_demand_publish_loop(
        core: EmulebbCore,
        signal: Ed2kSharedPublishDemandSignal,
        shutdown: Arc<AtomicBool>,
    ) {
        let mut observed_revision = signal.revision();
        while !shutdown.load(Ordering::SeqCst) {
            let revision = signal.revision();
            if revision != observed_revision {
                observed_revision = revision;
                core.queue_ed2k_shared_catalog_publish();
                continue;
            }
            if tokio::time::timeout(Duration::from_secs(1), signal.notified())
                .await
                .is_err()
            {
                continue;
            }
        }
    }

    async fn ed2k_server_connection_view(
        &self,
    ) -> (Option<String>, Option<String>, ServerLiveDetails) {
        let server_state = {
            let Ok(runtime_guard) = self.ed2k_runtime.try_lock() else {
                return (None, None, ServerLiveDetails::default());
            };
            let Some(runtime) = runtime_guard.as_ref() else {
                return (None, None, ServerLiveDetails::default());
            };
            Arc::clone(&runtime.server_state)
        };
        let state = server_state.read().await;
        let endpoint = state.endpoint.map(|endpoint| endpoint.to_string());
        let connected = state.connected.then(|| endpoint.clone()).flatten();
        let connecting = state.connecting.then_some(endpoint).flatten();
        let live = ServerLiveDetails {
            name: state.server_name.clone(),
            description: state.server_description.clone(),
            users: state.server_users,
            files: state.server_files,
        };
        (connected, connecting, live)
    }

    async fn ed2k_status(&self) -> NetworkStatus {
        let server_state = {
            let Ok(runtime_guard) = self.ed2k_runtime.try_lock() else {
                return ed2k_starting_status();
            };
            let Some(runtime) = runtime_guard.as_ref() else {
                return ed2k_stopped_status();
            };
            Arc::clone(&runtime.server_state)
        };
        let state = server_state.read().await;
        NetworkStatus {
            running: true,
            connected: state.connected,
            peer_count: u32::from(state.connected),
            firewalled: state.connected.then(|| state.tcp_firewalled()).flatten(),
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
            let Ok(runtime_guard) = self.ed2k_runtime.try_lock() else {
                return kad_starting_status(manual_running);
            };
            runtime_guard
                .as_ref()
                .map(|runtime| (runtime.dht.clone(), Arc::clone(&runtime.kad_firewall)))
        };
        let Some((dht, kad_firewall)) = runtime_snapshot else {
            return kad_status_from_running(manual_running);
        };
        let contact_count = dht.routing_table_size() as u32;
        let connected = dht.is_bootstrapped();
        // Report the real UDP-firewall verdict (oracle
        // `CUDPFirewallTester::IsFirewalledUDP`): unverified is treated as OPEN.
        let firewalled = kad_firewall.lock().await.is_udp_firewalled();
        // Kad DHT population estimate (oracle `CKademlia::GetKademliaUsers` via
        // `CRoutingZone::EstimateCount`) and the derived file estimate (oracle
        // `CPrefs::SetKademliaFiles`, using its ~108 files-per-user floor since rust
        // does not track the live ed2k-server file average). Only meaningful once the
        // routing tree is populated, so gate on `connected` like the oracle.
        let kad_users = if connected {
            u64::from(dht.estimate_kad_users(firewalled).await)
        } else {
            0
        };
        let kad_files = kad_users.saturating_mul(KAD_ESTIMATED_FILES_PER_USER);
        // The bootstrap driver always runs while Kad is up, re-driving the
        // self-lookup until connected, so we are "bootstrapping" whenever we have
        // contacts to bootstrap from and are not yet connected.
        let bootstrapping = !connected && contact_count > 0;
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
            firewalled: Some(firewalled),
            bootstrapping: Some(bootstrapping),
            bootstrap_progress: Some(if connected {
                100
            } else if bootstrapping {
                50
            } else {
                0
            }),
            contact_count: Some(contact_count),
            lan_mode: Some(false),
            users: connected.then_some(kad_users),
            files: connected.then_some(kad_files),
            indexed_sources: Some(indexed_sources),
            indexed_keywords: Some(indexed_keywords),
            operation_queued: None,
            already_running: None,
        }
    }
}

fn ed2k_stopped_status() -> NetworkStatus {
    NetworkStatus {
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
    }
}

fn ed2k_starting_status() -> NetworkStatus {
    NetworkStatus {
        running: true,
        connected: false,
        peer_count: 0,
        firewalled: None,
        bootstrapping: Some(true),
        bootstrap_progress: Some(0),
        contact_count: None,
        lan_mode: None,
        users: None,
        files: None,
        indexed_sources: None,
        indexed_keywords: None,
        operation_queued: Some(true),
        already_running: None,
    }
}

fn kad_starting_status(manual_running: bool) -> NetworkStatus {
    let mut status = kad_status_from_running(manual_running);
    if manual_running {
        status.operation_queued = Some(true);
    }
    status
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

/// Initial delay before the first bootstrap attempt, giving any nodes.dat import
/// / configured seeds time to land in the routing table after start.
const KAD_BOOTSTRAP_INITIAL_DELAY_SECS: u64 = 2;
/// Retry cadence while Kad is not yet bootstrapped (oracle `CKademlia::Process`
/// re-drives the bootstrap self-lookup until the node is connected). Gentle by
/// design so a node sitting on a stale `nodes.dat` keeps trying without flooding.
const KAD_BOOTSTRAP_RETRY_SECS: u64 = 30;

/// Drive the Kad bootstrap self-lookup until the node reaches the bootstrapped
/// (connected) state, then keep idling so a later table-collapse can re-trigger
/// it. eMule promotes Kad to connected only after the bootstrap self-lookup
/// against live peers succeeds; this loop is the rust analogue of
/// `CKademlia::Process` re-running `m_pRoutingZone->Bootstrap()` while not yet
/// connected. It seeds from configured `nodes_text`, the hardcoded fallback, and
/// (critically) the live routing table, so a node restored from an imported
/// `nodes.dat` alone — with no configured bootstrap nodes — still bootstraps.
async fn run_configured_kad_bootstrap(dht: DhtNode, shutdown: Arc<AtomicBool>) {
    tokio::time::sleep(Duration::from_secs(KAD_BOOTSTRAP_INITIAL_DELAY_SECS)).await;

    while !shutdown.load(Ordering::SeqCst) {
        if dht.is_bootstrapped() {
            // Already connected: re-check on the retry cadence so a routing-table
            // collapse (all contacts expired) re-drives the bootstrap.
            tokio::time::sleep(Duration::from_secs(KAD_BOOTSTRAP_RETRY_SECS)).await;
            continue;
        }

        match dht.bootstrap().await {
            Ok(()) => tracing::info!(
                "Kad bootstrap completed bootstrapped={} contacts={}",
                dht.is_bootstrapped(),
                dht.routing_table_size()
            ),
            Err(error) => {
                if !shutdown.load(Ordering::SeqCst) {
                    tracing::warn!("Kad bootstrap attempt failed (will retry): {error}");
                }
            }
        }

        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(KAD_BOOTSTRAP_RETRY_SECS)).await;
    }
}

/// Shared inputs for the Kad shared-file (re)publish loop. Carries the
/// firewall/buddy state so the loop can apply the master
/// `CSharedFileList::Publish` gate (see [`kad_publish_schedule::kad_publish_allowed`]).
struct KadPublishLoopRuntime {
    dht: DhtNode,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    metadata_store: MetadataStore,
    diagnostics: kad_publish_diagnostics::SharedKadPublishDiagnostics,
    ed2k_listener: Arc<TcpListener>,
    server_state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    kad_buddy: Arc<Mutex<KadBuddyState>>,
    network: Ed2kNetworkConfig,
}

/// Re-scan cadence for the shared-file publish loop. The master `Publish()` runs
/// off its 1s heartbeat gated by `KADEMLIAPUBLISHTIME` (2s); the actual
/// (re)publish rate is bounded per-file by the 24h keyword / 5h source intervals,
/// so this only controls how often we re-evaluate which files are due.
/// Files-per-user used to derive the Kad file-population estimate from the user
/// estimate, mirroring the oracle `CPrefs::SetKademliaFiles` floor (108) applied
/// when no live ed2k-server file average is available.
const KAD_ESTIMATED_FILES_PER_USER: u64 = 108;
const KAD_SHARED_FILE_PUBLISH_TICK_SECS: u64 = 2;
/// Cadence of the periodic `kad_publish_snapshot` diag_event (A5), kept well above
/// the fast publish tick so the log time-series is sampled, not flooded.
const KAD_PUBLISH_SNAPSHOT_INTERVAL_SECS: u64 = 30;
/// Upper bound on files inspected in one Kad publish cycle. A large library may
/// need several rounds to drain; this keeps each async loop slice bounded while
/// the rotating cursor prevents first-file starvation.
const KAD_SHARED_FILE_PUBLISH_SCAN_BUDGET: usize = 256;
/// Per-kind new publish starts per 2s round. MFC active store caps are 3/4/1,
/// but each `CSharedFileList::Publish()` tick starts at most one keyword target,
/// one source file, and one notes file. Keep Rust's start cadence the same so a
/// large library does not burst-fill the shared DHT search pool.
const KAD_KEYWORD_PUBLISH_BUDGET: usize = 1;
/// Master caps one STOREKEYWORD request to 150 file IDs for the selected keyword.
const KAD_KEYWORD_PUBLISH_FILE_LIMIT: usize = 150;
const KAD_SOURCE_PUBLISH_BUDGET: usize = 1;
const KAD_NOTES_PUBLISH_BUDGET: usize = 1;
const KAD_KEYWORD_PUBLISH_IN_FLIGHT_CAP: usize = 3;
const KAD_SOURCE_PUBLISH_IN_FLIGHT_CAP: usize = 4;
const KAD_NOTES_PUBLISH_IN_FLIGHT_CAP: usize = 1;
const KAD_SHARED_FILE_PUBLISH_KIND_CAP_TOTAL: usize = KAD_KEYWORD_PUBLISH_IN_FLIGHT_CAP
    + KAD_SOURCE_PUBLISH_IN_FLIGHT_CAP
    + KAD_NOTES_PUBLISH_IN_FLIGHT_CAP;
/// Keep one DHT traversal permit free for interactive searches, bootstrap
/// refresh, and firewall/buddy maintenance while large-library publishing runs.
/// The live DHT cap is raised to this total plus the MFC store caps so shared
/// publishing can reach `3 keyword + 4 source + 1 notes` concurrently.
const KAD_SHARED_FILE_PUBLISH_RESERVED_SEARCH_PERMITS: usize = 1;
const KAD_SHARED_FILE_PUBLISH_DHT_SEARCH_CAP: usize =
    KAD_SHARED_FILE_PUBLISH_KIND_CAP_TOTAL + KAD_SHARED_FILE_PUBLISH_RESERVED_SEARCH_PERMITS;
/// Store traversals need enough lookup packets to converge before the stock
/// 140s store timeout. One packet/sec across several concurrent store lookups
/// self-throttles large-library publishing without changing wire semantics.
const KAD_PUBLISH_MAX_OUTBOUND_PPS: u32 = 2;

fn kad_rpc_class_budgets() -> RpcClassBudgetConfig {
    RpcClassBudgetConfig {
        publish_max_outbound_pps: KAD_PUBLISH_MAX_OUTBOUND_PPS,
        ..RpcClassBudgetConfig::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KadSharedPublishKind {
    Keyword,
    Source,
    Notes,
}

impl KadSharedPublishKind {
    fn label(self) -> &'static str {
        match self {
            Self::Keyword => "keyword",
            Self::Source => "source",
            Self::Notes => "notes",
        }
    }
}

#[derive(Debug)]
struct KadSharedPublishOutcome {
    kind: KadSharedPublishKind,
    file_hashes: Vec<String>,
    /// The published keyword (`Keyword` kind only), so the drain can apply the
    /// oracle load deferral to it.
    keyword: Option<String>,
    started_at: Instant,
    result: Result<PublishAttemptStats, KadSharedPublishError>,
}

#[derive(Debug)]
enum KadSharedPublishError {
    Busy,
    TimedOut,
    Failed(String),
}

#[derive(Debug, Default)]
struct KadSharedPublishActiveCounts {
    keyword: usize,
    source: usize,
    notes: usize,
}

impl KadSharedPublishActiveCounts {
    fn count(&self, kind: KadSharedPublishKind) -> usize {
        match kind {
            KadSharedPublishKind::Keyword => self.keyword,
            KadSharedPublishKind::Source => self.source,
            KadSharedPublishKind::Notes => self.notes,
        }
    }

    fn can_start(&self, kind: KadSharedPublishKind) -> bool {
        self.count(kind) < kad_shared_publish_kind_cap(kind)
    }

    fn started(&mut self, kind: KadSharedPublishKind) {
        match kind {
            KadSharedPublishKind::Keyword => self.keyword += 1,
            KadSharedPublishKind::Source => self.source += 1,
            KadSharedPublishKind::Notes => self.notes += 1,
        }
    }

    fn finished(&mut self, kind: KadSharedPublishKind) {
        match kind {
            KadSharedPublishKind::Keyword => self.keyword = self.keyword.saturating_sub(1),
            KadSharedPublishKind::Source => self.source = self.source.saturating_sub(1),
            KadSharedPublishKind::Notes => self.notes = self.notes.saturating_sub(1),
        }
    }

    fn write_diagnostics(
        &self,
        diagnostics: &mut KadPublishDiagnostics,
        available_search_permits: usize,
    ) {
        diagnostics.active_keyword_publishes = self.keyword;
        diagnostics.active_source_publishes = self.source;
        diagnostics.active_notes_publishes = self.notes;
        diagnostics.available_search_permits = available_search_permits;
    }
}

fn kad_shared_publish_kind_cap(kind: KadSharedPublishKind) -> usize {
    match kind {
        KadSharedPublishKind::Keyword => KAD_KEYWORD_PUBLISH_IN_FLIGHT_CAP,
        KadSharedPublishKind::Source => KAD_SOURCE_PUBLISH_IN_FLIGHT_CAP,
        KadSharedPublishKind::Notes => KAD_NOTES_PUBLISH_IN_FLIGHT_CAP,
    }
}

fn diag_publish_kind(kind: KadSharedPublishKind) -> diag_kad_event::KadPublishKind {
    match kind {
        KadSharedPublishKind::Keyword => diag_kad_event::KadPublishKind::Keyword,
        KadSharedPublishKind::Source => diag_kad_event::KadPublishKind::Source,
        KadSharedPublishKind::Notes => diag_kad_event::KadPublishKind::Notes,
    }
}

fn kad_shared_file_publish_in_flight_budget(runtime: &KadPublishLoopRuntime) -> usize {
    kad_shared_file_publish_in_flight_budget_for(runtime.dht.max_concurrent_searches())
}

fn kad_shared_file_publish_in_flight_budget_for(max_concurrent_searches: usize) -> usize {
    max_concurrent_searches
        .saturating_sub(KAD_SHARED_FILE_PUBLISH_RESERVED_SEARCH_PERMITS)
        .clamp(1, KAD_SHARED_FILE_PUBLISH_KIND_CAP_TOTAL)
}

async fn run_kad_shared_file_publish_loop(
    runtime: KadPublishLoopRuntime,
    shutdown: Arc<AtomicBool>,
) {
    let mut schedule = kad_publish_schedule::KadPublishSchedule::new();
    hydrate_kad_outbound_publish_schedule(&runtime.metadata_store, &mut schedule);
    let mut publish_tasks = JoinSet::new();
    let mut active_counts = KadSharedPublishActiveCounts::default();
    let mut last_publish_snapshot = std::time::Instant::now();
    while !shutdown.load(Ordering::SeqCst) {
        if !runtime.dht.is_bootstrapped() {
            let in_flight_budget = kad_shared_file_publish_in_flight_budget(&runtime);
            let available_search_permits = runtime.dht.available_search_permits();
            kad_publish_diagnostics::record(&runtime.diagnostics, |diagnostics| {
                diagnostics.phase = "waitingBootstrap".to_string();
                diagnostics.running = true;
                diagnostics.bootstrapped = false;
                diagnostics.gate_allowed = false;
                diagnostics.gate_block_reason = "kadNotBootstrapped".to_string();
                diagnostics.tick_secs = KAD_SHARED_FILE_PUBLISH_TICK_SECS;
                diagnostics.file_budget = KAD_SHARED_FILE_PUBLISH_SCAN_BUDGET;
                diagnostics.in_flight_count = publish_tasks.len();
                diagnostics.in_flight_budget = in_flight_budget;
                active_counts.write_diagnostics(diagnostics, available_search_permits);
                diagnostics.keyword_budget = KAD_KEYWORD_PUBLISH_BUDGET;
                diagnostics.source_budget = KAD_SOURCE_PUBLISH_BUDGET;
                diagnostics.notes_budget = KAD_NOTES_PUBLISH_BUDGET;
            });
            tokio::time::sleep(Duration::from_secs(KAD_SHARED_FILE_PUBLISH_RETRY_SECS)).await;
            continue;
        }

        if let Err(error) = publish_kad_due_shared_files(
            &runtime,
            &mut schedule,
            &mut publish_tasks,
            &mut active_counts,
        )
        .await
        {
            tracing::debug!("Kad shared-file publish cycle failed: {error:#}");
        }

        // A5: periodic diag_event snapshot of the publish-loop gate state so the
        // in-flight/permit/due-vs-skipped picture is analysable from the log
        // time-series, not only the live /api/v1/status kadPublish snapshot.
        if last_publish_snapshot.elapsed()
            >= Duration::from_secs(KAD_PUBLISH_SNAPSHOT_INTERVAL_SECS)
        {
            diag_kad_event::kad_publish_snapshot(&kad_publish_diagnostics::snapshot(
                &runtime.diagnostics,
            ));
            last_publish_snapshot = std::time::Instant::now();
        }

        let tick_secs = KAD_SHARED_FILE_PUBLISH_TICK_SECS;
        for _ in 0..tick_secs {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    kad_publish_diagnostics::record(&runtime.diagnostics, |diagnostics| {
        diagnostics.phase = "stopped".to_string();
        diagnostics.running = false;
    });
}

fn hydrate_kad_outbound_publish_schedule(
    metadata_store: &MetadataStore,
    schedule: &mut kad_publish_schedule::KadPublishSchedule,
) {
    let wall_now_ms = Utc::now().timestamp_millis();
    let instant_now = Instant::now();
    let persisted = match metadata_store.load_kad_outbound_publish_schedule() {
        Ok(persisted) => persisted,
        Err(error) => {
            tracing::warn!("failed to load Kad outbound publish schedule: {error:#}");
            return;
        }
    };
    for publish in persisted.publishes {
        let at = instant_from_persisted_wall_ms(publish.published_at_ms, wall_now_ms, instant_now);
        match publish.publish_kind {
            MetadataKadOutboundPublishKind::Keyword => {
                schedule.hydrate_keyword_published(&publish.file_hash, &publish.keyword, at);
            }
            MetadataKadOutboundPublishKind::Source => {
                schedule.hydrate_source_published(&publish.file_hash, at);
            }
            MetadataKadOutboundPublishKind::Notes => {
                schedule.hydrate_notes_published(&publish.file_hash, at);
            }
        }
    }
}

fn instant_from_persisted_wall_ms(
    persisted_ms: i64,
    wall_now_ms: i64,
    instant_now: Instant,
) -> Instant {
    let elapsed_ms = wall_now_ms.saturating_sub(persisted_ms);
    instant_now
        .checked_sub(Duration::from_millis(elapsed_ms as u64))
        .unwrap_or(instant_now)
}

fn persist_kad_outbound_publish(
    metadata_store: &MetadataStore,
    file_hash: &str,
    publish_kind: MetadataKadOutboundPublishKind,
    keyword: &str,
    published_at_ms: i64,
) {
    if let Err(error) = metadata_store.upsert_kad_outbound_publish(
        &MetadataKadOutboundPublish {
            file_hash: file_hash.to_string(),
            publish_kind,
            keyword: keyword.to_string(),
            published_at_ms,
        },
        Utc::now().timestamp_millis(),
    ) {
        tracing::warn!(
            file_hash,
            publish_kind = publish_kind.as_str(),
            "failed to persist Kad outbound publish schedule: {error:#}"
        );
    }
}

fn mark_kad_keyword_publish_started(
    metadata_store: &MetadataStore,
    schedule: &mut kad_publish_schedule::KadPublishSchedule,
    file_hashes: &[String],
    keyword: &str,
    started_at: Instant,
    published_at_ms: i64,
) {
    for file_hash in file_hashes {
        schedule.mark_keyword_published(file_hash, keyword, started_at);
        persist_kad_outbound_publish(
            metadata_store,
            file_hash,
            MetadataKadOutboundPublishKind::Keyword,
            keyword,
            published_at_ms,
        );
    }
}

/// MFC advances Kad publish timers when the store search starts, not when ACKs
/// arrive. Marking at admission avoids timeout-heavy targets being retried every
/// publish tick and starving the rotating scan.
fn mark_kad_file_publish_started(
    metadata_store: &MetadataStore,
    schedule: &mut kad_publish_schedule::KadPublishSchedule,
    file_hash: &str,
    publish_kind: MetadataKadOutboundPublishKind,
    started_at: Instant,
    published_at_ms: i64,
    buddy_ip: Option<Ipv4Addr>,
) {
    match publish_kind {
        MetadataKadOutboundPublishKind::Keyword => {
            unreachable!("keyword publishes must use mark_kad_keyword_publish_started");
        }
        MetadataKadOutboundPublishKind::Source => {
            schedule.mark_source_published(file_hash, started_at, buddy_ip);
        }
        MetadataKadOutboundPublishKind::Notes => {
            schedule.mark_notes_published(file_hash, started_at);
        }
    }
    persist_kad_outbound_publish(metadata_store, file_hash, publish_kind, "", published_at_ms);
}

/// Build the master `CSharedFileList::Publish` firewall/buddy gate input from the
/// current firewall + buddy state.
async fn kad_publish_gate_input(
    runtime: &KadPublishLoopRuntime,
) -> kad_publish_schedule::KadPublishGateInput {
    let kad_connected = runtime.dht.is_bootstrapped();
    let tcp_firewalled = current_tcp_firewalled(
        &runtime.ed2k_listener,
        &runtime.server_state,
        &runtime.kad_firewall,
    )
    .await;
    let udp_open = {
        let firewall = runtime.kad_firewall.lock().await;
        // The master term (IsFirewalledUDP(true) || !IsVerified()) is false only
        // when the UDP port is verified open.
        firewall.udp_open && firewall.udp_verified
    };
    let buddy_connected = runtime.kad_buddy.lock().await.has_outgoing_buddy();
    kad_publish_schedule::KadPublishGateInput {
        kad_connected,
        tcp_firewalled,
        buddy_connected,
        udp_open,
    }
}

/// One publish cycle: republish only the shared files whose per-file, per-kind
/// master interval is due (keyword 24h / source 5h), and only while the master
/// `CSharedFileList::Publish` firewall/buddy gate permits publishing.
#[allow(clippy::cognitive_complexity)]
async fn publish_kad_due_shared_files(
    runtime: &KadPublishLoopRuntime,
    schedule: &mut kad_publish_schedule::KadPublishSchedule,
    publish_tasks: &mut JoinSet<KadSharedPublishOutcome>,
    active_counts: &mut KadSharedPublishActiveCounts,
) -> Result<usize> {
    let shared_files = kad_publishable_shared_files(&runtime.transfer_runtime).await?;
    let in_flight_budget = kad_shared_file_publish_in_flight_budget(runtime);
    let available_search_permits = runtime.dht.available_search_permits();
    kad_publish_diagnostics::record(&runtime.diagnostics, |diagnostics| {
        diagnostics.phase = "scanning".to_string();
        diagnostics.running = true;
        diagnostics.bootstrapped = true;
        diagnostics.tick_secs = KAD_SHARED_FILE_PUBLISH_TICK_SECS;
        diagnostics.file_budget = KAD_SHARED_FILE_PUBLISH_SCAN_BUDGET;
        diagnostics.in_flight_count = publish_tasks.len();
        diagnostics.in_flight_budget = in_flight_budget;
        active_counts.write_diagnostics(diagnostics, available_search_permits);
        diagnostics.keyword_budget = KAD_KEYWORD_PUBLISH_BUDGET;
        diagnostics.source_budget = KAD_SOURCE_PUBLISH_BUDGET;
        diagnostics.notes_budget = KAD_NOTES_PUBLISH_BUDGET;
        diagnostics.item_count = shared_files.len();
    });
    // Keep the per-file schedule from growing without bound: forget files that
    // are no longer publishable (removed / no longer complete).
    schedule.retain_only(shared_files.iter().map(|entry| entry.file_hash.as_str()));
    if shared_files.is_empty() {
        kad_publish_diagnostics::record(&runtime.diagnostics, |diagnostics| {
            diagnostics.phase = "idle".to_string();
            diagnostics.running = true;
            diagnostics.bootstrapped = true;
            diagnostics.gate_allowed = true;
            diagnostics.gate_block_reason.clear();
            diagnostics.item_count = 0;
            diagnostics.inspected_count = 0;
            diagnostics.attempted_files = 0;
            diagnostics.file_budget = KAD_SHARED_FILE_PUBLISH_SCAN_BUDGET;
            diagnostics.in_flight_count = publish_tasks.len();
            diagnostics.in_flight_budget = in_flight_budget;
            active_counts.write_diagnostics(diagnostics, available_search_permits);
            diagnostics.keyword_budget = KAD_KEYWORD_PUBLISH_BUDGET;
            diagnostics.source_budget = KAD_SOURCE_PUBLISH_BUDGET;
            diagnostics.notes_budget = KAD_NOTES_PUBLISH_BUDGET;
            diagnostics.budget_exhausted = false;
            diagnostics.keyword_due_count = 0;
            diagnostics.source_due_count = 0;
            diagnostics.notes_due_count = 0;
            diagnostics.keyword_attempted = 0;
            diagnostics.source_attempted = 0;
            diagnostics.notes_attempted = 0;
            diagnostics.keyword_skipped_by_budget = 0;
            diagnostics.source_skipped_by_budget = 0;
            diagnostics.notes_skipped_by_budget = 0;
            diagnostics.keyword_published = 0;
            diagnostics.source_published = 0;
            diagnostics.notes_published = 0;
            diagnostics.keyword_acked_contacts = 0;
            diagnostics.source_acked_contacts = 0;
            diagnostics.notes_acked_contacts = 0;
        });
        return Ok(0);
    }

    // Master CSharedFileList::Publish gate (SharedFileList.cpp:3066-3076): do not
    // emit PUBLISH_*_REQ while firewalled-and-unreachable (no buddy, UDP closed).
    let gate = kad_publish_gate_input(runtime).await;
    if !kad_publish_schedule::kad_publish_allowed(gate) {
        let gate_block_reason = if !gate.kad_connected {
            "kadNotConnected"
        } else if gate.tcp_firewalled && !gate.buddy_connected && !gate.udp_open {
            "firewalledWithoutBuddyOrUdp"
        } else {
            "blocked"
        };
        kad_publish_diagnostics::record(&runtime.diagnostics, |diagnostics| {
            diagnostics.phase = "blocked".to_string();
            diagnostics.running = true;
            diagnostics.bootstrapped = true;
            diagnostics.gate_allowed = false;
            diagnostics.gate_block_reason = gate_block_reason.to_string();
            diagnostics.item_count = shared_files.len();
            diagnostics.inspected_count = 0;
            diagnostics.attempted_files = 0;
            diagnostics.file_budget = KAD_SHARED_FILE_PUBLISH_SCAN_BUDGET;
            diagnostics.in_flight_count = publish_tasks.len();
            diagnostics.in_flight_budget = in_flight_budget;
            active_counts.write_diagnostics(diagnostics, available_search_permits);
            diagnostics.keyword_budget = KAD_KEYWORD_PUBLISH_BUDGET;
            diagnostics.source_budget = KAD_SOURCE_PUBLISH_BUDGET;
            diagnostics.notes_budget = KAD_NOTES_PUBLISH_BUDGET;
            diagnostics.budget_exhausted = false;
            diagnostics.keyword_attempted = 0;
            diagnostics.source_attempted = 0;
            diagnostics.notes_attempted = 0;
            diagnostics.keyword_skipped_by_budget = 0;
            diagnostics.source_skipped_by_budget = 0;
            diagnostics.notes_skipped_by_budget = 0;
        });
        tracing::debug!(
            "Kad shared-file publish skipped: firewalled without buddy and UDP not verified-open"
        );
        return Ok(0);
    }

    let network = &runtime.network;
    let bind_addr = network.kad_bind_addr;
    let source_publish_identity = source_publish_client_hash(network.user_hash);
    let source_publish_settings = SourcePublishSettings {
        tcp_port: network.listen_port,
        obfuscation_enabled: network.config.obfuscation_enabled,
    };
    // Select the oracle STOREFILE publish branch from the live firewall/buddy
    // state (Search.cpp:700-745): open → direct UDP callback → buddy relay.
    // `None` = firewalled with neither relay path usable right now (e.g. the
    // buddy dropped after the gate check); source publishes skip this cycle,
    // mirroring the oracle's PrepareToStop for that state.
    let source_publish_reachability = if !gate.tcp_firewalled {
        Some(SourcePublishReachability::Open)
    } else if gate.udp_open {
        Some(SourcePublishReachability::DirectUdpCallback)
    } else {
        runtime
            .kad_buddy
            .lock()
            .await
            .outgoing_buddy_udp_endpoint()
            .map(|(buddy_ip, buddy_kad_port)| SourcePublishReachability::BuddyRelay {
                buddy_ip,
                buddy_kad_port,
            })
    };
    let source_publish_buddy_ip = match source_publish_reachability {
        Some(SourcePublishReachability::BuddyRelay { buddy_ip, .. }) => Some(buddy_ip),
        _ => None,
    };
    let own_kad_id = runtime.dht.own_id();
    let mut keyword_totals = PublishAttemptStats::default();
    let mut source_totals = PublishAttemptStats::default();
    let mut notes_totals = PublishAttemptStats::default();
    let mut keyword_published = 0usize;
    let mut source_published = 0usize;
    let mut notes_published = 0usize;
    drain_completed_kad_publish_tasks(
        runtime,
        schedule,
        publish_tasks,
        &mut keyword_totals,
        &mut source_totals,
        &mut notes_totals,
        &mut keyword_published,
        &mut source_published,
        &mut notes_published,
        active_counts,
    )
    .await;
    let mut available_publish_starts = runtime.dht.available_search_permits();
    if available_publish_starts == 0 && publish_tasks.is_empty() {
        kad_publish_diagnostics::record(&runtime.diagnostics, |diagnostics| {
            diagnostics.phase = "dhtSearchBusy".to_string();
            diagnostics.running = true;
            diagnostics.bootstrapped = true;
            diagnostics.gate_allowed = false;
            diagnostics.gate_block_reason = "dhtSearchBusy".to_string();
            diagnostics.item_count = shared_files.len();
            diagnostics.inspected_count = 0;
            diagnostics.attempted_files = 0;
            diagnostics.file_budget = KAD_SHARED_FILE_PUBLISH_SCAN_BUDGET;
            diagnostics.in_flight_count = publish_tasks.len();
            diagnostics.in_flight_budget = in_flight_budget;
            active_counts.write_diagnostics(diagnostics, available_publish_starts);
            diagnostics.keyword_budget = KAD_KEYWORD_PUBLISH_BUDGET;
            diagnostics.source_budget = KAD_SOURCE_PUBLISH_BUDGET;
            diagnostics.notes_budget = KAD_NOTES_PUBLISH_BUDGET;
            diagnostics.budget_exhausted = true;
            diagnostics.keyword_attempted = 0;
            diagnostics.source_attempted = 0;
            diagnostics.notes_attempted = 0;
            diagnostics.keyword_skipped_by_budget = 0;
            diagnostics.source_skipped_by_budget = 0;
            diagnostics.notes_skipped_by_budget = 0;
            diagnostics.tick_secs = KAD_SHARED_FILE_PUBLISH_TICK_SECS;
        });
        return Ok(shared_files.len());
    }
    if publish_tasks.len() >= in_flight_budget {
        kad_publish_diagnostics::record(&runtime.diagnostics, |diagnostics| {
            diagnostics.phase = "publishing".to_string();
            diagnostics.running = true;
            diagnostics.bootstrapped = true;
            diagnostics.gate_allowed = true;
            diagnostics.gate_block_reason.clear();
            diagnostics.item_count = shared_files.len();
            diagnostics.inspected_count = 0;
            diagnostics.attempted_files = 0;
            diagnostics.file_budget = KAD_SHARED_FILE_PUBLISH_SCAN_BUDGET;
            diagnostics.in_flight_count = publish_tasks.len();
            diagnostics.in_flight_budget = in_flight_budget;
            active_counts.write_diagnostics(diagnostics, available_publish_starts);
            diagnostics.keyword_budget = KAD_KEYWORD_PUBLISH_BUDGET;
            diagnostics.source_budget = KAD_SOURCE_PUBLISH_BUDGET;
            diagnostics.notes_budget = KAD_NOTES_PUBLISH_BUDGET;
            diagnostics.budget_exhausted = true;
            diagnostics.keyword_published = keyword_published;
            diagnostics.source_published = source_published;
            diagnostics.notes_published = notes_published;
            diagnostics.keyword_due_count = 0;
            diagnostics.source_due_count = 0;
            diagnostics.notes_due_count = 0;
            diagnostics.keyword_attempted = 0;
            diagnostics.source_attempted = 0;
            diagnostics.notes_attempted = 0;
            diagnostics.keyword_skipped_by_budget = 0;
            diagnostics.source_skipped_by_budget = 0;
            diagnostics.notes_skipped_by_budget = 0;
            diagnostics.keyword_acked_contacts = keyword_totals.acked_contacts;
            diagnostics.source_acked_contacts = source_totals.acked_contacts;
            diagnostics.notes_acked_contacts = notes_totals.acked_contacts;
            diagnostics.tick_secs = KAD_SHARED_FILE_PUBLISH_TICK_SECS;
        });
        return Ok(shared_files.len());
    }
    let mut keyword_due_count = 0usize;
    let mut source_due_count = 0usize;
    let mut notes_due_count = 0usize;
    let mut keyword_attempted = 0usize;
    let mut source_attempted = 0usize;
    let mut notes_attempted = 0usize;
    let mut keyword_skipped_by_budget = 0usize;
    let mut source_skipped_by_budget = 0usize;
    let mut notes_skipped_by_budget = 0usize;
    let mut attempted_keywords_this_cycle = HashSet::new();
    // Our Kad node id is the notes publisher identity (master STORENOTES writes
    // GetKadID() into the second 128-bit field of KADEMLIA2_PUBLISH_NOTES_REQ).
    let notes_publisher_id = runtime.dht.own_id();
    let item_count = shared_files.len();
    let start = schedule.cursor(item_count);
    let mut inspected = 0usize;
    let mut attempted_files = 0usize;

    for offset in 0..item_count.min(KAD_SHARED_FILE_PUBLISH_SCAN_BUDGET) {
        let entry = &shared_files[(start + offset) % item_count];
        let now = Instant::now();
        let keyword_terms = significant_keyword_words_unique(&entry.canonical_name);
        schedule.retain_keywords(&entry.file_hash, keyword_terms.iter().map(String::as_str));
        let due_keyword = keyword_terms.iter().find(|keyword| {
            schedule.keyword_due(&entry.file_hash, keyword, now)
                && !attempted_keywords_this_cycle.contains(keyword.as_str())
        });
        let due_keyword = due_keyword.cloned();
        let keyword_due = due_keyword.is_some();
        let source_due = source_publish_reachability.is_some()
            && schedule.source_due(&entry.file_hash, now, source_publish_buddy_ip);
        let notes_due =
            kad_publish_schedule::file_has_publishable_note(&entry.comment, entry.rating)
                && schedule.notes_due(&entry.file_hash, now);
        keyword_due_count += usize::from(keyword_due);
        source_due_count += usize::from(source_due);
        notes_due_count += usize::from(notes_due);
        inspected = offset + 1;
        if !keyword_due && !source_due && !notes_due {
            continue;
        }
        let file_hash: Ed2kHash = match entry.file_hash.parse() {
            Ok(hash) => hash,
            Err(error) => {
                tracing::warn!(
                    file_hash = %entry.file_hash,
                    error = %error,
                    "skipping invalid shared-file hash during Kad publish cycle"
                );
                continue;
            }
        };
        let mut attempted_this_file = false;

        // MFC can start keyword and source store searches independently in one
        // Publish() tick. Rust has an additional global DHT start budget, so let
        // source publish claim the first available start to avoid keyword work
        // starving source visibility after a large-library restart.
        if source_due {
            if source_attempted >= KAD_SOURCE_PUBLISH_BUDGET
                || available_publish_starts == 0
                || publish_tasks.len() >= in_flight_budget
                || !active_counts.can_start(KadSharedPublishKind::Source)
            {
                source_skipped_by_budget += 1;
            } else {
                source_attempted += 1;
                attempted_this_file = true;
                let source_tags = build_source_publish_tags(
                    bind_addr.port(),
                    source_publish_settings,
                    entry.file_size,
                    source_publish_reachability
                        .expect("source_due implies a usable publish reachability"),
                    own_kad_id,
                );
                let dht = runtime.dht.clone();
                let file_hash_text = entry.file_hash.clone();
                let fanout = network.kad_publish_contact_fanout;
                let started_at = now;
                mark_kad_file_publish_started(
                    &runtime.metadata_store,
                    schedule,
                    &file_hash_text,
                    MetadataKadOutboundPublishKind::Source,
                    started_at,
                    Utc::now().timestamp_millis(),
                    source_publish_buddy_ip,
                );
                available_publish_starts = available_publish_starts.saturating_sub(1);
                active_counts.started(KadSharedPublishKind::Source);
                publish_tasks.spawn(async move {
                    let result = dht
                        .publish_source_with_class_and_fanout(
                            file_hash,
                            source_publish_identity,
                            source_tags,
                            RpcWorkClass::Publish,
                            fanout,
                        )
                        .await;
                    KadSharedPublishOutcome {
                        kind: KadSharedPublishKind::Source,
                        file_hashes: vec![file_hash_text],
                        keyword: None,
                        started_at,
                        result: match result {
                            Ok(stats) => Ok(stats),
                            Err(DhtError::SearchBusy) => Err(KadSharedPublishError::Busy),
                            Err(DhtError::SearchTimeout) => Err(KadSharedPublishError::TimedOut),
                            Err(error) => Err(KadSharedPublishError::Failed(error.to_string())),
                        },
                    }
                });
            }
        }

        if let Some(keyword) = due_keyword.as_deref() {
            if keyword_attempted >= KAD_KEYWORD_PUBLISH_BUDGET
                || available_publish_starts == 0
                || publish_tasks.len() >= in_flight_budget
                || !active_counts.can_start(KadSharedPublishKind::Keyword)
            {
                keyword_skipped_by_budget += 1;
            } else {
                let keyword_hash = keyword_target(keyword);
                let keyword = keyword.to_string();
                let keyword_entries = kad_keyword_publish_entries_for_keyword(
                    &shared_files,
                    &keyword,
                    KAD_KEYWORD_PUBLISH_FILE_LIMIT,
                    (start + offset) % item_count,
                );
                if keyword_entries.is_empty() {
                    keyword_skipped_by_budget += 1;
                } else {
                    keyword_attempted += 1;
                    attempted_keywords_this_cycle.insert(keyword.clone());
                    attempted_this_file = true;
                    let keyword_file_hashes: Vec<String> = keyword_entries
                        .iter()
                        .map(|(file_hash, _)| file_hash.clone())
                        .collect();
                    let keyword_entries = keyword_entries
                        .into_iter()
                        .map(|(_, publish_entry)| publish_entry)
                        .collect();
                    let dht = runtime.dht.clone();
                    let fanout = network.kad_publish_contact_fanout;
                    let started_at = now;
                    mark_kad_keyword_publish_started(
                        &runtime.metadata_store,
                        schedule,
                        &keyword_file_hashes,
                        &keyword,
                        started_at,
                        Utc::now().timestamp_millis(),
                    );
                    available_publish_starts = available_publish_starts.saturating_sub(1);
                    active_counts.started(KadSharedPublishKind::Keyword);
                    publish_tasks.spawn(async move {
                        let result = dht
                            .publish_keyword_entries_with_class_and_fanout(
                                keyword_hash,
                                keyword_entries,
                                RpcWorkClass::Publish,
                                fanout,
                            )
                            .await;
                        KadSharedPublishOutcome {
                            kind: KadSharedPublishKind::Keyword,
                            file_hashes: keyword_file_hashes,
                            keyword: Some(keyword),
                            started_at,
                            result: match result {
                                Ok(stats) => Ok(stats),
                                Err(DhtError::SearchBusy) => Err(KadSharedPublishError::Busy),
                                Err(DhtError::SearchTimeout) => {
                                    Err(KadSharedPublishError::TimedOut)
                                }
                                Err(error) => Err(KadSharedPublishError::Failed(error.to_string())),
                            },
                        }
                    });
                }
            }
        }

        // Notes (comment/rating) publish: only for files that actually carry a
        // user-set comment/rating, on the 24h notes interval (master
        // CKnownFile::PublishNotes + STORENOTES tags). Per-file gated like keyword
        // and source so an un-annotated file never emits a notes publish.
        if notes_due {
            if notes_attempted >= KAD_NOTES_PUBLISH_BUDGET
                || available_publish_starts == 0
                || publish_tasks.len() >= in_flight_budget
                || !active_counts.can_start(KadSharedPublishKind::Notes)
            {
                notes_skipped_by_budget += 1;
            } else {
                notes_attempted += 1;
                attempted_this_file = true;
                // Master STORENOTES taglist: FILENAME, FILERATING (>0 only),
                // DESCRIPTION (non-empty only), FILESIZE.
                let mut notes_tags = vec![Tag::filename(entry.canonical_name.clone())];
                if entry.rating > 0 {
                    notes_tags.push(Tag::new_short(
                        emulebb_kad_proto::tag_name::FILERATING,
                        emulebb_kad_proto::TagValue::UInt(u64::from(entry.rating)),
                    ));
                }
                if !entry.comment.is_empty() {
                    notes_tags.push(Tag::new_short(
                        emulebb_kad_proto::tag_name::DESCRIPTION,
                        emulebb_kad_proto::TagValue::String(entry.comment.clone()),
                    ));
                }
                notes_tags.push(Tag::filesize(entry.file_size));
                let dht = runtime.dht.clone();
                let file_hash_text = entry.file_hash.clone();
                let fanout = network.kad_publish_contact_fanout;
                let started_at = now;
                mark_kad_file_publish_started(
                    &runtime.metadata_store,
                    schedule,
                    &file_hash_text,
                    MetadataKadOutboundPublishKind::Notes,
                    started_at,
                    Utc::now().timestamp_millis(),
                    None,
                );
                available_publish_starts = available_publish_starts.saturating_sub(1);
                active_counts.started(KadSharedPublishKind::Notes);
                publish_tasks.spawn(async move {
                    let result = dht
                        .publish_notes_with_class_and_fanout(
                            file_hash,
                            notes_publisher_id,
                            notes_tags,
                            RpcWorkClass::Publish,
                            fanout,
                        )
                        .await;
                    KadSharedPublishOutcome {
                        kind: KadSharedPublishKind::Notes,
                        file_hashes: vec![file_hash_text],
                        keyword: None,
                        started_at,
                        result: match result {
                            Ok(stats) => Ok(stats),
                            Err(DhtError::SearchBusy) => Err(KadSharedPublishError::Busy),
                            Err(DhtError::SearchTimeout) => Err(KadSharedPublishError::TimedOut),
                            Err(error) => Err(KadSharedPublishError::Failed(error.to_string())),
                        },
                    }
                });
            }
        }
        if attempted_this_file {
            attempted_files += 1;
        }
    }
    schedule.advance_cursor(start, inspected, item_count);
    let budget_exhausted = (inspected >= KAD_SHARED_FILE_PUBLISH_SCAN_BUDGET
        && inspected < item_count)
        || publish_tasks.len() >= in_flight_budget
        || keyword_skipped_by_budget > 0
        || source_skipped_by_budget > 0
        || notes_skipped_by_budget > 0;
    if keyword_attempted > 0 || source_attempted > 0 || notes_attempted > 0 {
        kad_publish_diagnostics::record(&runtime.diagnostics, |diagnostics| {
            diagnostics.phase = "publishing".to_string();
            diagnostics.running = true;
            diagnostics.bootstrapped = true;
            diagnostics.gate_allowed = true;
            diagnostics.gate_block_reason.clear();
            diagnostics.item_count = item_count;
            diagnostics.inspected_count = inspected;
            diagnostics.attempted_files = attempted_files;
            diagnostics.file_budget = KAD_SHARED_FILE_PUBLISH_SCAN_BUDGET;
            diagnostics.in_flight_count = publish_tasks.len();
            diagnostics.in_flight_budget = in_flight_budget;
            active_counts.write_diagnostics(diagnostics, available_publish_starts);
            diagnostics.keyword_budget = KAD_KEYWORD_PUBLISH_BUDGET;
            diagnostics.source_budget = KAD_SOURCE_PUBLISH_BUDGET;
            diagnostics.notes_budget = KAD_NOTES_PUBLISH_BUDGET;
            diagnostics.budget_exhausted = budget_exhausted;
            diagnostics.keyword_due_count = keyword_due_count;
            diagnostics.source_due_count = source_due_count;
            diagnostics.notes_due_count = notes_due_count;
            diagnostics.keyword_attempted = keyword_attempted;
            diagnostics.source_attempted = source_attempted;
            diagnostics.notes_attempted = notes_attempted;
            diagnostics.keyword_skipped_by_budget = keyword_skipped_by_budget;
            diagnostics.source_skipped_by_budget = source_skipped_by_budget;
            diagnostics.notes_skipped_by_budget = notes_skipped_by_budget;
            diagnostics.tick_secs = KAD_SHARED_FILE_PUBLISH_TICK_SECS;
        });
    }

    kad_publish_diagnostics::record(&runtime.diagnostics, |diagnostics| {
        diagnostics.phase = if publish_tasks.is_empty() {
            "idle".to_string()
        } else {
            "publishing".to_string()
        };
        diagnostics.running = true;
        diagnostics.bootstrapped = true;
        diagnostics.gate_allowed = true;
        diagnostics.gate_block_reason.clear();
        diagnostics.item_count = item_count;
        diagnostics.inspected_count = inspected;
        diagnostics.attempted_files = attempted_files;
        diagnostics.file_budget = KAD_SHARED_FILE_PUBLISH_SCAN_BUDGET;
        diagnostics.in_flight_count = publish_tasks.len();
        diagnostics.in_flight_budget = in_flight_budget;
        active_counts.write_diagnostics(diagnostics, available_publish_starts);
        diagnostics.keyword_budget = KAD_KEYWORD_PUBLISH_BUDGET;
        diagnostics.source_budget = KAD_SOURCE_PUBLISH_BUDGET;
        diagnostics.notes_budget = KAD_NOTES_PUBLISH_BUDGET;
        diagnostics.budget_exhausted = budget_exhausted;
        diagnostics.keyword_due_count = keyword_due_count;
        diagnostics.source_due_count = source_due_count;
        diagnostics.notes_due_count = notes_due_count;
        diagnostics.keyword_attempted = keyword_attempted;
        diagnostics.source_attempted = source_attempted;
        diagnostics.notes_attempted = notes_attempted;
        diagnostics.keyword_skipped_by_budget = keyword_skipped_by_budget;
        diagnostics.source_skipped_by_budget = source_skipped_by_budget;
        diagnostics.notes_skipped_by_budget = notes_skipped_by_budget;
        diagnostics.keyword_published = keyword_published;
        diagnostics.source_published = source_published;
        diagnostics.notes_published = notes_published;
        diagnostics.keyword_acked_contacts = keyword_totals.acked_contacts;
        diagnostics.source_acked_contacts = source_totals.acked_contacts;
        diagnostics.notes_acked_contacts = notes_totals.acked_contacts;
        diagnostics.tick_secs = KAD_SHARED_FILE_PUBLISH_TICK_SECS;
    });

    if keyword_published > 0 || source_published > 0 || notes_published > 0 {
        tracing::info!(
            "Kad shared-file publish cycle items={} inspected={} attempted_files={} keyword_published={} keyword_acked={} source_published={} source_acked={} notes_published={} notes_acked={}",
            item_count,
            inspected,
            attempted_files,
            keyword_published,
            keyword_totals.acked_contacts,
            source_published,
            source_totals.acked_contacts,
            notes_published,
            notes_totals.acked_contacts,
        );
        // Per-round outbound-publish rollup milestone (no-op without
        // EMULEBB_RUST_LOG_DIR): one diag line summarizing how many files'
        // keywords/sources/notes we stored to Kad this cycle.
        diag_kad_event::publish_round(
            item_count,
            keyword_published,
            keyword_totals.acked_contacts,
            source_published,
            source_totals.acked_contacts,
            notes_published,
            notes_totals.acked_contacts,
        );
    }

    Ok(item_count)
}

#[allow(clippy::too_many_arguments)]
async fn drain_completed_kad_publish_tasks(
    runtime: &KadPublishLoopRuntime,
    schedule: &mut kad_publish_schedule::KadPublishSchedule,
    publish_tasks: &mut JoinSet<KadSharedPublishOutcome>,
    keyword_totals: &mut PublishAttemptStats,
    source_totals: &mut PublishAttemptStats,
    notes_totals: &mut PublishAttemptStats,
    keyword_published: &mut usize,
    source_published: &mut usize,
    notes_published: &mut usize,
    active_counts: &mut KadSharedPublishActiveCounts,
) {
    loop {
        let joined =
            match tokio::time::timeout(Duration::from_millis(1), publish_tasks.join_next()).await {
                Ok(Some(joined)) => joined,
                Ok(None) | Err(_) => break,
            };
        let outcome = match joined {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::warn!("Kad shared-file publish task failed to join: {error}");
                continue;
            }
        };
        let elapsed_ms = outcome.started_at.elapsed().as_millis() as u64;
        let primary_file_hash = outcome.file_hashes.first().cloned().unwrap_or_default();
        active_counts.finished(outcome.kind);
        match outcome.result {
            Ok(stats) => match outcome.kind {
                KadSharedPublishKind::Keyword => {
                    record_kad_publish_completion(
                        runtime,
                        outcome.kind,
                        outcome.file_hashes.len(),
                        stats,
                    );
                    // Oracle load feedback (Search.cpp:166-167): a hot keyword
                    // (average answering-node load > 20) is deferred up to 7
                    // days instead of republishing on the base interval.
                    if let Some(keyword) = outcome.keyword.as_deref() {
                        let node_load = stats.node_load();
                        schedule.defer_keyword_by_load(keyword, node_load, Instant::now());
                        if node_load > 20 {
                            tracing::debug!(
                                keyword,
                                node_load,
                                "Kad keyword republish load-deferred (oracle AddLoad)"
                            );
                        }
                    }
                    accumulate_publish_stats(keyword_totals, stats);
                    diag_kad_event::publish(
                        diag_kad_event::KadPublishKind::Keyword,
                        &primary_file_hash,
                        outcome.file_hashes.len(),
                        stats,
                    );
                    *keyword_published += outcome.file_hashes.len();
                }
                KadSharedPublishKind::Source => {
                    record_kad_publish_completion(runtime, outcome.kind, 1, stats);
                    accumulate_publish_stats(source_totals, stats);
                    diag_kad_event::publish(
                        diag_kad_event::KadPublishKind::Source,
                        &primary_file_hash,
                        1,
                        stats,
                    );
                    *source_published += 1;
                }
                KadSharedPublishKind::Notes => {
                    record_kad_publish_completion(runtime, outcome.kind, 1, stats);
                    accumulate_publish_stats(notes_totals, stats);
                    diag_kad_event::publish(
                        diag_kad_event::KadPublishKind::Notes,
                        &primary_file_hash,
                        1,
                        stats,
                    );
                    *notes_published += 1;
                }
            },
            Err(KadSharedPublishError::Busy) => {
                record_kad_publish_failure(runtime, outcome.kind, KadPublishFailureClass::Busy);
                diag_kad_event::publish_failure(
                    diag_publish_kind(outcome.kind),
                    &primary_file_hash,
                    outcome.file_hashes.len(),
                    "busy",
                    elapsed_ms,
                    "",
                );
                tracing::debug!(
                    file_hash = %primary_file_hash,
                    kind = outcome.kind.label(),
                    elapsed_ms,
                    "Kad shared-file publish skipped: DHT search capacity busy"
                );
            }
            Err(KadSharedPublishError::TimedOut) => {
                record_kad_publish_failure(runtime, outcome.kind, KadPublishFailureClass::TimedOut);
                diag_kad_event::publish_failure(
                    diag_publish_kind(outcome.kind),
                    &primary_file_hash,
                    outcome.file_hashes.len(),
                    "timedOut",
                    elapsed_ms,
                    "",
                );
                tracing::debug!(
                    file_hash = %primary_file_hash,
                    kind = outcome.kind.label(),
                    elapsed_ms,
                    "Kad shared-file publish attempt timed out"
                );
            }
            Err(KadSharedPublishError::Failed(error)) => {
                record_kad_publish_failure(runtime, outcome.kind, KadPublishFailureClass::Other);
                diag_kad_event::publish_failure(
                    diag_publish_kind(outcome.kind),
                    &primary_file_hash,
                    outcome.file_hashes.len(),
                    "failed",
                    elapsed_ms,
                    &error,
                );
                tracing::debug!(
                    file_hash = %primary_file_hash,
                    kind = outcome.kind.label(),
                    elapsed_ms,
                    "Kad shared-file publish attempt failed: {error}"
                );
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum KadPublishFailureClass {
    Busy,
    TimedOut,
    Other,
}

fn record_kad_publish_completion(
    runtime: &KadPublishLoopRuntime,
    kind: KadSharedPublishKind,
    published_count: usize,
    stats: PublishAttemptStats,
) {
    kad_publish_diagnostics::record(&runtime.diagnostics, |diagnostics| {
        diagnostics.completed_count = diagnostics.completed_count.saturating_add(1);
        match kind {
            KadSharedPublishKind::Keyword => {
                diagnostics.keyword_published_total = diagnostics
                    .keyword_published_total
                    .saturating_add(published_count);
                diagnostics.keyword_contacts_considered_total = diagnostics
                    .keyword_contacts_considered_total
                    .saturating_add(stats.closest_contacts_considered);
                diagnostics.keyword_attempted_contacts_total = diagnostics
                    .keyword_attempted_contacts_total
                    .saturating_add(stats.attempted_contacts);
                diagnostics.keyword_acked_contacts_total = diagnostics
                    .keyword_acked_contacts_total
                    .saturating_add(stats.acked_contacts);
                diagnostics.keyword_contact_timeouts_total = diagnostics
                    .keyword_contact_timeouts_total
                    .saturating_add(stats.timed_out_contacts);
            }
            KadSharedPublishKind::Source => {
                diagnostics.source_published_total = diagnostics
                    .source_published_total
                    .saturating_add(published_count);
                diagnostics.source_contacts_considered_total = diagnostics
                    .source_contacts_considered_total
                    .saturating_add(stats.closest_contacts_considered);
                diagnostics.source_attempted_contacts_total = diagnostics
                    .source_attempted_contacts_total
                    .saturating_add(stats.attempted_contacts);
                diagnostics.source_acked_contacts_total = diagnostics
                    .source_acked_contacts_total
                    .saturating_add(stats.acked_contacts);
                diagnostics.source_contact_timeouts_total = diagnostics
                    .source_contact_timeouts_total
                    .saturating_add(stats.timed_out_contacts);
            }
            KadSharedPublishKind::Notes => {
                diagnostics.notes_published_total = diagnostics
                    .notes_published_total
                    .saturating_add(published_count);
                diagnostics.notes_contacts_considered_total = diagnostics
                    .notes_contacts_considered_total
                    .saturating_add(stats.closest_contacts_considered);
                diagnostics.notes_attempted_contacts_total = diagnostics
                    .notes_attempted_contacts_total
                    .saturating_add(stats.attempted_contacts);
                diagnostics.notes_acked_contacts_total = diagnostics
                    .notes_acked_contacts_total
                    .saturating_add(stats.acked_contacts);
                diagnostics.notes_contact_timeouts_total = diagnostics
                    .notes_contact_timeouts_total
                    .saturating_add(stats.timed_out_contacts);
            }
        }
    });
}

fn record_kad_publish_failure(
    runtime: &KadPublishLoopRuntime,
    kind: KadSharedPublishKind,
    failure_class: KadPublishFailureClass,
) {
    kad_publish_diagnostics::record(&runtime.diagnostics, |diagnostics| {
        diagnostics.failed_count = diagnostics.failed_count.saturating_add(1);
        match failure_class {
            KadPublishFailureClass::Busy => {
                diagnostics.busy_count = diagnostics.busy_count.saturating_add(1);
            }
            KadPublishFailureClass::TimedOut => {
                diagnostics.timed_out_count = diagnostics.timed_out_count.saturating_add(1);
            }
            KadPublishFailureClass::Other => {}
        }
        match kind {
            KadSharedPublishKind::Keyword => {
                diagnostics.keyword_failed = diagnostics.keyword_failed.saturating_add(1);
            }
            KadSharedPublishKind::Source => {
                diagnostics.source_failed = diagnostics.source_failed.saturating_add(1);
            }
            KadSharedPublishKind::Notes => {
                diagnostics.notes_failed = diagnostics.notes_failed.saturating_add(1);
            }
        }
    });
}

async fn kad_publishable_shared_files(
    runtime: &Ed2kTransferRuntime,
) -> Result<Vec<MetadataTransferPublishEntry>> {
    let shared_catalog = runtime.shared_catalog();
    let entries = shared_catalog
        .read()
        .await
        .iter()
        .filter(|entry| entry.verified_complete && !entry.compatibility_hint)
        .map(kad_publish_entry_from_shared_entry)
        .collect::<Vec<_>>();
    Ok(kad_publishable_shared_file_entries(entries))
}

fn kad_publish_entry_from_shared_entry(entry: &Ed2kSharedEntry) -> MetadataTransferPublishEntry {
    MetadataTransferPublishEntry {
        file_hash: entry.file_hash.clone(),
        canonical_name: entry.canonical_name.clone(),
        file_size: entry.file_size,
        aich_root: entry.aich_root.clone(),
        upload_priority: entry.upload_priority.clone(),
        auto_upload_priority: entry.auto_upload_priority,
        session_uploaded_bytes: entry.publish.session_uploaded_bytes,
        session_request_count: entry.publish.session_request_count,
        session_accept_count: entry.publish.session_accept_count,
        all_time_uploaded_bytes: entry.all_time_uploaded_bytes,
        all_time_upload_requests: entry.publish.all_time_request_count,
        all_time_upload_accepts: entry.publish.all_time_accept_count,
        last_upload_request_ms: entry.publish.last_request_unix_ms,
        comment: entry.comment.clone(),
        rating: entry.rating,
    }
}

fn kad_publishable_shared_file_entries(
    entries: Vec<MetadataTransferPublishEntry>,
) -> Vec<MetadataTransferPublishEntry> {
    let now_unix_ms = Utc::now().timestamp_millis();
    let mut ranked = entries
        .into_iter()
        .enumerate()
        .map(|(sequence, entry)| {
            let rank = shared_publish_rank(SharedPublishRankInput {
                file_hash: &entry.file_hash,
                file_size: entry.file_size,
                upload_priority: &entry.upload_priority,
                auto_upload_priority: entry.auto_upload_priority,
                queued_count: 0,
                session_request_count: entry.session_request_count,
                session_accept_count: entry.session_accept_count,
                all_time_request_count: entry.all_time_upload_requests,
                all_time_accept_count: entry.all_time_upload_accepts,
                all_time_uploaded_bytes: entry.all_time_uploaded_bytes,
                session_uploaded_bytes: entry.session_uploaded_bytes,
                last_request_unix_ms: entry.last_upload_request_ms,
                last_publish_unix_ms: 0,
                sequence,
                now_unix_ms,
            });
            (rank, entry)
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|(left, _), (right, _)| compare_shared_publish_rank(left, right));
    ranked.into_iter().map(|(_, entry)| entry).collect()
}

fn kad_keyword_publish_entries_for_keyword(
    shared_files: &[MetadataTransferPublishEntry],
    keyword: &str,
    limit: usize,
    start_index: usize,
) -> Vec<(String, KeywordPublishEntry)> {
    let mut entries = Vec::new();
    if shared_files.is_empty() || limit == 0 {
        return entries;
    }
    let start_index = start_index % shared_files.len();
    for offset in 0..shared_files.len() {
        if entries.len() >= limit {
            break;
        }
        let entry = &shared_files[(start_index + offset) % shared_files.len()];
        if !significant_keyword_words_unique(&entry.canonical_name)
            .iter()
            .any(|term| term == keyword)
        {
            continue;
        }
        let file_hash = match entry.file_hash.parse() {
            Ok(file_hash) => file_hash,
            Err(error) => {
                tracing::warn!(
                    file_hash = %entry.file_hash,
                    error = %error,
                    "skipping invalid shared-file hash during Kad keyword batch build"
                );
                continue;
            }
        };
        let mut tags = vec![
            Tag::filename(entry.canonical_name.clone()),
            Tag::filesize(entry.file_size),
            Tag::sources(1),
        ];
        if let Some(file_type) = ed2k_file_type_search_term(&entry.canonical_name) {
            tags.push(Tag::filetype(file_type));
        }
        entries.push((
            entry.file_hash.clone(),
            KeywordPublishEntry {
                file_hash,
                tags,
                aich_hash: entry
                    .aich_root
                    .as_deref()
                    .and_then(decode_aich_root_hex_for_publish),
            },
        ));
    }
    entries
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
    total.total_load += stats.total_load;
    total.load_responses += stats.load_responses;
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
    /// Lazily-read handle to the UDP reask loop, so a buddy link established here
    /// can answer buddy-relayed `OP_REASKCALLBACKTCP` over UDP (source side). Read
    /// at buddy-link spawn time because the reask loop starts after this task.
    reask_handle: Arc<std::sync::Mutex<Option<ReaskSourceHandle>>>,
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

        // kad_event routing_summary (uniform-diagnostics-v2 §3.3): emit the
        // routing-table + connection gauge from this periodic maintenance tick
        // (the 30s cadence matches the master's LogRoutingSummary interval). A
        // no-op when EMULEBB_RUST_LOG_DIR is unset.
        let connected = runtime.dht.is_bootstrapped();
        let counts = runtime.dht.routing_summary_counts().await;
        crate::diag_kad_event::routing_summary(
            connected,
            !connected,
            need.tcp_firewalled,
            false,
            counts,
        );

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

/// Kad version at/above which a contact supports the receiver-key three-way
/// handshake (oracle `KADEMLIA_VERSION8_49b` = 8). Below this a contact must be
/// IP-verified with a legacy challenge instead.
const LEGACY_VERIFY_VERSION_THRESHOLD: u8 = 8;
/// Kad version 7 (oracle `KADEMLIA_VERSION7_49a`): supports sender/receiver keys
/// but not `HELLO_RES_ACK`, so on a HELLO_REQ it is verified with a PING
/// challenge, and it is not challenged at all on the HELLO_RES leg.
const KAD_VERSION_7: u8 = 7;

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
    if let IpAddr::V4(ip) = from.ip()
        && network.ip_filter.is_filtered(ip)
    {
        tracing::trace!("dropping Kad packet from IP-filtered peer {from}");
        return Ok(());
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
                // The requester's version gates the KADMISCOPTIONS tag (v8+ only),
                // matching SendMyDetails(..., byContactVersion, ...).
                req.version,
            )
            .await?;
            dht.send_packet(from, &KadPacket::HelloRes(response))
                .await?;
            // Oracle Process_KADEMLIA2_HELLO_REQ: a pre-v8 contact that was
            // added/updated without a valid receiver key supports no three-way
            // handshake, so verify its source IP with a legacy challenge
            // (v7 -> PING, <v7 -> REQ). send_legacy_challenge enforces the
            // one-challenge-per-IP guard and picks the opcode by version.
            if added_or_updated
                && !receiver_verify_key_valid
                && req.version < LEGACY_VERIFY_VERSION_THRESHOLD
                && let Err(error) = dht
                    .send_legacy_challenge(req.node_id, req.version, from)
                    .await
            {
                tracing::debug!("failed to send legacy Kad challenge to {from}: {error:#}");
            }
        }
        KadPacket::HelloRes(res) => {
            let mut added_or_updated = false;
            match dht
                .add_contact_from_hello(from, res.node_id, res.tcp_port, res.version, &res.tags)
                .await
            {
                Ok(metadata) => {
                    added_or_updated = true;
                    if metadata.requests_hello_res_ack {
                        dht.send_packet(
                            from,
                            &KadPacket::HelloResAck(HelloResAck {
                                node_id: dht.own_id(),
                                tags: Vec::new(),
                            }),
                        )
                        .await?;
                    }
                }
                Err(error) => {
                    tracing::debug!(
                        "failed to record Kad HELLO_RES contact from {from}: {error:#}"
                    );
                }
            }
            // Oracle Process_KADEMLIA2_HELLO_RES: a pre-0.49a (version < 7)
            // contact answered our HELLO_REQ but supports no keys, and the
            // response could still be spoofed, so verify it with a legacy REQ
            // challenge. (Version 7 relies on receiver keys here and is not
            // challenged on the HELLO_RES leg.)
            if added_or_updated
                && !receiver_verify_key_valid
                && res.version < KAD_VERSION_7
                && let Err(error) = dht
                    .send_legacy_challenge(res.node_id, res.version, from)
                    .await
            {
                tracing::debug!("failed to send legacy Kad challenge to {from}: {error:#}");
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
                tracing::debug!("ignoring Kad HELLO_RES_ACK from {from}: receiver key is invalid");
            } else if let IpAddr::V4(ip) = from.ip() {
                if dht.verify_contact(&ack.node_id, ip).await {
                    tracing::debug!("verified Kad contact {} via HELLO_RES_ACK", ack.node_id);
                } else {
                    tracing::debug!("Kad HELLO_RES_ACK from {from}: no matching contact to verify");
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
                    tracing::debug!("ignoring unrequested Kad FIREWALLED_RES from {from}");
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
        KadPacket::FirewalledAckRes => {
            // Legacy (pre-Kad-v7) UDP TCP-firewall-check acknowledgement: a helper
            // we probed connected back to our eD2k TCP port and confirms it over
            // UDP (0x59) instead of over the modern TCP OP_KAD_FWTCPCHECK_ACK path
            // (oracle Process_KADEMLIA_FIREWALLED_ACK_RES -> IncFirewalled). Count
            // it as an open observation through the SAME TCP-recheck accounting as
            // the modern ack. `record_tcp_open_ack` source-validates internally
            // (IsKadFirewallCheckIP), so an unrequested 0x59 is dropped — stricter
            // than the oracle's unvalidated legacy path, matching rust's posture.
            // The decoder already enforced the oracle's zero-length body check.
            let accepted = kad_firewall
                .lock()
                .await
                .record_tcp_open_ack(from.ip(), Utc::now());
            tracing::debug!("Kad legacy FIREWALLED_ACK_RES from {from} accepted={accepted}");
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
                    crate::diag_kad_event::firewall(false);
                    // An open result that discovered a distinct external UDP port
                    // is the most authoritative reachability fact; pin it over the
                    // UPnP mapping. (The driver loop also applies this on finish;
                    // doing it here too means a fast inbound completion is reflected
                    // immediately.)
                    if let Some(external_udp_port) = summary.external_udp_port {
                        runtime
                            .reachability
                            .set_peer_confirmed_udp_port(external_udp_port);
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
            // Oracle Process_KADEMLIA2_PUBLISH_KEY_REQ: do not index (and do not
            // give the publisher a false ack) while we are UDP firewalled, and
            // drop publishes whose XOR distance exceeds SEARCHTOLERANCE unless on
            // a LAN IP.
            if kad_firewall.lock().await.is_udp_firewalled() {
                tracing::debug!("dropping Kad PUBLISH_KEY_REQ from {from}: locally UDP firewalled");
                return Ok(());
            }
            if !kad_publish_within_tolerance(dht.own_id(), req.target, from.ip()) {
                tracing::debug!(
                    "dropping Kad PUBLISH_KEY_REQ from {from}: target beyond SEARCHTOLERANCE"
                );
                return Ok(());
            }
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
            if kad_firewall.lock().await.is_udp_firewalled() {
                tracing::debug!(
                    "dropping Kad PUBLISH_SOURCE_REQ from {from}: locally UDP firewalled"
                );
                return Ok(());
            }
            if !kad_publish_within_tolerance(dht.own_id(), req.target, from.ip()) {
                tracing::debug!(
                    "dropping Kad PUBLISH_SOURCE_REQ from {from}: target beyond SEARCHTOLERANCE"
                );
                return Ok(());
            }
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
            if kad_firewall.lock().await.is_udp_firewalled() {
                tracing::debug!(
                    "dropping Kad PUBLISH_NOTES_REQ from {from}: locally UDP firewalled"
                );
                return Ok(());
            }
            if !kad_publish_within_tolerance(dht.own_id(), req.target, from.ip()) {
                tracing::debug!(
                    "dropping Kad PUBLISH_NOTES_REQ from {from}: target beyond SEARCHTOLERANCE"
                );
                return Ok(());
            }
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
            // Snapshot the reask handle into an owned Option before the await so no
            // MutexGuard is held across it (the future must stay Send).
            let reask_handle = runtime.reask_handle.lock().unwrap().clone();
            handle_kad_find_buddy_res(
                dht,
                kad_buddy,
                buddy_registry,
                &runtime.reachability,
                &runtime.transfer_runtime,
                reask_handle,
                network,
                from,
                res,
            )
            .await;
        }
        KadPacket::CallbackReq(req) => {
            handle_kad_callback_req(kad_buddy, buddy_registry, from, &req).await;
        }
        KadPacket::Res(res) => {
            // Oracle Process_KADEMLIA2_RES top check: a KADEMLIA2_RES whose target
            // echoes one of our pending legacy challenges verifies that pre-v8
            // contact (its source IP is not spoofed). Other RES packets are
            // search/lookup responses consumed by the traversal layer, so a
            // non-match here is a no-op.
            if let IpAddr::V4(ip) = from.ip()
                && dht
                    .resolve_legacy_challenge(res.target, ip, emulebb_kad_proto::opcode::RES)
                    .await
            {
                tracing::debug!(
                    "verified Kad contact via legacy challenge (KADEMLIA2_RES) from {from}"
                );
            }
        }
        KadPacket::Pong(_) => {
            // Oracle Process_KADEMLIA2_PONG top check: a PONG answering one of our
            // pending legacy PING challenges verifies that version-7 contact.
            if let IpAddr::V4(ip) = from.ip()
                && dht
                    .resolve_legacy_challenge(
                        emulebb_kad_proto::NodeId::ZERO,
                        ip,
                        emulebb_kad_proto::opcode::PONG,
                    )
                    .await
            {
                tracing::debug!(
                    "verified Kad contact via legacy challenge (KADEMLIA2_PONG) from {from}"
                );
            }
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
#[allow(clippy::too_many_arguments)]
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
        return Err(error).with_context(|| format!("failed to send Kad FINDBUDDY_RES to {from}"));
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
#[allow(clippy::too_many_arguments)]
async fn handle_kad_find_buddy_res(
    dht: &DhtNode,
    kad_buddy: &Arc<Mutex<KadBuddyState>>,
    buddy_registry: &BuddySocketRegistry,
    reachability: &ExternalReachability,
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    reask_handle: Option<ReaskSourceHandle>,
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
    set_hello_buddy_snapshot(Some(HelloBuddySnapshot {
        ip: buddy_ip,
        udp_port: from.port(),
    }));
    // kad_event buddy milestone `buddy_established` (uniform-diagnostics-v2 §3.3).
    crate::diag_kad_event::buddy(true, from);
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
            reask_handle,
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
        // kad_event buddy milestone `buddy_released` (uniform-diagnostics-v2 §3.3).
        crate::diag_kad_event::buddy(false, buddy_addr);
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

    let frame =
        encode_kad_callback_relay_frame(req.buddy_id.0, &req.file_hash, requester_ip, req.tcp_port);
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
    // Sources that reported No Needed Parts; the driver runs the A4AF-lite swap
    // on each after the round (move to another wanted file the peer serves, else
    // drop). Kept across retry rounds.
    let mut no_needed_parts_sources: Vec<Ed2kFoundSource> = Vec::new();

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
            // Release the global connection budget slot this finished download
            // held (acquired in spawn_pending_ed2k_direct_downloads) so the next
            // source can claim it.
            transfer_runtime.release_source_connection();
            let (peer_addr, source, result) = match joined {
                Ok(joined) => joined,
                Err(join_error) => {
                    // The worker panicked. Returning here without draining the
                    // remaining in-flight tasks would leak their connection-budget
                    // slots permanently (their release_source_connection never
                    // runs), eventually stalling the whole download subsystem.
                    // Abort and drain the rest, releasing one slot per task.
                    active_downloads.abort_all();
                    while active_downloads.join_next().await.is_some() {
                        transfer_runtime.release_source_connection();
                    }
                    return Err(anyhow::Error::new(join_error)
                        .context("ED2K direct download worker panicked"));
                }
            };
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
                        // Release the budget slot held by each aborted download.
                        while active_downloads.join_next().await.is_some() {
                            transfer_runtime.release_source_connection();
                        }
                        return Ok(DirectDownloadOutcome {
                            completed: true,
                            accepted_incomplete_peers,
                            last_error: last_error
                                .as_ref()
                                .map(|error| anyhow::anyhow!(error.to_string())),
                            detached_reask_endpoints: detached_reask_endpoints.clone(),
                            no_needed_parts_sources: no_needed_parts_sources.clone(),
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
                Ok(Ed2kPeerDownloadOutcome::NoNeededParts) => {
                    // No Needed Parts for this file (eMuleBB DS_NONEEDEDPARTS). The
                    // driver runs the A4AF-lite SwapToAnotherFile afterwards: this
                    // source is moved to another wanted file it serves, if any.
                    no_needed_parts_sources.push(source.clone());
                    tracing::info!(
                        "ED2K direct download peer reported no needed parts file_hash={} peer={}",
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
            no_needed_parts_sources: no_needed_parts_sources.clone(),
        };
        if outcome.completed
            || outcome.accepted_incomplete_peers != 0
            || !outcome.no_needed_parts_sources.is_empty()
        {
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
        // Global connection budget (eMule CListenSocket::TooManySockets): the
        // shared coordinator caps concurrent outgoing source connections and
        // the new-connection per-5s rate across ALL transfers. When no slot is
        // available, leave the source pending (push it back) for the next cycle
        // rather than dropping it, and stop spawning this round.
        let budget = context
            .transfer_runtime
            .try_acquire_source_connection_detailed();
        crate::diag_sched::source_conn_budget(budget, context.file_hash_hex, &source);
        if !budget.admitted {
            pending_sources.push_front(source);
            tracing::debug!(
                "ED2K direct download deferred by connection budget file_hash={} active={}",
                context.file_hash_hex,
                active_downloads.len()
            );
            break;
        }
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
        source_path: summary.source_path,
        priority: "normal".to_string(),
        auto_upload_priority: false,
        all_time_uploaded_bytes: 0,
        all_time_upload_requests: 0,
        all_time_upload_accepts: 0,
        comment: String::new(),
        rating: 0,
    }
}

const ED2K_DOWNLOAD_KAD_SOURCE_CAP: usize = 64;
const ED2K_DOWNLOAD_KAD_SOURCE_TIMEOUT_FLOOR_SECS: u64 = 45;
const ED2K_DOWNLOAD_KAD_SOURCE_RETRY_DELAY_MS: u64 = 500;
const ED2K_DOWNLOAD_KAD_SOURCE_QUIET_DELAY_MS: u64 = 750;
const ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS: usize = 2;
const ED2K_DOWNLOAD_SOURCE_REQUERY_DELAY_SECS: u64 = 5;
const ED2K_DOWNLOAD_BACKGROUND_RETRY_SECS: u64 = 5;
/// Startup download hydration pacing. Let the post-connect startup burst (large
/// shared-library reload, publish) settle before adding download load, then stagger
/// each resumed download so a big backlog does not thunder-herd the state lock /
/// source coordinator and starve REST (a 39-download all-at-once resume wedged the
/// control plane in a live test).
const RESUME_DOWNLOADS_INITIAL_DELAY_SECS: u64 = 20;
const RESUME_DOWNLOADS_STAGGER_MS: u64 = 1500;
/// Parse a REST-surface IP string (the `Upload.address` / `TransferSource.ip`
/// fields) into an `Ipv4Addr` for the ban store. Returns `None` when the value
/// is empty or not a dialable IPv4 (e.g. a LowID client-id), so the ban falls
/// back to the user-hash key alone.
fn parse_ban_ip(ip: &str) -> Option<Ipv4Addr> {
    ip.trim()
        .parse::<Ipv4Addr>()
        .ok()
        .filter(|ip| !ip.is_unspecified())
}

/// Parse a 32-char lowercase-hex user-hash string into the 16-byte key used by
/// the ban store. Returns `None` for a missing/malformed hash so the ban falls
/// back to the IP key alone.
fn parse_ban_hash(user_hash: Option<&str>) -> Option<[u8; 16]> {
    let hash = user_hash?;
    let bytes = hex::decode(hash).ok()?;
    <[u8; 16]>::try_from(bytes.as_slice()).ok()
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

/// Case-insensitive check that `path` resides within `dir`, tolerating the
/// `\\?\` verbatim long-path prefix and `/` vs `\` separators that share/ingest
/// paths carry on Windows. Used to classify a transfer as a download (its file
/// is in the incoming dir) vs a pure share.
fn path_is_within(path: &str, dir: &std::path::Path) -> bool {
    fn norm(s: &str) -> String {
        s.strip_prefix(r"\\?\")
            .unwrap_or(s)
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    }
    let base = norm(&dir.display().to_string());
    if base.is_empty() {
        return false;
    }
    let candidate = norm(path);
    candidate == base || candidate.starts_with(&format!("{base}\\"))
}

fn apply_persisted_transfer_category(
    transfer: &mut Transfer,
    manifest: &Ed2kResumeManifest,
    categories: &BTreeMap<u32, Category>,
) {
    if let Some(category) = categories
        .get(&manifest.category_id)
        .or_else(|| categories.get(&0))
    {
        transfer.category_id = category.id;
        transfer.category_name = category.name.clone();
    } else {
        transfer.category_id = 0;
        transfer.category_name = default_transfer_category_name().to_string();
    }
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

fn connected_server_keyword_search_timeout(config: &Ed2kConfig) -> Duration {
    // WHY: eMuleBB MFC arms `TimerServerTimeout` for 50 seconds before a silent
    // connected server search falls through to the global UDP walk.
    Duration::from_secs(
        config
            .connect_timeout_secs
            .max(ED2K_LOCAL_SERVER_SEARCH_TIMEOUT_SECS),
    )
}

#[cfg(test)]
mod tests {
    use emulebb_ed2k::{NatConfig, ipfilter::IpFilter};
    use emulebb_index::IndexedFile;
    use emulebb_kad_proto::{NodeId, Tag, TagValue};
    use md4::{Digest, Md4};

    use super::*;
    use crate::source_publish::emule_high_id_source_type;

    #[test]
    fn path_is_within_classifies_incoming_vs_shared_dirs() {
        use std::path::Path;
        let incoming = Path::new(r"C:\Downloads\Incoming");
        // A downloaded file living in the incoming dir (verbatim long path, mixed
        // case, forward slashes) is recognized as in-incoming.
        assert!(path_is_within(
            r"\\?\C:\Downloads\Incoming\example.iso",
            incoming
        ));
        assert!(path_is_within(
            r"c:/downloads/incoming/sub/file.bin",
            incoming
        ));
        // A file shared only from a separate shared dir is NOT in-incoming.
        assert!(!path_is_within(r"D:\Library\Media\sample.mkv", incoming));
        // A sibling dir sharing a name prefix must not count as inside.
        assert!(!path_is_within(r"C:\Downloads\IncomingOther\x", incoming));
        assert!(!path_is_within("anything", Path::new("")));
    }

    #[test]
    fn connected_server_keyword_search_timeout_matches_mfc_floor() {
        let mut config = Ed2kConfig {
            connect_timeout_secs: 1,
            ..Ed2kConfig::default()
        };

        assert_eq!(
            connected_server_keyword_search_timeout(&config),
            Duration::from_secs(ED2K_LOCAL_SERVER_SEARCH_TIMEOUT_SECS)
        );

        config.connect_timeout_secs = 75;
        assert_eq!(
            connected_server_keyword_search_timeout(&config),
            Duration::from_secs(75)
        );
    }

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
            kad_routing_maintenance_enabled: true,
            kad_udp_firewall_check_enabled: true,
            kad_udp_firewall_check_interval_secs: 600,
            kad_tcp_firewall_check_enabled: true,
            kad_tcp_firewall_check_interval_secs: 600,
            kad_buddy_enabled: true,
            nat_config: NatConfig::default(),
            config: Ed2kConfig::default(),
            p2p_bind_ip: Some(Ipv4Addr::new(198, 51, 100, 10)),
            p2p_bind_interface: None,
            vpn_guard: VpnGuardConfig::default(),
            vpn_interface_bound: false,
            vpn_interface_bound_runtime: None,
            ip_filter: IpFilter::default(),
            ip_filter_path: None,
            ip_filter_level: emulebb_ed2k::ipfilter::DEFAULT_FILTER_LEVEL,
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
        let relayed = rx
            .try_recv()
            .expect("relay frame delivered to held buddy socket");
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

    #[tokio::test]
    async fn default_preferences_match_the_master() {
        // FIX 6: defaults aligned to srchybrid/Preferences.cpp +
        // PreferenceValidationSeams.h.
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        let prefs = core.preferences().await;
        assert_eq!(prefs.upload_limit_ki_bps, 6200);
        assert_eq!(prefs.download_limit_ki_bps, 12207);
        assert_eq!(prefs.max_connections, 500);
        assert_eq!(prefs.max_connections_per_five_seconds, 50);
        assert_eq!(prefs.max_sources_per_file, 600);
        assert_eq!(prefs.max_upload_slots, 12);
        assert_eq!(prefs.upload_slot_elastic_percent, 80);
        assert_eq!(prefs.queue_size, 10000);
        assert!(!prefs.auto_connect);
        assert!(prefs.reconnect);
    }

    #[test]
    fn preferences_json_without_reconnect_defaults_to_enabled() {
        let mut value = serde_json::to_value(default_preferences()).unwrap();
        value.as_object_mut().unwrap().remove("reconnect");

        let preferences: Preferences = serde_json::from_value(value).unwrap();

        assert!(preferences.reconnect);
    }

    #[tokio::test]
    async fn network_kademlia_disabled_refuses_kad_bootstrap() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        // Disable the Kademlia network (eMule thePrefs.GetNetworkKademlia() == false).
        core.update_preferences(PreferencesUpdate {
            network_kademlia: Some(false),
            ..PreferencesUpdate::default()
        })
        .await
        .unwrap();
        let err = core
            .bootstrap_kad("203.0.113.9", 4672)
            .await
            .expect_err("Kad bootstrap must be refused when networkKademlia=false");
        assert!(err.to_string().contains("Kademlia network is disabled"));
        // Re-enabling lets Kad start again.
        core.update_preferences(PreferencesUpdate {
            network_kademlia: Some(true),
            ..PreferencesUpdate::default()
        })
        .await
        .unwrap();
        assert!(core.bootstrap_kad("203.0.113.9", 4672).await.is_ok());
    }

    #[tokio::test]
    async fn vpn_guard_allows_kad_start_until_public_ip_disproves_allowed_cidr() {
        let transfer_root = unique_runtime_dir("emulebb-core-vpn-guard-kad-start");
        let mut network = test_network_config_with_store(
            &transfer_root,
            KadLocalStoreConfig::default(),
            SnoopQueueConfig::default(),
        );
        network.vpn_guard = VpnGuardConfig {
            enabled: true,
            mode: "block".to_string(),
            allowed_public_ip_cidrs: "8.8.8.0/24".to_string(),
        };
        network.vpn_interface_bound = true;
        let core = EmulebbCore::new_with_network(
            "test",
            FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
            transfer_root.join("transfers"),
            Some(network),
        )
        .unwrap();

        assert!(
            core.start_kad().await.is_ok(),
            "valid VPN-bound public-CIDR mode should not block before any public IP is observed"
        );
        core.set_kad_running(false).await;

        core.ed2k_reachability.set(Ipv4Addr::new(1, 1, 1, 1));
        let err = core
            .start_kad()
            .await
            .expect_err("Kad start must be refused after public IP is outside the allowed CIDR");
        assert!(err.to_string().contains("blocked by VPN guard"));
        assert!(
            err.to_string()
                .contains("outside VPN Guard allowed public IP CIDRs")
        );

        core.ed2k_reachability.set(Ipv4Addr::new(8, 8, 8, 8));
        assert!(core.start_kad().await.is_ok());
    }

    #[tokio::test]
    async fn network_ed2k_disabled_refuses_server_connect() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        // Disable the eD2k network (eMule thePrefs.GetNetworkED2K() == false): the
        // server connect is refused on the preference gate (before any network
        // config / VPN-guard checks).
        core.update_preferences(PreferencesUpdate {
            network_ed2k: Some(false),
            ..PreferencesUpdate::default()
        })
        .await
        .unwrap();
        let err = core
            .connect_ed2k()
            .await
            .expect_err("eD2k connect must be refused when networkEd2k=false");
        assert!(err.to_string().contains("eD2k network is disabled"));
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
            kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
            nat: Arc::new(NatManager::default()),
            shutdown: Arc::clone(&shutdown),
            server_reconnect_signal: Arc::new(tokio::sync::Notify::new()),
            target_server_endpoint: Arc::new(RwLock::new(None)),
            kad_firewall_recheck: None,
            tasks: vec![dht_task],
            download_tasks: Arc::clone(&core.ed2k_download_tasks),
        });

        let status = core.status().await;

        assert!(status.kad.running);
        assert!(!status.kad.connected);
        assert_eq!(status.kad.contact_count, Some(0));
        // Empty routing table: not connected and nothing to bootstrap from, so
        // we report not-bootstrapping (the always-running driver has no seeds).
        assert_eq!(status.kad.bootstrapping, Some(false));
        // Unverified firewall state is reported as open (oracle IsFirewalledUDP).
        assert_eq!(status.kad.firewalled, Some(false));
        assert_eq!(status.kad.users, None);
        assert_eq!(status.kad.files, None);
        shutdown.store(true, Ordering::SeqCst);
        let _ = core.disconnect_ed2k().await;
    }

    #[tokio::test]
    async fn ed2k_shared_catalog_publish_waits_for_connected_server() {
        let transfer_root = unique_runtime_dir("emulebb-core-shared-publish-disconnected");
        let core = EmulebbCore::new_with_network(
            "test",
            FileIndex::in_memory().unwrap(),
            &transfer_root,
            Some(test_network_config_with_store(
                &transfer_root,
                KadLocalStoreConfig::default(),
                SnoopQueueConfig::default(),
            )),
        )
        .unwrap();
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
            kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
            nat: Arc::new(NatManager::default()),
            shutdown: Arc::clone(&shutdown),
            server_reconnect_signal: Arc::new(tokio::sync::Notify::new()),
            target_server_endpoint: Arc::new(RwLock::new(None)),
            kad_firewall_recheck: None,
            tasks: vec![dht_task],
            download_tasks: Arc::clone(&core.ed2k_download_tasks),
        });

        assert_eq!(
            core.publish_ed2k_shared_catalog().await.unwrap(),
            Ed2kSharedCatalogPublishOutcome::NotConnected
        );
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
    fn source_type_switches_to_large_file_variant_at_old_max_emule_file_size() {
        // Oracle IsLargeFile(): strictly greater than OLD_MAX_EMULE_FILE_SIZE
        // (4290048000), not the raw u32 ceiling.
        assert_eq!(emule_high_id_source_type(4_290_048_000), 1);
        assert_eq!(emule_high_id_source_type(4_290_048_001), 4);
    }

    #[test]
    fn source_publish_tags_match_oracle_open_shape() {
        // Oracle non-firewalled STOREFILE branch (Search.cpp:732-743):
        // SOURCETYPE, SOURCEPORT, SOURCEUPORT, FILESIZE, ENCRYPTION — and no
        // SOURCEIP tag (indexers take the IP from the datagram sender).
        let tags = build_source_publish_tags(
            41000,
            SourcePublishSettings {
                tcp_port: 41001,
                obfuscation_enabled: false,
            },
            2_097_152,
            SourcePublishReachability::Open,
            NodeId::from_bytes([0x11; 16]),
        );

        assert_eq!(
            tags,
            vec![
                Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
                Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(41001)),
                Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
                Tag::filesize(2_097_152),
                Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0)),
            ]
        );
    }

    #[test]
    fn source_publish_tags_set_obfuscated_encryption_bits() {
        let tags = build_source_publish_tags(
            41000,
            SourcePublishSettings {
                tcp_port: 41001,
                obfuscation_enabled: true,
            },
            2_097_152,
            SourcePublishReachability::Open,
            NodeId::from_bytes([0x11; 16]),
        );

        assert_eq!(
            tags.last(),
            Some(&Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(3)))
        );
    }

    #[test]
    fn source_publish_tags_match_oracle_buddy_relay_shape() {
        // Oracle firewalled-with-buddy STOREFILE branch (Search.cpp:717-730):
        // SOURCETYPE 3 (uint8), SERVERIP = buddy in_addr DWORD, SERVERPORT =
        // buddy Kad UDP port, BUDDYHASH = uppercase hex of ~KadID in wire
        // order, then the common tail.
        let own_id = NodeId::from_bytes([0xF0; 16]);
        let tags = build_source_publish_tags(
            41000,
            SourcePublishSettings {
                tcp_port: 41001,
                obfuscation_enabled: false,
            },
            2_097_152,
            SourcePublishReachability::BuddyRelay {
                buddy_ip: "198.51.100.136".parse().unwrap(),
                buddy_kad_port: 4672,
            },
            own_id,
        );

        assert_eq!(
            tags,
            vec![
                Tag::new_short(tag_name::SOURCETYPE, TagValue::U8(3)),
                Tag::new_short(tag_name::SERVERIP, TagValue::UInt(0x8864_33C6)),
                Tag::new_short(tag_name::SERVERPORT, TagValue::UInt(4672)),
                Tag::new_short(
                    tag_name::BUDDYHASH,
                    TagValue::String("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F".to_string()),
                ),
                Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(41001)),
                Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
                Tag::filesize(2_097_152),
                Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0)),
            ]
        );
    }

    #[test]
    fn source_publish_tags_buddy_relay_uses_large_file_type_5() {
        let tags = build_source_publish_tags(
            41000,
            SourcePublishSettings {
                tcp_port: 41001,
                obfuscation_enabled: false,
            },
            EMULE_LARGE_FILE_SIZE_THRESHOLD + 1,
            SourcePublishReachability::BuddyRelay {
                buddy_ip: "198.51.100.136".parse().unwrap(),
                buddy_kad_port: 4672,
            },
            NodeId::from_bytes([0xF0; 16]),
        );

        assert_eq!(
            tags.first(),
            Some(&Tag::new_short(tag_name::SOURCETYPE, TagValue::U8(5)))
        );
    }

    #[test]
    fn source_publish_tags_direct_callback_sets_type_6_and_callback_bit() {
        // Oracle direct-callback STOREFILE branch (Search.cpp:708-715) +
        // GetMyConnectOptions(true, true): type 6 with connect options bit 3.
        let tags = build_source_publish_tags(
            41000,
            SourcePublishSettings {
                tcp_port: 41001,
                obfuscation_enabled: true,
            },
            2_097_152,
            SourcePublishReachability::DirectUdpCallback,
            NodeId::from_bytes([0x11; 16]),
        );

        assert_eq!(
            tags.first(),
            Some(&Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(6)))
        );
        assert_eq!(
            tags.last(),
            Some(&Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0x0B)))
        );
    }

    #[test]
    fn kad_hello_request_tags_advertise_source_udp_port_when_verified_open() {
        let tags = build_kad_hello_request_tags(41000, true, false, false, false, KAD_VERSION);

        assert_eq!(
            tags,
            vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))]
        );
    }

    #[test]
    fn kad_hello_request_tags_emit_source_port_and_misc_bits_additively() {
        // Oracle SendMyDetails writes SOURCEUPORT (intern port) AND KADMISCOPTIONS
        // (firewalled/ack) together, not one or the other.
        let tags = build_kad_hello_request_tags(41000, true, true, false, true, KAD_VERSION);

        assert_eq!(
            tags,
            vec![
                Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
                Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05)),
            ]
        );
    }

    #[test]
    fn kad_hello_tags_omit_misc_options_toward_pre_v8_contacts() {
        // Oracle SendMyDetails only writes (and counts) TAG_KADMISCOPTIONS when
        // byKadVersion >= KADEMLIA_VERSION8_49b. A v7 (or older) contact that
        // would otherwise get the ACK/firewall bits receives SOURCEUPORT only;
        // it is IP-verified via a PING / legacy challenge instead.
        for build in [
            build_kad_hello_request_tags as fn(u16, bool, bool, bool, bool, u8) -> Vec<Tag>,
            build_kad_hello_response_tags,
        ] {
            assert_eq!(
                build(41000, true, true, true, true, 7),
                vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))],
                "pre-v8 contact must not receive KADMISCOPTIONS"
            );
            // v8 exactly is the first version that receives it.
            assert!(
                build(41000, true, true, true, true, 8)
                    .iter()
                    .any(|tag| tag.name
                        == emulebb_kad_proto::TagName::Short(tag_name::KADMISCOPTIONS))
            );
        }
    }

    #[test]
    fn kad_publish_tolerance_gate_matches_oracle_distance_and_lan_exemption() {
        use std::net::Ipv4Addr;
        let own = NodeId::ZERO;

        // Close target (chunk0 distance well under SEARCHTOLERANCE) -> accepted.
        let close =
            NodeId::from_be_bytes([0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(kad_publish_within_tolerance(
            own,
            close,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        ));

        // Far target (chunk0 distance > SEARCHTOLERANCE) from a public IP -> dropped.
        let far =
            NodeId::from_be_bytes([0x7F, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!kad_publish_within_tolerance(
            own,
            far,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        ));

        // The same far target from a LAN IP is exempt -> accepted.
        assert!(kad_publish_within_tolerance(
            own,
            far,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))
        ));
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
        let tags = build_kad_hello_request_tags(41000, false, true, false, true, KAD_VERSION);

        assert_eq!(
            tags,
            vec![Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05))]
        );
    }

    #[test]
    fn kad_hello_response_tags_include_source_udp_port_and_misc_bits() {
        let tags = build_kad_hello_response_tags(41000, true, true, true, true, KAD_VERSION);

        assert_eq!(
            tags,
            vec![
                Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
                Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x07)),
            ]
        );
    }

    #[test]
    fn kad_hello_response_tags_gate_both_tags_like_request_and_oracle() {
        // Oracle SendMyDetails gates HELLO_RES tags as HELLO_REQ: SOURCEUPORT
        // only when advertising the intern port; KADMISCOPTIONS only on ACK/fw.
        assert!(build_kad_hello_response_tags(41000, false, false, false, false, KAD_VERSION).is_empty());
        assert_eq!(
            build_kad_hello_response_tags(41000, true, false, false, false, KAD_VERSION),
            vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))]
        );
        assert_eq!(
            build_kad_hello_response_tags(41000, false, true, false, true, KAD_VERSION),
            vec![Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05))]
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
    fn kad_publishable_shared_files_follow_mfc_publish_rank() {
        let shared = MetadataTransferPublishEntry {
            file_hash: Ed2kHash::from_bytes([0x11; 16]).to_string(),
            canonical_name: "shared.bin".to_string(),
            file_size: 128,
            aich_root: None,
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            session_uploaded_bytes: 0,
            session_request_count: 0,
            session_accept_count: 0,
            all_time_uploaded_bytes: 0,
            all_time_upload_requests: 0,
            all_time_upload_accepts: 0,
            last_upload_request_ms: 0,
            comment: "synthetic note".to_string(),
            rating: 4,
        };
        let other = MetadataTransferPublishEntry {
            file_hash: Ed2kHash::from_bytes([0x22; 16]).to_string(),
            canonical_name: "other.bin".to_string(),
            upload_priority: "release".to_string(),
            ..shared.clone()
        };

        let publishable = kad_publishable_shared_file_entries(vec![shared.clone(), other.clone()]);

        assert_eq!(publishable, vec![other, shared]);
    }

    #[test]
    fn kad_publish_entry_from_shared_catalog_preserves_live_rank_inputs() {
        let mut entry = Ed2kSharedEntry {
            file_hash: Ed2kHash::from_bytes([0x33; 16]).to_string(),
            canonical_name: "ubuntu-python-sample.iso".to_string(),
            file_size: 4096,
            verified_complete: true,
            verified_ranges: Vec::new(),
            compatibility_hint: false,
            source_count_hint: None,
            aich_root: Some("ab".repeat(20)),
            upload_priority: "high".to_string(),
            auto_upload_priority: false,
            comment: "synthetic note".to_string(),
            rating: 5,
            all_time_uploaded_bytes: 512,
            complete_parts: Vec::new(),
            publish: Default::default(),
        };
        entry.publish.session_uploaded_bytes = 128;
        entry.publish.session_request_count = 3;
        entry.publish.session_accept_count = 2;
        entry.publish.all_time_request_count = 7;
        entry.publish.all_time_accept_count = 4;
        entry.publish.last_request_unix_ms = 1_700_000_000_000;

        let publish = kad_publish_entry_from_shared_entry(&entry);

        assert_eq!(publish.session_uploaded_bytes, 128);
        assert_eq!(publish.session_request_count, 3);
        assert_eq!(publish.session_accept_count, 2);
        assert_eq!(publish.all_time_upload_requests, 7);
        assert_eq!(publish.all_time_upload_accepts, 4);
        assert_eq!(publish.comment, "synthetic note");
        assert_eq!(publish.rating, 5);
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
                source_type: 1,
                buddy_id: None,
                buddy_ip: None,
                buddy_port: 0,
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
        assert_eq!(search.id, "1");
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

    // Operator directive 2026-07-06: a network search submitted while the
    // backend is still connecting/absent must surface an honest "queued"
    // status with a reason and wait for readiness — never complete instantly
    // with local-only results — and identical queued queries are rejected
    // explicitly instead of amassing wire traffic for later.
    #[tokio::test]
    async fn network_search_queues_with_honest_status_and_rejects_duplicates() {
        let transfer_root = unique_runtime_dir("emulebb-core-search-queue");
        let network = test_network_config_with_store(
            &transfer_root,
            KadLocalStoreConfig::default(),
            SnoopQueueConfig::default(),
        );
        let core = EmulebbCore::new_with_network(
            "test",
            FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
            transfer_root.join("transfers"),
            Some(network),
        )
        .unwrap();

        let request = SearchCreate {
            query: "queued query".to_string(),
            method: "server".to_string(),
            ..Default::default()
        };
        let search = core.create_search(request.clone()).await.unwrap();
        assert_eq!(search.status, "queued");
        assert_eq!(
            search.status_reason.as_deref(),
            Some("waiting-for-server-connection")
        );

        // No server session ever connects: the search stays honestly queued
        // (drain ticks run but the backend never becomes ready).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let still_queued = core.search(&search.id).await.unwrap();
        assert_eq!(still_queued.status, "queued");

        // An identical queued query on the same lane is rejected explicitly.
        let error = core
            .create_search(request)
            .await
            .expect_err("duplicate queued query must be rejected");
        assert!(error.to_string().contains("already queued"));

        // A different query queues fine alongside it.
        let other = core
            .create_search(SearchCreate {
                query: "another queued query".to_string(),
                method: "server".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(other.status, "queued");
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

    #[tokio::test]
    async fn effective_ed2k_config_includes_runtime_servers() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        let base = Ed2kConfig {
            server_endpoints: vec!["203.0.113.10:4661".to_string()],
            ..Ed2kConfig::default()
        };
        core.add_server(ServerCreate {
            address: "203.0.113.20".to_string(),
            port: 4661,
            name: None,
            priority: None,
            static_server: Some(false),
            connect: None,
        })
        .await
        .unwrap();

        let config = core.effective_ed2k_config(&base, None).await.unwrap();

        assert!(
            config
                .server_endpoints
                .iter()
                .any(|endpoint| endpoint == "203.0.113.10:4661")
        );
        assert!(
            config
                .server_entries
                .iter()
                .any(|entry| entry.host == "203.0.113.20" && entry.port == 4661)
        );
    }

    #[tokio::test]
    async fn effective_ed2k_config_honors_reconnect_preference() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        core.update_preferences(PreferencesUpdate {
            reconnect: Some(false),
            ..PreferencesUpdate::default()
        })
        .await
        .unwrap();

        let config = core
            .effective_ed2k_config(&Ed2kConfig::default(), None)
            .await
            .unwrap();

        assert!(!config.reconnect_enabled);
    }

    #[tokio::test]
    async fn explicit_server_connect_targets_running_server_loop() {
        let transfer_root = unique_runtime_dir("emulebb-core-target-running-server-loop");
        let mut network = test_network_config_with_store(
            &transfer_root,
            KadLocalStoreConfig::default(),
            SnoopQueueConfig::default(),
        );
        network.config.server_endpoints = vec![
            "203.0.113.10:4661".to_string(),
            "203.0.113.20:4661".to_string(),
        ];
        let core = EmulebbCore::new_with_network(
            "test",
            FileIndex::in_memory().unwrap(),
            &transfer_root,
            Some(network),
        )
        .unwrap();
        let (search_handle, _search_inbox) = new_ed2k_server_search_channel(1);
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some("0.0.0.0:0".parse().unwrap()),
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let dht_task = dht.start();
        let target_server_endpoint = Arc::new(RwLock::new(None));
        let server_reconnect_signal = Arc::new(tokio::sync::Notify::new());

        *core.ed2k_runtime.lock().await = Some(Ed2kRuntime {
            search_handle,
            server_state: Arc::new(RwLock::new(Ed2kServerState::default())),
            dht,
            kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
            nat: Arc::new(NatManager::default()),
            shutdown: Arc::clone(&shutdown),
            server_reconnect_signal: Arc::clone(&server_reconnect_signal),
            target_server_endpoint: Arc::clone(&target_server_endpoint),
            kad_firewall_recheck: None,
            tasks: vec![dht_task],
            download_tasks: Arc::clone(&core.ed2k_download_tasks),
        });

        let result = core.connect_ed2k_server("203.0.113.20:4661").await.unwrap();

        assert!(result.is_some());
        assert_eq!(
            target_server_endpoint.read().await.as_deref(),
            Some("203.0.113.20:4661")
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                server_reconnect_signal.notified()
            )
            .await
            .is_ok(),
            "retargeting a running server loop must signal reconnect"
        );
        shutdown.store(true, Ordering::SeqCst);
        let _ = core.disconnect_ed2k().await;
    }

    #[tokio::test]
    async fn explicit_server_connect_to_live_endpoint_is_idempotent() {
        let transfer_root = unique_runtime_dir("emulebb-core-same-server-connect-noop");
        let mut network = test_network_config_with_store(
            &transfer_root,
            KadLocalStoreConfig::default(),
            SnoopQueueConfig::default(),
        );
        network.config.server_endpoints = vec!["203.0.113.20:4661".to_string()];
        let core = EmulebbCore::new_with_network(
            "test",
            FileIndex::in_memory().unwrap(),
            &transfer_root,
            Some(network),
        )
        .unwrap();
        let (search_handle, _search_inbox) = new_ed2k_server_search_channel(1);
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some("0.0.0.0:0".parse().unwrap()),
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let dht_task = dht.start();
        let target_server_endpoint = Arc::new(RwLock::new(None));
        let server_reconnect_signal = Arc::new(tokio::sync::Notify::new());
        let server_state = Arc::new(RwLock::new(Ed2kServerState {
            endpoint: Some("203.0.113.20:4661".parse().unwrap()),
            connected: true,
            ..Ed2kServerState::default()
        }));

        *core.ed2k_runtime.lock().await = Some(Ed2kRuntime {
            search_handle,
            server_state,
            dht,
            kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
            nat: Arc::new(NatManager::default()),
            shutdown: Arc::clone(&shutdown),
            server_reconnect_signal: Arc::clone(&server_reconnect_signal),
            target_server_endpoint: Arc::clone(&target_server_endpoint),
            kad_firewall_recheck: None,
            tasks: vec![dht_task],
            download_tasks: Arc::clone(&core.ed2k_download_tasks),
        });

        let result = core.connect_ed2k_server("203.0.113.20:4661").await.unwrap();

        assert!(result.is_some());
        assert_eq!(
            target_server_endpoint.read().await.as_deref(),
            Some("203.0.113.20:4661")
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                server_reconnect_signal.notified()
            )
            .await
            .is_err(),
            "same-endpoint connect must not drop a live server session"
        );
        shutdown.store(true, Ordering::SeqCst);
        let _ = core.disconnect_ed2k().await;
    }

    #[tokio::test]
    async fn merge_discovered_servers_adds_new_dedups_existing() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        core.add_server(ServerCreate {
            address: "45.82.80.155".to_string(),
            port: 5687,
            name: None,
            priority: None,
            static_server: Some(true),
            connect: None,
        })
        .await
        .unwrap();

        core.merge_discovered_ed2k_servers(vec![
            (Ipv4Addr::new(45, 82, 80, 155), 5687), // duplicate of existing
            (Ipv4Addr::new(203, 0, 113, 9), 4661),  // new
            (Ipv4Addr::new(203, 0, 113, 9), 4661),  // duplicate within batch
        ])
        .await;

        let servers = core.servers().await;
        let lugd = servers
            .iter()
            .filter(|s| s.address == "45.82.80.155" && s.port == 5687)
            .count();
        assert_eq!(lugd, 1, "existing server is not duplicated");
        let new_server = servers
            .iter()
            .find(|s| s.address == "203.0.113.9" && s.port == 4661)
            .expect("discovered server added");
        assert_eq!(new_server.priority, "low");
        assert!(!new_server.static_server);
    }

    #[tokio::test]
    async fn merge_discovered_servers_respects_add_servers_from_server_preference() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        // eMule GetAddServersFromServer default is on; turning it off must stop
        // OP_SERVERLIST auto-add.
        core.update_preferences(PreferencesUpdate {
            add_servers_from_server: Some(false),
            ..PreferencesUpdate::default()
        })
        .await
        .unwrap();
        core.merge_discovered_ed2k_servers(vec![(Ipv4Addr::new(203, 0, 113, 9), 4661)])
            .await;
        assert!(
            !core
                .servers()
                .await
                .iter()
                .any(|s| s.address == "203.0.113.9" && s.port == 4661),
            "auto-add disabled: a discovered server must not be added"
        );
    }

    #[tokio::test]
    async fn connect_failed_drops_non_static_dead_server_at_threshold() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        core.add_server(ServerCreate {
            address: "203.0.113.5".to_string(),
            port: 4661,
            name: None,
            priority: None,
            static_server: Some(false),
            connect: None,
        })
        .await
        .unwrap();
        let endpoint = "203.0.113.5:4661";

        // Default dead_server_retries = 1: first failure drops the server.
        core.note_ed2k_server_connect_failed(endpoint, 1).await;
        assert!(
            core.server(endpoint).await.is_none(),
            "non-static dead server is dropped at the threshold"
        );
    }

    #[tokio::test]
    async fn connect_failed_never_drops_static_server() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        core.add_server(ServerCreate {
            address: "203.0.113.6".to_string(),
            port: 4661,
            name: None,
            priority: None,
            static_server: Some(true),
            connect: None,
        })
        .await
        .unwrap();
        let endpoint = "203.0.113.6:4661";

        // Even far past the threshold, a static server is kept (eMule keeps
        // static servers); the fail-count is still tracked.
        for _ in 0..5 {
            core.note_ed2k_server_connect_failed(endpoint, 1).await;
        }
        let server = core.server(endpoint).await.expect("static server kept");
        assert!(server.failed_count >= 1);
    }

    #[tokio::test]
    async fn connect_succeeded_clears_fail_count() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        core.add_server(ServerCreate {
            address: "203.0.113.7".to_string(),
            port: 4661,
            name: None,
            priority: None,
            static_server: Some(false),
            connect: None,
        })
        .await
        .unwrap();
        let endpoint = "203.0.113.7:4661";

        // With a higher threshold, accumulate failures, then a success clears them.
        core.note_ed2k_server_connect_failed(endpoint, 3).await;
        core.note_ed2k_server_connect_failed(endpoint, 3).await;
        assert_eq!(core.server(endpoint).await.unwrap().failed_count, 2);
        core.note_ed2k_server_connect_succeeded(endpoint).await;
        assert_eq!(core.server(endpoint).await.unwrap().failed_count, 0);
        // The cleared count means it now takes the full threshold again to drop.
        core.note_ed2k_server_connect_failed(endpoint, 3).await;
        assert!(core.server(endpoint).await.is_some());
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
    fn significant_words_unique_preserve_first_occurrence_order() {
        assert_eq!(
            significant_keyword_words_unique("Ubuntu Python ubuntu programming Apache Camel"),
            vec![
                "ubuntu".to_string(),
                "python".to_string(),
                "programming".to_string(),
                "apache".to_string(),
                "camel".to_string(),
            ]
        );
    }

    #[test]
    fn keyword_publish_entries_batch_matching_files_up_to_stock_limit() {
        let mut shared_files = (0..160)
            .map(|index| MetadataTransferPublishEntry {
                file_hash: Ed2kHash::from_bytes([index as u8; 16]).to_string(),
                canonical_name: format!("Ubuntu Python Sample {index}.iso"),
                file_size: 1000 + index,
                aich_root: None,
                upload_priority: "normal".to_string(),
                auto_upload_priority: false,
                session_uploaded_bytes: 0,
                session_request_count: 0,
                session_accept_count: 0,
                all_time_uploaded_bytes: 0,
                all_time_upload_requests: 0,
                all_time_upload_accepts: 0,
                last_upload_request_ms: 0,
                comment: String::new(),
                rating: 0,
            })
            .collect::<Vec<_>>();
        shared_files.push(MetadataTransferPublishEntry {
            file_hash: Ed2kHash::from_bytes([0xFE; 16]).to_string(),
            canonical_name: "Apache Camel Sample.iso".to_string(),
            file_size: 1,
            aich_root: None,
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            session_uploaded_bytes: 0,
            session_request_count: 0,
            session_accept_count: 0,
            all_time_uploaded_bytes: 0,
            all_time_upload_requests: 0,
            all_time_upload_accepts: 0,
            last_upload_request_ms: 0,
            comment: String::new(),
            rating: 0,
        });

        let entries = kad_keyword_publish_entries_for_keyword(
            &shared_files,
            "ubuntu",
            KAD_KEYWORD_PUBLISH_FILE_LIMIT,
            0,
        );

        assert_eq!(entries.len(), KAD_KEYWORD_PUBLISH_FILE_LIMIT);
        assert_eq!(entries[0].1.file_hash, Ed2kHash::from_bytes([0_u8; 16]));
        assert_eq!(entries[149].1.file_hash, Ed2kHash::from_bytes([149_u8; 16]));
        assert!(
            entries
                .iter()
                .all(|(_, entry)| entry.tags.iter().any(|tag| tag == &Tag::sources(1)))
        );
    }

    #[test]
    fn keyword_publish_entries_start_at_triggering_file_and_wrap() {
        let shared_files = (0..160)
            .map(|index| MetadataTransferPublishEntry {
                file_hash: Ed2kHash::from_bytes([index as u8; 16]).to_string(),
                canonical_name: format!("Ubuntu Python Sample {index}.iso"),
                file_size: 1000 + index,
                aich_root: None,
                upload_priority: "normal".to_string(),
                auto_upload_priority: false,
                session_uploaded_bytes: 0,
                session_request_count: 0,
                session_accept_count: 0,
                all_time_uploaded_bytes: 0,
                all_time_upload_requests: 0,
                all_time_upload_accepts: 0,
                last_upload_request_ms: 0,
                comment: String::new(),
                rating: 0,
            })
            .collect::<Vec<_>>();

        let entries = kad_keyword_publish_entries_for_keyword(
            &shared_files,
            "ubuntu",
            KAD_KEYWORD_PUBLISH_FILE_LIMIT,
            155,
        );

        assert_eq!(entries.len(), KAD_KEYWORD_PUBLISH_FILE_LIMIT);
        assert_eq!(entries[0].1.file_hash, Ed2kHash::from_bytes([155_u8; 16]));
        assert_eq!(entries[4].1.file_hash, Ed2kHash::from_bytes([159_u8; 16]));
        assert_eq!(entries[5].1.file_hash, Ed2kHash::from_bytes([0_u8; 16]));
        assert_eq!(entries[149].1.file_hash, Ed2kHash::from_bytes([144_u8; 16]));
    }

    #[test]
    fn kad_shared_publish_active_counts_follow_mfc_store_caps() {
        let mut counts = KadSharedPublishActiveCounts::default();
        assert_eq!(
            kad_shared_publish_kind_cap(KadSharedPublishKind::Keyword),
            KAD_KEYWORD_PUBLISH_IN_FLIGHT_CAP
        );
        assert_eq!(
            kad_shared_publish_kind_cap(KadSharedPublishKind::Source),
            KAD_SOURCE_PUBLISH_IN_FLIGHT_CAP
        );
        assert_eq!(
            kad_shared_publish_kind_cap(KadSharedPublishKind::Notes),
            KAD_NOTES_PUBLISH_IN_FLIGHT_CAP
        );

        for _ in 0..KAD_KEYWORD_PUBLISH_IN_FLIGHT_CAP {
            assert!(counts.can_start(KadSharedPublishKind::Keyword));
            counts.started(KadSharedPublishKind::Keyword);
        }
        assert!(!counts.can_start(KadSharedPublishKind::Keyword));
        counts.finished(KadSharedPublishKind::Keyword);
        assert!(counts.can_start(KadSharedPublishKind::Keyword));

        counts.started(KadSharedPublishKind::Notes);
        assert!(!counts.can_start(KadSharedPublishKind::Notes));
        counts.finished(KadSharedPublishKind::Notes);
        assert!(counts.can_start(KadSharedPublishKind::Notes));
    }

    #[test]
    fn kad_shared_publish_budget_reserves_search_capacity() {
        assert_eq!(kad_shared_file_publish_in_flight_budget_for(1), 1);
        assert_eq!(kad_shared_file_publish_in_flight_budget_for(2), 1);
        assert_eq!(kad_shared_file_publish_in_flight_budget_for(5), 4);
        assert_eq!(
            kad_shared_file_publish_in_flight_budget_for(KAD_SHARED_FILE_PUBLISH_DHT_SEARCH_CAP),
            KAD_SHARED_FILE_PUBLISH_KIND_CAP_TOTAL
        );
    }

    #[test]
    fn kad_rpc_class_budgets_give_publish_traversals_room_to_converge() {
        let budgets = kad_rpc_class_budgets();
        assert_eq!(
            budgets.publish_max_outbound_pps,
            KAD_PUBLISH_MAX_OUTBOUND_PPS
        );
        assert!(
            budgets.publish_max_outbound_pps
                > RpcClassBudgetConfig::default().publish_max_outbound_pps
        );
    }

    #[test]
    fn kad_outbound_publish_schedule_advances_when_store_search_starts() {
        let store = MetadataStore::in_memory().unwrap();
        let mut schedule = kad_publish_schedule::KadPublishSchedule::new();
        let started_at = Instant::now();
        let published_at_ms = 12_345;
        let keyword = "ubuntu";
        let keyword_hashes = vec![
            Ed2kHash::from_bytes([0x11; 16]).to_string(),
            Ed2kHash::from_bytes([0x22; 16]).to_string(),
        ];
        let source_hash = Ed2kHash::from_bytes([0x33; 16]).to_string();
        let notes_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

        mark_kad_keyword_publish_started(
            &store,
            &mut schedule,
            &keyword_hashes,
            keyword,
            started_at,
            published_at_ms,
        );
        mark_kad_file_publish_started(
            &store,
            &mut schedule,
            &source_hash,
            MetadataKadOutboundPublishKind::Source,
            started_at,
            published_at_ms,
            None,
        );
        mark_kad_file_publish_started(
            &store,
            &mut schedule,
            &notes_hash,
            MetadataKadOutboundPublishKind::Notes,
            started_at,
            published_at_ms,
            None,
        );

        for file_hash in &keyword_hashes {
            assert!(!schedule.keyword_due(file_hash, keyword, started_at));
        }
        assert!(!schedule.source_due(&source_hash, started_at, None));
        assert!(!schedule.notes_due(&notes_hash, started_at));

        let persisted = store.load_kad_outbound_publish_schedule().unwrap();
        assert_eq!(persisted.publishes.len(), 4);
        assert!(persisted.publishes.iter().any(|publish| {
            publish.file_hash == keyword_hashes[0]
                && publish.publish_kind == MetadataKadOutboundPublishKind::Keyword
                && publish.keyword == keyword
                && publish.published_at_ms == published_at_ms
        }));
        assert!(persisted.publishes.iter().any(|publish| {
            publish.file_hash == source_hash
                && publish.publish_kind == MetadataKadOutboundPublishKind::Source
                && publish.keyword.is_empty()
                && publish.published_at_ms == published_at_ms
        }));
        assert!(persisted.publishes.iter().any(|publish| {
            publish.file_hash == notes_hash
                && publish.publish_kind == MetadataKadOutboundPublishKind::Notes
                && publish.keyword.is_empty()
                && publish.published_at_ms == published_at_ms
        }));
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

    #[test]
    fn category_id_selector_ignores_malformed_category_name_like_master() {
        let request = serde_json::from_str::<TransferCreate>(
            r#"{"link":"ed2k://|file|Selector.bin|1|00112233445566778899aabbccddeeff|/","categoryId":0,"categoryName":1}"#,
        )
        .unwrap();

        assert_eq!(request.category_id, Some(0));
        assert_eq!(request.category_name, None);
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
    async fn delete_transfer_files_removes_delivered_completed_download() {
        let runtime_dir = unique_runtime_dir("emulebb-core-delete-delivered-transfer");
        let transfer_root = runtime_dir.join("transfers");
        let incoming_dir = runtime_dir.join("incoming");
        let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root)
            .unwrap()
            .with_incoming_dir(incoming_dir.clone());
        let payload = b"completed delivered download payload".repeat(64);
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into()).to_string();
        let transfer = core
            .create_transfer(TransferCreate {
                link: Some(format!(
                    "ed2k://|file|Delivered.Delete.bin|{}|{}|/",
                    payload.len(),
                    file_hash
                )),
                links: None,
                category_id: None,
                category_name: None,
                paused: Some(true),
            })
            .await
            .unwrap();

        core.ed2k_transfers
            .store_md4_hashset(&file_hash, Vec::new())
            .await
            .unwrap();
        core.ed2k_transfers
            .store_piece_data(&file_hash, 0, &payload)
            .await
            .unwrap();
        let completed = core
            .refresh_transfer_from_manifest_default(&file_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(completed.state, "completed");
        core.deliver_completed_transfer(&file_hash).await;
        let delivered_manifest = core.ed2k_transfers.manifest(&file_hash).await.unwrap();
        let delivered_path = PathBuf::from(delivered_manifest.delivered_path.as_deref().unwrap());
        assert_eq!(std::fs::read(&delivered_path).unwrap(), payload);

        let row_only = core
            .delete_completed_transfer_row(&file_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row_only.hash, transfer.hash);
        assert!(
            delivered_path.exists(),
            "row-only completed transfer removal must preserve the delivered file"
        );

        let deleted = core
            .delete_transfer_files(&file_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(deleted.hash, transfer.hash);
        assert!(
            !delivered_path.exists(),
            "destructive transfer delete must remove the delivered completed file"
        );
        assert!(!transfer_root.join(&file_hash).exists());
        assert!(core.transfer(&file_hash).await.is_none());
    }

    #[tokio::test]
    async fn unshare_file_removes_live_shared_catalog_entry() {
        let runtime_dir = unique_runtime_dir("emulebb-core-unshare-shared-catalog");
        let transfer_root = runtime_dir.join("transfers");
        let shared_path = runtime_dir.join("shared.bin");
        fs::write(&shared_path, b"shared catalog removal payload").unwrap();
        let core =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();

        let share = core
            .share_local_file(LocalShareCreate {
                path: shared_path.display().to_string(),
                name: None,
            })
            .await
            .unwrap();
        assert_eq!(core.shares().await.len(), 1);
        assert_eq!(core.shared_catalog_count().await, 1);

        let removed = core.unshare_file(&share.hash).await.unwrap().unwrap();

        assert_eq!(removed.hash, share.hash);
        assert!(core.shares().await.is_empty());
        assert_eq!(core.shared_catalog_count().await, 0);
    }

    #[tokio::test]
    async fn update_shared_file_queues_ed2k_republish() {
        let runtime_dir = unique_runtime_dir("emulebb-core-update-shared-republish");
        let transfer_root = runtime_dir.join("transfers");
        let shared_path = runtime_dir.join("shared-metadata.bin");
        fs::write(&shared_path, b"shared metadata update payload").unwrap();
        let core =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();

        let share = core
            .share_local_file(LocalShareCreate {
                path: shared_path.display().to_string(),
                name: None,
            })
            .await
            .unwrap();
        let queued_before = core.ed2k_publish_diagnostics().queued_count;

        let updated = core
            .update_shared_file(
                &share.hash,
                SharedFileUpdate {
                    priority: Some("high".to_string()),
                    comment: Some("synthetic note".to_string()),
                    rating: Some(4),
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated.priority, "high");
        assert_eq!(updated.comment, "synthetic note");
        assert_eq!(updated.rating, 4);
        assert_eq!(
            core.ed2k_publish_diagnostics().queued_count,
            queued_before.saturating_add(1)
        );
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
        assert!(core.transfer(&share.hash).await.is_none());
        assert!(core.transfers().await.is_empty());

        let restored = core
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
    async fn shared_files_stay_out_of_transfer_queue_until_link_is_added() {
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
        assert_eq!(restored.state, "completed");
        assert_eq!(restored.completed_bytes, payload.len() as u64);
        assert_eq!(restored.progress, 1.0);
        assert!(!restored.path.is_empty());
        assert_eq!(std::fs::read(&restored.path).unwrap(), payload);
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
            buddy_id: None,
            buddy_endpoint: None,
            source_udp_port: None,
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
    async fn direct_download_scheduler_releases_all_slots_on_worker_panic() {
        // A panicking download worker must not leak the connection-budget slots
        // held by the other in-flight workers: the error path drains and releases
        // every remaining slot before returning (FIX B1).
        let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size) =
            completed_ed2k_transfer_runtime("emulebb-core-direct-download-panic").await;
        let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
        let mut options = direct_download_options(
            Arc::clone(&transfer_runtime),
            secure_ident,
            file_hash_hex,
            file_name,
            file_size,
            vec![
                direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001),
                direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 11), 41002),
                direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 12), 41003),
            ],
        );
        // Spawn all sources at once so several slots are in flight when one panics.
        options.max_parallel_download_peers = 3;

        let result = run_ed2k_direct_downloads(
            options,
            move |_bind_ip,
                  _source,
                  _hello_identity,
                  _secure_ident,
                  _transfer_runtime,
                  _file_name,
                  _file_size,
                  _connect_timeout| async move {
                // Yield first so all three workers are spawned (and hold a slot)
                // before the panic unwinds, exercising the drain path.
                tokio::task::yield_now().await;
                panic!("simulated download worker panic");
            },
        )
        .await;

        assert!(result.is_err(), "a worker panic propagates as an error");

        // Every acquired connection-budget slot must have been released; if a
        // slot leaked, active_connections would be non-zero. Probe via a fresh
        // acquire and inspect the reported occupancy before the probe.
        let decision = transfer_runtime.try_acquire_source_connection_detailed();
        // active_connections counts AFTER this probe acquired one slot, so it must
        // be exactly 1 (the probe itself) with no leaked predecessors.
        assert_eq!(
            decision.active_connections, 1,
            "all worker slots were released after the panic (no budget leak)"
        );
        transfer_runtime.release_source_connection();
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
    async fn direct_download_scheduler_does_not_downgrade_failed_obfuscated_peer() {
        let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size) =
            completed_ed2k_transfer_runtime("emulebb-core-direct-download-no-plaintext-downgrade")
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

        assert_eq!(
            outcome
                .last_error
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("simulated obfuscated peer close")
        );
        assert_eq!(*attempts.lock().await, vec![(41001, true, true)]);
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
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: lower_hash.clone(),
                    file_priority: 1,
                    needed_parts: 8,
                    rare_parts: 0,
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: higher_hash.clone(),
                    file_priority: 9,
                    needed_parts: 1,
                    rare_parts: 0,
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
        }

        let (lower_sources, lower_deferred, lower_delay) = core
            .acquire_direct_download_source_leases(&lower_hash, std::slice::from_ref(&source))
            .await;
        let (higher_sources, higher_deferred, higher_delay) = core
            .acquire_direct_download_source_leases(&higher_hash, std::slice::from_ref(&source))
            .await;

        assert!(lower_sources.is_empty());
        assert_eq!(lower_deferred, 1);
        assert!(lower_delay.is_none());
        assert_eq!(higher_sources, vec![source.clone()]);
        assert_eq!(higher_deferred, 0);
        assert!(higher_delay.is_none());
        core.release_direct_download_source_leases(&[source_endpoint_key(&source)])
            .await;
    }

    #[tokio::test]
    async fn disconnect_releases_detached_reask_source_leases_and_re_engages() {
        // A detached source held on the UDP reask loop keeps its lease
        // (active_download_peer_endpoints + the registry leased_peers). When the
        // reask loop breaks on shutdown without emitting SourceReleased, the lease
        // would leak; disconnect_ed2k must reset it so the source is re-engageable
        // after a reconnect.
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        let file_hash = Ed2kHash::from_bytes([0x4a; 16]).to_string();
        let source = direct_test_source(
            Ed2kHash::from_bytes([0x4a; 16]),
            Ipv4Addr::new(192, 0, 2, 50),
            41020,
        );
        {
            let mut state = core.state.lock().await;
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: file_hash.clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 0,
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
        }

        // Engage (lease) the source, as a download attempt would before detaching
        // it onto the reask loop.
        let (engaged, deferred, retry_delay) = core
            .acquire_direct_download_source_leases(&file_hash, std::slice::from_ref(&source))
            .await;
        assert_eq!(engaged, vec![source.clone()]);
        assert_eq!(deferred, 0);
        assert!(retry_delay.is_none());
        {
            let state = core.state.lock().await;
            assert_eq!(state.active_download_peer_endpoints.len(), 1);
            assert_eq!(state.download_source_registry.leased_peer_count(), 1);
        }

        // The reask loop breaks on shutdown without emitting SourceReleased; the
        // lease would leak. disconnect_ed2k must release it.
        core.disconnect_ed2k().await;
        {
            let state = core.state.lock().await;
            assert!(
                state.active_download_peer_endpoints.is_empty(),
                "disconnect must clear active download peer endpoints"
            );
            assert_eq!(
                state.download_source_registry.leased_peer_count(),
                0,
                "disconnect must release detached source leases"
            );
        }

        // The lease is gone, but the endpoint retry cooldown still gates redial.
        let (re_engaged, re_deferred, re_retry_delay) = core
            .acquire_direct_download_source_leases(&file_hash, std::slice::from_ref(&source))
            .await;
        assert!(re_engaged.is_empty());
        assert_eq!(re_deferred, 1);
        assert!(re_retry_delay.is_some());
    }

    #[tokio::test]
    async fn run_attempt_stops_immediately_when_pre_cancelled() {
        // The requery loop checks the per-hash cancel token at the top of each
        // round (and the function checks it before any work). A pre-cancelled token
        // makes the attempt a no-op that returns Ok(None) so the queued-attempt
        // wrapper neither rewrites the transfer state nor re-queues a retry.
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        let transfer =
            a4af_test_transfer(&Ed2kHash::from_bytes([0x80; 16]).to_string(), "downloading");
        let cancel = CancellationToken::new();
        cancel.cancel();

        let result = core
            .run_ed2k_download_attempt(&transfer, &cancel)
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "a cancelled attempt must return Ok(None) so it neither restates nor retries"
        );
    }

    #[tokio::test]
    async fn delete_transfer_files_cancels_attempt_and_releases_hash_leases() {
        // Delete must promptly free everything the running attempt holds for the
        // hash: cancel its in-flight token, release the hash's leases + the
        // matching active endpoints, and clear the dedup + cancel slots so a
        // re-create can immediately re-download (it no longer early-returns on a
        // stale dedup slot or finds the peer deferred by a leaked lease).
        let runtime_dir = unique_runtime_dir("emulebb-core-delete-cancels-attempt");
        let transfer_root = runtime_dir.join("transfers");
        let core =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
        // Create paused so no background attempt is queued to race the simulated
        // running-attempt state we install below.
        let transfer = core
            .create_transfer(TransferCreate {
                link: Some(
                    "ed2k://|file|Cancel.Me.bin|4096|00112233445566778899aabbccddeeff|/"
                        .to_string(),
                ),
                links: None,
                category_id: None,
                category_name: None,
                paused: Some(true),
            })
            .await
            .unwrap();
        let hash = transfer.hash.clone();
        let source = direct_test_source(hash.parse().unwrap(), Ipv4Addr::new(192, 0, 2, 60), 41030);
        let endpoint = source_endpoint_key(&source);

        // Simulate a running attempt for this hash: a registered + leased source
        // (active endpoint), the dedup slot, and an installed cancel token.
        let cancel = CancellationToken::new();
        {
            let mut state = core.state.lock().await;
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: hash.clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 0,
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
            assert!(
                state
                    .download_source_registry
                    .lease_best_for_file(Instant::now(), Duration::ZERO, &source, &hash)
                    .is_some()
            );
            state.active_download_peer_endpoints.insert(endpoint);
            state.active_download_attempts.insert(hash.clone());
            state
                .download_cancels
                .insert(hash.clone(), (0, cancel.clone()));
        }

        let deleted = core.delete_transfer_files(&hash).await.unwrap().unwrap();
        assert_eq!(deleted.hash, hash);

        // The in-flight attempt is signalled to stop.
        assert!(
            cancel.is_cancelled(),
            "delete must cancel the in-flight attempt for the hash"
        );
        let state = core.state.lock().await;
        assert_eq!(
            state.download_source_registry.leased_peer_count(),
            0,
            "delete must release the hash's leases"
        );
        assert_eq!(
            state
                .download_source_registry
                .candidate_count_for_file(Instant::now(), &hash),
            0,
            "delete must forget the hash's source candidates"
        );
        assert!(
            !state.active_download_peer_endpoints.contains(&endpoint),
            "delete must drop the matching active download endpoint"
        );
        assert!(
            !state.active_download_attempts.contains(&hash),
            "delete must clear the dedup slot so a re-create can re-download"
        );
        assert!(
            !state.download_cancels.contains_key(&hash),
            "delete must clear the cancel slot"
        );
    }

    #[tokio::test]
    async fn pause_transfer_cancels_in_flight_attempt() {
        // Pause must stop the transfer now: the driver does not read control_state
        // mid-attempt, so pause cancels the in-flight attempt's token (the loop
        // then stops at its next cancel check) rather than only suppressing the
        // next retry.
        let runtime_dir = unique_runtime_dir("emulebb-core-pause-cancels-attempt");
        let transfer_root = runtime_dir.join("transfers");
        let core =
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
        // Create paused so no background attempt is queued to race our manually
        // installed token (the attempt's own token would otherwise overwrite it).
        let transfer = core
            .create_transfer(TransferCreate {
                link: Some(
                    "ed2k://|file|Pause.Me.bin|4096|00112233445566778899aabbccddeeff|/".to_string(),
                ),
                links: None,
                category_id: None,
                category_name: None,
                paused: Some(true),
            })
            .await
            .unwrap();
        let hash = transfer.hash.clone();

        // Simulate a running attempt's cancel token for this hash.
        let cancel = CancellationToken::new();
        core.state
            .lock()
            .await
            .download_cancels
            .insert(hash.clone(), (0, cancel.clone()));

        let paused = core.pause_transfer(&hash).await.unwrap().unwrap();
        assert_eq!(paused.state, "paused");
        assert!(
            cancel.is_cancelled(),
            "pause must cancel the in-flight attempt so it stops now, not at next retry"
        );
    }

    fn a4af_test_transfer(hash: &str, state_name: &str) -> Transfer {
        Transfer {
            hash: hash.to_string(),
            name: "file".to_string(),
            path: String::new(),
            delivered_path: None,
            size_bytes: 1,
            completed_bytes: 0,
            state: state_name.to_string(),
            progress: 0.0,
            sources: 0,
            sources_transferring: 0,
            download_speed_ki_bps: 0.0,
            upload_speed_ki_bps: 0.0,
            stopped: state_name == "paused" || state_name == "stopped",
            ed2k_link: String::new(),
            priority: "normal".to_string(),
            category_id: 0,
            category_name: String::new(),
            eta: None,
            added_at: None,
            completed_at: None,
            parts_total: 1,
            parts_obtained: 0,
            parts_progress_text: "0".to_string(),
            parts_available: 0,
            auto_priority: false,
            in_incoming: false,
        }
    }

    #[tokio::test]
    async fn a4af_multi_file_peer_is_reused_and_not_double_engaged() {
        // A4AF-lite leg 1: a peer registered for two of our files is engaged for
        // exactly one file at a time; the second file defers the same peer
        // (one active relationship per peer, like eMule) rather than opening a
        // redundant second engagement.
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        let file_a = Ed2kHash::from_bytes([0x71; 16]).to_string();
        let file_b = Ed2kHash::from_bytes([0x72; 16]).to_string();
        let source = direct_test_source(
            Ed2kHash::from_bytes([0x71; 16]),
            Ipv4Addr::new(192, 0, 2, 31),
            41010,
        );
        {
            let mut state = core.state.lock().await;
            // File A is the peer's best (higher priority), so it wins the single
            // per-peer relationship; file B is the lower-priority other file.
            for (hash, priority) in [(&file_a, 9u32), (&file_b, 3u32)] {
                state.download_source_registry.add_candidate(
                    Instant::now(),
                    DownloadSourceCandidate {
                        file_hash: hash.clone(),
                        file_priority: priority,
                        needed_parts: 4,
                        rare_parts: 1,
                        source: source.clone(),
                        last_seen: Instant::now(),
                    },
                );
            }
        }

        let (a_sources, a_deferred, a_delay) = core
            .acquire_direct_download_source_leases(&file_a, std::slice::from_ref(&source))
            .await;
        let (b_sources, b_deferred, b_delay) = core
            .acquire_direct_download_source_leases(&file_b, std::slice::from_ref(&source))
            .await;

        // Engaged once (file A, the peer's best), deferred (NOT double-engaged)
        // for file B: one active relationship per peer, like eMule.
        assert_eq!(a_sources, vec![source.clone()]);
        assert_eq!(a_deferred, 0);
        assert!(a_delay.is_none());
        assert!(b_sources.is_empty());
        assert_eq!(b_deferred, 1);
        assert!(b_delay.is_none());

        // The peer holds exactly one active engagement across both files (no
        // double-engage / one relationship per peer).
        assert_eq!(
            core.state.lock().await.active_download_peer_endpoints.len(),
            1
        );

        // After the peer is released, the same endpoint remains cooldown-deferred
        // until the MFC-style retry window expires instead of being redialed.
        core.release_direct_download_source_leases(&[source_endpoint_key(&source)])
            .await;
        let (a_again, a_again_deferred, a_again_delay) = core
            .acquire_direct_download_source_leases(&file_a, std::slice::from_ref(&source))
            .await;
        assert!(a_again.is_empty());
        assert_eq!(a_again_deferred, 1);
        assert!(a_again_delay.is_some());
    }

    #[tokio::test]
    async fn a4af_nnp_source_is_swapped_to_another_wanted_file() {
        // A4AF-lite leg 2: a source with No Needed Parts for the current file but
        // registered for another WANTED file is swapped to that file (its attempt
        // is queued) instead of being dropped (master SwapToAnotherFile).
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        let current = Ed2kHash::from_bytes([0x73; 16]).to_string();
        let other = Ed2kHash::from_bytes([0x74; 16]).to_string();
        let source = direct_test_source(
            Ed2kHash::from_bytes([0x73; 16]),
            Ipv4Addr::new(192, 0, 2, 32),
            41011,
        );
        {
            let mut state = core.state.lock().await;
            // The other file is a wanted (downloading) transfer.
            state
                .transfers
                .insert(other.clone(), a4af_test_transfer(&other, "downloading"));
            for hash in [&current, &other] {
                state.download_source_registry.add_candidate(
                    Instant::now(),
                    DownloadSourceCandidate {
                        file_hash: hash.clone(),
                        file_priority: 5,
                        needed_parts: 4,
                        rare_parts: 1,
                        source: source.clone(),
                        last_seen: Instant::now(),
                    },
                );
            }
        }

        let swapped = core
            .swap_no_needed_parts_sources(&current, std::slice::from_ref(&source))
            .await;
        assert_eq!(
            swapped, 1,
            "NNP source must be swapped to the other wanted file"
        );
    }

    #[tokio::test]
    async fn a4af_nnp_source_without_other_wanted_file_is_dropped() {
        // A4AF-lite leg 2 negative: a source with No Needed Parts that serves no
        // OTHER wanted file is not swapped (it stays dropped, as before).
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        let current = Ed2kHash::from_bytes([0x75; 16]).to_string();
        let source = direct_test_source(
            Ed2kHash::from_bytes([0x75; 16]),
            Ipv4Addr::new(192, 0, 2, 33),
            41012,
        );
        {
            let mut state = core.state.lock().await;
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: current.clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 1,
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
        }

        let swapped = core
            .swap_no_needed_parts_sources(&current, std::slice::from_ref(&source))
            .await;
        assert_eq!(
            swapped, 0,
            "NNP source with no other wanted file must not be swapped"
        );
    }

    #[tokio::test]
    async fn a4af_nnp_source_other_file_completed_is_not_swapped() {
        // A4AF-lite leg 2 guard: the swap target must still be a wanted transfer;
        // a completed/paused other file is not a valid swap target.
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        let current = Ed2kHash::from_bytes([0x76; 16]).to_string();
        let other = Ed2kHash::from_bytes([0x77; 16]).to_string();
        let source = direct_test_source(
            Ed2kHash::from_bytes([0x76; 16]),
            Ipv4Addr::new(192, 0, 2, 34),
            41013,
        );
        {
            let mut state = core.state.lock().await;
            state
                .transfers
                .insert(other.clone(), a4af_test_transfer(&other, "completed"));
            for hash in [&current, &other] {
                state.download_source_registry.add_candidate(
                    Instant::now(),
                    DownloadSourceCandidate {
                        file_hash: hash.clone(),
                        file_priority: 5,
                        needed_parts: 4,
                        rare_parts: 1,
                        source: source.clone(),
                        last_seen: Instant::now(),
                    },
                );
            }
        }

        let swapped = core
            .swap_no_needed_parts_sources(&current, std::slice::from_ref(&source))
            .await;
        assert_eq!(
            swapped, 0,
            "completed other file is not a valid swap target"
        );
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
    fn ed2k_server_source_refresh_is_initial_round_only() {
        assert!(should_refresh_ed2k_server_sources(0));
        assert!(!should_refresh_ed2k_server_sources(1));
        assert!(!should_refresh_ed2k_server_sources(2));
    }

    #[test]
    fn global_udp_source_search_skips_connected_server_only_when_background_is_available() {
        let connected_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 4661));

        assert_eq!(
            global_udp_source_search_excluded_endpoint(false, Some(connected_server)),
            None
        );
        assert_eq!(global_udp_source_search_excluded_endpoint(true, None), None);
        assert_eq!(
            global_udp_source_search_excluded_endpoint(true, Some(connected_server)),
            Some(connected_server)
        );
    }

    #[test]
    fn server_udp_source_supplement_runs_below_the_udp_source_cap() {
        // Oracle: GetMaxSourcePerFileUDP() > GetSourceCount() (default cap 100).
        assert!(should_query_server_udp_source_supplement(0, 100));
        assert!(should_query_server_udp_source_supplement(99, 100));
        assert!(!should_query_server_udp_source_supplement(100, 100));
        assert!(!should_query_server_udp_source_supplement(150, 100));
        // 0 = uncapped.
        assert!(should_query_server_udp_source_supplement(10_000, 0));
    }

    #[test]
    fn callback_route_uses_only_matching_connected_server() {
        let connected_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 4661));
        let other_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 4661));

        assert_eq!(
            ed2k_server_callback_route(Some(connected_server), Some(connected_server)),
            Ed2kServerCallbackRoute::BackgroundSession
        );
        assert_eq!(
            ed2k_server_callback_route(Some(other_server), Some(connected_server)),
            Ed2kServerCallbackRoute::Unavailable
        );
        assert_eq!(
            ed2k_server_callback_route(None, Some(connected_server)),
            Ed2kServerCallbackRoute::Unavailable
        );
        assert_eq!(
            ed2k_server_callback_route(Some(connected_server), None),
            Ed2kServerCallbackRoute::Unavailable
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
    fn kad_source_supplement_runs_below_the_udp_source_cap() {
        // Same GetMaxSourcePerFileUDP gate as the server UDP walk.
        assert!(should_query_kad_source_supplement(0, 100));
        assert!(should_query_kad_source_supplement(99, 100));
        assert!(!should_query_kad_source_supplement(100, 100));
        // 0 = uncapped.
        assert!(should_query_kad_source_supplement(10_000, 0));
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
            source_type: 1,
            buddy_id: None,
            buddy_ip: None,
            buddy_port: 0,
        })
        .expect("mapped source");

        assert_eq!(source.file_hash, file_hash);
        assert_eq!(source.ip, Ipv4Addr::new(192, 0, 2, 55));
        assert_eq!(source.tcp_port, 4662);
        assert_eq!(source.client_id, u32::from(Ipv4Addr::new(192, 0, 2, 55)));
        assert!(!source.low_id);
        assert!(source.obfuscated);
        assert_eq!(source.obfuscation_options, Some(0x03));
        assert_eq!(source.user_hash, Some(source_id.0));
        assert_eq!(source.source_server, None);
        assert_eq!(source.buddy_id, None);
        assert_eq!(source.buddy_endpoint, None);
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
    fn drop_self_sources_removes_own_endpoint_and_user_hash() {
        let file_hash = Ed2kHash::from_bytes([0x47; 16]);
        let own_ip = Ipv4Addr::new(203, 0, 113, 7);
        let own_port = 4662u16;
        let own_user_hash = [0xAB; 16];
        let identity = OwnSourceIdentity {
            user_hash: own_user_hash,
            endpoints: vec![(Ipv4Addr::new(192, 168, 50, 2), 4662), (own_ip, own_port)],
        };

        // (1) self by advertised public endpoint, (2) self by local bind endpoint,
        // (3) self by user-hash on a different endpoint, (4) a real foreign source.
        let mut self_by_endpoint = direct_test_source(file_hash, own_ip, own_port);
        self_by_endpoint.user_hash = None;
        let self_by_bind = direct_test_source(file_hash, Ipv4Addr::new(192, 168, 50, 2), 4662);
        let mut self_by_hash = direct_test_source(file_hash, Ipv4Addr::new(198, 51, 100, 9), 5000);
        self_by_hash.user_hash = Some(own_user_hash);
        let foreign = direct_test_source(file_hash, Ipv4Addr::new(198, 51, 100, 22), 4662);

        let mut sources = vec![
            self_by_endpoint,
            self_by_bind,
            self_by_hash,
            foreign.clone(),
        ];
        let dropped = drop_self_sources(&mut sources, &identity);

        assert_eq!(dropped, 3);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].ip, foreign.ip);
        assert_eq!(sources[0].tcp_port, foreign.tcp_port);
    }

    #[test]
    fn drop_self_sources_keeps_foreign_when_only_port_collides() {
        let file_hash = Ed2kHash::from_bytes([0x48; 16]);
        let identity = OwnSourceIdentity {
            user_hash: [0x01; 16],
            endpoints: vec![(Ipv4Addr::new(203, 0, 113, 7), 4662)],
        };
        // Same port, different IP, different user-hash: a genuine peer, kept.
        let foreign = direct_test_source(file_hash, Ipv4Addr::new(198, 51, 100, 30), 4662);
        let mut sources = vec![foreign];
        assert_eq!(drop_self_sources(&mut sources, &identity), 0);
        assert_eq!(sources.len(), 1);
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

    #[test]
    fn parse_ban_ip_accepts_dialable_ipv4_only() {
        assert_eq!(
            parse_ban_ip("203.0.113.7"),
            Some(Ipv4Addr::new(203, 0, 113, 7))
        );
        // Empty / unspecified / LowID-style non-IP fall back to no IP key.
        assert_eq!(parse_ban_ip(""), None);
        assert_eq!(parse_ban_ip("0.0.0.0"), None);
        assert_eq!(parse_ban_ip("low-id-12345"), None);
    }

    #[test]
    fn parse_ban_hash_decodes_16_byte_hex() {
        assert_eq!(
            parse_ban_hash(Some("000102030405060708090a0b0c0d0e0f")),
            Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
        assert_eq!(parse_ban_hash(None), None);
        assert_eq!(parse_ban_hash(Some("not-hex")), None);
        // Wrong length is rejected.
        assert_eq!(parse_ban_hash(Some("0011")), None);
    }
}
