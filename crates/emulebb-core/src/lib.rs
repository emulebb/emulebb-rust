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

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
#[cfg(test)]
use emulebb_ed2k::config::Ed2kUploadQueuePolicyConfig;
#[cfg(test)]
use emulebb_ed2k::ed2k_server::Ed2kSearchFile;
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
        SharedPublishRank, SharedPublishRankInput, compare_shared_publish_rank, shared_publish_rank,
    },
};
#[cfg(test)]
use emulebb_ed2k::{MappingExposure, TransportProtocol};
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
    PublishRes, Tag, packet::ContactEntry,
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

mod app_api;
mod callback_tracker;
mod categories;
mod category_api;
mod category_runtime;
mod core_state;
mod delivery;
mod diag_kad_event;
mod diag_sched;
mod direct_download_runtime;
mod disk_guard;
mod download_source_registry;
mod ed2k_buddy_reask;
mod ed2k_dead_source_list;
mod ed2k_direct_download_types;
mod ed2k_download_retry;
mod ed2k_net_drivers;
mod ed2k_publish_diagnostics;
mod ed2k_source_batch;
mod ed2k_sources;
mod friend_api;
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
mod network_api;
mod network_binding;
mod physical_disk;
mod preferences;
mod profile_state;
mod search_api;
mod search_query;
mod search_queue;
mod search_queue_runtime;
mod search_state;
mod server_api;
mod server_list;
mod shared_dir_monitor;
mod shared_directories;
mod shared_file_api;
mod source_publish;
mod transfer_control_api;
mod transfer_create_api;
mod transfer_state_api;
mod upload_api;
mod upload_view;
mod views;
pub mod vpn_guard;
use categories::default_categories;
pub(crate) use core_state::CoreState;
use direct_download_runtime::{parse_server_endpoint, run_ed2k_direct_downloads};
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
    ed2k_server_callback_permitted, ed2k_server_callback_route, found_source_from_hint,
    global_udp_source_batch_server_attempts, global_udp_source_search_excluded_endpoint,
    hash_only_ed2k_search_query, kad_source_result_to_ed2k_found_source, keyword_target,
    manifest_has_ed2k_transfer_progress, merge_download_sources, new_direct_ed2k_source_count,
    select_ed2k_keyword_metadata, should_adopt_hash_only_metadata_name,
    should_query_kad_source_supplement, should_query_server_udp_source_supplement,
    should_refresh_ed2k_server_sources, should_skip_no_progress_source_requery,
    significant_keyword_words_unique, sort_download_sources, source_endpoint_key, source_key,
};
#[cfg(test)]
use ed2k_sources::{
    ed2k_keyword_server_attempts, exact_ed2k_hash_query_token, kad_keyword_lowercase,
    select_kad_keyword_metadata, significant_keyword_words,
};
use kad_buddy::{
    BuddyNeedInput, FindBuddyReqRefusal, INCOMING_BUDDY_ATTACH_TIMEOUT_SECS, IncomingBuddy,
    KadBuddyState, OutgoingBuddy, buddy_search_target, find_buddy_res_matches,
};
use kad_callback_initiator::{KAD_CALLBACK_INITIATOR_COOLDOWN, should_send_kad_callback};
#[cfg(test)]
use kad_hello::{
    build_kad_hello_request_tags, build_kad_hello_response_tags, firewalled_response_ip_for_sender,
};
use kad_hello::{
    build_kad_hello_response, kad_publish_within_tolerance, kad_req_masked_count,
    should_request_hello_res_ack, spawn_kad_firewalled_response,
    spawn_modern_kad_firewalled_response,
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
use network_status_defaults::{ed2k_starting_status, ed2k_stopped_status, kad_starting_status};
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

mod network_status_defaults;
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
    /// Files whose Kad NOTES clock must be reset on the next publish tick because
    /// their comment/rating was just edited (oracle `SetLastPublishTimeKadNotes(0)`).
    /// Drained by the loop-local `KadPublishSchedule`; `std::sync::Mutex` since it
    /// is only ever held for a brief insert/drain, never across an `.await`.
    kad_notes_dirty: Arc<std::sync::Mutex<HashSet<String>>>,
    ed2k_publish_diagnostics: ed2k_publish_diagnostics::SharedEd2kPublishDiagnostics,
    kad_publish_diagnostics: kad_publish_diagnostics::SharedKadPublishDiagnostics,
    /// Connection-aware queue for network searches (`search_queue.rs` state
    /// machine + `search_queue_runtime.rs` drain task). `std::sync::Mutex` by
    /// design: guards are held for short sync sections only — never across an
    /// `.await` and never while acquiring the `state` lock — so the create
    /// path (state → queue) cannot deadlock against the drain path.
    search_queue: Arc<parking_lot::Mutex<SearchQueue>>,
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
            kad_notes_dirty: Arc::new(std::sync::Mutex::new(HashSet::new())),
            ed2k_publish_diagnostics: ed2k_publish_diagnostics::new_shared(),
            kad_publish_diagnostics: kad_publish_diagnostics::new_shared(),
            search_queue: Arc::new(parking_lot::Mutex::new(SearchQueue::new())),
            state: Arc::new(Mutex::new(core_state)),
        })
    }

    pub fn new_in_memory(version: impl Into<String>, index: FileIndex) -> Result<Self> {
        Self::new(version, index, unique_runtime_dir("emulebb-core-transfers"))
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
            let dead_server_endpoints = self
                .ed2k_dead_server_endpoints(config.dead_server_retries)
                .await;
            match search_keyword_udp_servers(Ed2kUdpKeywordSearchOptions {
                bind_ip: network.bind_ip,
                config: &config,
                excluded_endpoint: connected_server_endpoint,
                dead_server_endpoints: &dead_server_endpoints,
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

    #[expect(
        clippy::cognitive_complexity,
        reason = "linear protocol orchestration flow"
    )]
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
            // Oracle CanDoCallback (emule.cpp:2952-2969): a server
            // OP_CALLBACKREQUEST is only legal when WE are HighID on the ed2k
            // server. A LowID node must NOT ask its own server to relay a
            // callback to a same-server LowID source ("breaks the protocol and
            // will get us banned"). Resolve our firewalled posture once per
            // round; the per-source permit check (below) combines it with the
            // same-server route.
            let self_tcp_firewalled = self.ed2k_self_tcp_firewalled().await;
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
                // TryToConnect reaches CCS_SERVERCALLBACK only for a same-server
                // source AND only after CanDoCallback passed (HighID). Suppress
                // both the wrong-server route and the LowID-self case here.
                if !ed2k_server_callback_permitted(
                    self_tcp_firewalled,
                    source.source_server,
                    connected_server_endpoint,
                ) {
                    tracing::debug!(
                        "ED2K server callback unavailable file_hash={} client_id={} self_firewalled={} source_server={} connected_server={}",
                        transfer.hash,
                        source.client_id,
                        self_tcp_firewalled,
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
                // (its transfer is re-driven so leg-1 selection reuses the peer).
                // Every NNP source is then HELD on THIS file for the doubled
                // 58-minute reask cycle (oracle DS_NONEEDEDPARTS: the source
                // stays in the srclist, DownloadClient.cpp:848-852, and is
                // re-asked after FILEREASKTIME*2, DownloadClient.cpp:2425-2431)
                // instead of being dropped — the swap moves the peer's activity,
                // the hold keeps the NNP relation to this file re-askable.
                if !outcome.no_needed_parts_sources.is_empty() {
                    self.swap_no_needed_parts_sources(
                        &transfer.hash,
                        &outcome.no_needed_parts_sources,
                    )
                    .await;
                    self.hold_no_needed_parts_sources(
                        &transfer.hash,
                        &outcome.no_needed_parts_sources,
                    )
                    .await;
                }
                // FNF dead-listing (oracle ListenSocket.cpp:645-661 + UDPReaskFNF):
                // a source that answered OP_FILEREQANSNOFIL (or an AICH-root
                // mismatch treated like FNF) is blocked from re-admission for 45
                // minutes and dropped from the registry. Rust maps the oracle
                // swap-or-RemoveSource to a plain drop (A4AF intentionally parked).
                if !outcome.file_not_found_sources.is_empty() {
                    self.dead_list_file_not_found_sources(
                        &transfer.hash,
                        &outcome.file_not_found_sources,
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
            // Dead-source gate (oracle IsDeadSource admission checks,
            // DownloadQueue.cpp:1420/:1530): an FNF-dead (source, file) pair
            // must not be re-attempted while its 45-minute block runs. Not a
            // deferral — the transfer must not wait on a dead source — and not
            // a drop event (its removal was already surfaced when dead-listed).
            if state
                .ed2k_dead_sources
                .is_dead_source(now, file_hash, source)
            {
                continue;
            }
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
            let nnp_source_count = state.download_source_registry.nnp_source_count(now);
            let a4af_file_count = state.download_source_registry.a4af_file_count();
            let transferring_source_count = state.active_download_peer_endpoints.len();
            crate::diag_sched::source_count(
                source_count,
                valid_source_count,
                nnp_source_count,
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

    /// Dead-list every FNF-answering source for `file_hash` for the oracle
    /// 45-minute block and drop its registry candidate. Mirrors the oracle
    /// OP_FILEREQANSNOFIL handler (`ListenSocket.cpp:645-661`:
    /// `m_DeadSourceList.AddDeadSource` then swap-or-`RemoveSource`) and the
    /// identical AICH-mismatch path (`DownloadClient.cpp:2971-3004`); rust's
    /// swap-or-remove is a plain drop because A4AF is intentionally parked.
    async fn dead_list_file_not_found_sources(&self, file_hash: &str, sources: &[Ed2kFoundSource]) {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        for source in sources {
            if state
                .ed2k_dead_sources
                .add_dead_source(now, file_hash, source)
            {
                crate::diag_sched::source_dead_listed(file_hash, source, "fnf");
            }
            state
                .download_source_registry
                .remove_candidate(source, file_hash);
        }
    }

    /// Dead-list a source that UDP-answered `OP_FILENOTFOUND` on the reask loop
    /// (oracle `CUpDownClient::UDPReaskFNF`, `DownloadClient.cpp:1774-1795`:
    /// `AddDeadSource` + swap-or-`RemoveSource`), unifying the UDP FNF drop with
    /// the TCP FNF dead list. The reask loop only knows the peer's UDP endpoint,
    /// so the full oracle identity is recovered from the registry by (ip, file);
    /// an already-forgotten or ambiguous source is left un-listed (it is already
    /// out of the reask loop, and without identity there is nothing to gate).
    async fn dead_list_udp_fnf_source(&self, file_hash: &str, peer_ip: Ipv4Addr) {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let Some(source) = state
            .download_source_registry
            .sole_candidate_source_by_ip(peer_ip, file_hash)
        else {
            return;
        };
        if state
            .ed2k_dead_sources
            .add_dead_source(now, file_hash, &source)
        {
            crate::diag_sched::source_dead_listed(file_hash, &source, "udp_fnf");
        }
        state
            .download_source_registry
            .remove_candidate(&source, file_hash);
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
            // Admission gate (oracle DownloadQueue.cpp:1420/:1530 CheckAndAdd*
            // paths): a dead-listed (source, file) pair is not re-admitted to
            // the source registry while its 45-minute block runs.
            if state
                .ed2k_dead_sources
                .is_dead_source(now, &transfer.hash, source)
            {
                continue;
            }
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
    /// one (no swap target) fall through to the NNP hold
    /// ([`Self::hold_no_needed_parts_sources`]) instead of a drop. Returns the
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

    /// Hold every No-Needed-Parts source for the doubled reask cycle instead of
    /// dropping it (RUST-PAR-017 DL-3). Oracle: an NNP source goes to
    /// `DS_NONEEDEDPARTS` but STAYS in the file's source list with
    /// `SetLastAskedTime` stamped (DownloadClient.cpp:848-852) and is re-asked
    /// after `FILEREASKTIME * 2` = 58 minutes because it may have acquired
    /// needed parts since (DownloadClient.cpp:2425-2431 + PartFile.cpp:3064-3068
    /// — which also resets to `DS_ONQUEUE` at reask time, mirrored by the
    /// expired-hold prune in [`DownloadSourceRegistry::lease_best_for_file`]).
    /// Retention mirrors the oracle NNP purge (PartFile.cpp:3056-3062): once the
    /// file already holds `maxSources * 4/5` live sources, at most one NNP
    /// source per 40-second window is dropped instead of held. A source that
    /// also sits on the UDP reask loop (a Kad buddy-registered source keeps its
    /// loop entry across a TCP session) is flagged there too, so the loop's own
    /// cadence doubles. Returns the number of sources held.
    async fn hold_no_needed_parts_sources(
        &self,
        file_hash: &str,
        sources: &[Ed2kFoundSource],
    ) -> usize {
        let reask_handle = self.ed2k_reask_handle.lock().unwrap().clone();
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let mut held = 0usize;
        for source in sources {
            let live_count = state
                .download_source_registry
                .candidate_count_for_file(now, file_hash);
            if self.ed2k_transfers.should_purge_nnp_source(live_count)
                && state.download_source_registry.try_nnp_purge(now, file_hash)
            {
                // Oracle NNP retention purge (PartFile.cpp:3056-3062): under
                // source-cap pressure the NNP source is removed to make room
                // for a potentially better one (RemoveSource; emits
                // source_dropped like every genuine registry removal).
                state
                    .download_source_registry
                    .remove_candidate(source, file_hash);
                continue;
            }
            if state
                .download_source_registry
                .mark_no_needed_parts(now, source, file_hash)
            {
                held += 1;
                crate::diag_sched::source_nnp_held(file_hash, source);
                // Double the UDP reask cadence too when the source has a loop
                // entry (keyed by its client-UDP endpoint; unknown = no-op).
                if let (Some(handle), Some(udp_port)) = (&reask_handle, source.source_udp_port) {
                    handle.mark_no_needed_parts((source.ip, udp_port));
                }
            }
        }
        held
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
                retry_downloading = should_retry_download_attempt_state(next_state);
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
        // re-drives) visible. A queued active download still needs the periodic
        // Process-style re-drive: sources, server availability, and peer upload
        // state can change after an attempt that made no immediate progress.
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
        if !should_retry_download_attempt_state(&transfer.state) {
            crate::diag_sched::download_retry_outcome(&hash, &transfer.state, false);
            return;
        }
        crate::diag_sched::download_retry_outcome(&hash, &transfer.state, true);
        core.queue_ed2k_download_attempt(transfer);
    }

    #[expect(
        clippy::cognitive_complexity,
        reason = "linear protocol orchestration flow"
    )]
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

    #[expect(
        clippy::cognitive_complexity,
        reason = "linear protocol orchestration flow"
    )]
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
                let dead_server_endpoints = self
                    .ed2k_dead_server_endpoints(config.dead_server_retries)
                    .await;
                match search_source_udp_server_batches(Ed2kUdpSourceBatchSearchOptions {
                    bind_ip: network.bind_ip,
                    config: &config,
                    preferred_endpoint,
                    excluded_endpoint: global_udp_source_search_excluded_endpoint(
                        has_background_search,
                        preferred_endpoint,
                    ),
                    dead_server_endpoints: &dead_server_endpoints,
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
            && should_query_kad_source_supplement(sources.len(), config.max_source_per_file_udp())
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
        if !sources
            .iter()
            .any(Ed2kFoundSource::is_direct_callback_source)
        {
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
/// Max contacts returned in a `KADEMLIA2_BOOTSTRAP_RES` (oracle
/// `Process_KADEMLIA2_BOOTSTRAP_REQ` -> `GetBootstrapContacts(contacts, 20)`).
const KAD_BOOTSTRAP_RESPONSE_CONTACTS: usize = 20;

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
    /// Shared queue of files whose NOTES clock must be reset (comment/rating
    /// edited); drained each tick into the loop-local schedule.
    kad_notes_dirty: Arc<std::sync::Mutex<HashSet<String>>>,
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

        // G1: republish edited notes promptly. A comment/rating PATCH enqueues
        // the file hash here; reset its in-memory NOTES clock so `notes_due`
        // becomes true this tick (analog of `SetLastPublishTimeKadNotes(0)`,
        // KnownFile.cpp:1340,1360). The persisted notes row is cleared at edit
        // time, so a restart cannot restore the stale clock either.
        drain_kad_notes_dirty(&runtime.kad_notes_dirty, &mut schedule);

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

/// Whether a shared-file PATCH changed the Kad notes-relevant fields
/// (comment/rating) versus the current values. A priority-only PATCH passes
/// `comment_rating = None` and is never a notes change — the oracle resets the
/// notes clock only from `SetFileComment`/`SetFileRating` (KnownFile.cpp:1337-
/// 1355,1357-1375), each gated on the value actually differing.
fn shared_file_notes_changed(
    current_comment: &str,
    current_rating: u8,
    comment_rating: Option<(&str, u8)>,
) -> bool {
    comment_rating
        .is_some_and(|(comment, rating)| comment != current_comment || rating != current_rating)
}

/// Whether a shared-file mutation changed a field that alters the eD2k
/// OP_OFFERFILES set or per-file offer content, and therefore warrants re-running
/// the rate-limited shared-catalog offer session. Only the SET of offered files
/// (a share/unshare) or a file's completion state is offer content; a file's
/// name/size/hash are fixed and cannot be edited. A metadata PATCH touches only
/// priority and comment/rating, none of which are offer content: priority merely
/// reorders a future full offer (oracle `CKnownFile::SetUpPriority` emits no
/// re-offer, KnownFile.cpp:1395-1402) and comment/rating are Kad-notes content
/// with their own trigger (Publish-G1), so such a PATCH passes both flags `false`
/// and must not queue a redundant no-op offer session (Publish-G3).
fn shared_file_change_requires_ed2k_reoffer(
    share_status_changed: bool,
    completion_changed: bool,
) -> bool {
    share_status_changed || completion_changed
}

/// Drain the pending NOTES-reset queue into the loop-local schedule, resetting
/// each file's notes clock so an edited comment/rating republishes this tick
/// (oracle `SetLastPublishTimeKadNotes(0)`).
fn drain_kad_notes_dirty(
    kad_notes_dirty: &Arc<std::sync::Mutex<HashSet<String>>>,
    schedule: &mut kad_publish_schedule::KadPublishSchedule,
) {
    let dirty: Vec<String> = match kad_notes_dirty.lock() {
        Ok(mut guard) => guard.drain().collect(),
        Err(poisoned) => poisoned.into_inner().drain().collect(),
    };
    for file_hash in dirty {
        schedule.reset_notes(&file_hash);
    }
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

/// Roll back a Kad publish clock that was advanced at admission when the store
/// search could not be CREATED (a `Busy` outcome: no search permit acquired, so
/// no STORE packet was ever sent). Mirrors the oracle's immediate-retry reset for
/// the `CSearchManager::PrepareLookup(...) == NULL` case — source
/// `SetLastPublishTimeKadSrc(0, 0)` (SharedFileList.cpp:3389-3390) and notes
/// `SetLastPublishTimeKadNotes(0)` (:3436-3437); the keyword kind is reset the
/// same way so a permit-starved keyword store retries next tick rather than
/// waiting the 24h interval. The persisted admission row is cleared too so a
/// restart cannot re-hydrate the advanced clock. `TimedOut`/`Failed` are NOT
/// rolled back: the oracle only resets when the lookup could not be created, and
/// a search that WAS created and sent keeps its advanced clock (KnownFile.cpp:1839
/// / SharedFileList.cpp:3342), which also avoids retrying timeout-heavy targets
/// every tick.
fn rollback_kad_publish_admission_on_busy(
    metadata_store: &MetadataStore,
    schedule: &mut kad_publish_schedule::KadPublishSchedule,
    kind: KadSharedPublishKind,
    file_hashes: &[String],
    keyword: Option<&str>,
) {
    let persist_kind = match kind {
        KadSharedPublishKind::Keyword => MetadataKadOutboundPublishKind::Keyword,
        KadSharedPublishKind::Source => MetadataKadOutboundPublishKind::Source,
        KadSharedPublishKind::Notes => MetadataKadOutboundPublishKind::Notes,
    };
    for file_hash in file_hashes {
        match kind {
            KadSharedPublishKind::Keyword => {
                if let Some(keyword) = keyword {
                    schedule.reset_keyword(file_hash, keyword);
                }
            }
            KadSharedPublishKind::Source => schedule.reset_source(file_hash),
            KadSharedPublishKind::Notes => schedule.reset_notes(file_hash),
        }
        // Clear the persisted admission row so a restart before the retry cannot
        // re-hydrate the advanced clock. For keyword this drops the file's whole
        // keyword row set (the store lacks a keyword-scoped delete); at worst a
        // sibling keyword republishes early after a restart, which stays budgeted.
        if let Err(error) = metadata_store.delete_kad_outbound_publish(file_hash, persist_kind) {
            tracing::warn!(
                file_hash = %file_hash,
                kind = kind.label(),
                "failed to clear Kad publish row after busy rollback: {error:#}"
            );
        }
    }
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
#[expect(
    clippy::cognitive_complexity,
    reason = "linear protocol orchestration flow"
)]
async fn publish_kad_due_shared_files(
    runtime: &KadPublishLoopRuntime,
    schedule: &mut kad_publish_schedule::KadPublishSchedule,
    publish_tasks: &mut JoinSet<KadSharedPublishOutcome>,
    active_counts: &mut KadSharedPublishActiveCounts,
) -> Result<usize> {
    let in_flight_budget = kad_shared_file_publish_in_flight_budget(runtime);
    let available_search_permits = runtime.dht.available_search_permits();
    // Cheap per-tick prune input: read ONLY the source-publishable file hashes
    // (one small allocation each), not the full ranked clone. The schedule is
    // pruned on EVERY tick — including a gate-blocked / DHT-busy / budget-full one
    // — so a file unshared while the tick cannot publish is still forgotten. The
    // expensive ranked candidate set is built later (after the cheap gate / busy /
    // in-flight-budget short-circuits), only on a tick that will actually publish.
    let publishable_hashes = kad_source_publishable_hashes(&runtime.transfer_runtime).await;
    let item_count = publishable_hashes.len();
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
        diagnostics.item_count = item_count;
    });
    // Keep the per-file schedule from growing without bound: forget files that
    // are no longer publishable (removed / no longer complete).
    schedule.retain_only(publishable_hashes.iter().map(String::as_str));
    if item_count == 0 {
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
            diagnostics.item_count = item_count;
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
            .map(
                |(buddy_ip, buddy_kad_port)| SourcePublishReachability::BuddyRelay {
                    buddy_ip,
                    buddy_kad_port,
                },
            )
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
            diagnostics.item_count = item_count;
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
        return Ok(item_count);
    }
    if publish_tasks.len() >= in_flight_budget {
        kad_publish_diagnostics::record(&runtime.diagnostics, |diagnostics| {
            diagnostics.phase = "publishing".to_string();
            diagnostics.running = true;
            diagnostics.bootstrapped = true;
            diagnostics.gate_allowed = true;
            diagnostics.gate_block_reason.clear();
            diagnostics.item_count = item_count;
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
        return Ok(item_count);
    }
    // Expensive ranked candidate build: reached only once the tick is committed
    // to publishing (past the gate / DHT-busy / in-flight-budget short-circuits),
    // so a gate-blocked, DHT-busy or in-flight-full tick never pays for the
    // clone+rank+sort — only the cheap hash read above ran on those ticks.
    let KadPublishCandidateSets {
        source_scan: shared_files,
        source_item_count,
        source_cursor_start,
        best_notes_hash,
        keyword_files,
        keyword_index,
    } = kad_publishable_shared_files(&runtime.transfer_runtime, schedule).await?;
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
    // `item_count` is the full ranked SOURCE population; `shared_files` is only the
    // cursor scan window drawn from it (ranked order, starting at `start`), so the
    // loop walks the window directly while the cursor advances over the full count.
    // The single best-ranked notes-due file (oracle notes budget 1,
    // SharedFileList.cpp:3412-3435) was picked over the FULL source set during the
    // candidate build so it stays global despite the windowed scan.
    let item_count = source_item_count;
    let start = source_cursor_start;
    let mut inspected = 0usize;
    let mut attempted_files = 0usize;

    for (offset, entry) in shared_files.iter().enumerate() {
        let now = Instant::now();
        let keyword_terms = significant_keyword_words_unique(&entry.canonical_name);
        schedule.sync_keyword_terms(&entry.file_hash, &keyword_terms);
        // Only completed files trigger keyword publishes (oracle `!IsPartFile()`
        // gate); an in-progress partfile in the source scan never emits keywords.
        let due_keyword = if keyword_index.contains_key(&entry.file_hash) {
            keyword_terms
                .iter()
                .find(|keyword| {
                    schedule.keyword_due(&entry.file_hash, keyword, now)
                        && !attempted_keywords_this_cycle.contains(keyword.as_str())
                })
                .cloned()
        } else {
            None
        };
        let keyword_due = due_keyword.is_some();
        let source_due = source_publish_reachability.is_some()
            && schedule.source_due(&entry.file_hash, now, source_publish_buddy_ip);
        let notes_due =
            kad_publish_schedule::file_has_publishable_note(&entry.comment, entry.rating)
                && schedule.notes_due(&entry.file_hash, now);
        // Only the single best-ranked notes-due file publishes this tick (oracle
        // notes budget 1, ranked on the notes clock); `notes_due` still counts
        // every due file for diagnostics parity.
        let notes_selected =
            notes_due && best_notes_hash.as_deref() == Some(entry.file_hash.as_str());
        keyword_due_count += usize::from(keyword_due);
        source_due_count += usize::from(source_due);
        notes_due_count += usize::from(notes_due);
        inspected = offset + 1;
        if !keyword_due && !source_due && !notes_selected {
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
                // The keyword batch is drawn from the completed-only keyword set,
                // starting at the triggering file's position within it and
                // wrapping (matching the >150-file cap rotation).
                let keyword_start = keyword_index.get(&entry.file_hash).copied().unwrap_or(0);
                let keyword_entries = kad_keyword_publish_entries_for_keyword(
                    &keyword_files,
                    &keyword,
                    KAD_KEYWORD_PUBLISH_FILE_LIMIT,
                    keyword_start,
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
        // and source so an un-annotated file never emits a notes publish, and
        // restricted to the single best-ranked notes candidate this tick.
        if notes_selected {
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

#[expect(
    clippy::too_many_arguments,
    reason = "flat protocol or runtime boundary"
)]
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
                // A `Busy` outcome means the store search could not be created (no
                // permit acquired, no packet sent) — the oracle `PrepareLookup ==
                // NULL` case. Roll the clock advanced at admission back to due so
                // the file retries next tick instead of waiting the full interval.
                rollback_kad_publish_admission_on_busy(
                    &runtime.metadata_store,
                    schedule,
                    outcome.kind,
                    &outcome.file_hashes,
                    outcome.keyword.as_deref(),
                );
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

/// Candidate file sets for one Kad publish cycle, split by lane to match the
/// oracle. The SOURCE and KEYWORD lanes advertise different file populations:
/// the source lane advertises any servable file (including in-progress
/// partfiles), the keyword lane only completed files.
struct KadPublishCandidateSets {
    /// SOURCE-lane scan list: our own files (not compatibility hints) that are
    /// servable right now — a fully verified file OR an in-progress partfile
    /// holding ≥1 complete ED2K part. Ordered by the SOURCE last-publish clock
    /// (the scan is driven by the source lane). Mirrors the oracle SOURCE loop
    /// iterating all of `m_Files_map` with no `IsPartFile()` filter
    /// (SharedFileList.cpp:3371-3388); `PublishSrc()` is inherited unchanged by
    /// `CPartFile` (KnownFile.cpp:1818).
    ///
    /// This holds ONLY the cursor scan window (≤ `KAD_SHARED_FILE_PUBLISH_SCAN_BUDGET`
    /// entries, in ranked order starting at `source_cursor_start`) — the source
    /// lane is ranked over borrowed catalog entries and only the window the tick
    /// inspects is cloned. `source_item_count` carries the full ranked population.
    source_scan: Vec<MetadataTransferPublishEntry>,
    /// Full count of SOURCE-eligible files (the ranked population the window is
    /// drawn from), used for the cursor rotation math and diagnostics.
    source_item_count: usize,
    /// Rotating cursor position the `source_scan` window starts at, so the loop
    /// advances the schedule cursor with the same `start` the window was cut with.
    source_cursor_start: usize,
    /// Single best-ranked notes-due file this tick (ranked on the NOTES clock over
    /// the FULL source-eligible set, in the source-sorted order), or `None` when no
    /// annotated file is notes-due. Computed here so the notes lane still selects
    /// the global best even though `source_scan` is only the window.
    best_notes_hash: Option<String>,
    /// KEYWORD-lane candidate list: completed files only, mirroring the oracle
    /// keyword loop's `!IsPartFile()` gate (SharedFileList.cpp:3313) — "only
    /// publish complete files as someone else should have the full file."
    ///
    /// This is intentionally narrower than `MetadataTransferPublishEntry`: keyword
    /// STORE packets only need name, size, file hash and AICH root. Keeping the full
    /// transfer-publish entry here clones upload counters/comments/priority for
    /// every complete file on every Kad publish tick.
    keyword_files: Vec<KadKeywordPublishCandidate>,
    /// Position of each keyword-eligible (completed) file within `keyword_files`,
    /// so a scanned file can be tested for keyword eligibility and its keyword
    /// batch can start at the triggering file and wrap.
    keyword_index: HashMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KadKeywordPublishCandidate {
    file_hash: String,
    file_hash_bytes: Ed2kHash,
    canonical_name: String,
    keyword_terms: Vec<String>,
    file_size: u64,
    aich_root: Option<String>,
}

impl KadKeywordPublishCandidate {
    fn new(
        file_hash: String,
        canonical_name: String,
        file_size: u64,
        aich_root: Option<String>,
    ) -> Result<Self> {
        let file_hash_bytes = file_hash.parse()?;
        let keyword_terms = significant_keyword_words_unique(&canonical_name);
        Ok(Self {
            file_hash,
            file_hash_bytes,
            canonical_name,
            keyword_terms,
            file_size,
            aich_root,
        })
    }
}

fn kad_keyword_publish_candidate_from_shared_entry(
    entry: &Ed2kSharedEntry,
) -> Result<KadKeywordPublishCandidate> {
    KadKeywordPublishCandidate::new(
        entry.file_hash.clone(),
        entry.canonical_name.clone(),
        entry.file_size,
        entry.aich_root.clone(),
    )
}

/// Whether a shared-catalog entry may be published as a Kad SOURCE: one of our
/// own files (not a compatibility hint) that is servable right now. A fully
/// verified file or an in-progress partfile with ≥1 complete ED2K part
/// qualifies; a partfile with no complete part yet has nothing to serve and is
/// excluded. Mirrors the oracle SOURCE loop admitting partfiles (no
/// `IsPartFile()` filter, SharedFileList.cpp:3371-3388).
fn kad_source_publish_eligible(entry: &Ed2kSharedEntry) -> bool {
    !entry.compatibility_hint && entry.is_servable()
}

/// Whether a shared-catalog entry may be published under a Kad KEYWORD: a
/// completed file only (oracle `!IsPartFile()`, SharedFileList.cpp:3313), never
/// an in-progress partfile.
fn kad_keyword_publish_eligible(entry: &Ed2kSharedEntry) -> bool {
    !entry.compatibility_hint && entry.verified_complete
}

/// Cheap per-tick read of the SOURCE-publishable file hashes (servable files that
/// are not compatibility hints), one small hash-string allocation each and no
/// rank/sort. Used to prune the publish schedule on every tick — including ticks
/// the gate/DHT-busy/in-flight-budget short-circuits abort — and to size the
/// pre-build diagnostics, without paying for the full ranked candidate clone. The
/// hash set is identical to the SOURCE-scan set built by
/// `kad_publishable_shared_files` (same `kad_source_publish_eligible` filter), so
/// the schedule prune is unchanged from the previous build-first ordering.
async fn kad_source_publishable_hashes(runtime: &Ed2kTransferRuntime) -> Vec<String> {
    let shared_catalog = runtime.shared_catalog();
    let guard = shared_catalog.read().await;
    guard
        .iter()
        .filter(|entry| kad_source_publish_eligible(entry))
        .map(|entry| entry.file_hash.clone())
        .collect()
}

async fn kad_publishable_shared_files(
    runtime: &Ed2kTransferRuntime,
    schedule: &kad_publish_schedule::KadPublishSchedule,
) -> Result<KadPublishCandidateSets> {
    let now_instant = Instant::now();
    let now_unix_ms = Utc::now().timestamp_millis();
    let shared_catalog = runtime.shared_catalog();
    let guard = shared_catalog.read().await;
    Ok(compute_kad_publish_candidates(
        &guard,
        schedule,
        now_instant,
        now_unix_ms,
        KAD_SHARED_FILE_PUBLISH_SCAN_BUDGET,
    ))
}

/// Compute the balanced publish rank directly over a borrowed shared-catalog
/// entry, without cloning it into a `MetadataTransferPublishEntry` first. The
/// field mapping mirrors `kad_publish_entry_from_shared_entry` exactly, and
/// `shared_publish_rank` is a pure function of these fields, so the resulting
/// rank (and thus the sort order) is byte-identical to ranking the clone.
fn shared_entry_publish_rank(
    entry: &Ed2kSharedEntry,
    sequence: usize,
    last_publish_unix_ms: i64,
    now_unix_ms: i64,
) -> SharedPublishRank {
    shared_publish_rank(SharedPublishRankInput {
        file_hash: &entry.file_hash,
        file_size: entry.file_size,
        upload_priority: &entry.upload_priority,
        auto_upload_priority: entry.auto_upload_priority,
        queued_count: 0,
        session_request_count: entry.publish.session_request_count,
        session_accept_count: entry.publish.session_accept_count,
        all_time_request_count: entry.publish.all_time_request_count,
        all_time_accept_count: entry.publish.all_time_accept_count,
        all_time_uploaded_bytes: entry.all_time_uploaded_bytes,
        session_uploaded_bytes: entry.publish.session_uploaded_bytes,
        last_request_unix_ms: entry.publish.last_request_unix_ms,
        last_publish_unix_ms,
        sequence,
        now_unix_ms,
    })
}

/// Rank a filtered list of borrowed shared entries and return their indices
/// ordered best-first, WITHOUT materializing any clone. `last_publish_unix_ms`
/// supplies the per-file age-term clock keyed by hash (the SOURCE/NOTES Kad clock,
/// or a constant for the keyword lane whose oracle age term is 0). Because the
/// sequence tie-break is the position in `entries` (the filtered catalog-iteration
/// order) and the rank is pure, the returned order equals ranking the cloned list
/// with `kad_publishable_shared_file_entries` — only the clones are avoided.
fn ranked_shared_entry_order(
    entries: &[&Ed2kSharedEntry],
    now_unix_ms: i64,
    last_publish_unix_ms: impl Fn(&str) -> i64,
) -> Vec<usize> {
    let mut ranked = entries
        .iter()
        .enumerate()
        .map(|(sequence, entry)| {
            (
                shared_entry_publish_rank(
                    entry,
                    sequence,
                    last_publish_unix_ms(&entry.file_hash),
                    now_unix_ms,
                ),
                sequence,
            )
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|(left, _), (right, _)| compare_shared_publish_rank(left, right));
    ranked.into_iter().map(|(_, index)| index).collect()
}

/// Build one publish cycle's candidate sets over borrowed catalog entries,
/// cloning only what a tick actually consumes. The SOURCE lane is ranked over
/// borrows and only the cursor scan window (≤ `scan_budget`, ranked order) is
/// cloned; the NOTES best candidate is picked over the full source-eligible set
/// (borrowed rank on the notes clock) so it stays global; the KEYWORD lane is
/// ranked over borrows and materialized in full because the >150-file keyword
/// batch builder scans the whole completed-file set. Selection (which files, in
/// what order) is identical to ranking full clones — see the equivalence test.
fn compute_kad_publish_candidates(
    entries: &[Ed2kSharedEntry],
    schedule: &kad_publish_schedule::KadPublishSchedule,
    now_instant: Instant,
    now_unix_ms: i64,
    scan_budget: usize,
) -> KadPublishCandidateSets {
    // SOURCE lane: every servable file, ranked by the SOURCE last-publish clock
    // (the oracle source selection ranks due files by `GetLastPublishTimeKadSrc()`,
    // SharedFileList.cpp:3377).
    let source_refs = entries
        .iter()
        .filter(|entry| kad_source_publish_eligible(entry))
        .collect::<Vec<_>>();
    let source_order = ranked_shared_entry_order(&source_refs, now_unix_ms, |file_hash| {
        schedule.source_last_publish_unix_ms(file_hash, now_instant, now_unix_ms)
    });
    let source_item_count = source_order.len();
    let source_cursor_start = schedule.cursor(source_item_count);
    // Materialize ONLY the cursor scan window (≤ scan_budget), in ranked order
    // starting at the cursor — the same slice the loop inspects.
    let window_len = source_item_count.min(scan_budget);
    let source_scan = (0..window_len)
        .map(|offset| {
            let ranked_pos = (source_cursor_start + offset) % source_item_count;
            kad_publish_entry_from_shared_entry(source_refs[source_order[ranked_pos]])
        })
        .collect::<Vec<_>>();
    // NOTES lane: single best-ranked notes-due file across the FULL source-eligible
    // set, taken in the SOURCE-sorted order so the sequence tie-break matches the
    // pre-optimization full-scan selection, then re-ranked on the NOTES clock.
    let notes_candidates = source_order
        .iter()
        .map(|&index| source_refs[index])
        .filter(|entry| {
            kad_publish_schedule::file_has_publishable_note(&entry.comment, entry.rating)
                && schedule.notes_due(&entry.file_hash, now_instant)
        })
        .map(kad_publish_entry_from_shared_entry)
        .collect::<Vec<_>>();
    let best_notes_hash =
        select_best_notes_publish_candidate(&notes_candidates, schedule, now_instant, now_unix_ms);
    // KEYWORD lane holds the age term CONSTANT, independent of the source-clock
    // scan sort: the oracle keyword rank passes 0 for `tLastPublish`
    // (SharedFileList.cpp:3316), so keyword selection is priority/demand-ordered,
    // not perturbed by when each file was last SOURCE-published. `|_| 0` maps
    // every file to `publish_age_score`'s flat max (80), matching that constant.
    // The batch builder walks the whole completed-file set (to fill a >150-file
    // keyword batch), so this lane is materialized in full in ranked order.
    let keyword_refs = entries
        .iter()
        .filter(|entry| kad_keyword_publish_eligible(entry))
        .collect::<Vec<_>>();
    let keyword_order = ranked_shared_entry_order(&keyword_refs, now_unix_ms, |_| 0);
    let keyword_files = keyword_order
        .iter()
        .filter_map(|&index| {
            match kad_keyword_publish_candidate_from_shared_entry(keyword_refs[index]) {
                Ok(candidate) => Some(candidate),
                Err(error) => {
                    tracing::warn!(
                        file_hash = %keyword_refs[index].file_hash,
                        error = %error,
                        "skipping invalid shared-file hash during Kad keyword candidate build"
                    );
                    None
                }
            }
        })
        .collect::<Vec<_>>();
    let keyword_index = keyword_files
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.file_hash.clone(), index))
        .collect();
    KadPublishCandidateSets {
        source_scan,
        source_item_count,
        source_cursor_start,
        best_notes_hash,
        keyword_files,
        keyword_index,
    }
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

/// Rank the publishable shared files by the balanced publish rank, ordered best
/// first. `last_publish_unix_ms` supplies the per-file last-publish wall time for
/// the age/staleness term, keyed by file hash — the caller passes the SOURCE or
/// NOTES Kad clock (or a constant for lanes whose oracle age term is constant),
/// so the longest-unpublished file wins within its priority tier
/// (SharedFileList.cpp:3374-3379,3421-3426, `GetPublishAgeScore`).
fn kad_publishable_shared_file_entries(
    entries: Vec<MetadataTransferPublishEntry>,
    now_unix_ms: i64,
    last_publish_unix_ms: impl Fn(&str) -> i64,
) -> Vec<MetadataTransferPublishEntry> {
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
                last_publish_unix_ms: last_publish_unix_ms(&entry.file_hash),
                sequence,
                now_unix_ms,
            });
            (rank, entry)
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|(left, _), (right, _)| compare_shared_publish_rank(left, right));
    ranked.into_iter().map(|(_, entry)| entry).collect()
}

/// Select the single best-ranked notes-due file for this publish tick, mirroring
/// the oracle notes selection loop (SharedFileList.cpp:3412-3435): among files
/// carrying a user comment/rating whose 24h notes interval is due, pick the
/// best-ranked hash using the NOTES last-publish clock
/// (`GetLastPublishTimeKadNotes`) so the longest-unpublished note wins within its
/// priority tier. Returns `None` when no annotated file is notes-due.
fn select_best_notes_publish_candidate(
    shared_files: &[MetadataTransferPublishEntry],
    schedule: &kad_publish_schedule::KadPublishSchedule,
    now_instant: Instant,
    now_unix_ms: i64,
) -> Option<String> {
    let candidates = shared_files
        .iter()
        .filter(|entry| {
            kad_publish_schedule::file_has_publishable_note(&entry.comment, entry.rating)
                && schedule.notes_due(&entry.file_hash, now_instant)
        })
        .cloned()
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return None;
    }
    kad_publishable_shared_file_entries(candidates, now_unix_ms, |file_hash| {
        schedule.notes_last_publish_unix_ms(file_hash, now_instant, now_unix_ms)
    })
    .into_iter()
    .next()
    .map(|entry| entry.file_hash)
}

/// Self-inclusive complete-source count published as the Kad keyword
/// `TAG_SOURCES` value.
///
/// The oracle publishes `CKnownFile::m_nCompleteSourcesCount`
/// (`CSearch::PreparePacketForTags`, Search.cpp:1479). The `CKnownFile`
/// constructor seeds that counter to 1 (KnownFile.cpp:126) because we hold the
/// complete file ourselves, and it only rises above 1 once source exchange
/// reports other clients that hold every part — `acount.Add(m_nCompleteSourcesCount + 1)`,
/// "plus 1 since we have the complete file too" (KnownFile.cpp:307-313). So the
/// published count is self-inclusive: `other_complete_sources + 1`.
///
/// rust does not yet track other complete sources for shared library files, so
/// the keyword-publish build site passes `other_complete_sources = 0` and the
/// faithful published value is the self-only base of 1.
fn keyword_publish_complete_source_count(other_complete_sources: u32) -> u32 {
    other_complete_sources.saturating_add(1)
}

fn kad_keyword_publish_entries_for_keyword(
    shared_files: &[KadKeywordPublishCandidate],
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
        if !entry.keyword_terms.iter().any(|term| term == keyword) {
            continue;
        }
        let mut tags = vec![
            Tag::filename(entry.canonical_name.clone()),
            Tag::filesize(entry.file_size),
            Tag::sources(keyword_publish_complete_source_count(0)),
        ];
        if let Some(file_type) = ed2k_file_type_search_term(&entry.canonical_name) {
            tags.push(Tag::filetype(file_type));
        }
        entries.push((
            entry.file_hash.clone(),
            KeywordPublishEntry {
                file_hash: entry.file_hash_bytes,
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
    /// Cancellation handle for the spawned outbound buddy link (LOWID-G8), shared
    /// with the buddy-management loop so it can tear the link down on a state
    /// change.
    buddy_link_cancel: Arc<std::sync::Mutex<Option<CancellationToken>>>,
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
    /// Cancellation handle for the spawned outbound buddy link (LOWID-G8).
    buddy_link_cancel: Arc<std::sync::Mutex<Option<CancellationToken>>>,
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
                    // LOWID-G8: tear down the persistent outbound buddy link (and
                    // its OP_BUDDYPING keepalive) now that we no longer need a
                    // buddy, instead of leaving it running until the socket dies
                    // and holding the remote helper's single buddy slot (oracle
                    // drops the buddy socket on HighID / Kad-disconnect,
                    // ClientList.cpp:770-780).
                    if let Some(cancel) = runtime.buddy_link_cancel.lock().unwrap().take() {
                        cancel.cancel();
                    }
                }
            }
            // LOWID-G2: expire an incoming-buddy claim whose buddy never attached
            // a TCP session (or whose held session ended and never returned), so a
            // later FINDBUDDY_REQ is answerable again. While a buddy session is
            // attached (registry holds an inbound socket) the claim is kept.
            let buddy_attached = runtime.buddy_registry.has_inbound();
            if state.reconcile_incoming_buddy(
                buddy_attached,
                now,
                chrono::Duration::seconds(INCOMING_BUDDY_ATTACH_TIMEOUT_SECS),
            ) {
                tracing::debug!(
                    "released a stale incoming Kad buddy claim (no attached buddy session)"
                );
                runtime.buddy_registry.clear_inbound();
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

/// Run one buddy search (oracle `CSearchManager::FindBuddy` -> `CSearch` type
/// FINDBUDDY): a full Kad walk near our derived buddy target whose routing
/// `KADEMLIA2_REQ`s carry the STORE contact count, sending
/// `KADEMLIA_FINDBUDDY_REQ` to each tolerance-passing responded contact up to
/// the oracle answer target within the FINDBUDDY search lifetime
/// (Search.cpp:864-896,1653-1657). Each `FINDBUDDY_RES` reply is recorded by
/// the unsolicited inbound dispatch into [`KadBuddyState`].
async fn run_kad_buddy_search(runtime: &KadBuddyRuntime) -> Result<()> {
    let own_id = runtime.dht.own_id();
    let target = buddy_search_target(own_id);
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
    tracing::info!(
        "starting Kad FINDBUDDY walk near {target} (we are firewalled, seeking a buddy)"
    );
    runtime
        .dht
        .find_buddy_search(request, RpcWorkClass::Interactive)
        .await;
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

#[expect(
    clippy::cognitive_complexity,
    reason = "linear protocol orchestration flow"
)]
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
        sender_verify_key,
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
            let our_tcp_port = ed2k_listener
                .local_addr()
                .context("failed to read eD2K listener address while handling Kad FIREWALLED_REQ")?
                .port();
            spawn_kad_firewalled_response(
                dht.clone(),
                network.bind_ip,
                runtime.reachability.clone(),
                Arc::clone(kad_firewall),
                our_tcp_port,
                from,
                req.tcp_port,
            );
        }
        KadPacket::Firewalled2Req(req) => {
            spawn_modern_kad_firewalled_response(
                dht.clone(),
                ed2k_listener.local_addr().context(
                    "failed to read eD2K listener address while handling Kad FIREWALLED2_REQ",
                )?,
                Arc::clone(server_state),
                Arc::clone(kad_firewall),
                runtime.reachability.clone(),
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
            // Oracle GetBootstrapContacts(20): a keyspace-spread sample capped at
            // 20, NOT the K contacts nearest our own id, so a bootstrapping node
            // receives a spread of the keyspace to seed its buckets.
            let contacts = dht
                .bootstrap_contacts(KAD_BOOTSTRAP_RESPONSE_CONTACTS)
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
                // The publisher IP feeds the FT_PUBLISHINFO publish-diversity /
                // anti-spam trust accounting (oracle CKeyEntry m_uIP tracking).
                let publisher_ip = match from.ip() {
                    IpAddr::V4(ip) => ip,
                    IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                };
                store.record_keyword_publish_batch(
                    req.target,
                    &req.entries,
                    publisher_ip,
                    Utc::now(),
                )
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
                &runtime.reachability,
                network,
                from,
                req,
                // LOWID-G11: the oracle appends the connect-options byte only when
                // the requester carried a UDP key (senderUDPKey non-empty); the
                // recovered sender verify key is that signal.
                sender_verify_key.is_some(),
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
                &runtime.buddy_link_cancel,
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
/// LOWID-G12 self-endpoint pre-check: refuse a `FINDBUDDY_REQ` whose `(IP, TCP
/// port)` is our own advertised endpoint (oracle `ClientList.cpp:906`,
/// `serverconnect->GetLocalIP() == nContactIP && thePrefs.GetPort() == TCPPort`).
/// IPv4-only; a non-IPv4 source or an unknown public IP can never be us.
fn find_buddy_req_is_self_endpoint(
    from_ip: IpAddr,
    req_tcp_port: u16,
    our_public_ip: Option<Ipv4Addr>,
    our_tcp_port: u16,
) -> bool {
    matches!(
        (from_ip, our_public_ip),
        (IpAddr::V4(from), Some(ours)) if from == ours
    ) && req_tcp_port == our_tcp_port
}

/// LOWID-G11 `FINDBUDDY_RES` connect-options byte: present only when the requester
/// carried a UDP key (oracle `if (!senderUDPKey.IsEmpty())`,
/// `KademliaUDPListener.cpp:1757-1758`), so a keyless legacy requester receives
/// the 34-byte response with no trailing byte.
fn find_buddy_res_connect_options(
    requester_has_udp_key: bool,
    obfuscation_enabled: bool,
) -> Option<u8> {
    requester_has_udp_key.then(|| emule_connect_options(obfuscation_enabled))
}

#[expect(
    clippy::too_many_arguments,
    reason = "flat protocol or runtime boundary"
)]
async fn handle_kad_find_buddy_req(
    dht: &DhtNode,
    ed2k_listener: &TcpListener,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    kad_buddy: &Arc<Mutex<KadBuddyState>>,
    buddy_registry: &BuddySocketRegistry,
    reachability: &ExternalReachability,
    network: &Ed2kNetworkConfig,
    from: SocketAddr,
    req: FindBuddyReq,
    requester_has_udp_key: bool,
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

    // LOWID-G12: oracle IncomingBuddy pre-checks (ClientList.cpp:895-907), each a
    // silent abort before accepting a new incoming buddy.
    //   - Kad-fwcheck collision (ClientList.cpp:902): we are mid TCP firewall
    //     check with this IP; RequestTCP owns the client, so refuse.
    //   - self-endpoint (ClientList.cpp:906): never buddy with ourselves.
    // The known-client-by-IP guard (ClientList.cpp:900, FindClientByIP) has no
    // rust equivalent: this client is connection-per-operation and keeps no
    // global CUpDownClient list to look a peer up in, so that pre-check is not
    // wired (the fwcheck-collision guard covers the main conflicting relationship).
    {
        let firewall = kad_firewall.lock().await;
        if firewall.is_tcp_firewall_check_ip(from.ip(), Utc::now()) {
            tracing::debug!(
                "ignoring Kad FINDBUDDY_REQ from {from}: Kad TCP firewall-check collision"
            );
            return Ok(());
        }
    }
    if find_buddy_req_is_self_endpoint(from.ip(), req.tcp_port, reachability.get(), tcp_port) {
        tracing::debug!("ignoring Kad FINDBUDDY_REQ from {from}: self endpoint");
        return Ok(());
    }

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
        // LOWID-G11: the oracle appends the connect-options byte only when the
        // requester carried a UDP key (KademliaUDPListener.cpp:1757-1758). A
        // keyless legacy requester gets the 34-byte response with no trailing byte.
        connect_options: find_buddy_res_connect_options(
            requester_has_udp_key,
            network.config.obfuscation_enabled,
        ),
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
#[expect(
    clippy::too_many_arguments,
    reason = "flat protocol or runtime boundary"
)]
async fn handle_kad_find_buddy_res(
    dht: &DhtNode,
    kad_buddy: &Arc<Mutex<KadBuddyState>>,
    buddy_registry: &BuddySocketRegistry,
    buddy_link_cancel: &Arc<std::sync::Mutex<Option<CancellationToken>>>,
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
    // LOWID-G8: install a fresh cancellation handle for this link so the
    // buddy-management loop can tear it down (and stop its keepalive pings) when
    // the buddy relationship is no longer warranted.
    let cancel = CancellationToken::new();
    // A newly-acquired buddy replaces any stale handle; the previous link (if any)
    // has already exited or is being torn down.
    *buddy_link_cancel.lock().unwrap() = Some(cancel.clone());
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
            cancel,
        })
        .await
        {
            tracing::debug!("outbound Kad buddy link to {buddy_addr} failed: {error:#}");
        }
        // On any exit (connect failure, link drop, or cancellation), drop the
        // acquired buddy so the next upkeep re-searches. The stale cancellation
        // handle in the shared cell is harmless: it is overwritten when a new
        // buddy is acquired, and cancelling an already-finished token is a no-op.
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedEd2kLink {
    file_hash: String,
    name: String,
    size_bytes: u64,
    sources: Vec<Ed2kSourceHint>,
}

fn parse_ed2k_link(link: &str) -> Result<ParsedEd2kLink> {
    let parts = link
        .strip_prefix("ed2k://|file|")
        .and_then(|rest| rest.strip_suffix("|/"))
        .ok_or_else(|| anyhow::anyhow!("invalid ED2K link"))?
        .split('|')
        .collect::<Vec<_>>();
    anyhow::ensure!(parts.len() >= 3, "invalid ED2K file link");
    Ok(ParsedEd2kLink {
        file_hash: parts[2].to_ascii_lowercase(),
        name: parts[0].to_string(),
        size_bytes: parts[1].parse()?,
        sources: parse_ed2k_link_sources(parts.iter().skip(3).copied()),
    })
}

fn parse_ed2k_link_sources<'a>(sections: impl Iterator<Item = &'a str>) -> Vec<Ed2kSourceHint> {
    let mut sources: Vec<Ed2kSourceHint> = Vec::new();
    for section in sections {
        let Some(rest) = section.strip_prefix("sources,") else {
            continue;
        };
        for item in rest.split(',') {
            let parts = item.split(':').collect::<Vec<_>>();
            let (address, port, user_hash) = match parts.as_slice() {
                [address, port] => (*address, *port, None),
                [address, port, user_hash] => {
                    let Some(user_hash) = parse_ed2k_source_user_hash(user_hash) else {
                        continue;
                    };
                    (*address, *port, Some(user_hash))
                }
                _ => continue,
            };
            let Ok(ip) = address.parse::<Ipv4Addr>() else {
                continue;
            };
            let Ok(tcp_port) = port.parse::<u16>() else {
                continue;
            };
            if ip.is_unspecified() || tcp_port == 0 {
                continue;
            };
            let ip = ip.to_string();
            if let Some(existing) = sources
                .iter_mut()
                .find(|source| source.ip == ip && source.tcp_port == tcp_port)
            {
                if existing.user_hash.is_none() {
                    existing.user_hash = user_hash;
                }
            } else {
                sources.push(Ed2kSourceHint {
                    ip: ip.to_string(),
                    tcp_port,
                    user_hash,
                });
            }
        }
    }
    sources
}

fn parse_ed2k_source_user_hash(value: &str) -> Option<String> {
    (value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn should_retry_download_attempt_state(state: &str) -> bool {
    matches!(state, "downloading" | "queued")
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
mod tests;
