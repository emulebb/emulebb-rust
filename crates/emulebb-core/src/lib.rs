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
use chrono::Utc;
use emulebb_ed2k::{
    NatManager, NatManagerBuilder, ReaskSourceHandle,
    buddy_socket::{BuddySocketRegistry, ExpectedInboundBuddy},
    built_in_upnp_port_mapping_providers,
    config::Ed2kConfig,
    ed2k_server::{
        Ed2kCallbackRequestOptions, Ed2kFoundSource, Ed2kKeywordSearchOptions,
        Ed2kServerLoopOptions, Ed2kServerSearchHandle, Ed2kServerState, Ed2kSourceSearchOptions,
        Ed2kUdpSourceSearchOptions, ed2k_server_list_event_channel, new_ed2k_server_search_channel,
        parse_server_met, publish_shared_catalog_via_background_session, request_callback_on_server,
        request_callback_via_background_session, run_ed2k_server_loop, search_keyword_servers,
        search_keyword_via_background_session, search_source_servers, search_source_udp_servers,
        search_source_via_background_session,
    },
    ed2k_tcp::{
        Ed2kHelloIdentity, Ed2kListenerOptions, Ed2kPeerDownloadOptions, Ed2kPeerDownloadOutcome,
        Ed2kSecureIdent, HelloBuddySnapshot, OutboundBuddyLinkOptions, download_file_from_peer, emule_connect_options,
        encode_kad_callback_relay_frame, run_ed2k_listener, run_outbound_buddy_link,
        set_hello_buddy_snapshot, set_publish_rust_identity,
    },
    ed2k_transfer::{
        ED2K_PART_SIZE, Ed2kCallbackIntent, Ed2kResumeManifest, Ed2kSourceHint,
        Ed2kTransferRuntime, Ed2kUploadSessionPhaseSnapshot, new_transfer_job,
    },
    kad_firewall::{FirewallUdpPacketOutcome, FirewalledResponseOutcome, KadFirewallState},
    reachability::ExternalReachability,
    reask_command_channel, reask_event_channel, run_ed2k_udp_reask_loop,
};
#[cfg(test)]
use emulebb_ed2k::config::Ed2kUploadQueuePolicyConfig;
#[cfg(test)]
use emulebb_ed2k::{MappingExposure, TransportProtocol};
use emulebb_index::{
    FileIndex, IndexedFile, KadLocalStore, SnoopEntry, SnoopQueue,
    metadata_from_publish_snapshot, publish_snapshot_from_metadata,
};
#[cfg(test)]
use emulebb_index::{KadLocalStoreConfig, SnoopQueueConfig, SnoopQueueFamilyCounts};
use emulebb_kad_dht::{
    DhtConfig, DhtNode, PublishAttemptStats, ReceivedKadPacket, RpcWorkClass,
};
#[cfg(test)]
use emulebb_kad_dht::{
    NoteResult as KadNoteResult, SearchResult as KadSearchResult, SourceResult,
};
use emulebb_kad_proto::{
    CallbackReq, Ed2kHash, FindBuddyReq, FindBuddyRes,
    HelloResAck, KAD_VERSION, KadPacket, PublishRes, Tag, constants::K,
    packet::ContactEntry,
};
#[cfg(test)]
use emulebb_kad_proto::{
    SearchKeyReq, SearchNotesReq, SearchRes, SearchResultEntry, SearchSourceReq,
};
#[cfg(test)]
use emulebb_ed2k::ed2k_server::Ed2kSearchFile;
#[cfg(test)]
use emulebb_kad_proto::tag_name;
use emulebb_metadata::MetadataStore;
use serde_json::json;
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod categories;
mod diag_kad_event;
mod diag_sched;
mod download_source_registry;
mod ed2k_buddy_reask;
mod ed2k_net_drivers;
mod ed2k_sources;
mod kad_buddy;
mod kad_hello;
mod kad_passive_replay;
mod kad_publish_schedule;
mod kad_routing_maintenance;
mod kad_snoop_entry;
mod local_search_response;
mod preferences;
mod kad_tcp_firewall_check;
mod kad_udp_firewall_check;
mod profile_state;
mod search_query;
mod search_state;
mod shared_directories;
mod source_publish;
mod upload_view;
mod views;
use categories::{
    PR_NORMAL, apply_category_create, apply_category_update, default_categories,
};
use download_source_registry::{DownloadSourceCandidate, DownloadSourceRegistry};
use ed2k_net_drivers::{
    ed2k_nat_mappings, fetch_url_bytes, run_advertised_ports_sync, run_ed2k_nat_type_probe,
    run_ed2k_public_ip_probe, run_ed2k_reask_reengage, run_ed2k_server_list_events,
};
use ed2k_buddy_reask::detach_kad_buddy_sources_for_reask;
use ed2k_sources::{
    Ed2kServerCallbackRoute, LearnedEd2kMetadata, OwnSourceIdentity, collect_kad_ed2k_metadata,
    collect_kad_ed2k_sources, configured_server_attempts, direct_download_candidate_sources,
    drop_self_sources, ed2k_keyword_server_attempts, ed2k_server_callback_route,
    found_source_from_hint, hash_only_ed2k_search_query, kad_source_result_to_ed2k_found_source,
    keyword_target, manifest_has_ed2k_transfer_progress, merge_download_sources,
    new_direct_ed2k_source_count,
    plaintext_fallback_for_obfuscated_source, select_ed2k_keyword_metadata,
    should_adopt_hash_only_metadata_name, should_exclude_background_source_endpoint,
    should_query_kad_source_supplement, should_skip_no_progress_source_requery,
    sort_download_sources, source_endpoint_key, source_key,
};
#[cfg(test)]
use ed2k_sources::{
    exact_ed2k_hash_query_token, select_kad_keyword_metadata, significant_keyword_words,
};
use kad_buddy::{
    BuddyNeedInput, FindBuddyReqRefusal, IncomingBuddy, KadBuddyState, OutgoingBuddy,
    buddy_search_target, find_buddy_res_matches,
};
use kad_hello::{
    build_kad_hello_request, build_kad_hello_response, kad_publish_within_tolerance,
    kad_req_masked_count, should_request_hello_res_ack, spawn_kad_firewalled_response,
    spawn_modern_kad_firewalled_response,
};
#[cfg(test)]
use kad_hello::{
    build_kad_hello_request_tags, build_kad_hello_response_tags, firewalled_response_ip_for_sender,
};
use kad_passive_replay::{PassiveReplayWorker, run_kad_passive_replay_loop};
#[cfg(test)]
use kad_passive_replay::{
    PassiveReplayFamily, index_passive_keyword_result, preferred_passive_replay_families,
    remember_passive_note_results, remember_passive_source_results,
};
use kad_snoop_entry::{
    build_keyword_snoop_entry, build_notes_snoop_entry, build_source_snoop_entry,
};
use local_search_response::send_local_search_response;
#[cfg(test)]
use local_search_response::split_stock_search_responses;
use preferences::{
    apply_preferences_update, default_preferences,
    ed2k_download_coordinator_config_from_preferences,
    ed2k_download_limit_bytes_per_sec_from_preferences, ed2k_upload_queue_policy_from_preferences,
    initial_ed2k_upload_queue_policy, preferences_update_is_empty,
};
use search_query::{apply_search_filters, search_result_from_ed2k, search_result_from_indexed};
use source_publish::{
    SourcePublishSettings, build_source_publish_tags, source_publish_client_hash,
};
use upload_view::{upload_from_snapshot, upload_policy_metrics_from_capacity};

pub use shared_directories::{
    SharedDirectories, SharedDirectoriesUpdate, SharedDirectoryRoot, SharedDirectoryRootUpdate,
};
use shared_directories::{
    collect_shared_directory_files, refresh_shared_directory_row, shared_directory_from_index,
    shared_directory_to_index, shared_directory_update_parts,
};

mod rest_model;
pub use rest_model::{
    AppInfo, AppLifecycle, Category, CategoryCreate, CategoryPriorityValue, CategoryUpdate,
    DiagnosticDumpResult, DownloadSourceMetrics, Ed2kNetworkConfig, Friend, FriendCreate,
    IndexingStatus, LocalShare, LocalShareCreate, NetworkStatus, NullableStringField,
    NullableU32Field, Preferences, PreferencesUpdate, Search, SearchCreate, SearchResult,
    SearchResultDownloadCreate, ServerCreate, ServerInfo, ServerUpdate, SharedFileUpdate,
    Status, Transfer, TransferCreate, TransferDetails, TransferPart, TransferSource,
    TransferStats, TransferThroughputStats, TransferUpdate, Upload, UploadPolicyMetrics,
    UploadScoreBreakdown, VpnGuardConfig, VpnGuardStatus,
};
use views::{
    apply_server_update, download_priority_score,
    ensure_category_selector_is_unambiguous, enrich_sources_with_live, kad_status_from_running,
    manifest_default_state_name, normalize_transfer_name, preserve_transfer_public_metadata,
    server_endpoint_from_create, server_info_from_parts, source_by_client_id, source_friend_name,
    transfer_create_links, transfer_create_state_name, transfer_from_manifest,
    transfer_parts_from_manifest, transfer_sources_from_manifest, validate_server_priority,
    validate_server_update, validate_shared_file_comment_rating, validate_shared_upload_priority,
    validate_source_client_id, validate_transfer_priority, validate_transfer_update_family,
    validate_url_import,
};

const LOCAL_KEYWORD_SEARCH_RESPONSE_LIMIT: usize = 300;
const LOCAL_SOURCE_SEARCH_RESPONSE_LIMIT: usize = 300;
const LOCAL_NOTES_SEARCH_RESPONSE_LIMIT: usize = 150;
const KAD_SHARED_FILE_PUBLISH_RETRY_SECS: u64 = 5;
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
    /// Sources that reported No Needed Parts for this file (eMuleBB
    /// `DS_NONEEDEDPARTS` / `OP_OUTOFPARTREQS`). The driver runs the A4AF-lite
    /// swap (`CUpDownClient::SwapToAnotherFile`) on each: if the registry shows
    /// the peer serves another wanted file, the source is moved to that file
    /// instead of being dropped.
    no_needed_parts_sources: Vec<Ed2kFoundSource>,
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
    /// Consecutive connect/ping failures per server endpoint (eMule
    /// `CServer::IncFailedCount`). A non-static server is dropped at the
    /// `dead_server_retries` threshold; a successful connect clears the count.
    server_fail_counts: HashMap<String, u32>,
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
    /// Detached per-transfer background download tasks for this session (FIX B3).
    /// Aborted by `disconnect_ed2k`; a fresh handle is created per connect so a
    /// later reconnect's tasks are never aborted by an earlier disconnect.
    download_tasks: Arc<Mutex<JoinSet<()>>>,
}

/// RAII guard that removes a transfer hash from `active_download_attempts` on
/// drop, so the dedup slot is freed on every exit path of a background download
/// attempt — normal return, early return, *or* a panic that unwinds the task
/// (FIX B2). The map lives behind an async mutex, so the cleanup is performed by
/// a short detached task spawned from `Drop`.
struct DownloadAttemptGuard {
    core: EmulebbCore,
    hash: String,
}

impl Drop for DownloadAttemptGuard {
    fn drop(&mut self) {
        let core = self.core.clone();
        let hash = std::mem::take(&mut self.hash);
        tokio::spawn(async move {
            core.state
                .lock()
                .await
                .active_download_attempts
                .remove(&hash);
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
    /// Tracks the detached per-transfer background download tasks for the current
    /// connected session, so `disconnect_ed2k` can abort them (they are otherwise
    /// untracked detached tasks that survive disconnect and orphan on shutdown).
    /// Reset to a fresh `JoinSet` on each connect; the same handle is stored in
    /// the session `Ed2kRuntime` and aborted on disconnect (FIX B3).
    ed2k_download_tasks: Arc<Mutex<JoinSet<()>>>,
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
        let ed2k_transfers = if ed2k_network.is_some() {
            Ed2kTransferRuntime::load_or_create_with_metadata_and_config(
                &transfer_root,
                metadata_store.clone(),
                &Ed2kConfig {
                    upload_queue: upload_queue_policy,
                    download_limit_bytes_per_sec,
                    ..Ed2kConfig::default()
                },
            )?
        } else {
            Ed2kTransferRuntime::load_or_create_with_metadata_and_config(
                &transfer_root,
                metadata_store.clone(),
                &Ed2kConfig {
                    upload_queue: upload_queue_policy,
                    download_limit_bytes_per_sec,
                    ..Ed2kConfig::default()
                },
            )?
        };
        // Drive the shared download coordinator from the live REST preferences
        // (maxConnections / maxConnectionsPerFiveSeconds / maxSourcesPerFile),
        // like the download throttle, so REST preference changes apply to the
        // global connection budget + per-file source caps.
        ed2k_transfers.apply_download_coordinator_config(
            ed2k_download_coordinator_config_from_preferences(&core_state.preferences),
        );
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
            ed2k_download_tasks: Arc::new(Mutex::new(JoinSet::new())),
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
        self.ed2k_transfers
            .apply_download_limit(ed2k_download_limit_bytes_per_sec_from_preferences(
                &preferences,
            ))
            .await;
        // Apply the global connection budget + per-file source caps live, like
        // the download limit (eMule GetMaxConnections / GetMaxConperFive /
        // GetConfiguredMaxSourcesPerFile preference changes take effect at once).
        self.ed2k_transfers
            .apply_download_coordinator_config(
                ed2k_download_coordinator_config_from_preferences(&preferences),
            );
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
        {
            let runtime = self.ed2k_runtime.lock().await;
            if let Some(signal) = runtime.as_ref().and_then(|rt| rt.kad_firewall_recheck.as_ref())
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
                KadPublishLoopRuntime {
                    dht: dht.clone(),
                    transfer_runtime: Arc::clone(&self.ed2k_transfers),
                    ed2k_listener: Arc::clone(&ed2k_listener),
                    server_state: Arc::clone(&server_state),
                    kad_firewall: Arc::clone(&kad_firewall),
                    kad_buddy: Arc::clone(&kad_buddy),
                    network: network.clone(),
                },
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
            reconnect_signal: server_reconnect_signal,
            server_list_events: Some(server_list_events_tx),
        })));
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
            kad_bootstrap_configured: configured_bootstrap_nodes_text.is_some(),
            nat,
            shutdown,
            kad_firewall_recheck,
            tasks,
            download_tasks: Arc::clone(&self.ed2k_download_tasks),
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
            // Abort this session's detached background-download tasks (FIX B3) so
            // downloads do not survive disconnect or orphan on shutdown.
            runtime.download_tasks.lock().await.abort_all();
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
        let connected_endpoint = self.ed2k_connected_endpoint().await;
        let mut added = 0usize;
        for (ip, port) in servers {
            if port == 0 {
                continue;
            }
            let endpoint = format!("{ip}:{port}");
            if existing.contains(&endpoint) || disabled.contains(&endpoint) {
                continue;
            }
            // Add directly to the store (never auto-connect a discovered server),
            // mirroring `add_server` minus the connect branch — eMule adds
            // OP_SERVERLIST servers at low priority without connecting.
            let mut server = server_info_from_parts(
                &ip.to_string(),
                port,
                None,
                None,
                false,
                connected_endpoint.as_deref(),
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
        self.ed2k_transfers
            .ban_client(parse_ban_ip(&upload.address), parse_ban_hash(upload.user_hash.as_deref()));
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
        self.ed2k_transfers
            .ban_client(parse_ban_ip(&source.ip), parse_ban_hash(source.user_hash.as_deref()));
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
        self.queue_ed2k_download_attempt(transfer.clone());
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
            self.queue_ed2k_download_attempt(transfer.clone());
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
            let callback_only_sources = sources
                .iter()
                .filter(|source| source.low_id && !source.has_kad_buddy_reask_target())
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
        // Per-file source cap (eMule GetMaxSourcePerFileSoft > GetSourceCount):
        // a file stops engaging new sources past its soft cap. The coordinator
        // (on the transfer runtime) owns the cap; the per-file source count
        // comes from the registry.
        for source in sources {
            let endpoint = source_endpoint_key(source);
            let file_source_count = state
                .download_source_registry
                .candidate_count_for_file(file_hash);
            if !self.ed2k_transfers.can_engage_file_source(file_source_count) {
                state.download_source_registry.release_peer(source);
                deferred = deferred.saturating_add(1);
                crate::diag_sched::source_dropped(file_hash, source);
                continue;
            }
            let registry_lease = state
                .download_source_registry
                .lease_best_for_file(source, file_hash);
            if registry_lease.is_some() && state.active_download_peer_endpoints.insert(endpoint) {
                acquired.push(source.clone());
                crate::diag_sched::source_engaged(file_hash, source);
            } else {
                state.download_source_registry.release_peer(source);
                deferred = deferred.saturating_add(1);
                crate::diag_sched::source_dropped(file_hash, source);
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
                if let Some(target) = state.transfers.get(&candidate.file_hash) {
                    if !matches!(
                        target.state.as_str(),
                        "completed" | "completing" | "paused" | "stopped"
                    ) {
                        swap_targets.push(target.clone());
                    }
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
        let guard = {
            let mut state = core.state.lock().await;
            if !state.active_download_attempts.insert(hash.clone()) {
                return;
            }
            DownloadAttemptGuard {
                core: core.clone(),
                hash: hash.clone(),
            }
        };

        let result = core.run_ed2k_download_attempt(&transfer).await;
        let mut retry_downloading = false;
        match result {
            Ok(Some(next_state)) => {
                retry_downloading = next_state == "downloading";
                if let Err(error) = core.refresh_transfer_from_manifest(&hash, next_state).await {
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
        // Release the dedup slot before re-queueing so the retry can re-acquire it.
        drop(guard);
        if retry_downloading {
            core.queue_ed2k_download_retry(hash);
        }
    }

    /// Body of one delayed background download retry, run as a tracked task.
    async fn run_queued_ed2k_download_retry(core: EmulebbCore, hash: String) {
        tokio::time::sleep(Duration::from_secs(ED2K_DOWNLOAD_BACKGROUND_RETRY_SECS)).await;
        let Some(transfer) = core.transfer(&hash).await else {
            return;
        };
        if transfer.state != "downloading" {
            return;
        }
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

/// Shared inputs for the Kad shared-file (re)publish loop. Carries the
/// firewall/buddy state so the loop can apply the master
/// `CSharedFileList::Publish` gate (see [`kad_publish_schedule::kad_publish_allowed`]).
struct KadPublishLoopRuntime {
    dht: DhtNode,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
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
const KAD_SHARED_FILE_PUBLISH_TICK_SECS: u64 = 60;

async fn run_kad_shared_file_publish_loop(
    runtime: KadPublishLoopRuntime,
    shutdown: Arc<AtomicBool>,
) {
    let mut schedule = kad_publish_schedule::KadPublishSchedule::new();
    while !shutdown.load(Ordering::SeqCst) {
        if !runtime.dht.is_bootstrapped() {
            tokio::time::sleep(Duration::from_secs(KAD_SHARED_FILE_PUBLISH_RETRY_SECS)).await;
            continue;
        }

        if let Err(error) = publish_kad_due_shared_files(&runtime, &mut schedule).await {
            tracing::debug!("Kad shared-file publish cycle failed: {error:#}");
        }

        let tick_secs = KAD_SHARED_FILE_PUBLISH_TICK_SECS;
        for _ in 0..tick_secs {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
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
#[allow(clippy::cognitive_complexity)]
async fn publish_kad_due_shared_files(
    runtime: &KadPublishLoopRuntime,
    schedule: &mut kad_publish_schedule::KadPublishSchedule,
) -> Result<usize> {
    let manifests = kad_publishable_manifests(runtime.transfer_runtime.manifests().await?);
    // Keep the per-file schedule from growing without bound: forget files that
    // are no longer publishable (removed / no longer complete).
    schedule.retain_only(manifests.iter().map(|m| m.file_hash.as_str()));
    if manifests.is_empty() {
        return Ok(0);
    }

    // Master CSharedFileList::Publish gate (SharedFileList.cpp:3066-3076): do not
    // emit PUBLISH_*_REQ while firewalled-and-unreachable (no buddy, UDP closed).
    if !kad_publish_schedule::kad_publish_allowed(kad_publish_gate_input(runtime).await) {
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
    let mut keyword_totals = PublishAttemptStats::default();
    let mut source_totals = PublishAttemptStats::default();
    let mut notes_totals = PublishAttemptStats::default();
    let mut keyword_published = 0usize;
    let mut source_published = 0usize;
    let mut notes_published = 0usize;
    // Our Kad node id is the notes publisher identity (master STORENOTES writes
    // GetKadID() into the second 128-bit field of KADEMLIA2_PUBLISH_NOTES_REQ).
    let notes_publisher_id = runtime.dht.own_id();
    let item_count = manifests.len();

    for manifest in manifests {
        let now = Instant::now();
        let file_hash: Ed2kHash = manifest.file_hash.parse()?;

        if schedule.keyword_due(&manifest.file_hash, now) {
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
            match runtime
                .dht
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
                Ok(stats) => {
                    accumulate_publish_stats(&mut keyword_totals, stats);
                    // Mark published only on a successful attempt, mirroring the
                    // master setting the next-publish time when the store search
                    // was actually started.
                    schedule.mark_keyword_published(&manifest.file_hash, now);
                    keyword_published += 1;
                }
                Err(error) => {
                    tracing::debug!(
                        file_hash = %manifest.file_hash,
                        name = manifest.canonical_name,
                        "Kad keyword publish failed: {error:#}"
                    );
                }
            }
        }

        if schedule.source_due(&manifest.file_hash, now) {
            let source_tags =
                build_source_publish_tags(bind_addr, source_publish_settings, manifest.file_size);
            match runtime
                .dht
                .publish_source_with_class_and_fanout(
                    file_hash,
                    source_publish_identity,
                    source_tags,
                    RpcWorkClass::Publish,
                    network.kad_publish_contact_fanout,
                )
                .await
            {
                Ok(stats) => {
                    accumulate_publish_stats(&mut source_totals, stats);
                    schedule.mark_source_published(&manifest.file_hash, now);
                    source_published += 1;
                }
                Err(error) => {
                    tracing::debug!(
                        file_hash = %manifest.file_hash,
                        name = manifest.canonical_name,
                        "Kad source publish failed: {error:#}"
                    );
                }
            }
        }

        // Notes (comment/rating) publish: only for files that actually carry a
        // user-set comment/rating, on the 24h notes interval (master
        // CKnownFile::PublishNotes + STORENOTES tags). Per-file gated like keyword
        // and source so an un-annotated file never emits a notes publish.
        if kad_publish_schedule::file_has_publishable_note(&manifest.comment, manifest.rating)
            && schedule.notes_due(&manifest.file_hash, now)
        {
            // Master STORENOTES taglist: FILENAME, FILERATING (>0 only),
            // DESCRIPTION (non-empty only), FILESIZE.
            let mut notes_tags = vec![Tag::filename(manifest.canonical_name.clone())];
            if manifest.rating > 0 {
                notes_tags.push(Tag::new_short(
                    emulebb_kad_proto::tag_name::FILERATING,
                    emulebb_kad_proto::TagValue::UInt(u64::from(manifest.rating)),
                ));
            }
            if !manifest.comment.is_empty() {
                notes_tags.push(Tag::new_short(
                    emulebb_kad_proto::tag_name::DESCRIPTION,
                    emulebb_kad_proto::TagValue::String(manifest.comment.clone()),
                ));
            }
            notes_tags.push(Tag::filesize(manifest.file_size));
            match runtime
                .dht
                .publish_notes_with_class_and_fanout(
                    file_hash,
                    notes_publisher_id,
                    notes_tags,
                    RpcWorkClass::Publish,
                    network.kad_publish_contact_fanout,
                )
                .await
            {
                Ok(stats) => {
                    accumulate_publish_stats(&mut notes_totals, stats);
                    schedule.mark_notes_published(&manifest.file_hash, now);
                    notes_published += 1;
                }
                Err(error) => {
                    tracing::debug!(
                        file_hash = %manifest.file_hash,
                        name = manifest.canonical_name,
                        "Kad notes publish failed: {error:#}"
                    );
                }
            }
        }
    }

    if keyword_published > 0 || source_published > 0 || notes_published > 0 {
        tracing::info!(
            "Kad shared-file publish cycle items={} keyword_published={} keyword_acked={} source_published={} source_acked={} notes_published={} notes_acked={}",
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
            // Oracle Process_KADEMLIA2_HELLO_REQ: a pre-v8 contact that was
            // added/updated without a valid receiver key supports no three-way
            // handshake, so verify its source IP with a legacy challenge
            // (v7 -> PING, <v7 -> REQ). send_legacy_challenge enforces the
            // one-challenge-per-IP guard and picks the opcode by version.
            if added_or_updated
                && !receiver_verify_key_valid
                && req.version < LEGACY_VERIFY_VERSION_THRESHOLD
            {
                if let Err(error) = dht
                    .send_legacy_challenge(req.node_id, req.version, from)
                    .await
                {
                    tracing::debug!(
                        "failed to send legacy Kad challenge to {from}: {error:#}"
                    );
                }
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
            if added_or_updated && !receiver_verify_key_valid && res.version < KAD_VERSION_7 {
                if let Err(error) = dht
                    .send_legacy_challenge(res.node_id, res.version, from)
                    .await
                {
                    tracing::debug!(
                        "failed to send legacy Kad challenge to {from}: {error:#}"
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
    set_hello_buddy_snapshot(Some(HelloBuddySnapshot { ip: buddy_ip, udp_port: from.port() }));
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
        crate::diag_sched::conn_budget(budget, context.file_hash_hex, &source);
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
        priority: "normal".to_string(),
        auto_upload_priority: false,
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
const ED2K_SOURCE_OBFUSCATION_REQUIRES_CRYPT: u8 = 0x04;

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
    use emulebb_ed2k::{NatConfig, ipfilter::IpFilter};
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
            kad_routing_maintenance_enabled: true,
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
            download_tasks: Arc::clone(&core.ed2k_download_tasks),
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
    fn kad_publish_tolerance_gate_matches_oracle_distance_and_lan_exemption() {
        use std::net::Ipv4Addr;
        let own = NodeId::ZERO;

        // Close target (chunk0 distance well under SEARCHTOLERANCE) -> accepted.
        let close = NodeId::from_be_bytes([
            0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert!(kad_publish_within_tolerance(
            own,
            close,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        ));

        // Far target (chunk0 distance > SEARCHTOLERANCE) from a public IP -> dropped.
        let far = NodeId::from_be_bytes([
            0x7F, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
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
        let tags = build_kad_hello_request_tags(41000, false, true, false, true);

        assert_eq!(
            tags,
            vec![Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05))]
        );
    }

    #[test]
    fn kad_hello_response_tags_include_source_udp_port_and_misc_bits() {
        let tags = build_kad_hello_response_tags(41000, true, true, true, true);

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
        assert!(build_kad_hello_response_tags(41000, false, false, false, false).is_empty());
        assert_eq!(
            build_kad_hello_response_tags(41000, true, false, false, false),
            vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))]
        );
        assert_eq!(
            build_kad_hello_response_tags(41000, false, true, false, true),
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

        let result = run_ed2k_direct_downloads(options, move |_bind_ip,
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
        })
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

    fn a4af_test_transfer(hash: &str, state_name: &str) -> Transfer {
        Transfer {
            hash: hash.to_string(),
            name: "file".to_string(),
            path: String::new(),
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
                state
                    .download_source_registry
                    .add_candidate(DownloadSourceCandidate {
                        file_hash: hash.clone(),
                        file_priority: priority,
                        needed_parts: 4,
                        rare_parts: 1,
                        source: source.clone(),
                    });
            }
        }

        let (a_sources, a_deferred) = core
            .acquire_direct_download_source_leases(&file_a, std::slice::from_ref(&source))
            .await;
        let (b_sources, b_deferred) = core
            .acquire_direct_download_source_leases(&file_b, std::slice::from_ref(&source))
            .await;

        // Engaged once (file A, the peer's best), deferred (NOT double-engaged)
        // for file B: one active relationship per peer, like eMule.
        assert_eq!(a_sources, vec![source.clone()]);
        assert_eq!(a_deferred, 0);
        assert!(b_sources.is_empty());
        assert_eq!(b_deferred, 1);

        // The peer holds exactly one active engagement across both files (no
        // double-engage / one relationship per peer).
        assert_eq!(core.state.lock().await.active_download_peer_endpoints.len(), 1);

        // After the peer is released, a fresh acquisition for the best file reuses
        // the same source rather than being permanently consumed.
        core.release_direct_download_source_leases(&[source_endpoint_key(&source)])
            .await;
        let (a_again, a_again_deferred) = core
            .acquire_direct_download_source_leases(&file_a, std::slice::from_ref(&source))
            .await;
        assert_eq!(a_again, vec![source.clone()]);
        assert_eq!(a_again_deferred, 0);
        core.release_direct_download_source_leases(&[source_endpoint_key(&source)])
            .await;
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
                state
                    .download_source_registry
                    .add_candidate(DownloadSourceCandidate {
                        file_hash: hash.clone(),
                        file_priority: 5,
                        needed_parts: 4,
                        rare_parts: 1,
                        source: source.clone(),
                    });
            }
        }

        let swapped = core
            .swap_no_needed_parts_sources(&current, std::slice::from_ref(&source))
            .await;
        assert_eq!(swapped, 1, "NNP source must be swapped to the other wanted file");
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
            state
                .download_source_registry
                .add_candidate(DownloadSourceCandidate {
                    file_hash: current.clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 1,
                    source: source.clone(),
                });
        }

        let swapped = core
            .swap_no_needed_parts_sources(&current, std::slice::from_ref(&source))
            .await;
        assert_eq!(swapped, 0, "NNP source with no other wanted file must not be swapped");
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
                state
                    .download_source_registry
                    .add_candidate(DownloadSourceCandidate {
                        file_hash: hash.clone(),
                        file_priority: 5,
                        needed_parts: 4,
                        rare_parts: 1,
                        source: source.clone(),
                    });
            }
        }

        let swapped = core
            .swap_no_needed_parts_sources(&current, std::slice::from_ref(&source))
            .await;
        assert_eq!(swapped, 0, "completed other file is not a valid swap target");
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
            source_type: 1,
            buddy_id: None,
            buddy_ip: None,
            buddy_port: 0,
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
            endpoints: vec![
                (Ipv4Addr::new(192, 168, 50, 2), 4662),
                (own_ip, own_port),
            ],
        };

        // (1) self by advertised public endpoint, (2) self by local bind endpoint,
        // (3) self by user-hash on a different endpoint, (4) a real foreign source.
        let mut self_by_endpoint = direct_test_source(file_hash, own_ip, own_port);
        self_by_endpoint.user_hash = None;
        let self_by_bind = direct_test_source(file_hash, Ipv4Addr::new(192, 168, 50, 2), 4662);
        let mut self_by_hash =
            direct_test_source(file_hash, Ipv4Addr::new(198, 51, 100, 9), 5000);
        self_by_hash.user_hash = Some(own_user_hash);
        let foreign = direct_test_source(file_hash, Ipv4Addr::new(198, 51, 100, 22), 4662);

        let mut sources = vec![self_by_endpoint, self_by_bind, self_by_hash, foreign.clone()];
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
