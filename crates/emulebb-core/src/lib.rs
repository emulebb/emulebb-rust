use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use emulebb_ed2k::{
    NatManager,
    config::Ed2kConfig,
    ed2k_server::{
        Ed2kFoundSource, Ed2kKeywordSearchOptions, Ed2kSearchFile, Ed2kServerLoopOptions,
        Ed2kServerSearchHandle, Ed2kServerState, Ed2kSourceSearchOptions,
        Ed2kUdpSourceSearchOptions, new_ed2k_server_search_channel,
        publish_shared_catalog_via_background_session, run_ed2k_server_loop,
        search_keyword_servers, search_keyword_via_background_session, search_source_servers,
        search_source_udp_servers, search_source_via_background_session,
    },
    ed2k_tcp::{
        Ed2kHelloIdentity, Ed2kListenerOptions, Ed2kPeerDownloadOptions, Ed2kPeerDownloadOutcome,
        Ed2kSecureIdent, download_file_from_peer, emule_connect_options, run_ed2k_listener,
    },
    ed2k_transfer::{
        ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kSourceHint, Ed2kTransferRuntime,
        Ed2kUploadQueueSnapshotEntry, Ed2kUploadSessionPhaseSnapshot, new_transfer_job,
    },
    kad_firewall::KadFirewallState,
};
use emulebb_index::{FileIndex, IndexedFile};
use emulebb_kad_dht::{DhtConfig, DhtNode};
use emulebb_kad_proto::Ed2kHash;
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
    task::JoinHandle,
};
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
#[serde(rename_all = "camelCase")]
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
}

/// One remembered ED2K peer source for a transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSource {
    pub hash: String,
    pub ip: String,
    pub tcp_port: u16,
    pub endpoint: String,
    pub user_hash: Option<String>,
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
    pub config: Ed2kConfig,
}

#[derive(Debug)]
struct CoreState {
    searches: HashMap<String, Search>,
    transfers: HashMap<String, Transfer>,
    servers: HashMap<String, ServerInfo>,
    server_overrides: HashMap<String, ServerUpdate>,
    disabled_servers: HashSet<String>,
    kad_running: bool,
}

struct Ed2kRuntime {
    search_handle: Ed2kServerSearchHandle,
    server_state: Arc<RwLock<Ed2kServerState>>,
    shutdown: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct EmulebbCore {
    started_at: Instant,
    version: String,
    index: Arc<Mutex<FileIndex>>,
    ed2k_transfers: Arc<Ed2kTransferRuntime>,
    ed2k_network: Option<Ed2kNetworkConfig>,
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
        let ed2k_transfers = Ed2kTransferRuntime::load_or_create(transfer_root.as_ref())?;
        Ok(Self {
            started_at: Instant::now(),
            version: version.into(),
            index: Arc::new(Mutex::new(index)),
            ed2k_transfers: Arc::new(ed2k_transfers),
            ed2k_network,
            ed2k_runtime: Arc::new(Mutex::new(None)),
            state: Arc::new(Mutex::new(CoreState {
                searches: HashMap::new(),
                transfers: HashMap::new(),
                servers: HashMap::new(),
                server_overrides: HashMap::new(),
                disabled_servers: HashSet::new(),
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
            kad: NetworkStatus {
                running: kad_running,
                connected: kad_running,
                peer_count: 0,
            },
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
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(network.kad_bind_addr),
            obfuscation_enabled: network.config.obfuscation_enabled,
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
        let mut tasks = Vec::new();
        tasks.push(dht.start());
        tasks.push(tokio::spawn(run_ed2k_listener(Ed2kListenerOptions {
            listener: ed2k_listener,
            dht,
            server_state: Arc::clone(&server_state),
            kad_firewall: Arc::clone(&kad_firewall),
            secure_ident: Arc::clone(&network.secure_ident),
            transfer_runtime: Arc::clone(&self.ed2k_transfers),
            hello_identity,
            shutdown: Arc::clone(&shutdown),
        })));
        tasks.push(tokio::spawn(run_ed2k_server_loop(Ed2kServerLoopOptions {
            bind_ip: network.bind_ip,
            nat: Arc::new(NatManager),
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
            shutdown,
            tasks,
        });
        drop(runtime_guard);
        Ok(self.ed2k_status().await)
    }

    pub async fn disconnect_ed2k(&self) -> NetworkStatus {
        if let Some(runtime) = self.ed2k_runtime.lock().await.take() {
            runtime.shutdown.store(true, Ordering::SeqCst);
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
        let state_name = transfer_create_state_name(request.paused);
        let links = transfer_create_links(request)?;
        let mut transfers = Vec::with_capacity(links.len());
        for link in links {
            let parsed = parse_ed2k_link(&link)?;
            transfers.push(
                self.upsert_transfer_from_parts(parsed.0, parsed.1, parsed.2, state_name)
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
        self.refresh_transfer_from_manifest(&summary.file_hash, "completed")
            .await?;
        if let Err(error) = self.publish_ed2k_shared_catalog().await {
            tracing::warn!("failed to refresh ED2K shared catalog advertisement: {error}");
        }
        Ok(local_share_from_summary(summary))
    }

    pub async fn shares(&self) -> Vec<LocalShare> {
        match self.ed2k_transfers.manifests().await {
            Ok(manifests) => manifests
                .into_iter()
                .filter(|manifest| manifest.completed)
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

    pub async fn transfer_sources(&self, hash: &str) -> Result<Option<Vec<TransferSource>>> {
        if self.transfer(hash).await.is_none() {
            return Ok(None);
        }
        let manifest = self.ed2k_transfers.manifest(hash).await?;
        Ok(Some(transfer_sources_from_manifest(&manifest)))
    }

    pub async fn pause_transfer(&self, hash: &str) -> Result<Option<Transfer>> {
        self.set_transfer_control_state(hash, "paused").await
    }

    pub async fn stop_transfer(&self, hash: &str) -> Result<Option<Transfer>> {
        self.set_transfer_control_state(hash, "stopped").await
    }

    pub async fn delete_transfer_files(&self, hash: &str) -> Result<Option<Transfer>> {
        let Some(transfer) = self.transfer(hash).await else {
            return Ok(None);
        };
        if !self.ed2k_transfers.delete_transfer_files(hash).await? {
            return Ok(None);
        }
        self.state.lock().await.transfers.remove(hash);
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
        let Some(mut transfer) = self.set_transfer_state(hash, "downloading").await else {
            return Ok(None);
        };
        if let Some(next_state) = self.run_ed2k_download_attempt(&transfer).await? {
            if let Some(updated) = self
                .refresh_transfer_from_manifest(hash, next_state)
                .await?
            {
                transfer = updated;
            }
        }
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
        let transfer = transfer_from_manifest(&manifest, state_name);
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
            let transfer = transfer_from_manifest(&manifest, &state_name);
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
        let transfer = transfer_from_manifest(&manifest, state_name);
        self.state
            .lock()
            .await
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
        let transfer = transfer_from_manifest(&manifest, state_name);
        self.state
            .lock()
            .await
            .transfers
            .insert(transfer.hash.clone(), transfer.clone());
        Ok(Some(transfer))
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
        sort_download_sources(&mut sources);
        let mut accepted_incomplete = false;
        let mut last_error = None;
        let hello_identity = self.ed2k_hello_identity(network);
        let timeout = Duration::from_secs(network.config.connect_timeout_secs.max(10));
        let max_peers = network.config.max_parallel_download_peers.max(1);
        for source in sources
            .iter()
            .filter(|source| source.is_direct_dialable())
            .take(max_peers)
        {
            match download_file_from_peer(Ed2kPeerDownloadOptions {
                bind_ip: network.bind_ip,
                peer: source,
                hello_identity,
                secure_ident: &network.secure_ident,
                transfer_runtime: self.ed2k_transfers.as_ref(),
                canonical_name: transfer.name.clone(),
                file_size: transfer.size_bytes,
                timeout,
            })
            .await
            {
                Ok(Ed2kPeerDownloadOutcome::Completed) => {
                    return Ok(Some("completed"));
                }
                Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete) => {
                    accepted_incomplete = true;
                }
                Err(error) => {
                    last_error = Some(error);
                }
            }
        }
        if accepted_incomplete {
            return Ok(Some("downloading"));
        }
        if let Some(error) = last_error {
            return Err(error).context("ED2K direct download did not complete");
        }
        Ok(Some("queued"))
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
                };
            };
            Arc::clone(&runtime.server_state)
        };
        let state = server_state.read().await;
        NetworkStatus {
            running: true,
            connected: state.connected,
            peer_count: u32::from(state.connected),
        }
    }
}

impl fmt::Debug for EmulebbCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmulebbCore")
            .field("started_at", &self.started_at)
            .field("version", &self.version)
            .field("ed2k_network_configured", &self.ed2k_network.is_some())
            .finish_non_exhaustive()
    }
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
    }
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

fn transfer_sources_from_manifest(manifest: &Ed2kResumeManifest) -> Vec<TransferSource> {
    manifest
        .sources
        .iter()
        .map(|source| TransferSource {
            hash: manifest.file_hash.clone(),
            endpoint: format!("{}:{}", source.ip, source.tcp_port),
            ip: source.ip.clone(),
            tcp_port: source.tcp_port,
            user_hash: source.user_hash.clone(),
            status: "remembered".to_string(),
        })
        .collect()
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

fn merge_download_sources(target: &mut Vec<Ed2kFoundSource>, incoming: Vec<Ed2kFoundSource>) {
    let mut seen =
        target
            .iter()
            .map(source_key)
            .collect::<HashSet<(Ipv4Addr, u16, Option<[u8; 16]>, Option<u8>)>>();
    for source in incoming {
        if seen.insert(source_key(&source)) {
            target.push(source);
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
    }
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

    use super::*;

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
