use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
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
    ed2k_transfer::{Ed2kResumeManifest, Ed2kTransferRuntime, new_transfer_job},
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
    pub endpoint: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub connected: bool,
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
#[serde(rename_all = "camelCase")]
pub struct TransferCreate {
    pub ed2k_link: Option<String>,
    pub hash: Option<String>,
    pub name: Option<String>,
    pub size_bytes: Option<u64>,
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
        let Some(network) = self.ed2k_network.clone() else {
            anyhow::bail!("ED2K network is not configured");
        };
        if network.config.server_entries.is_empty() && network.config.server_endpoints.is_empty() {
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
            config: network.config.clone(),
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
        let Some(network) = self.ed2k_network.as_ref() else {
            return Vec::new();
        };
        let connected_endpoint = self.ed2k_connected_endpoint().await;
        let mut servers = network
            .config
            .server_entries
            .iter()
            .map(|entry| ServerInfo {
                endpoint: format!("{}:{}", entry.host, entry.port),
                name: entry.name.clone(),
                description: entry.description.clone(),
                connected: connected_endpoint
                    .as_deref()
                    .is_some_and(|endpoint| endpoint == format!("{}:{}", entry.host, entry.port)),
            })
            .collect::<Vec<_>>();
        servers.extend(network.config.server_endpoints.iter().map(|endpoint| {
            ServerInfo {
                endpoint: endpoint.clone(),
                name: None,
                description: None,
                connected: connected_endpoint
                    .as_deref()
                    .is_some_and(|connected| connected == endpoint),
            }
        }));
        servers
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
    ) -> Result<Option<Transfer>> {
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
        self.upsert_transfer_from_parts(result.hash, result.name, result.size_bytes, "queued")
            .await
            .map(Some)
    }

    pub async fn create_transfer(&self, request: TransferCreate) -> Result<Transfer> {
        if let Some(link) = request.ed2k_link {
            let parsed = parse_ed2k_link(&link)?;
            return Ok(self
                .upsert_transfer_from_parts(parsed.0, parsed.1, parsed.2, "queued")
                .await?);
        }
        let hash = request
            .hash
            .ok_or_else(|| anyhow::anyhow!("transfer hash or ed2kLink is required"))?;
        let name = request.name.unwrap_or_else(|| hash.clone());
        let size_bytes = request.size_bytes.unwrap_or(0);
        Ok(self
            .upsert_transfer_from_parts(hash, name, size_bytes, "queued")
            .await?)
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
        let catalog = self.ed2k_transfers.shared_catalog();
        catalog
            .read()
            .await
            .iter()
            .filter(|entry| entry.verified_complete && !entry.compatibility_hint)
            .map(|entry| LocalShare {
                hash: entry.file_hash.clone(),
                name: entry.canonical_name.clone(),
                size_bytes: entry.file_size,
                ed2k_link: format!(
                    "ed2k://|file|{}|{}|{}|/",
                    entry.canonical_name, entry.file_size, entry.file_hash
                ),
                aich_root: entry.aich_root.clone().unwrap_or_default(),
                transfer_dir: String::new(),
            })
            .collect()
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

    pub async fn set_transfer_state(&self, hash: &str, state_name: &str) -> Option<Transfer> {
        let mut state = self.state.lock().await;
        let transfer = state.transfers.get_mut(hash)?;
        transfer.state = state_name.to_string();
        Some(transfer.clone())
    }

    pub async fn resume_transfer(&self, hash: &str) -> Result<Option<Transfer>> {
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

    async fn upsert_transfer_from_parts(
        &self,
        hash: String,
        name: String,
        size_bytes: u64,
        state_name: &str,
    ) -> Result<Transfer> {
        let file_hash = hash.parse()?;
        let job = new_transfer_job(file_hash, name, size_bytes);
        let manifest = self.ed2k_transfers.ensure_job(&job).await?;
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
        if network.config.server_entries.is_empty() && network.config.server_endpoints.is_empty() {
            return Ok(None);
        }

        let cancel = CancellationToken::new();
        if let Some(handle) = self.connected_ed2k_search_handle().await {
            let timeout = Duration::from_secs(network.config.connect_timeout_secs.max(15));
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
            connect_options: emule_connect_options(network.config.obfuscation_enabled),
            direct_udp_callback: false,
        };
        let shared_catalog = self.ed2k_transfers.shared_catalog();
        let shared_catalog_snapshot = shared_catalog.read().await.clone();
        let max_attempts = network.config.keyword_server_attempt_budget.max(1).min(
            network
                .config
                .server_entries
                .len()
                .max(network.config.server_endpoints.len())
                .max(1),
        );
        let files = search_keyword_servers(Ed2kKeywordSearchOptions {
            bind_ip: network.bind_ip,
            config: &network.config,
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
            self.ed2k_transfers
                .remember_source(
                    &file_hash.to_string(),
                    emulebb_ed2k::ed2k_transfer::Ed2kSourceHint {
                        ip: source.ip.to_string(),
                        tcp_port: source.tcp_port,
                        user_hash: source.user_hash.map(hex::encode),
                    },
                )
                .await?;
        }
        Ok(())
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
    } else if manifest.pieces.iter().any(|piece| piece.bytes_written != 0) {
        "downloading"
    } else {
        "queued"
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
        aich_root: summary.aich_root,
        transfer_dir: summary.transfer_dir,
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
            .download_search_result(&search.id, "00112233445566778899aabbccddeeff")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(transfer.state, "queued");
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
}
