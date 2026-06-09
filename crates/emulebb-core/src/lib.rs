use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use emulebb_ed2k::{
    config::Ed2kConfig,
    ed2k_server::{
        Ed2kFoundSource, Ed2kKeywordSearchOptions, Ed2kSearchFile, Ed2kSourceSearchOptions,
        Ed2kUdpSourceSearchOptions, search_keyword_servers, search_source_servers,
        search_source_udp_servers,
    },
    ed2k_tcp::{
        Ed2kHelloIdentity, Ed2kPeerDownloadOptions, Ed2kPeerDownloadOutcome, Ed2kSecureIdent,
        download_file_from_peer, emule_connect_options,
    },
    ed2k_transfer::{Ed2kResumeManifest, Ed2kTransferRuntime, Ed2kTransferState, new_transfer_job},
};
use emulebb_index::{FileIndex, IndexedFile};
use emulebb_kad_proto::Ed2kHash;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
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

#[derive(Debug, Clone)]
pub struct Ed2kNetworkConfig {
    pub bind_ip: Ipv4Addr,
    pub user_hash: [u8; 16],
    pub secure_ident: Arc<Ed2kSecureIdent>,
    pub config: Ed2kConfig,
}

#[derive(Debug)]
struct CoreState {
    searches: HashMap<String, Search>,
    transfers: HashMap<String, Transfer>,
    kad_running: bool,
    ed2k_connected: bool,
}

#[derive(Debug, Clone)]
pub struct EmulebbCore {
    started_at: Instant,
    version: String,
    index: Arc<Mutex<FileIndex>>,
    ed2k_transfers: Arc<Ed2kTransferRuntime>,
    ed2k_network: Option<Ed2kNetworkConfig>,
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
            state: Arc::new(Mutex::new(CoreState {
                searches: HashMap::new(),
                transfers: HashMap::new(),
                kad_running: false,
                ed2k_connected: false,
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
                "indexing.localFts".to_string(),
            ],
        }
    }

    pub async fn status(&self) -> Status {
        let state = self.state.lock().await;
        let completed = state
            .transfers
            .values()
            .filter(|transfer| transfer.state == "completed")
            .count();
        Status {
            lifecycle: AppLifecycle {
                state: "running".to_string(),
            },
            uptime_secs: self.started_at.elapsed().as_secs(),
            kad: NetworkStatus {
                running: state.kad_running,
                connected: state.kad_running,
                peer_count: 0,
            },
            ed2k: NetworkStatus {
                running: state.ed2k_connected,
                connected: state.ed2k_connected,
                peer_count: 0,
            },
            indexing: IndexingStatus {
                enabled: true,
                backend: "sqlite-fts5".to_string(),
            },
            transfers: TransferStats {
                active: state.transfers.len().saturating_sub(completed),
                completed,
            },
        }
    }

    pub async fn set_kad_running(&self, running: bool) {
        self.state.lock().await.kad_running = running;
    }

    pub async fn set_ed2k_connected(&self, connected: bool) {
        self.state.lock().await.ed2k_connected = connected;
    }

    pub async fn servers(&self) -> Vec<ServerInfo> {
        let connected = self.state.lock().await.ed2k_connected;
        let Some(network) = self.ed2k_network.as_ref() else {
            return Vec::new();
        };
        let mut servers = network
            .config
            .server_entries
            .iter()
            .map(|entry| ServerInfo {
                endpoint: format!("{}:{}", entry.host, entry.port),
                name: entry.name.clone(),
                description: entry.description.clone(),
                connected,
            })
            .collect::<Vec<_>>();
        servers.extend(
            network
                .config
                .server_endpoints
                .iter()
                .map(|endpoint| ServerInfo {
                    endpoint: endpoint.clone(),
                    name: None,
                    description: None,
                    connected,
                }),
        );
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
        self.state
            .lock()
            .await
            .transfers
            .values()
            .cloned()
            .collect()
    }

    pub async fn transfer(&self, hash: &str) -> Option<Transfer> {
        self.state.lock().await.transfers.get(hash).cloned()
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
            if let Some(updated) = self.set_transfer_state(hash, next_state).await {
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
        let hello_identity = Ed2kHelloIdentity {
            user_hash: network.user_hash,
            client_id: 0,
            tcp_port: network.config.listen_port,
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
        Ok(sources)
    }

    fn ed2k_hello_identity(&self, network: &Ed2kNetworkConfig) -> Ed2kHelloIdentity {
        Ed2kHelloIdentity {
            user_hash: network.user_hash,
            client_id: 0,
            tcp_port: network.config.listen_port,
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(network.config.obfuscation_enabled),
            direct_udp_callback: false,
        }
    }
}

fn transfer_from_manifest(manifest: &Ed2kResumeManifest, state_name: &str) -> Transfer {
    let completed_bytes = manifest
        .pieces
        .iter()
        .map(|piece| match piece.state {
            Ed2kTransferState::Verified | Ed2kTransferState::Written => manifest.piece_size,
            Ed2kTransferState::Requested | Ed2kTransferState::Missing => piece.bytes_written,
        })
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
}
