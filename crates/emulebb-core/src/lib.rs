use std::{collections::HashMap, sync::Arc, time::Instant};

use anyhow::Result;
use chrono::{DateTime, Utc};
use emulebb_index::{FileIndex, IndexedFile};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
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
    state: Arc<Mutex<CoreState>>,
}

impl EmulebbCore {
    pub fn new(version: impl Into<String>, index: FileIndex) -> Self {
        Self {
            started_at: Instant::now(),
            version: version.into(),
            index: Arc::new(Mutex::new(index)),
            state: Arc::new(Mutex::new(CoreState {
                searches: HashMap::new(),
                transfers: HashMap::new(),
                kad_running: false,
                ed2k_connected: false,
            })),
        }
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

    pub async fn create_search(&self, request: SearchCreate) -> Result<Search> {
        let search_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let indexed = self.index.lock().await.search(&request.query, 200)?;
        let results = indexed
            .into_iter()
            .map(|file| search_result_from_indexed(&search_id, &request, file))
            .collect();
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
        Ok(Some(
            self.upsert_transfer_from_parts(
                result.hash,
                result.name,
                result.size_bytes,
                0,
                "queued",
            )
            .await,
        ))
    }

    pub async fn create_transfer(&self, request: TransferCreate) -> Result<Transfer> {
        if let Some(link) = request.ed2k_link {
            let parsed = parse_ed2k_link(&link)?;
            return Ok(self
                .upsert_transfer_from_parts(parsed.0, parsed.1, parsed.2, 0, "queued")
                .await);
        }
        let hash = request
            .hash
            .ok_or_else(|| anyhow::anyhow!("transfer hash or ed2kLink is required"))?;
        let name = request.name.unwrap_or_else(|| hash.clone());
        let size_bytes = request.size_bytes.unwrap_or(0);
        Ok(self
            .upsert_transfer_from_parts(hash, name, size_bytes, 0, "queued")
            .await)
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

    pub async fn index_file(&self, file: IndexedFile) -> Result<()> {
        self.index.lock().await.upsert_file(&file)
    }

    async fn upsert_transfer_from_parts(
        &self,
        hash: String,
        name: String,
        size_bytes: u64,
        completed_bytes: u64,
        state_name: &str,
    ) -> Transfer {
        let progress = if size_bytes == 0 {
            0.0
        } else {
            completed_bytes as f64 / size_bytes as f64
        };
        let transfer = Transfer {
            ed2k_link: format!("ed2k://|file|{}|{}|{}|/", name, size_bytes, hash),
            hash: hash.clone(),
            name,
            path: String::new(),
            size_bytes,
            completed_bytes,
            state: state_name.to_string(),
            progress,
            sources: 0,
            download_speed_bytes_per_sec: 0,
        };
        self.state
            .lock()
            .await
            .transfers
            .insert(hash, transfer.clone());
        transfer
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

#[cfg(test)]
mod tests {
    use emulebb_index::IndexedFile;

    use super::*;

    #[tokio::test]
    async fn search_uses_local_index() {
        let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap());
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
        let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap());
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
