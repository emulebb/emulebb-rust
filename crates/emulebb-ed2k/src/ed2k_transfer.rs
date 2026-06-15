//! Native ED2K transfer runtime state for piece-store persistence and
//! transfer-backed shared-file serving.
//!
//! This module does not yet implement the full downloader scheduler, but it
//! establishes the durable storage and shared-catalog boundary the rest of the
//! runtime can build on:
//! - resumable per-download manifests
//! - deterministic piece-store payload paths
//! - transfer job bookkeeping
//! - verified local file exposure for upload serving
//! - compatibility catalog hints for server-side `OP_OFFERFILES`

use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex, atomic::AtomicU64},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use emulebb_metadata::MetadataStore;
use tokio::sync::{Mutex, RwLock};

use crate::config::{Ed2kConfig, Ed2kUploadQueuePolicyConfig};

mod callback;
mod catalog;
mod download_activity;
mod hashset;
mod ingest;
mod manifest;
mod metadata;
mod model;
mod piece_store;
mod reask_reciprocity;
mod shared_catalog;
mod store;
mod transfer_sql;
mod upload;
mod upload_queue;

pub use catalog::{Ed2kSharedCatalog, Ed2kSharedEntry, Ed2kSharedRange};
pub use download_activity::Ed2kLiveSource;
use download_activity::{Ed2kDownloadActivity, Ed2kSourceActivity};
#[cfg(test)]
use hashset::build_aich_hashset_from_payload;
pub(crate) use hashset::decode_aich_hash_hex;
use manifest::Ed2kManifestCheckpointState;
pub(crate) use manifest::expected_piece_length;
pub use manifest::new_transfer_job;
pub(crate) use model::{Ed2kAichHashset, Ed2kClaimedPart};
pub use model::{
    Ed2kCallbackIntent, Ed2kLocalIngestSummary, Ed2kPieceState, Ed2kResumeManifest, Ed2kSourceHint,
    Ed2kTransferJob, Ed2kTransferState,
};
use upload_queue::Ed2kUploadQueueState;
pub(crate) use upload_queue::{
    Ed2kUploadPeerIdentity, Ed2kUploadQueueConfig, Ed2kUploadSessionHandle, Ed2kUploadSessionStatus,
};
pub use upload_queue::{Ed2kUploadQueueCapacitySnapshot, Ed2kUploadThrottleReservation};
pub use upload_queue::{Ed2kUploadQueueSnapshotEntry, Ed2kUploadSessionPhaseSnapshot};

/// Canonical ED2K part size used by eMule-compatible file hashing.
pub const ED2K_PART_SIZE: u64 = 9_728_000;
/// Canonical eMule upload block size used inside one ED2K part request.
pub(crate) const ED2K_EMBLOCK_SIZE: u64 = 184_320;
const PAYLOAD_FILE_NAME: &str = "pieces.bin";
const SOURCE_EXCHANGE_REASK_INTERVAL: Duration = Duration::from_secs(40 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SourceExchangeRequestKey {
    file_hash: String,
    peer_addr: SocketAddr,
    user_hash: Option<[u8; 16]>,
}

/// Runtime owner for ED2K transfer manifests, piece-store payloads, and the
/// transfer-backed shared catalog.
#[derive(Debug)]
pub struct Ed2kTransferRuntime {
    root_dir: PathBuf,
    metadata: MetadataStore,
    shared_catalog: Ed2kSharedCatalog,
    callback_intents: Arc<RwLock<Vec<Ed2kCallbackIntent>>>,
    manifest_io: Arc<Mutex<()>>,
    manifest_cache: Arc<Mutex<HashMap<String, Ed2kResumeManifest>>>,
    manifest_checkpoint_state: Arc<Mutex<HashMap<String, Ed2kManifestCheckpointState>>>,
    source_exchange_requests: Arc<Mutex<HashMap<SourceExchangeRequestKey, Instant>>>,
    download_activity: Arc<StdMutex<HashMap<String, Ed2kDownloadActivity>>>,
    /// Live per-source download state keyed by file hash -> peer endpoint, used
    /// to surface sourcesTransferring/partsAvailable and live transfer-source
    /// detail. In-memory only (live session state, never persisted).
    download_sources: Arc<StdMutex<HashMap<String, HashMap<String, Ed2kSourceActivity>>>>,
    upload_queue: Arc<Mutex<Ed2kUploadQueueState>>,
    next_upload_connection_id: AtomicU64,
}

impl Ed2kTransferRuntime {
    /// Load any persisted transfer manifests and create the runtime root if it
    /// does not exist yet.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn load_or_create(root_dir: &Path) -> Result<Self> {
        fs::create_dir_all(root_dir).with_context(|| {
            format!("failed to create ED2K transfer root {}", root_dir.display())
        })?;
        let metadata = MetadataStore::open(root_dir.join("metadata.sqlite"))?;
        Self::load_or_create_with_metadata(root_dir, metadata)
    }

    pub fn load_or_create_with_metadata(root_dir: &Path, metadata: MetadataStore) -> Result<Self> {
        Self::load_or_create_with_metadata_and_upload_queue(
            root_dir,
            metadata,
            Ed2kUploadQueueConfig::default(),
        )
    }

    /// Load transfer state using the ED2K runtime policy supplied by the daemon/core config.
    pub fn load_or_create_with_metadata_and_config(
        root_dir: &Path,
        metadata: MetadataStore,
        config: &Ed2kConfig,
    ) -> Result<Self> {
        Self::load_or_create_with_metadata_and_upload_queue(
            root_dir,
            metadata,
            upload_queue_config_from_policy(&config.upload_queue),
        )
    }

    /// Load any persisted transfer manifests with an explicit inbound upload
    /// queue policy and create the runtime root if it does not exist yet.
    pub(crate) fn load_or_create_with_upload_queue(
        root_dir: &Path,
        upload_queue_config: Ed2kUploadQueueConfig,
    ) -> Result<Self> {
        fs::create_dir_all(root_dir).with_context(|| {
            format!("failed to create ED2K transfer root {}", root_dir.display())
        })?;
        let metadata = MetadataStore::open(root_dir.join("metadata.sqlite"))?;
        Self::load_or_create_with_metadata_and_upload_queue(root_dir, metadata, upload_queue_config)
    }

    pub(crate) fn load_or_create_with_metadata_and_upload_queue(
        root_dir: &Path,
        metadata: MetadataStore,
        upload_queue_config: Ed2kUploadQueueConfig,
    ) -> Result<Self> {
        fs::create_dir_all(root_dir).with_context(|| {
            format!("failed to create ED2K transfer root {}", root_dir.display())
        })?;
        let shared_catalog = Arc::new(RwLock::new(transfer_sql::completed_catalog_from_metadata(
            metadata.transfer_manifests()?,
        )?));
        Ok(Self {
            root_dir: root_dir.to_path_buf(),
            metadata,
            shared_catalog,
            callback_intents: Arc::new(RwLock::new(Vec::new())),
            manifest_io: Arc::new(Mutex::new(())),
            manifest_cache: Arc::new(Mutex::new(HashMap::new())),
            manifest_checkpoint_state: Arc::new(Mutex::new(HashMap::new())),
            source_exchange_requests: Arc::new(Mutex::new(HashMap::new())),
            download_activity: Arc::new(StdMutex::new(HashMap::new())),
            download_sources: Arc::new(StdMutex::new(HashMap::new())),
            upload_queue: Arc::new(Mutex::new(Ed2kUploadQueueState::new(upload_queue_config))),
            next_upload_connection_id: AtomicU64::new(1),
        })
    }

    pub(crate) async fn should_request_source_exchange(
        &self,
        file_hash: &str,
        peer_addr: SocketAddr,
        user_hash: Option<[u8; 16]>,
        now: Instant,
    ) -> bool {
        let key = SourceExchangeRequestKey {
            file_hash: file_hash.to_string(),
            peer_addr,
            user_hash,
        };
        let mut requests = self.source_exchange_requests.lock().await;
        let allowed = requests.get(&key).is_none_or(|last_requested| {
            now.duration_since(*last_requested) > SOURCE_EXCHANGE_REASK_INTERVAL
        });
        if allowed {
            requests.insert(key, now);
        }
        allowed
    }
}

pub(super) fn upload_queue_config_from_policy(
    policy: &Ed2kUploadQueuePolicyConfig,
) -> Ed2kUploadQueueConfig {
    Ed2kUploadQueueConfig {
        active_slots: policy.active_slots.max(1),
        elastic_percent: policy.elastic_percent.min(100),
        upload_limit_bytes_per_sec: policy.upload_limit_bytes_per_sec,
        elastic_underfill_bytes_per_sec: policy.elastic_underfill_bytes_per_sec,
        elastic_underfill: Duration::from_secs(policy.elastic_underfill_secs.max(1)),
        waiting_capacity: policy.waiting_capacity,
        waiting_timeout: Duration::from_secs(policy.waiting_timeout_secs.max(1)),
        granted_timeout: Duration::from_secs(policy.granted_timeout_secs.max(1)),
        upload_timeout: Duration::from_secs(policy.upload_timeout_secs.max(1)),
    }
}

pub(super) fn upload_queue_policy_from_config(
    config: Ed2kUploadQueueConfig,
) -> Ed2kUploadQueuePolicyConfig {
    Ed2kUploadQueuePolicyConfig {
        active_slots: config.active_slots,
        elastic_percent: config.elastic_percent,
        upload_limit_bytes_per_sec: config.upload_limit_bytes_per_sec,
        elastic_underfill_bytes_per_sec: config.elastic_underfill_bytes_per_sec,
        elastic_underfill_secs: config.elastic_underfill.as_secs(),
        waiting_capacity: config.waiting_capacity,
        waiting_timeout_secs: config.waiting_timeout.as_secs(),
        granted_timeout_secs: config.granted_timeout.as_secs(),
        upload_timeout_secs: config.upload_timeout.as_secs(),
    }
}

#[cfg(test)]
mod tests;
