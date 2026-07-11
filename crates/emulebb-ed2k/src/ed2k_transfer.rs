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
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use emulebb_metadata::MetadataStore;
use tokio::sync::{Mutex, Notify, RwLock};

use crate::config::{Ed2kConfig, Ed2kUploadQueuePolicyConfig};

mod aich_recovery;
mod aich_tree;
mod aich_trust;
mod block_bitmap;
mod callback;
mod catalog;
mod corruption_blackbox;
mod credit_ledger;
mod deliver;
pub(crate) mod diag_bad_peer;
pub(crate) mod diag_sched;
mod download_activity;
mod download_coordinator;
mod download_pick;
mod download_throttle;
mod hashset;
mod ich_salvage;
mod inbound_admission;
mod ingest;
mod manifest;
mod metadata;
mod model;
mod piece_store;
mod reask_reciprocity;
mod reload_index;
mod requested_block;
mod salvage;
mod shared_catalog;
mod source_exchange;
mod store;
mod transfer_sql;
mod upload;
mod upload_cooldown;
mod upload_queue;

pub use catalog::{Ed2kSharedCatalog, Ed2kSharedEntry, Ed2kSharedRange, IndexedSharedCatalog};
pub use deliver::Ed2kDeliveryOutcome;
pub use download_activity::Ed2kLiveSource;
use download_activity::{Ed2kDownloadActivity, Ed2kSourceActivity};
use download_coordinator::{
    DEFAULT_CONNECTION_WINDOW, DEFAULT_REASK_PACING_INTERVAL, Ed2kDownloadCoordinator,
};
pub use download_coordinator::{Ed2kDownloadCoordinatorConfig, MAX_SOURCES_FILE_UDP};
use download_throttle::Ed2kDownloadThrottle;
pub use download_throttle::Ed2kDownloadThrottleReservation;
#[cfg(test)]
use hashset::build_aich_hashset_from_payload;
pub(crate) use hashset::decode_aich_hash_hex;
pub use inbound_admission::Ed2kInboundConnectionGuard;
use manifest::Ed2kManifestCheckpointState;
pub(crate) use manifest::expected_piece_length;
pub use manifest::new_transfer_job;
pub(crate) use model::{Ed2kAichHashset, Ed2kClaimedPart, PieceWriteOutcome};
pub use model::{
    Ed2kCallbackIntent, Ed2kLocalIngestSummary, Ed2kPieceState, Ed2kReloadIndexEntry,
    Ed2kResumeManifest, Ed2kSourceHint, Ed2kTransferJob, Ed2kTransferState,
};
pub(crate) use piece_store::Ed2kVerifiedRangeReader;
use source_exchange::SourceExchangeState;
use upload_queue::DEFAULT_SOFT_QUEUE_SIZE;
use upload_queue::Ed2kUploadQueueState;
pub(crate) use upload_queue::is_low_id_client_id;
pub(crate) use upload_queue::{
    Ed2kUploadFirewallContext, Ed2kUploadPeerIdentity, Ed2kUploadPendingPromotion,
    Ed2kUploadQueueConfig, Ed2kUploadRangeAdmission, Ed2kUploadSessionHandle,
    Ed2kUploadSessionStatus,
};
pub use upload_queue::{Ed2kUploadQueueCapacitySnapshot, Ed2kUploadThrottleReservation};
pub use upload_queue::{Ed2kUploadQueueSnapshotEntry, Ed2kUploadSessionPhaseSnapshot};

/// Outcome of a global connection-budget acquisition attempt, carrying the
/// occupancy + binding cap so the caller can emit the `conn_budget`
/// `diag_event_v1` event (uniform-diagnostics-v2 schema §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed2kConnectionBudgetDecision {
    /// Whether a budget slot was granted (`outcome` admit vs deny).
    pub admitted: bool,
    /// Live concurrent source-connection count after the decision.
    pub active_connections: usize,
    /// Configured concurrent-connection cap (0 = unlimited).
    pub connection_cap: usize,
    /// Which cap denied the slot, when `admitted` is false.
    pub deny_reason: Option<Ed2kConnectionBudgetDenyReason>,
}

/// Why a connection-budget slot was denied (`denyReason`, schema §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed2kConnectionBudgetDenyReason {
    /// The concurrent-connection cap was full (`concurrent_cap`).
    ConcurrentCap,
    /// The per-window new-connection rate was exhausted (`window_cap`).
    WindowCap,
}

impl Ed2kConnectionBudgetDenyReason {
    /// Stable wire token for the `denyReason` field.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConcurrentCap => "concurrent_cap",
            Self::WindowCap => "window_cap",
        }
    }
}

/// Canonical ED2K part size used by eMule-compatible file hashing.
pub const ED2K_PART_SIZE: u64 = 9_728_000;

/// Part count used by OP_FILESTATUS / the OP_REQUESTFILENAME ext-info
/// partstatus, i.e. eMule's `CKnownFile::m_iED2KPartCount`. This is
/// `size / PARTSIZE + 1` for non-empty files (KnownFile.cpp:769), one MORE
/// than the data-part count at exact PARTSIZE multiples: the trailing extra
/// part is the zero-length EOF slice eMule always treats complete. Empty files
/// map to 0 (the complete-file sentinel domain). NOTE: this is NOT the data /
/// MD4-hashing part count (`size.div_ceil(PARTSIZE)`); use `div_ceil` for piece
/// geometry and hashing, and this for every wire partstatus count/length.
#[must_use]
pub fn ed2k_part_count(file_size: u64) -> u16 {
    if file_size == 0 {
        return 0;
    }
    u16::try_from(file_size / ED2K_PART_SIZE + 1).unwrap_or(u16::MAX)
}
/// Canonical eMule upload block size used inside one ED2K part request.
pub(crate) const ED2K_EMBLOCK_SIZE: u64 = 184_320;
const PAYLOAD_FILE_NAME: &str = "pieces.bin";

/// Cross-connection same-file upload-churn ledger: `(peer key, file hash) ->
/// (repeat count, first-seen)`, bounded and window-pruned for MFC
/// `repeat_file_request` parity (observe-only).
type UploadFileChurnLedger = Arc<StdMutex<HashMap<(String, String), (u32, Instant)>>>;

/// Runtime owner for ED2K transfer manifests, piece-store payloads, and the
/// transfer-backed shared catalog.
#[derive(Debug)]
pub struct Ed2kTransferRuntime {
    root_dir: PathBuf,
    metadata: MetadataStore,
    shared_catalog: Ed2kSharedCatalog,
    callback_intents: Arc<RwLock<Vec<Ed2kCallbackIntent>>>,
    /// Per-file-hash manifest IO locks (see [`Self::lock_manifest`]). Manifest
    /// state is keyed by one file hash everywhere, so transfers only serialize
    /// against themselves; a single global lock here used to serialize every
    /// block append of every concurrent download (and upload reader opens)
    /// behind one mutex.
    manifest_locks: Arc<StdMutex<HashMap<String, Arc<Mutex<()>>>>>,
    manifest_cache: Arc<Mutex<HashMap<String, Ed2kResumeManifest>>>,
    manifest_checkpoint_state: Arc<Mutex<HashMap<String, Ed2kManifestCheckpointState>>>,
    /// Cached read+write payload handles, one per transfer with active piece
    /// writes, so the per-block download path does not re-open the piece
    /// store (a CreateFileW + blocking-pool hop) for every received block.
    /// Take/store runs under the transfer's manifest IO lock, so a handle
    /// never has two concurrent users; the entry is dropped before payload
    /// deletion so a pending handle cannot leave the transfer directory
    /// undeletable on Windows. A `std` Mutex held only for instant map ops,
    /// never across an `.await`.
    payload_handles: Arc<StdMutex<HashMap<String, tokio::fs::File>>>,
    source_exchange: SourceExchangeState,
    /// Per-file accumulator of network-proposed AICH roots and their distinct
    /// proposing IPs. A network-learned root is only promoted to the
    /// salvage-authorizing `manifest.aich_root` once it clears the master's
    /// `MINUNIQUEIPS_TOTRUST`/`MINPERCENTAGE_TOTRUST` corroboration gate. The
    /// signer set lives here (in-memory, live session state, never persisted);
    /// the durable trust decision is the promoted `manifest.aich_root`.
    aich_root_corroboration: Arc<StdMutex<HashMap<String, aich_trust::AichRootCorroboration>>>,
    download_activity: Arc<StdMutex<HashMap<String, Ed2kDownloadActivity>>>,
    /// Live per-source download state keyed by file hash -> peer endpoint, used
    /// to surface sourcesTransferring/partsAvailable and live transfer-source
    /// detail. In-memory only (live session state, never persisted).
    download_sources: Arc<StdMutex<HashMap<String, HashMap<String, Ed2kSourceActivity>>>>,
    /// Cross-connection same-file upload-churn ledger keyed by (peer key, file
    /// hash) -> (count, first-seen) for MFC repeat_file_request parity. Bounded and
    /// window-pruned; observe-only.
    upload_file_churn: UploadFileChurnLedger,
    /// Per-file accumulator of served-upload bytes still awaiting a shared-catalog
    /// demand-counter flush (RUST-PAR-025 Note-1), keyed by file-hash hex. The
    /// per-fragment catalog credit uses a NON-blocking `try_write` so a busy
    /// catalog write lock (e.g. a publish-rank build holding the read lock) can
    /// never stall the upload hot path (preserving the REST-starvation fix). When
    /// that `try_write` cannot be taken the fragment's bytes are parked here
    /// instead of being dropped, and the WHOLE parked amount is flushed on the
    /// next successful `try_write` (per fragment) and unconditionally at session
    /// release -- so the demand counter under-counts no served byte while the hot
    /// path stays non-blocking. A tiny `std` Mutex held only for instant map ops
    /// plus a non-blocking catalog `try_write`; never held across an `.await`.
    pending_catalog_upload: Arc<StdMutex<HashMap<String, u64>>>,
    /// Parked peer-credit / file all-time-uploaded deltas awaiting the batched
    /// SQLite flush (see `credit_ledger`): the per-fragment/per-block credit
    /// commits (each a WAL fsync) are parked here instead, matching eMule's
    /// in-memory CClientCredits/CKnownFile counters with periodic
    /// clients.met/known.met saves. Queue-scoring reads go read-through over
    /// this ledger, so scores never lag the parking.
    parked_credit: Arc<parking_lot::Mutex<credit_ledger::ParkedCreditLedger>>,
    /// Serializes ledger drain+commit with credit writes needing a settled
    /// ledger (secure-ident wipe, absolute totals seed) — see `credit_ledger`.
    credit_flush_gate: Arc<parking_lot::Mutex<()>>,
    upload_queue: Arc<Mutex<Ed2kUploadQueueState>>,
    /// Shared cross-transfer download-rate limiter (token bucket). One per
    /// runtime, consulted by every download task before it consumes a received
    /// block so the aggregate inbound payload respects the global cap (eMule
    /// `CDownloadQueue::Process` `downspeed` budget). The symmetric counterpart
    /// to the upload-side `reserve_upload_payload` limiter. Unlimited by default.
    download_throttle: Arc<Mutex<Ed2kDownloadThrottle>>,
    /// Shared cross-transfer download coordinator enforcing the global controls
    /// the per-transfer task model lacks: the connection budget (concurrent cap
    /// + new-connection per-window rate, eMule `CListenSocket::TooManySockets`),
    ///   the per-file soft/UDP source caps (eMule
    ///   `GetMaxSourcePerFileSoft`/`GetMaxSourcePerFileUDP`), and global UDP reask
    ///   round-robin pacing (eMule `CDownloadQueue::Process` `m_udcounter`). One
    ///   per runtime, consulted by the per-transfer driver and the reask loop. A
    ///   `std::sync::Mutex` because every decision is instant (no await held), so
    ///   the download closure / reask path can consult it without `.await`.
    download_coordinator: Arc<StdMutex<Ed2kDownloadCoordinator>>,
    /// Live count of inbound (accepted) eD2k peer connections currently being
    /// handled. The listener admits a new inbound connection only while this is
    /// under the concurrent-connection cap (eMule `CListenSocket::OnAccept`
    /// refuses/stops accepting when `TooManySockets()`), then decrements it on
    /// every handler exit path. An `AtomicUsize` so the listener's accept loop
    /// can check/bump it without holding the coordinator mutex across an await.
    inbound_connections: Arc<AtomicUsize>,
    next_upload_connection_id: AtomicU64,
    /// Monotonic payload bytes received/sent since the runtime started, for the
    /// REST `sessionDownloadedBytes`/`sessionUploadedBytes` stats (oracle
    /// `theStats.sessionReceivedBytes`/`sessionSentBytes`). In-memory only.
    session_downloaded_bytes: AtomicU64,
    session_uploaded_bytes: AtomicU64,
    /// Monotonic shared-file demand revision. Upload serving bumps this when
    /// requests/accepts alter publish rank inputs, and core listens for changes
    /// to queue the existing ED2K OP_OFFERFILES refresh worker.
    shared_publish_demand_revision: Arc<AtomicU64>,
    shared_publish_demand_notify: Arc<Notify>,
    /// Whether the credit system weights upload scoring (eMule
    /// `thePrefs.GetCreditSystem()`). When false, every peer gets the neutral 1.0
    /// credit ratio (`DEFAULT_CREDIT_SCORE_PERMILLE`) so stored bytes never alter
    /// the queue order. Set from the upload-queue policy at startup and on every
    /// preferences update; an atomic so the lock-free credit-score path reads it.
    credit_system_enabled: AtomicBool,
    /// Whether MD4-only ICH salvage of corrupted parts is enabled (eMule
    /// `thePrefs.IsICHEnabled()`; ini default true, Preferences.cpp:3187).
    /// When false a corrupted part is fully re-downloaded, never re-hashed
    /// early against its retained stale bytes.
    ich_enabled: AtomicBool,
    /// In-memory client ban store (eMule `CClientList` ban lists), keyed by IP +
    /// user hash with a 4h `CLIENTBANTIME` TTL. Shared with the inbound listener,
    /// the download driver, the UDP reask runtime, and core via this runtime's
    /// `Arc`. Not persisted across restart, matching the master.
    ban_store: Arc<crate::ban_store::BanStore>,
    /// Per-transfer corruption blackbox (eMule `CCorruptionBlackBox`), keyed by
    /// file hash: which sender IP wrote which byte ranges, credited/debited by
    /// AICH block verdicts, evaluated for the 32%-corrupt-share ban. In-memory
    /// only (live per part file at runtime, never persisted), matching the
    /// master.
    corruption_blackbox: Arc<StdMutex<HashMap<String, corruption_blackbox::CorruptionBlackBox>>>,
}

/// Lightweight notification handle for shared-file demand changes that can
/// affect ED2K/Kad publish ranking.
#[derive(Debug, Clone)]
pub struct Ed2kSharedPublishDemandSignal {
    revision: Arc<AtomicU64>,
    notify: Arc<Notify>,
}

impl Ed2kSharedPublishDemandSignal {
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    pub async fn notified(&self) {
        self.notify.notified().await;
    }
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
            0,
            Ed2kDownloadCoordinatorConfig::default(),
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
            config.download_limit_bytes_per_sec,
            download_coordinator_config_from_policy(config),
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
        Self::load_or_create_with_metadata_and_upload_queue(
            root_dir,
            metadata,
            upload_queue_config,
            0,
            Ed2kDownloadCoordinatorConfig::default(),
        )
    }

    pub(crate) fn load_or_create_with_metadata_and_upload_queue(
        root_dir: &Path,
        metadata: MetadataStore,
        upload_queue_config: Ed2kUploadQueueConfig,
        download_limit_bytes_per_sec: u64,
        coordinator_config: Ed2kDownloadCoordinatorConfig,
    ) -> Result<Self> {
        fs::create_dir_all(root_dir).with_context(|| {
            format!("failed to create ED2K transfer root {}", root_dir.display())
        })?;
        let shared_catalog = Arc::new(RwLock::new(IndexedSharedCatalog::from_entries(
            transfer_sql::completed_catalog_from_metadata_store(&metadata)?,
        )));
        // The ban store is built before the upload queue so the queue state can
        // hand a no-request repeat-offender straight to the shared ban list
        // (RUST-PAR-020 U-GAP3, mirroring `client->Ban(...)`, UploadQueue.cpp:1640).
        let ban_store = Arc::new(crate::ban_store::BanStore::new());
        let mut upload_queue_state = Ed2kUploadQueueState::new(upload_queue_config);
        upload_queue_state.set_ban_store(Arc::clone(&ban_store));
        let runtime = Self {
            root_dir: root_dir.to_path_buf(),
            metadata,
            shared_catalog,
            callback_intents: Arc::new(RwLock::new(Vec::new())),
            manifest_locks: Arc::new(StdMutex::new(HashMap::new())),
            manifest_cache: Arc::new(Mutex::new(HashMap::new())),
            manifest_checkpoint_state: Arc::new(Mutex::new(HashMap::new())),
            payload_handles: Arc::new(StdMutex::new(HashMap::new())),
            source_exchange: SourceExchangeState::default(),
            aich_root_corroboration: Arc::new(StdMutex::new(HashMap::new())),
            download_activity: Arc::new(StdMutex::new(HashMap::new())),
            download_sources: Arc::new(StdMutex::new(HashMap::new())),
            upload_file_churn: Arc::new(StdMutex::new(HashMap::new())),
            pending_catalog_upload: Arc::new(StdMutex::new(HashMap::new())),
            parked_credit: Arc::new(parking_lot::Mutex::new(
                credit_ledger::ParkedCreditLedger::new(),
            )),
            credit_flush_gate: Arc::new(parking_lot::Mutex::new(())),
            upload_queue: Arc::new(Mutex::new(upload_queue_state)),
            download_throttle: Arc::new(Mutex::new(Ed2kDownloadThrottle::new(
                download_limit_bytes_per_sec,
            ))),
            download_coordinator: Arc::new(StdMutex::new(Ed2kDownloadCoordinator::new(
                coordinator_config,
            ))),
            inbound_connections: Arc::new(AtomicUsize::new(0)),
            next_upload_connection_id: AtomicU64::new(1),
            session_downloaded_bytes: AtomicU64::new(0),
            session_uploaded_bytes: AtomicU64::new(0),
            shared_publish_demand_revision: Arc::new(AtomicU64::new(0)),
            shared_publish_demand_notify: Arc::new(Notify::new()),
            credit_system_enabled: AtomicBool::new(true),
            ich_enabled: AtomicBool::new(true),
            ban_store,
            corruption_blackbox: Arc::new(StdMutex::new(HashMap::new())),
        };
        // Credit aging on startup: drop peer credit rows last seen > 150 days ago
        // (eMule CClientCreditsList::LoadList, ClientCredits.cpp:240-251). The
        // ban list itself is intentionally NOT persisted, matching the master.
        if let Err(error) = runtime.prune_aged_peer_credits() {
            tracing::warn!("failed to prune aged peer credits on startup: {error:#}");
        }
        Ok(runtime)
    }

    /// Shared client ban store handle (eMule `CClientList` ban lists). Cloning
    /// the `Arc` lets the listener / download driver / reask runtime / core
    /// consult and mutate the same in-memory, TTL'd ban set.
    #[must_use]
    pub fn ban_store(&self) -> Arc<crate::ban_store::BanStore> {
        Arc::clone(&self.ban_store)
    }

    /// Return a cloneable signal that fires when upload demand changes the
    /// shared-file publish rank inputs.
    #[must_use]
    pub fn shared_publish_demand_signal(&self) -> Ed2kSharedPublishDemandSignal {
        Ed2kSharedPublishDemandSignal {
            revision: Arc::clone(&self.shared_publish_demand_revision),
            notify: Arc::clone(&self.shared_publish_demand_notify),
        }
    }

    pub(crate) fn notify_shared_publish_demand_changed(&self) {
        self.shared_publish_demand_revision
            .fetch_add(1, Ordering::AcqRel);
        self.shared_publish_demand_notify.notify_waiters();
    }

    /// Ban a client by IP and/or user hash for `CLIENTBANTIME` (4h), mirroring
    /// `CClientList::AddBannedClient(pClient, clientBanScopeBoth)`.
    pub fn ban_client(&self, ip: Option<Ipv4Addr>, user_hash: Option<[u8; 16]>) {
        self.ban_store.ban(ip, user_hash);
    }

    /// Whether the client identified by `ip` and/or `user_hash` is currently
    /// banned by either key (`CClientList::IsBannedClient`).
    #[must_use]
    pub fn is_client_banned(&self, ip: Option<Ipv4Addr>, user_hash: Option<&[u8; 16]>) -> bool {
        self.ban_store.is_banned(ip, user_hash)
    }

    /// Reserve global download budget for `byte_count` inbound payload bytes,
    /// returning the delay the download task must await before consuming them.
    ///
    /// The symmetric counterpart to `reserve_upload_payload_budget`: every
    /// transfer task draws from one shared token bucket, so the SUM of all
    /// concurrent transfers' inbound payload respects the configured cap. A
    /// no-op (instant) when the limit is 0 (unlimited).
    pub(crate) async fn reserve_download_payload_budget(
        &self,
        byte_count: u64,
    ) -> Ed2kDownloadThrottleReservation {
        self.reserve_download_payload_budget_at(byte_count, Instant::now())
            .await
    }

    pub(crate) async fn reserve_download_payload_budget_at(
        &self,
        byte_count: u64,
        now: Instant,
    ) -> Ed2kDownloadThrottleReservation {
        let (reservation, limit_bytes_per_sec) = {
            let mut throttle = self.download_throttle.lock().await;
            let reservation = throttle.reserve_download_payload(byte_count, now);
            (reservation, throttle.limit_bytes_per_sec())
        };
        // `throttle_applied` (uniform-diagnostics-v2 schema §3.5): the shared
        // inbound rate limiter delayed this read. `delayMs` is S (exact timing
        // differs per client); `limitBytesPerSec` is C (the configured limit).
        if !reservation.delay.is_zero() {
            crate::diag_event::emit(
                "sched",
                "throttle_applied",
                "info",
                serde_json::json!({}),
                serde_json::json!({
                    "outcome": "applied",
                    "delayMs": u64::try_from(reservation.delay.as_millis()).unwrap_or(u64::MAX),
                    "limitBytesPerSec": limit_bytes_per_sec,
                }),
            );
        }
        reservation
    }

    /// Replace the active global download rate limit (0 = unlimited). Threaded
    /// from the daemon/REST preferences like the upload limit.
    pub async fn apply_download_limit(&self, limit_bytes_per_sec: u64) {
        self.download_throttle
            .lock()
            .await
            .set_limit(limit_bytes_per_sec);
    }

    /// Return the active global download rate limit in bytes per second
    /// (0 = unlimited).
    pub async fn download_limit_bytes_per_sec(&self) -> u64 {
        self.download_throttle.lock().await.limit_bytes_per_sec()
    }

    /// Try to claim a global connection budget slot for one new outgoing source
    /// connection (eMule `CListenSocket::TooManySockets` inverted). Returns
    /// `true` and reserves the slot when both the concurrent cap and the
    /// per-window new-connection rate allow it. A `false` means the caller must
    /// leave the source for the next cycle (never drop it).
    pub fn try_acquire_source_connection(&self) -> bool {
        self.try_acquire_source_connection_detailed().admitted
    }

    /// Like [`try_acquire_source_connection`] but also reports the connection
    /// budget occupancy and (on a deny) the limiting cap, so the caller can emit
    /// the `conn_budget` `diag_event_v1` event (schema §3.5) with real
    /// `activeConnections` / `connectionCap` / `denyReason` values.
    pub fn try_acquire_source_connection_detailed(&self) -> Ed2kConnectionBudgetDecision {
        let mut coordinator = self
            .download_coordinator
            .lock()
            .expect("download coordinator mutex poisoned");
        let config = coordinator.config();
        let active_before = coordinator.active_connections();
        let admitted = coordinator.try_acquire_connection(Instant::now());
        let deny_reason = if admitted {
            None
        } else if config.max_connections != 0 && active_before >= config.max_connections {
            Some(Ed2kConnectionBudgetDenyReason::ConcurrentCap)
        } else {
            // The concurrent cap was not the binding limit, so the per-window
            // new-connection rate (`m_OpenSocketsInterval`) denied it.
            Some(Ed2kConnectionBudgetDenyReason::WindowCap)
        };
        Ed2kConnectionBudgetDecision {
            admitted,
            active_connections: coordinator.active_connections(),
            connection_cap: config.max_connections,
            deny_reason,
        }
    }

    /// Signal that a granted outgoing source connection has completed its TCP
    /// connect + hello handshake, transitioning it from half-open to established
    /// (eMule `m_nHalfOpen` decrement). Frees a half-open budget slot for a new
    /// connect. Called by the download driver once the peer session reaches the
    /// connected/hello-done point. Saturating: a no-op when nothing is half-open.
    pub fn mark_connection_established(&self) {
        self.download_coordinator
            .lock()
            .expect("download coordinator mutex poisoned")
            .mark_connection_established();
    }

    /// Release a source connection budget slot when an outgoing peer connection
    /// closes (the counterpart to [`try_acquire_source_connection`]). Decrements
    /// the established bucket first, falling back to the half-open bucket for a
    /// connection that closed before it ever handshaked; both saturate.
    pub fn release_source_connection(&self) {
        self.download_coordinator
            .lock()
            .expect("download coordinator mutex poisoned")
            .release_connection();
    }

    /// Whether one more source may be engaged over TCP for a file already
    /// holding `current_source_count` sources (eMule `GetMaxSourcePerFileSoft`).
    pub fn can_engage_file_source(&self, current_source_count: usize) -> bool {
        self.download_coordinator
            .lock()
            .expect("download coordinator mutex poisoned")
            .can_engage_source(current_source_count)
    }

    /// Whether a file holding `current_source_count` sources may issue a UDP
    /// source reask (eMule `GetMaxSourcePerFileUDP`).
    pub fn can_reask_file_via_udp(&self, current_source_count: usize) -> bool {
        self.download_coordinator
            .lock()
            .expect("download coordinator mutex poisoned")
            .can_reask_via_udp(current_source_count)
    }

    /// Whether a No-Needed-Parts source of a file already holding
    /// `current_source_count` sources should be purged instead of held for the
    /// doubled reask cycle (eMule `CPartFile::Process` `DS_NONEEDEDPARTS` purge,
    /// PartFile.cpp:3059: `GetSourceCount() >= GetMaxSources() * 4 / 5`).
    pub fn should_purge_nnp_source(&self, current_source_count: usize) -> bool {
        self.download_coordinator
            .lock()
            .expect("download coordinator mutex poisoned")
            .should_purge_nnp_source(current_source_count)
    }

    /// Round-robin the next file index due for a global UDP source reask,
    /// enforcing the minimum global inter-reask interval (eMule
    /// `CDownloadQueue::Process` `m_udcounter` rotation + `SendNextUDPPacket`).
    /// `None` means the pacing floor has not elapsed or nothing is eligible.
    pub fn next_reask_file_slot(&self, file_count: usize) -> Option<usize> {
        self.download_coordinator
            .lock()
            .expect("download coordinator mutex poisoned")
            .next_reask_slot(file_count, Instant::now())
    }

    /// Replace the active download coordinator configuration (live preference
    /// change). Counters are preserved; the new caps apply on the next decision.
    pub fn apply_download_coordinator_config(&self, config: Ed2kDownloadCoordinatorConfig) {
        self.download_coordinator
            .lock()
            .expect("download coordinator mutex poisoned")
            .set_config(config);
    }

    pub(crate) async fn should_request_source_exchange(
        &self,
        file_hash: &str,
        peer_addr: SocketAddr,
        user_hash: Option<[u8; 16]>,
        current_source_count: usize,
        now: Instant,
    ) -> bool {
        if !self.can_engage_file_source(current_source_count) {
            return false;
        }
        self.source_exchange
            .should_request(file_hash, peer_addr, user_hash, current_source_count, now)
            .await
    }

    pub(crate) async fn note_source_exchange_answer(&self, file_hash: &str, now: Instant) {
        self.source_exchange.note_answer(file_hash, now).await;
    }
}

/// Build the shared download-coordinator config from the daemon/core
/// `Ed2kConfig`, mirroring the eMule defaults
/// (`GetMaxConnections`/`GetMaxConperFive`/`GetDefaultMaxSourcesPerFile`).
pub fn download_coordinator_config_from_policy(
    config: &Ed2kConfig,
) -> Ed2kDownloadCoordinatorConfig {
    Ed2kDownloadCoordinatorConfig {
        max_connections: config.max_concurrent_downloads,
        max_connections_per_window: config.max_new_connections_per_five_seconds,
        connection_window: DEFAULT_CONNECTION_WINDOW,
        max_half_open_connections: config.max_half_open_connections,
        max_sources_per_file: config.max_sources_per_file,
        reask_pacing_interval: DEFAULT_REASK_PACING_INTERVAL,
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
        soft_queue_size: DEFAULT_SOFT_QUEUE_SIZE,
        waiting_timeout: Duration::from_secs(policy.waiting_timeout_secs.max(1)),
        granted_timeout: Duration::from_secs(policy.granted_timeout_secs.max(1)),
        upload_timeout: Duration::from_secs(policy.upload_timeout_secs.max(1)),
        // Session rotation caps: 0 stays 0 (cap disabled), mirroring the oracle
        // disabled session-transfer mode / zero time limit.
        session_transfer_percent: policy.session_transfer_percent.min(100),
        session_time_limit: Duration::from_secs(policy.session_time_limit_secs),
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
        session_transfer_percent: config.session_transfer_percent,
        session_time_limit_secs: config.session_time_limit.as_secs(),
    }
}

#[cfg(test)]
mod tests;
