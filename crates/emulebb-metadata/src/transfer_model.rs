#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataTransferManifest {
    pub file_hash: String,
    pub display_name: String,
    pub file_size: u64,
    pub piece_size: u64,
    pub completed: bool,
    pub md4_hashset_acquired: bool,
    pub md4_hashset: Vec<String>,
    pub aich_hashset_acquired: bool,
    pub aich_root: Option<String>,
    pub aich_hashset: Vec<String>,
    pub verified_ranges: Vec<MetadataTransferRange>,
    pub pieces: Vec<MetadataTransferPiece>,
    pub sources: Vec<MetadataTransferSource>,
    pub upload_priority: String,
    pub auto_upload_priority: bool,
    pub comment: String,
    pub rating: u8,
    pub category_id: u32,
    pub control_state: Option<String>,
    pub transfer_row_removed: bool,
    /// Absolute path the completed payload was materialized to by its canonical
    /// name, or `None` until the transfer is delivered. Persisted on the
    /// `transfers` row to make finished-file delivery idempotent across restarts.
    pub delivered_path: Option<String>,
    /// Original on-disk path of a shared, already-complete file seeded IN PLACE
    /// (added via a shared directory, never downloaded). `Some` marks a
    /// share-in-place transfer: its payload is read directly from this path for
    /// upload serving, it is never copied into the internal piece store, and it
    /// is never delivered to the incoming dir. `None` for a real download.
    pub source_path: Option<String>,
    /// Last-modified time (Unix milliseconds) of the share-in-place source file
    /// captured at ingest. Compared against the on-disk mtime on reload so an
    /// unchanged shared file (same `source_path` + `file_size` + mtime) is reused
    /// instead of being re-hashed. `None` means no reusable source mtime is
    /// available.
    pub source_mtime_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataTransferCatalogEntry {
    pub file_hash: String,
    pub display_name: String,
    pub file_size: u64,
    pub aich_root: Option<String>,
    pub upload_priority: String,
    pub auto_upload_priority: bool,
    pub comment: String,
    pub rating: u8,
    pub all_time_uploaded_bytes: u64,
    pub all_time_upload_requests: u64,
    pub all_time_upload_accepts: u64,
    pub last_upload_request_ms: i64,
    /// Best persisted payload path for rebuilding non-durable derived metadata.
    pub media_path: Option<String>,
    pub media: MetadataTransferMediaMetadata,
}

/// Persisted derived media tags for a completed shared payload.
///
/// The file hash is the content identity, so a non-zero extractor version makes
/// even an all-empty result a valid cache hit. This prevents warm startup from
/// reopening every shared payload merely to rediscover that it is not a media
/// file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataTransferMediaMetadata {
    pub artist: String,
    pub album: String,
    pub title: String,
    pub length_seconds: u32,
    pub bitrate_kbps: u32,
    pub codec: String,
    pub extractor_version: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetadataTransferCounts {
    pub active: usize,
    pub completed: usize,
    pub total: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataTransferPublishEntry {
    pub file_hash: String,
    pub display_name: String,
    pub file_size: u64,
    pub aich_root: Option<String>,
    pub upload_priority: String,
    pub auto_upload_priority: bool,
    pub session_uploaded_bytes: u64,
    pub session_request_count: u64,
    pub session_accept_count: u64,
    pub all_time_uploaded_bytes: u64,
    pub all_time_upload_requests: u64,
    pub all_time_upload_accepts: u64,
    pub last_upload_request_ms: i64,
    pub comment: String,
    pub rating: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataTransferShareEntry {
    pub file_hash: String,
    pub display_name: String,
    pub file_size: u64,
    pub part_count: u32,
    pub source_path: Option<String>,
    pub aich_root: Option<String>,
    pub upload_priority: String,
    pub auto_upload_priority: bool,
    pub all_time_uploaded_bytes: u64,
    pub all_time_upload_requests: u64,
    pub all_time_upload_accepts: u64,
    pub comment: String,
    pub rating: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataShareInPlaceReloadEntry {
    pub file_hash: String,
    pub file_size: u64,
    pub source_path: String,
    pub source_mtime_ms: Option<i64>,
}

/// One completed download whose delivered file can be reused (not re-hashed)
/// when a shared-directory rescan re-finds it in a configured shared Incoming /
/// category dir. The delivered payload already carries the download's computed
/// MD4/AICH hashset, so on reload the delivered path + `(file_size,
/// delivered_mtime_ms)` identity is a cache hit -- the oracle
/// `FindKnownFile(name, date, size)` reuse (SharedFileList.cpp:2138), not a
/// wasteful full re-hash of the whole payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataDeliveredReuseEntry {
    pub file_hash: String,
    pub file_size: u64,
    pub delivered_path: String,
    /// Last-modified time (Unix ms) of the delivered file captured at delivery,
    /// compared against the on-disk mtime so a delivered file the operator later
    /// replaced (same name, different content) is re-hashed instead of reused.
    pub delivered_mtime_ms: Option<i64>,
}

/// One pathless stock eMule ``known.met`` row imported into a Rust profile.
///
/// Stock ``known.met`` records do not carry a directory path. Rust can safely
/// reuse one only after a configured shared-root scan finds exactly one file
/// with the same file name, byte size, and whole-second mtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataImportedKnownFileEntry {
    pub file_hash: String,
    pub display_name: String,
    pub file_size: u64,
    pub modified_s: i64,
    pub md4_hashset: Vec<String>,
    pub aich_root: Option<String>,
    pub aich_hashset: Vec<String>,
    pub upload_priority: String,
    pub auto_upload_priority: bool,
    pub all_time_uploaded_bytes: u64,
    pub all_time_upload_requests: u64,
    pub all_time_upload_accepts: u64,
    pub last_upload_request_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSharedSourceFailure {
    pub source_path: String,
    pub file_size: u64,
    pub source_mtime_ms: Option<i64>,
    pub reason: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataTransferPiece {
    pub piece_index: u32,
    pub state: String,
    pub bytes_written: u64,
    /// Lowercase-hex packed per-part block presence bitmap, or `None` when the
    /// part's present blocks are simply the contiguous prefix up to
    /// `bytes_written` (contiguous fast path).
    pub block_bitmap: Option<String>,
    /// Whether the part previously failed its MD4 flush check and is pending
    /// MD4-only ICH salvage: the stale on-disk bytes are retained so the part
    /// can re-verify early during re-download (the rust analog of eMule's
    /// persisted `FT_CORRUPTEDPARTS` corrupted-parts list).
    pub ich_corrupted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataTransferRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataTransferSource {
    pub ip: String,
    pub tcp_port: u16,
    pub user_hash: Option<String>,
    pub connect_options: Option<u8>,
    pub file_comment: String,
    pub file_rating: u8,
}
