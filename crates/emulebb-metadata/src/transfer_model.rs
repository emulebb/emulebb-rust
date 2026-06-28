#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataTransferManifest {
    pub file_hash: String,
    pub canonical_name: String,
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
    /// instead of being re-hashed. `None` for a real download or a share-in-place
    /// row written before this field existed.
    pub source_mtime_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataTransferCatalogEntry {
    pub file_hash: String,
    pub canonical_name: String,
    pub file_size: u64,
    pub aich_root: Option<String>,
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
    pub canonical_name: String,
    pub file_size: u64,
    pub aich_root: Option<String>,
    pub comment: String,
    pub rating: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataTransferShareEntry {
    pub file_hash: String,
    pub canonical_name: String,
    pub file_size: u64,
    pub part_count: u32,
    pub aich_root: Option<String>,
    pub upload_priority: String,
    pub auto_upload_priority: bool,
    pub comment: String,
    pub rating: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataTransferPiece {
    pub piece_index: u32,
    pub state: String,
    pub bytes_written: u64,
    /// Lowercase-hex packed per-part block presence bitmap, or `None` when the
    /// part's present blocks are simply the contiguous prefix up to
    /// `bytes_written` (legacy / contiguous fast path).
    pub block_bitmap: Option<String>,
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
}
