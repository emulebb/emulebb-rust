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
    pub control_state: Option<String>,
    pub transfer_row_removed: bool,
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
