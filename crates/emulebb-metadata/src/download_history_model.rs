#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataDownloadHistoryEntry {
    pub file_hash: String,
    pub display_name: String,
    pub file_size: u64,
    pub aich_root: Option<String>,
    pub first_completed_at_ms: i64,
    pub last_completed_at_ms: i64,
}
