#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearch {
    pub public_id: String,
    pub query: String,
    pub normalized_query: String,
    pub method: String,
    pub search_type: String,
    pub status: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub completed_at_ms: Option<i64>,
    pub results: Vec<MetadataSearchResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchResult {
    pub source_method: String,
    pub file_hash: String,
    pub name: String,
    pub size_bytes: u64,
    pub source_count: u32,
    pub complete_source_count: u32,
    pub file_type: String,
    pub complete: bool,
    pub known_type: String,
    pub directory: String,
    pub observed_at_ms: i64,
}
