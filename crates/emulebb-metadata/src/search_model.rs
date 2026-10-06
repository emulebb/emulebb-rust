#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearch {
    pub public_id: String,
    pub query: String,
    pub normalized_query: String,
    pub requested_method: String,
    pub resolved_method: Option<String>,
    pub file_type_filter: String,
    pub status: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub completed_at_ms: Option<i64>,
    pub results: Vec<MetadataSearchResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchResult {
    pub file_hash: String,
    pub name: String,
    pub size_bytes: u64,
    pub source_count: u32,
    pub complete_source_count: u32,
    pub file_type: String,
    pub rating: u8,
    pub aich_hash: String,
    pub complete: bool,
    pub directory: String,
    pub observations: Vec<MetadataSearchResultObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchResultObservation {
    pub origin: String,
    pub name: String,
    pub size_bytes: u64,
    pub source_count: u32,
    pub complete_source_count: u32,
    pub source_client_id: Option<u32>,
    pub source_client_port: Option<u16>,
    pub file_type: String,
    pub rating: u8,
    pub aich_hash: String,
    pub complete: bool,
    pub directory: String,
    pub observed_at_ms: i64,
}
