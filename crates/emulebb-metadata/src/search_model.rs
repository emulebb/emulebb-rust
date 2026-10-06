#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearch {
    pub public_id: String,
    pub normalized_query: String,
    pub spec: MetadataSearchSpec,
    pub resolved_method: Option<String>,
    pub status: String,
    pub status_reason: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub completed_at_ms: Option<i64>,
    pub results: Vec<MetadataSearchResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchSpec {
    pub query: String,
    pub method: String,
    pub file_type: String,
    pub extension: String,
    pub min_size_bytes: Option<u64>,
    pub max_size_bytes: Option<u64>,
    pub min_availability: Option<u32>,
    pub min_complete_sources: Option<u32>,
    pub min_bitrate_kbps: Option<u32>,
    pub min_length_seconds: Option<u32>,
    pub codec: String,
    pub title: String,
    pub album: String,
    pub artist: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchResult {
    pub file_hash: String,
    pub name: String,
    pub size_bytes: u64,
    pub source_count: u32,
    pub complete_source_count: u32,
    pub file_type: String,
    pub media_artist: String,
    pub media_album: String,
    pub media_title: String,
    pub media_length_seconds: u32,
    pub media_bitrate_kbps: u32,
    pub media_codec: String,
    pub rating: u8,
    pub aich_hash: String,
    pub complete: bool,
    pub directory: String,
    pub observations: Vec<MetadataSearchResultObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchResultObservation {
    pub origin: String,
    pub server_endpoint: Option<String>,
    pub name: String,
    pub size_bytes: u64,
    pub source_count: u32,
    pub complete_source_count: u32,
    pub source_client_id: Option<u32>,
    pub source_client_port: Option<u16>,
    pub file_type: String,
    pub media_artist: String,
    pub media_album: String,
    pub media_title: String,
    pub media_length_seconds: u32,
    pub media_bitrate_kbps: u32,
    pub media_codec: String,
    pub rating: u8,
    pub aich_hash: String,
    pub complete: bool,
    pub directory: String,
    pub observed_at_ms: i64,
}
