#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearch {
    pub id: i64,
    pub data: MetadataSearchData,
    pub results: Vec<MetadataSearchResult>,
}

/// Search attributes accepted by both creation and updates; identity is allocated
/// separately by SQLite and cannot be supplied by a creator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchData {
    pub normalized_query: String,
    pub spec: MetadataSearchSpec,
    pub resolved_method: Option<String>,
    pub status: String,
    pub status_reason: Option<String>,
    pub created_at_s: i64,
    pub updated_at_s: i64,
    pub completed_at_s: Option<i64>,
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

/// Materialized presentation for one immutable hash/size claim in a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchResultSummary {
    pub name: String,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchResult {
    pub claim_id: i64,
    pub file_hash: String,
    pub size_bytes: Option<u64>,
    pub summary: MetadataSearchResultSummary,
    pub observations: Vec<MetadataSearchResultObservation>,
}

/// Optional session projection attached to newly decoded network occurrences.
/// The transaction checks the session's collecting state before writing it.
#[derive(Debug, Clone)]
pub struct MetadataSearchProjection {
    pub session_id: i64,
    pub summary: MetadataSearchResultSummary,
}

/// Session-local occurrence accounting alongside immutable corpus references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchResultObservation {
    pub observation: crate::MetadataContentObservation,
    pub first_seen_at_s: i64,
    pub last_seen_at_s: i64,
    pub observation_count: i64,
}
