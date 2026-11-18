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

/// Presentation fields supplied by ingress; the database selects name and counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchResultFields {
    pub quality: MetadataSearchNameQuality,
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

impl MetadataSearchResultFields {
    pub fn payload_bytes(&self) -> Option<usize> {
        [
            &self.file_type,
            &self.media_artist,
            &self.media_album,
            &self.media_title,
            &self.media_codec,
            &self.aich_hash,
            &self.directory,
        ]
        .into_iter()
        .try_fold(256usize, |bytes, value| {
            bytes.checked_add(value.len().checked_mul(6)?)
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetadataSearchNameQuality {
    pub useful: bool,
    pub sources: u32,
    pub complete_sources: u32,
    pub rating: u8,
}

/// A bounded, filtered presentation name; raw metadata remains independent.
#[derive(Debug, Clone)]
pub struct MetadataSearchNameVote {
    pub normalized_name: String,
    pub reporter_endpoint: Option<std::net::SocketAddrV4>,
    pub origin: crate::MetadataObservationOrigin,
    pub quality: MetadataSearchNameQuality,
}
impl MetadataSearchNameVote {
    pub fn payload_bytes(&self) -> Option<usize> {
        self.normalized_name.len().checked_mul(6)?.checked_add(256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchPublication {
    pub claim_id: i64,
    pub summary: MetadataSearchResultSummary,
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
    pub fields: Vec<MetadataSearchResultFields>,
    pub name_votes: Vec<MetadataSearchNameVote>,
}

/// Session-local occurrence accounting alongside immutable corpus references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchResultObservation {
    pub observation: crate::MetadataContentObservation,
    pub first_seen_at_s: i64,
    pub last_seen_at_s: i64,
    pub observation_count: i64,
}

/// Session metadata for browsing; it never owns a result/provenance snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchHeader {
    pub id: i64,
    pub data: MetadataSearchData,
    pub result_count: u64,
}

/// One materialized claim summary without observation hydration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSearchResultHeader {
    pub claim_id: i64,
    pub file_hash: String,
    pub size_bytes: Option<u64>,
    pub summary: MetadataSearchResultSummary,
}

#[derive(Debug)]
pub struct MetadataSearchPage<T> {
    pub items: Vec<T>,
    pub has_more: bool,
}

/// Bounded initial peer/name evidence for one selected claim, not full provenance.
#[derive(Debug)]
pub struct MetadataSearchDownloadSeed {
    pub claim_id: i64,
    pub file_hash: String,
    pub size_bytes: Option<u64>,
    pub name: String,
    pub source_client_id: Option<u32>,
    pub source_client_port: Option<u16>,
    pub observations: Vec<MetadataSearchResultObservation>,
}

/// The fixed native global result sorts. Text uses binary ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MetadataSearchResultSort {
    #[serde(rename = "displayName")]
    Name,
    SizeBytes,
    Sources,
    CompleteSources,
    Rating,
    FileType,
    Artist,
    Album,
    Title,
    LengthSeconds,
    BitrateKbps,
    Codec,
}
impl MetadataSearchResultSort {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Name => "displayName",
            Self::SizeBytes => "sizeBytes",
            Self::Sources => "sources",
            Self::CompleteSources => "completeSources",
            Self::Rating => "rating",
            Self::FileType => "fileType",
            Self::Artist => "artist",
            Self::Album => "album",
            Self::Title => "title",
            Self::LengthSeconds => "lengthSeconds",
            Self::BitrateKbps => "bitrateKbps",
            Self::Codec => "codec",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetadataSearchSortOrder {
    Asc,
    Desc,
}
impl MetadataSearchSortOrder {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }
}
/// The anchor is a membership identity, never an unbounded text sort key.
#[derive(Debug, Clone, Copy)]
pub struct MetadataSearchResultsQuery {
    pub session_id: i64,
    pub after_claim_id: Option<i64>,
    pub sort: MetadataSearchResultSort,
    pub order: MetadataSearchSortOrder,
    pub limit: usize,
}
