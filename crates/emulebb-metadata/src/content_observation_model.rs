//! Remote claims are evidence, independent of accepted content and sessions.

use std::net::SocketAddrV4;

use serde::Serialize;

pub const CONTENT_OBSERVATION_BATCH_ITEMS: usize = 128;
pub const CONTENT_OBSERVATION_BATCH_BYTES: usize = 256 * 1024;
pub(crate) const OBSERVATION_BYTES: usize = 64 * 1024;

/// Unknown size is its own claim, distinct from a known zero-byte file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataContentClaim {
    pub hash: [u8; 16],
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataObservationOrigin {
    Server,
    Global,
    Kad,
}

impl MetadataObservationOrigin {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Global => "global",
            Self::Kad => "kad",
        }
    }
}

/// Exact reported values. Absence is retained instead of inventing defaults.
/// Field order and omission of absent values form the observation fingerprint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MetadataContentMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complete_source_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_client_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_client_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_artist: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_album: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_length_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_bitrate_kbps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_codec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rating: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aich_root: Option<[u8; 20]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
}

impl MetadataContentMetadata {
    pub(crate) fn text_bytes(&self) -> Option<usize> {
        [
            &self.name,
            &self.file_type,
            &self.media_artist,
            &self.media_album,
            &self.media_title,
            &self.media_codec,
            &self.directory,
        ]
        .into_iter()
        .try_fold(0usize, |bytes, text| {
            bytes.checked_add(text.as_ref().map_or(0, String::len))
        })
    }
}

/// One decoded network occurrence. Never submit session snapshots or cache hits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataContentObservationEvent {
    pub claim: MetadataContentClaim,
    pub origin: MetadataObservationOrigin,
    pub reporter_endpoint: Option<SocketAddrV4>,
    pub metadata: MetadataContentMetadata,
    pub observed_at_s: i64,
}

impl MetadataContentObservationEvent {
    /// Conservative retained/serialization byte bound, without allocating.
    pub fn payload_bytes(&self) -> Option<usize> {
        self.metadata
            .text_bytes()?
            .checked_mul(6)?
            .checked_add(2048)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataContentObservationReceipt {
    pub claim_id: i64,
    pub observation_id: i64,
    pub first_seen_at_s: i64,
    pub last_seen_at_s: i64,
    pub observation_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataContentObservation {
    pub receipt: MetadataContentObservationReceipt,
    pub event: MetadataContentObservationEvent,
}

#[derive(Debug)]
pub struct MetadataContentObservationPage {
    pub items: Vec<MetadataContentObservation>,
    pub has_more: bool,
}
