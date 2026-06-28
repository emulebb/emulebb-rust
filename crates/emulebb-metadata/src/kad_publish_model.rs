#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetadataKadPublishCache {
    pub keyword_publishes: Vec<MetadataKadKeywordPublish>,
    pub source_publishes: Vec<MetadataKadSourcePublish>,
    pub note_publishes: Vec<MetadataKadNotePublish>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetadataKadOutboundPublishSchedule {
    pub publishes: Vec<MetadataKadOutboundPublish>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataKadOutboundPublish {
    pub file_hash: String,
    pub publish_kind: MetadataKadOutboundPublishKind,
    pub keyword: String,
    pub published_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataKadOutboundPublishKind {
    Keyword,
    Source,
    Notes,
}

impl MetadataKadOutboundPublishKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keyword => "keyword",
            Self::Source => "source",
            Self::Notes => "notes",
        }
    }

    // Inherent token parser returning Option, deliberately not the Result-based
    // `std::str::FromStr` trait (the trait shape does not fit this enum mapping).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "keyword" => Some(Self::Keyword),
            "source" => Some(Self::Source),
            "notes" => Some(Self::Notes),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataKadKeywordPublish {
    pub target_node_id: String,
    pub file_hash: String,
    pub raw_tags: Vec<u8>,
    pub load: Option<u8>,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataKadSourcePublish {
    pub target_node_id: String,
    pub publisher_id: String,
    pub file_hash: String,
    pub source_ip: String,
    pub source_tcp_port: u16,
    pub source_udp_port: u16,
    pub raw_tags: Vec<u8>,
    pub load: Option<u8>,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataKadNotePublish {
    pub target_node_id: String,
    pub publisher_id: String,
    pub publisher_ip: String,
    pub file_hash: Option<String>,
    pub raw_tags: Vec<u8>,
    pub load: Option<u8>,
    pub observed_at_ms: i64,
}
