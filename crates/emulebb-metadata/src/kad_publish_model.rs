#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetadataKadPublishCache {
    pub keyword_publishes: Vec<MetadataKadKeywordPublish>,
    pub source_publishes: Vec<MetadataKadSourcePublish>,
    pub note_publishes: Vec<MetadataKadNotePublish>,
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
