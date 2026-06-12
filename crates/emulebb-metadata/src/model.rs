#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataIndexedFile {
    pub ed2k_hash: String,
    pub name: String,
    pub size_bytes: u64,
    pub content_type: String,
    pub availability_score: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSharedDirectoryRoot {
    pub path: String,
    pub recursive: bool,
    pub monitor_owned: bool,
    pub shareable: bool,
    pub accessible: bool,
}
