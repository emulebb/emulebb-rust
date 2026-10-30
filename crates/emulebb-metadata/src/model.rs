#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataIndexedFile {
    pub ed2k_hash: String,
    pub name: String,
    pub size_bytes: u64,
    pub content_type: String,
    pub availability_score: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataIndexedFileOrigin {
    LocalShare,
    Transfer,
    PassiveCache,
}

impl MetadataIndexedFileOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalShare => "local_share",
            Self::Transfer => "transfer",
            Self::PassiveCache => "passive_cache",
        }
    }

    pub(crate) const fn precedence(self) -> i64 {
        match self {
            Self::LocalShare => 3,
            Self::Transfer => 2,
            Self::PassiveCache => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSharedDirectoryRoot {
    pub path: String,
    pub monitor_owned: bool,
    pub shareable: bool,
    pub accessible: bool,
}
