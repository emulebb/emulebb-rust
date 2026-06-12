#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataCategory {
    pub id: u32,
    pub name: String,
    pub path: Option<String>,
    pub comment: String,
    pub priority: u32,
    pub color: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataFriend {
    pub user_hash: String,
    pub name: String,
    pub last_address: Option<String>,
    pub last_port: u16,
    pub first_seen_ms: i64,
    pub last_seen_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataServer {
    pub endpoint: String,
    pub address: String,
    pub port: u16,
    pub name: String,
    pub description: String,
    pub priority: String,
    pub static_server: bool,
    pub enabled: bool,
    pub failed_count: u32,
    pub ping_ms: Option<u32>,
    pub users: u64,
    pub files: u64,
    pub soft_files: u64,
    pub hard_files: u64,
    pub version: String,
}

