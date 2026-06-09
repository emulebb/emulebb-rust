use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Ed2kConfig {
    /// Local ED2K peer TCP listener port.
    pub listen_port: u16,
    /// Ordered ED2K server bootstrap entries mirrored from `server.met`.
    pub server_entries: Vec<Ed2kServerEntry>,
    /// Ordered ED2K server bootstrap endpoints in `host:port` form.
    pub server_endpoints: Vec<String>,
    /// Whether the client should advertise and use ED2K TCP obfuscation.
    pub obfuscation_enabled: bool,
    /// Optional one-shot ED2K server search probe term used for parity runs.
    pub probe_search_term: Option<String>,
    /// Timeout for one outbound ED2K server connection attempt.
    pub connect_timeout_secs: u64,
    /// Delay before retrying the next ED2K server endpoint.
    pub reconnect_interval_secs: u64,
    /// Idle interval before the client refreshes the ED2K server session.
    pub keepalive_secs: u64,
    /// Maximum lifetime of one ED2K server session before rotating endpoints.
    pub session_rotation_secs: u64,
    /// Maximum number of ED2K download jobs allowed to run at once.
    pub max_concurrent_downloads: usize,
    /// Maximum number of direct ED2K peers one download may keep in flight.
    pub max_parallel_download_peers: usize,
    /// Maximum number of one-shot ED2K servers to probe for a keyword search.
    pub keyword_server_attempt_budget: usize,
    /// Maximum number of one-shot ED2K servers to probe for exact hash metadata.
    pub exact_hash_keyword_server_attempt_budget: usize,
    /// Maximum number of one-shot ED2K servers to probe while acquiring sources.
    pub source_server_attempt_budget: usize,
    /// Only run Kad source supplementation when server search found few sources.
    pub kad_source_supplement_max_existing_sources: usize,
    /// Deterministic inbound upload queue policy for peer download sessions.
    pub upload_queue: Ed2kUploadQueuePolicyConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Ed2kUploadQueuePolicyConfig {
    pub active_slots: usize,
    pub waiting_capacity: usize,
    pub waiting_timeout_secs: u64,
    pub granted_timeout_secs: u64,
    pub upload_timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct Ed2kServerEntry {
    pub host: String,
    pub port: u16,
    pub name: Option<String>,
    pub description: Option<String>,
    pub udp_flags: u32,
    pub udp_key: u32,
    pub udp_key_ip: u32,
    pub obfuscation_port_tcp: u16,
    pub obfuscation_port_udp: u16,
}

impl Default for Ed2kConfig {
    fn default() -> Self {
        Self {
            listen_port: 41_001,
            server_entries: Vec::new(),
            server_endpoints: Vec::new(),
            obfuscation_enabled: true,
            probe_search_term: None,
            connect_timeout_secs: 15,
            reconnect_interval_secs: 30,
            keepalive_secs: 60,
            session_rotation_secs: 0,
            max_concurrent_downloads: 1,
            max_parallel_download_peers: 2,
            keyword_server_attempt_budget: 3,
            exact_hash_keyword_server_attempt_budget: 4,
            source_server_attempt_budget: 3,
            kad_source_supplement_max_existing_sources: 2,
            upload_queue: Ed2kUploadQueuePolicyConfig::default(),
        }
    }
}

impl Default for Ed2kUploadQueuePolicyConfig {
    fn default() -> Self {
        Self {
            active_slots: 3,
            waiting_capacity: 512,
            waiting_timeout_secs: 180,
            granted_timeout_secs: 30,
            upload_timeout_secs: 90,
        }
    }
}
