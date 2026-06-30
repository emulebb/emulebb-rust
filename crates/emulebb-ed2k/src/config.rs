use serde::{Deserialize, Serialize};

/// eMule `MAX_PURGEQUEUETIME` (`Opcodes.h`) for stale waiting upload clients.
const DEFAULT_UPLOAD_QUEUE_WAITING_TIMEOUT_SECS: u64 = 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Ed2kConfig {
    /// Local ED2K peer TCP listener port, resolved by the daemon from config.
    pub listen_port: Option<u16>,
    /// Ordered ED2K server bootstrap entries mirrored from `server.met`.
    pub server_entries: Vec<Ed2kServerEntry>,
    /// Ordered ED2K server bootstrap endpoints in `host:port` form.
    pub server_endpoints: Vec<String>,
    /// Whether the client should advertise and use ED2K TCP obfuscation.
    pub obfuscation_enabled: bool,
    /// Optional connected-session ED2K server search probe term used for parity runs.
    pub probe_search_term: Option<String>,
    /// Timeout for one outbound direct ED2K *peer* connection attempt (the
    /// connect + handshake budget for a download source). eMule reaps a pending
    /// peer connection at `SEC2MS(45)` (ClientList.cpp:1059) but keeps the direct
    /// connect budget conservative (~15-20s); this is the direct-peer floor.
    pub connect_timeout_secs: u64,
    /// Timeout for one outbound ED2K *server* connection attempt. eMule ages a
    /// pending server connection out at `CONSERVTIMEOUT = SEC2MS(25)`
    /// (Opcodes.h:109); this is the server-connect floor (default 25).
    pub server_connect_timeout_secs: u64,
    /// Budget for a LowID source *callback* round-trip (request a callback via
    /// the server and wait for the peer to connect back). eMule reaps a pending
    /// connecting client — including a LowID callback wait — at `SEC2MS(45)`
    /// (ClientList.cpp:1059); this is the callback-wait floor (default 45).
    pub callback_timeout_secs: u64,
    /// Delay before retrying the next ED2K server endpoint.
    pub reconnect_interval_secs: u64,
    /// Whether the background ED2K server session should reconnect after the
    /// initial configured-server pass. Mirrors eMule's `Reconnect` preference.
    pub reconnect_enabled: bool,
    /// Idle interval before the client refreshes the ED2K server session.
    pub keepalive_secs: u64,
    /// Maximum lifetime of one ED2K server session before rotating endpoints.
    pub session_rotation_secs: u64,
    /// Overall cap on concurrent outgoing source connections across all
    /// transfers, consulted by the shared download coordinator before opening a
    /// new peer connection (eMule `thePrefs.GetMaxConnections()`, default 500
    /// from `GetRecommendedMaxConnections`). 0 disables the concurrent cap.
    /// This is the wired meaning of the former dead `max_concurrent_downloads`.
    pub max_concurrent_downloads: usize,
    /// Maximum new outgoing source connections admitted per 5s window (eMule
    /// `thePrefs.GetMaxConperFive()`, default 50). 0 disables the rate limiter.
    pub max_new_connections_per_five_seconds: usize,
    /// Maximum number of simultaneously half-open outgoing source connections
    /// (granted a slot but TCP+hello handshake not yet complete), consulted by
    /// the shared download coordinator as the third `CListenSocket::TooManySockets`
    /// term (eMule `thePrefs.GetMaxHalfConnections()`, default 50,
    /// `GetDefaultMaxHalfConnections`). 0 disables the half-open cap.
    pub max_half_open_connections: usize,
    /// Configured `maxSources` per file; the soft (TCP) and UDP per-file source
    /// caps derive from this like eMule (`GetDefaultMaxSourcesPerFile` = 600,
    /// soft = `min(*9/10, 1000)`, UDP = `min(*3/4, 100)`). 0 disables the cap.
    pub max_sources_per_file: usize,
    /// Maximum number of direct ED2K peers one download may keep in flight.
    pub max_parallel_download_peers: usize,
    /// Legacy diagnostic budget for the inactive one-shot keyword helper.
    ///
    /// Normal core keyword searches use the connected ED2K server session.
    pub keyword_server_attempt_budget: usize,
    /// Legacy diagnostic budget for the inactive one-shot exact-hash helper.
    ///
    /// Normal core metadata resolution uses the connected server session and Kad.
    pub exact_hash_keyword_server_attempt_budget: usize,
    /// Maximum number of ED2K servers to probe while acquiring sources.
    ///
    /// This applies only to the initial source acquisition round; short source
    /// requery rounds do not open extra server source probes.
    pub source_server_attempt_budget: usize,
    /// Only run global UDP + Kad source supplementation while a file is
    /// source-scarce (existing sources <= this, default 2). Deliberate be-gentle
    /// divergence from eMule's per-file UDP source cap (~100); the connected-server
    /// reask is unaffected. Recorded as `source-supplement-scarcity-gate` in
    /// `policy/rust-client-omissions.toml`.
    pub kad_source_supplement_max_existing_sources: usize,
    /// Deterministic inbound upload queue policy for peer download sessions.
    pub upload_queue: Ed2kUploadQueuePolicyConfig,
    /// Global (cross-transfer) download payload budget in bytes per second.
    /// Zero (the default) disables throttling: aggregate inbound bandwidth is
    /// unbounded, matching today's behavior. When non-zero, a single shared
    /// token bucket paces every transfer task's inbound block reads so their
    /// SUM respects this cap (eMule `CDownloadQueue::Process` `downspeed`
    /// budget). The download-side counterpart to
    /// `upload_queue.upload_limit_bytes_per_sec`.
    pub download_limit_bytes_per_sec: u64,
    /// Enable client-to-client UDP source reask on the shared Kad UDP port.
    /// The Rust client's experimental transfer profile keeps queued sources warm
    /// over UDP and falls back to TCP when a peer cannot be reasked reliably.
    pub enable_udp_reask: bool,
    /// Publish the real `emule-rust` mod identity in the eD2k hello instead of
    /// the default "eMule Community" (0.7-series) identity used to blend in.
    pub publish_emule_rust_identity: bool,
    /// Number of consecutive connect/ping failures after which a non-static
    /// server is dropped from the list (eMule `thePrefs.GetDeadServerRetries`,
    /// `DeadServerRetry` ini key). Master default is 1 (range 1..=10,
    /// `MAX_SERVERFAILCOUNT`); a successful connect clears the count. Static
    /// servers are never dropped.
    pub dead_server_retries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Ed2kUploadQueuePolicyConfig {
    pub active_slots: usize,
    pub elastic_percent: u32,
    pub upload_limit_bytes_per_sec: u64,
    pub elastic_underfill_bytes_per_sec: u64,
    pub elastic_underfill_secs: u64,
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
    /// Server-reported soft file limit (server.met / status). 0 = unknown.
    pub soft_files: u32,
    /// Server-reported hard file limit (server.met / status). 0 = unknown.
    pub hard_files: u32,
}

impl Default for Ed2kConfig {
    fn default() -> Self {
        Self {
            listen_port: None,
            server_entries: Vec::new(),
            server_endpoints: Vec::new(),
            obfuscation_enabled: true,
            probe_search_term: None,
            connect_timeout_secs: 15,
            // eMule CONSERVTIMEOUT (Opcodes.h:109) = SEC2MS(25) for a pending
            // server connection attempt.
            server_connect_timeout_secs: 25,
            // eMule ClientList.cpp:1059 reaps a pending connecting client
            // (incl. a LowID callback wait) at SEC2MS(45).
            callback_timeout_secs: 45,
            reconnect_interval_secs: 30,
            reconnect_enabled: true,
            keepalive_secs: 60,
            session_rotation_secs: 0,
            // eMule GetRecommendedMaxConnections default ceiling (500) /
            // GetDefaultMaxConperFive (50) / GetDefaultMaxSourcesPerFile (600).
            max_concurrent_downloads: 500,
            max_new_connections_per_five_seconds: 50,
            // eMule GetDefaultMaxHalfConnections (Preferences.h:1132).
            max_half_open_connections: 50,
            max_sources_per_file: 600,
            max_parallel_download_peers: 2,
            keyword_server_attempt_budget: 3,
            exact_hash_keyword_server_attempt_budget: 4,
            source_server_attempt_budget: 3,
            kad_source_supplement_max_existing_sources: 2,
            upload_queue: Ed2kUploadQueuePolicyConfig::default(),
            download_limit_bytes_per_sec: 0,
            enable_udp_reask: true,
            publish_emule_rust_identity: false,
            // eMule `CPreferences` DeadServerRetry default (NormalizeRetryCount
            // default 1, min 1, max MAX_SERVERFAILCOUNT=10).
            dead_server_retries: 1,
        }
    }
}

impl Default for Ed2kUploadQueuePolicyConfig {
    fn default() -> Self {
        Self {
            active_slots: 3,
            elastic_percent: 0,
            upload_limit_bytes_per_sec: 0,
            elastic_underfill_bytes_per_sec: 0,
            elastic_underfill_secs: 10,
            waiting_capacity: 512,
            waiting_timeout_secs: DEFAULT_UPLOAD_QUEUE_WAITING_TIMEOUT_SECS,
            granted_timeout_secs: 30,
            upload_timeout_secs: 90,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ed2k_config_limits_active_download_fanout() {
        let config = Ed2kConfig::default();

        // Global download coordinator caps default to the eMule master values:
        // GetRecommendedMaxConnections (500), GetDefaultMaxConperFive (50), and
        // GetDefaultMaxSourcesPerFile (600).
        assert_eq!(config.max_concurrent_downloads, 500);
        assert_eq!(config.max_new_connections_per_five_seconds, 50);
        // eMule GetDefaultMaxHalfConnections (Preferences.h:1132).
        assert_eq!(config.max_half_open_connections, 50);
        assert_eq!(config.max_sources_per_file, 600);
        assert_eq!(config.max_parallel_download_peers, 2);
        assert_eq!(config.keyword_server_attempt_budget, 3);
        assert_eq!(config.exact_hash_keyword_server_attempt_budget, 4);
        assert_eq!(config.source_server_attempt_budget, 3);
        assert_eq!(config.kad_source_supplement_max_existing_sources, 2);
        assert!(config.enable_udp_reask);
        // Download throttle is unlimited (0) by default, matching today's
        // unbounded aggregate inbound behavior.
        assert_eq!(config.download_limit_bytes_per_sec, 0);
        // eMule MAX_PURGEQUEUETIME (Opcodes.h) = HR2MS(1).
        assert_eq!(config.upload_queue.waiting_timeout_secs, 60 * 60);
        // eMule DeadServerRetry default is 1.
        assert_eq!(config.dead_server_retries, 1);
    }

    #[test]
    fn default_connect_timeout_budgets_match_emule_reach() {
        let config = Ed2kConfig::default();
        // Direct peer connect stays conservative (~15s).
        assert_eq!(config.connect_timeout_secs, 15);
        // eMule CONSERVTIMEOUT (Opcodes.h:109) = SEC2MS(25) for server connect.
        assert_eq!(config.server_connect_timeout_secs, 25);
        // eMule ClientList.cpp:1059 reaps a LowID callback wait at SEC2MS(45).
        assert_eq!(config.callback_timeout_secs, 45);
    }
}
