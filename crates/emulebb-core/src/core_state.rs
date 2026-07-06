use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::Ipv4Addr,
    path::PathBuf,
    time::Instant,
};

use tokio_util::sync::CancellationToken;

use crate::{
    Category, Friend, Preferences, Search, ServerInfo, ServerUpdate, SharedDirectoryRoot, Transfer,
    download_source_registry::DownloadSourceRegistry,
};

#[derive(Debug)]
pub(crate) struct CoreState {
    pub(crate) searches: HashMap<String, Search>,
    pub(crate) next_search_id: u32,
    pub(crate) transfers: HashMap<String, Transfer>,
    pub(crate) preferences: Preferences,
    pub(crate) categories: BTreeMap<u32, Category>,
    pub(crate) next_category_id: u32,
    pub(crate) friends: BTreeMap<String, Friend>,
    pub(crate) servers: HashMap<String, ServerInfo>,
    pub(crate) server_overrides: HashMap<String, ServerUpdate>,
    pub(crate) disabled_servers: HashSet<String>,
    pub(crate) server_fail_counts: HashMap<String, u32>,
    pub(crate) banned_source_clients: HashSet<String>,
    pub(crate) active_download_attempts: HashSet<String>,
    pub(crate) download_cancels: HashMap<String, (u64, CancellationToken)>,
    pub(crate) next_download_cancel_id: u64,
    pub(crate) active_download_peer_endpoints: HashSet<(Ipv4Addr, u16)>,
    pub(crate) download_source_registry: DownloadSourceRegistry,
    pub(crate) ed2k_server_source_last_queried: HashMap<String, Instant>,
    pub(crate) ed2k_udp_source_batch_last_queried: HashMap<String, Instant>,
    pub(crate) ed2k_kad_source_last_queried: HashMap<String, (Instant, u8)>,
    /// Last time we sent an outbound Kad `KADEMLIA_CALLBACK_REQ` for a firewalled
    /// buddy source, keyed by (source ip, source tcp port, file hash). Enforces the
    /// callback cooldown so a buddy-only source is not re-callbacked every requery
    /// round (oracle `DS_WAITCALLBACKKAD` reap window).
    pub(crate) ed2k_kad_callback_last_sent:
        HashMap<crate::kad_callback_initiator::KadCallbackKey, Instant>,
    pub(crate) shared_directories: Vec<SharedDirectoryRoot>,
    pub(crate) unshared_hashes: HashSet<String>,
    pub(crate) monitor_shared_hashes: HashMap<PathBuf, String>,
    pub(crate) kad_running: bool,
    /// Last time the periodic `sched:source_count` snapshot was emitted, so the
    /// download-source picture is throttled to roughly the MFC snapshot cadence
    /// instead of firing on every source-acquisition round.
    pub(crate) last_source_count_emit_at: Option<Instant>,
}
