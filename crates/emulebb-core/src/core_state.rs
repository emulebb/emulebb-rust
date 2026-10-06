use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    time::Instant,
};

const MAX_KAD_AICH_VOTES_PER_RESULT: usize = 64;

/// Live Kad AICH evidence for one search result. The first candidate from each
/// actual responder wins, matching current aMule and preventing a responder
/// from multiplying or changing its vote. This state is deliberately absent
/// from persisted search metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KadAichSearchVotes {
    votes: BTreeMap<Ipv4Addr, [u8; 20]>,
}

impl KadAichSearchVotes {
    pub(crate) fn record(&mut self, responder_ip: Ipv4Addr, root: [u8; 20]) {
        if self.votes.len() < MAX_KAD_AICH_VOTES_PER_RESULT {
            self.votes.entry(responder_ip).or_insert(root);
        }
    }

    pub(crate) fn observations(&self) -> Vec<([u8; 20], IpAddr)> {
        self.votes
            .iter()
            .map(|(ip, root)| (*root, IpAddr::V4(*ip)))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.votes.len()
    }
}

use tokio_util::sync::CancellationToken;

use crate::{
    Category, CoreSettings, Friend, Search, ServerInfo, ServerUpdate, SharedDirectoryRoot,
    Transfer, download_source_registry::DownloadSourceRegistry,
    ed2k_dead_source_list::DeadSourceList,
};

/// Last settled on-disk identity observed for one monitored shared path.
///
/// The live watcher can emit multiple events for one logical write. Retaining
/// the cheap `(size, mtime)` identity prevents every duplicate event from
/// re-reading and re-hashing the payload, while the hash still lets a later
/// change or removal retire the previous catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MonitoredSharedFile {
    pub(crate) hash: String,
    pub(crate) file_size: u64,
    pub(crate) source_mtime_ms: Option<i64>,
}

#[derive(Debug)]
pub(crate) struct CoreState {
    pub(crate) searches: HashMap<String, Search>,
    /// Cancellation handles for queued or running network searches, keyed by
    /// public search id. Terminal settlement and deletion remove the handle.
    pub(crate) search_cancels: HashMap<String, CancellationToken>,
    pub(crate) kad_aich_search_votes: HashMap<(String, String), KadAichSearchVotes>,
    pub(crate) next_search_id: u32,
    pub(crate) transfers: HashMap<String, Transfer>,
    pub(crate) core_settings: CoreSettings,
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
    /// Per-(file, source) dead-source list: sources that answered FNF are
    /// blocked from re-admission for 45 minutes (oracle
    /// `CPartFile::m_DeadSourceList`, see `ed2k_dead_source_list`).
    pub(crate) ed2k_dead_sources: DeadSourceList,
    pub(crate) ed2k_server_source_last_queried: HashMap<String, Instant>,
    pub(crate) ed2k_server_source_last_frame_at: Option<Instant>,
    pub(crate) ed2k_udp_source_batch_last_queried: HashMap<String, Instant>,
    pub(crate) ed2k_kad_source_last_queried: HashMap<String, (Instant, u8)>,
    /// Last time we sent an outbound Kad `KADEMLIA_CALLBACK_REQ` for a firewalled
    /// buddy source, keyed by (source ip, source tcp port, file hash). Enforces the
    /// callback cooldown so a buddy-only source is not re-callbacked every requery
    /// round (oracle `DS_WAITCALLBACKKAD` reap window).
    pub(crate) ed2k_kad_callback_last_sent:
        HashMap<crate::kad_callback_initiator::KadCallbackKey, Instant>,
    /// Last time we sent `OP_CALLBACKREQUEST` through the connected eD2K server,
    /// keyed by (LowID client id, file hash). Mirrors eMule's per-source
    /// `MIN2MS(20)` callback retry gate.
    pub(crate) ed2k_server_callback_last_sent:
        HashMap<crate::ed2k_sources::Ed2kServerCallbackKey, Instant>,
    /// Last time we originated an `OP_DIRECTCALLBACKREQ` to a firewalled type-6
    /// source, keyed by (source ip, source tcp port, file hash). Enforces the
    /// same callback cooldown as the Kad-buddy path so a direct-callback source
    /// is not re-requested every requery round.
    pub(crate) ed2k_direct_callback_last_sent:
        HashMap<crate::kad_callback_initiator::KadCallbackKey, Instant>,
    pub(crate) shared_directories: Vec<SharedDirectoryRoot>,
    pub(crate) unshared_hashes: HashSet<String>,
    pub(crate) monitor_shared_hashes: HashMap<PathBuf, MonitoredSharedFile>,
    pub(crate) kad_running: bool,
    /// Last time the periodic `sched:source_count` snapshot was emitted, so the
    /// download-source picture is throttled to roughly the MFC snapshot cadence
    /// instead of firing on every source-acquisition round.
    pub(crate) last_source_count_emit_at: Option<Instant>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kad_aich_votes_keep_first_root_per_responder_and_cap_state() {
        let mut votes = KadAichSearchVotes::default();
        let first_responder = Ipv4Addr::new(10, 0, 0, 1);
        votes.record(first_responder, [0xAA; 20]);
        votes.record(first_responder, [0xBB; 20]);
        for index in 1..80u8 {
            votes.record(Ipv4Addr::new(10, index, 0, 1), [0xAA; 20]);
        }

        assert_eq!(votes.len(), MAX_KAD_AICH_VOTES_PER_RESULT);
        assert_eq!(
            votes
                .observations()
                .into_iter()
                .find(|(_, ip)| *ip == IpAddr::V4(first_responder)),
            Some(([0xAA; 20], IpAddr::V4(first_responder)))
        );
    }
}
