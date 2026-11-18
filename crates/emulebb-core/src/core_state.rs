use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
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

    pub(crate) fn payload_bytes(&self) -> usize {
        // Includes conservative B-tree node/link overhead per bounded vote.
        self.votes.len() * 128
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

// Conservative accounting covers both key copies, map nodes and bounded FIFO
// capacity. This is an internal optional-evidence cache, not a daemon RAM limit.
const KAD_AICH_CACHE_BYTES: usize = 4 * 1024 * 1024;
const KAD_AICH_CACHE_HEADROOM: usize = 64 * 1024;
const KAD_AICH_CACHE_ENTRIES: usize = 512;
type AichVoteKey = (String, String);

#[derive(Debug)]
struct CachedAichVotes {
    votes: KadAichSearchVotes,
    charged_bytes: usize,
}

/// Bounded process-local evidence for selected-download seeding. Eviction only
/// drops this optimization; persisted claims never become network trust votes.
#[derive(Debug, Default)]
pub(crate) struct KadAichVoteCache {
    entries: BTreeMap<AichVoteKey, CachedAichVotes>,
    fifo: VecDeque<AichVoteKey>,
    charged_bytes: usize,
}

impl KadAichVoteCache {
    pub(crate) fn insert(&mut self, hash: &str, session: &str, votes: KadAichSearchVotes) {
        let Some(bytes) = hash
            .len()
            .checked_add(session.len())
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(votes.payload_bytes()))
            .and_then(|n| n.checked_add(512))
        else {
            return;
        };
        let budget = KAD_AICH_CACHE_BYTES - KAD_AICH_CACHE_HEADROOM;
        if bytes > budget {
            return;
        }
        let key = (hash.to_owned(), session.to_owned());
        if let Some(old) = self.entries.remove(&key) {
            self.charged_bytes -= old.charged_bytes;
            self.fifo.retain(|entry| entry != &key);
        }
        if votes.votes.is_empty() {
            return;
        }
        // WHY: completed searches can accumulate indefinitely. Evict before
        // retaining the next allocation; both entry count and bytes are bounded.
        while self.entries.len() >= KAD_AICH_CACHE_ENTRIES || self.charged_bytes + bytes > budget {
            let oldest = self
                .fifo
                .pop_front()
                .expect("nonempty evidence cache has a FIFO entry");
            let old = self
                .entries
                .remove(&oldest)
                .expect("evidence cache indexes agree");
            self.charged_bytes -= old.charged_bytes;
        }
        self.fifo.push_back(key.clone());
        self.entries.insert(
            key,
            CachedAichVotes {
                votes,
                charged_bytes: bytes,
            },
        );
        self.charged_bytes += bytes;
    }

    pub(crate) fn remove_session(&mut self, session: &str) {
        self.entries.retain(|(_, id), entry| {
            if id == session {
                self.charged_bytes -= entry.charged_bytes;
                false
            } else {
                true
            }
        });
        self.fifo.retain(|(_, id)| id != session);
        if self.entries.is_empty() {
            self.clear();
        }
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }

    /// Seek only this hash and inspect at most four retained sessions. Each
    /// actual responder contributes once, up to 64 candidates for the download.
    pub(crate) fn observations_for_hash(&self, hash: &str) -> Vec<([u8; 20], IpAddr)> {
        let mut votes = BTreeMap::new();
        for (_, evidence) in self
            .entries
            .range((hash.to_owned(), String::new())..)
            .take_while(|((candidate, _), _)| candidate == hash)
            .take(4)
        {
            for (root, ip) in evidence.votes.observations() {
                if votes.len() == 64 {
                    break;
                }
                votes.entry(ip).or_insert(root);
            }
        }
        votes.into_iter().map(|(ip, root)| (root, ip)).collect()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

use tokio_util::sync::CancellationToken;

use emulebb_metadata::NativeFileFingerprint;

use crate::{
    Category, CoreSettings, Friend, Search, ServerInfo, ServerUpdate, SharedDirectoryRoot,
    Transfer, download_source_registry::DownloadSourceRegistry,
    ed2k_dead_source_list::DeadSourceList,
};

/// Last settled on-disk identity observed for one monitored shared path.
///
/// The live watcher can emit multiple events for one logical write. Retaining
/// the native file fingerprint prevents every duplicate event from
/// re-reading and re-hashing the payload, while the hash still lets a later
/// change or removal retire the previous catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MonitoredSharedFile {
    pub(crate) hash: String,
    pub(crate) source_fingerprint: Option<NativeFileFingerprint>,
}

#[derive(Debug)]
pub(crate) struct CoreState {
    /// Execution metadata only. Retained sessions and results live in SQLite.
    pub(crate) searches: HashMap<String, Search>,
    /// Cancellation handles for queued or running network searches, keyed by
    /// public search id. Terminal settlement and deletion remove the handle.
    pub(crate) search_cancels: HashMap<String, CancellationToken>,
    pub(crate) kad_aich_search_votes: KadAichVoteCache,
    pub(crate) transfers: HashMap<String, Transfer>,
    pub(crate) core_settings: CoreSettings,
    pub(crate) categories: BTreeMap<i64, Category>,
    pub(crate) friends: BTreeMap<String, Friend>,
    pub(crate) servers: HashMap<String, ServerInfo>,
    pub(crate) server_overrides: HashMap<String, ServerUpdate>,
    pub(crate) disabled_servers: HashSet<String>,
    pub(crate) server_fail_counts: HashMap<String, u32>,

    pub(crate) active_download_peer_endpoints: HashMap<(Ipv4Addr, u16), emulebb_metadata::JobToken>,
    pub(crate) download_source_registry: DownloadSourceRegistry,
    /// Per-(file, source) dead-source list: sources that answered FNF are
    /// blocked from re-admission for 45 minutes (oracle
    /// `CPartFile::m_DeadSourceList`, see `ed2k_dead_source_list`).
    pub(crate) ed2k_dead_sources: DeadSourceList,
    pub(crate) ed2k_server_source_last_queried: HashMap<String, Instant>,
    pub(crate) ed2k_server_source_last_frame_at: Option<Instant>,
    pub(crate) ed2k_udp_source_batch_last_queried: HashMap<String, Instant>,
    pub(crate) ed2k_kad_source_last_queried: HashMap<String, (Instant, u8)>,
    /// Last settled outbound Kad callback per firewalled peer/route. One inbound
    /// callback session can negotiate all A4AF files, while direct-buddy and
    /// FINDSOURCE routes remain distinct. Enforces the oracle
    /// `DS_WAITCALLBACKKAD` reap window without multiplying requests by file.
    pub(crate) ed2k_kad_callback_last_sent:
        HashMap<crate::kad_callback_initiator::KadCallbackKey, Instant>,
    /// Last time we sent a classic server callback for one server-local LowID
    /// peer, keyed by (server endpoint, client id). The peer-scoped gate covers
    /// every A4AF file joined to that callback session and mirrors eMule's
    /// per-client `MIN2MS(20)` retry gate.
    pub(crate) ed2k_server_callback_last_sent:
        HashMap<crate::ed2k_sources::Ed2kServerCallbackKey, Instant>,
    /// Last settled `OP_DIRECTCALLBACKREQ` dispatch per direct route/peer,
    /// keyed by (source UDP endpoint, user hash). One connect-back session can
    /// negotiate every A4AF file, so file identity is deliberately absent.
    pub(crate) ed2k_direct_callback_last_sent:
        HashMap<crate::ed2k_sources::Ed2kDirectCallbackKey, Instant>,
    pub(crate) shared_directories: Vec<SharedDirectoryRoot>,
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

#[cfg(test)]
mod kad_aich_vote_cache_tests {
    use super::*;

    fn evidence(count: u8) -> KadAichSearchVotes {
        let mut votes = KadAichSearchVotes::default();
        for index in 0..count {
            votes.record(Ipv4Addr::new(192, 0, 2, index), [0xab; 20]);
        }
        votes
    }

    fn assert_accounting(cache: &KadAichVoteCache) {
        assert_eq!(cache.entries.len(), cache.fifo.len());
        assert_eq!(
            cache.charged_bytes,
            cache
                .entries
                .values()
                .map(|e| e.charged_bytes)
                .sum::<usize>()
        );
        assert!(cache.entries.len() <= KAD_AICH_CACHE_ENTRIES);
        assert!(cache.charged_bytes + KAD_AICH_CACHE_HEADROOM <= KAD_AICH_CACHE_BYTES);
        assert!(cache.fifo.iter().all(|key| cache.entries.contains_key(key)));
    }

    #[test]
    fn one_hundred_thousand_retained_results_stay_bounded_and_evict_oldest() {
        let mut cache = KadAichVoteCache::default();
        for id in 0..100000 {
            cache.insert(&format!("{id:032x}"), &id.to_string(), evidence(1));
            if id % 1000 == 0 {
                assert_accounting(&cache);
            }
        }
        assert_accounting(&cache);
        assert_eq!(cache.len(), KAD_AICH_CACHE_ENTRIES);
        assert!(
            cache
                .observations_for_hash(&format!("{:032x}", 0))
                .is_empty()
        );
        assert_eq!(
            cache
                .observations_for_hash(&format!("{:032x}", 99999))
                .len(),
            1
        );
        assert_eq!(
            cache.fifo.front().unwrap().1,
            (100000 - KAD_AICH_CACHE_ENTRIES).to_string()
        );
    }

    #[test]
    fn worst_case_votes_obey_byte_cap_and_session_removal_releases_charges() {
        let mut cache = KadAichVoteCache::default();
        for id in 0..1024 {
            cache.insert(&format!("{id:032x}"), "1", evidence(64));
        }
        assert_accounting(&cache);
        assert!(cache.len() < KAD_AICH_CACHE_ENTRIES);
        let first = cache.fifo.front().unwrap().clone();
        cache.insert(&first.0, &first.1, evidence(1));
        assert_accounting(&cache);
        assert_eq!(cache.fifo.back(), Some(&first));
        cache.insert(&"ff".repeat(16), "2", evidence(2));
        cache.remove_session("1");
        assert_accounting(&cache);
        assert_eq!(cache.len(), 1);
        cache.remove_session("2");
        assert_eq!(cache.charged_bytes, 0);
        assert_eq!(cache.fifo.capacity(), 0);
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn hash_selection_deduplicates_actual_reporters_and_clear_releases_cache() {
        let mut cache = KadAichVoteCache::default();
        let original = evidence(64);
        let hash = "11".repeat(16);
        cache.insert(&hash, "1", original.clone());
        let mut conflicting = evidence(64);
        // First candidate from each responder remains authoritative.
        conflicting.record(Ipv4Addr::new(192, 0, 2, 0), [0xcd; 20]);
        cache.insert(&hash, "2", conflicting);
        cache.insert(&"22".repeat(16), "3", evidence(1));
        let observations = cache.observations_for_hash(&hash);
        assert_eq!(observations.len(), 64);
        assert!(observations.iter().all(|(root, _)| *root == [0xab; 20]));
        cache.clear();
        assert_accounting(&cache);
        assert!(cache.observations_for_hash(&hash).is_empty());
        assert_eq!(original.len(), 64);
    }
}
