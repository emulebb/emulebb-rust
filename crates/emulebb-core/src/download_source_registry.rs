use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use emulebb_ed2k::ed2k_server::Ed2kFoundSource;

/// Liveness TTL for a per-file source candidate. A candidate is "live" while it
/// was last refreshed (re-seen on a requery / source-exchange round) within this
/// window; older candidates are stale and excluded from the per-file source
/// count and pruned opportunistically. Chosen on the order of the source
/// requery/reask window (eMule re-asks/requeries a source's availability on the
/// order of tens of minutes) so an actively-tracked live source stays counted
/// across rounds while a source not seen for an hour ages out. Without this the
/// per-file count grew monotonically with every distinct peer ever seen, so a
/// long-lived transfer eventually hit the soft per-file cap on dead candidates
/// and stopped engaging new live sources (and the `peers` map grew unbounded).
const CANDIDATE_LIVENESS_TTL: Duration = Duration::from_secs(60 * 60);

/// File-scoped source candidate retained by the peer-centric download registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DownloadSourceCandidate {
    pub file_hash: String,
    pub file_priority: u32,
    pub needed_parts: u32,
    pub rare_parts: u32,
    pub source: Ed2kFoundSource,
    /// When this candidate was last added/refreshed. Stamped by
    /// [`DownloadSourceRegistry::add_candidate`]; the value supplied at
    /// construction is overwritten, so callers may use any placeholder.
    pub last_seen: Instant,
}

/// In-memory source registry that derives A4AF state from peer ownership.
#[derive(Debug, Default)]
pub(crate) struct DownloadSourceRegistry {
    peers: HashMap<DownloadPeerKey, Vec<DownloadSourceCandidate>>,
    leased_peers: HashSet<DownloadPeerKey>,
    /// Per-(endpoint, file) attempt stamps backing the anti-churn retry
    /// cooldown. WHY keyed by file and not by endpoint alone: the cooldown
    /// exists to stop reconnect-hammering one endpoint for the SAME file
    /// (eMule MIN_REQUEST_TIME is a per client-file relation). A bare-endpoint
    /// key made a peer that had just SUCCESSFULLY served file A unleasable for
    /// file B for the whole cooldown, serializing multi-file downloads from
    /// one peer with 20-minute gaps and dead-locking the A4AF NNP swap (the
    /// swapped-to file deferred against the stamp the swapped-from file left).
    last_attempted_endpoints: HashMap<((Ipv4Addr, u16), String), Instant>,
}

impl DownloadSourceRegistry {
    pub(crate) fn add_candidate(&mut self, now: Instant, mut candidate: DownloadSourceCandidate) {
        candidate.last_seen = now;
        let candidates = self
            .peers
            .entry(DownloadPeerKey::from_source(&candidate.source))
            .or_default();
        if let Some(existing) = candidates
            .iter_mut()
            .find(|existing| existing.file_hash == candidate.file_hash)
        {
            *existing = candidate;
        } else {
            candidates.push(candidate);
        }
    }

    /// Drop every candidate not seen within [`CANDIDATE_LIVENESS_TTL`] of `now`
    /// and forget peers left with no candidates, so the `peers` map stays bounded
    /// over many requery rounds (it otherwise grew with every distinct peer ever
    /// seen). Leases are untouched: a leased (engaged/detached) source is being
    /// actively worked and its lease is released through its own lifecycle.
    pub(crate) fn prune_stale_candidates(&mut self, now: Instant) {
        self.peers.retain(|_, candidates| {
            candidates.retain(|candidate| {
                if is_stale(candidate, now) {
                    // Genuine source removal: the candidate aged out of the liveness
                    // window and is dropped from tracking. This is the rust analogue
                    // of the MFC oracle source_dropped (source removed from a part
                    // file's srclist) — the only place it should fire.
                    crate::diag_sched::source_dropped(&candidate.file_hash, &candidate.source);
                    false
                } else {
                    true
                }
            });
            !candidates.is_empty()
        });
    }

    #[cfg(test)]
    pub(crate) fn candidate_count_for_peer(&self, source: &Ed2kFoundSource) -> usize {
        self.peers
            .get(&DownloadPeerKey::from_source(source))
            .map_or(0, Vec::len)
    }

    pub(crate) fn candidate_count(&self) -> usize {
        self.peers.values().map(Vec::len).sum()
    }

    /// Number of CURRENTLY-LIVE source candidates registered for `file_hash`
    /// across all peers, i.e. those refreshed within [`CANDIDATE_LIVENESS_TTL`]
    /// of `now`. This is the per-file source count the download coordinator checks
    /// against the soft/UDP per-file caps (eMule `CPartFile::GetSourceCount`):
    /// counting only live candidates keeps the cap a measure of how many live
    /// sources we are tracking for this file rather than how many distinct peers
    /// were ever seen, so a long-lived transfer keeps accepting fresh sources.
    /// The same per-file source state A4AF-lite reads to bias selection.
    pub(crate) fn candidate_count_for_file(&self, now: Instant, file_hash: &str) -> usize {
        self.peers
            .values()
            .flat_map(|candidates| candidates.iter())
            .filter(|candidate| candidate.file_hash == file_hash && !is_stale(candidate, now))
            .count()
    }

    pub(crate) fn a4af_candidate_count(&self) -> usize {
        self.peers
            .values()
            .filter(|candidates| candidates.len() > 1)
            .map(|candidates| candidates.len().saturating_sub(1))
            .sum()
    }

    /// Number of distinct files that have at least one A4AF source, i.e. a source
    /// (peer) that is also a candidate for another file. This is the MFC oracle
    /// `a4afFileCount` semantic (a per-FILE count of files with `GetSrcA4AFCount()>0`),
    /// as distinct from [`Self::a4af_candidate_count`] which sums A4AF source
    /// relationships.
    pub(crate) fn a4af_file_count(&self) -> usize {
        let mut a4af_files: HashSet<&str> = HashSet::new();
        for candidates in self.peers.values() {
            if candidates.len() > 1 {
                for candidate in candidates {
                    a4af_files.insert(candidate.file_hash.as_str());
                }
            }
        }
        a4af_files.len()
    }

    pub(crate) fn leased_peer_count(&self) -> usize {
        self.leased_peers.len()
    }

    pub(crate) fn lease_best_for_file(
        &mut self,
        now: Instant,
        retry_cooldown: Duration,
        source: &Ed2kFoundSource,
        file_hash: &str,
    ) -> Option<DownloadSourceCandidate> {
        let peer_key = DownloadPeerKey::from_source(source);
        let endpoint = (source.ip, source.tcp_port);
        self.last_attempted_endpoints.retain(|_, last_attempted| {
            now.saturating_duration_since(*last_attempted) < retry_cooldown
        });
        if self
            .last_attempted_endpoints
            .get(&(endpoint, file_hash.to_string()))
            .is_some_and(|last_attempted| {
                now.saturating_duration_since(*last_attempted) < retry_cooldown
            })
        {
            return None;
        }
        let candidates = self.peers.get(&peer_key)?;
        let candidate = candidates.iter().max_by_key(candidate_score)?;
        if candidate.file_hash != file_hash || !self.leased_peers.insert(peer_key) {
            return None;
        }
        self.last_attempted_endpoints
            .insert((endpoint, file_hash.to_string()), now);
        Some(candidate.clone())
    }

    pub(crate) fn endpoint_retry_delay(
        &self,
        now: Instant,
        retry_cooldown: Duration,
        source: &Ed2kFoundSource,
        file_hash: &str,
    ) -> Option<Duration> {
        let last = *self
            .last_attempted_endpoints
            .get(&((source.ip, source.tcp_port), file_hash.to_string()))?;
        retry_cooldown.checked_sub(now.saturating_duration_since(last))
    }

    /// A4AF-lite NNP swap target (master `CUpDownClient::SwapToAnotherFile`):
    /// when a source reports No Needed Parts for `current_file_hash`, find the
    /// best OTHER file this same peer is registered to serve, so the source is
    /// moved to that file instead of being dropped. Returns the highest-priority
    /// candidate (by [`candidate_score`]: file priority, then rare/needed parts)
    /// among the peer's files whose hash differs from `current_file_hash`, or
    /// `None` when the peer serves no other wanted file (caller then drops it as
    /// before). Does not mutate lease state; the caller leases the chosen file's
    /// candidate via [`lease_best_for_file`] on the swap target if it engages it.
    pub(crate) fn swap_target_for_peer(
        &self,
        source: &Ed2kFoundSource,
        current_file_hash: &str,
    ) -> Option<DownloadSourceCandidate> {
        let peer_key = DownloadPeerKey::from_source(source);
        let candidates = self.peers.get(&peer_key)?;
        candidates
            .iter()
            .filter(|candidate| candidate.file_hash != current_file_hash)
            .max_by_key(candidate_score)
            .cloned()
    }

    /// Remove this peer's candidate for `file_hash` (a genuine source removal:
    /// the source answered FNF and was dead-listed, the rust analogue of the
    /// oracle `RemoveSource` after `AddDeadSource`, `ListenSocket.cpp:645-661`).
    /// Emits `source_dropped` per removed candidate like the other genuine
    /// removal paths; the peer is forgotten when no candidate remains. Its
    /// lease, if held, stays with the caller's endpoint-release lifecycle.
    /// Returns whether a candidate was removed.
    pub(crate) fn remove_candidate(&mut self, source: &Ed2kFoundSource, file_hash: &str) -> bool {
        let peer_key = DownloadPeerKey::from_source(source);
        let Some(candidates) = self.peers.get_mut(&peer_key) else {
            return false;
        };
        let before = candidates.len();
        candidates.retain(|candidate| {
            if candidate.file_hash == file_hash {
                crate::diag_sched::source_dropped(&candidate.file_hash, &candidate.source);
                false
            } else {
                true
            }
        });
        let removed = candidates.len() != before;
        if candidates.is_empty() {
            self.peers.remove(&peer_key);
        }
        removed
    }

    pub(crate) fn release_peer(&mut self, source: &Ed2kFoundSource) {
        self.leased_peers
            .remove(&DownloadPeerKey::from_source(source));
    }

    pub(crate) fn release_endpoint(&mut self, endpoint: (Ipv4Addr, u16)) {
        self.leased_peers
            .retain(|peer| (peer.ip, peer.tcp_port) != endpoint);
    }

    /// Forget everything the registry holds for `file_hash`: drop every source
    /// candidate registered for that file (removing peers left with no remaining
    /// candidate), and release every lease held by a peer whose remaining set no
    /// longer includes the file. Returns the endpoints whose lease was cleared so
    /// the caller can drop the matching `active_download_peer_endpoints` entries.
    ///
    /// Used when a transfer is deleted (or otherwise cancelled): the running
    /// attempt's own release path is per-endpoint and idempotent, so this can run
    /// concurrently with it without double-freeing — clearing a lease that the
    /// attempt also clears is a no-op, and the candidate map is rebuilt on the next
    /// requery. A peer that still serves ANOTHER file keeps its lease (its other
    /// engagement is untouched); only a peer left serving no file is released, so
    /// an A4AF peer shared with a live transfer is not yanked out from under it.
    pub(crate) fn release_file(&mut self, file_hash: &str) -> Vec<(Ipv4Addr, u16)> {
        // Drop this file's candidates and forget peers left with nothing. Each
        // candidate removed here is a genuine source removal (the file was deleted /
        // cancelled), so emit source_dropped per candidate — mirroring MFC
        // RemoveSource, which drops every source off a deleted part file's srclist
        // with a source_dropped event (previously rust cleared them silently).
        self.peers.retain(|_, candidates| {
            candidates.retain(|candidate| {
                if candidate.file_hash == file_hash {
                    crate::diag_sched::source_dropped(&candidate.file_hash, &candidate.source);
                    false
                } else {
                    true
                }
            });
            !candidates.is_empty()
        });
        // Release the lease of every peer that no longer has any candidate (it was
        // engaged only for the file just cleared). A peer still present in `peers`
        // serves another file and keeps its lease.
        let mut cleared = Vec::new();
        self.leased_peers.retain(|peer| {
            if self.peers.contains_key(peer) {
                true
            } else {
                cleared.push((peer.ip, peer.tcp_port));
                false
            }
        });
        cleared
    }

    /// Drop every outstanding source lease (FIX: detached-reask lease leak on
    /// disconnect/shutdown). Detached sources live on the UDP reask loop and free
    /// their lease only via a `SourceReleased` event; when the loop breaks on
    /// shutdown / command-channel close the still-detached sources never emit it,
    /// so those endpoints stay leased forever and `acquire_*_leases` defers them
    /// indefinitely. `disconnect_ed2k` tears the whole download stack down before
    /// any reconnect rebuilds it, so a full lease reset here is correct and cannot
    /// race a fresh connect; the candidate map is left intact (it is rebuilt on
    /// requery and pruned by TTL). Returns the leased peer endpoints cleared so
    /// the caller can drop the matching `active_download_peer_endpoints` entries.
    pub(crate) fn reset_leases(&mut self) -> Vec<(Ipv4Addr, u16)> {
        let cleared = self
            .leased_peers
            .iter()
            .map(|peer| (peer.ip, peer.tcp_port))
            .collect();
        self.leased_peers.clear();
        cleared
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DownloadPeerKey {
    ip: Ipv4Addr,
    tcp_port: u16,
    user_hash: Option<[u8; 16]>,
    client_id: u32,
}

impl DownloadPeerKey {
    fn from_source(source: &Ed2kFoundSource) -> Self {
        Self {
            ip: source.ip,
            tcp_port: source.tcp_port,
            user_hash: source.user_hash,
            client_id: source.client_id,
        }
    }
}

/// Whether `candidate` has not been refreshed within [`CANDIDATE_LIVENESS_TTL`]
/// of `now` (a saturating elapsed so a future `last_seen` never reads as stale).
fn is_stale(candidate: &DownloadSourceCandidate, now: Instant) -> bool {
    now.saturating_duration_since(candidate.last_seen) > CANDIDATE_LIVENESS_TTL
}

fn candidate_score(candidate: &&DownloadSourceCandidate) -> (u32, u32, u32) {
    (
        candidate.file_priority,
        candidate.rare_parts,
        candidate.needed_parts,
    )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use emulebb_ed2k::ed2k_server::Ed2kFoundSource;
    use emulebb_kad_proto::Ed2kHash;

    use super::{CANDIDATE_LIVENESS_TTL, DownloadSourceCandidate, DownloadSourceRegistry};

    #[test]
    fn registry_derives_a4af_candidates_from_peer_fanout() {
        let source = source_with_hash([0x11; 16]);
        let mut registry = DownloadSourceRegistry::default();
        let now = Instant::now();

        registry.add_candidate(
            now,
            candidate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 1, source.clone()),
        );
        registry.add_candidate(
            now,
            candidate("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 2, 1, source.clone()),
        );

        assert_eq!(registry.candidate_count_for_peer(&source), 2);
        assert_eq!(registry.a4af_candidate_count(), 1);
    }

    #[test]
    fn registry_leases_one_file_per_peer_and_prefers_best_candidate() {
        let source = source_with_hash([0x22; 16]);
        let mut registry = DownloadSourceRegistry::default();
        let now = Instant::now();
        registry.add_candidate(
            now,
            candidate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 10, source.clone()),
        );
        registry.add_candidate(
            now,
            candidate("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 5, 1, source.clone()),
        );

        let leased = registry
            .lease_best_for_file(
                now,
                Duration::ZERO,
                &source,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap();

        assert_eq!(leased.file_hash, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert!(
            registry
                .lease_best_for_file(
                    now,
                    Duration::ZERO,
                    &source,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                )
                .is_none()
        );
        registry.release_peer(&source);
        assert!(
            registry
                .lease_best_for_file(
                    now,
                    Duration::ZERO,
                    &source,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                )
                .is_some()
        );
    }

    #[test]
    fn registry_refreshing_same_source_does_not_bypass_retry_cooldown() {
        let source = source_with_hash([0x23; 16]);
        let mut registry = DownloadSourceRegistry::default();
        let file = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let now = Instant::now();
        let retry_cooldown = Duration::from_secs(20 * 60);
        registry.add_candidate(now, candidate(file, 1, 10, source.clone()));

        assert!(
            registry
                .lease_best_for_file(now, retry_cooldown, &source, file)
                .is_some()
        );
        registry.release_peer(&source);

        // Fresh source discovery may re-add/refresh the same peer on the next
        // download attempt. That must not clear the last-attempt stamp; otherwise
        // a failing source can be redialed every short retry cycle.
        let refreshed_at = now + Duration::from_secs(30);
        registry.add_candidate(refreshed_at, candidate(file, 1, 10, source.clone()));

        assert!(
            registry
                .lease_best_for_file(refreshed_at, retry_cooldown, &source, file)
                .is_none()
        );
        assert_eq!(
            registry.endpoint_retry_delay(refreshed_at, retry_cooldown, &source, file),
            Some(retry_cooldown - Duration::from_secs(30))
        );
    }

    #[test]
    fn registry_defers_when_peer_is_better_for_another_file() {
        let source = source_with_hash([0x33; 16]);
        let mut registry = DownloadSourceRegistry::default();
        let now = Instant::now();
        registry.add_candidate(
            now,
            candidate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 10, source.clone()),
        );
        registry.add_candidate(
            now,
            candidate("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 5, 1, source.clone()),
        );

        assert!(
            registry
                .lease_best_for_file(
                    now,
                    Duration::ZERO,
                    &source,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .is_none()
        );
        assert!(
            registry
                .lease_best_for_file(
                    now,
                    Duration::ZERO,
                    &source,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                )
                .is_some()
        );
    }

    #[test]
    fn registry_swap_target_picks_best_other_wanted_file_and_skips_current() {
        let source = source_with_hash([0x55; 16]);
        let mut registry = DownloadSourceRegistry::default();
        let now = Instant::now();
        // Peer serves three files: current (a), a low-priority other (b), and a
        // high-priority other (c). The NNP swap must pick c over b and never a.
        registry.add_candidate(
            now,
            candidate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9, 9, source.clone()),
        );
        registry.add_candidate(
            now,
            candidate("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1, 1, source.clone()),
        );
        registry.add_candidate(
            now,
            candidate("cccccccccccccccccccccccccccccccc", 5, 1, source.clone()),
        );

        let target = registry
            .swap_target_for_peer(&source, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        assert_eq!(target.file_hash, "cccccccccccccccccccccccccccccccc");
    }

    #[test]
    fn registry_swap_target_is_none_when_peer_serves_only_the_current_file() {
        let source = source_with_hash([0x66; 16]);
        let mut registry = DownloadSourceRegistry::default();
        let now = Instant::now();
        registry.add_candidate(
            now,
            candidate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9, 9, source.clone()),
        );

        assert!(
            registry
                .swap_target_for_peer(&source, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .is_none()
        );
    }

    #[test]
    fn stale_candidates_age_out_of_the_per_file_count_and_are_pruned() {
        // A long-lived file sees many distinct peers over time. Without a liveness
        // TTL the per-file count grew monotonically with every peer ever seen and
        // the file eventually stopped accepting new live sources. The TTL-filtered
        // count must reflect only currently-live candidates, and prune must keep
        // the map bounded.
        let mut registry = DownloadSourceRegistry::default();
        let file = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let t0 = Instant::now();

        // A dead source registered long ago.
        registry.add_candidate(t0, candidate(file, 5, 1, source_with_endpoint(0x01, 41100)));

        // A fresh source registered well past the TTL: only it is still live.
        let later = t0 + CANDIDATE_LIVENESS_TTL + Duration::from_secs(1);
        registry.add_candidate(
            later,
            candidate(file, 5, 1, source_with_endpoint(0x02, 41101)),
        );

        // The stale candidate is excluded from the live per-file count.
        assert_eq!(
            registry.candidate_count_for_file(later, file),
            1,
            "stale candidate must not count toward the per-file soft cap"
        );
        // Both rows still exist until a prune runs.
        assert_eq!(registry.candidate_count(), 2);

        // Pruning drops the stale candidate so the map stays bounded.
        registry.prune_stale_candidates(later);
        assert_eq!(registry.candidate_count(), 1);
        assert_eq!(registry.candidate_count_for_file(later, file), 1);

        // A still-fresh candidate keeps counting (a re-seen live source survives).
        let refreshed = later + Duration::from_secs(1);
        registry.add_candidate(
            refreshed,
            candidate(file, 5, 1, source_with_endpoint(0x02, 41101)),
        );
        assert_eq!(registry.candidate_count_for_file(refreshed, file), 1);
    }

    #[test]
    fn release_file_clears_candidates_and_only_that_files_leases() {
        // A peer leased for the file being released loses its lease (returned for
        // the caller to drop the matching active endpoint); the file's candidates
        // are gone. A different peer leased for ANOTHER file keeps its lease and
        // candidate (an A4AF peer shared with a live transfer is not yanked out).
        let mut registry = DownloadSourceRegistry::default();
        let now = Instant::now();
        let target = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        // Peer 1 serves only the target file and is leased on it.
        let peer_target = source_with_endpoint(0x01, 41200);
        registry.add_candidate(now, candidate(target, 5, 1, peer_target.clone()));
        assert!(
            registry
                .lease_best_for_file(now, Duration::ZERO, &peer_target, target)
                .is_some()
        );

        // Peer 2 serves a different file and is leased on it.
        let peer_other = source_with_endpoint(0x02, 41201);
        registry.add_candidate(now, candidate(other, 5, 1, peer_other.clone()));
        assert!(
            registry
                .lease_best_for_file(now, Duration::ZERO, &peer_other, other)
                .is_some()
        );

        // Peer 3 serves the target file but is NOT leased.
        let peer_unleased = source_with_endpoint(0x03, 41202);
        registry.add_candidate(now, candidate(target, 5, 1, peer_unleased.clone()));

        assert_eq!(registry.candidate_count_for_file(now, target), 2);
        assert_eq!(registry.leased_peer_count(), 2);

        let cleared = registry.release_file(target);

        // Only peer 1's endpoint is returned (it was leased for the target file).
        assert_eq!(cleared, vec![(peer_target.ip, peer_target.tcp_port)]);
        // The target file's candidates are gone; the other file's remain.
        assert_eq!(registry.candidate_count_for_file(now, target), 0);
        assert_eq!(registry.candidate_count_for_file(now, other), 1);
        // Peer 2's lease (for the other file) is untouched; peer 1's is gone.
        assert_eq!(registry.leased_peer_count(), 1);
        assert!(
            registry
                .lease_best_for_file(now, Duration::ZERO, &peer_other, other)
                .is_none(),
            "the other file's lease must still be held"
        );
    }

    #[test]
    fn released_endpoint_stays_cooldown_deferred_until_retry_window_expires() {
        let source = source_with_endpoint(0x04, 41203);
        let mut registry = DownloadSourceRegistry::default();
        let now = Instant::now();
        let file = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let cooldown = Duration::from_secs(20 * 60);
        registry.add_candidate(now, candidate(file, 5, 1, source.clone()));

        assert!(
            registry
                .lease_best_for_file(now, cooldown, &source, file)
                .is_some()
        );
        registry.release_peer(&source);
        assert!(
            registry
                .lease_best_for_file(now + Duration::from_secs(60), cooldown, &source, file)
                .is_none(),
            "a failed endpoint should not be re-dialed inside the MFC retry window"
        );
        assert!(
            registry
                .lease_best_for_file(
                    now + cooldown + Duration::from_secs(1),
                    cooldown,
                    &source,
                    file
                )
                .is_some()
        );
    }

    #[test]
    fn endpoint_cooldown_is_per_file_so_a_multi_file_peer_serves_files_back_to_back() {
        // Regression (kad_swarm E2E stall): a peer that had just successfully
        // served file A was cooldown-blocked for file B for the whole 20-minute
        // window, so the deferred transfer's attempt slept past every test and
        // user-visible horizon. The cooldown is a per-(endpoint, file) anti-churn
        // floor, not a per-endpoint one.
        let source = source_with_endpoint(0x05, 41204);
        let mut registry = DownloadSourceRegistry::default();
        let now = Instant::now();
        let file_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let file_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let cooldown = Duration::from_secs(20 * 60);
        registry.add_candidate(now, candidate(file_a, 5, 1, source.clone()));

        assert!(
            registry
                .lease_best_for_file(now, cooldown, &source, file_a)
                .is_some()
        );
        // File A completes: the peer's lease is released, file A's candidates are
        // gone, and the peer is now registered for file B (the next wanted file).
        registry.release_peer(&source);
        registry.release_file(file_a);
        let later = now + Duration::from_secs(5);
        registry.add_candidate(later, candidate(file_b, 5, 1, source.clone()));

        assert!(
            registry
                .lease_best_for_file(later, cooldown, &source, file_b)
                .is_some(),
            "a peer that just served file A must be immediately leasable for file B"
        );
        assert!(
            registry
                .endpoint_retry_delay(later, cooldown, &source, file_a)
                .is_some(),
            "file A keeps its own anti-churn window against the same endpoint"
        );
    }

    fn source_with_endpoint(last_octet: u8, tcp_port: u16) -> Ed2kFoundSource {
        let mut source = source_with_hash([last_octet; 16]);
        source.ip = Ipv4Addr::new(198, 51, 100, last_octet);
        source.tcp_port = tcp_port;
        source.client_id = u32::from_be_bytes(source.ip.octets());
        source
    }

    fn candidate(
        file_hash: &str,
        file_priority: u32,
        rare_parts: u32,
        source: Ed2kFoundSource,
    ) -> DownloadSourceCandidate {
        DownloadSourceCandidate {
            file_hash: file_hash.to_string(),
            file_priority,
            needed_parts: 4,
            rare_parts,
            source,
            // Overwritten by add_candidate; placeholder only.
            last_seen: Instant::now(),
        }
    }

    fn source_with_hash(user_hash: [u8; 16]) -> Ed2kFoundSource {
        Ed2kFoundSource {
            file_hash: Ed2kHash::from_bytes([0x44; 16]),
            ip: Ipv4Addr::new(198, 51, 100, 40),
            tcp_port: 4662,
            client_id: 0xC633_6428,
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: Some(user_hash),
            source_server: None,
            buddy_id: None,
            buddy_endpoint: None,
            source_udp_port: None,
        }
    }
}
