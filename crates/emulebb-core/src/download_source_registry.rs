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

/// No-Needed-Parts reask hold: a source whose file status showed no part we
/// still need is HELD (kept registered but not re-dialed) for the doubled
/// reask interval — `FILEREASKTIME * 2` = 58 minutes (oracle
/// `CUpDownClient::GetTimeUntilReask`, DownloadClient.cpp:2425-2431) — before
/// the next TCP re-ask rechecks whether the peer has acquired needed parts
/// since (oracle `CPartFile::Process` `DS_NONEEDEDPARTS` branch,
/// PartFile.cpp:3064-3068).
pub(crate) const NNP_REASK_HOLD: Duration = Duration::from_secs(2 * 29 * 60);

/// Throttle between No-Needed-Parts retention purges for one file (oracle
/// `m_lastpurgetime + SEC2MS(40)`, PartFile.cpp:3056): even under source-cap
/// pressure at most one NNP source is dropped per 40-second window.
const NNP_PURGE_INTERVAL: Duration = Duration::from_secs(40);

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
    /// Per-(endpoint, file) No-Needed-Parts hold stamps (oracle
    /// `DS_NONEEDEDPARTS` + `SetLastAskedTime`, DownloadClient.cpp:848-852):
    /// while a stamp is younger than [`NNP_REASK_HOLD`] the source is not
    /// leased (re-dialed) for that file. Expired stamps are pruned in
    /// [`Self::lease_best_for_file`], which mirrors the oracle reset to
    /// `DS_ONQUEUE` at reask time (PartFile.cpp:3067-3068): the re-ask session
    /// re-marks the pair only if the peer is still NNP.
    nnp_holds: HashMap<((Ipv4Addr, u16), String), Instant>,
    /// Per-file stamp of the last NNP retention purge (oracle per-file
    /// `m_lastpurgetime`, PartFile.cpp:3056-3057).
    last_nnp_purge: HashMap<String, Instant>,
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
        let mut removed: Vec<((Ipv4Addr, u16), String)> = Vec::new();
        self.peers.retain(|_, candidates| {
            candidates.retain(|candidate| {
                if is_stale(candidate, now) {
                    // Genuine source removal: the candidate aged out of the liveness
                    // window and is dropped from tracking. This is the rust analogue
                    // of the MFC oracle source_dropped (source removed from a part
                    // file's srclist) — the only place it should fire.
                    crate::diag_sched::source_dropped(&candidate.file_hash, &candidate.source);
                    removed.push((
                        (candidate.source.ip, candidate.source.tcp_port),
                        candidate.file_hash.clone(),
                    ));
                    false
                } else {
                    true
                }
            });
            !candidates.is_empty()
        });
        // A pruned candidate's NNP hold goes with it (nothing left to hold).
        for key in removed {
            self.nnp_holds.remove(&key);
        }
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
        // NNP hold gate (oracle DS_NONEEDEDPARTS + doubled GetTimeUntilReask):
        // a No-Needed-Parts source is not re-dialed for this file until its
        // 58-minute hold elapses. Expired holds are pruned here — the oracle
        // analogue of the reset to DS_ONQUEUE at reask time
        // (PartFile.cpp:3067-3068); the re-ask session re-marks the pair only
        // when the peer is still NNP, so a peer that acquired needed parts in
        // the meantime resumes the normal cadence.
        self.nnp_holds
            .retain(|_, held_at| now.saturating_duration_since(*held_at) < NNP_REASK_HOLD);
        if self
            .nnp_holds
            .contains_key(&(endpoint, file_hash.to_string()))
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

    /// How long until `(source, file_hash)` may be re-dialed: the remainder of
    /// the anti-churn attempt cooldown and/or of an active No-Needed-Parts hold,
    /// whichever ends later (an NNP-held source waits the full doubled reask
    /// interval, not the 20-minute redial floor). `None` when neither applies.
    pub(crate) fn endpoint_retry_delay(
        &self,
        now: Instant,
        retry_cooldown: Duration,
        source: &Ed2kFoundSource,
        file_hash: &str,
    ) -> Option<Duration> {
        let cooldown_remaining = self
            .last_attempted_endpoints
            .get(&((source.ip, source.tcp_port), file_hash.to_string()))
            .and_then(|last| retry_cooldown.checked_sub(now.saturating_duration_since(*last)));
        let nnp_remaining = self.nnp_hold_remaining(now, source, file_hash);
        match (cooldown_remaining, nnp_remaining) {
            (Some(cooldown), Some(nnp)) => Some(cooldown.max(nnp)),
            (cooldown, nnp) => cooldown.or(nnp),
        }
    }

    /// Hold a No-Needed-Parts source for the doubled reask cycle instead of
    /// dropping it (oracle: the source stays in the file's srclist in
    /// `DS_NONEEDEDPARTS` with `SetLastAskedTime` stamped,
    /// DownloadClient.cpp:848-852, and is re-asked after `FILEREASKTIME * 2`
    /// because it may have acquired needed parts since,
    /// DownloadClient.cpp:2425-2431). Also refreshes the candidate's liveness so
    /// the held source survives its own hold window rather than aging out of
    /// [`CANDIDATE_LIVENESS_TTL`] before the re-ask. Returns whether the peer
    /// had a candidate for `file_hash` (no candidate -> nothing to hold).
    pub(crate) fn mark_no_needed_parts(
        &mut self,
        now: Instant,
        source: &Ed2kFoundSource,
        file_hash: &str,
    ) -> bool {
        let peer_key = DownloadPeerKey::from_source(source);
        let Some(candidate) = self.peers.get_mut(&peer_key).and_then(|candidates| {
            candidates
                .iter_mut()
                .find(|candidate| candidate.file_hash == file_hash)
        }) else {
            return false;
        };
        candidate.last_seen = now;
        self.nnp_holds
            .insert(((source.ip, source.tcp_port), file_hash.to_string()), now);
        true
    }

    /// Remaining time of an active No-Needed-Parts hold on `(source, file_hash)`,
    /// or `None` when the pair is not held (never marked, or the hold elapsed).
    pub(crate) fn nnp_hold_remaining(
        &self,
        now: Instant,
        source: &Ed2kFoundSource,
        file_hash: &str,
    ) -> Option<Duration> {
        let held_at = *self
            .nnp_holds
            .get(&((source.ip, source.tcp_port), file_hash.to_string()))?;
        NNP_REASK_HOLD
            .checked_sub(now.saturating_duration_since(held_at))
            .filter(|remaining| !remaining.is_zero())
    }

    /// Number of (source, file) pairs currently under an active No-Needed-Parts
    /// hold — the rust analogue of the MFC `DS_NONEEDEDPARTS` aggregate
    /// (`GetSrcStatisticsValue(DS_NONEEDEDPARTS)`) reported by `source_count`.
    pub(crate) fn nnp_source_count(&self, now: Instant) -> usize {
        self.nnp_holds
            .values()
            .filter(|held_at| now.saturating_duration_since(**held_at) < NNP_REASK_HOLD)
            .count()
    }

    /// Whether an NNP retention purge may run for `file_hash` now (oracle
    /// per-file `m_lastpurgetime + SEC2MS(40)` throttle, PartFile.cpp:3056-3057:
    /// at most one NNP source is purged per 40-second window even under
    /// source-cap pressure). Stamps the window when it grants.
    pub(crate) fn try_nnp_purge(&mut self, now: Instant, file_hash: &str) -> bool {
        match self.last_nnp_purge.get(file_hash) {
            Some(last) if now.saturating_duration_since(*last) < NNP_PURGE_INTERVAL => false,
            _ => {
                self.last_nnp_purge.insert(file_hash.to_string(), now);
                true
            }
        }
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

    /// Find the SINGLE candidate source for `file_hash` owned by a peer at
    /// `ip`. Used by the UDP reask FNF path to recover the full source identity
    /// for dead-listing: the reask loop only holds the peer's UDP endpoint,
    /// while candidates are keyed by TCP endpoint, so the IP is the only shared
    /// key. Returns `None` when no candidate matches or when several distinct
    /// peers at that IP serve the file (ambiguous — dead-listing the wrong
    /// client behind a shared NAT would be worse than skipping).
    pub(crate) fn sole_candidate_source_by_ip(
        &self,
        ip: Ipv4Addr,
        file_hash: &str,
    ) -> Option<Ed2kFoundSource> {
        let mut found: Option<Ed2kFoundSource> = None;
        for candidates in self.peers.values() {
            for candidate in candidates {
                if candidate.file_hash == file_hash && candidate.source.ip == ip {
                    if found.is_some() {
                        return None;
                    }
                    found = Some(candidate.source.clone());
                }
            }
        }
        found
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
        if removed {
            self.nnp_holds
                .remove(&((source.ip, source.tcp_port), file_hash.to_string()));
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
        // The cleared file's NNP holds and purge stamp go with its candidates.
        self.nnp_holds.retain(|(_, file), _| file != file_hash);
        self.last_nnp_purge.remove(file_hash);
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
mod tests;
