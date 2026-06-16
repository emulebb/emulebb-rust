//! Shared cross-transfer download coordinator for the global controls the
//! per-transfer task model lacks.
//!
//! The downloader runs one independent task per transfer
//! (`run_ed2k_download_attempt` / `run_ed2k_direct_downloads`). Each task
//! acquires its own sources and opens its own outgoing peer connections, so
//! nothing bounds the *aggregate* across transfers. eMule's centralized
//! `CDownloadQueue::Process` enforces three global controls this module restores
//! WITHOUT collapsing the per-transfer task model into a monolithic loop:
//!
//! 1. **Global connection budget** — eMule `CListenSocket::TooManySockets`:
//!    `GetOpenSockets() > GetMaxConnections()` OR
//!    `m_OpenSocketsInterval > GetMaxConperFive()` in a 5s window. The driver
//!    consults [`Ed2kDownloadCoordinator::try_acquire_connection`] before
//!    opening a new outgoing source connection and [`release_connection`] when
//!    it closes; a source that cannot get a slot is left for the next cycle
//!    (never dropped).
//!
//! 2. **Per-file source cap** — eMule `CPartFile::GetMaxSourcePerFileSoft()`
//!    (`min(maxSources*9/10, MAX_SOURCES_FILE_SOFT)`): a file stops acquiring
//!    new sources past its soft cap, and only reasks via UDP under the UDP cap
//!    `GetMaxSourcePerFileUDP()` (`min(maxSources*3/4, MAX_SOURCES_FILE_UDP)`).
//!    Checked at source engagement / before a UDP reask.
//!
//! 3. **Global reask pacing / round-robin** — eMule `CDownloadQueue::Process`
//!    `m_udcounter` round-robins `SendNextUDPPacket` across files so the
//!    aggregate outbound UDP source-reask rate is bounded and fair, instead of
//!    each transfer reasking on its own unbounded cadence. The reask runtime
//!    consults [`next_reask_slot`] for the next file due + a minimum global
//!    inter-reask interval.
//!
//! This module is I/O-free and unit-testable: it holds counters/timestamps and
//! makes pure admit/deny decisions. The runtime owns one instance behind a
//! `Mutex` (mirroring the download throttle) and the per-transfer driver / reask
//! loop consult it. The per-file source state here is also the foundation A4AF
//! (`A4AF-lite`) will later read to bias source selection across files, so it is
//! kept as an explicit per-file map rather than a single aggregate.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Master `CPreferences::GetRecommendedMaxConnections()` default ceiling (the
/// value used when the real Windows TCP cap is unlimited / large): 500.
pub const DEFAULT_MAX_CONNECTIONS: usize = 500;
/// Master `CPreferences::GetDefaultMaxConperFive()`: at most 50 new outgoing
/// connections may be opened within one 5s window.
pub const DEFAULT_MAX_CONNECTIONS_PER_WINDOW: usize = 50;
/// Master `m_OpenSocketsInterval` window length for the new-connection rate.
pub const DEFAULT_CONNECTION_WINDOW: Duration = Duration::from_secs(5);
/// Master `CPreferences::GetDefaultMaxSourcesPerFile()`: 600 sources/file.
pub const DEFAULT_MAX_SOURCES_PER_FILE: usize = 600;
/// Master `MAX_SOURCES_FILE_SOFT` clamp on the soft per-file source cap.
pub const MAX_SOURCES_FILE_SOFT: usize = 1000;
/// Master `MAX_SOURCES_FILE_UDP` clamp on the UDP per-file source cap.
pub const MAX_SOURCES_FILE_UDP: usize = 100;
/// Minimum global interval between two outbound UDP source reasks. Derived from
/// the master `m_udcounter` cadence: `Process` runs ~1Hz and only fires
/// `SendNextUDPPacket` when the counter wraps (every ~10 ticks), so reasks are
/// paced at roughly one batch every ~10s globally. Used as the floor between
/// successive per-file reask slots so N transfers cannot each blast on their
/// own cadence.
pub const DEFAULT_REASK_PACING_INTERVAL: Duration = Duration::from_secs(10);

/// Configuration for the shared download coordinator. All defaults mirror the
/// master (`GetMaxConnections` / `GetMaxConperFive` / `GetDefaultMaxSourcesPerFile`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed2kDownloadCoordinatorConfig {
    /// Overall cap on concurrent outgoing source connections (0 = unlimited).
    pub max_connections: usize,
    /// Maximum new outgoing connections admitted per [`connection_window`].
    /// 0 disables the rate limiter (the concurrent cap may still apply).
    pub max_connections_per_window: usize,
    /// Sliding window length for the new-connection rate limiter.
    pub connection_window: Duration,
    /// Configured `maxSources` per file; the soft/UDP caps derive from this
    /// exactly like the master (`* 9/10` clamped, `* 3/4` clamped). 0 disables
    /// the per-file cap.
    pub max_sources_per_file: usize,
    /// Minimum global interval between successive UDP source reasks.
    pub reask_pacing_interval: Duration,
}

impl Default for Ed2kDownloadCoordinatorConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_window: DEFAULT_MAX_CONNECTIONS_PER_WINDOW,
            connection_window: DEFAULT_CONNECTION_WINDOW,
            max_sources_per_file: DEFAULT_MAX_SOURCES_PER_FILE,
            reask_pacing_interval: DEFAULT_REASK_PACING_INTERVAL,
        }
    }
}

impl Ed2kDownloadCoordinatorConfig {
    /// Soft per-file source cap (master `GetMaxSourcePerFileSoft`):
    /// `min(maxSources * 9 / 10, MAX_SOURCES_FILE_SOFT)`. 0 means unlimited.
    pub fn max_source_per_file_soft(&self) -> usize {
        if self.max_sources_per_file == 0 {
            return 0;
        }
        ((self.max_sources_per_file * 9) / 10).min(MAX_SOURCES_FILE_SOFT)
    }

    /// UDP per-file source cap (master `GetMaxSourcePerFileUDP`):
    /// `min(maxSources * 3 / 4, MAX_SOURCES_FILE_UDP)`. 0 means unlimited.
    pub fn max_source_per_file_udp(&self) -> usize {
        if self.max_sources_per_file == 0 {
            return 0;
        }
        ((self.max_sources_per_file * 3) / 4).min(MAX_SOURCES_FILE_UDP)
    }
}

/// Shared cross-transfer download coordinator (one per runtime, behind a
/// `Mutex`). I/O-free: it only tracks counts/timestamps and makes pure
/// admit/deny decisions consulted by the per-transfer driver and reask loop.
#[derive(Debug)]
pub struct Ed2kDownloadCoordinator {
    config: Ed2kDownloadCoordinatorConfig,
    /// Live count of outgoing source connections holding a budget slot.
    active_connections: usize,
    /// Timestamps of new connections admitted within the current window, oldest
    /// first (master `m_OpenSocketsInterval` accumulator over a 5s window).
    recent_connection_grants: VecDeque<Instant>,
    /// Round-robin cursor into the file list for fair reask selection
    /// (master `m_lastfile` / `m_udcounter` rotation).
    reask_cursor: usize,
    /// Instant the last global reask slot was granted, for pacing.
    last_reask_at: Option<Instant>,
}

impl Ed2kDownloadCoordinator {
    pub fn new(config: Ed2kDownloadCoordinatorConfig) -> Self {
        Self {
            config,
            active_connections: 0,
            recent_connection_grants: VecDeque::new(),
            reask_cursor: 0,
            last_reask_at: None,
        }
    }

    pub fn config(&self) -> Ed2kDownloadCoordinatorConfig {
        self.config
    }

    /// Replace the active configuration (live preference change). Counters are
    /// preserved; the new caps take effect on the next decision.
    pub fn set_config(&mut self, config: Ed2kDownloadCoordinatorConfig) {
        self.config = config;
    }

    pub fn active_connections(&self) -> usize {
        self.active_connections
    }

    /// Try to claim a global connection budget slot for one new outgoing source
    /// connection (master `CListenSocket::TooManySockets` inverted). Returns
    /// `true` and reserves the slot when BOTH the concurrent cap and the
    /// per-window new-connection rate allow it; `false` otherwise, in which case
    /// the caller leaves the source for the next cycle (never drops it).
    pub fn try_acquire_connection(&mut self, now: Instant) -> bool {
        self.expire_connection_window(now);
        if self.config.max_connections != 0
            && self.active_connections >= self.config.max_connections
        {
            return false;
        }
        if self.config.max_connections_per_window != 0
            && self.recent_connection_grants.len() >= self.config.max_connections_per_window
        {
            return false;
        }
        self.active_connections += 1;
        self.recent_connection_grants.push_back(now);
        true
    }

    /// Release a previously acquired connection budget slot when a source
    /// connection closes. Does not touch the rate-limiter window: the new
    /// connection was already counted toward this window's rate.
    pub fn release_connection(&mut self) {
        self.active_connections = self.active_connections.saturating_sub(1);
    }

    /// Whether `file_hash` may engage one more source over TCP given how many
    /// sources it already holds (master `GetMaxSourcePerFileSoft > sourceCount`).
    /// `current_source_count` is the file's current source count. Unlimited when
    /// the soft cap is 0.
    pub fn can_engage_source(&self, current_source_count: usize) -> bool {
        let soft = self.config.max_source_per_file_soft();
        soft == 0 || current_source_count < soft
    }

    /// Whether `file_hash` may issue a UDP source reask given how many sources it
    /// already holds (master `GetMaxSourcePerFileUDP > sourceCount`). Unlimited
    /// when the UDP cap is 0.
    pub fn can_reask_via_udp(&self, current_source_count: usize) -> bool {
        let udp = self.config.max_source_per_file_udp();
        udp == 0 || current_source_count < udp
    }

    /// Round-robin the next file due for a global UDP source reask, enforcing the
    /// minimum global inter-reask interval (master `CDownloadQueue::Process`
    /// `m_udcounter` rotation + `SendNextUDPPacket` cadence).
    ///
    /// `files` is the current reask-eligible file set (already filtered by the
    /// caller for status / UDP per-file cap). Returns the chosen index into
    /// `files`, or `None` when the global pacing floor has not elapsed or there
    /// is nothing to reask. On a grant the cursor advances so the next call
    /// picks a different file, giving every transfer a fair turn.
    pub fn next_reask_slot(&mut self, file_count: usize, now: Instant) -> Option<usize> {
        if file_count == 0 {
            return None;
        }
        if let Some(last) = self.last_reask_at {
            if now.saturating_duration_since(last) < self.config.reask_pacing_interval {
                return None;
            }
        }
        let index = self.reask_cursor % file_count;
        self.reask_cursor = self.reask_cursor.wrapping_add(1);
        self.last_reask_at = Some(now);
        Some(index)
    }

    /// Drop new-connection grant timestamps that have aged out of the rate
    /// window so the per-window counter reflects only recent admissions.
    fn expire_connection_window(&mut self, now: Instant) {
        let window = self.config.connection_window;
        while let Some(front) = self.recent_connection_grants.front() {
            if now.saturating_duration_since(*front) >= window {
                self.recent_connection_grants.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Ed2kDownloadCoordinatorConfig {
        Ed2kDownloadCoordinatorConfig {
            max_connections: 3,
            max_connections_per_window: 2,
            connection_window: Duration::from_secs(5),
            max_sources_per_file: 600,
            reask_pacing_interval: Duration::from_secs(10),
        }
    }

    #[test]
    fn master_derived_per_file_caps_match_the_oracle_formula() {
        let config = Ed2kDownloadCoordinatorConfig::default();
        // GetMaxSourcePerFileSoft: 600*9/10 = 540 (< 1000 clamp).
        assert_eq!(config.max_source_per_file_soft(), 540);
        // GetMaxSourcePerFileUDP: 600*3/4 = 450 -> clamped to MAX_SOURCES_FILE_UDP (100).
        assert_eq!(config.max_source_per_file_udp(), 100);
    }

    #[test]
    fn per_file_caps_clamp_to_the_oracle_ceilings() {
        let config = Ed2kDownloadCoordinatorConfig {
            max_sources_per_file: 100_000,
            ..Ed2kDownloadCoordinatorConfig::default()
        };
        assert_eq!(config.max_source_per_file_soft(), MAX_SOURCES_FILE_SOFT);
        assert_eq!(config.max_source_per_file_udp(), MAX_SOURCES_FILE_UDP);
    }

    #[test]
    fn zero_max_sources_disables_the_per_file_caps() {
        let config = Ed2kDownloadCoordinatorConfig {
            max_sources_per_file: 0,
            ..Ed2kDownloadCoordinatorConfig::default()
        };
        let coordinator = Ed2kDownloadCoordinator::new(config);
        assert!(coordinator.can_engage_source(10_000));
        assert!(coordinator.can_reask_via_udp(10_000));
    }

    #[test]
    fn connection_budget_enforces_the_concurrent_cap() {
        let mut coordinator = Ed2kDownloadCoordinator::new(Ed2kDownloadCoordinatorConfig {
            max_connections: 2,
            // Disable the rate limiter so only the concurrent cap is tested.
            max_connections_per_window: 0,
            ..test_config()
        });
        let now = Instant::now();
        assert!(coordinator.try_acquire_connection(now));
        assert!(coordinator.try_acquire_connection(now));
        // Third is over the concurrent cap.
        assert!(!coordinator.try_acquire_connection(now));
        assert_eq!(coordinator.active_connections(), 2);
        // Releasing frees a slot so the next acquire succeeds.
        coordinator.release_connection();
        assert!(coordinator.try_acquire_connection(now));
    }

    #[test]
    fn connection_budget_enforces_the_per_window_rate() {
        let mut coordinator = Ed2kDownloadCoordinator::new(Ed2kDownloadCoordinatorConfig {
            // High concurrent cap so only the rate matters.
            max_connections: 100,
            max_connections_per_window: 2,
            connection_window: Duration::from_secs(5),
            ..test_config()
        });
        let start = Instant::now();
        assert!(coordinator.try_acquire_connection(start));
        assert!(coordinator.try_acquire_connection(start));
        // Two new connections already opened in this window -> rate-limited even
        // though the concurrent cap (100) is nowhere near full.
        assert!(!coordinator.try_acquire_connection(start));
        // Releasing does NOT refill the rate window (the connection still counted
        // toward this window's rate).
        coordinator.release_connection();
        assert!(!coordinator.try_acquire_connection(start));
        // After the window elapses the rate budget refills.
        let after_window = start + Duration::from_secs(5) + Duration::from_millis(1);
        assert!(coordinator.try_acquire_connection(after_window));
    }

    #[test]
    fn per_file_source_cap_blocks_engagement_past_the_soft_cap() {
        let coordinator = Ed2kDownloadCoordinator::new(test_config());
        let soft = coordinator.config().max_source_per_file_soft();
        assert_eq!(soft, 540);
        assert!(coordinator.can_engage_source(soft - 1));
        // At the soft cap no more sources may be engaged.
        assert!(!coordinator.can_engage_source(soft));
        assert!(!coordinator.can_engage_source(soft + 1));
    }

    #[test]
    fn per_file_udp_cap_blocks_reask_past_the_udp_cap() {
        let coordinator = Ed2kDownloadCoordinator::new(test_config());
        let udp = coordinator.config().max_source_per_file_udp();
        assert_eq!(udp, 100);
        assert!(coordinator.can_reask_via_udp(udp - 1));
        assert!(!coordinator.can_reask_via_udp(udp));
    }

    #[test]
    fn reask_round_robin_rotates_files_and_paces_globally() {
        let mut coordinator = Ed2kDownloadCoordinator::new(test_config());
        let start = Instant::now();
        // Three eligible files; first slot picks file 0.
        assert_eq!(coordinator.next_reask_slot(3, start), Some(0));
        // A second slot too soon is paced out (global floor not elapsed).
        let too_soon = start + Duration::from_secs(1);
        assert_eq!(coordinator.next_reask_slot(3, too_soon), None);
        // After the pacing interval the cursor has advanced -> file 1, then 2, 0.
        let t1 = start + Duration::from_secs(10);
        assert_eq!(coordinator.next_reask_slot(3, t1), Some(1));
        let t2 = t1 + Duration::from_secs(10);
        assert_eq!(coordinator.next_reask_slot(3, t2), Some(2));
        let t3 = t2 + Duration::from_secs(10);
        assert_eq!(coordinator.next_reask_slot(3, t3), Some(0));
    }

    #[test]
    fn reask_slot_is_none_when_no_files_are_eligible() {
        let mut coordinator = Ed2kDownloadCoordinator::new(test_config());
        assert_eq!(coordinator.next_reask_slot(0, Instant::now()), None);
    }
}
