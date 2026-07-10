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
/// Master `CPreferences::GetDefaultMaxHalfConnections()` (Preferences.h:1132):
/// at most 50 outgoing connections may be simultaneously *half-open* (TCP
/// connect + hello handshake not yet completed). This is the third term of
/// `CListenSocket::TooManySockets` (`m_nHalfOpen >= GetMaxHalfConnections()`,
/// ListenSocket.cpp:2654).
pub const DEFAULT_MAX_HALF_OPEN_CONNECTIONS: usize = 50;
/// Master `m_OpenSocketsInterval` window length for the new-connection rate.
pub const DEFAULT_CONNECTION_WINDOW: Duration = Duration::from_secs(5);
const CONNECTION_AVERAGE_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
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
    /// Maximum number of simultaneously *half-open* outgoing source connections
    /// (granted a slot but not yet TCP+hello established). Master
    /// `CListenSocket::TooManySockets` half-open term (`m_nHalfOpen >=
    /// GetMaxHalfConnections()`, default 50). 0 disables the half-open cap.
    pub max_half_open_connections: usize,
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
            max_half_open_connections: DEFAULT_MAX_HALF_OPEN_CONNECTIONS,
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

    /// No-Needed-Parts retention purge threshold (master `CPartFile::Process`
    /// `DS_NONEEDEDPARTS` purge, PartFile.cpp:3056-3062): an NNP source is only
    /// dropped — instead of held for the doubled reask cycle — once the file
    /// already holds `GetMaxSources() * 4 / 5` sources. 0 means never purge
    /// (the per-file cap is disabled).
    pub fn nnp_purge_threshold(&self) -> usize {
        self.max_sources_per_file * 4 / 5
    }
}

/// Shared cross-transfer download coordinator (one per runtime, behind a
/// `Mutex`). I/O-free: it only tracks counts/timestamps and makes pure
/// admit/deny decisions consulted by the per-transfer driver and reask loop.
#[derive(Debug)]
pub struct Ed2kDownloadCoordinator {
    config: Ed2kDownloadCoordinatorConfig,
    /// Live count of outgoing source connections that hold a budget slot but
    /// have NOT yet completed their TCP connect + hello handshake (master
    /// `m_nHalfOpen`). A granted slot starts here and moves to
    /// `established_connections` once [`mark_connection_established`] is called.
    half_open_connections: usize,
    /// Live count of outgoing source connections whose TCP+hello handshake has
    /// completed (master: an `m_nHalfOpen`-decremented, fully-open socket).
    established_connections: usize,
    /// Timestamps of new connections admitted within the current window, oldest
    /// first (master `m_OpenSocketsInterval` accumulator over a 5s window).
    recent_connection_grants: VecDeque<Instant>,
    /// One-second sampled moving average used by MFC's connection-spike
    /// suppressor (`CListenSocket::UpdateConnectionsStatus`).
    average_connections: f64,
    connection_average_samples: u64,
    last_connection_average_sample_at: Option<Instant>,
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
            half_open_connections: 0,
            established_connections: 0,
            recent_connection_grants: VecDeque::new(),
            average_connections: 0.0,
            connection_average_samples: 0,
            last_connection_average_sample_at: None,
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

    /// Total live outgoing source connections holding a budget slot, i.e. the
    /// half-open plus established buckets (master `GetOpenSockets()` for the
    /// outgoing-source subset). This is the value the concurrent cap compares.
    pub fn active_connections(&self) -> usize {
        self.half_open_connections + self.established_connections
    }

    /// Live count of half-open (not-yet-established) outgoing source connections
    /// (master `m_nHalfOpen`).
    pub fn half_open_connections(&self) -> usize {
        self.half_open_connections
    }

    /// Live count of established (TCP+hello complete) outgoing source connections.
    pub fn established_connections(&self) -> usize {
        self.established_connections
    }

    /// Try to claim a global connection budget slot for one new outgoing source
    /// connection (master `CListenSocket::TooManySockets` inverted). Returns
    /// `true` and reserves the slot — as a *half-open* connection — when the
    /// concurrent cap, the per-window new-connection rate, AND the half-open cap
    /// (master `m_nHalfOpen >= GetMaxHalfConnections()`) all allow it; `false`
    /// otherwise, in which case the caller leaves the source for the next cycle
    /// (never drops it). The granted connection stays half-open until
    /// [`mark_connection_established`] is called once its handshake completes.
    pub fn try_acquire_connection(&mut self, now: Instant) -> bool {
        self.expire_connection_window(now);
        self.sample_connection_average(now);
        if self.config.max_connections != 0
            && self.active_connections() >= self.config.max_connections
        {
            return false;
        }
        if self.config.max_connections_per_window != 0 {
            let effective_limit = self.effective_connection_window_limit();
            // MFC compares the already-opened interval count with `>` before
            // opening the next socket. Preserve that boundary instead of
            // rounding the fractional effective limit.
            if self.recent_connection_grants.len() as f64 > effective_limit {
                return false;
            }
        }
        // Half-open cap (master TooManySockets third term): refuse a new
        // outgoing connect while too many handshakes are already in flight.
        if self.config.max_half_open_connections != 0
            && self.half_open_connections >= self.config.max_half_open_connections
        {
            return false;
        }
        self.half_open_connections += 1;
        self.recent_connection_grants.push_back(now);
        true
    }

    /// Transition one half-open connection to established once its TCP connect +
    /// hello handshake has completed (master: the `m_nHalfOpen` decrement on a
    /// fully-open socket). Frees one half-open budget slot for a new connect.
    /// Saturating: a no-op when there is no half-open connection to promote.
    pub fn mark_connection_established(&mut self) {
        if self.half_open_connections > 0 {
            self.half_open_connections -= 1;
            self.established_connections += 1;
        }
    }

    /// Release a previously acquired connection budget slot when a source
    /// connection closes. Decrements the established bucket first (the common
    /// case once a connection has handshaked) and falls back to the half-open
    /// bucket for a connection that closed before it ever established. Both
    /// decrements saturate. Does not touch the rate-limiter window: the new
    /// connection was already counted toward this window's rate.
    pub fn release_connection(&mut self) {
        if self.established_connections > 0 {
            self.established_connections -= 1;
        } else {
            self.half_open_connections = self.half_open_connections.saturating_sub(1);
        }
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

    /// Whether a No-Needed-Parts source of a file currently holding
    /// `current_source_count` sources should be purged rather than held for the
    /// doubled reask cycle (master `CPartFile::Process` NNP purge,
    /// PartFile.cpp:3059: `GetSourceCount() >= GetMaxSources() * 4 / 5`). Never
    /// purges when the per-file cap is disabled (threshold 0).
    pub fn should_purge_nnp_source(&self, current_source_count: usize) -> bool {
        let threshold = self.config.nnp_purge_threshold();
        threshold != 0 && current_source_count >= threshold
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
        if let Some(last) = self.last_reask_at
            && now.saturating_duration_since(last) < self.config.reask_pacing_interval
        {
            return None;
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

    fn sample_connection_average(&mut self, now: Instant) {
        if self.last_connection_average_sample_at.is_some_and(|last| {
            now.saturating_duration_since(last) < CONNECTION_AVERAGE_SAMPLE_INTERVAL
        }) {
            return;
        }
        self.connection_average_samples = self.connection_average_samples.saturating_add(1);
        let samples = self.connection_average_samples as f64;
        let weight = ((samples - 1.0) / samples).min(0.99);
        self.average_connections = (self.average_connections * weight
            + self.active_connections() as f64 * (1.0 - weight))
            .max(0.001);
        self.last_connection_average_sample_at = Some(now);
    }

    fn effective_connection_window_limit(&self) -> f64 {
        let configured = self.config.max_connections_per_window as f64;
        let spike_size = (self.active_connections() as f64 - self.average_connections).max(1.0);
        let spike_tolerance = 25.0 * configured / 10.0;
        let modifier = if spike_size > spike_tolerance {
            0.0
        } else {
            1.0 - spike_size / spike_tolerance
        };
        configured * modifier
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
            max_half_open_connections: 50,
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
        // NNP purge is also cap-driven: never purge with the cap disabled.
        assert!(!coordinator.should_purge_nnp_source(10_000));
    }

    #[test]
    fn nnp_purge_threshold_matches_the_oracle_formula() {
        // Oracle PartFile.cpp:3059: GetSourceCount() >= GetMaxSources() * 4/5.
        let config = Ed2kDownloadCoordinatorConfig::default();
        assert_eq!(config.nnp_purge_threshold(), 480); // 600 * 4/5
        let coordinator = Ed2kDownloadCoordinator::new(config);
        assert!(!coordinator.should_purge_nnp_source(479));
        assert!(coordinator.should_purge_nnp_source(480));
        assert!(coordinator.should_purge_nnp_source(481));
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
    fn connection_spike_modifier_suppresses_a_same_tick_burst() {
        let mut config = test_config();
        config.max_connections = 0;
        config.max_half_open_connections = 0;
        config.max_connections_per_window = 10;
        let mut coordinator = Ed2kDownloadCoordinator::new(config);
        let now = Instant::now();

        let admitted = (0..10)
            .take_while(|_| coordinator.try_acquire_connection(now))
            .count();

        assert_eq!(admitted, 8, "MFC spike modifier must reduce the flat cap");
    }

    #[test]
    fn zero_spike_modifier_preserves_mfc_first_connection_boundary() {
        let mut config = test_config();
        config.max_connections = 0;
        config.max_half_open_connections = 0;
        config.max_connections_per_window = 10;
        let mut coordinator = Ed2kDownloadCoordinator::new(config);
        coordinator.half_open_connections = 26;
        coordinator.average_connections = 0.001;
        coordinator.connection_average_samples = 1;
        let now = Instant::now();
        coordinator.last_connection_average_sample_at = Some(now);

        assert!(coordinator.try_acquire_connection(now));
        assert!(!coordinator.try_acquire_connection(now));
    }

    #[test]
    fn half_open_cap_denies_a_grant_once_too_many_handshakes_are_in_flight() {
        let mut coordinator = Ed2kDownloadCoordinator::new(Ed2kDownloadCoordinatorConfig {
            // High concurrent + rate caps so only the half-open cap binds.
            max_connections: 100,
            max_connections_per_window: 0,
            max_half_open_connections: 2,
            ..test_config()
        });
        let now = Instant::now();
        // Two grants fill the half-open budget.
        assert!(coordinator.try_acquire_connection(now));
        assert!(coordinator.try_acquire_connection(now));
        assert_eq!(coordinator.half_open_connections(), 2);
        // Third grant is denied by the half-open cap even though the concurrent
        // cap (100) is nowhere near full.
        assert!(!coordinator.try_acquire_connection(now));
        assert_eq!(coordinator.active_connections(), 2);
    }

    #[test]
    fn establishing_a_connection_frees_half_open_budget() {
        let mut coordinator = Ed2kDownloadCoordinator::new(Ed2kDownloadCoordinatorConfig {
            max_connections: 100,
            max_connections_per_window: 0,
            max_half_open_connections: 1,
            ..test_config()
        });
        let now = Instant::now();
        // One grant exhausts the half-open budget.
        assert!(coordinator.try_acquire_connection(now));
        assert!(!coordinator.try_acquire_connection(now));
        // Completing the handshake moves it half-open -> established, which frees
        // the half-open slot so the next connect is admitted again.
        coordinator.mark_connection_established();
        assert_eq!(coordinator.half_open_connections(), 0);
        assert_eq!(coordinator.established_connections(), 1);
        assert!(coordinator.try_acquire_connection(now));
        assert_eq!(coordinator.active_connections(), 2);
    }

    #[test]
    fn release_saturates_from_both_half_open_and_established_states() {
        let mut coordinator = Ed2kDownloadCoordinator::new(Ed2kDownloadCoordinatorConfig {
            max_connections: 100,
            max_connections_per_window: 0,
            max_half_open_connections: 50,
            ..test_config()
        });
        let now = Instant::now();
        // One established (acquired + handshaked) and one still half-open.
        assert!(coordinator.try_acquire_connection(now));
        coordinator.mark_connection_established();
        assert!(coordinator.try_acquire_connection(now));
        assert_eq!(coordinator.established_connections(), 1);
        assert_eq!(coordinator.half_open_connections(), 1);
        // Release prefers the established bucket, then the half-open bucket.
        coordinator.release_connection();
        assert_eq!(coordinator.established_connections(), 0);
        assert_eq!(coordinator.half_open_connections(), 1);
        coordinator.release_connection();
        assert_eq!(coordinator.half_open_connections(), 0);
        // Extra releases saturate at zero (no underflow).
        coordinator.release_connection();
        coordinator.release_connection();
        assert_eq!(coordinator.active_connections(), 0);
        // mark_connection_established is also a no-op with nothing half-open.
        coordinator.mark_connection_established();
        assert_eq!(coordinator.established_connections(), 0);
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
