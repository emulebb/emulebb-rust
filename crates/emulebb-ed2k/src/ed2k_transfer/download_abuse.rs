//! Cross-connection download-source anti-abuse state.
//!
//! The maintained MFC client keeps these counters on `CUpDownClient`, so they
//! survive file changes and ordinary socket reconnects. Rust download sessions
//! are deliberately short-lived, therefore the equivalent state belongs to the
//! transfer runtime and is keyed by the peer user hash (or source IP until a
//! hash is known).

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

const OUT_OF_PART_COOLDOWN_THRESHOLD: u32 = 3;
const OUT_OF_PART_SHORT_WINDOW: Duration = Duration::from_secs(30);
const OUT_OF_PART_COOLDOWN: Duration = Duration::from_secs(2 * 60);
const OUT_OF_PART_BURST_QUARANTINE_THRESHOLD: u32 = 2;
const OUT_OF_PART_LONG_QUARANTINE_THRESHOLD: u32 = 10;
const OUT_OF_PART_LONG_WINDOW: Duration = Duration::from_secs(5 * 60);

const QUEUE_RANK_FLOOD_THRESHOLD: u8 = 3;
const QUEUE_RANK_BAN_BAD_REQUESTS: u8 = 2;

// The MFC client objects are finite too. Keep this process-scoped compatibility
// ledger bounded while retaining inactive identities for at least a ban TTL.
const PEER_STATE_TTL: Duration = Duration::from_secs(4 * 60 * 60);
const MAX_PEER_STATES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DownloadPeerKey {
    UserHash([u8; 16]),
    Ip(IpAddr),
}

impl DownloadPeerKey {
    fn new(peer: SocketAddr, user_hash: Option<[u8; 16]>) -> Self {
        user_hash
            .filter(|hash| hash != &[0; 16])
            .map_or(Self::Ip(peer.ip()), Self::UserHash)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutOfPartDisposition {
    Observed,
    Cooldown,
    QuarantinedLongWindow,
    QuarantinedCooldownBursts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutOfPartRecord {
    pub(crate) disposition: OutOfPartDisposition,
    pub(crate) short_window_count: u32,
    pub(crate) long_window_count: u32,
    pub(crate) cooldown_bursts: u32,
    pub(crate) cooldown_remaining: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutOfPartAcceptGuard {
    Allowed,
    Suppressed {
        quarantined: bool,
        cooldown_remaining: Option<Duration>,
        long_window_count: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutOfPartSuppressionRecord {
    pub(crate) long_window_count: u32,
    pub(crate) newly_quarantined: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueRankDecision {
    Accept,
    Disconnect {
        unsolicited_count: u8,
        tracked_bad_requests: u8,
    },
    Ban {
        unsolicited_count: u8,
        tracked_bad_requests: u8,
    },
}

#[derive(Debug)]
struct PeerAbuseState {
    last_seen: Instant,
    queue_rank_unsolicited: u8,
    queue_rank_bad_requests: u8,
    out_of_part_short_window_start: Option<Instant>,
    out_of_part_short_window_count: u32,
    out_of_part_long_window_start: Option<Instant>,
    out_of_part_long_window_count: u32,
    out_of_part_cooldown_until: Option<Instant>,
    out_of_part_cooldown_bursts: u32,
    out_of_part_quarantined: bool,
}

impl PeerAbuseState {
    fn new(now: Instant) -> Self {
        Self {
            last_seen: now,
            queue_rank_unsolicited: 0,
            queue_rank_bad_requests: 0,
            out_of_part_short_window_start: None,
            out_of_part_short_window_count: 0,
            out_of_part_long_window_start: None,
            out_of_part_long_window_count: 0,
            out_of_part_cooldown_until: None,
            out_of_part_cooldown_bursts: 0,
            out_of_part_quarantined: false,
        }
    }

    fn refresh_window(
        now: Instant,
        start: &mut Option<Instant>,
        count: &mut u32,
        window: Duration,
    ) {
        if start.is_none_or(|started| now.saturating_duration_since(started) >= window) {
            *start = Some(now);
            *count = 0;
        }
    }

    fn out_of_part_record(
        &self,
        now: Instant,
        disposition: OutOfPartDisposition,
    ) -> OutOfPartRecord {
        OutOfPartRecord {
            disposition,
            short_window_count: self.out_of_part_short_window_count,
            long_window_count: self.out_of_part_long_window_count,
            cooldown_bursts: self.out_of_part_cooldown_bursts,
            cooldown_remaining: self
                .out_of_part_cooldown_until
                .and_then(|until| until.checked_duration_since(now)),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct DownloadAbuseTracker {
    peers: HashMap<DownloadPeerKey, PeerAbuseState>,
}

impl DownloadAbuseTracker {
    fn state_mut(
        &mut self,
        peer: SocketAddr,
        user_hash: Option<[u8; 16]>,
        now: Instant,
    ) -> &mut PeerAbuseState {
        let key = DownloadPeerKey::new(peer, user_hash);
        if !self.peers.contains_key(&key) {
            self.peers
                .retain(|_, state| now.saturating_duration_since(state.last_seen) < PEER_STATE_TTL);
            if self.peers.len() >= MAX_PEER_STATES
                && let Some(oldest) = self
                    .peers
                    .iter()
                    .min_by_key(|(_, state)| state.last_seen)
                    .map(|(key, _)| *key)
            {
                self.peers.remove(&oldest);
            }
        }
        let state = self
            .peers
            .entry(key)
            .or_insert_with(|| PeerAbuseState::new(now));
        state.last_seen = now;
        state
    }

    pub(crate) fn note_out_of_part(
        &mut self,
        peer: SocketAddr,
        user_hash: Option<[u8; 16]>,
        now: Instant,
    ) -> OutOfPartRecord {
        let state = self.state_mut(peer, user_hash, now);
        PeerAbuseState::refresh_window(
            now,
            &mut state.out_of_part_short_window_start,
            &mut state.out_of_part_short_window_count,
            OUT_OF_PART_SHORT_WINDOW,
        );
        state.out_of_part_short_window_count += 1;
        PeerAbuseState::refresh_window(
            now,
            &mut state.out_of_part_long_window_start,
            &mut state.out_of_part_long_window_count,
            OUT_OF_PART_LONG_WINDOW,
        );
        state.out_of_part_long_window_count += 1;

        if !state.out_of_part_quarantined
            && state.out_of_part_long_window_count >= OUT_OF_PART_LONG_QUARANTINE_THRESHOLD
        {
            state.out_of_part_quarantined = true;
            state.out_of_part_cooldown_until = None;
            return state.out_of_part_record(now, OutOfPartDisposition::QuarantinedLongWindow);
        }

        let cooldown_active = state
            .out_of_part_cooldown_until
            .is_some_and(|until| now < until);
        if !state.out_of_part_quarantined
            && !cooldown_active
            && state.out_of_part_short_window_count >= OUT_OF_PART_COOLDOWN_THRESHOLD
        {
            state.out_of_part_cooldown_bursts += 1;
            if state.out_of_part_cooldown_bursts >= OUT_OF_PART_BURST_QUARANTINE_THRESHOLD {
                state.out_of_part_quarantined = true;
                state.out_of_part_cooldown_until = None;
                return state
                    .out_of_part_record(now, OutOfPartDisposition::QuarantinedCooldownBursts);
            }
            state.out_of_part_cooldown_until = Some(now + OUT_OF_PART_COOLDOWN);
            return state.out_of_part_record(now, OutOfPartDisposition::Cooldown);
        }

        state.out_of_part_record(now, OutOfPartDisposition::Observed)
    }

    pub(crate) fn accept_guard(
        &mut self,
        peer: SocketAddr,
        user_hash: Option<[u8; 16]>,
        now: Instant,
    ) -> OutOfPartAcceptGuard {
        let state = self.state_mut(peer, user_hash, now);
        let cooldown_remaining = state
            .out_of_part_cooldown_until
            .and_then(|until| until.checked_duration_since(now))
            .filter(|remaining| !remaining.is_zero());
        if state.out_of_part_quarantined || cooldown_remaining.is_some() {
            OutOfPartAcceptGuard::Suppressed {
                quarantined: state.out_of_part_quarantined,
                cooldown_remaining,
                long_window_count: state.out_of_part_long_window_count,
            }
        } else {
            OutOfPartAcceptGuard::Allowed
        }
    }

    pub(crate) fn note_out_of_part_suppression(
        &mut self,
        peer: SocketAddr,
        user_hash: Option<[u8; 16]>,
        now: Instant,
    ) -> OutOfPartSuppressionRecord {
        let state = self.state_mut(peer, user_hash, now);
        PeerAbuseState::refresh_window(
            now,
            &mut state.out_of_part_long_window_start,
            &mut state.out_of_part_long_window_count,
            OUT_OF_PART_LONG_WINDOW,
        );
        state.out_of_part_long_window_count += 1;
        let newly_quarantined = !state.out_of_part_quarantined
            && state.out_of_part_long_window_count >= OUT_OF_PART_LONG_QUARANTINE_THRESHOLD;
        if newly_quarantined {
            state.out_of_part_quarantined = true;
            state.out_of_part_cooldown_until = None;
        }
        OutOfPartSuppressionRecord {
            long_window_count: state.out_of_part_long_window_count,
            newly_quarantined,
        }
    }

    pub(crate) fn note_queue_rank(
        &mut self,
        peer: SocketAddr,
        user_hash: Option<[u8; 16]>,
        expected: bool,
        downloading: bool,
        now: Instant,
    ) -> QueueRankDecision {
        let state = self.state_mut(peer, user_hash, now);
        if expected {
            state.queue_rank_unsolicited = 0;
            return QueueRankDecision::Accept;
        }
        if downloading {
            return QueueRankDecision::Accept;
        }

        state.queue_rank_unsolicited = state
            .queue_rank_unsolicited
            .saturating_add(1)
            .min(QUEUE_RANK_FLOOD_THRESHOLD);
        if state.queue_rank_unsolicited < QUEUE_RANK_FLOOD_THRESHOLD {
            return QueueRankDecision::Accept;
        }

        if state.queue_rank_bad_requests < QUEUE_RANK_BAN_BAD_REQUESTS {
            state.queue_rank_bad_requests += 1;
        }
        if state.queue_rank_bad_requests == QUEUE_RANK_BAN_BAD_REQUESTS {
            let decision = QueueRankDecision::Ban {
                unsolicited_count: state.queue_rank_unsolicited,
                tracked_bad_requests: state.queue_rank_bad_requests,
            };
            // MFC resets the two tracked bad requests before applying the ban so
            // expiry does not immediately re-ban the client.
            state.queue_rank_bad_requests = 0;
            state.queue_rank_unsolicited = 0;
            decision
        } else {
            QueueRankDecision::Disconnect {
                unsolicited_count: state.queue_rank_unsolicited,
                tracked_bad_requests: state.queue_rank_bad_requests,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        "198.51.100.17:4662".parse().unwrap()
    }

    #[test]
    fn three_out_of_part_events_start_two_minute_cooldown() {
        let mut tracker = DownloadAbuseTracker::default();
        let start = Instant::now();
        assert_eq!(
            tracker.note_out_of_part(peer(), None, start).disposition,
            OutOfPartDisposition::Observed
        );
        tracker.note_out_of_part(peer(), None, start + Duration::from_secs(5));
        let third = tracker.note_out_of_part(peer(), None, start + Duration::from_secs(10));
        assert_eq!(third.disposition, OutOfPartDisposition::Cooldown);
        assert_eq!(third.short_window_count, 3);
        assert_eq!(third.cooldown_bursts, 1);
        assert_eq!(third.cooldown_remaining, Some(OUT_OF_PART_COOLDOWN));
        assert!(matches!(
            tracker.accept_guard(peer(), None, start + Duration::from_secs(11)),
            OutOfPartAcceptGuard::Suppressed {
                quarantined: false,
                ..
            }
        ));
        assert_eq!(
            tracker.accept_guard(peer(), None, start + Duration::from_secs(130)),
            OutOfPartAcceptGuard::Allowed
        );
    }

    #[test]
    fn second_short_burst_quarantines_source_for_runtime() {
        let mut tracker = DownloadAbuseTracker::default();
        let start = Instant::now();
        for seconds in [0, 1, 2] {
            tracker.note_out_of_part(peer(), None, start + Duration::from_secs(seconds));
        }
        let second_start = start + OUT_OF_PART_COOLDOWN + Duration::from_secs(3);
        tracker.note_out_of_part(peer(), None, second_start);
        tracker.note_out_of_part(peer(), None, second_start + Duration::from_secs(1));
        let result = tracker.note_out_of_part(peer(), None, second_start + Duration::from_secs(2));
        assert_eq!(
            result.disposition,
            OutOfPartDisposition::QuarantinedCooldownBursts
        );
        assert!(matches!(
            tracker.accept_guard(peer(), None, second_start + Duration::from_secs(600)),
            OutOfPartAcceptGuard::Suppressed {
                quarantined: true,
                ..
            }
        ));
    }

    #[test]
    fn ten_long_window_events_quarantine_even_during_cooldown() {
        let mut tracker = DownloadAbuseTracker::default();
        let start = Instant::now();
        let mut last = OutOfPartDisposition::Observed;
        for offset in 0..10 {
            last = tracker
                .note_out_of_part(peer(), None, start + Duration::from_secs(offset))
                .disposition;
        }
        assert_eq!(last, OutOfPartDisposition::QuarantinedLongWindow);
    }

    #[test]
    fn suppressed_accepts_feed_long_window_quarantine() {
        let mut tracker = DownloadAbuseTracker::default();
        let start = Instant::now();
        for offset in 0..3 {
            tracker.note_out_of_part(peer(), None, start + Duration::from_secs(offset));
        }
        let mut last = OutOfPartSuppressionRecord {
            long_window_count: 0,
            newly_quarantined: false,
        };
        for offset in 3..10 {
            last = tracker.note_out_of_part_suppression(
                peer(),
                None,
                start + Duration::from_secs(offset),
            );
        }
        assert_eq!(last.long_window_count, 10);
        assert!(last.newly_quarantined);
    }

    #[test]
    fn queue_rank_flood_disconnects_then_bans_across_connections() {
        let mut tracker = DownloadAbuseTracker::default();
        let start = Instant::now();
        for offset in 0..2 {
            assert_eq!(
                tracker.note_queue_rank(
                    peer(),
                    Some([7; 16]),
                    false,
                    false,
                    start + Duration::from_secs(offset),
                ),
                QueueRankDecision::Accept
            );
        }
        assert_eq!(
            tracker.note_queue_rank(
                peer(),
                Some([7; 16]),
                false,
                false,
                start + Duration::from_secs(2),
            ),
            QueueRankDecision::Disconnect {
                unsolicited_count: 3,
                tracked_bad_requests: 1,
            }
        );
        // The next connection uses another source port but the same hash and
        // reaches the second tracked bad request immediately.
        assert_eq!(
            tracker.note_queue_rank(
                "198.51.100.17:4888".parse().unwrap(),
                Some([7; 16]),
                false,
                false,
                start + Duration::from_secs(3),
            ),
            QueueRankDecision::Ban {
                unsolicited_count: 3,
                tracked_bad_requests: 2,
            }
        );
    }

    #[test]
    fn expected_rank_clears_unsolicited_counter() {
        let mut tracker = DownloadAbuseTracker::default();
        let start = Instant::now();
        tracker.note_queue_rank(peer(), None, false, false, start);
        tracker.note_queue_rank(peer(), None, true, false, start + Duration::from_secs(1));
        for offset in 2..4 {
            assert_eq!(
                tracker.note_queue_rank(
                    peer(),
                    None,
                    false,
                    false,
                    start + Duration::from_secs(offset),
                ),
                QueueRankDecision::Accept
            );
        }
    }
}
