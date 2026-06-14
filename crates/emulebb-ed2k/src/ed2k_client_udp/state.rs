//! Per-source reask state, cadence policy, and the downloader-side reaction
//! table (`docs/design/udp-source-reask.md` §4.1-§4.4). Pure: no socket, no
//! transport — drives the per-transfer reask ticker.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use emulebb_kad_proto::Ed2kHash;

/// Nominal per-source reask interval (`FILEREASKTIME`, eMuleBB opcodes.h).
pub(crate) const FILE_REASK_TIME: Duration = Duration::from_secs(29 * 60);
/// Minimum spacing between reasks to one source (`MIN_REQUESTTIME`).
pub(crate) const MIN_REQUEST_TIME: Duration = Duration::from_secs(10 * 60);
/// Uploader-side: how long a just-asked slot is held warm (`UDPMAXQUEUETIME`).
pub(crate) const UDP_MAX_QUEUE_TIME: Duration = Duration::from_secs(20);
/// Failure-ratio backoff gate: stop UDP-reasking a source once it has had more
/// than this many attempts and the failure ratio exceeds `UDP_FAILURE_RATIO`.
const UDP_FAILURE_MIN_ATTEMPTS: u32 = 3;
const UDP_FAILURE_RATIO: f64 = 0.3;

/// Live reask state for one queued, TCP-detached source (eMuleBB
/// `QueuedDetached`): we hold its queue slot purely by periodic UDP reask, with
/// no socket open. Drives the per-transfer reask ticker.
#[derive(Debug, Clone)]
pub(crate) struct ReaskSource {
    pub endpoint: (Ipv4Addr, u16),
    pub file_hash: Ed2kHash,
    pub udp_version: u8,
    /// Our last known queue rank on this source (0 == queue full / unknown).
    pub last_rank: Option<u16>,
    /// When the next reask is due.
    pub next_reask: Instant,
    pub udp_total: u32,
    pub udp_failed: u32,
    /// Set once the UDP failure ratio is bad; subsequent reasks use TCP.
    pub fallback_tcp_only: bool,
    /// Whether the source has no parts we currently need (doubles the interval).
    pub no_needed_parts: bool,
    /// Set when the last reply was `OP_QUEUEFULL`; cleared on a real rank ack.
    pub remote_queue_full: bool,
    /// The peer's eD2k user hash — obfuscation key material for outbound reasks.
    /// `None` until learned (then reasks to it can be obfuscated).
    pub user_hash: Option<[u8; 16]>,
    /// Whether to obfuscate reasks to this peer (`ShouldReceiveCryptUDPPackets`).
    pub should_crypt: bool,
}

impl ReaskSource {
    pub(crate) fn new(
        endpoint: (Ipv4Addr, u16),
        file_hash: Ed2kHash,
        udp_version: u8,
        now: Instant,
    ) -> Self {
        Self {
            endpoint,
            file_hash,
            udp_version,
            last_rank: None,
            // Reask immediately on entry; the ticker spaces subsequent reasks.
            next_reask: now,
            udp_total: 0,
            udp_failed: 0,
            fallback_tcp_only: false,
            no_needed_parts: false,
            remote_queue_full: false,
            user_hash: None,
            should_crypt: false,
        }
    }

    /// Attach the peer's obfuscation key material (learned from the download
    /// session) so reasks to this source can be encrypted.
    pub(crate) fn with_obfuscation(mut self, user_hash: [u8; 16], should_crypt: bool) -> Self {
        self.user_hash = Some(user_hash);
        self.should_crypt = should_crypt;
        self
    }

    pub(crate) fn is_due(&self, now: Instant) -> bool {
        now >= self.next_reask
    }

    /// Schedules the next reask one cadence interval out.
    pub(crate) fn schedule_next(&mut self, now: Instant) {
        self.next_reask = now + reask_interval(self.no_needed_parts);
    }

    /// Records a successful reask reply with our updated queue rank.
    pub(crate) fn record_success(&mut self, rank: u16, now: Instant) {
        self.udp_total = self.udp_total.saturating_add(1);
        self.last_rank = Some(rank);
        self.remote_queue_full = false;
        self.schedule_next(now);
    }

    /// Records a reask with no reply; flips to TCP fallback once the failure
    /// ratio is bad. Returns whether UDP is now disqualified for this source.
    pub(crate) fn record_failure(&mut self, now: Instant) -> bool {
        self.udp_total = self.udp_total.saturating_add(1);
        self.udp_failed = self.udp_failed.saturating_add(1);
        if should_fall_back_to_tcp(self.udp_total, self.udp_failed) {
            self.fallback_tcp_only = true;
        }
        self.schedule_next(now);
        self.fallback_tcp_only
    }
}

/// A decoded inbound reask reply (or the no-reply timeout) for one source,
/// classified so the downloader-side reaction is a single pure decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReaskReply {
    /// `OP_REASKACK` with our updated queue rank.
    Ack { rank: u16 },
    /// `OP_QUEUEFULL`: still queued but the uploader's queue is full.
    QueueFull,
    /// `OP_FILENOTFOUND`: the source no longer has this file.
    FileNotFound,
    /// No reply arrived within the reask deadline.
    Timeout,
}

/// The action the per-transfer reask driver should take after a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReaskAction {
    /// Keep the source; our queue rank was refreshed.
    UpdatedRank(u16),
    /// Keep the source; the uploader's queue is full (treated as rank 0).
    QueueFull,
    /// Remove the source from this transfer (it no longer has the file).
    DropSource,
    /// UDP is disqualified for this source — reask over TCP next cadence.
    RetryTcp,
    /// Transient miss — retry over UDP on the next cadence.
    RetryUdp,
}

/// The downloader-side reaction table (`udp-source-reask.md` §4.4): maps a
/// decoded reply onto the next source state + driver action. Pure — mutates only
/// the passed `ReaskSource`; the transport/registry pending-gate is applied by
/// the caller before this. `OP_QUEUEFULL` counts as a received reply (improves
/// the failure ratio), not a failure; only `Timeout` increments failures and may
/// flip the source to TCP fallback.
pub(crate) fn apply_reask_reply(
    source: &mut ReaskSource,
    reply: ReaskReply,
    now: Instant,
) -> ReaskAction {
    match reply {
        ReaskReply::Ack { rank } => {
            source.record_success(rank, now);
            ReaskAction::UpdatedRank(rank)
        }
        ReaskReply::QueueFull => {
            // A reply was received (so it counts toward the total, not failures),
            // the slot is kept, and the rank is treated as 0 / queue-full.
            source.udp_total = source.udp_total.saturating_add(1);
            source.last_rank = Some(0);
            source.remote_queue_full = true;
            source.schedule_next(now);
            ReaskAction::QueueFull
        }
        ReaskReply::FileNotFound => ReaskAction::DropSource,
        ReaskReply::Timeout => {
            if source.record_failure(now) {
                ReaskAction::RetryTcp
            } else {
                ReaskAction::RetryUdp
            }
        }
    }
}

/// Per-source reask interval: nominal `FILE_REASK_TIME`, doubled for
/// no-needed-parts sources, never below `MIN_REQUEST_TIME` (mirrors
/// `CUpDownClient::GetTimeUntilReask`-style spacing).
pub(crate) fn reask_interval(no_needed_parts: bool) -> Duration {
    let base = if no_needed_parts {
        FILE_REASK_TIME.saturating_mul(2)
    } else {
        FILE_REASK_TIME
    };
    base.max(MIN_REQUEST_TIME)
}

/// Whether a queued source is eligible for UDP reask (eMuleBB
/// `UDPReaskForDownload` preconditions): the source advertised a UDP port and a
/// non-zero udp_version, we have a local UDP port, we are not firewalled, there
/// is no live TCP socket to it, and no proxy is configured.
pub(crate) fn udp_reask_eligible(
    source_udp_port: u16,
    source_udp_version: u8,
    have_local_udp_port: bool,
    self_firewalled: bool,
    has_live_tcp_socket: bool,
    proxy_configured: bool,
) -> bool {
    source_udp_port != 0
        && source_udp_version != 0
        && have_local_udp_port
        && !self_firewalled
        && !has_live_tcp_socket
        && !proxy_configured
}

/// Whether UDP reask for a source should fall back to TCP because its UDP
/// failure ratio is bad (`total > 3 && failed/total > 0.3`).
pub(crate) fn should_fall_back_to_tcp(udp_total: u32, udp_failed: u32) -> bool {
    udp_total > UDP_FAILURE_MIN_ATTEMPTS
        && f64::from(udp_failed) / f64::from(udp_total) > UDP_FAILURE_RATIO
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash() -> Ed2kHash {
        Ed2kHash::from_bytes([
            0x9e, 0xce, 0xd4, 0x7d, 0xf2, 0xed, 0xfb, 0xd7, 0x2f, 0x29, 0xf9, 0x34, 0x47, 0xd6,
            0x0b, 0x7b,
        ])
    }

    #[test]
    fn reask_interval_doubles_for_no_needed_parts() {
        assert_eq!(reask_interval(false), FILE_REASK_TIME);
        assert_eq!(reask_interval(true), FILE_REASK_TIME * 2);
        // Nominal interval always clears the minimum spacing floor.
        assert!(reask_interval(false) >= MIN_REQUEST_TIME);
        // Keep UDP_MAX_QUEUE_TIME referenced (uploader-side warm-hold constant).
        assert!(UDP_MAX_QUEUE_TIME < MIN_REQUEST_TIME);
    }

    #[test]
    fn udp_eligibility_requires_all_preconditions() {
        // All good -> eligible.
        assert!(udp_reask_eligible(4672, 4, true, false, false, false));
        // Each disqualifier individually blocks UDP reask.
        assert!(!udp_reask_eligible(0, 4, true, false, false, false)); // no source UDP port
        assert!(!udp_reask_eligible(4672, 0, true, false, false, false)); // udp_version 0
        assert!(!udp_reask_eligible(4672, 4, false, false, false, false)); // no local UDP port
        assert!(!udp_reask_eligible(4672, 4, true, true, false, false)); // firewalled
        assert!(!udp_reask_eligible(4672, 4, true, false, true, false)); // live TCP socket held
        assert!(!udp_reask_eligible(4672, 4, true, false, false, true)); // proxy configured
    }

    #[test]
    fn failure_ratio_backoff_threshold() {
        assert!(!should_fall_back_to_tcp(0, 0));
        assert!(!should_fall_back_to_tcp(3, 3)); // not > 3 attempts yet
        assert!(!should_fall_back_to_tcp(10, 3)); // 0.3 ratio, not > 0.3
        assert!(should_fall_back_to_tcp(10, 4)); // 0.4 > 0.3
        assert!(should_fall_back_to_tcp(4, 2)); // 0.5 > 0.3, > 3 attempts
    }

    #[test]
    fn reask_source_success_updates_rank_and_reschedules() {
        let now = Instant::now();
        let mut source = ReaskSource::new((Ipv4Addr::new(198, 51, 100, 5), 4672), hash(), 4, now);
        assert!(source.is_due(now)); // reasks immediately on entry
        source.record_success(12, now);
        assert_eq!(source.last_rank, Some(12));
        assert_eq!(source.udp_total, 1);
        assert_eq!(source.udp_failed, 0);
        assert!(!source.is_due(now)); // rescheduled one interval out
        assert!(source.is_due(now + reask_interval(false)));
    }

    #[test]
    fn reask_source_failures_flip_to_tcp_fallback() {
        let now = Instant::now();
        let mut source = ReaskSource::new((Ipv4Addr::new(198, 51, 100, 6), 4672), hash(), 4, now);
        // 4 attempts, all failed -> ratio 1.0 > 0.3 with > 3 attempts.
        for _ in 0..3 {
            assert!(!source.record_failure(now));
        }
        assert!(source.record_failure(now)); // 4th failure trips the backoff
        assert!(source.fallback_tcp_only);
        assert_eq!(source.udp_failed, 4);
    }

    #[test]
    fn reask_source_no_needed_parts_doubles_interval() {
        let now = Instant::now();
        let mut source = ReaskSource::new((Ipv4Addr::new(198, 51, 100, 7), 4672), hash(), 4, now);
        source.no_needed_parts = true;
        source.schedule_next(now);
        assert!(!source.is_due(now + FILE_REASK_TIME)); // not due at single interval
        assert!(source.is_due(now + FILE_REASK_TIME * 2));
    }

    #[test]
    fn reaction_ack_updates_rank_and_clears_queue_full() {
        let now = Instant::now();
        let mut source = ReaskSource::new((Ipv4Addr::new(198, 51, 100, 8), 4672), hash(), 4, now);
        source.remote_queue_full = true;
        let action = apply_reask_reply(&mut source, ReaskReply::Ack { rank: 7 }, now);
        assert_eq!(action, ReaskAction::UpdatedRank(7));
        assert_eq!(source.last_rank, Some(7));
        assert!(!source.remote_queue_full);
        assert_eq!(source.udp_total, 1);
        assert_eq!(source.udp_failed, 0);
    }

    #[test]
    fn reaction_queue_full_keeps_source_as_rank_zero_not_a_failure() {
        let now = Instant::now();
        let mut source = ReaskSource::new((Ipv4Addr::new(198, 51, 100, 9), 4672), hash(), 4, now);
        let action = apply_reask_reply(&mut source, ReaskReply::QueueFull, now);
        assert_eq!(action, ReaskAction::QueueFull);
        assert_eq!(source.last_rank, Some(0));
        assert!(source.remote_queue_full);
        // A received reply counts toward the total but is not a failure.
        assert_eq!(source.udp_total, 1);
        assert_eq!(source.udp_failed, 0);
        assert!(!source.is_due(now)); // rescheduled
    }

    #[test]
    fn reaction_file_not_found_drops_the_source() {
        let now = Instant::now();
        let mut source = ReaskSource::new((Ipv4Addr::new(198, 51, 100, 10), 4672), hash(), 4, now);
        assert_eq!(
            apply_reask_reply(&mut source, ReaskReply::FileNotFound, now),
            ReaskAction::DropSource
        );
    }

    #[test]
    fn reaction_timeout_retries_udp_then_falls_back_to_tcp() {
        let now = Instant::now();
        let mut source = ReaskSource::new((Ipv4Addr::new(198, 51, 100, 11), 4672), hash(), 4, now);
        // First failures retry over UDP until the ratio backoff trips.
        for _ in 0..3 {
            assert_eq!(
                apply_reask_reply(&mut source, ReaskReply::Timeout, now),
                ReaskAction::RetryUdp
            );
        }
        // 4th timeout (> 3 attempts, ratio 1.0) flips to TCP fallback.
        assert_eq!(
            apply_reask_reply(&mut source, ReaskReply::Timeout, now),
            ReaskAction::RetryTcp
        );
        assert!(source.fallback_tcp_only);
        assert_eq!(source.udp_failed, 4);
    }
}
