//! Per-transfer set of TCP-detached reask sources + the pending-reply gate — the
//! state container the core download runtime's reask ticker owns. Composes
//! [`super::ReaskSource`] (per-source state + cadence), the
//! [`super::ReaskPendingRegistry`] (anti-spoof gate) and the
//! [`super::apply_reask_reply`] reaction table. Pure (no I/O, no socket); the
//! ticker drives it and performs the actual sends. `docs/design/udp-source-reask.md`
//! §4.1-§4.4.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use emulebb_kad_proto::Ed2kHash;

use super::outbound::{OutboundReaskTarget, build_reask_file_ping_datagram};
use super::registry::ReaskPendingRegistry;
use super::state::{ReaskAction, ReaskReply, ReaskSource, apply_reask_reply};

/// The reask sources for one download transfer, keyed by UDP endpoint.
#[derive(Debug, Default)]
pub(crate) struct ReaskSourceSet {
    sources: HashMap<(Ipv4Addr, u16), ReaskSource>,
    pending: ReaskPendingRegistry,
}

impl ReaskSourceSet {
    pub(crate) fn new() -> Self {
        Self {
            sources: HashMap::new(),
            pending: ReaskPendingRegistry::new(),
        }
    }

    /// Add a queued, already-eligibility-checked source in detached reask state
    /// (§4.1). The caller decides UDP-eligibility via
    /// [`super::udp_reask_eligible`] and builds the [`ReaskSource`].
    pub(crate) fn insert(&mut self, source: ReaskSource) {
        self.sources.insert(source.endpoint, source);
    }

    /// Endpoints whose next reask is due *and* have no reply outstanding — the
    /// ticker reasks exactly these (one in-flight reask per source).
    pub(crate) fn due(&self, now: Instant) -> Vec<(Ipv4Addr, u16)> {
        self.sources
            .iter()
            .filter(|((ip, port), source)| {
                source.is_due(now) && !self.pending.is_pending(*ip, *port)
            })
            .map(|(endpoint, _)| *endpoint)
            .collect()
    }

    /// Build the outbound `OP_REASKFILEPING` datagrams for every source that is
    /// due (and not already awaiting a reply), marking each pending. The ticker
    /// sends each `(endpoint, bytes)` via `RpcManager::send_raw_datagram`.
    /// UDP-disqualified sources (`fallback_tcp_only`) are skipped — the caller
    /// reasks those over TCP. Transfer-level inputs (`our_part_status`,
    /// `complete_source_count`, `our_udp_version`, `our_public_ip`) are passed in;
    /// per-source obfuscation comes from the source's learned `user_hash`.
    pub(crate) fn due_datagrams(
        &mut self,
        now: Instant,
        our_part_status: Option<&[bool]>,
        complete_source_count: u16,
        our_udp_version: u8,
        our_public_ip: [u8; 4],
    ) -> Vec<((Ipv4Addr, u16), Vec<u8>)> {
        let mut out = Vec::new();
        for (ip, udp_port) in self.due(now) {
            let Some(source) = self.sources.get(&(ip, udp_port)) else {
                continue;
            };
            if source.fallback_tcp_only {
                continue; // UDP disqualified — caller reasks over TCP
            }
            let target = OutboundReaskTarget {
                dest_user_hash: source.user_hash.unwrap_or([0u8; 16]),
                our_public_ip,
                // Only obfuscate when we actually hold the peer's key.
                obfuscate: source.should_crypt && source.user_hash.is_some(),
            };
            let datagram = build_reask_file_ping_datagram(
                &source.file_hash,
                our_part_status,
                complete_source_count,
                our_udp_version,
                &target,
            );
            self.mark_reasked(ip, udp_port, now);
            out.push(((ip, udp_port), datagram));
        }
        out
    }

    /// Mark that a reask was just sent to `endpoint` (opens the pending-reply
    /// gate). The source reschedules when the reply or timeout lands.
    pub(crate) fn mark_reasked(&mut self, ip: Ipv4Addr, udp_port: u16, now: Instant) {
        if let Some(source) = self.sources.get(&(ip, udp_port)) {
            let file_hash = source.file_hash;
            self.pending.mark_sent(ip, udp_port, file_hash, now);
        }
    }

    /// Apply a *received* reply (`Ack`/`QueueFull`/`FileNotFound`) to the source,
    /// gated by the pending registry: an unsolicited reply (no outstanding reask)
    /// returns `None` and is dropped (R3 anti-spoof). Removes the source on
    /// `FileNotFound`. `Timeout` is handled by [`Self::drain_timeouts`], not here.
    pub(crate) fn apply_reply(
        &mut self,
        ip: Ipv4Addr,
        udp_port: u16,
        reply: ReaskReply,
        now: Instant,
    ) -> Option<ReaskAction> {
        // Anti-spoof correlation gate: only accept a reply we asked for.
        self.pending.take_reply(ip, udp_port)?;
        let source = self.sources.get_mut(&(ip, udp_port))?;
        let action = apply_reask_reply(source, reply, now);
        if matches!(action, ReaskAction::DropSource) {
            self.sources.remove(&(ip, udp_port));
        }
        Some(action)
    }

    /// Reasks with no reply within `timeout` count as UDP failures: clears the
    /// pending entry and applies the timeout reaction (record_failure → cadence
    /// reschedule, flipping to TCP fallback past the failure-ratio threshold).
    /// Returns the per-endpoint action (`RetryUdp` / `RetryTcp`).
    pub(crate) fn drain_timeouts(
        &mut self,
        now: Instant,
        timeout: Duration,
    ) -> Vec<((Ipv4Addr, u16), ReaskAction)> {
        self.pending
            .drain_timed_out(now, timeout)
            .into_iter()
            .filter_map(|((ip, port), _)| {
                let source = self.sources.get_mut(&(ip, port))?;
                Some(((ip, port), apply_reask_reply(source, ReaskReply::Timeout, now)))
            })
            .collect()
    }

    /// Explicitly drop a source (e.g. the transfer no longer needs it).
    pub(crate) fn remove(&mut self, ip: Ipv4Addr, udp_port: u16) {
        self.sources.remove(&(ip, udp_port));
        self.pending.take_reply(ip, udp_port);
    }

    pub(crate) fn get(&self, ip: Ipv4Addr, udp_port: u16) -> Option<&ReaskSource> {
        self.sources.get(&(ip, udp_port))
    }

    pub(crate) fn len(&self) -> usize {
        self.sources.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
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

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, last)
    }

    fn source(set: &mut ReaskSourceSet, last: u8, now: Instant) -> (Ipv4Addr, u16) {
        let endpoint = (ip(last), 4672);
        set.insert(ReaskSource::new(endpoint, hash(), 4, now));
        endpoint
    }

    #[test]
    fn due_lists_fresh_sources_then_excludes_pending() {
        let now = Instant::now();
        let mut set = ReaskSourceSet::new();
        let (a, pa) = source(&mut set, 1, now);
        // A freshly inserted source reasks immediately.
        assert_eq!(set.due(now), vec![(a, pa)]);
        // Once a reask is outstanding it is no longer "due" (one in-flight reask).
        set.mark_reasked(a, pa, now);
        assert!(set.due(now).is_empty());
    }

    #[test]
    fn ack_reply_is_gated_then_updates_rank_and_reschedules() {
        let now = Instant::now();
        let mut set = ReaskSourceSet::new();
        let (a, pa) = source(&mut set, 2, now);
        // Unsolicited ack (no pending reask) is dropped.
        assert!(set.apply_reply(a, pa, ReaskReply::Ack { rank: 5 }, now).is_none());
        // After a reask is outstanding, the ack is accepted.
        set.mark_reasked(a, pa, now);
        assert_eq!(
            set.apply_reply(a, pa, ReaskReply::Ack { rank: 5 }, now),
            Some(ReaskAction::UpdatedRank(5))
        );
        assert_eq!(set.get(a, pa).unwrap().last_rank, Some(5));
        // Reply consumed the pending entry and the source rescheduled (not due now).
        assert!(set.due(now).is_empty());
    }

    #[test]
    fn file_not_found_drops_the_source() {
        let now = Instant::now();
        let mut set = ReaskSourceSet::new();
        let (a, pa) = source(&mut set, 3, now);
        set.mark_reasked(a, pa, now);
        assert_eq!(
            set.apply_reply(a, pa, ReaskReply::FileNotFound, now),
            Some(ReaskAction::DropSource)
        );
        assert!(set.get(a, pa).is_none());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn queue_full_keeps_source_and_is_not_a_failure() {
        let now = Instant::now();
        let mut set = ReaskSourceSet::new();
        let (a, pa) = source(&mut set, 4, now);
        set.mark_reasked(a, pa, now);
        assert_eq!(
            set.apply_reply(a, pa, ReaskReply::QueueFull, now),
            Some(ReaskAction::QueueFull)
        );
        let src = set.get(a, pa).unwrap();
        assert!(src.remote_queue_full);
        assert_eq!(src.udp_failed, 0);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn timeouts_drain_as_failures_and_eventually_fall_back_to_tcp() {
        let now = Instant::now();
        let timeout = Duration::from_secs(20);
        let mut set = ReaskSourceSet::new();
        let (a, pa) = source(&mut set, 5, now);

        // Drive four timed-out reasks; the 4th trips the >3-attempts ratio backoff.
        let mut last_action = None;
        for i in 0..4 {
            let sent_at = now + Duration::from_secs(i * 60);
            set.mark_reasked(a, pa, sent_at);
            let drained = set.drain_timeouts(sent_at + timeout + Duration::from_secs(1), timeout);
            assert_eq!(drained.len(), 1);
            last_action = Some(drained[0].1);
        }
        assert_eq!(last_action, Some(ReaskAction::RetryTcp));
        assert!(set.get(a, pa).unwrap().fallback_tcp_only);
        assert_eq!(set.get(a, pa).unwrap().udp_failed, 4);
    }

    #[test]
    fn due_datagrams_builds_pings_marks_pending_and_skips_tcp_fallback() {
        use super::super::dispatch::{InboundReaskMessage, parse_inbound_reask_datagram};

        let now = Instant::now();
        let our_ip = [203, 0, 113, 9];
        let peer_hash = [0x55u8; 16];
        let mut set = ReaskSourceSet::new();

        // One obfuscation-capable due source.
        let endpoint = (ip(8), 4672);
        set.insert(
            ReaskSource::new(endpoint, hash(), 4, now).with_obfuscation(peer_hash, true),
        );

        let datagrams = set.due_datagrams(now, Some(&[true, false, true]), 2, 4, our_ip);
        assert_eq!(datagrams.len(), 1);
        assert_eq!(datagrams[0].0, endpoint);

        // The built datagram is a valid OP_REASKFILEPING the peer (keying on its
        // own hash == peer_hash + our IP as the sender) can parse back.
        let msg = parse_inbound_reask_datagram(&datagrams[0].1, our_ip, &peer_hash, 4)
            .expect("peer should parse our reask");
        match msg {
            InboundReaskMessage::FilePing(ping) => {
                assert_eq!(ping.file_hash, hash());
                assert_eq!(ping.complete_source_count, Some(2));
            }
            other => panic!("expected FilePing, got {other:?}"),
        }

        // The source is now pending, so it is no longer due.
        assert!(set.due(now).is_empty());

        // A TCP-fallback source produces no datagram.
        let tcp_endpoint = (ip(9), 4672);
        let mut tcp_src = ReaskSource::new(tcp_endpoint, hash(), 4, now);
        tcp_src.fallback_tcp_only = true;
        set.insert(tcp_src);
        let next = set.due_datagrams(now, None, 0, 4, our_ip);
        assert!(
            next.iter().all(|(ep, _)| *ep != tcp_endpoint),
            "tcp-fallback source must not get a UDP reask datagram"
        );
    }

    #[test]
    fn multiple_sources_are_tracked_independently() {
        let now = Instant::now();
        let mut set = ReaskSourceSet::new();
        let (a, pa) = source(&mut set, 6, now);
        let (b, pb) = source(&mut set, 7, now);
        assert_eq!(set.len(), 2);
        // Reask only A; B stays due, A does not.
        set.mark_reasked(a, pa, now);
        let due = set.due(now);
        assert!(due.contains(&(b, pb)));
        assert!(!due.contains(&(a, pa)));
        set.remove(b, pb);
        assert_eq!(set.len(), 1);
        assert!(set.get(b, pb).is_none());
    }
}
