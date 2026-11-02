//! Anti-spoof correlation gate for client-UDP reask replies.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use emulebb_kad_proto::Ed2kHash;

/// One outstanding reask awaiting a reply, keyed by the source's UDP endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingReask {
    pub file_hash: Ed2kHash,
    pub sent_at: Instant,
    /// Our part-status snapshot from the exact request. It supplies both the
    /// expected V4 ACK part count and the local side of the usefulness verdict.
    pub request_part_status: Option<Vec<bool>>,
}

/// Anti-spoof correlation gate for client-UDP reask replies (eMuleBB
/// `m_bUDPPending` + `GetDownloadClientByIP_UDP`): a reply
/// (`OP_REASKACK`/`OP_QUEUEFULL`/`OP_FILENOTFOUND`) is accepted only when a reask
/// to that `(ip, udp_port)` is outstanding; unsolicited replies are dropped.
#[derive(Debug, Default)]
pub(crate) struct ReaskPendingRegistry {
    pending: HashMap<(Ipv4Addr, u16), PendingReask>,
}

impl ReaskPendingRegistry {
    pub(crate) fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    /// Marks a reask to `(ip, udp_port)` outstanding. One outstanding reask per
    /// source; a fresh send replaces any prior pending entry.
    pub(crate) fn mark_sent(
        &mut self,
        ip: Ipv4Addr,
        udp_port: u16,
        file_hash: Ed2kHash,
        request_part_status: Option<Vec<bool>>,
        now: Instant,
    ) {
        self.pending.insert(
            (ip, udp_port),
            PendingReask {
                file_hash,
                sent_at: now,
                request_part_status,
            },
        );
    }

    pub(crate) fn is_pending(&self, ip: Ipv4Addr, udp_port: u16) -> bool {
        self.pending.contains_key(&(ip, udp_port))
    }

    pub(crate) fn get(&self, ip: Ipv4Addr, udp_port: u16) -> Option<&PendingReask> {
        self.pending.get(&(ip, udp_port))
    }

    /// Accepts and clears the pending reask for a reply from `(ip, udp_port)`.
    /// Returns `None` for an unsolicited reply (the caller must drop it).
    pub(crate) fn take_reply(&mut self, ip: Ipv4Addr, udp_port: u16) -> Option<PendingReask> {
        self.pending.remove(&(ip, udp_port))
    }

    /// Removes and returns reasks with no reply within `timeout` (UDP failures,
    /// for failure-ratio backoff accounting).
    pub(crate) fn drain_timed_out(
        &mut self,
        now: Instant,
        timeout: Duration,
    ) -> Vec<((Ipv4Addr, u16), PendingReask)> {
        let expired: Vec<(Ipv4Addr, u16)> = self
            .pending
            .iter()
            .filter(|(_, reask)| now.saturating_duration_since(reask.sent_at) > timeout)
            .map(|(endpoint, _)| *endpoint)
            .collect();
        expired
            .into_iter()
            .filter_map(|endpoint| {
                self.pending
                    .remove(&endpoint)
                    .map(|reask| (endpoint, reask))
            })
            .collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.pending.len()
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

    #[test]
    fn pending_registry_correlates_replies_and_drops_unsolicited() {
        let mut registry = ReaskPendingRegistry::new();
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let now = Instant::now();
        // Unsolicited reply (no pending reask) -> dropped.
        assert!(registry.take_reply(ip, 4672).is_none());
        // After marking a reask outstanding, the matching reply is accepted once.
        registry.mark_sent(ip, 4672, hash(), Some(vec![true, false, true]), now);
        assert!(registry.is_pending(ip, 4672));
        let accepted = registry.take_reply(ip, 4672).expect("pending reply");
        assert_eq!(accepted.file_hash, hash());
        assert_eq!(accepted.request_part_status, Some(vec![true, false, true]));
        // A second reply for the same endpoint is now unsolicited.
        assert!(registry.take_reply(ip, 4672).is_none());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn pending_registry_drains_timed_out_reasks() {
        let mut registry = ReaskPendingRegistry::new();
        let ip = Ipv4Addr::new(203, 0, 113, 8);
        let start = Instant::now();
        registry.mark_sent(ip, 5000, hash(), None, start);
        // Not yet timed out.
        assert!(
            registry
                .drain_timed_out(start + Duration::from_secs(5), Duration::from_secs(30))
                .is_empty()
        );
        // Past the timeout -> drained as a UDP failure.
        let timed_out =
            registry.drain_timed_out(start + Duration::from_secs(31), Duration::from_secs(30));
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0].0, (ip, 5000));
        assert_eq!(registry.len(), 0);
    }
}
