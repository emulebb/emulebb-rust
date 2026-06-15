//! Outbound Kad request tracking for the oracle's "did we ask for this
//! response?" validation (`CPacketTracking::IsOnOutTrackList` /
//! `IsTrackedOutListRequestPacket`).

use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Tracks outbound Kad requests by IP and opcode for the oracle's "did we ask
/// for this response?" validation.
pub struct OutboundRequestTracker {
    entries: VecDeque<OutboundRequestEntry>,
    window: Duration,
}

#[derive(Debug, Clone, Copy)]
struct OutboundRequestEntry {
    inserted_at: Instant,
    ip: IpAddr,
    opcode: u8,
}

impl OutboundRequestTracker {
    /// Create a new outbound request tracker with the given retention window.
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            entries: VecDeque::new(),
            window,
        }
    }

    /// Record an outbound request if the oracle would track it.
    pub fn record(&mut self, ip: IpAddr, opcode: u8) {
        self.prune();
        if !tracks_outbound_request_opcode(opcode) {
            return;
        }
        self.entries.push_front(OutboundRequestEntry {
            inserted_at: Instant::now(),
            ip,
            opcode,
        });
    }

    /// Find a matching tracked request by IP and opcode.
    ///
    /// When `remove` is true the newest matching request is consumed, mirroring
    /// the oracle's list walk.
    #[must_use]
    pub fn contains(&mut self, ip: IpAddr, opcode: u8, remove: bool) -> bool {
        self.prune();
        for index in 0..self.entries.len() {
            let Some(entry) = self.entries.get(index).copied() else {
                continue;
            };
            if entry.ip == ip && entry.opcode == opcode {
                if remove {
                    let _ = self.entries.remove(index);
                }
                return true;
            }
        }
        false
    }

    /// Find the first matching opcode from the provided oracle-ordered set.
    #[must_use]
    pub fn find_any(&mut self, ip: IpAddr, opcodes: &[u8], remove: bool) -> Option<u8> {
        for opcode in opcodes {
            if self.contains(ip, *opcode, remove) {
                return Some(*opcode);
            }
        }
        None
    }

    fn prune(&mut self) {
        let now = Instant::now();
        while self
            .entries
            .back()
            .is_some_and(|entry| now.duration_since(entry.inserted_at) >= self.window)
        {
            let _ = self.entries.pop_back();
        }
    }
}

/// Whether the oracle out-tracks an outbound request of this opcode
/// (`IsTrackedOutListRequestPacket`). Both the Kad2 (0x35) and legacy (0x32)
/// notes-search opcodes are tracked.
fn tracks_outbound_request_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        emulebb_kad_proto::constants::opcode::BOOTSTRAP_REQ
            | emulebb_kad_proto::constants::opcode::HELLO_REQ
            | emulebb_kad_proto::constants::opcode::HELLO_RES
            | emulebb_kad_proto::constants::opcode::REQ
            | emulebb_kad_proto::constants::opcode::SEARCH_NOTES_REQ
            | emulebb_kad_proto::constants::opcode::SEARCH_NOTES_REQ_LEGACY
            | emulebb_kad_proto::constants::opcode::PUBLISH_KEY_REQ
            | emulebb_kad_proto::constants::opcode::PUBLISH_SOURCE_REQ
            | emulebb_kad_proto::constants::opcode::PUBLISH_NOTES_REQ
            | emulebb_kad_proto::constants::opcode::FINDBUDDY_REQ
            | emulebb_kad_proto::constants::opcode::CALLBACK_REQ
            | emulebb_kad_proto::constants::opcode::PING
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn outbound_request_tracker_matches_newest_request_by_ip_and_opcode() {
        let mut tracker = OutboundRequestTracker::new(Duration::from_secs(180));
        let ip = parse_ip("1.2.3.4");

        tracker.record(ip, emulebb_kad_proto::constants::opcode::PUBLISH_KEY_REQ);
        tracker.record(ip, emulebb_kad_proto::constants::opcode::PUBLISH_KEY_REQ);

        assert!(tracker.contains(
            ip,
            emulebb_kad_proto::constants::opcode::PUBLISH_KEY_REQ,
            true
        ));
        assert!(tracker.contains(
            ip,
            emulebb_kad_proto::constants::opcode::PUBLISH_KEY_REQ,
            true
        ));
        assert!(!tracker.contains(
            ip,
            emulebb_kad_proto::constants::opcode::PUBLISH_KEY_REQ,
            true
        ));
    }

    #[test]
    fn outbound_request_tracker_ignores_untracked_opcodes() {
        let mut tracker = OutboundRequestTracker::new(Duration::from_secs(180));
        let ip = parse_ip("1.2.3.4");

        tracker.record(ip, emulebb_kad_proto::constants::opcode::PUBLISH_RES);

        assert!(!tracker.contains(ip, emulebb_kad_proto::constants::opcode::PUBLISH_RES, false));
    }

    #[test]
    fn outbound_request_tracker_tracks_legacy_notes_search_opcode() {
        // Oracle IsTrackedOutListRequestPacket out-tracks both the Kad2 (0x35)
        // and legacy (0x32) notes-search request opcodes.
        let mut tracker = OutboundRequestTracker::new(Duration::from_secs(180));
        let ip = parse_ip("1.2.3.4");
        tracker.record(
            ip,
            emulebb_kad_proto::constants::opcode::SEARCH_NOTES_REQ_LEGACY,
        );
        assert!(tracker.contains(
            ip,
            emulebb_kad_proto::constants::opcode::SEARCH_NOTES_REQ_LEGACY,
            true,
        ));
    }
}
