//! Periodic routing-table upkeep mirroring the oracle `CRoutingZone` timers.
//!
//! The master refreshes its routing tree from two cadenced callbacks:
//!   - `OnSmallTimer` (~1 min/leaf): seed expiry windows, drop dead+expired
//!     contacts, and HELLO-probe the single lowest-quality expired contact per
//!     leaf to re-verify liveness (`RoutingZone.cpp:852-906`).
//!   - `OnBigTimer` (~10 s tick/leaf): per-zone random-target `FindNode` to keep
//!     buckets populated (`RoutingZone.cpp:802-810,908-916`).
//!
//! This module ports those decisions onto the rust `RoutingTable` so core can
//! drive them from a single maintenance task. The wire side (sending HELLO /
//! running the lookup) stays in core; this module only computes *what* to act on.

use std::net::Ipv4Addr;
use std::time::SystemTime;

use emulebb_kad_proto::{KadUdpKey, NodeId};

use crate::contact::Contact;

/// One contact selected for a small-timer HELLO liveness re-probe (the oracle
/// `GetLowestQualityExpiredContact` pick per leaf). Carries exactly the endpoint
/// + identity the core HELLO send path needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeCandidate {
    /// Peer Kad node id.
    pub id: NodeId,
    /// Peer IPv4 address.
    pub ip: Ipv4Addr,
    /// Peer Kad UDP port.
    pub udp_port: u16,
    /// Highest Kad version observed for the peer (selects the HELLO variant).
    pub kad_version: u8,
    /// Peer UDP anti-spoofing key, if known.
    pub udp_key: KadUdpKey,
}

impl ProbeCandidate {
    fn from_contact(contact: &Contact) -> Self {
        ProbeCandidate {
            id: contact.id,
            ip: contact.ip,
            udp_port: contact.udp_port,
            kad_version: contact.kad_version,
            udp_key: contact.udp_key,
        }
    }
}

/// Result of one small-timer maintenance sweep over the whole table.
#[derive(Debug, Default)]
pub struct SmallTimerOutcome {
    /// Contacts removed because they reached the dead+expired state.
    pub removed: Vec<NodeId>,
    /// Per-leaf lowest-quality expired contacts to HELLO-probe (one per leaf).
    pub probes: Vec<ProbeCandidate>,
}

/// Compute the small-timer maintenance actions for a leaf bin at `now`,
/// mirroring `CRoutingZone::OnSmallTimer`.
///
/// Side effects on the bin: seeds an expiry window on any contact that has none
/// (`m_tExpires == 0 -> tNow`) and removes contacts that are dead (type 4) and
/// expired. Returns the IDs removed plus the single lowest-quality *expired*
/// contact to probe (if any). The caller advances that contact's `CheckingType`
/// once it actually sends the HELLO (so a contact we cannot reach still ages).
pub(crate) fn small_timer_for_bin(
    bin: &mut crate::bin::RoutingBin,
    now: SystemTime,
) -> (Vec<NodeId>, Option<ProbeCandidate>) {
    // Pass 1: seed missing expiry windows and collect dead+expired removals.
    let mut to_remove = Vec::new();
    for contact in bin.iter_mut() {
        if contact.is_dead() && contact.is_expired_at(now) {
            to_remove.push(contact.id);
            continue;
        }
        if contact.expires_at.is_none() {
            contact.expires_at = Some(now);
        }
    }
    for id in &to_remove {
        bin.remove(id);
    }

    // Pass 2: pick the lowest-quality expired (not-yet-dead) contact to probe.
    let mut probe: Option<(ProbeCandidate, u32)> = None;
    for contact in bin.iter() {
        if contact.is_dead() || !contact.is_expired_at(now) {
            continue;
        }
        let quality = contact.local_quality_score(now);
        if probe.is_none_or(|(_, best)| quality < best) {
            probe = Some((ProbeCandidate::from_contact(contact), quality));
        }
    }
    (to_remove, probe.map(|(candidate, _)| candidate))
}

/// Build a random `FindNode` target inside the leaf identified by
/// `(depth, zone_index)`, mirroring `CRoutingZone::RandomLookup`
/// (`RoutingZone.cpp:908-916`).
///
/// The path from the tree root to a leaf fixes the top `depth` bits of the XOR
/// *distance* to our own id (the rust tree branches on `distance(own).bit(d)`),
/// and `zone_index` encodes those branch bits MSB-first. So a target whose
/// distance prefix equals `zone_index` (random below) lands in the leaf's range;
/// XOR-ing the distance back with `own_id` yields the lookup target.
pub(crate) fn random_target_in_zone(
    own_id: &NodeId,
    depth: u32,
    zone_index: usize,
    rng: &mut impl FnMut() -> u8,
) -> NodeId {
    let mut distance = [0u8; 16];
    for byte in distance.iter_mut() {
        *byte = rng();
    }
    // Overwrite the top `depth` distance bits with the zone-index path bits.
    let depth = depth.min(128);
    for level in 0..depth {
        let path_bit = (zone_index >> (depth - 1 - level)) & 1 == 1;
        set_bit(&mut distance, level, path_bit);
    }
    let distance = NodeId::from_bytes(distance);
    own_id.distance(&distance)
}

/// Set bit `pos` (0 = MSB of the first wire chunk, matching `NodeId::bit`) in a
/// little-endian-per-u32 NodeId byte buffer.
fn set_bit(bytes: &mut [u8; 16], pos: u32, value: bool) {
    let chunk_idx = (pos / 32) as usize;
    if chunk_idx >= 4 {
        return;
    }
    let bit_idx = 31 - (pos % 32);
    // Within a chunk, byte order is little-endian, so bit `bit_idx` lives in
    // chunk byte `bit_idx / 8` (from the chunk's low byte) at `bit_idx % 8`.
    let byte_index = chunk_idx * 4 + (bit_idx / 8) as usize;
    let mask = 1u8 << (bit_idx % 8);
    if value {
        bytes[byte_index] |= mask;
    } else {
        bytes[byte_index] &= !mask;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RoutingError;
    use crate::table::RoutingTable;
    use emulebb_kad_proto::{K, KadUdpKey};
    use std::time::{Duration, SystemTime};

    fn make_contact(id_byte: u8, ip: &str) -> Contact {
        Contact::new(
            NodeId::from_bytes([id_byte; 16]),
            ip.parse().unwrap(),
            4672,
            4662,
            9,
        )
    }

    fn make_strong(id_byte: u8, ip: &str, now: SystemTime) -> Contact {
        let mut c = make_contact(id_byte, ip);
        c.verified = true;
        c.received_hello_packet = true;
        c.udp_key = KadUdpKey::new(0xABCD);
        c.probe_type = 0;
        c.expires_at = Some(now + Duration::from_secs(3600));
        c
    }

    #[test]
    fn small_timer_removes_dead_expired_and_picks_probe() {
        let mut table = RoutingTable::new(NodeId::ZERO);
        let now = SystemTime::now();

        // Dead+expired -> removed.
        let mut dead = make_contact(0x01, "20.0.0.1");
        dead.probe_type = 4;
        dead.expires_at = Some(now - Duration::from_secs(1));
        table.add_contact(dead).unwrap();

        // Live but expired (stale) low-quality -> probe candidate.
        let mut stale = make_contact(0x02, "21.0.0.1");
        stale.probe_type = 2;
        stale.expires_at = Some(now - Duration::from_secs(1));
        table.add_contact(stale).unwrap();

        assert_eq!(table.len(), 2);
        let outcome = table.small_timer_maintenance(now);
        assert_eq!(outcome.removed, vec![NodeId::from_bytes([0x01; 16])]);
        assert_eq!(table.len(), 1);
        assert_eq!(outcome.probes.len(), 1);
        assert_eq!(outcome.probes[0].id, NodeId::from_bytes([0x02; 16]));
    }

    #[test]
    fn full_unsplittable_bin_replaces_weak_via_add_contact() {
        // Cap max size at K so the single full bin cannot split and must fall
        // back to weak replacement.
        let mut table = RoutingTable::with_max_size(NodeId::ZERO, K);
        let now = SystemTime::now();

        let mut weak = make_contact(0x01, "30.0.0.1");
        weak.probe_type = 3;
        weak.expires_at = Some(now - Duration::from_secs(60));
        table.add_contact(weak).unwrap();
        for i in 2..=K as u8 {
            table
                .add_contact(make_strong(i, &format!("31.{}.0.1", i), now))
                .unwrap();
        }
        assert_eq!(table.len(), K);

        let mut newcomer = make_strong(0xFE, "32.0.0.1", now);
        newcomer.udp_key = KadUdpKey::new(0x1357);
        table.add_contact(newcomer).unwrap();
        assert_eq!(table.len(), K);
        assert!(table.get(&NodeId::from_bytes([0xFE; 16])).is_some());
        assert!(table.get(&NodeId::from_bytes([0x01; 16])).is_none());
    }

    #[test]
    fn full_unsplittable_bin_keeps_strong_contacts() {
        let mut table = RoutingTable::with_max_size(NodeId::ZERO, K);
        let now = SystemTime::now();
        for i in 1..=K as u8 {
            table
                .add_contact(make_strong(i, &format!("40.{}.0.1", i), now))
                .unwrap();
        }
        assert_eq!(table.len(), K);

        let mut newcomer = make_contact(0xFE, "41.0.0.1");
        newcomer.verified = true;
        let err = table.add_contact(newcomer);
        assert!(matches!(err, Err(RoutingError::SplitDenied { .. })));
        assert_eq!(table.len(), K);
        assert!(table.get(&NodeId::from_bytes([0xFE; 16])).is_none());
    }

    #[test]
    fn random_target_lands_in_expected_branch() {
        // own_id all zeros -> distance == target, so branch bits read directly.
        let own = NodeId::ZERO;
        let mut counter = 0u8;
        let mut rng = || {
            counter = counter.wrapping_add(1);
            counter
        };
        // depth 3, zone_index 0b101: the top three distance bits must be 1,0,1.
        let target = random_target_in_zone(&own, 3, 0b101, &mut rng);
        let distance = own.distance(&target);
        assert!(distance.bit(0));
        assert!(!distance.bit(1));
        assert!(distance.bit(2));
    }

    #[test]
    fn random_target_respects_own_id_xor() {
        let own = NodeId::from_bytes([0x5A; 16]);
        let mut rng = || 0u8;
        let target = random_target_in_zone(&own, 2, 0b11, &mut rng);
        // With own_id != 0, the *distance* prefix (not the raw target) carries
        // the path bits.
        let distance = own.distance(&target);
        assert!(distance.bit(0));
        assert!(distance.bit(1));
    }
}
