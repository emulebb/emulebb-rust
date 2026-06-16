use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::SystemTime;

use emulebb_kad_proto::{K, KadUdpKey, NodeId};

use crate::contact::{Contact, ContactType, KAD_LOCAL_QUALITY_REPLACEMENT_MARGIN, is_lan};
use crate::error::{RoutingError, RoutingSubnetLimitScope};

/// Maximum contacts from one non-LAN `/24` inside a single bin.
const MAX_PER_BIN_SUBNET24: usize = 2;

/// A k-bucket holding up to K contacts.
#[derive(Debug, Clone)]
pub struct RoutingBin {
    contacts: VecDeque<Contact>,
}

impl Default for RoutingBin {
    fn default() -> Self {
        RoutingBin::new()
    }
}

impl RoutingBin {
    pub fn new() -> Self {
        RoutingBin {
            contacts: VecDeque::new(),
        }
    }

    /// Number of contacts in this bin.
    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    /// Returns true if the bin is full (K contacts).
    pub fn is_full(&self) -> bool {
        self.contacts.len() >= K
    }

    /// Returns true if the bin is empty.
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    /// Try to add or update a contact.
    ///
    /// Returns:
    /// - `Ok(true)` — contact was newly inserted
    /// - `Ok(false)` — contact already existed and was refreshed/updated
    /// - `Err(TableFull)` — bin is full and cannot accept the new contact
    pub fn try_add(&mut self, contact: Contact) -> Result<bool, RoutingError> {
        let existing_pos = self.contacts.iter().position(|c| c.id == contact.id);

        // Mirror the oracle bucket-local anti-clustering rule: each non-LAN
        // `/24` may occupy at most two slots inside one bin.
        if !is_lan(contact.ip) {
            let subnet = subnet24(contact.ip);
            let same_subnet_contacts = self
                .contacts
                .iter()
                .enumerate()
                .filter(|(index, existing)| {
                    Some(*index) != existing_pos
                        && !is_lan(existing.ip)
                        && subnet24(existing.ip) == subnet
                })
                .count();
            if same_subnet_contacts >= MAX_PER_BIN_SUBNET24 {
                return Err(RoutingError::SubnetLimitExceeded {
                    prefix: 24,
                    scope: RoutingSubnetLimitScope::BinLocal,
                });
            }
        }

        // Check if contact already exists (update it).
        if let Some(pos) = existing_pos {
            // Oracle CRoutingZone::Add (RoutingZone.cpp:519-555): once a contact
            // has a non-zero UDP sender key, an update must present the SAME key
            // (anti-hijack protection). A mismatching or empty key on an entry
            // that already holds one is rejected: the table is left untouched.
            let stored_key = self.contacts[pos].udp_key;
            if stored_key != KadUdpKey::ZERO && contact.udp_key != stored_key {
                return Ok(false);
            }

            let existing = &mut self.contacts[pos];
            existing.ip = contact.ip;
            existing.udp_port = contact.udp_port;
            existing.tcp_port = contact.tcp_port;
            existing.kad_version = existing.kad_version.max(contact.kad_version);
            if contact.udp_key != KadUdpKey::ZERO {
                existing.udp_key = contact.udp_key;
            }
            existing.last_seen = contact.last_seen;
            // Move to back (most recently seen)
            let c = self.contacts.remove(pos).expect("position valid");
            self.contacts.push_back(c);
            return Ok(false);
        }

        // Bin is full?
        if self.contacts.len() >= K {
            return Err(RoutingError::TableFull { max: K });
        }

        self.contacts.push_back(contact);
        Ok(true)
    }

    /// Remove a contact by ID. Returns the removed contact if found.
    pub fn remove(&mut self, id: &NodeId) -> Option<Contact> {
        if let Some(pos) = self.contacts.iter().position(|c| &c.id == id) {
            self.contacts.remove(pos)
        } else {
            None
        }
    }

    /// The oldest contact (front of the deque).
    pub fn oldest(&self) -> Option<&Contact> {
        self.contacts.front()
    }

    /// The first Dead contact (for replacement).
    pub fn first_dead(&self) -> Option<&Contact> {
        self.contacts
            .iter()
            .find(|c| c.contact_type == ContactType::Dead)
    }

    /// Check if a contact with the given IP already exists in this bin.
    pub fn contains_ip(&self, ip: Ipv4Addr) -> bool {
        self.contacts.iter().any(|c| c.ip == ip)
    }

    /// Move a contact to the back (most recently used).
    pub fn refresh(&mut self, id: &NodeId) {
        if let Some(pos) = self.contacts.iter().position(|c| &c.id == id)
            && let Some(c) = self.contacts.remove(pos)
        {
            self.contacts.push_back(c);
        }
    }

    /// Find a mutable contact by ID.
    pub fn get_mut(&mut self, id: &NodeId) -> Option<&mut Contact> {
        self.contacts.iter_mut().find(|c| &c.id == id)
    }

    /// Iterate over all contacts.
    pub fn iter(&self) -> impl Iterator<Item = &Contact> {
        self.contacts.iter()
    }

    /// Drain all contacts out (consuming).
    pub fn drain(&mut self) -> impl Iterator<Item = Contact> + '_ {
        self.contacts.drain(..)
    }

    /// Iterate over all contacts mutably.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Contact> {
        self.contacts.iter_mut()
    }

    /// Snapshot the IDs of all contacts (caller-owned so the bin lock can be
    /// released before acting on them).
    pub fn contact_ids(&self) -> Vec<NodeId> {
        self.contacts.iter().map(|c| c.id).collect()
    }

    /// Replace the weakest locally-replaceable contact with `contact` when the
    /// bin is full and unsplittable, mirroring `CRoutingBin::ReplaceWeakContact`
    /// (RoutingBin.cpp:407-436) plus `GetWeakestReplaceableContact`
    /// (RoutingBin.cpp:509-524).
    ///
    /// The newcomer is accepted only if (a) the bin is at capacity, (b) a weak
    /// replacement candidate exists, and (c) the newcomer's local quality beats
    /// the candidate's by at least [`KAD_LOCAL_QUALITY_REPLACEMENT_MARGIN`].
    /// Returns the evicted contact on success, or `None` when no swap was made
    /// (the newcomer is then dropped, exactly as the oracle does).
    pub fn replace_weak_contact(&mut self, contact: Contact) -> Option<Contact> {
        self.replace_weak_contact_at(contact, SystemTime::now())
    }

    /// [`RoutingBin::replace_weak_contact`] evaluated at an explicit instant
    /// (test seam).
    pub fn replace_weak_contact_at(
        &mut self,
        contact: Contact,
        now: SystemTime,
    ) -> Option<Contact> {
        if self.contacts.len() < K {
            return None;
        }
        let (weakest_pos, removed_quality) = self.weakest_replaceable_contact(now)?;
        let new_quality = contact.local_quality_score(now);
        if new_quality < removed_quality.saturating_add(KAD_LOCAL_QUALITY_REPLACEMENT_MARGIN) {
            return None;
        }
        let removed = self.contacts.remove(weakest_pos)?;
        self.contacts.push_back(contact);
        Some(removed)
    }

    /// Position + quality of the weakest replaceable contact at `now`, or `None`
    /// when no contact qualifies (oracle `GetWeakestReplaceableContact`).
    fn weakest_replaceable_contact(&self, now: SystemTime) -> Option<(usize, u32)> {
        let mut weakest: Option<(usize, u32)> = None;
        for (index, contact) in self.contacts.iter().enumerate() {
            if !contact.is_weak_for_replacement(now) {
                continue;
            }
            let quality = contact.local_quality_score(now);
            if weakest.is_none_or(|(_, best)| quality < best) {
                weakest = Some((index, quality));
            }
        }
        weakest
    }
}

fn subnet24(ip: Ipv4Addr) -> [u8; 3] {
    let octets = ip.octets();
    [octets[0], octets[1], octets[2]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulebb_kad_proto::NodeId;
    use std::net::Ipv4Addr;

    fn make_contact(id_byte: u8, ip: Ipv4Addr) -> Contact {
        Contact::new(NodeId::from_bytes([id_byte; 16]), ip, 4672, 4662, 9)
    }

    #[test]
    fn test_add_and_full() {
        let mut bin = RoutingBin::new();
        for i in 0..K {
            let ip = format!("1.2.{}.1", i).parse().unwrap();
            let c = make_contact(i as u8, ip);
            assert!(bin.try_add(c).unwrap());
        }
        assert!(bin.is_full());
        let extra = make_contact(99, "1.2.99.1".parse().unwrap());
        assert!(matches!(
            bin.try_add(extra),
            Err(RoutingError::TableFull { .. })
        ));
    }

    #[test]
    fn test_update_existing() {
        let mut bin = RoutingBin::new();
        let c = make_contact(1, "1.2.3.4".parse().unwrap());
        assert!(bin.try_add(c).unwrap());
        // Same ID, different IP (update)
        let c2 = make_contact(1, "1.2.3.5".parse().unwrap());
        assert!(!bin.try_add(c2).unwrap()); // updated, not new
        assert_eq!(bin.len(), 1);
        assert_eq!(bin.contacts[0].ip, "1.2.3.5".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_update_with_matching_key_keeps_highest_version() {
        let mut bin = RoutingBin::new();
        let mut seeded = make_contact(1, "1.2.3.4".parse().unwrap());
        seeded.kad_version = 10;
        seeded.udp_key = KadUdpKey::new(0xAABB_CCDD);
        assert!(bin.try_add(seeded).unwrap());

        // A legitimate re-HELLO from the same peer carries the SAME sender key,
        // so the update applies and the highest version is kept.
        let mut refreshed = make_contact(1, "1.2.3.6".parse().unwrap());
        refreshed.kad_version = 11;
        refreshed.udp_key = KadUdpKey::new(0xAABB_CCDD);
        assert!(!bin.try_add(refreshed).unwrap());

        assert_eq!(bin.contacts[0].ip, "1.2.3.6".parse::<Ipv4Addr>().unwrap());
        assert_eq!(bin.contacts[0].kad_version, 11);
        assert_eq!(bin.contacts[0].udp_key, KadUdpKey::new(0xAABB_CCDD));
    }

    #[test]
    fn test_update_rejected_when_key_mismatches_stored_non_zero_key() {
        // Oracle anti-hijack: once a non-zero UDP sender key is stored, an
        // update with a different key (or an empty key) leaves the entry intact.
        let mut bin = RoutingBin::new();
        let mut seeded = make_contact(1, "1.2.3.4".parse().unwrap());
        seeded.kad_version = 10;
        seeded.udp_key = KadUdpKey::new(0xAABB_CCDD);
        assert!(bin.try_add(seeded).unwrap());

        // Empty-key update is denied.
        let mut thin = make_contact(1, "1.2.3.5".parse().unwrap());
        thin.kad_version = 2;
        thin.udp_key = KadUdpKey::ZERO;
        assert!(!bin.try_add(thin).unwrap());
        assert_eq!(bin.contacts[0].ip, "1.2.3.4".parse::<Ipv4Addr>().unwrap());
        assert_eq!(bin.contacts[0].kad_version, 10);
        assert_eq!(bin.contacts[0].udp_key, KadUdpKey::new(0xAABB_CCDD));

        // Mismatched-key (hijack) update is denied.
        let mut hijack = make_contact(1, "1.2.3.6".parse().unwrap());
        hijack.kad_version = 11;
        hijack.udp_key = KadUdpKey::new(0x1122_3344);
        assert!(!bin.try_add(hijack).unwrap());
        assert_eq!(bin.contacts[0].ip, "1.2.3.4".parse::<Ipv4Addr>().unwrap());
        assert_eq!(bin.contacts[0].udp_key, KadUdpKey::new(0xAABB_CCDD));
    }

    #[test]
    fn test_update_allowed_when_no_key_stored_yet() {
        // Before any key is learned, updates (including key-less ones) apply, so
        // a first-HELLO can still refresh a bootstrap-only entry.
        let mut bin = RoutingBin::new();
        let seeded = make_contact(1, "1.2.3.4".parse().unwrap());
        assert!(bin.try_add(seeded).unwrap());

        let mut learned = make_contact(1, "1.2.3.5".parse().unwrap());
        learned.udp_key = KadUdpKey::new(0xDEAD_BEEF);
        assert!(!bin.try_add(learned).unwrap());
        assert_eq!(bin.contacts[0].ip, "1.2.3.5".parse::<Ipv4Addr>().unwrap());
        assert_eq!(bin.contacts[0].udp_key, KadUdpKey::new(0xDEAD_BEEF));
    }

    #[test]
    fn test_remove() {
        let mut bin = RoutingBin::new();
        let c = make_contact(5, "5.5.5.5".parse().unwrap());
        bin.try_add(c).unwrap();
        let removed = bin.remove(&NodeId::from_bytes([5u8; 16]));
        assert!(removed.is_some());
        assert!(bin.is_empty());
    }

    #[test]
    fn test_third_non_lan_contact_from_same_subnet_is_rejected() {
        let mut bin = RoutingBin::new();
        for i in 1..=2u8 {
            let ip: Ipv4Addr = format!("5.5.5.{}", i).parse().unwrap();
            let c = make_contact(i, ip);
            bin.try_add(c).unwrap();
        }
        let third = make_contact(3, "5.5.5.3".parse().unwrap());
        assert!(matches!(
            bin.try_add(third),
            Err(RoutingError::SubnetLimitExceeded {
                prefix: 24,
                scope: RoutingSubnetLimitScope::BinLocal
            })
        ));
        assert_eq!(bin.len(), 2);
    }

    #[test]
    fn test_lan_ips_accepted() {
        let mut bin = RoutingBin::new();
        // Multiple LAN IPs from same /24 can be added freely in a bin
        for i in 0..5 {
            let ip: Ipv4Addr = format!("192.168.1.{}", i + 1).parse().unwrap();
            let c = make_contact(i as u8 + 1, ip);
            bin.try_add(c).unwrap();
        }
        assert_eq!(bin.len(), 5);
    }

    #[test]
    fn test_oldest() {
        let mut bin = RoutingBin::new();
        let c1 = make_contact(1, "1.1.1.1".parse().unwrap());
        let c2 = make_contact(2, "2.2.2.2".parse().unwrap());
        bin.try_add(c1).unwrap();
        bin.try_add(c2).unwrap();
        let oldest = bin.oldest().unwrap();
        assert_eq!(oldest.id, NodeId::from_bytes([1u8; 16]));
    }

    #[test]
    fn test_refresh() {
        let mut bin = RoutingBin::new();
        let c1 = make_contact(1, "1.1.1.1".parse().unwrap());
        let c2 = make_contact(2, "2.2.2.2".parse().unwrap());
        bin.try_add(c1).unwrap();
        bin.try_add(c2).unwrap();
        bin.refresh(&NodeId::from_bytes([1u8; 16]));
        // c1 should now be at back, c2 at front
        let oldest = bin.oldest().unwrap();
        assert_eq!(oldest.id, NodeId::from_bytes([2u8; 16]));
    }

    #[test]
    fn test_first_dead() {
        let mut bin = RoutingBin::new();
        let c1 = make_contact(1, "1.1.1.1".parse().unwrap());
        let mut c2 = make_contact(2, "2.2.2.2".parse().unwrap());
        c2.mark_dead();
        bin.try_add(c1).unwrap();
        bin.try_add(c2).unwrap();
        let dead = bin.first_dead().unwrap();
        assert_eq!(dead.id, NodeId::from_bytes([2u8; 16]));
    }

    /// A strong fresh contact: IP-verified, hello-received, keyed, current type.
    fn make_strong_contact(id_byte: u8, ip: Ipv4Addr) -> Contact {
        let mut c = make_contact(id_byte, ip);
        c.verified = true;
        c.received_hello_packet = true;
        c.udp_key = KadUdpKey::new(0x1234_5678);
        c.probe_type = 0;
        c.expires_at = Some(std::time::SystemTime::now() + std::time::Duration::from_secs(3600));
        c
    }

    /// A weak contact: unverified, no hello, no key, expired window.
    fn make_weak_contact(id_byte: u8, ip: Ipv4Addr) -> Contact {
        let mut c = make_contact(id_byte, ip);
        c.verified = false;
        c.received_hello_packet = false;
        c.udp_key = KadUdpKey::ZERO;
        c.probe_type = 3;
        c.expires_at = Some(std::time::SystemTime::now() - std::time::Duration::from_secs(60));
        c
    }

    #[test]
    fn test_full_bin_replaces_weak_contact_with_fresh_verified_one() {
        // Fill the bin: one weak stale unverified contact + (K-1) strong ones,
        // all in distinct /24s to avoid the per-bin subnet limit.
        let mut bin = RoutingBin::new();
        let weak = make_weak_contact(0, "9.9.9.1".parse().unwrap());
        assert!(bin.try_add(weak).unwrap());
        for i in 1..K {
            let ip: Ipv4Addr = format!("10.{}.0.1", i).parse().unwrap();
            assert!(bin.try_add(make_strong_contact(i as u8, ip)).unwrap());
        }
        assert!(bin.is_full());

        // The bin is full; a fresh verified newcomer should evict the weak one.
        let newcomer = make_strong_contact(200, "11.0.0.1".parse().unwrap());
        let evicted = bin
            .replace_weak_contact(newcomer)
            .expect("weak contact should be replaced");
        assert_eq!(evicted.id, NodeId::from_bytes([0u8; 16]));
        assert_eq!(bin.len(), K);
        // The newcomer is now present, the weak contact gone.
        assert!(bin.iter().any(|c| c.id == NodeId::from_bytes([200u8; 16])));
        assert!(!bin.iter().any(|c| c.id == NodeId::from_bytes([0u8; 16])));
    }

    #[test]
    fn test_full_bin_does_not_evict_when_all_existing_are_stronger() {
        // Fill the bin entirely with strong contacts -> none is weak.
        let mut bin = RoutingBin::new();
        for i in 0..K {
            let ip: Ipv4Addr = format!("12.{}.0.1", i).parse().unwrap();
            assert!(bin.try_add(make_strong_contact(i as u8, ip)).unwrap());
        }
        assert!(bin.is_full());

        // A fresh verified newcomer must NOT evict anyone: no weak candidate.
        let newcomer = make_strong_contact(201, "13.0.0.1".parse().unwrap());
        assert!(bin.replace_weak_contact(newcomer).is_none());
        assert_eq!(bin.len(), K);
        assert!(!bin.iter().any(|c| c.id == NodeId::from_bytes([201u8; 16])));
    }

    #[test]
    fn test_weak_replacement_requires_quality_margin() {
        // Fill with one weak contact + strong ones, but the newcomer is itself
        // weak (unverified/stale) so it does not beat the margin.
        let mut bin = RoutingBin::new();
        let weak = make_weak_contact(0, "14.9.9.1".parse().unwrap());
        assert!(bin.try_add(weak).unwrap());
        for i in 1..K {
            let ip: Ipv4Addr = format!("15.{}.0.1", i).parse().unwrap();
            assert!(bin.try_add(make_strong_contact(i as u8, ip)).unwrap());
        }
        // A weak newcomer is not >= weakest + margin, so no swap.
        let weak_newcomer = make_weak_contact(202, "16.0.0.1".parse().unwrap());
        assert!(bin.replace_weak_contact(weak_newcomer).is_none());
        assert_eq!(bin.len(), K);
    }

    #[test]
    fn test_non_full_bin_never_replaces() {
        let mut bin = RoutingBin::new();
        let weak = make_weak_contact(0, "17.9.9.1".parse().unwrap());
        assert!(bin.try_add(weak).unwrap());
        // Bin is not full, so replace_weak_contact is a no-op (newcomer should
        // go through the normal try_add path instead).
        let newcomer = make_strong_contact(203, "18.0.0.1".parse().unwrap());
        assert!(bin.replace_weak_contact(newcomer).is_none());
        assert_eq!(bin.len(), 1);
    }
}
