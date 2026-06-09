use std::collections::VecDeque;
use std::net::Ipv4Addr;

use emulebb_kad_proto::{K, KadUdpKey, NodeId};

use crate::contact::{Contact, ContactType, is_lan};
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

    /// Iterate over all contacts.
    pub fn iter(&self) -> impl Iterator<Item = &Contact> {
        self.contacts.iter()
    }

    /// Drain all contacts out (consuming).
    pub fn drain(&mut self) -> impl Iterator<Item = Contact> + '_ {
        self.contacts.drain(..)
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
    fn test_update_existing_keeps_highest_version_and_learned_udp_key() {
        let mut bin = RoutingBin::new();
        let mut seeded = make_contact(1, "1.2.3.4".parse().unwrap());
        seeded.kad_version = 10;
        seeded.udp_key = KadUdpKey::new(0xAABB_CCDD);
        assert!(bin.try_add(seeded).unwrap());

        let mut thin_bootstrap_entry = make_contact(1, "1.2.3.5".parse().unwrap());
        thin_bootstrap_entry.kad_version = 2;
        thin_bootstrap_entry.udp_key = KadUdpKey::ZERO;
        assert!(!bin.try_add(thin_bootstrap_entry).unwrap());

        assert_eq!(bin.contacts[0].ip, "1.2.3.5".parse::<Ipv4Addr>().unwrap());
        assert_eq!(bin.contacts[0].kad_version, 10);
        assert_eq!(bin.contacts[0].udp_key, KadUdpKey::new(0xAABB_CCDD));

        let mut refreshed = make_contact(1, "1.2.3.6".parse().unwrap());
        refreshed.kad_version = 11;
        refreshed.udp_key = KadUdpKey::new(0x1122_3344);
        assert!(!bin.try_add(refreshed).unwrap());

        assert_eq!(bin.contacts[0].ip, "1.2.3.6".parse::<Ipv4Addr>().unwrap());
        assert_eq!(bin.contacts[0].kad_version, 11);
        assert_eq!(bin.contacts[0].udp_key, KadUdpKey::new(0x1122_3344));
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
}
