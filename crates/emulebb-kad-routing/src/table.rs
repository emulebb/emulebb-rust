use std::collections::HashMap;
use std::net::Ipv4Addr;

use emulebb_kad_proto::NodeId;

use crate::contact::{Contact, is_lan};
use crate::error::{RoutingError, RoutingSubnetLimitScope};
use crate::zone::RoutingZone;

/// Default maximum contacts in the routing table.
pub const DEFAULT_MAX_SIZE: usize = 12_000;

/// Maximum contacts per /24 subnet (globally across all bins).
const GLOBAL_MAX_PER_SUBNET24: usize = 10;

/// The top-level routing table.
pub struct RoutingTable {
    own_id: NodeId,
    max_size: usize,
    root: RoutingZone,
    /// Count of contacts per IP address.
    ip_counts: HashMap<Ipv4Addr, usize>,
    /// Count of contacts per /24 subnet (3-byte prefix).
    subnet_counts: HashMap<[u8; 3], usize>,
    /// Total contact count across all bins.
    total_contacts: usize,
}

impl RoutingTable {
    /// Create a new routing table with default max size.
    pub fn new(own_id: NodeId) -> Self {
        RoutingTable::with_max_size(own_id, DEFAULT_MAX_SIZE)
    }

    /// Create a new routing table with a specified max size.
    pub fn with_max_size(own_id: NodeId, max_size: usize) -> Self {
        RoutingTable {
            own_id,
            max_size,
            root: RoutingZone::new_root(),
            ip_counts: HashMap::new(),
            subnet_counts: HashMap::new(),
            total_contacts: 0,
        }
    }

    /// Add a contact to the routing table.
    pub fn add_contact(&mut self, contact: Contact) -> Result<(), RoutingError> {
        // Global IP uniqueness check.
        let ip_count = self.ip_counts.get(&contact.ip).copied().unwrap_or(0);
        if ip_count > 0 {
            // Allow only if this is an update to an existing contact (same ID).
            if self.root.get(&contact.id).map(|c| c.ip) != Some(contact.ip) {
                return Err(RoutingError::IpLimitExceeded { ip: contact.ip });
            }
        }

        // Global /24 subnet limit (skip for LAN IPs).
        if !is_lan(contact.ip) {
            let subnet = subnet24(contact.ip);
            let subnet_count = self.subnet_counts.get(&subnet).copied().unwrap_or(0);
            // Check if this IP is new (not already in table under this contact)
            let existing_ip = self.root.get(&contact.id).map(|c| c.ip);
            let is_new_ip = existing_ip.map(|ip| ip != contact.ip).unwrap_or(true);
            if is_new_ip && subnet_count >= GLOBAL_MAX_PER_SUBNET24 {
                return Err(RoutingError::SubnetLimitExceeded {
                    prefix: 24,
                    scope: RoutingSubnetLimitScope::Global,
                });
            }
        }

        // Save old IP if contact already exists (for bookkeeping update).
        let old_ip = self.root.get(&contact.id).map(|c| c.ip);
        let new_ip = contact.ip;

        let result = self.root.add(contact, self.total_contacts, self.max_size);

        match result {
            Ok(true) => {
                // Newly added.
                *self.ip_counts.entry(new_ip).or_insert(0) += 1;
                if !is_lan(new_ip) {
                    let subnet = subnet24(new_ip);
                    *self.subnet_counts.entry(subnet).or_insert(0) += 1;
                }
                self.total_contacts += 1;
                Ok(())
            }
            Ok(false) => {
                // Updated existing. If IP changed, update maps.
                if let Some(old) = old_ip
                    && old != new_ip
                {
                    // Decrement old IP count.
                    if let Some(cnt) = self.ip_counts.get_mut(&old) {
                        if *cnt > 1 {
                            *cnt -= 1;
                        } else {
                            self.ip_counts.remove(&old);
                        }
                    }
                    if !is_lan(old) {
                        let subnet = subnet24(old);
                        if let Some(cnt) = self.subnet_counts.get_mut(&subnet) {
                            if *cnt > 1 {
                                *cnt -= 1;
                            } else {
                                self.subnet_counts.remove(&subnet);
                            }
                        }
                    }
                    // Increment new IP count.
                    *self.ip_counts.entry(new_ip).or_insert(0) += 1;
                    if !is_lan(new_ip) {
                        let subnet = subnet24(new_ip);
                        *self.subnet_counts.entry(subnet).or_insert(0) += 1;
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Get up to `n` contacts closest to `target` by XOR distance.
    pub fn get_closest(&self, target: &NodeId, n: usize) -> Vec<Contact> {
        let mut result = Vec::new();
        self.root.get_closest(target, usize::MAX, &mut result);
        result.sort_by(|a, b| {
            let da = a.id.distance(target);
            let db = b.id.distance(target);
            da.cmp(&db)
        });
        result.truncate(n);
        result
    }

    /// Get up to `n` contacts closest to `target` by XOR distance, restricted to
    /// contacts whose oracle freshness type is at most `max_type`.
    ///
    /// Mirrors `CRoutingZone::GetClosestTo(uMaxType, ...)`: the REQ responder
    /// passes `max_type = 2`, which keeps only contacts that have a valid age
    /// bucket and drops contacts staler than the requested freshness.
    pub fn get_closest_max_type(&self, target: &NodeId, n: usize, max_type: u8) -> Vec<Contact> {
        let mut result = Vec::new();
        self.root
            .get_closest_max_type(target, usize::MAX, max_type, &mut result);
        result.sort_by(|a, b| {
            let da = a.id.distance(target);
            let db = b.id.distance(target);
            da.cmp(&db)
        });
        result.truncate(n);
        result
    }

    /// Remove a contact by ID. Returns true if found and removed.
    pub fn remove(&mut self, id: &NodeId) -> bool {
        if let Some(contact) = self.root.remove(id) {
            let ip = contact.ip;
            if let Some(cnt) = self.ip_counts.get_mut(&ip) {
                if *cnt > 1 {
                    *cnt -= 1;
                } else {
                    self.ip_counts.remove(&ip);
                }
            }
            if !is_lan(ip) {
                let subnet = subnet24(ip);
                if let Some(cnt) = self.subnet_counts.get_mut(&subnet) {
                    if *cnt > 1 {
                        *cnt -= 1;
                    } else {
                        self.subnet_counts.remove(&subnet);
                    }
                }
            }
            self.total_contacts -= 1;
            true
        } else {
            false
        }
    }

    /// Total number of contacts in the routing table.
    pub fn len(&self) -> usize {
        self.total_contacts
    }

    /// Returns true if the routing table is empty.
    pub fn is_empty(&self) -> bool {
        self.total_contacts == 0
    }

    /// Returns the configured maximum size.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Returns our own node ID.
    pub fn own_id(&self) -> &NodeId {
        &self.own_id
    }

    /// Find a contact by ID.
    pub fn get(&self, id: &NodeId) -> Option<&Contact> {
        self.root.get(id)
    }

    /// Mark a contact as IP-verified after a successful three-way handshake or
    /// legacy challenge response.
    ///
    /// Mirrors the oracle `CRoutingZone::VerifyContact(uID, uIP)`: the contact
    /// must exist and its stored IP must match the responding peer's IP, which
    /// proves the peer is not using a spoofed source address. Returns `true`
    /// when the contact was found with a matching IP (and is now verified),
    /// `false` otherwise (unknown contact or IP mismatch).
    pub fn verify_contact(&mut self, id: &NodeId, ip: Ipv4Addr) -> bool {
        match self.root.get_mut(id) {
            Some(contact) if contact.ip == ip => {
                contact.verified = true;
                true
            }
            _ => false,
        }
    }

    /// Snapshot all known contacts ordered by XOR distance from our own ID.
    pub fn all_contacts(&self) -> Vec<Contact> {
        self.get_closest(&self.own_id, self.total_contacts)
    }
}

/// Extract the /24 prefix as [u8; 3].
fn subnet24(ip: Ipv4Addr) -> [u8; 3] {
    let o = ip.octets();
    [o[0], o[1], o[2]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulebb_kad_proto::{K, NodeId};
    use std::net::Ipv4Addr;

    fn make_contact(id_bytes: [u8; 16], ip: &str) -> Contact {
        Contact::new(
            NodeId::from_bytes(id_bytes),
            ip.parse::<Ipv4Addr>().unwrap(),
            4672,
            4662,
            9,
        )
    }

    fn unique_ip(i: usize) -> String {
        // Spread across different /24 subnets
        let a = (i / (256 * 256)) as u8;
        let b = ((i / 256) % 256) as u8;
        let c = (i % 256) as u8;
        format!("{}.{}.{}.1", a + 2, b, c)
    }

    #[test]
    fn test_add_and_len() {
        let own_id = NodeId::from_bytes([0x00; 16]);
        let mut table = RoutingTable::new(own_id);
        for i in 1..=20usize {
            let mut id = [0u8; 16];
            id[0] = (i >> 8) as u8;
            id[1] = i as u8;
            let c = make_contact(id, &unique_ip(i));
            table.add_contact(c).unwrap();
        }
        assert_eq!(table.len(), 20);
    }

    #[test]
    fn test_get_closest_order() {
        let own_id = NodeId::from_bytes([0x00; 16]);
        let mut table = RoutingTable::new(own_id);
        // Add contacts with known IDs
        for i in 1..=20u8 {
            let mut id = [0x00u8; 16];
            id[15] = i; // distances 1..20 to ZERO
            let c = make_contact(id, &format!("3.{}.{}.1", i, i));
            table.add_contact(c).unwrap();
        }
        let target = NodeId::ZERO;
        let closest = table.get_closest(&target, 5);
        assert_eq!(closest.len(), 5);
        // Closest should be id with last byte = 1 (distance 1)
        assert_eq!(closest[0].id.0[15], 1);
        // Second closest last byte = 2
        assert_eq!(closest[1].id.0[15], 2);
    }

    #[test]
    fn test_get_closest_max_type_filters_stale_contacts() {
        use std::time::Duration;
        let own_id = NodeId::from_bytes([0x00; 16]);
        let mut table = RoutingTable::new(own_id);

        // Fresh contact (created now -> oracle type 2).
        let fresh = make_contact([0x01; 16], "3.0.0.1");
        // Stale contact: created 3 hours ago -> oracle type 0, but we want one
        // that EXCEEDS max_type to prove filtering. Make it "too fresh" relative
        // to a low max_type instead: created now -> type 2, filtered by max_type 1.
        let also_fresh = make_contact([0x02; 16], "3.0.1.1");
        table.add_contact(fresh).unwrap();
        table.add_contact(also_fresh).unwrap();

        // max_type 2 keeps both fresh contacts.
        assert_eq!(table.get_closest_max_type(&NodeId::ZERO, 10, 2).len(), 2);

        // max_type 1 drops the brand-new (type 2) contacts.
        assert_eq!(table.get_closest_max_type(&NodeId::ZERO, 10, 1).len(), 0);

        // Age one contact past two hours so it becomes oracle type 0 and passes
        // even the strict max_type 0 filter.
        let aged_id = NodeId::from_bytes([0x01; 16]);
        {
            let c = table.root.get_mut(&aged_id).unwrap();
            c.created_at = std::time::SystemTime::now() - Duration::from_secs(3 * 3600);
        }
        assert_eq!(table.get_closest_max_type(&NodeId::ZERO, 10, 0).len(), 1);
    }

    #[test]
    fn test_global_ip_limit() {
        let own_id = NodeId::from_bytes([0x00; 16]);
        let mut table = RoutingTable::new(own_id);
        let ip = "1.2.3.4";
        let c1 = make_contact([0x01; 16], ip);
        table.add_contact(c1).unwrap();
        // Different node ID, same IP → rejected
        let c2 = make_contact([0x02; 16], ip);
        let err = table.add_contact(c2);
        assert!(matches!(err, Err(RoutingError::IpLimitExceeded { .. })));
    }

    #[test]
    fn test_subnet_limit_rejects_over_clustered_prefixes() {
        let own_id = NodeId::from_bytes([0x00; 16]);
        let mut table = RoutingTable::new(own_id);
        // The table now enforces both the global `/24` cap and the oracle
        // per-bin two-per-`/24` rule, so the third clustered contact is enough
        // to prove subnet guarding works.
        for i in 1..=2u8 {
            let mut id = [0u8; 16];
            id[0] = i;
            let c = make_contact(id, &format!("5.5.5.{}", i));
            table.add_contact(c).unwrap();
        }
        assert_eq!(table.len(), 2);
        let mut id = [0u8; 16];
        id[0] = 3;
        let c = make_contact(id, "5.5.5.3");
        let err = table.add_contact(c);
        assert!(matches!(
            err,
            Err(RoutingError::SubnetLimitExceeded {
                prefix: 24,
                scope: RoutingSubnetLimitScope::BinLocal
            })
        ));
    }

    #[test]
    fn test_global_subnet_limit_reports_global_scope() {
        let own_id = NodeId::from_bytes([0x00; 16]);
        let mut table = RoutingTable::new(own_id);
        table.subnet_counts.insert([6, 6, 6], 10);

        let contact = make_contact([0x04; 16], "6.6.6.4");
        let err = table.add_contact(contact);

        assert!(matches!(
            err,
            Err(RoutingError::SubnetLimitExceeded {
                prefix: 24,
                scope: RoutingSubnetLimitScope::Global
            })
        ));
    }

    #[test]
    fn test_remove() {
        let own_id = NodeId::from_bytes([0x00; 16]);
        let mut table = RoutingTable::new(own_id);
        let id = NodeId::from_bytes([0x01; 16]);
        let c = make_contact([0x01; 16], "7.7.7.7");
        table.add_contact(c).unwrap();
        assert_eq!(table.len(), 1);
        assert!(table.remove(&id));
        assert_eq!(table.len(), 0);
        // Removing again returns false
        assert!(!table.remove(&id));
    }

    #[test]
    fn test_zone_splits_with_own_id() {
        // own_id has bit 0 = 0 (starts with 0x00)
        let own_id = NodeId::from_bytes([0x00; 16]);
        let mut table = RoutingTable::new(own_id);

        // Add K+1 contacts where all share bit 0 = 0 with own_id.
        // This forces a split.
        for i in 0..(K + 1) as u8 {
            let mut id = [0x00u8; 16];
            id[1] = i + 1;
            let c = make_contact(id, &format!("2.{}.0.1", i));
            table.add_contact(c).unwrap();
        }
        assert_eq!(table.len(), K + 1);
    }

    #[test]
    fn test_update_same_contact() {
        let own_id = NodeId::from_bytes([0x00; 16]);
        let mut table = RoutingTable::new(own_id);
        let id = NodeId::from_bytes([0xAA; 16]);
        let c1 = Contact::new(id, "1.1.1.1".parse().unwrap(), 4672, 4662, 9);
        table.add_contact(c1).unwrap();
        assert_eq!(table.len(), 1);
        // Update same contact with same IP (no-op on counts)
        let c2 = Contact::new(id, "1.1.1.1".parse().unwrap(), 4673, 4662, 9);
        table.add_contact(c2).unwrap();
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_verify_contact_marks_verified_on_matching_ip() {
        let own_id = NodeId::from_bytes([0x00; 16]);
        let mut table = RoutingTable::new(own_id);
        let id = NodeId::from_bytes([0xCC; 16]);
        let c = make_contact([0xCC; 16], "9.8.7.6");
        table.add_contact(c).unwrap();
        assert!(!table.get(&id).unwrap().verified);

        // Matching IP -> verified.
        assert!(table.verify_contact(&id, "9.8.7.6".parse().unwrap()));
        assert!(table.get(&id).unwrap().verified);
    }

    #[test]
    fn test_verify_contact_rejects_ip_mismatch_and_unknown() {
        let own_id = NodeId::from_bytes([0x00; 16]);
        let mut table = RoutingTable::new(own_id);
        let id = NodeId::from_bytes([0xDD; 16]);
        let c = make_contact([0xDD; 16], "9.8.7.6");
        table.add_contact(c).unwrap();

        // Spoofed (mismatched) IP must not verify the contact.
        assert!(!table.verify_contact(&id, "1.1.1.1".parse().unwrap()));
        assert!(!table.get(&id).unwrap().verified);

        // Unknown contact ID must not verify anything.
        let unknown = NodeId::from_bytes([0xEE; 16]);
        assert!(!table.verify_contact(&unknown, "9.8.7.6".parse().unwrap()));
    }

    #[test]
    fn test_get_returns_contact() {
        let own_id = NodeId::from_bytes([0x00; 16]);
        let mut table = RoutingTable::new(own_id);
        let id = NodeId::from_bytes([0xBB; 16]);
        let c = make_contact([0xBB; 16], "6.6.6.6");
        table.add_contact(c).unwrap();
        let found = table.get(&id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, id);
    }
}
