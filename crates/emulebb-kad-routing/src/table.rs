use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use emulebb_kad_proto::NodeId;

use crate::contact::{Contact, is_lan};
use crate::error::{RoutingError, RoutingSubnetLimitScope};
use crate::zone::{AddOutcome, RoutingZone};

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
    /// None means the counter exhausted and persistence must fail visibly.
    generation: Option<u64>,
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
            generation: Some(0),
        }
    }

    /// Add a contact to the routing table.
    pub fn add_contact(&mut self, contact: Contact) -> Result<(), RoutingError> {
        let own_id = self.own_id;
        // Global IP uniqueness check.
        let ip_count = self.ip_counts.get(&contact.ip).copied().unwrap_or(0);
        if ip_count > 0 {
            // Allow only if this is an update to an existing contact (same ID).
            if self.root.get(&contact.id, &own_id).map(|c| c.ip) != Some(contact.ip) {
                return Err(RoutingError::IpLimitExceeded { ip: contact.ip });
            }
        }

        // Global /24 subnet limit (skip for LAN IPs).
        if !is_lan(contact.ip) {
            let subnet = subnet24(contact.ip);
            let subnet_count = self.subnet_counts.get(&subnet).copied().unwrap_or(0);
            // Check if this IP is new (not already in table under this contact)
            let existing_ip = self.root.get(&contact.id, &own_id).map(|c| c.ip);
            let is_new_ip = existing_ip.map(|ip| ip != contact.ip).unwrap_or(true);
            if is_new_ip && subnet_count >= GLOBAL_MAX_PER_SUBNET24 {
                return Err(RoutingError::SubnetLimitExceeded {
                    prefix: 24,
                    scope: RoutingSubnetLimitScope::Global,
                });
            }
        }

        // Save old IP if contact already exists (for bookkeeping update).
        let id = contact.id;
        let previous = self.root.get(&id, &own_id).cloned();
        let old_ip = previous.as_ref().map(|c| c.ip);
        let new_ip = contact.ip;

        let result = self
            .root
            .add(contact, &own_id, self.total_contacts, self.max_size);

        match result {
            Ok(AddOutcome::Added) => {
                // Newly added.
                *self.ip_counts.entry(new_ip).or_insert(0) += 1;
                if !is_lan(new_ip) {
                    let subnet = subnet24(new_ip);
                    *self.subnet_counts.entry(subnet).or_insert(0) += 1;
                }
                self.total_contacts += 1;
                self.advance_generation();
                Ok(())
            }
            Ok(AddOutcome::Replaced(evicted)) => {
                // A weak contact was evicted to admit the newcomer. The total
                // count is unchanged: release the evicted IP/subnet bookkeeping
                // and account for the newcomer's IP/subnet.
                self.release_ip_bookkeeping(evicted.ip);
                *self.ip_counts.entry(new_ip).or_insert(0) += 1;
                if !is_lan(new_ip) {
                    let subnet = subnet24(new_ip);
                    *self.subnet_counts.entry(subnet).or_insert(0) += 1;
                }
                self.advance_generation();
                Ok(())
            }
            Ok(AddOutcome::Updated) => {
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
                if previous
                    .as_ref()
                    .zip(self.root.get(&id, &own_id))
                    .is_some_and(|(old, new)| !old.persistence_eq(new))
                {
                    self.advance_generation();
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Get up to `n` contacts closest to `target` by XOR distance.
    pub fn get_closest(&self, target: &NodeId, n: usize) -> Vec<Contact> {
        let mut result = Vec::new();
        self.root
            .get_closest(target, &self.own_id, usize::MAX, &mut result);
        result.sort_by(|a, b| {
            let da = a.id.distance(target);
            let db = b.id.distance(target);
            da.cmp(&db)
        });
        result.truncate(n);
        result
    }

    /// Get up to `n` contacts closest to `target` by XOR distance, restricted to
    /// contacts whose oracle freshness type is at most `max_type` AND that are
    /// IP-verified.
    ///
    /// Mirrors `CRoutingZone::GetClosestTo(uMaxType, ...)` /
    /// `CRoutingBin::GetClosestTo` (`GetType() <= uMaxType && IsIpVerified()`):
    /// the `KADEMLIA2_REQ` responder passes `max_type = 2` and must never hand
    /// out an unverified (potentially source-spoofed) contact. Bootstrap uses
    /// the unfiltered [`get_closest`](Self::get_closest).
    pub fn get_closest_max_type(&self, target: &NodeId, n: usize, max_type: u8) -> Vec<Contact> {
        let mut result = Vec::new();
        self.root
            .get_closest_max_type(target, &self.own_id, usize::MAX, max_type, &mut result);
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
        let own_id = self.own_id;
        if let Some(contact) = self.root.remove(id, &own_id) {
            self.release_ip_bookkeeping(contact.ip);
            self.total_contacts -= 1;
            self.advance_generation();
            true
        } else {
            false
        }
    }

    /// Decrement the per-IP and per-`/24` bookkeeping counters for `ip`. Used by
    /// both [`RoutingTable::remove`] and the weak-contact replacement path (where
    /// the evicted contact's IP must be released without touching the total).
    fn release_ip_bookkeeping(&mut self, ip: Ipv4Addr) {
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
    }

    /// Total number of contacts in the routing table.
    /// Kademlia DHT network-size estimate (oracle `CKademlia::GetKademliaUsers`
    /// backed by `CRoutingZone::EstimateCount`, taken over the whole tree). Returns
    /// the estimated number of users on the Kad network from local routing density.
    pub fn estimate_network_size(&self, udp_firewalled: bool) -> u32 {
        self.root.estimate_network_size(udp_firewalled)
    }

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
        self.root.get(id, &self.own_id)
    }

    /// Current persistence generation, or None after counter exhaustion.
    pub fn persistence_generation(&self) -> Option<u64> {
        self.generation
    }

    fn advance_generation(&mut self) {
        self.generation = self.generation.and_then(|value| value.checked_add(1));
    }

    /// Visit contacts without cloning the full routing table.
    pub fn visit_contacts(&self, mut visit: impl FnMut(&Contact)) {
        self.root.visit_contacts(&mut visit);
    }

    /// Merge durable evidence without letting a stale snapshot replace a live
    /// endpoint or weaken existing contact knowledge. New contacts still pass
    /// the ordinary routing admission and subnet rules.
    pub fn merge_restored_contact(&mut self, incoming: Contact) -> Result<bool, RoutingError> {
        if let Some(existing) = self.root.get_mut(&incoming.id, &self.own_id) {
            if existing.ip != incoming.ip || existing.udp_port != incoming.udp_port {
                return Ok(false);
            }
            let previous = existing.clone();
            existing.kad_version = existing.kad_version.max(incoming.kad_version);
            if existing.tcp_port == 0 {
                existing.tcp_port = incoming.tcp_port;
            }
            if existing.udp_key == emulebb_kad_proto::KadUdpKey::ZERO {
                existing.udp_key = incoming.udp_key;
                existing.udp_key_ip = incoming.udp_key_ip;
            }
            existing.verified |= incoming.verified;
            existing.received_hello_packet |= incoming.received_hello_packet;
            existing.bootstrap |= incoming.bootstrap;
            if existing.hello_source_udp_port.is_none() {
                existing.hello_source_udp_port = incoming.hello_source_udp_port;
            }
            existing.created_at = existing.created_at.min(incoming.created_at);
            existing.last_seen = existing.last_seen.max(incoming.last_seen);
            let changed = !previous.persistence_eq(existing);
            if changed {
                self.advance_generation();
            }
            return Ok(true);
        }
        self.add_contact(incoming)?;
        Ok(true)
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
        let own_id = self.own_id;
        let (found, changed) = match self.root.get_mut(id, &own_id) {
            Some(contact) if contact.ip == ip => {
                let changed = !contact.verified;
                contact.verified = true;
                (true, changed)
            }
            _ => (false, false),
        };
        if changed {
            self.advance_generation();
        }
        found
    }

    /// Snapshot all known contacts ordered by XOR distance from our own ID.
    pub fn all_contacts(&self) -> Vec<Contact> {
        self.get_closest(&self.own_id, self.total_contacts)
    }

    /// Keyspace-spread contact sample for the `KADEMLIA2_BOOTSTRAP_RES`
    /// responder, capped at `max` (oracle `GetBootstrapContacts(20)` ->
    /// `TopDepth(LOG_BASE_EXPONENT)`). Unlike [`all_contacts`](Self::all_contacts)
    /// / `get_closest`, this samples across the top of the routing tree so a
    /// bootstrapping newcomer receives a spread of the keyspace rather than a
    /// cluster near this node's own ID. `rng` returns a random bit for the
    /// `RandomBin` sub-zone choice below the depth cutoff. The oracle then sorts
    /// the sample by a FastKad health/latency priority (an eMuleBB-specific,
    /// non-wire extension) before truncating; we take the spread in traversal
    /// order, which preserves the keyspace diversity that actually reaches the
    /// wire.
    pub fn bootstrap_contacts(&self, max: usize, rng: &mut impl FnMut() -> bool) -> Vec<Contact> {
        const LOG_BASE_EXPONENT: i32 = 5;
        let mut contacts = Vec::new();
        self.root
            .top_depth_contacts(LOG_BASE_EXPONENT, rng, &mut contacts);
        contacts.truncate(max);
        contacts
    }

    /// Run the oracle small-timer maintenance sweep at `now`: seed expiry
    /// windows, drop dead+expired contacts, and pick one lowest-quality expired
    /// contact per leaf to HELLO-probe. Removals are applied to the tree and
    /// their per-IP/`/24` bookkeeping released so counters stay consistent.
    ///
    /// Mirrors `CRoutingZone::OnSmallTimer` (`RoutingZone.cpp:852-906`).
    pub fn small_timer_maintenance(
        &mut self,
        now: std::time::SystemTime,
    ) -> crate::maintenance::SmallTimerOutcome {
        // Snapshot the IP of every dead+expired contact before the sweep deletes
        // it so bookkeeping can be released by id afterwards.
        let removed_ips: std::collections::HashMap<NodeId, Ipv4Addr> = self
            .all_contacts()
            .into_iter()
            .filter(|c| c.is_dead() && c.is_expired_at(now))
            .map(|c| (c.id, c.ip))
            .collect();
        let mut outcome = crate::maintenance::SmallTimerOutcome::default();
        self.root.small_timer_sweep(now, &mut outcome);
        for id in &outcome.removed {
            if let Some(ip) = removed_ips.get(id) {
                self.release_ip_bookkeeping(*ip);
                self.total_contacts = self.total_contacts.saturating_sub(1);
            }
        }
        if outcome.snapshot_changed {
            self.advance_generation();
        }
        outcome
    }

    /// Merge sparse sibling leaf zones back into their parent (oracle
    /// `CRoutingZone::Consolidate`, driven on the 45-minute consolidate timer).
    /// Keeps the routing tree compact as contacts churn out over long uptimes.
    /// Returns the number of merged zones. Any contact a merged bin rejects has
    /// its per-IP / per-/24 bookkeeping released and `total_contacts` decremented
    /// through the same accounting as removal — the `< K/2` merge gate means the
    /// merged bin always fits every contact, so this is a defensive no-op path.
    pub fn consolidate(&mut self) -> u32 {
        let mut dropped = Vec::new();
        let merges = self.root.consolidate(&mut dropped);
        let changed = !dropped.is_empty();
        for contact in dropped {
            self.release_ip_bookkeeping(contact.ip);
            self.total_contacts = self.total_contacts.saturating_sub(1);
        }
        if changed {
            self.advance_generation();
        }
        merges
    }

    /// Take the next due big-timer random `FindNode` target, if any leaf both
    /// passes the oracle fill gate (`CRoutingZone::OnBigTimer` ->
    /// `RandomLookup`) and has an elapsed per-zone big timer; the fired leaf
    /// is re-armed one hour out (oracle `m_tNextBigTimer = tNow + HR2S(1)`,
    /// Kademlia.cpp:293). At most one target per call, matching the master's
    /// one-zone-per-10s global slot. `rng` supplies random bytes for the
    /// in-zone target suffix.
    pub fn take_due_random_lookup_target(
        &mut self,
        now: std::time::SystemTime,
        rng: &mut impl FnMut() -> u8,
    ) -> Option<NodeId> {
        const BIG_TIMER_REARM: Duration = Duration::from_secs(3600);
        let own_id = self.own_id;
        self.root
            .take_due_random_lookup_target(&own_id, now, BIG_TIMER_REARM, rng)
    }

    /// Advance a contact's `CheckingType` staleness counter after a maintenance
    /// HELLO probe was sent to it (oracle `CContact::CheckingType`). Returns the
    /// new counter value, or `None` if the contact is gone.
    pub fn checking_type(&mut self, id: &NodeId) -> Option<u8> {
        let own_id = self.own_id;
        let mut changed = false;
        let result = self.root.get_mut(id, &own_id).map(|contact| {
            let previous = contact.clone();
            let value = contact.checking_type();
            changed = !previous.persistence_eq(contact);
            value
        });
        if changed {
            self.advance_generation();
        }
        result
    }
}

/// Extract the /24 prefix as [u8; 3].
fn subnet24(ip: Ipv4Addr) -> [u8; 3] {
    let o = ip.octets();
    [o[0], o[1], o[2]]
}

#[cfg(test)]
mod tests;
