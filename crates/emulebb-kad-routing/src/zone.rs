use emulebb_kad_proto::{K, KBASE, KK, NodeId};
use tracing::info;

use crate::bin::RoutingBin;
use crate::contact::Contact;
use crate::error::{RoutingError, RoutingSplitDeniedReason};

// ── ZoneContent ───────────────────────────────────────────────────────────────

enum ZoneContent {
    Leaf(RoutingBin),
    Branch {
        /// Owns nodes where bit[depth] == 0
        left: Box<RoutingZone>,
        /// Owns nodes where bit[depth] == 1
        right: Box<RoutingZone>,
    },
}

/// Outcome of a successful [`RoutingZone::add`] / [`RoutingTable::add_contact`].
#[derive(Debug)]
pub enum AddOutcome {
    /// A brand-new contact was inserted into a bin.
    Added,
    /// An existing contact (same id) was refreshed/updated in place.
    Updated,
    /// A full+unsplittable bin evicted a weak contact to admit the newcomer
    /// (oracle `ReplaceWeakContact`). Carries the evicted contact so the table
    /// can release its IP/subnet bookkeeping.
    Replaced(Box<Contact>),
}

impl AddOutcome {
    /// Whether the table's total contact count grew by one (a fresh insertion).
    /// A replacement keeps the total unchanged; an update is a no-op on counts.
    #[must_use]
    pub fn grew_total(&self) -> bool {
        matches!(self, AddOutcome::Added)
    }
}

// ── RoutingZone ───────────────────────────────────────────────────────────────

pub struct RoutingZone {
    depth: u32,
    zone_index: usize,
    content: ZoneContent,
}

impl RoutingZone {
    /// Create a new root zone.
    pub fn new_root() -> Self {
        RoutingZone {
            depth: 0,
            zone_index: 0,
            content: ZoneContent::Leaf(RoutingBin::new()),
        }
    }

    fn new_leaf(depth: u32, zone_index: usize) -> Self {
        RoutingZone {
            depth,
            zone_index,
            content: ZoneContent::Leaf(RoutingBin::new()),
        }
    }

    /// Try to add a contact.
    ///
    /// - `total_contacts`: current total in the whole table
    /// - `max_table_size`: configured maximum
    ///
    /// Returns [`AddOutcome`] (Added / Updated / Replaced) on success,
    /// `Err` = rejected.
    pub fn add(
        &mut self,
        contact: Contact,
        own_id: &NodeId,
        total_contacts: usize,
        max_table_size: usize,
    ) -> Result<AddOutcome, RoutingError> {
        match &mut self.content {
            ZoneContent::Leaf(_) => {
                // Try adding to the leaf bin.
                let result = {
                    let ZoneContent::Leaf(bin) = &mut self.content else {
                        unreachable!()
                    };
                    bin.try_add(contact.clone())
                };

                match result {
                    Ok(true) => Ok(AddOutcome::Added),
                    Ok(false) => Ok(AddOutcome::Updated),
                    Err(RoutingError::TableFull { .. }) => {
                        // Attempt to split.
                        let split_check = self.can_split(total_contacts, max_table_size);
                        if split_check.is_ok() {
                            info!(
                                target: "kad_routing",
                                depth = self.depth,
                                zone_index = self.zone_index,
                                total_contacts,
                                max_table_size,
                                "routing leaf split allowed by oracle can_split rule"
                            );
                            self.split(own_id)?;
                            // Retry after split.
                            self.add(contact, own_id, total_contacts, max_table_size)
                        } else {
                            // Full + unsplittable: mirror the oracle
                            // ReplaceWeakContact path (RoutingZone.cpp:613-626)
                            // before dropping the newcomer.
                            let ZoneContent::Leaf(bin) = &mut self.content else {
                                unreachable!()
                            };
                            match bin.replace_weak_contact(contact) {
                                Some(evicted) => Ok(AddOutcome::Replaced(Box::new(evicted))),
                                None => Err(RoutingError::SplitDenied {
                                    reason: split_check.expect_err("checked above"),
                                }),
                            }
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            ZoneContent::Branch { left, right } => {
                // Oracle CRoutingZone::Add branches on the XOR distance bit
                // (GetDistance().GetBitNumber(level)), not the raw contact-ID bit,
                // so contacts are placed relative to our own ID.
                if branch_is_right(&contact.id, own_id, self.depth) {
                    right.add(contact, own_id, total_contacts, max_table_size)
                } else {
                    left.add(contact, own_id, total_contacts, max_table_size)
                }
            }
        }
    }

    /// Collect up to `n` contacts closest to `target` by XOR distance.
    ///
    /// For simplicity: recurse into all leaf bins, add contacts to result.
    /// The caller (RoutingTable) sorts by XOR distance.
    pub fn get_closest(
        &self,
        target: &NodeId,
        own_id: &NodeId,
        n: usize,
        result: &mut Vec<Contact>,
    ) {
        match &self.content {
            ZoneContent::Leaf(bin) => {
                for c in bin.iter() {
                    result.push(c.clone());
                }
            }
            ZoneContent::Branch { left, right } => {
                // Oracle GetClosestTo recurses into the closer subzone first,
                // selected by the XOR-distance bit of the target relative to our
                // own ID. Correctness does not depend on order (the table sorts
                // and truncates), but matching the traversal keeps retention parity.
                if branch_is_right(target, own_id, self.depth) {
                    right.get_closest(target, own_id, n, result);
                    if result.len() < n {
                        left.get_closest(target, own_id, n, result);
                    }
                } else {
                    left.get_closest(target, own_id, n, result);
                    if result.len() < n {
                        right.get_closest(target, own_id, n, result);
                    }
                }
            }
        }
    }

    /// Collect contacts closest to `target` whose oracle freshness type is at
    /// most `max_type` (mirrors `CRoutingBin::GetClosestTo`'s `GetType() <=
    /// uMaxType` gate). The caller sorts by XOR distance and truncates.
    pub fn get_closest_max_type(
        &self,
        target: &NodeId,
        own_id: &NodeId,
        n: usize,
        max_type: u8,
        result: &mut Vec<Contact>,
    ) {
        match &self.content {
            ZoneContent::Leaf(bin) => {
                for c in bin.iter() {
                    if c.oracle_type() <= max_type {
                        result.push(c.clone());
                    }
                }
            }
            ZoneContent::Branch { left, right } => {
                if branch_is_right(target, own_id, self.depth) {
                    right.get_closest_max_type(target, own_id, n, max_type, result);
                    if result.len() < n {
                        left.get_closest_max_type(target, own_id, n, max_type, result);
                    }
                } else {
                    left.get_closest_max_type(target, own_id, n, max_type, result);
                    if result.len() < n {
                        right.get_closest_max_type(target, own_id, n, max_type, result);
                    }
                }
            }
        }
    }

    /// Remove a contact by ID. Returns the removed contact if found.
    pub fn remove(&mut self, id: &NodeId, own_id: &NodeId) -> Option<Contact> {
        match &mut self.content {
            ZoneContent::Leaf(bin) => bin.remove(id),
            ZoneContent::Branch { left, right } => {
                if branch_is_right(id, own_id, self.depth) {
                    right.remove(id, own_id)
                } else {
                    left.remove(id, own_id)
                }
            }
        }
    }

    /// Find a contact by ID.
    pub fn get(&self, id: &NodeId, own_id: &NodeId) -> Option<&Contact> {
        match &self.content {
            ZoneContent::Leaf(bin) => bin.iter().find(|c| &c.id == id),
            ZoneContent::Branch { left, right } => {
                if branch_is_right(id, own_id, self.depth) {
                    right.get(id, own_id)
                } else {
                    left.get(id, own_id)
                }
            }
        }
    }

    /// Find a mutable contact by ID.
    pub fn get_mut(&mut self, id: &NodeId, own_id: &NodeId) -> Option<&mut Contact> {
        match &mut self.content {
            ZoneContent::Leaf(bin) => bin.get_mut(id),
            ZoneContent::Branch { left, right } => {
                if branch_is_right(id, own_id, self.depth) {
                    right.get_mut(id, own_id)
                } else {
                    left.get_mut(id, own_id)
                }
            }
        }
    }

    /// Count total contacts in this zone and all children.
    pub fn count(&self) -> usize {
        match &self.content {
            ZoneContent::Leaf(bin) => bin.len(),
            ZoneContent::Branch { left, right } => left.count() + right.count(),
        }
    }

    /// Run the small-timer maintenance sweep over every leaf bin, accumulating
    /// removed-contact IDs and per-leaf probe candidates (oracle
    /// `CRoutingZone::OnSmallTimer` walked across the tree).
    pub(crate) fn small_timer_sweep(
        &mut self,
        now: std::time::SystemTime,
        outcome: &mut crate::maintenance::SmallTimerOutcome,
    ) {
        match &mut self.content {
            ZoneContent::Leaf(bin) => {
                let (removed, probe) = crate::maintenance::small_timer_for_bin(bin, now);
                outcome.removed.extend(removed);
                if let Some(candidate) = probe {
                    outcome.probes.push(candidate);
                }
            }
            ZoneContent::Branch { left, right } => {
                left.small_timer_sweep(now, outcome);
                right.small_timer_sweep(now, outcome);
            }
        }
    }

    /// Collect one random `FindNode` target per leaf zone that passes the
    /// oracle big-timer fill gate (`OnBigTimer`: leaf and `zone_index < KK ||
    /// level < KBASE || GetRemaining() >= 0.8*K`), mirroring `RandomLookup`.
    /// `GetRemaining() = K - size` (FREE slots, RoutingBin.cpp:195), so the
    /// third disjunct fires when the bin is nearly EMPTY (`size <= 0.2*K`), i.e.
    /// the tree fills sparse zones first. NOTE: this is the inverse of a
    /// fill-when-full gate.
    pub(crate) fn random_lookup_targets(
        &self,
        own_id: &NodeId,
        rng: &mut impl FnMut() -> u8,
        targets: &mut Vec<NodeId>,
    ) {
        match &self.content {
            ZoneContent::Leaf(bin) => {
                let fill_gate =
                    self.zone_index < KK || (self.depth as usize) < KBASE || bin.len() * 5 <= K; // GetRemaining() >= 0.8*K <=> size <= 0.2*K
                if fill_gate {
                    targets.push(crate::maintenance::random_target_in_zone(
                        own_id,
                        self.depth,
                        self.zone_index,
                        rng,
                    ));
                }
            }
            ZoneContent::Branch { left, right } => {
                left.random_lookup_targets(own_id, rng, targets);
                right.random_lookup_targets(own_id, rng, targets);
            }
        }
    }

    /// Whether this zone may be split.
    fn can_split(
        &self,
        total_contacts: usize,
        max_table_size: usize,
    ) -> Result<(), RoutingSplitDeniedReason> {
        // Condition 1: depth < 127
        if self.depth >= 127 {
            return Err(RoutingSplitDeniedReason::DepthLimit);
        }
        // Condition 2: total < max
        if total_contacts >= max_table_size {
            return Err(RoutingSplitDeniedReason::MaxTableSize);
        }
        // Condition 3: oracle `CanSplit` keeps splitting the low-index zones
        // and the whole tree up to `KBASE`, regardless of our own node ID.
        if self.depth < KBASE as u32 || self.zone_index < KK {
            return Ok(());
        }
        Err(RoutingSplitDeniedReason::ZoneIndexCap)
    }

    /// Split a leaf into two child zones, redistributing contacts.
    fn split(&mut self, own_id: &NodeId) -> Result<(), RoutingError> {
        let bin = match &mut self.content {
            ZoneContent::Leaf(b) => {
                let mut drained = RoutingBin::new();
                for c in b.drain() {
                    drained.try_add(c)?;
                }
                drained
            }
            ZoneContent::Branch { .. } => return Ok(()), // already split
        };

        let depth = self.depth;
        let mut left = Box::new(RoutingZone::new_leaf(
            depth + 1,
            child_zone_index(self.zone_index, false),
        ));
        let mut right = Box::new(RoutingZone::new_leaf(
            depth + 1,
            child_zone_index(self.zone_index, true),
        ));

        for c in bin.iter() {
            // Redistribute by the XOR-distance bit (oracle Split), so the side
            // a contact lands on matches how lookups will later traverse the tree.
            if branch_is_right(&c.id, own_id, depth) {
                // Preserve existing contacts exactly during redistribution.
                // Any failure here means the table already violated its own invariants.
                right.add(c.clone(), own_id, 0, usize::MAX)?;
            } else {
                left.add(c.clone(), own_id, 0, usize::MAX)?;
            }
        }

        self.content = ZoneContent::Branch { left, right };
        Ok(())
    }
}

/// Choose the branch (right = bit set) for `id` at `depth` using the XOR
/// distance to our own ID, mirroring the oracle
/// `GetDistance().GetBitNumber(level)`.
fn branch_is_right(id: &NodeId, own_id: &NodeId, depth: u32) -> bool {
    id.distance(own_id).bit(depth)
}

fn child_zone_index(parent_zone_index: usize, right_child: bool) -> usize {
    let child_zone_index = parent_zone_index
        .saturating_mul(2)
        .saturating_add(usize::from(right_child));
    child_zone_index.min(KK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::Contact;
    use emulebb_kad_proto::{K, NodeId};
    use std::net::Ipv4Addr;

    // Tests predate the distance-keyed tree; own_id ZERO makes distance(id, own)
    // == id, so branching matches the original raw-bit expectations.
    const OWN: NodeId = NodeId::ZERO;

    fn make_contact(id_bytes: [u8; 16], ip: &str) -> Contact {
        Contact::new(
            NodeId::from_bytes(id_bytes),
            ip.parse::<Ipv4Addr>().unwrap(),
            4672,
            4662,
            9,
        )
    }

    #[test]
    fn test_add_and_count() {
        let mut zone = RoutingZone::new_root();
        for i in 0..5u8 {
            let mut id = [0u8; 16];
            id[0] = i + 1;
            // Use distinct /24 subnets to avoid per-bin subnet limit
            let c = make_contact(id, &format!("1.{}.0.1", i + 1));
            zone.add(c, &OWN, i as usize, 1000).unwrap();
        }
        assert_eq!(zone.count(), 5);
    }

    #[test]
    fn test_get_closest_all_contacts() {
        let mut zone = RoutingZone::new_root();
        for i in 1..=5u8 {
            let mut id = [0u8; 16];
            id[0] = i;
            let c = make_contact(id, &format!("10.0.0.{}", i));
            zone.add(c, &OWN, i as usize, 1000).unwrap();
        }
        let mut result = Vec::new();
        let target = NodeId::from_bytes([0x00; 16]);
        zone.get_closest(&target, &OWN, 10, &mut result);
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_remove() {
        let mut zone = RoutingZone::new_root();
        let id = NodeId::from_bytes([0x01; 16]);
        let c = make_contact([0x01; 16], "1.1.1.1");
        zone.add(c, &OWN, 0, 1000).unwrap();
        assert_eq!(zone.count(), 1);
        let removed = zone.remove(&id, &OWN);
        assert!(removed.is_some());
        assert_eq!(zone.count(), 0);
    }

    #[test]
    fn test_split_on_overflow() {
        // own_id starts with 0x00, so bit 0 = 0 → own side is left (bit=0)
        let mut zone = RoutingZone::new_root();

        // Add K contacts with bit 0 = 0 (same side as own_id)
        // Use distinct /24 subnets to avoid per-bin subnet limit
        for i in 0..K as u8 {
            let mut id = [0x00u8; 16];
            id[1] = i + 1; // all have bit 0 = 0
            let c = make_contact(id, &format!("1.{}.0.1", i + 1));
            zone.add(c, &OWN, i as usize, 10000).unwrap();
        }
        assert_eq!(zone.count(), K);

        // Adding one more on the same side should trigger a split
        let mut extra_id = [0x00u8; 16];
        extra_id[2] = 1;
        let extra = make_contact(extra_id, "1.99.0.1");
        let result = zone.add(extra, &OWN, K, 10000);
        // After split, it should succeed
        assert!(result.is_ok());
        assert_eq!(zone.count(), K + 1);
    }

    #[test]
    fn test_get_by_id() {
        let mut zone = RoutingZone::new_root();
        let id = NodeId::from_bytes([0xAB; 16]);
        let c = make_contact([0xAB; 16], "9.9.9.9");
        zone.add(c, &OWN, 0, 1000).unwrap();
        assert!(zone.get(&id, &OWN).is_some());
        assert!(zone.get(&NodeId::ZERO, &OWN).is_none());
    }

    fn make_id_with_bit(depth: u32, wanted_bit: bool, discriminator: u8) -> [u8; 16] {
        let chunk_idx = (depth / 32) as usize;
        assert!(chunk_idx < 4, "depth {depth} exceeds NodeId width");
        let bit_idx = 31 - (depth % 32);
        let byte_index = chunk_idx * 4 + (bit_idx / 8) as usize;
        let mask = 1u8 << (bit_idx % 8);

        let mut id = [discriminator; 16];
        if wanted_bit {
            id[byte_index] |= mask;
        } else {
            id[byte_index] &= !mask;
        }
        assert_eq!(NodeId::from_bytes(id).bit(depth), wanted_bit);
        id
    }

    fn make_full_leaf(depth: u32, zone_index: usize, right_contacts: usize) -> RoutingZone {
        let mut zone = RoutingZone {
            depth,
            zone_index,
            content: ZoneContent::Leaf(RoutingBin::new()),
        };
        for i in 0..K as u8 {
            let wants_right_child = usize::from(i >= (K - right_contacts) as u8) != 0;
            let id = make_id_with_bit(depth, wants_right_child, i + 1);
            let contact = make_contact(id, &format!("20.{}.0.1", i + 1));
            let _ = zone.add(contact, &OWN, i as usize, usize::MAX);
        }
        zone
    }

    #[test]
    fn test_zone_index_below_kk_still_splits_after_kbase() {
        let mut zone = make_full_leaf(KBASE as u32, KK - 1, 1);
        let extra = make_contact(make_id_with_bit(KBASE as u32, true, 200), "21.1.0.1");

        let result = zone.add(extra, &OWN, K, usize::MAX);

        assert!(result.is_ok());
        assert_eq!(zone.count(), K + 1);
    }

    #[test]
    fn test_zone_index_at_kk_stops_splitting_after_kbase() {
        let mut zone = make_full_leaf(KBASE as u32, KK, 0);
        let extra = make_contact(make_id_with_bit(KBASE as u32, false, 201), "22.1.0.1");

        let result = zone.add(extra, &OWN, K, usize::MAX);

        assert!(matches!(
            result,
            Err(RoutingError::SplitDenied {
                reason: RoutingSplitDeniedReason::ZoneIndexCap
            })
        ));
        assert_eq!(zone.count(), K);
    }

    #[test]
    fn test_max_table_size_blocks_split_with_explicit_reason() {
        let mut zone = make_full_leaf(0, 0, 1);
        let extra = make_contact(make_id_with_bit(0, true, 202), "23.1.0.1");

        let result = zone.add(extra, &OWN, K, K);

        assert!(matches!(
            result,
            Err(RoutingError::SplitDenied {
                reason: RoutingSplitDeniedReason::MaxTableSize
            })
        ));
        assert_eq!(zone.count(), K);
    }

    fn make_leaf_with_size(size: usize) -> RoutingZone {
        let mut zone = RoutingZone {
            depth: KBASE as u32,
            zone_index: KK,
            content: ZoneContent::Leaf(RoutingBin::new()),
        };
        for i in 0..size as u8 {
            let id = make_id_with_bit(KBASE as u32, false, i + 1);
            zone.add(
                make_contact(id, &format!("30.{}.0.1", i + 1)),
                &OWN,
                i as usize,
                usize::MAX,
            )
            .unwrap();
        }
        assert_eq!(zone.count(), size);
        zone
    }

    fn gate_fires(zone: &RoutingZone) -> bool {
        let mut targets = Vec::new();
        zone.random_lookup_targets(&OWN, &mut || 0u8, &mut targets);
        !targets.is_empty()
    }

    #[test]
    fn big_timer_random_lookup_selects_sparse_leaf_not_full_leaf() {
        assert!(gate_fires(&make_leaf_with_size(0)));
        assert!(gate_fires(&make_leaf_with_size(2))); // exactly 0.2*K
        assert!(!gate_fires(&make_leaf_with_size(3)));
        assert!(!gate_fires(&make_leaf_with_size(K - 2))); // nearly full
    }
}
