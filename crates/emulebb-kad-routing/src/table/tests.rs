
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
fn bootstrap_contacts_returns_the_whole_root_leaf_uncapped_below_the_limit() {
    // A table whose contacts all fit in the root leaf (no split): the
    // bootstrap sample is simply every contact, capped at the oracle max.
    let own_id = NodeId::from_bytes([0x40; 16]);
    let mut table = RoutingTable::new(own_id);
    let mut added = 0usize;
    for i in 0..8usize {
        let mut id = [0u8; 16];
        id[0] = if i % 2 == 0 { 0x10 } else { 0xF0 };
        id[1] = (i as u8).wrapping_mul(17).wrapping_add(1);
        if table
            .add_contact(make_contact(id, &unique_ip(added + 1)))
            .is_ok()
        {
            added += 1;
        }
    }
    let mut rng = || true;
    let contacts = table.bootstrap_contacts(20, &mut rng);
    assert_eq!(
        contacts.len(),
        added,
        "root-leaf sample returns every contact"
    );
    // Spans both keyspace halves (the leaf holds both), unlike a
    // closest-to-own-id selection which would cluster on one side.
    assert!(contacts.iter().any(|c| c.id.0[0] & 0x80 == 0));
    assert!(contacts.iter().any(|c| c.id.0[0] & 0x80 != 0));
}

#[test]
fn bootstrap_contacts_never_exceeds_the_oracle_cap() {
    // A large, deep table: the sample must still respect the cap of 20
    // (oracle GetBootstrapContacts(20)) and only return real contacts.
    let own_id = NodeId::from_bytes([0x00; 16]);
    let mut table = RoutingTable::new(own_id);
    let mut added = 0usize;
    for i in 0..300usize {
        let mut id = [0u8; 16];
        id[0] = (i.wrapping_mul(37) & 0xFF) as u8;
        id[1] = (i.wrapping_mul(101) & 0xFF) as u8;
        id[2] = i as u8;
        if id != [0u8; 16]
            && table
                .add_contact(make_contact(id, &unique_ip(added + 1)))
                .is_ok()
        {
            added += 1;
        }
    }
    assert!(
        added > 20,
        "need a table larger than the cap, added={added}"
    );
    let mut flip = false;
    let mut rng = || {
        flip = !flip;
        flip
    };
    let contacts = table.bootstrap_contacts(20, &mut rng);
    assert!(
        contacts.len() <= 20,
        "bootstrap sample exceeded the cap of 20"
    );
    // Every returned entry is a real, distinct table contact.
    let ids: std::collections::HashSet<_> = contacts.iter().map(|c| c.id).collect();
    assert_eq!(ids.len(), contacts.len(), "bootstrap sample has duplicates");
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
fn consolidate_preserves_contacts_and_the_table_counters() {
    let own_id = NodeId::from_bytes([0x00; 16]);
    let mut table = RoutingTable::new(own_id);
    // A handful of contacts across distinct /24s; enough to make the root
    // split at least once but sparse enough that consolidate can re-merge.
    for i in 1..=6usize {
        let mut id = [0u8; 16];
        id[0] = if i % 2 == 0 { 0x80 } else { 0x00 };
        id[1] = i as u8;
        table.add_contact(make_contact(id, &unique_ip(i))).unwrap();
    }
    let before = table.len();
    assert_eq!(before, 6);

    // Consolidate must never lose a contact here (combined bins stay under the
    // K/2 gate that guarantees no reject), so total_contacts is unchanged and
    // every contact is still retrievable.
    let _ = table.consolidate();
    assert_eq!(
        table.len(),
        before,
        "consolidate must not drop live contacts"
    );
    let all = table.get_closest(&NodeId::ZERO, 100);
    assert_eq!(all.len(), before, "every contact survives consolidation");

    // Re-adding is idempotent (no double-count) and a fresh contact still fits,
    // proving the per-IP/subnet bookkeeping was not corrupted by the merge.
    let mut extra_id = [0x00u8; 16];
    extra_id[1] = 0xEE;
    table
        .add_contact(make_contact(extra_id, &unique_ip(500)))
        .unwrap();
    assert_eq!(table.len(), before + 1);
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
    // Verify both so this test isolates the freshness (max_type) filter from
    // the IP-verified filter (covered separately below).
    assert!(table.verify_contact(&NodeId::from_bytes([0x01; 16]), "3.0.0.1".parse().unwrap()));
    assert!(table.verify_contact(&NodeId::from_bytes([0x02; 16]), "3.0.1.1".parse().unwrap()));

    // max_type 2 keeps both fresh contacts.
    assert_eq!(table.get_closest_max_type(&NodeId::ZERO, 10, 2).len(), 2);

    // max_type 1 drops the brand-new (type 2) contacts.
    assert_eq!(table.get_closest_max_type(&NodeId::ZERO, 10, 1).len(), 0);

    // Age one contact past two hours so it becomes oracle type 0 and passes
    // even the strict max_type 0 filter.
    let aged_id = NodeId::from_bytes([0x01; 16]);
    {
        let own = table.own_id;
        let c = table.root.get_mut(&aged_id, &own).unwrap();
        c.created_at = std::time::SystemTime::now() - Duration::from_secs(3 * 3600);
    }
    assert_eq!(table.get_closest_max_type(&NodeId::ZERO, 10, 0).len(), 1);
}

#[test]
fn get_closest_max_type_excludes_unverified_contacts() {
    // The KADEMLIA2_REQ responder must never hand out an unverified
    // (potentially source-spoofed) contact, even a fresh one (oracle
    // CRoutingBin::GetClosestTo IsIpVerified gate). Bootstrap's get_closest
    // stays unfiltered.
    let own_id = NodeId::from_bytes([0x00; 16]);
    let mut table = RoutingTable::new(own_id);
    table
        .add_contact(make_contact([0x01; 16], "3.0.0.1"))
        .unwrap();
    // Unverified (default): excluded from the REQ/RES serve path...
    assert_eq!(table.get_closest_max_type(&NodeId::ZERO, 10, 2).len(), 0);
    // ...but still present for bootstrap (unfiltered).
    assert_eq!(table.get_closest(&NodeId::ZERO, 10).len(), 1);
    // Once IP-verified, it is served.
    assert!(table.verify_contact(&NodeId::from_bytes([0x01; 16]), "3.0.0.1".parse().unwrap()));
    assert_eq!(table.get_closest_max_type(&NodeId::ZERO, 10, 2).len(), 1);
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
fn test_distance_keyed_tree_keeps_contacts_findable_after_split() {
    // Use a non-zero own_id so distance-based branching diverges from raw
    // contact-ID branching. If add() and get() disagreed on the branch (the
    // pre-fix raw-bit bug), some contacts would become unreachable after a
    // leaf split. Inserting enough contacts to force a split and then
    // re-finding every one proves add/get/remove all key on XOR distance.
    let own_id = NodeId::from_bytes([0xF3; 16]);
    let mut table = RoutingTable::new(own_id);

    let mut ids = Vec::new();
    for i in 0..(K + 5) {
        // Spread the top distance bits by varying the most significant ID
        // byte, so the tree actually splits across both branches instead of
        // clustering and hitting the zone-index cap.
        // bit(0) reads the MSB of chunk0, which is byte index 3 in the wire
        // layout, so vary byte 3 (and below) to spread the top distance bits.
        let mut id = [0u8; 16];
        id[3] = ((i as u8).wrapping_mul(101)) ^ 0x5A;
        id[2] = ((i as u8).wrapping_mul(53)) ^ 0x11;
        id[1] = i as u8;
        id[0] = 0xA5;
        let nid = NodeId::from_bytes(id);
        let c = make_contact(id, &unique_ip(i + 1));
        table
            .add_contact(c)
            .unwrap_or_else(|e| panic!("add {i} failed: {e:?}"));
        ids.push(nid);
    }

    // Every inserted contact must still resolve through the distance-keyed tree.
    for nid in &ids {
        assert!(
            table.get(nid).is_some(),
            "contact {nid} unreachable after split (branching mismatch)"
        );
    }

    // Removal also walks the distance-keyed path.
    let victim = ids[3];
    assert!(table.remove(&victim));
    assert!(table.get(&victim).is_none());
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
