use super::*;

fn contact(id: u8, ip: u32) -> KadRoutingContact {
    KadRoutingContact {
        node_id: [id; 16],
        ip,
        udp_port: 20020,
        tcp_port: 20019,
        version: 9,
        udp_key: u32::MAX,
        udp_key_ip: Some(0xc0000201),
        hello_source_udp_port: Some(20021),
        udp_firewalled: true,
        tcp_firewalled: true,
        requests_hello_res_ack: true,
        received_hello_packet: true,
        verified: true,
        contact_type: KadRoutingContactType::Active,
        probe_type: 3,
        bootstrap: true,
        expires_at_seconds: Some(1_800_000_000),
        last_type_set_at_seconds: Some(1_700_000_010),
        last_seen_at_seconds: 1_700_000_005,
        created_at_seconds: 1_700_000_000,
    }
}

#[test]
fn checkpoint_preserves_discovery_initialization_while_advancing_revision() {
    let store = MetadataStore::in_memory().unwrap();
    assert_eq!(
        store
            .checkpoint_kad_routing_snapshot(0, &[contact(1, 0xc0000201)])
            .unwrap(),
        Some(1)
    );
    let pending = store.load_kad_routing_snapshot().unwrap();
    assert_eq!(
        pending.initialization,
        DiscoveryInitializationStatus::Pending
    );
    assert_eq!(
        store.checkpoint_kad_routing_snapshot(1, &[]).unwrap(),
        Some(2)
    );
    assert_eq!(
        store.load_kad_routing_snapshot().unwrap().initialization,
        DiscoveryInitializationStatus::Pending
    );
    assert_eq!(
        store.replace_kad_routing_snapshot(2, true, &[]).unwrap(),
        Some(3)
    );
    assert_eq!(
        store.checkpoint_kad_routing_snapshot(3, &[]).unwrap(),
        Some(4)
    );
    assert_eq!(
        store.load_kad_routing_snapshot().unwrap().initialization,
        DiscoveryInitializationStatus::Initialized
    );
}

#[test]
fn load_rejects_more_than_the_routing_limit() {
    let store = MetadataStore::in_memory().unwrap();
    {
        let mut conn = store.connection().unwrap();
        let tx = conn.transaction().unwrap();
        {
            let mut insert = tx.prepare("INSERT INTO kad_routing_contacts (node_id, ip, udp_port, tcp_port, version, udp_key, udp_firewalled, tcp_firewalled, requests_hello_res_ack, received_hello_packet, verified, contact_type, probe_type, bootstrap, last_seen_at_seconds, created_at_seconds) VALUES (?1, ?2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 'inactive', 0, 0, 0, 0)").unwrap();
            for i in 0..=KAD_ROUTING_MAX_CONTACTS {
                insert
                    .execute(rusqlite::params![
                        (i as u128).to_be_bytes().as_slice(),
                        (i + 1) as i64
                    ])
                    .unwrap();
            }
        }
        tx.commit().unwrap();
    }
    assert!(store.load_kad_routing_snapshot().is_err());
}

#[test]
fn full_snapshot_reopens_and_replacement_preserves_independent_status() {
    let path =
        std::env::temp_dir().join(format!("emulebb-kad-snapshot-{}.db", uuid::Uuid::new_v4()));
    let store = MetadataStore::open(&path).unwrap();
    let original = contact(1, 0xc0000201);
    let fresh = store.load_kad_routing_snapshot().unwrap();
    assert_eq!(fresh.revision, 0);
    assert_eq!(fresh.initialization, DiscoveryInitializationStatus::Pending);
    assert!(fresh.contacts.is_empty());
    assert_eq!(
        store
            .replace_kad_routing_snapshot(0, true, std::slice::from_ref(&original))
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        store
            .discovery_initialization_status(DiscoveryDomain::Servers)
            .unwrap(),
        DiscoveryInitializationStatus::Pending
    );
    drop(store);
    let store = MetadataStore::open(&path).unwrap();
    let loaded = store.load_kad_routing_snapshot().unwrap();
    assert_eq!(loaded.contacts, vec![original.clone()]);
    assert_eq!(
        loaded.initialization,
        DiscoveryInitializationStatus::Initialized
    );
    assert_eq!(
        store.replace_kad_routing_snapshot(0, false, &[]).unwrap(),
        None
    );
    assert_eq!(
        store.replace_kad_routing_snapshot(1, true, &[]).unwrap(),
        None
    );
    assert_eq!(store.load_kad_routing_snapshot().unwrap(), loaded);
    let mut next = contact(2, 0xc0000202);
    next.contact_type = KadRoutingContactType::Dead;
    next.expires_at_seconds = None;
    next.last_type_set_at_seconds = None;
    assert_eq!(
        store
            .replace_kad_routing_snapshot(1, false, std::slice::from_ref(&next))
            .unwrap(),
        Some(2)
    );
    assert_eq!(
        store.load_kad_routing_snapshot().unwrap().contacts,
        vec![next]
    );
    assert_eq!(
        store.replace_kad_routing_snapshot(2, false, &[]).unwrap(),
        Some(3)
    );
    let empty = store.load_kad_routing_snapshot().unwrap();
    assert!(empty.contacts.is_empty());
    assert_eq!(
        empty.initialization,
        DiscoveryInitializationStatus::Initialized
    );
    drop(store);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn invalid_duplicate_and_failed_writes_preserve_snapshot_and_revision() {
    let store = MetadataStore::in_memory().unwrap();
    let a = contact(1, 0xc0000201);
    assert_eq!(
        store
            .replace_kad_routing_snapshot(0, true, std::slice::from_ref(&a))
            .unwrap(),
        Some(1)
    );
    let previous = store.load_kad_routing_snapshot().unwrap();
    let mut b = contact(2, 0xc0000202);
    b.udp_port = 0;
    assert!(
        store
            .replace_kad_routing_snapshot(1, false, &[a.clone(), b])
            .is_err()
    );
    assert!(
        store
            .replace_kad_routing_snapshot(1, false, &[a.clone(), a.clone()])
            .is_err()
    );
    assert!(
        store
            .replace_kad_routing_snapshot(1, false, &[a.clone(), contact(2, a.ip)])
            .is_err()
    );
    assert!(
        store
            .replace_kad_routing_snapshot(1, false, &vec![a.clone(); KAD_ROUTING_MAX_CONTACTS + 1])
            .is_err()
    );
    assert_eq!(store.load_kad_routing_snapshot().unwrap(), previous);
    {
        let conn = store.connection().unwrap();
        conn.execute_batch("CREATE TEMP TRIGGER fail_kad_revision BEFORE UPDATE ON kad_routing_revision BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    }
    assert!(
        store
            .replace_kad_routing_snapshot(1, false, &[contact(3, 0xc0000203)])
            .is_err()
    );
    assert_eq!(store.load_kad_routing_snapshot().unwrap(), previous);
}

#[test]
fn first_initialization_failure_remains_pending_and_limit_is_accepted() {
    let store = MetadataStore::in_memory().unwrap();
    let mut invalid = contact(1, 0xc0000201);
    invalid.created_at_seconds = -1;
    assert!(
        store
            .replace_kad_routing_snapshot(0, true, &[invalid])
            .is_err()
    );
    let snapshot = store.load_kad_routing_snapshot().unwrap();
    assert_eq!(snapshot.revision, 0);
    assert_eq!(
        snapshot.initialization,
        DiscoveryInitializationStatus::Pending
    );
    assert!(snapshot.contacts.is_empty());
    let contacts: Vec<_> = (1..=KAD_ROUTING_MAX_CONTACTS as u32)
        .map(|n| {
            let mut entry = contact(1, n);
            entry.node_id[..4].copy_from_slice(&n.to_be_bytes());
            entry
        })
        .collect();
    assert_eq!(
        store
            .replace_kad_routing_snapshot(0, true, &contacts)
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        store.load_kad_routing_snapshot().unwrap().contacts.len(),
        KAD_ROUTING_MAX_CONTACTS
    );
}

#[test]
fn competing_connections_cannot_commit_the_same_revision() {
    let path = std::env::temp_dir().join(format!("emulebb-kad-race-{}.db", uuid::Uuid::new_v4()));
    let first = MetadataStore::open(&path).unwrap();
    let second = MetadataStore::open(&path).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = [(first, contact(1, 1)), (second, contact(2, 2))]
        .into_iter()
        .map(|(store, candidate)| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .replace_kad_routing_snapshot(0, false, &[candidate])
                    .unwrap()
            })
        })
        .collect();
    let outcomes: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Some(1))
            .count(),
        1
    );
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_none()).count(),
        1
    );
    let store = MetadataStore::open(&path).unwrap();
    let snapshot = store.load_kad_routing_snapshot().unwrap();
    assert_eq!(snapshot.revision, 1);
    assert_eq!(snapshot.contacts.len(), 1);
    drop(store);
    std::fs::remove_file(path).unwrap();
}
