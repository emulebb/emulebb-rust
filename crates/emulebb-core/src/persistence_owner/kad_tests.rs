use super::kad::{kad_charge, kad_import_charge, kad_runtime_charge, kad_scratch_tree_bound};
use super::tests::{kad_contact, setup, usage, wait_for_slots};

async fn import_kad(
    owner: &PersistenceOwner,
    bytes: &[u8],
    pending: bool,
) -> Result<Result<usize, String>, PersistenceError> {
    let mut ticket = owner.reserve_kad_ingress()?;
    let bytes = bytes.to_vec();
    ticket.finish_preparation()?;
    owner.import_kad_owned(bytes, pending, ticket).await
}
use super::*;

async fn test_dht(owner: &PersistenceOwner) -> DhtNode {
    let id = owner.load_or_create_kad_node_id().await.unwrap();
    DhtNode::new(emulebb_kad_dht::DhtConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        node_id: emulebb_kad_proto::NodeId::from_bytes(*id.as_bytes()),
        ..Default::default()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn kad_runtime_checkpoints_only_changed_state_and_seals_on_finish() {
    let (store, _, owner) = setup();
    let dht = test_dht(&owner).await;
    owner.attach_kad(&dht).await.unwrap().commit();
    wait_for_slots(&owner, 0).await;
    dht.set_public_ip_for_udp_keys(Some("198.51.100.1".parse().unwrap()))
        .await;
    dht.register_peer_key("192.0.2.99:4672".parse().unwrap(), 19);
    owner.checkpoint_kad(&dht, false).await.unwrap();
    wait_for_slots(&owner, 0).await;
    assert_eq!(store.load_kad_routing_snapshot().unwrap().revision, 0);
    let peer = emulebb_kad_routing::Contact::new(
        emulebb_kad_proto::NodeId::from_bytes([8; 16]),
        "192.0.2.8".parse().unwrap(),
        4672,
        4662,
        9,
    );
    dht.add_contact(peer.clone()).await.unwrap();
    owner.checkpoint_kad(&dht, false).await.unwrap();
    wait_for_slots(&owner, 0).await;
    let saved = store.load_kad_routing_snapshot().unwrap();
    assert_eq!(saved.revision, 1);
    assert_eq!(saved.contacts.len(), 1);
    assert_eq!(
        saved.initialization,
        emulebb_metadata::DiscoveryInitializationStatus::Pending
    );
    owner.checkpoint_kad(&dht, false).await.unwrap();
    wait_for_slots(&owner, 0).await;
    assert_eq!(store.load_kad_routing_snapshot().unwrap().revision, 1);
    owner.finish_kad(&dht).await.unwrap();
    assert_eq!(
        store.load_kad_routing_snapshot().unwrap().initialization,
        emulebb_metadata::DiscoveryInitializationStatus::Pending
    );
    assert!(
        dht.add_contact(emulebb_kad_routing::Contact::new(
            emulebb_kad_proto::NodeId::from_bytes([9; 16]),
            "192.0.2.9".parse().unwrap(),
            4672,
            4662,
            9
        ))
        .await
        .is_err()
    );
    owner.finish_kad(&dht).await.unwrap();
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn abandoned_attach_releases_runtime_for_the_next_start() {
    let (_, _, owner) = setup();
    let first = test_dht(&owner).await;
    let guard = owner.attach_kad(&first).await.unwrap();
    drop(guard);
    let next = test_dht(&owner).await;
    owner.attach_kad(&next).await.unwrap().commit();
    wait_for_slots(&owner, 0).await;
    owner.finish_kad(&next).await.unwrap();
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn retired_runtime_cannot_checkpoint_over_replacement() {
    let (store, _, owner) = setup();
    let first = test_dht(&owner).await;
    owner.attach_kad(&first).await.unwrap().commit();
    wait_for_slots(&owner, 0).await;
    owner.finish_kad(&first).await.unwrap();
    let second = test_dht(&owner).await;
    owner.attach_kad(&second).await.unwrap().commit();
    wait_for_slots(&owner, 0).await;
    assert!(matches!(
        owner.checkpoint_kad(&first, false).await,
        Err(PersistenceError::Closing)
    ));
    assert_eq!(store.load_kad_routing_snapshot().unwrap().revision, 0);
    owner.finish_kad(&second).await.unwrap();
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn shutdown_closes_regular_admission_but_allows_final_kad_snapshot() {
    let (store, _, owner) = setup();
    let dht = test_dht(&owner).await;
    owner.attach_kad(&dht).await.unwrap().commit();
    wait_for_slots(&owner, 0).await;
    dht.add_contact(emulebb_kad_routing::Contact::new(
        emulebb_kad_proto::NodeId::from_bytes([31; 16]),
        "192.0.2.31".parse().unwrap(),
        4672,
        4662,
        9,
    ))
    .await
    .unwrap();
    owner.admission.lock().unwrap().stopping = true;
    assert!(matches!(
        owner.add("44".repeat(16), "sample".into()).await,
        Err(PersistenceError::Closing)
    ));
    owner.finish_kad(&dht).await.unwrap();
    assert_eq!(store.load_kad_routing_snapshot().unwrap().contacts.len(), 1);
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn cancelled_final_snapshot_remains_queued_and_drains() {
    let (store, state, owner) = setup();
    let dht = test_dht(&owner).await;
    owner.attach_kad(&dht).await.unwrap().commit();
    wait_for_slots(&owner, 0).await;
    let held = state.lock().await;
    let friend = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("44".repeat(16), "sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    let finish = {
        let owner = Arc::clone(&owner);
        let dht = dht.clone();
        tokio::spawn(async move { owner.finish_kad(&dht).await })
    };
    wait_for_slots(&owner, 2).await;
    finish.abort();
    let _ = finish.await;
    dht.add_contact(emulebb_kad_routing::Contact::new(
        emulebb_kad_proto::NodeId::from_bytes([32; 16]),
        "192.0.2.32".parse().unwrap(),
        4672,
        4662,
        9,
    ))
    .await
    .unwrap();
    drop(held);
    friend.await.unwrap().unwrap();
    owner.close_and_drain().await.unwrap();
    assert_eq!(store.load_kad_routing_snapshot().unwrap().contacts.len(), 1);
}

#[tokio::test]
async fn final_snapshot_waits_for_ingress_reservations_and_then_drains() {
    let (store, _, owner) = setup();
    let dht = test_dht(&owner).await;
    owner.attach_kad(&dht).await.unwrap().commit();
    wait_for_slots(&owner, 0).await;
    dht.add_contact(emulebb_kad_routing::Contact::new(
        emulebb_kad_proto::NodeId::from_bytes([33; 16]),
        "192.0.2.33".parse().unwrap(),
        4672,
        4662,
        9,
    ))
    .await
    .unwrap();
    let mut tickets = Vec::new();
    while let Ok(ticket) = owner.reserve_kad_ingress() {
        tickets.push(ticket);
    }
    assert!(!tickets.is_empty());
    let waiters: Vec<_> = tickets
        .into_iter()
        .map(|ticket| {
            tokio::spawn(async move {
                ticket.cancelled().await;
                drop(ticket);
            })
        })
        .collect();
    let finish = {
        let owner = Arc::clone(&owner);
        let dht = dht.clone();
        tokio::spawn(async move { owner.finish_kad(&dht).await })
    };
    tokio::task::yield_now().await;
    assert!(!finish.is_finished());
    {
        let mut admission = owner.admission.lock().unwrap();
        admission.stopping = true;
        admission.cancel_ingress.cancel();
    }
    for waiter in waiters {
        waiter.await.unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), finish)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(store.load_kad_routing_snapshot().unwrap().contacts.len(), 1);
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn final_snapshot_survives_cancelled_caller_and_last_owner_drop() {
    use emulebb_metadata::ProfileLeaseGuard;
    use std::{
        fs::{self, OpenOptions, TryLockError},
        path::PathBuf,
        time::Duration,
    };
    let root = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join("tmp/persistence-owner-tests")
        .join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&root).unwrap();
    let lock = || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join(".emulebb-profile.lock"))
            .unwrap()
    };
    let lease = Arc::new(ProfileLeaseGuard::try_lock(lock()).unwrap());
    let path = root.join("metadata.db");
    let store = MetadataStore::open_with_profile_lease(&path, Arc::clone(&lease)).unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), Arc::clone(&state)).unwrap();
    let dht = test_dht(&owner).await;
    owner.attach_kad(&dht).await.unwrap().commit();
    wait_for_slots(&owner, 0).await;
    dht.add_contact(emulebb_kad_routing::Contact::new(
        emulebb_kad_proto::NodeId::from_bytes([34; 16]),
        "192.0.2.34".parse().unwrap(),
        4672,
        4662,
        9,
    ))
    .await
    .unwrap();
    let held = state.lock().await;
    let friend = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("44".repeat(16), "sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    let finish = {
        let owner = Arc::clone(&owner);
        let dht = dht.clone();
        tokio::spawn(async move { owner.finish_kad(&dht).await })
    };
    wait_for_slots(&owner, 2).await;
    finish.abort();
    let _ = finish.await;
    friend.abort();
    let _ = friend.await;
    drop(owner);
    drop(store);
    drop(lease);
    drop(held);
    drop(state);
    drop(dht);
    let next = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ProfileLeaseGuard::try_lock(lock()) {
                Ok(lease) => break lease,
                Err(TryLockError::WouldBlock) => {
                    tokio::time::sleep(Duration::from_millis(10)).await
                }
                Err(error) => panic!("unexpected lock error: {error:?}"),
            }
        }
    })
    .await
    .unwrap();
    let reopened = MetadataStore::open_with_profile_lease(&path, Arc::new(next)).unwrap();
    assert_eq!(
        reopened.load_kad_routing_snapshot().unwrap().contacts.len(),
        1
    );
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn attached_runtime_restores_all_saved_fields_and_bound_key() {
    let (store, _, owner) = setup();
    let record = kad_contact(42);
    store
        .replace_kad_routing_snapshot(0, true, std::slice::from_ref(&record))
        .unwrap();
    let dht = test_dht(&owner).await;
    dht.set_public_ip_for_udp_keys(Some(std::net::Ipv4Addr::from(record.udp_key_ip.unwrap())))
        .await;
    owner.attach_kad(&dht).await.unwrap().commit();
    wait_for_slots(&owner, 0).await;
    let (_, captured) = dht.capture_routing_bundle().await.unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(kad_persistence::to_metadata(&captured[0]), record);
    owner.finish_kad(&dht).await.unwrap();
    assert_eq!(store.load_kad_routing_snapshot().unwrap().revision, 1);
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn queued_checkpoint_then_import_preserves_both_sources() {
    let (store, state, owner) = setup();
    let dht = test_dht(&owner).await;
    owner.attach_kad(&dht).await.unwrap().commit();
    wait_for_slots(&owner, 0).await;
    let live = emulebb_kad_routing::Contact::new(
        emulebb_kad_proto::NodeId::from_bytes([41; 16]),
        "192.0.2.41".parse().unwrap(),
        4672,
        4662,
        9,
    );
    dht.add_contact(live).await.unwrap();
    let held = state.lock().await;
    let friend = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("44".repeat(16), "sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    let checkpoint = {
        let owner = Arc::clone(&owner);
        let dht = dht.clone();
        tokio::spawn(async move { owner.checkpoint_kad(&dht, false).await })
    };
    wait_for_slots(&owner, 2).await;
    let mut bytes = 1u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[42; 16]);
    bytes.extend_from_slice(&u32::from_be_bytes([192, 0, 3, 42]).to_le_bytes());
    bytes.extend_from_slice(&4672u16.to_le_bytes());
    bytes.extend_from_slice(&4662u16.to_le_bytes());
    bytes.push(0);
    assert!(matches!(
        import_kad(&owner, &bytes, false).await,
        Err(PersistenceError::Busy)
    ));
    drop(held);
    friend.await.unwrap().unwrap();
    checkpoint.await.unwrap().unwrap();
    wait_for_slots(&owner, 0).await;
    assert_eq!(import_kad(&owner, &bytes, false).await.unwrap().unwrap(), 1);
    let saved = store.load_kad_routing_snapshot().unwrap();
    assert_eq!(saved.contacts.len(), 2);
    assert_eq!(saved.revision, 2);
    owner.finish_kad(&dht).await.unwrap();
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn live_changes_during_import_are_not_overwritten_or_marked_clean() {
    use std::{fs, path::PathBuf, time::Duration};
    let root = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join("tmp/persistence-owner-tests")
        .join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&root).unwrap();
    let path = root.join("metadata.db");
    let store = MetadataStore::open(&path).unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), state).unwrap();
    let dht = test_dht(&owner).await;
    dht.set_public_ip_for_udp_keys(Some("198.51.100.10".parse().unwrap()))
        .await;
    owner.attach_kad(&dht).await.unwrap().commit();
    wait_for_slots(&owner, 0).await;
    let mut old = emulebb_kad_routing::Contact::new(
        emulebb_kad_proto::NodeId::from_bytes([51; 16]),
        "192.0.2.51".parse().unwrap(),
        4672,
        4662,
        9,
    );
    old.mark_dead();
    old.expires_at = Some(std::time::SystemTime::now() + Duration::from_secs(2));
    dht.add_contact(old).await.unwrap();
    let blocker = rusqlite::Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut bytes = 1u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[52; 16]);
    bytes.extend_from_slice(&u32::from_be_bytes([192, 0, 3, 52]).to_le_bytes());
    bytes.extend_from_slice(&4672u16.to_le_bytes());
    bytes.extend_from_slice(&4662u16.to_le_bytes());
    bytes.push(0);
    let mut ticket = owner.reserve_kad_ingress().unwrap();
    ticket.finish_preparation().unwrap();
    let import = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.import_kad_owned(bytes, false, ticket).await })
    };
    tokio::time::timeout(Duration::from_secs(5), owner.worker_started.notified())
        .await
        .unwrap();
    assert!(usage(&owner).1 >= kad_import_charge().unwrap());
    assert!(matches!(
        owner.reserve_kad_ingress(),
        Err(PersistenceError::Busy)
    ));
    let fresh = emulebb_kad_routing::Contact::new(
        emulebb_kad_proto::NodeId::from_bytes([53; 16]),
        "192.0.4.53".parse().unwrap(),
        4672,
        4662,
        9,
    );
    dht.add_contact(fresh).await.unwrap();
    dht.register_peer_key("192.0.4.53:4672".parse().unwrap(), 0x55);
    tokio::time::sleep(Duration::from_millis(2200)).await;
    dht.routing_small_timer_maintenance().await;
    blocker.execute_batch("ROLLBACK").unwrap();
    drop(blocker);
    assert_eq!(import.await.unwrap().unwrap().unwrap(), 1);
    assert!(
        store
            .load_kad_routing_snapshot()
            .unwrap()
            .contacts
            .iter()
            .any(|c| c.node_id == [51; 16])
    );
    let live = dht.capture_routing_snapshot().await.unwrap();
    assert!(
        !live
            .iter()
            .any(|c| c.node_id == emulebb_kad_proto::NodeId::from_bytes([51; 16]))
    );
    assert!(
        live.iter()
            .any(|c| c.node_id == emulebb_kad_proto::NodeId::from_bytes([52; 16]))
    );
    assert!(live.iter().any(
        |c| c.node_id == emulebb_kad_proto::NodeId::from_bytes([53; 16])
            && c.udp_key.value() == 0x55
    ));
    owner.checkpoint_kad(&dht, false).await.unwrap();
    wait_for_slots(&owner, 0).await;
    let saved = store.load_kad_routing_snapshot().unwrap();
    assert!(!saved.contacts.iter().any(|c| c.node_id == [51; 16]));
    assert!(
        saved
            .contacts
            .iter()
            .any(|c| c.node_id == [53; 16] && c.udp_key == 0x55)
    );
    owner.finish_kad(&dht).await.unwrap();
    owner.close_and_drain().await.unwrap();
    drop(dht);
    drop(owner);
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn kad_full_runtime_and_import_reservations_fit_the_shared_budget() {
    let baseline =
        KAD_RESERVED_CAPACITY * std::mem::size_of::<emulebb_kad_dht::RoutingKeyProjection>();
    assert!(kad_runtime_charge().unwrap() + baseline <= MAX_BYTES);
    assert!(kad_import_charge().unwrap() + baseline <= MAX_BYTES);
    let live_delta = KAD_RESERVED_CAPACITY * std::mem::size_of::<RoutingSnapshotContact>()
        + 2 * KAD_RESERVED_CAPACITY * (std::mem::size_of::<emulebb_kad_proto::NodeId>() + 1);
    assert!(kad_import_charge().unwrap() - crate::NODES_DAT_MAX_BYTES >= live_delta);
    assert!(
        std::mem::size_of::<KadRoutingContact>() * KAD_ROUTING_MAX_CONTACTS
            <= kad_charge().unwrap()
    );
    let mut table = emulebb_kad_routing::RoutingTable::new(emulebb_kad_proto::NodeId::ZERO);
    for i in 1..=12_000u32 {
        let mut id = [0; 16];
        id[..4].copy_from_slice(&i.wrapping_mul(2_654_435_761).to_be_bytes());
        let ip = std::net::Ipv4Addr::from(i.wrapping_mul(256) + 1);
        let contact = emulebb_kad_routing::Contact::new(
            emulebb_kad_proto::NodeId::from_bytes(id),
            ip,
            4672,
            4662,
            9,
        );
        let _ = table.add_contact(contact);
    }
    assert!(table.owned_bytes() <= kad_scratch_tree_bound().unwrap());
}

#[tokio::test]
async fn kad_import_accepts_large_source_but_rejects_truncated_source_atomically() {
    let (store, _, owner) = setup();
    let mut bytes = 13_000u32.to_le_bytes().to_vec();
    for _ in 0..13_000 {
        bytes.extend_from_slice(&[4; 16]);
        bytes.extend_from_slice(&u32::from_be_bytes([192, 0, 2, 4]).to_le_bytes());
        bytes.extend_from_slice(&4672u16.to_le_bytes());
        bytes.extend_from_slice(&4662u16.to_le_bytes());
        bytes.push(0);
    }
    assert!(
        import_kad(&owner, &bytes[..bytes.len() - 1], true)
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(store.load_kad_routing_snapshot().unwrap().revision, 0);
    assert_eq!(import_kad(&owner, &bytes, true).await.unwrap().unwrap(), 1);
    let saved = store.load_kad_routing_snapshot().unwrap();
    assert_eq!(saved.revision, 1);
    assert_eq!(saved.contacts.len(), 1);
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn kad_import_sql_failure_rolls_back_and_retry_succeeds() {
    let root = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join("tmp/persistence-owner-tests")
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("metadata.db");
    drop(MetadataStore::open(&path).unwrap());
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TEMP TRIGGER fail_kad_import BEFORE INSERT ON main.kad_routing_contacts WHEN NEW.ip = 3221225988 BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    let store = MetadataStore::from_connection(conn).unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), state).unwrap();
    let source = |last: u8| {
        let mut bytes = 1u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[last; 16]);
        bytes.extend_from_slice(&u32::from_be_bytes([192, 0, 2, last]).to_le_bytes());
        bytes.extend_from_slice(&4672u16.to_le_bytes());
        bytes.extend_from_slice(&4662u16.to_le_bytes());
        bytes.push(0);
        bytes
    };
    assert!(matches!(
        import_kad(&owner, &source(4), true).await,
        Err(PersistenceError::Storage(_))
    ));
    let failed = store.load_kad_routing_snapshot().unwrap();
    assert_eq!(
        failed.initialization,
        emulebb_metadata::DiscoveryInitializationStatus::Pending
    );
    assert_eq!(failed.revision, 0);
    assert!(failed.contacts.is_empty());
    assert_eq!(
        import_kad(&owner, &source(5), true).await.unwrap().unwrap(),
        1
    );
    owner.close_and_drain().await.unwrap();
    drop(owner);
    drop(store);
    let reopened = MetadataStore::open(&path).unwrap();
    assert_eq!(
        reopened.load_kad_routing_snapshot().unwrap().contacts.len(),
        1
    );
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn provider_import_does_not_overwrite_initialized_empty_operator_state() {
    let (store, _, owner) = setup();
    let mut bytes = 1u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[4; 16]);
    bytes.extend_from_slice(&u32::from_be_bytes([192, 0, 2, 4]).to_le_bytes());
    bytes.extend_from_slice(&4672u16.to_le_bytes());
    bytes.extend_from_slice(&4662u16.to_le_bytes());
    bytes.push(0);
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let pending = {
        let owner = Arc::clone(&owner);
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        tokio::spawn(async move {
            entered.notify_one();
            release.notified().await;
            import_kad(&owner, &bytes, true).await.unwrap().unwrap()
        })
    };
    entered.notified().await;
    store.replace_kad_routing_snapshot(0, true, &[]).unwrap();
    release.notify_one();
    assert_eq!(pending.await.unwrap(), 0);
    let snapshot = store.load_kad_routing_snapshot().unwrap();
    assert!(snapshot.contacts.is_empty());
    assert_eq!(
        snapshot.initialization,
        emulebb_metadata::DiscoveryInitializationStatus::Initialized
    );
    assert_eq!(snapshot.revision, 1);
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn provider_retry_merges_pending_contacts_without_weakening_them() {
    let root = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join("tmp/persistence-owner-tests")
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("metadata.db");
    let store = MetadataStore::open(&path).unwrap();
    let mut existing = kad_contact(44);
    existing.ip = u32::from_be_bytes([192, 0, 2, 44]);
    store
        .checkpoint_kad_routing_snapshot(0, std::slice::from_ref(&existing))
        .unwrap();
    drop(store);
    let store = MetadataStore::open(&path).unwrap();
    assert_eq!(
        store.load_kad_routing_snapshot().unwrap().initialization,
        emulebb_metadata::DiscoveryInitializationStatus::Pending
    );
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), state).unwrap();
    let mut bytes = 1u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&existing.node_id);
    bytes.extend_from_slice(&existing.ip.to_le_bytes());
    bytes.extend_from_slice(&existing.udp_port.to_le_bytes());
    bytes.extend_from_slice(&existing.tcp_port.to_le_bytes());
    bytes.push(0);
    assert_eq!(import_kad(&owner, &bytes, true).await.unwrap().unwrap(), 1);
    let saved = store.load_kad_routing_snapshot().unwrap();
    assert_eq!(
        saved.initialization,
        emulebb_metadata::DiscoveryInitializationStatus::Initialized
    );
    assert_eq!(saved.contacts.len(), 1);
    let merged = &saved.contacts[0];
    assert_eq!(merged.node_id, existing.node_id);
    assert_eq!(merged.udp_key, existing.udp_key);
    assert_eq!(merged.udp_key_ip, existing.udp_key_ip);
    assert_eq!(merged.version, existing.version);
    assert_eq!(merged.probe_type, existing.probe_type);
    assert!(merged.verified);
    owner.close_and_drain().await.unwrap();
    drop(owner);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn pending_empty_runtime_stays_pending_across_final_flush_and_reopen() {
    let root = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join("tmp/persistence-owner-tests")
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("metadata.db");
    let store = MetadataStore::open(&path).unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), state).unwrap();
    let dht = test_dht(&owner).await;
    owner.attach_kad(&dht).await.unwrap().commit();
    wait_for_slots(&owner, 0).await;
    owner.checkpoint_kad(&dht, false).await.unwrap();
    wait_for_slots(&owner, 0).await;
    owner.finish_kad(&dht).await.unwrap();
    owner.close_and_drain().await.unwrap();
    drop(dht);
    drop(owner);
    drop(store);
    let reopened = MetadataStore::open(&path).unwrap();
    let pending = reopened.load_kad_routing_snapshot().unwrap();
    assert_eq!(
        pending.initialization,
        emulebb_metadata::DiscoveryInitializationStatus::Pending
    );
    assert!(pending.contacts.is_empty());
    assert_eq!(pending.revision, 0);
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn attach_handoff_releases_payload_quota_but_fences_following_commands() {
    let (_, _, owner) = setup();
    let dht = test_dht(&owner).await;
    let handoff = owner.attach_kad(&dht).await.unwrap();
    assert_eq!(usage(&owner).0, 0);
    let ticket = owner.reserve_kad_ingress().unwrap();
    drop(ticket);
    let pending = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.load_kad().await })
    };
    wait_for_slots(&owner, 1).await;
    assert!(!pending.is_finished());
    handoff.commit();
    pending.await.unwrap().unwrap();
    owner.finish_kad(&dht).await.unwrap();
    owner.close_and_drain().await.unwrap();
}
