use super::kad::kad_charge;
use super::*;
use std::sync::atomic::Ordering;

pub(super) fn setup() -> (MetadataStore, Arc<Mutex<CoreState>>, Arc<PersistenceOwner>) {
    let store = MetadataStore::in_memory().unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), Arc::clone(&state)).unwrap();
    (store, state, owner)
}

pub(super) fn usage(owner: &PersistenceOwner) -> (usize, usize) {
    let admission = owner.admission.lock().unwrap();
    let quota = admission.quota.lock().unwrap();
    (quota.slots, quota.bytes)
}

pub(super) async fn wait_for_slots(owner: &PersistenceOwner, expected: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if usage(owner).0 == expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn root_sql_failure_keeps_state_and_serving_then_retry_succeeds() {
    let uri = format!(
        "file:root-failure-{}?mode=memory&cache=shared",
        uuid::Uuid::new_v4()
    );
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        | rusqlite::OpenFlags::SQLITE_OPEN_URI;
    let store =
        MetadataStore::from_connection(rusqlite::Connection::open_with_flags(&uri, flags).unwrap())
            .unwrap();
    let root = crate::unique_runtime_dir("root-sql-failure");
    let path = root.join("copy.bin");
    std::fs::write(&path, b"root failure serving evidence").unwrap();
    let mut roots_store = store.clone();
    let root_row = crate::SharedDirectoryRoot {
        path: root.to_string_lossy().into_owned(),
        watch_enabled: false,
        monitor_owned: false,
        shareable: true,
        accessible: true,
    };
    roots_store
        .replace_shared_directory_roots(&[emulebb_metadata::MetadataSharedDirectoryRoot {
            path: root_row.path.clone(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    let runtime = Arc::new(
        emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime::load_or_create_with_metadata(
            &root.join("transfers"),
            store.clone(),
        )
        .unwrap(),
    );
    let shared = runtime.ingest_local_file(&path, "copy.bin").await.unwrap();
    let native = emulebb_ed2k::long_path::long_path(&path);
    let fingerprint = store
        .local_file_instance(&native)
        .unwrap()
        .unwrap()
        .verified_fingerprint;
    assert!(
        runtime
            .admit_monitored_shared_path(
                &shared.file_hash,
                &root,
                &native,
                std::path::Path::new("copy.bin"),
                &fingerprint,
                None
            )
            .await
            .unwrap()
    );
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![root_row.clone()]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), Arc::clone(&state)).unwrap();
    let fault = rusqlite::Connection::open_with_flags(&uri, flags).unwrap();
    fault.execute_batch("CREATE TRIGGER root_failure BEFORE DELETE ON shared_directory_root_origins WHEN old.origin='explicit' BEGIN SELECT RAISE(ABORT,'injected root failure'); END;").unwrap();
    let root_id = store.library_root_page(0, 100).unwrap().items[0].id;
    let sharing = || category::CategorySharingContext {
        runtime: Arc::clone(&runtime),
        incoming: Arc::new(root.join("incoming")),
        root_change: Arc::default(),
        probe_sender: std::sync::Weak::new(),
    };
    assert!(matches!(
        owner.delete_root(root_id, sharing()).await,
        Err(PersistenceError::Storage(_))
    ));
    assert_eq!(
        state.lock().await.shared_directories,
        vec![root_row.clone()]
    );
    assert_eq!(store.shared_directory_roots().unwrap().len(), 1);
    let hash: emulebb_kad_proto::Ed2kHash = shared.file_hash.parse().unwrap();
    assert_eq!(
        runtime.admit_shared_hashes(&[hash.0], true).await.unwrap(),
        Some(vec![true])
    );
    fault.execute_batch("DROP TRIGGER root_failure;").unwrap();
    assert!(matches!(
        owner.delete_root(root_id, sharing()).await.unwrap(),
        emulebb_metadata::MetadataLibraryRootDelete::Deleted(_)
    ));
    assert!(state.lock().await.shared_directories.is_empty());
    assert!(store.shared_directory_roots().unwrap().is_empty());
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn cancelled_root_deletion_reconciles_memberships_and_preserves_payload() {
    let core =
        crate::EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
            .unwrap();
    let root = crate::unique_runtime_dir("root-delete-owner");
    let path = root.join("sample.bin");
    std::fs::write(&path, b"root deletion preserves payload").unwrap();
    let resource = core
        .metadata_store
        .create_library_root(&root, false, true)
        .unwrap()
        .unwrap();
    let descriptor = crate::SharedDirectoryRoot {
        path: emulebb_metadata::NativePath::from(root.as_path()).display_path(),
        watch_enabled: false,
        monitor_owned: false,
        accessible: true,
        shareable: true,
    };
    core.state.lock().await.shared_directories = vec![descriptor.clone()];
    let shared = core
        .ed2k_transfers
        .ingest_local_file(&path, "sample.bin")
        .await
        .unwrap();
    let native = emulebb_ed2k::long_path::long_path(&path);
    let fingerprint = core
        .metadata_store
        .local_file_instance(&native)
        .unwrap()
        .unwrap()
        .verified_fingerprint;
    assert!(
        core.ed2k_transfers
            .admit_monitored_shared_path(
                &shared.file_hash,
                &root,
                &native,
                std::path::Path::new("sample.bin"),
                &fingerprint,
                None
            )
            .await
            .unwrap()
    );
    let hash: emulebb_kad_proto::Ed2kHash = shared.file_hash.parse().unwrap();
    assert_eq!(
        core.ed2k_transfers
            .admit_shared_hashes(&[hash.0], true)
            .await
            .unwrap(),
        Some(vec![true])
    );
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let entered = gate.entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();
    let writer = {
        let core = core.clone();
        tokio::spawn(async move { core.delete_library_root(resource.id).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), entered)
        .await
        .unwrap();
    assert!(
        core.metadata_store
            .library_root(resource.id)
            .unwrap()
            .is_none()
    );
    assert_eq!(core.state.lock().await.shared_directories, vec![descriptor]);
    writer.abort();
    let _ = writer.await;
    gate.release.notify_one();
    // Caller cancellation leaves the admitted reconciliation running. Wait for
    // that owned request before issuing a separate daemon shutdown cancellation.
    wait_for_slots(&owner, 0).await;
    tokio::time::timeout(std::time::Duration::from_secs(10), owner.close_and_drain())
        .await
        .unwrap()
        .unwrap();
    assert!(core.state.lock().await.shared_directories.is_empty());
    assert_eq!(
        core.ed2k_transfers
            .admit_shared_hashes(&[hash.0], true)
            .await
            .unwrap(),
        Some(vec![false])
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"root deletion preserves payload"
    );
    assert_eq!(usage(&owner), (0, 0));
}

#[tokio::test]
async fn cancelled_watch_edit_publishes_only_addressed_root_without_scan() {
    let core =
        crate::EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
            .unwrap();
    let base = crate::unique_runtime_dir("root-watch-owner");
    let roots: Vec<_> = ["alpha", "beta"]
        .into_iter()
        .map(|name| crate::SharedDirectoryRoot {
            path: base.join(name).to_string_lossy().into_owned(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        })
        .collect();
    core.metadata_store
        .clone()
        .replace_shared_directory_roots(
            &roots
                .iter()
                .map(|root| emulebb_metadata::MetadataSharedDirectoryRoot {
                    path: root.path.clone(),
                    watch_enabled: root.watch_enabled,
                    monitor_owned: root.monitor_owned,
                    shareable: root.shareable,
                    accessible: root.accessible,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
    core.state.lock().await.shared_directories = roots.clone();
    let id = core.metadata_store.library_root_page(0, 100).unwrap().items[0].id;
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let entered = gate.entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();
    let writer = {
        let core = core.clone();
        tokio::spawn(async move { core.patch_library_root_watch(id, true).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), entered)
        .await
        .unwrap();
    assert!(
        core.metadata_store
            .library_root(id)
            .unwrap()
            .unwrap()
            .watch_enabled
    );
    assert_eq!(core.state.lock().await.shared_directories, roots);
    writer.abort();
    let _ = writer.await;
    gate.release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), owner.close_and_drain())
        .await
        .unwrap()
        .unwrap();
    let cached = core.state.lock().await.shared_directories.clone();
    assert!(cached[0].watch_enabled);
    assert_eq!(cached[1], roots[1]);
    assert!(!core.shared_reload_running.load(Ordering::Acquire));
    assert_eq!(usage(&owner), (0, 0));
}

#[tokio::test]
async fn managed_root_watch_edit_preserves_ownership_and_missing_id_is_absent() {
    let core =
        crate::EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
            .unwrap();
    let incoming = crate::unique_runtime_dir("managed-root-watch-owner");
    core.metadata_store
        .clone()
        .replace_implicit_shared_directory_roots(&[emulebb_metadata::MetadataSharedDirectoryRoot {
            path: incoming.to_string_lossy().into_owned(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    let id = core.metadata_store.library_root_page(0, 100).unwrap().items[0].id;
    let result = core
        .patch_library_root_watch(id, true)
        .await
        .unwrap()
        .unwrap();
    assert!(result.managed && result.watch_enabled);
    assert_eq!(
        core.delete_library_root(id).await.unwrap(),
        emulebb_metadata::MetadataLibraryRootDelete::Managed
    );
    assert_eq!(
        core.delete_library_root(i64::MAX).await.unwrap(),
        emulebb_metadata::MetadataLibraryRootDelete::Missing
    );
    assert_eq!(core.metadata_store.library_root(id).unwrap(), Some(result));
    assert!(
        core.patch_library_root_watch(i64::MAX, true)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!core.shared_reload_running.load(Ordering::Acquire));
    core.drain_persistence().await.unwrap();
}

#[tokio::test]
async fn canonical_root_creation_rejects_overlap_without_changing_existing_resources() {
    let base = crate::unique_runtime_dir("root-create-owner");
    let incoming = base.join("incoming");
    let shared = base.join("shared");
    let child = shared.join("rare");
    std::fs::create_dir_all(&incoming).unwrap();
    std::fs::create_dir_all(&child).unwrap();
    let core =
        crate::EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
            .unwrap()
            .with_incoming_dir(incoming);
    let execution = core.shared_reload_gate.lock().await;
    // A mandatory destination participates in overlap rejection before any
    // explicit root has been created.
    assert!(
        core.create_library_root(base.to_str().unwrap(), false)
            .await
            .unwrap()
            .is_none()
    );
    let created = core
        .create_library_root(shared.to_str().unwrap(), true)
        .await
        .unwrap()
        .unwrap();
    let before = core.state.lock().await.shared_directories.clone();
    for path in [&base, &shared, &child] {
        assert!(
            core.create_library_root(path.to_str().unwrap(), false)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(core.state.lock().await.shared_directories, before);
    assert_eq!(
        core.metadata_store.library_root(created.id).unwrap(),
        Some(created)
    );
    assert_eq!(
        core.metadata_store.library_root_page(0, 100).unwrap().total,
        2
    );
    drop(execution);
    core.drain_persistence().await.unwrap();
}

#[tokio::test]
async fn cancelled_root_request_still_scans_committed_directory() {
    let core =
        crate::EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
            .unwrap();
    let root = crate::unique_runtime_dir("cancel-root-scan");
    std::fs::write(root.join("committed.bin"), b"committed scan").unwrap();
    let execution = core.shared_reload_gate.lock().await;
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let entered = gate.entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();
    let writer = {
        let core = core.clone();
        let path = root.to_string_lossy().into_owned();
        tokio::spawn(async move { core.create_library_root(&path, false).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), entered)
        .await
        .unwrap();
    writer.abort();
    let _ = writer.await;
    gate.release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while core.state.lock().await.shared_directories.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(core.shares().await.is_empty());
    assert!(core.shared_reload_running.load(Ordering::Acquire));
    // The canceled request cannot advance the worker: release the execution
    // gate and require the owned scan to discover and publish the real file.
    drop(execution);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if core
                .shares()
                .await
                .iter()
                .any(|share| share.name == "committed.bin")
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(core.shared_monitor_stopped.load(Ordering::Acquire));
    tokio::time::timeout(std::time::Duration::from_secs(5), core.drain_persistence())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn sealed_reload_handoff_reports_committed_root_without_scan() {
    let core =
        crate::EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
            .unwrap();
    let root = crate::unique_runtime_dir("sealed-root-scan");
    std::fs::write(root.join("committed.bin"), b"committed root").unwrap();
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let entered = gate.entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();
    let writer = {
        let core = core.clone();
        let path = root.to_string_lossy().into_owned();
        tokio::spawn(async move { core.create_library_root(&path, false).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), entered)
        .await
        .unwrap();
    assert_eq!(
        core.metadata_store.shared_directory_roots().unwrap().len(),
        1
    );
    assert!(core.state.lock().await.shared_directories.is_empty());
    core.begin_shutdown();
    gate.release.notify_one();
    let error = tokio::time::timeout(std::time::Duration::from_secs(5), writer)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<PersistenceError>(),
        Some(PersistenceError::CommittedPublicationFailed)
    ));
    assert_eq!(core.state.lock().await.shared_directories.len(), 1);
    assert_eq!(
        core.metadata_store.shared_directory_roots().unwrap().len(),
        1
    );
    assert!(!core.shared_reload_pending.load(Ordering::Acquire));
    assert!(core.shares().await.is_empty());
    tokio::time::timeout(std::time::Duration::from_secs(5), core.drain_persistence())
        .await
        .unwrap()
        .unwrap_err();
    assert!(!core.shared_reload_running.load(Ordering::Acquire));
    assert_eq!(usage(&owner), (0, 0));
}

#[tokio::test]
async fn explicit_root_continuation_reconciles_each_removed_root() {
    let uri = format!(
        "file:root-multi-{}?mode=memory&cache=shared",
        uuid::Uuid::new_v4()
    );
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        | rusqlite::OpenFlags::SQLITE_OPEN_URI;
    let store =
        MetadataStore::from_connection(rusqlite::Connection::open_with_flags(&uri, flags).unwrap())
            .unwrap();
    let base = crate::unique_runtime_dir("multi-root-owner");
    let roots: Vec<_> = ["one", "two"]
        .into_iter()
        .map(|name| crate::SharedDirectoryRoot {
            path: base.join(name).to_string_lossy().into_owned(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        })
        .collect();
    let rows: Vec<_> = roots
        .iter()
        .map(|root| emulebb_metadata::MetadataSharedDirectoryRoot {
            path: root.path.clone(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        })
        .collect();
    store.clone().replace_shared_directory_roots(&rows).unwrap();
    let mut conn = rusqlite::Connection::open_with_flags(&uri, flags).unwrap();
    let tx = conn.transaction().unwrap();
    for (index, root) in roots.iter().enumerate() {
        let hash = [u8::try_from(index + 1).unwrap(); 16];
        tx.execute("INSERT INTO known_files(ed2k_hash,size_bytes,display_name,first_seen_at_s,last_seen_at_s,updated_at_s) VALUES(?1,1,'sample',0,0,0)", [&hash[..]]).unwrap();
        let known_id = tx.last_insert_rowid();
        let path =
            emulebb_metadata::NativePath::from(std::path::Path::new(&root.path).join("sample"));
        let display = path.display_path();
        tx.execute("INSERT INTO local_paths(display_path,native_path,search_key,sort_key,file_name_search_key,platform) VALUES(?1,?2,?1,?1,?1,?3)", rusqlite::params![display, path.storage_bytes(), emulebb_metadata::NativePath::platform()]).unwrap();
        let path_id = tx.last_insert_rowid();
        tx.execute("INSERT INTO local_file_instances(path_id,known_file_id,size_bytes,native_identity,verified_fingerprint,verified_at_s) VALUES(?1,?2,1,x'01',x'01',0)", rusqlite::params![path_id, known_id]).unwrap();
        let root_native = emulebb_metadata::NativePath::from(std::path::Path::new(&root.path));
        let root_id: i64 = tx.query_row("SELECT r.id FROM shared_directory_roots r JOIN local_paths p ON p.id=r.path_id WHERE p.platform=?1 AND p.native_path=?2", rusqlite::params![emulebb_metadata::NativePath::platform(), root_native.storage_bytes()], |row| row.get(0)).unwrap();
        tx.execute("INSERT INTO shared_file_memberships(root_id,path_id,known_file_id,relative_path,first_seen_at_s,last_seen_at_s) VALUES(?1,?2,?3,'sample',0,0)", rusqlite::params![root_id,path_id,known_id]).unwrap();
    }
    tx.commit().unwrap();
    drop(conn);
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, roots.clone()).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), Arc::clone(&state)).unwrap();
    let runtime = Arc::new(
        emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime::load_or_create_with_metadata(
            &base.join("transfers"),
            store.clone(),
        )
        .unwrap(),
    );
    for value in 1..=2u8 {
        runtime
            .shared_catalog()
            .write()
            .await
            .push(emulebb_ed2k::ed2k_transfer::Ed2kSharedEntry {
                file_hash: emulebb_kad_proto::Ed2kHash::from_bytes([value; 16]).to_string(),
                display_name: "sample".into(),
                file_size: 1,
                verified_complete: true,
                verified_ranges: vec![],
                compatibility_hint: false,
                source_count_hint: None,
                aich_root: None,
                upload_priority: "normal".into(),
                auto_upload_priority: false,
                comment: String::new(),
                rating: 0,
                media: Default::default(),
                all_time_uploaded_bytes: 0,
                complete_parts: vec![],
                publish: Default::default(),
            });
    }
    let ids: Vec<_> = store
        .library_root_page(0, 100)
        .unwrap()
        .items
        .into_iter()
        .map(|root| root.id)
        .collect();
    for id in ids {
        let result = owner.delete_root(
            id,
            category::CategorySharingContext {
                runtime: Arc::clone(&runtime),
                incoming: Arc::new(base.join("incoming")),
                root_change: Arc::default(),
                probe_sender: std::sync::Weak::new(),
            },
        );
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(5), result)
                .await
                .unwrap()
                .unwrap(),
            emulebb_metadata::MetadataLibraryRootDelete::Deleted(_)
        ));
    }
    assert!(state.lock().await.shared_directories.is_empty());
    assert_eq!(runtime.shared_catalog_count().await, 0);
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn cancelled_identity_request_completes_before_drain() {
    let (store, state, owner) = setup();
    let held = state.lock().await;
    let friend = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("44".repeat(16), "sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    let identity = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.load_or_create_kad_node_id().await })
    };
    wait_for_slots(&owner, 2).await;
    identity.abort();
    let _ = identity.await;
    drop(held);
    friend.await.unwrap().unwrap();
    owner.close_and_drain().await.unwrap();
    let saved = store.load_local_identity("kad-node-id").unwrap().unwrap();
    assert_ne!(saved.public_identity.unwrap(), vec![0; 16]);
    assert_eq!(usage(&owner), (0, 0));
}

#[tokio::test]
async fn identity_owner_returns_the_same_nonzero_id() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let store = MetadataStore::from_connection(conn).unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), state).unwrap();
    let id = owner.load_or_create_kad_node_id().await.unwrap();
    assert_ne!(id.as_bytes(), &[0; 16]);
    assert_eq!(owner.load_or_create_kad_node_id().await.unwrap(), id);
    owner.close_and_drain().await.unwrap();
}

pub(super) fn kad_contact(i: u32) -> KadRoutingContact {
    let mut id = [0; 16];
    id[..4].copy_from_slice(&i.to_be_bytes());
    KadRoutingContact {
        node_id: id,
        ip: i + 1,
        udp_port: 20020,
        tcp_port: 20019,
        version: 9,
        udp_key: 123,
        udp_key_ip: Some(42),
        hello_source_udp_port: Some(20020),
        udp_firewalled: false,
        tcp_firewalled: false,
        requests_hello_res_ack: false,
        received_hello_packet: true,
        verified: true,
        contact_type: emulebb_metadata::KadRoutingContactType::Active,
        probe_type: 1,
        bootstrap: false,
        expires_at_seconds: Some(1_900_000_000),
        last_type_set_at_seconds: Some(1_700_000_000),
        last_seen_at_seconds: 1_700_000_000,
        created_at_seconds: 1_700_000_000,
    }
}

#[tokio::test]
async fn kad_full_snapshot_reply_retains_bytes_without_retaining_slot() {
    use emulebb_metadata::DiscoveryInitializationStatus;
    let (store, _, owner) = setup();
    let input: Vec<_> = (0..KAD_ROUTING_MAX_CONTACTS as u32)
        .map(kad_contact)
        .collect();
    assert!(kad_charge().unwrap() <= MAX_BYTES);
    assert_eq!(
        store.replace_kad_routing_snapshot(0, true, &input).unwrap(),
        Some(1)
    );
    let loaded = owner.load_kad().await.unwrap();
    assert_eq!(loaded.snapshot().contacts, input);
    assert_eq!(
        loaded.snapshot().initialization,
        DiscoveryInitializationStatus::Initialized
    );
    wait_for_slots(&owner, 0).await;
    let actual = loaded.snapshot().contacts.capacity() * std::mem::size_of::<KadRoutingContact>();
    assert_eq!(usage(&owner), (0, actual));
    assert!(actual <= kad_charge().unwrap());
    owner.close_and_drain().await.unwrap();
    assert_eq!(usage(&owner), (0, actual));
    drop(loaded);
    assert_eq!(usage(&owner), (0, 0));
}

#[tokio::test]
async fn empty_kad_load_retains_no_payload_bytes() {
    let (_, _, owner) = setup();
    let pending = owner.load_kad().await.unwrap();
    assert_eq!(
        pending.snapshot().initialization,
        emulebb_metadata::DiscoveryInitializationStatus::Pending
    );
    assert_eq!(pending.snapshot().contacts.capacity(), 0);
    assert_eq!(usage(&owner), (0, 0));
    drop(pending);
    owner.close_and_drain().await.unwrap();
}
#[tokio::test]
async fn retained_kad_replies_apply_shared_byte_backpressure() {
    let (store, _, owner) = setup();
    let input: Vec<_> = (0..KAD_ROUTING_MAX_CONTACTS as u32)
        .map(kad_contact)
        .collect();
    assert_eq!(
        store.replace_kad_routing_snapshot(0, true, &input).unwrap(),
        Some(1)
    );
    let mut replies = Vec::new();
    loop {
        match owner.load_kad().await {
            Ok(snapshot) => replies.push(snapshot),
            Err(PersistenceError::Busy) => break,
            Err(error) => panic!("unexpected load error: {error}"),
        }
    }
    assert!(!replies.is_empty());
    wait_for_slots(&owner, 0).await;
    assert!(usage(&owner).1 <= MAX_BYTES);
    drop(replies.pop());
    let next = owner.load_kad().await.unwrap();
    drop(next);
    drop(replies);
    owner.close_and_drain().await.unwrap();
    assert_eq!(usage(&owner), (0, 0));
}

#[tokio::test]
async fn concurrent_ingress_is_reserved_before_fetch_and_released_on_drop() {
    let (_, _, owner) = setup();
    let mut tickets = Vec::new();
    for _ in 0..(MAX_BYTES / KAD_INGRESS_PREPARATION_BYTES) {
        tickets.push(owner.reserve_kad_ingress().unwrap());
    }
    assert_eq!(usage(&owner), (0, MAX_BYTES));
    assert!(matches!(
        owner.reserve_kad_ingress(),
        Err(PersistenceError::Busy)
    ));
    drop(tickets.pop());
    let ticket = owner.reserve_kad_ingress().unwrap();
    drop(ticket);
    drop(tickets);
    assert_eq!(usage(&owner), (0, 0));
    let mut ticket = owner.reserve_kad_ingress().unwrap();
    let mut bytes = 1u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[4; 16]);
    bytes.extend_from_slice(&u32::from_be_bytes([192, 0, 2, 4]).to_le_bytes());
    bytes.extend_from_slice(&4672u16.to_le_bytes());
    bytes.extend_from_slice(&4662u16.to_le_bytes());
    bytes.push(0);
    ticket.finish_preparation().unwrap();
    assert_eq!(
        owner
            .import_kad_owned(bytes, true, ticket)
            .await
            .unwrap()
            .unwrap(),
        1
    );
    wait_for_slots(&owner, 0).await;
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn cancelled_queued_kad_initialization_survives_last_owner_drop() {
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
    let mut ticket = owner.reserve_kad_ingress().unwrap();
    ticket.finish_preparation().unwrap();
    let mut bytes = 1u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[17; 16]);
    bytes.extend_from_slice(&u32::from_be_bytes([192, 0, 2, 17]).to_le_bytes());
    bytes.extend_from_slice(&4672u16.to_le_bytes());
    bytes.extend_from_slice(&4662u16.to_le_bytes());
    bytes.push(0);
    let guard = state.lock().await;
    let friend = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("88".repeat(16), "sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    let kad = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.import_kad_owned(bytes, true, ticket).await })
    };
    wait_for_slots(&owner, 2).await;
    kad.abort();
    let _ = kad.await;
    friend.abort();
    let _ = friend.await;
    drop(owner);
    drop(store);
    drop(lease);
    drop(guard);
    drop(state);
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
        reopened.load_kad_routing_snapshot().unwrap().contacts[0].node_id,
        [17; 16]
    );
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn cancelled_caller_keeps_permit_until_ordered_publication_and_drain() {
    let (store, state, owner) = setup();
    let guard = state.lock().await;
    let task = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("11".repeat(16), "Sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    task.abort();
    assert_eq!(usage(&owner).0, 1);
    let close = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.close_and_drain().await })
    };
    tokio::task::yield_now().await;
    assert!(!close.is_finished());
    drop(guard);
    close.await.unwrap().unwrap();
    assert_eq!(state.lock().await.friends.len(), 1);
    assert_eq!(store.load_friends().unwrap().len(), 1);
    assert_eq!(usage(&owner).0, 0);
    assert!(matches!(
        owner.delete("11".repeat(16)).await,
        Err(PersistenceError::Closing)
    ));
}

#[tokio::test]
async fn cancellation_after_commit_cannot_abandon_publication() {
    let (store, state, owner) = setup();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let task = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("55".repeat(16), "Sample".into()).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert!(store.has_friend(&"55".repeat(16)).unwrap());
    assert!(state.lock().await.friends.is_empty());
    assert_eq!(usage(&owner).0, 1);
    task.abort();
    let drain = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.close_and_drain().await })
    };
    tokio::task::yield_now().await;
    assert!(!drain.is_finished());
    gate.release.notify_one();
    drain.await.unwrap().unwrap();
    assert_eq!(state.lock().await.friends.len(), 1);
    assert_eq!(usage(&owner).0, 0);
}

#[tokio::test]
async fn same_key_fifo_survives_cancelled_delete_between_adds() {
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
    let owner = PersistenceOwner::start(store.clone(), Arc::clone(&state)).unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let first = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("aa".repeat(16), "First".into()).await })
    };
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    *owner.publication_gate.lock().unwrap() = None;
    let delete = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.delete("aa".repeat(16)).await })
    };
    wait_for_slots(&owner, 2).await;
    delete.abort();
    let _ = delete.await;
    let last = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("aa".repeat(16), "Second".into()).await })
    };
    wait_for_slots(&owner, 3).await;
    gate.release.notify_one();
    assert_eq!(first.await.unwrap().unwrap().name, "First");
    assert_eq!(last.await.unwrap().unwrap().name, "Second");
    owner.close_and_drain().await.unwrap();
    assert_eq!(state.lock().await.friends[&"aa".repeat(16)].name, "Second");
    drop(owner);
    drop(store);
    let reopened = MetadataStore::open(&path).unwrap();
    assert_eq!(reopened.load_friends().unwrap()[0].name, "Second");
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn bounded_slots_bytes_and_same_key_fifo() {
    let (store, state, owner) = setup();
    let guard = state.lock().await;
    let mut tasks = Vec::new();
    for n in 0..MAX_SLOTS {
        let owner = Arc::clone(&owner);
        tasks.push(tokio::spawn(async move {
            owner.add(format!("{n:032x}"), "Sample".into()).await
        }));
    }
    wait_for_slots(&owner, MAX_SLOTS).await;
    assert!(matches!(
        owner.add("ff".repeat(16), "Sample".into()).await,
        Err(PersistenceError::Busy)
    ));
    drop(guard);
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    wait_for_slots(&owner, 0).await;
    assert!(matches!(
        owner.add("aa".repeat(16), "x".repeat(MAX_BYTES / 4)).await,
        Err(PersistenceError::TooLarge)
    ));
    let original = owner.add("ff".repeat(16), "First".into()).await.unwrap();
    let duplicate = owner.add("ff".repeat(16), "Second".into()).await.unwrap();
    assert_eq!(original.name, duplicate.name);
    assert_eq!(
        owner.delete("ff".repeat(16)).await.unwrap().unwrap().name,
        "First"
    );
    assert!(owner.delete("ff".repeat(16)).await.unwrap().is_none());
    owner.close_and_drain().await.unwrap();
    assert_eq!(store.load_friends().unwrap().len(), MAX_SLOTS);
    assert_eq!(state.lock().await.friends.len(), MAX_SLOTS);
}

#[tokio::test]
async fn aggregate_owned_bytes_are_reserved_before_work_is_cloned() {
    let (_, state, owner) = setup();
    let guard = state.lock().await;
    let name = "x".repeat(MAX_BYTES / 8);
    let expected = FIXED_CHARGE + 4 * (32 + name.capacity());
    let task = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("66".repeat(16), name).await })
    };
    wait_for_slots(&owner, 1).await;
    assert_eq!(usage(&owner).1, expected);
    assert!(matches!(
        owner.add("77".repeat(16), "x".repeat(MAX_BYTES / 8)).await,
        Err(PersistenceError::Busy)
    ));
    drop(guard);
    task.await.unwrap().unwrap();
    owner.close_and_drain().await.unwrap();
    assert_eq!(usage(&owner).1, 0);
}

#[tokio::test]
async fn failed_write_never_publishes_and_drain_succeeds() {
    let (store, state, owner) = setup();
    assert!(matches!(
        owner.add("invalid".into(), "Sample".into()).await,
        Err(PersistenceError::Storage(_))
    ));
    assert!(state.lock().await.friends.is_empty());
    assert!(store.load_friends().unwrap().is_empty());
    owner.close_and_drain().await.unwrap();
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn sqlite_failure_retry_drains_and_survives_reopen() {
    use std::{fs, path::PathBuf};

    let root = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join("tmp/persistence-owner-tests")
        .join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&root).unwrap();
    let path = root.join("metadata.db");
    drop(MetadataStore::open(&path).unwrap());
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TEMP TRIGGER fail_friend_write BEFORE INSERT ON main.friends WHEN NEW.name = 'Blocked' BEGIN SELECT RAISE(ABORT, 'injected SQL failure'); END;").unwrap();
    let store = MetadataStore::from_connection(conn).unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), Arc::clone(&state)).unwrap();
    let hash = "aa".repeat(16);
    assert!(matches!(
        owner.add(hash.clone(), "Blocked".into()).await,
        Err(PersistenceError::Storage(_))
    ));
    assert!(state.lock().await.friends.is_empty());
    assert!(!store.has_friend(&hash).unwrap());
    assert_eq!(
        owner
            .add(hash.clone(), "Allowed".into())
            .await
            .unwrap()
            .name,
        "Allowed"
    );
    owner.close_and_drain().await.unwrap();
    owner.close_and_drain().await.unwrap();
    drop(owner);
    drop(store);
    let reopened = MetadataStore::open(&path).unwrap();
    assert_eq!(reopened.load_friends().unwrap()[0].name, "Allowed");
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn post_commit_worker_failure_reconciles_or_faults_the_domain() {
    use std::sync::atomic::Ordering;

    let (store, state, owner) = setup();
    owner.fault.store(1, Ordering::SeqCst);
    assert!(matches!(
        owner.add("11".repeat(16), "Sample".into()).await,
        Err(PersistenceError::CommittedAfterWorkerFailure)
    ));
    assert!(store.has_friend(&"11".repeat(16)).unwrap());
    assert_eq!(state.lock().await.friends.len(), 1);
    assert!(owner.close_and_drain().await.is_err());

    let (store, state, owner) = setup();
    owner.fault.store(3, Ordering::SeqCst);
    assert!(matches!(
        owner.add("33".repeat(16), "Sample".into()).await,
        Err(PersistenceError::Worker)
    ));
    assert!(!store.has_friend(&"33".repeat(16)).unwrap());
    assert!(state.lock().await.friends.is_empty());
    assert!(owner.close_and_drain().await.is_err());

    let store = MetadataStore::in_memory().unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let slot = PersistenceSlot::default();
    let owner = slot.owner(&store, &state).unwrap();
    let guard = state.lock().await;
    owner.fault.store(2, Ordering::SeqCst);
    let first = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("22".repeat(16), "Sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    let second = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("44".repeat(16), "Sample".into()).await })
    };
    wait_for_slots(&owner, 2).await;
    drop(guard);
    assert!(matches!(
        first.await.unwrap(),
        Err(PersistenceError::CommitUnknown)
    ));
    assert!(matches!(
        second.await.unwrap(),
        Err(PersistenceError::CommitUnknown)
    ));
    assert!(store.has_friend(&"22".repeat(16)).unwrap());
    assert!(!store.has_friend(&"44".repeat(16)).unwrap());
    assert!(matches!(
        slot.check_coherent_state(),
        Err(PersistenceError::CommitUnknown)
    ));
    assert!(matches!(
        owner.delete("22".repeat(16)).await,
        Err(PersistenceError::CommitUnknown)
    ));
    assert!(slot.close_and_drain().await.is_err());
}

#[tokio::test]
async fn drain_releases_worker_profile_lease_before_reopen() {
    use emulebb_metadata::ProfileLeaseGuard;
    use std::{
        fs::{self, OpenOptions, TryLockError},
        path::PathBuf,
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
    let guard = Arc::new(ProfileLeaseGuard::try_lock(lock()).unwrap());
    let store =
        MetadataStore::open_with_profile_lease(root.join("metadata.db"), Arc::clone(&guard))
            .unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), Arc::clone(&state)).unwrap();
    drop(store);
    drop(guard);
    assert!(matches!(
        ProfileLeaseGuard::try_lock(lock()),
        Err(TryLockError::WouldBlock)
    ));
    owner.add("11".repeat(16), "Sample".into()).await.unwrap();
    owner.close_and_drain().await.unwrap();
    let reopened_guard = Arc::new(ProfileLeaseGuard::try_lock(lock()).unwrap());
    let reopened =
        MetadataStore::open_with_profile_lease(root.join("metadata.db"), reopened_guard).unwrap();
    assert_eq!(reopened.load_friends().unwrap().len(), 1);
    drop(reopened);
    drop(owner);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn dropped_last_owner_still_finishes_accepted_write_and_releases_lease() {
    use emulebb_metadata::ProfileLeaseGuard;
    use std::{
        fs::{self, OpenOptions, TryLockError},
        path::PathBuf,
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
    let held = state.lock().await;
    let task = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("88".repeat(16), "Sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    task.abort();
    let _ = task.await;
    drop(owner);
    drop(store);
    drop(lease);
    drop(held);
    drop(state);
    let next = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match ProfileLeaseGuard::try_lock(lock()) {
                Ok(lease) => break lease,
                Err(TryLockError::WouldBlock) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await
                }
                Err(error) => panic!("unexpected lock error: {error:?}"),
            }
        }
    })
    .await
    .unwrap();
    let reopened = MetadataStore::open_with_profile_lease(&path, Arc::new(next)).unwrap();
    assert!(reopened.has_friend(&"88".repeat(16)).unwrap());
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn sqlite_writer_contention_keeps_runtime_responsive_and_drains_cancelled_write() {
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
    let owner = PersistenceOwner::start(store.clone(), Arc::clone(&state)).unwrap();
    let blocker = rusqlite::Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let task = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("99".repeat(16), "Sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    tokio::time::timeout(Duration::from_secs(1), owner.worker_started.notified())
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        tokio::time::sleep(Duration::from_millis(100)),
    )
    .await
    .unwrap();
    assert!(!task.is_finished());
    assert!(state.lock().await.friends.is_empty());
    task.abort();
    let _ = task.await;
    let drain = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.close_and_drain().await })
    };
    tokio::task::yield_now().await;
    assert!(!drain.is_finished());
    blocker.execute_batch("ROLLBACK").unwrap();
    drop(blocker);
    drain.await.unwrap().unwrap();
    assert_eq!(state.lock().await.friends.len(), 1);
    drop(owner);
    drop(store);
    let reopened = MetadataStore::open(&path).unwrap();
    assert!(reopened.has_friend(&"99".repeat(16)).unwrap());
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn cancelled_queued_category_create_is_committed_and_published_before_drain() {
    let core =
        crate::EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
            .unwrap();
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    let held = core.state.lock().await;
    let friend = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("44".repeat(16), "sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    let pending = {
        let core = core.clone();
        tokio::spawn(async move {
            core.create_category(crate::CategoryCreate {
                name: "Queued".into(),
                temp_dir: crate::NullableStringField::Missing,
                destination_dir: crate::NullableStringField::Missing,
                comment: None,
            })
            .await
        })
    };
    wait_for_slots(&owner, 2).await;
    pending.abort();
    let _ = pending.await;
    drop(held);
    friend.await.unwrap().unwrap();
    owner.close_and_drain().await.unwrap();
    assert_eq!(
        core.metadata_store.load_categories().unwrap()[0].name,
        "Queued"
    );
    assert_eq!(
        core.state
            .lock()
            .await
            .categories
            .values()
            .next()
            .unwrap()
            .name,
        "Queued"
    );
    assert_eq!(usage(&owner), (0, 0));
}
