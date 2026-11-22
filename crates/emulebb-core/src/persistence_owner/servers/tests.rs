use super::*;
use crate::{LibraryTagRequest, persistence_owner::tests::usage};
use emulebb_index::FileIndex;

fn record() -> MetadataServerCreate {
    MetadataServerCreate {
        address: "seed.example".into(),
        port: 4661,
        priority: "normal".into(),
        static_server: false,
        enabled: true,
    }
}

async fn disconnected_mutation(action: u8) {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let mut server = record();
    if action == 3 {
        server.enabled = false;
        server.static_server = true;
        server.priority = "high".into();
    }
    let endpoint = format!("{}:{}", server.address, server.port);
    let id = if action == 0 {
        0
    } else {
        core.create_server_resource(&server).await.unwrap()
    };
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(gate.clone());
    let caller = {
        let core = core.clone();
        tokio::spawn(async move {
            match action {
                0 => core.create_server_resource(&server).await.map(|_| true),
                1 => {
                    core.update_server_resource(
                        id,
                        &MetadataServerUpdate {
                            priority: Some("high".into()),
                            enabled: Some(false),
                            ..Default::default()
                        },
                    )
                    .await
                }
                3 => core
                    .import_server_resource(&MetadataServerImport {
                        address: server.address,
                        port: server.port,
                        name: Some("Observed Server".into()),
                    })
                    .await
                    .map(|_| true),
                _ => core.delete_server_resource(id).await,
            }
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert!(usage(&owner).0 > 0 && usage(&owner).1 > 0);
    match action {
        0 => assert_eq!(
            core.metadata_store
                .server_page(Default::default())
                .unwrap()
                .servers
                .len(),
            1
        ),
        1 => {
            assert!(
                !core
                    .metadata_store
                    .server_by_id(id)
                    .unwrap()
                    .unwrap()
                    .server
                    .enabled
            );
            let mut state = core.state.lock().await;
            let cached = state.servers.get_mut(&endpoint).unwrap();
            assert!(cached.enabled);
            cached.failed_count = 99;
        }
        3 => {
            assert_eq!(
                core.metadata_store
                    .server_by_id(id)
                    .unwrap()
                    .unwrap()
                    .server
                    .name,
                "Observed Server"
            );
            core.state
                .lock()
                .await
                .servers
                .get_mut(&endpoint)
                .unwrap()
                .failed_count = 99;
        }
        _ => assert!(core.metadata_store.server_by_id(id).unwrap().is_none()),
    }
    caller.abort();
    assert!(caller.await.is_err_and(|error| error.is_cancelled()));
    assert_eq!(
        Arc::strong_count(&core),
        1,
        "retained command must not own the full Core"
    );
    *owner.publication_gate.lock().unwrap() = None;
    gate.release.notify_one();
    drop(
        core.library_tags(&LibraryTagRequest::Get("Missing".into()))
            .await
            .unwrap(),
    );
    let state = core.state.lock().await;
    match action {
        0 => assert!(state.servers.get(&endpoint).unwrap().enabled),
        1 => {
            let cached = state.servers.get(&endpoint).unwrap();
            assert!(!cached.enabled);
            assert!(cached.name.is_empty());
            assert_eq!(cached.priority, "high");
            assert_eq!(cached.failed_count, 99);
            assert!(state.disabled_servers.contains(&endpoint));
        }
        3 => {
            let cached = state.servers.get(&endpoint).unwrap();
            assert_eq!(cached.name, "Observed Server");
            assert!(!cached.enabled);
            assert!(cached.static_server);
            assert_eq!(cached.priority, "high");
            assert_eq!(cached.failed_count, 99);
            assert!(state.disabled_servers.contains(&endpoint));
        }
        _ => {
            assert!(!state.servers.contains_key(&endpoint));
            assert!(state.disabled_servers.contains(&endpoint));
        }
    }
    assert_eq!(usage(&owner), (0, 0));
}

#[tokio::test]
async fn disconnected_server_creator_finishes_cache_publication() {
    disconnected_mutation(0).await;
}

#[tokio::test]
async fn disconnected_server_editor_preserves_newer_health_observations() {
    disconnected_mutation(1).await;
}

#[tokio::test]
async fn disconnected_server_deleter_finishes_cache_publication() {
    disconnected_mutation(2).await;
}

#[tokio::test]
async fn disconnected_server_import_preserves_controls_and_newer_health() {
    disconnected_mutation(3).await;
}

#[tokio::test]
async fn server_conflict_is_typed_and_sql_failure_does_not_publish() {
    let uri = format!(
        "file:server-failure-{}?mode=memory&cache=shared",
        uuid::Uuid::new_v4()
    );
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        | rusqlite::OpenFlags::SQLITE_OPEN_URI;
    let store =
        MetadataStore::from_connection(rusqlite::Connection::open_with_flags(&uri, flags).unwrap())
            .unwrap();
    let core = EmulebbCore::new_in_memory("test", FileIndex::from_metadata_store(store)).unwrap();
    let server = record();
    let id = core.create_server_resource(&server).await.unwrap();
    let mut duplicate = server.clone();
    duplicate.address.make_ascii_uppercase();
    duplicate.priority = "high".into();
    assert!(
        core.create_server_resource(&duplicate)
            .await
            .unwrap_err()
            .is::<ServerEndpointConflict>()
    );
    let fault = rusqlite::Connection::open_with_flags(&uri, flags).unwrap();
    fault.execute_batch(
        "CREATE TRIGGER block_server_edit BEFORE UPDATE ON servers BEGIN SELECT RAISE(ABORT,'injected server write failure'); END;"
    ).unwrap();
    assert!(
        core.update_server_resource(
            id,
            &MetadataServerUpdate {
                priority: Some("high".into()),
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .is::<PersistenceError>()
    );
    assert_eq!(
        core.state
            .lock()
            .await
            .servers
            .get(&format!("{}:{}", server.address, server.port))
            .unwrap()
            .priority,
        "normal"
    );
    assert_eq!(
        core.metadata_store
            .server_by_id(id)
            .unwrap()
            .unwrap()
            .server
            .server_priority,
        "normal"
    );
    core.persistence_owner.check_coherent_state().unwrap();
}

#[tokio::test]
async fn oversized_server_create_is_refused_before_sql_capture() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let mut server = record();
    for size in [emulebb_metadata::SERVER_READ_MAX_BYTES / 4, MAX_BYTES] {
        server.address = "x".repeat(size);
        assert!(matches!(
            core.create_server_resource(&server)
                .await
                .unwrap_err()
                .downcast_ref::<PersistenceError>(),
            Some(PersistenceError::TooLarge)
        ));
    }
    assert!(
        core.metadata_store
            .server_page(Default::default())
            .unwrap()
            .servers
            .is_empty()
    );
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    assert_eq!(usage(&owner), (0, 0));
}

#[tokio::test]
async fn network_feedback_waits_for_committed_server_edit_publication() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let server = record();
    let endpoint = format!("{}:{}", server.address, server.port);
    let id = core.create_server_resource(&server).await.unwrap();
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(gate.clone());
    let editor = {
        let core = core.clone();
        tokio::spawn(async move {
            core.update_server_resource(
                id,
                &MetadataServerUpdate {
                    priority: Some("high".into()),
                    ..Default::default()
                },
            )
            .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert!(
        core.server_mutation_gate.try_lock().is_err(),
        "SQL-to-publication window must exclude feedback writes"
    );
    let feedback = {
        let core = core.clone();
        let endpoint = endpoint.clone();
        tokio::spawn(async move {
            core.note_ed2k_server_metadata(
                &endpoint,
                Some("Observed Server".into()),
                Some("Observed description".into()),
                None,
                None,
                vec![],
            )
            .await
        })
    };
    editor.abort();
    assert!(editor.await.unwrap_err().is_cancelled());
    *owner.publication_gate.lock().unwrap() = None;
    gate.release.notify_one();
    assert_eq!(feedback.await.unwrap(), Some(endpoint.clone()));
    drop(
        core.library_tags(&LibraryTagRequest::Get("Missing".into()))
            .await
            .unwrap(),
    );
    let saved = core
        .metadata_store
        .server_by_id(id)
        .unwrap()
        .unwrap()
        .server;
    assert_eq!(saved.name, "Observed Server");
    assert_eq!(saved.server_priority, "high");
    assert_eq!(saved.description, "Observed description");
    assert_eq!(
        core.state.lock().await.servers.get(&endpoint).unwrap().name,
        "Observed Server"
    );
}

#[tokio::test]
async fn late_feedback_does_not_recreate_deleted_configured_server() {
    let root = crate::unique_runtime_dir("server-retired-feedback");
    let server = record();
    let endpoint = format!("{}:{}", server.address, server.port);
    let mut network = crate::tests::test_network_config_with_store(
        &root,
        crate::KadLocalStoreConfig::default(),
        crate::SnoopQueueConfig::default(),
    );
    network.ed2k.server_endpoints = vec![endpoint.clone()];
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &root,
        Some(network),
    )
    .unwrap();
    let id = core.create_server_resource(&server).await.unwrap();
    assert!(core.delete_server_resource(id).await.unwrap());
    assert_eq!(
        core.note_ed2k_server_metadata(
            &endpoint,
            Some("Late name".into()),
            None,
            None,
            None,
            vec![]
        )
        .await,
        None
    );
    assert!(
        core.metadata_store
            .server_page(Default::default())
            .unwrap()
            .servers
            .is_empty()
    );
    let next = core.create_server_resource(&server).await.unwrap();
    assert!(next > id);
}

#[tokio::test]
async fn disconnected_document_import_finishes_all_committed_rows() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(gate.clone());
    let mut bytes = vec![0x0e];
    bytes.extend_from_slice(&3u32.to_le_bytes());
    for last in [1, 2] {
        bytes.extend_from_slice(&[192, 0, 2, last]);
        bytes.extend_from_slice(&4661u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
    }
    bytes.push(192);
    let caller = {
        let core = Arc::clone(&core);
        tokio::spawn(async move { core.import_server_met_bytes(&bytes).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert_eq!(
        core.metadata_store
            .server_page(Default::default())
            .unwrap()
            .servers
            .len(),
        2
    );
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert_eq!(Arc::strong_count(&core), 1);
    *owner.publication_gate.lock().unwrap() = None;
    gate.release.notify_one();
    drop(
        core.library_tags(&LibraryTagRequest::Get("Missing".into()))
            .await
            .unwrap(),
    );
    let state = core.state.lock().await;
    assert!(state.servers.contains_key("192.0.2.1:4661"));
    assert!(state.servers.contains_key("192.0.2.2:4661"));
    assert_eq!(usage(&owner), (0, 0));
}

#[tokio::test]
async fn discovery_document_limits_and_empty_server_imports_release_admission() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    assert_eq!(crate::SERVER_MET_MAX_BYTES, 8192);
    assert_eq!(crate::NODES_DAT_MAX_BYTES, 8192);
    assert!(
        core.import_server_met_bytes(&[0x0e, 0, 0, 0, 0])
            .await
            .unwrap_err()
            .to_string()
            .contains("no usable records")
    );
    assert!(matches!(
        core.import_server_met_bytes(&vec![0; 8193])
            .await
            .unwrap_err()
            .downcast_ref::<PersistenceError>(),
        Some(PersistenceError::TooLarge)
    ));
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    assert_eq!(usage(&owner), (0, 0));
    assert!(
        core.metadata_store
            .server_page(Default::default())
            .unwrap()
            .servers
            .is_empty()
    );
}
