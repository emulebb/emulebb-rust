use super::*;
use emulebb_metadata::MetadataServerUpdate;

async fn saved_server_id(core: &EmulebbCore, endpoint: &str) -> i64 {
    core.server_page(Default::default())
        .await
        .unwrap()
        .servers
        .iter()
        .find(|record| record.server.endpoint() == endpoint)
        .expect("fixture must persist the server before editing it")
        .id
}

use emulebb_ed2k::ed2k_server::{
    Ed2kServerFailure, Ed2kServerFailurePhase, Ed2kServerFailureReason,
};

#[test]
fn split_stock_search_responses_keeps_pages_under_fragment_limit() {
    let sender_id = NodeId::from_bytes([1; 16]);
    let target = NodeId::from_bytes([2; 16]);
    let results = (0..12)
        .map(|index| SearchResultEntry {
            entry_id: Ed2kHash::from_bytes([index; 16]),
            tags: vec![Tag::filename(format!(
                "ubuntu-linux-parity-result-{index:02}-{}",
                "x".repeat(220)
            ))],
        })
        .collect::<Vec<_>>();
    let response = SearchRes {
        sender_id,
        target,
        results: results.clone(),
    };

    let pages = split_stock_search_responses(response, 1420);

    assert!(pages.len() > 1);
    assert_eq!(
        pages.iter().map(|page| page.results.len()).sum::<usize>(),
        results.len()
    );
    assert!(
        pages
            .iter()
            .all(|page| { KadPacket::SearchRes(page.clone()).encode().unwrap().len() <= 1420 })
    );
    assert_eq!(
        pages
            .into_iter()
            .flat_map(|page| page.results)
            .map(|result| result.entry_id)
            .collect::<Vec<_>>(),
        results
            .into_iter()
            .map(|result| result.entry_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn split_stock_search_responses_keeps_single_oversized_result_like_stock() {
    let sender_id = NodeId::from_bytes([1; 16]);
    let target = NodeId::from_bytes([2; 16]);
    let response = SearchRes {
        sender_id,
        target,
        results: vec![SearchResultEntry {
            entry_id: Ed2kHash::from_bytes([3; 16]),
            tags: vec![Tag::filename("x".repeat(1600))],
        }],
    };

    let pages = split_stock_search_responses(response, 1420);

    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].results.len(), 1);
    assert!(
        KadPacket::SearchRes(pages[0].clone())
            .encode()
            .unwrap()
            .len()
            > 1420
    );
}

#[tokio::test]
async fn live_search_collects_network_results_independently_of_passive_index_settings() {
    for passive_replay in [false, true] {
        let root = unique_runtime_dir("live-search-network-results");
        let mut index = FileIndex::open(root.join("metadata.sqlite")).unwrap();
        for (hash, name, origin) in [
            (
                "00112233445566778899aabbccddeeff",
                "Passive.Indexed.File.iso",
                emulebb_index::IndexedFileOrigin::PassiveCache,
            ),
            (
                "ffeeddccbbaa99887766554433221100",
                "Transfer.Indexed.File.iso",
                emulebb_index::IndexedFileOrigin::Transfer,
            ),
        ] {
            index
                .upsert_file(
                    &IndexedFile {
                        ed2k_hash: hash.into(),
                        name: name.into(),
                        size_bytes: 2048,
                        content_type: "iso".into(),
                        availability_score: 3,
                    },
                    origin,
                )
                .unwrap();
        }
        let mut network = test_network_config_with_store(
            &root,
            KadLocalStoreConfig::default(),
            SnoopQueueConfig::default(),
        );
        network.kad_passive_replay_enabled = passive_replay;
        let core =
            EmulebbCore::new_with_network("test", index, root.join("transfers"), Some(network))
                .unwrap();
        let request = SearchCreate {
            parent_search_id: None,
            query: "indexed file".into(),
            method: "server".into(),
            ..Default::default()
        };
        let search = core.create_search(request.clone()).await.unwrap();
        assert_eq!(search.status, "queued");
        assert_eq!(
            core.metadata_store
                .search_header(search.id.parse().unwrap())
                .unwrap()
                .unwrap()
                .result_count,
            0
        );
        assert!(
            core.metadata_store
                .search_result_headers_page(search.id.parse().unwrap(), 0, 10)
                .unwrap()
                .unwrap()
                .items
                .is_empty()
        );
        assert_eq!(
            core.metadata_store.table_count("content_claims").unwrap(),
            0
        );
        let mut raw = crate::search_observations::tests::raw_file();
        raw.file_name = Some("Network.Indexed.File.iso".into());
        raw.file_size = Some(8192);
        let reporter = "192.0.2.4:4661".parse().unwrap();
        let projected = crate::search_query::search_result_from_ed2k(
            &search.id,
            &request,
            "server",
            Some(reporter),
            raw.clone(),
        );
        let update = crate::search_observations::ed2k(
            projected,
            emulebb_metadata::MetadataObservationOrigin::Server,
            Some(reporter),
            &raw,
        );
        core.apply_search_live_update(&search.id, &request, update)
            .await
            .unwrap();
        let collected = core
            .metadata_store
            .search_result_headers_page(search.id.parse().unwrap(), 0, 10)
            .unwrap()
            .unwrap();
        assert_eq!(collected.items.len(), 1);
        assert_eq!(collected.items[0].summary.name, "Network.Indexed.File.iso");
        assert_eq!(
            core.metadata_store.table_count("content_claims").unwrap(),
            1
        );
        assert_eq!(
            core.index
                .lock()
                .await
                .search("indexed file", 10)
                .unwrap()
                .len(),
            2
        );
        core.delete_search(&search.id).await.unwrap();
        core.persistence_owner
            .owner(&core.metadata_store, &core.state)
            .unwrap()
            .close_and_drain()
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn explicit_network_search_without_runtime_is_rejected() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();

    for method in ["automatic", "server", "global", "kad"] {
        let error = core
            .create_search(SearchCreate {
                parent_search_id: None,
                query: "must use requested network".to_string(),
                method: method.to_string(),
                ..Default::default()
            })
            .await
            .expect_err("explicit network search must not fall back to local-only");
        assert!(
            error
                .to_string()
                .contains("search network is not configured"),
            "unexpected {method} error: {error:#}"
        );
    }

    assert_eq!(
        core.metadata_store.table_count("search_sessions").unwrap(),
        0
    );
}

#[tokio::test]
async fn invalid_search_method_is_rejected_before_creating_a_search() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();

    let error = core
        .create_search(SearchCreate {
            parent_search_id: None,
            query: "invalid method".to_string(),
            method: "local-ish".to_string(),
            ..Default::default()
        })
        .await
        .expect_err("unknown methods must not silently become local-only searches");

    assert_eq!(
        error.to_string(),
        "search method must be one of automatic, server, global, kad"
    );
    assert_eq!(
        core.metadata_store.table_count("search_sessions").unwrap(),
        0
    );
}

#[tokio::test]
async fn search_spec_is_canonicalized_before_persistence() {
    let transfer_root = unique_runtime_dir("emulebb-core-search-canonicalization");
    let network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap();

    let search = core
        .create_search(SearchCreate {
            parent_search_id: None,
            query: "  alpha\t beta  ".to_string(),
            method: " AUTOMATIC ".to_string(),
            r#type: " AUDIO ".to_string(),
            extension: " .MP3 ".to_string(),
            min_size_bytes: Some(0),
            max_size_bytes: Some(0),
            min_availability: Some(0),
            min_complete_sources: Some(0),
            min_bitrate_kbps: Some(0),
            min_length_seconds: Some(0),
            codec: " MP3 ".to_string(),
            title: " Example Title ".to_string(),
            album: " Example Album ".to_string(),
            artist: " Example Artist ".to_string(),
        })
        .await
        .unwrap();

    assert_eq!(search.spec.query, "alpha beta");
    assert_eq!(search.spec.method, "automatic");
    assert_eq!(search.spec.r#type, "audio");
    assert_eq!(search.spec.extension, "mp3");
    assert_eq!(search.spec.min_size_bytes, None);
    assert_eq!(search.spec.max_size_bytes, None);
    assert_eq!(search.spec.min_availability, None);
    assert_eq!(search.spec.min_complete_sources, None);
    assert_eq!(search.spec.min_bitrate_kbps, None);
    assert_eq!(search.spec.min_length_seconds, None);
    assert_eq!(search.spec.codec, "MP3");
    assert_eq!(search.spec.title, "Example Title");
    assert_eq!(search.spec.album, "Example Album");
    assert_eq!(search.spec.artist, "Example Artist");

    let persisted = core
        .metadata_store
        .search_header(search.id.parse().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        persisted.data.spec,
        crate::search_state::search_to_metadata(&search).spec
    );
}

#[tokio::test]
async fn invalid_search_spec_is_rejected_before_creating_a_search() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let invalid = [
        (SearchCreate::default(), "query must not be empty"),
        (
            SearchCreate {
                parent_search_id: None,
                query: "bad type".to_string(),
                r#type: "executable".to_string(),
                ..SearchCreate::default()
            },
            "type is not supported",
        ),
        (
            SearchCreate {
                parent_search_id: None,
                query: "bad range".to_string(),
                min_size_bytes: Some(2),
                max_size_bytes: Some(1),
                ..SearchCreate::default()
            },
            "maxSizeBytes must be greater than or equal to minSizeBytes",
        ),
        (
            SearchCreate {
                parent_search_id: None,
                query: "x".repeat(161),
                ..SearchCreate::default()
            },
            "query must be at most 160 characters",
        ),
        (
            SearchCreate {
                parent_search_id: None,
                query: "bad\0query".to_string(),
                ..SearchCreate::default()
            },
            "query must be valid UTF-8 without control characters",
        ),
        (
            SearchCreate {
                parent_search_id: None,
                query: "too many sources".to_string(),
                min_availability: Some(1_000_001),
                ..SearchCreate::default()
            },
            "minAvailability must be an unsigned number in the range 0..1000000",
        ),
        (
            SearchCreate {
                parent_search_id: None,
                query: "bad codec".to_string(),
                codec: "bad\0codec".to_string(),
                ..SearchCreate::default()
            },
            "codec must not contain control characters",
        ),
    ];

    for (request, expected) in invalid {
        let error = core.create_search(request).await.unwrap_err();
        assert_eq!(error.to_string(), expected);
    }
    assert_eq!(
        core.metadata_store.table_count("search_sessions").unwrap(),
        0
    );
}

#[tokio::test]
async fn explicit_network_search_respects_disabled_network_settings() {
    let transfer_root = unique_runtime_dir("emulebb-core-search-disabled-network");
    let network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let core = EmulebbCore::new_with_network(
        "test",
        test_index_with_settings(
            FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
            serde_json::json!({"network": {"ed2kEnabled": false, "kadEnabled": false}}),
        ),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap();

    for method in ["server", "global", "kad"] {
        let error = core
            .create_search(SearchCreate {
                parent_search_id: None,
                query: "disabled network".to_string(),
                method: method.to_string(),
                ..Default::default()
            })
            .await
            .expect_err("disabled explicit network must reject search");
        assert!(
            error.to_string().contains("search network is disabled"),
            "unexpected {method} error: {error:#}"
        );
    }

    assert_eq!(
        core.metadata_store.table_count("search_sessions").unwrap(),
        0
    );
    assert_eq!(core.search_queue.lock().pending_len(), 0);
}

#[tokio::test]
async fn automatic_search_is_rejected_when_all_networks_are_disabled() {
    let transfer_root = unique_runtime_dir("emulebb-core-search-disabled-auto");
    let network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let core = EmulebbCore::new_with_network(
        "test",
        test_index_with_settings(
            FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
            serde_json::json!({"network": {"ed2kEnabled": false, "kadEnabled": false}}),
        ),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap();

    let error = core
        .create_search(SearchCreate {
            parent_search_id: None,
            query: "local only automatic search".to_string(),
            method: "automatic".to_string(),
            ..Default::default()
        })
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "search networks are disabled in settings.core"
    );
    assert_eq!(core.search_queue.lock().pending_len(), 0);
    assert_eq!(
        core.metadata_store.table_count("search_sessions").unwrap(),
        0
    );
}

#[tokio::test]
async fn automatic_search_waits_only_for_compatible_enabled_backends() {
    let transfer_root = unique_runtime_dir("emulebb-core-search-auto-compatible");
    let network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap();

    let search = core
        .create_search(SearchCreate {
            parent_search_id: None,
            query: "alpha-beta".to_string(),
            method: "automatic".to_string(),
            ..SearchCreate::default()
        })
        .await
        .unwrap();

    assert_eq!(search.status, "queued");
    assert_eq!(
        search.status_reason.as_deref(),
        Some("waiting-for-server-connection")
    );
    assert_eq!(core.search_queue.lock().pending_len(), 1);
}

#[tokio::test]
async fn kad_only_automatic_search_rejects_an_invalid_kad_keyword() {
    let transfer_root = unique_runtime_dir("emulebb-core-search-auto-kad-invalid");
    let network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let core = EmulebbCore::new_with_network(
        "test",
        test_index_with_settings(
            FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
            serde_json::json!({"network": {"ed2kEnabled": false, "kadEnabled": true}}),
        ),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap();

    let error = core
        .create_search(SearchCreate {
            parent_search_id: None,
            query: "alpha-beta".to_string(),
            method: "automatic".to_string(),
            ..SearchCreate::default()
        })
        .await
        .unwrap_err();

    assert_eq!(error.to_string(), "invalid Kad search keyword");
    assert_eq!(
        core.metadata_store.table_count("search_sessions").unwrap(),
        0
    );
    assert_eq!(core.search_queue.lock().pending_len(), 0);
}

#[tokio::test]
async fn network_search_rejects_malformed_expression_before_allocating_an_id() {
    let transfer_root = unique_runtime_dir("emulebb-core-search-invalid-expression");
    let network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap();

    let error = core
        .create_search(SearchCreate {
            parent_search_id: None,
            query: "alpha OR".to_string(),
            method: "server".to_string(),
            ..SearchCreate::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "invalid ED2K search expression");

    let search = core
        .create_search(SearchCreate {
            parent_search_id: None,
            query: "valid query".to_string(),
            method: "server".to_string(),
            ..SearchCreate::default()
        })
        .await
        .unwrap();
    assert_eq!(search.id, "1");
}

// Operator directive 2026-07-06: a network search submitted while the
// backend is still connecting/absent must surface an honest "queued"
// status with a reason and wait for readiness — never complete instantly
// with local-only results — and identical queued queries are rejected
// explicitly instead of amassing wire traffic for later.
#[tokio::test]
async fn network_search_queues_with_honest_status_and_rejects_duplicates() {
    let transfer_root = unique_runtime_dir("emulebb-core-search-queue");
    let network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap();

    let request = SearchCreate {
        parent_search_id: None,
        query: "queued query".to_string(),
        method: "server".to_string(),
        ..Default::default()
    };
    let search = core.create_search(request.clone()).await.unwrap();
    assert_eq!(search.status, "queued");
    assert_eq!(search.spec.method, "server");
    assert_eq!(search.resolved_method, None);
    assert_eq!(
        search.status_reason.as_deref(),
        Some("waiting-for-server-connection")
    );

    // No server session ever connects: the search stays honestly queued
    // (drain ticks run but the backend never becomes ready).
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let still_queued = core
        .metadata_store
        .search_header(search.id.parse().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(still_queued.data.status, "queued");

    // An identical queued query on the same lane is rejected explicitly.
    let error = core
        .create_search(request)
        .await
        .expect_err("duplicate queued query must be rejected");
    assert!(error.to_string().contains("already queued"));

    // A different query queues fine alongside it.
    let other = core
        .create_search(SearchCreate {
            parent_search_id: None,
            query: "another queued query".to_string(),
            method: "server".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(other.status, "queued");
}

#[tokio::test]
async fn initial_persistence_failure_leaves_queue_runnable_for_the_next_search() {
    let transfer_root = unique_runtime_dir("emulebb-core-search-persist-failure");
    let network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap();
    let request = SearchCreate {
        parent_search_id: None,
        query: "recover after persistence failure".to_string(),
        method: "server".to_string(),
        ..SearchCreate::default()
    };

    let sql = rusqlite::Connection::open(transfer_root.join("metadata.sqlite")).unwrap();
    sql.execute_batch("CREATE TRIGGER fail_search_create BEFORE INSERT ON search_sessions BEGIN SELECT RAISE(ABORT, 'injected initial-search persistence failure'); END;").unwrap();
    let error = core
        .create_search(request.clone())
        .await
        .expect_err("SQL failure must reject search creation");
    assert!(matches!(
        error.downcast_ref::<PersistenceError>(),
        Some(PersistenceError::Storage(_))
    ));
    sql.execute_batch("DROP TRIGGER fail_search_create;")
        .unwrap();
    assert_eq!(
        core.metadata_store.table_count("search_sessions").unwrap(),
        0
    );
    assert!(
        core.metadata_store
            .search_headers_page(None, 10)
            .unwrap()
            .items
            .is_empty()
    );
    assert_eq!(core.search_queue.lock().pending_len(), 0);
    assert!(!core.search_queue.lock().drain_task_running());

    let search = core.create_search(request).await.unwrap();
    assert_eq!(search.id, "1");
    assert_eq!(search.status, "queued");
    assert_eq!(
        core.metadata_store
            .search_headers_page(None, 10)
            .unwrap()
            .items
            .len(),
        1
    );
    assert_eq!(core.search_queue.lock().pending_len(), 1);
    assert!(core.search_queue.lock().drain_task_running());
    sql.execute_batch("CREATE TRIGGER fail_search_update BEFORE UPDATE ON search_sessions BEGIN SELECT RAISE(ABORT, 'injected status persistence failure'); END;").unwrap();
    core.update_search_status(&search.id, "running", None, Some("server"))
        .await;
    assert_eq!(
        core.metadata_store
            .search_header(search.id.parse().unwrap())
            .unwrap()
            .unwrap()
            .data
            .status,
        "queued"
    );
    assert_eq!(
        core.metadata_store
            .search_headers_page(None, 10)
            .unwrap()
            .items[0]
            .data
            .status,
        "queued"
    );
    sql.execute_batch("DROP TRIGGER fail_search_update;")
        .unwrap();
    core.update_search_status(&search.id, "running", None, Some("server"))
        .await;
    assert_eq!(
        core.metadata_store
            .search_header(search.id.parse().unwrap())
            .unwrap()
            .unwrap()
            .data
            .status,
        "running"
    );
    assert_eq!(
        core.metadata_store
            .search_headers_page(None, 10)
            .unwrap()
            .items[0]
            .data
            .status,
        "running"
    );
    core.clear_searches().await.unwrap();
}

#[tokio::test]
async fn deleting_searches_cancels_pending_network_work() {
    let transfer_root = unique_runtime_dir("emulebb-core-search-queue-cancel");
    let network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap();

    let first_request = SearchCreate {
        parent_search_id: None,
        query: "first pending query".to_string(),
        method: "server".to_string(),
        ..Default::default()
    };
    let first = core.create_search(first_request.clone()).await.unwrap();
    let second = core
        .create_search(SearchCreate {
            parent_search_id: None,
            query: "second pending query".to_string(),
            method: "kad".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(core.search_queue.lock().pending_len(), 2);
    let (first_cancel, second_cancel) = {
        let state = core.state.lock().await;
        (
            state.search_cancels[&first.id].clone(),
            state.search_cancels[&second.id].clone(),
        )
    };

    let mut raw = crate::search_observations::tests::raw_file();
    raw.file_name = Some("Live Result.bin".into());
    raw.file_size = Some(4096);
    raw.source_count = Some(7);
    let reporter = "192.0.2.4:4661".parse().unwrap();
    let projected = crate::search_query::search_result_from_ed2k(
        &first.id,
        &first_request,
        "server",
        Some(reporter),
        raw.clone(),
    );
    let update = crate::search_observations::ed2k(
        projected,
        emulebb_metadata::MetadataObservationOrigin::Server,
        Some(reporter),
        &raw,
    );
    core.apply_search_live_update(&first.id, &first_request, update)
        .await
        .unwrap();
    assert_eq!(
        core.metadata_store
            .search_header(first.id.parse().unwrap())
            .unwrap()
            .unwrap()
            .result_count,
        1
    );

    assert!(core.delete_search(&first.id).await.unwrap());
    assert_eq!(core.search_queue.lock().pending_len(), 1);
    assert!(first_cancel.is_cancelled());
    assert!(!second_cancel.is_cancelled());

    core.clear_searches().await.unwrap();
    assert_eq!(core.search_queue.lock().pending_len(), 0);
    assert_eq!(
        core.metadata_store.table_count("search_sessions").unwrap(),
        0
    );
    assert!(second_cancel.is_cancelled());
    let next = core.create_search(first_request).await.unwrap();
    assert!(next.id.parse::<i64>().unwrap() > second.id.parse::<i64>().unwrap());
}

#[tokio::test]
async fn import_server_met_bytes_adds_servers() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    // version 0x0E + count 1 + (ip 45.82.80.155, port 5687, 0 tags)
    let mut met = vec![0x0Eu8];
    met.extend_from_slice(&1u32.to_le_bytes());
    met.extend_from_slice(&[45, 82, 80, 155]);
    met.extend_from_slice(&5687u16.to_le_bytes());
    met.extend_from_slice(&0u32.to_le_bytes());

    let added = core.import_server_met_bytes(&met).await.unwrap();
    assert_eq!(added, 1);
    let servers = core.servers().await;
    assert!(
        servers
            .iter()
            .any(|server| server.address == "45.82.80.155" && server.port == 5687)
    );
}

#[tokio::test]
async fn effective_ed2k_config_includes_runtime_servers() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let base = Ed2kRuntimeConfig {
        server_endpoints: vec!["203.0.113.10:4661".to_string()],
        ..Ed2kRuntimeConfig::default()
    };
    core.create_server_resource(&emulebb_metadata::MetadataServerCreate {
        address: "203.0.113.20".to_string(),
        port: 4661,
        priority: "high".to_string(),
        static_server: true,
        enabled: true,
    })
    .await
    .unwrap();

    let config = core.effective_ed2k_config(&base).await.unwrap();

    assert!(
        config
            .server_endpoints
            .iter()
            .any(|endpoint| endpoint == "203.0.113.10:4661")
    );
    let runtime_server = config
        .server_entries
        .iter()
        .find(|entry| entry.host == "203.0.113.20" && entry.port == 4661)
        .expect("runtime server carried into connection config");
    assert_eq!(runtime_server.priority, "high");
    assert!(runtime_server.static_server);
}

#[tokio::test]
async fn effective_ed2k_config_excludes_disabled_runtime_servers() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.create_server_resource(&emulebb_metadata::MetadataServerCreate {
        address: "203.0.113.20".to_string(),
        port: 4661,
        priority: "normal".into(),
        static_server: false,
        enabled: true,
    })
    .await
    .unwrap();
    core.update_server_resource(
        saved_server_id(&core, "203.0.113.20:4661").await,
        &MetadataServerUpdate {
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let servers = core.servers().await;
    let server = servers
        .iter()
        .find(|server| server.endpoint == "203.0.113.20:4661")
        .expect("disabled server remains visible");
    assert!(!server.enabled);

    let config = core
        .effective_ed2k_config(&Ed2kRuntimeConfig::default())
        .await
        .unwrap();
    assert!(config.server_entries.is_empty());
    assert!(config.server_endpoints.is_empty());
}

#[tokio::test]
async fn server_update_reenables_disabled_runtime_servers() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.create_server_resource(&emulebb_metadata::MetadataServerCreate {
        address: "203.0.113.21".to_string(),
        port: 4661,
        priority: "normal".into(),
        static_server: false,
        enabled: true,
    })
    .await
    .unwrap();
    core.update_server_resource(
        saved_server_id(&core, "203.0.113.21:4661").await,
        &MetadataServerUpdate {
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let updated = core
        .update_server_resource(
            saved_server_id(&core, "203.0.113.21:4661").await,
            &MetadataServerUpdate {
                enabled: Some(true),
                ..MetadataServerUpdate::default()
            },
        )
        .await
        .unwrap();

    assert!(updated);
    assert!(
        core.server_resource(saved_server_id(&core, "203.0.113.21:4661").await)
            .await
            .unwrap()
            .unwrap()
            .server
            .enabled
    );
    let config = core
        .effective_ed2k_config(&Ed2kRuntimeConfig::default())
        .await
        .unwrap();
    assert!(
        config
            .server_entries
            .iter()
            .any(|entry| entry.host == "203.0.113.21" && entry.port == 4661)
    );
}

#[tokio::test]
async fn effective_ed2k_config_preserves_ed2k_owned_server_policy() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let base = Ed2kRuntimeConfig {
        reconnect_enabled: false,
        safe_server_connect: true,
        add_servers_from_server: true,
        ..Ed2kRuntimeConfig::default()
    };

    let config = core.effective_ed2k_config(&base).await.unwrap();

    assert!(!config.reconnect_enabled);
    assert!(config.safe_server_connect);
    assert!(config.add_servers_from_server);
}

#[tokio::test]
async fn server_point_read_and_plan_merge_preserve_reported_metadata_and_endpoint_identity() {
    let transfer_root = unique_runtime_dir("server-point-and-plan-merge");
    let mut network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.ed2k.server_entries = vec![emulebb_ed2k::config::Ed2kServerEntry {
        host: "Seed.Example".into(),
        port: 4661,
        name: Some("Configured".into()),
        priority: "high".into(),
        static_server: true,
        ..Default::default()
    }];
    network.ed2k.server_endpoints = vec!["Endpoint.Example:4662".into()];
    let base = network.ed2k.clone();
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(network),
    )
    .unwrap();
    assert_eq!(
        core.server("SEED.EXAMPLE:4661").await.unwrap().name,
        "Configured"
    );
    assert_eq!(
        core.server("endpoint.example:4662").await.unwrap().endpoint,
        "Endpoint.Example:4662"
    );
    core.import_server_resource(&emulebb_metadata::MetadataServerImport {
        address: "seed.example".into(),
        port: 4661,
        name: Some("Reported".into()),
    })
    .await
    .unwrap();
    let point = core.server("SEED.EXAMPLE:4661").await.unwrap();
    assert_eq!(point.name, "Reported");
    let config = core.effective_ed2k_config(&base).await.unwrap();
    assert_eq!(config.server_entries.len(), 1);
    assert_eq!(config.server_entries[0].host, "Seed.Example");
    assert_eq!(config.server_entries[0].name.as_deref(), Some("Reported"));
    assert_eq!(config.server_entries[0].priority, point.priority);
    assert_eq!(config.server_entries[0].static_server, point.static_server);
    assert!(core.server("missing.example:4661").await.is_none());
    let page = core.server_page(Default::default()).await.unwrap();
    let id = page
        .servers
        .iter()
        .find(|row| row.server.address.eq_ignore_ascii_case("seed.example"))
        .unwrap()
        .id;
    drop(page);
    core.delete_server_resource(id).await.unwrap();
    assert!(
        core.note_ed2k_server_metadata(
            "SEED.EXAMPLE:4661",
            Some("Delayed observation".into()),
            None,
            None,
            None,
            Vec::new()
        )
        .await
        .is_none()
    );
    assert!(core.server_by_id(id).await.unwrap().is_none());
    assert!(!core.server("Seed.Example:4661").await.unwrap().enabled);
    assert!(
        core.effective_ed2k_config(&base)
            .await
            .unwrap()
            .server_entries
            .is_empty()
    );
    let replacement = core
        .import_server_resource(&emulebb_metadata::MetadataServerImport {
            address: "SEED.EXAMPLE".into(),
            port: 4661,
            name: Some("Fresh observation".into()),
        })
        .await
        .unwrap();
    assert!(replacement > id);
    assert!(core.server("seed.example:4661").await.unwrap().enabled);
}

#[tokio::test]
async fn udp_server_description_metadata_updates_the_persisted_server() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let definition = emulebb_metadata::MetadataServerCreate {
        address: "192.0.2.44".to_string(),
        port: 4661,
        priority: "normal".into(),
        static_server: false,
        enabled: true,
    };
    core.create_server_resource(&definition).await.unwrap();
    core.import_server_resource(&emulebb_metadata::MetadataServerImport {
        address: definition.address,
        port: definition.port,
        name: Some("Old Name".to_string()),
    })
    .await
    .unwrap();

    assert_eq!(
        core.note_ed2k_server_metadata(
            "192.0.2.44:4661",
            Some("New Name".to_string()),
            Some("New Description".to_string()),
            Some("dyn.example".to_string()),
            Some("17.06".to_string()),
            vec![4662, 4663],
        )
        .await
        .as_deref(),
        Some("192.0.2.44:4661")
    );

    let server = core.server("192.0.2.44:4661").await.expect("server");
    assert_eq!(server.name, "New Name");
    assert_eq!(server.description, "New Description");
    assert_eq!(server.dyn_ip, "dyn.example");
    assert_eq!(server.version, "17.06");
    assert_eq!(server.auxiliary_ports, vec![4662, 4663]);
}

#[tokio::test]
async fn udp_server_metadata_reports_failure_for_an_unknown_endpoint() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();

    assert!(
        core.note_ed2k_server_metadata(
            "192.0.2.99:4661",
            Some("Unknown".to_string()),
            Some("Not applied".to_string()),
            None,
            None,
            Vec::new(),
        )
        .await
        .is_none()
    );
    assert!(
        core.note_ed2k_server_status("192.0.2.99:4661", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn server_udp_status_persists_and_stale_keys_are_not_reused() {
    let runtime_dir = unique_runtime_dir("emulebb-core-server-udp-status");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let definition = emulebb_metadata::MetadataServerCreate {
        address: "192.0.2.45".to_string(),
        port: 4661,
        priority: "normal".into(),
        static_server: false,
        enabled: true,
    };
    core.create_server_resource(&definition).await.unwrap();
    core.import_server_resource(&emulebb_metadata::MetadataServerImport {
        address: definition.address,
        port: definition.port,
        name: Some("UDP metadata server".to_string()),
    })
    .await
    .unwrap();
    let key_ip = Ipv4Addr::new(198, 51, 100, 7);
    let key_ip_client_id = u32::from_le_bytes(key_ip.octets());
    assert_eq!(
        core.note_ed2k_server_status(
            "192.0.2.45:4661",
            12_345,
            67_890,
            15_000,
            456,
            37,
            111,
            222,
            0x30,
            0x1122_3344,
            key_ip_client_id,
            4711,
            4723,
        )
        .await
        .as_deref(),
        Some("192.0.2.45:4661")
    );

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let persisted = reloaded.server("192.0.2.45:4661").await.expect("server");
    assert_eq!(persisted.users, 12_345);
    assert_eq!(persisted.files, 67_890);
    assert_eq!(persisted.max_users, 15_000);
    assert_eq!(persisted.low_id_users, 456);
    assert_eq!(persisted.ping, 37);
    assert_eq!(persisted.soft_files, 111);
    assert_eq!(persisted.hard_files, 222);
    assert_eq!(persisted.udp_flags, Some(0x30));
    assert_eq!(persisted.udp_key, Some(0x1122_3344));
    assert_eq!(persisted.udp_key_ip, Some(key_ip_client_id));
    assert_eq!(persisted.obfuscation_tcp_port, Some(4711));
    assert_eq!(persisted.obfuscation_udp_port, Some(4723));

    let reachability = reloaded.ed2k_reachability_authority.begin_runtime();
    let runtime_writer = reachability.writer();
    let mut server_reachability = runtime_writer.begin_server_session().unwrap();
    server_reachability.activate();
    let server_writer = server_reachability.writer();
    server_writer.set_server_public_ip(key_ip);
    let current = reloaded
        .effective_ed2k_config(&Ed2kRuntimeConfig::default())
        .await
        .unwrap();
    let current = current
        .server_entries
        .iter()
        .find(|entry| entry.host == "192.0.2.45" && entry.port == 4661)
        .expect("persisted server entry");
    assert_eq!(current.udp_key, 0x1122_3344);
    assert_eq!(current.udp_key_ip, key_ip_client_id);
    assert_eq!(current.obfuscation_port_tcp, 4711);
    assert_eq!(current.obfuscation_port_udp, 4723);

    server_writer.set_server_public_ip(Ipv4Addr::new(198, 51, 100, 8));
    let stale = reloaded
        .effective_ed2k_config(&Ed2kRuntimeConfig::default())
        .await
        .unwrap();
    let stale = stale
        .server_entries
        .iter()
        .find(|entry| entry.host == "192.0.2.45" && entry.port == 4661)
        .expect("persisted server entry");
    assert_eq!(stale.udp_key, 0);
    assert_eq!(stale.udp_key_ip, key_ip_client_id);
}

async fn install_test_server_plan_runtime(
    core: &EmulebbCore,
    mode: Ed2kServerConnectMode,
    server_state: Ed2kServerState,
) -> (
    tokio::sync::watch::Sender<Ed2kServerConnectPlan>,
    tokio::sync::watch::Receiver<Ed2kServerConnectPlan>,
    Arc<AtomicBool>,
) {
    let (search_handle, _search_inbox) = new_ed2k_server_search_channel(1);
    let dht = DhtNode::new(DhtConfig {
        bind_addr: Some("0.0.0.0:0".parse().unwrap()),
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let dht_task = dht.start();
    let initial_config = core
        .effective_ed2k_config(&core.ed2k_network.as_ref().unwrap().ed2k)
        .await
        .unwrap();
    let (server_connect_plan, server_connect_plan_rx) =
        tokio::sync::watch::channel(Ed2kServerConnectPlan::new(initial_config, mode));
    *core.ed2k_runtime.lock().await = Some(Ed2kRuntime {
        search_handle,
        server_state: Arc::new(RwLock::new(server_state)),
        server_control: test_server_control_handle(),
        dht,
        callback_sessions: ed2k_callback_session_channel().0,
        kad_persistence_finished: true,
        kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
        reachability: core.ed2k_reachability_authority.begin_runtime(),
        nat: Arc::new(NatManager::default()),
        shutdown: Arc::clone(&shutdown),
        server_connect_plan: server_connect_plan.clone(),
        server_task: test_server_task(),
        kad_firewall_recheck: None,
        tasks: vec![dht_task],
    });
    (server_connect_plan, server_connect_plan_rx, shutdown)
}

async fn wait_for_server_plan_update(
    receiver: &mut tokio::sync::watch::Receiver<Ed2kServerConnectPlan>,
) -> Ed2kServerConnectPlan {
    tokio::time::timeout(Duration::from_secs(1), receiver.changed())
        .await
        .expect("server mutation should publish a plan generation")
        .expect("server plan sender should remain open");
    receiver.borrow().clone()
}

#[tokio::test]
async fn server_add_publishes_a_live_plan_generation() {
    let transfer_root = unique_runtime_dir("emulebb-core-server-add-live-plan");
    let network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(network),
    )
    .unwrap();
    let (_plan, mut plan_rx, shutdown) = install_test_server_plan_runtime(
        &core,
        Ed2kServerConnectMode::Automatic,
        Ed2kServerState::default(),
    )
    .await;

    let definition = emulebb_metadata::MetadataServerCreate {
        address: "203.0.113.70".to_string(),
        port: 4661,
        priority: "high".to_string(),
        static_server: true,
        enabled: true,
    };
    core.create_server_resource(&definition).await.unwrap();
    core.import_server_resource(&emulebb_metadata::MetadataServerImport {
        address: definition.address,
        port: definition.port,
        name: Some("Live Add".to_string()),
    })
    .await
    .unwrap();

    let plan = wait_for_server_plan_update(&mut plan_rx).await;
    assert_eq!(plan.mode(), &Ed2kServerConnectMode::Automatic);
    let added = plan
        .config()
        .server_entries
        .iter()
        .find(|entry| entry.host == "203.0.113.70" && entry.port == 4661)
        .expect("added server should be immediately eligible");
    assert_eq!(added.priority, "high");
    assert!(added.static_server);
    assert!(!shutdown.load(Ordering::SeqCst));

    let _ = core.disconnect_ed2k().await;
}

#[tokio::test]
async fn server_mutations_replace_the_plan_without_stopping_the_runtime() {
    let transfer_root = unique_runtime_dir("emulebb-core-server-mutations-live-plan");
    let mut network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let endpoint = "203.0.113.71:4661";
    network.ed2k.server_endpoints = vec![endpoint.to_string()];
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(network),
    )
    .unwrap();
    core.create_server_resource(&emulebb_metadata::MetadataServerCreate {
        address: "203.0.113.71".into(),
        port: 4661,
        priority: "normal".into(),
        static_server: false,
        enabled: true,
    })
    .await
    .unwrap();
    let (_plan, mut plan_rx, shutdown) = install_test_server_plan_runtime(
        &core,
        Ed2kServerConnectMode::Directed(endpoint.to_string()),
        Ed2kServerState {
            endpoint: Some(endpoint.parse().unwrap()),
            connected: true,
            ..Ed2kServerState::default()
        },
    )
    .await;

    core.update_server_resource(
        saved_server_id(&core, endpoint).await,
        &MetadataServerUpdate {
            priority: Some("high".to_string()),
            static_server: Some(true),
            ..MetadataServerUpdate::default()
        },
    )
    .await
    .unwrap();
    let updated = wait_for_server_plan_update(&mut plan_rx).await;
    let updated_entry = updated
        .config()
        .server_entries
        .iter()
        .find(|entry| entry.host == "203.0.113.71" && entry.port == 4661)
        .expect("updated server should remain eligible");
    assert_eq!(updated_entry.priority, "high");
    assert!(updated_entry.static_server);

    core.update_server_resource(
        saved_server_id(&core, endpoint).await,
        &MetadataServerUpdate {
            enabled: Some(false),
            ..MetadataServerUpdate::default()
        },
    )
    .await
    .unwrap();
    let disabled = wait_for_server_plan_update(&mut plan_rx).await;
    assert_eq!(
        disabled.mode(),
        &Ed2kServerConnectMode::Directed(endpoint.to_string())
    );
    assert!(disabled.config().server_entries.is_empty());
    assert!(disabled.config().server_endpoints.is_empty());
    let peer_server_ip = "203.0.113.71".parse().unwrap();
    assert_eq!(
        core.ed2k_transfers.known_server_endpoint(peer_server_ip),
        Some(endpoint.parse().unwrap())
    );
    assert!(core.ed2k_runtime.lock().await.is_some());
    assert!(!shutdown.load(Ordering::SeqCst));

    core.update_server_resource(
        saved_server_id(&core, endpoint).await,
        &MetadataServerUpdate {
            enabled: Some(true),
            ..MetadataServerUpdate::default()
        },
    )
    .await
    .unwrap();
    let reenabled = wait_for_server_plan_update(&mut plan_rx).await;
    assert!(
        reenabled
            .config()
            .server_entries
            .iter()
            .any(|entry| entry.host == "203.0.113.71" && entry.port == 4661)
    );

    core.delete_server_resource(saved_server_id(&core, endpoint).await)
        .await
        .unwrap();
    let removed = wait_for_server_plan_update(&mut plan_rx).await;
    assert!(removed.config().server_entries.is_empty());
    assert!(removed.config().server_endpoints.is_empty());
    assert_eq!(
        core.ed2k_transfers.known_server_endpoint(peer_server_ip),
        None
    );
    assert!(core.ed2k_runtime.lock().await.is_some());
    assert!(!shutdown.load(Ordering::SeqCst));

    let _ = core.disconnect_ed2k().await;
}

#[tokio::test]
async fn core_settings_do_not_republish_or_overwrite_ed2k_server_policy() {
    let transfer_root = unique_runtime_dir("emulebb-core-settings-live-plan");
    let mut network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.ed2k.reconnect_enabled = false;
    network.ed2k.safe_server_connect = true;
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(network),
    )
    .unwrap();
    let (_plan, mut plan_rx, _shutdown) = install_test_server_plan_runtime(
        &core,
        Ed2kServerConnectMode::Manual,
        Ed2kServerState::default(),
    )
    .await;

    update_test_settings(
        &core,
        serde_json::json!({"network":{"connections":{"maxConnections":321}}}),
    )
    .await;

    assert!(
        tokio::time::timeout(Duration::from_millis(50), plan_rx.changed())
            .await
            .is_err(),
        "unrelated core settings must not republish the ED2K server plan"
    );
    let unchanged = plan_rx.borrow().clone();
    assert!(!unchanged.config().reconnect_enabled);
    assert!(unchanged.config().safe_server_connect);

    let _ = core.disconnect_ed2k().await;
}

#[tokio::test]
async fn server_status_metadata_refreshes_the_live_plan_in_place() {
    let transfer_root = unique_runtime_dir("emulebb-core-server-status-live-plan");
    let mut network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let endpoint = "203.0.113.72:4661";
    network.ed2k.server_endpoints = vec![endpoint.to_string()];
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(network),
    )
    .unwrap();
    let (_plan, mut plan_rx, shutdown) = install_test_server_plan_runtime(
        &core,
        Ed2kServerConnectMode::Directed(endpoint.to_string()),
        Ed2kServerState {
            endpoint: Some(endpoint.parse().unwrap()),
            connected: true,
            ..Ed2kServerState::default()
        },
    )
    .await;

    assert_eq!(
        core.note_ed2k_server_status(
            endpoint, 12_345, 67_890, 20_000, 500, 42, 100_000, 120_000, 0x30, 0, 0, 4711, 4723,
        )
        .await
        .as_deref(),
        Some(endpoint)
    );

    let updated = wait_for_server_plan_update(&mut plan_rx).await;
    let entry = updated
        .config()
        .server_entries
        .iter()
        .find(|entry| entry.host == "203.0.113.72" && entry.port == 4661)
        .expect("status-updated server should remain eligible");
    assert_eq!(entry.udp_flags, 0x30);
    assert_eq!(entry.obfuscation_port_tcp, 4711);
    assert_eq!(entry.obfuscation_port_udp, 4723);
    assert_eq!(
        updated.mode(),
        &Ed2kServerConnectMode::Directed(endpoint.to_string())
    );
    assert!(core.ed2k_runtime.lock().await.is_some());
    assert!(!shutdown.load(Ordering::SeqCst));

    let _ = core.disconnect_ed2k().await;
}

#[tokio::test]
async fn explicit_server_connect_targets_running_server_loop() {
    let transfer_root = unique_runtime_dir("emulebb-core-target-running-server-loop");
    let mut network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.ed2k.server_endpoints = vec![
        "203.0.113.10:4661".to_string(),
        "203.0.113.20:4661".to_string(),
    ];
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(network),
    )
    .unwrap();
    let (search_handle, _search_inbox) = new_ed2k_server_search_channel(1);
    let dht = DhtNode::new(DhtConfig {
        bind_addr: Some("0.0.0.0:0".parse().unwrap()),
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let dht_task = dht.start();
    let initial_config = core
        .effective_ed2k_config(&core.ed2k_network.as_ref().unwrap().ed2k)
        .await
        .unwrap();
    let (server_connect_plan, mut server_connect_plan_rx) = tokio::sync::watch::channel(
        Ed2kServerConnectPlan::new(initial_config, Ed2kServerConnectMode::Manual),
    );

    *core.ed2k_runtime.lock().await = Some(Ed2kRuntime {
        search_handle,
        server_state: Arc::new(RwLock::new(Ed2kServerState::default())),
        server_control: test_server_control_handle(),
        dht,
        callback_sessions: ed2k_callback_session_channel().0,
        kad_persistence_finished: true,
        kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
        reachability: core.ed2k_reachability_authority.begin_runtime(),
        nat: Arc::new(NatManager::default()),
        shutdown: Arc::clone(&shutdown),
        server_connect_plan: server_connect_plan.clone(),
        server_task: test_server_task(),
        kad_firewall_recheck: None,
        tasks: vec![dht_task],
    });

    let result = core.connect_ed2k_server("203.0.113.20:4661").await.unwrap();

    assert!(result.is_some());
    assert_eq!(
        server_connect_plan.borrow().mode().directed_endpoint(),
        Some("203.0.113.20:4661")
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), server_connect_plan_rx.changed())
            .await
            .is_ok(),
        "retargeting a running server loop must publish a new selection generation"
    );
    assert_eq!(
        server_connect_plan.borrow().config().server_endpoints.len(),
        2
    );

    core.connect_ed2k().await.unwrap();

    assert_eq!(
        server_connect_plan.borrow().mode(),
        &Ed2kServerConnectMode::Manual
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), server_connect_plan_rx.changed())
            .await
            .is_ok(),
        "global connect must clear a directed target and resume automatic selection"
    );
    shutdown.store(true, Ordering::SeqCst);
    let _ = core.disconnect_ed2k().await;
}

#[tokio::test]
async fn explicit_server_connect_to_live_endpoint_is_idempotent() {
    let transfer_root = unique_runtime_dir("emulebb-core-same-server-connect-noop");
    let mut network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.ed2k.server_endpoints = vec!["203.0.113.20:4661".to_string()];
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(network),
    )
    .unwrap();
    let (search_handle, _search_inbox) = new_ed2k_server_search_channel(1);
    let dht = DhtNode::new(DhtConfig {
        bind_addr: Some("0.0.0.0:0".parse().unwrap()),
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let dht_task = dht.start();
    let initial_config = core
        .effective_ed2k_config(&core.ed2k_network.as_ref().unwrap().ed2k)
        .await
        .unwrap();
    let (server_connect_plan, mut server_connect_plan_rx) =
        tokio::sync::watch::channel(Ed2kServerConnectPlan::new(
            initial_config,
            Ed2kServerConnectMode::Directed("203.0.113.20:4661".to_string()),
        ));
    let server_state = Arc::new(RwLock::new(Ed2kServerState {
        endpoint: Some("203.0.113.20:4661".parse().unwrap()),
        connected: true,
        ..Ed2kServerState::default()
    }));

    *core.ed2k_runtime.lock().await = Some(Ed2kRuntime {
        search_handle,
        server_state,
        server_control: test_server_control_handle(),
        dht,
        callback_sessions: ed2k_callback_session_channel().0,
        kad_persistence_finished: true,
        kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
        reachability: core.ed2k_reachability_authority.begin_runtime(),
        nat: Arc::new(NatManager::default()),
        shutdown: Arc::clone(&shutdown),
        server_connect_plan: server_connect_plan.clone(),
        server_task: test_server_task(),
        kad_firewall_recheck: None,
        tasks: vec![dht_task],
    });

    let result = core.connect_ed2k_server("203.0.113.20:4661").await.unwrap();

    assert!(result.is_some());
    assert_eq!(
        server_connect_plan.borrow().mode().directed_endpoint(),
        Some("203.0.113.20:4661")
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), server_connect_plan_rx.changed())
            .await
            .is_err(),
        "same-endpoint connect must not drop a live server session"
    );
    shutdown.store(true, Ordering::SeqCst);
    let _ = core.disconnect_ed2k().await;
}

#[tokio::test]
async fn merge_discovered_servers_adds_new_dedups_existing() {
    let transfer_root = unique_runtime_dir("emulebb-core-discovered-server-add");
    let mut network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.ed2k.add_servers_from_server = true;
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(network),
    )
    .unwrap();
    core.create_server_resource(&emulebb_metadata::MetadataServerCreate {
        address: "45.82.80.155".to_string(),
        port: 5687,
        priority: "normal".into(),
        static_server: true,
        enabled: true,
    })
    .await
    .unwrap();

    core.merge_discovered_ed2k_servers(vec![
        (Ipv4Addr::new(45, 82, 80, 155), 5687), // duplicate of existing
        (Ipv4Addr::new(203, 0, 113, 9), 4661),  // new
        (Ipv4Addr::new(203, 0, 113, 9), 4661),  // duplicate within batch
    ])
    .await;

    let servers = core.servers().await;
    let lugd = servers
        .iter()
        .filter(|s| s.address == "45.82.80.155" && s.port == 5687)
        .count();
    assert_eq!(lugd, 1, "existing server is not duplicated");
    let new_server = servers
        .iter()
        .find(|s| s.address == "203.0.113.9" && s.port == 4661)
        .expect("discovered server added");
    assert_eq!(new_server.priority, "low");
    assert!(!new_server.static_server);
}

#[tokio::test]
async fn merge_discovered_servers_respects_ed2k_owned_add_servers_policy() {
    let transfer_root = unique_runtime_dir("emulebb-core-discovered-server-disabled");
    let mut network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.ed2k.add_servers_from_server = false;
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(network),
    )
    .unwrap();
    core.merge_discovered_ed2k_servers(vec![(Ipv4Addr::new(203, 0, 113, 9), 4661)])
        .await;
    assert!(
        !core
            .servers()
            .await
            .iter()
            .any(|s| s.address == "203.0.113.9" && s.port == 4661),
        "auto-add disabled: a discovered server must not be added"
    );
}

#[tokio::test]
async fn connect_failed_drops_non_static_dead_server_at_threshold() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.create_server_resource(&emulebb_metadata::MetadataServerCreate {
        address: "203.0.113.5".to_string(),
        port: 4661,
        priority: "normal".into(),
        static_server: false,
        enabled: true,
    })
    .await
    .unwrap();
    let endpoint = "203.0.113.5:4661";

    // Default dead_server_retries = 1: first failure drops the server.
    core.note_ed2k_server_connection_failed(
        endpoint,
        &Ed2kServerFailure::new(
            Ed2kServerFailurePhase::Connect,
            Ed2kServerFailureReason::ConnectionRefused,
            "test refusal",
        ),
        1,
    )
    .await;
    let server = core
        .server(endpoint)
        .await
        .expect("dead server remains visible");
    assert!(
        !server.enabled,
        "non-static dead server is disabled at the threshold"
    );
}

#[tokio::test]
async fn classified_non_remote_failures_never_mutate_server_health() {
    let failures = [
        (
            Ed2kServerFailurePhase::Resolve,
            Ed2kServerFailureReason::DnsResolution,
        ),
        (
            Ed2kServerFailurePhase::SocketSetup,
            Ed2kServerFailureReason::LocalBindInterface,
        ),
        (
            Ed2kServerFailurePhase::Connect,
            Ed2kServerFailureReason::TimeoutUnreachable,
        ),
        (
            Ed2kServerFailurePhase::Handshake,
            Ed2kServerFailureReason::ProtocolRejection,
        ),
        (
            Ed2kServerFailurePhase::Established,
            Ed2kServerFailureReason::EstablishedDisconnect,
        ),
        (
            Ed2kServerFailurePhase::Handshake,
            Ed2kServerFailureReason::TransportOther,
        ),
    ];

    for threshold in [1, 3] {
        for (index, &(phase, reason)) in failures.iter().enumerate() {
            let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
            let address = format!("203.0.113.{}", index + 20);
            let endpoint = format!("{address}:4661");
            core.create_server_resource(&emulebb_metadata::MetadataServerCreate {
                address,
                port: 4661,
                priority: "normal".into(),
                static_server: false,
                enabled: true,
            })
            .await
            .unwrap();

            core.note_ed2k_server_connection_failed(
                &endpoint,
                &Ed2kServerFailure::new(phase, reason, "classified test failure"),
                threshold,
            )
            .await;

            let server = core.server(&endpoint).await.unwrap();
            assert!(server.enabled, "{phase:?}/{reason:?} disabled the server");
            assert_eq!(
                server.failed_count, 0,
                "{phase:?}/{reason:?} changed failedCount"
            );
        }
    }
}

#[tokio::test]
async fn classified_refusal_obeys_multi_failure_threshold() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let endpoint = "203.0.113.40:4661";
    core.create_server_resource(&emulebb_metadata::MetadataServerCreate {
        address: "203.0.113.40".to_string(),
        port: 4661,
        priority: "normal".into(),
        static_server: false,
        enabled: true,
    })
    .await
    .unwrap();
    let failure = Ed2kServerFailure::new(
        Ed2kServerFailurePhase::Connect,
        Ed2kServerFailureReason::ConnectionRefused,
        "test refusal",
    );

    for expected in 1..3 {
        core.note_ed2k_server_connection_failed(endpoint, &failure, 3)
            .await;
        let server = core.server(endpoint).await.unwrap();
        assert!(server.enabled);
        assert_eq!(server.failed_count, expected);
    }
    core.note_ed2k_server_connection_failed(endpoint, &failure, 3)
        .await;
    let server = core.server(endpoint).await.unwrap();
    assert!(!server.enabled);
    assert_eq!(server.failed_count, 3);
}

#[tokio::test]
async fn explicit_server_connect_ignores_disabled_servers() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.create_server_resource(&emulebb_metadata::MetadataServerCreate {
        address: "203.0.113.8".to_string(),
        port: 4661,
        priority: "normal".into(),
        static_server: false,
        enabled: true,
    })
    .await
    .unwrap();
    core.update_server_resource(
        saved_server_id(&core, "203.0.113.8:4661").await,
        &MetadataServerUpdate {
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let result = core.connect_ed2k_server("203.0.113.8:4661").await.unwrap();

    assert!(result.is_none());
}

#[tokio::test]
async fn connect_failed_never_drops_static_server() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.create_server_resource(&emulebb_metadata::MetadataServerCreate {
        address: "203.0.113.6".to_string(),
        port: 4661,
        priority: "normal".into(),
        static_server: true,
        enabled: true,
    })
    .await
    .unwrap();
    let endpoint = "203.0.113.6:4661";

    // Even far past the threshold, a static server is kept (eMule keeps
    // static servers); the fail-count is still tracked.
    for _ in 0..5 {
        core.note_ed2k_server_connect_failed(endpoint, 1).await;
    }
    let server = core.server(endpoint).await.expect("static server kept");
    assert!(server.failed_count >= 1);
}

#[tokio::test]
async fn connect_succeeded_clears_fail_count() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.create_server_resource(&emulebb_metadata::MetadataServerCreate {
        address: "203.0.113.7".to_string(),
        port: 4661,
        priority: "normal".into(),
        static_server: false,
        enabled: true,
    })
    .await
    .unwrap();
    let endpoint = "203.0.113.7:4661";

    // With a higher threshold, accumulate failures, then a success clears them.
    core.note_ed2k_server_connect_failed(endpoint, 3).await;
    core.note_ed2k_server_connect_failed(endpoint, 3).await;
    assert_eq!(core.server(endpoint).await.unwrap().failed_count, 2);
    core.note_ed2k_server_connect_succeeded(endpoint).await;
    assert_eq!(core.server(endpoint).await.unwrap().failed_count, 0);
    // The cleared count means it now takes the full threshold again to drop.
    core.note_ed2k_server_connect_failed(endpoint, 3).await;
    assert!(core.server(endpoint).await.is_some());
}

#[test]
fn exact_ed2k_hash_query_token_extracts_hash_only_queries() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    assert_eq!(
        exact_ed2k_hash_query_token(&format!("ed2k::{exact_hash}")),
        Some(exact_hash.clone())
    );
    assert_eq!(
        exact_ed2k_hash_query_token(&exact_hash.to_ascii_uppercase()),
        Some(exact_hash)
    );
    assert_eq!(exact_ed2k_hash_query_token("ed2k::torino train"), None);
}

#[test]
fn significant_words_ignore_short_tokens() {
    assert_eq!(
        significant_keyword_words("A torino x train"),
        vec!["torino".to_string(), "train".to_string()]
    );
}

#[test]
fn significant_words_keep_in_word_symbols_matching_getwords_separators() {
    // `INV_KAD_KEYWORD_CHARS` does not include `&`, `+`, `'` or `#`, so the
    // oracle keeps them inside the word instead of over-splitting.
    assert_eq!(
        significant_keyword_words("AT&T Wireless"),
        vec!["at&t".to_string(), "wireless".to_string()]
    );
    assert_eq!(
        significant_keyword_words("C++ Tutorial"),
        vec!["c++".to_string(), "tutorial".to_string()]
    );
    assert_eq!(
        significant_keyword_words("rock'n'roll live"),
        vec!["rock'n'roll".to_string(), "live".to_string()]
    );
}

#[test]
fn significant_words_drop_trailing_three_char_extension() {
    // GetWords pops a trailing 3-char/3-byte token (SearchManager.cpp:284-286)
    // when more than one word survived; the drop applies to publish keywords
    // and to search queries alike because both share this tokenizer.
    assert_eq!(
        significant_keyword_words("ubuntu.iso"),
        vec!["ubuntu".to_string()]
    );
    assert_eq!(
        significant_keyword_words("AT&T.avi"),
        vec!["at&t".to_string()]
    );
    assert_eq!(
        significant_keyword_words("C++ Tutorial.pdf"),
        vec!["c++".to_string(), "tutorial".to_string()]
    );
    // A search query tokenizes identically: the trailing extension is dropped.
    assert_eq!(
        significant_keyword_words("ubuntu iso"),
        vec!["ubuntu".to_string()]
    );
    // The extension drop only fires when more than one word survives, so a
    // lone 3-char word is kept ("a.b.mp3" leaves only "mp3").
    assert_eq!(
        significant_keyword_words("a.b.mp3"),
        vec!["mp3".to_string()]
    );
    // A trailing token longer than 3 chars is not an extension: "#1" is under
    // the 3-byte minimum and drops out, "flac" is kept.
    assert_eq!(
        significant_keyword_words("R&B #1.flac"),
        vec!["r&b".to_string(), "flac".to_string()]
    );
}

#[test]
fn kad_keyword_lowercase_matches_oracle_frozen_table() {
    // ASCII A-Z lower-cases exactly as before (the common case).
    assert_eq!(
        kad_keyword_lowercase("Ubuntu ISO"),
        "ubuntu iso".to_string()
    );
    // Latin-1 / Greek / Cyrillic uppercase letters that the oracle's
    // `LANG_ENGLISH` map lowers are still lowered (À->à, Β->β, А->а).
    assert_eq!(kad_keyword_lowercase("À"), "à".to_string());
    assert_eq!(kad_keyword_lowercase("Β"), "β".to_string());
    assert_eq!(kad_keyword_lowercase("А"), "а".to_string());
    // Code points the oracle's frozen table leaves UNCHANGED but Rust's
    // `str::to_lowercase()` would alter: U+0130 (İ, which Rust expands to two
    // chars), U+1E9E (ẞ, Rust -> ß), the U+212A Kelvin sign (Rust -> k) and
    // the U+00B5 micro sign (Rust -> μ). Keeping them verbatim is what makes
    // the md4 keyword hash match eMule for these words.
    assert_eq!(kad_keyword_lowercase("\u{0130}"), "\u{0130}".to_string());
    assert_eq!(kad_keyword_lowercase("\u{1E9E}"), "\u{1E9E}".to_string());
    assert_eq!(kad_keyword_lowercase("\u{212A}"), "\u{212A}".to_string());
    assert_eq!(kad_keyword_lowercase("\u{00B5}"), "\u{00B5}".to_string());
    // Already-lower and astral (identity-mapped surrogate) code points pass
    // through untouched.
    assert_eq!(kad_keyword_lowercase("café"), "café".to_string());
    assert_eq!(kad_keyword_lowercase("\u{1F600}"), "\u{1F600}".to_string());
}

#[test]
fn significant_words_lowercase_uses_oracle_table_for_non_ascii() {
    // The tokenizer lower-cases through the oracle table: "Café.İşi" keeps
    // U+0130 verbatim (Rust's full lower-casing would expand it) so the
    // produced keyword — and thus its md4 target — matches eMule's.
    assert_eq!(
        significant_keyword_words("Café İyi"),
        vec!["café".to_string(), "\u{0130}yi".to_string()]
    );
}

#[test]
fn significant_words_dedup_keeps_last_occurrence() {
    // GetWords de-duplicates with `remove` + `push_back` (SearchManager.cpp:
    // 277-278), moving a repeated word to the END of the list. "ubuntu"
    // repeats, so it lands after "python" rather than staying at the front.
    assert_eq!(
        significant_keyword_words_unique("Ubuntu Python ubuntu programming Apache Camel"),
        vec![
            "python".to_string(),
            "ubuntu".to_string(),
            "programming".to_string(),
            "apache".to_string(),
            "camel".to_string(),
        ]
    );
}

#[test]
fn significant_words_repeated_first_token_shifts_primary_keyword() {
    // When the first token repeats, the oracle's remove+push_back moves it to
    // the end, so the primary keyword (GetWords `front()`, hashed by
    // `keyword_target`) becomes the next distinct word. "love song love"
    // dedups to ["song", "love"], not ["love", "song"].
    assert_eq!(
        significant_keyword_words("love song love"),
        vec!["song".to_string(), "love".to_string()]
    );
    // The Kad keyword target therefore hashes "song", not "love".
    assert_eq!(keyword_target("love song love"), keyword_target("song"));
    assert_ne!(keyword_target("love song love"), keyword_target("love"));
}

#[tokio::test]
async fn raw_search_evidence_counts_once_survives_filters_and_freezes_terminal_membership() {
    let root = unique_runtime_dir("search-corpus-ingestion");
    let network = test_network_config_with_store(
        &root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::open(root.join("metadata.sqlite")).unwrap(),
        root.join("transfers"),
        Some(network),
    )
    .unwrap();
    let request = SearchCreate {
        parent_search_id: None,
        query: "sample query".into(),
        method: "server".into(),
        min_size_bytes: Some(1024),
        ..Default::default()
    };
    let search = core.create_search(request.clone()).await.unwrap();
    let reporter = "192.0.2.4:4661".parse().unwrap();
    let mut raw = crate::search_observations::tests::raw_file();
    raw.file_size = Some(2048);
    let update = |raw: &emulebb_ed2k::ed2k_server::Ed2kSearchFile| {
        let mapped = crate::search_query::search_result_from_ed2k(
            &search.id,
            &request,
            "server",
            Some(reporter),
            raw.clone(),
        );
        crate::search_observations::ed2k(
            mapped,
            emulebb_metadata::MetadataObservationOrigin::Server,
            Some(reporter),
            raw,
        )
    };
    core.apply_search_live_update(&search.id, &request, update(&raw))
        .await
        .unwrap();
    core.apply_search_live_update(&search.id, &request, update(&raw))
        .await
        .unwrap();
    assert_eq!(
        core.metadata_store
            .search_header(search.id.parse().unwrap())
            .unwrap()
            .unwrap()
            .result_count,
        1
    );
    let page = core
        .metadata_store
        .content_observations_page(1, 0, 100)
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].receipt.observation_count, 2);
    let mut filtered = raw.clone();
    filtered.file_hash.0 = [0x99; 16];
    filtered.file_size = Some(1);
    core.apply_search_live_update(&search.id, &request, update(&filtered))
        .await
        .unwrap();
    assert_eq!(
        core.metadata_store
            .search_header(search.id.parse().unwrap())
            .unwrap()
            .unwrap()
            .result_count,
        1
    );
    assert_eq!(
        core.metadata_store.table_count("content_claims").unwrap(),
        2
    );
    core.complete_search_with_results(&search.id, &request, "server", None, None)
        .await;
    assert_eq!(
        core.metadata_store
            .content_observations_page(1, 0, 100)
            .unwrap()
            .items[0]
            .receipt
            .observation_count,
        2
    );
    raw.file_name = Some("Alternate.bin".into());
    core.apply_search_live_update(&search.id, &request, update(&raw))
        .await
        .unwrap();
    let completed = core
        .metadata_store
        .search_result_headers_page(search.id.parse().unwrap(), 0, 1)
        .unwrap()
        .unwrap();
    assert_eq!(completed.items[0].summary.name, "Sample.bin");
    assert!(!core.state.lock().await.searches.contains_key(&search.id));
    assert_eq!(
        core.metadata_store
            .content_observations_page(1, 0, 100)
            .unwrap()
            .items
            .len(),
        2
    );
    core.delete_search(&search.id).await.unwrap();
    raw.file_hash.0 = [0x56; 16];
    raw.file_size = None;
    core.apply_search_live_update(&search.id, &request, update(&raw))
        .await
        .unwrap();
    assert_eq!(
        core.metadata_store.table_count("content_claims").unwrap(),
        3
    );
    assert_eq!(
        core.metadata_store.table_count("search_sessions").unwrap(),
        0
    );
    core.persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap()
        .close_and_drain()
        .await
        .unwrap();
}

#[tokio::test]
async fn search_state_survives_core_restart_and_downloads_result() {
    let runtime_dir = unique_runtime_dir("search-state");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let open = || {
        EmulebbCore::new_with_network(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
            Some(test_network_config_with_store(
                &transfer_root,
                KadLocalStoreConfig::default(),
                SnoopQueueConfig::default(),
            )),
        )
        .unwrap()
    };

    let (search_id, file_hash) = {
        let core = open();
        let search = core
            .create_search(SearchCreate {
                parent_search_id: None,
                query: "sample payload".to_string(),
                method: "automatic".to_string(),
                r#type: "arc".to_string(),
                extension: "bin".to_string(),
                min_size_bytes: Some(1_000),
                max_size_bytes: Some(2_000),
                min_availability: Some(5),
                min_complete_sources: Some(0),
                min_bitrate_kbps: Some(0),
                min_length_seconds: Some(0),
                codec: String::new(),
                title: String::new(),
                album: String::new(),
                artist: String::new(),
            })
            .await
            .unwrap();
        assert_eq!(
            core.metadata_store
                .search_header(search.id.parse().unwrap())
                .unwrap()
                .unwrap()
                .result_count,
            0
        );
        let mut raw = crate::search_observations::tests::raw_file();
        raw.file_name = Some("Sample Search Payload.bin".into());
        raw.file_size = Some(1234);
        raw.file_type = Some("Arc".into());
        raw.source_count = Some(7);
        let reporter = "192.0.2.4:4661".parse().unwrap();
        let projected = crate::search_query::search_result_from_ed2k(
            &search.id,
            &search.spec,
            "server",
            Some(reporter),
            raw.clone(),
        );
        let update = crate::search_observations::ed2k(
            projected,
            emulebb_metadata::MetadataObservationOrigin::Server,
            Some(reporter),
            &raw,
        );
        core.apply_search_live_update(&search.id, &search.spec, update)
            .await
            .unwrap();
        core.complete_search_with_results(&search.id, &search.spec, "server", None, None)
            .await;
        let recorded = core
            .metadata_store
            .search_result_headers_page(search.id.parse().unwrap(), 0, 1)
            .unwrap()
            .unwrap();
        assert_eq!(recorded.items.len(), 1);
        assert!(core.state.lock().await.searches.is_empty());
        (search.id, recorded.items[0].file_hash.clone())
    };

    let reloaded = open();
    assert!(reloaded.state.lock().await.searches.is_empty());
    let searches = reloaded
        .metadata_store
        .search_headers_page(None, 10)
        .unwrap();
    assert_eq!(searches.items.len(), 1);
    assert_eq!(searches.items[0].id.to_string(), search_id);
    assert_eq!(searches.items[0].data.spec.method, "automatic");
    assert_eq!(searches.items[0].data.spec.file_type, "arc");
    assert_eq!(searches.items[0].data.spec.extension, "bin");
    assert_eq!(searches.items[0].data.spec.min_size_bytes, Some(1_000));
    assert_eq!(searches.items[0].data.spec.max_size_bytes, Some(2_000));
    assert_eq!(searches.items[0].data.spec.min_availability, Some(5));
    assert_eq!(searches.items[0].data.spec.min_complete_sources, None);
    assert_eq!(searches.items[0].data.spec.min_bitrate_kbps, None);
    assert_eq!(searches.items[0].data.spec.min_length_seconds, None);
    assert_eq!(searches.items[0].data.spec.codec, "");
    assert_eq!(searches.items[0].data.spec.title, "");
    assert_eq!(searches.items[0].data.spec.album, "");
    assert_eq!(searches.items[0].data.spec.artist, "");
    assert_eq!(
        searches.items[0].data.resolved_method.as_deref(),
        Some("server")
    );
    let results = reloaded
        .metadata_store
        .search_result_headers_page(search_id.parse().unwrap(), 0, 1)
        .unwrap()
        .unwrap();
    assert_eq!(results.items[0].summary.name, "Sample Search Payload.bin");
    assert_eq!(results.items[0].summary.file_type, "Arc");

    assert_eq!(
        reloaded
            .metadata_store
            .content_observations_page(1, 0, 10)
            .unwrap()
            .items[0]
            .receipt
            .observation_count,
        1
    );
    assert_eq!(results.items[0].file_hash, file_hash);

    let (_, download) = reloaded
        .download_search_result(
            &search_id,
            &results.items[0].claim_id.to_string(),
            SearchResultDownloadCreate::default(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(download.hash, file_hash);
}

#[tokio::test]
async fn startup_keeps_one_hundred_thousand_retained_sessions_out_of_runtime_state() {
    let root = unique_runtime_dir("search-retained-startup");
    let path = root.join("metadata.sqlite");
    drop(FileIndex::open(&path).unwrap());
    {
        let sql = rusqlite::Connection::open(&path).unwrap();
        sql.execute_batch("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100000)
            INSERT INTO search_sessions(id,query,normalized_query,requested_method,status,created_at_s,updated_at_s)
            SELECT i,'sample','sample','server',CASE WHEN i<3 THEN 'running' ELSE 'completed' END,1,1 FROM n;").unwrap();
    }
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::open(&path).unwrap(),
        root.join("transfers"),
        None,
    )
    .unwrap();
    assert!(core.state.lock().await.searches.is_empty());
    assert!(core.state.lock().await.search_cancels.is_empty());
    assert_eq!(
        core.metadata_store.table_count("search_sessions").unwrap(),
        100000
    );
    let interrupted = core.metadata_store.search_header(1).unwrap().unwrap();
    assert_eq!(interrupted.data.status, "error");
    assert_eq!(
        interrupted.data.status_reason.as_deref(),
        Some("interrupted-by-restart")
    );
    let page = core.search_headers_page(None, 2).await.unwrap();
    assert_eq!(page.value().items.len(), 2);
    assert!(page.value().has_more);
    assert_eq!(page.value().items[0].id, 100000);
    assert!(core.state.lock().await.searches.is_empty());
}
