use super::*;

#[test]
fn search_storage_has_binary_roots_and_ordered_unsigned_filter_bounds() {
    let store = super::super::MetadataStore::in_memory().unwrap();
    let mut search = sample_search();
    search.spec.min_size_bytes = Some(255);
    search.spec.max_size_bytes = Some(256);
    let id = store.create_search(&search).unwrap();
    let conn = store.connection().unwrap();
    let (size, valid): (i64, bool) = conn.query_row(
        "SELECT (SELECT length(aich_root) FROM search_results), min_size_bytes < max_size_bytes FROM search_sessions",
        [], |r| Ok((r.get(0)?, r.get(1)?)),
    ).unwrap();
    assert_eq!(size, 20);
    assert!(valid);
    drop(conn);
    search.spec.min_size_bytes = Some(257);
    assert!(store.update_search(id, &search).is_err());
    search.spec.min_size_bytes = Some(255);
    search.results[0].aich_hash = "invalid-root".into();
    assert!(store.update_search(id, &search).is_err());
    assert_eq!(
        store.load_searches().unwrap()[0].data.spec.min_size_bytes,
        Some(255)
    );
}

#[test]
fn search_snapshots_preserve_result_and_observation_identity() {
    let store = super::super::MetadataStore::in_memory().unwrap();
    let mut search = sample_search();
    let id = store.create_search(&search).unwrap();
    let ids = || {
        store.connection().unwrap().query_row(
        "SELECT r.id, o.id FROM search_results r JOIN search_result_observations o ON o.result_id=r.id",
        [], |r| Ok((r.get::<_,i64>(0)?, r.get::<_,i64>(1)?)),
    ).unwrap()
    };
    let original = ids();
    store.connection().unwrap().execute_batch(
        "CREATE TEMP TRIGGER reject_result_delete BEFORE DELETE ON main.search_results BEGIN SELECT RAISE(ABORT,'result identity lost'); END;
         CREATE TEMP TRIGGER reject_observation_delete BEFORE DELETE ON main.search_result_observations BEGIN SELECT RAISE(ABORT,'observation identity lost'); END;"
    ).unwrap();
    store.update_search(id, &search).unwrap();
    search.results[0].source_count += 1;
    let mut next = search.results[0].observations[0].clone();
    next.observed_at_ms += 1;
    search.results[0].observations.push(next);
    store.update_search(id, &search).unwrap();
    assert_eq!(ids(), original);
    assert_eq!(store.table_count("search_result_observations").unwrap(), 2);
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_result_delete; DROP TRIGGER reject_observation_delete;")
        .unwrap();
    search.results.clear();
    store.update_search(id, &search).unwrap();
    assert_eq!(store.table_count("search_results").unwrap(), 0);
    assert_eq!(store.table_count("search_result_observations").unwrap(), 0);
}

#[test]
fn search_state_roundtrips_unicode_results() {
    let store = super::super::MetadataStore::in_memory().unwrap();
    let search = sample_search();

    let id = store.create_search(&search).unwrap();

    let searches = store.load_searches().unwrap();
    assert_eq!(searches.len(), 1);
    assert_eq!(searches[0].id, id);
    let data = &searches[0].data;
    assert_eq!(data.spec.method, "automatic");
    assert_eq!(data.resolved_method.as_deref(), Some("global"));
    assert_eq!(data.spec.min_size_bytes, Some(u64::MAX - 1));
    assert_eq!(data.spec.max_size_bytes, Some(u64::MAX));
    assert_eq!(data.spec.min_availability, Some(17));
    assert_eq!(data.spec.artist, "Example Artist");
    assert_eq!(
        data.status_reason.as_deref(),
        Some("synthetic-status-reason")
    );
    assert_eq!(data.results.len(), 1);
    assert_eq!(data.results[0].name, "Zażółć Sample.bin");
    assert_eq!(
        data.results[0].observations[0].source_client_id,
        Some(u32::from_le_bytes([10, 20, 30, 40]))
    );
    assert_eq!(
        data.results[0].observations[0].source_client_port,
        Some(4662)
    );
    assert_eq!(data.results[0].rating, 4);
    assert_eq!(data.results[0].aich_hash, "A".repeat(32));
    assert_eq!(data.results[0].media_artist, "Example Artist");
    assert_eq!(data.results[0].media_length_seconds, 321);
    assert_eq!(data.results[0].media_bitrate_kbps, 192);
    assert_eq!(data.results[0].media_codec, "AV1");
    assert_eq!(data.results[0].observations[0].origin, "server");
    assert_eq!(
        data.results[0].observations[0].reporter_endpoint.as_deref(),
        Some("192.0.2.10:4661")
    );
    assert_eq!(data.results[0].observations[0].media_album, "Example Album");
}

#[test]
fn delete_and_clear_searches_remove_results() {
    let store = super::super::MetadataStore::in_memory().unwrap();
    let first = store.create_search(&sample_search()).unwrap();
    store.create_search(&sample_search()).unwrap();

    assert!(store.delete_search(first).unwrap());
    assert_eq!(store.load_searches().unwrap().len(), 1);
    assert!(!store.delete_search(i64::MAX).unwrap());

    store.clear_searches().unwrap();
    assert!(store.load_searches().unwrap().is_empty());
    assert_eq!(store.table_count("search_results").unwrap(), 0);
}

#[test]
fn deleted_and_cleared_session_ids_are_not_reused_after_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("metadata.sqlite");
    let store = super::super::MetadataStore::open(&path).unwrap();
    let first = store.create_search(&sample_search()).unwrap();
    assert!(store.delete_search(first).unwrap());
    assert!(store.update_search(first, &sample_search()).is_err());
    drop(store);
    let store = super::super::MetadataStore::open(&path).unwrap();
    let second = store.create_search(&sample_search()).unwrap();
    assert!(second > first);
    store.clear_searches().unwrap();
    drop(store);
    let store = super::super::MetadataStore::open(path).unwrap();
    let third = store.create_search(&sample_search()).unwrap();
    assert!(third > second);
    assert!(store.update_search(second, &sample_search()).is_err());
    assert_eq!(store.load_searches().unwrap()[0].id, third);
}

#[test]
fn session_ids_use_full_positive_i64_space_and_fail_at_exhaustion() {
    for previous in [u32::MAX as i64, 9_007_199_254_740_992, i64::MAX - 1] {
        let store = super::super::MetadataStore::in_memory().unwrap();
        let first = store.create_search(&sample_search()).unwrap();
        store.delete_search(first).unwrap();
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE sqlite_sequence SET seq=?1 WHERE name='search_sessions'",
                [previous],
            )
            .unwrap();
        let id = store.create_search(&sample_search()).unwrap();
        assert_eq!(id, previous + 1);
        assert_eq!(store.load_searches().unwrap()[0].id, id);
        store.update_search(id, &sample_search()).unwrap();
        if id == i64::MAX {
            assert!(store.create_search(&sample_search()).is_err());
            assert_eq!(store.load_searches().unwrap().len(), 1);
        }
    }
}

#[test]
fn failed_initial_payload_does_not_publish_a_session_or_consume_its_id() {
    let store = super::super::MetadataStore::in_memory().unwrap();
    let mut invalid = sample_search();
    invalid.results[0].aich_hash = "invalid".into();
    assert!(store.create_search(&invalid).is_err());
    assert_eq!(store.table_count("search_sessions").unwrap(), 0);
    assert_eq!(store.table_count("search_results").unwrap(), 0);
    assert_eq!(store.create_search(&sample_search()).unwrap(), 1);
}

#[test]
fn independent_connections_allocate_distinct_session_ids() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("metadata.sqlite");
    let first = super::super::MetadataStore::open(&path).unwrap();
    let second = super::super::MetadataStore::open(path).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let other_barrier = barrier.clone();
    let worker = std::thread::spawn(move || {
        other_barrier.wait();
        second.create_search(&sample_search()).unwrap()
    });
    barrier.wait();
    let a = first.create_search(&sample_search()).unwrap();
    let b = worker.join().unwrap();
    assert_ne!(a, b);
    assert_eq!(first.load_searches().unwrap().len(), 2);
}

fn sample_search() -> MetadataSearchData {
    MetadataSearchData {
        normalized_query: normalized_search_query("zażółć"),
        spec: MetadataSearchSpec {
            query: "zażółć".to_string(),
            method: "automatic".to_string(),
            file_type: "video".to_string(),
            extension: "mkv".to_string(),
            min_size_bytes: Some(u64::MAX - 1),
            max_size_bytes: Some(u64::MAX),
            min_availability: Some(17),
            min_complete_sources: Some(5),
            min_bitrate_kbps: Some(320),
            min_length_seconds: Some(90),
            codec: "av1".to_string(),
            title: "Example Title".to_string(),
            album: "Example Album".to_string(),
            artist: "Example Artist".to_string(),
        },
        resolved_method: Some("global".to_string()),
        status: "error".to_string(),
        status_reason: Some("synthetic-status-reason".to_string()),
        created_at_ms: 1,
        updated_at_ms: 2,
        completed_at_ms: None,
        results: vec![MetadataSearchResult {
            file_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Zażółć Sample.bin".to_string(),
            size_bytes: 123,
            source_count: 4,
            complete_source_count: 3,
            file_type: "video".to_string(),
            media_artist: "Example Artist".to_string(),
            media_album: "Example Album".to_string(),
            media_title: "Example Title".to_string(),
            media_length_seconds: 321,
            media_bitrate_kbps: 192,
            media_codec: "AV1".to_string(),
            rating: 4,
            aich_hash: "A".repeat(32),
            complete: false,
            directory: String::new(),
            observations: vec![MetadataSearchResultObservation {
                origin: "server".to_string(),
                reporter_endpoint: Some("192.0.2.10:4661".to_string()),
                name: "Zażółć Sample.bin".to_string(),
                size_bytes: 123,
                source_count: 4,
                complete_source_count: 3,
                source_client_id: Some(u32::from_le_bytes([10, 20, 30, 40])),
                source_client_port: Some(4662),
                file_type: "video".to_string(),
                media_artist: "Example Artist".to_string(),
                media_album: "Example Album".to_string(),
                media_title: "Example Title".to_string(),
                media_length_seconds: 321,
                media_bitrate_kbps: 192,
                media_codec: "AV1".to_string(),
                rating: 4,
                aich_hash: "A".repeat(32),
                complete: false,
                directory: String::new(),
                observed_at_ms: 2,
            }],
        }],
    }
}
