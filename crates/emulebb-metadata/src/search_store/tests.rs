use super::*;

#[test]
fn search_storage_has_binary_roots_and_ordered_unsigned_filter_bounds() {
    let store = super::super::MetadataStore::in_memory().unwrap();
    let mut search = sample_search("typed-search");
    search.spec.min_size_bytes = Some(255);
    search.spec.max_size_bytes = Some(256);
    store.upsert_search(&search).unwrap();
    let conn = store.connection().unwrap();
    let (size, valid): (i64, bool) = conn.query_row(
        "SELECT (SELECT length(aich_root) FROM search_results), min_size_bytes < max_size_bytes FROM search_sessions",
        [], |r| Ok((r.get(0)?, r.get(1)?)),
    ).unwrap();
    assert_eq!(size, 20);
    assert!(valid);
    drop(conn);
    search.spec.min_size_bytes = Some(257);
    assert!(store.upsert_search(&search).is_err());
    search.spec.min_size_bytes = Some(255);
    search.results[0].aich_hash = "invalid-root".into();
    assert!(store.upsert_search(&search).is_err());
    assert_eq!(
        store.load_searches().unwrap()[0].spec.min_size_bytes,
        Some(255)
    );
}

#[test]
fn search_snapshots_preserve_result_and_observation_identity() {
    let store = super::super::MetadataStore::in_memory().unwrap();
    let mut search = sample_search("incremental");
    store.upsert_search(&search).unwrap();
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
    store.upsert_search(&search).unwrap();
    search.results[0].source_count += 1;
    let mut next = search.results[0].observations[0].clone();
    next.observed_at_ms += 1;
    search.results[0].observations.push(next);
    store.upsert_search(&search).unwrap();
    assert_eq!(ids(), original);
    assert_eq!(store.table_count("search_result_observations").unwrap(), 2);
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_result_delete; DROP TRIGGER reject_observation_delete;")
        .unwrap();
    search.results.clear();
    store.upsert_search(&search).unwrap();
    assert_eq!(store.table_count("search_results").unwrap(), 0);
    assert_eq!(store.table_count("search_result_observations").unwrap(), 0);
}

#[test]
fn search_state_roundtrips_unicode_results() {
    let store = super::super::MetadataStore::in_memory().unwrap();
    let search = sample_search("search-one");

    store.upsert_search(&search).unwrap();

    let searches = store.load_searches().unwrap();
    assert_eq!(searches.len(), 1);
    assert_eq!(searches[0].public_id, "search-one");
    assert_eq!(searches[0].spec.method, "automatic");
    assert_eq!(searches[0].resolved_method.as_deref(), Some("global"));
    assert_eq!(searches[0].spec.min_size_bytes, Some(u64::MAX - 1));
    assert_eq!(searches[0].spec.max_size_bytes, Some(u64::MAX));
    assert_eq!(searches[0].spec.min_availability, Some(17));
    assert_eq!(searches[0].spec.artist, "Example Artist");
    assert_eq!(
        searches[0].status_reason.as_deref(),
        Some("synthetic-status-reason")
    );
    assert_eq!(searches[0].results.len(), 1);
    assert_eq!(searches[0].results[0].name, "Zażółć Sample.bin");
    assert_eq!(
        searches[0].results[0].observations[0].source_client_id,
        Some(u32::from_le_bytes([10, 20, 30, 40]))
    );
    assert_eq!(
        searches[0].results[0].observations[0].source_client_port,
        Some(4662)
    );
    assert_eq!(searches[0].results[0].rating, 4);
    assert_eq!(searches[0].results[0].aich_hash, "A".repeat(32));
    assert_eq!(searches[0].results[0].media_artist, "Example Artist");
    assert_eq!(searches[0].results[0].media_length_seconds, 321);
    assert_eq!(searches[0].results[0].media_bitrate_kbps, 192);
    assert_eq!(searches[0].results[0].media_codec, "AV1");
    assert_eq!(searches[0].results[0].observations[0].origin, "server");
    assert_eq!(
        searches[0].results[0].observations[0]
            .server_endpoint
            .as_deref(),
        Some("192.0.2.10:4661")
    );
    assert_eq!(
        searches[0].results[0].observations[0].media_album,
        "Example Album"
    );
}

#[test]
fn delete_and_clear_searches_remove_results() {
    let store = super::super::MetadataStore::in_memory().unwrap();
    store.upsert_search(&sample_search("search-one")).unwrap();
    store.upsert_search(&sample_search("search-two")).unwrap();

    assert!(store.delete_search("search-one").unwrap());
    assert_eq!(store.load_searches().unwrap().len(), 1);
    assert!(!store.delete_search("missing").unwrap());

    store.clear_searches().unwrap();
    assert!(store.load_searches().unwrap().is_empty());
    assert_eq!(store.table_count("search_results").unwrap(), 0);
}

fn sample_search(public_id: &str) -> MetadataSearch {
    MetadataSearch {
        public_id: public_id.to_string(),
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
                server_endpoint: Some("192.0.2.10:4661".to_string()),
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
