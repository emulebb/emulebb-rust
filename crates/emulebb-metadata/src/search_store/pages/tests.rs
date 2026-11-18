use super::*;
use crate::search_store::tests::{event, fields, name_vote, project, sample_search};
use crate::{MetadataSearchProjection, MetadataStore};

#[test]
fn stored_counts_track_claim_membership_without_counting_packets_or_overwriting_headers() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store.create_search(&sample_search()).unwrap();
    let second = store.create_search(&sample_search()).unwrap();
    let claim = project(&store, first, None, "sample.bin");
    project(&store, first, None, "sample.bin");
    project(&store, first, Some(0), "sample.bin");
    project(&store, first, Some(u64::MAX), "sample.bin");
    store
        .transition_search(first, &sample_search(), &[])
        .unwrap();
    assert_eq!(store.search_header(first).unwrap().unwrap().result_count, 3);
    store
        .connection()
        .unwrap()
        .execute(
            "DELETE FROM search_results WHERE session_id=?1 AND claim_id=?2",
            params![first, claim],
        )
        .unwrap();
    assert_eq!(store.search_header(first).unwrap().unwrap().result_count, 2);
    project(&store, second, None, "sample.bin");
    assert_eq!(
        store.search_header(second).unwrap().unwrap().result_count,
        1
    );
    store
        .connection()
        .unwrap()
        .execute(
            "DELETE FROM search_results WHERE session_id=?1 AND claim_id=?2",
            params![second, claim],
        )
        .unwrap();
    assert_eq!(
        store.search_header(second).unwrap().unwrap().result_count,
        0
    );
    store.delete_search(first).unwrap();
    assert!(store.search_header(first).unwrap().is_none());
    assert_eq!(store.table_count("content_claims").unwrap(), 3);
    store.clear_searches().unwrap();
    assert!(
        store
            .search_headers_page(None, 200)
            .unwrap()
            .items
            .is_empty()
    );
}

#[test]
fn pages_preserve_full_width_keys_and_unknown_zero_and_unsigned_claim_sizes() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store.create_search(&sample_search()).unwrap();
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE sqlite_sequence SET seq=9007199254740992 WHERE name='search_sessions'",
            [],
        )
        .unwrap();
    let last = store.create_search(&sample_search()).unwrap();
    assert_eq!(last, 9_007_199_254_740_993);
    let page = store.search_headers_page(None, 1).unwrap();
    assert_eq!(page.items[0].id, last);
    assert!(page.has_more);
    store.delete_search(last).unwrap();
    let page = store.search_headers_page(Some(last), 1).unwrap();
    assert_eq!(page.items[0].id, first);
    assert!(!page.has_more);
    for size in [None, Some(0), Some(u64::MAX)] {
        project(&store, first, size, "sample.bin");
    }
    let page = store
        .search_result_headers_page(first, 0, 2)
        .unwrap()
        .unwrap();
    assert_eq!(
        page.items.iter().map(|v| v.size_bytes).collect::<Vec<_>>(),
        [None, Some(0)]
    );
    assert!(page.has_more);
    let after = page.items.last().unwrap().claim_id;
    let page = store
        .search_result_headers_page(first, after, 2)
        .unwrap()
        .unwrap();
    assert_eq!(page.items[0].size_bytes, Some(u64::MAX));
    assert!(!page.has_more);
    assert!(
        store
            .search_result_headers_page(last, 0, 2)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .search_result_header(last, page.items[0].claim_id)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .search_result_headers_page(first, i64::MAX, 2)
            .unwrap()
            .unwrap()
            .items
            .is_empty()
    );
}

#[test]
fn provenance_pages_keep_session_accounting_distinct_from_global_occurrences() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store.create_search(&sample_search()).unwrap();
    let second = store.create_search(&sample_search()).unwrap();
    let claim = project(&store, first, Some(12), "sample.bin");
    project(&store, first, Some(12), "sample.bin");
    project(&store, second, Some(12), "sample.bin");
    project(&store, first, Some(12), "alternative.bin");
    let page = store
        .search_result_observations_page(first, claim, 0, 1)
        .unwrap()
        .unwrap();
    assert!(page.has_more);
    let item = &page.items[0];
    assert_eq!(item.observation_count, 2);
    assert_eq!(item.observation.receipt.observation_count, 3);
    let after = item.observation.receipt.observation_id;
    let page = store
        .search_result_observations_page(first, claim, after, 200)
        .unwrap()
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].observation_count, 1);
    assert!(!page.has_more);
    assert!(
        store
            .search_result_observations_page(first, claim + 1, 0, 1)
            .unwrap()
            .is_none()
    );
    store.delete_search(first).unwrap();
    assert!(
        store
            .search_result_observations_page(first, claim, 0, 1)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.search_header(second).unwrap().unwrap().result_count,
        1
    );
}

#[test]
fn byte_bounds_stop_before_materializing_the_next_large_row_and_allow_continuation() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let mut claim = 0;
    for index in 0..12 {
        let name = format!("{index:02}{}", "x".repeat(7500));
        claim = project(&store, id, Some(12), &name);
    }
    let page = store
        .search_result_observations_page(id, claim, 0, 200)
        .unwrap()
        .unwrap();
    assert!(!page.items.is_empty());
    assert!(page.items.len() < 12);
    assert!(page.has_more);
    let mut count = page.items.len();
    let mut after = page
        .items
        .last()
        .unwrap()
        .observation
        .receipt
        .observation_id;
    loop {
        let page = store
            .search_result_observations_page(id, claim, after, 200)
            .unwrap()
            .unwrap();
        count += page.items.len();
        if !page.has_more {
            break;
        }
        after = page
            .items
            .last()
            .unwrap()
            .observation
            .receipt
            .observation_id;
    }
    assert_eq!(count, 12);
    let mut large = sample_search();
    large.spec.query = "x".repeat(3000);
    large.normalized_query.clone_from(&large.spec.query);
    for _ in 0..12 {
        store.create_search(&large).unwrap();
    }
    let page = store.search_headers_page(None, 200).unwrap();
    assert!(page.has_more && !page.items.is_empty() && page.items.len() < 12);
    assert!(store.search_headers_page(None, 0).is_err());
    assert!(store.search_headers_page(Some(0), 1).is_err());
    assert!(store.search_result_headers_page(id, 0, 201).is_err());
}

#[test]
fn count_trigger_failure_rolls_back_corpus_and_membership_atomically() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE search_sessions SET result_count=9223372036854775807 WHERE id=?1",
            [id],
        )
        .unwrap();
    assert!(
        store
            .ingest_search_observations(
                &[event(Some(12), "sample.bin")],
                &MetadataSearchProjection {
                    session_id: id,
                    fields: vec![fields()],
                    name_votes: vec![name_vote("sample.bin")]
                }
            )
            .is_err()
    );
    assert_eq!(store.table_count("content_claims").unwrap(), 0);
    assert_eq!(store.table_count("search_results").unwrap(), 0);
}

#[test]
fn late_pages_seek_indexes_with_one_hundred_thousand_sessions_results_and_variants() {
    let store = MetadataStore::in_memory().unwrap();
    store.connection().unwrap().execute_batch("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100000)
        INSERT INTO search_sessions(id,query,normalized_query,requested_method,status,created_at_s,updated_at_s)
        SELECT i,'sample','sample','server','completed',1,1 FROM n;
        WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100000)
        INSERT INTO content_claims(id,ed2k_hash,size_bytes,first_seen_at_s,last_seen_at_s)
        SELECT i,zeroblob(16),CAST(printf('%08d',i) AS BLOB),1,1 FROM n;
        INSERT INTO search_results(session_id,claim_id,size_sort_key,ed2k_hash,name,ed2k_source_count,ed2k_complete_source_count,source_client_id,source_client_port,
            file_type,media_artist,media_album,media_title,media_length_seconds,media_bitrate_kbps,media_codec,rating,aich_root,complete,directory)
        SELECT 100000,id,size_sort_key,ed2k_hash,'sample.bin',1,0,NULL,NULL,'pro','','','',0,0,'',0,NULL,0,'' FROM content_claims;
        WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100000)
        INSERT INTO content_claim_observations(id,claim_id,fingerprint,origin,first_seen_at_s,last_seen_at_s,observation_count,name)
        SELECT i,1,CAST(printf('%032d',i) AS BLOB),'server',1,1,1,'sample.bin' FROM n;
        INSERT INTO search_result_observations(session_id,claim_id,observation_id,first_seen_at_s,last_seen_at_s,observation_count)
        SELECT 100000,1,id,1,1,1 FROM content_claim_observations;").unwrap();
    assert_eq!(
        store.search_header(100000).unwrap().unwrap().result_count,
        100000
    );
    assert_eq!(
        store
            .search_headers_page(Some(10), 5)
            .unwrap()
            .items
            .iter()
            .map(|v| v.id)
            .collect::<Vec<_>>(),
        [9, 8, 7, 6, 5]
    );
    assert_eq!(
        store
            .search_result_headers_page(100000, 99990, 5)
            .unwrap()
            .unwrap()
            .items
            .iter()
            .map(|v| v.claim_id)
            .collect::<Vec<_>>(),
        [99991, 99992, 99993, 99994, 99995]
    );
    assert_eq!(
        store
            .search_result_observations_page(100000, 1, 99990, 5)
            .unwrap()
            .unwrap()
            .items
            .len(),
        5
    );
    let conn = store.connection().unwrap();
    for (sql, parameters) in [
        (header_sql(true), vec![9, 6]),
        (result_sql(true), vec![100000, 99990, 6]),
        (observation_sql(), vec![100000, 1, 99990, 6]),
    ] {
        let mut statement = conn.prepare(&sql).unwrap();
        let ids = statement
            .query_map(rusqlite::params_from_iter(parameters), |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(ids.len(), 6);
        assert_eq!(
            statement.get_status(rusqlite::StatementStatus::FullscanStep),
            0,
            "{sql}"
        );
        assert_eq!(
            statement.get_status(rusqlite::StatementStatus::Sort),
            0,
            "{sql}"
        );
        assert!(
            statement.get_status(rusqlite::StatementStatus::VmStep) < 1000,
            "{sql}"
        );
    }
    let mut delete = conn
        .prepare("DELETE FROM search_sessions WHERE id=1")
        .unwrap();
    assert_eq!(delete.execute([]).unwrap(), 1);
    assert_eq!(
        delete.get_status(rusqlite::StatementStatus::FullscanStep),
        0
    );
    assert!(delete.get_status(rusqlite::StatementStatus::VmStep) < 1000);
}

#[test]
fn result_summary_can_combine_independently_bounded_packet_fields() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let long = "x".repeat(5000);
    let mut claim = 0;
    for index in 0..7 {
        let mut aggregate = fields();
        aggregate.file_type.clear();
        aggregate.aich_hash.clear();
        let mut packet = event(Some(12), &long);
        match index {
            0 => {
                packet.metadata.name = Some(long.clone());
            }
            1 => {
                packet.metadata.file_type = Some(long.clone());
                aggregate.file_type.clone_from(&long);
            }
            2 => {
                packet.metadata.media_artist = Some(long.clone());
                aggregate.media_artist.clone_from(&long);
            }
            3 => {
                packet.metadata.media_album = Some(long.clone());
                aggregate.media_album.clone_from(&long);
            }
            4 => {
                packet.metadata.media_title = Some(long.clone());
                aggregate.media_title.clone_from(&long);
            }
            5 => {
                packet.metadata.media_codec = Some(long.clone());
                aggregate.media_codec.clone_from(&long);
            }
            _ => {
                packet.metadata.directory = Some(long.clone());
                aggregate.directory.clone_from(&long);
            }
        }
        claim = store
            .ingest_search_observations(
                &[packet],
                &MetadataSearchProjection {
                    session_id: id,
                    fields: vec![aggregate.clone()],
                    name_votes: vec![name_vote(&long)],
                },
            )
            .unwrap()
            .unwrap()
            .claim_id;
    }
    let page = store
        .search_result_headers_page(id, 0, 100)
        .unwrap()
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert!(!page.has_more);
    let stored = store
        .search_result_header(id, claim)
        .unwrap()
        .unwrap()
        .summary;
    assert_eq!(page.items[0].summary, stored);
    for text in [
        &stored.name,
        &stored.file_type,
        &stored.media_artist,
        &stored.media_album,
        &stored.media_title,
        &stored.media_codec,
        &stored.directory,
    ] {
        assert_eq!(text, &long);
    }
    let seed = store.search_download_seed(id, claim).unwrap().unwrap();
    assert_eq!(seed.name, long);
    assert_eq!(seed.size_bytes, Some(12));
    assert!(!seed.observations.is_empty());
    assert!(seed.observations.len() < 7);
}
