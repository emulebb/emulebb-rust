use super::*;
use crate::{
    MetadataContentClaim, MetadataContentMetadata, MetadataContentObservationEvent,
    MetadataObservationOrigin, MetadataStore,
};

pub(super) fn sample_search() -> MetadataSearchData {
    MetadataSearchData {
        normalized_query: "sample query".into(),
        spec: MetadataSearchSpec {
            query: "sample query".into(),
            method: "kad".into(),
            file_type: String::new(),
            extension: String::new(),
            min_size_bytes: None,
            max_size_bytes: None,
            min_availability: None,
            min_complete_sources: None,
            min_bitrate_kbps: None,
            min_length_seconds: None,
            codec: String::new(),
            title: String::new(),
            album: String::new(),
            artist: String::new(),
        },
        resolved_method: Some("kad".into()),
        status: "running".into(),
        status_reason: None,
        created_at_s: 1,
        updated_at_s: 2,
        completed_at_s: None,
    }
}
pub(super) fn fields() -> crate::MetadataSearchResultFields {
    crate::MetadataSearchResultFields {
        quality: Default::default(),
        source_client_id: None,
        source_client_port: None,
        file_type: "Pro".into(),
        media_artist: String::new(),
        media_album: String::new(),
        media_title: String::new(),
        media_length_seconds: 0,
        media_bitrate_kbps: 0,
        media_codec: String::new(),
        rating: 0,
        aich_hash: data_encoding::BASE32_NOPAD.encode(&[0x12; 20]),
        complete: false,
        directory: String::new(),
    }
}
pub(super) fn name_vote(name: &str) -> crate::MetadataSearchNameVote {
    crate::MetadataSearchNameVote {
        normalized_name: name.into(),
        reporter_endpoint: Some("192.0.2.4:4672".parse().unwrap()),
        origin: MetadataObservationOrigin::Kad,
        quality: crate::MetadataSearchNameQuality {
            useful: true,
            sources: 3,
            complete_sources: 0,
            rating: 0,
        },
    }
}

pub(super) fn event(size: Option<u64>, name: &str) -> MetadataContentObservationEvent {
    MetadataContentObservationEvent {
        claim: MetadataContentClaim {
            hash: [0x42; 16],
            size_bytes: size,
        },
        origin: MetadataObservationOrigin::Kad,
        reporter_endpoint: Some("192.0.2.4:4672".parse().unwrap()),
        metadata: MetadataContentMetadata {
            name: Some(name.into()),
            source_count: Some(3),
            aich_root: Some([0x12; 20]),
            ..Default::default()
        },
        observed_at_s: 100,
    }
}
pub(super) fn project(store: &MetadataStore, id: i64, size: Option<u64>, name: &str) -> i64 {
    store
        .ingest_search_observations(
            &[event(size, name)],
            &MetadataSearchProjection {
                session_id: id,
                fields: vec![fields()],
                name_votes: vec![name_vote(name)],
            },
        )
        .unwrap()
        .unwrap()
        .claim_id
}

#[test]
fn session_results_reference_distinct_unknown_zero_conflicting_and_full_unsigned_claims() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let sizes = [None, Some(0), Some(1024), Some(u64::MAX)];
    let claims: Vec<_> = sizes
        .into_iter()
        .map(|size| project(&store, id, size, "Sample.bin"))
        .collect();
    let loaded = store.load_searches().unwrap();
    assert_eq!(loaded[0].results.len(), 4);
    for (index, result) in loaded[0].results.iter().enumerate() {
        assert_eq!(result.claim_id, claims[index]);
        assert_eq!(result.size_bytes, sizes[index]);
        assert_eq!(
            result.observations[0].observation.event.claim.size_bytes,
            sizes[index]
        );
    }
    assert_eq!(store.table_count("known_files").unwrap(), 0);
}

#[test]
fn header_writes_never_replay_results_and_membership_counts_are_session_local() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store.create_search(&sample_search()).unwrap();
    let second = store.create_search(&sample_search()).unwrap();
    let claim = project(&store, first, Some(12), "Sample.bin");
    store.update_search(first, &sample_search()).unwrap();
    assert_eq!(
        store.content_observations_page(claim, 0, 10).unwrap().items[0]
            .receipt
            .observation_count,
        1
    );
    assert_eq!(project(&store, first, Some(12), "Sample.bin"), claim);
    assert_eq!(project(&store, second, Some(12), "Sample.bin"), claim);
    let searches = store.load_searches().unwrap();
    assert_eq!(searches[0].results[0].observations[0].observation_count, 2);
    assert_eq!(searches[1].results[0].observations[0].observation_count, 1);
    assert_eq!(
        store.content_observations_page(claim, 0, 10).unwrap().items[0]
            .receipt
            .observation_count,
        3
    );
}

#[test]
fn terminal_or_missing_sessions_freeze_membership_but_keep_valid_corpus_events() {
    let store = MetadataStore::in_memory().unwrap();
    let mut header = sample_search();
    let id = store.create_search(&header).unwrap();
    let claim = project(&store, id, Some(12), "First.bin");
    header.status = "completed".into();
    header.completed_at_s = Some(200);
    header.updated_at_s = 200;
    store.update_search(id, &header).unwrap();
    let projection = MetadataSearchProjection {
        session_id: id,
        fields: vec![fields()],
        name_votes: vec![name_vote("Later.bin")],
    };
    assert!(
        store
            .ingest_search_observations(&[event(Some(12), "Later.bin")], &projection)
            .unwrap()
            .is_none()
    );
    let result = &store.load_searches().unwrap()[0].results[0];
    assert_eq!(result.summary.name, "First.bin");
    assert_eq!(result.observations.len(), 1);
    assert_eq!(
        store
            .content_observations_page(claim, 0, 10)
            .unwrap()
            .items
            .len(),
        2
    );
    store.delete_search(id).unwrap();
    assert!(
        store
            .ingest_search_observations(&[event(Some(12), "Later.bin")], &projection)
            .unwrap()
            .is_none()
    );
    assert_eq!(store.table_count("search_results").unwrap(), 0);
    assert_eq!(store.table_count("search_result_observations").unwrap(), 0);
    assert_eq!(
        store.content_observations_page(claim, 0, 10).unwrap().items[1]
            .receipt
            .observation_count,
        2
    );
}

#[test]
fn membership_failure_rolls_back_corpus_and_projection_together() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    store
        .connection()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_membership BEFORE INSERT ON search_result_observations
         BEGIN SELECT RAISE(ABORT,'injected membership failure'); END;",
        )
        .unwrap();
    assert!(
        store
            .ingest_search_observations(
                &[event(None, "Sample.bin")],
                &MetadataSearchProjection {
                    session_id: id,
                    fields: vec![fields()],
                    name_votes: vec![name_vote("Sample.bin")]
                }
            )
            .is_err()
    );
    for table in [
        "content_claims",
        "content_claim_observations",
        "search_results",
        "search_result_observations",
    ] {
        assert_eq!(store.table_count(table).unwrap(), 0);
    }
}

#[test]
fn observations_cannot_be_attached_to_another_claim() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let first = project(&store, id, Some(12), "First.bin");
    let second = project(&store, id, Some(13), "Second.bin");
    let observation = store.content_observations_page(first, 0, 1).unwrap().items[0]
        .receipt
        .observation_id;
    assert!(
        store
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO search_result_observations VALUES(?1,?2,?3,100,100,1)",
                params![id, second, observation]
            )
            .is_err()
    );
}

#[test]
fn unicode_and_binary_roots_roundtrip_and_filter_sizes_keep_unsigned_order() {
    let store = MetadataStore::in_memory().unwrap();
    let mut header = sample_search();
    header.spec.min_size_bytes = Some(255);
    header.spec.max_size_bytes = Some(256);
    let id = store.create_search(&header).unwrap();
    project(&store, id, Some(256), "样本 Δ Sample.bin");
    let loaded = store.load_searches().unwrap();
    assert_eq!(loaded[0].results[0].summary.name, "样本 Δ Sample.bin");
    assert_eq!(
        loaded[0].results[0].observations[0]
            .observation
            .event
            .metadata
            .aich_root,
        Some([0x12; 20])
    );
    assert!(
        store
            .connection()
            .unwrap()
            .query_row(
                "SELECT min_size_bytes<max_size_bytes FROM search_sessions",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    header.spec.min_size_bytes = Some(257);
    assert!(store.update_search(id, &header).is_err());
    assert_eq!(
        store.load_searches().unwrap()[0].data.spec.min_size_bytes,
        Some(255)
    );
    store.clear_searches().unwrap();
    assert_eq!(store.table_count("search_result_observations").unwrap(), 0);
    assert_eq!(store.table_count("content_claim_observations").unwrap(), 1);
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
    invalid.spec.min_size_bytes = Some(200);
    invalid.spec.max_size_bytes = Some(100);
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

#[test]
fn startup_interruption_is_durable_atomic_idempotent_and_preserves_terminal_history() {
    let store = MetadataStore::in_memory().unwrap();
    let running = store.create_search(&sample_search()).unwrap();
    let mut queued_header = sample_search();
    queued_header.status = "queued".into();
    let queued = store.create_search(&queued_header).unwrap();
    let mut completed = sample_search();
    completed.status = "completed".into();
    completed.completed_at_s = Some(3);
    let terminal = store.create_search(&completed).unwrap();
    let claim = project(&store, running, Some(12), "Sample.bin");
    store.connection().unwrap().execute_batch("CREATE TRIGGER fail_interruption BEFORE UPDATE OF status ON search_sessions WHEN old.status='running' BEGIN SELECT RAISE(ABORT,'injected interruption failure'); END;").unwrap();
    assert!(store.interrupt_collecting_searches(200).is_err());
    assert_eq!(
        store.search_header(queued).unwrap().unwrap().data.status,
        "queued"
    );
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_interruption")
        .unwrap();
    assert_eq!(store.interrupt_collecting_searches(200).unwrap(), 2);
    assert_eq!(store.interrupt_collecting_searches(300).unwrap(), 0);
    for id in [running, queued] {
        let header = store.search_header(id).unwrap().unwrap();
        assert_eq!(header.data.status, "error");
        assert_eq!(
            header.data.status_reason.as_deref(),
            Some("interrupted-by-restart")
        );
        assert_eq!(header.data.updated_at_s, 200);
    }
    assert_eq!(
        store.search_header(terminal).unwrap().unwrap().data,
        completed
    );
    assert!(
        store
            .search_result_header(running, claim)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store
            .search_result_observations_page(running, claim, 0, 1)
            .unwrap()
            .unwrap()
            .items
            .len(),
        1
    );
}

#[test]
fn startup_interruption_seeks_collecting_index_among_one_hundred_thousand_terminal_sessions() {
    let store = MetadataStore::in_memory().unwrap();
    let mut completed = sample_search();
    completed.status = "completed".into();
    completed.completed_at_s = Some(3);
    let terminal = store.create_search(&completed).unwrap();
    let conn = store.connection().unwrap();
    let columns = conn
        .prepare(
            "SELECT name FROM pragma_table_info('search_sessions') WHERE name!='id' ORDER BY cid",
        )
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let names = columns.join(",");
    let selected = columns
        .iter()
        .map(|name| format!("s.{name}"))
        .collect::<Vec<_>>()
        .join(",");
    conn.execute(&format!("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100000)
        INSERT INTO search_sessions({names}) SELECT {selected} FROM search_sessions s CROSS JOIN n WHERE s.id=?1"),[terminal]).unwrap();
    drop(conn);
    let collecting = store.create_search(&sample_search()).unwrap();
    let conn = store.connection().unwrap();
    let mut statement = conn.prepare(INTERRUPT_COLLECTING_SQL).unwrap();
    assert_eq!(statement.execute([100]).unwrap(), 1);
    assert_eq!(
        statement.get_status(rusqlite::StatementStatus::FullscanStep),
        0
    );
    assert_eq!(statement.get_status(rusqlite::StatementStatus::Sort), 0);
    assert!(statement.get_status(rusqlite::StatementStatus::VmStep) < 1000);
    drop(statement);
    drop(conn);
    assert_eq!(
        store
            .search_header(collecting)
            .unwrap()
            .unwrap()
            .data
            .status,
        "error"
    );
}
