use super::*;

fn seed(store: &mut MetadataStore, byte: u8) -> String {
    let hash = hex::encode([byte; 16]);
    store
        .upsert_indexed_file(
            &crate::MetadataIndexedFile {
                ed2k_hash: hash.clone(),
                name: "Sample.bin".into(),
                size_bytes: 32,
                content_type: String::new(),
                availability_score: 0,
            },
            crate::MetadataIndexedFileOrigin::LocalShare,
        )
        .unwrap();
    hash
}

fn delta(hash: &str, bytes: u64, requests: u64, accepted: u64) -> MetadataFileUploadDelta {
    MetadataFileUploadDelta {
        file_hash: hash.into(),
        uploaded_bytes: bytes,
        upload_requests: requests,
        accepted_sessions: accepted,
        last_requested_at_s: (requests > 0).then_some(0),
        last_uploaded_at_s: (bytes > 0).then_some(0),
    }
}

fn capture(delta: &MetadataFileUploadDelta) -> MetadataFileUploadCapture {
    MetadataFileUploadCapture {
        file_hash: hex::decode(&delta.file_hash).unwrap().try_into().unwrap(),
        session_uploaded_bytes: delta.uploaded_bytes,
        session_upload_requests: delta.upload_requests,
        session_accepted_uploads: delta.accepted_sessions,
        pending: MetadataFileUploadTotals {
            uploaded_bytes: delta.uploaded_bytes,
            upload_requests: delta.upload_requests,
            accepted_sessions: delta.accepted_sessions,
            last_requested_at_s: delta.last_requested_at_s,
            last_uploaded_at_s: delta.last_uploaded_at_s,
        },
    }
}

#[test]
fn session_projection_is_shared_by_clones_and_starts_empty_on_another_connection() {
    let database = format!(
        "file:upload-statistics-{}?mode=memory&cache=shared",
        uuid::Uuid::new_v4()
    );
    let open = || {
        Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .unwrap()
    };
    let mut store = MetadataStore::from_connection(open()).unwrap();
    let hash = seed(&mut store, 0x11);
    store.add_file_all_time_uploaded(&hash, 50).unwrap();
    let mut publication = capture(&delta(&hash, 12, 3, 1));
    store
        .clone()
        .publish_file_upload_captures(&[publication])
        .unwrap();
    assert_eq!(
        store
            .file_upload_snapshot(&hash)
            .unwrap()
            .unwrap()
            .totals
            .uploaded_bytes,
        50,
        "publication must not checkpoint pending counters"
    );
    let before_checkpoint = store.file_upload_statistics(&hash).unwrap();
    store
        .apply_credit_deltas(&[], &[delta(&hash, 7, 2, 1)])
        .unwrap();
    store
        .clone()
        .apply_credit_deltas(&[], &[delta(&hash, 5, 1, 0)])
        .unwrap();
    let stats = store.file_upload_statistics(&hash).unwrap().unwrap();
    assert_eq!(Some(stats), before_checkpoint);
    publication.pending = MetadataFileUploadTotals::default();
    store.publish_file_upload_captures(&[publication]).unwrap();
    assert_eq!(store.file_upload_statistics(&hash).unwrap(), Some(stats));
    assert_eq!(stats.session_uploaded_bytes, 12);
    assert_eq!(stats.session_upload_requests, 3);
    assert_eq!(stats.session_accepted_uploads, 1);
    assert_eq!(stats.lifetime.uploaded_bytes, 62);
    assert_eq!(stats.lifetime.upload_requests, 3);
    assert_eq!(stats.lifetime.accepted_sessions, 1);
    assert_eq!(stats.lifetime.last_requested_at_s, Some(0));
    assert_eq!(stats.lifetime.last_uploaded_at_s, Some(0));

    let reopened = MetadataStore::from_connection(open()).unwrap();
    let fresh = reopened.file_upload_statistics(&hash).unwrap().unwrap();
    assert_eq!(fresh.session_uploaded_bytes, 0);
    assert_eq!(fresh.session_upload_requests, 0);
    assert_eq!(fresh.session_accepted_uploads, 0);
    assert_eq!(fresh.lifetime, stats.lifetime);
    assert_eq!(store.file_upload_statistics(&hash).unwrap(), Some(stats));
    assert_eq!(
        reopened
            .connection()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM temp.session_file_upload_statistics",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1,
        "the indexed population includes zero-activity client hashes"
    );
}

#[test]
fn publication_failure_rolls_back_the_batch_without_checkpointing_then_retries_once() {
    let mut store = MetadataStore::in_memory().unwrap();
    let first = seed(&mut store, 0x11);
    let second = seed(&mut store, 0x22);
    let before = store.file_upload_statistics(&first).unwrap();
    let peer = "33".repeat(16);
    let deltas = [delta(&first, 5, 1, 1), delta(&second, 7, 2, 1)];
    let captures = deltas.each_ref().map(capture);
    store
        .connection()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_statistics BEFORE INSERT ON session_file_upload_statistics
         WHEN new.ed2k_hash=x'22222222222222222222222222222222'
         BEGIN SELECT RAISE(ABORT,'injected statistics failure'); END;",
        )
        .unwrap();
    assert!(store.publish_file_upload_captures(&captures).is_err());
    assert_eq!(store.file_upload_statistics(&first).unwrap(), before);
    assert_eq!(
        store.file_upload_statistics(&second).unwrap().unwrap(),
        MetadataFileUploadStatistics::default()
    );
    assert!(store.peer_credit_by_hash(&peer).unwrap().is_none());
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM temp.session_file_upload_statistics",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );

    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_statistics")
        .unwrap();
    store.publish_file_upload_captures(&captures).unwrap();
    let first = store.file_upload_statistics(&first).unwrap().unwrap();
    let second = store.file_upload_statistics(&second).unwrap().unwrap();
    assert_eq!(
        (first.session_uploaded_bytes, first.lifetime.uploaded_bytes),
        (5, 5)
    );
    assert_eq!(
        (
            second.session_uploaded_bytes,
            second.lifetime.uploaded_bytes
        ),
        (7, 7)
    );
    assert_eq!(first.session_upload_requests, 1);
    assert_eq!(second.session_upload_requests, 2);
    assert!(store.peer_credit_by_hash(&peer).unwrap().is_none());
    store
        .apply_credit_deltas(&[(peer.clone(), 11, 13)], &deltas)
        .unwrap();
    let peer = store.peer_credit_by_hash(&peer).unwrap().unwrap();
    assert_eq!((peer.uploaded_bytes, peer.downloaded_bytes), (11, 13));
}

#[test]
fn session_statistic_indexes_support_bounded_scalar_seeks() {
    let mut store = MetadataStore::in_memory().unwrap();
    let first = seed(&mut store, 0x11);
    let second = seed(&mut store, 0x22);
    store
        .publish_file_upload_captures(&[
            capture(&delta(&first, 7, 2, 1)),
            capture(&delta(&second, 3, 1, 2)),
        ])
        .unwrap();
    let conn = store.connection().unwrap();
    for (field, index, expected) in [
        (
            "uploaded_bytes",
            "session_upload_bytes_idx",
            second.as_str(),
        ),
        (
            "upload_requests",
            "session_upload_requests_idx",
            second.as_str(),
        ),
        (
            "accepted_sessions",
            "session_upload_accepts_idx",
            first.as_str(),
        ),
    ] {
        let sql = format!(
            "SELECT lower(hex(ed2k_hash)),{field} FROM temp.session_file_upload_statistics
            WHERE ({field},ed2k_hash)>(?1,?2) ORDER BY {field},ed2k_hash LIMIT 1"
        );
        let plan = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap()
            .query_map(params![0, Vec::<u8>::new()], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|row| row.contains("SEARCH") && row.contains(index)),
            "{plan:?}"
        );
        assert!(
            !plan.iter().any(|row| row.contains("TEMP B-TREE")),
            "{plan:?}"
        );
        let mut statement = conn.prepare(&sql).unwrap();
        let hash: String = statement
            .query_row(params![0, Vec::<u8>::new()], |row| row.get(0))
            .unwrap();
        assert_eq!(hash, expected);
        assert_eq!(statement.get_status(rusqlite::StatementStatus::Sort), 0);
        assert_eq!(
            statement.get_status(rusqlite::StatementStatus::FullscanStep),
            0
        );
    }
}

#[test]
fn unknown_hashes_and_zero_deltas_do_not_expand_the_library_population() {
    let mut store = MetadataStore::in_memory().unwrap();
    let hash = seed(&mut store, 0x11);
    let unknown = "22".repeat(16);
    store
        .apply_credit_deltas(&[], &[delta(&hash, 0, 0, 0), delta(&unknown, 7, 1, 1)])
        .unwrap();
    store
        .publish_file_upload_captures(&[capture(&delta(&unknown, 7, 1, 1))])
        .unwrap();
    assert_eq!(
        store.file_upload_statistics(&hash).unwrap().unwrap(),
        MetadataFileUploadStatistics::default()
    );
    assert!(store.file_upload_statistics(&unknown).unwrap().is_none());
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM temp.session_file_upload_statistics",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn every_statistic_orders_the_full_hundred_thousand_hash_population_without_sorting() {
    let store = MetadataStore::in_memory().unwrap();
    let key = |n: u128| n.to_be_bytes();
    {
        let mut conn = store.connection().unwrap();
        let tx = conn.transaction().unwrap();
        {
            let mut insert = tx.prepare("INSERT INTO known_files(ed2k_hash,display_name,first_seen_at_ms,last_seen_at_ms,updated_at_ms)
                VALUES(?1,'Sample.bin',0,0,0)").unwrap();
            for n in 0..100_000 {
                insert.execute([key(n).as_slice()]).unwrap();
            }
        }
        tx.execute("INSERT INTO library_files SELECT id FROM known_files", [])
            .unwrap();
        tx.commit().unwrap();
    }
    let active = MetadataFileUploadCapture {
        file_hash: key(99_999),
        session_uploaded_bytes: 7,
        session_upload_requests: 2,
        session_accepted_uploads: 1,
        pending: MetadataFileUploadTotals {
            uploaded_bytes: 7,
            upload_requests: 2,
            accepted_sessions: 1,
            last_requested_at_s: Some(0),
            last_uploaded_at_s: Some(0),
        },
    };
    store.publish_file_upload_captures(&[active]).unwrap();
    let conn = store.connection().unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM session_file_upload_statistics",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        100_000
    );
    for (field, index) in [
        ("uploaded_bytes", "session_upload_bytes_idx"),
        ("upload_requests", "session_upload_requests_idx"),
        ("accepted_sessions", "session_upload_accepts_idx"),
        ("lifetime_bytes", "lifetime_upload_bytes_idx"),
        ("lifetime_requests", "lifetime_upload_requests_idx"),
        ("lifetime_accepts", "lifetime_upload_accepts_idx"),
        ("last_requested_at_s", "last_upload_requested_idx"),
        ("last_uploaded_at_s", "last_uploaded_idx"),
    ] {
        for direction in ["ASC", "DESC"] {
            let sql = format!(
                "SELECT ed2k_hash,{field} FROM session_file_upload_statistics
                ORDER BY {field} {direction},ed2k_hash {direction} LIMIT 200"
            );
            let plan: Vec<String> = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map([], |r| r.get(3))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert!(
                plan.iter().any(|line| line.contains(index)),
                "{sql}: {plan:?}"
            );
            assert!(
                !plan.iter().any(|line| line.contains("TEMP B-TREE")),
                "{plan:?}"
            );
            let mut statement = conn.prepare(&sql).unwrap();
            let rows: Vec<(Vec<u8>, Option<i64>)> = statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert_eq!(rows.len(), 200);
            let expected = if direction == "ASC" {
                key(0)
            } else {
                key(99_999)
            };
            assert_eq!(rows[0].0, expected);
            assert_eq!(
                rows[0].1.is_none(),
                direction == "ASC" && field.ends_with("_s")
            );
            assert_eq!(statement.get_status(rusqlite::StatementStatus::Sort), 0);
            assert!(statement.get_status(rusqlite::StatementStatus::FullscanStep) <= 200);
        }
        let predicate = if field.ends_with("_s") {
            format!("{field} IS NULL AND ed2k_hash>?1")
        } else {
            format!("({field},ed2k_hash)>(0,?1)")
        };
        let sql = format!(
            "SELECT ed2k_hash FROM session_file_upload_statistics WHERE {predicate}
            ORDER BY {field},ed2k_hash LIMIT 200"
        );
        let mut statement = conn.prepare(&sql).unwrap();
        let rows: Vec<Vec<u8>> = statement
            .query_map([key(99_000).as_slice()], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(rows.len(), 200);
        assert_eq!(rows[0], key(99_001));
        assert_eq!(statement.get_status(rusqlite::StatementStatus::Sort), 0);
        assert_eq!(
            statement.get_status(rusqlite::StatementStatus::FullscanStep),
            0
        );
    }
    let before = conn.total_changes();
    drop(conn);
    store.publish_file_upload_captures(&[active]).unwrap();
    assert_eq!(
        store.connection().unwrap().total_changes(),
        before,
        "identical publication must not rewrite indexes"
    );
    assert!(
        store
            .publish_file_upload_captures(&[active; FILE_UPLOAD_CAPTURE_BATCH + 1])
            .is_err()
    );
}
