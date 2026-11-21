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
    store
        .apply_credit_deltas(&[], &[delta(&hash, 7, 2, 1)])
        .unwrap();
    store
        .clone()
        .apply_credit_deltas(&[], &[delta(&hash, 5, 1, 0)])
        .unwrap();
    let stats = store.file_upload_statistics(&hash).unwrap().unwrap();
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
        0,
        "reads must not allocate session records"
    );
}

#[test]
fn session_projection_failure_rolls_back_every_peer_and_file_delta_then_retries_once() {
    let mut store = MetadataStore::in_memory().unwrap();
    let first = seed(&mut store, 0x11);
    let second = seed(&mut store, 0x22);
    let before = store.file_upload_statistics(&first).unwrap();
    let peer = "33".repeat(16);
    let deltas = [delta(&first, 5, 1, 1), delta(&second, 7, 2, 1)];
    store
        .connection()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_statistics BEFORE INSERT ON session_file_upload_statistics
         WHEN new.ed2k_hash=x'22222222222222222222222222222222'
         BEGIN SELECT RAISE(ABORT,'injected statistics failure'); END;",
        )
        .unwrap();
    assert!(
        store
            .apply_credit_deltas(&[(peer.clone(), 11, 13)], &deltas)
            .is_err()
    );
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
        0
    );

    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_statistics")
        .unwrap();
    store
        .apply_credit_deltas(&[(peer.clone(), 11, 13)], &deltas)
        .unwrap();
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
    let peer = store.peer_credit_by_hash(&peer).unwrap().unwrap();
    assert_eq!((peer.uploaded_bytes, peer.downloaded_bytes), (11, 13));
}

#[test]
fn session_statistic_indexes_support_bounded_scalar_seeks() {
    let mut store = MetadataStore::in_memory().unwrap();
    let first = seed(&mut store, 0x11);
    let second = seed(&mut store, 0x22);
    store
        .apply_credit_deltas(&[], &[delta(&first, 7, 2, 1), delta(&second, 3, 1, 2)])
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
fn unknown_hashes_and_zero_deltas_create_no_session_records() {
    let mut store = MetadataStore::in_memory().unwrap();
    let hash = seed(&mut store, 0x11);
    let unknown = "22".repeat(16);
    store
        .apply_credit_deltas(&[], &[delta(&hash, 0, 0, 0), delta(&unknown, 7, 1, 1)])
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
        0
    );
}
