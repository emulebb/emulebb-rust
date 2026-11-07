use crate::{MetadataStore, SCHEMA_VERSION};
use rusqlite::params;

#[test]
fn schema_rejects_wrong_storage_types_null_keys_and_out_of_range_values() {
    let store = MetadataStore::in_memory().unwrap();
    let conn = store.connection().unwrap();
    for sql in [
        "INSERT INTO known_files(ed2k_hash,size_bytes,display_name,first_seen_ms,last_seen_ms,updated_at_ms) VALUES ('abcdefghijklmnop',1,'sample',0,0,0)",
        "INSERT INTO known_files(ed2k_hash,size_bytes,display_name,first_seen_ms,last_seen_ms,updated_at_ms) VALUES (zeroblob(16),'invalid','sample',0,0,0)",
        "INSERT INTO download_history(ed2k_hash,size_bytes,display_name,first_completed_at_ms,last_completed_at_ms) VALUES (NULL,1,'sample',0,0)",
        "INSERT INTO known_files(ed2k_hash,size_bytes,display_name,media_length_seconds,first_seen_ms,last_seen_ms,updated_at_ms) VALUES (zeroblob(16),1,'sample',4294967296,0,0,0)",
        "INSERT INTO metadata_schema(schema_id,schema_version,created_at_ms) VALUES ('second-schema',1,0)",
        "INSERT INTO shared_file_ignore_patterns(pattern,created_at_ms) VALUES (NULL,0)",
        "INSERT INTO peers(user_hash,secure_ident_pubkey,secure_ident_pubkey_len,first_seen_ms,last_seen_ms) VALUES(zeroblob(16),x'01',2,0,0)",
    ] {
        assert!(
            conn.execute(sql, []).is_err(),
            "accepted invalid row: {sql}"
        );
    }
    assert_eq!(
        conn.query_row(
            "SELECT schema_version FROM metadata_schema WHERE id = 1",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        SCHEMA_VERSION
    );
    let strict: i64 = conn.query_row("SELECT min(strict) FROM pragma_table_list WHERE schema = 'main' AND name NOT LIKE 'file_name_fts%' AND name NOT LIKE 'sqlite_%'", [], |r| r.get(0)).unwrap();
    assert_eq!(strict, 1);
    assert!(
        conn.execute(
            "UPDATE metadata_schema SET schema_version = ?1",
            params![-1]
        )
        .is_err()
    );
}

#[test]
fn observation_only_name_updates_do_not_rewrite_fts() {
    let mut store = MetadataStore::in_memory().unwrap();
    let file = crate::MetadataIndexedFile {
        ed2k_hash: "11".repeat(16),
        name: "sample.bin".into(),
        size_bytes: 1,
        content_type: String::new(),
        availability_score: 0,
    };
    store
        .upsert_indexed_file(&file, crate::MetadataIndexedFileOrigin::PassiveCache)
        .unwrap();
    let conn = store.connection().unwrap();
    conn.execute_batch("CREATE TEMP TABLE fts_changes(value INTEGER); CREATE TEMP TRIGGER track_fts_data AFTER INSERT ON main.file_name_fts_data BEGIN INSERT INTO fts_changes VALUES(1); END;").unwrap();
    conn.execute(
        "UPDATE file_names SET seen_count = seen_count + 1, last_seen_ms = 1",
        [],
    )
    .unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM fts_changes", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    conn.execute(
        "INSERT INTO file_name_fts(file_name_fts, rank) VALUES('integrity-check', 1)",
        [],
    )
    .unwrap();
}
