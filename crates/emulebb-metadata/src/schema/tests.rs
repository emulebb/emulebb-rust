use crate::{MetadataStore, SCHEMA_VERSION};
use rusqlite::params;

#[test]
fn current_marker_cannot_hide_missing_indexes_triggers_or_wrong_columns() {
    for damage in [
        "DROP INDEX search_results_known_file_id_idx",
        "DROP TRIGGER file_names_ai",
        "ALTER TABLE known_files ADD COLUMN obsolete_value TEXT",
        "DELETE FROM profile",
        "DELETE FROM library_catalog_revision",
    ] {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::SCHEMA_SQL).unwrap();
        conn.execute(
            "INSERT INTO metadata_schema(schema_id,schema_version,created_at_ms) VALUES(?1,?2,0)",
            params![crate::SCHEMA_ID, crate::SCHEMA_VERSION],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO profile VALUES(1,'00000000-0000-0000-0000-000000000001','test',0,0)",
            [],
        )
        .unwrap();
        conn.execute_batch(damage).unwrap();
        assert!(
            MetadataStore::from_connection(conn).is_err(),
            "accepted damaged schema: {damage}"
        );
    }
}

#[test]
fn every_child_foreign_key_has_a_leading_index() {
    let store = MetadataStore::in_memory().unwrap();
    let conn = store.connection().unwrap();
    let mut tables = conn.prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'file_name_fts%' AND name NOT LIKE 'sqlite_%'").unwrap();
    let tables = tables
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for table in tables {
        let mut keys = conn
            .prepare(&format!("PRAGMA foreign_key_list({table})"))
            .unwrap();
        let keys = keys
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    crate::sql_value::unsigned::<usize>(r, 1)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .unwrap();
        // Individual components must occur at their declared position in a shared index.
        // The schema currently has only single-column keys and the recovery-set pair.
        let mut groups = std::collections::BTreeMap::<i64, Vec<(usize, String)>>::new();
        for key in keys {
            let (id, position, column) = key.unwrap();
            groups.entry(id).or_default().push((position, column));
        }
        for columns in groups.values_mut() {
            columns.sort();
            let mut indexes = conn
                .prepare("SELECT name FROM pragma_index_list(?1) WHERE partial = 0")
                .unwrap();
            let indexes = indexes
                .query_map([&table], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let found = indexes.into_iter().any(|index| {
                let mut info = conn
                    .prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")
                    .unwrap();
                let names = info
                    .query_map([index], |r| r.get::<_, Option<String>>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                columns.iter().all(|(position, column)| {
                    names
                        .get(*position)
                        .is_some_and(|name| name.as_ref() == Some(column))
                })
            });
            let rowid_key = columns.len() == 1 && conn.query_row("SELECT count(*) FROM pragma_table_info(?1) WHERE name = ?2 AND type = 'INTEGER' AND pk = 1", params![table, columns[0].1], |r| r.get::<_, i64>(0)).unwrap() == 1;
            assert!(
                found || rowid_key,
                "unindexed foreign key: {table} {columns:?}"
            );
        }
    }
}

#[test]
fn schema_rejects_wrong_storage_types_null_keys_and_out_of_range_values() {
    let store = MetadataStore::in_memory().unwrap();
    let conn = store.connection().unwrap();
    for sql in [
        "INSERT INTO known_files(ed2k_hash,size_bytes,display_name,first_seen_at_ms,last_seen_at_ms,updated_at_ms) VALUES ('abcdefghijklmnop',1,'sample',0,0,0)",
        "INSERT INTO known_files(ed2k_hash,size_bytes,display_name,aich_root,first_seen_at_ms,last_seen_at_ms,updated_at_ms) VALUES (zeroblob(16),1,'sample',zeroblob(20),0,0,0)",
        "INSERT INTO known_files(ed2k_hash,size_bytes,display_name,aich_root,aich_root_origin,first_seen_at_ms,last_seen_at_ms,updated_at_ms) VALUES (zeroblob(16),1,'sample',zeroblob(20),'network_consensus',0,0,0)",
        "INSERT INTO known_files(ed2k_hash,size_bytes,display_name,first_seen_at_ms,last_seen_at_ms,updated_at_ms) VALUES (zeroblob(16),'invalid','sample',0,0,0)",
        "INSERT INTO download_history(ed2k_hash,size_bytes,display_name,first_completed_at_ms,last_completed_at_ms) VALUES (NULL,1,'sample',0,0)",
        "INSERT INTO known_files(ed2k_hash,size_bytes,display_name,media_length_seconds,first_seen_at_ms,last_seen_at_ms,updated_at_ms) VALUES (zeroblob(16),1,'sample',4294967296,0,0,0)",
        "INSERT INTO metadata_schema(schema_id,schema_version,created_at_ms) VALUES ('second-schema',1,0)",
        "INSERT INTO shared_file_ignore_patterns(pattern,created_at_ms) VALUES (NULL,0)",
        "INSERT INTO peers(user_hash,secure_ident_pubkey,secure_ident_pubkey_len,first_seen_at_ms,last_seen_at_ms) VALUES(zeroblob(16),x'01',2,0,0)",
        "INSERT INTO local_identities(identity_kind, public_identity, created_at_ms, updated_at_ms) VALUES('ed2k-secure-ident',zeroblob(16),0,0)",
        "INSERT INTO local_identities(identity_kind, created_at_ms, updated_at_ms) VALUES('ed2k-user-hash',0,0)",
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
        "UPDATE file_names SET seen_count = seen_count + 1, last_seen_at_ms = 1",
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
