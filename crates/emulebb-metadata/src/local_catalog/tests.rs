use super::*;
use crate::{NativeFileFingerprint, NativeFileIdentity, NativeFileTimestamp, NativePath};

#[test]
fn large_catalog_uses_hash_seeks_and_path_cursors() {
    let database = format!(
        "file:library-catalog-{}?mode=memory&cache=shared",
        uuid::Uuid::new_v4()
    );
    let open = || {
        rusqlite::Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .unwrap()
    };
    let store = MetadataStore::from_connection(open()).unwrap();
    let root = std::env::temp_dir().join("synthetic-catalog");
    let fingerprint = NativeFileFingerprint {
        identity: NativeFileIdentity::Unix {
            device_id: 1,
            inode_number: 1,
        },
        size_bytes: 32,
        modified: NativeFileTimestamp::new(1, 0).unwrap(),
        changed: None,
    }
    .storage_bytes();
    {
        let mut conn = store.connection().unwrap();
        let tx = conn.transaction().unwrap();
        let root_id = crate::store::upsert_local_path(&tx, &root).unwrap();
        tx.execute(
            "INSERT INTO shared_directory_roots(id,path_id,created_at_ms) VALUES(1,?1,0)",
            [root_id],
        )
        .unwrap();
        tx.execute_batch("WITH RECURSIVE files(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM files WHERE n<100000)
            INSERT INTO known_files(id,ed2k_hash,size_bytes,display_name,first_seen_at_ms,last_seen_at_ms,updated_at_ms)
            SELECT n,CAST(printf('%016d',n) AS BLOB),32,'sample',0,0,0 FROM files;
            INSERT INTO verified_local_content(known_file_id,display_name,part_size_bytes,part_count)
            SELECT id,'sample',9728000,0 FROM known_files;").unwrap();
        {
            let mut insert = tx.prepare("INSERT INTO local_paths(id,display_path,native_path,search_key,platform,sort_key,file_name_search_key) VALUES(?1,?2,?3,?2,?4,?5,?6)").unwrap();
            for n in 1..=100_000 {
                let name = format!("sample-{n:06}.bin");
                let path = NativePath::from(root.join(&name));
                let display = path.display_path();
                insert
                    .execute(params![
                        n + 1,
                        display,
                        path.storage_bytes(),
                        NativePath::platform(),
                        display.to_lowercase(),
                        name
                    ])
                    .unwrap();
            }
        }
        tx.execute(
            "INSERT INTO local_file_instances SELECT id+1,id,32,x'01',?1,0 FROM known_files",
            [&fingerprint],
        )
        .unwrap();
        tx.execute_batch("INSERT INTO shared_file_memberships SELECT 1,id+1,'sample',0,0,NULL FROM known_files;
            INSERT INTO temp.session_verified_local_paths SELECT path_id,verified_fingerprint FROM local_file_instances;
            ANALYZE;").unwrap();
        for exact in [false, true] {
            let sql = format!("EXPLAIN QUERY PLAN {}", catalog_sql(exact, true, false));
            let mut stmt = tx.prepare(&sql).unwrap();
            let plan = stmt
                .query_map(params![100, b"0000000000050000".as_slice()], |r| {
                    r.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                plan.iter().any(
                    |line| line.starts_with("SEARCH known_files") && line.contains("ed2k_hash")
                ),
                "{plan:?}"
            );
            assert!(
                !plan.iter().any(|line| line.starts_with("SCAN candidate")),
                "{plan:?}"
            );
        }
        tx.commit().unwrap();
    }
    let first = store
        .query_active_local_share_entries(&MetadataSharedFileQuery {
            limit: 2,
            count_total: false,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(first.total, 0);
    assert_eq!(first.entries.len(), 2);
    store
        .connection()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TRIGGER keep_projection BEFORE DELETE ON session_library_catalog
         BEGIN SELECT RAISE(ABORT,'unchanged catalog rebuilt'); END;
         UPDATE known_files SET all_time_uploaded_bytes = 1 WHERE id = 1;",
        )
        .unwrap();
    let next = store
        .query_active_local_share_entries(&MetadataSharedFileQuery {
            limit: 2,
            after: first.next_cursor.clone(),
            count_total: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(next.total, 100_000);
    assert_eq!(next.entries[0].display_name, "sample-000003.bin");
    assert_eq!(
        store
            .active_local_catalog_entry(&first.entries[0].file_hash)
            .unwrap()
            .unwrap()
            .file_hash,
        first.entries[0].file_hash
    );
    let filtered = store
        .query_active_local_share_entries(&MetadataSharedFileQuery {
            limit: 2,
            search: Some("SAMPLE-100000".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(filtered.entries.len(), 1);
    assert!(filtered.next_cursor.is_none());
    store
        .connection()
        .unwrap()
        .execute_batch(
            "DROP TRIGGER keep_projection;
        UPDATE local_file_instances SET known_file_id = 1 WHERE known_file_id != 1;",
        )
        .unwrap();
    let aliases = store
        .query_active_local_share_entries(&MetadataSharedFileQuery {
            limit: 2,
            count_total: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(aliases.total, 1);
    assert_eq!(aliases.entries.len(), 1);
    let chosen = aliases.entries[0].path.clone();
    store.connection().unwrap().execute("DELETE FROM temp.session_verified_local_paths WHERE path_id = (SELECT id FROM local_paths WHERE native_path = ?1)", [NativePath::from(chosen.as_path()).storage_bytes()]).unwrap();
    let next_alias = store
        .query_active_local_share_entries(&MetadataSharedFileQuery {
            limit: 2,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(next_alias.entries.len(), 1);
    assert_ne!(next_alias.entries[0].path, chosen);
    let other = MetadataStore::from_connection(open()).unwrap();
    other.set_shared_root_accessible(&root, false).unwrap();
    assert!(
        store
            .query_active_local_share_entries(&MetadataSharedFileQuery {
                limit: 2,
                ..Default::default()
            })
            .unwrap()
            .entries
            .is_empty()
    );
}
