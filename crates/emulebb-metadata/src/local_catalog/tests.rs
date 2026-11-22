use super::*;
use crate::{NativeFileFingerprint, NativeFileIdentity, NativeFileTimestamp, NativePath};

#[test]
fn library_search_counts_characters_before_unicode_lowercasing() {
    assert_eq!(normalize_library_search(None).unwrap(), None);
    for short in ["", "  ", "ab", "é🙂", "İA"] {
        assert!(normalize_library_search(Some(short)).is_err(), "{short:?}");
    }
    assert_eq!(
        normalize_library_search(Some("  ÄBC  ")).unwrap(),
        Some("äbc".into())
    );
    assert_eq!(
        normalize_library_search(Some("a_%")).unwrap(),
        Some("a_%".into())
    );
}

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
            "INSERT INTO shared_directory_roots(id,path_id,created_at_s) VALUES(1,?1,0)",
            [root_id],
        )
        .unwrap();
        tx.execute_batch("WITH RECURSIVE files(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM files WHERE n<100000)
            INSERT INTO known_files(id,ed2k_hash,size_bytes,display_name,first_seen_at_s,last_seen_at_s,updated_at_s)
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
            "INSERT INTO local_file_instances(path_id,known_file_id,size_bytes,native_identity,verified_fingerprint,verified_at_s) SELECT id+1,id,32,x'01',?1,0 FROM known_files",
            [&fingerprint],
        )
        .unwrap();
        tx.execute_batch("INSERT INTO shared_file_memberships SELECT 1,id+1,id,'sample',0,0,NULL FROM known_files;
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
    let identities = store.local_reload_identities().unwrap();
    assert_eq!(identities.len(), 100_000);
    assert!(
        identities.capacity() * std::mem::size_of::<(i64, [u8; 16])>() < 4 * 1024 * 1024,
        "100k pruning identities must remain compact"
    );
    let late_path = root.join("sample-100000.bin");
    let late = store.local_reload_entry(&late_path).unwrap().unwrap();
    assert_eq!(late.path_id, 100_001);
    assert_eq!(
        late.file_hash.as_slice(),
        format!("{:016}", 100_000).as_bytes()
    );
    assert_eq!(late.source_fingerprint.storage_bytes(), fingerprint);
    assert!(identities.contains(&(late.path_id, late.file_hash)));
    assert!(
        store
            .local_reload_entry(&root.join("absent.bin"))
            .unwrap()
            .is_none()
    );
    {
        let conn = store.connection().unwrap();
        let mut statement = conn
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {}",
                crate::local_file_store::LOCAL_RELOAD_ENTRY_SQL
            ))
            .unwrap();
        let path = NativePath::from(late_path);
        let plan = statement
            .query_map(
                params![NativePath::platform(), path.storage_bytes()],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            plan.iter().all(|line| !line.starts_with("SCAN ")),
            "{plan:?}"
        );
        assert!(
            plan.iter().any(|line| line.starts_with("SEARCH p ")),
            "{plan:?}"
        );
    }
    // Withdrawn memberships remain enumerable for bounded root reconciliation.
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE shared_file_memberships SET removed_at_s=1 WHERE root_id=1 AND known_file_id=1",
            [],
        )
        .unwrap();
    let affected_first = store.category_root_hash_page(&root, 0, 128).unwrap();
    let affected_next = store
        .category_root_hash_page(&root, affected_first.last().unwrap().0, 128)
        .unwrap();
    assert_eq!(affected_first.len(), 128);
    assert_eq!(affected_next.len(), 128);
    assert_eq!(affected_first[0].0, 1);
    assert!(affected_next[0].0 > affected_first.last().unwrap().0);
    store.connection().unwrap().execute("UPDATE shared_file_memberships SET removed_at_s=NULL WHERE root_id=1 AND known_file_id=1", []).unwrap();
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
    {
        let conn = store.connection().unwrap();
        let mut count = conn.prepare(CATALOG_COUNT_SQL).unwrap();
        assert_eq!(
            count.query_row([], |row| row.get::<_, i64>(0)).unwrap(),
            100_000
        );
        assert_eq!(count.get_status(rusqlite::StatementStatus::FullscanStep), 0);
        assert_eq!(count.get_status(rusqlite::StatementStatus::Sort), 0);
        assert!(count.get_status(rusqlite::StatementStatus::VmStep) < 20);
    }
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
    // Filename matching does not include the parent directory or content hash.
    for search in ["synthetic-catalog", "3030303030303030", "sample_%"] {
        let page = store
            .query_active_local_share_entries(&MetadataSharedFileQuery {
                limit: 2,
                search: Some(search.into()),
                count_total: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.total, 0, "{search}");
        assert!(page.entries.is_empty(), "{search}");
    }
    // A one-content mutation must not rewrite the other 99,999 index rows.
    {
        let conn = store.connection().unwrap();
        conn.execute_batch(
            "DROP TRIGGER keep_projection;
             CREATE TEMP TRIGGER protect_other_content BEFORE DELETE ON session_library_catalog
             WHEN old.known_file_id != 1
             BEGIN SELECT RAISE(ABORT,'unrelated content rewritten'); END;
             UPDATE temp.session_verified_local_paths SET verified_fingerprint=x'00' WHERE path_id=2;",
        ).unwrap();
    }
    let withdrawn = store
        .query_active_local_share_entries(&MetadataSharedFileQuery {
            limit: 2,
            count_total: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(withdrawn.total, 99_999);
    assert_eq!(withdrawn.entries[0].display_name, "sample-000002.bin");
    {
        let conn = store.connection().unwrap();
        conn.execute(
            "UPDATE temp.session_verified_local_paths SET verified_fingerprint=?1 WHERE path_id=2",
            [&fingerprint],
        )
        .unwrap();
    }
    let restored = store
        .query_active_local_share_entries(&MetadataSharedFileQuery {
            limit: 2,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(restored.entries[0].display_name, "sample-000001.bin");
    // Durable changes made by a second connection cannot be consumed by it.
    {
        let other = MetadataStore::from_connection(open()).unwrap();
        other
            .connection()
            .unwrap()
            .execute("UPDATE local_paths SET sort_key='zz-last' WHERE id=2", [])
            .unwrap();
        let page = store
            .query_active_local_share_entries(&MetadataSharedFileQuery {
                limit: 2,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.entries[0].display_name, "sample-000002.bin");
        other
            .connection()
            .unwrap()
            .execute(
                "UPDATE local_paths SET sort_key=lower(display_path) WHERE id=2",
                [],
            )
            .unwrap();
    }
    assert_eq!(
        store
            .query_active_local_share_entries(&MetadataSharedFileQuery {
                limit: 2,
                ..Default::default()
            })
            .unwrap()
            .entries[0]
            .display_name,
        "sample-000001.bin"
    );
    {
        let conn = store.connection().unwrap();
        let mut explain = conn.prepare(
            "EXPLAIN QUERY PLAN SELECT known_file_id FROM library_catalog_changes INDEXED BY library_catalog_changes_revision_idx WHERE revision > ?1 AND revision <= ?2"
        ).unwrap();
        let plan = explain
            .query_map(params![1, i64::MAX], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(plan.iter().any(|p| p.contains("SEARCH") && p.contains("library_catalog_changes_revision_idx")), "{plan:?}");
    }
    // Tag/policy changes are read directly and do not alter physical membership.
    {
        let conn = store.connection().unwrap();
        conn.execute_batch(
            "CREATE TEMP TRIGGER protect_all_content BEFORE DELETE ON session_library_catalog
             BEGIN SELECT RAISE(ABORT,'policy rebuilt physical catalog'); END;
             UPDATE temp.session_verified_local_paths SET verified_fingerprint=verified_fingerprint;
             UPDATE known_files SET sharing_enabled=0 WHERE id=2;
             INSERT INTO library_tags(name) VALUES('Batch');
             INSERT INTO known_file_tags SELECT 2,id FROM library_tags WHERE name='Batch';",
        )
        .unwrap();
    }
    // Re-observation uses the real admission writer, retaining its success
    // result while leaving identical index evidence untouched.
    assert!(
        store
            .mark_session_verified_local_path(
                &restored.entries[0].path,
                &NativeFileFingerprint::from_storage_bytes(&fingerprint).unwrap(),
            )
            .unwrap()
    );
    // A full unchanged scan uses the root writer, not the single-copy writer.
    // It must preserve the same physical projection under the guard above.
    let current = NativeFileFingerprint::from_storage_bytes(&fingerprint).unwrap();
    assert!(
        store
            .admit_local_path_to_root(
                &root,
                &restored.entries[0].path,
                restored.entries[0].path.strip_prefix(&root).unwrap(),
                &current,
            )
            .unwrap()
    );
    let scanned = (1..=100_000)
        .map(|n| {
            let relative = std::path::PathBuf::from(format!("sample-{n:06}.bin"));
            (root.join(&relative), relative, current.clone())
        })
        .collect::<Vec<_>>();
    store
        .replace_root_memberships(
            &root,
            &store.shared_root_scan_watermark(&root).unwrap(),
            &scanned,
        )
        .unwrap();
    assert_eq!(
        store
            .query_active_local_share_entries(&MetadataSharedFileQuery {
                limit: 2,
                ..Default::default()
            })
            .unwrap()
            .entries
            .len(),
        2
    );
    store
        .connection()
        .unwrap()
        .execute_batch(
            "DROP TRIGGER protect_other_content;
         DROP TRIGGER protect_all_content;
         UPDATE local_file_instances SET known_file_id = 1 WHERE known_file_id != 1;",
        )
        .unwrap();
    let root_page = store.category_root_hash_page(&root, 0, 128).unwrap();
    assert_eq!(
        root_page.len(),
        1,
        "all copies now belong to one content identity"
    );
    assert_eq!(root_page[0].0, 1);
    let hash = hex::encode(root_page[0].1);
    assert!(
        store.next_shared_copy(&hash, 0, 1).is_err(),
        "oversized path must fail before allocation"
    );
    let first_copy = store.next_shared_copy(&hash, 0, 65_536).unwrap().unwrap();
    assert_eq!(
        store
            .try_verified_share_batch(&[root_page[0].1, [0xff; 16]])
            .unwrap(),
        Some(vec![(true, None), (false, None)])
    );
    assert!(store.try_verified_share_batch(&[[0; 16]; 201]).is_err());
    // Policy applies to the hash, including every otherwise eligible copy.
    assert_eq!(
        store.set_library_sharing_enabled(&hash, false).unwrap(),
        Some(true)
    );
    assert_eq!(
        store.try_verified_share_batch(&[root_page[0].1]).unwrap(),
        Some(vec![(false, None)])
    );
    assert!(store.active_local_catalog_entry(&hash).unwrap().is_some());
    assert!(store.next_shared_copy(&hash, 0, 65_536).unwrap().is_some());
    assert_eq!(
        store.set_library_sharing_enabled(&hash, true).unwrap(),
        Some(true)
    );
    assert_eq!(
        store.try_verified_share_batch(&[root_page[0].1]).unwrap(),
        Some(vec![(true, None)])
    );
    let second_copy = store
        .next_shared_copy(&hash, first_copy.path_id, 65_536)
        .unwrap()
        .unwrap();
    assert!(second_copy.path_id > first_copy.path_id);
    let locations = store
        .library_locations(&hash, 50_000, 2, crate::LIBRARY_READ_MAX_BYTES)
        .unwrap()
        .unwrap();
    assert_eq!(locations.locations.len(), 2);
    assert_eq!(locations.locations[0].path_id, 50_001);
    assert_eq!(locations.next_after, Some(50_002));
    assert!(
        locations
            .locations
            .iter()
            .all(|p| p.verified_in_session && p.root_accessible)
    );
    let conn = store.connection().unwrap();
    // A one-row root table legitimately favors SCAN. Populate unrelated roots
    // before qualifying seeks, so this checks growing roots as well as copies.
    conn.execute_batch(
        "INSERT INTO shared_directory_roots(id,path_id,created_at_s)
        SELECT id+1,id+1,0 FROM known_files WHERE id<=32;
        ANALYZE shared_directory_roots;",
    )
    .unwrap();
    let sql = format!(
        "EXPLAIN QUERY PLAN {}",
        crate::library_read_store::LOCATION_PAGE_SQL
    );
    let mut explain = conn.prepare(&sql).unwrap();
    let plan = explain
        .query_map(params![1, 50_000, 3], |r| r.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plan.iter().any(|p| p.contains("SEARCH i")
            && p.contains("local_file_instances_content_idx")
            && p.contains("rowid>")),
        "{plan:?}"
    );
    assert!(
        plan.iter()
            .all(|p| !p.contains("TEMP B-TREE") && !p.starts_with("SCAN")),
        "{plan:?}"
    );
    drop(explain);
    let query = format!("EXPLAIN QUERY PLAN {}", super::VERIFIED_SHARE_EXISTS_SQL);
    let mut query_plan = conn.prepare(&query).unwrap();
    let eligibility_plan = query_plan
        .query_map([root_page[0].1.as_slice()], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        eligibility_plan
            .iter()
            .any(|line| line.contains("local_file_instances_content_idx")),
        "{eligibility_plan:#?}"
    );
    assert!(
        eligibility_plan
            .iter()
            .all(|line| !line.contains("TEMP B-TREE")),
        "{eligibility_plan:#?}"
    );
    drop(query_plan);
    let mismatches: i64 = conn.query_row("SELECT count(*) FROM shared_file_memberships m JOIN local_file_instances i ON i.path_id=m.path_id WHERE m.known_file_id != i.known_file_id", [], |row| row.get(0)).unwrap();
    assert_eq!(
        mismatches, 0,
        "content reassignment cascades to memberships"
    );
    let sql = format!(
        "EXPLAIN QUERY PLAN {}",
        crate::profile_store::CATEGORY_ROOT_HASH_PAGE_SQL
    );
    let mut explain = conn.prepare(&sql).unwrap();
    let plan = explain
        .query_map(
            params![
                NativePath::platform(),
                NativePath::from(root.as_path()).storage_bytes(),
                0,
                128
            ],
            |row| row.get::<_, String>(3),
        )
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|line| line.contains("shared_file_memberships_root_content_idx"))
    );
    assert!(
        plan.iter().all(|line| !line.contains("TEMP B-TREE")),
        "query plan: {plan:#?}"
    );
    drop(explain);
    conn.execute(
        "DELETE FROM local_file_instances WHERE path_id=?1",
        [first_copy.path_id],
    )
    .unwrap();
    let remaining: i64 = conn
        .query_row(
            "SELECT count(*) FROM shared_file_memberships WHERE path_id=?1",
            [first_copy.path_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        remaining, 0,
        "deleting an instance cascades to its memberships"
    );
    drop(conn);
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
    assert_eq!(
        store.try_verified_share_batch(&[root_page[0].1]).unwrap(),
        Some(vec![(false, None)])
    );
    assert_eq!(
        store.category_root_hash_page(&root, 0, 128).unwrap().len(),
        1,
        "withdrawn memberships remain enumerable"
    );
    assert!(store.next_shared_copy(&hash, 0, 65_536).unwrap().is_none());
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
