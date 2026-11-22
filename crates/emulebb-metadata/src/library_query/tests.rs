use super::*;
use crate::{MetadataFileUploadCapture, MetadataIndexedFile, MetadataIndexedFileOrigin};
use rusqlite::params;

fn hash(byte: u8) -> [u8; 16] {
    [byte; 16]
}

#[test]
fn hash_detail_has_canonical_local_metadata_and_rejects_oversized_text() {
    let store = fixture();
    let file_hash = hex::encode(hash(1));
    store
        .update_shared_content_metadata(
            &file_hash,
            Some(("high", false)),
            Some(("Explicit note", 4)),
        )
        .unwrap();
    let detail = store.library_file_detail(&hash(1)).unwrap().unwrap();
    assert_eq!(detail.file, store.library_file(&hash(1)).unwrap().unwrap());
    assert_eq!(
        (
            detail.upload_priority.as_str(),
            detail.auto_upload_priority,
            detail.comment.as_str(),
            detail.rating
        ),
        ("high", false, "Explicit note", 4)
    );
    assert!(detail.aich_root.is_none());
    assert!(
        store.library_file_detail(&hash(5)).unwrap().is_none(),
        "passive evidence is not a client library hash"
    );
    assert!(store.library_file_detail(&hash(99)).unwrap().is_none());
    let conn = store.connection().unwrap();
    conn.execute(
        "UPDATE known_files SET comment=?2 WHERE ed2k_hash=?1",
        params![hash(1).as_slice(), "x".repeat(65_537)],
    )
    .unwrap();
    drop(conn);
    assert!(store.library_file_detail(&hash(1)).is_err());
    assert!(
        store.library_file(&hash(1)).unwrap().is_some(),
        "thin summaries do not load detail text"
    );
    let conn = store.connection().unwrap();
    let text = "\u{0001}".repeat(65_536);
    conn.execute("UPDATE known_files SET display_name=?2,comment=?2,aich_root=?3,aich_root_origin='operator_link' WHERE ed2k_hash=?1",
        params![hash(1).as_slice(), text, [0x42u8;20].as_slice()]).unwrap();
    drop(conn);
    let detail = store.library_file_detail(&hash(1)).unwrap().unwrap();
    assert_eq!(detail.file.display_name, text);
    assert_eq!(detail.comment, text);
    assert_eq!(detail.aich_root, Some([0x42; 20]));
}

// Paths deliberately do not exist. Browsing must use cached observations only.
fn fixture() -> MetadataStore {
    let mut store = MetadataStore::in_memory().unwrap();
    for (byte, name) in [
        (1, "İİİ.bin"),
        (2, "Alpha%_.bin"),
        (3, "alpha-other.bin"),
        (4, "Beta.bin"),
        (5, "Alpha Remote.bin"),
    ] {
        store
            .upsert_indexed_file(
                &MetadataIndexedFile {
                    ed2k_hash: hex::encode(hash(byte)),
                    name: name.into(),
                    size_bytes: 32,
                    content_type: String::new(),
                    availability_score: 0,
                },
                if byte == 5 {
                    MetadataIndexedFileOrigin::PassiveCache
                } else {
                    MetadataIndexedFileOrigin::LocalShare
                },
            )
            .unwrap();
    }
    {
        let mut conn = store.connection().unwrap();
        let tx = conn.transaction().unwrap();
        let root = std::env::temp_dir().join(format!("library-query-{}", uuid::Uuid::new_v4()));
        let root_path = crate::store::upsert_local_path(&tx, &root).unwrap();
        tx.execute(
            "INSERT INTO shared_directory_roots(id,path_id,created_at_s) VALUES(1,?1,0)",
            [root_path],
        )
        .unwrap();
        for (byte, size) in [(2, 0), (3, 32)] {
            tx.execute(
                "UPDATE known_files SET size_bytes=?2 WHERE id=?1",
                params![byte, size],
            )
            .unwrap();
            tx.execute("INSERT INTO verified_local_content(known_file_id,display_name,part_size_bytes,part_count)
                VALUES(?1,'Other-Physical-Name.bin',9728000,0)",[byte]).unwrap();
            let path = crate::store::upsert_local_path(
                &tx,
                &root.join(format!("Unrelated-copy-{byte}.bin")),
            )
            .unwrap();
            tx.execute("INSERT INTO local_file_instances(path_id,known_file_id,size_bytes,native_identity,verified_fingerprint,verified_at_s)
                VALUES(?1,?2,?3,x'01',x'02',0)",params![path,byte,size]).unwrap();
            tx.execute(
                "INSERT INTO shared_file_memberships VALUES(1,?1,?2,'Unrelated-copy.bin',0,0,NULL)",
                params![path, byte],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO temp.session_verified_local_paths VALUES(?1,x'02')",
                [path],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    store
        .set_library_sharing_enabled(&hex::encode(hash(3)), false)
        .unwrap();
    store.create_library_tag("Group-1").unwrap();
    store
        .set_library_file_tag(&hex::encode(hash(3)), "Group-1", true)
        .unwrap();
    store
        .publish_file_upload_captures(&[
            MetadataFileUploadCapture {
                file_hash: hash(2),
                session_uploaded_bytes: 17,
                session_upload_requests: 4,
                session_accepted_uploads: 1,
                pending: MetadataFileUploadTotals {
                    uploaded_bytes: 17,
                    upload_requests: 4,
                    accepted_sessions: 1,
                    last_requested_at_s: Some(0),
                    last_uploaded_at_s: Some(3),
                },
            },
            MetadataFileUploadCapture {
                file_hash: hash(3),
                session_uploaded_bytes: 9,
                session_upload_requests: 8,
                session_accepted_uploads: 2,
                pending: MetadataFileUploadTotals {
                    uploaded_bytes: 9,
                    upload_requests: 8,
                    accepted_sessions: 2,
                    last_requested_at_s: Some(5),
                    last_uploaded_at_s: Some(1),
                },
            },
        ])
        .unwrap();
    store
}

fn page(store: &MetadataStore, query: &LibraryFileQuery) -> MetadataLibraryFilePage {
    store
        .library_file_page(query, crate::LIBRARY_READ_MAX_BYTES)
        .unwrap()
}
fn ids(page: &MetadataLibraryFilePage) -> Vec<String> {
    page.files.iter().map(|row| row.file_hash.clone()).collect()
}
fn query(view: LibraryFileView) -> LibraryFileQuery {
    LibraryFileQuery {
        view,
        ..Default::default()
    }
}

#[test]
fn views_include_client_knowledge_and_preserve_independent_presence_and_policy() {
    let store = fixture();
    assert_eq!(
        ids(&page(&store, &LibraryFileQuery::default())),
        vec![hex::encode(hash(2)), hex::encode(hash(3))]
    );
    assert_eq!(
        ids(&page(&store, &query(LibraryFileView::Shared))),
        vec![hex::encode(hash(2))]
    );
    assert_eq!(
        ids(&page(&store, &query(LibraryFileView::Unavailable))),
        vec![hex::encode(hash(4)), hex::encode(hash(1))]
    );
    let all = page(
        &store,
        &LibraryFileQuery {
            count_total: true,
            ..query(LibraryFileView::AllKnown)
        },
    );
    assert_eq!(all.total, Some(4));
    assert_eq!(
        all.files
            .iter()
            .find(|row| row.file_hash == hex::encode(hash(1)))
            .unwrap()
            .size_bytes,
        None
    );
    assert_eq!(
        all.files
            .iter()
            .find(|row| row.file_hash == hex::encode(hash(2)))
            .unwrap()
            .size_bytes,
        Some(0)
    );
    assert!(
        all.files
            .iter()
            .any(|row| row.present && !row.sharing_enabled)
    );
    store
        .connection()
        .unwrap()
        .execute("UPDATE shared_directory_roots SET accessible=0", [])
        .unwrap();
    assert!(page(&store, &LibraryFileQuery::default()).files.is_empty());
    assert_eq!(
        page(&store, &query(LibraryFileView::Unavailable))
            .files
            .len(),
        4
    );
    assert_eq!(
        page(&store, &query(LibraryFileView::AllKnown)).files.len(),
        4
    );
}

#[test]
fn filename_substrings_and_root_tag_policy_filters_compose_without_expansion() {
    let store = fixture();
    let selected = LibraryFileQuery {
        search: Some("ALPHA".into()),
        root_id: Some(1),
        tag: Some("gRoUp-1".into()),
        sharing_enabled: Some(false),
        ..Default::default()
    };
    assert_eq!(ids(&page(&store, &selected)), vec![hex::encode(hash(3))]);
    for (search, expected) in [
        ("%_.", vec![hex::encode(hash(2))]),
        ("İİİ", vec![hex::encode(hash(1))]),
        ("Unrelated", vec![]),
        ("010101", vec![]),
        ("alpha' OR 1=1 --", vec![]),
    ] {
        assert_eq!(
            ids(&page(
                &store,
                &LibraryFileQuery {
                    search: Some(search.into()),
                    ..query(LibraryFileView::AllKnown)
                }
            )),
            expected
        );
    }
    assert!(
        page(
            &store,
            &LibraryFileQuery {
                root_id: Some(99),
                ..query(LibraryFileView::AllKnown)
            }
        )
        .files
        .is_empty()
    );
    for search in ["ab", "İİ"] {
        assert!(
            store
                .library_file_page(
                    &LibraryFileQuery {
                        search: Some(search.into()),
                        ..Default::default()
                    },
                    crate::LIBRARY_READ_MAX_BYTES
                )
                .is_err()
        );
    }
}

const SORTS: [LibraryFileSort; 10] = [
    LibraryFileSort::DisplayName,
    LibraryFileSort::SizeBytes,
    LibraryFileSort::SessionUploadedBytes,
    LibraryFileSort::SessionUploadRequests,
    LibraryFileSort::SessionAcceptedUploads,
    LibraryFileSort::LifetimeUploadedBytes,
    LibraryFileSort::LifetimeUploadRequests,
    LibraryFileSort::LifetimeAcceptedUploads,
    LibraryFileSort::LastRequestedAt,
    LibraryFileSort::LastUploadedAt,
];

#[test]
fn every_global_sort_traverses_one_row_pages_in_both_directions_with_hash_ties() {
    let store = fixture();
    for sort in SORTS {
        let expected = match sort {
            LibraryFileSort::DisplayName => [2, 3, 4, 1],
            LibraryFileSort::SizeBytes => [1, 4, 2, 3],
            LibraryFileSort::SessionUploadedBytes | LibraryFileSort::LifetimeUploadedBytes => {
                [1, 4, 3, 2]
            }
            LibraryFileSort::LastUploadedAt => [1, 4, 3, 2],
            _ => [1, 4, 2, 3],
        };
        for descending in [false, true] {
            let mut request = LibraryFileQuery {
                sort,
                descending,
                limit: 1,
                ..query(LibraryFileView::AllKnown)
            };
            let mut observed = Vec::new();
            loop {
                let result = page(&store, &request);
                assert_eq!(result.files.len(), 1);
                assert_eq!(result.total, None);
                observed.extend(ids(&result));
                request.after = result.next_after;
                if request.after.is_none() {
                    break;
                }
                assert!(observed.len() < 5);
            }
            let mut expected: Vec<_> = expected.map(|byte| hex::encode(hash(byte))).into();
            if descending {
                expected.reverse();
            }
            assert_eq!(observed, expected, "{sort:?} descending={descending}");
        }
    }
}

#[test]
fn byte_pages_keep_a_resume_anchor_and_cursor_does_not_require_filter_membership() {
    let store = fixture();
    let request = query(LibraryFileView::AllKnown);
    let first = store.library_file_page(&request, 4096).unwrap();
    assert_eq!(first.files.len(), 1);
    let mut next = request.clone();
    next.after = first.next_after;
    assert_eq!(
        ids(&page(&store, &next)),
        vec![
            hex::encode(hash(3)),
            hex::encode(hash(4)),
            hex::encode(hash(1))
        ]
    );
    let shared = LibraryFileQuery {
        after: Some(hash(3)),
        ..query(LibraryFileView::Shared)
    };
    assert!(
        page(&store, &shared).files.is_empty(),
        "an anchor may be outside the selected filter"
    );
    let error = store
        .library_file_page(
            &LibraryFileQuery {
                after: Some(hash(99)),
                ..request.clone()
            },
            crate::LIBRARY_READ_MAX_BYTES,
        )
        .unwrap_err();
    assert!(
        error
            .downcast_ref::<MetadataLibraryCursorExpired>()
            .is_some()
    );
    assert!(store.library_file_page(&request, 1).is_err());
    for limit in [0, 201] {
        assert!(
            store
                .library_file_page(
                    &LibraryFileQuery {
                        limit,
                        ..request.clone()
                    },
                    crate::LIBRARY_READ_MAX_BYTES
                )
                .is_err()
        );
    }
    for invalid in [
        LibraryFileQuery {
            root_id: Some(0),
            ..request.clone()
        },
        LibraryFileQuery {
            tag: Some("invalid name".into()),
            ..request
        },
    ] {
        assert!(
            store
                .library_file_page(&invalid, crate::LIBRARY_READ_MAX_BYTES)
                .is_err()
        );
    }
}

#[test]
fn idle_reads_do_not_rebuild_names_or_touch_the_projections() {
    let store = fixture();
    let request = query(LibraryFileView::AllKnown);
    let before = page(&store, &request);
    let changes = store.connection().unwrap().total_changes();
    assert_eq!(page(&store, &request).files, before.files);
    assert_eq!(store.connection().unwrap().total_changes(), changes);
}

#[test]
fn exact_reads_include_copyless_hashes_without_warming_other_names_or_passive_claims() {
    let store = fixture();
    let copyless = store.library_file(&hash(1)).unwrap().unwrap();
    assert_eq!(copyless.display_name, "İİİ.bin");
    assert_eq!(copyless.size_bytes, None);
    assert!(!copyless.present);
    let present = store.library_file(&hash(2)).unwrap().unwrap();
    assert!(present.present);
    assert_eq!(present.statistics.session_uploaded_bytes, 17);
    assert!(store.library_file(&hash(5)).unwrap().is_none());
    assert!(store.library_file(&hash(99)).unwrap().is_none());
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM temp.session_library_files WHERE name_key IS NULL",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        4
    );
}

#[test]
fn a_missing_tag_is_an_empty_named_filter_and_never_creates_a_tag() {
    let store = fixture();
    let result = page(
        &store,
        &LibraryFileQuery {
            tag: Some("Missing-1".into()),
            count_total: true,
            ..query(LibraryFileView::AllKnown)
        },
    );
    assert!(result.files.is_empty());
    assert_eq!(result.total, Some(0));
    assert!(store.library_tag("Missing-1").unwrap().is_none());
}

#[test]
fn a_missing_anchor_does_not_warm_and_roll_back_the_cold_projection() {
    let store = fixture();
    let changes = store.connection().unwrap().total_changes();
    let error = store
        .library_file_page(
            &LibraryFileQuery {
                after: Some(hash(99)),
                ..Default::default()
            },
            crate::LIBRARY_READ_MAX_BYTES,
        )
        .unwrap_err();
    assert!(
        error
            .downcast_ref::<MetadataLibraryCursorExpired>()
            .is_some()
    );
    assert_eq!(store.connection().unwrap().total_changes(), changes);
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM temp.session_library_files WHERE name_key IS NULL",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        4
    );
}

#[test]
fn indexed_queries_seek_all_views_and_sorts_among_a_hundred_thousand_hashes() {
    let store = MetadataStore::in_memory().unwrap();
    let key = |n: u128| n.to_be_bytes();
    {
        let mut conn = store.connection().unwrap();
        let tx = conn.transaction().unwrap();
        {
            let mut insert=tx.prepare("INSERT INTO known_files(ed2k_hash,display_name,first_seen_at_s,last_seen_at_s,updated_at_s)
                VALUES(?1,'Sample.bin',0,0,0)").unwrap();
            for n in 0..100_000 {
                insert.execute([key(n).as_slice()]).unwrap();
            }
        }
        tx.execute("INSERT INTO library_files SELECT id FROM known_files", [])
            .unwrap();
        // Two cached presence cohorts: 99,900 retained copyless hashes and 100
        // complete copies. SQL plans must skip the former for Present sorts.
        let root =
            std::env::temp_dir().join(format!("library-query-scale-{}", uuid::Uuid::new_v4()));
        let root_path = crate::store::upsert_local_path(&tx, &root).unwrap();
        tx.execute(
            "INSERT INTO shared_directory_roots(id,path_id,created_at_s) VALUES(1,?1,0)",
            [root_path],
        )
        .unwrap();
        for id in 99_901..=100_000 {
            tx.execute("UPDATE known_files SET size_bytes=32 WHERE id=?1", [id])
                .unwrap();
            tx.execute("INSERT INTO verified_local_content(known_file_id,display_name,part_size_bytes,part_count)
                VALUES(?1,'Sample.bin',9728000,0)",[id]).unwrap();
            let path =
                crate::store::upsert_local_path(&tx, &root.join(format!("Copy-{id}.bin"))).unwrap();
            tx.execute("INSERT INTO local_file_instances(path_id,known_file_id,size_bytes,native_identity,verified_fingerprint,verified_at_s)
                VALUES(?1,?2,32,x'01',x'02',0)",params![path,id]).unwrap();
            tx.execute(
                "INSERT INTO shared_file_memberships VALUES(1,?1,?2,'Sample.bin',0,0,NULL)",
                params![path, id],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO temp.session_verified_local_paths VALUES(?1,x'02')",
                [path],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    assert_eq!(
        page(&store, &query(LibraryFileView::AllKnown)).files[0].file_hash,
        hex::encode(key(0))
    );
    let present = page(
        &store,
        &LibraryFileQuery {
            count_total: true,
            ..Default::default()
        },
    );
    assert_eq!(present.total, Some(100));
    assert_eq!(present.files[0].file_hash, hex::encode(key(99_900)));
    for view in [
        LibraryFileView::AllKnown,
        LibraryFileView::Present,
        LibraryFileView::Unavailable,
    ] {
        for sort in SORTS {
            for descending in [false, true] {
                let anchor = if view == LibraryFileView::Present {
                    99_950
                } else {
                    50_000
                };
                let request = LibraryFileQuery {
                    view,
                    sort,
                    descending,
                    after: Some(key(anchor)),
                    limit: 20,
                    ..Default::default()
                };
                let (source, mut values) = source_and_filters(&request, None);
                let sql = page_sql(&request, &source, &mut values);
                let conn = store.connection().unwrap();
                let plan: Vec<String> = conn
                    .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                    .unwrap()
                    .query_map(params_from_iter(values.iter()), |r| r.get(3))
                    .unwrap()
                    .collect::<rusqlite::Result<_>>()
                    .unwrap();
                assert!(
                    !plan.iter().any(|line| line.contains("TEMP B-TREE")),
                    "{view:?} {sort:?}: {plan:?}"
                );
                assert!(
                    plan.iter().any(|line| line.contains(sort.index())),
                    "{plan:?}"
                );
                let mut statement = conn.prepare(&sql).unwrap();
                let hashes: Vec<Vec<u8>> = statement
                    .query_map(params_from_iter(values.iter()), |r| r.get(0))
                    .unwrap()
                    .collect::<rusqlite::Result<_>>()
                    .unwrap();
                assert_eq!(
                    hashes.len(),
                    21,
                    "the SQL query includes one pagination lookahead row"
                );
                assert_eq!(
                    hashes[0],
                    key(if descending { anchor - 1 } else { anchor + 1 })
                );
                assert_eq!(statement.get_status(rusqlite::StatementStatus::Sort), 0);
                assert!(
                    statement.get_status(rusqlite::StatementStatus::VmStep) < 10_000,
                    "{view:?} {sort:?}: {} VM steps: {plan:?}",
                    statement.get_status(rusqlite::StatementStatus::VmStep)
                );
            }
        }
    }
}
