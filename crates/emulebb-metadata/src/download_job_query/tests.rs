use super::*;
use crate::{
    DownloadIntent, DownloadJobRequest, MetadataTransferDeliveryOwnership,
    MetadataTransferDeliveryState, MetadataTransferPiece, NativeFileFingerprint,
    NativeFileIdentity, NativeFileTimestamp,
};

fn add(
    store: &MetadataStore,
    hash: u8,
    category_id: Option<i64>,
    name_bytes: usize,
) -> DownloadJobRecord {
    store
        .admit_download_job(&DownloadJobRequest {
            file_hash: hex::encode([hash; 16]),
            display_name: "n".repeat(name_bytes),
            expected_size_bytes: Some(16),
            category_id,
            intent: DownloadIntent::Stopped,
            piece_size: 16,
        })
        .unwrap()
        .job
}
fn ids(page: &DownloadJobPage) -> Vec<i64> {
    page.jobs.iter().map(|job| job.token.job_id.get()).collect()
}
fn counts(store: &MetadataStore, unfinished: u64, completed: u64) {
    assert_eq!(
        store.download_job_counts().unwrap(),
        DownloadJobCounts {
            unfinished,
            completed
        }
    );
}

#[test]
fn waiting_counter_tracks_lifecycle_and_excludes_only_matching_selected_jobs() {
    let store = MetadataStore::in_memory().unwrap();
    let a = add(&store, 91, None, 8);
    let b = add(&store, 92, None, 8);
    let aid = a.token.job_id;
    let bid = b.token.job_id;
    let check = |expected| {
        assert_eq!(store.waiting_download_count(&[]).unwrap(), expected);
        let actual: u64 = store.connection().unwrap().query_row(
            "SELECT count(*) FROM download_jobs WHERE removed_at_s IS NULL
             AND terminal_completed_at_s IS NULL AND delete_requested_at_s IS NULL
             AND intent='started' AND storage_failure_code IS NULL AND expected_size_bytes IS NOT NULL
             AND (completed=0 OR final_rehash_pending=1)",
            [], |row| crate::sql_value::unsigned(row, 0),
        ).unwrap();
        assert_eq!(actual, expected);
    };
    let update = |id: JobId, set: &str| {
        store
            .connection()
            .unwrap()
            .execute(&format!("UPDATE download_jobs SET {set} WHERE id=?1"), [id])
            .unwrap();
    };
    check(0);
    update(aid, "intent='started'");
    update(bid, "intent='started'");
    check(2);
    assert_eq!(store.waiting_download_count(&[aid]).unwrap(), 1);
    assert_eq!(store.waiting_download_count(&[aid, bid]).unwrap(), 0);
    assert!(store.waiting_download_count(&[aid, aid]).is_err());
    assert!(store.waiting_download_count(&[bid, aid]).is_err());
    update(aid, "expected_size_bytes=NULL");
    check(1);
    assert_eq!(store.waiting_download_count(&[aid]).unwrap(), 1);
    update(aid, "expected_size_bytes=16");
    check(2);
    update(
        aid,
        "storage_failure_code='io', storage_failure_message='test fault', storage_failed_at_s=1",
    );
    check(1);
    assert_eq!(store.waiting_download_count(&[aid]).unwrap(), 1);
    update(
        aid,
        "storage_failure_code=NULL, storage_failure_message=NULL, storage_failed_at_s=NULL",
    );
    check(2);
    update(aid, "completed=1, visible_state='completed'");
    check(1);
    update(aid, "final_rehash_pending=1");
    check(2);
    update(aid, "final_rehash_pending=0");
    check(1);
    update(bid, "delete_requested_at_s=1");
    check(0);
    store
        .connection()
        .unwrap()
        .execute_batch("BEGIN; UPDATE download_jobs SET delete_requested_at_s=NULL; ROLLBACK;")
        .unwrap();
    check(0);
    update(bid, "delete_requested_at_s=NULL");
    check(1);
    update(bid, "removed_at_s=1");
    check(0);
    update(bid, "removed_at_s=NULL");
    check(1);
    update(bid, "intent='stopped'");
    check(0);
    update(bid, "intent='started'");
    check(1);
    store
        .connection()
        .unwrap()
        .execute("DELETE FROM download_jobs WHERE id=?1", [bid])
        .unwrap();
    check(0);
    assert_eq!(store.waiting_download_count(&[bid]).unwrap(), 0);
}

#[test]
fn dashboard_counters_track_intent_delete_admission_removal_and_rollback() {
    let store = MetadataStore::in_memory().unwrap();
    let a = add(&store, 81, None, 8);
    let b = add(&store, 82, None, 8);
    let c = add(&store, 83, None, 8);
    complete(&store, &c);
    let check = |total, active, completed| {
        assert_eq!(store.waiting_download_count(&[]).unwrap(), active);
        let expected = crate::MetadataTransferCounts { total, completed };
        assert_eq!(store.transfer_counts().unwrap(), expected);
        // Independent row-scan oracle for the existing public membership rules.
        let conn = store.connection().unwrap();
        let actual = conn
            .query_row(
                "SELECT count(*),coalesce(sum(terminal_completed_at_s IS NOT NULL),0)
             FROM download_jobs WHERE removed_at_s IS NULL AND delete_requested_at_s IS NULL",
                [],
                |row| {
                    Ok(crate::MetadataTransferCounts {
                        total: crate::sql_value::unsigned(row, 0)?,
                        completed: crate::sql_value::unsigned(row, 1)?,
                    })
                },
            )
            .unwrap();
        assert_eq!(actual, expected);
    };
    let update = |id: JobId, set: &str| {
        store
            .connection()
            .unwrap()
            .execute(
                &format!("UPDATE download_jobs SET {set} WHERE id=?1"),
                [id.get()],
            )
            .unwrap();
    };
    check(3, 0, 1);
    update(a.token.job_id, "intent='started'");
    check(3, 1, 1);
    update(a.token.job_id, "delete_requested_at_s=1");
    check(2, 0, 1);
    update(b.token.job_id, "delete_requested_at_s=1");
    check(1, 0, 1);
    update(c.token.job_id, "delete_requested_at_s=1");
    check(0, 0, 0);
    store
        .connection()
        .unwrap()
        .execute_batch("BEGIN; UPDATE download_jobs SET delete_requested_at_s=NULL; ROLLBACK;")
        .unwrap();
    check(0, 0, 0);
    store
        .connection()
        .unwrap()
        .execute_batch("UPDATE download_jobs SET delete_requested_at_s=NULL;")
        .unwrap();
    check(3, 1, 1);
    update(b.token.job_id, "removed_at_s=1");
    check(2, 1, 1);
    store
        .connection()
        .unwrap()
        .execute(
            "DELETE FROM download_jobs WHERE id=?1",
            [a.token.job_id.get()],
        )
        .unwrap();
    check(1, 0, 1);
    update(c.token.job_id, "removed_at_s=1");
    check(0, 0, 0);
    assert!(store.finalize_transfer_retirement(c.token.job_id).unwrap());
    assert!(store.delete_transfer_manifest(b.token.job_id).unwrap());
    assert!(store.delete_transfer_manifest(c.token.job_id).unwrap());
    check(0, 0, 0);
}
fn prepare_completion(store: &MetadataStore, job: &DownloadJobRecord) {
    let path = std::env::temp_dir().join(format!("completed-sample-{}.bin", job.token.job_id));
    let fingerprint = NativeFileFingerprint {
        identity: NativeFileIdentity::Unix {
            device_id: 1,
            inode_number: job.token.job_id.get() as u64,
        },
        size_bytes: 16,
        modified: NativeFileTimestamp::new(1, 0).unwrap(),
        changed: None,
    };
    store
        .upsert_verified_local_content(&crate::MetadataVerifiedLocalContent {
            secondary_identity: None,
            file_hash: job.file_hash.clone(),
            display_name: job.display_name.clone(),
            file_size: 16,
            part_size: 16,
            md4_hashset: Vec::new(),
            aich_root: None,
            aich_hashset: Vec::new(),
            path: path.clone(),
            fingerprint,
            upload_priority: "normal".into(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
        })
        .unwrap();
    let mut manifest = store
        .download_job_manifest(job.token.job_id)
        .unwrap()
        .unwrap();
    manifest.completed = true;
    manifest.pieces = vec![MetadataTransferPiece {
        piece_index: 0,
        state: "Verified".into(),
        prefix_bytes: 16,
        present_bytes: 16,
        block_bitmap: None,
        ich_corrupted: false,
    }];
    manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
    manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Unowned;
    manifest.delivered_path = Some(path);
    store.upsert_transfer_manifest(&manifest).unwrap();
}
fn complete(store: &MetadataStore, job: &DownloadJobRecord) {
    prepare_completion(store, job);
    // Retirement admission requires started intent, independently of browsing.
    let current = store.download_job(job.token.job_id).unwrap().unwrap();
    let current = store
        .start_download_job(current.token, &std::env::temp_dir())
        .unwrap()
        .unwrap();
    assert!(store.request_transfer_retirement(current.token).unwrap());
}

#[test]
fn descending_pages_are_live_and_keep_an_exclusive_numeric_boundary() {
    let store = MetadataStore::in_memory().unwrap();
    let jobs: Vec<_> = (1..=5).map(|hash| add(&store, hash, None, 8)).collect();
    let query = DownloadJobQuery {
        limit: 2,
        ..Default::default()
    };
    let first = store.download_job_page(query).unwrap();
    assert_eq!(ids(&first), vec![5, 4]);
    assert!(first.has_more);
    assert_eq!(first.next_before, Some(jobs[3].token.job_id));
    let later = add(&store, 6, None, 8);
    assert!(
        store
            .delete_transfer_manifest(jobs[2].token.job_id)
            .unwrap()
    );
    complete(&store, &jobs[1]);
    let second = store
        .download_job_page(DownloadJobQuery {
            before: first.next_before,
            ..query
        })
        .unwrap();
    assert_eq!(ids(&second), vec![1]);
    assert!(!second.has_more);
    assert_eq!(second.next_before, None);
    let all_tail = store
        .download_job_page(DownloadJobQuery {
            view: DownloadJobView::All,
            before: first.next_before,
            ..query
        })
        .unwrap();
    assert_eq!(ids(&all_tail), vec![2, 1]);
    assert!(!all_tail.has_more);
    let fresh = store.download_job_page(query).unwrap();
    assert_eq!(fresh.jobs[0].token.job_id, later.token.job_id);
    let completed = store
        .download_job_page(DownloadJobQuery {
            view: DownloadJobView::Completed,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(ids(&completed), vec![2]);
    counts(&store, 4, 1);
    for limit in [0, 201] {
        assert!(
            store
                .download_job_page(DownloadJobQuery { limit, ..query })
                .is_err()
        );
    }
    for category_id in [0, -1] {
        assert!(
            store
                .download_job_page(DownloadJobQuery {
                    category_id: Some(category_id),
                    ..query
                })
                .is_err()
        );
    }
    assert_eq!(DownloadJobQuery::default().limit, 100);
    assert_eq!(
        DownloadJobQuery::default().view,
        DownloadJobView::Unfinished
    );
}

#[test]
fn byte_short_pages_resume_without_skipping_and_lookahead_never_hydrates() {
    let store = MetadataStore::in_memory().unwrap();
    let failure =
        crate::DownloadJobStorageFailure::new(&"c".repeat(64), &"m".repeat(4096), 0).unwrap();
    for hash in 10..42 {
        let job = add(&store, hash, None, 65_536);
        assert!(
            store
                .fail_download_job_storage(job.token, &failure)
                .unwrap()
                .applied
        );
    }
    store
        .connection()
        .unwrap()
        .execute_batch(
            "CREATE TEMP VIEW download_job_pieces AS SELECT * FROM forbidden_piece_read;",
        )
        .unwrap();
    let mut query = DownloadJobQuery {
        view: DownloadJobView::All,
        ..Default::default()
    };
    let mut seen = Vec::new();
    for expected in [15, 15, 2] {
        let page = store.download_job_page(query).unwrap();
        assert_eq!(page.jobs.len(), expected);
        assert_eq!(page.has_more, expected == 15);
        assert_eq!(
            page.next_before,
            if page.has_more {
                page.jobs.last().map(|job| job.token.job_id)
            } else {
                None
            }
        );
        seen.extend(ids(&page));
        query.before = page.next_before;
    }
    assert_eq!(seen, (1..=32).rev().collect::<Vec<_>>());
    let store = MetadataStore::in_memory().unwrap();
    let older = add(&store, 43, None, 8);
    let newest = add(&store, 44, None, 8);
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET display_name=?2 WHERE id=?1",
            params![older.token.job_id, "x".repeat(1_000_000)],
        )
        .unwrap();
    let page = store
        .download_job_page(DownloadJobQuery {
            limit: 1,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(ids(&page), vec![newest.token.job_id.get()]);
    assert!(page.has_more);
    assert!(
        store
            .download_job_page(DownloadJobQuery {
                before: page.next_before,
                limit: 1,
                ..Default::default()
            })
            .is_err()
    );
}

#[test]
fn initial_page_includes_the_largest_sqlite_job_id() {
    let store = MetadataStore::in_memory().unwrap();
    let original = add(&store, 45, None, 8);
    store.remove_download_job(original.token.job_id).unwrap();
    store.connection().unwrap().execute("INSERT INTO download_jobs(id,known_file_id,display_name,part_size_bytes,part_count,visible_state,delivery_state,created_at_s,updated_at_s)
        SELECT 9223372036854775807,known_file_id,'maximum-id',16,0,'queued','pending',0,0 FROM download_jobs WHERE id=?1", [original.token.job_id]).unwrap();
    let first = store.download_job_page(Default::default()).unwrap();
    assert_eq!(ids(&first), vec![i64::MAX]);
    assert!(!first.has_more);
    let next = store
        .download_job_page(DownloadJobQuery {
            before: Some(JobId::new(i64::MAX).unwrap()),
            ..Default::default()
        })
        .unwrap();
    assert!(next.jobs.is_empty());
}

#[test]
fn summary_lifecycle_reopen_and_removed_physical_deletion_are_exact() {
    let root = std::env::temp_dir().join(format!("job-counts-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let database = root.join("metadata.db");
    let store = MetadataStore::open(&database).unwrap();
    counts(&store, 0, 0);
    let a = add(&store, 50, None, 8);
    let b = add(&store, 51, None, 8);
    counts(&store, 2, 0);
    complete(&store, &a);
    counts(&store, 1, 1);
    assert!(store.finalize_transfer_retirement(a.token.job_id).unwrap());
    counts(&store, 1, 1);
    assert!(store.delete_transfer_manifest(b.token.job_id).unwrap());
    counts(&store, 0, 1);
    assert!(store.remove_download_job(a.token.job_id).unwrap());
    counts(&store, 0, 0);
    assert!(!store.remove_download_job(a.token.job_id).unwrap());
    if store.transfer_retirement_pending(a.token.job_id).unwrap() {
        assert!(store.finalize_transfer_retirement(a.token.job_id).unwrap());
    }
    assert!(store.delete_transfer_manifest(a.token.job_id).unwrap());
    counts(&store, 0, 0);
    let c = add(&store, 52, None, 8);
    assert!(store.remove_download_job(c.token.job_id).unwrap());
    counts(&store, 0, 0);
    assert!(store.finalize_transfer_retirement(c.token.job_id).unwrap());
    assert!(store.delete_transfer_manifest(c.token.job_id).unwrap());
    counts(&store, 0, 0);
    add(&store, 53, None, 8);
    let d = add(&store, 54, None, 8);
    complete(&store, &d);
    counts(&store, 1, 1);
    drop(store);
    let store = MetadataStore::open(&database).unwrap();
    counts(&store, 1, 1);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn summary_rolls_back_admission_completion_removal_and_deletion_failures() {
    let store = MetadataStore::in_memory().unwrap();
    store.connection().unwrap().execute_batch("CREATE TEMP TRIGGER reject_admission AFTER UPDATE OF latest_download_job_id ON known_files BEGIN SELECT RAISE(ABORT,'injected admission rejection'); END;").unwrap();
    let request = DownloadJobRequest {
        file_hash: "61".repeat(16),
        display_name: "rollback-sample".into(),
        expected_size_bytes: Some(16),
        category_id: None,
        intent: DownloadIntent::Started,
        piece_size: 16,
    };
    assert!(store.admit_download_job(&request).is_err());
    counts(&store, 0, 0);
    assert_eq!(store.table_count("download_jobs").unwrap(), 0);
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_admission;")
        .unwrap();
    let a = store.admit_download_job(&request).unwrap().job;
    prepare_completion(&store, &a);
    counts(&store, 1, 0); // Verified payload alone is not terminal completion.
    store.connection().unwrap().execute_batch("CREATE TEMP TRIGGER reject_completion AFTER UPDATE OF terminal_completed_at_s ON download_jobs WHEN new.terminal_completed_at_s IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected completion rejection'); END;").unwrap();
    assert!(store.request_transfer_retirement(a.token).is_err());
    counts(&store, 1, 0);
    assert!(
        store
            .download_job(a.token.job_id)
            .unwrap()
            .unwrap()
            .completed_at_s
            .is_none()
    );
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_completion;")
        .unwrap();
    assert!(store.request_transfer_retirement(a.token).unwrap());
    counts(&store, 0, 1);
    store.connection().unwrap().execute_batch("CREATE TEMP TRIGGER reject_removal AFTER UPDATE OF removed_at_s ON download_jobs WHEN new.removed_at_s IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected removal rejection'); END;").unwrap();
    assert!(store.remove_download_job(a.token.job_id).is_err());
    counts(&store, 0, 1);
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_removal;")
        .unwrap();
    assert!(store.remove_download_job(a.token.job_id).unwrap());
    counts(&store, 0, 0);
    let b = add(&store, 62, None, 8);
    store.connection().unwrap().execute_batch("CREATE TEMP TRIGGER reject_delete AFTER DELETE ON download_jobs BEGIN SELECT RAISE(ABORT,'injected deletion rejection'); END;").unwrap();
    assert!(store.delete_transfer_manifest(b.token.job_id).is_err());
    counts(&store, 1, 0);
    assert!(store.download_job(b.token.job_id).unwrap().is_some());
}

#[test]
fn mixed_100k_keysets_use_exact_indexes_and_summary_never_scans_jobs() {
    let store = MetadataStore::in_memory().unwrap();
    {
        let conn = store.connection().unwrap();
        conn.execute_batch("BEGIN;
            INSERT INTO categories(id,name,comment) VALUES(1,'Alpha',''),(2,'Beta','');
            INSERT INTO local_paths(id,display_path,native_path,search_key,sort_key,file_name_search_key,platform) VALUES(1,'/sample/output',CAST('/sample/output' AS BLOB),'/sample/output','/sample/output','output','unix');
            WITH RECURSIVE ids(id) AS (VALUES(1) UNION ALL SELECT id+1 FROM ids WHERE id<100000)
            INSERT INTO known_files(id,ed2k_hash,display_name,first_seen_at_ms,last_seen_at_ms,updated_at_ms)
                SELECT id,CAST(printf('%016x',id) AS BLOB),'retained-sample',0,0,0 FROM ids;
            INSERT INTO download_jobs(id,known_file_id,display_name,part_size_bytes,part_count,visible_state,intent,delivery_state,delivery_ownership,delivered_path_id,completed,terminal_completed_at_s,removed_at_s,category_id,created_at_s,updated_at_s)
                SELECT id,id,'retained-sample',16,0,CASE WHEN id%3=0 THEN 'completed' ELSE 'queued' END,'stopped',
                CASE WHEN id%3=0 THEN 'delivered' ELSE 'pending' END,CASE WHEN id%3=0 THEN 'unowned' ELSE 'none' END,
                CASE WHEN id%3=0 THEN 1 END,id%3=0,CASE WHEN id%3=0 THEN 1 END,CASE WHEN id%7=0 THEN 1 END,
                CASE WHEN id%10=0 THEN 1 WHEN id%13=0 THEN 2 END,0,0 FROM known_files;
            COMMIT;").unwrap();
    }
    let visible = |id: i64| id % 7 != 0;
    let category = |id: i64| {
        if id % 10 == 0 {
            Some(1)
        } else if id % 13 == 0 {
            Some(2)
        } else {
            None
        }
    };
    let matches = |id: i64, view, cat: Option<i64>| {
        visible(id)
            && cat.is_none_or(|value| category(id) == Some(value))
            && match view {
                DownloadJobView::All => true,
                DownloadJobView::Unfinished => id % 3 != 0,
                DownloadJobView::Completed => id % 3 == 0,
            }
    };
    for (view, global_index, category_index) in [
        (
            DownloadJobView::All,
            "download_jobs_visible_page_idx",
            "download_jobs_category_page_idx",
        ),
        (
            DownloadJobView::Unfinished,
            "download_jobs_unfinished_page_idx",
            "download_jobs_category_unfinished_page_idx",
        ),
        (
            DownloadJobView::Completed,
            "download_jobs_completed_page_idx",
            "download_jobs_category_completed_page_idx",
        ),
    ] {
        for category_id in [None, Some(1), Some(2)] {
            for before in [None, Some(JobId::new(50001).unwrap())] {
                let query = DownloadJobQuery {
                    view,
                    category_id,
                    before,
                    limit: 4,
                };
                let upper = before.map_or(100001, JobId::get);
                let expected: Vec<_> = (1..upper)
                    .rev()
                    .filter(|id| matches(*id, view, category_id))
                    .take(5)
                    .collect();
                let page = store.download_job_page(query).unwrap();
                assert_eq!(ids(&page), expected[..4]);
                assert!(page.has_more);
                assert_eq!(page.next_before.unwrap().get(), expected[3]);
                let conn = store.connection().unwrap();
                let mut stmt = conn
                    .prepare(&format!("EXPLAIN QUERY PLAN {}", page_sql(&query)))
                    .unwrap();
                let plan = stmt
                    .query_map(
                        params![before.map_or(i64::MAX, JobId::get), category_id, 5],
                        |row| row.get::<_, String>(3),
                    )
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let index = if category_id.is_some() {
                    category_index
                } else {
                    global_index
                };
                assert!(
                    plan.iter()
                        .any(|line| line.contains("SEARCH j") && line.contains(index)),
                    "{plan:?}"
                );
                assert!(
                    plan.iter()
                        .all(|line| !line.contains("SCAN ") && !line.contains("TEMP B-TREE")),
                    "{plan:?}"
                );
            }
        }
    }
    let unfinished = (1..=100000)
        .filter(|id| visible(*id) && id % 3 != 0)
        .count() as u64;
    let completed = (1..=100000)
        .filter(|id| visible(*id) && id % 3 == 0)
        .count() as u64;
    counts(&store, unfinished, completed);
    {
        let conn = store.connection().unwrap();
        for sql in [COUNTS_SQL, crate::transfer_store::TRANSFER_COUNTS_SQL] {
            let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let plan = stmt
                .query_map([], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                plan.iter()
                    .all(|line| line
                        .contains("SEARCH download_job_counts USING INTEGER PRIMARY KEY")),
                "{plan:?}"
            );
            let mut stmt = conn.prepare(sql).unwrap();
            stmt.query_row([], |_| Ok(())).unwrap();
            assert_eq!(stmt.get_status(rusqlite::StatementStatus::FullscanStep), 0);
            assert_eq!(stmt.get_status(rusqlite::StatementStatus::Sort), 0);
            assert!(stmt.get_status(rusqlite::StatementStatus::VmStep) < 80);
        }
        conn.execute_batch("CREATE TEMP VIEW download_jobs AS SELECT * FROM forbidden_job_scan;")
            .unwrap();
    }
    for _ in 0..8 {
        counts(&store, unfinished, completed);
        assert_eq!(
            store.transfer_counts().unwrap(),
            crate::MetadataTransferCounts {
                total: (unfinished + completed) as usize,
                completed: completed as usize,
            }
        );
    }
}

#[test]
fn summary_numeric_bounds_refuse_overflow_before_real_promotion() {
    let store = MetadataStore::in_memory().unwrap();
    let a = store
        .admit_download_job(&DownloadJobRequest {
            file_hash: "70".repeat(16),
            display_name: "count-boundary".into(),
            expected_size_bytes: Some(16),
            category_id: None,
            intent: DownloadIntent::Started,
            piece_size: 16,
        })
        .unwrap()
        .job;
    prepare_completion(&store, &a);
    store
        .connection()
        .unwrap()
        .execute_batch("UPDATE download_job_counts SET completed=9223372036854775807;")
        .unwrap();
    assert!(store.request_transfer_retirement(a.token).is_err());
    counts(&store, 1, i64::MAX as u64);
    store
        .connection()
        .unwrap()
        .execute_batch("UPDATE download_job_counts SET unfinished=9223372036854775807;")
        .unwrap();
    let request = DownloadJobRequest {
        file_hash: "71".repeat(16),
        display_name: "overflow-sample".into(),
        expected_size_bytes: Some(16),
        category_id: None,
        intent: DownloadIntent::Stopped,
        piece_size: 16,
    };
    assert!(store.admit_download_job(&request).is_err());
    assert_eq!(store.table_count("download_jobs").unwrap(), 1);
    let conn = store.connection().unwrap();
    let kinds: (String, String) = conn
        .query_row(
            "SELECT typeof(unfinished),typeof(completed) FROM download_job_counts WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(kinds, ("integer".into(), "integer".into()));
    assert!(
        conn.execute_batch("UPDATE download_job_counts SET unfinished=-1;")
            .is_err()
    );
}
