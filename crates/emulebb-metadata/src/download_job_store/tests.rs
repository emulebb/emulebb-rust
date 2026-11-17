use super::*;

fn request(hash: u8, size: Option<u64>) -> DownloadJobRequest {
    DownloadJobRequest {
        file_hash: hex::encode([hash; 16]),
        display_name: format!("job-{hash}.bin"),
        expected_size_bytes: size,
        category_id: None,
        intent: DownloadIntent::Started,
        piece_size: 1024,
    }
}

#[test]
fn new_attempt_without_size_uses_accepted_content_but_duplicate_does_not_enrich() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store.admit_download_job(&request(41, None)).unwrap().job;
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE known_files SET size_bytes=19 WHERE latest_download_job_id=?1",
            [first.token.job_id],
        )
        .unwrap();
    assert!(
        store
            .admit_download_job(&request(41, None))
            .unwrap()
            .job
            .expected_size_bytes
            .is_none()
    );
    assert!(store.remove_download_job(first.token.job_id).unwrap());
    let next = store.admit_download_job(&request(41, None)).unwrap().job;
    assert_eq!(next.expected_size_bytes, Some(19));
    assert_eq!(next.accepted_size_bytes, Some(19));
}

#[test]
fn compact_pages_bound_bytes_and_resume_without_skipping_rows() {
    let store = MetadataStore::in_memory().unwrap();
    for hash in 50..70 {
        let mut input = request(hash, None);
        input.display_name = "n".repeat(MAX_JOB_TEXT_BYTES);
        store.admit_download_job(&input).unwrap();
    }
    let first = store.download_jobs_after(None, 256, false).unwrap();
    assert!(!first.is_empty() && first.len() < 20);
    let last = first.last().unwrap().token.job_id;
    let second = store.download_jobs_after(Some(last), 256, false).unwrap();
    assert_eq!(first.len() + second.len(), 20);
    assert!(second[0].token.job_id > last);
    let mut oversized = request(70, None);
    oversized.display_name = "n".repeat(MAX_JOB_TEXT_BYTES + 1);
    assert!(store.admit_download_job(&oversized).is_err());
    let job = first[0].token;
    let path = std::env::temp_dir().join("x".repeat(MAX_JOB_PATH_BYTES + 1));
    assert!(store.start_download_job(job, &path).is_err());
    assert!(
        store
            .download_job(job.job_id)
            .unwrap()
            .unwrap()
            .selected_temp
            .is_none()
    );
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET display_name=?2 WHERE id=?1",
            params![job.job_id, oversized.display_name],
        )
        .unwrap();
    assert!(store.download_job(job.job_id).is_err());
    assert!(store.download_jobs_after(None, 256, false).is_err());
}

#[test]
fn repeated_start_and_stop_preserve_tokens_and_do_not_write_unchanged_jobs() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store
        .admit_download_job(&request(42, Some(4096)))
        .unwrap()
        .job;
    let root = std::env::temp_dir();
    let running = store
        .start_download_job(first.token, &root)
        .unwrap()
        .unwrap();
    assert_ne!(running.token, first.token);
    let before = store.connection().unwrap().total_changes();
    let unchanged = store
        .start_download_job(running.token, &root.join("other"))
        .unwrap()
        .unwrap();
    assert_eq!(unchanged, running);
    assert_eq!(store.connection().unwrap().total_changes(), before);

    assert!(store.stop_download_job(running.token).unwrap());
    let stopped = store.download_job(running.token.job_id).unwrap().unwrap();
    let before = store.connection().unwrap().total_changes();
    assert!(!store.stop_download_job(stopped.token).unwrap());
    assert_eq!(
        store.download_job(stopped.token.job_id).unwrap().unwrap(),
        stopped
    );
    assert_eq!(store.connection().unwrap().total_changes(), before);

    let resumed = store
        .start_download_job(stopped.token, &root.join("other"))
        .unwrap()
        .unwrap();
    assert_ne!(resumed.token, stopped.token);
    assert_eq!(resumed.selected_temp, running.selected_temp);
    assert_eq!(resumed.storage, running.storage);
    let fault =
        crate::DownloadJobStorageFailure::new("TEMP_UNAVAILABLE", "Sample storage offline", 1)
            .unwrap();
    let failed = store
        .fail_download_job_storage(resumed.token, &fault)
        .unwrap()
        .job
        .unwrap();
    let retried = store
        .start_download_job(failed.token, &root)
        .unwrap()
        .unwrap();
    assert_ne!(retried.token, failed.token);
    assert!(retried.storage_failure.is_none());
    assert_eq!(retried.storage, running.storage);
}

#[test]
fn job_ids_are_positive_canonical_decimal_strings() {
    for invalid in [
        "",
        "0",
        "01",
        "-1",
        "+1",
        " 1",
        "1 ",
        "1.0",
        "9223372036854775808",
    ] {
        assert!(invalid.parse::<JobId>().is_err(), "{invalid}");
    }
    assert!(JobId::new(0).is_err());
    assert_eq!(
        i64::MAX.to_string().parse::<JobId>().unwrap().to_string(),
        i64::MAX.to_string()
    );
}

#[test]
fn deleted_highest_job_id_is_never_reallocated() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store.admit_download_job(&request(20, None)).unwrap().job;
    assert!(store.delete_transfer_manifest(first.token.job_id).unwrap());
    let next = store.admit_download_job(&request(20, None)).unwrap().job;
    assert!(next.token.job_id > first.token.job_id);
    assert_eq!(store.table_count("known_files").unwrap(), 1);
}

#[test]
fn duplicate_admission_is_unchanged_and_never_enriches_unknown_size() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store.admit_download_job(&request(1, None)).unwrap();
    let manifest = store
        .download_job_manifest(first.job.token.job_id)
        .unwrap()
        .unwrap();
    assert!(manifest.expected_size_bytes.is_none());
    assert!(manifest.pieces.is_empty());
    let mut duplicate = request(1, Some(4096));
    duplicate.display_name = "different.bin".into();
    duplicate.intent = DownloadIntent::Stopped;
    let second = store.admit_download_job(&duplicate).unwrap();
    assert!(!second.created);
    assert_eq!(second.job, first.job);
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(
        store
            .learn_download_job_size(first.job.token, 4096)
            .unwrap()
    );
    assert!(
        !store
            .learn_download_job_size(first.job.token, 4096)
            .unwrap()
    );
    assert!(
        store
            .admit_download_job(&request(1, Some(4097)))
            .unwrap_err()
            .is::<MetadataContentConflict>()
    );
    let actual = store.download_job(first.job.token.job_id).unwrap().unwrap();
    assert_eq!(actual.expected_size_bytes, Some(4096));
    assert_eq!(actual.accepted_size_bytes, None);
}

#[test]
fn duplicate_admission_checks_accepted_size_even_with_unknown_attempt_size() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store.admit_download_job(&request(2, None)).unwrap().job;
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE known_files SET size_bytes=19 WHERE latest_download_job_id=?1",
            [first.token.job_id],
        )
        .unwrap();
    assert!(
        store
            .admit_download_job(&request(2, Some(20)))
            .unwrap_err()
            .is::<MetadataContentConflict>()
    );
    let duplicate = store.admit_download_job(&request(2, Some(19))).unwrap();
    assert!(!duplicate.created);
    assert_eq!(duplicate.job.expected_size_bytes, None);
    assert_eq!(duplicate.job.accepted_size_bytes, Some(19));
    assert!(
        store
            .connection()
            .unwrap()
            .execute("UPDATE known_files SET size_bytes=20", [])
            .is_err()
    );
}

#[test]
fn concurrent_duplicate_admission_allocates_one_job_and_one_head() {
    let store = MetadataStore::in_memory().unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let workers = (0..2)
        .map(|_| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.admit_download_job(&request(3, Some(17))).unwrap()
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.created).count(), 1);
    assert_eq!(results[0].job.token, results[1].job.token);
    assert_eq!(store.table_count("download_jobs").unwrap(), 1);
    assert_eq!(
        store
            .latest_download_job(&request(3, None).file_hash)
            .unwrap()
            .unwrap()
            .token,
        results[0].job.token
    );
}

#[test]
fn latest_head_and_admission_roll_back_together() {
    let store = MetadataStore::in_memory().unwrap();
    store.connection().unwrap().execute_batch("CREATE TEMP TRIGGER reject_head BEFORE UPDATE OF latest_download_job_id ON known_files BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(store.admit_download_job(&request(4, None)).is_err());
    assert_eq!(store.table_count("download_jobs").unwrap(), 0);
    assert_eq!(store.table_count("known_files").unwrap(), 0);
}

#[test]
fn removed_pending_cleanup_does_not_block_new_job_or_change_its_head() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store.admit_download_job(&request(5, Some(16))).unwrap().job;
    assert!(store.request_transfer_deletion(first.token.job_id).unwrap());
    let second = store.admit_download_job(&request(5, Some(16))).unwrap();
    assert!(second.created);
    assert!(second.job.token.job_id > first.token.job_id);
    if store
        .transfer_retirement_pending(first.token.job_id)
        .unwrap()
    {
        assert!(
            store
                .finalize_transfer_retirement(first.token.job_id)
                .unwrap()
        );
    }
    assert!(
        store
            .finalize_transfer_deletion(first.token.job_id)
            .unwrap()
    );
    assert_eq!(
        store
            .latest_download_job(&first.file_hash)
            .unwrap()
            .unwrap(),
        second.job
    );
    assert!(store.remove_download_job(second.job.token.job_id).unwrap());
    assert!(
        store
            .latest_download_job(&first.file_hash)
            .unwrap()
            .is_none()
    );
    let third = store.admit_download_job(&request(5, Some(16))).unwrap().job;
    assert!(third.token.job_id > second.job.token.job_id);
}

#[test]
fn latest_pointer_and_job_content_are_database_enforced() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store.admit_download_job(&request(6, None)).unwrap().job;
    let second = store.admit_download_job(&request(7, None)).unwrap().job;
    let conn = store.connection().unwrap();
    assert!(
        conn.execute(
            "UPDATE known_files SET latest_download_job_id=?1 WHERE latest_download_job_id=?2",
            params![second.token.job_id, first.token.job_id]
        )
        .is_err()
    );
    assert!(conn.execute("UPDATE download_jobs SET known_file_id=(SELECT known_file_id FROM download_jobs WHERE id=?2) WHERE id=?1",params![first.token.job_id,second.token.job_id]).is_err());
    assert!(
        conn.execute(
            "UPDATE download_jobs SET id=100 WHERE id=?1",
            [first.token.job_id]
        )
        .is_err()
    );
}

#[test]
fn fixed_temp_and_generation_survive_stop_and_restart() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store.admit_download_job(&request(8, None)).unwrap().job;
    let fixed = std::env::temp_dir().join("fixed-download-root");
    let alternate = std::env::temp_dir().join("other-download-root");
    let running = store
        .start_download_job(first.token, &fixed)
        .unwrap()
        .unwrap();
    assert_eq!(running.selected_temp.as_deref(), Some(fixed.as_path()));
    assert!(running.token.generation > first.token.generation);
    assert!(!store.stop_download_job(first.token).unwrap());
    assert!(store.stop_download_job(running.token).unwrap());
    let stopped = store.download_job(first.token.job_id).unwrap().unwrap();
    let resumed = store
        .start_download_job(stopped.token, &alternate)
        .unwrap()
        .unwrap();
    assert_eq!(resumed.selected_temp.as_deref(), Some(fixed.as_path()));
    assert!(
        store
            .start_download_job(stopped.token, &alternate)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE download_jobs SET selected_temp_path_id=NULL WHERE id=?1",
                [first.token.job_id]
            )
            .is_err()
    );
}

#[test]
fn nullable_sizes_are_distinct_from_zero_and_pages_are_bounded() {
    let store = MetadataStore::in_memory().unwrap();
    assert!(store.admit_download_job(&request(9, Some(0))).is_err());
    for hash in 10..14 {
        store.admit_download_job(&request(hash, None)).unwrap();
    }
    let first = store.download_jobs_after(None, 2, true).unwrap();
    let second = store
        .download_jobs_after(Some(first[1].token.job_id), 2, true)
        .unwrap();
    assert_eq!(first.len(), 2);
    assert_eq!(second.len(), 2);
    assert!(first[1].token.job_id < second[0].token.job_id);
    assert!(
        first
            .iter()
            .chain(&second)
            .all(|job| job.expected_size_bytes.is_none() && job.accepted_size_bytes.is_none())
    );
    assert!(store.download_jobs_after(None, 257, false).is_err());
    // Storage can express future real zero-byte facts without calling them unknown.
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET expected_size_bytes=0 WHERE id=?1",
            [first[0].token.job_id],
        )
        .unwrap();
    assert_eq!(
        store
            .download_job(first[0].token.job_id)
            .unwrap()
            .unwrap()
            .expected_size_bytes,
        Some(0)
    );
}

#[test]
fn physical_storage_is_fixed_and_distinct_between_fresh_profiles() {
    let first = MetadataStore::in_memory().unwrap();
    let second = MetadataStore::in_memory().unwrap();
    let a = first
        .admit_download_job(&request(91, Some(16)))
        .unwrap()
        .job;
    let b = second
        .admit_download_job(&request(91, Some(16)))
        .unwrap()
        .job;
    assert_eq!(a.token.job_id, b.token.job_id);
    let base = std::env::temp_dir().join("shared-download-temp");
    let a = first.start_download_job(a.token, &base).unwrap().unwrap();
    let b = second.start_download_job(b.token, &base).unwrap().unwrap();
    let storage = a.storage.clone().unwrap();
    assert!(storage.path.starts_with(&base));
    assert_ne!(storage.path, b.storage.unwrap().path);
    assert!(storage.identity.is_none());
    let identity = crate::NativeFileIdentity::Unix {
        device_id: 11,
        inode_number: 12,
    };
    assert!(
        first
            .establish_download_job_storage(a.token, identity)
            .unwrap()
    );
    assert!(first.stop_download_job(a.token).unwrap());
    assert!(
        !first
            .establish_download_job_storage(a.token, identity)
            .unwrap()
    );
    let stopped = first.download_job(a.token.job_id).unwrap().unwrap();
    let resumed = first
        .start_download_job(stopped.token, &base.join("ignored-new-base"))
        .unwrap()
        .unwrap();
    let established = resumed.storage.unwrap();
    assert_eq!(established.path, storage.path);
    assert_eq!(established.marker_id, storage.marker_id);
    assert_eq!(established.identity, Some(identity));
    assert!(
        first
            .connection()
            .unwrap()
            .execute(
                "UPDATE download_jobs SET storage_directory_marker_id=?2 WHERE id=?1",
                params![a.token.job_id, uuid::Uuid::new_v4().to_string()]
            )
            .is_err()
    );
    assert!(first.request_transfer_deletion(a.token.job_id).unwrap());
    assert_eq!(
        first
            .download_job_retirement(a.token.job_id)
            .unwrap()
            .and_then(|intent| intent.authority),
        Some(crate::MetadataTransferDirectoryDeletionAuthority {
            identity,
            marker_id: storage.marker_id
        })
    );
}

#[test]
fn allocation_intent_without_established_identity_never_authorizes_cleanup() {
    let store = MetadataStore::in_memory().unwrap();
    let job = store
        .admit_download_job(&request(92, Some(16)))
        .unwrap()
        .job;
    let job = store
        .start_download_job(job.token, &std::env::temp_dir())
        .unwrap()
        .unwrap();
    let storage = job.storage.clone().unwrap();
    std::fs::create_dir(&storage.path).unwrap();
    let foreign = storage.path.join("unknown.bin");
    std::fs::write(&foreign, b"preserve unknown allocation residue").unwrap();
    assert!(store.request_transfer_deletion(job.token.job_id).unwrap());
    let intent = store
        .download_job_retirement(job.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(intent.source_path.as_ref(), Some(&storage.path));
    assert!(intent.target_path.is_some());
    assert!(intent.authority.is_none());
    assert_eq!(
        std::fs::read(&foreign).unwrap(),
        b"preserve unknown allocation residue"
    );
    assert_eq!(
        store
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .storage,
        Some(storage.clone())
    );
    assert!(
        !store
            .establish_download_job_storage(
                job.token,
                crate::NativeFileIdentity::Unix {
                    device_id: 1,
                    inode_number: 2
                }
            )
            .unwrap()
    );
    std::fs::remove_file(foreign).unwrap();
    std::fs::remove_dir(storage.path).unwrap();
}

#[test]
fn stop_preserves_internal_data_but_remove_reserves_only_its_exact_internal_retirement() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store
        .admit_download_job(&request(61, Some(16)))
        .unwrap()
        .job;
    let temp = std::env::temp_dir().join("job-remove-internal");
    let running = store
        .start_download_job(first.token, &temp)
        .unwrap()
        .unwrap();
    let identity = crate::NativeFileIdentity::Unix {
        device_id: 7,
        inode_number: 9,
    };
    assert!(
        store
            .establish_download_job_storage(running.token, identity)
            .unwrap()
    );
    assert!(store.stop_download_job(running.token).unwrap());
    // A stopped unfinished job remains resumable: the schema itself rejects
    // retiring its pieces without completion or explicit logical removal.
    assert!(
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE download_jobs SET internal_storage_retired = 1 WHERE id = ?1",
                [first.token.job_id.get()],
            )
            .is_err()
    );
    assert!(
        !store
            .transfer_retirement_pending(first.token.job_id)
            .unwrap()
    );
    assert!(store.remove_download_job(first.token.job_id).unwrap());
    let removed = store.download_job(first.token.job_id).unwrap().unwrap();
    assert!(removed.completed_at_s.is_none());
    assert!(removed.removed_at_s.is_some());
    assert!(
        !store
            .transfer_deletion_requested(first.token.job_id)
            .unwrap()
    );
    assert!(
        store
            .latest_download_job(&first.file_hash)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .download_job_retirement(first.token.job_id)
            .unwrap()
            .unwrap()
            .authority
            .unwrap()
            .identity,
        identity
    );
    let next = store
        .admit_download_job(&request(61, Some(16)))
        .unwrap()
        .job;
    let next = store
        .start_download_job(next.token, &temp)
        .unwrap()
        .unwrap();
    assert_ne!(
        removed.storage.as_ref().unwrap().path,
        next.storage.as_ref().unwrap().path
    );
    assert!(
        store
            .finalize_transfer_retirement(first.token.job_id)
            .unwrap()
    );
    assert_eq!(
        store
            .latest_download_job(&first.file_hash)
            .unwrap()
            .unwrap()
            .token,
        next.token
    );
    assert!(
        store
            .download_job(first.token.job_id)
            .unwrap()
            .unwrap()
            .internal_storage_retired
    );
    assert_eq!(store.table_count("known_files").unwrap(), 1);
}

#[test]
fn current_job_and_page_reject_marker_nul_suffix_before_string_allocation() {
    let store = MetadataStore::in_memory().unwrap();
    let job = store
        .admit_download_job(&request(117, Some(16)))
        .unwrap()
        .job;
    let marker = format!("{}\0{}", uuid::Uuid::new_v4(), "x".repeat(1024 * 1024));
    {
        let mut conn = store.connection().unwrap();
        let tx = conn.transaction().unwrap();
        let temp = std::env::temp_dir();
        let storage = temp.join(format!("job-marker-{}", uuid::Uuid::new_v4()));
        let temp_id = upsert_local_path(&tx, &temp).unwrap();
        let storage_id = upsert_local_path(&tx, &storage).unwrap();
        // First assignment preserves every storage immutability trigger; the
        // NUL suffix passes SQLite length(TEXT)=36 but is not a bounded UUID.
        tx.execute(
            "UPDATE download_jobs SET selected_temp_path_id=?2,storage_path_id=?3,
            storage_directory_marker_id=?4 WHERE id=?1",
            params![job.token.job_id, temp_id, storage_id, marker],
        )
        .unwrap();
        let lengths:(i64,i64)=tx.query_row("SELECT length(storage_directory_marker_id),length(CAST(storage_directory_marker_id AS BLOB))
            FROM download_jobs WHERE id=?1",[job.token.job_id],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(lengths.0, 36);
        assert!(lengths.1 > 1024 * 1024);
        tx.commit().unwrap();
    }
    let error = store.download_job(job.token.job_id).unwrap_err();
    assert!(
        error.to_string().contains("job UUID exceeds byte bound"),
        "{error:#}"
    );
    let error = store.download_jobs_after(None, 16, false).unwrap_err();
    assert!(
        error.to_string().contains("job UUID exceeds byte bound"),
        "{error:#}"
    );
}

fn storage_failure() -> crate::DownloadJobStorageFailure {
    crate::DownloadJobStorageFailure::new(
        "storage_unavailable",
        "Sample storage is unavailable",
        123,
    )
    .unwrap()
}

#[test]
fn storage_failure_survives_reopen_stop_and_reopen_until_admitted_start() {
    let root = std::path::PathBuf::from(std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT").unwrap())
        .join("tmp")
        .join(format!("storage-failure-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("metadata.db");
    let store = MetadataStore::open(&database).unwrap();
    let first = store.admit_download_job(&request(120, None)).unwrap().job;
    let running = store
        .start_download_job(first.token, &root)
        .unwrap()
        .unwrap();
    let outcome = store
        .fail_download_job_storage(running.token, &storage_failure())
        .unwrap();
    assert!(outcome.applied);
    let failed = outcome.job.unwrap();
    assert_eq!(failed.intent, DownloadIntent::Started);
    assert_eq!(failed.token.generation, running.token.generation + 1);
    assert_eq!(failed.storage_failure, Some(storage_failure()));
    let duplicate = store.admit_download_job(&request(120, Some(16))).unwrap();
    assert!(!duplicate.created);
    assert_eq!(duplicate.job, failed);
    assert!(!store.learn_download_job_size(running.token, 16).unwrap());
    assert!(!store.stop_download_job(running.token).unwrap());
    assert!(
        store
            .download_jobs_after(None, 256, true)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.download_jobs_after(None, 256, false).unwrap(),
        vec![failed.clone()]
    );
    drop(store);
    let store = MetadataStore::open(&database).unwrap();
    assert_eq!(
        store.download_job(failed.token.job_id).unwrap(),
        Some(failed.clone())
    );
    assert!(store.stop_download_job(failed.token).unwrap());
    let stopped = store.download_job(failed.token.job_id).unwrap().unwrap();
    assert_eq!(stopped.intent, DownloadIntent::Stopped);
    assert_eq!(stopped.storage_failure, Some(storage_failure()));
    drop(store);
    let store = MetadataStore::open(&database).unwrap();
    assert_eq!(
        store.download_job(stopped.token.job_id).unwrap(),
        Some(stopped.clone())
    );
    assert!(
        store
            .start_download_job(failed.token, &root)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .start_download_job(stopped.token, std::path::Path::new("relative"))
            .is_err()
    );
    assert_eq!(
        store.download_job(stopped.token.job_id).unwrap(),
        Some(stopped.clone())
    );
    let restarted = store
        .start_download_job(stopped.token, &root.join("other"))
        .unwrap()
        .unwrap();
    assert_eq!(restarted.token.generation, stopped.token.generation + 1);
    assert!(restarted.storage_failure.is_none());
    assert_eq!(restarted.storage, stopped.storage);
    assert_eq!(restarted.selected_temp, stopped.selected_temp);
    assert_eq!(
        store.download_jobs_after(None, 256, true).unwrap(),
        vec![restarted.clone()]
    );
    assert!(
        !store
            .fail_download_job_storage(running.token, &storage_failure())
            .unwrap()
            .applied
    );
    drop(store);
    let store = MetadataStore::open(&database).unwrap();
    assert_eq!(
        store.download_job(restarted.token.job_id).unwrap(),
        Some(restarted)
    );
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn failure_and_start_race_obeys_the_captured_generation() {
    for hash in 121..129 {
        let store = MetadataStore::in_memory().unwrap();
        let job = store
            .admit_download_job(&request(hash, Some(16)))
            .unwrap()
            .job;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let other = store.clone();
        let ready = barrier.clone();
        let thread = std::thread::spawn(move || {
            ready.wait();
            other
                .fail_download_job_storage(job.token, &storage_failure())
                .unwrap()
        });
        barrier.wait();
        let started = store
            .start_download_job(job.token, &std::env::temp_dir())
            .unwrap();
        let failed = thread.join().unwrap();
        let current = store.download_job(job.token.job_id).unwrap().unwrap();
        assert_eq!(current.token.generation, job.token.generation + 1);
        if let Some(started) = started {
            assert!(!failed.applied);
            assert_eq!(failed.job, Some(started.clone()));
            assert_eq!(current, started);
            assert!(current.storage_failure.is_none());
        } else {
            assert!(failed.applied);
            assert_eq!(failed.job, Some(current.clone()));
            assert_eq!(current.storage_failure, Some(storage_failure()));
        }
    }
}

#[test]
fn verified_preterminal_failure_is_eligible_but_terminal_and_removed_cleanup_are_not() {
    let store = MetadataStore::in_memory().unwrap();
    let job = store
        .admit_download_job(&request(130, Some(16)))
        .unwrap()
        .job;
    store.connection().unwrap().execute(
        "UPDATE download_jobs SET completed=1,visible_state='completed',final_rehash_pending=0 WHERE id=?1", [job.token.job_id]).unwrap();
    assert_eq!(
        store.pending_delivery_jobs_after(None, 256).unwrap(),
        vec![job.token.job_id]
    );
    let failed = store
        .fail_download_job_storage(job.token, &storage_failure())
        .unwrap();
    assert!(failed.applied);
    assert!(failed.job.as_ref().unwrap().payload_verified);
    let attempt = uuid::Uuid::new_v4();
    let temp = std::env::temp_dir();
    assert!(
        store
            .begin_transfer_delivery_attempt(
                job.token,
                attempt,
                &temp.join("sample-output.bin"),
                &temp.join(format!(".emulebb-delivery-{attempt}.tmp"))
            )
            .is_err()
    );
    assert!(
        store
            .download_job_delivery_attempt(job.token.job_id)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .pending_delivery_jobs_after(None, 256)
            .unwrap()
            .is_empty()
    );
    let resumed = store
        .start_download_job(failed.job.unwrap().token, &std::env::temp_dir())
        .unwrap()
        .unwrap();
    assert_eq!(
        store.pending_delivery_jobs_after(None, 256).unwrap(),
        vec![job.token.job_id]
    );
    {
        let mut conn = store.connection().unwrap();
        let tx = conn.transaction().unwrap();
        let path =
            upsert_local_path(&tx, &std::env::temp_dir().join("sample-completed.bin")).unwrap();
        tx.execute("UPDATE download_jobs SET delivery_state='delivered',delivery_ownership='unowned',delivered_path_id=?2,terminal_completed_at_s=124 WHERE id=?1", params![job.token.job_id,path]).unwrap();
        tx.commit().unwrap();
    }
    let terminal = store.download_job(job.token.job_id).unwrap().unwrap();
    let refused = store
        .fail_download_job_storage(resumed.token, &storage_failure())
        .unwrap();
    assert!(!refused.applied);
    assert_eq!(refused.job, Some(terminal.clone()));
    assert!(
        store
            .start_download_job(terminal.token, &std::env::temp_dir())
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .download_jobs_after(None, 256, true)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .pending_delivery_jobs_after(None, 256)
            .unwrap()
            .is_empty()
    );
    let job = store
        .admit_download_job(&request(131, Some(16)))
        .unwrap()
        .job;
    assert!(store.remove_download_job(job.token.job_id).unwrap());
    let removed = store.download_job(job.token.job_id).unwrap().unwrap();
    for token in [job.token, removed.token] {
        let refused = store
            .fail_download_job_storage(token, &storage_failure())
            .unwrap();
        assert!(!refused.applied);
        assert_eq!(refused.job, Some(removed.clone()));
    }
    assert!(removed.storage_failure.is_none());
    assert!(
        store
            .finalize_transfer_retirement(job.token.job_id)
            .unwrap()
    );
    assert!(store.delete_transfer_manifest(job.token.job_id).unwrap());
    let missing = store
        .fail_download_job_storage(removed.token, &storage_failure())
        .unwrap();
    assert!(!missing.applied);
    assert!(missing.job.is_none());
}

#[test]
fn failure_byte_nul_and_timestamp_bounds_are_enforced_by_api_and_schema() {
    use crate::DownloadJobStorageFailure as Failure;
    assert!(Failure::new(&"\u{e9}".repeat(32), &"\u{e9}".repeat(2048), 0).is_ok());
    for (code, message, at) in [
        ("".to_owned(), String::new(), 0),
        ("\u{e9}".repeat(33), String::new(), 0),
        ("x".into(), "\u{e9}".repeat(2049), 0),
        ("x\0".into(), String::new(), 0),
        ("x".into(), "message\0suffix".into(), 0),
        ("x".into(), String::new(), -1),
    ] {
        assert!(Failure::new(&code, &message, at).is_err());
    }
    let store = MetadataStore::in_memory().unwrap();
    let job = store
        .admit_download_job(&request(132, Some(16)))
        .unwrap()
        .job;
    for sql in [
        "storage_failure_code='x'",
        "storage_failure_message='x'",
        "storage_failed_at_s=0",
        "storage_failure_code='',storage_failure_message='',storage_failed_at_s=0",
        "storage_failure_code='x',storage_failure_message='',storage_failed_at_s=-1",
        "storage_failure_code='x'||char(0),storage_failure_message='',storage_failed_at_s=0",
        "storage_failure_code='x',storage_failure_message='x'||char(0),storage_failed_at_s=0",
        "storage_failure_code=printf('%065d',0),storage_failure_message='',storage_failed_at_s=0",
        "storage_failure_code='x',storage_failure_message=printf('%04097d',0),storage_failed_at_s=0",
    ] {
        assert!(
            store
                .connection()
                .unwrap()
                .execute(
                    &format!("UPDATE download_jobs SET {sql} WHERE id=?1"),
                    [job.token.job_id]
                )
                .is_err(),
            "{sql}"
        );
        assert_eq!(
            store.download_job(job.token.job_id).unwrap(),
            Some(job.clone())
        );
    }
    let maximum = Failure::new(&"\u{e9}".repeat(32), &"\u{e9}".repeat(2048), i64::MAX).unwrap();
    let failed = store
        .fail_download_job_storage(job.token, &maximum)
        .unwrap()
        .job
        .unwrap();
    assert_eq!(failed.storage_failure, Some(maximum));
    assert_eq!(
        store.download_jobs_after(None, 1, false).unwrap(),
        vec![failed]
    );
}

#[test]
fn failed_start_transaction_rolls_back_failure_and_path_assignment() {
    let store = MetadataStore::in_memory().unwrap();
    let job = store
        .admit_download_job(&request(133, Some(16)))
        .unwrap()
        .job;
    let failed = store
        .fail_download_job_storage(job.token, &storage_failure())
        .unwrap()
        .job
        .unwrap();
    store.connection().unwrap().execute_batch("CREATE TEMP TRIGGER refuse_start BEFORE UPDATE OF intent ON download_jobs WHEN new.intent='started' BEGIN SELECT RAISE(ABORT,'injected start failure'); END;").unwrap();
    assert!(
        store
            .start_download_job(failed.token, &std::env::temp_dir())
            .is_err()
    );
    assert_eq!(store.download_job(job.token.job_id).unwrap(), Some(failed));
    assert_eq!(store.table_count("local_paths").unwrap(), 0);
}

#[test]
fn compact_failure_pages_charge_maximum_utf8_diagnostics_and_resume() {
    let store = MetadataStore::in_memory().unwrap();
    let failure =
        crate::DownloadJobStorageFailure::new(&"\u{e9}".repeat(32), &"\u{e9}".repeat(2048), 123)
            .unwrap();
    for hash in 140..204 {
        let mut input = request(hash, None);
        input.display_name = "n".repeat(16_384);
        let job = store.admit_download_job(&input).unwrap().job;
        assert!(
            store
                .fail_download_job_storage(job.token, &failure)
                .unwrap()
                .applied
        );
    }
    // Each row charges 32 KiB for the name, 2 KiB fixed overhead, and
    // 4160 bytes for its maximum UTF-8 diagnostic. The 54th row exceeds 2 MiB.
    let first = store.download_jobs_after(None, 256, false).unwrap();
    assert_eq!(first.len(), 53);
    let second = store
        .download_jobs_after(Some(first.last().unwrap().token.job_id), 256, false)
        .unwrap();
    assert_eq!(second.len(), 11);
    let mut previous = None;
    for job in first.iter().chain(&second) {
        assert!(previous.is_none_or(|id| job.token.job_id > id));
        previous = Some(job.token.job_id);
        assert_eq!(job.storage_failure.as_ref(), Some(&failure));
    }
    assert!(
        store
            .download_jobs_after(previous, 256, false)
            .unwrap()
            .is_empty()
    );
}
