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
            .transfer_directory_deletion_authority(a.token.job_id)
            .unwrap(),
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
    assert!(store.request_transfer_deletion(job.token.job_id).unwrap());
    assert!(
        store
            .transfer_directory_deletion_authority(job.token.job_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .storage,
        Some(storage)
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
}
