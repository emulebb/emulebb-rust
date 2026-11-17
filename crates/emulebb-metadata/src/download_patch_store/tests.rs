use super::*;
use crate::{DownloadIntent, DownloadJobRequest, JobId, store::upsert_local_path};

fn job(store: &MetadataStore, size: Option<u64>) -> crate::DownloadJobRecord {
    store
        .admit_download_job(&DownloadJobRequest {
            file_hash: "71".repeat(16),
            display_name: "Sample.bin".into(),
            expected_size_bytes: size,
            category_id: None,
            intent: DownloadIntent::Stopped,
            piece_size: 16,
        })
        .unwrap()
        .job
}

#[test]
fn combined_patch_commits_once_without_allocating_and_equal_values_are_unchanged() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store, None);
    let category = store
        .create_category("Media", None, None, "", &std::env::temp_dir())
        .unwrap();
    let patch = MetadataDownloadPatch {
        name: Some("Renamed.bin".into()),
        category_id: Some(Some(category.id)),
        size_bytes: Some(32),
    };
    let result = store
        .patch_download_job(job.token, &patch)
        .unwrap()
        .unwrap();
    assert!(result.changed && result.size_changed);
    let current = store.download_job(job.token.job_id).unwrap().unwrap();
    assert_eq!(current.token, job.token);
    assert_eq!(current.display_name, "Renamed.bin");
    assert_eq!(current.category_id, Some(category.id));
    assert_eq!(current.expected_size_bytes, Some(32));
    assert_eq!(current.intent, DownloadIntent::Stopped);
    assert!(current.storage.is_none() && current.selected_temp.is_none());
    let no_op = store
        .patch_download_job(job.token, &patch)
        .unwrap()
        .unwrap();
    assert!(!no_op.changed && !no_op.size_changed);
    assert_eq!(
        store
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .updated_at_s,
        current.updated_at_s
    );
    let clear = MetadataDownloadPatch {
        category_id: Some(None),
        ..Default::default()
    };
    assert!(
        store
            .patch_download_job(job.token, &clear)
            .unwrap()
            .unwrap()
            .changed
    );
    assert_eq!(
        store.download_job_category(job.token.job_id).unwrap(),
        Some(None)
    );
}

#[test]
fn invalid_category_or_size_never_commits_the_other_fields() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store, Some(32));
    for (patch, expected) in [
        (
            MetadataDownloadPatch {
                name: Some("Renamed.bin".into()),
                category_id: Some(Some(999)),
                size_bytes: Some(32),
            },
            DownloadPatchError::CategoryNotFound,
        ),
        (
            MetadataDownloadPatch {
                name: Some("Renamed.bin".into()),
                category_id: Some(None),
                size_bytes: Some(33),
            },
            DownloadPatchError::SizeConflict,
        ),
    ] {
        let error = store.patch_download_job(job.token, &patch).unwrap_err();
        assert_eq!(error.downcast_ref::<DownloadPatchError>(), Some(&expected));
        assert_eq!(store.download_job(job.token.job_id).unwrap().unwrap(), job);
    }
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE known_files SET size_bytes=33 WHERE ed2k_hash=?1",
            [vec![0x71; 16]],
        )
        .unwrap();
    let error = store
        .patch_download_job(
            job.token,
            &MetadataDownloadPatch {
                name: Some("Renamed.bin".into()),
                size_bytes: Some(32),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<DownloadPatchError>(),
        Some(&DownloadPatchError::SizeConflict)
    );
    assert_eq!(
        store
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .display_name,
        job.display_name
    );
}

#[test]
fn fixed_delivery_attempt_blocks_rename_but_allows_category_metadata_only() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store, Some(32));
    let category = store
        .create_category("Media", None, None, "", &std::env::temp_dir())
        .unwrap();
    let (target, staging) = {
        let mut conn = store.connection().unwrap();
        let tx = conn.transaction().unwrap();
        let target =
            upsert_local_path(&tx, &std::env::temp_dir().join("patch-target.bin")).unwrap();
        let staging =
            upsert_local_path(&tx, &std::env::temp_dir().join("patch-staging.bin")).unwrap();
        tx.execute("INSERT INTO download_delivery_attempts(job_id,attempt_id,phase,target_path_id,staging_path_id,created_at_s,updated_at_s)
            VALUES(?1,?2,'prepared',?3,?4,1,1)", params![job.token.job_id, uuid::Uuid::new_v4().to_string(), target, staging]).unwrap();
        tx.commit().unwrap();
        (target, staging)
    };
    let error = store
        .patch_download_job(
            job.token,
            &MetadataDownloadPatch {
                name: Some("Renamed.bin".into()),
                category_id: Some(Some(category.id)),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<DownloadPatchError>(),
        Some(&DownloadPatchError::NameFixed)
    );
    assert_eq!(store.download_job(job.token.job_id).unwrap().unwrap(), job);
    assert!(
        store
            .patch_download_job(
                job.token,
                &MetadataDownloadPatch {
                    category_id: Some(Some(category.id)),
                    ..Default::default()
                }
            )
            .unwrap()
            .unwrap()
            .changed
    );
    let paths = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT target_path_id,staging_path_id FROM download_delivery_attempts WHERE job_id=?1",
            [job.token.job_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .unwrap();
    assert_eq!(paths, (target, staging));
}

#[test]
fn stale_tokens_and_sql_failure_leave_the_whole_candidate_unchanged() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store, None);
    let patch = MetadataDownloadPatch {
        name: Some("Renamed.bin".into()),
        size_bytes: Some(32),
        ..Default::default()
    };
    let stale = JobToken {
        job_id: job.token.job_id,
        generation: job.token.generation + 1,
    };
    assert_eq!(
        store
            .patch_download_job(stale, &patch)
            .unwrap_err()
            .downcast_ref::<DownloadPatchError>(),
        Some(&DownloadPatchError::Stale)
    );
    store.connection().unwrap().execute_batch("CREATE TRIGGER fail_patch BEFORE UPDATE OF display_name ON download_jobs
        WHEN new.display_name='Renamed.bin' BEGIN SELECT RAISE(ABORT,'injected patch write failure'); END;").unwrap();
    assert!(store.patch_download_job(job.token, &patch).is_err());
    assert_eq!(store.download_job(job.token.job_id).unwrap().unwrap(), job);
    assert!(
        store
            .patch_download_job(
                JobToken {
                    job_id: JobId::new(999).unwrap(),
                    generation: 1
                },
                &patch
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn invalid_scalar_input_is_rejected_before_mutation() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store, None);
    for patch in [
        MetadataDownloadPatch {
            name: Some(" ".into()),
            ..Default::default()
        },
        MetadataDownloadPatch {
            name: Some("n".repeat(65_537)),
            ..Default::default()
        },
        MetadataDownloadPatch {
            size_bytes: Some(0),
            ..Default::default()
        },
        MetadataDownloadPatch {
            size_bytes: Some(u64::MAX),
            ..Default::default()
        },
        MetadataDownloadPatch {
            category_id: Some(Some(0)),
            ..Default::default()
        },
    ] {
        assert!(store.patch_download_job(job.token, &patch).is_err());
        assert_eq!(store.download_job(job.token.job_id).unwrap().unwrap(), job);
    }
}
