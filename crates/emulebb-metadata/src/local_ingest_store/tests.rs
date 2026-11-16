use super::*;

fn capture_jobs(
    db: &MetadataStore,
    content: &MetadataVerifiedLocalContent,
    expected: Option<&MetadataLocalFileInstance>,
) -> Vec<MetadataIngestJob> {
    let mut hashes = vec![content.file_hash.clone()];
    if let Some(expected) = expected {
        hashes.push(expected.file_hash.clone());
    }
    hashes.sort_unstable();
    hashes.dedup();
    db.capture_local_ingest_jobs(&hashes).unwrap()
}

fn content(root: &std::path::Path, byte: &str) -> MetadataVerifiedLocalContent {
    MetadataVerifiedLocalContent {
        secondary_identity: None,
        file_hash: byte.repeat(16),
        display_name: "Sample.bin".into(),
        file_size: 184_321,
        part_size: 9_728_000,
        md4_hashset: Vec::new(),
        aich_root: Some("22".repeat(20)),
        aich_hashset: Vec::new(),
        path: root.join("sample.bin"),
        fingerprint: crate::NativeFileFingerprint {
            identity: crate::NativeFileIdentity::Unix {
                device_id: 1,
                inode_number: 2,
            },
            size_bytes: 184_321,
            modified: crate::NativeFileTimestamp::new(1700000000, 0).unwrap(),
            changed: None,
        },
        upload_priority: "normal".into(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
    }
}

#[test]
fn recovery_transaction_abort_repeats_conditional_binding_root_index_and_projection() {
    let db = MetadataStore::in_memory().unwrap();
    let root = std::env::temp_dir().join("owned-ingest-transaction");
    db.clone()
        .replace_shared_directory_roots(&[crate::MetadataSharedDirectoryRoot {
            path: root.to_string_lossy().into_owned(),
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    let roots = [MetadataIngestRoot {
        root: root.clone(),
        relative: "sample.bin".into(),
    }];
    let a = content(&root, "11");
    let recovery = MetadataAichRecoverySet {
        root: [0x22; 20],
        size: a.file_size,
        parts: vec![vec![0x33; 40]],
        part_roots: vec![[0x22; 20]],
    };
    let epoch = AtomicU64::new(0);
    let media = MetadataTransferMediaMetadata::default();
    // This is a real SQLite transaction-wide abort, not a pre-SQL mocked error.
    db.connection()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TABLE ingest_cache_abort(enabled INTEGER NOT NULL);
         INSERT INTO ingest_cache_abort VALUES(1);
         CREATE TEMP TRIGGER ingest_abort_cache BEFORE INSERT ON main.aich_recovery_parts
         WHEN (SELECT enabled FROM ingest_cache_abort)=1
         BEGIN SELECT RAISE(ROLLBACK, 'injected ingest cache abort'); END;",
        )
        .unwrap();
    let result = db
        .commit_local_ingest(
            &a,
            &recovery,
            &media,
            None,
            &capture_jobs(&db, &a, None),
            &roots,
            Some("unknown"),
            (&epoch, 0),
        )
        .unwrap();
    assert!(result.recovery_error.is_some());
    assert!(result.projections[0].complete.is_some());
    assert!(
        db.find_indexed_file_by_hash(&a.file_hash)
            .unwrap()
            .is_some()
    );
    assert_eq!(db.table_count("aich_recovery_sets").unwrap(), 0);
    let old = db.local_file_instance(&a.path).unwrap().unwrap();

    let mut b = content(&root, "44");
    b.fingerprint.identity = crate::NativeFileIdentity::Unix {
        device_id: 1,
        inode_number: 3,
    };
    let oversized = MetadataTransferMediaMetadata {
        title: "x".repeat(65_537),
        ..media.clone()
    };
    // Projection validation must also run in the fallback transaction. No
    // mutation, index row or membership reassignment may survive this error.
    assert!(
        db.commit_local_ingest(
            &b,
            &recovery,
            &oversized,
            Some(&old),
            &capture_jobs(&db, &b, Some(&old)),
            &roots,
            Some("unknown"),
            (&epoch, 0)
        )
        .is_err()
    );
    assert_eq!(db.local_file_instance(&b.path).unwrap().unwrap(), old);
    assert!(
        db.find_indexed_file_by_hash(&b.file_hash)
            .unwrap()
            .is_none()
    );
    assert!(
        db.next_shared_copy(&a.file_hash, 0, 65_536)
            .unwrap()
            .is_some()
    );

    epoch.store(2, Ordering::Release);
    assert!(
        db.commit_local_ingest(
            &b,
            &recovery,
            &media,
            Some(&old),
            &capture_jobs(&db, &b, Some(&old)),
            &roots,
            Some("unknown"),
            (&epoch, 0)
        )
        .unwrap_err()
        .is::<ObservedRootChanged>()
    );
    assert_eq!(db.local_file_instance(&b.path).unwrap().unwrap(), old);
    let result = db
        .commit_local_ingest(
            &b,
            &recovery,
            &media,
            Some(&old),
            &capture_jobs(&db, &b, Some(&old)),
            &roots,
            Some("unknown"),
            (&epoch, 2),
        )
        .unwrap();
    assert!(result.recovery_error.is_some());
    assert_eq!(result.projections.len(), 2);
    assert!(
        db.next_shared_copy(&a.file_hash, 0, 65_536)
            .unwrap()
            .is_none()
    );
    assert!(
        db.next_shared_copy(&b.file_hash, 0, 65_536)
            .unwrap()
            .is_some()
    );
    assert!(
        db.find_indexed_file_by_hash(&b.file_hash)
            .unwrap()
            .is_some()
    );

    let c = content(&root, "66");
    assert!(
        db.commit_local_ingest(
            &c,
            &recovery,
            &media,
            Some(&old),
            &capture_jobs(&db, &c, Some(&old)),
            &roots,
            Some("unknown"),
            (&epoch, 2)
        )
        .unwrap_err()
        .is::<MetadataIngestPathChanged>()
    );
    assert_eq!(
        db.local_file_instance(&b.path).unwrap().unwrap().file_hash,
        b.file_hash
    );
    assert!(
        db.find_indexed_file_by_hash(&c.file_hash)
            .unwrap()
            .is_none()
    );
    assert!(
        db.commit_local_ingest(
            &c,
            &recovery,
            &media,
            None,
            &capture_jobs(&db, &c, None),
            &roots,
            Some("unknown"),
            (&epoch, 2)
        )
        .unwrap_err()
        .is::<MetadataIngestPathChanged>()
    );
}

#[test]
fn savepoint_recovery_failure_preserves_owned_binding_without_recovery_rows() {
    let db = MetadataStore::in_memory().unwrap();
    let root = std::env::temp_dir().join("owned-ingest-savepoint");
    let content = content(&root, "11");
    let malformed = MetadataAichRecoverySet {
        root: [0x22; 20],
        size: content.file_size,
        parts: vec![vec![0; 20]],
        part_roots: vec![[0x22; 20]],
    };
    let epoch = AtomicU64::new(0);
    let result = db
        .commit_local_ingest(
            &content,
            &malformed,
            &MetadataTransferMediaMetadata::default(),
            None,
            &capture_jobs(&db, &content, None),
            &[],
            None,
            (&epoch, 0),
        )
        .unwrap();
    assert!(result.recovery_error.is_some());
    assert_eq!(
        db.local_file_instance(&content.path)
            .unwrap()
            .unwrap()
            .file_hash,
        content.file_hash
    );
    assert_eq!(db.table_count("aich_recovery_sets").unwrap(), 0);
}

#[test]
fn fallback_rechecks_binding_changed_after_actual_recovery_transaction_abort() {
    let root = std::env::temp_dir().join(format!(
        "owned-ingest-fallback-cas-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("metadata.sqlite");
    let db = MetadataStore::open(&database).unwrap();
    let competing = MetadataStore::open(&database).unwrap();
    db.clone()
        .replace_shared_directory_roots(&[crate::MetadataSharedDirectoryRoot {
            path: root.to_string_lossy().into_owned(),
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    let a = content(&root, "11");
    db.upsert_verified_local_content(&a).unwrap();
    let expected = db.local_file_instance(&a.path).unwrap().unwrap();
    let stale = content(&root, "44");
    let mut winner = content(&root, "66");
    winner.fingerprint.identity = crate::NativeFileIdentity::Unix {
        device_id: 1,
        inode_number: 9,
    };
    db.connection()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TRIGGER abort_ingest_for_cas BEFORE INSERT ON main.aich_recovery_parts
         BEGIN SELECT RAISE(ROLLBACK, 'injected fallback CAS abort'); END;",
        )
        .unwrap();
    let (reached, ready) = std::sync::mpsc::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let worker_db = db.clone();
    let worker_root = root.clone();
    let worker_stale = stale.clone();
    let worker_expected = expected.clone();
    let worker = std::thread::spawn(move || {
        FALLBACK_GATE.with(|gate| *gate.borrow_mut() = Some((reached, resume)));
        worker_db.commit_local_ingest(
            &worker_stale,
            &MetadataAichRecoverySet {
                root: [0x22; 20],
                size: worker_stale.file_size,
                parts: vec![vec![0x33; 40]],
                part_roots: vec![[0x22; 20]],
            },
            &MetadataTransferMediaMetadata::default(),
            Some(&worker_expected),
            &capture_jobs(&worker_db, &worker_stale, Some(&worker_expected)),
            &[MetadataIngestRoot {
                root: worker_root,
                relative: "sample.bin".into(),
            }],
            Some("unknown"),
            (&AtomicU64::new(0), 0),
        )
    });
    ready
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    // The worker has already passed its initial CAS and RAISE(ROLLBACK) has
    // removed every staged write. Use a genuinely independent connection.
    assert_eq!(db.local_file_instance(&a.path).unwrap().unwrap(), expected);
    assert!(
        db.find_indexed_file_by_hash(&stale.file_hash)
            .unwrap()
            .is_none()
    );
    competing.upsert_verified_local_content(&winner).unwrap();
    assert!(
        competing
            .admit_local_path_to_root(
                &root,
                &winner.path,
                std::path::Path::new("sample.bin"),
                &winner.fingerprint
            )
            .unwrap()
    );
    release.send(()).unwrap();
    assert!(
        worker
            .join()
            .unwrap()
            .unwrap_err()
            .is::<MetadataIngestPathChanged>()
    );
    assert_eq!(
        db.local_file_instance(&winner.path)
            .unwrap()
            .unwrap()
            .file_hash,
        winner.file_hash
    );
    assert!(
        db.find_indexed_file_by_hash(&stale.file_hash)
            .unwrap()
            .is_none()
    );
    assert!(
        competing
            .next_shared_copy(&winner.file_hash, 0, 65_536)
            .unwrap()
            .is_some()
    );
    assert!(
        competing
            .next_shared_copy(&stale.file_hash, 0, 65_536)
            .unwrap()
            .is_none()
    );
    assert_eq!(db.table_count("aich_recovery_sets").unwrap(), 0);
    drop(competing);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn ingest_projection_and_copy_readers_skip_paired_exclusion_before_selecting_sibling() {
    let root = std::env::temp_dir().join(format!("ingest-exclusion-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let mut db = MetadataStore::in_memory().unwrap();
    db.replace_shared_directory_roots(&[crate::MetadataSharedDirectoryRoot {
        path: root.to_string_lossy().into_owned(),
        monitor_owned: false,
        shareable: true,
        accessible: true,
    }])
    .unwrap();
    let low = crate::NativeFileIdentity::WindowsLowResolution {
        volume_serial_number: 7,
        file_index: 11,
    };
    let mut blocked = content(&root, "11");
    blocked.fingerprint.identity = crate::NativeFileIdentity::WindowsHighResolution {
        volume_serial_number: 7,
        file_id: 19,
    };
    blocked.secondary_identity = Some(low);
    db.upsert_verified_local_content(&blocked).unwrap();
    assert!(
        db.admit_local_path_to_root(
            &root,
            &blocked.path,
            std::path::Path::new("sample.bin"),
            &blocked.fingerprint
        )
        .unwrap()
    );
    // Retained orphan reservation authority remains effective even after its
    // originating job is gone. Leave membership/session rows in place.
    let output = root.join("output.bin");
    db.connection().unwrap().execute(
        "INSERT INTO download_delivery_exclusions(platform,native_path,reservation_id,originating_job_id,output_identity)
         VALUES(?1,?2,?3,1,?4)",
        params![NativePath::platform(), NativePath::from(output.as_path()).storage_bytes(),
            uuid::Uuid::new_v4().to_string(), low.storage_bytes()],
    ).unwrap();
    assert!(
        db.local_ingest_projections(&[blocked.file_hash.clone()])
            .unwrap()[0]
            .complete
            .is_none()
    );
    assert!(
        db.current_shared_files_by_hash(&blocked.file_hash)
            .unwrap()
            .is_empty()
    );
    assert!(
        db.next_shared_copy(&blocked.file_hash, 0, 65_536)
            .unwrap()
            .is_none()
    );

    let mut sibling = content(&root, "11");
    sibling.path = root.join("sibling.bin");
    db.upsert_verified_local_content(&sibling).unwrap();
    assert!(
        db.admit_local_path_to_root(
            &root,
            &sibling.path,
            std::path::Path::new("sibling.bin"),
            &sibling.fingerprint
        )
        .unwrap()
    );
    let projections = db
        .local_ingest_projections(&[blocked.file_hash.clone()])
        .unwrap();
    assert_eq!(
        projections[0]
            .complete
            .as_ref()
            .unwrap()
            .media_path
            .as_ref(),
        Some(&sibling.path)
    );
    let copies = db.current_shared_files_by_hash(&blocked.file_hash).unwrap();
    assert_eq!(copies.len(), 1);
    assert_eq!(copies[0].source_path, sibling.path);
    assert_eq!(
        db.next_shared_copy(&blocked.file_hash, 0, 65_536)
            .unwrap()
            .unwrap()
            .source_path,
        sibling.path
    );

    let recovery = MetadataAichRecoverySet {
        root: [0x22; 20],
        size: sibling.file_size,
        parts: vec![vec![0x33; 40]],
        part_roots: vec![[0x22; 20]],
    };
    let expected = db.local_file_instance(&sibling.path).unwrap().unwrap();
    let epoch = AtomicU64::new(0);
    let committed = db
        .commit_local_ingest(
            &sibling,
            &recovery,
            &MetadataTransferMediaMetadata::default(),
            Some(&expected),
            &capture_jobs(&db, &sibling, Some(&expected)),
            &[],
            None,
            (&epoch, 0),
        )
        .unwrap();
    assert_eq!(
        committed.projections[0]
            .complete
            .as_ref()
            .unwrap()
            .media_path
            .as_ref(),
        Some(&sibling.path)
    );
    drop(db);
    std::fs::remove_dir(root).unwrap();
}

#[test]
fn ingest_job_snapshot_fences_absence_and_generation_after_real_fallback_abort() {
    let root = std::env::temp_dir().join(format!("ingest-job-fence-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let database = root.join("metadata.sqlite");
    let db = MetadataStore::open(&database).unwrap();
    let competing = MetadataStore::open(&database).unwrap();
    let content = content(&root, "11");
    let absent = capture_jobs(&db, &content, None);
    let token = db
        .admit_download_job(&crate::DownloadJobRequest {
            file_hash: content.file_hash.clone(),
            display_name: content.display_name.clone(),
            expected_size_bytes: Some(content.file_size),
            category_id: None,
            intent: crate::DownloadIntent::Started,
            piece_size: content.part_size,
        })
        .unwrap()
        .job
        .token;
    let recovery = MetadataAichRecoverySet {
        root: [0x22; 20],
        size: content.file_size,
        parts: vec![vec![0x33; 40]],
        part_roots: vec![[0x22; 20]],
    };
    let epoch = AtomicU64::new(0);
    assert!(
        db.commit_local_ingest(
            &content,
            &recovery,
            &MetadataTransferMediaMetadata::default(),
            None,
            &absent,
            &[],
            Some("unknown"),
            (&epoch, 0)
        )
        .unwrap_err()
        .is::<MetadataIngestJobChanged>()
    );
    assert!(db.local_file_instance(&content.path).unwrap().is_none());
    let captured = capture_jobs(&db, &content, None);
    db.connection()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TRIGGER abort_job_ingest BEFORE INSERT ON main.aich_recovery_parts
        BEGIN SELECT RAISE(ROLLBACK, 'injected job fallback abort'); END;",
        )
        .unwrap();
    let (reached, ready) = std::sync::mpsc::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let worker_db = db.clone();
    let input = content.clone();
    let worker = std::thread::spawn(move || {
        FALLBACK_GATE.with(|gate| *gate.borrow_mut() = Some((reached, resume)));
        worker_db.commit_local_ingest(
            &input,
            &recovery,
            &MetadataTransferMediaMetadata::default(),
            None,
            &captured,
            &[],
            Some("unknown"),
            (&AtomicU64::new(0), 0),
        )
    });
    ready
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    assert!(competing.stop_download_job(token).unwrap());
    let stopped = competing.download_job(token.job_id).unwrap().unwrap().token;
    let restarted = competing
        .start_download_job(stopped, &root)
        .unwrap()
        .unwrap()
        .token;
    release.send(()).unwrap();
    assert!(
        worker
            .join()
            .unwrap()
            .unwrap_err()
            .is::<MetadataIngestJobChanged>()
    );
    assert!(db.local_file_instance(&content.path).unwrap().is_none());
    assert!(
        db.find_indexed_file_by_hash(&content.file_hash)
            .unwrap()
            .is_none()
    );
    assert!(db.download_job_aich_identity(token).unwrap().is_none());
    let mut called = false;
    assert!(
        db.publish_download_job_aich_identity(token, |_| {
            called = true;
            Ok(())
        })
        .is_err()
    );
    assert!(!called);
    assert!(
        db.publish_download_job_aich_identity(restarted, |_| Ok(()))
            .is_ok()
    );
    assert_eq!(capture_jobs(&db, &content, None)[0].token, Some(restarted));
    drop(competing);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}
