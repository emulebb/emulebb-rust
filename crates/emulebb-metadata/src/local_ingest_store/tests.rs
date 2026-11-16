use super::*;

fn content(root: &std::path::Path, byte: &str) -> MetadataVerifiedLocalContent {
    MetadataVerifiedLocalContent {
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
