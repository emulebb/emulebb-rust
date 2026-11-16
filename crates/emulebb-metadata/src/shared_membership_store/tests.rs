use super::*;
use crate::{
    MetadataSharedDirectoryRoot, NativeFileFingerprint, NativeFileIdentity, NativeFileTimestamp,
};

#[test]
fn overlapping_roots_withdraw_independently_and_keep_hash_cache() {
    let mut store = MetadataStore::in_memory().unwrap();
    let root = std::env::temp_dir().join("emulebb-membership-root");
    let nested = root.join("nested");
    let file = nested.join("Sample.bin");
    let roots = [&root, &nested].map(|path| MetadataSharedDirectoryRoot {
        path: path.to_string_lossy().into_owned(),
        monitor_owned: false,
        shareable: true,
        accessible: true,
    });
    store.replace_shared_directory_roots(&roots).unwrap();
    let hash = "00112233445566778899aabbccddeeff";
    store
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO known_files(ed2k_hash, size_bytes, display_name,
            first_seen_at_ms, last_seen_at_ms, updated_at_ms)
         VALUES (?1, 32, 'Sample.bin', 1, 1, 1)",
            params![crate::store::decode_fixed_hex(hash, 16, "ED2K hash").unwrap()],
        )
        .unwrap();
    let fingerprint = NativeFileFingerprint {
        identity: NativeFileIdentity::Unix {
            device_id: 7,
            inode_number: 11,
        },
        size_bytes: 32,
        modified: NativeFileTimestamp::new(1_700_000_000, 123_456_789).unwrap(),
        changed: Some(NativeFileTimestamp::new(1_700_000_001, 234_567_890).unwrap()),
    };
    store
        .upsert_local_file_instance(
            &file,
            hash,
            &fingerprint,
            crate::NativeFileIdentityEvidence::new((&fingerprint).identity, None).unwrap(),
        )
        .unwrap();
    store.connection().unwrap().execute_batch(
        "CREATE TEMP TRIGGER fail_session_verification BEFORE INSERT ON session_verified_local_paths
         BEGIN SELECT RAISE(ABORT, 'injected verification failure'); END;",
    ).unwrap();
    assert!(
        store
            .admit_local_path_to_root(&root, &file, Path::new("nested/Sample.bin"), &fingerprint)
            .is_err()
    );
    let count: i64 = store
        .connection()
        .unwrap()
        .query_row("SELECT count(*) FROM shared_file_memberships", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        count, 0,
        "membership and verification must roll back together"
    );
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_session_verification;")
        .unwrap();
    // This fixture has no verified-content row. The bounded admission
    // projection must fail before membership or session verification commits.
    assert!(
        store
            .admit_shared_path_with_projection(
                &root,
                &file,
                Path::new("nested/Sample.bin"),
                &fingerprint,
                hash,
                None,
            )
            .is_err()
    );
    let counts: (i64, i64) = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT (SELECT count(*) FROM shared_file_memberships),
                (SELECT count(*) FROM temp.session_verified_local_paths)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        counts,
        (0, 0),
        "projection failure must roll back admission"
    );
    let verified_file = (
        file.clone(),
        PathBuf::from("nested/Sample.bin"),
        fingerprint.clone(),
    );
    let nested_file = (
        file.clone(),
        PathBuf::from("Sample.bin"),
        fingerprint.clone(),
    );
    store
        .replace_root_memberships(&root, std::slice::from_ref(&verified_file))
        .unwrap();
    store
        .replace_root_memberships(&nested, std::slice::from_ref(&nested_file))
        .unwrap();
    assert_eq!(store.active_shared_content_count().unwrap(), 1);
    store.connection().unwrap().execute_batch("CREATE TEMP TRIGGER keep_active_membership BEFORE UPDATE OF removed_at_ms ON main.shared_file_memberships WHEN new.removed_at_ms IS NOT NULL BEGIN SELECT RAISE(ABORT,'live member withdrawn during scan'); END;").unwrap();
    store
        .replace_root_memberships(&root, std::slice::from_ref(&verified_file))
        .unwrap();
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER keep_active_membership;")
        .unwrap();
    let (withdrawn, complete, partial) = store
        .withdraw_shared_path_with_projection(&file, hash, Some(&fingerprint))
        .unwrap();
    assert_eq!(withdrawn, 2);
    assert!(!complete);
    assert!(partial.is_none());
    assert_eq!(store.active_shared_content_count().unwrap(), 0);
    assert!(store.local_file_instance(&file).unwrap().is_some());
    store
        .replace_root_memberships(&root, std::slice::from_ref(&verified_file))
        .unwrap();
    store
        .replace_root_memberships(&nested, std::slice::from_ref(&nested_file))
        .unwrap();
    let page = store.active_local_share_page(None, 10).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].file_hash, hash);
    assert_eq!(
        store.active_local_file_by_hash(hash).unwrap().unwrap().path,
        file
    );
    assert!(
        store
            .active_local_share_page(Some(hash), 10)
            .unwrap()
            .is_empty()
    );
    store.set_shared_root_accessible(&root, false).unwrap();
    assert_eq!(store.active_shared_content_count().unwrap(), 1);
    store.set_shared_root_accessible(&nested, false).unwrap();
    assert_eq!(store.active_shared_content_count().unwrap(), 0);
    assert!(store.active_local_share_page(None, 10).unwrap().is_empty());
    assert!(store.active_local_file_by_hash(hash).unwrap().is_none());
    assert!(store.local_file_instance(&file).unwrap().is_some());
    store.set_shared_root_accessible(&root, true).unwrap();
    assert_eq!(store.active_shared_content_count().unwrap(), 0);
    store
        .replace_root_memberships(&root, std::slice::from_ref(&verified_file))
        .unwrap();
    assert_eq!(store.active_shared_content_count().unwrap(), 1);
    let mut changed = fingerprint.clone();
    changed.size_bytes = 33;
    store
        .replace_root_memberships(
            &root,
            &[(file.clone(), PathBuf::from("nested/Sample.bin"), changed)],
        )
        .unwrap();
    assert_eq!(store.active_shared_content_count().unwrap(), 0);
    store
        .replace_root_memberships(&root, &[verified_file])
        .unwrap();
    assert_eq!(store.active_shared_content_count().unwrap(), 1);
    store.replace_root_memberships(&root, &[]).unwrap();
    assert_eq!(store.active_shared_content_count().unwrap(), 0);

    // An upload holding the old fingerprint must not withdraw a path that
    // a watcher has already reverified and admitted as a new generation.
    let mut replacement = fingerprint.clone();
    replacement.identity = NativeFileIdentity::Unix {
        device_id: 7,
        inode_number: 12,
    };
    store
        .upsert_local_file_instance(
            &file,
            hash,
            &replacement,
            crate::NativeFileIdentityEvidence::new((&replacement).identity, None).unwrap(),
        )
        .unwrap();
    store
        .replace_root_memberships(
            &root,
            &[(
                file.clone(),
                PathBuf::from("nested/Sample.bin"),
                replacement.clone(),
            )],
        )
        .unwrap();
    assert_eq!(
        store
            .withdraw_local_file_path_if_verified(&file, hash, &fingerprint)
            .unwrap(),
        0
    );
    assert_eq!(store.active_shared_content_count().unwrap(), 1);
    assert_eq!(
        store
            .withdraw_local_file_path_if_verified(
                &file,
                "ffffffffffffffffffffffffffffffff",
                &replacement,
            )
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .withdraw_local_file_path_if_verified(&file, hash, &replacement)
            .unwrap(),
        1
    );
    assert_eq!(store.active_shared_content_count().unwrap(), 0);
}
