use super::*;
fn payload(store: &MetadataStore, marker: u8) -> MetadataDownloadPayload {
    let job = store
        .admit_download_job(&crate::DownloadJobRequest {
            file_hash: hex::encode([marker; 16]),
            display_name: format!("payload-{marker}.bin"),
            expected_size_bytes: Some(16),
            category_id: None,
            intent: crate::DownloadIntent::Started,
            piece_size: 9_728_000,
        })
        .unwrap()
        .job;
    let job = store
        .start_download_job(job.token, &std::env::temp_dir())
        .unwrap()
        .unwrap();
    store
        .establish_download_job_storage(
            job.token,
            NativeFileIdentity::Unix {
                device_id: 1,
                inode_number: u64::from(marker),
            },
        )
        .unwrap();
    let mut manifest = store
        .download_job_manifest(job.token.job_id)
        .unwrap()
        .unwrap();
    manifest.completed = true;
    manifest.md4_hashset_acquired = true;
    manifest.pieces = vec![crate::MetadataTransferPiece {
        piece_index: 0,
        state: "Verified".into(),
        prefix_bytes: 16,
        present_bytes: 16,
        block_bitmap: None,
        ich_corrupted: false,
    }];
    manifest.verified_ranges = vec![crate::MetadataTransferRange { start: 0, end: 16 }];
    manifest.payload_fingerprint = Some(NativeFileFingerprint {
        identity: NativeFileIdentity::Unix {
            device_id: 1,
            inode_number: u64::from(marker) + 100,
        },
        size_bytes: 16,
        modified: crate::NativeFileTimestamp::new(1, 0).unwrap(),
        changed: None,
    });
    store.upsert_transfer_manifest(&manifest).unwrap();
    let conn = store.connection().unwrap();
    match read(
        &conn,
        job.token.job_id,
        crate::download_job_store::JOB_PAGE_BYTES,
    )
    .unwrap()
    {
        PayloadRead::Value(value) => *value,
        _ => panic!("verified job must be a candidate"),
    }
}
#[test]
fn payload_candidates_are_exact_generation_and_retirement_fenced() {
    let store = MetadataStore::in_memory().unwrap();
    let original = payload(&store, 11);
    assert!(store.download_payload_is_current(&original).unwrap());
    assert_eq!(
        store
            .download_payload_candidate(&original.catalog.file_hash)
            .unwrap(),
        Some(original.clone())
    );
    store
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO download_retirements(job_id) VALUES(?1)",
            [original.token.job_id],
        )
        .unwrap();
    assert!(
        store
            .download_payloads_after(None, 16)
            .unwrap()
            .entries
            .is_empty()
    );
    assert!(!store.download_payload_is_current(&original).unwrap());
    store
        .connection()
        .unwrap()
        .execute(
            "DELETE FROM download_retirements WHERE job_id=?1",
            [original.token.job_id],
        )
        .unwrap();
    assert!(store.stop_download_job(original.token).unwrap());
    assert!(!store.download_payload_is_current(&original).unwrap());
    let stopped = store.download_payloads_after(None, 16).unwrap();
    assert_eq!(stopped.entries.len(), 1);
    assert_ne!(stopped.entries[0].token, original.token);
    assert!(store.remove_download_job(original.token.job_id).unwrap());
    assert!(
        store
            .download_payloads_after(None, 16)
            .unwrap()
            .entries
            .is_empty()
    );
    assert!(
        store
            .download_payload_candidate(&original.catalog.file_hash)
            .unwrap()
            .is_none()
    );
}
#[test]
fn payload_page_advances_over_ineligible_ids_and_short_byte_pages() {
    let store = MetadataStore::in_memory().unwrap();
    for marker in 1..=20 {
        let value = payload(&store, marker);
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE download_jobs SET display_name=?2 WHERE id=?1",
                params![value.token.job_id, "x".repeat(65_536)],
            )
            .unwrap();
        store.connection().unwrap().execute(
            "UPDATE known_files SET comment=?2 WHERE id=(SELECT known_file_id FROM download_jobs WHERE id=?1)",
            params![value.token.job_id, "x".repeat(65_536)],
        ).unwrap();
    }
    let first = store.download_payloads_after(None, 256).unwrap();
    assert!(!first.entries.is_empty() && first.entries.len() < 20);
    let mut count = first.entries.len();
    let mut cursor = first.cursor;
    loop {
        let next = store.download_payloads_after(cursor, 256).unwrap();
        if next.cursor.is_none() {
            break;
        }
        assert!(next.cursor > cursor);
        count += next.entries.len();
        cursor = next.cursor;
    }
    assert_eq!(count, 20);
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET completed=0,visible_state='queued',payload_fingerprint=NULL",
            [],
        )
        .unwrap();
    let empty = store.download_payloads_after(None, 3).unwrap();
    assert!(empty.entries.is_empty());
    assert_eq!(empty.cursor.unwrap().get(), 3);
    let plans = store
        .connection()
        .unwrap()
        .prepare(&format!("EXPLAIN QUERY PLAN {IDS}"))
        .unwrap()
        .query_map(params![10, 3], |r| r.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plans
            .iter()
            .any(|p| p.contains("download_jobs_visible_page_idx") && p.contains(">?")),
        "{plans:?}"
    );
}
#[test]
fn malformed_or_oversized_payload_proof_fails_before_publication() {
    let store = MetadataStore::in_memory().unwrap();
    let value = payload(&store, 31);
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET display_name=?2 WHERE id=?1",
            params![value.token.job_id, "x".repeat(65_537)],
        )
        .unwrap();
    assert!(store.download_payloads_after(None, 16).is_err());
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET display_name='safe.bin',part_count=2 WHERE id=?1",
            [value.token.job_id],
        )
        .unwrap();
    assert!(store.download_payloads_after(None, 16).is_err());
}

#[test]
fn payload_admission_checks_captured_token_and_paired_exclusion() {
    let store = MetadataStore::in_memory().unwrap();
    let value = payload(&store, 41);
    let evidence =
        crate::NativeFileIdentityEvidence::new(value.fingerprint.identity, None).unwrap();
    let path = value.storage.path.join("pieces.bin");
    assert!(
        store
            .admit_download_payload(&value, &path, evidence)
            .unwrap()
    );
    let reservation = uuid::Uuid::new_v4();
    let native = crate::NativePath::from(path.as_path());
    store.connection().unwrap().execute("INSERT INTO download_delivery_exclusions(platform,native_path,originating_job_id,reservation_id,output_identity)
        VALUES(?1,?2,?3,?4,?5)",params![crate::NativePath::platform(),native.storage_bytes(),value.token.job_id,reservation.to_string(),value.fingerprint.identity.storage_bytes()]).unwrap();
    assert!(
        !store
            .admit_download_payload(&value, &path, evidence)
            .unwrap()
    );
    store
        .connection()
        .unwrap()
        .execute(
            "DELETE FROM download_delivery_exclusions WHERE reservation_id=?1",
            [reservation.to_string()],
        )
        .unwrap();
    assert!(store.stop_download_job(value.token).unwrap());
    assert!(
        !store
            .admit_download_payload(&value, &path, evidence)
            .unwrap()
    );
}

#[test]
fn payload_admission_blocks_secondary_only_alias_but_preserves_other_volume() {
    let store = MetadataStore::in_memory().unwrap();
    // The same independent observations used by the exclusion-store fixture:
    // the low ID is supplied evidence, never derived from the high file ID.
    let high = NativeFileIdentity::WindowsHighResolution {
        volume_serial_number: 7,
        file_id: 19,
    };
    let low = NativeFileIdentity::WindowsLowResolution {
        volume_serial_number: 7,
        file_index: 17,
    };
    let other_high = NativeFileIdentity::WindowsHighResolution {
        volume_serial_number: 71,
        file_id: 19,
    };
    let other_low = NativeFileIdentity::WindowsLowResolution {
        volume_serial_number: 71,
        file_index: 17,
    };
    let mut candidate = payload(&store, 51);
    let mut unrelated = payload(&store, 52);
    for (value, identity) in [(&mut candidate, high), (&mut unrelated, other_high)] {
        value.fingerprint.identity = identity;
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE download_jobs SET payload_fingerprint=?2 WHERE id=?1",
                params![value.token.job_id, value.fingerprint.storage_bytes()],
            )
            .unwrap();
    }
    let evidence = crate::NativeFileIdentityEvidence::new(high, Some(low)).unwrap();
    let other_evidence =
        crate::NativeFileIdentityEvidence::new(other_high, Some(other_low)).unwrap();
    let path = candidate.storage.path.join("pieces.bin");
    let other_path = unrelated.storage.path.join("pieces.bin");
    let excluded_path = candidate.storage.path.join("distinct-output.bin");
    assert_ne!(excluded_path, path);
    assert_ne!(excluded_path, other_path);
    let native = crate::NativePath::from(excluded_path.as_path());
    assert!(
        store
            .admit_download_payload(&candidate, &path, evidence)
            .unwrap()
    );

    let unrelated_high_on_same_volume = NativeFileIdentity::WindowsHighResolution {
        volume_serial_number: 7,
        file_id: 29,
    };
    // Exercise candidate.secondary against each stored slot, then primary.
    // Every reservation has a distinct lexical path, so the path predicate
    // cannot accidentally make these native-evidence assertions pass.
    for (primary, secondary) in [
        (low, None),
        (unrelated_high_on_same_volume, Some(low)),
        (
            high,
            Some(NativeFileIdentity::WindowsLowResolution {
                volume_serial_number: 7,
                file_index: 37,
            }),
        ),
    ] {
        let reservation = uuid::Uuid::new_v4();
        store.connection().unwrap().execute(
            "INSERT INTO download_delivery_exclusions(platform,native_path,originating_job_id,reservation_id,output_identity,secondary_identity)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![crate::NativePath::platform(),native.storage_bytes(),candidate.token.job_id,
                reservation.to_string(),primary.storage_bytes(),secondary.map(NativeFileIdentity::storage_bytes)],
        ).unwrap();
        assert!(
            !store
                .admit_download_payload(&candidate, &path, evidence)
                .unwrap(),
            "overlapping actual identity must stay excluded: {primary:?}/{secondary:?}"
        );
        assert!(
            store
                .admit_download_payload(&unrelated, &other_path, other_evidence)
                .unwrap(),
            "same file IDs on another volume must remain eligible"
        );
        store
            .connection()
            .unwrap()
            .execute(
                "DELETE FROM download_delivery_exclusions WHERE reservation_id=?1",
                [reservation.to_string()],
            )
            .unwrap();
        assert!(
            store
                .admit_download_payload(&candidate, &path, evidence)
                .unwrap()
        );
    }
}

#[test]
fn payload_marker_nul_suffix_is_rejected_before_owned_uuid_conversion() {
    let store = MetadataStore::in_memory().unwrap();
    let original = payload(&store, 61);
    let job = store
        .admit_download_job(&crate::DownloadJobRequest {
            file_hash: hex::encode([62; 16]),
            display_name: "oversized-marker.bin".into(),
            expected_size_bytes: Some(16),
            category_id: None,
            intent: crate::DownloadIntent::Started,
            piece_size: 9_728_000,
        })
        .unwrap()
        .job;
    let marker = format!("{}\0{}", uuid::Uuid::new_v4(), "x".repeat(1024 * 1024));
    {
        let mut conn = store.connection().unwrap();
        let tx = conn.transaction().unwrap();
        let temp = std::env::temp_dir();
        let path = temp.join(format!("payload-marker-{}", uuid::Uuid::new_v4()));
        let temp_id = crate::store::upsert_local_path(&tx, &temp).unwrap();
        let path_id = crate::store::upsert_local_path(&tx, &path).unwrap();
        // First assignment respects immutable storage authority. This raw SQL
        // proves the current schema accepts a NUL suffix without disabling any
        // CHECK or trigger, while the bounded reader must reject its bytes.
        tx.execute("UPDATE download_jobs SET selected_temp_path_id=?2,storage_path_id=?3,
            storage_directory_marker_id=?4,storage_directory_identity=?5,
            completed=1,visible_state='completed',md4_hashset_acquired=1,part_count=1,payload_fingerprint=?6
            WHERE id=?1",params![job.token.job_id,temp_id,path_id,marker,
                original.storage.identity.unwrap().storage_bytes(),original.fingerprint.storage_bytes()]).unwrap();
        let lengths:(i64,i64)=tx.query_row("SELECT length(storage_directory_marker_id),length(CAST(storage_directory_marker_id AS BLOB))
            FROM download_jobs WHERE id=?1",[job.token.job_id],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(lengths.0, 36);
        assert!(lengths.1 > 1024 * 1024);
        tx.commit().unwrap();
    }
    let error = store
        .download_payloads_after(Some(original.token.job_id), 16)
        .unwrap_err();
    assert!(
        error.to_string().contains("job UUID exceeds byte bound"),
        "{error:#}"
    );
    let error = store
        .download_payload_candidate(&job.file_hash)
        .unwrap_err();
    assert!(
        error.to_string().contains("job UUID exceeds byte bound"),
        "{error:#}"
    );
}
