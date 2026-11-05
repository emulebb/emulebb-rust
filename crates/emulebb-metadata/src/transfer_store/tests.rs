use super::*;
use crate::MetadataStore;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

fn unique_store_path(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "emulebb-metadata-{label}-{}-{}.sqlite",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ))
}

fn remove_store_files(path: &std::path::Path) {
    fs::remove_file(path).ok();
    fs::remove_file(path.with_extension("sqlite-wal")).ok();
    fs::remove_file(path.with_extension("sqlite-shm")).ok();
}

fn completed_download_manifest() -> MetadataTransferManifest {
    MetadataTransferManifest {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Concurrent.Sample.bin".to_string(),
        display_name_pinned: false,
        follow_majority_filename: false,
        file_name_observations: Vec::new(),
        file_size: 16,
        piece_size: 16,
        completed: true,
        final_rehash_pending: false,
        md4_hashset_acquired: true,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_hashset: Vec::new(),
        verified_ranges: vec![MetadataTransferRange { start: 0, end: 16 }],
        pieces: Vec::new(),
        sources: Vec::new(),
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        category_id: 0,
        control_state: None,
        transfer_row_removed: false,
        delivery_state: MetadataTransferDeliveryState::Pending,
        delivery_ownership: MetadataTransferDeliveryOwnership::None,
        delivered_path: None,
        source_fingerprint: None,
        payload_fingerprint: None,
    }
}

fn completed_pending_download_manifest() -> MetadataTransferManifest {
    let mut manifest = completed_download_manifest();
    manifest.display_name = "Delivery.Attempt.bin".to_string();
    manifest.delivery_state = MetadataTransferDeliveryState::Pending;
    manifest.source_fingerprint = None;
    manifest.payload_fingerprint = Some(fingerprint(manifest.file_size, 91));
    manifest
}

fn fingerprint(size_bytes: u64, sequence: u64) -> NativeFileFingerprint {
    NativeFileFingerprint {
        identity: crate::NativeFileIdentity::Unix {
            device_id: 7,
            inode_number: 11 + sequence,
        },
        size_bytes,
        modified: crate::NativeFileTimestamp::new(
            1_700_000_000 + i64::try_from(sequence).unwrap(),
            123_456_789,
        )
        .unwrap(),
        changed: Some(
            crate::NativeFileTimestamp::new(
                1_700_000_001 + i64::try_from(sequence).unwrap(),
                234_567_890,
            )
            .unwrap(),
        ),
    }
}

#[test]
fn metadata_manifest_alone_cannot_claim_verified_local_identity() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = completed_download_manifest();
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(
        store
            .current_shared_files_by_hash(&manifest.file_hash)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn owned_delivery_requires_exact_size_fingerprint_authority() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest();
    manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
    manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Owned;
    manifest.delivered_path = Some("/incoming/Delivery.Attempt.bin".into());

    assert!(store.upsert_transfer_manifest(&manifest).is_err());
    manifest.source_fingerprint = Some(fingerprint(manifest.file_size + 1, 92));
    assert!(store.upsert_transfer_manifest(&manifest).is_err());
    manifest.source_fingerprint = Some(fingerprint(manifest.file_size, 93));
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store
            .transfer_manifest_by_hash(&manifest.file_hash)
            .unwrap(),
        Some(manifest)
    );
}

#[test]
fn transfer_manifest_waits_for_existing_writer_before_reading_snapshot() {
    let path = unique_store_path("manifest-immediate-transaction");
    remove_store_files(&path);
    let writer = MetadataStore::open(&path).unwrap();
    let contender = MetadataStore::open(&path).unwrap();
    let mut writer_conn = writer.connection().unwrap();
    let writer_tx = writer_conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    writer_tx
        .execute(
            "UPDATE metadata_schema SET created_at_ms = created_at_ms + 1",
            [],
        )
        .unwrap();

    let manifest = completed_download_manifest();
    let contender_write = std::thread::spawn(move || contender.upsert_transfer_manifest(&manifest));
    std::thread::sleep(Duration::from_millis(100));
    assert!(!contender_write.is_finished());

    writer_tx.commit().unwrap();
    assert!(contender_write.join().unwrap().is_ok());
    drop(writer_conn);
    drop(writer);
    remove_store_files(&path);
}

#[test]
fn transfer_manifest_roundtrips_sql_tables() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest();
    manifest.display_name = "Sample.Transfer.bin".to_string();
    manifest.aich_root = Some("1111111111111111111111111111111111111111".to_string());
    manifest.aich_hashset_acquired = true;
    manifest.aich_hashset = vec!["2222222222222222222222222222222222222222".to_string()];
    manifest.pieces = vec![MetadataTransferPiece {
        piece_index: 0,
        state: "Verified".to_string(),
        bytes_written: manifest.file_size,
        block_bitmap: None,
        ich_corrupted: false,
    }];

    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store
            .transfer_manifest_by_hash(&manifest.file_hash)
            .unwrap(),
        Some(manifest.clone())
    );
    assert_eq!(
        store.managed_download_transfer_hashes().unwrap(),
        vec![manifest.file_hash.clone()]
    );
    assert_eq!(
        store.managed_download_transfer_manifests().unwrap(),
        vec![manifest.clone()]
    );
    assert!(
        store
            .managed_download_transfer_exists(&manifest.file_hash)
            .unwrap()
    );
    assert_eq!(
        store.active_transfer_manifests().unwrap(),
        vec![manifest.clone()]
    );
    assert_eq!(store.completed_transfer_catalog_entries().unwrap().len(), 1);
    assert_eq!(store.completed_transfer_publish_entries().unwrap().len(), 1);

    manifest.transfer_row_removed = true;
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(store.active_transfer_manifests().unwrap().is_empty());
    assert_eq!(store.transfer_manifests().unwrap(), vec![manifest.clone()]);

    manifest.transfer_row_removed = false;
    manifest.completed = false;
    manifest.final_rehash_pending = true;
    manifest.payload_fingerprint = None;
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store.incomplete_transfer_manifests().unwrap(),
        vec![manifest]
    );
}

#[test]
fn current_schema_rejects_persisted_network_claim_states() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_download_manifest();
    manifest.completed = false;
    manifest.verified_ranges.clear();
    manifest.pieces = vec![MetadataTransferPiece {
        piece_index: 0,
        state: "Missing".to_string(),
        bytes_written: 0,
        block_bitmap: None,
        ich_corrupted: false,
    }];
    store.upsert_transfer_manifest(&manifest).unwrap();

    for state in ["Requested", "Written"] {
        manifest.pieces[0].state = state.to_string();
        assert!(store.upsert_transfer_manifest(&manifest).is_err());
    }
    assert_eq!(
        store
            .transfer_manifest_by_hash(&manifest.file_hash)
            .unwrap()
            .unwrap()
            .pieces[0]
            .state,
        "Missing"
    );
}

#[test]
fn upload_demand_counters_persist_on_known_files() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = MetadataTransferManifest {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Demand.Sample.bin".to_string(),
        display_name_pinned: false,
        follow_majority_filename: false,
        file_name_observations: Vec::new(),
        file_size: 1024,
        piece_size: 1024,
        completed: true,
        final_rehash_pending: false,
        md4_hashset_acquired: false,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_hashset: Vec::new(),
        verified_ranges: vec![MetadataTransferRange {
            start: 0,
            end: 1024,
        }],
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Verified".to_string(),
            bytes_written: 1024,
            block_bitmap: None,
            ich_corrupted: false,
        }],
        sources: Vec::new(),
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        category_id: 0,
        control_state: None,
        transfer_row_removed: false,
        delivery_state: MetadataTransferDeliveryState::Pending,
        delivery_ownership: MetadataTransferDeliveryOwnership::None,
        delivered_path: None,
        source_fingerprint: None,
        payload_fingerprint: Some(fingerprint(1024, 10)),
    };

    let mut invalid = manifest.clone();
    invalid.completed = false;
    assert!(store.upsert_transfer_manifest(&invalid).is_err());
    invalid.completed = true;
    invalid.final_rehash_pending = true;
    assert!(store.upsert_transfer_manifest(&invalid).is_err());
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store.pending_completed_delivery_hashes().unwrap(),
        vec![manifest.file_hash.clone()]
    );
    assert_eq!(
        store.completed_delivery_reconciliation_hashes().unwrap(),
        vec![manifest.file_hash.clone()]
    );
    assert!(
        store
            .add_file_upload_request(&manifest.file_hash, 1_700_000_001_000)
            .unwrap()
    );
    assert!(
        store
            .add_file_upload_request(&manifest.file_hash, 1_700_000_000_000)
            .unwrap()
    );
    assert!(store.add_file_upload_accept(&manifest.file_hash).unwrap());

    let publish = store.completed_transfer_publish_entries().unwrap();
    assert_eq!(publish.len(), 1);
    assert_eq!(publish[0].all_time_upload_requests, 2);
    assert_eq!(publish[0].all_time_upload_accepts, 1);
    assert_eq!(publish[0].last_upload_request_ms, 1_700_000_001_000);

    let catalog = store.completed_transfer_catalog_entries().unwrap();
    assert_eq!(catalog[0].all_time_upload_requests, 2);
    assert_eq!(catalog[0].all_time_upload_accepts, 1);
    assert_eq!(catalog[0].last_upload_request_ms, 1_700_000_001_000);
}

#[test]
fn shared_source_failures_roundtrip_update_and_clear() {
    let store = MetadataStore::in_memory().unwrap();
    let initial_fingerprint = fingerprint(1024, 0);

    store
        .upsert_shared_source_failure(
            Path::new("/library/Broken.Source.bin"),
            1024,
            Some(&initial_fingerprint),
            "ingest failed",
        )
        .unwrap();
    let initial = store.shared_source_failures().unwrap();
    assert_eq!(initial.len(), 1);
    assert_eq!(
        initial[0].source_path,
        Path::new("/library/Broken.Source.bin")
    );
    assert_eq!(initial[0].file_size, 1024);
    assert_eq!(
        initial[0].source_fingerprint,
        Some(initial_fingerprint.clone())
    );
    assert_eq!(initial[0].reason, "ingest failed");

    let updated_fingerprint = fingerprint(2048, 1);
    store
        .upsert_shared_source_failure(
            Path::new("/library/Broken.Source.bin"),
            2048,
            Some(&updated_fingerprint),
            "changed identity failed",
        )
        .unwrap();
    let updated = store.shared_source_failures().unwrap();
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].file_size, 2048);
    assert_eq!(updated[0].source_fingerprint, Some(updated_fingerprint));
    assert_eq!(updated[0].reason, "changed identity failed");
    assert_eq!(updated[0].created_at_ms, initial[0].created_at_ms);
    assert!(updated[0].updated_at_ms >= initial[0].updated_at_ms);

    assert!(
        store
            .clear_shared_source_failure(Path::new("/library/Broken.Source.bin"))
            .unwrap()
    );
    assert!(store.shared_source_failures().unwrap().is_empty());
    assert!(
        !store
            .clear_shared_source_failure(Path::new("/library/Broken.Source.bin"))
            .unwrap()
    );
}

#[test]
fn imported_known_file_identity_matches_roundtrip_pathless_stock_rows() {
    let store = MetadataStore::in_memory().unwrap();
    let entry = MetadataImportedKnownFileEntry {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Known.Payload.bin".to_string(),
        file_size: 1024,
        modified_s: 1_700_000_000,
        md4_hashset: vec!["11111111111111111111111111111111".to_string()],
        aich_root: Some("2222222222222222222222222222222222222222".to_string()),
        aich_hashset: vec!["3333333333333333333333333333333333333333".to_string()],
        upload_priority: "high".to_string(),
        auto_upload_priority: false,
        all_time_uploaded_bytes: 1234,
        all_time_upload_requests: 9,
        all_time_upload_accepts: 4,
        last_upload_request_ms: 1_700_000_001_000,
    };

    store.upsert_imported_known_file(&entry).unwrap();

    assert_eq!(
        store
            .imported_known_file_identity_matches("Known.Payload.bin", 1024, 1_700_000_000)
            .unwrap(),
        vec![entry]
    );
    assert!(
        store
            .imported_known_file_identity_matches("known.payload.bin", 1024, 1_700_000_000)
            .unwrap()
            .is_empty(),
        "stock FindKnownFile uses exact file-name equality"
    );
}

#[test]
fn imported_known_file_identity_matches_returns_ambiguous_rows() {
    let store = MetadataStore::in_memory().unwrap();
    for hash in [
        "00112233445566778899aabbccddeeff",
        "ffeeddccbbaa99887766554433221100",
    ] {
        store
            .upsert_imported_known_file(&MetadataImportedKnownFileEntry {
                file_hash: hash.to_string(),
                display_name: "Ambiguous.Payload.bin".to_string(),
                file_size: 1024,
                modified_s: 1_700_000_000,
                md4_hashset: Vec::new(),
                aich_root: None,
                aich_hashset: Vec::new(),
                upload_priority: "normal".to_string(),
                auto_upload_priority: false,
                all_time_uploaded_bytes: 0,
                all_time_upload_requests: 0,
                all_time_upload_accepts: 0,
                last_upload_request_ms: 0,
            })
            .unwrap();
    }

    let matches = store
        .imported_known_file_identity_matches("Ambiguous.Payload.bin", 1024, 1_700_000_000)
        .unwrap();

    assert_eq!(matches.len(), 2);
}

#[test]
fn deleting_download_preserves_same_hash_local_content() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest();
    manifest.md4_hashset = vec!["22222222222222222222222222222222".to_string()];
    manifest.aich_hashset = vec!["3333333333333333333333333333333333333333".to_string()];
    store.upsert_transfer_manifest(&manifest).unwrap();
    let path = std::env::temp_dir().join("emulebb-same-hash-local-content.bin");
    let content = crate::MetadataVerifiedLocalContent {
        file_hash: manifest.file_hash.clone(),
        display_name: "shared.bin".to_string(),
        file_size: manifest.file_size,
        part_size: manifest.piece_size,
        md4_hashset: vec!["44444444444444444444444444444444".to_string()],
        aich_root: "1111111111111111111111111111111111111111".to_string(),
        aich_hashset: vec!["5555555555555555555555555555555555555555".to_string()],
        path: path.clone(),
        fingerprint: fingerprint(manifest.file_size, 200),
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
    };
    store.upsert_verified_local_content(&content).unwrap();
    assert_eq!(
        store
            .transfer_manifest_by_hash(&manifest.file_hash)
            .unwrap(),
        Some(manifest.clone())
    );

    assert!(store.delete_transfer_manifest(&manifest.file_hash).unwrap());
    assert!(
        store
            .transfer_manifest_by_hash(&manifest.file_hash)
            .unwrap()
            .is_none()
    );
    assert!(store.local_file_instance(&path).unwrap().is_some());
    let conn = store.connection().unwrap();
    for (table, column, expected) in [
        (
            "verified_local_md4_hashes",
            "md4_hash",
            "44444444444444444444444444444444",
        ),
        (
            "verified_local_aich_hashes",
            "aich_hash",
            "5555555555555555555555555555555555555555",
        ),
    ] {
        let actual: String = conn
            .query_row(
                &format!("SELECT lower(hex({column})) FROM {table}"),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(actual, expected);
    }
    for table in ["ed2k_part_hashes", "aich_part_hashes", "verified_ranges"] {
        assert_eq!(
            conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0,
            "{table} must cascade with the download"
        );
    }
    drop(conn);
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row("SELECT count(*) FROM verified_local_content", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(!store.delete_transfer_manifest(&manifest.file_hash).unwrap());
}

#[test]
fn delete_transfer_manifest_removes_transfer_rows() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = MetadataTransferManifest {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Sample.Transfer.bin".to_string(),
        display_name_pinned: false,
        follow_majority_filename: false,
        file_name_observations: Vec::new(),
        file_size: 1,
        piece_size: 1,
        completed: false,
        final_rehash_pending: false,
        md4_hashset_acquired: false,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_hashset: Vec::new(),
        verified_ranges: Vec::new(),
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Missing".to_string(),
            bytes_written: 0,
            block_bitmap: None,
            ich_corrupted: false,
        }],
        sources: Vec::new(),
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        category_id: 0,
        control_state: None,
        transfer_row_removed: false,
        delivery_state: MetadataTransferDeliveryState::Pending,
        delivery_ownership: MetadataTransferDeliveryOwnership::None,
        delivered_path: None,
        source_fingerprint: None,
        payload_fingerprint: None,
    };
    store.upsert_transfer_manifest(&manifest).unwrap();

    assert!(
        store
            .delete_transfer_manifest("00112233445566778899aabbccddeeff")
            .unwrap()
    );
    assert!(
        store
            .transfer_manifest_by_hash("00112233445566778899aabbccddeeff")
            .unwrap()
            .is_none()
    );
}

#[test]
fn delivery_attempts_roundtrip_and_transition_idempotently() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = completed_pending_download_manifest();
    let hash = manifest.file_hash.clone();
    store.upsert_transfer_manifest(&manifest).unwrap();

    let attempt_id = Uuid::new_v4();
    let target_path = std::env::temp_dir().join("Delivery.Attempt.bin");
    let staging_path = std::env::temp_dir().join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    let prepared = store
        .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
        .unwrap();
    assert_eq!(prepared.file_hash, hash);
    assert_eq!(prepared.attempt_id, attempt_id);
    assert_eq!(
        prepared.phase,
        MetadataTransferDeliveryAttemptPhase::Prepared
    );
    assert_eq!(prepared.target_path, target_path);
    assert_eq!(prepared.staging_path, staging_path);
    assert!(prepared.staging_fingerprint.is_none());
    assert_eq!(prepared.created_at_ms, prepared.updated_at_ms);
    assert_eq!(store.table_count("delivery_attempts").unwrap(), 1);
    assert_eq!(
        store.transfer_delivery_attempt_by_hash(&hash).unwrap(),
        Some(prepared.clone())
    );
    assert_eq!(
        store.transfer_delivery_attempts().unwrap(),
        vec![prepared.clone()]
    );
    assert_eq!(
        store
            .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
            .unwrap(),
        prepared
    );
    assert!(
        store
            .begin_transfer_delivery_attempt(&hash, Uuid::new_v4(), &target_path, &staging_path,)
            .is_err()
    );

    let staging_fingerprint = fingerprint(manifest.file_size, 91);
    assert!(
        !store
            .mark_transfer_delivery_attempt_staged(&hash, Uuid::new_v4(), &staging_fingerprint,)
            .unwrap()
    );
    assert!(
        store
            .mark_transfer_delivery_attempt_staged(&hash, attempt_id, &staging_fingerprint)
            .unwrap()
    );
    assert!(
        store
            .mark_transfer_delivery_attempt_staged(&hash, attempt_id, &staging_fingerprint)
            .unwrap()
    );
    assert!(
        !store
            .mark_transfer_delivery_attempt_staged(
                &hash,
                attempt_id,
                &fingerprint(manifest.file_size, 93),
            )
            .unwrap()
    );
    let staged = store
        .transfer_delivery_attempt_by_hash(&hash)
        .unwrap()
        .unwrap();
    assert_eq!(staged.phase, MetadataTransferDeliveryAttemptPhase::Staged);
    assert_eq!(
        staged.staging_fingerprint.as_ref(),
        Some(&staging_fingerprint)
    );
    assert!(staged.published_fingerprint.is_none());
    assert_eq!(staged.created_at_ms, prepared.created_at_ms);
    assert!(staged.updated_at_ms >= staged.created_at_ms);

    let published_fingerprint = fingerprint(manifest.file_size, 94);
    assert!(
        store
            .mark_transfer_delivery_attempt_published(&hash, attempt_id, &published_fingerprint,)
            .unwrap()
    );
    assert!(
        store
            .mark_transfer_delivery_attempt_published(&hash, attempt_id, &published_fingerprint,)
            .unwrap()
    );
    assert!(
        !store
            .mark_transfer_delivery_attempt_published(
                &hash,
                attempt_id,
                &fingerprint(manifest.file_size, 95),
            )
            .unwrap()
    );
    let published = store
        .transfer_delivery_attempt_by_hash(&hash)
        .unwrap()
        .unwrap();
    assert_eq!(
        published.phase,
        MetadataTransferDeliveryAttemptPhase::Published
    );
    assert_eq!(
        published.published_fingerprint.as_ref(),
        Some(&published_fingerprint)
    );

    let mut delivered_manifest = manifest.clone();
    delivered_manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
    delivered_manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Owned;
    delivered_manifest.delivered_path = Some(target_path.clone());
    delivered_manifest.source_fingerprint = Some(fingerprint(delivered_manifest.file_size, 92));
    store.upsert_transfer_manifest(&delivered_manifest).unwrap();
    assert!(
        store
            .transfer_delivery_attempt_by_hash(&hash)
            .unwrap()
            .is_none(),
        "delivered manifest commit must atomically clear its attempt"
    );

    let mut pending_manifest = delivered_manifest;
    pending_manifest.delivery_state = MetadataTransferDeliveryState::Pending;
    pending_manifest.delivery_ownership = MetadataTransferDeliveryOwnership::None;
    pending_manifest.delivered_path = None;
    pending_manifest.source_fingerprint = None;
    store.upsert_transfer_manifest(&pending_manifest).unwrap();
    let prepared = store
        .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
        .unwrap();
    assert_eq!(
        prepared.phase,
        MetadataTransferDeliveryAttemptPhase::Prepared
    );

    assert!(
        !store
            .clear_transfer_delivery_attempt(&hash, Uuid::new_v4())
            .unwrap()
    );
    assert!(
        store
            .clear_transfer_delivery_attempt(&hash, attempt_id)
            .unwrap()
    );
    assert!(
        store
            .transfer_delivery_attempt_by_hash(&hash)
            .unwrap()
            .is_none()
    );
}

#[test]
fn delivery_attempt_requires_an_authoritative_pending_download() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest();
    let hash = manifest.file_hash.clone();
    store.upsert_transfer_manifest(&manifest).unwrap();
    let target_path = std::env::temp_dir().join("Delivery.Eligibility.bin");
    let attempt_id = Uuid::new_v4();
    let staging_path = std::env::temp_dir().join(format!(".emulebb-delivery-{attempt_id}.tmp"));

    assert!(
        store
            .begin_transfer_delivery_attempt(
                &hash,
                attempt_id,
                &target_path,
                &std::env::temp_dir().join("unowned-staging.tmp"),
            )
            .is_err()
    );

    store
        .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
        .unwrap();
    assert!(store.request_transfer_deletion(&hash, None).unwrap());
    assert!(
        store
            .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path,)
            .is_err()
    );
    assert!(
        store
            .transfer_delivery_attempt_by_hash(&hash)
            .unwrap()
            .is_some()
    );
    assert!(store.finalize_transfer_deletion(&hash).unwrap());
    assert!(
        store
            .transfer_delivery_attempt_by_hash(&hash)
            .unwrap()
            .is_none()
    );

    manifest.file_hash = "ffeeddccbbaa99887766554433221100".to_string();
    manifest.completed = false;
    manifest.payload_fingerprint = None;
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(
        store
            .begin_transfer_delivery_attempt(
                &manifest.file_hash,
                Uuid::new_v4(),
                &target_path,
                &staging_path,
            )
            .is_err()
    );
}

#[test]
fn destructive_deletion_intent_is_idempotent_and_required_for_finalization() {
    let store = MetadataStore::in_memory().unwrap();
    let hash = "00112233445566778899aabbccddeeff";
    let mut manifest = MetadataTransferManifest {
        file_hash: hash.to_string(),
        display_name: "Delete.Intent.bin".to_string(),
        display_name_pinned: false,
        follow_majority_filename: false,
        file_name_observations: Vec::new(),
        file_size: 1,
        piece_size: 1,
        completed: true,
        final_rehash_pending: false,
        md4_hashset_acquired: true,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_hashset: Vec::new(),
        verified_ranges: vec![MetadataTransferRange { start: 0, end: 1 }],
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Verified".to_string(),
            bytes_written: 1,
            block_bitmap: None,
            ich_corrupted: false,
        }],
        sources: Vec::new(),
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        category_id: 0,
        control_state: None,
        transfer_row_removed: false,
        delivery_state: MetadataTransferDeliveryState::Delivered,
        delivery_ownership: MetadataTransferDeliveryOwnership::Owned,
        delivered_path: Some("/incoming/Delete.Intent.bin".into()),
        source_fingerprint: Some(fingerprint(1, 9)),
        payload_fingerprint: Some(fingerprint(1, 10)),
    };
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store.managed_download_transfer_hashes().unwrap(),
        vec![hash.to_string()]
    );
    assert!(store.managed_download_transfer_exists(hash).unwrap());

    assert_eq!(
        store.transfer_manifest_by_hash(hash).unwrap(),
        Some(manifest.clone())
    );
    assert_eq!(store.transfer_manifests().unwrap(), vec![manifest.clone()]);
    assert_eq!(
        store.active_transfer_manifests().unwrap(),
        vec![manifest.clone()]
    );
    assert!(store.incomplete_transfer_manifests().unwrap().is_empty());
    manifest.transfer_row_removed = true;
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store.managed_download_transfer_manifests().unwrap(),
        vec![manifest.clone()]
    );
    manifest.transfer_row_removed = false;
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(store.completed_transfer_catalog_entries().unwrap().len(), 1);
    assert_eq!(store.completed_transfer_publish_entries().unwrap().len(), 1);
    assert_eq!(
        store
            .try_completed_transfer_publish_entries()
            .unwrap()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.transfer_counts().unwrap(),
        MetadataTransferCounts {
            active: 0,
            completed: 1,
            total: 1,
        }
    );
    assert_eq!(
        store.completed_delivery_reconciliation_hashes().unwrap(),
        vec![hash.to_string()]
    );
    assert!(store.transfer_timestamps_by_hash(hash).unwrap().is_some());

    assert!(!store.finalize_transfer_deletion(hash).unwrap());
    let directory_identity = NativeFileIdentity::Unix {
        device_id: 17,
        inode_number: 29,
    };
    let directory_authority = MetadataTransferDirectoryDeletionAuthority {
        identity: directory_identity,
        marker_id: Uuid::from_u128(31),
    };
    assert!(
        store
            .request_transfer_deletion(hash, Some(directory_authority))
            .unwrap()
    );
    assert!(
        store
            .request_transfer_deletion(
                hash,
                Some(MetadataTransferDirectoryDeletionAuthority {
                    identity: NativeFileIdentity::Unix {
                        device_id: 17,
                        inode_number: 30,
                    },
                    marker_id: Uuid::from_u128(37),
                }),
            )
            .unwrap()
    );
    assert_eq!(
        store.transfer_directory_deletion_authority(hash).unwrap(),
        Some(directory_authority)
    );
    assert_eq!(
        store.pending_transfer_deletion_hashes().unwrap(),
        vec![hash.to_string()]
    );
    assert_eq!(
        store.managed_download_transfer_hashes().unwrap(),
        vec![hash.to_string()]
    );
    assert!(store.managed_download_transfer_exists(hash).unwrap());
    assert!(store.transfer_deletion_requested(hash).unwrap());
    assert!(store.transfer_timestamps_by_hash(hash).unwrap().is_none());
    assert!(store.transfer_manifest_by_hash(hash).unwrap().is_none());
    assert_eq!(
        store
            .pending_transfer_deletion_manifest_by_hash(hash)
            .unwrap(),
        Some(manifest.clone())
    );
    assert!(store.transfer_manifests().unwrap().is_empty());
    assert!(store.active_transfer_manifests().unwrap().is_empty());
    assert!(store.incomplete_transfer_manifests().unwrap().is_empty());
    assert!(
        store
            .managed_download_transfer_manifests()
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .completed_transfer_catalog_entries()
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .completed_transfer_publish_entries()
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .try_completed_transfer_publish_entries()
            .unwrap()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.transfer_counts().unwrap(),
        MetadataTransferCounts::default()
    );
    assert!(
        store
            .pending_completed_delivery_hashes()
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .completed_delivery_reconciliation_hashes()
            .unwrap()
            .is_empty()
    );

    let checkpointed = store
        .checkpoint_transfer_piece_progress(hash, &manifest.pieces[0])
        .unwrap();
    assert!(!checkpointed);

    let error = store.upsert_transfer_manifest(&manifest).unwrap_err();
    assert!(error.to_string().contains("pending cleanup"));
    {
        let conn = store.connection().unwrap();
        conn.execute(
            "UPDATE transfers SET delete_requested_at_ms = 7, updated_at_ms = 11",
            [],
        )
        .unwrap();
    }
    assert!(store.request_transfer_deletion(hash, None).unwrap());
    let timestamps = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT delete_requested_at_ms, updated_at_ms FROM transfers",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .unwrap();
    assert_eq!(timestamps, (7, 11));

    assert!(store.finalize_transfer_deletion(hash).unwrap());
    assert!(!store.finalize_transfer_deletion(hash).unwrap());
    assert!(store.pending_transfer_deletion_hashes().unwrap().is_empty());
    assert!(store.managed_download_transfer_hashes().unwrap().is_empty());
    assert!(!store.managed_download_transfer_exists(hash).unwrap());
    assert!(store.transfer_manifest_by_hash(hash).unwrap().is_none());
    assert!(
        store
            .pending_transfer_deletion_manifest_by_hash(hash)
            .unwrap()
            .is_none()
    );
}

#[test]
fn deletion_intent_never_adopts_a_later_transfer_directory() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = completed_pending_download_manifest();
    store.upsert_transfer_manifest(&manifest).unwrap();

    assert!(
        store
            .request_transfer_deletion(&manifest.file_hash, None)
            .unwrap()
    );
    assert!(
        store
            .request_transfer_deletion(
                &manifest.file_hash,
                Some(MetadataTransferDirectoryDeletionAuthority {
                    identity: NativeFileIdentity::Unix {
                        device_id: 41,
                        inode_number: 43,
                    },
                    marker_id: Uuid::from_u128(47),
                }),
            )
            .unwrap()
    );
    assert_eq!(
        store
            .transfer_directory_deletion_authority(&manifest.file_hash)
            .unwrap(),
        None
    );
}

#[test]
fn deletion_tombstone_roundtrips_and_transitions_idempotently() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest();
    let original_path = std::env::temp_dir().join("Delivery.Tombstone.bin");
    let source_fingerprint = fingerprint(manifest.file_size, 101);
    manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
    manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Owned;
    manifest.delivered_path = Some(original_path.clone());
    manifest.source_fingerprint = Some(source_fingerprint.clone());
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(
        store
            .request_transfer_deletion(&manifest.file_hash, None)
            .unwrap()
    );

    let abandoned_id = Uuid::new_v4();
    let abandoned_path = original_path
        .parent()
        .unwrap()
        .join(format!(".emulebb-delete-{abandoned_id}.tmp"));
    let prepared = store
        .begin_transfer_deletion_tombstone(
            &manifest.file_hash,
            abandoned_id,
            &original_path,
            &abandoned_path,
            &source_fingerprint,
        )
        .unwrap();
    assert_eq!(
        prepared.phase,
        MetadataTransferDeletionTombstonePhase::Prepared
    );
    assert!(prepared.moved_fingerprint.is_none());
    assert!(
        store
            .clear_prepared_transfer_deletion_tombstone(&manifest.file_hash, abandoned_id)
            .unwrap()
    );

    let tombstone_id = Uuid::new_v4();
    let tombstone_path = original_path
        .parent()
        .unwrap()
        .join(format!(".emulebb-delete-{tombstone_id}.tmp"));
    let prepared = store
        .begin_transfer_deletion_tombstone(
            &manifest.file_hash,
            tombstone_id,
            &original_path,
            &tombstone_path,
            &source_fingerprint,
        )
        .unwrap();
    assert_eq!(prepared.original_path, original_path);
    assert_eq!(prepared.tombstone_path, tombstone_path);
    assert_eq!(prepared.source_fingerprint, source_fingerprint);
    assert_eq!(
        store
            .transfer_deletion_tombstone_by_hash(&manifest.file_hash)
            .unwrap(),
        Some(prepared.clone())
    );

    let moved_fingerprint = fingerprint(manifest.file_size, 102);
    assert!(
        store
            .mark_transfer_deletion_tombstone_moved(
                &manifest.file_hash,
                tombstone_id,
                &moved_fingerprint,
            )
            .unwrap()
    );
    assert!(
        store
            .mark_transfer_deletion_tombstone_moved(
                &manifest.file_hash,
                tombstone_id,
                &moved_fingerprint,
            )
            .unwrap()
    );
    assert!(
        !store
            .mark_transfer_deletion_tombstone_moved(
                &manifest.file_hash,
                tombstone_id,
                &fingerprint(manifest.file_size, 103),
            )
            .unwrap()
    );
    let moved = store
        .transfer_deletion_tombstone_by_hash(&manifest.file_hash)
        .unwrap()
        .unwrap();
    assert_eq!(moved.phase, MetadataTransferDeletionTombstonePhase::Moved);
    assert_eq!(moved.moved_fingerprint, Some(moved_fingerprint));
    assert!(
        !store
            .clear_prepared_transfer_deletion_tombstone(&manifest.file_hash, tombstone_id)
            .unwrap()
    );

    assert!(
        store
            .finalize_transfer_deletion(&manifest.file_hash)
            .unwrap()
    );
    assert!(
        store
            .transfer_deletion_tombstone_by_hash(&manifest.file_hash)
            .unwrap()
            .is_none()
    );
}

#[test]
fn deletion_tombstone_requires_owned_delivered_output() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest();
    let original_path = std::env::temp_dir().join("Unowned.Tombstone.bin");
    let source_fingerprint = fingerprint(manifest.file_size, 104);
    manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
    manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Unowned;
    manifest.delivered_path = Some(original_path.clone());
    manifest.source_fingerprint = Some(source_fingerprint.clone());
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(
        store
            .request_transfer_deletion(&manifest.file_hash, None)
            .unwrap()
    );
    let tombstone_id = Uuid::new_v4();
    let tombstone_path = original_path
        .parent()
        .unwrap()
        .join(format!(".emulebb-delete-{tombstone_id}.tmp"));

    assert!(
        store
            .begin_transfer_deletion_tombstone(
                &manifest.file_hash,
                tombstone_id,
                &original_path,
                &tombstone_path,
                &source_fingerprint,
            )
            .is_err()
    );
}

#[test]
fn delete_transfer_manifest_clears_soft_known_file_references() {
    // A search result links to the known file by hash. Deleting the transfer
    // (and its known_files row) must not fail the foreign key check; the soft
    // reference is set to NULL so the search result row survives.
    let store = MetadataStore::in_memory().unwrap();
    let hash = "00112233445566778899aabbccddeeff";
    let manifest = MetadataTransferManifest {
        file_hash: hash.to_string(),
        display_name: "Scenario.File.bin".to_string(),
        display_name_pinned: false,
        follow_majority_filename: false,
        file_name_observations: Vec::new(),
        file_size: 1,
        piece_size: 1,
        completed: false,
        final_rehash_pending: false,
        md4_hashset_acquired: false,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_hashset: Vec::new(),
        verified_ranges: Vec::new(),
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Missing".to_string(),
            bytes_written: 0,
            block_bitmap: None,
            ich_corrupted: false,
        }],
        sources: Vec::new(),
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        category_id: 0,
        control_state: None,
        transfer_row_removed: false,
        delivery_state: MetadataTransferDeliveryState::Pending,
        delivery_ownership: MetadataTransferDeliveryOwnership::None,
        delivered_path: None,
        source_fingerprint: None,
        payload_fingerprint: None,
    };
    store.upsert_transfer_manifest(&manifest).unwrap();
    store
        .upsert_search(&crate::MetadataSearch {
            public_id: "search-one".to_string(),
            normalized_query: "scenario file".to_string(),
            spec: crate::MetadataSearchSpec {
                query: "scenario file".to_string(),
                method: "automatic".to_string(),
                file_type: String::new(),
                extension: String::new(),
                min_size_bytes: None,
                max_size_bytes: None,
                min_availability: None,
                min_complete_sources: None,
                min_bitrate_kbps: None,
                min_length_seconds: None,
                codec: String::new(),
                title: String::new(),
                album: String::new(),
                artist: String::new(),
            },
            resolved_method: None,
            status: "completed".to_string(),
            status_reason: None,
            created_at_ms: 1,
            updated_at_ms: 2,
            completed_at_ms: Some(2),
            results: vec![crate::MetadataSearchResult {
                file_hash: hash.to_string(),
                name: "Scenario.File.bin".to_string(),
                size_bytes: 1,
                source_count: 1,
                complete_source_count: 1,
                file_type: String::new(),
                media_artist: String::new(),
                media_album: String::new(),
                media_title: String::new(),
                media_length_seconds: 0,
                media_bitrate_kbps: 0,
                media_codec: String::new(),
                rating: 0,
                aich_hash: String::new(),
                complete: false,
                directory: String::new(),
                observations: vec![crate::MetadataSearchResultObservation {
                    origin: "local_index".to_string(),
                    server_endpoint: None,
                    name: "Scenario.File.bin".to_string(),
                    size_bytes: 1,
                    source_count: 1,
                    complete_source_count: 1,
                    source_client_id: None,
                    source_client_port: None,
                    file_type: String::new(),
                    media_artist: String::new(),
                    media_album: String::new(),
                    media_title: String::new(),
                    media_length_seconds: 0,
                    media_bitrate_kbps: 0,
                    media_codec: String::new(),
                    rating: 0,
                    aich_hash: String::new(),
                    complete: false,
                    directory: String::new(),
                    observed_at_ms: 2,
                }],
            }],
        })
        .unwrap();

    assert!(store.delete_transfer_manifest(hash).unwrap());
    // The search result row is retained with its known-file link cleared.
    assert_eq!(store.table_count("search_results").unwrap(), 1);
}

#[test]
fn completed_catalog_supports_hash_keyset_pages() {
    let store = MetadataStore::in_memory().unwrap();
    for sequence in 1..=3u128 {
        let file_hash = format!("{sequence:032x}");
        store
            .upsert_transfer_manifest(&MetadataTransferManifest {
                file_hash: file_hash.clone(),
                display_name: format!("catalog-{sequence}.bin"),
                display_name_pinned: false,
                follow_majority_filename: false,
                file_name_observations: Vec::new(),
                file_size: sequence as u64,
                piece_size: 1,
                completed: true,
                final_rehash_pending: false,
                md4_hashset_acquired: true,
                md4_hashset: Vec::new(),
                aich_hashset_acquired: false,
                aich_root: None,
                aich_hashset: Vec::new(),
                verified_ranges: vec![MetadataTransferRange {
                    start: 0,
                    end: sequence as u64,
                }],
                pieces: Vec::new(),
                sources: Vec::new(),
                upload_priority: "normal".to_string(),
                auto_upload_priority: false,
                comment: String::new(),
                rating: 0,
                category_id: 0,
                control_state: None,
                transfer_row_removed: false,
                delivery_state: MetadataTransferDeliveryState::Pending,
                delivery_ownership: MetadataTransferDeliveryOwnership::None,
                delivered_path: None,
                source_fingerprint: None,
                payload_fingerprint: Some(fingerprint(sequence as u64, sequence as u64)),
            })
            .unwrap();
    }

    let first = store
        .completed_transfer_catalog_entries_after(None, 2)
        .unwrap();
    assert_eq!(
        first
            .iter()
            .map(|entry| entry.file_hash.as_str())
            .collect::<Vec<_>>(),
        vec![
            "00000000000000000000000000000001",
            "00000000000000000000000000000002",
        ]
    );
    let second = store
        .completed_transfer_catalog_entries_after(Some(&first[1].file_hash), 2)
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].file_hash, "00000000000000000000000000000003");
    assert!(
        store
            .completed_transfer_catalog_entries_after(Some(&second[0].file_hash), 2)
            .unwrap()
            .is_empty()
    );
}
