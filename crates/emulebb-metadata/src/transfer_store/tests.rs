use super::*;
use crate::{MetadataStore, MetadataTransferSource};
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

fn completed_download_manifest(store: &MetadataStore) -> MetadataTransferManifest {
    MetadataTransferManifest {
        token: store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: "00112233445566778899aabbccddeeff".to_string(),
                display_name: "Concurrent.Sample.bin".to_string(),
                expected_size_bytes: Some(16),
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: 16,
            })
            .unwrap()
            .job
            .token,
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Concurrent.Sample.bin".to_string(),
        expected_size_bytes: Some(16),
        piece_size: 16,
        completed: true,
        final_rehash_pending: false,
        md4_hashset_acquired: true,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_root_origin: None,
        aich_trust_generation: 0,
        aich_hashset: Vec::new(),
        verified_ranges: vec![MetadataTransferRange { start: 0, end: 16 }],
        pieces: Vec::new(),
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        category_id: None,
        intent: crate::DownloadIntent::Started,
        transfer_row_removed: false,
        delivery_state: MetadataTransferDeliveryState::Pending,
        delivery_ownership: MetadataTransferDeliveryOwnership::None,
        delivered_path: None,
        source_fingerprint: None,
        payload_fingerprint: None,
    }
}

fn completed_pending_download_manifest(store: &MetadataStore) -> MetadataTransferManifest {
    let mut manifest = completed_download_manifest(store);
    manifest.delivery_state = MetadataTransferDeliveryState::Pending;
    manifest.source_fingerprint = None;
    manifest.payload_fingerprint = Some(fingerprint(manifest.expected_size_bytes.unwrap(), 91));
    manifest
}

fn register_shared_test_job(store: &MetadataStore, id: crate::JobId) {
    let manifest = store.download_job_manifest(id).unwrap().unwrap();
    let root = std::env::temp_dir().join("metadata-job-catalog");
    let relative = PathBuf::from(format!("{id}.bin"));
    let path = root.join(&relative);
    let fingerprint = fingerprint(manifest.expected_size_bytes.unwrap(), id.get() as u64 + 400);
    let mut roots = store.clone();
    roots
        .replace_shared_directory_roots(&[crate::MetadataSharedDirectoryRoot {
            path: root.to_string_lossy().into_owned(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    store
        .upsert_verified_local_content(&crate::MetadataVerifiedLocalContent {
            secondary_identity: None,
            file_hash: manifest.file_hash.clone(),
            display_name: manifest.display_name,
            file_size: manifest.expected_size_bytes.unwrap(),
            part_size: manifest.piece_size,
            md4_hashset: manifest.md4_hashset,
            aich_root: manifest.aich_root,
            aich_hashset: manifest.aich_hashset,
            path: path.clone(),
            fingerprint: fingerprint.clone(),
            upload_priority: manifest.upload_priority,
            auto_upload_priority: manifest.auto_upload_priority,
            comment: manifest.comment,
            rating: manifest.rating,
        })
        .unwrap();
    assert!(
        store
            .admit_local_path_to_root(&root, &path, &relative, &fingerprint)
            .unwrap()
    );
}

#[test]
fn recovery_settlement_rejects_changed_generation_and_journal_snapshot() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = completed_pending_download_manifest(&store);
    store.upsert_transfer_manifest(&manifest).unwrap();
    let attempt = Uuid::new_v4();
    let target = std::env::temp_dir().join("recovery-snapshot.bin");
    let prepared = store
        .begin_transfer_delivery_attempt(
            manifest.token,
            attempt,
            &target,
            &target
                .parent()
                .unwrap()
                .join(format!(".emulebb-delivery-{attempt}.tmp")),
        )
        .unwrap();
    assert!(
        store
            .reserve_delivery_output(manifest.token, &target, attempt)
            .unwrap()
    );
    let reservation = store
        .delivery_output_reservation(manifest.token.job_id, attempt)
        .unwrap()
        .unwrap();
    assert!(
        !store
            .release_orphaned_delivery_output(&reservation)
            .unwrap()
    );
    assert!(
        !store
            .release_recovered_delivery_output(manifest.token, &reservation, None)
            .unwrap()
    );
    let old_recovery_token = manifest.token;
    assert!(store.stop_download_job(manifest.token).unwrap());
    let stopped = store.download_job(manifest.token.job_id).unwrap().unwrap();
    let restarted = store
        .start_download_job(stopped.token, &std::env::temp_dir())
        .unwrap()
        .unwrap();
    assert!(
        !store
            .settle_recovered_delivery_attempt(old_recovery_token, &prepared)
            .unwrap()
    );
    assert!(
        !store
            .release_recovered_delivery_output(old_recovery_token, &reservation, Some(&prepared))
            .unwrap()
    );
    let recovery_token = restarted.token;
    let proof = fingerprint(16, 405);
    assert!(
        store
            .mark_transfer_delivery_attempt_staged(recovery_token, attempt, &proof)
            .unwrap()
            .is_some()
    );
    assert!(
        !store
            .settle_recovered_delivery_attempt(recovery_token, &prepared)
            .unwrap()
    );
    assert!(
        !store
            .release_recovered_delivery_output(recovery_token, &reservation, Some(&prepared))
            .unwrap()
    );
    let staged = store
        .download_job_delivery_attempt(recovery_token.job_id)
        .unwrap()
        .unwrap();
    assert!(
        store
            .mark_transfer_delivery_attempt_published(recovery_token, attempt, &proof)
            .unwrap()
            .is_some()
    );
    assert!(
        !store
            .settle_recovered_delivery_attempt(recovery_token, &staged)
            .unwrap()
    );
    let published = store
        .download_job_delivery_attempt(recovery_token.job_id)
        .unwrap()
        .unwrap();
    assert!(
        store
            .release_recovered_delivery_output(recovery_token, &reservation, Some(&published))
            .unwrap()
    );
    assert!(
        store
            .settle_recovered_delivery_attempt(recovery_token, &published)
            .unwrap()
    );
}

#[test]
fn partial_publication_requires_acquired_md4_authority() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_download_manifest(&store);
    manifest.completed = false;
    manifest.md4_hashset_acquired = false;
    manifest.verified_ranges = vec![MetadataTransferRange { start: 0, end: 8 }];
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(
        store
            .download_publish_entries_after(None, 256)
            .unwrap()
            .is_empty()
    );
    manifest.md4_hashset_acquired = true;
    store.upsert_transfer_manifest(&manifest).unwrap();
    let entries = store.download_publish_entries_after(None, 256).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file_hash, manifest.file_hash);
}

#[test]
fn live_journal_callbacks_cannot_advance_or_release_after_stop() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = completed_pending_download_manifest(&store);
    store.upsert_transfer_manifest(&manifest).unwrap();
    let attempt = Uuid::new_v4();
    let target = std::env::temp_dir().join(format!("{attempt}.bin"));
    let staging = std::env::temp_dir().join(format!(".emulebb-delivery-{attempt}.tmp"));
    store
        .begin_transfer_delivery_attempt(manifest.token, attempt, &target, &staging)
        .unwrap();
    assert!(store.stop_download_job(manifest.token).unwrap());
    let proof = fingerprint(16, 81);
    assert!(
        !store
            .mark_transfer_delivery_attempt_staged(manifest.token, attempt, &proof)
            .unwrap()
            .is_some()
    );
    let stopped = store.download_job(manifest.token.job_id).unwrap().unwrap();
    assert!(
        !store
            .mark_transfer_delivery_attempt_staged(stopped.token, attempt, &proof)
            .unwrap()
            .is_some()
    );
    let resumed = store
        .start_download_job(stopped.token, &std::env::temp_dir())
        .unwrap()
        .unwrap();
    assert!(
        store
            .mark_transfer_delivery_attempt_staged(resumed.token, attempt, &proof)
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .reserve_delivery_output(resumed.token, &target, attempt)
            .unwrap()
    );
    let reservation = store
        .delivery_output_reservation(resumed.token.job_id, attempt)
        .unwrap()
        .unwrap();
    let release_snapshot = store
        .download_job_delivery_attempt(resumed.token.job_id)
        .unwrap()
        .unwrap();
    assert!(store.stop_download_job(resumed.token).unwrap());
    assert!(
        !store
            .mark_transfer_delivery_attempt_published(resumed.token, attempt, &proof)
            .unwrap()
            .is_some()
    );
    assert!(
        !store
            .publish_reserved_delivery_attempt(resumed.token, attempt, &proof)
            .unwrap()
            .is_some()
    );
    assert!(
        !store
            .release_delivery_output(resumed.token, &reservation, &release_snapshot)
            .unwrap()
    );
    assert!(
        store
            .has_delivery_reservation(resumed.token.job_id, attempt)
            .unwrap()
    );
    assert_eq!(
        store
            .download_job_delivery_attempt(resumed.token.job_id)
            .unwrap()
            .unwrap()
            .phase,
        MetadataTransferDeliveryAttemptPhase::Staged
    );
    let recovery_token = store
        .download_job(resumed.token.job_id)
        .unwrap()
        .unwrap()
        .token;
    let recovery = store
        .download_job_delivery_attempt(resumed.token.job_id)
        .unwrap()
        .unwrap();
    store
        .release_recovered_delivery_output(recovery_token, &reservation, Some(&recovery))
        .unwrap();
    assert!(
        store
            .settle_recovered_delivery_attempt(recovery_token, &recovery)
            .unwrap()
    );
}

#[test]
fn retirement_creation_is_generation_fenced_and_pending_authority_blocks_job_deletion() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_download_manifest(&store);
    store.upsert_transfer_manifest(&manifest).unwrap();
    register_shared_test_job(&store, manifest.token.job_id);
    manifest = store
        .download_job_manifest(manifest.token.job_id)
        .unwrap()
        .unwrap();
    manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
    manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Unowned;
    manifest.delivered_path = Some(std::env::temp_dir().join("retirement-generation.bin"));
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(store.stop_download_job(manifest.token).unwrap());
    assert!(!store.request_transfer_retirement(manifest.token).unwrap());
    assert!(
        !store
            .transfer_retirement_pending(manifest.token.job_id)
            .unwrap()
    );
    let stopped = store.download_job(manifest.token.job_id).unwrap().unwrap();
    let resumed = store
        .start_download_job(stopped.token, &std::env::temp_dir())
        .unwrap()
        .unwrap();
    assert!(store.request_transfer_retirement(resumed.token).unwrap());
    assert!(
        store
            .request_transfer_deletion(resumed.token.job_id)
            .unwrap()
    );
    assert!(
        store
            .finalize_transfer_deletion(resumed.token.job_id)
            .is_err()
    );
    assert!(
        store
            .transfer_retirement_pending(resumed.token.job_id)
            .unwrap()
    );
    assert!(store.download_job(resumed.token.job_id).unwrap().is_some());
    assert!(
        store
            .finalize_transfer_retirement(resumed.token.job_id)
            .unwrap()
    );
    if store
        .transfer_retirement_pending(resumed.token.job_id)
        .unwrap()
    {
        assert!(
            store
                .finalize_transfer_retirement(resumed.token.job_id)
                .unwrap()
        );
    }
    assert!(
        store
            .finalize_transfer_deletion(resumed.token.job_id)
            .unwrap()
    );
    assert_eq!(store.table_count("known_files").unwrap(), 1);
}

#[test]
fn publication_collapses_history_and_preserves_current_partial_claim_size() {
    let mut store = MetadataStore::in_memory().unwrap();
    for _ in 0..2 {
        let mut manifest = completed_download_manifest(&store);
        store.upsert_transfer_manifest(&manifest).unwrap();
        register_shared_test_job(&store, manifest.token.job_id);
        manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
        manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Unowned;
        manifest.delivered_path = Some(
            std::env::temp_dir()
                .join("metadata-job-catalog")
                .join(format!("{}.bin", manifest.token.job_id)),
        );
        store.upsert_transfer_manifest(&manifest).unwrap();
        assert!(store.request_transfer_retirement(manifest.token).unwrap());
        assert!(
            store
                .finalize_transfer_retirement(manifest.token.job_id)
                .unwrap()
        );
    }
    let mut current = completed_download_manifest(&store);
    current.display_name = "current-partial.bin".into();
    assert!(
        store
            .apply_download_peer_delta(
                current.token,
                &crate::MetadataDownloadPeerDelta::Rename(current.display_name.clone()),
            )
            .unwrap()
            .changed
    );
    current.completed = false;
    current.verified_ranges = vec![MetadataTransferRange { start: 0, end: 8 }];
    store.upsert_transfer_manifest(&current).unwrap();
    assert_eq!(
        store.download_jobs_after(None, 256, false).unwrap().len(),
        3
    );
    let complete = store.download_publish_entries_after(None, 256).unwrap();
    assert_eq!(complete.len(), 1);
    assert_ne!(complete[0].display_name, current.display_name);
    assert_eq!(
        store
            .completed_transfer_catalog_entries_after(None, 256)
            .unwrap()
            .len(),
        1
    );
    store.replace_shared_directory_roots(&[]).unwrap();
    let partial = store.download_publish_entries_after(None, 256).unwrap();
    assert_eq!(partial.len(), 1);
    assert_eq!(partial[0].display_name, current.display_name);
    assert_eq!(partial[0].file_size, 16);
    assert!(
        store
            .completed_transfer_catalog_entries_after(None, 256)
            .unwrap()
            .is_empty()
    );
    let unknown = store
        .admit_download_job(&crate::DownloadJobRequest {
            file_hash: "ab".repeat(16),
            display_name: "unverified-claim.bin".into(),
            expected_size_bytes: Some(73),
            category_id: None,
            intent: crate::DownloadIntent::Started,
            piece_size: 73,
        })
        .unwrap()
        .job;
    assert!(unknown.accepted_size_bytes.is_none());
    assert_eq!(
        store
            .file_all_time_upload_totals(&unknown.file_hash)
            .unwrap(),
        Some((0, 73))
    );
    let mut manifest = store
        .download_job_manifest(unknown.token.job_id)
        .unwrap()
        .unwrap();
    manifest.md4_hashset_acquired = true;
    manifest.verified_ranges = vec![MetadataTransferRange { start: 0, end: 20 }];
    store.upsert_transfer_manifest(&manifest).unwrap();
    let offered = store.download_publish_entries_after(None, 256).unwrap();
    assert_eq!(offered.len(), 2);
    assert_eq!(
        offered
            .iter()
            .find(|entry| entry.file_hash == unknown.file_hash)
            .unwrap()
            .file_size,
        73
    );
}

#[test]
fn delivery_pages_bound_native_path_bytes_and_keep_a_resumable_prefix() {
    let store = MetadataStore::in_memory().unwrap();
    let parent = std::env::temp_dir().join("p".repeat(20_000));
    for hash in 100u8..120 {
        let job = store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: hex::encode([hash; 16]),
                display_name: format!("{hash}.bin"),
                expected_size_bytes: Some(16),
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: 16,
            })
            .unwrap()
            .job;
        let mut manifest = store
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap();
        manifest.completed = true;
        store.upsert_transfer_manifest(&manifest).unwrap();
        let attempt = Uuid::new_v4();
        store
            .begin_transfer_delivery_attempt(
                job.token,
                attempt,
                &parent.join(format!("{hash}.bin")),
                &parent.join(format!(".emulebb-delivery-{attempt}.tmp")),
            )
            .unwrap();
    }
    let first = store.download_delivery_attempts_after(None, 256).unwrap();
    assert!(!first.is_empty() && first.len() < 20);
    let mut total = first.len();
    let mut cursor = first.last().unwrap().job_id;
    loop {
        let page = store
            .download_delivery_attempts_after(Some(cursor), 256)
            .unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page[0].job_id > cursor);
        cursor = page.last().unwrap().job_id;
        total += page.len();
    }
    assert_eq!(total, 20);
    store.connection().unwrap().execute("UPDATE local_paths SET native_path=zeroblob(65538) WHERE id=(SELECT target_path_id FROM download_delivery_attempts WHERE job_id=?1)",[first[0].job_id]).unwrap();
    assert!(
        store
            .download_job_delivery_attempt(first[0].job_id)
            .is_err()
    );
    assert!(store.download_delivery_attempts_after(None, 256).is_err());
}

#[test]
fn old_generation_cannot_checkpoint_or_begin_delivery_after_stop() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest(&store);
    manifest.pieces = vec![MetadataTransferPiece {
        piece_index: 0,
        state: "Verified".into(),
        prefix_bytes: 16,
        present_bytes: 16,
        block_bitmap: None,
        ich_corrupted: false,
    }];
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(store.stop_download_job(manifest.token).unwrap());
    assert!(store.upsert_transfer_manifest(&manifest).is_err());
    assert!(
        !store
            .checkpoint_download_progress(manifest.token, &manifest.pieces[..1])
            .unwrap()
    );
    let attempt = Uuid::new_v4();
    let target = std::env::temp_dir().join("stale-delivery.bin");
    let staging = std::env::temp_dir().join(format!(".emulebb-delivery-{attempt}.tmp"));
    assert!(
        store
            .begin_transfer_delivery_attempt(manifest.token, attempt, &target, &staging)
            .is_err()
    );
    assert!(
        store
            .download_job_delivery_attempt(manifest.token.job_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn terminal_job_survives_retirement_and_old_callbacks_cannot_touch_redownload() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_download_manifest(&store);
    let path = std::env::temp_dir().join("retained-completed-job.bin");
    store
        .upsert_verified_local_content(&crate::MetadataVerifiedLocalContent {
            secondary_identity: None,
            file_hash: manifest.file_hash.clone(),
            display_name: manifest.display_name.clone(),
            file_size: 16,
            part_size: 16,
            md4_hashset: Vec::new(),
            aich_root: None,
            aich_hashset: Vec::new(),
            path: path.clone(),
            fingerprint: fingerprint(16, 200),
            upload_priority: "normal".into(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
        })
        .unwrap();
    manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
    manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Unowned;
    manifest.delivered_path = Some(path.clone());
    manifest.pieces = vec![MetadataTransferPiece {
        piece_index: 0,
        state: "Verified".into(),
        prefix_bytes: 16,
        present_bytes: 16,
        block_bitmap: None,
        ich_corrupted: false,
    }];
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(store.request_transfer_retirement(manifest.token).unwrap());
    let completed = store.download_job(manifest.token.job_id).unwrap().unwrap();
    assert!(completed.completed_at_s.is_some());
    assert_eq!(completed.checkpointed_bytes, 16);
    assert_eq!(completed.progress(), Some(1.0));
    assert!(completed.removed_at_s.is_none());
    assert!(!completed.internal_storage_retired);
    assert!(
        store
            .pending_delivery_jobs_after(None, 256)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .connection()
            .unwrap()
            .execute(
                "DELETE FROM download_jobs WHERE id=?1",
                [manifest.token.job_id]
            )
            .is_err()
    );
    assert!(
        store
            .finalize_transfer_retirement(manifest.token.job_id)
            .unwrap()
    );
    assert_eq!(store.table_count("download_job_pieces").unwrap(), 0);
    let retired = store.download_job(manifest.token.job_id).unwrap().unwrap();
    assert_eq!(retired.completed_at_s, completed.completed_at_s);
    assert!(retired.internal_storage_retired);
    assert_eq!(retired.checkpointed_bytes, 0);
    assert_eq!(retired.progress(), Some(1.0));
    assert!(store.local_file_instance(&path).unwrap().is_some());
    assert!(store.upsert_transfer_manifest(&manifest).is_err());
    assert!(store.connection().unwrap().execute("UPDATE download_jobs SET delivery_state='pending',delivery_ownership='none',delivered_path_id=NULL WHERE id=?1",[manifest.token.job_id]).is_err());
    let next = store
        .admit_download_job(&crate::DownloadJobRequest {
            file_hash: manifest.file_hash.clone(),
            display_name: "again.bin".into(),
            expected_size_bytes: Some(16),
            category_id: None,
            intent: crate::DownloadIntent::Started,
            piece_size: 16,
        })
        .unwrap()
        .job;
    assert!(next.token.job_id > manifest.token.job_id);
    let mut new_manifest = store
        .download_job_manifest(next.token.job_id)
        .unwrap()
        .unwrap();
    new_manifest.pieces = vec![MetadataTransferPiece {
        piece_index: 0,
        state: "Missing".into(),
        prefix_bytes: 0,
        present_bytes: 0,
        block_bitmap: None,
        ich_corrupted: false,
    }];
    store.upsert_transfer_manifest(&new_manifest).unwrap();
    assert!(
        !store
            .checkpoint_download_progress(manifest.token, &manifest.pieces[..1])
            .unwrap()
    );
    assert_eq!(
        store
            .download_job_manifest(next.token.job_id)
            .unwrap()
            .unwrap()
            .pieces[0]
            .prefix_bytes,
        0
    );
    assert_eq!(
        store.download_jobs_after(None, 256, false).unwrap().len(),
        2
    );
    assert!(store.remove_download_job(manifest.token.job_id).unwrap());
    assert_eq!(
        store
            .latest_download_job(&manifest.file_hash)
            .unwrap()
            .unwrap()
            .token,
        next.token
    );
}

#[test]
fn failed_partial_projection_rolls_back_shared_path_withdrawal() {
    let mut store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_download_manifest(&store);
    manifest.completed = false;
    store.upsert_transfer_manifest(&manifest).unwrap();
    store
        .connection()
        .unwrap()
        .execute("UPDATE download_jobs SET comment=?1", ["x".repeat(65_537)])
        .unwrap();
    let root =
        PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").expect("CARGO_TARGET_DIR is required"))
            .join("tmp")
            .join("projection-rollback");
    let path = root.join("sample.bin");
    store
        .replace_shared_directory_roots(&[crate::MetadataSharedDirectoryRoot {
            path: root.to_string_lossy().into_owned(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    let fingerprint = fingerprint(manifest.expected_size_bytes.unwrap(), 19);
    store
        .upsert_verified_local_content(&crate::MetadataVerifiedLocalContent {
            secondary_identity: None,
            file_hash: manifest.file_hash.clone(),
            display_name: manifest.display_name.clone(),
            file_size: 16,
            part_size: 16,
            md4_hashset: Vec::new(),
            aich_root: None,
            aich_hashset: Vec::new(),
            path: path.clone(),
            fingerprint: fingerprint.clone(),
            upload_priority: "normal".into(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
        })
        .unwrap();
    store
        .replace_root_memberships(
            &root,
            &store.shared_root_scan_watermark(&root).unwrap(),
            &[(
                path.clone(),
                PathBuf::from("sample.bin"),
                fingerprint.clone(),
            )],
        )
        .unwrap();
    assert!(
        store
            .withdraw_shared_path_with_projection(&path, &manifest.file_hash, Some(&fingerprint))
            .is_err()
    );
    assert!(
        store
            .next_shared_copy(&manifest.file_hash, 0, 65_536)
            .unwrap()
            .is_some()
    );
}

#[test]
fn partial_offer_batch_returns_a_bounded_prefix_and_can_resume() {
    let store = MetadataStore::in_memory().unwrap();
    let mut hashes = Vec::new();
    for index in 1u8..=5 {
        let mut manifest = completed_download_manifest(&store);
        manifest.file_hash = hex::encode([index; 16]);
        manifest.display_name = format!("{}-{index}", "n".repeat(60_000));
        manifest.completed = false;
        manifest.token = store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: manifest.file_hash.clone(),
                display_name: manifest.display_name.clone(),
                expected_size_bytes: manifest.expected_size_bytes,
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: manifest.piece_size,
            })
            .unwrap()
            .job
            .token;
        store.upsert_transfer_manifest(&manifest).unwrap();
        hashes.push([index; 16]);
    }
    // Disabling complete-library sharing does not suppress verified partials.
    for hash in &hashes {
        assert_eq!(
            store
                .set_library_sharing_enabled(&hex::encode(hash), false)
                .unwrap(),
            Some(true)
        );
    }
    let first = store.try_verified_share_batch(&hashes).unwrap().unwrap();
    assert_eq!(first.len(), 3);
    assert!(first.iter().all(|(_, partial)| partial.is_some()));
    let remainder = store
        .try_verified_share_batch(&hashes[first.len()..])
        .unwrap()
        .unwrap();
    assert_eq!(remainder.len(), 2);
    assert!(remainder.iter().all(|(_, partial)| partial.is_some()));
}

#[test]
fn accepted_network_decision_roundtrips_without_becoming_known_content_identity() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest(&store);
    manifest.completed = false;
    manifest.payload_fingerprint = None;
    manifest.aich_root = Some("11".repeat(20));
    manifest.aich_root_origin = Some("network_consensus".to_string());
    manifest.aich_trust_generation = 1;
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store.download_job_manifest(manifest.token.job_id).unwrap(),
        Some(manifest.clone())
    );
    let known_root: Option<Vec<u8>> = store
        .connection()
        .unwrap()
        .query_row("SELECT aich_root FROM known_files", [], |row| row.get(0))
        .unwrap();
    assert!(known_root.is_none());

    manifest.aich_root = None;
    manifest.aich_root_origin = None;
    manifest.aich_trust_generation = 2;
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store.download_job_manifest(manifest.token.job_id).unwrap(),
        Some(manifest)
    );
}

#[test]
fn root_origin_and_part_set_cannot_manufacture_an_accepted_decision() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = completed_pending_download_manifest(&store);
    let mut invalid = manifest.clone();
    invalid.aich_root = Some("11".repeat(20));
    assert!(store.upsert_transfer_manifest(&invalid).is_err());
    invalid = manifest.clone();
    invalid.aich_root_origin = Some("network_consensus".to_string());
    assert!(store.upsert_transfer_manifest(&invalid).is_err());
    invalid = manifest.clone();
    invalid.aich_hashset_acquired = true;
    assert!(store.upsert_transfer_manifest(&invalid).is_err());
    invalid = manifest;
    invalid.aich_trust_generation = u64::MAX;
    assert!(store.upsert_transfer_manifest(&invalid).is_err());
}

#[test]
fn accepted_local_identity_and_stale_checkpoint_preserve_md4_verified_progress() {
    let store = MetadataStore::in_memory().unwrap();
    let mut stale = completed_download_manifest(&store);
    stale.completed = false;
    stale.aich_root = Some("11".repeat(20));
    stale.aich_root_origin = Some("network_consensus".to_owned());
    stale.aich_trust_generation = 1;
    stale.aich_hashset_acquired = true;
    stale.aich_hashset = vec!["33".repeat(20)];
    stale.pieces = vec![MetadataTransferPiece {
        piece_index: 0,
        state: "Verified".to_owned(),
        prefix_bytes: 16,
        present_bytes: 16,
        block_bitmap: None,
        ich_corrupted: false,
    }];
    store.upsert_transfer_manifest(&stale).unwrap();
    let content = crate::MetadataVerifiedLocalContent {
        secondary_identity: None,
        file_hash: stale.file_hash.clone(),
        display_name: "local-authority.bin".to_owned(),
        file_size: stale.expected_size_bytes.unwrap(),
        part_size: stale.piece_size,
        md4_hashset: Vec::new(),
        aich_root: Some("22".repeat(20)),
        aich_hashset: Vec::new(),
        path: std::env::temp_dir().join("aich-new-authority.bin"),
        fingerprint: fingerprint(stale.expected_size_bytes.unwrap(), 21),
        upload_priority: "normal".to_owned(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
    };
    store.upsert_verified_local_content(&content).unwrap();
    let accepted = store
        .download_job_manifest(stale.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(accepted.aich_root, content.aich_root);
    assert_eq!(accepted.aich_root_origin.as_deref(), Some("local_computed"));
    assert_eq!(accepted.aich_trust_generation, 2);
    assert!(!accepted.aich_hashset_acquired);
    assert!(accepted.aich_hashset.is_empty());
    assert_eq!(accepted.verified_ranges, stale.verified_ranges);
    assert_eq!(accepted.pieces, stale.pieces);
    assert_eq!(accepted.md4_hashset_acquired, stale.md4_hashset_acquired);

    stale.comment = "newer independent checkpoint metadata".to_owned();
    let canonical = store.upsert_transfer_manifest_reconciled(&stale).unwrap();
    assert_eq!(canonical.aich_root, accepted.aich_root);
    assert_eq!(canonical.aich_root_origin, accepted.aich_root_origin);
    assert_eq!(
        canonical.aich_trust_generation,
        accepted.aich_trust_generation
    );
    assert!(canonical.aich_hashset.is_empty());
    assert!(!canonical.aich_hashset_acquired);
    assert_eq!(canonical.comment, stale.comment);
    assert_eq!(canonical.verified_ranges, stale.verified_ranges);
    assert_eq!(canonical.pieces, stale.pieces);
    assert_eq!(
        store.download_job_manifest(stale.token.job_id).unwrap(),
        Some(canonical)
    );
}

#[test]
fn local_acceptance_of_same_master_preserves_acquired_parts_and_progress() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest(&store);
    manifest.md4_hashset = vec!["22".repeat(16)];
    manifest.aich_root = Some("11".repeat(20));
    manifest.aich_root_origin = Some("network_consensus".to_owned());
    manifest.aich_trust_generation = 7;
    manifest.aich_hashset_acquired = true;
    manifest.aich_hashset = vec!["33".repeat(20)];
    store.upsert_transfer_manifest(&manifest).unwrap();
    let content = crate::MetadataVerifiedLocalContent {
        secondary_identity: None,
        file_hash: manifest.file_hash.clone(),
        display_name: "same-master.bin".to_owned(),
        file_size: manifest.expected_size_bytes.unwrap(),
        part_size: manifest.piece_size,
        md4_hashset: manifest.md4_hashset.clone(),
        aich_root: manifest.aich_root.clone(),
        aich_hashset: manifest.aich_hashset.clone(),
        path: std::env::temp_dir().join("emulebb-same-master.bin"),
        fingerprint: fingerprint(manifest.expected_size_bytes.unwrap(), 201),
        upload_priority: "normal".to_owned(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
    };
    store.upsert_verified_local_content(&content).unwrap();
    manifest.aich_root_origin = Some("local_computed".to_owned());
    manifest.aich_trust_generation = 8;
    // Provenance changed, but the acquired set is still bound to the same
    // master. Whole-manifest equality also preserves independent MD4/progress.
    assert_eq!(
        store.download_job_manifest(manifest.token.job_id).unwrap(),
        Some(manifest.clone())
    );
    store.upsert_verified_local_content(&content).unwrap();
    assert_eq!(
        store.download_job_manifest(manifest.token.job_id).unwrap(),
        Some(manifest)
    );
}

#[test]
fn unverified_operator_claim_does_not_override_verified_content_authority() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_download_manifest(&store);
    manifest.completed = false;
    manifest.aich_root = Some("11".repeat(20));
    manifest.aich_root_origin = Some("operator_link".to_string());
    manifest.aich_trust_generation = 1;
    store.upsert_transfer_manifest(&manifest).unwrap();
    let mut proposal = manifest.clone();
    proposal.aich_root = Some("22".repeat(20));
    proposal.aich_root_origin = Some("network_consensus".to_string());
    proposal.aich_trust_generation = 2;
    store.upsert_transfer_manifest(&proposal).unwrap();

    let content = crate::MetadataVerifiedLocalContent {
        secondary_identity: None,
        file_hash: manifest.file_hash.clone(),
        display_name: "local.bin".to_string(),
        file_size: manifest.expected_size_bytes.unwrap(),
        part_size: manifest.piece_size,
        md4_hashset: Vec::new(),
        aich_root: Some("22".repeat(20)),
        aich_hashset: Vec::new(),
        path: std::env::temp_dir().join("aich-operator-conflict.bin"),
        fingerprint: fingerprint(manifest.expected_size_bytes.unwrap(), 9),
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
    };
    store.upsert_verified_local_content(&content).unwrap();
    let accepted = store
        .download_job_manifest(manifest.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(accepted.aich_root, content.aich_root);
    assert_eq!(accepted.aich_root_origin.as_deref(), Some("local_computed"));
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store
            .download_job_manifest(manifest.token.job_id)
            .unwrap()
            .unwrap(),
        accepted
    );
    let mut conflict = accepted.clone();
    conflict.aich_root = Some("33".repeat(20));
    conflict.aich_trust_generation += 1;
    assert!(
        store
            .upsert_transfer_manifest(&conflict)
            .unwrap_err()
            .is::<crate::MetadataContentConflict>()
    );
    assert_eq!(
        store
            .download_job_manifest(manifest.token.job_id)
            .unwrap()
            .unwrap(),
        accepted
    );
    assert_eq!(store.table_count("verified_local_content").unwrap(), 1);
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
    let manifest = completed_download_manifest(&store);
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(
        store
            .current_shared_files_by_hash(&manifest.file_hash)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn invalid_payload_geometry_cannot_replace_a_valid_transfer() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = completed_download_manifest(&store);
    store.upsert_transfer_manifest(&manifest).unwrap();
    let mut invalid = manifest.clone();
    invalid.verified_ranges[0].end += 1;
    assert!(store.upsert_transfer_manifest(&invalid).is_err());
    invalid = manifest.clone();
    invalid.pieces.push(MetadataTransferPiece {
        piece_index: 0,
        state: "Missing".into(),
        prefix_bytes: manifest.expected_size_bytes.unwrap() + 1,
        present_bytes: manifest.expected_size_bytes.unwrap() + 1,
        block_bitmap: None,
        ich_corrupted: false,
    });
    assert!(store.upsert_transfer_manifest(&invalid).is_err());
    invalid.pieces[0].prefix_bytes = 0;
    invalid.pieces[0].present_bytes = 0;
    invalid.pieces[0].piece_index = 1;
    assert!(store.upsert_transfer_manifest(&invalid).is_err());
    assert_eq!(
        store.download_job_manifest(manifest.token.job_id).unwrap(),
        Some(manifest)
    );
}

#[test]
fn transfer_presentation_is_independent_of_canonical_index_names() {
    let mut store = MetadataStore::in_memory().unwrap();
    let manifest = completed_download_manifest(&store);
    store.upsert_transfer_manifest(&manifest).unwrap();
    store
        .upsert_indexed_file(
            &crate::MetadataIndexedFile {
                ed2k_hash: manifest.file_hash.clone(),
                name: "local-sample.bin".into(),
                size_bytes: manifest.expected_size_bytes.unwrap(),
                content_type: String::new(),
                availability_score: 0,
            },
            crate::MetadataIndexedFileOrigin::LocalShare,
        )
        .unwrap();
    assert_eq!(
        store.download_job_manifest(manifest.token.job_id).unwrap(),
        Some(manifest)
    );
}

#[test]
fn accepted_identity_survives_conflicting_transfer_and_index_observations() {
    let mut store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_download_manifest(&store);
    manifest.completed = false;
    manifest.aich_root = Some("11".repeat(20));
    manifest.aich_root_origin = Some("operator_link".to_string());
    manifest.aich_trust_generation = 1;
    store.upsert_transfer_manifest(&manifest).unwrap();
    store
        .upsert_verified_local_content(&crate::MetadataVerifiedLocalContent {
            secondary_identity: None,
            file_hash: manifest.file_hash.clone(),
            display_name: manifest.display_name.clone(),
            file_size: 16,
            part_size: 16,
            md4_hashset: Vec::new(),
            aich_root: manifest.aich_root.clone(),
            aich_hashset: Vec::new(),
            path: std::env::temp_dir().join("accepted-job-identity.bin"),
            fingerprint: fingerprint(16, 303),
            upload_priority: "normal".into(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
        })
        .unwrap();
    manifest = store
        .download_job_manifest(manifest.token.job_id)
        .unwrap()
        .unwrap();

    let mut conflicting = manifest.clone();
    conflicting.expected_size_bytes = conflicting.expected_size_bytes.map(|size| size + 1);
    assert!(
        store
            .upsert_transfer_manifest(&conflicting)
            .unwrap_err()
            .is::<crate::MetadataContentConflict>()
    );
    conflicting = manifest.clone();
    conflicting.aich_root = Some("22".repeat(20));
    assert!(
        store
            .upsert_transfer_manifest(&conflicting)
            .unwrap_err()
            .is::<crate::MetadataContentConflict>()
    );
    assert!(
        store
            .upsert_indexed_file(
                &crate::MetadataIndexedFile {
                    ed2k_hash: manifest.file_hash.clone(),
                    name: "sample.bin".into(),
                    size_bytes: manifest.expected_size_bytes.unwrap() + 1,
                    content_type: String::new(),
                    availability_score: 1,
                },
                crate::MetadataIndexedFileOrigin::LocalShare
            )
            .unwrap_err()
            .is::<crate::MetadataContentConflict>()
    );

    let mut sparse = manifest.clone();
    sparse.aich_root = None;
    sparse.aich_root_origin = None;
    store.upsert_transfer_manifest(&sparse).unwrap();
    assert_eq!(
        store.download_job_manifest(manifest.token.job_id).unwrap(),
        Some(manifest)
    );
}

#[test]
fn transfer_snapshots_keep_unchanged_children_and_source_first_seen() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_download_manifest(&store);
    manifest.completed = false;
    manifest.pieces.push(MetadataTransferPiece {
        piece_index: 0,
        state: "Missing".into(),
        prefix_bytes: 0,
        present_bytes: 0,
        block_bitmap: None,
        ich_corrupted: false,
    });
    manifest.md4_hashset.push("11".repeat(16));
    store
        .apply_download_peer_delta(
            manifest.token,
            &crate::MetadataDownloadPeerDelta::Source {
                source: MetadataTransferSource {
                    ip: "192.0.2.1".into(),
                    tcp_port: 4662,
                    user_hash: None,
                    connect_options: None,
                    file_comment: String::new(),
                    file_rating: 0,
                },
                description_only: false,
            },
        )
        .unwrap();
    store.upsert_transfer_manifest(&manifest).unwrap();
    store.connection().unwrap().execute_batch(
        "UPDATE download_job_sources SET first_seen_at_s = 1;
         CREATE TEMP TRIGGER no_piece_delete BEFORE DELETE ON main.download_job_pieces BEGIN SELECT RAISE(ABORT,'unchanged piece deleted'); END;
         CREATE TEMP TRIGGER no_piece_update BEFORE UPDATE ON main.download_job_pieces BEGIN SELECT RAISE(ABORT,'unchanged piece updated'); END;
         CREATE TEMP TRIGGER no_hash_delete BEFORE DELETE ON main.download_job_md4_part_hashes BEGIN SELECT RAISE(ABORT,'unchanged hash deleted'); END;
         CREATE TEMP TRIGGER no_range_delete BEFORE DELETE ON main.download_job_verified_ranges BEGIN SELECT RAISE(ABORT,'unchanged range deleted'); END;"
    ).unwrap();
    manifest.comment = "updated comment".into();
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row(
                "SELECT first_seen_at_s FROM download_job_sources",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER no_piece_update;")
        .unwrap();
    manifest.pieces[0].prefix_bytes = 8;
    manifest.pieces[0].present_bytes = 8;
    store.upsert_transfer_manifest(&manifest).unwrap();
    let expected = manifest.clone();
    manifest.pieces.push(manifest.pieces[0].clone());
    assert!(store.upsert_transfer_manifest(&manifest).is_err());
    assert_eq!(
        store.download_job_manifest(manifest.token.job_id).unwrap(),
        Some(expected)
    );
}

#[test]
fn owned_delivery_requires_exact_size_fingerprint_authority() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest(&store);
    manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
    manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Owned;
    manifest.delivered_path = Some("/incoming/Delivery.Attempt.bin".into());

    assert!(store.upsert_transfer_manifest(&manifest).is_err());
    manifest.source_fingerprint = Some(fingerprint(manifest.expected_size_bytes.unwrap() + 1, 92));
    assert!(store.upsert_transfer_manifest(&manifest).is_err());
    manifest.source_fingerprint = Some(fingerprint(manifest.expected_size_bytes.unwrap(), 93));
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store.download_job_manifest(manifest.token.job_id).unwrap(),
        Some(manifest)
    );
}

#[test]
fn transfer_manifest_waits_for_existing_writer_before_reading_snapshot() {
    let path = unique_store_path("manifest-immediate-transaction");
    remove_store_files(&path);
    let writer = MetadataStore::open(&path).unwrap();
    let contender = MetadataStore::open(&path).unwrap();
    let manifest = completed_download_manifest(&writer);
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
    let mut manifest = completed_pending_download_manifest(&store);
    manifest.display_name = "Sample.Transfer.bin".to_string();
    assert!(
        store
            .apply_download_peer_delta(
                manifest.token,
                &crate::MetadataDownloadPeerDelta::Rename(manifest.display_name.clone()),
            )
            .unwrap()
            .changed
    );
    manifest.aich_root = Some("1111111111111111111111111111111111111111".to_string());
    manifest.aich_root_origin = Some("operator_link".to_string());
    manifest.aich_trust_generation = 1;
    manifest.aich_hashset_acquired = true;
    manifest.aich_hashset = vec!["2222222222222222222222222222222222222222".to_string()];
    manifest.pieces = vec![MetadataTransferPiece {
        piece_index: 0,
        state: "Verified".to_string(),
        prefix_bytes: manifest.expected_size_bytes.unwrap(),
        present_bytes: manifest.expected_size_bytes.unwrap(),
        block_bitmap: None,
        ich_corrupted: false,
    }];

    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store.download_job_manifest(manifest.token.job_id).unwrap(),
        Some(manifest.clone())
    );
    assert_eq!(
        store
            .managed_download_transfer_jobs_after(None, 256)
            .unwrap(),
        vec![manifest.token.job_id]
    );
    assert_eq!(
        store.download_jobs_after(None, 256, false).unwrap(),
        vec![store.download_job(manifest.token.job_id).unwrap().unwrap()]
    );
    assert!(
        store
            .managed_download_transfer_exists(manifest.token.job_id)
            .unwrap()
    );
    assert_eq!(
        store.download_jobs_after(None, 256, false).unwrap(),
        vec![store.download_job(manifest.token.job_id).unwrap().unwrap()]
    );
    assert_eq!(
        store
            .completed_transfer_catalog_entries_after(None, 256)
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        store
            .download_publish_entries_after(None, 256)
            .unwrap()
            .len(),
        1
    );

    assert!(store.remove_download_job(manifest.token.job_id).unwrap());
    assert!(store.upsert_transfer_manifest(&manifest).is_err());
    assert!(
        store
            .download_jobs_after(None, 256, false)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .latest_download_job(&manifest.file_hash)
            .unwrap()
            .is_none()
    );
    let next = store
        .admit_download_job(&crate::DownloadJobRequest {
            file_hash: manifest.file_hash.clone(),
            display_name: manifest.display_name.clone(),
            expected_size_bytes: manifest.expected_size_bytes,
            category_id: None,
            intent: crate::DownloadIntent::Started,
            piece_size: manifest.piece_size,
        })
        .unwrap()
        .job;
    assert_ne!(next.token.job_id, manifest.token.job_id);
    manifest.token = next.token;
    manifest.completed = false;
    manifest.final_rehash_pending = true;
    manifest.payload_fingerprint = None;
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store.download_jobs_after(None, 256, true).unwrap(),
        vec![store.download_job(manifest.token.job_id).unwrap().unwrap()]
    );
}

#[test]
fn current_schema_rejects_persisted_network_claim_states() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_download_manifest(&store);
    manifest.completed = false;
    manifest.verified_ranges.clear();
    manifest.pieces = vec![MetadataTransferPiece {
        piece_index: 0,
        state: "Missing".to_string(),
        prefix_bytes: 0,
        present_bytes: 0,
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
            .download_job_manifest(manifest.token.job_id)
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
        token: store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: "00112233445566778899aabbccddeeff".to_string(),
                display_name: "Demand.Sample.bin".to_string(),
                expected_size_bytes: Some(1024),
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: 1024,
            })
            .unwrap()
            .job
            .token,
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Demand.Sample.bin".to_string(),
        expected_size_bytes: Some(1024),
        piece_size: 1024,
        completed: true,
        final_rehash_pending: false,
        md4_hashset_acquired: false,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_root_origin: None,
        aich_trust_generation: 0,
        aich_hashset: Vec::new(),
        verified_ranges: vec![MetadataTransferRange {
            start: 0,
            end: 1024,
        }],
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Verified".to_string(),
            prefix_bytes: 1024,
            present_bytes: 1024,
            block_bitmap: None,
            ich_corrupted: false,
        }],
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        category_id: None,
        intent: crate::DownloadIntent::Started,
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
        store.pending_delivery_jobs_after(None, 256).unwrap(),
        vec![manifest.token.job_id]
    );
    assert_eq!(
        store.pending_delivery_jobs_after(None, 256).unwrap(),
        vec![manifest.token.job_id]
    );
    assert!(
        store
            .file_upload_snapshot(&manifest.file_hash)
            .unwrap()
            .unwrap()
            .known_client
    );
    assert!(
        store
            .file_upload_snapshot(&manifest.file_hash)
            .unwrap()
            .is_some()
    );
    store
        .apply_credit_deltas(
            &[],
            &[crate::MetadataFileUploadDelta {
                file_hash: manifest.file_hash.clone(),
                accepted_sessions: 1,
                upload_requests: 2,
                last_requested_at_s: Some(1_700_000_001),
                ..Default::default()
            }],
        )
        .unwrap();

    assert!(
        store
            .download_publish_entries_after(None, 256)
            .unwrap()
            .is_empty()
    );
    let mut manifest = manifest;
    manifest.md4_hashset_acquired = true;
    store.upsert_transfer_manifest(&manifest).unwrap();
    let publish = store.download_publish_entries_after(None, 256).unwrap();
    assert_eq!(publish.len(), 1);
    assert_eq!(publish[0].all_time_upload_requests, 2);
    assert_eq!(publish[0].all_time_upload_accepts, 1);
    assert_eq!(publish[0].last_upload_requested_at_s, Some(1_700_000_001));

    register_shared_test_job(&store, manifest.token.job_id);
    let catalog = store
        .completed_transfer_catalog_entries_after(None, 256)
        .unwrap();
    assert_eq!(catalog[0].all_time_upload_requests, 2);
    assert_eq!(catalog[0].all_time_upload_accepts, 1);
    assert_eq!(catalog[0].last_upload_requested_at_s, Some(1_700_000_001));
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
fn deleting_download_preserves_same_hash_local_content() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest(&store);
    manifest.md4_hashset = vec!["22222222222222222222222222222222".to_string()];
    manifest.aich_hashset = vec!["3333333333333333333333333333333333333333".to_string()];
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store.download_job_manifest(manifest.token.job_id).unwrap(),
        Some(manifest.clone())
    );
    let path = std::env::temp_dir().join("emulebb-same-hash-local-content.bin");
    let content = crate::MetadataVerifiedLocalContent {
        secondary_identity: None,
        file_hash: manifest.file_hash.clone(),
        display_name: "shared.bin".to_string(),
        file_size: manifest.expected_size_bytes.unwrap(),
        part_size: manifest.piece_size,
        md4_hashset: vec!["44444444444444444444444444444444".to_string()],
        aich_root: Some("1111111111111111111111111111111111111111".to_string()),
        aich_hashset: vec!["5555555555555555555555555555555555555555".to_string()],
        path: path.clone(),
        fingerprint: fingerprint(manifest.expected_size_bytes.unwrap(), 200),
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
    };
    store.upsert_verified_local_content(&content).unwrap();
    // A newly accepted master retires parts stored without that authority. MD4
    // hashes and verified progress remain independent of this AICH transition.
    manifest.aich_root = content.aich_root.clone();
    manifest.aich_root_origin = Some("local_computed".to_string());
    manifest.aich_trust_generation += 1;
    manifest.aich_hashset.clear();
    manifest.aich_hashset_acquired = false;
    assert_eq!(
        store.download_job_manifest(manifest.token.job_id).unwrap(),
        Some(manifest.clone())
    );

    assert!(
        store
            .delete_transfer_manifest(manifest.token.job_id)
            .unwrap()
    );
    assert!(
        store
            .download_job_manifest(manifest.token.job_id)
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
    for table in [
        "download_job_md4_part_hashes",
        "download_job_aich_part_hashes",
        "download_job_verified_ranges",
    ] {
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
    assert!(
        !store
            .delete_transfer_manifest(manifest.token.job_id)
            .unwrap()
    );
}

#[test]
fn delete_transfer_manifest_removes_transfer_rows() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = MetadataTransferManifest {
        token: store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: "00112233445566778899aabbccddeeff".to_string(),
                display_name: "Sample.Transfer.bin".to_string(),
                expected_size_bytes: Some(1),
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: 1,
            })
            .unwrap()
            .job
            .token,
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Sample.Transfer.bin".to_string(),
        expected_size_bytes: Some(1),
        piece_size: 1,
        completed: false,
        final_rehash_pending: false,
        md4_hashset_acquired: false,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_root_origin: None,
        aich_trust_generation: 0,
        aich_hashset: Vec::new(),
        verified_ranges: Vec::new(),
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Missing".to_string(),
            prefix_bytes: 0,
            present_bytes: 0,
            block_bitmap: None,
            ich_corrupted: false,
        }],
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        category_id: None,
        intent: crate::DownloadIntent::Started,
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
            .delete_transfer_manifest(manifest.token.job_id)
            .unwrap()
    );
    assert!(
        store
            .download_job_manifest(manifest.token.job_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn download_delivery_attempts_roundtrip_and_transition_idempotently() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = completed_pending_download_manifest(&store);
    let hash = manifest.file_hash.clone();
    store.upsert_transfer_manifest(&manifest).unwrap();

    let attempt_id = Uuid::new_v4();
    let target_path = std::env::temp_dir().join("Delivery.Attempt.bin");
    let staging_path = std::env::temp_dir().join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    let prepared = store
        .begin_transfer_delivery_attempt(manifest.token, attempt_id, &target_path, &staging_path)
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
    assert_eq!(prepared.created_at_s, prepared.updated_at_s);
    assert_eq!(store.table_count("download_delivery_attempts").unwrap(), 1);
    assert_eq!(
        store
            .download_job_delivery_attempt(manifest.token.job_id)
            .unwrap(),
        Some(prepared.clone())
    );
    assert_eq!(
        store.download_delivery_attempts_after(None, 256).unwrap(),
        vec![prepared.clone()]
    );
    assert_eq!(
        store
            .begin_transfer_delivery_attempt(
                manifest.token,
                attempt_id,
                &target_path,
                &staging_path
            )
            .unwrap(),
        prepared
    );
    assert!(
        store
            .begin_transfer_delivery_attempt(
                manifest.token,
                Uuid::new_v4(),
                &target_path,
                &staging_path,
            )
            .is_err()
    );

    let staging_fingerprint = fingerprint(manifest.expected_size_bytes.unwrap(), 91);
    assert!(
        !store
            .mark_transfer_delivery_attempt_staged(
                manifest.token,
                Uuid::new_v4(),
                &staging_fingerprint,
            )
            .unwrap()
            .is_some()
    );
    let staged_receipt = store
        .mark_transfer_delivery_attempt_staged(manifest.token, attempt_id, &staging_fingerprint)
        .unwrap()
        .unwrap();
    assert!(
        store
            .mark_transfer_delivery_attempt_staged(manifest.token, attempt_id, &staging_fingerprint)
            .unwrap()
            .is_some()
    );
    assert!(
        !store
            .mark_transfer_delivery_attempt_staged(
                manifest.token,
                attempt_id,
                &fingerprint(manifest.expected_size_bytes.unwrap(), 93),
            )
            .unwrap()
            .is_some()
    );
    let staged = store
        .download_job_delivery_attempt(manifest.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(staged_receipt, staged);
    assert_eq!(staged.phase, MetadataTransferDeliveryAttemptPhase::Staged);
    assert_eq!(
        staged.staging_fingerprint.as_ref(),
        Some(&staging_fingerprint)
    );
    assert!(staged.published_fingerprint.is_none());
    assert_eq!(staged.created_at_s, prepared.created_at_s);
    assert!(staged.updated_at_s >= staged.created_at_s);

    let published_fingerprint = fingerprint(manifest.expected_size_bytes.unwrap(), 94);
    let published_receipt = store
        .mark_transfer_delivery_attempt_published(
            manifest.token,
            attempt_id,
            &published_fingerprint,
        )
        .unwrap()
        .unwrap();
    assert!(
        store
            .mark_transfer_delivery_attempt_published(
                manifest.token,
                attempt_id,
                &published_fingerprint,
            )
            .unwrap()
            .is_some()
    );
    assert!(
        !store
            .mark_transfer_delivery_attempt_published(
                manifest.token,
                attempt_id,
                &fingerprint(manifest.expected_size_bytes.unwrap(), 95),
            )
            .unwrap()
            .is_some()
    );
    let published = store
        .download_job_delivery_attempt(manifest.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(published_receipt, published);
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
    delivered_manifest.source_fingerprint = Some(fingerprint(
        delivered_manifest.expected_size_bytes.unwrap(),
        92,
    ));
    store.upsert_transfer_manifest(&delivered_manifest).unwrap();
    assert!(
        store
            .download_job_delivery_attempt(manifest.token.job_id)
            .unwrap()
            .is_none(),
        "delivered manifest commit must atomically clear its attempt"
    );

    let mut pending_manifest = delivered_manifest;
    pending_manifest.delivery_state = MetadataTransferDeliveryState::Pending;
    pending_manifest.delivery_ownership = MetadataTransferDeliveryOwnership::None;
    pending_manifest.delivered_path = None;
    pending_manifest.source_fingerprint = None;
    assert!(store.upsert_transfer_manifest(&pending_manifest).is_err());
    // Recovery settlement belongs to a genuinely pending job, not a rewind of
    // durable delivery that could create a duplicate output after restart.
    let store = MetadataStore::in_memory().unwrap();
    let manifest = completed_pending_download_manifest(&store);
    store.upsert_transfer_manifest(&manifest).unwrap();
    let prepared = store
        .begin_transfer_delivery_attempt(manifest.token, attempt_id, &target_path, &staging_path)
        .unwrap();
    assert_eq!(
        prepared.phase,
        MetadataTransferDeliveryAttemptPhase::Prepared
    );

    let mut wrong_attempt = prepared.clone();
    wrong_attempt.attempt_id = Uuid::new_v4();
    assert!(
        !store
            .settle_recovered_delivery_attempt(manifest.token, &wrong_attempt)
            .unwrap()
    );
    assert!(
        store
            .settle_recovered_delivery_attempt(manifest.token, &prepared)
            .unwrap()
    );
    assert!(
        store
            .download_job_delivery_attempt(manifest.token.job_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn delivery_attempt_requires_an_authoritative_pending_download() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest(&store);
    store.upsert_transfer_manifest(&manifest).unwrap();
    let target_path = std::env::temp_dir().join("Delivery.Eligibility.bin");
    let attempt_id = Uuid::new_v4();
    let staging_path = std::env::temp_dir().join(format!(".emulebb-delivery-{attempt_id}.tmp"));

    assert!(
        store
            .begin_transfer_delivery_attempt(
                manifest.token,
                attempt_id,
                &target_path,
                &std::env::temp_dir().join("unowned-staging.tmp"),
            )
            .is_err()
    );

    store
        .begin_transfer_delivery_attempt(manifest.token, attempt_id, &target_path, &staging_path)
        .unwrap();
    assert!(
        store
            .request_transfer_deletion(manifest.token.job_id)
            .unwrap()
    );
    // Simulate completed exact internal cleanup while independent output
    // authority remains. It alone must prevent physical owner-row deletion.
    assert!(
        store
            .finalize_transfer_retirement(manifest.token.job_id)
            .unwrap()
    );

    assert!(
        store
            .begin_transfer_delivery_attempt(
                manifest.token,
                attempt_id,
                &target_path,
                &staging_path,
            )
            .is_err()
    );
    assert!(
        store
            .download_job_delivery_attempt(manifest.token.job_id)
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .finalize_transfer_deletion(manifest.token.job_id)
            .is_err()
    );
    assert!(
        store
            .download_job_delivery_attempt(manifest.token.job_id)
            .unwrap()
            .is_some()
    );
    let recovery_token = store
        .download_job(manifest.token.job_id)
        .unwrap()
        .unwrap()
        .token;
    let recovery = store
        .download_job_delivery_attempt(manifest.token.job_id)
        .unwrap()
        .unwrap();
    assert!(
        store
            .settle_recovered_delivery_attempt(recovery_token, &recovery)
            .unwrap()
    );
    if store
        .transfer_retirement_pending(manifest.token.job_id)
        .unwrap()
    {
        assert!(
            store
                .finalize_transfer_retirement(manifest.token.job_id)
                .unwrap()
        );
    }
    assert!(
        store
            .finalize_transfer_deletion(manifest.token.job_id)
            .unwrap()
    );
    assert!(
        store
            .download_job_delivery_attempt(manifest.token.job_id)
            .unwrap()
            .is_none()
    );

    manifest.file_hash = "ffeeddccbbaa99887766554433221100".to_string();
    manifest.completed = false;
    manifest.payload_fingerprint = None;
    manifest.token = store
        .admit_download_job(&crate::DownloadJobRequest {
            file_hash: manifest.file_hash.clone(),
            display_name: manifest.display_name.clone(),
            expected_size_bytes: manifest.expected_size_bytes,
            category_id: None,
            intent: crate::DownloadIntent::Started,
            piece_size: manifest.piece_size,
        })
        .unwrap()
        .job
        .token;
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(
        store
            .begin_transfer_delivery_attempt(
                manifest.token,
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
        token: store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: hash.to_string(),
                display_name: "Delete.Intent.bin".to_string(),
                expected_size_bytes: Some(1),
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: 1,
            })
            .unwrap()
            .job
            .token,
        file_hash: hash.to_string(),
        display_name: "Delete.Intent.bin".to_string(),
        expected_size_bytes: Some(1),
        piece_size: 1,
        completed: true,
        final_rehash_pending: false,
        md4_hashset_acquired: true,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_root_origin: None,
        aich_trust_generation: 0,
        aich_hashset: Vec::new(),
        verified_ranges: vec![MetadataTransferRange { start: 0, end: 1 }],
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Verified".to_string(),
            prefix_bytes: 1,
            present_bytes: 1,
            block_bitmap: None,
            ich_corrupted: false,
        }],
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        category_id: None,
        intent: crate::DownloadIntent::Started,
        transfer_row_removed: false,
        delivery_state: MetadataTransferDeliveryState::Delivered,
        delivery_ownership: MetadataTransferDeliveryOwnership::Owned,
        delivered_path: Some("/incoming/Delete.Intent.bin".into()),
        source_fingerprint: Some(fingerprint(1, 9)),
        payload_fingerprint: Some(fingerprint(1, 10)),
    };
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store
            .managed_download_transfer_jobs_after(None, 256)
            .unwrap(),
        vec![manifest.token.job_id]
    );
    assert!(
        store
            .managed_download_transfer_exists(manifest.token.job_id)
            .unwrap()
    );

    assert_eq!(
        store.download_job_manifest(manifest.token.job_id).unwrap(),
        Some(manifest.clone())
    );
    assert_eq!(
        store.download_jobs_after(None, 256, false).unwrap(),
        vec![store.download_job(manifest.token.job_id).unwrap().unwrap()]
    );
    assert_eq!(
        store.download_jobs_after(None, 256, false).unwrap(),
        vec![store.download_job(manifest.token.job_id).unwrap().unwrap()]
    );
    assert!(
        !store
            .download_jobs_after(None, 256, true)
            .unwrap()
            .is_empty()
    );
    manifest.transfer_row_removed = true;
    let canonical = store
        .upsert_transfer_manifest_reconciled(&manifest)
        .unwrap();
    assert!(!canonical.transfer_row_removed);
    manifest = canonical;
    assert_eq!(
        store
            .completed_transfer_catalog_entries_after(None, 256)
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        store
            .download_publish_entries_after(None, 256)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .try_download_publish_entries_after(None, 256)
            .unwrap()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.transfer_counts().unwrap(),
        MetadataTransferCounts {
            active: 1,
            completed: 0,
            total: 1,
        }
    );
    assert_eq!(
        store.pending_delivery_jobs_after(None, 256).unwrap(),
        vec![manifest.token.job_id]
    );
    assert!(
        store
            .download_job_timestamps(manifest.token.job_id)
            .unwrap()
            .is_some()
    );

    assert!(
        !store
            .finalize_transfer_deletion(manifest.token.job_id)
            .unwrap()
    );
    let directory_identity = NativeFileIdentity::Unix {
        device_id: 17,
        inode_number: 29,
    };
    let allocated = store
        .start_download_job(manifest.token, &std::env::temp_dir())
        .unwrap()
        .unwrap();
    assert!(
        store
            .establish_download_job_storage(allocated.token, directory_identity)
            .unwrap()
    );
    let directory_authority = MetadataTransferDirectoryDeletionAuthority {
        identity: directory_identity,
        marker_id: allocated.storage.unwrap().marker_id,
    };
    assert!(
        store
            .request_transfer_deletion(manifest.token.job_id)
            .unwrap()
    );
    assert!(
        store
            .request_transfer_deletion(manifest.token.job_id)
            .unwrap()
    );
    assert_eq!(
        store
            .download_job_retirement(manifest.token.job_id)
            .unwrap()
            .and_then(|intent| intent.authority),
        Some(directory_authority)
    );
    assert_eq!(
        store
            .pending_transfer_deletion_jobs_after(None, 256)
            .unwrap(),
        vec![manifest.token.job_id]
    );
    assert_eq!(
        store
            .managed_download_transfer_jobs_after(None, 256)
            .unwrap(),
        vec![manifest.token.job_id]
    );
    assert!(
        store
            .managed_download_transfer_exists(manifest.token.job_id)
            .unwrap()
    );
    assert!(
        store
            .transfer_deletion_requested(manifest.token.job_id)
            .unwrap()
    );
    assert!(
        store
            .download_job_timestamps(manifest.token.job_id)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .download_job_manifest(manifest.token.job_id)
            .unwrap()
            .is_none()
    );
    let mut removed_manifest = manifest.clone();
    removed_manifest.token = store
        .download_job(manifest.token.job_id)
        .unwrap()
        .unwrap()
        .token;
    removed_manifest.transfer_row_removed = true;
    assert_eq!(
        store
            .pending_download_job_deletion_manifest(manifest.token.job_id)
            .unwrap(),
        Some(removed_manifest)
    );
    assert!(
        store
            .download_jobs_after(None, 256, false)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .download_jobs_after(None, 256, false)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .download_jobs_after(None, 256, true)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .download_jobs_after(None, 256, false)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .completed_transfer_catalog_entries_after(None, 256)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .download_publish_entries_after(None, 256)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .try_download_publish_entries_after(None, 256)
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
            .pending_delivery_jobs_after(None, 256)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .pending_delivery_jobs_after(None, 256)
            .unwrap()
            .is_empty()
    );

    let checkpointed = store
        .checkpoint_download_progress(manifest.token, &manifest.pieces[..1])
        .unwrap();
    assert!(!checkpointed);

    let error = store.upsert_transfer_manifest(&manifest).unwrap_err();
    assert!(error.to_string().contains("stale download job"));
    {
        let conn = store.connection().unwrap();
        conn.execute(
            "UPDATE download_jobs SET delete_requested_at_s = 7, updated_at_s = 11",
            [],
        )
        .unwrap();
    }
    assert!(
        store
            .request_transfer_deletion(manifest.token.job_id)
            .unwrap()
    );
    let timestamps = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT delete_requested_at_s, updated_at_s FROM download_jobs",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .unwrap();
    assert_eq!(timestamps, (7, 11));

    if store
        .transfer_retirement_pending(manifest.token.job_id)
        .unwrap()
    {
        assert!(
            store
                .finalize_transfer_retirement(manifest.token.job_id)
                .unwrap()
        );
    }
    assert!(
        store
            .finalize_transfer_deletion(manifest.token.job_id)
            .unwrap()
    );
    assert!(
        !store
            .finalize_transfer_deletion(manifest.token.job_id)
            .unwrap()
    );
    assert!(
        store
            .pending_transfer_deletion_jobs_after(None, 256)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .managed_download_transfer_jobs_after(None, 256)
            .unwrap()
            .is_empty()
    );
    assert!(
        !store
            .managed_download_transfer_exists(manifest.token.job_id)
            .unwrap()
    );
    assert!(
        store
            .download_job_manifest(manifest.token.job_id)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .pending_download_job_deletion_manifest(manifest.token.job_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn deletion_intent_never_adopts_a_later_transfer_directory() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = completed_pending_download_manifest(&store);
    store.upsert_transfer_manifest(&manifest).unwrap();

    assert!(
        store
            .request_transfer_deletion(manifest.token.job_id)
            .unwrap()
    );
    assert!(
        store
            .request_transfer_deletion(manifest.token.job_id)
            .unwrap()
    );
    assert_eq!(
        store
            .download_job_retirement(manifest.token.job_id)
            .unwrap()
            .and_then(|intent| intent.authority),
        None
    );
}

#[test]
fn deletion_tombstone_roundtrips_and_transitions_idempotently() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest(&store);
    let original_path = std::env::temp_dir().join("Delivery.Tombstone.bin");
    let source_fingerprint = fingerprint(manifest.expected_size_bytes.unwrap(), 101);
    manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
    manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Owned;
    manifest.delivered_path = Some(original_path.clone());
    manifest.source_fingerprint = Some(source_fingerprint.clone());
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(
        store
            .request_transfer_deletion(manifest.token.job_id)
            .unwrap()
    );
    // Simulate completed exact internal cleanup while independent output
    // authority remains. It alone must prevent physical owner-row deletion.
    assert!(
        store
            .finalize_transfer_retirement(manifest.token.job_id)
            .unwrap()
    );

    let abandoned_id = Uuid::new_v4();
    let abandoned_path = original_path
        .parent()
        .unwrap()
        .join(format!(".emulebb-delete-{abandoned_id}.tmp"));
    let prepared = store
        .begin_transfer_deletion_tombstone(
            manifest.token.job_id,
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
    let cleanup_token = store
        .download_job(manifest.token.job_id)
        .unwrap()
        .unwrap()
        .token;
    assert!(
        !store
            .settle_recovered_output_tombstone(manifest.token, &prepared)
            .unwrap()
    );
    let mut changed_prepared = prepared.clone();
    changed_prepared.updated_at_s += 1;
    assert!(
        !store
            .settle_recovered_output_tombstone(cleanup_token, &changed_prepared)
            .unwrap()
    );
    assert!(
        store
            .settle_recovered_output_tombstone(cleanup_token, &prepared)
            .unwrap()
    );

    let tombstone_id = Uuid::new_v4();
    let tombstone_path = original_path
        .parent()
        .unwrap()
        .join(format!(".emulebb-delete-{tombstone_id}.tmp"));
    let prepared = store
        .begin_transfer_deletion_tombstone(
            manifest.token.job_id,
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
            .download_job_deletion_tombstone(manifest.token.job_id)
            .unwrap(),
        Some(prepared.clone())
    );

    let recovery_token = store
        .download_job(manifest.token.job_id)
        .unwrap()
        .unwrap()
        .token;
    let moved_fingerprint = fingerprint(manifest.expected_size_bytes.unwrap(), 102);
    let committed_moved = store
        .mark_transfer_deletion_tombstone_moved(
            manifest.token.job_id,
            tombstone_id,
            &moved_fingerprint,
        )
        .unwrap()
        .unwrap();
    assert!(
        store
            .mark_transfer_deletion_tombstone_moved(
                manifest.token.job_id,
                tombstone_id,
                &moved_fingerprint,
            )
            .unwrap()
            .is_some()
    );
    assert!(
        !store
            .mark_transfer_deletion_tombstone_moved(
                manifest.token.job_id,
                tombstone_id,
                &fingerprint(manifest.expected_size_bytes.unwrap(), 103),
            )
            .unwrap()
            .is_some()
    );
    let moved = store
        .download_job_deletion_tombstone(manifest.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(committed_moved, moved);
    assert_eq!(moved.phase, MetadataTransferDeletionTombstonePhase::Moved);
    assert_eq!(moved.moved_fingerprint, Some(moved_fingerprint.clone()));
    assert!(
        !store
            .settle_recovered_output_tombstone(recovery_token, &prepared)
            .unwrap()
    );
    assert!(
        !store
            .settle_recovered_output_tombstone(manifest.token, &moved)
            .unwrap()
    );
    let delete_intent = {
        let conn = store.connection().unwrap();
        let intent: i64 = conn
            .query_row(
                "SELECT delete_requested_at_s FROM download_jobs WHERE id=?1",
                [recovery_token.job_id],
                |row| row.get(0),
            )
            .unwrap();
        conn.execute(
            "UPDATE download_jobs SET delete_requested_at_s=NULL WHERE id=?1",
            [recovery_token.job_id],
        )
        .unwrap();
        intent
    };
    assert!(
        !store
            .settle_recovered_output_tombstone(recovery_token, &moved)
            .unwrap()
    );
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET delete_requested_at_s=?2 WHERE id=?1",
            params![recovery_token.job_id, delete_intent],
        )
        .unwrap();
    let mut wrong_snapshot = moved.clone();
    wrong_snapshot.updated_at_s += 1;
    assert!(
        !store
            .settle_recovered_output_tombstone(recovery_token, &wrong_snapshot)
            .unwrap()
    );
    assert!(
        !store
            .clear_prepared_transfer_deletion_tombstone(manifest.token.job_id, tombstone_id)
            .unwrap()
    );

    assert!(
        store
            .finalize_transfer_deletion(manifest.token.job_id)
            .is_err()
    );
    assert!(
        store
            .download_job_deletion_tombstone(manifest.token.job_id)
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .settle_recovered_output_tombstone(recovery_token, &moved)
            .unwrap()
    );
    if store
        .transfer_retirement_pending(manifest.token.job_id)
        .unwrap()
    {
        assert!(
            store
                .finalize_transfer_retirement(manifest.token.job_id)
                .unwrap()
        );
    }
    assert!(
        store
            .finalize_transfer_deletion(manifest.token.job_id)
            .unwrap()
    );
    assert!(
        store
            .download_job_deletion_tombstone(manifest.token.job_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn deletion_tombstone_requires_owned_delivered_output() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_pending_download_manifest(&store);
    let original_path = std::env::temp_dir().join("Unowned.Tombstone.bin");
    let source_fingerprint = fingerprint(manifest.expected_size_bytes.unwrap(), 104);
    manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
    manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Unowned;
    manifest.delivered_path = Some(original_path.clone());
    manifest.source_fingerprint = Some(source_fingerprint.clone());
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(
        store
            .request_transfer_deletion(manifest.token.job_id)
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
                manifest.token.job_id,
                tombstone_id,
                &original_path,
                &tombstone_path,
                &source_fingerprint,
            )
            .is_err()
    );
}

#[test]
fn deleting_last_job_preserves_known_file_knowledge_and_search_links() {
    // Removing a job is not an instruction to forget canonical content knowledge.
    let store = MetadataStore::in_memory().unwrap();
    let hash = "00112233445566778899aabbccddeeff";
    let manifest = MetadataTransferManifest {
        token: store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: hash.to_string(),
                display_name: "Scenario.File.bin".to_string(),
                expected_size_bytes: Some(1),
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: 1,
            })
            .unwrap()
            .job
            .token,
        file_hash: hash.to_string(),
        display_name: "Scenario.File.bin".to_string(),
        expected_size_bytes: Some(1),
        piece_size: 1,
        completed: false,
        final_rehash_pending: false,
        md4_hashset_acquired: false,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_root_origin: None,
        aich_trust_generation: 0,
        aich_hashset: Vec::new(),
        verified_ranges: Vec::new(),
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Missing".to_string(),
            prefix_bytes: 0,
            present_bytes: 0,
            block_bitmap: None,
            ich_corrupted: false,
        }],
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        category_id: None,
        intent: crate::DownloadIntent::Started,
        transfer_row_removed: false,
        delivery_state: MetadataTransferDeliveryState::Pending,
        delivery_ownership: MetadataTransferDeliveryOwnership::None,
        delivered_path: None,
        source_fingerprint: None,
        payload_fingerprint: None,
    };
    store.upsert_transfer_manifest(&manifest).unwrap();
    store.add_file_all_time_uploaded(hash, 23).unwrap();
    let session_id = store
        .create_search(&crate::MetadataSearchData {
            parent_search_id: None,
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
            status: "running".to_string(),
            status_reason: None,
            created_at_s: 1,
            updated_at_s: 2,
            completed_at_s: None,
        })
        .unwrap();
    store
        .ingest_search_observations(
            &[crate::MetadataContentObservationEvent {
                claim: crate::MetadataContentClaim {
                    hash: hex::decode(hash).unwrap().try_into().unwrap(),
                    size_bytes: Some(1),
                },
                origin: crate::MetadataObservationOrigin::Server,
                reporter_endpoint: Some("192.0.2.4:4661".parse().unwrap()),
                metadata: crate::MetadataContentMetadata {
                    name: Some("Scenario.File.bin".into()),
                    source_count: Some(1),
                    complete_source_count: Some(1),
                    ..Default::default()
                },
                observed_at_s: 2,
            }],
            &crate::MetadataSearchProjection {
                session_id,
                name_votes: vec![crate::MetadataSearchNameVote {
                    normalized_name: "Scenario.File.bin".into(),
                    origin: crate::MetadataObservationOrigin::Server,
                    reporter_endpoint: Some("192.0.2.9:4661".parse().unwrap()),
                    quality: crate::MetadataSearchNameQuality {
                        useful: true,
                        sources: 1,
                        complete_sources: 1,
                        rating: 0,
                    },
                }],
                fields: vec![crate::MetadataSearchResultFields {
                    quality: Default::default(),
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
                }],
            },
        )
        .unwrap();

    assert!(
        store
            .delete_transfer_manifest(manifest.token.job_id)
            .unwrap()
    );
    assert_eq!(store.table_count("search_results").unwrap(), 1);
    assert_eq!(store.table_count("known_files").unwrap(), 1);
    assert!(store.latest_download_job(hash).unwrap().is_none());
    let retained:(String,i64,bool)=store.connection().unwrap().query_row(
        "SELECT display_name,all_time_uploaded_bytes,EXISTS(SELECT 1 FROM search_results r JOIN content_claims c ON c.id=r.claim_id WHERE c.ed2k_hash=known_files.ed2k_hash) FROM known_files",
        [],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
    assert_eq!(retained, ("Scenario.File.bin".into(), 23, true));
}

#[test]
fn completed_catalog_supports_hash_keyset_pages() {
    let store = MetadataStore::in_memory().unwrap();
    for sequence in 1..=3u128 {
        let file_hash = format!("{sequence:032x}");
        store
            .upsert_transfer_manifest(&MetadataTransferManifest {
                token: store
                    .admit_download_job(&crate::DownloadJobRequest {
                        file_hash: file_hash.clone(),
                        display_name: format!("catalog-{sequence}.bin"),
                        expected_size_bytes: Some(sequence as u64),
                        category_id: None,
                        intent: crate::DownloadIntent::Started,
                        piece_size: 1,
                    })
                    .unwrap()
                    .job
                    .token,
                file_hash: file_hash.clone(),
                display_name: format!("catalog-{sequence}.bin"),
                expected_size_bytes: Some(sequence as u64),
                piece_size: 1,
                completed: true,
                final_rehash_pending: false,
                md4_hashset_acquired: true,
                md4_hashset: Vec::new(),
                aich_hashset_acquired: false,
                aich_root: None,
                aich_root_origin: None,
                aich_trust_generation: 0,
                aich_hashset: Vec::new(),
                verified_ranges: vec![MetadataTransferRange {
                    start: 0,
                    end: sequence as u64,
                }],
                pieces: Vec::new(),
                upload_priority: "normal".to_string(),
                auto_upload_priority: false,
                comment: String::new(),
                rating: 0,
                category_id: None,
                intent: crate::DownloadIntent::Started,
                transfer_row_removed: false,
                delivery_state: MetadataTransferDeliveryState::Pending,
                delivery_ownership: MetadataTransferDeliveryOwnership::None,
                delivered_path: None,
                source_fingerprint: None,
                payload_fingerprint: Some(fingerprint(sequence as u64, sequence as u64)),
            })
            .unwrap();
        let id = store
            .latest_download_job(&file_hash)
            .unwrap()
            .unwrap()
            .token
            .job_id;
        register_shared_test_job(&store, id);
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

#[test]
fn live_schema_has_no_import_staging_tables() {
    let store = MetadataStore::in_memory().unwrap();
    let count: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name LIKE 'imported_%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn delivered_verification_refresh_is_exact_unowned_and_preserves_terminal_history() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = completed_download_manifest(&store);
    let path = std::env::temp_dir().join("Verified.Delivery.Refresh.bin");
    let original = fingerprint(16, 91);
    manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
    manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Owned;
    manifest.delivered_path = Some(path.clone());
    manifest.source_fingerprint = Some(original.clone());
    store.upsert_transfer_manifest(&manifest).unwrap();
    register_shared_test_job(&store, manifest.token.job_id);
    assert!(store.request_transfer_retirement(manifest.token).unwrap());
    let completed = store.download_job(manifest.token.job_id).unwrap().unwrap();
    let mut timestamp_only = original.clone();
    timestamp_only.modified = fingerprint(16, 92).modified;
    assert!(
        !store
            .refresh_delivered_verification(
                manifest.token,
                &path.with_extension("other"),
                Some(&original),
                MetadataTransferDeliveryOwnership::Owned,
                &timestamp_only
            )
            .unwrap()
    );
    assert!(
        store
            .refresh_delivered_verification(
                manifest.token,
                &path,
                Some(&original),
                MetadataTransferDeliveryOwnership::Owned,
                &timestamp_only
            )
            .unwrap()
    );
    let after = store
        .download_job_manifest(manifest.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        after.delivery_ownership,
        MetadataTransferDeliveryOwnership::Unowned
    );
    assert_eq!(after.source_fingerprint, Some(timestamp_only.clone()));
    assert_eq!(after.pieces, manifest.pieces);
    assert_eq!(after.verified_ranges, manifest.verified_ranges);
    assert_eq!(
        store
            .download_job(manifest.token.job_id)
            .unwrap()
            .unwrap()
            .completed_at_s,
        completed.completed_at_s
    );
    let replacement = fingerprint(16, 93);
    assert!(
        !store
            .refresh_delivered_verification(
                manifest.token,
                &path,
                Some(&original),
                MetadataTransferDeliveryOwnership::Owned,
                &replacement
            )
            .unwrap()
    );
    assert!(
        store
            .refresh_delivered_verification(
                manifest.token,
                &path,
                Some(&timestamp_only),
                MetadataTransferDeliveryOwnership::Unowned,
                &replacement
            )
            .unwrap()
    );
    assert!(store.remove_download_job(manifest.token.job_id).unwrap());
    assert!(
        !store
            .refresh_delivered_verification(
                manifest.token,
                &path,
                Some(&replacement),
                MetadataTransferDeliveryOwnership::Unowned,
                &original
            )
            .unwrap()
    );
}

#[test]
fn delivery_maintenance_respects_stop_and_manual_storage_retry() {
    let store = MetadataStore::in_memory().unwrap();
    {
        let conn = store.connection().unwrap();
        let mut plan = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {PENDING_DELIVERY_PAGE_SQL}"))
            .unwrap();
        let steps = plan
            .query_map(params![0i64, 1i64], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            steps
                .iter()
                .any(|step| step.contains("download_jobs_pending_delivery_page_idx")),
            "delivery pages must seek the eligible subset: {steps:?}"
        );
        assert!(
            !steps.iter().any(|step| step.contains("USE TEMP B-TREE")),
            "{steps:?}"
        );
    }
    let manifest = completed_pending_download_manifest(&store);
    store.upsert_transfer_manifest(&manifest).unwrap();
    let id = manifest.token.job_id;
    assert_eq!(
        store.pending_delivery_jobs_after(None, 1).unwrap(),
        vec![id]
    );
    assert!(store.stop_download_job(manifest.token).unwrap());
    assert!(
        store
            .pending_delivery_jobs_after(None, 1)
            .unwrap()
            .is_empty()
    );
    let stopped = store.download_job(id).unwrap().unwrap();
    assert!(stopped.payload_verified);
    let started = store
        .start_download_job(stopped.token, &std::env::temp_dir())
        .unwrap()
        .unwrap();
    assert_eq!(
        store.pending_delivery_jobs_after(None, 1).unwrap(),
        vec![id]
    );
    let fault =
        crate::DownloadJobStorageFailure::new("DELIVERY_FAILED", "Sample delivery offline", 1)
            .unwrap();
    let failed = store
        .fail_download_job_storage(started.token, &fault)
        .unwrap()
        .job
        .unwrap();
    assert!(
        store
            .pending_delivery_jobs_after(None, 1)
            .unwrap()
            .is_empty()
    );
    let restarted = store
        .start_download_job(failed.token, &std::env::temp_dir())
        .unwrap()
        .unwrap();
    assert!(restarted.storage_failure.is_none());
    assert_eq!(
        store.pending_delivery_jobs_after(None, 1).unwrap(),
        vec![id]
    );
    assert!(store.remove_download_job(id).unwrap());
    assert!(
        store
            .pending_delivery_jobs_after(None, 1)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn delivered_before_retirement_survives_reopen_without_becoming_pending() {
    let database = unique_store_path("delivered-before-retirement");
    let store = MetadataStore::open(&database).unwrap();
    let mut manifest = completed_download_manifest(&store);
    manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
    manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Owned;
    manifest.delivered_path = Some(std::env::temp_dir().join("Retained.Delivery.bin"));
    manifest.source_fingerprint = Some(fingerprint(16, 98));
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(
        store
            .download_job(manifest.token.job_id)
            .unwrap()
            .unwrap()
            .completed_at_s
            .is_none()
    );
    drop(store);
    let store = MetadataStore::open(&database).unwrap();
    // Still selected for terminal admission/retirement, never materialization.
    assert_eq!(
        store.pending_delivery_jobs_after(None, 256).unwrap(),
        vec![manifest.token.job_id]
    );
    assert_eq!(
        store
            .download_job(manifest.token.job_id)
            .unwrap()
            .unwrap()
            .delivery_state,
        MetadataTransferDeliveryState::Delivered
    );
    let mut stale = manifest.clone();
    stale.delivery_state = MetadataTransferDeliveryState::Pending;
    stale.delivery_ownership = MetadataTransferDeliveryOwnership::None;
    stale.delivered_path = None;
    stale.source_fingerprint = None;
    assert!(store.upsert_transfer_manifest(&stale).is_err());
    assert!(store.connection().unwrap().execute(
        "UPDATE download_jobs SET delivery_state='pending',delivery_ownership='none',delivered_path_id=NULL WHERE id=?1",
        [manifest.token.job_id]).is_err());
    assert_eq!(
        store
            .download_job_manifest(manifest.token.job_id)
            .unwrap()
            .unwrap(),
        manifest
    );
    register_shared_test_job(&store, manifest.token.job_id);
    assert!(store.request_transfer_retirement(manifest.token).unwrap());
    assert!(
        store
            .pending_delivery_jobs_after(None, 256)
            .unwrap()
            .is_empty()
    );
    drop(store);
    remove_store_files(&database);
}

#[test]
fn retirement_uses_fixed_physical_snapshot_across_reopen_and_repeated_remove() {
    let database = unique_store_path("retirement-physical-snapshot");
    let store = MetadataStore::open(&database).unwrap();
    let manifest = completed_pending_download_manifest(&store);
    store.upsert_transfer_manifest(&manifest).unwrap();
    let running = store
        .start_download_job(manifest.token, &std::env::temp_dir())
        .unwrap()
        .unwrap();
    let storage = running.storage.unwrap();
    let identity = NativeFileIdentity::Unix {
        device_id: 71,
        inode_number: 81,
    };
    assert!(
        store
            .establish_download_job_storage(running.token, identity)
            .unwrap()
    );
    assert!(store.remove_download_job(running.token.job_id).unwrap());
    let intent = store
        .download_job_retirement(running.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(intent.source_path.as_ref(), Some(&storage.path));
    assert_eq!(
        intent.target_path.as_ref().unwrap().parent(),
        storage.path.parent()
    );
    assert_ne!(intent.target_path, intent.source_path);
    assert_eq!(intent.authority.unwrap().identity, identity);
    assert_eq!(intent.authority.unwrap().marker_id, storage.marker_id);
    assert!(
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE download_retirements SET target_path_id=NULL WHERE job_id=?1",
                [running.token.job_id]
            )
            .is_err()
    );
    drop(store);
    let store = MetadataStore::open(&database).unwrap();
    assert!(!store.remove_download_job(running.token.job_id).unwrap());
    assert_eq!(
        store.download_job_retirement(running.token.job_id).unwrap(),
        Some(intent)
    );
    drop(store);
    remove_store_files(&database);
}

#[test]
fn stale_checkpoint_cannot_restore_owned_delivery_or_old_verification() {
    for originally_owned in [false, true] {
        let store = MetadataStore::in_memory().unwrap();
        let mut manifest = completed_download_manifest(&store);
        let path = std::env::temp_dir().join("Delivery.Authority.Interleaving.bin");
        let original = fingerprint(16, 601);
        manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
        manifest.delivery_ownership = if originally_owned {
            MetadataTransferDeliveryOwnership::Owned
        } else {
            MetadataTransferDeliveryOwnership::Unowned
        };
        manifest.delivered_path = Some(path.clone());
        manifest.source_fingerprint = Some(original.clone());
        store.upsert_transfer_manifest(&manifest).unwrap();
        let mut stale = manifest.clone();
        stale.delivery_ownership = MetadataTransferDeliveryOwnership::Owned;
        let fresh = fingerprint(16, 602);
        assert!(
            store
                .refresh_delivered_verification(
                    manifest.token,
                    &path,
                    Some(&original),
                    manifest.delivery_ownership,
                    &fresh
                )
                .unwrap()
        );
        let returned = store.upsert_transfer_manifest_reconciled(&stale).unwrap();
        assert_eq!(
            returned.delivery_ownership,
            MetadataTransferDeliveryOwnership::Unowned
        );
        assert_eq!(returned.source_fingerprint, Some(fresh.clone()));
        let durable = store
            .download_job_manifest(manifest.token.job_id)
            .unwrap()
            .unwrap();
        assert_eq!(durable, returned);
        assert_eq!(
            durable.delivery_state,
            MetadataTransferDeliveryState::Delivered
        );
        assert_eq!(durable.delivered_path, Some(path));
        assert_eq!(durable.verified_ranges, manifest.verified_ranges);
        // Repeating the old clone is no stronger than its first checkpoint.
        store.upsert_transfer_manifest(&stale).unwrap();
        let durable = store
            .download_job_manifest(manifest.token.job_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            durable.delivery_ownership,
            MetadataTransferDeliveryOwnership::Unowned
        );
        assert_eq!(durable.source_fingerprint, Some(fresh));
    }
}
