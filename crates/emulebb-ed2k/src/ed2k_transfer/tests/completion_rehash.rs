use std::io::{Seek, SeekFrom, Write};

use emulebb_kad_proto::Ed2kHash;
use md4::{Digest, Md4};

use super::super::{
    ED2K_PART_SIZE, Ed2kDeliveryOutcome, Ed2kSharedEntry, Ed2kTransferRuntime, Ed2kTransferState,
    new_transfer_job,
};
use crate::paths::unique_test_dir;

fn md4(bytes: &[u8]) -> [u8; 16] {
    Md4::digest(bytes).into()
}

#[tokio::test]
async fn clean_completion_persists_pending_before_restart_finalizer_accepts() {
    let root = unique_test_dir("ed2k-final-rehash-clean-restart");
    let payload = b"completion barrier payload";
    let file_hash = Ed2kHash::from_bytes(md4(payload));
    let job = new_transfer_job(file_hash, "clean.bin".to_string(), payload.len() as u64);

    {
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        runtime.ensure_job(&job).await.unwrap();
        runtime
            .store_md4_hashset(&job.file_hash, Vec::new())
            .await
            .unwrap();
        runtime
            .store_piece_data_unfinalized(&job.file_hash, 0, payload)
            .await
            .unwrap();
        let pending = runtime.manifest(&job.file_hash).await.unwrap();
        assert!(!pending.completed);
        assert!(pending.final_rehash_pending);
        assert!(pending.payload_fingerprint.is_none());
        assert_eq!(runtime.shared_catalog_count().await, 0);
        assert_eq!(
            runtime
                .materialize_completed_payload(&job.file_hash, &root.join("incoming"))
                .await
                .unwrap(),
            Ed2kDeliveryOutcome::NotCompleted
        );
    }

    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert!(
        runtime
            .finalize_pending_transfer(&job.file_hash)
            .await
            .unwrap()
    );
    let completed = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(completed.completed);
    assert!(!completed.final_rehash_pending);
    assert!(completed.payload_fingerprint.is_some());
}

#[tokio::test]
async fn mutation_before_last_part_is_found_and_only_bad_part_is_demoted() {
    let root = unique_test_dir("ed2k-final-rehash-earlier-mutation");
    let first = vec![0x31; ED2K_PART_SIZE as usize];
    let second = vec![0x72; 257];
    let first_hash = md4(&first);
    let second_hash = md4(&second);
    let mut composite = Md4::new();
    composite.update(first_hash);
    composite.update(second_hash);
    let file_hash = Ed2kHash::from_bytes(composite.finalize().into());
    let job = new_transfer_job(
        file_hash,
        "mutated.bin".to_string(),
        first.len() as u64 + second.len() as u64,
    );
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, vec![first_hash, second_hash])
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 0, &first)
        .await
        .unwrap();

    let mut payload = std::fs::OpenOptions::new()
        .write(true)
        .open(runtime.payload_path(&job.file_hash))
        .unwrap();
    payload.seek(SeekFrom::Start(0)).unwrap();
    payload.write_all(&[0xff]).unwrap();
    payload.sync_all().unwrap();

    runtime
        .store_piece_data_unfinalized(&job.file_hash, 1, &second)
        .await
        .unwrap();
    assert!(
        !runtime
            .finalize_pending_transfer(&job.file_hash)
            .await
            .unwrap()
    );
    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(!manifest.completed);
    assert!(!manifest.final_rehash_pending);
    assert!(manifest.payload_fingerprint.is_none());
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Missing);
    assert!(manifest.pieces[0].ich_corrupted);
    assert_eq!(manifest.pieces[1].state, Ed2kTransferState::Verified);
}

#[tokio::test]
async fn automatic_store_does_not_return_a_deliverable_file_before_final_rehash() {
    let root = unique_test_dir("ed2k-final-rehash-auto");
    let payload = b"automatic final rehash";
    let file_hash = Ed2kHash::from_bytes(md4(payload));
    let job = new_transfer_job(file_hash, "automatic.bin".to_string(), payload.len() as u64);
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, Vec::new())
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 0, payload)
        .await
        .unwrap();
    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(manifest.completed);
    assert!(!manifest.final_rehash_pending);
}

#[tokio::test]
async fn stale_incomplete_hydration_cannot_republish_a_pending_completion() {
    let root = unique_test_dir("ed2k-final-rehash-stale-incomplete-hydration");
    let first = vec![0x42; ED2K_PART_SIZE as usize];
    let second = vec![0x91; 257];
    let first_hash = md4(&first);
    let second_hash = md4(&second);
    let mut composite = Md4::new();
    composite.update(first_hash);
    composite.update(second_hash);
    let file_hash = Ed2kHash::from_bytes(composite.finalize().into());
    let job = new_transfer_job(
        file_hash,
        "stale-hydration.bin".to_string(),
        first.len() as u64 + second.len() as u64,
    );
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, vec![first_hash, second_hash])
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 0, &first)
        .await
        .unwrap();
    let stale_manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(!stale_manifest.verified_ranges.is_empty());
    assert_eq!(runtime.shared_catalog_count().await, 1);

    runtime
        .store_piece_data_unfinalized(&job.file_hash, 1, &second)
        .await
        .unwrap();
    let pending = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(pending.final_rehash_pending);
    assert_eq!(runtime.shared_catalog_count().await, 0);

    assert!(
        !runtime
            .insert_hydrated_incomplete_entry_if_current(&stale_manifest)
            .await
            .unwrap()
    );
    assert_eq!(runtime.shared_catalog_count().await, 0);
}

#[tokio::test]
async fn incomplete_hydration_requires_md4_authority() {
    let root = unique_test_dir("ed2k-incomplete-hydration-md4-authority");
    let payload = vec![0x4d; ED2K_PART_SIZE as usize];
    let tail = vec![0x8a; 257];
    let first_hash = md4(&payload);
    let tail_hash = md4(&tail);
    let mut composite = Md4::new();
    composite.update(first_hash);
    composite.update(tail_hash);
    let file_hash = Ed2kHash::from_bytes(composite.finalize().into());
    let job = new_transfer_job(
        file_hash,
        "missing-md4-authority.bin".to_string(),
        payload.len() as u64 + tail.len() as u64,
    );
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, vec![first_hash, tail_hash])
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 0, &payload)
        .await
        .unwrap();
    let mut manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert_eq!(runtime.shared_catalog_count().await, 1);
    manifest.md4_hashset_acquired = false;
    manifest.md4_hashset.clear();
    {
        let _guard = runtime.lock_manifest(&job.file_hash).await;
        runtime.store_manifest_unlocked(&manifest).await.unwrap();
        runtime.remove_verified_catalog_entry(&job.file_hash).await;
    }

    assert!(
        !runtime
            .insert_hydrated_incomplete_entry_if_current(&manifest)
            .await
            .unwrap()
    );
    assert_eq!(runtime.shared_catalog_count().await, 0);
}

#[tokio::test]
async fn oversized_payload_is_quarantined_before_retry() {
    let root = unique_test_dir("ed2k-final-rehash-oversized");
    let payload = b"authoritative expected payload";
    let file_hash = Ed2kHash::from_bytes(md4(payload));
    let job = new_transfer_job(file_hash, "oversized.bin".to_string(), payload.len() as u64);
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, Vec::new())
        .await
        .unwrap();
    runtime
        .store_piece_data_unfinalized(&job.file_hash, 0, payload)
        .await
        .unwrap();
    assert_eq!(runtime.shared_catalog_count().await, 0);

    let payload_path = runtime.payload_path(&job.file_hash);
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&payload_path)
        .unwrap();
    file.write_all(b"stale-tail").unwrap();
    file.sync_all().unwrap();

    assert!(
        !runtime
            .finalize_pending_transfer(&job.file_hash)
            .await
            .unwrap()
    );
    assert_eq!(std::fs::metadata(&payload_path).unwrap().len(), 0);
    let quarantined = std::fs::read_dir(payload_path.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with(".pieces.bin.invalid-") && name.ends_with(".quarantine")
                })
        })
        .unwrap();
    assert_eq!(
        std::fs::read(quarantined).unwrap(),
        [payload.as_slice(), b"stale-tail"].concat()
    );
    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(!manifest.completed);
    assert!(manifest.payload_fingerprint.is_none());
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Missing);
    assert!(!manifest.pieces[0].ich_corrupted);
    runtime
        .store_piece_data(&job.file_hash, 0, payload)
        .await
        .unwrap();
    assert!(runtime.manifest(&job.file_hash).await.unwrap().completed);
}

#[cfg(unix)]
#[tokio::test]
async fn final_rehash_rejects_symlink_payload_without_touching_target() {
    use std::os::unix::fs::symlink;

    let root = unique_test_dir("ed2k-final-rehash-symlink");
    let payload = b"authoritative expected payload";
    let file_hash = Ed2kHash::from_bytes(md4(payload));
    let job = new_transfer_job(file_hash, "symlink.bin".to_string(), payload.len() as u64);
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, Vec::new())
        .await
        .unwrap();
    runtime
        .store_piece_data_unfinalized(&job.file_hash, 0, payload)
        .await
        .unwrap();

    let payload_path = runtime.payload_path(&job.file_hash);
    let foreign_path = root.join("foreign.bin");
    std::fs::write(&foreign_path, payload).unwrap();
    std::fs::remove_file(&payload_path).unwrap();
    symlink(&foreign_path, &payload_path).unwrap();

    runtime
        .finalize_pending_transfer(&job.file_hash)
        .await
        .unwrap_err();
    assert_eq!(std::fs::read(&foreign_path).unwrap(), payload);
    assert!(
        payload_path
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(manifest.final_rehash_pending);
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Verified);
    assert_eq!(runtime.shared_catalog_count().await, 0);
}

#[tokio::test]
async fn forced_rehash_with_authority_failure_withdraws_catalog_without_touching_occupant() {
    let root = unique_test_dir("ed2k-final-rehash-wrong-type");
    let payload = b"authoritative expected payload";
    let file_hash = Ed2kHash::from_bytes(md4(payload));
    let job = new_transfer_job(
        file_hash,
        "wrong-type.bin".to_string(),
        payload.len() as u64,
    );
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, Vec::new())
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 0, payload)
        .await
        .unwrap();
    let completed = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(completed.completed);
    let stale_catalog_entry = Ed2kSharedEntry::from_manifest(&completed);
    assert_eq!(runtime.shared_catalog_count().await, 1);
    let catalog = runtime.shared_catalog();
    assert!(
        catalog
            .write()
            .await
            .update_by_hash(&file_hash, |entry| entry.all_time_uploaded_bytes = 17)
    );
    assert!(
        !runtime
            .insert_hydrated_completed_entry_if_current(stale_catalog_entry.clone())
            .await
            .unwrap()
    );
    assert_eq!(
        catalog
            .read()
            .await
            .entry_by_hash(&file_hash)
            .unwrap()
            .all_time_uploaded_bytes,
        17
    );

    let payload_path = runtime.payload_path(&job.file_hash);
    std::fs::remove_file(&payload_path).unwrap();
    std::fs::create_dir(&payload_path).unwrap();

    runtime.recheck_transfer(&job.file_hash).await.unwrap_err();
    assert!(payload_path.is_dir());
    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(manifest.final_rehash_pending);
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Verified);
    assert_eq!(runtime.shared_catalog_count().await, 0);
    assert!(
        !runtime
            .insert_hydrated_completed_entry_if_current(stale_catalog_entry)
            .await
            .unwrap()
    );
    assert_eq!(runtime.shared_catalog_count().await, 0);
}

#[tokio::test]
async fn replaced_completed_payload_is_withdrawn_before_upload() {
    let root = unique_test_dir("ed2k-completed-payload-replaced");
    let trusted_payload = vec![0x63; 4096];
    let foreign_payload = vec![0xa4; trusted_payload.len()];
    let file_hash = Ed2kHash::from_bytes(md4(&trusted_payload));
    let job = new_transfer_job(
        file_hash,
        "replaced.bin".to_string(),
        trusted_payload.len() as u64,
    );
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, Vec::new())
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 0, &trusted_payload)
        .await
        .unwrap();
    let completed = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(completed.completed);
    assert!(completed.payload_fingerprint.is_some());
    assert_eq!(runtime.shared_catalog_count().await, 1);

    runtime.invalidate_payload_handle(&job.file_hash);
    let payload_path = runtime.payload_path(&job.file_hash);
    let original_path = payload_path.with_extension("trusted");
    std::fs::rename(&payload_path, &original_path).unwrap();
    std::fs::write(&payload_path, &foreign_payload).unwrap();

    assert!(
        runtime
            .read_verified_range(&file_hash, 0, trusted_payload.len() as u64)
            .await
            .unwrap()
            .is_none(),
        "foreign replacement bytes must never be served under the completed hash"
    );
    let withdrawn = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(!withdrawn.completed);
    assert!(withdrawn.final_rehash_pending);
    assert!(withdrawn.payload_fingerprint.is_none());
    assert_eq!(withdrawn.pieces[0].state, Ed2kTransferState::Verified);
    assert_eq!(runtime.shared_catalog_count().await, 0);
    assert_eq!(std::fs::read(&payload_path).unwrap(), foreign_payload);
    assert_eq!(std::fs::read(&original_path).unwrap(), trusted_payload);
}

#[tokio::test]
async fn missing_pending_payload_resets_idempotently_and_redownloads() {
    let root = unique_test_dir("ed2k-final-rehash-missing");
    let payload = b"authoritative expected payload";
    let file_hash = Ed2kHash::from_bytes(md4(payload));
    let job = new_transfer_job(file_hash, "missing.bin".to_string(), payload.len() as u64);
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, Vec::new())
        .await
        .unwrap();
    runtime
        .store_piece_data_unfinalized(&job.file_hash, 0, payload)
        .await
        .unwrap();

    let payload_path = runtime.payload_path(&job.file_hash);
    std::fs::remove_file(&payload_path).unwrap();

    assert!(
        !runtime
            .finalize_pending_transfer(&job.file_hash)
            .await
            .unwrap()
    );
    assert_eq!(std::fs::metadata(&payload_path).unwrap().len(), 0);
    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(!manifest.final_rehash_pending);
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Missing);
    assert!(!manifest.pieces[0].ich_corrupted);

    runtime
        .store_piece_data(&job.file_hash, 0, payload)
        .await
        .unwrap();
    assert!(runtime.manifest(&job.file_hash).await.unwrap().completed);
}
