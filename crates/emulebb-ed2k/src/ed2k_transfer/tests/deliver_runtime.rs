//! Runtime-level end-to-end tests for finished-file delivery
//! (`materialize_completed_payload`): a completed transfer's internal piece
//! store is materialized into an operator-facing file by its canonical name,
//! idempotently and long-path aware.

use std::{fs, path::Path, sync::Arc, time::Duration};

use emulebb_kad_proto::Ed2kHash;
use md4::{Digest, Md4};
use uuid::Uuid;

use super::super::{
    ED2K_PART_SIZE, Ed2kDeliveryOutcome, Ed2kDeliveryState, Ed2kTransferRuntime, new_transfer_job,
};
use crate::long_path::long_path;
use crate::paths::unique_test_dir;

/// Build a fully verified, completed DOWNLOAD transfer with a real internal
/// piece store (the bytes live in `transfer_dir/pieces.bin`, `source_path` is
/// `None`) so the delivery tests have a finished downloaded file to materialize.
/// Delivery is download-only, so the fixture must be a download, not a
/// share-in-place ingest.
async fn ingest_completed(
    runtime: &Ed2kTransferRuntime,
    _root: &Path,
    display_name: &str,
) -> String {
    // A single-part payload (< one ED2K part) so one verified piece completes it.
    let mut payload = Vec::with_capacity(1_048_576);
    while payload.len() < 1_048_576 {
        payload.extend_from_slice(b"emulebb-delivery-payload");
    }
    payload.truncate(1_048_576);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let job = new_transfer_job(file_hash, display_name.to_string(), payload.len() as u64);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&file_hash_hex, Vec::new())
        .await
        .unwrap();
    runtime
        .store_piece_data(&file_hash_hex, 0, &payload)
        .await
        .unwrap();
    file_hash_hex
}

#[tokio::test]
async fn materialize_completed_payload_delivers_by_name() {
    let root = unique_test_dir("ed2k-deliver-by-name");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Sample.Title.mkv").await;
    let incoming = root.join("incoming");

    let outcome = runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();

    let delivered = incoming.join("Sample.Title.mkv");
    assert_eq!(outcome, Ed2kDeliveryOutcome::Delivered(delivered.clone()));
    // The delivered file is byte-identical to the internal piece store.
    let expected = fs::read(runtime.payload_path(&hash)).unwrap();
    assert_eq!(fs::read(&delivered).unwrap(), expected);
    // The internal piece store is kept as the verified upload authority.
    assert!(runtime.payload_path(&hash).exists());
    // The delivered path is recorded on the manifest.
    let manifest = runtime.manifest(&hash).await.unwrap();
    assert_eq!(
        manifest.delivered_path.as_deref(),
        Some(delivered.as_path())
    );
    assert!(
        runtime
            .metadata
            .transfer_delivery_attempt_by_hash(&hash)
            .unwrap()
            .is_none(),
        "the committed manifest must not retain an active delivery attempt"
    );

    // A second call is an idempotent no-op (already delivered, file present).
    let again = runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    assert_eq!(again, Ed2kDeliveryOutcome::AlreadyDelivered(delivered));
}

#[tokio::test]
async fn materialize_completed_payload_isolated_from_piece_store() {
    let root = unique_test_dir("ed2k-deliver-isolated-copy");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Editable.mkv").await;
    let payload_path = runtime.payload_path(&hash);
    let verified_payload = fs::read(&payload_path).unwrap();
    let incoming = root.join("incoming");

    let outcome = runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    let Ed2kDeliveryOutcome::Delivered(delivered) = outcome else {
        panic!("expected a fresh delivery");
    };

    fs::write(&delivered, b"operator-owned edited bytes").unwrap();

    assert_eq!(
        fs::read(payload_path).unwrap(),
        verified_payload,
        "editing the delivered file must not mutate verified upload bytes"
    );
}

#[tokio::test]
async fn staged_attempt_is_installed_and_committed_after_interruption() {
    let root = unique_test_dir("ed2k-deliver-recover-staged");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Recovered.Staged.mkv").await;
    let payload = fs::read(runtime.payload_path(&hash)).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Recovered.Staged.mkv");
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, &payload).unwrap();
    assert!(
        runtime
            .metadata
            .mark_transfer_delivery_attempt_staged(&hash, attempt_id)
            .unwrap()
    );

    assert_eq!(
        runtime
            .materialize_completed_payload(&hash, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::AlreadyDelivered(target_path.clone())
    );
    assert_eq!(fs::read(&target_path).unwrap(), payload);
    assert!(!staging_path.exists());
    assert!(
        runtime
            .metadata
            .transfer_delivery_attempt_by_hash(&hash)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn prepared_attempt_reclaims_only_its_exact_staging_path() {
    let root = unique_test_dir("ed2k-deliver-recover-prepared");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Prepared.mkv").await;
    let payload = fs::read(runtime.payload_path(&hash)).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Prepared.mkv");
    fs::write(&target_path, &payload).unwrap();
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, b"partial").unwrap();
    let legacy_temp = incoming.join(".Prepared.mkv.ed2k-delivering-legacy");
    fs::write(&legacy_temp, b"unproven legacy artifact").unwrap();

    let delivered = incoming.join("Prepared (1).mkv");
    assert_eq!(
        runtime
            .materialize_completed_payload(&hash, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::Delivered(delivered.clone())
    );
    assert_eq!(fs::read(&target_path).unwrap(), payload);
    assert_eq!(fs::read(&delivered).unwrap(), payload);
    assert!(!staging_path.exists());
    assert_eq!(fs::read(&legacy_temp).unwrap(), b"unproven legacy artifact");
}

#[tokio::test]
async fn materialize_completed_payload_rejects_missing_nonempty_piece_store() {
    let root = unique_test_dir("ed2k-deliver-missing-source");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Missing.mkv").await;
    fs::remove_file(runtime.payload_path(&hash)).unwrap();
    let incoming = root.join("incoming");

    let error = runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap_err();

    assert!(
        format!("{error:#}").contains("missing delivery payload"),
        "unexpected error: {error:#}"
    );
    assert!(!incoming.exists());
    assert!(
        runtime
            .manifest(&hash)
            .await
            .unwrap()
            .delivered_path
            .is_none()
    );
}

#[tokio::test]
async fn materialize_completed_payload_persists_across_reload() {
    let root = unique_test_dir("ed2k-deliver-reload");
    let incoming = root.join("incoming");
    let hash = {
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let hash = ingest_completed(&runtime, &root, "Clip.mkv").await;
        runtime
            .materialize_completed_payload(&hash, &incoming)
            .await
            .unwrap();
        hash
    };

    // Reopen the runtime over the same root/metadata: the recorded delivered
    // path survives, so a restart re-delivery is a no-op (no duplicate file).
    let reloaded = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let outcome = reloaded
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        Ed2kDeliveryOutcome::AlreadyDelivered(incoming.join("Clip.mkv"))
    );
    // Exactly one delivered file exists for the name.
    let entries: Vec<_> = fs::read_dir(&incoming)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, vec!["Clip.mkv".to_string()]);
}

#[tokio::test]
async fn materialize_reconciles_replaced_output_without_overwriting_it() {
    let root = unique_test_dir("ed2k-deliver-reconcile-replaced");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Replaced.mkv").await;
    let incoming = root.join("incoming");
    let verified_payload = fs::read(runtime.payload_path(&hash)).unwrap();
    let delivered = incoming.join("Replaced.mkv");
    runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();

    fs::remove_file(&delivered).unwrap();
    let unrelated_replacement = vec![0xA5; verified_payload.len()];
    fs::write(&delivered, &unrelated_replacement).unwrap();

    let reconciled = runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    let redelivered = incoming.join("Replaced (1).mkv");
    assert_eq!(
        reconciled,
        Ed2kDeliveryOutcome::Delivered(redelivered.clone())
    );
    assert_eq!(fs::read(&delivered).unwrap(), unrelated_replacement);
    assert_eq!(fs::read(&redelivered).unwrap(), verified_payload);
    let manifest = runtime.manifest(&hash).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Delivered);
    assert_eq!(
        manifest.delivered_path.as_deref(),
        Some(redelivered.as_path())
    );
}

#[tokio::test]
async fn materialize_recreates_deleted_recorded_output() {
    let root = unique_test_dir("ed2k-deliver-reconcile-missing");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Missing.Output.mkv").await;
    let incoming = root.join("incoming");
    let verified_payload = fs::read(runtime.payload_path(&hash)).unwrap();
    let delivered = incoming.join("Missing.Output.mkv");
    runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    fs::remove_file(&delivered).unwrap();

    assert_eq!(
        runtime
            .materialize_completed_payload(&hash, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::Delivered(delivered.clone())
    );
    assert_eq!(fs::read(&delivered).unwrap(), verified_payload);
    let manifest = runtime.manifest(&hash).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Delivered);
    assert_eq!(
        manifest.delivered_path.as_deref(),
        Some(delivered.as_path())
    );
}

#[tokio::test]
async fn failed_redelivery_leaves_mismatched_output_pending() {
    let root = unique_test_dir("ed2k-deliver-reconcile-pending");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Pending.Output.mkv").await;
    let incoming = root.join("incoming");
    let delivered = incoming.join("Pending.Output.mkv");
    runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();

    fs::remove_file(&delivered).unwrap();
    let unrelated_replacement = vec![0xC3; 1_048_576];
    fs::write(&delivered, &unrelated_replacement).unwrap();
    fs::remove_file(runtime.payload_path(&hash)).unwrap();

    runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap_err();
    assert_eq!(fs::read(&delivered).unwrap(), unrelated_replacement);
    let manifest = runtime.manifest(&hash).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Pending);
    assert!(manifest.delivered_path.is_none());
    assert!(manifest.source_fingerprint.is_none());
}

#[tokio::test]
async fn materialize_preserves_byte_identical_replacement_without_adopting_it() {
    let root = unique_test_dir("ed2k-deliver-reconcile-identical");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Identical.mkv").await;
    let incoming = root.join("incoming");
    let verified_payload = fs::read(runtime.payload_path(&hash)).unwrap();
    let delivered = incoming.join("Identical.mkv");
    runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    let recorded_fingerprint = runtime.manifest(&hash).await.unwrap().source_fingerprint;

    fs::remove_file(&delivered).unwrap();
    fs::write(&delivered, &verified_payload).unwrap();

    let redelivered = incoming.join("Identical (1).mkv");
    assert_eq!(
        runtime
            .materialize_completed_payload(&hash, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::Delivered(redelivered.clone())
    );
    assert_eq!(fs::read(&delivered).unwrap(), verified_payload);
    assert_eq!(fs::read(&redelivered).unwrap(), verified_payload);
    let refreshed = runtime.manifest(&hash).await.unwrap();
    assert_eq!(refreshed.delivery_state, Ed2kDeliveryState::Delivered);
    assert_eq!(
        refreshed.delivered_path.as_deref(),
        Some(redelivered.as_path())
    );
    assert_ne!(refreshed.source_fingerprint, recorded_fingerprint);
}

#[tokio::test]
async fn pending_completed_download_cannot_hide_its_transfer_row() {
    let root = unique_test_dir("ed2k-deliver-pending-row-removal");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let hash = ingest_completed(&runtime, &root, "Pending.Row.mkv").await;
    let lifecycle_guard = runtime.lock_lifecycle(&hash).await;
    let removal_runtime = Arc::clone(&runtime);
    let removal_hash = hash.clone();
    let mut removal = tokio::spawn(async move {
        removal_runtime
            .remove_completed_transfer_row(&removal_hash)
            .await
    });

    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut removal)
            .await
            .is_err(),
        "row removal must wait for the transfer lifecycle gate"
    );
    drop(lifecycle_guard);
    let error = removal.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("must be delivered"));
    assert!(!runtime.manifest(&hash).await.unwrap().transfer_row_removed);

    runtime
        .materialize_completed_payload(&hash, &root.join("incoming"))
        .await
        .unwrap();
    assert!(
        runtime
            .remove_completed_transfer_row(&hash)
            .await
            .unwrap()
            .is_some()
    );
    assert!(runtime.manifest(&hash).await.unwrap().transfer_row_removed);
}

#[tokio::test]
async fn destructive_delete_uses_lifecycle_gate_and_removes_both_authorities() {
    let root = unique_test_dir("ed2k-deliver-serialized-delete");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let hash = ingest_completed(&runtime, &root, "Serialized.Delete.mkv").await;
    let incoming = root.join("incoming");
    let delivered = incoming.join("Serialized.Delete.mkv");
    runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    let transfer_dir = runtime.transfer_dir(&hash);

    let lifecycle_guard = runtime.lock_lifecycle(&hash).await;
    let delete_runtime = Arc::clone(&runtime);
    let delete_hash = hash.clone();
    let mut deletion =
        tokio::spawn(async move { delete_runtime.delete_transfer_files(&delete_hash).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut deletion)
            .await
            .is_err(),
        "destructive deletion must wait for the transfer lifecycle gate"
    );
    assert!(delivered.exists());
    assert!(transfer_dir.exists());

    drop(lifecycle_guard);
    assert!(deletion.await.unwrap().unwrap());
    assert!(!delivered.exists());
    assert!(!transfer_dir.exists());
    assert!(runtime.manifest(&hash).await.is_err());
}

#[tokio::test]
async fn destructive_delete_preserves_foreign_delivered_path_occupant() {
    let root = unique_test_dir("ed2k-deliver-delete-foreign-output");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Foreign.Delete.mkv").await;
    let incoming = root.join("incoming");
    let delivered = incoming.join("Foreign.Delete.mkv");
    runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    let foreign = vec![0x5a; 1_048_576];
    fs::write(&delivered, &foreign).unwrap();

    assert!(runtime.delete_transfer_files(&hash).await.unwrap());

    assert_eq!(fs::read(&delivered).unwrap(), foreign);
    assert!(!runtime.transfer_dir(&hash).exists());
    assert!(runtime.manifest(&hash).await.is_err());
}

#[tokio::test]
async fn destructive_delete_resumes_a_preexisting_durable_intent() {
    let root = unique_test_dir("ed2k-deliver-delete-resume-intent");
    let hash;
    let delivered;
    {
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        hash = ingest_completed(&runtime, &root, "Resume.Delete.mkv").await;
        let incoming = root.join("incoming");
        delivered = incoming.join("Resume.Delete.mkv");
        runtime
            .materialize_completed_payload(&hash, &incoming)
            .await
            .unwrap();
        assert!(runtime.metadata.request_transfer_deletion(&hash).unwrap());
    }

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_eq!(
        restarted
            .recover_pending_transfer_deletions()
            .await
            .unwrap(),
        1
    );
    assert!(!delivered.exists());
    assert!(!restarted.transfer_dir(&hash).exists());
    assert!(
        restarted
            .metadata
            .pending_transfer_deletion_hashes()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn destructive_delete_resolves_preexisting_staged_delivery_attempt() {
    let root = unique_test_dir("ed2k-deliver-delete-staged-attempt");
    let hash;
    let target_path;
    {
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        hash = ingest_completed(&runtime, &root, "Staged.Delete.mkv").await;
        let incoming = root.join("incoming");
        fs::create_dir_all(&incoming).unwrap();
        target_path = incoming.join("Staged.Delete.mkv");
        fs::copy(runtime.payload_path(&hash), &target_path).unwrap();
        let attempt_id = Uuid::new_v4();
        let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
        runtime
            .metadata
            .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
            .unwrap();
        assert!(
            runtime
                .metadata
                .mark_transfer_delivery_attempt_staged(&hash, attempt_id)
                .unwrap()
        );
        assert!(runtime.metadata.request_transfer_deletion(&hash).unwrap());
    }

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_eq!(
        restarted
            .recover_pending_transfer_deletions()
            .await
            .unwrap(),
        1
    );
    assert!(!target_path.exists());
    assert!(!restarted.transfer_dir(&hash).exists());
    assert!(
        restarted
            .metadata
            .transfer_delivery_attempt_by_hash(&hash)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn destructive_delete_keeps_intent_when_cleanup_must_retry() {
    let root = unique_test_dir("ed2k-deliver-delete-cleanup-retry");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Retry.Delete.mkv").await;
    let incoming = root.join("incoming");
    let delivered = incoming.join("Retry.Delete.mkv");
    runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    let transfer_dir = runtime.transfer_dir(&hash);
    fs::remove_dir_all(&transfer_dir).unwrap();
    fs::write(&transfer_dir, b"cleanup blocker").unwrap();

    assert!(runtime.delete_transfer_files(&hash).await.unwrap());
    assert!(!delivered.exists());
    assert!(transfer_dir.is_file());
    assert!(runtime.manifest(&hash).await.is_err());
    assert_eq!(
        runtime.metadata.pending_transfer_deletion_hashes().unwrap(),
        vec![hash.clone()]
    );

    drop(runtime);
    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let error = restarted
        .recover_pending_transfer_deletions()
        .await
        .unwrap_err();
    let error = format!("{error:#}");
    assert!(error.contains(&hash));
    assert!(error.contains("failed to delete ED2K transfer directory"));
    assert_eq!(
        restarted
            .metadata
            .pending_transfer_deletion_hashes()
            .unwrap(),
        vec![hash.clone()]
    );

    fs::remove_file(&transfer_dir).unwrap();
    assert_eq!(
        restarted
            .recover_pending_transfer_deletions()
            .await
            .unwrap(),
        1
    );
    assert!(
        restarted
            .metadata
            .pending_transfer_deletion_hashes()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn pending_deletion_recovery_is_a_noop_without_intents() {
    let root = unique_test_dir("ed2k-deliver-delete-recovery-empty");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    assert_eq!(
        runtime.recover_pending_transfer_deletions().await.unwrap(),
        0
    );
}

#[tokio::test]
async fn concurrent_materialization_of_one_transfer_is_idempotent() {
    let root = unique_test_dir("ed2k-deliver-concurrent");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Concurrent.mkv").await;
    let incoming = root.join("incoming");

    let (first, second) = tokio::join!(
        runtime.materialize_completed_payload(&hash, &incoming),
        runtime.materialize_completed_payload(&hash, &incoming)
    );
    let outcomes = [first.unwrap(), second.unwrap()];
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, Ed2kDeliveryOutcome::Delivered(_)))
    );
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, Ed2kDeliveryOutcome::AlreadyDelivered(_)))
    );
    assert_eq!(fs::read_dir(&incoming).unwrap().count(), 1);
}

#[tokio::test]
async fn materialize_records_delivered_fingerprint_for_reload_reuse() {
    let root = unique_test_dir("ed2k-deliver-fingerprint");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Reusable.mkv").await;
    let incoming = root.join("incoming");

    let outcome = runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    let Ed2kDeliveryOutcome::Delivered(delivered) = outcome else {
        panic!("expected a fresh delivery");
    };

    // The delivered download records its native fingerprint with source_path still
    // None, so the shared-directory reload's delivered-reuse index picks it up
    // and an unchanged delivered file is a cache hit rather than a re-hash.
    let manifest = runtime.manifest(&hash).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Delivered);
    assert!(
        manifest.source_path.is_none(),
        "a delivered download must stay source_path == None"
    );
    let recorded = manifest
        .source_fingerprint
        .expect("the delivered file fingerprint must be recorded");
    let (_, _, scanned_fingerprint) =
        Ed2kTransferRuntime::scanned_source_identity(&delivered).unwrap();
    assert_eq!(
        Some(recorded),
        scanned_fingerprint,
        "recorded delivered fingerprint must match the on-disk file the reload sees"
    );
}

#[tokio::test]
async fn materialize_skips_incomplete_transfer() {
    let root = unique_test_dir("ed2k-deliver-incomplete");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    // A fresh job with no downloaded parts is not complete.
    let job = new_transfer_job(
        Ed2kHash::from_bytes([0x33; 16]),
        "unfinished.bin".to_string(),
        ED2K_PART_SIZE + 1,
    );
    runtime.ensure_job(&job).await.unwrap();
    let incoming = root.join("incoming");

    let outcome = runtime
        .materialize_completed_payload(&job.file_hash, &incoming)
        .await
        .unwrap();

    assert_eq!(outcome, Ed2kDeliveryOutcome::NotCompleted);
    assert!(!incoming.exists());
}

#[tokio::test]
async fn materialize_completed_payload_under_long_incoming_path() {
    let root = unique_test_dir("ed2k-deliver-long-path");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "LongPath.mkv").await;
    // Build an incoming directory whose absolute path exceeds the legacy
    // MAX_PATH (260) limit; delivery must still succeed via the `\\?\` long-path
    // boundary in the delivery module.
    let mut incoming = root.join("incoming");
    for index in 0..12 {
        incoming = incoming.join(format!("deep-delivery-segment-component-{index:02}"));
    }
    assert!(
        incoming.to_string_lossy().chars().count() > 260,
        "test setup must exceed MAX_PATH"
    );

    let outcome = runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();

    let delivered = incoming.join("LongPath.mkv");
    assert_eq!(outcome, Ed2kDeliveryOutcome::Delivered(delivered.clone()));
    let expected = fs::read(runtime.payload_path(&hash)).unwrap();
    assert_eq!(fs::read(long_path(&delivered)).unwrap(), expected);
}
