//! Runtime-level end-to-end tests for finished-file delivery
//! (`materialize_completed_payload`): a completed transfer's internal piece
//! store is materialized into an operator-facing file by its canonical name,
//! idempotently and long-path aware.

use std::{fs, path::Path, sync::Arc, time::Duration};

use emulebb_kad_proto::Ed2kHash;
use md4::{Digest, Md4};
use uuid::Uuid;

#[cfg(unix)]
use super::super::deliver::set_after_publish_move_hook;
use super::super::delivery_tombstone::set_before_move_hook;
use super::super::ingest::native_file_fingerprint;
use super::super::metadata::transfer_directory_tombstone_path;
use super::super::{
    ED2K_PART_SIZE, Ed2kDeliveryOutcome, Ed2kDeliveryOwnership, Ed2kDeliveryState,
    Ed2kTransferRuntime, new_transfer_job,
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

struct DeletionTombstoneFixture {
    runtime: Ed2kTransferRuntime,
    hash: String,
    delivered: std::path::PathBuf,
    tombstone: std::path::PathBuf,
    tombstone_id: Uuid,
}

async fn prepare_deletion_tombstone(root: &Path, display_name: &str) -> DeletionTombstoneFixture {
    let runtime = Ed2kTransferRuntime::load_or_create(root).unwrap();
    let hash = ingest_completed(&runtime, root, display_name).await;
    let incoming = root.join("incoming");
    let delivered = incoming.join(display_name);
    runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    let source_fingerprint = runtime
        .manifest(&hash)
        .await
        .unwrap()
        .source_fingerprint
        .unwrap();
    assert!(runtime.metadata.request_transfer_deletion(&hash).unwrap());
    let tombstone_id = Uuid::new_v4();
    let tombstone = incoming.join(format!(".emulebb-delete-{tombstone_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_deletion_tombstone(
            &hash,
            tombstone_id,
            &delivered,
            &tombstone,
            &source_fingerprint,
        )
        .unwrap();
    DeletionTombstoneFixture {
        runtime,
        hash,
        delivered,
        tombstone,
        tombstone_id,
    }
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
    assert_eq!(manifest.delivery_ownership, Ed2kDeliveryOwnership::Owned);
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
    let staging_fingerprint = native_file_fingerprint(&staging_path).unwrap();
    assert!(
        runtime
            .metadata
            .mark_transfer_delivery_attempt_staged(&hash, attempt_id, &staging_fingerprint)
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
    assert_eq!(
        runtime.manifest(&hash).await.unwrap().delivery_ownership,
        Ed2kDeliveryOwnership::Owned
    );
}

#[tokio::test]
async fn staged_attempt_does_not_adopt_byte_identical_foreign_target() {
    let root = unique_test_dir("ed2k-deliver-recover-staged-collision");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Recovered.Collision.mkv").await;
    let payload = fs::read(runtime.payload_path(&hash)).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Recovered.Collision.mkv");
    fs::write(&target_path, &payload).unwrap();
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, &payload).unwrap();
    let staging_fingerprint = native_file_fingerprint(&staging_path).unwrap();
    runtime
        .metadata
        .mark_transfer_delivery_attempt_staged(&hash, attempt_id, &staging_fingerprint)
        .unwrap();

    let delivered = incoming.join("Recovered.Collision (1).mkv");
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
    let manifest = runtime.manifest(&hash).await.unwrap();
    assert_eq!(manifest.delivery_ownership, Ed2kDeliveryOwnership::Owned);
    assert_eq!(
        manifest.delivered_path.as_deref(),
        Some(delivered.as_path())
    );
}

#[cfg(unix)]
#[tokio::test]
async fn publication_rehash_rejects_equal_length_mutation_after_move() {
    let root = unique_test_dir("ed2k-deliver-post-move-mutation");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Mutated.After.Move.mkv").await;
    let payload = fs::read(runtime.payload_path(&hash)).unwrap();
    let replacement = vec![0xA5; payload.len()];
    let incoming = root.join("incoming");
    let target_path = incoming.join("Mutated.After.Move.mkv");
    let hook_replacement = replacement.clone();
    set_after_publish_move_hook(
        &hash,
        Box::new(move |published_path| {
            fs::write(published_path, &hook_replacement).unwrap();
        }),
    );

    let error = runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("published delivery failed verification"),
        "unexpected error: {error:#}"
    );
    assert_eq!(fs::read(&target_path).unwrap(), replacement);
    let manifest = runtime.manifest(&hash).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Pending);
    assert_eq!(manifest.delivery_ownership, Ed2kDeliveryOwnership::None);

    let delivered = incoming.join("Mutated.After.Move (1).mkv");
    assert_eq!(
        runtime
            .materialize_completed_payload(&hash, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::Delivered(delivered.clone())
    );
    assert_eq!(fs::read(&target_path).unwrap(), replacement);
    assert_eq!(fs::read(&delivered).unwrap(), payload);
}

#[tokio::test]
async fn interrupted_publication_is_adopted_without_delete_ownership() {
    let root = unique_test_dir("ed2k-deliver-recover-ambiguous-publish");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Recovered.Unowned.mkv").await;
    let payload = fs::read(runtime.payload_path(&hash)).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Recovered.Unowned.mkv");
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, &payload).unwrap();
    let staging_fingerprint = native_file_fingerprint(&staging_path).unwrap();
    runtime
        .metadata
        .mark_transfer_delivery_attempt_staged(&hash, attempt_id, &staging_fingerprint)
        .unwrap();
    fs::rename(&staging_path, &target_path).unwrap();

    assert_eq!(
        runtime
            .materialize_completed_payload(&hash, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::AlreadyDelivered(target_path.clone())
    );
    assert_eq!(fs::read(&target_path).unwrap(), payload);
    let manifest = runtime.manifest(&hash).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Delivered);
    assert_eq!(manifest.delivery_ownership, Ed2kDeliveryOwnership::Unowned);
}

#[tokio::test]
async fn published_attempt_recovers_with_delete_ownership() {
    let root = unique_test_dir("ed2k-deliver-recover-published");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Recovered.Published.mkv").await;
    let payload = fs::read(runtime.payload_path(&hash)).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Recovered.Published.mkv");
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, &payload).unwrap();
    let staging_fingerprint = native_file_fingerprint(&staging_path).unwrap();
    runtime
        .metadata
        .mark_transfer_delivery_attempt_staged(&hash, attempt_id, &staging_fingerprint)
        .unwrap();
    fs::rename(&staging_path, &target_path).unwrap();
    let published_fingerprint = native_file_fingerprint(&target_path).unwrap();
    runtime
        .metadata
        .mark_transfer_delivery_attempt_published(&hash, attempt_id, &published_fingerprint)
        .unwrap();

    assert_eq!(
        runtime
            .materialize_completed_payload(&hash, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::AlreadyDelivered(target_path.clone())
    );
    assert_eq!(fs::read(&target_path).unwrap(), payload);
    let manifest = runtime.manifest(&hash).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Delivered);
    assert_eq!(manifest.delivery_ownership, Ed2kDeliveryOwnership::Owned);
}

#[tokio::test]
async fn prepared_attempt_preserves_unproven_staging_occupant() {
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
    assert_eq!(fs::read(&staging_path).unwrap(), b"partial");
    assert_eq!(fs::read(&legacy_temp).unwrap(), b"unproven legacy artifact");
}

#[tokio::test]
async fn destructive_delete_preserves_prepared_staging_occupant() {
    let root = unique_test_dir("ed2k-delete-prepared-attempt");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Prepared Delete.mkv").await;
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Prepared Delete.mkv");
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, b"unproven occupant").unwrap();

    assert!(runtime.delete_transfer_files(&hash).await.unwrap());
    assert_eq!(fs::read(&staging_path).unwrap(), b"unproven occupant");
    assert!(!target_path.exists());
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
    assert_eq!(manifest.delivery_ownership, Ed2kDeliveryOwnership::None);
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
async fn destructive_delete_preserves_unowned_recovered_output() {
    let root = unique_test_dir("ed2k-deliver-delete-unowned-output");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Unowned.Delete.mkv").await;
    let payload = fs::read(runtime.payload_path(&hash)).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Unowned.Delete.mkv");
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, &payload).unwrap();
    let staging_fingerprint = native_file_fingerprint(&staging_path).unwrap();
    runtime
        .metadata
        .mark_transfer_delivery_attempt_staged(&hash, attempt_id, &staging_fingerprint)
        .unwrap();
    fs::rename(&staging_path, &target_path).unwrap();
    runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    assert_eq!(
        runtime.manifest(&hash).await.unwrap().delivery_ownership,
        Ed2kDeliveryOwnership::Unowned
    );

    assert!(runtime.delete_transfer_files(&hash).await.unwrap());
    assert_eq!(fs::read(&target_path).unwrap(), payload);
    assert!(!runtime.transfer_dir(&hash).exists());
}

#[tokio::test]
async fn destructive_delete_recovers_prepared_tombstone() {
    let root = unique_test_dir("ed2k-deliver-delete-prepared-tombstone");
    let fixture = prepare_deletion_tombstone(&root, "Prepared.Tombstone.mkv").await;
    assert!(fixture.delivered.exists());
    assert!(!fixture.tombstone.exists());
    drop(fixture.runtime);

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_eq!(
        restarted
            .recover_pending_transfer_deletions()
            .await
            .unwrap(),
        1
    );
    assert!(!fixture.delivered.exists());
    assert!(!fixture.tombstone.exists());
    assert!(!restarted.transfer_dir(&fixture.hash).exists());
}

#[tokio::test]
async fn destructive_delete_recovers_rename_before_moved_checkpoint() {
    let root = unique_test_dir("ed2k-deliver-delete-uncheckpointed-tombstone");
    let fixture = prepare_deletion_tombstone(&root, "Uncheckpointed.Tombstone.mkv").await;
    fs::rename(&fixture.delivered, &fixture.tombstone).unwrap();
    drop(fixture.runtime);

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_eq!(
        restarted
            .recover_pending_transfer_deletions()
            .await
            .unwrap(),
        1
    );
    assert!(!fixture.delivered.exists());
    assert!(!fixture.tombstone.exists());
    assert!(!restarted.transfer_dir(&fixture.hash).exists());
}

#[tokio::test]
async fn destructive_delete_recovers_moved_tombstone() {
    let root = unique_test_dir("ed2k-deliver-delete-moved-tombstone");
    let fixture = prepare_deletion_tombstone(&root, "Moved.Tombstone.mkv").await;
    fs::rename(&fixture.delivered, &fixture.tombstone).unwrap();
    let moved_fingerprint = native_file_fingerprint(&fixture.tombstone).unwrap();
    fixture
        .runtime
        .metadata
        .mark_transfer_deletion_tombstone_moved(
            &fixture.hash,
            fixture.tombstone_id,
            &moved_fingerprint,
        )
        .unwrap();
    drop(fixture.runtime);

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_eq!(
        restarted
            .recover_pending_transfer_deletions()
            .await
            .unwrap(),
        1
    );
    assert!(!fixture.tombstone.exists());
    assert!(!restarted.transfer_dir(&fixture.hash).exists());
}

#[tokio::test]
async fn destructive_delete_recovers_tombstone_unlink_before_finalization() {
    let root = unique_test_dir("ed2k-deliver-delete-unlinked-tombstone");
    let fixture = prepare_deletion_tombstone(&root, "Unlinked.Tombstone.mkv").await;
    fs::rename(&fixture.delivered, &fixture.tombstone).unwrap();
    let moved_fingerprint = native_file_fingerprint(&fixture.tombstone).unwrap();
    fixture
        .runtime
        .metadata
        .mark_transfer_deletion_tombstone_moved(
            &fixture.hash,
            fixture.tombstone_id,
            &moved_fingerprint,
        )
        .unwrap();
    fs::remove_file(&fixture.tombstone).unwrap();
    drop(fixture.runtime);

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_eq!(
        restarted
            .recover_pending_transfer_deletions()
            .await
            .unwrap(),
        1
    );
    assert!(!restarted.transfer_dir(&fixture.hash).exists());
}

#[tokio::test]
async fn destructive_delete_preserves_byte_identical_replacement_before_rename() {
    let root = unique_test_dir("ed2k-deliver-delete-identical-replacement");
    let fixture = prepare_deletion_tombstone(&root, "Identical.Replacement.mkv").await;
    let payload = fs::read(&fixture.delivered).unwrap();
    fs::remove_file(&fixture.delivered).unwrap();
    fs::write(&fixture.delivered, &payload).unwrap();

    assert!(
        fixture
            .runtime
            .delete_transfer_files(&fixture.hash)
            .await
            .unwrap()
    );
    assert_eq!(fs::read(&fixture.delivered).unwrap(), payload);
    assert!(!fixture.runtime.transfer_dir(&fixture.hash).exists());
    assert!(
        fixture
            .runtime
            .metadata
            .transfer_deletion_tombstone_by_hash(&fixture.hash)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn destructive_delete_restores_replacement_racing_the_atomic_rename() {
    let root = unique_test_dir("ed2k-deliver-delete-rename-race");
    let fixture = prepare_deletion_tombstone(&root, "Rename.Race.mkv").await;
    let replacement = fs::read(&fixture.delivered).unwrap();
    let hook_replacement = replacement.clone();
    set_before_move_hook(
        &fixture.hash,
        Box::new(move |original_path, _tombstone_path| {
            fs::remove_file(original_path).unwrap();
            fs::write(original_path, &hook_replacement).unwrap();
        }),
    );

    assert!(
        fixture
            .runtime
            .delete_transfer_files(&fixture.hash)
            .await
            .unwrap()
    );
    assert_eq!(fs::read(&fixture.delivered).unwrap(), replacement);
    assert!(!fixture.tombstone.exists());
    assert!(!fixture.runtime.transfer_dir(&fixture.hash).exists());
}

#[tokio::test]
async fn destructive_delete_retries_after_foreign_tombstone_collision() {
    let root = unique_test_dir("ed2k-deliver-delete-tombstone-collision");
    let fixture = prepare_deletion_tombstone(&root, "Tombstone.Collision.mkv").await;
    let foreign = b"foreign tombstone occupant";
    fs::write(&fixture.tombstone, foreign).unwrap();

    assert!(
        fixture
            .runtime
            .delete_transfer_files(&fixture.hash)
            .await
            .unwrap()
    );
    assert_eq!(fs::read(&fixture.tombstone).unwrap(), foreign);
    assert!(!fixture.delivered.exists());
    assert!(!fixture.runtime.transfer_dir(&fixture.hash).exists());
}

#[cfg(windows)]
#[tokio::test]
async fn destructive_delete_retries_windows_sharing_violation() {
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    let root = unique_test_dir("ed2k-deliver-delete-sharing-violation");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Sharing.Violation.mkv").await;
    let incoming = root.join("incoming");
    let delivered = incoming.join("Sharing.Violation.mkv");
    runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    let blocker = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(long_path(&delivered))
        .unwrap();

    assert!(runtime.delete_transfer_files(&hash).await.unwrap());
    assert!(delivered.exists());
    assert_eq!(
        runtime.metadata.pending_transfer_deletion_hashes().unwrap(),
        vec![hash.clone()]
    );
    drop(blocker);

    assert_eq!(
        runtime.recover_pending_transfer_deletions().await.unwrap(),
        1
    );
    assert!(!delivered.exists());
    assert!(!runtime.transfer_dir(&hash).exists());
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
async fn destructive_delete_preserves_ambiguous_staged_delivery_target() {
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
        let staging_fingerprint = native_file_fingerprint(&target_path).unwrap();
        let attempt_id = Uuid::new_v4();
        let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
        runtime
            .metadata
            .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
            .unwrap();
        assert!(
            runtime
                .metadata
                .mark_transfer_delivery_attempt_staged(&hash, attempt_id, &staging_fingerprint)
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
    assert!(target_path.exists());
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
async fn destructive_delete_reclaims_preexisting_published_delivery_attempt() {
    let root = unique_test_dir("ed2k-deliver-delete-published-attempt");
    let hash;
    let target_path;
    {
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        hash = ingest_completed(&runtime, &root, "Published.Delete.mkv").await;
        let incoming = root.join("incoming");
        fs::create_dir_all(&incoming).unwrap();
        target_path = incoming.join("Published.Delete.mkv");
        let attempt_id = Uuid::new_v4();
        let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
        runtime
            .metadata
            .begin_transfer_delivery_attempt(&hash, attempt_id, &target_path, &staging_path)
            .unwrap();
        fs::copy(runtime.payload_path(&hash), &staging_path).unwrap();
        let staging_fingerprint = native_file_fingerprint(&staging_path).unwrap();
        runtime
            .metadata
            .mark_transfer_delivery_attempt_staged(&hash, attempt_id, &staging_fingerprint)
            .unwrap();
        fs::rename(&staging_path, &target_path).unwrap();
        let published_fingerprint = native_file_fingerprint(&target_path).unwrap();
        runtime
            .metadata
            .mark_transfer_delivery_attempt_published(&hash, attempt_id, &published_fingerprint)
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
    let transfer_tombstone = transfer_directory_tombstone_path(&hash, &transfer_dir);
    fs::remove_dir_all(&transfer_dir).unwrap();
    fs::write(&transfer_dir, b"cleanup blocker").unwrap();

    assert!(runtime.delete_transfer_files(&hash).await.unwrap());
    assert!(!delivered.exists());
    assert!(!transfer_dir.exists());
    assert!(transfer_tombstone.is_file());
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
    assert!(error.contains("failed to delete ED2K transfer directory tombstone"));
    assert_eq!(
        restarted
            .metadata
            .pending_transfer_deletion_hashes()
            .unwrap(),
        vec![hash.clone()]
    );

    fs::remove_file(&transfer_tombstone).unwrap();
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
async fn destructive_delete_recovers_transfer_directory_tombstone() {
    let root = unique_test_dir("ed2k-deliver-delete-transfer-dir-tombstone");
    let hash;
    let transfer_dir;
    let transfer_tombstone;
    {
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        hash = ingest_completed(&runtime, &root, "Transfer.Directory.Tombstone.mkv").await;
        runtime
            .materialize_completed_payload(&hash, &root.join("incoming"))
            .await
            .unwrap();
        assert!(runtime.metadata.request_transfer_deletion(&hash).unwrap());
        transfer_dir = runtime.transfer_dir(&hash);
        transfer_tombstone = transfer_directory_tombstone_path(&hash, &transfer_dir);
        fs::rename(&transfer_dir, &transfer_tombstone).unwrap();
    }

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_eq!(
        restarted
            .recover_pending_transfer_deletions()
            .await
            .unwrap(),
        1
    );
    assert!(!transfer_dir.exists());
    assert!(!transfer_tombstone.exists());
    assert!(restarted.manifest(&hash).await.is_err());
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
    assert!(runtime.delete_transfer_files(&hash).await.unwrap());
    assert!(!long_path(&delivered).exists());
}
