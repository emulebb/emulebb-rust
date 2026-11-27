//! Runtime-level end-to-end tests for finished-file delivery
//! (`materialize_completed_payload`): a completed transfer's internal piece
//! store is materialized into an operator-facing file by its canonical name,
//! idempotently and long-path aware.

use std::{fs, path::Path, sync::Arc, time::Duration};

use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::MetadataTransferDirectoryDeletionAuthority;
use md4::{Digest, Md4};
use uuid::Uuid;

use super::super::deliver::pause_after_direct_create;
#[cfg(unix)]
use super::super::deliver::set_after_publish_move_hook;
use super::super::deliver::set_before_fingerprint_remove_hook;
use super::super::delivery_tombstone::set_before_move_hook;
use super::super::fs_durability::force_unsupported_move;
use super::super::ingest::native_file_fingerprint;
use super::super::metadata::transfer_directory_authority_marker_path;
use super::super::test_support::admit_download_job;
use super::super::{
    ED2K_PART_SIZE, Ed2kDeliveryOutcome, Ed2kDeliveryOwnership, Ed2kDeliveryState,
    Ed2kTransferDeletionRecoveryReport, Ed2kTransferJob, Ed2kTransferRuntime,
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
) -> Ed2kTransferJob {
    // A single-part payload (< one ED2K part) so one verified piece completes it.
    let mut payload = Vec::with_capacity(1_048_576);
    while payload.len() < 1_048_576 {
        payload.extend_from_slice(b"emulebb-delivery-payload");
    }
    payload.truncate(1_048_576);
    ingest_completed_bytes(runtime, display_name, &payload).await
}

async fn ingest_completed_bytes(
    runtime: &Ed2kTransferRuntime,
    display_name: &str,
    payload: &[u8],
) -> Ed2kTransferJob {
    let file_hash = Ed2kHash::from_bytes(Md4::digest(payload).into());
    let job = admit_download_job(
        runtime,
        file_hash,
        display_name.to_string(),
        payload.len() as u64,
    );
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(job.token, Vec::new())
        .await
        .unwrap();
    runtime
        .store_piece_data(job.token, 0, payload)
        .await
        .unwrap();
    job
}

struct DeletionTombstoneFixture {
    runtime: Ed2kTransferRuntime,
    hash: Ed2kTransferJob,
    transfer_dir: std::path::PathBuf,
    delivered: std::path::PathBuf,
    tombstone: std::path::PathBuf,
    tombstone_id: Uuid,
}

#[tokio::test]
async fn explicit_completed_verify_hashes_only_recorded_output_after_piece_retirement() {
    use super::super::CompletedOutputVerification;
    let root = unique_test_dir("ed2k-explicit-completed-verify");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = ingest_completed(&runtime, &root, "Verify.bin").await;
    let transfer_dir = runtime.transfer_dir_path(job.token.job_id).unwrap();
    runtime
        .materialize_completed_payload(job.token, &root.join("incoming"))
        .await
        .unwrap();
    let (output, _) = runtime
        .register_delivered_local_content(job.token)
        .await
        .unwrap();
    assert!(runtime.complete_download_job(job.token).await.unwrap());
    assert!(
        runtime
            .retire_download_storage(job.token.job_id)
            .await
            .unwrap()
    );
    let before = runtime
        .metadata
        .download_job(job.token.job_id)
        .unwrap()
        .unwrap();
    let detail = runtime
        .metadata
        .download_job_detail(job.token.job_id)
        .unwrap()
        .unwrap();
    let unrelated = root.join("other-copy.bin");
    fs::copy(&output, &unrelated).unwrap();
    let original = fs::read(&output).unwrap();
    let modified = fs::metadata(&output).unwrap().modified().unwrap();
    assert_eq!(
        runtime.verify_completed_output(job.token).await.unwrap(),
        Some(CompletedOutputVerification::Verified)
    );
    fs::write(&output, vec![b'x'; original.len()]).unwrap();
    fs::File::options()
        .write(true)
        .open(&output)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert_eq!(
        runtime.verify_completed_output(job.token).await.unwrap(),
        Some(CompletedOutputVerification::Damaged)
    );
    fs::remove_file(&output).unwrap();
    assert_eq!(
        runtime.verify_completed_output(job.token).await.unwrap(),
        Some(CompletedOutputVerification::Missing)
    );
    assert_eq!(fs::read(&unrelated).unwrap(), original);
    assert!(!output.exists());
    assert!(!transfer_dir.exists());
    assert!(
        !runtime
            .manifest_cache
            .lock()
            .await
            .contains_key(&job.token.job_id)
    );
    assert_eq!(
        runtime
            .metadata
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap(),
        before
    );
    let after = runtime
        .metadata
        .download_job_detail(job.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(after.delivered_path, detail.delivered_path);
    assert_eq!(after.ownership, detail.ownership);
    // A read-only verification result also survives an ordinary daemon reload
    // without treating a missing output as permission to download it again.
    drop(runtime);
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_eq!(
        runtime.verify_completed_output(job.token).await.unwrap(),
        Some(CompletedOutputVerification::Missing)
    );
    assert_eq!(
        runtime
            .metadata
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap(),
        before
    );
}

#[tokio::test]
async fn completed_verify_refuses_unfinished_and_stale_jobs_without_hydration() {
    let root = unique_test_dir("ed2k-completed-verify-authority");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = runtime
        .metadata
        .admit_download_job(&emulebb_metadata::DownloadJobRequest {
            file_hash: "91".repeat(16),
            display_name: "Queued.bin".into(),
            expected_size_bytes: Some(16),
            category_id: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            piece_size: ED2K_PART_SIZE,
        })
        .unwrap()
        .job;
    assert!(runtime.verify_completed_output(job.token).await.is_err());
    let stale = emulebb_metadata::JobToken {
        generation: job.token.generation + 1,
        ..job.token
    };
    assert!(runtime.verify_completed_output(stale).await.is_err());
    assert!(runtime.manifest_cache.lock().await.is_empty());
    assert!(
        runtime
            .metadata
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .storage
            .is_none()
    );
}

fn persist_deletion_intent(
    runtime: &Ed2kTransferRuntime,
    job: &Ed2kTransferJob,
) -> MetadataTransferDirectoryDeletionAuthority {
    let storage = runtime
        .metadata
        .download_job(job.token.job_id)
        .unwrap()
        .unwrap()
        .storage
        .unwrap();
    let identity = storage
        .identity
        .expect("fixture must own its selected directory");
    let marker_id = storage.marker_id;
    let authority = MetadataTransferDirectoryDeletionAuthority {
        identity,
        marker_id,
    };
    assert!(
        runtime
            .metadata
            .request_transfer_deletion(job.token.job_id)
            .unwrap()
    );
    authority
}

async fn prepare_deletion_tombstone(root: &Path, display_name: &str) -> DeletionTombstoneFixture {
    let runtime = Ed2kTransferRuntime::load_or_create(root).unwrap();
    let hash = ingest_completed(&runtime, root, display_name).await;
    let incoming = root.join("incoming");
    let delivered = incoming.join(display_name);
    runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();
    let source_fingerprint = runtime
        .manifest(hash.token)
        .await
        .unwrap()
        .source_fingerprint
        .clone()
        .unwrap();
    let transfer_dir = runtime.transfer_dir(hash.token.job_id).unwrap();
    persist_deletion_intent(&runtime, &hash);
    let tombstone_id = Uuid::new_v4();
    let tombstone = incoming.join(format!(".emulebb-delete-{tombstone_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_deletion_tombstone(
            hash.token.job_id,
            tombstone_id,
            &delivered,
            &tombstone,
            &source_fingerprint,
        )
        .unwrap();
    DeletionTombstoneFixture {
        runtime,
        hash,
        transfer_dir,
        delivered,
        tombstone,
        tombstone_id,
    }
}

fn assert_complete_deletion_recovery(
    report: Ed2kTransferDeletionRecoveryReport,
    expected_recovered: usize,
) {
    assert!(
        report.failures.is_empty(),
        "unexpected deletion recovery failures: {:?}",
        report.failures
    );
    assert_eq!(report.recovered, expected_recovered);
}

#[tokio::test]
async fn unsupported_atomic_move_uses_verified_exclusive_copy() {
    let root = unique_test_dir("ed2k-direct-delivery");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Sample.bin").await;
    let payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let incoming = root.join("incoming");
    let target = incoming.join("Sample.bin");
    force_unsupported_move(&target);
    assert_eq!(
        runtime
            .materialize_completed_payload(hash.token, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::Delivered(target.clone())
    );
    assert_eq!(fs::read(&target).unwrap(), payload);
    assert!(runtime.payload_path(hash.token.job_id).unwrap().exists());
    assert!(
        !runtime
            .metadata
            .delivery_output_is_excluded(&target)
            .unwrap()
    );
}

#[tokio::test]
async fn recovery_after_directory_sync_failure_keeps_the_original_name() {
    let root = unique_test_dir("ed2k-publish-parent-sync-failure");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = ingest_completed(&runtime, &root, "Sample.bin").await;
    let payload = runtime.payload_path(job.token.job_id).unwrap();
    let incoming = root.join("incoming");
    let target = incoming.join("Sample.bin");
    super::super::fs_durability::force_parent_sync_failure(&target);

    let error = runtime
        .materialize_completed_payload(job.token, &incoming)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("forced parent sync failure after rename"));
    assert_eq!(fs::read(&target).unwrap(), fs::read(&payload).unwrap());

    assert_eq!(
        runtime
            .materialize_completed_payload(job.token, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::AlreadyDelivered(target.clone()),
    );
    assert_eq!(fs::read(&target).unwrap(), fs::read(&payload).unwrap());
    assert!(!incoming.join("Sample_01.bin").exists());
}

#[tokio::test]
async fn recovery_releases_an_unused_direct_copy_reservation() {
    let root = unique_test_dir("ed2k-direct-before-create");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = ingest_completed(&runtime, &root, "Sample.bin").await;
    let payload = fs::read(runtime.payload_path(job.token.job_id).unwrap()).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target = incoming.join("Sample.bin");
    let attempt = Uuid::new_v4();
    let staging = incoming.join(format!(".emulebb-delivery-{attempt}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(job.token, attempt, &target, &staging)
        .unwrap();
    fs::write(&staging, &payload).unwrap();
    runtime
        .metadata
        .mark_transfer_delivery_attempt_staged(
            job.token,
            attempt,
            &native_file_fingerprint(&staging).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(
        runtime
            .metadata
            .reserve_delivery_output(job.token, &target, attempt)
            .unwrap()
    );
    assert_eq!(
        runtime
            .materialize_completed_payload(job.token, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::AlreadyDelivered(target.clone()),
    );
    assert_eq!(fs::read(&target).unwrap(), payload);
    assert!(
        !runtime
            .metadata
            .delivery_output_is_excluded(&target)
            .unwrap()
    );
    assert!(!incoming.join("Sample_01.bin").exists());
}

#[tokio::test]
async fn direct_delivery_retries_after_reclaiming_its_disk_full_partial() {
    let root = unique_test_dir("ed2k-direct-storage-full");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = ingest_completed(&runtime, &root, "Sample.bin").await;
    let source = runtime.payload_path(job.token.job_id).unwrap();
    let payload = fs::read(&source).unwrap();
    let incoming = root.join("incoming");
    let target = incoming.join("Sample.bin");
    force_unsupported_move(&target);
    super::super::deliver::force_delivery_storage_full(&target);

    let error = runtime
        .materialize_completed_payload(job.token, &incoming)
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::StorageFull
    );
    assert!(!target.exists());
    assert_eq!(fs::read(&source).unwrap(), payload);
    let journal = runtime
        .metadata
        .download_job_delivery_attempt(job.token.job_id)
        .unwrap()
        .unwrap();
    assert!(
        !runtime
            .metadata
            .has_delivery_reservation(job.token.job_id, journal.attempt_id)
            .unwrap()
    );

    force_unsupported_move(&target);
    assert_eq!(
        runtime
            .materialize_completed_payload(job.token, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::AlreadyDelivered(target.clone()),
    );
    assert_eq!(fs::read(&target).unwrap(), payload);
    assert!(!incoming.join("Sample_01.bin").exists());
}

#[tokio::test]
async fn interrupted_direct_copy_preserves_and_excludes_partial() {
    let root = unique_test_dir("ed2k-direct-interrupted");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Sample.bin").await;
    let payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target = incoming.join("Sample.bin");
    let attempt = Uuid::new_v4();
    let staging = incoming.join(format!(".emulebb-delivery-{attempt}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(hash.token, attempt, &target, &staging)
        .unwrap();
    fs::write(&staging, &payload).unwrap();
    let fingerprint = native_file_fingerprint(&staging).unwrap();
    runtime
        .metadata
        .mark_transfer_delivery_attempt_staged(hash.token, attempt, &fingerprint)
        .unwrap()
        .expect("delivery journal transition must match captured job");
    assert!(
        runtime
            .metadata
            .reserve_delivery_output(hash.token, &target, attempt)
            .unwrap()
    );
    fs::write(&target, b"partial").unwrap();
    let second = incoming.join("Sample_01.bin");
    let error = runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("reservation remains pending"));
    assert_eq!(fs::read(&target).unwrap(), b"partial");
    assert_eq!(fs::read(&staging).unwrap(), payload);
    assert!(!second.exists());
    assert!(
        runtime
            .metadata
            .download_job_delivery_attempt(hash.token.job_id)
            .unwrap()
            .is_some()
    );
    assert!(
        runtime
            .metadata
            .delivery_output_is_excluded(&target)
            .unwrap()
    );
    assert!(
        !runtime
            .metadata
            .delete_transfer_manifest(hash.token.job_id)
            .unwrap()
    );
    assert!(
        runtime
            .metadata
            .delivery_output_is_excluded(&target)
            .unwrap()
    );
    assert_eq!(fs::read(&target).unwrap(), b"partial");

    // Removing a job while the destination is unavailable must keep the
    // sharing barrier. Restoring the directory must not expose its partial.
    runtime
        .remove_download_job(hash.token.job_id, false)
        .await
        .unwrap();
    let moved_incoming = root.join("moved-incoming");
    fs::rename(&incoming, &moved_incoming).unwrap();
    let (_, cleanup) = runtime
        .recover_removed_download_jobs_page(None, 4)
        .await
        .unwrap();
    assert_eq!(cleanup.recovered, 0);
    assert_eq!(cleanup.failures.len(), 1);
    assert!(
        runtime
            .metadata
            .has_delivery_reservation(hash.token.job_id, attempt)
            .unwrap()
    );
    fs::rename(&moved_incoming, &incoming).unwrap();
    assert!(
        runtime
            .metadata
            .delivery_output_is_excluded(&target)
            .unwrap()
    );
    assert_eq!(fs::read(&target).unwrap(), b"partial");
}

#[tokio::test]
async fn cancelled_direct_copy_keeps_partial_excluded_and_retry_pending() {
    let root = unique_test_dir("ed2k-direct-cancel");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let hash = ingest_completed(&runtime, &root, "Sample.bin").await;
    let payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let incoming = root.join("incoming");
    let target = incoming.join("Sample.bin");
    force_unsupported_move(&target);
    let (created, release) = pause_after_direct_create(&target);
    let task_runtime = Arc::clone(&runtime);
    let task_hash = hash.clone();
    let task_incoming = incoming.clone();
    let task = tokio::spawn(async move {
        task_runtime
            .materialize_completed_payload(task_hash.token, &task_incoming)
            .await
    });
    tokio::time::timeout(Duration::from_secs(10), created)
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(
        runtime
            .metadata
            .delivery_output_is_excluded(&target)
            .unwrap()
    );
    assert_eq!(fs::read(&target).unwrap(), b"");
    {
        let mut wait_for_owner = std::pin::pin!(runtime.lock_lifecycle(hash.token.job_id));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(wait_for_owner.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
    }
    release.send(()).unwrap();
    let retry = incoming.join("Sample_01.bin");
    let error = runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("reservation remains pending"));
    assert!(!retry.exists());
    assert_eq!(
        fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap(),
        payload
    );
    let attempt = runtime
        .metadata
        .download_job_delivery_attempt(hash.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(fs::read(attempt.staging_path).unwrap(), payload);
    assert!(
        runtime
            .metadata
            .delivery_output_is_excluded(&target)
            .unwrap()
    );
}

#[tokio::test]
async fn materialize_completed_payload_delivers_by_name() {
    let root = unique_test_dir("ed2k-deliver-by-name");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Sample.Title.mkv").await;
    let incoming = root.join("incoming");

    let outcome = runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();

    let delivered = incoming.join("Sample.Title.mkv");
    assert_eq!(outcome, Ed2kDeliveryOutcome::Delivered(delivered.clone()));
    // The delivered file is byte-identical to the internal piece store.
    let expected = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    assert_eq!(fs::read(&delivered).unwrap(), expected);
    // The internal piece store is kept as the verified upload authority.
    assert!(runtime.payload_path(hash.token.job_id).unwrap().exists());
    // The delivered path is recorded on the manifest.
    let manifest = runtime.manifest(hash.token).await.unwrap();
    assert_eq!(manifest.delivery_ownership, Ed2kDeliveryOwnership::Owned);
    assert_eq!(
        manifest.delivered_path.as_deref(),
        Some(delivered.as_path())
    );
    assert!(
        runtime
            .metadata
            .download_job_delivery_attempt(hash.token.job_id)
            .unwrap()
            .is_none(),
        "the committed manifest must not retain an active delivery attempt"
    );

    // A second call is an idempotent no-op (already delivered, file present).
    let again = runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();
    assert_eq!(again, Ed2kDeliveryOutcome::AlreadyDelivered(delivered));
}

#[tokio::test]
async fn materialize_completed_payload_uses_explicitly_repaired_chosen_name() {
    let root = unique_test_dir("ed2k-deliver-repaired-name");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Caf%C3%A9 &amp; FranÃ§ais.mkv").await;
    let chosen = runtime
        .manifest(hash.token)
        .await
        .unwrap()
        .display_name
        .clone();
    assert!(
        chosen.contains("&amp;"),
        "admission must preserve the chosen name"
    );
    assert!(
        runtime
            .rename_download_job(hash.token, &chosen)
            .await
            .unwrap()
    );
    let incoming = root.join("incoming");
    let delivered = incoming.join("Café & Français.mkv");

    let outcome = runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();

    assert_eq!(outcome, Ed2kDeliveryOutcome::Delivered(delivered.clone()));
    assert!(delivered.is_file());
    assert_eq!(
        runtime.manifest(hash.token).await.unwrap().display_name,
        "Café & Français.mkv"
    );
}

#[tokio::test]
async fn materialize_completed_payload_isolated_from_piece_store() {
    let root = unique_test_dir("ed2k-deliver-isolated-copy");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Editable.mkv").await;
    let payload_path = runtime.payload_path(hash.token.job_id).unwrap();
    let verified_payload = fs::read(&payload_path).unwrap();
    let incoming = root.join("incoming");

    let outcome = runtime
        .materialize_completed_payload(hash.token, &incoming)
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
    let payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Recovered.Staged.mkv");
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(hash.token, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, &payload).unwrap();
    let staging_fingerprint = native_file_fingerprint(&staging_path).unwrap();
    assert!(
        runtime
            .metadata
            .mark_transfer_delivery_attempt_staged(hash.token, attempt_id, &staging_fingerprint)
            .unwrap()
            .is_some()
    );

    assert_eq!(
        runtime
            .materialize_completed_payload(hash.token, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::AlreadyDelivered(target_path.clone())
    );
    assert_eq!(fs::read(&target_path).unwrap(), payload);
    assert!(!staging_path.exists());
    assert!(
        runtime
            .metadata
            .download_job_delivery_attempt(hash.token.job_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        runtime
            .manifest(hash.token)
            .await
            .unwrap()
            .delivery_ownership,
        Ed2kDeliveryOwnership::Owned
    );
}

#[tokio::test]
async fn staged_attempt_does_not_adopt_byte_identical_foreign_target() {
    let root = unique_test_dir("ed2k-deliver-recover-staged-collision");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Recovered.Collision.mkv").await;
    let payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Recovered.Collision.mkv");
    fs::write(&target_path, &payload).unwrap();
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(hash.token, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, &payload).unwrap();
    let staging_fingerprint = native_file_fingerprint(&staging_path).unwrap();
    runtime
        .metadata
        .mark_transfer_delivery_attempt_staged(hash.token, attempt_id, &staging_fingerprint)
        .unwrap()
        .expect("delivery journal transition must match captured job");

    let delivered = incoming.join("Recovered.Collision_01.mkv");
    assert_eq!(
        runtime
            .materialize_completed_payload(hash.token, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::Delivered(delivered.clone())
    );
    assert_eq!(fs::read(&target_path).unwrap(), payload);
    assert_eq!(fs::read(&delivered).unwrap(), payload);
    assert!(!staging_path.exists());
    let manifest = runtime.manifest(hash.token).await.unwrap();
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
    let payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let replacement = vec![0xA5; payload.len()];
    let incoming = root.join("incoming");
    let target_path = incoming.join("Mutated.After.Move.mkv");
    let hook_replacement = replacement.clone();
    set_after_publish_move_hook(
        &target_path,
        Box::new(move |published_path| {
            fs::write(published_path, &hook_replacement).unwrap();
        }),
    );

    let error = runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("published delivery failed verification"),
        "unexpected error: {error:#}"
    );
    assert_eq!(fs::read(&target_path).unwrap(), replacement);
    let manifest = runtime.manifest(hash.token).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Pending);
    assert_eq!(manifest.delivery_ownership, Ed2kDeliveryOwnership::None);

    let delivered = incoming.join("Mutated.After.Move_01.mkv");
    assert_eq!(
        runtime
            .materialize_completed_payload(hash.token, &incoming)
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
    let payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Recovered.Unowned.mkv");
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(hash.token, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, &payload).unwrap();
    let staging_fingerprint = native_file_fingerprint(&staging_path).unwrap();
    runtime
        .metadata
        .mark_transfer_delivery_attempt_staged(hash.token, attempt_id, &staging_fingerprint)
        .unwrap()
        .expect("delivery journal transition must match captured job");
    fs::rename(&staging_path, &target_path).unwrap();

    assert_eq!(
        runtime
            .materialize_completed_payload(hash.token, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::AlreadyDelivered(target_path.clone())
    );
    assert_eq!(fs::read(&target_path).unwrap(), payload);
    let manifest = runtime.manifest(hash.token).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Delivered);
    assert_eq!(manifest.delivery_ownership, Ed2kDeliveryOwnership::Unowned);
}

#[tokio::test]
async fn published_attempt_recovers_with_delete_ownership() {
    let root = unique_test_dir("ed2k-deliver-recover-published");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Recovered.Published.mkv").await;
    let payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Recovered.Published.mkv");
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(hash.token, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, &payload).unwrap();
    let staging_fingerprint = native_file_fingerprint(&staging_path).unwrap();
    runtime
        .metadata
        .mark_transfer_delivery_attempt_staged(hash.token, attempt_id, &staging_fingerprint)
        .unwrap()
        .expect("delivery journal transition must match captured job");
    fs::rename(&staging_path, &target_path).unwrap();
    let published_fingerprint = native_file_fingerprint(&target_path).unwrap();
    runtime
        .metadata
        .mark_transfer_delivery_attempt_published(hash.token, attempt_id, &published_fingerprint)
        .unwrap()
        .expect("delivery journal transition must match captured job");

    assert_eq!(
        runtime
            .materialize_completed_payload(hash.token, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::AlreadyDelivered(target_path.clone())
    );
    assert_eq!(fs::read(&target_path).unwrap(), payload);
    let manifest = runtime.manifest(hash.token).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Delivered);
    assert_eq!(manifest.delivery_ownership, Ed2kDeliveryOwnership::Owned);
}

#[tokio::test]
async fn prepared_attempt_preserves_unproven_staging_occupant() {
    let root = unique_test_dir("ed2k-deliver-recover-prepared");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Prepared.mkv").await;
    let payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Prepared.mkv");
    fs::write(&target_path, &payload).unwrap();
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(hash.token, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, b"partial").unwrap();
    let legacy_temp = incoming.join(".Prepared.mkv.ed2k-delivering-legacy");
    fs::write(&legacy_temp, b"unproven legacy artifact").unwrap();

    let delivered = incoming.join("Prepared_01.mkv");
    assert_eq!(
        runtime
            .materialize_completed_payload(hash.token, &incoming)
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
        .begin_transfer_delivery_attempt(hash.token, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, b"unproven occupant").unwrap();

    assert!(
        runtime
            .remove_download_job(hash.token.job_id, true)
            .await
            .unwrap()
    );
    assert!(
        runtime
            .cleanup_removed_download_job(hash.token.job_id)
            .await
            .unwrap()
    );
    assert_eq!(fs::read(&staging_path).unwrap(), b"unproven occupant");
    assert!(!target_path.exists());
}

#[tokio::test]
async fn destructive_delete_hides_transfer_when_attempt_cleanup_retries() {
    let root = unique_test_dir("ed2k-delete-staged-cleanup-retry");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Staged Cleanup Retry.mkv").await;
    let selected_storage = runtime
        .metadata
        .download_job(hash.token.job_id)
        .unwrap()
        .unwrap()
        .storage
        .unwrap()
        .path;
    let parsed_hash = hash.file_hash.parse().unwrap();
    let payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Staged Cleanup Retry.mkv");
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(hash.token, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, &payload).unwrap();
    let staging_fingerprint = native_file_fingerprint(&staging_path).unwrap();
    runtime
        .metadata
        .mark_transfer_delivery_attempt_staged(hash.token, attempt_id, &staging_fingerprint)
        .unwrap()
        .expect("delivery journal transition must match captured job");
    assert!(
        runtime
            .local_servable_entry(&parsed_hash)
            .await
            .unwrap()
            .is_some()
    );
    set_before_fingerprint_remove_hook(
        &staging_path,
        Box::new(|_| Err(std::io::Error::other("injected staging cleanup failure"))),
    );

    assert!(
        runtime
            .remove_download_job(hash.token.job_id, true)
            .await
            .unwrap()
    );
    assert!(
        runtime
            .cleanup_removed_download_job(hash.token.job_id)
            .await
            .is_err()
    );
    assert!(runtime.manifest(hash.token).await.is_err());
    assert!(
        runtime
            .local_servable_entry(&parsed_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        runtime
            .metadata
            .pending_transfer_deletion_jobs_after(None, 100)
            .unwrap(),
        vec![hash.token.job_id]
    );
    assert!(staging_path.exists());
    assert!(!selected_storage.exists());

    assert_complete_deletion_recovery(
        runtime
            .recover_removed_download_jobs_page(None, 100)
            .await
            .unwrap()
            .1,
        1,
    );
    assert!(!staging_path.exists());
    assert!(!selected_storage.exists());
}

#[tokio::test]
async fn materialize_completed_payload_rejects_missing_nonempty_piece_store() {
    let root = unique_test_dir("ed2k-deliver-missing-source");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Missing.mkv").await;
    fs::remove_file(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let incoming = root.join("incoming");

    let error = runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap_err();

    assert!(
        format!("{error:#}").contains("missing delivery payload"),
        "unexpected error: {error:#}"
    );
    assert!(!incoming.exists());
    assert!(
        runtime
            .manifest(hash.token)
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
            .materialize_completed_payload(hash.token, &incoming)
            .await
            .unwrap();
        hash
    };

    // Reopen the runtime over the same root/metadata: the recorded delivered
    // path survives, so a restart re-delivery is a no-op (no duplicate file).
    let reloaded = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let outcome = reloaded
        .materialize_completed_payload(hash.token, &incoming)
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
    let verified_payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let delivered = incoming.join("Replaced.mkv");
    runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();

    fs::remove_file(&delivered).unwrap();
    let unrelated_replacement = vec![0xA5; verified_payload.len()];
    fs::write(&delivered, &unrelated_replacement).unwrap();

    assert_eq!(
        runtime
            .materialize_completed_payload(hash.token, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::AlreadyDelivered(delivered.clone())
    );
    assert_eq!(fs::read(&delivered).unwrap(), unrelated_replacement);
    assert!(!incoming.join("Replaced_01.mkv").exists());
    let manifest = runtime.manifest(hash.token).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Delivered);
    assert_eq!(
        manifest.delivered_path.as_deref(),
        Some(delivered.as_path())
    );
}

#[tokio::test]
async fn materialize_does_not_recreate_deleted_recorded_output() {
    let root = unique_test_dir("ed2k-deliver-reconcile-missing");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Missing.Output.mkv").await;
    let incoming = root.join("incoming");
    let verified_payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let delivered = incoming.join("Missing.Output.mkv");
    runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();
    fs::remove_file(&delivered).unwrap();

    assert_eq!(
        runtime
            .materialize_completed_payload(hash.token, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::AlreadyDelivered(delivered.clone())
    );
    assert!(!delivered.exists());
    assert!(!incoming.join("Missing.Output_01.mkv").exists());
    assert_eq!(
        fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap(),
        verified_payload
    );
    let manifest = runtime.manifest(hash.token).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Delivered);
    assert_eq!(
        manifest.delivered_path.as_deref(),
        Some(delivered.as_path())
    );
}

#[tokio::test]
async fn completed_delivery_stays_recorded_after_output_and_payload_loss() {
    let root = unique_test_dir("ed2k-deliver-reconcile-pending");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Pending.Output.mkv").await;
    let incoming = root.join("incoming");
    let delivered = incoming.join("Pending.Output.mkv");
    runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();

    fs::remove_file(&delivered).unwrap();
    let unrelated_replacement = vec![0xC3; 1_048_576];
    fs::write(&delivered, &unrelated_replacement).unwrap();
    fs::remove_file(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();

    assert_eq!(
        runtime
            .materialize_completed_payload(hash.token, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::AlreadyDelivered(delivered.clone())
    );
    assert_eq!(fs::read(&delivered).unwrap(), unrelated_replacement);
    assert!(!incoming.join("Pending.Output_01.mkv").exists());
    let manifest = runtime.manifest(hash.token).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Delivered);
    assert_eq!(
        manifest.delivered_path.as_deref(),
        Some(delivered.as_path())
    );
}

#[tokio::test]
async fn materialize_verifies_identical_replacement_without_ownership() {
    let root = unique_test_dir("ed2k-deliver-reconcile-identical");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Identical.mkv").await;
    let incoming = root.join("incoming");
    let verified_payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let delivered = incoming.join("Identical.mkv");
    runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();
    let recorded_fingerprint = runtime
        .manifest(hash.token)
        .await
        .unwrap()
        .source_fingerprint
        .clone();

    fs::remove_file(&delivered).unwrap();
    fs::write(&delivered, &verified_payload).unwrap();

    assert_eq!(
        runtime
            .materialize_completed_payload(hash.token, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::AlreadyDelivered(delivered.clone())
    );
    assert_eq!(fs::read(&delivered).unwrap(), verified_payload);
    assert!(!incoming.join("Identical_01.mkv").exists());
    let refreshed = runtime.manifest(hash.token).await.unwrap();
    assert_eq!(refreshed.delivery_state, Ed2kDeliveryState::Delivered);
    assert_eq!(refreshed.delivery_ownership, Ed2kDeliveryOwnership::Unowned);
    assert_eq!(
        refreshed.delivered_path.as_deref(),
        Some(delivered.as_path())
    );
    assert_ne!(refreshed.source_fingerprint, recorded_fingerprint);
}

#[tokio::test]
async fn pending_completed_download_cannot_retire_before_local_content_registration() {
    let root = unique_test_dir("ed2k-deliver-pending-row-removal");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = ingest_completed(&runtime, &root, "Pending.Row.mkv").await;
    assert!(!runtime.complete_download_job(job.token).await.unwrap());
    assert!(
        runtime
            .metadata
            .download_job_retirement(job.token.job_id)
            .unwrap()
            .is_none()
    );
    assert!(
        runtime
            .metadata
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .completed_at_s
            .is_none()
    );
    runtime
        .materialize_completed_payload(job.token, &root.join("incoming"))
        .await
        .unwrap();
    let (delivered, _) = runtime
        .register_delivered_local_content(job.token)
        .await
        .unwrap();
    let transfer_dir = runtime.transfer_dir_path(job.token.job_id).unwrap();
    assert!(runtime.complete_download_job(job.token).await.unwrap());
    let intent = runtime
        .metadata
        .download_job_retirement(job.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(intent.source_path.as_deref(), Some(transfer_dir.as_path()));
    assert!(
        runtime
            .retire_download_storage(job.token.job_id)
            .await
            .unwrap()
    );
    assert!(!transfer_dir.exists());
    assert!(delivered.exists());
    let retained = runtime
        .metadata
        .download_job(job.token.job_id)
        .unwrap()
        .unwrap();
    assert!(retained.completed_at_s.is_some());
    assert!(retained.internal_storage_retired);
    assert!(retained.removed_at_s.is_none());
}

#[tokio::test]
async fn retired_download_recovery_reclaims_only_owned_piece_storage() {
    let root = unique_test_dir("ed2k-retired-download-recovery");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = ingest_completed(&runtime, &root, "Retired.bin").await;
    let delivered = root.join("incoming").join("Retired.bin");
    runtime
        .materialize_completed_payload(job.token, &root.join("incoming"))
        .await
        .unwrap();
    runtime
        .register_delivered_local_content(job.token)
        .await
        .unwrap();
    let transfer_dir = runtime.transfer_dir_path(job.token.job_id).unwrap();
    assert!(runtime.complete_download_job(job.token).await.unwrap());
    let snapshot = runtime
        .metadata
        .download_job_retirement(job.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot.source_path.as_deref(),
        Some(transfer_dir.as_path())
    );
    assert!(snapshot.target_path.is_some());
    assert!(snapshot.authority.is_some());
    drop(runtime);
    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_eq!(
        restarted
            .metadata
            .download_job_retirement(job.token.job_id)
            .unwrap(),
        Some(snapshot)
    );
    let (_, report) = restarted
        .recover_download_retirements_page(None, 100)
        .await
        .unwrap();
    assert_eq!(report.recovered, 1);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert!(!transfer_dir.exists());
    assert!(delivered.exists());
    let retained = restarted
        .metadata
        .download_job(job.token.job_id)
        .unwrap()
        .unwrap();
    assert!(retained.completed_at_s.is_some() && retained.internal_storage_retired);
    assert_eq!(retained.file_hash, job.file_hash);
}

#[tokio::test]
async fn saturated_delivery_defers_retirement_and_the_next_sweep_recovers_it_once() {
    let root = unique_test_dir("ed2k-retirement-delivery-pressure");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = ingest_completed(&runtime, &root, "Retired.bin").await;
    let incoming = root.join("incoming");
    let delivered = incoming.join("Retired.bin");
    runtime
        .materialize_completed_payload(job.token, &incoming)
        .await
        .unwrap();
    runtime
        .register_delivered_local_content(job.token)
        .await
        .unwrap();
    let transfer_dir = runtime.transfer_dir_path(job.token.job_id).unwrap();
    assert!(runtime.complete_download_job(job.token).await.unwrap());
    let before = fs::read(&delivered).unwrap();
    let journal = runtime
        .metadata
        .download_job_retirement(job.token.job_id)
        .unwrap()
        .unwrap();

    // Each retained delivery reserves a physical slot and 512 KiB. The
    // journal read can still run, but three deliveries leave no cleanup slot.
    let mut held = Vec::new();
    for offset in 1..=3 {
        let other_id = emulebb_metadata::JobId::new(job.token.job_id.get() + offset).unwrap();
        let guard = runtime.lock_lifecycle(other_id).await;
        let (release, wait) = std::sync::mpsc::channel();
        let receipt = runtime
            .local_mutations
            .submit_delivery_io(guard, move || {
                wait.recv()?;
                Ok(())
            })
            .unwrap();
        held.push((release, receipt));
    }
    let (cursor, deferred) = runtime
        .recover_download_retirements_page(None, 4)
        .await
        .unwrap();
    assert_eq!(cursor, Some(job.token.job_id));
    assert_eq!(deferred.deferred_due_to_capacity, 1);
    assert_eq!(deferred.recovered, 0);
    assert!(deferred.failures.is_empty(), "{:?}", deferred.failures);
    assert_eq!(
        runtime
            .metadata
            .download_job_retirement(job.token.job_id)
            .unwrap(),
        Some(journal)
    );
    assert!(transfer_dir.exists());
    assert_eq!(fs::read(&delivered).unwrap(), before);

    for (release, receipt) in held {
        release.send(()).unwrap();
        receipt.await.unwrap().unwrap();
    }
    let (cursor, wrapped) = runtime
        .recover_download_retirements_page(cursor, 4)
        .await
        .unwrap();
    assert_eq!(cursor, None);
    assert_eq!(wrapped.recovered, 0);
    let (_, recovered) = runtime
        .recover_download_retirements_page(cursor, 4)
        .await
        .unwrap();
    assert_eq!(recovered.recovered, 1);
    assert_eq!(recovered.deferred_due_to_capacity, 0);
    assert!(recovered.failures.is_empty(), "{:?}", recovered.failures);
    let (_, settled) = runtime
        .recover_download_retirements_page(None, 4)
        .await
        .unwrap();
    assert_eq!(settled.recovered, 0);
    assert!(!transfer_dir.exists());
    assert_eq!(fs::read(&delivered).unwrap(), before);
    let completed = runtime
        .metadata
        .download_job(job.token.job_id)
        .unwrap()
        .unwrap();
    assert!(completed.completed_at_s.is_some() && completed.internal_storage_retired);
}

#[tokio::test]
async fn retired_download_recovery_preserves_replaced_piece_directory() {
    let root = unique_test_dir("ed2k-retired-download-collision");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = ingest_completed(&runtime, &root, "Retired.Collision.bin").await;
    let delivered = root.join("incoming").join("Retired.Collision.bin");
    runtime
        .materialize_completed_payload(job.token, &root.join("incoming"))
        .await
        .unwrap();
    runtime
        .register_delivered_local_content(job.token)
        .await
        .unwrap();
    let transfer_dir = runtime.transfer_dir_path(job.token.job_id).unwrap();
    assert!(runtime.complete_download_job(job.token).await.unwrap());
    let snapshot = runtime
        .metadata
        .download_job_retirement(job.token.job_id)
        .unwrap()
        .unwrap();
    let owned_dir = root.join("owned-piece-directory");
    fs::rename(&transfer_dir, &owned_dir).unwrap();
    fs::create_dir(&transfer_dir).unwrap();
    fs::write(transfer_dir.join("foreign.bin"), b"foreign bytes").unwrap();
    let (_, report) = runtime
        .recover_download_retirements_page(None, 100)
        .await
        .unwrap();
    assert_eq!(report.recovered, 0);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(
        runtime
            .metadata
            .download_job_retirement(job.token.job_id)
            .unwrap(),
        Some(snapshot)
    );
    assert_eq!(
        fs::read(transfer_dir.join("foreign.bin")).unwrap(),
        b"foreign bytes"
    );
    assert!(delivered.exists());
    fs::remove_dir_all(&transfer_dir).unwrap();
    fs::rename(&owned_dir, &transfer_dir).unwrap();
    let (_, report) = runtime
        .recover_download_retirements_page(None, 100)
        .await
        .unwrap();
    assert_eq!(report.recovered, 1);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert!(!transfer_dir.exists());
    assert!(delivered.exists());
    assert!(
        runtime
            .metadata
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .completed_at_s
            .is_some()
    );
}

#[tokio::test]
async fn stop_preserves_selected_storage_and_resumable_progress() {
    let root = unique_test_dir("ed2k-deliver-stop-preserves-pieces");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5a; 32_768];
    let hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let job = admit_download_job(
        &runtime,
        hash,
        "Resume.bin".to_owned(),
        payload.len() as u64,
    );
    runtime.ensure_job(&job).await.unwrap();
    let storage = runtime.transfer_dir_path(job.token.job_id).unwrap();
    runtime
        .append_piece_block(job.token, 0, 0, 8192, &payload[..8192])
        .await
        .unwrap();
    assert_eq!(
        runtime.checkpoint_dirty_download_progress().await.unwrap(),
        1
    );
    assert!(runtime.stop_download_job(job.token).await.unwrap());
    assert!(storage.join(super::super::PAYLOAD_FILE_NAME).exists());
    let stopped = runtime
        .metadata
        .download_job(job.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(stopped.intent, emulebb_metadata::DownloadIntent::Stopped);
    assert!(stopped.removed_at_s.is_none());
    assert_eq!(stopped.storage.unwrap().path, storage);
    assert!(
        runtime
            .metadata
            .download_job_retirement(job.token.job_id)
            .unwrap()
            .is_none()
    );
    let persisted = runtime
        .metadata
        .download_job_manifest(job.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(persisted.pieces[0].prefix_bytes, 8192);
}

#[tokio::test]
async fn remove_without_data_retires_internal_storage_but_preserves_output() {
    let root = unique_test_dir("ed2k-deliver-remove-keeps-output");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = ingest_completed(&runtime, &root, "Retained.Output.bin").await;
    let payload = fs::read(runtime.payload_path(job.token.job_id).unwrap()).unwrap();
    let output = root.join("incoming").join("Retained.Output.bin");
    runtime
        .materialize_completed_payload(job.token, &root.join("incoming"))
        .await
        .unwrap();
    let storage = runtime.transfer_dir_path(job.token.job_id).unwrap();
    assert!(
        runtime
            .remove_download_job(job.token.job_id, false)
            .await
            .unwrap()
    );
    let pending = runtime
        .metadata
        .download_job_retirement(job.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(pending.source_path.as_deref(), Some(storage.as_path()));
    assert!(
        !runtime
            .metadata
            .transfer_deletion_requested(job.token.job_id)
            .unwrap()
    );
    assert!(
        runtime
            .cleanup_removed_download_job(job.token.job_id)
            .await
            .unwrap()
    );
    assert!(!storage.exists());
    assert_eq!(fs::read(output).unwrap(), payload);
}

#[tokio::test]
async fn destructive_delete_accepts_intent_before_lifecycle_cleanup() {
    let root = unique_test_dir("ed2k-deliver-serialized-delete");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let job = ingest_completed(&runtime, &root, "Serialized.Delete.mkv").await;
    let incoming = root.join("incoming");
    let delivered = incoming.join("Serialized.Delete.mkv");
    runtime
        .materialize_completed_payload(job.token, &incoming)
        .await
        .unwrap();
    let transfer_dir = runtime.transfer_dir(job.token.job_id).unwrap();
    let lifecycle_guard = runtime.lock_lifecycle(job.token.job_id).await;
    assert!(
        tokio::time::timeout(
            Duration::from_secs(10),
            runtime.remove_download_job(job.token.job_id, true)
        )
        .await
        .unwrap()
        .unwrap()
    );
    let cleanup_runtime = Arc::clone(&runtime);
    let id = job.token.job_id;
    let mut cleanup =
        tokio::spawn(async move { cleanup_runtime.cleanup_removed_download_job(id).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut cleanup)
            .await
            .is_err()
    );
    assert!(delivered.exists());
    assert!(transfer_dir.exists());
    drop(lifecycle_guard);
    assert!(
        tokio::time::timeout(Duration::from_secs(10), cleanup)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    );
    assert!(!delivered.exists());
    assert!(!transfer_dir.exists());
    assert!(runtime.manifest(job.token).await.is_err());
}

#[tokio::test]
async fn destructive_delete_preserves_foreign_delivered_path_occupant() {
    let root = unique_test_dir("ed2k-deliver-delete-foreign-output");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Foreign.Delete.mkv").await;
    let selected_storage = runtime
        .metadata
        .download_job(hash.token.job_id)
        .unwrap()
        .unwrap()
        .storage
        .unwrap()
        .path;
    let incoming = root.join("incoming");
    let delivered = incoming.join("Foreign.Delete.mkv");
    runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();
    let foreign = vec![0x5a; 1_048_576];
    fs::write(&delivered, &foreign).unwrap();

    assert!(
        runtime
            .remove_download_job(hash.token.job_id, true)
            .await
            .unwrap()
    );
    assert!(
        runtime
            .cleanup_removed_download_job(hash.token.job_id)
            .await
            .unwrap()
    );

    assert_eq!(fs::read(&delivered).unwrap(), foreign);
    assert!(!selected_storage.exists());
    assert!(runtime.manifest(hash.token).await.is_err());
}

#[tokio::test]
async fn destructive_delete_preserves_unowned_recovered_output() {
    let root = unique_test_dir("ed2k-deliver-delete-unowned-output");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Unowned.Delete.mkv").await;
    let selected_storage = runtime
        .metadata
        .download_job(hash.token.job_id)
        .unwrap()
        .unwrap()
        .storage
        .unwrap()
        .path;
    let payload = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    let target_path = incoming.join("Unowned.Delete.mkv");
    let attempt_id = Uuid::new_v4();
    let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
    runtime
        .metadata
        .begin_transfer_delivery_attempt(hash.token, attempt_id, &target_path, &staging_path)
        .unwrap();
    fs::write(&staging_path, &payload).unwrap();
    let staging_fingerprint = native_file_fingerprint(&staging_path).unwrap();
    runtime
        .metadata
        .mark_transfer_delivery_attempt_staged(hash.token, attempt_id, &staging_fingerprint)
        .unwrap()
        .expect("delivery journal transition must match captured job");
    fs::rename(&staging_path, &target_path).unwrap();
    runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();
    assert_eq!(
        runtime
            .manifest(hash.token)
            .await
            .unwrap()
            .delivery_ownership,
        Ed2kDeliveryOwnership::Unowned
    );

    assert!(
        runtime
            .remove_download_job(hash.token.job_id, true)
            .await
            .unwrap()
    );
    assert!(
        runtime
            .cleanup_removed_download_job(hash.token.job_id)
            .await
            .unwrap()
    );
    assert_eq!(fs::read(&target_path).unwrap(), payload);
    assert!(!selected_storage.exists());
}

#[tokio::test]
async fn destructive_delete_recovers_prepared_tombstone() {
    let root = unique_test_dir("ed2k-deliver-delete-prepared-tombstone");
    let fixture = prepare_deletion_tombstone(&root, "Prepared.Tombstone.mkv").await;
    assert!(fixture.delivered.exists());
    assert!(!fixture.tombstone.exists());
    drop(fixture.runtime);

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_complete_deletion_recovery(
        restarted
            .recover_removed_download_jobs_page(None, 100)
            .await
            .unwrap()
            .1,
        1,
    );
    assert!(!fixture.delivered.exists());
    assert!(!fixture.tombstone.exists());
    assert!(!fixture.transfer_dir.exists());
}

#[tokio::test]
async fn destructive_delete_recovers_rename_before_moved_checkpoint() {
    let root = unique_test_dir("ed2k-deliver-delete-uncheckpointed-tombstone");
    let fixture = prepare_deletion_tombstone(&root, "Uncheckpointed.Tombstone.mkv").await;
    fs::rename(&fixture.delivered, &fixture.tombstone).unwrap();
    drop(fixture.runtime);

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_complete_deletion_recovery(
        restarted
            .recover_removed_download_jobs_page(None, 100)
            .await
            .unwrap()
            .1,
        1,
    );
    assert!(!fixture.delivered.exists());
    assert!(!fixture.tombstone.exists());
    assert!(!fixture.transfer_dir.exists());
}

#[tokio::test]
async fn destructive_delete_preserves_uncheckpointed_tombstone_with_changed_identity() {
    let root = unique_test_dir("ed2k-delete-rename-unstable-identity");
    let fixture = prepare_deletion_tombstone(&root, "Unstable.Identity.Tombstone.mkv").await;
    let pre_rename_fingerprint = native_file_fingerprint(&fixture.delivered).unwrap();
    fs::rename(&fixture.delivered, &fixture.tombstone).unwrap();
    let moved_object = fixture.tombstone.with_extension("moved-object");
    fs::rename(&fixture.tombstone, &moved_object).unwrap();
    fs::copy(&moved_object, &fixture.tombstone).unwrap();
    fs::remove_file(&moved_object).unwrap();
    let changed_fingerprint = native_file_fingerprint(&fixture.tombstone).unwrap();
    assert_ne!(
        pre_rename_fingerprint.identity,
        changed_fingerprint.identity
    );
    drop(fixture.runtime);

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let report = restarted
        .recover_removed_download_jobs_page(None, 100)
        .await
        .unwrap()
        .1;
    assert_complete_deletion_recovery(report, 1);
    assert!(!fixture.delivered.exists());
    assert!(fixture.tombstone.exists());
    assert!(!fixture.transfer_dir.exists());
    assert_eq!(
        restarted
            .metadata
            .pending_transfer_deletion_jobs_after(None, 100)
            .unwrap(),
        Vec::<emulebb_metadata::JobId>::new()
    );
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
            fixture.hash.token.job_id,
            fixture.tombstone_id,
            &moved_fingerprint,
        )
        .unwrap();
    drop(fixture.runtime);

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_complete_deletion_recovery(
        restarted
            .recover_removed_download_jobs_page(None, 100)
            .await
            .unwrap()
            .1,
        1,
    );
    assert!(!fixture.tombstone.exists());
    assert!(!fixture.transfer_dir.exists());
}

#[tokio::test]
async fn destructive_delete_preserves_tombstone_replacement_before_unlink() {
    let root = unique_test_dir("ed2k-delete-tombstone-unlink-race");
    let fixture = prepare_deletion_tombstone(&root, "Tombstone.Unlink.Race.mkv").await;
    fs::rename(&fixture.delivered, &fixture.tombstone).unwrap();
    let moved_fingerprint = native_file_fingerprint(&fixture.tombstone).unwrap();
    fixture
        .runtime
        .metadata
        .mark_transfer_deletion_tombstone_moved(
            fixture.hash.token.job_id,
            fixture.tombstone_id,
            &moved_fingerprint,
        )
        .unwrap();
    let owned_backup = fixture.tombstone.with_extension("owned-backup");
    let hook_backup = owned_backup.clone();
    set_before_fingerprint_remove_hook(
        &fixture.tombstone,
        Box::new(move |tombstone_path| {
            fs::rename(tombstone_path, &hook_backup).unwrap();
            fs::write(tombstone_path, b"foreign replacement").unwrap();
            Ok(())
        }),
    );

    let report = fixture
        .runtime
        .recover_removed_download_jobs_page(None, 100)
        .await
        .unwrap()
        .1;
    assert_eq!(report.recovered, 0);
    assert_eq!(report.failures.len(), 1);
    let error = &report.failures[0];
    assert!(
        error.contains("changed before physical reclamation"),
        "unexpected error: {error}"
    );
    assert_eq!(
        fs::read(&fixture.tombstone).unwrap(),
        b"foreign replacement"
    );
    assert!(owned_backup.exists());

    fs::remove_file(&fixture.tombstone).unwrap();
    fs::rename(&owned_backup, &fixture.tombstone).unwrap();
    assert_eq!(
        native_file_fingerprint(&fixture.tombstone)
            .unwrap()
            .identity,
        moved_fingerprint.identity
    );
    assert_eq!(
        fixture
            .runtime
            .metadata
            .pending_transfer_deletion_jobs_after(None, 100)
            .unwrap(),
        vec![fixture.hash.token.job_id]
    );
    assert!(
        !fixture.transfer_dir.exists(),
        "internal retirement precedes the independent pending output journal"
    );
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
            fixture.hash.token.job_id,
            fixture.tombstone_id,
            &moved_fingerprint,
        )
        .unwrap();
    fs::remove_file(&fixture.tombstone).unwrap();
    drop(fixture.runtime);

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_complete_deletion_recovery(
        restarted
            .recover_removed_download_jobs_page(None, 100)
            .await
            .unwrap()
            .1,
        1,
    );
    assert!(!fixture.transfer_dir.exists());
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
            .cleanup_removed_download_job(fixture.hash.token.job_id)
            .await
            .unwrap()
    );
    assert_eq!(fs::read(&fixture.delivered).unwrap(), payload);
    assert!(!fixture.transfer_dir.exists());
    assert!(
        fixture
            .runtime
            .metadata
            .download_job_deletion_tombstone(fixture.hash.token.job_id)
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
        &fixture.delivered,
        Box::new(move |original_path, _tombstone_path| {
            fs::remove_file(original_path).unwrap();
            fs::write(original_path, &hook_replacement).unwrap();
        }),
    );

    assert!(
        fixture
            .runtime
            .cleanup_removed_download_job(fixture.hash.token.job_id)
            .await
            .unwrap()
    );
    assert_eq!(fs::read(&fixture.delivered).unwrap(), replacement);
    assert!(!fixture.tombstone.exists());
    assert!(!fixture.transfer_dir.exists());
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
            .cleanup_removed_download_job(fixture.hash.token.job_id)
            .await
            .unwrap()
    );
    assert_eq!(fs::read(&fixture.tombstone).unwrap(), foreign);
    assert!(!fixture.delivered.exists());
    assert!(!fixture.transfer_dir.exists());
}

#[cfg(windows)]
#[tokio::test]
async fn destructive_delete_retries_windows_sharing_violation() {
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    let root = unique_test_dir("ed2k-deliver-delete-sharing-violation");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Sharing.Violation.mkv").await;
    let selected_storage = runtime
        .metadata
        .download_job(hash.token.job_id)
        .unwrap()
        .unwrap()
        .storage
        .unwrap()
        .path;
    let incoming = root.join("incoming");
    let delivered = incoming.join("Sharing.Violation.mkv");
    runtime
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();
    let blocker = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(long_path(&delivered))
        .unwrap();

    assert!(
        runtime
            .remove_download_job(hash.token.job_id, true)
            .await
            .unwrap()
    );
    assert!(
        runtime
            .cleanup_removed_download_job(hash.token.job_id)
            .await
            .is_err()
    );
    assert!(delivered.exists());
    assert_eq!(
        runtime
            .metadata
            .pending_transfer_deletion_jobs_after(None, 100)
            .unwrap(),
        vec![hash.token.job_id]
    );
    drop(blocker);

    assert_complete_deletion_recovery(
        runtime
            .recover_removed_download_jobs_page(None, 100)
            .await
            .unwrap()
            .1,
        1,
    );
    assert!(!delivered.exists());
    assert!(!selected_storage.exists());
}

#[tokio::test]
async fn destructive_delete_resumes_a_preexisting_durable_intent() {
    let root = unique_test_dir("ed2k-deliver-delete-resume-intent");
    let hash;
    let selected_storage;
    let delivered;
    {
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        hash = ingest_completed(&runtime, &root, "Resume.Delete.mkv").await;
        selected_storage = runtime
            .metadata
            .download_job(hash.token.job_id)
            .unwrap()
            .unwrap()
            .storage
            .unwrap()
            .path;
        let incoming = root.join("incoming");
        delivered = incoming.join("Resume.Delete.mkv");
        runtime
            .materialize_completed_payload(hash.token, &incoming)
            .await
            .unwrap();
        persist_deletion_intent(&runtime, &hash);
    }

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_complete_deletion_recovery(
        restarted
            .recover_removed_download_jobs_page(None, 100)
            .await
            .unwrap()
            .1,
        1,
    );
    assert!(!delivered.exists());
    assert!(!selected_storage.exists());
    assert!(
        restarted
            .metadata
            .pending_transfer_deletion_jobs_after(None, 100)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn destructive_delete_preserves_ambiguous_staged_delivery_target() {
    let root = unique_test_dir("ed2k-deliver-delete-staged-attempt");
    let hash;
    let selected_storage;
    let target_path;
    {
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        hash = ingest_completed(&runtime, &root, "Staged.Delete.mkv").await;
        selected_storage = runtime
            .metadata
            .download_job(hash.token.job_id)
            .unwrap()
            .unwrap()
            .storage
            .unwrap()
            .path;
        let incoming = root.join("incoming");
        fs::create_dir_all(&incoming).unwrap();
        target_path = incoming.join("Staged.Delete.mkv");
        fs::copy(
            runtime.payload_path(hash.token.job_id).unwrap(),
            &target_path,
        )
        .unwrap();
        let staging_fingerprint = native_file_fingerprint(&target_path).unwrap();
        let attempt_id = Uuid::new_v4();
        let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
        runtime
            .metadata
            .begin_transfer_delivery_attempt(hash.token, attempt_id, &target_path, &staging_path)
            .unwrap();
        assert!(
            runtime
                .metadata
                .mark_transfer_delivery_attempt_staged(hash.token, attempt_id, &staging_fingerprint)
                .unwrap()
                .is_some()
        );
        persist_deletion_intent(&runtime, &hash);
    }

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_complete_deletion_recovery(
        restarted
            .recover_removed_download_jobs_page(None, 100)
            .await
            .unwrap()
            .1,
        1,
    );
    assert!(target_path.exists());
    assert!(!selected_storage.exists());
    assert!(
        restarted
            .metadata
            .download_job_delivery_attempt(hash.token.job_id)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn destructive_delete_reclaims_preexisting_published_delivery_attempt() {
    let root = unique_test_dir("ed2k-deliver-delete-published-attempt");
    let hash;
    let selected_storage;
    let target_path;
    {
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        hash = ingest_completed(&runtime, &root, "Published.Delete.mkv").await;
        selected_storage = runtime
            .metadata
            .download_job(hash.token.job_id)
            .unwrap()
            .unwrap()
            .storage
            .unwrap()
            .path;
        let incoming = root.join("incoming");
        fs::create_dir_all(&incoming).unwrap();
        target_path = incoming.join("Published.Delete.mkv");
        let attempt_id = Uuid::new_v4();
        let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
        runtime
            .metadata
            .begin_transfer_delivery_attempt(hash.token, attempt_id, &target_path, &staging_path)
            .unwrap();
        fs::copy(
            runtime.payload_path(hash.token.job_id).unwrap(),
            &staging_path,
        )
        .unwrap();
        let staging_fingerprint = native_file_fingerprint(&staging_path).unwrap();
        runtime
            .metadata
            .mark_transfer_delivery_attempt_staged(hash.token, attempt_id, &staging_fingerprint)
            .unwrap()
            .expect("delivery journal transition must match captured job");
        fs::rename(&staging_path, &target_path).unwrap();
        let published_fingerprint = native_file_fingerprint(&target_path).unwrap();
        runtime
            .metadata
            .mark_transfer_delivery_attempt_published(
                hash.token,
                attempt_id,
                &published_fingerprint,
            )
            .unwrap()
            .expect("delivery journal transition must match captured job");
        persist_deletion_intent(&runtime, &hash);
    }

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_complete_deletion_recovery(
        restarted
            .recover_removed_download_jobs_page(None, 100)
            .await
            .unwrap()
            .1,
        1,
    );
    assert!(!target_path.exists());
    assert!(!selected_storage.exists());
    assert!(
        restarted
            .metadata
            .download_job_delivery_attempt(hash.token.job_id)
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
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();
    let transfer_dir = runtime.transfer_dir(hash.token.job_id).unwrap();
    fs::remove_dir_all(&transfer_dir).unwrap();
    fs::write(&transfer_dir, b"cleanup blocker").unwrap();

    assert!(
        runtime
            .remove_download_job(hash.token.job_id, true)
            .await
            .unwrap()
    );
    let transfer_tombstone = runtime
        .metadata
        .download_job_retirement(hash.token.job_id)
        .unwrap()
        .unwrap()
        .target_path
        .unwrap();
    assert!(
        runtime
            .cleanup_removed_download_job(hash.token.job_id)
            .await
            .is_err()
    );
    assert!(
        delivered.exists(),
        "internal retirement must settle before output deletion"
    );
    assert!(transfer_dir.is_file());
    assert!(!transfer_tombstone.exists());
    assert!(runtime.manifest(hash.token).await.is_err());
    assert_eq!(
        runtime
            .metadata
            .pending_transfer_deletion_jobs_after(None, 100)
            .unwrap(),
        vec![hash.token.job_id]
    );

    drop(runtime);
    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let report = restarted
        .recover_removed_download_jobs_page(None, 100)
        .await
        .unwrap()
        .1;
    assert_eq!(report.recovered, 0);
    assert_eq!(report.failures.len(), 1);
    let error = &report.failures[0];
    assert!(error.contains(&hash.token.job_id.to_string()));
    assert!(
        error.contains("job storage directory identity changed"),
        "{error}"
    );
    assert_eq!(
        restarted
            .metadata
            .pending_transfer_deletion_jobs_after(None, 100)
            .unwrap(),
        vec![hash.token.job_id]
    );

    fs::remove_file(&transfer_dir).unwrap();
    assert_complete_deletion_recovery(
        restarted
            .recover_removed_download_jobs_page(None, 100)
            .await
            .unwrap()
            .1,
        1,
    );
    assert!(!delivered.exists());
    assert!(
        restarted
            .metadata
            .pending_transfer_deletion_jobs_after(None, 100)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn pending_deletion_recovery_continues_after_an_earlier_failure() {
    let root = unique_test_dir("ed2k-delete-continue-after-failure");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let incoming = root.join("incoming");
    let hash_a = ingest_completed_bytes(&runtime, "First.bin", b"first deletion payload").await;
    let delivered_a = match runtime
        .materialize_completed_payload(hash_a.token, &incoming)
        .await
        .unwrap()
    {
        Ed2kDeliveryOutcome::Delivered(path) => path,
        outcome => panic!("unexpected first delivery outcome: {outcome:?}"),
    };
    let hash_b = ingest_completed_bytes(&runtime, "Second.bin", b"second deletion payload").await;
    let delivered_b = match runtime
        .materialize_completed_payload(hash_b.token, &incoming)
        .await
        .unwrap()
    {
        Ed2kDeliveryOutcome::Delivered(path) => path,
        outcome => panic!("unexpected second delivery outcome: {outcome:?}"),
    };
    let mut transfers = [(hash_a, delivered_a), (hash_b, delivered_b)];
    transfers.sort_by_key(|entry| entry.0.token.job_id);
    let (blocked_hash, blocked_output) = transfers[0].clone();
    let (later_hash, later_output) = transfers[1].clone();

    let later_dir = runtime
        .metadata
        .download_job(later_hash.token.job_id)
        .unwrap()
        .unwrap()
        .storage
        .unwrap()
        .path;
    let blocked_dir = runtime.transfer_dir(blocked_hash.token.job_id).unwrap();
    fs::remove_dir_all(&blocked_dir).unwrap();
    fs::write(&blocked_dir, b"cleanup blocker").unwrap();
    assert!(
        runtime
            .remove_download_job(blocked_hash.token.job_id, true)
            .await
            .unwrap()
    );
    persist_deletion_intent(&runtime, &later_hash);

    let report = runtime
        .recover_removed_download_jobs_page(None, 100)
        .await
        .unwrap()
        .1;
    assert_eq!(report.recovered, 1);
    assert_eq!(report.failures.len(), 1);
    assert!(report.failures[0].contains(&blocked_hash.token.job_id.to_string()));
    assert!(blocked_output.exists());
    assert!(!later_output.exists());
    assert!(!later_dir.exists());
    assert!(runtime.manifest(later_hash.token).await.is_err());
    assert_eq!(
        runtime
            .metadata
            .pending_transfer_deletion_jobs_after(None, 100)
            .unwrap(),
        vec![blocked_hash.token.job_id]
    );

    fs::remove_file(&blocked_dir).unwrap();
    assert_complete_deletion_recovery(
        runtime
            .recover_removed_download_jobs_page(None, 100)
            .await
            .unwrap()
            .1,
        1,
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
            .materialize_completed_payload(hash.token, &root.join("incoming"))
            .await
            .unwrap();
        transfer_dir = runtime.transfer_dir(hash.token.job_id).unwrap();
        persist_deletion_intent(&runtime, &hash);
        transfer_tombstone = runtime
            .metadata
            .download_job_retirement(hash.token.job_id)
            .unwrap()
            .unwrap()
            .target_path
            .unwrap();
        fs::rename(&transfer_dir, &transfer_tombstone).unwrap();
    }

    let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_complete_deletion_recovery(
        restarted
            .recover_removed_download_jobs_page(None, 100)
            .await
            .unwrap()
            .1,
        1,
    );
    assert!(!transfer_dir.exists());
    assert!(!transfer_tombstone.exists());
    assert!(restarted.manifest(hash.token).await.is_err());
}

#[tokio::test]
async fn destructive_delete_preserves_invalid_markers_across_restart_and_retry() {
    for tombstoned in [false, true] {
        for (case, length) in [
            ("empty", 0),
            ("short", 15),
            ("wrong-uuid", 16),
            ("overflow", 17),
            ("long", 32),
            ("huge", 64 * 1024 * 1024),
        ] {
            let root = unique_test_dir(&format!("ed2k-delete-marker-{case}-{tombstoned}"));
            let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
            let payload = b"preserve pending deletion payload";
            let hash = ingest_completed_bytes(&runtime, "Marker.Bounds.bin", payload).await;
            let transfer_dir = runtime.transfer_dir(hash.token.job_id).unwrap();
            let authority = persist_deletion_intent(&runtime, &hash);
            let transfer_tombstone = runtime
                .metadata
                .download_job_retirement(hash.token.job_id)
                .unwrap()
                .unwrap()
                .target_path
                .unwrap();
            let directory = if tombstoned {
                fs::rename(&transfer_dir, &transfer_tombstone).unwrap();
                &transfer_tombstone
            } else {
                &transfer_dir
            };
            let payload_path = directory.join(
                runtime
                    .payload_path(hash.token.job_id)
                    .unwrap()
                    .file_name()
                    .unwrap(),
            );
            let marker_path =
                transfer_directory_authority_marker_path(directory, authority.marker_id);
            let mut contents = *authority.marker_id.as_bytes();
            if case == "wrong-uuid" {
                contents[0] ^= 1;
            }
            fs::write(&marker_path, contents).unwrap();
            fs::OpenOptions::new()
                .write(true)
                .open(&marker_path)
                .unwrap()
                .set_len(length)
                .unwrap();
            drop(runtime);

            let restarted = Ed2kTransferRuntime::load_or_create(&root).unwrap();
            for _ in 0..2 {
                let report = restarted
                    .recover_removed_download_jobs_page(None, 100)
                    .await
                    .unwrap()
                    .1;
                assert_eq!(report.recovered, 0, "{case}, tombstoned={tombstoned}");
                assert_eq!(report.failures.len(), 1);
                assert!(
                    report.failures[0].contains("job storage marker"),
                    "{:?}",
                    report.failures
                );
                assert_eq!(fs::read(&payload_path).unwrap(), payload);
                assert_eq!(fs::metadata(&marker_path).unwrap().len(), length);
                assert_eq!(
                    super::super::ingest::native_directory_identity(directory),
                    Some(authority.identity)
                );
                assert_eq!(transfer_dir.exists(), !tombstoned);
                assert_eq!(transfer_tombstone.exists(), tombstoned);
                assert_eq!(
                    restarted
                        .metadata
                        .pending_transfer_deletion_jobs_after(None, 100)
                        .unwrap(),
                    vec![hash.token.job_id]
                );
            }

            fs::write(&marker_path, authority.marker_id.as_bytes()).unwrap();
            assert_complete_deletion_recovery(
                restarted
                    .recover_removed_download_jobs_page(None, 100)
                    .await
                    .unwrap()
                    .1,
                1,
            );
            assert!(!transfer_dir.exists());
            assert!(!transfer_tombstone.exists());
            assert!(
                restarted
                    .metadata
                    .pending_transfer_deletion_jobs_after(None, 100)
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

#[tokio::test]
async fn destructive_delete_preserves_tombstone_without_authority_marker() {
    let root = unique_test_dir("ed2k-delete-transfer-dir-tombstone-marker-missing");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Missing.Authority.Marker.mkv").await;
    runtime
        .materialize_completed_payload(hash.token, &root.join("incoming"))
        .await
        .unwrap();
    let transfer_dir = runtime.transfer_dir(hash.token.job_id).unwrap();
    let authority = persist_deletion_intent(&runtime, &hash);
    let transfer_tombstone = runtime
        .metadata
        .download_job_retirement(hash.token.job_id)
        .unwrap()
        .unwrap()
        .target_path
        .unwrap();
    fs::rename(&transfer_dir, &transfer_tombstone).unwrap();
    assert_eq!(
        super::super::ingest::native_directory_identity(&transfer_tombstone),
        Some(authority.identity)
    );
    fs::remove_file(transfer_directory_authority_marker_path(
        &transfer_tombstone,
        authority.marker_id,
    ))
    .unwrap();
    let sentinel = transfer_tombstone.join("unrelated.txt");
    fs::write(&sentinel, b"preserve me").unwrap();

    let report = runtime
        .recover_removed_download_jobs_page(None, 100)
        .await
        .unwrap()
        .1;
    assert_eq!(report.recovered, 0);
    assert_eq!(report.failures.len(), 1);
    assert!(
        report.failures[0].contains("job storage marker"),
        "{:?}",
        report.failures
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"preserve me");
    assert_eq!(
        runtime
            .metadata
            .pending_transfer_deletion_jobs_after(None, 100)
            .unwrap(),
        vec![hash.token.job_id]
    );
}

#[tokio::test]
async fn destructive_delete_preserves_replaced_transfer_directory_tombstone() {
    let root = unique_test_dir("ed2k-delete-transfer-dir-tombstone-replaced");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Replaced.Transfer.Tombstone.mkv").await;
    runtime
        .materialize_completed_payload(hash.token, &root.join("incoming"))
        .await
        .unwrap();
    let transfer_dir = runtime.transfer_dir(hash.token.job_id).unwrap();
    persist_deletion_intent(&runtime, &hash);
    let transfer_tombstone = runtime
        .metadata
        .download_job_retirement(hash.token.job_id)
        .unwrap()
        .unwrap()
        .target_path
        .unwrap();
    fs::rename(&transfer_dir, &transfer_tombstone).unwrap();
    // WHY: keep the old directory alive so inode reuse cannot make the
    // replacement appear to have the original native identity on Unix.
    let displaced_tombstone = transfer_tombstone.with_extension("displaced");
    fs::rename(&transfer_tombstone, &displaced_tombstone).unwrap();
    fs::create_dir(&transfer_tombstone).unwrap();
    let sentinel = transfer_tombstone.join("unrelated.txt");
    fs::write(&sentinel, b"preserve me").unwrap();

    let report = runtime
        .recover_removed_download_jobs_page(None, 100)
        .await
        .unwrap()
        .1;
    assert_eq!(report.recovered, 0);
    assert_eq!(report.failures.len(), 1);
    assert!(
        report.failures[0].contains("job storage directory identity changed"),
        "{:?}",
        report.failures
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"preserve me");
    assert_eq!(
        runtime
            .metadata
            .pending_transfer_deletion_jobs_after(None, 100)
            .unwrap(),
        vec![hash.token.job_id]
    );
}

#[tokio::test]
async fn pending_deletion_recovery_is_a_noop_without_intents() {
    let root = unique_test_dir("ed2k-deliver-delete-recovery-empty");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    assert_complete_deletion_recovery(
        runtime
            .recover_removed_download_jobs_page(None, 100)
            .await
            .unwrap()
            .1,
        0,
    );
}

#[tokio::test]
async fn concurrent_materialization_of_one_transfer_is_idempotent() {
    let root = unique_test_dir("ed2k-deliver-concurrent");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = ingest_completed(&runtime, &root, "Concurrent.mkv").await;
    let incoming = root.join("incoming");

    let (first, second) = tokio::join!(
        runtime.materialize_completed_payload(hash.token, &incoming),
        runtime.materialize_completed_payload(hash.token, &incoming)
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
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();
    let Ed2kDeliveryOutcome::Delivered(delivered) = outcome else {
        panic!("expected a fresh delivery");
    };

    // Delivery records the native fingerprint for promotion into the verified
    // local instance cache, which makes the next root scan a cache hit.
    let manifest = runtime.manifest(hash.token).await.unwrap();
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Delivered);
    let recorded = manifest
        .source_fingerprint
        .clone()
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
    let job = admit_download_job(
        &runtime,
        Ed2kHash::from_bytes([0x33; 16]),
        "unfinished.bin".to_string(),
        ED2K_PART_SIZE + 1,
    );
    runtime.ensure_job(&job).await.unwrap();
    let incoming = root.join("incoming");

    let outcome = runtime
        .materialize_completed_payload(job.token, &incoming)
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
        .materialize_completed_payload(hash.token, &incoming)
        .await
        .unwrap();

    let delivered = incoming.join("LongPath.mkv");
    assert_eq!(outcome, Ed2kDeliveryOutcome::Delivered(delivered.clone()));
    let expected = fs::read(runtime.payload_path(hash.token.job_id).unwrap()).unwrap();
    assert_eq!(fs::read(long_path(&delivered)).unwrap(), expected);
    assert!(
        runtime
            .remove_download_job(hash.token.job_id, true)
            .await
            .unwrap()
    );
    assert!(
        runtime
            .cleanup_removed_download_job(hash.token.job_id)
            .await
            .unwrap()
    );
    assert!(!long_path(&delivered).exists());
}

#[tokio::test]
async fn sharing_policy_blocks_internal_payload_admission_without_revoking_physical_evidence() {
    let root = unique_test_dir("sharing-payload-admission");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = ingest_completed(&runtime, &root, "Sample Payload.bin").await;
    let hash: emulebb_kad_proto::Ed2kHash = job.file_hash.parse().unwrap();
    let candidate = runtime
        .metadata
        .download_payload_candidate(&job.file_hash)
        .unwrap()
        .unwrap();
    let before = runtime
        .share_eligibility
        .try_batch(&[hash.0])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.complete, vec![true]);
    drop(before);
    runtime
        .metadata
        .set_library_sharing_enabled(&job.file_hash, false)
        .unwrap();
    let disabled = runtime
        .share_eligibility
        .try_batch(&[hash.0])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(disabled.complete, vec![false]);
    assert!(disabled.partial[0].is_none());
    drop(disabled);
    // A policy change is not a physical ownership or integrity change.
    assert!(
        runtime
            .metadata
            .download_payload_is_current(&candidate)
            .unwrap()
    );
    runtime
        .metadata
        .set_library_sharing_enabled(&job.file_hash, true)
        .unwrap();
    let enabled = runtime
        .share_eligibility
        .try_batch(&[hash.0])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(enabled.complete, vec![true]);
}
