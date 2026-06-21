//! Runtime-level end-to-end tests for finished-file delivery
//! (`materialize_completed_payload`): a completed transfer's internal piece
//! store is materialized into an operator-facing file by its canonical name,
//! idempotently and long-path aware.

use std::{fs, path::Path};

use emulebb_kad_proto::Ed2kHash;

use super::super::{ED2K_PART_SIZE, Ed2kDeliveryOutcome, Ed2kTransferRuntime, new_transfer_job};
use super::write_repeating_pattern_file;
use crate::long_path::long_path;
use crate::paths::unique_test_dir;

/// Ingest a local payload (a fully verified, completed transfer with a real
/// piece store) so the delivery tests have a finished file to materialize.
async fn ingest_completed(
    runtime: &Ed2kTransferRuntime,
    root: &Path,
    canonical_name: &str,
) -> String {
    let source_dir = root.join("source");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("payload.bin");
    write_repeating_pattern_file(&source_path, 1_048_576, b"emulebb-delivery-payload");
    runtime
        .ingest_local_file(&source_path, canonical_name)
        .await
        .unwrap()
        .file_hash
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
    // The internal piece store is kept (hard-link or copy never removes it).
    assert!(runtime.payload_path(&hash).exists());
    // The delivered path is recorded on the manifest.
    let manifest = runtime.manifest(&hash).await.unwrap();
    assert_eq!(
        manifest.delivered_path.as_deref(),
        Some(delivered.to_string_lossy().as_ref())
    );

    // A second call is an idempotent no-op (already delivered, file present).
    let again = runtime
        .materialize_completed_payload(&hash, &incoming)
        .await
        .unwrap();
    assert_eq!(again, Ed2kDeliveryOutcome::AlreadyDelivered(delivered));
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
