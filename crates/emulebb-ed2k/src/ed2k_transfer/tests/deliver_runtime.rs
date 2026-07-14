//! Runtime-level end-to-end tests for finished-file delivery
//! (`materialize_completed_payload`): a completed transfer's internal piece
//! store is materialized into an operator-facing file by its canonical name,
//! idempotently and long-path aware.

use std::{fs, path::Path};

use emulebb_kad_proto::Ed2kHash;
use md4::{Digest, Md4};

use super::super::{ED2K_PART_SIZE, Ed2kDeliveryOutcome, Ed2kTransferRuntime, new_transfer_job};
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
async fn materialize_records_delivered_mtime_for_reload_reuse() {
    let root = unique_test_dir("ed2k-deliver-mtime");
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

    // The delivered download records its mtime baseline with source_path still
    // None, so the shared-directory reload's delivered-reuse index picks it up
    // and an unchanged delivered file is a cache hit rather than a re-hash.
    let manifest = runtime.manifest(&hash).await.unwrap();
    assert!(
        manifest.source_path.is_none(),
        "a delivered download must stay source_path == None"
    );
    let recorded = manifest
        .source_mtime_ms
        .expect("the delivered file's mtime baseline must be recorded");
    // It equals exactly what the reload stats for the same file (the mtime is
    // stable across delivery), so the (size, mtime) reuse identity matches.
    let (_, _, scanned_mtime) = Ed2kTransferRuntime::scanned_source_identity(&delivered).unwrap();
    assert_eq!(
        Some(recorded),
        scanned_mtime,
        "recorded delivered mtime must match the on-disk mtime the reload sees"
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
