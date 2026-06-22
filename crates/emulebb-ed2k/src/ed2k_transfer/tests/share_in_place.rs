//! Share-in-place ingest: a shared, already-complete file is seeded for upload
//! DIRECTLY from its original on-disk path. Ingest must NOT copy the payload
//! into the internal piece store (`transfer_dir/pieces.bin`), the manifest must
//! record `source_path`, and the upload-serving read path
//! (`read_verified_range`) must return the original file's bytes.

use std::fs;

use emulebb_kad_proto::Ed2kHash;
use std::str::FromStr;

use super::super::{Ed2kTransferRuntime, PAYLOAD_FILE_NAME};
use super::write_repeating_pattern_file;
use crate::paths::unique_test_dir;

#[tokio::test]
async fn ingest_shares_complete_file_in_place_without_copying_to_piece_store() {
    let root = unique_test_dir("ed2k-share-in-place");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    // The operator's original shared file lives OUTSIDE the transfer store.
    let source_dir = root.join("library");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("Shared.Complete.File.bin");
    let size = 1_048_576usize; // single ED2K part
    write_repeating_pattern_file(&source_path, size, b"emulebb-share-in-place-payload");
    let size = size as u64;

    let summary = runtime
        .ingest_local_file(&source_path, "Shared.Complete.File.bin")
        .await
        .unwrap();
    let file_hash = summary.file_hash.clone();

    // (1) The manifest is a completed share that records the ORIGINAL path.
    let manifest = runtime.manifest(&file_hash).await.unwrap();
    assert!(manifest.completed, "shared complete file must be completed");
    assert_eq!(
        manifest.source_path.as_deref().map(canonicalize_lossy),
        Some(canonicalize_lossy(source_path.to_string_lossy().as_ref())),
        "manifest must record the original on-disk source path",
    );

    // (2) NO copy was made into the internal piece store.
    let piece_store = runtime
        .transfer_dir_path(&file_hash)
        .join(PAYLOAD_FILE_NAME);
    assert!(
        !piece_store.exists(),
        "share-in-place must NOT copy the payload into the piece store ({})",
        piece_store.display(),
    );

    // (3) The original file is untouched and still its full size.
    assert_eq!(fs::metadata(&source_path).unwrap().len(), size);

    // (4) The upload-serving read path returns the ORIGINAL file's bytes,
    // proving uploads serve from the real path rather than a piece-store copy.
    let hash = Ed2kHash::from_str(&file_hash).unwrap();
    let served = runtime
        .read_verified_range(&hash, 0, size)
        .await
        .unwrap()
        .expect("a completed shared file must serve its verified range");
    assert_eq!(served.len() as u64, size);
    assert_eq!(served, fs::read(&source_path).unwrap());
}

/// Best-effort canonicalization for path comparison (the ingest path is stored
/// after canonicalize + long-path normalization).
fn canonicalize_lossy(path: &str) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}
