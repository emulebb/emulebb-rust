//! Share-in-place ingest: a shared, already-complete file is seeded for upload
//! DIRECTLY from its original on-disk path. Ingest must NOT copy the payload
//! into the internal piece store (`transfer_dir/pieces.bin`), the manifest must
//! record `source_path`, and the upload-serving read path
//! (`read_verified_range`) must return the original file's bytes.

use std::fs;

use emulebb_kad_proto::Ed2kHash;
use std::str::FromStr;

use super::super::{
    ED2K_EMBLOCK_SIZE, Ed2kDeliveryOutcome, Ed2kDeliveryState, Ed2kTransferRuntime,
    PAYLOAD_FILE_NAME,
};
use super::write_repeating_pattern_file;
use crate::paths::unique_test_dir;

#[cfg(unix)]
use emulebb_metadata::NativePath;

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
    assert_eq!(manifest.delivery_state, Ed2kDeliveryState::NotApplicable);
    assert!(
        manifest.transfer_row_removed,
        "shared complete file must stay out of the download queue from its first write",
    );
    assert_eq!(
        manifest.source_path.as_deref().map(canonicalize_lossy),
        Some(canonicalize_lossy(&source_path)),
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
    assert!(
        !runtime.transfer_dir_path(&file_hash).exists(),
        "share-in-place must not create an empty per-hash transfer directory",
    );

    let incoming = root.join("incoming");
    assert_eq!(
        runtime
            .materialize_completed_payload(&file_hash, &incoming)
            .await
            .unwrap(),
        Ed2kDeliveryOutcome::NotRequired,
    );
    assert!(!incoming.exists());

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

    // (5) Small/tail upload reads stay exact instead of priming a full
    // protocol-window read-ahead, avoiding cold-disk amplification when a peer
    // asks for a short range near the end of a file.
    let mut reader = runtime
        .open_verified_range_reader(&hash)
        .await
        .unwrap()
        .expect("a completed shared file must open a verified range reader");
    let source_bytes = fs::read(&source_path).unwrap();
    let first = reader.read_range(0, 4096).await.unwrap().unwrap();
    let second = reader.read_range(4096, 8192).await.unwrap().unwrap();
    assert_eq!(first, source_bytes[0..4096]);
    assert_eq!(second, source_bytes[4096..8192]);
    assert_eq!(reader.cache_miss_count(), 2);
    assert_eq!(reader.cache_hit_count(), 0);
    assert_eq!(reader.disk_read_bytes(), 8192);

    // (6) A caller can suppress read-ahead for an accepted block when the rest
    // of the OP_REQUESTPARTS ranges were already served and should not drive
    // speculative disk IO.
    let mut reader = runtime
        .open_verified_range_reader(&hash)
        .await
        .unwrap()
        .expect("a completed shared file must open a verified range reader");
    let first = reader
        .read_range_with_read_ahead(0, ED2K_EMBLOCK_SIZE, ED2K_EMBLOCK_SIZE)
        .await
        .unwrap()
        .unwrap();
    let second = reader
        .read_range_with_read_ahead(ED2K_EMBLOCK_SIZE, ED2K_EMBLOCK_SIZE * 2, ED2K_EMBLOCK_SIZE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first, source_bytes[0..ED2K_EMBLOCK_SIZE as usize]);
    assert_eq!(
        second,
        source_bytes[ED2K_EMBLOCK_SIZE as usize..(ED2K_EMBLOCK_SIZE * 2) as usize]
    );
    assert_eq!(reader.cache_miss_count(), 2);
    assert_eq!(reader.cache_hit_count(), 0);
    assert_eq!(reader.disk_read_bytes(), ED2K_EMBLOCK_SIZE * 2);

    // (7) Upload read-ahead is bounded to one protocol request window: the
    // first fragment primes the cache, and the next two contiguous EMBLOCKSIZE
    // fragments reuse it without another disk read.
    let mut reader = runtime
        .open_verified_range_reader(&hash)
        .await
        .unwrap()
        .expect("a completed shared file must open a verified range reader");
    for index in 0..3u64 {
        let start = index * ED2K_EMBLOCK_SIZE;
        let end = start + ED2K_EMBLOCK_SIZE;
        let served = reader.read_range(start, end).await.unwrap().unwrap();
        assert_eq!(
            served,
            source_bytes[start as usize..end as usize],
            "fragment {index} must match the original source bytes",
        );
    }
    assert_eq!(
        reader.disk_read_count(),
        1,
        "three contiguous upload fragments should be covered by one read-ahead"
    );
    assert_eq!(reader.cache_miss_count(), 1);
    assert_eq!(reader.cache_hit_count(), 2);
    assert_eq!(reader.disk_read_bytes(), ED2K_EMBLOCK_SIZE * 3);
}

#[tokio::test]
async fn relocated_share_uses_new_source_without_runtime_restart() {
    let root = unique_test_dir("ed2k-share-relocate-live-cache");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let source_dir = root.join("library");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("before.bin");
    let relocated_path = source_dir.join("after.bin");
    let payload = b"relocated live cache payload";
    fs::write(&source_path, payload).unwrap();
    let summary = runtime
        .ingest_local_file(&source_path, "before.bin")
        .await
        .unwrap();
    let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();

    fs::rename(&source_path, &relocated_path).unwrap();
    let (_, file_size, source_fingerprint) =
        Ed2kTransferRuntime::scanned_source_identity(&relocated_path).unwrap();
    assert!(
        runtime
            .relocate_shared_source(
                &summary.file_hash,
                &source_path,
                &relocated_path,
                file_size,
                source_fingerprint.clone(),
                "after.bin",
                "unknown",
            )
            .await
            .unwrap()
    );

    let manifest = runtime.manifest(&summary.file_hash).await.unwrap();
    let expected_relocated_path = crate::long_path::long_path(&relocated_path);
    assert_eq!(
        manifest.source_path.as_deref(),
        Some(expected_relocated_path.as_path())
    );
    assert_eq!(manifest.source_fingerprint, source_fingerprint);
    assert_eq!(manifest.display_name, "after.bin");
    assert_eq!(
        runtime
            .read_verified_range(&hash, 0, payload.len() as u64)
            .await
            .unwrap()
            .unwrap(),
        payload,
    );
}

#[tokio::test]
async fn changed_relocation_withdraws_share_until_rehashed() {
    let root = unique_test_dir("ed2k-share-relocate-changed");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let source_dir = root.join("library");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("before.bin");
    let relocated_path = source_dir.join("after.bin");
    let payload = vec![0x35; 4096];
    fs::write(&source_path, &payload).unwrap();
    let summary = runtime
        .ingest_local_file(&source_path, "before.bin")
        .await
        .unwrap();
    let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();
    assert_eq!(runtime.shared_catalog_count().await, 1);

    fs::rename(&source_path, &relocated_path).unwrap();
    assert!(
        runtime
            .relocate_shared_source(
                &summary.file_hash,
                &source_path,
                &relocated_path,
                payload.len() as u64,
                None,
                "after.bin",
                "unknown",
            )
            .await
            .unwrap()
    );

    let manifest = runtime.manifest(&summary.file_hash).await.unwrap();
    assert_eq!(
        manifest.source_path.as_deref(),
        Some(crate::long_path::long_path(&relocated_path).as_path())
    );
    assert!(manifest.source_fingerprint.is_none());
    assert_eq!(runtime.shared_catalog_count().await, 0);
    assert!(
        runtime
            .read_verified_range(&hash, 0, payload.len() as u64)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(fs::read(&relocated_path).unwrap(), payload);
}

#[tokio::test]
async fn replaced_share_source_is_withdrawn_before_upload() {
    let root = unique_test_dir("ed2k-share-replaced-source");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let source_dir = root.join("library");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("shared.bin");
    let original_path = source_dir.join("original.bin");
    let trusted_payload = vec![0x46; 4096];
    let foreign_payload = vec![0x97; trusted_payload.len()];
    fs::write(&source_path, &trusted_payload).unwrap();
    let summary = runtime
        .ingest_local_file(&source_path, "shared.bin")
        .await
        .unwrap();
    let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();
    assert_eq!(runtime.shared_catalog_count().await, 1);

    fs::rename(&source_path, &original_path).unwrap();
    fs::write(&source_path, &foreign_payload).unwrap();

    assert!(
        runtime
            .read_verified_range(&hash, 0, trusted_payload.len() as u64)
            .await
            .unwrap()
            .is_none(),
        "foreign replacement bytes must never be served under the trusted hash"
    );
    let manifest = runtime.manifest(&summary.file_hash).await.unwrap();
    assert!(manifest.completed);
    assert!(manifest.source_fingerprint.is_none());
    assert_eq!(runtime.shared_catalog_count().await, 0);
    assert_eq!(fs::read(&source_path).unwrap(), foreign_payload);
    assert_eq!(fs::read(&original_path).unwrap(), trusted_payload);
}

#[cfg(windows)]
#[tokio::test]
async fn verified_reader_excludes_concurrent_windows_writers() {
    let root = unique_test_dir("ed2k-share-reader-writer-exclusion");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let source_path = root.join("shared.bin");
    let payload = vec![0x42; 4096];
    fs::write(&source_path, &payload).unwrap();
    let summary = runtime
        .ingest_local_file(&source_path, "shared.bin")
        .await
        .unwrap();
    let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();

    let reader = runtime
        .open_verified_range_reader(&hash)
        .await
        .unwrap()
        .expect("verified share must open a reader");
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .is_err(),
        "the verified reader must deny concurrent write handles"
    );
    drop(reader);
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .is_ok(),
        "writer must succeed after the verified reader closes"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn verified_reader_rejects_unix_mutation_after_open() {
    let root = unique_test_dir("ed2k-share-reader-post-open-mutation");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let source_path = root.join("shared.bin");
    let trusted_payload = vec![0x42; 4096];
    let foreign_payload = vec![0x73; trusted_payload.len()];
    fs::write(&source_path, &trusted_payload).unwrap();
    let summary = runtime
        .ingest_local_file(&source_path, "shared.bin")
        .await
        .unwrap();
    let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();

    let mut reader = runtime
        .open_verified_range_reader(&hash)
        .await
        .unwrap()
        .expect("verified share must open a reader");
    fs::write(&source_path, &foreign_payload).unwrap();
    let error = reader
        .read_range(0, foreign_payload.len() as u64)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("verified ED2K upload payload changed while being read")
    );
}

#[tokio::test]
async fn relocating_secondary_source_preserves_canonical_manifest_identity() {
    let root = unique_test_dir("ed2k-share-relocate-secondary");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let source_dir = root.join("library");
    fs::create_dir_all(&source_dir).unwrap();
    let first_path = source_dir.join("first.bin");
    let second_path = source_dir.join("second.bin");
    let relocated_path = source_dir.join("relocated-secondary.bin");
    let payload = vec![0x58; 4096];
    fs::write(&first_path, &payload).unwrap();
    fs::write(&second_path, &payload).unwrap();
    let first = runtime
        .ingest_local_file(&first_path, "first.bin")
        .await
        .unwrap();
    let second = runtime
        .ingest_local_file(&second_path, "second.bin")
        .await
        .unwrap();
    assert_eq!(first.file_hash, second.file_hash);
    let canonical_before = runtime.manifest(&first.file_hash).await.unwrap();
    assert_eq!(canonical_before.display_name, "second.bin");
    assert_eq!(
        canonical_before.source_path.as_deref(),
        Some(crate::long_path::long_path(&second_path).as_path())
    );

    fs::rename(&first_path, &relocated_path).unwrap();
    let (_, file_size, source_fingerprint) =
        Ed2kTransferRuntime::scanned_source_identity(&relocated_path).unwrap();
    assert!(
        runtime
            .relocate_shared_source(
                &first.file_hash,
                &first_path,
                &relocated_path,
                file_size,
                source_fingerprint,
                "relocated-secondary.bin",
                "unknown",
            )
            .await
            .unwrap()
    );

    let canonical_after = runtime.manifest(&first.file_hash).await.unwrap();
    assert_eq!(canonical_after.display_name, canonical_before.display_name);
    assert_eq!(canonical_after.source_path, canonical_before.source_path);
    assert_eq!(
        canonical_after.source_fingerprint,
        canonical_before.source_fingerprint
    );
    let shared_sources = runtime
        .metadata
        .current_shared_files_by_hash(&first.file_hash)
        .unwrap();
    assert_eq!(shared_sources.len(), 2);
    assert!(
        shared_sources
            .iter()
            .all(|source| source.display_name == "second.bin")
    );
    assert!(
        shared_sources
            .iter()
            .any(|source| { source.source_path == crate::long_path::long_path(&second_path) })
    );
    assert!(
        shared_sources
            .iter()
            .any(|source| { source.source_path == crate::long_path::long_path(&relocated_path) })
    );
    assert!(
        shared_sources
            .iter()
            .all(|source| { source.source_path != crate::long_path::long_path(&first_path) })
    );
}

/// Best-effort canonicalization for path comparison (the ingest path is stored
/// after canonicalize + long-path normalization).
fn canonicalize_lossy(path: &std::path::Path) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

/// Regression guard: sharing must not silently drop files whose paths carry
/// non-ASCII characters (accents / CJK), brackets, or that live in nested
/// subfolders.
///
/// Background: on Windows the live failure was ingest converting the source path
/// to the verbatim (`\\?\`) long-path form and then `canonicalize()`ing it; on
/// the operator's volume the OS-re-normalized verbatim path no longer resolved
/// for such names, so the follow-up stat failed and the file was skipped
/// ("failed to stat local ingest source"). The exact re-normalization mismatch
/// is filesystem/volume/locale specific and does not reproduce on every NTFS
/// volume, so this test does not assert the old code panics; instead it exercises
/// the long-path ingest path end-to-end for exactly the affected name classes and
/// asserts each file ingests and serves. The fix removes the redundant
/// `canonicalize()` so ingest stats/hashes the long-path form directly -- the
/// same absolute path the directory walk already validated.
#[tokio::test]
async fn ingest_shares_files_with_unicode_brackets_and_nested_subfolders() {
    let root = unique_test_dir("ed2k-share-unicode-paths");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    let size = 1_048_576usize; // single ED2K part
    let payload = b"emulebb-unicode-share-payload";

    // A library tree with the exact shape that triggered the live failure:
    // an accented + bracketed directory holding an accented + bracketed file,
    // a nested "covers" subfolder, and a CJK-named file -- all created with
    // their real on-disk names (NFC composed `\u{00e0}` = a-grave).
    let library = root.join("library");

    // (1) accented + bracketed directory and file, two levels deep.
    let accented_dir = library
        .join("Studio Sample")
        .join("La citt\u{00e0} sample [tt0000001]");
    fs::create_dir_all(&accented_dir).unwrap();
    let accented_file = accented_dir.join("(2001) La citt\u{00e0} sample [tt0000001].mkv");
    write_repeating_pattern_file(&accented_file, size, payload);

    // (2) nested "covers" subfolder with a plain file (subfolder-only case).
    let covers_dir = library.join("Studio Sample").join("Covers");
    fs::create_dir_all(&covers_dir).unwrap();
    let cover_file = covers_dir.join("front-cover.jpg");
    write_repeating_pattern_file(&cover_file, size, payload);

    // (3) CJK-named file in a CJK-named subfolder.
    let cjk_dir = library.join("\u{6620}\u{753b}");
    fs::create_dir_all(&cjk_dir).unwrap();
    let cjk_file = cjk_dir.join("\u{30b5}\u{30f3}\u{30d7}\u{30eb} sample.bin");
    write_repeating_pattern_file(&cjk_file, size, payload);

    // Every one of these must ingest without a stat/skip failure.
    for (label, source_path, display_name) in [
        (
            "accented+bracketed nested file",
            &accented_file,
            "(2001) La citt\u{00e0} sample [tt0000001].mkv",
        ),
        ("nested subfolder cover", &cover_file, "front-cover.jpg"),
        (
            "CJK nested file",
            &cjk_file,
            "\u{30b5}\u{30f3}\u{30d7}\u{30eb} sample.bin",
        ),
    ] {
        let summary = runtime
            .ingest_local_file(source_path, display_name)
            .await
            .unwrap_or_else(|error| panic!("ingest of {label} failed: {error:#}"));
        assert_eq!(
            summary.file_size, size as u64,
            "{label}: ingested file size must match the on-disk payload",
        );

        // The shared file must be served back from its ORIGINAL on-disk path
        // (in-place share), proving the long-path stat/read resolved correctly.
        let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();
        let served = runtime
            .read_verified_range(&hash, 0, size as u64)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{label}: shared file did not serve its verified range"));
        assert_eq!(
            served,
            fs::read(source_path).unwrap(),
            "{label}: served bytes"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn non_utf8_share_reopens_relocates_and_serves_exact_bytes() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let root = unique_test_dir("ed2k-share-non-utf8-path");
    let source_dir = root.join("library");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join(OsString::from_vec(b"native-\xff.bin".to_vec()));
    let payload = b"non-UTF-8 share upload payload";
    if let Err(error) = fs::write(&source_path, payload) {
        eprintln!("skipping non-UTF-8 path test: filesystem rejected name: {error}");
        return;
    }
    let display_name = NativePath::from(source_path.as_path())
        .display_file_name()
        .unwrap();
    assert_eq!(display_name, r"native-\xFF.bin");

    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let summary = runtime
        .ingest_local_file(&source_path, &display_name)
        .await
        .unwrap();
    let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();
    assert_eq!(
        runtime
            .read_verified_range(&hash, 0, payload.len() as u64)
            .await
            .unwrap()
            .unwrap(),
        payload,
    );
    drop(runtime);

    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_eq!(
        runtime
            .read_verified_range(&hash, 0, payload.len() as u64)
            .await
            .unwrap()
            .unwrap(),
        payload,
    );

    let renamed_path = source_dir.join(OsString::from_vec(b"renamed-\xfe.bin".to_vec()));
    fs::rename(&source_path, &renamed_path).unwrap();
    let (_, file_size, source_fingerprint) =
        Ed2kTransferRuntime::scanned_source_identity(&renamed_path).unwrap();
    let renamed_display_name = NativePath::from(renamed_path.as_path())
        .display_file_name()
        .unwrap();
    assert!(
        runtime
            .relocate_shared_source(
                &summary.file_hash,
                &source_path,
                &renamed_path,
                file_size,
                source_fingerprint,
                &renamed_display_name,
                "unknown",
            )
            .await
            .unwrap()
    );
    drop(runtime);

    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let manifest = runtime.manifest(&summary.file_hash).await.unwrap();
    assert_eq!(
        manifest.source_path.as_deref(),
        Some(renamed_path.as_path())
    );
    assert_eq!(manifest.display_name, r"renamed-\xFE.bin");
    assert_eq!(
        runtime
            .read_verified_range(&hash, 0, payload.len() as u64)
            .await
            .unwrap()
            .unwrap(),
        payload,
    );
    drop(runtime);

    fs::remove_file(&renamed_path).unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert!(!matches!(
        runtime
            .read_verified_range(&hash, 0, payload.len() as u64)
            .await,
        Ok(Some(_)),
    ));
}
