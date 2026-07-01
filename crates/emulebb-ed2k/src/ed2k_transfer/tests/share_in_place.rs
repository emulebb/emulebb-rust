//! Share-in-place ingest: a shared, already-complete file is seeded for upload
//! DIRECTLY from its original on-disk path. Ingest must NOT copy the payload
//! into the internal piece store (`transfer_dir/pieces.bin`), the manifest must
//! record `source_path`, and the upload-serving read path
//! (`read_verified_range`) must return the original file's bytes.

use std::fs;

use emulebb_kad_proto::Ed2kHash;
use std::str::FromStr;

use super::super::{ED2K_EMBLOCK_SIZE, Ed2kTransferRuntime, PAYLOAD_FILE_NAME};
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

    // (5) A single upload request can serve multiple fragments through one
    // verified reader, avoiding repeated manifest loads and file opens.
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

    // (6) Upload read-ahead is bounded to one protocol request window: the
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
}

/// Best-effort canonicalization for path comparison (the ingest path is stored
/// after canonicalize + long-path normalization).
fn canonicalize_lossy(path: &str) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
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
    for (label, source_path, canonical_name) in [
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
            .ingest_local_file(source_path, canonical_name)
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
