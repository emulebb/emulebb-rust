//! Behavioral end-to-end test for the Windows long-path (>260 char)
//! shared-directory boundary (round-12 IO feature).
//!
//! This is a real-filesystem test: it builds a shared-directory tree whose
//! absolute path exceeds the legacy `MAX_PATH` (260) limit under the OS temp
//! root, creates it through the verbatim `\\?\` form so creation succeeds
//! regardless of the machine's `LongPathsEnabled` registry state, configures it
//! as a shared root on a temp `EmulebbCore`, runs the real scan/share, and
//! asserts the deep files are scanned, ingested, and published into the shared
//! catalog with a valid hash.
//!
//! On non-Windows `long_path` is the identity function and a >260 path is
//! created/used directly; the same assertions hold.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use emulebb_core::{EmulebbCore, LocalShare, SharedDirectoriesUpdate, SharedDirectoryRootUpdate};
use emulebb_ed2k::long_path::long_path;
use emulebb_index::FileIndex;

/// Build a deep directory path under `base` whose total length exceeds 260
/// chars, by joining repeated fixed-length segments. Returns the deepest
/// directory path (NOT yet created on disk).
fn deep_long_path(base: &Path) -> PathBuf {
    // 30-char segments; ~10 of them clears 260 comfortably even for a short base.
    const SEGMENT: &str = "seg-0123456789abcdef-padding01"; // 30 chars
    assert_eq!(SEGMENT.len(), 30, "segment must be exactly 30 chars");
    let mut path = base.to_path_buf();
    for _ in 0..10 {
        path = path.join(SEGMENT);
    }
    path
}

/// Create `dir` (and parents) on disk through the verbatim long-path form so
/// creation succeeds past the legacy MAX_PATH limit regardless of the OS
/// LongPathsEnabled registry. FAILS LOUDLY (panics with the reason) if the deep
/// directory cannot be created -- the whole point of the test is that the
/// verbatim helper makes this work, so a failure here is a real bug, not a skip.
fn create_dir_all_verbatim(dir: &Path) {
    let verbatim = long_path(dir);
    fs::create_dir_all(&verbatim).unwrap_or_else(|error| {
        panic!(
            "failed to create deep (>260) shared directory via the verbatim long-path helper \
             (this must work via emulebb_ed2k::long_path::long_path): path_len={} verbatim={} error={error}",
            dir.display().to_string().len(),
            verbatim.display(),
        )
    });
}

/// Write `contents` to `file` through the verbatim long-path form.
fn write_verbatim(file: &Path, contents: &[u8]) {
    let verbatim = long_path(file);
    fs::write(&verbatim, contents).unwrap_or_else(|error| {
        panic!(
            "failed to write deep (>260) shared file via the verbatim long-path helper: file={} error={error}",
            verbatim.display(),
        )
    });
}

#[tokio::test]
async fn long_path_shared_directory_files_are_scanned_ingested_and_shared() {
    let runtime_dir = unique_test_dir("long-path-shared");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");

    // Build a deep shared root whose absolute path is > 260 chars.
    let shared_root = deep_long_path(&runtime_dir.join("shared-root"));
    let root_len = shared_root.display().to_string().len();
    assert!(
        root_len > 260,
        "deep shared root must exceed the legacy MAX_PATH (260) limit, got {root_len}; \
         the test cannot exercise the long-path boundary otherwise",
    );
    let nested_dir = shared_root.join("nested-subdir");

    // Create the tree + payloads via the verbatim helper (works regardless of
    // the OS LongPathsEnabled registry). Two top-level files + one nested.
    create_dir_all_verbatim(&nested_dir);
    let top_a_payload = b"long-path top-level payload A";
    let top_b_payload = b"long-path top-level payload B (different)";
    let nested_payload = b"long-path nested payload";
    write_verbatim(&shared_root.join("deep-top-a.bin"), top_a_payload);
    write_verbatim(&shared_root.join("deep-top-b.bin"), top_b_payload);
    write_verbatim(&nested_dir.join("deep-nested.bin"), nested_payload);

    // Configure the deep root as a shared root using its verbatim form so the
    // core's fs::canonicalize step succeeds past MAX_PATH; the stored canonical
    // path then flows through the long-path-aware scan/ingest boundary.
    let configured_root = long_path(&shared_root).display().to_string();

    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();

    core.set_shared_directories(SharedDirectoriesUpdate {
        roots: vec![SharedDirectoryRootUpdate::Object {
            path: configured_root.clone(),
        }],
        confirm_replace_roots: true,
    })
    .await
    .expect("configuring the deep (>260) shared root must succeed via the verbatim form");

    let shares = core
        .reload_shared_directories()
        .await
        .expect("scanning the deep (>260) shared tree must succeed (long-path boundary)");
    let mut names = share_names(&shares);
    names.sort();
    assert_eq!(
        names,
        vec!["deep-nested.bin", "deep-top-a.bin", "deep-top-b.bin"],
        "a >260 shared root must share the full folder tree",
    );

    // Every file is ingested with a valid (32 hex char) MD4 file hash.
    let share_a = require_share(&shares, "deep-top-a.bin");
    let share_b = require_share(&shares, "deep-top-b.bin");
    let nested_share = require_share(&shares, "deep-nested.bin");
    assert_valid_hash(&share_a);
    assert_valid_hash(&share_b);
    assert_valid_hash(&nested_share);
    assert_ne!(
        share_a.hash, share_b.hash,
        "distinct deep-path payloads must hash differently",
    );

    // The canonical shared catalog (shares()) must also list both with the same
    // hash -- i.e. they are really ingested + published, not just returned by
    // reload.
    let catalog = core.shares().await;
    assert_eq!(
        require_share(&catalog, "deep-top-a.bin").hash,
        share_a.hash,
        "deep-top-a.bin must appear in the shared catalog with its ingested hash",
    );
    assert_eq!(
        require_share(&catalog, "deep-nested.bin").hash,
        nested_share.hash,
        "deep-nested.bin must appear in the shared catalog with its ingested hash",
    );

    // Clean up the deep tree through the verbatim form (a plain remove_dir_all
    // would fail past MAX_PATH on a machine without LongPathsEnabled).
    let _ = fs::remove_dir_all(long_path(&shared_root));
    let _ = fs::remove_dir_all(long_path(&runtime_dir));
}

fn share_names(shares: &[LocalShare]) -> Vec<String> {
    shares.iter().map(|s| s.name.clone()).collect()
}

fn require_share(shares: &[LocalShare], name: &str) -> LocalShare {
    shares
        .iter()
        .find(|s| s.name == name)
        .cloned()
        .unwrap_or_else(|| panic!("expected shared file {name} not found in the catalog"))
}

fn assert_valid_hash(share: &LocalShare) {
    assert_eq!(
        share.hash.len(),
        32,
        "ED2K MD4 file hash must be 32 hex chars, got {:?} for {}",
        share.hash,
        share.name,
    );
    assert!(
        share.hash.chars().all(|c| c.is_ascii_hexdigit()),
        "ED2K file hash must be hex, got {:?} for {}",
        share.hash,
        share.name,
    );
}

fn unique_test_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let root = std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT")
        .map(PathBuf::from)
        .map(|path| path.join("tmp"))
        .unwrap_or_else(std::env::temp_dir);
    let path = root.join(format!(
        "emulebb-core-{name}-{}-{stamp}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("create test dir");
    path
}
