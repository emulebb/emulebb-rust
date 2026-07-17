//! Behavioral end-to-end test for the live shared-directory monitor
//! (auto-pickup / auto-remove; round-12 IO feature).
//!
//! This drives the REAL OS file-system watcher (`notify` + the
//! `notify-debouncer-full` settle window) end to end: it starts the monitor on
//! a temp shared root, writes a new file into the watched directory, and asserts
//! the file is auto-shared into the catalog after the settle window; then
//! removes the file and asserts it is auto-unshared; then stops the monitor and
//! asserts a clean teardown (no panic, idempotent stop).
//!
//! It is a multi-thread tokio test because the watcher runs on its own thread
//! and bridges to the async consumer over a channel. Timing is handled with a
//! poll-until-condition-with-timeout loop (not a single fixed sleep) to stay
//! robust against settle-window jitter; the test is expected to take several
//! seconds because the settle window is ~2s.

use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use emulebb_core::{EmulebbCore, SharedDirectoriesUpdate, SharedDirectoryRootUpdate};
use emulebb_index::FileIndex;

/// Upper bound for the auto-pickup / auto-remove to land. The settle window is
/// ~2s; we allow generously more for hashing + scheduling jitter on a loaded CI
/// machine. The poll exits as soon as the condition is met, so a healthy run is
/// fast (~settle window).
const CONDITION_TIMEOUT: Duration = Duration::from_secs(15);
/// How often the poll loop re-checks the catalog.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Poll `core.shares()` until `name` is present (`present = true`) or absent
/// (`present = false`), up to [`CONDITION_TIMEOUT`]. Returns true if the
/// condition was met, false on timeout.
async fn poll_share_presence(core: &EmulebbCore, name: &str, present: bool) -> bool {
    let deadline = Instant::now() + CONDITION_TIMEOUT;
    loop {
        let has = core.shares().await.iter().any(|s| s.name == name);
        if has == present {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

// SKIP on macOS: the auto-remove leg depends on a filesystem *delete* event
// reaching `notify` promptly, but the macOS FSEvents backend coalesces/delays
// delete events unreliably under CI load, so the removal is not observed within
// any practical timeout even though the watcher is healthy (the create leg
// passes). macOS is a compile/test-viable-only platform (not release-supported;
// Windows x64 is the release target, Linux is runtime-proven), so this
// behavioral watcher test runs on Linux + Windows where the delete event is
// deterministic.
#[cfg_attr(
    target_os = "macos",
    ignore = "macOS FSEvents delete-event latency; watcher is release-tested on Linux + Windows"
)]
#[tokio::test(flavor = "multi_thread")]
async fn live_monitor_auto_shares_and_auto_removes_a_dropped_file() {
    let runtime_dir = unique_test_dir("monitor-e2e");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let shared_root = runtime_dir.join("shared-root");
    fs::create_dir_all(&shared_root).unwrap();

    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();

    // Configure the (initially empty) shared root. set_shared_directories already
    // (re)starts the monitor; we also call start explicitly per the feature's
    // public entry to prove it is idempotent.
    core.set_shared_directories(SharedDirectoriesUpdate {
        roots: vec![SharedDirectoryRootUpdate::Object {
            path: shared_root.display().to_string(),
        }],
        confirm_replace_roots: true,
    })
    .await
    .unwrap();
    core.start_shared_directory_monitor().await;

    // Nothing shared yet.
    assert!(
        core.shares().await.is_empty(),
        "no files should be shared before any are dropped into the watched dir",
    );

    // --- auto-pickup: drop a new file into the watched dir ---
    let watched_file = shared_root.join("auto-pickup.bin");
    fs::write(&watched_file, b"live monitor auto-pickup payload").unwrap();

    let picked_up = poll_share_presence(&core, "auto-pickup.bin", true).await;
    assert!(
        picked_up,
        "the live monitor must auto-share a file dropped into the watched dir within {CONDITION_TIMEOUT:?} \
         (settle window ~2s); the OS watcher did not pick it up",
    );

    // The auto-shared file must be a real catalog entry with a valid hash.
    let share = core
        .shares()
        .await
        .into_iter()
        .find(|s| s.name == "auto-pickup.bin")
        .expect("auto-shared file present");
    assert_eq!(
        share.hash.len(),
        32,
        "auto-shared file must have a 32-hex-char MD4 hash, got {:?}",
        share.hash,
    );
    assert!(
        share.hash.chars().all(|c| c.is_ascii_hexdigit()),
        "auto-shared file hash must be hex, got {:?}",
        share.hash,
    );

    // --- auto-remove: delete the file from the watched dir ---
    fs::remove_file(&watched_file).unwrap();

    let removed = poll_share_presence(&core, "auto-pickup.bin", false).await;
    assert!(
        removed,
        "the live monitor must auto-unshare a file removed from the watched dir within {CONDITION_TIMEOUT:?}; \
         it stayed in the catalog",
    );

    // --- clean teardown: stop is idempotent and must not panic ---
    core.stop_shared_directory_monitor();
    core.stop_shared_directory_monitor(); // second stop is a no-op, not a panic

    let _ = fs::remove_dir_all(&runtime_dir);
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
