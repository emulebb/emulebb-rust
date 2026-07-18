use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use emulebb_core::{EmulebbCore, LocalShare, SharedDirectoriesUpdate, SharedDirectoryRootUpdate};
use emulebb_index::FileIndex;

#[tokio::test]
async fn shared_directory_roots_survive_core_restart() {
    let runtime_dir = unique_test_dir("shared-directory-roots");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let shared_root = runtime_dir.join("shared-root");
    fs::create_dir_all(&shared_root).unwrap();

    {
        let core = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap();
        core.set_shared_directories(SharedDirectoriesUpdate {
            roots: vec![SharedDirectoryRootUpdate::Object {
                path: shared_root.display().to_string(),
            }],
            confirm_replace_roots: true,
        })
        .await
        .unwrap();
    }

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let directories = reloaded.shared_directories().await;
    let expected_path = fs::canonicalize(&shared_root)
        .unwrap()
        .display()
        .to_string();

    assert_eq!(directories.roots.len(), 1);
    assert_eq!(directories.roots[0].path, expected_path);
}

#[tokio::test]
async fn shared_directory_reload_always_shares_folder_tree() {
    let runtime_dir = unique_test_dir("shared-directory-tree");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let shared_root = runtime_dir.join("shared-root");
    let nested_root = shared_root.join("nested");
    fs::create_dir_all(&nested_root).unwrap();
    fs::write(shared_root.join("top.bin"), b"top-level payload").unwrap();
    fs::write(nested_root.join("nested.bin"), b"nested payload").unwrap();

    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    core.set_shared_directories(SharedDirectoriesUpdate {
        roots: vec![SharedDirectoryRootUpdate::Object {
            path: shared_root.display().to_string(),
        }],
        confirm_replace_roots: true,
    })
    .await
    .unwrap();

    let names = shared_file_names(core.reload_shared_directories().await.unwrap());
    assert_eq!(names, vec!["nested.bin", "top.bin"]);
}

#[tokio::test]
async fn shared_directory_model_expands_folder_tree_items_like_mfc() {
    let runtime_dir = unique_test_dir("shared-directory-tree-items");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let shared_root = runtime_dir.join("shared-root");
    let nested_root = shared_root.join("nested");
    fs::create_dir_all(&nested_root).unwrap();

    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let directories = core
        .set_shared_directories(SharedDirectoriesUpdate {
            roots: vec![SharedDirectoryRootUpdate::Object {
                path: shared_root.display().to_string(),
            }],
            confirm_replace_roots: true,
        })
        .await
        .unwrap();

    let expected_root = fs::canonicalize(&shared_root)
        .unwrap()
        .display()
        .to_string();
    let expected_nested = fs::canonicalize(&nested_root)
        .unwrap()
        .display()
        .to_string();

    assert_eq!(directories.roots.len(), 1);
    assert_eq!(directories.roots[0].path, expected_root);
    assert!(!directories.roots[0].monitor_owned);

    assert_eq!(
        directories
            .items
            .iter()
            .map(|item| (item.path.as_str(), item.monitor_owned))
            .collect::<Vec<_>>(),
        vec![
            (expected_root.as_str(), false),
            (expected_nested.as_str(), true)
        ]
    );
    assert_eq!(directories.monitor_owned, vec![expected_nested]);
}

#[tokio::test]
async fn shared_directory_tree_shares_survive_restart_and_reload_new_files() {
    let runtime_dir = unique_test_dir("shared-directory-tree-restart");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let shared_root = runtime_dir.join("shared-root");
    let nested_root = shared_root.join("nested").join("unicode");
    fs::create_dir_all(&nested_root).unwrap();
    let first_payload = b"first folder-tree shared payload";
    let second_payload = b"second folder-tree shared payload";
    fs::write(nested_root.join("Persisted Unicode äöü.bin"), first_payload).unwrap();

    let first_hash = {
        let core = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap();
        core.set_shared_directories(SharedDirectoriesUpdate {
            roots: vec![SharedDirectoryRootUpdate::Object {
                path: shared_root.display().to_string(),
            }],
            confirm_replace_roots: true,
        })
        .await
        .unwrap();
        let shares = core.reload_shared_directories().await.unwrap();
        let first_share = require_share_by_name(&shares, "Persisted Unicode äöü.bin");
        // Share-in-place: the file is seeded directly from its original on-disk
        // path and must NOT be copied into the internal piece store.
        assert_no_piece_store_copy(&first_share);
        assert_eq!(
            fs::read(nested_root.join("Persisted Unicode äöü.bin")).unwrap(),
            first_payload
        );
        first_share.hash
    };

    fs::write(
        shared_root.join("Reloaded Tree Payload.bin"),
        second_payload,
    )
    .unwrap();

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let existing_shares = reloaded.shares().await;
    let existing_first_share = require_share_by_name(&existing_shares, "Persisted Unicode äöü.bin");
    assert_eq!(existing_first_share.hash, first_hash);
    assert!(PathBuf::from(&existing_first_share.transfer_dir).is_dir());
    assert_no_piece_store_copy(&existing_first_share);
    assert_eq!(
        fs::read(nested_root.join("Persisted Unicode äöü.bin")).unwrap(),
        first_payload
    );

    let reloaded_shares = reloaded.reload_shared_directories().await.unwrap();
    assert_eq!(
        shared_file_names(reloaded_shares.clone()),
        vec!["Persisted Unicode äöü.bin", "Reloaded Tree Payload.bin"]
    );
    let second_share = require_share_by_name(&reloaded_shares, "Reloaded Tree Payload.bin");
    assert_no_piece_store_copy(&second_share);
    assert_eq!(
        fs::read(shared_root.join("Reloaded Tree Payload.bin")).unwrap(),
        second_payload
    );
}

/// The detached reload must hash + index the *entire* configured library on a
/// background task that survives independent of the caller: after a single
/// `reload_shared_directories_detached()` the caller does nothing further, yet
/// every file under the roots must end up shared and `hashingCount` must drain
/// back to 0. This is the regression guard for the bug where the full hash was
/// tied to a short-lived HTTP request and stalled after a handful of files.
#[tokio::test]
async fn detached_reload_hashes_whole_library_without_caller_driving_it() {
    let runtime_dir = unique_test_dir("shared-directory-detached");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let shared_root = runtime_dir.join("shared-root");
    let nested_root = shared_root.join("a").join("b");
    fs::create_dir_all(&nested_root).unwrap();

    // A spread of files across the tree (more than the handful that survived the
    // request-bound stall), each with distinct content so they hash to distinct
    // shares (no idempotent collapse hiding a missed file).
    const FILE_COUNT: usize = 24;
    let mut expected_names = Vec::new();
    for index in 0..FILE_COUNT {
        let dir = if index % 2 == 0 {
            &shared_root
        } else {
            &nested_root
        };
        let name = format!("payload-{index:02}.bin");
        fs::write(
            dir.join(&name),
            format!("distinct payload contents #{index}"),
        )
        .unwrap();
        expected_names.push(name);
    }
    expected_names.sort();

    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    core.set_shared_directories(SharedDirectoriesUpdate {
        roots: vec![SharedDirectoryRootUpdate::Object {
            path: shared_root.display().to_string(),
        }],
        confirm_replace_roots: true,
    })
    .await
    .unwrap();

    // `set_shared_directories` already kicked the initial detached reload, which
    // hashes the whole fresh library. Wait for that to complete and confirm the
    // entire library is shared WITHOUT the caller driving the hash path.
    wait_for_hashing_idle(&core).await;
    let mut shared_names = Vec::new();
    for _ in 0..600 {
        shared_names = shared_file_names(core.shares().await);
        if shared_names.len() >= FILE_COUNT {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        shared_names, expected_names,
        "detached reload must hash and share the entire library on its own",
    );
    wait_for_hashing_idle(&core).await;
    assert_eq!(core.shared_directories().await.hashing_count, 0);
    let progress = core.shared_directories().await.reload_progress;
    assert_eq!(progress.planned_hash_count, FILE_COUNT);
    assert_eq!(progress.hashed_count, FILE_COUNT);
    assert_eq!(progress.failed_hash_count, 0);
    assert!(progress.planned_hash_bytes > 0);
    assert_eq!(progress.planned_read_bytes, progress.planned_hash_bytes * 2);
    assert!(!progress.recent.is_empty());
    assert!(!progress.disks.is_empty());

    // Incremental skip: a SECOND detached reload over the now-indexed, unchanged
    // library must NOT re-queue any file for hashing (every file matches its
    // persisted path + size + mtime), yet the whole library stays shared. This is
    // the regression guard for the wasteful full re-hash on every reload.
    let requeued = core.reload_shared_directories_detached().await.unwrap();
    assert_eq!(
        requeued, 0,
        "an unchanged library must re-hash nothing on reload",
    );
    assert_eq!(
        core.shared_directories().await.hashing_count,
        0,
        "hashingCount must stay 0 when nothing needs re-hashing",
    );
    wait_for_reload_reuse_count(&core, FILE_COUNT).await;
    let reload = core.shared_directories().await.reload_progress;
    assert_eq!(reload.scanned_count, FILE_COUNT);
    assert_eq!(reload.planned_hash_count, 0);
    assert_eq!(reload.reused_count, FILE_COUNT);
    assert_eq!(
        shared_file_names(core.shares().await),
        expected_names,
        "unchanged files must remain shared after an incremental reload",
    );
}

/// Sharing a directory of already-complete files must NOT run any file through
/// the download-completion delivery path: nothing may be copied into the
/// incoming dir, and nothing may be copied into the internal piece store. This
/// is the regression guard for the bug where each shared complete file was
/// treated as a "completed transfer" and duplicated into incoming + transfers.
#[tokio::test]
async fn sharing_complete_directory_never_delivers_to_incoming_or_piece_store() {
    let runtime_dir = unique_test_dir("share-no-delivery");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let shared_root = runtime_dir.join("library");
    let incoming_dir = runtime_dir.join("incoming");
    fs::create_dir_all(&shared_root).unwrap();

    let payloads = [
        (
            "Complete.Movie.One.bin",
            &b"complete shared payload one xxxx"[..],
        ),
        (
            "Complete.Movie.Two.bin",
            &b"complete shared payload two yyyy"[..],
        ),
        (
            "Complete.Movie.Three.bin",
            &b"complete shared payload three z"[..],
        ),
    ];
    for (name, payload) in payloads {
        fs::write(shared_root.join(name), payload).unwrap();
    }

    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap()
    .with_incoming_dir(incoming_dir.clone());

    core.set_shared_directories(SharedDirectoriesUpdate {
        roots: vec![SharedDirectoryRootUpdate::Object {
            path: shared_root.display().to_string(),
        }],
        confirm_replace_roots: true,
    })
    .await
    .unwrap();

    let shares = core.reload_shared_directories().await.unwrap();
    assert_eq!(shares.len(), payloads.len(), "every file must be shared");

    // The startup delivery sweep (run by the daemon on boot) must treat these
    // shared complete files as share-in-place and deliver NOTHING.
    core.deliver_pending_completed_transfers().await;

    // (1) The incoming dir was never created / never received a copy.
    if incoming_dir.exists() {
        let entries: Vec<_> = fs::read_dir(&incoming_dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries.is_empty(),
            "no shared complete file may be delivered to incoming, found: {entries:?}",
        );
    }

    // (2) No shared file was copied into the internal piece store, and the
    // original files are untouched.
    for share in &shares {
        assert_no_piece_store_copy(share);
    }
    for (name, payload) in payloads {
        assert_eq!(
            fs::read(shared_root.join(name)).unwrap(),
            payload,
            "the operator's original {name} must be untouched",
        );
    }
}

/// Incremental reload: once a shared library is hashed and persisted, a later
/// reload must SKIP re-hashing every file whose on-disk identity (path + size +
/// mtime) is unchanged, re-hash only a file whose size/mtime changed, and hash a
/// newly added file. This is the regression guard for the wasteful full re-hash
/// of the entire library on every daemon startup / reload.
///
/// `reload_shared_directories_detached` returns as soon as the reload job is
/// accepted. The scan/stat planning and hashing happen inside that job, so this
/// test observes the resulting shared-library state instead of relying on a
/// synchronous queued count.
#[tokio::test]
async fn reload_skips_unchanged_files_and_rehashes_only_changed_or_new() {
    let runtime_dir = unique_test_dir("shared-directory-incremental");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let shared_root = runtime_dir.join("library");
    fs::create_dir_all(&shared_root).unwrap();

    // Three distinct files seed the initial library.
    fs::write(
        shared_root.join("keep-unchanged.bin"),
        b"unchanged payload one",
    )
    .unwrap();
    fs::write(
        shared_root.join("change-mtime.bin"),
        b"mtime payload two!!!!",
    )
    .unwrap();
    fs::write(shared_root.join("change-size.bin"), b"size payload three").unwrap();

    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    // `set_shared_directories` kicks the initial detached reload; let it finish.
    core.set_shared_directories(SharedDirectoriesUpdate {
        roots: vec![SharedDirectoryRootUpdate::Object {
            path: shared_root.display().to_string(),
        }],
        confirm_replace_roots: true,
    })
    .await
    .unwrap();
    wait_for_shared_file_names(
        &core,
        vec![
            "change-mtime.bin".to_string(),
            "change-size.bin".to_string(),
            "keep-unchanged.bin".to_string(),
        ],
    )
    .await;

    // (1) A reload over the fully-unchanged library re-hashes NOTHING.
    let queued = core.reload_shared_directories_detached().await.unwrap();
    assert_eq!(
        queued, 0,
        "detached reload returns before scan/planning knows the queued hash count"
    );
    wait_for_shared_file_count(&core, 3).await;

    // Mutate two files: one keeps its size but gets a new mtime, the other grows.
    // `keep-unchanged.bin` is left exactly as is.
    let mtime_target = shared_root.join("change-mtime.bin");
    let bumped = SystemTime::now() + std::time::Duration::from_secs(120);
    fs::OpenOptions::new()
        .write(true)
        .open(&mtime_target)
        .unwrap()
        .set_modified(bumped)
        .unwrap();
    fs::write(
        shared_root.join("change-size.bin"),
        b"size payload three -- now noticeably longer than before",
    )
    .unwrap();

    // (2)+(3) Exactly the two mutated files are re-queued; the unchanged file is
    // skipped. (A changed mtime and a changed size are both detected.)
    let queued = core.reload_shared_directories_detached().await.unwrap();
    assert_eq!(
        queued, 0,
        "detached reload returns before scan/planning knows the queued hash count",
    );
    wait_for_shared_file_count(&core, 3).await;

    // Add a brand-new file: a follow-up reload queues exactly that one file.
    fs::write(shared_root.join("brand-new.bin"), b"freshly added payload").unwrap();
    let queued = core.reload_shared_directories_detached().await.unwrap();
    assert_eq!(
        queued, 0,
        "detached reload returns before scan/planning knows the queued hash count",
    );
    wait_for_shared_file_count(&core, 4).await;

    // The library now lists all four files, and a final unchanged reload is a
    // pure no-op again (the re-hashed/added files recorded their new mtimes).
    wait_for_shared_file_names(
        &core,
        vec![
            "brand-new.bin".to_string(),
            "change-mtime.bin".to_string(),
            "change-size.bin".to_string(),
            "keep-unchanged.bin".to_string(),
        ],
    )
    .await;
    let queued = core.reload_shared_directories_detached().await.unwrap();
    assert_eq!(
        queued, 0,
        "detached reload returns before scan/planning knows the queued hash count",
    );
}

/// Poll until the live `hashingCount` reaches 0 (the background reload worker has
/// finished the whole library), or panic after a generous timeout.
async fn wait_for_hashing_idle(core: &EmulebbCore) {
    for _ in 0..600 {
        if core.shared_directories().await.hashing_count == 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("background shared-directory hashing did not finish in time");
}

async fn wait_for_shared_file_count(core: &EmulebbCore, count: usize) {
    for _ in 0..600 {
        if core.shares().await.len() >= count {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("shared file count did not reach {count} in time");
}

async fn wait_for_shared_file_names(core: &EmulebbCore, expected: Vec<String>) {
    let mut last_seen = Vec::new();
    for _ in 0..600 {
        let names = shared_file_names(core.shares().await);
        if names == expected {
            return;
        }
        last_seen = names;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!(
        "shared file names did not settle to expected set: expected {expected:?}, last seen {last_seen:?}"
    );
}

async fn wait_for_reload_reuse_count(core: &EmulebbCore, count: usize) {
    for _ in 0..600 {
        let reload = core.shared_directories().await.reload_progress;
        if reload.phase == "idle" && reload.reused_count >= count {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("shared-directory reload progress did not report {count} reused files");
}

fn shared_file_names(shares: Vec<emulebb_core::LocalShare>) -> Vec<String> {
    let mut names = shares
        .into_iter()
        .map(|share| share.name)
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn require_share_by_name(shares: &[LocalShare], name: &str) -> LocalShare {
    shares
        .iter()
        .find(|share| share.name == name)
        .cloned()
        .unwrap_or_else(|| panic!("shared directory reload did not publish {name}"))
}

/// A shared, already-complete file is seeded IN PLACE: the daemon must never
/// copy its payload into the internal piece store (`transfer_dir/pieces.bin`).
/// The transfer dir still exists (it holds the resume manifest), but the bulky
/// payload bytes are never duplicated there.
fn assert_no_piece_store_copy(share: &LocalShare) {
    let transfer_dir = PathBuf::from(&share.transfer_dir);
    assert!(transfer_dir.is_dir(), "transfer dir must hold the manifest");
    let piece_store = transfer_dir.join("pieces.bin");
    assert!(
        !piece_store.exists(),
        "shared complete file must NOT be copied into the piece store ({})",
        piece_store.display(),
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
