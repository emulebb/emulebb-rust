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
                recursive: true,
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
    assert!(directories.roots[0].recursive);
}

#[tokio::test]
async fn shared_directory_reload_honors_recursive_flag() {
    let runtime_dir = unique_test_dir("shared-directory-recursive");
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
            recursive: false,
        }],
        confirm_replace_roots: true,
    })
    .await
    .unwrap();

    let flat_names = shared_file_names(core.reload_shared_directories().await.unwrap());
    assert_eq!(flat_names, vec!["top.bin"]);

    core.set_shared_directories(SharedDirectoriesUpdate {
        roots: vec![SharedDirectoryRootUpdate::Object {
            path: shared_root.display().to_string(),
            recursive: true,
        }],
        confirm_replace_roots: true,
    })
    .await
    .unwrap();

    let recursive_names = shared_file_names(core.reload_shared_directories().await.unwrap());
    assert_eq!(recursive_names, vec!["nested.bin", "top.bin"]);
}

#[tokio::test]
async fn shared_directory_tree_shares_survive_restart_and_reload_new_files() {
    let runtime_dir = unique_test_dir("shared-directory-tree-restart");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let shared_root = runtime_dir.join("shared-root");
    let nested_root = shared_root.join("nested").join("unicode");
    fs::create_dir_all(&nested_root).unwrap();
    let first_payload = b"first recursive shared payload";
    let second_payload = b"second recursive shared payload";
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
                recursive: true,
            }],
            confirm_replace_roots: true,
        })
        .await
        .unwrap();
        let shares = core.reload_shared_directories().await.unwrap();
        let first_share = require_share_by_name(&shares, "Persisted Unicode äöü.bin");
        assert_eq!(
            fs::read(share_payload_path(&first_share)).unwrap(),
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
    assert_eq!(
        fs::read(share_payload_path(&existing_first_share)).unwrap(),
        first_payload
    );

    let reloaded_shares = reloaded.reload_shared_directories().await.unwrap();
    assert_eq!(
        shared_file_names(reloaded_shares.clone()),
        vec!["Persisted Unicode äöü.bin", "Reloaded Tree Payload.bin"]
    );
    assert_eq!(
        fs::read(share_payload_path(&require_share_by_name(
            &reloaded_shares,
            "Reloaded Tree Payload.bin"
        )))
        .unwrap(),
        second_payload
    );
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

fn share_payload_path(share: &LocalShare) -> PathBuf {
    let path = PathBuf::from(&share.transfer_dir);
    assert!(path.is_dir());
    path.join("pieces.bin")
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
