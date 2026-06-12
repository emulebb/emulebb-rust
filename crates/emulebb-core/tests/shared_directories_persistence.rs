use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use emulebb_core::{EmulebbCore, SharedDirectoriesUpdate, SharedDirectoryRootUpdate};
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
