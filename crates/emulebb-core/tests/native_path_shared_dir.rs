#![cfg(unix)]

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use emulebb_core::{EmulebbCore, SharedDirectoriesUpdate, SharedDirectoryRootUpdate};
use emulebb_index::FileIndex;
use emulebb_metadata::NativePath;

#[tokio::test]
async fn non_utf8_shared_path_survives_restart_rename_and_delete() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let runtime_dir = unique_test_dir("non-utf8-shared-path");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let shared_root = runtime_dir.join("shared-root");
    fs::create_dir_all(&shared_root).unwrap();
    let source_path = shared_root.join(OsString::from_vec(b"native-\xff.bin".to_vec()));
    let payload = b"non-UTF-8 native path payload";
    if let Err(error) = fs::write(&source_path, payload) {
        eprintln!("skipping non-UTF-8 path test: filesystem rejected name: {error}");
        let _ = fs::remove_dir_all(&runtime_dir);
        return;
    }

    let first_hash = {
        let core = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap();
        core.set_shared_directories(SharedDirectoriesUpdate {
            roots: vec![SharedDirectoryRootUpdate {
                path: shared_root.display().to_string(),
            }],
            confirm_replace_roots: true,
        })
        .await
        .unwrap();
        core.stop_shared_directory_monitor();

        let shares = core.reload_shared_directories().await.unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, r"native-\xFF.bin");
        let expected_source_path = NativePath::from(source_path.as_path()).display_path();
        assert_eq!(
            shares[0].source_path.as_deref(),
            Some(expected_source_path.as_str()),
        );
        assert_eq!(
            core.shared_directories()
                .await
                .reload_progress
                .escaped_display_path_count,
            1,
        );
        shares[0].hash.clone()
    };

    let renamed_path = shared_root.join(OsString::from_vec(b"renamed-\xfe.bin".to_vec()));
    fs::rename(&source_path, &renamed_path).unwrap();

    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let shares = core.reload_shared_directories().await.unwrap();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].hash, first_hash);
    assert_eq!(shares[0].name, r"renamed-\xFE.bin");

    fs::remove_file(&renamed_path).unwrap();
    assert!(core.reload_shared_directories().await.unwrap().is_empty());
    assert!(core.shares().await.is_empty());

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
