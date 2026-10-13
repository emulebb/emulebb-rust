#![cfg(any(windows, target_os = "macos"))]

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(windows)]
use std::path::Path;

use emulebb_core::EmulebbCore;
#[cfg(target_os = "macos")]
use emulebb_core::LocalShareCreate;
#[cfg(windows)]
use emulebb_core::{SharedDirectoriesUpdate, SharedDirectoryRootUpdate};
use emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime;
use emulebb_index::FileIndex;

#[cfg(windows)]
#[tokio::test]
async fn case_sensitive_windows_directory_preserves_case_variant_files() {
    use std::io::Write;

    let runtime_dir = unique_test_dir("windows-case-sensitive-paths");
    let shared_root = runtime_dir.join("shared-root");
    fs::create_dir_all(&shared_root).unwrap();
    if !enable_windows_case_sensitive_directory(&shared_root) {
        eprintln!("skipping Windows case-sensitive path test: volume capability unavailable");
        let _ = fs::remove_dir_all(&runtime_dir);
        return;
    }

    let upper_path = shared_root.join("Case.bin");
    let lower_path = shared_root.join("case.bin");
    fs::write(&upper_path, b"UPPER").unwrap();
    let mut lower_file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lower_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            eprintln!(
                "skipping Windows case-sensitive path test: directory remained case-insensitive"
            );
            let _ = fs::remove_dir_all(&runtime_dir);
            return;
        }
        Err(error) => panic!("create case-variant file: {error}"),
    };
    lower_file.write_all(b"lower").unwrap();
    drop(lower_file);
    let upper_fingerprint = Ed2kTransferRuntime::scanned_source_identity(&upper_path)
        .unwrap()
        .2
        .unwrap();
    let lower_fingerprint = Ed2kTransferRuntime::scanned_source_identity(&lower_path)
        .unwrap()
        .2
        .unwrap();
    assert_ne!(upper_fingerprint.identity, lower_fingerprint.identity);

    let core = EmulebbCore::new(
        "test",
        FileIndex::open(runtime_dir.join("metadata.sqlite")).unwrap(),
        runtime_dir.join("transfers"),
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

    let mut shares = core.reload_shared_directories().await.unwrap();
    shares.sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(
        shares
            .iter()
            .map(|share| share.name.as_str())
            .collect::<Vec<_>>(),
        vec!["Case.bin", "case.bin"],
    );
    assert_ne!(shares[0].hash, shares[1].hash);

    let _ = fs::remove_dir_all(&runtime_dir);
}

#[cfg(windows)]
fn enable_windows_case_sensitive_directory(path: &Path) -> bool {
    use std::{mem::size_of, os::windows::fs::OpenOptionsExt, os::windows::io::AsRawHandle};
    use windows_sys::Win32::{
        Storage::FileSystem::{
            FILE_CASE_SENSITIVE_INFO, FILE_FLAG_BACKUP_SEMANTICS, FileCaseSensitiveInfo,
            SetFileInformationByHandle,
        },
        System::SystemServices::FILE_CS_FLAG_CASE_SENSITIVE_DIR,
    };

    let directory = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
    {
        Ok(directory) => directory,
        Err(error) => {
            eprintln!("open case-sensitive test directory: {error}");
            return false;
        }
    };
    let info = FILE_CASE_SENSITIVE_INFO {
        Flags: FILE_CS_FLAG_CASE_SENSITIVE_DIR,
    };
    // SAFETY: `directory` remains open for the call and `info` points to the
    // exact structure required by `FileCaseSensitiveInfo`.
    let changed = unsafe {
        SetFileInformationByHandle(
            directory.as_raw_handle(),
            FileCaseSensitiveInfo,
            std::ptr::from_ref(&info).cast(),
            size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    };
    if changed == 0 {
        eprintln!(
            "enable case-sensitive directory: {}",
            std::io::Error::last_os_error()
        );
    }
    changed != 0
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn case_insensitive_macos_alias_keeps_one_native_file_identity() {
    let runtime_dir = unique_test_dir("macos-case-insensitive-alias");
    let source_dir = runtime_dir.join("library");
    fs::create_dir_all(&source_dir).unwrap();
    let upper_path = source_dir.join("Case.bin");
    let lower_alias = source_dir.join("case.bin");
    fs::write(&upper_path, b"case-insensitive alias payload").unwrap();
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lower_alias)
    {
        Ok(_) => {
            eprintln!("skipping macOS case-insensitive alias test: volume is case-sensitive");
            let _ = fs::remove_dir_all(&runtime_dir);
            return;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => panic!("probe macOS case-insensitive volume: {error}"),
    }
    let upper_fingerprint = Ed2kTransferRuntime::scanned_source_identity(&upper_path)
        .unwrap()
        .2
        .unwrap();
    let alias_fingerprint = Ed2kTransferRuntime::scanned_source_identity(&lower_alias)
        .unwrap()
        .2
        .unwrap();
    assert_eq!(upper_fingerprint.identity, alias_fingerprint.identity);
    assert!(upper_fingerprint.safely_matches(&alias_fingerprint));

    let metadata_path = runtime_dir.join("metadata.sqlite");
    let transfer_root = runtime_dir.join("transfers");
    let first_hash = {
        let core = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap();
        let first = core
            .share_local_file(LocalShareCreate {
                path: upper_path.display().to_string(),
                name: Some("Case.bin".to_string()),
            })
            .await
            .unwrap();
        let alias = core
            .share_local_file(LocalShareCreate {
                path: lower_alias.display().to_string(),
                name: Some("Case.bin".to_string()),
            })
            .await
            .unwrap();
        assert_eq!(alias.hash, first.hash);
        assert_eq!(core.shares().await.len(), 1);
        first.hash
    };

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    reloaded.hydrate_shared_catalog().await.unwrap();
    let shares = reloaded.shares().await;
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].hash, first_hash);

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
