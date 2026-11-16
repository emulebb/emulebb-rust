use super::*;
use emulebb_metadata::{DownloadIntent, DownloadJobRequest, MetadataLocalContentChoiceRequired};

fn request(hash: &str) -> DownloadJobRequest {
    DownloadJobRequest {
        file_hash: hash.into(),
        display_name: "sample.bin".into(),
        expected_size_bytes: Some(8),
        category_id: None,
        intent: DownloadIntent::Started,
        piece_size: transfer::ED2K_PART_SIZE,
    }
}
async fn fixture() -> (
    tempfile::TempDir,
    transfer::Ed2kTransferRuntime,
    std::path::PathBuf,
    String,
) {
    let root = tempfile::tempdir().unwrap();
    let runtime = transfer::Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let shared = root.path().join("library");
    std::fs::create_dir(&shared).unwrap();
    let path = shared.join("sample.bin");
    std::fs::write(&path, b"12345678").unwrap();
    let summary = runtime
        .ingest_local_file(&path, "sample.bin")
        .await
        .unwrap();
    transfer::test_support::admit_local_share(&runtime, &shared, &path).await;
    (root, runtime, path, summary.file_hash)
}
fn choice(error: anyhow::Error, expected: Availability) {
    assert_eq!(
        error
            .downcast_ref::<MetadataLocalContentChoiceRequired>()
            .unwrap()
            .0,
        expected
    );
}

#[tokio::test]
async fn present_requires_choice_and_active_redownload_is_unchanged() {
    let (_root, runtime, _path, hash) = fixture().await;
    choice(
        runtime
            .admit_download_job(&request(&hash), false, None)
            .await
            .unwrap_err(),
        Availability::Present,
    );
    let admitted = runtime
        .admit_download_job(&request(&hash), true, None)
        .await
        .unwrap();
    assert!(admitted.created);
    let saved = admitted.job.clone();
    drop(admitted);
    let mut changed = request(&hash);
    changed.display_name = "different.bin".into();
    changed.intent = DownloadIntent::Stopped;
    let duplicate = runtime
        .admit_download_job(&changed, true, None)
        .await
        .unwrap();
    assert!(!duplicate.created);
    assert_eq!(duplicate.job, saved);
    drop(duplicate);
    changed.expected_size_bytes = Some(9);
    assert!(
        runtime
            .admit_download_job(&changed, true, None)
            .await
            .unwrap_err()
            .is::<emulebb_metadata::MetadataContentConflict>()
    );
    assert!(
        runtime
            .admit_download_job(&request(&hash), true, Some(&"11".repeat(20)))
            .await
            .unwrap_err()
            .is::<emulebb_metadata::MetadataContentConflict>()
    );
}

#[tokio::test]
async fn leaf_absence_admits_but_missing_root_and_changed_fingerprint_require_choice() {
    let (_root, runtime, path, hash) = fixture().await;
    std::fs::write(&path, b"87654321").unwrap();
    choice(
        runtime
            .admit_download_job(&request(&hash), false, None)
            .await
            .unwrap_err(),
        Availability::Unavailable,
    );
    std::fs::remove_file(&path).unwrap();
    let parent = path.parent().unwrap();
    let moved = parent.with_file_name("disconnected");
    std::fs::rename(parent, &moved).unwrap();
    choice(
        runtime
            .admit_download_job(&request(&hash), false, None)
            .await
            .unwrap_err(),
        Availability::Unavailable,
    );
    std::fs::rename(moved, parent).unwrap();
    let admitted = runtime
        .admit_download_job(&request(&hash), false, None)
        .await
        .unwrap();
    assert!(admitted.created);
}

#[tokio::test]
async fn offline_root_is_not_hidden_and_another_present_copy_wins() {
    let (root, runtime, path, hash) = fixture().await;
    runtime
        .metadata
        .clone()
        .replace_shared_directory_roots(&[emulebb_metadata::MetadataSharedDirectoryRoot {
            path: path.parent().unwrap().to_string_lossy().into_owned(),
            monitor_owned: false,
            shareable: true,
            accessible: false,
        }])
        .unwrap();
    choice(
        runtime
            .admit_download_job(&request(&hash), false, None)
            .await
            .unwrap_err(),
        Availability::Unavailable,
    );
    let second = root.path().join("second.bin");
    std::fs::write(&second, b"12345678").unwrap();
    runtime
        .ingest_local_file(&second, "second.bin")
        .await
        .unwrap();
    let evidence = runtime.download_evidence(&hash).await.unwrap();
    assert_eq!(evidence.availability, Availability::Present);
    assert_eq!(
        evidence.present_file.as_ref().unwrap().path,
        emulebb_metadata::NativePath::from(crate::long_path::long_path(&second).as_path())
            .display_path()
    );
}

#[cfg(windows)]
#[tokio::test]
async fn native_sharing_denial_is_unavailable() {
    use std::os::windows::fs::OpenOptionsExt;
    let (_root, runtime, path, hash) = fixture().await;
    let _exclusive = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    choice(
        runtime
            .admit_download_job(&request(&hash), false, None)
            .await
            .unwrap_err(),
        Availability::Unavailable,
    );
}

#[tokio::test]
async fn history_work_budget_does_not_become_absence() {
    let root = tempfile::tempdir().unwrap();
    let runtime = transfer::Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let input = request(&"42".repeat(16));
    for _ in 0..MAX_STEPS {
        let job = runtime.metadata.admit_download_job(&input).unwrap().job;
        runtime
            .metadata
            .remove_download_job(job.token.job_id)
            .unwrap();
    }
    choice(
        runtime
            .admit_download_job(&input, false, None)
            .await
            .unwrap_err(),
        Availability::Unavailable,
    );
    assert!(
        runtime
            .admit_download_job(&input, true, None)
            .await
            .unwrap()
            .created
    );
}

#[tokio::test]
async fn content_or_root_change_after_probe_refuses_without_creating() {
    for change_root in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let runtime = Arc::new(transfer::Ed2kTransferRuntime::load_or_create(root.path()).unwrap());
        let hash = "43".repeat(16);
        let capacity = Arc::clone(&runtime.local_mutations.state.lock().unwrap().capacity);
        let (reached, ready) = oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        capacity.install_probe_gate(reached, gate);
        let worker = Arc::clone(&runtime);
        let input = request(&hash);
        let task =
            tokio::spawn(async move { worker.admit_download_job(&input, false, None).await });
        ready.await.unwrap();
        if change_root {
            runtime
                .category_root_epoch
                .fetch_add(2, std::sync::atomic::Ordering::AcqRel);
        } else {
            runtime
                .metadata
                .admit_download_job(&request(&"44".repeat(16)))
                .unwrap();
        }
        release.send(()).unwrap();
        assert!(matches!(
            task.await
                .unwrap()
                .unwrap_err()
                .downcast_ref::<LocalMutationError>(),
            Some(LocalMutationError::Busy)
        ));
        assert!(
            runtime
                .metadata
                .active_download_job(&hash)
                .unwrap()
                .is_none()
        );
        runtime.local_mutations.seal_and_drain().await.unwrap();
    }
}

#[tokio::test]
async fn cancelled_native_admission_and_drain_keep_probe_owned() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Arc::new(transfer::Ed2kTransferRuntime::load_or_create(root.path()).unwrap());
    let registry = Arc::clone(&runtime.local_mutations);
    let capacity = Arc::clone(&registry.state.lock().unwrap().capacity);
    let (reached, ready) = oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    capacity.install_probe_gate(reached, gate);
    let worker = Arc::clone(&runtime);
    let caller = tokio::spawn(async move {
        worker
            .admit_download_job(&request(&"45".repeat(16)), false, None)
            .await
    });
    ready.await.unwrap();
    caller.abort();
    let _ = caller.await;
    assert_eq!(capacity.usage().long_fs_units, 1);
    assert_eq!(capacity.usage().long_fs_bytes, WORKSPACE);
    let owner = Arc::clone(&registry);
    let drain = tokio::spawn(async move { owner.seal_and_drain().await });
    tokio::task::yield_now().await;
    drain.abort();
    let _ = drain.await;
    assert_eq!(capacity.usage().long_fs_units, 1);
    release.send(()).unwrap();
    registry.seal_and_drain().await.unwrap();
    assert!(
        runtime
            .metadata
            .active_download_job(&"45".repeat(16))
            .unwrap()
            .is_some()
    );
    assert_eq!(capacity.usage().bytes, 0);
}

#[tokio::test]
async fn physical_reappearance_after_probe_does_not_admit_from_stale_absence() {
    let (_root, runtime, path, hash) = fixture().await;
    std::fs::remove_file(&path).unwrap();
    let runtime = Arc::new(runtime);
    let capacity = Arc::clone(&runtime.local_mutations.state.lock().unwrap().capacity);
    let (reached, ready) = oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    capacity.install_probe_gate(reached, gate);
    let worker = Arc::clone(&runtime);
    let input = request(&hash);
    let caller = tokio::spawn(async move { worker.admit_download_job(&input, false, None).await });
    ready.await.unwrap();
    // No SQLite/root epoch update accompanies this external filesystem change.
    std::fs::write(&path, b"87654321").unwrap();
    release.send(()).unwrap();
    choice(
        caller.await.unwrap().unwrap_err(),
        Availability::Unavailable,
    );
    assert!(
        runtime
            .metadata
            .active_download_job(&hash)
            .unwrap()
            .is_none()
    );
    runtime.local_mutations.seal_and_drain().await.unwrap();
    assert_eq!(capacity.usage().bytes, 0);
}

#[tokio::test]
async fn publication_capacity_contention_refuses_before_creating() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Arc::new(transfer::Ed2kTransferRuntime::load_or_create(root.path()).unwrap());
    let capacity = Arc::clone(&runtime.local_mutations.state.lock().unwrap().capacity);
    let (reached, ready) = oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    capacity.install_probe_gate(reached, gate);
    let worker = Arc::clone(&runtime);
    let hash = "46".repeat(16);
    let input = request(&hash);
    let caller = tokio::spawn(async move { worker.admit_download_job(&input, false, None).await });
    ready.await.unwrap();
    let held = capacity.reserve(4 * 1024 * 1024, false, false).unwrap();
    let backing = vec![0u8; 4 * 1024 * 1024];
    release.send(()).unwrap();
    assert!(matches!(
        caller
            .await
            .unwrap()
            .unwrap_err()
            .downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Busy)
    ));
    assert!(
        runtime
            .metadata
            .active_download_job(&hash)
            .unwrap()
            .is_none()
    );
    drop(backing);
    drop(held);
    runtime.local_mutations.seal_and_drain().await.unwrap();
    assert_eq!(capacity.usage().bytes, 0);
}
