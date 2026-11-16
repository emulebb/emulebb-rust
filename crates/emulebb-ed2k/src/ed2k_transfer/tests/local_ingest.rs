//! Real retained hash/binding work, including cancellation and two identities.
use super::super::*;
use emulebb_metadata::{MetadataIngestRoot, MetadataSharedDirectoryRoot};
use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

fn runtime(label: &str) -> (Arc<Ed2kTransferRuntime>, PathBuf) {
    let profile = crate::paths::unique_test_dir(label);
    let root = profile.join("library");
    fs::create_dir_all(&root).unwrap();
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&profile).unwrap());
    runtime
        .metadata
        .clone()
        .replace_shared_directory_roots(&[MetadataSharedDirectoryRoot {
            path: root.to_string_lossy().into_owned(),
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    (runtime, root)
}

async fn share(
    runtime: &Ed2kTransferRuntime,
    root: &Path,
    name: &str,
) -> Result<Ed2kLocalIngestSummary> {
    runtime
        .ingest_local_file_owned(
            &root.join(name),
            name,
            None,
            LocalIngestOptions {
                roots: &[MetadataIngestRoot {
                    root: root.to_path_buf(),
                    relative: name.into(),
                }],
                index_type: Some("unknown"),
            },
        )
        .await
}

fn hash_gate() -> (
    LocalIngestProgressObserver,
    tokio::sync::oneshot::Receiver<()>,
    std::sync::mpsc::Sender<()>,
) {
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    let state = Mutex::new(Some((started, gate)));
    let observer = Arc::new(move |_: LocalIngestProgressEvent| {
        if let Some((started, gate)) = state.lock().unwrap().take() {
            let _ = started.send(());
            gate.recv().unwrap();
        }
    });
    (observer, ready, release)
}

async fn reached(ready: tokio::sync::oneshot::Receiver<()>) {
    tokio::time::timeout(Duration::from_secs(10), ready)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn cancelled_hash_and_cancelled_drain_retain_actual_ingest_until_publication() {
    let (runtime, root) = runtime("owned-ingest-cancel-hash");
    let path = root.join("sample.bin");
    fs::write(&path, b"retained actual hash bytes").unwrap();
    let (observer, ready, release) = hash_gate();
    let caller = {
        let runtime = Arc::clone(&runtime);
        let path = path.clone();
        tokio::spawn(async move {
            runtime
                .ingest_local_file_with_progress(&path, "sample.bin", observer)
                .await
        })
    };
    reached(ready).await;
    caller.abort();
    let _ = caller.await;
    let pending = runtime.local_mutations.signal_next_pending_drain();
    let drain = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { runtime.drain_local_mutations().await })
    };
    reached(pending).await;
    drain.abort();
    let _ = drain.await;
    let normalized = crate::long_path::long_path(&path);
    assert!(
        runtime
            .metadata
            .local_file_instance(&normalized)
            .unwrap()
            .is_none()
    );
    release.send(()).unwrap();
    runtime.drain_local_mutations().await.unwrap();
    assert!(
        runtime
            .metadata
            .local_file_instance(&normalized)
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        runtime
            .ingest_local_file(&path, "sample.bin")
            .await
            .unwrap_err()
            .downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Closing)
    ));
}

#[tokio::test]
async fn held_preparation_leaves_ordinary_mutations_available_and_second_ingest_waits() {
    let (runtime, root) = runtime("owned-ingest-capacity");
    fs::write(root.join("old.bin"), b"independent old content").unwrap();
    let old = share(&runtime, &root, "old.bin").await.unwrap();
    let first_path = root.join("first.bin");
    let second_path = root.join("second.bin");
    fs::write(&first_path, b"first prepared payload").unwrap();
    fs::write(&second_path, b"second prepared payload").unwrap();
    let (observer, ready, release) = hash_gate();
    let first = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            runtime
                .ingest_local_file_with_progress(&first_path, "first.bin", observer)
                .await
        })
    };
    reached(ready).await;
    // This needs the ordinary 4 MiB workspace while the hash still owns its
    // preparation lease. Double-charging ingest would make this time out.
    tokio::time::timeout(
        Duration::from_secs(5),
        runtime.withdraw_monitored_shared_path(
            &old.file_hash,
            &crate::long_path::long_path(&root.join("old.bin")),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let waiting = runtime.local_mutations.signal_next_pending_wait();
    let second = {
        let runtime = Arc::clone(&runtime);
        let path = second_path.clone();
        tokio::spawn(async move { runtime.ingest_local_file(&path, "second.bin").await })
    };
    reached(waiting).await;
    assert!(!second.is_finished());
    assert!(
        runtime
            .metadata
            .local_file_instance(&crate::long_path::long_path(&second_path))
            .unwrap()
            .is_none()
    );
    release.send(()).unwrap();
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();
    runtime.drain_local_mutations().await.unwrap();
}

#[tokio::test]
async fn cancelled_committed_ingest_finishes_index_membership_and_catalog() {
    let (runtime, root) = runtime("owned-ingest-cancel-commit");
    fs::write(root.join("sample.bin"), b"committed ingest sample").unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(started, gate);
    let caller = {
        let runtime = Arc::clone(&runtime);
        let root = root.clone();
        tokio::spawn(async move { share(&runtime, &root, "sample.bin").await })
    };
    reached(ready).await;
    let instance = runtime
        .metadata
        .local_file_instance(&crate::long_path::long_path(&root.join("sample.bin")))
        .unwrap()
        .unwrap();
    let hash = instance.file_hash.parse().unwrap();
    assert!(
        runtime
            .metadata
            .find_indexed_file_by_hash(&instance.file_hash)
            .unwrap()
            .is_some()
    );
    assert!(
        runtime
            .metadata
            .next_shared_copy(&instance.file_hash, 0, 65_536)
            .unwrap()
            .is_some()
    );
    assert!(
        runtime
            .shared_catalog
            .read()
            .await
            .entry_by_hash(&hash)
            .is_none()
    );
    caller.abort();
    let _ = caller.await;
    release.send(()).unwrap();
    runtime.drain_local_mutations().await.unwrap();
    assert!(
        runtime
            .shared_catalog
            .read()
            .await
            .entry_by_hash(&hash)
            .unwrap()
            .verified_complete
    );
}

#[tokio::test]
async fn same_path_rebind_preserves_independent_complete_copy_and_live_partial_progress() {
    for keep_sibling in [false, true] {
        let (runtime, root) = runtime(if keep_sibling {
            "owned-rebind-sibling"
        } else {
            "owned-rebind-partial"
        });
        fs::write(root.join("changing.bin"), b"original content sample").unwrap();
        let old = share(&runtime, &root, "changing.bin").await.unwrap();
        if keep_sibling {
            fs::write(root.join("sibling.bin"), b"original content sample").unwrap();
            share(&runtime, &root, "sibling.bin").await.unwrap();
        }
        let old_hash = old.file_hash.parse().unwrap();
        let job = new_transfer_job(old_hash, "partial.bin".into(), old.file_size);
        let mut manifest = Ed2kResumeManifest::new(&job);
        manifest.md4_hashset_acquired = true;
        manifest.verified_ranges = vec![Ed2kSharedRange { start: 0, end: 4 }];
        runtime
            .manifest_cache
            .lock()
            .await
            .insert(old.file_hash.clone(), manifest.clone());
        {
            let mut catalog = runtime.shared_catalog.write().await;
            let mut entry = catalog.entry_by_hash(&old_hash).unwrap().clone();
            entry.publish.session_request_count = 17;
            entry.all_time_uploaded_bytes = 31;
            catalog.upsert_verified(old_hash, Some(entry));
        }
        fs::write(root.join("changing.bin"), b"different new local content").unwrap();
        let new = share(&runtime, &root, "changing.bin").await.unwrap();
        assert_ne!(old.file_hash, new.file_hash);
        let catalog = runtime.shared_catalog.read().await;
        let old_entry = catalog.entry_by_hash(&old_hash).unwrap();
        assert_eq!(old_entry.verified_complete, keep_sibling);
        if !keep_sibling {
            assert_eq!(old_entry.verified_ranges, manifest.verified_ranges);
        }
        assert_eq!(old_entry.publish.session_request_count, 17);
        assert_eq!(old_entry.all_time_uploaded_bytes, 31);
        assert!(
            catalog
                .entry_by_hash(&new.file_hash.parse().unwrap())
                .unwrap()
                .verified_complete
        );
        drop(catalog);
        assert_eq!(
            runtime.manifest_cache.lock().await[&old.file_hash].verified_ranges,
            manifest.verified_ranges
        );
        runtime.drain_local_mutations().await.unwrap();
    }
}

#[tokio::test]
async fn root_change_after_ingest_commit_reprojects_without_replaying_binding() {
    let (runtime, root) = runtime("owned-ingest-root-retry");
    fs::write(root.join("sample.bin"), b"root overlap sample").unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(started, gate);
    let caller = {
        let runtime = Arc::clone(&runtime);
        let root = root.clone();
        tokio::spawn(async move { share(&runtime, &root, "sample.bin").await })
    };
    reached(ready).await;
    let mutation = runtime.begin_category_root_mutation().await.unwrap();
    runtime
        .metadata
        .set_shared_root_accessible(&root, false)
        .unwrap();
    drop(mutation);
    release.send(()).unwrap();
    let summary = caller.await.unwrap().unwrap();
    assert!(
        runtime
            .shared_catalog
            .read()
            .await
            .entry_by_hash(&summary.file_hash.parse().unwrap())
            .is_none()
    );
    assert!(
        runtime
            .metadata
            .find_indexed_file_by_hash(&summary.file_hash)
            .unwrap()
            .is_some()
    );
    runtime.drain_local_mutations().await.unwrap();
}

#[tokio::test]
async fn unrelated_root_epoch_during_hash_does_not_discard_prepared_bytes() {
    let (runtime, root) = runtime("owned-ingest-long-preparation-epoch");
    let path = root.join("sample.bin");
    fs::write(&path, b"prepared across unrelated root mutation").unwrap();
    let (observer, ready, release) = hash_gate();
    let caller = {
        let runtime = Arc::clone(&runtime);
        let root = root.clone();
        tokio::spawn(async move {
            runtime
                .ingest_local_file_owned(
                    &path,
                    "sample.bin",
                    Some(observer),
                    LocalIngestOptions {
                        roots: &[MetadataIngestRoot {
                            root,
                            relative: "sample.bin".into(),
                        }],
                        index_type: Some("unknown"),
                    },
                )
                .await
        })
    };
    reached(ready).await;
    let previous = runtime.root_observation_epoch().await;
    let mutation = runtime.begin_category_root_mutation().await.unwrap();
    drop(mutation);
    assert_ne!(runtime.root_observation_epoch().await, previous);
    release.send(()).unwrap();
    let summary = caller.await.unwrap().unwrap();
    assert!(
        runtime
            .shared_catalog
            .read()
            .await
            .entry_by_hash(&summary.file_hash.parse().unwrap())
            .unwrap()
            .verified_complete
    );
    runtime.drain_local_mutations().await.unwrap();
}

#[tokio::test]
async fn oversized_sparse_source_is_rejected_before_hashing_and_releases_preparation() {
    let (runtime, root) = runtime("owned-ingest-oversized-sparse");
    let path = root.join("oversized.bin");
    let file = fs::File::create(&path).unwrap();
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let mut returned = 0u32;
        // SAFETY: the owned file handle remains valid through this synchronous
        // call. Null input requests sparse=true; no output/overlapped buffer is
        // used. Never extend the file until sparse marking has succeeded.
        let sparse = unsafe {
            windows_sys::Win32::System::IO::DeviceIoControl(
                file.as_raw_handle(),
                windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(
            sparse,
            0,
            "failed to mark fixture sparse: {}",
            std::io::Error::last_os_error()
        );
    }
    file.set_len(0x4000000001).unwrap();
    drop(file);
    let callbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observer_count = Arc::clone(&callbacks);
    let observer = Arc::new(move |_: LocalIngestProgressEvent| {
        observer_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // A regressed size guard must fail promptly, not leave a 256 GiB
        // blocking read running after the test's timeout.
        panic!("oversized fixture reached the first hash read");
    });
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        runtime.ingest_local_file_with_progress(&path, "oversized.bin", observer),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        error.to_string().contains("supported 256 GiB size"),
        "{error:#}"
    );
    assert_eq!(callbacks.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(
        runtime
            .metadata
            .local_file_instance(&crate::long_path::long_path(&path))
            .unwrap()
            .is_none()
    );
    fs::remove_file(&path).unwrap();
    fs::write(root.join("small.bin"), b"preparation lease is reusable").unwrap();
    share(&runtime, &root, "small.bin").await.unwrap();
    runtime.drain_local_mutations().await.unwrap();
}
