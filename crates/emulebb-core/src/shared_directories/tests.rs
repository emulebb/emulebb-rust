use super::*;
use emulebb_index::FileIndex;
use emulebb_metadata::MetadataFileImportRecord;
use std::fs;
use std::sync::atomic::AtomicU64;

/// Allocate a unique scratch directory under the system temp root.
fn scratch_dir(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "emulebb-shared-scan-{label}-{}-{unique}",
        std::process::id(),
    ));
    fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

async fn configure_test_root(core: &EmulebbCore, root: &Path) {
    let path = root.display().to_string();
    core.state.lock().await.shared_directories = vec![SharedDirectoryRoot {
        path: path.clone(),
        watch_enabled: false,
        monitor_owned: false,
        shareable: true,
        accessible: true,
    }];
    core.metadata_store
        .clone()
        .replace_shared_directory_roots(&[emulebb_metadata::MetadataSharedDirectoryRoot {
            path,
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
}

#[tokio::test]
async fn watched_child_keeps_its_policy_without_duplicate_hash_planning() {
    let parent = scratch_dir("watched-child");
    let child = parent.join("intake");
    fs::create_dir_all(&child).unwrap();
    fs::write(child.join("sample.bin"), b"one physical path").unwrap();
    for child_first in [false, true] {
        let mut roots = vec![
            emulebb_metadata::MetadataSharedDirectoryRoot {
                path: parent.display().to_string(),
                watch_enabled: false,
                monitor_owned: false,
                shareable: true,
                accessible: true,
            },
            emulebb_metadata::MetadataSharedDirectoryRoot {
                path: child.display().to_string(),
                watch_enabled: true,
                monitor_owned: false,
                shareable: true,
                accessible: true,
            },
        ];
        if child_first {
            roots.reverse();
        }
        let mut metadata = MetadataStore::in_memory().unwrap();
        metadata.replace_shared_directory_roots(&roots).unwrap();
        let retained = consolidate_shared_directory_roots(roots);
        assert_eq!(retained.len(), 2);
        assert_eq!(retained.iter().filter(|root| root.watch_enabled).count(), 1);
        let roots = retained
            .into_iter()
            .map(|root| SharedDirectoryRoot {
                path: root.path,
                watch_enabled: root.watch_enabled,
                monitor_owned: root.monitor_owned,
                shareable: root.shareable,
                accessible: root.accessible,
            })
            .collect();
        let scan = scan_shared_directory_roots(roots, SharedFileIgnorePolicy::default(), metadata)
            .await
            .unwrap();
        assert_eq!(scan.files.len(), 1);
        assert_eq!(scan.root_files.len(), 2);
        assert!(scan.root_files.iter().all(|root| root.files.len() == 1));
    }
    fs::remove_dir_all(parent).unwrap();
}

#[tokio::test]
async fn watch_only_update_does_not_reserve_a_library_scan() {
    let scratch = scratch_dir("watch-policy-only");
    let root = PathBuf::from(normal_path_display(fs::canonicalize(&scratch).unwrap()));
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    configure_test_root(&core, &root).await;
    let execution = core.shared_reload_gate.lock().await;
    let id = core.metadata_store.library_root_page(0, 100).unwrap().items[0].id;
    let result = core
        .patch_library_root_watch(id, true)
        .await
        .unwrap()
        .unwrap();
    assert!(result.watch_enabled);
    assert!(!core.shared_reload_running.load(Ordering::Acquire));
    assert!(!core.shared_reload_pending.load(Ordering::Acquire));
    drop(execution);
    core.drain_persistence().await.unwrap();
    fs::remove_dir_all(scratch).unwrap();
}

#[tokio::test]
async fn cancelled_direct_share_finishes_owned_index_membership_and_publication() {
    let root = scratch_dir("owned-direct-share-cancel");
    let source = root.join("sample.bin");
    fs::write(&source, b"owned Core share preparation").unwrap();
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    configure_test_root(&core, &root).await;
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    let gate = std::sync::Mutex::new(Some((started, gate)));
    let progress = Arc::new(move |_: LocalIngestProgressEvent| {
        if let Some((started, gate)) = gate.lock().unwrap().take() {
            let _ = started.send(());
            gate.recv().unwrap();
        }
    });
    // The public frontdoor delegates to this exact path; the observer only
    // holds an actual hash read so caller cancellation is deterministic.
    let caller = {
        let core = core.clone();
        let path = source.display().to_string();
        tokio::spawn(async move {
            core.share_local_file_inner(
                crate::LocalShareCreate { path, name: None },
                Some(progress),
            )
            .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), ready)
        .await
        .unwrap()
        .unwrap();
    caller.abort();
    let _ = caller.await;
    release.send(()).unwrap();
    core.drain_local_share_mutations().await.unwrap();
    let instance = core
        .metadata_store
        .local_file_instance(&long_path(&source))
        .unwrap()
        .unwrap();
    assert!(
        core.index
            .lock()
            .await
            .find_by_hash(&instance.file_hash)
            .unwrap()
            .is_some()
    );
    assert!(
        core.metadata_store
            .next_shared_copy(&instance.file_hash, 0, 65_536)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        core.share(&instance.file_hash).await.unwrap().hash,
        instance.file_hash
    );
    core.drain_persistence().await.unwrap();
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn reserved_partial_is_excluded_from_scan_and_direct_share() {
    let root = scratch_dir("reserved-partial");
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    configure_test_root(&core, &root).await;
    let partial = root.join("partial.bin");
    let other = root.join("complete.bin");
    fs::write(&other, b"complete bytes").unwrap();
    let summary = core
        .ed2k_transfers
        .ingest_local_file(&other, "complete.bin")
        .await
        .unwrap();
    let token = crate::tests::admit_scheduler_test_job(
        &core.ed2k_transfers,
        &core.transfer_root,
        summary.file_hash.parse().unwrap(),
        "complete.bin".into(),
        14,
    )
    .await;
    drop(
        core.ed2k_transfers
            .store_md4_hashset(token, Vec::new())
            .await
            .unwrap(),
    );
    core.ed2k_transfers
        .store_piece_data(token, 0, b"complete bytes")
        .await
        .unwrap();
    let attempt = uuid::Uuid::new_v4();
    core.metadata_store
        .begin_transfer_delivery_attempt(
            token,
            attempt,
            &partial,
            &root.join(format!(".emulebb-delivery-{attempt}.tmp")),
        )
        .unwrap();
    assert!(
        core.metadata_store
            .reserve_delivery_output(token, &partial, attempt)
            .unwrap()
    );
    fs::write(&partial, b"partial bytes").unwrap();
    fs::write(&other, b"complete bytes").unwrap();
    let scan = scan_shared_files(&core).await.unwrap();
    assert_eq!(names(scan.files), vec!["complete.bin"]);
    assert!(
        core.share_local_file(LocalShareCreate {
            path: partial.display().to_string(),
            name: None,
        })
        .await
        .is_err()
    );
    let shares = core.reload_shared_directories().await.unwrap();
    assert_eq!(shares.len(), 1);
    fs::remove_dir_all(&root).ok();
}

fn names(mut files: Vec<ScannedSharedFile>) -> Vec<String> {
    files.sort_by(|left, right| left.path.cmp(&right.path));
    files
        .into_iter()
        .map(|file| {
            file.path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

fn scanned_file(path: &Path) -> ScannedSharedFile {
    let metadata = fs::metadata(path).expect("stat scanned test file");
    let (key, file_size, source_fingerprint) =
        Ed2kTransferRuntime::scanned_source_identity_from_metadata(path, &metadata);
    ScannedSharedFile {
        path: path.to_path_buf(),
        key,
        disk_key: "disk:test".to_string(),
        file_size,
        source_fingerprint,
    }
}

fn source_evidence(
    path: &Path,
    fingerprint: &NativeFileFingerprint,
) -> emulebb_metadata::NativeFileIdentityEvidence {
    let file = fs::File::open(long_path(path)).unwrap();
    let (current, evidence) = Ed2kTransferRuntime::opened_source_identity(&file).unwrap();
    assert!(fingerprint.safely_matches(&current));
    evidence
}

fn synthetic_fingerprint(size_bytes: u64, modified_nanoseconds: u32) -> NativeFileFingerprint {
    NativeFileFingerprint {
        identity: emulebb_metadata::NativeFileIdentity::Unix {
            device_id: 7,
            inode_number: 11,
        },
        size_bytes,
        modified: emulebb_metadata::NativeFileTimestamp::new(1_700_000_000, modified_nanoseconds)
            .unwrap(),
        changed: None,
    }
}

fn synthetic_windows_fingerprint(size_bytes: u64) -> NativeFileFingerprint {
    NativeFileFingerprint {
        identity: emulebb_metadata::NativeFileIdentity::WindowsLowResolution {
            volume_serial_number: 13,
            file_index: 17,
        },
        size_bytes,
        modified: emulebb_metadata::NativeFileTimestamp::new(1_700_000_000, 0).unwrap(),
        changed: Some(emulebb_metadata::NativeFileTimestamp::new(1_700_000_001, 0).unwrap()),
    }
}

#[tokio::test]
async fn creation_canonicalizes_configured_root() {
    let root = scratch_dir("configured-root");
    let configured = root.join(".");
    let expected = fs::canonicalize(long_path(&root))
        .unwrap()
        .display()
        .to_string();
    let expected = normal_path_display(&expected);
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();

    core.create_library_root(&(configured.display().to_string()), false)
        .await
        .unwrap()
        .unwrap();
    let directories = core.shared_directories().await;

    assert_eq!(directories.roots.len(), 1);
    assert_eq!(directories.roots[0].path, expected);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn api_does_not_add_children_already_shared_by_incoming() {
    let temp = scratch_dir("api-incoming-roots");
    let child = temp.join("Child");
    fs::create_dir(&child).unwrap();
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap())
        .unwrap()
        .with_incoming_dir(temp.clone());
    // A mandatory parent participates in creation overlap rejection.
    core.reload_shared_directories().await.unwrap();
    let result = core
        .create_library_root(child.to_str().unwrap(), false)
        .await
        .unwrap();
    assert!(result.is_none());
    assert!(
        core.metadata_store
            .shared_directory_roots()
            .unwrap()
            .is_empty()
    );
    fs::remove_dir_all(temp).ok();
}

#[test]
fn unavailable_configured_parent_still_covers_its_children() {
    let temp = scratch_dir("unavailable-recursive-root");
    let parent = temp.join("Unavailable");
    let roots =
        consolidate_shared_directory_roots([parent.join("Child"), parent.clone()].map(|path| {
            MetadataSharedDirectoryRoot {
                path: path.display().to_string(),
                watch_enabled: false,
                monitor_owned: false,
                shareable: false,
                accessible: false,
            }
        }));
    assert_eq!(roots.len(), 1);
    assert_eq!(Path::new(&roots[0].path), parent);
    fs::remove_dir_all(temp).ok();
}

#[test]
fn unavailable_parent_does_not_hide_an_available_child() {
    let temp = scratch_dir("available-child-root");
    let parent = temp.join("Parent");
    let child = parent.join("Child");
    fs::create_dir_all(&child).unwrap();
    let roots = consolidate_shared_directory_roots([
        MetadataSharedDirectoryRoot {
            path: parent.display().to_string(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: false,
        },
        MetadataSharedDirectoryRoot {
            path: child.display().to_string(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        },
    ]);
    assert_eq!(roots.len(), 2);
    fs::remove_dir_all(temp).ok();
}

#[tokio::test]
async fn incoming_is_shared_without_an_explicit_root() {
    let incoming = scratch_dir("implicit-incoming");
    let path = incoming.join("Sample.bin");
    fs::write(&path, b"completed local content").unwrap();
    let core = EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
        .unwrap()
        .with_incoming_dir(incoming.clone());
    assert!(core.shared_directories().await.roots.is_empty());

    let shared = core.reload_shared_directories().await.unwrap();
    assert_eq!(shared.len(), 1);
    assert!(core.share(&shared[0].hash).await.is_some());
    assert!(
        core.metadata_store
            .shared_directory_roots()
            .unwrap()
            .is_empty()
    );
    assert!(
        core.metadata_store
            .active_local_file_by_hash(&shared[0].hash)
            .unwrap()
            .is_some()
    );
    fs::remove_dir_all(incoming).ok();
}

#[tokio::test]
async fn category_destination_is_shared_and_withdrawn_with_category() {
    let category_path = scratch_dir("implicit-category");
    fs::write(category_path.join("Sample.bin"), b"category content").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let category = core
        .create_category(crate::CategoryCreate {
            name: "Samples".to_string(),
            temp_dir: crate::NullableStringField::Missing,
            destination_dir: crate::NullableStringField::Value(
                category_path.to_string_lossy().into_owned(),
            ),
            comment: None,
        })
        .await
        .unwrap();
    let shared = core.reload_shared_directories().await.unwrap();
    assert_eq!(shared.len(), 1);
    let hash = shared[0].hash.clone();
    assert!(core.share(&hash).await.is_some());

    core.delete_category(category.id).await.unwrap();
    assert!(core.share(&hash).await.is_none());
    core.reload_shared_directories().await.unwrap();
    assert!(core.share(&hash).await.is_none());
    fs::remove_dir_all(category_path).ok();
}

#[tokio::test]
async fn reload_returns_cached_files_after_admitting_new_memberships() {
    let root = scratch_dir("cached-admission-result");
    let source = root.join("Cached.bin");
    fs::write(&source, b"cached payload without a root membership").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    configure_test_root(&core, &root).await;
    let cached = core
        .ed2k_transfers
        .ingest_local_file(&source, "Cached.bin")
        .await
        .unwrap();
    assert!(core.share(&cached.file_hash).await.is_none());

    let shares = core.reload_shared_directories().await.unwrap();

    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].hash, cached.file_hash);
    assert_eq!(
        core.shared_directories().await.reload_progress.reused_count,
        1
    );
    assert_eq!(
        core.shared_directories().await.reload_progress.hashed_count,
        0
    );
    fs::remove_dir_all(root).ok();
}

#[tokio::test]
async fn synchronous_and_detached_reloads_share_one_execution_gate() {
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let reload_guard = core.shared_reload_gate.lock().await;

    core.reload_shared_directories_detached().await.unwrap();
    let synchronous_core = core.clone();
    let synchronous_reload =
        tokio::spawn(async move { synchronous_core.reload_shared_directories().await });

    tokio::task::yield_now().await;
    assert!(core.shared_reload_running.load(Ordering::Acquire));
    assert!(!synchronous_reload.is_finished());

    drop(reload_guard);
    assert!(synchronous_reload.await.unwrap().unwrap().is_empty());
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while core.shared_reload_running.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_reload_drain_keeps_worker_until_final_join() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let guard = core.shared_reload_gate.lock().await;
    core.reload_shared_directories_detached().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while core.shared_reload_pending.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    core.begin_shutdown();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        core.finish_kad_persistence(),
    )
    .await
    .unwrap()
    .unwrap();
    let mut first = Box::pin(drain_reload(&core));
    assert!(
        poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(first);
    let mut second = Box::pin(drain_reload(&core));
    assert!(
        poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(guard);
    tokio::time::timeout(std::time::Duration::from_secs(5), second)
        .await
        .unwrap()
        .unwrap();
}

async fn assert_concurrent_reload_drains(cancel_latest: bool) {
    use std::future::{Future, poll_fn};

    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    // This holds the existing execution gate, not a filesystem operation.
    let execution = core.shared_reload_gate.lock().await;
    core.reload_shared_directories_detached().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while core.shared_reload_pending.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    core.begin_shutdown();

    let spawn_drain = || {
        let core = core.clone();
        let (pending, observed) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut drain = Box::pin(drain_reload(&core));
            let mut pending = Some(pending);
            poll_fn(|cx| {
                let result = drain.as_mut().poll(cx);
                if result.is_pending()
                    && let Some(pending) = pending.take()
                {
                    let _ = pending.send(());
                }
                result
            })
            .await
        });
        (task, observed)
    };
    let (first, first_pending) = spawn_drain();
    tokio::time::timeout(std::time::Duration::from_secs(5), first_pending)
        .await
        .unwrap()
        .unwrap();
    let (latest, latest_pending) = spawn_drain();
    tokio::time::timeout(std::time::Duration::from_secs(5), latest_pending)
        .await
        .unwrap()
        .unwrap();
    assert!(!first.is_finished());
    assert!(!latest.is_finished());
    if cancel_latest {
        latest.abort();
    }
    drop(execution);
    tokio::time::timeout(std::time::Duration::from_secs(5), first)
        .await
        .expect("first drain lost its worker wakeup")
        .unwrap()
        .unwrap();
    let latest = tokio::time::timeout(std::time::Duration::from_secs(5), latest)
        .await
        .expect("latest drain did not settle");
    if cancel_latest {
        assert!(latest.unwrap_err().is_cancelled());
    } else {
        latest.unwrap().unwrap();
    }
    assert!(core.shared_reload_task.task.lock().unwrap().is_none());
    core.drain_persistence().await.unwrap();
}

#[tokio::test]
async fn concurrent_reload_drains_both_finish() {
    assert_concurrent_reload_drains(false).await;
}

#[tokio::test]
async fn cancelling_latest_reload_drain_preserves_first_waiter() {
    assert_concurrent_reload_drains(true).await;
}

#[tokio::test]
async fn incremental_reload_skips_unchanged_failed_source_and_retries_changed_identity() {
    let root = scratch_dir("failed-source");
    let source = root.join("Failed.Source.bin");
    fs::write(&source, b"initial payload").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let (key, size, fingerprint) = Ed2kTransferRuntime::scanned_source_identity(&source).unwrap();
    core.metadata_store
        .upsert_shared_source_failure(&key, size, fingerprint.as_ref(), "ingest failed")
        .unwrap();

    let skipped = plan_incremental_reload(&core, vec![scanned_file(&source)])
        .await
        .unwrap();

    assert!(skipped.to_hash.is_empty());
    assert_eq!(skipped.stats.planned_hash_count, 0);
    assert_eq!(skipped.stats.skipped_failed_count, 1);

    fs::write(&source, b"changed payload with a different length").unwrap();
    let retried = plan_incremental_reload(&core, vec![scanned_file(&source)])
        .await
        .unwrap();

    assert_eq!(retried.to_hash.len(), 1);
    assert_eq!(retried.stats.planned_hash_count, 1);
    assert_eq!(retried.stats.new_count, 1);
    assert_eq!(retried.stats.skipped_failed_count, 0);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn incremental_reload_prunes_persisted_share_absent_from_scan() {
    let root = scratch_dir("pruned-source");
    let source = root.join("Pruned.Source.bin");
    fs::write(&source, b"payload").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    configure_test_root(&core, &root).await;
    let shared = core
        .share_local_file(LocalShareCreate {
            path: source.display().to_string(),
            name: None,
        })
        .await
        .unwrap();

    let plan = plan_incremental_reload(&core, Vec::new()).await.unwrap();

    assert_eq!(plan.stats.pruned_count, 1);
    fs::remove_file(&source).unwrap();
    let reloaded = core.reload_shared_directories().await.unwrap();
    assert!(reloaded.is_empty());
    assert!(core.share(&shared.hash).await.is_none());
    assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 0);
    assert_eq!(
        core.metadata_store.active_shared_content_count().unwrap(),
        0
    );
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn full_reload_replaces_changed_source_offer_after_membership_commit() {
    let root = scratch_dir("changed-offer");
    let source = root.join("Changed.Source.bin");
    fs::write(&source, b"old payload").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    configure_test_root(&core, &root).await;
    let old = core
        .share_local_file(LocalShareCreate {
            path: source.display().to_string(),
            name: None,
        })
        .await
        .unwrap();

    fs::write(&source, b"a different, longer payload").unwrap();
    let reloaded = core.reload_shared_directories().await.unwrap();

    assert_eq!(reloaded.len(), 1);
    assert_ne!(reloaded[0].hash, old.hash);
    assert!(core.share(&old.hash).await.is_none());
    assert!(core.share(&reloaded[0].hash).await.is_some());
    assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 1);
    assert_eq!(
        core.metadata_store.active_shared_content_count().unwrap(),
        1
    );
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn incremental_reload_reuses_imported_share_not_yet_active() {
    let root = scratch_dir("imported-source");
    let source = root.join("Imported.Source.bin");
    fs::write(&source, b"imported payload").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let file_hash = core
        .ed2k_transfers
        .ingest_local_file(&source, "Imported.Source.bin")
        .await
        .unwrap()
        .file_hash;
    assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 0);

    let plan = plan_incremental_reload(&core, vec![scanned_file(&source)])
        .await
        .unwrap();

    assert!(plan.to_hash.is_empty());
    assert_eq!(plan.reused_shares.len(), 1);
    assert_eq!(plan.reused_shares[0].file_hash, file_hash);
    assert_eq!(plan.stats.planned_hash_count, 0);
    assert_eq!(plan.stats.reused_count, 1);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn incremental_reload_reuses_unchanged_coarse_timestamp() {
    let root = scratch_dir("coarse-timestamp");
    let source = root.join("Coarse.Timestamp.bin");
    fs::write(&source, b"same-size").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let file_size = fs::metadata(&source).unwrap().len();
    let coarse_fingerprint = synthetic_fingerprint(file_size, 0);
    let file_hash = core
        .ed2k_transfers
        .ingest_local_file(&source, "Coarse.Timestamp.bin")
        .await
        .unwrap()
        .file_hash;
    core.metadata_store
        .upsert_local_file_instance(
            &long_path(&source),
            &file_hash,
            &coarse_fingerprint,
            emulebb_metadata::NativeFileIdentityEvidence::new(coarse_fingerprint.identity, None)
                .unwrap(),
        )
        .unwrap();

    let plan = plan_incremental_reload(
        &core,
        vec![ScannedSharedFile {
            path: source.clone(),
            key: long_path(&source),
            disk_key: "disk:test".to_string(),
            file_size,
            source_fingerprint: Some(coarse_fingerprint),
        }],
    )
    .await
    .unwrap();

    assert!(plan.to_hash.is_empty());
    assert_eq!(plan.reused_shares.len(), 1);
    assert_eq!(plan.stats.changed_count, 0);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn incremental_reload_reuses_windows_whole_second_timestamp_with_change_time() {
    let root = scratch_dir("windows-whole-second-timestamp");
    let source = root.join("Whole.Second.bin");
    fs::write(&source, b"same-size").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let file_size = fs::metadata(&source).unwrap().len();
    let fingerprint = synthetic_windows_fingerprint(file_size);
    let file_hash = core
        .ed2k_transfers
        .ingest_local_file(&source, "Whole.Second.bin")
        .await
        .unwrap()
        .file_hash;
    core.metadata_store
        .upsert_local_file_instance(
            &long_path(&source),
            &file_hash,
            &fingerprint,
            emulebb_metadata::NativeFileIdentityEvidence::new(fingerprint.identity, None).unwrap(),
        )
        .unwrap();

    let plan = plan_incremental_reload(
        &core,
        vec![ScannedSharedFile {
            path: source.clone(),
            key: long_path(&source),
            disk_key: "disk:test".to_string(),
            file_size,
            source_fingerprint: Some(fingerprint),
        }],
    )
    .await
    .unwrap();

    assert!(plan.to_hash.is_empty());
    assert_eq!(plan.reused_shares.len(), 1);
    assert_eq!(plan.stats.planned_hash_count, 0);
    assert_eq!(plan.stats.reused_count, 1);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn incremental_reload_accepts_unique_stock_hash_without_payload_reads() {
    let root = scratch_dir("imported-known-pathless");
    let source = root.join("Imported.Known.bin");
    fs::write(&source, b"known payload").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let (_, size, fingerprint) = Ed2kTransferRuntime::scanned_source_identity(&source).unwrap();
    let imported = MetadataFileImportRecord {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Imported.Known.bin".to_string(),
        file_size: size,
        modified_s: fingerprint.as_ref().unwrap().modified.seconds,
        md4_hashset: Vec::new(),
        aich_root: None,
        aich_hashset: Vec::new(),
        upload_priority: "release".to_string(),
        auto_upload_priority: false,
        all_time_uploaded_bytes: 1234,
        all_time_upload_requests: 9,
        all_time_upload_accepts: 4,
        last_upload_requested_at_s: Some(1_700_000_001),
    };
    core.metadata_store
        .accept_imported_local_files(&[(
            imported.clone(),
            emulebb_ed2k::long_path::long_path(&source),
            fingerprint.clone().unwrap(),
            source_evidence(&source, fingerprint.as_ref().unwrap()),
        )])
        .unwrap();

    let plan = plan_incremental_reload(&core, vec![scanned_file(&source)])
        .await
        .unwrap();

    assert!(plan.to_hash.is_empty());
    assert_eq!(plan.stats.planned_hash_count, 0);
    assert_eq!(plan.stats.reused_count, 1);
    assert_eq!(plan.reused_shares[0].file_hash, imported.file_hash);
    let repeated = plan_incremental_reload(&core, vec![scanned_file(&source)])
        .await
        .unwrap();
    assert!(repeated.to_hash.is_empty());
    assert_eq!(repeated.stats.reused_count, 1);
    assert!(core.share(&imported.file_hash).await.is_none());
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn reload_without_live_binding_plans_hashing_without_staging_fallback() {
    let root = scratch_dir("no-staging-fallback");
    let source = root.join("Sample.bin");
    fs::write(&source, b"sample").unwrap();
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let plan = plan_incremental_reload(&core, vec![scanned_file(&source)])
        .await
        .unwrap();
    assert_eq!(plan.stats.planned_hash_count, 1);
    assert_eq!(plan.stats.reused_count, 0);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn added_path_reuses_accepted_live_identity_without_stock_lookup_or_payload_hash() {
    let root = scratch_dir("native-alias-reuse");
    let first = root.join("First.bin");
    let second = root.join("Second.bin");
    fs::write(&first, b"sample bytes").unwrap();
    fs::hard_link(&first, &second).unwrap();
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let (key, size, fp) = Ed2kTransferRuntime::scanned_source_identity(&first).unwrap();
    let fp = fp.unwrap();
    let expected = "00112233445566778899aabbccddeeff";
    core.metadata_store
        .accept_imported_local_files(&[(
            MetadataFileImportRecord {
                file_hash: expected.into(),
                display_name: "First.bin".into(),
                file_size: size,
                modified_s: fp.modified.seconds,
                md4_hashset: Vec::new(),
                aich_root: None,
                aich_hashset: Vec::new(),
                upload_priority: "normal".into(),
                auto_upload_priority: false,
                all_time_uploaded_bytes: 0,
                all_time_upload_requests: 0,
                all_time_upload_accepts: 0,
                last_upload_requested_at_s: None,
            },
            key,
            fp.clone(),
            source_evidence(&first, &fp),
        )])
        .unwrap();
    let plan = plan_incremental_reload(&core, vec![scanned_file(&second)])
        .await
        .unwrap();
    assert!(plan.to_hash.is_empty());
    assert_eq!(plan.stats.reused_count, 1);
    assert_eq!(plan.reused_shares[0].file_hash, expected);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn trusted_stock_hash_survives_normal_scans_and_restart() {
    let root = scratch_dir("trusted-stock-restart");
    let shared = root.join("shared");
    fs::create_dir(&shared).unwrap();
    let source = shared.join("Sample.bin");
    fs::write(&source, b"stock payload").unwrap();
    let db = root.join("profile.db");
    let transfers = root.join("runtime").join("transfers");
    let core = EmulebbCore::new("test", FileIndex::open(&db).unwrap(), &transfers).unwrap();
    configure_test_root(&core, &shared).await;
    let (_, size, fingerprint) = Ed2kTransferRuntime::scanned_source_identity(&source).unwrap();
    // Deliberately unrelated to the fixture bytes: any content-hashing path
    // would replace this stock identity and make the assertions fail.
    let expected_hash = "00112233445566778899aabbccddeeff";
    core.metadata_store
        .accept_imported_local_files(&[(
            MetadataFileImportRecord {
                file_hash: expected_hash.to_string(),
                display_name: "Sample.bin".to_string(),
                file_size: size,
                modified_s: fingerprint.as_ref().unwrap().modified.seconds,
                md4_hashset: Vec::new(),
                aich_root: None,
                aich_hashset: Vec::new(),
                upload_priority: "release".to_string(),
                auto_upload_priority: false,
                all_time_uploaded_bytes: 1234,
                all_time_upload_requests: 9,
                all_time_upload_accepts: 4,
                last_upload_requested_at_s: Some(1_700_000_001),
            },
            emulebb_ed2k::long_path::long_path(&source),
            fingerprint.clone().unwrap(),
            source_evidence(&source, fingerprint.as_ref().unwrap()),
        )])
        .unwrap();
    assert_eq!(
        core.metadata_store.active_shared_content_count().unwrap(),
        0
    );
    let shares = core.reload_shared_directories().await.unwrap();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].hash, expected_hash);
    let view = core
        .ed2k_transfers
        .serving_view(expected_hash)
        .await
        .unwrap();
    assert_eq!(view.aich_root, None);
    assert!(!view.aich_hashset_acquired);
    let content = core
        .metadata_store
        .active_local_file_by_hash(expected_hash)
        .unwrap();
    assert!(content.is_some());
    drop(core);

    let restarted = EmulebbCore::new("test", FileIndex::open(&db).unwrap(), &transfers).unwrap();
    let shares = restarted.reload_shared_directories().await.unwrap();
    assert_eq!(shares[0].hash, expected_hash);

    fs::write(&source, b"changed stock payload").unwrap();
    let scan = scan_shared_files(&restarted).await.unwrap();
    let plan = plan_incremental_reload(&restarted, scan.files)
        .await
        .unwrap();
    assert_eq!(plan.to_hash.len(), 1);
    let changed = plan.stats;
    assert_eq!(changed.changed_count, 1);
    assert_eq!(changed.planned_hash_count, 1);
    assert!(
        restarted
            .ed2k_transfers
            .serving_view(expected_hash)
            .await
            .is_err()
    );
    drop(restarted);
    fs::remove_dir_all(&root).ok();
}

/// A promoted download uses the same verified local instance cache as any
/// other library file. A replaced payload must lose that cache hit.
#[tokio::test]
async fn incremental_reload_reuses_verified_local_instance_without_rehash() {
    let root = scratch_dir("delivered-download");
    let delivered = root.join("Completed.Download.bin");
    fs::write(&delivered, b"completed download payload").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    configure_test_root(&core, &root).await;
    let file_hash = core
        .share_local_file(LocalShareCreate {
            path: delivered.display().to_string(),
            name: None,
        })
        .await
        .unwrap()
        .hash;

    // Unchanged delivered file: reuse HIT, no re-hash.
    let plan = plan_incremental_reload(&core, vec![scanned_file(&delivered)])
        .await
        .unwrap();
    assert!(
        plan.to_hash.is_empty(),
        "an unchanged delivered download must not be re-hashed"
    );
    assert_eq!(plan.reused_shares.len(), 1);
    assert_eq!(plan.reused_shares[0].file_hash, file_hash);
    assert_eq!(plan.stats.reused_count, 1);
    assert_eq!(plan.stats.planned_hash_count, 0);
    assert_eq!(plan.stats.new_count, 0);

    // Operator replaces the delivered file: the stale reuse
    // baseline no longer matches, so it is (correctly) re-hashed as new.
    std::thread::sleep(std::time::Duration::from_millis(10));
    fs::write(&delivered, b"a different payload the operator dropped in").unwrap();
    let replaced = plan_incremental_reload(&core, vec![scanned_file(&delivered)])
        .await
        .unwrap();
    assert_eq!(
        replaced.to_hash.len(),
        1,
        "a replaced delivered file must be re-hashed, not served under the old hash"
    );
    assert!(replaced.reused_shares.is_empty());
    assert_eq!(replaced.stats.changed_count, 1);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn incremental_reload_keeps_hash_when_duplicate_source_remains_scanned() {
    let root = scratch_dir("duplicate-source");
    let kept_source = root.join("Kept.Source.bin");
    let missing_source = root.join("Missing.Source.bin");
    fs::write(&kept_source, b"same payload").unwrap();
    fs::write(&missing_source, b"same payload").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    configure_test_root(&core, &root).await;
    let kept = core
        .share_local_file(LocalShareCreate {
            path: kept_source.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    let duplicate = core
        .share_local_file(LocalShareCreate {
            path: missing_source.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    assert_eq!(kept.hash, duplicate.hash);

    let plan = plan_incremental_reload(&core, vec![scanned_file(&kept_source)])
        .await
        .unwrap();

    assert_eq!(plan.reused_shares.len(), 1);
    assert_eq!(plan.reused_shares[0].file_hash, kept.hash);
    assert_eq!(plan.stats.pruned_count, 0);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn shared_directory_scan_collects_full_tree_files_only() {
    let root = scratch_dir("rec");
    fs::write(root.join("top.dat"), b"a").unwrap();
    let nested = root.join("nested").join("more");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("deep.dat"), b"b").unwrap();

    let mut output = Vec::new();
    let skipped = collect_shared_directory_files(&root, &mut output).unwrap();

    assert_eq!(skipped, 0);
    // Directories are skipped; only the two files are reported.
    assert_eq!(names(output), vec!["deep.dat", "top.dat"]);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn unreadable_root_is_skipped_without_aborting() {
    // walkdir surfaces a per-entry error when the root itself cannot be
    // read (here: it does not exist). The scan must log/skip that entry and
    // return Ok with an empty result rather than propagating the error.
    let missing = scratch_dir("missing");
    let missing = missing.join("does-not-exist");
    assert!(!missing.exists());

    let mut output = Vec::new();
    let result = collect_shared_directory_files(&missing, &mut output);

    assert_eq!(result.unwrap(), 1);
    assert!(output.is_empty());
}

#[tokio::test]
async fn root_scan_keeps_successful_membership_separate_from_offline_root() {
    let available = scratch_dir("available-root");
    fs::write(available.join("Sample.bin"), b"sample").unwrap();
    let offline = available.join("missing-root");
    let mut metadata = MetadataStore::in_memory().unwrap();
    metadata
        .replace_shared_directory_roots(&[&available, &offline].map(|path| {
            MetadataSharedDirectoryRoot {
                path: path.to_string_lossy().into_owned(),
                watch_enabled: false,
                monitor_owned: false,
                shareable: true,
                accessible: true,
            }
        }))
        .unwrap();
    let roots = [&available, &offline]
        .map(|path| SharedDirectoryRoot {
            path: path.to_string_lossy().into_owned(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        })
        .to_vec();
    let scan = scan_shared_directory_roots(roots, SharedFileIgnorePolicy::default(), metadata)
        .await
        .unwrap();
    assert_eq!(scan.root_files.len(), 1);
    assert_eq!(scan.root_files[0].files.len(), 1);
    assert_eq!(scan.files.len(), 1);
    assert_eq!(scan.root_files[0].files[0].path, scan.files[0].path);
    assert_eq!(
        scan.root_files[0].files[0].source_fingerprint,
        scan.files[0].source_fingerprint
    );
    assert_eq!(scan.inaccessible_roots, vec![offline]);
    fs::remove_dir_all(available).ok();
}

#[test]
fn shared_scan_ignores_mfc_intake_file_names_and_empty_files() {
    let root = scratch_dir("ignored-files");
    fs::write(root.join("alpha.bin"), b"a").unwrap();
    fs::write(root.join("desktop.ini"), b"metadata").unwrap();
    fs::write(root.join("download.part"), b"partial").unwrap();
    fs::write(root.join("~$office.tmp"), b"lock").unwrap();
    fs::write(root.join("empty.bin"), b"").unwrap();

    let mut output = Vec::new();
    let skipped = collect_shared_directory_files(&root, &mut output).unwrap();

    assert_eq!(skipped, 4);
    assert_eq!(names(output), vec!["alpha.bin"]);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn folder_tree_shared_scan_prunes_mfc_ignored_directories() {
    let root = scratch_dir("ignored-dirs");
    fs::write(root.join("alpha.bin"), b"a").unwrap();
    let git_dir = root.join(".git");
    fs::create_dir_all(&git_dir).unwrap();
    fs::write(git_dir.join("object.bin"), b"b").unwrap();
    let nested = root.join("visible");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("beta.bin"), b"c").unwrap();

    let mut output = Vec::new();
    let skipped = collect_shared_directory_files(&root, &mut output).unwrap();

    assert_eq!(skipped, 1);
    assert_eq!(names(output), vec!["alpha.bin", "beta.bin"]);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn shared_file_name_policy_matches_mfc_affixes() {
    assert!(should_ignore_shared_file_name("Thumbs.db"));
    assert!(should_ignore_shared_file_name(".DS_Store"));
    assert!(should_ignore_shared_file_name("._resource"));
    assert!(should_ignore_shared_file_name("download.crdownload"));
    assert!(should_ignore_shared_file_name("~lock.document#"));
    assert!(!should_ignore_shared_file_name("sample.data"));
}

#[test]
fn shared_scan_applies_custom_patterns_and_removable_defaults() {
    let root = scratch_dir("exclusion-policy");
    let excluded = root.join("private.bin");
    fs::write(&excluded, b"private").unwrap();
    fs::write(root.join("PRIVATE2.BIN"), b"private too").unwrap();
    fs::write(root.join("desktop.ini"), b"metadata").unwrap();
    fs::write(root.join("known.met"), b"runtime").unwrap();
    fs::write(root.join("public.bin"), b"public").unwrap();

    let policy = SharedFileIgnorePolicy::new(
        vec!["private*.bin".to_string()],
        vec!["noise.desktop-ini".to_string()],
    )
    .unwrap();
    let mut output = Vec::new();
    let skipped = collect_shared_directory_files_with_policy(&root, &mut output, &policy).unwrap();

    assert_eq!(skipped, 3);
    assert_eq!(names(output), vec!["desktop.ini", "public.bin"]);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn custom_ignore_patterns_reject_paths_and_exact_file_names() {
    assert!(validate_shared_file_ignore_pattern("*.private.bin").is_ok());
    assert!(validate_shared_file_ignore_pattern("C:/Shared/private.bin").is_err());
    assert!(validate_shared_file_ignore_pattern("private.bin").is_err());
    assert!(validate_shared_file_ignore_pattern("[").is_err());
}

#[test]
fn shared_file_name_policy_ignores_emule_runtime_files() {
    assert!(should_ignore_shared_file_name("known.met"));
    assert!(should_ignore_shared_file_name("KNOWN2_64.MET"));
    assert!(should_ignore_shared_file_name("001.part.met.bak"));
    assert!(should_ignore_shared_file_name("preferences.dat"));
}

#[tokio::test]
async fn direct_share_rejects_a_persisted_ignore_pattern() {
    let root = scratch_dir("direct-exclusion");
    let source = root.join("private.bin");
    fs::write(&source, b"private payload").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    core.metadata_store
        .add_shared_file_ignore_pattern("private*.bin")
        .unwrap();

    let error = core
        .share_native_local_file_with_progress(&source, None, None)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("excluded from sharing"));
    assert!(core.shares().await.is_empty());
    fs::remove_dir_all(&root).ok();
}

#[test]
fn initial_publish_cohort_is_small_first_and_bounded() {
    let candidates = (0..205)
        .map(|sequence| ScannedSharedFile {
            path: PathBuf::from(format!("file-{sequence:03}.bin")),
            key: format!("key-{sequence:03}").into(),
            disk_key: "disk:test".to_string(),
            file_size: u64::try_from(sequence + 1).unwrap(),
            source_fingerprint: None,
        })
        .collect::<Vec<_>>();

    let selected = select_initial_publish_cohort(candidates);

    assert_eq!(selected.len(), INITIAL_PUBLISH_COHORT_FILE_LIMIT);
    assert_eq!(selected.first().unwrap().file_size, 1);
    assert_eq!(selected.last().unwrap().file_size, 200);

    let byte_bounded = select_initial_publish_cohort(vec![
        ScannedSharedFile {
            path: PathBuf::from("smallest.bin"),
            key: "smallest".into(),
            disk_key: "disk:test".to_string(),
            file_size: INITIAL_PUBLISH_COHORT_BYTE_LIMIT / 2,
            source_fingerprint: None,
        },
        ScannedSharedFile {
            path: PathBuf::from("second.bin"),
            key: "second".into(),
            disk_key: "disk:test".to_string(),
            file_size: INITIAL_PUBLISH_COHORT_BYTE_LIMIT / 2,
            source_fingerprint: None,
        },
        ScannedSharedFile {
            path: PathBuf::from("over-budget.bin"),
            key: "over-budget".into(),
            disk_key: "disk:test".to_string(),
            file_size: INITIAL_PUBLISH_COHORT_BYTE_LIMIT,
            source_fingerprint: None,
        },
    ]);
    assert_eq!(byte_bounded.len(), 2);
    assert_eq!(
        byte_bounded.iter().map(|file| file.file_size).sum::<u64>(),
        INITIAL_PUBLISH_COHORT_BYTE_LIMIT
    );
}

#[tokio::test]
async fn empty_catalog_bootstrap_makes_files_publishable_before_full_scan() {
    use std::future::{Future, poll_fn};

    let root = scratch_dir("initial-publish");
    for sequence in 0..3 {
        fs::write(
            root.join(format!("bootstrap-{sequence}.bin")),
            format!("bootstrap payload {sequence}"),
        )
        .unwrap();
    }
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    core.state.lock().await.shared_directories = vec![SharedDirectoryRoot {
        path: root.display().to_string(),
        watch_enabled: false,
        monitor_owned: false,
        shareable: true,
        accessible: true,
    }];
    core.metadata_store
        .clone()
        .replace_shared_directory_roots(&[emulebb_metadata::MetadataSharedDirectoryRoot {
            path: root.display().to_string(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();

    let mut bootstrap = Box::pin(bootstrap_initial_publish_catalog(&core));
    let bootstrap = poll_fn(|cx| {
        let result = bootstrap.as_mut().poll(cx);
        // Check the actual producer at every suspension and completion through
        // the same serialized progress surface consumed by REST clients.
        let progress = serde_json::to_value(core.shared_directory_reload_progress()).unwrap();
        assert!(
            matches!(
                progress["phase"].as_str(),
                Some("idle" | "queued" | "scanning" | "planning" | "hashing")
            ),
            "reload phase outside the public contract: {}",
            progress["phase"]
        );
        result
    })
    .await
    .unwrap()
    .unwrap();

    assert_eq!(bootstrap.progress.hashed_count, 3);
    assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 3);
    let progress = reload_progress_snapshot(&core);
    assert_eq!(progress.phase, "hashing");
    assert_eq!(progress.hashed_count, 3);
    assert_eq!(progress.scanned_count, 3);
    fs::remove_dir_all(root).ok();
}
