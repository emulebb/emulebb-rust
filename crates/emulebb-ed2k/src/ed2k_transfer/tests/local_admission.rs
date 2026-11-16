//! Tracked new-path admission crosses real SQL and catalog publication boundaries.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::{MetadataSharedDirectoryRoot, NativeFileFingerprint};

use super::super::{
    Ed2kResumeManifest, Ed2kSharedEntry, Ed2kSharedRange, Ed2kTransferRuntime, new_transfer_job,
};

struct VerifiedPath {
    path: PathBuf,
    hash: String,
    fingerprint: NativeFileFingerprint,
}

async fn prepare_path(
    runtime: &Ed2kTransferRuntime,
    root: &Path,
    name: &str,
    bytes: &[u8],
) -> VerifiedPath {
    fs::create_dir_all(root).unwrap();
    let path = root.join(name);
    fs::write(&path, bytes).unwrap();
    let shared = runtime.ingest_local_file(&path, name).await.unwrap();
    let path = crate::long_path::long_path(&path);
    let fingerprint = runtime
        .metadata
        .local_file_instance(&path)
        .unwrap()
        .unwrap()
        .verified_fingerprint;
    VerifiedPath {
        path,
        hash: shared.file_hash,
        fingerprint,
    }
}

fn configure_roots(runtime: &Ed2kTransferRuntime, roots: &[&Path]) {
    let rows = roots
        .iter()
        .map(|root| MetadataSharedDirectoryRoot {
            path: root.to_string_lossy().into_owned(),
            monitor_owned: false,
            shareable: true,
            accessible: true,
        })
        .collect::<Vec<_>>();
    runtime
        .metadata
        .clone()
        .replace_shared_directory_roots(&rows)
        .unwrap();
}

async fn admit(
    runtime: &Ed2kTransferRuntime,
    root: &Path,
    file: &VerifiedPath,
) -> anyhow::Result<bool> {
    let normalized_root = crate::long_path::long_path(root);
    runtime
        .admit_monitored_shared_path(
            &file.hash,
            root,
            &file.path,
            file.path.strip_prefix(normalized_root).unwrap(),
            &file.fingerprint,
            None,
        )
        .await
}

async fn reached(receiver: tokio::sync::oneshot::Receiver<()>) {
    tokio::time::timeout(Duration::from_secs(5), receiver)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn observed_delivery_restores_only_its_path_and_keeps_independent_copy() {
    let profile = crate::paths::unique_test_dir("observed-delivery-root");
    let root = profile.join("recovered");
    let other = profile.join("other");
    let runtime = Ed2kTransferRuntime::load_or_create(&profile).unwrap();
    let old = prepare_path(&runtime, &root, "old.bin", b"old content").await;
    let independent = prepare_path(&runtime, &other, "copy.bin", b"old content").await;
    let delivered = prepare_path(&runtime, &root, "delivered.bin", b"new content").await;
    configure_roots(&runtime, &[&root, &other]);
    assert!(admit(&runtime, &root, &old).await.unwrap());
    assert!(admit(&runtime, &other, &independent).await.unwrap());
    let prior_scan = runtime.metadata.shared_root_last_scan_ms(&root).unwrap();
    runtime
        .metadata
        .set_shared_root_accessible(&root, false)
        .unwrap();
    let stale = runtime.root_observation_epoch().await;
    drop(runtime.begin_category_root_mutation().await.unwrap());
    let relative = delivered
        .path
        .strip_prefix(crate::long_path::long_path(&root))
        .unwrap();
    let error = runtime
        .admit_monitored_shared_path(
            &delivered.hash,
            &root,
            &delivered.path,
            relative,
            &delivered.fingerprint,
            Some(stale),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<super::super::LocalMutationError>(),
        Some(super::super::LocalMutationError::Busy)
    ));
    assert!(
        runtime
            .metadata
            .next_shared_copy(&delivered.hash, 0, 65_536)
            .unwrap()
            .is_none()
    );
    let epoch = runtime.root_observation_epoch().await;
    assert!(
        runtime
            .admit_monitored_shared_path(
                &delivered.hash,
                &root,
                &delivered.path,
                relative,
                &delivered.fingerprint,
                Some(epoch)
            )
            .await
            .unwrap()
    );
    let copy = runtime
        .metadata
        .next_shared_copy(&old.hash, 0, 65_536)
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::long_path::long_path(&copy.source_path),
        independent.path
    );
    assert!(
        runtime
            .metadata
            .next_shared_copy(&old.hash, copy.path_id, 65_536)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        runtime.metadata.shared_root_last_scan_ms(&root).unwrap(),
        prior_scan
    );
    assert!(
        runtime
            .metadata
            .shared_directory_roots()
            .unwrap()
            .iter()
            .find(|item| Path::new(&item.path) == root)
            .unwrap()
            .accessible
    );
}

#[tokio::test]
async fn cancelled_admission_publishes_exact_copy_before_drain_returns() {
    let profile = crate::paths::unique_test_dir("local-admission-cancel");
    let root = profile.join("library");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&profile).unwrap());
    let file = prepare_path(
        &runtime,
        &root,
        "new-copy.bin",
        b"verified admission content",
    )
    .await;
    configure_roots(&runtime, &[&root]);
    let hash: Ed2kHash = file.hash.parse().unwrap();
    assert!(
        runtime
            .shared_catalog
            .read()
            .await
            .entry_by_hash(&hash)
            .is_none()
    );
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(started, gate);
    let caller = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { admit(&runtime, &root, &file).await })
    };
    reached(ready).await;
    assert!(
        runtime
            .metadata
            .next_shared_copy(&hash.to_string(), 0, 65_536)
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
    assert!(
        runtime
            .share_eligibility
            .stripe_snapshot(&[hash.0])
            .is_none()
    );
    caller.abort();
    let _ = caller.await;
    let pending = runtime.local_mutations.signal_next_pending_drain();
    let drain = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { runtime.drain_local_mutations().await })
    };
    reached(pending).await;
    assert!(!drain.is_finished());
    release.send(()).unwrap();
    drain.await.unwrap().unwrap();
    let catalog = runtime.shared_catalog.read().await;
    let entry = catalog.entry_by_hash(&hash).unwrap();
    assert!(entry.verified_complete);
    assert_eq!(entry.display_name, "new-copy.bin");
    assert!(
        runtime
            .share_eligibility
            .stripe_snapshot(&[hash.0])
            .is_some()
    );
}

#[tokio::test]
async fn admission_waits_for_capacity_without_writing_the_waiting_path() {
    let profile = crate::paths::unique_test_dir("local-admission-capacity");
    let root = profile.join("library");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&profile).unwrap());
    let first = prepare_path(&runtime, &root, "first.bin", b"first admission content").await;
    let second = prepare_path(&runtime, &root, "second.bin", b"second admission content").await;
    configure_roots(&runtime, &[&root]);
    let first_hash: Ed2kHash = first.hash.parse().unwrap();
    let second_hash: Ed2kHash = second.hash.parse().unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(started, gate);
    let first_task = {
        let runtime = Arc::clone(&runtime);
        let root = root.clone();
        tokio::spawn(async move { admit(&runtime, &root, &first).await })
    };
    reached(ready).await;
    let waiting = runtime.local_mutations.signal_next_pending_wait();
    let second_task = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { admit(&runtime, &root, &second).await })
    };
    reached(waiting).await;
    assert!(!second_task.is_finished());
    assert!(
        runtime
            .metadata
            .next_shared_copy(&second_hash.to_string(), 0, 65_536)
            .unwrap()
            .is_none()
    );
    assert!(
        runtime
            .shared_catalog
            .read()
            .await
            .entry_by_hash(&second_hash)
            .is_none()
    );
    release.send(()).unwrap();
    assert!(first_task.await.unwrap().unwrap());
    assert!(second_task.await.unwrap().unwrap());
    runtime.drain_local_mutations().await.unwrap();
    let catalog = runtime.shared_catalog.read().await;
    assert!(
        catalog
            .entry_by_hash(&first_hash)
            .unwrap()
            .verified_complete
    );
    assert!(
        catalog
            .entry_by_hash(&second_hash)
            .unwrap()
            .verified_complete
    );
}

#[tokio::test]
async fn root_change_after_admission_restores_live_uncheckpointed_partial_and_counters() {
    let profile = crate::paths::unique_test_dir("local-admission-partial-overlap");
    let root = profile.join("library");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&profile).unwrap());
    let file = prepare_path(&runtime, &root, "shared.bin", b"verified admission content").await;
    configure_roots(&runtime, &[&root]);
    let hash: Ed2kHash = file.hash.parse().unwrap();
    let job = new_transfer_job(hash, "partial.bin".into(), file.fingerprint.size_bytes);
    let mut manifest = Ed2kResumeManifest::new(&job);
    manifest.md4_hashset_acquired = true;
    manifest.verified_ranges = vec![Ed2kSharedRange { start: 0, end: 4 }];
    runtime
        .manifest_cache
        .lock()
        .await
        .insert(file.hash.clone(), manifest.clone());
    let mut entry = Ed2kSharedEntry::from_manifest(&manifest);
    entry.publish.session_request_count = 17;
    entry.all_time_uploaded_bytes = 31;
    runtime
        .shared_catalog
        .write()
        .await
        .upsert_verified(hash, Some(entry));
    assert!(
        runtime
            .metadata
            .partial_share_for_category_reconciliation(&file.hash)
            .unwrap()
            .is_none()
    );
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(started, gate);
    let caller = {
        let runtime = Arc::clone(&runtime);
        let root = root.clone();
        tokio::spawn(async move { admit(&runtime, &root, &file).await })
    };
    reached(ready).await;
    let mutation = runtime.begin_category_root_mutation().await.unwrap();
    runtime
        .metadata
        .set_shared_root_accessible(&root, false)
        .unwrap();
    drop(mutation);
    release.send(()).unwrap();
    assert!(caller.await.unwrap().unwrap());
    runtime.drain_local_mutations().await.unwrap();
    let catalog = runtime.shared_catalog.read().await;
    let entry = catalog.entry_by_hash(&hash).unwrap();
    assert!(!entry.verified_complete);
    assert_eq!(entry.verified_ranges, manifest.verified_ranges);
    assert_eq!(entry.publish.session_request_count, 17);
    assert_eq!(entry.all_time_uploaded_bytes, 31);
    assert_eq!(
        runtime.manifest_cache.lock().await[&hash.to_string()].verified_ranges,
        manifest.verified_ranges
    );
    assert!(
        !runtime
            .share_publication_failed
            .load(std::sync::atomic::Ordering::Acquire)
    );
}

#[tokio::test]
async fn overlapping_root_change_keeps_an_independent_complete_copy() {
    let profile = crate::paths::unique_test_dir("local-admission-independent-copy");
    let root = profile.join("library");
    let sibling_root = profile.join("sibling");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&profile).unwrap());
    let first = prepare_path(&runtime, &root, "new.bin", b"independent admission content").await;
    let sibling = prepare_path(
        &runtime,
        &sibling_root,
        "sibling.bin",
        b"independent admission content",
    )
    .await;
    configure_roots(&runtime, &[&root, &sibling_root]);
    assert!(admit(&runtime, &sibling_root, &sibling).await.unwrap());
    let hash: Ed2kHash = first.hash.parse().unwrap();
    runtime
        .shared_catalog
        .write()
        .await
        .update_by_hash(&hash, |entry| {
            entry.publish.session_request_count = 23;
            entry.all_time_uploaded_bytes = 47;
        });
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(started, gate);
    let caller = {
        let runtime = Arc::clone(&runtime);
        let root = root.clone();
        tokio::spawn(async move { admit(&runtime, &root, &first).await })
    };
    reached(ready).await;
    let mutation = runtime.begin_category_root_mutation().await.unwrap();
    runtime
        .metadata
        .set_shared_root_accessible(&root, false)
        .unwrap();
    drop(mutation);
    release.send(()).unwrap();
    assert!(caller.await.unwrap().unwrap());
    runtime.drain_local_mutations().await.unwrap();
    let catalog = runtime.shared_catalog.read().await;
    let entry = catalog.entry_by_hash(&hash).unwrap();
    assert!(entry.verified_complete);
    assert_eq!(entry.publish.session_request_count, 23);
    assert_eq!(entry.all_time_uploaded_bytes, 47);
}
