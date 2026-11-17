use super::super::{ED2K_PART_SIZE, test_support::admit_download_job};
use super::*;

#[tokio::test]
async fn combined_patch_uses_preadmitted_credit_and_old_progress_cannot_replay_scalars() {
    let (root, runtime) = runtime("download-scalar-patch");
    let category = runtime
        .metadata
        .create_category("Media", None, None, "", &root)
        .unwrap();
    let job = admit_download_job(
        &runtime,
        "73".repeat(16).parse().unwrap(),
        "Sample.bin".into(),
        ED2K_PART_SIZE,
    );
    let old = runtime.ensure_job(&job).await.unwrap();
    let patch = emulebb_metadata::MetadataDownloadPatch {
        name: Some("Renamed.bin".into()),
        category_id: Some(Some(category.id)),
        ..Default::default()
    };
    let plan = runtime
        .prepare_download_patch(job.token.job_id, &patch)
        .await
        .unwrap()
        .unwrap();
    let core_fence = plan.retain_fence();
    let worker_runtime = Arc::clone(&runtime);
    let (committed, ready) = tokio::sync::oneshot::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let (done, finished) = tokio::sync::oneshot::channel();
    let worker = tokio::task::spawn_blocking(move || {
        let value = worker_runtime
            .metadata
            .patch_download_job(plan.token(), &patch)
            .unwrap()
            .unwrap();
        committed.send(()).unwrap();
        resume.recv().unwrap();
        worker_runtime.publish_download_patch(plan, &value).unwrap();
        done.send(()).unwrap();
    });
    ready.await.unwrap();
    let mut held = Vec::new();
    while let Ok(credit) = runtime.local_mutations.residents.reserve(job.token.job_id) {
        held.push(credit);
    }
    worker.abort();
    drop(worker);
    release.send(()).unwrap();
    finished.await.unwrap();
    {
        let cache = runtime.manifest_cache.lock().await;
        assert_eq!(cache[&job.token.job_id].display_name, "Renamed.bin");
        assert_eq!(cache[&job.token.job_id].category_id, Some(category.id));
    }
    assert_eq!(old.display_name, "Sample.bin");
    assert_eq!(old.category_id, None);
    assert!(runtime.category_assignment_gate.try_read().is_err());
    drop(core_fence);
    drop(held);
    let refreshed = runtime.cache_manifest_unlocked(&old).await.unwrap();
    assert_eq!(refreshed.display_name, "Renamed.bin");
    assert_eq!(refreshed.category_id, Some(category.id));
}

#[tokio::test]
async fn scalar_patch_capacity_refusal_precedes_sql_and_noop_needs_no_replacement() {
    let (_, runtime) = runtime("download-scalar-patch-pressure");
    let job = admit_download_job(
        &runtime,
        "74".repeat(16).parse().unwrap(),
        "Sample.bin".into(),
        ED2K_PART_SIZE,
    );
    drop(runtime.ensure_job(&job).await.unwrap());
    let mut held = Vec::new();
    while let Ok(credit) = runtime.local_mutations.residents.reserve(job.token.job_id) {
        held.push(credit);
    }
    let patch = emulebb_metadata::MetadataDownloadPatch {
        name: Some("Renamed.bin".into()),
        ..Default::default()
    };
    let error = runtime
        .prepare_download_patch(job.token.job_id, &patch)
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error.downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Busy)
    ));
    assert_eq!(
        runtime
            .metadata
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .display_name,
        "Sample.bin"
    );
    assert!(runtime.category_assignment_gate.try_read().is_ok());
    let noop = emulebb_metadata::MetadataDownloadPatch {
        name: Some("Sample.bin".into()),
        ..Default::default()
    };
    let plan = runtime
        .prepare_download_patch(job.token.job_id, &noop)
        .await
        .unwrap()
        .unwrap();
    let worker_runtime = Arc::clone(&runtime);
    tokio::task::spawn_blocking(move || {
        let value = worker_runtime
            .metadata
            .patch_download_job(plan.token(), &noop)
            .unwrap()
            .unwrap();
        assert!(!value.changed);
        worker_runtime.publish_download_patch(plan, &value).unwrap();
    })
    .await
    .unwrap();
    drop(held);
}

fn runtime(label: &str) -> (std::path::PathBuf, Arc<Ed2kTransferRuntime>) {
    let root = crate::paths::unique_test_dir(label);
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    (root, runtime)
}

#[tokio::test]
async fn prepared_assignment_finishes_after_commit_and_request_cancellation_under_pressure() {
    let (root, runtime) = runtime("category-cache-prepared");
    let category = runtime
        .metadata
        .create_category("Sample", None, None, "", &root)
        .unwrap();
    let job = admit_download_job(
        &runtime,
        "61".repeat(16).parse().unwrap(),
        "Sample.bin".into(),
        ED2K_PART_SIZE,
    );
    let old = runtime.ensure_job(&job).await.unwrap();
    let plan = runtime
        .prepare_category_assignment(job.token.job_id, Some(category.id))
        .await
        .unwrap();
    let core_fence = plan.retain_fence();
    let metadata = runtime.metadata.clone();
    let (committed, ready) = tokio::sync::oneshot::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let (done, finished) = tokio::sync::oneshot::channel();
    let worker = tokio::task::spawn_blocking(move || {
        assert!(
            metadata
                .assign_transfer_category(job.token.job_id, Some(category.id))
                .unwrap()
        );
        committed.send(()).unwrap();
        resume.recv().unwrap();
        plan.publish().unwrap();
        done.send(()).unwrap();
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), ready)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        runtime.manifest_cache.lock().await[&job.token.job_id].category_id,
        None
    );
    let mut held = Vec::new();
    while let Ok(permit) = runtime.local_mutations.residents.reserve(job.token.job_id) {
        held.push(permit);
    }
    // The actual blocking owner already started. Cancelling observation does
    // not cancel SQL/cache publication or release its preadmitted credit.
    worker.abort();
    drop(worker);
    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), finished)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        runtime.manifest_cache.lock().await[&job.token.job_id].category_id,
        Some(category.id)
    );
    assert_eq!(old.category_id, None);
    assert_eq!(
        runtime
            .metadata
            .download_job_category(job.token.job_id)
            .unwrap(),
        Some(Some(category.id))
    );
    assert!(runtime.category_assignment_gate.try_read().is_err());
    drop(core_fence);
    assert!(runtime.category_assignment_gate.try_read().is_ok());
    drop(held);
}

#[tokio::test]
async fn failed_category_admission_leaves_sql_and_cache_unchanged_and_releases_fence() {
    let (root, runtime) = runtime("category-cache-pressure");
    let category = runtime
        .metadata
        .create_category("Sample", None, None, "", &root)
        .unwrap();
    let job = admit_download_job(
        &runtime,
        "62".repeat(16).parse().unwrap(),
        "Sample.bin".into(),
        ED2K_PART_SIZE,
    );
    drop(runtime.ensure_job(&job).await.unwrap());
    let mut held = Vec::new();
    while let Ok(permit) = runtime.local_mutations.residents.reserve(job.token.job_id) {
        held.push(permit);
    }
    let error = runtime
        .prepare_category_assignment(job.token.job_id, Some(category.id))
        .await
        .err()
        .expect("full budget must refuse before SQL");
    assert!(matches!(
        error.downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Busy)
    ));
    assert_eq!(
        runtime
            .metadata
            .download_job_category(job.token.job_id)
            .unwrap(),
        Some(None)
    );
    assert_eq!(
        runtime.manifest_cache.lock().await[&job.token.job_id].category_id,
        None
    );
    drop(held);
    let plan = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        runtime.prepare_category_assignment(job.token.job_id, Some(category.id)),
    )
    .await
    .unwrap()
    .unwrap();
    let metadata = runtime.metadata.clone();
    tokio::task::spawn_blocking(move || {
        metadata
            .assign_transfer_category(job.token.job_id, Some(category.id))
            .unwrap();
        plan.publish().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn category_removal_publishes_all_prepared_members_and_preserves_old_readers() {
    let (root, runtime) = runtime("category-cache-remove");
    let category = runtime
        .metadata
        .create_category("Sample", None, None, "", &root)
        .unwrap();
    let mut old = Vec::new();
    for hash in ["63", "64"] {
        let job = admit_download_job(
            &runtime,
            hash.repeat(16).parse().unwrap(),
            "Sample.bin".into(),
            ED2K_PART_SIZE,
        );
        runtime
            .metadata
            .assign_transfer_category(job.token.job_id, Some(category.id))
            .unwrap();
        old.push(runtime.ensure_job(&job).await.unwrap());
    }
    let plan = runtime.prepare_category_removal(category.id).await.unwrap();
    let metadata = runtime.metadata.clone();
    tokio::task::spawn_blocking(move || {
        assert!(metadata.delete_category(category.id, &root).unwrap());
        plan.publish().unwrap();
    })
    .await
    .unwrap();
    let cache = runtime.manifest_cache.lock().await;
    assert!(
        cache
            .values()
            .all(|manifest| manifest.category_id.is_none())
    );
    assert!(
        old.iter()
            .all(|manifest| manifest.category_id == Some(category.id))
    );
}
