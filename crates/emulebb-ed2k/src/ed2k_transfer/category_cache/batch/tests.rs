use super::super::super::{ED2K_PART_SIZE, test_support::admit_download_job};
use super::*;

#[tokio::test]
async fn large_category_cut_retains_readers_and_writers_through_cancelled_observation() {
    let root = crate::paths::unique_test_dir("category-resident-byte-cohort");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let category = runtime
        .metadata
        .create_category("Sample", None, None, "", &root)
        .unwrap();
    let mut old = Vec::new();
    for id in 1..=32 {
        let job = admit_download_job(
            &runtime,
            format!("{id:032x}").parse().unwrap(),
            "Sample.bin".into(),
            ED2K_PART_SIZE,
        );
        runtime
            .metadata
            .assign_transfer_category(job.token.job_id, Some(category.id))
            .unwrap();
        old.push(runtime.ensure_job(&job).await.unwrap());
    }
    let token = old[0].token;
    let mut proposal = (*old[0]).clone();
    proposal.pieces[0].bytes_written = 32;
    let request = runtime.prepare_category_removal(category.id).await.unwrap();
    let core_fence = request.retain_fence();
    let control = Arc::clone(&runtime.local_mutations.residents);
    let worker_control = Arc::clone(&control);
    let metadata = runtime.metadata.clone();
    let (prepared, ready) = tokio::sync::oneshot::channel();
    let (commit, commit_now) = std::sync::mpsc::channel();
    let (committed, sql_done) = tokio::sync::oneshot::channel();
    let (publish, publish_now) = std::sync::mpsc::channel();
    let (finished, done) = tokio::sync::oneshot::channel();
    let worker = tokio::task::spawn_blocking(move || {
        let before = worker_control.used_bytes();
        let plan = request.prepare().unwrap();
        prepared.send(worker_control.used_bytes() - before).unwrap();
        commit_now.recv().unwrap();
        assert!(metadata.delete_category(category.id, &root).unwrap());
        committed.send(()).unwrap();
        publish_now.recv().unwrap();
        plan.publish().unwrap();
        finished.send(()).unwrap();
    });
    let extra = tokio::time::timeout(std::time::Duration::from_secs(10), ready)
        .await
        .unwrap()
        .unwrap();
    assert!(
        extra > 0 && extra < 1024 * 1024,
        "small category copies must use actual retained backing"
    );
    assert!(runtime.manifest_cache.try_lock().is_err());
    let reader_runtime = Arc::clone(&runtime);
    let reader = tokio::spawn(async move { reader_runtime.manifest(token).await });
    let writer_runtime = Arc::clone(&runtime);
    let (started, starting) = tokio::sync::oneshot::channel();
    let writer = tokio::spawn(async move {
        started.send(()).unwrap();
        writer_runtime.cache_manifest_unlocked(&proposal).await
    });
    starting.await.unwrap();
    let held = control
        .reserve_bytes(128 * 1024 * 1024 - control.used_bytes())
        .unwrap();
    commit.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), sql_done)
        .await
        .unwrap()
        .unwrap();
    assert!(!reader.is_finished());
    assert!(!writer.is_finished());
    worker.abort();
    drop(worker);
    publish.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), done)
        .await
        .unwrap()
        .unwrap();
    let current = tokio::time::timeout(std::time::Duration::from_secs(10), reader)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(current.category_id, None);
    assert!(
        old.iter()
            .all(|value| value.category_id == Some(category.id))
    );
    assert!(!writer.is_finished());
    {
        let cache = runtime.manifest_cache.lock().await;
        assert_eq!(cache.values().count(), 32);
        assert!(cache.values().all(|value| value.category_id.is_none()));
    }
    drop(held);
    drop(core_fence);
    let current = tokio::time::timeout(std::time::Duration::from_secs(10), writer)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(current.category_id, None);
    assert_eq!(current.pieces[0].bytes_written, 32);
    assert_eq!(old[0].pieces[0].bytes_written, 0);
}
