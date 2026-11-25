use super::*;
use transfer::{Ed2kTransferRuntime, test_support::admit_download_job};

#[tokio::test]
async fn upload_caption_retains_read_charge_without_storage_or_resident_hydration() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let job = runtime
        .metadata
        .admit_download_job(&emulebb_metadata::DownloadJobRequest {
            file_hash: "6c".repeat(16),
            display_name: "Sample.bin".into(),
            expected_size_bytes: Some(0x4000000000),
            category_id: None,
            intent: emulebb_metadata::DownloadIntent::Stopped,
            piece_size: transfer::ED2K_PART_SIZE,
        })
        .unwrap()
        .job;
    let baseline = runtime.download_resource_snapshot().resident_bytes;
    let summary = runtime
        .upload_file_summary(&job.file_hash)
        .await
        .unwrap()
        .unwrap();
    reap_workers(&runtime.local_mutations).await;
    assert_eq!(summary.display_name, "Sample.bin");
    assert_eq!(summary.file_size, 0x4000000000);
    assert_eq!(summary.parts_obtained, 0);
    assert_eq!(
        runtime.download_resource_snapshot().resident_bytes,
        baseline
    );
    assert_eq!(
        runtime.download_resource_snapshot().transient_bytes,
        256 * 1024
    );
    assert!(runtime.manifest_cache.lock().await.is_empty());
    assert!(
        runtime
            .metadata
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .storage
            .is_none()
    );
    drop(summary);
    assert_eq!(runtime.download_resource_snapshot().transient_bytes, 0);
}

#[tokio::test]
async fn waiting_preparation_status_retains_transient_charge_without_resident_hydration() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let job = runtime
        .metadata
        .admit_download_job(&emulebb_metadata::DownloadJobRequest {
            file_hash: "5c".repeat(16),
            display_name: "Sample.bin".into(),
            expected_size_bytes: Some(0x4000000000),
            category_id: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            piece_size: transfer::ED2K_PART_SIZE,
        })
        .unwrap()
        .job;
    let baseline = runtime.download_resource_snapshot().resident_bytes;
    let parts = runtime
        .download_verified_parts(job.token)
        .await
        .unwrap()
        .unwrap();
    reap_workers(&runtime.local_mutations).await;
    assert_eq!(parts.file_size_bytes, 0x4000000000);
    assert_eq!(
        parts.verified_parts.len(),
        (0x4000000000u64).div_ceil(transfer::ED2K_PART_SIZE) as usize
    );
    assert!(parts.verified_parts.iter().all(|verified| !verified));
    assert_eq!(
        runtime.download_resource_snapshot().resident_bytes,
        baseline
    );
    assert_eq!(
        runtime.download_resource_snapshot().transient_bytes,
        128 * 1024
    );
    assert!(
        runtime
            .manifest_cache
            .lock()
            .await
            .get(&job.token.job_id)
            .is_none()
    );
    drop(parts);
    assert_eq!(runtime.download_resource_snapshot().transient_bytes, 0);
    assert!(
        runtime
            .download_job(job.token.job_id)
            .await
            .unwrap()
            .unwrap()
            .storage
            .is_none()
    );
}

async fn reap_workers(registry: &LocalMutationRegistry) {
    loop {
        let result =
            std::future::poll_fn(|cx| registry.state.lock().unwrap().tasks.poll_join_next(cx))
                .await;
        match result {
            Some(result) => assert_eq!(result.unwrap(), 0),
            None => break,
        }
    }
}

#[tokio::test]
async fn detail_and_large_part_reads_leave_the_manifest_cache_empty() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let job = runtime
        .metadata
        .admit_download_job(&emulebb_metadata::DownloadJobRequest {
            file_hash: "4b".repeat(16),
            display_name: "large.bin".into(),
            expected_size_bytes: Some(0x4000000000),
            category_id: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            piece_size: transfer::ED2K_PART_SIZE,
        })
        .unwrap()
        .job;
    let detail = runtime
        .download_detail(job.token.job_id)
        .await
        .unwrap()
        .unwrap();
    assert!(detail.job.storage.is_none());
    assert!(
        runtime
            .manifest_cache
            .lock()
            .await
            .get(&job.token.job_id)
            .is_none()
    );
    let page = runtime
        .download_parts_after(job.token.job_id, None, 200)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(page.parts.len(), 200);
    assert!(
        runtime
            .manifest_cache
            .lock()
            .await
            .get(&job.token.job_id)
            .is_none()
    );
}

#[tokio::test]
async fn received_page_conversion_retains_charge_after_reap() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    admit_download_job(
        &runtime,
        emulebb_kad_proto::Ed2kHash::from_bytes([71; 16]),
        "sample.bin".into(),
        16,
    );
    let page = runtime.download_jobs_after(None, 256, false).await.unwrap();
    assert_eq!(page.len(), 1);
    reap_workers(&runtime.local_mutations).await;
    let charge = 2 * 1024 * 1024 + 4096;
    let capacity = Arc::clone(&runtime.local_mutations.state.lock().unwrap().capacity);
    let headroom = capacity.reserve(MAX_BYTES - charge, false, false).unwrap();
    let converted = page.map(|rows| {
        rows.into_iter()
            .map(|row| row.display_name)
            .collect::<Vec<_>>()
    });
    assert_eq!(converted.as_slice(), &["sample.bin"]);
    assert_eq!(capacity.usage().bytes, MAX_BYTES);
    assert!(matches!(
        runtime
            .local_mutations
            .submit_job_read(&runtime, JobRead::Page(None, 1, false))
            .err()
            .unwrap()
            .downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Busy)
    ));
    let observed = runtime.local_mutations.capacity_revision();
    let waiting = runtime.local_mutations.wait_for_completion(observed);
    tokio::pin!(waiting);
    // Poll the real empty-task-set wait to Pending: a task-completion signal
    // cannot release this wait; the retained result's final drop must wake it.
    assert!(
        std::future::poll_fn(|cx| {
            std::task::Poll::Ready(std::future::Future::poll(waiting.as_mut(), cx))
        })
        .await
        .is_pending()
    );
    drop(converted);
    tokio::time::timeout(std::time::Duration::from_secs(2), waiting)
        .await
        .unwrap()
        .unwrap();
    let next = runtime.download_jobs_after(None, 1, false).await.unwrap();
    assert_eq!(capacity.usage().bytes, MAX_BYTES);
    drop(next);
    drop(headroom);
    runtime.local_mutations.seal_and_drain().await.unwrap();
    assert_eq!(capacity.usage().bytes, 0);
}

#[tokio::test]
async fn local_serving_read_releases_manifest_guard_while_waiting_for_capacity() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(root.path()).unwrap());
    let hash = emulebb_kad_proto::Ed2kHash([0x6c; 16]);
    let job = runtime
        .metadata
        .admit_download_job(&emulebb_metadata::DownloadJobRequest {
            file_hash: hash.to_string(),
            display_name: "Sample.bin".into(),
            expected_size_bytes: Some(transfer::ED2K_PART_SIZE),
            category_id: None,
            intent: emulebb_metadata::DownloadIntent::Stopped,
            piece_size: transfer::ED2K_PART_SIZE,
        })
        .unwrap()
        .job;
    let registry = Arc::clone(&runtime.local_mutations);
    let (started, ready) = oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    registry.install_publication_gate(started, gate);
    let page = registry
        .submit_job_read(&runtime, JobRead::Page(None, 1, false))
        .unwrap();
    ready.await.unwrap();

    let waiting = registry.signal_next_pending_wait();
    let serving = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { runtime.local_serving_view(&hash).await })
    };
    let test_timeout = std::time::Duration::from_secs(5);
    tokio::time::timeout(test_timeout, waiting)
        .await
        .expect("serving lookup must wait for read capacity")
        .unwrap();
    let guard = tokio::time::timeout(test_timeout, runtime.lock_manifest(job.token))
        .await
        .expect("serving lookup must drop the manifest guard before waiting");
    drop(guard);
    release.send(()).unwrap();
    drop(page.await.unwrap().unwrap());

    let view = serving.await.unwrap().unwrap().unwrap();
    assert_eq!(view.job_token, Some(job.token));
    assert!(!view.completed);
}

#[tokio::test]
async fn cancelled_read_receiver_and_drain_keep_actual_worker_charged() {
    for (request, expected) in [
        (JobRead::Page(None, 1, false), 2 * 1024 * 1024 + 4096),
        (
            JobRead::ServerPage(Default::default()),
            emulebb_metadata::SERVER_READ_MAX_BYTES,
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let registry = Arc::clone(&runtime.local_mutations);
        let (started, ready) = oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        registry.install_publication_gate(started, gate);
        let receipt = registry.submit_job_read(&runtime, request).unwrap();
        ready.await.unwrap();
        drop(receipt);
        let pending = registry.signal_next_pending_drain();
        let drain = {
            let registry = Arc::clone(&registry);
            tokio::spawn(async move { registry.seal_and_drain().await })
        };
        pending.await.unwrap();
        drain.abort();
        let _ = drain.await;
        let capacity = Arc::clone(&registry.state.lock().unwrap().capacity);
        assert_eq!(capacity.usage().bytes, expected);
        release.send(()).unwrap();
        registry.seal_and_drain().await.unwrap();
        assert_eq!(capacity.usage().bytes, 0);
        assert_eq!(capacity.usage().long_fs_units, 0);
        assert_eq!(capacity.usage().long_fs_bytes, 0);
    }
}

#[tokio::test]
async fn result_retains_only_capacity_control_without_runtime_or_task_set_cycle() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let registry = Arc::downgrade(&runtime.local_mutations);
    let capacity = Arc::downgrade(&runtime.local_mutations.state.lock().unwrap().capacity);
    let page = runtime.download_jobs_after(None, 1, false).await.unwrap();
    reap_workers(&runtime.local_mutations).await;
    drop(runtime);
    assert!(registry.upgrade().is_none());
    assert_eq!(
        capacity.upgrade().unwrap().usage().bytes,
        2 * 1024 * 1024 + 4096
    );
    drop(page);
    assert!(capacity.upgrade().is_none());
}

#[tokio::test]
async fn every_compact_result_variant_reuses_and_releases_the_registry_control() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let hash = [73; 16];
    let job = admit_download_job(
        &runtime,
        emulebb_kad_proto::Ed2kHash::from_bytes(hash),
        "compact.bin".into(),
        16,
    );
    let capacity = Arc::clone(&runtime.local_mutations.state.lock().unwrap().capacity);
    for request in [
        JobRead::Query(emulebb_metadata::DownloadJobQuery::default()),
        JobRead::Counts,
        JobRead::Waiting(vec![job.token.job_id]),
        JobRead::TransferCounts,
        JobRead::ServerPage(Default::default()),
        JobRead::Exact(job.token.job_id),
        JobRead::Detail(job.token.job_id),
        JobRead::Parts(job.token.job_id, None, 1),
        JobRead::Latest(hash),
        JobRead::Page(None, 1, false),
        JobRead::Publish(None, 1),
        JobRead::Endpoints(job.token, 0, 1, false),
        JobRead::Sources(job.token, 0, 1),
        JobRead::Comments(job.token, 0, 1),
        JobRead::Names(job.token, 0, 1),
        JobRead::Delivery(None, 1),
        JobRead::Retirement(None, 1),
        JobRead::Deletion(None, 1),
        JobRead::Removed(None, 1),
    ] {
        let result = runtime
            .local_mutations
            .submit_job_read(&runtime, request)
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        reap_workers(&runtime.local_mutations).await;
        assert!(capacity.usage().bytes > 0);
        assert_eq!(capacity.usage().long_fs_units, 0);
        assert_eq!(capacity.usage().long_fs_bytes, 0);
        drop(result);
        assert_eq!(capacity.usage().bytes, 0);
    }
    let missing = runtime
        .read_job_metadata(JobRead::Latest([74; 16]))
        .await
        .unwrap();
    reap_workers(&runtime.local_mutations).await;
    assert!(matches!(missing, JobReadResult::Exact(None)));
    assert_eq!(capacity.usage().bytes, 0);
}

#[tokio::test]
async fn native_queries_preserve_order_filter_and_retained_charge() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let first = admit_download_job(
        &runtime,
        emulebb_kad_proto::Ed2kHash::from_bytes([81; 16]),
        "first.bin".into(),
        16,
    );
    let second = admit_download_job(
        &runtime,
        emulebb_kad_proto::Ed2kHash::from_bytes([82; 16]),
        "second.bin".into(),
        16,
    );
    let page = runtime
        .query_download_jobs(emulebb_metadata::DownloadJobQuery {
            limit: 1,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(page.jobs[0].token.job_id, second.token.job_id);
    assert!(page.has_more);
    assert_eq!(page.next_before, Some(second.token.job_id));
    reap_workers(&runtime.local_mutations).await;
    let capacity = Arc::clone(&runtime.local_mutations.state.lock().unwrap().capacity);
    assert_eq!(capacity.usage().bytes, 2 * 1024 * 1024 + 4096);
    drop(page);
    let last = runtime
        .query_download_jobs(emulebb_metadata::DownloadJobQuery {
            before: Some(second.token.job_id),
            limit: 1,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(last.jobs[0].token.job_id, first.token.job_id);
    assert!(!last.has_more);
    drop(last);
    let counts = runtime.download_job_counts().await.unwrap();
    assert_eq!(counts.unfinished, 2);
    assert_eq!(counts.completed, 0);
    reap_workers(&runtime.local_mutations).await;
    assert_eq!(capacity.usage().bytes, 4096);
    drop(counts);
    assert_eq!(capacity.usage().bytes, 0);
    runtime.local_mutations.seal_and_drain().await.unwrap();
}

#[tokio::test]
async fn server_reads_share_capacity_and_release_missing_or_closed_results() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let page = runtime.server_page(Default::default()).await.unwrap();
    reap_workers(&runtime.local_mutations).await;
    let capacity = Arc::clone(&runtime.local_mutations.state.lock().unwrap().capacity);
    let charge = emulebb_metadata::SERVER_READ_MAX_BYTES;
    assert_eq!(capacity.usage().bytes, charge);
    let headroom = capacity.reserve(MAX_BYTES - charge, false, false).unwrap();
    let error = runtime.server_page(Default::default()).await.err().unwrap();
    assert!(matches!(
        error.downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Busy)
    ));
    let invalid = runtime
        .server_page(emulebb_metadata::MetadataServerQuery {
            limit: 0,
            ..Default::default()
        })
        .await
        .err()
        .unwrap();
    assert_eq!(
        invalid.downcast_ref::<emulebb_metadata::MetadataServerReadError>(),
        Some(&emulebb_metadata::MetadataServerReadError::InvalidQuery)
    );
    drop(page);
    drop(headroom);
    assert!(runtime.server_by_id(i64::MAX).await.unwrap().is_none());
    reap_workers(&runtime.local_mutations).await;
    assert_eq!(capacity.usage().bytes, 0);
    runtime.local_mutations.seal_and_drain().await.unwrap();
    let closed = runtime.server_by_id(1).await.err().unwrap();
    assert!(matches!(
        closed.downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Closing)
    ));
    assert_eq!(capacity.usage().bytes, 0);
}
