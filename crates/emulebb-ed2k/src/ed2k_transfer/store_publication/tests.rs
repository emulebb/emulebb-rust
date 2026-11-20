use super::super::{ED2K_PART_SIZE, Ed2kTransferRuntime, test_support::admit_download_job};
use emulebb_kad_proto::Ed2kHash;
use md4::{Digest, Md4};

async fn partial_job(runtime: &Ed2kTransferRuntime, bytes: &[u8]) -> super::super::Ed2kTransferJob {
    let first: [u8; 16] = Md4::digest(bytes).into();
    let last = [0x45; 16];
    let mut hasher = Md4::new();
    hasher.update(first);
    hasher.update(last);
    let hash = Ed2kHash::from_bytes(hasher.finalize().into());
    let job = admit_download_job(runtime, hash, "Sample.bin".into(), ED2K_PART_SIZE + 1024);
    drop(runtime.ensure_job(&job).await.unwrap());
    runtime
        .store_md4_hashset(job.token, vec![first, last])
        .await
        .unwrap();
    job
}

#[tokio::test]
async fn refused_whole_piece_store_never_advertises_uncommitted_ranges() {
    let root = crate::paths::unique_test_dir("store-refused-catalog");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let bytes = vec![3; ED2K_PART_SIZE as usize];
    let job = partial_job(&runtime, &bytes).await;
    let before = runtime
        .metadata
        .download_job_manifest(job.token.job_id)
        .unwrap()
        .unwrap();
    runtime
        .manifest_checkpoint_state
        .lock()
        .await
        .get_mut(&job.token)
        .unwrap()
        .revision = u64::MAX;
    let error = runtime
        .store_piece_data_unfinalized(job.token, 0, &bytes)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("revision exhausted"));
    let hash = job.file_hash.parse().unwrap();
    assert!(
        runtime
            .shared_catalog
            .read()
            .await
            .entry_by_hash(&hash)
            .is_none()
    );
    assert_eq!(
        runtime
            .metadata
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap(),
        before
    );
    assert!(
        runtime.manifest_cache.lock().await[&job.token.job_id]
            .verified_ranges
            .is_empty()
    );
    runtime
        .manifest_checkpoint_state
        .lock()
        .await
        .get_mut(&job.token)
        .unwrap()
        .revision = 0;
    runtime
        .store_piece_data_unfinalized(job.token, 0, &bytes)
        .await
        .unwrap();
    let catalog = runtime.shared_catalog.read().await;
    let entry = catalog.entry_by_hash(&hash).unwrap();
    assert!(entry.is_servable());
    assert_eq!(entry.complete_parts, vec![true, false]);
}

#[tokio::test]
async fn stale_progress_publication_keeps_current_operator_presentation() {
    let root = crate::paths::unique_test_dir("store-catalog-current-presentation");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let bytes = vec![3; ED2K_PART_SIZE as usize];
    let job = partial_job(&runtime, &bytes).await;
    runtime
        .store_piece_data_unfinalized(job.token, 0, &bytes)
        .await
        .unwrap();
    let stale = runtime.manifest(job.token).await.unwrap();
    runtime
        .metadata
        .update_shared_content_metadata(
            &job.file_hash,
            Some(("high", false)),
            Some(("Current operator comment", 4)),
        )
        .unwrap();
    runtime.upsert_verified_catalog_entry_cached(&stale).await;
    let catalog = runtime.shared_catalog.read().await;
    let entry = catalog
        .entry_by_hash(&job.file_hash.parse().unwrap())
        .unwrap();
    assert!(entry.is_servable());
    assert_eq!(entry.verified_ranges, stale.verified_ranges);
    assert_eq!(entry.upload_priority, "high");
    assert!(!entry.auto_upload_priority);
    assert_eq!(entry.comment, "Current operator comment");
    assert_eq!(entry.rating, 4);
}
