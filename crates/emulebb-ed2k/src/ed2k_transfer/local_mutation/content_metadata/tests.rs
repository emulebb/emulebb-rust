use super::*;
use emulebb_kad_proto::Ed2kHash;
use md4::Digest;
use transfer::test_support::admit_download_job;

const BYTES: &[u8] = b"sample verified upload request payload";

async fn payload() -> (
    tempfile::TempDir,
    Arc<transfer::Ed2kTransferRuntime>,
    Ed2kHash,
) {
    let root = tempfile::tempdir().unwrap();
    let runtime = Arc::new(transfer::Ed2kTransferRuntime::load_or_create(root.path()).unwrap());
    let hash = Ed2kHash::from_bytes(md4::Md4::digest(BYTES).into());
    let job = admit_download_job(&runtime, hash, "Sample.bin".into(), BYTES.len() as u64);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(job.token, Vec::new())
        .await
        .unwrap();
    runtime
        .append_piece_block(job.token, 0, 0, BYTES.len() as u64, BYTES)
        .await
        .unwrap();
    runtime
        .persist_content_metadata(hash, Some(("high", false)), None)
        .await
        .unwrap();
    (root, runtime, hash)
}

#[tokio::test]
async fn sharing_mutation_blocks_new_grants_preserves_accepted_reader_and_restores_priority() {
    let (_root, runtime, hash) = payload().await;
    let (_, mut accepted) = runtime
        .admit_upload_reader(&hash, None)
        .await
        .unwrap()
        .unwrap();
    assert!(
        runtime
            .servable_shared_file_hashes()
            .await
            .contains(&hash.to_string())
    );
    assert_eq!(
        runtime
            .set_library_sharing_enabled(hash, false)
            .await
            .unwrap(),
        Some(true)
    );
    assert!(runtime.local_servable_entry(&hash).await.unwrap().is_none());
    assert!(
        !runtime
            .servable_shared_file_hashes()
            .await
            .contains(&hash.to_string())
    );
    assert!(
        runtime
            .admit_upload_reader(&hash, None)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        runtime
            .read_verified_range_with_reader(&mut accepted, 0, BYTES.len() as u64, 0)
            .await
            .unwrap(),
        Some(BYTES.to_vec())
    );
    // An idle cached reader conveys no entitlement to another request.
    assert!(
        runtime
            .admit_upload_reader(&hash, Some(accepted))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        runtime
            .set_library_sharing_enabled(hash, false)
            .await
            .unwrap(),
        Some(false)
    );
    assert_eq!(
        runtime
            .set_library_sharing_enabled(hash, true)
            .await
            .unwrap(),
        Some(true)
    );
    let (entry, _) = runtime
        .admit_upload_reader(&hash, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.upload_priority, "high");
    let missing = Ed2kHash::from_bytes([0xff; 16]);
    assert_eq!(
        runtime
            .set_library_sharing_enabled(missing, false)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        runtime
            .metadata
            .library_sharing_enabled(&missing.to_string())
            .unwrap(),
        None
    );
    runtime.drain_local_mutations().await.unwrap();
}

#[tokio::test]
async fn cancelled_sharing_writer_finishes_publication_before_drain_returns() {
    let (_root, runtime, hash) = payload().await;
    let (started, ready) = oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(started, gate);
    let caller = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { runtime.set_library_sharing_enabled(hash, false).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), ready)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        runtime
            .metadata
            .library_sharing_enabled(&hash.to_string())
            .unwrap(),
        Some(false)
    );
    assert!(
        runtime
            .share_eligibility
            .stripe_snapshot(&[hash.0])
            .is_none()
    );
    assert!(
        runtime
            .admit_upload_reader(&hash, None)
            .await
            .unwrap()
            .is_none()
    );
    caller.abort();
    let _ = caller.await;
    let pending = runtime.local_mutations.signal_next_pending_drain();
    let drain = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { runtime.drain_local_mutations().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap();
    assert!(!drain.is_finished());
    release.send(()).unwrap();
    drain.await.unwrap().unwrap();
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
            .is_some()
    );
}

#[tokio::test]
async fn disabled_payload_stays_unpublished_after_restart_and_hydration() {
    let (root, runtime, hash) = payload().await;
    runtime
        .set_library_sharing_enabled(hash, false)
        .await
        .unwrap();
    runtime.drain_local_mutations().await.unwrap();
    drop(runtime);
    let runtime = transfer::Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    runtime.hydrate_initial_shared_catalog().await.unwrap();
    runtime.hydrate_shared_catalog().await.unwrap();
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
            .admit_upload_reader(&hash, None)
            .await
            .unwrap()
            .is_none()
    );
    runtime
        .set_library_sharing_enabled(hash, true)
        .await
        .unwrap();
    assert!(
        runtime
            .admit_upload_reader(&hash, None)
            .await
            .unwrap()
            .is_some()
    );
    runtime.drain_local_mutations().await.unwrap();
}

#[tokio::test]
async fn disabled_complete_copy_cannot_replace_the_admitted_partial_reader() {
    let root = tempfile::tempdir().unwrap();
    let runtime = transfer::Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let first = vec![1u8; transfer::ED2K_PART_SIZE as usize];
    let last = [2u8; 7];
    let source = root.path().join("Sample Complete.bin");
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&source).unwrap();
        file.write_all(&first).unwrap();
        file.write_all(&last).unwrap();
    }
    let local = runtime
        .ingest_local_file(&source, "Sample Complete.bin")
        .await
        .unwrap();
    transfer::test_support::admit_local_share(&runtime, root.path(), &source).await;
    let hash: Ed2kHash = local.file_hash.parse().unwrap();
    let job = admit_download_job(
        &runtime,
        hash,
        "Sample Partial.bin".into(),
        first.len() as u64 + 7,
    );
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(
            job.token,
            vec![
                md4::Md4::digest(&first).into(),
                md4::Md4::digest(last).into(),
            ],
        )
        .await
        .unwrap();
    runtime
        .store_piece_data(job.token, 0, &first)
        .await
        .unwrap();
    let (complete, cached) = runtime
        .admit_upload_reader(&hash, None)
        .await
        .unwrap()
        .unwrap();
    assert!(complete.verified_complete);
    runtime
        .set_library_sharing_enabled(hash, false)
        .await
        .unwrap();
    let (partial, mut reader) = runtime
        .admit_upload_reader(&hash, Some(cached))
        .await
        .unwrap()
        .unwrap();
    assert!(!partial.verified_complete);
    assert_eq!(
        runtime
            .read_verified_range_with_reader(&mut reader, 0, 128, 0)
            .await
            .unwrap(),
        Some(vec![1; 128])
    );
    assert!(
        runtime
            .read_verified_range_with_reader(
                &mut reader,
                first.len() as u64,
                first.len() as u64 + 7,
                0
            )
            .await
            .unwrap()
            .is_none()
    );
    runtime
        .ingest_local_file(&source, "Sample Complete.bin")
        .await
        .unwrap();
    transfer::test_support::admit_local_share(&runtime, root.path(), &source).await;
    let manifest = runtime.manifest(job.token).await.unwrap();
    runtime
        .upsert_verified_catalog_entry_cached(&manifest)
        .await;
    let entry = runtime.local_servable_entry(&hash).await.unwrap().unwrap();
    assert!(!entry.verified_complete);
    assert_eq!(
        runtime.admit_shared_hashes(&[hash.0], true).await.unwrap(),
        Some(vec![false])
    );
    runtime
        .set_library_sharing_enabled(hash, true)
        .await
        .unwrap();
    assert!(
        runtime
            .admit_upload_reader(&hash, None)
            .await
            .unwrap()
            .unwrap()
            .0
            .verified_complete
    );
    runtime.drain_local_mutations().await.unwrap();
}
