use super::super::{
    ED2K_PART_SIZE, Ed2kTransferJob, Ed2kTransferRuntime, test_support::admit_download_job,
};
use super::*;
use emulebb_metadata::{JobId, JobToken};

#[test]
fn maximum_geometry_membership_stays_charged_after_every_acknowledgment() {
    let control = Arc::new(ResidentControl::default());
    let manifest = Ed2kResumeManifest::new(&Ed2kTransferJob {
        token: JobToken {
            job_id: JobId::new(1).unwrap(),
            generation: 1,
        },
        file_hash: "11".repeat(16),
        display_name: "Sample.bin".into(),
        file_size: 0x4000000000,
        piece_size: ED2K_PART_SIZE,
    });
    let mut dirty = DirtyPieces::new(&control, &manifest).unwrap();
    assert_eq!(dirty.words.len() * size_of::<u64>(), 3_536);
    assert_eq!(control.used_bytes(), 3_536);
    for index in 0..dirty.piece_count {
        dirty.insert(index).unwrap();
        dirty.insert(index).unwrap();
    }
    assert_eq!(dirty.len(), manifest.pieces.len());
    assert_eq!(
        dirty.iter().collect::<Vec<_>>(),
        (0..dirty.piece_count).collect::<Vec<_>>()
    );
    assert!(dirty.insert(dirty.piece_count).is_err());
    for index in 0..dirty.piece_count {
        assert_eq!(dirty.first(), Some(index));
        dirty.remove(&index);
        dirty.remove(&index);
    }
    assert!(dirty.is_empty());
    assert_eq!(dirty.first(), None);
    assert_eq!(control.used_bytes(), 3_536);
    drop(dirty);
    assert_eq!(control.used_bytes(), 0);
}

#[tokio::test]
async fn replacement_bitmap_credit_refusal_precedes_sql_and_cache_mutation() {
    let root = crate::paths::unique_test_dir("checkpoint-bitmap-preadmission");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = admit_download_job(
        &runtime,
        "55".repeat(16).parse().unwrap(),
        "Sample.bin".into(),
        ED2K_PART_SIZE,
    );
    let old = runtime.ensure_job(&job).await.unwrap();
    let before = runtime
        .metadata
        .download_job_manifest(job.token.job_id)
        .unwrap()
        .unwrap();
    let control = &runtime.local_mutations.residents;
    let mut held = Vec::new();
    let allowance = super::super::resident::MANIFEST_BYTES;
    loop {
        let free = 128 * 1024 * 1024 - control.used_bytes();
        if free == allowance {
            break;
        }
        held.push(
            control
                .reserve_bookkeeping(job.token.job_id, (free - allowance).min(allowance))
                .unwrap(),
        );
    }
    // The ordinary mutable allowance fits exactly; only the new bitmap refuses.
    let io = runtime.lock_manifest(job.token).await;
    let mut proposal = (*old).clone();
    proposal.pieces[0].bytes_written = 32;
    let error = runtime
        .store_manifest_unlocked(&proposal, io.clone())
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Busy)
    ));
    assert_eq!(
        runtime
            .metadata
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap(),
        before
    );
    assert_eq!(
        &*runtime.manifest_cache.lock().await[&job.token.job_id],
        &*old
    );
    drop(held);
    runtime
        .store_manifest_unlocked(&proposal, io)
        .await
        .unwrap();
    assert_eq!(
        runtime.manifest_cache.lock().await[&job.token.job_id].pieces[0].bytes_written,
        32
    );
    assert_eq!(old.pieces[0].bytes_written, 0);
}
