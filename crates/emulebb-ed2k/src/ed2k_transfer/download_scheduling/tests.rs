use super::*;
use crate::ed2k_transfer::{ED2K_PART_SIZE, test_support::admit_download_job};
use emulebb_kad_proto::Ed2kHash;
use std::{sync::Arc, time::Duration};

#[tokio::test]
async fn yield_request_rechecks_protection_progress_and_current_execution() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(root.path()).unwrap());
    let job = admit_download_job(
        &runtime,
        Ed2kHash([0x73; 16]),
        "yield.bin".into(),
        3 * ED2K_PART_SIZE,
    );
    assert!(!runtime.request_download_yield(job.token, 0).await.unwrap());
    drop(runtime.ensure_job(&job).await.unwrap());
    let stale = JobToken {
        generation: job.token.generation + 1,
        ..job.token
    };
    assert!(!runtime.request_download_yield(stale, 0).await.unwrap());
    assert!(runtime.note_download_source_part_bitmap(
        job.token,
        "192.0.2.1:4662".parse().unwrap(),
        Some([1; 16]),
        None,
        vec![true, false, false]
    ));
    assert!(
        !runtime
            .download_scheduling_state(job.token)
            .await
            .unwrap()
            .unwrap()
            .acquiring_rare,
        "source availability alone is not active rare-part acquisition"
    );
    let rare_lease = runtime
        .lease_next_download_block(
            job.token,
            "192.0.2.1:4662".parse().unwrap(),
            Some(&[true, false, false]),
            None,
            0,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        !runtime.request_download_yield(job.token, 0).await.unwrap(),
        "current rare work is protected"
    );
    assert!(runtime.note_download_source_part_bitmap(
        job.token,
        "192.0.2.2:4662".parse().unwrap(),
        Some([2; 16]),
        None,
        vec![true, false, false]
    ));
    runtime.note_download_payload_bytes_at(job.token, 17, Instant::now());
    assert!(
        !runtime.request_download_yield(job.token, 0).await.unwrap(),
        "renewed progress invalidates the selection"
    );
    assert!(runtime.request_download_yield(job.token, 17).await.unwrap());
    assert!(runtime.download_yield_requested(job.token));
    assert!(
        runtime
            .lease_next_download_block(
                job.token,
                "192.0.2.1:4662".parse().unwrap(),
                Some(&[true, false, false]),
                None,
                0
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        runtime
            .metadata
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .intent,
        emulebb_metadata::DownloadIntent::Started
    );
    assert!(
        runtime
            .download_scheduling_state(job.token)
            .await
            .unwrap()
            .unwrap()
            .yielding
    );
    drop(rare_lease);
    runtime
        .release_download_job_execution(job.token)
        .await
        .unwrap();
    assert!(!runtime.download_yield_requested(job.token));
    runtime.local_mutations.seal_and_drain().await.unwrap();
}

#[tokio::test]
async fn scheduling_read_never_hydrates_waiting_jobs_and_refuses_a_busy_io_gate() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(root.path()).unwrap());
    let job = admit_download_job(
        &runtime,
        Ed2kHash([0x71; 16]),
        "waiting.bin".into(),
        3 * ED2K_PART_SIZE,
    );
    let before = runtime.download_resource_snapshot().resident_bytes;
    assert!(
        runtime
            .download_scheduling_state(job.token)
            .await
            .unwrap()
            .is_none()
    );
    assert!(runtime.manifest_cache.lock().await.is_empty());
    assert_eq!(runtime.download_resource_snapshot().resident_bytes, before);
    drop(runtime.ensure_job(&job).await.unwrap());
    let held = runtime.lock_manifest(job.token).await;
    let refused = tokio::time::timeout(
        Duration::from_secs(1),
        runtime.download_scheduling_state(job.token),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(matches!(
        refused.downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Busy)
    ));
    drop(held);
    let snapshot = runtime
        .download_scheduling_state(job.token)
        .await
        .unwrap()
        .unwrap();
    assert!(!snapshot.acquiring_rare && !snapshot.endgame);
    assert_eq!(
        (snapshot.session_bytes, snapshot.last_payload_at),
        (0, None)
    );
    let stale = JobToken {
        generation: job.token.generation + 1,
        ..job.token
    };
    assert!(
        runtime
            .download_scheduling_state(stale)
            .await
            .unwrap()
            .is_none()
    );
    runtime.local_mutations.seal_and_drain().await.unwrap();
}

#[tokio::test]
async fn scheduling_protection_uses_current_reporters_progress_and_endgame_at_full_residency() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(root.path()).unwrap());
    let job = admit_download_job(
        &runtime,
        Ed2kHash([0x72; 16]),
        "active.bin".into(),
        3 * ED2K_PART_SIZE,
    );
    drop(runtime.ensure_job(&job).await.unwrap());
    let now = Instant::now();
    for (last, identity) in [(1, [1; 16]), (2, [1; 16])] {
        assert!(runtime.note_download_source_part_bitmap_at(
            job.token,
            format!("192.0.2.{last}:4662").parse().unwrap(),
            Some(identity),
            None,
            vec![true, false, false],
            now
        ));
    }
    assert!(
        !runtime
            .download_scheduling_state(job.token)
            .await
            .unwrap()
            .unwrap()
            .acquiring_rare
    );
    let rare_lease = runtime
        .lease_next_download_block(
            job.token,
            "192.0.2.1:4662".parse().unwrap(),
            Some(&[true, false, false]),
            None,
            0,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        runtime
            .download_scheduling_state(job.token)
            .await
            .unwrap()
            .unwrap()
            .acquiring_rare
    );
    assert!(runtime.note_download_source_part_bitmap_at(
        job.token,
        "192.0.2.3:4662".parse().unwrap(),
        Some([2; 16]),
        None,
        vec![true, false, false],
        now
    ));
    runtime.note_download_payload_bytes_at(job.token, 17, now);
    let snapshot = runtime
        .download_scheduling_state(job.token)
        .await
        .unwrap()
        .unwrap();
    assert!(!snapshot.acquiring_rare && !snapshot.endgame);
    drop(rare_lease);
    assert_eq!(
        (snapshot.session_bytes, snapshot.last_payload_at),
        (17, Some(now))
    );
    assert!(
        runtime
            .source_frequencies_with_budget(job.token, 3, now, Some(13))
            .is_none(),
        "insufficient workspace refuses classification without truncating reporters"
    );
    assert_eq!(
        runtime.available_sources_per_part_at(job.token, 3, now),
        [2, 0, 0]
    );
    let write = runtime
        .local_mutations
        .residents
        .reserve(job.token.job_id)
        .unwrap();
    runtime
        .manifest_cache
        .lock()
        .await
        .get_mut(&job.token.job_id)
        .unwrap()
        .write_with(write, |manifest| {
            manifest.final_rehash_pending = true;
            Ok(())
        })
        .unwrap();
    let maximum = 128 * 1024 * 1024;
    let mut full = Vec::new();
    while let Ok(credit) = runtime.local_mutations.residents.reserve(job.token.job_id) {
        full.push(credit);
    }
    let remainder = maximum - runtime.download_resource_snapshot().resident_bytes;
    full.push(
        runtime
            .local_mutations
            .residents
            .reserve_bookkeeping(job.token.job_id, remainder)
            .unwrap(),
    );
    let snapshot = runtime
        .download_scheduling_state(job.token)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.endgame, "final verification remains protected");
    assert_eq!(runtime.download_resource_snapshot().resident_bytes, maximum);
    drop(full);
    runtime.local_mutations.seal_and_drain().await.unwrap();
}
