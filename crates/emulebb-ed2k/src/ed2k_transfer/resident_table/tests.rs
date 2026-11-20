use super::super::{ED2K_PART_SIZE, Ed2kTransferRuntime, test_support::admit_download_job};
use super::*;

#[test]
fn sorted_storage_keeps_spare_capacity_charged_until_empty() {
    let control = Arc::new(ResidentControl::default());
    let mut table = ResidentTable::<u64, u64>::new(Arc::clone(&control)).unwrap();
    let fixed = table.charged_bytes();
    for key in (0..64).rev() {
        let claim = table.claim_insert().unwrap();
        table.insert_claimed(key, key + 100, claim);
        assert_eq!(control.used_bytes(), table.charged_bytes());
    }
    assert_eq!(
        table.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
        (0..64).collect::<Vec<_>>()
    );
    let retained = table.charged_bytes();
    for key in 1..64 {
        assert_eq!(table.remove(&key), Some(key + 100));
    }
    assert_eq!(table.get(&0), Some(&100));
    assert_eq!(table.charged_bytes(), retained);
    assert_eq!(table.remove(&0), Some(100));
    assert_eq!(control.used_bytes(), fixed);
    drop(table);
    assert_eq!(control.used_bytes(), 0);
}

#[test]
fn accepted_claims_survive_full_budget_other_insertions_removal_and_rollback() {
    let control = Arc::new(ResidentControl::default());
    let mut table = ResidentTable::<u64, u64>::new(Arc::clone(&control)).unwrap();
    let fixed = table.charged_bytes();
    let first = table.claim_insert().unwrap();
    let second = table.claim_insert().unwrap();
    let cancelled = table.claim_insert().unwrap();
    let held = control
        .reserve_bytes(128 * 1024 * 1024 - control.used_bytes())
        .unwrap();
    table.insert_claimed(2, 20, first);
    assert_eq!(table.remove(&2), Some(20));
    assert!(table.entries.capacity() >= 2);
    std::thread::spawn(move || drop(cancelled)).join().unwrap();
    table.insert_claimed(1, 10, second);
    assert_eq!(table.get(&1), Some(&10));
    assert_eq!(table.remove(&1), Some(10));
    drop(held);
    assert_eq!(control.used_bytes(), fixed);
    // An abandoned empty-table insertion leaves only charged spare until edit.
    let cancelled = table.claim_insert().unwrap();
    drop(cancelled);
    assert!(table.charged_bytes() > fixed);
    table.reclaim_empty();
    assert_eq!(control.used_bytes(), fixed);
}

#[test]
fn growth_requires_peak_old_and_new_backing_before_moving_any_entry() {
    let control = Arc::new(ResidentControl::default());
    let mut table = ResidentTable::<u64, u64>::new(Arc::clone(&control)).unwrap();
    let claim = table.claim_insert().unwrap();
    table.insert_claimed(1, 10, claim);
    assert_eq!(table.entries.capacity(), 1);
    let peak = 2 * size_of::<(u64, u64)>();
    let held = control
        .reserve_bytes(128 * 1024 * 1024 - control.used_bytes() - (peak - 1))
        .unwrap();
    let error = table.claim_insert().unwrap_err();
    assert!(matches!(
        error.downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Busy)
    ));
    assert_eq!(table.entries.capacity(), 1);
    assert_eq!(table.get(&1), Some(&10));
    assert_eq!(table.claims.pending.load(Ordering::Acquire), 0);
    drop(held);
    let claim = table.claim_insert().unwrap();
    table.insert_claimed(2, 20, claim);
    assert_eq!(table.get(&1), Some(&10));
    assert_eq!(table.get(&2), Some(&20));
    assert_eq!(control.used_bytes(), table.charged_bytes());
}

#[tokio::test]
async fn checkpoint_table_growth_refusal_precedes_progress_sql_and_publication() {
    let root = crate::paths::unique_test_dir("checkpoint-table-preadmission");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = admit_download_job(
        &runtime,
        "77".repeat(16).parse().unwrap(),
        "Sample.bin".into(),
        ED2K_PART_SIZE,
    );
    let old = runtime.ensure_job(&job).await.unwrap();
    assert_eq!(
        runtime
            .manifest_checkpoint_state
            .lock()
            .await
            .entries
            .capacity(),
        1
    );
    let before = runtime
        .metadata
        .download_job_manifest(job.token.job_id)
        .unwrap()
        .unwrap();
    let control = &runtime.local_mutations.residents;
    // Manifest and bitmap credit fit; peak table replacement backing does not.
    let free = super::super::resident::MANIFEST_BYTES + size_of::<u64>();
    let held = control
        .reserve_bytes(128 * 1024 * 1024 - control.used_bytes() - free)
        .unwrap();
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
    assert_eq!(
        runtime
            .manifest_checkpoint_state
            .lock()
            .await
            .entries
            .capacity(),
        1
    );
    drop(held);
    runtime
        .store_manifest_unlocked(&proposal, io)
        .await
        .unwrap();
    assert_eq!(
        runtime
            .metadata
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap()
            .pieces[0]
            .prefix_bytes,
        32
    );
    assert_eq!(
        runtime.manifest_cache.lock().await[&job.token.job_id].pieces[0].bytes_written,
        32
    );
    assert_eq!(old.pieces[0].bytes_written, 0);
}
