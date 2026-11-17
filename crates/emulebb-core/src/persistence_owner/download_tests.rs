use super::*;
use crate::{DownloadAction, DownloadChange, DownloadControlError, EmulebbCore};
use emulebb_index::FileIndex;
use emulebb_metadata::{DownloadIntent, DownloadJobRequest, JobId, JobToken};

fn setup() -> (Arc<EmulebbCore>, Arc<PersistenceOwner>) {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    (core, owner)
}

fn job(core: &EmulebbCore, value: u8, category_id: Option<i64>) -> JobToken {
    core.metadata_store
        .admit_download_job(&DownloadJobRequest {
            file_hash: hex::encode([value; 16]),
            display_name: "Sample.bin".into(),
            expected_size_bytes: None,
            piece_size: emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE,
            category_id,
            intent: DownloadIntent::Started,
        })
        .unwrap()
        .job
        .token
}

#[tokio::test]
async fn verification_survives_abort_drains_execution_and_does_not_block_other_commands() {
    let (core, owner) = setup();
    let first = job(&core, 0x61, None);
    let last = job(&core, 0x62, None);
    let execution = core
        .download_attempts
        .try_enter(first, crate::Ed2kHash::from_bytes([0x61; 16]))
        .unwrap();
    let caller = {
        let core = Arc::clone(&core);
        tokio::spawn(async move {
            core.control_downloads(DownloadAction::Verify, &[first.job_id, last.job_id])
                .await
        })
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        execution.cancellation().cancelled(),
    )
    .await
    .unwrap();
    assert_eq!(core.download_attempts.verifications(), vec![first]);
    caller.abort();
    assert!(caller.await.is_err_and(|error| error.is_cancelled()));
    // This command must finish while verification is still waiting for the old
    // network producer. No detached receipt owns the admitted batch.
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        owner.add("ab".repeat(16), "Peer".into()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(core.download_attempts.verifications(), vec![first]);
    drop(execution);
    owner.close_and_drain().await.unwrap();
    for token in [first, last] {
        let job = core
            .metadata_store
            .download_job(token.job_id)
            .unwrap()
            .unwrap();
        assert_eq!(job.intent, DownloadIntent::Started);
        assert!(job.storage.is_none());
        assert!(job.storage_failure.is_none());
    }
    assert!(core.download_attempts.verifications().is_empty());
    assert_eq!(tests::usage(&owner), (0, 0));
}

#[tokio::test]
async fn verification_preserves_stopped_intent_and_continues_after_item_failure() {
    let (core, owner) = setup();
    let broken = verified_payload(&core, b"missing internal payload").await;
    let directory = core
        .ed2k_transfers
        .transfer_dir_path(broken.job_id)
        .unwrap();
    std::fs::remove_file(directory.join("pieces.bin")).unwrap();
    let stopped = job(&core, 0x64, None);
    core.metadata_store.stop_download_job(stopped).unwrap();
    let stopped = core
        .metadata_store
        .download_job(stopped.job_id)
        .unwrap()
        .unwrap();
    let batch = core
        .control_downloads(
            DownloadAction::Verify,
            &[
                broken.job_id,
                stopped.token.job_id,
                JobId::new(999).unwrap(),
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        batch.results()[0].outcome,
        Err(DownloadControlError::Failed)
    );
    assert_eq!(batch.results()[1].outcome, Ok(DownloadChange::Unchanged));
    assert_eq!(batch.results()[2].outcome, Ok(DownloadChange::NotFound));
    assert_eq!(
        core.metadata_store
            .download_job(stopped.token.job_id)
            .unwrap()
            .unwrap(),
        stopped
    );
    assert!(core.download_attempts.verifications().is_empty());
    drop(batch);
    owner.close_and_drain().await.unwrap();
    assert_eq!(tests::usage(&owner), (0, 0));
}

async fn verified_payload(core: &EmulebbCore, payload: &[u8]) -> JobToken {
    use md4::{Digest, Md4};
    let hash = crate::Ed2kHash::from_bytes(Md4::digest(payload).into());
    let admitted = core
        .metadata_store
        .admit_download_job(&DownloadJobRequest {
            file_hash: hash.to_string(),
            display_name: "Verify.bin".into(),
            expected_size_bytes: Some(payload.len() as u64),
            category_id: None,
            intent: DownloadIntent::Started,
            piece_size: emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE,
        })
        .unwrap()
        .job;
    let token = core
        .metadata_store
        .start_download_job(admitted.token, &core.transfer_root)
        .unwrap()
        .unwrap()
        .token;
    let job = emulebb_ed2k::ed2k_transfer::new_transfer_job(
        token,
        hash,
        "Verify.bin".into(),
        payload.len() as u64,
    );
    drop(core.ed2k_transfers.ensure_job(&job).await.unwrap());
    drop(
        core.ed2k_transfers
            .store_md4_hashset(token, Vec::new())
            .await
            .unwrap(),
    );
    core.ed2k_transfers
        .store_piece_data(token, 0, payload)
        .await
        .unwrap();
    token
}

#[tokio::test]
async fn explicit_verify_preserves_storage_failure_and_stopped_intent_with_real_payloads() {
    let (core, owner) = setup();
    let token = verified_payload(&core, b"failed storage payload").await;
    let failure =
        emulebb_metadata::DownloadJobStorageFailure::new("STORAGE_WRITE_FAILED", "full disk", 123)
            .unwrap();
    let failed = core
        .ed2k_transfers
        .fail_download_job_storage(token, &failure)
        .await
        .unwrap();
    assert!(failed.applied);
    let token = failed.job.as_ref().unwrap().token;
    drop(failed);
    assert_eq!(
        core.verify_download(token.job_id).await.unwrap(),
        DownloadChange::Changed
    );
    let after = core
        .metadata_store
        .download_job(token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(after.intent, DownloadIntent::Started);
    assert_eq!(after.storage_failure, Some(failure));
    assert!(after.completed_at_s.is_none());
    let stopped = verified_payload(&core, b"stopped storage payload").await;
    assert_eq!(
        core.stop_download(stopped.job_id).await.unwrap(),
        DownloadChange::Changed
    );
    assert_eq!(
        core.verify_download(stopped.job_id).await.unwrap(),
        DownloadChange::Changed
    );
    assert_eq!(
        core.metadata_store
            .download_job(stopped.job_id)
            .unwrap()
            .unwrap()
            .intent,
        DownloadIntent::Stopped
    );
    assert!(core.download_attempts.snapshot().is_empty());
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn completed_verification_reports_output_damage_without_reopening_history() {
    let (core, owner) = setup();
    let payload = b"completed output payload";
    let token = verified_payload(&core, payload).await;
    core.ed2k_transfers
        .materialize_completed_payload(token, &core.transfer_root.join("incoming"))
        .await
        .unwrap();
    let (output, _) = core
        .ed2k_transfers
        .register_delivered_local_content(token)
        .await
        .unwrap();
    assert!(
        core.ed2k_transfers
            .complete_download_job(token)
            .await
            .unwrap()
    );
    assert!(
        core.ed2k_transfers
            .retire_download_storage(token.job_id)
            .await
            .unwrap()
    );
    let before = core
        .metadata_store
        .download_job(token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        core.verify_download(token.job_id).await.unwrap(),
        DownloadChange::Changed
    );
    std::fs::write(&output, vec![b'x'; payload.len()]).unwrap();
    let error = core.verify_download(token.job_id).await.unwrap_err();
    assert_eq!(
        error.downcast_ref::<DownloadControlError>(),
        Some(&DownloadControlError::OutputDamaged)
    );
    std::fs::remove_file(&output).unwrap();
    let error = core.verify_download(token.job_id).await.unwrap_err();
    assert_eq!(
        error.downcast_ref::<DownloadControlError>(),
        Some(&DownloadControlError::OutputMissing)
    );
    assert_eq!(
        core.metadata_store
            .download_job(token.job_id)
            .unwrap()
            .unwrap(),
        before
    );
    assert!(core.download_attempts.snapshot().is_empty());
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn verification_batch_larger_than_resident_cohort_releases_each_stopped_view() {
    let (core, owner) = setup();
    let mut ids = Vec::new();
    for index in 0..20 {
        let payload = format!("bounded verification payload {index}");
        let token = verified_payload(&core, payload.as_bytes()).await;
        assert_eq!(
            core.stop_download(token.job_id).await.unwrap(),
            DownloadChange::Changed
        );
        ids.push(token.job_id);
    }
    let batch = core
        .control_downloads(DownloadAction::Verify, &ids)
        .await
        .unwrap();
    assert_eq!(batch.results().len(), ids.len());
    for result in batch.results() {
        assert_eq!(result.outcome, Ok(DownloadChange::Changed));
        assert_eq!(
            core.metadata_store
                .download_job(result.id)
                .unwrap()
                .unwrap()
                .intent,
            DownloadIntent::Stopped
        );
    }
    drop(batch);
    assert!(core.download_attempts.verifications().is_empty());
    owner.close_and_drain().await.unwrap();
    assert_eq!(tests::usage(&owner), (0, 0));
}

#[tokio::test]
async fn admitted_batch_finishes_later_jobs_and_execution_cancellation_after_abort() {
    let (core, owner) = setup();
    let first = job(&core, 1, None);
    let last = job(&core, 2, None);
    let first_execution = core
        .download_attempts
        .try_enter(first, crate::Ed2kHash::from_bytes([1; 16]))
        .unwrap();
    let last_execution = core
        .download_attempts
        .try_enter(last, crate::Ed2kHash::from_bytes([2; 16]))
        .unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let caller = {
        let core = Arc::clone(&core);
        tokio::spawn(async move {
            core.control_downloads(
                DownloadAction::Stop,
                &[first.job_id, JobId::new(900).unwrap(), last.job_id],
            )
            .await
        })
    };
    gate.entered.notified().await;
    gate.release.notify_one();
    gate.entered.notified().await;
    assert_eq!(
        core.metadata_store
            .download_job(first.job_id)
            .unwrap()
            .unwrap()
            .intent,
        DownloadIntent::Stopped
    );
    assert!(first_execution.cancellation().is_cancelled());
    caller.abort();
    assert!(matches!(caller.await, Err(error) if error.is_cancelled()));
    *owner.publication_gate.lock().unwrap() = None;
    gate.release.notify_one();
    owner.close_and_drain().await.unwrap();
    assert_eq!(
        core.metadata_store
            .download_job(last.job_id)
            .unwrap()
            .unwrap()
            .intent,
        DownloadIntent::Stopped
    );
    assert!(last_execution.cancellation().is_cancelled());
    assert_eq!(tests::usage(&owner), (0, 0));
}

#[tokio::test]
async fn batch_keeps_request_order_and_continues_after_item_failure() {
    let (core, owner) = setup();
    let category = core
        .metadata_store
        .create_category("Media", None, None, "", &core.transfer_root)
        .unwrap();
    // Deliberately omit cache publication to inject a start-selection failure.
    let failing = job(&core, 3, Some(category.id));
    let succeeding = job(&core, 4, None);
    core.metadata_store.stop_download_job(succeeding).unwrap();
    let absent = JobId::new(900).unwrap();
    let batch = core
        .control_downloads(
            DownloadAction::Start,
            &[failing.job_id, absent, succeeding.job_id],
        )
        .await
        .unwrap();
    assert_eq!(
        batch
            .results()
            .iter()
            .map(|item| item.id)
            .collect::<Vec<_>>(),
        vec![failing.job_id, absent, succeeding.job_id]
    );
    assert_eq!(
        batch.results()[0].outcome,
        Err(DownloadControlError::Failed)
    );
    assert_eq!(batch.results()[1].outcome, Ok(DownloadChange::NotFound));
    assert_eq!(batch.results()[2].outcome, Ok(DownloadChange::Changed));
    assert_eq!(
        core.metadata_store
            .download_job(succeeding.job_id)
            .unwrap()
            .unwrap()
            .intent,
        DownloadIntent::Started
    );
    assert_eq!(tests::usage(&owner).0, 0);
    assert!(tests::usage(&owner).1 >= 3 * std::mem::size_of::<crate::DownloadControlResult>());
    drop(batch);
    assert_eq!(tests::usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn batch_refused_before_admission_changes_no_jobs() {
    let (core, owner) = setup();
    let first = job(&core, 5, None);
    let last = job(&core, 6, None);
    let guard = core.state.lock().await;
    let mut writers = Vec::new();
    for value in 0..MAX_SLOTS {
        let owner = Arc::clone(&owner);
        writers.push(tokio::spawn(async move {
            owner.add(format!("{value:032x}"), "Sample".into()).await
        }));
    }
    tests::wait_for_slots(&owner, MAX_SLOTS).await;
    let error = match core
        .control_downloads(DownloadAction::Stop, &[first.job_id, last.job_id])
        .await
    {
        Err(error) => error,
        Ok(_) => panic!("full owner admitted a control batch"),
    };
    assert!(matches!(
        error.downcast_ref::<PersistenceError>(),
        Some(PersistenceError::Busy)
    ));
    for token in [first, last] {
        assert_eq!(
            core.metadata_store
                .download_job(token.job_id)
                .unwrap()
                .unwrap()
                .intent,
            DownloadIntent::Started
        );
    }
    drop(guard);
    for writer in writers {
        writer.await.unwrap().unwrap();
    }
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn malformed_batches_are_not_admitted_and_single_controls_share_owner() {
    let (core, owner) = setup();
    let token = job(&core, 7, None);
    for ids in [
        vec![],
        vec![token.job_id; 2],
        (1..=101).map(|id| JobId::new(id).unwrap()).collect(),
    ] {
        assert!(
            core.control_downloads(DownloadAction::Stop, &ids)
                .await
                .is_err()
        );
        assert_eq!(tests::usage(&owner), (0, 0));
    }
    assert_eq!(
        core.stop_download(token.job_id).await.unwrap(),
        DownloadChange::Changed
    );
    assert_eq!(
        core.stop_download(token.job_id).await.unwrap(),
        DownloadChange::Unchanged
    );
    assert_eq!(
        core.start_download(token.job_id).await.unwrap(),
        DownloadChange::Changed
    );
    assert_eq!(
        core.remove_download(token.job_id, false).await.unwrap(),
        DownloadChange::Changed
    );
    assert_eq!(
        core.stop_download(token.job_id).await.unwrap(),
        DownloadChange::NotFound
    );
    owner.close_and_drain().await.unwrap();
}
