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
