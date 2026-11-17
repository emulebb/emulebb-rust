use super::*;
use crate::FileIndex;
use emulebb_metadata::{DownloadJobRequest, DownloadJobStorageFailure};

fn job(core: &EmulebbCore, size: Option<u64>) -> DownloadJobRecord {
    core.metadata_store
        .admit_download_job(&DownloadJobRequest {
            file_hash: "53".repeat(16),
            display_name: "Sample.bin".into(),
            expected_size_bytes: size,
            category_id: None,
            intent: DownloadIntent::Stopped,
            piece_size: emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE,
        })
        .unwrap()
        .job
}

#[tokio::test]
async fn detail_matches_summary_and_exposes_bounded_storage_failure_without_recovery() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let job = job(&core, None);
    let detail = core
        .download_detail(job.token.job_id)
        .await
        .unwrap()
        .unwrap();
    let list = core.download_page(Default::default()).await.unwrap();
    assert_eq!(
        serde_json::to_value(&detail.summary).unwrap(),
        serde_json::to_value(&list.downloads[0]).unwrap()
    );
    assert!(detail.delivery.path.is_none());
    assert_eq!(detail.delivery.ownership, DownloadDeliveryOwnership::None);
    let value = serde_json::to_value(&*detail).unwrap();
    assert_eq!(value["delivery"]["ownership"], "none");
    assert!(value["failure"].is_null());
    assert!(value.get("parts").is_none() && value.get("sources").is_none());
    drop(detail);
    drop(list);
    let failure =
        DownloadJobStorageFailure::new("STORAGE_UNAVAILABLE", "Storage is unavailable", 123)
            .unwrap();
    core.metadata_store
        .fail_download_job_storage(job.token, &failure)
        .unwrap();
    let detail = core
        .download_detail(job.token.job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail.summary.state, DownloadState::Failed);
    let value = serde_json::to_value(&*detail).unwrap();
    assert_eq!(value["failure"]["code"], "STORAGE_UNAVAILABLE");
    assert_eq!(value["failure"]["failedAt"], 123);
    let current = core
        .ed2k_transfers
        .download_job(job.token.job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.storage_failure.as_ref(), Some(&failure));
    assert!(current.storage.is_none());
}

#[tokio::test]
async fn large_part_pages_are_bounded_and_never_allocate_execution_storage() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let job = job(&core, Some(0x4000000000));
    let first = core
        .download_parts_page(job.token.job_id, None, 200)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.parts.len(), 200);
    assert_eq!(first.next_after, Some(199));
    assert!(first.has_more);
    let value = serde_json::to_value(&first.parts[0]).unwrap();
    assert_eq!(value["start"], 0);
    assert_eq!(
        value["end"],
        emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE - 1
    );
    assert_eq!(value["presentBytes"], 0);
    assert_eq!(value["complete"], false);
    let next = core
        .download_parts_page(job.token.job_id, first.next_after, 200)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.parts[0].index, 200);
    assert!(
        core.ed2k_transfers
            .download_job(job.token.job_id)
            .await
            .unwrap()
            .unwrap()
            .storage
            .is_none()
    );
    assert!(
        core.download_parts_page(job.token.job_id, None, 201)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn unknown_parts_and_missing_detail_have_distinct_results() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let job = job(&core, None);
    let page = core
        .download_parts_page(job.token.job_id, None, 100)
        .await
        .unwrap()
        .unwrap();
    assert!(page.parts.is_empty() && !page.has_more);
    let missing = JobId::new(999).unwrap();
    assert!(core.download_detail(missing).await.unwrap().is_none());
    assert!(
        core.download_parts_page(missing, None, 100)
            .await
            .unwrap()
            .is_none()
    );
}
