use super::*;
use crate::persistence_owner::{MAX_SLOTS, tests as owner_tests};
use crate::{CategoryCreate, EmulebbCore, FileIndex, NullableStringField};
use emulebb_metadata::{DownloadIntent, DownloadJobRequest};

fn setup(
    size: Option<u64>,
) -> (
    Arc<EmulebbCore>,
    Arc<PersistenceOwner>,
    emulebb_metadata::DownloadJobRecord,
) {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    let job = core
        .metadata_store
        .admit_download_job(&DownloadJobRequest {
            file_hash: "75".repeat(16),
            display_name: "Sample.bin".into(),
            expected_size_bytes: size,
            category_id: None,
            intent: DownloadIntent::Started,
            piece_size: emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE,
        })
        .unwrap()
        .job;
    (core, owner, job)
}

async fn category(core: &EmulebbCore) -> crate::Category {
    core.create_category(CategoryCreate {
        name: "Media".into(),
        temp_dir: NullableStringField::Missing,
        destination_dir: NullableStringField::Missing,
        comment: None,
    })
    .await
    .unwrap()
}

#[test]
fn patch_request_distinguishes_omission_null_and_current_non_null_fields() {
    let empty: DownloadUpdate = serde_json::from_str("{}").unwrap();
    assert!(empty.category.is_none() && empty.name.is_none() && empty.size_bytes.is_none());
    assert_eq!(serde_json::to_string(&empty).unwrap(), "{}");
    let clear: DownloadUpdate = serde_json::from_str(r#"{"category":null}"#).unwrap();
    assert_eq!(clear.category, Some(None));
    for invalid in [
        r#"{"name":null}"#,
        r#"{"sizeBytes":null}"#,
        r#"{"unexpected":true}"#,
    ] {
        assert!(serde_json::from_str::<DownloadUpdate>(invalid).is_err());
    }
}

#[tokio::test]
async fn combined_patch_replans_metadata_discovery_without_starting_or_allocating() {
    let (core, owner, job) = setup(None);
    let category = category(&core).await;
    let guard = core
        .download_attempts
        .try_prepare(job.token, job.file_hash.parse().unwrap())
        .unwrap();
    let update = DownloadUpdate {
        name: Some("Renamed.bin".into()),
        category: Some(Some("media".into())),
        size_bytes: Some(32),
    };
    assert_eq!(
        core.patch_download(job.token.job_id, update.clone())
            .await
            .unwrap(),
        DownloadChange::Changed
    );
    assert!(guard.cancellation().is_cancelled());
    drop(guard);
    let detail = core
        .download_detail(job.token.job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail.summary.name, "Renamed.bin");
    assert_eq!(
        detail.summary.category.as_deref(),
        Some(category.name.as_str())
    );
    assert_eq!(detail.summary.size_bytes, Some(32));
    assert_eq!(detail.summary.intent, DownloadIntent::Started);
    drop(detail);
    let current = core
        .metadata_store
        .download_job(job.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(current.token, job.token);
    assert!(current.storage.is_none() && current.selected_temp.is_none());
    assert_eq!(
        core.patch_download(job.token.job_id, update).await.unwrap(),
        DownloadChange::Unchanged
    );
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn conflicting_patch_never_applies_valid_fields() {
    let (core, owner, job) = setup(Some(32));
    let _category = category(&core).await;
    for (update, expected) in [
        (
            DownloadUpdate {
                name: Some("Renamed.bin".into()),
                category: Some(Some("Missing".into())),
                size_bytes: Some(32),
            },
            DownloadPatchError::CategoryNotFound,
        ),
        (
            DownloadUpdate {
                name: Some("Renamed.bin".into()),
                category: Some(Some("Media".into())),
                size_bytes: Some(33),
            },
            DownloadPatchError::SizeConflict,
        ),
    ] {
        let error = core
            .patch_download(job.token.job_id, update)
            .await
            .unwrap_err();
        assert_eq!(error.downcast_ref::<DownloadPatchError>(), Some(&expected));
        assert_eq!(
            core.metadata_store
                .download_job(job.token.job_id)
                .unwrap()
                .unwrap(),
            job
        );
    }
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn admitted_patch_finishes_core_publication_after_disconnect() {
    let (core, owner, job) = setup(Some(32));
    let (_guard, transfer) = core
        .select_download_execution(job.token.job_id)
        .await
        .unwrap()
        .unwrap();
    core.state
        .lock()
        .await
        .transfers
        .insert(job.token.job_id.to_string(), transfer);
    let mut events = core.subscribe_download_events(crate::DownloadEventResetReason::Initial, None);
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let caller = {
        let core = Arc::clone(&core);
        tokio::spawn(async move {
            core.patch_download(
                job.token.job_id,
                DownloadUpdate {
                    name: Some("Renamed.bin".into()),
                    ..Default::default()
                },
            )
            .await
        })
    };
    gate.entered.notified().await;
    assert_eq!(
        core.metadata_store
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .display_name,
        "Renamed.bin"
    );
    assert_eq!(
        core.state.lock().await.transfers[&job.token.job_id.to_string()].name,
        "Sample.bin"
    );
    caller.abort();
    assert!(matches!(caller.await, Err(error) if error.is_cancelled()));
    gate.release.notify_one();
    owner.close_and_drain().await.unwrap();
    assert!(
        matches!(events.receiver.try_recv().unwrap(),crate::DownloadEvent::Changed{download_id,..} if download_id==job.token.job_id)
    );
    assert_eq!(
        core.state.lock().await.transfers[&job.token.job_id.to_string()].name,
        "Renamed.bin"
    );
    assert!(!_guard.cancellation().is_cancelled());
    assert_eq!(owner_tests::usage(&owner), (0, 0));
}

#[tokio::test]
async fn shared_capacity_refusal_does_not_modify_the_job() {
    let (core, owner, job) = setup(None);
    let state = core.state.lock().await;
    let mut writers = Vec::new();
    for value in 0..MAX_SLOTS {
        let owner = Arc::clone(&owner);
        writers.push(tokio::spawn(async move {
            owner.add(format!("{value:032x}"), "Sample".into()).await
        }));
    }
    owner_tests::wait_for_slots(&owner, MAX_SLOTS).await;
    let error = core
        .patch_download(
            job.token.job_id,
            DownloadUpdate {
                name: Some("Renamed.bin".into()),
                size_bytes: Some(32),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<PersistenceError>(),
        Some(PersistenceError::Busy)
    ));
    assert_eq!(
        core.metadata_store
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap(),
        job
    );
    drop(state);
    for writer in writers {
        writer.await.unwrap().unwrap();
    }
    owner.close_and_drain().await.unwrap();
}
