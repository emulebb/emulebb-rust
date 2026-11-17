use super::*;
use crate::{DownloadCreate, DownloadCreateSource, EmulebbCore, FileIndex};
use emulebb_metadata::{DownloadIntent, DownloadJobQuery};

fn setup() -> (Arc<EmulebbCore>, Arc<PersistenceOwner>) {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    (core, owner)
}

fn request() -> DownloadCreate {
    DownloadCreate {
        source: DownloadCreateSource::Content {
            hash: "87".repeat(16),
            name: "Sample.bin".into(),
            size_bytes: None,
        },
        category: None,
        intent: DownloadIntent::Started,
        redownload: false,
    }
}

#[tokio::test]
async fn caller_abort_after_sql_cannot_skip_scheduler_publication() {
    let (core, owner) = setup();
    let mut events = core.subscribe_download_events(crate::DownloadEventResetReason::Initial, None);
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let caller = {
        let core = Arc::clone(&core);
        tokio::spawn(async move { core.create_download(request()).await })
    };
    gate.entered.notified().await;
    let page = core
        .metadata_store
        .download_job_page(DownloadJobQuery::default())
        .unwrap();
    assert_eq!(page.jobs.len(), 1);
    assert_eq!(page.jobs[0].intent, DownloadIntent::Started);
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    *owner.publication_gate.lock().unwrap() = None;
    gate.release.notify_one();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        core.download_attempts.changed.notified(),
    )
    .await
    .unwrap();
    owner.close_and_drain().await.unwrap();
    assert!(
        matches!(events.receiver.try_recv().unwrap(),crate::DownloadEvent::Changed{download_id,..} if download_id.get()==1)
    );
    assert_eq!(super::super::tests::usage(&owner), (0, 0));
}

#[tokio::test]
async fn shared_owner_refusal_precedes_durable_creation() {
    let (core, owner) = setup();
    let guard = core.state.lock().await;
    let mut writers = Vec::new();
    for value in 0..MAX_SLOTS {
        let owner = Arc::clone(&owner);
        writers.push(tokio::spawn(async move {
            owner.add(format!("{value:032x}"), "Sample".into()).await
        }));
    }
    super::super::tests::wait_for_slots(&owner, MAX_SLOTS).await;
    let error = core.create_download(request()).await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<PersistenceError>(),
        Some(PersistenceError::Busy)
    ));
    assert!(
        core.metadata_store
            .download_job_page(DownloadJobQuery::default())
            .unwrap()
            .jobs
            .is_empty()
    );
    drop(guard);
    for writer in writers {
        writer.await.unwrap().unwrap();
    }
    owner.close_and_drain().await.unwrap();
}
