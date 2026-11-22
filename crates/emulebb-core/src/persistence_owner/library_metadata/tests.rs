use super::super::tests::usage;
use super::*;
use crate::{DownloadCreate, DownloadCreateSource, LibraryTagRequest};
use emulebb_index::FileIndex;

#[tokio::test]
async fn disconnected_copyless_editor_finishes_both_network_publications() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let hash = "61".repeat(16);
    let (_, job) = core
        .create_download(DownloadCreate {
            source: DownloadCreateSource::Content {
                hash: hash.clone(),
                name: "Sample.bin".into(),
                size_bytes: Some(32),
            },
            category: None,
            intent: emulebb_metadata::DownloadIntent::Stopped,
            redownload: false,
        })
        .await
        .unwrap();
    let id = job.id;
    drop(job);
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let caller = {
        let core = Arc::clone(&core);
        let hash = hash.clone();
        tokio::spawn(async move {
            core.edit_library_file_metadata(
                &hash,
                &LibraryFileUpdate {
                    upload_priority: Some("high".into()),
                    comment: Some("Operator note".into()),
                    rating: Some(4),
                },
            )
            .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    // The durable edit and Native publication are done; Core publication is held.
    let stored = core
        .metadata_store
        .download_job_manifest(id)
        .unwrap()
        .unwrap();
    assert_eq!(
        (stored.comment.as_str(), stored.rating),
        ("Operator note", 4)
    );
    assert!(core.kad_notes_dirty.lock().unwrap().is_empty());
    let queued = core.ed2k_publish_diagnostics().queued_count;
    caller.abort();
    assert!(caller.await.is_err_and(|error| error.is_cancelled()));
    *owner.publication_gate.lock().unwrap() = None;
    gate.release.notify_one();
    // Existing ordered profile read is a completion barrier, not a retry.
    drop(
        core.library_tags(&LibraryTagRequest::Get("Missing".into()))
            .await
            .unwrap(),
    );
    assert!(core.kad_notes_dirty.lock().unwrap().remove(&hash));
    assert_eq!(core.ed2k_publish_diagnostics().queued_count, queued + 1);
    assert_eq!(usage(&owner), (0, 0));

    // An unchanged note and ordinary priority edit do not dirty Kad notes.
    for request in [
        LibraryFileUpdate {
            comment: Some("Operator note".into()),
            rating: Some(4),
            ..Default::default()
        },
        LibraryFileUpdate {
            upload_priority: Some("low".into()),
            ..Default::default()
        },
    ] {
        assert!(
            core.edit_library_file_metadata(&hash, &request)
                .await
                .unwrap()
        );
        assert!(core.kad_notes_dirty.lock().unwrap().is_empty());
        assert_eq!(core.ed2k_publish_diagnostics().queued_count, queued + 1);
    }
    assert!(
        !core
            .edit_library_file_metadata(
                &"ff".repeat(16),
                &LibraryFileUpdate {
                    upload_priority: Some("normal".into()),
                    ..Default::default()
                }
            )
            .await
            .unwrap()
    );
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
    core.ed2k_transfers.drain_local_mutations().await.unwrap();
}
