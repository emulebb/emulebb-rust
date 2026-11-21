use super::super::tests::{usage, wait_for_slots};
use super::*;
use crate::{EmulebbCore, LibraryTagRequest};
use emulebb_index::FileIndex;

fn setup() -> (Arc<EmulebbCore>, Arc<PersistenceOwner>) {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    (core, owner)
}
fn known(store: &MetadataStore, byte: u8) -> String {
    let hash = hex::encode([byte; 16]);
    store
        .clone()
        .upsert_indexed_file(
            &emulebb_metadata::MetadataIndexedFile {
                ed2k_hash: hash.clone(),
                name: "Sample.bin".into(),
                size_bytes: 123,
                content_type: String::new(),
                availability_score: 0,
            },
            emulebb_metadata::MetadataIndexedFileOrigin::LocalShare,
        )
        .unwrap();
    hash
}

#[tokio::test]
async fn sharing_results_preserve_order_and_charge_through_projection() {
    let (core, owner) = setup();
    let first = known(&core.metadata_store, 1);
    let last = known(&core.metadata_store, 2);
    core.metadata_store
        .set_library_sharing_enabled(&first, false)
        .unwrap();
    let hashes = vec![first, "ff".repeat(16), last];
    let reply = core
        .set_library_sharing(&LibrarySharingRequest {
            enabled: false,
            hashes: hashes.clone(),
        })
        .await
        .unwrap();
    assert_eq!(
        reply
            .value()
            .iter()
            .map(|row| row.hash.clone())
            .collect::<Vec<_>>(),
        hashes
    );
    assert_eq!(
        reply
            .value()
            .iter()
            .map(|row| row.outcome.as_ref().unwrap())
            .collect::<Vec<_>>(),
        [
            &LibraryFileChange::Unchanged,
            &LibraryFileChange::NotFound,
            &LibraryFileChange::Changed
        ]
    );
    assert_eq!(usage(&owner), (0, RESULT_BYTES));
    let reply = reply.map(|rows| rows.into_iter().map(|row| row.hash).collect::<Vec<_>>());
    assert_eq!(
        serde_json::to_value(&reply).unwrap(),
        serde_json::json!(hashes)
    );
    assert_eq!(usage(&owner).1, RESULT_BYTES);
    drop(reply);
    assert_eq!(usage(&owner), (0, 0));
    assert_eq!(
        core.metadata_store
            .library_sharing_enabled(&hashes[1])
            .unwrap(),
        None
    );
    owner.close_and_drain().await.unwrap();
    core.ed2k_transfers.drain_local_mutations().await.unwrap();
}

#[tokio::test]
async fn admitted_sharing_batch_finishes_after_caller_disconnect() {
    let (core, owner) = setup();
    let hashes = vec![
        known(&core.metadata_store, 1),
        known(&core.metadata_store, 2),
    ];
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let caller = {
        let core = Arc::clone(&core);
        let hashes = hashes.clone();
        tokio::spawn(async move {
            core.set_library_sharing(&LibrarySharingRequest {
                hashes,
                enabled: false,
            })
            .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    caller.abort();
    assert!(caller.await.is_err_and(|error| error.is_cancelled()));
    *owner.publication_gate.lock().unwrap() = None;
    gate.release.notify_one();
    // The existing ordered profile read is a completion barrier.
    drop(
        core.library_tags(&LibraryTagRequest::Get("Missing".into()))
            .await
            .unwrap(),
    );
    for hash in hashes {
        assert_eq!(
            core.metadata_store.library_sharing_enabled(&hash).unwrap(),
            Some(false)
        );
    }
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
    core.ed2k_transfers.drain_local_mutations().await.unwrap();
}

#[tokio::test]
async fn shared_slot_refusal_precedes_any_sharing_mutation() {
    let (core, owner) = setup();
    let hash = known(&core.metadata_store, 1);
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let mut callers = Vec::new();
    for _ in 0..MAX_SLOTS {
        let core = Arc::clone(&core);
        let hash = hash.clone();
        callers.push(tokio::spawn(async move {
            core.set_library_sharing(&LibrarySharingRequest {
                hashes: vec![hash],
                enabled: false,
            })
            .await
        }));
    }
    wait_for_slots(&owner, MAX_SLOTS).await;
    let error = core
        .set_library_sharing(&LibrarySharingRequest {
            enabled: false,
            hashes: vec![hash.clone()],
        })
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error.downcast_ref::<PersistenceError>(),
        Some(PersistenceError::Busy)
    ));
    assert_eq!(
        core.metadata_store.library_sharing_enabled(&hash).unwrap(),
        Some(true)
    );
    *owner.publication_gate.lock().unwrap() = None;
    gate.release.notify_one();
    for caller in callers {
        drop(caller.await.unwrap().unwrap());
    }
    assert_eq!(
        core.metadata_store.library_sharing_enabled(&hash).unwrap(),
        Some(false)
    );
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
    core.ed2k_transfers.drain_local_mutations().await.unwrap();
}

#[tokio::test]
async fn invalid_sharing_selection_never_enters_the_owner() {
    let (core, owner) = setup();
    let hash = known(&core.metadata_store, 1);
    for hashes in [
        Vec::new(),
        vec![hash.clone(), hash.clone()],
        vec![hash.clone(), "BAD".into()],
        (0..101).map(|n| format!("{n:032x}")).collect(),
    ] {
        assert!(
            core.set_library_sharing(&LibrarySharingRequest {
                hashes,
                enabled: false
            })
            .await
            .is_err()
        );
        assert_eq!(usage(&owner), (0, 0));
        assert_eq!(
            core.metadata_store.library_sharing_enabled(&hash).unwrap(),
            Some(true)
        );
    }
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn sharing_sql_item_failure_does_not_skip_later_hashes() {
    let uri = format!(
        "file:sharing-items-{}?mode=memory&cache=shared",
        uuid::Uuid::new_v4()
    );
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        | rusqlite::OpenFlags::SQLITE_OPEN_URI;
    let store =
        MetadataStore::from_connection(rusqlite::Connection::open_with_flags(&uri, flags).unwrap())
            .unwrap();
    let hashes = vec![known(&store, 1), known(&store, 2), known(&store, 3)];
    let fault = rusqlite::Connection::open_with_flags(&uri, flags).unwrap();
    fault.execute_batch("CREATE TRIGGER refuse_one_sharing BEFORE UPDATE OF sharing_enabled ON known_files WHEN old.ed2k_hash=x'02020202020202020202020202020202' BEGIN SELECT RAISE(ABORT,'injected sharing item fault'); END;").unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), state).unwrap();
    let runtime = Arc::new(
        Ed2kTransferRuntime::load_or_create_with_metadata(
            &crate::unique_runtime_dir("sharing-sql-items"),
            store.clone(),
        )
        .unwrap(),
    );
    let reply = owner
        .library_sharing(
            &LibrarySharingRequest {
                hashes: hashes.clone(),
                enabled: false,
            },
            || Arc::clone(&runtime),
        )
        .await
        .unwrap();
    assert_eq!(
        reply.value()[0].outcome.as_ref().unwrap(),
        &LibraryFileChange::Changed
    );
    assert!(matches!(
        &reply.value()[1].outcome,
        Err(PersistenceError::Storage(_))
    ));
    assert_eq!(
        reply.value()[2].outcome.as_ref().unwrap(),
        &LibraryFileChange::Changed
    );
    assert_eq!(
        store.library_sharing_enabled(&hashes[0]).unwrap(),
        Some(false)
    );
    assert_eq!(
        store.library_sharing_enabled(&hashes[1]).unwrap(),
        Some(true)
    );
    assert_eq!(
        store.library_sharing_enabled(&hashes[2]).unwrap(),
        Some(false)
    );
    drop(reply);
    owner.close_and_drain().await.unwrap();
    runtime.drain_local_mutations().await.unwrap();
}
