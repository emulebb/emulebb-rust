use super::super::tests::{setup, usage, wait_for_slots};
use super::*;
use crate::{EmulebbCore, FileIndex};

fn known(store: &mut MetadataStore, byte: u8) -> String {
    let hash = format!("{byte:02x}").repeat(16);
    store
        .upsert_indexed_file(
            &emulebb_metadata::MetadataIndexedFile {
                ed2k_hash: hash.clone(),
                name: "Sample.bin".into(),
                size_bytes: 123,
                content_type: String::new(),
                availability_score: 0,
            },
            emulebb_metadata::MetadataIndexedFileOrigin::PassiveCache,
        )
        .unwrap();
    hash
}

#[tokio::test]
async fn tag_response_retains_shared_charge_through_projection_and_serialization() {
    let (_store, _state, owner) = setup();
    let reply = owner
        .library_tags(&LibraryTagRequest::Create("Media".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(usage(&owner), (0, RESULT_BYTES));
    let reply = reply.map(|value| match value {
        LibraryTagValue::Tag(Some(tag)) => tag,
        _ => panic!("expected created tag"),
    });
    assert_eq!(
        serde_json::to_value(&reply).unwrap(),
        serde_json::json!({"name":"Media"})
    );
    assert_eq!(usage(&owner).1, RESULT_BYTES);
    drop(reply);
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn admitted_tag_batch_finishes_all_hashes_after_caller_disconnect() {
    let (mut store, _state, owner) = setup();
    let hashes = [
        known(&mut store, 1),
        known(&mut store, 2),
        known(&mut store, 3),
    ];
    store.create_library_tag("Rotate").unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let caller = {
        let owner = Arc::clone(&owner);
        let hashes = hashes.to_vec();
        tokio::spawn(async move {
            owner
                .library_tags(&LibraryTagRequest::Change {
                    tag: "Rotate".into(),
                    hashes,
                    assigned: true,
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
    // An ordered read is the completion barrier; no sleep or caller-owned task.
    drop(
        owner
            .library_tags(&LibraryTagRequest::Get("Rotate".into()))
            .await
            .unwrap()
            .unwrap(),
    );
    for hash in hashes {
        let page = store
            .library_file_tags_page(&hash, None, 1)
            .unwrap()
            .unwrap();
        assert_eq!(page.tags[0].name, "Rotate");
    }
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn shared_slot_refusal_precedes_tag_creation() {
    let (store, _state, owner) = setup();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let mut callers = Vec::new();
    for i in 0..MAX_SLOTS {
        let owner = Arc::clone(&owner);
        callers.push(tokio::spawn(async move {
            owner
                .library_tags(&LibraryTagRequest::Create(format!("Tag-{i}")))
                .await
        }));
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    wait_for_slots(&owner, MAX_SLOTS).await;
    assert!(matches!(
        owner
            .library_tags(&LibraryTagRequest::Create("Refused".into()))
            .await,
        Err(PersistenceError::Busy)
    ));
    assert!(store.library_tag("Refused").unwrap().is_none());
    *owner.publication_gate.lock().unwrap() = None;
    gate.release.notify_one();
    for caller in callers {
        drop(caller.await.unwrap().unwrap().unwrap());
    }
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn tag_batch_preserves_order_and_continues_after_a_failed_sql_item() {
    let uri = format!(
        "file:tag-items-{}?mode=memory&cache=shared",
        uuid::Uuid::new_v4()
    );
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        | rusqlite::OpenFlags::SQLITE_OPEN_URI;
    let mut store =
        MetadataStore::from_connection(rusqlite::Connection::open_with_flags(&uri, flags).unwrap())
            .unwrap();
    let hashes = [
        known(&mut store, 1),
        known(&mut store, 2),
        "ff".repeat(16),
        known(&mut store, 3),
    ];
    store.create_library_tag("Batch").unwrap();
    let fault = rusqlite::Connection::open_with_flags(&uri, flags).unwrap();
    fault.execute_batch("CREATE TRIGGER refuse_one_tag BEFORE INSERT ON known_file_tags WHEN new.known_file_id=(SELECT id FROM known_files WHERE lower(hex(ed2k_hash))='02020202020202020202020202020202') BEGIN SELECT RAISE(ABORT,'injected tag item fault'); END;").unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), state).unwrap();
    let reply = owner
        .library_tags(&LibraryTagRequest::Change {
            tag: "Batch".into(),
            hashes: hashes.to_vec(),
            assigned: true,
        })
        .await
        .unwrap()
        .unwrap();
    let LibraryTagValue::Assignments(items) = reply.value() else {
        panic!("expected batch");
    };
    assert_eq!(
        items
            .iter()
            .map(|item| item.hash.as_str())
            .collect::<Vec<_>>(),
        hashes.iter().map(String::as_str).collect::<Vec<_>>()
    );
    assert_eq!(
        items.iter().map(|item| item.change).collect::<Vec<_>>(),
        [
            LibraryTagChange::Changed,
            LibraryTagChange::StorageFailed,
            LibraryTagChange::NotFound,
            LibraryTagChange::Changed,
        ]
    );
    assert_eq!(
        store
            .library_file_tags_page(&hashes[0], None, 1)
            .unwrap()
            .unwrap()
            .tags
            .len(),
        1
    );
    assert!(
        store
            .library_file_tags_page(&hashes[1], None, 1)
            .unwrap()
            .unwrap()
            .tags
            .is_empty()
    );
    assert_eq!(
        store
            .library_file_tags_page(&hashes[3], None, 1)
            .unwrap()
            .unwrap()
            .tags
            .len(),
        1
    );
    drop(reply);
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn invalid_tag_selections_fail_before_admission_or_implicit_creation() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    for request in [
        LibraryTagRequest::Create("two words".into()),
        LibraryTagRequest::Page {
            hash: None,
            after: None,
            limit: 201,
        },
        LibraryTagRequest::Change {
            tag: "Valid".into(),
            hashes: vec![],
            assigned: true,
        },
        LibraryTagRequest::Change {
            tag: "Valid".into(),
            hashes: vec!["00".repeat(16); 101],
            assigned: true,
        },
        LibraryTagRequest::Change {
            tag: "Valid".into(),
            hashes: vec!["00".repeat(16); 2],
            assigned: true,
        },
        LibraryTagRequest::Change {
            tag: "Valid".into(),
            hashes: vec!["AA".repeat(16)],
            assigned: true,
        },
    ] {
        assert!(core.library_tags(&request).await.is_err());
    }
    assert!(
        core.metadata_store
            .library_tags_page(None, 200)
            .unwrap()
            .tags
            .is_empty()
    );
    let reply = core
        .library_tags(&LibraryTagRequest::Change {
            tag: "Missing".into(),
            hashes: vec!["00".repeat(16)],
            assigned: true,
        })
        .await;
    assert_eq!(
        reply.err().unwrap().downcast_ref::<LibraryTagError>(),
        Some(&LibraryTagError::NotFound)
    );
}
