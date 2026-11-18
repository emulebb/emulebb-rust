use super::*;
use crate::persistence_owner::content_observations::tests::search_fixture;
use crate::persistence_owner::tests::usage;
use emulebb_metadata::MetadataSearchProjection;

#[tokio::test]
async fn selected_download_seed_is_byte_bounded_and_keeps_its_reply_charge() {
    let (store, state, owner, publication, mut observations) = search_fixture().await;
    let id: i64 = publication.search_id.parse().unwrap();
    let fields = crate::search_state::result_fields(&publication.result);
    let mut claim_id = 0;
    for index in 0..220 {
        observations[0].metadata.name = Some(format!("{index:03}{}", "x".repeat(5000)));
        claim_id = store
            .ingest_search_observations(
                &observations,
                &MetadataSearchProjection {
                    session_id: id,
                    fields: fields.clone(),
                    name_votes: vec![emulebb_metadata::MetadataSearchNameVote {
                        normalized_name: observations[0].metadata.name.clone().unwrap(),
                        reporter_endpoint: observations[0].reporter_endpoint,
                        origin: observations[0].origin,
                        quality: emulebb_metadata::MetadataSearchNameQuality {
                            useful: true,
                            sources: 3,
                            complete_sources: 0,
                            rating: 0,
                        },
                    }],
                },
            )
            .unwrap()
            .unwrap()
            .claim_id;
    }
    state.lock().await.searches.clear();
    let seed = owner.search_download_seed(id, claim_id).await.unwrap();
    assert_eq!(usage(&owner), (0, 512 * 1024));
    let selected = seed.value().as_ref().unwrap();
    assert_eq!(selected.claim_id, claim_id);
    assert!(!selected.observations.is_empty());
    assert!(selected.observations.len() < 100);
    assert_eq!(
        store.table_count("search_result_observations").unwrap(),
        220
    );
    assert!(state.lock().await.searches.is_empty());
    drop(seed);
    assert_eq!(usage(&owner), (0, 0));
    let missing = owner.search_download_seed(id, claim_id + 1).await.unwrap();
    assert!(missing.value().is_none());
    drop(missing);
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn search_pages_and_selected_reads_retain_their_individual_byte_charges() {
    let (_store, _state, owner, publication, events) = search_fixture().await;
    let session = publication.search_id.parse().unwrap();
    owner
        .observe_content(&events, Some(&publication))
        .await
        .unwrap();
    let headers = owner.search_headers_page(None, 1).await.unwrap();
    assert_eq!(headers.value().items.len(), 1);
    assert_eq!(headers.value().items[0].result_count, 1);
    assert_eq!(usage(&owner), (0, 256 * 1024));
    drop(headers);
    let header = owner.search_header(session).await.unwrap();
    assert_eq!(header.value().as_ref().unwrap().id, session);
    drop(header);
    let results = owner
        .search_result_headers_page(session, 0, 1)
        .await
        .unwrap();
    let claim = results.value().as_ref().unwrap().items[0].claim_id;
    assert_eq!(usage(&owner), (0, 1024 * 1024));
    drop(results);
    let result = owner.search_result_header(session, claim).await.unwrap();
    assert_eq!(result.value().as_ref().unwrap().claim_id, claim);
    assert_eq!(usage(&owner), (0, 512 * 1024));
    drop(result);
    let observations = owner
        .search_result_observations_page(session, claim, 0, 1)
        .await
        .unwrap();
    assert_eq!(observations.value().as_ref().unwrap().items.len(), 1);
    assert_eq!(usage(&owner), (0, 256 * 1024));
    drop(observations);
    let missing = owner
        .search_result_headers_page(session + 1, 0, 1)
        .await
        .unwrap();
    assert!(missing.value().is_none());
    drop(missing);
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn search_page_admission_bounds_and_retained_replies_share_the_existing_budget() {
    let (_store, _state, owner, publication, _events) = search_fixture().await;
    let session = publication.search_id.parse().unwrap();
    for (after, limit) in [(-1, 1), (0, 0), (0, 201)] {
        assert!(matches!(
            owner
                .search_result_headers_page(session, after, limit)
                .await,
            Err(PersistenceError::TooLarge)
        ));
    }
    let mut replies = Vec::new();
    for _ in 0..7 {
        replies.push(
            owner
                .search_result_headers_page(session, 0, 200)
                .await
                .unwrap(),
        );
    }
    assert!(matches!(
        owner.search_result_headers_page(session, 0, 200).await,
        Err(PersistenceError::Busy)
    ));
    assert_eq!(usage(&owner), (0, 7 * 1024 * 1024));
    drop(replies);
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
    assert!(matches!(
        owner.search_header(session).await,
        Err(PersistenceError::Closing)
    ));
}

#[tokio::test]
async fn a_read_failure_does_not_fault_or_replay_the_persistence_owner() {
    let uri = format!(
        "file:search-read-failure-{}?mode=memory&cache=shared",
        uuid::Uuid::new_v4()
    );
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        | rusqlite::OpenFlags::SQLITE_OPEN_URI;
    let store =
        MetadataStore::from_connection(rusqlite::Connection::open_with_flags(&uri, flags).unwrap())
            .unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store, state).unwrap();
    let connection = rusqlite::Connection::open_with_flags(&uri, flags).unwrap();
    connection
        .execute_batch("ALTER TABLE search_sessions RENAME COLUMN query TO unavailable_query")
        .unwrap();
    assert!(matches!(
        owner.search_header(1).await,
        Err(PersistenceError::Storage(_))
    ));
    assert_eq!(usage(&owner), (0, 0));
    connection
        .execute_batch("ALTER TABLE search_sessions RENAME COLUMN unavailable_query TO query")
        .unwrap();
    assert!(owner.search_header(1).await.unwrap().value().is_none());
    owner.close_and_drain().await.unwrap();
}
