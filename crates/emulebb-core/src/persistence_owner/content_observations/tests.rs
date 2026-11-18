use super::super::tests::{setup, usage, wait_for_slots};
use super::*;
use emulebb_metadata::{MetadataContentClaim, MetadataContentMetadata, MetadataObservationOrigin};

fn event() -> MetadataContentObservationEvent {
    MetadataContentObservationEvent {
        claim: MetadataContentClaim {
            hash: [0x56; 16],
            size_bytes: None,
        },
        origin: MetadataObservationOrigin::Kad,
        reporter_endpoint: Some("192.0.2.9:4672".parse().unwrap()),
        metadata: MetadataContentMetadata {
            name: Some("Sample.bin".into()),
            ..Default::default()
        },
        observed_at_s: 100,
    }
}

#[tokio::test]
async fn admitted_observations_finish_once_after_caller_disconnect() {
    let (store, _state, owner) = setup();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let caller = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.observe_content(&[event(), event()], None).await })
    };
    gate.entered.notified().await;
    assert_eq!(usage(&owner).0, 1);
    caller.abort();
    gate.release.notify_one();
    wait_for_slots(&owner, 0).await;
    let page = store.content_observations_page(1, 0, 10).unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].receipt.observation_count, 2);
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn observed_content_is_ordered_and_closing_never_replays_it() {
    let (store, _state, owner) = setup();
    owner.observe_content(&[event()], None).await.unwrap();
    owner.observe_content(&[event()], None).await.unwrap();
    owner.close_and_drain().await.unwrap();
    assert!(matches!(
        owner.observe_content(&[event()], None).await,
        Err(PersistenceError::Closing)
    ));
    let page = store.content_observations_page(1, 0, 10).unwrap();
    assert_eq!(page.items[0].receipt.observation_count, 2);
}

#[tokio::test]
async fn committed_search_observation_publishes_after_caller_disconnect() {
    let (store, state, owner) = setup();
    let request = crate::SearchCreate {
        query: "sample query".into(),
        method: "server".into(),
        ..Default::default()
    };
    let now = chrono::Utc::now();
    let mut search = crate::Search {
        id: String::new(),
        spec: request.clone(),
        resolved_method: None,
        status: "running".into(),
        status_reason: None,
        progress: crate::SearchProgress::new("running", 0, None, ""),
        created_at: now,
        updated_at: now,
        results: Vec::new(),
    };
    search.id = crate::search_state::create_search(&store, &search).unwrap();
    let search_id = search.id.clone();
    state
        .lock()
        .await
        .searches
        .insert(search_id.clone(), search);
    let raw = crate::search_observations::tests::raw_file();
    let projected = crate::search_query::search_result_from_ed2k(
        &search_id,
        &request,
        "server",
        Some("192.0.2.4:4661".parse().unwrap()),
        raw.clone(),
    );
    let crate::search_queue_runtime::SearchLiveUpdate::Result {
        result,
        observations,
    } = crate::search_observations::ed2k(
        projected,
        MetadataObservationOrigin::Server,
        Some("192.0.2.4:4661".parse().unwrap()),
        &raw,
    )
    else {
        panic!("expected result");
    };
    let publication = SearchPublication {
        state: Arc::clone(&state),
        search_id: search_id.clone(),
        request,
        result: *result,
    };
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let caller = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move {
            owner
                .observe_content(&observations, Some(&publication))
                .await
        })
    };
    gate.entered.notified().await;
    assert_eq!(
        store
            .content_observations_page(1, 0, 10)
            .unwrap()
            .items
            .len(),
        1
    );
    assert!(state.lock().await.searches[&search_id].results.is_empty());
    caller.abort();
    gate.release.notify_one();
    wait_for_slots(&owner, 0).await;
    let state = state.lock().await;
    assert_eq!(state.searches[&search_id].results.len(), 1);
    assert_eq!(state.searches[&search_id].results[0].name, "Sample.bin");
    drop(state);
    assert_eq!(
        store.content_observations_page(1, 0, 10).unwrap().items[0]
            .receipt
            .observation_count,
        1
    );
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}
