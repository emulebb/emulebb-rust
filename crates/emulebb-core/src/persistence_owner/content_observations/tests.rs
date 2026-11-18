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

async fn search_fixture() -> (
    MetadataStore,
    Arc<Mutex<CoreState>>,
    Arc<PersistenceOwner>,
    SearchPublication,
    Vec<MetadataContentObservationEvent>,
) {
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
    (store, state, owner, publication, observations)
}

#[tokio::test]
async fn committed_search_observation_publishes_after_caller_disconnect() {
    let (store, state, owner, publication, observations) = search_fixture().await;
    let search_id = publication.search_id.clone();
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

#[tokio::test]
async fn projection_capacity_refusal_does_not_retry_or_commit() {
    let (store, state, owner, mut publication, mut events) = search_fixture().await;
    for index in 0..64 {
        let name = format!("{index}{}", "x".repeat(1024));
        publication.result.name = name.clone();
        publication.result.observations[0].name = name.clone();
        events[0].metadata.name = Some(name);
        owner
            .observe_content(&events, Some(&publication))
            .await
            .unwrap();
    }
    let held_bytes = MAX_BYTES - 64 * 1024;
    let quota = {
        let admission = owner.admission.lock().unwrap();
        let mut quota = admission.quota.lock().unwrap();
        quota.bytes += held_bytes;
        Arc::clone(&admission.quota)
    };
    let held = ByteLease {
        quota,
        bytes: held_bytes,
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        owner.observe_content(&events, Some(&publication)),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(PersistenceError::Busy)));
    assert_eq!(usage(&owner), (0, held_bytes));
    assert_eq!(store.table_count("content_claim_observations").unwrap(), 64);
    let mut after = 0;
    let mut seen = 0;
    loop {
        let page = store.content_observations_page(1, after, 100).unwrap();
        assert!(page.items.iter().all(|r| r.receipt.observation_count == 1));
        seen += page.items.len();
        if let Some(last) = page.items.last() {
            after = last.receipt.observation_id;
        }
        if !page.has_more {
            break;
        }
    }
    assert_eq!(seen, 64);
    assert_eq!(
        state.lock().await.searches[&publication.search_id].results[0]
            .observations
            .len(),
        64
    );
    drop(held);
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn same_hash_different_sizes_publish_distinct_claim_ids() {
    let (store, state, owner, mut publication, mut events) = search_fixture().await;
    for size in [None, Some(0), Some(1024), Some(2048)] {
        publication.result.size_bytes = size;
        publication.result.observations[0].size_bytes = size;
        events[0].claim.size_bytes = size;
        owner
            .observe_content(&events, Some(&publication))
            .await
            .unwrap();
    }
    let state = state.lock().await;
    let results = &state.searches[&publication.search_id].results;
    assert_eq!(results.len(), 4);
    for (index, result) in results.iter().enumerate() {
        assert!(!result.id.is_empty());
        assert!(
            results[..index]
                .iter()
                .all(|previous| previous.id != result.id)
        );
    }
    drop(state);
    assert_eq!(store.load_searches().unwrap()[0].results.len(), 4);
    owner.close_and_drain().await.unwrap();
}
