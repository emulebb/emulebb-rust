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

pub(in crate::persistence_owner) async fn search_fixture() -> (
    MetadataStore,
    Arc<Mutex<CoreState>>,
    Arc<PersistenceOwner>,
    SearchPublication,
    Vec<MetadataContentObservationEvent>,
) {
    let (store, state, owner) = setup();
    let request = crate::SearchCreate {
        parent_search_id: None,
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
    assert!(state.lock().await.searches.contains_key(&search_id));
    caller.abort();
    gate.release.notify_one();
    wait_for_slots(&owner, 0).await;
    assert_eq!(
        store
            .search_header(search_id.parse().unwrap())
            .unwrap()
            .unwrap()
            .result_count,
        1
    );
    assert_eq!(
        store
            .search_result_headers_page(search_id.parse().unwrap(), 0, 1)
            .unwrap()
            .unwrap()
            .items[0]
            .summary
            .name,
        "Sample.bin"
    );
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
    let (store, _state, owner, mut publication, mut events) = search_fixture().await;
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
    drop(held);
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn same_hash_different_sizes_publish_distinct_claim_ids() {
    let (store, _state, owner, mut publication, mut events) = search_fixture().await;
    for size in [None, Some(0), Some(1024), Some(2048)] {
        publication.result.size_bytes = size;
        publication.result.observations[0].size_bytes = size;
        events[0].claim.size_bytes = size;
        owner
            .observe_content(&events, Some(&publication))
            .await
            .unwrap();
    }
    let page = store
        .search_result_headers_page(publication.search_id.parse().unwrap(), 0, 10)
        .unwrap()
        .unwrap();
    assert_eq!(page.items.len(), 4);
    let ids = page
        .items
        .iter()
        .map(|row| row.claim_id)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(ids.len(), 4);
    assert_eq!(
        store
            .search_header(publication.search_id.parse().unwrap())
            .unwrap()
            .unwrap()
            .result_count,
        4
    );
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn name_consensus_counts_each_reporter_once_across_changing_metadata() {
    let (store, _state, owner, mut publication, mut events) = search_fixture().await;
    let id = publication.search_id.clone();
    for (name, reporter, sources) in [
        ("Alpha.bin", "192.0.2.1:4661", 3),
        ("Beta.bin", "192.0.2.2:4661", 1),
        ("Beta.bin", "192.0.2.3:4661", 1),
    ]
    .into_iter()
    .chain((100..120).map(|sources| ("Alpha.bin", "192.0.2.1:4661", sources)))
    {
        publication.result.name = name.into();
        publication.result.sources = sources;
        publication.result.observations[0].name = name.into();
        publication.result.observations[0].sources = sources;
        publication.result.observations[0].reporter_endpoint = Some(reporter.into());
        events[0].metadata.name = Some(name.into());
        events[0].metadata.source_count = Some(sources);
        events[0].reporter_endpoint = Some(reporter.parse().unwrap());
        owner
            .observe_content(&events, Some(&publication))
            .await
            .unwrap();
    }
    let claim = store
        .search_result_headers_page(id.parse().unwrap(), 0, 1)
        .unwrap()
        .unwrap()
        .items[0]
        .claim_id;
    assert_eq!(
        store
            .search_result_header(id.parse().unwrap(), claim)
            .unwrap()
            .unwrap()
            .summary
            .name,
        "Beta.bin"
    );
    assert_eq!(store.table_count("search_name_reporters").unwrap(), 3);
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn late_raw_occurrence_does_not_consult_removed_session_presentation() {
    let (store, state, owner, mut publication, events) = search_fixture().await;
    let queue = Arc::new(parking_lot::Mutex::new(
        crate::search_queue::SearchQueue::new(),
    ));
    owner
        .remove_search_sessions(Some(publication.search_id.parse().unwrap()), &queue)
        .await
        .unwrap();
    publication.result.observations[0].origin = "unused-after-session-removal".into();
    owner
        .observe_content(&events, Some(&publication))
        .await
        .unwrap();
    assert!(state.lock().await.searches.is_empty());
    assert_eq!(store.table_count("search_name_reporters").unwrap(), 0);
    assert_eq!(store.table_count("content_claim_observations").unwrap(), 1);
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn publication_uses_durable_independent_ed2k_and_kad_counts() {
    let (store, _state, owner, mut publication, mut events) = search_fixture().await;
    let id = publication.search_id.clone();
    for (origin, reporter, sources, complete, expected) in [
        (
            MetadataObservationOrigin::Kad,
            "192.0.2.9:4672",
            100,
            2,
            (100, 2),
        ),
        (
            MetadataObservationOrigin::Server,
            "192.0.2.1:4661",
            60,
            4,
            (100, 4),
        ),
        (
            MetadataObservationOrigin::Global,
            "192.0.2.1:4661",
            20,
            3,
            (100, 4),
        ),
        (
            MetadataObservationOrigin::Server,
            "192.0.2.2:4661",
            50,
            3,
            (110, 7),
        ),
    ] {
        events[0].origin = origin;
        events[0].reporter_endpoint = Some(reporter.parse().unwrap());
        events[0].metadata.source_count = Some(sources);
        events[0].metadata.complete_source_count = Some(complete);
        publication.result.sources = sources;
        publication.result.complete_sources = complete;
        let observation = &mut publication.result.observations[0];
        observation.origin = origin.as_str().into();
        observation.reporter_endpoint = Some(reporter.into());
        observation.sources = sources;
        observation.complete_sources = complete;
        owner
            .observe_content(&events, Some(&publication))
            .await
            .unwrap();
        let persisted = store
            .search_result_headers_page(id.parse().unwrap(), 0, 1)
            .unwrap()
            .unwrap()
            .items
            .remove(0);
        assert_eq!(
            (
                persisted.summary.source_count,
                persisted.summary.complete_source_count
            ),
            expected
        );
    }
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn durable_field_winners_combine_independent_incoming_fields() {
    let (store, _state, owner, mut publication, mut events) = search_fixture().await;
    let id = publication.search_id.clone();
    publication.result.observations[0].media.artist = "Sample Artist".into();
    publication.result.observations[0].sources = 3;
    events[0].metadata.media_artist = Some("Sample Artist".into());
    events[0].metadata.source_count = Some(3);
    owner
        .observe_content(&events, Some(&publication))
        .await
        .unwrap();
    publication.result.observations[0].media.artist.clear();
    publication.result.observations[0].media.codec = "flac".into();
    publication.result.observations[0].sources = 9;
    events[0].metadata.media_artist = None;
    events[0].metadata.media_codec = Some("flac".into());
    events[0].metadata.source_count = Some(9);
    owner
        .observe_content(&events, Some(&publication))
        .await
        .unwrap();
    let result = store
        .search_result_headers_page(id.parse().unwrap(), 0, 1)
        .unwrap()
        .unwrap()
        .items
        .remove(0);
    assert_eq!(result.summary.media_artist, "Sample Artist");
    assert_eq!(result.summary.media_codec, "flac");
    assert_eq!(
        store
            .search_result_observations_page(id.parse().unwrap(), result.claim_id, 0, 10)
            .unwrap()
            .unwrap()
            .items
            .len(),
        2
    );
    owner.close_and_drain().await.unwrap();
}
