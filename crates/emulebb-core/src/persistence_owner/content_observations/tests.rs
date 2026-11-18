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
        tokio::spawn(async move { owner.observe_content(&[event(), event()]).await })
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
    owner.observe_content(&[event()]).await.unwrap();
    owner.observe_content(&[event()]).await.unwrap();
    owner.close_and_drain().await.unwrap();
    assert!(matches!(
        owner.observe_content(&[event()]).await,
        Err(PersistenceError::Closing)
    ));
    let page = store.content_observations_page(1, 0, 10).unwrap();
    assert_eq!(page.items[0].receipt.observation_count, 2);
}
