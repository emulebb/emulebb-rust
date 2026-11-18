use super::*;
use crate::persistence_owner::content_observations::tests::search_fixture;
use crate::persistence_owner::tests::{usage, wait_for_slots};
use tokio_util::sync::CancellationToken;

async fn transition_after_disconnect(phase: Phase) {
    let (store, state, owner, publication, observations) = search_fixture().await;
    owner
        .observe_content(&observations, Some(&publication))
        .await
        .unwrap();
    let id = publication.search_id.clone();
    let cancel = CancellationToken::new();
    state
        .lock()
        .await
        .search_cancels
        .insert(id.clone(), cancel.clone());
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let expected = phase.status();
    let caller = {
        let owner = Arc::clone(&owner);
        let id = id.clone();
        let mut votes = KadAichSearchVotes::default();
        votes.record("192.0.2.4".parse().unwrap(), [0x12; 20]);
        let votes = matches!(phase, Phase::Completed).then(|| {
            HashMap::from([
                (publication.result.hash.clone(), votes.clone()),
                ("ff".repeat(16), votes),
            ])
        });
        tokio::spawn(async move {
            owner
                .transition_search(Transition {
                    id,
                    phase,
                    reason: Some("test-reason".into()),
                    method: Some("server".into()),
                    method_token: "server",
                    votes,
                })
                .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert_eq!(store.load_searches().unwrap()[0].data.status, expected);
    caller.abort();
    *owner.publication_gate.lock().unwrap() = None;
    gate.release.notify_one();
    wait_for_slots(&owner, 0).await;
    let snapshot = state.lock().await;
    assert_eq!(snapshot.searches[&id].status, expected);
    assert_eq!(snapshot.searches[&id].results.len(), 1);
    assert_eq!(
        snapshot.searches[&id].status_reason.as_deref(),
        Some("test-reason")
    );
    assert_eq!(
        snapshot.search_cancels.contains_key(&id),
        matches!(phase, Phase::Running)
    );
    assert_eq!(cancel.is_cancelled(), matches!(phase, Phase::Error));
    assert_eq!(
        snapshot.kad_aich_search_votes.len(),
        usize::from(matches!(phase, Phase::Completed))
    );
    drop(snapshot);
    assert_eq!(
        store.content_observations_page(1, 0, 10).unwrap().items[0]
            .receipt
            .observation_count,
        1
    );
    if !matches!(phase, Phase::Running) {
        owner
            .transition_search(Transition {
                id: id.clone(),
                phase: Phase::Running,
                reason: None,
                method: None,
                method_token: "server",
                votes: None,
            })
            .await
            .unwrap();
        assert_eq!(state.lock().await.searches[&id].status, expected);
        assert_eq!(store.load_searches().unwrap()[0].data.status, expected);
    }
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn running_status_publishes_after_caller_disconnect() {
    transition_after_disconnect(Phase::Running).await;
}
#[tokio::test]
async fn completion_publishes_votes_without_replaying_results_after_disconnect() {
    transition_after_disconnect(Phase::Completed).await;
}
#[tokio::test]
async fn failure_publishes_cancellation_after_caller_disconnect() {
    transition_after_disconnect(Phase::Error).await;
}
