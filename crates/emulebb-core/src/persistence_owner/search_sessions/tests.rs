use super::*;
use crate::persistence_owner::content_observations::tests::search_fixture;
use crate::persistence_owner::tests::{usage, wait_for_slots};
use crate::search_queue::SearchQueueLane;
use tokio_util::sync::CancellationToken;

async fn removal_after_disconnect(clear: bool) {
    let (store, state, owner, publication, observations) = search_fixture().await;
    owner
        .observe_content(&observations, Some(&publication))
        .await
        .unwrap();
    let first_id = publication.search_id.clone();
    let queue = Arc::new(parking_lot::Mutex::new(SearchQueue::new()));
    let first_cancel = CancellationToken::new();
    let second_cancel = CancellationToken::new();
    let mut second = state.lock().await.searches[&first_id].clone();
    second.spec.query = "another query".into();
    second.id = crate::search_state::create_search(&store, &second).unwrap();
    let second_id = second.id.clone();
    {
        let mut state = state.lock().await;
        state.searches.insert(second_id.clone(), second);
        state
            .search_cancels
            .insert(first_id.clone(), first_cancel.clone());
        state
            .search_cancels
            .insert(second_id.clone(), second_cancel.clone());
        let mut queue = queue.lock();
        for id in [&first_id, &second_id] {
            let request = state.searches[id].spec.clone();
            let prepared = queue
                .prepare_enqueue(request, SearchQueueLane::Server, Instant::now())
                .unwrap();
            queue.commit_enqueue(prepared, id.clone());
        }
    }
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let caller = {
        let owner = Arc::clone(&owner);
        let queue = Arc::clone(&queue);
        let id = (!clear).then(|| first_id.parse().unwrap());
        tokio::spawn(async move { owner.remove_search_sessions(id, &queue).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert_eq!(
        store.search_headers_page(None, 10).unwrap().items.len(),
        usize::from(!clear)
    );
    caller.abort();
    *owner.publication_gate.lock().unwrap() = None;
    let late_ingress = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move {
            owner
                .observe_content(&observations, Some(&publication))
                .await
        })
    };
    gate.release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), late_ingress)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    wait_for_slots(&owner, 0).await;
    let state = state.lock().await;
    assert!(!state.searches.contains_key(&first_id));
    assert_eq!(state.searches.contains_key(&second_id), !clear);
    assert_eq!(queue.lock().pending_len(), usize::from(!clear));
    assert!(first_cancel.is_cancelled());
    assert_eq!(second_cancel.is_cancelled(), clear);
    assert_eq!(state.search_cancels.len(), usize::from(!clear));
    drop(state);
    assert_eq!(store.table_count("search_result_observations").unwrap(), 0);
    assert_eq!(
        store.content_observations_page(1, 0, 10).unwrap().items[0]
            .receipt
            .observation_count,
        2
    );
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn delete_finishes_after_disconnect_and_late_ingress_cannot_restore_membership() {
    removal_after_disconnect(false).await;
}

#[tokio::test]
async fn clear_finishes_after_disconnect_and_preserves_independent_evidence() {
    removal_after_disconnect(true).await;
}
