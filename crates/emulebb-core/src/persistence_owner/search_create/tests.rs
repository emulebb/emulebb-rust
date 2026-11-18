use super::*;
use crate::persistence_owner::tests::{usage, wait_for_slots};

#[tokio::test]
async fn creation_finishes_queue_and_cache_publication_after_caller_disconnect() {
    let root = crate::unique_runtime_dir("owned-search-create");
    let network =
        crate::tests::test_network_config_with_store(&root, Default::default(), Default::default());
    let core = EmulebbCore::new_with_network(
        "test",
        crate::FileIndex::in_memory().unwrap(),
        &root,
        Some(network),
    )
    .unwrap();
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let caller = {
        let core = core.clone();
        tokio::spawn(async move {
            core.create_search(SearchCreate {
                query: "owned creation".into(),
                method: "server".into(),
                ..Default::default()
            })
            .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    let rows = core
        .metadata_store
        .search_headers_page(None, 10)
        .unwrap()
        .items;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].data.status, "queued");
    caller.abort();
    *owner.publication_gate.lock().unwrap() = None;
    gate.release.notify_one();
    wait_for_slots(&owner, 0).await;
    let id = rows[0].id.to_string();
    assert_eq!(
        core.metadata_store
            .search_header(id.parse().unwrap())
            .unwrap()
            .unwrap()
            .id
            .to_string(),
        id
    );
    assert!(core.state.lock().await.search_cancels.contains_key(&id));
    assert_eq!(core.search_queue.lock().pending_len(), 1);
    assert!(core.search_queue.lock().drain_task_running());
    assert_eq!(usage(&owner), (0, 0));
    core.clear_searches().await.unwrap();
    core.drain_persistence().await.unwrap();
}
