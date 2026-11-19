use super::super::tests::{setup, usage};
use super::*;

#[tokio::test]
async fn root_reply_keeps_quota_through_projection_and_serialization() {
    let (store, _state, owner) = setup();
    let path = std::env::temp_dir().join("root-read-does-not-probe");
    let root = store
        .create_library_root(&path, false, false)
        .unwrap()
        .unwrap();
    let reply = owner.read_library_roots(Query::Get(root.id)).await.unwrap();
    assert_eq!(usage(&owner), (0, RESULT_BYTES));
    let reply = reply.map(|value| match value {
        Value::Root(Some(root)) => root,
        _ => panic!("expected root"),
    });
    let json = serde_json::to_value(&reply).unwrap();
    assert_eq!(json["id"], root.id.to_string());
    assert_eq!(
        json["path"],
        emulebb_metadata::NativePath::from(path).display_path()
    );
    assert_eq!(json["accessible"], false);
    assert_eq!(json["watchEnabled"], false);
    store.patch_library_root_watch(root.id, true).unwrap();
    // The serialized response is a committed read snapshot, independent of later edits.
    assert_eq!(serde_json::to_value(&reply).unwrap()["watchEnabled"], false);
    assert_eq!(usage(&owner), (0, RESULT_BYTES));
    drop(reply);
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn retained_root_replies_exhaust_and_release_the_shared_budget() {
    let (_store, _state, owner) = setup();
    let mut replies = Vec::new();
    for _ in 0..7 {
        replies.push(
            owner
                .read_library_roots(Query::Get(i64::MAX))
                .await
                .unwrap(),
        );
    }
    assert_eq!(usage(&owner), (0, 7 * RESULT_BYTES));
    assert!(matches!(
        owner.read_library_roots(Query::Get(i64::MAX)).await,
        Err(PersistenceError::Busy)
    ));
    replies.pop();
    drop(
        owner
            .read_library_roots(Query::Page {
                after: 0,
                limit: 100,
            })
            .await
            .unwrap(),
    );
    drop(replies);
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}

#[tokio::test]
async fn core_root_reads_preserve_cached_health_and_page_managed_resources() {
    let core =
        crate::EmulebbCore::new_in_memory("test", crate::FileIndex::in_memory().unwrap()).unwrap();
    let path = std::env::temp_dir().join("root-read-cached-health");
    let root = core
        .metadata_store
        .create_library_root(&path, false, true)
        .unwrap()
        .unwrap();
    core.metadata_store
        .clone()
        .replace_implicit_shared_directory_roots(&[emulebb_metadata::MetadataSharedDirectoryRoot {
            path: path.to_string_lossy().into_owned(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    let page = core.library_root_page(0, 1).await.unwrap();
    assert_eq!(page.value().total, 1);
    assert!(page.value().next_id.is_none());
    assert!(page.value().roots[0].managed && page.value().roots[0].accessible);
    let point = core.library_root(root.id).await.unwrap();
    assert_eq!(point.value().as_ref(), Some(&page.value().roots[0]));
    assert!(core.library_root(i64::MAX).await.unwrap().value().is_none());
    assert!(core.library_root(0).await.is_err());
    assert!(core.library_root_page(-1, 1).await.is_err());
    assert!(core.library_root_page(0, 101).await.is_err());
    assert!(core.library_root_page(0, 0).await.is_err());
    drop(page);
    drop(point);
    core.drain_persistence().await.unwrap();
}

#[test]
fn root_timestamps_use_unix_seconds_and_ids_remain_decimal_strings() {
    let root = crate::LibraryRoot::from(emulebb_metadata::MetadataLibraryRoot {
        id: i64::MAX,
        path: std::env::temp_dir(),
        watch_enabled: false,
        managed: false,
        accessible: false,
        shareable: true,
        last_scanned_at_ms: Some(1_234_567),
    });
    let json = serde_json::to_value(root).unwrap();
    assert_eq!(json["id"], i64::MAX.to_string());
    assert_eq!(json["lastScannedAt"], 1234);
}
