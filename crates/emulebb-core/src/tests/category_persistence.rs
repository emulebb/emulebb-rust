use super::*;

fn category_create(name: &str) -> CategoryCreate {
    CategoryCreate {
        name: name.into(),
        temp_dir: NullableStringField::Missing,
        destination_dir: NullableStringField::Missing,
        comment: None,
    }
}

#[test]
fn public_category_is_nullable_and_patch_preserves_omission() {
    let missing: DownloadUpdate = serde_json::from_str("{}").unwrap();
    let cleared: DownloadUpdate = serde_json::from_str(r#"{"category":null}"#).unwrap();
    let assigned: DownloadUpdate = serde_json::from_str(r#"{"category":"Media"}"#).unwrap();
    assert_eq!(missing.category, None);
    assert_eq!(cleared.category, Some(None));
    assert_eq!(assigned.category, Some(Some("Media".into())));
    let category = Category {
        id: 42,
        name: "Media".into(),
        temp_dir: None,
        destination_dir: None,
        comment: String::new(),
    };
    let value = serde_json::to_value(category).unwrap();
    assert_eq!(value["name"], "Media");
    assert!(value.get("id").is_none());
}

#[tokio::test]
async fn category_root_stays_unavailable_until_a_successful_scan() {
    let root = unique_runtime_dir("category-root-availability");
    let destination = root.join("destination");
    std::fs::create_dir_all(&destination).unwrap();
    let core = EmulebbCore::new(
        "test",
        FileIndex::in_memory().unwrap(),
        root.join("transfers"),
    )
    .unwrap();
    core.create_category(CategoryCreate {
        name: "Media".into(),
        temp_dir: NullableStringField::Missing,
        destination_dir: NullableStringField::Value(destination.to_string_lossy().into_owned()),
        comment: None,
    })
    .await
    .unwrap();
    let expected = emulebb_ed2k::long_path::normal_path_display(&destination);
    let find = |roots: Vec<emulebb_metadata::MetadataSharedDirectoryRoot>| {
        roots
            .into_iter()
            .find(|item| emulebb_ed2k::long_path::normal_path_display(&item.path) == expected)
            .unwrap()
    };
    assert!(
        !find(
            core.metadata_store
                .implicit_shared_directory_roots()
                .unwrap()
        )
        .accessible
    );
    core.reload_shared_directories().await.unwrap();
    assert!(
        find(
            core.metadata_store
                .implicit_shared_directory_roots()
                .unwrap()
        )
        .accessible
    );
}

#[tokio::test]
async fn category_ids_survive_deletion_and_names_are_ascii_case_insensitive() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let first = core
        .create_category(category_create("First"))
        .await
        .unwrap();
    let second = core
        .create_category(category_create("Media"))
        .await
        .unwrap();
    let third = core
        .create_category(category_create("Third"))
        .await
        .unwrap();
    let conflict = core
        .create_category(category_create("MEDIA"))
        .await
        .unwrap_err();
    assert!(conflict.downcast_ref::<CategoryNameConflict>().is_some());
    core.delete_category(second.id).await.unwrap();
    let next = core.create_category(category_create("Next")).await.unwrap();
    assert!(next.id > third.id);
    assert_eq!(
        core.categories()
            .await
            .unwrap()
            .iter()
            .map(|value| value.id)
            .collect::<Vec<_>>(),
        vec![first.id, third.id, next.id]
    );
}

#[tokio::test]
async fn category_path_overrides_resolve_relative_to_profile_and_clear() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let category = core
        .create_category(CategoryCreate {
            name: "Offline".into(),
            temp_dir: NullableStringField::Value("temp-offline".into()),
            destination_dir: NullableStringField::Missing,
            comment: None,
        })
        .await
        .unwrap();
    assert_eq!(
        category.temp_dir.as_deref(),
        Some(
            core.profile_dir
                .join("temp-offline")
                .to_string_lossy()
                .as_ref()
        )
    );
    let changed = core
        .update_category(
            category.id,
            CategoryUpdate {
                temp_dir: NullableStringField::Null(()),
                ..CategoryUpdate::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(changed.temp_dir, None);
}

#[tokio::test]
async fn concurrent_case_equivalent_creates_have_one_winner() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let (first, second) = tokio::join!(
        core.create_category(category_create("Media")),
        core.create_category(category_create("MEDIA"))
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let failure = first.err().or_else(|| second.err()).unwrap();
    assert!(failure.downcast_ref::<CategoryNameConflict>().is_some());
    assert_eq!(core.categories().await.unwrap().len(), 1);
    core.drain_persistence().await.unwrap();
}

#[tokio::test]
async fn stopped_monitor_keeps_one_probe_and_final_kad_can_finish() {
    let root = unique_runtime_dir("category-probe-restart");
    let old_a = root.join("old-a");
    let old_b = root.join("old-b");
    let sibling = root.join("sibling");
    for path in [&old_a, &old_b, &sibling] {
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(path.join("same.bin"), b"one shared identity").unwrap();
    }
    let core = Arc::new(
        EmulebbCore::new(
            "test",
            FileIndex::in_memory().unwrap(),
            root.join("transfers"),
        )
        .unwrap(),
    );
    let category = |name: &str, path: &Path| CategoryCreate {
        name: name.into(),
        temp_dir: NullableStringField::Missing,
        destination_dir: NullableStringField::Value(path.to_string_lossy().into_owned()),
        comment: None,
    };
    let a = core.create_category(category("A", &old_a)).await.unwrap();
    let b = core.create_category(category("B", &old_b)).await.unwrap();
    configure_test_shared_root(&core, &sibling.join("same.bin")).await;
    core.reload_shared_directories().await.unwrap();
    for path in [&old_a, &old_b, &sibling] {
        core.share_local_file(LocalShareCreate {
            path: path.join("same.bin").to_string_lossy().into_owned(),
            name: None,
        })
        .await
        .unwrap();
    }
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    let id = owner.load_or_create_kad_node_id().await.unwrap();
    let dht = emulebb_kad_dht::DhtNode::new(emulebb_kad_dht::DhtConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        node_id: emulebb_kad_proto::NodeId::from_bytes(*id.as_bytes()),
        ..Default::default()
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), owner.attach_kad(&dht))
        .await
        .unwrap()
        .unwrap()
        .commit();
    tokio::time::timeout(
        Duration::from_secs(5),
        core.start_shared_directory_monitor(),
    )
    .await
    .unwrap();
    let (entered, entered_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    *core.category_probe_gate.lock().unwrap() = Some((entered, release_rx));
    let first = {
        let core = Arc::clone(&core);
        tokio::spawn(async move { core.delete_category(a.id).await })
    };
    tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), core.stop_shared_directory_monitor())
        .await
        .unwrap()
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<crate::persistence_owner::PersistenceError>(),
        Some(crate::persistence_owner::PersistenceError::CommittedPublicationFailed)
    ));
    tokio::time::timeout(
        Duration::from_secs(5),
        core.start_shared_directory_monitor(),
    )
    .await
    .unwrap();
    let (waiting, waiting_rx) = tokio::sync::oneshot::channel();
    *core.category_probe_waiting.lock().unwrap() = Some(waiting);
    let second = {
        let core = Arc::clone(&core);
        tokio::spawn(async move { core.delete_category(b.id).await })
    };
    tokio::time::timeout(Duration::from_secs(5), waiting_rx)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), core.stop_shared_directory_monitor())
        .await
        .unwrap()
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(5), second)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<crate::persistence_owner::PersistenceError>(),
        Some(crate::persistence_owner::PersistenceError::CommittedPublicationFailed)
    ));
    core.stop_persistence_admission().unwrap();
    tokio::time::timeout(Duration::from_secs(5), owner.finish_kad(&dht))
        .await
        .unwrap()
        .unwrap();
    release.send(()).unwrap();
    {
        let mut slot = core.category_probe_slot.lock().await;
        if let Some(task) = slot.as_mut() {
            let _ = tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .unwrap();
        }
        slot.take();
    }
    assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 1);
    tokio::time::timeout(Duration::from_secs(5), core.drain_persistence())
        .await
        .unwrap()
        .unwrap_err();
}
