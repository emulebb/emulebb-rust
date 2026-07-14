use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use emulebb_core::{
    CategoryCreate, CategoryPriorityValue, CoreSettingsUpdate, EmulebbCore, FriendCreate,
    LocalShareCreate, NullableStringField, NullableU32Field, ServerCreate, ServerUpdate,
    TransferCreate, TransferUpdate,
};
use emulebb_index::FileIndex;

#[tokio::test]
async fn profile_state_survives_core_restart() {
    let runtime_dir = unique_test_dir("profile-state");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");

    {
        let core = open_core(&metadata_path, &transfer_root);
        core.update_core_settings(CoreSettingsUpdate {
            download_limit_ki_bps: Some(2048),
            reconnect: Some(false),
            network_kademlia: Some(false),
            ..CoreSettingsUpdate::default()
        })
        .await
        .unwrap();
        let category = core
            .create_category(CategoryCreate {
                name: "Samples".to_string(),
                path: NullableStringField::Missing,
                comment: Some("Synthetic category".to_string()),
                color: NullableU32Field::Value(0x00aa11),
                priority: Some(CategoryPriorityValue::Name("high".to_string())),
            })
            .await
            .unwrap();
        assert_eq!(category.id, 1);
        core.add_friend(FriendCreate {
            user_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: Some("Peer One".to_string()),
        })
        .await
        .unwrap();
        core.add_server(ServerCreate {
            address: "192.0.2.10".to_string(),
            port: 4661,
            name: Some("Server One".to_string()),
            priority: Some("high".to_string()),
            static_server: Some(true),
            connect: Some(false),
        })
        .await
        .unwrap();
    }

    let reloaded = open_core(&metadata_path, &transfer_root);
    let core_settings = reloaded.core_settings().await;
    assert_eq!(core_settings.download_limit_ki_bps, 2048);
    assert!(!core_settings.reconnect);
    assert!(!core_settings.network_kademlia);

    let categories = reloaded.categories().await;
    assert_eq!(categories.len(), 2);
    assert_eq!(categories[1].name, "Samples");
    assert_eq!(categories[1].priority, 2);

    let friends = reloaded.friends().await;
    assert_eq!(friends.len(), 1);
    assert_eq!(friends[0].name, "Peer One");

    let server = reloaded.server("192.0.2.10:4661").await.unwrap();
    assert_eq!(server.name, "Server One");
    assert_eq!(server.priority, "high");
    assert!(server.static_server);
    assert!(server.enabled);

    reloaded
        .update_server(
            "192.0.2.10:4661",
            ServerUpdate {
                name: Some("Server Renamed".to_string()),
                priority: Some("low".to_string()),
                static_server: Some(false),
                enabled: None,
            },
        )
        .await
        .unwrap();
    reloaded
        .delete_friend("00112233445566778899aabbccddeeff")
        .await
        .unwrap();
    reloaded.delete_category(1).await.unwrap();
    reloaded.remove_server("192.0.2.10:4661").await.unwrap();

    let reloaded_again = open_core(&metadata_path, &transfer_root);
    assert_eq!(reloaded_again.categories().await.len(), 1);
    assert!(reloaded_again.friends().await.is_empty());
    let disabled_server = reloaded_again.server("192.0.2.10:4661").await.unwrap();
    assert!(!disabled_server.enabled);
    assert_eq!(disabled_server.name, "Server Renamed");
}

#[tokio::test]
async fn unshared_file_marker_survives_core_restart() {
    let runtime_dir = unique_test_dir("unshared-file");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let source_path = runtime_dir.join("sample.bin");
    fs::write(&source_path, b"synthetic share payload").unwrap();

    let file_hash = {
        let core = open_core(&metadata_path, &transfer_root);
        let share = core
            .share_local_file(LocalShareCreate {
                path: source_path.display().to_string(),
                name: Some("Sample.bin".to_string()),
            })
            .await
            .unwrap();
        let file_hash = share.hash.clone();
        core.unshare_file(&file_hash).await.unwrap();
        file_hash
    };

    let reloaded = open_core(&metadata_path, &transfer_root);
    assert!(reloaded.share(&file_hash).await.is_none());
}

#[tokio::test]
async fn delete_category_resets_referencing_transfers_to_uncategorized() {
    let runtime_dir = unique_test_dir("delete-category-reset");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let payload_path = runtime_dir.join("Shared.Payload.bin");
    fs::write(&payload_path, b"category reset payload").unwrap();
    let core = open_core(&metadata_path, &transfer_root);

    let share = core
        .share_local_file(LocalShareCreate {
            path: payload_path.display().to_string(),
            name: Some("Shared.Payload.bin".to_string()),
        })
        .await
        .unwrap();
    // Shared files stay out of the transfer queue; re-adding the link restores
    // the completed transfer row so this test has a real queued transfer to
    // categorize (same restore path as the share lifecycle tests).
    let restored = core
        .create_transfer(TransferCreate {
            link: Some(share.ed2k_link.clone()),
            links: None,
            category_id: None,
            category_name: None,
            paused: None,
        })
        .await
        .unwrap();
    assert_eq!(restored.hash, share.hash);
    let category = core
        .create_category(CategoryCreate {
            name: "Movies".to_string(),
            path: NullableStringField::Missing,
            comment: None,
            color: NullableU32Field::Missing,
            priority: None,
        })
        .await
        .unwrap();
    assert_ne!(category.id, 0);

    let updated = core
        .update_transfer(
            &share.hash,
            TransferUpdate {
                category_id: Some(category.id),
                ..TransferUpdate::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.category_id, category.id);
    assert_eq!(updated.category_name, "Movies");

    assert!(core.delete_category(category.id).await.unwrap().is_some());

    let transfer = core.transfer(&share.hash).await.unwrap();
    assert_eq!(
        transfer.category_id, 0,
        "transfer category_id must reset to uncategorized after its category is deleted"
    );
    assert_eq!(transfer.category_name, "");

    // Idempotent: deleting an already-removed category returns None.
    assert!(core.delete_category(category.id).await.unwrap().is_none());
}

fn open_core(metadata_path: &Path, transfer_root: &Path) -> EmulebbCore {
    EmulebbCore::new(
        "test",
        FileIndex::open(metadata_path).unwrap(),
        transfer_root,
    )
    .unwrap()
}

fn unique_test_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let root = std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT")
        .map(PathBuf::from)
        .map(|path| path.join("tmp"))
        .unwrap_or_else(std::env::temp_dir);
    let path = root.join(format!(
        "emulebb-core-{name}-{}-{stamp}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("create test dir");
    path
}
