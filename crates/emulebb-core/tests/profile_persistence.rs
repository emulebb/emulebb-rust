use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use emulebb_core::{
    AppSettingsUpdate, CategoryCreate, CoreSettingsUpdate, DownloadCreate, DownloadCreateSource,
    EmulebbCore, FriendCreate, LocalShareCreate, NullableStringField, ServerCreate, ServerUpdate,
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
            network_kademlia: Some(false),
            ..CoreSettingsUpdate::default()
        })
        .await
        .unwrap();
        let category = core
            .create_category(CategoryCreate {
                name: "Samples".to_string(),
                temp_dir: NullableStringField::Missing,
                destination_dir: NullableStringField::Missing,
                comment: Some("Synthetic category".to_string()),
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
    assert!(!core_settings.network_kademlia);

    let categories = reloaded.categories().await.unwrap();
    assert_eq!(categories.len(), 1);
    assert_eq!(categories[0].name, "Samples");

    let friends = reloaded.friends().await.unwrap();
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
    assert!(reloaded_again.categories().await.unwrap().is_empty());
    assert!(reloaded_again.friends().await.unwrap().is_empty());
    let disabled_server = reloaded_again.server("192.0.2.10:4661").await.unwrap();
    assert!(!disabled_server.enabled);
    assert_eq!(disabled_server.name, "Server Renamed");
}

#[tokio::test]
async fn network_and_upload_settings_survive_core_restart() {
    let runtime_dir = unique_test_dir("network-upload-settings");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");

    {
        let core = open_core(&metadata_path, &transfer_root);
        let update: AppSettingsUpdate = serde_json::from_value(serde_json::json!({
            "core": {
                "uploadLimitKiBps": 2048,
                "uploadClientDataRate": 64,
                "baseUploadSlots": 5,
                "uploadSlotElasticPercent": 70,
                "queueSize": 4000
            },
            "ed2k": {
                "listenPort": 11719,
                "reconnectEnabled": false,
                "safeServerConnect": true,
                "addServersFromServer": true,
                "serverKeepaliveMinutes": 45,
                "uploadQueue": {
                    "elasticUnderfillSecs": 12,
                    "waitingTimeoutSecs": 1800,
                    "grantedTimeoutSecs": 7,
                    "uploadTimeoutSecs": 45,
                    "sessionTransferPercent": 75,
                    "sessionTimeLimitSecs": 3600
                }
            },
            "kad": {
                "listenPort": 11719
            }
        }))
        .unwrap();

        core.update_app_settings(update).await.unwrap();
    }

    let reloaded = open_core(&metadata_path, &transfer_root);
    let settings = reloaded.app_settings().await.unwrap();
    assert_eq!(settings.core.upload_limit_ki_bps, 2048);
    assert_eq!(settings.core.upload_client_data_rate, 64);
    assert_eq!(settings.core.base_upload_slots, 5);
    assert_eq!(settings.core.upload_slot_elastic_percent, 70);
    assert_eq!(settings.core.queue_size, 4000);
    assert_eq!(settings.ed2k.listen_port, Some(11719));
    assert!(!settings.ed2k.reconnect_enabled);
    assert!(settings.ed2k.safe_server_connect);
    assert!(settings.ed2k.add_servers_from_server);
    assert_eq!(settings.ed2k.server_keepalive_minutes, 45);
    assert_eq!(settings.ed2k.upload_queue.elastic_underfill_secs, 12);
    assert_eq!(settings.ed2k.upload_queue.waiting_timeout_secs, 1800);
    assert_eq!(settings.ed2k.upload_queue.granted_timeout_secs, 7);
    assert_eq!(settings.ed2k.upload_queue.upload_timeout_secs, 45);
    assert_eq!(settings.ed2k.upload_queue.session_transfer_percent, 75);
    assert_eq!(settings.ed2k.upload_queue.session_time_limit_secs, 3600);
    assert_eq!(settings.kad.listen_port, Some(11719));
}

#[tokio::test]
async fn removed_shared_root_survives_core_restart() {
    let runtime_dir = unique_test_dir("unshared-file");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let source_path = runtime_dir.join("sample.bin");
    fs::write(&source_path, b"synthetic share payload").unwrap();

    let file_hash = {
        let core = open_core(&metadata_path, &transfer_root);
        core.add_shared_directory_root(&runtime_dir.display().to_string())
            .await
            .unwrap();
        let share = core
            .share_local_file(LocalShareCreate {
                path: source_path.display().to_string(),
                name: Some("Sample.bin".to_string()),
            })
            .await
            .unwrap();
        let file_hash = share.hash.clone();
        core.remove_shared_directory_root(&runtime_dir.display().to_string())
            .await
            .unwrap();
        file_hash
    };

    let reloaded = open_core(&metadata_path, &transfer_root);
    assert!(reloaded.share(&file_hash).await.is_none());
}

#[tokio::test]
async fn delete_category_resets_referencing_downloads_to_uncategorized() {
    let runtime_dir = unique_test_dir("delete-category-reset");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let core = open_core(&metadata_path, &transfer_root);
    let category = core
        .create_category(CategoryCreate {
            name: "Movies".to_string(),
            temp_dir: NullableStringField::Missing,
            destination_dir: NullableStringField::Missing,
            comment: None,
        })
        .await
        .unwrap();
    assert_ne!(category.id, 0);

    let (created, download) = core
        .create_download(DownloadCreate {
            source: DownloadCreateSource::Content {
                hash: "45454545454545454545454545454545".into(),
                name: "Sample.bin".into(),
                size_bytes: Some(16),
            },
            category: Some(category.name.clone()),
            intent: emulebb_metadata::DownloadIntent::Stopped,
            redownload: false,
        })
        .await
        .unwrap();
    assert!(created);
    assert_eq!(download.hash, "45454545454545454545454545454545");
    assert_eq!(download.category.as_deref(), Some("Movies"));
    let id = download.id;
    drop(download);
    assert!(core.delete_category(category.id).await.unwrap().is_some());

    let page = core.download_page(Default::default()).await.unwrap();
    let download = page
        .downloads
        .iter()
        .find(|download| download.id == id)
        .unwrap();
    assert_eq!(
        download.category, None,
        "deleting a category resets its existing jobs to uncategorized"
    );
    drop(page);
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
