use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use emulebb_core::{
    CategoryCreate, DownloadCreate, DownloadCreateSource, EmulebbCore, FriendCreate,
    LocalShareCreate, NullableStringField,
};
use emulebb_index::FileIndex;
use emulebb_metadata::{MetadataServerCreate, MetadataServerUpdate};

#[tokio::test]
async fn profile_state_survives_core_restart() {
    let runtime_dir = unique_test_dir("profile-state");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");

    let server_id;
    {
        let core = open_core(&metadata_path, &transfer_root);
        core.update_settings(
            &serde_json::from_value(serde_json::json!({
                "expectedRevision":"1", "set":{
                    "transfers":{"downloadLimitBytesPerSecond":2097152},
                    "network":{"kadEnabled":false}
                }
            }))
            .unwrap(),
        )
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
        server_id = core
            .create_server_resource(&MetadataServerCreate {
                address: "192.0.2.10".into(),
                port: 4661,
                priority: "high".into(),
                static_server: true,
                enabled: true,
            })
            .await
            .unwrap();
    }

    let reloaded = open_core(&metadata_path, &transfer_root);
    let values = reloaded.effective_settings().await.unwrap();
    assert_eq!(values.transfers.download_limit_bytes_per_second, 2097152);
    assert!(!values.network.kad_enabled);

    let categories = reloaded.categories().await.unwrap();
    assert_eq!(categories.len(), 1);
    assert_eq!(categories[0].name, "Samples");

    let friends = reloaded.friends().await.unwrap();
    assert_eq!(friends.len(), 1);
    assert_eq!(friends[0].name, "Peer One");

    let server = reloaded.server("192.0.2.10:4661").await.unwrap();
    assert_eq!(server.priority, "high");
    assert!(server.static_server);
    assert!(server.enabled);

    reloaded
        .update_server_resource(
            server_id,
            &MetadataServerUpdate {
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
    reloaded
        .update_server_resource(
            server_id,
            &MetadataServerUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let reloaded_again = open_core(&metadata_path, &transfer_root);
    assert!(reloaded_again.categories().await.unwrap().is_empty());
    assert!(reloaded_again.friends().await.unwrap().is_empty());
    let disabled_server = reloaded_again.server("192.0.2.10:4661").await.unwrap();
    assert!(!disabled_server.enabled);
    assert_eq!(disabled_server.priority, "low");
    assert!(!disabled_server.static_server);
    assert_eq!(
        reloaded_again
            .server_resource(server_id)
            .await
            .unwrap()
            .unwrap()
            .id,
        server_id.to_string()
    );
    assert!(
        reloaded_again
            .delete_server_resource(server_id)
            .await
            .unwrap()
    );
    let after_deletion = open_core(&metadata_path, &transfer_root);
    assert!(
        after_deletion
            .server_by_id(server_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn network_and_upload_settings_survive_core_restart() {
    let runtime_dir = unique_test_dir("network-upload-settings");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");

    {
        let core = open_core(&metadata_path, &transfer_root);
        let patch = serde_json::from_value(serde_json::json!({
            "expectedRevision":"1", "set": {
                "network": {"p2p":{"tcpPort":11719,"udpPort":11719},
                    "servers":{"autoReconnect":false,"safeConnect":true,"acceptServerListUpdates":true,"keepaliveMinutes":45}},
                "transfers":{"uploadLimitBytesPerSecond":2097152,"upload":{
                    "targetClientRateBytesPerSecond":65536,"baseSlots":5,"elasticPercent":70,"queueCapacity":4000,
                    "sessionTransferPercent":75,"sessionTimeLimitSeconds":3600}}
            }
        })).unwrap();
        core.update_settings(&patch).await.unwrap();
    }
    let reloaded = open_core(&metadata_path, &transfer_root);
    let settings = reloaded.effective_settings().await.unwrap();
    assert_eq!(settings.transfers.upload_limit_bytes_per_second, 2097152);
    assert_eq!(
        settings
            .transfers
            .upload
            .target_client_rate_bytes_per_second,
        65536
    );
    assert_eq!(settings.transfers.upload.base_slots, 5);
    assert_eq!(settings.transfers.upload.elastic_percent, 70);
    assert_eq!(settings.transfers.upload.queue_capacity, 4000);
    assert_eq!(settings.network.p2p.tcp_port, 11719);
    assert_eq!(settings.network.p2p.udp_port, 11719);
    assert!(!settings.network.servers.auto_reconnect);
    assert!(settings.network.servers.safe_connect);
    assert!(settings.network.servers.accept_server_list_updates);
    assert_eq!(settings.network.servers.keepalive_minutes, 45);
    assert_eq!(settings.transfers.upload.session_transfer_percent, 75);
    assert_eq!(settings.transfers.upload.session_time_limit_seconds, 3600);
}

#[tokio::test]
async fn removed_shared_root_survives_core_restart() {
    let runtime_dir = unique_test_dir("unshared-file");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let shared_root = runtime_dir.join("library");
    fs::create_dir_all(&shared_root).unwrap();
    let source_path = shared_root.join("sample.bin");
    fs::write(&source_path, b"synthetic share payload").unwrap();

    let file_hash = {
        let core = open_core(&metadata_path, &transfer_root);
        let root = core
            .create_library_root(&shared_root.display().to_string(), false)
            .await
            .unwrap()
            .unwrap();
        let share = core
            .share_local_file(LocalShareCreate {
                path: source_path.display().to_string(),
                name: Some("Sample.bin".to_string()),
            })
            .await
            .unwrap();
        let file_hash = share.hash.clone();
        core.delete_library_root(root.id).await.unwrap();
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
