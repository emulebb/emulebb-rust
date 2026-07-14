use super::*;

#[test]
fn keyword_target_is_stable() {
    assert_eq!(
        hex::encode(keyword_target("Torino Train").0),
        "b2bc3aa39f375069e7c27eb83ce6baf3"
    );
}

#[test]
fn keyword_target_uses_hash_token_for_exact_ed2k_hash_queries() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    assert_eq!(
        keyword_target(&format!("ed2k::{exact_hash}")),
        keyword_target(&exact_hash.to_ascii_uppercase())
    );
}

#[test]
fn exact_ed2k_hash_queries_use_configured_server_budget() {
    let mut config = Ed2kRuntimeConfig {
        server_endpoints: vec![
            "192.0.2.1:4661".to_string(),
            "192.0.2.2:4661".to_string(),
            "192.0.2.3:4661".to_string(),
            "192.0.2.4:4661".to_string(),
            "192.0.2.5:4661".to_string(),
        ],
        keyword_server_attempt_budget: 2,
        exact_hash_keyword_server_attempt_budget: 4,
        ..Ed2kRuntimeConfig::default()
    };
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    assert_eq!(
        ed2k_keyword_server_attempts(&config, &format!("ed2k::{exact_hash}")),
        4
    );
    assert_eq!(ed2k_keyword_server_attempts(&config, "ubuntu linux"), 2);

    config.exact_hash_keyword_server_attempt_budget = 99;
    assert_eq!(
        ed2k_keyword_server_attempts(&config, &exact_hash.to_ascii_uppercase()),
        5
    );
}

#[test]
fn select_ed2k_keyword_metadata_prefers_exact_hash_with_size_and_name() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]);
    let other_hash = Ed2kHash::from_bytes([0xAA; 16]);
    let metadata = select_ed2k_keyword_metadata(
        &[
            Ed2kSearchFile {
                file_hash: exact_hash,
                file_name: Some(String::new()),
                file_size: Some(0),
                file_type: None,
                source_count: Some(100),
            },
            Ed2kSearchFile {
                file_hash: other_hash,
                file_name: Some("wrong.bin".to_string()),
                file_size: Some(123),
                file_type: None,
                source_count: Some(5),
            },
            Ed2kSearchFile {
                file_hash: exact_hash,
                file_name: Some("resolved.bin".to_string()),
                file_size: Some(4_294_967_299),
                file_type: Some("Pro".to_string()),
                source_count: Some(12),
            },
        ],
        exact_hash,
    )
    .unwrap();

    assert_eq!(metadata.canonical_name.as_deref(), Some("resolved.bin"));
    assert_eq!(metadata.file_size, Some(4_294_967_299));
}

#[test]
fn kad_search_result_exposes_exact_hash_metadata() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]);
    let metadata = select_kad_keyword_metadata(
        &KadSearchResult {
            hash: exact_hash,
            names: vec!["resolved.bin".to_string()],
            size: Some(5_000),
            source_count: Some(3),
            tags: Vec::new(),
        },
        exact_hash,
    )
    .unwrap();

    assert_eq!(metadata.canonical_name.as_deref(), Some("resolved.bin"));
    assert_eq!(metadata.file_size, Some(5_000));
}

#[tokio::test]
async fn download_search_result_creates_transfer() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.index_file(IndexedFile {
        ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
        name: "Download.Me.bin".to_string(),
        size_bytes: 4096,
        content_type: "archive".to_string(),
        availability_score: 1,
    })
    .await
    .unwrap();
    let search = core
        .create_search(SearchCreate {
            query: "download me".to_string(),
            method: "automatic".to_string(),
            r#type: String::new(),
            ..Default::default()
        })
        .await
        .unwrap();

    let transfer = core
        .download_search_result(
            &search.id,
            "00112233445566778899aabbccddeeff",
            SearchResultDownloadCreate::default(),
        )
        .await
        .unwrap()
        .unwrap();
    // A non-paused download starts immediately (eMule/aMule parity).
    assert_eq!(transfer.state, "downloading");
}

#[tokio::test]
async fn create_transfer_uses_canonical_link_and_paused_state() {
    let runtime_dir = unique_runtime_dir("emulebb-core-paused-transfer-create");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();

    let transfer = core
        .create_transfer(TransferCreate {
            link: Some(
                "ed2k://|file|Paused.Create.bin|4096|00112233445566778899aabbccddeeff|/"
                    .to_string(),
            ),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap();

    assert_eq!(transfer.state, "paused");
    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    assert_eq!(
        reloaded
            .transfer("00112233445566778899aabbccddeeff")
            .await
            .unwrap()
            .state,
        "paused"
    );
}

#[tokio::test]
async fn create_transfer_remembers_ed2k_link_source_hints() {
    let runtime_dir = unique_runtime_dir("emulebb-core-create-transfer-source-hints");
    let transfer_root = runtime_dir.join("transfers");
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();

    let transfer = core
        .create_transfer(TransferCreate {
            link: Some(
                "ed2k://|file|Seeded.Link.bin|4096|00112233445566778899aabbccddeeff|sources,192.0.2.10:4662:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,bad-source,192.0.2.10:4662,192.0.2.11:0|/"
                    .to_string(),
            ),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap();

    let sources = core
        .transfer_sources(&transfer.hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].address, "192.0.2.10");
    assert_eq!(sources[0].port, 4662);
    assert_eq!(
        sources[0].user_hash.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}

#[test]
fn transfer_create_rejects_legacy_ed2k_link_field() {
    let error = serde_json::from_str::<TransferCreate>(
        r#"{"ed2kLink":"ed2k://|file|Legacy.bin|1|00112233445566778899aabbccddeeff|/"}"#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("unknown field `ed2kLink`"));
}

#[test]
fn category_id_selector_ignores_malformed_category_name_like_master() {
    let request = serde_json::from_str::<TransferCreate>(
        r#"{"link":"ed2k://|file|Selector.bin|1|00112233445566778899aabbccddeeff|/","categoryId":0,"categoryName":1}"#,
    )
    .unwrap();

    assert_eq!(request.category_id, Some(0));
    assert_eq!(request.category_name, None);
}

#[tokio::test]
async fn delete_transfer_files_removes_manifest_and_transfer_row() {
    let runtime_dir = unique_runtime_dir("emulebb-core-delete-transfer-files");
    let transfer_root = runtime_dir.join("transfers");
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
    let transfer = core
        .create_transfer(TransferCreate {
            link: Some(
                "ed2k://|file|Delete.Me.bin|4096|00112233445566778899aabbccddeeff|/".to_string(),
            ),
            links: None,
            category_id: None,
            category_name: None,
            paused: None,
        })
        .await
        .unwrap();
    let transfer_dir = transfer_root.join(&transfer.hash);
    assert!(transfer_dir.is_dir());

    let deleted = core
        .delete_transfer_files(&transfer.hash)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(deleted.hash, transfer.hash);
    assert!(!transfer_dir.exists());
    assert!(core.transfer(&transfer.hash).await.is_none());
}

#[tokio::test]
async fn delete_transfer_files_removes_delivered_completed_download() {
    let runtime_dir = unique_runtime_dir("emulebb-core-delete-delivered-transfer");
    let transfer_root = runtime_dir.join("transfers");
    let incoming_dir = runtime_dir.join("incoming");
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root)
        .unwrap()
        .with_incoming_dir(incoming_dir.clone());
    let payload = b"completed delivered download payload".repeat(64);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into()).to_string();
    let transfer = core
        .create_transfer(TransferCreate {
            link: Some(format!(
                "ed2k://|file|Delivered.Delete.bin|{}|{}|/",
                payload.len(),
                file_hash
            )),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap();

    core.ed2k_transfers
        .store_md4_hashset(&file_hash, Vec::new())
        .await
        .unwrap();
    core.ed2k_transfers
        .store_piece_data(&file_hash, 0, &payload)
        .await
        .unwrap();
    let completed = core
        .refresh_transfer_from_manifest_default(&file_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.state, "completed");
    core.deliver_completed_transfer(&file_hash).await;
    let delivered_manifest = core.ed2k_transfers.manifest(&file_hash).await.unwrap();
    let delivered_path = PathBuf::from(delivered_manifest.delivered_path.as_deref().unwrap());
    assert_eq!(std::fs::read(&delivered_path).unwrap(), payload);

    let row_only = core
        .delete_completed_transfer_row(&file_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row_only.hash, transfer.hash);
    assert!(
        delivered_path.exists(),
        "row-only completed transfer removal must preserve the delivered file"
    );

    let deleted = core
        .delete_transfer_files(&file_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deleted.hash, transfer.hash);
    assert!(
        !delivered_path.exists(),
        "destructive transfer delete must remove the delivered completed file"
    );
    assert!(!transfer_root.join(&file_hash).exists());
    assert!(core.transfer(&file_hash).await.is_none());
}

#[tokio::test]
async fn unshare_file_removes_live_shared_catalog_entry() {
    let runtime_dir = unique_runtime_dir("emulebb-core-unshare-shared-catalog");
    let transfer_root = runtime_dir.join("transfers");
    let shared_path = runtime_dir.join("shared.bin");
    fs::write(&shared_path, b"shared catalog removal payload").unwrap();
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();

    let share = core
        .share_local_file(LocalShareCreate {
            path: shared_path.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    assert_eq!(core.shares().await.len(), 1);
    assert_eq!(core.shared_catalog_count().await, 1);

    let removed = core.unshare_file(&share.hash).await.unwrap().unwrap();

    assert_eq!(removed.hash, share.hash);
    assert!(core.shares().await.is_empty());
    assert_eq!(core.shared_catalog_count().await, 0);
}

#[tokio::test]
async fn update_shared_file_does_not_queue_redundant_ed2k_reoffer() {
    // Publish-G3: a metadata PATCH mutates only priority/comment/rating, none
    // of which are in the eD2k OP_OFFERFILES set/content, so it must apply the
    // metadata without spinning up a redundant shared-catalog re-offer (oracle
    // `CKnownFile::SetUpPriority` emits no re-offer, KnownFile.cpp:1395-1402).
    let runtime_dir = unique_runtime_dir("emulebb-core-update-shared-republish");
    let transfer_root = runtime_dir.join("transfers");
    let shared_path = runtime_dir.join("shared-metadata.bin");
    fs::write(&shared_path, b"shared metadata update payload").unwrap();
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();

    let share = core
        .share_local_file(LocalShareCreate {
            path: shared_path.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    let queued_before = core.ed2k_publish_diagnostics().queued_count;

    let updated = core
        .update_shared_file(
            &share.hash,
            SharedFileUpdate {
                priority: Some("high".to_string()),
                comment: Some("synthetic note".to_string()),
                rating: Some(4),
            },
        )
        .await
        .unwrap()
        .unwrap();

    // The metadata is still applied over REST.
    assert_eq!(updated.priority, "high");
    assert_eq!(updated.comment, "synthetic note");
    assert_eq!(updated.rating, 4);
    // ...but no eD2k re-offer session was queued (net-nil delta before G3).
    assert_eq!(core.ed2k_publish_diagnostics().queued_count, queued_before);
}

#[tokio::test]
async fn delete_completed_transfer_row_preserves_files_and_survives_restart() {
    let runtime_dir = unique_runtime_dir("emulebb-core-delete-completed-transfer-row");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let payload_path = runtime_dir.join("Completed.Row.bin");
    std::fs::write(&payload_path, b"completed row removal payload").unwrap();
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let share = core
        .share_local_file(LocalShareCreate {
            path: payload_path.display().to_string(),
            name: Some("Completed.Row.bin".to_string()),
        })
        .await
        .unwrap();
    let transfer_dir = std::path::Path::new(&share.transfer_dir);
    assert!(transfer_dir.is_dir());
    assert!(core.transfer(&share.hash).await.is_none());
    assert!(core.transfers().await.is_empty());

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
    assert!(core.transfer(&share.hash).await.is_some());

    let deleted = core
        .delete_completed_transfer_row(&share.hash)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(deleted.hash, share.hash);
    assert!(transfer_dir.is_dir());
    assert!(core.transfer(&share.hash).await.is_none());
    assert!(
        core.shares()
            .await
            .iter()
            .any(|entry| entry.hash == share.hash)
    );

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    assert!(reloaded.transfer(&share.hash).await.is_none());
    assert!(reloaded.transfers().await.is_empty());
    assert!(reloaded.shares().await.iter().any(
        |entry| entry.hash == share.hash && std::path::Path::new(&entry.transfer_dir).is_dir()
    ));

    let restored = reloaded
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
    assert!(reloaded.transfer(&share.hash).await.is_some());
}

#[tokio::test]
async fn delete_completed_transfer_row_rejects_incomplete_transfer() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let transfer = core
        .create_transfer(TransferCreate {
            link: Some(
                "ed2k://|file|Incomplete.Row.bin|4096|00112233445566778899aabbccddeeff|/"
                    .to_string(),
            ),
            links: None,
            category_id: None,
            category_name: None,
            paused: None,
        })
        .await
        .unwrap();

    let error = core
        .delete_completed_transfer_row(&transfer.hash)
        .await
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("only completed transfers can be removed without deleting files")
    );
    assert!(core.transfer(&transfer.hash).await.is_some());
}

#[tokio::test]
async fn stopped_transfer_cannot_be_resumed() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let transfer = core
        .create_transfer(TransferCreate {
            link: Some(
                "ed2k://|file|Stopped.bin|4096|00112233445566778899aabbccddeeff|/".to_string(),
            ),
            links: None,
            category_id: None,
            category_name: None,
            paused: None,
        })
        .await
        .unwrap();
    let stopped_transfer = core.stop_transfer(&transfer.hash).await.unwrap().unwrap();
    // Master parity: stopped is reported as the `paused` state + stopped flag.
    assert_eq!(stopped_transfer.state, "paused");
    assert!(stopped_transfer.stopped);

    let error = core.resume_transfer(&transfer.hash).await.unwrap_err();

    assert!(
        error
            .to_string()
            .contains("stopped transfer cannot be resumed")
    );
}

#[tokio::test]
async fn stopped_transfer_state_survives_restart() {
    let runtime_dir = unique_runtime_dir("emulebb-core-stopped-transfer");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let transfer = core
        .create_transfer(TransferCreate {
            link: Some(
                "ed2k://|file|Stopped.Restart.bin|4096|00112233445566778899aabbccddeeff|/"
                    .to_string(),
            ),
            links: None,
            category_id: None,
            category_name: None,
            paused: None,
        })
        .await
        .unwrap();
    core.stop_transfer(&transfer.hash).await.unwrap().unwrap();

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let reloaded_transfer = reloaded.transfer(&transfer.hash).await.unwrap();

    // Master parity: a stopped transfer reports the `paused` state plus a
    // separate `stopped` flag (not a distinct `stopped` state token).
    assert_eq!(reloaded_transfer.state, "paused");
    assert!(reloaded_transfer.stopped);
    let error = reloaded.resume_transfer(&transfer.hash).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("stopped transfer cannot be resumed")
    );
}

#[tokio::test]
async fn shared_files_stay_out_of_transfer_queue_until_link_is_added() {
    let runtime_dir = unique_runtime_dir("emulebb-core-persisted-manifests");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let payload_path = runtime_dir.join("Shared.Payload.bin");
    let payload = b"persisted transfer payload";
    std::fs::write(&payload_path, payload).unwrap();
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let share = core
        .share_local_file(LocalShareCreate {
            path: payload_path.display().to_string(),
            name: Some("Shared.Payload.bin".to_string()),
        })
        .await
        .unwrap();

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    assert!(reloaded.transfers().await.is_empty());
    assert!(
        reloaded
            .shares()
            .await
            .iter()
            .any(|entry| entry.hash == share.hash)
    );

    let restored = reloaded
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
    assert_eq!(restored.state, "completed");
    assert_eq!(restored.completed_bytes, payload.len() as u64);
    assert_eq!(restored.progress, 1.0);
    assert!(!restored.path.is_empty());
    assert_eq!(std::fs::read(&restored.path).unwrap(), payload);
}
