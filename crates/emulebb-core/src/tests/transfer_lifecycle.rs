use super::*;

#[tokio::test]
async fn transfer_details_refresh_verified_parts_without_a_state_change() {
    let runtime_dir = unique_runtime_dir("emulebb-core-details-verified-parts");
    let core = EmulebbCore::new(
        "test",
        FileIndex::in_memory().unwrap(),
        runtime_dir.join("transfers"),
    )
    .unwrap();
    let part = vec![0x35; emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE as usize];
    let tail = b"tail";
    let hashset: Vec<[u8; 16]> = vec![Md4::digest(&part).into(), Md4::digest(tail).into()];
    let hash = Ed2kHash::from_bytes(Md4::digest(hashset.concat()).into()).to_string();
    let size = part.len() + tail.len();
    core.create_transfer(TransferCreate {
        known_file_policy: KnownFilePolicy::Reject,
        link: Some(format!("ed2k://|file|Sample.Parts.bin|{size}|{hash}|/")),
        links: None,
        category_id: None,
        category_name: None,
        paused: Some(true),
    })
    .await
    .unwrap();
    {
        let mut state = core.state.lock().await;
        let cached = state.transfers.get_mut(&hash).unwrap();
        assert_eq!(cached.parts_obtained, 0);
        cached.priority = "high".to_string();
        cached.category_id = 7;
        cached.category_name = "Sample Category".to_string();
    }
    core.ed2k_transfers
        .store_md4_hashset(&hash, hashset)
        .await
        .unwrap();
    core.ed2k_transfers
        .store_piece_data(&hash, 0, &part)
        .await
        .unwrap();
    let details = core.transfer_details(&hash).await.unwrap().unwrap();
    assert!(details.parts[0].complete);
    assert!(!details.parts[1].complete);
    assert_eq!(details.transfer.parts_obtained, 1);
    assert_eq!(details.transfer.parts_progress_text, "#0");
    assert_eq!(details.transfer.completed_bytes, part.len() as u64);
    assert_eq!(details.transfer.state, "paused");
    assert_eq!(details.transfer.priority, "high");
    assert_eq!(details.transfer.category_id, 7);
    assert_eq!(details.transfer.category_name, "Sample Category");
}

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
                client_id: 0,
                client_port: 0,
                file_name: Some(String::new()),
                file_size: Some(0),
                file_type: None,
                media_artist: None,
                media_album: None,
                media_title: None,
                media_length_seconds: None,
                media_bitrate_kbps: None,
                media_codec: None,
                source_count: Some(100),
                complete_source_count: None,
                rating: None,
                aich_hash: None,
                directory: None,
            },
            Ed2kSearchFile {
                file_hash: other_hash,
                client_id: 0,
                client_port: 0,
                file_name: Some("wrong.bin".to_string()),
                file_size: Some(123),
                file_type: None,
                media_artist: None,
                media_album: None,
                media_title: None,
                media_length_seconds: None,
                media_bitrate_kbps: None,
                media_codec: None,
                source_count: Some(5),
                complete_source_count: None,
                rating: None,
                aich_hash: None,
                directory: None,
            },
            Ed2kSearchFile {
                file_hash: exact_hash,
                client_id: 0,
                client_port: 0,
                file_name: Some("resolved.bin".to_string()),
                file_size: Some(4_294_967_299),
                file_type: Some("Pro".to_string()),
                media_artist: None,
                media_album: None,
                media_title: None,
                media_length_seconds: None,
                media_bitrate_kbps: None,
                media_codec: None,
                source_count: Some(12),
                complete_source_count: None,
                rating: None,
                aich_hash: None,
                directory: None,
            },
        ],
        exact_hash,
    )
    .unwrap();

    assert_eq!(metadata.display_name.as_deref(), Some("resolved.bin"));
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
            file_type: None,
            source_count: Some(3),
            media_artist: None,
            media_album: None,
            media_title: None,
            media_length_seconds: None,
            media_bitrate_kbps: None,
            media_codec: None,
            aich_candidate: None,
            tags: Vec::new(),
        },
        exact_hash,
    )
    .unwrap();

    assert_eq!(metadata.display_name.as_deref(), Some("resolved.bin"));
    assert_eq!(metadata.file_size, Some(5_000));
}

#[tokio::test]
async fn download_search_result_creates_transfer() {
    let runtime_dir = unique_runtime_dir("emulebb-core-download-passive-search-result");
    let mut index = FileIndex::open(runtime_dir.join("metadata.sqlite")).unwrap();
    index
        .upsert_file(
            &IndexedFile {
                ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
                name: "Download.Me.bin".to_string(),
                size_bytes: 4096,
                content_type: "archive".to_string(),
                availability_score: 1,
            },
            IndexedFileOrigin::PassiveCache,
        )
        .unwrap();
    let core = EmulebbCore::new_with_network(
        "test",
        index,
        &runtime_dir,
        Some(test_network_config_with_store(
            &runtime_dir,
            KadLocalStoreConfig::default(),
            SnoopQueueConfig::default(),
        )),
    )
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
    assert_eq!(transfer.name, "Download.Me.bin");
    assert_eq!(transfer.name_consensus.observation_count, 1);
    let manifest = core
        .ed2k_transfers
        .manifest("00112233445566778899aabbccddeeff")
        .await
        .unwrap();
    assert_eq!(manifest.file_name_observations.len(), 1);
    assert_eq!(
        manifest.file_name_observations[0].raw_name,
        "Download.Me.bin"
    );
    assert_eq!(
        manifest.file_name_observations[0].normalized_name,
        "Download.Me.bin"
    );
    assert_eq!(manifest.file_name_observations[0].origin, "passive_cache");
    assert_eq!(manifest.file_name_observations[0].source_ip, None);
}

#[tokio::test]
async fn download_search_result_rejects_missing_file_size() {
    let runtime_dir = unique_runtime_dir("emulebb-core-download-passive-missing-size");
    let mut index = FileIndex::open(runtime_dir.join("metadata.sqlite")).unwrap();
    let file_hash = "ffeeddccbbaa99887766554433221100";
    index
        .upsert_file(
            &IndexedFile {
                ed2k_hash: file_hash.to_string(),
                name: "Missing.Size.bin".to_string(),
                size_bytes: 0,
                content_type: "archive".to_string(),
                availability_score: 1,
            },
            IndexedFileOrigin::PassiveCache,
        )
        .unwrap();
    let core = EmulebbCore::new_with_network(
        "test",
        index,
        &runtime_dir,
        Some(test_network_config_with_store(
            &runtime_dir,
            KadLocalStoreConfig::default(),
            SnoopQueueConfig::default(),
        )),
    )
    .unwrap();
    let search = core
        .create_search(SearchCreate {
            query: "missing size".to_string(),
            ..SearchCreate::default()
        })
        .await
        .unwrap();

    let error = core
        .download_search_result(&search.id, file_hash, SearchResultDownloadCreate::default())
        .await
        .unwrap_err();

    assert_eq!(error.to_string(), "search result has no usable file size");
    assert!(core.transfer(file_hash).await.is_none());
}

#[tokio::test]
async fn download_search_result_replays_live_kad_aich_observations() {
    let runtime_dir = unique_runtime_dir("emulebb-core-download-passive-aich");
    let mut index = FileIndex::open(runtime_dir.join("metadata.sqlite")).unwrap();
    let file_hash = "11111111111111111111111111111111";
    index
        .upsert_file(
            &IndexedFile {
                ed2k_hash: file_hash.to_string(),
                name: "Kad.AICH.bin".to_string(),
                size_bytes: 4096,
                content_type: "archive".to_string(),
                availability_score: 1,
            },
            IndexedFileOrigin::PassiveCache,
        )
        .unwrap();
    let core = EmulebbCore::new_with_network(
        "test",
        index,
        &runtime_dir,
        Some(test_network_config_with_store(
            &runtime_dir,
            KadLocalStoreConfig::default(),
            SnoopQueueConfig::default(),
        )),
    )
    .unwrap();
    let search = core
        .create_search(SearchCreate {
            query: "kad aich".to_string(),
            method: "automatic".to_string(),
            r#type: String::new(),
            ..Default::default()
        })
        .await
        .unwrap();
    let root = [0xAB; 20];
    let mut votes = KadAichSearchVotes::default();
    for index in 0..10u8 {
        votes.record(std::net::Ipv4Addr::new(203, index, 0, 9), root);
    }
    core.state
        .lock()
        .await
        .kad_aich_search_votes
        .insert((search.id.clone(), file_hash.to_string()), votes);

    core.download_search_result(&search.id, file_hash, SearchResultDownloadCreate::default())
        .await
        .unwrap()
        .expect("transfer");
    let manifest = core.ed2k_transfers.manifest(file_hash).await.unwrap();
    assert_eq!(
        manifest.aich_root.as_deref(),
        Some(hex::encode(root).as_str())
    );
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
            known_file_policy: KnownFilePolicy::Redownload,
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
async fn create_transfer_persists_and_emits_link_aich_root() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let hash = "00112233445566778899aabbccddeeff";
    let transfer = core
        .create_transfer(TransferCreate {
            known_file_policy: KnownFilePolicy::Redownload,
            link: Some(format!(
                "ed2k://|file|Aich.bin|4096|{hash}|h=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|/"
            )),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap();

    assert_eq!(
        core.ed2k_transfers
            .manifest(hash)
            .await
            .unwrap()
            .aich_root
            .as_deref(),
        Some("0000000000000000000000000000000000000000")
    );
    assert!(
        transfer
            .ed2k_link
            .contains("|h=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|/")
    );
}

#[tokio::test]
async fn transfer_events_publish_add_update_and_remove() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let mut events = core.subscribe_transfer_events();

    let transfer = core
        .create_transfer(TransferCreate {
            known_file_policy: Default::default(),
            link: Some(
                "ed2k://|file|Event.Stream.bin|4096|00112233445566778899aabbccddeeff|/".to_string(),
            ),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap();
    let added = events.recv().await.unwrap();
    assert_eq!(added.id(), 1);
    assert_eq!(added.event_type(), TransferEventType::Added);
    match added {
        TransferEvent::Added {
            transfer: event_transfer,
            ..
        } => assert_eq!(event_transfer.hash, transfer.hash),
        other => panic!("expected transfer.added event, got {other:?}"),
    }

    let updated = core
        .update_transfer(
            &transfer.hash,
            TransferUpdate {
                name: None,
                priority: Some("high".to_string()),
                category_id: None,
                category_name: None,
            },
        )
        .await
        .unwrap()
        .unwrap();
    let event = events.recv().await.unwrap();
    assert_eq!(event.id(), 2);
    assert_eq!(event.event_type(), TransferEventType::Updated);
    match event {
        TransferEvent::Updated {
            transfer: event_transfer,
            ..
        } => assert_eq!(event_transfer.priority, updated.priority),
        other => panic!("expected transfer.updated event, got {other:?}"),
    }

    let deleted = core
        .delete_transfer_files(&transfer.hash)
        .await
        .unwrap()
        .unwrap();
    let event = events.recv().await.unwrap();
    assert_eq!(event.id(), 3);
    assert_eq!(event.event_type(), TransferEventType::Removed);
    match event {
        TransferEvent::Removed { hash, .. } => assert_eq!(hash, deleted.hash),
        other => panic!("expected transfer.removed event, got {other:?}"),
    }
}

#[tokio::test]
async fn create_transfer_remembers_ed2k_link_source_hints() {
    let runtime_dir = unique_runtime_dir("emulebb-core-create-transfer-source-hints");
    let transfer_root = runtime_dir.join("transfers");
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();

    let transfer = core
        .create_transfer(TransferCreate {
            known_file_policy: Default::default(),
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

    core.ed2k_transfers
        .remember_source_file_description(
            &transfer.hash,
            Ed2kSourceHint {
                ip: "192.0.2.10".to_string(),
                tcp_port: 4662,
                user_hash: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
                connect_options: None,
                file_comment: "trusted release".to_string(),
                file_rating: 5,
            },
        )
        .await
        .unwrap();
    let comments = core
        .transfer_comments(&transfer.hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(comments.len(), 1);
    assert_eq!(comments[0].source, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(comments[0].file_name, "Seeded.Link.bin");
    assert_eq!(comments[0].comment, "trusted release");
    assert_eq!(comments[0].rating, 5);
}

#[tokio::test]
async fn active_duplicate_rejects_batch_before_any_new_transfer_is_created() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let active_hash = "00112233445566778899aabbccddeeff";
    let new_hash = "11112222333344445555666677778888";
    core.create_transfer(TransferCreate {
        known_file_policy: KnownFilePolicy::Reject,
        link: Some(format!("ed2k://|file|Active.bin|4096|{active_hash}|/")),
        links: None,
        category_id: None,
        category_name: None,
        paused: Some(true),
    })
    .await
    .unwrap();

    let error = core
        .create_transfers(TransferCreate {
            known_file_policy: KnownFilePolicy::Reject,
            link: None,
            links: Some(vec![
                format!("ed2k://|file|New.bin|4096|{new_hash}|/"),
                format!("ed2k://|file|Active.bin|4096|{active_hash}|/"),
            ]),
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap_err();
    let conflict = error.downcast_ref::<DownloadConflictError>().unwrap();
    assert!(conflict.conflicts.iter().any(|item| {
        item.kind == DownloadConflictKind::ActiveTransfer && !item.redownload_allowed
    }));
    assert!(core.transfer(new_hash).await.is_none());

    let override_error = core
        .create_transfer(TransferCreate {
            known_file_policy: KnownFilePolicy::Redownload,
            link: Some(format!("ed2k://|file|Active.bin|4096|{active_hash}|/")),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap_err();
    assert_eq!(
        override_error
            .downcast_ref::<DownloadConflictError>()
            .unwrap()
            .conflicts[0]
            .kind,
        DownloadConflictKind::ActiveTransfer
    );
}

#[tokio::test]
async fn removed_completed_download_requires_explicit_redownload_without_stale_path() {
    let runtime_dir = unique_runtime_dir("emulebb-core-historical-redownload");
    let transfer_root = runtime_dir.join("transfers");
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
    let payload = b"historical completed payload".repeat(64);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into()).to_string();
    let link = format!(
        "ed2k://|file|Historical.bin|{}|{}|/",
        payload.len(),
        file_hash
    );
    core.create_transfer(TransferCreate {
        known_file_policy: KnownFilePolicy::Reject,
        link: Some(link.clone()),
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
    core.refresh_transfer_from_manifest_default(&file_hash)
        .await
        .unwrap();
    assert!(
        core.ed2k_transfers
            .manifest(&file_hash)
            .await
            .unwrap()
            .completed
    );
    core.delete_transfer_files(&file_hash)
        .await
        .unwrap()
        .unwrap();

    let error = core
        .create_transfer(TransferCreate {
            known_file_policy: KnownFilePolicy::Reject,
            link: Some(link.clone()),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap_err();
    let conflict = error.downcast_ref::<DownloadConflictError>().unwrap();
    let history = conflict
        .conflicts
        .iter()
        .find(|item| item.kind == DownloadConflictKind::PreviouslyCompleted)
        .unwrap();
    assert!(history.current_paths.is_empty());
    assert!(history.first_completed_at_ms.is_some());
    assert!(history.last_completed_at_ms.is_some());
    assert!(history.redownload_allowed);
    assert!(core.transfer(&file_hash).await.is_none());

    let redownload = core
        .create_transfer(TransferCreate {
            known_file_policy: KnownFilePolicy::Redownload,
            link: Some(link),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap();
    assert_eq!(redownload.hash, file_hash);
    assert_eq!(redownload.state, "paused");
    assert_eq!(redownload.completed_bytes, 0);
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
            known_file_policy: Default::default(),
            link: Some(
                "ed2k://|file|Delete.Me.bin|4096|00112233445566778899aabbccddeeff|/".to_string(),
            ),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
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
async fn completed_delivery_retires_transfer_without_deleting_local_file() {
    let runtime_dir = unique_runtime_dir("emulebb-core-delete-delivered-transfer");
    let transfer_root = runtime_dir.join("transfers");
    let incoming_dir = runtime_dir.join("incoming");
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root)
        .unwrap()
        .with_incoming_dir(incoming_dir.clone());
    let payload = b"completed delivered download payload".repeat(64);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into()).to_string();
    core.create_transfer(TransferCreate {
        known_file_policy: Default::default(),
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
    let awaiting_delivery = core
        .refresh_transfer_from_manifest_default(&file_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(awaiting_delivery.state, "completing");
    core.deliver_completed_transfer(&file_hash).await;
    assert!(core.transfer(&file_hash).await.is_none());
    assert!(core.share(&file_hash).await.is_some());
    let delivered_path = incoming_dir.join("Delivered.Delete.bin");
    assert_eq!(std::fs::read(&delivered_path).unwrap(), payload);
    assert!(core.ed2k_transfers.manifest(&file_hash).await.is_err());
    assert!(!transfer_root.join(&file_hash).exists());

    assert!(
        core.delete_completed_transfer_row(&file_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        delivered_path.exists(),
        "row-only completed transfer removal must preserve the delivered file"
    );

    assert!(
        core.delete_transfer_files(&file_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        delivered_path.exists(),
        "retired download actions must not delete local shared content"
    );
    assert!(core.transfer(&file_hash).await.is_none());
}

#[tokio::test]
async fn completed_download_is_history_only_after_restart() {
    let runtime_dir = unique_runtime_dir("emulebb-core-persisted-completed-list");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let incoming_dir = runtime_dir.join("incoming");
    let payload = b"persisted completed transfer payload".repeat(32);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into()).to_string();
    {
        let core = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap()
        .with_incoming_dir(incoming_dir.clone());
        core.create_transfer(TransferCreate {
            known_file_policy: Default::default(),
            link: Some(format!(
                "ed2k://|file|Persisted.Completed.bin|{}|{}|/",
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
        core.deliver_completed_transfer(&file_hash).await;
        assert!(core.transfer(&file_hash).await.is_none());
    }

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap()
    .with_incoming_dir(incoming_dir.clone());
    assert!(reloaded.transfers().await.is_empty());
    let evidence = reloaded
        .ed2k_transfers
        .download_evidence(&file_hash)
        .await
        .unwrap();
    assert!(evidence.previously_completed.is_some());
    assert_eq!(evidence.current_local_files.len(), 1);

    let clear_without_prior_lookup = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap()
    .with_incoming_dir(incoming_dir.clone());
    clear_without_prior_lookup
        .clear_completed_transfer_rows()
        .await
        .unwrap();

    assert!(clear_without_prior_lookup.transfers().await.is_empty());
    assert!(incoming_dir.join("Persisted.Completed.bin").exists());
    let final_reload = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap()
    .with_incoming_dir(incoming_dir);
    assert!(final_reload.transfers().await.is_empty());
}

#[tokio::test]
async fn retired_download_does_not_redeliver_replaced_local_output() {
    let runtime_dir = unique_runtime_dir("emulebb-core-startup-delivery-reconcile");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let incoming_dir = runtime_dir.join("incoming");
    let payload = b"startup delivery reconciliation payload".repeat(32);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into()).to_string();
    let recorded_path = incoming_dir.join("Reconcile.Completed.bin");
    {
        let core = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap()
        .with_incoming_dir(incoming_dir.clone());
        core.create_transfer(TransferCreate {
            known_file_policy: Default::default(),
            link: Some(format!(
                "ed2k://|file|Reconcile.Completed.bin|{}|{}|/",
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
        core.deliver_completed_transfer(&file_hash).await;
        assert_eq!(std::fs::read(&recorded_path).unwrap(), payload);
    }

    std::fs::remove_file(&recorded_path).unwrap();
    let unrelated_replacement = vec![0x5A; payload.len()];
    std::fs::write(&recorded_path, &unrelated_replacement).unwrap();

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap()
    .with_incoming_dir(incoming_dir.clone());
    reloaded.hydrate_persisted_transfer_rows().await.unwrap();
    assert_eq!(
        reloaded
            .reconcile_persisted_completed_deliveries()
            .await
            .unwrap(),
        0
    );
    reloaded.reload_shared_directories().await.unwrap();

    let redelivered_path = incoming_dir.join("Reconcile.Completed (1).bin");
    assert_eq!(
        std::fs::read(&recorded_path).unwrap(),
        unrelated_replacement
    );
    assert!(!redelivered_path.exists());
    assert!(reloaded.transfer(&file_hash).await.is_none());
    assert!(reloaded.share(&file_hash).await.is_none());
}

#[tokio::test]
async fn retired_delivery_is_not_subject_to_transfer_deletion_recovery() {
    let runtime_dir = unique_runtime_dir("emulebb-core-startup-delete-recovery");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let incoming_dir = runtime_dir.join("incoming");
    let payload = b"startup destructive deletion recovery payload".repeat(32);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into()).to_string();
    let delivered_path = incoming_dir.join("Delete.On.Startup.bin");
    {
        let core = EmulebbCore::new(
            "test",
            FileIndex::open(&metadata_path).unwrap(),
            &transfer_root,
        )
        .unwrap()
        .with_incoming_dir(incoming_dir.clone());
        core.create_transfer(TransferCreate {
            known_file_policy: Default::default(),
            link: Some(format!(
                "ed2k://|file|Delete.On.Startup.bin|{}|{}|/",
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
        core.deliver_completed_transfer(&file_hash).await;
        assert!(delivered_path.exists());
        assert!(
            !core
                .ed2k_transfers
                .delete_transfer_files(&file_hash)
                .await
                .unwrap()
        );
        assert!(delivered_path.exists());
    }

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap()
    .with_incoming_dir(incoming_dir);
    let deletion_recovery = reloaded.recover_pending_transfer_deletions().await.unwrap();
    assert_eq!(deletion_recovery.recovered, 0);
    assert!(deletion_recovery.failures.is_empty());
    assert_eq!(reloaded.hydrate_persisted_transfer_rows().await.unwrap(), 0);
    assert_eq!(
        reloaded
            .reconcile_persisted_completed_deliveries()
            .await
            .unwrap(),
        0
    );
    assert!(reloaded.transfers().await.is_empty());
    assert!(delivered_path.exists());
    assert!(
        reloaded
            .metadata_store
            .pending_transfer_deletion_hashes()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn delivery_failure_stays_completing_and_clears_after_retry() {
    let runtime_dir = unique_runtime_dir("emulebb-core-delivery-retry-state");
    let transfer_root = runtime_dir.join("transfers");
    let blocked_incoming = runtime_dir.join("incoming-blocked");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::write(&blocked_incoming, b"not a directory").unwrap();
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root)
        .unwrap()
        .with_incoming_dir(blocked_incoming.clone());
    let payload = b"delivery retry payload".repeat(32);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into()).to_string();
    core.create_transfer(TransferCreate {
        known_file_policy: Default::default(),
        link: Some(format!(
            "ed2k://|file|Retry.bin|{}|{}|/",
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

    core.deliver_completed_transfer(&file_hash).await;
    let failed = core.transfer(&file_hash).await.unwrap();
    assert_eq!(failed.state, "completing");
    assert!(failed.delivery_error.is_some());

    std::fs::remove_file(&blocked_incoming).unwrap();
    core.deliver_completed_transfer(&file_hash).await;
    assert!(core.transfer(&file_hash).await.is_none());
    assert!(core.share(&file_hash).await.is_some());
    assert!(blocked_incoming.join("Retry.bin").exists());
}

#[tokio::test]
async fn removing_root_withdraws_live_share_but_preserves_verified_hash() {
    let runtime_dir = unique_runtime_dir("emulebb-core-unshare-shared-catalog");
    let transfer_root = runtime_dir.join("transfers");
    let shared_path = runtime_dir.join("shared.bin");
    // Hosted Windows output roots contain mixed separators; exercise the
    // same fixture spelling without changing the inherited output root.
    #[cfg(windows)]
    let shared_path = PathBuf::from(shared_path.to_string_lossy().replace('\\', "/"));
    fs::write(&shared_path, b"shared catalog removal payload").unwrap();
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
    configure_test_shared_root(&core, &shared_path).await;

    let share = core
        .share_local_file(LocalShareCreate {
            path: shared_path.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    assert_eq!(core.shares().await.len(), 1);
    assert_eq!(core.shared_catalog_count().await, 1);

    core.remove_shared_directory_root(&runtime_dir.display().to_string())
        .await
        .unwrap();
    core.reload_shared_directories().await.unwrap();
    assert!(core.shares().await.is_empty());
    assert_eq!(core.shared_catalog_count().await, 0);
    assert_eq!(
        core.metadata_store
            .local_file_instance(&emulebb_ed2k::long_path::long_path(&shared_path))
            .unwrap()
            .unwrap()
            .file_hash,
        share.hash
    );
}

#[tokio::test]
async fn update_shared_file_priority_and_comment_do_not_queue_redundant_ed2k_reoffer() {
    // Priority/comment do not change OP_OFFERFILES content, so apply them
    // without spinning up a redundant shared-catalog re-offer (oracle
    // `CKnownFile::SetUpPriority` emits no re-offer, KnownFile.cpp:1395-1402).
    let runtime_dir = unique_runtime_dir("emulebb-core-update-shared-republish");
    let transfer_root = runtime_dir.join("transfers");
    let shared_path = runtime_dir.join("shared-metadata.bin");
    fs::write(&shared_path, b"shared metadata update payload").unwrap();
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
    configure_test_shared_root(&core, &shared_path).await;

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
                rating: Some(0),
            },
        )
        .await
        .unwrap()
        .unwrap();

    // The metadata is still applied over REST.
    assert_eq!(updated.priority, "high");
    assert_eq!(updated.comment, "synthetic note");
    assert_eq!(updated.rating, 0);
    // ...but no eD2k re-offer session was queued.
    assert_eq!(core.ed2k_publish_diagnostics().queued_count, queued_before);
}

#[tokio::test]
async fn update_shared_file_rating_queues_ed2k_reoffer() {
    let runtime_dir = unique_runtime_dir("emulebb-core-update-shared-rating");
    let transfer_root = runtime_dir.join("transfers");
    let shared_path = runtime_dir.join("shared-rating.bin");
    fs::write(&shared_path, b"shared rating update payload").unwrap();
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
    configure_test_shared_root(&core, &shared_path).await;

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
                priority: None,
                comment: Some(String::new()),
                rating: Some(4),
            },
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(updated.rating, 4);
    assert_eq!(
        core.ed2k_publish_diagnostics().queued_count,
        queued_before + 1
    );
}

#[tokio::test]
async fn update_shared_file_not_published_queues_ed2k_reoffer() {
    let runtime_dir = unique_runtime_dir("emulebb-core-update-shared-not-published");
    let transfer_root = runtime_dir.join("transfers");
    let shared_path = runtime_dir.join("shared-suppressed.bin");
    fs::write(&shared_path, b"shared publish suppression payload").unwrap();
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
    configure_test_shared_root(&core, &shared_path).await;

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
                priority: Some("not-published".to_string()),
                comment: None,
                rating: None,
            },
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(updated.priority, "not-published");
    assert_eq!(
        core.ed2k_publish_diagnostics().queued_count,
        queued_before + 1
    );
}

#[tokio::test]
async fn verified_local_share_survives_restart_without_transfer_row() {
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
    configure_test_shared_root(&core, &payload_path).await;
    let share = core
        .share_local_file(LocalShareCreate {
            path: payload_path.display().to_string(),
            name: Some("Completed.Row.bin".to_string()),
        })
        .await
        .unwrap();
    assert!(
        core.metadata_store
            .transfer_manifest_by_hash(&share.hash)
            .unwrap()
            .is_none()
    );
    assert!(core.transfer(&share.hash).await.is_none());
    assert!(core.transfers().await.is_empty());

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    assert!(reloaded.transfer(&share.hash).await.is_none());
    assert!(reloaded.transfers().await.is_empty());
    assert!(
        reloaded
            .shares()
            .await
            .iter()
            .any(|entry| entry.hash == share.hash)
    );
    assert!(
        reloaded
            .metadata_store
            .transfer_manifest_by_hash(&share.hash)
            .unwrap()
            .is_none()
    );

    let restored = reloaded
        .create_transfer(TransferCreate {
            known_file_policy: KnownFilePolicy::Redownload,
            link: Some(share.ed2k_link.clone()),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
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
            known_file_policy: Default::default(),
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
async fn delete_completed_transfer_row_rejects_pending_delivery() {
    let runtime_dir = unique_runtime_dir("emulebb-core-pending-delivery-row");
    let transfer_root = runtime_dir.join("transfers");
    let incoming_dir = runtime_dir.join("incoming");
    let payload = b"completed but not delivered row".repeat(32);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into()).to_string();
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root)
        .unwrap()
        .with_incoming_dir(incoming_dir);
    core.create_transfer(TransferCreate {
        known_file_policy: Default::default(),
        link: Some(format!(
            "ed2k://|file|Pending.Row.bin|{}|{}|/",
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
    core.refresh_transfer_from_manifest_default(&file_hash)
        .await
        .unwrap();

    let error = core
        .delete_completed_transfer_row(&file_hash)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("must be delivered"));
    assert_eq!(core.transfer(&file_hash).await.unwrap().state, "completing");
    assert!(
        !core
            .ed2k_transfers
            .manifest(&file_hash)
            .await
            .unwrap()
            .transfer_row_removed
    );
}

#[tokio::test]
async fn stopped_transfer_cannot_be_resumed() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let transfer = core
        .create_transfer(TransferCreate {
            known_file_policy: Default::default(),
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
    let details = core
        .transfer_details(&transfer.hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(details.transfer.state, "paused");
    assert!(details.transfer.stopped);

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
            known_file_policy: Default::default(),
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
async fn shared_files_require_explicit_redownload_and_remain_shared() {
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
    configure_test_shared_root(&core, &payload_path).await;
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

    let request = TransferCreate {
        known_file_policy: KnownFilePolicy::Reject,
        link: Some(share.ed2k_link.clone()),
        links: None,
        category_id: None,
        category_name: None,
        paused: Some(true),
    };
    let error = reloaded.create_transfer(request.clone()).await.unwrap_err();
    let conflict = error.downcast_ref::<DownloadConflictError>().unwrap();
    let present = conflict
        .conflicts
        .iter()
        .find(|item| item.kind == DownloadConflictKind::PresentLocalFile)
        .unwrap();
    assert!(present.redownload_allowed);
    assert_eq!(present.current_paths.len(), 1);
    assert_eq!(std::fs::read(&present.current_paths[0]).unwrap(), payload);
    assert!(reloaded.transfers().await.is_empty());

    let redownload = reloaded
        .create_transfer(TransferCreate {
            known_file_policy: KnownFilePolicy::Redownload,
            ..request
        })
        .await
        .unwrap();
    assert_eq!(redownload.hash, share.hash);
    assert_eq!(redownload.state, "paused");
    assert_eq!(redownload.completed_bytes, 0);
    assert_eq!(redownload.progress, 0.0);
    assert!(
        reloaded
            .shares()
            .await
            .iter()
            .any(|entry| entry.hash == share.hash)
    );
    assert_eq!(std::fs::read(payload_path).unwrap(), payload);
}
