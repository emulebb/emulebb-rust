use super::*;
use emulebb_metadata::DownloadIntent;
fn link_download(link: &str, intent: DownloadIntent) -> DownloadCreate {
    DownloadCreate {
        source: DownloadCreateSource::Ed2kLink { link: link.into() },
        category: None,
        intent,
        redownload: false,
    }
}

#[tokio::test]
async fn retained_category_entry_wakes_the_real_server_publish_pump() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let root = unique_runtime_dir("category-keep-server-pump");
    let shared_path = root.join("kept.bin");
    fs::write(&shared_path, b"category retained share").unwrap();
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let endpoint = listener.local_addr().unwrap();
    let mut network = test_network_config_with_store(
        &root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.egress_route = emulebb_ed2k::networking::EgressRoute::DirectSystemRoute;
    network.vpn_guard.mode = "off".into();
    network.bind_ip = Ipv4Addr::LOCALHOST;
    network.kad_bind_addr = "127.0.0.1:0".parse().unwrap();
    network.listen_port = 0;
    network.p2p_bind_ip = None;
    network.nat_config.enabled = false;
    network.ed2k.enable_udp_reask = false;
    // WHY: metadata-poor endpoints are probed with crypt negotiation first
    // when enabled; this owned mock implements a plaintext server login.
    network.ed2k.obfuscation_enabled = false;
    network.ed2k.server_endpoints = vec![endpoint.to_string()];
    network.ed2k.offer_files_capability_enabled = false;
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        root.join("transfers"),
        Some(network),
    )
    .unwrap();
    // WHY: Kad or UDP reask would start public STUN probes even with NAT
    // mapping disabled. This fixture owns only its loopback eD2K server.
    core.update_core_settings(CoreSettingsUpdate {
        network_kademlia: Some(false),
        ..CoreSettingsUpdate::default()
    })
    .await
    .unwrap();
    configure_test_shared_root(&core, &shared_path).await;
    let share = core
        .share_local_file(LocalShareCreate {
            path: shared_path.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    let hash: Ed2kHash = share.hash.parse().unwrap();
    assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 1);
    assert!(
        core.ed2k_transfers
            .shared_catalog()
            .read()
            .await
            .entry_by_hash(&hash)
            .is_some_and(|entry| entry.verified_complete)
    );
    let shared_root = PathBuf::from(&core.state.lock().await.shared_directories[0].path);
    let change = core
        .ed2k_transfers
        .begin_category_root_mutation()
        .await
        .unwrap();
    assert!(
        core.metadata_store
            .set_shared_root_accessible(&shared_root, false)
            .unwrap()
    );
    drop(change);
    assert_eq!(
        core.metadata_store.active_shared_content_count().unwrap(),
        0
    );
    assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 1);

    let (offer_sent, mut offer_received) = tokio::sync::oneshot::channel();
    let (release_server, server_release) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("owned server did not receive a TCP connection")
            .unwrap();
        let mut header = [0u8; 6];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
            .await
            .expect("owned server did not receive the login header")
            .unwrap();
        assert_eq!(header[0], 0xe3, "mock requires plaintext eD2K framing");
        assert_eq!(header[5], 0x01, "mock requires OP_LOGINREQUEST first");
        let length = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        assert!((1..=65_536).contains(&length), "invalid mock login length");
        let mut login = vec![0; length - 1];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut login))
            .await
            .expect("owned server did not receive the complete login body")
            .unwrap();
        // OP_IDCHANGE assigns a high ID on the existing loopback server session.
        stream
            .write_all(&[0xe3, 5, 0, 0, 0, 0x40, 0x10, 0x20, 0x30, 0x40])
            .await
            .unwrap();
        loop {
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 0xe3, "mock requires plaintext eD2K framing");
            let length = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
            assert!((1..=65_536).contains(&length), "invalid mock packet length");
            let mut payload = vec![0; length - 1];
            stream.read_exact(&mut payload).await.unwrap();
            if header[5] == 0x15 {
                assert!(payload.len() >= 4, "short offer-files packet");
                if u32::from_le_bytes(payload[..4].try_into().unwrap()) == 0 {
                    continue;
                }
                offer_sent.send(payload).unwrap();
                // WHY: closing the mock here races the public session mirror
                // and can erase the publish counters before the test sees them.
                let _ = server_release.await;
                return;
            }
        }
    });
    core.connect_ed2k_server(&endpoint.to_string())
        .await
        .unwrap()
        .expect("owned loopback server is configured and enabled");
    let suppressed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match offer_received.try_recv() {
                Ok(payload) => panic!(
                    "nonempty offer while root is ineligible: bytes={}, {}",
                    payload.len(),
                    category_keep_publish_snapshot(&core).await
                ),
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => panic!(
                    "owned server stopped before suppressed rotation: {}",
                    category_keep_publish_snapshot(&core).await
                ),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
            }
            let state = {
                let runtime = core.ed2k_runtime.lock().await;
                Arc::clone(&runtime.as_ref().unwrap().server_state)
            };
            let state = state.read().await;
            if state.connected
                && state.offer_files_pending_entries == 1
                && state.offer_files_published_entries == 0
            {
                break;
            }
            drop(state);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        suppressed.is_ok(),
        "the real session did not finish its suppressed rotation: {}",
        category_keep_publish_snapshot(&core).await
    );
    assert!(matches!(
        offer_received.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));

    let change = core
        .ed2k_transfers
        .begin_category_root_mutation()
        .await
        .unwrap();
    core.metadata_store
        .set_shared_root_accessible(&shared_root, true)
        .unwrap();
    let native_path = emulebb_ed2k::long_path::long_path(&shared_path);
    let native_root = emulebb_ed2k::long_path::long_path(&shared_root);
    let fingerprint = core
        .metadata_store
        .local_file_instance(&native_path)
        .unwrap()
        .unwrap()
        .verified_fingerprint;
    assert!(
        core.metadata_store
            .admit_local_path_to_root(
                &shared_root,
                &native_path,
                native_path.strip_prefix(&native_root).unwrap(),
                &fingerprint,
            )
            .unwrap()
    );
    drop(change);
    let watch = core
        .ed2k_transfers
        .watch_category_catalog_hash(hash.0)
        .await
        .unwrap();
    assert!(
        core.ed2k_transfers
            .publish_category_catalog_decision(
                hash.0,
                watch,
                emulebb_ed2k::ed2k_transfer::CategoryCatalogDecision::Keep,
            )
            .await
            .unwrap()
    );
    let offer = tokio::time::timeout(Duration::from_secs(75), offer_received).await;
    assert!(
        offer.is_ok(),
        "retained eligibility did not wake the real publish pump: {}",
        category_keep_publish_snapshot(&core).await
    );
    let payload = offer.unwrap().expect("owned server stopped before offer");
    assert_eq!(u32::from_le_bytes(payload[..4].try_into().unwrap()), 1);
    assert_eq!(&payload[4..20], &hash.0);
    core.disconnect_ed2k().await.unwrap();
    core.drain_persistence().await.unwrap();
    release_server.send(()).unwrap();
    server.await.unwrap();
}

async fn category_keep_publish_snapshot(core: &EmulebbCore) -> String {
    let state = core
        .ed2k_runtime
        .lock()
        .await
        .as_ref()
        .map(|runtime| Arc::clone(&runtime.server_state));
    let session = if let Some(state) = state {
        let state = state.read().await;
        Some((
            state.connected,
            state.connecting,
            state.offer_files_pending_entries,
            state.offer_files_published_entries,
            state.offer_files_mode.clone(),
        ))
    } else {
        None
    };
    let publish = ed2k_publish_diagnostics::snapshot(&core.ed2k_publish_diagnostics);
    format!(
        "session(connected,connecting,pending,published,mode)={session:?}, catalog={}, durable={:?}, publisher(phase,running,dirty,total,pending,published)=({},{},{},{},{},{})",
        core.ed2k_transfers.shared_catalog_count().await,
        core.metadata_store.active_shared_content_count(),
        publish.phase,
        publish.running,
        publish.dirty,
        publish.total_entries,
        publish.pending_entries,
        publish.published_entries,
    )
}

#[tokio::test]
async fn download_headers_and_part_projection_observe_verified_data() {
    let root = unique_runtime_dir("core-verified-parts");
    let core = EmulebbCore::new(
        "test",
        FileIndex::in_memory().unwrap(),
        root.join("transfers"),
    )
    .unwrap();
    let part = vec![0x35; emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE as usize];
    let tail = b"tail";
    let hashset: Vec<[u8; 16]> = vec![Md4::digest(&part).into(), Md4::digest(tail).into()];
    let hash = Ed2kHash::from_bytes(Md4::digest(hashset.concat()).into()).to_string();
    let (_, download) = core
        .create_download(link_download(
            &format!(
                "ed2k://|file|Sample.Parts.bin|{}|{hash}|/",
                part.len() + tail.len()
            ),
            DownloadIntent::Started,
        ))
        .await
        .unwrap();
    let id = download.id;
    drop(download);
    let (_guard, transfer) = core.select_download_execution(id).await.unwrap().unwrap();
    let token = transfer.job_token();
    drop(
        core.ed2k_transfers
            .store_md4_hashset(token, hashset)
            .await
            .unwrap(),
    );
    core.ed2k_transfers
        .store_piece_data(token, 0, &part)
        .await
        .unwrap();
    let page = core.download_page(Default::default()).await.unwrap();
    assert_eq!(page.downloads[0].id, id);
    assert_eq!(
        page.downloads[0].progress,
        Some(part.len() as f64 / (part.len() + tail.len()) as f64)
    );
    drop(page);
    let parts = core
        .download_parts_page(id, None, 200)
        .await
        .unwrap()
        .unwrap();
    assert!(parts.parts[0].complete);
    assert!(!parts.parts[1].complete);
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
fn select_ed2k_download_size_prefers_exact_hash_with_size() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]);
    let other_hash = Ed2kHash::from_bytes([0xAA; 16]);
    let metadata = select_ed2k_download_size(
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

    assert_eq!(metadata, 4_294_967_299);
}

#[test]
fn kad_search_result_exposes_exact_hash_metadata() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]);
    let metadata = select_kad_download_size(
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
            reporter_endpoint: None,
            tags: Vec::new(),
        },
        exact_hash,
    )
    .unwrap();

    assert_eq!(metadata, 5_000);
}

#[tokio::test]
async fn search_result_admission_reads_selected_claim_without_hydrating_history() {
    let runtime_dir = unique_runtime_dir("emulebb-core-download-network-search-result");
    let index = FileIndex::open(runtime_dir.join("metadata.sqlite")).unwrap();
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
            parent_search_id: None,
            query: "download me".to_string(),
            method: "automatic".to_string(),
            r#type: String::new(),
            ..Default::default()
        })
        .await
        .unwrap();
    publish_server_search_result(
        &core,
        &search,
        "00112233445566778899aabbccddeeff",
        "Download.Me.bin",
        Some(4096),
        Some([0xcd; 20]),
    )
    .await;

    let result_id = core
        .metadata_store
        .search_result_headers_page(search.id.parse().unwrap(), 0, 1)
        .unwrap()
        .unwrap()
        .items[0]
        .claim_id
        .to_string();
    // Retained membership is authoritative; selecting one result must not
    // hydrate the session history or depend on its in-memory snapshot.
    core.state.lock().await.searches.clear();
    let (created, download) = core
        .download_search_result(
            &search.id,
            &result_id,
            SearchResultDownloadCreate::default(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(created);
    assert_eq!(download.state, DownloadState::Queued);
    assert_eq!(download.name, "Download.Me.bin");
    let id = download.id;
    drop(download);
    let job = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
    assert!(job.storage.is_none());
    let token = job.token;
    drop(job);
    let observations = core
        .ed2k_transfers
        .download_names_after(token, 0, 16)
        .await
        .unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].observation.raw_name, "Download.Me.bin");
    assert_eq!(
        observations[0].observation.normalized_name,
        "Download.Me.bin"
    );
    assert_eq!(observations[0].observation.origin, "server");
    assert_eq!(observations[0].observation.source_ip, None);
    drop(observations);
    let (_guard, transfer) = core.select_download_execution(id).await.unwrap().unwrap();
    assert!(
        core.ed2k_transfers
            .manifest(transfer.job_token())
            .await
            .unwrap()
            .aich_root
            .is_none(),
        "server AICH metadata alone must not become a Kad trust vote"
    );
}

#[tokio::test]
async fn unknown_size_search_result_creates_waiting_metadata_job() {
    let runtime_dir = unique_runtime_dir("emulebb-core-download-network-missing-size");
    let index = FileIndex::open(runtime_dir.join("metadata.sqlite")).unwrap();
    let file_hash = "ffeeddccbbaa99887766554433221100";
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
            parent_search_id: None,
            query: "missing size".to_string(),
            ..SearchCreate::default()
        })
        .await
        .unwrap();
    publish_server_search_result(&core, &search, file_hash, "Missing.Size.bin", None, None).await;

    let result_id = core
        .metadata_store
        .search_result_headers_page(search.id.parse().unwrap(), 0, 1)
        .unwrap()
        .unwrap()
        .items[0]
        .claim_id
        .to_string();
    let (created, download) = core
        .download_search_result(
            &search.id,
            &result_id,
            SearchResultDownloadCreate::default(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(created);
    assert_eq!(download.size_bytes, None);
    assert_eq!(download.state, DownloadState::WaitingMetadata);
}

#[tokio::test]
async fn download_search_result_honors_corroborated_kad_aich() {
    let runtime_dir = unique_runtime_dir("emulebb-core-download-network-aich");
    let index = FileIndex::open(runtime_dir.join("metadata.sqlite")).unwrap();
    let file_hash = "11111111111111111111111111111111";
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
            parent_search_id: None,
            query: "kad aich".to_string(),
            method: "automatic".to_string(),
            r#type: String::new(),
            ..Default::default()
        })
        .await
        .unwrap();
    publish_server_search_result(&core, &search, file_hash, "Kad.AICH.bin", Some(4096), None).await;
    let root = [0xAB; 20];
    let mut votes = KadAichSearchVotes::default();
    for index in 0..10u8 {
        votes.record(std::net::Ipv4Addr::new(203, index, 0, 9), root);
    }
    core.state
        .lock()
        .await
        .kad_aich_search_votes
        .insert(file_hash, &search.id, votes);

    let result_id = core
        .metadata_store
        .search_result_headers_page(search.id.parse().unwrap(), 0, 1)
        .unwrap()
        .unwrap()
        .items[0]
        .claim_id
        .to_string();
    let (_, download) = core
        .download_search_result(
            &search.id,
            &result_id,
            SearchResultDownloadCreate::default(),
        )
        .await
        .unwrap()
        .unwrap();
    let id = download.id;
    drop(download);
    let (_guard, transfer) = core.select_download_execution(id).await.unwrap().unwrap();
    let manifest = core
        .ed2k_transfers
        .manifest(transfer.job_token())
        .await
        .unwrap();
    assert_eq!(
        manifest.aich_root.as_deref(),
        Some(hex::encode(root).as_str())
    );
}

#[tokio::test]
async fn creation_decodes_chosen_name_and_preserves_stopped_intent_without_storage() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let (created, download) = core
        .create_download(link_download(
            "ed2k://|file|Sample%20Name.bin|4096|00112233445566778899aabbccddeeff|/",
            DownloadIntent::Stopped,
        ))
        .await
        .unwrap();
    assert!(created);
    assert_eq!(download.name, "Sample Name.bin");
    assert_eq!(download.state, DownloadState::Stopped);
    assert_eq!(download.size_bytes, Some(4096));
    let id = download.id;
    drop(download);
    assert!(
        core.ed2k_transfers
            .download_job(id)
            .await
            .unwrap()
            .unwrap()
            .storage
            .is_none()
    );
}

#[tokio::test]
async fn operator_link_aich_root_survives_lazy_creation_and_selection() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let root = hex::encode([0xab; 20]);
    let link = format_ed2k_file_link(
        "Sample.bin",
        4096,
        "00112233445566778899aabbccddeeff",
        Some(&root),
    );
    let (_, download) = core
        .create_download(link_download(&link, DownloadIntent::Started))
        .await
        .unwrap();
    let id = download.id;
    drop(download);
    let (_guard, transfer) = core.select_download_execution(id).await.unwrap().unwrap();
    assert_eq!(
        core.ed2k_transfers
            .manifest(transfer.job_token())
            .await
            .unwrap()
            .aich_root
            .as_deref(),
        Some(root.as_str())
    );
}

#[tokio::test]
async fn creation_retains_initial_hints_and_later_source_comments() {
    let runtime_dir = unique_runtime_dir("emulebb-core-create-transfer-source-hints");
    let transfer_root = runtime_dir.join("transfers");
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();

    let (_,download)=core.create_download(link_download(
        "ed2k://|file|Seeded.Link.bin|4096|00112233445566778899aabbccddeeff|sources,192.0.2.10:4662:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,bad-source,192.0.2.10:4662,192.0.2.11:0|/",
        DownloadIntent::Stopped)).await.unwrap();
    let id = download.id;
    drop(download);
    let sources = core
        .download_sources_page(id, 0, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sources.sources.len(), 1);
    assert_eq!(sources.sources[0].address, "192.0.2.10");
    assert_eq!(sources.sources[0].port, 4662);
    assert_eq!(
        sources.sources[0].user_hash.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );

    drop(sources);
    core.start_download(id).await.unwrap();
    let token = core
        .ed2k_transfers
        .download_job(id)
        .await
        .unwrap()
        .unwrap()
        .token;
    core.ed2k_transfers
        .remember_source_file_description(
            token,
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
        .download_comments_page(id, 0, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(comments.comments.len(), 1);
    assert_eq!(
        comments.comments[0].source,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(comments.comments[0].file_name, "Seeded.Link.bin");
    assert_eq!(comments.comments[0].comment, "trusted release");
    assert_eq!(comments.comments[0].rating, 5);
}

#[tokio::test]
async fn confirmed_absent_completed_content_can_create_a_new_job_without_resetting_history() {
    let root = unique_runtime_dir("core-absent-history");
    let core = EmulebbCore::new(
        "test",
        FileIndex::in_memory().unwrap(),
        root.join("transfers"),
    )
    .unwrap();
    let payload = b"completed payload";
    let token = ready_download_for_delivery(&core, &root, "Historical.bin", payload).await;
    assert!(core.deliver_completed_download(token).await.unwrap());
    std::fs::remove_file(root.join("seed-Historical.bin")).unwrap();
    assert_eq!(
        core.remove_download(token.job_id, true).await.unwrap(),
        DownloadChange::Changed
    );
    core.maintain_download_cleanup().await.unwrap();
    let hash = Ed2kHash::from_bytes(Md4::digest(payload).into()).to_string();
    let (created, download) = core
        .create_download(link_download(
            &format!("ed2k://|file|Historical.bin|{}|{hash}|/", payload.len()),
            DownloadIntent::Stopped,
        ))
        .await
        .unwrap();
    assert!(created);
    assert_ne!(download.id, token.job_id);
    assert_eq!(download.progress, Some(0.0));
    let evidence = core.ed2k_transfers.download_evidence(&hash).await.unwrap();
    assert!(evidence.previously_completed.is_some());
}

#[test]
fn creation_category_requires_a_name_string() {
    assert!(serde_json::from_value::<DownloadCreate>(serde_json::json!({
        "source":{"type":"content","hash":"00112233445566778899aabbccddeeff","name":"Sample.bin"},"category":7
    })).is_err());
}

#[tokio::test]
async fn removal_retires_internal_storage_before_purging_the_removed_job() {
    let root = unique_runtime_dir("core-remove-job");
    let core = EmulebbCore::new(
        "test",
        FileIndex::in_memory().unwrap(),
        root.join("transfers"),
    )
    .unwrap();
    let (_, download) = core
        .create_download(link_download(
            "ed2k://|file|Sample.bin|8|00112233445566778899aabbccddeeff|/",
            DownloadIntent::Started,
        ))
        .await
        .unwrap();
    let id = download.id;
    drop(download);
    let (guard, transfer) = core.select_download_execution(id).await.unwrap().unwrap();
    let directory = core.ed2k_transfers.transfer_dir_path(id).unwrap();
    assert!(directory.is_dir());
    assert_eq!(
        core.remove_download(id, false).await.unwrap(),
        DownloadChange::Changed
    );
    assert!(guard.cancellation().is_cancelled());
    drop(transfer);
    drop(guard);
    core.maintain_download_cleanup().await.unwrap();
    assert!(
        core.ed2k_transfers
            .download_job(id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!directory.exists());
}

async fn ready_download_for_delivery(
    core: &EmulebbCore,
    root: &std::path::Path,
    name: &str,
    payload: &[u8],
) -> emulebb_metadata::JobToken {
    let seed = root.join(format!("seed-{name}"));
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(&seed, payload).unwrap();
    let summary = core
        .ed2k_transfers
        .ingest_local_file(&seed, name)
        .await
        .unwrap();
    let token = admit_scheduler_test_job(
        &core.ed2k_transfers,
        &root.join("transfers"),
        summary.file_hash.parse().unwrap(),
        name.to_owned(),
        payload.len() as u64,
    )
    .await;
    drop(
        core.ed2k_transfers
            .store_md4_hashset(token, Vec::new())
            .await
            .unwrap(),
    );
    core.ed2k_transfers
        .store_piece_data(token, 0, payload)
        .await
        .unwrap();
    assert!(
        core.ed2k_transfers
            .download_job(token.job_id)
            .await
            .unwrap()
            .unwrap()
            .payload_verified
    );
    token
}

#[tokio::test]
async fn delivered_job_retains_history_and_removal_preserves_output() {
    let root = unique_runtime_dir("core-completed-job-history");
    let incoming = root.join("incoming");
    let core = EmulebbCore::new(
        "test",
        FileIndex::in_memory().unwrap(),
        root.join("transfers"),
    )
    .unwrap()
    .with_incoming_dir(incoming.clone());
    let payload = b"Sample completed job payload".repeat(64);
    let token = ready_download_for_delivery(&core, &root, "Sample.bin", &payload).await;
    assert!(core.deliver_completed_download(token).await.unwrap());
    let path = incoming.join("Sample.bin");
    assert_eq!(std::fs::read(&path).unwrap(), payload);
    assert!(
        core.share(&Ed2kHash::from_bytes(Md4::digest(&payload).into()).to_string())
            .await
            .is_some()
    );
    let completed = core
        .download_page(emulebb_metadata::DownloadJobQuery {
            view: emulebb_metadata::DownloadJobView::Completed,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(completed.downloads.len(), 1);
    assert_eq!(completed.downloads[0].id, token.job_id);
    assert_eq!(completed.downloads[0].state, DownloadState::Completed);
    assert!(completed.downloads[0].completed_at.is_some());
    drop(completed);
    assert_eq!(core.maintain_download_delivery().await.unwrap(), 0);
    assert!(!core.deliver_completed_download(token).await.unwrap());
    core.ed2k_transfers
        .retire_download_storage(token.job_id)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), payload);
    assert!(
        core.ed2k_transfers
            .remove_download_job(token.job_id, false)
            .await
            .unwrap()
    );
    core.ed2k_transfers
        .cleanup_removed_download_job(token.job_id)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), payload);
    assert!(
        core.download_page(emulebb_metadata::DownloadJobQuery {
            view: emulebb_metadata::DownloadJobView::All,
            ..Default::default()
        })
        .await
        .unwrap()
        .downloads
        .is_empty()
    );
    core.drain_persistence().await.unwrap();
}

#[tokio::test]
async fn completed_history_survives_restart_without_recreating_replaced_output() {
    let root = unique_runtime_dir("core-persisted-completed-history");
    let incoming = root.join("incoming");
    let database = root.join("metadata.sqlite");
    let payload = b"Sample persisted completed payload".repeat(32);
    let token;
    {
        let core = EmulebbCore::new(
            "test",
            FileIndex::open(&database).unwrap(),
            root.join("transfers"),
        )
        .unwrap()
        .with_incoming_dir(incoming.clone());
        token = ready_download_for_delivery(&core, &root, "Sample.bin", &payload).await;
        assert!(core.deliver_completed_download(token).await.unwrap());
        core.drain_persistence().await.unwrap();
    }
    let path = incoming.join("Sample.bin");
    std::fs::remove_file(&path).unwrap();
    let replacement = vec![0x5a; payload.len()];
    std::fs::write(&path, &replacement).unwrap();
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&database).unwrap(),
        root.join("transfers"),
    )
    .unwrap()
    .with_incoming_dir(incoming.clone());
    assert_eq!(core.maintain_download_delivery().await.unwrap(), 0);
    assert!(!core.deliver_completed_download(token).await.unwrap());
    assert_eq!(std::fs::read(&path).unwrap(), replacement);
    assert_eq!(std::fs::read_dir(&incoming).unwrap().count(), 1);
    let completed = core
        .download_page(emulebb_metadata::DownloadJobQuery {
            view: emulebb_metadata::DownloadJobView::Completed,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(completed.downloads.len(), 1);
    assert_eq!(completed.downloads[0].id, token.job_id);
    drop(completed);
    core.drain_persistence().await.unwrap();
}

#[tokio::test]
async fn unfinished_delivery_failure_requires_explicit_start_after_restart() {
    let root = unique_runtime_dir("core-delivery-manual-storage-retry");
    std::fs::create_dir_all(&root).unwrap();
    let incoming = root.join("incoming-blocked");
    std::fs::write(&incoming, b"Sample obstruction").unwrap();
    let database = root.join("metadata.sqlite");
    let token;
    {
        let core = EmulebbCore::new(
            "test",
            FileIndex::open(&database).unwrap(),
            root.join("transfers"),
        )
        .unwrap()
        .with_incoming_dir(incoming.clone());
        token = ready_download_for_delivery(
            &core,
            &root,
            "Sample.bin",
            &b"Sample retry payload".repeat(32),
        )
        .await;
        assert!(core.deliver_completed_download(token).await.is_err());
        let failed = core
            .ed2k_transfers
            .download_job(token.job_id)
            .await
            .unwrap()
            .unwrap();
        assert!(failed.storage_failure.is_some());
        assert_ne!(failed.token, token);
        drop(failed);
        core.drain_persistence().await.unwrap();
    }
    std::fs::remove_file(&incoming).unwrap();
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&database).unwrap(),
        root.join("transfers"),
    )
    .unwrap()
    .with_incoming_dir(incoming.clone());
    let failed = core
        .ed2k_transfers
        .download_job(token.job_id)
        .await
        .unwrap()
        .unwrap();
    assert!(failed.storage_failure.is_some());
    let failed_token = failed.token;
    drop(failed);
    assert_eq!(core.maintain_download_delivery().await.unwrap(), 0);
    assert!(!core.deliver_completed_download(failed_token).await.unwrap());
    assert!(!incoming.exists());
    let started = core
        .ed2k_transfers
        .start_download_job(failed_token, &root.join("transfers"))
        .await
        .unwrap();
    let restarted = started.as_ref().unwrap().token;
    drop(started);
    assert!(core.deliver_completed_download(restarted).await.unwrap());
    assert!(incoming.join("Sample.bin").exists());
    core.drain_persistence().await.unwrap();
}

#[tokio::test]
async fn delivery_maintenance_bounds_each_pass_and_respects_stop() {
    let root = unique_runtime_dir("core-bounded-delivery-maintenance");
    let incoming = root.join("incoming");
    let core = EmulebbCore::new(
        "test",
        FileIndex::in_memory().unwrap(),
        root.join("transfers"),
    )
    .unwrap()
    .with_incoming_dir(incoming.clone());
    let mut tokens = Vec::new();
    for index in 0..6 {
        let token = ready_download_for_delivery(
            &core,
            &root,
            &format!("Sample-{index}.bin"),
            &vec![index as u8 + 1; 1024],
        )
        .await;
        tokens.push(token);
    }
    assert!(
        core.ed2k_transfers
            .stop_download_job(tokens[0])
            .await
            .unwrap()
    );
    assert_eq!(core.maintain_download_delivery().await.unwrap(), 4);
    assert!(!incoming.join("Sample-0.bin").exists());
    assert_eq!(std::fs::read_dir(&incoming).unwrap().count(), 4);
    assert_eq!(core.maintain_download_delivery().await.unwrap(), 1);
    assert_eq!(std::fs::read_dir(&incoming).unwrap().count(), 5);
    assert_eq!(core.maintain_download_delivery().await.unwrap(), 0);
    let stopped = core
        .ed2k_transfers
        .download_job(tokens[0].job_id)
        .await
        .unwrap()
        .unwrap();
    let stopped_token = stopped.token;
    drop(stopped);
    let restarted = core
        .ed2k_transfers
        .start_download_job(stopped_token, &root.join("transfers"))
        .await
        .unwrap();
    let token = restarted.as_ref().unwrap().token;
    drop(restarted);
    assert!(core.deliver_completed_download(token).await.unwrap());
    assert!(incoming.join("Sample-0.bin").exists());
    core.drain_persistence().await.unwrap();
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
async fn verified_local_share_survives_restart_without_creating_a_download_job() {
    let runtime_dir = unique_runtime_dir("core-library-only-restart");
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
        core.download_page(Default::default())
            .await
            .unwrap()
            .downloads
            .is_empty()
    );
    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    assert!(
        reloaded
            .download_page(Default::default())
            .await
            .unwrap()
            .downloads
            .is_empty()
    );
    assert!(
        reloaded
            .shares()
            .await
            .iter()
            .any(|entry| entry.hash == share.hash)
    );
    assert!(
        reloaded
            .download_page(Default::default())
            .await
            .unwrap()
            .downloads
            .is_empty()
    );
}

#[tokio::test]
async fn a_late_worker_refresh_cannot_overwrite_a_durable_stop() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let (_, download) = core
        .create_download(link_download(
            "ed2k://|file|Sample.bin|8|00112233445566778899aabbccddeeff|/",
            DownloadIntent::Started,
        ))
        .await
        .unwrap();
    let id = download.id;
    drop(download);
    let (guard, transfer) = core.select_download_execution(id).await.unwrap().unwrap();
    assert_eq!(
        core.stop_download(id).await.unwrap(),
        DownloadChange::Changed
    );
    assert!(guard.cancellation().is_cancelled());
    assert!(matches!(
        core.refresh_transfer_from_manifest(transfer.job_token(), "downloading")
            .await,
        Ok(None) | Err(_)
    ));
    let page = core.download_page(Default::default()).await.unwrap();
    assert_eq!(page.downloads[0].intent, DownloadIntent::Stopped);
    assert_eq!(page.downloads[0].state, DownloadState::Stopping);
    drop(page);
    drop(guard);
    assert_eq!(
        core.download_page(Default::default())
            .await
            .unwrap()
            .downloads[0]
            .state,
        DownloadState::Stopped
    );
}

#[tokio::test]
async fn stopped_job_survives_restart_and_an_explicit_start_reuses_its_identity() {
    let root = unique_runtime_dir("core-stopped-restart");
    let db = root.join("metadata.sqlite");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&db).unwrap(),
        root.join("transfers"),
    )
    .unwrap();
    let (_, download) = core
        .create_download(link_download(
            "ed2k://|file|Sample.bin|8|00112233445566778899aabbccddeeff|/",
            DownloadIntent::Stopped,
        ))
        .await
        .unwrap();
    let id = download.id;
    drop(download);
    drop(core);
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&db).unwrap(),
        root.join("transfers"),
    )
    .unwrap();
    let page = core.download_page(Default::default()).await.unwrap();
    assert_eq!(page.downloads[0].id, id);
    assert_eq!(page.downloads[0].state, DownloadState::Stopped);
    drop(page);
    assert!(core.select_download_execution(id).await.unwrap().is_none());
    assert_eq!(
        core.start_download(id).await.unwrap(),
        DownloadChange::Changed
    );
    assert_eq!(
        core.download_page(Default::default())
            .await
            .unwrap()
            .downloads[0]
            .id,
        id
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
    assert!(
        reloaded
            .download_page(Default::default())
            .await
            .unwrap()
            .downloads
            .is_empty()
    );
    assert!(
        reloaded
            .shares()
            .await
            .iter()
            .any(|entry| entry.hash == share.hash)
    );

    let request = link_download(&share.ed2k_link, DownloadIntent::Stopped);
    let error = reloaded.create_download(request.clone()).await.unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<emulebb_metadata::MetadataLocalContentChoiceRequired>()
            .unwrap()
            .0,
        emulebb_metadata::LocalContentAvailability::Present
    );
    assert!(
        reloaded
            .download_page(Default::default())
            .await
            .unwrap()
            .downloads
            .is_empty()
    );
    let (created, redownload) = reloaded
        .create_download(DownloadCreate {
            redownload: true,
            ..request
        })
        .await
        .unwrap();
    assert!(created);
    assert_eq!(redownload.hash, share.hash);
    assert_eq!(redownload.state, DownloadState::Stopped);
    assert_eq!(redownload.progress, Some(0.0));
    assert!(
        reloaded
            .shares()
            .await
            .iter()
            .any(|entry| entry.hash == share.hash)
    );
    assert_eq!(std::fs::read(payload_path).unwrap(), payload);
}

async fn publish_server_search_result(
    core: &EmulebbCore,
    search: &crate::Search,
    hash: &str,
    name: &str,
    size: Option<u64>,
    aich: Option<[u8; 20]>,
) {
    let mut raw = crate::search_observations::tests::raw_file();
    raw.file_hash = Ed2kHash::from_bytes(hex::decode(hash).unwrap().try_into().unwrap());
    raw.file_name = Some(name.into());
    raw.file_size = size;
    raw.aich_hash = aich.map(|root| data_encoding::BASE32.encode(&root));
    let reporter = "192.0.2.4:4661".parse().unwrap();
    let projected = crate::search_query::search_result_from_ed2k(
        &search.id,
        &search.spec,
        "server",
        Some(reporter),
        raw.clone(),
    );
    let update = crate::search_observations::ed2k(
        projected,
        emulebb_metadata::MetadataObservationOrigin::Server,
        Some(reporter),
        &raw,
    );
    core.apply_search_live_update(&search.id, &search.spec, update)
        .await
        .unwrap();
}
