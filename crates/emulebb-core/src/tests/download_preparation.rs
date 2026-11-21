use super::*;
use crate::download_preparation::DownloadPreparation;

fn local_preparation_core(root: &Path, user_hash: [u8; 16]) -> (EmulebbCore, Ed2kNetworkConfig) {
    std::fs::create_dir_all(root).unwrap();
    let port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut network = test_network_config_with_store(
        root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.bind_ip = Ipv4Addr::LOCALHOST;
    network.p2p_bind_ip = Some(Ipv4Addr::LOCALHOST);
    network.kad_bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    network.listen_port = port;
    network.ed2k.listen_port = Some(port);
    network.user_hash = user_hash;
    network.nat_config.enabled = false;
    network.ed2k.server_entries.clear();
    let server_probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    network.ed2k.server_endpoints = vec![server_probe.local_addr().unwrap().to_string()];
    network.ed2k.enable_udp_reask = false;
    network.kad_publish_shared_files = false;
    network.kad_udp_firewall_check_enabled = false;
    network.kad_tcp_firewall_check_enabled = false;
    network.kad_buddy_enabled = false;
    network.kad_routing_maintenance_enabled = false;
    let core = EmulebbCore::new_with_network(
        "test",
        test_index_with_settings(
            FileIndex::in_memory().unwrap(),
            serde_json::json!({"network":{"kadEnabled":false}}),
        ),
        root,
        Some(network.clone()),
    )
    .unwrap();
    (core, network)
}

#[tokio::test]
async fn prepared_connection_survives_local_hydration_busy_and_delivers_without_reask() {
    let root = unique_runtime_dir("core-prepared-hydration-recovery");
    let library = root.join("library");
    std::fs::create_dir_all(&library).unwrap();
    let payload = vec![0x61; 2048];
    std::fs::write(library.join("Sample.bin"), &payload).unwrap();
    let (seed, network) = local_preparation_core(&root.join("seed"), [0x61; 16]);
    seed.create_library_root(&library.to_string_lossy(), false)
        .await
        .unwrap()
        .unwrap();
    let shares = seed.reload_shared_directories().await.unwrap();
    let hash_hex = shares
        .iter()
        .find(|share| share.name == "Sample.bin")
        .unwrap()
        .hash
        .clone();
    drop(shares);
    seed.connect_ed2k().await.unwrap();
    let (download, _) = local_preparation_core(&root.join("download"), [0x62; 16]);
    let (_, created) = download
        .create_download(DownloadCreate {
            source: DownloadCreateSource::Content {
                hash: hash_hex.clone(),
                name: "Sample.bin".into(),
                size_bytes: Some(payload.len() as u64),
            },
            category: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            redownload: false,
        })
        .await
        .unwrap();
    let id = created.id;
    drop(created);
    let job = download
        .ed2k_transfers
        .download_job(id)
        .await
        .unwrap()
        .unwrap();
    let original = job.token;
    drop(job);
    download
        .ed2k_transfers
        .remember_source(
            original,
            Ed2kSourceHint {
                ip: Ipv4Addr::LOCALHOST.to_string(),
                tcp_port: network.listen_port,
                user_hash: Some(hex::encode(network.user_hash)),
                connect_options: None,
                file_comment: String::new(),
                file_rating: 0,
            },
        )
        .await
        .unwrap();
    let baseline = download
        .ed2k_transfers
        .download_resource_snapshot()
        .resident_bytes;
    download
        .download_hydration_busy
        .store(true, Ordering::Release);
    download.connect_ed2k().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while download.download_hydration_busy.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let job = download
        .ed2k_transfers
        .download_job(id)
        .await
        .unwrap()
        .unwrap();
    let selected = job.token;
    assert_eq!(selected.generation, original.generation + 1);
    assert!(
        job.storage
            .as_ref()
            .is_some_and(|storage| storage.identity.is_none() && !storage.path.exists())
    );
    assert!(job.storage_failure.is_none());
    drop(job);
    assert_eq!(
        download
            .ed2k_transfers
            .download_resource_snapshot()
            .resident_bytes,
        baseline
    );

    assert_eq!(
        download
            .ed2k_transfers
            .download_resource_snapshot()
            .connections,
        1,
        "the prepared socket must remain owned during the local wait"
    );
    let source = direct_test_source(
        hash_hex.parse().unwrap(),
        Ipv4Addr::LOCALHOST,
        network.listen_port,
    );
    let cooldown = crate::ed2k_download_retry::ED2K_DIRECT_SOURCE_RETRY_COOLDOWN;
    assert!(
        download
            .state
            .lock()
            .await
            .download_source_registry
            .endpoint_retry_delay(Instant::now(), cooldown, &source, &hash_hex,)
            .unwrap()
            > Duration::from_secs(19 * 60)
    );
    let delivered = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(share) = download.share(&hash_hex).await {
                break share;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(std::fs::read(&delivered.path).unwrap(), payload);
    assert!(
        download
            .state
            .lock()
            .await
            .download_source_registry
            .endpoint_retry_delay(Instant::now(), cooldown, &source, &hash_hex,)
            .unwrap()
            > Duration::from_secs(19 * 60),
        "recovery must not erase the network cooldown"
    );
    let job = download
        .ed2k_transfers
        .download_job(id)
        .await
        .unwrap()
        .unwrap();
    assert!(job.completed_at_s.is_some());
    assert!(job.storage_failure.is_none());
    assert!(
        job.token.generation <= selected.generation + 1,
        "only final retirement may follow the single begin"
    );
    drop(job);
    download.disconnect_ed2k().await.unwrap();
    seed.disconnect_ed2k().await.unwrap();
}

#[tokio::test]
async fn known_size_waiting_preparation_never_hydrates_without_a_useful_source() {
    let root = unique_runtime_dir("core-waiting-source-preparation");
    let mut network = test_network_config_with_store(
        &root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.bind_ip = Ipv4Addr::LOCALHOST;
    network.p2p_bind_ip = Some(Ipv4Addr::LOCALHOST);
    network.ed2k.server_entries.clear();
    network.ed2k.server_endpoints.clear();
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &root,
        Some(network),
    )
    .unwrap();
    let (_, created) = core
        .create_download(DownloadCreate {
            source: DownloadCreateSource::Content {
                hash: "94949494949494949494949494949494".into(),
                name: "Sample.bin".into(),
                size_bytes: Some(0x4000000000),
            },
            category: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            redownload: false,
        })
        .await
        .unwrap();
    let id = created.id;
    drop(created);
    let job = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
    let token = job.token;
    let guard = core
        .download_attempts
        .try_prepare(token, job.file_hash.parse().unwrap())
        .unwrap();
    drop(job);
    let baseline = core
        .ed2k_transfers
        .download_resource_snapshot()
        .resident_bytes;
    assert!(matches!(
        core.prepare_download_sources(&guard, &CancellationToken::new())
            .await
            .unwrap(),
        DownloadPreparation::Waiting
    ));
    let job = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
    assert_eq!(
        job.token, token,
        "source preparation must not begin another execution"
    );
    assert!(job.storage.is_none());
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .resident_bytes,
        baseline
    );
    assert!(!core.download_attempts.owns(token));
    assert!(core.state.lock().await.transfers.is_empty());
}
