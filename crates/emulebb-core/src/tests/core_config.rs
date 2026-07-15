use super::*;

#[test]
fn upload_queue_policy_uses_core_settings_for_slot_and_queue_limits() {
    let mut core_settings = default_core_settings();
    core_settings.max_upload_slots = 11;
    core_settings.queue_size = 6_000;
    let base = Ed2kUploadQueueRuntimeConfig {
        active_slots: 3,
        elastic_percent: 15,
        upload_limit_bytes_per_sec: 512 * 1024,
        elastic_underfill_bytes_per_sec: 16 * 1024,
        elastic_underfill_secs: 10,
        waiting_capacity: 512,
        waiting_timeout_secs: 44,
        granted_timeout_secs: 22,
        upload_timeout_secs: 88,
        session_transfer_percent: 45,
        session_time_limit_secs: 1_234,
    };

    let policy = ed2k_upload_queue_policy_from_core_settings(Some(&base), &core_settings);

    assert_eq!(policy.active_slots, 11);
    assert_eq!(
        policy.elastic_percent,
        core_settings.upload_slot_elastic_percent
    );
    assert_eq!(
        policy.upload_limit_bytes_per_sec,
        u64::from(core_settings.upload_limit_ki_bps) * 1024
    );
    assert_eq!(
        policy.elastic_underfill_bytes_per_sec,
        u64::from(core_settings.upload_client_data_rate) * 1024
    );
    assert_eq!(policy.waiting_capacity, 6_000);
    assert_eq!(policy.waiting_timeout_secs, 44);
    assert_eq!(policy.granted_timeout_secs, 22);
    assert_eq!(policy.upload_timeout_secs, 88);
    // Session rotation caps are queue-policy knobs, not settings.core-derived:
    // a core settings update must pass them through untouched.
    assert_eq!(policy.session_transfer_percent, 45);
    assert_eq!(policy.session_time_limit_secs, 1_234);
}

#[test]
fn initial_upload_queue_policy_preserves_config_for_fresh_profiles() {
    let core_settings = default_core_settings();
    let base = Ed2kUploadQueueRuntimeConfig {
        active_slots: 3,
        elastic_percent: 15,
        upload_limit_bytes_per_sec: 512 * 1024,
        elastic_underfill_bytes_per_sec: 16 * 1024,
        elastic_underfill_secs: 10,
        waiting_capacity: 512,
        waiting_timeout_secs: 44,
        granted_timeout_secs: 22,
        upload_timeout_secs: 88,
        session_transfer_percent: 45,
        session_time_limit_secs: 1_234,
    };

    let policy = initial_ed2k_upload_queue_policy(Some(&base), false, &core_settings);

    assert_eq!(policy, base);
}

#[tokio::test]
async fn persisted_core_settings_configure_upload_queue_on_startup() {
    let transfer_root = unique_runtime_dir("emulebb-core-upload-queue-startup-core_settings");
    let metadata = MetadataStore::open(transfer_root.join("metadata.sqlite")).unwrap();
    let mut core_settings = default_core_settings();
    core_settings.max_upload_slots = 2;
    core_settings.queue_size = 3_000;
    profile_state::persist_core_settings(&metadata, &core_settings).unwrap();
    let index = FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap();

    let core = EmulebbCore::new("test", index, transfer_root.join("transfers")).unwrap();
    let policy = core.ed2k_transfers.upload_queue_policy_snapshot().await;

    assert_eq!(policy.active_slots, 2);
    assert_eq!(policy.waiting_capacity, 3_000);
}

#[tokio::test]
async fn core_settings_update_reconfigures_live_upload_queue() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();

    let core_settings = core
        .update_core_settings(CoreSettingsUpdate {
            max_upload_slots: Some(4),
            queue_size: Some(4_000),
            ..CoreSettingsUpdate::default()
        })
        .await
        .unwrap();
    let policy = core.ed2k_transfers.upload_queue_policy_snapshot().await;

    assert_eq!(core_settings.max_upload_slots, 4);
    assert_eq!(core_settings.queue_size, 4_000);
    assert_eq!(policy.active_slots, 4);
    assert_eq!(policy.waiting_capacity, 4_000);
}

#[tokio::test]
async fn default_core_settings_match_the_master() {
    // FIX 6: defaults aligned to srchybrid/CoreSettings.cpp +
    // PreferenceValidationSeams.h.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let core_settings = core.core_settings().await;
    assert_eq!(core_settings.upload_limit_ki_bps, 6200);
    assert_eq!(core_settings.download_limit_ki_bps, 12207);
    assert_eq!(core_settings.max_connections, 500);
    assert_eq!(core_settings.max_connections_per_five_seconds, 50);
    assert_eq!(core_settings.max_sources_per_file, 600);
    assert_eq!(core_settings.max_upload_slots, 12);
    assert_eq!(core_settings.upload_slot_elastic_percent, 80);
    assert_eq!(core_settings.queue_size, 10000);
    assert!(!core_settings.auto_connect);
    assert!(core_settings.reconnect);
}

#[test]
fn core_settings_json_without_reconnect_defaults_to_enabled() {
    let mut value = serde_json::to_value(default_core_settings()).unwrap();
    value.as_object_mut().unwrap().remove("reconnect");

    let core_settings: CoreSettings = serde_json::from_value(value).unwrap();

    assert!(core_settings.reconnect);
}

#[tokio::test]
async fn network_kademlia_disabled_refuses_kad_bootstrap() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    // Disable the Kademlia network (eMule thePrefs.GetNetworkKademlia() == false).
    core.update_core_settings(CoreSettingsUpdate {
        network_kademlia: Some(false),
        ..CoreSettingsUpdate::default()
    })
    .await
    .unwrap();
    let err = core
        .bootstrap_kad("203.0.113.9", 4672)
        .await
        .expect_err("Kad bootstrap must be refused when networkKademlia=false");
    assert!(err.to_string().contains("Kademlia network is disabled"));
    // Re-enabling lets Kad start again.
    core.update_core_settings(CoreSettingsUpdate {
        network_kademlia: Some(true),
        ..CoreSettingsUpdate::default()
    })
    .await
    .unwrap();
    assert!(core.bootstrap_kad("203.0.113.9", 4672).await.is_ok());
}

#[tokio::test]
async fn vpn_guard_allows_kad_start_until_public_ip_disproves_allowed_cidr() {
    let transfer_root = unique_runtime_dir("emulebb-core-vpn-guard-kad-start");
    let mut network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.vpn_guard = VpnGuardConfig {
        enabled: true,
        mode: "block".to_string(),
        allowed_public_ip_cidrs: "8.8.8.0/24".to_string(),
    };
    network.vpn_interface_bound = true;
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap();

    assert!(
        core.start_kad().await.is_ok(),
        "valid VPN-bound public-CIDR mode should not block before any public IP is observed"
    );
    core.set_kad_running(false).await;

    core.ed2k_reachability.set(Ipv4Addr::new(1, 1, 1, 1));
    let err = core
        .start_kad()
        .await
        .expect_err("Kad start must be refused after public IP is outside the allowed CIDR");
    assert!(err.to_string().contains("blocked by VPN guard"));
    assert!(
        err.to_string()
            .contains("outside VPN Guard allowed public IP CIDRs")
    );

    core.ed2k_reachability.set(Ipv4Addr::new(8, 8, 8, 8));
    assert!(core.start_kad().await.is_ok());
}

#[tokio::test]
async fn network_ed2k_disabled_refuses_server_connect() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    // Disable the eD2k network (eMule thePrefs.GetNetworkED2K() == false): the
    // server connect is refused on the core setting gate (before any network
    // config / VPN-guard checks).
    core.update_core_settings(CoreSettingsUpdate {
        network_ed2k: Some(false),
        ..CoreSettingsUpdate::default()
    })
    .await
    .unwrap();
    let err = core
        .connect_ed2k()
        .await
        .expect_err("eD2k connect must be refused when networkEd2k=false");
    assert!(err.to_string().contains("eD2k network is disabled"));
}

#[test]
fn ed2k_nat_mappings_follow_configured_listener_addresses() {
    let transfer_root = unique_runtime_dir("emulebb-core-nat-mappings");
    let network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );

    let mappings = ed2k_nat_mappings(&network);

    assert_eq!(mappings.len(), 2);
    assert_eq!(mappings[0].name, "ed2k_tcp");
    assert_eq!(
        mappings[0].local_addr,
        "198.51.100.10:4662".parse().unwrap()
    );
    assert_eq!(mappings[0].protocol, TransportProtocol::Tcp);
    assert_eq!(mappings[0].exposure, MappingExposure::Required);
    assert_eq!(mappings[1].name, "kad_udp");
    assert_eq!(
        mappings[1].local_addr,
        "198.51.100.10:4665".parse().unwrap()
    );
    assert_eq!(mappings[1].protocol, TransportProtocol::Udp);
    assert_eq!(mappings[1].exposure, MappingExposure::Preferred);
}

#[test]
fn kad_firewalled_response_ip_uses_sender_ipv4_bytes() {
    let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 4672);

    assert_eq!(
        firewalled_response_ip_for_sender(from),
        Some(u32::from_be_bytes([203, 0, 113, 9]))
    );
}

#[tokio::test]
async fn network_config_initializes_kad_local_store() {
    let transfer_root = unique_runtime_dir("emulebb-core-kad-local-store-config");
    let expected = KadLocalStoreConfig {
        enabled: true,
        keyword_ttl: Duration::from_secs(11),
        source_ttl: Duration::from_secs(22),
        notes_ttl: Duration::from_secs(33),
        keyword_capacity: 44,
        source_capacity: 55,
        notes_capacity: 66,
        source_per_file_capacity: 77,
        notes_per_file_capacity: 88,
    };
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(test_network_config_with_store(
            &transfer_root,
            expected,
            SnoopQueueConfig::default(),
        )),
    )
    .unwrap();

    assert_eq!(
        core.kad_local_store_config_for_tests().await,
        Some(expected)
    );
}

#[tokio::test]
async fn network_config_hydrates_kad_publish_cache() {
    let transfer_root = unique_runtime_dir("emulebb-core-kad-publish-cache-hydrate");
    let metadata_store = MetadataStore::in_memory().unwrap();
    let target = NodeId::from_bytes([1; 16]);
    let file_hash = Ed2kHash::from_bytes([2; 16]);
    let snapshot = emulebb_index::KadPublishCacheSnapshot {
        keyword_publishes: vec![emulebb_index::KadKeywordPublishSnapshot {
            observed_at: Utc::now(),
            target,
            file_hash,
            tags: vec![
                Tag::filename("Sample Publish Cache.bin"),
                Tag::filesize(123),
            ],
            load: None,
        }],
        source_publishes: Vec::new(),
        note_publishes: Vec::new(),
    };
    metadata_store
        .replace_kad_publish_cache(&metadata_from_publish_snapshot(&snapshot).unwrap())
        .unwrap();

    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::from_metadata_store(metadata_store),
        &transfer_root,
        Some(test_network_config_with_store(
            &transfer_root,
            KadLocalStoreConfig {
                enabled: true,
                ..KadLocalStoreConfig::default()
            },
            SnoopQueueConfig::default(),
        )),
    )
    .unwrap();

    let hydrated = core.kad_publish_cache_snapshot_for_tests().await.unwrap();
    assert_eq!(hydrated.keyword_publishes.len(), 1);
    assert_eq!(hydrated.keyword_publishes[0].file_hash, file_hash);
}

#[tokio::test]
async fn network_config_initializes_kad_snoop_queue() {
    let transfer_root = unique_runtime_dir("emulebb-core-kad-snoop-queue-config");
    let expected = SnoopQueueConfig {
        dedup_window_secs: 7,
        general_max_queries_per_600s: 8,
        general_drain_cooldown_secs: 9,
        source_max_queries_per_600s: 10,
        source_drain_cooldown_secs: 11,
        source_stop_after_results: 12,
    };
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(test_network_config_with_store(
            &transfer_root,
            KadLocalStoreConfig::default(),
            expected.clone(),
        )),
    )
    .unwrap();

    assert_eq!(
        core.kad_snoop_queue_config_for_tests().await,
        Some(expected)
    );
    assert_eq!(
        core.kad_snoop_queue_snapshot_for_tests().await,
        Some(vec![])
    );
}

#[tokio::test]
async fn status_reports_live_dht_runtime_kad_contacts() {
    let transfer_root = unique_runtime_dir("emulebb-core-kad-status-runtime");
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
    let (search_handle, _search_inbox) = new_ed2k_server_search_channel(1);
    let dht = DhtNode::new(DhtConfig {
        bind_addr: Some("0.0.0.0:0".parse().unwrap()),
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let dht_task = dht.start();

    *core.ed2k_runtime.lock().await = Some(Ed2kRuntime {
        search_handle,
        server_state: Arc::new(RwLock::new(Ed2kServerState::default())),
        dht,
        kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
        nat: Arc::new(NatManager::default()),
        shutdown: Arc::clone(&shutdown),
        server_reconnect_signal: Arc::new(tokio::sync::Notify::new()),
        target_server_endpoint: Arc::new(RwLock::new(None)),
        kad_firewall_recheck: None,
        tasks: vec![dht_task],
        download_tasks: Arc::clone(&core.ed2k_download_tasks),
    });

    let status = core.status().await;

    assert!(status.kad.running);
    assert!(!status.kad.connected);
    assert_eq!(status.kad.contact_count, Some(0));
    // Empty routing table: not connected and nothing to bootstrap from, so
    // we report not-bootstrapping (the always-running driver has no seeds).
    assert_eq!(status.kad.bootstrapping, Some(false));
    // Unverified firewall state is reported as open (oracle IsFirewalledUDP).
    assert_eq!(status.kad.firewalled, Some(false));
    assert_eq!(status.kad.users, None);
    assert_eq!(status.kad.files, None);
    shutdown.store(true, Ordering::SeqCst);
    let _ = core.disconnect_ed2k().await;
}
