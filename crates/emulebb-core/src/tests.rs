use emulebb_ed2k::{NatConfig, ipfilter::IpFilter};
use emulebb_index::IndexedFile;
use emulebb_kad_proto::{NodeId, Tag, TagValue};
use md4::{Digest, Md4};

use super::*;
use crate::source_publish::emule_high_id_source_type;

#[test]
fn path_is_within_classifies_incoming_vs_shared_dirs() {
    use std::path::Path;
    let incoming = Path::new(r"C:\Downloads\Incoming");
    // A downloaded file living in the incoming dir (verbatim long path, mixed
    // case, forward slashes) is recognized as in-incoming.
    assert!(path_is_within(
        r"\\?\C:\Downloads\Incoming\example.iso",
        incoming
    ));
    assert!(path_is_within(
        r"c:/downloads/incoming/sub/file.bin",
        incoming
    ));
    // A file shared only from a separate shared dir is NOT in-incoming.
    assert!(!path_is_within(r"D:\Library\Media\sample.mkv", incoming));
    // A sibling dir sharing a name prefix must not count as inside.
    assert!(!path_is_within(r"C:\Downloads\IncomingOther\x", incoming));
    assert!(!path_is_within("anything", Path::new("")));
}

#[test]
fn connected_server_keyword_search_timeout_matches_mfc_floor() {
    let mut config = Ed2kConfig {
        connect_timeout_secs: 1,
        ..Ed2kConfig::default()
    };

    assert_eq!(
        connected_server_keyword_search_timeout(&config),
        Duration::from_secs(ED2K_LOCAL_SERVER_SEARCH_TIMEOUT_SECS)
    );

    config.connect_timeout_secs = 75;
    assert_eq!(
        connected_server_keyword_search_timeout(&config),
        Duration::from_secs(75)
    );
}

#[test]
fn find_buddy_res_connect_options_present_only_for_keyed_requester() {
    // LOWID-G11: a keyless legacy requester gets no trailing options byte.
    assert_eq!(find_buddy_res_connect_options(false, true), None);
    assert_eq!(find_buddy_res_connect_options(false, false), None);
    // A keyed requester gets the 0.49a+ connect-options byte.
    assert_eq!(
        find_buddy_res_connect_options(true, true),
        Some(emule_connect_options(true))
    );
    assert_eq!(
        find_buddy_res_connect_options(true, false),
        Some(emule_connect_options(false))
    );
}

#[test]
fn find_buddy_req_self_endpoint_matches_only_our_ip_and_port() {
    // LOWID-G12: refuse a request whose (IP, TCP port) is our own endpoint.
    let ours = Ipv4Addr::new(203, 0, 113, 5);
    let our_port = 4662u16;
    assert!(find_buddy_req_is_self_endpoint(
        IpAddr::V4(ours),
        our_port,
        Some(ours),
        our_port
    ));
    // Different IP or port is not us.
    assert!(!find_buddy_req_is_self_endpoint(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        our_port,
        Some(ours),
        our_port
    ));
    assert!(!find_buddy_req_is_self_endpoint(
        IpAddr::V4(ours),
        4663,
        Some(ours),
        our_port
    ));
    // Unknown public IP: can never match (we cannot be sure it is us).
    assert!(!find_buddy_req_is_self_endpoint(
        IpAddr::V4(ours),
        our_port,
        None,
        our_port
    ));
}

fn test_network_config_with_store(
    transfer_root: &Path,
    kad_local_store: KadLocalStoreConfig,
    kad_snoop_queue: SnoopQueueConfig,
) -> Ed2kNetworkConfig {
    Ed2kNetworkConfig {
        bind_ip: Ipv4Addr::new(198, 51, 100, 10),
        kad_bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 4665),
        listen_port: 4662,
        user_hash: [0x44; 16],
        secure_ident: Arc::new(
            Ed2kSecureIdent::load_or_create(&transfer_root.join("secure-ident.der")).unwrap(),
        ),
        kad_local_store,
        kad_snoop_queue,
        kad_bootstrap_nodes: Vec::new(),
        kad_bootstrap_min_routing_contacts: 10,
        kad_publish_shared_files: true,
        kad_republish_interval_secs: 1_800,
        kad_publish_contact_fanout: 4,
        kad_routing_maintenance_enabled: true,
        kad_udp_firewall_check_enabled: true,
        kad_udp_firewall_check_interval_secs: 600,
        kad_tcp_firewall_check_enabled: true,
        kad_tcp_firewall_check_interval_secs: 600,
        kad_buddy_enabled: true,
        nat_config: NatConfig::default(),
        config: Ed2kConfig::default(),
        p2p_bind_ip: Some(Ipv4Addr::new(198, 51, 100, 10)),
        p2p_bind_interface: None,
        vpn_guard: VpnGuardConfig::default(),
        vpn_interface_bound: false,
        vpn_interface_bound_runtime: None,
        ip_filter: IpFilter::default(),
        ip_filter_path: None,
        ip_filter_level: emulebb_ed2k::ipfilter::DEFAULT_FILTER_LEVEL,
    }
}

#[tokio::test]
async fn kad_callback_req_relays_op_callback_down_held_buddy_socket() {
    use emulebb_ed2k::buddy_socket::BuddySocketRegistry;
    use tokio::sync::mpsc;

    let buddy_id = NodeId::from_bytes([0x77; 16]);
    let file_hash = Ed2kHash::from_bytes([0xC4; 16]);
    let requester_ip = Ipv4Addr::new(203, 0, 113, 9);
    let requester_tcp = 4662u16;
    let firewalled_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30)), 4662);

    let mut state = KadBuddyState::new();
    state
        .accept_incoming_buddy(
            false,
            IncomingBuddy {
                client_hash: Ed2kHash::from_bytes([0x11; 16]),
                buddy_id,
                tcp_addr: firewalled_addr,
                udp_addr: firewalled_addr,
                registered_at: Utc::now(),
            },
        )
        .unwrap();
    let kad_buddy = Arc::new(Mutex::new(state));

    // Simulate the held inbound buddy session: attach a relay writer.
    let registry = BuddySocketRegistry::new();
    let (tx, mut rx) = mpsc::unbounded_channel();
    assert!(registry.attach_inbound(buddy_id, tx));

    // The callback requester (UDP source) wants the firewalled client; its
    // CALLBACK_REQ echoes the buddy check id (== registered buddy_id).
    let req = CallbackReq {
        buddy_id,
        file_hash,
        tcp_port: requester_tcp,
    };
    let from = SocketAddr::new(IpAddr::V4(requester_ip), 5000);

    handle_kad_callback_req(&kad_buddy, &registry, from, &req).await;

    // The exact OP_CALLBACK relay frame must be pushed down the held socket.
    let relayed = rx
        .try_recv()
        .expect("relay frame delivered to held buddy socket");
    let expected =
        encode_kad_callback_relay_frame(buddy_id.0, &file_hash, requester_ip, requester_tcp);
    assert_eq!(relayed, expected);
}

#[tokio::test]
async fn kad_callback_req_without_held_socket_does_not_relay() {
    use emulebb_ed2k::buddy_socket::BuddySocketRegistry;

    let buddy_id = NodeId::from_bytes([0x88; 16]);
    let firewalled_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31)), 4662);
    let mut state = KadBuddyState::new();
    state
        .accept_incoming_buddy(
            false,
            IncomingBuddy {
                client_hash: Ed2kHash::from_bytes([0x22; 16]),
                buddy_id,
                tcp_addr: firewalled_addr,
                udp_addr: firewalled_addr,
                registered_at: Utc::now(),
            },
        )
        .unwrap();
    let kad_buddy = Arc::new(Mutex::new(state));
    // No inbound socket attached -> the matched callback cannot be relayed.
    let registry = BuddySocketRegistry::new();
    let req = CallbackReq {
        buddy_id,
        file_hash: Ed2kHash::from_bytes([0xC5; 16]),
        tcp_port: 4662,
    };
    let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 5000);
    // Must not panic and must not relay (no attached socket).
    handle_kad_callback_req(&kad_buddy, &registry, from, &req).await;
    assert!(!registry.has_inbound());
}

#[test]
fn upload_queue_policy_uses_preferences_for_slot_and_queue_limits() {
    let mut preferences = default_preferences();
    preferences.max_upload_slots = 11;
    preferences.queue_size = 6_000;
    let base = Ed2kUploadQueuePolicyConfig {
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

    let policy = ed2k_upload_queue_policy_from_preferences(Some(&base), &preferences);

    assert_eq!(policy.active_slots, 11);
    assert_eq!(
        policy.elastic_percent,
        preferences.upload_slot_elastic_percent
    );
    assert_eq!(
        policy.upload_limit_bytes_per_sec,
        u64::from(preferences.upload_limit_ki_bps) * 1024
    );
    assert_eq!(
        policy.elastic_underfill_bytes_per_sec,
        u64::from(preferences.upload_client_data_rate) * 1024
    );
    assert_eq!(policy.waiting_capacity, 6_000);
    assert_eq!(policy.waiting_timeout_secs, 44);
    assert_eq!(policy.granted_timeout_secs, 22);
    assert_eq!(policy.upload_timeout_secs, 88);
    // Session rotation caps are queue-policy knobs, not preference-derived:
    // a preferences update must pass them through untouched.
    assert_eq!(policy.session_transfer_percent, 45);
    assert_eq!(policy.session_time_limit_secs, 1_234);
}

#[test]
fn initial_upload_queue_policy_preserves_config_for_fresh_profiles() {
    let preferences = default_preferences();
    let base = Ed2kUploadQueuePolicyConfig {
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

    let policy = initial_ed2k_upload_queue_policy(Some(&base), false, &preferences);

    assert_eq!(policy, base);
}

#[tokio::test]
async fn persisted_preferences_configure_upload_queue_on_startup() {
    let transfer_root = unique_runtime_dir("emulebb-core-upload-queue-startup-preferences");
    let metadata = MetadataStore::open(transfer_root.join("metadata.sqlite")).unwrap();
    let mut preferences = default_preferences();
    preferences.max_upload_slots = 2;
    preferences.queue_size = 3_000;
    profile_state::persist_preferences(&metadata, &preferences).unwrap();
    let index = FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap();

    let core = EmulebbCore::new("test", index, transfer_root.join("transfers")).unwrap();
    let policy = core.ed2k_transfers.upload_queue_policy_snapshot().await;

    assert_eq!(policy.active_slots, 2);
    assert_eq!(policy.waiting_capacity, 3_000);
}

#[tokio::test]
async fn preferences_update_reconfigures_live_upload_queue() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();

    let preferences = core
        .update_preferences(PreferencesUpdate {
            max_upload_slots: Some(4),
            queue_size: Some(4_000),
            ..PreferencesUpdate::default()
        })
        .await
        .unwrap();
    let policy = core.ed2k_transfers.upload_queue_policy_snapshot().await;

    assert_eq!(preferences.max_upload_slots, 4);
    assert_eq!(preferences.queue_size, 4_000);
    assert_eq!(policy.active_slots, 4);
    assert_eq!(policy.waiting_capacity, 4_000);
}

#[tokio::test]
async fn default_preferences_match_the_master() {
    // FIX 6: defaults aligned to srchybrid/Preferences.cpp +
    // PreferenceValidationSeams.h.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let prefs = core.preferences().await;
    assert_eq!(prefs.upload_limit_ki_bps, 6200);
    assert_eq!(prefs.download_limit_ki_bps, 12207);
    assert_eq!(prefs.max_connections, 500);
    assert_eq!(prefs.max_connections_per_five_seconds, 50);
    assert_eq!(prefs.max_sources_per_file, 600);
    assert_eq!(prefs.max_upload_slots, 12);
    assert_eq!(prefs.upload_slot_elastic_percent, 80);
    assert_eq!(prefs.queue_size, 10000);
    assert!(!prefs.auto_connect);
    assert!(prefs.reconnect);
}

#[test]
fn preferences_json_without_reconnect_defaults_to_enabled() {
    let mut value = serde_json::to_value(default_preferences()).unwrap();
    value.as_object_mut().unwrap().remove("reconnect");

    let preferences: Preferences = serde_json::from_value(value).unwrap();

    assert!(preferences.reconnect);
}

#[tokio::test]
async fn network_kademlia_disabled_refuses_kad_bootstrap() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    // Disable the Kademlia network (eMule thePrefs.GetNetworkKademlia() == false).
    core.update_preferences(PreferencesUpdate {
        network_kademlia: Some(false),
        ..PreferencesUpdate::default()
    })
    .await
    .unwrap();
    let err = core
        .bootstrap_kad("203.0.113.9", 4672)
        .await
        .expect_err("Kad bootstrap must be refused when networkKademlia=false");
    assert!(err.to_string().contains("Kademlia network is disabled"));
    // Re-enabling lets Kad start again.
    core.update_preferences(PreferencesUpdate {
        network_kademlia: Some(true),
        ..PreferencesUpdate::default()
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
    // server connect is refused on the preference gate (before any network
    // config / VPN-guard checks).
    core.update_preferences(PreferencesUpdate {
        network_ed2k: Some(false),
        ..PreferencesUpdate::default()
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

#[tokio::test]
async fn ed2k_shared_catalog_publish_waits_for_connected_server() {
    let transfer_root = unique_runtime_dir("emulebb-core-shared-publish-disconnected");
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(test_network_config_with_store(
            &transfer_root,
            KadLocalStoreConfig::default(),
            SnoopQueueConfig::default(),
        )),
    )
    .unwrap();
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

    assert_eq!(
        core.publish_ed2k_shared_catalog().await.unwrap(),
        Ed2kSharedCatalogPublishOutcome::NotConnected
    );
    shutdown.store(true, Ordering::SeqCst);
    let _ = core.disconnect_ed2k().await;
}

#[test]
fn kad_snoop_entry_builders_preserve_passive_search_shapes() {
    let target = NodeId::from_bytes([
        0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x0c, 0x0b, 0x0a, 0x09, 0x10, 0x0f, 0x0e,
        0x0d,
    ]);
    let now = Utc::now();

    let keyword = build_keyword_snoop_entry(
        &SearchKeyReq {
            target,
            start_position: 0x8002,
            restrictive_payload: vec![0xaa, 0xbb],
        },
        now,
    );
    let source = build_source_snoop_entry(
        &SearchSourceReq {
            target,
            start_position: 0x0011,
            size: 123_456,
        },
        now,
    );
    let notes = build_notes_snoop_entry(
        &SearchNotesReq {
            target,
            size: 654_321,
        },
        now,
    );

    assert_eq!(
        keyword.logical_key(),
        "keyword:0102030405060708090a0b0c0d0e0f10:8002:aabb"
    );
    assert_eq!(keyword.restrictive_payload_hex(), Some("aabb"));
    assert_eq!(
        source.logical_key(),
        "source:0102030405060708090a0b0c0d0e0f10:0011:123456"
    );
    assert_eq!(
        notes.logical_key(),
        "notes:0102030405060708090a0b0c0d0e0f10:654321"
    );
}

#[test]
fn configured_kad_bootstrap_nodes_text_keeps_only_valid_ipv4_nodes() {
    let nodes = vec![
        "192.0.2.20:4665".to_string(),
        " ".to_string(),
        "[2001:db8::1]:4665".to_string(),
        "not-an-address".to_string(),
        "192.0.2.21:4666".to_string(),
    ];

    assert_eq!(
        configured_kad_bootstrap_nodes_text(&nodes).as_deref(),
        Some("192.0.2.20:4665\n192.0.2.21:4666")
    );
    assert_eq!(
        configured_kad_bootstrap_nodes_text(&["bad".to_string()]),
        None
    );
}

#[test]
fn source_type_switches_to_large_file_variant_at_old_max_emule_file_size() {
    // Oracle IsLargeFile(): strictly greater than OLD_MAX_EMULE_FILE_SIZE
    // (4290048000), not the raw u32 ceiling.
    assert_eq!(emule_high_id_source_type(4_290_048_000), 1);
    assert_eq!(emule_high_id_source_type(4_290_048_001), 4);
}

#[test]
fn source_publish_tags_match_oracle_open_shape() {
    // Oracle non-firewalled STOREFILE branch (Search.cpp:732-743):
    // SOURCETYPE, SOURCEPORT, SOURCEUPORT, FILESIZE, ENCRYPTION — and no
    // SOURCEIP tag (indexers take the IP from the datagram sender).
    let tags = build_source_publish_tags(
        41000,
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: false,
        },
        2_097_152,
        SourcePublishReachability::Open,
        NodeId::from_bytes([0x11; 16]),
    );

    assert_eq!(
        tags,
        vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(41001)),
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
            Tag::filesize(2_097_152),
            Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0)),
        ]
    );
}

#[test]
fn source_publish_tags_set_obfuscated_encryption_bits() {
    let tags = build_source_publish_tags(
        41000,
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: true,
        },
        2_097_152,
        SourcePublishReachability::Open,
        NodeId::from_bytes([0x11; 16]),
    );

    assert_eq!(
        tags.last(),
        Some(&Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(3)))
    );
}

#[test]
fn source_publish_tags_match_oracle_buddy_relay_shape() {
    // Oracle firewalled-with-buddy STOREFILE branch (Search.cpp:717-730):
    // SOURCETYPE 3 (uint8), SERVERIP = buddy in_addr DWORD, SERVERPORT =
    // buddy Kad UDP port, BUDDYHASH = uppercase hex of ~KadID in wire
    // order, then the common tail.
    let own_id = NodeId::from_bytes([0xF0; 16]);
    let tags = build_source_publish_tags(
        41000,
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: false,
        },
        2_097_152,
        SourcePublishReachability::BuddyRelay {
            buddy_ip: "198.51.100.136".parse().unwrap(),
            buddy_kad_port: 4672,
        },
        own_id,
    );

    assert_eq!(
        tags,
        vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::U8(3)),
            Tag::new_short(tag_name::SERVERIP, TagValue::UInt(0x8864_33C6)),
            Tag::new_short(tag_name::SERVERPORT, TagValue::UInt(4672)),
            Tag::new_short(
                tag_name::BUDDYHASH,
                TagValue::String("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F".to_string()),
            ),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(41001)),
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
            Tag::filesize(2_097_152),
            Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0)),
        ]
    );
}

#[test]
fn source_publish_tags_buddy_relay_uses_large_file_type_5() {
    let tags = build_source_publish_tags(
        41000,
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: false,
        },
        EMULE_LARGE_FILE_SIZE_THRESHOLD + 1,
        SourcePublishReachability::BuddyRelay {
            buddy_ip: "198.51.100.136".parse().unwrap(),
            buddy_kad_port: 4672,
        },
        NodeId::from_bytes([0xF0; 16]),
    );

    assert_eq!(
        tags.first(),
        Some(&Tag::new_short(tag_name::SOURCETYPE, TagValue::U8(5)))
    );
}

#[test]
fn source_publish_tags_direct_callback_sets_type_6_and_callback_bit() {
    // Oracle direct-callback STOREFILE branch (Search.cpp:708-715) +
    // GetMyConnectOptions(true, true): type 6 with connect options bit 3.
    let tags = build_source_publish_tags(
        41000,
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: true,
        },
        2_097_152,
        SourcePublishReachability::DirectUdpCallback,
        NodeId::from_bytes([0x11; 16]),
    );

    assert_eq!(
        tags.first(),
        Some(&Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(6)))
    );
    assert_eq!(
        tags.last(),
        Some(&Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0x0B)))
    );
}

#[test]
fn kad_hello_request_tags_advertise_source_udp_port_when_verified_open() {
    let tags = build_kad_hello_request_tags(41000, true, false, false, false, KAD_VERSION);

    assert_eq!(
        tags,
        vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))]
    );
}

#[test]
fn kad_hello_request_tags_emit_source_port_and_misc_bits_additively() {
    // Oracle SendMyDetails writes SOURCEUPORT (intern port) AND KADMISCOPTIONS
    // (firewalled/ack) together, not one or the other.
    let tags = build_kad_hello_request_tags(41000, true, true, false, true, KAD_VERSION);

    assert_eq!(
        tags,
        vec![
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
            Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05)),
        ]
    );
}

#[test]
fn kad_hello_tags_omit_misc_options_toward_pre_v8_contacts() {
    // Oracle SendMyDetails only writes (and counts) TAG_KADMISCOPTIONS when
    // byKadVersion >= KADEMLIA_VERSION8_49b. A v7 (or older) contact that
    // would otherwise get the ACK/firewall bits receives SOURCEUPORT only;
    // it is IP-verified via a PING / legacy challenge instead.
    for build in [
        build_kad_hello_request_tags as fn(u16, bool, bool, bool, bool, u8) -> Vec<Tag>,
        build_kad_hello_response_tags,
    ] {
        assert_eq!(
            build(41000, true, true, true, true, 7),
            vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))],
            "pre-v8 contact must not receive KADMISCOPTIONS"
        );
        // v8 exactly is the first version that receives it.
        assert!(
            build(41000, true, true, true, true, 8)
                .iter()
                .any(|tag| tag.name == emulebb_kad_proto::TagName::Short(tag_name::KADMISCOPTIONS))
        );
    }
}

#[test]
fn kad_publish_tolerance_gate_matches_oracle_distance_and_lan_exemption() {
    use std::net::Ipv4Addr;
    let own = NodeId::ZERO;

    // Close target (chunk0 distance well under SEARCHTOLERANCE) -> accepted.
    let close = NodeId::from_be_bytes([0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(kad_publish_within_tolerance(
        own,
        close,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    ));

    // Far target (chunk0 distance > SEARCHTOLERANCE) from a public IP -> dropped.
    let far = NodeId::from_be_bytes([0x7F, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(!kad_publish_within_tolerance(
        own,
        far,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    ));

    // The same far target from a LAN IP is exempt -> accepted.
    assert!(kad_publish_within_tolerance(
        own,
        far,
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))
    ));
}

#[test]
fn kad_req_masks_type_to_low_five_bits_and_rejects_zero() {
    // Oracle: byType &= 0x1F; throw on 0.
    assert_eq!(kad_req_masked_count(0x00), None);
    assert_eq!(kad_req_masked_count(0x20), None); // high bits only -> 0
    assert_eq!(kad_req_masked_count(0x02), Some(2));
    assert_eq!(kad_req_masked_count(0xE2), Some(2)); // high bits masked off
    assert_eq!(kad_req_masked_count(0x1F), Some(0x1F));
}

#[test]
fn hello_res_ack_requested_only_when_added_and_key_unverified() {
    // Oracle: SendMyDetails(..., bAddedOrUpdated && !bValidReceiverKey).
    assert!(should_request_hello_res_ack(true, false));
    assert!(!should_request_hello_res_ack(true, true));
    assert!(!should_request_hello_res_ack(false, false));
    assert!(!should_request_hello_res_ack(false, true));
}

#[test]
fn kad_hello_request_tags_emit_only_misc_bits_when_on_extern_port() {
    // When we advertise our extern Kad port (GetUseExternKadPort), the oracle
    // omits SOURCEUPORT but still emits KADMISCOPTIONS while firewalled.
    let tags = build_kad_hello_request_tags(41000, false, true, false, true, KAD_VERSION);

    assert_eq!(
        tags,
        vec![Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05))]
    );
}

#[test]
fn kad_hello_response_tags_include_source_udp_port_and_misc_bits() {
    let tags = build_kad_hello_response_tags(41000, true, true, true, true, KAD_VERSION);

    assert_eq!(
        tags,
        vec![
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
            Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x07)),
        ]
    );
}

#[test]
fn kad_hello_response_tags_gate_both_tags_like_request_and_oracle() {
    // Oracle SendMyDetails gates HELLO_RES tags as HELLO_REQ: SOURCEUPORT
    // only when advertising the intern port; KADMISCOPTIONS only on ACK/fw.
    assert!(
        build_kad_hello_response_tags(41000, false, false, false, false, KAD_VERSION).is_empty()
    );
    assert_eq!(
        build_kad_hello_response_tags(41000, true, false, false, false, KAD_VERSION),
        vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))]
    );
    assert_eq!(
        build_kad_hello_response_tags(41000, false, true, false, true, KAD_VERSION),
        vec![Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05))]
    );
}

#[test]
fn source_publish_identity_uses_emule_kad_chunk_order() {
    let user_hash = [
        0xB4, 0x22, 0xCF, 0x1A, 0x44, 0x0E, 0x71, 0x6B, 0xD2, 0xE1, 0xDD, 0x6E, 0x77, 0x21, 0x6F,
        0xE4,
    ];

    let publisher_id = source_publish_client_hash(user_hash);

    assert_eq!(
        publisher_id.0,
        [
            0x1A, 0xCF, 0x22, 0xB4, 0x6B, 0x71, 0x0E, 0x44, 0x6E, 0xDD, 0xE1, 0xD2, 0xE4, 0x6F,
            0x21, 0x77,
        ]
    );
    assert_eq!(publisher_id.to_be_bytes(), user_hash);
}

#[test]
fn kad_publishable_shared_files_follow_mfc_publish_rank() {
    let shared = MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([0x11; 16]).to_string(),
        canonical_name: "shared.bin".to_string(),
        file_size: 128,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        session_uploaded_bytes: 0,
        session_request_count: 0,
        session_accept_count: 0,
        all_time_uploaded_bytes: 0,
        all_time_upload_requests: 0,
        all_time_upload_accepts: 0,
        last_upload_request_ms: 0,
        comment: "synthetic note".to_string(),
        rating: 4,
    };
    let other = MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([0x22; 16]).to_string(),
        canonical_name: "other.bin".to_string(),
        upload_priority: "release".to_string(),
        ..shared.clone()
    };

    let publishable =
        kad_publishable_shared_file_entries(vec![shared.clone(), other.clone()], 4_000, |_| 0);

    assert_eq!(publishable, vec![other, shared]);
}

#[test]
fn kad_publish_rank_age_term_favors_longest_unpublished() {
    // Two files identical except their last Kad-publish wall time. The
    // longer-unpublished file must rank higher on the age term (ordered
    // first), and a never-published file (last-publish 0) must rank as the
    // most-overdue of all — the age term is no longer a flat constant.
    let now_unix_ms = 100_000_000i64;
    let hour_ms = 3_600_000i64;
    let recent = MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([0xA1; 16]).to_string(),
        canonical_name: "recent.bin".to_string(),
        file_size: 1_000,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        session_uploaded_bytes: 0,
        session_request_count: 0,
        session_accept_count: 0,
        all_time_uploaded_bytes: 0,
        all_time_upload_requests: 0,
        all_time_upload_accepts: 0,
        last_upload_request_ms: 0,
        comment: String::new(),
        rating: 0,
    };
    let stale = MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([0xB2; 16]).to_string(),
        canonical_name: "stale.bin".to_string(),
        ..recent.clone()
    };
    let never = MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([0xC3; 16]).to_string(),
        canonical_name: "never.bin".to_string(),
        ..recent.clone()
    };

    // recent: published 1h ago; stale: published 30h ago (age capped later);
    // never: never published (0). Age boost: never (80) > stale > recent.
    let last_publish = |file_hash: &str| -> i64 {
        if file_hash == recent.file_hash {
            now_unix_ms - hour_ms
        } else if file_hash == stale.file_hash {
            now_unix_ms - 30 * hour_ms
        } else {
            0
        }
    };

    let ordered = kad_publishable_shared_file_entries(
        vec![recent.clone(), stale.clone(), never.clone()],
        now_unix_ms,
        last_publish,
    );

    assert_eq!(
        ordered
            .iter()
            .map(|e| e.file_hash.clone())
            .collect::<Vec<_>>(),
        vec![
            never.file_hash.clone(),
            stale.file_hash.clone(),
            recent.file_hash.clone()
        ]
    );

    // Sanity: feeding the same constant to every file (the old bug) flattens
    // the age term so ordering falls back to the deterministic jitter/sequence
    // rather than staleness.
    let flat = kad_publishable_shared_file_entries(
        vec![recent.clone(), stale.clone(), never.clone()],
        now_unix_ms,
        |_| 0,
    );
    assert!(flat.iter().all(|e| {
        e.file_hash == recent.file_hash
            || e.file_hash == stale.file_hash
            || e.file_hash == never.file_hash
    }));
}

#[test]
fn best_notes_candidate_uses_notes_clock_not_source_clock() {
    use crate::kad_publish_schedule::KadPublishSchedule;
    use std::time::Duration;

    let now = Instant::now();
    let now_unix_ms = 200_000_000i64;
    let annotated = |tag: u8, name: &str| MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([tag; 16]).to_string(),
        canonical_name: name.to_string(),
        file_size: 1_000,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        session_uploaded_bytes: 0,
        session_request_count: 0,
        session_accept_count: 0,
        all_time_uploaded_bytes: 0,
        all_time_upload_requests: 0,
        all_time_upload_accepts: 0,
        last_upload_request_ms: 0,
        comment: "synthetic note".to_string(),
        rating: 3,
    };
    let recent_notes = annotated(0x51, "recent-notes.bin");
    let stale_notes = annotated(0x62, "stale-notes.bin");
    let un_annotated = MetadataTransferPublishEntry {
        comment: String::new(),
        rating: 0,
        ..annotated(0x73, "plain.bin")
    };

    let mut schedule = KadPublishSchedule::new();
    // NOTES clock: recent published 1h ago, stale 30h ago -> stale is the best
    // notes candidate. SOURCE clock is deliberately the opposite so a bug that
    // read the source clock would pick `recent_notes` instead.
    schedule.mark_notes_published(&recent_notes.file_hash, now - Duration::from_secs(3_600));
    schedule.mark_notes_published(
        &stale_notes.file_hash,
        now - Duration::from_secs(30 * 3_600),
    );
    schedule.mark_source_published(&stale_notes.file_hash, now - Duration::from_secs(60), None);

    let best = select_best_notes_publish_candidate(
        &[
            recent_notes.clone(),
            stale_notes.clone(),
            un_annotated.clone(),
        ],
        &schedule,
        now,
        now_unix_ms,
    );
    assert_eq!(best, Some(stale_notes.file_hash.clone()));

    // No annotated file -> no notes candidate.
    assert_eq!(
        select_best_notes_publish_candidate(&[un_annotated], &schedule, now, now_unix_ms),
        None
    );
}

#[test]
fn kad_publish_entry_from_shared_catalog_preserves_live_rank_inputs() {
    let mut entry = Ed2kSharedEntry {
        file_hash: Ed2kHash::from_bytes([0x33; 16]).to_string(),
        canonical_name: "ubuntu-python-sample.iso".to_string(),
        file_size: 4096,
        verified_complete: true,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: Some("ab".repeat(20)),
        upload_priority: "high".to_string(),
        auto_upload_priority: false,
        comment: "synthetic note".to_string(),
        rating: 5,
        all_time_uploaded_bytes: 512,
        complete_parts: Vec::new(),
        publish: Default::default(),
    };
    entry.publish.session_uploaded_bytes = 128;
    entry.publish.session_request_count = 3;
    entry.publish.session_accept_count = 2;
    entry.publish.all_time_request_count = 7;
    entry.publish.all_time_accept_count = 4;
    entry.publish.last_request_unix_ms = 1_700_000_000_000;

    let publish = kad_publish_entry_from_shared_entry(&entry);

    assert_eq!(publish.session_uploaded_bytes, 128);
    assert_eq!(publish.session_request_count, 3);
    assert_eq!(publish.session_accept_count, 2);
    assert_eq!(publish.all_time_upload_requests, 7);
    assert_eq!(publish.all_time_upload_accepts, 4);
    assert_eq!(publish.comment, "synthetic note");
    assert_eq!(publish.rating, 5);
}

#[test]
fn keyword_ordering_holds_age_constant_and_ignores_source_publish_clock() {
    // The keyword lane ranks candidates with the age term held at 0 (oracle
    // passes 0 for tLastPublish, SharedFileList.cpp:3316), so two files
    // identical except their SOURCE last-publish clock rank equally for
    // keyword selection -- unlike the source lane, whose ordering the
    // last-publish clock deliberately moves.
    let now_unix_ms = 100_000_000i64;
    let make = |hash: u8| MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([hash; 16]).to_string(),
        canonical_name: "ubuntu-python-sample.iso".to_string(),
        file_size: 4096,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        session_uploaded_bytes: 0,
        session_request_count: 0,
        session_accept_count: 0,
        all_time_uploaded_bytes: 0,
        all_time_upload_requests: 0,
        all_time_upload_accepts: 0,
        last_upload_request_ms: 0,
        comment: String::new(),
        rating: 0,
    };
    let a = make(0xA1);
    let b = make(0xB2);
    let entries = vec![a.clone(), b.clone()];
    let hashes = |entries: Vec<MetadataTransferPublishEntry>| {
        entries.into_iter().map(|e| e.file_hash).collect::<Vec<_>>()
    };

    // SOURCE ordering DOES move with the clock: whichever file is
    // "never published" (0 -> max age boost) sorts ahead of the other.
    let source_a_overdue = hashes(kad_publishable_shared_file_entries(
        entries.clone(),
        now_unix_ms,
        |file_hash| {
            if file_hash == b.file_hash {
                now_unix_ms - 60_000
            } else {
                0
            }
        },
    ));
    let source_b_overdue = hashes(kad_publishable_shared_file_entries(
        entries.clone(),
        now_unix_ms,
        |file_hash| {
            if file_hash == a.file_hash {
                now_unix_ms - 60_000
            } else {
                0
            }
        },
    ));
    assert_ne!(source_a_overdue, source_b_overdue);

    // KEYWORD ordering (age held at 0) is invariant to the source clock.
    let keyword_first = hashes(kad_publishable_shared_file_entries(
        entries.clone(),
        now_unix_ms,
        |_| 0,
    ));
    let keyword_again = hashes(kad_publishable_shared_file_entries(
        entries,
        now_unix_ms,
        |_| 0,
    ));
    assert_eq!(keyword_first, keyword_again);
}

#[test]
fn kad_source_publish_admits_servable_partfiles_but_keyword_stays_complete_only() {
    let base = |hash: u8, verified_complete: bool, complete_parts: Vec<bool>| Ed2kSharedEntry {
        file_hash: Ed2kHash::from_bytes([hash; 16]).to_string(),
        canonical_name: "ubuntu-python-sample.iso".to_string(),
        file_size: 4096,
        verified_complete,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        all_time_uploaded_bytes: 0,
        complete_parts,
        publish: Default::default(),
    };

    // Completed file: eligible for both lanes.
    let complete = base(0x01, true, Vec::new());
    assert!(kad_source_publish_eligible(&complete));
    assert!(kad_keyword_publish_eligible(&complete));

    // In-progress partfile with ≥1 complete ED2K part: SOURCE-eligible (we
    // can serve that part) but NOT keyword-eligible (oracle `!IsPartFile()`).
    let servable_partfile = base(0x02, false, vec![true, false]);
    assert!(servable_partfile.is_servable());
    assert!(kad_source_publish_eligible(&servable_partfile));
    assert!(!kad_keyword_publish_eligible(&servable_partfile));

    // Partfile with no complete part yet: nothing to serve, so in neither.
    let empty_partfile = base(0x03, false, vec![false, false]);
    assert!(!empty_partfile.is_servable());
    assert!(!kad_source_publish_eligible(&empty_partfile));
    assert!(!kad_keyword_publish_eligible(&empty_partfile));

    // Compatibility hint (a file we do not hold): never published either way.
    let hint = Ed2kSharedEntry {
        compatibility_hint: true,
        ..base(0x04, true, Vec::new())
    };
    assert!(!kad_source_publish_eligible(&hint));
    assert!(!kad_keyword_publish_eligible(&hint));
}

#[test]
fn cheap_prune_hash_set_matches_old_source_scan_and_prunes_on_blocked_tick() {
    use crate::kad_publish_schedule::KadPublishSchedule;
    use std::collections::HashSet;
    use std::time::Duration;

    let base = |hash: u8, verified_complete: bool, complete_parts: Vec<bool>| Ed2kSharedEntry {
        file_hash: Ed2kHash::from_bytes([hash; 16]).to_string(),
        canonical_name: "ubuntu-python-sample.iso".to_string(),
        file_size: 4096,
        verified_complete,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        all_time_uploaded_bytes: 0,
        complete_parts,
        publish: Default::default(),
    };
    let complete = base(0x01, true, Vec::new());
    let servable_partfile = base(0x02, false, vec![true, false]);
    let empty_partfile = base(0x03, false, vec![false, false]);
    let hint = Ed2kSharedEntry {
        compatibility_hint: true,
        ..base(0x04, true, Vec::new())
    };
    let catalog = [
        complete.clone(),
        servable_partfile.clone(),
        empty_partfile.clone(),
        hint.clone(),
    ];

    // OPP-1 prune input: the cheap hash read (what a gate-blocked tick uses to
    // prune) must select exactly the SOURCE-scan file set the expensive
    // build+prune used before the reorder. Build the old set the way the
    // pre-optimization prune did — from the fully ranked SOURCE clones.
    let cheap: HashSet<String> = catalog
        .iter()
        .filter(|entry| kad_source_publish_eligible(entry))
        .map(|entry| entry.file_hash.clone())
        .collect();
    let old_source_scan = kad_publishable_shared_file_entries(
        catalog
            .iter()
            .filter(|entry| kad_source_publish_eligible(entry))
            .map(kad_publish_entry_from_shared_entry)
            .collect(),
        0,
        |_| 0,
    );
    let old_set: HashSet<String> = old_source_scan
        .iter()
        .map(|entry| entry.file_hash.clone())
        .collect();
    assert_eq!(cheap, old_set);
    // Only the servable files (complete + servable partfile) are in the set.
    assert_eq!(
        cheap,
        HashSet::from([
            complete.file_hash.clone(),
            servable_partfile.file_hash.clone()
        ])
    );

    // The prune still runs on a gate-blocked tick from the cheap read alone: a
    // file unshared while blocked is forgotten (reads as source-due again),
    // while a still-shared file keeps its recent-publish clock.
    let now = Instant::now();
    let mut schedule = KadPublishSchedule::new();
    schedule.mark_source_published(&complete.file_hash, now, None);
    let gone = Ed2kHash::from_bytes([0x09; 16]).to_string();
    schedule.mark_source_published(&gone, now, None);
    schedule.retain_only(cheap.iter().map(String::as_str));
    assert!(!schedule.source_due(&complete.file_hash, now, None));
    assert!(schedule.source_due(&gone, now, None));
    // Sanity: after the source interval elapses the retained file is due again.
    let later = now + Duration::from_secs(6 * 3_600);
    assert!(schedule.source_due(&complete.file_hash, later, None));
}

#[test]
fn windowed_candidate_build_selects_identically_to_full_clone_build() {
    use crate::kad_publish_schedule::KadPublishSchedule;
    use std::collections::HashMap;
    use std::time::Duration;

    let now_instant = Instant::now();
    let now_unix_ms = 1_700_000_000_000i64;

    let mk = |hash: u8,
              name: &str,
              priority: &str,
              verified_complete: bool,
              complete_parts: Vec<bool>,
              comment: &str,
              rating: u8,
              all_time_uploaded_bytes: u64| Ed2kSharedEntry {
        file_hash: Ed2kHash::from_bytes([hash; 16]).to_string(),
        canonical_name: name.to_string(),
        file_size: 4096,
        verified_complete,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
        upload_priority: priority.to_string(),
        auto_upload_priority: false,
        comment: comment.to_string(),
        rating,
        all_time_uploaded_bytes,
        complete_parts,
        publish: Default::default(),
    };

    // Diverse catalog: completed files across priorities/upload stats (distinct
    // ranks), two annotated (notes) files, a servable partfile (source-only,
    // never keyword), an empty partfile + a hint (excluded from both lanes).
    let catalog = vec![
        mk(
            0x11,
            "alpha-release.iso",
            "release",
            true,
            Vec::new(),
            "note a",
            3,
            0,
        ),
        mk(
            0x22,
            "bravo-normal.iso",
            "normal",
            true,
            Vec::new(),
            "",
            0,
            5000,
        ),
        mk(
            0x33,
            "charlie-high.iso",
            "high",
            true,
            Vec::new(),
            "note c",
            5,
            100,
        ),
        mk(0x44, "delta-low.iso", "low", true, Vec::new(), "", 0, 0),
        mk(
            0x55,
            "echo-normal.iso",
            "normal",
            true,
            Vec::new(),
            "",
            0,
            0,
        ),
        mk(
            0x66,
            "foxtrot-part.iso",
            "normal",
            false,
            vec![true, false],
            "",
            0,
            0,
        ),
        mk(
            0x77,
            "golf-empty.iso",
            "normal",
            false,
            vec![false, false],
            "",
            0,
            0,
        ),
        Ed2kSharedEntry {
            compatibility_hint: true,
            ..mk(0x88, "hotel-hint.iso", "normal", true, Vec::new(), "", 0, 0)
        },
    ];

    let mut schedule = KadPublishSchedule::new();
    // Vary the SOURCE clock so the source ordering is non-trivial (age term).
    schedule.mark_source_published(
        &catalog[0].file_hash,
        now_instant - Duration::from_secs(3_600),
        None,
    );
    schedule.mark_source_published(
        &catalog[2].file_hash,
        now_instant - Duration::from_secs(10 * 3_600),
        None,
    );
    // NOTES clocks for the two annotated files: 0x11 recent (not due), 0x33
    // stale (due) -> the notes lane must pick 0x33 in both builds.
    schedule.mark_notes_published(
        &catalog[0].file_hash,
        now_instant - Duration::from_secs(3_600),
    );
    schedule.mark_notes_published(
        &catalog[2].file_hash,
        now_instant - Duration::from_secs(48 * 3_600),
    );

    let source_clock =
        |file_hash: &str| schedule.source_last_publish_unix_ms(file_hash, now_instant, now_unix_ms);

    // OLD reference: full clone + rank + sort of BOTH lanes (the pre-OPP-2 path).
    let old_source_full = kad_publishable_shared_file_entries(
        catalog
            .iter()
            .filter(|e| kad_source_publish_eligible(e))
            .map(kad_publish_entry_from_shared_entry)
            .collect(),
        now_unix_ms,
        source_clock,
    );
    let old_keyword_files = kad_publishable_shared_file_entries(
        catalog
            .iter()
            .filter(|e| kad_keyword_publish_eligible(e))
            .map(kad_publish_entry_from_shared_entry)
            .collect(),
        now_unix_ms,
        |_| 0,
    );
    let old_keyword_index: HashMap<String, usize> = old_keyword_files
        .iter()
        .enumerate()
        .map(|(i, e)| (e.file_hash.clone(), i))
        .collect();
    let old_keyword_candidates = old_keyword_files
        .iter()
        .map(|entry| KadKeywordPublishCandidate {
            file_hash: entry.file_hash.clone(),
            canonical_name: entry.canonical_name.clone(),
            file_size: entry.file_size,
            aich_root: entry.aich_root.clone(),
        })
        .collect::<Vec<_>>();

    let n = old_source_full.len();
    assert_eq!(
        n, 6,
        "5 completed + 1 servable partfile are source-eligible"
    );
    let scan_budget = 3usize;
    assert!(
        scan_budget < n,
        "budget must be a strict subset to exercise wrap"
    );

    // Walk more than a full rotation, advancing the cursor each tick so the
    // window wraps and every ranked position is materialized at some point.
    // NEW (windowed borrow-rank-clone) must equal OLD (full clone) every tick.
    for _ in 0..(2 * n + 1) {
        let start = schedule.cursor(n);
        let window_len = n.min(scan_budget);
        let old_window: Vec<_> = (0..window_len)
            .map(|off| old_source_full[(start + off) % n].clone())
            .collect();
        let old_best_notes = select_best_notes_publish_candidate(
            &old_source_full,
            &schedule,
            now_instant,
            now_unix_ms,
        );

        let cand = compute_kad_publish_candidates(
            &catalog,
            &schedule,
            now_instant,
            now_unix_ms,
            scan_budget,
        );

        assert_eq!(cand.source_item_count, n);
        assert_eq!(cand.source_cursor_start, start);
        assert_eq!(
            cand.source_scan, old_window,
            "window differs at cursor {start}"
        );
        assert_eq!(cand.best_notes_hash, old_best_notes);
        assert_eq!(
            cand.best_notes_hash.as_deref(),
            Some(catalog[2].file_hash.as_str())
        );
        assert_eq!(cand.keyword_files, old_keyword_candidates);
        assert_eq!(cand.keyword_index, old_keyword_index);

        schedule.advance_cursor(start, window_len, n);
    }
}

#[test]
fn comment_edit_marks_notes_dirty_but_priority_only_edit_does_not() {
    // A comment change edits the notes-relevant fields -> notes clock resets.
    assert!(shared_file_notes_changed("old", 3, Some(("new", 3))));
    // A rating change is also a notes change.
    assert!(shared_file_notes_changed("same", 3, Some(("same", 5))));
    // Re-submitting identical comment/rating is NOT a change.
    assert!(!shared_file_notes_changed("same", 3, Some(("same", 3))));
    // A priority-only PATCH carries no comment/rating and must not reset notes.
    assert!(!shared_file_notes_changed("same", 3, None));
}

#[test]
fn only_offer_relevant_changes_queue_the_ed2k_reoffer() {
    // Publish-G3: a metadata PATCH (priority/comment/rating) changes neither
    // the offered SET nor a file's offer content, so it passes both flags
    // `false` and must NOT queue the rate-limited shared-catalog re-offer.
    assert!(!shared_file_change_requires_ed2k_reoffer(false, false));
    // A genuinely offer-relevant change (share/unshare, or completion) does.
    assert!(shared_file_change_requires_ed2k_reoffer(true, false));
    assert!(shared_file_change_requires_ed2k_reoffer(false, true));
}

#[test]
fn draining_notes_dirty_queue_resets_the_notes_clock() {
    // The edit path enqueues the file hash; the publish loop drains it and
    // resets the in-memory notes clock so the file is notes-due next tick.
    let hash = Ed2kHash::from_bytes([0x44; 16]).to_string();
    let mut schedule = kad_publish_schedule::KadPublishSchedule::new();
    let now = Instant::now();
    schedule.mark_notes_published(&hash, now);
    assert!(!schedule.notes_due(&hash, now));

    let dirty: Arc<std::sync::Mutex<HashSet<String>>> =
        Arc::new(std::sync::Mutex::new(HashSet::new()));
    dirty.lock().unwrap().insert(hash.clone());

    drain_kad_notes_dirty(&dirty, &mut schedule);

    assert!(schedule.notes_due(&hash, now));
    assert!(dirty.lock().unwrap().is_empty());
}

#[test]
fn ed2k_file_type_search_term_matches_oracle_families() {
    assert_eq!(
        ed2k_file_type_search_term("ubuntu-linux-oracle-sample.iso"),
        Some("Pro")
    );
    assert_eq!(ed2k_file_type_search_term("album.flac"), Some("Audio"));
    assert_eq!(ed2k_file_type_search_term("movie.mkv"), Some("Video"));
    assert_eq!(ed2k_file_type_search_term("scan.png"), Some("Image"));
    assert_eq!(ed2k_file_type_search_term("manual.pdf"), Some("Doc"));
    assert_eq!(
        ed2k_file_type_search_term("bundle.emulecollection"),
        Some("EmuleCollection")
    );
    assert_eq!(ed2k_file_type_search_term("README"), None);
}

#[test]
fn passive_replay_family_preference_follows_deepest_queue_with_stable_tie_breaks() {
    assert_eq!(
        preferred_passive_replay_families(SnoopQueueFamilyCounts {
            keyword: 1,
            source: 4,
            notes: 2,
        }),
        [
            PassiveReplayFamily::Source,
            PassiveReplayFamily::Notes,
            PassiveReplayFamily::Keyword,
        ]
    );
    assert_eq!(
        preferred_passive_replay_families(SnoopQueueFamilyCounts {
            keyword: 2,
            source: 2,
            notes: 2,
        }),
        [
            PassiveReplayFamily::Keyword,
            PassiveReplayFamily::Source,
            PassiveReplayFamily::Notes,
        ]
    );
}

#[tokio::test]
async fn passive_keyword_result_indexes_searchable_file_metadata() {
    let index = Arc::new(Mutex::new(FileIndex::in_memory().unwrap()));
    index_passive_keyword_result(
        &index,
        &KadSearchResult {
            hash: Ed2kHash::from_bytes([0x31; 16]),
            names: vec!["Passive Replay Result.iso".to_string(), "   ".to_string()],
            size: Some(4096),
            source_count: Some(7),
            tags: vec![],
        },
    )
    .await;

    let results = index.lock().await.search("passive replay", 10).unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ed2k_hash, "31313131313131313131313131313131");
    assert_eq!(results[0].size_bytes, 4096);
    assert_eq!(results[0].availability_score, 7);
}

#[tokio::test]
async fn passive_source_results_are_remembered_for_existing_transfer() {
    let transfer_root = unique_runtime_dir("emulebb-core-passive-source-memory");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&transfer_root).unwrap());
    let file_hash = Ed2kHash::from_bytes([0x41; 16]);
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "passive-source-target.bin".to_string(),
            4096,
        ))
        .await
        .unwrap();

    remember_passive_source_results(
        &transfer_runtime,
        &[SourceResult {
            file_hash,
            source_id: Ed2kHash::from_bytes([0x52; 16]),
            ip: Ipv4Addr::new(198, 51, 100, 22),
            tcp_port: 4662,
            udp_port: 4672,
            obfuscation_options: Some(0x03),
            source_type: 1,
            buddy_id: None,
            buddy_ip: None,
            buddy_port: 0,
        }],
    )
    .await;

    let manifest = transfer_runtime
        .manifest(&file_hash.to_string())
        .await
        .unwrap();

    assert_eq!(manifest.sources.len(), 1);
    assert_eq!(manifest.sources[0].ip, "198.51.100.22");
    assert_eq!(manifest.sources[0].tcp_port, 4662);
    assert_eq!(
        manifest.sources[0].user_hash.as_deref(),
        Some("52525252525252525252525252525252")
    );
}

#[tokio::test]
async fn passive_note_results_update_empty_existing_transfer_metadata() {
    let transfer_root = unique_runtime_dir("emulebb-core-passive-note-memory");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&transfer_root).unwrap());
    let file_hash = Ed2kHash::from_bytes([0x42; 16]);
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "passive-note-target.bin".to_string(),
            4096,
        ))
        .await
        .unwrap();

    remember_passive_note_results(
        &transfer_runtime,
        &[KadNoteResult {
            file_hash,
            source_id: Ed2kHash::from_bytes([0x53; 16]),
            rating: Some(4),
            comment: Some("clean release".to_string()),
            source_tags: vec![],
        }],
    )
    .await;

    let manifest = transfer_runtime
        .manifest(&file_hash.to_string())
        .await
        .unwrap();

    assert_eq!(manifest.comment, "clean release");
    assert_eq!(manifest.rating, 4);
}

#[tokio::test]
async fn passive_note_results_do_not_replace_local_transfer_metadata() {
    let transfer_root = unique_runtime_dir("emulebb-core-passive-note-preserve");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&transfer_root).unwrap());
    let file_hash = Ed2kHash::from_bytes([0x43; 16]);
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "passive-note-preserve.bin".to_string(),
            4096,
        ))
        .await
        .unwrap();
    transfer_runtime
        .update_shared_file_metadata(&file_hash.to_string(), None, Some(("local note", 2)))
        .await
        .unwrap();

    remember_passive_note_results(
        &transfer_runtime,
        &[KadNoteResult {
            file_hash,
            source_id: Ed2kHash::from_bytes([0x54; 16]),
            rating: Some(5),
            comment: Some("remote note".to_string()),
            source_tags: vec![],
        }],
    )
    .await;

    let manifest = transfer_runtime
        .manifest(&file_hash.to_string())
        .await
        .unwrap();

    assert_eq!(manifest.comment, "local note");
    assert_eq!(manifest.rating, 2);
}

#[test]
fn split_stock_search_responses_keeps_pages_under_fragment_limit() {
    let sender_id = NodeId::from_bytes([1; 16]);
    let target = NodeId::from_bytes([2; 16]);
    let results = (0..12)
        .map(|index| SearchResultEntry {
            entry_id: Ed2kHash::from_bytes([index; 16]),
            tags: vec![Tag::filename(format!(
                "ubuntu-linux-parity-result-{index:02}-{}",
                "x".repeat(220)
            ))],
        })
        .collect::<Vec<_>>();
    let response = SearchRes {
        sender_id,
        target,
        results: results.clone(),
    };

    let pages = split_stock_search_responses(response, 1420);

    assert!(pages.len() > 1);
    assert_eq!(
        pages.iter().map(|page| page.results.len()).sum::<usize>(),
        results.len()
    );
    assert!(
        pages
            .iter()
            .all(|page| { KadPacket::SearchRes(page.clone()).encode().unwrap().len() <= 1420 })
    );
    assert_eq!(
        pages
            .into_iter()
            .flat_map(|page| page.results)
            .map(|result| result.entry_id)
            .collect::<Vec<_>>(),
        results
            .into_iter()
            .map(|result| result.entry_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn split_stock_search_responses_keeps_single_oversized_result_like_stock() {
    let sender_id = NodeId::from_bytes([1; 16]);
    let target = NodeId::from_bytes([2; 16]);
    let response = SearchRes {
        sender_id,
        target,
        results: vec![SearchResultEntry {
            entry_id: Ed2kHash::from_bytes([3; 16]),
            tags: vec![Tag::filename("x".repeat(1600))],
        }],
    };

    let pages = split_stock_search_responses(response, 1420);

    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].results.len(), 1);
    assert!(
        KadPacket::SearchRes(pages[0].clone())
            .encode()
            .unwrap()
            .len()
            > 1420
    );
}

#[tokio::test]
async fn search_uses_local_index() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.index_file(IndexedFile {
        ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
        name: "Local.Indexed.File.iso".to_string(),
        size_bytes: 2048,
        content_type: "iso".to_string(),
        availability_score: 3,
    })
    .await
    .unwrap();

    let search = core
        .create_search(SearchCreate {
            query: "indexed file".to_string(),
            method: "automatic".to_string(),
            r#type: String::new(),
            ..Default::default()
        })
        .await
        .unwrap();
    // Local index results are present immediately while the search starts
    // "running"; it flips to "completed" once the background pass finishes.
    assert_eq!(search.id, "1");
    assert_eq!(search.status, "running");
    assert_eq!(search.results.len(), 1);
    let mut completed = search;
    for _ in 0..100 {
        if completed.status == "completed" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        completed = core.search(&completed.id).await.unwrap();
    }
    assert_eq!(completed.status, "completed");
    assert_eq!(completed.results.len(), 1);
}

// Operator directive 2026-07-06: a network search submitted while the
// backend is still connecting/absent must surface an honest "queued"
// status with a reason and wait for readiness — never complete instantly
// with local-only results — and identical queued queries are rejected
// explicitly instead of amassing wire traffic for later.
#[tokio::test]
async fn network_search_queues_with_honest_status_and_rejects_duplicates() {
    let transfer_root = unique_runtime_dir("emulebb-core-search-queue");
    let network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap();

    let request = SearchCreate {
        query: "queued query".to_string(),
        method: "server".to_string(),
        ..Default::default()
    };
    let search = core.create_search(request.clone()).await.unwrap();
    assert_eq!(search.status, "queued");
    assert_eq!(
        search.status_reason.as_deref(),
        Some("waiting-for-server-connection")
    );

    // No server session ever connects: the search stays honestly queued
    // (drain ticks run but the backend never becomes ready).
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let still_queued = core.search(&search.id).await.unwrap();
    assert_eq!(still_queued.status, "queued");

    // An identical queued query on the same lane is rejected explicitly.
    let error = core
        .create_search(request)
        .await
        .expect_err("duplicate queued query must be rejected");
    assert!(error.to_string().contains("already queued"));

    // A different query queues fine alongside it.
    let other = core
        .create_search(SearchCreate {
            query: "another queued query".to_string(),
            method: "server".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(other.status, "queued");
}

#[tokio::test]
async fn import_server_met_bytes_adds_servers() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    // version 0x0E + count 1 + (ip 45.82.80.155, port 5687, 0 tags)
    let mut met = vec![0x0Eu8];
    met.extend_from_slice(&1u32.to_le_bytes());
    met.extend_from_slice(&[45, 82, 80, 155]);
    met.extend_from_slice(&5687u16.to_le_bytes());
    met.extend_from_slice(&0u32.to_le_bytes());

    let added = core.import_server_met_bytes(&met).await.unwrap();
    assert_eq!(added, 1);
    let servers = core.servers().await;
    assert!(
        servers
            .iter()
            .any(|server| server.address == "45.82.80.155" && server.port == 5687)
    );
}

#[tokio::test]
async fn effective_ed2k_config_includes_runtime_servers() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let base = Ed2kConfig {
        server_endpoints: vec!["203.0.113.10:4661".to_string()],
        ..Ed2kConfig::default()
    };
    core.add_server(ServerCreate {
        address: "203.0.113.20".to_string(),
        port: 4661,
        name: None,
        priority: None,
        static_server: Some(false),
        connect: None,
    })
    .await
    .unwrap();

    let config = core.effective_ed2k_config(&base, None).await.unwrap();

    assert!(
        config
            .server_endpoints
            .iter()
            .any(|endpoint| endpoint == "203.0.113.10:4661")
    );
    assert!(
        config
            .server_entries
            .iter()
            .any(|entry| entry.host == "203.0.113.20" && entry.port == 4661)
    );
}

#[tokio::test]
async fn effective_ed2k_config_honors_reconnect_preference() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.update_preferences(PreferencesUpdate {
        reconnect: Some(false),
        ..PreferencesUpdate::default()
    })
    .await
    .unwrap();

    let config = core
        .effective_ed2k_config(&Ed2kConfig::default(), None)
        .await
        .unwrap();

    assert!(!config.reconnect_enabled);
}

#[tokio::test]
async fn explicit_server_connect_targets_running_server_loop() {
    let transfer_root = unique_runtime_dir("emulebb-core-target-running-server-loop");
    let mut network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.config.server_endpoints = vec![
        "203.0.113.10:4661".to_string(),
        "203.0.113.20:4661".to_string(),
    ];
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(network),
    )
    .unwrap();
    let (search_handle, _search_inbox) = new_ed2k_server_search_channel(1);
    let dht = DhtNode::new(DhtConfig {
        bind_addr: Some("0.0.0.0:0".parse().unwrap()),
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let dht_task = dht.start();
    let target_server_endpoint = Arc::new(RwLock::new(None));
    let server_reconnect_signal = Arc::new(tokio::sync::Notify::new());

    *core.ed2k_runtime.lock().await = Some(Ed2kRuntime {
        search_handle,
        server_state: Arc::new(RwLock::new(Ed2kServerState::default())),
        dht,
        kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
        nat: Arc::new(NatManager::default()),
        shutdown: Arc::clone(&shutdown),
        server_reconnect_signal: Arc::clone(&server_reconnect_signal),
        target_server_endpoint: Arc::clone(&target_server_endpoint),
        kad_firewall_recheck: None,
        tasks: vec![dht_task],
        download_tasks: Arc::clone(&core.ed2k_download_tasks),
    });

    let result = core.connect_ed2k_server("203.0.113.20:4661").await.unwrap();

    assert!(result.is_some());
    assert_eq!(
        target_server_endpoint.read().await.as_deref(),
        Some("203.0.113.20:4661")
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            server_reconnect_signal.notified()
        )
        .await
        .is_ok(),
        "retargeting a running server loop must signal reconnect"
    );
    shutdown.store(true, Ordering::SeqCst);
    let _ = core.disconnect_ed2k().await;
}

#[tokio::test]
async fn explicit_server_connect_to_live_endpoint_is_idempotent() {
    let transfer_root = unique_runtime_dir("emulebb-core-same-server-connect-noop");
    let mut network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.config.server_endpoints = vec!["203.0.113.20:4661".to_string()];
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(network),
    )
    .unwrap();
    let (search_handle, _search_inbox) = new_ed2k_server_search_channel(1);
    let dht = DhtNode::new(DhtConfig {
        bind_addr: Some("0.0.0.0:0".parse().unwrap()),
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let dht_task = dht.start();
    let target_server_endpoint = Arc::new(RwLock::new(None));
    let server_reconnect_signal = Arc::new(tokio::sync::Notify::new());
    let server_state = Arc::new(RwLock::new(Ed2kServerState {
        endpoint: Some("203.0.113.20:4661".parse().unwrap()),
        connected: true,
        ..Ed2kServerState::default()
    }));

    *core.ed2k_runtime.lock().await = Some(Ed2kRuntime {
        search_handle,
        server_state,
        dht,
        kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
        nat: Arc::new(NatManager::default()),
        shutdown: Arc::clone(&shutdown),
        server_reconnect_signal: Arc::clone(&server_reconnect_signal),
        target_server_endpoint: Arc::clone(&target_server_endpoint),
        kad_firewall_recheck: None,
        tasks: vec![dht_task],
        download_tasks: Arc::clone(&core.ed2k_download_tasks),
    });

    let result = core.connect_ed2k_server("203.0.113.20:4661").await.unwrap();

    assert!(result.is_some());
    assert_eq!(
        target_server_endpoint.read().await.as_deref(),
        Some("203.0.113.20:4661")
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            server_reconnect_signal.notified()
        )
        .await
        .is_err(),
        "same-endpoint connect must not drop a live server session"
    );
    shutdown.store(true, Ordering::SeqCst);
    let _ = core.disconnect_ed2k().await;
}

#[tokio::test]
async fn merge_discovered_servers_adds_new_dedups_existing() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.add_server(ServerCreate {
        address: "45.82.80.155".to_string(),
        port: 5687,
        name: None,
        priority: None,
        static_server: Some(true),
        connect: None,
    })
    .await
    .unwrap();

    core.merge_discovered_ed2k_servers(vec![
        (Ipv4Addr::new(45, 82, 80, 155), 5687), // duplicate of existing
        (Ipv4Addr::new(203, 0, 113, 9), 4661),  // new
        (Ipv4Addr::new(203, 0, 113, 9), 4661),  // duplicate within batch
    ])
    .await;

    let servers = core.servers().await;
    let lugd = servers
        .iter()
        .filter(|s| s.address == "45.82.80.155" && s.port == 5687)
        .count();
    assert_eq!(lugd, 1, "existing server is not duplicated");
    let new_server = servers
        .iter()
        .find(|s| s.address == "203.0.113.9" && s.port == 4661)
        .expect("discovered server added");
    assert_eq!(new_server.priority, "low");
    assert!(!new_server.static_server);
}

#[tokio::test]
async fn merge_discovered_servers_respects_add_servers_from_server_preference() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    // eMule GetAddServersFromServer default is on; turning it off must stop
    // OP_SERVERLIST auto-add.
    core.update_preferences(PreferencesUpdate {
        add_servers_from_server: Some(false),
        ..PreferencesUpdate::default()
    })
    .await
    .unwrap();
    core.merge_discovered_ed2k_servers(vec![(Ipv4Addr::new(203, 0, 113, 9), 4661)])
        .await;
    assert!(
        !core
            .servers()
            .await
            .iter()
            .any(|s| s.address == "203.0.113.9" && s.port == 4661),
        "auto-add disabled: a discovered server must not be added"
    );
}

#[tokio::test]
async fn connect_failed_drops_non_static_dead_server_at_threshold() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.add_server(ServerCreate {
        address: "203.0.113.5".to_string(),
        port: 4661,
        name: None,
        priority: None,
        static_server: Some(false),
        connect: None,
    })
    .await
    .unwrap();
    let endpoint = "203.0.113.5:4661";

    // Default dead_server_retries = 1: first failure drops the server.
    core.note_ed2k_server_connect_failed(endpoint, 1).await;
    assert!(
        core.server(endpoint).await.is_none(),
        "non-static dead server is dropped at the threshold"
    );
}

#[tokio::test]
async fn connect_failed_never_drops_static_server() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.add_server(ServerCreate {
        address: "203.0.113.6".to_string(),
        port: 4661,
        name: None,
        priority: None,
        static_server: Some(true),
        connect: None,
    })
    .await
    .unwrap();
    let endpoint = "203.0.113.6:4661";

    // Even far past the threshold, a static server is kept (eMule keeps
    // static servers); the fail-count is still tracked.
    for _ in 0..5 {
        core.note_ed2k_server_connect_failed(endpoint, 1).await;
    }
    let server = core.server(endpoint).await.expect("static server kept");
    assert!(server.failed_count >= 1);
}

#[tokio::test]
async fn connect_succeeded_clears_fail_count() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.add_server(ServerCreate {
        address: "203.0.113.7".to_string(),
        port: 4661,
        name: None,
        priority: None,
        static_server: Some(false),
        connect: None,
    })
    .await
    .unwrap();
    let endpoint = "203.0.113.7:4661";

    // With a higher threshold, accumulate failures, then a success clears them.
    core.note_ed2k_server_connect_failed(endpoint, 3).await;
    core.note_ed2k_server_connect_failed(endpoint, 3).await;
    assert_eq!(core.server(endpoint).await.unwrap().failed_count, 2);
    core.note_ed2k_server_connect_succeeded(endpoint).await;
    assert_eq!(core.server(endpoint).await.unwrap().failed_count, 0);
    // The cleared count means it now takes the full threshold again to drop.
    core.note_ed2k_server_connect_failed(endpoint, 3).await;
    assert!(core.server(endpoint).await.is_some());
}

#[test]
fn exact_ed2k_hash_query_token_extracts_hash_only_queries() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    assert_eq!(
        exact_ed2k_hash_query_token(&format!("ed2k::{exact_hash}")),
        Some(exact_hash.clone())
    );
    assert_eq!(
        exact_ed2k_hash_query_token(&exact_hash.to_ascii_uppercase()),
        Some(exact_hash)
    );
    assert_eq!(exact_ed2k_hash_query_token("ed2k::torino train"), None);
}

#[test]
fn significant_words_ignore_short_tokens() {
    assert_eq!(
        significant_keyword_words("A torino x train"),
        vec!["torino".to_string(), "train".to_string()]
    );
}

#[test]
fn significant_words_keep_in_word_symbols_matching_getwords_separators() {
    // `INV_KAD_KEYWORD_CHARS` does not include `&`, `+`, `'` or `#`, so the
    // oracle keeps them inside the word instead of over-splitting.
    assert_eq!(
        significant_keyword_words("AT&T Wireless"),
        vec!["at&t".to_string(), "wireless".to_string()]
    );
    assert_eq!(
        significant_keyword_words("C++ Tutorial"),
        vec!["c++".to_string(), "tutorial".to_string()]
    );
    assert_eq!(
        significant_keyword_words("rock'n'roll live"),
        vec!["rock'n'roll".to_string(), "live".to_string()]
    );
}

#[test]
fn significant_words_drop_trailing_three_char_extension() {
    // GetWords pops a trailing 3-char/3-byte token (SearchManager.cpp:284-286)
    // when more than one word survived; the drop applies to publish keywords
    // and to search queries alike because both share this tokenizer.
    assert_eq!(
        significant_keyword_words("ubuntu.iso"),
        vec!["ubuntu".to_string()]
    );
    assert_eq!(
        significant_keyword_words("AT&T.avi"),
        vec!["at&t".to_string()]
    );
    assert_eq!(
        significant_keyword_words("C++ Tutorial.pdf"),
        vec!["c++".to_string(), "tutorial".to_string()]
    );
    // A search query tokenizes identically: the trailing extension is dropped.
    assert_eq!(
        significant_keyword_words("ubuntu iso"),
        vec!["ubuntu".to_string()]
    );
    // The extension drop only fires when more than one word survives, so a
    // lone 3-char word is kept ("a.b.mp3" leaves only "mp3").
    assert_eq!(
        significant_keyword_words("a.b.mp3"),
        vec!["mp3".to_string()]
    );
    // A trailing token longer than 3 chars is not an extension: "#1" is under
    // the 3-byte minimum and drops out, "flac" is kept.
    assert_eq!(
        significant_keyword_words("R&B #1.flac"),
        vec!["r&b".to_string(), "flac".to_string()]
    );
}

#[test]
fn kad_keyword_lowercase_matches_oracle_frozen_table() {
    // ASCII A-Z lower-cases exactly as before (the common case).
    assert_eq!(
        kad_keyword_lowercase("Ubuntu ISO"),
        "ubuntu iso".to_string()
    );
    // Latin-1 / Greek / Cyrillic uppercase letters that the oracle's
    // `LANG_ENGLISH` map lowers are still lowered (À->à, Β->β, А->а).
    assert_eq!(kad_keyword_lowercase("À"), "à".to_string());
    assert_eq!(kad_keyword_lowercase("Β"), "β".to_string());
    assert_eq!(kad_keyword_lowercase("А"), "а".to_string());
    // Code points the oracle's frozen table leaves UNCHANGED but Rust's
    // `str::to_lowercase()` would alter: U+0130 (İ, which Rust expands to two
    // chars), U+1E9E (ẞ, Rust -> ß), the U+212A Kelvin sign (Rust -> k) and
    // the U+00B5 micro sign (Rust -> μ). Keeping them verbatim is what makes
    // the md4 keyword hash match eMule for these words.
    assert_eq!(kad_keyword_lowercase("\u{0130}"), "\u{0130}".to_string());
    assert_eq!(kad_keyword_lowercase("\u{1E9E}"), "\u{1E9E}".to_string());
    assert_eq!(kad_keyword_lowercase("\u{212A}"), "\u{212A}".to_string());
    assert_eq!(kad_keyword_lowercase("\u{00B5}"), "\u{00B5}".to_string());
    // Already-lower and astral (identity-mapped surrogate) code points pass
    // through untouched.
    assert_eq!(kad_keyword_lowercase("café"), "café".to_string());
    assert_eq!(kad_keyword_lowercase("\u{1F600}"), "\u{1F600}".to_string());
}

#[test]
fn significant_words_lowercase_uses_oracle_table_for_non_ascii() {
    // The tokenizer lower-cases through the oracle table: "Café.İşi" keeps
    // U+0130 verbatim (Rust's full lower-casing would expand it) so the
    // produced keyword — and thus its md4 target — matches eMule's.
    assert_eq!(
        significant_keyword_words("Café İyi"),
        vec!["café".to_string(), "\u{0130}yi".to_string()]
    );
}

#[test]
fn significant_words_dedup_keeps_last_occurrence() {
    // GetWords de-duplicates with `remove` + `push_back` (SearchManager.cpp:
    // 277-278), moving a repeated word to the END of the list. "ubuntu"
    // repeats, so it lands after "python" rather than staying at the front.
    assert_eq!(
        significant_keyword_words_unique("Ubuntu Python ubuntu programming Apache Camel"),
        vec![
            "python".to_string(),
            "ubuntu".to_string(),
            "programming".to_string(),
            "apache".to_string(),
            "camel".to_string(),
        ]
    );
}

#[test]
fn significant_words_repeated_first_token_shifts_primary_keyword() {
    // When the first token repeats, the oracle's remove+push_back moves it to
    // the end, so the primary keyword (GetWords `front()`, hashed by
    // `keyword_target`) becomes the next distinct word. "love song love"
    // dedups to ["song", "love"], not ["love", "song"].
    assert_eq!(
        significant_keyword_words("love song love"),
        vec!["song".to_string(), "love".to_string()]
    );
    // The Kad keyword target therefore hashes "song", not "love".
    assert_eq!(keyword_target("love song love"), keyword_target("song"));
    assert_ne!(keyword_target("love song love"), keyword_target("love"));
}

#[test]
fn keyword_publish_entries_batch_matching_files_up_to_stock_limit() {
    let mut shared_files = (0..160)
        .map(|index| KadKeywordPublishCandidate {
            file_hash: Ed2kHash::from_bytes([index as u8; 16]).to_string(),
            canonical_name: format!("Ubuntu Python Sample {index}.iso"),
            file_size: 1000 + index,
            aich_root: None,
        })
        .collect::<Vec<_>>();
    shared_files.push(KadKeywordPublishCandidate {
        file_hash: Ed2kHash::from_bytes([0xFE; 16]).to_string(),
        canonical_name: "Apache Camel Sample.iso".to_string(),
        file_size: 1,
        aich_root: None,
    });

    let entries = kad_keyword_publish_entries_for_keyword(
        &shared_files,
        "ubuntu",
        KAD_KEYWORD_PUBLISH_FILE_LIMIT,
        0,
    );

    assert_eq!(entries.len(), KAD_KEYWORD_PUBLISH_FILE_LIMIT);
    assert_eq!(entries[0].1.file_hash, Ed2kHash::from_bytes([0_u8; 16]));
    assert_eq!(entries[149].1.file_hash, Ed2kHash::from_bytes([149_u8; 16]));
    assert!(
        entries
            .iter()
            .all(|(_, entry)| entry.tags.iter().any(|tag| tag == &Tag::sources(1)))
    );
}

#[test]
fn keyword_publish_entries_start_at_triggering_file_and_wrap() {
    let shared_files = (0..160)
        .map(|index| KadKeywordPublishCandidate {
            file_hash: Ed2kHash::from_bytes([index as u8; 16]).to_string(),
            canonical_name: format!("Ubuntu Python Sample {index}.iso"),
            file_size: 1000 + index,
            aich_root: None,
        })
        .collect::<Vec<_>>();

    let entries = kad_keyword_publish_entries_for_keyword(
        &shared_files,
        "ubuntu",
        KAD_KEYWORD_PUBLISH_FILE_LIMIT,
        155,
    );

    assert_eq!(entries.len(), KAD_KEYWORD_PUBLISH_FILE_LIMIT);
    assert_eq!(entries[0].1.file_hash, Ed2kHash::from_bytes([155_u8; 16]));
    assert_eq!(entries[4].1.file_hash, Ed2kHash::from_bytes([159_u8; 16]));
    assert_eq!(entries[5].1.file_hash, Ed2kHash::from_bytes([0_u8; 16]));
    assert_eq!(entries[149].1.file_hash, Ed2kHash::from_bytes([144_u8; 16]));
}

#[test]
fn keyword_publish_source_count_is_self_inclusive() {
    // Oracle `CKnownFile::m_nCompleteSourcesCount` counts ourselves as one
    // complete source and adds any other known complete sources on top
    // (KnownFile.cpp:126,313). A file with no other known complete sources
    // publishes SOURCES = 1; N others publish SOURCES = N + 1.
    assert_eq!(keyword_publish_complete_source_count(0), 1);
    assert_eq!(keyword_publish_complete_source_count(4), 5);
}

#[test]
fn keyword_publish_entry_publishes_self_inclusive_source_count() {
    // rust tracks no other complete sources for shared files, so the built
    // keyword entry carries the self-only TAG_SOURCES value of 1 rather than
    // a hardcoded constant divorced from the oracle semantics.
    let shared_files = vec![KadKeywordPublishCandidate {
        file_hash: Ed2kHash::from_bytes([7_u8; 16]).to_string(),
        canonical_name: "Ubuntu Sample.iso".to_string(),
        file_size: 4096,
        aich_root: None,
    }];

    let entries = kad_keyword_publish_entries_for_keyword(
        &shared_files,
        "ubuntu",
        KAD_KEYWORD_PUBLISH_FILE_LIMIT,
        0,
    );

    assert_eq!(entries.len(), 1);
    assert!(entries[0].1.tags.iter().any(|tag| tag == &Tag::sources(1)));
}

#[test]
fn kad_shared_publish_active_counts_follow_mfc_store_caps() {
    let mut counts = KadSharedPublishActiveCounts::default();
    assert_eq!(
        kad_shared_publish_kind_cap(KadSharedPublishKind::Keyword),
        KAD_KEYWORD_PUBLISH_IN_FLIGHT_CAP
    );
    assert_eq!(
        kad_shared_publish_kind_cap(KadSharedPublishKind::Source),
        KAD_SOURCE_PUBLISH_IN_FLIGHT_CAP
    );
    assert_eq!(
        kad_shared_publish_kind_cap(KadSharedPublishKind::Notes),
        KAD_NOTES_PUBLISH_IN_FLIGHT_CAP
    );

    for _ in 0..KAD_KEYWORD_PUBLISH_IN_FLIGHT_CAP {
        assert!(counts.can_start(KadSharedPublishKind::Keyword));
        counts.started(KadSharedPublishKind::Keyword);
    }
    assert!(!counts.can_start(KadSharedPublishKind::Keyword));
    counts.finished(KadSharedPublishKind::Keyword);
    assert!(counts.can_start(KadSharedPublishKind::Keyword));

    counts.started(KadSharedPublishKind::Notes);
    assert!(!counts.can_start(KadSharedPublishKind::Notes));
    counts.finished(KadSharedPublishKind::Notes);
    assert!(counts.can_start(KadSharedPublishKind::Notes));
}

#[test]
fn kad_shared_publish_budget_reserves_search_capacity() {
    assert_eq!(kad_shared_file_publish_in_flight_budget_for(1), 1);
    assert_eq!(kad_shared_file_publish_in_flight_budget_for(2), 1);
    assert_eq!(kad_shared_file_publish_in_flight_budget_for(5), 4);
    assert_eq!(
        kad_shared_file_publish_in_flight_budget_for(KAD_SHARED_FILE_PUBLISH_DHT_SEARCH_CAP),
        KAD_SHARED_FILE_PUBLISH_KIND_CAP_TOTAL
    );
}

#[test]
fn kad_rpc_class_budgets_give_publish_traversals_room_to_converge() {
    let budgets = kad_rpc_class_budgets();
    assert_eq!(
        budgets.publish_max_outbound_pps,
        KAD_PUBLISH_MAX_OUTBOUND_PPS
    );
    assert!(
        budgets.publish_max_outbound_pps > RpcClassBudgetConfig::default().publish_max_outbound_pps
    );
}

#[test]
fn kad_outbound_publish_schedule_advances_when_store_search_starts() {
    let store = MetadataStore::in_memory().unwrap();
    let mut schedule = kad_publish_schedule::KadPublishSchedule::new();
    let started_at = Instant::now();
    let published_at_ms = 12_345;
    let keyword = "ubuntu";
    let keyword_hashes = vec![
        Ed2kHash::from_bytes([0x11; 16]).to_string(),
        Ed2kHash::from_bytes([0x22; 16]).to_string(),
    ];
    let source_hash = Ed2kHash::from_bytes([0x33; 16]).to_string();
    let notes_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    mark_kad_keyword_publish_started(
        &store,
        &mut schedule,
        &keyword_hashes,
        keyword,
        started_at,
        published_at_ms,
    );
    mark_kad_file_publish_started(
        &store,
        &mut schedule,
        &source_hash,
        MetadataKadOutboundPublishKind::Source,
        started_at,
        published_at_ms,
        None,
    );
    mark_kad_file_publish_started(
        &store,
        &mut schedule,
        &notes_hash,
        MetadataKadOutboundPublishKind::Notes,
        started_at,
        published_at_ms,
        None,
    );

    for file_hash in &keyword_hashes {
        assert!(!schedule.keyword_due(file_hash, keyword, started_at));
    }
    assert!(!schedule.source_due(&source_hash, started_at, None));
    assert!(!schedule.notes_due(&notes_hash, started_at));

    let persisted = store.load_kad_outbound_publish_schedule().unwrap();
    assert_eq!(persisted.publishes.len(), 4);
    assert!(persisted.publishes.iter().any(|publish| {
        publish.file_hash == keyword_hashes[0]
            && publish.publish_kind == MetadataKadOutboundPublishKind::Keyword
            && publish.keyword == keyword
            && publish.published_at_ms == published_at_ms
    }));
    assert!(persisted.publishes.iter().any(|publish| {
        publish.file_hash == source_hash
            && publish.publish_kind == MetadataKadOutboundPublishKind::Source
            && publish.keyword.is_empty()
            && publish.published_at_ms == published_at_ms
    }));
    assert!(persisted.publishes.iter().any(|publish| {
        publish.file_hash == notes_hash
            && publish.publish_kind == MetadataKadOutboundPublishKind::Notes
            && publish.keyword.is_empty()
            && publish.published_at_ms == published_at_ms
    }));
}

#[test]
fn busy_rollback_makes_publish_due_again_while_timeout_keeps_it_advanced() {
    // Publish-G2: a `Busy` outcome (store search could not be created, no
    // packet sent -> oracle PrepareLookup==NULL) rolls the admission-advanced
    // clock back to due so the file retries next tick; a `TimedOut`/`Failed`
    // outcome does NOT roll back (the search WAS created and sent), so that
    // file keeps waiting its interval.
    let store = MetadataStore::in_memory().unwrap();
    let mut schedule = kad_publish_schedule::KadPublishSchedule::new();
    let started_at = Instant::now();
    let published_at_ms = 42;
    let keyword = "ubuntu";
    let busy_keyword_hash = Ed2kHash::from_bytes([0x11; 16]).to_string();
    let busy_source_hash = Ed2kHash::from_bytes([0x22; 16]).to_string();
    let busy_notes_hash = Ed2kHash::from_bytes([0x33; 16]).to_string();
    let timeout_source_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    // Admission advances every clock (keyword/source/notes).
    mark_kad_keyword_publish_started(
        &store,
        &mut schedule,
        std::slice::from_ref(&busy_keyword_hash),
        keyword,
        started_at,
        published_at_ms,
    );
    for (hash, kind) in [
        (&busy_source_hash, MetadataKadOutboundPublishKind::Source),
        (&timeout_source_hash, MetadataKadOutboundPublishKind::Source),
        (&busy_notes_hash, MetadataKadOutboundPublishKind::Notes),
    ] {
        mark_kad_file_publish_started(
            &store,
            &mut schedule,
            hash,
            kind,
            started_at,
            published_at_ms,
            None,
        );
    }
    assert!(!schedule.keyword_due(&busy_keyword_hash, keyword, started_at));
    assert!(!schedule.source_due(&busy_source_hash, started_at, None));
    assert!(!schedule.source_due(&timeout_source_hash, started_at, None));
    assert!(!schedule.notes_due(&busy_notes_hash, started_at));

    // Busy rollback on the keyword/source/notes stores that never sent a packet.
    rollback_kad_publish_admission_on_busy(
        &store,
        &mut schedule,
        KadSharedPublishKind::Keyword,
        std::slice::from_ref(&busy_keyword_hash),
        Some(keyword),
    );
    rollback_kad_publish_admission_on_busy(
        &store,
        &mut schedule,
        KadSharedPublishKind::Source,
        std::slice::from_ref(&busy_source_hash),
        None,
    );
    rollback_kad_publish_admission_on_busy(
        &store,
        &mut schedule,
        KadSharedPublishKind::Notes,
        std::slice::from_ref(&busy_notes_hash),
        None,
    );

    // Busy targets are due again immediately (re-selectable next tick).
    assert!(schedule.keyword_due(&busy_keyword_hash, keyword, started_at));
    assert!(schedule.source_due(&busy_source_hash, started_at, None));
    assert!(schedule.notes_due(&busy_notes_hash, started_at));
    // The timed-out source (created + sent, no rollback) keeps its clock.
    assert!(!schedule.source_due(&timeout_source_hash, started_at, None));

    // Persistence mirrors the in-memory rollback: busy rows are cleared, the
    // timed-out source row survives.
    let persisted = store.load_kad_outbound_publish_schedule().unwrap();
    assert_eq!(persisted.publishes.len(), 1);
    assert_eq!(persisted.publishes[0].file_hash, timeout_source_hash);
    assert_eq!(
        persisted.publishes[0].publish_kind,
        MetadataKadOutboundPublishKind::Source
    );
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
    let mut config = Ed2kConfig {
        server_endpoints: vec![
            "192.0.2.1:4661".to_string(),
            "192.0.2.2:4661".to_string(),
            "192.0.2.3:4661".to_string(),
            "192.0.2.4:4661".to_string(),
            "192.0.2.5:4661".to_string(),
        ],
        keyword_server_attempt_budget: 2,
        exact_hash_keyword_server_attempt_budget: 4,
        ..Ed2kConfig::default()
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

async fn completed_ed2k_transfer_runtime(
    test_name: &str,
) -> (
    Arc<Ed2kTransferRuntime>,
    Arc<Ed2kSecureIdent>,
    String,
    String,
    u64,
) {
    let runtime_dir = unique_runtime_dir(test_name);
    let payload_path = runtime_dir.join("fixture.bin");
    let payload = b"completed direct download scheduler payload".repeat(64);
    std::fs::write(&payload_path, &payload).unwrap();
    let transfer_runtime =
        Arc::new(Ed2kTransferRuntime::load_or_create(&runtime_dir.join("transfers")).unwrap());
    let summary = transfer_runtime
        .ingest_local_file(&payload_path, "fixture.bin")
        .await
        .unwrap();
    let secure_ident =
        Arc::new(Ed2kSecureIdent::load_or_create(&runtime_dir.join("secure-ident.der")).unwrap());
    (
        transfer_runtime,
        secure_ident,
        summary.file_hash,
        summary.canonical_name,
        summary.file_size,
    )
}

fn direct_test_source(file_hash: Ed2kHash, ip: Ipv4Addr, tcp_port: u16) -> Ed2kFoundSource {
    Ed2kFoundSource {
        file_hash,
        ip,
        tcp_port,
        client_id: u32::from_be_bytes(ip.octets()),
        low_id: false,
        obfuscated: false,
        obfuscation_options: None,
        user_hash: None,
        source_server: None,
        buddy_id: None,
        buddy_endpoint: None,
        source_udp_port: None,
    }
}

fn direct_download_options(
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    secure_ident: Arc<Ed2kSecureIdent>,
    file_hash_hex: String,
    file_name: String,
    file_size: u64,
    sources: Vec<Ed2kFoundSource>,
) -> DirectDownloadOptions {
    DirectDownloadOptions {
        bind_ip: Ipv4Addr::new(192, 0, 2, 10),
        hello_identity: Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        secure_ident,
        transfer_runtime,
        file_hash_hex,
        file_name,
        file_size,
        sources,
        connect_timeout: Duration::from_secs(1),
        max_parallel_download_peers: 1,
    }
}

#[tokio::test]
async fn direct_download_scheduler_releases_all_slots_on_worker_panic() {
    // A panicking download worker must not leak the connection-budget slots
    // held by the other in-flight workers: the error path drains and releases
    // every remaining slot before returning (FIX B1).
    let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size) =
        completed_ed2k_transfer_runtime("emulebb-core-direct-download-panic").await;
    let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
    let mut options = direct_download_options(
        Arc::clone(&transfer_runtime),
        secure_ident,
        file_hash_hex,
        file_name,
        file_size,
        vec![
            direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001),
            direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 11), 41002),
            direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 12), 41003),
        ],
    );
    // Spawn all sources at once so several slots are in flight when one panics.
    options.max_parallel_download_peers = 3;

    let result = run_ed2k_direct_downloads(
        options,
        move |_bind_ip,
              _source,
              _hello_identity,
              _secure_ident,
              _transfer_runtime,
              _file_name,
              _file_size,
              _connect_timeout| async move {
            // Yield first so all three workers are spawned (and hold a slot)
            // before the panic unwinds, exercising the drain path.
            tokio::task::yield_now().await;
            panic!("simulated download worker panic");
        },
    )
    .await;

    assert!(result.is_err(), "a worker panic propagates as an error");

    // Every acquired connection-budget slot must have been released; if a
    // slot leaked, active_connections would be non-zero. Probe via a fresh
    // acquire and inspect the reported occupancy before the probe.
    let decision = transfer_runtime.try_acquire_source_connection_detailed();
    // active_connections counts AFTER this probe acquired one slot, so it must
    // be exactly 1 (the probe itself) with no leaked predecessors.
    assert_eq!(
        decision.active_connections, 1,
        "all worker slots were released after the panic (no budget leak)"
    );
    transfer_runtime.release_source_connection();
}

#[tokio::test]
async fn direct_download_scheduler_retries_other_peer_after_failure() {
    let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size) =
        completed_ed2k_transfer_runtime("emulebb-core-direct-download-retry").await;
    let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let outcome = run_ed2k_direct_downloads(
        direct_download_options(
            transfer_runtime,
            secure_ident,
            file_hash_hex,
            file_name,
            file_size,
            vec![
                direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001),
                direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 11), 41002),
            ],
        ),
        {
            let attempts = Arc::clone(&attempts);
            move |_bind_ip,
                  source,
                  _hello_identity,
                  _secure_ident,
                  _transfer_runtime,
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.lock().await.push(source.tcp_port);
                    if source.tcp_port == 41001 {
                        anyhow::bail!("simulated first peer failure");
                    }
                    Ok(Ed2kPeerDownloadOutcome::Completed)
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(outcome.completed);
    assert_eq!(outcome.accepted_incomplete_peers, 0);
    assert!(outcome.last_error.is_some());
    assert_eq!(*attempts.lock().await, vec![41001, 41002]);
}

#[tokio::test]
async fn direct_download_scheduler_retries_loopback_peer_after_connection_refused() {
    let runtime_dir = unique_runtime_dir("emulebb-core-loopback-refused-retry");
    let transfer_runtime =
        Arc::new(Ed2kTransferRuntime::load_or_create(&runtime_dir.join("transfers")).unwrap());
    let secure_ident =
        Arc::new(Ed2kSecureIdent::load_or_create(&runtime_dir.join("secure-ident.der")).unwrap());
    let payload = Arc::new(b"captured small file payload".repeat(32));
    let file_name = "captured.epub".to_string();
    let payload_path = runtime_dir.join("payload.bin");
    std::fs::write(&payload_path, payload.as_slice()).unwrap();
    let hash_runtime =
        Ed2kTransferRuntime::load_or_create(&runtime_dir.join("hash-transfers")).unwrap();
    let summary = hash_runtime
        .ingest_local_file(&payload_path, &file_name)
        .await
        .unwrap();
    let file_hash: Ed2kHash = summary.file_hash.parse().unwrap();
    let file_hash_hex = summary.file_hash;
    let file_size = summary.file_size;
    transfer_runtime
        .ensure_job(&new_transfer_job(file_hash, file_name.clone(), file_size))
        .await
        .unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let success_after_attempt = 3usize;
    let outcome = run_ed2k_direct_downloads(
        direct_download_options(
            transfer_runtime,
            secure_ident,
            file_hash_hex.clone(),
            file_name,
            file_size,
            vec![direct_test_source(file_hash, Ipv4Addr::LOCALHOST, 41001)],
        ),
        {
            let attempts = Arc::clone(&attempts);
            let payload = Arc::clone(&payload);
            let file_hash_hex = file_hash_hex.clone();
            move |_bind_ip,
                  source,
                  _hello_identity,
                  _secure_ident,
                  transfer_runtime,
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                let payload = Arc::clone(&payload);
                let file_hash_hex = file_hash_hex.clone();
                async move {
                    attempts.lock().await.push(source.tcp_port);
                    if attempts.lock().await.len() < success_after_attempt {
                        return Err(anyhow::Error::new(std::io::Error::from(
                            std::io::ErrorKind::ConnectionRefused,
                        )));
                    }
                    transfer_runtime
                        .store_md4_hashset(&file_hash_hex, Vec::new())
                        .await?;
                    transfer_runtime
                        .store_piece_data(&file_hash_hex, 0, payload.as_slice())
                        .await?;
                    Ok(Ed2kPeerDownloadOutcome::Completed)
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(outcome.completed);
    assert_eq!(outcome.accepted_incomplete_peers, 0);
    assert!(outcome.last_error.is_some());
    assert_eq!(*attempts.lock().await, vec![41001, 41001, 41001]);
}

#[tokio::test]
async fn direct_download_scheduler_tracks_accepted_incomplete_peer() {
    let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size) =
        completed_ed2k_transfer_runtime("emulebb-core-direct-download-incomplete").await;
    let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let outcome = run_ed2k_direct_downloads(
        direct_download_options(
            transfer_runtime,
            secure_ident,
            file_hash_hex,
            file_name,
            file_size,
            vec![
                direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001),
                direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 11), 41002),
            ],
        ),
        {
            let attempts = Arc::clone(&attempts);
            move |_bind_ip,
                  source,
                  _hello_identity,
                  _secure_ident,
                  _transfer_runtime,
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.lock().await.push(source.tcp_port);
                    if source.tcp_port == 41001 {
                        return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                    }
                    Ok(Ed2kPeerDownloadOutcome::Completed)
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(outcome.completed);
    assert_eq!(outcome.accepted_incomplete_peers, 1);
    assert!(outcome.last_error.is_none());
    assert_eq!(*attempts.lock().await, vec![41001, 41002]);
}

#[tokio::test]
async fn direct_download_scheduler_does_not_downgrade_failed_obfuscated_peer() {
    let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size) =
        completed_ed2k_transfer_runtime("emulebb-core-direct-download-no-plaintext-downgrade")
            .await;
    let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let mut source = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
    source.obfuscated = true;
    source.obfuscation_options = Some(0x03);
    source.user_hash = Some([0x22; 16]);
    let outcome = run_ed2k_direct_downloads(
        direct_download_options(
            transfer_runtime,
            secure_ident,
            file_hash_hex,
            file_name,
            file_size,
            vec![source],
        ),
        {
            let attempts = Arc::clone(&attempts);
            move |_bind_ip,
                  source,
                  _hello_identity,
                  _secure_ident,
                  _transfer_runtime,
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.lock().await.push((
                        source.tcp_port,
                        source.obfuscated,
                        source.user_hash.is_some(),
                    ));
                    if source.obfuscated {
                        anyhow::bail!("simulated obfuscated peer close");
                    }
                    Ok(Ed2kPeerDownloadOutcome::Completed)
                }
            }
        },
    )
    .await
    .unwrap();

    assert_eq!(
        outcome
            .last_error
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("simulated obfuscated peer close")
    );
    assert_eq!(*attempts.lock().await, vec![(41001, true, true)]);
}

#[test]
fn direct_download_candidates_deduplicate_same_endpoint_in_one_round() {
    let file_hash = Ed2kHash::from_bytes([0x45; 16]);
    let mut obfuscated = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
    obfuscated.obfuscated = true;
    obfuscated.obfuscation_options = Some(0x03);
    obfuscated.user_hash = Some([0x11; 16]);
    let plaintext = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);

    let candidates =
        direct_download_candidate_sources(&[obfuscated.clone(), plaintext], &HashSet::new());

    assert_eq!(candidates, vec![obfuscated]);
}

#[test]
fn direct_download_candidates_skip_attempted_endpoint_family() {
    let file_hash = Ed2kHash::from_bytes([0x47; 16]);
    let mut attempted_endpoints = HashSet::new();
    attempted_endpoints.insert((Ipv4Addr::new(192, 0, 2, 10), 41001));
    let mut obfuscated = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
    obfuscated.obfuscated = true;
    obfuscated.obfuscation_options = Some(0x03);
    obfuscated.user_hash = Some([0x11; 16]);
    let next_endpoint = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 11), 41002);

    let candidates = direct_download_candidate_sources(
        &[
            obfuscated,
            direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001),
            next_endpoint.clone(),
        ],
        &attempted_endpoints,
    );

    assert_eq!(candidates, vec![next_endpoint]);
}

#[tokio::test]
async fn direct_download_source_leases_defer_peer_to_better_file_candidate() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let lower_hash = Ed2kHash::from_bytes([0x48; 16]).to_string();
    let higher_hash = Ed2kHash::from_bytes([0x49; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x48; 16]),
        Ipv4Addr::new(192, 0, 2, 12),
        41003,
    );
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: lower_hash.clone(),
                file_priority: 1,
                needed_parts: 8,
                rare_parts: 0,
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: higher_hash.clone(),
                file_priority: 9,
                needed_parts: 1,
                rare_parts: 0,
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    }

    let (lower_sources, lower_deferred, lower_delay) = core
        .acquire_direct_download_source_leases(&lower_hash, std::slice::from_ref(&source))
        .await;
    let (higher_sources, higher_deferred, higher_delay) = core
        .acquire_direct_download_source_leases(&higher_hash, std::slice::from_ref(&source))
        .await;

    assert!(lower_sources.is_empty());
    assert_eq!(lower_deferred, 1);
    assert!(lower_delay.is_none());
    assert_eq!(higher_sources, vec![source.clone()]);
    assert_eq!(higher_deferred, 0);
    assert!(higher_delay.is_none());
    core.release_direct_download_source_leases(&[source_endpoint_key(&source)])
        .await;
}

#[tokio::test]
async fn disconnect_releases_detached_reask_source_leases_and_re_engages() {
    // A detached source held on the UDP reask loop keeps its lease
    // (active_download_peer_endpoints + the registry leased_peers). When the
    // reask loop breaks on shutdown without emitting SourceReleased, the lease
    // would leak; disconnect_ed2k must reset it so the source is re-engageable
    // after a reconnect.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x4a; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x4a; 16]),
        Ipv4Addr::new(192, 0, 2, 50),
        41020,
    );
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: file_hash.clone(),
                file_priority: 5,
                needed_parts: 4,
                rare_parts: 0,
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    }

    // Engage (lease) the source, as a download attempt would before detaching
    // it onto the reask loop.
    let (engaged, deferred, retry_delay) = core
        .acquire_direct_download_source_leases(&file_hash, std::slice::from_ref(&source))
        .await;
    assert_eq!(engaged, vec![source.clone()]);
    assert_eq!(deferred, 0);
    assert!(retry_delay.is_none());
    {
        let state = core.state.lock().await;
        assert_eq!(state.active_download_peer_endpoints.len(), 1);
        assert_eq!(state.download_source_registry.leased_peer_count(), 1);
    }

    // The reask loop breaks on shutdown without emitting SourceReleased; the
    // lease would leak. disconnect_ed2k must release it.
    core.disconnect_ed2k().await;
    {
        let state = core.state.lock().await;
        assert!(
            state.active_download_peer_endpoints.is_empty(),
            "disconnect must clear active download peer endpoints"
        );
        assert_eq!(
            state.download_source_registry.leased_peer_count(),
            0,
            "disconnect must release detached source leases"
        );
    }

    // The lease is gone, but the endpoint retry cooldown still gates redial.
    let (re_engaged, re_deferred, re_retry_delay) = core
        .acquire_direct_download_source_leases(&file_hash, std::slice::from_ref(&source))
        .await;
    assert!(re_engaged.is_empty());
    assert_eq!(re_deferred, 1);
    assert!(re_retry_delay.is_some());
}

#[tokio::test]
async fn lease_release_is_tcp_keyed_so_a_udp_endpoint_never_matches() {
    // RUST-PAR-017 DL-11: core's lease sets (active_download_peer_endpoints +
    // the registry leased peers) are keyed by (ip, tcp_port), while the UDP
    // reask loop routes sources by (ip, udp_port). A SourceReleased carrying
    // the UDP endpoint therefore releases NOTHING — the lease leaks and the
    // source can never be re-engaged. This pins the constraint that forced
    // the loop to carry the TCP lease key in its release events.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x5b; 16]).to_string();
    let ip = Ipv4Addr::new(192, 0, 2, 60);
    let tcp_port = 4662u16;
    let udp_port = 4672u16;
    let source = direct_test_source(Ed2kHash::from_bytes([0x5b; 16]), ip, tcp_port);
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: file_hash.clone(),
                file_priority: 5,
                needed_parts: 4,
                rare_parts: 0,
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    }
    let (engaged, _, _) = core
        .acquire_direct_download_source_leases(&file_hash, std::slice::from_ref(&source))
        .await;
    assert_eq!(engaged, vec![source.clone()]);

    // Releasing by the peer's UDP endpoint (what the reask loop routes on)
    // must not free the TCP-keyed lease — the endpoints live in different
    // keyspaces, so this is a no-op by construction.
    core.release_direct_download_source_leases(&[(ip, udp_port)])
        .await;
    {
        let state = core.state.lock().await;
        assert_eq!(
            state.active_download_peer_endpoints.len(),
            1,
            "a UDP endpoint must not match the TCP-keyed active set"
        );
        assert_eq!(
            state.download_source_registry.leased_peer_count(),
            1,
            "a UDP endpoint must not match the TCP-keyed registry lease"
        );
    }

    // Releasing by the TCP lease key (what SourceReleased now carries) frees it.
    core.release_direct_download_source_leases(&[source_endpoint_key(&source)])
        .await;
    {
        let state = core.state.lock().await;
        assert!(state.active_download_peer_endpoints.is_empty());
        assert_eq!(state.download_source_registry.leased_peer_count(), 0);
    }
}

#[tokio::test]
async fn run_attempt_stops_immediately_when_pre_cancelled() {
    // The requery loop checks the per-hash cancel token at the top of each
    // round (and the function checks it before any work). A pre-cancelled token
    // makes the attempt a no-op that returns Ok(None) so the queued-attempt
    // wrapper neither rewrites the transfer state nor re-queues a retry.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let transfer = a4af_test_transfer(&Ed2kHash::from_bytes([0x80; 16]).to_string(), "downloading");
    let cancel = CancellationToken::new();
    cancel.cancel();

    let result = core
        .run_ed2k_download_attempt(&transfer, &cancel)
        .await
        .unwrap();
    assert!(
        result.is_none(),
        "a cancelled attempt must return Ok(None) so it neither restates nor retries"
    );
}

#[tokio::test]
async fn delete_transfer_files_cancels_attempt_and_releases_hash_leases() {
    // Delete must promptly free everything the running attempt holds for the
    // hash: cancel its in-flight token, release the hash's leases + the
    // matching active endpoints, and clear the dedup + cancel slots so a
    // re-create can immediately re-download (it no longer early-returns on a
    // stale dedup slot or finds the peer deferred by a leaked lease).
    let runtime_dir = unique_runtime_dir("emulebb-core-delete-cancels-attempt");
    let transfer_root = runtime_dir.join("transfers");
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
    // Create paused so no background attempt is queued to race the simulated
    // running-attempt state we install below.
    let transfer = core
        .create_transfer(TransferCreate {
            link: Some(
                "ed2k://|file|Cancel.Me.bin|4096|00112233445566778899aabbccddeeff|/".to_string(),
            ),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap();
    let hash = transfer.hash.clone();
    let source = direct_test_source(hash.parse().unwrap(), Ipv4Addr::new(192, 0, 2, 60), 41030);
    let endpoint = source_endpoint_key(&source);

    // Simulate a running attempt for this hash: a registered + leased source
    // (active endpoint), the dedup slot, and an installed cancel token.
    let cancel = CancellationToken::new();
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: hash.clone(),
                file_priority: 5,
                needed_parts: 4,
                rare_parts: 0,
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
        assert!(
            state
                .download_source_registry
                .lease_best_for_file(Instant::now(), Duration::ZERO, &source, &hash)
                .is_some()
        );
        state.active_download_peer_endpoints.insert(endpoint);
        state.active_download_attempts.insert(hash.clone());
        state
            .download_cancels
            .insert(hash.clone(), (0, cancel.clone()));
    }

    let deleted = core.delete_transfer_files(&hash).await.unwrap().unwrap();
    assert_eq!(deleted.hash, hash);

    // The in-flight attempt is signalled to stop.
    assert!(
        cancel.is_cancelled(),
        "delete must cancel the in-flight attempt for the hash"
    );
    let state = core.state.lock().await;
    assert_eq!(
        state.download_source_registry.leased_peer_count(),
        0,
        "delete must release the hash's leases"
    );
    assert_eq!(
        state
            .download_source_registry
            .candidate_count_for_file(Instant::now(), &hash),
        0,
        "delete must forget the hash's source candidates"
    );
    assert!(
        !state.active_download_peer_endpoints.contains(&endpoint),
        "delete must drop the matching active download endpoint"
    );
    assert!(
        !state.active_download_attempts.contains(&hash),
        "delete must clear the dedup slot so a re-create can re-download"
    );
    assert!(
        !state.download_cancels.contains_key(&hash),
        "delete must clear the cancel slot"
    );
}

#[tokio::test]
async fn pause_transfer_cancels_in_flight_attempt() {
    // Pause must stop the transfer now: the driver does not read control_state
    // mid-attempt, so pause cancels the in-flight attempt's token (the loop
    // then stops at its next cancel check) rather than only suppressing the
    // next retry.
    let runtime_dir = unique_runtime_dir("emulebb-core-pause-cancels-attempt");
    let transfer_root = runtime_dir.join("transfers");
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
    // Create paused so no background attempt is queued to race our manually
    // installed token (the attempt's own token would otherwise overwrite it).
    let transfer = core
        .create_transfer(TransferCreate {
            link: Some(
                "ed2k://|file|Pause.Me.bin|4096|00112233445566778899aabbccddeeff|/".to_string(),
            ),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap();
    let hash = transfer.hash.clone();

    // Simulate a running attempt's cancel token for this hash.
    let cancel = CancellationToken::new();
    core.state
        .lock()
        .await
        .download_cancels
        .insert(hash.clone(), (0, cancel.clone()));

    let paused = core.pause_transfer(&hash).await.unwrap().unwrap();
    assert_eq!(paused.state, "paused");
    assert!(
        cancel.is_cancelled(),
        "pause must cancel the in-flight attempt so it stops now, not at next retry"
    );
}

fn a4af_test_transfer(hash: &str, state_name: &str) -> Transfer {
    Transfer {
        hash: hash.to_string(),
        name: "file".to_string(),
        path: String::new(),
        delivered_path: None,
        size_bytes: 1,
        completed_bytes: 0,
        state: state_name.to_string(),
        progress: 0.0,
        sources: 0,
        sources_transferring: 0,
        download_speed_ki_bps: 0.0,
        upload_speed_ki_bps: 0.0,
        stopped: state_name == "paused" || state_name == "stopped",
        ed2k_link: String::new(),
        priority: "normal".to_string(),
        category_id: 0,
        category_name: String::new(),
        eta: None,
        added_at: None,
        completed_at: None,
        parts_total: 1,
        parts_obtained: 0,
        parts_progress_text: "0".to_string(),
        parts_available: 0,
        auto_priority: false,
        in_incoming: false,
    }
}

#[tokio::test]
async fn a4af_multi_file_peer_is_reused_and_not_double_engaged() {
    // A4AF-lite leg 1: a peer registered for two of our files is engaged for
    // exactly one file at a time; the second file defers the same peer
    // (one active relationship per peer, like eMule) rather than opening a
    // redundant second engagement.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let file_a = Ed2kHash::from_bytes([0x71; 16]).to_string();
    let file_b = Ed2kHash::from_bytes([0x72; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x71; 16]),
        Ipv4Addr::new(192, 0, 2, 31),
        41010,
    );
    {
        let mut state = core.state.lock().await;
        // File A is the peer's best (higher priority), so it wins the single
        // per-peer relationship; file B is the lower-priority other file.
        for (hash, priority) in [(&file_a, 9u32), (&file_b, 3u32)] {
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: hash.clone(),
                    file_priority: priority,
                    needed_parts: 4,
                    rare_parts: 1,
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
        }
    }

    let (a_sources, a_deferred, a_delay) = core
        .acquire_direct_download_source_leases(&file_a, std::slice::from_ref(&source))
        .await;
    let (b_sources, b_deferred, b_delay) = core
        .acquire_direct_download_source_leases(&file_b, std::slice::from_ref(&source))
        .await;

    // Engaged once (file A, the peer's best), deferred (NOT double-engaged)
    // for file B: one active relationship per peer, like eMule.
    assert_eq!(a_sources, vec![source.clone()]);
    assert_eq!(a_deferred, 0);
    assert!(a_delay.is_none());
    assert!(b_sources.is_empty());
    assert_eq!(b_deferred, 1);
    assert!(b_delay.is_none());

    // The peer holds exactly one active engagement across both files (no
    // double-engage / one relationship per peer).
    assert_eq!(
        core.state.lock().await.active_download_peer_endpoints.len(),
        1
    );

    // After the peer is released, the same endpoint remains cooldown-deferred
    // until the MFC-style retry window expires instead of being redialed.
    core.release_direct_download_source_leases(&[source_endpoint_key(&source)])
        .await;
    let (a_again, a_again_deferred, a_again_delay) = core
        .acquire_direct_download_source_leases(&file_a, std::slice::from_ref(&source))
        .await;
    assert!(a_again.is_empty());
    assert_eq!(a_again_deferred, 1);
    assert!(a_again_delay.is_some());
}

#[tokio::test]
async fn fnf_dead_listed_source_is_dropped_and_blocked_from_readmission() {
    // DL-2 (oracle CPartFile::m_DeadSourceList, ListenSocket.cpp:645-661): a
    // source that answered OP_FILEREQANSNOFIL is dead-listed for 45 minutes —
    // its registry candidate is dropped, re-registration is refused
    // (DownloadQueue.cpp:1420/:1530 IsDeadSource admission gates), and lease
    // acquisition skips it WITHOUT deferring (the transfer must not wait on a
    // dead source). The same peer's relationship with another file is
    // untouched (the list is per-(file, source)).
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let dead_file = Ed2kHash::from_bytes([0x74; 16]).to_string();
    let other_file = Ed2kHash::from_bytes([0x75; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x74; 16]),
        Ipv4Addr::new(192, 0, 2, 32),
        41011,
    );
    {
        let mut state = core.state.lock().await;
        for hash in [&dead_file, &other_file] {
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: (*hash).clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 0,
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
        }
    }

    core.dead_list_file_not_found_sources(&dead_file, std::slice::from_ref(&source))
        .await;
    {
        let now = Instant::now();
        let state = core.state.lock().await;
        assert_eq!(
            state
                .download_source_registry
                .candidate_count_for_file(now, &dead_file),
            0,
            "the FNF source's candidate for the dead file must be dropped"
        );
        assert_eq!(
            state
                .download_source_registry
                .candidate_count_for_file(now, &other_file),
            1,
            "the same peer's candidate for another file is untouched"
        );
    }

    // Re-registration is refused while the 45-minute block runs.
    let transfer = a4af_test_transfer(&dead_file, "downloading");
    core.register_download_source_candidates(&transfer, std::slice::from_ref(&source))
        .await;
    {
        let now = Instant::now();
        let state = core.state.lock().await;
        assert_eq!(
            state
                .download_source_registry
                .candidate_count_for_file(now, &dead_file),
            0,
            "a dead-listed source must not be re-admitted to the registry"
        );
    }

    // Lease acquisition skips the dead source without deferring: no retry
    // wait is owed to a dead source.
    let (engaged, deferred, retry_delay) = core
        .acquire_direct_download_source_leases(&dead_file, std::slice::from_ref(&source))
        .await;
    assert!(engaged.is_empty());
    assert_eq!(deferred, 0);
    assert!(retry_delay.is_none());
}

#[tokio::test]
async fn udp_fnf_dead_lists_the_sole_registered_source_by_ip() {
    // UDP reask FNF (oracle UDPReaskFNF): the loop only knows the peer's UDP
    // endpoint, so core recovers the full identity from the registry by
    // (ip, file), dead-lists it, and drops the candidate — after which the
    // admission gate refuses re-registration. With TWO distinct peers at the
    // same IP serving the file the resolution is ambiguous and nothing is
    // dead-listed (better than blocking the wrong client behind a NAT).
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let file = Ed2kHash::from_bytes([0x76; 16]).to_string();
    let peer_ip = Ipv4Addr::new(192, 0, 2, 33);
    let source = direct_test_source(Ed2kHash::from_bytes([0x76; 16]), peer_ip, 41012);
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: file.clone(),
                file_priority: 5,
                needed_parts: 4,
                rare_parts: 0,
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    }

    core.dead_list_udp_fnf_source(&file, peer_ip).await;
    {
        let now = Instant::now();
        let state = core.state.lock().await;
        assert_eq!(
            state
                .download_source_registry
                .candidate_count_for_file(now, &file),
            0,
            "the UDP-FNF source's candidate must be dropped"
        );
    }
    let transfer = a4af_test_transfer(&file, "downloading");
    core.register_download_source_candidates(&transfer, std::slice::from_ref(&source))
        .await;
    assert_eq!(
        core.state
            .lock()
            .await
            .download_source_registry
            .candidate_count_for_file(Instant::now(), &file),
        0,
        "a UDP-FNF dead-listed source must not be re-admitted"
    );

    // Ambiguity guard: two distinct peers at one IP -> no dead-listing.
    let ambiguous_file = Ed2kHash::from_bytes([0x77; 16]).to_string();
    let ambiguous_ip = Ipv4Addr::new(192, 0, 2, 34);
    {
        let mut state = core.state.lock().await;
        for tcp_port in [41013u16, 41014] {
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: ambiguous_file.clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 0,
                    source: direct_test_source(
                        Ed2kHash::from_bytes([0x77; 16]),
                        ambiguous_ip,
                        tcp_port,
                    ),
                    last_seen: Instant::now(),
                },
            );
        }
    }
    core.dead_list_udp_fnf_source(&ambiguous_file, ambiguous_ip)
        .await;
    assert_eq!(
        core.state
            .lock()
            .await
            .download_source_registry
            .candidate_count_for_file(Instant::now(), &ambiguous_file),
        2,
        "an ambiguous IP match must not dead-list either candidate"
    );
}

#[tokio::test]
async fn a4af_nnp_source_is_swapped_to_another_wanted_file() {
    // A4AF-lite leg 2: a source with No Needed Parts for the current file but
    // registered for another WANTED file is swapped to that file (its attempt
    // is queued) instead of being dropped (master SwapToAnotherFile).
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let current = Ed2kHash::from_bytes([0x73; 16]).to_string();
    let other = Ed2kHash::from_bytes([0x74; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x73; 16]),
        Ipv4Addr::new(192, 0, 2, 32),
        41011,
    );
    {
        let mut state = core.state.lock().await;
        // The other file is a wanted (downloading) transfer.
        state
            .transfers
            .insert(other.clone(), a4af_test_transfer(&other, "downloading"));
        for hash in [&current, &other] {
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: hash.clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 1,
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
        }
    }

    let swapped = core
        .swap_no_needed_parts_sources(&current, std::slice::from_ref(&source))
        .await;
    assert_eq!(
        swapped, 1,
        "NNP source must be swapped to the other wanted file"
    );
}

#[tokio::test]
async fn a4af_nnp_source_without_other_wanted_file_is_dropped() {
    // A4AF-lite leg 2 negative: a source with No Needed Parts that serves no
    // OTHER wanted file is not swapped (it stays dropped, as before).
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let current = Ed2kHash::from_bytes([0x75; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x75; 16]),
        Ipv4Addr::new(192, 0, 2, 33),
        41012,
    );
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: current.clone(),
                file_priority: 5,
                needed_parts: 4,
                rare_parts: 1,
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    }

    let swapped = core
        .swap_no_needed_parts_sources(&current, std::slice::from_ref(&source))
        .await;
    assert_eq!(
        swapped, 0,
        "NNP source with no other wanted file must not be swapped"
    );
}

#[tokio::test]
async fn a4af_nnp_source_other_file_completed_is_not_swapped() {
    // A4AF-lite leg 2 guard: the swap target must still be a wanted transfer;
    // a completed/paused other file is not a valid swap target.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let current = Ed2kHash::from_bytes([0x76; 16]).to_string();
    let other = Ed2kHash::from_bytes([0x77; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x76; 16]),
        Ipv4Addr::new(192, 0, 2, 34),
        41013,
    );
    {
        let mut state = core.state.lock().await;
        state
            .transfers
            .insert(other.clone(), a4af_test_transfer(&other, "completed"));
        for hash in [&current, &other] {
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: hash.clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 1,
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
        }
    }

    let swapped = core
        .swap_no_needed_parts_sources(&current, std::slice::from_ref(&source))
        .await;
    assert_eq!(
        swapped, 0,
        "completed other file is not a valid swap target"
    );
}

#[tokio::test]
async fn nnp_source_is_held_for_the_doubled_reask_cycle_not_dropped_or_dead_listed() {
    // RUST-PAR-017 DL-3: an NNP source stays in the download source registry
    // in an NNP-held state (oracle DS_NONEEDEDPARTS keeps the source in the
    // srclist, DownloadClient.cpp:848-852) — it is neither dropped nor
    // dead-listed (NNP is not FNF), and its next re-ask is deferred by the
    // 58-minute hold rather than the 20-minute endpoint cooldown.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let file = Ed2kHash::from_bytes([0x78; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x78; 16]),
        Ipv4Addr::new(192, 0, 2, 35),
        41014,
    );
    let now = Instant::now();
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            now,
            DownloadSourceCandidate {
                file_hash: file.clone(),
                file_priority: 5,
                needed_parts: 4,
                rare_parts: 1,
                source: source.clone(),
                last_seen: now,
            },
        );
    }

    let held = core
        .hold_no_needed_parts_sources(&file, std::slice::from_ref(&source))
        .await;
    assert_eq!(held, 1, "the NNP source must be held");

    let mut state = core.state.lock().await;
    assert_eq!(
        state
            .download_source_registry
            .candidate_count_for_file(now, &file),
        1,
        "the held source stays a candidate (kept, not dropped)"
    );
    assert!(
        !state.ed2k_dead_sources.is_dead_source(now, &file, &source),
        "an NNP source is never dead-listed (that is the FNF path)"
    );
    assert_eq!(state.download_source_registry.nnp_source_count(now), 1);
    // The hold (not the attempt cooldown) gates the redial: even with a zero
    // cooldown the lease defers for the full doubled reask interval.
    assert!(
        state
            .download_source_registry
            .lease_best_for_file(
                now + Duration::from_secs(25 * 60),
                Duration::ZERO,
                &source,
                &file
            )
            .is_none(),
        "NNP-held source must not be redialed before the 58-minute hold"
    );
    assert!(
        state
            .download_source_registry
            .lease_best_for_file(
                now + crate::download_source_registry::NNP_REASK_HOLD + Duration::from_secs(1),
                Duration::ZERO,
                &source,
                &file
            )
            .is_some(),
        "the held source is re-asked after FILEREASKTIME * 2"
    );
}

#[tokio::test]
async fn nnp_hold_purges_one_source_per_window_under_source_cap_pressure() {
    // Oracle retention bound (PartFile.cpp:3056-3062): once the file holds
    // >= maxSources * 4/5 sources, an NNP source is dropped instead of held
    // — but at most one per 40-second purge window; the rest stay held.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.ed2k_transfers.apply_download_coordinator_config(
        emulebb_ed2k::ed2k_transfer::Ed2kDownloadCoordinatorConfig {
            // Threshold = 5 * 4/5 = 4 live sources.
            max_sources_per_file: 5,
            ..emulebb_ed2k::ed2k_transfer::Ed2kDownloadCoordinatorConfig::default()
        },
    );
    let file = Ed2kHash::from_bytes([0x79; 16]).to_string();
    let now = Instant::now();
    let sources: Vec<Ed2kFoundSource> = (0..5u8)
        .map(|index| {
            direct_test_source(
                Ed2kHash::from_bytes([0x79; 16]),
                Ipv4Addr::new(192, 0, 2, 40 + index),
                41020 + u16::from(index),
            )
        })
        .collect();
    {
        let mut state = core.state.lock().await;
        for source in &sources {
            state.download_source_registry.add_candidate(
                now,
                DownloadSourceCandidate {
                    file_hash: file.clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 1,
                    source: source.clone(),
                    last_seen: now,
                },
            );
        }
    }

    // Two NNP verdicts in one round: the first is purged (5 >= 4 with the
    // purge window open), the second is held (the 40-second window is spent).
    let held = core
        .hold_no_needed_parts_sources(&file, &sources[0..2])
        .await;
    assert_eq!(held, 1, "only one NNP source is purged per 40s window");

    let mut state = core.state.lock().await;
    assert_eq!(
        state
            .download_source_registry
            .candidate_count_for_file(Instant::now(), &file),
        4,
        "exactly one NNP source was dropped under cap pressure"
    );
    assert_eq!(
        state
            .download_source_registry
            .nnp_source_count(Instant::now()),
        1,
        "the non-purged NNP source is held"
    );
    // The purged source is gone entirely; the held one keeps its candidate.
    assert!(
        state
            .download_source_registry
            .lease_best_for_file(Instant::now(), Duration::ZERO, &sources[0], &file)
            .is_none(),
        "the purged source has no candidate left to lease"
    );
}

#[test]
fn source_requery_skip_waits_for_one_refresh_round_without_progress() {
    assert!(!should_skip_no_progress_source_requery(true, false, 0, 0));
    assert!(should_skip_no_progress_source_requery(true, false, 0, 1));
    assert!(!should_skip_no_progress_source_requery(true, true, 0, 1));
    assert!(!should_skip_no_progress_source_requery(true, false, 1, 1));
    assert!(!should_skip_no_progress_source_requery(false, false, 0, 1));
}

#[test]
fn ed2k_server_source_refresh_is_initial_round_only() {
    assert!(should_refresh_ed2k_server_sources(0));
    assert!(!should_refresh_ed2k_server_sources(1));
    assert!(!should_refresh_ed2k_server_sources(2));
}

#[test]
fn global_udp_source_search_skips_connected_server_only_when_background_is_available() {
    let connected_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 4661));

    assert_eq!(
        global_udp_source_search_excluded_endpoint(false, Some(connected_server)),
        None
    );
    assert_eq!(global_udp_source_search_excluded_endpoint(true, None), None);
    assert_eq!(
        global_udp_source_search_excluded_endpoint(true, Some(connected_server)),
        Some(connected_server)
    );
}

#[test]
fn server_udp_source_supplement_runs_below_the_udp_source_cap() {
    // Oracle: GetMaxSourcePerFileUDP() > GetSourceCount() (default cap 100).
    assert!(should_query_server_udp_source_supplement(0, 100));
    assert!(should_query_server_udp_source_supplement(99, 100));
    assert!(!should_query_server_udp_source_supplement(100, 100));
    assert!(!should_query_server_udp_source_supplement(150, 100));
    // 0 = uncapped.
    assert!(should_query_server_udp_source_supplement(10_000, 0));
}

#[test]
fn callback_route_uses_only_matching_connected_server() {
    let connected_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 4661));
    let other_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 4661));

    assert_eq!(
        ed2k_server_callback_route(Some(connected_server), Some(connected_server)),
        Ed2kServerCallbackRoute::BackgroundSession
    );
    assert_eq!(
        ed2k_server_callback_route(Some(other_server), Some(connected_server)),
        Ed2kServerCallbackRoute::Unavailable
    );
    assert_eq!(
        ed2k_server_callback_route(None, Some(connected_server)),
        Ed2kServerCallbackRoute::Unavailable
    );
    assert_eq!(
        ed2k_server_callback_route(Some(connected_server), None),
        Ed2kServerCallbackRoute::Unavailable
    );
}

#[test]
fn manifest_progress_includes_hashset_and_partial_piece_bytes() {
    let file_hash = Ed2kHash::from_bytes([0x48; 16]);
    let job = new_transfer_job(file_hash, "partial.bin".to_string(), 4096);
    let mut manifest = Ed2kResumeManifest::new(&job);
    assert!(!manifest_has_ed2k_transfer_progress(&manifest));

    manifest.md4_hashset_acquired = true;
    assert!(manifest_has_ed2k_transfer_progress(&manifest));
    manifest.md4_hashset_acquired = false;

    manifest.pieces[0].bytes_written = 512;
    assert!(manifest_has_ed2k_transfer_progress(&manifest));
}

#[test]
fn kad_source_supplement_runs_below_the_udp_source_cap() {
    // Same GetMaxSourcePerFileUDP gate as the server UDP walk.
    assert!(should_query_kad_source_supplement(0, 100));
    assert!(should_query_kad_source_supplement(99, 100));
    assert!(!should_query_kad_source_supplement(100, 100));
    // 0 = uncapped.
    assert!(should_query_kad_source_supplement(10_000, 0));
}

#[test]
fn kad_source_result_maps_to_direct_ed2k_source() {
    let file_hash = Ed2kHash::from_bytes([0x49; 16]);
    let source_id = Ed2kHash::from_bytes([0x4a; 16]);
    let source = kad_source_result_to_ed2k_found_source(SourceResult {
        file_hash,
        source_id,
        ip: Ipv4Addr::new(192, 0, 2, 55),
        tcp_port: 4662,
        udp_port: 4672,
        obfuscation_options: Some(0x03),
        source_type: 1,
        buddy_id: None,
        buddy_ip: None,
        buddy_port: 0,
    })
    .expect("mapped source");

    assert_eq!(source.file_hash, file_hash);
    assert_eq!(source.ip, Ipv4Addr::new(192, 0, 2, 55));
    assert_eq!(source.tcp_port, 4662);
    assert_eq!(source.client_id, u32::from(Ipv4Addr::new(192, 0, 2, 55)));
    assert!(!source.low_id);
    assert!(source.obfuscated);
    assert_eq!(source.obfuscation_options, Some(0x03));
    assert_eq!(source.user_hash, Some(source_id.0));
    assert_eq!(source.source_server, None);
    assert_eq!(source.buddy_id, None);
    assert_eq!(source.buddy_endpoint, None);
}

#[test]
fn merge_download_sources_preserves_later_server_provenance() {
    let file_hash = Ed2kHash::from_bytes([0x46; 16]);
    let source_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 4661));
    let mut sources = vec![direct_test_source(
        file_hash,
        Ipv4Addr::new(192, 0, 2, 10),
        41001,
    )];
    let mut sourced = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
    sourced.source_server = Some(source_server);

    merge_download_sources(&mut sources, vec![sourced]);

    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].source_server, Some(source_server));
}

#[test]
fn drop_self_sources_removes_own_endpoint_and_user_hash() {
    let file_hash = Ed2kHash::from_bytes([0x47; 16]);
    let own_ip = Ipv4Addr::new(203, 0, 113, 7);
    let own_port = 4662u16;
    let own_user_hash = [0xAB; 16];
    let identity = OwnSourceIdentity {
        user_hash: own_user_hash,
        endpoints: vec![(Ipv4Addr::new(192, 168, 50, 2), 4662), (own_ip, own_port)],
    };

    // (1) self by advertised public endpoint, (2) self by local bind endpoint,
    // (3) self by user-hash on a different endpoint, (4) a real foreign source.
    let mut self_by_endpoint = direct_test_source(file_hash, own_ip, own_port);
    self_by_endpoint.user_hash = None;
    let self_by_bind = direct_test_source(file_hash, Ipv4Addr::new(192, 168, 50, 2), 4662);
    let mut self_by_hash = direct_test_source(file_hash, Ipv4Addr::new(198, 51, 100, 9), 5000);
    self_by_hash.user_hash = Some(own_user_hash);
    let foreign = direct_test_source(file_hash, Ipv4Addr::new(198, 51, 100, 22), 4662);

    let mut sources = vec![
        self_by_endpoint,
        self_by_bind,
        self_by_hash,
        foreign.clone(),
    ];
    let dropped = drop_self_sources(&mut sources, &identity);

    assert_eq!(dropped, 3);
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].ip, foreign.ip);
    assert_eq!(sources[0].tcp_port, foreign.tcp_port);
}

#[test]
fn drop_self_sources_keeps_foreign_when_only_port_collides() {
    let file_hash = Ed2kHash::from_bytes([0x48; 16]);
    let identity = OwnSourceIdentity {
        user_hash: [0x01; 16],
        endpoints: vec![(Ipv4Addr::new(203, 0, 113, 7), 4662)],
    };
    // Same port, different IP, different user-hash: a genuine peer, kept.
    let foreign = direct_test_source(file_hash, Ipv4Addr::new(198, 51, 100, 30), 4662);
    let mut sources = vec![foreign];
    assert_eq!(drop_self_sources(&mut sources, &identity), 0);
    assert_eq!(sources.len(), 1);
}

#[test]
fn remembered_source_hint_becomes_direct_dial_source() {
    let file_hash: Ed2kHash = "00112233445566778899aabbccddeeff".parse().unwrap();
    let source = found_source_from_hint(
        file_hash,
        &Ed2kSourceHint {
            ip: "192.0.2.10".to_string(),
            tcp_port: 4662,
            user_hash: Some("0102030405060708090a0b0c0d0e0f10".to_string()),
        },
    )
    .unwrap();

    assert_eq!(source.file_hash, file_hash);
    assert_eq!(source.ip, "192.0.2.10".parse::<Ipv4Addr>().unwrap());
    assert_eq!(source.tcp_port, 4662);
    assert!(source.is_direct_dialable());
    assert!(source.obfuscated);
    assert_eq!(
        source.user_hash,
        Some([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
    );
}

#[test]
fn parse_ban_ip_accepts_dialable_ipv4_only() {
    assert_eq!(
        parse_ban_ip("203.0.113.7"),
        Some(Ipv4Addr::new(203, 0, 113, 7))
    );
    // Empty / unspecified / LowID-style non-IP fall back to no IP key.
    assert_eq!(parse_ban_ip(""), None);
    assert_eq!(parse_ban_ip("0.0.0.0"), None);
    assert_eq!(parse_ban_ip("low-id-12345"), None);
}

#[test]
fn parse_ban_hash_decodes_16_byte_hex() {
    assert_eq!(
        parse_ban_hash(Some("000102030405060708090a0b0c0d0e0f")),
        Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    );
    assert_eq!(parse_ban_hash(None), None);
    assert_eq!(parse_ban_hash(Some("not-hex")), None);
    // Wrong length is rejected.
    assert_eq!(parse_ban_hash(Some("0011")), None);
}
