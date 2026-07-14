use emulebb_ed2k::{NatConfig, ipfilter::IpFilter};
use emulebb_index::IndexedFile;
use emulebb_kad_proto::{NodeId, Tag, TagValue};
use md4::{Digest, Md4};

use super::*;
use crate::source_publish::emule_high_id_source_type;

mod core_config;
mod download_scheduler;
mod download_source_policy;
mod kad_protocol;
mod kad_publish_candidates;
mod kad_publish_runtime;
mod search_servers;
mod transfer_lifecycle;

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
    let mut config = Ed2kRuntimeConfig {
        connect_timeout_secs: 1,
        ..Ed2kRuntimeConfig::default()
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
        kad_bootstrap_endpoints: Vec::new(),
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
        ed2k: Ed2kRuntimeConfig::default(),
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
fn configured_kad_bootstrap_endpoints_text_keeps_only_valid_ipv4_endpoints() {
    let endpoints = vec![
        "192.0.2.20:4665".to_string(),
        " ".to_string(),
        "[2001:db8::1]:4665".to_string(),
        "not-an-address".to_string(),
        "192.0.2.21:4666".to_string(),
    ];

    assert_eq!(
        configured_kad_bootstrap_endpoints_text(&endpoints).as_deref(),
        Some("192.0.2.20:4665\n192.0.2.21:4666")
    );
    assert_eq!(
        configured_kad_bootstrap_endpoints_text(&["bad".to_string()]),
        None
    );
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
fn passive_replay_family_core_setting_follows_deepest_queue_with_stable_tie_breaks() {
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
        summary.display_name,
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
