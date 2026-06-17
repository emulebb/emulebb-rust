use super::*;
use emulebb_ed2k::{InterfaceAddressFamily, NetworkInterfaceAddress};

fn metadata_store(config: &DaemonConfig) -> MetadataStore {
    MetadataStore::open(config.metadata_path()).unwrap()
}

fn config_with_server(runtime_dir: PathBuf, p2p_bind_ip: Option<Ipv4Addr>) -> DaemonConfig {
    let ed2k = Ed2kConfig {
        listen_port: Some(41001),
        server_endpoints: vec!["192.0.2.20:4661".to_string()],
        ..Ed2kConfig::default()
    };
    DaemonConfig {
        runtime_dir,
        p2p_bind_ip,
        kad: KadListenerConfig {
            listen_port: Some(41002),
            ..KadListenerConfig::default()
        },
        ed2k,
        ..DaemonConfig::default()
    }
}

fn config_with_rest_bind(runtime_dir: PathBuf, bind_addr: Option<SocketAddr>) -> DaemonConfig {
    DaemonConfig {
        runtime_dir,
        rest: RestListenerConfig {
            bind_addr,
            ..RestListenerConfig::default()
        },
        ..DaemonConfig::default()
    }
}

fn iface(name: &str, ip: &str) -> NetworkInterface {
    iface_with_vpn(name, ip, false)
}

fn iface_with_vpn(name: &str, ip: &str, is_vpn_candidate: bool) -> NetworkInterface {
    NetworkInterface {
        name: name.to_string(),
        description: None,
        addresses: vec![NetworkInterfaceAddress {
            family: InterfaceAddressFamily::Ipv4,
            address: ip.to_string(),
        }],
        is_loopback: false,
        is_vpn_candidate,
        has_default_route: false,
    }
}

#[test]
fn load_requires_explicit_config_path() {
    let error = DaemonConfig::load(None).unwrap_err().to_string();

    assert!(error.contains("--config is required"));
}

#[test]
fn load_requires_existing_config_path() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("missing.toml");

    let error = DaemonConfig::load(Some(path)).unwrap_err().to_string();

    assert!(error.contains("config file does not exist"));
}

#[test]
#[allow(clippy::cognitive_complexity)]
fn load_parses_camel_case_ed2k_config() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("emulebb-rust.toml");
    fs::write(
        &config_path,
        r#"
runtimeDir = "runtime"
p2pBindIp = "192.0.2.10"
p2pBindInterface = "Ethernet"

[rest]
bindAddr = "192.0.2.10:13301"
apiKey = "secret"

[kad]
listenPort = 41002
bootstrapNodes = ["192.0.2.30:41002"]
bootstrapMinRoutingContacts = 3
localStoreEnabled = true
localStoreKeywordTtlSecs = 86400
localStoreSourceTtlSecs = 21600
localStoreNotesTtlSecs = 86400
localStoreKeywordCapacity = 20000
localStoreSourceCapacity = 20000
localStoreNotesCapacity = 5000
publishSharedFilesEnabled = true
republishIntervalSecs = 120
publishContactFanout = 5
helloIntroIntervalSecs = 42
helloIntroFanout = 3
snoopQueueDedupWindowSecs = 28800
snoopQueueGeneralMaxQueriesPer600s = 24
snoopQueueGeneralDrainCooldownSecs = 900
snoopQueueSourceMaxQueriesPer600s = 60
snoopQueueSourceDrainCooldownSecs = 300
snoopQueueSourceStopAfterResults = 2

[ed2k]
listenPort = 41001
serverEndpoints = ["192.0.2.20:4661"]
connectTimeoutSecs = 1
reconnectIntervalSecs = 60
enableUdpReask = true
publishEmuleRustIdentity = true

[nat]
enabled = true
backendOrder = ["upnp_miniupnpc", "upnp_rupnp"]
bindIp = "192.0.2.11"
igdIp = "192.0.2.1"
minissdpdSocket = "/var/run/minissdpd.sock"
ssdpLocalPort = 1901
discoveryTimeoutSecs = 7
leaseDurationSecs = 1200
renewMarginSecs = 120
externalIpOverride = "203.0.113.10"
"#,
    )
    .unwrap();

    let config = DaemonConfig::load(Some(config_path)).unwrap();

    assert_eq!(config.p2p_bind_ip, Some("192.0.2.10".parse().unwrap()));
    assert_eq!(config.p2p_bind_interface.as_deref(), Some("Ethernet"));
    assert_eq!(
        config.rest.bind_addr,
        Some("192.0.2.10:13301".parse().unwrap())
    );
    assert_eq!(config.kad.listen_port, Some(41002));
    assert_eq!(config.kad.bootstrap_nodes, ["192.0.2.30:41002"]);
    assert_eq!(config.kad.bootstrap_min_routing_contacts, 3);
    assert!(config.kad.local_store_enabled);
    assert_eq!(config.kad.local_store_keyword_ttl_secs, 86_400);
    assert_eq!(config.kad.local_store_source_ttl_secs, 21_600);
    assert_eq!(config.kad.local_store_notes_ttl_secs, 86_400);
    assert_eq!(config.kad.local_store_keyword_capacity, 20_000);
    assert_eq!(config.kad.local_store_source_capacity, 20_000);
    assert_eq!(config.kad.local_store_notes_capacity, 5_000);
    assert!(config.kad.publish_shared_files_enabled);
    assert_eq!(config.kad.republish_interval_secs, 120);
    assert_eq!(config.kad.publish_contact_fanout, 5);
    assert_eq!(config.kad.hello_intro_interval_secs, 42);
    assert_eq!(config.kad.hello_intro_fanout, 3);
    assert_eq!(config.kad.snoop_queue_dedup_window_secs, 28_800);
    assert_eq!(config.kad.snoop_queue_general_max_queries_per_600s, 24);
    assert_eq!(config.kad.snoop_queue_general_drain_cooldown_secs, 900);
    assert_eq!(config.kad.snoop_queue_source_max_queries_per_600s, 60);
    assert_eq!(config.kad.snoop_queue_source_drain_cooldown_secs, 300);
    assert_eq!(config.kad.snoop_queue_source_stop_after_results, 2);
    assert_eq!(config.ed2k.listen_port, Some(41001));
    assert_eq!(config.ed2k.server_endpoints, ["192.0.2.20:4661"]);
    assert_eq!(config.ed2k.connect_timeout_secs, 1);
    assert_eq!(config.ed2k.reconnect_interval_secs, 60);
    // The UDP source-reask flag is config-settable (camelCase), so enabling it
    // for live validation is a config flip, not a code change (FEAT-001).
    assert!(config.ed2k.enable_udp_reask);
    // The eD2k identity flag is config-settable: default appears as eMule
    // Community, this opts in to publishing the real emule-rust identity.
    assert!(config.ed2k.publish_emule_rust_identity);
    assert!(config.nat.enabled);
    assert_eq!(
        config.nat.backend_order,
        ["upnp_miniupnpc".to_string(), "upnp_rupnp".to_string()]
    );
    assert_eq!(config.nat.bind_ip.as_deref(), Some("192.0.2.11"));
    assert_eq!(config.nat.igd_ip.as_deref(), Some("192.0.2.1"));
    assert_eq!(
        config.nat.minissdpd_socket.as_deref(),
        Some("/var/run/minissdpd.sock")
    );
    assert_eq!(config.nat.ssdp_local_port, Some(1901));
    assert_eq!(config.nat.discovery_timeout_secs, 7);
    assert_eq!(config.nat.lease_duration_secs, 1200);
    assert_eq!(config.nat.renew_margin_secs, 120);
    assert_eq!(
        config.nat.external_ip_override.as_deref(),
        Some("203.0.113.10")
    );
}

#[test]
fn load_parses_ed2k_server_entry_obfuscation_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("emulebb-rust-server-entry.toml");
    fs::write(
        &config_path,
        r#"
runtimeDir = "runtime"
p2pBindIp = "192.0.2.10"

[rest]
bindAddr = "192.0.2.10:13301"
apiKey = "secret"

[kad]
listenPort = 41002

[ed2k]
listenPort = 41001
obfuscationEnabled = false

[[ed2k.serverEntries]]
host = "192.0.2.20"
port = 4661
name = "emulebb-local-e2e"
description = "local deterministic server"
udpFlags = 1827
udpKey = 287454020
udpKeyIp = 0
obfuscationPortTcp = 4661
obfuscationPortUdp = 4665
"#,
    )
    .unwrap();

    let config = DaemonConfig::load(Some(config_path)).unwrap();

    assert!(!config.ed2k.obfuscation_enabled);
    assert!(config.ed2k.server_endpoints.is_empty());
    assert_eq!(config.ed2k.server_entries.len(), 1);
    let entry = &config.ed2k.server_entries[0];
    assert_eq!(entry.host, "192.0.2.20");
    assert_eq!(entry.port, 4661);
    assert_eq!(entry.name.as_deref(), Some("emulebb-local-e2e"));
    assert_eq!(
        entry.description.as_deref(),
        Some("local deterministic server")
    );
    assert_eq!(entry.udp_flags, 1827);
    assert_eq!(entry.udp_key, 287454020);
    assert_eq!(entry.udp_key_ip, 0);
    assert_eq!(entry.obfuscation_port_tcp, 4661);
    assert_eq!(entry.obfuscation_port_udp, 4665);
}

#[test]
fn kad_local_store_config_is_config_driven_and_clamped() {
    let config = DaemonConfig {
        kad: KadListenerConfig {
            listen_port: Some(41002),
            local_store_enabled: false,
            local_store_keyword_ttl_secs: 0,
            local_store_source_ttl_secs: 0,
            local_store_notes_ttl_secs: 0,
            local_store_keyword_capacity: 0,
            local_store_source_capacity: 0,
            local_store_notes_capacity: 0,
            ..KadListenerConfig::default()
        },
        ..DaemonConfig::default()
    };

    let local_store = config.kad_local_store_config();

    assert!(!local_store.enabled);
    assert_eq!(local_store.keyword_ttl, std::time::Duration::from_secs(1));
    assert_eq!(local_store.source_ttl, std::time::Duration::from_secs(1));
    assert_eq!(local_store.notes_ttl, std::time::Duration::from_secs(1));
    assert_eq!(local_store.keyword_capacity, 1);
    assert_eq!(local_store.source_capacity, 1);
    assert_eq!(local_store.notes_capacity, 1);
}

#[test]
fn kad_snoop_queue_config_is_config_driven_and_clamped() {
    let config = DaemonConfig {
        kad: KadListenerConfig {
            listen_port: Some(41002),
            snoop_queue_dedup_window_secs: 0,
            snoop_queue_general_max_queries_per_600s: 0,
            snoop_queue_general_drain_cooldown_secs: 0,
            snoop_queue_source_max_queries_per_600s: 0,
            snoop_queue_source_drain_cooldown_secs: 0,
            snoop_queue_source_stop_after_results: 0,
            ..KadListenerConfig::default()
        },
        ..DaemonConfig::default()
    };

    let queue = config.kad_snoop_queue_config();

    assert_eq!(queue.dedup_window_secs, 1);
    assert_eq!(queue.general_max_queries_per_600s, 1);
    assert_eq!(queue.general_drain_cooldown_secs, 1);
    assert_eq!(queue.source_max_queries_per_600s, 1);
    assert_eq!(queue.source_drain_cooldown_secs, 1);
    assert_eq!(queue.source_stop_after_results, 1);
}

#[test]
fn rest_bind_addr_requires_configured_address() {
    let temp = tempfile::tempdir().unwrap();
    let config = config_with_rest_bind(temp.path().to_path_buf(), None);

    let error = config.rest_bind_addr().unwrap_err().to_string();

    assert!(error.contains("rest.bindAddr is required"));
}

#[test]
fn rest_bind_addr_accepts_configured_loopback_address() {
    let temp = tempfile::tempdir().unwrap();
    let config = config_with_rest_bind(
        temp.path().to_path_buf(),
        Some("127.0.0.1:13301".parse().unwrap()),
    );

    assert_eq!(
        config.rest_bind_addr().unwrap(),
        "127.0.0.1:13301".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn rest_bind_addr_accepts_configured_wildcard_address() {
    let temp = tempfile::tempdir().unwrap();
    let config = config_with_rest_bind(
        temp.path().to_path_buf(),
        Some("0.0.0.0:13301".parse().unwrap()),
    );

    assert_eq!(
        config.rest_bind_addr().unwrap(),
        "0.0.0.0:13301".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn rest_bind_addr_accepts_configured_non_loopback_address() {
    let temp = tempfile::tempdir().unwrap();
    let config = config_with_rest_bind(
        temp.path().to_path_buf(),
        Some("192.0.2.10:13301".parse().unwrap()),
    );

    assert_eq!(
        config.rest_bind_addr().unwrap(),
        "192.0.2.10:13301".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn ed2k_network_config_is_absent_without_servers() {
    let temp = tempfile::tempdir().unwrap();
    let config = DaemonConfig {
        runtime_dir: temp.path().to_path_buf(),
        ..DaemonConfig::default()
    };

    assert!(
        config
            .ed2k_network_config(&metadata_store(&config))
            .unwrap()
            .is_none()
    );
}

#[test]
fn ed2k_network_config_requires_configured_bind_ip() {
    let temp = tempfile::tempdir().unwrap();
    let config = config_with_server(temp.path().to_path_buf(), None);

    let error = config
        .ed2k_network_config(&metadata_store(&config))
        .unwrap_err()
        .to_string();
    assert!(error.contains("p2pBindIp or p2pBindInterface is required"));
}

#[test]
fn ed2k_network_config_requires_configured_kad_listen_port() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    config.kad.listen_port = None;

    let error = config
        .ed2k_network_config(&metadata_store(&config))
        .unwrap_err()
        .to_string();
    assert!(error.contains("kad.listenPort is required"));
}

#[test]
fn ed2k_network_config_requires_configured_ed2k_listen_port() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    config.ed2k.listen_port = None;

    let error = config
        .ed2k_network_config(&metadata_store(&config))
        .unwrap_err()
        .to_string();
    assert!(error.contains("ed2k.listenPort is required"));
}

#[test]
fn ed2k_network_config_accepts_configured_loopback_bind_ip() {
    let temp = tempfile::tempdir().unwrap();
    let config = config_with_server(temp.path().to_path_buf(), Some(Ipv4Addr::LOCALHOST));

    let network = config
        .ed2k_network_config(&metadata_store(&config))
        .unwrap()
        .unwrap();

    assert_eq!(network.bind_ip, Ipv4Addr::LOCALHOST);
    assert_eq!(network.listen_port, 41001);
    assert_eq!(network.kad_bind_addr, "127.0.0.1:41002".parse().unwrap());
}

#[test]
fn ed2k_network_config_accepts_configured_non_loopback_bind_ip() {
    let temp = tempfile::tempdir().unwrap();
    let config = config_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );

    let network = config
        .ed2k_network_config(&metadata_store(&config))
        .unwrap()
        .unwrap();

    assert_eq!(network.bind_ip, "192.0.2.10".parse::<Ipv4Addr>().unwrap());
    assert_eq!(network.listen_port, 41001);
    assert_eq!(network.kad_bind_addr, "192.0.2.10:41002".parse().unwrap());
    assert!(network.kad_local_store.enabled);
    assert_eq!(network.kad_bootstrap_nodes, Vec::<String>::new());
    assert_eq!(network.kad_bootstrap_min_routing_contacts, 10);
    assert!(network.kad_publish_shared_files);
    assert_eq!(network.kad_republish_interval_secs, 1_800);
    assert_eq!(network.kad_publish_contact_fanout, 4);
    assert_eq!(network.kad_hello_intro_interval_secs, 300);
    assert_eq!(network.kad_hello_intro_fanout, 2);
    // Default source TTL mirrors the master inbound source entry lifetime =
    // KADEMLIAREPUBLISHTIMES (5h), KademliaUDPListener.cpp:1349.
    assert_eq!(
        network.kad_local_store.source_ttl,
        std::time::Duration::from_secs(18_000)
    );
    assert_eq!(network.kad_snoop_queue.source_stop_after_results, 2);
    let store = metadata_store(&config);
    assert!(
        store
            .load_local_identity(ED2K_USER_HASH_IDENTITY_KIND)
            .unwrap()
            .unwrap()
            .public_identity
            .is_some()
    );
    assert!(
        store
            .load_local_identity(ED2K_SECURE_IDENT_IDENTITY_KIND)
            .unwrap()
            .unwrap()
            .private_secret
            .is_some()
    );
    assert!(!config.runtime_dir.join("ed2k-user-hash.hex").exists());
    assert!(!config.runtime_dir.join("ed2k-secure-ident.pk8").exists());
}

#[test]
fn ed2k_user_hash_uses_emule_markers() {
    let hash = parse_user_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();

    assert_eq!(hash[5], 0x0E);
    assert_eq!(hash[14], 0x6F);
}

#[test]
fn ed2k_user_hash_rejects_emule_bad_hash_after_marker_normalization() {
    let error = parse_user_hash("00000000000000000000000000000000")
        .unwrap_err()
        .to_string();

    assert!(error.contains("bad hash"));
}

#[test]
fn ed2k_network_config_normalizes_configured_user_hash() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    config.ed2k_user_hash = Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());

    let network = config
        .ed2k_network_config(&metadata_store(&config))
        .unwrap()
        .unwrap();

    assert_eq!(network.user_hash[5], 0x0E);
    assert_eq!(network.user_hash[14], 0x6F);
    assert_eq!(
        metadata_store(&config)
            .load_local_identity(ED2K_USER_HASH_IDENTITY_KIND)
            .unwrap()
            .unwrap()
            .public_identity
            .unwrap(),
        network.user_hash.to_vec()
    );
}

#[test]
fn load_or_create_user_hash_persists_emule_markers() {
    let temp = tempfile::tempdir().unwrap();
    let store = MetadataStore::open(temp.path().join("metadata.sqlite")).unwrap();

    let hash = load_or_create_user_hash(&store).unwrap();
    let persisted = parse_user_hash_bytes(
        &store
            .load_local_identity(ED2K_USER_HASH_IDENTITY_KIND)
            .unwrap()
            .unwrap()
            .public_identity
            .unwrap(),
    )
    .unwrap();

    assert_eq!(hash[5], 0x0E);
    assert_eq!(hash[14], 0x6F);
    assert_eq!(persisted, hash);
}

#[test]
fn load_or_create_user_hash_rewrites_markerless_sql_hash() {
    let temp = tempfile::tempdir().unwrap();
    let store = MetadataStore::open(temp.path().join("metadata.sqlite")).unwrap();
    store
        .upsert_local_identity(&MetadataLocalIdentity {
            kind: ED2K_USER_HASH_IDENTITY_KIND.to_string(),
            public_identity: Some(vec![0xaa; 16]),
            private_secret: None,
        })
        .unwrap();

    let hash = load_or_create_user_hash(&store).unwrap();

    assert_eq!(hash[5], 0x0E);
    assert_eq!(hash[14], 0x6F);
    assert_eq!(
        store
            .load_local_identity(ED2K_USER_HASH_IDENTITY_KIND)
            .unwrap()
            .unwrap()
            .public_identity
            .unwrap(),
        hash.to_vec()
    );
}

#[test]
fn load_or_create_secure_ident_reuses_sql_private_secret() {
    let temp = tempfile::tempdir().unwrap();
    let store = MetadataStore::open(temp.path().join("metadata.sqlite")).unwrap();

    let first = load_or_create_secure_ident(&store).unwrap();
    let second = load_or_create_secure_ident(&store).unwrap();

    assert_eq!(
        first.to_pkcs8_der().unwrap(),
        second.to_pkcs8_der().unwrap()
    );
    assert!(
        !store
            .load_local_identity(ED2K_SECURE_IDENT_IDENTITY_KIND)
            .unwrap()
            .unwrap()
            .private_secret
            .unwrap()
            .is_empty()
    );
}

#[test]
fn p2p_bind_interface_resolves_configured_interface_ipv4() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(temp.path().to_path_buf(), None);
    config.p2p_bind_interface = Some("hide.me".to_string());

    let bind_ip = config
        .resolve_p2p_bind_ip_from_interfaces(&[
            iface("Ethernet", "192.0.2.10"),
            iface("hide.me", "10.44.55.66"),
        ])
        .unwrap();

    assert_eq!(bind_ip, "10.44.55.66".parse::<Ipv4Addr>().unwrap());
}

#[test]
fn p2p_bind_interface_matches_name_case_insensitively() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(temp.path().to_path_buf(), None);
    config.p2p_bind_interface = Some("HIDE.ME".to_string());

    let bind_ip = config
        .resolve_p2p_bind_ip_from_interfaces(&[iface("hide.me", "10.44.55.66")])
        .unwrap();

    assert_eq!(bind_ip, "10.44.55.66".parse::<Ipv4Addr>().unwrap());
}

#[test]
fn p2p_bind_interface_rejects_ambiguous_case_insensitive_names() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(temp.path().to_path_buf(), None);
    config.p2p_bind_interface = Some("hide.me".to_string());

    let error = config
        .resolve_p2p_bind_ip_from_interfaces(&[
            iface("hide.me", "10.44.55.66"),
            iface("HIDE.ME", "10.44.55.67"),
        ])
        .unwrap_err()
        .to_string();

    assert!(error.contains("ambiguous"));
}

#[test]
fn p2p_bind_ip_and_interface_accept_matching_pair() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(
        temp.path().to_path_buf(),
        Some("10.44.55.66".parse().unwrap()),
    );
    config.p2p_bind_interface = Some("hide.me".to_string());

    let bind_ip = config
        .resolve_p2p_bind_ip_from_interfaces(&[iface("hide.me", "10.44.55.66")])
        .unwrap();

    assert_eq!(bind_ip, "10.44.55.66".parse::<Ipv4Addr>().unwrap());
}

#[test]
fn p2p_bind_ip_and_interface_reject_mismatched_pair() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    config.p2p_bind_interface = Some("hide.me".to_string());

    let error = config
        .resolve_p2p_bind_ip_from_interfaces(&[
            iface("Ethernet", "192.0.2.10"),
            iface("hide.me", "10.44.55.66"),
        ])
        .unwrap_err()
        .to_string();

    assert!(error.contains("p2pBindIp"));
    assert!(error.contains("not assigned to p2pBindInterface"));
}

#[test]
fn p2p_bind_interface_requires_matching_ipv4_interface() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(temp.path().to_path_buf(), None);
    config.p2p_bind_interface = Some("hide.me".to_string());

    let error = config
        .resolve_p2p_bind_ip_from_interfaces(&[iface("Ethernet", "192.0.2.10")])
        .unwrap_err()
        .to_string();

    assert!(error.contains("p2pBindInterface"));
    assert!(error.contains("did not resolve"));
}

#[test]
fn vpn_binding_is_confirmed_by_named_interface_or_vpn_ip() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(temp.path().to_path_buf(), None);
    config.p2p_bind_interface = Some("hide.me".to_string());

    assert!(config.vpn_binding_confirmed(
        "10.44.55.66".parse().unwrap(),
        &[iface("hide.me", "10.44.55.66")]
    ));

    let ip_only = config_with_server(
        temp.path().to_path_buf(),
        Some("10.44.55.66".parse().unwrap()),
    );
    assert!(ip_only.vpn_binding_confirmed(
        "10.44.55.66".parse().unwrap(),
        &[iface_with_vpn("hide.me", "10.44.55.66", true)]
    ));
}

#[test]
fn vpn_binding_does_not_treat_mismatched_name_as_confirmed() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    config.p2p_bind_interface = Some("hide.me".to_string());

    assert!(!config.vpn_binding_confirmed(
        "192.0.2.10".parse().unwrap(),
        &[
            iface("Ethernet", "192.0.2.10"),
            iface_with_vpn("hide.me", "10.44.55.66", true),
        ],
    ));
}

#[test]
fn ed2k_network_config_derives_nat_bind_from_configured_p2p_bind_ip() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    config.nat.enabled = true;

    let network = config
        .ed2k_network_config(&metadata_store(&config))
        .unwrap()
        .unwrap();

    assert_eq!(network.nat_config.bind_ip.as_deref(), Some("192.0.2.10"));
    assert!(network.nat_config.enabled);
}

#[test]
fn ed2k_network_config_honors_explicit_nat_bind_ip() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    config.nat.bind_ip = Some("198.51.100.20".to_string());

    let network = config
        .ed2k_network_config(&metadata_store(&config))
        .unwrap()
        .unwrap();

    assert_eq!(network.nat_config.bind_ip.as_deref(), Some("198.51.100.20"));
}

#[test]
fn ed2k_network_config_passes_configured_kad_bootstrap_nodes() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    config.kad.bootstrap_nodes = vec!["192.0.2.30:41002".to_string()];
    config.kad.bootstrap_min_routing_contacts = 0;
    config.kad.republish_interval_secs = 0;
    config.kad.publish_contact_fanout = 0;
    config.kad.hello_intro_interval_secs = 0;
    config.kad.hello_intro_fanout = 0;

    let network = config
        .ed2k_network_config(&metadata_store(&config))
        .unwrap()
        .unwrap();

    assert_eq!(network.kad_bootstrap_nodes, ["192.0.2.30:41002"]);
    assert_eq!(network.kad_bootstrap_min_routing_contacts, 1);
    assert_eq!(network.kad_republish_interval_secs, 1);
    assert_eq!(network.kad_publish_contact_fanout, 1);
    assert_eq!(network.kad_hello_intro_interval_secs, 1);
    assert_eq!(network.kad_hello_intro_fanout, 0);
}

#[tokio::test]
async fn graceful_teardown_disconnects_and_is_idempotent() {
    // Mirrors what `run()` does after the REST server stops on any shutdown
    // trigger (REST shutdown, Ctrl-C, SIGTERM): the ordered network teardown
    // runs `disconnect_ed2k` (NAT release + task abort + lease reset). Signals
    // can't be raised deterministically in a unit test, so this drives the
    // teardown function directly and asserts it (a) leaves ed2k disconnected,
    // (b) is safe to call twice (idempotent, no double-free / panic), and
    // (c) completes well within the bounded timeout.
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());

    let teardown = async {
        graceful_teardown(&core).await;
        // Second call must not panic or hang: the runtime is already gone.
        graceful_teardown(&core).await;
    };
    tokio::time::timeout(SHUTDOWN_TEARDOWN_TIMEOUT * 3, teardown)
        .await
        .expect("graceful teardown must finish within the bounded timeout");

    assert!(
        !core.status().await.ed2k.connected,
        "ed2k must be disconnected after graceful teardown"
    );
}
