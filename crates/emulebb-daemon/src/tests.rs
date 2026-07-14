use super::*;
use emulebb_ed2k::{InterfaceAddressFamily, NetworkInterface, NetworkInterfaceAddress};

fn metadata_store(config: &DaemonConfig) -> MetadataStore {
    MetadataStore::open(config.metadata_path()).unwrap()
}

fn persist_test_server(config: &DaemonConfig) {
    metadata_store(config)
        .upsert_server(&emulebb_metadata::MetadataServer {
            endpoint: "192.0.2.20:4661".to_string(),
            address: "192.0.2.20".to_string(),
            port: 4661,
            name: "test server".to_string(),
            description: String::new(),
            priority: "normal".to_string(),
            static_server: false,
            enabled: true,
            failed_count: 0,
            ping_ms: None,
            users: 0,
            files: 0,
            soft_files: 0,
            hard_files: 0,
            version: String::new(),
        })
        .unwrap();
}

fn config_with_ed2k_network(runtime_dir: PathBuf, p2p_bind_ip: Option<Ipv4Addr>) -> DaemonConfig {
    let ed2k = Ed2kRuntimeConfig {
        listen_port: Some(41001),
        ..Ed2kRuntimeConfig::default()
    };
    DaemonConfig {
        runtime_dir,
        p2p_bind_ip,
        kad: KadSettings {
            listen_port: Some(41002),
            ..KadSettings::default()
        },
        ed2k,
        ..DaemonConfig::default()
    }
}

fn config_with_server(runtime_dir: PathBuf, p2p_bind_ip: Option<Ipv4Addr>) -> DaemonConfig {
    let config = config_with_ed2k_network(runtime_dir, p2p_bind_ip);
    persist_test_server(&config);
    config
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

fn iface_with_description(name: &str, description: &str, ip: &str) -> NetworkInterface {
    NetworkInterface {
        description: Some(description.to_string()),
        ..iface(name, ip)
    }
}

fn write_bootstrap_config(dir: &std::path::Path) -> PathBuf {
    let config_path = dir.join("emulebb-rust.toml");
    let runtime_dir = dir.join("runtime");
    fs::create_dir_all(&runtime_dir).unwrap();
    let runtime_dir_text = runtime_dir.to_string_lossy().replace('\\', "/");
    fs::write(
        &config_path,
        format!(
            r#"
runtimeDir = "{runtime_dir_text}"

[rest]
bindAddr = "192.0.2.10:13301"
apiKey = "secret"
"#
        ),
    )
    .unwrap();
    config_path
}

fn put_setting(metadata: &MetadataStore, section: &str, key: &str, value: serde_json::Value) {
    let value_json = serde_json::to_string(&value).unwrap();
    metadata
        .put_setting_json(section, key, &value_json)
        .unwrap();
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
#[expect(
    clippy::cognitive_complexity,
    reason = "linear protocol orchestration flow"
)]
fn load_parses_bootstrap_toml_and_db_runtime_config() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = write_bootstrap_config(temp.path());
    let runtime_dir = temp.path().join("runtime");
    let metadata = MetadataStore::open(runtime_dir.join("metadata.sqlite")).unwrap();
    put_setting(
        &metadata,
        SECTION_DAEMON_RUNTIME,
        "p2pBindIp",
        serde_json::json!("192.0.2.10"),
    );
    put_setting(
        &metadata,
        SECTION_DAEMON_RUNTIME,
        "p2pBindInterface",
        serde_json::json!("Ethernet"),
    );
    put_setting(
        &metadata,
        SECTION_KAD,
        "listenPort",
        serde_json::json!(41002),
    );
    metadata
        .replace_kad_bootstrap_endpoints(&["192.0.2.30:41002".to_string()])
        .unwrap();
    put_setting(
        &metadata,
        SECTION_KAD,
        "bootstrapMinRoutingContacts",
        serde_json::json!(3),
    );
    put_setting(
        &metadata,
        SECTION_KAD,
        "localStoreSourceTtlSecs",
        serde_json::json!(21600),
    );
    put_setting(
        &metadata,
        SECTION_KAD,
        "localStoreKeywordCapacity",
        serde_json::json!(20000),
    );
    put_setting(
        &metadata,
        SECTION_KAD,
        "localStoreSourceCapacity",
        serde_json::json!(20000),
    );
    put_setting(
        &metadata,
        SECTION_KAD,
        "localStoreNotesCapacity",
        serde_json::json!(5000),
    );
    put_setting(
        &metadata,
        SECTION_KAD,
        "republishIntervalSecs",
        serde_json::json!(120),
    );
    put_setting(
        &metadata,
        SECTION_KAD,
        "publishContactFanout",
        serde_json::json!(5),
    );
    put_setting(
        &metadata,
        SECTION_ED2K,
        "listenPort",
        serde_json::json!(41001),
    );
    put_setting(
        &metadata,
        SECTION_ED2K,
        "connectTimeoutSecs",
        serde_json::json!(1),
    );
    put_setting(
        &metadata,
        SECTION_ED2K,
        "reconnectIntervalSecs",
        serde_json::json!(60),
    );
    put_setting(
        &metadata,
        SECTION_ED2K,
        "publishEmuleRustIdentity",
        serde_json::json!(true),
    );
    put_setting(&metadata, SECTION_NAT, "enabled", serde_json::json!(true));
    put_setting(
        &metadata,
        SECTION_NAT,
        "requireInitialMapping",
        serde_json::json!(false),
    );
    put_setting(
        &metadata,
        SECTION_NAT,
        "backendOrder",
        serde_json::json!(["upnp_miniupnpc"]),
    );
    put_setting(
        &metadata,
        SECTION_NAT,
        "bindIp",
        serde_json::json!("192.0.2.11"),
    );
    put_setting(
        &metadata,
        SECTION_NAT,
        "igdIp",
        serde_json::json!("192.0.2.1"),
    );
    put_setting(
        &metadata,
        SECTION_NAT,
        "minissdpdSocket",
        serde_json::json!("/var/run/minissdpd.sock"),
    );
    put_setting(
        &metadata,
        SECTION_NAT,
        "ssdpLocalPort",
        serde_json::json!(1901),
    );
    put_setting(
        &metadata,
        SECTION_NAT,
        "discoveryTimeoutSecs",
        serde_json::json!(7),
    );
    put_setting(
        &metadata,
        SECTION_NAT,
        "leaseDurationSecs",
        serde_json::json!(1200),
    );
    put_setting(
        &metadata,
        SECTION_NAT,
        "renewMarginSecs",
        serde_json::json!(120),
    );
    put_setting(
        &metadata,
        SECTION_NAT,
        "externalIpOverride",
        serde_json::json!("203.0.113.10"),
    );

    let config = DaemonConfig::load(Some(config_path)).unwrap();

    assert_eq!(config.runtime_dir, runtime_dir);
    assert_eq!(config.p2p_bind_ip, Some("192.0.2.10".parse().unwrap()));
    assert_eq!(config.p2p_bind_interface.as_deref(), Some("Ethernet"));
    assert_eq!(
        config.rest.bind_addr,
        Some("192.0.2.10:13301".parse().unwrap())
    );
    assert_eq!(config.kad.listen_port, Some(41002));
    assert_eq!(config.kad_bootstrap_endpoints, ["192.0.2.30:41002"]);
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
    assert_eq!(config.kad.snoop_queue_dedup_window_secs, 28_800);
    assert_eq!(config.kad.snoop_queue_general_max_queries_per_600s, 24);
    assert_eq!(config.kad.snoop_queue_general_drain_cooldown_secs, 900);
    assert_eq!(config.kad.snoop_queue_source_max_queries_per_600s, 60);
    assert_eq!(config.kad.snoop_queue_source_drain_cooldown_secs, 300);
    assert_eq!(config.kad.snoop_queue_source_stop_after_results, 2);
    assert_eq!(config.ed2k.listen_port, Some(41001));
    assert!(config.ed2k.server_endpoints.is_empty());
    assert_eq!(config.ed2k.connect_timeout_secs, 1);
    assert_eq!(config.ed2k.reconnect_interval_secs, 60);
    assert!(config.ed2k.enable_udp_reask);
    assert!(config.ed2k.publish_emule_rust_identity);
    assert!(config.nat.enabled);
    assert!(!config.nat.require_initial_mapping);
    assert_eq!(config.nat.backend_order, ["upnp_miniupnpc".to_string()]);
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
fn load_uses_default_db_runtime_config_when_missing() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = write_bootstrap_config(temp.path());

    let config = DaemonConfig::load(Some(config_path)).unwrap();
    let metadata = MetadataStore::open(config.metadata_path()).unwrap();

    assert!(!metadata.has_settings_section(SECTION_ED2K).unwrap());
    assert_eq!(config.ed2k.listen_port, None);
}

#[test]
fn default_ed2k_settings_match_runtime_config_defaults() {
    assert_eq!(
        ed2k_runtime_config_from_settings(Ed2kSettings::default()),
        Ed2kRuntimeConfig::default()
    );
}

#[test]
fn default_upload_queue_settings_match_runtime_config_defaults() {
    assert_eq!(
        ed2k_upload_queue_runtime_config_from_settings(Ed2kUploadQueueSettings::default()),
        Ed2kUploadQueueRuntimeConfig::default()
    );
}

#[test]
fn default_nat_settings_match_runtime_config_defaults() {
    assert_eq!(
        nat_config_from_settings(NatSettings::default()),
        NatConfig::default()
    );
}

#[test]
fn load_rejects_runtime_fields_in_bootstrap_toml() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("emulebb-rust.toml");
    let runtime_dir = temp.path().join("runtime");
    fs::create_dir_all(&runtime_dir).unwrap();
    let runtime_dir_text = runtime_dir.to_string_lossy().replace('\\', "/");
    fs::write(
        &config_path,
        format!(
            r#"
runtimeDir = "{runtime_dir_text}"
p2pBindIp = "192.0.2.10"

[rest]
bindAddr = "192.0.2.10:13301"
apiKey = "secret"

[ed2k]
listenPort = 41001
"#
        ),
    )
    .unwrap();

    let error = DaemonConfig::load(Some(config_path)).unwrap_err();
    assert!(
        format!("{error:#}").contains("unknown field"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn load_rejects_retired_nat_backend_from_db_runtime_config() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = write_bootstrap_config(temp.path());
    let metadata =
        MetadataStore::open(temp.path().join("runtime").join("metadata.sqlite")).unwrap();
    put_setting(
        &metadata,
        SECTION_NAT,
        "backendOrder",
        serde_json::json!(["upnp_rupnp"]),
    );

    let error = DaemonConfig::load(Some(config_path)).unwrap_err();
    assert!(
        error.to_string().contains("invalid NAT config"),
        "unexpected error: {error:#}"
    );
    assert!(
        format!("{error:#}").contains("remove retired backend \"upnp_rupnp\""),
        "unexpected error: {error:#}"
    );
}

#[test]
fn load_rejects_db_runtime_server_endpoints() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = write_bootstrap_config(temp.path());
    let metadata =
        MetadataStore::open(temp.path().join("runtime").join("metadata.sqlite")).unwrap();
    put_setting(
        &metadata,
        SECTION_ED2K,
        "serverEndpoints",
        serde_json::json!(["192.0.2.20:4661"]),
    );

    let error = DaemonConfig::load(Some(config_path)).unwrap_err();

    assert!(
        error.to_string().contains("failed to load ed2k settings"),
        "unexpected error: {error:#}"
    );
    assert!(
        format!("{error:#}").contains("unknown field `serverEndpoints`"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn load_rejects_db_runtime_server_entries() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = write_bootstrap_config(temp.path());
    let metadata =
        MetadataStore::open(temp.path().join("runtime").join("metadata.sqlite")).unwrap();
    put_setting(
        &metadata,
        SECTION_ED2K,
        "serverEntries",
        serde_json::json!([
            {
                "host": "192.0.2.20",
                "port": 4661,
                "name": "emulebb-local-e2e"
            }
        ]),
    );

    let error = DaemonConfig::load(Some(config_path)).unwrap_err();

    assert!(
        format!("{error:#}").contains("unknown field `serverEntries`"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn load_rejects_legacy_toml_preferences_instead_of_migrating() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("emulebb-rust.toml");
    let runtime_dir = temp.path().join("runtime");
    fs::create_dir_all(&runtime_dir).unwrap();
    let runtime_dir_text = runtime_dir.to_string_lossy().replace('\\', "/");
    fs::write(
        &config_path,
        format!(
            r#"
runtimeDir = "{runtime_dir_text}"

[rest]
bindAddr = "192.0.2.10:13301"
apiKey = "secret"

[preferences]
autoConnect = false
"#,
        ),
    )
    .unwrap();

    let error = DaemonConfig::load(Some(config_path)).unwrap_err();
    assert!(
        format!("{error:#}").contains("unknown field"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn kad_local_store_config_is_config_driven_and_clamped() {
    let config = DaemonConfig {
        kad: KadSettings {
            listen_port: Some(41002),
            local_store_enabled: false,
            local_store_keyword_ttl_secs: 0,
            local_store_source_ttl_secs: 0,
            local_store_notes_ttl_secs: 0,
            local_store_keyword_capacity: 0,
            local_store_source_capacity: 0,
            local_store_notes_capacity: 0,
            ..KadSettings::default()
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
fn kad_local_store_defaults_follow_index_defaults() {
    let defaults = KadLocalStoreConfig::default();
    let config = kad_local_store_config(&KadSettings::default());

    assert_eq!(config.keyword_capacity, defaults.keyword_capacity);
    assert_eq!(config.source_capacity, defaults.source_capacity);
    assert_eq!(config.notes_capacity, defaults.notes_capacity);
    assert_eq!(
        config.source_per_file_capacity,
        defaults.source_per_file_capacity
    );
    assert_eq!(
        config.notes_per_file_capacity,
        defaults.notes_per_file_capacity
    );
}

#[test]
fn kad_snoop_queue_config_is_config_driven_and_clamped() {
    let config = DaemonConfig {
        kad: KadSettings {
            listen_port: Some(41002),
            snoop_queue_dedup_window_secs: 0,
            snoop_queue_general_max_queries_per_600s: 0,
            snoop_queue_general_drain_cooldown_secs: 0,
            snoop_queue_source_max_queries_per_600s: 0,
            snoop_queue_source_drain_cooldown_secs: 0,
            snoop_queue_source_stop_after_results: 0,
            ..KadSettings::default()
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
    assert_eq!(network.kad_bootstrap_endpoints, Vec::<String>::new());
    assert_eq!(network.kad_bootstrap_min_routing_contacts, 10);
    assert!(network.kad_publish_shared_files);
    assert_eq!(network.kad_republish_interval_secs, 1_800);
    assert_eq!(network.kad_publish_contact_fanout, 10);
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
fn p2p_bind_interface_only_keeps_no_configured_ip_override() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(temp.path().to_path_buf(), None);
    config.p2p_bind_interface = Some("hide.me".to_string());

    let bind_ip = config
        .resolve_p2p_bind_ip_from_interfaces(&[iface("hide.me", "10.44.55.66")])
        .unwrap();

    assert_eq!(bind_ip, "10.44.55.66".parse::<Ipv4Addr>().unwrap());
    assert_eq!(config.p2p_bind_ip, None);
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
fn p2p_bind_interface_matches_name_or_description_token() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(temp.path().to_path_buf(), None);
    config.p2p_bind_interface = Some("hide.me".to_string());

    let bind_ip = config
        .resolve_p2p_bind_ip_from_interfaces(&[iface_with_description(
            "Ethernet 7",
            "hide.me VPN Adapter",
            "10.44.55.66",
        )])
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
fn p2p_bind_ip_and_interface_prefers_current_interface_ip() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
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
fn ed2k_network_config_stores_resolved_interface_bind_ip() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    config.p2p_bind_interface = Some("hide.me".to_string());
    config.nat.enabled = false;

    let network = config
        .ed2k_network_config_from_interfaces(
            &metadata_store(&config),
            &[
                iface("Ethernet", "192.0.2.10"),
                iface("hide.me", "10.44.55.66"),
            ],
        )
        .unwrap()
        .unwrap();

    assert_eq!(network.bind_ip, "10.44.55.66".parse::<Ipv4Addr>().unwrap());
    assert_eq!(
        network.p2p_bind_ip,
        Some("10.44.55.66".parse::<Ipv4Addr>().unwrap())
    );
    assert!(network.vpn_interface_bound);
}

#[test]
fn p2p_bind_ip_and_interface_mismatch_starts_when_vpn_guard_blocks_p2p() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    config.p2p_bind_interface = Some("hide.me".to_string());
    config.vpn_guard.enabled = true;
    config.vpn_guard.mode = "block".to_string();

    let bind_ip = config
        .resolve_p2p_bind_ip_from_interfaces(&[iface("Ethernet", "192.0.2.10")])
        .unwrap();

    assert_eq!(bind_ip, "192.0.2.10".parse::<Ipv4Addr>().unwrap());
    assert!(!config.vpn_binding_confirmed(bind_ip, &[iface("Ethernet", "192.0.2.10")]));
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
    config.p2p_bind_interface = Some("HIDE.ME".to_string());

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
    assert!(network.nat_config.require_initial_mapping);
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
fn ed2k_network_config_passes_configured_kad_bootstrap_endpoints() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    config.kad_bootstrap_endpoints = vec!["192.0.2.30:41002".to_string()];
    config.kad.bootstrap_min_routing_contacts = 0;
    config.kad.republish_interval_secs = 0;
    config.kad.publish_contact_fanout = 0;

    let network = config
        .ed2k_network_config(&metadata_store(&config))
        .unwrap()
        .unwrap();

    assert_eq!(network.kad_bootstrap_endpoints, ["192.0.2.30:41002"]);
    assert_eq!(network.kad_bootstrap_min_routing_contacts, 1);
    assert_eq!(network.kad_republish_interval_secs, 1);
    assert_eq!(network.kad_publish_contact_fanout, 1);
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
