use super::*;
use emulebb_ed2k::{InterfaceAddressFamily, NetworkInterface, NetworkInterfaceAddress};
use emulebb_settings::{BOOTSTRAP_SETTINGS_SURFACE, SettingSurfaceClass};
use std::collections::BTreeSet;
use std::io::Write;

fn metadata_store(profile: &DaemonProfile) -> MetadataStore {
    MetadataStore::open(profile.metadata_path()).unwrap()
}

#[test]
fn build_identity_is_well_formed() {
    assert!(!BUILD_VERSION.is_empty());
    assert!(matches!(
        BUILD_CHANNEL,
        "development" | "candidate" | "beta" | "nightly"
    ));
    assert!(
        BUILD_SOURCE_REVISION == "unknown"
            || (BUILD_SOURCE_REVISION.len() == 40
                && BUILD_SOURCE_REVISION
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
    );
}

#[tokio::test]
async fn automatic_server_selection_prefers_the_largest_enabled_population() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let mut smaller = core
        .add_server(emulebb_core::ServerCreate {
            address: "192.0.2.10".to_string(),
            port: 4661,
            name: Some("smaller".to_string()),
            priority: None,
            static_server: None,
            connect: None,
        })
        .await
        .unwrap();
    smaller.users = 10_000;
    smaller.files = 1_000_000;
    let mut larger = core
        .add_server(emulebb_core::ServerCreate {
            address: "192.0.2.20".to_string(),
            port: 4661,
            name: Some("larger".to_string()),
            priority: None,
            static_server: None,
            connect: None,
        })
        .await
        .unwrap();
    larger.users = 50_000;
    larger.files = 500_000;
    let mut disabled = larger.clone();
    disabled.endpoint = "192.0.2.30:4661".to_string();
    disabled.users = 100_000;
    disabled.enabled = false;

    let selected = ranked_popular_enabled_servers(vec![smaller, larger, disabled])
        .into_iter()
        .next()
        .unwrap();

    assert_eq!(selected.endpoint, "192.0.2.20:4661");
}

fn collect_leaf_paths(prefix: &str, value: &serde_json::Value, output: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(object) if !object.is_empty() => {
            for (key, nested) in object {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                collect_leaf_paths(&path, nested, output);
            }
        }
        _ => {
            output.insert(prefix.to_string());
        }
    }
}

fn persist_test_server(profile: &DaemonProfile) {
    metadata_store(profile)
        .upsert_server(&emulebb_metadata::MetadataServer {
            address: "192.0.2.20".to_string(),
            port: 4661,
            name: "test server".to_string(),
            description: String::new(),
            server_priority: "normal".to_string(),
            static_server: false,
            enabled: true,
            failed_count: 0,
            ping_ms: None,
            users: 0,
            files: 0,
            max_users: 0,
            low_id_users: 0,
            soft_files: 0,
            hard_files: 0,
            version: String::new(),
            dynamic_host: String::new(),
            auxiliary_ports: Vec::new(),
            obfuscation_tcp_port: None,
            obfuscation_udp_port: None,
            udp_flags: None,
            udp_key: None,
            udp_key_ip: None,
        })
        .unwrap();
}

fn profile_with_ed2k_network(profile_dir: PathBuf, p2p_bind_ip: Option<Ipv4Addr>) -> DaemonProfile {
    let ed2k = Ed2kRuntimeConfig {
        listen_port: Some(41001),
        ..Ed2kRuntimeConfig::default()
    };
    DaemonProfile {
        profile_dir,
        p2p_bind_ip,
        kad: KadRuntimePolicy {
            listen_port: Some(41002),
            ..KadRuntimePolicy::default()
        },
        ed2k,
        ..DaemonProfile::default()
    }
}

fn profile_with_server(profile_dir: PathBuf, p2p_bind_ip: Option<Ipv4Addr>) -> DaemonProfile {
    let profile = profile_with_ed2k_network(profile_dir, p2p_bind_ip);
    persist_test_server(&profile);
    profile
}

fn profile_with_rest_bind(profile_dir: PathBuf, bind_addr: Option<SocketAddr>) -> DaemonProfile {
    DaemonProfile {
        profile_dir,
        rest: RestBootstrapSettings {
            bind_addr,
            ..RestBootstrapSettings::default()
        },
        ..DaemonProfile::default()
    }
}

fn profile_with_web_root(profile_dir: PathBuf, web_root_dir: Option<PathBuf>) -> DaemonProfile {
    DaemonProfile {
        profile_dir,
        rest: RestBootstrapSettings {
            web_root_dir,
            ..RestBootstrapSettings::default()
        },
        ..DaemonProfile::default()
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

fn write_bootstrap_settings(dir: &std::path::Path) -> PathBuf {
    let profile_dir = dir.join("profile");
    fs::create_dir_all(&profile_dir).unwrap();
    let settings_path = profile_dir.join(PROFILE_SETTINGS_FILE);
    write_private_settings(
        &settings_path,
        r#"
[rest]
bind_addr = "192.0.2.10:13301"
api_key = "secret"
"#,
    );
    profile_dir
}

fn write_private_settings(path: &std::path::Path, contents: &str) {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
}

fn edit_settings(metadata: &MetadataStore, values: serde_json::Value) {
    metadata
        .edit_app_settings(&emulebb_settings::product::SettingsEdit {
            set: serde_json::from_value(values).unwrap(),
            ..Default::default()
        })
        .unwrap();
}

fn host_storage(incoming: PathBuf, temp: PathBuf, shared: PathBuf) -> InitialProfileStorage {
    InitialProfileStorage {
        incoming_dir: incoming,
        temp_dir: temp,
        shared_dir: shared,
    }
}

#[cfg(unix)]
#[test]
fn retargeted_profile_alias_keeps_io_in_the_leased_directory() {
    use std::os::unix::fs::symlink;

    let target = PathBuf::from(
        env::var_os("CARGO_TARGET_DIR").expect("profile ownership tests require CARGO_TARGET_DIR"),
    );
    assert!(target.is_absolute(), "CARGO_TARGET_DIR must be absolute");
    let scratch = target.join("tmp/profile-ownership-tests");
    fs::create_dir_all(&scratch).unwrap();
    let temporary = tempfile::tempdir_in(scratch).unwrap();
    let leased = temporary.path().join("leased");
    let other = temporary.path().join("other");
    let alias = temporary.path().join("alias");
    fs::create_dir(&leased).unwrap();
    fs::create_dir(&other).unwrap();
    symlink(&leased, &alias).unwrap();

    let lease = ProfileLease::acquire(&alias, false).unwrap();
    fs::remove_file(&alias).unwrap();
    symlink(&other, &alias).unwrap();
    assert_eq!(
        fs::canonicalize(&alias).unwrap(),
        fs::canonicalize(&other).unwrap()
    );

    let profile = DaemonProfile::load_owned(alias.clone(), lease, None).unwrap();
    let metadata = profile.open_metadata_store().unwrap();
    edit_settings(
        &metadata,
        serde_json::json!({"network":{"nickname":"Sample Client"}}),
    );
    let leased = fs::canonicalize(leased).unwrap();
    assert_eq!(profile.profile_dir, alias);
    assert!(leased.join(PROFILE_SETTINGS_FILE).is_file());
    assert_eq!(profile.metadata_path(), leased.join(PROFILE_METADATA_FILE));
    assert!(profile.metadata_path().is_file());
    assert_eq!(profile.transfer_root(), leased.join("temp"));
    assert_eq!(profile.incoming_dir(), leased.join("incoming"));
    assert!(fs::read_dir(other).unwrap().next().is_none());
}

#[test]
fn default_profile_bootstrap_listens_on_all_ipv4_interfaces_and_seeds_network_ports() {
    let temp = tempfile::tempdir().unwrap();
    let profile_dir = temp.path().join("profile");
    let settings_path = profile_dir.join(PROFILE_SETTINGS_FILE);

    create_private_profile_dir(&profile_dir).unwrap();
    create_default_profile_bootstrap(&profile_dir, &settings_path).unwrap();
    let text = fs::read_to_string(&settings_path).unwrap();
    let bootstrap: DaemonBootstrapSettings = toml::from_str(&text).unwrap();
    assert_eq!(
        bootstrap.rest.bind_addr,
        Some("0.0.0.0:20017".parse().unwrap())
    );
    assert_eq!(
        bootstrap.rest.api_key,
        "change_me_123change_me_123change_me_123"
    );
    let profile = DaemonProfile {
        rest: bootstrap.rest,
        ..Default::default()
    };
    profile.validate_rest_api_key().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(&profile_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&settings_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let metadata = MetadataStore::open(profile_dir.join(PROFILE_METADATA_FILE)).unwrap();
    let snapshot = metadata.load_app_settings().unwrap();
    assert_eq!(snapshot.revision.get(), 1);
    assert_eq!(snapshot.saved.values().network.p2p.tcp_port, 20019);
    assert_eq!(snapshot.saved.values().network.p2p.udp_port, 20020);
}

#[cfg(unix)]
#[test]
fn load_rejects_group_or_world_readable_bootstrap_settings() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let profile_dir = write_bootstrap_settings(temp.path());
    let settings_path = profile_dir.join(PROFILE_SETTINGS_FILE);
    fs::set_permissions(&settings_path, fs::Permissions::from_mode(0o640)).unwrap();

    let error = DaemonProfile::load(Some(profile_dir)).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("requires owner-only permissions")
    );
    assert!(error.to_string().contains("chmod 600"));
}

#[test]
fn bootstrap_settings_surface_inventory_covers_serialized_toml_fields() {
    let mut expected = BTreeSet::new();
    collect_leaf_paths(
        "",
        &serde_json::to_value(DaemonBootstrapSettings::default()).unwrap(),
        &mut expected,
    );
    let actual = BOOTSTRAP_SETTINGS_SURFACE
        .iter()
        .map(|entry| entry.path.to_string())
        .collect::<BTreeSet<_>>();

    assert_eq!(actual, expected);
    assert!(
        BOOTSTRAP_SETTINGS_SURFACE
            .iter()
            .all(|entry| entry.class == SettingSurfaceClass::BootstrapOnly)
    );
}

#[test]
fn packaged_bootstrap_loads_and_seeds_a_fresh_database() {
    let temp = tempfile::tempdir().unwrap();
    let profile_dir = temp.path().join("profile");
    fs::create_dir(&profile_dir).unwrap();
    let settings_path = profile_dir.join(PROFILE_SETTINGS_FILE);
    write_private_settings(&settings_path, DEFAULT_BOOTSTRAP_SETTINGS);

    let profile = DaemonProfile::load(Some(profile_dir)).unwrap();

    assert_eq!(
        profile.rest_bind_addr().unwrap(),
        "0.0.0.0:20017".parse().unwrap()
    );
    assert_eq!(
        profile.rest.api_key,
        "change_me_123change_me_123change_me_123"
    );
    profile.validate_rest_api_key().unwrap();
    assert_eq!(profile.ed2k.listen_port, Some(20019));
    assert_eq!(profile.kad.listen_port, Some(20020));
    assert_eq!(
        fs::read_to_string(settings_path).unwrap(),
        DEFAULT_BOOTSTRAP_SETTINGS
    );
}

#[test]
fn packaged_bootstrap_does_not_replace_existing_database_preferences() {
    let temp = tempfile::tempdir().unwrap();
    let profile_dir = temp.path().join("profile");
    fs::create_dir(&profile_dir).unwrap();
    write_private_settings(
        &profile_dir.join(PROFILE_SETTINGS_FILE),
        DEFAULT_BOOTSTRAP_SETTINGS,
    );
    {
        let metadata = MetadataStore::open(profile_dir.join(PROFILE_METADATA_FILE)).unwrap();
        edit_settings(
            &metadata,
            serde_json::json!({"network":{"p2p":{"tcpPort":20119,"udpPort":20120}}}),
        );
    }

    let profile = DaemonProfile::load(Some(profile_dir)).unwrap();

    assert_eq!(profile.ed2k.listen_port, Some(20119));
    assert_eq!(profile.kad.listen_port, Some(20120));
}

#[test]
fn bootstrap_parse_errors_do_not_echo_secret_source_lines() {
    let temp = tempfile::tempdir().unwrap();
    let profile_dir = temp.path().join("profile");
    fs::create_dir(&profile_dir).unwrap();
    let secret = "synthetic-private-key-not-for-diagnostics";
    write_private_settings(
        &profile_dir.join(PROFILE_SETTINGS_FILE),
        &format!("[rest]\nextension = \"{secret}\"\n"),
    );

    let error = DaemonProfile::load(Some(profile_dir)).unwrap_err();
    let diagnostic = format!("{error:#}");

    assert!(diagnostic.contains("unknown field"));
    assert!(!diagnostic.contains(secret));
}

#[test]
fn load_creates_a_fresh_explicit_profile_without_a_special_dot_case() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("missing-profile");

    let profile = DaemonProfile::load(Some(path.clone())).unwrap();
    assert_eq!(profile.profile_dir, path);
    assert!(profile.profile_dir.join(PROFILE_SETTINGS_FILE).is_file());
    assert!(profile.profile_dir.join(PROFILE_METADATA_FILE).is_file());
    assert_eq!(
        profile.rest.api_key,
        "change_me_123change_me_123change_me_123"
    );
}

#[test]
fn default_profile_candidate_is_the_executable_directory() {
    assert_eq!(
        default_profile_dir().unwrap(),
        env::current_exe().unwrap().parent().unwrap()
    );
}

#[test]
fn hosted_folder_defaults_are_canonical_and_never_reseed_operator_changes() {
    let base = tempfile::tempdir().unwrap();
    let directory = base.path().join("profile");
    let incoming = base.path().join("Incoming");
    let temp = base.path().join("Pieces");
    let shared = base.path().join("Shared");
    let profile = DaemonProfile::load_hosted(
        directory.clone(),
        host_storage(incoming.clone(), temp.clone(), shared.clone()),
    )
    .unwrap();
    assert_eq!(
        profile.incoming_dir(),
        PathBuf::from(emulebb_core::normal_path_display(
            incoming.canonicalize().unwrap()
        ))
    );
    assert_eq!(
        profile.transfer_root(),
        PathBuf::from(emulebb_core::normal_path_display(
            temp.canonicalize().unwrap()
        ))
    );
    let mut metadata = profile.open_metadata_store().unwrap();
    assert_eq!(metadata.shared_directory_roots().unwrap().len(), 1);
    let edited_incoming = base.path().join("operator-incoming");
    let edited_temp = base.path().join("operator-temp");
    edit_settings(
        &metadata,
        serde_json::json!({"storage":{"incomingDirectory":edited_incoming,"tempDirectory":edited_temp}}),
    );
    let before = metadata.load_app_settings().unwrap();
    metadata.replace_shared_directory_roots(&[]).unwrap();
    drop(metadata);
    drop(profile);
    let profile =
        DaemonProfile::load_hosted(directory, host_storage(incoming, temp, shared)).unwrap();
    assert_eq!(profile.incoming_dir(), edited_incoming);
    assert_eq!(profile.transfer_root(), edited_temp);
    let metadata = profile.open_metadata_store().unwrap();
    assert_eq!(metadata.load_app_settings().unwrap(), before);
    assert!(metadata.shared_directory_roots().unwrap().is_empty());
}

#[test]
fn hosted_defaults_do_not_reinterpret_an_existing_unconfigured_profile() {
    let base = tempfile::tempdir().unwrap();
    let directory = base.path().join("profile");
    drop(DaemonProfile::load(Some(directory.clone())).unwrap());
    let incoming = base.path().join("not-created-incoming");
    let temp = base.path().join("not-created-temp");
    let shared = base.path().join("not-created-shared");
    let profile = DaemonProfile::load_hosted(
        directory,
        host_storage(incoming.clone(), temp.clone(), shared.clone()),
    )
    .unwrap();
    assert_eq!(
        profile.incoming_dir(),
        profile.profile_io_dir().join("incoming")
    );
    assert_eq!(
        profile.transfer_root(),
        profile.profile_io_dir().join("temp")
    );
    assert!(!incoming.exists() && !temp.exists() && !shared.exists());
    assert!(
        profile
            .open_metadata_store()
            .unwrap()
            .shared_directory_roots()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn hosted_folder_initialization_retries_after_a_first_start_filesystem_failure() {
    let base = tempfile::tempdir().unwrap();
    let directory = base.path().join("profile");
    let incoming = base.path().join("Incoming");
    let temp = base.path().join("Pieces");
    let shared = base.path().join("Shared");
    fs::write(&shared, b"owned conflicting fixture").unwrap();
    assert!(
        DaemonProfile::load_hosted(
            directory.clone(),
            host_storage(incoming.clone(), temp.clone(), shared.clone())
        )
        .is_err()
    );
    fs::remove_file(&shared).unwrap();
    let profile = DaemonProfile::load_hosted(
        directory,
        host_storage(incoming.clone(), temp.clone(), shared),
    )
    .unwrap();
    assert_eq!(
        profile.incoming_dir(),
        PathBuf::from(emulebb_core::normal_path_display(
            incoming.canonicalize().unwrap()
        ))
    );
    assert_eq!(
        profile.transfer_root(),
        PathBuf::from(emulebb_core::normal_path_display(
            temp.canonicalize().unwrap()
        ))
    );
    assert_eq!(
        profile
            .open_metadata_store()
            .unwrap()
            .shared_directory_roots()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn load_for_import_creates_an_explicit_profile() {
    let temp = tempfile::tempdir().unwrap();
    let profile_dir = temp.path().join("fresh-import-profile");

    let profile = DaemonProfile::load_for_import(profile_dir.clone()).unwrap();

    assert_eq!(profile.profile_dir, profile_dir);
    assert!(profile.profile_dir.join(PROFILE_SETTINGS_FILE).is_file());
    assert!(profile.profile_dir.join(PROFILE_METADATA_FILE).is_file());
    assert_eq!(profile.ed2k.listen_port, Some(20019));
    assert_eq!(profile.kad.listen_port, Some(20020));
}

#[test]
fn load_parses_bootstrap_and_canonical_sqlite_settings() {
    let base = tempfile::tempdir().unwrap();
    let directory = write_bootstrap_settings(base.path());
    let metadata = MetadataStore::open(directory.join(PROFILE_METADATA_FILE)).unwrap();
    edit_settings(
        &metadata,
        serde_json::json!({
            "network":{"nickname":"Sample Client","p2p":{"bindIp":"127.0.0.1","tcpPort":42001,"udpPort":42002},
              "connections":{"maxConnections":321,"maxNewConnectionsPerFiveSeconds":20,"maxHalfOpenConnections":10,"connectTimeoutSeconds":31,"callbackTimeoutSeconds":46},
              "nat":{"enabled":false,"backendOrder":["upnp"]},"servers":{"autoReconnect":false,"safeConnect":true,"usePriorities":false,"staticOnly":true,"keepaliveMinutes":45}},
            "transfers":{"downloadLimitBytesPerSecond":2097152,"uploadLimitBytesPerSecond":1048576,"maxParallelDownloadPeers":3,
              "upload":{"baseSlots":4,"queueCapacity":3000,"sessionTransferPercent":75,"sessionTimeLimitSeconds":3600}},
            "storage":{"incomingDirectory":"finished","tempDirectory":"pieces"},
            "sharing":{"scanOnStartup":false,"kadPublishingEnabled":false},
            "security":{"obfuscationEnabled":false,"tcpErrorFloodDetection":{"intervalSeconds":120,"threshold":20}}
        }),
    );
    let before = metadata.load_app_settings().unwrap();
    drop(metadata);
    let profile = DaemonProfile::load(Some(directory)).unwrap();
    assert_eq!(
        profile.rest_bind_addr().unwrap(),
        "192.0.2.10:13301".parse().unwrap()
    );
    assert_eq!(profile.p2p_bind_ip, Some(Ipv4Addr::LOCALHOST));
    assert_eq!(profile.ed2k.listen_port, Some(42001));
    assert_eq!(profile.kad.listen_port, Some(42002));
    assert_eq!(profile.ed2k.nickname, "Sample Client");
    assert_eq!(profile.ed2k.max_connections, 321);
    assert_eq!(profile.ed2k.max_half_open_connections, 10);
    assert_eq!(profile.ed2k.connect_timeout_secs, 31);
    assert_eq!(profile.ed2k.callback_timeout_secs, 46);
    assert_eq!(profile.ed2k.download_limit_bytes_per_sec, 2097152);
    assert_eq!(
        profile.ed2k.upload_queue.upload_limit_bytes_per_sec,
        1048576
    );
    assert_eq!(profile.ed2k.upload_queue.base_slots, 4);
    assert_eq!(profile.ed2k.upload_queue.waiting_capacity, 3000);
    assert_eq!(profile.ed2k.upload_queue.session_transfer_percent, 75);
    assert_eq!(profile.ed2k.upload_queue.session_time_limit_secs, 3600);
    assert_eq!(profile.ed2k.max_parallel_download_peers, 3);
    assert!(!profile.ed2k.obfuscation_enabled);
    assert!(!profile.ed2k.reconnect_enabled);
    assert!(profile.ed2k.safe_server_connect);
    assert!(!profile.ed2k.use_server_priorities);
    assert!(profile.ed2k.auto_connect_static_only);
    assert_eq!(profile.ed2k.server_keepalive_minutes, 45);
    assert_eq!(profile.ed2k.tcp_error_flooder_interval_minutes, 2);
    assert_eq!(profile.ed2k.tcp_error_flooder_threshold, 20);
    assert!(!profile.nat.enabled);
    assert_eq!(
        profile.nat.backend_order,
        vec![emulebb_ed2k::nat::UPNP_MINIUPNPC_BACKEND]
    );
    assert!(!profile.initial_shared_directory_reload);
    assert!(!profile.kad.publish_shared_files_enabled);
    assert_eq!(
        profile.incoming_dir(),
        profile.profile_io_dir().join("finished")
    );
    assert_eq!(
        profile.transfer_root(),
        profile.profile_io_dir().join("pieces")
    );
    assert_eq!(
        profile
            .open_metadata_store()
            .unwrap()
            .load_app_settings()
            .unwrap(),
        before
    );
}

#[test]
fn transport_listeners_follow_the_admitted_networks() {
    for (ed2k, kad) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut values = SettingsValues::default();
        values.network.ed2k_enabled = ed2k;
        values.network.kad_enabled = kad;
        let projected = runtime_settings::from_values(values, Vec::new());
        assert!(projected.nat.validate().is_ok());
        assert_eq!(projected.ed2k.listen_port.is_some(), ed2k || kad);
        assert_eq!(projected.kad.listen_port.is_some(), ed2k || kad);
    }
}

#[test]
fn kad_internal_policy_bounds_local_store_resources() {
    let profile = DaemonProfile {
        kad: KadRuntimePolicy {
            listen_port: Some(41002),
            local_store_enabled: false,
            local_store_keyword_ttl_secs: 0,
            local_store_source_ttl_secs: 0,
            local_store_notes_ttl_secs: 0,
            local_store_keyword_capacity: 0,
            local_store_source_capacity: 0,
            local_store_notes_capacity: 0,
            ..KadRuntimePolicy::default()
        },
        ..DaemonProfile::default()
    };

    let local_store = profile.kad_local_store_config();

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
    let config = kad_local_store_config(&KadRuntimePolicy::default());

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
fn kad_passive_replay_uses_one_default_off_switch_and_fixed_queue_policy() {
    let temp = tempfile::tempdir().unwrap();
    let mut profile =
        profile_with_ed2k_network(temp.path().to_path_buf(), Some(Ipv4Addr::LOCALHOST));
    profile.kad.passive_replay_enabled = true;
    let config = profile
        .ed2k_network_config(&metadata_store(&profile))
        .unwrap()
        .unwrap();

    assert!(config.kad_passive_replay_enabled);
    assert_eq!(config.kad_snoop_queue, SnoopQueueConfig::default());
}

#[test]
fn rest_bind_addr_requires_configured_address() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile_with_rest_bind(temp.path().to_path_buf(), None);

    let error = profile.rest_bind_addr().unwrap_err().to_string();

    assert!(error.contains("rest.bind_addr is required"));
}

#[test]
fn rest_bind_addr_accepts_configured_loopback_address() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile_with_rest_bind(
        temp.path().to_path_buf(),
        Some("127.0.0.1:13301".parse().unwrap()),
    );

    assert_eq!(
        profile.rest_bind_addr().unwrap(),
        "127.0.0.1:13301".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn rest_bind_addr_accepts_configured_wildcard_address() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile_with_rest_bind(
        temp.path().to_path_buf(),
        Some("0.0.0.0:13301".parse().unwrap()),
    );

    assert_eq!(
        profile.rest_bind_addr().unwrap(),
        "0.0.0.0:13301".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn rest_bind_addr_accepts_configured_non_loopback_address() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile_with_rest_bind(
        temp.path().to_path_buf(),
        Some("192.0.2.10:13301".parse().unwrap()),
    );

    assert_eq!(
        profile.rest_bind_addr().unwrap(),
        "192.0.2.10:13301".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn rest_api_key_accepts_generated_length_secret() {
    let mut profile = DaemonProfile::default();
    profile.rest.api_key = "0123456789abcdef0123456789abcdef".to_string();

    profile.validate_rest_api_key().unwrap();
}

#[test]
fn rest_api_key_accepts_printable_keys_at_or_above_the_minimum() {
    for key in [
        "0123456789abcdef0123456789abcdef",
        "change_me_123change_me_123change_me_123",
    ] {
        let mut profile = DaemonProfile::default();
        profile.rest.api_key = key.to_string();
        profile.validate_rest_api_key().unwrap();
    }
}

#[test]
fn rest_api_key_rejects_empty_placeholder_short_and_whitespace_values() {
    for (api_key, expected) in [
        ("", "must not be empty"),
        ("change-me", "placeholder"),
        ("REPLACE_WITH_32_OR_MORE_RANDOM_CHARACTERS", "placeholder"),
        ("too-short", "at least 32 bytes"),
        (
            " 0123456789abcdef0123456789abcdef",
            "leading or trailing whitespace",
        ),
        (
            "0123456789abcdef 0123456789abcdef",
            "printable ASCII characters without spaces",
        ),
    ] {
        let mut profile = DaemonProfile::default();
        profile.rest.api_key = api_key.to_string();

        let error = profile.validate_rest_api_key().unwrap_err().to_string();

        assert!(error.contains(expected), "{api_key:?}: {error}");
    }
}

#[test]
fn web_root_dir_accepts_configured_relative_directory() {
    let temp = tempfile::tempdir().unwrap();
    let profile_dir = temp.path().join("profile");
    let web_root = profile_dir.join("webui");
    fs::create_dir_all(&web_root).unwrap();
    fs::write(web_root.join("index.html"), "<!doctype html>").unwrap();
    let profile = profile_with_web_root(profile_dir.clone(), Some(PathBuf::from("webui")));

    assert_eq!(profile.web_root_dir().unwrap(), Some(web_root));
}

#[test]
fn web_root_dir_rejects_configured_missing_directory() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile_with_web_root(
        temp.path().to_path_buf(),
        Some(PathBuf::from("missing-webui")),
    );

    let error = profile.web_root_dir().unwrap_err().to_string();

    assert!(error.contains("rest.web_root_dir must be an existing directory"));
}

#[test]
fn web_root_dir_rejects_configured_directory_without_index() {
    let temp = tempfile::tempdir().unwrap();
    let web_root = temp.path().join("webui");
    fs::create_dir_all(&web_root).unwrap();
    let profile = profile_with_web_root(temp.path().to_path_buf(), Some(web_root));

    let error = profile.web_root_dir().unwrap_err().to_string();

    assert!(error.contains("rest.web_root_dir must contain index.html"));
}

#[test]
fn ed2k_network_config_is_absent_without_listener_settings() {
    let temp = tempfile::tempdir().unwrap();
    let mut profile = DaemonProfile {
        profile_dir: temp.path().to_path_buf(),
        ..DaemonProfile::default()
    };

    profile.ed2k.listen_port = None;
    profile.kad.listen_port = None;
    assert!(
        profile
            .ed2k_network_config(&metadata_store(&profile))
            .unwrap()
            .is_none()
    );
}

#[test]
fn ed2k_network_config_requires_a_direct_default_route_or_explicit_bind() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile_with_server(temp.path().to_path_buf(), None);

    let error = profile
        .ed2k_network_config_from_interfaces(
            &metadata_store(&profile),
            &[iface("Offline", "192.0.2.10")],
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("no default-route IPv4 interface was detected")
    );
    assert_eq!(
        error.downcast_ref::<NetworkStartupError>(),
        Some(&NetworkStartupError::DefaultRouteUnavailable)
    );

    let mut first = iface("First", "192.0.2.10");
    first.has_default_route = true;
    let mut second = iface("Second", "198.51.100.10");
    second.has_default_route = true;
    let ambiguous = profile
        .ed2k_network_config_from_interfaces(&metadata_store(&profile), &[first, second])
        .unwrap_err();
    assert!(ambiguous.to_string().contains("multiple default-route"));
    assert!(ambiguous.downcast_ref::<NetworkStartupError>().is_none());
}

#[test]
fn ed2k_network_config_requires_configured_kad_listen_port() {
    let temp = tempfile::tempdir().unwrap();
    let mut profile = profile_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    profile.kad.listen_port = None;

    let error = profile
        .ed2k_network_config(&metadata_store(&profile))
        .unwrap_err()
        .to_string();
    assert!(error.contains("network.p2p.udpPort is required"));
}

#[test]
fn ed2k_network_config_requires_configured_ed2k_listen_port() {
    let temp = tempfile::tempdir().unwrap();
    let mut profile = profile_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    profile.ed2k.listen_port = None;

    let error = profile
        .ed2k_network_config(&metadata_store(&profile))
        .unwrap_err()
        .to_string();
    assert!(error.contains("network.p2p.tcpPort is required"));
}

#[test]
fn ed2k_network_config_accepts_configured_loopback_bind_ip() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile_with_server(temp.path().to_path_buf(), Some(Ipv4Addr::LOCALHOST));

    let network = profile
        .ed2k_network_config(&metadata_store(&profile))
        .unwrap()
        .unwrap();

    assert_eq!(network.bind_ip, Ipv4Addr::LOCALHOST);
    assert_eq!(network.listen_port, 41001);
    assert_eq!(network.kad_bind_addr, "127.0.0.1:41002".parse().unwrap());
}

#[test]
fn ed2k_network_config_accepts_configured_non_loopback_bind_ip() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );

    let network = profile
        .ed2k_network_config(&metadata_store(&profile))
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
    let store = metadata_store(&profile);
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
    assert!(!profile.profile_dir.join("ed2k-user-hash.hex").exists());
    assert!(!profile.profile_dir.join("ed2k-secure-ident.pk8").exists());
}

#[test]
fn network_config_reuses_the_persisted_user_identity() {
    let base = tempfile::tempdir().unwrap();
    let profile = profile_with_server(base.path().to_path_buf(), Some(Ipv4Addr::LOCALHOST));
    let metadata = metadata_store(&profile);
    let identity = create_user_hash();
    store_user_hash(&metadata, identity).unwrap();
    let config = profile
        .ed2k_network_config_from_interfaces(&metadata, &[iface("Loopback", "127.0.0.1")])
        .unwrap()
        .unwrap();
    assert_eq!(config.user_hash, identity);
    assert_eq!(load_or_create_user_hash(&metadata).unwrap(), identity);
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
    let mut profile = profile_with_server(temp.path().to_path_buf(), None);
    profile.p2p_bind_interface = Some("hide.me".to_string());

    let bind_ip = profile
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
    let mut profile = profile_with_server(temp.path().to_path_buf(), None);
    profile.p2p_bind_interface = Some("hide.me".to_string());

    let bind_ip = profile
        .resolve_p2p_bind_ip_from_interfaces(&[iface("hide.me", "10.44.55.66")])
        .unwrap();

    assert_eq!(bind_ip, "10.44.55.66".parse::<Ipv4Addr>().unwrap());
    assert_eq!(profile.p2p_bind_ip, None);
}

#[test]
fn direct_profile_uses_the_single_default_route_ipv4() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile_with_server(temp.path().to_path_buf(), None);
    let mut default_route = iface("Ethernet", "192.0.2.10");
    default_route.has_default_route = true;

    let bind_ip = profile
        .resolve_p2p_bind_ip_from_interfaces(&[iface("Offline", "198.51.100.20"), default_route])
        .unwrap();

    assert_eq!(bind_ip, "192.0.2.10".parse::<Ipv4Addr>().unwrap());
}

#[test]
fn p2p_bind_interface_matches_name_case_insensitively() {
    let temp = tempfile::tempdir().unwrap();
    let mut profile = profile_with_server(temp.path().to_path_buf(), None);
    profile.p2p_bind_interface = Some("HIDE.ME".to_string());

    let bind_ip = profile
        .resolve_p2p_bind_ip_from_interfaces(&[iface("hide.me", "10.44.55.66")])
        .unwrap();

    assert_eq!(bind_ip, "10.44.55.66".parse::<Ipv4Addr>().unwrap());
}

#[test]
fn p2p_bind_interface_matches_name_or_description_token() {
    let temp = tempfile::tempdir().unwrap();
    let mut profile = profile_with_server(temp.path().to_path_buf(), None);
    profile.p2p_bind_interface = Some("hide.me".to_string());

    let bind_ip = profile
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
    let mut profile = profile_with_server(temp.path().to_path_buf(), None);
    profile.p2p_bind_interface = Some("hide.me".to_string());

    let error = profile
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
    let mut profile = profile_with_server(
        temp.path().to_path_buf(),
        Some("10.44.55.66".parse().unwrap()),
    );
    profile.p2p_bind_interface = Some("hide.me".to_string());

    let bind_ip = profile
        .resolve_p2p_bind_ip_from_interfaces(&[iface("hide.me", "10.44.55.66")])
        .unwrap();

    assert_eq!(bind_ip, "10.44.55.66".parse::<Ipv4Addr>().unwrap());
}

#[test]
fn p2p_bind_ip_and_interface_prefers_current_interface_ip() {
    let temp = tempfile::tempdir().unwrap();
    let mut profile = profile_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    profile.p2p_bind_interface = Some("hide.me".to_string());

    let bind_ip = profile
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
    let mut profile = profile_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    profile.p2p_bind_interface = Some("hide.me".to_string());
    profile.nat.enabled = false;

    let network = profile
        .ed2k_network_config_from_interfaces(
            &metadata_store(&profile),
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
    let mut profile = profile_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    profile.p2p_bind_interface = Some("hide.me".to_string());
    profile.vpn_guard.enabled = true;
    profile.vpn_guard.mode = "block".to_string();

    let bind_ip = profile
        .resolve_p2p_bind_ip_from_interfaces(&[iface("Ethernet", "192.0.2.10")])
        .unwrap();

    assert_eq!(bind_ip, "192.0.2.10".parse::<Ipv4Addr>().unwrap());
    assert!(!profile.vpn_binding_confirmed(bind_ip, &[iface("Ethernet", "192.0.2.10")]));
}

#[test]
fn p2p_bind_interface_requires_matching_ipv4_interface() {
    let temp = tempfile::tempdir().unwrap();
    let mut profile = profile_with_server(temp.path().to_path_buf(), None);
    profile.p2p_bind_interface = Some("hide.me".to_string());

    let error = profile
        .resolve_p2p_bind_ip_from_interfaces(&[iface("Ethernet", "192.0.2.10")])
        .unwrap_err()
        .to_string();

    assert!(error.contains("p2pBindInterface"));
    assert!(error.contains("did not resolve"));
}

#[test]
fn vpn_binding_is_confirmed_by_named_interface_or_vpn_ip() {
    let temp = tempfile::tempdir().unwrap();
    let mut profile = profile_with_server(temp.path().to_path_buf(), None);
    profile.p2p_bind_interface = Some("HIDE.ME".to_string());

    assert!(profile.vpn_binding_confirmed(
        "10.44.55.66".parse().unwrap(),
        &[iface("hide.me", "10.44.55.66")]
    ));

    let ip_only = profile_with_server(
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
    let mut profile = profile_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    profile.p2p_bind_interface = Some("hide.me".to_string());

    assert!(!profile.vpn_binding_confirmed(
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
    let mut profile = profile_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    profile.nat.enabled = true;

    let network = profile
        .ed2k_network_config(&metadata_store(&profile))
        .unwrap()
        .unwrap();

    assert_eq!(network.nat_config.bind_ip.as_deref(), Some("192.0.2.10"));
    assert!(network.nat_config.enabled);
    assert!(!network.nat_config.require_initial_mapping);
}

#[test]
fn ed2k_network_config_honors_explicit_nat_bind_ip() {
    let temp = tempfile::tempdir().unwrap();
    let mut profile = profile_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    profile.nat.bind_ip = Some("198.51.100.20".to_string());

    let network = profile
        .ed2k_network_config(&metadata_store(&profile))
        .unwrap()
        .unwrap();

    assert_eq!(network.nat_config.bind_ip.as_deref(), Some("198.51.100.20"));
}

#[test]
fn ed2k_network_config_passes_configured_kad_bootstrap_endpoints() {
    let temp = tempfile::tempdir().unwrap();
    let mut profile = profile_with_server(
        temp.path().to_path_buf(),
        Some("192.0.2.10".parse().unwrap()),
    );
    profile.kad_bootstrap_endpoints = vec!["192.0.2.30:41002".to_string()];
    profile.kad.bootstrap_min_routing_contacts = 0;
    profile.kad.republish_interval_secs = 0;
    profile.kad.publish_contact_fanout = 0;

    let network = profile
        .ed2k_network_config(&metadata_store(&profile))
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
        graceful_teardown(&core).await.unwrap();
        // Second call must not panic or hang: the runtime is already gone.
        graceful_teardown(&core).await.unwrap();
    };
    tokio::time::timeout(SHUTDOWN_TEARDOWN_TIMEOUT * 3, teardown)
        .await
        .expect("graceful teardown must finish within the bounded timeout");

    assert!(
        !core.status().await.ed2k.connected,
        "ed2k must be disconnected after graceful teardown"
    );
}

#[tokio::test]
async fn teardown_sequence_finishes_snapshot_before_timeout_and_cleans_up_after_failure() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let phase = AtomicUsize::new(0);
    let result = teardown_sequence(
        async {
            phase.store(1, Ordering::SeqCst);
            Ok(())
        },
        async {
            assert_eq!(phase.load(Ordering::SeqCst), 1);
            phase.store(2, Ordering::SeqCst);
            std::future::pending::<Result<()>>().await
        },
        Duration::from_millis(20),
    )
    .await;
    assert!(result.is_ok());
    assert_eq!(phase.load(Ordering::SeqCst), 2);
    let result = teardown_sequence(
        async { anyhow::bail!("injected snapshot failure") },
        async {
            phase.store(3, Ordering::SeqCst);
            Ok(())
        },
        Duration::from_secs(1),
    )
    .await;
    assert!(result.unwrap_err().to_string().contains("final Kad state"));
    assert_eq!(phase.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn daemon_finalization_drains_owner_and_stops_network_after_snapshot_sql_failure() {
    let root = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join("tmp/daemon-kad-finalization")
        .join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&root).unwrap();
    let profile = profile_with_ed2k_network(root.clone(), Some(Ipv4Addr::LOCALHOST));
    let store = MetadataStore::open(profile.metadata_path()).unwrap();
    let mut network = profile
        .ed2k_network_config_from_interfaces(&store, &[iface("loopback", "127.0.0.1")])
        .unwrap()
        .unwrap();
    network.egress_route = emulebb_ed2k::networking::EgressRoute::DirectSystemRoute;
    network.vpn_guard.mode = "off".into();
    network.vpn_guard.enabled = false;
    network.p2p_bind_ip = None;
    network.p2p_bind_interface = None;
    network.kad_bind_addr = "127.0.0.1:0".parse().unwrap();
    network.listen_port = 0;
    network.nat_config.enabled = false;
    network.ed2k.server_endpoints = vec!["127.0.0.1:1".into()];
    let core = Arc::new(
        EmulebbCore::new_with_network(
            "test",
            FileIndex::from_metadata_store(store.clone()),
            &root,
            Some(network),
        )
        .unwrap(),
    );
    core.connect_ed2k().await.unwrap();
    core.set_kad_running(false).await;
    let mut source = 0u32.to_le_bytes().to_vec();
    source.extend_from_slice(&1u32.to_le_bytes());
    source.extend_from_slice(&1u32.to_le_bytes());
    source.extend_from_slice(&[45; 16]);
    source.extend_from_slice(&u32::from_be_bytes([192, 0, 2, 45]).to_le_bytes());
    source.extend_from_slice(&4672u16.to_le_bytes());
    source.extend_from_slice(&4662u16.to_le_bytes());
    source.push(9);
    assert_eq!(core.import_kad_nodes_bytes(source).await.unwrap(), 1);
    let saved_revision = store.load_kad_routing_snapshot().unwrap().revision;
    let fault = rusqlite::Connection::open(profile.metadata_path()).unwrap();
    fault.execute_batch("CREATE TRIGGER fail_kad_checkpoint BEFORE UPDATE ON kad_routing_revision BEGIN SELECT RAISE(ABORT, 'injected checkpoint failure'); END;").unwrap();
    let error = finalize_daemon(&core).await.unwrap_err();
    assert!(format!("{error:#}").contains("failed to persist final Kad state"));
    assert!(matches!(
        error.downcast_ref::<emulebb_core::PersistenceError>(),
        Some(emulebb_core::PersistenceError::Storage(_))
    ));
    let status = core.status().await.ed2k;
    assert!(!status.running);
    assert!(!status.connected);
    let trigger_count: i64 = fault.query_row("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name='fail_kad_checkpoint'", [], |row| row.get(0)).unwrap();
    assert_eq!(trigger_count, 1);
    assert!(matches!(
        core.kad_discovery_pending()
            .await
            .unwrap_err()
            .downcast_ref::<emulebb_core::PersistenceError>(),
        Some(emulebb_core::PersistenceError::Closing)
    ));
    drop(core);
    drop(store);
    fault
        .execute_batch("DROP TRIGGER fail_kad_checkpoint;")
        .unwrap();
    drop(fault);
    let reopened = MetadataStore::open(profile.metadata_path()).unwrap();
    let persisted = reopened.load_kad_routing_snapshot().unwrap();
    assert_eq!(persisted.contacts.len(), 1);
    assert_eq!(persisted.revision, saved_revision);
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}
