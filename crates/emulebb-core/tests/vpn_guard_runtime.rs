use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use emulebb_core::{Ed2kNetworkConfig, EmulebbCore, VpnGuardConfig};
use emulebb_ed2k::{NatConfig, config::Ed2kConfig, ed2k_tcp::Ed2kSecureIdent};
use emulebb_index::{FileIndex, KadLocalStoreConfig, SnoopQueueConfig};

#[tokio::test]
async fn vpn_guard_uses_runtime_binding_state() {
    let transfer_root = unique_runtime_dir("vpn-guard-runtime-bind");
    let runtime_bound = Arc::new(AtomicBool::new(false));
    let mut network = test_network_config(&transfer_root);
    network.vpn_guard = VpnGuardConfig {
        enabled: true,
        mode: "block".to_string(),
        allowed_public_ip_cidrs: String::new(),
    };
    network.vpn_interface_bound = true;
    network.vpn_interface_bound_runtime = Some(Arc::clone(&runtime_bound));
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap();

    let err = core
        .start_kad()
        .await
        .expect_err("runtime VPN bind loss must block Kad start");
    assert!(err.to_string().contains("not VPN-confirmed"));

    runtime_bound.store(true, Ordering::SeqCst);
    assert!(core.start_kad().await.is_ok());
}

fn test_network_config(root: &Path) -> Ed2kNetworkConfig {
    Ed2kNetworkConfig {
        bind_ip: Ipv4Addr::new(198, 51, 100, 10),
        kad_bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 4665),
        listen_port: 4662,
        user_hash: [0x44; 16],
        secure_ident: Arc::new(
            Ed2kSecureIdent::load_or_create(&root.join("secure-ident.der")).unwrap(),
        ),
        kad_local_store: KadLocalStoreConfig::default(),
        kad_snoop_queue: SnoopQueueConfig::default(),
        kad_bootstrap_nodes: Vec::new(),
        kad_bootstrap_min_routing_contacts: 10,
        kad_publish_shared_files: true,
        kad_republish_interval_secs: 1_800,
        kad_publish_contact_fanout: 4,
        kad_hello_intro_interval_secs: 300,
        kad_hello_intro_fanout: 2,
        kad_routing_maintenance_enabled: true,
        kad_udp_firewall_check_enabled: true,
        kad_udp_firewall_check_interval_secs: 600,
        kad_tcp_firewall_check_enabled: true,
        kad_tcp_firewall_check_interval_secs: 600,
        kad_buddy_enabled: true,
        nat_config: NatConfig::default(),
        config: Ed2kConfig::default(),
        p2p_bind_interface: None,
        vpn_guard: VpnGuardConfig::default(),
        vpn_interface_bound: false,
        vpn_interface_bound_runtime: None,
        ip_filter: Default::default(),
        ip_filter_path: None,
        ip_filter_level: emulebb_ed2k::ipfilter::DEFAULT_FILTER_LEVEL,
    }
}

fn unique_runtime_dir(name: &str) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let path = rust_test_tmp_root().join(format!(
        "emulebb-rust-{name}-{}-{stamp}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create runtime dir");
    path
}

fn rust_test_tmp_root() -> std::path::PathBuf {
    std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT")
        .map(std::path::PathBuf::from)
        .map(|root| root.join("tmp").join("emulebb-rust-tests"))
        .unwrap_or_else(|| std::env::temp_dir().join("emulebb-rust-tests"))
}
