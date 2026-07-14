//! RUST-FEAT-005 automated VPN leak-test (release-blocking gate).
//!
//! Proves the P0 Network Safety invariant with a deterministic, local,
//! fail-closed FAULT INJECTION (no packet capture, no privileged netns, portable
//! across the CI matrix): with the VPN tunnel down / not bound, the public P2P
//! DATA plane (Kad UDP + eD2K TCP) refuses to start — so no socket is ever
//! opened and zero bytes can leave a non-tunnel interface — while the
//! control/REST plane on the local IP keeps answering. When the tunnel is
//! confirmed, the data plane comes up, proving we fail CLOSED, not bricked.
//!
//! This is the dynamic complement to the static guards: the eD2K-TCP / Kad-UDP
//! egress pins (`require_bind_if_index`, IP_UNICAST_IF) and the Python policy
//! guard. The socket-layer pin (an unassigned bind IP fails closed instead of
//! degrading to unpinned egress) is unit-tested in
//! `emulebb_ed2k::networking::resolve_bind_if_index_matches_a_present_address_and_rejects_absent`.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use emulebb_core::{Ed2kNetworkConfig, EmulebbCore, VpnGuardConfig};
use emulebb_ed2k::{NatConfig, config::Ed2kRuntimeConfig, ed2k_tcp::Ed2kSecureIdent};
use emulebb_index::{FileIndex, KadLocalStoreConfig, SnoopQueueConfig};

#[tokio::test]
async fn data_plane_fails_closed_when_tunnel_down_control_plane_unaffected() {
    let transfer_root = unique_runtime_dir("vpn-failclosed-down");
    let mut network = test_network_config(&transfer_root);
    network.vpn_guard = VpnGuardConfig {
        enabled: true,
        mode: "block".to_string(),
        allowed_public_ip_cidrs: String::new(),
    };
    // Tunnel is NOT confirmed-bound: the data plane must fail closed.
    network.vpn_interface_bound = false;
    let core = build_core(&transfer_root, network);

    // 1. Kad UDP data plane refuses to start — no UDP socket is ever opened, so
    //    no Kad datagram can leave a non-tunnel interface.
    let kad_err = core
        .start_kad()
        .await
        .expect_err("Kad UDP must fail closed when the tunnel is down");
    assert!(
        kad_err.to_string().contains("not VPN-confirmed"),
        "unexpected Kad error: {kad_err}"
    );

    // 2. eD2K TCP data plane refuses to connect — no TCP socket is ever opened,
    //    so no eD2K byte can leave a non-tunnel interface.
    let ed2k_err = core
        .connect_ed2k()
        .await
        .expect_err("eD2K TCP must fail closed when the tunnel is down");
    assert!(
        ed2k_err.to_string().contains("blocked by VPN guard"),
        "unexpected eD2K error: {ed2k_err}"
    );

    // 3. The control/REST plane on the local IP still answers (we fail the data
    //    plane closed WITHOUT bricking control). These reads do not touch the
    //    tunnel.
    assert_eq!(core.app_info().name, "eMuleBB");
    let status = core.status().await;
    assert!(
        !status.ed2k.connected,
        "eD2K must not be connected while the tunnel is down"
    );
    assert!(
        !status.kad.running,
        "Kad must not be running while the tunnel is down"
    );
}

#[tokio::test]
async fn data_plane_recovers_when_tunnel_is_confirmed() {
    // Fail-closed, not bricked: once the tunnel binds, the data plane comes up.
    let transfer_root = unique_runtime_dir("vpn-failclosed-recover");
    let runtime_bound = Arc::new(AtomicBool::new(false));
    let mut network = test_network_config(&transfer_root);
    network.vpn_guard = VpnGuardConfig {
        enabled: true,
        mode: "block".to_string(),
        allowed_public_ip_cidrs: String::new(),
    };
    network.vpn_interface_bound = true;
    network.vpn_interface_bound_runtime = Some(Arc::clone(&runtime_bound));
    let core = build_core(&transfer_root, network);

    // Tunnel down -> Kad blocked.
    assert!(
        core.start_kad().await.is_err(),
        "Kad must fail closed while the tunnel is unbound"
    );

    // Tunnel confirmed -> Kad starts.
    runtime_bound.store(true, Ordering::SeqCst);
    assert!(
        core.start_kad().await.is_ok(),
        "Kad must start once the tunnel is confirmed (fail-closed, not bricked)"
    );
}

fn build_core(transfer_root: &Path, network: Ed2kNetworkConfig) -> EmulebbCore {
    EmulebbCore::new_with_network(
        "test",
        FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap()
}

fn test_network_config(root: &Path) -> Ed2kNetworkConfig {
    // A configured server so connect_ed2k exercises the real connect path; the
    // VPN-guard bail happens before any server contact regardless.
    let config = Ed2kRuntimeConfig {
        server_endpoints: vec!["198.51.100.20:4661".to_string()],
        ..Ed2kRuntimeConfig::default()
    };
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
        kad_routing_maintenance_enabled: true,
        kad_udp_firewall_check_enabled: true,
        kad_udp_firewall_check_interval_secs: 600,
        kad_tcp_firewall_check_enabled: true,
        kad_tcp_firewall_check_interval_secs: 600,
        kad_buddy_enabled: true,
        nat_config: NatConfig::default(),
        config,
        p2p_bind_ip: Some(Ipv4Addr::new(198, 51, 100, 10)),
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
