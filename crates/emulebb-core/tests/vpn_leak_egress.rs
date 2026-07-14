//! RUST-FEAT-005 dynamic VPN leak test — OBSERVED egress (release-blocking gate).
//!
//! The sibling `vpn_failclosed.rs` proves the data plane REFUSES TO START when the
//! tunnel is down. This test upgrades that to *observed* egress: with the
//! `egress-audit` feature on, every P2P socket the client opens records its bound
//! local address and the interface index its egress was pinned to. We then assert,
//! at the socket layer, that:
//!   - tunnel UP: every P2P socket is bound to the tunnel IP and pinned to the
//!     tunnel interface — so no datagram/segment can leave a non-tunnel interface;
//!   - tunnel DOWN: ZERO P2P sockets are ever opened (empty audit), while the
//!     control/REST plane keeps answering;
//!   - tunnel pulled mid-run: no NEW P2P socket opens (steady-state fail-closed).
//!
//! Deterministic, unprivileged, portable across the CI matrix (no packet capture).
//! Runs only under `--features egress-audit`; the feature is never in a release
//! build (guarded by tools/check_rust_client_policy.py). The Windows wire-truth
//! (pktmon on the physical NIC with a real tunnel pull) stays an operator gate
//! (tools/vpn_leak_local_gate.py) — CI cannot reproduce a real multi-NIC tunnel.
#![cfg(feature = "egress-audit")]

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
use emulebb_kad_dht::socket_opts::egress_audit;

/// The tunnel IP for the test: `X_LOCAL_IP`, a real local interface so egress
/// pinning resolves an actual index (the swarm/socket tests already require it to
/// be a non-loopback LAN address; CI exports the runner's primary IPv4).
fn tunnel_ip() -> Ipv4Addr {
    std::env::var("X_LOCAL_IP")
        .expect("X_LOCAL_IP must be set for the egress leak test")
        .parse()
        .expect("X_LOCAL_IP must be an IPv4 address")
}

fn tunnel_if_index() -> u32 {
    emulebb_ed2k::networking::resolve_bind_if_index(tunnel_ip())
        .filter(|index| *index != 0)
        .expect("X_LOCAL_IP must resolve to a local interface index")
}

#[tokio::test]
async fn tunnel_up_every_p2p_socket_is_bound_and_pinned_to_the_tunnel() {
    let transfer_root = unique_runtime_dir("leak-egress-up");
    let bound = Arc::new(AtomicBool::new(true));
    let network = tunnel_network_config(&transfer_root, true, Some(Arc::clone(&bound)));
    let core = build_core(&transfer_root, network);

    egress_audit::reset();
    // Bring the P2P data plane up (tunnel confirmed): connect_ed2k binds the
    // pinned Kad UDP socket (DhtNode::new -> bind_pinned) and the eD2K sockets.
    // The connect to the (absent) fixture server may error asynchronously, but
    // the sockets are bound + pinned + recorded first.
    let _ = core.connect_ed2k().await;

    let records = egress_audit::snapshot();
    assert!(
        !records.is_empty(),
        "at least the Kad UDP socket must be observed once the data plane comes up"
    );
    let index = tunnel_if_index();
    let tunnel = tunnel_ip();
    for record in &records {
        let local = record
            .local
            .unwrap_or_else(|| panic!("audited P2P socket has no local address: {record:?}"));
        assert_eq!(
            local.ip(),
            IpAddr::V4(tunnel),
            "P2P socket bound off the tunnel: {record:?}"
        );
        assert_eq!(
            record.pinned_if_index,
            Some(index),
            "P2P socket egress not pinned to the tunnel interface: {record:?}"
        );
    }
    egress_audit::reset();
}

#[tokio::test]
async fn tunnel_down_opens_zero_p2p_sockets_but_control_plane_answers() {
    let transfer_root = unique_runtime_dir("leak-egress-down");
    // Tunnel not confirmed: fail closed.
    let network = tunnel_network_config(&transfer_root, false, None);
    let core = build_core(&transfer_root, network);

    egress_audit::reset();
    assert!(
        core.start_kad().await.is_err(),
        "Kad must fail closed when the tunnel is down"
    );
    assert!(
        core.connect_ed2k().await.is_err(),
        "eD2K must fail closed when the tunnel is down"
    );

    let records = egress_audit::snapshot();
    assert!(
        records.is_empty(),
        "tunnel down: ZERO P2P sockets must open, observed: {records:?}"
    );

    // Control/REST plane on the local IP is unaffected.
    assert_eq!(core.app_info().name, "eMuleBB");
    let status = core.status().await;
    assert!(!status.ed2k.connected);
    assert!(!status.kad.running);
    egress_audit::reset();
}

#[tokio::test]
async fn tunnel_pulled_mid_run_opens_no_new_p2p_socket() {
    let transfer_root = unique_runtime_dir("leak-egress-pull");
    let bound = Arc::new(AtomicBool::new(true));
    let network = tunnel_network_config(&transfer_root, true, Some(Arc::clone(&bound)));
    let core = build_core(&transfer_root, network);

    // Bring the data plane up with the tunnel confirmed.
    egress_audit::reset();
    let _ = core.connect_ed2k().await;
    assert!(!egress_audit::snapshot().is_empty());
    core.disconnect_ed2k().await;

    // Pull the tunnel mid-run, then attempt to re-open the data plane.
    bound.store(false, Ordering::SeqCst);
    egress_audit::reset();
    let _ = core.connect_ed2k().await; // must fail closed, opening no socket
    let records = egress_audit::snapshot();
    assert!(
        records.is_empty(),
        "tunnel pulled mid-run: no NEW P2P socket may open, observed: {records:?}"
    );
    egress_audit::reset();
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

fn tunnel_network_config(
    root: &Path,
    bound: bool,
    runtime_bound: Option<Arc<AtomicBool>>,
) -> Ed2kNetworkConfig {
    let ip = tunnel_ip();
    let config = Ed2kRuntimeConfig {
        // A configured server so connect_ed2k exercises the real connect path; the
        // VPN-guard bail happens before any server contact when the tunnel is down.
        server_endpoints: vec![format!("{ip}:4661")],
        ..Ed2kRuntimeConfig::default()
    };
    Ed2kNetworkConfig {
        bind_ip: ip,
        kad_bind_addr: SocketAddr::new(IpAddr::V4(ip), 0),
        listen_port: 0,
        user_hash: [0x44; 16],
        secure_ident: Arc::new(
            Ed2kSecureIdent::load_or_create(&root.join("secure-ident.der")).unwrap(),
        ),
        kad_local_store: KadLocalStoreConfig::default(),
        kad_snoop_queue: SnoopQueueConfig::default(),
        kad_bootstrap_endpoints: Vec::new(),
        kad_bootstrap_min_routing_contacts: 10,
        kad_publish_shared_files: false,
        kad_republish_interval_secs: 1_800,
        kad_publish_contact_fanout: 4,
        kad_routing_maintenance_enabled: false,
        kad_udp_firewall_check_enabled: false,
        kad_udp_firewall_check_interval_secs: 600,
        kad_tcp_firewall_check_enabled: false,
        kad_tcp_firewall_check_interval_secs: 600,
        kad_buddy_enabled: false,
        nat_config: NatConfig {
            enabled: false,
            ..NatConfig::default()
        },
        config,
        p2p_bind_ip: Some(ip),
        p2p_bind_interface: None,
        vpn_guard: VpnGuardConfig {
            enabled: true,
            mode: "block".to_string(),
            allowed_public_ip_cidrs: String::new(),
        },
        vpn_interface_bound: bound,
        vpn_interface_bound_runtime: runtime_bound,
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
