use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use emulebb_core::{Ed2kNetworkConfig, EmulebbCore};
use emulebb_ed2k::{
    NatConfig,
    config::{Ed2kRuntimeConfig, Ed2kUploadQueueRuntimeConfig},
    ed2k_tcp::Ed2kSecureIdent,
};
use emulebb_index::{FileIndex, KadLocalStoreConfig, SnoopQueueConfig};

const TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);

pub fn open_network_core(
    root: &Path,
    bind_ip: Ipv4Addr,
    bootstrap: SocketAddr,
    listen_port: u16,
    user_hash: [u8; 16],
    publish_shared_files: bool,
) -> EmulebbCore {
    std::fs::create_dir_all(root).expect("create core root");
    EmulebbCore::new_with_network(
        "kad-transfer-test",
        FileIndex::open(root.join("metadata.sqlite")).expect("open metadata"),
        root.join("transfers"),
        Some(test_network_config(
            root,
            bind_ip,
            bootstrap,
            listen_port,
            user_hash,
            publish_shared_files,
        )),
    )
    .expect("open network core")
}

pub async fn wait_for_kad_connected(core: &EmulebbCore) {
    wait_until("Kad runtime did not bootstrap", || async {
        core.status().await.kad.connected
    })
    .await;
}

pub async fn wait_for_completed_transfer(core: &EmulebbCore, hash: &str) -> emulebb_core::Transfer {
    wait_until("ED2K transfer did not complete from Kad source", || async {
        core.transfer(hash)
            .await
            .filter(|transfer| transfer.state == "completed")
    })
    .await
    .expect("completed transfer")
}

pub fn free_lan_tcp_port(bind_ip: Ipv4Addr) -> u16 {
    TcpListener::bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
        .expect("bind LAN TCP port probe")
        .local_addr()
        .expect("LAN TCP port probe address")
        .port()
}

pub fn deterministic_payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| (index.wrapping_mul(31).wrapping_add(17) % 251) as u8)
        .collect()
}

fn test_network_config(
    root: &Path,
    bind_ip: Ipv4Addr,
    bootstrap: SocketAddr,
    listen_port: u16,
    user_hash: [u8; 16],
    publish_shared_files: bool,
) -> Ed2kNetworkConfig {
    let dummy_server_port = free_lan_tcp_port(bind_ip);
    let mut config = Ed2kRuntimeConfig {
        server_endpoints: vec![format!("{bind_ip}:{dummy_server_port}")],
        obfuscation_enabled: false,
        connect_timeout_secs: 1,
        max_parallel_download_peers: 1,
        keyword_server_attempt_budget: 1,
        exact_hash_keyword_server_attempt_budget: 1,
        source_server_attempt_budget: 1,
        upload_queue: Ed2kUploadQueueRuntimeConfig {
            active_slots: 2,
            elastic_percent: 0,
            upload_limit_bytes_per_sec: 0,
            elastic_underfill_bytes_per_sec: 0,
            elastic_underfill_secs: 10,
            waiting_capacity: 8,
            waiting_timeout_secs: 5,
            granted_timeout_secs: 10,
            upload_timeout_secs: 30,
            session_transfer_percent: 0,
            session_time_limit_secs: 0,
        },
        ..Ed2kRuntimeConfig::default()
    };
    config.listen_port = Some(listen_port);
    Ed2kNetworkConfig {
        bind_ip,
        kad_bind_addr: SocketAddr::new(IpAddr::V4(bind_ip), 0),
        listen_port,
        user_hash,
        secure_ident: Arc::new(
            Ed2kSecureIdent::load_or_create(&root.join("secure-ident.der"))
                .expect("load secure ident"),
        ),
        kad_local_store: KadLocalStoreConfig {
            enabled: true,
            ..KadLocalStoreConfig::default()
        },
        kad_snoop_queue: SnoopQueueConfig::default(),
        kad_bootstrap_endpoints: vec![bootstrap.to_string()],
        kad_bootstrap_min_routing_contacts: 1,
        kad_publish_shared_files: publish_shared_files,
        kad_republish_interval_secs: 1,
        kad_publish_contact_fanout: 4,
        kad_udp_firewall_check_enabled: false,
        kad_udp_firewall_check_interval_secs: 600,
        kad_tcp_firewall_check_enabled: false,
        kad_tcp_firewall_check_interval_secs: 600,
        kad_buddy_enabled: false,
        kad_routing_maintenance_enabled: false,
        nat_config: NatConfig {
            enabled: false,
            ..NatConfig::default()
        },
        config,
        p2p_bind_ip: Some(bind_ip),
        p2p_bind_interface: None,
        vpn_guard: emulebb_core::VpnGuardConfig::default(),
        vpn_interface_bound: false,
        vpn_interface_bound_runtime: None,
        ip_filter: Default::default(),
        ip_filter_path: None,
        ip_filter_level: 127,
    }
}

async fn wait_until<T, F, Fut>(message: &str, mut probe: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = T>,
    T: WaitOutcome,
{
    let deadline = Instant::now() + TRANSFER_TIMEOUT;
    loop {
        let result = probe().await;
        if result.is_ready() {
            return result;
        }
        assert!(Instant::now() < deadline, "{message}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

trait WaitOutcome {
    fn is_ready(&self) -> bool;
}

impl WaitOutcome for bool {
    fn is_ready(&self) -> bool {
        *self
    }
}

impl<T> WaitOutcome for Option<T> {
    fn is_ready(&self) -> bool {
        self.is_some()
    }
}
