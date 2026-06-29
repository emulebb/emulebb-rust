pub mod ban_store;
pub mod buddy_socket;
pub mod config;
pub mod diag_event;
pub mod disk_space;
mod ed2k_client_udp;
mod ed2k_client_udp_obfuscation;
pub use ed2k_client_udp::{
    ReaskCommand, ReaskCommandReceiver, ReaskDetachArgs, ReaskEvent, ReaskEventReceiver,
    ReaskEventSender, ReaskSourceHandle, reask_command_channel, reask_event_channel,
    run_ed2k_udp_reask_loop,
};
#[allow(dead_code)]
pub mod ed2k_server;
#[allow(dead_code)]
pub mod ed2k_tcp;
#[allow(dead_code)]
pub mod ed2k_transfer;
pub mod ipfilter;
pub mod kad_firewall;
pub mod long_path;
pub mod nat;
pub mod networking;
pub mod reachability;
pub mod shared_publish_rank;
pub mod stun;

#[allow(deprecated)]
pub use nat::RupnpPortMappingProvider;
pub use nat::{
    IgdPortMappingProvider, MappedEndpoint, MappingExposure, MappingSpec,
    MiniupnpcPortMappingProvider, NatCapableAgent, NatConfig, NatManager, NatManagerBuilder,
    NatStatus, NatStatusSnapshot, NoopReachabilityStrategy, PortMappingProvider,
    ReachabilityStrategy, SelectedGateway, TransportProtocol, UPNP_IGD_BACKEND,
    UPNP_MINIUPNPC_BACKEND, UPNP_RUPNP_BACKEND, built_in_upnp_port_mapping_providers,
    default_upnp_backend_order,
};
pub use networking::{
    InterfaceAddressFamily, InterfaceBindingReport, InterfaceBindingSelection,
    InterfaceSelectionState, NetworkInterface, NetworkInterfaceAddress, NetworkReport,
    ResolvedInterfaceBindingReport, build_interface_binding_report, detect_interfaces,
    recommend_interface, resolve_bind_ip,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashType {
    Ed2k(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopularHash {
    pub hash: HashType,
    pub canonical_name: String,
    pub size: u64,
    pub source_count: u32,
}

/// LAN bind IP for tests that open a real socket — always `X_LOCAL_IP`, never a
/// loopback literal (the operator's VPN split tunnel breaks 127.0.0.1 -> os
/// error 10049; CI exports `X_LOCAL_IP=127.0.0.1`). Panics if unset so the
/// loopback habit can't creep back in via a silent default.
#[cfg(test)]
pub(crate) fn test_bind_ip() -> std::net::Ipv4Addr {
    std::env::var("X_LOCAL_IP")
        .expect("X_LOCAL_IP must be set for emulebb-ed2k socket-binding tests")
        .parse()
        .expect("X_LOCAL_IP must be an IPv4 address")
}

#[cfg(test)]
pub(crate) mod paths {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

    pub(crate) fn unique_test_dir(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = rust_test_tmp_root().join(format!(
            "emulebb-rust-{name}-{}-{stamp}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create test directory");
        path
    }

    fn rust_test_tmp_root() -> PathBuf {
        std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT")
            .map(PathBuf::from)
            .map(|root| root.join("tmp").join("emulebb-rust-tests"))
            .unwrap_or_else(|| std::env::temp_dir().join("emulebb-rust-tests"))
    }
}
