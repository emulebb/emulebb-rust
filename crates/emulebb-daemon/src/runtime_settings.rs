//! Startup projections from the single canonical product document.
use super::*;
use emulebb_settings::product::{NatBackend, SecurityIpFilterValues, SettingsValues, VpnMode};

/// Fixed Kad execution policy plus the admitted listener/publication controls.
#[derive(Debug, Clone)]
pub struct KadRuntimePolicy {
    pub listen_port: Option<u16>,
    pub bootstrap_min_routing_contacts: usize,
    pub local_store_enabled: bool,
    pub local_store_keyword_ttl_secs: u64,
    pub local_store_source_ttl_secs: u64,
    pub local_store_notes_ttl_secs: u64,
    pub local_store_keyword_capacity: usize,
    pub local_store_source_capacity: usize,
    pub local_store_notes_capacity: usize,
    pub local_store_source_per_file_capacity: usize,
    pub local_store_notes_per_file_capacity: usize,
    pub publish_shared_files_enabled: bool,
    pub republish_interval_secs: u64,
    pub publish_contact_fanout: usize,
    pub udp_firewall_check_enabled: bool,
    pub udp_firewall_check_interval_secs: u64,
    pub tcp_firewall_check_enabled: bool,
    pub tcp_firewall_check_interval_secs: u64,
    pub buddy_enabled: bool,
    pub routing_maintenance_enabled: bool,
    pub passive_replay_enabled: bool,
}
impl Default for KadRuntimePolicy {
    fn default() -> Self {
        Self::from_values(&SettingsValues::default())
    }
}
impl KadRuntimePolicy {
    fn from_values(values: &SettingsValues) -> Self {
        Self {
            listen_port: (values.network.ed2k_enabled || values.network.kad_enabled)
                .then_some(values.network.p2p.udp_port),
            bootstrap_min_routing_contacts: 10,
            local_store_enabled: true,
            local_store_keyword_ttl_secs: 86_400,
            local_store_source_ttl_secs: 18_000,
            local_store_notes_ttl_secs: 86_400,
            local_store_keyword_capacity: 60_000,
            local_store_source_capacity: 100_000,
            local_store_notes_capacity: 60_000,
            local_store_source_per_file_capacity: 1_000,
            local_store_notes_per_file_capacity: 150,
            publish_shared_files_enabled: values.sharing.kad_publishing_enabled,
            republish_interval_secs: 1_800,
            publish_contact_fanout: 10,
            udp_firewall_check_enabled: true,
            udp_firewall_check_interval_secs: 3_600,
            tcp_firewall_check_enabled: true,
            tcp_firewall_check_interval_secs: 3_600,
            buddy_enabled: true,
            routing_maintenance_enabled: true,
            passive_replay_enabled: false,
        }
    }
}

pub(super) struct LoadedSettings {
    pub incoming_dir: PathBuf,
    pub temp_dir: PathBuf,
    pub p2p_bind_ip: Option<Ipv4Addr>,
    pub p2p_bind_interface: Option<String>,
    pub initial_shared_directory_reload: bool,
    pub kad: KadRuntimePolicy,
    pub kad_bootstrap_endpoints: Vec<String>,
    pub ed2k: Ed2kRuntimeConfig,
    pub nat: NatConfig,
    pub vpn_guard: VpnGuardConfig,
    pub ip_filter: SecurityIpFilterValues,
}

pub(super) fn load_settings(metadata: &MetadataStore) -> Result<LoadedSettings> {
    Ok(from_values(
        metadata.load_app_settings()?.saved.values(),
        metadata.load_kad_bootstrap_endpoints()?,
    ))
}

pub(super) fn from_values(
    values: SettingsValues,
    kad_bootstrap_endpoints: Vec<String>,
) -> LoadedSettings {
    let enabled = values.network.ed2k_enabled || values.network.kad_enabled;
    let servers = &values.network.servers;
    let connections = &values.network.connections;
    let upload = &values.transfers.upload;
    let mut ed2k = Ed2kRuntimeConfig::default();
    // Both discovery networks share the ED2K transport listeners. Disabling
    // server discovery must not remove TCP transfer service from a Kad-only node.
    ed2k.listen_port = enabled.then_some(values.network.p2p.tcp_port);
    ed2k.nickname = values.network.nickname.clone();
    ed2k.obfuscation_enabled = values.security.obfuscation_enabled;
    ed2k.connect_timeout_secs = connections.connect_timeout_seconds;
    ed2k.callback_timeout_secs = connections.callback_timeout_seconds;
    ed2k.server_connect_timeout_secs = servers.connect_timeout_seconds;
    ed2k.reconnect_interval_secs = servers.reconnect_interval_seconds;
    ed2k.reconnect_enabled = servers.auto_reconnect;
    ed2k.safe_server_connect = servers.safe_connect;
    ed2k.use_server_priorities = servers.use_priorities;
    ed2k.auto_connect_static_only = servers.static_only;
    ed2k.add_servers_from_server = servers.accept_server_list_updates;
    ed2k.server_keepalive_minutes = servers.keepalive_minutes;
    ed2k.session_rotation_secs = servers.session_rotation_seconds;
    ed2k.dead_server_retries = servers
        .dead_server_retries
        .try_into()
        .expect("validated retry count fits u32");
    ed2k.max_connections = connections.max_connections as usize;
    ed2k.max_new_connections_per_five_seconds =
        connections.max_new_connections_per_five_seconds as usize;
    ed2k.max_half_open_connections = connections.max_half_open_connections as usize;
    ed2k.max_sources_per_file = values.transfers.max_sources_per_file as usize;
    ed2k.max_parallel_download_peers = values.transfers.max_parallel_download_peers as usize;
    ed2k.download_limit_bytes_per_sec = values.transfers.download_limit_bytes_per_second;
    ed2k.upload_queue.base_slots = upload.base_slots as usize;
    ed2k.upload_queue.elastic_percent = upload.elastic_percent;
    ed2k.upload_queue.upload_limit_bytes_per_sec = values.transfers.upload_limit_bytes_per_second;
    ed2k.upload_queue.elastic_underfill_bytes_per_sec = upload.target_client_rate_bytes_per_second;
    ed2k.upload_queue.waiting_capacity = upload.queue_capacity as usize;
    ed2k.upload_queue.session_transfer_percent = upload.session_transfer_percent;
    ed2k.upload_queue.session_time_limit_secs = upload.session_time_limit_seconds;
    ed2k.detect_tcp_error_flooder = values.security.tcp_error_flood_detection.enabled;
    ed2k.tcp_error_flooder_interval_minutes =
        values.security.tcp_error_flood_detection.interval_seconds / 60;
    ed2k.tcp_error_flooder_threshold = values.security.tcp_error_flood_detection.threshold;
    let mut nat = NatConfig::default();
    nat.enabled = values.network.nat.enabled;
    nat.require_initial_mapping = values.network.nat.require_initial_mapping;
    nat.backend_order = values
        .network
        .nat
        .backend_order
        .iter()
        .map(|backend| match backend {
            NatBackend::PcpNatpmp => "pcp-natpmp".to_owned(),
            NatBackend::Upnp => "upnp-miniupnpc".to_owned(),
        })
        .collect();
    nat.pcp_server_ip = values.network.nat.pcp_server_ip.map(|ip| ip.to_string());
    nat.igd_ip = values.network.nat.igd_ip.map(|ip| ip.to_string());
    nat.external_ip_override = values
        .network
        .nat
        .external_ip_override
        .map(|ip| ip.to_string());
    let vpn_guard = VpnGuardConfig {
        enabled: values.security.vpn_guard.mode == VpnMode::Block,
        mode: match values.security.vpn_guard.mode {
            VpnMode::Off => "off",
            VpnMode::Block => "block",
        }
        .into(),
        allowed_public_ip_cidrs: values
            .security
            .vpn_guard
            .allowed_public_ip_cidrs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
    };
    LoadedSettings {
        kad: KadRuntimePolicy::from_values(&values),
        incoming_dir: values.storage.incoming_directory,
        temp_dir: values.storage.temp_directory,
        p2p_bind_ip: values.network.p2p.bind_ip,
        p2p_bind_interface: values.network.p2p.bind_interface,
        initial_shared_directory_reload: values.sharing.scan_on_startup,
        kad_bootstrap_endpoints,
        ed2k,
        nat,
        vpn_guard,
        ip_filter: values.security.ip_filter,
    }
}
