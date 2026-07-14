use std::{error::Error, fmt, net::Ipv4Addr, path::PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const SECTION_CORE_PREFERENCES: &str = "core.preferences";
pub const SECTION_DAEMON_RUNTIME: &str = "daemon.runtime";
pub const SECTION_ED2K: &str = "ed2k";
pub const SECTION_KAD: &str = "kad";
pub const SECTION_NAT: &str = "nat";
pub const SECTION_VPN_GUARD: &str = "vpn.guard";
pub const SECTION_IP_FILTER: &str = "ip.filter";

pub const DEFAULT_IP_FILTER_LEVEL: u32 = 127;
pub const DEFAULT_KAD_PUBLISH_CONTACT_FANOUT: usize = 10;
pub const UPNP_MINIUPNPC_BACKEND: &str = "upnp_miniupnpc";

pub const FIELD_UPLOAD_LIMIT_KIBPS: &str = "uploadLimitKiBps";
pub const FIELD_DOWNLOAD_LIMIT_KIBPS: &str = "downloadLimitKiBps";
pub const FIELD_MAX_CONNECTIONS: &str = "maxConnections";
pub const FIELD_MAX_CONNECTIONS_PER_FIVE_SECONDS: &str = "maxConnectionsPerFiveSeconds";
pub const FIELD_MAX_SOURCES_PER_FILE: &str = "maxSourcesPerFile";
pub const FIELD_UPLOAD_CLIENT_DATA_RATE: &str = "uploadClientDataRate";
pub const FIELD_MAX_UPLOAD_SLOTS: &str = "maxUploadSlots";
pub const FIELD_UPLOAD_SLOT_ELASTIC_PERCENT: &str = "uploadSlotElasticPercent";
pub const FIELD_QUEUE_SIZE: &str = "queueSize";
pub const FIELD_AUTO_CONNECT: &str = "autoConnect";
pub const FIELD_RECONNECT: &str = "reconnect";
pub const FIELD_CREDIT_SYSTEM: &str = "creditSystem";
pub const FIELD_SAFE_SERVER_CONNECT: &str = "safeServerConnect";
pub const FIELD_ADD_SERVERS_FROM_SERVER: &str = "addServersFromServer";
pub const FIELD_NETWORK_KADEMLIA: &str = "networkKademlia";
pub const FIELD_NETWORK_ED2K: &str = "networkEd2k";

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PreferenceFieldKind {
    Number,
    Boolean,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PreferenceGroup {
    Network,
    Transfers,
    Server,
    Kad,
    Safety,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum PreferenceDefaultValue {
    Number(u32),
    Boolean(bool),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreferenceSpec {
    pub key: &'static str,
    pub label: &'static str,
    pub group: PreferenceGroup,
    pub kind: PreferenceFieldKind,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub unit: Option<&'static str>,
    pub default_value: PreferenceDefaultValue,
    pub restart_required: bool,
    pub advanced: bool,
    pub description: &'static str,
}

pub const PREFERENCE_SPECS: &[PreferenceSpec] = &[
    number(
        FIELD_UPLOAD_LIMIT_KIBPS,
        "Upload limit",
        PreferenceGroup::Transfers,
        1,
        u32::MAX - 1,
        Some("KiB/s"),
        6200,
        false,
        false,
        "Maximum upload payload budget.",
    ),
    number(
        FIELD_DOWNLOAD_LIMIT_KIBPS,
        "Download limit",
        PreferenceGroup::Transfers,
        1,
        u32::MAX - 1,
        Some("KiB/s"),
        12207,
        false,
        false,
        "Maximum download payload budget.",
    ),
    number(
        FIELD_MAX_CONNECTIONS,
        "Maximum connections",
        PreferenceGroup::Network,
        1,
        i32::MAX as u32,
        Some("connections"),
        500,
        false,
        true,
        "Global outgoing connection budget.",
    ),
    number(
        FIELD_MAX_CONNECTIONS_PER_FIVE_SECONDS,
        "New connections per five seconds",
        PreferenceGroup::Network,
        1,
        i32::MAX as u32,
        Some("connections"),
        50,
        false,
        true,
        "New outgoing connection budget over the rolling five-second window.",
    ),
    number(
        FIELD_MAX_SOURCES_PER_FILE,
        "Maximum sources per file",
        PreferenceGroup::Transfers,
        1,
        i32::MAX as u32,
        Some("sources"),
        600,
        false,
        true,
        "Maximum tracked eD2K sources per transfer.",
    ),
    number(
        FIELD_UPLOAD_CLIENT_DATA_RATE,
        "Target upload slot rate",
        PreferenceGroup::Transfers,
        1,
        u32::MAX,
        Some("KiB/s"),
        32,
        false,
        true,
        "Target per-peer upload rate used to derive elastic slot behavior.",
    ),
    number(
        FIELD_MAX_UPLOAD_SLOTS,
        "Maximum upload slots",
        PreferenceGroup::Transfers,
        1,
        64,
        Some("slots"),
        12,
        false,
        false,
        "Maximum active upload slots.",
    ),
    number(
        FIELD_UPLOAD_SLOT_ELASTIC_PERCENT,
        "Upload slot elasticity",
        PreferenceGroup::Transfers,
        0,
        100,
        Some("percent"),
        80,
        false,
        true,
        "Elastic underfill percentage for upload slot expansion.",
    ),
    number(
        FIELD_QUEUE_SIZE,
        "Upload queue size",
        PreferenceGroup::Transfers,
        2_000,
        10_000,
        Some("clients"),
        10000,
        false,
        true,
        "Maximum waiting upload clients.",
    ),
    boolean(
        FIELD_AUTO_CONNECT,
        "Auto-connect",
        PreferenceGroup::Server,
        false,
        true,
        "Connect to eD2K servers automatically on daemon startup.",
    ),
    boolean(
        FIELD_RECONNECT,
        "Reconnect",
        PreferenceGroup::Server,
        true,
        true,
        "Reconnect after an eD2K server session drops.",
    ),
    boolean(
        FIELD_CREDIT_SYSTEM,
        "Credit system",
        PreferenceGroup::Safety,
        true,
        false,
        "Use peer credit history when scoring upload queue clients.",
    ),
    boolean(
        FIELD_SAFE_SERVER_CONNECT,
        "Safe server connect",
        PreferenceGroup::Server,
        true,
        false,
        "Limit automatic server connection concurrency.",
    ),
    boolean(
        FIELD_ADD_SERVERS_FROM_SERVER,
        "Add servers from server",
        PreferenceGroup::Server,
        true,
        false,
        "Accept servers advertised by the connected eD2K server.",
    ),
    boolean(
        FIELD_NETWORK_KADEMLIA,
        "Kad enabled",
        PreferenceGroup::Kad,
        true,
        true,
        "Enable Kad runtime participation on startup.",
    ),
    boolean(
        FIELD_NETWORK_ED2K,
        "eD2K enabled",
        PreferenceGroup::Network,
        true,
        true,
        "Enable eD2K server and peer networking on startup.",
    ),
];

const fn number(
    key: &'static str,
    label: &'static str,
    group: PreferenceGroup,
    min: u32,
    max: u32,
    unit: Option<&'static str>,
    default_value: u32,
    restart_required: bool,
    advanced: bool,
    description: &'static str,
) -> PreferenceSpec {
    PreferenceSpec {
        key,
        label,
        group,
        kind: PreferenceFieldKind::Number,
        min: Some(min),
        max: Some(max),
        unit,
        default_value: PreferenceDefaultValue::Number(default_value),
        restart_required,
        advanced,
        description,
    }
}

const fn boolean(
    key: &'static str,
    label: &'static str,
    group: PreferenceGroup,
    default_value: bool,
    restart_required: bool,
    description: &'static str,
) -> PreferenceSpec {
    PreferenceSpec {
        key,
        label,
        group,
        kind: PreferenceFieldKind::Boolean,
        min: None,
        max: None,
        unit: None,
        default_value: PreferenceDefaultValue::Boolean(default_value),
        restart_required,
        advanced: false,
        description,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Preferences {
    pub upload_limit_ki_bps: u32,
    pub download_limit_ki_bps: u32,
    pub max_connections: u32,
    pub max_connections_per_five_seconds: u32,
    pub max_sources_per_file: u32,
    pub upload_client_data_rate: u32,
    pub max_upload_slots: u32,
    pub upload_slot_elastic_percent: u32,
    pub queue_size: u32,
    pub auto_connect: bool,
    #[serde(default = "default_reconnect")]
    pub reconnect: bool,
    pub credit_system: bool,
    pub safe_server_connect: bool,
    #[serde(default = "default_add_servers_from_server")]
    pub add_servers_from_server: bool,
    pub network_kademlia: bool,
    pub network_ed2k: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreferencesUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_limit_ki_bps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_limit_ki_bps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections_per_five_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sources_per_file: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_client_data_rate: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_upload_slots: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_slot_elastic_percent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_connect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credit_system: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_server_connect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_servers_from_server: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_kademlia: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_ed2k: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct DaemonRuntimeSettings {
    /// Global finished-file delivery directory (eMule Incoming folder). When a
    /// completed transfer has no category path, its payload is materialized here
    /// by its canonical name. Defaults to `<runtimeDir>/incoming` when unset.
    pub incoming_dir: Option<PathBuf>,
    pub p2p_bind_ip: Option<Ipv4Addr>,
    pub p2p_bind_interface: Option<String>,
    pub ed2k_user_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Ed2kSettings {
    pub listen_port: Option<u16>,
    pub obfuscation_enabled: bool,
    pub probe_search_term: Option<String>,
    pub connect_timeout_secs: u64,
    pub server_connect_timeout_secs: u64,
    pub callback_timeout_secs: u64,
    pub reconnect_interval_secs: u64,
    pub reconnect_enabled: bool,
    pub safe_server_connect: bool,
    pub keepalive_secs: u64,
    pub session_rotation_secs: u64,
    pub max_concurrent_downloads: usize,
    pub max_new_connections_per_five_seconds: usize,
    pub max_half_open_connections: usize,
    pub max_sources_per_file: usize,
    pub max_parallel_download_peers: usize,
    pub keyword_server_attempt_budget: usize,
    pub exact_hash_keyword_server_attempt_budget: usize,
    pub source_server_attempt_budget: usize,
    pub upload_queue: Ed2kUploadQueueSettings,
    pub download_limit_bytes_per_sec: u64,
    pub enable_udp_reask: bool,
    pub publish_emule_rust_identity: bool,
    pub add_servers_from_server: bool,
    pub dead_server_retries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Ed2kUploadQueueSettings {
    pub active_slots: usize,
    pub elastic_percent: u32,
    pub upload_limit_bytes_per_sec: u64,
    pub elastic_underfill_bytes_per_sec: u64,
    pub elastic_underfill_secs: u64,
    pub waiting_capacity: usize,
    pub waiting_timeout_secs: u64,
    pub granted_timeout_secs: u64,
    pub upload_timeout_secs: u64,
    pub session_transfer_percent: u32,
    pub session_time_limit_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct KadSettings {
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
    pub snoop_queue_dedup_window_secs: u64,
    pub snoop_queue_general_max_queries_per_600s: u32,
    pub snoop_queue_general_drain_cooldown_secs: u64,
    pub snoop_queue_source_max_queries_per_600s: u32,
    pub snoop_queue_source_drain_cooldown_secs: u64,
    pub snoop_queue_source_stop_after_results: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct NatSettings {
    pub enabled: bool,
    pub require_initial_mapping: bool,
    pub backend_order: Vec<String>,
    pub bind_ip: Option<String>,
    pub igd_ip: Option<String>,
    pub minissdpd_socket: Option<String>,
    pub ssdp_local_port: Option<u16>,
    pub discovery_timeout_secs: u64,
    pub lease_duration_secs: u32,
    pub renew_margin_secs: u64,
    pub external_ip_override: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct VpnGuardSettings {
    pub enabled: bool,
    pub mode: String,
    pub allowed_public_ip_cidrs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct IpFilterSettings {
    pub enabled: bool,
    pub path: Option<PathBuf>,
    pub level: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PreferenceValidationError {
    message: String,
}

impl PreferenceValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PreferenceValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for PreferenceValidationError {}

pub fn default_preferences() -> Preferences {
    Preferences {
        upload_limit_ki_bps: 6200,
        download_limit_ki_bps: 12207,
        max_connections: 500,
        max_connections_per_five_seconds: 50,
        max_sources_per_file: 600,
        upload_client_data_rate: 32,
        max_upload_slots: 12,
        upload_slot_elastic_percent: 80,
        queue_size: 10000,
        auto_connect: false,
        reconnect: true,
        credit_system: true,
        safe_server_connect: true,
        add_servers_from_server: true,
        network_kademlia: true,
        network_ed2k: true,
    }
}

impl Default for DaemonRuntimeSettings {
    fn default() -> Self {
        Self {
            incoming_dir: None,
            p2p_bind_ip: None,
            p2p_bind_interface: None,
            ed2k_user_hash: None,
        }
    }
}

impl Default for Ed2kSettings {
    fn default() -> Self {
        Self {
            listen_port: None,
            obfuscation_enabled: true,
            probe_search_term: None,
            connect_timeout_secs: 30,
            server_connect_timeout_secs: 25,
            callback_timeout_secs: 45,
            reconnect_interval_secs: 30,
            reconnect_enabled: true,
            safe_server_connect: true,
            keepalive_secs: 20 * 60,
            session_rotation_secs: 0,
            max_concurrent_downloads: 500,
            max_new_connections_per_five_seconds: 50,
            max_half_open_connections: 50,
            max_sources_per_file: 600,
            max_parallel_download_peers: 2,
            keyword_server_attempt_budget: 3,
            exact_hash_keyword_server_attempt_budget: 4,
            source_server_attempt_budget: 3,
            upload_queue: Ed2kUploadQueueSettings::default(),
            download_limit_bytes_per_sec: 0,
            enable_udp_reask: true,
            publish_emule_rust_identity: false,
            add_servers_from_server: false,
            dead_server_retries: 1,
        }
    }
}

impl Default for Ed2kUploadQueueSettings {
    fn default() -> Self {
        Self {
            active_slots: 3,
            elastic_percent: 0,
            upload_limit_bytes_per_sec: 0,
            elastic_underfill_bytes_per_sec: 0,
            elastic_underfill_secs: 10,
            waiting_capacity: 512,
            waiting_timeout_secs: 60 * 60,
            granted_timeout_secs: 30,
            upload_timeout_secs: 90,
            session_transfer_percent: 90,
            session_time_limit_secs: 7_200,
        }
    }
}

impl Default for KadSettings {
    fn default() -> Self {
        Self {
            listen_port: None,
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
            publish_shared_files_enabled: true,
            republish_interval_secs: 1_800,
            publish_contact_fanout: DEFAULT_KAD_PUBLISH_CONTACT_FANOUT,
            udp_firewall_check_enabled: true,
            udp_firewall_check_interval_secs: 3_600,
            tcp_firewall_check_enabled: true,
            tcp_firewall_check_interval_secs: 3_600,
            buddy_enabled: true,
            routing_maintenance_enabled: true,
            snoop_queue_dedup_window_secs: 28_800,
            snoop_queue_general_max_queries_per_600s: 24,
            snoop_queue_general_drain_cooldown_secs: 900,
            snoop_queue_source_max_queries_per_600s: 60,
            snoop_queue_source_drain_cooldown_secs: 300,
            snoop_queue_source_stop_after_results: 2,
        }
    }
}

impl Default for NatSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            require_initial_mapping: true,
            backend_order: vec![UPNP_MINIUPNPC_BACKEND.to_string()],
            bind_ip: None,
            igd_ip: None,
            minissdpd_socket: None,
            ssdp_local_port: None,
            discovery_timeout_secs: 5,
            lease_duration_secs: 3_600,
            renew_margin_secs: 300,
            external_ip_override: None,
        }
    }
}

impl Default for IpFilterSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            path: None,
            level: DEFAULT_IP_FILTER_LEVEL,
        }
    }
}

pub fn preferences_from_setting_values<'a>(
    values: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<Preferences, PreferenceValidationError> {
    let mut object = Map::new();
    for (key, value_json) in values {
        let value = serde_json::from_str::<Value>(value_json).map_err(|error| {
            PreferenceValidationError::new(format!("{key} contains invalid JSON: {error}"))
        })?;
        if object.insert(key.to_string(), value).is_some() {
            return Err(PreferenceValidationError::new(format!(
                "duplicate preference field: {key}"
            )));
        }
    }

    let update =
        serde_json::from_value::<PreferencesUpdate>(Value::Object(object)).map_err(|error| {
            PreferenceValidationError::new(format!("invalid preference settings: {error}"))
        })?;
    let mut preferences = default_preferences();
    apply_preferences_update(&mut preferences, update)?;
    Ok(preferences)
}

pub fn preferences_to_setting_values(
    preferences: &Preferences,
) -> Result<Vec<(&'static str, String)>, serde_json::Error> {
    let values = serde_json::to_value(preferences)?;
    let object = values
        .as_object()
        .expect("Preferences serializes as object");
    PREFERENCE_SPECS
        .iter()
        .map(|field| {
            let value = object
                .get(field.key)
                .expect("preference spec must match Preferences serialization");
            serde_json::to_string(value).map(|value_json| (field.key, value_json))
        })
        .collect()
}

pub fn preferences_update_is_empty(update: &PreferencesUpdate) -> bool {
    update.upload_limit_ki_bps.is_none()
        && update.download_limit_ki_bps.is_none()
        && update.max_connections.is_none()
        && update.max_connections_per_five_seconds.is_none()
        && update.max_sources_per_file.is_none()
        && update.upload_client_data_rate.is_none()
        && update.max_upload_slots.is_none()
        && update.upload_slot_elastic_percent.is_none()
        && update.queue_size.is_none()
        && update.auto_connect.is_none()
        && update.reconnect.is_none()
        && update.credit_system.is_none()
        && update.safe_server_connect.is_none()
        && update.add_servers_from_server.is_none()
        && update.network_kademlia.is_none()
        && update.network_ed2k.is_none()
}

pub fn apply_preferences_update(
    preferences: &mut Preferences,
    update: PreferencesUpdate,
) -> Result<(), PreferenceValidationError> {
    if let Some(value) = update.upload_limit_ki_bps {
        validate_u32(FIELD_UPLOAD_LIMIT_KIBPS, value)?;
        preferences.upload_limit_ki_bps = value;
    }
    if let Some(value) = update.download_limit_ki_bps {
        validate_u32(FIELD_DOWNLOAD_LIMIT_KIBPS, value)?;
        preferences.download_limit_ki_bps = value;
    }
    if let Some(value) = update.max_connections {
        validate_u32(FIELD_MAX_CONNECTIONS, value)?;
        preferences.max_connections = value;
    }
    if let Some(value) = update.max_connections_per_five_seconds {
        validate_u32(FIELD_MAX_CONNECTIONS_PER_FIVE_SECONDS, value)?;
        preferences.max_connections_per_five_seconds = value;
    }
    if let Some(value) = update.max_sources_per_file {
        validate_u32(FIELD_MAX_SOURCES_PER_FILE, value)?;
        preferences.max_sources_per_file = value;
    }
    if let Some(value) = update.upload_client_data_rate {
        validate_u32(FIELD_UPLOAD_CLIENT_DATA_RATE, value)?;
        preferences.upload_client_data_rate = value;
        preferences.max_upload_slots = derive_upload_slots(preferences.upload_limit_ki_bps, value);
    }
    if let Some(value) = update.max_upload_slots {
        validate_u32(FIELD_MAX_UPLOAD_SLOTS, value)?;
        preferences.max_upload_slots = value;
    }
    if let Some(value) = update.upload_slot_elastic_percent {
        validate_u32(FIELD_UPLOAD_SLOT_ELASTIC_PERCENT, value)?;
        preferences.upload_slot_elastic_percent = value;
    }
    if let Some(value) = update.queue_size {
        validate_u32(FIELD_QUEUE_SIZE, value)?;
        preferences.queue_size = value;
    }
    if let Some(value) = update.auto_connect {
        preferences.auto_connect = value;
    }
    if let Some(value) = update.reconnect {
        preferences.reconnect = value;
    }
    if let Some(value) = update.credit_system {
        preferences.credit_system = value;
    }
    if let Some(value) = update.safe_server_connect {
        preferences.safe_server_connect = value;
    }
    if let Some(value) = update.add_servers_from_server {
        preferences.add_servers_from_server = value;
    }
    if let Some(value) = update.network_kademlia {
        preferences.network_kademlia = value;
    }
    if let Some(value) = update.network_ed2k {
        preferences.network_ed2k = value;
    }
    Ok(())
}

pub fn changed_preferences_update(
    next: &Preferences,
    baseline: Option<&Preferences>,
) -> PreferencesUpdate {
    let Some(baseline) = baseline else {
        return PreferencesUpdate {
            upload_limit_ki_bps: Some(next.upload_limit_ki_bps),
            download_limit_ki_bps: Some(next.download_limit_ki_bps),
            max_connections: Some(next.max_connections),
            max_connections_per_five_seconds: Some(next.max_connections_per_five_seconds),
            max_sources_per_file: Some(next.max_sources_per_file),
            upload_client_data_rate: Some(next.upload_client_data_rate),
            max_upload_slots: Some(next.max_upload_slots),
            upload_slot_elastic_percent: Some(next.upload_slot_elastic_percent),
            queue_size: Some(next.queue_size),
            auto_connect: Some(next.auto_connect),
            reconnect: Some(next.reconnect),
            credit_system: Some(next.credit_system),
            safe_server_connect: Some(next.safe_server_connect),
            add_servers_from_server: Some(next.add_servers_from_server),
            network_kademlia: Some(next.network_kademlia),
            network_ed2k: Some(next.network_ed2k),
        };
    };
    PreferencesUpdate {
        upload_limit_ki_bps: changed(next.upload_limit_ki_bps, baseline.upload_limit_ki_bps),
        download_limit_ki_bps: changed(next.download_limit_ki_bps, baseline.download_limit_ki_bps),
        max_connections: changed(next.max_connections, baseline.max_connections),
        max_connections_per_five_seconds: changed(
            next.max_connections_per_five_seconds,
            baseline.max_connections_per_five_seconds,
        ),
        max_sources_per_file: changed(next.max_sources_per_file, baseline.max_sources_per_file),
        upload_client_data_rate: changed(
            next.upload_client_data_rate,
            baseline.upload_client_data_rate,
        ),
        max_upload_slots: changed(next.max_upload_slots, baseline.max_upload_slots),
        upload_slot_elastic_percent: changed(
            next.upload_slot_elastic_percent,
            baseline.upload_slot_elastic_percent,
        ),
        queue_size: changed(next.queue_size, baseline.queue_size),
        auto_connect: changed(next.auto_connect, baseline.auto_connect),
        reconnect: changed(next.reconnect, baseline.reconnect),
        credit_system: changed(next.credit_system, baseline.credit_system),
        safe_server_connect: changed(next.safe_server_connect, baseline.safe_server_connect),
        add_servers_from_server: changed(
            next.add_servers_from_server,
            baseline.add_servers_from_server,
        ),
        network_kademlia: changed(next.network_kademlia, baseline.network_kademlia),
        network_ed2k: changed(next.network_ed2k, baseline.network_ed2k),
    }
}

pub fn parse_u32_preference(
    field_name: &str,
    value: &str,
) -> Result<u32, PreferenceValidationError> {
    let parsed = value.trim().parse::<u32>().map_err(|_| {
        PreferenceValidationError::new(format!("{field_name} must be an unsigned number"))
    })?;
    validate_u32(field_name, parsed)?;
    Ok(parsed)
}

pub fn validate_u32(field_name: &str, value: u32) -> Result<(), PreferenceValidationError> {
    let field = preference_field(field_name).ok_or_else(|| {
        PreferenceValidationError::new(format!("unknown preference field: {field_name}"))
    })?;
    if field.kind != PreferenceFieldKind::Number {
        return Err(PreferenceValidationError::new(format!(
            "{field_name} is not a numeric preference"
        )));
    }
    let min = field.min.unwrap_or(0);
    let max = field.max.unwrap_or(u32::MAX);
    if !(min..=max).contains(&value) {
        return Err(PreferenceValidationError::new(format!(
            "{field_name} must be an unsigned number in the range {min}..{max}"
        )));
    }
    Ok(())
}

pub fn preference_schema() -> &'static [PreferenceSpec] {
    PREFERENCE_SPECS
}

pub fn preference_field(field_name: &str) -> Option<&'static PreferenceSpec> {
    PREFERENCE_SPECS
        .iter()
        .find(|field| field.key == field_name)
}

pub fn derive_upload_slots(upload_limit_ki_bps: u32, upload_client_data_rate: u32) -> u32 {
    upload_limit_ki_bps
        .div_ceil(upload_client_data_rate)
        .clamp(1, 64)
}

fn default_reconnect() -> bool {
    true
}

fn default_add_servers_from_server() -> bool {
    true
}

fn changed<T: Copy + PartialEq>(next: T, current: T) -> Option<T> {
    (next != current).then_some(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preferences_include_current_rest_fields() {
        let value = serde_json::to_value(default_preferences()).unwrap();

        assert_eq!(value[FIELD_UPLOAD_LIMIT_KIBPS], 6200);
        assert_eq!(value[FIELD_RECONNECT], true);
        assert_eq!(value.as_object().unwrap().len(), PREFERENCE_SPECS.len());
    }

    #[test]
    fn preference_schema_matches_default_values() {
        let defaults = serde_json::to_value(default_preferences()).unwrap();

        for field in preference_schema() {
            let expected_default = match field.default_value {
                PreferenceDefaultValue::Number(value) => serde_json::json!(value),
                PreferenceDefaultValue::Boolean(value) => serde_json::json!(value),
            };
            assert_eq!(defaults[field.key], expected_default);
        }
    }

    #[test]
    fn preference_settings_roundtrip_as_scalar_rows() {
        let mut preferences = default_preferences();
        preferences.download_limit_ki_bps = 2048;
        preferences.reconnect = false;

        let rows = preferences_to_setting_values(&preferences).unwrap();
        assert_eq!(rows.len(), PREFERENCE_SPECS.len());
        assert!(rows.contains(&(FIELD_RECONNECT, "false".to_string())));

        let decoded = preferences_from_setting_values(
            rows.iter()
                .map(|(key, value_json)| (*key, value_json.as_str())),
        )
        .unwrap();
        assert_eq!(decoded, preferences);
    }

    #[test]
    fn preference_settings_reject_unknown_keys() {
        let error = preferences_from_setting_values([("hiddenLegacySetting", "true")]).unwrap_err();

        assert!(
            error.to_string().contains("unknown field"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validation_uses_field_metadata_ranges() {
        let error = validate_u32(FIELD_QUEUE_SIZE, 1_999).unwrap_err();

        assert_eq!(
            error.to_string(),
            "queueSize must be an unsigned number in the range 2000..10000"
        );
    }

    #[test]
    fn changed_preferences_update_only_sets_changed_fields() {
        let baseline = default_preferences();
        let mut next = baseline.clone();
        next.upload_limit_ki_bps = 2048;
        next.network_ed2k = false;

        let update = changed_preferences_update(&next, Some(&baseline));

        assert_eq!(update.upload_limit_ki_bps, Some(2048));
        assert_eq!(update.network_ed2k, Some(false));
        assert_eq!(update.download_limit_ki_bps, None);
        assert_eq!(update.network_kademlia, None);
    }
}
