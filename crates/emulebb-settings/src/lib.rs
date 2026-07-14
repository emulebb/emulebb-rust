use std::{error::Error, fmt, net::Ipv4Addr, path::PathBuf};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};

pub const SECTION_CORE: &str = "core";
pub const SECTION_DAEMON: &str = "daemon";
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
pub enum CoreSettingFieldKind {
    Number,
    Boolean,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CoreSettingGroup {
    Network,
    Transfers,
    Server,
    Kad,
    Safety,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CoreSettingDefaultValue {
    Number(u32),
    Boolean(bool),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreSettingSpec {
    pub key: &'static str,
    pub label: &'static str,
    pub group: CoreSettingGroup,
    pub kind: CoreSettingFieldKind,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub unit: Option<&'static str>,
    pub default_value: CoreSettingDefaultValue,
    pub restart_required: bool,
    pub advanced: bool,
    pub description: &'static str,
}

pub const CORE_SETTING_SPECS: &[CoreSettingSpec] = &[
    number(NumberSettingSpec {
        key: FIELD_UPLOAD_LIMIT_KIBPS,
        label: "Upload limit",
        group: CoreSettingGroup::Transfers,
        min: 1,
        max: u32::MAX - 1,
        unit: Some("KiB/s"),
        default_value: 6200,
        restart_required: false,
        advanced: false,
        description: "Maximum upload payload budget.",
    }),
    number(NumberSettingSpec {
        key: FIELD_DOWNLOAD_LIMIT_KIBPS,
        label: "Download limit",
        group: CoreSettingGroup::Transfers,
        min: 1,
        max: u32::MAX - 1,
        unit: Some("KiB/s"),
        default_value: 12207,
        restart_required: false,
        advanced: false,
        description: "Maximum download payload budget.",
    }),
    number(NumberSettingSpec {
        key: FIELD_MAX_CONNECTIONS,
        label: "Maximum connections",
        group: CoreSettingGroup::Network,
        min: 1,
        max: i32::MAX as u32,
        unit: Some("connections"),
        default_value: 500,
        restart_required: false,
        advanced: true,
        description: "Global outgoing connection budget.",
    }),
    number(NumberSettingSpec {
        key: FIELD_MAX_CONNECTIONS_PER_FIVE_SECONDS,
        label: "New connections per five seconds",
        group: CoreSettingGroup::Network,
        min: 1,
        max: i32::MAX as u32,
        unit: Some("connections"),
        default_value: 50,
        restart_required: false,
        advanced: true,
        description: "New outgoing connection budget over the rolling five-second window.",
    }),
    number(NumberSettingSpec {
        key: FIELD_MAX_SOURCES_PER_FILE,
        label: "Maximum sources per file",
        group: CoreSettingGroup::Transfers,
        min: 1,
        max: i32::MAX as u32,
        unit: Some("sources"),
        default_value: 600,
        restart_required: false,
        advanced: true,
        description: "Maximum tracked eD2K sources per transfer.",
    }),
    number(NumberSettingSpec {
        key: FIELD_UPLOAD_CLIENT_DATA_RATE,
        label: "Target upload slot rate",
        group: CoreSettingGroup::Transfers,
        min: 1,
        max: u32::MAX,
        unit: Some("KiB/s"),
        default_value: 32,
        restart_required: false,
        advanced: true,
        description: "Target per-peer upload rate used to derive elastic slot behavior.",
    }),
    number(NumberSettingSpec {
        key: FIELD_MAX_UPLOAD_SLOTS,
        label: "Maximum upload slots",
        group: CoreSettingGroup::Transfers,
        min: 1,
        max: 64,
        unit: Some("slots"),
        default_value: 12,
        restart_required: false,
        advanced: false,
        description: "Maximum active upload slots.",
    }),
    number(NumberSettingSpec {
        key: FIELD_UPLOAD_SLOT_ELASTIC_PERCENT,
        label: "Upload slot elasticity",
        group: CoreSettingGroup::Transfers,
        min: 0,
        max: 100,
        unit: Some("percent"),
        default_value: 80,
        restart_required: false,
        advanced: true,
        description: "Elastic underfill percentage for upload slot expansion.",
    }),
    number(NumberSettingSpec {
        key: FIELD_QUEUE_SIZE,
        label: "Upload queue size",
        group: CoreSettingGroup::Transfers,
        min: 2_000,
        max: 10_000,
        unit: Some("clients"),
        default_value: 10000,
        restart_required: false,
        advanced: true,
        description: "Maximum waiting upload clients.",
    }),
    boolean(
        FIELD_AUTO_CONNECT,
        "Auto-connect",
        CoreSettingGroup::Server,
        false,
        true,
        "Connect to eD2K servers automatically on daemon startup.",
    ),
    boolean(
        FIELD_RECONNECT,
        "Reconnect",
        CoreSettingGroup::Server,
        true,
        true,
        "Reconnect after an eD2K server session drops.",
    ),
    boolean(
        FIELD_CREDIT_SYSTEM,
        "Credit system",
        CoreSettingGroup::Safety,
        true,
        false,
        "Use peer credit history when scoring upload queue clients.",
    ),
    boolean(
        FIELD_SAFE_SERVER_CONNECT,
        "Safe server connect",
        CoreSettingGroup::Server,
        true,
        false,
        "Limit automatic server connection concurrency.",
    ),
    boolean(
        FIELD_ADD_SERVERS_FROM_SERVER,
        "Add servers from server",
        CoreSettingGroup::Server,
        true,
        false,
        "Accept servers advertised by the connected eD2K server.",
    ),
    boolean(
        FIELD_NETWORK_KADEMLIA,
        "Kad enabled",
        CoreSettingGroup::Kad,
        true,
        true,
        "Enable Kad runtime participation on startup.",
    ),
    boolean(
        FIELD_NETWORK_ED2K,
        "eD2K enabled",
        CoreSettingGroup::Network,
        true,
        true,
        "Enable eD2K server and peer networking on startup.",
    ),
];

struct NumberSettingSpec {
    key: &'static str,
    label: &'static str,
    group: CoreSettingGroup,
    min: u32,
    max: u32,
    unit: Option<&'static str>,
    default_value: u32,
    restart_required: bool,
    advanced: bool,
    description: &'static str,
}

const fn number(spec: NumberSettingSpec) -> CoreSettingSpec {
    CoreSettingSpec {
        key: spec.key,
        label: spec.label,
        group: spec.group,
        kind: CoreSettingFieldKind::Number,
        min: Some(spec.min),
        max: Some(spec.max),
        unit: spec.unit,
        default_value: CoreSettingDefaultValue::Number(spec.default_value),
        restart_required: spec.restart_required,
        advanced: spec.advanced,
        description: spec.description,
    }
}

const fn boolean(
    key: &'static str,
    label: &'static str,
    group: CoreSettingGroup,
    default_value: bool,
    restart_required: bool,
    description: &'static str,
) -> CoreSettingSpec {
    CoreSettingSpec {
        key,
        label,
        group,
        kind: CoreSettingFieldKind::Boolean,
        min: None,
        max: None,
        unit: None,
        default_value: CoreSettingDefaultValue::Boolean(default_value),
        restart_required,
        advanced: false,
        description,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoreSettings {
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoreSettingsUpdate {
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct DaemonSettings {
    /// Global finished-file delivery directory (eMule Incoming folder). When a
    /// completed transfer has no category path, its payload is materialized here
    /// by its canonical name. Defaults to `<profile>/incoming` when unset.
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct AppSettings {
    pub core: CoreSettings,
    pub daemon: DaemonSettings,
    pub ed2k: Ed2kSettings,
    pub kad: KadSettings,
    pub nat: NatSettings,
    pub vpn_guard: VpnGuardSettings,
    pub ip_filter: IpFilterSettings,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct AppSettingsUpdate {
    pub core: Option<CoreSettingsUpdate>,
    pub daemon: Option<DaemonSettings>,
    pub ed2k: Option<Ed2kSettings>,
    pub kad: Option<KadSettings>,
    pub nat: Option<NatSettings>,
    pub vpn_guard: Option<VpnGuardSettings>,
    pub ip_filter: Option<IpFilterSettings>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CoreSettingValidationError {
    message: String,
}

impl CoreSettingValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CoreSettingValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CoreSettingValidationError {}

pub fn default_core_settings() -> CoreSettings {
    CoreSettings {
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

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            daemon: DaemonSettings::default(),
            core: default_core_settings(),
            ed2k: Ed2kSettings::default(),
            kad: KadSettings::default(),
            nat: NatSettings::default(),
            vpn_guard: VpnGuardSettings::default(),
            ip_filter: IpFilterSettings::default(),
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

pub fn core_settings_from_values<'a>(
    values: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<CoreSettings, CoreSettingValidationError> {
    let mut object = Map::new();
    for (key, value_json) in values {
        let value = serde_json::from_str::<Value>(value_json).map_err(|error| {
            CoreSettingValidationError::new(format!("{key} contains invalid JSON: {error}"))
        })?;
        if object.insert(key.to_string(), value).is_some() {
            return Err(CoreSettingValidationError::new(format!(
                "duplicate core setting field: {key}"
            )));
        }
    }

    let update =
        serde_json::from_value::<CoreSettingsUpdate>(Value::Object(object)).map_err(|error| {
            CoreSettingValidationError::new(format!("invalid core settings: {error}"))
        })?;
    let mut core_settings = default_core_settings();
    apply_core_settings_update(&mut core_settings, update)?;
    Ok(core_settings)
}

pub fn core_settings_to_values(
    core_settings: &CoreSettings,
) -> Result<Vec<(&'static str, String)>, serde_json::Error> {
    let values = serde_json::to_value(core_settings)?;
    let object = values
        .as_object()
        .expect("CoreSettings serializes as object");
    CORE_SETTING_SPECS
        .iter()
        .map(|field| {
            let value = object
                .get(field.key)
                .expect("core setting spec must match CoreSettings serialization");
            serde_json::to_string(value).map(|value_json| (field.key, value_json))
        })
        .collect()
}

pub fn section_settings_from_values<'a, T>(
    section: &str,
    values: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<T, CoreSettingValidationError>
where
    T: Default + DeserializeOwned,
{
    let mut object = Map::new();
    for (key, value_json) in values {
        let value = serde_json::from_str::<Value>(value_json).map_err(|error| {
            CoreSettingValidationError::new(format!(
                "{section}.{key} contains invalid JSON: {error}"
            ))
        })?;
        if object.insert(key.to_string(), value).is_some() {
            return Err(CoreSettingValidationError::new(format!(
                "duplicate setting field: {section}.{key}"
            )));
        }
    }
    if object.is_empty() {
        return Ok(T::default());
    }
    serde_json::from_value::<T>(Value::Object(object)).map_err(|error| {
        CoreSettingValidationError::new(format!("invalid settings section {section}: {error}"))
    })
}

pub fn section_settings_to_values<T>(
    settings: &T,
) -> Result<Vec<(String, String)>, serde_json::Error>
where
    T: Serialize,
{
    let values = serde_json::to_value(settings)?;
    let object = values
        .as_object()
        .expect("settings section serializes as object");
    let mut entries = object
        .iter()
        .map(|(key, value)| {
            serde_json::to_string(value).map(|value_json| (key.clone(), value_json))
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

pub fn app_settings_update_is_empty(update: &AppSettingsUpdate) -> bool {
    update.core.is_none()
        && update.daemon.is_none()
        && update.ed2k.is_none()
        && update.kad.is_none()
        && update.nat.is_none()
        && update.vpn_guard.is_none()
        && update.ip_filter.is_none()
}

pub fn core_settings_update_is_empty(update: &CoreSettingsUpdate) -> bool {
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

pub fn apply_core_settings_update(
    core_settings: &mut CoreSettings,
    update: CoreSettingsUpdate,
) -> Result<(), CoreSettingValidationError> {
    if let Some(value) = update.upload_limit_ki_bps {
        validate_u32(FIELD_UPLOAD_LIMIT_KIBPS, value)?;
        core_settings.upload_limit_ki_bps = value;
    }
    if let Some(value) = update.download_limit_ki_bps {
        validate_u32(FIELD_DOWNLOAD_LIMIT_KIBPS, value)?;
        core_settings.download_limit_ki_bps = value;
    }
    if let Some(value) = update.max_connections {
        validate_u32(FIELD_MAX_CONNECTIONS, value)?;
        core_settings.max_connections = value;
    }
    if let Some(value) = update.max_connections_per_five_seconds {
        validate_u32(FIELD_MAX_CONNECTIONS_PER_FIVE_SECONDS, value)?;
        core_settings.max_connections_per_five_seconds = value;
    }
    if let Some(value) = update.max_sources_per_file {
        validate_u32(FIELD_MAX_SOURCES_PER_FILE, value)?;
        core_settings.max_sources_per_file = value;
    }
    if let Some(value) = update.upload_client_data_rate {
        validate_u32(FIELD_UPLOAD_CLIENT_DATA_RATE, value)?;
        core_settings.upload_client_data_rate = value;
        core_settings.max_upload_slots =
            derive_upload_slots(core_settings.upload_limit_ki_bps, value);
    }
    if let Some(value) = update.max_upload_slots {
        validate_u32(FIELD_MAX_UPLOAD_SLOTS, value)?;
        core_settings.max_upload_slots = value;
    }
    if let Some(value) = update.upload_slot_elastic_percent {
        validate_u32(FIELD_UPLOAD_SLOT_ELASTIC_PERCENT, value)?;
        core_settings.upload_slot_elastic_percent = value;
    }
    if let Some(value) = update.queue_size {
        validate_u32(FIELD_QUEUE_SIZE, value)?;
        core_settings.queue_size = value;
    }
    if let Some(value) = update.auto_connect {
        core_settings.auto_connect = value;
    }
    if let Some(value) = update.reconnect {
        core_settings.reconnect = value;
    }
    if let Some(value) = update.credit_system {
        core_settings.credit_system = value;
    }
    if let Some(value) = update.safe_server_connect {
        core_settings.safe_server_connect = value;
    }
    if let Some(value) = update.add_servers_from_server {
        core_settings.add_servers_from_server = value;
    }
    if let Some(value) = update.network_kademlia {
        core_settings.network_kademlia = value;
    }
    if let Some(value) = update.network_ed2k {
        core_settings.network_ed2k = value;
    }
    Ok(())
}

pub fn changed_core_settings_update(
    next: &CoreSettings,
    baseline: Option<&CoreSettings>,
) -> CoreSettingsUpdate {
    let Some(baseline) = baseline else {
        return CoreSettingsUpdate {
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
    CoreSettingsUpdate {
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

pub fn parse_u32_core_setting(
    field_name: &str,
    value: &str,
) -> Result<u32, CoreSettingValidationError> {
    let parsed = value.trim().parse::<u32>().map_err(|_| {
        CoreSettingValidationError::new(format!("{field_name} must be an unsigned number"))
    })?;
    validate_u32(field_name, parsed)?;
    Ok(parsed)
}

pub fn validate_u32(field_name: &str, value: u32) -> Result<(), CoreSettingValidationError> {
    let field = core_setting_field(field_name).ok_or_else(|| {
        CoreSettingValidationError::new(format!("unknown core setting field: {field_name}"))
    })?;
    if field.kind != CoreSettingFieldKind::Number {
        return Err(CoreSettingValidationError::new(format!(
            "{field_name} is not a numeric core setting"
        )));
    }
    let min = field.min.unwrap_or(0);
    let max = field.max.unwrap_or(u32::MAX);
    if !(min..=max).contains(&value) {
        return Err(CoreSettingValidationError::new(format!(
            "{field_name} must be an unsigned number in the range {min}..{max}"
        )));
    }
    Ok(())
}

pub fn core_settings_schema() -> &'static [CoreSettingSpec] {
    CORE_SETTING_SPECS
}

pub fn core_setting_field(field_name: &str) -> Option<&'static CoreSettingSpec> {
    CORE_SETTING_SPECS
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
    fn default_core_settings_include_current_rest_fields() {
        let value = serde_json::to_value(default_core_settings()).unwrap();

        assert_eq!(value[FIELD_UPLOAD_LIMIT_KIBPS], 6200);
        assert_eq!(value[FIELD_RECONNECT], true);
        assert_eq!(value.as_object().unwrap().len(), CORE_SETTING_SPECS.len());
    }

    #[test]
    fn core_settings_schema_matches_default_values() {
        let defaults = serde_json::to_value(default_core_settings()).unwrap();

        for field in core_settings_schema() {
            let expected_default = match field.default_value {
                CoreSettingDefaultValue::Number(value) => serde_json::json!(value),
                CoreSettingDefaultValue::Boolean(value) => serde_json::json!(value),
            };
            assert_eq!(defaults[field.key], expected_default);
        }
    }

    #[test]
    fn core_settings_roundtrip_as_scalar_rows() {
        let mut core_settings = default_core_settings();
        core_settings.download_limit_ki_bps = 2048;
        core_settings.reconnect = false;

        let rows = core_settings_to_values(&core_settings).unwrap();
        assert_eq!(rows.len(), CORE_SETTING_SPECS.len());
        assert!(rows.contains(&(FIELD_RECONNECT, "false".to_string())));

        let decoded = core_settings_from_values(
            rows.iter()
                .map(|(key, value_json)| (*key, value_json.as_str())),
        )
        .unwrap();
        assert_eq!(decoded, core_settings);
    }

    #[test]
    fn core_settings_reject_unknown_keys() {
        let error = core_settings_from_values([("hiddenLegacySetting", "true")]).unwrap_err();

        assert!(
            error.to_string().contains("unknown field"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn typed_settings_section_roundtrips_as_scalar_rows() {
        let settings = VpnGuardSettings {
            enabled: true,
            mode: "block".to_string(),
            allowed_public_ip_cidrs: "192.0.2.0/24".to_string(),
        };

        let rows = section_settings_to_values(&settings).unwrap();
        assert!(rows.contains(&("enabled".to_string(), "true".to_string())));
        assert!(rows.contains(&("mode".to_string(), r#""block""#.to_string())));

        let decoded: VpnGuardSettings = section_settings_from_values(
            SECTION_VPN_GUARD,
            rows.iter()
                .map(|(key, value_json)| (key.as_str(), value_json.as_str())),
        )
        .unwrap();

        assert_eq!(decoded, settings);
    }

    #[test]
    fn typed_settings_section_rejects_unknown_keys() {
        let error = section_settings_from_values::<VpnGuardSettings>(
            SECTION_VPN_GUARD,
            [("hidden", "true")],
        )
        .unwrap_err();

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
    fn changed_core_settings_update_only_sets_changed_fields() {
        let baseline = default_core_settings();
        let mut next = baseline.clone();
        next.upload_limit_ki_bps = 2048;
        next.network_ed2k = false;

        let update = changed_core_settings_update(&next, Some(&baseline));

        assert_eq!(update.upload_limit_ki_bps, Some(2048));
        assert_eq!(update.network_ed2k, Some(false));
        assert_eq!(update.download_limit_ki_bps, None);
        assert_eq!(update.network_kademlia, None);
    }
}
