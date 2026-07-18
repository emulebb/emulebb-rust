use std::{error::Error, fmt, net::Ipv4Addr, path::PathBuf};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};

mod surface;
pub use surface::{
    BOOTSTRAP_SETTINGS_SURFACE, SettingSurfaceClass, SettingSurfaceSpec,
    SettingsSectionResourceSpec, app_settings_surface_inventory,
    bootstrap_settings_surface_inventory, settings_section_resource_inventory,
};

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
    pub hostname_lookup: HostnameLookupSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct HostnameLookupSettings {
    pub enabled: bool,
    pub dns_servers: Vec<String>,
    pub cache_ttl_secs: u64,
    pub max_lookups_per_tick: usize,
    pub tick_interval_secs: u64,
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
    pub daemon: Option<DaemonSettingsUpdate>,
    pub ed2k: Option<Ed2kSettingsUpdate>,
    pub kad: Option<KadSettingsUpdate>,
    pub nat: Option<NatSettingsUpdate>,
    pub vpn_guard: Option<VpnGuardSettingsUpdate>,
    pub ip_filter: Option<IpFilterSettingsUpdate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullableUpdate<T> {
    Null,
    Value(T),
}

impl<T> NullableUpdate<T> {
    pub fn into_option(self) -> Option<T> {
        match self {
            Self::Null => None,
            Self::Value(value) => Some(value),
        }
    }
}

impl<T> Serialize for NullableUpdate<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Null => serializer.serialize_none(),
            Self::Value(value) => value.serialize(serializer),
        }
    }
}

fn deserialize_nullable_update<'de, D, T>(
    deserializer: D,
) -> Result<Option<NullableUpdate<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
        .map(|value| Some(value.map_or(NullableUpdate::Null, NullableUpdate::Value)))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct DaemonSettingsUpdate {
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_update",
        skip_serializing_if = "Option::is_none"
    )]
    pub incoming_dir: Option<NullableUpdate<PathBuf>>,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_update",
        skip_serializing_if = "Option::is_none"
    )]
    pub p2p_bind_ip: Option<NullableUpdate<Ipv4Addr>>,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_update",
        skip_serializing_if = "Option::is_none"
    )]
    pub p2p_bind_interface: Option<NullableUpdate<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_update",
        skip_serializing_if = "Option::is_none"
    )]
    pub ed2k_user_hash: Option<NullableUpdate<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname_lookup: Option<HostnameLookupSettingsUpdate>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct HostnameLookupSettingsUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_servers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lookups_per_tick: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tick_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Ed2kSettingsUpdate {
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_update",
        skip_serializing_if = "Option::is_none"
    )]
    pub listen_port: Option<NullableUpdate<u16>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscation_enabled: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_update",
        skip_serializing_if = "Option::is_none"
    )]
    pub probe_search_term: Option<NullableUpdate<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_connect_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_server_connect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_rotation_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_downloads: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_new_connections_per_five_seconds: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_half_open_connections: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sources_per_file: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_parallel_download_peers: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyword_server_attempt_budget: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_hash_keyword_server_attempt_budget: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_server_attempt_budget: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_queue: Option<Ed2kUploadQueueSettingsUpdate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_limit_bytes_per_sec: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_udp_reask: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_emule_rust_identity: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_servers_from_server: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead_server_retries: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Ed2kUploadQueueSettingsUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_slots: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elastic_percent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_limit_bytes_per_sec: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elastic_underfill_bytes_per_sec: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elastic_underfill_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting_capacity: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_transfer_percent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_time_limit_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct KadSettingsUpdate {
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_update",
        skip_serializing_if = "Option::is_none"
    )]
    pub listen_port: Option<NullableUpdate<u16>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_min_routing_contacts: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_store_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_store_keyword_ttl_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_store_source_ttl_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_store_notes_ttl_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_store_keyword_capacity: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_store_source_capacity: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_store_notes_capacity: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_store_source_per_file_capacity: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_store_notes_per_file_capacity: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_shared_files_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub republish_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_contact_fanout: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_firewall_check_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_firewall_check_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_firewall_check_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_firewall_check_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buddy_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_maintenance_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snoop_queue_dedup_window_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snoop_queue_general_max_queries_per_600s: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snoop_queue_general_drain_cooldown_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snoop_queue_source_max_queries_per_600s: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snoop_queue_source_drain_cooldown_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snoop_queue_source_stop_after_results: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct NatSettingsUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_initial_mapping: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_order: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_update",
        skip_serializing_if = "Option::is_none"
    )]
    pub bind_ip: Option<NullableUpdate<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_update",
        skip_serializing_if = "Option::is_none"
    )]
    pub igd_ip: Option<NullableUpdate<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_update",
        skip_serializing_if = "Option::is_none"
    )]
    pub minissdpd_socket: Option<NullableUpdate<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_update",
        skip_serializing_if = "Option::is_none"
    )]
    pub ssdp_local_port: Option<NullableUpdate<u16>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_duration_secs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renew_margin_secs: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_update",
        skip_serializing_if = "Option::is_none"
    )]
    pub external_ip_override: Option<NullableUpdate<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct VpnGuardSettingsUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_public_ip_cidrs: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct IpFilterSettingsUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_update",
        skip_serializing_if = "Option::is_none"
    )]
    pub path: Option<NullableUpdate<PathBuf>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
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

impl Default for HostnameLookupSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            dns_servers: Vec::new(),
            cache_ttl_secs: 86_400,
            max_lookups_per_tick: 32,
            tick_interval_secs: 30,
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
    update
        .core
        .as_ref()
        .is_none_or(core_settings_update_is_empty)
        && update
            .daemon
            .as_ref()
            .is_none_or(DaemonSettingsUpdate::is_empty)
        && update
            .ed2k
            .as_ref()
            .is_none_or(Ed2kSettingsUpdate::is_empty)
        && update.kad.as_ref().is_none_or(KadSettingsUpdate::is_empty)
        && update.nat.as_ref().is_none_or(NatSettingsUpdate::is_empty)
        && update
            .vpn_guard
            .as_ref()
            .is_none_or(VpnGuardSettingsUpdate::is_empty)
        && update
            .ip_filter
            .as_ref()
            .is_none_or(IpFilterSettingsUpdate::is_empty)
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

impl DaemonSettingsUpdate {
    pub fn is_empty(&self) -> bool {
        self.incoming_dir.is_none()
            && self.p2p_bind_ip.is_none()
            && self.p2p_bind_interface.is_none()
            && self.ed2k_user_hash.is_none()
            && self
                .hostname_lookup
                .as_ref()
                .is_none_or(HostnameLookupSettingsUpdate::is_empty)
    }
}

impl HostnameLookupSettingsUpdate {
    pub fn is_empty(&self) -> bool {
        self.enabled.is_none()
            && self.dns_servers.is_none()
            && self.cache_ttl_secs.is_none()
            && self.max_lookups_per_tick.is_none()
            && self.tick_interval_secs.is_none()
    }
}

impl Ed2kSettingsUpdate {
    pub fn is_empty(&self) -> bool {
        self.listen_port.is_none()
            && self.obfuscation_enabled.is_none()
            && self.probe_search_term.is_none()
            && self.connect_timeout_secs.is_none()
            && self.server_connect_timeout_secs.is_none()
            && self.callback_timeout_secs.is_none()
            && self.reconnect_interval_secs.is_none()
            && self.reconnect_enabled.is_none()
            && self.safe_server_connect.is_none()
            && self.keepalive_secs.is_none()
            && self.session_rotation_secs.is_none()
            && self.max_concurrent_downloads.is_none()
            && self.max_new_connections_per_five_seconds.is_none()
            && self.max_half_open_connections.is_none()
            && self.max_sources_per_file.is_none()
            && self.max_parallel_download_peers.is_none()
            && self.keyword_server_attempt_budget.is_none()
            && self.exact_hash_keyword_server_attempt_budget.is_none()
            && self.source_server_attempt_budget.is_none()
            && self
                .upload_queue
                .as_ref()
                .is_none_or(Ed2kUploadQueueSettingsUpdate::is_empty)
            && self.download_limit_bytes_per_sec.is_none()
            && self.enable_udp_reask.is_none()
            && self.publish_emule_rust_identity.is_none()
            && self.add_servers_from_server.is_none()
            && self.dead_server_retries.is_none()
    }
}

impl Ed2kUploadQueueSettingsUpdate {
    pub fn is_empty(&self) -> bool {
        self.active_slots.is_none()
            && self.elastic_percent.is_none()
            && self.upload_limit_bytes_per_sec.is_none()
            && self.elastic_underfill_bytes_per_sec.is_none()
            && self.elastic_underfill_secs.is_none()
            && self.waiting_capacity.is_none()
            && self.waiting_timeout_secs.is_none()
            && self.granted_timeout_secs.is_none()
            && self.upload_timeout_secs.is_none()
            && self.session_transfer_percent.is_none()
            && self.session_time_limit_secs.is_none()
    }
}

impl KadSettingsUpdate {
    pub fn is_empty(&self) -> bool {
        self.listen_port.is_none()
            && self.bootstrap_min_routing_contacts.is_none()
            && self.local_store_enabled.is_none()
            && self.local_store_keyword_ttl_secs.is_none()
            && self.local_store_source_ttl_secs.is_none()
            && self.local_store_notes_ttl_secs.is_none()
            && self.local_store_keyword_capacity.is_none()
            && self.local_store_source_capacity.is_none()
            && self.local_store_notes_capacity.is_none()
            && self.local_store_source_per_file_capacity.is_none()
            && self.local_store_notes_per_file_capacity.is_none()
            && self.publish_shared_files_enabled.is_none()
            && self.republish_interval_secs.is_none()
            && self.publish_contact_fanout.is_none()
            && self.udp_firewall_check_enabled.is_none()
            && self.udp_firewall_check_interval_secs.is_none()
            && self.tcp_firewall_check_enabled.is_none()
            && self.tcp_firewall_check_interval_secs.is_none()
            && self.buddy_enabled.is_none()
            && self.routing_maintenance_enabled.is_none()
            && self.snoop_queue_dedup_window_secs.is_none()
            && self.snoop_queue_general_max_queries_per_600s.is_none()
            && self.snoop_queue_general_drain_cooldown_secs.is_none()
            && self.snoop_queue_source_max_queries_per_600s.is_none()
            && self.snoop_queue_source_drain_cooldown_secs.is_none()
            && self.snoop_queue_source_stop_after_results.is_none()
    }
}

impl NatSettingsUpdate {
    pub fn is_empty(&self) -> bool {
        self.enabled.is_none()
            && self.require_initial_mapping.is_none()
            && self.backend_order.is_none()
            && self.bind_ip.is_none()
            && self.igd_ip.is_none()
            && self.minissdpd_socket.is_none()
            && self.ssdp_local_port.is_none()
            && self.discovery_timeout_secs.is_none()
            && self.lease_duration_secs.is_none()
            && self.renew_margin_secs.is_none()
            && self.external_ip_override.is_none()
    }
}

impl VpnGuardSettingsUpdate {
    pub fn is_empty(&self) -> bool {
        self.enabled.is_none() && self.mode.is_none() && self.allowed_public_ip_cidrs.is_none()
    }
}

impl IpFilterSettingsUpdate {
    pub fn is_empty(&self) -> bool {
        self.enabled.is_none() && self.path.is_none() && self.level.is_none()
    }
}

pub fn apply_daemon_settings_update(settings: &mut DaemonSettings, update: DaemonSettingsUpdate) {
    apply_nullable_update(&mut settings.incoming_dir, update.incoming_dir);
    apply_nullable_update(&mut settings.p2p_bind_ip, update.p2p_bind_ip);
    apply_nullable_update(&mut settings.p2p_bind_interface, update.p2p_bind_interface);
    apply_nullable_update(&mut settings.ed2k_user_hash, update.ed2k_user_hash);
    if let Some(hostname_lookup) = update.hostname_lookup {
        apply_hostname_lookup_settings_update(&mut settings.hostname_lookup, hostname_lookup);
    }
}

fn apply_hostname_lookup_settings_update(
    settings: &mut HostnameLookupSettings,
    update: HostnameLookupSettingsUpdate,
) {
    if let Some(value) = update.enabled {
        settings.enabled = value;
    }
    if let Some(value) = update.dns_servers {
        settings.dns_servers = value;
    }
    if let Some(value) = update.cache_ttl_secs {
        settings.cache_ttl_secs = value;
    }
    if let Some(value) = update.max_lookups_per_tick {
        settings.max_lookups_per_tick = value;
    }
    if let Some(value) = update.tick_interval_secs {
        settings.tick_interval_secs = value;
    }
}

pub fn apply_ed2k_settings_update(settings: &mut Ed2kSettings, update: Ed2kSettingsUpdate) {
    apply_nullable_update(&mut settings.listen_port, update.listen_port);
    if let Some(value) = update.obfuscation_enabled {
        settings.obfuscation_enabled = value;
    }
    apply_nullable_update(&mut settings.probe_search_term, update.probe_search_term);
    if let Some(value) = update.connect_timeout_secs {
        settings.connect_timeout_secs = value;
    }
    if let Some(value) = update.server_connect_timeout_secs {
        settings.server_connect_timeout_secs = value;
    }
    if let Some(value) = update.callback_timeout_secs {
        settings.callback_timeout_secs = value;
    }
    if let Some(value) = update.reconnect_interval_secs {
        settings.reconnect_interval_secs = value;
    }
    if let Some(value) = update.reconnect_enabled {
        settings.reconnect_enabled = value;
    }
    if let Some(value) = update.safe_server_connect {
        settings.safe_server_connect = value;
    }
    if let Some(value) = update.keepalive_secs {
        settings.keepalive_secs = value;
    }
    if let Some(value) = update.session_rotation_secs {
        settings.session_rotation_secs = value;
    }
    if let Some(value) = update.max_concurrent_downloads {
        settings.max_concurrent_downloads = value;
    }
    if let Some(value) = update.max_new_connections_per_five_seconds {
        settings.max_new_connections_per_five_seconds = value;
    }
    if let Some(value) = update.max_half_open_connections {
        settings.max_half_open_connections = value;
    }
    if let Some(value) = update.max_sources_per_file {
        settings.max_sources_per_file = value;
    }
    if let Some(value) = update.max_parallel_download_peers {
        settings.max_parallel_download_peers = value;
    }
    if let Some(value) = update.keyword_server_attempt_budget {
        settings.keyword_server_attempt_budget = value;
    }
    if let Some(value) = update.exact_hash_keyword_server_attempt_budget {
        settings.exact_hash_keyword_server_attempt_budget = value;
    }
    if let Some(value) = update.source_server_attempt_budget {
        settings.source_server_attempt_budget = value;
    }
    if let Some(upload_queue) = update.upload_queue {
        apply_ed2k_upload_queue_settings_update(&mut settings.upload_queue, upload_queue);
    }
    if let Some(value) = update.download_limit_bytes_per_sec {
        settings.download_limit_bytes_per_sec = value;
    }
    if let Some(value) = update.enable_udp_reask {
        settings.enable_udp_reask = value;
    }
    if let Some(value) = update.publish_emule_rust_identity {
        settings.publish_emule_rust_identity = value;
    }
    if let Some(value) = update.add_servers_from_server {
        settings.add_servers_from_server = value;
    }
    if let Some(value) = update.dead_server_retries {
        settings.dead_server_retries = value;
    }
}

fn apply_ed2k_upload_queue_settings_update(
    settings: &mut Ed2kUploadQueueSettings,
    update: Ed2kUploadQueueSettingsUpdate,
) {
    if let Some(value) = update.active_slots {
        settings.active_slots = value;
    }
    if let Some(value) = update.elastic_percent {
        settings.elastic_percent = value;
    }
    if let Some(value) = update.upload_limit_bytes_per_sec {
        settings.upload_limit_bytes_per_sec = value;
    }
    if let Some(value) = update.elastic_underfill_bytes_per_sec {
        settings.elastic_underfill_bytes_per_sec = value;
    }
    if let Some(value) = update.elastic_underfill_secs {
        settings.elastic_underfill_secs = value;
    }
    if let Some(value) = update.waiting_capacity {
        settings.waiting_capacity = value;
    }
    if let Some(value) = update.waiting_timeout_secs {
        settings.waiting_timeout_secs = value;
    }
    if let Some(value) = update.granted_timeout_secs {
        settings.granted_timeout_secs = value;
    }
    if let Some(value) = update.upload_timeout_secs {
        settings.upload_timeout_secs = value;
    }
    if let Some(value) = update.session_transfer_percent {
        settings.session_transfer_percent = value;
    }
    if let Some(value) = update.session_time_limit_secs {
        settings.session_time_limit_secs = value;
    }
}

pub fn apply_kad_settings_update(settings: &mut KadSettings, update: KadSettingsUpdate) {
    apply_nullable_update(&mut settings.listen_port, update.listen_port);
    if let Some(value) = update.bootstrap_min_routing_contacts {
        settings.bootstrap_min_routing_contacts = value;
    }
    if let Some(value) = update.local_store_enabled {
        settings.local_store_enabled = value;
    }
    if let Some(value) = update.local_store_keyword_ttl_secs {
        settings.local_store_keyword_ttl_secs = value;
    }
    if let Some(value) = update.local_store_source_ttl_secs {
        settings.local_store_source_ttl_secs = value;
    }
    if let Some(value) = update.local_store_notes_ttl_secs {
        settings.local_store_notes_ttl_secs = value;
    }
    if let Some(value) = update.local_store_keyword_capacity {
        settings.local_store_keyword_capacity = value;
    }
    if let Some(value) = update.local_store_source_capacity {
        settings.local_store_source_capacity = value;
    }
    if let Some(value) = update.local_store_notes_capacity {
        settings.local_store_notes_capacity = value;
    }
    if let Some(value) = update.local_store_source_per_file_capacity {
        settings.local_store_source_per_file_capacity = value;
    }
    if let Some(value) = update.local_store_notes_per_file_capacity {
        settings.local_store_notes_per_file_capacity = value;
    }
    if let Some(value) = update.publish_shared_files_enabled {
        settings.publish_shared_files_enabled = value;
    }
    if let Some(value) = update.republish_interval_secs {
        settings.republish_interval_secs = value;
    }
    if let Some(value) = update.publish_contact_fanout {
        settings.publish_contact_fanout = value;
    }
    if let Some(value) = update.udp_firewall_check_enabled {
        settings.udp_firewall_check_enabled = value;
    }
    if let Some(value) = update.udp_firewall_check_interval_secs {
        settings.udp_firewall_check_interval_secs = value;
    }
    if let Some(value) = update.tcp_firewall_check_enabled {
        settings.tcp_firewall_check_enabled = value;
    }
    if let Some(value) = update.tcp_firewall_check_interval_secs {
        settings.tcp_firewall_check_interval_secs = value;
    }
    if let Some(value) = update.buddy_enabled {
        settings.buddy_enabled = value;
    }
    if let Some(value) = update.routing_maintenance_enabled {
        settings.routing_maintenance_enabled = value;
    }
    if let Some(value) = update.snoop_queue_dedup_window_secs {
        settings.snoop_queue_dedup_window_secs = value;
    }
    if let Some(value) = update.snoop_queue_general_max_queries_per_600s {
        settings.snoop_queue_general_max_queries_per_600s = value;
    }
    if let Some(value) = update.snoop_queue_general_drain_cooldown_secs {
        settings.snoop_queue_general_drain_cooldown_secs = value;
    }
    if let Some(value) = update.snoop_queue_source_max_queries_per_600s {
        settings.snoop_queue_source_max_queries_per_600s = value;
    }
    if let Some(value) = update.snoop_queue_source_drain_cooldown_secs {
        settings.snoop_queue_source_drain_cooldown_secs = value;
    }
    if let Some(value) = update.snoop_queue_source_stop_after_results {
        settings.snoop_queue_source_stop_after_results = value;
    }
}

pub fn apply_nat_settings_update(settings: &mut NatSettings, update: NatSettingsUpdate) {
    if let Some(value) = update.enabled {
        settings.enabled = value;
    }
    if let Some(value) = update.require_initial_mapping {
        settings.require_initial_mapping = value;
    }
    if let Some(value) = update.backend_order {
        settings.backend_order = value;
    }
    apply_nullable_update(&mut settings.bind_ip, update.bind_ip);
    apply_nullable_update(&mut settings.igd_ip, update.igd_ip);
    apply_nullable_update(&mut settings.minissdpd_socket, update.minissdpd_socket);
    apply_nullable_update(&mut settings.ssdp_local_port, update.ssdp_local_port);
    if let Some(value) = update.discovery_timeout_secs {
        settings.discovery_timeout_secs = value;
    }
    if let Some(value) = update.lease_duration_secs {
        settings.lease_duration_secs = value;
    }
    if let Some(value) = update.renew_margin_secs {
        settings.renew_margin_secs = value;
    }
    apply_nullable_update(
        &mut settings.external_ip_override,
        update.external_ip_override,
    );
}

pub fn apply_vpn_guard_settings_update(
    settings: &mut VpnGuardSettings,
    update: VpnGuardSettingsUpdate,
) {
    if let Some(value) = update.enabled {
        settings.enabled = value;
    }
    if let Some(value) = update.mode {
        settings.mode = value;
    }
    if let Some(value) = update.allowed_public_ip_cidrs {
        settings.allowed_public_ip_cidrs = value;
    }
}

pub fn apply_ip_filter_settings_update(
    settings: &mut IpFilterSettings,
    update: IpFilterSettingsUpdate,
) {
    if let Some(value) = update.enabled {
        settings.enabled = value;
    }
    apply_nullable_update(&mut settings.path, update.path);
    if let Some(value) = update.level {
        settings.level = value;
    }
}

fn apply_nullable_update<T>(target: &mut Option<T>, update: Option<NullableUpdate<T>>) {
    if let Some(update) = update {
        *target = update.into_option();
    }
}

fn nullable_from_option<T>(value: Option<T>) -> NullableUpdate<T> {
    value.map_or(NullableUpdate::Null, NullableUpdate::Value)
}

impl From<DaemonSettings> for DaemonSettingsUpdate {
    fn from(settings: DaemonSettings) -> Self {
        Self {
            incoming_dir: Some(nullable_from_option(settings.incoming_dir)),
            p2p_bind_ip: Some(nullable_from_option(settings.p2p_bind_ip)),
            p2p_bind_interface: Some(nullable_from_option(settings.p2p_bind_interface)),
            ed2k_user_hash: Some(nullable_from_option(settings.ed2k_user_hash)),
            hostname_lookup: Some(settings.hostname_lookup.into()),
        }
    }
}

impl From<HostnameLookupSettings> for HostnameLookupSettingsUpdate {
    fn from(settings: HostnameLookupSettings) -> Self {
        Self {
            enabled: Some(settings.enabled),
            dns_servers: Some(settings.dns_servers),
            cache_ttl_secs: Some(settings.cache_ttl_secs),
            max_lookups_per_tick: Some(settings.max_lookups_per_tick),
            tick_interval_secs: Some(settings.tick_interval_secs),
        }
    }
}

impl From<Ed2kSettings> for Ed2kSettingsUpdate {
    fn from(settings: Ed2kSettings) -> Self {
        Self {
            listen_port: Some(nullable_from_option(settings.listen_port)),
            obfuscation_enabled: Some(settings.obfuscation_enabled),
            probe_search_term: Some(nullable_from_option(settings.probe_search_term)),
            connect_timeout_secs: Some(settings.connect_timeout_secs),
            server_connect_timeout_secs: Some(settings.server_connect_timeout_secs),
            callback_timeout_secs: Some(settings.callback_timeout_secs),
            reconnect_interval_secs: Some(settings.reconnect_interval_secs),
            reconnect_enabled: Some(settings.reconnect_enabled),
            safe_server_connect: Some(settings.safe_server_connect),
            keepalive_secs: Some(settings.keepalive_secs),
            session_rotation_secs: Some(settings.session_rotation_secs),
            max_concurrent_downloads: Some(settings.max_concurrent_downloads),
            max_new_connections_per_five_seconds: Some(
                settings.max_new_connections_per_five_seconds,
            ),
            max_half_open_connections: Some(settings.max_half_open_connections),
            max_sources_per_file: Some(settings.max_sources_per_file),
            max_parallel_download_peers: Some(settings.max_parallel_download_peers),
            keyword_server_attempt_budget: Some(settings.keyword_server_attempt_budget),
            exact_hash_keyword_server_attempt_budget: Some(
                settings.exact_hash_keyword_server_attempt_budget,
            ),
            source_server_attempt_budget: Some(settings.source_server_attempt_budget),
            upload_queue: Some(settings.upload_queue.into()),
            download_limit_bytes_per_sec: Some(settings.download_limit_bytes_per_sec),
            enable_udp_reask: Some(settings.enable_udp_reask),
            publish_emule_rust_identity: Some(settings.publish_emule_rust_identity),
            add_servers_from_server: Some(settings.add_servers_from_server),
            dead_server_retries: Some(settings.dead_server_retries),
        }
    }
}

impl From<Ed2kUploadQueueSettings> for Ed2kUploadQueueSettingsUpdate {
    fn from(settings: Ed2kUploadQueueSettings) -> Self {
        Self {
            active_slots: Some(settings.active_slots),
            elastic_percent: Some(settings.elastic_percent),
            upload_limit_bytes_per_sec: Some(settings.upload_limit_bytes_per_sec),
            elastic_underfill_bytes_per_sec: Some(settings.elastic_underfill_bytes_per_sec),
            elastic_underfill_secs: Some(settings.elastic_underfill_secs),
            waiting_capacity: Some(settings.waiting_capacity),
            waiting_timeout_secs: Some(settings.waiting_timeout_secs),
            granted_timeout_secs: Some(settings.granted_timeout_secs),
            upload_timeout_secs: Some(settings.upload_timeout_secs),
            session_transfer_percent: Some(settings.session_transfer_percent),
            session_time_limit_secs: Some(settings.session_time_limit_secs),
        }
    }
}

impl From<KadSettings> for KadSettingsUpdate {
    fn from(settings: KadSettings) -> Self {
        Self {
            listen_port: Some(nullable_from_option(settings.listen_port)),
            bootstrap_min_routing_contacts: Some(settings.bootstrap_min_routing_contacts),
            local_store_enabled: Some(settings.local_store_enabled),
            local_store_keyword_ttl_secs: Some(settings.local_store_keyword_ttl_secs),
            local_store_source_ttl_secs: Some(settings.local_store_source_ttl_secs),
            local_store_notes_ttl_secs: Some(settings.local_store_notes_ttl_secs),
            local_store_keyword_capacity: Some(settings.local_store_keyword_capacity),
            local_store_source_capacity: Some(settings.local_store_source_capacity),
            local_store_notes_capacity: Some(settings.local_store_notes_capacity),
            local_store_source_per_file_capacity: Some(
                settings.local_store_source_per_file_capacity,
            ),
            local_store_notes_per_file_capacity: Some(settings.local_store_notes_per_file_capacity),
            publish_shared_files_enabled: Some(settings.publish_shared_files_enabled),
            republish_interval_secs: Some(settings.republish_interval_secs),
            publish_contact_fanout: Some(settings.publish_contact_fanout),
            udp_firewall_check_enabled: Some(settings.udp_firewall_check_enabled),
            udp_firewall_check_interval_secs: Some(settings.udp_firewall_check_interval_secs),
            tcp_firewall_check_enabled: Some(settings.tcp_firewall_check_enabled),
            tcp_firewall_check_interval_secs: Some(settings.tcp_firewall_check_interval_secs),
            buddy_enabled: Some(settings.buddy_enabled),
            routing_maintenance_enabled: Some(settings.routing_maintenance_enabled),
            snoop_queue_dedup_window_secs: Some(settings.snoop_queue_dedup_window_secs),
            snoop_queue_general_max_queries_per_600s: Some(
                settings.snoop_queue_general_max_queries_per_600s,
            ),
            snoop_queue_general_drain_cooldown_secs: Some(
                settings.snoop_queue_general_drain_cooldown_secs,
            ),
            snoop_queue_source_max_queries_per_600s: Some(
                settings.snoop_queue_source_max_queries_per_600s,
            ),
            snoop_queue_source_drain_cooldown_secs: Some(
                settings.snoop_queue_source_drain_cooldown_secs,
            ),
            snoop_queue_source_stop_after_results: Some(
                settings.snoop_queue_source_stop_after_results,
            ),
        }
    }
}

impl From<NatSettings> for NatSettingsUpdate {
    fn from(settings: NatSettings) -> Self {
        Self {
            enabled: Some(settings.enabled),
            require_initial_mapping: Some(settings.require_initial_mapping),
            backend_order: Some(settings.backend_order),
            bind_ip: Some(nullable_from_option(settings.bind_ip)),
            igd_ip: Some(nullable_from_option(settings.igd_ip)),
            minissdpd_socket: Some(nullable_from_option(settings.minissdpd_socket)),
            ssdp_local_port: Some(nullable_from_option(settings.ssdp_local_port)),
            discovery_timeout_secs: Some(settings.discovery_timeout_secs),
            lease_duration_secs: Some(settings.lease_duration_secs),
            renew_margin_secs: Some(settings.renew_margin_secs),
            external_ip_override: Some(nullable_from_option(settings.external_ip_override)),
        }
    }
}

impl From<VpnGuardSettings> for VpnGuardSettingsUpdate {
    fn from(settings: VpnGuardSettings) -> Self {
        Self {
            enabled: Some(settings.enabled),
            mode: Some(settings.mode),
            allowed_public_ip_cidrs: Some(settings.allowed_public_ip_cidrs),
        }
    }
}

impl From<IpFilterSettings> for IpFilterSettingsUpdate {
    fn from(settings: IpFilterSettings) -> Self {
        Self {
            enabled: Some(settings.enabled),
            path: Some(nullable_from_option(settings.path)),
            level: Some(settings.level),
        }
    }
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
    fn partial_app_settings_update_preserves_unspecified_section_fields() {
        let mut settings = AppSettings::default();
        settings.nat.backend_order = vec!["first".to_string(), "second".to_string()];
        settings.nat.lease_duration_secs = 7_200;

        let update: AppSettingsUpdate =
            serde_json::from_str(r#"{"nat":{"enabled":true}}"#).unwrap();
        apply_nat_settings_update(&mut settings.nat, update.nat.unwrap());

        assert!(settings.nat.enabled);
        assert_eq!(settings.nat.backend_order, ["first", "second"]);
        assert_eq!(settings.nat.lease_duration_secs, 7_200);
    }

    #[test]
    fn nullable_app_settings_update_distinguishes_clear_from_missing() {
        let mut settings = AppSettings::default();
        settings.daemon.incoming_dir = Some(PathBuf::from("C:/Incoming"));
        settings.daemon.p2p_bind_interface = Some("hide.me".to_string());

        let update: AppSettingsUpdate =
            serde_json::from_str(r#"{"daemon":{"incomingDir":null}}"#).unwrap();
        apply_daemon_settings_update(&mut settings.daemon, update.daemon.unwrap());

        assert_eq!(settings.daemon.incoming_dir, None);
        assert_eq!(
            settings.daemon.p2p_bind_interface.as_deref(),
            Some("hide.me")
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
