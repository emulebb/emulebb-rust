use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PreferenceFieldKind {
    Number,
    Boolean,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PreferenceField {
    pub json_name: &'static str,
    pub kind: PreferenceFieldKind,
    pub min: Option<u32>,
    pub max: Option<u32>,
}

pub const PREFERENCE_FIELDS: &[PreferenceField] = &[
    number(FIELD_UPLOAD_LIMIT_KIBPS, 1, u32::MAX - 1),
    number(FIELD_DOWNLOAD_LIMIT_KIBPS, 1, u32::MAX - 1),
    number(FIELD_MAX_CONNECTIONS, 1, i32::MAX as u32),
    number(FIELD_MAX_CONNECTIONS_PER_FIVE_SECONDS, 1, i32::MAX as u32),
    number(FIELD_MAX_SOURCES_PER_FILE, 1, i32::MAX as u32),
    number(FIELD_UPLOAD_CLIENT_DATA_RATE, 1, u32::MAX),
    number(FIELD_MAX_UPLOAD_SLOTS, 1, 64),
    number(FIELD_UPLOAD_SLOT_ELASTIC_PERCENT, 0, 100),
    number(FIELD_QUEUE_SIZE, 2_000, 10_000),
    boolean(FIELD_AUTO_CONNECT),
    boolean(FIELD_RECONNECT),
    boolean(FIELD_CREDIT_SYSTEM),
    boolean(FIELD_SAFE_SERVER_CONNECT),
    boolean(FIELD_ADD_SERVERS_FROM_SERVER),
    boolean(FIELD_NETWORK_KADEMLIA),
    boolean(FIELD_NETWORK_ED2K),
];

const fn number(json_name: &'static str, min: u32, max: u32) -> PreferenceField {
    PreferenceField {
        json_name,
        kind: PreferenceFieldKind::Number,
        min: Some(min),
        max: Some(max),
    }
}

const fn boolean(json_name: &'static str) -> PreferenceField {
    PreferenceField {
        json_name,
        kind: PreferenceFieldKind::Boolean,
        min: None,
        max: None,
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

pub fn preference_field(field_name: &str) -> Option<&'static PreferenceField> {
    PREFERENCE_FIELDS
        .iter()
        .find(|field| field.json_name == field_name)
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
        assert_eq!(value.as_object().unwrap().len(), PREFERENCE_FIELDS.len());
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
