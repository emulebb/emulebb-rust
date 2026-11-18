//! Typed product settings: declaration-derived values, saved modes and edits.
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    collections::HashSet,
    fmt,
    io::Write,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    sync::OnceLock,
};

#[macro_use]
mod groups;
mod catalog;
mod patch;
mod revision;
pub use catalog::*;
pub use patch::{SettingsPatch, json_size};
pub use revision::{SettingsRevision, SettingsRevisionError};

pub const MAX_SAVED_BYTES: usize = 131_072;
pub const MAX_PATCH_BYTES: usize = 262_144;
pub const MAX_SNAPSHOT_BYTES: usize = 524_288;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueMode {
    Default,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedValue<T> {
    pub mode: ValueMode,
    pub value: T,
}

impl<T: Clone + Eq> SavedValue<T> {
    fn from_default(value: &T) -> Self {
        Self {
            mode: ValueMode::Default,
            value: value.clone(),
        }
    }
    fn set(&mut self, value: T, default: &T) {
        self.mode = if &value == default {
            ValueMode::Default
        } else {
            ValueMode::Custom
        };
        self.value = value;
    }
    fn resolve(&mut self, default: &T) {
        if self.mode == ValueMode::Default {
            self.value.clone_from(default);
        }
    }
}

/// Presence is separate from T: null means Set(None) for nullable leaves;
/// omitted fields remain Unchanged. Required leaves use normal typed errors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PartialValue<T> {
    #[default]
    Unchanged,
    Set(T),
}
impl<T> PartialValue<T> {
    pub fn is_unchanged(&self) -> bool {
        matches!(self, Self::Unchanged)
    }
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for PartialValue<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self::Set)
    }
}
impl<T: Serialize> Serialize for PartialValue<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Unchanged => serializer.serialize_none(),
            Self::Set(value) => value.serialize(serializer),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NatBackend {
    PcpNatpmp,
    Upnp,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnMode {
    Off,
    Block,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplyMode {
    Live,
    Restart,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Rule {
    Boolean,
    Integer {
        min: u64,
        max: u64,
        step: u64,
    },
    Text {
        min_bytes: usize,
        max_bytes: usize,
        forbid_controls: bool,
    },
    Path,
    Ipv4,
    DnsServers,
    NatBackends,
    Ipv4Cidrs,
    VpnMode,
}

trait SettingType: Clone + Eq + Serialize + DeserializeOwned {
    const NULLABLE: bool = false;
}
macro_rules! setting_types { ($($ty:ty),*) => { $(impl SettingType for $ty {})* }; }
setting_types!(
    bool,
    u16,
    u32,
    u64,
    String,
    PathBuf,
    Ipv4Addr,
    Vec<SocketAddrV4>,
    Vec<NatBackend>,
    Vec<Ipv4Net>,
    VpnMode
);
impl<T: SettingType> SettingType for Option<T> {
    const NULLABLE: bool = true;
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingSpec {
    pub key: &'static str,
    pub nullable: bool,
    pub default_value: Value,
    pub application: ApplyMode,
    pub unit: &'static str,
    pub rule: Rule,
}
fn spec<T: SettingType>(
    key: &'static str,
    default: T,
    application: ApplyMode,
    unit: &'static str,
    rule: Rule,
) -> SettingSpec {
    SettingSpec {
        key,
        nullable: T::NULLABLE,
        default_value: serde_json::to_value(default).expect("compiled setting default serializes"),
        application,
        unit,
        rule,
    }
}
pub fn setting_specs() -> &'static [SettingSpec] {
    static SPECS: OnceLock<Vec<SettingSpec>> = OnceLock::new();
    SPECS.get_or_init(|| {
        let mut specs = Vec::new();
        SettingsValues::append_specs(&mut specs);
        specs
    })
}

/// Closed canonical key. Parsing performs only current-catalog lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct SettingKey(&'static str);
impl SettingKey {
    pub fn parse(value: &str) -> Result<Self, SettingsError> {
        setting_specs()
            .iter()
            .find(|spec| spec.key == value)
            .map(|spec| Self(spec.key))
            .ok_or(SettingsError::UnknownKey)
    }
    pub fn as_str(self) -> &'static str {
        self.0
    }
}
impl<'de> Deserialize<'de> for SettingKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationIssue {
    pub key: &'static str,
    pub code: &'static str,
    pub message: &'static str,
}
fn issue(
    issues: &mut Vec<ValidationIssue>,
    key: &'static str,
    code: &'static str,
    message: &'static str,
) {
    if !issues.iter().any(|issue| issue.key == key) {
        issues.push(ValidationIssue { key, code, message });
    }
}
fn unicast(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
}
fn validate_field<T: SettingType>(
    value: &T,
    key: &'static str,
    rule: Rule,
    issues: &mut Vec<ValidationIssue>,
) {
    let Ok(value) = serde_json::to_value(value) else {
        issue(
            issues,
            key,
            "invalid-value",
            "Value cannot be represented as UTF-8 JSON.",
        );
        return;
    };
    if value.is_null() && T::NULLABLE {
        return;
    }
    let valid = match rule {
        Rule::Boolean | Rule::VpnMode => true,
        Rule::Integer { min, max, step } => value
            .as_u64()
            .is_some_and(|n| n >= min && n <= max && n % step == 0),
        Rule::Text {
            min_bytes,
            max_bytes,
            forbid_controls,
        } => value.as_str().is_some_and(|v| {
            v.len() >= min_bytes
                && v.len() <= max_bytes
                && !v.contains('\0')
                && (!forbid_controls || !v.chars().any(char::is_control))
        }),
        Rule::Path => value
            .as_str()
            .is_some_and(|v| !v.is_empty() && !v.contains('\0')),
        Rule::Ipv4 => value
            .as_str()
            .and_then(|v| v.parse::<Ipv4Addr>().ok())
            .is_some_and(unicast),
        Rule::DnsServers | Rule::NatBackends | Rule::Ipv4Cidrs => {
            let Some(items) = value.as_array() else {
                issue(issues, key, "invalid-value", "Expected a typed list.");
                return;
            };
            let (min, max) = match rule {
                Rule::NatBackends => (1, 2),
                Rule::DnsServers => (0, 8),
                _ => (0, 256),
            };
            let mut seen = HashSet::new();
            items.len() >= min
                && items.len() <= max
                && items.iter().all(|item| {
                    let Some(item) = item.as_str() else {
                        return false;
                    };
                    seen.insert(item)
                        && match rule {
                            Rule::DnsServers => item
                                .parse::<SocketAddrV4>()
                                .is_ok_and(|addr| unicast(*addr.ip()) && addr.port() != 0),
                            Rule::Ipv4Cidrs => item
                                .parse::<Ipv4Net>()
                                .is_ok_and(|net| net.addr() == net.network()),
                            _ => true,
                        }
                })
        }
    };
    if !valid {
        issue(
            issues,
            key,
            "invalid-value",
            match rule {
                Rule::Integer { .. } => "Value is outside the supported integer range or step.",
                Rule::Text { .. } => {
                    "Text is outside the supported UTF-8 byte bounds or contains NUL."
                }
                Rule::Path => "Path must be nonempty UTF-8 without NUL.",
                Rule::Ipv4 => "Address must be unicast IPv4.",
                Rule::DnsServers => {
                    "Use at most eight distinct unicast IPv4 resolvers with nonzero ports."
                }
                Rule::NatBackends => "Select one or two distinct supported NAT backends.",
                Rule::Ipv4Cidrs => "Use at most 256 distinct canonical IPv4 CIDRs.",
                _ => "Value is invalid.",
            },
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsError {
    UnknownKey,
    InvalidValue,
    EmptyOperation,
    DuplicateReset,
    OverlappingEdit,
    DocumentTooLarge,
    InvalidDocument,
    Validation(Vec<ValidationIssue>),
}
impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownKey => "Unknown setting key.",
            Self::InvalidValue => "Value does not match the setting type.",
            Self::EmptyOperation => "Settings operation is empty.",
            Self::DuplicateReset => "A reset key occurs more than once.",
            Self::OverlappingEdit => "A key cannot be set and reset together.",
            Self::DocumentTooLarge => "Settings document exceeds its serialized byte limit.",
            Self::InvalidDocument => "Settings document is invalid.",
            Self::Validation(_) => "Settings validation failed.",
        })
    }
}
impl std::error::Error for SettingsError {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsEdit {
    #[serde(default)]
    pub set: SettingsPartial,
    #[serde(default)]
    pub reset: Vec<SettingKey>,
}

impl SettingsValues {
    pub fn validate(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();
        self.validate_fields(&mut issues);
        let cap = self.network.connections.max_connections;
        for (key, value) in [
            (
                "network.connections.maxHalfOpenConnections",
                self.network.connections.max_half_open_connections,
            ),
            (
                "transfers.maxParallelDownloadPeers",
                self.transfers.max_parallel_download_peers,
            ),
            (
                "transfers.upload.baseSlots",
                self.transfers.upload.base_slots,
            ),
        ] {
            if cap > 0 && cap <= i32::MAX as u32 && value > cap {
                issue(
                    &mut issues,
                    key,
                    "dependency",
                    "Value must not exceed the connection cap.",
                );
            }
        }
        if self.network.hostname_lookup.enabled
            && self.network.hostname_lookup.dns_servers.is_empty()
        {
            issue(
                &mut issues,
                "network.hostnameLookup.dnsServers",
                "required",
                "Hostname lookup requires a configured resolver.",
            );
        }
        if self.security.vpn_guard.mode == VpnMode::Block
            && self.network.p2p.bind_ip.is_none()
            && self.network.p2p.bind_interface.is_none()
        {
            issue(
                &mut issues,
                "security.vpnGuard.mode",
                "dependency",
                "Blocking VPN guard requires an explicit bind address or interface.",
            );
        }
        if self.security.ip_filter.enabled && self.security.ip_filter.file_path.is_none() {
            issue(
                &mut issues,
                "security.ipFilter.filePath",
                "required",
                "Enabled IP filtering requires a source path.",
            );
        }
        issues
    }
}
impl SavedSettings {
    pub fn resolve(&mut self) {
        self.resolve_with(&SettingsValues::default());
    }
    pub fn resolved(&self) -> Result<Self, SettingsError> {
        let mut saved = self.clone();
        saved.resolve();
        saved.check()?;
        Ok(saved)
    }
    fn check(&self) -> Result<(), SettingsError> {
        let issues = self.values().validate();
        if !issues.is_empty() {
            return Err(SettingsError::Validation(issues));
        }
        self.to_json_bytes().map(|_| ())
    }
    /// Apply the whole edit to a private candidate. The receiver never changes
    /// on validation, overlap, or size failure; persistence owns revision CAS.
    pub fn edited(&self, edit: &SettingsEdit) -> Result<Self, SettingsError> {
        let mut touched = Vec::new();
        edit.set.touched_keys(&mut touched);
        if touched.is_empty() && edit.reset.is_empty() {
            return Err(SettingsError::EmptyOperation);
        }
        let mut reset = HashSet::new();
        for key in &edit.reset {
            if !reset.insert(*key) {
                return Err(SettingsError::DuplicateReset);
            }
            if touched.contains(key) {
                return Err(SettingsError::OverlappingEdit);
            }
        }
        let defaults = SettingsValues::default();
        let mut candidate = self.clone();
        candidate.resolve_with(&defaults);
        candidate.apply_partial(&edit.set, &defaults);
        for key in &edit.reset {
            if !candidate.reset_key(key.0, &defaults) {
                return Err(SettingsError::UnknownKey);
            }
        }
        candidate.check()?;
        Ok(candidate)
    }
    /// Single-key typed input used by offline preparation; it shares validation
    /// and default classification with partial REST edits.
    pub fn with_value(&self, key: SettingKey, value: &Value) -> Result<Self, SettingsError> {
        let defaults = SettingsValues::default();
        let mut candidate = self.clone();
        candidate.resolve_with(&defaults);
        if !candidate.set_key(key.0, value, &defaults)? {
            return Err(SettingsError::UnknownKey);
        }
        candidate.check()?;
        Ok(candidate)
    }
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, SettingsError> {
        if bytes.len() > MAX_SAVED_BYTES {
            return Err(SettingsError::DocumentTooLarge);
        }
        let saved: Self =
            serde_json::from_slice(bytes).map_err(|_| SettingsError::InvalidDocument)?;
        saved.resolved()
    }
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, SettingsError> {
        let mut writer = LimitedJson {
            bytes: Vec::new(),
            exceeded: false,
        };
        if serde_json::to_writer(&mut writer, self).is_err() {
            return Err(if writer.exceeded {
                SettingsError::DocumentTooLarge
            } else {
                SettingsError::InvalidDocument
            });
        }
        Ok(writer.bytes)
    }
}
struct LimitedJson {
    bytes: Vec<u8>,
    exceeded: bool,
}
impl Write for LimitedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_SAVED_BYTES - self.bytes.len() {
            self.exceeded = true;
            return Err(std::io::Error::other("settings document limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
