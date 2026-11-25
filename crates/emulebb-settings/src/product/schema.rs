//! OpenAPI 3.1 schema components generated from the typed settings declaration.
use super::*;
use serde_json::{Map, json};

/// Return named OpenAPI 3.1 schema components for the canonical settings model.
///
/// These describe wire shapes and leaf constraints. Whole-candidate dependency
/// validation remains authoritative. UTF-8 byte limits use explicit extensions
/// because JSON Schema string lengths count Unicode characters, not bytes.
/// Partial edits deliberately have no schema defaults: an omitted leaf must
/// stay omitted when a client constructs a PATCH.
pub fn settings_schemas() -> Value {
    let keys = json!({
        "type":"string",
        "enum":setting_specs().iter().map(|spec|spec.key).collect::<Vec<_>>()
    });
    let revision = json!({
        "type":"string",
        "minLength":1,
        "maxLength":i64::MAX.to_string().len(),
        "pattern":"^[1-9][0-9]*$",
        "description":format!("Opaque positive decimal-string CAS token, at most {}. No leading zero.",i64::MAX),
        "x-maximumDecimalValue":i64::MAX.to_string()
    });
    let mut saved = SavedSettings::schema();
    saved["x-maxSerializedBytes"] = json!(MAX_SAVED_BYTES);
    let mut patch = object_schema(
        [
            ("expectedRevision", revision.clone()),
            ("set", SettingsPartial::schema()),
            (
                "reset",
                json!({"type":"array","items":keys.clone(),"uniqueItems":true,"maxItems":setting_specs().len()}),
            ),
        ],
        false,
    );
    patch["required"] = json!(["expectedRevision"]);
    patch["x-maxSerializedBytes"] = json!(MAX_PATCH_BYTES);
    patch["description"] = json!(
        "Atomic settings edit. At least one leaf must be set or reset. Set/reset must not overlap. The complete edited candidate must validate; any failure saves nothing."
    );
    let failure = object_schema(
        [
            ("key", keys.clone()),
            (
                "code",
                json!({"type":"string","enum":[snapshot::APPLY_FAILURE_CODE]}),
            ),
            (
                "message",
                json!({"type":"string","maxLength":MAX_APPLY_MESSAGE_BYTES,"x-maxUtf8Bytes":MAX_APPLY_MESSAGE_BYTES}),
            ),
            ("truncated", json!({"type":"boolean"})),
        ],
        true,
    );
    let application = object_schema(
        [
            (
                "pendingRestart",
                json!({"type":"array","items":keys.clone(),"uniqueItems":true,"maxItems":setting_specs().len()}),
            ),
            (
                "failed",
                json!({"type":"array","items":failure.clone(),"maxItems":setting_specs().len(),"x-uniqueBy":"key"}),
            ),
        ],
        true,
    );
    let mut read = object_schema(
        [
            ("saved", saved.clone()),
            ("effective", SettingsValues::schema()),
            ("application", application.clone()),
        ],
        true,
    );
    read["x-maxSerializedBytes"] = json!(MAX_SNAPSHOT_BYTES);
    read["description"] = json!(
        "Coherent settings data. The containing native envelope carries the saved revision in meta.settingsRevision; effective values are supplied by the runtime owner."
    );
    json!({
        "SettingsValues":SettingsValues::schema(),
        "SavedSettings":saved,
        "SettingsPartial":SettingsPartial::schema(),
        "SettingsPatch":patch,
        "SettingKey":keys,
        "SettingsRevision":revision,
        "SettingApplyFailure":failure,
        "SettingsApplicationStatus":application,
        "SettingsReadData":read
    })
}

pub(super) fn object_schema<const N: usize>(fields: [(&str, Value); N], required: bool) -> Value {
    let mut properties = Map::new();
    let mut names = Vec::with_capacity(N);
    for (key, schema) in fields {
        properties.insert(key.into(), schema);
        names.push(key);
    }
    let mut value = json!({"type":"object","properties":properties,"additionalProperties":false});
    if required && !names.is_empty() {
        value["required"] = json!(names);
    }
    value
}

pub(super) fn saved_leaf_schema<T: SettingType>(rule: Rule) -> Value {
    object_schema(
        [
            ("mode", json!({"type":"string","enum":["default","custom"]})),
            ("value", leaf_schema::<T>(rule)),
        ],
        true,
    )
}

pub(super) fn leaf_schema<T: SettingType>(rule: Rule) -> Value {
    let mut value = match rule {
        Rule::Boolean => json!({"type":"boolean"}),
        Rule::Integer { min, max, step } => {
            json!({"type":"integer","minimum":min,"maximum":max,"multipleOf":step})
        }
        Rule::Text {
            min_bytes,
            max_bytes,
            forbid_controls,
        } => {
            let mut text = json!({
                "type":"string",
                "maxLength":max_bytes,
                "x-minUtf8Bytes":min_bytes,
                "x-maxUtf8Bytes":max_bytes,
                "pattern":if forbid_controls {r"^[^\u0000-\u001F\u007F-\u009F]*$"} else {r"^[^\u0000]*$"}
            });
            if min_bytes > 0 {
                text["minLength"] = json!(1);
            }
            text
        }
        Rule::Path => {
            json!({"type":"string","minLength":1,"pattern":r"^[^\u0000]+$","description":"Profile-relative or absolute UTF-8 filesystem path without NUL. No shell, environment or tilde expansion."})
        }
        Rule::Ipv4 => {
            json!({"type":"string","format":"ipv4","description":"Unicast IPv4 address."})
        }
        Rule::VpnMode => json!({"type":"string","enum":[VpnMode::Off,VpnMode::Block]}),
        Rule::SharedFilesVisibility => json!({"type":"string","enum":[
            SharedFilesVisibility::Everyone, SharedFilesVisibility::Friends, SharedFilesVisibility::Off
        ]}),
        Rule::DnsServers | Rule::NatBackends | Rule::Ipv4Cidrs => {
            let (min, max) = rule.list_bounds().expect("list rule has bounds");
            let items = match rule {
                Rule::DnsServers => {
                    json!({"type":"string","description":"Unicast IPv4 socket address with a nonzero port."})
                }
                Rule::NatBackends => {
                    json!({"type":"string","enum":[NatBackend::PcpNatpmp,NatBackend::Upnp]})
                }
                _ => {
                    json!({"type":"string","description":"Canonical IPv4 CIDR with no host bits set."})
                }
            };
            json!({"type":"array","minItems":min,"maxItems":max,"uniqueItems":true,"items":items})
        }
    };
    if T::NULLABLE {
        // WHY: wrapping keeps all constraints conditional on the non-null branch;
        // in particular an enum must not accidentally exclude explicit null.
        value = json!({"anyOf":[value,{"type":"null"}]});
    }
    value
}

#[cfg(test)]
mod tests;
