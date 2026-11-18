use super::*;

fn leaf<'a>(schema: &'a Value, key: &str) -> &'a Value {
    key.split('.')
        .fold(schema, |schema, part| &schema["properties"][part])
}

fn assert_complete_shape(instance: &Value, schema: &Value) {
    let fields = instance.as_object().unwrap();
    let properties = schema["properties"].as_object().unwrap();
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        fields.keys().collect::<Vec<_>>(),
        properties.keys().collect::<Vec<_>>()
    );
    let required = schema["required"].as_array().unwrap();
    assert_eq!(required.len(), fields.len());
    for (key, value) in fields {
        assert!(required.iter().any(|required| required == key));
        if value.is_object() {
            assert_complete_shape(value, &properties[key]);
        }
    }
}

#[test]
fn complete_schemas_match_actual_serde_shapes_and_all_canonical_keys() {
    let schemas = settings_schemas();
    assert_complete_shape(
        &serde_json::to_value(SettingsValues::default()).unwrap(),
        &schemas["SettingsValues"],
    );
    assert_complete_shape(
        &serde_json::to_value(SavedSettings::default()).unwrap(),
        &schemas["SavedSettings"],
    );
    let keys = schemas["SettingKey"]["enum"].as_array().unwrap();
    assert_eq!(keys.len(), 59);
    for spec in setting_specs() {
        assert!(keys.iter().any(|key| key == spec.key));
        assert!(leaf(&schemas["SettingsValues"], spec.key).is_object());
        assert!(leaf(&schemas["SettingsPartial"], spec.key).is_object());
        let saved = leaf(&schemas["SavedSettings"], spec.key);
        assert_eq!(
            saved["properties"]["mode"]["enum"],
            json!(["default", "custom"])
        );
        assert_eq!(saved["required"], json!(["mode", "value"]));
    }
}

#[test]
fn partial_schema_does_not_invent_values_or_require_omitted_groups() {
    let schemas = settings_schemas();
    let partial = schemas["SettingsPartial"].to_string();
    assert!(!partial.contains("\"required\""));
    assert!(!partial.contains("\"default\""));
    let patch = &schemas["SettingsPatch"];
    assert_eq!(patch["required"], json!(["expectedRevision"]));
    assert_eq!(patch["properties"]["reset"]["items"], schemas["SettingKey"]);
    assert_eq!(patch["properties"]["reset"]["uniqueItems"], true);
    assert_eq!(patch["x-maxSerializedBytes"], MAX_PATCH_BYTES);
    assert_eq!(
        schemas["SavedSettings"]["x-maxSerializedBytes"],
        MAX_SAVED_BYTES
    );
    assert_eq!(schemas["SettingsRevision"]["type"], "string");
    assert_eq!(
        schemas["SettingsRevision"]["x-maximumDecimalValue"],
        i64::MAX.to_string()
    );
}

#[test]
fn nullable_enums_and_numbers_preserve_explicit_null_without_weakening_values() {
    let schemas = settings_schemas();
    let concurrent = leaf(
        &schemas["SettingsPartial"],
        "transfers.maxConcurrentDownloads",
    );
    assert_eq!(concurrent["anyOf"][0]["type"], "integer");
    assert_eq!(concurrent["anyOf"][0]["minimum"], 1);
    assert_eq!(concurrent["anyOf"][1], json!({"type":"null"}));
    let mode = leaf(&schemas["SettingsValues"], "security.vpnGuard.mode");
    assert_eq!(
        mode["enum"],
        serde_json::to_value([VpnMode::Off, VpnMode::Block]).unwrap()
    );
    assert!(mode.get("anyOf").is_none());
    let backends = leaf(&schemas["SettingsValues"], "network.nat.backendOrder");
    assert_eq!(backends["minItems"], 1);
    assert_eq!(backends["maxItems"], 2);
    assert_eq!(backends["uniqueItems"], true);
    assert_eq!(
        backends["items"]["enum"],
        serde_json::to_value([NatBackend::PcpNatpmp, NatBackend::Upnp]).unwrap()
    );
}

#[test]
fn unicode_byte_constraints_do_not_claim_character_counts_or_limit_paths() {
    let schemas = settings_schemas();
    let nickname = leaf(&schemas["SettingsValues"], "network.nickname");
    assert_eq!(nickname["x-maxUtf8Bytes"], 128);
    let mut values = SettingsValues::default();
    values.network.nickname = "é".repeat(64);
    assert!(values.validate().is_empty());
    values.network.nickname.push('é');
    assert!(
        values
            .validate()
            .iter()
            .any(|issue| issue.key == "network.nickname")
    );
    let path = leaf(&schemas["SettingsValues"], "storage.incomingDirectory");
    assert_eq!(path["type"], "string");
    assert_eq!(path["minLength"], 1);
    assert!(path.get("maxLength").is_none());
    assert!(path.get("x-maxUtf8Bytes").is_none());
}
