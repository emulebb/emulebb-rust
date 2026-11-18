use super::*;
use serde_json::json;

fn key(value: &str) -> SettingKey {
    SettingKey::parse(value).unwrap()
}
fn edit(value: Value) -> SettingsEdit {
    serde_json::from_value(value).unwrap()
}

#[test]
fn complete_defaults_and_metadata_have_exactly_the_same_59_typed_leaves() {
    let saved = SavedSettings::default();
    let values = saved.values();
    assert!(values.validate().is_empty());
    let specs = setting_specs();
    assert_eq!(specs.len(), 59);
    assert_eq!(
        specs
            .iter()
            .map(|spec| spec.key)
            .collect::<HashSet<_>>()
            .len(),
        59
    );
    let plain = serde_json::to_value(values).unwrap();
    let document = serde_json::to_value(&saved).unwrap();
    for spec in specs {
        let pointer = format!("/{}", spec.key.replace('.', "/"));
        assert_eq!(plain.pointer(&pointer), Some(&spec.default_value));
        assert_eq!(
            document.pointer(&(pointer.clone() + "/mode")),
            Some(&json!("default"))
        );
        assert_eq!(
            document.pointer(&(pointer + "/value")),
            Some(&spec.default_value)
        );
    }
    assert_eq!(
        SavedSettings::from_json_bytes(&saved.to_json_bytes().unwrap()).unwrap(),
        saved
    );
}

#[test]
fn startup_resolves_only_default_modes_before_validation() {
    let mut saved = SavedSettings::default();
    saved.network.p2p.tcp_port.value = 0;
    let resolved = saved.resolved().unwrap();
    assert_eq!(resolved.network.p2p.tcp_port.value, 20019);
    assert_eq!(
        saved.network.p2p.tcp_port.value, 0,
        "resolution does not mutate saved input"
    );
    saved.network.p2p.tcp_port.mode = ValueMode::Custom;
    assert!(matches!(
        saved.resolved(),
        Err(SettingsError::Validation(_))
    ));
}

#[test]
fn validation_diagnostics_name_all_fields_without_echoing_input_values() {
    let mut values = SettingsValues::default();
    values.network.nickname = "Private Sample Value\n".into();
    values.network.hostname_lookup.enabled = true;
    let message = SettingsError::Validation(values.validate()).to_string();
    assert!(message.contains("network.nickname [invalid-value]"));
    assert!(message.contains("network.hostnameLookup.dnsServers [required]"));
    assert!(!message.contains("Private Sample Value"));
}

#[test]
fn custom_values_and_null_keep_their_modes_across_default_changes() {
    let mut saved = SavedSettings::default();
    saved.network.nickname = SavedValue {
        mode: ValueMode::Custom,
        value: "Sample".into(),
    };
    saved.network.p2p.bind_ip = SavedValue {
        mode: ValueMode::Custom,
        value: None,
    };
    let mut release = SettingsValues::default();
    release.network.nickname = "Sample".into();
    release.network.p2p.bind_ip = Some(Ipv4Addr::new(192, 0, 2, 1));
    saved.resolve_with(&release);
    assert_eq!(saved.network.nickname.mode, ValueMode::Custom);
    assert_eq!(saved.network.p2p.bind_ip.value, None);
    release.network.p2p.bind_ip = None;
    saved.resolve_with(&release);
    assert_eq!(saved.network.p2p.bind_ip.mode, ValueMode::Custom);
    assert_eq!(saved.network.p2p.bind_ip.value, None);
}

#[test]
fn explicit_sets_classify_equality_and_reset_selects_defaults() {
    let initial = SavedSettings::default();
    let changed = initial
        .with_value(key("network.nickname"), &json!("Sample"))
        .unwrap();
    assert_eq!(changed.network.nickname.mode, ValueMode::Custom);
    let same = changed
        .with_value(key("network.nickname"), &json!("eMule"))
        .unwrap();
    assert_eq!(same.network.nickname.mode, ValueMode::Default);
    let reset = changed
        .edited(&edit(json!({"reset":["network.nickname"]})))
        .unwrap();
    assert_eq!(reset, initial);
    assert_eq!(changed.network.nickname.value, "Sample");
}

#[test]
fn nullable_presence_and_whole_array_replacement_are_preserved() {
    let initial = SavedSettings::default()
        .with_value(key("network.p2p.bindInterface"), &json!("Sample Interface"))
        .unwrap();
    let untouched = initial
        .edited(&edit(
            json!({"set":{"network":{"nickname":"Sample","p2p":{}}}}),
        ))
        .unwrap();
    assert_eq!(
        untouched.network.p2p.bind_interface,
        initial.network.p2p.bind_interface
    );
    let cleared = initial
        .edited(&edit(
            json!({"set":{"network":{"p2p":{"bindInterface":null}}}}),
        ))
        .unwrap();
    assert_eq!(cleared.network.p2p.bind_interface.value, None);
    assert_eq!(cleared.network.p2p.bind_interface.mode, ValueMode::Default);
    assert!(
        serde_json::from_value::<SettingsEdit>(json!({"set":{"network":{"ed2kEnabled":null}}}))
            .is_err()
    );
    let list = initial
        .with_value(
            key("network.hostnameLookup.dnsServers"),
            &json!(["192.0.2.1:53", "192.0.2.2:53"]),
        )
        .unwrap();
    let replaced = list
        .with_value(
            key("network.hostnameLookup.dnsServers"),
            &json!(["192.0.2.3:53"]),
        )
        .unwrap();
    assert_eq!(replaced.network.hostname_lookup.dns_servers.value.len(), 1);
    assert_eq!(
        replaced.network.hostname_lookup.dns_servers.value[0].ip(),
        &Ipv4Addr::new(192, 0, 2, 3)
    );
}

#[test]
fn whole_candidate_reports_independent_issues_without_mutating_the_receiver() {
    let initial = SavedSettings::default();
    let invalid = edit(json!({"set":{
        "network":{"connections":{"maxConnections":1},"hostnameLookup":{"enabled":true}},
        "security":{"vpnGuard":{"mode":"block"},"ipFilter":{"enabled":true},"tcpErrorFloodDetection":{"intervalSeconds":61}},
        "transfers":{"upload":{"elasticPercent":101}}
    }}));
    let SettingsError::Validation(issues) = initial.edited(&invalid).unwrap_err() else {
        panic!("expected validation issues")
    };
    let paths = issues.iter().map(|issue| issue.key).collect::<HashSet<_>>();
    assert_eq!(paths.len(), issues.len());
    for path in [
        "network.connections.maxHalfOpenConnections",
        "transfers.maxParallelDownloadPeers",
        "transfers.upload.baseSlots",
        "network.hostnameLookup.dnsServers",
        "security.vpnGuard.mode",
        "security.ipFilter.filePath",
        "security.tcpErrorFloodDetection.intervalSeconds",
        "transfers.upload.elasticPercent",
    ] {
        assert!(paths.contains(path), "missing {path}");
    }
    assert_eq!(initial, SavedSettings::default());
}

#[test]
fn dependent_checks_do_not_report_secondary_connection_errors_after_invalid_cap() {
    let mut values = SettingsValues::default();
    values.network.connections.max_connections = 0;
    let issues = values.validate();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].key, "network.connections.maxConnections");
}

#[test]
fn lists_addresses_controls_and_canonical_cidrs_use_current_typed_rules() {
    let initial = SavedSettings::default();
    for (path, value) in [
        ("network.nat.backendOrder", json!([])),
        ("network.nat.backendOrder", json!(["upnp", "upnp"])),
        ("network.hostnameLookup.dnsServers", json!(["192.0.2.1:0"])),
        ("network.hostnameLookup.dnsServers", json!(["224.0.0.1:53"])),
        (
            "network.hostnameLookup.dnsServers",
            json!(["192.0.2.1:53", "192.0.2.1:53"]),
        ),
        (
            "security.vpnGuard.allowedPublicIpCidrs",
            json!(["192.0.2.1/24"]),
        ),
        (
            "security.vpnGuard.allowedPublicIpCidrs",
            json!(["192.0.2.0/24", "192.0.2.0/24"]),
        ),
        ("network.p2p.bindIp", json!("0.0.0.0")),
        ("network.nickname", json!("Sample\nName")),
        ("network.nickname", json!("界".repeat(43))),
        ("storage.tempDirectory", json!("")),
    ] {
        assert!(
            matches!(
                initial.with_value(key(path), &value),
                Err(SettingsError::Validation(_))
            ),
            "accepted invalid {path}"
        );
    }
    assert!(
        initial
            .with_value(
                key("security.vpnGuard.allowedPublicIpCidrs"),
                &json!(["192.0.2.0/24"])
            )
            .is_ok()
    );
    assert!(
        initial
            .with_value(key("network.nickname"), &json!("界".repeat(42)))
            .is_ok()
    );
}

#[test]
fn edits_reject_empty_duplicate_and_overlapping_operations() {
    let saved = SavedSettings::default();
    assert_eq!(
        saved.edited(&edit(json!({"set":{"network":{"p2p":{}}}}))),
        Err(SettingsError::EmptyOperation)
    );
    assert_eq!(
        saved.edited(&edit(
            json!({"reset":["network.nickname","network.nickname"]})
        )),
        Err(SettingsError::DuplicateReset)
    );
    assert_eq!(
        saved.edited(&edit(
            json!({"set":{"network":{"nickname":"Sample"}},"reset":["network.nickname"]})
        )),
        Err(SettingsError::OverlappingEdit)
    );
    assert!(SettingKey::parse("network.notAControl").is_err());
    assert!(
        serde_json::from_value::<SettingsEdit>(json!({"set":{"network":{"notAControl":true}}}))
            .is_err()
    );
}

#[test]
fn complete_saved_documents_require_all_groups_leaves_and_mode_fields() {
    let original = serde_json::to_value(SavedSettings::default()).unwrap();
    let mut missing = original.clone();
    missing.as_object_mut().unwrap().remove("network");
    assert!(serde_json::from_value::<SavedSettings>(missing).is_err());
    let mut missing = original.clone();
    missing["network"]
        .as_object_mut()
        .unwrap()
        .remove("nickname");
    assert!(serde_json::from_value::<SavedSettings>(missing).is_err());
    let mut missing = original;
    missing["network"]["nickname"]
        .as_object_mut()
        .unwrap()
        .remove("mode");
    assert!(serde_json::from_value::<SavedSettings>(missing).is_err());
}

#[test]
fn serialized_document_limit_counts_exact_utf8_and_json_escaping() {
    let mut saved = SavedSettings::default();
    saved.storage.incoming_directory = SavedValue {
        mode: ValueMode::Custom,
        value: PathBuf::new(),
    };
    let overhead = saved.to_json_bytes().unwrap().len();
    let prefix = "界\"\\".repeat(1000);
    let escaped = serde_json::to_string(&prefix).unwrap().len() - 2;
    let path = prefix + &"x".repeat(MAX_SAVED_BYTES - overhead - escaped);
    saved.storage.incoming_directory.value = PathBuf::from(&path);
    let exact = saved.to_json_bytes().unwrap();
    assert_eq!(exact.len(), MAX_SAVED_BYTES);
    assert_eq!(serde_json::to_vec(&saved).unwrap(), exact);
    saved.storage.incoming_directory.value.push("x");
    assert_eq!(saved.to_json_bytes(), Err(SettingsError::DocumentTooLarge));
    assert_eq!(
        SavedSettings::default().with_value(key("storage.incomingDirectory"), &json!(path + "x")),
        Err(SettingsError::DocumentTooLarge)
    );
}
