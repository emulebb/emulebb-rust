use super::*;
use serde_json::json;

fn key(name: &str) -> SettingKey {
    SettingKey::parse(name).unwrap()
}

#[test]
fn failure_messages_preserve_utf8_and_report_actual_truncation() {
    let key = key("network.nickname");
    for message in ["".into(), "a".repeat(512), "é".repeat(256)] {
        let failure = SettingApplyFailure::new(key, &message);
        assert_eq!(failure.message, message);
        assert!(!failure.truncated);
    }
    let message = format!("{}€tail", "a".repeat(511));
    let failure = SettingApplyFailure::new(key, &message);
    assert_eq!(failure.message, "a".repeat(511));
    assert!(failure.truncated);
    let escaped = SettingApplyFailure::new(key, &"\n".repeat(513));
    let encoded = serde_json::to_vec(&escaped).unwrap();
    assert!(encoded.len() > MAX_APPLY_MESSAGE_BYTES);
    assert_eq!(
        serde_json::from_slice::<Value>(&encoded).unwrap()["message"],
        "\n".repeat(512)
    );
}

#[test]
fn application_status_is_bounded_by_unique_catalog_keys() {
    let keys: Vec<_> = setting_specs().iter().map(|spec| key(spec.key)).collect();
    assert_eq!(keys.len(), 59);
    let failures: Vec<_> = keys
        .iter()
        .map(|key| SettingApplyFailure::new(*key, "failure"))
        .collect();
    let status = SettingsApplicationStatus::new(keys.clone(), failures.clone()).unwrap();
    assert_eq!(status.pending_restart(), keys);
    assert_eq!(status.failed(), failures);
    let duplicate = keys[0];
    assert_eq!(
        SettingsApplicationStatus::new(vec![duplicate; 2], vec![]),
        Err(SettingsError::InvalidDocument)
    );
    assert_eq!(
        SettingsApplicationStatus::new(vec![], vec![failures[0].clone(); 2]),
        Err(SettingsError::InvalidDocument)
    );
    assert_eq!(
        SettingsApplicationStatus::new(vec![duplicate; 60], vec![]),
        Err(SettingsError::InvalidDocument)
    );
    assert_eq!(
        SettingsApplicationStatus::new(vec![], vec![failures[0].clone(); 60]),
        Err(SettingsError::InvalidDocument)
    );
}

#[test]
fn read_keeps_saved_and_effective_distinct_and_resolves_default_markers() {
    let mut saved = SavedSettings::default();
    saved.network.nickname.value = "stale compiled default".into();
    let mut effective = SettingsValues::default();
    effective.network.nickname = "currently applied".into();
    let snapshot = SettingsReadData::new(
        saved,
        effective.clone(),
        SettingsApplicationStatus::default(),
    )
    .unwrap();
    assert_eq!(
        snapshot.saved().network.nickname.value,
        SettingsValues::default().network.nickname
    );
    assert_eq!(snapshot.effective(), &effective);
    let data: Value = serde_json::from_slice(&snapshot.to_json_bytes().unwrap()).unwrap();
    assert_eq!(
        data["application"],
        json!({"pendingRestart":[],"failed":[]})
    );
    assert_eq!(data.as_object().unwrap().len(), 3);
    assert!(data.get("revision").is_none());
    assert_eq!(
        data["effective"]["network"]["nickname"],
        "currently applied"
    );
}

#[test]
fn read_limit_counts_exact_serialized_bytes_including_json_escaping() {
    let saved = SavedSettings::default();
    let mut effective = SettingsValues::default();
    effective.storage.incoming_directory = PathBuf::from("a");
    let initial = SettingsReadData::new(
        saved.clone(),
        effective.clone(),
        SettingsApplicationStatus::default(),
    )
    .unwrap();
    let overhead = initial.to_json_bytes().unwrap().len() - 1;
    // Quotes are valid path characters here and each needs two JSON bytes.
    let remaining = MAX_SNAPSHOT_BYTES - overhead;
    let path = format!(
        "{}{}",
        "\"".repeat(remaining / 2),
        "a".repeat(remaining % 2)
    );
    effective.storage.incoming_directory = PathBuf::from(&path);
    let full = SettingsReadData::new(
        saved.clone(),
        effective.clone(),
        SettingsApplicationStatus::default(),
    )
    .unwrap();
    assert_eq!(full.to_json_bytes().unwrap().len(), MAX_SNAPSHOT_BYTES);
    effective.storage.incoming_directory.push("a");
    assert_eq!(
        SettingsReadData::new(saved, effective, SettingsApplicationStatus::default()),
        Err(SettingsError::DocumentTooLarge)
    );
}

#[test]
fn invalid_saved_or_effective_values_are_not_published() {
    let mut saved = SavedSettings::default();
    saved.storage.temp_directory = SavedValue {
        mode: ValueMode::Custom,
        value: PathBuf::new(),
    };
    assert!(matches!(
        SettingsReadData::new(
            saved,
            SettingsValues::default(),
            SettingsApplicationStatus::default()
        ),
        Err(SettingsError::Validation(_))
    ));
    let mut effective = SettingsValues::default();
    effective.storage.temp_directory = PathBuf::new();
    assert!(matches!(
        SettingsReadData::new(
            SavedSettings::default(),
            effective,
            SettingsApplicationStatus::default()
        ),
        Err(SettingsError::Validation(_))
    ));
}
