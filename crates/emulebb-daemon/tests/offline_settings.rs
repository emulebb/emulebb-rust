use emulebb_daemon::{
    OfflineSettingsOperation, PROFILE_METADATA_FILE, PROFILE_SETTINGS_FILE, run_offline_settings,
};

#[test]
fn fresh_offline_settings_initialize_only_owned_metadata() {
    let temporary = tempfile::tempdir().unwrap();
    let profile = temporary.path().join("profile");
    let value = run_offline_settings(
        profile.clone(),
        OfflineSettingsOperation::Get {
            key: "network.ed2kEnabled".into(),
        },
    )
    .unwrap();
    assert_eq!(value.as_deref(), Some("true"));
    assert!(profile.join(PROFILE_METADATA_FILE).is_file());
    assert!(!profile.join(PROFILE_SETTINGS_FILE).exists());
}

#[test]
fn offline_settings_do_not_load_or_rewrite_control_service_bootstrap() {
    let temporary = tempfile::tempdir().unwrap();
    let profile = temporary.path().to_path_buf();
    let bootstrap_path = profile.join(PROFILE_SETTINGS_FILE);
    let bootstrap = "[rest\n";
    std::fs::write(&bootstrap_path, bootstrap).unwrap();

    run_offline_settings(
        profile.clone(),
        OfflineSettingsOperation::Set {
            key: "network.nickname".into(),
            value: "Sample".into(),
        },
    )
    .unwrap();
    assert_eq!(
        run_offline_settings(
            profile,
            OfflineSettingsOperation::Get {
                key: "network.nickname".into(),
            },
        )
        .unwrap()
        .as_deref(),
        Some("Sample")
    );
    assert_eq!(std::fs::read_to_string(bootstrap_path).unwrap(), bootstrap);
}
