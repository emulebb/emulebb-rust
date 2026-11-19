use super::*;
use crate::{PROFILE_METADATA_FILE, run_offline_settings};
use emulebb_metadata::MetadataStore;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

fn inputs(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    fs::create_dir(root.join("config")).unwrap();
    sync_directory(root).unwrap();
    (
        root.join("config/profile"),
        root.join("data/incoming"),
        root.join("data/temp"),
    )
}

#[test]
fn missing_installation_parent_is_not_created_implicitly() {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("missing");
    assert!(
        initialize(
            &parent.join("profile"),
            &root.path().join("incoming"),
            &root.path().join("temp")
        )
        .is_err()
    );
    assert!(!parent.exists());
}

#[test]
fn interrupted_final_publication_is_preserved_without_replaying_its_journal() {
    let root = tempfile::tempdir().unwrap();
    let (profile, incoming, temporary) = inputs(root.path());
    let installation = Installation::begin(&profile).unwrap().unwrap();
    installation.create_stage().unwrap();
    let lease = ProfileLease::acquire(&installation.stage, false).unwrap();
    prepare_stage(&lease, &incoming, &temporary).unwrap();
    sync_stage(lease.directory()).unwrap();
    renameat_with(
        CWD,
        &installation.stage,
        CWD,
        &profile,
        RenameFlags::NOREPLACE,
    )
    .unwrap();
    let journal = installation.journal_path.clone();
    let before = fs::read(&journal).unwrap();
    drop(lease);
    drop(installation);
    initialize(&profile, &incoming, &temporary).unwrap();
    assert_eq!(fs::read(journal).unwrap(), before);
    let store = MetadataStore::open(profile.join(PROFILE_METADATA_FILE)).unwrap();
    assert_eq!(store.load_app_settings().unwrap().revision.get(), 3);
}

#[test]
fn fresh_installation_publishes_canonical_settings_and_private_bootstrap() {
    let root = tempfile::tempdir().unwrap();
    let (profile, incoming, temporary) = inputs(root.path());
    initialize(&profile, &incoming, &temporary).unwrap();
    let store = MetadataStore::open(profile.join(PROFILE_METADATA_FILE)).unwrap();
    let snapshot = store.load_app_settings().unwrap();
    assert_eq!(snapshot.revision.get(), 3);
    assert_eq!(snapshot.saved.storage.incoming_directory.value, incoming);
    assert_eq!(snapshot.saved.storage.temp_directory.value, temporary);
    assert_eq!(
        snapshot.saved.storage.incoming_directory.mode,
        ValueMode::Custom
    );
    assert!(store.shared_directory_roots().unwrap().is_empty());
    assert_eq!(
        fs::metadata(&profile).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(profile.join(PROFILE_SETTINGS_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(
        !profile
            .parent()
            .unwrap()
            .join(".profile.provision.json")
            .exists()
    );
}

#[test]
fn existing_final_profile_is_preserved_without_loading_or_provisioning_it() {
    let root = tempfile::tempdir().unwrap();
    let (profile, incoming, temporary) = inputs(root.path());
    fs::create_dir_all(&profile).unwrap();
    fs::write(profile.join(PROFILE_SETTINGS_FILE), "operator contents").unwrap();
    // Even an abandoned malformed journal cannot authorize replay into final.
    let journal = profile.parent().unwrap().join(".profile.provision.json");
    fs::write(&journal, "interrupted record").unwrap();
    initialize(&profile, &incoming, &temporary).unwrap();
    assert_eq!(
        fs::read_to_string(profile.join(PROFILE_SETTINGS_FILE)).unwrap(),
        "operator contents"
    );
    assert_eq!(fs::read_to_string(journal).unwrap(), "interrupted record");
    assert!(!profile.join(PROFILE_METADATA_FILE).exists());
}

#[test]
fn interruption_after_journal_before_stage_resumes_automatically() {
    let root = tempfile::tempdir().unwrap();
    let (profile, incoming, temporary) = inputs(root.path());
    let installation = Installation::begin(&profile).unwrap().unwrap();
    assert!(installation.journal_path.is_file());
    assert!(!installation.stage.exists());
    drop(installation);
    initialize(&profile, &incoming, &temporary).unwrap();
    assert!(profile.join(PROFILE_METADATA_FILE).is_file());
}

#[test]
fn resume_preserves_staged_user_edits_and_relative_final_namespace() {
    let root = tempfile::tempdir().unwrap();
    let (profile, incoming, temporary) = inputs(root.path());
    let installation = Installation::begin(&profile).unwrap().unwrap();
    installation.create_stage().unwrap();
    let stage = installation.stage.clone();
    drop(installation);
    for (key, value) in [
        ("storage.incomingDirectory", "operator-incoming"),
        ("network.nickname", "Sample Client"),
    ] {
        run_offline_settings(
            stage.clone(),
            OfflineSettingsOperation::Set {
                key: key.into(),
                value: value.into(),
            },
        )
        .unwrap();
    }
    initialize(&profile, &incoming, &temporary).unwrap();
    let store = MetadataStore::open(profile.join(PROFILE_METADATA_FILE)).unwrap();
    let snapshot = store.load_app_settings().unwrap();
    assert_eq!(snapshot.revision.get(), 4);
    assert_eq!(
        snapshot.saved.storage.incoming_directory.value,
        Path::new("operator-incoming")
    );
    assert_eq!(snapshot.saved.storage.temp_directory.value, temporary);
    assert_eq!(snapshot.saved.network.nickname.value, "Sample Client");
    assert!(store.shared_directory_roots().unwrap().is_empty());
    assert!(!stage.exists());
    drop(store);
    let loaded = crate::DaemonProfile::load(Some(profile.clone())).unwrap();
    assert_eq!(loaded.incoming_dir(), profile.join("operator-incoming"));
}

#[test]
fn already_committed_staging_steps_are_not_replayed() {
    let root = tempfile::tempdir().unwrap();
    let (profile, incoming, temporary) = inputs(root.path());
    let installation = Installation::begin(&profile).unwrap().unwrap();
    installation.create_stage().unwrap();
    let lease = ProfileLease::acquire(&installation.stage, false).unwrap();
    prepare_stage(&lease, &incoming, &temporary).unwrap();
    let before = open_owned_settings(&lease)
        .unwrap()
        .load_app_settings()
        .unwrap();
    drop(lease);
    drop(installation);
    initialize(&profile, &incoming, &temporary).unwrap();
    let store = MetadataStore::open(profile.join(PROFILE_METADATA_FILE)).unwrap();
    assert_eq!(store.load_app_settings().unwrap(), before);
}

#[test]
fn unknown_or_unbounded_journal_never_creates_or_cleans_a_stage() {
    for contents in [
        "invalid".to_owned(),
        "x".repeat(MAX_JOURNAL_BYTES as usize + 1),
        r#"{"profile_name":"profile","stage_name":"../unowned"}"#.to_owned(),
    ] {
        let root = tempfile::tempdir().unwrap();
        let (profile, incoming, temporary) = inputs(root.path());
        let parent = profile.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let journal = parent.join(".profile.provision.json");
        fs::write(&journal, &contents).unwrap();
        let unowned = parent.join("unowned");
        fs::create_dir(&unowned).unwrap();
        fs::write(unowned.join("sentinel"), "preserve").unwrap();
        assert!(initialize(&profile, &incoming, &temporary).is_err());
        assert!(!profile.exists());
        assert_eq!(fs::read_to_string(&journal).unwrap(), contents);
        assert_eq!(
            fs::read_to_string(unowned.join("sentinel")).unwrap(),
            "preserve"
        );
    }
}

#[test]
fn redirected_stage_is_not_opened_or_modified() {
    let root = tempfile::tempdir().unwrap();
    let (profile, incoming, temporary) = inputs(root.path());
    let installation = Installation::begin(&profile).unwrap().unwrap();
    let external = root.path().join("unowned");
    fs::create_dir(&external).unwrap();
    symlink(&external, &installation.stage).unwrap();
    drop(installation);
    assert!(initialize(&profile, &incoming, &temporary).is_err());
    assert!(fs::read_dir(external).unwrap().next().is_none());
}

#[test]
fn parent_lock_prevents_competing_installations() {
    let root = tempfile::tempdir().unwrap();
    let (profile, incoming, temporary) = inputs(root.path());
    let installation = Installation::begin(&profile).unwrap().unwrap();
    assert!(initialize(&profile, &incoming, &temporary).is_err());
    assert!(!installation.stage.exists());
    drop(installation);
    initialize(&profile, &incoming, &temporary).unwrap();
}

#[test]
fn redirected_database_is_rejected_before_opening_or_writing_it() {
    let root = tempfile::tempdir().unwrap();
    let (profile, incoming, temporary) = inputs(root.path());
    let installation = Installation::begin(&profile).unwrap().unwrap();
    installation.create_stage().unwrap();
    let external = root.path().join("unowned-file");
    fs::write(&external, "preserve").unwrap();
    symlink(&external, installation.stage.join(PROFILE_METADATA_FILE)).unwrap();
    drop(installation);
    assert!(initialize(&profile, &incoming, &temporary).is_err());
    assert_eq!(fs::read_to_string(external).unwrap(), "preserve");
    assert!(!profile.exists());
}

#[test]
fn no_replace_publication_preserves_a_competing_final_profile() {
    let root = tempfile::tempdir().unwrap();
    let (profile, incoming, temporary) = inputs(root.path());
    let installation = Installation::begin(&profile).unwrap().unwrap();
    installation.create_stage().unwrap();
    let lease = ProfileLease::acquire(&installation.stage, false).unwrap();
    prepare_stage(&lease, &incoming, &temporary).unwrap();
    sync_stage(lease.directory()).unwrap();
    fs::create_dir(&profile).unwrap();
    fs::write(profile.join("sentinel"), "winner").unwrap();
    installation.publish().unwrap();
    assert_eq!(
        fs::read_to_string(profile.join("sentinel")).unwrap(),
        "winner"
    );
    assert!(!profile.join(PROFILE_METADATA_FILE).exists());
    assert!(installation.stage.join(PROFILE_METADATA_FILE).is_file());
    assert!(installation.journal_path.is_file());
}

#[test]
fn cross_filesystem_publication_has_no_copy_or_overwrite_fallback() {
    let root = tempfile::tempdir().unwrap();
    let shared_memory = tempfile::tempdir_in("/dev/shm").unwrap();
    assert_ne!(
        fs::metadata(root.path()).unwrap().dev(),
        fs::metadata(shared_memory.path()).unwrap().dev()
    );
    let (profile, incoming, temporary) = inputs(root.path());
    let mut installation = Installation::begin(&profile).unwrap().unwrap();
    installation.create_stage().unwrap();
    let lease = ProfileLease::acquire(&installation.stage, false).unwrap();
    prepare_stage(&lease, &incoming, &temporary).unwrap();
    installation.destination = shared_memory.path().join("profile");
    assert!(installation.publish().is_err());
    assert!(!installation.destination.exists());
    assert!(installation.stage.join(PROFILE_METADATA_FILE).is_file());
    assert!(installation.journal_path.is_file());
}
