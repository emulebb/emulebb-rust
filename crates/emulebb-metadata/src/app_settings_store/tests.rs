use super::*;
use crate::MetadataStore;
use emulebb_settings::product::{
    PartialValue, SavedValue, SettingsError, SettingsRevisionError, ValueMode,
};

fn nickname(value: &str) -> SettingsEdit {
    let mut edit = SettingsEdit::default();
    edit.set.network.nickname = PartialValue::Set(value.into());
    edit
}
fn raw(store: &MetadataStore) -> (i64, String) {
    store
        .connection()
        .unwrap()
        .query_row(
            "SELECT revision,document_json FROM app_settings WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}
fn file_fixture() -> (std::path::PathBuf, MetadataStore) {
    let target = std::path::PathBuf::from(
        std::env::var_os("CARGO_TARGET_DIR").expect("settings tests require CARGO_TARGET_DIR"),
    );
    assert!(target.is_absolute());
    let root = target.join("tmp/metadata-settings");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join(format!("{}.db", uuid::Uuid::new_v4()));
    let store = MetadataStore::open(&path).unwrap();
    (path, store)
}

#[test]
fn fresh_document_is_complete_and_reads_do_not_advance_revision() {
    let store = MetadataStore::in_memory().unwrap();
    let before = raw(&store);
    let snapshot = store.load_app_settings().unwrap();
    assert_eq!(snapshot.revision, SettingsRevision::INITIAL);
    assert_eq!(snapshot.saved, SavedSettings::default());
    assert_eq!(store.load_app_settings().unwrap(), snapshot);
    assert_eq!(raw(&store), before);
}

#[test]
fn explicit_reset_can_restore_validity_after_default_resolution() {
    let store = MetadataStore::in_memory().unwrap();
    let mut saved = SavedSettings::default();
    saved.network.hostname_lookup.enabled = SavedValue {
        mode: ValueMode::Custom,
        value: true,
    };
    saved.network.hostname_lookup.dns_servers.value = vec!["192.0.2.1:53".parse().unwrap()];
    assert!(saved.values().validate().is_empty());
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE app_settings SET document_json=?1",
            [String::from_utf8(saved.to_json_bytes().unwrap()).unwrap()],
        )
        .unwrap();
    let before = raw(&store);
    let error = store.load_app_settings().unwrap_err();
    assert!(format!("{error:#}").contains("network.hostnameLookup.dnsServers"));
    assert_eq!(
        raw(&store),
        before,
        "a read never repairs the saved document"
    );
    let edit = SettingsEdit {
        reset: vec![
            emulebb_settings::product::SettingKey::parse("network.hostnameLookup.enabled").unwrap(),
        ],
        ..SettingsEdit::default()
    };
    let fixed = store.edit_app_settings(&edit).unwrap();
    assert_eq!(fixed.revision.get(), 2);
    assert!(!fixed.saved.network.hostname_lookup.enabled.value);
    assert!(
        fixed
            .saved
            .network
            .hostname_lookup
            .dns_servers
            .value
            .is_empty()
    );
}

#[test]
fn explicit_unchanged_writes_advance_and_stale_cas_changes_nothing() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store
        .compare_and_set_app_settings(SettingsRevision::INITIAL, &nickname("eMule"))
        .unwrap();
    assert_eq!(first.revision.get(), 2);
    assert_eq!(first.saved.network.nickname.mode, ValueMode::Default);
    let before = raw(&store);
    let error = store
        .compare_and_set_app_settings(SettingsRevision::INITIAL, &nickname("Sample"))
        .unwrap_err();
    assert!(
        matches!(error.downcast_ref::<MetadataSettingsWriteError>(),Some(MetadataSettingsWriteError::Conflict {actual}) if actual==&first.revision)
    );
    assert_eq!(raw(&store), before);
    let second = store.edit_app_settings(&nickname("eMule")).unwrap();
    assert_eq!(second.revision.get(), 3);
    assert_eq!(second.saved, first.saved);
}

#[test]
fn candidate_failure_and_escaped_size_failure_happen_before_any_sql_write() {
    let store = MetadataStore::in_memory().unwrap();
    let before = raw(&store);
    let changes = store.connection().unwrap().total_changes();
    store.connection().unwrap().execute_batch("CREATE TRIGGER synthetic_settings_write BEFORE UPDATE ON app_settings BEGIN SELECT RAISE(ABORT,'write must not run'); END").unwrap();
    let mut invalid = nickname("Sample");
    invalid.set.network.hostname_lookup.enabled = PartialValue::Set(true);
    let error = store.edit_app_settings(&invalid).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<SettingsError>(),
        Some(SettingsError::Validation(_))
    ));
    let mut large = SettingsEdit::default();
    large.set.storage.incoming_directory =
        PartialValue::Set(std::path::PathBuf::from("\\".repeat(70_000)));
    let error = store.edit_app_settings(&large).unwrap_err();
    assert_eq!(
        error.downcast_ref::<SettingsError>(),
        Some(&SettingsError::DocumentTooLarge)
    );
    assert_eq!(raw(&store), before);
    assert_eq!(store.connection().unwrap().total_changes(), changes);
}

#[test]
fn failed_update_rolls_back_document_and_revision_then_manual_retry_commits_once() {
    let (path, store) = file_fixture();
    let before = raw(&store);
    store.connection().unwrap().execute_batch("CREATE TRIGGER synthetic_settings_failure BEFORE UPDATE ON app_settings BEGIN SELECT RAISE(ABORT,'synthetic update failure'); END").unwrap();
    let error = store.edit_app_settings(&nickname("Sample")).unwrap_err();
    assert!(error.downcast_ref::<MetadataSettingsWriteError>().is_none());
    assert_eq!(raw(&store), before);
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER synthetic_settings_failure")
        .unwrap();
    let committed = store
        .compare_and_set_app_settings(SettingsRevision::INITIAL, &nickname("Sample"))
        .unwrap();
    assert_eq!(committed.revision.get(), 2);
    assert_eq!(committed.saved.network.nickname.mode, ValueMode::Custom);
    drop(store);
    assert_eq!(
        MetadataStore::open(path)
            .unwrap()
            .load_app_settings()
            .unwrap(),
        committed
    );
}

#[test]
fn commit_failure_is_typed_uncertainty_without_a_successful_receipt() {
    let store = MetadataStore::in_memory().unwrap();
    let before = raw(&store);
    store.connection().unwrap().execute_batch("CREATE TABLE synthetic_parent(id INTEGER PRIMARY KEY);
        CREATE TABLE synthetic_child(id INTEGER REFERENCES synthetic_parent(id) DEFERRABLE INITIALLY DEFERRED);
        CREATE TRIGGER synthetic_commit_failure AFTER UPDATE ON app_settings BEGIN INSERT INTO synthetic_child VALUES(1); END;").unwrap();
    let error = store.edit_app_settings(&nickname("Sample")).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<MetadataSettingsWriteError>(),
        Some(MetadataSettingsWriteError::CommitUncertain(_))
    ));
    assert_eq!(raw(&store), before);
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row("SELECT count(*) FROM synthetic_child", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    store.connection().unwrap().execute_batch("DROP TRIGGER synthetic_commit_failure; DROP TABLE synthetic_child; DROP TABLE synthetic_parent;").unwrap();
    assert_eq!(
        store
            .edit_app_settings(&nickname("Sample"))
            .unwrap()
            .revision
            .get(),
        2
    );
}

#[test]
fn startup_resolution_keeps_stored_document_and_custom_modes_untouched() {
    let (path, store) = file_fixture();
    let mut saved = SavedSettings::default();
    saved.network.p2p.tcp_port.value = 0;
    saved.network.nickname = SavedValue {
        mode: ValueMode::Custom,
        value: "eMule".into(),
    };
    let document = String::from_utf8(saved.to_json_bytes().unwrap()).unwrap();
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE app_settings SET revision=42,document_json=?1",
            [&document],
        )
        .unwrap();
    let resolved = store.load_app_settings().unwrap();
    assert_eq!(resolved.revision.get(), 42);
    assert_eq!(resolved.saved.network.p2p.tcp_port.value, 20019);
    assert_eq!(resolved.saved.network.nickname.mode, ValueMode::Custom);
    assert_eq!(raw(&store), (42, document.clone()));
    drop(store);
    let reopened = MetadataStore::open(path).unwrap();
    assert_eq!(reopened.load_app_settings().unwrap(), resolved);
    assert_eq!(raw(&reopened), (42, document));
}

#[test]
fn revision_exhaustion_and_empty_edits_never_change_the_row() {
    let store = MetadataStore::in_memory().unwrap();
    store
        .connection()
        .unwrap()
        .execute("UPDATE app_settings SET revision=?1", [i64::MAX])
        .unwrap();
    let before = raw(&store);
    let error = store.edit_app_settings(&nickname("Sample")).unwrap_err();
    assert_eq!(
        error.downcast_ref::<SettingsRevisionError>(),
        Some(&SettingsRevisionError::Exhausted)
    );
    let error = store
        .edit_app_settings(&SettingsEdit::default())
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<SettingsError>(),
        Some(&SettingsError::EmptyOperation)
    );
    assert_eq!(raw(&store), before);
}

#[test]
fn concurrent_independent_connections_commit_only_one_candidate_for_one_revision() {
    let (path, first) = file_fixture();
    let second = MetadataStore::open(path).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles = [(first.clone(), "First"), (second, "Second")]
        .into_iter()
        .map(|(store, value)| {
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.compare_and_set_app_settings(SettingsRevision::INITIAL, &nickname(value))
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let rejected = results
        .iter()
        .find_map(|result| result.as_ref().err())
        .unwrap();
    assert!(
        matches!(rejected.downcast_ref::<MetadataSettingsWriteError>(),Some(MetadataSettingsWriteError::Conflict {actual}) if actual.get()==2)
    );
    let current = first.load_app_settings().unwrap();
    assert_eq!(current.revision.get(), 2);
    assert!(matches!(
        current.saved.network.nickname.value.as_str(),
        "First" | "Second"
    ));
}

#[test]
fn singleton_constraints_and_canonical_reader_never_repair_missing_or_malformed_documents() {
    let store = MetadataStore::in_memory().unwrap();
    for sql in [
        "INSERT INTO app_settings VALUES(2,1,'{}')",
        "UPDATE app_settings SET revision=0",
        "UPDATE app_settings SET document_json='[]'",
        "UPDATE app_settings SET document_json='broken'",
    ] {
        assert!(store.connection().unwrap().execute(sql, []).is_err());
    }
    let oversized = format!("{{\"value\":\"{}\"}}", "界".repeat(44_000));
    assert!(
        store
            .connection()
            .unwrap()
            .execute("UPDATE app_settings SET document_json=?1", [oversized])
            .is_err()
    );
    store
        .connection()
        .unwrap()
        .execute("UPDATE app_settings SET document_json='{}'", [])
        .unwrap();
    assert!(store.load_app_settings().is_err());
    assert_eq!(raw(&store).1, "{}");
    store
        .connection()
        .unwrap()
        .execute("DELETE FROM app_settings", [])
        .unwrap();
    assert!(store.load_app_settings().is_err());
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row("SELECT count(*) FROM app_settings", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
