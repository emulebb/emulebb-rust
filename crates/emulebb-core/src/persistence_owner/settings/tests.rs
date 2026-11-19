use super::*;
use crate::EmulebbCore;
use crate::persistence_owner::tests::wait_for_slots;
use emulebb_index::FileIndex;
use serde_json::json;
use std::time::Duration;

fn patch(revision: &str, set: serde_json::Value) -> SettingsPatch {
    serde_json::from_value(json!({"expectedRevision":revision,"set":set})).unwrap()
}
fn core() -> EmulebbCore {
    EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap()
}
fn file_core() -> (EmulebbCore, rusqlite::Connection) {
    let root = crate::unique_runtime_dir("settings-owner");
    let database = root.join("metadata.sqlite");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&database).unwrap(),
        root.join("temp"),
    )
    .unwrap();
    (core, rusqlite::Connection::open(database).unwrap())
}

#[tokio::test]
async fn invalid_whole_candidate_changes_neither_saved_document_nor_runtime() {
    let core = core();
    let saved = core.metadata_store.load_app_settings().unwrap();
    let effective = core.effective_settings().await.unwrap();
    let error = core
        .update_settings(&patch(
            "1",
            json!({"network":{"nat":{"enabled":false}},"transfers":{"upload":{"baseSlots":0}}}),
        ))
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error.downcast_ref::<SettingsMutationError>(),
        Some(SettingsMutationError::Invalid(_))
    ));
    assert_eq!(core.metadata_store.load_app_settings().unwrap(), saved);
    assert_eq!(core.effective_settings().await.unwrap(), effective);
}

#[tokio::test]
async fn concurrent_same_revision_writers_commit_only_one_whole_candidate() {
    let core = core();
    let a = patch(
        "1",
        json!({"transfers":{"uploadLimitBytesPerSecond":1048576}}),
    );
    let b = patch(
        "1",
        json!({"transfers":{"downloadLimitBytesPerSecond":2097152}}),
    );
    let (a, b) = tokio::join!(core.update_settings(&a), core.update_settings(&b));
    let results = [a, b];
    assert_eq!(results.iter().filter(|v| v.is_ok()).count(), 1);
    let error = results.iter().find_map(|v| v.as_ref().err()).unwrap();
    assert!(
        matches!(error.downcast_ref::<SettingsMutationError>(),Some(SettingsMutationError::Conflict {actual}) if actual.get()==2)
    );
    let saved = core.metadata_store.load_app_settings().unwrap();
    assert_eq!(saved.revision.get(), 2);
    assert_eq!(
        core.effective_settings().await.unwrap(),
        saved.saved.values()
    );
}

#[tokio::test]
async fn caller_disconnect_after_commit_cannot_abandon_runtime_publication() {
    let core = core();
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)
        .unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let writer = {
        let core = core.clone();
        tokio::spawn(async move {
            core.update_settings(&patch("1",json!({"transfers":{"uploadLimitBytesPerSecond":1048576,"downloadLimitBytesPerSecond":2097152}}))).await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert_eq!(
        core.metadata_store
            .load_app_settings()
            .unwrap()
            .revision
            .get(),
        2
    );
    assert_ne!(
        core.effective_settings()
            .await
            .unwrap()
            .transfers
            .upload_limit_bytes_per_second,
        1048576
    );
    writer.abort();
    assert!(writer.await.err().unwrap().is_cancelled());
    *owner.publication_gate.lock().unwrap() = None;
    gate.release.notify_one();
    let read = tokio::time::timeout(Duration::from_secs(5), core.settings())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.value().revision().get(), 2);
    assert_eq!(
        read.value()
            .data()
            .effective()
            .transfers
            .upload_limit_bytes_per_second,
        1048576
    );
    assert_eq!(
        core.ed2k_transfers
            .upload_queue_policy_snapshot()
            .await
            .upload_limit_bytes_per_sec,
        1048576
    );
    assert_eq!(
        core.ed2k_transfers.download_limit_bytes_per_sec().await,
        2097152
    );
    drop(read);
    wait_for_slots(&owner, 0).await;
}

#[tokio::test]
async fn incompatible_mixed_update_defers_every_change_until_explicit_update_or_restart() {
    let core = core();
    let before = core.effective_settings().await.unwrap();
    let updated=core.update_settings(&patch("1",json!({
        "network":{"connections":{"maxConnections":20,"maxNewConnectionsPerFiveSeconds":20,"maxHalfOpenConnections":5}},
        "transfers":{"uploadLimitBytesPerSecond":1048576}
    }))).await.unwrap();
    assert_eq!(updated.value().data().effective(), &before);
    assert_eq!(
        updated.value().data().application().pending_restart().len(),
        4
    );
    assert!(updated.value().data().application().failed().is_empty());
    drop(updated);
    assert_eq!(
        core.settings().await.unwrap().value().data().effective(),
        &before
    );
    assert_eq!(
        core.ed2k_transfers
            .upload_queue_policy_snapshot()
            .await
            .upload_limit_bytes_per_sec,
        before.transfers.upload_limit_bytes_per_second
    );
    let retry = core
        .update_settings(&patch(
            "2",
            json!({"network":{"connections":{"maxConnections":100}}}),
        ))
        .await
        .unwrap();
    assert_eq!(
        retry
            .value()
            .data()
            .effective()
            .network
            .connections
            .max_connections,
        100
    );
    assert_eq!(
        retry
            .value()
            .data()
            .effective()
            .network
            .connections
            .max_half_open_connections,
        50
    );
    assert_eq!(
        retry
            .value()
            .data()
            .effective()
            .transfers
            .upload_limit_bytes_per_second,
        1048576
    );
    let pending = retry.value().data().application().pending_restart();
    assert_eq!(
        pending.iter().map(|key| key.as_str()).collect::<Vec<_>>(),
        vec!["network.connections.maxHalfOpenConnections"]
    );
}

#[tokio::test]
async fn sql_rollback_preserves_runtime_and_allows_explicit_retry() {
    let (core, sql) = file_core();
    let before = core.effective_settings().await.unwrap();
    sql.execute_batch("CREATE TRIGGER synthetic_write_failure BEFORE UPDATE ON app_settings BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    let change = patch(
        "1",
        json!({"transfers":{"downloadLimitBytesPerSecond":2097152}}),
    );
    assert!(core.update_settings(&change).await.is_err());
    assert_eq!(core.effective_settings().await.unwrap(), before);
    assert_eq!(
        core.metadata_store
            .load_app_settings()
            .unwrap()
            .revision
            .get(),
        1
    );
    sql.execute_batch("DROP TRIGGER synthetic_write_failure;")
        .unwrap();
    assert_eq!(
        core.update_settings(&change)
            .await
            .unwrap()
            .value()
            .revision()
            .get(),
        2
    );
}

#[tokio::test]
async fn uncertain_sql_commit_stops_coherent_reads_and_further_mutation() {
    let (core, sql) = file_core();
    sql.execute_batch("CREATE TABLE synthetic_parent(id INTEGER PRIMARY KEY);
        CREATE TABLE synthetic_child(id INTEGER REFERENCES synthetic_parent(id) DEFERRABLE INITIALLY DEFERRED);
        CREATE TRIGGER synthetic_commit_failure AFTER UPDATE ON app_settings BEGIN INSERT INTO synthetic_child VALUES(1); END;").unwrap();
    let change = patch(
        "1",
        json!({"transfers":{"downloadLimitBytesPerSecond":2097152}}),
    );
    let error = core.update_settings(&change).await.err().unwrap();
    assert!(matches!(
        error.downcast_ref::<PersistenceError>(),
        Some(PersistenceError::CommitUnknown)
    ));
    assert!(core.effective_settings().await.is_err());
    assert!(core.settings().await.is_err());
    assert!(core.update_settings(&change).await.is_err());
    assert_eq!(
        core.metadata_store
            .load_app_settings()
            .unwrap()
            .revision
            .get(),
        1
    );
}

#[tokio::test]
async fn revision_exhaustion_changes_neither_saved_values_nor_admitted_effective_values() {
    let (core, sql) = file_core();
    sql.execute("UPDATE app_settings SET revision=?1", [i64::MAX])
        .unwrap();
    let before = core.effective_settings().await.unwrap();
    let error = core
        .update_settings(&patch(
            &i64::MAX.to_string(),
            json!({"transfers":{"downloadLimitBytesPerSecond":2097152}}),
        ))
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error.downcast_ref::<SettingsMutationError>(),
        Some(SettingsMutationError::RevisionExhausted)
    ));
    assert_eq!(
        core.metadata_store
            .load_app_settings()
            .unwrap()
            .revision
            .get(),
        i64::MAX
    );
    assert_eq!(core.effective_settings().await.unwrap(), before);
}
