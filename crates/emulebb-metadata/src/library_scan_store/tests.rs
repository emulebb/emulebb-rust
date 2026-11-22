use super::*;
use crate::NativeFileFingerprint;
use std::path::PathBuf;

fn loss_state(store: &MetadataStore, id: i64) -> (bool, i64) {
    store
        .connection()
        .unwrap()
        .query_row(
            "SELECT scan_required,watch_loss_revision FROM shared_directory_roots WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn finish(store: &MetadataStore, path: &Path, watermark: &MetadataRootScanWatermark) -> Result<()> {
    store.replace_root_memberships(
        path,
        watermark,
        std::iter::empty::<(PathBuf, PathBuf, NativeFileFingerprint)>(),
    )
}

#[test]
fn a_scan_cannot_acknowledge_losses_that_arrive_after_its_watermark() {
    let store = MetadataStore::in_memory().unwrap();
    let path = std::env::temp_dir().join("scan-loss-watermark");
    let root = store
        .create_library_root(&path, true, true)
        .unwrap()
        .unwrap();
    let initial = store.shared_root_scan_watermark(&path).unwrap();
    assert_eq!(loss_state(&store, root.id), (false, 0));
    assert!(store.mark_library_root_scan_required(root.id).unwrap());
    let first_loss = store.shared_root_scan_watermark(&path).unwrap();
    finish(&store, &path, &initial).unwrap();
    assert_eq!(loss_state(&store, root.id), (true, 1));
    assert!(store.mark_library_root_scan_required(root.id).unwrap());
    finish(&store, &path, &first_loss).unwrap();
    assert_eq!(loss_state(&store, root.id), (true, 2));
    let current = store.shared_root_scan_watermark(&path).unwrap();
    finish(&store, &path, &current).unwrap();
    assert_eq!(loss_state(&store, root.id), (false, 2));
    assert!(store.shared_root_last_scan_s(&path).unwrap().is_some());
}

#[test]
fn loss_state_and_watermarks_survive_reopening_the_database() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("metadata.db");
    let path = directory.path().join("root");
    let store = MetadataStore::open(&database).unwrap();
    let root = store
        .create_library_root(&path, false, false)
        .unwrap()
        .unwrap();
    store.mark_library_root_scan_required(root.id).unwrap();
    let watermark = store.shared_root_scan_watermark(&path).unwrap();
    drop(store);
    let reopened = MetadataStore::open(&database).unwrap();
    assert_eq!(loss_state(&reopened, root.id), (true, 1));
    assert_eq!(
        reopened.shared_root_scan_watermark(&path).unwrap(),
        watermark
    );
    finish(&reopened, &path, &watermark).unwrap();
    assert_eq!(loss_state(&reopened, root.id), (false, 1));
}

#[test]
fn a_retired_root_cannot_mark_or_admit_a_replacement_at_the_same_path() {
    let store = MetadataStore::in_memory().unwrap();
    let path = std::env::temp_dir().join("scan-loss-replaced");
    let root = store
        .create_library_root(&path, true, true)
        .unwrap()
        .unwrap();
    let watermark = store.shared_root_scan_watermark(&path).unwrap();
    store.delete_library_root(root.id).unwrap();
    let replacement = store
        .create_library_root(&path, true, true)
        .unwrap()
        .unwrap();
    assert_ne!(replacement.id, root.id);
    assert!(!store.mark_library_root_scan_required(root.id).unwrap());
    store
        .mark_library_root_scan_required(replacement.id)
        .unwrap();
    assert!(finish(&store, &path, &watermark).is_err());
    assert_eq!(loss_state(&store, replacement.id), (true, 1));
    assert!(store.shared_root_last_scan_s(&path).unwrap().is_none());
}

#[test]
fn a_failed_scan_commit_does_not_acknowledge_the_loss() {
    let store = MetadataStore::in_memory().unwrap();
    let path = std::env::temp_dir().join("scan-loss-commit-failure");
    let root = store
        .create_library_root(&path, true, true)
        .unwrap()
        .unwrap();
    store.mark_library_root_scan_required(root.id).unwrap();
    let watermark = store.shared_root_scan_watermark(&path).unwrap();
    store
        .connection()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_scan BEFORE UPDATE OF last_scanned_at_s ON shared_directory_roots
         BEGIN SELECT RAISE(ABORT,'synthetic scan commit failure'); END;",
        )
        .unwrap();
    assert!(finish(&store, &path, &watermark).is_err());
    assert_eq!(loss_state(&store, root.id), (true, 1));
    assert!(store.shared_root_last_scan_s(&path).unwrap().is_none());
}

#[test]
fn exhausted_loss_revisions_stay_required_without_overflow_or_false_acknowledgement() {
    let store = MetadataStore::in_memory().unwrap();
    let path = std::env::temp_dir().join("scan-loss-exhausted");
    let root = store
        .create_library_root(&path, true, true)
        .unwrap()
        .unwrap();
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE shared_directory_roots SET watch_loss_revision=?2 WHERE id=?1",
            params![root.id, i64::MAX - 1],
        )
        .unwrap();
    store.mark_library_root_scan_required(root.id).unwrap();
    let watermark = store.shared_root_scan_watermark(&path).unwrap();
    store.mark_library_root_scan_required(root.id).unwrap();
    finish(&store, &path, &watermark).unwrap();
    assert_eq!(loss_state(&store, root.id), (true, i64::MAX));
}

#[test]
fn scan_completions_advance_with_identical_calendar_times_and_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("root");
    let database = dir.path().join("metadata.sqlite");
    let store = MetadataStore::open(&database).unwrap();
    let root = store
        .create_library_root(&path, false, true)
        .unwrap()
        .unwrap();
    assert_eq!(
        store.shared_root_scan_completion(&path).unwrap(),
        Some((root.id, 0))
    );
    store.connection().unwrap().execute_batch(
        "CREATE TEMP TRIGGER freeze_scan_clock AFTER UPDATE OF last_scanned_at_s ON shared_directory_roots
         WHEN new.last_scanned_at_s!=0 BEGIN UPDATE shared_directory_roots SET last_scanned_at_s=0 WHERE id=new.id; END;"
    ).unwrap();
    let watermark = store.shared_root_scan_watermark(&path).unwrap();
    for revision in 1..=2 {
        finish(&store, &path, &watermark).unwrap();
        assert_eq!(store.shared_root_last_scan_s(&path).unwrap(), Some(0));
        assert_eq!(
            store.shared_root_scan_completion(&path).unwrap(),
            Some((root.id, revision))
        );
    }
    drop(store);
    let store = MetadataStore::open(&database).unwrap();
    assert_eq!(
        store.shared_root_scan_completion(&path).unwrap(),
        Some((root.id, 2))
    );
    store.delete_library_root(root.id).unwrap();
    assert_eq!(store.shared_root_scan_completion(&path).unwrap(), None);
    let replacement = store
        .create_library_root(&path, false, true)
        .unwrap()
        .unwrap();
    assert_ne!(root.id, replacement.id);
    assert_eq!(
        store.shared_root_scan_completion(&path).unwrap(),
        Some((replacement.id, 0))
    );
}

#[test]
fn exhausted_scan_completion_revision_rolls_back_the_entire_scan() {
    let store = MetadataStore::in_memory().unwrap();
    let path = std::env::temp_dir().join("scan-completion-exhausted");
    let root = store
        .create_library_root(&path, false, true)
        .unwrap()
        .unwrap();
    store.mark_library_root_scan_required(root.id).unwrap();
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE shared_directory_roots SET scan_revision=?2 WHERE id=?1",
            params![root.id, i64::MAX],
        )
        .unwrap();
    let watermark = store.shared_root_scan_watermark(&path).unwrap();
    assert!(finish(&store, &path, &watermark).is_err());
    assert_eq!(
        store.shared_root_scan_completion(&path).unwrap(),
        Some((root.id, i64::MAX))
    );
    assert!(store.shared_root_last_scan_s(&path).unwrap().is_none());
    assert_eq!(loss_state(&store, root.id), (true, 1));
}

#[test]
fn library_observations_and_root_scan_calendar_times_use_seconds() {
    let before = crate::store::unix_s();
    let mut store = MetadataStore::in_memory().unwrap();
    store
        .upsert_indexed_file(
            &crate::MetadataIndexedFile {
                ed2k_hash: "11".repeat(16),
                name: "Sample File.bin".into(),
                size_bytes: 32,
                content_type: "archive".into(),
                availability_score: 1,
            },
            crate::MetadataIndexedFileOrigin::LocalShare,
        )
        .unwrap();
    let path = std::env::temp_dir().join("calendar-library-root");
    let root = store
        .create_library_root(&path, false, true)
        .unwrap()
        .unwrap();
    let watermark = store.shared_root_scan_watermark(&path).unwrap();
    finish(&store, &path, &watermark).unwrap();
    let conn = store.connection().unwrap();
    for sql in [
        "SELECT first_seen_at_s,last_seen_at_s,updated_at_s FROM known_files",
        "SELECT first_seen_at_s,last_seen_at_s,last_seen_at_s FROM known_file_origins",
        "SELECT first_seen_at_s,last_seen_at_s,last_seen_at_s FROM file_names",
        "SELECT first_seen_at_s,last_seen_at_s,last_seen_at_s FROM file_name_origins",
        "SELECT created_at_s,last_scanned_at_s,last_scanned_at_s FROM shared_directory_roots",
    ] {
        let times: (i64, i64, i64) = conn
            .query_row(sql, [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap();
        assert!(
            [times.0, times.1, times.2]
                .into_iter()
                .all(|time| (before..=crate::store::unix_s()).contains(&time)),
            "{sql}: {times:?}"
        );
    }
    drop(conn);
    store.delete_library_root(root.id).unwrap();
    let deleted: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT deleted_at_s FROM shared_directory_roots WHERE id=?1",
            [root.id],
            |row| row.get(0),
        )
        .unwrap();
    assert!((before..=crate::store::unix_s()).contains(&deleted));
}
