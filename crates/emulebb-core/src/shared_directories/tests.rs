use super::*;
use std::fs;
use std::sync::atomic::AtomicU64;

/// Allocate a unique scratch directory under the system temp root.
fn scratch_dir(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "emulebb-shared-scan-{label}-{}-{unique}",
        std::process::id(),
    ));
    fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn names(mut paths: Vec<PathBuf>) -> Vec<String> {
    paths.sort();
    paths
        .into_iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect()
}

#[tokio::test]
async fn incremental_reload_skips_unchanged_failed_source_and_retries_changed_identity() {
    let root = scratch_dir("failed-source");
    let source = root.join("Failed.Source.bin");
    fs::write(&source, b"initial payload").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let (key, size, mtime_ms) = Ed2kTransferRuntime::scanned_source_identity(&source).unwrap();
    core.metadata_store
        .upsert_shared_source_failure(&key, size, mtime_ms, "ingest failed")
        .unwrap();

    let skipped = plan_incremental_reload(&core, vec![source.clone()])
        .await
        .unwrap();

    assert!(skipped.to_hash.is_empty());
    assert_eq!(skipped.stats.planned_hash_count, 0);
    assert_eq!(skipped.stats.skipped_failed_count, 1);

    fs::write(&source, b"changed payload with a different length").unwrap();
    let retried = plan_incremental_reload(&core, vec![source.clone()])
        .await
        .unwrap();

    assert_eq!(retried.to_hash.len(), 1);
    assert_eq!(retried.stats.planned_hash_count, 1);
    assert_eq!(retried.stats.new_count, 1);
    assert_eq!(retried.stats.skipped_failed_count, 0);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn incremental_reload_prunes_persisted_share_absent_from_scan() {
    let root = scratch_dir("pruned-source");
    let source = root.join("Pruned.Source.bin");
    fs::write(&source, b"payload").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let shared = core
        .share_local_file(LocalShareCreate {
            path: source.display().to_string(),
            name: None,
        })
        .await
        .unwrap();

    let plan = plan_incremental_reload(&core, Vec::new()).await.unwrap();

    assert_eq!(plan.pruned_hashes, vec![shared.hash.clone()]);
    assert_eq!(plan.stats.pruned_count, 1);
    forget_stale_shares(&core, &plan.pruned_hashes, "").await;
    assert!(core.share(&shared.hash).await.is_none());
    assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 0);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn incremental_reload_reuses_imported_share_not_yet_active() {
    let root = scratch_dir("imported-source");
    let source = root.join("Imported.Source.bin");
    fs::write(&source, b"imported payload").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let (_, size, mtime_ms) = Ed2kTransferRuntime::scanned_source_identity(&source).unwrap();
    let file_hash = "00112233445566778899aabbccddeeff".to_string();
    core.metadata_store
        .upsert_transfer_manifest(&emulebb_metadata::MetadataTransferManifest {
            file_hash: file_hash.clone(),
            display_name: "Imported.Source.bin".to_string(),
            file_size: size,
            piece_size: emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE,
            completed: true,
            md4_hashset_acquired: true,
            md4_hashset: Vec::new(),
            aich_hashset_acquired: false,
            aich_root: None,
            aich_hashset: Vec::new(),
            verified_ranges: vec![emulebb_metadata::MetadataTransferRange {
                start: 0,
                end: size,
            }],
            pieces: Vec::new(),
            sources: Vec::new(),
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
            category_id: 0,
            control_state: None,
            transfer_row_removed: false,
            delivered_path: None,
            source_path: Some(source.display().to_string()),
            source_mtime_ms: mtime_ms,
        })
        .unwrap();
    assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 0);

    let plan = plan_incremental_reload(&core, vec![source.clone()])
        .await
        .unwrap();

    assert!(plan.to_hash.is_empty());
    assert_eq!(plan.reused_shares.len(), 1);
    assert_eq!(plan.reused_shares[0].file_hash, file_hash);
    assert_eq!(plan.stats.planned_hash_count, 0);
    assert_eq!(plan.stats.reused_count, 1);
    fs::remove_dir_all(&root).ok();
}

/// A completed DOWNLOAD delivered into a shared dir has NO share-in-place
/// source row, so it used to look brand-new on reload and its whole payload
/// was re-hashed just to reshare content it already hashed while downloading
/// (HASH-2). With the delivered file's `(size, mtime)` baseline recorded at
/// delivery, an unchanged delivered file is now a reuse cache HIT (oracle
/// FindKnownFile) -- reused, not re-hashed. If the operator later replaces
/// the delivered file (mtime changes), it correctly falls back to a re-hash.
#[tokio::test]
async fn incremental_reload_reuses_delivered_download_without_rehash() {
    let root = scratch_dir("delivered-download");
    let delivered = root.join("Completed.Download.bin");
    fs::write(&delivered, b"completed download payload").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let (_, size, mtime_ms) = Ed2kTransferRuntime::scanned_source_identity(&delivered).unwrap();
    let file_hash = "aabbccddeeff00112233445566778899".to_string();
    // A completed download: delivered_path set, source_path NONE, and the
    // delivered mtime baseline recorded (as deliver.rs does at delivery).
    core.metadata_store
        .upsert_transfer_manifest(&emulebb_metadata::MetadataTransferManifest {
            file_hash: file_hash.clone(),
            display_name: "Completed.Download.bin".to_string(),
            file_size: size,
            piece_size: emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE,
            completed: true,
            md4_hashset_acquired: true,
            md4_hashset: Vec::new(),
            aich_hashset_acquired: false,
            aich_root: None,
            aich_hashset: Vec::new(),
            verified_ranges: vec![emulebb_metadata::MetadataTransferRange {
                start: 0,
                end: size,
            }],
            pieces: Vec::new(),
            sources: Vec::new(),
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
            category_id: 0,
            control_state: None,
            transfer_row_removed: false,
            delivered_path: Some(delivered.display().to_string()),
            source_path: None,
            source_mtime_ms: mtime_ms,
        })
        .unwrap();

    // Unchanged delivered file: reuse HIT, no re-hash.
    let plan = plan_incremental_reload(&core, vec![delivered.clone()])
        .await
        .unwrap();
    assert!(
        plan.to_hash.is_empty(),
        "an unchanged delivered download must not be re-hashed"
    );
    assert_eq!(plan.reused_shares.len(), 1);
    assert_eq!(plan.reused_shares[0].file_hash, file_hash);
    assert_eq!(plan.stats.reused_count, 1);
    assert_eq!(plan.stats.planned_hash_count, 0);
    assert_eq!(plan.stats.new_count, 0);

    // Operator replaces the delivered file (new mtime): the stale reuse
    // baseline no longer matches, so it is (correctly) re-hashed as new.
    std::thread::sleep(std::time::Duration::from_millis(10));
    fs::write(&delivered, b"a different payload the operator dropped in").unwrap();
    let replaced = plan_incremental_reload(&core, vec![delivered.clone()])
        .await
        .unwrap();
    assert_eq!(
        replaced.to_hash.len(),
        1,
        "a replaced delivered file must be re-hashed, not served under the old hash"
    );
    assert!(replaced.reused_shares.is_empty());
    assert_eq!(replaced.stats.new_count, 1);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn incremental_reload_keeps_hash_when_duplicate_source_remains_scanned() {
    let root = scratch_dir("duplicate-source");
    let kept_source = root.join("Kept.Source.bin");
    let missing_source = root.join("Missing.Source.bin");
    fs::write(&kept_source, b"same payload").unwrap();
    fs::write(&missing_source, b"same payload").unwrap();
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let kept = core
        .share_local_file(LocalShareCreate {
            path: kept_source.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    let duplicate = core
        .share_local_file(LocalShareCreate {
            path: missing_source.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    assert_eq!(kept.hash, duplicate.hash);

    let plan = plan_incremental_reload(&core, vec![kept_source.clone()])
        .await
        .unwrap();

    assert_eq!(plan.reused_shares.len(), 1);
    assert_eq!(plan.reused_shares[0].file_hash, kept.hash);
    assert!(plan.pruned_hashes.is_empty());
    assert_eq!(plan.stats.pruned_count, 0);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn non_recursive_collects_only_immediate_files() {
    let root = scratch_dir("nonrec");
    fs::write(root.join("top-a.dat"), b"a").unwrap();
    fs::write(root.join("top-b.dat"), b"b").unwrap();
    let nested = root.join("nested");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("deep.dat"), b"c").unwrap();

    let mut output = Vec::new();
    let skipped = collect_shared_directory_files(&root, false, &mut output).unwrap();

    assert_eq!(skipped, 0);
    assert_eq!(names(output), vec!["top-a.dat", "top-b.dat"]);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn recursive_collects_full_tree_files_only() {
    let root = scratch_dir("rec");
    fs::write(root.join("top.dat"), b"a").unwrap();
    let nested = root.join("nested").join("more");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("deep.dat"), b"b").unwrap();

    let mut output = Vec::new();
    let skipped = collect_shared_directory_files(&root, true, &mut output).unwrap();

    assert_eq!(skipped, 0);
    // Directories are skipped; only the two files are reported.
    assert_eq!(names(output), vec!["deep.dat", "top.dat"]);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn unreadable_root_is_skipped_without_aborting() {
    // walkdir surfaces a per-entry error when the root itself cannot be
    // read (here: it does not exist). The scan must log/skip that entry and
    // return Ok with an empty result rather than propagating the error.
    let missing = scratch_dir("missing");
    let missing = missing.join("does-not-exist");
    assert!(!missing.exists());

    let mut output = Vec::new();
    let result = collect_shared_directory_files(&missing, true, &mut output);

    assert_eq!(result.unwrap(), 1);
    assert!(output.is_empty());
}

#[test]
fn shared_scan_ignores_mfc_intake_file_names_and_empty_files() {
    let root = scratch_dir("ignored-files");
    fs::write(root.join("alpha.bin"), b"a").unwrap();
    fs::write(root.join("desktop.ini"), b"metadata").unwrap();
    fs::write(root.join("download.part"), b"partial").unwrap();
    fs::write(root.join("~$office.tmp"), b"lock").unwrap();
    fs::write(root.join("empty.bin"), b"").unwrap();

    let mut output = Vec::new();
    let skipped = collect_shared_directory_files(&root, false, &mut output).unwrap();

    assert_eq!(skipped, 4);
    assert_eq!(names(output), vec!["alpha.bin"]);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn recursive_shared_scan_prunes_mfc_ignored_directories() {
    let root = scratch_dir("ignored-dirs");
    fs::write(root.join("alpha.bin"), b"a").unwrap();
    let git_dir = root.join(".git");
    fs::create_dir_all(&git_dir).unwrap();
    fs::write(git_dir.join("object.bin"), b"b").unwrap();
    let nested = root.join("visible");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("beta.bin"), b"c").unwrap();

    let mut output = Vec::new();
    let skipped = collect_shared_directory_files(&root, true, &mut output).unwrap();

    assert_eq!(skipped, 1);
    assert_eq!(names(output), vec!["alpha.bin", "beta.bin"]);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn shared_file_name_policy_matches_mfc_affixes() {
    assert!(should_ignore_shared_file_name(".DS_Store"));
    assert!(should_ignore_shared_file_name("._resource"));
    assert!(should_ignore_shared_file_name("download.crdownload"));
    assert!(should_ignore_shared_file_name("~lock.document#"));
    assert!(!should_ignore_shared_file_name("sample.data"));
}
