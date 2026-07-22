use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use emulebb_ed2k::ed2k_transfer::LocalIngestProgressEvent;
use emulebb_ed2k::long_path::long_path;
use emulebb_index::IndexedSharedDirectoryRoot;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

const MAX_SHARED_RELOAD_HASH_WORKERS_PER_DISK: usize = 4;

/// One configured shared-directory root exposed through the eMuleBB REST contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedDirectoryRoot {
    pub path: String,
    pub monitor_owned: bool,
    pub shareable: bool,
    pub accessible: bool,
}

/// Current shared-directory configuration plus lightweight hashing status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedDirectories {
    pub roots: Vec<SharedDirectoryRoot>,
    pub items: Vec<SharedDirectoryRoot>,
    pub monitor_owned: Vec<String>,
    pub hashing_count: i64,
    pub reload_progress: SharedDirectoryReloadProgress,
}

/// Live counters and file-level progress for the latest shared-directory reload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedDirectoryReloadProgress {
    pub phase: String,
    pub running: bool,
    pub pending: bool,
    pub scanned_count: usize,
    pub planned_hash_count: usize,
    pub reused_count: usize,
    pub new_count: usize,
    pub changed_count: usize,
    pub missing_mtime_count: usize,
    pub stat_failed_count: usize,
    pub skipped_failed_count: usize,
    pub skipped_intake_count: usize,
    pub pruned_count: usize,
    pub stale_hash_count: usize,
    pub disk_count: usize,
    pub active_hash_count: usize,
    pub hashed_count: usize,
    pub failed_hash_count: usize,
    pub planned_hash_bytes: u64,
    pub completed_hash_bytes: u64,
    pub planned_read_bytes: u64,
    pub completed_read_bytes: u64,
    pub read_rate_bytes_per_sec: u64,
    pub started_at_ms: Option<i64>,
    pub updated_at_ms: Option<i64>,
    pub active: Vec<SharedDirectoryHashActiveFile>,
    pub recent: Vec<SharedDirectoryHashRecentFile>,
    pub upcoming: Vec<SharedDirectoryHashQueuedFile>,
    pub disks: Vec<SharedDirectoryHashDiskProgress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedDirectoryHashActiveFile {
    pub id: String,
    pub disk_key: String,
    pub path: String,
    pub name: String,
    pub size_bytes: u64,
    pub reason: String,
    pub stage: String,
    pub stage_read_bytes: u64,
    pub stage_total_bytes: u64,
    pub read_bytes: u64,
    pub read_bytes_total: u64,
    pub read_rate_bytes_per_sec: u64,
    pub started_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedDirectoryHashRecentFile {
    pub id: String,
    pub disk_key: String,
    pub path: String,
    pub name: String,
    pub size_bytes: u64,
    pub reason: String,
    pub result: String,
    pub error: Option<String>,
    pub hash: Option<String>,
    pub read_bytes: u64,
    pub read_bytes_total: u64,
    pub duration_ms: i64,
    pub average_read_rate_bytes_per_sec: u64,
    pub finished_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedDirectoryHashQueuedFile {
    pub id: String,
    pub disk_key: String,
    pub path: String,
    pub name: String,
    pub size_bytes: u64,
    pub reason: String,
    pub order: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedDirectoryHashDiskProgress {
    pub disk_key: String,
    pub planned_count: usize,
    pub active_count: usize,
    pub completed_count: usize,
    pub failed_count: usize,
    pub queued_count: usize,
    pub planned_read_bytes: u64,
    pub completed_read_bytes: u64,
    pub read_rate_bytes_per_sec: u64,
    pub current_path: Option<String>,
    pub current_name: Option<String>,
    pub current_stage: Option<String>,
}

impl Default for SharedDirectoryReloadProgress {
    fn default() -> Self {
        Self {
            phase: "idle".to_string(),
            running: false,
            pending: false,
            scanned_count: 0,
            planned_hash_count: 0,
            reused_count: 0,
            new_count: 0,
            changed_count: 0,
            missing_mtime_count: 0,
            stat_failed_count: 0,
            skipped_failed_count: 0,
            skipped_intake_count: 0,
            pruned_count: 0,
            stale_hash_count: 0,
            disk_count: 0,
            active_hash_count: 0,
            hashed_count: 0,
            failed_hash_count: 0,
            planned_hash_bytes: 0,
            completed_hash_bytes: 0,
            planned_read_bytes: 0,
            completed_read_bytes: 0,
            read_rate_bytes_per_sec: 0,
            started_at_ms: None,
            updated_at_ms: None,
            active: Vec::new(),
            recent: Vec::new(),
            upcoming: Vec::new(),
            disks: Vec::new(),
        }
    }
}

/// Replacement request for the configured shared-directory roots.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharedDirectoriesUpdate {
    pub roots: Vec<SharedDirectoryRootUpdate>,
    pub confirm_replace_roots: bool,
}

/// Shared-directory root input accepted by the REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharedDirectoryRootUpdate {
    pub path: String,
}

pub(crate) fn shared_directory_from_index(root: IndexedSharedDirectoryRoot) -> SharedDirectoryRoot {
    SharedDirectoryRoot {
        path: root.path,
        monitor_owned: false,
        shareable: root.shareable,
        accessible: root.accessible,
    }
}

pub(crate) fn shared_directory_to_index(root: &SharedDirectoryRoot) -> IndexedSharedDirectoryRoot {
    IndexedSharedDirectoryRoot {
        path: root.path.clone(),
        monitor_owned: root.monitor_owned,
        shareable: root.shareable,
        accessible: root.accessible,
    }
}

pub(crate) fn refresh_shared_directory_row(root: &SharedDirectoryRoot) -> SharedDirectoryRoot {
    let path = Path::new(&root.path);
    let accessible = path.is_dir();
    SharedDirectoryRoot {
        path: root.path.clone(),
        monitor_owned: root.monitor_owned,
        shareable: accessible,
        accessible,
    }
}

/// Build the MFC-compatible `items` view from configured roots.
///
/// Configured roots remain user-owned. Recursive child directories are derived
/// monitor-owned items, matching MFC's `shareddir.dat` + monitored expansion
/// model without persisting those child directories as real roots.
pub(crate) async fn shared_directory_items(
    roots: Vec<SharedDirectoryRoot>,
) -> Vec<SharedDirectoryRoot> {
    match tokio::task::spawn_blocking(move || expand_shared_directory_items(roots)).await {
        Ok(items) => items,
        Err(error) => {
            tracing::warn!(%error, "failed to expand shared-directory items");
            Vec::new()
        }
    }
}

fn expand_shared_directory_items(roots: Vec<SharedDirectoryRoot>) -> Vec<SharedDirectoryRoot> {
    let mut items = Vec::new();
    let mut seen = HashSet::new();
    for root in roots {
        let refreshed = refresh_shared_directory_row(&root);
        push_shared_directory_item(&mut items, &mut seen, refreshed.clone());
        if !refreshed.accessible {
            continue;
        }
        let walk_root = long_path(Path::new(&refreshed.path));
        for entry in WalkDir::new(&walk_root)
            .min_depth(1)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                if !entry.file_type().is_dir() {
                    return true;
                }
                !should_ignore_shared_directory_name(&entry.file_name().to_string_lossy())
            })
        {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    tracing::warn!(
                        root = %walk_root.display(),
                        error = %error,
                        "skipping unreadable shared-directory item",
                    );
                    continue;
                }
            };
            if !entry.file_type().is_dir() {
                continue;
            }
            let path = entry
                .path()
                .strip_prefix(&walk_root)
                .map(|relative| Path::new(&refreshed.path).join(relative))
                .unwrap_or_else(|_| entry.path().to_path_buf())
                .display()
                .to_string();
            push_shared_directory_item(
                &mut items,
                &mut seen,
                SharedDirectoryRoot {
                    path,
                    monitor_owned: true,
                    shareable: true,
                    accessible: true,
                },
            );
        }
    }
    items
}

fn push_shared_directory_item(
    items: &mut Vec<SharedDirectoryRoot>,
    seen: &mut HashSet<String>,
    item: SharedDirectoryRoot,
) {
    let key = item.path.to_ascii_lowercase();
    if seen.insert(key) {
        items.push(item);
    }
}

const MAX_EMULE_FILE_SIZE: u64 = 0x4000000000;

fn should_ignore_shared_file_candidate(path: &Path, metadata: &Metadata) -> bool {
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    metadata.len() == 0
        || metadata.len() > MAX_EMULE_FILE_SIZE
        || has_windows_ignored_file_attributes(metadata)
        || should_ignore_shared_file_name(&file_name)
}

#[cfg(windows)]
fn has_windows_ignored_file_attributes(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
    const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
    metadata.file_attributes() & (FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY) != 0
}

#[cfg(not(windows))]
fn has_windows_ignored_file_attributes(_: &Metadata) -> bool {
    false
}

fn should_ignore_shared_file_name(file_name: &str) -> bool {
    const EXACT: &[&str] = &[
        "ehthumbs.db",
        "desktop.ini",
        ".ds_store",
        ".localized",
        "Icon\r",
        ".directory",
    ];
    const PREFIXES: &[&str] = &["._", "~$", ".nfs", ".sb-", ".syncthing."];
    const SUFFIXES: &[&str] = &[
        ".lnk",
        ".part",
        ".crdownload",
        ".download",
        ".tmp",
        ".temp",
        "~",
    ];

    EXACT
        .iter()
        .any(|name| file_name.eq_ignore_ascii_case(name))
        || PREFIXES
            .iter()
            .any(|prefix| starts_with_ascii_case_insensitive(file_name, prefix))
        || SUFFIXES
            .iter()
            .any(|suffix| ends_with_ascii_case_insensitive(file_name, suffix))
        || (starts_with_ascii_case_insensitive(file_name, "~lock.")
            && ends_with_ascii_case_insensitive(file_name, "#")
            && file_name.len() >= "~lock.".len() + "#".len())
}

fn should_ignore_shared_directory_name(directory_name: &str) -> bool {
    const EXACT: &[&str] = &[
        ".fseventsd",
        ".spotlight-v100",
        ".temporaryitems",
        ".trashes",
        ".git",
        ".svn",
        ".hg",
        "CVS",
    ];
    const PREFIXES: &[&str] = &["._", ".nfs", ".sb-", ".syncthing."];

    EXACT
        .iter()
        .any(|name| directory_name.eq_ignore_ascii_case(name))
        || PREFIXES
            .iter()
            .any(|prefix| starts_with_ascii_case_insensitive(directory_name, prefix))
}

fn starts_with_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn ends_with_ascii_case_insensitive(value: &str, suffix: &str) -> bool {
    value
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

/// Enumerate the regular files under a shared-directory root tree.
///
/// This walk is intentionally synchronous and recursive (via `walkdir`), so it
/// MUST NOT be invoked directly from an async context: async callers wrap it in
/// `tokio::task::spawn_blocking` so the (potentially large) blocking scan never
/// stalls a tokio worker thread.
///
/// `walkdir` descends the full tree and uses its own loop detection for symlink
/// cycles. A single unreadable entry (permissions, vanished file, broken
/// symlink) is logged and skipped instead of aborting the whole scan, so the
/// readable files are still collected.
pub(crate) fn collect_shared_directory_files(
    root: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<usize> {
    // Operator-facing shared-directory boundary: walk the root through the
    // long-path helper so a shared tree deeper than the legacy MAX_PATH (260)
    // limit is still enumerated. The verbatim root flows into every entry path
    // walkdir produces, so the ingest read path inherits the long-path form.
    // (Operator-rule scope: shared-directory trees -- see long_path.rs.)
    let root = long_path(root);
    let root = root.as_path();
    let skipped_intake_count = Cell::new(0usize);
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 || !entry.file_type().is_dir() {
                return true;
            }
            if should_ignore_shared_directory_name(&entry.file_name().to_string_lossy()) {
                skipped_intake_count.set(skipped_intake_count.get() + 1);
                return false;
            }
            true
        })
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                skipped_intake_count.set(skipped_intake_count.get() + 1);
                tracing::warn!(
                    root = %root.display(),
                    error = %error,
                    "skipping unreadable shared-directory entry",
                );
                continue;
            }
        };
        if entry.file_type().is_file() {
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    skipped_intake_count.set(skipped_intake_count.get() + 1);
                    tracing::warn!(
                        path = %entry.path().display(),
                        error = %error,
                        "skipping unreadable shared file candidate",
                    );
                    continue;
                }
            };
            if should_ignore_shared_file_candidate(entry.path(), &metadata) {
                skipped_intake_count.set(skipped_intake_count.get() + 1);
                continue;
            }
            output.push(entry.into_path());
        }
    }
    Ok(skipped_intake_count.get())
}

/// Async-safe wrapper around [`collect_shared_directory_files`] for every root.
///
/// The blocking `walkdir` scan is dispatched onto `tokio`'s blocking thread
/// pool via `spawn_blocking`, so async callers never run the (potentially large)
/// recursive filesystem walk on a runtime worker thread.
pub(crate) async fn scan_shared_directory_roots(
    roots: Vec<SharedDirectoryRoot>,
) -> Result<SharedScanResult> {
    tokio::task::spawn_blocking(move || -> Result<SharedScanResult> {
        let mut file_paths = Vec::new();
        let mut skipped_intake_count = 0;
        for root in roots {
            skipped_intake_count +=
                collect_shared_directory_files(Path::new(&root.path), &mut file_paths)
                    .with_context(|| format!("failed to scan shared directory {}", root.path))?;
        }
        Ok(SharedScanResult {
            file_paths,
            skipped_intake_count,
        })
    })
    .await?
}

pub(crate) struct SharedScanResult {
    file_paths: Vec<PathBuf>,
    skipped_intake_count: usize,
}

// ---------------------------------------------------------------------------
// Core orchestration (kept out of lib.rs to respect its frozen line budget).
//
// These free functions take `&EmulebbCore` and drive the full shared-directory
// scan + MD4/ed2k hash. A child module may read its ancestor's private items, so
// they touch the core's private `state` / `shared_hashing_count` fields directly
// and reuse the public `share_local_file` ingest path so MD4/AICH/catalog stay
// consistent. `lib.rs` keeps only thin entry methods that delegate here.
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime;
use emulebb_metadata::MetadataSharedSourceFailure;
use tokio::task::JoinSet;

use crate::physical_disk::physical_disk_key;
use crate::{EmulebbCore, LocalShare, LocalShareCreate};

/// Resets the live `hashingCount` to 0 on any exit path (success, hash error, or
/// panic unwind) so a failed/aborted reload never leaves a stale non-zero count.
struct HashingCountGuard(Arc<AtomicI64>);

impl Drop for HashingCountGuard {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Relaxed);
    }
}

/// Live `hashingCount` snapshot for the REST surface: files still pending the
/// initial hash in the background reload worker (0 when idle / fully indexed).
pub(crate) fn hashing_count_snapshot(core: &EmulebbCore) -> i64 {
    core.shared_hashing_count.load(Ordering::Relaxed).max(0)
}

/// Scan the configured shared roots and return the deduped, sorted file list.
async fn scan_shared_files(core: &EmulebbCore) -> Result<SharedScanResult> {
    let roots = core.state.lock().await.shared_directories.clone();
    // The recursive directory walk is synchronous and may be large, so the helper
    // runs it off the async executor via spawn_blocking to avoid stalling a tokio
    // worker thread.
    let mut result = scan_shared_directory_roots(roots).await?;
    result.file_paths.sort();
    result.file_paths.dedup();
    Ok(result)
}

/// Outcome of partitioning a freshly scanned shared-file list against the
/// persisted share-in-place index: the files that still need (re)hashing plus a
/// count of unchanged files skipped (for logging / the live `hashingCount`).
#[derive(Clone)]
struct ReloadHashTarget {
    /// Runtime-only progress identity for this reload plan.
    id: String,
    /// Stable order inside the latest reload plan.
    order: usize,
    /// Physical disk key used by the per-disk hashing workers.
    disk_key: String,
    /// The scanned file to (re)hash via `share_local_file`.
    path: PathBuf,
    /// Why this path needs hashing in the latest incremental plan.
    reason: String,
    /// Long-path-normalized source identity key used by the durable failure cache.
    key: String,
    /// File size captured at planning time.
    file_size: u64,
    /// Source mtime captured at planning time, when the filesystem reports it.
    source_mtime_ms: Option<i64>,
    /// Existing hashes for the same source path. Once the current identity is
    /// known, every different hash here is removed so a changed file does not
    /// leave duplicate shares for the same source path.
    stale_hashes: Vec<String>,
}

struct ReusedReloadShare {
    /// File hash reused from the persisted index because path, size, and mtime
    /// still match the scanned file.
    file_hash: String,
    /// The scanned source path this share was reused for. Registered in
    /// `monitor_shared_hashes` at reload time so the live directory monitor can
    /// resolve and de-offer this file if its source is later deleted (HASH-1).
    source_path: PathBuf,
    /// Older duplicate hashes for the same source path, if any.
    stale_hashes: Vec<String>,
}

struct ReloadPlan {
    /// Files that are new, changed (size/mtime), or whose persisted manifest has
    /// no recorded mtime yet -- each gets hashed via `share_local_file`.
    to_hash: Vec<ReloadHashTarget>,
    /// Scanned files reused from the persisted index without rehashing. Used to
    /// resolve their `Localshare`s for the reload result so an unchanged file
    /// still appears in the returned set.
    reused_shares: Vec<ReusedReloadShare>,
    /// Persisted share-in-place hashes whose source path is no longer part of
    /// the current filtered scan and must be removed from serving/publishing.
    pruned_hashes: Vec<String>,
    /// Live reload counters for REST/WebUI progress.
    stats: ReloadPlanStats,
}

#[derive(Debug, Clone, Default)]
struct ReloadPlanStats {
    scanned_count: usize,
    planned_hash_count: usize,
    reused_count: usize,
    new_count: usize,
    changed_count: usize,
    missing_mtime_count: usize,
    stat_failed_count: usize,
    skipped_failed_count: usize,
    skipped_intake_count: usize,
    pruned_count: usize,
    stale_hash_count: usize,
    planned_hash_bytes: u64,
}

impl ReloadPlanStats {
    fn into_diagnostics(
        self,
        phase: &str,
        running: bool,
        pending: bool,
    ) -> SharedDirectoryReloadProgress {
        SharedDirectoryReloadProgress {
            phase: phase.to_string(),
            running,
            pending,
            scanned_count: self.scanned_count,
            planned_hash_count: self.planned_hash_count,
            reused_count: self.reused_count,
            new_count: self.new_count,
            changed_count: self.changed_count,
            missing_mtime_count: self.missing_mtime_count,
            stat_failed_count: self.stat_failed_count,
            skipped_failed_count: self.skipped_failed_count,
            skipped_intake_count: self.skipped_intake_count,
            pruned_count: self.pruned_count,
            stale_hash_count: self.stale_hash_count,
            disk_count: 0,
            active_hash_count: 0,
            hashed_count: 0,
            failed_hash_count: 0,
            planned_hash_bytes: self.planned_hash_bytes,
            completed_hash_bytes: 0,
            planned_read_bytes: self.planned_hash_bytes,
            completed_read_bytes: 0,
            read_rate_bytes_per_sec: 0,
            started_at_ms: None,
            updated_at_ms: None,
            active: Vec::new(),
            recent: Vec::new(),
            upcoming: Vec::new(),
            disks: Vec::new(),
        }
    }
}

pub(crate) fn reload_progress_snapshot(core: &EmulebbCore) -> SharedDirectoryReloadProgress {
    let mut snapshot = match core.shared_directory_reload_progress.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    snapshot.running = core.shared_reload_running.load(Ordering::Acquire);
    snapshot.pending = core.shared_reload_pending.load(Ordering::Acquire);
    snapshot
}

fn record_reload_progress(
    core: &EmulebbCore,
    update: impl FnOnce(&mut SharedDirectoryReloadProgress),
) {
    let mut progress = match core.shared_directory_reload_progress.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    update(&mut progress);
    progress.running = core.shared_reload_running.load(Ordering::Acquire);
    progress.pending = core.shared_reload_pending.load(Ordering::Acquire);
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn target_read_bytes_total(file_size: u64) -> u64 {
    file_size
}

fn shared_reload_hash_workers_per_disk() -> usize {
    let cpu_bound = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .saturating_div(2)
        .max(1);
    cpu_bound.min(MAX_SHARED_RELOAD_HASH_WORKERS_PER_DISK)
}

fn split_hash_targets_by_worker<T>(targets: Vec<T>, max_workers: usize) -> Vec<Vec<T>> {
    let worker_count = targets.len().min(max_workers.max(1));
    if worker_count == 0 {
        return Vec::new();
    }
    let mut lanes = (0..worker_count).map(|_| Vec::new()).collect::<Vec<_>>();
    for (index, target) in targets.into_iter().enumerate() {
        lanes[index % worker_count].push(target);
    }
    lanes
}

fn target_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string()
}

fn reload_hash_target(
    path: PathBuf,
    key: String,
    file_size: u64,
    source_mtime_ms: Option<i64>,
    stale_hashes: Vec<String>,
    reason: &str,
) -> ReloadHashTarget {
    ReloadHashTarget {
        id: String::new(),
        order: 0,
        disk_key: String::new(),
        path,
        reason: reason.to_string(),
        key,
        file_size,
        source_mtime_ms,
        stale_hashes,
    }
}

/// Decide which scanned files actually need (re)hashing on this reload.
///
/// This is the incremental skip: a scanned file whose long-path-normalized path
/// is already in the persisted share-in-place index with a matching on-disk
/// `(file_size, mtime)` is reused as-is (its complete manifest, hash, catalog and
/// index entry already persist), so the (potentially hundreds-of-GB) payload is
/// never re-read. A file that is new, resized, re-timestamped, or whose persisted
/// manifest predates the recorded-mtime column (mtime `None`) falls through to
/// `to_hash` and is hashed exactly as before.
///
/// The stat work runs on the blocking pool: statting every file in a large
/// library is cheap relative to hashing but still touches the filesystem, so it
/// must not run on a tokio worker thread.
async fn plan_incremental_reload(
    core: &EmulebbCore,
    file_paths: Vec<PathBuf>,
) -> Result<ReloadPlan> {
    let index = core.ed2k_transfers.share_in_place_reload_index().await?;
    // Completed downloads delivered into a shared dir are reuse-only (never
    // pruned): recognized by delivered path + (size, mtime) so an unchanged
    // delivered file is a cache hit instead of a needless whole-payload re-hash.
    let delivered_index = core.ed2k_transfers.delivered_reuse_index().await?;
    let failure_entries = load_shared_source_failures(core).await?;
    tokio::task::spawn_blocking(move || {
        let failures = failure_entries
            .into_iter()
            .map(|failure| (failure.source_path.clone(), failure))
            .collect::<HashMap<_, _>>();
        let mut stats = ReloadPlanStats {
            scanned_count: file_paths.len(),
            ..ReloadPlanStats::default()
        };
        let mut to_hash = Vec::new();
        let mut reused_shares = Vec::new();
        let mut scanned_source_keys = HashSet::with_capacity(file_paths.len());
        for path in file_paths {
            // Stat the scanned file with the same long-path normalization the
            // persisted index keys use. A file that cannot be stat-ed is treated
            // as needing a hash (the ingest path will surface the real error).
            match Ed2kTransferRuntime::scanned_source_identity(&path) {
                Some((key, size, mtime_ms)) => {
                    scanned_source_keys.insert(key.clone());
                    if unchanged_failure(&failures, &key, size, mtime_ms) {
                        stats.skipped_failed_count += 1;
                        continue;
                    }
                    match index.get(&key) {
                        // Reuse only on an exact size + mtime match, and only when the
                        // persisted manifest actually recorded an mtime (pre-v9 rows
                        // store `None`, so they are rehashed once to backfill it).
                        Some(entries) => {
                            if let Some(entry) = entries.iter().find(|entry| {
                                entry.file_size == size
                                    && entry.source_mtime_ms.is_some()
                                    && entry.source_mtime_ms == mtime_ms
                            }) {
                                stats.reused_count += 1;
                                stats.stale_hash_count += entries.len().saturating_sub(1);
                                reused_shares.push(ReusedReloadShare {
                                    file_hash: entry.file_hash.clone(),
                                    source_path: path.clone(),
                                    stale_hashes: entries
                                        .iter()
                                        .filter(|stale| stale.file_hash != entry.file_hash)
                                        .map(|stale| stale.file_hash.clone())
                                        .collect(),
                                });
                            } else {
                                stats.planned_hash_count += 1;
                                stats.stale_hash_count += entries.len();
                                if entries.iter().any(|entry| entry.source_mtime_ms.is_none()) {
                                    stats.missing_mtime_count += 1;
                                } else {
                                    stats.changed_count += 1;
                                }
                                to_hash.push(reload_hash_target(
                                    path,
                                    key,
                                    size,
                                    mtime_ms,
                                    entries
                                        .iter()
                                        .map(|entry| entry.file_hash.clone())
                                        .collect(),
                                    if entries.iter().any(|entry| entry.source_mtime_ms.is_none()) {
                                        "missingMtime"
                                    } else {
                                        "changed"
                                    },
                                ));
                            }
                        }
                        // Not a share-in-place source. Before treating it as a
                        // brand-new file to hash, check whether it is a completed
                        // download's delivered file re-found in a shared dir: if
                        // its delivered identity (size + mtime) still matches, the
                        // download already computed this hashset, so reuse it
                        // (oracle FindKnownFile) rather than re-hashing the whole
                        // payload. Reuse-only: this never contributes to pruning.
                        None => {
                            match delivered_index.get(&key) {
                                Some(entry)
                                    if entry.file_size == size
                                        && entry.source_mtime_ms.is_some()
                                        && entry.source_mtime_ms == mtime_ms =>
                                {
                                    stats.reused_count += 1;
                                    reused_shares.push(ReusedReloadShare {
                                        file_hash: entry.file_hash.clone(),
                                        source_path: path.clone(),
                                        stale_hashes: Vec::new(),
                                    });
                                }
                                // Brand-new path: hash it, nothing stale to clean up.
                                _ => {
                                    stats.planned_hash_count += 1;
                                    stats.new_count += 1;
                                    to_hash.push(reload_hash_target(
                                        path,
                                        key,
                                        size,
                                        mtime_ms,
                                        Vec::new(),
                                        "new",
                                    ));
                                }
                            }
                        }
                    }
                }
                None => {
                    let key = shared_source_key(&path);
                    scanned_source_keys.insert(key.clone());
                    if unchanged_failure(&failures, &key, 0, None) {
                        stats.skipped_failed_count += 1;
                        continue;
                    }
                    stats.planned_hash_count += 1;
                    stats.stat_failed_count += 1;
                    to_hash.push(reload_hash_target(
                        path,
                        key,
                        0,
                        None,
                        Vec::new(),
                        "statFailed",
                    ));
                }
            }
        }
        let kept_hashes = reused_shares
            .iter()
            .map(|share| share.file_hash.to_ascii_lowercase())
            .chain(
                to_hash
                    .iter()
                    .flat_map(|target| target.stale_hashes.iter())
                    .map(|hash| hash.to_ascii_lowercase()),
            )
            .collect::<HashSet<_>>();
        let pruned_hashes = index
            .iter()
            .filter(|(key, _)| !scanned_source_keys.contains(*key))
            .flat_map(|(_, entries)| entries.iter().map(|entry| entry.file_hash.clone()))
            .filter(|hash| !kept_hashes.contains(&hash.to_ascii_lowercase()))
            .collect::<Vec<_>>();
        stats.pruned_count = pruned_hashes.len();
        stats.planned_hash_bytes = to_hash.iter().map(|target| target.file_size).sum();
        ReloadPlan {
            to_hash,
            reused_shares,
            pruned_hashes,
            stats,
        }
    })
    .await
    .map_err(Into::into)
}

async fn load_shared_source_failures(
    core: &EmulebbCore,
) -> Result<Vec<MetadataSharedSourceFailure>> {
    let metadata = core.metadata_store.clone();
    tokio::task::spawn_blocking(move || metadata.shared_source_failures())
        .await
        .map_err(anyhow::Error::from)?
}

fn shared_source_key(path: &Path) -> String {
    long_path(path).display().to_string()
}

fn unchanged_failure(
    failures: &HashMap<String, MetadataSharedSourceFailure>,
    key: &str,
    file_size: u64,
    source_mtime_ms: Option<i64>,
) -> bool {
    failures.get(key).is_some_and(|failure| {
        failure.file_size == file_size && failure.source_mtime_ms == source_mtime_ms
    })
}

fn refresh_reload_rates(progress: &mut SharedDirectoryReloadProgress, now_ms: i64) {
    if let Some(started_at_ms) = progress.started_at_ms {
        let elapsed_ms = now_ms.saturating_sub(started_at_ms).max(1);
        progress.read_rate_bytes_per_sec = progress
            .completed_read_bytes
            .saturating_mul(1000)
            .saturating_div(u64::try_from(elapsed_ms).unwrap_or(1));
    }
    for active in &mut progress.active {
        let elapsed_ms = now_ms.saturating_sub(active.started_at_ms).max(1);
        active.read_rate_bytes_per_sec = active
            .read_bytes
            .saturating_mul(1000)
            .saturating_div(u64::try_from(elapsed_ms).unwrap_or(1));
    }
    for disk in &mut progress.disks {
        if let Some(started_at_ms) = progress.started_at_ms {
            let elapsed_ms = now_ms.saturating_sub(started_at_ms).max(1);
            disk.read_rate_bytes_per_sec = disk
                .completed_read_bytes
                .saturating_mul(1000)
                .saturating_div(u64::try_from(elapsed_ms).unwrap_or(1));
        }
    }
}

fn target_to_queued_file(target: &ReloadHashTarget) -> SharedDirectoryHashQueuedFile {
    SharedDirectoryHashQueuedFile {
        id: target.id.clone(),
        disk_key: target.disk_key.clone(),
        path: target.path.display().to_string(),
        name: target_name(&target.path),
        size_bytes: target.file_size,
        reason: target.reason.clone(),
        order: target.order,
    }
}

fn record_hash_queue(core: &EmulebbCore, targets: &[ReloadHashTarget]) {
    const UPCOMING_HASH_LIMIT: usize = 50;
    let now_ms = current_time_ms();
    let planned_hash_bytes = targets.iter().map(|target| target.file_size).sum::<u64>();
    let mut disks = targets
        .iter()
        .fold(
            HashMap::<String, SharedDirectoryHashDiskProgress>::new(),
            |mut disks, target| {
                let entry = disks.entry(target.disk_key.clone()).or_insert_with(|| {
                    SharedDirectoryHashDiskProgress {
                        disk_key: target.disk_key.clone(),
                        planned_count: 0,
                        active_count: 0,
                        completed_count: 0,
                        failed_count: 0,
                        queued_count: 0,
                        planned_read_bytes: 0,
                        completed_read_bytes: 0,
                        read_rate_bytes_per_sec: 0,
                        current_path: None,
                        current_name: None,
                        current_stage: None,
                    }
                });
                entry.planned_count += 1;
                entry.queued_count += 1;
                entry.planned_read_bytes = entry
                    .planned_read_bytes
                    .saturating_add(target_read_bytes_total(target.file_size));
                disks
            },
        )
        .into_values()
        .collect::<Vec<_>>();
    disks.sort_by(|left, right| left.disk_key.cmp(&right.disk_key));
    record_reload_progress(core, |diagnostics| {
        diagnostics.started_at_ms = Some(now_ms);
        diagnostics.updated_at_ms = Some(now_ms);
        diagnostics.active_hash_count = 0;
        diagnostics.hashed_count = 0;
        diagnostics.failed_hash_count = 0;
        diagnostics.planned_hash_bytes = planned_hash_bytes;
        diagnostics.completed_hash_bytes = 0;
        diagnostics.planned_read_bytes = planned_hash_bytes;
        diagnostics.completed_read_bytes = 0;
        diagnostics.read_rate_bytes_per_sec = 0;
        diagnostics.active.clear();
        diagnostics.recent.clear();
        diagnostics.upcoming = targets
            .iter()
            .take(UPCOMING_HASH_LIMIT)
            .map(target_to_queued_file)
            .collect();
        diagnostics.disks = disks;
    });
}

fn record_hash_target_started(core: &EmulebbCore, target: &ReloadHashTarget) {
    let now_ms = current_time_ms();
    record_reload_progress(core, |diagnostics| {
        diagnostics.updated_at_ms = Some(now_ms);
        diagnostics.upcoming.retain(|queued| queued.id != target.id);
        diagnostics.active.push(SharedDirectoryHashActiveFile {
            id: target.id.clone(),
            disk_key: target.disk_key.clone(),
            path: target.path.display().to_string(),
            name: target_name(&target.path),
            size_bytes: target.file_size,
            reason: target.reason.clone(),
            stage: "md4".to_string(),
            stage_read_bytes: 0,
            stage_total_bytes: target.file_size,
            read_bytes: 0,
            read_bytes_total: target_read_bytes_total(target.file_size),
            read_rate_bytes_per_sec: 0,
            started_at_ms: now_ms,
            updated_at_ms: now_ms,
        });
        diagnostics.active_hash_count = diagnostics.active.len();
        if let Some(disk) = diagnostics
            .disks
            .iter_mut()
            .find(|disk| disk.disk_key == target.disk_key)
        {
            disk.active_count += 1;
            disk.queued_count = disk.queued_count.saturating_sub(1);
            disk.current_path = Some(target.path.display().to_string());
            disk.current_name = Some(target_name(&target.path));
            disk.current_stage = Some("md4".to_string());
        }
        refresh_reload_rates(diagnostics, now_ms);
    });
}

fn record_hash_target_progress(
    core: &EmulebbCore,
    target: &ReloadHashTarget,
    event: &LocalIngestProgressEvent,
) {
    let now_ms = current_time_ms();
    record_reload_progress(core, |diagnostics| {
        if let Some(active) = diagnostics
            .active
            .iter_mut()
            .find(|active| active.id == target.id)
        {
            let next_read = event.file_bytes_read.min(active.read_bytes_total);
            let delta = next_read.saturating_sub(active.read_bytes);
            active.stage = event.stage.as_str().to_string();
            active.stage_read_bytes = event.stage_bytes_read.min(event.stage_bytes_total);
            active.stage_total_bytes = event.stage_bytes_total;
            active.read_bytes = next_read;
            active.updated_at_ms = now_ms;
            diagnostics.completed_read_bytes =
                diagnostics.completed_read_bytes.saturating_add(delta);
            if let Some(disk) = diagnostics
                .disks
                .iter_mut()
                .find(|disk| disk.disk_key == target.disk_key)
            {
                disk.completed_read_bytes = disk.completed_read_bytes.saturating_add(delta);
                disk.current_stage = Some(event.stage.as_str().to_string());
            }
        }
        diagnostics.updated_at_ms = Some(now_ms);
        refresh_reload_rates(diagnostics, now_ms);
    });
}

fn record_hash_target_finished(
    core: &EmulebbCore,
    target: &ReloadHashTarget,
    hash: Option<&str>,
    error: Option<&str>,
) {
    const RECENT_HASH_LIMIT: usize = 20;
    let now_ms = current_time_ms();
    record_reload_progress(core, |diagnostics| {
        let active = diagnostics
            .active
            .iter()
            .find(|active| active.id == target.id)
            .cloned();
        diagnostics.active.retain(|active| active.id != target.id);
        let read_bytes_total = target_read_bytes_total(target.file_size);
        let read_bytes = active
            .as_ref()
            .map(|active| active.read_bytes)
            .unwrap_or(0)
            .min(read_bytes_total);
        if hash.is_some() {
            let missing = read_bytes_total.saturating_sub(read_bytes);
            diagnostics.completed_read_bytes =
                diagnostics.completed_read_bytes.saturating_add(missing);
            diagnostics.completed_hash_bytes = diagnostics
                .completed_hash_bytes
                .saturating_add(target.file_size);
            diagnostics.hashed_count += 1;
        } else {
            diagnostics.failed_hash_count += 1;
        }
        if let Some(disk) = diagnostics
            .disks
            .iter_mut()
            .find(|disk| disk.disk_key == target.disk_key)
        {
            disk.active_count = disk.active_count.saturating_sub(1);
            if hash.is_some() {
                disk.completed_count += 1;
                disk.completed_read_bytes = disk
                    .completed_read_bytes
                    .saturating_add(read_bytes_total.saturating_sub(read_bytes));
            } else {
                disk.failed_count += 1;
            }
            disk.current_path = None;
            disk.current_name = None;
            disk.current_stage = None;
        }
        let started_at_ms = active
            .as_ref()
            .map(|active| active.started_at_ms)
            .or(diagnostics.started_at_ms)
            .unwrap_or(now_ms);
        let duration_ms = now_ms.saturating_sub(started_at_ms).max(0);
        let average_read_rate_bytes_per_sec = if duration_ms > 0 {
            read_bytes
                .saturating_mul(1000)
                .saturating_div(u64::try_from(duration_ms).unwrap_or(1))
        } else {
            0
        };
        diagnostics.recent.insert(
            0,
            SharedDirectoryHashRecentFile {
                id: target.id.clone(),
                disk_key: target.disk_key.clone(),
                path: target.path.display().to_string(),
                name: target_name(&target.path),
                size_bytes: target.file_size,
                reason: target.reason.clone(),
                result: if hash.is_some() { "ok" } else { "failed" }.to_string(),
                error: error.map(str::to_string),
                hash: hash.map(str::to_string),
                read_bytes: if hash.is_some() {
                    read_bytes_total
                } else {
                    read_bytes
                },
                read_bytes_total,
                duration_ms,
                average_read_rate_bytes_per_sec,
                finished_at_ms: now_ms,
            },
        );
        diagnostics.recent.truncate(RECENT_HASH_LIMIT);
        diagnostics.active_hash_count = diagnostics.active.len();
        diagnostics.updated_at_ms = Some(now_ms);
        refresh_reload_rates(diagnostics, now_ms);
    });
}

/// Synchronous core primitive: scan + hash + share the whole library, returning
/// the full set of shares once it is fully indexed.
///
/// This drives the entire (potentially very large) MD4/ed2k hash to completion
/// before it resolves, so it MUST NOT be awaited directly from a short-lived HTTP
/// request: a client timeout that drops the request future would cancel the
/// in-progress hash loop mid-library, leaving most files un-indexed. The REST
/// surface instead uses [`reload_shared_directories_detached`], which runs the
/// hash on a detached background task so it always runs to completion independent
/// of the caller. The live `hashingCount` lets a controller watch progress: it is
/// set to the file count up front and decremented per file as the hash completes,
/// reaching 0 when the library is fully indexed.
pub(crate) async fn reload_shared_directories(core: &EmulebbCore) -> Result<Vec<LocalShare>> {
    record_reload_progress(core, |diagnostics| {
        diagnostics.phase = "scanning".to_string();
    });
    let scan = scan_shared_files(core).await?;
    record_reload_progress(core, |diagnostics| {
        diagnostics.phase = "planning".to_string();
        diagnostics.scanned_count = scan.file_paths.len();
        diagnostics.skipped_intake_count = scan.skipped_intake_count;
    });
    // Incremental skip: only (re)hash files that are new or whose size/mtime
    // changed since the last index; unchanged files keep their persisted shares.
    let mut plan = plan_incremental_reload(core, scan.file_paths).await?;
    plan.stats.skipped_intake_count = scan.skipped_intake_count;
    record_reload_progress(core, |diagnostics| {
        *diagnostics = plan.stats.clone().into_diagnostics("hashing", true, false);
    });
    // `hashingCount` reflects only the files actually being hashed, so an
    // unchanged library reports ~0 and REST stays responsive.
    core.shared_hashing_count
        .store(plan.to_hash.len() as i64, Ordering::Relaxed);
    let _guard = HashingCountGuard(core.shared_hashing_count.clone());

    let mut shares = Vec::new();
    // Unchanged files were not re-hashed but are still shared, so resolve their
    // already-persisted shares so the returned set reflects the whole library.
    for reused in &plan.reused_shares {
        if let Some(share) = core.share(&reused.file_hash).await {
            shares.push(share);
        }
        // Register the source path -> hash so the live directory monitor can
        // de-offer this file if its source is deleted at runtime (HASH-1).
        register_monitor_shared_hash(core, reused.source_path.clone(), &reused.file_hash).await;
        forget_stale_shares(core, &reused.stale_hashes, &reused.file_hash).await;
    }
    forget_stale_shares(core, &plan.pruned_hashes, "").await;
    for target in plan.to_hash {
        let source_path = target.path.clone();
        let share = core
            .share_local_file(LocalShareCreate {
                path: target.path.display().to_string(),
                name: None,
            })
            .await?;
        // Same HASH-1 registration for a freshly (re)hashed startup share.
        register_monitor_shared_hash(core, source_path, &share.hash).await;
        forget_stale_shares(core, &target.stale_hashes, &share.hash).await;
        shares.push(share);
        core.shared_hashing_count.fetch_sub(1, Ordering::Relaxed);
    }
    record_reload_progress(core, |diagnostics| {
        diagnostics.phase = "idle".to_string();
        diagnostics.disk_count = 0;
    });
    core.queue_ed2k_shared_catalog_publish();
    Ok(shares)
}

/// Record a shared file's source path -> hash in the live monitor's tracking
/// map so a runtime deletion of a startup-shared file is de-offered/de-published
/// the same way a monitor-picked-up file already is (HASH-1). The live
/// directory monitor watches the same roots the startup reload scans, so its
/// `Remove` event for a vanished startup share resolves the hash here (the file
/// is gone and can no longer be re-hashed) and drops it from the catalog.
async fn register_monitor_shared_hash(core: &EmulebbCore, source_path: PathBuf, hash: &str) {
    // Normalize through `long_path` so the key matches the form the live monitor
    // resolves against (see `monitor_shared_key`): the scan already walks the
    // root through `long_path`, but normalize here too so the invariant is local
    // and holds even if a caller passes a raw path.
    let key = long_path(&source_path);
    core.state
        .lock()
        .await
        .monitor_shared_hashes
        .insert(key, hash.to_string());
}

/// Drop previous identities for the same share-in-place source path so modified
/// files do not leave duplicate, unreachable shares. A no-op for the current
/// hash, which covers timestamp-only changes that hash to the same content.
async fn forget_stale_shares(core: &EmulebbCore, stale_hashes: &[String], new_hash: &str) {
    for stale_hash in stale_hashes {
        if stale_hash.eq_ignore_ascii_case(new_hash) {
            continue;
        }
        match core.ed2k_transfers.delete_transfer_files(stale_hash).await {
            Ok(true) => core.queue_ed2k_shared_catalog_publish(),
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(
                    stale_hash,
                    error = %error,
                    "failed to remove the stale manifest of a changed shared file",
                );
            }
        }
    }
}

/// Kick a full shared-directory scan + hash on a **detached** background task and
/// return immediately, so the work runs to completion independent of the HTTP
/// request/connection that triggered it.
///
/// The blocking issue this solves: hashing a large shared library (hundreds of
/// GB) takes far longer than any reasonable HTTP timeout. Awaiting
/// [`reload_shared_directories`] inside the request handler tied the hash to the
/// request lifetime, so a client timeout cancelled the handler future and stopped
/// hashing after only a handful of files. By spawning the hash on a detached
/// `tokio` task (the core is `Clone` / `Arc`-backed), the request returns
/// promptly while `hashingCount` climbs/drains in the background and
/// `shared-files` fills in on its own.
///
/// Returns immediately after enqueueing the reload job. The queued hash count is
/// only known after the background scan/stat planning phase, so callers should
/// observe `hashingCount` instead of relying on the return value. Unlike the
/// synchronous primitive, the background worker logs and skips a file that fails
/// to hash and continues, so one bad file never aborts indexing of the rest of
/// the library.
pub(crate) async fn reload_shared_directories_detached(core: &EmulebbCore) -> Result<usize> {
    core.shared_reload_pending.store(true, Ordering::Release);
    record_reload_progress(core, |diagnostics| {
        diagnostics.phase = "queued".to_string();
    });
    if core.shared_reload_running.swap(true, Ordering::AcqRel) {
        return Ok(0);
    }
    let core = core.clone();
    tokio::spawn(async move {
        loop {
            core.shared_reload_pending.store(false, Ordering::Release);
            if let Err(error) = run_shared_directories_reload_job(core.clone()).await {
                tracing::warn!(%error, "background shared-directory reload failed");
            }
            if !core.shared_reload_pending.load(Ordering::Acquire) {
                core.shared_reload_running.store(false, Ordering::Release);
                if !core.shared_reload_pending.load(Ordering::Acquire) {
                    break;
                }
                if core.shared_reload_running.swap(true, Ordering::AcqRel) {
                    break;
                }
            }
        }
    });
    Ok(0)
}

async fn run_shared_directories_reload_job(core: EmulebbCore) -> Result<()> {
    record_reload_progress(&core, |diagnostics| {
        diagnostics.phase = "scanning".to_string();
    });
    let scan = scan_shared_files(&core).await?;
    let scanned = scan.file_paths.len();
    let skipped_intake_count = scan.skipped_intake_count;
    record_reload_progress(&core, |diagnostics| {
        diagnostics.phase = "planning".to_string();
        diagnostics.scanned_count = scanned;
        diagnostics.skipped_intake_count = skipped_intake_count;
    });
    // Incremental skip: an unchanged file (same path + size + mtime as its
    // persisted manifest) is NOT re-hashed, so a restart over an unchanged
    // library finishes near-instantly and `hashingCount` stays ~0.
    let mut plan = plan_incremental_reload(&core, scan.file_paths).await?;
    plan.stats.skipped_intake_count = skipped_intake_count;
    record_reload_progress(&core, |diagnostics| {
        *diagnostics = plan.stats.clone().into_diagnostics(
            "hashing",
            true,
            core.shared_reload_pending.load(Ordering::Acquire),
        );
    });
    let queued = plan.to_hash.len();
    let reused = plan.reused_shares.len();
    // Publish the pending count after scan/planning. It counts only the files
    // actually being hashed, so an unchanged library reports ~0.
    core.shared_hashing_count
        .store(queued as i64, Ordering::Relaxed);
    tracing::info!(
        scanned,
        to_hash = queued,
        reused_unchanged = reused,
        "shared-directory reload planned (incremental skip of unchanged files)"
    );

    for reused in &plan.reused_shares {
        forget_stale_shares(&core, &reused.stale_hashes, &reused.file_hash).await;
    }
    forget_stale_shares(&core, &plan.pruned_hashes, "").await;

    let mut to_hash = plan.to_hash;
    let _guard = HashingCountGuard(core.shared_hashing_count.clone());
    // Group the to-hash set by physical disk, then fan out a bounded number of
    // workers per disk. The hash itself already runs off the manifest lock and on a
    // blocking thread (see `ingest_local_file`), and local ingest now reads each file
    // once for both MD4 and AICH, so a small per-disk fanout keeps large SSD/NVMe
    // startup libraries moving without unbounded HDD seek pressure.
    let mut by_disk: HashMap<String, Vec<ReloadHashTarget>> = HashMap::new();
    for (order, target) in to_hash.iter_mut().enumerate() {
        target.order = order;
        target.id = format!("hash-{order:06}");
        target.disk_key = physical_disk_key(&target.path);
    }
    record_hash_queue(&core, &to_hash);
    for target in to_hash {
        by_disk
            .entry(target.disk_key.clone())
            .or_default()
            .push(target);
    }
    let disk_count = by_disk.len();
    record_reload_progress(&core, |diagnostics| {
        diagnostics.disk_count = disk_count;
    });
    let max_workers_per_disk = shared_reload_hash_workers_per_disk();
    tracing::info!(
        disks = disk_count,
        max_workers_per_disk,
        "background shared-directory reload hashing across physical disks"
    );
    let mut workers = JoinSet::new();
    let mut worker_count = 0usize;
    for (disk, targets) in by_disk {
        for (lane, targets) in split_hash_targets_by_worker(targets, max_workers_per_disk)
            .into_iter()
            .enumerate()
        {
            worker_count += 1;
            let core = core.clone();
            let disk = disk.clone();
            workers.spawn(async move {
                let files = targets.len();
                for target in targets {
                    hash_one_reload_target(&core, target).await;
                    tokio::task::yield_now().await;
                }
                tracing::debug!(
                    disk = %disk,
                    lane,
                    files,
                    "shared-directory hashing worker finished"
                );
            });
        }
    }
    tracing::info!(
        workers = worker_count,
        "background shared-directory reload hash workers started"
    );
    while workers.join_next().await.is_some() {}
    record_reload_progress(&core, |diagnostics| {
        diagnostics.phase = "idle".to_string();
        diagnostics.active.clear();
        diagnostics.upcoming.clear();
        diagnostics.active_hash_count = 0;
        for disk in &mut diagnostics.disks {
            disk.active_count = 0;
            disk.queued_count = 0;
            disk.current_path = None;
            disk.current_name = None;
            disk.current_stage = None;
        }
        diagnostics.updated_at_ms = Some(current_time_ms());
    });
    // A reused-only reload does not pass through `share_local_file`, so queue a
    // final server offer refresh explicitly once the catalog is known complete.
    core.queue_ed2k_shared_catalog_publish();
    tracing::info!("background shared-directory reload finished hashing the library");
    Ok(())
}

/// Hash and share one reloaded file, then prune a now-stale duplicate manifest
/// and decrement the live `hashingCount`. A file that fails to hash is logged and
/// skipped so one bad file never aborts indexing of the rest of the library.
async fn hash_one_reload_target(core: &EmulebbCore, target: ReloadHashTarget) {
    record_hash_target_started(core, &target);
    let progress_core = core.clone();
    let progress_target = target.clone();
    let progress = Arc::new(move |event: LocalIngestProgressEvent| {
        record_hash_target_progress(&progress_core, &progress_target, &event);
    });
    let source_path = target.path.clone();
    match core
        .share_local_file_with_progress(
            LocalShareCreate {
                path: target.path.display().to_string(),
                name: None,
            },
            Some(progress),
        )
        .await
    {
        Ok(share) => {
            register_monitor_shared_hash(core, source_path, &share.hash).await;
            forget_stale_shares(core, &target.stale_hashes, &share.hash).await;
            record_hash_target_finished(core, &target, Some(&share.hash), None);
        }
        Err(error) => {
            let error_message = error.to_string();
            record_reload_target_failure(core, &target, "ingest failed").await;
            record_hash_target_finished(core, &target, None, Some(&error_message));
            tracing::warn!(
                path = %target.path.display(),
                error = %error,
                "failed to hash/share file during background shared-directory reload (skipping)",
            );
        }
    }
    core.shared_hashing_count.fetch_sub(1, Ordering::Relaxed);
}

async fn record_reload_target_failure(core: &EmulebbCore, target: &ReloadHashTarget, reason: &str) {
    let metadata = core.metadata_store.clone();
    let key = target.key.clone();
    let file_size = target.file_size;
    let source_mtime_ms = target.source_mtime_ms;
    let reason = reason.to_string();
    match tokio::task::spawn_blocking(move || {
        metadata.upsert_shared_source_failure(&key, file_size, source_mtime_ms, &reason)
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "failed to persist shared-source reload failure");
        }
        Err(error) => {
            tracing::warn!(error = %error, "shared-source failure persistence task panicked");
        }
    }
}

#[cfg(test)]
mod tests;
