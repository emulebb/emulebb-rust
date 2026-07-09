use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fs::Metadata;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use emulebb_ed2k::long_path::long_path;
use emulebb_index::IndexedSharedDirectoryRoot;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

/// One configured shared-directory root exposed through the eMuleBB REST contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedDirectoryRoot {
    pub path: String,
    pub recursive: bool,
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
    pub reload: SharedReloadDiagnostics,
}

/// Path-free counters for the latest shared-directory reload decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedReloadDiagnostics {
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
}

impl Default for SharedReloadDiagnostics {
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

/// Backward-compatible shared-directory root input accepted by the REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SharedDirectoryRootUpdate {
    Path(String),
    Object {
        path: String,
        #[serde(default)]
        recursive: bool,
    },
}

pub(crate) fn shared_directory_update_parts(root: SharedDirectoryRootUpdate) -> (String, bool) {
    match root {
        SharedDirectoryRootUpdate::Path(path) => (path, false),
        SharedDirectoryRootUpdate::Object { path, recursive } => (path, recursive),
    }
}

pub(crate) fn shared_directory_from_index(root: IndexedSharedDirectoryRoot) -> SharedDirectoryRoot {
    SharedDirectoryRoot {
        path: root.path,
        recursive: root.recursive,
        monitor_owned: false,
        shareable: root.shareable,
        accessible: root.accessible,
    }
}

pub(crate) fn shared_directory_to_index(root: &SharedDirectoryRoot) -> IndexedSharedDirectoryRoot {
    IndexedSharedDirectoryRoot {
        path: root.path.clone(),
        recursive: root.recursive,
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
        recursive: root.recursive,
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
        if !refreshed.accessible || !refreshed.recursive {
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
                    recursive: false,
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

/// Enumerate the regular files under a shared-directory root.
///
/// This walk is intentionally synchronous and recursive (via `walkdir`), so it
/// MUST NOT be invoked directly from an async context: async callers wrap it in
/// `tokio::task::spawn_blocking` so the (potentially large) blocking scan never
/// stalls a tokio worker thread.
///
/// When `recursive == false` only the immediate directory's files are returned
/// (`max_depth(1)`); when `recursive == true` the full tree is descended.
/// `walkdir`'s own loop detection guards against symlink cycles. A single
/// unreadable entry (permissions, vanished file, broken symlink) is logged and
/// skipped instead of aborting the whole scan, so the readable files are still
/// collected.
pub(crate) fn collect_shared_directory_files(
    root: &Path,
    recursive: bool,
    output: &mut Vec<PathBuf>,
) -> Result<usize> {
    // Operator-facing shared-directory boundary: walk the root through the
    // long-path helper so a shared tree deeper than the legacy MAX_PATH (260)
    // limit is still enumerated. The verbatim root flows into every entry path
    // walkdir produces, so the ingest read path inherits the long-path form.
    // (Operator-rule scope: shared-directory trees -- see long_path.rs.)
    let root = long_path(root);
    let root = root.as_path();
    let max_depth = if recursive { usize::MAX } else { 1 };
    let skipped_intake_count = Cell::new(0usize);
    for entry in WalkDir::new(root)
        .max_depth(max_depth)
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
            skipped_intake_count += collect_shared_directory_files(
                Path::new(&root.path),
                root.recursive,
                &mut file_paths,
            )
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
struct ReloadHashTarget {
    /// The scanned file to (re)hash via `share_local_file`.
    path: PathBuf,
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
    /// Path-free reload counters for REST diagnostics and live-parity evidence.
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
}

impl ReloadPlanStats {
    fn into_diagnostics(
        self,
        phase: &str,
        running: bool,
        pending: bool,
    ) -> SharedReloadDiagnostics {
        SharedReloadDiagnostics {
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
        }
    }
}

pub(crate) fn reload_diagnostics_snapshot(core: &EmulebbCore) -> SharedReloadDiagnostics {
    let mut snapshot = match core.shared_reload_diagnostics.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    snapshot.running = core.shared_reload_running.load(Ordering::Acquire);
    snapshot.pending = core.shared_reload_pending.load(Ordering::Acquire);
    snapshot
}

fn record_reload_diagnostics(
    core: &EmulebbCore,
    update: impl FnOnce(&mut SharedReloadDiagnostics),
) {
    let mut diagnostics = match core.shared_reload_diagnostics.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    update(&mut diagnostics);
    diagnostics.running = core.shared_reload_running.load(Ordering::Acquire);
    diagnostics.pending = core.shared_reload_pending.load(Ordering::Acquire);
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
                                to_hash.push(ReloadHashTarget {
                                    path,
                                    key,
                                    file_size: size,
                                    source_mtime_ms: mtime_ms,
                                    stale_hashes: entries
                                        .iter()
                                        .map(|entry| entry.file_hash.clone())
                                        .collect(),
                                });
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
                                    to_hash.push(ReloadHashTarget {
                                        path,
                                        key,
                                        file_size: size,
                                        source_mtime_ms: mtime_ms,
                                        stale_hashes: Vec::new(),
                                    });
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
                    to_hash.push(ReloadHashTarget {
                        path,
                        key,
                        file_size: 0,
                        source_mtime_ms: None,
                        stale_hashes: Vec::new(),
                    });
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
    record_reload_diagnostics(core, |diagnostics| {
        diagnostics.phase = "scanning".to_string();
    });
    let scan = scan_shared_files(core).await?;
    record_reload_diagnostics(core, |diagnostics| {
        diagnostics.phase = "planning".to_string();
        diagnostics.scanned_count = scan.file_paths.len();
        diagnostics.skipped_intake_count = scan.skipped_intake_count;
    });
    // Incremental skip: only (re)hash files that are new or whose size/mtime
    // changed since the last index; unchanged files keep their persisted shares.
    let mut plan = plan_incremental_reload(core, scan.file_paths).await?;
    plan.stats.skipped_intake_count = scan.skipped_intake_count;
    record_reload_diagnostics(core, |diagnostics| {
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
    record_reload_diagnostics(core, |diagnostics| {
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
    record_reload_diagnostics(core, |diagnostics| {
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
    record_reload_diagnostics(&core, |diagnostics| {
        diagnostics.phase = "scanning".to_string();
    });
    let scan = scan_shared_files(&core).await?;
    let scanned = scan.file_paths.len();
    let skipped_intake_count = scan.skipped_intake_count;
    record_reload_diagnostics(&core, |diagnostics| {
        diagnostics.phase = "planning".to_string();
        diagnostics.scanned_count = scanned;
        diagnostics.skipped_intake_count = skipped_intake_count;
    });
    // Incremental skip: an unchanged file (same path + size + mtime as its
    // persisted manifest) is NOT re-hashed, so a restart over an unchanged
    // library finishes near-instantly and `hashingCount` stays ~0.
    let mut plan = plan_incremental_reload(&core, scan.file_paths).await?;
    plan.stats.skipped_intake_count = skipped_intake_count;
    record_reload_diagnostics(&core, |diagnostics| {
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

    let to_hash = plan.to_hash;
    let _guard = HashingCountGuard(core.shared_hashing_count.clone());
    // Group the to-hash set by physical disk and hash one file at a time per
    // spindle, with distinct disks running in parallel. Concurrent reads on a
    // single HDD seek-thrash (slower than serial), so per-disk concurrency is 1;
    // the speed-up comes from fanning out across disks. The hash itself already
    // runs off the manifest lock and on a blocking thread (see
    // `ingest_local_file`), so N disks means N files in flight without freezing
    // the REST/control plane.
    let mut by_disk: HashMap<String, Vec<ReloadHashTarget>> = HashMap::new();
    for target in to_hash {
        by_disk
            .entry(physical_disk_key(&target.path))
            .or_default()
            .push(target);
    }
    let disk_count = by_disk.len();
    record_reload_diagnostics(&core, |diagnostics| {
        diagnostics.disk_count = disk_count;
    });
    tracing::info!(
        disks = disk_count,
        "background shared-directory reload hashing across physical disks"
    );
    let mut workers = JoinSet::new();
    for (disk, targets) in by_disk {
        let core = core.clone();
        workers.spawn(async move {
            let files = targets.len();
            for target in targets {
                hash_one_reload_target(&core, target).await;
                tokio::task::yield_now().await;
            }
            tracing::debug!(
                disk = %disk,
                files,
                "per-disk shared-directory hashing worker finished"
            );
        });
    }
    while workers.join_next().await.is_some() {}
    record_reload_diagnostics(&core, |diagnostics| {
        diagnostics.phase = "idle".to_string();
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
    match core
        .share_local_file(LocalShareCreate {
            path: target.path.display().to_string(),
            name: None,
        })
        .await
    {
        Ok(share) => {
            forget_stale_shares(core, &target.stale_hashes, &share.hash).await;
        }
        Err(error) => {
            record_reload_target_failure(core, &target, "ingest failed").await;
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
mod tests {
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
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
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
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
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
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
        let (_, size, mtime_ms) = Ed2kTransferRuntime::scanned_source_identity(&source).unwrap();
        let file_hash = "00112233445566778899aabbccddeeff".to_string();
        core.metadata_store
            .upsert_transfer_manifest(&emulebb_metadata::MetadataTransferManifest {
                file_hash: file_hash.clone(),
                canonical_name: "Imported.Source.bin".to_string(),
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
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
        let (_, size, mtime_ms) =
            Ed2kTransferRuntime::scanned_source_identity(&delivered).unwrap();
        let file_hash = "aabbccddeeff00112233445566778899".to_string();
        // A completed download: delivered_path set, source_path NONE, and the
        // delivered mtime baseline recorded (as deliver.rs does at delivery).
        core.metadata_store
            .upsert_transfer_manifest(&emulebb_metadata::MetadataTransferManifest {
                file_hash: file_hash.clone(),
                canonical_name: "Completed.Download.bin".to_string(),
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
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
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
}
