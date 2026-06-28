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
        monitor_owned: root.monitor_owned,
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
) -> Result<()> {
    // Operator-facing shared-directory boundary: walk the root through the
    // long-path helper so a shared tree deeper than the legacy MAX_PATH (260)
    // limit is still enumerated. The verbatim root flows into every entry path
    // walkdir produces, so the ingest read path inherits the long-path form.
    // (Operator-rule scope: shared-directory trees -- see long_path.rs.)
    let root = long_path(root);
    let root = root.as_path();
    let max_depth = if recursive { usize::MAX } else { 1 };
    for entry in WalkDir::new(root)
        .max_depth(max_depth)
        .follow_links(false)
        .into_iter()
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(
                    root = %root.display(),
                    error = %error,
                    "skipping unreadable shared-directory entry",
                );
                continue;
            }
        };
        if entry.file_type().is_file() {
            output.push(entry.into_path());
        }
    }
    Ok(())
}

/// Async-safe wrapper around [`collect_shared_directory_files`] for every root.
///
/// The blocking `walkdir` scan is dispatched onto `tokio`'s blocking thread
/// pool via `spawn_blocking`, so async callers never run the (potentially large)
/// recursive filesystem walk on a runtime worker thread.
pub(crate) async fn scan_shared_directory_roots(
    roots: Vec<SharedDirectoryRoot>,
) -> Result<Vec<PathBuf>> {
    tokio::task::spawn_blocking(move || -> Result<Vec<PathBuf>> {
        let mut file_paths = Vec::new();
        for root in roots {
            collect_shared_directory_files(Path::new(&root.path), root.recursive, &mut file_paths)
                .with_context(|| format!("failed to scan shared directory {}", root.path))?;
        }
        Ok(file_paths)
    })
    .await?
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

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime;
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
async fn scan_shared_files(core: &EmulebbCore) -> Result<Vec<PathBuf>> {
    let roots = core.state.lock().await.shared_directories.clone();
    // The recursive directory walk is synchronous and may be large, so the helper
    // runs it off the async executor via spawn_blocking to avoid stalling a tokio
    // worker thread.
    let mut file_paths = scan_shared_directory_roots(roots).await?;
    file_paths.sort();
    file_paths.dedup();
    Ok(file_paths)
}

/// Outcome of partitioning a freshly scanned shared-file list against the
/// persisted share-in-place index: the files that still need (re)hashing plus a
/// count of unchanged files skipped (for logging / the live `hashingCount`).
struct ReloadHashTarget {
    /// The scanned file to (re)hash via `share_local_file`.
    path: PathBuf,
    /// Existing hashes for the same source path. Once the current identity is
    /// known, every different hash here is removed so a changed file does not
    /// leave duplicate shares for the same source path.
    stale_hashes: Vec<String>,
}

struct ReusedReloadShare {
    /// File hash reused from the persisted index because path, size, and mtime
    /// still match the scanned file.
    file_hash: String,
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
    tokio::task::spawn_blocking(move || {
        let mut stats = ReloadPlanStats {
            scanned_count: file_paths.len(),
            ..ReloadPlanStats::default()
        };
        let mut to_hash = Vec::new();
        let mut reused_shares = Vec::new();
        for path in file_paths {
            // Stat the scanned file with the same long-path normalization the
            // persisted index keys use. A file that cannot be stat-ed is treated
            // as needing a hash (the ingest path will surface the real error).
            match Ed2kTransferRuntime::scanned_source_identity(&path) {
                Some((key, size, mtime_ms)) => match index.get(&key) {
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
                                stale_hashes: entries
                                    .iter()
                                    .map(|entry| entry.file_hash.clone())
                                    .collect(),
                            });
                        }
                    }
                    // Brand-new path: hash it, nothing stale to clean up.
                    None => {
                        stats.planned_hash_count += 1;
                        stats.new_count += 1;
                        to_hash.push(ReloadHashTarget {
                            path,
                            stale_hashes: Vec::new(),
                        });
                    }
                },
                None => {
                    stats.planned_hash_count += 1;
                    stats.stat_failed_count += 1;
                    to_hash.push(ReloadHashTarget {
                        path,
                        stale_hashes: Vec::new(),
                    });
                }
            }
        }
        ReloadPlan {
            to_hash,
            reused_shares,
            stats,
        }
    })
    .await
    .map_err(Into::into)
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
    let file_paths = scan_shared_files(core).await?;
    record_reload_diagnostics(core, |diagnostics| {
        diagnostics.phase = "planning".to_string();
        diagnostics.scanned_count = file_paths.len();
    });
    // Incremental skip: only (re)hash files that are new or whose size/mtime
    // changed since the last index; unchanged files keep their persisted shares.
    let plan = plan_incremental_reload(core, file_paths).await?;
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
        forget_stale_shares(core, &reused.stale_hashes, &reused.file_hash).await;
    }
    for target in plan.to_hash {
        let share = core
            .share_local_file(LocalShareCreate {
                path: target.path.display().to_string(),
                name: None,
            })
            .await?;
        forget_stale_shares(core, &target.stale_hashes, &share.hash).await;
        shares.push(share);
        core.shared_hashing_count.fetch_sub(1, Ordering::Relaxed);
    }
    record_reload_diagnostics(core, |diagnostics| {
        diagnostics.phase = "idle".to_string();
        diagnostics.disk_count = 0;
    });
    Ok(shares)
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
    let file_paths = scan_shared_files(&core).await?;
    let scanned = file_paths.len();
    record_reload_diagnostics(&core, |diagnostics| {
        diagnostics.phase = "planning".to_string();
        diagnostics.scanned_count = scanned;
    });
    // Incremental skip: an unchanged file (same path + size + mtime as its
    // persisted manifest) is NOT re-hashed, so a restart over an unchanged
    // library finishes near-instantly and `hashingCount` stays ~0.
    let plan = plan_incremental_reload(&core, file_paths).await?;
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
            tracing::warn!(
                path = %target.path.display(),
                error = %error,
                "failed to hash/share file during background shared-directory reload (skipping)",
            );
        }
    }
    core.shared_hashing_count.fetch_sub(1, Ordering::Relaxed);
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

    #[test]
    fn non_recursive_collects_only_immediate_files() {
        let root = scratch_dir("nonrec");
        fs::write(root.join("top-a.dat"), b"a").unwrap();
        fs::write(root.join("top-b.dat"), b"b").unwrap();
        let nested = root.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("deep.dat"), b"c").unwrap();

        let mut output = Vec::new();
        collect_shared_directory_files(&root, false, &mut output).unwrap();

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
        collect_shared_directory_files(&root, true, &mut output).unwrap();

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

        assert!(result.is_ok());
        assert!(output.is_empty());
    }
}
