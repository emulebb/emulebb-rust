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

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

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
    let file_paths = scan_shared_files(core).await?;
    core.shared_hashing_count
        .store(file_paths.len() as i64, Ordering::Relaxed);
    let _guard = HashingCountGuard(core.shared_hashing_count.clone());

    let mut shares = Vec::new();
    for path in file_paths {
        shares.push(
            core.share_local_file(LocalShareCreate {
                path: path.display().to_string(),
                name: None,
            })
            .await?,
        );
        core.shared_hashing_count.fetch_sub(1, Ordering::Relaxed);
    }
    Ok(shares)
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
/// Returns the number of files queued for hashing. The scan itself runs before
/// returning, so the count and the initial `hashingCount` are accurate the
/// instant the caller gets control back. Unlike the synchronous primitive, the
/// background worker logs and skips a file that fails to hash and continues, so
/// one bad file never aborts indexing of the rest of the library.
pub(crate) async fn reload_shared_directories_detached(core: &EmulebbCore) -> Result<usize> {
    let file_paths = scan_shared_files(core).await?;
    let queued = file_paths.len();
    // Publish the pending count now so `hashingCount` is non-zero the instant the
    // request returns, before the detached worker starts draining it.
    core.shared_hashing_count
        .store(queued as i64, Ordering::Relaxed);

    let core = core.clone();
    tokio::spawn(async move {
        let _guard = HashingCountGuard(core.shared_hashing_count.clone());
        for path in file_paths {
            if let Err(error) = core
                .share_local_file(LocalShareCreate {
                    path: path.display().to_string(),
                    name: None,
                })
                .await
            {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "failed to hash/share file during background shared-directory reload (skipping)",
                );
            }
            core.shared_hashing_count.fetch_sub(1, Ordering::Relaxed);
        }
        tracing::info!("background shared-directory reload finished hashing the library");
    });

    Ok(queued)
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
