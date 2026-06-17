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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

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
