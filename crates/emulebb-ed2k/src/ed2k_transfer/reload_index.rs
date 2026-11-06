//! Incremental shared-directory reload index for verified local files.
//!
//! The background shared-directory reload used to re-hash the entire shared
//! library from disk on every daemon start / `reload`, even when nothing
//! changed. These helpers let the reload skip that waste: each persisted
//! local file instance records its path plus a native file
//! fingerprint captured at ingest, so a scanned file whose exact identity still
//! matches its persisted entry is reused as-is instead of being re-read/re-hashed.

use std::collections::HashMap;
use std::fs::Metadata;
use std::path::{Path, PathBuf};

use anyhow::Result;
use emulebb_metadata::NativeFileFingerprint;

use super::{Ed2kReloadIndexEntry, Ed2kTransferRuntime};

impl Ed2kTransferRuntime {
    /// Build the normalized incremental-reload identity from metadata already
    /// fetched by a directory walk. Reusing that metadata avoids a second
    /// filesystem lookup for every file in large shared libraries.
    #[must_use]
    pub fn scanned_source_identity_from_metadata(
        source_path: &Path,
        metadata: &Metadata,
    ) -> (PathBuf, u64, Option<NativeFileFingerprint>) {
        let normalized = crate::long_path::long_path(source_path);
        (
            normalized.clone(),
            metadata.len(),
            super::ingest::native_file_fingerprint(&normalized),
        )
    }

    /// Build the verified local path index used by incremental root scans.
    pub async fn verified_local_reload_index(
        &self,
    ) -> Result<HashMap<PathBuf, Vec<Ed2kReloadIndexEntry>>> {
        let metadata = self.metadata.clone();
        let entries = tokio::task::spawn_blocking(move || metadata.verified_local_file_instances())
            .await
            .map_err(anyhow::Error::from)??;
        let mut index = HashMap::new();
        for entry in entries {
            let key = crate::long_path::long_path(&entry.path);
            index
                .entry(key)
                .or_insert_with(Vec::new)
                .push(Ed2kReloadIndexEntry {
                    file_hash: entry.file_hash,
                    source_fingerprint: Some(entry.verified_fingerprint),
                });
        }
        Ok(index)
    }

    /// Stat one scanned shared file for the incremental reload, returning its
    /// long-path-normalized key plus its on-disk native fingerprint. The key is
    /// produced with the same `long_path` normalization as
    /// [`Ed2kTransferRuntime::share_in_place_reload_index`], so a hit there means
    /// the file is unchanged and can skip re-hashing. Returns `None` when the
    /// file cannot be stat-ed (treated as changed, so it is (re)hashed).
    #[must_use]
    pub fn scanned_source_identity(
        source_path: &Path,
    ) -> Option<(PathBuf, u64, Option<NativeFileFingerprint>)> {
        let normalized = crate::long_path::long_path(source_path);
        let metadata = std::fs::metadata(&normalized).ok()?;
        let size = metadata.len();
        let fingerprint = super::ingest::native_file_fingerprint(&normalized);
        Some((normalized, size, fingerprint))
    }
}
