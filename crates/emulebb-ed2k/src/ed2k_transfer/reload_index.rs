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
use emulebb_metadata::{MetadataImportedKnownFileEntry, NativeFileFingerprint};

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

    /// Return pathless stock ``known.met`` rows whose exact stock identity
    /// matches one scanned file: file name, byte size, and whole-second mtime.
    pub async fn imported_known_file_identity_matches(
        &self,
        display_name: String,
        file_size: u64,
        modified_s: i64,
    ) -> Result<Vec<MetadataImportedKnownFileEntry>> {
        let metadata = self.metadata.clone();
        tokio::task::spawn_blocking(move || {
            metadata.imported_known_file_identity_matches(&display_name, file_size, modified_s)
        })
        .await
        .map_err(anyhow::Error::from)?
    }

    /// Build a pathless stock ``known.met`` lookup keyed by exact
    /// `(file_name, file_size, modified_s)`. The caller must only trust a key
    /// when it maps to exactly one row.
    pub async fn imported_known_file_identity_index(
        &self,
    ) -> Result<HashMap<(String, u64, i64), Vec<MetadataImportedKnownFileEntry>>> {
        let metadata = self.metadata.clone();
        let entries = tokio::task::spawn_blocking(move || metadata.imported_known_file_entries())
            .await
            .map_err(anyhow::Error::from)??;
        let mut index = HashMap::new();
        for entry in entries {
            index
                .entry((
                    entry.display_name.clone(),
                    entry.file_size,
                    entry.modified_s,
                ))
                .or_insert_with(Vec::new)
                .push(entry);
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
