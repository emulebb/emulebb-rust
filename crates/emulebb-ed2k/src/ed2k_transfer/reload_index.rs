//! Incremental shared-directory reload index for share-in-place files.
//!
//! The background shared-directory reload used to re-hash the entire shared
//! library from disk on every daemon start / `reload`, even when nothing
//! changed. These helpers let the reload skip that waste: each persisted
//! share-in-place manifest records its `source_path` plus a native file
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

    /// Build the share-in-place reload index: a map from each persisted
    /// share-in-place source path (normalized to its long-path form, the same
    /// form the directory walk produces) to all recorded identities for that
    /// path ([`Ed2kReloadIndexEntry`]: file hash and native fingerprint).
    ///
    /// The incremental shared-directory reload stats each scanned file and, when
    /// the path is present here with a safely matching fingerprint, skips re-hashing
    /// and reuses the already-persisted manifest (resolving the share by the
    /// stored hash). Only manifests that recorded a `source_path` are included
    /// (real downloads are excluded); a manifest with no fingerprint is always
    /// re-hashed.
    pub async fn share_in_place_reload_index(
        &self,
    ) -> Result<HashMap<PathBuf, Vec<Ed2kReloadIndexEntry>>> {
        let metadata = self.metadata.clone();
        let entries = tokio::task::spawn_blocking(move || metadata.share_in_place_reload_entries())
            .await
            .map_err(anyhow::Error::from)??;
        let mut index = HashMap::new();
        for entry in entries {
            let key = crate::long_path::long_path(&entry.source_path);
            index
                .entry(key)
                .or_insert_with(Vec::new)
                .push(Ed2kReloadIndexEntry {
                    file_hash: entry.file_hash,
                    source_fingerprint: entry.source_fingerprint,
                });
        }
        Ok(index)
    }

    /// Build the delivered-download reuse index: a map from each completed
    /// download's delivered file path (normalized to its long-path form, the
    /// same form the directory walk produces) to its recorded identity
    /// ([`Ed2kReloadIndexEntry`]: file hash and delivered fingerprint).
    ///
    /// A real download has no `share_in_place_sources` row, so when its delivered
    /// file lands in a configured shared dir (the standard "Incoming is shared"
    /// setup) a rescan would otherwise treat it as brand-new and re-read/re-hash
    /// the whole payload just to reshare content it already hashed during
    /// download. This index lets the reload recognize the delivered file by its
    /// exact native identity and reuse the already-persisted hash instead --
    /// the oracle `FindKnownFile(name, date, size)` cache hit
    /// (SharedFileList.cpp:2138). It is consulted for reuse ONLY: unlike the
    /// share-in-place index it never drives pruning, so a completed download
    /// whose Incoming dir is not shared is never dropped from serving.
    pub async fn delivered_reuse_index(&self) -> Result<HashMap<PathBuf, Ed2kReloadIndexEntry>> {
        let metadata = self.metadata.clone();
        let entries =
            tokio::task::spawn_blocking(move || metadata.completed_delivered_reuse_entries())
                .await
                .map_err(anyhow::Error::from)??;
        let mut index = HashMap::new();
        for entry in entries {
            let key = crate::long_path::long_path(&entry.delivered_path);
            index.insert(
                key,
                Ed2kReloadIndexEntry {
                    file_hash: entry.file_hash,
                    source_fingerprint: entry.delivered_fingerprint,
                },
            );
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
