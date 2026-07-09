//! Incremental shared-directory reload index for share-in-place files.
//!
//! The background shared-directory reload used to re-hash the entire shared
//! library from disk on every daemon start / `reload`, even when nothing
//! changed. These helpers let the reload skip that waste: each persisted
//! share-in-place manifest records its `source_path` plus the `(file_size,
//! source_mtime_ms)` captured at ingest, so a scanned file whose on-disk identity
//! matches its persisted entry is reused as-is instead of being re-read/re-hashed.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;

use super::{Ed2kReloadIndexEntry, Ed2kTransferRuntime};

impl Ed2kTransferRuntime {
    /// Build the share-in-place reload index: a map from each persisted
    /// share-in-place source path (normalized to its long-path form, the same
    /// form the directory walk produces) to all recorded identities for that
    /// path ([`Ed2kReloadIndexEntry`]: file hash, size, and source mtime).
    ///
    /// The incremental shared-directory reload stats each scanned file and, when
    /// the path is present here with a matching size and mtime, skips re-hashing
    /// and reuses the already-persisted manifest (resolving the share by the
    /// stored hash). Only manifests that recorded a `source_path` are included
    /// (real downloads are excluded); a manifest whose `source_mtime_ms` is `None`
    /// (pre-v9 row) still appears but will not match an on-disk mtime, so such a
    /// file is re-hashed once and its mtime recorded.
    pub async fn share_in_place_reload_index(
        &self,
    ) -> Result<HashMap<String, Vec<Ed2kReloadIndexEntry>>> {
        let metadata = self.metadata.clone();
        let entries = tokio::task::spawn_blocking(move || metadata.share_in_place_reload_entries())
            .await
            .map_err(anyhow::Error::from)??;
        let mut index = HashMap::new();
        for entry in entries {
            let key = crate::long_path::long_path(Path::new(&entry.source_path))
                .display()
                .to_string();
            index
                .entry(key)
                .or_insert_with(Vec::new)
                .push(Ed2kReloadIndexEntry {
                    file_hash: entry.file_hash,
                    file_size: entry.file_size,
                    source_mtime_ms: entry.source_mtime_ms,
                });
        }
        Ok(index)
    }

    /// Build the delivered-download reuse index: a map from each completed
    /// download's delivered file path (normalized to its long-path form, the
    /// same form the directory walk produces) to its recorded identity
    /// ([`Ed2kReloadIndexEntry`]: file hash, size, delivered mtime).
    ///
    /// A real download has no `share_in_place_sources` row, so when its delivered
    /// file lands in a configured shared dir (the standard "Incoming is shared"
    /// setup) a rescan would otherwise treat it as brand-new and re-read/re-hash
    /// the whole payload just to reshare content it already hashed during
    /// download. This index lets the reload recognize the delivered file by its
    /// `(size, mtime)` identity and reuse the already-persisted hash instead --
    /// the oracle `FindKnownFile(name, date, size)` cache hit
    /// (SharedFileList.cpp:2138). It is consulted for reuse ONLY: unlike the
    /// share-in-place index it never drives pruning, so a completed download
    /// whose Incoming dir is not shared is never dropped from serving.
    pub async fn delivered_reuse_index(
        &self,
    ) -> Result<HashMap<String, Ed2kReloadIndexEntry>> {
        let metadata = self.metadata.clone();
        let entries =
            tokio::task::spawn_blocking(move || metadata.completed_delivered_reuse_entries())
                .await
                .map_err(anyhow::Error::from)??;
        let mut index = HashMap::new();
        for entry in entries {
            let key = crate::long_path::long_path(Path::new(&entry.delivered_path))
                .display()
                .to_string();
            index.insert(
                key,
                Ed2kReloadIndexEntry {
                    file_hash: entry.file_hash,
                    file_size: entry.file_size,
                    source_mtime_ms: entry.delivered_mtime_ms,
                },
            );
        }
        Ok(index)
    }

    /// Stat one scanned shared file for the incremental reload, returning its
    /// long-path-normalized key plus on-disk `(file_size, mtime_ms)`. The key is
    /// produced with the same `long_path` normalization as
    /// [`Ed2kTransferRuntime::share_in_place_reload_index`], so a hit there means
    /// the file is unchanged and can skip re-hashing. Returns `None` when the
    /// file cannot be stat-ed (treated as changed, so it is (re)hashed).
    #[must_use]
    pub fn scanned_source_identity(source_path: &Path) -> Option<(String, u64, Option<i64>)> {
        let normalized = crate::long_path::long_path(source_path);
        let (size, mtime_ms) = super::ingest::stat_source_identity(&normalized)?;
        Some((normalized.display().to_string(), size, mtime_ms))
    }
}
