//! Manifest store, cache, and checkpoint helpers for the ED2K transfer runtime.

use std::{
    collections::HashSet,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use super::manifest::manifest_progress_bytes;
use super::transfer_sql::{manifest_from_metadata, manifest_to_metadata, piece_to_metadata};
use super::{
    ED2K_EMBLOCK_SIZE, Ed2kManifestCheckpointState, Ed2kResumeManifest, Ed2kTransferJob,
    Ed2kTransferRootReconciliation, Ed2kTransferRuntime, PAYLOAD_FILE_NAME,
};

const ED2K_RESUME_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(2);
// Batch the durable mid-piece progress checkpoint: persist once per this many
// received bytes (or on the interval above), instead of committing SQLite (a
// WAL fsync under `synchronous = FULL`) for every 180 K block. The crash-loss
// window is bounded to this many re-downloadable bytes per transfer — the
// same class of loss as eMule's ~1.5 MB in-memory write buffer that only
// flushes on threshold/part-completion — while state transitions
// (verified/failed/salvage/completion) still checkpoint immediately. The
// dirty pieces accumulated between checkpoints are tracked in
// `Ed2kManifestCheckpointState::dirty_piece_indexes`, so a batched checkpoint
// persists every piece touched since the last durable store.
const ED2K_RESUME_CHECKPOINT_BYTES: u64 = 8 * ED2K_EMBLOCK_SIZE;

impl Ed2kTransferRuntime {
    /// Acquire the lifecycle gate for one transfer. Delivery, row-only
    /// removal, and destructive deletion must hold this gate before taking the
    /// manifest lock so their filesystem and persisted-state transitions
    /// cannot interleave.
    pub(super) async fn lock_lifecycle(&self, file_hash: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.lifecycle_locks.lock().unwrap();
            Arc::clone(locks.entry(file_hash.to_ascii_lowercase()).or_default())
        };
        lock.lock_owned().await
    }

    /// Acquire the manifest IO lock for one transfer. Manifest state (cache,
    /// checkpoint bookkeeping, payload handle, SQL rows) is always keyed by a
    /// single file hash, so the lock is per hash: concurrent transfers no
    /// longer serialize each other's block appends. The lock-map mutex is
    /// held only for the entry lookup, never across the await; entries are
    /// never removed (a removed entry could hand out a second lock for the
    /// same hash while an old guard is still alive).
    pub(super) async fn lock_manifest(&self, file_hash: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.manifest_locks.lock().unwrap();
            Arc::clone(locks.entry(file_hash.to_ascii_lowercase()).or_default())
        };
        lock.lock_owned().await
    }

    pub(super) async fn load_manifest_or_rebuild_unlocked(
        &self,
        job: &Ed2kTransferJob,
    ) -> Result<Ed2kResumeManifest> {
        if let Some(manifest) = self.load_manifest_optional_unlocked(&job.file_hash).await? {
            return Ok(manifest);
        }
        self.prepare_new_download_directory(&job.file_hash).await?;
        let mut manifest = Ed2kResumeManifest::new(job);
        manifest.follow_majority_filename = self.file_name_policy.follow_majority_for_new_downloads;
        self.store_manifest_unlocked(&manifest).await?;
        Ok(manifest)
    }

    /// Remove only the empty directory that can remain when startup crashes
    /// after directory creation but before the first manifest commit, or one
    /// containing only the retired pre-SQL `resume-manifest.json` artifact.
    /// Any other non-empty directory, regular file, or symlink has no provable
    /// ownership without metadata and must never be adopted by a new download.
    pub(super) async fn prepare_new_download_directory(&self, file_hash: &str) -> Result<()> {
        let transfer_dir = self.transfer_dir(file_hash);
        let metadata = match tokio::fs::symlink_metadata(&transfer_dir).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect unmanaged ED2K transfer path {}",
                        transfer_dir.display()
                    )
                });
            }
        };
        anyhow::ensure!(
            metadata.file_type().is_dir(),
            "refusing to create ED2K transfer {file_hash}: unmanaged path {} is not a directory",
            transfer_dir.display()
        );
        let mut entries = tokio::fs::read_dir(&transfer_dir).await.with_context(|| {
            format!(
                "failed to inspect unmanaged ED2K transfer directory {}",
                transfer_dir.display()
            )
        })?;
        let first_entry = entries.next_entry().await?;
        let second_entry = entries.next_entry().await?;
        if let Some(entry) = first_entry {
            let is_retired_manifest = second_entry.is_none()
                && entry.file_name() == std::ffi::OsStr::new("resume-manifest.json")
                && entry.file_type().await?.is_file();
            anyhow::ensure!(
                is_retired_manifest,
                "refusing to create ED2K transfer {file_hash}: unmanaged directory {} is not empty",
                transfer_dir.display()
            );
            tokio::fs::remove_file(entry.path())
                .await
                .with_context(|| {
                    format!(
                        "failed to remove retired ED2K resume manifest from {}",
                        transfer_dir.display()
                    )
                })?;
        }
        tokio::fs::remove_dir(&transfer_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to reclaim empty unmanaged ED2K transfer directory {}",
                    transfer_dir.display()
                )
            })?;
        Ok(())
    }

    /// Reconcile canonical hash paths which have no owning download row.
    /// Safe crash residue is reclaimed; every path containing unknown bytes is
    /// preserved and reported for operator repair.
    pub async fn reconcile_transfer_root(&self) -> Result<Ed2kTransferRootReconciliation> {
        let metadata = self.metadata.clone();
        let managed_hashes =
            tokio::task::spawn_blocking(move || metadata.managed_download_transfer_hashes())
                .await
                .context("ED2K managed transfer path scan task panicked")??
                .into_iter()
                .collect::<HashSet<_>>();

        let mut candidates = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.root_dir).await.with_context(|| {
            format!(
                "failed to inventory ED2K transfer root {}",
                self.root_dir.display()
            )
        })?;
        while let Some(entry) = entries.next_entry().await? {
            let Ok(file_name) = entry.file_name().into_string() else {
                continue;
            };
            let Ok(parsed_hash) = file_name.parse::<Ed2kHash>() else {
                continue;
            };
            if parsed_hash.to_string() == file_name && !managed_hashes.contains(&file_name) {
                candidates.push(file_name);
            }
        }
        candidates.sort_unstable();

        let mut reconciliation = Ed2kTransferRootReconciliation::default();
        for file_hash in candidates {
            let _lifecycle_guard = self.lock_lifecycle(&file_hash).await;
            let _manifest_guard = self.lock_manifest(&file_hash).await;
            let metadata = self.metadata.clone();
            let owned_hash = file_hash.clone();
            let is_managed = tokio::task::spawn_blocking(move || {
                metadata.managed_download_transfer_exists(&owned_hash)
            })
            .await
            .context("ED2K managed transfer path recheck task panicked")??;
            if is_managed {
                continue;
            }
            match self.prepare_new_download_directory(&file_hash).await {
                Ok(()) => {
                    reconciliation.reclaimed_paths =
                        reconciliation.reclaimed_paths.saturating_add(1);
                }
                Err(error) => {
                    reconciliation.preserved_collisions =
                        reconciliation.preserved_collisions.saturating_add(1);
                    tracing::warn!(
                        %error,
                        file_hash,
                        path = %self.transfer_dir(&file_hash).display(),
                        "preserving unmanaged ED2K transfer path discovered during startup"
                    );
                }
            }
        }
        Ok(reconciliation)
    }

    pub(super) async fn load_manifest_optional_unlocked(
        &self,
        file_hash: &str,
    ) -> Result<Option<Ed2kResumeManifest>> {
        if let Some(manifest) = self.manifest_cache.lock().await.get(file_hash).cloned() {
            return Ok(Some(manifest));
        }
        // Cache miss: the SQL read (global connection mutex + row mapping)
        // runs on the blocking pool so it cannot stall the async runtime.
        let metadata = self.metadata.clone();
        let owned_hash = file_hash.to_string();
        let row =
            tokio::task::spawn_blocking(move || metadata.transfer_manifest_by_hash(&owned_hash))
                .await
                .context("ED2K manifest load task panicked")??;
        let Some(manifest) = row else {
            return Ok(None);
        };
        let manifest = manifest_from_metadata(manifest)?;
        self.mark_manifest_persisted_unlocked(&manifest).await;
        Ok(Some(manifest))
    }

    pub(super) async fn load_manifest_unlocked(
        &self,
        file_hash: &str,
    ) -> Result<Ed2kResumeManifest> {
        self.load_manifest_optional_unlocked(file_hash)
            .await?
            .with_context(|| format!("missing ED2K transfer metadata for {file_hash}"))
    }

    /// Run a read-only probe against the manifest WITHOUT cloning it on the
    /// (hot) cache-hit path; only a cache miss pays the full load. For
    /// per-block predicates like the salvage-mode check.
    pub(super) async fn probe_manifest_unlocked<R>(
        &self,
        file_hash: &str,
        probe: impl FnOnce(&Ed2kResumeManifest) -> R,
    ) -> Result<R> {
        {
            let cache = self.manifest_cache.lock().await;
            if let Some(manifest) = cache.get(file_hash) {
                return Ok(probe(manifest));
            }
        }
        let manifest = self.load_manifest_unlocked(file_hash).await?;
        Ok(probe(&manifest))
    }

    pub(super) async fn store_manifest_unlocked(
        &self,
        manifest: &Ed2kResumeManifest,
    ) -> Result<()> {
        // Share-in-place manifests live entirely in SQLite and serve bytes from
        // `source_path`. Creating an empty hash directory for each such file
        // turns a 100k-file library into 100k unnecessary MFT/inode writes.
        // Downloads still need their directory for `pieces.bin`.
        if manifest.source_path.is_none() {
            let transfer_dir = self.transfer_dir(&manifest.file_hash);
            tokio::fs::create_dir_all(&transfer_dir)
                .await
                .with_context(|| {
                    format!(
                        "failed to create ED2K transfer directory {}",
                        transfer_dir.display()
                    )
                })?;
        }
        // The upsert commits a SQLite transaction (a WAL fsync under
        // `synchronous = FULL`): run it on the blocking pool so the fsync
        // never parks an async worker thread.
        let metadata = self.metadata.clone();
        let row = manifest_to_metadata(manifest);
        tokio::task::spawn_blocking(move || metadata.upsert_transfer_manifest(&row))
            .await
            .context("ED2K manifest upsert task panicked")??;
        self.mark_manifest_persisted_unlocked(manifest).await;
        Ok(())
    }

    /// Persist mid-piece progress WITHOUT rewriting the manifest's child
    /// tables — the batched download checkpoint. Persists `current_piece`
    /// plus every piece dirtied by cache-only appends since the last durable
    /// store (multiple sessions of one file dirty different pieces between
    /// batched checkpoints). Only valid when piece progress (state /
    /// bytes_written / block_bitmap / ich_corrupted) is the sole dirt since
    /// the last persisted state; structural transitions (piece
    /// verified/failed, hashsets, completion, sources) must use
    /// `store_manifest_unlocked`. Falls back to the full store when a piece
    /// row is not persisted yet.
    pub(super) async fn store_manifest_piece_progress_unlocked(
        &self,
        manifest: &Ed2kResumeManifest,
        current_piece: u32,
    ) -> Result<()> {
        // Snapshot (not take) the dirty set: it is only cleared by
        // `mark_manifest_persisted_unlocked` after every row landed, so a
        // failed persist keeps the pieces tracked for the next checkpoint.
        let mut dirty_piece_indexes: std::collections::BTreeSet<u32> = self
            .manifest_checkpoint_state
            .lock()
            .await
            .get(&manifest.file_hash)
            .map(|state| state.dirty_piece_indexes.clone())
            .unwrap_or_default();
        dirty_piece_indexes.insert(current_piece);
        let mut rows = Vec::with_capacity(dirty_piece_indexes.len());
        for piece_index in dirty_piece_indexes {
            let Some(piece) = manifest
                .pieces
                .iter()
                .find(|piece| piece.piece_index == piece_index)
            else {
                return self.store_manifest_unlocked(manifest).await;
            };
            rows.push(piece_to_metadata(piece));
        }
        // One blocking-pool hop persists every dirty row (each UPDATE commits
        // a WAL fsync under `synchronous = FULL`), keeping the fsyncs off the
        // async worker threads.
        let metadata = self.metadata.clone();
        let owned_hash = manifest.file_hash.clone();
        let all_rows_updated = tokio::task::spawn_blocking(move || -> Result<bool> {
            for row in &rows {
                if !metadata.checkpoint_transfer_piece_progress(&owned_hash, row)? {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .await
        .context("ED2K piece checkpoint task panicked")??;
        if !all_rows_updated {
            return self.store_manifest_unlocked(manifest).await;
        }
        self.mark_manifest_persisted_unlocked(manifest).await;
        Ok(())
    }

    /// Record a cache-only progress append so the next batched checkpoint
    /// persists this piece's row even if the checkpoint is triggered by a
    /// block landing in a different piece.
    pub(super) async fn note_dirty_piece_unlocked(
        &self,
        manifest: &Ed2kResumeManifest,
        piece_index: u32,
    ) {
        let current_progress = manifest_progress_bytes(manifest);
        let mut states = self.manifest_checkpoint_state.lock().await;
        states
            .entry(manifest.file_hash.clone())
            .or_insert_with(|| Ed2kManifestCheckpointState {
                persisted_bytes_written: current_progress,
                last_persisted_at: Instant::now(),
                dirty_piece_indexes: std::collections::BTreeSet::new(),
            })
            .dirty_piece_indexes
            .insert(piece_index);
    }

    pub(super) async fn cache_manifest_unlocked(&self, manifest: &Ed2kResumeManifest) {
        self.manifest_cache
            .lock()
            .await
            .insert(manifest.file_hash.clone(), manifest.clone());
    }

    pub(super) async fn mark_manifest_persisted_unlocked(&self, manifest: &Ed2kResumeManifest) {
        self.cache_manifest_unlocked(manifest).await;
        self.manifest_checkpoint_state.lock().await.insert(
            manifest.file_hash.clone(),
            Ed2kManifestCheckpointState {
                persisted_bytes_written: manifest_progress_bytes(manifest),
                last_persisted_at: Instant::now(),
                dirty_piece_indexes: std::collections::BTreeSet::new(),
            },
        );
    }

    pub(super) async fn should_checkpoint_manifest_unlocked(
        &self,
        manifest: &Ed2kResumeManifest,
    ) -> bool {
        let current_progress = manifest_progress_bytes(manifest);
        let mut states = self.manifest_checkpoint_state.lock().await;
        let state = states.entry(manifest.file_hash.clone()).or_insert_with(|| {
            Ed2kManifestCheckpointState {
                persisted_bytes_written: current_progress,
                last_persisted_at: Instant::now(),
                dirty_piece_indexes: std::collections::BTreeSet::new(),
            }
        });
        let dirty_bytes = current_progress.saturating_sub(state.persisted_bytes_written);
        dirty_bytes >= ED2K_RESUME_CHECKPOINT_BYTES
            || (dirty_bytes != 0
                && state.last_persisted_at.elapsed() >= ED2K_RESUME_CHECKPOINT_INTERVAL)
    }

    pub(super) fn transfer_dir(&self, file_hash: &str) -> PathBuf {
        self.root_dir.join(file_hash)
    }

    /// Return the managed transfer directory for one ED2K transfer hash.
    #[must_use]
    pub fn transfer_dir_path(&self, file_hash: &str) -> PathBuf {
        self.transfer_dir(file_hash)
    }

    /// Return the managed payload path for one ED2K transfer hash.
    #[must_use]
    pub fn payload_path(&self, file_hash: &str) -> PathBuf {
        self.transfer_dir(file_hash).join(PAYLOAD_FILE_NAME)
    }
}
