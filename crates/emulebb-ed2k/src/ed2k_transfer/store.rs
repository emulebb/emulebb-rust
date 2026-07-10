//! Manifest store, cache, and checkpoint helpers for the ED2K transfer runtime.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};

use super::manifest::manifest_progress_bytes;
use super::transfer_sql::{manifest_from_metadata, manifest_to_metadata, piece_to_metadata};
use super::{
    ED2K_EMBLOCK_SIZE, Ed2kManifestCheckpointState, Ed2kResumeManifest, Ed2kTransferJob,
    Ed2kTransferRuntime, PAYLOAD_FILE_NAME,
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
    pub(super) async fn load_manifest_or_rebuild_unlocked(
        &self,
        job: &Ed2kTransferJob,
    ) -> Result<Ed2kResumeManifest> {
        if let Some(manifest) = self.load_manifest_optional_unlocked(&job.file_hash).await? {
            return Ok(manifest);
        }
        let manifest = Ed2kResumeManifest::new(job);
        self.store_manifest_unlocked(&manifest).await?;
        Ok(manifest)
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

    pub(super) async fn store_manifest_unlocked(
        &self,
        manifest: &Ed2kResumeManifest,
    ) -> Result<()> {
        let transfer_dir = self.transfer_dir(&manifest.file_hash);
        tokio::fs::create_dir_all(&transfer_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to create ED2K transfer directory {}",
                    transfer_dir.display()
                )
            })?;
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
