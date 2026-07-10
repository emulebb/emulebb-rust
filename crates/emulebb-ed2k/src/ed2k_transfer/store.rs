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
// WHY: request-window bitmap recovery may have to seed from the durable
// manifest after a later block arrives out of order. Persist every full eMule
// block so accepted ranges cannot be lost at that transition.
const ED2K_RESUME_CHECKPOINT_BYTES: u64 = ED2K_EMBLOCK_SIZE;

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
        let Some(manifest) = self.metadata.transfer_manifest_by_hash(file_hash)? else {
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
        self.metadata
            .upsert_transfer_manifest(&manifest_to_metadata(manifest))?;
        self.mark_manifest_persisted_unlocked(manifest).await;
        Ok(())
    }

    /// Persist the progress of the given pieces WITHOUT rewriting the
    /// manifest's child tables — the per-block download checkpoint. Only valid
    /// when piece progress (state / bytes_written / block_bitmap /
    /// ich_corrupted) is the sole dirt since the last persisted state;
    /// structural transitions (piece verified/failed, hashsets, completion,
    /// sources) must use `store_manifest_unlocked`. Falls back to the full
    /// store when a piece row is not persisted yet.
    pub(super) async fn store_manifest_piece_progress_unlocked(
        &self,
        manifest: &Ed2kResumeManifest,
        dirty_piece_indexes: &[u32],
    ) -> Result<()> {
        for piece_index in dirty_piece_indexes {
            let Some(piece) = manifest
                .pieces
                .iter()
                .find(|piece| piece.piece_index == *piece_index)
            else {
                return self.store_manifest_unlocked(manifest).await;
            };
            if !self.metadata.checkpoint_transfer_piece_progress(
                &manifest.file_hash,
                &piece_to_metadata(piece),
            )? {
                return self.store_manifest_unlocked(manifest).await;
            }
        }
        self.mark_manifest_persisted_unlocked(manifest).await;
        Ok(())
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
