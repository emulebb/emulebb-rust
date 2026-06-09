//! Manifest store, cache, and checkpoint helpers for the ED2K transfer runtime.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};

use super::manifest::{manifest_progress_bytes, quarantine_corrupt_manifest};
use super::{
    ED2K_EMBLOCK_SIZE, Ed2kManifestCheckpointState, Ed2kResumeManifest, Ed2kTransferJob,
    Ed2kTransferRuntime, MANIFEST_FILE_NAME,
};

const ED2K_RESUME_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(2);
const ED2K_RESUME_CHECKPOINT_BYTES: u64 = ED2K_EMBLOCK_SIZE * 16;

impl Ed2kTransferRuntime {
    pub(super) async fn load_manifest_or_rebuild_unlocked(
        &self,
        job: &Ed2kTransferJob,
    ) -> Result<Ed2kResumeManifest> {
        match self.load_manifest_unlocked(&job.file_hash).await {
            Ok(manifest) => Ok(manifest),
            Err(error) => {
                let manifest_path = self.transfer_dir(&job.file_hash).join(MANIFEST_FILE_NAME);
                quarantine_corrupt_manifest(&manifest_path).await?;
                let manifest = Ed2kResumeManifest::new(job);
                self.store_manifest_unlocked(&manifest).await?;
                tracing::warn!(
                    "rebuilt ED2K manifest after corrupt state for {}: {error}",
                    job.file_hash
                );
                Ok(manifest)
            }
        }
    }

    pub(super) async fn load_manifest_unlocked(
        &self,
        file_hash: &str,
    ) -> Result<Ed2kResumeManifest> {
        if let Some(manifest) = self.manifest_cache.lock().await.get(file_hash).cloned() {
            return Ok(manifest);
        }
        let path = self.transfer_dir(file_hash).join(MANIFEST_FILE_NAME);
        let bytes = tokio::fs::read(&path)
            .await
            .with_context(|| format!("failed to read ED2K manifest {}", path.display()))?;
        let manifest = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to decode ED2K manifest {}", path.display()))?;
        self.mark_manifest_persisted_unlocked(&manifest).await;
        Ok(manifest)
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
        let path = transfer_dir.join(MANIFEST_FILE_NAME);
        let encoded = serde_json::to_vec_pretty(manifest)?;
        tokio::fs::write(&path, encoded)
            .await
            .with_context(|| format!("failed to write ED2K manifest {}", path.display()))?;
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
}
