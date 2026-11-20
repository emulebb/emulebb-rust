//! Ordinary manifest persistence retains its exact I/O cut and preadmitted backing.
use super::manifest::manifest_progress_bytes;
use super::store::ScopedLockGuard;
use super::transfer_sql::{manifest_from_metadata, manifest_to_metadata};
use super::{Ed2kManifestCheckpointState, Ed2kResumeManifest, Ed2kTransferRuntime};
use anyhow::{Context, Result, ensure};
use emulebb_metadata::JobId;
use std::{sync::Arc, time::Instant};

impl Ed2kTransferRuntime {
    /// The caller captures its proposal under this I/O guard. The existing SQL
    /// worker retains it through publication, even after caller cancellation.
    pub(super) async fn store_manifest_unlocked(
        &self,
        manifest: &Ed2kResumeManifest,
        io: ScopedLockGuard<JobId>,
    ) -> Result<()> {
        ensure!(
            *io.key() == manifest.token.job_id,
            "manifest I/O guard belongs to another job"
        );
        let content = self.lock_content(&manifest.file_hash).await;
        let category = Arc::clone(&self.category_assignment_gate)
            .read_owned()
            .await;
        let permit = self
            .local_mutations
            .residents
            .reserve(manifest.token.job_id)?;
        let revision = self
            .manifest_checkpoint_state
            .lock()
            .await
            .get(&manifest.token)
            .map_or(0, |state| state.revision)
            .checked_add(1)
            .context("download progress revision exhausted")?;
        let row = manifest_to_metadata(manifest)?;
        let transfer_dir = self.transfer_dir(manifest.token.job_id)?;
        tokio::fs::create_dir_all(&transfer_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to create ED2K transfer directory {}",
                    transfer_dir.display()
                )
            })?;
        let metadata = self.metadata.clone();
        let cache = Arc::clone(&self.manifest_cache);
        let checkpoints = Arc::clone(&self.manifest_checkpoint_state);
        #[cfg(test)]
        let publication_gate = self.local_mutations.take_publication_gate();
        // WHY: the next writer must not capture unpublished state after its
        // predecessor's SQL commits. The worker owns I/O/content/category fences
        // and prepares reconciled resident backing while SQL can still roll back.
        // Global cache locks cover publication only, never SQLite fsync.
        tokio::task::spawn_blocking(move || -> Result<()> {
            let (_io, _content, _category) = (io, content, category);
            let current = metadata.upsert_transfer_manifest_reconciled(&row, |stored| {
                permit.publish(manifest_from_metadata(stored)?)
            })?;
            #[cfg(test)]
            if let Some((reached, release)) = publication_gate {
                let _ = reached.send(());
                let _ = release.recv();
            }
            let token = current.token;
            let progress = manifest_progress_bytes(&current);
            let mut cache = cache.blocking_lock();
            let mut checkpoints = checkpoints.blocking_lock();
            cache.insert(token.job_id, current);
            checkpoints.insert(
                token,
                Ed2kManifestCheckpointState {
                    revision,
                    persisted_bytes_written: progress,
                    last_persisted_at: Instant::now(),
                    dirty_piece_indexes: Default::default(),
                },
            );
            Ok(())
        })
        .await
        .context("ED2K manifest upsert task panicked")??;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
