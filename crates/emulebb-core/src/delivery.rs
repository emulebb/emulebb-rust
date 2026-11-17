//! Job-addressed completed-output delivery and bounded maintenance.
use crate::EmulebbCore;
use anyhow::{Result, ensure};
use emulebb_ed2k::ed2k_transfer::{Ed2kDeliveryOutcome, LocalMutationError};
use emulebb_metadata::{JobId, JobToken};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

const DELIVERY_JOBS_PER_PASS: usize = 4;

impl EmulebbCore {
    #[must_use]
    pub fn with_incoming_dir(mut self, incoming_dir: PathBuf) -> Self {
        self.category_incoming_dir = Arc::new(incoming_dir.clone());
        self.incoming_dir = incoming_dir;
        self
    }

    #[must_use]
    pub fn incoming_dir(&self) -> &Path {
        &self.incoming_dir
    }

    /// Resolve the current category destination before the native owner fixes
    /// an attempt. Existing attempt journals retain their own selected target.
    async fn download_delivery_destination(&self, token: JobToken) -> Result<Option<PathBuf>> {
        let _fence = self.ed2k_transfers.lock_category_publication().await;
        let Some(job) = self.ed2k_transfers.download_job(token.job_id).await? else {
            return Ok(None);
        };
        if job.token != token
            || job.removed_at_s.is_some()
            || job.completed_at_s.is_some()
            || job.storage_failure.is_some()
            || job.intent != emulebb_metadata::DownloadIntent::Started
            || !job.payload_verified
        {
            return Ok(None);
        }
        let state = self.state.lock().await;
        self.persistence_owner.check_coherent_state()?;
        let category = job
            .category_id
            .map(|id| {
                state.categories.get(&id).ok_or_else(|| {
                    anyhow::anyhow!("download category is absent from coherent Core state")
                })
            })
            .transpose()?;
        Ok(Some(
            category
                .and_then(|category| category.destination_dir.as_ref())
                .map(PathBuf::from)
                .unwrap_or_else(|| self.incoming_dir.clone()),
        ))
    }

    /// Deliver only this captured execution. Historical completion is never
    /// revisited to recreate a missing output. Native journaling owns recovery
    /// when a delivery attempt was interrupted before terminal completion.
    pub(crate) async fn deliver_completed_download(&self, token: JobToken) -> Result<bool> {
        let Some(destination) = self.download_delivery_destination(token).await? else {
            return Ok(false);
        };
        let result: Result<bool> = async {
            // Reopen only this eligible job's owned storage after restart or a
            // generation change. Terminal history never reaches this branch.
            self.ed2k_transfers
                .prepare_download_job_storage(token)
                .await?;
            match self
                .ed2k_transfers
                .materialize_completed_payload(token, &destination)
                .await?
            {
                Ed2kDeliveryOutcome::Delivered(_) | Ed2kDeliveryOutcome::AlreadyDelivered(_) => {}
                Ed2kDeliveryOutcome::NotCompleted => return Ok(false),
            }
            self.promote_delivered_download(token).await?;
            Ok(true)
        }
        .await;
        if let Err(error) = &result {
            // WHY: subsystem admission is a pending retry, not a disk fault.
            // Actual unfinished storage failures require explicit start, with
            // the exact token fencing late delivery against another execution.
            let capacity = matches!(
                error.downcast_ref::<LocalMutationError>(),
                Some(LocalMutationError::Busy | LocalMutationError::Closing)
            ) || matches!(
                error.downcast_ref::<crate::persistence_owner::PersistenceError>(),
                Some(
                    crate::persistence_owner::PersistenceError::Busy
                        | crate::persistence_owner::PersistenceError::Closing
                )
            );
            if !capacity {
                let mut message = format!("{error:#}");
                message.truncate(message.floor_char_boundary(1024));
                let fault = emulebb_metadata::DownloadJobStorageFailure::new(
                    "DELIVERY_FAILED",
                    &message,
                    chrono::Utc::now().timestamp(),
                )?;
                let outcome = self
                    .ed2k_transfers
                    .fail_download_job_storage(token, &fault)
                    .await?;
                if outcome.applied {
                    self.download_attempts.cancel_execution(token);
                }
            }
        }
        result
    }

    async fn promote_delivered_download(&self, token: JobToken) -> Result<()> {
        crate::shared_directories::sync_implicit_shared_directory_roots(self).await?;
        let (path, fingerprint) = self
            .ed2k_transfers
            .register_delivered_local_content(token)
            .await?;
        let normalized_path = crate::long_path(&path);
        let file_metadata = tokio::fs::metadata(&normalized_path).await?;
        let job = self
            .ed2k_transfers
            .download_job(token.job_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("delivered job disappeared during admission"))?;
        ensure!(job.token == token, "stale delivered job admission");
        let hash = job.file_hash.clone();
        drop(job);
        if !crate::shared_directories::load_shared_file_ignore_policy(self)?
            .should_ignore(&normalized_path, &file_metadata)
        {
            ensure!(
                crate::shared_dir_monitor::admit_delivered_path(
                    self,
                    &normalized_path,
                    &fingerprint,
                    &hash
                )
                .await?,
                "delivered output is not eligible under an Incoming or category root"
            );
        }
        if !self.ed2k_transfers.complete_download_job(token).await? {
            let current = self.ed2k_transfers.download_job(token.job_id).await?;
            ensure!(
                current.as_ref().is_some_and(|job| job.token == token
                    && job.completed_at_s.is_some()
                    && job.removed_at_s.is_none()),
                "download completion was superseded"
            );
        }
        // Retire only the selected runtime view. The durable job remains visible
        // in completed history; physical pieces retire through the native journal.
        let mut state = self.state.lock().await;
        if state
            .transfers
            .get(&hash)
            .is_some_and(|selected| selected.job_token() == token)
        {
            state.transfers.remove(&hash);
        }
        drop(state);
        self.download_attempts.changed.notify_waiters();
        self.queue_ed2k_shared_catalog_publish();
        Ok(())
    }

    /// One bounded maintenance pass, advancing even over pending failures. Its
    /// cursor/gate has no other readers and never holds global Core state over I/O.
    /// Read-result leases are dropped before delivery enters its native owner.
    pub async fn maintain_download_delivery(&self) -> Result<usize> {
        let Ok(mut cursor) = self.delivery_cursor.try_lock() else {
            return Ok(0);
        };
        let mut attempted = 0;
        for _ in 0..DELIVERY_JOBS_PER_PASS {
            let page = self
                .ed2k_transfers
                .pending_delivery_jobs_after(*cursor, 1)
                .await?;
            let id: Option<JobId> = page.first().copied();
            drop(page);
            let Some(id) = id else {
                *cursor = None;
                break;
            };
            *cursor = Some(id);
            let Some(job) = self.ed2k_transfers.download_job(id).await? else {
                continue;
            };
            let token = job.token;
            drop(job);
            attempted += 1;
            if let Err(error) = self.deliver_completed_download(token).await {
                tracing::warn!(job_id = %id, %error, "download delivery remains pending");
            }
        }
        Ok(attempted)
    }
}
