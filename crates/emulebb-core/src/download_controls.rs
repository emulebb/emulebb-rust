//! Durable job-ID controls; execution is selected separately by the bounded scheduler.
use crate::EmulebbCore;
use anyhow::{Context, Result, ensure};
use emulebb_metadata::{DownloadIntent, JobId};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadChange {
    Changed,
    Unchanged,
    NotFound,
}

impl EmulebbCore {
    pub(crate) async fn download_temp_selection(
        &self,
        job: &emulebb_metadata::DownloadJobRecord,
    ) -> Result<PathBuf> {
        Ok(match &job.selected_temp {
            Some(path) => path.clone(),
            None => {
                let state = self.state.lock().await;
                job.category_id
                    .map(|id| state.categories.get(&id).context("missing job category"))
                    .transpose()?
                    .and_then(|category| category.temp_dir.as_ref())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.transfer_root.clone())
            }
        })
    }

    /// An explicit start retries a storage failure and preserves fixed storage.
    /// It does not allocate a per-queued-job worker or a piece map.
    pub async fn start_download(&self, id: JobId) -> Result<DownloadChange> {
        let _category_guard = self.category_mutation_gate.lock().await;
        self.persistence_owner.check_coherent_state()?;
        let Some(job) = self.ed2k_transfers.download_job(id).await? else {
            return Ok(DownloadChange::NotFound);
        };
        if job.removed_at_s.is_some() {
            return Ok(DownloadChange::NotFound);
        }
        ensure!(
            job.completed_at_s.is_none(),
            "a completed job cannot be started again"
        );
        let token = job.token;
        let temp = self.download_temp_selection(&job).await?;
        drop(job);
        let started = self.ed2k_transfers.start_download_job(token, &temp).await?;
        let Some(started) = started.as_ref() else {
            return Ok(DownloadChange::NotFound);
        };
        let changed = started.token != token;
        if changed {
            self.download_attempts.changed.notify_one();
        }
        Ok(if changed {
            DownloadChange::Changed
        } else {
            DownloadChange::Unchanged
        })
    }

    /// Stop preserves all resumable data. An old stop result may cancel only
    /// executions through its captured cut, never a later admitted start.
    pub async fn stop_download(&self, id: JobId) -> Result<DownloadChange> {
        let Some(job) = self.ed2k_transfers.download_job(id).await? else {
            return Ok(DownloadChange::NotFound);
        };
        if job.removed_at_s.is_some() {
            return Ok(DownloadChange::NotFound);
        }
        if job.completed_at_s.is_some() || job.intent == DownloadIntent::Stopped {
            return Ok(DownloadChange::Unchanged);
        }
        let token = job.token;
        drop(job);
        let changed = self.ed2k_transfers.stop_download_job(token).await?;
        if changed {
            self.download_attempts.cancel_through(token);
        }
        Ok(if changed {
            DownloadChange::Changed
        } else {
            DownloadChange::Unchanged
        })
    }

    /// Logical removal is durable before execution cancellation. Actual
    /// physical cleanup remains owned by the automatic cleanup journal.
    pub async fn remove_download(&self, id: JobId, delete_data: bool) -> Result<DownloadChange> {
        let Some(job) = self.ed2k_transfers.download_job(id).await? else {
            return Ok(DownloadChange::NotFound);
        };
        if job.removed_at_s.is_some() {
            return Ok(DownloadChange::NotFound);
        }
        drop(job);
        let changed = self
            .ed2k_transfers
            .remove_download_job(id, delete_data)
            .await?;
        if changed {
            self.download_attempts.cancel(id);
        }
        Ok(if changed {
            DownloadChange::Changed
        } else {
            DownloadChange::Unchanged
        })
    }
}
