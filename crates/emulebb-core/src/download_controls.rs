//! Durable job-ID controls; execution is selected separately by the bounded scheduler.
use crate::{EmulebbCore, core_state::CoreState, download_attempts::DownloadAttemptControl};
use anyhow::{Context, Result, ensure};
use emulebb_ed2k::ed2k_transfer::{Ed2kTransferRuntime, LocalMutationError};
use emulebb_metadata::{DownloadIntent, JobId};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadChange {
    Changed,
    Unchanged,
    NotFound,
}

/// Explicit execution controls. Verification has a separate native lifecycle.
#[derive(Debug, Clone, Copy)]
pub enum DownloadAction {
    Start,
    Stop,
    Remove { delete_data: bool },
}

/// Stable domain failures; transport owners choose their status and envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadControlError {
    Completed,
    Unavailable,
    Failed,
}
impl std::fmt::Display for DownloadControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Completed => "a completed job cannot be started again",
            Self::Unavailable => "download control is temporarily unavailable",
            Self::Failed => "download control failed",
        })
    }
}
impl std::error::Error for DownloadControlError {}

#[derive(Debug)]
pub struct DownloadControlResult {
    pub id: JobId,
    pub outcome: std::result::Result<DownloadChange, DownloadControlError>,
}

/// Request-order results retain their backing charge until the caller drops
/// them, independently of the owner's request slot.
pub struct DownloadControlBatch {
    pub(crate) results: Vec<DownloadControlResult>,
    pub(crate) _lease: crate::persistence_owner::ByteLease,
}

impl DownloadControlBatch {
    pub fn results(&self) -> &[DownloadControlResult] {
        &self.results
    }
}

/// Only the resources needed after admission; never retain a Core/owner cycle.
pub(crate) struct DownloadControlContext {
    pub runtime: Arc<Ed2kTransferRuntime>,
    pub attempts: Arc<DownloadAttemptControl>,
    pub state: Arc<Mutex<CoreState>>,
    pub category_gate: Arc<Mutex<()>>,
    pub transfer_root: PathBuf,
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
        self.control_download(id, DownloadAction::Start).await
    }

    /// Stop preserves all resumable data and finishes cancellation even when
    /// its caller disappears after admission.
    pub async fn stop_download(&self, id: JobId) -> Result<DownloadChange> {
        self.control_download(id, DownloadAction::Stop).await
    }

    /// Physical retirement remains owned by the automatic cleanup journal.
    pub async fn remove_download(&self, id: JobId, delete_data: bool) -> Result<DownloadChange> {
        self.control_download(id, DownloadAction::Remove { delete_data })
            .await
    }

    async fn control_download(&self, id: JobId, action: DownloadAction) -> Result<DownloadChange> {
        let batch = self.control_downloads(action, &[id]).await?;
        Ok(batch.results[0].outcome?)
    }

    /// Admit one bounded batch before changing any job. The persistence owner
    /// completes every item after admission, including after caller abort.
    pub async fn control_downloads(
        &self,
        action: DownloadAction,
        ids: &[JobId],
    ) -> Result<DownloadControlBatch> {
        ensure!(
            (1..=100).contains(&ids.len()),
            "expected 1 to 100 download IDs"
        );
        ensure!(
            ids.iter()
                .enumerate()
                .all(|(index, id)| !ids[..index].contains(id)),
            "download IDs must be distinct"
        );
        self.persistence_owner.check_coherent_state()?;
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        Ok(owner
            .downloads(action, ids, &self.transfer_root, || {
                DownloadControlContext {
                    runtime: Arc::clone(&self.ed2k_transfers),
                    attempts: Arc::clone(&self.download_attempts),
                    state: Arc::clone(&self.state),
                    category_gate: Arc::clone(&self.category_mutation_gate),
                    transfer_root: self.transfer_root.clone(),
                }
            })
            .await?)
    }
}

impl DownloadControlContext {
    pub(crate) async fn apply(&self, action: DownloadAction, id: JobId) -> DownloadControlResult {
        let result = match action {
            DownloadAction::Start => self.start(id).await,
            DownloadAction::Stop => self.stop(id).await,
            DownloadAction::Remove { delete_data } => self.remove(id, delete_data).await,
        };
        let outcome = result.map_err(|error| {
            let kind = if let Some(error) = error.downcast_ref::<DownloadControlError>() {
                *error
            } else if matches!(
                error.downcast_ref::<LocalMutationError>(),
                Some(LocalMutationError::Busy | LocalMutationError::Closing)
            ) {
                DownloadControlError::Unavailable
            } else {
                DownloadControlError::Failed
            };
            tracing::warn!(job_id = %id, %error, "download control item failed");
            kind
        });
        DownloadControlResult { id, outcome }
    }

    async fn start(&self, id: JobId) -> Result<DownloadChange> {
        let _category_guard = self.category_gate.lock().await;
        let Some(job) = self.runtime.download_job(id).await? else {
            return Ok(DownloadChange::NotFound);
        };
        if job.removed_at_s.is_some() {
            return Ok(DownloadChange::NotFound);
        }
        if job.completed_at_s.is_some() {
            return Err(DownloadControlError::Completed.into());
        }
        let token = job.token;
        let temp = match &job.selected_temp {
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
        };
        drop(job);
        let started = self.runtime.start_download_job(token, &temp).await?;
        let Some(started) = started.as_ref() else {
            return Ok(DownloadChange::NotFound);
        };
        let changed = started.token != token;
        if changed {
            self.attempts.changed.notify_one();
        }
        Ok(if changed {
            DownloadChange::Changed
        } else {
            DownloadChange::Unchanged
        })
    }

    async fn stop(&self, id: JobId) -> Result<DownloadChange> {
        let Some(job) = self.runtime.download_job(id).await? else {
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
        let changed = self.runtime.stop_download_job(token).await?;
        if changed {
            // WHY: cancel only through the captured cut; a later execution
            // selected during native retirement must never be canceled here.
            self.attempts.cancel_through(token);
        }
        Ok(if changed {
            DownloadChange::Changed
        } else {
            DownloadChange::Unchanged
        })
    }

    async fn remove(&self, id: JobId, delete_data: bool) -> Result<DownloadChange> {
        let Some(job) = self.runtime.download_job(id).await? else {
            return Ok(DownloadChange::NotFound);
        };
        if job.removed_at_s.is_some() {
            return Ok(DownloadChange::NotFound);
        }
        drop(job);
        let changed = self.runtime.remove_download_job(id, delete_data).await?;
        if changed {
            self.attempts.cancel(id);
        }
        Ok(if changed {
            DownloadChange::Changed
        } else {
            DownloadChange::Unchanged
        })
    }
}
