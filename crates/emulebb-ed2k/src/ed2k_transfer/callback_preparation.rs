//! Bounded, linear Core decisions for listener-owned callback preparation.
use super::{Ed2kCallbackDownload, Ed2kTransferRuntime};
use crate::ed2k_tcp::{Ed2kPeerAvailability, Ed2kPeerDownloadOutcome};
use anyhow::{Context, Result, ensure};
use emulebb_metadata::JobToken;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed2kCallbackPreparationId(u64);

#[derive(Debug)]
pub enum Ed2kCallbackPreparationOutcome {
    Available(Ed2kPeerAvailability),
    FileNotFound,
    Incomplete,
    Deferred,
}

enum Admission {
    Start(JobToken),
    Skip,
}

struct Pending {
    id: Ed2kCallbackPreparationId,
    token: JobToken,
    hash: emulebb_kad_proto::Ed2kHash,
    size: u64,
    deadline: tokio::time::Instant,
    cancel: CancellationToken,
    available: Option<oneshot::Sender<Ed2kCallbackPreparationOutcome>>,
    admission: oneshot::Receiver<Admission>,
    completion: Option<oneshot::Sender<Result<Ed2kPeerDownloadOutcome>>>,
    capacity: Option<OwnedSemaphorePermit>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        // WHY: closing an unclaimed completion channel wakes Core. Release the
        // real slot first, so that receipt cannot race stale capacity usage.
        drop(self.capacity.take());
    }
}
struct State {
    next: u64,
    pending: Vec<Pending>,
}
pub(super) struct CallbackPreparations {
    state: Mutex<State>,
    slots: Arc<Semaphore>,
}
impl std::fmt::Debug for CallbackPreparations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackPreparations")
            .field("available_slots", &self.slots.available_permits())
            .finish_non_exhaustive()
    }
}
impl Default for CallbackPreparations {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                next: 1,
                pending: Vec::with_capacity(2),
            }),
            slots: Arc::new(Semaphore::new(2)),
        }
    }
}
impl CallbackPreparations {
    fn remove(&self, id: Ed2kCallbackPreparationId) -> Option<Pending> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let index = state.pending.iter().position(|entry| entry.id == id)?;
        Some(state.pending.swap_remove(index))
    }
}

/// One pending/ready callback. Its borrowed availability cannot outlive this
/// owner; sending the single decision releases the retained observation copy.
pub struct Ed2kCallbackPreparation {
    download: Ed2kCallbackDownload,
    store: Arc<CallbackPreparations>,
    cancel: CancellationToken,
    available: oneshot::Receiver<Ed2kCallbackPreparationOutcome>,
    deadline: tokio::time::Instant,
    cached: Option<Ed2kCallbackPreparationOutcome>,
    admission: Option<oneshot::Sender<Admission>>,
    completion: oneshot::Receiver<Result<Ed2kPeerDownloadOutcome>>,
}
impl Ed2kCallbackPreparation {
    pub fn download(&self) -> &Ed2kCallbackDownload {
        &self.download
    }

    pub async fn availability(&mut self) -> Result<&Ed2kCallbackPreparationOutcome> {
        ensure!(self.admission.is_some(), "callback decision already sent");
        if self.cached.is_none() {
            self.cached = Some(
                tokio::time::timeout_at(self.deadline, &mut self.available)
                    .await
                    .context("callback availability expired")?
                    .context("callback availability owner ended")?,
            );
        }
        Ok(self.cached.as_ref().expect("received availability"))
    }

    /// Authorize only this job's current successor execution after hydration.
    pub fn start(&mut self, token: JobToken) -> Result<()> {
        ensure!(
            token.job_id == self.download.job_token.job_id
                && token.generation >= self.download.job_token.generation,
            "callback start differs from prepared job"
        );
        self.decide(Admission::Start(token))
    }
    pub fn skip(&mut self) -> Result<()> {
        self.decide(Admission::Skip)
    }
    fn decide(&mut self, decision: Admission) -> Result<()> {
        ensure!(
            matches!(
                self.cached,
                Some(Ed2kCallbackPreparationOutcome::Available(_))
            ),
            "callback has no availability proof"
        );
        let sender = self
            .admission
            .take()
            .context("callback decision already sent")?;
        self.cached = None;
        sender
            .send(decision)
            .map_err(|_| anyhow::anyhow!("callback listener ended before admission"))
    }
    pub fn cancel(&self) {
        self.cancel.cancel();
        drop(
            self.store
                .remove(self.download.preparation_id.expect("preparation identity")),
        );
    }
    /// Wait for actual listener-file settlement after start or cancellation.
    pub async fn completed(&mut self) -> Result<Ed2kPeerDownloadOutcome> {
        (&mut self.completion)
            .await
            .context("callback listener ended before settlement")?
    }
}
impl Drop for Ed2kCallbackPreparation {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub(crate) struct CallbackPreparationSession {
    pending: Pending,
}
impl CallbackPreparationSession {
    pub(crate) fn deadline(&self) -> tokio::time::Instant {
        self.pending.deadline
    }
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.pending.cancel.clone()
    }
    pub(crate) fn publish(&mut self, outcome: Ed2kCallbackPreparationOutcome) -> Result<()> {
        self.pending
            .available
            .take()
            .context("callback availability already published")?
            .send(outcome)
            .map_err(|_| anyhow::anyhow!("callback preparation owner ended"))
    }
    /// None means the owner skipped this file; a cancelled or expired request
    /// is an error and must close the socket before another framed read.
    pub(crate) async fn admit(
        &mut self,
        runtime: &Ed2kTransferRuntime,
    ) -> Result<Option<JobToken>> {
        let decision = tokio::select! {
            biased;
            () = self.pending.cancel.cancelled() => anyhow::bail!("callback preparation cancelled"),
            result = tokio::time::timeout_at(self.pending.deadline, &mut self.pending.admission) =>
                result.context("callback decision expired")?.context("callback decision owner ended")?,
        };
        let token = match decision {
            Admission::Skip => return Ok(None),
            Admission::Start(token) => token,
        };
        ensure!(
            token.job_id == self.pending.token.job_id
                && token.generation >= self.pending.token.generation,
            "callback admission differs from preparation"
        );
        let job = runtime
            .download_job(token.job_id)
            .await?
            .context("callback job disappeared")?;
        ensure!(
            job.token == token
                && job.file_hash == self.pending.hash.to_string()
                && job.expected_size_bytes == Some(self.pending.size)
                && job.intent == emulebb_metadata::DownloadIntent::Started
                && job.storage_failure.is_none()
                && job.removed_at_s.is_none()
                && job.completed_at_s.is_none(),
            "callback admission is no longer current"
        );
        drop(job);
        ensure!(
            !self.pending.cancel.is_cancelled(),
            "callback admission cancelled"
        );
        drop(self.pending.capacity.take());
        Ok(Some(token))
    }
    pub(crate) fn complete(mut self, outcome: Ed2kPeerDownloadOutcome) {
        let sender = self.pending.completion.take();
        drop(self);
        if let Some(sender) = sender {
            let _ = sender.send(Ok(outcome));
        }
    }
}
impl Drop for CallbackPreparationSession {
    fn drop(&mut self) {
        drop(self.pending.capacity.take());
        if let Some(sender) = self.pending.completion.take() {
            let _ = sender.send(Err(anyhow::anyhow!(
                "callback file ended before settlement"
            )));
        }
    }
}

impl Ed2kTransferRuntime {
    /// Register before reserving/sending a callback ticket. Pending and ready
    /// owners share two slots; active execution is owned by Core's attempt guard.
    pub fn prepare_callback_download(
        &self,
        mut download: Ed2kCallbackDownload,
        valid_for: Duration,
    ) -> Result<Ed2kCallbackPreparation> {
        ensure!(
            download.preparation_id.is_none()
                && !valid_for.is_zero()
                && valid_for <= super::ED2K_CALLBACK_TICKET_MAX_LIFETIME,
            "invalid callback preparation"
        );
        let capacity = Arc::clone(&self.callback_preparations.slots)
            .try_acquire_owned()
            .context("callback preparation capacity full")?;
        let deadline = tokio::time::Instant::now()
            .checked_add(valid_for)
            .context("callback deadline overflow")?;
        let mut state = self
            .callback_preparations
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let id = Ed2kCallbackPreparationId(state.next);
        state.next = state
            .next
            .checked_add(1)
            .context("callback preparation identity exhausted")?;
        download.preparation_id = Some(id);
        let cancel = CancellationToken::new();
        let (available_tx, available_rx) = oneshot::channel();
        let (admission_tx, admission_rx) = oneshot::channel();
        let (completion_tx, completion_rx) = oneshot::channel();
        state.pending.push(Pending {
            id,
            token: download.job_token,
            hash: download.file_hash,
            size: download.file_size,
            deadline,
            cancel: cancel.clone(),
            available: Some(available_tx),
            admission: admission_rx,
            completion: Some(completion_tx),
            capacity: Some(capacity),
        });
        Ok(Ed2kCallbackPreparation {
            download,
            store: Arc::clone(&self.callback_preparations),
            cancel,
            available: available_rx,
            deadline,
            cached: None,
            admission: Some(admission_tx),
            completion: completion_rx,
        })
    }

    pub(crate) fn claim_callback_preparation(
        &self,
        download: &Ed2kCallbackDownload,
    ) -> Result<Option<CallbackPreparationSession>> {
        let Some(id) = download.preparation_id else {
            return Ok(None);
        };
        let mut state = self
            .callback_preparations
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let Some(index) = state.pending.iter().position(|entry| entry.id == id) else {
            return Ok(None);
        };
        let entry = &state.pending[index];
        ensure!(
            entry.token == download.job_token
                && entry.hash == download.file_hash
                && entry.size == download.file_size,
            "callback preparation identity mismatch"
        );
        Ok(Some(CallbackPreparationSession {
            pending: state.pending.swap_remove(index),
        }))
    }
}

#[cfg(test)]
mod tests;
