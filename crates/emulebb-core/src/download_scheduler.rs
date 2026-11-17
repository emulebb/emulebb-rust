//! One SQLite cursor and retry clock for the bounded selected cohort.
use crate::{
    EmulebbCore, Transfer,
    download_attempts::{AdmissionDenied, DownloadAttemptGuard},
};
use anyhow::Result;
use emulebb_metadata::JobId;
use tokio::{
    sync::watch,
    task::JoinSet,
    time::{Duration, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;

const PAGE_SIZE: usize = 32;
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
const IDLE_SELECTION_INTERVAL: Duration = Duration::from_secs(30);

/// Only selected jobs own this scalar clock. Completed network rounds may yield
/// after inactivity; an in-flight payload operation is never timed out by it.
struct SelectionProgress {
    bytes: u64,
    changed_at: tokio::time::Instant,
}
impl SelectionProgress {
    fn new(bytes: u64) -> Self {
        Self {
            bytes,
            changed_at: tokio::time::Instant::now(),
        }
    }
    fn idle(&mut self, bytes: u64) -> bool {
        if bytes != self.bytes {
            self.bytes = bytes;
            self.changed_at = tokio::time::Instant::now();
        }
        self.changed_at.elapsed() >= IDLE_SELECTION_INTERVAL
    }
}

impl EmulebbCore {
    pub(crate) fn start_download_scheduler(&self) {
        let core = self.clone();
        self.ed2k_download_tasks
            .spawn(move |shutdown| core.run_download_scheduler(shutdown));
    }

    async fn run_download_scheduler(self, shutdown: CancellationToken) {
        let mut workers = JoinSet::new();
        let mut cursor = None;
        let (ticks, clock) = watch::channel(());
        let mut interval = tokio::time::interval(RETRY_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                result = workers.join_next(), if !workers.is_empty() => {
                    if let Some(Err(error)) = result {
                        tracing::error!(%error, "selected download worker failed");
                    }
                }
                () = self.download_attempts.changed.notified(), if workers.is_empty() => {
                    if let Err(error) = self.select_download_page(&mut cursor, &mut workers, &clock, &shutdown).await {
                        tracing::warn!(%error, "download selection deferred");
                    }
                }
                _ = interval.tick() => {
                    ticks.send_replace(());
                    if let Err(error) = self.select_download_page(&mut cursor, &mut workers, &clock, &shutdown).await {
                        tracing::warn!(%error, "download selection deferred");
                    }
                }
            }
        }
        self.download_attempts.cancel_all();
        while let Some(result) = workers.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "selected download worker failed during shutdown");
            }
        }
    }

    async fn select_download_page(
        &self,
        cursor: &mut Option<JobId>,
        workers: &mut JoinSet<()>,
        clock: &watch::Receiver<()>,
        shutdown: &CancellationToken,
    ) -> Result<()> {
        if self.download_attempts.available() == (0, 0) {
            return Ok(());
        }
        let page = self
            .ed2k_transfers
            .download_jobs_after(*cursor, PAGE_SIZE, true)
            .await?;
        // Copy only scalar selection keys, then release the page's native loan
        // before any worker can reserve mutation/hydration workspace.
        let candidates = page
            .iter()
            .map(|job| {
                Ok((
                    job.token,
                    job.file_hash.parse()?,
                    job.expected_size_bytes.is_some(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        *cursor = page.last().map(|job| job.token.job_id);
        drop(page);
        for (token, hash, known_size) in candidates {
            if shutdown.is_cancelled() {
                break;
            }
            let admission = if known_size {
                self.download_attempts.try_enter(token, hash)
            } else {
                self.download_attempts.try_prepare(token, hash)
            };
            let guard = match admission {
                Ok(guard) => guard,
                Err(AdmissionDenied::Duplicate | AdmissionDenied::Busy) => continue,
                Err(AdmissionDenied::Exhausted) => {
                    anyhow::bail!("download admission nonce exhausted")
                }
            };
            let core = self.clone();
            let clock = clock.clone();
            let shutdown = shutdown.clone();
            workers.spawn(async move {
                if known_size {
                    core.run_selected_download(guard, clock, shutdown).await;
                } else if let Err(error) = core.prepare_download_metadata(guard, shutdown).await {
                    tracing::warn!(job_id = %token.job_id, %error, "download metadata preparation deferred");
                }
            });
        }
        Ok(())
    }

    async fn prepare_download_metadata(
        &self,
        mut guard: DownloadAttemptGuard,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let Some(network) = self.ed2k_network.as_ref() else {
            return Ok(());
        };
        let selected = self
            .ed2k_transfers
            .begin_download_job_execution(guard.token(), None)
            .await?;
        let Some(job) = selected.as_ref() else {
            return Ok(());
        };
        let hash = job.file_hash.parse()?;
        if !guard.rebind(job.token) {
            return Ok(());
        }
        drop(selected);
        let cancel = guard.cancellation();
        let resolution = self.resolve_download_size(network, hash, &cancel);
        tokio::pin!(resolution);
        let size = tokio::select! {
            size = &mut resolution => size?,
            () = shutdown.cancelled() => { cancel.cancel(); resolution.await? }
        };
        if !cancel.is_cancelled()
            && let Some(size) = size
        {
            self.ed2k_transfers
                .learn_download_job_size(guard.token(), size)
                .await?;
        }
        Ok(())
    }

    async fn run_selected_download(
        &self,
        mut guard: DownloadAttemptGuard,
        mut clock: watch::Receiver<()>,
        shutdown: CancellationToken,
    ) {
        let transfer = match self.hydrate_selected_download(&mut guard).await {
            Ok(Some(transfer)) => transfer,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(job_id = %guard.token().job_id, %error, "download hydration deferred");
                if !matches!(
                    error.downcast_ref::<emulebb_ed2k::ed2k_transfer::LocalMutationError>(),
                    Some(
                        emulebb_ed2k::ed2k_transfer::LocalMutationError::Busy
                            | emulebb_ed2k::ed2k_transfer::LocalMutationError::Closing
                    )
                ) {
                    self.persist_selection_storage_failure(
                        &guard,
                        "STORAGE_PREPARATION_FAILED",
                        &error,
                        &mut clock,
                        &shutdown,
                    )
                    .await;
                }
                return;
            }
        };
        let cancel = guard.cancellation();
        let reask = self.ed2k_reask_handle.lock().unwrap().clone();
        let mut progress =
            SelectionProgress::new(self.ed2k_transfers.downloaded_session_bytes(guard.token()));
        loop {
            if shutdown.is_cancelled() || cancel.is_cancelled() {
                break;
            }
            crate::diag_sched::download_attempt_started(&transfer.hash, false);
            let attempt = self.run_ed2k_download_attempt(&transfer, guard.token(), &cancel);
            tokio::pin!(attempt);
            let result = tokio::select! {
                result = &mut attempt => result,
                () = shutdown.cancelled() => { cancel.cancel(); attempt.await }
            };
            let state = match &result {
                Ok(Some(state)) => *state,
                Ok(None) => "cancelled",
                Err(_) => "error",
            };
            crate::diag_sched::download_task_settled(
                &transfer.hash,
                state,
                !matches!(&result, Ok(None | Some("completed"))),
            );
            match result {
                Ok(Some("completed")) => {
                    if let Err(error) = self.deliver_completed_download(guard.token()).await {
                        tracing::warn!(job_id = %guard.token().job_id, %error, "download delivery deferred");
                    }
                    break;
                }
                Ok(None) => break,
                Ok(Some(state)) => {
                    if let Err(error) = self
                        .refresh_transfer_from_manifest(guard.token(), state)
                        .await
                    {
                        tracing::warn!(job_id = %guard.token().job_id, %error, "selected download projection deferred");
                    }
                }
                Err(error) => {
                    tracing::warn!(job_id = %guard.token().job_id, %error, "download network attempt deferred")
                }
            }
            if progress.idle(self.ed2k_transfers.downloaded_session_bytes(guard.token())) {
                break;
            }
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = cancel.cancelled() => break,
                () = guard.notified() => {},
                tick = clock.changed() => { if tick.is_err() { break; } },
            }
            crate::diag_sched::download_retry_outcome(
                &transfer.hash,
                state,
                !cancel.is_cancelled() && !shutdown.is_cancelled(),
            );
        }
        cancel.cancel();
        // All attempt producers have returned. Retire UDP state before freeing
        // the slot; already emitted callbacks carry the old token and fail the
        // canceled ownership check. On disconnect the UDP loop is already gone.
        if let Some(reask) = reask
            && let Err(error) = reask.retire_execution(guard.token()).await
        {
            tracing::warn!(job_id = %guard.token().job_id, error, "UDP execution retirement ended with its runtime");
        }
        if let Err(error) = self
            .ed2k_transfers
            .release_download_job_execution(guard.token())
            .await
        {
            tracing::error!(job_id = %guard.token().job_id, %error, "download selection release failed");
            self.persist_selection_storage_failure(
                &guard,
                "STORAGE_CHECKPOINT_FAILED",
                &error,
                &mut clock,
                &shutdown,
            )
            .await;
        }
        self.release_download_source_file(guard.token(), &transfer.hash)
            .await;
    }

    async fn persist_selection_storage_failure(
        &self,
        guard: &DownloadAttemptGuard,
        code: &str,
        error: &anyhow::Error,
        clock: &mut watch::Receiver<()>,
        shutdown: &CancellationToken,
    ) {
        guard.cancellation().cancel();
        let message: String = error
            .to_string()
            .chars()
            .filter(|value| *value != '\0')
            .take(1000)
            .collect();
        let failure = emulebb_metadata::DownloadJobStorageFailure::new(
            code,
            &message,
            chrono::Utc::now().timestamp().max(0),
        )
        .expect("bounded failure fields");
        // Keep ownership while fault persistence is refused. Releasing this
        // guard first would turn a storage failure into an automatic retry.
        loop {
            match self
                .ed2k_transfers
                .fail_download_job_storage(guard.token(), &failure)
                .await
            {
                Ok(_) => return,
                Err(error) => {
                    tracing::error!(job_id = %guard.token().job_id, %error, "download storage fault publication pending")
                }
            }
            tokio::select! {
                () = shutdown.cancelled() => return,
                tick = clock.changed() => { if tick.is_err() { return; } },
            }
        }
    }

    /// A network callback wakes its existing owner; it never creates a worker
    /// for a queued row or takes a second slot for the same execution.
    pub(crate) fn queue_ed2k_download_attempt(&self, transfer: Transfer) {
        self.download_attempts.wake(transfer.job_token());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DownloadCreate, DownloadCreateSource};

    #[tokio::test(start_paused = true)]
    async fn progress_extends_selection_but_idle_rounds_eventually_yield() {
        let mut progress = SelectionProgress::new(0);
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(!progress.idle(0));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(progress.idle(0));
        assert!(!progress.idle(8192));
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(!progress.idle(8192));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(progress.idle(8192));
    }

    #[tokio::test]
    async fn failed_storage_preparation_persists_manual_retry_and_preserves_the_foreign_object() {
        let core =
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
        let (_, created) = core
            .create_download(DownloadCreate {
                source: DownloadCreateSource::Content {
                    hash: "45454545454545454545454545454545".into(),
                    name: "Sample.bin".into(),
                    size_bytes: Some(16),
                },
                category: None,
                intent: emulebb_metadata::DownloadIntent::Started,
                redownload: false,
            })
            .await
            .unwrap();
        let id = created.id;
        drop(created);
        let job = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
        let token = job.token;
        drop(job);
        let allocated = core
            .ed2k_transfers
            .start_download_job(token, &core.transfer_root)
            .await
            .unwrap();
        let job = allocated.as_ref().unwrap();
        let token = job.token;
        let path = job.storage.as_ref().unwrap().path.clone();
        drop(allocated);
        std::fs::write(&path, b"foreign object").unwrap();
        let guard = core
            .download_attempts
            .try_enter(token, "45454545454545454545454545454545".parse().unwrap())
            .unwrap();
        let (_ticks, clock) = watch::channel(());
        core.run_selected_download(guard, clock, CancellationToken::new())
            .await;
        let failed = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
        assert_eq!(
            failed.storage_failure.as_ref().unwrap().code(),
            "STORAGE_PREPARATION_FAILED"
        );
        assert_eq!(failed.intent, emulebb_metadata::DownloadIntent::Started);
        drop(failed);
        assert!(
            core.ed2k_transfers
                .download_jobs_after(None, 1, true)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"foreign object");
        assert_eq!(core.download_attempts.available(), (16, 2));
        assert_eq!(
            core.start_download(id).await.unwrap(),
            crate::download_controls::DownloadChange::Changed
        );
        assert!(
            core.ed2k_transfers
                .download_job(id)
                .await
                .unwrap()
                .unwrap()
                .storage_failure
                .is_none()
        );
    }
}
