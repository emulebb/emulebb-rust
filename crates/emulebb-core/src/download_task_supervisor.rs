//! Generation-safe ownership for background ED2K download tasks.

use std::future::Future;
use std::time::Duration;

use anyhow::Result;
use parking_lot::Mutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const DOWNLOAD_TASK_QUIESCE_TIMEOUT: Duration = Duration::from_secs(2);
const DOWNLOAD_CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(2);

struct DownloadTaskState {
    accepting: bool,
    quiesce: CancellationToken,
    tasks: JoinSet<()>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DownloadTaskShutdownReport {
    pub(crate) forced_task_count: usize,
    pub(crate) checkpointed_transfer_count: Option<usize>,
}

/// Owns the current ED2K download-task generation.
///
/// Admission and generation replacement share one short synchronous lock, so a
/// task cannot slip into a new session while the previous generation drains.
pub(crate) struct DownloadTaskSupervisor {
    state: Mutex<DownloadTaskState>,
}

impl DownloadTaskSupervisor {
    /// Creates an accepting supervisor for the initial runtime generation.
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(DownloadTaskState {
                accepting: true,
                quiesce: CancellationToken::new(),
                tasks: JoinSet::new(),
            }),
        }
    }

    /// Tracks one task when the current runtime generation accepts work.
    pub(crate) fn spawn<Task, TaskFuture>(&self, task: Task)
    where
        Task: FnOnce(CancellationToken) -> TaskFuture,
        TaskFuture: Future<Output = ()> + Send + 'static,
    {
        let mut state = self.state.lock();
        if state.accepting {
            let quiesce = state.quiesce.child_token();
            state.tasks.spawn(task(quiesce));
        }
    }

    /// Opens a fresh generation after the prior one has drained.
    pub(crate) fn start(&self) {
        let mut state = self.state.lock();
        debug_assert!(state.tasks.is_empty());
        state.quiesce = CancellationToken::new();
        state.accepting = true;
    }

    /// Fences new work, requests cooperative quiescence, checkpoints final
    /// progress, and aborts only tasks that exceed the shutdown deadline.
    pub(crate) async fn stop_and_drain(
        &self,
        final_checkpoint: impl Future<Output = Result<usize>>,
    ) -> DownloadTaskShutdownReport {
        self.stop_and_drain_with_timeouts(
            final_checkpoint,
            DOWNLOAD_TASK_QUIESCE_TIMEOUT,
            DOWNLOAD_CHECKPOINT_TIMEOUT,
        )
        .await
    }

    async fn stop_and_drain_with_timeouts(
        &self,
        final_checkpoint: impl Future<Output = Result<usize>>,
        quiesce_timeout: Duration,
        checkpoint_timeout: Duration,
    ) -> DownloadTaskShutdownReport {
        let (quiesce, mut tasks) = {
            let mut state = self.state.lock();
            state.accepting = false;
            (state.quiesce.clone(), std::mem::take(&mut state.tasks))
        };
        quiesce.cancel();

        let cooperative_drain = async { while tasks.join_next().await.is_some() {} };
        let forced_task_count = if tokio::time::timeout(quiesce_timeout, cooperative_drain)
            .await
            .is_err()
        {
            let forced_task_count = tasks.len();
            tracing::warn!(
                forced_task_count,
                timeout_ms = quiesce_timeout.as_millis(),
                "ED2K download tasks exceeded quiesce deadline; aborting remaining tasks"
            );
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            forced_task_count
        } else {
            0
        };

        let checkpointed_transfer_count =
            match tokio::time::timeout(checkpoint_timeout, final_checkpoint).await {
                Ok(Ok(checkpointed)) => Some(checkpointed),
                Ok(Err(error)) => {
                    tracing::warn!(
                        "failed to persist final ED2K download progress during shutdown: {error:#}"
                    );
                    None
                }
                Err(_) => {
                    tracing::warn!(
                        timeout_ms = checkpoint_timeout.as_millis(),
                        "final ED2K download progress checkpoint exceeded shutdown deadline"
                    );
                    None
                }
            };

        DownloadTaskShutdownReport {
            forced_task_count,
            checkpointed_transfer_count,
        }
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.state.lock().tasks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn cooperative_shutdown_checkpoints_after_tasks_exit() {
        let supervisor = DownloadTaskSupervisor::new();
        let task_exited = Arc::new(AtomicBool::new(false));
        let task_exited_from_task = Arc::clone(&task_exited);
        supervisor.spawn(move |quiesce| async move {
            quiesce.cancelled().await;
            task_exited_from_task.store(true, Ordering::SeqCst);
        });

        let task_exited_at_checkpoint = Arc::clone(&task_exited);
        let report = supervisor
            .stop_and_drain(async move {
                assert!(task_exited_at_checkpoint.load(Ordering::SeqCst));
                Ok(1)
            })
            .await;

        assert_eq!(report.forced_task_count, 0);
        assert_eq!(report.checkpointed_transfer_count, Some(1));
        assert!(supervisor.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn forced_shutdown_aborts_only_after_bounded_quiesce_timeout() {
        let supervisor = Arc::new(DownloadTaskSupervisor::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_by_task = Arc::clone(&dropped);
        supervisor.spawn(move |_quiesce| async move {
            let _drop_signal = DropSignal(dropped_by_task);
            std::future::pending::<()>().await;
        });

        let started_at = tokio::time::Instant::now();
        let supervisor_for_shutdown = Arc::clone(&supervisor);
        let shutdown = tokio::spawn(async move {
            supervisor_for_shutdown
                .stop_and_drain_with_timeouts(
                    async { Ok(0) },
                    Duration::from_secs(5),
                    Duration::from_secs(1),
                )
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;

        let report = shutdown.await.unwrap();
        assert_eq!(started_at.elapsed(), Duration::from_secs(5));
        assert_eq!(report.forced_task_count, 1);
        assert_eq!(report.checkpointed_transfer_count, Some(0));
        assert!(dropped.load(Ordering::SeqCst));
        assert!(supervisor.is_empty());
    }
}
