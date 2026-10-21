//! Generation-safe ownership for background ED2K download tasks.

use std::future::Future;

use parking_lot::Mutex;
use tokio::task::JoinSet;

struct DownloadTaskState {
    accepting: bool,
    tasks: JoinSet<()>,
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
                tasks: JoinSet::new(),
            }),
        }
    }

    /// Tracks one task when the current runtime generation accepts work.
    pub(crate) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        let mut state = self.state.lock();
        if state.accepting {
            state.tasks.spawn(task);
        }
    }

    /// Opens a fresh generation after the prior one has drained.
    pub(crate) fn start(&self) {
        let mut state = self.state.lock();
        debug_assert!(state.tasks.is_empty());
        state.accepting = true;
    }

    /// Fences new work, aborts the prior generation, and awaits every task.
    pub(crate) async fn stop_and_drain(&self) {
        let mut tasks = {
            let mut state = self.state.lock();
            state.accepting = false;
            std::mem::take(&mut state.tasks)
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.state.lock().tasks.is_empty()
    }
}
