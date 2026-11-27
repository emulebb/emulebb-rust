//! Cursor-based cleanup: one bounded page from each durable journal per pass.
use crate::EmulebbCore;
use anyhow::Result;
impl EmulebbCore {
    /// Automatic cleanup never changes intent or re-delivers completed output.
    pub async fn maintain_download_cleanup(&self) -> Result<()> {
        let Ok(mut cursors) = self.cleanup_cursors.try_lock() else {
            return Ok(());
        };
        let (next, removed) = self
            .ed2k_transfers
            .recover_removed_download_jobs_page(cursors.0, 4)
            .await?;
        cursors.0 = next;
        for failure in removed.failures {
            tracing::warn!(%failure,"download removal cleanup remains pending");
        }
        let (next, retired) = self
            .ed2k_transfers
            .recover_download_retirements_page(cursors.1, 4)
            .await?;
        cursors.1 = next;
        let deferred = removed.deferred_due_to_capacity + retired.deferred_due_to_capacity;
        if deferred > 0 {
            tracing::debug!(deferred, "download cleanup deferred by local capacity");
        }
        for failure in retired.failures {
            tracing::warn!(%failure,"download storage retirement remains pending");
        }
        Ok(())
    }
}
