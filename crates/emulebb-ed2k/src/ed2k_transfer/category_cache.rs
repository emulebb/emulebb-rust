//! Precommit resident admission for the existing category persistence owner.
use super::{Ed2kTransferRuntime, LocalMutationError, ResidentManifest, resident::Reservation};
use anyhow::{Result, ensure};
use emulebb_metadata::{JobId, JobToken};
use std::sync::Arc;
use tokio::sync::{Mutex, OwnedRwLockWriteGuard};

mod batch;
pub use batch::{CategoryCacheMutation, PreparedCategoryCacheMutation};

mod download_patch;
pub use download_patch::{DownloadPatchFence, PreparedDownloadPatch};

/// Retained by the existing async owner until its Core state publication ends.
/// The blocking DB command holds a clone across SQL and cache publication.
#[derive(Clone)]
pub struct CategoryCacheFence {
    _guard: Arc<OwnedRwLockWriteGuard<()>>,
}

/// Transfer this prepared plan to the existing blocking database owner before
/// committing SQL. That owner publishes synchronously before its reply, even
/// when the requesting client disconnects. Dropping an unsubmitted plan is safe.
struct ScalarCacheMutation {
    cache: Arc<Mutex<super::resident_table::ResidentCache>>,
    entries: Vec<(JobToken, Reservation)>,
    _plan: super::resident::ResidentBytes,
    // Keep new hydration/category admission fenced until all entries publish.
    _fence: CategoryCacheFence,
}
impl ScalarCacheMutation {
    /// Keep the same fence across the blocking reply and Core state publication.
    fn retain_fence(&self) -> CategoryCacheFence {
        self._fence.clone()
    }
}
impl Ed2kTransferRuntime {
    async fn prepare_scalar_cache(
        &self,
        selected: impl Fn(&ResidentManifest) -> bool,
    ) -> Result<ScalarCacheMutation> {
        let fence = Arc::clone(&self.category_assignment_gate)
            .write_owned()
            .await;
        let cache = self.manifest_cache.lock().await;
        let count = cache.values().filter(|manifest| selected(manifest)).count();
        let mut plan = self.local_mutations.residents.reserve_bytes(
            count
                .checked_mul(size_of::<(JobToken, Reservation)>())
                .ok_or(LocalMutationError::TooLarge)?,
        )?;
        let mut entries = Vec::with_capacity(count);
        plan.resize(entries.capacity() * size_of::<(JobToken, Reservation)>())?;
        for current in cache.values().filter(|manifest| selected(manifest)) {
            entries.push((
                current.token,
                self.local_mutations
                    .residents
                    .reserve(current.token.job_id)?,
            ));
        }
        drop(cache);
        Ok(ScalarCacheMutation {
            cache: Arc::clone(&self.manifest_cache),
            entries,
            _plan: plan,
            _fence: CategoryCacheFence {
                _guard: Arc::new(fence),
            },
        })
    }
}

#[cfg(test)]
mod tests;
