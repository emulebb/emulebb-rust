//! Precommit resident admission for the existing category persistence owner.
use super::{Ed2kTransferRuntime, LocalMutationError, ResidentManifest, resident::Reservation};
use anyhow::{Result, ensure};
use emulebb_metadata::{JobId, JobToken};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, OwnedRwLockWriteGuard};

/// Retained by the existing async owner until its Core state publication ends.
/// The blocking DB command holds a clone across SQL and cache publication.
#[derive(Clone)]
pub struct CategoryCacheFence {
    _guard: Arc<OwnedRwLockWriteGuard<()>>,
}

/// Transfer this prepared plan to the existing blocking database owner before
/// committing SQL. That owner publishes synchronously before its reply, even
/// when the requesting client disconnects. Dropping an unsubmitted plan is safe.
pub struct CategoryCacheMutation {
    cache: Arc<Mutex<HashMap<JobId, ResidentManifest>>>,
    category_id: Option<i64>,
    entries: Vec<(JobToken, Reservation)>,
    // Keep new hydration/category admission fenced until all entries publish.
    _fence: CategoryCacheFence,
}
impl CategoryCacheMutation {
    /// Keep the same fence across the blocking reply and Core state publication.
    pub fn retain_fence(&self) -> CategoryCacheFence {
        self._fence.clone()
    }

    /// Called by the existing blocking persistence worker after successful SQL.
    /// Memory has already been admitted; no capacity wait or async boundary is
    /// introduced after commit. Generation changes never patch a new execution.
    pub fn publish(self) -> Result<()> {
        let mut cache = self.cache.blocking_lock();
        for (token, permit) in self.entries {
            if let Some(current) = cache.get_mut(&token.job_id).filter(|m| m.token == token) {
                current.write_with(permit, |current| {
                    current.category_id = self.category_id;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }
}
impl Ed2kTransferRuntime {
    /// Prepare the selected job's assignment before sending a database command.
    pub async fn prepare_category_assignment(
        &self,
        job_id: JobId,
        category_id: Option<i64>,
    ) -> Result<CategoryCacheMutation> {
        ensure!(
            category_id.is_none_or(|id| id > 0),
            "category ID must be positive"
        );
        self.prepare_category_cache(|manifest| manifest.token.job_id == job_id, category_id)
            .await
    }

    /// Prepare every currently resident member before deleting a category.
    pub async fn prepare_category_removal(
        &self,
        category_id: i64,
    ) -> Result<CategoryCacheMutation> {
        ensure!(category_id > 0, "category ID must be positive");
        self.prepare_category_cache(|manifest| manifest.category_id == Some(category_id), None)
            .await
    }

    async fn prepare_category_cache(
        &self,
        selected: impl Fn(&ResidentManifest) -> bool,
        category_id: Option<i64>,
    ) -> Result<CategoryCacheMutation> {
        let fence = Arc::clone(&self.category_assignment_gate)
            .write_owned()
            .await;
        let cache = self.manifest_cache.lock().await;
        let count = cache
            .values()
            .filter(|manifest| selected(manifest) && manifest.category_id != category_id)
            .count();
        ensure!(
            count <= super::resident::MAX_JOBS,
            LocalMutationError::TooLarge
        );
        let mut entries = Vec::with_capacity(count);
        for current in cache
            .values()
            .filter(|manifest| selected(manifest) && manifest.category_id != category_id)
        {
            entries.push((
                current.token,
                self.local_mutations
                    .residents
                    .reserve(current.token.job_id)?,
            ));
        }
        drop(cache);
        Ok(CategoryCacheMutation {
            cache: Arc::clone(&self.manifest_cache),
            category_id,
            entries,
            _fence: CategoryCacheFence {
                _guard: Arc::new(fence),
            },
        })
    }
}

#[cfg(test)]
mod tests;
