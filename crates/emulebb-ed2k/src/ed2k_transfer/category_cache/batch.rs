//! Category copies are prepared by the existing DB owner immediately before SQL.
use super::*;
use tokio::sync::OwnedMutexGuard;

enum Selection {
    Assignment(JobId, Option<i64>),
    Removal(i64),
}

#[cfg(test)]
mod tests;
impl Selection {
    fn selects(&self, manifest: &ResidentManifest) -> bool {
        match self {
            Self::Assignment(id, category) => {
                manifest.token.job_id == *id && manifest.category_id != *category
            }
            Self::Removal(id) => manifest.category_id == Some(*id),
        }
    }
    fn category(&self) -> Option<i64> {
        match self {
            Self::Assignment(_, category) => *category,
            Self::Removal(_) => None,
        }
    }
}

/// The category fence can travel through Core/root preparation and the DB queue
/// without holding the cache. The blocking owner must prepare before SQL.
pub struct CategoryCacheMutation {
    cache: Arc<Mutex<super::super::resident_table::ResidentCache>>,
    residents: Arc<super::super::resident::ResidentControl>,
    selection: Selection,
    _fence: CategoryCacheFence,
}

/// One stable cache cut, retained only from precommit preparation to publication.
pub struct PreparedCategoryCacheMutation {
    entries: Vec<(JobToken, ResidentManifest)>,
    _plan: super::super::resident::ResidentBytes,
    cache: OwnedMutexGuard<super::super::resident_table::ResidentCache>,
    _fence: CategoryCacheFence,
}

impl CategoryCacheMutation {
    pub fn retain_fence(&self) -> CategoryCacheFence {
        self._fence.clone()
    }

    /// Run in the existing blocking DB owner, before its transaction. Keeping
    /// this cache cut through SQL prevents readers/writers from invalidating the
    /// exact prepared copies. No lock is retained while queued or changing roots.
    pub fn prepare(self) -> Result<PreparedCategoryCacheMutation> {
        let cache = self.cache.blocking_lock_owned();
        let count = cache.values().filter(|m| self.selection.selects(m)).count();
        let bytes = count
            .checked_mul(size_of::<(JobToken, ResidentManifest)>())
            .ok_or(LocalMutationError::TooLarge)?;
        let mut plan = self.residents.reserve_bytes(bytes)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(count)?;
        plan.resize(
            entries
                .capacity()
                .checked_mul(size_of::<(JobToken, ResidentManifest)>())
                .ok_or(LocalMutationError::TooLarge)?,
        )?;
        for current in cache.values().filter(|m| self.selection.selects(m)) {
            let copy = self
                .residents
                .copy_category(current, self.selection.category())?;
            entries.push((current.token, copy));
        }
        Ok(PreparedCategoryCacheMutation {
            entries,
            _plan: plan,
            cache,
            _fence: self._fence,
        })
    }
}

impl PreparedCategoryCacheMutation {
    /// Synchronous publication spends no new capacity and cannot observe a
    /// different cache version: this owner retained its guard through commit.
    pub fn publish(mut self) -> Result<()> {
        for (token, replacement) in self.entries.drain(..) {
            let current = self
                .cache
                .get_mut(&token.job_id)
                .filter(|current| current.token == token)
                .ok_or_else(|| anyhow::anyhow!("prepared category cache cut changed"))?;
            *current = replacement;
        }
        Ok(())
    }
}

impl Ed2kTransferRuntime {
    pub async fn prepare_category_assignment(
        &self,
        job_id: JobId,
        category_id: Option<i64>,
    ) -> Result<CategoryCacheMutation> {
        ensure!(
            category_id.is_none_or(|id| id > 0),
            "category ID must be positive"
        );
        self.category_request(Selection::Assignment(job_id, category_id))
            .await
    }

    pub async fn prepare_category_removal(
        &self,
        category_id: i64,
    ) -> Result<CategoryCacheMutation> {
        ensure!(category_id > 0, "category ID must be positive");
        self.category_request(Selection::Removal(category_id)).await
    }

    async fn category_request(&self, selection: Selection) -> Result<CategoryCacheMutation> {
        let guard = Arc::clone(&self.category_assignment_gate)
            .write_owned()
            .await;
        Ok(CategoryCacheMutation {
            cache: Arc::clone(&self.manifest_cache),
            residents: Arc::clone(&self.local_mutations.residents),
            selection,
            _fence: CategoryCacheFence {
                _guard: Arc::new(guard),
            },
        })
    }
}
