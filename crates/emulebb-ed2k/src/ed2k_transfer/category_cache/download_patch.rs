//! Combined scalar publication using the existing precommit cache credits.
use super::*;
use crate::ed2k_transfer::store::ScopedLockGuard;
use emulebb_metadata::{DownloadPatchError, MetadataDownloadPatch, MetadataDownloadPatched};
use std::sync::atomic::Ordering;

struct PatchGuards {
    _lifecycle: ScopedLockGuard<JobId>,
    _io: ScopedLockGuard<JobId>,
    _content: ScopedLockGuard<String>,
}

/// Keeps the same native cut through the blocking reply and Core publication.
pub struct DownloadPatchFence {
    _category: CategoryCacheFence,
    _guards: Arc<PatchGuards>,
}

/// Owned by the existing database command, never by the requesting connection.
pub struct PreparedDownloadPatch {
    token: JobToken,
    hash: emulebb_kad_proto::Ed2kHash,
    cache: CategoryCacheMutation,
    guards: Arc<PatchGuards>,
}

impl PreparedDownloadPatch {
    pub fn token(&self) -> JobToken {
        self.token
    }

    pub fn retain_fence(&self) -> DownloadPatchFence {
        DownloadPatchFence {
            _category: self.cache.retain_fence(),
            _guards: Arc::clone(&self.guards),
        }
    }
}

impl Ed2kTransferRuntime {
    /// Acquire lifecycle/I/O/content before the category fence, matching progress
    /// publication's content-before-category order. Admit COW before SQL.
    pub async fn prepare_download_patch(
        &self,
        id: JobId,
        patch: &MetadataDownloadPatch,
    ) -> Result<Option<PreparedDownloadPatch>> {
        patch.validate()?;
        let Some(initial) = self.download_job(id).await? else {
            return Ok(None);
        };
        let lifecycle = self.lock_lifecycle(id).await;
        let io = self.lock_manifest(initial.token).await;
        let content = self.lock_content(&initial.file_hash).await;
        drop(initial);
        let Some(current) = self.download_job(id).await? else {
            return Ok(None);
        };
        if current.removed_at_s.is_some() {
            return Ok(None);
        }
        if let (Some(old), Some(new)) = (current.expected_size_bytes, patch.size_bytes)
            && old != new
        {
            return Err(DownloadPatchError::SizeConflict.into());
        }
        let token = current.token;
        let hash = current.file_hash.parse()?;
        {
            let cache = self.manifest_cache.lock().await;
            if let Some(resident) = cache.get(&id).filter(|entry| entry.token == token) {
                // Unknown-size discovery owns no executable resident geometry.
                ensure!(
                    current.expected_size_bytes == Some(resident.file_size),
                    LocalMutationError::Unknown
                );
            }
        }
        drop(current);
        let cache = self
            .prepare_category_cache(
                |manifest| {
                    manifest.token == token
                        && (patch
                            .name
                            .as_ref()
                            .is_some_and(|name| *name != manifest.display_name)
                            || patch
                                .category_id
                                .is_some_and(|category| category != manifest.category_id))
                },
                None,
            )
            .await?;
        Ok(Some(PreparedDownloadPatch {
            token,
            hash,
            cache,
            guards: Arc::new(PatchGuards {
                _lifecycle: lifecycle,
                _io: io,
                _content: content,
            }),
        }))
    }

    /// Called synchronously by the existing blocking owner after its atomic SQL
    /// commit. Reader-pinned replacements use credits admitted before commit.
    pub fn publish_download_patch(
        &self,
        prepared: PreparedDownloadPatch,
        value: &MetadataDownloadPatched,
    ) -> Result<()> {
        ensure!(
            prepared.token == value.token,
            "patch publication token changed"
        );
        {
            let mut cache = prepared.cache.cache.blocking_lock();
            for (token, credit) in prepared.cache.entries {
                if let Some(current) = cache
                    .get_mut(&token.job_id)
                    .filter(|entry| entry.token == token)
                {
                    current.write_with(credit, |manifest| {
                        manifest.display_name = value.name.clone();
                        manifest.category_id = value.category_id;
                        if let Some(size) = value.size_bytes {
                            manifest.file_size = size;
                        }
                        Ok(())
                    })?;
                }
            }
        }
        let mut changed = false;
        let mut catalog = self.shared_catalog.blocking_write();
        catalog.update_by_hash(&prepared.hash, |entry| {
            if !entry.verified_complete && entry.display_name != value.name {
                entry.display_name = value.name.clone();
                changed = true;
            }
        });
        drop(catalog);
        if changed {
            self.shared_catalog_generation
                .fetch_add(1, Ordering::AcqRel);
        }
        if changed || value.changed {
            self.shared_publish_demand_revision
                .fetch_add(1, Ordering::AcqRel);
            self.shared_publish_demand_notify.notify_waiters();
        }
        Ok(())
    }
}
