//! Runtime facade for shared-catalog reads and mutation.

use std::{
    str::FromStr,
    sync::{Arc, atomic::Ordering},
};

use crate::PopularHash;
use emulebb_kad_proto::Ed2kHash;

use super::{
    Ed2kMediaMetadata, Ed2kResumeManifest, Ed2kSharedCatalog, Ed2kSharedEntry, Ed2kTransferRuntime,
};

/// Marks a root transaction in progress until its durable/cache publication ends.
pub struct CategoryRootMutation {
    epoch: Arc<std::sync::atomic::AtomicU64>,
    ready: Arc<tokio::sync::Notify>,
    clean_epoch: Option<u64>,
}
impl CategoryRootMutation {
    /// A scoped reconciliation may clear safety only if no earlier root work
    /// was pending and no later root transaction changes this epoch.
    pub fn finish(self) -> Option<u64> {
        self.clean_epoch
    }
}
impl Drop for CategoryRootMutation {
    fn drop(&mut self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.ready.notify_waiters();
    }
}

/// Fixed-workspace outcome of reconciling a root-affected hash.
pub enum CategoryCatalogDecision {
    Keep,
    Remove,
    Partial(emulebb_metadata::MetadataPartialShare),
}

/// Probe one already-reserved candidate without holding a metadata connection.
/// The caller owns the candidate and its allocation lease for the whole probe.
pub fn category_copy_matches(candidate: &emulebb_metadata::MetadataSharedCopyCandidate) -> bool {
    let Some(expected) = &candidate.source_fingerprint else {
        return false;
    };
    let path = crate::long_path::long_path(&candidate.source_path);
    expected.size_bytes == candidate.file_size
        && super::ingest::native_file_fingerprint(&path)
            .as_ref()
            .is_some_and(|value| expected.safely_matches(value))
}

impl Ed2kTransferRuntime {
    /// Admit a verified monitored path and publish its catalog entry under the
    /// tracked owner. Capacity waits retain only the current caller's event.
    pub async fn admit_monitored_shared_path(
        &self,
        file_hash: &str,
        root: &std::path::Path,
        path: &std::path::Path,
        relative: &std::path::Path,
        fingerprint: &emulebb_metadata::NativeFileFingerprint,
        observed_root: Option<u64>,
    ) -> anyhow::Result<bool> {
        let hash = file_hash.parse::<Ed2kHash>()?;
        loop {
            let capacity_revision = self.local_mutations.capacity_revision();
            let result = async {
                let manifest_guard = self.lock_content(file_hash).await;
                let stripe_guard = self.begin_shared_file_mutation(&[hash.0])?;
                let receive = self.local_mutations.submit_admission(
                    self,
                    file_hash,
                    root,
                    path,
                    relative,
                    fingerprint,
                    observed_root,
                    manifest_guard,
                    stripe_guard,
                )?;
                receive
                    .await
                    .map_err(|_| anyhow::anyhow!("local admission worker stopped"))?
            }
            .await;
            match result {
                Err(error)
                    if matches!(
                        error.downcast_ref::<super::LocalMutationError>(),
                        Some(super::LocalMutationError::Busy)
                    ) =>
                {
                    self.local_mutations
                        .wait_for_completion(capacity_revision)
                        .await?;
                    if observed_root.is_some() {
                        return Err(error);
                    }
                    self.stable_category_root_epoch().await;
                }
                other => return other.map(|admitted| admitted != 0),
            }
        }
    }

    /// Capture the stable root epoch before a filesystem observation.
    pub async fn root_observation_epoch(&self) -> u64 {
        self.stable_category_root_epoch().await
    }

    /// Withdraw one monitored path through the tracked SQL/publication unit.
    pub async fn withdraw_monitored_shared_path(
        &self,
        file_hash: &str,
        path: &std::path::Path,
    ) -> anyhow::Result<usize> {
        let hash = file_hash.parse::<Ed2kHash>()?;
        loop {
            let capacity_revision = self.local_mutations.capacity_revision();
            let result = async {
                let manifest_guard = self.lock_content(file_hash).await;
                let stripe_guard = self.begin_shared_file_mutation(&[hash.0])?;
                let receive = self.local_mutations.submit_withdrawal(
                    self,
                    file_hash,
                    path,
                    None,
                    false,
                    manifest_guard,
                    stripe_guard,
                )?;
                receive
                    .await
                    .map_err(|_| anyhow::anyhow!("local withdrawal worker stopped"))?
            }
            .await;
            match result {
                Err(error)
                    if matches!(
                        error.downcast_ref::<super::LocalMutationError>(),
                        Some(super::LocalMutationError::Busy)
                    ) =>
                {
                    self.local_mutations
                        .wait_for_completion(capacity_revision)
                        .await?;
                    self.stable_category_root_epoch().await;
                }
                other => return other,
            }
        }
    }
    /// Fence one or two content identities through durable and cache publication.
    pub fn begin_shared_file_mutation(
        &self,
        hashes: &[[u8; 16]],
    ) -> anyhow::Result<super::SharedFileMutation> {
        self.share_eligibility.begin_mutation(hashes)
    }
    /// Fence stale catalog candidates across an in-flight root transaction.
    pub async fn begin_category_root_mutation(&self) -> anyhow::Result<CategoryRootMutation> {
        loop {
            let epoch = self.stable_category_root_epoch().await;
            // Serialize the transition with the final epoch check and catalog write.
            let _catalog = self.shared_catalog.write().await;
            if self.category_root_epoch.load(Ordering::Acquire) != epoch {
                continue;
            }
            let next = epoch
                .checked_add(2)
                .ok_or_else(|| anyhow::anyhow!("category root generation is exhausted"))?
                - 1;
            self.category_root_epoch.store(next, Ordering::Release);
            let previously_dirty = self.category_root_dirty.swap(true, Ordering::AcqRel);
            return Ok(CategoryRootMutation {
                epoch: Arc::clone(&self.category_root_epoch),
                ready: Arc::clone(&self.category_root_epoch_ready),
                clean_epoch: (!previously_dirty).then_some(next + 1),
            });
        }
    }

    /// Clear a scoped root fence only after its publication and only at its epoch.
    pub async fn finish_scoped_root_publication(&self, epoch: u64) {
        let catalog = self.shared_catalog.write().await;
        let cleared = self.category_root_epoch.load(Ordering::Acquire) == epoch
            && self.category_root_dirty.swap(false, Ordering::AcqRel);
        drop(catalog);
        if cleared {
            self.notify_shared_publish_demand_changed();
        }
    }

    async fn stable_category_root_epoch(&self) -> u64 {
        loop {
            let notified = self.category_root_epoch_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let epoch = self.category_root_epoch.load(Ordering::Acquire);
            if epoch % 2 == 0 {
                return epoch;
            }
            notified.await;
        }
    }

    /// Watch one root-affected hash while its replacement is resolved.
    pub async fn watch_category_catalog_hash(&self, hash: [u8; 16]) -> anyhow::Result<(u64, u64)> {
        loop {
            let epoch = self.stable_category_root_epoch().await;
            let mut catalog = self.shared_catalog.write().await;
            if self.category_root_epoch.load(Ordering::Acquire) != epoch {
                continue;
            }
            let watch = catalog
                .watch_category_hash(hash)
                .ok_or_else(|| anyhow::anyhow!("catalog watch sequence exhausted"))?;
            return Ok((epoch, watch));
        }
    }

    /// Apply a worker decision only if no newer catalog publisher won the race.
    pub async fn publish_category_catalog_decision(
        &self,
        hash: [u8; 16],
        expected: (u64, u64),
        decision: CategoryCatalogDecision,
    ) -> anyhow::Result<bool> {
        if !matches!(decision, CategoryCatalogDecision::Keep) {
            // The root worker's local/partial projection cannot exclude an
            // independent internal payload. Transfer fresh selection to the
            // same retained owner, keeping its final watch/root CAS.
            drop(decision);
            return self
                .persist_category_publication(Ed2kHash::from_bytes(hash), expected)
                .await;
        }
        let mut catalog = self.shared_catalog.write().await;
        if self.category_root_epoch.load(Ordering::Acquire) != expected.0
            || !catalog.finish_category_watch(hash, expected.1)
        {
            return Ok(false);
        }
        drop(catalog);
        self.notify_shared_publish_demand_changed();
        Ok(true)
    }

    /// Reconcile one hash after a watcher changes its root membership. A
    /// local share takes precedence over an independently servable download.
    pub async fn refresh_shared_catalog_entry(&self, file_hash: &str) -> anyhow::Result<()> {
        self.persist_content_metadata(file_hash.parse()?, None, None)
            .await
    }

    /// Rebuild complete offers after a root scan changes membership. Verified
    /// in-progress download entries and compatibility hints stay in the catalog.
    pub async fn refresh_complete_shared_catalog(&self) -> anyhow::Result<usize> {
        loop {
            let root_epoch = self.stable_category_root_epoch().await;
            let Some(stripes) = self.share_eligibility.full_rebuild_snapshot()? else {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            };
            let metadata = self.metadata.clone();
            let mut rebuilt = tokio::task::spawn_blocking(move || {
                let mut rebuilt =
                    super::transfer_sql::completed_catalog_from_metadata_store(&metadata)?;
                // The full catalog rebuild remains a separate scale target;
                // it must never hydrate all historical execution manifests.
                let mut after = None;
                loop {
                    let page = metadata.download_publish_entries_after(after.as_deref(), 200)?;
                    if page.is_empty() {
                        break;
                    }
                    for entry in &page {
                        if let Some(source) =
                            metadata.partial_share_for_category_reconciliation(&entry.file_hash)?
                        {
                            let hash = Ed2kHash::from_str(&entry.file_hash)?;
                            if rebuilt.entry_by_hash(&hash).is_none() {
                                rebuilt.push(Ed2kSharedEntry::from_partial_share(source));
                            }
                        }
                    }
                    after = page.last().map(|entry| entry.file_hash.clone());
                }
                Ok::<_, anyhow::Error>(rebuilt)
            })
            .await??;
            let mut after_job = None;
            loop {
                let page = self
                    .payload_catalog_page(after_job, super::STARTUP_SHARED_CATALOG_BATCH)
                    .await?;
                for entry in page.entries {
                    let hash = entry.file_hash.parse::<Ed2kHash>()?;
                    if rebuilt
                        .entry_by_hash(&hash)
                        .is_none_or(|old| !old.verified_complete)
                    {
                        rebuilt.upsert_verified(hash, Some(entry));
                    }
                }
                let Some(cursor) = page.cursor else { break };
                anyhow::ensure!(
                    Some(cursor) > after_job,
                    "payload catalog cursor did not advance"
                );
                after_job = Some(cursor);
                tokio::task::yield_now().await;
            }
            let count = rebuilt.completed_verified_len();
            let mut catalog = self.shared_catalog.write().await;
            if self.category_root_epoch.load(Ordering::Acquire) != root_epoch {
                drop(catalog);
                continue;
            }
            if !self
                .share_eligibility
                .publish_full_rebuild(&stripes, &mut catalog, &mut rebuilt)
            {
                drop(catalog);
                continue;
            }
            self.category_root_dirty.store(false, Ordering::Release);
            drop(catalog);
            self.note_shared_catalog_entries_changed();
            self.notify_shared_publish_demand_changed();
            return Ok(count);
        }
    }

    /// Borrow the shared catalog used by server-session advertisement and
    /// listener-side upload serving.
    #[must_use]
    pub fn shared_catalog(&self) -> Ed2kSharedCatalog {
        Arc::clone(&self.shared_catalog)
    }

    /// Join a cancelled batch read before releasing the profile lease.
    pub async fn drain_shared_eligibility(&self) -> anyhow::Result<()> {
        let provider = self.shared_catalog.read().await.eligibility();
        if let Some(provider) = provider {
            provider.drain().await?;
        }
        Ok(())
    }

    /// Seal and join accepted local SQL/publication units before profile release.
    pub async fn drain_local_mutations(&self) -> anyhow::Result<()> {
        self.local_mutations.seal_and_drain().await
    }

    /// Admit a bounded outbound candidate batch before spawning network work.
    /// A later root change does not revoke already-admitted work.
    pub async fn admit_shared_hashes(
        &self,
        hashes: &[[u8; 16]],
        complete_only: bool,
    ) -> anyhow::Result<Option<Vec<bool>>> {
        anyhow::ensure!(
            hashes.len() <= 200,
            "shared admission batch exceeds 200 hashes"
        );
        let provider = self.shared_catalog.read().await.eligibility();
        let Some(provider) = provider else {
            return Ok(Some(vec![true; hashes.len()]));
        };
        let epoch = provider.epoch();
        let Some(stripes) = provider.stripe_snapshot(hashes) else {
            return Ok(None);
        };
        if provider.requires_revalidation() {
            let mut allowed = Vec::with_capacity(hashes.len());
            let mut offset = 0;
            while offset < hashes.len() {
                let end = (offset + 2).min(hashes.len());
                let chunk = &hashes[offset..end];
                let Some(batch) = provider.try_batch(chunk).await? else {
                    return Ok(None);
                };
                let count = batch.complete.len();
                if count == 0 {
                    return Ok(None);
                }
                allowed.extend(
                    batch
                        .complete
                        .iter()
                        .zip(batch.partial.iter())
                        .map(|(complete, partial)| {
                            *complete || (!complete_only && partial.is_some())
                        }),
                );
                offset += count;
            }
            let catalog = self.shared_catalog.read().await;
            if !catalog.admit_revalidated_epoch(epoch, &stripes) {
                return Ok(None);
            }
            Ok(Some(allowed))
        } else {
            let catalog = self.shared_catalog.read().await;
            if !catalog.admit_clean_epoch(epoch, &stripes) {
                return Ok(None);
            }
            Ok(Some(vec![true; hashes.len()]))
        }
    }

    /// Return the current verified shared-catalog entry count without walking
    /// persisted manifests. This is used by liveness/status surfaces that must
    /// stay cheap while a large shared-library hash is in progress.
    pub async fn shared_catalog_count(&self) -> usize {
        self.shared_catalog.read().await.len()
    }

    /// Hydrate one bounded completed-catalog cohort after startup reconciliation
    /// has validated persisted filesystem authority and before any external
    /// surface can observe it.
    pub async fn hydrate_initial_shared_catalog(&self) -> anyhow::Result<usize> {
        self.hydrate_initial_shared_catalog_page(super::STARTUP_SHARED_CATALOG_BATCH)
            .await
    }

    pub(super) async fn hydrate_initial_shared_catalog_page(
        &self,
        limit: usize,
    ) -> anyhow::Result<usize> {
        if !self
            .shared_catalog_hydration_pending
            .swap(false, Ordering::AcqRel)
        {
            return Ok(0);
        }

        let result = async {
            let metadata = self.metadata.clone();
            let page = tokio::task::spawn_blocking(move || {
                super::transfer_sql::completed_catalog_page_from_metadata_store(
                    &metadata, None, limit,
                )
            })
            .await??;
            let mut has_more = page.has_more;
            let cursor = has_more.then_some(page.cursor).flatten();
            let mut hydrated = 0usize;
            for entry in page.entries {
                if self
                    .insert_hydrated_completed_entry_if_current(entry)
                    .await?
                {
                    hydrated = hydrated.saturating_add(1);
                }
            }
            *self
                .shared_catalog_hydration_cursor
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = cursor;
            if !has_more {
                self.shared_local_hydration_done
                    .store(true, Ordering::Release);
                let (count, more) = self.hydrate_payload_catalog_page(limit).await?;
                hydrated += count;
                has_more = more;
            }
            self.shared_catalog_hydration_pending
                .store(has_more, Ordering::Release);
            if hydrated > 0 {
                self.note_shared_catalog_entries_changed();
                self.notify_shared_publish_demand_changed();
            }
            Ok(hydrated)
        }
        .await;

        if result.is_err() {
            self.shared_catalog_hydration_pending
                .store(true, Ordering::Release);
        }
        result
    }

    /// Append persisted catalog pages remaining after the explicit initial
    /// cohort. This work runs off the async executor and yields between bounded
    /// pages so normal network operation can proceed concurrently.
    pub async fn hydrate_shared_catalog(&self) -> anyhow::Result<usize> {
        const HYDRATION_PAGE_SIZE: usize = super::STARTUP_SHARED_CATALOG_BATCH;

        if !self
            .shared_catalog_hydration_pending
            .swap(false, Ordering::AcqRel)
        {
            return Ok(0);
        }

        let result = async {
            let mut after_hash = self
                .shared_catalog_hydration_cursor
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let mut hydrated = 0usize;
            if !self.shared_local_hydration_done.load(Ordering::Acquire) {
                loop {
                    let metadata = self.metadata.clone();
                    let page_after = after_hash.clone();
                    let page = tokio::task::spawn_blocking(move || {
                        super::transfer_sql::completed_catalog_page_from_metadata_store(
                            &metadata,
                            page_after.as_deref(),
                            HYDRATION_PAGE_SIZE,
                        )
                    })
                    .await??;
                    if page.cursor.is_none() {
                        *self
                            .shared_catalog_hydration_cursor
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
                        break;
                    }

                    let has_more = page.has_more;
                    let next_after = page.cursor;
                    let mut inserted = 0usize;
                    for entry in page.entries {
                        if self
                            .insert_hydrated_completed_entry_if_current(entry)
                            .await?
                        {
                            inserted = inserted.saturating_add(1);
                        }
                    }
                    if inserted > 0 {
                        self.note_shared_catalog_entries_changed();
                        self.notify_shared_publish_demand_changed();
                        hydrated = hydrated.saturating_add(inserted);
                    }
                    after_hash = next_after;
                    *self
                        .shared_catalog_hydration_cursor
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = after_hash.clone();

                    if !has_more {
                        *self
                            .shared_catalog_hydration_cursor
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }
            self.shared_local_hydration_done
                .store(true, Ordering::Release);
            loop {
                let (count, more) = self
                    .hydrate_payload_catalog_page(HYDRATION_PAGE_SIZE)
                    .await?;
                hydrated += count;
                if !more {
                    break;
                }
                tokio::task::yield_now().await;
            }
            Ok(hydrated)
        }
        .await;

        if result.is_err() {
            self.shared_catalog_hydration_pending
                .store(true, Ordering::Release);
        }
        result
    }

    async fn hydrate_payload_catalog_page(&self, limit: usize) -> anyhow::Result<(usize, bool)> {
        let after = *self
            .shared_payload_hydration_cursor
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let epoch = self.stable_category_root_epoch().await;
        let snapshot = self
            .share_eligibility
            .full_rebuild_snapshot()?
            .ok_or_else(|| anyhow::anyhow!("payload hydration overlaps a content mutation"))?;
        let page = self.payload_catalog_page(after, limit).await?;
        let mut catalog = self.shared_catalog.write().await;
        anyhow::ensure!(
            self.category_root_epoch.load(Ordering::Acquire) == epoch,
            "payload hydration overlaps a root mutation"
        );
        let inserted = self
            .share_eligibility
            .publish_payload_page(&snapshot, &mut catalog, page.entries)?
            .ok_or_else(|| anyhow::anyhow!("payload hydration overlaps a content mutation"))?;
        drop(catalog);
        if let Some(cursor) = page.cursor {
            anyhow::ensure!(
                Some(cursor) > after,
                "payload hydration cursor did not advance"
            );
            *self
                .shared_payload_hydration_cursor
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(cursor);
        }
        if inserted > 0 {
            self.note_shared_catalog_entries_changed();
            self.notify_shared_publish_demand_changed();
        }
        Ok((inserted, page.cursor.is_some()))
    }

    pub(super) async fn insert_hydrated_completed_entry_if_current(
        &self,
        entry: Ed2kSharedEntry,
    ) -> anyhow::Result<bool> {
        let Ok(file_hash) = Ed2kHash::from_str(&entry.file_hash) else {
            return Ok(false);
        };
        let _guard = self.lock_content(&entry.file_hash).await;
        loop {
            let root_epoch = self.stable_category_root_epoch().await;
            let Some(manifest) = self
                .load_serving_view_optional_unlocked(&entry.file_hash, None)
                .await?
            else {
                return Ok(false);
            };
            if !hydrated_entry_matches_serving_view(&entry, &manifest) {
                return Ok(false);
            }
            let mut catalog = self.shared_catalog.write().await;
            if self.category_root_epoch.load(Ordering::Acquire) != root_epoch {
                drop(catalog);
                continue;
            }
            if catalog.entry_by_hash(&file_hash).is_some() {
                return Ok(false);
            }
            catalog.upsert_verified(file_hash, Some(entry));
            return Ok(true);
        }
    }

    pub(super) async fn insert_hydrated_incomplete_entry_if_current(
        &self,
        snapshot: &Ed2kResumeManifest,
    ) -> anyhow::Result<bool> {
        let Ok(file_hash) = Ed2kHash::from_str(&snapshot.file_hash) else {
            return Ok(false);
        };
        let _guard = self.lock_content(&snapshot.file_hash).await;
        let Some(manifest) = self.load_manifest_optional_unlocked(snapshot.token).await? else {
            return Ok(false);
        };
        if manifest.completed || !manifest_has_servable_payload_authority(&manifest) {
            return Ok(false);
        }
        let entry = Ed2kSharedEntry::from_manifest(&manifest);
        let mut catalog = self.shared_catalog.write().await;
        if catalog.entry_by_hash(&file_hash).is_some() {
            return Ok(false);
        }
        catalog.upsert_verified(file_hash, Some(entry));
        drop(catalog);
        self.note_shared_catalog_entries_changed();
        Ok(true)
    }

    /// Replace compatibility-hint catalog entries while preserving verified
    /// local files loaded from manifests.
    pub async fn replace_catalog_hints(&self, hashes: &[PopularHash]) {
        let mut preserved_verified = {
            let guard = self.shared_catalog.read().await;
            guard
                .iter()
                .filter(|entry| !entry.compatibility_hint)
                .cloned()
                .collect::<Vec<_>>()
        };
        preserved_verified.extend(hashes.iter().filter_map(Ed2kSharedEntry::from_popular_hash));
        let mut guard = self.shared_catalog.write().await;
        guard.replace_with(dedupe_entries(preserved_verified));
        self.note_shared_catalog_entries_changed();
    }

    pub(super) async fn upsert_verified_catalog_entry(&self, manifest: &Ed2kResumeManifest) {
        self.upsert_verified_catalog_entry_with_media_refresh(manifest, true)
            .await;
    }

    pub(super) async fn upsert_verified_catalog_entry_cached(&self, manifest: &Ed2kResumeManifest) {
        self.upsert_verified_catalog_entry_with_media_refresh(manifest, false)
            .await;
    }

    async fn upsert_verified_catalog_entry_with_media_refresh(
        &self,
        manifest: &Ed2kResumeManifest,
        refresh_missing_media: bool,
    ) {
        let Ok(file_hash) = Ed2kHash::from_str(&manifest.file_hash) else {
            return;
        };
        loop {
            let root_epoch = self.stable_category_root_epoch().await;
            // A download may acquire verified parts while the same hash is already
            // shared as a complete local file. The local file owns the effective
            // protocol entry until its root membership is withdrawn.
            match self
                .metadata
                .active_local_catalog_entry(&manifest.file_hash)
            {
                Ok(Some(mut local)) => {
                    let source = match self.first_present_shared_source(&manifest.file_hash).await {
                        Ok(source) => source,
                        Err(error) => {
                            tracing::warn!(%error, "failed to validate local share precedence");
                            return;
                        }
                    };
                    let Some(source) = source else {
                        // A stale local path cannot displace verified download parts.
                        if self
                            .upsert_partial_catalog_entry(
                                manifest,
                                file_hash,
                                refresh_missing_media,
                                Some(root_epoch),
                            )
                            .await
                        {
                            return;
                        }
                        continue;
                    };
                    if let Some(name) = emulebb_metadata::NativePath::from(source.path.as_path())
                        .display_file_name()
                    {
                        local.display_name = name;
                    }
                    match super::transfer_sql::shared_entry_from_catalog_entry(local) {
                        Ok(entry) => {
                            let mut catalog = self.shared_catalog.write().await;
                            if self.category_root_epoch.load(Ordering::Acquire) != root_epoch {
                                drop(catalog);
                                continue;
                            }
                            catalog.upsert_verified(file_hash, Some(entry));
                            self.note_shared_catalog_entries_changed();
                        }
                        Err(error) => {
                            tracing::warn!(%error, "failed to project local shared entry")
                        }
                    }
                    return;
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, "failed to resolve local share precedence");
                    return;
                }
            }
            if self
                .upsert_partial_catalog_entry(
                    manifest,
                    file_hash,
                    refresh_missing_media,
                    Some(root_epoch),
                )
                .await
            {
                return;
            }
        }
    }

    async fn upsert_partial_catalog_entry(
        &self,
        manifest: &Ed2kResumeManifest,
        file_hash: Ed2kHash,
        refresh_missing_media: bool,
        expected_root_epoch: Option<u64>,
    ) -> bool {
        // Build the replacement entry (if any) before taking the write lock so the
        // lock hold covers only the in-place upsert.
        let mut new_entry = manifest_has_servable_payload_authority(manifest)
            .then(|| Ed2kSharedEntry::from_manifest(manifest));
        if let Some(entry) = new_entry.as_mut() {
            let cached = self
                .metadata
                .transfer_media_metadata(&manifest.file_hash)
                .ok()
                .flatten()
                .filter(|media| {
                    media.extractor_version == super::transfer_sql::MEDIA_METADATA_EXTRACTOR_VERSION
                });
            entry.media = if let Some(cached) = cached {
                super::transfer_sql::media_from_metadata(cached)
            } else if manifest.completed && refresh_missing_media {
                let path = match manifest.delivered_path.as_deref() {
                    Some(path) => path.to_path_buf(),
                    None => match self.payload_path(manifest.token.job_id) {
                        Ok(path) => path,
                        Err(error) => {
                            tracing::warn!(%error,"verified payload storage is unavailable");
                            return false;
                        }
                    },
                };
                let display_name = manifest.display_name.clone();
                let media = tokio::task::spawn_blocking(move || {
                    super::media_metadata::extract_media_metadata(&path, &display_name)
                })
                .await
                .unwrap_or_default();
                let persisted = super::transfer_sql::media_to_metadata(
                    &media,
                    super::transfer_sql::MEDIA_METADATA_EXTRACTOR_VERSION,
                );
                if let Err(error) = self
                    .metadata
                    .update_transfer_media_metadata(&manifest.file_hash, &persisted)
                {
                    tracing::warn!(
                        file_hash = %manifest.file_hash,
                        "failed to persist shared media metadata: {error:#}"
                    );
                }
                media
            } else {
                Ed2kMediaMetadata::default()
            };
        }
        // The caller's progress may be newer than SQL while its AICH authority
        // is older. Preserve membership/media/MD4 state, but do not advertise a
        // root retired by local/import acceptance during the work above.
        // Lock order: catalog -> servable-hash cache -> metadata connection.
        // The identity-only callback acquires no further locks and does no I/O.
        let mut entries = Arc::clone(&self.shared_catalog).write_owned().await;
        if expected_root_epoch
            .is_some_and(|epoch| self.category_root_epoch.load(Ordering::Acquire) != epoch)
        {
            return false;
        }
        let metadata = self.metadata.clone();
        let token = manifest.token;
        let generation = Arc::clone(&self.shared_catalog_generation);
        let hashes = Arc::clone(&self.servable_shared_hash_cache);
        let published = tokio::task::spawn_blocking(move || {
            let mut hashes = hashes.lock().expect("servable hash cache mutex poisoned");
            metadata.publish_download_job_aich_identity(token, |identity| {
                if let Some(entry) = new_entry.as_mut() {
                    entry.aich_root = identity.root;
                }
                entries.upsert_verified(file_hash, new_entry);
                generation.fetch_add(1, Ordering::AcqRel);
                hashes.hashes = None;
                Ok(())
            })
        })
        .await;
        match published {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "failed to fence shared AICH identity"),
            Err(error) => tracing::warn!(%error, "shared AICH publication task panicked"),
        }
        true
    }

    /// Remove a locally verified file from the live serving/advertisement
    /// catalog while preserving compatibility hints for the same hash.
    pub async fn remove_verified_catalog_entry(&self, file_hash: &str) {
        let Ok(file_hash) = Ed2kHash::from_str(file_hash) else {
            return;
        };
        let mut entries = self.shared_catalog.write().await;
        entries.upsert_verified(file_hash, None);
        self.note_shared_catalog_entries_changed();
    }

    pub(super) fn note_shared_catalog_entries_changed(&self) {
        self.shared_catalog_generation
            .fetch_add(1, Ordering::AcqRel);
        self.servable_shared_hash_cache.lock().unwrap().hashes = None;
    }
}

fn hydrated_entry_matches_serving_view(
    entry: &Ed2kSharedEntry,
    manifest: &super::Ed2kFileServingView,
) -> bool {
    manifest.has_payload_authority
        && manifest.completed
        && entry.verified_complete
        && entry.file_hash == manifest.file_hash
        && entry.display_name == manifest.display_name
        && entry.file_size == manifest.file_size
        && entry.aich_root == manifest.aich_root
        && entry.upload_priority == manifest.upload_priority
        && entry.auto_upload_priority == manifest.auto_upload_priority
        && entry.comment == manifest.comment
        && entry.rating == manifest.rating
}

fn manifest_has_servable_payload_authority(manifest: &Ed2kResumeManifest) -> bool {
    if manifest.final_rehash_pending {
        return false;
    }
    if !manifest.completed {
        return manifest.md4_hashset_acquired && !manifest.verified_ranges.is_empty();
    }
    manifest.payload_fingerprint.is_some()
}

fn dedupe_entries(entries: Vec<Ed2kSharedEntry>) -> Vec<Ed2kSharedEntry> {
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::with_capacity(entries.len());
    for entry in entries.into_iter().rev() {
        if seen.insert((entry.file_hash.clone(), entry.compatibility_hint)) {
            deduped.push(entry);
        }
    }
    deduped.reverse();
    deduped
}

#[cfg(test)]
mod upsert_collapse_tests {
    //! Proof that the collapsed in-place upsert
    //! ([`IndexedSharedCatalog::retain_push_dedup`]) yields a catalog byte-identical
    //! to the previous `retain` -> `to_vec` (whole-catalog deep clone) -> `dedupe`
    //! -> `replace_with` chain, for every mutation shape the upsert can take.

    use super::super::IndexedSharedCatalog;
    use super::dedupe_entries;
    use crate::ed2k_transfer::Ed2kSharedEntry;
    use emulebb_kad_proto::Ed2kHash;
    use std::str::FromStr;

    fn hex_hash(nibble: u8) -> String {
        std::iter::repeat_n(format!("{nibble:x}{nibble:x}"), 16).collect()
    }

    /// One entry; `marker` (carried in `all_time_uploaded_bytes`) makes otherwise
    /// same-hash instances distinguishable so a wrong dedupe survivor is caught.
    fn entry(nibble: u8, hint: bool, marker: u64) -> Ed2kSharedEntry {
        Ed2kSharedEntry {
            file_hash: hex_hash(nibble),
            display_name: format!("file-{nibble}.bin"),
            file_size: 1_000,
            verified_complete: !hint,
            verified_ranges: Vec::new(),
            compatibility_hint: hint,
            source_count_hint: None,
            aich_root: None,
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
            media: Default::default(),
            all_time_uploaded_bytes: marker,
            complete_parts: Vec::new(),
            publish: Default::default(),
        }
    }

    /// Run BOTH the exact old chain and the new collapsed method over the same
    /// start + upsert, assert the resulting entry list (contents AND order) and the
    /// by-hash index are identical, and return the collapsed result.
    fn assert_upsert_identical(
        start: Vec<Ed2kSharedEntry>,
        target_hash: &str,
        new_entry: Option<Ed2kSharedEntry>,
    ) -> IndexedSharedCatalog {
        // Old behavior: retain -> push -> deep-clone via to_vec -> dedupe ->
        // replace_with, exactly as `upsert_verified_catalog_entry` used to do.
        let old = {
            let mut cat = IndexedSharedCatalog::from_entries(start.clone());
            cat.retain(|e| e.file_hash != target_hash || e.compatibility_hint);
            if let Some(e) = new_entry.clone() {
                cat.push(e);
            }
            let deduped = dedupe_entries(cat.to_vec());
            cat.replace_with(deduped);
            cat
        };
        // New behavior: single in-place collapse, no whole-catalog deep clone.
        let new = {
            let mut cat = IndexedSharedCatalog::from_entries(start);
            cat.retain_push_dedup(
                |e| e.file_hash != target_hash || e.compatibility_hint,
                new_entry,
                dedupe_entries,
            );
            cat
        };

        // Entry list: same contents AND same order (the ordered Vec is the source
        // of truth for cursor/rank/REST).
        assert_eq!(new.len(), old.len(), "entry count differs");
        assert_eq!(&new[..], &old[..], "entry contents or order differ");
        assert_eq!(
            new.completed_verified_len(),
            new.iter()
                .filter(|entry| !entry.compatibility_hint && entry.verified_complete)
                .count(),
            "cached completed count differs",
        );

        // Index: both internally consistent, and every hash resolves to the same
        // slot (or to nothing) in both — hints excluded, first occurrence wins.
        old.assert_index_consistent();
        new.assert_index_consistent();
        for e in old.iter() {
            if let Ok(hash) = e.parsed_hash() {
                assert_eq!(
                    new.index_by_hash(&hash),
                    old.index_by_hash(&hash),
                    "index slot differs for hash {}",
                    e.file_hash
                );
            }
        }
        new
    }

    #[test]
    fn insert_brand_new_entry() {
        let result = assert_upsert_identical(
            vec![entry(1, false, 10), entry(2, false, 20)],
            &hex_hash(3),
            Some(entry(3, false, 30)),
        );
        // Appended at the tail, index resolves it.
        assert_eq!(result.len(), 3);
        let idx = result
            .index_by_hash(&Ed2kHash::from_str(&hex_hash(3)).unwrap())
            .unwrap();
        assert_eq!(result[idx].all_time_uploaded_bytes, 30);
    }

    #[test]
    fn replace_existing_entry_same_hash_moves_to_tail() {
        // The old non-hint entry for the hash is dropped and the new one appended,
        // so the surviving order is [2, 1'] — order preservation must match.
        let result = assert_upsert_identical(
            vec![entry(1, false, 10), entry(2, false, 20)],
            &hex_hash(1),
            Some(entry(1, false, 99)),
        );
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].file_hash, hex_hash(2));
        assert_eq!(result[1].file_hash, hex_hash(1));
        assert_eq!(result[1].all_time_uploaded_bytes, 99);
    }

    #[test]
    fn duplicate_hash_collapses_to_last_occurrence() {
        // A pre-existing duplicate (no upsert append) must collapse exactly as the
        // reverse-scan dedupe did: the LAST occurrence survives, order preserved.
        let result = assert_upsert_identical(
            vec![
                entry(1, false, 10),
                entry(1, false, 20),
                entry(2, false, 30),
            ],
            &hex_hash(5),
            None,
        );
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].file_hash, hex_hash(1));
        assert_eq!(result[0].all_time_uploaded_bytes, 20);
        assert_eq!(result[1].file_hash, hex_hash(2));
    }

    #[test]
    fn hint_and_verified_shadowing_preserved() {
        // A hint for the upserted hash survives retain (hints are exempt), the new
        // verified entry is appended, and the index targets only the verified entry.
        let result = assert_upsert_identical(
            vec![entry(1, true, 10), entry(1, false, 20), entry(2, true, 30)],
            &hex_hash(1),
            Some(entry(1, false, 99)),
        );
        assert_eq!(result.len(), 3);
        // hash 1 resolves to the verified (non-hint) entry only.
        let idx = result
            .index_by_hash(&Ed2kHash::from_str(&hex_hash(1)).unwrap())
            .unwrap();
        assert!(!result[idx].compatibility_hint);
        assert_eq!(result[idx].all_time_uploaded_bytes, 99);
        // hash 2 is hint-only, never indexed.
        assert!(
            result
                .index_by_hash(&Ed2kHash::from_str(&hex_hash(2)).unwrap())
                .is_none()
        );
    }
}
