//! Bounded post-commit content projection shared by exact-job finalizers.
use super::*;
use crate::ed2k_transfer as transfer;
use std::sync::atomic::{AtomicU64, Ordering};

enum Selection {
    Ready(Option<Box<transfer::Ed2kSharedEntry>>),
    NeedProbe,
}
type PayloadProof = (
    emulebb_metadata::MetadataDownloadPayload,
    Option<super::job_payload::PhysicalProof>,
);
pub(super) struct PublicationGuards {
    pub content: transfer::store::ScopedLockGuard<String>,
    pub stripe: transfer::SharedFileMutation,
    pub job: Option<(
        emulebb_metadata::JobToken,
        transfer::store::ScopedLockGuard<emulebb_metadata::JobId>,
    )>,
}
pub(super) struct ContentPublication {
    watch: Option<([u8; 16], (u64, u64))>,
    stale_watch: std::cell::Cell<bool>,
    metadata: emulebb_metadata::MetadataStore,
    cache: Arc<
        tokio::sync::Mutex<
            std::collections::HashMap<emulebb_metadata::JobId, transfer::ResidentManifest>,
        >,
    >,
    catalog: transfer::Ed2kSharedCatalog,
    epoch: Arc<AtomicU64>,
    generation: Arc<AtomicU64>,
    hashes: Arc<std::sync::Mutex<transfer::ServableSharedHashCache>>,
    demand: Arc<AtomicU64>,
    notify: Arc<tokio::sync::Notify>,
    dirty: Arc<std::sync::atomic::AtomicBool>,
    locks: Arc<
        std::sync::Mutex<
            std::collections::HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>,
        >,
    >,
    eligibility: Arc<transfer::catalog::SharedEligibility>,
    job_locks: Arc<
        std::sync::Mutex<
            std::collections::HashMap<
                emulebb_metadata::JobId,
                std::sync::Weak<tokio::sync::Mutex<()>>,
            >,
        >,
    >,
}
impl ContentPublication {
    pub(super) fn new(runtime: &transfer::Ed2kTransferRuntime) -> Self {
        Self {
            watch: None,
            stale_watch: std::cell::Cell::new(false),
            metadata: runtime.metadata.clone(),
            cache: Arc::clone(&runtime.manifest_cache),
            catalog: Arc::clone(&runtime.shared_catalog),
            epoch: Arc::clone(&runtime.category_root_epoch),
            generation: Arc::clone(&runtime.shared_catalog_generation),
            hashes: Arc::clone(&runtime.servable_shared_hash_cache),
            demand: Arc::clone(&runtime.shared_publish_demand_revision),
            notify: Arc::clone(&runtime.shared_publish_demand_notify),
            dirty: Arc::clone(&runtime.category_root_dirty),
            locks: Arc::clone(&runtime.content_locks),
            eligibility: Arc::clone(&runtime.share_eligibility),
            job_locks: Arc::clone(&runtime.manifest_locks),
        }
    }
    pub(super) fn with_watch(mut self, hash: [u8; 16], watch: Option<(u64, u64)>) -> Self {
        self.watch = watch.map(|watch| (hash, watch));
        self
    }
    pub(super) fn watch_accepted(&self) -> bool {
        !self.stale_watch.get()
    }
    fn partial(
        &self,
        hash: &str,
        stored: Option<emulebb_metadata::MetadataPartialShare>,
    ) -> Result<Option<transfer::Ed2kSharedEntry>> {
        let token = self
            .metadata
            .capture_local_ingest_jobs(&[hash.to_owned()])?[0]
            .token;
        let live = {
            let cache = self.cache.blocking_lock();
            super::ingest::live_partial(token.and_then(|token| {
                cache
                    .get(&token.job_id)
                    .filter(|m| m.token == token)
                    .map(|m| &**m)
            }))?
        };
        Ok(live
            .unwrap_or(stored)
            .map(transfer::Ed2kSharedEntry::from_partial_share))
    }
    fn local(&self, hash: &str) -> Result<Option<transfer::Ed2kSharedEntry>> {
        let projection = self
            .metadata
            .local_ingest_projections(&[hash.to_owned()])?
            .pop()
            .expect("one content projection");
        drop(projection.partial);
        projection
            .complete
            .map(transfer::transfer_sql::shared_entry_from_catalog_entry)
            .transpose()
    }
    /// Select under the current content guard. Payload evidence is always
    /// rechecked against its captured token, exclusion barrier and exact row.
    fn select(&self, text: &str, prepared: Option<PayloadProof>) -> Result<Selection> {
        let (local, mut partial) = self.metadata.shared_path_projection(text)?;
        if self.metadata.library_sharing_enabled(text)? != Some(true) {
            drop(prepared);
            return Ok(Selection::Ready(
                (self.partial(text, partial)?).map(Box::new),
            ));
        }
        if local {
            drop(prepared);
            drop(partial);
            return Ok(Selection::Ready((self.local(text)?).map(Box::new)));
        }
        if let Some((candidate, proof)) = prepared {
            // Do not overlap a maximum partial with the payload exact-row
            // reread and native evidence. Reload only a needed fallback.
            drop(partial.take());
            let physical = match proof {
                Some(proof) => proof.admit(&self.metadata, &candidate)?,
                None => false,
            };
            if !physical && !self.metadata.download_payload_is_current(&candidate)? {
                return Ok(Selection::NeedProbe);
            }
            if physical {
                drop(partial);
                return Ok(Selection::Ready(Some(Box::new(
                    transfer::transfer_sql::shared_entry_from_catalog_entry(candidate.catalog)?,
                ))));
            }
            drop(candidate);
            let (local, fresh) = self.metadata.shared_path_projection(text)?;
            if local {
                drop(fresh);
                return Ok(Selection::Ready((self.local(text)?).map(Box::new)));
            }
            partial = fresh;
        } else if self.metadata.download_payload_candidate(text)?.is_some() {
            return Ok(Selection::NeedProbe);
        }
        Ok(Selection::Ready(
            (self.partial(text, partial)?).map(Box::new),
        ))
    }
    fn probe(&self, text: &str) -> Result<Option<PayloadProof>> {
        let Some(candidate) = self.metadata.download_payload_candidate(text)? else {
            return Ok(None);
        };
        let proof = super::job_payload::physical_proof(&candidate)?;
        Ok(Some((candidate, proof)))
    }
    fn publish_entries(
        &self,
        cut: u64,
        replacements: Vec<(
            emulebb_kad_proto::Ed2kHash,
            Option<transfer::Ed2kSharedEntry>,
        )>,
    ) -> Result<bool> {
        let mut entries = self.catalog.blocking_write();
        if self.epoch.load(Ordering::Acquire) != cut {
            return Ok(false);
        }
        if let Some((hash, expected)) = self.watch
            && (cut != expected.0 || !entries.finish_category_watch(hash, expected.1))
        {
            self.stale_watch.set(true);
            return Ok(true);
        }
        for (hash, mut next) in replacements {
            if let (Some(previous), Some(next)) = (entries.entry_by_hash(&hash), next.as_mut()) {
                next.publish = previous.publish.clone();
                next.all_time_uploaded_bytes = previous.all_time_uploaded_bytes;
            }
            entries.upsert_verified(hash, next);
        }
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.hashes
            .lock()
            .map_err(|_| LocalMutationError::Unknown)?
            .hashes = None;
        Ok(true)
    }
    fn notify(&self) {
        self.demand.fetch_add(1, Ordering::AcqRel);
        self.notify.notify_waiters();
    }
    /// Short work retains the original guards. Only the physical phase releases
    /// them, retaining a dirty fence and receipt through capacity waits.
    pub(super) fn publish(
        &self,
        hash: emulebb_kad_proto::Ed2kHash,
        lease: &mut CapacityLease,
        guards: PublicationGuards,
    ) -> Result<Option<transfer::store::ScopedLockGuard<emulebb_metadata::JobId>>> {
        let PublicationGuards {
            content,
            stripe,
            job,
        } = guards;
        let mut initial = Some((content, stripe));
        let job_token = job.as_ref().map(|(token, _)| *token);
        let mut job_guard = job.map(|(_, guard)| guard);
        let text = hash.to_string();
        for _ in 0..100 {
            if job_guard.is_none()
                && let Some(token) = job_token
            {
                job_guard = Some(
                    transfer::store::scoped_lock(&self.job_locks, token.job_id)
                        .blocking_lock_owned(),
                );
            }
            let (content, stripe) = match initial.take() {
                Some(guards) => guards,
                None => (
                    transfer::store::scoped_lock(&self.locks, text.clone()).blocking_lock_owned(),
                    self.eligibility.begin_mutation(&[hash.0])?,
                ),
            };
            let mut cut = self.epoch.load(Ordering::Acquire);
            if !cut.is_multiple_of(2) {
                drop(stripe);
                drop(content);
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            let (next, content, stripe) = match self.select(&text, None)? {
                Selection::Ready(next) => (next.map(|entry| *entry), content, stripe),
                Selection::NeedProbe => {
                    self.dirty.store(true, Ordering::Release);
                    drop(stripe);
                    drop(content);
                    drop(job_guard.take());
                    if !lease.is_filesystem() {
                        lease.enter_filesystem(128 * 1024, 2 * 1024 * 1024)?;
                    }
                    let prepared = self.probe(&text)?;
                    #[cfg(test)]
                    lease.pause_after_probe();
                    // Never park behind a long writer with an old physical proof.
                    if let Some(token) = job_token {
                        let Some(guard) =
                            transfer::store::scoped_lock(&self.job_locks, token.job_id)
                                .try_lock_owned()
                        else {
                            continue;
                        };
                        job_guard = Some(guard);
                    }
                    let Some(content) =
                        transfer::store::scoped_lock(&self.locks, text.clone()).try_lock_owned()
                    else {
                        continue;
                    };
                    let stripe = self.eligibility.begin_mutation(&[hash.0])?;
                    cut = self.epoch.load(Ordering::Acquire);
                    if !cut.is_multiple_of(2) {
                        continue;
                    }
                    let Selection::Ready(next) = self.select(&text, prepared)? else {
                        continue;
                    };
                    (next.map(|entry| *entry), content, stripe)
                }
            };
            let published = self.publish_entries(cut, vec![(hash, next)])?;
            drop(stripe);
            drop(content);
            if published {
                self.notify();
                return Ok(job_guard);
            }
        }
        Err(anyhow!("content publication could not stabilize"))
    }
    /// Completion/removal already made this job's internal payload ineligible.
    /// Keep the original content cut and use ordinary headroom, even when all
    /// physical slots are occupied. A different current payload belongs to its
    /// own admitted publisher; removing history must not overwrite that owner.
    pub(super) fn publish_terminal(
        &self,
        hash: emulebb_kad_proto::Ed2kHash,
        guards: PublicationGuards,
    ) -> Result<()> {
        let text = hash.to_string();
        for _ in 0..100 {
            let cut = self.epoch.load(Ordering::Acquire);
            if !cut.is_multiple_of(2) {
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            let next = match self.select(&text, None)? {
                Selection::Ready(next) => next.map(|entry| *entry),
                Selection::NeedProbe => return Ok(()),
            };
            if self.publish_entries(cut, vec![(hash, next)])? {
                drop(guards);
                self.notify();
                return Ok(());
            }
        }
        Err(anyhow!("terminal publication could not stabilize"))
    }
    /// Ingest already owns its one prepared representation lease and long-FS
    /// admission. Two sequential proofs/replacements fit its existing 4 MiB
    /// publication workspace; no ordinary reservation or new unit is admitted.
    pub(super) fn publish_prepared_pair(
        &self,
        hashes: &[String],
        _prepared: &super::ingest::PreparationLease,
    ) -> Result<()> {
        ensure!(
            !hashes.is_empty() && hashes.len() <= 2,
            "invalid ingest publication batch"
        );
        let mut ordered = hashes
            .iter()
            .map(|text| text.parse::<emulebb_kad_proto::Ed2kHash>())
            .collect::<Result<Vec<_>, _>>()?;
        ordered.sort_by_key(|hash| hash.0);
        ordered.dedup();
        let texts = ordered.iter().map(ToString::to_string).collect::<Vec<_>>();
        let keys = ordered.iter().map(|h| h.0).collect::<Vec<_>>();
        self.dirty.store(true, Ordering::Release);
        for _ in 0..100 {
            // All waits precede physical proofs. This also gives the retry a
            // bounded wait instead of repeatedly probing a busy content lock.
            let waits = texts
                .iter()
                .map(|text| {
                    transfer::store::scoped_lock(&self.locks, text.clone()).blocking_lock_owned()
                })
                .collect::<Vec<_>>();
            drop(waits);
            let mut proofs = Vec::with_capacity(texts.len());
            for text in &texts {
                let (local, partial) = self.metadata.shared_path_projection(text)?;
                drop(partial);
                proofs.push(if local { None } else { self.probe(text)? });
            }
            let mut guards = Vec::with_capacity(texts.len());
            for text in &texts {
                let Some(guard) =
                    transfer::store::scoped_lock(&self.locks, text.clone()).try_lock_owned()
                else {
                    break;
                };
                guards.push(guard);
            }
            if guards.len() != texts.len() {
                continue;
            }
            let stripe = self.eligibility.begin_mutation(&keys)?;
            let cut = self.epoch.load(Ordering::Acquire);
            if !cut.is_multiple_of(2) {
                drop(stripe);
                drop(guards);
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            let mut replacements = Vec::with_capacity(texts.len());
            for ((hash, text), proof) in ordered.iter().zip(&texts).zip(proofs) {
                let Selection::Ready(next) = self.select(text, proof)? else {
                    break;
                };
                replacements.push((*hash, next.map(|entry| *entry)));
            }
            if replacements.len() != texts.len() {
                continue;
            }
            let published = self.publish_entries(cut, replacements)?;
            drop(stripe);
            drop(guards);
            if published {
                self.notify();
                return Ok(());
            }
        }
        Err(anyhow!("ingest publication could not stabilize"))
    }
}
