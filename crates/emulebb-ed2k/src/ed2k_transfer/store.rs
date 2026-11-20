//! Manifest store, cache, and checkpoint helpers for the ED2K transfer runtime.

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::{JobId, JobToken};
use tokio::io::AsyncWriteExt;

use super::manifest::manifest_progress_bytes;
use super::{
    ED2K_EMBLOCK_SIZE, Ed2kResumeManifest, Ed2kTransferJob, Ed2kTransferRuntime, PAYLOAD_FILE_NAME,
};

const ED2K_RESUME_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(2);
// Batch the durable mid-piece progress checkpoint: persist once per this many
// received bytes (or on the interval above), instead of committing SQLite (a
// WAL fsync under `synchronous = FULL`) for every 180 K block. The crash-loss
// window is bounded to this many re-downloadable bytes per transfer — the
// same class of loss as eMule's ~1.5 MB in-memory write buffer that only
// flushes on threshold/part-completion — while state transitions
// (verified/failed/salvage/completion) still checkpoint immediately. The
// dirty pieces accumulated between checkpoints are tracked in
// `Ed2kManifestCheckpointState::dirty_piece_indexes`, so a batched checkpoint
// persists every piece touched since the last durable store.
const ED2K_RESUME_CHECKPOINT_BYTES: u64 = 8 * ED2K_EMBLOCK_SIZE;

impl Ed2kTransferRuntime {
    /// Flush and persist every cache-only download progress update.
    ///
    /// Callers must first quiesce or abort download writers so no new dirty
    /// progress can race this final checkpoint.
    pub async fn checkpoint_dirty_download_progress(&self) -> Result<usize> {
        let dirty_tokens = self
            .manifest_checkpoint_state
            .lock()
            .await
            .iter()
            .filter(|(_, state)| !state.dirty_piece_indexes.is_empty())
            .map(|(token, _)| *token)
            .collect::<Vec<_>>();
        let mut checkpointed = 0;

        for token in dirty_tokens {
            checkpointed += usize::from(self.checkpoint_download_progress(token).await?);
        }

        Ok(checkpointed)
    }

    /// Checkpoint one quiesced selection without scanning or flushing another
    /// active job. Both shutdown and ordinary slot retirement use this path.
    pub(super) async fn checkpoint_download_progress(&self, token: JobToken) -> Result<bool> {
        let manifest_guard = self.lock_manifest(token).await;
        let Some(current_piece) = self
            .manifest_checkpoint_state
            .lock()
            .await
            .get(&token)
            .and_then(|state| state.dirty_piece_indexes.first())
        else {
            return Ok(false);
        };
        let manifest = self
            .manifest_cache
            .lock()
            .await
            .get(&token.job_id)
            .filter(|manifest| manifest.token == token)
            .cloned()
            .with_context(|| {
                format!("dirty ED2K download {token:?} is missing its cached manifest")
            })?;
        // WHY: cached payload writes precede their row checkpoint, so restart
        // cannot observe progress beyond cleanly written payload bytes.
        let mut file = self.take_payload_handle(token).await?;
        file.flush().await?;
        self.store_payload_handle(token, file);
        self.store_manifest_piece_progress_unlocked(&manifest, current_piece, manifest_guard)
            .await
            .with_context(|| {
                format!("failed to checkpoint final ED2K download progress for {token:?}")
            })?;
        Ok(true)
    }

    /// Acquire the lifecycle gate for one transfer. Delivery, row-only
    /// removal, and destructive deletion must hold this gate before taking the
    /// manifest lock so their filesystem and persisted-state transitions
    /// cannot interleave.
    pub(super) async fn lock_lifecycle(&self, job_id: JobId) -> ScopedLockGuard<JobId> {
        scoped_lock(&self.lifecycle_locks, job_id)
            .lock_owned()
            .await
    }

    /// A job's generations share one I/O lock; unrelated cleanup never holds it.
    pub(super) async fn lock_manifest(&self, token: JobToken) -> ScopedLockGuard<JobId> {
        scoped_lock(&self.manifest_locks, token.job_id)
            .lock_owned()
            .await
    }

    /// Content publication uses a separate short lock, never a long job FS lock.
    pub(super) async fn lock_content(&self, file_hash: &str) -> ScopedLockGuard<String> {
        scoped_lock(&self.content_locks, file_hash.to_ascii_lowercase())
            .lock_owned()
            .await
    }

    pub(super) async fn load_manifest_or_rebuild_unlocked(
        &self,
        job: &Ed2kTransferJob,
        io: &ScopedLockGuard<JobId>,
    ) -> Result<super::ResidentManifest> {
        let cached = self
            .manifest_cache
            .lock()
            .await
            .get(&job.token.job_id)
            .filter(|manifest| manifest.token == job.token)
            .cloned();
        let manifest = if let Some(manifest) = cached {
            manifest
        } else {
            let super::local_mutation::job_read::JobReadResult::Execution(manifest) = self
                .read_job_metadata(super::local_mutation::job_read::JobRead::SelectExecution(
                    job.token,
                ))
                .await?
            else {
                unreachable!()
            };
            manifest.context("selected download has no execution geometry")?
        };
        anyhow::ensure!(
            manifest.file_hash == job.file_hash && manifest.file_size == job.file_size,
            "execution descriptor differs from admitted job"
        );
        if manifest.pieces.is_empty() {
            let mut manifest = manifest.edit()?;
            // Admission creates the job before payload geometry. Initialize only
            // this exact row; an absent job is never recreated by a callback.
            manifest.pieces = Ed2kResumeManifest::new(job).pieces;
            self.store_manifest_unlocked(&manifest, io.clone()).await?;
            return self.load_manifest_unlocked(job.token).await;
        }
        Ok(manifest)
    }

    pub(super) async fn load_manifest_optional_unlocked(
        &self,
        token: JobToken,
    ) -> Result<Option<super::ResidentManifest>> {
        if let Some(manifest) = self.manifest_cache.lock().await.get(&token.job_id).cloned() {
            anyhow::ensure!(
                manifest.token == token,
                "stale download execution generation"
            );
            return Ok(Some(manifest));
        }
        let super::local_mutation::job_read::JobReadResult::Execution(manifest) = self
            .read_job_metadata(super::local_mutation::job_read::JobRead::Execution(token))
            .await?
        else {
            unreachable!()
        };
        Ok(manifest)
    }

    /// Resolve a complete local share for read-only protocol views without
    /// introducing it into transfer mutation or checkpoint paths.
    pub(super) async fn load_serving_view_optional_unlocked(
        &self,
        file_hash: &str,
        token: Option<JobToken>,
    ) -> Result<Option<super::Ed2kFileServingView>> {
        // WHY: SQLite remembers verified bytes, but an offline replacement
        // can leave the selected path stale. Resolve a live sibling path or
        // fall through to an independently verified download payload.
        let local = if let Some(source) = self.first_present_shared_source(file_hash).await? {
            let metadata = self.metadata.clone();
            let expected_hash = file_hash.to_string();
            tokio::task::spawn_blocking(move || {
                let Some(instance) = metadata.local_file_instance(&source.metadata_path)? else {
                    return Ok(None);
                };
                if !instance.file_hash.eq_ignore_ascii_case(&expected_hash)
                    || instance.verified_fingerprint != source.fingerprint
                {
                    return Ok(None);
                }
                let mut content = metadata.verified_local_content_for_instance(instance)?;
                content.path = source.path;
                content.fingerprint = source.fingerprint;
                Ok::<_, anyhow::Error>(Some(content))
            })
            .await
            .context("ED2K local content load task panicked")??
        } else {
            None
        };
        let local_view = local.map(|content| {
            let display_name = emulebb_metadata::NativePath::from(content.path.as_path())
                .display_file_name()
                .unwrap_or(content.display_name);
            super::Ed2kFileServingView {
                job_token: None,
                file_hash: content.file_hash,
                display_name,
                file_size: content.file_size,
                piece_size: content.part_size,
                completed: true,
                md4_hashset_acquired: true,
                md4_hashset: content.md4_hashset,
                aich_hashset_acquired: content.aich_root.is_some()
                    && (content.file_size <= super::ED2K_PART_SIZE
                        || !content.aich_hashset.is_empty()),
                aich_root: content.aich_root,
                aich_hashset: content.aich_hashset,
                verified_ranges: vec![super::Ed2kSharedRange {
                    start: 0,
                    end: content.file_size,
                }],
                upload_priority: content.upload_priority,
                auto_upload_priority: content.auto_upload_priority,
                comment: content.comment,
                rating: content.rating,
                local_path: Some(content.path),
                local_fingerprint: Some(content.fingerprint),
                has_payload_authority: true,
            }
        });
        let view = if local_view.is_some() {
            local_view
        } else if let Some(token) = token {
            self.load_manifest_optional_unlocked(token)
                .await?
                .map(|manifest| super::Ed2kFileServingView::from(&*manifest))
        } else {
            None
        };
        self.authorize_serving_view_unlocked(file_hash, token, view)
            .await
    }

    /// Revalidate the selected view at admission while the manifest lock is held.
    pub(super) async fn authorize_serving_view_unlocked(
        &self,
        file_hash: &str,
        token: Option<JobToken>,
        view: Option<super::Ed2kFileServingView>,
    ) -> Result<Option<super::Ed2kFileServingView>> {
        if view.is_none() {
            return Ok(None);
        }
        let hash = file_hash.parse::<Ed2kHash>()?;
        let complete_only = view.as_ref().is_some_and(|value| value.completed);
        // Metadata and callback ownership for an unfinished job do not require
        // verified upload parts. Payload admission checks servability separately.
        if !complete_only {
            return Ok(view);
        }
        let Some(allowed) = self.admit_shared_hashes(&[hash.0], complete_only).await? else {
            return Ok(None);
        };
        if allowed[0] {
            return Ok(view);
        }
        if complete_only
            && let Some(token) = token
            && self.load_manifest_optional_unlocked(token).await?.is_some()
        {
            let partial =
                super::Ed2kFileServingView::from(&*self.load_aich_manifest_unlocked(token).await?);
            if !partial.completed && partial.has_payload_authority {
                let Some(allowed) = self.admit_shared_hashes(&[hash.0], false).await? else {
                    return Ok(None);
                };
                if allowed[0] {
                    return Ok(Some(partial));
                }
            }
        }
        Ok(None)
    }

    pub(super) async fn load_manifest_unlocked(
        &self,
        token: JobToken,
    ) -> Result<super::ResidentManifest> {
        self.load_manifest_optional_unlocked(token)
            .await?
            .with_context(|| format!("missing ED2K transfer metadata for job {}", token.job_id))
    }

    /// Merge only durable AICH identity into cached progress. Accepted local or
    /// import writers share SQLite's transaction fence, not this runtime lock.
    /// Never reload pieces/ranges or discard newer cache-only payload progress.
    pub(super) async fn load_aich_manifest_unlocked(
        &self,
        token: JobToken,
    ) -> Result<super::ResidentManifest> {
        let manifest = self.load_manifest_unlocked(token).await?;
        let file_hash = manifest.file_hash.clone();
        let metadata = self.metadata.clone();
        let identity =
            tokio::task::spawn_blocking(move || metadata.download_job_aich_identity(token))
                .await
                .context("AICH identity refresh task panicked")??
                .with_context(|| format!("missing AICH transfer identity for {file_hash}"))?;
        let origin = identity
            .origin
            .as_deref()
            .map(super::Ed2kAichRootOrigin::parse)
            .transpose()?;
        if manifest.aich_root != identity.root
            || manifest.aich_root_origin != origin
            || manifest.aich_trust_generation != identity.generation
        {
            let metadata = self.metadata.clone();
            let parsed_hash = file_hash.parse::<Ed2kHash>()?;
            let _category_fence = self.category_assignment_gate.read().await;
            let existing_category = self
                .manifest_cache
                .lock()
                .await
                .get(&token.job_id)
                .filter(|value| value.token == token)
                .map(|value| value.category_id);
            let category_id = if let Some(category) = existing_category {
                category
            } else {
                let metadata = metadata.clone();
                tokio::task::spawn_blocking(move || metadata.download_job_category(token.job_id))
                    .await
                    .context("category read task panicked")??
                    .context("missing transfer while publishing AICH identity")?
            };
            let resident_write = self.local_mutations.residents.reserve(token.job_id)?;
            let mut cache = Arc::clone(&self.manifest_cache).lock_owned().await;
            let cache_claim = cache.claim_insert()?;
            let mut manifest = cache
                .get(&token.job_id)
                .filter(|value| value.token == token)
                .cloned()
                .unwrap_or(manifest);
            let mut catalog = Arc::clone(&self.shared_catalog).write_owned().await;
            let generation = Arc::clone(&self.shared_catalog_generation);
            let corroboration = Arc::clone(&self.aich_root_corroboration);
            // Same publication order as owned decisions, omitting checkpoint
            // bookkeeping because identity refresh must preserve dirty pieces.
            return tokio::task::spawn_blocking(move || {
                let mut map = corroboration
                    .lock()
                    .expect("aich corroboration mutex poisoned");
                metadata.publish_download_job_state(token, |state| {
                    let identity = state.identity;
                    manifest.write_with(resident_write, |manifest| {
                        manifest.category_id = category_id;
                        super::aich_trust::merge_persisted_identity(manifest, &identity)
                    })?;
                    if manifest.aich_root_origin
                        != Some(super::Ed2kAichRootOrigin::NetworkConsensus)
                    {
                        map.remove(&token);
                    }
                    cache.insert_claimed(token.job_id, manifest.clone(), cache_claim);
                    let mut changed = false;
                    catalog.update_by_hash(&parsed_hash, |entry| {
                        if entry.aich_root != manifest.aich_root {
                            entry.aich_root = manifest.aich_root.clone();
                            changed = true;
                        }
                    });
                    if changed {
                        generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    }
                    Ok(manifest)
                })
            })
            .await
            .context("AICH identity publication task panicked")?;
        }
        Ok(manifest)
    }

    /// Run a read-only probe against the manifest WITHOUT cloning it on the
    /// (hot) cache-hit path; only a cache miss pays the full load. For
    /// per-block predicates like the salvage-mode check.
    pub(super) async fn probe_manifest_unlocked<R>(
        &self,
        token: JobToken,
        probe: impl FnOnce(&Ed2kResumeManifest) -> R,
    ) -> Result<R> {
        {
            let cache = self.manifest_cache.lock().await;
            if let Some(manifest) = cache
                .get(&token.job_id)
                .filter(|manifest| manifest.token == token)
            {
                return Ok(probe(manifest));
            }
        }
        let manifest = self.load_manifest_unlocked(token).await?;
        Ok(probe(&manifest))
    }

    /// Publish a single progress delta and its dirty bookkeeping without an
    /// await between them. Readers retain their earlier charged backing.
    pub(super) async fn publish_piece_progress_unlocked(
        &self,
        token: JobToken,
        file_hash: &str,
        expected: Option<&super::Ed2kPieceState>,
        piece: &super::Ed2kPieceState,
        permit: super::resident::Reservation,
    ) -> Result<super::ResidentManifest> {
        let _content = self.lock_content(file_hash).await;
        let mut cache = self.manifest_cache.lock().await;
        let current = cache
            .get_mut(&token.job_id)
            .filter(|value| value.token == token)
            .context("progress execution no longer has a cache")?;
        let target = current
            .pieces
            .get(piece.piece_index as usize)
            .filter(|target| target.piece_index == piece.piece_index)
            .context("progress cache geometry changed")?;
        anyhow::ensure!(
            expected.is_none_or(|expected| expected == target),
            "progress changed during payload write"
        );
        anyhow::ensure!(
            target.state == piece.state && target.ich_corrupted == piece.ich_corrupted,
            "structural transition cannot use a progress delta"
        );
        let changed = target != piece;
        let progress = manifest_progress_bytes(current);
        let mut states = self.manifest_checkpoint_state.lock().await;
        let state = super::manifest::checkpoint_state(
            &mut states,
            &self.local_mutations.residents,
            current,
            progress,
        )?;
        state.dirty_piece_indexes.validate(piece.piece_index)?;
        let revision = state
            .revision
            .checked_add(1)
            .context("download progress revision exhausted")?;
        if changed {
            current.write_with(permit, |current| {
                current.pieces[piece.piece_index as usize] = piece.clone();
                Ok(())
            })?;
        }
        state.revision = revision;
        state.dirty_piece_indexes.insert(piece.piece_index)?;
        Ok(current.clone())
    }

    /// Transfer the exact job guard and bounded dirty-piece delta to the shared
    /// retained registry. Capacity waits release the job guard and rebuild the
    /// delta from current dirty state, so they cannot replay a stale snapshot.
    pub(super) async fn store_manifest_piece_progress_unlocked(
        &self,
        manifest: &Ed2kResumeManifest,
        current_piece: u32,
        mut guard: ScopedLockGuard<JobId>,
    ) -> Result<()> {
        let token = manifest.token;
        let piece = manifest
            .pieces
            .get(current_piece as usize)
            .filter(|piece| piece.piece_index == current_piece)
            .context("missing checkpoint piece")?;
        let permit = self.local_mutations.residents.reserve(token.job_id)?;
        self.publish_piece_progress_unlocked(token, &manifest.file_hash, None, piece, permit)
            .await?;
        loop {
            let capacity_revision = self.local_mutations.capacity_revision();
            let submitted = {
                let cache = self.manifest_cache.lock().await;
                let current = cache
                    .get(&token.job_id)
                    .filter(|value| value.token == token)
                    .context("checkpoint execution was invalidated while waiting")?;
                let checkpoints = self.manifest_checkpoint_state.lock().await;
                let dirty = checkpoints
                    .get(&token)
                    .map(|state| &state.dirty_piece_indexes);
                let Some(piece) = dirty.and_then(|set| set.first()) else {
                    return Ok(());
                };
                self.local_mutations
                    .submit_piece_checkpoint(self, current, dirty, piece, guard)
            };
            match submitted {
                Ok(receipt) => {
                    receipt
                        .await
                        .map_err(|_| super::local_mutation::LocalMutationError::Unknown)??;
                    return Ok(());
                }
                Err(error)
                    if matches!(
                        error.downcast_ref::<super::local_mutation::LocalMutationError>(),
                        Some(super::local_mutation::LocalMutationError::Busy)
                    ) =>
                {
                    // submit consumed/dropped the guard on rejection. A retained
                    // worker can now acquire it while this caller waits for space.
                    self.local_mutations
                        .wait_for_completion(capacity_revision)
                        .await?;
                    guard = self.lock_manifest(token).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Record a cache-only progress append so the next batched checkpoint
    /// persists this piece's row even if the checkpoint is triggered by a
    /// block landing in a different piece.
    #[cfg(test)]
    pub(super) async fn note_dirty_piece_unlocked(
        &self,
        manifest: &Ed2kResumeManifest,
        piece_index: u32,
    ) -> Result<()> {
        let current_progress = manifest_progress_bytes(manifest);
        let mut states = self.manifest_checkpoint_state.lock().await;
        let state = super::manifest::checkpoint_state(
            &mut states,
            &self.local_mutations.residents,
            manifest,
            current_progress,
        )?;
        state.dirty_piece_indexes.validate(piece_index)?;
        state.revision = state
            .revision
            .checked_add(1)
            .context("download progress revision exhausted")?;
        state.dirty_piece_indexes.insert(piece_index)?;
        Ok(())
    }

    /// Keep dirty bookkeeping and cache publication inside the same short
    /// content fence as logical stop. A late old-token callback can publish
    /// neither half after stop has invalidated its execution.
    pub(super) async fn publish_dirty_manifest_unlocked(
        &self,
        manifest: &Ed2kResumeManifest,
        piece_index: u32,
    ) -> Result<super::ResidentManifest> {
        let _content = self.lock_content(&manifest.file_hash).await;
        self.cache_manifest_with_content(manifest, Some(piece_index))
            .await
    }

    /// Publish only while category writers are fenced; an older progress clone
    /// must not replace the current cached assignment.
    pub(super) async fn cache_manifest_unlocked(
        &self,
        manifest: &Ed2kResumeManifest,
    ) -> Result<super::ResidentManifest> {
        let _content = self.lock_content(&manifest.file_hash).await;
        self.cache_manifest_with_content(manifest, None).await
    }

    /// Caller retains the content fence through any compound publication.
    async fn cache_manifest_with_content(
        &self,
        manifest: &Ed2kResumeManifest,
        dirty_piece: Option<u32>,
    ) -> Result<super::ResidentManifest> {
        let token = manifest.token;
        let _fence = self.category_assignment_gate.read().await;
        let job = self
            .download_job(token.job_id)
            .await?
            .context("missing job while publishing progress")?;
        anyhow::ensure!(
            job.token == token && job.removed_at_s.is_none() && job.completed_at_s.is_none(),
            "stale execution cannot publish a manifest"
        );
        let mut cache = self.manifest_cache.lock().await;
        let cache_claim = cache.claim_insert()?;
        let permit = self.local_mutations.residents.reserve(token.job_id)?;
        let mut current_value = manifest.clone();
        // Explicit verification can publish a stopped job's current generation.
        // Network callbacks retain the earlier generation and remain fenced.
        current_value.intent = job.intent;
        current_value.category_id = job.category_id;
        current_value.display_name = job.display_name.clone();
        anyhow::ensure!(
            job.expected_size_bytes == Some(current_value.file_size),
            super::LocalMutationError::Unknown
        );
        if let Some(persisted) = cache
            .get(&token.job_id)
            .filter(|value| value.token == token)
        {
            current_value.upload_priority = persisted.upload_priority.clone();
            current_value.auto_upload_priority = persisted.auto_upload_priority;
            current_value.comment = persisted.comment.clone();
            current_value.rating = persisted.rating;
        }
        if let Some(persisted) = cache
            .get(&token.job_id)
            .filter(|value| value.token == token)
            && persisted.delivery_state == super::Ed2kDeliveryState::Delivered
        {
            // Only delivery's dedicated authority boundary may change these.
            current_value.delivery_state = persisted.delivery_state;
            current_value.delivery_ownership = persisted.delivery_ownership;
            current_value.delivered_path = persisted.delivered_path.clone();
            current_value.source_fingerprint = persisted.source_fingerprint.clone();
            current_value.completed = true;
            current_value.final_rehash_pending = false;
        }
        let current = permit.publish(current_value)?;
        if let Some(index) = dirty_piece {
            // WHY: validate the live execution before admitting bookkeeping.
            // A late stopped callback must recreate neither cache nor dirty state.
            // Complete fallible preparation before publishing either half.
            let mut states = self.manifest_checkpoint_state.lock().await;
            let state = super::manifest::checkpoint_state(
                &mut states,
                &self.local_mutations.residents,
                &current,
                manifest_progress_bytes(&current),
            )?;
            state.dirty_piece_indexes.validate(index)?;
            let revision = state
                .revision
                .checked_add(1)
                .context("download progress revision exhausted")?;
            state.dirty_piece_indexes.insert(index)?;
            state.revision = revision;
            cache.insert_claimed(token.job_id, current.clone(), cache_claim);
            return Ok(current);
        }
        cache.insert_claimed(token.job_id, current.clone(), cache_claim);
        Ok(current)
    }

    pub(super) async fn should_checkpoint_manifest_unlocked(
        &self,
        manifest: &Ed2kResumeManifest,
    ) -> Result<bool> {
        let current_progress = manifest_progress_bytes(manifest);
        let mut states = self.manifest_checkpoint_state.lock().await;
        let state = super::manifest::checkpoint_state(
            &mut states,
            &self.local_mutations.residents,
            manifest,
            current_progress,
        )?;
        let dirty_bytes = current_progress.saturating_sub(state.persisted_bytes_written);
        Ok(dirty_bytes >= ED2K_RESUME_CHECKPOINT_BYTES
            || (dirty_bytes != 0
                && state.last_persisted_at.elapsed() >= ED2K_RESUME_CHECKPOINT_INTERVAL))
    }

    pub(super) fn transfer_dir(&self, job_id: JobId) -> Result<PathBuf> {
        self.job_storage
            .lock()
            .unwrap()
            .get(&job_id)
            .map(|session| session.storage.path.clone())
            .with_context(|| format!("job {job_id} has no selected resident storage"))
    }

    /// Short callback admission fence, shared with logical lifecycle publication.
    /// Hold the guard through the ledger update, never through I/O or SQL.
    pub(super) fn active_job_session(
        &self,
        token: JobToken,
    ) -> Option<std::sync::MutexGuard<'_, std::collections::HashMap<JobId, JobStorageSession>>>
    {
        let sessions = self.job_storage.lock().ok()?;
        if sessions
            .get(&token.job_id)
            .is_some_and(|session| session.token == token)
        {
            Some(sessions)
        } else {
            None
        }
    }

    /// Exact allocation-time path for a selected job; never derives a layout.
    pub fn transfer_dir_path(&self, job_id: JobId) -> Result<PathBuf> {
        self.transfer_dir(job_id)
    }

    pub fn payload_path(&self, job_id: JobId) -> Result<PathBuf> {
        Ok(self.transfer_dir(job_id)?.join(PAYLOAD_FILE_NAME))
    }
}

/// Current resident execution for one selected physical allocation. Logical
/// removal/stop retires this cache entry before old I/O may return its handle.
#[derive(Debug, Clone)]
pub(super) struct JobStorageSession {
    pub(super) token: JobToken,
    pub(super) storage: emulebb_metadata::DownloadJobStorage,
}

type LockRegistry<K> =
    Arc<std::sync::Mutex<std::collections::HashMap<K, std::sync::Weak<tokio::sync::Mutex<()>>>>>;

/// A live acquisition owns its exact registry key. Last-owner destruction
/// removes that key directly; acquisition never scans historical entries.
pub(super) struct ScopedLock<K: std::hash::Hash + Eq> {
    registry: LockRegistry<K>,
    key: K,
    lock: Arc<tokio::sync::Mutex<()>>,
}
impl<K: std::hash::Hash + Eq> Drop for ScopedLock<K> {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.registry.lock()
            && Arc::strong_count(&self.lock) == 1
            && entries
                .get(&self.key)
                .is_some_and(|entry| entry.ptr_eq(&Arc::downgrade(&self.lock)))
        {
            entries.remove(&self.key);
        }
    }
}
pub(super) struct ScopedLockGuard<K: std::hash::Hash + Eq> {
    held: Arc<HeldScopedLock<K>>,
}
struct HeldScopedLock<K: std::hash::Hash + Eq> {
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
    _owner: ScopedLock<K>,
}
impl<K: std::hash::Hash + Eq> ScopedLockGuard<K> {
    pub(super) fn key(&self) -> &K {
        &self.held._owner.key
    }
    fn new(guard: tokio::sync::OwnedMutexGuard<()>, owner: ScopedLock<K>) -> Self {
        Self {
            held: Arc::new(HeldScopedLock {
                guard: Some(guard),
                _owner: owner,
            }),
        }
    }
}
impl<K: std::hash::Hash + Eq> Clone for ScopedLockGuard<K> {
    fn clone(&self) -> Self {
        // WHY: a retained SQL owner must keep the exact I/O cut after its caller
        // disappears, preventing the next writer from reading unpublished state.
        Self {
            held: Arc::clone(&self.held),
        }
    }
}
impl<K: std::hash::Hash + Eq> Drop for HeldScopedLock<K> {
    fn drop(&mut self) {
        drop(self.guard.take());
    }
}
impl<K: std::hash::Hash + Eq> ScopedLock<K> {
    pub(super) async fn lock_owned(self) -> ScopedLockGuard<K> {
        let guard = Arc::clone(&self.lock).lock_owned().await;
        ScopedLockGuard::new(guard, self)
    }
    pub(super) fn try_lock_owned(self) -> Option<ScopedLockGuard<K>> {
        let guard = Arc::clone(&self.lock).try_lock_owned().ok()?;
        Some(ScopedLockGuard::new(guard, self))
    }
    pub(super) fn blocking_lock_owned(self) -> ScopedLockGuard<K> {
        let guard = Arc::clone(&self.lock).blocking_lock_owned();
        ScopedLockGuard::new(guard, self)
    }
}
pub(super) fn scoped_lock<K: std::hash::Hash + Eq + Clone>(
    registry: &LockRegistry<K>,
    key: K,
) -> ScopedLock<K> {
    let mut entries = registry.lock().unwrap();
    let lock = entries
        .get(&key)
        .and_then(std::sync::Weak::upgrade)
        .unwrap_or_else(|| {
            let lock = Arc::new(tokio::sync::Mutex::new(()));
            entries.insert(key.clone(), Arc::downgrade(&lock));
            lock
        });
    ScopedLock {
        registry: Arc::clone(registry),
        key,
        lock,
    }
}

#[cfg(test)]
mod scoped_lock_tests {
    use super::*;
    #[tokio::test]
    async fn retained_guard_blocks_the_next_writer_until_its_last_owner_releases() {
        use std::{
            future::{Future, poll_fn},
            task::Poll,
        };
        let registry: LockRegistry<u64> = Arc::default();
        let caller = scoped_lock(&registry, 1).lock_owned().await;
        let retained_owner = caller.clone();
        drop(caller);
        assert!(scoped_lock(&registry, 1).try_lock_owned().is_none());
        let unrelated = scoped_lock(&registry, 2).try_lock_owned().unwrap();
        drop(unrelated);
        let mut next = Box::pin(scoped_lock(&registry, 1).lock_owned());
        assert!(
            poll_fn(|cx| Poll::Ready(next.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        assert_eq!(registry.lock().unwrap().len(), 1);
        drop(retained_owner);
        let next = next.await;
        assert_eq!(registry.lock().unwrap().len(), 1);
        drop(next);
        assert!(registry.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn exact_lock_keys_retire_after_guards_and_cancelled_waiters() {
        let registry: LockRegistry<u64> = Arc::default();
        let first = scoped_lock(&registry, 1).lock_owned().await;
        let waiting = scoped_lock(&registry, 1);
        assert_eq!(registry.lock().unwrap().len(), 1);
        let (entered, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = entered.send(());
            waiting.lock_owned().await
        });
        ready.await.unwrap();
        task.abort();
        let _ = task.await;
        assert_eq!(registry.lock().unwrap().len(), 1);
        drop(first);
        assert!(registry.lock().unwrap().is_empty());
        for id in 1..=100_000 {
            let guard = scoped_lock(&registry, id).lock_owned().await;
            assert_eq!(registry.lock().unwrap().len(), 1);
            drop(guard);
        }
        assert!(registry.lock().unwrap().is_empty());
    }
}
