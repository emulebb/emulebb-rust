//! Short durable lifecycle publication, separate from potentially slow cleanup.
use super::*;
use crate::ed2k_transfer as transfer;
use emulebb_metadata::{JobId, JobToken};
use std::sync::atomic::Ordering;

// One exact content projection plus its selected native path/conversions.
const LIFECYCLE_WORKSPACE: usize = PUBLICATION_WORKSPACE + 512 * 1024;
#[derive(Clone, Copy)]
enum LifecycleChange {
    Complete(JobToken),
    Stop(JobToken),
    Remove(JobId, bool),
}
impl LifecycleChange {
    fn id(self) -> JobId {
        match self {
            Self::Complete(token) | Self::Stop(token) => token.job_id,
            Self::Remove(id, _) => id,
        }
    }
}

impl LocalMutationRegistry {
    fn submit_lifecycle(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        change: LifecycleChange,
    ) -> Result<oneshot::Receiver<Result<bool>>> {
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let lease = Self::reserve_unit(
            &mut state,
            LIFECYCLE_WORKSPACE,
            matches!(change, LifecycleChange::Stop(_)),
            false,
        )?;
        let metadata = runtime.metadata.clone();
        let publication = super::publication::ContentPublication::new(runtime);
        let locks = Arc::clone(&runtime.content_locks);
        let eligibility = Arc::clone(&runtime.share_eligibility);
        let cache = Arc::clone(&runtime.manifest_cache);
        let sessions = Arc::clone(&runtime.job_storage);
        let payloads = Arc::clone(&runtime.payload_handles);
        let checkpoints = Arc::clone(&runtime.manifest_checkpoint_state);
        let activity = Arc::clone(&runtime.download_activity);
        let sources = Arc::clone(&runtime.download_sources);
        let votes = Arc::clone(&runtime.aich_root_corroboration);
        let blackboxes = Arc::clone(&runtime.corruption_blackbox);
        let source_exchange = runtime.source_exchange.clone();
        let dirty = Arc::clone(&runtime.category_root_dirty);
        let failed = Arc::clone(&runtime.share_publication_failed);
        let (sender, receipt) = oneshot::channel();
        #[cfg(test)]
        let publication_gate = state.publication_gate.take();
        Self::spawn_unit_reply(&mut state, lease, sender, move |lease| {
            let mut committed = false;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let id = change.id();
                let Some(job) = metadata.download_job(id)? else {
                    return Ok(false);
                };
                let hash = job.file_hash.parse::<emulebb_kad_proto::Ed2kHash>()?;
                // Never acquire this job's long I/O/lifecycle guard. Its durable
                // generation is invalidated now; actual cleanup drains it later.
                let content = transfer::store::scoped_lock(&locks, job.file_hash.clone())
                    .blocking_lock_owned();
                let stripe = eligibility.begin_mutation(&[hash.0])?;
                let changed = match change {
                    LifecycleChange::Complete(token) => {
                        metadata.request_transfer_retirement(token)?
                    }
                    LifecycleChange::Stop(token) => {
                        // WHY: acknowledged appends may still be cache-only.
                        // Their payload is flushed before dirty publication, so
                        // stop can persist these exact deltas without waiting
                        // on a later writer's long job I/O guard.
                        let manifests = cache.blocking_lock();
                        let states = checkpoints.blocking_lock();
                        let pending = states.get(&token).map(|state| &state.dirty_piece_indexes);
                        let count = pending.map_or(0, std::collections::BTreeSet::len);
                        let bytes = count
                            .checked_mul(
                                std::mem::size_of::<emulebb_metadata::MetadataTransferPiece>() + 22,
                            )
                            .and_then(|bytes| bytes.checked_add(512 * 1024))
                            .ok_or(LocalMutationError::TooLarge)?;
                        ensure!(bytes <= LIFECYCLE_WORKSPACE, LocalMutationError::TooLarge);
                        let manifest = manifests
                            .get(&id)
                            .filter(|manifest| manifest.token == token);
                        let mut pieces = Vec::with_capacity(count);
                        if let Some(pending) = pending {
                            for index in pending {
                                let piece = manifest
                                    .and_then(|manifest| manifest.pieces.get(*index as usize))
                                    .filter(|piece| piece.piece_index == *index)
                                    .ok_or_else(|| {
                                        anyhow!("stopping dirty execution has no current piece")
                                    })?;
                                ensure!(
                                    piece
                                        .block_bitmap
                                        .as_ref()
                                        .is_none_or(|bitmap| bitmap.len() <= 14),
                                    LocalMutationError::TooLarge
                                );
                                let manifest = manifest.expect("dirty piece has a manifest");
                                pieces.push(transfer::transfer_sql::piece_to_metadata(
                                    piece,
                                    transfer::expected_piece_length(
                                        manifest.file_size,
                                        manifest.piece_size,
                                        u64::from(piece.piece_index),
                                    ),
                                ));
                            }
                        }
                        drop(states);
                        drop(manifests);
                        let changed = metadata.checkpoint_and_stop_download_job(token, &pieces)?;
                        if !changed && !pieces.is_empty() {
                            // A structural writer may have committed before its
                            // cache publication. Refuse this conflicting cut;
                            // it must not masquerade as an unchanged stop.
                            ensure!(
                                metadata
                                    .download_job(id)?
                                    .is_none_or(|current| current.token != token
                                        || current.intent
                                            != emulebb_metadata::DownloadIntent::Started
                                        || current.completed_at_s.is_some()
                                        || current.removed_at_s.is_some()),
                                LocalMutationError::Busy
                            );
                        }
                        changed
                    }
                    LifecycleChange::Remove(id, true) => metadata.request_transfer_deletion(id)?,
                    LifecycleChange::Remove(id, false) => metadata.remove_download_job(id)?,
                };
                if !changed {
                    return Ok(false);
                }
                committed = true;
                #[cfg(test)]
                if let Some((reached, release)) = publication_gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                let previous = cache.blocking_lock().remove(&id);
                {
                    let mut sessions = sessions.lock().map_err(|_| LocalMutationError::Unknown)?;
                    let resident = sessions.remove(&id);
                    let token = resident
                        .map(|session| session.token)
                        .or_else(|| previous.as_ref().map(|manifest| manifest.token));
                    if let Some(token) = token {
                        payloads
                            .lock()
                            .map_err(|_| LocalMutationError::Unknown)?
                            .remove(&token);
                        activity
                            .lock()
                            .map_err(|_| LocalMutationError::Unknown)?
                            .remove(&token);
                        sources
                            .lock()
                            .map_err(|_| LocalMutationError::Unknown)?
                            .remove(&token);
                        votes
                            .lock()
                            .map_err(|_| LocalMutationError::Unknown)?
                            .remove(&token);
                        blackboxes
                            .lock()
                            .map_err(|_| LocalMutationError::Unknown)?
                            .remove(&token);
                        checkpoints.blocking_lock().remove(&token);
                        source_exchange.clear(token);
                    }
                }
                drop(previous);
                drop(job);
                let guards = super::publication::PublicationGuards {
                    content,
                    stripe,
                    job: None,
                };
                if matches!(change, LifecycleChange::Stop(_)) {
                    publication.publish(hash, lease, guards)?;
                } else {
                    publication.publish_terminal(hash, guards)?;
                }
                Ok(true)
            }));
            let (result, outcome) = match result {
                Ok(Ok(changed)) => (Ok(changed), 0),
                Ok(Err(error)) if committed => {
                    tracing::error!(%error,"job lifecycle committed but publication failed");
                    (Err(LocalMutationError::Committed.into()), 1)
                }
                Ok(Err(error)) => (Err(error), 0),
                Err(_) => (Err(LocalMutationError::Unknown.into()), 2),
            };
            if outcome != 0 {
                dirty.store(true, Ordering::Release);
                failed.store(true, Ordering::Release);
            }
            (result, outcome)
        });
        Ok(receipt)
    }
}
impl transfer::Ed2kTransferRuntime {
    /// Invalidate this execution while retaining the durable resumable job and
    /// allocation. A later START drains its old I/O before physical reuse.
    pub async fn stop_download_job(&self, token: JobToken) -> Result<bool> {
        self.publish_lifecycle(LifecycleChange::Stop(token)).await
    }

    /// Retain terminal history and accept internal cleanup. This receipt covers
    /// SQL/cache/catalog publication, not completion of physical retirement.
    pub async fn complete_download_job(&self, token: JobToken) -> Result<bool> {
        self.publish_lifecycle(LifecycleChange::Complete(token))
            .await
    }
    /// Both removal choices retire internal pieces; only true authorizes the
    /// separately fingerprint-checked delivered-output deletion workflow.
    pub async fn remove_download_job(&self, id: JobId, delete_data: bool) -> Result<bool> {
        self.publish_lifecycle(LifecycleChange::Remove(id, delete_data))
            .await
    }
    async fn publish_lifecycle(&self, change: LifecycleChange) -> Result<bool> {
        loop {
            let capacity_revision = self.local_mutations.capacity_revision();
            match self.local_mutations.submit_lifecycle(self, change) {
                Err(error)
                    if matches!(
                        error.downcast_ref::<LocalMutationError>(),
                        Some(LocalMutationError::Busy)
                    ) =>
                {
                    self.local_mutations
                        .wait_for_completion(capacity_revision)
                        .await?
                }
                Err(error) => return Err(error),
                Ok(receipt) => return receipt.await.map_err(|_| LocalMutationError::Unknown)?,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn partial_job(
        runtime: &transfer::Ed2kTransferRuntime,
        bitmap: bool,
    ) -> transfer::Ed2kTransferJob {
        let request = emulebb_metadata::DownloadJobRequest {
            file_hash: if bitmap {
                "46".repeat(16)
            } else {
                "45".repeat(16)
            },
            display_name: "Sample.bin".into(),
            expected_size_bytes: Some(4 * transfer::ED2K_EMBLOCK_SIZE),
            category_id: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            piece_size: transfer::ED2K_PART_SIZE,
        };
        let admitted = runtime
            .admit_download_job(&request, false, None, &Default::default())
            .await
            .unwrap();
        let token = admitted.job.token;
        drop(admitted);
        let selected = runtime
            .begin_download_job_execution(token, Some(&runtime.root_dir))
            .await
            .unwrap();
        let token = selected.as_ref().unwrap().token;
        drop(selected);
        let job = transfer::new_transfer_job(
            token,
            request.file_hash.parse().unwrap(),
            request.display_name,
            request.expected_size_bytes.unwrap(),
        );
        drop(runtime.ensure_job(&job).await.unwrap());
        job
    }

    #[tokio::test]
    async fn acknowledged_prefix_and_bitmap_progress_survive_stop_and_restart() {
        for bitmap in [false, true] {
            let root = crate::paths::unique_test_dir("stop-dirty-progress");
            let runtime = transfer::Ed2kTransferRuntime::load_or_create(&root).unwrap();
            let job = partial_job(&runtime, bitmap).await;
            let start = if bitmap {
                transfer::ED2K_EMBLOCK_SIZE
            } else {
                0
            };
            let data = vec![
                0x5a;
                if bitmap {
                    transfer::ED2K_EMBLOCK_SIZE as usize
                } else {
                    8192
                }
            ];
            assert!(
                !runtime
                    .append_piece_block(job.token, 0, start, start + data.len() as u64, &data)
                    .await
                    .unwrap()
                    .is_completed()
            );
            let piece = runtime.manifest(job.token).await.unwrap().pieces[0].clone();
            assert_eq!(piece.block_bitmap.is_some(), bitmap);
            let payload = runtime.payload_path(job.token.job_id).unwrap();
            assert!(runtime.stop_download_job(job.token).await.unwrap());
            assert_eq!(
                &std::fs::read(payload).unwrap()[start as usize..start as usize + data.len()],
                data
            );
            runtime.local_mutations.seal_and_drain().await.unwrap();
            drop(runtime);

            let runtime = transfer::Ed2kTransferRuntime::load_or_create(&root).unwrap();
            let stopped = runtime
                .download_job(job.token.job_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stopped.intent, emulebb_metadata::DownloadIntent::Stopped);
            assert_eq!(stopped.checkpointed_bytes, data.len() as u64);
            let token = stopped.token;
            drop(stopped);
            let restarted = runtime.start_download_job(token, &root).await.unwrap();
            let token = restarted.as_ref().unwrap().token;
            drop(restarted);
            let resumed = runtime
                .ensure_job(&transfer::new_transfer_job(
                    token,
                    job.file_hash.parse().unwrap(),
                    job.display_name,
                    job.file_size,
                ))
                .await
                .unwrap();
            assert_eq!(resumed.pieces[0], piece);
            assert_eq!(
                transfer::manifest::manifest_progress_bytes(&resumed),
                data.len() as u64
            );
            drop(resumed);
            runtime.local_mutations.seal_and_drain().await.unwrap();
        }
    }

    #[tokio::test]
    async fn stop_preserves_acknowledged_data_without_waiting_later_io_and_rejects_late_publication()
     {
        let root = crate::paths::unique_test_dir("stop-held-job-io");
        let runtime = transfer::Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let job = partial_job(&runtime, false).await;
        runtime
            .append_piece_block(job.token, 0, 0, 8192, &[0x5a; 8192])
            .await
            .unwrap();
        let snapshot = runtime.manifest(job.token).await.unwrap();
        let io = runtime.lock_manifest(job.token).await;
        let late_handle = runtime.take_payload_handle(job.token).await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                runtime.stop_download_job(job.token)
            )
            .await
            .unwrap()
            .unwrap()
        );
        assert_eq!(
            runtime
                .download_job(job.token.job_id)
                .await
                .unwrap()
                .unwrap()
                .checkpointed_bytes,
            8192
        );
        assert!(
            runtime
                .publish_dirty_manifest_unlocked(&snapshot, 0)
                .await
                .is_err()
        );
        assert!(runtime.cache_manifest_unlocked(&snapshot).await.is_err());
        runtime.store_payload_handle(job.token, late_handle);
        assert!(
            !runtime
                .payload_handles
                .lock()
                .unwrap()
                .contains_key(&job.token)
        );
        assert!(
            !runtime
                .manifest_cache
                .lock()
                .await
                .contains_key(&job.token.job_id)
        );
        assert!(
            !runtime
                .manifest_checkpoint_state
                .lock()
                .await
                .contains_key(&job.token)
        );
        drop(snapshot);
        drop(io);
        runtime.local_mutations.seal_and_drain().await.unwrap();
    }
    #[tokio::test]
    async fn logical_remove_survives_caller_abort_without_waiting_old_io_or_rearming_late_handles()
    {
        let root = crate::paths::unique_test_dir("job-logical-remove");
        let metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let runtime = Arc::new(
            transfer::Ed2kTransferRuntime::load_or_create_with_metadata(&root, metadata.clone())
                .unwrap(),
        );
        let request = emulebb_metadata::DownloadJobRequest {
            file_hash: "11".repeat(16),
            display_name: "removed.bin".into(),
            expected_size_bytes: Some(16),
            category_id: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            piece_size: transfer::ED2K_PART_SIZE,
        };
        let old = metadata.admit_download_job(&request).unwrap().job;
        let old = metadata
            .start_download_job(old.token, &root)
            .unwrap()
            .unwrap();
        let storage = runtime
            .prepare_download_job_storage(old.token)
            .await
            .unwrap();
        let job = transfer::new_transfer_job(
            old.token,
            request.file_hash.parse().unwrap(),
            request.display_name.clone(),
            16,
        );
        let manifest = transfer::Ed2kResumeManifest::new(&job);
        metadata
            .upsert_transfer_manifest(
                &transfer::transfer_sql::manifest_to_metadata(&manifest).unwrap(),
            )
            .unwrap();
        runtime.manifest_cache.lock().await.insert(
            old.token.job_id,
            runtime
                .local_mutations
                .residents
                .copy_manifest(&manifest)
                .unwrap(),
        );
        let lifecycle = runtime.lock_lifecycle(old.token.job_id).await;
        let io = runtime.lock_manifest(old.token).await;
        let late_handle = runtime.take_payload_handle(old.token).await.unwrap();
        let (reached, ready) = oneshot::channel();
        let (release, resume) = std::sync::mpsc::channel();
        runtime
            .local_mutations
            .install_publication_gate(reached, resume);
        let caller_runtime = Arc::clone(&runtime);
        let caller = tokio::spawn(async move {
            caller_runtime
                .remove_download_job(old.token.job_id, false)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        assert!(
            metadata
                .download_job(old.token.job_id)
                .unwrap()
                .unwrap()
                .removed_at_s
                .is_some()
        );
        assert!(
            metadata
                .latest_download_job(&request.file_hash)
                .unwrap()
                .is_none()
        );
        assert!(
            metadata
                .transfer_retirement_pending(old.token.job_id)
                .unwrap()
        );
        assert!(
            !metadata
                .transfer_deletion_requested(old.token.job_id)
                .unwrap()
        );
        caller.abort();
        let _ = caller.await;
        release.send(()).unwrap();
        let content = runtime.lock_content(&request.file_hash).await;
        drop(content);
        assert!(
            !runtime
                .manifest_cache
                .lock()
                .await
                .contains_key(&old.token.job_id)
        );
        runtime.store_payload_handle(old.token, late_handle);
        assert!(
            !runtime
                .payload_handles
                .lock()
                .unwrap()
                .contains_key(&old.token)
        );
        runtime.note_download_payload_bytes(old.token, 16);
        assert_eq!(runtime.downloaded_session_bytes(old.token), 0);
        let new = metadata.admit_download_job(&request).unwrap().job;
        let new = metadata
            .start_download_job(new.token, &root)
            .unwrap()
            .unwrap();
        let new_storage = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            runtime.prepare_download_job_storage(new.token),
        )
        .await
        .unwrap()
        .unwrap();
        assert_ne!(storage.path, new_storage.path);
        assert!(storage.path.exists());
        drop(io);
        drop(lifecycle);
        assert!(
            runtime
                .retire_download_storage(old.token.job_id)
                .await
                .unwrap()
        );
        assert!(!storage.path.exists());
        assert!(new_storage.path.exists());
        runtime.local_mutations.seal_and_drain().await.unwrap();
        drop(runtime);
        drop(metadata);
        std::fs::remove_dir_all(root).unwrap();
    }
}
