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
        Self::spawn_unit(&mut state, lease, move |lease| {
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
                    LifecycleChange::Stop(token) => metadata.stop_download_job(token)?,
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
            let _ = sender.send(result);
            outcome
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
        runtime
            .manifest_cache
            .lock()
            .await
            .insert(old.token.job_id, manifest);
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
