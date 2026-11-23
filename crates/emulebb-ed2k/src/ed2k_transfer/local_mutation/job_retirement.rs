//! One retained internal-storage cleanup at a time, independent of content locks.
use super::*;
use crate::ed2k_transfer as transfer;
use anyhow::Context;
use emulebb_metadata::{DownloadJobStorage, JobId, MetadataDownloadRetirement};
use std::sync::atomic::{AtomicBool, Ordering};

const CLEANUP_WORKSPACE: usize = 1024 * 1024;
struct CleanupLease(Arc<AtomicBool>);
impl Drop for CleanupLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl LocalMutationRegistry {
    pub(in crate::ed2k_transfer) fn submit_retirement(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        id: JobId,
        removed: bool,
        lifecycle: transfer::store::ScopedLockGuard<JobId>,
        job_guard: transfer::store::ScopedLockGuard<JobId>,
    ) -> Result<oneshot::Receiver<Result<bool>>> {
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        ensure!(
            !self.cleanup.load(Ordering::Acquire),
            LocalMutationError::Busy
        );
        let capacity_lease = Self::reserve_long_fs(&mut state, CLEANUP_WORKSPACE)?;
        self.cleanup.store(true, Ordering::Release);
        let lease = CleanupLease(Arc::clone(&self.cleanup));
        let metadata = runtime.metadata.clone();
        let publication = super::publication::ContentPublication::new(runtime);
        let content_locks = Arc::clone(&runtime.content_locks);
        let eligibility = Arc::clone(&runtime.share_eligibility);
        let dirty = Arc::clone(&runtime.category_root_dirty);
        let failed = Arc::clone(&runtime.share_publication_failed);
        let cache = Arc::clone(&runtime.manifest_cache);
        let checkpoints = Arc::clone(&runtime.manifest_checkpoint_state);
        let storage = Arc::clone(&runtime.job_storage);
        let payloads = Arc::clone(&runtime.payload_handles);
        let corroboration = Arc::clone(&runtime.aich_root_corroboration);
        let (sender, receipt) = oneshot::channel();
        #[cfg(test)]
        let publication_gate = state.publication_gate.take();
        Self::spawn_unit_reply(&mut state, capacity_lease, sender, move |capacity| {
            let _lease = lease;
            let job_guards = (job_guard, lifecycle);
            let mut committed = false;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let cleanup = if removed {
                    metadata.removed_download_cleanup_snapshot(id)?
                } else {
                    None
                };
                if removed && cleanup.is_none() {
                    return Ok(false);
                }
                let intent = metadata.download_job_retirement(id)?;
                if !removed && intent.is_none() {
                    return Ok(false);
                }
                if let Some(token) = cache
                    .blocking_lock()
                    .get(&id)
                    .map(|manifest| manifest.token)
                {
                    payloads
                        .lock()
                        .map_err(|_| LocalMutationError::Unknown)?
                        .remove(&token);
                }
                // No SQL/content/catalog lock is held during physical cleanup.
                // Another job for the same hash has a different I/O namespace.
                if let Some(intent) = intent {
                    cleanup_owned_storage(&intent)?;
                    ensure!(
                        metadata.finalize_transfer_retirement(id)?,
                        "internal retirement disappeared before settlement"
                    );
                    committed = true;
                }
                #[cfg(test)]
                if let Some((reached, release)) = publication_gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                if let Some(manifest) = cache.blocking_lock().remove(&id) {
                    checkpoints.blocking_lock().remove(&manifest.token);
                    payloads
                        .lock()
                        .map_err(|_| LocalMutationError::Unknown)?
                        .remove(&manifest.token);
                    corroboration
                        .lock()
                        .map_err(|_| LocalMutationError::Unknown)?
                        .remove(&manifest.token);
                }
                storage
                    .lock()
                    .map_err(|_| LocalMutationError::Unknown)?
                    .remove(&id);
                // Internal cleanup and its cache publication are complete even
                // if independent output authority must remain pending.
                committed = false;
                if let Some(cleanup) = cleanup {
                    cleanup_removed_output(&metadata, &cleanup)?;
                    // Refusal retains the durable removed row for the ordinary
                    // cleanup retry, without waiting while holding job guards.
                    capacity.try_enter_publication(PUBLICATION_WORKSPACE + 512 * 1024)?;
                    // The retained owner also publishes the changed local view,
                    // before dropping the durable row that permits cleanup retry.
                    committed = true;
                    let hash: emulebb_kad_proto::Ed2kHash = cleanup.file_hash.parse()?;
                    let token = cleanup.token;
                    let delete_output = cleanup.delete_output;
                    let content = transfer::store::scoped_lock(&content_locks, cleanup.file_hash)
                        .blocking_lock_owned();
                    drop(cleanup.owned_output);
                    let stripe = eligibility.begin_mutation(&[hash.0])?;
                    let guards = super::publication::PublicationGuards {
                        content,
                        stripe,
                        job: None,
                    };
                    if delete_output {
                        // WHY: the deleted output may have masked a newer verified
                        // payload for this hash. Recheck it without holding the
                        // retired job's guards during physical publication.
                        drop(job_guards);
                        publication.publish(hash, capacity, guards)?;
                    } else {
                        publication.publish_terminal(hash, guards)?;
                    }
                    ensure!(
                        metadata.finalize_removed_download_job(token)?,
                        "removed job changed before final settlement"
                    );
                }
                Ok(true)
            }));
            let (result, outcome) = match result {
                Ok(Ok(done)) => (Ok(done), 0),
                Ok(Err(error)) if committed => {
                    tracing::error!(%error,"internal retirement committed but cache publication failed");
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

fn present(path: &std::path::Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn cleanup_owned_storage(intent: &MetadataDownloadRetirement) -> Result<()> {
    let (source, target) = match (&intent.source_path, &intent.target_path) {
        (None, None) => {
            ensure!(
                intent.authority.is_none(),
                "retirement authority has no allocated path"
            );
            return Ok(());
        }
        (Some(source), Some(target)) => (source, target),
        _ => anyhow::bail!("incomplete persisted internal retirement paths"),
    };
    if present(source)? {
        ensure!(
            !present(target)?,
            "internal retirement target already exists"
        );
        let authority = intent
            .authority
            .context("unestablished internal directory must remain untouched")?;
        super::job_storage::validate_storage(&DownloadJobStorage {
            path: source.clone(),
            marker_id: authority.marker_id,
            identity: Some(authority.identity),
        })?;
        ensure!(
            matches!(
                transfer::fs_durability::move_path_no_replace_retained(source, target)?,
                transfer::fs_durability::NoReplaceMoveOutcome::Moved
            ),
            "internal retirement target collision"
        );
    } else {
        transfer::fs_durability::sync_parent_directory_retained(source)?;
    }
    if present(target)? {
        let authority = intent
            .authority
            .context("unowned internal retirement target must remain untouched")?;
        super::job_storage::validate_storage(&DownloadJobStorage {
            path: target.clone(),
            marker_id: authority.marker_id,
            identity: Some(authority.identity),
        })?;
        std::fs::remove_dir_all(target).context("internal retirement directory removal failed")?;
    }
    transfer::fs_durability::sync_parent_directory_retained(target)?;
    Ok(())
}

fn cleanup_removed_output(
    metadata: &emulebb_metadata::MetadataStore,
    snapshot: &emulebb_metadata::MetadataDownloadCleanupSnapshot,
) -> Result<()> {
    use emulebb_metadata::MetadataTransferDeliveryAttemptPhase;
    let token = snapshot.token;
    let attempt = metadata.download_job_delivery_attempt(token.job_id)?;
    if let Some(attempt) = attempt.as_ref()
        && let Some(reservation) =
            metadata.delivery_output_reservation(token.job_id, attempt.attempt_id)?
    {
        // An unproven partial direct output remains excluded. Missing output
        // permits exact-snapshot barrier release, never authority adoption.
        match std::fs::symlink_metadata(crate::long_path::long_path(&attempt.target_path)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                transfer::fs_durability::sync_parent_directory_retained(&attempt.target_path)?;
                ensure!(
                    metadata.release_recovered_delivery_output(
                        token,
                        &reservation,
                        Some(attempt)
                    )?,
                    "reservation changed during cleanup"
                );
            }
            Err(error) => return Err(error.into()),
            Ok(_) => anyhow::bail!(
                "unproven direct output remains excluded for job {}",
                token.job_id
            ),
        }
    }
    if snapshot.delete_output {
        let authority = snapshot
            .owned_output
            .as_ref()
            .map(
                |(path, fingerprint)| transfer::deliver::OwnedDeliveryOutput {
                    path: path.clone(),
                    fingerprint: fingerprint.clone(),
                },
            )
            .or_else(|| {
                if snapshot.delivered {
                    None
                } else {
                    attempt
                        .as_ref()
                        .filter(|a| a.phase == MetadataTransferDeliveryAttemptPhase::Published)
                        .and_then(|a| {
                            a.published_fingerprint.clone().map(|fingerprint| {
                                transfer::deliver::OwnedDeliveryOutput {
                                    path: a.target_path.clone(),
                                    fingerprint,
                                }
                            })
                        })
                }
            });
        transfer::delivery_tombstone::OutputCleanup { metadata, token }
            .cleanup_delivery_output_for_deletion(token.job_id, &snapshot.file_hash, authority)?;
    }
    if let Some(attempt) = attempt {
        if let Some(expected) = attempt.staging_fingerprint.as_ref() {
            // False removal preserves the output; only an exact owned staging
            // artifact is reclaimed. Unknown/replaced staging is left intact.
            let _ = transfer::deliver::remove_file_if_fingerprint_matches_retained(
                &attempt.staging_path,
                expected,
            )?;
        }
        ensure!(
            metadata.settle_recovered_delivery_attempt(token, &attempt)?,
            "delivery attempt changed during removal cleanup"
        );
    }
    Ok(())
}

impl transfer::Ed2kTransferRuntime {
    pub async fn cleanup_removed_download_job(&self, id: JobId) -> Result<bool> {
        let lifecycle = self.lock_lifecycle(id).await;
        let guard = super::super::store::scoped_lock(&self.manifest_locks, id)
            .lock_owned()
            .await;
        let receipt = self
            .local_mutations
            .submit_retirement(self, id, true, lifecycle, guard)?;
        receipt.await.context("removed job cleanup owner stopped")?
    }

    pub async fn recover_removed_download_jobs_page(
        &self,
        after: Option<JobId>,
        limit: usize,
    ) -> Result<(Option<JobId>, transfer::Ed2kTransferDeletionRecoveryReport)> {
        let super::job_read::JobReadResult::Ids(ids) = self
            .read_job_metadata(super::job_read::JobRead::Removed(after, limit))
            .await?
        else {
            unreachable!()
        };
        let cursor = ids.last().copied();
        let mut report = transfer::Ed2kTransferDeletionRecoveryReport::default();
        for &id in &ids {
            match self.cleanup_removed_download_job(id).await {
                Ok(true) => report.recovered += 1,
                Ok(false) => {}
                Err(error) => report.failures.push(format!("job {id}: {error:#}")),
            }
        }
        Ok((cursor, report))
    }

    /// One bounded maintenance page. A cursor advances even over safely pending
    /// failures; the existing maintenance owner chooses the next backoff pass.
    pub async fn recover_download_retirements_page(
        &self,
        after: Option<JobId>,
        limit: usize,
    ) -> Result<(
        Option<JobId>,
        transfer::Ed2kTransferRetirementRecoveryReport,
    )> {
        let super::job_read::JobReadResult::Ids(ids) = self
            .read_job_metadata(super::job_read::JobRead::Retirement(after, limit))
            .await?
        else {
            unreachable!()
        };
        let cursor = ids.last().copied();
        let mut report = transfer::Ed2kTransferRetirementRecoveryReport::default();
        for &id in &ids {
            match self.retire_download_storage(id).await {
                Ok(true) => report.recovered += 1,
                Ok(false) => {}
                Err(error) => report.failures.push(format!("job {id}: {error:#}")),
            }
        }
        Ok((cursor, report))
    }

    /// Attempt already durable cleanup. Admission failure leaves the journal
    /// pending; it neither changes unfinished-job retry policy nor owns outputs.
    pub async fn retire_download_storage(&self, id: JobId) -> Result<bool> {
        let lifecycle = self.lock_lifecycle(id).await;
        let guard = super::super::store::scoped_lock(&self.manifest_locks, id)
            .lock_owned()
            .await;
        let receipt = self
            .local_mutations
            .submit_retirement(self, id, false, lifecycle, guard)?;
        receipt.await.context("internal retirement owner stopped")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn allocated(
        runtime: &transfer::Ed2kTransferRuntime,
        hash: &str,
        root: &std::path::Path,
    ) -> (emulebb_metadata::JobToken, DownloadJobStorage) {
        let admitted = runtime
            .metadata
            .admit_download_job(&emulebb_metadata::DownloadJobRequest {
                file_hash: hash.into(),
                display_name: "retire.bin".into(),
                expected_size_bytes: Some(16),
                category_id: None,
                intent: emulebb_metadata::DownloadIntent::Started,
                piece_size: transfer::ED2K_PART_SIZE,
            })
            .unwrap()
            .job;
        let started = runtime
            .metadata
            .start_download_job(admitted.token, root)
            .unwrap()
            .unwrap();
        let storage = runtime
            .prepare_download_job_storage(started.token)
            .await
            .unwrap();
        (started.token, storage)
    }
    #[tokio::test]
    async fn removed_cleanup_survives_receipt_and_first_drain_cancellation() {
        let root = crate::paths::unique_test_dir("removed-cleanup-retained");
        let metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let runtime = Arc::new(
            transfer::Ed2kTransferRuntime::load_or_create_with_metadata(&root, metadata.clone())
                .unwrap(),
        );
        let (first, storage) = allocated(&runtime, &"21".repeat(16), &root).await;
        let (second, _) = allocated(&runtime, &"22".repeat(16), &root).await;
        runtime
            .remove_download_job(first.job_id, false)
            .await
            .unwrap();
        runtime
            .remove_download_job(second.job_id, false)
            .await
            .unwrap();
        let (reached, ready) = oneshot::channel();
        let (release, resume) = std::sync::mpsc::channel();
        runtime
            .local_mutations
            .install_publication_gate(reached, resume);
        let worker = Arc::clone(&runtime);
        let caller =
            tokio::spawn(async move { worker.cleanup_removed_download_job(first.job_id).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        assert!(!storage.path.exists());
        assert!(
            metadata
                .download_job(first.job_id)
                .unwrap()
                .unwrap()
                .internal_storage_retired
        );
        let busy = runtime
            .cleanup_removed_download_job(second.job_id)
            .await
            .unwrap_err();
        assert!(matches!(
            busy.downcast_ref::<LocalMutationError>(),
            Some(LocalMutationError::Busy)
        ));
        // The held cleanup owns one slot and its narrow workspace, leaving
        // ordinary SQL reads admitted. This is a publication gate, not slow-I/O proof.
        assert!(runtime.download_job(second.job_id).await.unwrap().is_some());
        caller.abort();
        let _ = caller.await;
        let pending = runtime.local_mutations.signal_next_pending_drain();
        let first_runtime = Arc::clone(&runtime);
        let drain =
            tokio::spawn(async move { first_runtime.local_mutations.seal_and_drain().await });
        tokio::time::timeout(std::time::Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap();
        drain.abort();
        let _ = drain.await;
        release.send(()).unwrap();
        runtime.local_mutations.seal_and_drain().await.unwrap();
        assert!(metadata.download_job(first.job_id).unwrap().is_none());
        assert!(metadata.download_job(second.job_id).unwrap().is_some());
        drop(runtime);
        drop(metadata);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn unsupported_retirement_stays_pending_and_new_same_content_job_is_independent() {
        let root = crate::paths::unique_test_dir("job-retirement-retry");
        let metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let runtime =
            transfer::Ed2kTransferRuntime::load_or_create_with_metadata(&root, metadata.clone())
                .unwrap();
        let hash = "11".repeat(16);
        let (old, old_storage) = allocated(&runtime, &hash, &root).await;
        std::fs::write(
            old_storage.path.join(transfer::PAYLOAD_FILE_NAME),
            b"old payload",
        )
        .unwrap();
        assert!(metadata.remove_download_job(old.job_id).unwrap());
        let intent = metadata
            .download_job_retirement(old.job_id)
            .unwrap()
            .unwrap();
        transfer::fs_durability::force_unsupported_move(intent.target_path.as_ref().unwrap());
        assert!(runtime.retire_download_storage(old.job_id).await.is_err());
        assert_eq!(
            metadata.download_job_retirement(old.job_id).unwrap(),
            Some(intent.clone())
        );
        assert_eq!(
            std::fs::read(old_storage.path.join(transfer::PAYLOAD_FILE_NAME)).unwrap(),
            b"old payload"
        );
        let (new, new_storage) = allocated(&runtime, &hash, &root).await;
        assert_ne!(old.job_id, new.job_id);
        std::fs::write(
            new_storage.path.join(transfer::PAYLOAD_FILE_NAME),
            b"new payload",
        )
        .unwrap();
        assert!(runtime.retire_download_storage(old.job_id).await.unwrap());
        assert!(!old_storage.path.exists());
        assert!(
            metadata
                .download_job_retirement(old.job_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            std::fs::read(new_storage.path.join(transfer::PAYLOAD_FILE_NAME)).unwrap(),
            b"new payload"
        );
        assert_eq!(
            metadata.latest_download_job(&hash).unwrap().unwrap().token,
            new
        );
        runtime.local_mutations.seal_and_drain().await.unwrap();
        drop(runtime);
        drop(metadata);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn retirement_collision_preserves_both_objects_and_durable_authority() {
        let root = crate::paths::unique_test_dir("job-retirement-collision");
        let metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let runtime =
            transfer::Ed2kTransferRuntime::load_or_create_with_metadata(&root, metadata.clone())
                .unwrap();
        let (token, storage) = allocated(&runtime, &"22".repeat(16), &root).await;
        assert!(metadata.remove_download_job(token.job_id).unwrap());
        let intent = metadata
            .download_job_retirement(token.job_id)
            .unwrap()
            .unwrap();
        let target = intent.target_path.as_ref().unwrap();
        std::fs::create_dir(target).unwrap();
        std::fs::write(target.join("foreign.bin"), b"preserve").unwrap();
        assert!(runtime.retire_download_storage(token.job_id).await.is_err());
        assert!(storage.path.exists());
        assert_eq!(
            std::fs::read(target.join("foreign.bin")).unwrap(),
            b"preserve"
        );
        assert_eq!(
            metadata.download_job_retirement(token.job_id).unwrap(),
            Some(intent)
        );
        runtime.local_mutations.seal_and_drain().await.unwrap();
        drop(runtime);
        drop(metadata);
        std::fs::remove_dir_all(root).unwrap();
    }
}
