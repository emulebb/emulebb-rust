//! Retained structural hash deltas with content publication in the same unit.
use super::*;
use crate::ed2k_transfer as transfer;
use emulebb_metadata::{JobId, JobToken};
use std::sync::atomic::Ordering;

const HASH_WORKSPACE: usize = PUBLICATION_WORKSPACE + 512 * 1024;
impl LocalMutationRegistry {
    fn submit_md4_hashes(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        token: JobToken,
        input: &mut Option<Vec<[u8; 16]>>,
        guard: transfer::store::ScopedLockGuard<JobId>,
    ) -> Result<oneshot::Receiver<Result<()>>> {
        let input_ref = input.as_ref().expect("unadmitted MD4 input");
        ensure!(
            input_ref.len() <= 28_259 && input_ref.capacity() <= 65_536,
            LocalMutationError::TooLarge
        );
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let lease = Self::reserve_unit(&mut state, HASH_WORKSPACE, true, false)?;
        let hashes = input.take().expect("admitted MD4 input");
        let metadata = runtime.metadata.clone();
        let locks = Arc::clone(&runtime.content_locks);
        let eligibility = Arc::clone(&runtime.share_eligibility);
        let cache = Arc::clone(&runtime.manifest_cache);
        let failed = Arc::clone(&runtime.share_publication_failed);
        let dirty = Arc::clone(&runtime.category_root_dirty);
        let publication = super::publication::ContentPublication::new(runtime);
        let (sender, receipt) = oneshot::channel();
        #[cfg(test)]
        let publication_gate = state.publication_gate.take();
        Self::spawn_unit(&mut state, lease, move |lease| {
            let _guard = guard;
            let mut committed = false;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let job = metadata
                    .download_job(token.job_id)?
                    .ok_or_else(|| anyhow!("missing MD4 callback job"))?;
                ensure!(job.token == token, "stale MD4 callback generation");
                let size = job
                    .expected_size_bytes
                    .ok_or_else(|| anyhow!("MD4 callback needs admitted size"))?;
                ensure!(
                    hashes.len() == usize::from(transfer::hashset::expected_md4_hash_count(size)),
                    "unexpected MD4 hashset length"
                );
                transfer::hashset::validate_md4_hashset(&job.file_hash, &hashes)?;
                let hash = job.file_hash.parse::<emulebb_kad_proto::Ed2kHash>()?;
                let _content = transfer::store::scoped_lock(&locks, job.file_hash.clone())
                    .blocking_lock_owned();
                let _stripe = eligibility.begin_mutation(&[hash.0])?;
                ensure!(
                    metadata.activate_download_md4_hashes(token, &hashes)?,
                    "stale MD4 callback"
                );
                committed = true;
                #[cfg(test)]
                if let Some((reached, release)) = publication_gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                {
                    let mut cache = cache.blocking_lock();
                    if let Some(manifest) =
                        cache.get_mut(&token.job_id).filter(|m| m.token == token)
                    {
                        // Drop the old list before allocating its exact-capacity replacement.
                        manifest.md4_hashset.clear();
                        manifest.md4_hashset = Vec::with_capacity(hashes.len());
                        manifest.md4_hashset.extend(hashes.iter().map(hex::encode));
                        manifest.md4_hashset_acquired = true;
                    }
                }
                // Raw input and publication scratch do not overlap. The resident
                // replacement is the selected job's cache, not a second DTO.
                drop(hashes);
                drop(job);
                publication.publish(
                    hash,
                    lease,
                    super::publication::PublicationGuards {
                        content: _content,
                        stripe: _stripe,
                        job: Some((token, _guard)),
                    },
                )?;
                Ok(())
            }));
            let (result, outcome) = match result {
                Ok(Ok(())) => (Ok(()), 0),
                Ok(Err(error)) if committed => {
                    tracing::error!(%error,"MD4 activation committed but publication failed");
                    (Err(LocalMutationError::Committed.into()), 1)
                }
                Ok(Err(error)) => (Err(error), 0),
                Err(_) => (Err(LocalMutationError::Unknown.into()), 2),
            };
            if outcome != 0 {
                failed.store(true, Ordering::Release);
                dirty.store(true, Ordering::Release);
            }
            let _ = sender.send(result);
            outcome
        });
        Ok(receipt)
    }
}
impl transfer::Ed2kTransferRuntime {
    pub(in crate::ed2k_transfer) async fn activate_md4_hashes(
        &self,
        token: JobToken,
        hashes: Vec<[u8; 16]>,
    ) -> Result<()> {
        let mut input = Some(hashes);
        loop {
            let capacity_revision = self.local_mutations.capacity_revision();
            let submitted = self.local_mutations.submit_md4_hashes(
                self,
                token,
                &mut input,
                self.lock_manifest(token).await,
            );
            match submitted {
                Ok(receipt) => return receipt.await.map_err(|_| LocalMutationError::Unknown)?,
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
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn md4_activation_caller_and_first_drain_cancel_after_sql_keep_publication_owned() {
        let root = crate::paths::unique_test_dir("job-md4-cancel");
        let metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let runtime = Arc::new(
            transfer::Ed2kTransferRuntime::load_or_create_with_metadata(&root, metadata.clone())
                .unwrap(),
        );
        let admitted = metadata
            .admit_download_job(&emulebb_metadata::DownloadJobRequest {
                file_hash: "61".repeat(16),
                display_name: "hash-evidence.bin".into(),
                expected_size_bytes: Some(16),
                category_id: None,
                intent: emulebb_metadata::DownloadIntent::Started,
                piece_size: transfer::ED2K_PART_SIZE,
            })
            .unwrap()
            .job;
        let job = transfer::new_transfer_job(
            admitted.token,
            admitted.file_hash.parse().unwrap(),
            admitted.display_name,
            16,
        );
        let mut manifest = transfer::Ed2kResumeManifest::new(&job);
        manifest.md4_hashset_acquired = false;
        manifest.pieces[0].bytes_written = 7;
        metadata
            .upsert_transfer_manifest(
                &transfer::transfer_sql::manifest_to_metadata(&manifest).unwrap(),
            )
            .unwrap();
        runtime
            .manifest_cache
            .lock()
            .await
            .insert(job.token.job_id, manifest);
        let (reached, ready) = oneshot::channel();
        let (release, resume) = std::sync::mpsc::channel();
        runtime
            .local_mutations
            .install_publication_gate(reached, resume);
        let worker = Arc::clone(&runtime);
        let caller =
            tokio::spawn(async move { worker.activate_md4_hashes(job.token, Vec::new()).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        assert!(
            metadata
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap()
                .md4_hashset_acquired
        );
        assert!(!runtime.manifest_cache.lock().await[&job.token.job_id].md4_hashset_acquired);
        caller.abort();
        let _ = caller.await;
        let pending = runtime.local_mutations.signal_next_pending_drain();
        let worker = Arc::clone(&runtime);
        let first = tokio::spawn(async move { worker.local_mutations.seal_and_drain().await });
        tokio::time::timeout(std::time::Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap();
        first.abort();
        let _ = first.await;
        release.send(()).unwrap();
        runtime.local_mutations.seal_and_drain().await.unwrap();
        {
            let cache = runtime.manifest_cache.lock().await;
            assert!(cache[&job.token.job_id].md4_hashset_acquired);
            assert_eq!(cache[&job.token.job_id].pieces[0].bytes_written, 7);
        }
        drop(runtime);
        drop(metadata);
        std::fs::remove_dir_all(root).unwrap();
    }
}
