//! Exact-generation AICH decisions retained through SQL and publication.
use super::*;
use crate::ed2k_transfer as transfer;
use emulebb_metadata::{JobId, MetadataDownloadAichState, MetadataTransferAichIdentity};
use std::sync::atomic::Ordering;

// Two bounded hash-list representations, live votes and later publication
// scratch share this ordinary allowance. No prepared-file lease is borrowed.
const AICH_WORKSPACE: usize = 7 * 1024 * 1024;
type AichReceipt = (
    MetadataTransferAichIdentity,
    bool,
    transfer::store::ScopedLockGuard<JobId>,
);
impl LocalMutationRegistry {
    fn submit_aich_decision(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        manifest: &mut Option<transfer::ResidentDraft>,
        expected_generation: u64,
        votes: &Option<transfer::aich_trust::AichRootCorroboration>,
        guard: transfer::store::ScopedLockGuard<JobId>,
    ) -> Result<oneshot::Receiver<Result<AichReceipt>>> {
        let source = manifest.as_ref().expect("unadmitted AICH proposal");
        let strings = source.aich_hashset.iter().try_fold(0usize, |n, hash| {
            ensure!(hash.len() == 40, "invalid AICH hash length");
            n.checked_add(hash.capacity())
                .ok_or_else(|| LocalMutationError::TooLarge.into())
        })?;
        let bytes = source
            .aich_hashset
            .capacity()
            .checked_mul(std::mem::size_of::<String>())
            .and_then(|n| n.checked_add(strings))
            .ok_or(LocalMutationError::TooLarge)?;
        ensure!(
            source.aich_hashset.len() <= 28_258 && bytes <= 2 * 1024 * 1024,
            LocalMutationError::TooLarge
        );
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let lease = Self::reserve_unit(&mut state, AICH_WORKSPACE, true, false)?;
        let manifest = manifest.take().expect("admitted AICH proposal");
        let token = manifest.token;
        let proposed = MetadataDownloadAichState {
            identity: MetadataTransferAichIdentity {
                root: manifest.aich_root.clone(),
                origin: manifest
                    .aich_root_origin
                    .map(|origin| origin.as_str().to_owned()),
                generation: manifest.aich_trust_generation,
            },
            acquired: manifest.aich_hashset_acquired,
            hashes: manifest.aich_hashset.clone(),
        };
        let resident_write = manifest.into_write_credit();
        let votes = votes.clone();
        let metadata = runtime.metadata.clone();
        let locks = Arc::clone(&runtime.content_locks);
        let eligibility = Arc::clone(&runtime.share_eligibility);
        let cache = Arc::clone(&runtime.manifest_cache);
        let corroboration = Arc::clone(&runtime.aich_root_corroboration);
        let failed = Arc::clone(&runtime.share_publication_failed);
        let dirty = Arc::clone(&runtime.category_root_dirty);
        let publication = super::publication::ContentPublication::new(runtime);
        let (sender, receipt) = oneshot::channel();
        #[cfg(test)]
        let publication_gate = state.publication_gate.take();
        #[cfg(test)]
        let barrier = runtime.aich_persist_barrier.lock().unwrap().take();
        #[cfg(test)]
        let executor = tokio::runtime::Handle::current();
        Self::spawn_unit(&mut state, lease, move |lease| {
            let mut committed = false;
            let mut published = false;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let job = metadata
                    .download_job(token.job_id)?
                    .ok_or_else(|| anyhow!("missing AICH decision job"))?;
                ensure!(job.token == token, "stale AICH execution generation");
                let hash = job.file_hash.parse::<emulebb_kad_proto::Ed2kHash>()?;
                let _content = transfer::store::scoped_lock(&locks, job.file_hash.clone())
                    .blocking_lock_owned();
                let _stripe = eligibility.begin_mutation(&[hash.0])?;
                let mut stored = metadata
                    .activate_download_aich(token, expected_generation, proposed)?
                    .ok_or_else(|| anyhow!("stale AICH decision"))?;
                committed = true;
                #[cfg(test)]
                if let Some((reached, release)) = publication_gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                #[cfg(test)]
                if let Some(barrier) = barrier {
                    barrier.committed.notify_one();
                    executor.block_on(barrier.release.notified());
                }
                {
                    let mut cache = cache.blocking_lock();
                    let mut map = corroboration
                        .lock()
                        .map_err(|_| LocalMutationError::Unknown)?;
                    // A content authority may have advanced after this decision's
                    // commit. Revalidate under the provider's existing short
                    // SQL/publication cut; never publish the earlier receipt.
                    metadata.publish_download_job_aich_identity(token, |identity| {
                        if stored.identity.root != identity.root {
                            stored.hashes.clear();
                            stored.acquired = false;
                        }
                        stored.identity = identity;
                        if let Some(current) =
                            cache.get_mut(&token.job_id).filter(|m| m.token == token)
                        {
                            current.write_with(resident_write, |current| {
                                transfer::aich_trust::merge_persisted_identity(
                                    current,
                                    &stored.identity,
                                )?;
                                current.aich_hashset = stored.hashes.clone();
                                current.aich_hashset_acquired = stored.acquired;
                                Ok(())
                            })?;
                        }
                        if let Some(votes) = votes
                            && matches!(
                                stored.identity.origin.as_deref(),
                                None | Some("network_consensus")
                            )
                        {
                            map.insert(token, votes);
                        } else {
                            map.remove(&token);
                        }
                        Ok(())
                    })?;
                }
                let MetadataDownloadAichState {
                    identity,
                    acquired,
                    hashes,
                } = stored;
                drop(hashes);
                drop(job);
                let guard = publication
                    .publish(
                        hash,
                        lease,
                        super::publication::PublicationGuards {
                            content: _content,
                            stripe: _stripe,
                            job: Some((token, guard)),
                        },
                    )?
                    .expect("AICH job guard");
                published = true;
                ensure!(
                    metadata
                        .download_job(token.job_id)?
                        .is_some_and(|job| job.token == token),
                    "AICH generation changed during publication"
                );
                Ok((identity, acquired, guard))
            }));
            let (result, outcome) = match result {
                Ok(Ok(value)) => (Ok(value), 0),
                Ok(Err(_)) if committed && published => {
                    (Err(LocalMutationError::Committed.into()), 0)
                }
                Ok(Err(error)) if committed => {
                    tracing::error!(%error,"AICH decision committed but publication failed");
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
    pub(in crate::ed2k_transfer) async fn persist_aich_decision(
        &self,
        mut guard: transfer::store::ScopedLockGuard<JobId>,
        manifest: transfer::ResidentDraft,
        expected_generation: u64,
        votes: Option<transfer::aich_trust::AichRootCorroboration>,
    ) -> Result<(
        transfer::ResidentManifest,
        transfer::store::ScopedLockGuard<JobId>,
    )> {
        let token = manifest.token;
        let mut proposal = Some(manifest);
        loop {
            let capacity_revision = self.local_mutations.capacity_revision();
            match self.local_mutations.submit_aich_decision(
                self,
                &mut proposal,
                expected_generation,
                &votes,
                guard,
            ) {
                Ok(receipt) => {
                    let (_identity, _acquired, guard) =
                        receipt.await.map_err(|_| LocalMutationError::Unknown)??;
                    // The owner published the current identity without retaining
                    // a second full proposal geometry across SQL or capacity waits.
                    let manifest = self.load_aich_manifest_unlocked(token).await?;
                    return Ok((manifest, guard));
                }
                Err(error)
                    if matches!(
                        error.downcast_ref::<LocalMutationError>(),
                        Some(LocalMutationError::Busy)
                    ) =>
                {
                    self.local_mutations
                        .wait_for_completion(capacity_revision)
                        .await?;
                    guard = self.lock_manifest(token).await;
                }
                Err(error) => return Err(error),
            }
        }
    }
}
