//! Retained exact-generation peer/name deltas, without manifest snapshots.
use super::*;
use crate::ed2k_transfer as transfer;
use emulebb_metadata::{JobId, JobToken, MetadataDownloadPeerDelta};
use std::sync::atomic::Ordering;

impl LocalMutationRegistry {
    fn submit_peer_delta(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        token: JobToken,
        delta: &MetadataDownloadPeerDelta,
        guard: transfer::store::ScopedLockGuard<JobId>,
    ) -> Result<oneshot::Receiver<Result<bool>>> {
        let bytes = delta.payload_bytes()?;
        ensure!(bytes <= 512 * 1024, LocalMutationError::TooLarge);
        // Both the waiting caller's bounded input and the owner's clone are
        // covered; the compact job header/publication has separate headroom.
        let charge = bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(1024 * 1024))
            .ok_or(LocalMutationError::TooLarge)?;
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        // WHY: only explicit renaming writes a cached manifest. Hint/status/name
        // observations must remain possible without resident execution backing.
        let (resident_write, lease) = if matches!(delta, MetadataDownloadPeerDelta::Rename(_)) {
            let (write, lease) = self.residents.reserve_with(token.job_id, || {
                Self::reserve_unit(&mut state, charge, false, false)
            })?;
            (Some(write), lease)
        } else {
            (None, Self::reserve_unit(&mut state, charge, false, false)?)
        };
        let delta = delta.clone();
        let metadata = runtime.metadata.clone();
        let locks = Arc::clone(&runtime.content_locks);
        let cache = Arc::clone(&runtime.manifest_cache);
        let catalog = Arc::clone(&runtime.shared_catalog);
        let generation = Arc::clone(&runtime.shared_catalog_generation);
        let demand = Arc::clone(&runtime.shared_publish_demand_revision);
        let notify = Arc::clone(&runtime.shared_publish_demand_notify);
        let (sender, receipt) = oneshot::channel();
        #[cfg(test)]
        let publication_gate = state.publication_gate.take();
        Self::spawn_unit_reply(&mut state, lease, sender, move |_capacity| {
            let _guard = guard;
            let mut committed = false;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let job = metadata
                    .download_job(token.job_id)?
                    .ok_or_else(|| anyhow!("missing peer callback job"))?;
                ensure!(job.token == token, "stale peer callback generation");
                let hash = job.file_hash.parse::<emulebb_kad_proto::Ed2kHash>()?;
                let _content =
                    transfer::store::scoped_lock(&locks, job.file_hash).blocking_lock_owned();
                let result = metadata.apply_download_peer_delta(token, &delta)?;
                committed = true;
                #[cfg(test)]
                if let Some((reached, release)) = publication_gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                if let Some(name) = result.display_name {
                    if let Some(manifest) = cache
                        .blocking_lock()
                        .get_mut(&token.job_id)
                        .filter(|value| value.token == token)
                    {
                        manifest.write_with(
                            resident_write.expect("rename reserved resident credit"),
                            |manifest| {
                                manifest.display_name = name.clone();
                                Ok(())
                            },
                        )?;
                    }
                    let mut catalog = catalog.blocking_write();
                    let mut changed = false;
                    catalog.update_by_hash(&hash, |entry| {
                        if !entry.verified_complete && entry.display_name != name {
                            entry.display_name = name.clone();
                            changed = true;
                        }
                    });
                    if changed {
                        generation.fetch_add(1, Ordering::AcqRel);
                    }
                    drop(catalog);
                    demand.fetch_add(1, Ordering::AcqRel);
                    notify.notify_waiters();
                }
                Ok(result.changed)
            }));
            let (result, outcome) = match result {
                Ok(Ok(changed)) => (Ok(changed), 0),
                Ok(Err(error)) if committed => {
                    tracing::error!(%error, "peer delta committed but publication failed");
                    (Err(LocalMutationError::Committed.into()), 1)
                }
                Ok(Err(error)) => (Err(error), 0),
                Err(_) => (Err(LocalMutationError::Unknown.into()), 2),
            };
            (result, outcome)
        });
        Ok(receipt)
    }
}
impl transfer::Ed2kTransferRuntime {
    pub(in crate::ed2k_transfer) async fn apply_peer_delta(
        &self,
        token: JobToken,
        delta: MetadataDownloadPeerDelta,
    ) -> Result<bool> {
        loop {
            let capacity_revision = self.local_mutations.capacity_revision();
            let submitted = self.local_mutations.submit_peer_delta(
                self,
                token,
                &delta,
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
                        .await?;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests;
