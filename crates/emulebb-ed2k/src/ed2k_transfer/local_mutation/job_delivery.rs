//! Small delivery evidence transitions retained through their cache publication.
use super::*;
use crate::ed2k_transfer as transfer;
use emulebb_metadata::{JobId, JobToken, NativeFileFingerprint};
use std::path::Path;

impl LocalMutationRegistry {
    /// A cancelled delivery waiter must leave its job and filesystem admission
    /// fenced until the underlying syscall has returned.
    pub(in crate::ed2k_transfer) fn submit_delivery_io<T: Send + 'static>(
        &self,
        guard: transfer::store::ScopedLockGuard<JobId>,
        operation: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<oneshot::Receiver<Result<T>>> {
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        // Copy and hashing are sequential and use bounded buffers.
        const DELIVERY_IO_WORKSPACE: usize = 512 * 1024;
        let lease = Self::reserve_long_fs(&mut state, DELIVERY_IO_WORKSPACE)?;
        let (sender, receipt) = oneshot::channel();
        Self::spawn_unit_reply(&mut state, lease, sender, move |_| {
            let _guard = guard;
            (operation(), 0)
        });
        Ok(receipt)
    }

    /// The caller already verified bytes and holds this exact job guard. The
    /// registry owns the SQL/cache boundary even if its receipt is abandoned.
    #[expect(
        clippy::too_many_arguments,
        reason = "exact captured delivery authority boundary"
    )]
    pub(in crate::ed2k_transfer) fn submit_delivery_verification(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        token: JobToken,
        path: &Path,
        previous: Option<&NativeFileFingerprint>,
        ownership: transfer::Ed2kDeliveryOwnership,
        verified: &NativeFileFingerprint,
        guard: transfer::store::ScopedLockGuard<JobId>,
    ) -> Result<oneshot::Receiver<Result<()>>> {
        let charge = withdrawal_path_charge(path)?
            .checked_add(4096)
            .ok_or(LocalMutationError::TooLarge)?;
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let (resident_write, lease) = self.residents.reserve_with(token.job_id, || {
            Self::reserve_unit(&mut state, charge, false, false)
        })?;
        let path = path.to_path_buf();
        let previous = previous.cloned();
        let verified = verified.clone();
        let metadata = runtime.metadata.clone();
        let cache = Arc::clone(&runtime.manifest_cache);
        let (sender, receipt) = oneshot::channel();
        #[cfg(test)]
        let publication_gate = state.publication_gate.take();
        Self::spawn_unit_reply(&mut state, lease, sender, move |_capacity| {
            let _guard = guard;
            let mut committed = false;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let expected = match ownership {
                    transfer::Ed2kDeliveryOwnership::None => {
                        emulebb_metadata::MetadataTransferDeliveryOwnership::None
                    }
                    transfer::Ed2kDeliveryOwnership::Owned => {
                        emulebb_metadata::MetadataTransferDeliveryOwnership::Owned
                    }
                    transfer::Ed2kDeliveryOwnership::Unowned => {
                        emulebb_metadata::MetadataTransferDeliveryOwnership::Unowned
                    }
                };
                ensure!(
                    metadata.refresh_delivered_verification(
                        token,
                        &path,
                        previous.as_ref(),
                        expected,
                        &verified
                    )?,
                    "recorded delivery changed during verification"
                );
                committed = true;
                #[cfg(test)]
                if let Some((reached, release)) = publication_gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                // Patch only evidence. Never replay captured piece progress,
                // category, counters or a newer execution generation.
                let mut cache = cache.blocking_lock();
                if let Some(manifest) = cache.get_mut(&token.job_id).filter(|m| m.token == token) {
                    ensure!(
                        manifest.delivery_state == transfer::Ed2kDeliveryState::Delivered
                            && manifest.delivered_path.as_ref() == Some(&path)
                            && manifest.source_fingerprint == previous
                            && manifest.delivery_ownership == ownership,
                        "delivery cache changed before verification publication"
                    );
                    manifest.write_with(resident_write, |manifest| {
                        manifest.source_fingerprint = Some(verified);
                        manifest.delivery_ownership = transfer::Ed2kDeliveryOwnership::Unowned;
                        Ok(())
                    })?;
                }
                Ok(())
            }));
            let (result, outcome) = match result {
                Ok(Ok(())) => (Ok(()), 0),
                Ok(Err(error)) if committed => {
                    tracing::error!(%error, "delivery verification committed but publication failed");
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

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cancelled_delivery_verification_receipt_and_drain_retain_cache_publication() {
        let root = crate::paths::unique_test_dir("job-delivery-evidence");
        let metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let runtime = Arc::new(
            transfer::Ed2kTransferRuntime::load_or_create_with_metadata(&root, metadata.clone())
                .unwrap(),
        );
        let admitted = metadata
            .admit_download_job(&emulebb_metadata::DownloadJobRequest {
                file_hash: "11".repeat(16),
                display_name: "delivered.bin".into(),
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
        manifest.completed = true;
        manifest.md4_hashset_acquired = true;
        manifest.pieces[0].state = transfer::Ed2kTransferState::Verified;
        manifest.pieces[0].bytes_written = 16;
        manifest.verified_ranges = vec![transfer::Ed2kSharedRange { start: 0, end: 16 }];
        manifest.delivery_state = transfer::Ed2kDeliveryState::Delivered;
        manifest.delivery_ownership = transfer::Ed2kDeliveryOwnership::Owned;
        let path = root.join("delivered.bin");
        manifest.delivered_path = Some(path.clone());
        let original = NativeFileFingerprint {
            identity: emulebb_metadata::NativeFileIdentity::Unix {
                device_id: 1,
                inode_number: 2,
            },
            size_bytes: 16,
            modified: emulebb_metadata::NativeFileTimestamp::new(100, 1).unwrap(),
            changed: None,
        };
        manifest.source_fingerprint = Some(original.clone());
        metadata
            .upsert_transfer_manifest(
                &transfer::transfer_sql::manifest_to_metadata(&manifest).unwrap(),
            )
            .unwrap();
        runtime.manifest_cache.lock().await.insert_fixture(
            job.token.job_id,
            runtime
                .local_mutations
                .residents
                .copy_manifest(&manifest)
                .unwrap(),
        );
        let mut verified = original.clone();
        verified.modified = emulebb_metadata::NativeFileTimestamp::new(100, 2).unwrap();
        let (reached, ready) = oneshot::channel();
        let (release, resume) = std::sync::mpsc::channel();
        runtime
            .local_mutations
            .install_publication_gate(reached, resume);
        let guard = runtime.lock_manifest(job.token).await;
        let receipt = runtime
            .local_mutations
            .submit_delivery_verification(
                &runtime,
                job.token,
                &path,
                Some(&original),
                transfer::Ed2kDeliveryOwnership::Owned,
                &verified,
                guard,
            )
            .unwrap();
        let caller = tokio::spawn(receipt);
        tokio::time::timeout(std::time::Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            metadata
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap()
                .source_fingerprint,
            Some(verified.clone())
        );
        assert_eq!(
            runtime.manifest_cache.lock().await[&job.token.job_id],
            manifest
        );
        caller.abort();
        let _ = caller.await;
        let pending = runtime.local_mutations.signal_next_pending_drain();
        let first_runtime = Arc::clone(&runtime);
        let first =
            tokio::spawn(async move { first_runtime.local_mutations.seal_and_drain().await });
        tokio::time::timeout(std::time::Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap();
        first.abort();
        let _ = first.await;
        release.send(()).unwrap();
        runtime.local_mutations.seal_and_drain().await.unwrap();
        manifest.source_fingerprint = Some(verified);
        manifest.delivery_ownership = transfer::Ed2kDeliveryOwnership::Unowned;
        assert_eq!(
            runtime.manifest_cache.lock().await[&job.token.job_id],
            manifest
        );
        drop(runtime);
        drop(metadata);
        std::fs::remove_dir_all(root).unwrap();
    }
}
