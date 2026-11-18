//! Cold demand lookup and capture share the existing retained command owner.
use super::*;
use crate::ed2k_transfer::Ed2kTransferRuntime;
use emulebb_kad_proto::Ed2kHash;

const WORKSPACE: usize = 4096;

impl LocalMutationRegistry {
    pub(in crate::ed2k_transfer) fn submit_upload_demand(
        &self,
        runtime: &Ed2kTransferRuntime,
        hash: Ed2kHash,
        at_s: i64,
    ) -> Result<oneshot::Receiver<Result<bool>>> {
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let lease = Self::reserve_unit(&mut state, WORKSPACE, false, false)?;
        let accounting = runtime.parked_credit_flush_parts();
        let catalog = runtime.shared_catalog();
        let signal = runtime.shared_publish_demand_signal();
        let (send, receive) = oneshot::channel();
        #[cfg(test)]
        let gate = state.publication_gate.take();
        Self::spawn_unit_reply(&mut state, lease, send, move |_| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #[cfg(test)]
                if let Some((reached, release)) = gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                let changed = accounting.classify_and_capture_file_request(&hash, at_s)?;
                if changed {
                    if let Ok(mut catalog) = catalog.try_write() {
                        catalog.sync_accounting(&hash);
                    }
                    signal.publish();
                }
                Ok(changed)
            }));
            match result {
                Ok(result) => {
                    if let Err(error) = &result {
                        tracing::warn!("retained cold upload demand failed: {error:#}");
                    }
                    (result, 0)
                }
                Err(_) => (Err(LocalMutationError::Unknown.into()), 2),
            }
        });
        Ok(receive)
    }
}

impl Ed2kTransferRuntime {
    pub(in crate::ed2k_transfer) async fn capture_cold_upload_demand(
        &self,
        hash: Ed2kHash,
        at_s: i64,
    ) -> Result<bool> {
        loop {
            let revision = self.local_mutations.capacity_revision();
            match self.local_mutations.submit_upload_demand(self, hash, at_s) {
                Ok(receipt) => return receipt.await.map_err(|_| LocalMutationError::Unknown)?,
                Err(error)
                    if matches!(
                        error.downcast_ref::<LocalMutationError>(),
                        Some(LocalMutationError::Busy)
                    ) =>
                {
                    self.local_mutations.wait_for_completion(revision).await?;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_transfer::test_support::admit_download_job;

    #[tokio::test]
    async fn cancelled_cold_caller_and_drain_retain_capture_until_checkpoint() {
        let root = tempfile::tempdir().unwrap();
        let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(root.path()).unwrap());
        let hash = Ed2kHash::from_bytes([0x47; 16]);
        admit_download_job(&runtime, hash, "Sample.bin".into(), 32);
        assert!(runtime.file_upload_statistics(&hash).is_none());
        let signal = runtime.shared_publish_demand_signal();
        let revision = signal.revision();
        let (started, ready) = oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        runtime
            .local_mutations
            .install_publication_gate(started, gate);
        let caller = {
            let runtime = Arc::clone(&runtime);
            tokio::spawn(async move { runtime.note_file_upload_request(&hash).await })
        };
        ready.await.unwrap();
        caller.abort();
        let _ = caller.await;
        assert_eq!(
            runtime
                .local_mutations
                .state
                .lock()
                .unwrap()
                .capacity
                .usage()
                .bytes,
            WORKSPACE
        );
        let pending = runtime.local_mutations.signal_next_pending_drain();
        let drain = {
            let runtime = Arc::clone(&runtime);
            tokio::spawn(async move { runtime.drain_local_mutations().await })
        };
        pending.await.unwrap();
        drain.abort();
        let _ = drain.await;
        assert!(matches!(
            runtime
                .local_mutations
                .submit_upload_demand(&runtime, hash, 0)
                .unwrap_err()
                .downcast_ref::<LocalMutationError>(),
            Some(LocalMutationError::Closing)
        ));
        assert_eq!(
            runtime
                .local_mutations
                .state
                .lock()
                .unwrap()
                .capacity
                .usage()
                .bytes,
            WORKSPACE
        );
        release.send(()).unwrap();
        runtime.drain_local_mutations().await.unwrap();
        assert_eq!(
            runtime
                .local_mutations
                .state
                .lock()
                .unwrap()
                .capacity
                .usage()
                .bytes,
            0
        );
        let captured = runtime.file_upload_statistics(&hash).unwrap();
        assert_eq!(captured.session_upload_requests, 1);
        assert_eq!(captured.lifetime.upload_requests, 1);
        assert_eq!(signal.revision(), revision + 1);
        assert_eq!(
            runtime
                .metadata
                .file_upload_snapshot(&hash.to_string())
                .unwrap()
                .unwrap()
                .totals
                .upload_requests,
            0
        );
        runtime.checkpoint_upload_accounting().await.unwrap();
        assert_eq!(
            runtime
                .metadata
                .file_upload_snapshot(&hash.to_string())
                .unwrap()
                .unwrap()
                .totals,
            captured.lifetime
        );
    }

    #[tokio::test]
    async fn cold_demand_refusal_has_no_capture_and_admitted_unknown_has_no_record() {
        let root = tempfile::tempdir().unwrap();
        let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let hash = Ed2kHash::from_bytes([0x48; 16]);
        let held = {
            let mut state = runtime.local_mutations.state.lock().unwrap();
            LocalMutationRegistry::reserve_unit(&mut state, MAX_BYTES, false, false).unwrap()
        };
        assert!(matches!(
            runtime
                .local_mutations
                .submit_upload_demand(&runtime, hash, 0)
                .unwrap_err()
                .downcast_ref::<LocalMutationError>(),
            Some(LocalMutationError::Busy)
        ));
        assert!(runtime.file_upload_statistics(&hash).is_none());
        drop(held);
        assert!(!runtime.capture_cold_upload_demand(hash, 0).await.unwrap());
        runtime.drain_local_mutations().await.unwrap();
        runtime.checkpoint_upload_accounting().await.unwrap();
        assert!(runtime.file_upload_statistics(&hash).is_none());
        assert!(
            runtime
                .metadata
                .file_upload_snapshot(&hash.to_string())
                .unwrap()
                .is_none()
        );
    }
}
