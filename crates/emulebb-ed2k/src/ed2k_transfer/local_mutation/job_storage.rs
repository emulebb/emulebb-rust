//! Retained physical job allocation. An existing unowned directory is never adopted.
use super::*;
use crate::ed2k_transfer as transfer;
use anyhow::Context;
use emulebb_metadata::{DownloadIntent, DownloadJobStorage, JobToken};
use std::io::{Read, Write};

// Two bounded persisted native paths, compact job text, and their native/display
// conversions fit here. No manifest, payload or directory inventory is retained.
// Shared long-FS admission leaves a slot and >=6 MiB for ordinary publication.
const STORAGE_WORKSPACE: usize = 1024 * 1024;

impl LocalMutationRegistry {
    pub(super) fn submit_prepare_storage(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        token: JobToken,
        lifecycle: transfer::store::ScopedLockGuard<emulebb_metadata::JobId>,
        manifest_guard: transfer::store::ScopedLockGuard<emulebb_metadata::JobId>,
    ) -> Result<oneshot::Receiver<Result<DownloadJobStorage>>> {
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let capacity_lease = Self::reserve_long_fs(&mut state, STORAGE_WORKSPACE)?;
        let metadata = runtime.metadata.clone();
        let resident = Arc::clone(&runtime.job_storage);
        let content_locks = Arc::clone(&runtime.content_locks);
        let (sender, receive) = oneshot::channel();
        #[cfg(test)]
        let publication_gate = state.publication_gate.take();
        Self::spawn_unit(&mut state, capacity_lease, move |_capacity| {
            let _lifecycle = lifecycle;
            let _manifest = manifest_guard;
            let mut committed = false;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let job = metadata
                    .download_job(token.job_id)?
                    .context("missing allocated job")?;
                ensure!(
                    job.token == token
                        && job.intent == DownloadIntent::Started
                        && job.removed_at_s.is_none()
                        && job.completed_at_s.is_none(),
                    "stale or inactive job storage request"
                );
                let mut storage = job
                    .storage
                    .context("job temp storage was not persisted before allocation")?;
                let native = crate::long_path::long_path(&storage.path);
                let establish = storage.identity.is_none();
                if establish {
                    // create_dir, never create_dir_all: even empty crash residue
                    // without established authority remains untouched.
                    std::fs::create_dir(&native)
                        .context("exclusive job directory allocation failed")?;
                    let identity = transfer::ingest::native_directory_identity(&native)
                        .context("allocated job directory has no stable native identity")?;
                    let marker = transfer::metadata::transfer_directory_authority_marker_path(
                        &native,
                        storage.marker_id,
                    );
                    let mut file = std::fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(&marker)?;
                    file.write_all(storage.marker_id.as_bytes())?;
                    file.sync_all()?;
                    drop(file);
                    transfer::fs_durability::sync_directory(&native)?;
                    transfer::fs_durability::sync_directory(
                        native.parent().context("job storage has no parent")?,
                    )?;
                    ensure!(
                        transfer::ingest::native_directory_identity(&native) == Some(identity),
                        "allocated job directory changed before ownership publication"
                    );
                    storage.identity = Some(identity);
                }
                validate_storage(&storage)?;
                // The short commit/publication fence starts only after physical
                // work. Logical removal shares it without waiting this job's I/O
                // guard, and a late allocation cannot resurrect a removed session.
                let _content = transfer::store::scoped_lock(&content_locks, job.file_hash)
                    .blocking_lock_owned();
                if establish {
                    ensure!(
                        metadata.establish_download_job_storage(
                            token,
                            storage.identity.expect("verified allocation identity")
                        )?,
                        "job generation changed during storage allocation"
                    );
                    committed = true;
                } else {
                    let current = metadata
                        .download_job(token.job_id)?
                        .context("allocated job disappeared")?;
                    ensure!(
                        current.token == token
                            && current.intent == DownloadIntent::Started
                            && current.removed_at_s.is_none()
                            && current.completed_at_s.is_none(),
                        "job generation changed during allocation validation"
                    );
                }
                #[cfg(test)]
                if let Some((reached, release)) = publication_gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                resident
                    .lock()
                    .map_err(|_| LocalMutationError::Unknown)?
                    .insert(
                        token.job_id,
                        transfer::store::JobStorageSession {
                            token,
                            storage: storage.clone(),
                        },
                    );
                Ok(storage)
            }));
            let (result, outcome) = match result {
                Ok(Ok(storage)) => (Ok(storage), 0),
                Ok(Err(error)) if committed => {
                    tracing::error!(%error, "job storage committed but publication failed");
                    (Err(LocalMutationError::Committed.into()), 1)
                }
                Ok(Err(error)) => (Err(error), 0),
                Err(_) => (Err(LocalMutationError::Unknown.into()), 2),
            };
            let _ = sender.send(result);
            outcome
        });
        Ok(receive)
    }
}

pub(in crate::ed2k_transfer) fn validate_storage(storage: &DownloadJobStorage) -> Result<()> {
    let path = crate::long_path::long_path(&storage.path);
    let expected = storage
        .identity
        .context("job storage has no established identity")?;
    ensure!(
        transfer::ingest::native_directory_identity(&path) == Some(expected),
        "job storage directory identity changed"
    );
    let marker =
        transfer::metadata::transfer_directory_authority_marker_path(&path, storage.marker_id);
    let file = transfer::ingest::open_regular_file_without_follow(&marker)
        .context("job storage marker unavailable")?;
    let mut bytes = [0u8; 17];
    let length = std::io::copy(&mut file.take(17), &mut bytes.as_mut_slice())?;
    ensure!(
        length == 16 && bytes[..16] == storage.marker_id.as_bytes()[..],
        "job storage marker changed"
    );
    ensure!(
        transfer::ingest::native_directory_identity(&path) == Some(expected),
        "job storage directory changed during marker validation"
    );
    Ok(())
}

impl transfer::Ed2kTransferRuntime {
    /// Prepare only an already persisted allocation. The actual blocking unit,
    /// guards, store and receipt survive cancellation and join the normal drain.
    pub async fn prepare_download_job_storage(
        &self,
        token: JobToken,
    ) -> Result<DownloadJobStorage> {
        loop {
            let capacity_revision = self.local_mutations.capacity_revision();
            let submitted = {
                let lifecycle = self.lock_lifecycle(token.job_id).await;
                let manifest = self.lock_manifest(token).await;
                self.local_mutations
                    .submit_prepare_storage(self, token, lifecycle, manifest)
            };
            match submitted {
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
                Ok(receipt) => return receipt.await.map_err(|_| LocalMutationError::Unknown)?,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn allocate(
        metadata: &emulebb_metadata::MetadataStore,
        root: &std::path::Path,
    ) -> emulebb_metadata::DownloadJobRecord {
        let job = metadata
            .admit_download_job(&emulebb_metadata::DownloadJobRequest {
                file_hash: "11".repeat(16),
                display_name: "owned.bin".into(),
                expected_size_bytes: Some(1),
                category_id: None,
                intent: DownloadIntent::Started,
                piece_size: transfer::ED2K_PART_SIZE,
            })
            .unwrap()
            .job;
        metadata
            .start_download_job(job.token, root)
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn unknown_existing_storage_directory_is_never_stamped_or_adopted() {
        let root = crate::paths::unique_test_dir("job-storage-unknown");
        let metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let runtime =
            transfer::Ed2kTransferRuntime::load_or_create_with_metadata(&root, metadata.clone())
                .unwrap();
        let job = allocate(&metadata, &root);
        let storage = job.storage.unwrap();
        std::fs::create_dir(&storage.path).unwrap();
        std::fs::write(storage.path.join("foreign.bin"), b"preserve").unwrap();
        assert!(
            runtime
                .prepare_download_job_storage(job.token)
                .await
                .is_err()
        );
        assert!(
            metadata
                .download_job(job.token.job_id)
                .unwrap()
                .unwrap()
                .storage
                .unwrap()
                .identity
                .is_none()
        );
        assert!(
            !transfer::metadata::transfer_directory_authority_marker_path(
                &storage.path,
                storage.marker_id
            )
            .exists()
        );
        assert_eq!(
            std::fs::read(storage.path.join("foreign.bin")).unwrap(),
            b"preserve"
        );
        runtime.local_mutations.seal_and_drain().await.unwrap();
        drop(runtime);
        drop(metadata);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn fresh_profiles_share_temp_without_sharing_physical_job_storage() {
        let root = crate::paths::unique_test_dir("job-storage-two-profiles");
        let shared_temp = root.join("temp");
        std::fs::create_dir_all(&shared_temp).unwrap();
        let first_db = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let second_db = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let first = transfer::Ed2kTransferRuntime::load_or_create_with_metadata(
            &root.join("first"),
            first_db.clone(),
        )
        .unwrap();
        let second = transfer::Ed2kTransferRuntime::load_or_create_with_metadata(
            &root.join("second"),
            second_db.clone(),
        )
        .unwrap();
        let a = allocate(&first_db, &shared_temp);
        let b = allocate(&second_db, &shared_temp);
        assert_eq!(a.token.job_id, b.token.job_id);
        let a = first.prepare_download_job_storage(a.token).await.unwrap();
        let b = second.prepare_download_job_storage(b.token).await.unwrap();
        assert_ne!(a.path, b.path);
        assert_ne!(a.marker_id, b.marker_id);
        validate_storage(&a).unwrap();
        validate_storage(&b).unwrap();
        first.local_mutations.seal_and_drain().await.unwrap();
        second.local_mutations.seal_and_drain().await.unwrap();
        drop(first);
        drop(second);
        drop(first_db);
        drop(second_db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn creation_crash_before_or_after_marker_never_claims_unestablished_directory() {
        for marker_written in [false, true] {
            let root = crate::paths::unique_test_dir("job-storage-creation-crash");
            let metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
            let runtime = transfer::Ed2kTransferRuntime::load_or_create_with_metadata(
                &root,
                metadata.clone(),
            )
            .unwrap();
            let job = allocate(&metadata, &root);
            let storage = job.storage.unwrap();
            std::fs::create_dir(&storage.path).unwrap();
            let marker = transfer::metadata::transfer_directory_authority_marker_path(
                &storage.path,
                storage.marker_id,
            );
            if marker_written {
                std::fs::write(&marker, storage.marker_id.as_bytes()).unwrap();
            }
            for _ in 0..2 {
                assert!(
                    runtime
                        .prepare_download_job_storage(job.token)
                        .await
                        .is_err()
                );
                assert!(
                    metadata
                        .download_job(job.token.job_id)
                        .unwrap()
                        .unwrap()
                        .storage
                        .unwrap()
                        .identity
                        .is_none()
                );
                assert!(!storage.path.join(transfer::PAYLOAD_FILE_NAME).exists());
                assert_eq!(marker.exists(), marker_written);
                if marker_written {
                    assert_eq!(
                        std::fs::read(&marker).unwrap(),
                        storage.marker_id.as_bytes()
                    );
                }
            }
            runtime.local_mutations.seal_and_drain().await.unwrap();
            drop(runtime);
            drop(metadata);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn cancelled_storage_caller_and_first_drain_retain_actual_allocation_publication() {
        let root = crate::paths::unique_test_dir("job-storage-cancel");
        let metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let runtime = Arc::new(
            transfer::Ed2kTransferRuntime::load_or_create_with_metadata(&root, metadata.clone())
                .unwrap(),
        );
        let job = allocate(&metadata, &root);
        let (reached, ready) = oneshot::channel();
        let (release, resume) = std::sync::mpsc::channel();
        runtime
            .local_mutations
            .install_publication_gate(reached, resume);
        let caller_runtime = Arc::clone(&runtime);
        let caller =
            tokio::spawn(
                async move { caller_runtime.prepare_download_job_storage(job.token).await },
            );
        tokio::time::timeout(std::time::Duration::from_secs(10), ready)
            .await
            .unwrap()
            .unwrap();
        let persisted = metadata
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .storage
            .unwrap();
        assert!(persisted.identity.is_some());
        assert!(runtime.job_storage.lock().unwrap().is_empty());
        {
            let state = runtime.local_mutations.state.lock().unwrap();
            assert_eq!(state.tasks.len(), 1);
            assert_eq!(state.capacity.usage().bytes, STORAGE_WORKSPACE);
            assert!(
                MAX_BYTES - state.capacity.usage().bytes >= PUBLICATION_WORKSPACE + 1024 * 1024
            );
            assert_eq!(state.capacity.usage().long_fs_units, 1);
        }
        caller.abort();
        let _ = caller.await;
        let pending = runtime.local_mutations.signal_next_pending_drain();
        let first_runtime = Arc::clone(&runtime);
        let first =
            tokio::spawn(async move { first_runtime.local_mutations.seal_and_drain().await });
        tokio::time::timeout(std::time::Duration::from_secs(10), pending)
            .await
            .unwrap()
            .unwrap();
        first.abort();
        let _ = first.await;
        assert_eq!(
            runtime
                .local_mutations
                .state
                .lock()
                .unwrap()
                .capacity
                .usage()
                .long_fs_units,
            1
        );
        release.send(()).unwrap();
        runtime.local_mutations.seal_and_drain().await.unwrap();
        assert_eq!(
            runtime
                .job_storage
                .lock()
                .unwrap()
                .get(&job.token.job_id)
                .map(|session| &session.storage),
            Some(&persisted)
        );
        assert_eq!(
            runtime
                .local_mutations
                .state
                .lock()
                .unwrap()
                .capacity
                .usage()
                .long_fs_units,
            0
        );
        assert!(!persisted.path.join(transfer::PAYLOAD_FILE_NAME).exists());
        validate_storage(&persisted).unwrap();
        drop(runtime);
        drop(metadata);
        std::fs::remove_dir_all(root).unwrap();
    }
}
