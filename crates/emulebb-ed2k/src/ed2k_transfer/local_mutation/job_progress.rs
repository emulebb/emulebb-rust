//! Retained progress batches. Only changed pieces cross the SQL boundary.
use super::*;
use crate::ed2k_transfer as transfer;
use emulebb_metadata::JobId;
use std::{collections::BTreeSet, time::Instant};

const CHECKPOINT_WORKSPACE: usize = 4 * 1024 * 1024;

impl LocalMutationRegistry {
    pub(in crate::ed2k_transfer) fn submit_piece_checkpoint(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        manifest: &transfer::Ed2kResumeManifest,
        dirty: Option<&BTreeSet<u32>>,
        current_piece: u32,
        guard: transfer::store::ScopedLockGuard<JobId>,
    ) -> Result<oneshot::Receiver<Result<()>>> {
        let selected =
            |index: u32| index == current_piece || dirty.is_some_and(|set| set.contains(&index));
        let count = manifest
            .pieces
            .iter()
            .filter(|piece| selected(piece.piece_index))
            .count();
        let expected = dirty.map_or(1, |set| {
            set.len() + usize::from(!set.contains(&current_piece))
        });
        ensure!(
            count == expected && count > 0 && count <= 28_258,
            "checkpoint refers to missing or unsupported piece geometry"
        );
        // Each SQL piece owns one <=8-byte state and one <=14-byte bitmap.
        // There is one exact-capacity Vec, no manifest/hash/source/name clone.
        let required = count
            .checked_mul(std::mem::size_of::<emulebb_metadata::MetadataTransferPiece>() + 22)
            .and_then(|n| n.checked_add(4096))
            .ok_or(LocalMutationError::TooLarge)?;
        ensure!(
            required <= CHECKPOINT_WORKSPACE,
            LocalMutationError::TooLarge
        );
        for piece in manifest
            .pieces
            .iter()
            .filter(|piece| selected(piece.piece_index))
        {
            ensure!(
                piece
                    .block_bitmap
                    .as_ref()
                    .is_none_or(|bitmap| bitmap.len() <= 14),
                LocalMutationError::TooLarge
            );
        }
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let lease = Self::reserve_unit(&mut state, CHECKPOINT_WORKSPACE, false, false)?;
        let mut pieces = Vec::with_capacity(count);
        for piece in manifest
            .pieces
            .iter()
            .filter(|piece| selected(piece.piece_index))
        {
            pieces.push(transfer::transfer_sql::piece_to_metadata(
                piece,
                transfer::expected_piece_length(
                    manifest.file_size,
                    manifest.piece_size,
                    u64::from(piece.piece_index),
                ),
            ));
        }
        let token = manifest.token;
        let hash = manifest.file_hash.clone();
        let metadata = runtime.metadata.clone();
        let locks = Arc::clone(&runtime.content_locks);
        let cache = Arc::clone(&runtime.manifest_cache);
        let checkpoints = Arc::clone(&runtime.manifest_checkpoint_state);
        let (sender, receipt) = oneshot::channel();
        #[cfg(test)]
        let publication_gate = state.publication_gate.take();
        Self::spawn_unit(&mut state, lease, move |_capacity| {
            let _guard = guard;
            let mut committed = false;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _content = transfer::store::scoped_lock(&locks, hash).blocking_lock_owned();
                {
                    let cache = cache.blocking_lock();
                    let current = cache
                        .get(&token.job_id)
                        .filter(|m| m.token == token)
                        .ok_or_else(|| anyhow!("checkpoint has no current execution cache"))?;
                    ensure!(
                        current.intent == emulebb_metadata::DownloadIntent::Started
                            && !current.transfer_row_removed,
                        "checkpoint execution is no longer active"
                    );
                    for piece in &pieces {
                        ensure!(
                            current
                                .pieces
                                .get(piece.piece_index as usize)
                                .is_some_and(|p| p.piece_index == piece.piece_index
                                    && p.bytes_written == piece.prefix_bytes
                                    && p.block_bitmap == piece.block_bitmap
                                    && p.ich_corrupted == piece.ich_corrupted
                                    && matches!(
                                        (p.state, piece.state.as_str()),
                                        (transfer::Ed2kTransferState::Missing, "Missing")
                                            | (transfer::Ed2kTransferState::Verified, "Verified")
                                    )),
                            "checkpoint cache no longer matches selected progress"
                        );
                    }
                }
                ensure!(
                    metadata.checkpoint_download_progress(token, &pieces)?,
                    "checkpoint rejected stale generation or structural transition"
                );
                committed = true;
                #[cfg(test)]
                if let Some((reached, release)) = publication_gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                let cache = cache.blocking_lock();
                let current = cache
                    .get(&token.job_id)
                    .filter(|m| m.token == token)
                    .ok_or_else(|| anyhow!("checkpoint cache disappeared before publication"))?;
                let mut checkpoints = checkpoints.blocking_lock();
                let checkpoint = checkpoints.entry(token).or_insert_with(|| {
                    transfer::Ed2kManifestCheckpointState {
                        revision: 0,
                        persisted_bytes_written: 0,
                        last_persisted_at: Instant::now(),
                        dirty_piece_indexes: BTreeSet::new(),
                    }
                });
                checkpoint.revision = checkpoint
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("download progress revision exhausted"))?;
                // The dirty cache was published before submission. Acknowledge
                // exact selected pieces without rewriting backing held by readers.
                for piece in pieces {
                    let target = &current.pieces[piece.piece_index as usize];
                    let state_matches = matches!(
                        (target.state, piece.state.as_str()),
                        (transfer::Ed2kTransferState::Missing, "Missing")
                            | (transfer::Ed2kTransferState::Verified, "Verified")
                    );
                    if state_matches
                        && target.bytes_written == piece.prefix_bytes
                        && target.block_bitmap == piece.block_bitmap
                        && target.ich_corrupted == piece.ich_corrupted
                    {
                        checkpoint.dirty_piece_indexes.remove(&piece.piece_index);
                    }
                }
                if checkpoint.dirty_piece_indexes.is_empty() {
                    checkpoint.persisted_bytes_written =
                        transfer::manifest::manifest_progress_bytes(current);
                }
                checkpoint.last_persisted_at = Instant::now();
                Ok(())
            }));
            let (result, outcome) = match result {
                Ok(Ok(())) => (Ok(()), 0),
                Ok(Err(error)) if committed => {
                    tracing::error!(%error, "download progress committed but cache publication failed");
                    (Err(LocalMutationError::Committed.into()), 1)
                }
                Ok(Err(error)) => (Err(error), 0),
                Err(_) => (Err(LocalMutationError::Unknown.into()), 2),
            };
            let _ = sender.send(result);
            outcome
        });
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn checkpoint_caller_and_first_drain_cancel_after_sql_still_acknowledge_dirty_progress() {
        let root = crate::paths::unique_test_dir("job-progress-owner");
        let metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let runtime = Arc::new(
            transfer::Ed2kTransferRuntime::load_or_create_with_metadata(&root, metadata.clone())
                .unwrap(),
        );
        let admitted = metadata
            .admit_download_job(&emulebb_metadata::DownloadJobRequest {
                file_hash: "32".repeat(16),
                display_name: "progress.bin".into(),
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
        metadata
            .upsert_transfer_manifest(
                &transfer::transfer_sql::manifest_to_metadata(&manifest).unwrap(),
            )
            .unwrap();
        runtime.manifest_cache.lock().await.insert(
            job.token.job_id,
            runtime
                .local_mutations
                .residents
                .copy_manifest(&manifest)
                .unwrap(),
        );
        manifest.pieces[0].bytes_written = 8;
        let permit = runtime
            .local_mutations
            .residents
            .reserve(job.token.job_id)
            .unwrap();
        drop(
            runtime
                .publish_piece_progress_unlocked(
                    job.token,
                    &job.file_hash,
                    None,
                    &manifest.pieces[0],
                    permit,
                )
                .await
                .unwrap(),
        );
        // Captured fields outside the delta must not overwrite current metadata.
        manifest.comment = "stale callback comment".into();
        let (reached, ready) = oneshot::channel();
        let (release, resume) = std::sync::mpsc::channel();
        runtime
            .local_mutations
            .install_publication_gate(reached, resume);
        let receipt = runtime
            .local_mutations
            .submit_piece_checkpoint(
                &runtime,
                &manifest,
                None,
                0,
                runtime.lock_manifest(job.token).await,
            )
            .unwrap();
        let caller = tokio::spawn(async move { receipt.await });
        tokio::time::timeout(std::time::Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            metadata
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap()
                .pieces[0]
                .prefix_bytes,
            8
        );
        assert_eq!(
            runtime.manifest_cache.lock().await[&job.token.job_id].pieces[0].bytes_written,
            8
        );
        assert!(
            runtime.manifest_checkpoint_state.lock().await[&job.token]
                .dirty_piece_indexes
                .contains(&0)
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
        let cache = runtime.manifest_cache.lock().await;
        assert_eq!(cache[&job.token.job_id].pieces[0].bytes_written, 8);
        assert!(cache[&job.token.job_id].comment.is_empty());
        drop(cache);
        assert!(
            runtime.manifest_checkpoint_state.lock().await[&job.token]
                .dirty_piece_indexes
                .is_empty()
        );
        drop(runtime);
        drop(metadata);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn older_checkpoint_keeps_newer_live_progress_and_dirty_acknowledgment() {
        let root = crate::paths::unique_test_dir("job-progress-live-cas");
        let metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let runtime =
            transfer::Ed2kTransferRuntime::load_or_create_with_metadata(&root, metadata.clone())
                .unwrap();
        let admitted = metadata
            .admit_download_job(&emulebb_metadata::DownloadJobRequest {
                file_hash: "33".repeat(16),
                display_name: "live-progress.bin".into(),
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
        let mut captured = transfer::Ed2kResumeManifest::new(&job);
        metadata
            .upsert_transfer_manifest(
                &transfer::transfer_sql::manifest_to_metadata(&captured).unwrap(),
            )
            .unwrap();
        runtime.manifest_cache.lock().await.insert(
            job.token.job_id,
            runtime
                .local_mutations
                .residents
                .copy_manifest(&captured)
                .unwrap(),
        );
        captured.pieces[0].bytes_written = 8;
        let permit = runtime
            .local_mutations
            .residents
            .reserve(job.token.job_id)
            .unwrap();
        drop(
            runtime
                .publish_piece_progress_unlocked(
                    job.token,
                    &job.file_hash,
                    None,
                    &captured.pieces[0],
                    permit,
                )
                .await
                .unwrap(),
        );
        let (reached, ready) = oneshot::channel();
        let (release, resume) = std::sync::mpsc::channel();
        runtime
            .local_mutations
            .install_publication_gate(reached, resume);
        let receipt = runtime
            .local_mutations
            .submit_piece_checkpoint(
                &runtime,
                &captured,
                None,
                0,
                runtime.lock_manifest(job.token).await,
            )
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        // Exercise the publication CAS itself, independently of normal writer
        // serialization: inject a newer cache publication after actual SQL.
        let mut live = captured.clone();
        live.pieces[0].bytes_written = 12;
        live.comment = "newer live metadata".into();
        runtime.note_dirty_piece_unlocked(&live, 0).await.unwrap();
        runtime.manifest_cache.lock().await.insert(
            job.token.job_id,
            runtime
                .local_mutations
                .residents
                .copy_manifest(&live)
                .unwrap(),
        );
        release.send(()).unwrap();
        receipt.await.unwrap().unwrap();
        assert_eq!(runtime.manifest_cache.lock().await[&job.token.job_id], live);
        assert!(
            runtime.manifest_checkpoint_state.lock().await[&job.token]
                .dirty_piece_indexes
                .contains(&0)
        );
        assert_eq!(
            metadata
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap()
                .pieces[0]
                .prefix_bytes,
            8
        );
        // The preserved dirty entry is durably acknowledged only by a fresh batch.
        let receipt = runtime
            .local_mutations
            .submit_piece_checkpoint(
                &runtime,
                &live,
                None,
                0,
                runtime.lock_manifest(job.token).await,
            )
            .unwrap();
        receipt.await.unwrap().unwrap();
        assert!(
            runtime.manifest_checkpoint_state.lock().await[&job.token]
                .dirty_piece_indexes
                .is_empty()
        );
        assert_eq!(
            metadata
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap()
                .pieces[0]
                .prefix_bytes,
            12
        );
        runtime.local_mutations.seal_and_drain().await.unwrap();
        drop(runtime);
        drop(metadata);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn unrelated_piece_progress_does_not_prevent_selected_piece_acknowledgment() {
        let root = crate::paths::unique_test_dir("job-progress-independent-ack");
        let metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let runtime =
            transfer::Ed2kTransferRuntime::load_or_create_with_metadata(&root, metadata.clone())
                .unwrap();
        let size = transfer::ED2K_PART_SIZE + 16;
        let admitted = metadata
            .admit_download_job(&emulebb_metadata::DownloadJobRequest {
                file_hash: "34".repeat(16),
                display_name: "two-pieces.bin".into(),
                expected_size_bytes: Some(size),
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
            size,
        );
        let mut live = transfer::Ed2kResumeManifest::new(&job);
        metadata
            .upsert_transfer_manifest(&transfer::transfer_sql::manifest_to_metadata(&live).unwrap())
            .unwrap();
        live.pieces[0].bytes_written = 8;
        runtime.note_dirty_piece_unlocked(&live, 0).await.unwrap();
        runtime.manifest_cache.lock().await.insert(
            job.token.job_id,
            runtime
                .local_mutations
                .residents
                .copy_manifest(&live)
                .unwrap(),
        );
        let (reached, ready) = oneshot::channel();
        let (release, resume) = std::sync::mpsc::channel();
        runtime
            .local_mutations
            .install_publication_gate(reached, resume);
        let receipt = runtime
            .local_mutations
            .submit_piece_checkpoint(
                &runtime,
                &live,
                None,
                0,
                runtime.lock_manifest(job.token).await,
            )
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        live.pieces[1].bytes_written = 12;
        runtime.note_dirty_piece_unlocked(&live, 1).await.unwrap();
        runtime.manifest_cache.lock().await.insert(
            job.token.job_id,
            runtime
                .local_mutations
                .residents
                .copy_manifest(&live)
                .unwrap(),
        );
        release.send(()).unwrap();
        receipt.await.unwrap().unwrap();
        assert_eq!(runtime.manifest_cache.lock().await[&job.token.job_id], live);
        assert_eq!(
            runtime.manifest_checkpoint_state.lock().await[&job.token].dirty_piece_indexes,
            BTreeSet::from([1])
        );
        let durable = metadata
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap();
        assert_eq!(durable.pieces[0].prefix_bytes, 8);
        assert_eq!(durable.pieces[1].prefix_bytes, 0);
        let receipt = runtime
            .local_mutations
            .submit_piece_checkpoint(
                &runtime,
                &live,
                None,
                1,
                runtime.lock_manifest(job.token).await,
            )
            .unwrap();
        receipt.await.unwrap().unwrap();
        assert!(
            runtime.manifest_checkpoint_state.lock().await[&job.token]
                .dirty_piece_indexes
                .is_empty()
        );
        assert_eq!(
            metadata
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap()
                .pieces[1]
                .prefix_bytes,
            12
        );
        runtime.local_mutations.seal_and_drain().await.unwrap();
        drop(runtime);
        drop(metadata);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn maximum_piece_delta_capacity_fits_ordinary_workspace() {
        let mut rows = Vec::with_capacity(28_258);
        for piece_index in 0..28_258 {
            rows.push(emulebb_metadata::MetadataTransferPiece {
                piece_index,
                state: "Verified".into(),
                prefix_bytes: transfer::ED2K_PART_SIZE,
                present_bytes: transfer::ED2K_PART_SIZE,
                block_bitmap: Some("7fffffffffffff".into()),
                ich_corrupted: false,
            });
        }
        let owned = rows.capacity()
            * std::mem::size_of::<emulebb_metadata::MetadataTransferPiece>()
            + rows
                .iter()
                .map(|piece| {
                    piece.state.capacity() + piece.block_bitmap.as_ref().unwrap().capacity()
                })
                .sum::<usize>();
        assert!(owned + 4096 <= CHECKPOINT_WORKSPACE);
    }
}
