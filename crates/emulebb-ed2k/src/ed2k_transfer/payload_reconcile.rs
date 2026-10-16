//! Startup reconciliation between persisted download progress and `pieces.bin`.

use anyhow::{Context, Result};

use super::manifest::{expected_piece_length, rebuild_verified_ranges};
use super::{
    Ed2kIncompletePayloadReconciliation, Ed2kResumeManifest, Ed2kTransferRuntime,
    Ed2kTransferState, PAYLOAD_FILE_NAME,
};

impl Ed2kTransferRuntime {
    /// Reconcile persisted incomplete downloads before transfer hydration or
    /// network publication can expose them.
    ///
    /// Missing directories are safe to recreate because the SQLite row proves
    /// ownership of the canonical hash path. Missing or truncated payloads
    /// demote every claimed piece because extent alone cannot prove that an
    /// earlier prefix still belongs to the persisted ED2K identity. Wrong
    /// filesystem types are preserved and fail startup instead of deleting an
    /// unprovable occupant or advertising bytes that cannot be read.
    pub async fn reconcile_incomplete_download_payloads(
        &self,
    ) -> Result<Ed2kIncompletePayloadReconciliation> {
        let candidates = self.incomplete_manifests_snapshot().await?;
        let mut reconciliation = Ed2kIncompletePayloadReconciliation::default();

        for candidate in candidates {
            let file_hash = candidate.file_hash;
            let _lifecycle_guard = self.lock_lifecycle(&file_hash).await;
            let _manifest_guard = self.lock_manifest(&file_hash).await;
            let Some(mut manifest) = self.load_manifest_optional_unlocked(&file_hash).await? else {
                continue;
            };
            if manifest.completed || manifest.source_path.is_some() {
                continue;
            }

            reconciliation.inspected_downloads =
                reconciliation.inspected_downloads.saturating_add(1);
            self.invalidate_payload_handle(&file_hash);
            let transfer_dir = self.transfer_dir(&file_hash);
            let transfer_dir_metadata = match tokio::fs::symlink_metadata(&transfer_dir).await {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tokio::fs::create_dir_all(&transfer_dir)
                        .await
                        .with_context(|| {
                            format!(
                                "failed to recreate ED2K transfer directory {}",
                                transfer_dir.display()
                            )
                        })?;
                    reconciliation.recreated_directories =
                        reconciliation.recreated_directories.saturating_add(1);
                    let reset_pieces = reconcile_manifest_payload_len(&mut manifest, 0);
                    if persist_reconciled_manifest(self, &manifest, reset_pieces).await? {
                        reconciliation.repaired_downloads =
                            reconciliation.repaired_downloads.saturating_add(1);
                        reconciliation.reset_pieces =
                            reconciliation.reset_pieces.saturating_add(reset_pieces);
                    }
                    continue;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to inspect ED2K transfer directory {}",
                            transfer_dir.display()
                        )
                    });
                }
            };
            anyhow::ensure!(
                transfer_dir_metadata.file_type().is_dir(),
                "persisted ED2K download {file_hash} owns {}, but the path is not a directory",
                transfer_dir.display()
            );

            let payload_path = transfer_dir.join(PAYLOAD_FILE_NAME);
            let payload_len = match tokio::fs::symlink_metadata(&payload_path).await {
                Ok(metadata) => {
                    anyhow::ensure!(
                        metadata.file_type().is_file(),
                        "persisted ED2K download {file_hash} owns {}, but the payload is not a regular file",
                        payload_path.display()
                    );
                    metadata.len()
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to inspect ED2K payload {}", payload_path.display())
                    });
                }
            };
            let reset_pieces = reconcile_manifest_payload_len(&mut manifest, payload_len);
            if persist_reconciled_manifest(self, &manifest, reset_pieces).await? {
                reconciliation.repaired_downloads =
                    reconciliation.repaired_downloads.saturating_add(1);
                reconciliation.reset_pieces =
                    reconciliation.reset_pieces.saturating_add(reset_pieces);
            }
        }

        Ok(reconciliation)
    }
}

fn reconcile_manifest_payload_len(manifest: &mut Ed2kResumeManifest, payload_len: u64) -> usize {
    let claimed_relative_ends = manifest
        .pieces
        .iter()
        .map(|piece| {
            let part_len = expected_piece_length(
                manifest.file_size,
                manifest.piece_size,
                u64::from(piece.piece_index),
            );
            if piece.state == Ed2kTransferState::Verified || piece.ich_corrupted {
                part_len
            } else if piece.block_bitmap.is_some() {
                piece
                    .resolve_block_bitmap(part_len)
                    .highest_present_end()
                    .max(piece.bytes_written.min(part_len))
            } else {
                piece.bytes_written.min(part_len)
            }
        })
        .collect::<Vec<_>>();
    let claimed_payload_end = manifest
        .pieces
        .iter()
        .zip(&claimed_relative_ends)
        .filter_map(|(piece, claimed_relative_end)| {
            if *claimed_relative_end == 0 {
                None
            } else {
                Some(
                    u64::from(piece.piece_index)
                        .saturating_mul(manifest.piece_size)
                        .saturating_add(*claimed_relative_end),
                )
            }
        })
        .max()
        .unwrap_or(0);

    let mut reset_pieces = 0usize;
    if claimed_payload_end > payload_len {
        for (piece, claimed_relative_end) in manifest.pieces.iter_mut().zip(claimed_relative_ends) {
            if claimed_relative_end == 0 {
                continue;
            }
            piece.state = Ed2kTransferState::Missing;
            piece.bytes_written = 0;
            piece.block_bitmap = None;
            piece.ich_corrupted = false;
            reset_pieces = reset_pieces.saturating_add(1);
        }
    }

    let previous_ranges = manifest.verified_ranges.clone();
    rebuild_verified_ranges(manifest);
    if manifest.final_rehash_pending && !manifest.is_fully_verified() {
        manifest.final_rehash_pending = false;
    }
    if reset_pieces == 0 && manifest.verified_ranges == previous_ranges {
        0
    } else {
        reset_pieces
    }
}

async fn persist_reconciled_manifest(
    runtime: &Ed2kTransferRuntime,
    manifest: &Ed2kResumeManifest,
    reset_pieces: usize,
) -> Result<bool> {
    let persisted = runtime.load_manifest_unlocked(&manifest.file_hash).await?;
    if reset_pieces == 0
        && persisted.verified_ranges == manifest.verified_ranges
        && persisted.final_rehash_pending == manifest.final_rehash_pending
    {
        return Ok(false);
    }
    runtime.store_manifest_unlocked(manifest).await?;
    runtime.upsert_verified_catalog_entry(manifest).await;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use emulebb_kad_proto::Ed2kHash;

    use super::*;
    use crate::ed2k_transfer::{Ed2kPieceState, Ed2kTransferJob};
    use crate::paths::unique_test_dir;

    async fn seed_manifest(
        runtime: &Ed2kTransferRuntime,
        job: &Ed2kTransferJob,
        pieces: Vec<Ed2kPieceState>,
    ) {
        runtime.ensure_job(job).await.unwrap();
        let _guard = runtime.lock_manifest(&job.file_hash).await;
        let mut manifest = runtime
            .load_manifest_unlocked(&job.file_hash)
            .await
            .unwrap();
        manifest.pieces = pieces;
        rebuild_verified_ranges(&mut manifest);
        runtime.store_manifest_unlocked(&manifest).await.unwrap();
    }

    fn piece(piece_index: u32, state: Ed2kTransferState, bytes_written: u64) -> Ed2kPieceState {
        Ed2kPieceState {
            piece_index,
            state,
            bytes_written,
            block_bitmap: None,
            ich_corrupted: false,
        }
    }

    #[tokio::test]
    async fn missing_payload_demotes_all_claimed_progress_before_publication() {
        let root = unique_test_dir("ed2k-missing-incomplete-payload");
        let job = Ed2kTransferJob {
            file_hash: Ed2kHash::from_bytes([0x71; 16]).to_string(),
            display_name: "missing.bin".to_string(),
            file_size: 24,
            piece_size: 8,
        };
        {
            let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
            seed_manifest(
                &runtime,
                &job,
                vec![
                    piece(0, Ed2kTransferState::Verified, 8),
                    piece(1, Ed2kTransferState::Missing, 4),
                    piece(2, Ed2kTransferState::Missing, 0),
                ],
            )
            .await;
            fs::write(runtime.payload_path(&job.file_hash), vec![0xA5; 12]).unwrap();
        }
        fs::remove_file(root.join(&job.file_hash).join(PAYLOAD_FILE_NAME)).unwrap();

        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let report = runtime
            .reconcile_incomplete_download_payloads()
            .await
            .unwrap();

        assert_eq!(report.inspected_downloads, 1);
        assert_eq!(report.repaired_downloads, 1);
        assert_eq!(report.reset_pieces, 2);
        let manifest = runtime.manifest(&job.file_hash).await.unwrap();
        assert!(manifest.verified_ranges.is_empty());
        assert!(manifest.pieces.iter().all(|piece| {
            piece.state == Ed2kTransferState::Missing && piece.bytes_written == 0
        }));
        runtime.incomplete_manifests().await.unwrap();
        assert!(runtime.shared_catalog().read().await.is_empty());
        assert_eq!(
            runtime
                .reconcile_incomplete_download_payloads()
                .await
                .unwrap()
                .repaired_downloads,
            0
        );
    }

    #[tokio::test]
    async fn truncated_payload_demotes_all_claimed_progress() {
        let root = unique_test_dir("ed2k-truncated-incomplete-payload");
        let job = Ed2kTransferJob {
            file_hash: Ed2kHash::from_bytes([0x72; 16]).to_string(),
            display_name: "truncated.bin".to_string(),
            file_size: 24,
            piece_size: 8,
        };
        {
            let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
            seed_manifest(
                &runtime,
                &job,
                vec![
                    piece(0, Ed2kTransferState::Verified, 8),
                    piece(1, Ed2kTransferState::Verified, 8),
                    piece(2, Ed2kTransferState::Missing, 4),
                ],
            )
            .await;
            fs::write(runtime.payload_path(&job.file_hash), vec![0x5A; 20]).unwrap();
        }
        fs::OpenOptions::new()
            .write(true)
            .open(root.join(&job.file_hash).join(PAYLOAD_FILE_NAME))
            .unwrap()
            .set_len(9)
            .unwrap();

        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let report = runtime
            .reconcile_incomplete_download_payloads()
            .await
            .unwrap();

        assert_eq!(report.repaired_downloads, 1);
        assert_eq!(report.reset_pieces, 3);
        let manifest = runtime.manifest(&job.file_hash).await.unwrap();
        assert!(manifest.verified_ranges.is_empty());
        assert!(manifest.pieces.iter().all(|piece| {
            piece.state == Ed2kTransferState::Missing && piece.bytes_written == 0
        }));
    }

    #[tokio::test]
    async fn intact_partial_payload_preserves_verified_progress() {
        let root = unique_test_dir("ed2k-intact-incomplete-payload");
        let job = Ed2kTransferJob {
            file_hash: Ed2kHash::from_bytes([0x76; 16]).to_string(),
            display_name: "intact.bin".to_string(),
            file_size: 24,
            piece_size: 8,
        };
        {
            let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
            seed_manifest(
                &runtime,
                &job,
                vec![
                    piece(0, Ed2kTransferState::Verified, 8),
                    piece(1, Ed2kTransferState::Missing, 0),
                    piece(2, Ed2kTransferState::Missing, 0),
                ],
            )
            .await;
            fs::write(runtime.payload_path(&job.file_hash), vec![0xA5; 8]).unwrap();
        }

        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let report = runtime
            .reconcile_incomplete_download_payloads()
            .await
            .unwrap();

        assert_eq!(report.repaired_downloads, 0);
        assert_eq!(report.reset_pieces, 0);
        let manifest = runtime.manifest(&job.file_hash).await.unwrap();
        assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Verified);
        assert_eq!(manifest.pieces[0].bytes_written, 8);
        assert_eq!(manifest.verified_ranges.len(), 1);
        assert_eq!(manifest.verified_ranges[0].end, 8);
    }

    #[tokio::test]
    async fn missing_transfer_directory_is_recreated_and_progress_is_demoted() {
        let root = unique_test_dir("ed2k-missing-incomplete-directory");
        let job = Ed2kTransferJob {
            file_hash: Ed2kHash::from_bytes([0x73; 16]).to_string(),
            display_name: "missing-directory.bin".to_string(),
            file_size: 8,
            piece_size: 8,
        };
        {
            let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
            seed_manifest(
                &runtime,
                &job,
                vec![piece(0, Ed2kTransferState::Verified, 8)],
            )
            .await;
        }
        fs::remove_dir_all(root.join(&job.file_hash)).unwrap();

        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let report = runtime
            .reconcile_incomplete_download_payloads()
            .await
            .unwrap();

        assert_eq!(report.recreated_directories, 1);
        assert_eq!(report.repaired_downloads, 1);
        assert!(root.join(&job.file_hash).is_dir());
        assert_eq!(
            runtime.manifest(&job.file_hash).await.unwrap().pieces[0].state,
            Ed2kTransferState::Missing
        );
    }

    #[tokio::test]
    async fn wrong_payload_type_fails_closed_without_removing_the_occupant() {
        let root = unique_test_dir("ed2k-wrong-incomplete-payload-type");
        let job = Ed2kTransferJob {
            file_hash: Ed2kHash::from_bytes([0x74; 16]).to_string(),
            display_name: "wrong-type.bin".to_string(),
            file_size: 8,
            piece_size: 8,
        };
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        runtime.ensure_job(&job).await.unwrap();
        let payload_path = runtime.payload_path(&job.file_hash);
        fs::create_dir(&payload_path).unwrap();

        let error = runtime
            .reconcile_incomplete_download_payloads()
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("payload is not a regular file"));
        assert!(payload_path.is_dir());
        assert!(runtime.manifest(&job.file_hash).await.is_ok());
    }

    #[tokio::test]
    async fn wrong_transfer_directory_type_fails_closed_without_removing_the_occupant() {
        let root = unique_test_dir("ed2k-wrong-incomplete-directory-type");
        let job = Ed2kTransferJob {
            file_hash: Ed2kHash::from_bytes([0x75; 16]).to_string(),
            display_name: "wrong-directory-type.bin".to_string(),
            file_size: 8,
            piece_size: 8,
        };
        {
            let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
            runtime.ensure_job(&job).await.unwrap();
        }
        let transfer_path = root.join(&job.file_hash);
        fs::remove_dir(&transfer_path).unwrap();
        fs::write(&transfer_path, b"foreign occupant").unwrap();

        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let error = runtime
            .reconcile_incomplete_download_payloads()
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("path is not a directory"));
        assert_eq!(fs::read(&transfer_path).unwrap(), b"foreign occupant");
        assert!(runtime.manifest(&job.file_hash).await.is_ok());
    }
}
