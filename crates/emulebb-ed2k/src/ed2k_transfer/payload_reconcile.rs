//! Startup reconciliation between persisted download authority and `pieces.bin`.

use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::NativeFileFingerprint;

use crate::long_path::long_path;

use super::deliver::{DeliveredOutputIdentity, classify_delivered_output};
use super::fs_durability::sync_parent_directory;
use super::manifest::{expected_piece_length, rebuild_verified_ranges};
use super::{
    Ed2kDeliveryState, Ed2kDownloadStorageReconciliation, Ed2kResumeManifest, Ed2kTransferRuntime,
    Ed2kTransferState, PAYLOAD_FILE_NAME,
};

#[derive(Debug)]
struct VerifiedRecoveryPayload {
    path: PathBuf,
    fingerprint: Option<NativeFileFingerprint>,
}

#[derive(Debug)]
struct VerifiedStagedPayload {
    path: PathBuf,
    fingerprint: Option<NativeFileFingerprint>,
}

static PAYLOAD_QUARANTINE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

impl Ed2kTransferRuntime {
    /// Reconcile every internally managed download before transfer hydration or
    /// network publication can expose it.
    ///
    /// Incomplete progress unsupported by durable bytes is demoted. Completed
    /// payloads that fail whole-file identity verification are restored from a
    /// verified delivered output when one exists; otherwise completion and every
    /// piece claim are demoted so the transfer can resume. Invalid regular files
    /// are quarantined, while wrong filesystem types fail startup untouched.
    pub async fn reconcile_managed_download_storage(
        &self,
    ) -> Result<Ed2kDownloadStorageReconciliation> {
        let candidates = self.managed_download_manifests_snapshot().await?;
        let mut reconciliation = Ed2kDownloadStorageReconciliation::default();

        for candidate in candidates {
            let file_hash = candidate.file_hash;
            let _lifecycle_guard = self.lock_lifecycle(&file_hash).await;
            self.recover_delivery_attempt_unlocked(&file_hash).await?;
            let snapshot = {
                let _manifest_guard = self.lock_manifest(&file_hash).await;
                let Some(manifest) = self.load_manifest_optional_unlocked(&file_hash).await? else {
                    continue;
                };
                if manifest.source_path.is_some() {
                    continue;
                }
                manifest
            };

            reconciliation.inspected_downloads =
                reconciliation.inspected_downloads.saturating_add(1);
            let transfer_dir = self.transfer_dir(&file_hash);
            let transfer_dir_id = match tokio::fs::symlink_metadata(&transfer_dir).await {
                Ok(metadata) => {
                    anyhow::ensure!(
                        metadata.file_type().is_dir(),
                        "persisted ED2K download {file_hash} owns {}, but the path is not a directory",
                        transfer_dir.display()
                    );
                    file_id::get_file_id(long_path(&transfer_dir)).with_context(|| {
                        format!(
                            "failed to identify ED2K transfer directory {}",
                            transfer_dir.display()
                        )
                    })?
                }
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
                    file_id::get_file_id(long_path(&transfer_dir)).with_context(|| {
                        format!(
                            "failed to identify recreated ED2K transfer directory {}",
                            transfer_dir.display()
                        )
                    })?
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

            let payload_path = transfer_dir.join(PAYLOAD_FILE_NAME);
            let payload_len = match tokio::fs::symlink_metadata(&payload_path).await {
                Ok(metadata) => {
                    anyhow::ensure!(
                        metadata.file_type().is_file(),
                        "persisted ED2K download {file_hash} owns {}, but the payload is not a regular file",
                        payload_path.display()
                    );
                    Some(metadata.len())
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to inspect ED2K payload {}", payload_path.display())
                    });
                }
            };

            if !snapshot.completed {
                let _manifest_guard = self.lock_manifest(&file_hash).await;
                let mut manifest = self.load_manifest_unlocked(&file_hash).await?;
                anyhow::ensure!(
                    manifest == snapshot,
                    "persisted ED2K download {file_hash} changed during storage reconciliation"
                );
                let reset_pieces =
                    reconcile_manifest_payload_len(&mut manifest, payload_len.unwrap_or(0));
                if persist_reconciled_manifest(self, &manifest, reset_pieces).await? {
                    reconciliation.demoted_downloads =
                        reconciliation.demoted_downloads.saturating_add(1);
                    reconciliation.reset_pieces =
                        reconciliation.reset_pieces.saturating_add(reset_pieces);
                }
                continue;
            }

            let expected_hash = Ed2kHash::from_str(&snapshot.file_hash)
                .with_context(|| format!("invalid ED2K file hash {}", snapshot.file_hash))?
                .0;
            if payload_len == Some(snapshot.file_size) {
                let identity = classify_delivered_output(
                    &payload_path,
                    snapshot.payload_fingerprint.as_ref(),
                    snapshot.file_size,
                    expected_hash,
                )
                .await?;
                if let DeliveredOutputIdentity::Matching(payload_fingerprint) = identity {
                    persist_verified_canonical_state(self, &snapshot, payload_fingerprint).await?;
                    continue;
                }
            }

            if let Some(recovery) = verified_recovery_payload(&snapshot).await? {
                let staged = stage_verified_payload(
                    &recovery.path,
                    &transfer_dir,
                    snapshot.file_size,
                    expected_hash,
                )
                .await?;
                let restore_result = async {
                    let _manifest_guard = self.lock_manifest(&file_hash).await;
                    let mut manifest = self.load_manifest_unlocked(&file_hash).await?;
                    anyhow::ensure!(
                        manifest == snapshot,
                        "persisted ED2K download {file_hash} changed during payload restoration"
                    );
                    self.invalidate_payload_handle(&file_hash);
                    ensure_transfer_directory_identity(&transfer_dir, &transfer_dir_id).await?;
                    if quarantine_payload_if_present(&payload_path)
                        .await?
                        .is_some()
                    {
                        reconciliation.quarantined_payloads =
                            reconciliation.quarantined_payloads.saturating_add(1);
                    }
                    replace_file_atomically_async(&staged.path, &payload_path).await?;
                    manifest.payload_fingerprint = verified_replaced_payload_fingerprint(
                        &payload_path,
                        staged.fingerprint.as_ref(),
                    );
                    if manifest.source_fingerprint != recovery.fingerprint {
                        manifest.source_fingerprint = recovery.fingerprint.clone();
                    }
                    if manifest != snapshot {
                        self.store_manifest_unlocked(&manifest).await?;
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if restore_result.is_err()
                    && let Err(error) = remove_file_if_exists(&staged.path).await
                {
                    tracing::warn!(
                        %error,
                        path = %staged.path.display(),
                        "failed to remove payload recovery temporary"
                    );
                }
                restore_result?;
                reconciliation.restored_payloads =
                    reconciliation.restored_payloads.saturating_add(1);
                continue;
            }

            let _manifest_guard = self.lock_manifest(&file_hash).await;
            let mut manifest = self.load_manifest_unlocked(&file_hash).await?;
            anyhow::ensure!(
                manifest == snapshot,
                "persisted ED2K download {file_hash} changed during completion demotion"
            );
            self.invalidate_payload_handle(&file_hash);
            ensure_transfer_directory_identity(&transfer_dir, &transfer_dir_id).await?;
            if quarantine_payload_if_present(&payload_path)
                .await?
                .is_some()
            {
                reconciliation.quarantined_payloads =
                    reconciliation.quarantined_payloads.saturating_add(1);
            }
            create_empty_payload(&payload_path).await?;
            let reset_pieces = demote_completed_manifest(&mut manifest);
            self.store_manifest_unlocked(&manifest).await?;
            self.upsert_verified_catalog_entry(&manifest).await;
            reconciliation.demoted_downloads = reconciliation.demoted_downloads.saturating_add(1);
            reconciliation.reset_pieces = reconciliation.reset_pieces.saturating_add(reset_pieces);
        }

        Ok(reconciliation)
    }
}

async fn verified_recovery_payload(
    manifest: &Ed2kResumeManifest,
) -> Result<Option<VerifiedRecoveryPayload>> {
    let (path, recorded_fingerprint) = match manifest.delivery_state {
        Ed2kDeliveryState::NotApplicable => return Ok(None),
        Ed2kDeliveryState::Delivered => (
            manifest.delivered_path.clone().with_context(|| {
                format!(
                    "delivered transfer {} has no recorded output path",
                    manifest.file_hash
                )
            })?,
            manifest.source_fingerprint.clone(),
        ),
        Ed2kDeliveryState::Pending => return Ok(None),
    };
    let expected_hash = Ed2kHash::from_str(&manifest.file_hash)
        .with_context(|| format!("invalid ED2K file hash {}", manifest.file_hash))?
        .0;
    match classify_delivered_output(
        &path,
        recorded_fingerprint.as_ref(),
        manifest.file_size,
        expected_hash,
    )
    .await?
    {
        DeliveredOutputIdentity::Matching(fingerprint) => {
            Ok(Some(VerifiedRecoveryPayload { path, fingerprint }))
        }
        DeliveredOutputIdentity::Missing | DeliveredOutputIdentity::Foreign => Ok(None),
    }
}

async fn persist_verified_canonical_state(
    runtime: &Ed2kTransferRuntime,
    snapshot: &Ed2kResumeManifest,
    payload_fingerprint: Option<NativeFileFingerprint>,
) -> Result<()> {
    {
        let _manifest_guard = runtime.lock_manifest(&snapshot.file_hash).await;
        let mut manifest = runtime.load_manifest_unlocked(&snapshot.file_hash).await?;
        anyhow::ensure!(
            manifest == *snapshot,
            "persisted ED2K download {} changed during canonical payload verification",
            snapshot.file_hash
        );
        manifest.payload_fingerprint = payload_fingerprint;
        if manifest != *snapshot {
            runtime.store_manifest_unlocked(&manifest).await?;
        }
    }
    Ok(())
}

async fn stage_verified_payload(
    source: &Path,
    transfer_dir: &Path,
    expected_size: u64,
    expected_hash: [u8; 16],
) -> Result<VerifiedStagedPayload> {
    let named = tempfile::Builder::new()
        .prefix(".pieces-restoring-")
        .tempfile_in(long_path(transfer_dir))
        .with_context(|| {
            format!(
                "failed to create payload recovery temp in {}",
                transfer_dir.display()
            )
        })?;
    let (temp_file, temp_path) = named.into_parts();
    let mut output = tokio::fs::File::from_std(temp_file);
    let mut input = tokio::fs::File::open(long_path(source))
        .await
        .with_context(|| format!("failed to open recovery payload {}", source.display()))?;
    let copied = tokio::io::copy(&mut input, &mut output)
        .await
        .with_context(|| format!("failed to copy recovery payload {}", source.display()))?;
    anyhow::ensure!(
        copied == expected_size,
        "recovery payload {} changed length during copy",
        source.display()
    );
    output.sync_all().await?;
    drop(output);
    let DeliveredOutputIdentity::Matching(fingerprint) =
        classify_delivered_output(&temp_path, None, expected_size, expected_hash).await?
    else {
        anyhow::bail!(
            "copied recovery payload {} failed ED2K identity verification",
            source.display()
        );
    };
    let path = temp_path
        .keep()
        .map_err(|error| error.error)
        .context("failed to preserve verified payload recovery temp")?;
    Ok(VerifiedStagedPayload { path, fingerprint })
}

fn verified_replaced_payload_fingerprint(
    payload_path: &Path,
    staged_fingerprint: Option<&NativeFileFingerprint>,
) -> Option<NativeFileFingerprint> {
    let metadata = payload_path.symlink_metadata().ok()?;
    if !metadata.file_type().is_file() {
        return None;
    }
    let current = super::ingest::native_file_fingerprint(payload_path)?;
    staged_fingerprint
        .filter(|staged| {
            staged.identity == current.identity
                && staged.size_bytes == current.size_bytes
                && staged.modified == current.modified
                && staged.modified.nanoseconds != 0
        })
        .map(|_| current)
}

fn demote_completed_manifest(manifest: &mut Ed2kResumeManifest) -> usize {
    let mut reset_pieces = 0usize;
    for piece in &mut manifest.pieces {
        if piece.state != Ed2kTransferState::Missing
            || piece.bytes_written != 0
            || piece.block_bitmap.is_some()
            || piece.ich_corrupted
        {
            reset_pieces = reset_pieces.saturating_add(1);
        }
        piece.state = Ed2kTransferState::Missing;
        piece.bytes_written = 0;
        piece.block_bitmap = None;
        piece.ich_corrupted = false;
    }
    manifest.completed = false;
    manifest.final_rehash_pending = false;
    manifest.transfer_row_removed = false;
    manifest.delivery_state = Ed2kDeliveryState::Pending;
    manifest.delivered_path = None;
    manifest.source_fingerprint = None;
    manifest.payload_fingerprint = None;
    rebuild_verified_ranges(manifest);
    reset_pieces
}

async fn replace_file_atomically_async(source: &Path, destination: &Path) -> Result<()> {
    let source = source.to_path_buf();
    let destination = destination.to_path_buf();
    let replace_destination = destination.clone();
    tokio::task::spawn_blocking(move || replace_file_atomically(&source, &replace_destination))
        .await
        .context("payload recovery replace task failed")?
        .with_context(|| format!("failed to replace payload {}", destination.display()))
}

pub(super) async fn existing_transfer_directory_identity(
    transfer_dir: &Path,
) -> Result<file_id::FileId> {
    let metadata = tokio::fs::symlink_metadata(transfer_dir)
        .await
        .with_context(|| {
            format!(
                "failed to inspect ED2K transfer directory {}",
                transfer_dir.display()
            )
        })?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "ED2K transfer path {} is not a directory",
        transfer_dir.display()
    );
    file_id::get_file_id(long_path(transfer_dir)).with_context(|| {
        format!(
            "failed to identify ED2K transfer directory {}",
            transfer_dir.display()
        )
    })
}

pub(super) async fn ensure_transfer_directory_identity(
    transfer_dir: &Path,
    expected_id: &file_id::FileId,
) -> Result<()> {
    let metadata = tokio::fs::symlink_metadata(transfer_dir)
        .await
        .with_context(|| {
            format!(
                "failed to revalidate ED2K transfer directory {}",
                transfer_dir.display()
            )
        })?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "ED2K transfer directory {} changed filesystem type during storage reconciliation",
        transfer_dir.display()
    );
    let current_id = file_id::get_file_id(long_path(transfer_dir)).with_context(|| {
        format!(
            "failed to re-identify ED2K transfer directory {}",
            transfer_dir.display()
        )
    })?;
    anyhow::ensure!(
        &current_id == expected_id,
        "ED2K transfer directory {} changed identity during storage reconciliation",
        transfer_dir.display()
    );
    Ok(())
}

pub(super) async fn quarantine_payload_if_present(payload_path: &Path) -> Result<Option<PathBuf>> {
    match tokio::fs::symlink_metadata(payload_path).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect invalid payload {}",
                    payload_path.display()
                )
            });
        }
    }
    loop {
        let sequence = PAYLOAD_QUARANTINE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let quarantine_path = payload_path.with_file_name(format!(
            ".{PAYLOAD_FILE_NAME}.invalid-{sequence}.quarantine"
        ));
        match tokio::fs::rename(payload_path, &quarantine_path).await {
            Ok(()) => {
                sync_parent_directory(&quarantine_path).await?;
                tracing::warn!(
                    source = %payload_path.display(),
                    quarantine = %quarantine_path.display(),
                    "preserved invalid canonical ED2K payload under a quarantine name"
                );
                return Ok(Some(quarantine_path));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to quarantine invalid payload {}",
                        payload_path.display()
                    )
                });
            }
        }
    }
}

pub(super) async fn create_empty_payload(payload_path: &Path) -> Result<()> {
    let payload = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(payload_path)
        .await
        .with_context(|| format!("failed to create reset payload {}", payload_path.display()))?;
    payload
        .sync_all()
        .await
        .with_context(|| format!("failed to sync reset payload {}", payload_path.display()))?;
    drop(payload);
    sync_parent_directory(payload_path).await
}

#[cfg(not(windows))]
fn replace_file_atomically(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)?;
    if let Some(parent) = destination.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(windows)]
fn replace_file_atomically(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = long_path(source)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = long_path(destination)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both buffers are NUL-terminated UTF-16 paths and remain alive
    // for the call. The temporary is created beside the canonical payload, so
    // MoveFileExW performs one same-volume atomic replacement.
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

async fn remove_file_if_exists(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn reconcile_manifest_payload_len(manifest: &mut Ed2kResumeManifest, payload_len: u64) -> usize {
    manifest.payload_fingerprint = None;
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
        && persisted.payload_fingerprint == manifest.payload_fingerprint
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
    use md4::{Digest, Md4};
    use uuid::Uuid;

    use super::*;
    use crate::ed2k_transfer::{
        Ed2kDeliveryOutcome, Ed2kPieceState, Ed2kTransferJob,
        deliver::{DELIVERY_PENDING_FILE_NAME, persist_pending_delivery_path},
    };
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

    async fn complete_download(
        runtime: &Ed2kTransferRuntime,
        display_name: &str,
        payload: &[u8],
    ) -> Ed2kTransferJob {
        let job = Ed2kTransferJob {
            file_hash: Ed2kHash::from_bytes(Md4::digest(payload).into()).to_string(),
            display_name: display_name.to_string(),
            file_size: payload.len() as u64,
            piece_size: payload.len() as u64,
        };
        runtime.ensure_job(&job).await.unwrap();
        runtime
            .store_md4_hashset(&job.file_hash, Vec::new())
            .await
            .unwrap();
        runtime
            .store_piece_data(&job.file_hash, 0, payload)
            .await
            .unwrap();
        let completed = runtime.manifest(&job.file_hash).await.unwrap();
        assert!(completed.completed);
        assert!(completed.payload_fingerprint.is_some());
        job
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
        let report = runtime.reconcile_managed_download_storage().await.unwrap();

        assert_eq!(report.inspected_downloads, 1);
        assert_eq!(report.demoted_downloads, 1);
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
                .reconcile_managed_download_storage()
                .await
                .unwrap()
                .demoted_downloads,
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
        let report = runtime.reconcile_managed_download_storage().await.unwrap();

        assert_eq!(report.demoted_downloads, 1);
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
        let report = runtime.reconcile_managed_download_storage().await.unwrap();

        assert_eq!(report.demoted_downloads, 0);
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
        let report = runtime.reconcile_managed_download_storage().await.unwrap();

        assert_eq!(report.recreated_directories, 1);
        assert_eq!(report.demoted_downloads, 1);
        assert!(root.join(&job.file_hash).is_dir());
        assert_eq!(
            runtime.manifest(&job.file_hash).await.unwrap().pieces[0].state,
            Ed2kTransferState::Missing
        );
    }

    #[tokio::test]
    async fn completed_payload_is_restored_from_verified_delivery() {
        let root = unique_test_dir("ed2k-restore-completed-payload");
        let incoming = root.join("incoming");
        let payload = b"completed payload recovery authority";
        let delivered_path;
        let job;
        {
            let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
            job = complete_download(&runtime, "recovered.bin", payload).await;
            delivered_path = match runtime
                .materialize_completed_payload(&job.file_hash, &incoming)
                .await
                .unwrap()
            {
                Ed2kDeliveryOutcome::Delivered(path) => path,
                outcome => panic!("unexpected delivery outcome: {outcome:?}"),
            };
            fs::remove_dir_all(runtime.transfer_dir(&job.file_hash)).unwrap();
        }

        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let report = runtime.reconcile_managed_download_storage().await.unwrap();

        assert_eq!(report.restored_payloads, 1);
        assert_eq!(report.demoted_downloads, 0);
        assert_eq!(report.recreated_directories, 1);
        assert_eq!(
            fs::read(runtime.payload_path(&job.file_hash)).unwrap(),
            payload
        );
        assert!(runtime.manifest(&job.file_hash).await.unwrap().completed);
        let hash = job.file_hash.parse::<Ed2kHash>().unwrap();
        assert_eq!(
            runtime
                .read_verified_range(&hash, 0, payload.len() as u64)
                .await
                .unwrap()
                .unwrap(),
            payload
        );
        assert_eq!(fs::read(&delivered_path).unwrap(), payload);
        assert!(
            runtime
                .manifest(&job.file_hash)
                .await
                .unwrap()
                .payload_fingerprint
                .is_some()
        );

        fs::OpenOptions::new()
            .write(true)
            .open(runtime.payload_path(&job.file_hash))
            .unwrap()
            .set_len(3)
            .unwrap();
        let report = runtime.reconcile_managed_download_storage().await.unwrap();
        assert_eq!(report.restored_payloads, 1);
        assert_eq!(
            fs::read(runtime.payload_path(&job.file_hash)).unwrap(),
            payload
        );
    }

    #[tokio::test]
    async fn legacy_pending_delivery_intent_is_preserved_without_adoption() {
        let root = unique_test_dir("ed2k-restore-pending-delivery");
        let incoming = root.join("incoming");
        let payload = b"pending delivery recovery authority";
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let job = complete_download(&runtime, "pending.bin", payload).await;
        fs::create_dir_all(&incoming).unwrap();
        let delivered_path = incoming.join("pending.bin");
        fs::write(&delivered_path, payload).unwrap();
        let pending_path = runtime
            .transfer_dir(&job.file_hash)
            .join(DELIVERY_PENDING_FILE_NAME);
        persist_pending_delivery_path(&pending_path, &delivered_path)
            .await
            .unwrap();
        fs::remove_file(runtime.payload_path(&job.file_hash)).unwrap();

        let report = runtime.reconcile_managed_download_storage().await.unwrap();

        assert_eq!(report.restored_payloads, 0);
        assert_eq!(report.demoted_downloads, 1);
        let manifest = runtime.manifest(&job.file_hash).await.unwrap();
        assert!(!manifest.completed);
        assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Pending);
        assert!(manifest.delivered_path.is_none());
        assert!(manifest.source_fingerprint.is_none());
        assert!(manifest.payload_fingerprint.is_none());
        assert!(pending_path.exists());
        assert_eq!(fs::read(&delivered_path).unwrap(), payload);
        assert!(
            fs::read(runtime.payload_path(&job.file_hash))
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn staged_delivery_attempt_restores_payload_and_commits_hidden_row() {
        let root = unique_test_dir("ed2k-adopt-pending-delivery-hidden-row");
        let incoming = root.join("incoming");
        let payload = b"hidden completed delivery recovery";
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let job = complete_download(&runtime, "hidden.bin", payload).await;
        fs::create_dir_all(&incoming).unwrap();
        let delivered_path = incoming.join("hidden.bin");
        fs::write(&delivered_path, payload).unwrap();
        let attempt_id = Uuid::new_v4();
        let staging_path = incoming.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
        runtime
            .metadata
            .begin_transfer_delivery_attempt(
                &job.file_hash,
                attempt_id,
                &delivered_path,
                &staging_path,
            )
            .unwrap();
        assert!(
            runtime
                .metadata
                .mark_transfer_delivery_attempt_staged(&job.file_hash, attempt_id)
                .unwrap()
        );
        {
            let _guard = runtime.lock_manifest(&job.file_hash).await;
            let mut manifest = runtime
                .load_manifest_unlocked(&job.file_hash)
                .await
                .unwrap();
            manifest.transfer_row_removed = true;
            runtime.store_manifest_unlocked(&manifest).await.unwrap();
        }
        fs::remove_file(runtime.payload_path(&job.file_hash)).unwrap();

        let report = runtime.reconcile_managed_download_storage().await.unwrap();

        assert_eq!(report.restored_payloads, 1);
        let manifest = runtime.manifest(&job.file_hash).await.unwrap();
        assert!(manifest.completed);
        assert!(manifest.transfer_row_removed);
        assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Delivered);
        assert_eq!(
            manifest.delivered_path.as_deref(),
            Some(delivered_path.as_path())
        );
        assert!(manifest.source_fingerprint.is_some());
        assert!(manifest.payload_fingerprint.is_some());
        assert!(
            runtime
                .metadata
                .transfer_delivery_attempt_by_hash(&job.file_hash)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fs::read(runtime.payload_path(&job.file_hash)).unwrap(),
            payload
        );
    }

    #[tokio::test]
    async fn same_length_completed_corruption_is_quarantined_and_restored() {
        let root = unique_test_dir("ed2k-restore-same-length-corruption");
        let incoming = root.join("incoming");
        let payload = b"same length completed authority";
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let job = complete_download(&runtime, "same-length.bin", payload).await;
        let delivered_path = match runtime
            .materialize_completed_payload(&job.file_hash, &incoming)
            .await
            .unwrap()
        {
            Ed2kDeliveryOutcome::Delivered(path) => path,
            outcome => panic!("unexpected delivery outcome: {outcome:?}"),
        };
        let payload_path = runtime.payload_path(&job.file_hash);
        let foreign = vec![b'X'; payload.len()];
        fs::write(&payload_path, &foreign).unwrap();

        let report = runtime.reconcile_managed_download_storage().await.unwrap();

        assert_eq!(report.restored_payloads, 1);
        assert_eq!(report.quarantined_payloads, 1);
        assert_eq!(fs::read(&payload_path).unwrap(), payload);
        assert_eq!(fs::read(&delivered_path).unwrap(), payload);
        let quarantined = fs::read_dir(runtime.transfer_dir(&job.file_hash))
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".pieces.bin.invalid-")
            })
            .expect("corrupt canonical payload must be preserved");
        assert_eq!(fs::read(quarantined.path()).unwrap(), foreign);
        assert!(runtime.manifest(&job.file_hash).await.unwrap().completed);
    }

    #[tokio::test]
    async fn missing_completed_payload_fingerprint_is_rehashed_and_persisted() {
        let root = unique_test_dir("ed2k-refresh-missing-payload-fingerprint");
        let payload = b"missing canonical fingerprint baseline";
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let job = complete_download(&runtime, "missing-fingerprint.bin", payload).await;
        {
            let _guard = runtime.lock_manifest(&job.file_hash).await;
            let mut manifest = runtime
                .load_manifest_unlocked(&job.file_hash)
                .await
                .unwrap();
            manifest.payload_fingerprint = None;
            runtime.store_manifest_unlocked(&manifest).await.unwrap();
        }

        let report = runtime.reconcile_managed_download_storage().await.unwrap();

        assert_eq!(report.restored_payloads, 0);
        assert_eq!(report.demoted_downloads, 0);
        let refreshed = runtime.manifest(&job.file_hash).await.unwrap();
        assert!(refreshed.completed);
        assert!(refreshed.payload_fingerprint.is_some());
    }

    #[tokio::test]
    async fn stale_completed_payload_fingerprint_is_rehashed_and_refreshed() {
        let root = unique_test_dir("ed2k-refresh-stale-payload-fingerprint");
        let payload = b"stale canonical fingerprint baseline";
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let job = complete_download(&runtime, "stale-fingerprint.bin", payload).await;
        let before = runtime
            .manifest(&job.file_hash)
            .await
            .unwrap()
            .payload_fingerprint
            .unwrap();
        let payload_path = runtime.payload_path(&job.file_hash);
        let replacement = payload_path.with_extension("replacement");
        fs::write(&replacement, payload).unwrap();
        fs::remove_file(&payload_path).unwrap();
        fs::rename(&replacement, &payload_path).unwrap();

        let report = runtime.reconcile_managed_download_storage().await.unwrap();

        assert_eq!(report.restored_payloads, 0);
        assert_eq!(report.demoted_downloads, 0);
        let refreshed = runtime.manifest(&job.file_hash).await.unwrap();
        assert!(refreshed.completed);
        assert_ne!(refreshed.payload_fingerprint, Some(before));
        assert!(refreshed.payload_fingerprint.is_some());
    }

    #[tokio::test]
    async fn completed_payload_without_valid_recovery_is_demoted() {
        let root = unique_test_dir("ed2k-demote-completed-payload");
        let incoming = root.join("incoming");
        let payload = b"completed payload lost authority";
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let job = complete_download(&runtime, "foreign.bin", payload).await;
        let delivered_path = match runtime
            .materialize_completed_payload(&job.file_hash, &incoming)
            .await
            .unwrap()
        {
            Ed2kDeliveryOutcome::Delivered(path) => path,
            outcome => panic!("unexpected delivery outcome: {outcome:?}"),
        };
        {
            let _guard = runtime.lock_manifest(&job.file_hash).await;
            let mut manifest = runtime
                .load_manifest_unlocked(&job.file_hash)
                .await
                .unwrap();
            manifest.transfer_row_removed = true;
            runtime.store_manifest_unlocked(&manifest).await.unwrap();
        }
        fs::remove_file(runtime.payload_path(&job.file_hash)).unwrap();
        let foreign = vec![b'X'; payload.len()];
        fs::write(&delivered_path, &foreign).unwrap();

        let report = runtime.reconcile_managed_download_storage().await.unwrap();

        assert_eq!(report.restored_payloads, 0);
        assert_eq!(report.demoted_downloads, 1);
        assert_eq!(report.reset_pieces, 1);
        let manifest = runtime.manifest(&job.file_hash).await.unwrap();
        assert!(!manifest.completed);
        assert!(!manifest.transfer_row_removed);
        assert_eq!(manifest.delivery_state, Ed2kDeliveryState::Pending);
        assert!(manifest.delivered_path.is_none());
        assert!(manifest.source_fingerprint.is_none());
        assert!(manifest.payload_fingerprint.is_none());
        assert!(manifest.verified_ranges.is_empty());
        assert!(manifest.pieces.iter().all(|piece| {
            piece.state == Ed2kTransferState::Missing
                && piece.bytes_written == 0
                && piece.block_bitmap.is_none()
                && !piece.ich_corrupted
        }));
        assert_eq!(fs::read(&delivered_path).unwrap(), foreign);
        assert!(
            runtime
                .shared_catalog()
                .read()
                .await
                .iter()
                .all(|entry| entry.file_hash != job.file_hash)
        );
    }

    #[tokio::test]
    async fn completed_wrong_payload_type_fails_closed_without_removal() {
        let root = unique_test_dir("ed2k-wrong-completed-payload-type");
        let payload = b"completed wrong payload type";
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let job = complete_download(&runtime, "wrong-completed.bin", payload).await;
        let payload_path = runtime.payload_path(&job.file_hash);
        fs::remove_file(&payload_path).unwrap();
        fs::create_dir(&payload_path).unwrap();

        let error = runtime
            .reconcile_managed_download_storage()
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("payload is not a regular file"));
        assert!(payload_path.is_dir());
        assert!(runtime.manifest(&job.file_hash).await.unwrap().completed);
    }

    #[tokio::test]
    async fn share_in_place_is_excluded_from_managed_storage_reconciliation() {
        let root = unique_test_dir("ed2k-reconcile-share-in-place");
        let source = root.join("library.bin");
        fs::write(&source, b"share-in-place authority").unwrap();
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let shared = runtime
            .ingest_local_file(&source, "library.bin")
            .await
            .unwrap();

        let report = runtime.reconcile_managed_download_storage().await.unwrap();

        assert_eq!(report.inspected_downloads, 0);
        assert!(
            runtime
                .manifest(&shared.file_hash)
                .await
                .unwrap()
                .payload_fingerprint
                .is_none()
        );
        assert!(!runtime.transfer_dir(&shared.file_hash).exists());
        assert_eq!(
            runtime
                .read_verified_range(
                    &shared.file_hash.parse().unwrap(),
                    0,
                    b"share-in-place authority".len() as u64,
                )
                .await
                .unwrap()
                .unwrap(),
            b"share-in-place authority",
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
            .reconcile_managed_download_storage()
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
            .reconcile_managed_download_storage()
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("path is not a directory"));
        assert_eq!(fs::read(&transfer_path).unwrap(), b"foreign occupant");
        assert!(runtime.manifest(&job.file_hash).await.is_ok());
    }
}
