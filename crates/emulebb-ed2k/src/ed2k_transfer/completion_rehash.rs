//! Authoritative whole-file ED2K completion rehash.
//!
//! Individual part verification is necessary for normal download scheduling,
//! but it is not the final completion authority: bytes in an earlier verified
//! part may change before the last part arrives. The durable pending bit is
//! written before this module rereads the complete payload so neither delivery
//! nor a restart can skip the final MD4 pass.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    str::FromStr,
};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::NativeFileFingerprint;
use md4::{Digest, Md4};

use super::{
    ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kTransferRuntime, Ed2kTransferState,
    hashset::refresh_completed_manifest_aich_hashset, manifest::rebuild_verified_ranges,
};

#[derive(Debug)]
struct FinalRehashComputation {
    actual_len: u64,
    file_hash: Option<[u8; 16]>,
    part_hashes: Vec<Option<[u8; 16]>>,
    payload_fingerprint: Option<NativeFileFingerprint>,
}

/// Refresh the durable completion barrier after a piece-state transition.
///
/// Returns true when all data parts are individually verified and the caller
/// must hand the transfer to the whole-file finalizer. A previously completed
/// manifest is never downgraded by this helper (share-in-place ingest already
/// performed its whole-file hash while importing).
pub(crate) fn mark_final_rehash_pending(manifest: &mut Ed2kResumeManifest) -> bool {
    if manifest.completed {
        manifest.final_rehash_pending = false;
        return false;
    }
    let pending = manifest.is_fully_verified();
    manifest.final_rehash_pending = pending;
    pending
}

impl Ed2kTransferRuntime {
    /// Run a persisted final rehash when the transfer is waiting at the
    /// completion barrier. Returns true only after the whole-file hash matches.
    pub async fn finalize_pending_transfer(&self, file_hash: &str) -> Result<bool> {
        self.final_rehash(file_hash, false).await
    }

    /// Operator-triggered recheck. Complete or fully present payloads use the
    /// final completion authority path; incomplete downloads revalidate every
    /// persisted verified piece without promoting unverified data.
    pub(super) async fn final_recheck_transfer(&self, file_hash: &str) -> Result<bool> {
        let manifest = self.manifest(file_hash).await?;
        if manifest.completed || manifest.is_fully_verified() {
            self.final_rehash(file_hash, true).await
        } else {
            self.recheck_verified_partial_pieces(manifest).await
        }
    }

    async fn recheck_verified_partial_pieces(&self, snapshot: Ed2kResumeManifest) -> Result<bool> {
        if snapshot.source_path.is_some() {
            return Ok(snapshot.completed);
        }
        if !snapshot
            .pieces
            .iter()
            .any(|piece| piece.state == Ed2kTransferState::Verified)
        {
            return Ok(false);
        }
        let file_hash = snapshot.file_hash.clone();
        let payload_path = self.payload_path(&file_hash);
        let expected_size = snapshot.file_size;
        self.invalidate_payload_handle(&file_hash);
        let payload_missing = match tokio::fs::symlink_metadata(&payload_path).await {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect ED2K payload {}", payload_path.display())
                });
            }
        };
        let computation = if payload_missing {
            failed_content_computation(expected_size, 0)
        } else {
            let rehash_path = payload_path.clone();
            tokio::task::spawn_blocking(move || compute_final_rehash(&rehash_path, expected_size))
                .await
                .context("ED2K partial recheck task failed")??
        };
        let damaged_parts = damaged_verified_part_indexes(&snapshot, &computation)?;

        let _guard = self.lock_manifest(&file_hash).await;
        let mut manifest = self.load_manifest_unlocked(&file_hash).await?;
        anyhow::ensure!(
            manifest.file_size == snapshot.file_size
                && manifest.piece_size == snapshot.piece_size
                && manifest.md4_hashset_acquired == snapshot.md4_hashset_acquired
                && manifest.md4_hashset == snapshot.md4_hashset
                && manifest.pieces == snapshot.pieces
                && !manifest.completed
                && !manifest.is_fully_verified(),
            "ED2K transfer {file_hash} changed while its verified pieces were being rechecked"
        );

        let previous_ranges = manifest.verified_ranges.clone();
        for piece in &mut manifest.pieces {
            if damaged_parts.contains(&piece.piece_index) {
                let index = usize::try_from(piece.piece_index).unwrap_or(usize::MAX);
                piece.state = Ed2kTransferState::Missing;
                piece.bytes_written = 0;
                piece.block_bitmap = None;
                piece.ich_corrupted = computation
                    .part_hashes
                    .get(index)
                    .copied()
                    .flatten()
                    .is_some();
            }
        }
        rebuild_verified_ranges(&mut manifest);
        if damaged_parts.is_empty() && manifest.verified_ranges == previous_ranges {
            return Ok(false);
        }
        self.store_manifest_unlocked(&manifest).await?;
        self.upsert_verified_catalog_entry(&manifest).await;
        tracing::warn!(
            event = "partial_recheck_completed",
            file_hash,
            damaged_parts = ?damaged_parts,
            "ED2K partial recheck refreshed verified piece authority"
        );
        Ok(false)
    }

    async fn final_rehash(&self, file_hash: &str, force: bool) -> Result<bool> {
        let _lifecycle_guard = self.lock_lifecycle(file_hash).await;
        let transfer_dir = self.transfer_dir(file_hash);
        let (payload_path, expected_size, transfer_dir_id) = {
            let _guard = self.lock_manifest(file_hash).await;
            let mut manifest = self.load_manifest_unlocked(file_hash).await?;
            if manifest.source_path.is_some() {
                return Ok(manifest.completed);
            }
            if !force && !manifest.final_rehash_pending {
                return Ok(manifest.completed);
            }
            if force && !(manifest.completed || manifest.is_fully_verified()) {
                return Ok(false);
            }

            manifest.completed = false;
            manifest.final_rehash_pending = true;
            manifest.payload_fingerprint = None;
            self.invalidate_payload_handle(file_hash);
            self.store_manifest_unlocked(&manifest).await?;
            self.remove_verified_catalog_entry(file_hash).await;
            let transfer_dir_id =
                super::payload_reconcile::existing_transfer_directory_identity(&transfer_dir)
                    .await?;
            let payload_path = self.payload_path(file_hash);
            match tokio::fs::symlink_metadata(&payload_path).await {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    super::payload_reconcile::ensure_transfer_directory_identity(
                        &transfer_dir,
                        &transfer_dir_id,
                    )
                    .await?;
                    super::payload_reconcile::create_empty_payload(&payload_path).await?;
                    demote_manifest_after_payload_reset(&mut manifest);
                    self.store_manifest_unlocked(&manifest).await?;
                    self.upsert_verified_catalog_entry(&manifest).await;
                    tracing::warn!(
                        event = "missing_payload_reset",
                        file_hash,
                        path = %payload_path.display(),
                        "reset missing ED2K payload before reopening all pieces"
                    );
                    return Ok(false);
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to inspect ED2K payload {}", payload_path.display())
                    });
                }
            }
            (payload_path, manifest.file_size, transfer_dir_id)
        };

        tracing::info!(
            event = "final_completion_rehash_started",
            file_hash,
            expected_size,
            "ED2K final completion rehash started"
        );

        let rehash_path = payload_path.clone();
        let computation =
            tokio::task::spawn_blocking(move || compute_final_rehash(&rehash_path, expected_size))
                .await
                .context("ED2K final completion rehash task failed")??;

        let _guard = self.lock_manifest(file_hash).await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        if !manifest.final_rehash_pending {
            return Ok(manifest.completed);
        }

        let expected_file_hash = Ed2kHash::from_str(&manifest.file_hash)
            .with_context(|| format!("invalid ED2K file hash {}", manifest.file_hash))?
            .0;
        let mut damaged_parts = damaged_part_indexes(&manifest, &computation)?;
        let whole_file_matches = computation.actual_len == manifest.file_size
            && computation.file_hash == Some(expected_file_hash);

        if whole_file_matches {
            manifest.completed = true;
            manifest.final_rehash_pending = false;
            manifest.payload_fingerprint = computation.payload_fingerprint;
            refresh_completed_manifest_aich_hashset(
                &self.transfer_dir(manifest.file_hash.as_str()),
                &mut manifest,
            )?;
            self.store_manifest_unlocked(&manifest).await?;
            self.upsert_verified_catalog_entry(&manifest).await;
            tracing::info!(
                event = "final_completion_rehash_succeeded",
                file_hash,
                bytes = manifest.file_size,
                "ED2K final completion rehash succeeded"
            );
            return Ok(true);
        }

        let mut payload_reset = computation.actual_len == 0 && manifest.file_size > 0;
        if computation.actual_len > manifest.file_size {
            super::payload_reconcile::ensure_transfer_directory_identity(
                &transfer_dir,
                &transfer_dir_id,
            )
            .await?;
            super::payload_reconcile::quarantine_payload_if_present(&payload_path).await?;
            super::payload_reconcile::create_empty_payload(&payload_path).await?;
            damaged_parts.clear();
            payload_reset = true;
        }

        // A validated multi-part hashset reconstructs the expected file hash.
        // If all computed parts match it but the composite does not, the local
        // state is internally inconsistent; fail closed instead of guessing.
        if damaged_parts.is_empty() {
            damaged_parts.extend(manifest.pieces.iter().map(|piece| piece.piece_index));
        }
        for piece in &mut manifest.pieces {
            if damaged_parts.contains(&piece.piece_index) {
                piece.state = Ed2kTransferState::Missing;
                piece.bytes_written = 0;
                piece.block_bitmap = None;
                piece.ich_corrupted = !payload_reset;
            }
        }
        manifest.completed = false;
        manifest.final_rehash_pending = false;
        manifest.payload_fingerprint = None;
        rebuild_verified_ranges(&mut manifest);
        self.store_manifest_unlocked(&manifest).await?;
        self.upsert_verified_catalog_entry(&manifest).await;
        tracing::warn!(
            event = "final_completion_rehash_failed",
            file_hash,
            expected_size = manifest.file_size,
            actual_size = computation.actual_len,
            damaged_parts = ?damaged_parts,
            "ED2K final completion rehash failed; damaged parts were requeued"
        );
        Ok(false)
    }
}

fn damaged_part_indexes(
    manifest: &Ed2kResumeManifest,
    computation: &FinalRehashComputation,
) -> Result<Vec<u32>> {
    let mut damaged = Vec::new();
    for piece in &manifest.pieces {
        let index = usize::try_from(piece.piece_index).unwrap_or(usize::MAX);
        let expected = expected_part_hash(manifest, index)?;
        if expected.is_none() || computation.part_hashes.get(index).copied().flatten() != expected {
            damaged.push(piece.piece_index);
        }
    }
    Ok(damaged)
}

fn damaged_verified_part_indexes(
    manifest: &Ed2kResumeManifest,
    computation: &FinalRehashComputation,
) -> Result<Vec<u32>> {
    let mut damaged = Vec::new();
    for piece in manifest
        .pieces
        .iter()
        .filter(|piece| piece.state == Ed2kTransferState::Verified)
    {
        let index = usize::try_from(piece.piece_index).unwrap_or(usize::MAX);
        let expected = expected_part_hash(manifest, index)?;
        if expected.is_none() || computation.part_hashes.get(index).copied().flatten() != expected {
            damaged.push(piece.piece_index);
        }
    }
    Ok(damaged)
}

fn expected_part_hash(manifest: &Ed2kResumeManifest, index: usize) -> Result<Option<[u8; 16]>> {
    if !manifest.md4_hashset_acquired {
        return Ok(None);
    }
    if manifest.md4_hashset.is_empty() {
        return Ed2kHash::from_str(&manifest.file_hash)
            .with_context(|| format!("invalid ED2K file hash {}", manifest.file_hash))
            .map(|hash| Some(hash.0));
    }
    manifest
        .md4_hashset
        .get(index)
        .map(|hash| decode_md4(hash).map(Some))
        .unwrap_or(Ok(None))
}

fn decode_md4(hash: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(hash).with_context(|| format!("invalid MD4 hash {hash}"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid MD4 hash length {len}"))
}

fn failed_content_computation(expected_size: u64, actual_len: u64) -> FinalRehashComputation {
    let part_count = expected_size.div_ceil(ED2K_PART_SIZE);
    FinalRehashComputation {
        actual_len,
        file_hash: None,
        part_hashes: vec![None; usize::try_from(part_count).unwrap_or(0)],
        payload_fingerprint: None,
    }
}

fn demote_manifest_after_payload_reset(manifest: &mut Ed2kResumeManifest) {
    for piece in &mut manifest.pieces {
        piece.state = Ed2kTransferState::Missing;
        piece.bytes_written = 0;
        piece.block_bitmap = None;
        piece.ich_corrupted = false;
    }
    manifest.completed = false;
    manifest.final_rehash_pending = false;
    manifest.payload_fingerprint = None;
    rebuild_verified_ranges(manifest);
}

fn compute_final_rehash(path: &Path, expected_size: u64) -> Result<FinalRehashComputation> {
    let part_count = expected_size.div_ceil(ED2K_PART_SIZE);
    let path_metadata = path
        .symlink_metadata()
        .with_context(|| format!("failed to inspect ED2K payload {}", path.display()))?;
    anyhow::ensure!(
        path_metadata.file_type().is_file(),
        "ED2K payload {} is not a regular file",
        path.display()
    );
    let mut file = File::open(path)
        .with_context(|| format!("failed to open ED2K payload {}", path.display()))?;
    let pre_hash_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened ED2K payload {}", path.display()))?;
    let pre_hash_fingerprint =
        super::ingest::native_file_fingerprint_from_handle(&file, &pre_hash_metadata)
            .with_context(|| {
                format!("failed to identify opened ED2K payload {}", path.display())
            })?;
    let opened_path_fingerprint = super::ingest::native_file_fingerprint(path)
        .with_context(|| format!("failed to identify ED2K payload path {}", path.display()))?;
    anyhow::ensure!(
        pre_hash_fingerprint == opened_path_fingerprint,
        "ED2K payload {} changed identity while opening for final rehash",
        path.display()
    );

    let mut part_hashes = Vec::with_capacity(usize::try_from(part_count).unwrap_or(0));
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("failed to seek ED2K payload {}", path.display()))?;
    let mut remaining = expected_size;
    for _ in 0..part_count {
        let part_len = remaining.min(ED2K_PART_SIZE);
        let mut hasher = Md4::new();
        let mut part_remaining = part_len;
        let mut buffer = [0u8; 65_536];
        let mut readable = true;
        while part_remaining > 0 {
            let chunk_len = usize::try_from(part_remaining.min(buffer.len() as u64)).unwrap_or(0);
            match file.read_exact(&mut buffer[..chunk_len]) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    readable = false;
                    break;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to read ED2K payload {}", path.display())
                    });
                }
            }
            hasher.update(&buffer[..chunk_len]);
            part_remaining -= chunk_len as u64;
        }
        part_hashes.push(readable.then(|| hasher.finalize().into()));
        remaining = remaining.saturating_sub(part_len);
        if !readable {
            part_hashes.resize(usize::try_from(part_count).unwrap_or(0), None);
            break;
        }
    }

    let computed_file_hash = if part_hashes.iter().any(Option::is_none) {
        None
    } else if expected_size == 0 {
        Some(Md4::new().finalize().into())
    } else if expected_size < ED2K_PART_SIZE {
        part_hashes.first().copied().flatten()
    } else {
        let mut hasher = Md4::new();
        for digest in part_hashes.iter().flatten() {
            hasher.update(digest);
        }
        if expected_size.is_multiple_of(ED2K_PART_SIZE) {
            let empty: [u8; 16] = Md4::new().finalize().into();
            hasher.update(empty);
        }
        Some(hasher.finalize().into())
    };
    let post_hash_metadata = file.metadata().with_context(|| {
        format!(
            "failed to re-inspect opened ED2K payload {}",
            path.display()
        )
    })?;
    let post_hash_fingerprint =
        super::ingest::native_file_fingerprint_from_handle(&file, &post_hash_metadata)
            .with_context(|| {
                format!(
                    "failed to re-identify opened ED2K payload {}",
                    path.display()
                )
            })?;
    let current_path_metadata = path
        .symlink_metadata()
        .with_context(|| format!("failed to re-inspect ED2K payload {}", path.display()))?;
    anyhow::ensure!(
        current_path_metadata.file_type().is_file(),
        "ED2K payload {} changed filesystem type during final rehash",
        path.display()
    );
    let current_path_fingerprint = super::ingest::native_file_fingerprint(path)
        .with_context(|| format!("failed to re-identify ED2K payload path {}", path.display()))?;
    anyhow::ensure!(
        pre_hash_fingerprint == post_hash_fingerprint,
        "ED2K payload {} changed while final rehash was running",
        path.display()
    );
    anyhow::ensure!(
        post_hash_fingerprint == current_path_fingerprint,
        "ED2K payload {} changed path identity during final rehash",
        path.display()
    );
    let payload_fingerprint = pre_hash_fingerprint
        .safely_matches(&post_hash_fingerprint)
        .then_some(post_hash_fingerprint);
    Ok(FinalRehashComputation {
        actual_len: post_hash_metadata.len(),
        file_hash: computed_file_hash,
        part_hashes,
        payload_fingerprint,
    })
}
