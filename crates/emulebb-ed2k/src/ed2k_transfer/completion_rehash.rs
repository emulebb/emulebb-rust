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

    /// Operator-triggered full recheck. This uses the same authority path as
    /// automatic completion and deliberately persists the pending barrier
    /// before reading the payload.
    pub(super) async fn final_recheck_transfer(&self, file_hash: &str) -> Result<bool> {
        self.final_rehash(file_hash, true).await
    }

    async fn final_rehash(&self, file_hash: &str, force: bool) -> Result<bool> {
        let (payload_path, expected_size) = {
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
            self.invalidate_payload_handle(file_hash);
            self.store_manifest_unlocked(&manifest).await?;
            (self.payload_path(file_hash), manifest.file_size)
        };

        tracing::info!(
            event = "final_completion_rehash_started",
            file_hash,
            expected_size,
            "ED2K final completion rehash started"
        );

        let computation =
            tokio::task::spawn_blocking(move || compute_final_rehash(&payload_path, expected_size))
                .await
                .context("ED2K final completion rehash task failed")?;

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
                piece.ich_corrupted = true;
            }
        }
        manifest.completed = false;
        manifest.final_rehash_pending = false;
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
    let expected_file_hash = Ed2kHash::from_str(&manifest.file_hash)
        .with_context(|| format!("invalid ED2K file hash {}", manifest.file_hash))?
        .0;
    let canonical = manifest
        .md4_hashset
        .iter()
        .map(|hash| decode_md4(hash))
        .collect::<Result<Vec<_>>>()?;
    let mut damaged = Vec::new();
    for piece in &manifest.pieces {
        let index = usize::try_from(piece.piece_index).unwrap_or(usize::MAX);
        let expected = if manifest.md4_hashset.is_empty() {
            Some(expected_file_hash)
        } else {
            canonical.get(index).copied()
        };
        if computation.part_hashes.get(index).copied().flatten() != expected {
            damaged.push(piece.piece_index);
        }
    }
    Ok(damaged)
}

fn decode_md4(hash: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(hash).with_context(|| format!("invalid MD4 hash {hash}"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid MD4 hash length {len}"))
}

fn compute_final_rehash(path: &Path, expected_size: u64) -> FinalRehashComputation {
    let actual_len = path.metadata().map_or(0, |metadata| metadata.len());
    let part_count = expected_size.div_ceil(ED2K_PART_SIZE);
    let mut part_hashes = Vec::with_capacity(usize::try_from(part_count).unwrap_or(0));
    let Ok(mut file) = File::open(path) else {
        part_hashes.resize(usize::try_from(part_count).unwrap_or(0), None);
        return FinalRehashComputation {
            actual_len,
            file_hash: None,
            part_hashes,
        };
    };
    let _ = file.seek(SeekFrom::Start(0));
    let mut remaining = expected_size;
    for _ in 0..part_count {
        let part_len = remaining.min(ED2K_PART_SIZE);
        let mut hasher = Md4::new();
        let mut part_remaining = part_len;
        let mut buffer = [0u8; 65_536];
        let mut readable = true;
        while part_remaining > 0 {
            let chunk_len = usize::try_from(part_remaining.min(buffer.len() as u64)).unwrap_or(0);
            if file.read_exact(&mut buffer[..chunk_len]).is_err() {
                readable = false;
                break;
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

    let file_hash = if part_hashes.iter().any(Option::is_none) {
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
    FinalRehashComputation {
        actual_len,
        file_hash,
        part_hashes,
    }
}
