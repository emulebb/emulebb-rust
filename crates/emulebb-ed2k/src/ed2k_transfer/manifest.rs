use std::{str::FromStr, time::Instant};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use md4::{Digest as Md4Digest, Md4};

use super::{
    ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kSharedRange, Ed2kTransferJob, Ed2kTransferState,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct Ed2kManifestCheckpointState {
    pub(super) persisted_bytes_written: u64,
    pub(super) last_persisted_at: Instant,
}

pub(super) fn manifest_progress_bytes(manifest: &Ed2kResumeManifest) -> u64 {
    manifest
        .pieces
        .iter()
        .map(|piece| piece.bytes_written)
        .sum::<u64>()
}

pub(super) fn piece_count(file_size: u64, piece_size: u64) -> u32 {
    if file_size == 0 {
        return 0;
    }
    u32::try_from(file_size.div_ceil(piece_size)).unwrap_or(u32::MAX)
}

pub(crate) fn expected_piece_length(file_size: u64, piece_size: u64, piece_index: u64) -> u64 {
    let start = piece_index.saturating_mul(piece_size);
    let end = (start + piece_size).min(file_size);
    end.saturating_sub(start)
}

/// Build a default slice-1 transfer job from a file identity.
#[must_use]
pub fn new_transfer_job(
    file_hash: Ed2kHash,
    canonical_name: String,
    file_size: u64,
) -> Ed2kTransferJob {
    Ed2kTransferJob {
        file_hash: file_hash.to_string(),
        canonical_name,
        file_size,
        piece_size: ED2K_PART_SIZE,
    }
}

pub(super) fn manifest_has_structural_progress(manifest: &Ed2kResumeManifest) -> bool {
    manifest.completed
        || manifest.md4_hashset_acquired
        || manifest.aich_hashset_acquired
        || manifest.aich_root.is_some()
        || !manifest.verified_ranges.is_empty()
        || manifest.pieces.iter().any(|piece| piece.bytes_written != 0)
}

pub(super) fn verify_piece_against_manifest(
    manifest: &Ed2kResumeManifest,
    piece_index: u32,
    data: &[u8],
) -> Result<bool> {
    let digest: [u8; 16] = Md4::digest(data).into();
    if manifest.md4_hashset_acquired {
        if manifest.md4_hashset.is_empty() {
            let expected = Ed2kHash::from_str(&manifest.file_hash)
                .with_context(|| format!("invalid ED2K file hash {}", manifest.file_hash))?;
            return Ok(digest == expected.0);
        }
        let expected = manifest
            .md4_hashset
            .get(piece_index as usize)
            .with_context(|| format!("missing MD4 hashset entry for part {}", piece_index))?;
        let expected = hex::decode(expected)
            .with_context(|| format!("invalid stored MD4 hashset entry {}", expected))?;
        let expected: [u8; 16] = expected
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored MD4 hashset entry has wrong length"))?;
        return Ok(digest == expected);
    }
    Ok(false)
}

pub(super) fn rebuild_verified_ranges(manifest: &mut Ed2kResumeManifest) {
    let mut ranges = Vec::new();
    let mut active_start: Option<u64> = None;
    for piece in &manifest.pieces {
        let piece_start = u64::from(piece.piece_index) * manifest.piece_size;
        let piece_end = (piece_start + manifest.piece_size).min(manifest.file_size);
        if piece.state == Ed2kTransferState::Verified {
            if active_start.is_none() {
                active_start = Some(piece_start);
            }
            if piece_end == manifest.file_size {
                ranges.push(Ed2kSharedRange {
                    start: active_start.expect("active start"),
                    end: piece_end,
                });
                active_start = None;
            }
        } else if let Some(start) = active_start.take() {
            ranges.push(Ed2kSharedRange {
                start,
                end: piece_start,
            });
        }
    }
    manifest.verified_ranges = ranges;
}
