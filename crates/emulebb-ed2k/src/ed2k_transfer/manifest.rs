use std::{str::FromStr, time::Instant};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use crate::normalize_ed2k_file_name;
use md4::{Digest as Md4Digest, Md4};

use super::{
    ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kSharedRange, Ed2kTransferJob, Ed2kTransferState,
};

#[derive(Debug)]
pub(super) struct Ed2kManifestCheckpointState {
    /// Checked cache-publication revision; guards dirty acknowledgments across owned SQL.
    pub(super) revision: u64,
    pub(super) persisted_bytes_written: u64,
    pub(super) last_persisted_at: Instant,
    /// Pieces whose progress advanced since the last durable persist (the
    /// cache-only appends between batched checkpoints). The next progress
    /// checkpoint persists every listed piece row, so a checkpoint triggered
    /// by one session cannot skip pieces dirtied by another session of the
    /// same file; any full manifest store clears the set.
    pub(super) dirty_piece_indexes: super::dirty_pieces::DirtyPieces,
}

/// Allocate a missing checkpoint bitmap before changing progress or committing SQL.
pub(super) fn checkpoint_state<'a>(
    states: &'a mut super::resident_table::ResidentTable<
        emulebb_metadata::JobToken,
        Ed2kManifestCheckpointState,
    >,
    residents: &std::sync::Arc<super::resident::ResidentControl>,
    manifest: &Ed2kResumeManifest,
    persisted_bytes_written: u64,
) -> Result<&'a mut Ed2kManifestCheckpointState> {
    if !states.contains_key(&manifest.token) {
        let claim = states.claim_insert()?;
        let dirty = match super::dirty_pieces::DirtyPieces::new(residents, manifest) {
            Ok(dirty) => dirty,
            Err(error) => {
                drop(claim);
                states.reclaim_empty();
                return Err(error);
            }
        };
        states.insert_claimed(
            manifest.token,
            Ed2kManifestCheckpointState {
                revision: 0,
                persisted_bytes_written,
                last_persisted_at: Instant::now(),
                dirty_piece_indexes: dirty,
            },
            claim,
        );
    }
    Ok(states
        .get_mut(&manifest.token)
        .expect("prepared checkpoint is present"))
}

pub(super) fn manifest_progress_bytes(manifest: &Ed2kResumeManifest) -> u64 {
    manifest
        .pieces
        .iter()
        .map(|piece| {
            // A sparse part stores only its contiguous prefix in bytes_written.
            // Count its authoritative bitmap too; otherwise out-of-order blocks
            // neither advance progress nor trigger the periodic checkpoint.
            if piece.block_bitmap.is_some() {
                piece
                    .resolve_block_bitmap(expected_piece_length(
                        manifest.file_size,
                        manifest.piece_size,
                        u64::from(piece.piece_index),
                    ))
                    .present_bytes()
            } else {
                piece.bytes_written
            }
        })
        .sum::<u64>()
}

pub(super) fn piece_count(file_size: u64, piece_size: u64) -> u32 {
    // Defensive guard: a piece_size of 0 (e.g. from a corrupt persisted row that
    // slipped past load-time validation) would make div_ceil panic with a
    // divide-by-zero. Treat it as "no pieces" instead of aborting.
    if file_size == 0 || piece_size == 0 {
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
    token: emulebb_metadata::JobToken,
    file_hash: Ed2kHash,
    display_name: String,
    file_size: u64,
) -> Ed2kTransferJob {
    Ed2kTransferJob {
        token,
        file_hash: file_hash.to_string(),
        display_name: normalize_ed2k_file_name(&display_name),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn piece_count_with_zero_piece_size_does_not_panic() {
        // A piece_size of 0 with a non-zero file size must return 0 rather than
        // panicking with a divide-by-zero in div_ceil.
        assert_eq!(piece_count(1024, 0), 0);
    }

    #[test]
    fn piece_count_normal_case() {
        // 3 full pieces + a partial -> 4 pieces.
        assert_eq!(piece_count(10, 3), 4);
    }
}
