use std::{
    collections::HashSet,
    fs,
    path::Path,
    str::FromStr,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use md4::{Digest as Md4Digest, Md4};

use super::{
    ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kSharedEntry, Ed2kSharedRange, Ed2kTransferJob,
    Ed2kTransferState, MANIFEST_FILE_NAME,
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

pub(super) fn load_catalog_from_manifests(root_dir: &Path) -> Result<Vec<Ed2kSharedEntry>> {
    if !root_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for child in fs::read_dir(root_dir)
        .with_context(|| format!("failed to enumerate {}", root_dir.display()))?
    {
        let child = child?;
        let manifest_path = child.path().join(MANIFEST_FILE_NAME);
        if !manifest_path.exists() {
            continue;
        }
        let bytes = fs::read(&manifest_path)
            .with_context(|| format!("failed to read {}", manifest_path.display()))?;
        let manifest: Ed2kResumeManifest = match serde_json::from_slice(&bytes) {
            Ok(manifest) => manifest,
            Err(error) => {
                tracing::warn!(
                    "skipping malformed ED2K manifest {} during catalog load: {error}",
                    manifest_path.display()
                );
                continue;
            }
        };
        if manifest.completed {
            entries.push(Ed2kSharedEntry::from_manifest(&manifest));
        }
    }
    Ok(dedupe_entries(entries))
}

pub(super) fn dedupe_entries(entries: Vec<Ed2kSharedEntry>) -> Vec<Ed2kSharedEntry> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::with_capacity(entries.len());
    for entry in entries.into_iter().rev() {
        if seen.insert((entry.file_hash.clone(), entry.compatibility_hint)) {
            deduped.push(entry);
        }
    }
    deduped.reverse();
    deduped
}

pub(super) async fn quarantine_corrupt_manifest(path: &Path) -> Result<()> {
    if !tokio::fs::try_exists(path).await? {
        return Ok(());
    }
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let quarantine_path = path.with_extension(format!("json.corrupt-{suffix}"));
    tokio::fs::rename(path, &quarantine_path)
        .await
        .with_context(|| {
            format!(
                "failed to quarantine corrupt ED2K manifest {} -> {}",
                path.display(),
                quarantine_path.display()
            )
        })
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
