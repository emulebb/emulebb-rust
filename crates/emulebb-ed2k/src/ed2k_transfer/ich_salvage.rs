//! MD4-only ICH (Intelligent Corruption Handling) salvage of a corrupt part.
//!
//! When a part fails its MD4 flush check the oracle does NOT discard the
//! already-downloaded bytes: it only gaps the part logically (`AddGap`,
//! PartFile.cpp:5186), remembers the part in `corrupted_list`
//! (PartFile.cpp:5188-5190) and keeps the stale bytes on disk. Replacement
//! data then overlays them, and every subsequent flush that touches the
//! still-incomplete corrupted part re-runs `HashSinglePart`; the moment the
//! part MD4-matches again the remaining gaps are filled from the retained
//! bytes (`FillGap`), the requested blocks are dropped and re-downloading
//! stops mid-part (PartFile.cpp:5214-5232). This works with nothing but the
//! MD4 part hash, so it is the salvage fallback when no AICH-capable source
//! exists; block-level AICH salvage (`salvage.rs`) remains the finer-grained
//! path when an OP_AICHANSWER is available.
//!
//! Gating mirrors the oracle: the branch runs only for a part flagged
//! corrupted (`IsCorruptedPart`) while ICH is enabled
//! (`thePrefs.IsICHEnabled()`, ini default true, Preferences.cpp:3187), and
//! only on a flush that changed the part (`m_aChangedPart`) — the rust analog
//! is each block write into the part, never a timer. A part mid AICH salvage
//! keeps its block bitmap untouched when the re-hash misses, so the AICH flow
//! proceeds unchanged (the re-hash can only fail while AICH-identified bad
//! blocks still hold stale bytes).

use std::sync::atomic::Ordering;

use anyhow::{Context, Result};

use super::manifest::{rebuild_verified_ranges, verify_piece_against_manifest};
use super::{
    Ed2kResumeManifest, Ed2kTransferRuntime, Ed2kTransferState, PAYLOAD_FILE_NAME,
    expected_piece_length,
};

/// Outcome of one ICH re-hash pass over a corrupted part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IchRehashResult {
    /// ICH did not apply (disabled, part not flagged corrupted, already
    /// verified, or no MD4 authority yet). Nothing was attempted.
    NotAttempted,
    /// The part was re-hashed but still fails MD4: keep re-downloading
    /// (oracle `HashSinglePart` returning false in the ICH branch).
    Failed,
    /// The part now MD4-matches: the remaining gap was filled from the
    /// retained stale bytes and the part is complete/verified (oracle
    /// PartFile.cpp:5216-5232). `salvaged_bytes` is the gap size recovered
    /// without re-download (`GetTotalGapSizeInPart`, PartFile.cpp:5220).
    Salvaged { salvaged_bytes: u64 },
}

impl Ed2kTransferRuntime {
    /// Whether MD4-only ICH salvage is enabled (oracle
    /// `thePrefs.IsICHEnabled()`; ini default true, Preferences.cpp:3187).
    #[must_use]
    pub fn ich_enabled(&self) -> bool {
        self.ich_enabled.load(Ordering::Acquire)
    }

    /// Enable/disable MD4-only ICH salvage (oracle ICH preference).
    pub fn set_ich_enabled(&self, enabled: bool) {
        self.ich_enabled.store(enabled, Ordering::Release);
    }

    /// Re-run the MD4 part check over the full on-disk bytes of an
    /// ICH-corrupted, still-incomplete part after a flush touched it (oracle
    /// `FlushBuffer` ICH branch, PartFile.cpp:5214-5232). Call under the
    /// `manifest_io` lock with the caller's write handle already flushed so
    /// the just-written bytes are visible to the re-hash read.
    ///
    /// On a match the part is promoted to `Verified` with the remaining gaps
    /// filled from the retained stale bytes (`FillGap` analog), the corrupted
    /// flag is cleared, every recorded sender of the part is credited in the
    /// corruption blackbox (`m_CorruptionBlackBox.VerifiedData`,
    /// PartFile.cpp:5225), and the manifest's verified ranges / completion are
    /// refreshed. The caller persists the manifest.
    pub(super) async fn ich_try_rehash_part_unlocked(
        &self,
        manifest: &mut Ed2kResumeManifest,
        piece_index: u32,
    ) -> Result<IchRehashResult> {
        if !self.ich_enabled() {
            return Ok(IchRehashResult::NotAttempted);
        }
        let piece_size = manifest.piece_size;
        let part_start = u64::from(piece_index) * piece_size;
        let part_len =
            expected_piece_length(manifest.file_size, piece_size, u64::from(piece_index));
        let part_end = part_start + part_len;
        let Some(piece) = manifest
            .pieces
            .iter()
            .find(|piece| piece.piece_index == piece_index)
        else {
            return Ok(IchRehashResult::NotAttempted);
        };
        if !piece.ich_corrupted
            || piece.state == Ed2kTransferState::Verified
            || part_len == 0
            // Without the MD4 authority there is nothing to re-check against.
            || !manifest.md4_hashset_acquired
        {
            return Ok(IchRehashResult::NotAttempted);
        }
        // The salvaged gap size is measured before the promotion below
        // (oracle `GetTotalGapSizeInPart` before `FillGap`). Present bytes are
        // the larger of the contiguous prefix (which may include a partial
        // trailing block) and the bitmap's whole-block presence.
        let present_bytes = piece
            .resolve_block_bitmap(part_len)
            .present_bytes()
            .max(piece.bytes_written);

        // Re-read the full on-disk part: the freshly overlaid prefix plus the
        // retained stale remainder (the rust analog of `HashSinglePart`).
        let payload_path = self
            .transfer_dir(&manifest.file_hash)
            .join(PAYLOAD_FILE_NAME);
        let Some(part_bytes) = read_part_bytes(&payload_path, part_start, part_len).await? else {
            // Payload missing or shorter than the part: the retained bytes are
            // gone, so the re-hash cannot succeed. Count it as a miss.
            return Ok(IchRehashResult::Failed);
        };
        if !verify_piece_against_manifest(manifest, piece_index, &part_bytes)? {
            tracing::debug!(
                file_hash = %manifest.file_hash,
                piece_index,
                "ED2K ICH re-hash attempt: part still fails MD4"
            );
            return Ok(IchRehashResult::Failed);
        }

        // Durability: the payload bytes must be on disk BEFORE the manifest
        // can durably say `Verified` (same ordering as the piece-complete
        // fsync in `append_piece_block`).
        sync_payload(&payload_path).await?;

        let salvaged_bytes = part_len.saturating_sub(present_bytes);
        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == piece_index)
            .with_context(|| {
                format!(
                    "missing piece index {piece_index} in {}",
                    manifest.file_hash
                )
            })?;
        // `FillGap` + `RemoveBlockFromList` analog: the whole part is present
        // and verified, the retained remainder is no longer re-requested.
        piece.bytes_written = part_len;
        piece.block_bitmap = None;
        piece.state = Ed2kTransferState::Verified;
        piece.ich_corrupted = false;
        // Credit every recorded sender of this part (oracle ICH success ->
        // `m_CorruptionBlackBox.VerifiedData`, PartFile.cpp:5225). The corrupt
        // attribution recorded by an earlier AICH verdict, if any, stays until
        // its own `EvaluateData`, matching the oracle overlay semantics.
        self.cbb_record_verified_data(&manifest.file_hash, part_start, part_end);

        rebuild_verified_ranges(manifest);
        manifest.completed = manifest.is_fully_verified();
        if manifest.completed {
            super::hashset::refresh_completed_manifest_aich_hashset(
                &self.transfer_dir(manifest.file_hash.as_str()),
                manifest,
            )?;
        }
        self.upsert_verified_catalog_entry(manifest).await;
        tracing::info!(
            file_hash = %manifest.file_hash,
            piece_index,
            salvaged_bytes,
            "ED2K ICH re-hash salvaged corrupted part (gap filled from retained bytes)"
        );
        Ok(IchRehashResult::Salvaged { salvaged_bytes })
    }
}

/// Read the full `[part_start, part_start + part_len)` payload range, or
/// `None` when the payload file is missing or too short to cover the part.
async fn read_part_bytes(
    payload_path: &std::path::Path,
    part_start: u64,
    part_len: u64,
) -> Result<Option<Vec<u8>>> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = match tokio::fs::OpenOptions::new()
        .read(true)
        .open(payload_path)
        .await
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to open piece store {}", payload_path.display()));
        }
    };
    file.seek(std::io::SeekFrom::Start(part_start)).await?;
    let mut bytes = vec![0u8; usize::try_from(part_len).unwrap_or(0)];
    match file.read_exact(&mut bytes).await {
        Ok(_) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("failed to read piece store {}", payload_path.display())),
    }
}

/// fsync the payload so the verified part bytes are durable before the
/// manifest checkpoint can mark the part `Verified`.
async fn sync_payload(payload_path: &std::path::Path) -> Result<()> {
    let file = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(payload_path)
        .await
        .with_context(|| format!("failed to reopen piece store {}", payload_path.display()))?;
    file.sync_all().await?;
    Ok(())
}
