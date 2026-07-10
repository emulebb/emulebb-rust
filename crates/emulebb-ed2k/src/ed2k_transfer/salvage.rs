//! ICH block-level AICH salvage of a corrupt part.
//!
//! When a part fails its MD4 check, eMule (`CPartFile::AICHRecoveryDataAvailable`)
//! does not discard the whole part. It requests AICH recovery data, re-hashes the
//! local part at 180 KB block granularity, keeps every block whose SHA1 matches
//! the trusted AICH block hash (`FillGap`), and re-downloads only the blocks that
//! differ. The part is then MD4 re-verified (`HashSinglePart`); if MD4 agrees it
//! is complete.
//!
//! This module ports that flow onto the block-bitmap piece store:
//!  - `begin_part_salvage` consumes a verified OP_AICHANSWER recovery body for a
//!    corrupt part, marks the good blocks present and the bad blocks missing in
//!    the persisted per-part bitmap, and returns the byte ranges still needed.
//!  - `write_salvage_block` writes one recovered block range out of order, marks
//!    it present, and once every block of the part is present MD4 re-verifies the
//!    whole part, promoting it to `Verified` (or rejecting it back to a salvage
//!    state if MD4 still disagrees).

use anyhow::{Context, Result};

use super::aich_recovery::{compute_part_recovery, trusted_part_block_hashes_from_recovery};
use super::block_bitmap::PartBlockBitmap;
use super::hashset::decode_aich_hash_hex;
use super::manifest::{rebuild_verified_ranges, verify_piece_against_manifest};
use super::{
    Ed2kTransferRuntime, Ed2kTransferState, PAYLOAD_FILE_NAME, PieceWriteOutcome,
    expected_piece_length,
};

/// Outcome of starting ICH salvage on one corrupt part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PartSalvageOutcome {
    /// Absolute byte ranges (file offsets) of the blocks that verified OK and
    /// were salvaged (kept). One entry per recovered 180 KB block.
    pub(crate) recovered_ranges: Vec<(u64, u64)>,
    /// Absolute byte ranges (file offsets) of the corrupt blocks that must be
    /// re-downloaded.
    pub(crate) needed_ranges: Vec<(u64, u64)>,
}

impl Ed2kTransferRuntime {
    /// Begin ICH salvage for a corrupt `part` using a peer's verified
    /// OP_AICHANSWER recovery body. Mirrors the comparison + `FillGap` loop of
    /// `CPartFile::AICHRecoveryDataAvailable`.
    ///
    /// `recovery_body` is the raw recovery payload that follows the answer
    /// header (`file hash 16` + `part u16` + `master hash 20`). The supplied
    /// `master_hash` must match the locally trusted AICH root.
    ///
    /// Marks the good blocks present and the bad blocks missing in the persisted
    /// per-part bitmap, moves the part into `Requested` (salvage in progress),
    /// and returns the still-needed corrupt ranges. Returns `None` when the file
    /// or part is unknown, the part is not currently corrupt, there is no
    /// trusted AICH root, or the recovery data fails verification.
    pub(crate) async fn begin_part_salvage(
        &self,
        file_hash: &str,
        part: u16,
        master_hash: [u8; 20],
        recovery_body: &[u8],
    ) -> Result<Option<PartSalvageOutcome>> {
        let _guard = self.lock_manifest(file_hash).await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;

        // Need a trusted AICH root that matches the answer's master hash.
        let Some(root_hex) = manifest.aich_root.as_deref() else {
            return Ok(None);
        };
        let trusted_root = decode_aich_hash_hex(root_hex)?;
        if trusted_root != master_hash {
            return Ok(None);
        }

        let part_index = u32::from(part);
        let piece_size = manifest.piece_size;
        let part_start = u64::from(part_index) * piece_size;
        let part_len = expected_piece_length(manifest.file_size, piece_size, u64::from(part_index));
        if part_len == 0 {
            return Ok(None);
        }

        // Only salvage a part that is not already verified/complete.
        let Some(piece) = manifest
            .pieces
            .iter()
            .find(|piece| piece.piece_index == part_index)
        else {
            return Ok(None);
        };
        if piece.state == Ed2kTransferState::Verified {
            return Ok(None);
        }

        // Read the current (corrupt) local part bytes.
        let part_bytes = self
            .read_part_raw_unlocked(file_hash, part_start, part_len)
            .await?;

        // Verify the recovery data against the trusted master hash and recover
        // the per-block trusted hashes for this part.
        let trusted_block_hashes = trusted_part_block_hashes_from_recovery(
            manifest.file_size,
            trusted_root,
            u64::from(part_index),
            recovery_body,
        )?;
        let recovery = compute_part_recovery(
            manifest.file_size,
            u64::from(part_index),
            &part_bytes,
            &trusted_block_hashes,
        )?;

        // Feed the per-block AICH verdicts into the corruption blackbox and
        // evaluate the senders: good blocks credit their recorded senders, bad
        // blocks debit them, and a sender whose corrupt share crosses 32% is
        // banned (oracle `CPartFile::AICHRecoveryDataAvailable` ->
        // `VerifiedData`/`CorruptedData` per block + `EvaluateData`,
        // PartFile.cpp:6555-6566).
        for (block_start, block_end) in &recovery.recovered_ranges {
            self.cbb_record_verified_data(file_hash, *block_start, *block_end);
        }
        for (block_start, block_end) in &recovery.corrupt_ranges {
            self.cbb_record_corrupted_data(file_hash, *block_start, *block_end);
        }
        self.cbb_evaluate_part(file_hash, part);

        // Build the per-part bitmap from the good/bad verdict: good blocks become
        // present, corrupt blocks become missing/needed.
        let mut bitmap = PartBlockBitmap::empty(part_len);
        for (abs_start, _abs_end) in &recovery.recovered_ranges {
            let rel = abs_start - part_start;
            let idx = usize::try_from(rel / super::ED2K_EMBLOCK_SIZE).unwrap_or(usize::MAX);
            bitmap.set_present(idx);
        }

        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == part_index)
            .with_context(|| format!("missing piece index {part_index} in {file_hash}"))?;
        piece.apply_block_bitmap(&bitmap);
        // Salvage in progress: the good blocks are recorded present in the
        // bitmap and the corrupt blocks remain as gaps. The part returns to the
        // `Missing` pool so the gap-aware download window re-claims it and
        // re-requests only the missing blocks, mirroring eMule leaving the bad
        // blocks in the gap list while the good blocks were `FillGap`-ed.
        piece.state = Ed2kTransferState::Missing;
        self.store_manifest_unlocked(&manifest).await?;

        Ok(Some(PartSalvageOutcome {
            recovered_ranges: recovery.recovered_ranges,
            needed_ranges: recovery.corrupt_ranges,
        }))
    }

    /// Write one recovered block range `[start, end)` (absolute file offsets) of
    /// a part undergoing salvage, mark it present in the bitmap, and once every
    /// block of the part is present MD4 re-verify the whole part.
    ///
    /// Returns `true` when this write completed and MD4-verified the part.
    /// Mirrors the `HashSinglePart` re-check at the end of
    /// `CPartFile::AICHRecoveryDataAvailable`.
    pub(crate) async fn write_salvage_block(
        &self,
        file_hash: &str,
        part: u16,
        start: u64,
        end: u64,
        data: &[u8],
    ) -> Result<PieceWriteOutcome> {
        let _guard = self.lock_manifest(file_hash).await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let part_index = u32::from(part);
        let piece_size = manifest.piece_size;
        let part_start = u64::from(part_index) * piece_size;
        let part_len = expected_piece_length(manifest.file_size, piece_size, u64::from(part_index));
        let part_end = part_start + part_len;

        let data_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        if end != start + data_len {
            anyhow::bail!(
                "salvage block for {file_hash} part {part}: range {start}..{end} does not match data len {data_len}"
            );
        }
        if start < part_start || end > part_end {
            anyhow::bail!(
                "salvage block for {file_hash} part {part}: range {start}..{end} outside part {part_start}..{part_end}"
            );
        }
        let rel_start = start - part_start;
        if !rel_start.is_multiple_of(super::ED2K_EMBLOCK_SIZE) {
            anyhow::bail!(
                "salvage block for {file_hash} part {part}: start {start} is not block-aligned"
            );
        }
        let block_idx = usize::try_from(rel_start / super::ED2K_EMBLOCK_SIZE).unwrap_or(usize::MAX);

        let piece = manifest
            .pieces
            .iter()
            .find(|piece| piece.piece_index == part_index)
            .with_context(|| format!("missing piece index {part_index} in {file_hash}"))?;
        let mut bitmap = piece.resolve_block_bitmap(part_len);
        let (expected_start, expected_end) = bitmap.block_range(block_idx);
        if start - part_start != expected_start || end - part_start != expected_end {
            anyhow::bail!(
                "salvage block for {file_hash} part {part}: range {start}..{end} is not block {block_idx} ({}..{})",
                part_start + expected_start,
                part_start + expected_end
            );
        }

        // Write the block bytes at their absolute offset (out of order is fine).
        let payload_path = self.transfer_dir(file_hash).join(PAYLOAD_FILE_NAME);
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&payload_path)
            .await
            .with_context(|| format!("failed to open piece store {}", payload_path.display()))?;
        use tokio::io::{AsyncSeekExt, AsyncWriteExt};
        file.seek(std::io::SeekFrom::Start(start)).await?;
        file.write_all(data).await?;

        // Mid-salvage blocks stay flush()-only (userspace -> OS) for speed; the
        // block that completes the part is fsync'd so the payload bytes are
        // durable on disk BEFORE the manifest checkpoint commit can mark the
        // part Verified. This keeps a durable "Verified" manifest state from
        // outracing the on-disk bytes on an OS crash / power loss, mirroring the
        // contiguous append_piece_block piece-complete fsync.
        let completes_part = {
            let mut probe = bitmap.clone();
            probe.set_present(block_idx);
            probe.all_present()
        };
        if completes_part {
            file.sync_all().await?;
        } else {
            file.flush().await?;
        }
        drop(file);

        bitmap.set_present(block_idx);

        let mut verified = false;
        if bitmap.all_present() {
            // Every block present: MD4 re-verify the whole part.
            let part_bytes = self
                .read_part_raw_unlocked(file_hash, part_start, part_len)
                .await?;
            verified = verify_piece_against_manifest(&manifest, part_index, &part_bytes)?;
        }

        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == part_index)
            .with_context(|| format!("missing piece index {part_index} in {file_hash}"))?;
        let mut outcome = PieceWriteOutcome::Incomplete;
        if verified {
            piece.bytes_written = part_len;
            piece.block_bitmap = None;
            piece.state = Ed2kTransferState::Verified;
            piece.ich_corrupted = false;
            outcome = PieceWriteOutcome::Verified;
            // Credit every recorded sender of the ICH-saved part (oracle
            // `HashSinglePart` success on a corrupted part ->
            // `m_CorruptionBlackBox.VerifiedData`, PartFile.cpp:5225).
            self.cbb_record_verified_data(file_hash, part_start, part_end);
        } else {
            piece.apply_block_bitmap(&bitmap);
            piece.state = if bitmap.all_present() {
                // All blocks present but MD4 still failed: the salvage could not
                // reconstruct the part. Drop back to a clean re-download and
                // signal the verification failure so the session can re-request
                // AICH recovery (a fresh, possibly different, recovery answer).
                // The bytes stay on disk and the part stays flagged for the
                // MD4-only ICH fallback (oracle keeps it in corrupted_list).
                piece.bytes_written = 0;
                piece.block_bitmap = None;
                piece.ich_corrupted = true;
                outcome = PieceWriteOutcome::VerificationFailed { part_index };
                Ed2kTransferState::Missing
            } else {
                Ed2kTransferState::Requested
            };
        }
        // The MD4-only ICH re-hash also runs on a flush into a part mid AICH
        // salvage (the oracle's FlushBuffer ICH branch is gated only on
        // corrupted_list membership, PartFile.cpp:5214). It can only succeed
        // once the AICH-identified bad blocks hold good bytes, so a miss
        // leaves the salvage bitmap untouched and the AICH flow proceeds.
        if matches!(outcome, PieceWriteOutcome::Incomplete) {
            match self
                .ich_try_rehash_part_unlocked(&mut manifest, part_index)
                .await?
            {
                super::ich_salvage::IchRehashResult::Salvaged { salvaged_bytes } => {
                    outcome = PieceWriteOutcome::IchSalvaged {
                        part_index,
                        salvaged_bytes,
                    };
                }
                super::ich_salvage::IchRehashResult::Failed => {
                    outcome = PieceWriteOutcome::IchRehashFailed { part_index };
                }
                super::ich_salvage::IchRehashResult::NotAttempted => {}
            }
        }

        rebuild_verified_ranges(&mut manifest);
        manifest.completed = manifest.is_fully_verified();
        if manifest.completed {
            super::hashset::refresh_completed_manifest_aich_hashset(
                &self.transfer_dir(manifest.file_hash.as_str()),
                &mut manifest,
            )?;
        }
        if verified {
            self.upsert_verified_catalog_entry(&manifest).await;
        }
        self.store_manifest_unlocked(&manifest).await?;
        Ok(outcome)
    }

    /// Write a downloaded block, dispatching to the ICH salvage path when the
    /// target part is mid-salvage (a non-contiguous block bitmap is persisted)
    /// and to the contiguous `append_piece_block` fast path otherwise.
    ///
    /// Returns `(part_completed, refreshed_manifest)` so the download flush layer
    /// can drive orchestration identically for both paths.
    pub(crate) async fn append_or_salvage_block_with_manifest(
        &self,
        file_hash: &str,
        piece_index: u32,
        start: u64,
        end: u64,
        data: &[u8],
    ) -> Result<(PieceWriteOutcome, super::Ed2kResumeManifest)> {
        let is_salvage = {
            let _guard = self.lock_manifest(file_hash).await;
            // Cache-hit probe: checking one piece's bitmap flag must not clone
            // the whole manifest on every accepted block.
            self.probe_manifest_unlocked(file_hash, |manifest| {
                manifest
                    .pieces
                    .iter()
                    .find(|piece| piece.piece_index == piece_index)
                    .map(|piece| piece.has_block_bitmap())
                    .unwrap_or(false)
            })
            .await?
        };
        if is_salvage {
            let part = u16::try_from(piece_index)
                .map_err(|_| anyhow::anyhow!("salvage part index {piece_index} exceeds u16"))?;
            let outcome = self
                .write_salvage_block(file_hash, part, start, end, data)
                .await?;
            let manifest = self.manifest(file_hash).await?;
            Ok((outcome, manifest))
        } else {
            self.append_piece_block_with_manifest(file_hash, piece_index, start, end, data)
                .await
        }
    }

    /// Read `len` raw bytes of the payload starting at absolute `start`, used to
    /// re-hash a not-yet-verified (corrupt) part for salvage.
    async fn read_part_raw_unlocked(
        &self,
        file_hash: &str,
        start: u64,
        len: u64,
    ) -> Result<Vec<u8>> {
        let payload_path = self.transfer_dir(file_hash).join(PAYLOAD_FILE_NAME);
        let mut file = tokio::fs::OpenOptions::new()
            .read(true)
            .open(&payload_path)
            .await
            .with_context(|| format!("failed to open piece store {}", payload_path.display()))?;
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        file.seek(std::io::SeekFrom::Start(start)).await?;
        let mut bytes = vec![0u8; usize::try_from(len).unwrap_or(0)];
        file.read_exact(&mut bytes).await?;
        Ok(bytes)
    }
}
