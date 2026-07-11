//! Out-of-order requested-block persistence for normal ED2K downloads.

use std::time::Instant;

use anyhow::{Context, Result};

use super::hashset::refresh_completed_manifest_aich_hashset;
use super::ich_salvage::IchRehashResult;
use super::manifest::{rebuild_verified_ranges, verify_piece_against_manifest};
use super::piece_store::{AppendPieceBlockLog, log_append_piece_block};
use super::{Ed2kResumeManifest, Ed2kTransferRuntime, Ed2kTransferState, PieceWriteOutcome};

impl Ed2kTransferRuntime {
    #[expect(
        clippy::too_many_arguments,
        reason = "flat protocol or runtime boundary"
    )]
    pub(super) async fn append_requested_block_by_bitmap_unlocked(
        &self,
        manifest: &mut Ed2kResumeManifest,
        file_hash: &str,
        piece_index: u32,
        piece_start: u64,
        expected_piece_len: u64,
        start: u64,
        end: u64,
        data: &[u8],
        block_received_at: Instant,
    ) -> Result<PieceWriteOutcome> {
        let piece_end = piece_start + expected_piece_len;
        let data_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        if end != start + data_len {
            anyhow::bail!(
                "piece {piece_index} for {file_hash} received block {start}..{end} with data length {data_len}"
            );
        }
        if start < piece_start || end > piece_end {
            anyhow::bail!(
                "piece {piece_index} for {file_hash} received block {start}..{end} outside {piece_start}..{piece_end}"
            );
        }
        let rel_start = start - piece_start;
        if !rel_start.is_multiple_of(super::ED2K_EMBLOCK_SIZE) {
            anyhow::bail!(
                "piece {piece_index} for {file_hash} received non-block-aligned requested block {start}..{end}"
            );
        }
        let block_idx = usize::try_from(rel_start / super::ED2K_EMBLOCK_SIZE).unwrap_or(usize::MAX);
        let piece = manifest
            .pieces
            .iter()
            .find(|piece| piece.piece_index == piece_index)
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        let mut bitmap = piece.resolve_block_bitmap(expected_piece_len);
        let (expected_rel_start, expected_rel_end) = bitmap.block_range(block_idx);
        if rel_start != expected_rel_start || end - piece_start != expected_rel_end {
            anyhow::bail!(
                "piece {piece_index} for {file_hash} received requested block {start}..{end} outside eMule block {block_idx} ({}..{})",
                piece_start + expected_rel_start,
                piece_start + expected_rel_end
            );
        }
        if bitmap.is_present(block_idx) {
            log_append_piece_block(AppendPieceBlockLog {
                manifest,
                piece_index,
                start,
                end,
                block_received_at,
                should_checkpoint: false,
                checkpoint_reason: Some("duplicate_block"),
            });
            return Ok(PieceWriteOutcome::Incomplete);
        }

        let mut file = self.take_payload_handle(file_hash).await?;
        use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
        file.seek(std::io::SeekFrom::Start(start)).await?;
        file.write_all(data).await?;

        let completes_piece = {
            let mut probe = bitmap.clone();
            probe.set_present(block_idx);
            probe.all_present()
        };
        if completes_piece {
            file.sync_all().await?;
        } else {
            file.flush().await?;
        }

        bitmap.set_present(block_idx);
        let mut verified = false;
        if bitmap.all_present() {
            let mut piece_bytes = vec![0u8; usize::try_from(expected_piece_len).unwrap_or(0)];
            file.seek(std::io::SeekFrom::Start(piece_start)).await?;
            file.read_exact(&mut piece_bytes).await?;
            verified = verify_piece_against_manifest(manifest, piece_index, &piece_bytes)?;
        }
        self.store_payload_handle(file_hash, file);

        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == piece_index)
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        let mut outcome = PieceWriteOutcome::Incomplete;
        let mut checkpoint_reason;
        if verified {
            piece.bytes_written = expected_piece_len;
            piece.block_bitmap = None;
            piece.state = Ed2kTransferState::Verified;
            piece.ich_corrupted = false;
            outcome = PieceWriteOutcome::Verified;
            checkpoint_reason = Some("piece_verified");
            // Credit every recorded sender of this part in the corruption
            // blackbox (oracle MD4 part success ->
            // `m_CorruptionBlackBox.VerifiedData`, PartFile.cpp:5205).
            self.cbb_record_verified_data(file_hash, piece_start, piece_end);
        } else if bitmap.all_present() {
            // The on-disk bytes are retained (logical gap only) and the part
            // is flagged for MD4-only ICH salvage (oracle corrupted_list add,
            // PartFile.cpp:5188-5190).
            piece.bytes_written = 0;
            piece.block_bitmap = None;
            piece.state = Ed2kTransferState::Missing;
            piece.ich_corrupted = true;
            outcome = PieceWriteOutcome::VerificationFailed {
                part_index: piece_index,
            };
            checkpoint_reason = Some("piece_verification_failed");
        } else {
            piece.apply_block_bitmap(&bitmap);
            piece.state = Ed2kTransferState::Requested;
            checkpoint_reason = Some("out_of_order_block");
        }
        // MD4-only ICH fallback on a mid-part flush into a corrupted part
        // (oracle FlushBuffer ICH branch, PartFile.cpp:5214-5232). The write
        // handle was already flushed above, so the re-hash read sees this
        // block's bytes.
        if matches!(outcome, PieceWriteOutcome::Incomplete) {
            match self
                .ich_try_rehash_part_unlocked(manifest, piece_index)
                .await?
            {
                IchRehashResult::Salvaged { salvaged_bytes } => {
                    outcome = PieceWriteOutcome::IchSalvaged {
                        part_index: piece_index,
                        salvaged_bytes,
                    };
                    checkpoint_reason = Some("ich_salvaged");
                }
                IchRehashResult::Failed => {
                    outcome = PieceWriteOutcome::IchRehashFailed {
                        part_index: piece_index,
                    };
                }
                IchRehashResult::NotAttempted => {}
            }
        }

        rebuild_verified_ranges(manifest);
        manifest.completed = manifest.is_fully_verified();
        if manifest.completed {
            refresh_completed_manifest_aich_hashset(
                &self.transfer_dir(manifest.file_hash.as_str()),
                manifest,
            )?;
            // No further appends will come: release the cached write handle
            // so a completed payload holds no open handle.
            self.invalidate_payload_handle(file_hash);
        }
        if outcome.is_completed() {
            self.upsert_verified_catalog_entry(manifest).await;
        }
        // A plain out-of-order block only dirties this piece's row (bitmap +
        // state), so it follows the batched progress-checkpoint policy: cache
        // the manifest and record the dirty piece between checkpoints, persist
        // via the piece-row UPDATE when the byte/interval threshold trips.
        // Verification outcomes and ICH salvage change verified ranges /
        // completion and keep the immediate full child-table store; an ICH
        // re-hash miss leaves the manifest untouched beyond the piece, so it
        // stays on the batched light path too.
        let mut should_checkpoint = true;
        if matches!(
            outcome,
            PieceWriteOutcome::Incomplete | PieceWriteOutcome::IchRehashFailed { .. }
        ) {
            should_checkpoint = self.should_checkpoint_manifest_unlocked(manifest).await;
            if should_checkpoint {
                self.store_manifest_piece_progress_unlocked(manifest, piece_index)
                    .await?;
            } else {
                checkpoint_reason = None;
                self.note_dirty_piece_unlocked(manifest, piece_index).await;
                self.cache_manifest_unlocked(manifest).await;
            }
        } else {
            self.store_manifest_unlocked(manifest).await?;
        }
        log_append_piece_block(AppendPieceBlockLog {
            manifest,
            piece_index,
            start,
            end,
            block_received_at,
            should_checkpoint,
            checkpoint_reason,
        });
        Ok(outcome)
    }
}
