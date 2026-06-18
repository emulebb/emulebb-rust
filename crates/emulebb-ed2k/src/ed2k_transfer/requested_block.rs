//! Out-of-order requested-block persistence for normal ED2K downloads.

use std::time::Instant;

use anyhow::{Context, Result};

use super::hashset::refresh_completed_manifest_aich_hashset;
use super::manifest::{rebuild_verified_ranges, verify_piece_against_manifest};
use super::piece_store::{AppendPieceBlockLog, log_append_piece_block};
use super::{
    Ed2kResumeManifest, Ed2kTransferRuntime, Ed2kTransferState, PAYLOAD_FILE_NAME,
    PieceWriteOutcome,
};

impl Ed2kTransferRuntime {
    #[expect(clippy::too_many_arguments)]
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

        let payload_path = self.transfer_dir(file_hash).join(PAYLOAD_FILE_NAME);
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&payload_path)
            .await
            .with_context(|| format!("failed to open piece store {}", payload_path.display()))?;
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
        drop(file);

        bitmap.set_present(block_idx);
        let mut verified = false;
        if bitmap.all_present() {
            let mut piece_bytes = vec![0u8; usize::try_from(expected_piece_len).unwrap_or(0)];
            let mut read_file = tokio::fs::OpenOptions::new()
                .read(true)
                .open(&payload_path)
                .await
                .with_context(|| {
                    format!("failed to reopen piece store {}", payload_path.display())
                })?;
            read_file
                .seek(std::io::SeekFrom::Start(piece_start))
                .await?;
            read_file.read_exact(&mut piece_bytes).await?;
            verified = verify_piece_against_manifest(manifest, piece_index, &piece_bytes)?;
        }

        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == piece_index)
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        let mut outcome = PieceWriteOutcome::Incomplete;
        let checkpoint_reason;
        if verified {
            piece.bytes_written = expected_piece_len;
            piece.block_bitmap = None;
            piece.state = Ed2kTransferState::Verified;
            outcome = PieceWriteOutcome::Verified;
            checkpoint_reason = Some("piece_verified");
        } else if bitmap.all_present() {
            piece.bytes_written = 0;
            piece.block_bitmap = None;
            piece.state = Ed2kTransferState::Missing;
            outcome = PieceWriteOutcome::VerificationFailed {
                part_index: piece_index,
            };
            checkpoint_reason = Some("piece_verification_failed");
        } else {
            piece.apply_block_bitmap(&bitmap);
            piece.state = Ed2kTransferState::Requested;
            checkpoint_reason = Some("out_of_order_block");
        }

        rebuild_verified_ranges(manifest);
        manifest.completed = manifest.is_fully_verified();
        if manifest.completed {
            refresh_completed_manifest_aich_hashset(
                &self.transfer_dir(manifest.file_hash.as_str()),
                manifest,
            )?;
        }
        if outcome.is_completed() {
            self.upsert_verified_catalog_entry(manifest).await;
        }
        self.store_manifest_unlocked(manifest).await?;
        log_append_piece_block(AppendPieceBlockLog {
            manifest,
            piece_index,
            start,
            end,
            block_received_at,
            should_checkpoint: true,
            checkpoint_reason,
        });
        Ok(outcome)
    }
}
