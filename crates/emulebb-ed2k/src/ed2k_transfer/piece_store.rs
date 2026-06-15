//! Piece claim, persistence, and verified-range IO for ED2K transfers.

use std::time::Instant;

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use tracing::debug;

use super::hashset::refresh_completed_manifest_aich_hashset;
use super::manifest::{rebuild_verified_ranges, verify_piece_against_manifest};
use super::{
    Ed2kClaimedPart, Ed2kResumeManifest, Ed2kTransferRuntime, Ed2kTransferState, PAYLOAD_FILE_NAME,
    expected_piece_length,
};

impl Ed2kTransferRuntime {
    /// Mark a specific missing piece as requested.
    #[cfg(test)]
    pub async fn mark_piece_requested(&self, file_hash: &str, piece_index: u32) -> Result<bool> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == piece_index)
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        if piece.state == Ed2kTransferState::Missing {
            piece.state = Ed2kTransferState::Requested;
            self.store_manifest_unlocked(&manifest).await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Claim the next incomplete part atomically for one peer session.
    ///
    /// `peer_bitmap` is the connected peer's advertised per-part availability
    /// (OP_FILESTATUS); when `Some`, only parts the peer holds are claimed so we
    /// never solicit an `OP_OUTOFPARTREQS` rejection (master
    /// `sender->IsPartAvailable`). Among the eligible missing parts the rarest
    /// is preferred, with a preview boost for the first/last part(s) and a
    /// near-completion priority inversion (master
    /// `CPartFile::GetNextRequestedBlock` chunk selection, scoped to this
    /// transfer's live per-part source frequency).
    pub(crate) async fn claim_next_missing_part(
        &self,
        file_hash: &str,
        peer_bitmap: Option<&[bool]>,
    ) -> Result<Option<Ed2kClaimedPart>> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let part_total = u32::try_from(manifest.pieces.len()).unwrap_or(u32::MAX);
        // Per-part live-source availability is the rarity input. Sampled outside
        // the manifest lock's borrow so the manifest stays mutably borrowed for
        // the claim below; this lock is independent of `manifest_io`.
        let frequency = self.available_sources_per_part(file_hash, part_total);
        let Some(piece_index) = super::download_pick::pick_next_missing_part(
            &manifest.pieces,
            manifest.file_size,
            manifest.piece_size,
            peer_bitmap,
            &frequency,
        ) else {
            return Ok(None);
        };
        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == piece_index)
            .with_context(|| format!("picked piece {piece_index} absent in {file_hash}"))?;
        let claimed = Ed2kClaimedPart {
            piece_index: piece.piece_index,
            bytes_written: piece.bytes_written,
        };
        piece.state = Ed2kTransferState::Requested;
        self.store_manifest_unlocked(&manifest).await?;
        Ok(Some(claimed))
    }

    /// Release a previously requested part back to the missing pool.
    ///
    /// Any already persisted byte prefix is kept so a later peer session can
    /// resume from the exact missing range instead of discarding good data.
    pub async fn release_piece_request(&self, file_hash: &str, piece_index: u32) -> Result<()> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == piece_index)
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        if piece.state == Ed2kTransferState::Requested {
            piece.state = Ed2kTransferState::Missing;
            self.store_manifest_unlocked(&manifest).await?;
        }
        Ok(())
    }

    /// Requeue any persisted requested pieces after a downloader restart.
    ///
    /// Requested pieces are session-local claims. If the process exits before
    /// the downloader releases them, the next process instance must move them
    /// back to `Missing` so resume can continue from the already persisted byte
    /// prefix instead of deadlocking on a stale in-flight marker.
    pub async fn reclaim_stale_piece_requests(&self, file_hash: &str) -> Result<bool> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let mut changed = false;
        for piece in &mut manifest.pieces {
            if piece.state == Ed2kTransferState::Requested {
                piece.state = Ed2kTransferState::Missing;
                changed = true;
            }
        }
        if changed {
            self.store_manifest_unlocked(&manifest).await?;
        }
        Ok(changed)
    }

    /// Persist one downloaded piece into the local piece store.
    #[allow(dead_code)]
    pub async fn store_piece_data(
        &self,
        file_hash: &str,
        piece_index: u32,
        data: &[u8],
    ) -> Result<()> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let piece_size = manifest.piece_size;
        let expected_piece_len =
            expected_piece_length(manifest.file_size, piece_size, u64::from(piece_index));
        if u64::try_from(data.len()).unwrap_or(u64::MAX) != expected_piece_len {
            anyhow::bail!(
                "piece {} for {} has unexpected size {} expected {}",
                piece_index,
                file_hash,
                data.len(),
                expected_piece_len
            );
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
        use tokio::io::{AsyncSeekExt, AsyncWriteExt};
        file.seek(std::io::SeekFrom::Start(
            u64::from(piece_index) * piece_size,
        ))
        .await?;
        file.write_all(data).await?;
        file.flush().await?;
        let verified = verify_piece_against_manifest(&manifest, piece_index, data)?;
        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == piece_index)
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        if verified {
            piece.bytes_written = expected_piece_len;
            piece.state = Ed2kTransferState::Verified;
        } else {
            piece.bytes_written = 0;
            piece.state = Ed2kTransferState::Missing;
        }
        rebuild_verified_ranges(&mut manifest);
        manifest.completed = manifest.is_fully_verified();
        if manifest.completed {
            refresh_completed_manifest_aich_hashset(
                &self.transfer_dir(manifest.file_hash.as_str()),
                &mut manifest,
            )?;
        }
        self.upsert_verified_catalog_entry(&manifest).await;
        self.store_manifest_unlocked(&manifest).await
    }

    /// Append one contiguous download block into a requested piece.
    ///
    /// This is used for single-part ED2K downloads where peers expect
    /// eMule-sized `OP_REQUESTPARTS` block ranges instead of one whole-file
    /// range. The method only accepts strictly contiguous writes for the
    /// claimed piece and verifies the full piece once the final block arrives.
    pub async fn append_piece_block(
        &self,
        file_hash: &str,
        piece_index: u32,
        start: u64,
        end: u64,
        data: &[u8],
    ) -> Result<bool> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let block_received_at = Instant::now();
        let piece_size = manifest.piece_size;
        let piece_start = u64::from(piece_index) * piece_size;
        let expected_piece_len =
            expected_piece_length(manifest.file_size, piece_size, u64::from(piece_index));
        let piece_end = piece_start + expected_piece_len;
        let data_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let current_piece_bytes_written = manifest
            .pieces
            .iter()
            .find(|piece| piece.piece_index == piece_index)
            .map(|piece| piece.bytes_written)
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        let expected_start = piece_start + current_piece_bytes_written;
        let expected_end = expected_start + data_len;
        if start != expected_start || end != expected_end || end > piece_end {
            anyhow::bail!(
                "piece {piece_index} for {file_hash} received unexpected block {start}..{end} expected {expected_start}..{expected_end} within {piece_start}..{piece_end}"
            );
        }

        let payload_path = self.transfer_dir(file_hash).join(PAYLOAD_FILE_NAME);
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&payload_path)
            .await
            .with_context(|| format!("failed to open piece store {}", payload_path.display()))?;
        use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
        file.seek(std::io::SeekFrom::Start(start)).await?;
        file.write_all(data).await?;

        let next_piece_bytes_written = current_piece_bytes_written + data_len;
        let mut piece_completed = false;
        let mut checkpoint_reason = None;
        if next_piece_bytes_written == expected_piece_len {
            file.flush().await?;
            let mut piece_bytes = vec![0u8; usize::try_from(expected_piece_len).unwrap_or(0)];
            drop(file);
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
            let verified = verify_piece_against_manifest(&manifest, piece_index, &piece_bytes)?;
            let piece = manifest
                .pieces
                .iter_mut()
                .find(|piece| piece.piece_index == piece_index)
                .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
            if verified {
                piece.bytes_written = expected_piece_len;
                piece.state = Ed2kTransferState::Verified;
                piece_completed = true;
                checkpoint_reason = Some("piece_verified");
            } else {
                piece.state = Ed2kTransferState::Missing;
                piece.bytes_written = 0;
                checkpoint_reason = Some("piece_verification_failed");
            }
            rebuild_verified_ranges(&mut manifest);
            manifest.completed = manifest.is_fully_verified();
            if manifest.completed {
                refresh_completed_manifest_aich_hashset(
                    &self.transfer_dir(manifest.file_hash.as_str()),
                    &mut manifest,
                )?;
            }
            if piece_completed {
                self.upsert_verified_catalog_entry(&manifest).await;
            }
        } else {
            let piece = manifest
                .pieces
                .iter_mut()
                .find(|piece| piece.piece_index == piece_index)
                .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
            piece.bytes_written = next_piece_bytes_written;
            piece.state = Ed2kTransferState::Requested;

            let should_checkpoint = checkpoint_reason.is_some()
                || self.should_checkpoint_manifest_unlocked(&manifest).await;
            if should_checkpoint {
                if checkpoint_reason.is_none() {
                    checkpoint_reason = Some("periodic_progress");
                }
                file.flush().await?;
                drop(file);
                self.store_manifest_unlocked(&manifest).await?;
                log_append_piece_block(AppendPieceBlockLog {
                    manifest: &manifest,
                    piece_index,
                    start,
                    end,
                    block_received_at,
                    should_checkpoint,
                    checkpoint_reason,
                });
                return Ok(piece_completed);
            }

            drop(file);
            self.cache_manifest_unlocked(&manifest).await;
            log_append_piece_block(AppendPieceBlockLog {
                manifest: &manifest,
                piece_index,
                start,
                end,
                block_received_at,
                should_checkpoint,
                checkpoint_reason,
            });
            return Ok(piece_completed);
        }

        let should_checkpoint = true;
        self.store_manifest_unlocked(&manifest).await?;
        log_append_piece_block(AppendPieceBlockLog {
            manifest: &manifest,
            piece_index,
            start,
            end,
            block_received_at,
            should_checkpoint,
            checkpoint_reason,
        });
        Ok(piece_completed)
    }

    /// Append a block and return the refreshed manifest snapshot used by
    /// downloader orchestration after a persistence boundary.
    pub async fn append_piece_block_with_manifest(
        &self,
        file_hash: &str,
        piece_index: u32,
        start: u64,
        end: u64,
        data: &[u8],
    ) -> Result<(bool, Ed2kResumeManifest)> {
        let piece_completed = self
            .append_piece_block(file_hash, piece_index, start, end, data)
            .await?;
        let manifest = self.manifest(file_hash).await?;
        Ok((piece_completed, manifest))
    }

    /// Read a fully verified range for upload serving.
    pub async fn read_verified_range(
        &self,
        file_hash: &Ed2kHash,
        start: u64,
        end: u64,
    ) -> Result<Option<Vec<u8>>> {
        let hash_hex = file_hash.to_string();
        let _guard = self.manifest_io.lock().await;
        let manifest = self.load_manifest_unlocked(&hash_hex).await?;
        if !manifest
            .verified_ranges
            .iter()
            .any(|range| start >= range.start && end <= range.end)
        {
            return Ok(None);
        }
        let payload_path = self.transfer_dir(&hash_hex).join(PAYLOAD_FILE_NAME);
        let mut file = tokio::fs::OpenOptions::new()
            .read(true)
            .open(&payload_path)
            .await
            .with_context(|| format!("failed to open piece store {}", payload_path.display()))?;
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        file.seek(std::io::SeekFrom::Start(start)).await?;
        let mut bytes = vec![0u8; usize::try_from(end.saturating_sub(start)).unwrap_or(0)];
        file.read_exact(&mut bytes).await?;
        Ok(Some(bytes))
    }
}

struct AppendPieceBlockLog<'a> {
    manifest: &'a Ed2kResumeManifest,
    piece_index: u32,
    start: u64,
    end: u64,
    block_received_at: Instant,
    should_checkpoint: bool,
    checkpoint_reason: Option<&'static str>,
}

fn log_append_piece_block(event: AppendPieceBlockLog<'_>) {
    debug!(
        file_hash = %event.manifest.file_hash,
        piece_index = event.piece_index,
        start = event.start,
        end = event.end,
        block_write_ms = event.block_received_at.elapsed().as_millis(),
        checkpoint = event.should_checkpoint,
        checkpoint_reason = event.checkpoint_reason.unwrap_or("cached_only"),
        completed = event.manifest.completed,
        "ED2K append_piece_block applied"
    );
}
