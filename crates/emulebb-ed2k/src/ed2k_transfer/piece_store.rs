//! Piece claim, persistence, and verified-range IO for ED2K transfers.

use std::{path::PathBuf, time::Instant};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use tracing::debug;

use crate::long_path::long_path;

use super::hashset::refresh_completed_manifest_aich_hashset;
use super::ich_salvage::IchRehashResult;
use super::manifest::{rebuild_verified_ranges, verify_piece_against_manifest};
use super::{
    ED2K_EMBLOCK_SIZE, Ed2kClaimedPart, Ed2kResumeManifest, Ed2kSharedRange, Ed2kTransferRuntime,
    Ed2kTransferState, PAYLOAD_FILE_NAME, PieceWriteOutcome, expected_piece_length,
};

const UPLOAD_READ_AHEAD_BYTES: u64 = ED2K_EMBLOCK_SIZE * 3;

/// Verified upload reader for one local file.
///
/// Holds a single open payload handle plus a verified-range snapshot so one
/// `OP_REQUESTPARTS` serve can walk many `EMBLOCKSIZE` fragments without
/// reopening the same file or reloading the manifest for every fragment.
pub(crate) struct Ed2kVerifiedRangeReader {
    file: tokio::fs::File,
    verified_ranges: Vec<Ed2kSharedRange>,
    cache_start: u64,
    cache: Vec<u8>,
    cache_hit_count: usize,
    cache_miss_count: usize,
    disk_read_bytes: u64,
    #[cfg(test)]
    disk_read_count: usize,
}

impl Ed2kVerifiedRangeReader {
    pub(crate) async fn read_range(&mut self, start: u64, end: u64) -> Result<Option<Vec<u8>>> {
        self.read_range_with_read_ahead(start, end, UPLOAD_READ_AHEAD_BYTES)
            .await
    }

    pub(crate) async fn read_range_with_read_ahead(
        &mut self,
        start: u64,
        end: u64,
        read_ahead_bytes: u64,
    ) -> Result<Option<Vec<u8>>> {
        let Some(verified_range) = self
            .verified_ranges
            .iter()
            .find(|range| start >= range.start && end <= range.end)
        else {
            return Ok(None);
        };
        if let Some(bytes) = self.read_cached_range(start, end) {
            self.cache_hit_count = self.cache_hit_count.saturating_add(1);
            return Ok(Some(bytes));
        }

        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let requested_len = end.saturating_sub(start);
        let read_len = if requested_len >= ED2K_EMBLOCK_SIZE {
            requested_len.max(read_ahead_bytes)
        } else {
            requested_len
        };
        let read_end = start.saturating_add(read_len).min(verified_range.end);
        self.file.seek(std::io::SeekFrom::Start(start)).await?;
        self.cache_start = start;
        self.cache = vec![0u8; usize::try_from(read_end.saturating_sub(start)).unwrap_or(0)];
        self.file.read_exact(&mut self.cache).await?;
        self.cache_miss_count = self.cache_miss_count.saturating_add(1);
        self.disk_read_bytes = self
            .disk_read_bytes
            .saturating_add(u64::try_from(self.cache.len()).unwrap_or(u64::MAX));
        #[cfg(test)]
        {
            self.disk_read_count = self.disk_read_count.saturating_add(1);
        }
        Ok(self.read_cached_range(start, end))
    }

    fn read_cached_range(&self, start: u64, end: u64) -> Option<Vec<u8>> {
        let cache_len = u64::try_from(self.cache.len()).unwrap_or(u64::MAX);
        let cache_end = self.cache_start.saturating_add(cache_len);
        if start < self.cache_start || end > cache_end {
            return None;
        }
        let offset = usize::try_from(start.saturating_sub(self.cache_start)).ok()?;
        let len = usize::try_from(end.saturating_sub(start)).ok()?;
        Some(self.cache.get(offset..offset.saturating_add(len))?.to_vec())
    }

    #[cfg(test)]
    pub(crate) const fn disk_read_count(&self) -> usize {
        self.disk_read_count
    }

    pub(crate) const fn cache_hit_count(&self) -> usize {
        self.cache_hit_count
    }

    pub(crate) const fn cache_miss_count(&self) -> usize {
        self.cache_miss_count
    }

    pub(crate) const fn disk_read_bytes(&self) -> u64 {
        self.disk_read_bytes
    }
}

impl Ed2kTransferRuntime {
    /// Take (or open) the cached read+write payload handle for one transfer.
    /// Callers run under the transfer's manifest IO lock, so at most one user
    /// holds the handle at a time; hand it back with
    /// [`Self::store_payload_handle`] after use. On an IO error, drop it
    /// instead (the next take re-opens a fresh handle).
    pub(super) async fn take_payload_handle(&self, file_hash: &str) -> Result<tokio::fs::File> {
        if let Some(file) = self.payload_handles.lock().unwrap().remove(file_hash) {
            return Ok(file);
        }
        let payload_path = self.transfer_dir(file_hash).join(PAYLOAD_FILE_NAME);
        tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&payload_path)
            .await
            .with_context(|| format!("failed to open piece store {}", payload_path.display()))
    }

    /// Return a payload handle taken with [`Self::take_payload_handle`] so the
    /// next block append reuses it instead of re-opening the piece store.
    pub(super) fn store_payload_handle(&self, file_hash: &str, file: tokio::fs::File) {
        self.payload_handles
            .lock()
            .unwrap()
            .insert(file_hash.to_string(), file);
    }

    /// Drop the cached payload handle. Must run before the payload file is
    /// deleted: on Windows a pending handle leaves the file delete-pending and
    /// the transfer directory undeletable.
    pub(super) fn invalidate_payload_handle(&self, file_hash: &str) {
        self.payload_handles.lock().unwrap().remove(file_hash);
    }

    /// Mark a specific missing piece as requested.
    #[cfg(test)]
    pub async fn mark_piece_requested(&self, file_hash: &str, piece_index: u32) -> Result<bool> {
        let _guard = self.lock_manifest(file_hash).await;
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
        let _guard = self.lock_manifest(file_hash).await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let part_total = u32::try_from(manifest.pieces.len()).unwrap_or(u32::MAX);
        // Per-part live-source availability is the rarity input. Sampled outside
        // the manifest lock's borrow so the manifest stays mutably borrowed for
        // the claim below; this lock is independent of the manifest lock.
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
        let _guard = self.lock_manifest(file_hash).await;
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
        let _guard = self.lock_manifest(file_hash).await;
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

    /// Re-verify every on-disk part of a transfer against the MD4 hashset and
    /// rewrite the piece states + verified ranges + completed flag accordingly
    /// (oracle `CPartFile::HashSinglePart` over the whole file, the forced re-hash
    /// behind the GUI "recheck" action). A part whose on-disk bytes no longer
    /// MD4-match (or is short / unreadable) is demoted to `Missing` (0 bytes
    /// written) so the normal download path re-fetches it; a part that re-verifies
    /// is marked `Verified`. Requires the MD4 hashset to be known (it is the only
    /// re-verification authority) — without it there is nothing to check against,
    /// so the manifest is returned unchanged. Returns the recomputed `completed`
    /// flag (true == still a complete, fully verified file).
    pub async fn recheck_transfer(&self, file_hash: &str) -> Result<bool> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let _guard = self.lock_manifest(file_hash).await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        if !manifest.md4_hashset_acquired {
            // No hashset to verify against: a recheck cannot reclassify anything.
            return Ok(manifest.completed);
        }
        let piece_size = manifest.piece_size;
        let payload_path = self.transfer_dir(file_hash).join(PAYLOAD_FILE_NAME);
        // Open read-only; a missing payload means every part is gone (Missing).
        let mut file = match tokio::fs::OpenOptions::new()
            .read(true)
            .open(&payload_path)
            .await
        {
            Ok(file) => Some(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to open piece store {}", payload_path.display())
                });
            }
        };
        let piece_indices: Vec<u32> = manifest.pieces.iter().map(|p| p.piece_index).collect();
        for piece_index in piece_indices {
            let piece_start = u64::from(piece_index) * piece_size;
            let expected_piece_len =
                expected_piece_length(manifest.file_size, piece_size, u64::from(piece_index));
            // Re-read the part's on-disk bytes and MD4-verify them. Any read short
            // of the expected length (truncated / corrupted file) fails the part.
            let verified = if let Some(file) = file.as_mut() {
                let mut piece_bytes = vec![0u8; usize::try_from(expected_piece_len).unwrap_or(0)];
                let read_ok = file
                    .seek(std::io::SeekFrom::Start(piece_start))
                    .await
                    .is_ok()
                    && file.read_exact(&mut piece_bytes).await.is_ok();
                read_ok && verify_piece_against_manifest(&manifest, piece_index, &piece_bytes)?
            } else {
                false
            };
            let piece = manifest
                .pieces
                .iter_mut()
                .find(|piece| piece.piece_index == piece_index)
                .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
            if verified {
                piece.bytes_written = expected_piece_len;
                piece.state = Ed2kTransferState::Verified;
                piece.ich_corrupted = false;
            } else {
                // Demote a part that no longer verifies so it is re-downloaded.
                piece.bytes_written = 0;
                piece.state = Ed2kTransferState::Missing;
                piece.block_bitmap = None;
            }
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
        self.store_manifest_unlocked(&manifest).await?;
        Ok(manifest.completed)
    }

    /// Persist one downloaded piece into the local piece store.
    #[allow(dead_code)]
    pub async fn store_piece_data(
        &self,
        file_hash: &str,
        piece_index: u32,
        data: &[u8],
    ) -> Result<()> {
        let _guard = self.lock_manifest(file_hash).await;
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

    /// Append one downloaded block into a requested piece.
    ///
    /// This is used for single-part ED2K downloads where peers expect
    /// eMule-sized `OP_REQUESTPARTS` block ranges instead of one whole-file
    /// range. The common path accepts strictly contiguous writes for the
    /// claimed piece. A non-prefix response is accepted only when it is exactly
    /// one requested eMule block; those bytes are tracked with the per-part
    /// block bitmap until the missing prefix arrives.
    pub(crate) async fn append_piece_block(
        &self,
        file_hash: &str,
        piece_index: u32,
        start: u64,
        end: u64,
        data: &[u8],
    ) -> Result<PieceWriteOutcome> {
        let (outcome, _manifest) = self
            .append_piece_block_inner(file_hash, piece_index, start, end, data)
            .await?;
        Ok(outcome)
    }

    /// [`Self::append_piece_block`] returning the post-append manifest it
    /// already holds, so orchestration callers do not re-lock and re-clone the
    /// manifest for every accepted block.
    async fn append_piece_block_inner(
        &self,
        file_hash: &str,
        piece_index: u32,
        start: u64,
        end: u64,
        data: &[u8],
    ) -> Result<(PieceWriteOutcome, Ed2kResumeManifest)> {
        let _guard = self.lock_manifest(file_hash).await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let block_received_at = Instant::now();
        let piece_size = manifest.piece_size;
        let piece_start = u64::from(piece_index) * piece_size;
        let expected_piece_len =
            expected_piece_length(manifest.file_size, piece_size, u64::from(piece_index));
        let piece_end = piece_start + expected_piece_len;
        let data_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let piece_snapshot = manifest
            .pieces
            .iter()
            .find(|piece| piece.piece_index == piece_index)
            .cloned()
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        let current_piece_bytes_written = piece_snapshot.bytes_written;
        let expected_start = piece_start + current_piece_bytes_written;
        let expected_end = expected_start + data_len;
        if piece_snapshot.has_block_bitmap()
            || start != expected_start
            || end != expected_end
            || end > piece_end
        {
            // WHY: live peers can send a later requested OP_REQUESTPARTS block
            // before the current prefix. MFC accepts any received range covered
            // by a pending request and writes it at the absolute file offset, so
            // preserve that data instead of dropping the session on ordering.
            let outcome = self
                .append_requested_block_by_bitmap_unlocked(
                    &mut manifest,
                    file_hash,
                    piece_index,
                    piece_start,
                    expected_piece_len,
                    start,
                    end,
                    data,
                    block_received_at,
                )
                .await?;
            return Ok((outcome, manifest));
        }

        let mut file = self.take_payload_handle(file_hash).await?;
        use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
        file.seek(std::io::SeekFrom::Start(start)).await?;
        file.write_all(data).await?;

        let next_piece_bytes_written = current_piece_bytes_written + data_len;
        let mut outcome = PieceWriteOutcome::Incomplete;
        let mut checkpoint_reason = None;
        if next_piece_bytes_written == expected_piece_len {
            // Piece-complete boundary: fsync the payload to disk (not just a
            // userspace flush) BEFORE the manifest checkpoint commit below marks
            // it Verified, so a durable "Verified" manifest state can never
            // outrace the on-disk bytes on an OS crash / power loss (matches
            // eMule, which fsyncs the .part file on flush). This is the only
            // per-piece fsync; mid-piece blocks stay flush()-only for speed.
            file.sync_all().await?;
            let mut piece_bytes = vec![0u8; usize::try_from(expected_piece_len).unwrap_or(0)];
            file.seek(std::io::SeekFrom::Start(piece_start)).await?;
            file.read_exact(&mut piece_bytes).await?;
            self.store_payload_handle(file_hash, file);
            let verified = verify_piece_against_manifest(&manifest, piece_index, &piece_bytes)?;
            let piece = manifest
                .pieces
                .iter_mut()
                .find(|piece| piece.piece_index == piece_index)
                .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
            if verified {
                piece.bytes_written = expected_piece_len;
                piece.state = Ed2kTransferState::Verified;
                piece.ich_corrupted = false;
                outcome = PieceWriteOutcome::Verified;
                checkpoint_reason = Some("piece_verified");
                // Credit every recorded sender of this part in the corruption
                // blackbox (oracle MD4 part success ->
                // `m_CorruptionBlackBox.VerifiedData`, PartFile.cpp:5205).
                self.cbb_record_verified_data(file_hash, piece_start, piece_end);
            } else {
                // MD4 failure alone never bans: the part is gapped for
                // re-download and the caller solicits AICH recovery
                // (PartFile.cpp:5184-5199); ban attribution is the AICH-verdict
                // `EvaluateData` path. The on-disk bytes are RETAINED (the gap
                // is logical only) and the part is flagged for MD4-only ICH
                // salvage so overlaying replacement data can re-verify it
                // early (oracle corrupted_list add, PartFile.cpp:5188-5190).
                piece.state = Ed2kTransferState::Missing;
                piece.bytes_written = 0;
                piece.ich_corrupted = true;
                outcome = PieceWriteOutcome::VerificationFailed {
                    part_index: piece_index,
                };
                checkpoint_reason = Some("piece_verification_failed");
            }
            rebuild_verified_ranges(&mut manifest);
            manifest.completed = manifest.is_fully_verified();
            if manifest.completed {
                refresh_completed_manifest_aich_hashset(
                    &self.transfer_dir(manifest.file_hash.as_str()),
                    &mut manifest,
                )?;
                // No further appends will come: release the cached write
                // handle so a completed payload holds no open handle.
                self.invalidate_payload_handle(file_hash);
            }
            if outcome.is_completed() {
                self.upsert_verified_catalog_entry(&manifest).await;
            }
        } else {
            let ich_candidate = {
                let piece = manifest
                    .pieces
                    .iter_mut()
                    .find(|piece| piece.piece_index == piece_index)
                    .with_context(|| {
                        format!("missing piece index {piece_index} in {file_hash}")
                    })?;
                piece.bytes_written = next_piece_bytes_written;
                piece.state = Ed2kTransferState::Requested;
                piece.ich_corrupted
            };
            // MD4-only ICH fallback: a flush that touched a corrupted part
            // re-runs the part MD4 check over the overlaid prefix plus the
            // retained stale remainder, salvaging the gap early when it now
            // matches (oracle FlushBuffer ICH branch, PartFile.cpp:5214-5232).
            if ich_candidate {
                // Drain the write handle so the just-written bytes are
                // visible to the re-hash read handle.
                file.flush().await?;
                match self
                    .ich_try_rehash_part_unlocked(&mut manifest, piece_index)
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

            let should_checkpoint = checkpoint_reason.is_some()
                || self.should_checkpoint_manifest_unlocked(&manifest).await;
            if should_checkpoint {
                // A pure progress checkpoint (no state transition) only dirties
                // this piece's row, so it takes the single-piece UPDATE instead
                // of the full child-table rewrite; ICH salvage promoted the
                // piece (verified ranges / completion changed) and keeps the
                // full store.
                let progress_only = checkpoint_reason.is_none();
                if progress_only {
                    checkpoint_reason = Some("periodic_progress");
                }
                file.flush().await?;
                self.store_payload_handle(file_hash, file);
                if progress_only {
                    self.store_manifest_piece_progress_unlocked(&manifest, piece_index)
                        .await?;
                } else {
                    self.store_manifest_unlocked(&manifest).await?;
                }
                log_append_piece_block(AppendPieceBlockLog {
                    manifest: &manifest,
                    piece_index,
                    start,
                    end,
                    block_received_at,
                    should_checkpoint,
                    checkpoint_reason,
                });
                return Ok((outcome, manifest));
            }

            self.store_payload_handle(file_hash, file);
            self.note_dirty_piece_unlocked(&manifest, piece_index).await;
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
            return Ok((outcome, manifest));
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
        Ok((outcome, manifest))
    }

    /// Append a block and return the refreshed manifest snapshot used by
    /// downloader orchestration after a persistence boundary. Returns the
    /// manifest the append already holds instead of re-locking and re-cloning
    /// it from the cache per block.
    pub(crate) async fn append_piece_block_with_manifest(
        &self,
        file_hash: &str,
        piece_index: u32,
        start: u64,
        end: u64,
        data: &[u8],
    ) -> Result<(PieceWriteOutcome, Ed2kResumeManifest)> {
        self.append_piece_block_inner(file_hash, piece_index, start, end, data)
            .await
    }

    /// Read a fully verified range for upload serving.
    pub async fn read_verified_range(
        &self,
        file_hash: &Ed2kHash,
        start: u64,
        end: u64,
    ) -> Result<Option<Vec<u8>>> {
        let Some(mut reader) = self.open_verified_range_reader(file_hash).await? else {
            return Ok(None);
        };
        reader.read_range(start, end).await
    }

    pub(crate) async fn open_verified_range_reader(
        &self,
        file_hash: &Ed2kHash,
    ) -> Result<Option<Ed2kVerifiedRangeReader>> {
        let hash_hex = file_hash.to_string();
        // Read the manifest geometry (verified-range check + payload path) under
        // the per-file manifest lock, then drop it before touching the payload, so
        // the file open/seek/read does not hold the lock and serialize concurrent
        // uploads/downloads against each other (FIX B4b).
        let (payload_path, verified_ranges) = {
            let _guard = self.lock_manifest(&hash_hex).await;
            let manifest = self.load_manifest_unlocked(&hash_hex).await?;
            if manifest.verified_ranges.is_empty() {
                return Ok(None);
            }
            // Share-in-place: serve upload bytes straight from the original
            // on-disk file (never copied into the piece store). A real download
            // reads from the internal piece store.
            let payload_path: PathBuf = match manifest.source_path.as_deref() {
                Some(source_path) => long_path(std::path::Path::new(source_path)),
                None => self.transfer_dir(&hash_hex).join(PAYLOAD_FILE_NAME),
            };
            (payload_path, manifest.verified_ranges.clone())
        };
        let file = tokio::fs::OpenOptions::new()
            .read(true)
            .open(&payload_path)
            .await
            .with_context(|| format!("failed to open piece store {}", payload_path.display()))?;
        Ok(Some(Ed2kVerifiedRangeReader {
            file,
            verified_ranges,
            cache_start: 0,
            cache: Vec::new(),
            cache_hit_count: 0,
            cache_miss_count: 0,
            disk_read_bytes: 0,
            #[cfg(test)]
            disk_read_count: 0,
        }))
    }
}

pub(super) struct AppendPieceBlockLog<'a> {
    pub(super) manifest: &'a Ed2kResumeManifest,
    pub(super) piece_index: u32,
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) block_received_at: Instant,
    pub(super) should_checkpoint: bool,
    pub(super) checkpoint_reason: Option<&'static str>,
}

pub(super) fn log_append_piece_block(event: AppendPieceBlockLog<'_>) {
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
