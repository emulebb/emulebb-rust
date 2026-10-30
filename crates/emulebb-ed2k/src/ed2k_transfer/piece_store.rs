//! Piece claim, persistence, and verified-range IO for ED2K transfers.

use std::{collections::BTreeSet, path::PathBuf, time::Instant};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::NativeFileFingerprint;
use md4::{Digest, Md4};
use tracing::{debug, warn};

use crate::long_path::long_path;

use super::ich_salvage::IchRehashResult;
use super::manifest::{rebuild_verified_ranges, verify_piece_against_manifest};
use super::{
    ED2K_EMBLOCK_SIZE, Ed2kResumeManifest, Ed2kSharedRange, Ed2kTransferRuntime, Ed2kTransferState,
    PAYLOAD_FILE_NAME, PieceWriteOutcome, expected_piece_length,
};

const UPLOAD_READ_AHEAD_BYTES: u64 = ED2K_EMBLOCK_SIZE * 3;

struct IncompletePayloadAuthority {
    file_hash: String,
    file_size: u64,
    piece_size: u64,
    part_hashes: Vec<[u8; 16]>,
}

impl IncompletePayloadAuthority {
    fn from_manifest(manifest: &Ed2kResumeManifest) -> Result<Self> {
        anyhow::ensure!(
            manifest.md4_hashset_acquired,
            "incomplete ED2K payload has verified ranges without an MD4 hashset"
        );
        let part_hashes = if manifest.md4_hashset.is_empty() {
            vec![
                manifest
                    .file_hash
                    .parse::<Ed2kHash>()
                    .with_context(|| format!("invalid ED2K file hash {}", manifest.file_hash))?
                    .0,
            ]
        } else {
            manifest
                .md4_hashset
                .iter()
                .map(|hash| {
                    let bytes = hex::decode(hash)
                        .with_context(|| format!("invalid stored MD4 hashset entry {hash}"))?;
                    bytes
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("stored MD4 hashset entry has wrong length"))
                })
                .collect::<Result<Vec<_>>>()?
        };
        Ok(Self {
            file_hash: manifest.file_hash.clone(),
            file_size: manifest.file_size,
            piece_size: manifest.piece_size,
            part_hashes,
        })
    }
}

#[derive(Debug)]
pub(super) struct Ed2kIncompletePayloadFailure {
    pub(super) file_hash: String,
    pub(super) piece_index: Option<u32>,
    pub(super) reason: String,
}

impl std::fmt::Display for Ed2kIncompletePayloadFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.piece_index {
            Some(piece_index) => write!(
                formatter,
                "verified ED2K part {piece_index} {}",
                self.reason
            ),
            None => write!(formatter, "verified ED2K payload {}", self.reason),
        }
    }
}

impl std::error::Error for Ed2kIncompletePayloadFailure {}

#[derive(Clone)]
enum VerifiedPayloadAuthority {
    ManagedIncomplete,
    ManagedCompleted {
        expected: Option<NativeFileFingerprint>,
    },
    ManifestSource {
        path: PathBuf,
        expected: Option<NativeFileFingerprint>,
    },
    SharedFallback {
        path: PathBuf,
        expected: NativeFileFingerprint,
    },
}

impl VerifiedPayloadAuthority {
    fn expected_fingerprint(&self) -> Option<&NativeFileFingerprint> {
        match self {
            Self::ManagedIncomplete => None,
            Self::ManagedCompleted { expected } | Self::ManifestSource { expected, .. } => {
                expected.as_ref()
            }
            Self::SharedFallback { expected, .. } => Some(expected),
        }
    }

    const fn requires_fingerprint(&self) -> bool {
        !matches!(self, Self::ManagedIncomplete)
    }

    const fn label(&self) -> &'static str {
        match self {
            Self::ManagedIncomplete => "managed_incomplete",
            Self::ManagedCompleted { .. } => "managed_completed",
            Self::ManifestSource { .. } => "manifest_source",
            Self::SharedFallback { .. } => "shared_fallback",
        }
    }
}

/// Verified upload reader for one local file.
///
/// Holds a single open payload handle plus a verified-range snapshot so one
/// `OP_REQUESTPARTS` serve can walk many `EMBLOCKSIZE` fragments without
/// reopening the same file or reloading the manifest for every fragment.
pub(crate) struct Ed2kVerifiedRangeReader {
    file: tokio::fs::File,
    expected_fingerprint: Option<NativeFileFingerprint>,
    incomplete_authority: Option<IncompletePayloadAuthority>,
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
        if self.incomplete_authority.is_some() {
            return self.read_cryptographically_verified_range(start, end).await;
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
        if let Err(error) = self.ensure_payload_identity_unchanged().await {
            self.cache.clear();
            return Err(error);
        }
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

    async fn read_cryptographically_verified_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<Option<Vec<u8>>> {
        anyhow::ensure!(end >= start, "invalid descending ED2K upload range");
        if start == end {
            return Ok(Some(Vec::new()));
        }
        let (file_size, piece_size) = {
            let authority = self
                .incomplete_authority
                .as_ref()
                .context("missing incomplete ED2K payload authority")?;
            (authority.file_size, authority.piece_size)
        };
        anyhow::ensure!(
            piece_size != 0,
            "incomplete ED2K payload has zero piece size"
        );

        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let first_piece = start / piece_size;
        let last_piece = end.saturating_sub(1) / piece_size;
        let mut response = Vec::with_capacity(usize::try_from(end - start).unwrap_or(0));
        for piece_index in first_piece..=last_piece {
            let piece_index = u32::try_from(piece_index)
                .context("ED2K part index exceeds the supported range")?;
            let part_hash_index = usize::try_from(piece_index)
                .context("ED2K part index does not fit this platform")?;
            let expected_hash = *self
                .incomplete_authority
                .as_ref()
                .and_then(|authority| authority.part_hashes.get(part_hash_index))
                .with_context(|| format!("missing MD4 hashset entry for part {piece_index}"))?;
            let piece_start = u64::from(piece_index).saturating_mul(piece_size);
            let piece_len = expected_piece_length(file_size, piece_size, u64::from(piece_index));
            anyhow::ensure!(piece_len != 0, "invalid empty ED2K part {piece_index}");
            let piece_end = piece_start.saturating_add(piece_len);
            let mut piece_bytes = vec![0u8; usize::try_from(piece_len).unwrap_or(0)];
            self.file
                .seek(std::io::SeekFrom::Start(piece_start))
                .await
                .map_err(|error| Ed2kIncompletePayloadFailure {
                    file_hash: self
                        .incomplete_authority
                        .as_ref()
                        .map(|authority| authority.file_hash.clone())
                        .unwrap_or_default(),
                    piece_index: Some(piece_index),
                    reason: format!("could not seek before upload serving: {error}"),
                })?;
            self.file
                .read_exact(&mut piece_bytes)
                .await
                .map_err(|error| Ed2kIncompletePayloadFailure {
                    file_hash: self
                        .incomplete_authority
                        .as_ref()
                        .map(|authority| authority.file_hash.clone())
                        .unwrap_or_default(),
                    piece_index: Some(piece_index),
                    reason: format!("could not be read for upload serving: {error}"),
                })?;
            // The contiguous partfile is mutable while later parts download, so
            // file-wide timestamps cannot authorize its already-verified ranges.
            // Snapshot and hash the whole requested part instead: the returned
            // bytes then come from the exact buffer whose MD4 was accepted.
            let (piece_bytes, digest) = tokio::task::spawn_blocking(move || {
                let digest: [u8; 16] = Md4::digest(&piece_bytes).into();
                (piece_bytes, digest)
            })
            .await
            .context("ED2K verified upload part hash task panicked")?;
            if digest != expected_hash {
                self.cache.clear();
                let file_hash = self
                    .incomplete_authority
                    .as_ref()
                    .context("missing incomplete ED2K payload authority")?
                    .file_hash
                    .clone();
                return Err(Ed2kIncompletePayloadFailure {
                    file_hash,
                    piece_index: Some(piece_index),
                    reason: "changed before upload serving".to_string(),
                }
                .into());
            }

            let copy_start = start.max(piece_start).saturating_sub(piece_start);
            let copy_end = end.min(piece_end).saturating_sub(piece_start);
            let copy_start = usize::try_from(copy_start)
                .context("ED2K upload range start does not fit this platform")?;
            let copy_end = usize::try_from(copy_end)
                .context("ED2K upload range end does not fit this platform")?;
            response.extend_from_slice(
                piece_bytes
                    .get(copy_start..copy_end)
                    .context("ED2K upload range exceeds its verified part")?,
            );
            self.cache_start = piece_start;
            self.cache = piece_bytes;
            self.disk_read_bytes = self.disk_read_bytes.saturating_add(piece_len);
            #[cfg(test)]
            {
                self.disk_read_count = self.disk_read_count.saturating_add(1);
            }
        }
        self.cache_miss_count = self.cache_miss_count.saturating_add(1);
        Ok(Some(response))
    }

    async fn ensure_payload_identity_unchanged(&self) -> Result<()> {
        #[cfg(unix)]
        if let Some(expected) = self.expected_fingerprint.as_ref() {
            let metadata = self
                .file
                .metadata()
                .await
                .context("failed to re-inspect verified ED2K upload payload")?;
            let current = super::ingest::native_file_fingerprint_from_unix_metadata(&metadata)
                .context("verified ED2K upload payload lost regular-file identity")?;
            anyhow::ensure!(
                expected == &current,
                "verified ED2K upload payload changed while being read"
            );
        }
        Ok(())
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

    /// Requeue legacy persisted transient piece states after a downloader restart.
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
            if matches!(
                piece.state,
                Ed2kTransferState::Requested | Ed2kTransferState::Written
            ) {
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
        self.final_recheck_transfer(file_hash).await
    }

    /// Persist one downloaded piece into the local piece store.
    pub async fn store_piece_data(
        &self,
        file_hash: &str,
        piece_index: u32,
        data: &[u8],
    ) -> Result<()> {
        self.store_piece_data_unfinalized(file_hash, piece_index, data)
            .await?;
        if self.manifest(file_hash).await?.final_rehash_pending {
            self.finalize_pending_transfer(file_hash).await?;
        }
        Ok(())
    }

    pub(super) async fn store_piece_data_unfinalized(
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
        super::mark_final_rehash_pending(&mut manifest);
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
        let (outcome, manifest) = self
            .append_piece_block_inner(file_hash, piece_index, start, end, data)
            .await?;
        if manifest.final_rehash_pending {
            self.finalize_pending_transfer(file_hash).await?;
        }
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
            if super::mark_final_rehash_pending(&mut manifest) {
                // No further appends will come: release the cached write
                // handle before the final whole-file reader opens the payload.
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
                    .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
                piece.bytes_written = next_piece_bytes_written;
                piece.state = Ed2kTransferState::Missing;
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
        let (outcome, mut manifest) = self
            .append_piece_block_inner(file_hash, piece_index, start, end, data)
            .await?;
        if manifest.final_rehash_pending {
            self.finalize_pending_transfer(file_hash).await?;
            manifest = self.manifest(file_hash).await?;
        }
        Ok((outcome, manifest))
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
        self.read_verified_range_with_reader(&mut reader, start, end, UPLOAD_READ_AHEAD_BYTES)
            .await
    }

    pub(crate) async fn read_verified_range_with_reader(
        &self,
        reader: &mut Ed2kVerifiedRangeReader,
        start: u64,
        end: u64,
        read_ahead_bytes: u64,
    ) -> Result<Option<Vec<u8>>> {
        match reader
            .read_range_with_read_ahead(start, end, read_ahead_bytes)
            .await
        {
            Ok(result) => Ok(result),
            Err(error) => {
                self.reconcile_verified_read_error(&error).await?;
                Err(error)
            }
        }
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
        let (payload_path, verified_ranges, authority, incomplete_authority) = {
            let _guard = self.lock_manifest(&hash_hex).await;
            let manifest = self.load_manifest_unlocked(&hash_hex).await?;
            // Share-in-place: serve upload bytes straight from the original
            // on-disk file (never copied into the piece store). A real download
            // reads from the internal piece store.
            match manifest.source_path.as_deref() {
                Some(source_path) => {
                    let payload_path = long_path(source_path);
                    let authority = VerifiedPayloadAuthority::ManifestSource {
                        path: payload_path.clone(),
                        expected: manifest.source_fingerprint.clone(),
                    };
                    (
                        payload_path,
                        manifest.verified_ranges.clone(),
                        authority,
                        None,
                    )
                }
                None if !manifest.verified_ranges.is_empty() => {
                    let (authority, incomplete_authority) = if manifest.completed {
                        (
                            VerifiedPayloadAuthority::ManagedCompleted {
                                expected: manifest.payload_fingerprint.clone(),
                            },
                            None,
                        )
                    } else {
                        (
                            VerifiedPayloadAuthority::ManagedIncomplete,
                            Some(IncompletePayloadAuthority::from_manifest(&manifest)?),
                        )
                    };
                    (
                        self.transfer_dir(&hash_hex).join(PAYLOAD_FILE_NAME),
                        manifest.verified_ranges.clone(),
                        authority,
                        incomplete_authority,
                    )
                }
                None => match self.first_present_shared_source(&hash_hex).await? {
                    Some(source) => {
                        let path = source.path;
                        (
                            path.clone(),
                            vec![Ed2kSharedRange {
                                start: 0,
                                end: manifest.file_size,
                            }],
                            VerifiedPayloadAuthority::SharedFallback {
                                path,
                                expected: source.fingerprint,
                            },
                            None,
                        )
                    }
                    None => return Ok(None),
                },
            }
        };

        if authority.requires_fingerprint() && authority.expected_fingerprint().is_none() {
            warn!(
                file_hash = hash_hex,
                path = %payload_path.display(),
                authority = authority.label(),
                "withdrawing verified ED2K payload without reusable file identity"
            );
            self.withdraw_untrusted_verified_payload(&hash_hex, &authority)
                .await?;
            return Ok(None);
        }

        let open_path = payload_path.clone();
        let expected_fingerprint = authority.expected_fingerprint().cloned();
        let stable_open = authority.requires_fingerprint();
        let opened = tokio::task::spawn_blocking(move || -> Result<std::fs::File> {
            let file = if stable_open {
                super::ingest::open_stable_read_file_without_follow(&open_path)
            } else {
                super::ingest::open_regular_file_without_follow(&open_path)
            }
            .with_context(|| format!("failed to open piece store {}", open_path.display()))?;
            let metadata = file.metadata().with_context(|| {
                format!("failed to inspect piece store {}", open_path.display())
            })?;
            anyhow::ensure!(
                metadata.file_type().is_file(),
                "piece store is not a regular file: {}",
                open_path.display()
            );
            if let Some(expected) = expected_fingerprint.as_ref() {
                let current = super::ingest::native_file_fingerprint_from_handle(&file, &metadata)
                    .with_context(|| {
                        format!(
                            "failed to identify verified ED2K payload {}",
                            open_path.display()
                        )
                    })?;
                anyhow::ensure!(
                    expected.safely_matches(&current),
                    "verified ED2K payload changed before upload: {}",
                    open_path.display()
                );
            }
            Ok(file)
        })
        .await
        .context("ED2K verified payload open task panicked")?;
        let file = match opened {
            Ok(file) => tokio::fs::File::from_std(file),
            Err(error) if authority.requires_fingerprint() => {
                warn!(
                    %error,
                    file_hash = hash_hex,
                    path = %payload_path.display(),
                    authority = authority.label(),
                    "withdrawing changed or unavailable verified ED2K payload"
                );
                self.withdraw_untrusted_verified_payload(&hash_hex, &authority)
                    .await?;
                return Ok(None);
            }
            Err(error) if matches!(authority, VerifiedPayloadAuthority::ManagedIncomplete) => {
                warn!(
                    %error,
                    file_hash = hash_hex,
                    path = %payload_path.display(),
                    "withdrawing unavailable incomplete ED2K payload"
                );
                self.reconcile_incomplete_payload_failure(&Ed2kIncompletePayloadFailure {
                    file_hash: hash_hex,
                    piece_index: None,
                    reason: format!("could not be opened for upload serving: {error}"),
                })
                .await?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        Ok(Some(Ed2kVerifiedRangeReader {
            file,
            expected_fingerprint: authority.expected_fingerprint().cloned(),
            incomplete_authority,
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

    async fn withdraw_untrusted_verified_payload(
        &self,
        file_hash: &str,
        authority: &VerifiedPayloadAuthority,
    ) -> Result<()> {
        match authority {
            VerifiedPayloadAuthority::ManagedIncomplete => Ok(()),
            VerifiedPayloadAuthority::ManifestSource { path, expected } => {
                let _lifecycle_guard = self.lock_lifecycle(file_hash).await;
                let _manifest_guard = self.lock_manifest(file_hash).await;
                let mut manifest = self.load_manifest_unlocked(file_hash).await?;
                if manifest.source_path.as_deref() != Some(path.as_path())
                    || manifest.source_fingerprint.as_ref() != expected.as_ref()
                {
                    return Ok(());
                }
                let invalidated = manifest.source_fingerprint.take().is_some();
                self.store_manifest_unlocked(&manifest).await?;
                self.upsert_verified_catalog_entry(&manifest).await;
                if invalidated {
                    self.queue_shared_source_invalidation(file_hash, path);
                }
                Ok(())
            }
            VerifiedPayloadAuthority::ManagedCompleted { expected } => {
                let _lifecycle_guard = self.lock_lifecycle(file_hash).await;
                let _manifest_guard = self.lock_manifest(file_hash).await;
                let mut manifest = self.load_manifest_unlocked(file_hash).await?;
                if manifest.source_path.is_some()
                    || !manifest.completed
                    || manifest.payload_fingerprint.as_ref() != expected.as_ref()
                {
                    return Ok(());
                }
                manifest.completed = false;
                manifest.final_rehash_pending = true;
                manifest.payload_fingerprint = None;
                self.invalidate_payload_handle(file_hash);
                self.store_manifest_unlocked(&manifest).await?;
                self.upsert_verified_catalog_entry(&manifest).await;
                Ok(())
            }
            VerifiedPayloadAuthority::SharedFallback { path, expected } => {
                let _lifecycle_guard = self.lock_lifecycle(file_hash).await;
                let _manifest_guard = self.lock_manifest(file_hash).await;
                let invalidated = self
                    .metadata
                    .invalidate_shared_file_source(file_hash, path, expected)?;
                if self.first_present_shared_source(file_hash).await?.is_none() {
                    self.remove_verified_catalog_entry(file_hash).await;
                }
                if invalidated {
                    self.queue_shared_source_invalidation(file_hash, path);
                }
                Ok(())
            }
        }
    }

    async fn reconcile_verified_read_error(&self, error: &anyhow::Error) -> Result<()> {
        let Some(failure) = error.downcast_ref::<Ed2kIncompletePayloadFailure>() else {
            return Ok(());
        };
        self.reconcile_incomplete_payload_failure(failure).await
    }

    pub(super) async fn reconcile_incomplete_payload_failure(
        &self,
        failure: &Ed2kIncompletePayloadFailure,
    ) -> Result<()> {
        let _lifecycle_guard = self.lock_lifecycle(&failure.file_hash).await;
        let _manifest_guard = self.lock_manifest(&failure.file_hash).await;
        let mut manifest = self.load_manifest_unlocked(&failure.file_hash).await?;
        if manifest.source_path.is_some() || manifest.completed || manifest.final_rehash_pending {
            return Ok(());
        }
        self.invalidate_payload_handle(&failure.file_hash);

        let mut damaged_pieces = BTreeSet::new();
        if let Some(piece_index) = failure.piece_index {
            let Some(piece) = manifest
                .pieces
                .iter()
                .find(|piece| piece.piece_index == piece_index)
            else {
                return Ok(());
            };
            if piece.state != Ed2kTransferState::Verified {
                return Ok(());
            }
            // The reader drops the manifest lock while doing disk IO. A
            // downloader may have repaired this part before reconciliation
            // acquired the lock, so confirm the current path still fails.
            if self
                .current_incomplete_part_matches(&manifest, piece_index)
                .await?
            {
                return Ok(());
            }
            damaged_pieces.insert(piece_index);
        } else {
            let verified_pieces = manifest
                .pieces
                .iter()
                .filter(|piece| piece.state == Ed2kTransferState::Verified)
                .map(|piece| piece.piece_index)
                .collect::<Vec<_>>();
            for piece_index in verified_pieces {
                if !self
                    .current_incomplete_part_matches(&manifest, piece_index)
                    .await?
                {
                    damaged_pieces.insert(piece_index);
                }
            }
        }
        if damaged_pieces.is_empty() {
            return Ok(());
        }
        let ich_corrupted = failure.piece_index.is_some();
        for piece in &mut manifest.pieces {
            if damaged_pieces.contains(&piece.piece_index) {
                piece.state = Ed2kTransferState::Missing;
                piece.bytes_written = 0;
                piece.block_bitmap = None;
                piece.ich_corrupted = ich_corrupted;
            }
        }
        rebuild_verified_ranges(&mut manifest);
        self.store_manifest_unlocked(&manifest).await?;
        self.upsert_verified_catalog_entry(&manifest).await;
        warn!(
            file_hash = failure.file_hash,
            damaged_pieces = ?damaged_pieces,
            reason = failure.reason,
            "requeued ED2K parts after upload-time payload authority failure"
        );
        Ok(())
    }

    async fn current_incomplete_part_matches(
        &self,
        manifest: &Ed2kResumeManifest,
        piece_index: u32,
    ) -> Result<bool> {
        let authority = IncompletePayloadAuthority::from_manifest(manifest)?;
        let part_hash_index =
            usize::try_from(piece_index).context("ED2K part index does not fit this platform")?;
        let expected_hash = *authority
            .part_hashes
            .get(part_hash_index)
            .with_context(|| format!("missing MD4 hashset entry for part {piece_index}"))?;
        let piece_start = u64::from(piece_index).saturating_mul(authority.piece_size);
        let piece_len = expected_piece_length(
            authority.file_size,
            authority.piece_size,
            u64::from(piece_index),
        );
        let payload_path = self
            .transfer_dir(&manifest.file_hash)
            .join(PAYLOAD_FILE_NAME);
        tokio::task::spawn_blocking(move || -> Result<bool> {
            use std::io::{Read, Seek};

            let mut file = match super::ingest::open_regular_file_without_follow(&payload_path) {
                Ok(file) => file,
                Err(_) => return Ok(false),
            };
            if file.seek(std::io::SeekFrom::Start(piece_start)).is_err() {
                return Ok(false);
            }
            let mut bytes = vec![0u8; usize::try_from(piece_len).unwrap_or(0)];
            if file.read_exact(&mut bytes).is_err() {
                return Ok(false);
            }
            let digest: [u8; 16] = Md4::digest(&bytes).into();
            Ok(digest == expected_hash)
        })
        .await
        .context("ED2K upload failure reconciliation hash task panicked")?
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
