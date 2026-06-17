//! Serializable ED2K transfer data models.

use serde::{Deserialize, Serialize};

use super::block_bitmap::PartBlockBitmap;
use super::{Ed2kSharedRange, manifest::piece_count};

/// One persisted ED2K transfer job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kTransferJob {
    /// ED2K file hash in lowercase hex.
    pub file_hash: String,
    /// Canonical file name.
    pub canonical_name: String,
    /// Target file size.
    pub file_size: u64,
    /// Piece size used by the local piece store.
    pub piece_size: u64,
}

/// Coarse piece lifecycle tracked in the resume manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ed2kTransferState {
    Missing,
    Requested,
    Written,
    Verified,
}

/// Result of writing the final block of a part into the piece store.
///
/// Surfaces an MD4 verification failure to the download session so it can
/// solicit AICH/ICH block-level recovery (master `CPartFile::HashSinglePart`
/// failure path -> `RequestAICHRecovery`) instead of silently re-downloading
/// the whole part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PieceWriteOutcome {
    /// The part is not yet fully written, or a non-final block landed.
    Incomplete,
    /// The full part was written and MD4-verified.
    Verified,
    /// The full part was written but failed MD4 verification. Carries the part
    /// index so the session can request AICH recovery for it.
    VerificationFailed { part_index: u32 },
}

impl PieceWriteOutcome {
    /// `true` when the part is now complete and verified (legacy `bool` form).
    #[must_use]
    pub(crate) fn is_completed(self) -> bool {
        matches!(self, PieceWriteOutcome::Verified)
    }

    /// The part index whose MD4 verification just failed, if any.
    #[must_use]
    pub(crate) fn verification_failed_part(self) -> Option<u32> {
        match self {
            PieceWriteOutcome::VerificationFailed { part_index } => Some(part_index),
            _ => None,
        }
    }
}

/// One claimed download piece plus the already persisted byte prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ed2kClaimedPart {
    /// Piece index inside the resume manifest.
    pub piece_index: u32,
    /// Number of contiguous bytes already persisted for this piece.
    pub bytes_written: u64,
}

/// Per-piece status tracked by the resume manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kPieceState {
    /// Piece index inside the piece store.
    pub piece_index: u32,
    /// Current lifecycle state for the piece.
    pub state: Ed2kTransferState,
    /// Last persisted byte count written into the piece store for this piece.
    ///
    /// For a contiguous download this is the written prefix length. For a part
    /// undergoing ICH block-level salvage this tracks the contiguous prefix of
    /// present blocks; the authoritative non-contiguous presence set lives in
    /// `block_bitmap`.
    pub bytes_written: u64,
    /// Lowercase-hex packed block presence bitmap at `EMBLOCKSIZE` granularity
    /// within the part. `None` (or absent on disk) means "all present blocks are
    /// the contiguous prefix up to `bytes_written`", preserving resume-manifest
    /// backward compatibility for manifests written before block-level salvage.
    #[serde(default)]
    pub block_bitmap: Option<String>,
}

impl Ed2kPieceState {
    /// Resolve the effective per-part block presence bitmap for a part of
    /// `part_len` bytes.
    ///
    /// When a bitmap was persisted it is decoded; otherwise (legacy manifest or
    /// the contiguous fast path) the bitmap is derived from `bytes_written` as a
    /// contiguous prefix of whole blocks. A persisted bitmap with a stale length
    /// also falls back to the contiguous-prefix derivation, preserving
    /// resume-manifest backward compatibility.
    pub(super) fn resolve_block_bitmap(&self, part_len: u64) -> PartBlockBitmap {
        match self.block_bitmap.as_deref() {
            Some(hex) => PartBlockBitmap::from_hex(part_len, hex).unwrap_or_else(|| {
                PartBlockBitmap::contiguous_prefix(part_len, self.bytes_written)
            }),
            None => PartBlockBitmap::contiguous_prefix(part_len, self.bytes_written),
        }
    }

    /// Whether this part is mid ICH salvage (a non-contiguous block bitmap is
    /// persisted). Used by the download window to switch to gap-aware
    /// re-requesting.
    pub(crate) fn has_block_bitmap(&self) -> bool {
        self.block_bitmap.is_some()
    }

    /// For a part of `part_len` bytes, return `Some(block_end_rel)` when the
    /// block containing relative offset `rel_offset` is already present (so the
    /// download window can skip it), or `None` when it is missing/needed.
    /// `block_end_rel` is the part-relative end offset of that present block.
    pub(crate) fn present_block_end(&self, part_len: u64, rel_offset: u64) -> Option<u64> {
        let bitmap = self.resolve_block_bitmap(part_len);
        let idx = usize::try_from(rel_offset / super::ED2K_EMBLOCK_SIZE).ok()?;
        if bitmap.is_present(idx) {
            let (_s, e) = bitmap.block_range(idx);
            Some(e)
        } else {
            None
        }
    }

    /// Persist `bitmap` into this piece and refresh `bytes_written` to the
    /// contiguous present prefix. The bitmap is dropped (set to `None`) when it
    /// is a clean contiguous prefix so the legacy/fast path representation is
    /// kept whenever block-level tracking is not needed.
    pub(super) fn apply_block_bitmap(&mut self, bitmap: &PartBlockBitmap) {
        let prefix = bitmap.contiguous_prefix_bytes();
        self.bytes_written = prefix;
        let is_clean_prefix = bitmap.present_bytes() == prefix;
        self.block_bitmap = if is_clean_prefix {
            None
        } else {
            Some(bitmap.to_hex())
        };
    }
}

/// One source hint remembered across restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kSourceHint {
    /// Remote source IP address.
    pub ip: String,
    /// Remote ED2K TCP port.
    pub tcp_port: u16,
    /// Optional peer user hash when known.
    pub user_hash: Option<String>,
}

/// Canonical AICH master hash plus per-part hashes for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ed2kAichHashset {
    pub master_hash: [u8; 20],
    pub part_hashes: Vec<[u8; 20]>,
}

/// Summary returned after a local payload is ingested into the transfer store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ed2kLocalIngestSummary {
    pub file_hash: String,
    pub canonical_name: String,
    pub file_size: u64,
    pub md4_hashset_count: usize,
    pub aich_root: String,
    pub aich_hashset_count: usize,
    pub transfer_dir: String,
}

/// One pending LowID callback download intent remembered until a peer calls back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kCallbackIntent {
    /// Raw server-reported LowID/client-id used when requesting the callback.
    pub client_id: u32,
    /// File hash in lowercase hex.
    pub file_hash: String,
    /// Canonical file name.
    pub canonical_name: String,
    /// Expected file size.
    pub file_size: u64,
    /// Best-effort source hint captured when the callback was requested.
    pub source: Ed2kSourceHint,
}

/// Durable download resume metadata stored next to the piece payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kResumeManifest {
    /// ED2K file hash in lowercase hex.
    pub file_hash: String,
    /// Canonical file name.
    pub canonical_name: String,
    /// Target file size.
    pub file_size: u64,
    /// Piece size used in the piece store.
    pub piece_size: u64,
    /// Whether the entire local payload has been structurally completed and
    /// verified for upload serving.
    pub completed: bool,
    /// Whether the canonical ED2K MD4 hashset for this file has been learned
    /// and validated against the file hash.
    pub md4_hashset_acquired: bool,
    /// Canonical ED2K MD4 part hashes in lowercase hex. For one-part files this
    /// list is empty and the file hash itself is the verification authority.
    #[serde(default)]
    pub md4_hashset: Vec<String>,
    /// Whether the canonical AICH part-hash set for this file has been
    /// learned or derived locally.
    pub aich_hashset_acquired: bool,
    /// Canonical AICH root in lowercase hex when known.
    pub aich_root: Option<String>,
    /// Canonical AICH per-part hashes in lowercase hex.
    pub aich_hashset: Vec<String>,
    /// Upload-safe verified ranges.
    pub verified_ranges: Vec<Ed2kSharedRange>,
    /// Piece states keyed by piece index.
    pub pieces: Vec<Ed2kPieceState>,
    /// Remembered source hints.
    pub sources: Vec<Ed2kSourceHint>,
    /// Public upload-priority token for shared-file REST metadata.
    #[serde(default = "default_shared_upload_priority")]
    pub upload_priority: String,
    /// Whether upload priority should be automatically managed.
    #[serde(default)]
    pub auto_upload_priority: bool,
    /// Locally configured shared-file comment.
    #[serde(default)]
    pub comment: String,
    /// Locally configured shared-file rating in the public 0..5 range.
    #[serde(default)]
    pub rating: u8,
    /// User-facing transfer control state persisted across restarts.
    #[serde(default)]
    pub control_state: Option<String>,
    /// Whether the completed transfer row was removed without deleting the
    /// local payload or shared-file registration.
    #[serde(default)]
    pub transfer_row_removed: bool,
}

impl Ed2kResumeManifest {
    /// Build an empty manifest for a new transfer.
    #[must_use]
    pub fn new(job: &Ed2kTransferJob) -> Self {
        let piece_count = piece_count(job.file_size, job.piece_size);
        Self {
            file_hash: job.file_hash.clone(),
            canonical_name: job.canonical_name.clone(),
            file_size: job.file_size,
            piece_size: job.piece_size,
            completed: false,
            md4_hashset_acquired: false,
            md4_hashset: Vec::new(),
            aich_hashset_acquired: false,
            aich_root: None,
            aich_hashset: Vec::new(),
            verified_ranges: Vec::new(),
            pieces: (0..piece_count)
                .map(|piece_index| Ed2kPieceState {
                    piece_index,
                    state: Ed2kTransferState::Missing,
                    bytes_written: 0,
                    block_bitmap: None,
                })
                .collect(),
            sources: Vec::new(),
            upload_priority: default_shared_upload_priority(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
            control_state: None,
            transfer_row_removed: false,
        }
    }

    /// Returns true when all expected parts have been individually verified.
    #[must_use]
    pub fn is_fully_verified(&self) -> bool {
        self.pieces
            .iter()
            .all(|piece| piece.state == Ed2kTransferState::Verified)
    }
}

fn default_shared_upload_priority() -> String {
    "normal".to_string()
}
