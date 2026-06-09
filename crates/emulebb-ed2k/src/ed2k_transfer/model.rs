//! Serializable ED2K transfer data models.

use serde::{Deserialize, Serialize};

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
    pub bytes_written: u64,
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
                })
                .collect(),
            sources: Vec::new(),
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
