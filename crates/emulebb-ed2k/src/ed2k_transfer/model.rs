//! Serializable ED2K transfer data models.

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::{
    NativeFileFingerprint, NativeFileIdentity, NativeFileTimestamp, NativePath,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use super::block_bitmap::PartBlockBitmap;
use super::{Ed2kSharedRange, manifest::piece_count};

/// One persisted ED2K transfer job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kTransferJob {
    /// ED2K file hash in lowercase hex.
    pub file_hash: String,
    /// Canonical file name.
    pub display_name: String,
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
    /// A mid-part flush into an ICH-corrupted part re-ran the part MD4 check
    /// and it now matches: the remaining gap was filled from the retained
    /// stale bytes and the part is complete/verified (oracle `FlushBuffer` ICH
    /// branch success, PartFile.cpp:5214-5232). `salvaged_bytes` is the gap
    /// size recovered without re-download (`GetTotalGapSizeInPart`,
    /// PartFile.cpp:5220).
    IchSalvaged {
        part_index: u32,
        salvaged_bytes: u64,
    },
    /// A mid-part flush into an ICH-corrupted part re-ran the part MD4 check
    /// and it still fails: the part stays gapped and re-download continues
    /// (oracle `HashSinglePart` returning false in the ICH branch). Otherwise
    /// identical to `Incomplete`; surfaced so the session can emit the ICH
    /// re-hash attempt diag event.
    IchRehashFailed { part_index: u32 },
}

impl PieceWriteOutcome {
    /// `true` when the part is now complete and verified (legacy `bool` form).
    #[must_use]
    pub(crate) fn is_completed(self) -> bool {
        matches!(
            self,
            PieceWriteOutcome::Verified | PieceWriteOutcome::IchSalvaged { .. }
        )
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
    /// Whether this part previously failed its MD4 flush check and is pending
    /// MD4-only ICH salvage. The stale on-disk bytes are RETAINED (the part is
    /// only logically gapped: `bytes_written` restarts at 0) so replacement
    /// data overlays them and each subsequent flush can re-run the part MD4
    /// check, salvaging the remaining gap early when it now matches (oracle
    /// `corrupted_list` + the `FlushBuffer` ICH branch, PartFile.cpp:5188-5190
    /// and :5214-5232; persisted like `FT_CORRUPTEDPARTS`,
    /// PartFile.cpp:1445-1462). Cleared when the part verifies.
    #[serde(default)]
    pub ich_corrupted: bool,
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
    /// Raw eMule connect-options byte when the discovery path supplied it.
    ///
    /// `None` means the source path did not carry connect options; `Some(0)`
    /// is a real advertised value and must not be conflated with unknown.
    #[serde(default)]
    pub connect_options: Option<u8>,
    /// File comment received from this source via `OP_FILEDESC`.
    #[serde(default)]
    pub file_comment: String,
    /// File rating received from this source via `OP_FILEDESC`.
    #[serde(default)]
    pub file_rating: u8,
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
    pub display_name: String,
    pub file_size: u64,
    pub md4_hashset_count: usize,
    pub aich_root: String,
    pub aich_hashset_count: usize,
    pub transfer_dir: String,
    pub source_path: Option<String>,
}

/// One persisted share-in-place entry used by the incremental shared-directory
/// reload to decide whether a scanned file can be reused without re-hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kReloadIndexEntry {
    /// ED2K file hash of the persisted share (lowercase hex), used to resolve the
    /// reused `LocalShare` without re-hashing the payload.
    pub file_hash: String,
    /// Native file identity, size, and timestamps captured when the hash was
    /// computed. `None` is always a reload miss.
    pub source_fingerprint: Option<NativeFileFingerprint>,
}

/// Opaque process-local identifier for one pending callback ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed2kCallbackTicketId(pub(super) u64);

/// Maximum lifetime accepted for an inbound callback admission ticket.
///
/// Producers should use the same bounded window for their outbound callback
/// dispatch so a queued wire request cannot outlive the admission authority it
/// is meant to activate.
pub const ED2K_CALLBACK_TICKET_MAX_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// Callback transport which was asked to make the peer connect back.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ed2kCallbackRoute {
    /// Classic server callback in one server-local LowID namespace.
    Server { server_endpoint: SocketAddr },
    /// Kad callback relayed through the source's buddy.
    KadBuddy {
        buddy_id: [u8; 16],
        buddy_endpoint: Option<SocketAddr>,
    },
    /// Direct UDP callback sent to the firewalled source itself.
    DirectUdp { source_endpoint: SocketAddr },
}

/// Expected identity of the peer for which a callback was requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ed2kCallbackPeer {
    /// Server-reported client-id. It is only authoritative together with the
    /// server endpoint stored by [`Ed2kCallbackRoute::Server`].
    pub client_id: u32,
    /// Protocol user hash when the discovery route supplied it.
    pub expected_user_hash: Option<[u8; 16]>,
    /// Dialable source IP for hashless non-server compatibility matching.
    /// Server LowID IPv4 renderings must be represented as `None`.
    pub source_ip: Option<Ipv4Addr>,
    /// Peer-advertised ED2K TCP port, never the inbound socket's ephemeral port.
    pub source_tcp_port: u16,
}

/// One file to negotiate after an expected callback peer is admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kCallbackDownload {
    /// Binary ED2K file hash; callback admission never accepts an invalid hex form.
    pub file_hash: Ed2kHash,
    /// Canonical file name.
    pub display_name: String,
    /// Expected file size.
    pub file_size: u64,
    /// Best available source metadata for the download session.
    pub source: Ed2kSourceHint,
}

/// Request used to reserve one bounded, expiring callback ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kCallbackTicketRequest {
    pub(super) route: Ed2kCallbackRoute,
    pub(super) peer: Ed2kCallbackPeer,
    pub(super) download: Ed2kCallbackDownload,
    /// Absolute ticket expiry is computed at reservation time. Merging another
    /// A4AF file does not extend the original callback window.
    pub(super) valid_for: Duration,
}

/// Identity observed on an inbound ED2K HELLO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ed2kCallbackHelloIdentity {
    pub user_hash: [u8; 16],
    pub client_id: u32,
    pub server_endpoint: Option<SocketAddr>,
    pub peer_ip: Option<Ipv4Addr>,
    pub tcp_port: u16,
}

/// Linear authority to finish or cancel one callback dispatch reservation.
#[derive(Debug, PartialEq, Eq)]
pub struct Ed2kCallbackDispatchPermit {
    pub(super) ticket_id: Ed2kCallbackTicketId,
    pub(super) expires_at: std::time::Instant,
}

impl Ed2kCallbackDispatchPermit {
    /// Exact reservation deadline shared with a queued outbound dispatch.
    pub fn expires_at(&self) -> std::time::Instant {
        self.expires_at
    }
}

/// Result of reserving callback work before dispatching the wire request.
#[derive(Debug, PartialEq, Eq)]
pub enum Ed2kCallbackReservation {
    /// This caller owns the network dispatch and must arm or cancel the permit.
    Dispatch(Ed2kCallbackDispatchPermit),
    /// Another caller owns the shared callback dispatch; this A4AF file joined it.
    Joined { ticket_id: Ed2kCallbackTicketId },
}

/// Result of settling a linear callback dispatch permit after the wire send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed2kCallbackDispatchOutcome {
    /// The pending ticket was armed for the expected connect-back.
    Armed,
    /// A fast callback session or expiry already settled this permit's epoch.
    Settled,
}

/// Opaque lease token used to settle an inbound callback admission exactly once.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Ed2kCallbackClaimToken {
    pub(super) ticket_ids: Vec<Ed2kCallbackTicketId>,
    pub(super) generation: u64,
}

/// Files admitted for one callback connection and the token which owns them.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Ed2kCallbackClaim {
    pub token: Ed2kCallbackClaimToken,
    pub downloads: Vec<Ed2kCallbackDownload>,
}

/// Bounded callback-ticket operation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed2kCallbackTicketError {
    ZeroLifetime,
    LifetimeTooLong,
    DeadlineOverflow,
    TicketCapacity,
    DownloadCapacity,
    IdentifierExhausted,
    InvalidServerEndpoint,
    InvalidServerClientId,
    InvalidBuddyId,
    InvalidBuddyEndpoint,
    InvalidDirectEndpoint,
    MissingUserHash,
    ZeroTcpPort,
}

impl std::fmt::Display for Ed2kCallbackTicketError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ZeroLifetime => "callback ticket lifetime must be non-zero",
            Self::LifetimeTooLong => "callback ticket lifetime exceeds the protocol bound",
            Self::DeadlineOverflow => "callback ticket deadline overflow",
            Self::TicketCapacity => "callback ticket capacity reached",
            Self::DownloadCapacity => "callback ticket A4AF capacity reached",
            Self::IdentifierExhausted => "callback ticket identifier space exhausted",
            Self::InvalidServerEndpoint => "callback server endpoint must be non-zero IPv4",
            Self::InvalidServerClientId => "server callback target must be a non-zero LowID",
            Self::InvalidBuddyId => "Kad callback buddy id must be non-zero",
            Self::InvalidBuddyEndpoint => "callback buddy endpoint must be non-zero IPv4",
            Self::InvalidDirectEndpoint => {
                "direct callback endpoint must be non-zero IPv4 and match the source"
            }
            Self::MissingUserHash => "Kad/direct callback requires a non-zero user hash",
            Self::ZeroTcpPort => "callback source TCP port must be non-zero",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for Ed2kCallbackTicketError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ed2kCallbackClaimError {
    AmbiguousPeer,
    ClaimCapacity,
    DeadlineOverflow,
    IdentifierExhausted,
    StaleClaim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ed2kDeliveryState {
    NotApplicable,
    Pending,
    Delivered,
}

/// Durable download resume metadata stored next to the piece payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kResumeManifest {
    /// ED2K file hash in lowercase hex.
    pub file_hash: String,
    /// Canonical file name.
    pub display_name: String,
    /// Target file size.
    pub file_size: u64,
    /// Piece size used in the piece store.
    pub piece_size: u64,
    /// Whether the entire local payload has been structurally completed and
    /// verified for upload serving.
    pub completed: bool,
    /// Whether every part is present but the mandatory whole-file ED2K MD4
    /// completion rehash has not yet succeeded. This is persisted before the
    /// rehash begins so a crash cannot turn individually verified parts into a
    /// deliverable file without the final authority check.
    #[serde(default)]
    pub final_rehash_pending: bool,
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
    /// Download category index, matching eMule's persisted FT_CATEGORY tag.
    #[serde(default)]
    pub category_id: u32,
    /// User-facing transfer control state persisted across restarts.
    #[serde(default)]
    pub control_state: Option<String>,
    /// Whether the completed transfer row was removed without deleting the
    /// local payload or shared-file registration.
    #[serde(default)]
    pub transfer_row_removed: bool,
    /// Explicit lifecycle for materializing a download outside the internal
    /// piece store. Share-in-place files use `NotApplicable`; downloads start
    /// `Pending` and become `Delivered` only with a persisted verified path.
    pub delivery_state: Ed2kDeliveryState,
    /// Absolute path the completed payload was materialized to by its canonical
    /// name (under a category path or the global incoming dir). `None` until the
    /// transfer is delivered; set once so finished-file delivery is idempotent
    /// across restarts (oracle: eMule moves the finished `.part` file into the
    /// Incoming/category folder by name).
    #[serde(default, with = "optional_native_path_serde")]
    pub delivered_path: Option<PathBuf>,
    /// Original on-disk path of a shared, already-complete file seeded IN PLACE
    /// (added via a shared directory, never downloaded). `Some` marks a
    /// share-in-place transfer: its payload is served directly from this path,
    /// never copied into the internal piece store (`transfer_dir/pieces.bin`),
    /// and never delivered to the incoming dir (delivery is download-only).
    /// `None` for a real download whose payload lives in the piece store.
    #[serde(default, with = "optional_native_path_serde")]
    pub source_path: Option<PathBuf>,
    /// Native file identity, size, and nanosecond timestamps captured for the
    /// incremental shared-directory reload. `None` forces a conservative hash.
    #[serde(default, with = "optional_native_file_fingerprint_serde")]
    pub source_fingerprint: Option<NativeFileFingerprint>,
}

mod optional_native_file_fingerprint_serde {
    use super::*;

    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct StoredFingerprint {
        identity: StoredIdentity,
        size_bytes: u64,
        modified: StoredTimestamp,
        changed: Option<StoredTimestamp>,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", tag = "kind")]
    enum StoredIdentity {
        Unix {
            device_id: u64,
            inode_number: u64,
        },
        WindowsLowResolution {
            volume_serial_number: u32,
            file_index: u64,
        },
        WindowsHighResolution {
            volume_serial_number: u64,
            file_id: u128,
        },
    }

    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct StoredTimestamp {
        seconds: i64,
        nanoseconds: u32,
    }

    impl From<&NativeFileFingerprint> for StoredFingerprint {
        fn from(value: &NativeFileFingerprint) -> Self {
            Self {
                identity: match value.identity {
                    NativeFileIdentity::Unix {
                        device_id,
                        inode_number,
                    } => StoredIdentity::Unix {
                        device_id,
                        inode_number,
                    },
                    NativeFileIdentity::WindowsLowResolution {
                        volume_serial_number,
                        file_index,
                    } => StoredIdentity::WindowsLowResolution {
                        volume_serial_number,
                        file_index,
                    },
                    NativeFileIdentity::WindowsHighResolution {
                        volume_serial_number,
                        file_id,
                    } => StoredIdentity::WindowsHighResolution {
                        volume_serial_number,
                        file_id,
                    },
                },
                size_bytes: value.size_bytes,
                modified: StoredTimestamp::from(value.modified),
                changed: value.changed.map(StoredTimestamp::from),
            }
        }
    }

    impl From<NativeFileTimestamp> for StoredTimestamp {
        fn from(value: NativeFileTimestamp) -> Self {
            Self {
                seconds: value.seconds,
                nanoseconds: value.nanoseconds,
            }
        }
    }

    impl StoredFingerprint {
        fn into_native(self) -> Result<NativeFileFingerprint, &'static str> {
            Ok(NativeFileFingerprint {
                identity: match self.identity {
                    StoredIdentity::Unix {
                        device_id,
                        inode_number,
                    } => NativeFileIdentity::Unix {
                        device_id,
                        inode_number,
                    },
                    StoredIdentity::WindowsLowResolution {
                        volume_serial_number,
                        file_index,
                    } => NativeFileIdentity::WindowsLowResolution {
                        volume_serial_number,
                        file_index,
                    },
                    StoredIdentity::WindowsHighResolution {
                        volume_serial_number,
                        file_id,
                    } => NativeFileIdentity::WindowsHighResolution {
                        volume_serial_number,
                        file_id,
                    },
                },
                size_bytes: self.size_bytes,
                modified: self.modified.into_native()?,
                changed: self.changed.map(StoredTimestamp::into_native).transpose()?,
            })
        }
    }

    impl StoredTimestamp {
        fn into_native(self) -> Result<NativeFileTimestamp, &'static str> {
            NativeFileTimestamp::new(self.seconds, self.nanoseconds)
                .ok_or("native file timestamp nanoseconds are out of range")
        }
    }

    pub fn serialize<S>(
        fingerprint: &Option<NativeFileFingerprint>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        fingerprint
            .as_ref()
            .map(StoredFingerprint::from)
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<NativeFileFingerprint>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<StoredFingerprint>::deserialize(deserializer)?
            .map(StoredFingerprint::into_native)
            .transpose()
            .map_err(D::Error::custom)
    }
}

mod optional_native_path_serde {
    use super::*;

    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct StoredNativePath {
        platform: String,
        native_hex: String,
    }

    pub fn serialize<S>(path: &Option<PathBuf>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        path.as_ref()
            .map(|path| {
                let native_path = NativePath::from(path.as_path());
                StoredNativePath {
                    platform: NativePath::platform().to_string(),
                    native_hex: hex::encode(native_path.storage_bytes()),
                }
            })
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<PathBuf>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let stored = Option::<StoredNativePath>::deserialize(deserializer)?;
        stored
            .map(|stored| {
                let native_path = hex::decode(&stored.native_hex).map_err(D::Error::custom)?;
                NativePath::from_storage(&stored.platform, &native_path)
                    .map(NativePath::into_path_buf)
                    .map_err(D::Error::custom)
            })
            .transpose()
    }
}

impl Ed2kResumeManifest {
    /// Exact durable payload bytes represented by the per-part block maps.
    ///
    /// Unlike summing `bytes_written`, this includes non-contiguous blocks
    /// retained by ICH salvage and is therefore suitable for disk reservation
    /// and endgame decisions.
    #[must_use]
    pub fn durable_present_bytes(&self) -> u64 {
        self.pieces
            .iter()
            .map(|piece| {
                let start = u64::from(piece.piece_index).saturating_mul(self.piece_size);
                let part_len = self.file_size.saturating_sub(start).min(self.piece_size);
                piece.resolve_block_bitmap(part_len).present_bytes()
            })
            .sum::<u64>()
            .min(self.file_size)
    }

    /// Build an empty manifest for a new transfer.
    #[must_use]
    pub fn new(job: &Ed2kTransferJob) -> Self {
        let piece_count = piece_count(job.file_size, job.piece_size);
        Self {
            file_hash: job.file_hash.clone(),
            display_name: job.display_name.clone(),
            file_size: job.file_size,
            piece_size: job.piece_size,
            completed: false,
            final_rehash_pending: false,
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
                    ich_corrupted: false,
                })
                .collect(),
            sources: Vec::new(),
            upload_priority: default_shared_upload_priority(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
            category_id: 0,
            control_state: None,
            transfer_row_removed: false,
            delivery_state: Ed2kDeliveryState::Pending,
            delivered_path: None,
            source_path: None,
            source_fingerprint: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with_source_path(source_path: PathBuf) -> Ed2kResumeManifest {
        let mut manifest = Ed2kResumeManifest::new(&Ed2kTransferJob {
            file_hash: "00112233445566778899aabbccddeeff".to_string(),
            display_name: "native-path.bin".to_string(),
            file_size: 1,
            piece_size: 1,
        });
        manifest.delivery_state = Ed2kDeliveryState::NotApplicable;
        manifest.source_path = Some(source_path);
        manifest.source_fingerprint = Some(NativeFileFingerprint {
            identity: NativeFileIdentity::Unix {
                device_id: 7,
                inode_number: 11,
            },
            size_bytes: 1,
            modified: NativeFileTimestamp::new(1_700_000_000, 123_456_789).unwrap(),
            changed: Some(NativeFileTimestamp::new(1_700_000_001, 234_567_890).unwrap()),
        });
        manifest
    }

    #[test]
    fn resume_manifest_native_path_json_round_trips() {
        let manifest = manifest_with_source_path(PathBuf::from("shared/native-path.bin"));
        let json = serde_json::to_string(&manifest).unwrap();
        let decoded = serde_json::from_str::<Ed2kResumeManifest>(&json).unwrap();

        assert!(json.contains("nativeHex"));
        assert!(json.contains("source_fingerprint"));
        assert_eq!(decoded, manifest);
    }

    #[cfg(unix)]
    #[test]
    fn resume_manifest_non_utf8_unix_path_json_round_trips() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let path = PathBuf::from(OsString::from_vec(b"shared/invalid-\xFF.bin".to_vec()));
        let manifest = manifest_with_source_path(path);
        let json = serde_json::to_string(&manifest).unwrap();
        let decoded = serde_json::from_str::<Ed2kResumeManifest>(&json).unwrap();

        assert_eq!(decoded, manifest);
    }

    #[cfg(windows)]
    #[test]
    fn resume_manifest_invalid_utf16_windows_path_json_round_trips() {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};

        let path = PathBuf::from(OsString::from_wide(&[
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            0xD800,
            b'.' as u16,
            b'b' as u16,
            b'i' as u16,
            b'n' as u16,
        ]));
        let manifest = manifest_with_source_path(path);
        let json = serde_json::to_string(&manifest).unwrap();
        let decoded = serde_json::from_str::<Ed2kResumeManifest>(&json).unwrap();

        assert_eq!(decoded, manifest);
    }
}
