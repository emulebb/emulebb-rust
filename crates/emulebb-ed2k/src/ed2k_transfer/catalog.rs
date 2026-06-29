use std::{str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{HashType, PopularHash};
use emulebb_kad_proto::Ed2kHash;

use super::{ED2K_PART_SIZE, Ed2kResumeManifest, ed2k_part_count};
/// Shared ED2K advertised file catalog used by the long-lived server session.
pub type Ed2kSharedCatalog = Arc<RwLock<Vec<Ed2kSharedEntry>>>;

/// One persisted or hinted ED2K shared-file entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kSharedEntry {
    /// Stable ED2K file hash in lowercase hex.
    pub file_hash: String,
    /// Canonical file name used in offer-files and filename answers.
    pub canonical_name: String,
    /// Full file size in bytes.
    pub file_size: u64,
    /// Whether the payload is fully verified and safe to serve to peers.
    pub verified_complete: bool,
    /// Byte ranges that are safe to upload. This slice only exposes verified
    /// complete files, but the schema is future-ready for finer-grained ranges.
    pub verified_ranges: Vec<Ed2kSharedRange>,
    /// Whether the entry is only a compatibility hint for offer-files.
    pub compatibility_hint: bool,
    /// Source count carried over from seed/popular-hash inputs when known.
    pub source_count_hint: Option<u32>,
    /// Canonical AICH root in lowercase hex when known.
    #[serde(default)]
    pub aich_root: Option<String>,
    /// Public upload-priority token used by the MFC-compatible publish ranker.
    #[serde(default = "default_upload_priority")]
    pub upload_priority: String,
    /// Whether upload priority is automatically managed.
    #[serde(default)]
    pub auto_upload_priority: bool,
    /// Lifetime bytes uploaded for this file, used for the all-time share ratio.
    #[serde(default)]
    pub all_time_uploaded_bytes: u64,
    /// Per-ED2K-part availability for an in-progress download ("share while
    /// downloading"). One entry per ED2K part (`ed2k_part_count(file_size)` =
    /// `size / PARTSIZE + 1`, i.e. eMule `m_iED2KPartCount`, one more than the
    /// data-part count at exact PARTSIZE multiples),
    /// `true` when that part is fully verified and safe to serve. For a fully
    /// verified file this is empty: the entry serves the whole file and the
    /// part-status answer collapses to the master "complete" sentinel
    /// (`CKnownFile::WritePartStatus` -> `WriteUInt16(0)`). Mirrors
    /// `CPartFile::IsCompleteBD(uPart)` used by `CPartFile::WritePartStatus`.
    #[serde(default)]
    pub complete_parts: Vec<bool>,
    /// In-memory publish/demand counters used by the MFC-compatible publish
    /// ranker. These are intentionally path/name-free and may be rebuilt during
    /// a long session.
    #[serde(default)]
    pub publish: Ed2kSharedPublishStats,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kSharedPublishStats {
    #[serde(default)]
    pub session_uploaded_bytes: u64,
    #[serde(default)]
    pub session_request_count: u64,
    #[serde(default)]
    pub session_accept_count: u64,
    #[serde(default)]
    pub all_time_request_count: u64,
    #[serde(default)]
    pub all_time_accept_count: u64,
    #[serde(default)]
    pub last_request_unix_ms: i64,
    #[serde(default)]
    pub last_ed2k_publish_unix_ms: i64,
}

impl Ed2kSharedEntry {
    /// Builds a compatibility-only entry from a popular-hash hint.
    #[must_use]
    pub fn from_popular_hash(hash: &PopularHash) -> Option<Self> {
        let HashType::Ed2k(value) = &hash.hash;
        let _ = Ed2kHash::from_str(value).ok()?;
        Some(Self {
            file_hash: value.clone(),
            canonical_name: hash.canonical_name.clone(),
            file_size: hash.size,
            verified_complete: false,
            verified_ranges: Vec::new(),
            compatibility_hint: true,
            source_count_hint: Some(hash.source_count),
            aich_root: None,
            upload_priority: default_upload_priority(),
            auto_upload_priority: false,
            all_time_uploaded_bytes: 0,
            complete_parts: Vec::new(),
            publish: Ed2kSharedPublishStats::default(),
        })
    }

    /// Builds a shared entry from a manifest, exposing either a fully verified
    /// file or an in-progress partfile with its per-part availability ("share
    /// while downloading").
    #[must_use]
    pub fn from_manifest(manifest: &Ed2kResumeManifest) -> Self {
        let complete_parts = if manifest.completed {
            // A complete file serves the whole payload; the part-status answer
            // collapses to the master "complete" sentinel, so no per-part vector.
            Vec::new()
        } else {
            complete_parts_from_ranges(manifest.file_size, &manifest.verified_ranges)
        };
        Self {
            file_hash: manifest.file_hash.clone(),
            canonical_name: manifest.canonical_name.clone(),
            file_size: manifest.file_size,
            verified_complete: manifest.completed,
            verified_ranges: manifest.verified_ranges.clone(),
            compatibility_hint: false,
            source_count_hint: None,
            aich_root: manifest.aich_root.clone(),
            upload_priority: manifest.upload_priority.clone(),
            auto_upload_priority: manifest.auto_upload_priority,
            all_time_uploaded_bytes: 0,
            complete_parts,
            publish: Ed2kSharedPublishStats::default(),
        }
    }

    /// Parse the ED2K hash carried by this entry.
    pub fn parsed_hash(&self) -> Result<Ed2kHash> {
        Ed2kHash::from_str(&self.file_hash)
            .with_context(|| format!("invalid ED2K hash in shared entry {}", self.file_hash))
    }

    /// Whether this entry may be served to an inbound peer right now: a fully
    /// verified file, or an in-progress partfile holding at least one complete
    /// ED2K part. Mirrors the master file-request fallback admitting a
    /// `downloadqueue` partfile only with `GetCompletedSize() >= PARTSIZE`
    /// (ListenSocket.cpp `OP_FILEREQUEST`), i.e. at least one complete part.
    #[must_use]
    pub fn is_servable(&self) -> bool {
        self.verified_complete || self.complete_parts.iter().any(|complete| *complete)
    }

    /// Encode the OP_FILESTATUS body for this entry (the bytes after the file
    /// hash): a leading `uED2KPartCount` (u16, LSB-first) followed by one bit per
    /// part. A fully verified file collapses to the master complete sentinel
    /// (`WriteUInt16(0)`), exactly mirroring `CPartFile::WritePartStatus` /
    /// `CKnownFile::WritePartStatus`.
    #[must_use]
    pub fn encode_part_status_body(&self) -> Vec<u8> {
        if self.verified_complete || self.complete_parts.is_empty() {
            return 0u16.to_le_bytes().to_vec();
        }
        let part_count = u16::try_from(self.complete_parts.len()).unwrap_or(u16::MAX);
        let mut body = Vec::with_capacity(2 + usize::from(part_count).div_ceil(8));
        body.extend_from_slice(&part_count.to_le_bytes());
        for chunk in self.complete_parts.chunks(8) {
            let mut byte = 0u8;
            for (bit, complete) in chunk.iter().enumerate() {
                if *complete {
                    byte |= 1 << bit;
                }
            }
            body.push(byte);
        }
        body
    }
}

fn default_upload_priority() -> String {
    "normal".to_string()
}

/// Derive the per-ED2K-part complete bitmap from verified byte ranges, one bit
/// per `CKnownFile::m_iED2KPartCount` part exactly as
/// `CPartFile::WritePartStatus` iterates `0..GetED2KPartCount()` and writes
/// `IsCompleteBD(uPart)`. The vector length is therefore [`ed2k_part_count`],
/// which is one MORE than the data-part count at exact PARTSIZE multiples.
///
/// For a normal part the whole `[part_start, part_end)` byte span must lie
/// inside a single verified range (`IsCompleteBD(uPart)` is gap-free over the
/// part). The trailing extra part at an exact multiple has `part_start ==
/// file_size` (EOF): `IsCompleteBD` clamps `end` to `file_size - 1`, yielding
/// `start > end`, so its gap/buffer scan finds nothing and returns `true`. We
/// mirror that by treating any zero-length (`part_start >= file_size`) part as
/// complete.
fn complete_parts_from_ranges(file_size: u64, ranges: &[Ed2kSharedRange]) -> Vec<bool> {
    if file_size == 0 {
        return Vec::new();
    }
    let part_count = u64::from(ed2k_part_count(file_size));
    (0..part_count)
        .map(|part| {
            let part_start = part * ED2K_PART_SIZE;
            if part_start >= file_size {
                // Trailing EOF slice at an exact PARTSIZE multiple: zero length,
                // always complete (eMule `IsCompleteBD` start > end -> true).
                return true;
            }
            let part_end = (part_start + ED2K_PART_SIZE).min(file_size);
            ranges
                .iter()
                .any(|range| range.start <= part_start && part_end <= range.end)
        })
        .collect()
}

/// One verified byte range that may be served to a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kSharedRange {
    /// Inclusive start offset.
    pub start: u64,
    /// Exclusive end offset.
    pub end: u64,
}
