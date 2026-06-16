use std::{str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{HashType, PopularHash};
use emulebb_kad_proto::Ed2kHash;

use super::{ED2K_PART_SIZE, Ed2kResumeManifest};
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
    /// Per-ED2K-part availability for an in-progress download ("share while
    /// downloading"). One entry per ED2K part (`ceil(file_size / PARTSIZE)`),
    /// `true` when that part is fully verified and safe to serve. For a fully
    /// verified file this is empty: the entry serves the whole file and the
    /// part-status answer collapses to the master "complete" sentinel
    /// (`CKnownFile::WritePartStatus` -> `WriteUInt16(0)`). Mirrors
    /// `CPartFile::IsCompleteBD(uPart)` used by `CPartFile::WritePartStatus`.
    #[serde(default)]
    pub complete_parts: Vec<bool>,
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
            complete_parts: Vec::new(),
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
            complete_parts,
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

/// Derive the per-ED2K-part complete bitmap from verified byte ranges. A part is
/// complete only when its whole `[part_start, part_end)` byte span lies inside a
/// single verified range, mirroring `CPartFile::IsCompleteBD(uPart)` (the whole
/// part is gap-free). The trailing part may be shorter than `PARTSIZE`.
fn complete_parts_from_ranges(file_size: u64, ranges: &[Ed2kSharedRange]) -> Vec<bool> {
    if file_size == 0 {
        return Vec::new();
    }
    let part_count = file_size.div_ceil(ED2K_PART_SIZE);
    (0..part_count)
        .map(|part| {
            let part_start = part * ED2K_PART_SIZE;
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
