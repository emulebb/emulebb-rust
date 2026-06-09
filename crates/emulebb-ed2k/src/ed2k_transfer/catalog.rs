use std::{str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{HashType, PopularHash};
use emulebb_kad_proto::Ed2kHash;

use super::Ed2kResumeManifest;
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
        })
    }

    /// Builds a fully verified shared entry from a manifest.
    #[must_use]
    pub fn from_manifest(manifest: &Ed2kResumeManifest) -> Self {
        Self {
            file_hash: manifest.file_hash.clone(),
            canonical_name: manifest.canonical_name.clone(),
            file_size: manifest.file_size,
            verified_complete: manifest.completed,
            verified_ranges: manifest.verified_ranges.clone(),
            compatibility_hint: false,
            source_count_hint: None,
            aich_root: manifest.aich_root.clone(),
        }
    }

    /// Parse the ED2K hash carried by this entry.
    pub fn parsed_hash(&self) -> Result<Ed2kHash> {
        Ed2kHash::from_str(&self.file_hash)
            .with_context(|| format!("invalid ED2K hash in shared entry {}", self.file_hash))
    }
}

/// One verified byte range that may be served to a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kSharedRange {
    /// Inclusive start offset.
    pub start: u64,
    /// Exclusive end offset.
    pub end: u64,
}
