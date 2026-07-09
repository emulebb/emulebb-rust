use std::{collections::HashMap, ops::Deref, str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{HashType, PopularHash};
use emulebb_kad_proto::Ed2kHash;

use super::{ED2K_PART_SIZE, Ed2kResumeManifest, ed2k_part_count};
/// Shared ED2K advertised file catalog used by the long-lived server session.
///
/// The locked value is an [`IndexedSharedCatalog`]: the ordered `Vec` of entries
/// stays the source of truth (publish-cursor rotation, rank sort, and REST all
/// iterate it in order) while a side by-hash index makes the upload hot path's
/// per-fragment/per-request crediting an O(1) lookup instead of a full scan held
/// under the write lock.
pub type Ed2kSharedCatalog = Arc<RwLock<IndexedSharedCatalog>>;

/// Ordered shared-file catalog paired with an O(1) raw-hash index.
///
/// `entries` is the ordered source of truth. `by_hash` is an ADDITIONAL lookup
/// structure mapping the raw 16-byte MD4 file hash to the index of the unique
/// non-compatibility-hint entry carrying that hash — the exact entry every by-hash
/// hot-path lookup targets (`update_shared_publish_stats`,
/// `add_file_all_time_uploaded`, and the reask serve check all filter to the
/// verified/servable entry, never a bare hint). Compatibility hints are
/// intentionally excluded from the index: after dedupe there is at most one
/// non-hint entry per hash, so the map is unambiguous, and a hint is never a
/// serve/credit target.
///
/// The raw 16 bytes are the key (not a lowercased hex string) because they are the
/// canonical form: `Ed2kHash` already holds them, so a lookup keys off
/// `hash.0` with zero allocation and zero per-lookup case-folding, and building the
/// index parses each stored hex hash exactly once.
///
/// The index is kept in lock-step with `entries` by EVERY mutator on this type
/// (`push`, `retain`, `replace_with`, `mutate_all`); the inner `Vec` is never
/// exposed mutably, so a caller cannot let the index drift out of sync.
#[derive(Debug, Clone, Default)]
pub struct IndexedSharedCatalog {
    entries: Vec<Ed2kSharedEntry>,
    by_hash: HashMap<[u8; 16], usize>,
}

impl IndexedSharedCatalog {
    /// Build an indexed catalog from an ordered entry list.
    #[must_use]
    pub fn from_entries(entries: Vec<Ed2kSharedEntry>) -> Self {
        let mut catalog = Self {
            entries,
            by_hash: HashMap::new(),
        };
        catalog.rebuild_index();
        catalog
    }

    /// Raw parsed 16-byte hash for an entry, or `None` when the stored hex hash is
    /// malformed. A malformed-hash entry can never be the target of a valid
    /// [`Ed2kHash`] lookup, so it is simply left out of the index.
    fn entry_hash_key(entry: &Ed2kSharedEntry) -> Option<[u8; 16]> {
        Ed2kHash::from_str(&entry.file_hash).ok().map(|hash| hash.0)
    }

    /// Rebuild the by-hash index from scratch over the current `entries` order.
    /// First occurrence wins (matching the previous `iter().find()` first-match
    /// semantics); only non-compatibility-hint entries are indexed.
    fn rebuild_index(&mut self) {
        self.by_hash.clear();
        self.by_hash.reserve(self.entries.len());
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.compatibility_hint {
                continue;
            }
            if let Some(key) = Self::entry_hash_key(entry) {
                self.by_hash.entry(key).or_insert(idx);
            }
        }
    }

    /// Number of catalog entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the catalog holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Append an entry, keeping the by-hash index in sync. A non-hint entry is
    /// indexed at its new tail position, first-occurrence-wins so an earlier
    /// duplicate keeps ownership (matching the old first-match scan).
    pub fn push(&mut self, entry: Ed2kSharedEntry) {
        let idx = self.entries.len();
        if !entry.compatibility_hint
            && let Some(key) = Self::entry_hash_key(&entry)
        {
            self.by_hash.entry(key).or_insert(idx);
        }
        self.entries.push(entry);
    }

    /// Retain entries matching `keep`, then rebuild the index. Removal shifts every
    /// later `Vec` position, so the map is rebuilt wholesale rather than patched.
    pub fn retain(&mut self, keep: impl FnMut(&Ed2kSharedEntry) -> bool) {
        self.entries.retain(keep);
        self.rebuild_index();
    }

    /// Replace the whole ordered entry list and rebuild the index.
    pub fn replace_with(&mut self, entries: Vec<Ed2kSharedEntry>) {
        self.entries = entries;
        self.rebuild_index();
    }

    /// O(1) index of the unique non-hint entry advertised under `hash`, if any.
    #[must_use]
    pub fn index_by_hash(&self, hash: &Ed2kHash) -> Option<usize> {
        self.by_hash.get(&hash.0).copied()
    }

    /// Apply `update` to the unique non-hint entry for `hash` (O(1)); returns
    /// whether an entry was found. `update` MUST NOT change `file_hash` (that would
    /// desync the index); it is only ever used to bump stat counters.
    pub fn update_by_hash(
        &mut self,
        hash: &Ed2kHash,
        update: impl FnOnce(&mut Ed2kSharedEntry),
    ) -> bool {
        if let Some(&idx) = self.by_hash.get(&hash.0) {
            update(&mut self.entries[idx]);
            true
        } else {
            false
        }
    }

    /// Apply `mutate` to every entry, then rebuild the index. Used off the hot path
    /// where a mutation could in principle touch a field the index depends on; the
    /// wholesale rebuild guarantees the index cannot drift regardless of what
    /// `mutate` does.
    pub fn mutate_all(&mut self, mutate: impl FnMut(&mut Ed2kSharedEntry)) {
        self.entries.iter_mut().for_each(mutate);
        self.rebuild_index();
    }

    /// Validate that the by-hash index is perfectly consistent with `entries`:
    /// every indexed hash points to a non-hint entry actually carrying that hash,
    /// and every non-hint entry with a parseable hash is reachable via the index at
    /// its first occurrence. Used by tests (and debug builds) to assert the
    /// sync-on-every-mutator invariant.
    #[cfg(any(test, debug_assertions))]
    pub(crate) fn assert_index_consistent(&self) {
        for (&key, &idx) in &self.by_hash {
            let entry = &self.entries[idx];
            assert!(
                !entry.compatibility_hint,
                "compatibility-hint entry must never be indexed"
            );
            assert_eq!(
                Self::entry_hash_key(entry),
                Some(key),
                "index key does not match the entry it points to"
            );
        }
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.compatibility_hint {
                continue;
            }
            let Some(key) = Self::entry_hash_key(entry) else {
                continue;
            };
            let mapped = self
                .by_hash
                .get(&key)
                .copied()
                .expect("non-hint entry missing from by-hash index");
            assert!(
                mapped <= idx,
                "index must point to the first occurrence of a hash"
            );
            assert_eq!(Self::entry_hash_key(&self.entries[mapped]), Some(key));
        }
    }
}

impl Deref for IndexedSharedCatalog {
    type Target = [Ed2kSharedEntry];

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

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
    /// Locally configured shared-file comment used for Kad note publishing.
    #[serde(default)]
    pub comment: String,
    /// Locally configured shared-file rating used for Kad note publishing.
    #[serde(default)]
    pub rating: u8,
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
            comment: String::new(),
            rating: 0,
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
            comment: manifest.comment.clone(),
            rating: manifest.rating,
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

#[cfg(test)]
mod indexed_catalog_tests {
    use super::*;

    fn hex_hash(nibble: u8) -> String {
        std::iter::repeat_n(format!("{nibble:x}{nibble:x}"), 16).collect()
    }

    fn verified_entry(nibble: u8) -> Ed2kSharedEntry {
        Ed2kSharedEntry {
            file_hash: hex_hash(nibble),
            canonical_name: format!("file-{nibble}.bin"),
            file_size: 1_000,
            verified_complete: true,
            verified_ranges: Vec::new(),
            compatibility_hint: false,
            source_count_hint: None,
            aich_root: None,
            upload_priority: default_upload_priority(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
            all_time_uploaded_bytes: 0,
            complete_parts: Vec::new(),
            publish: Ed2kSharedPublishStats::default(),
        }
    }

    fn hint_entry(nibble: u8) -> Ed2kSharedEntry {
        Ed2kSharedEntry {
            compatibility_hint: true,
            verified_complete: false,
            ..verified_entry(nibble)
        }
    }

    fn key(nibble: u8) -> Ed2kHash {
        Ed2kHash::from_str(&hex_hash(nibble)).unwrap()
    }

    #[test]
    fn add_then_lookup_each_entry_resolves() {
        let catalog =
            IndexedSharedCatalog::from_entries(vec![verified_entry(1), verified_entry(2), verified_entry(3)]);
        catalog.assert_index_consistent();
        for n in 1..=3u8 {
            let idx = catalog.index_by_hash(&key(n)).expect("entry present");
            assert_eq!(catalog[idx].file_hash, hex_hash(n));
        }
        assert!(catalog.index_by_hash(&key(9)).is_none());
    }

    #[test]
    fn remove_shifts_indices_without_leaving_stale_entry() {
        // remove the MIDDLE entry so every later Vec index shifts down by one; a
        // stale index would now resolve C to the wrong slot.
        let mut catalog =
            IndexedSharedCatalog::from_entries(vec![verified_entry(1), verified_entry(2), verified_entry(3)]);
        catalog.retain(|entry| entry.file_hash != hex_hash(2));
        catalog.assert_index_consistent();
        assert_eq!(catalog.len(), 2);
        assert!(catalog.index_by_hash(&key(2)).is_none());
        for n in [1u8, 3] {
            let idx = catalog.index_by_hash(&key(n)).expect("survivor present");
            assert_eq!(catalog[idx].file_hash, hex_hash(n));
        }
    }

    #[test]
    fn remove_then_readd_reindexes() {
        let mut catalog = IndexedSharedCatalog::from_entries(vec![verified_entry(1), verified_entry(2)]);
        catalog.retain(|entry| entry.file_hash != hex_hash(1));
        assert!(catalog.index_by_hash(&key(1)).is_none());
        catalog.push(verified_entry(1));
        catalog.assert_index_consistent();
        let idx = catalog.index_by_hash(&key(1)).expect("re-added entry present");
        assert_eq!(catalog[idx].file_hash, hex_hash(1));
    }

    #[test]
    fn bulk_replace_rebuilds_index() {
        let mut catalog = IndexedSharedCatalog::from_entries(vec![verified_entry(1), verified_entry(2)]);
        catalog.replace_with(vec![verified_entry(3), verified_entry(4)]);
        catalog.assert_index_consistent();
        assert!(catalog.index_by_hash(&key(1)).is_none());
        assert!(catalog.index_by_hash(&key(3)).is_some());
        assert!(catalog.index_by_hash(&key(4)).is_some());
    }

    #[test]
    fn compatibility_hints_are_not_indexed() {
        // A hint sharing a hash with a verified entry must not shadow it, and a
        // hint-only hash must not resolve (hot-path lookups target the verified
        // entry, never a hint).
        let catalog =
            IndexedSharedCatalog::from_entries(vec![hint_entry(1), verified_entry(1), hint_entry(2)]);
        catalog.assert_index_consistent();
        let idx = catalog.index_by_hash(&key(1)).expect("verified entry present");
        assert!(!catalog[idx].compatibility_hint);
        assert!(catalog.index_by_hash(&key(2)).is_none());
    }

    #[test]
    fn update_by_hash_targets_only_matching_verified_entry() {
        let mut catalog = IndexedSharedCatalog::from_entries(vec![verified_entry(1), verified_entry(2)]);
        assert!(catalog.update_by_hash(&key(1), |entry| {
            entry.all_time_uploaded_bytes = 42;
        }));
        let idx1 = catalog.index_by_hash(&key(1)).unwrap();
        let idx2 = catalog.index_by_hash(&key(2)).unwrap();
        assert_eq!(catalog[idx1].all_time_uploaded_bytes, 42);
        assert_eq!(catalog[idx2].all_time_uploaded_bytes, 0);
        assert!(!catalog.update_by_hash(&key(9), |_| unreachable!()));
    }

    #[test]
    fn multi_fragment_credit_accumulates_all_time_total() {
        // Mirror the per-fragment upload credit path: many O(1) credits must sum to
        // the exact all-time total (no bytes lost, no double count).
        let mut catalog = IndexedSharedCatalog::from_entries(vec![verified_entry(1)]);
        const FRAGMENT: u64 = 180 * 1024;
        const FRAGMENTS: u64 = 55;
        for _ in 0..FRAGMENTS {
            catalog.update_by_hash(&key(1), |entry| {
                entry.all_time_uploaded_bytes = entry.all_time_uploaded_bytes.saturating_add(FRAGMENT);
                entry.publish.session_uploaded_bytes =
                    entry.publish.session_uploaded_bytes.saturating_add(FRAGMENT);
            });
        }
        let idx = catalog.index_by_hash(&key(1)).unwrap();
        assert_eq!(catalog[idx].all_time_uploaded_bytes, FRAGMENT * FRAGMENTS);
        assert_eq!(catalog[idx].publish.session_uploaded_bytes, FRAGMENT * FRAGMENTS);
    }

    #[test]
    fn mutate_all_keeps_index_consistent() {
        let mut catalog =
            IndexedSharedCatalog::from_entries(vec![verified_entry(1), verified_entry(2), hint_entry(3)]);
        catalog.mutate_all(|entry| entry.publish.last_ed2k_publish_unix_ms = 7);
        catalog.assert_index_consistent();
        assert!(catalog.iter().all(|entry| entry.publish.last_ed2k_publish_unix_ms == 7));
    }
}
