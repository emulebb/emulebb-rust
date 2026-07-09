//! Runtime facade for shared-catalog reads and mutation.

use std::sync::Arc;

use crate::PopularHash;

use super::{Ed2kResumeManifest, Ed2kSharedCatalog, Ed2kSharedEntry, Ed2kTransferRuntime};

impl Ed2kTransferRuntime {
    /// Borrow the shared catalog used by server-session advertisement and
    /// listener-side upload serving.
    #[must_use]
    pub fn shared_catalog(&self) -> Ed2kSharedCatalog {
        Arc::clone(&self.shared_catalog)
    }

    /// Return the current verified shared-catalog entry count without walking
    /// persisted manifests. This is used by liveness/status surfaces that must
    /// stay cheap while a large shared-library hash is in progress.
    pub async fn shared_catalog_count(&self) -> usize {
        self.shared_catalog.read().await.len()
    }

    /// Replace compatibility-hint catalog entries while preserving verified
    /// local files loaded from manifests.
    pub async fn replace_catalog_hints(&self, hashes: &[PopularHash]) {
        let mut preserved_verified = {
            let guard = self.shared_catalog.read().await;
            guard
                .iter()
                .filter(|entry| !entry.compatibility_hint)
                .cloned()
                .collect::<Vec<_>>()
        };
        preserved_verified.extend(hashes.iter().filter_map(Ed2kSharedEntry::from_popular_hash));
        let mut guard = self.shared_catalog.write().await;
        guard.replace_with(dedupe_entries(preserved_verified));
    }

    pub(super) async fn upsert_verified_catalog_entry(&self, manifest: &Ed2kResumeManifest) {
        // Build the replacement entry (if any) before taking the write lock so the
        // lock hold covers only the in-place upsert.
        let new_entry = (manifest.completed || !manifest.verified_ranges.is_empty())
            .then(|| Ed2kSharedEntry::from_manifest(manifest));
        let mut entries = self.shared_catalog.write().await;
        // Collapse the old retain -> to_vec (whole-catalog deep clone) -> dedupe ->
        // replace_with chain into a single in-place upsert: no deep clone, one
        // index rebuild. The predicate, the appended entry, and the dedupe policy
        // are unchanged, so the resulting order + index are identical.
        entries.retain_push_dedup(
            |entry| entry.file_hash != manifest.file_hash || entry.compatibility_hint,
            new_entry,
            dedupe_entries,
        );
    }

    /// Remove a locally verified file from the live serving/advertisement
    /// catalog while preserving compatibility hints for the same hash.
    pub async fn remove_verified_catalog_entry(&self, file_hash: &str) {
        let mut entries = self.shared_catalog.write().await;
        entries.retain(|entry| {
            !entry.file_hash.eq_ignore_ascii_case(file_hash) || entry.compatibility_hint
        });
    }
}

fn dedupe_entries(entries: Vec<Ed2kSharedEntry>) -> Vec<Ed2kSharedEntry> {
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::with_capacity(entries.len());
    for entry in entries.into_iter().rev() {
        if seen.insert((entry.file_hash.clone(), entry.compatibility_hint)) {
            deduped.push(entry);
        }
    }
    deduped.reverse();
    deduped
}

#[cfg(test)]
mod upsert_collapse_tests {
    //! Proof that the collapsed in-place upsert
    //! ([`IndexedSharedCatalog::retain_push_dedup`]) yields a catalog byte-identical
    //! to the previous `retain` -> `to_vec` (whole-catalog deep clone) -> `dedupe`
    //! -> `replace_with` chain, for every mutation shape the upsert can take.

    use super::dedupe_entries;
    use super::super::IndexedSharedCatalog;
    use crate::ed2k_transfer::Ed2kSharedEntry;
    use emulebb_kad_proto::Ed2kHash;
    use std::str::FromStr;

    fn hex_hash(nibble: u8) -> String {
        std::iter::repeat_n(format!("{nibble:x}{nibble:x}"), 16).collect()
    }

    /// One entry; `marker` (carried in `all_time_uploaded_bytes`) makes otherwise
    /// same-hash instances distinguishable so a wrong dedupe survivor is caught.
    fn entry(nibble: u8, hint: bool, marker: u64) -> Ed2kSharedEntry {
        Ed2kSharedEntry {
            file_hash: hex_hash(nibble),
            canonical_name: format!("file-{nibble}.bin"),
            file_size: 1_000,
            verified_complete: !hint,
            verified_ranges: Vec::new(),
            compatibility_hint: hint,
            source_count_hint: None,
            aich_root: None,
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
            all_time_uploaded_bytes: marker,
            complete_parts: Vec::new(),
            publish: Default::default(),
        }
    }

    /// Run BOTH the exact old chain and the new collapsed method over the same
    /// start + upsert, assert the resulting entry list (contents AND order) and the
    /// by-hash index are identical, and return the collapsed result.
    fn assert_upsert_identical(
        start: Vec<Ed2kSharedEntry>,
        target_hash: &str,
        new_entry: Option<Ed2kSharedEntry>,
    ) -> IndexedSharedCatalog {
        // Old behavior: retain -> push -> deep-clone via to_vec -> dedupe ->
        // replace_with, exactly as `upsert_verified_catalog_entry` used to do.
        let old = {
            let mut cat = IndexedSharedCatalog::from_entries(start.clone());
            cat.retain(|e| e.file_hash != target_hash || e.compatibility_hint);
            if let Some(e) = new_entry.clone() {
                cat.push(e);
            }
            let deduped = dedupe_entries(cat.to_vec());
            cat.replace_with(deduped);
            cat
        };
        // New behavior: single in-place collapse, no whole-catalog deep clone.
        let new = {
            let mut cat = IndexedSharedCatalog::from_entries(start);
            cat.retain_push_dedup(
                |e| e.file_hash != target_hash || e.compatibility_hint,
                new_entry,
                dedupe_entries,
            );
            cat
        };

        // Entry list: same contents AND same order (the ordered Vec is the source
        // of truth for cursor/rank/REST).
        assert_eq!(new.len(), old.len(), "entry count differs");
        assert_eq!(&new[..], &old[..], "entry contents or order differ");

        // Index: both internally consistent, and every hash resolves to the same
        // slot (or to nothing) in both — hints excluded, first occurrence wins.
        old.assert_index_consistent();
        new.assert_index_consistent();
        for e in old.iter() {
            if let Ok(hash) = e.parsed_hash() {
                assert_eq!(
                    new.index_by_hash(&hash),
                    old.index_by_hash(&hash),
                    "index slot differs for hash {}",
                    e.file_hash
                );
            }
        }
        new
    }

    #[test]
    fn insert_brand_new_entry() {
        let result = assert_upsert_identical(
            vec![entry(1, false, 10), entry(2, false, 20)],
            &hex_hash(3),
            Some(entry(3, false, 30)),
        );
        // Appended at the tail, index resolves it.
        assert_eq!(result.len(), 3);
        let idx = result
            .index_by_hash(&Ed2kHash::from_str(&hex_hash(3)).unwrap())
            .unwrap();
        assert_eq!(result[idx].all_time_uploaded_bytes, 30);
    }

    #[test]
    fn replace_existing_entry_same_hash_moves_to_tail() {
        // The old non-hint entry for the hash is dropped and the new one appended,
        // so the surviving order is [2, 1'] — order preservation must match.
        let result = assert_upsert_identical(
            vec![entry(1, false, 10), entry(2, false, 20)],
            &hex_hash(1),
            Some(entry(1, false, 99)),
        );
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].file_hash, hex_hash(2));
        assert_eq!(result[1].file_hash, hex_hash(1));
        assert_eq!(result[1].all_time_uploaded_bytes, 99);
    }

    #[test]
    fn duplicate_hash_collapses_to_last_occurrence() {
        // A pre-existing duplicate (no upsert append) must collapse exactly as the
        // reverse-scan dedupe did: the LAST occurrence survives, order preserved.
        let result = assert_upsert_identical(
            vec![entry(1, false, 10), entry(1, false, 20), entry(2, false, 30)],
            &hex_hash(5),
            None,
        );
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].file_hash, hex_hash(1));
        assert_eq!(result[0].all_time_uploaded_bytes, 20);
        assert_eq!(result[1].file_hash, hex_hash(2));
    }

    #[test]
    fn hint_and_verified_shadowing_preserved() {
        // A hint for the upserted hash survives retain (hints are exempt), the new
        // verified entry is appended, and the index targets only the verified entry.
        let result = assert_upsert_identical(
            vec![entry(1, true, 10), entry(1, false, 20), entry(2, true, 30)],
            &hex_hash(1),
            Some(entry(1, false, 99)),
        );
        assert_eq!(result.len(), 3);
        // hash 1 resolves to the verified (non-hint) entry only.
        let idx = result
            .index_by_hash(&Ed2kHash::from_str(&hex_hash(1)).unwrap())
            .unwrap();
        assert!(!result[idx].compatibility_hint);
        assert_eq!(result[idx].all_time_uploaded_bytes, 99);
        // hash 2 is hint-only, never indexed.
        assert!(
            result
                .index_by_hash(&Ed2kHash::from_str(&hex_hash(2)).unwrap())
                .is_none()
        );
    }
}
