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
        *guard = dedupe_entries(preserved_verified);
    }

    pub(super) async fn upsert_verified_catalog_entry(&self, manifest: &Ed2kResumeManifest) {
        let mut entries = self.shared_catalog.write().await;
        entries.retain(|entry| entry.file_hash != manifest.file_hash || entry.compatibility_hint);
        if manifest.completed || !manifest.verified_ranges.is_empty() {
            entries.push(Ed2kSharedEntry::from_manifest(manifest));
        }
        *entries = dedupe_entries(entries.clone());
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
