use std::{
    collections::HashMap,
    ops::Deref,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

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
type EligibilityTask =
    tokio::sync::oneshot::Receiver<anyhow::Result<super::local_mutation::job_payload::Output>>;

#[derive(Debug, Default, Clone, Copy)]
struct ShareStripe {
    active: u32,
    generation: u64,
}

#[derive(Debug)]
pub(crate) struct ShareStripes {
    stripes: [ShareStripe; 256],
    faulted: bool,
}
impl Default for ShareStripes {
    fn default() -> Self {
        Self {
            stripes: [ShareStripe::default(); 256],
            faulted: false,
        }
    }
}

/// Holds only fixed stripe identities across the actual SQL mutation lifetime.
pub struct SharedFileMutation {
    stripes: Arc<std::sync::Mutex<ShareStripes>>,
    indexes: Vec<u8>,
}
impl Drop for SharedFileMutation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.stripes.lock() {
            for index in &self.indexes {
                let stripe = &mut state.stripes[usize::from(*index)];
                stripe.active -= 1;
                if let Some(next) = stripe.generation.checked_add(1) {
                    stripe.generation = next;
                } else {
                    state.faulted = true;
                }
            }
        }
    }
}

impl ShareStripes {
    fn snapshot_all(&self) -> Option<Vec<(u8, u64)>> {
        if self.faulted || self.stripes.iter().any(|stripe| stripe.active != 0) {
            return None;
        }
        Some(
            self.stripes
                .iter()
                .enumerate()
                .map(|(index, stripe)| (index as u8, stripe.generation))
                .collect(),
        )
    }
    fn indexes(hashes: &[[u8; 16]]) -> Vec<u8> {
        let mut indexes = hashes
            .iter()
            .map(|hash| hash[0] ^ hash[7] ^ hash[15])
            .collect::<Vec<_>>();
        indexes.sort_unstable();
        indexes.dedup();
        indexes
    }
    fn snapshot(&self, hashes: &[[u8; 16]]) -> Option<Vec<(u8, u64)>> {
        if self.faulted {
            return None;
        }
        Self::indexes(hashes)
            .into_iter()
            .map(|index| {
                let stripe = self.stripes[usize::from(index)];
                (stripe.active == 0).then_some((index, stripe.generation))
            })
            .collect()
    }
    fn matches(&self, snapshot: &[(u8, u64)]) -> bool {
        !self.faulted
            && snapshot.iter().all(|(index, generation)| {
                let stripe = self.stripes[usize::from(*index)];
                stripe.active == 0 && stripe.generation == *generation
            })
    }
}

/// One separately bounded, tracked eligibility read for outgoing batches.
/// Product-owned retained result buffers are capped at 1 MiB independently
/// of persistence-owner payloads; SQLite/allocator and transport internals
/// are outside this retained-payload bound. Physical probes additionally use
/// the existing registry long-filesystem workspace and admission sublimits.
#[derive(Debug)]
pub struct SharedEligibility {
    metadata: emulebb_metadata::MetadataStore,
    root_epoch: Arc<AtomicU64>,
    root_dirty: Arc<AtomicBool>,
    publication_failed: Arc<AtomicBool>,
    sealed: AtomicBool,
    stripes: Arc<std::sync::Mutex<ShareStripes>>,
    manifests: Arc<tokio::sync::Mutex<HashMap<emulebb_metadata::JobId, super::ResidentManifest>>>,
    read_slot: Arc<tokio::sync::Mutex<Option<EligibilityTask>>>,
    local_mutations: Arc<super::local_mutation::LocalMutationRegistry>,
}

pub struct SharedEligibilityBatch {
    epoch: u64,
    stripes: Vec<(u8, u64)>,
    pub complete: Vec<bool>,
    pub partial: Vec<Option<emulebb_metadata::MetadataPartialOffer>>,
    _slot: tokio::sync::OwnedMutexGuard<Option<EligibilityTask>>,
    _result_lease: super::local_mutation::capacity::CapacityLease,
}

impl SharedEligibility {
    pub(super) fn new(
        metadata: emulebb_metadata::MetadataStore,
        root_epoch: Arc<AtomicU64>,
        root_dirty: Arc<AtomicBool>,
        publication_failed: Arc<AtomicBool>,
        stripes: Arc<std::sync::Mutex<ShareStripes>>,
        manifests: Arc<
            tokio::sync::Mutex<HashMap<emulebb_metadata::JobId, super::ResidentManifest>>,
        >,
        local_mutations: Arc<super::local_mutation::LocalMutationRegistry>,
    ) -> Self {
        Self {
            metadata,
            root_epoch,
            root_dirty,
            publication_failed,
            sealed: AtomicBool::new(false),
            stripes,
            manifests,
            local_mutations,
            read_slot: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Returns None when the bounded slot or SQLite connection is busy, or a
    /// root transaction overlaps the read. No waiting caller copies a batch.
    pub async fn try_batch(&self, hashes: &[[u8; 16]]) -> Result<Option<SharedEligibilityBatch>> {
        anyhow::ensure!(hashes.len() <= 200, "eligibility batch exceeds 200 hashes");
        if self.sealed.load(Ordering::Acquire) {
            return Ok(None);
        }
        let Ok(mut slot) = Arc::clone(&self.read_slot).try_lock_owned() else {
            return Ok(None);
        };
        if self.sealed.load(Ordering::Acquire) {
            return Ok(None);
        }
        if let Some(task) = slot.as_mut() {
            if matches!(
                task.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ) {
                return Ok(None);
            }
            slot.take();
        }
        let epoch = self.root_epoch.load(Ordering::Acquire);
        if epoch % 2 != 0 {
            return Ok(None);
        }
        let Some(mut stripes) = self
            .stripes
            .lock()
            .map_err(|_| anyhow::anyhow!("share stripe lock poisoned"))?
            .snapshot(hashes)
        else {
            return Ok(None);
        };
        let receipt = match self.local_mutations.submit_payload_read(
            &self.metadata,
            super::local_mutation::job_payload::Request::Eligibility(hashes),
        ) {
            Ok(receipt) => receipt,
            Err(error)
                if matches!(
                    error.downcast_ref::<super::LocalMutationError>(),
                    Some(super::LocalMutationError::Busy | super::LocalMutationError::Closing)
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        *slot = Some(receipt);
        let result = slot.as_mut().expect("eligibility read slot").await;
        slot.take();
        let super::local_mutation::job_payload::Output::Eligibility(result, result_lease) =
            result.context("eligibility read owner stopped")??
        else {
            unreachable!()
        };
        let Some(rows) = result else {
            return Ok(None);
        };
        if self.root_epoch.load(Ordering::Acquire) != epoch {
            return Ok(None);
        }
        let Ok(cache) = self.manifests.try_lock() else {
            return Ok(None);
        };
        let mut complete = Vec::with_capacity(hashes.len());
        let mut partial = Vec::with_capacity(hashes.len());
        let mut output_text_bytes = 0usize;
        for (_hash, (is_complete, persisted_partial)) in hashes.iter().zip(rows) {
            let offer = if let Some(manifest) = persisted_partial.as_ref().and_then(|partial| {
                cache
                    .get(&partial.job_token.job_id)
                    .filter(|manifest| manifest.token == partial.job_token)
            }) {
                if !manifest.completed
                    && !manifest.final_rehash_pending
                    && manifest.md4_hashset_acquired
                    && !manifest.transfer_row_removed
                    && !manifest.verified_ranges.is_empty()
                {
                    let name_len = manifest.display_name.len();
                    let priority_len = manifest.upload_priority.len();
                    anyhow::ensure!(
                        name_len <= 65_536 && priority_len <= 65_536,
                        "live partial offer exceeds per-entry bound"
                    );
                    let next = output_text_bytes
                        .checked_add(name_len)
                        .and_then(|n| n.checked_add(priority_len))
                        .ok_or_else(|| anyhow::anyhow!("live partial offer batch exceeds bound"))?;
                    if next > 192 * 1024 {
                        break;
                    }
                    output_text_bytes = next;
                    Some(emulebb_metadata::MetadataPartialOffer {
                        job_token: manifest.token,
                        name: manifest.display_name.clone(),
                        size: manifest.file_size,
                        priority: manifest.upload_priority.clone(),
                        rating: manifest.rating,
                    })
                } else {
                    None
                }
            } else {
                if let Some(offer) = &persisted_partial {
                    let next = output_text_bytes
                        .checked_add(offer.name.len())
                        .and_then(|n| n.checked_add(offer.priority.len()))
                        .ok_or_else(|| anyhow::anyhow!("partial offer batch exceeds bound"))?;
                    if next > 192 * 1024 {
                        break;
                    }
                    output_text_bytes = next;
                }
                persisted_partial
            };
            complete.push(is_complete);
            partial.push(offer);
        }
        drop(cache);
        let retained = ShareStripes::indexes(&hashes[..complete.len()]);
        stripes.retain(|(index, _)| retained.binary_search(index).is_ok());
        Ok(Some(SharedEligibilityBatch {
            epoch,
            stripes,
            complete,
            partial,
            _slot: slot,
            _result_lease: result_lease,
        }))
    }

    pub fn requires_revalidation(&self) -> bool {
        self.root_dirty.load(Ordering::Acquire) || self.publication_failed.load(Ordering::Acquire)
    }

    pub fn epoch(&self) -> u64 {
        self.root_epoch.load(Ordering::Acquire)
    }

    pub fn stripe_snapshot(&self, hashes: &[[u8; 16]]) -> Option<Vec<(u8, u64)>> {
        if hashes.len() > 200 {
            return None;
        }
        self.stripes.lock().ok()?.snapshot(hashes)
    }

    pub(crate) fn full_rebuild_snapshot(&self) -> Result<Option<Vec<(u8, u64)>>> {
        let state = self
            .stripes
            .lock()
            .map_err(|_| anyhow::anyhow!("share stripe lock poisoned"))?;
        anyhow::ensure!(!state.faulted, "share stripe generation exhausted");
        Ok(state.snapshot_all())
    }

    pub(crate) fn publish_full_rebuild(
        &self,
        snapshot: &[(u8, u64)],
        catalog: &mut IndexedSharedCatalog,
        rebuilt: &mut IndexedSharedCatalog,
    ) -> bool {
        let Ok(state) = self.stripes.lock() else {
            return false;
        };
        if !state.matches(snapshot) {
            return false;
        }
        catalog.replace_rebuilt(rebuilt);
        self.publication_failed.store(false, Ordering::Release);
        true
    }

    /// Complete payload candidates were physically checked by the retained
    /// worker. Validate only their stripes; unrelated content cannot starve a
    /// page. Existing complete local copies keep precedence.
    pub(crate) fn publish_payload_page(
        &self,
        snapshot: &[(u8, u64)],
        catalog: &mut IndexedSharedCatalog,
        entries: Vec<Ed2kSharedEntry>,
    ) -> Result<Option<usize>> {
        let hashes = entries
            .iter()
            .map(|entry| entry.file_hash.parse::<Ed2kHash>().map(|h| h.0))
            .collect::<Result<Vec<_>, _>>()?;
        let indexes = ShareStripes::indexes(&hashes);
        let selected = snapshot
            .iter()
            .copied()
            .filter(|(index, _)| indexes.contains(index))
            .collect::<Vec<_>>();
        let state = self
            .stripes
            .lock()
            .map_err(|_| anyhow::anyhow!("share stripe lock poisoned"))?;
        if !state.matches(&selected) {
            return Ok(None);
        }
        let mut inserted = 0;
        for (mut entry, hash) in entries.into_iter().zip(hashes) {
            let hash = Ed2kHash::from_bytes(hash);
            if catalog
                .entry_by_hash(&hash)
                .is_some_and(|old| old.verified_complete)
            {
                continue;
            }
            if let Some(old) = catalog.entry_by_hash(&hash) {
                entry.publish = old.publish.clone();
                entry.all_time_uploaded_bytes = entry
                    .all_time_uploaded_bytes
                    .max(old.all_time_uploaded_bytes);
            }
            catalog.upsert_verified(hash, Some(entry));
            inserted += 1;
        }
        Ok(Some(inserted))
    }

    pub(crate) fn begin_mutation(&self, hashes: &[[u8; 16]]) -> Result<SharedFileMutation> {
        anyhow::ensure!(
            !hashes.is_empty() && hashes.len() <= 2,
            "invalid share mutation identity count"
        );
        let indexes = ShareStripes::indexes(hashes);
        let mut state = self
            .stripes
            .lock()
            .map_err(|_| anyhow::anyhow!("share stripe lock poisoned"))?;
        anyhow::ensure!(
            !state.faulted
                && indexes.iter().all(|index| {
                    let stripe = state.stripes[usize::from(*index)];
                    stripe.active < u32::MAX
                        && stripe
                            .generation
                            .checked_add(u64::from(stripe.active) + 2)
                            .is_some()
                }),
            "share stripe generation exhausted"
        );
        for index in &indexes {
            let stripe = &mut state.stripes[usize::from(*index)];
            stripe.active += 1;
            stripe.generation += 1;
        }
        drop(state);
        Ok(SharedFileMutation {
            stripes: Arc::clone(&self.stripes),
            indexes,
        })
    }

    pub async fn drain(&self) -> Result<()> {
        {
            let _cut = self
                .stripes
                .lock()
                .map_err(|_| anyhow::anyhow!("share stripe lock poisoned"))?;
            self.sealed.store(true, Ordering::Release);
        }
        let mut slot = self.read_slot.lock().await;
        if let Some(task) = slot.as_mut() {
            let outcome = task.await;
            slot.take();
            outcome.context("eligibility read owner stopped")??;
        }
        Ok(())
    }
}

/// Ordered shared-file catalog paired with an O(1) raw-hash index.
///
/// `entries` is the ordered source of truth. `by_hash` is an ADDITIONAL lookup
/// structure mapping the raw 16-byte MD4 file hash to the index of the unique
/// non-compatibility-hint entry carrying that hash - the exact entry every by-hash
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
#[derive(Debug, Clone)]
pub struct IndexedSharedCatalog {
    entries: Vec<Ed2kSharedEntry>,
    by_hash: HashMap<[u8; 16], usize>,
    completed_verified_count: usize,
    category_watch: Option<([u8; 16], u64)>,
    category_watch_sequence: Option<u64>,
    eligibility: Option<Arc<SharedEligibility>>,
}

impl Default for IndexedSharedCatalog {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            by_hash: HashMap::new(),
            completed_verified_count: 0,
            category_watch: None,
            category_watch_sequence: Some(0),
            eligibility: None,
        }
    }
}

impl IndexedSharedCatalog {
    pub(crate) fn set_eligibility(&mut self, eligibility: Arc<SharedEligibility>) {
        self.eligibility = Some(eligibility);
    }

    pub fn eligibility(&self) -> Option<Arc<SharedEligibility>> {
        self.eligibility.clone()
    }

    /// Called under the catalog read lock to admit one already-owned packet.
    pub fn admit_eligibility_batch(&self, batch: &SharedEligibilityBatch) -> bool {
        self.eligibility.as_ref().is_some_and(|provider| {
            let Ok(state) = provider.stripes.lock() else {
                return false;
            };
            !provider.sealed.load(Ordering::Acquire)
                && provider.root_epoch.load(Ordering::Acquire) == batch.epoch
                && state.matches(&batch.stripes)
        })
    }

    pub fn admit_clean_epoch(&self, epoch: u64, stripes: &[(u8, u64)]) -> bool {
        self.eligibility.as_ref().is_some_and(|provider| {
            let Ok(state) = provider.stripes.lock() else {
                return false;
            };
            provider.epoch() == epoch
                && epoch % 2 == 0
                && !provider.requires_revalidation()
                && !provider.sealed.load(Ordering::Acquire)
                && state.matches(stripes)
        })
    }

    pub fn admit_revalidated_epoch(&self, epoch: u64, stripes: &[(u8, u64)]) -> bool {
        self.eligibility.as_ref().is_some_and(|provider| {
            let Ok(state) = provider.stripes.lock() else {
                return false;
            };
            provider.epoch() == epoch
                && epoch % 2 == 0
                && !provider.sealed.load(Ordering::Acquire)
                && state.matches(stripes)
        })
    }
    /// Install the single bounded root-reconciliation watch under the catalog lock.
    pub fn watch_category_hash(&mut self, hash: [u8; 16]) -> Option<u64> {
        self.category_watch = None;
        self.category_watch_sequence = self
            .category_watch_sequence
            .and_then(|value| value.checked_add(1));
        let next = self.category_watch_sequence?;
        self.category_watch = Some((hash, next));
        Some(next)
    }

    /// Check and retire a watch while holding the same lock as publication.
    pub fn finish_category_watch(&mut self, hash: [u8; 16], token: u64) -> bool {
        if self.category_watch == Some((hash, token)) {
            self.category_watch = None;
            true
        } else {
            false
        }
    }

    fn invalidate_category_watch(&mut self, hash: Option<[u8; 16]>) {
        if self
            .category_watch
            .is_some_and(|(watched, _)| hash.is_none_or(|key| key == watched))
        {
            self.category_watch = None;
        }
    }

    /// Build an indexed catalog from an ordered entry list.
    #[must_use]
    pub fn from_entries(entries: Vec<Ed2kSharedEntry>) -> Self {
        let mut catalog = Self {
            entries,
            by_hash: HashMap::new(),
            completed_verified_count: 0,
            category_watch: None,
            category_watch_sequence: Some(0),
            eligibility: None,
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
        self.completed_verified_count = 0;
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.compatibility_hint {
                continue;
            }
            self.completed_verified_count += usize::from(entry.verified_complete);
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

    /// Number of active, fully verified local files exposed by the shared-file
    /// REST collection. This is maintained with the hash index so a UI/status
    /// poll over a 100k-file library does not rescan SQLite merely to return its
    /// `total` field.
    #[must_use]
    pub fn completed_verified_len(&self) -> usize {
        self.completed_verified_count
    }

    /// Append an entry, keeping the by-hash index in sync. A non-hint entry is
    /// indexed at its new tail position, first-occurrence-wins so an earlier
    /// duplicate keeps ownership (matching the old first-match scan).
    pub fn push(&mut self, entry: Ed2kSharedEntry) {
        self.invalidate_category_watch(Self::entry_hash_key(&entry));
        let idx = self.entries.len();
        if !entry.compatibility_hint && entry.verified_complete {
            self.completed_verified_count += 1;
        }
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
        self.invalidate_category_watch(None);
        self.entries.retain(keep);
        self.rebuild_index();
    }

    /// Replace the whole ordered entry list and rebuild the index.
    pub fn replace_with(&mut self, entries: Vec<Ed2kSharedEntry>) {
        self.invalidate_category_watch(None);
        self.entries = entries;
        self.rebuild_index();
    }

    /// Publish the prepared projection without another whole-library vector.
    /// Live partial progress wins over a persisted partial, while a verified
    /// complete copy wins over either. Preserve counters updated during the read.
    fn replace_rebuilt(&mut self, rebuilt: &mut Self) {
        self.invalidate_category_watch(None);
        for current in &self.entries {
            if current.compatibility_hint {
                rebuilt.push(current.clone());
                continue;
            }
            let Some(hash) = Self::entry_hash_key(current) else {
                continue;
            };
            if let Some(&index) = rebuilt.by_hash.get(&hash) {
                let next = &mut rebuilt.entries[index];
                if !next.verified_complete && !current.verified_complete {
                    *next = current.clone();
                } else {
                    next.publish = current.publish.clone();
                    next.all_time_uploaded_bytes = next
                        .all_time_uploaded_bytes
                        .max(current.all_time_uploaded_bytes);
                }
            } else if !current.verified_complete {
                rebuilt.push(current.clone());
            }
        }
        self.entries = std::mem::take(&mut rebuilt.entries);
        self.by_hash = std::mem::take(&mut rebuilt.by_hash);
        self.completed_verified_count = rebuilt.completed_verified_count;
        rebuilt.completed_verified_count = 0;
    }

    /// Upsert a verified entry in place: drop the entries `keep` rejects, append
    /// `new_entry` when present, canonicalise the survivors through `dedup`, and
    /// rebuild the by-hash index ONCE.
    ///
    /// The owned inner `Vec` is moved through `dedup` via [`std::mem::take`], so
    /// entries are MOVED, never deep cloned - this replaces the previous
    /// `retain` -> `to_vec` (whole-catalog deep clone) -> `dedup` -> `replace_with`
    /// chain, which cloned every entry (and its inner `Vec`s) on each mutation.
    ///
    /// The end state is byte-identical to that chain: `keep` filters in place
    /// (same predicate), the appended entry lands at the tail, `dedup` sees the
    /// exact same ordered list `to_vec` would have produced, and the final index
    /// is a single wholesale rebuild over the deduped order (first occurrence
    /// wins, compatibility hints excluded).
    pub fn retain_push_dedup(
        &mut self,
        keep: impl FnMut(&Ed2kSharedEntry) -> bool,
        new_entry: Option<Ed2kSharedEntry>,
        dedup: impl FnOnce(Vec<Ed2kSharedEntry>) -> Vec<Ed2kSharedEntry>,
    ) {
        self.invalidate_category_watch(None);
        self.entries.retain(keep);
        if let Some(entry) = new_entry {
            self.entries.push(entry);
        }
        self.entries = dedup(std::mem::take(&mut self.entries));
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
        self.invalidate_category_watch(Some(hash.0));
        self.update_by_hash_inner(hash, update)
    }

    /// Update only publication/upload counters without invalidating eligibility work.
    pub fn update_stats_by_hash(
        &mut self,
        hash: &Ed2kHash,
        update: impl FnOnce(&mut Ed2kSharedEntry),
    ) -> bool {
        self.update_by_hash_inner(hash, update)
    }

    fn update_by_hash_inner(
        &mut self,
        hash: &Ed2kHash,
        update: impl FnOnce(&mut Ed2kSharedEntry),
    ) -> bool {
        if let Some(&idx) = self.by_hash.get(&hash.0) {
            let was_completed = self.entries[idx].verified_complete;
            update(&mut self.entries[idx]);
            let is_completed = self.entries[idx].verified_complete;
            match (was_completed, is_completed) {
                (false, true) => self.completed_verified_count += 1,
                (true, false) => self.completed_verified_count -= 1,
                _ => {}
            }
            true
        } else {
            false
        }
    }

    /// Borrow the unique verified/non-hint catalog entry for `hash` in O(1).
    #[must_use]
    pub fn entry_by_hash(&self, hash: &Ed2kHash) -> Option<&Ed2kSharedEntry> {
        self.by_hash.get(&hash.0).map(|&idx| &self.entries[idx])
    }

    /// Insert, replace, or remove one verified catalog entry without rebuilding
    /// the complete by-hash index.
    ///
    /// Initial large-library ingestion calls this once per hashed file.  The old
    /// retain/deduplicate/reindex path walked the complete catalog for every file,
    /// making a fresh N-file ingest quadratic.  A verified hash is unique by
    /// construction, so replacement can stay in its existing slot and insertion
    /// can append. Removal uses `swap_remove` and repairs only the moved entry's
    /// index. Compatibility hints are deliberately untouched.
    pub fn upsert_verified(&mut self, hash: Ed2kHash, new_entry: Option<Ed2kSharedEntry>) {
        self.invalidate_category_watch(Some(hash.0));
        if let Some(entry) = new_entry.as_ref() {
            debug_assert!(!entry.compatibility_hint);
            debug_assert_eq!(Self::entry_hash_key(entry), Some(hash.0));
        }

        match (self.by_hash.get(&hash.0).copied(), new_entry) {
            (Some(idx), Some(entry)) => {
                self.completed_verified_count = self
                    .completed_verified_count
                    .saturating_sub(usize::from(self.entries[idx].verified_complete))
                    .saturating_add(usize::from(entry.verified_complete));
                self.entries[idx] = entry;
            }
            (None, Some(entry)) => {
                let idx = self.entries.len();
                self.completed_verified_count += usize::from(entry.verified_complete);
                self.entries.push(entry);
                self.by_hash.insert(hash.0, idx);
            }
            (Some(idx), None) => {
                self.completed_verified_count = self
                    .completed_verified_count
                    .saturating_sub(usize::from(self.entries[idx].verified_complete));
                self.by_hash.remove(&hash.0);
                self.entries.swap_remove(idx);
                if idx < self.entries.len() {
                    let moved = &self.entries[idx];
                    if !moved.compatibility_hint
                        && let Some(moved_hash) = Self::entry_hash_key(moved)
                    {
                        self.by_hash.insert(moved_hash, idx);
                    }
                }
            }
            (None, None) => {}
        }

        #[cfg(debug_assertions)]
        self.assert_index_consistent();
    }

    /// Apply `mutate` to every entry, then rebuild the index. Used off the hot path
    /// where a mutation could in principle touch a field the index depends on; the
    /// wholesale rebuild guarantees the index cannot drift regardless of what
    /// `mutate` does.
    pub fn mutate_all(&mut self, mutate: impl FnMut(&mut Ed2kSharedEntry)) {
        self.invalidate_category_watch(None);
        self.entries.iter_mut().for_each(mutate);
        self.rebuild_index();
    }

    /// Validate that the by-hash index and completed counter are perfectly
    /// consistent with `entries`:
    /// every indexed hash points to a non-hint entry actually carrying that hash,
    /// and every non-hint entry with a parseable hash is reachable via the index at
    /// its first occurrence. Used by tests (and debug builds) to assert the
    /// sync-on-every-mutator invariant.
    #[cfg(any(test, debug_assertions))]
    pub(crate) fn assert_index_consistent(&self) {
        assert_eq!(
            self.completed_verified_count,
            self.entries
                .iter()
                .filter(|entry| !entry.compatibility_hint && entry.verified_complete)
                .count(),
            "cached completed verified count does not match catalog entries",
        );
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
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kMediaMetadata {
    /// Track/stream artist, truncated to the stock 80-character ceiling.
    #[serde(default)]
    pub artist: String,
    /// Album/product name, truncated to the stock 80-character ceiling.
    #[serde(default)]
    pub album: String,
    /// Embedded media title, truncated to the stock 80-character ceiling.
    #[serde(default)]
    pub title: String,
    /// Whole media duration in seconds.
    #[serde(default)]
    pub length_seconds: u32,
    /// Average media bitrate in kilobits per second.
    #[serde(default)]
    pub bitrate_kbps: u32,
    /// Container/stream codec label, truncated to 80 characters.
    #[serde(default)]
    pub codec: String,
}

/// One persisted or hinted ED2K shared-file entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kSharedEntry {
    /// Stable ED2K file hash in lowercase hex.
    pub file_hash: String,
    /// Canonical file name used in offer-files and filename answers.
    pub display_name: String,
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
    /// Media properties published in server offers and Kad keyword entries.
    #[serde(default)]
    pub media: Ed2kMediaMetadata,
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
            display_name: hash.display_name.clone(),
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
            media: Ed2kMediaMetadata::default(),
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
            display_name: manifest.display_name.clone(),
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
            media: Ed2kMediaMetadata::default(),
            all_time_uploaded_bytes: 0,
            complete_parts,
            publish: Ed2kSharedPublishStats::default(),
        }
    }

    /// Build a partial entry from the bounded transfer-only projection.
    #[must_use]
    pub(crate) fn from_partial_share(partial: emulebb_metadata::MetadataPartialShare) -> Self {
        let ranges: Vec<Ed2kSharedRange> = partial
            .ranges
            .into_iter()
            .map(|range| Ed2kSharedRange {
                start: range.start,
                end: range.end,
            })
            .collect();
        let count = usize::from(ed2k_part_count(partial.file_size));
        let mut complete_parts = Vec::with_capacity(count);
        let mut range_index = 0;
        for part in 0..count {
            let start = part as u64 * ED2K_PART_SIZE;
            let end = (start + ED2K_PART_SIZE).min(partial.file_size);
            while range_index < ranges.len() && ranges[range_index].end < end {
                range_index += 1;
            }
            complete_parts.push(
                start >= partial.file_size
                    || ranges
                        .get(range_index)
                        .is_some_and(|range| range.start <= start && end <= range.end),
            );
        }
        Self {
            file_hash: partial.file_hash,
            display_name: partial.display_name,
            file_size: partial.file_size,
            verified_complete: false,
            verified_ranges: ranges,
            compatibility_hint: false,
            source_count_hint: None,
            aich_root: partial.aich_root,
            upload_priority: partial.upload_priority,
            auto_upload_priority: partial.auto_upload_priority,
            comment: partial.comment,
            rating: partial.rating,
            media: Ed2kMediaMetadata::default(),
            all_time_uploaded_bytes: 0,
            complete_parts,
            publish: Ed2kSharedPublishStats::default(),
        }
    }

    #[must_use]
    pub fn from_serving_view(manifest: &super::Ed2kFileServingView) -> Self {
        let complete_parts = if manifest.completed {
            // A complete file serves the whole payload; the part-status answer
            // collapses to the master "complete" sentinel, so no per-part vector.
            Vec::new()
        } else {
            complete_parts_from_ranges(manifest.file_size, &manifest.verified_ranges)
        };
        Self {
            file_hash: manifest.file_hash.clone(),
            display_name: manifest.display_name.clone(),
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
            media: Ed2kMediaMetadata::default(),
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

    #[tokio::test]
    async fn eligibility_reads_are_bounded_and_single_slot() {
        let maximum_workspace = 2 * 200 * std::mem::size_of::<[u8; 16]>()
            + 2 * 200 * std::mem::size_of::<(u8, u64)>()
            + 2 * 200
                * std::mem::size_of::<(bool, Option<emulebb_metadata::MetadataPartialOffer>)>()
            + 200 * 32
            + 4096
            + 4 * 192 * 1024;
        assert!(maximum_workspace <= 1024 * 1024);
        let epoch = Arc::new(AtomicU64::new(0));
        let provider = SharedEligibility::new(
            emulebb_metadata::MetadataStore::in_memory().unwrap(),
            Arc::clone(&epoch),
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(std::sync::Mutex::new(ShareStripes::default())),
            Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            Arc::new(super::super::local_mutation::LocalMutationRegistry::default()),
        );
        assert!(provider.try_batch(&[[0; 16]; 201]).await.is_err());
        let first = provider.try_batch(&[[1; 16]]).await.unwrap().unwrap();
        assert_eq!(first.complete, vec![false]);
        assert_eq!(first.partial, vec![None]);
        assert!(provider.try_batch(&[[2; 16]]).await.unwrap().is_none());
        drop(first);
        epoch.store(1, Ordering::Release);
        assert!(provider.try_batch(&[[2; 16]]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn eligibility_drain_seals_before_waiting_for_the_inflight_batch() {
        let provider = Arc::new(SharedEligibility::new(
            emulebb_metadata::MetadataStore::in_memory().unwrap(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(std::sync::Mutex::new(ShareStripes::default())),
            Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            Arc::new(super::super::local_mutation::LocalMutationRegistry::default()),
        ));
        let batch = provider.try_batch(&[[1; 16]]).await.unwrap().unwrap();
        let draining = {
            let provider = Arc::clone(&provider);
            tokio::spawn(async move { provider.drain().await })
        };
        while !provider.sealed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        assert!(!draining.is_finished());
        assert!(provider.try_batch(&[[2; 16]]).await.unwrap().is_none());
        drop(batch);
        draining.await.unwrap().unwrap();
        assert!(provider.try_batch(&[[3; 16]]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn packet_admission_rejects_an_epoch_changed_before_admission() {
        let epoch = Arc::new(AtomicU64::new(0));
        let provider = Arc::new(SharedEligibility::new(
            emulebb_metadata::MetadataStore::in_memory().unwrap(),
            Arc::clone(&epoch),
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(std::sync::Mutex::new(ShareStripes::default())),
            Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            Arc::new(super::super::local_mutation::LocalMutationRegistry::default()),
        ));
        let mut catalog = IndexedSharedCatalog::default();
        catalog.set_eligibility(Arc::clone(&provider));
        let batch = provider.try_batch(&[[1; 16]]).await.unwrap().unwrap();
        epoch.store(2, Ordering::Release);
        assert!(!catalog.admit_eligibility_batch(&batch));
        drop(batch);
        let next = provider.try_batch(&[[1; 16]]).await.unwrap().unwrap();
        assert!(catalog.admit_eligibility_batch(&next));
        epoch.store(4, Ordering::Release);
        // The prior owned packet was already admitted; the next one retries.
        assert!(!catalog.admit_eligibility_batch(&next));
    }

    #[test]
    fn share_stripes_detect_inflight_and_completed_mutations_without_wrap() {
        let provider = SharedEligibility::new(
            emulebb_metadata::MetadataStore::in_memory().unwrap(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(std::sync::Mutex::new(ShareStripes::default())),
            Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            Arc::new(super::super::local_mutation::LocalMutationRegistry::default()),
        );
        let hash = [1; 16];
        let snapshot = provider.stripe_snapshot(&[hash]).unwrap();
        let guard = provider.begin_mutation(&[hash, hash]).unwrap();
        assert!(provider.stripe_snapshot(&[hash]).is_none());
        drop(guard);
        assert!(!provider.stripes.lock().unwrap().matches(&snapshot));
        let stripe = ShareStripes::indexes(&[hash])[0];
        provider.stripes.lock().unwrap().stripes[usize::from(stripe)].generation = u64::MAX - 1;
        assert!(provider.begin_mutation(&[hash]).is_err());
    }

    #[test]
    fn category_watch_ignores_unrelated_hashes_but_detects_replacement() {
        let mut catalog = IndexedSharedCatalog::default();
        let watched = [1; 16];
        let token = catalog.watch_category_hash(watched).unwrap();
        catalog.upsert_verified(Ed2kHash::from_bytes([2; 16]), None);
        catalog.update_stats_by_hash(&Ed2kHash::from_bytes(watched), |_| {});
        assert!(catalog.finish_category_watch(watched, token));

        let token = catalog.watch_category_hash(watched).unwrap();
        catalog.upsert_verified(Ed2kHash::from_bytes(watched), None);
        assert!(!catalog.finish_category_watch(watched, token));

        let token = catalog.watch_category_hash(watched).unwrap();
        catalog.replace_with(Vec::new());
        assert!(!catalog.finish_category_watch(watched, token));

        catalog.category_watch_sequence = Some(u64::MAX);
        assert!(catalog.watch_category_hash(watched).is_none());
    }

    #[test]
    fn maximum_partial_projection_fits_category_workspace() {
        let ranges = vec![emulebb_metadata::MetadataTransferRange { start: 0, end: 1 }; 28_258];
        let input_range_bytes =
            ranges.capacity() * std::mem::size_of::<emulebb_metadata::MetadataTransferRange>();
        let partial = emulebb_metadata::MetadataPartialShare {
            job_token: emulebb_metadata::JobToken {
                job_id: emulebb_metadata::JobId::new(1).unwrap(),
                generation: 0,
            },
            file_hash: "11".repeat(16),
            display_name: "n".repeat(65_536),
            file_size: 0x4000000000,
            aich_root: Some("22".repeat(20)),
            upload_priority: "normal".into(),
            auto_upload_priority: false,
            comment: "c".repeat(65_536),
            rating: 0,
            ranges,
        };
        let output = Ed2kSharedEntry::from_partial_share(partial);
        let output_bytes = output.verified_ranges.capacity()
            * std::mem::size_of::<Ed2kSharedRange>()
            + output.complete_parts.capacity()
            + output.display_name.capacity()
            + output.comment.capacity()
            + output.file_hash.capacity()
            + output.upload_priority.capacity()
            + output.aich_root.as_ref().map_or(0, String::capacity);
        // Conservatively include the input allocation during conversion, one
        // maximum native-path candidate and fixed page/allocator headroom.
        assert!(input_range_bytes + output_bytes + 2 * 65_536 + 64 * 1024 < 4 * 1024 * 1024);
    }

    fn hex_hash(nibble: u8) -> String {
        std::iter::repeat_n(format!("{nibble:x}{nibble:x}"), 16).collect()
    }

    fn verified_entry(nibble: u8) -> Ed2kSharedEntry {
        Ed2kSharedEntry {
            file_hash: hex_hash(nibble),
            display_name: format!("file-{nibble}.bin"),
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
            media: Ed2kMediaMetadata::default(),
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
        let catalog = IndexedSharedCatalog::from_entries(vec![
            verified_entry(1),
            verified_entry(2),
            verified_entry(3),
        ]);
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
        let mut catalog = IndexedSharedCatalog::from_entries(vec![
            verified_entry(1),
            verified_entry(2),
            verified_entry(3),
        ]);
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
        let mut catalog =
            IndexedSharedCatalog::from_entries(vec![verified_entry(1), verified_entry(2)]);
        catalog.retain(|entry| entry.file_hash != hex_hash(1));
        assert!(catalog.index_by_hash(&key(1)).is_none());
        catalog.push(verified_entry(1));
        catalog.assert_index_consistent();
        let idx = catalog
            .index_by_hash(&key(1))
            .expect("re-added entry present");
        assert_eq!(catalog[idx].file_hash, hex_hash(1));
    }

    #[test]
    fn rebuilt_projection_preserves_live_partial_progress_hints_and_counters() {
        let mut partial = verified_entry(1);
        partial.verified_complete = false;
        partial.verified_ranges = vec![super::super::Ed2kSharedRange { start: 0, end: 7 }];
        partial.publish.session_request_count = 9;
        let mut complete = verified_entry(2);
        complete.publish.session_request_count = 11;
        complete.all_time_uploaded_bytes = 17;
        let mut hint = verified_entry(3);
        hint.compatibility_hint = true;
        let mut current = IndexedSharedCatalog::from_entries(vec![partial.clone(), complete, hint]);
        let watched = current.watch_category_hash(key(1).0).unwrap();
        let mut persisted_partial = partial.clone();
        persisted_partial.verified_ranges.clear();
        let mut rebuilt =
            IndexedSharedCatalog::from_entries(vec![persisted_partial, verified_entry(2)]);
        current.replace_rebuilt(&mut rebuilt);
        current.assert_index_consistent();
        assert!(rebuilt.is_empty());
        assert!(!current.finish_category_watch(key(1).0, watched));
        assert_eq!(
            current.entry_by_hash(&key(1)).unwrap().verified_ranges,
            partial.verified_ranges
        );
        assert_eq!(
            current
                .entry_by_hash(&key(1))
                .unwrap()
                .publish
                .session_request_count,
            9
        );
        assert_eq!(
            current
                .entry_by_hash(&key(2))
                .unwrap()
                .publish
                .session_request_count,
            11
        );
        assert_eq!(
            current
                .entry_by_hash(&key(2))
                .unwrap()
                .all_time_uploaded_bytes,
            17
        );
        assert_eq!(current.completed_verified_len(), 1);
        assert!(current.iter().any(|entry| entry.compatibility_hint));
    }

    #[test]
    fn bulk_replace_rebuilds_index() {
        let mut catalog =
            IndexedSharedCatalog::from_entries(vec![verified_entry(1), verified_entry(2)]);
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
        let catalog = IndexedSharedCatalog::from_entries(vec![
            hint_entry(1),
            verified_entry(1),
            hint_entry(2),
        ]);
        catalog.assert_index_consistent();
        let idx = catalog
            .index_by_hash(&key(1))
            .expect("verified entry present");
        assert!(!catalog[idx].compatibility_hint);
        assert!(catalog.index_by_hash(&key(2)).is_none());
    }

    #[test]
    fn verified_upsert_is_indexed_and_preserves_compatibility_hints() {
        let mut catalog = IndexedSharedCatalog::from_entries(vec![
            hint_entry(1),
            verified_entry(1),
            verified_entry(2),
        ]);
        let mut replacement = verified_entry(1);
        replacement.all_time_uploaded_bytes = 99;

        catalog.upsert_verified(key(1), Some(replacement));
        assert_eq!(
            catalog
                .entry_by_hash(&key(1))
                .unwrap()
                .all_time_uploaded_bytes,
            99
        );
        assert_eq!(
            catalog
                .iter()
                .filter(|entry| entry.compatibility_hint && entry.file_hash == hex_hash(1))
                .count(),
            1
        );

        catalog.upsert_verified(key(1), None);
        catalog.assert_index_consistent();
        assert!(catalog.entry_by_hash(&key(1)).is_none());
        assert!(catalog.entry_by_hash(&key(2)).is_some());
        assert!(
            catalog
                .iter()
                .any(|entry| entry.compatibility_hint && entry.file_hash == hex_hash(1))
        );

        catalog.upsert_verified(key(3), Some(verified_entry(3)));
        catalog.assert_index_consistent();
        assert!(catalog.entry_by_hash(&key(3)).is_some());
    }

    #[test]
    fn update_by_hash_targets_only_matching_verified_entry() {
        let mut catalog =
            IndexedSharedCatalog::from_entries(vec![verified_entry(1), verified_entry(2)]);
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
                entry.all_time_uploaded_bytes =
                    entry.all_time_uploaded_bytes.saturating_add(FRAGMENT);
                entry.publish.session_uploaded_bytes = entry
                    .publish
                    .session_uploaded_bytes
                    .saturating_add(FRAGMENT);
            });
        }
        let idx = catalog.index_by_hash(&key(1)).unwrap();
        assert_eq!(catalog[idx].all_time_uploaded_bytes, FRAGMENT * FRAGMENTS);
        assert_eq!(
            catalog[idx].publish.session_uploaded_bytes,
            FRAGMENT * FRAGMENTS
        );
    }

    #[test]
    fn mutate_all_keeps_index_consistent() {
        let mut catalog = IndexedSharedCatalog::from_entries(vec![
            verified_entry(1),
            verified_entry(2),
            hint_entry(3),
        ]);
        catalog.mutate_all(|entry| entry.publish.last_ed2k_publish_unix_ms = 7);
        catalog.assert_index_consistent();
        assert!(
            catalog
                .iter()
                .all(|entry| entry.publish.last_ed2k_publish_unix_ms == 7)
        );
    }
}
