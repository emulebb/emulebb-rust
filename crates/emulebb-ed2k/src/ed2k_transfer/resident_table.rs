//! Charged sorted storage with insertion space retained across owned SQL work.
use super::{
    LocalMutationError,
    resident::{ResidentBytes, ResidentControl},
};
use anyhow::{Context, Result};
use std::{
    ops::Index,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

pub(super) type ResidentCache = ResidentTable<emulebb_metadata::JobId, super::ResidentManifest>;

#[derive(Debug)]
struct Claims {
    pending: AtomicUsize,
    _credit: ResidentBytes,
}

/// One accepted owner's insertion space. Drop cancels without an async lock.
#[derive(Debug)]
pub(super) struct InsertionClaim {
    claims: Arc<Claims>,
}
impl Drop for InsertionClaim {
    fn drop(&mut self) {
        let previous = self.claims.pending.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
        self.claims._credit.wake();
    }
}

#[derive(Debug)]
pub(super) struct ResidentTable<K, V> {
    // Storage is freed before its charge; values own their independent backing.
    entries: Vec<(K, V)>,
    storage: ResidentBytes,
    claims: Arc<Claims>,
    control: Arc<ResidentControl>,
}

impl<K: Ord, V> ResidentTable<K, V> {
    pub(super) fn new(control: Arc<ResidentControl>) -> Result<Self> {
        // Same fixed allocation allowance used for resident Arc backing. No
        // assumptions about private HashMap buckets or BTreeMap nodes are needed.
        let fixed = size_of::<Claims>() + size_of::<tokio::sync::Mutex<Self>>() + 128;
        let credit = control.reserve_bytes(fixed)?;
        let claims = Arc::new(Claims {
            pending: AtomicUsize::new(0),
            _credit: credit,
        });
        let storage = control.reserve_bytes(0)?;
        Ok(Self {
            entries: Vec::new(),
            storage,
            claims,
            control,
        })
    }

    fn position(&self, key: &K) -> std::result::Result<usize, usize> {
        self.entries
            .binary_search_by(|(existing, _)| existing.cmp(key))
    }

    pub(super) fn get(&self, key: &K) -> Option<&V> {
        self.position(key).ok().map(|i| &self.entries[i].1)
    }
    pub(super) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.position(key).ok().map(|i| &mut self.entries[i].1)
    }
    pub(super) fn contains_key(&self, key: &K) -> bool {
        self.position(key).is_ok()
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, value)| value)
    }

    /// Reserve peak old+new storage before moving entries. Installation and
    /// every later claimed insertion require no further resident admission.
    pub(super) fn claim_insert(&mut self) -> Result<InsertionClaim> {
        self.reclaim_empty();
        let needed = self
            .entries
            .len()
            .checked_add(self.claims.pending.load(Ordering::Acquire))
            .and_then(|v| v.checked_add(1))
            .ok_or(LocalMutationError::TooLarge)?;
        if needed > self.entries.capacity() {
            let target = needed
                .checked_next_power_of_two()
                .ok_or(LocalMutationError::TooLarge)?;
            let bytes = target
                .checked_mul(size_of::<(K, V)>())
                .ok_or(LocalMutationError::TooLarge)?;
            let mut credit = self.control.reserve_bytes(bytes)?;
            let mut replacement = Vec::new();
            replacement
                .try_reserve_exact(target)
                .context("failed to allocate resident table storage")?;
            let actual = replacement
                .capacity()
                .checked_mul(size_of::<(K, V)>())
                .ok_or(LocalMutationError::TooLarge)?;
            credit.resize(actual)?;
            replacement.append(&mut self.entries);
            let old = std::mem::replace(&mut self.entries, replacement);
            let old_credit = std::mem::replace(&mut self.storage, credit);
            drop(old);
            drop(old_credit);
        }
        self.claims.pending.fetch_add(1, Ordering::AcqRel);
        Ok(InsertionClaim {
            claims: Arc::clone(&self.claims),
        })
    }

    /// The claim binds to this table. Its space survives other insertions,
    /// removals, caller cancellation and SQL waits until this owner publishes.
    pub(super) fn insert_claimed(&mut self, key: K, value: V, claim: InsertionClaim) -> Option<V> {
        assert!(
            Arc::ptr_eq(&self.claims, &claim.claims),
            "resident table claim belongs to another owner"
        );
        match self.position(&key) {
            Ok(index) => Some(std::mem::replace(&mut self.entries[index].1, value)),
            Err(index) => {
                assert!(
                    self.entries.len() < self.entries.capacity(),
                    "resident table insertion lacks reserved storage"
                );
                self.entries.insert(index, (key, value));
                None
            }
        }
    }

    pub(super) fn remove(&mut self, key: &K) -> Option<V> {
        let value = self.position(key).ok().map(|i| self.entries.remove(i).1);
        self.reclaim_empty();
        value
    }

    /// An outstanding claim pins its spare capacity. After rollback, the next
    /// edit reclaims an empty buffer; any retained spare remains fully charged.
    pub(super) fn reclaim_empty(&mut self) {
        if self.entries.is_empty() && self.claims.pending.load(Ordering::Acquire) == 0 {
            self.entries = Vec::new();
            self.storage.release();
        }
    }

    #[cfg(test)]
    pub(super) fn charged_bytes(&self) -> usize {
        self.storage.bytes() + self.claims._credit.bytes()
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Fixture construction still admits its table backing before insertion.
    #[cfg(test)]
    pub(super) fn insert_fixture(&mut self, key: K, value: V) -> Option<V> {
        let claim = self.claim_insert().expect("fixture table capacity");
        self.insert_claimed(key, value, claim)
    }
}

impl<K: Ord, V> Index<&K> for ResidentTable<K, V> {
    type Output = V;
    fn index(&self, key: &K) -> &V {
        self.get(key).expect("resident table key is absent")
    }
}

#[cfg(test)]
mod tests;
