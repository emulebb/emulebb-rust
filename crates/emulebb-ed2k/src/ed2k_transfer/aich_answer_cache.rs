//! Bounded recovery proof work, keyed only by immutable content metadata.
use super::aich_recovery::AichRecoveryHashSet;
use anyhow::Result;
use emulebb_metadata::MetadataStore;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Mutex, OnceLock},
};
use tokio::sync::{Semaphore, SemaphorePermit};

type Key = ([u8; 20], u64, u16);
const BYTE_LIMIT: usize = 64 * 1024 * 1024;
static WORK: Semaphore = Semaphore::const_new(2);
static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();

#[derive(Default)]
struct Cache {
    ready: HashMap<Key, Vec<u8>>,
    order: VecDeque<Key>,
    inflight: HashSet<Key>,
    bytes: usize,
}

fn cache() -> &'static Mutex<Cache> {
    CACHE.get_or_init(|| Mutex::new(Cache::default()))
}

/// Admission is immediate: network requests never form an unbounded work queue.
pub(super) fn try_work() -> Option<SemaphorePermit<'static>> {
    WORK.try_acquire().ok()
}

struct Inflight(Key);
impl Drop for Inflight {
    fn drop(&mut self) {
        if let Ok(mut cache) = cache().lock() {
            cache.inflight.remove(&self.0);
        }
    }
}

/// Fingerprint/availability checks must run before calling this metadata-only path.
pub(super) fn answer(
    metadata: &MetadataStore,
    master: [u8; 20],
    size: u64,
    part: u16,
) -> Result<Option<Vec<u8>>> {
    let key = (master, size, part);
    {
        let mut cache = cache()
            .lock()
            .map_err(|_| anyhow::anyhow!("AICH answer cache poisoned"))?;
        if let Some(answer) = cache.ready.get(&key) {
            return Ok(Some(answer.clone()));
        }
        // Coalesce duplicate work without retaining blocked requests. Peers can
        // retry the protocol's recovery-unavailable response while work is busy.
        if !cache.inflight.insert(key) {
            return Ok(None);
        }
    }
    let _inflight = Inflight(key);
    let root = hex::encode(master);
    let Some(leaves) = metadata.aich_recovery_part(&root, size, part)? else {
        return Ok(None);
    };
    let roots = metadata.aich_recovery_roots(&root, size)?;
    let mut set = AichRecoveryHashSet::from_cached_part(size, master, &roots, part, &leaves)?;
    let response = set.create_part_recovery_data(u64::from(part))?;
    // Include generous per-entry bookkeeping in the byte budget, rather than
    // bounding only the count of entries in a potentially huge library.
    let cost = response.capacity() + 256;
    if cost <= BYTE_LIMIT {
        let mut cache = cache()
            .lock()
            .map_err(|_| anyhow::anyhow!("AICH answer cache poisoned"))?;
        while cache.bytes + cost > BYTE_LIMIT {
            let Some(old) = cache.order.pop_front() else {
                break;
            };
            if let Some(answer) = cache.ready.remove(&old) {
                cache.bytes -= answer.capacity() + 256;
            }
        }
        cache.bytes += cost;
        cache.order.push_back(key);
        cache.ready.insert(key, response.clone());
    }
    Ok(Some(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_answers_require_only_saved_metadata_and_validate_against_master() {
        let db = MetadataStore::in_memory().unwrap();
        let parts = vec![vec![0x36; 40]];
        let (master, roots) = super::super::aich_cache::recovery_roots(184_321, &parts).unwrap();
        assert!(answer(&db, master, 184_321, 0).unwrap().is_none());
        db.store_aich_recovery_set(&hex::encode(master), 184_321, &parts, &roots)
            .unwrap();
        let response = answer(&db, master, 184_321, 0).unwrap().unwrap();
        let leaves = super::super::aich_recovery::trusted_part_block_hashes_from_recovery(
            184_321, master, 0, &response,
        )
        .unwrap();
        assert_eq!(leaves, vec![[0x36; 20]; 2]);
        assert_eq!(answer(&db, master, 184_321, 0).unwrap().unwrap(), response);
    }
}
