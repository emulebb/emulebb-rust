//! Search/publish concurrency control (oracle `CSearchManager`).
//!
//! The oracle `CSearchManager` enforces two things the Rust node previously
//! left unguarded:
//!
//! - **Per-target dedup.** `CSearchManager::AlreadySearchingFor(target)` rejects
//!   a new search for a target that is already being searched
//!   (`m_mapSearches` is keyed by `m_uTarget`), so a duplicate same-target
//!   search is dropped rather than launched twice.
//! - **A bounded number of concurrent searches.** The Rust node carries a
//!   `Semaphore` for this purpose, but the permit was never acquired
//!   ("reserved for future use").
//!
//! [`SearchConcurrency`] combines both: callers ask for a [`SearchPermit`] for a
//! target; a duplicate same-target request returns `None` (coalesced/dropped),
//! otherwise the call waits for a semaphore slot and returns an RAII permit. The
//! permit releases the semaphore slot and removes the target from the in-flight
//! set on drop, so every exit path (including a panic that unwinds through the
//! held permit) frees the resources.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use emulebb_kad_proto::NodeId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Shared search/publish concurrency state for a single [`super::DhtNode`].
#[derive(Clone)]
pub(crate) struct SearchConcurrency {
    semaphore: Arc<Semaphore>,
    in_flight: Arc<Mutex<HashSet<NodeId>>>,
    max_concurrent: usize,
}

impl SearchConcurrency {
    /// Build a concurrency guard that allows `max_concurrent` simultaneous
    /// traversals. `max_concurrent` is clamped to at least 1 so the node can
    /// always make progress even if mis-configured to 0.
    pub(crate) fn new(max_concurrent: usize) -> Self {
        let max_concurrent = max_concurrent.max(1);
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            in_flight: Arc::new(Mutex::new(HashSet::new())),
            max_concurrent,
        }
    }

    pub(crate) fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Acquire a permit for `target`.
    ///
    /// Returns `None` when a search for the same target is already in flight
    /// (oracle `AlreadySearchingFor`): the duplicate is coalesced/dropped. When
    /// the target is new this waits for a free concurrency slot and returns an
    /// RAII [`SearchPermit`]; dropping it frees the slot and the target.
    pub(crate) async fn acquire(&self, target: NodeId) -> Option<SearchPermit> {
        // Reserve the target first so a duplicate is rejected without consuming
        // a semaphore slot. If insertion fails the target is already in flight.
        {
            let mut in_flight = self.in_flight.lock().expect("in-flight set poisoned");
            if !in_flight.insert(target) {
                return None;
            }
        }

        // `acquire_owned` only errors if the semaphore is closed, which we never
        // do; on the (impossible) error path release the target we just claimed.
        match Arc::clone(&self.semaphore).acquire_owned().await {
            Ok(permit) => Some(SearchPermit {
                _permit: permit,
                target,
                in_flight: Arc::clone(&self.in_flight),
            }),
            Err(_) => {
                self.in_flight
                    .lock()
                    .expect("in-flight set poisoned")
                    .remove(&target);
                None
            }
        }
    }
}

/// RAII guard for one in-flight search/publish traversal.
///
/// Holding it keeps one semaphore slot and one in-flight-target entry reserved;
/// dropping it (normal return *or* unwind) releases both.
pub(crate) struct SearchPermit {
    _permit: OwnedSemaphorePermit,
    target: NodeId,
    in_flight: Arc<Mutex<HashSet<NodeId>>>,
}

impl Drop for SearchPermit {
    fn drop(&mut self) {
        if let Ok(mut in_flight) = self.in_flight.lock() {
            in_flight.remove(&self.target);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 16])
    }

    #[tokio::test]
    async fn duplicate_same_target_is_dropped() {
        let guard = SearchConcurrency::new(5);
        let first = guard.acquire(target(1)).await;
        assert!(first.is_some(), "first search acquires");
        let dup = guard.acquire(target(1)).await;
        assert!(dup.is_none(), "duplicate same-target search is dropped");

        // A different target is still allowed concurrently.
        let other = guard.acquire(target(2)).await;
        assert!(other.is_some(), "different target acquires");
    }

    #[tokio::test]
    async fn permit_drop_releases_target_and_slot() {
        let guard = SearchConcurrency::new(1);
        {
            let permit = guard.acquire(target(1)).await;
            assert!(permit.is_some());
            // Slot is taken; a different target cannot acquire (cap is 1) without
            // blocking. Use try via timeout to avoid hanging the test.
            let blocked = tokio::time::timeout(
                std::time::Duration::from_millis(20),
                guard.acquire(target(2)),
            )
            .await;
            assert!(
                blocked.is_err(),
                "second target blocks while the only slot is held"
            );
        }
        // After drop, the same target can be searched again and the slot frees.
        let again = guard.acquire(target(1)).await;
        assert!(again.is_some(), "target released after permit drop");
    }

    #[tokio::test]
    async fn permit_release_on_unwind() {
        // A panic that unwinds through a held permit must still release the
        // target and slot (Drop runs during unwind).
        let guard = SearchConcurrency::new(1);
        let guard_clone = guard.clone();
        let handle = tokio::spawn(async move {
            let _permit = guard_clone.acquire(target(7)).await.expect("acquire");
            panic!("worker panic with permit held");
        });
        assert!(handle.await.is_err(), "worker panicked");

        // The target and slot must be free again.
        let after = guard.acquire(target(7)).await;
        assert!(after.is_some(), "permit released on unwind");
    }
}
