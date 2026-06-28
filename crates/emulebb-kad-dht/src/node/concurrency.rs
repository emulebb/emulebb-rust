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
//! target; a duplicate same-target request or a saturated concurrency cap is
//! rejected immediately. The permit releases the semaphore slot and removes the
//! target from the in-flight set on drop, so every exit path (including a panic
//! that unwinds through the held permit) frees the resources.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use emulebb_kad_proto::NodeId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SearchAcquireError {
    Duplicate,
    Busy,
    Closed,
}

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

    /// Try to acquire a permit for `target`.
    ///
    /// The oracle does not build an unbounded async wait queue in front of
    /// `m_mapSearches`; if the cap is full, callers retry on their own cadence.
    /// This also keeps cancellation safe: no target is reserved before a
    /// semaphore slot is available.
    pub(crate) fn try_acquire(&self, target: NodeId) -> Result<SearchPermit, SearchAcquireError> {
        let permit = match Arc::clone(&self.semaphore).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => return Err(SearchAcquireError::Busy),
            Err(TryAcquireError::Closed) => return Err(SearchAcquireError::Closed),
        };

        {
            let mut in_flight = self.in_flight.lock().expect("in-flight set poisoned");
            if !in_flight.insert(target) {
                return Err(SearchAcquireError::Duplicate);
            }
        }

        Ok(SearchPermit {
            _permit: permit,
            target,
            in_flight: Arc::clone(&self.in_flight),
        })
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
        let first = guard.try_acquire(target(1));
        assert!(first.is_ok(), "first search acquires");
        let dup = guard.try_acquire(target(1));
        assert_eq!(
            dup.err(),
            Some(SearchAcquireError::Duplicate),
            "duplicate same-target search is dropped"
        );

        // A different target is still allowed concurrently.
        let other = guard.try_acquire(target(2));
        assert!(other.is_ok(), "different target acquires");
    }

    #[tokio::test]
    async fn permit_drop_releases_target_and_slot() {
        let guard = SearchConcurrency::new(1);
        {
            let permit = guard.try_acquire(target(1));
            assert!(permit.is_ok());
            let busy = guard.try_acquire(target(2));
            assert_eq!(
                busy.err(),
                Some(SearchAcquireError::Busy),
                "second target is rejected while the only slot is held"
            );
        }
        // After drop, the same target can be searched again and the slot frees.
        let again = guard.try_acquire(target(1));
        assert!(again.is_ok(), "target released after permit drop");
    }

    #[tokio::test]
    async fn permit_release_on_unwind() {
        // A panic that unwinds through a held permit must still release the
        // target and slot (Drop runs during unwind).
        let guard = SearchConcurrency::new(1);
        let guard_clone = guard.clone();
        let handle = tokio::spawn(async move {
            let _permit = guard_clone.try_acquire(target(7)).expect("acquire");
            panic!("worker panic with permit held");
        });
        assert!(handle.await.is_err(), "worker panicked");

        // The target and slot must be free again.
        let after = guard.try_acquire(target(7));
        assert!(after.is_ok(), "permit released on unwind");
    }
}
