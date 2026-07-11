//! Connection-aware queued-search state machine for `/api/v1/searches`.
//!
//! Operator directive (2026-07-06 parity audit): a search submitted while the
//! relevant backend is not ready (eD2k server session connecting/absent for the
//! `server`/`global` methods, Kad not bootstrapped for `kad`) must be QUEUED —
//! not fired into a stale handle and not silently completed with local-only
//! results. When the backend becomes ready the queue drains automatically, one
//! search per network lane at a time, with gentle spacing between dispatches.
//!
//! This module is the pure state machine (no I/O, no tokio time): callers pass
//! `Instant`s in, so every rule is unit-testable. The async glue (readiness
//! probing, the drain task, dispatch execution) lives in
//! `search_queue_runtime.rs`.
//!
//! Oracle grounding: eMuleBB MFC already queues searches
//! (`SearchResultsWnd.cpp` `m_queuedSearches` + `ProcessSearchQueue`):
//! `SEARCH_QUEUE_SLOT_MS = SEC2MS(5)` spaces queued search starts and a blocked
//! head re-checks at `SEC2MS(1)`. MFC fails a queued search outright when the
//! backend is disconnected at drain time; per the operator directive rust
//! instead keeps waiting for readiness, bounded by `SEARCH_QUEUE_MAX_WAIT`.

use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::SearchCreate;

/// Minimum spacing between queued search dispatches on the SAME network lane
/// while draining. Oracle: MFC `SEARCH_QUEUE_SLOT_MS` (`SearchResultsWnd.cpp`)
/// = `SEC2MS(5)`.
pub(crate) const SEARCH_QUEUE_DRAIN_SLOT: Duration = Duration::from_secs(5);

/// Poll interval of the drain task while queued searches wait for backend
/// readiness or an open lane slot. Oracle: MFC `ProcessSearchQueue` re-arms the
/// queue timer with `SEC2MS(1)` when the head is blocked.
pub(crate) const SEARCH_QUEUE_RECHECK: Duration = Duration::from_secs(1);

/// Cap on simultaneously queued searches. Beyond it the POST fails with an
/// explicit error instead of growing an unbounded backlog (an unattended
/// controller retry-looping POSTs must not amass wire traffic for later).
pub(crate) const SEARCH_QUEUE_CAP: usize = 16;

/// Upper bound on how long a search may wait in the queue for its backend.
/// Expired searches fail with an explicit error status — never a fake
/// "completed". Conservative rust-side bound; no MFC oracle (MFC fails a
/// disconnected queued search immediately instead of waiting).
pub(crate) const SEARCH_QUEUE_MAX_WAIT: Duration = Duration::from_secs(10 * 60);

/// Bounded mid-flight retries: how many times one search may be handed to the
/// server session in total. A dispatch whose send fails on a stale/closing
/// session re-queues and retries on a fresh session; beyond this the search
/// fails with an explicit error (never silently completed-empty).
pub(crate) const SEARCH_QUEUE_MAX_SEND_ATTEMPTS: u32 = 3;

/// Which backend a queued search waits for, from the request `method`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SearchQueueLane {
    /// `server` / `global`: needs the connected eD2k server session.
    Server,
    /// `kad`: needs a bootstrapped Kad node.
    Kad,
    /// `automatic` / empty: dispatches on whichever backend is ready first,
    /// preferring the eD2k server (mirrors `resolve_search_network_method`).
    Auto,
}

impl SearchQueueLane {
    /// Queue lane for a request `method`; `None` for methods that never touch
    /// the network (they keep the immediate local-index-only completion path).
    pub(crate) fn for_method(method: &str) -> Option<Self> {
        match method.trim().to_ascii_lowercase().as_str() {
            "server" | "global" => Some(Self::Server),
            "kad" => Some(Self::Kad),
            "" | "automatic" => Some(Self::Auto),
            _ => None,
        }
    }

    /// Honest `statusReason` token surfaced while a search waits in the queue.
    pub(crate) fn waiting_reason(self) -> &'static str {
        match self {
            Self::Server => "waiting-for-server-connection",
            Self::Kad => "waiting-for-kad",
            Self::Auto => "waiting-for-search-network",
        }
    }
}

/// Live readiness snapshot of the two search backends.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SearchBackendReadiness {
    /// Connected eD2k server session with a usable search handle.
    pub(crate) server: bool,
    /// Kad node bootstrapped.
    pub(crate) kad: bool,
}

/// Concrete network lane a dispatch resolved to (`Auto` collapses here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConcreteSearchLane {
    Server,
    Kad,
}

/// One search waiting in (or re-queued to) the connection-aware queue.
#[derive(Debug, Clone)]
pub(crate) struct QueuedSearch {
    pub(crate) search_id: String,
    pub(crate) request: SearchCreate,
    pub(crate) lane: SearchQueueLane,
    pub(crate) enqueued_at: Instant,
    /// Times this search has been dispatched to a backend (1 after the first
    /// dispatch). Bounded by [`SEARCH_QUEUE_MAX_SEND_ATTEMPTS`].
    pub(crate) send_attempts: u32,
}

/// Explicit enqueue rejections surfaced as POST errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SearchEnqueueError {
    /// An identical query is already waiting on the same lane.
    DuplicateQueued,
    /// The queue is at [`SEARCH_QUEUE_CAP`].
    QueueFull,
}

impl fmt::Display for SearchEnqueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateQueued => {
                write!(f, "an identical search is already queued for this network")
            }
            Self::QueueFull => write!(
                f,
                "search queue is full ({SEARCH_QUEUE_CAP} waiting searches)"
            ),
        }
    }
}

/// One dispatch produced by [`SearchQueue::tick`].
#[derive(Debug)]
pub(crate) struct SearchDispatch {
    pub(crate) entry: QueuedSearch,
    pub(crate) lane: ConcreteSearchLane,
}

/// Result of one drain tick.
#[derive(Debug, Default)]
pub(crate) struct SearchQueueTick {
    /// At most one dispatch per concrete lane per tick.
    pub(crate) dispatches: Vec<SearchDispatch>,
    /// Entries that exceeded [`SEARCH_QUEUE_MAX_WAIT`]; fail them explicitly.
    pub(crate) expired: Vec<QueuedSearch>,
}

/// Connection-aware search queue: FIFO within each lane, single in-flight
/// search per concrete lane, [`SEARCH_QUEUE_DRAIN_SLOT`] spacing between
/// dispatches on the same lane.
#[derive(Debug, Default)]
pub(crate) struct SearchQueue {
    pending: VecDeque<QueuedSearch>,
    server_in_flight: bool,
    kad_in_flight: bool,
    last_server_dispatch: Option<Instant>,
    last_kad_dispatch: Option<Instant>,
    drain_task_running: bool,
}

impl SearchQueue {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Number of waiting (not in-flight) searches.
    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Queues a search for dispatch when its backend becomes ready.
    ///
    /// Rejects duplicates (same normalized query on the same lane) and
    /// enforces [`SEARCH_QUEUE_CAP`]; both surface as explicit POST errors,
    /// never silent drops.
    pub(crate) fn enqueue(
        &mut self,
        search_id: String,
        request: SearchCreate,
        lane: SearchQueueLane,
        now: Instant,
    ) -> Result<(), SearchEnqueueError> {
        if self.pending.len() >= SEARCH_QUEUE_CAP {
            return Err(SearchEnqueueError::QueueFull);
        }
        let normalized = normalized_queue_query(&request.query);
        if self.pending.iter().any(|entry| {
            entry.lane == lane && normalized_queue_query(&entry.request.query) == normalized
        }) {
            return Err(SearchEnqueueError::DuplicateQueued);
        }
        self.pending.push_back(QueuedSearch {
            search_id,
            request,
            lane,
            enqueued_at: now,
            send_attempts: 0,
        });
        Ok(())
    }

    /// Claims the single drain-task slot; the caller that receives `true`
    /// must spawn the drain task. Called under the queue lock right after a
    /// successful enqueue so exactly one task runs at a time.
    pub(crate) fn claim_drain_task(&mut self) -> bool {
        if self.drain_task_running {
            return false;
        }
        self.drain_task_running = true;
        true
    }

    /// Releases the drain-task slot when there is nothing left to drive.
    /// Returns `true` when the caller (the drain task) should exit. Checked
    /// under the queue lock so an enqueue racing the exit either sees the slot
    /// still claimed or claims it itself — never both, never neither.
    pub(crate) fn release_drain_task_if_idle(&mut self) -> bool {
        if self.pending.is_empty() && !self.server_in_flight && !self.kad_in_flight {
            self.drain_task_running = false;
            return true;
        }
        false
    }

    /// One drain tick: expire over-age entries, then dispatch at most one
    /// ready search per concrete lane (FIFO order, honoring the single
    /// in-flight search and the drain slot spacing per lane).
    pub(crate) fn tick(
        &mut self,
        now: Instant,
        readiness: SearchBackendReadiness,
    ) -> SearchQueueTick {
        let mut tick = SearchQueueTick::default();

        // Expire first so a stale entry can never consume a dispatch slot.
        let mut index = 0;
        while index < self.pending.len() {
            if now.duration_since(self.pending[index].enqueued_at) > SEARCH_QUEUE_MAX_WAIT {
                if let Some(entry) = self.pending.remove(index) {
                    tick.expired.push(entry);
                }
            } else {
                index += 1;
            }
        }

        let mut index = 0;
        while index < self.pending.len() {
            let lane = self.pending[index].lane;
            let concrete = match lane {
                SearchQueueLane::Server => self
                    .server_lane_open(now, readiness)
                    .then_some(ConcreteSearchLane::Server),
                SearchQueueLane::Kad => self
                    .kad_lane_open(now, readiness)
                    .then_some(ConcreteSearchLane::Kad),
                // Auto prefers the eD2k server, like resolve_search_network_method.
                SearchQueueLane::Auto => {
                    if self.server_lane_open(now, readiness) {
                        Some(ConcreteSearchLane::Server)
                    } else if self.kad_lane_open(now, readiness) {
                        Some(ConcreteSearchLane::Kad)
                    } else {
                        None
                    }
                }
            };
            let Some(concrete) = concrete else {
                index += 1;
                continue;
            };
            let Some(mut entry) = self.pending.remove(index) else {
                break;
            };
            entry.send_attempts += 1;
            match concrete {
                ConcreteSearchLane::Server => {
                    self.server_in_flight = true;
                    self.last_server_dispatch = Some(now);
                }
                ConcreteSearchLane::Kad => {
                    self.kad_in_flight = true;
                    self.last_kad_dispatch = Some(now);
                }
            }
            tick.dispatches.push(SearchDispatch {
                entry,
                lane: concrete,
            });
            // Don't advance `index`: the removed slot now holds the next entry.
        }

        tick
    }

    /// Marks the concrete lane's in-flight search as finished (any outcome).
    pub(crate) fn finish(&mut self, lane: ConcreteSearchLane) {
        match lane {
            ConcreteSearchLane::Server => self.server_in_flight = false,
            ConcreteSearchLane::Kad => self.kad_in_flight = false,
        }
    }

    /// Puts a dispatched search whose send failed mid-flight (stale handle /
    /// session died before answering) back at the FRONT of the queue for a
    /// bounded retry on a fresh session. Returns `false` (dropping the entry)
    /// when the attempt budget is exhausted — the caller must then fail the
    /// search with an explicit error, never a fake "completed".
    #[must_use]
    pub(crate) fn requeue_for_retry(&mut self, entry: QueuedSearch) -> bool {
        if entry.send_attempts >= SEARCH_QUEUE_MAX_SEND_ATTEMPTS {
            return false;
        }
        // Front, not back: the retried search was first in line; re-appending
        // would let later submissions leapfrog it on every session flap.
        self.pending.push_front(entry);
        true
    }

    fn server_lane_open(&self, now: Instant, readiness: SearchBackendReadiness) -> bool {
        readiness.server
            && !self.server_in_flight
            && slot_elapsed(self.last_server_dispatch, now)
            && !self.dispatched_lane_this_tick(ConcreteSearchLane::Server, now)
    }

    fn kad_lane_open(&self, now: Instant, readiness: SearchBackendReadiness) -> bool {
        readiness.kad
            && !self.kad_in_flight
            && slot_elapsed(self.last_kad_dispatch, now)
            && !self.dispatched_lane_this_tick(ConcreteSearchLane::Kad, now)
    }

    /// A lane that dispatched at `now` already used its slot this tick (the
    /// in-flight flag covers it anyway; this keeps the invariant local).
    fn dispatched_lane_this_tick(&self, lane: ConcreteSearchLane, now: Instant) -> bool {
        match lane {
            ConcreteSearchLane::Server => self.last_server_dispatch == Some(now),
            ConcreteSearchLane::Kad => self.last_kad_dispatch == Some(now),
        }
    }
}

fn slot_elapsed(last_dispatch: Option<Instant>, now: Instant) -> bool {
    last_dispatch.is_none_or(|last| now.duration_since(last) >= SEARCH_QUEUE_DRAIN_SLOT)
}

/// Duplicate detection key: whitespace-trimmed, case-folded query text.
fn normalized_queue_query(query: &str) -> String {
    query.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests;
