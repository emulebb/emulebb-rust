//! Async glue for the connection-aware search queue (`search_queue.rs`).
//!
//! Owns the drain task (readiness probing + paced dispatch), the per-dispatch
//! execution, and the shared search-completion helpers. Locking rule: the
//! queue's `parking_lot::Mutex` guard is NEVER held across an `.await`. Paths
//! that must atomically coordinate session state and queued work use the sole
//! nested order `state` -> brief queue lock; the drain path takes those locks
//! only in disjoint scopes.

use std::{future::Future, time::Instant};

use chrono::Utc;
use emulebb_ed2k::ed2k_server::Ed2kBackgroundSearchInterrupted;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::search_query::SearchNetworkMethod;
use crate::search_queue::{
    ConcreteSearchLane, QueuedSearch, SEARCH_QUEUE_RECHECK, SearchBackendReadiness, SearchDispatch,
};
use crate::{
    EmulebbCore, SearchCreate, SearchProgress, SearchResult, kad_public_search, search_state,
};

pub(crate) enum SearchLiveUpdate {
    Result(Box<SearchResult>),
    Progress(SearchProgress),
}

/// Outcome of one eD2k server keyword-search execution
/// (`EmulebbCore::search_ed2k_servers`).
#[derive(Debug)]
pub(crate) enum Ed2kServerSearchOutcome {
    /// No eD2k network / no configured servers / non-server method: there is
    /// nothing to wait for on this backend.
    Unavailable,
    /// No connected background session at execution time (the readiness seen
    /// at dispatch evaporated): retry when a session is back.
    NotConnected,
    /// The search ran on a live session (possibly returning nothing).
    Completed(Vec<SearchResult>),
}

impl EmulebbCore {
    /// Spawns the single queue drain task. Callers must have won
    /// `SearchQueue::claim_drain_task` under the queue lock first.
    pub(crate) fn spawn_search_queue_drain(&self) {
        let core = self.clone();
        tokio::spawn(async move {
            core.run_search_queue_drain().await;
        });
    }

    /// Drain loop: one readiness-checked tick per `SEARCH_QUEUE_RECHECK`
    /// (oracle: MFC re-arms the blocked search queue at SEC2MS(1)), exiting
    /// when the queue is idle (an enqueue then claims a fresh task).
    async fn run_search_queue_drain(self) {
        loop {
            let readiness = SearchBackendReadiness {
                server: self.connected_ed2k_search_handle().await.is_some(),
                kad: self
                    .ed2k_dht_node()
                    .await
                    .is_some_and(|dht| dht.is_bootstrapped()),
            };
            let tick = self.search_queue.lock().tick(Instant::now(), readiness);
            for entry in tick.expired {
                crate::diag_sched::keyword_search_queue(
                    "expired",
                    &entry.request.method,
                    Some(entry.lane.waiting_reason()),
                    entry.send_attempts,
                );
                self.fail_search(
                    &entry.search_id,
                    &entry.request,
                    request_method_token(&entry.request),
                    "search-queue-wait-timeout",
                )
                .await;
            }
            for dispatch in tick.dispatches {
                crate::diag_sched::keyword_search_queue(
                    "drained",
                    &dispatch.entry.request.method,
                    None,
                    dispatch.entry.send_attempts,
                );
                let resolved_method = match dispatch.lane {
                    ConcreteSearchLane::Server
                        if dispatch
                            .entry
                            .request
                            .method
                            .trim()
                            .eq_ignore_ascii_case("server") =>
                    {
                        "server"
                    }
                    ConcreteSearchLane::Server => "global",
                    ConcreteSearchLane::Kad => "kad",
                };
                self.update_search_status(
                    &dispatch.entry.search_id,
                    "running",
                    None,
                    Some(resolved_method),
                )
                .await;
                let core = self.clone();
                tokio::spawn(async move {
                    core.execute_queued_search(dispatch).await;
                });
            }
            if self.search_queue.lock().release_drain_task_if_idle() {
                return;
            }
            tokio::time::sleep(SEARCH_QUEUE_RECHECK).await;
        }
    }

    /// Runs one dispatched search on its concrete lane and settles the
    /// search: completed with results, re-queued for a bounded retry, or
    /// failed with an explicit error status — never silently completed-empty.
    async fn execute_queued_search(self, dispatch: SearchDispatch) {
        let SearchDispatch { entry, lane } = dispatch;
        // The search may have been deleted while queued. Claim its registered
        // cancellation handle under the same state lock used by delete/clear,
        // so deletion either prevents dispatch or cancels it after this point.
        let cancel = {
            let state = self.state.lock().await;
            state
                .searches
                .contains_key(&entry.search_id)
                .then(|| state.search_cancels.get(&entry.search_id).cloned())
                .flatten()
        };
        let Some(cancel) = cancel else {
            self.search_queue.lock().finish(lane);
            return;
        };
        match lane {
            ConcreteSearchLane::Server => {
                self.execute_queued_server_search(entry, lane, &cancel)
                    .await
            }
            ConcreteSearchLane::Kad => self.execute_queued_kad_search(entry, lane, &cancel).await,
        }
    }

    async fn execute_queued_server_search(
        &self,
        entry: QueuedSearch,
        lane: ConcreteSearchLane,
        cancel: &CancellationToken,
    ) {
        // Explicit `server` keeps the connected-server-only search; `global`
        // and `automatic` add the UDP pass (automatic resolves like
        // resolve_search_network_method with the server connected).
        let network_method = if entry.request.method.trim().eq_ignore_ascii_case("server") {
            SearchNetworkMethod::Ed2kServer
        } else {
            SearchNetworkMethod::Ed2kGlobal
        };
        let method_token = match network_method {
            SearchNetworkMethod::Ed2kServer => "server",
            _ => "global",
        };
        self.update_search_progress(
            &entry.search_id,
            SearchProgress::new("connected-server", 0, Some(1), "servers"),
        )
        .await;
        let (incremental_tx, incremental_rx) = mpsc::unbounded_channel();
        let outcome = self
            .await_with_incremental_results(
                &entry.search_id,
                &entry.request,
                incremental_rx,
                self.search_ed2k_servers(
                    &entry.search_id,
                    &entry.request,
                    Some(network_method),
                    cancel,
                    Some(&incremental_tx),
                ),
            )
            .await;
        match outcome {
            Ok(Ed2kServerSearchOutcome::Completed(results)) => {
                self.search_queue.lock().finish(lane);
                self.complete_search_with_results(
                    &entry.search_id,
                    &entry.request,
                    method_token,
                    Some(results),
                    None,
                )
                .await;
            }
            Ok(Ed2kServerSearchOutcome::Unavailable) => {
                // The eD2k network was torn down while the search waited:
                // nothing will ever become ready, fail explicitly.
                self.search_queue.lock().finish(lane);
                self.fail_search(
                    &entry.search_id,
                    &entry.request,
                    method_token,
                    "server-network-unavailable",
                )
                .await;
            }
            Ok(Ed2kServerSearchOutcome::NotConnected) => {
                self.settle_retryable_dispatch(entry, lane, method_token, "reconnect-pending")
                    .await;
            }
            Err(error)
                if error
                    .downcast_ref::<Ed2kBackgroundSearchInterrupted>()
                    .is_some() =>
            {
                // WHY: the send never completed on a live session (stale
                // handle / session dropped mid-flight). Reporting results now
                // would be the silent completed-empty bug; requeue for a
                // fresh session instead, bounded by the attempt budget.
                tracing::debug!(
                    "queued server search interrupted mid-flight; re-queueing search_id={} attempt={} error={error:#}",
                    entry.search_id,
                    entry.send_attempts
                );
                self.settle_retryable_dispatch(entry, lane, method_token, "session-interrupted")
                    .await;
            }
            Err(error) => {
                self.search_queue.lock().finish(lane);
                tracing::warn!(
                    "queued server search failed search_id={}: {error:#}",
                    entry.search_id
                );
                self.fail_search(
                    &entry.search_id,
                    &entry.request,
                    method_token,
                    "network-search-failed",
                )
                .await;
            }
        }
    }

    async fn execute_queued_kad_search(
        &self,
        entry: QueuedSearch,
        lane: ConcreteSearchLane,
        cancel: &CancellationToken,
    ) {
        let dht = self.ed2k_dht_node().await;
        self.update_search_progress(
            &entry.search_id,
            SearchProgress::new("kad-traversal", 0, None, ""),
        )
        .await;
        let (incremental_tx, incremental_rx) = mpsc::unbounded_channel();
        let outcome = match dht {
            Some(dht) => {
                self.await_with_incremental_results(
                    &entry.search_id,
                    &entry.request,
                    incremental_rx,
                    kad_public_search::search_kad_keywords(
                        dht,
                        &entry.search_id,
                        &entry.request,
                        cancel,
                        Some(&incremental_tx),
                    ),
                )
                .await
            }
            // Runtime torn down between dispatch and execution.
            None => Ok(None),
        };
        match outcome {
            // `None` = not bootstrapped (or no runtime) at execution time:
            // the readiness seen at dispatch evaporated, retry bounded.
            Ok(None) => {
                self.settle_retryable_dispatch(entry, lane, "kad", "kad-not-ready")
                    .await;
            }
            Ok(Some(outcome)) => {
                self.search_queue.lock().finish(lane);
                self.complete_search_with_results(
                    &entry.search_id,
                    &entry.request,
                    "kad",
                    Some(outcome.results),
                    Some(outcome.aich_votes),
                )
                .await;
            }
            Err(error) => {
                self.search_queue.lock().finish(lane);
                tracing::warn!(
                    "queued kad search failed search_id={}: {error:#}",
                    entry.search_id
                );
                self.fail_search(
                    &entry.search_id,
                    &entry.request,
                    "kad",
                    "network-search-failed",
                )
                .await;
            }
        }
    }

    async fn await_with_incremental_results<T>(
        &self,
        search_id: &str,
        request: &SearchCreate,
        mut incremental_rx: mpsc::UnboundedReceiver<SearchLiveUpdate>,
        operation: impl Future<Output = T>,
    ) -> T {
        tokio::pin!(operation);
        loop {
            tokio::select! {
                output = &mut operation => {
                    while let Ok(update) = incremental_rx.try_recv() {
                        self.apply_search_live_update(search_id, request, update).await;
                    }
                    return output;
                }
                update = incremental_rx.recv() => {
                    if let Some(update) = update {
                        self.apply_search_live_update(search_id, request, update).await;
                    }
                }
            }
        }
    }

    async fn apply_search_live_update(
        &self,
        search_id: &str,
        request: &SearchCreate,
        update: SearchLiveUpdate,
    ) {
        match update {
            SearchLiveUpdate::Result(result) => {
                self.merge_incremental_search_result(search_id, request, *result)
                    .await;
            }
            SearchLiveUpdate::Progress(progress) => {
                self.update_search_progress(search_id, progress).await;
            }
        }
    }

    async fn update_search_progress(&self, search_id: &str, progress: SearchProgress) {
        let mut state = self.state.lock().await;
        let Some(search) = state.searches.get_mut(search_id) else {
            return;
        };
        search.progress = progress;
        search.updated_at = Utc::now();
    }

    /// Makes accepted network observations visible to REST/UI polling while a
    /// long Kad traversal or global server sweep is still active. Durability
    /// remains a terminal checkpoint in complete/fail, avoiding a full SQLite
    /// rewrite for every wire result.
    pub(crate) async fn merge_incremental_search_result(
        &self,
        search_id: &str,
        request: &SearchCreate,
        result: SearchResult,
    ) {
        let mut accepted = vec![result];
        crate::search_query::apply_search_filters(&mut accepted, request);
        let Some(result) = accepted.pop() else {
            return;
        };
        let mut state = self.state.lock().await;
        let Some(search) = state.searches.get_mut(search_id) else {
            return;
        };
        if let Some(existing) = search
            .results
            .iter_mut()
            .find(|existing| existing.hash == result.hash)
        {
            existing.merge_observations(result);
        } else {
            search.results.push(result);
        }
        search.updated_at = Utc::now();
    }

    /// Re-queues a dispatched-but-not-completed search (bounded retries) or
    /// fails it explicitly when the attempt budget is exhausted. The requeue
    /// and the lane release happen under ONE queue lock scope: releasing
    /// first would let the drain task observe an idle queue and exit between
    /// the two steps, stranding the re-queued entry with no drain task.
    async fn settle_retryable_dispatch(
        &self,
        entry: QueuedSearch,
        lane: ConcreteSearchLane,
        method_token: &'static str,
        retry_reason: &'static str,
    ) {
        let search_id = entry.search_id.clone();
        let request = entry.request.clone();
        let waiting_reason = entry.lane.waiting_reason();
        let attempts = entry.send_attempts;
        // Coordinate with delete/clear using the shared state -> queue lock
        // order. If deletion wins, this dispatch can release its lane but
        // must never resurrect itself as orphaned queued wire work. If retry
        // wins, deletion will subsequently find and remove the pending entry.
        let (search_exists, requeued) = {
            let state = self.state.lock().await;
            let search_exists = state.searches.contains_key(&search_id);
            let mut queue = self.search_queue.lock();
            let requeued = search_exists && queue.requeue_for_retry(entry);
            queue.finish(lane);
            (search_exists, requeued)
        };
        if !search_exists {
            return;
        }
        if requeued {
            crate::diag_sched::keyword_search_queue(
                "retry",
                &request.method,
                Some(retry_reason),
                attempts,
            );
            self.update_search_status(&search_id, "queued", Some(waiting_reason), None)
                .await;
        } else {
            crate::diag_sched::keyword_search_queue(
                "retry-exhausted",
                &request.method,
                Some(retry_reason),
                attempts,
            );
            self.fail_search(
                &search_id,
                &request,
                method_token,
                "search-send-retries-exhausted",
            )
            .await;
        }
    }

    /// Sets a search's non-terminal status (queued <-> running) with an
    /// honest `statusReason`, persisting the transition.
    pub(crate) async fn update_search_status(
        &self,
        search_id: &str,
        status: &str,
        status_reason: Option<&str>,
        resolved_method: Option<&str>,
    ) {
        let snapshot = {
            let mut state = self.state.lock().await;
            let Some(search) = state.searches.get_mut(search_id) else {
                return;
            };
            search.status = status.to_string();
            search.status_reason = status_reason.map(str::to_string);
            if let Some(resolved_method) = resolved_method {
                search.resolved_method = Some(resolved_method.to_string());
            }
            match status {
                "queued" => search.progress = SearchProgress::new("queued", 0, None, ""),
                "running" => search.progress = SearchProgress::new("starting", 0, None, ""),
                _ => {}
            }
            search.updated_at = Utc::now();
            search.clone()
        };
        if let Err(error) = search_state::persist_search(&self.metadata_store, &snapshot) {
            tracing::warn!("failed to persist search {search_id} status change: {error}");
        }
    }

    /// Marks a search completed, merging network results (deduped by hash)
    /// over the local-index results captured at create time. Shared by the
    /// queued path and the legacy immediate path.
    pub(crate) async fn complete_search_with_results(
        &self,
        search_id: &str,
        request: &SearchCreate,
        method_token: &'static str,
        network_results: Option<Vec<SearchResult>>,
        kad_aich_votes: Option<std::collections::HashMap<String, crate::KadAichSearchVotes>>,
    ) {
        let snapshot = {
            let mut state = self.state.lock().await;
            state.search_cancels.remove(search_id);
            let mut network_results = network_results.unwrap_or_default();
            crate::search_query::apply_search_filters(&mut network_results, request);
            let accepted_hashes = network_results
                .iter()
                .map(|result| result.hash.clone())
                .collect::<std::collections::HashSet<_>>();
            let snapshot = {
                let Some(search) = state.searches.get_mut(search_id) else {
                    return;
                };
                for result in network_results {
                    if let Some(existing) = search
                        .results
                        .iter_mut()
                        .find(|existing| existing.hash == result.hash)
                    {
                        existing.merge_observations(result);
                    } else {
                        search.results.push(result);
                    }
                }
                search.status = "completed".to_string();
                search.status_reason = None;
                search.resolved_method = concrete_method(method_token).map(str::to_string);
                search.progress.phase = "completed".to_string();
                if let Some(total_units) = search.progress.total_units {
                    search.progress.completed_units = total_units;
                }
                search.updated_at = Utc::now();
                search.clone()
            };
            state
                .kad_aich_search_votes
                .retain(|(candidate_search_id, _), _| candidate_search_id != search_id);
            if let Some(kad_aich_votes) = kad_aich_votes {
                for (hash, votes) in kad_aich_votes {
                    if accepted_hashes.contains(&hash) {
                        state
                            .kad_aich_search_votes
                            .insert((search_id.to_string(), hash), votes);
                    }
                }
            }
            snapshot
        };
        crate::diag_sched::keyword_search(
            method_token,
            snapshot.results.len(),
            request.query.chars().count(),
            &snapshot.status,
        );
        if let Err(error) = search_state::persist_search(&self.metadata_store, &snapshot) {
            tracing::warn!("failed to persist completed search {search_id}: {error}");
        }
    }

    /// Fails a search with an explicit error status + reason (never a fake
    /// "completed"). Shared by the queued path and the legacy immediate path.
    pub(crate) async fn fail_search(
        &self,
        search_id: &str,
        request: &SearchCreate,
        method_token: &'static str,
        reason: &'static str,
    ) {
        let snapshot = {
            let mut state = self.state.lock().await;
            state.search_cancels.remove(search_id);
            let Some(search) = state.searches.get_mut(search_id) else {
                return;
            };
            search.status = "error".to_string();
            search.status_reason = Some(reason.to_string());
            if let Some(method) = concrete_method(method_token) {
                search.resolved_method = Some(method.to_string());
            }
            search.progress.phase = "failed".to_string();
            search.updated_at = Utc::now();
            search.clone()
        };
        crate::diag_sched::keyword_search(
            method_token,
            snapshot.results.len(),
            request.query.chars().count(),
            &snapshot.status,
        );
        if let Err(error) = search_state::persist_search(&self.metadata_store, &snapshot) {
            tracing::warn!("failed to persist failed search {search_id}: {error}");
        }
    }
}

/// Diag token for the REQUESTED method (used before a lane resolves, e.g. on
/// queue expiry); resolved dispatches report their concrete lane instead.
fn request_method_token(request: &SearchCreate) -> &'static str {
    match request.method.trim().to_ascii_lowercase().as_str() {
        "server" => "server",
        "global" => "global",
        "kad" => "kad",
        _ => "automatic",
    }
}

fn concrete_method(method: &str) -> Option<&str> {
    matches!(method, "server" | "global" | "kad").then_some(method)
}
