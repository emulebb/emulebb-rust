use super::*;

impl EmulebbCore {
    pub async fn create_search(&self, request: SearchCreate) -> Result<Search> {
        let now = Utc::now();
        // Local index results are cheap, so include them immediately.
        let indexed = self.index.lock().await.search(&request.query, 200)?;
        let mut state = self.state.lock().await;
        let (search_id, next_search_id) =
            search_state::allocate_search_id(&state.searches, state.next_search_id)?;
        state.next_search_id = next_search_id;
        let mut results = Vec::new();
        results.extend(
            indexed
                .into_iter()
                .map(|file| search_result_from_indexed(&search_id, &request, file)),
        );
        apply_search_filters(&mut results, &request);
        // Network methods go through the connection-aware queue (operator
        // directive 2026-07-06): a search submitted while its backend is still
        // connecting/absent is QUEUED with an honest status+reason and drains
        // automatically when the backend is ready — it is never fired into a
        // stale handle and never silently "completed" with local-only results.
        // Non-network methods (or no eD2k network configured at all) keep the
        // immediate running->completed local-index path.
        let queue_lane = self
            .ed2k_network
            .as_ref()
            .and_then(|_| SearchQueueLane::for_method(&request.method));
        let mut spawn_drain = false;
        if let Some(lane) = queue_lane {
            let mut queue = self.search_queue.lock();
            if let Err(error) =
                queue.enqueue(search_id.clone(), request.clone(), lane, Instant::now())
            {
                // Explicit POST rejection (duplicate / queue full) — the
                // allocated id is simply skipped, never inserted.
                crate::diag_sched::keyword_search_queue(
                    "rejected",
                    &request.method,
                    Some(match error {
                        search_queue::SearchEnqueueError::DuplicateQueued => "duplicate-queued",
                        search_queue::SearchEnqueueError::QueueFull => "queue-full",
                    }),
                    0,
                );
                bail!("{error}");
            }
            spawn_drain = queue.claim_drain_task();
            crate::diag_sched::keyword_search_queue(
                "queued",
                &request.method,
                Some(lane.waiting_reason()),
                0,
            );
        }
        // Create the search and return immediately; the network part runs via
        // the queue drain (or the legacy background task) and flips the status
        // queued->running->completed. This keeps the eMuleBB contract's
        // running->complete lifecycle: controllers (e.g. aMuTorrent) get a
        // prompt POST and poll GET for results; "queued" is an additive state
        // consumers treat like running (poll until "complete").
        let (status, status_reason) = match queue_lane {
            Some(lane) => ("queued", Some(lane.waiting_reason().to_string())),
            None => ("running", None),
        };
        let search = Search {
            id: search_id.clone(),
            query: request.query.clone(),
            method: request.method.clone(),
            r#type: request.r#type.clone(),
            status: status.to_string(),
            status_reason,
            created_at: now,
            updated_at: now,
            results,
        };
        search_state::persist_search(&self.metadata_store, &search)?;
        state.searches.insert(search_id.clone(), search.clone());
        drop(state);
        if queue_lane.is_some() {
            if spawn_drain {
                self.spawn_search_queue_drain();
            }
        } else {
            let core = self.clone();
            tokio::spawn(async move {
                core.run_background_search(search_id, request).await;
            });
        }
        Ok(search)
    }

    /// Legacy immediate path for NON-QUEUED searches (unknown methods, or no
    /// eD2k network configured): resolves the live network method, runs any
    /// applicable network search, and completes the search with whatever the
    /// local index already provided. Network methods never reach this path —
    /// they go through the connection-aware queue (`search_queue_runtime`).
    async fn run_background_search(&self, search_id: String, request: SearchCreate) {
        let ed2k_connected = self.connected_ed2k_search_handle().await.is_some();
        let kad_connected = self
            .ed2k_dht_node()
            .await
            .is_some_and(|dht| dht.is_bootstrapped());
        let network_method =
            resolve_search_network_method(&request.method, ed2k_connected, kad_connected);
        let method_str = match network_method {
            Some(SearchNetworkMethod::Ed2kServer) => "server",
            Some(SearchNetworkMethod::Ed2kGlobal) => "global",
            Some(SearchNetworkMethod::Kad) => "kad",
            None => "none",
        };
        let outcome = match network_method {
            Some(SearchNetworkMethod::Ed2kServer | SearchNetworkMethod::Ed2kGlobal) => self
                .search_ed2k_servers(&search_id, &request, network_method)
                .await
                .map(|outcome| match outcome {
                    Ed2kServerSearchOutcome::Completed(results) => Some(results),
                    Ed2kServerSearchOutcome::Unavailable
                    | Ed2kServerSearchOutcome::NotConnected => None,
                }),
            Some(SearchNetworkMethod::Kad) => match self.ed2k_dht_node().await {
                Some(dht) => search_kad_keywords(dht, &search_id, &request).await,
                None => Ok(None),
            },
            None => Ok(None),
        };
        match outcome {
            Ok(network_results) => {
                self.complete_search_with_results(
                    &search_id,
                    &request,
                    method_str,
                    network_results,
                )
                .await;
            }
            Err(error) => {
                tracing::warn!("background search failed for {search_id}: {error:#}");
                self.fail_search(&search_id, &request, method_str, "network-search-failed")
                    .await;
            }
        }
    }

    pub async fn searches(&self) -> Vec<Search> {
        self.state.lock().await.searches.values().cloned().collect()
    }

    pub async fn search(&self, search_id: &str) -> Option<Search> {
        self.state.lock().await.searches.get(search_id).cloned()
    }

    pub async fn delete_search(&self, search_id: &str) -> Result<bool> {
        let persisted = self.metadata_store.delete_search(search_id)?;
        let cached = self.state.lock().await.searches.remove(search_id).is_some();
        Ok(persisted || cached)
    }

    pub async fn clear_searches(&self) -> Result<()> {
        self.metadata_store.clear_searches()?;
        self.state.lock().await.searches.clear();
        Ok(())
    }
}
