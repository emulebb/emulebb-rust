use super::*;

impl EmulebbCore {
    pub async fn create_search(&self, mut request: SearchCreate) -> Result<Search> {
        request.method = match request.method.trim().to_ascii_lowercase().as_str() {
            "" | "automatic" => "automatic".to_string(),
            "server" => "server".to_string(),
            "global" => "global".to_string(),
            "kad" => "kad".to_string(),
            _ => bail!("search method must be one of automatic, server, global, kad"),
        };
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
        match request.method.as_str() {
            "server" | "global" => {
                ensure!(
                    self.ed2k_network.is_some(),
                    "eD2k search network is not configured"
                );
                ensure!(
                    state.core_settings.network_ed2k,
                    "eD2k search network is disabled in settings.core (networkEd2k=false)"
                );
            }
            "kad" => {
                ensure!(
                    self.ed2k_network.is_some(),
                    "Kad search network is not configured"
                );
                ensure!(
                    state.core_settings.network_kademlia,
                    "Kad search network is disabled in settings.core (networkKademlia=false)"
                );
            }
            _ => {}
        }
        // Network methods go through the connection-aware queue (operator
        // directive 2026-07-06): a search submitted while its backend is still
        // connecting/absent is QUEUED with an honest status+reason and drains
        // automatically when the backend is ready — it is never fired into a
        // stale handle and never silently "completed" with local-only results.
        // Automatic searches without an eD2k network runtime keep the
        // immediate running->completed local-index path. Explicit network
        // methods were rejected above rather than misreported as local-only
        // completed searches.
        let queue_lane = self.ed2k_network.as_ref().and_then(|_| {
            let lane = SearchQueueLane::for_method(&request.method)?;
            if lane == SearchQueueLane::Auto
                && !state.core_settings.network_ed2k
                && !state.core_settings.network_kademlia
            {
                None
            } else {
                Some(lane)
            }
        });
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
            spec: request.clone(),
            resolved_method: None,
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

    /// Legacy immediate path for NON-QUEUED searches (unknown methods, or an
    /// automatic search with no eD2k network configured): resolves the live
    /// network method, runs any applicable network search, and completes the
    /// search with whatever the local index already provided. Explicit network
    /// methods never reach this path — they are either rejected or go through
    /// the connection-aware queue (`search_queue_runtime`).
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
                    Ed2kServerSearchOutcome::Completed(results) => Some(
                        crate::kad_public_search::KadKeywordSearchOutcome::without_aich(results),
                    ),
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
            Ok(network_outcome) => {
                let (network_results, aich_votes) = match network_outcome {
                    Some(outcome) => (Some(outcome.results), Some(outcome.aich_votes)),
                    None => (None, None),
                };
                self.complete_search_with_results(
                    &search_id,
                    &request,
                    method_str,
                    network_results,
                    aich_votes,
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
        // Serialize against create/retry while removing the durable record,
        // pending wire work, and cached session. The shared lock order is
        // state -> queue; the drain loop never holds both locks at once.
        let mut state = self.state.lock().await;
        let persisted = self.metadata_store.delete_search(search_id)?;
        let queued = self.search_queue.lock().remove_pending(search_id);
        let cached = state.searches.remove(search_id).is_some();
        state
            .kad_aich_search_votes
            .retain(|(candidate_search_id, _), _| candidate_search_id != search_id);
        Ok(persisted || queued || cached)
    }

    pub async fn clear_searches(&self) -> Result<()> {
        // Keep creates and retry requeues outside the clear transaction so a
        // deleted session cannot leave orphaned network work behind.
        let mut state = self.state.lock().await;
        self.metadata_store.clear_searches()?;
        self.search_queue.lock().clear_pending();
        state.searches.clear();
        state.kad_aich_search_votes.clear();
        Ok(())
    }
}
