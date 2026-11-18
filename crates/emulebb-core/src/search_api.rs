use super::*;

impl EmulebbCore {
    pub async fn create_search(&self, request: SearchCreate) -> Result<Search> {
        self.create_search_with_initial_persistence(request, search_state::create_search)
            .await
    }

    pub(crate) async fn create_search_with_initial_persistence<P>(
        &self,
        mut request: SearchCreate,
        persist: P,
    ) -> Result<Search>
    where
        P: FnOnce(&MetadataStore, &Search) -> Result<String>,
    {
        request.canonicalize();
        request.validate()?;
        let now = Utc::now();
        let mut state = self.state.lock().await;
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
        // Every public search is live-network work. The queue keeps an accepted
        // search honest while its selected backend is still connecting; local
        // metadata never creates an offline /searches mode.
        let queue_lane = automatic_search_queue_lane(
            &request,
            self.ed2k_network.is_some(),
            state.core_settings.network_ed2k,
            state.core_settings.network_kademlia,
        )?;
        let _ = emulebb_ed2k::ed2k_server::encode_kad_search_expression(
            &request.query,
            &search_criteria_from_request(&request),
        )?;
        let prepared_queue_entry = {
            let queue = self.search_queue.lock();
            match queue.prepare_enqueue(request.clone(), queue_lane, Instant::now()) {
                Ok(prepared) => prepared,
                Err(error) => {
                    // Queue rejection happens before allocating a durable ID.
                    crate::diag_sched::keyword_search_queue(
                        "",
                        &request.query,
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
            }
        };
        // Create the search and return immediately; the network part runs via
        // the queue drain and flips the status
        // queued->running->completed. This keeps the eMuleBB contract's
        // running->complete lifecycle: controllers (e.g. aMuTorrent) get a
        // prompt POST and poll GET for results; "queued" is an additive state
        // consumers treat like running (poll until "complete").
        // The private candidate has no ID until SQLite commits. Queue entries,
        // results and the public response receive that allocated identity together.
        let mut search = Search {
            id: String::new(),
            spec: request.clone(),
            resolved_method: None,
            status: "queued".to_string(),
            status_reason: Some(queue_lane.waiting_reason().to_string()),
            progress: SearchProgress::new("queued", 0, None, ""),
            created_at: now,
            updated_at: now,
            results: Vec::new(),
        };
        let search_id = persist(&self.metadata_store, &search)?;
        search.id.clone_from(&search_id);
        for result in &mut search.results {
            result.search_id.clone_from(&search_id);
        }
        let spawn_drain = {
            let mut queue = self.search_queue.lock();
            queue.commit_enqueue(prepared_queue_entry, search_id.clone());
            let spawn_drain = queue.claim_drain_task();
            crate::diag_sched::keyword_search_queue(
                &search_id,
                &request.query,
                "queued",
                &request.method,
                Some(queue_lane.waiting_reason()),
                0,
            );
            spawn_drain
        };
        state
            .search_cancels
            .insert(search_id.clone(), CancellationToken::new());
        state.searches.insert(search_id.clone(), search.clone());
        drop(state);
        if spawn_drain {
            self.spawn_search_queue_drain();
        }
        Ok(search)
    }

    pub async fn searches(&self) -> Vec<Search> {
        self.state.lock().await.searches.values().cloned().collect()
    }

    pub async fn search(&self, search_id: &str) -> Option<Search> {
        self.state.lock().await.searches.get(search_id).cloned()
    }

    pub async fn delete_search(&self, search_id: &str) -> Result<bool> {
        let id: i64 = search_id.parse().context("invalid search identity")?;
        ensure!(
            id > 0 && id.to_string() == search_id,
            "invalid search identity"
        );
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        Ok(owner
            .remove_search_sessions(Some(id), &self.search_queue)
            .await?)
    }

    pub async fn clear_searches(&self) -> Result<()> {
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        owner
            .remove_search_sessions(None, &self.search_queue)
            .await?;
        Ok(())
    }
}

fn automatic_search_queue_lane(
    request: &SearchCreate,
    runtime_configured: bool,
    ed2k_enabled: bool,
    kad_enabled: bool,
) -> Result<SearchQueueLane> {
    ensure!(runtime_configured, "search network is not configured");
    match SearchQueueLane::for_method(&request.method) {
        Some(SearchQueueLane::Server) => Ok(SearchQueueLane::Server),
        Some(SearchQueueLane::Kad) => {
            crate::kad_public_search::kad_public_search_keyword(&request.query)?;
            Ok(SearchQueueLane::Kad)
        }
        Some(SearchQueueLane::Auto) => match (ed2k_enabled, kad_enabled) {
            (false, false) => bail!("search networks are disabled in settings.core"),
            (true, false) => Ok(SearchQueueLane::Server),
            (false, true) => {
                crate::kad_public_search::kad_public_search_keyword(&request.query)?;
                Ok(SearchQueueLane::Kad)
            }
            (true, true) => Ok(
                if crate::kad_public_search::kad_public_search_keyword(&request.query).is_ok() {
                    SearchQueueLane::Auto
                } else {
                    SearchQueueLane::Server
                },
            ),
        },
        None => bail!("unsupported search method {}", request.method),
    }
}
