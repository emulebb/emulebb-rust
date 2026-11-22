//! Retained publication context without a profile persistence-owner reference.
use super::*;

#[derive(Clone)]
pub(crate) struct SharedCatalogPublisher {
    connect_timeout: Option<Duration>,
    ed2k_runtime: Arc<Mutex<Option<Ed2kRuntime>>>,
    ed2k_transfers: Arc<Ed2kTransferRuntime>,
    shared_catalog_publish_dirty: Arc<AtomicBool>,
    shared_catalog_publish_worker: Arc<AtomicBool>,
    shared_catalog_publish_last: Arc<Mutex<Option<Instant>>>,
    ed2k_publish_diagnostics: ed2k_publish_diagnostics::SharedEd2kPublishDiagnostics,
}

impl SharedCatalogPublisher {
    pub(crate) fn new(core: &EmulebbCore) -> Self {
        Self {
            connect_timeout: core
                .ed2k_network
                .as_ref()
                .map(|network| Duration::from_secs(network.ed2k.connect_timeout_secs.max(10))),
            ed2k_runtime: Arc::clone(&core.ed2k_runtime),
            ed2k_transfers: Arc::clone(&core.ed2k_transfers),
            shared_catalog_publish_dirty: Arc::clone(&core.shared_catalog_publish_dirty),
            shared_catalog_publish_worker: Arc::clone(&core.shared_catalog_publish_worker),
            shared_catalog_publish_last: Arc::clone(&core.shared_catalog_publish_last),
            ed2k_publish_diagnostics: Arc::clone(&core.ed2k_publish_diagnostics),
        }
    }
    pub(super) async fn publish_ed2k_shared_catalog(
        &self,
    ) -> Result<Ed2kSharedCatalogPublishOutcome> {
        let Some(timeout) = self.connect_timeout else {
            return Ok(Ed2kSharedCatalogPublishOutcome::NoNetwork);
        };
        let (handle, server_state) = {
            let runtime_guard = self.ed2k_runtime.lock().await;
            let Some(runtime) = runtime_guard.as_ref() else {
                return Ok(Ed2kSharedCatalogPublishOutcome::NoNetwork);
            };
            (
                runtime.search_handle.clone(),
                Arc::clone(&runtime.server_state),
            )
        };
        if !server_state.read().await.connected {
            return Ok(Ed2kSharedCatalogPublishOutcome::NotConnected);
        }
        let stats = publish_shared_catalog_via_background_session(
            &handle,
            timeout,
            &CancellationToken::new(),
        )
        .await?;
        Ok(Ed2kSharedCatalogPublishOutcome::Published(stats))
    }

    pub(crate) fn queue(&self) {
        self.shared_catalog_publish_dirty
            .store(true, Ordering::Release);
        ed2k_publish_diagnostics::record(&self.ed2k_publish_diagnostics, |diagnostics| {
            if !diagnostics.running {
                diagnostics.phase = "queued".to_string();
            }
            diagnostics.running = true;
            diagnostics.dirty = true;
            diagnostics.queued_count = diagnostics.queued_count.saturating_add(1);
        });
        if self
            .shared_catalog_publish_worker
            .swap(true, Ordering::AcqRel)
        {
            return;
        }
        let core = self.clone();
        tokio::spawn(async move {
            core.run_queued_ed2k_shared_catalog_publisher().await;
        });
    }

    async fn run_queued_ed2k_shared_catalog_publisher(self) {
        const ED2K_SHARED_CATALOG_PUBLISH_DEBOUNCE: Duration = Duration::from_secs(2);
        const ED2K_SHARED_CATALOG_PUBLISH_MIN_INTERVAL: Duration = Duration::from_secs(60);
        const ED2K_SHARED_CATALOG_PUBLISH_NOT_CONNECTED_RETRY: Duration = Duration::from_secs(10);

        loop {
            ed2k_publish_diagnostics::record(&self.ed2k_publish_diagnostics, |diagnostics| {
                diagnostics.phase = "debouncing".to_string();
                diagnostics.running = true;
                diagnostics.dirty = self.shared_catalog_publish_dirty.load(Ordering::Acquire);
            });
            tokio::time::sleep(ED2K_SHARED_CATALOG_PUBLISH_DEBOUNCE).await;
            let current_entries = self.ed2k_transfers.shared_catalog_count().await;
            let previous_entries =
                ed2k_publish_diagnostics::snapshot(&self.ed2k_publish_diagnostics).total_entries;
            // An empty startup offer must not hold back the first real file.
            // A shrinking catalog must withdraw stale server offers promptly.
            let wait = if previous_entries > 0 && current_entries >= previous_entries {
                let last = self.shared_catalog_publish_last.lock().await;
                last.and_then(|last| {
                    ED2K_SHARED_CATALOG_PUBLISH_MIN_INTERVAL.checked_sub(last.elapsed())
                })
            } else {
                None
            };
            if let Some(wait) = wait {
                ed2k_publish_diagnostics::record(&self.ed2k_publish_diagnostics, |diagnostics| {
                    diagnostics.phase = "waitingInterval".to_string();
                    diagnostics.running = true;
                    diagnostics.dirty = self.shared_catalog_publish_dirty.load(Ordering::Acquire);
                });
                tokio::time::sleep(wait).await;
            }
            // Clear before the network publish. If hashing completes another
            // shared file while the advertisement is in flight, queueing sets
            // dirty again and this loop performs a follow-up publish.
            self.shared_catalog_publish_dirty
                .store(false, Ordering::Release);
            ed2k_publish_diagnostics::record(&self.ed2k_publish_diagnostics, |diagnostics| {
                diagnostics.phase = "publishing".to_string();
                diagnostics.running = true;
                diagnostics.dirty = false;
                diagnostics.last_attempt_at = Some(Utc::now().timestamp());
            });
            match self.publish_ed2k_shared_catalog().await {
                Ok(Ed2kSharedCatalogPublishOutcome::Published(stats)) => {
                    *self.shared_catalog_publish_last.lock().await = Some(Instant::now());
                    ed2k_publish_diagnostics::record(
                        &self.ed2k_publish_diagnostics,
                        |diagnostics| {
                            diagnostics.phase = "published".to_string();
                            diagnostics.running = true;
                            diagnostics.dirty =
                                self.shared_catalog_publish_dirty.load(Ordering::Acquire);
                            diagnostics.entries_sent = stats.entries_sent;
                            diagnostics.total_entries = stats.total_entries;
                            diagnostics.published_entries = stats.published_entries;
                            diagnostics.pending_entries = stats.pending_entries;
                            diagnostics.next_cursor = stats.next_cursor;
                            diagnostics.wrapped = stats.wrapped;
                            diagnostics.skipped_duplicate_batch = stats.skipped_duplicate_batch;
                            diagnostics.session_pump_active = stats.session_pump_active;
                            diagnostics.last_error = None;
                            diagnostics.last_success_at = Some(Utc::now().timestamp());
                        },
                    );
                    tracing::debug!(
                        entries_sent = stats.entries_sent,
                        total_entries = stats.total_entries,
                        published_entries = stats.published_entries,
                        pending_entries = stats.pending_entries,
                        next_cursor = stats.next_cursor,
                        wrapped = stats.wrapped,
                        skipped_duplicate_batch = stats.skipped_duplicate_batch,
                        session_pump_active = stats.session_pump_active,
                        "refreshed ED2K shared catalog advertisement"
                    );
                    if !stats.wrapped
                        && !stats.skipped_duplicate_batch
                        && !stats.session_pump_active
                    {
                        self.shared_catalog_publish_dirty
                            .store(true, Ordering::Release);
                        ed2k_publish_diagnostics::record(
                            &self.ed2k_publish_diagnostics,
                            |diagnostics| {
                                diagnostics.dirty = true;
                            },
                        );
                    }
                }
                Ok(Ed2kSharedCatalogPublishOutcome::NoNetwork) => {
                    ed2k_publish_diagnostics::record(
                        &self.ed2k_publish_diagnostics,
                        |diagnostics| {
                            diagnostics.phase = "noNetwork".to_string();
                            diagnostics.running = true;
                            diagnostics.dirty =
                                self.shared_catalog_publish_dirty.load(Ordering::Acquire);
                            diagnostics.no_network_count =
                                diagnostics.no_network_count.saturating_add(1);
                        },
                    );
                }
                Ok(Ed2kSharedCatalogPublishOutcome::NotConnected) => {
                    self.shared_catalog_publish_dirty
                        .store(true, Ordering::Release);
                    ed2k_publish_diagnostics::record(
                        &self.ed2k_publish_diagnostics,
                        |diagnostics| {
                            diagnostics.phase = "notConnected".to_string();
                            diagnostics.running = true;
                            diagnostics.dirty = true;
                            diagnostics.not_connected_count =
                                diagnostics.not_connected_count.saturating_add(1);
                        },
                    );
                    tokio::time::sleep(ED2K_SHARED_CATALOG_PUBLISH_NOT_CONNECTED_RETRY).await;
                    continue;
                }
                Err(error) => {
                    *self.shared_catalog_publish_last.lock().await = Some(Instant::now());
                    self.shared_catalog_publish_dirty
                        .store(true, Ordering::Release);
                    ed2k_publish_diagnostics::record(
                        &self.ed2k_publish_diagnostics,
                        |diagnostics| {
                            diagnostics.phase = "failed".to_string();
                            diagnostics.running = true;
                            diagnostics.dirty = true;
                            diagnostics.failure_count = diagnostics.failure_count.saturating_add(1);
                            diagnostics.last_error = Some(error.to_string());
                        },
                    );
                    tracing::warn!("failed to refresh ED2K shared catalog advertisement: {error}");
                }
            }
            if !self.shared_catalog_publish_dirty.load(Ordering::Acquire) {
                self.shared_catalog_publish_worker
                    .store(false, Ordering::Release);
                if !self.shared_catalog_publish_dirty.load(Ordering::Acquire) {
                    ed2k_publish_diagnostics::record(
                        &self.ed2k_publish_diagnostics,
                        |diagnostics| {
                            diagnostics.phase = "idle".to_string();
                            diagnostics.running = false;
                            diagnostics.dirty = false;
                        },
                    );
                    break;
                }
                if self
                    .shared_catalog_publish_worker
                    .swap(true, Ordering::AcqRel)
                {
                    ed2k_publish_diagnostics::record(
                        &self.ed2k_publish_diagnostics,
                        |diagnostics| {
                            diagnostics.running = true;
                            diagnostics.dirty = true;
                        },
                    );
                    break;
                }
            }
        }
    }
}
