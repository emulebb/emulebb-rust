use super::*;
use crate::shared_file_publication::TrackedPublishPhase;
use emulebb_ed2k::ed2k_server::{Ed2kOfferFilePublishPhase, Ed2kOfferFilesPublication};

struct SharedFilePublicationContext {
    ed2k_connected: bool,
    ed2k_publication: Option<Ed2kOfferFilesPublication>,
    kad_enabled: bool,
    kad_diagnostics: KadPublishDiagnostics,
}

impl EmulebbCore {
    /// Hydrate the first persisted shared-catalog cohort after startup storage
    /// reconciliation and before REST or network publication.
    pub async fn hydrate_initial_shared_catalog(&self) -> Result<usize> {
        let hydrated = self.ed2k_transfers.hydrate_initial_shared_catalog().await?;
        if hydrated > 0 {
            self.queue_ed2k_shared_catalog_publish();
        }
        Ok(hydrated)
    }

    /// Hydrate the persisted shared catalog pages deferred by daemon startup.
    /// Every appended page updates the live catalog and the final queue
    /// guarantees a server refresh even if catalog-demand notifications
    /// preceded network runtime construction.
    pub async fn hydrate_shared_catalog(&self) -> Result<usize> {
        let hydrated = self.ed2k_transfers.hydrate_shared_catalog().await?;
        if hydrated > 0 {
            self.queue_ed2k_shared_catalog_publish();
        }
        Ok(hydrated)
    }

    pub async fn share_local_file(&self, request: LocalShareCreate) -> Result<LocalShare> {
        self.share_native_local_file_with_progress(Path::new(&request.path), request.name, None)
            .await
    }

    pub(crate) async fn share_native_local_file_with_progress(
        &self,
        source_path: &Path,
        requested_name: Option<String>,
        progress: Option<emulebb_ed2k::ed2k_transfer::LocalIngestProgressObserver>,
    ) -> Result<LocalShare> {
        let metadata = tokio::fs::metadata(long_path(source_path))
            .await
            .with_context(|| format!("failed to inspect {}", source_path.display()))?;
        ensure!(metadata.is_file(), "local share path is not a file");
        ensure!(
            !load_shared_file_exclusion_policy(self)?.should_ignore(source_path, &metadata),
            "local share path is excluded from sharing"
        );
        let display_name = match requested_name {
            Some(name) => name,
            None => emulebb_metadata::NativePath::from(source_path)
                .display_file_name()
                .ok_or_else(|| anyhow::anyhow!("local share path has no valid file name"))?,
        };
        let summary = match progress {
            Some(progress) => {
                self.ed2k_transfers
                    .ingest_local_file_with_progress(source_path, &display_name, progress)
                    .await?
            }
            None => {
                self.ed2k_transfers
                    .ingest_local_file(source_path, &display_name)
                    .await?
            }
        };
        if self
            .state
            .lock()
            .await
            .transfers
            .remove(&summary.file_hash)
            .is_some()
        {
            self.publish_transfer_removed(summary.file_hash.clone());
        }
        self.metadata_store
            .unmark_unshared_file(&summary.file_hash)?;
        self.state
            .lock()
            .await
            .unshared_hashes
            .remove(&summary.file_hash);
        self.index.lock().await.upsert_file(
            &IndexedFile {
                ed2k_hash: summary.file_hash.clone(),
                name: summary.display_name.clone(),
                size_bytes: summary.file_size,
                content_type: ed2k_file_type_search_term(&summary.display_name)
                    .unwrap_or("unknown")
                    .to_string(),
                availability_score: 1,
            },
            emulebb_index::IndexedFileOrigin::LocalShare,
        )?;
        self.queue_ed2k_shared_catalog_publish();
        Ok(local_share_from_summary(summary))
    }

    pub async fn shares(&self) -> Vec<LocalShare> {
        match self.ed2k_transfers.share_entries().await {
            Ok(entries) => entries
                .into_iter()
                .map(|entry| self.local_share_from_entry(entry))
                .collect(),
            Err(error) => {
                tracing::warn!("failed to enumerate ED2K shared-file summaries: {error}");
                Vec::new()
            }
        }
    }

    pub async fn shares_page(&self, offset: usize, limit: usize) -> (Vec<LocalShare>, usize) {
        match self.ed2k_transfers.share_entries_page(offset, limit).await {
            Ok((entries, total)) => (
                entries
                    .into_iter()
                    .map(|entry| self.local_share_from_entry(entry))
                    .collect(),
                total,
            ),
            Err(error) => {
                tracing::warn!("failed to enumerate ED2K shared-file summary page: {error}");
                (Vec::new(), 0)
            }
        }
    }

    pub async fn shares_after(
        &self,
        after_hash: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<LocalShare>, usize, bool)> {
        let (entries, total, has_more) = self
            .ed2k_transfers
            .share_entries_after(after_hash, limit)
            .await?;
        Ok((
            entries
                .into_iter()
                .map(|entry| self.local_share_from_entry(entry))
                .collect(),
            total,
            has_more,
        ))
    }

    pub async fn query_shared_files(
        &self,
        query: SharedFileListQuery,
    ) -> Result<SharedFileListPage> {
        let context = self.shared_file_publication_context().await;
        let page = self
            .ed2k_transfers
            .query_share_entries(MetadataSharedFileQuery {
                search: query.search,
                priority: query.priority,
                after: query.after.map(metadata_shared_file_cursor),
                limit: query.limit,
                count_total: true,
            })
            .await?;
        Ok(SharedFileListPage {
            items: page
                .entries
                .into_iter()
                .map(|entry| {
                    let share = self.local_share_from_entry(entry);
                    let publication = self.shared_file_publication_status(&share, &context);
                    SharedFileListItem { share, publication }
                })
                .collect(),
            total: page.total,
            next_cursor: page.next_cursor.map(shared_file_list_cursor),
        })
    }

    async fn shared_file_publication_context(&self) -> SharedFilePublicationContext {
        let server_state = {
            let runtime = self.ed2k_runtime.lock().await;
            runtime
                .as_ref()
                .map(|runtime| Arc::clone(&runtime.server_state))
        };
        let (ed2k_connected, ed2k_publication) = match server_state {
            Some(server_state) => {
                let server_state = server_state.read().await;
                (
                    server_state.connected,
                    Some(server_state.offer_files_publication.clone()),
                )
            }
            None => (false, None),
        };
        SharedFilePublicationContext {
            ed2k_connected,
            ed2k_publication,
            kad_enabled: self
                .ed2k_network
                .as_ref()
                .is_some_and(|network| network.kad_publish_shared_files),
            kad_diagnostics: self.kad_publish_diagnostics(),
        }
    }

    fn shared_file_publication_status(
        &self,
        share: &LocalShare,
        context: &SharedFilePublicationContext,
    ) -> SharedFilePublicationStatus {
        let ed2k = if !shared_file_publish_enabled(&share.priority) {
            SharedFilePublishLane {
                state: SharedFilePublishState::Unavailable,
                last_success_at_ms: None,
            }
        } else if !context.ed2k_connected {
            SharedFilePublishLane {
                state: SharedFilePublishState::Waiting,
                last_success_at_ms: None,
            }
        } else {
            let tracked = share.hash.parse::<Ed2kHash>().ok().and_then(|hash| {
                context
                    .ed2k_publication
                    .as_ref()
                    .and_then(|publication| publication.status(&hash))
            });
            tracked.map_or_else(
                || SharedFilePublishLane {
                    state: SharedFilePublishState::Queued,
                    last_success_at_ms: None,
                },
                |tracked| SharedFilePublishLane {
                    state: match tracked.phase {
                        Ed2kOfferFilePublishPhase::Queued => SharedFilePublishState::Queued,
                        Ed2kOfferFilePublishPhase::Publishing => SharedFilePublishState::Publishing,
                        Ed2kOfferFilePublishPhase::Published => SharedFilePublishState::Published,
                        Ed2kOfferFilePublishPhase::Failed => SharedFilePublishState::Failed,
                    },
                    last_success_at_ms: tracked.last_success_at_ms,
                },
            )
        };

        let keyword_terms = significant_keyword_words_unique(&share.name);
        let tracked = self.kad_file_publication.snapshot(&share.hash);
        let kad_keyword = kad_keyword_publication_status(
            &keyword_terms,
            &tracked,
            context.kad_enabled,
            &context.kad_diagnostics,
        );
        let kad_source =
            kad_source_publication_status(&tracked, context.kad_enabled, &context.kad_diagnostics);
        SharedFilePublicationStatus {
            ed2k,
            kad_keyword,
            kad_source,
        }
    }

    fn local_share_from_entry(&self, entry: MetadataTransferShareEntry) -> LocalShare {
        LocalShare {
            hash: entry.file_hash.clone(),
            name: entry.display_name.clone(),
            size_bytes: entry.file_size,
            part_count: entry.part_count,
            ed2k_link: format_ed2k_file_link(
                &entry.display_name,
                entry.file_size,
                &entry.file_hash,
                entry.aich_root.as_deref(),
            ),
            aich_root: entry.aich_root.clone().unwrap_or_default(),
            transfer_dir: self
                .ed2k_transfers
                .transfer_dir_path(&entry.file_hash)
                .display()
                .to_string(),
            source_path: entry.source_path.as_deref().map(normal_path_display),
            priority: entry.upload_priority.clone(),
            auto_upload_priority: entry.auto_upload_priority,
            all_time_uploaded_bytes: entry.all_time_uploaded_bytes,
            all_time_upload_requests: entry.all_time_upload_requests,
            all_time_upload_accepts: entry.all_time_upload_accepts,
            comment: entry.comment.clone(),
            rating: entry.rating,
        }
    }

    pub async fn shared_catalog_count(&self) -> usize {
        self.ed2k_transfers.shared_catalog_count().await
    }

    pub fn kad_publish_diagnostics(&self) -> KadPublishDiagnostics {
        kad_publish_diagnostics::snapshot(&self.kad_publish_diagnostics)
    }

    pub fn ed2k_publish_diagnostics(&self) -> Ed2kPublishDiagnostics {
        ed2k_publish_diagnostics::snapshot(&self.ed2k_publish_diagnostics)
    }

    pub async fn share(&self, hash: &str) -> Option<LocalShare> {
        match self.ed2k_transfers.share_entry(hash).await {
            Ok(Some(entry)) => Some(self.local_share_from_entry(entry)),
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(hash, "failed to read ED2K shared-file summary: {error}");
                None
            }
        }
    }

    pub async fn update_shared_file(
        &self,
        hash: &str,
        request: SharedFileUpdate,
    ) -> Result<Option<LocalShare>> {
        let Some(share) = self.share(hash).await else {
            return Ok(None);
        };
        let priority = request
            .priority
            .as_deref()
            .map(validate_shared_upload_priority)
            .transpose()?
            .map(|priority| (priority.0.to_string(), priority.1));
        let comment_rating = validate_shared_file_comment_rating(&request)?;
        if priority.is_none() && comment_rating.is_none() {
            anyhow::bail!("shared-file PATCH requires priority, comment, or rating");
        }
        let publish_status_changed = priority.as_ref().is_some_and(|(priority, _)| {
            shared_file_publish_enabled(priority) != shared_file_publish_enabled(&share.priority)
        });
        // A comment/rating change resets the Kad NOTES clock (oracle
        // `SetLastPublishTimeKadNotes(0)`, KnownFile.cpp:1340,1360) so the edited
        // note republishes promptly; a priority-only PATCH does NOT. Detect an
        // actual change against the current values, not merely a present field.
        let notes_changed = shared_file_notes_changed(
            &share.comment,
            share.rating,
            comment_rating
                .as_ref()
                .map(|(comment, rating)| (comment.as_str(), *rating)),
        );
        let rating_changed = comment_rating
            .as_ref()
            .is_some_and(|(_, rating)| *rating != share.rating);
        self.ed2k_transfers
            .update_shared_file_metadata(
                hash,
                priority
                    .as_ref()
                    .map(|(priority, auto)| (priority.as_str(), *auto)),
                comment_rating
                    .as_ref()
                    .map(|(comment, rating)| (comment.as_str(), *rating)),
            )
            .await?;
        if notes_changed {
            // Clear the persisted notes row first so a restart before the loop
            // drains the queue cannot re-hydrate the stale 24h clock, then flag
            // the live loop-local schedule.
            if let Err(error) = self
                .metadata_store
                .delete_kad_outbound_publish(&share.hash, MetadataKadOutboundPublishKind::Notes)
            {
                tracing::warn!(
                    file_hash = %share.hash,
                    "failed to clear persisted Kad notes publish row after edit: {error:#}"
                );
            }
            match self.kad_notes_dirty.lock() {
                Ok(mut dirty) => {
                    dirty.insert(share.hash.clone());
                }
                Err(poisoned) => {
                    poisoned.into_inner().insert(share.hash.clone());
                }
            }
        }
        // A regular priority/comment-only PATCH leaves the server offer intact;
        // toggling not-published or changing the published rating does not.
        if shared_file_change_requires_ed2k_reoffer(
            false,
            false,
            publish_status_changed,
            rating_changed,
        ) {
            if let Ok(file_hash) = share.hash.parse::<Ed2kHash>() {
                let server_state = {
                    let runtime = self.ed2k_runtime.lock().await;
                    runtime
                        .as_ref()
                        .map(|runtime| Arc::clone(&runtime.server_state))
                };
                if let Some(server_state) = server_state {
                    server_state
                        .read()
                        .await
                        .offer_files_publication
                        .mark_queued(file_hash);
                }
            }
            self.queue_ed2k_shared_catalog_publish();
        }
        Ok(self.share(hash).await)
    }

    pub async fn unshare_file(&self, hash: &str) -> Result<Option<LocalShare>> {
        let Some(share) = self.share(hash).await else {
            return Ok(None);
        };
        self.ed2k_transfers
            .remove_completed_transfer_row(&share.hash)
            .await?;
        self.ed2k_transfers
            .remove_verified_catalog_entry(&share.hash)
            .await;
        ensure!(
            self.metadata_store
                .mark_unshared_file(&share.hash, "manual")?,
            "shared file metadata row is missing"
        );
        let mut state = self.state.lock().await;
        let removed = state.transfers.remove(&share.hash).is_some();
        state.unshared_hashes.insert(share.hash.clone());
        drop(state);
        if removed {
            self.publish_transfer_removed(share.hash.clone());
        }
        self.queue_ed2k_shared_catalog_publish();
        Ok(Some(share))
    }

    pub async fn shared_directories(&self) -> SharedDirectories {
        let roots = self
            .state
            .lock()
            .await
            .shared_directories
            .iter()
            .map(refresh_shared_directory_row)
            .collect::<Vec<_>>();
        SharedDirectories {
            roots,
            // Files still pending the initial hash in the background reload worker.
            hashing_count: shared_directories::hashing_count_snapshot(self),
            reload_progress: reload_progress_snapshot(self),
        }
    }

    pub fn shared_file_exclusions(&self) -> Result<SharedFileExclusions> {
        let custom = self
            .metadata_store
            .shared_file_exclusions()?
            .into_iter()
            .map(|path| SharedFileExclusion {
                path: normal_path_display(path.display_path()),
            })
            .collect();
        let disabled = self
            .metadata_store
            .disabled_shared_default_ignore_rules()?
            .into_iter()
            .collect::<HashSet<_>>();
        Ok(SharedFileExclusions {
            custom,
            defaults: shared_file_ignore_rules(&disabled),
        })
    }

    pub async fn add_shared_file_exclusion(&self, path: &str) -> Result<SharedFileExclusions> {
        let canonical_path = canonical_shared_file_exclusion(path)?;
        self.metadata_store
            .add_shared_file_exclusion(&canonical_path)?;
        self.reload_shared_directories_detached().await?;
        self.shared_file_exclusions()
    }

    pub async fn remove_shared_file_exclusion(&self, path: &str) -> Result<SharedFileExclusions> {
        let canonical_path = removable_shared_file_exclusion(path)?;
        self.metadata_store
            .remove_shared_file_exclusion(&canonical_path)?;
        self.reload_shared_directories_detached().await?;
        self.shared_file_exclusions()
    }

    pub async fn set_shared_file_ignore_rule_enabled(
        &self,
        rule_key: &str,
        enabled: bool,
    ) -> Result<SharedFileExclusions> {
        ensure!(
            is_shared_file_ignore_rule(rule_key),
            "unknown shared-file ignore rule"
        );
        self.metadata_store
            .set_shared_default_ignore_rule_enabled(rule_key, enabled)?;
        self.reload_shared_directories_detached().await?;
        self.shared_file_exclusions()
    }

    pub async fn set_shared_directories(
        &self,
        request: SharedDirectoriesUpdate,
    ) -> Result<SharedDirectories> {
        ensure!(
            request.confirm_replace_roots,
            "confirmReplaceRoots must be true"
        );
        let mut seen = HashSet::new();
        let mut roots = Vec::new();
        for root in request.roots {
            let canonical_path = canonical_shared_directory_root(&root.path)?;
            if seen.insert(canonical_path.clone()) {
                roots.push(SharedDirectoryRoot {
                    path: canonical_path,
                    monitor_owned: false,
                    shareable: true,
                    accessible: true,
                });
            }
        }
        self.replace_shared_directory_roots(roots).await
    }

    pub async fn add_shared_directory_root(&self, path: &str) -> Result<SharedDirectories> {
        let canonical_path = canonical_shared_directory_root(path)?;
        let mut roots = self.state.lock().await.shared_directories.clone();
        if !roots
            .iter()
            .any(|root| root.path.eq_ignore_ascii_case(&canonical_path))
        {
            roots.push(SharedDirectoryRoot {
                path: canonical_path,
                monitor_owned: false,
                shareable: true,
                accessible: true,
            });
        }
        self.replace_shared_directory_roots(dedupe_shared_directory_roots(roots))
            .await
    }

    pub async fn remove_shared_directory_root(&self, path: &str) -> Result<SharedDirectories> {
        let canonical_path = removable_shared_directory_root(path)?;
        let roots = self
            .state
            .lock()
            .await
            .shared_directories
            .iter()
            .filter(|root| !root.path.eq_ignore_ascii_case(&canonical_path))
            .cloned()
            .collect::<Vec<_>>();
        self.replace_shared_directory_roots(dedupe_shared_directory_roots(roots))
            .await
    }

    async fn replace_shared_directory_roots(
        &self,
        roots: Vec<SharedDirectoryRoot>,
    ) -> Result<SharedDirectories> {
        self.index.lock().await.replace_shared_directory_roots(
            &roots
                .iter()
                .map(shared_directory_to_index)
                .collect::<Vec<_>>(),
        )?;
        self.state.lock().await.shared_directories = roots;
        // Re-establish the live auto-pickup watch set for the new roots (it stops
        // the previous monitor first), matching eMule re-monitoring on reconfigure.
        // The monitor only auto-picks-up *newly arriving* files; files already
        // present under the new roots still need the initial hash, so kick a
        // detached background scan + hash (progress in `hashingCount`).
        self.start_shared_directory_monitor().await;
        self.reload_shared_directories_detached().await?;
        Ok(self.shared_directories().await)
    }

    /// Synchronous core primitive: scan + hash + share the whole library, blocking
    /// until fully indexed. Thin entry to `shared_directories`.
    pub async fn reload_shared_directories(&self) -> Result<Vec<LocalShare>> {
        shared_directories::reload_shared_directories(self).await
    }

    /// Kick the full scan + hash on a detached background task; returns the queued
    /// file count immediately. Thin entry to `shared_directories`.
    pub async fn reload_shared_directories_detached(&self) -> Result<usize> {
        shared_directories::reload_shared_directories_detached(self).await
    }

    /// (Re)start the live shared-directory auto-pickup monitor (eMule directory
    /// auto-monitor parity); thin entry to `shared_dir_monitor`. Must run inside
    /// a tokio runtime (it spawns the consumer task).
    pub async fn start_shared_directory_monitor(&self) {
        shared_dir_monitor::start_shared_directory_monitor(self).await;
    }

    /// Stop the live shared-directory monitor (if running). Idempotent.
    pub fn stop_shared_directory_monitor(&self) {
        shared_dir_monitor::stop_shared_directory_monitor(self);
    }
}

fn metadata_shared_file_cursor(cursor: SharedFileListCursor) -> MetadataSharedFileCursor {
    MetadataSharedFileCursor {
        sort_path: cursor.sort_path,
        file_hash: cursor.hash,
    }
}

fn shared_file_list_cursor(cursor: MetadataSharedFileCursor) -> SharedFileListCursor {
    SharedFileListCursor {
        sort_path: cursor.sort_path,
        hash: cursor.file_hash,
    }
}

fn kad_keyword_publication_status(
    keyword_terms: &[String],
    tracked: &shared_file_publication::KadFilePublishState,
    kad_enabled: bool,
    diagnostics: &KadPublishDiagnostics,
) -> SharedFileKadKeywordPublish {
    if !kad_enabled || keyword_terms.is_empty() {
        return SharedFileKadKeywordPublish {
            state: SharedFilePublishState::Unavailable,
            published_keywords: 0,
            total_keywords: keyword_terms.len(),
            last_success_at_ms: None,
        };
    }
    let attempts = keyword_terms
        .iter()
        .filter_map(|keyword| tracked.keywords.get(keyword))
        .collect::<Vec<_>>();
    let published_keywords = attempts
        .iter()
        .filter(|attempt| attempt.last_success_at_ms.is_some())
        .count();
    let last_success_at_ms = attempts
        .iter()
        .filter_map(|attempt| attempt.last_success_at_ms)
        .max();
    let state = if attempts
        .iter()
        .any(|attempt| attempt.phase == TrackedPublishPhase::Publishing)
    {
        SharedFilePublishState::Publishing
    } else if attempts
        .iter()
        .any(|attempt| attempt.phase == TrackedPublishPhase::Failed)
    {
        SharedFilePublishState::Failed
    } else if published_keywords == keyword_terms.len() {
        SharedFilePublishState::Published
    } else if published_keywords > 0 {
        SharedFilePublishState::Partial
    } else if !diagnostics.running || !diagnostics.bootstrapped || !diagnostics.gate_allowed {
        SharedFilePublishState::Waiting
    } else {
        SharedFilePublishState::Queued
    };
    SharedFileKadKeywordPublish {
        state,
        published_keywords,
        total_keywords: keyword_terms.len(),
        last_success_at_ms,
    }
}

fn kad_source_publication_status(
    tracked: &shared_file_publication::KadFilePublishState,
    kad_enabled: bool,
    diagnostics: &KadPublishDiagnostics,
) -> SharedFilePublishLane {
    if !kad_enabled {
        return SharedFilePublishLane {
            state: SharedFilePublishState::Unavailable,
            last_success_at_ms: None,
        };
    }
    match tracked.source {
        Some(attempt) => SharedFilePublishLane {
            state: match attempt.phase {
                TrackedPublishPhase::Publishing => SharedFilePublishState::Publishing,
                TrackedPublishPhase::Published => SharedFilePublishState::Published,
                TrackedPublishPhase::Failed => SharedFilePublishState::Failed,
            },
            last_success_at_ms: attempt.last_success_at_ms,
        },
        None if !diagnostics.running || !diagnostics.bootstrapped || !diagnostics.gate_allowed => {
            SharedFilePublishLane {
                state: SharedFilePublishState::Waiting,
                last_success_at_ms: None,
            }
        }
        None => SharedFilePublishLane {
            state: SharedFilePublishState::Queued,
            last_success_at_ms: None,
        },
    }
}

fn canonical_shared_directory_root(path: &str) -> Result<String> {
    let path = path.trim();
    ensure!(!path.is_empty(), "path must not be empty");
    let canonical = fs::canonicalize(long_path(Path::new(path)))
        .with_context(|| format!("failed to resolve {path}"))?;
    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("failed to inspect {}", canonical.display()))?;
    ensure!(metadata.is_dir(), "path is not a directory");
    Ok(normal_path_display(canonical.display().to_string()))
}

fn removable_shared_directory_root(path: &str) -> Result<String> {
    let path = path.trim();
    ensure!(!path.is_empty(), "path must not be empty");
    match fs::canonicalize(long_path(Path::new(path))) {
        Ok(canonical) => {
            let metadata = fs::metadata(&canonical)
                .with_context(|| format!("failed to inspect {}", canonical.display()))?;
            ensure!(metadata.is_dir(), "path is not a directory");
            Ok(normal_path_display(canonical.display().to_string()))
        }
        Err(_) => Ok(normal_path_display(path)),
    }
}

fn canonical_shared_file_exclusion(path: &str) -> Result<PathBuf> {
    let path = path.trim();
    ensure!(!path.is_empty(), "path must not be empty");
    let canonical = fs::canonicalize(long_path(Path::new(path)))
        .with_context(|| format!("failed to resolve {path}"))?;
    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("failed to inspect {}", canonical.display()))?;
    ensure!(metadata.is_file(), "path is not a file");
    Ok(long_path(&canonical))
}

fn removable_shared_file_exclusion(path: &str) -> Result<PathBuf> {
    let path = path.trim();
    ensure!(!path.is_empty(), "path must not be empty");
    match fs::canonicalize(long_path(Path::new(path))) {
        Ok(canonical) => {
            let metadata = fs::metadata(&canonical)
                .with_context(|| format!("failed to inspect {}", canonical.display()))?;
            ensure!(metadata.is_file(), "path is not a file");
            Ok(long_path(&canonical))
        }
        Err(_) => Ok(long_path(Path::new(path))),
    }
}

fn dedupe_shared_directory_roots(roots: Vec<SharedDirectoryRoot>) -> Vec<SharedDirectoryRoot> {
    let mut seen = HashSet::new();
    roots
        .into_iter()
        .filter(|root| seen.insert(root.path.to_ascii_lowercase()))
        .collect()
}
