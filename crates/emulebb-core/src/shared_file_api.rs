use super::*;
use crate::shared_file_publication::TrackedPublishPhase;
use emulebb_ed2k::ed2k_server::{Ed2kOfferFilePublishPhase, Ed2kOfferFilesPublication};

struct SharedFilePublicationContext {
    ed2k_connected: bool,
    ed2k_publication: Option<Ed2kOfferFilesPublication>,
    kad_enabled: bool,
    kad_diagnostics: KadPublishDiagnostics,
}

enum ExplicitRootEdit {
    Replace(Vec<SharedDirectoryRoot>),
    Add(String),
    Remove(String),
}

impl EmulebbCore {
    /// Reconcile cached hashes with target-native file metadata offline.
    /// Unresolved and changed files are counted but never read or hashed.
    /// Normal daemon startup remains responsible for active root membership.
    pub async fn reconcile_shared_files(&self) -> Result<SharedDirectoryReloadProgress> {
        shared_directories::reconcile_shared_files(self).await
    }

    /// Hydrate the first persisted shared-catalog cohort after startup storage
    /// reconciliation and before REST or network publication.
    pub async fn hydrate_initial_shared_catalog(&self) -> Result<usize> {
        shared_directories::sync_implicit_shared_directory_roots(self).await?;
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
        self.share_local_file_inner(request, None).await
    }

    pub(crate) async fn share_local_file_inner(
        &self,
        request: LocalShareCreate,
        progress: Option<emulebb_ed2k::ed2k_transfer::LocalIngestProgressObserver>,
    ) -> Result<LocalShare> {
        let path = Path::new(&request.path);
        let normalized = long_path(path);
        shared_directories::sync_implicit_shared_directory_roots(self).await?;
        let roots = crate::shared_dir_monitor::prepare_ingest_roots(self, &normalized).await?;
        ensure!(
            !roots.is_empty(),
            "local share path is outside accessible shared roots"
        );
        let share = self
            .share_native_local_file_with_intent(path, request.name, progress, &roots)
            .await?;
        self.share(&share.hash)
            .await
            .context("admitted local share is absent from the active library")
    }

    pub(crate) async fn share_native_local_file_with_progress(
        &self,
        source_path: &Path,
        requested_name: Option<String>,
        progress: Option<emulebb_ed2k::ed2k_transfer::LocalIngestProgressObserver>,
    ) -> Result<LocalShare> {
        self.share_native_local_file_with_intent(source_path, requested_name, progress, &[])
            .await
    }

    pub(crate) async fn share_native_local_file_with_intent(
        &self,
        source_path: &Path,
        requested_name: Option<String>,
        progress: Option<emulebb_ed2k::ed2k_transfer::LocalIngestProgressObserver>,
        roots: &[emulebb_metadata::MetadataIngestRoot],
    ) -> Result<LocalShare> {
        ensure!(
            !self
                .metadata_store
                .delivery_output_is_excluded(source_path)?,
            "local file is an incomplete delivery output"
        );
        let metadata = tokio::fs::metadata(long_path(source_path))
            .await
            .with_context(|| format!("failed to inspect {}", source_path.display()))?;
        ensure!(metadata.is_file(), "local share path is not a file");
        ensure!(
            !load_shared_file_ignore_policy(self)?.should_ignore(source_path, &metadata),
            "local share path is excluded from sharing"
        );
        let display_name = match requested_name {
            Some(name) => name,
            None => emulebb_metadata::NativePath::from(source_path)
                .display_file_name()
                .ok_or_else(|| anyhow::anyhow!("local share path has no valid file name"))?,
        };
        let summary = self
            .ed2k_transfers
            .ingest_local_file_owned(
                source_path,
                &display_name,
                progress,
                emulebb_ed2k::ed2k_transfer::LocalIngestOptions {
                    roots,
                    index_type: Some(
                        ed2k_file_type_search_term(&display_name).unwrap_or("unknown"),
                    ),
                },
            )
            .await?;
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

    pub(crate) fn local_share_from_entry(&self, entry: MetadataLocalShareEntry) -> LocalShare {
        // WHY: SQLite checkpoints may lag captured service. Merge only the
        // selected row's scalar facts with the owner; never hydrate the catalog
        // or query storage again to make a live read current.
        let totals = self
            .ed2k_transfers
            .observe_file_upload_statistics(
                &entry
                    .file_hash
                    .parse::<Ed2kHash>()
                    .expect("metadata hash is valid"),
                emulebb_metadata::MetadataFileUploadTotals {
                    uploaded_bytes: entry.all_time_uploaded_bytes,
                    upload_requests: entry.all_time_upload_requests,
                    accepted_sessions: entry.all_time_upload_accepts,
                    ..Default::default()
                },
            )
            .lifetime;
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
            path: normal_path_display(&entry.path),
            priority: entry.upload_priority.clone(),
            auto_upload_priority: entry.auto_upload_priority,
            all_time_uploaded_bytes: totals.uploaded_bytes,
            all_time_upload_requests: totals.upload_requests,
            all_time_upload_accepts: totals.accepted_sessions,
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

    /// Return the last health observations published by the monitor or scan.
    pub async fn shared_directories(&self) -> SharedDirectories {
        let roots = self.state.lock().await.shared_directories.clone();
        SharedDirectories {
            roots,
            // Files still pending the initial hash in the background reload worker.
            hashing_count: shared_directories::hashing_count_snapshot(self),
            reload_progress: self.shared_directory_reload_progress(),
        }
    }

    /// Read cached scan/hash counters without locking root configuration or
    /// probing its filesystem. Progress readers must not stall the reload worker.
    pub fn shared_directory_reload_progress(&self) -> SharedDirectoryReloadProgress {
        reload_progress_snapshot(self)
    }

    pub fn shared_file_ignores(&self) -> Result<SharedFileIgnores> {
        let custom = self
            .metadata_store
            .shared_file_ignore_patterns()?
            .into_iter()
            .map(|pattern| SharedFileIgnorePattern { pattern })
            .collect();
        let disabled = self
            .metadata_store
            .disabled_shared_default_ignore_rules()?
            .into_iter()
            .collect::<HashSet<_>>();
        Ok(SharedFileIgnores {
            custom,
            defaults: shared_file_ignore_rules(&disabled),
        })
    }

    pub async fn add_shared_file_ignore_pattern(&self, pattern: &str) -> Result<SharedFileIgnores> {
        crate::shared_directories::validate_shared_file_ignore_pattern(pattern)?;
        self.metadata_store
            .add_shared_file_ignore_pattern(pattern)?;
        self.reload_shared_directories_detached().await?;
        self.shared_file_ignores()
    }

    pub async fn remove_shared_file_ignore_pattern(
        &self,
        pattern: &str,
    ) -> Result<SharedFileIgnores> {
        crate::shared_directories::validate_shared_file_ignore_pattern(pattern)?;
        self.metadata_store
            .remove_shared_file_ignore_pattern(pattern)?;
        self.reload_shared_directories_detached().await?;
        self.shared_file_ignores()
    }

    pub async fn set_shared_file_ignore_rule_enabled(
        &self,
        rule_key: &str,
        enabled: bool,
    ) -> Result<SharedFileIgnores> {
        ensure!(
            is_shared_file_ignore_rule(rule_key),
            "unknown shared-file ignore rule"
        );
        self.metadata_store
            .set_shared_default_ignore_rule_enabled(rule_key, enabled)?;
        self.reload_shared_directories_detached().await?;
        self.shared_file_ignores()
    }

    pub async fn set_shared_directories(
        &self,
        request: SharedDirectoriesUpdate,
    ) -> Result<SharedDirectories> {
        ensure!(
            request.confirm_replace_roots,
            "confirmReplaceRoots must be true"
        );
        let paths = request.roots.into_iter().map(|root| root.path).collect();
        let crate::shared_dir_monitor::RootIoResult::Canonical(paths) =
            crate::shared_dir_monitor::run_root_io(
                self,
                crate::shared_dir_monitor::RootIoRequest::Canonical(paths),
            )
            .await?
        else {
            unreachable!()
        };
        let mut seen = HashSet::new();
        let mut roots = Vec::new();
        for canonical_path in paths {
            if seen.insert(canonical_path.clone()) {
                roots.push(SharedDirectoryRoot {
                    path: canonical_path,
                    monitor_owned: false,
                    shareable: true,
                    accessible: true,
                });
            }
        }
        self.replace_shared_directory_roots(ExplicitRootEdit::Replace(roots))
            .await
    }

    pub async fn add_shared_directory_root(&self, path: &str) -> Result<SharedDirectories> {
        let crate::shared_dir_monitor::RootIoResult::Canonical(mut paths) =
            crate::shared_dir_monitor::run_root_io(
                self,
                crate::shared_dir_monitor::RootIoRequest::Canonical(vec![path.to_owned()]),
            )
            .await?
        else {
            unreachable!()
        };
        let canonical_path = paths.pop().expect("one canonical root");
        self.replace_shared_directory_roots(ExplicitRootEdit::Add(canonical_path))
            .await
    }

    pub async fn remove_shared_directory_root(&self, path: &str) -> Result<SharedDirectories> {
        self.replace_shared_directory_roots(ExplicitRootEdit::Remove(path.to_owned()))
            .await
    }

    async fn replace_shared_directory_roots(
        &self,
        edit: ExplicitRootEdit,
    ) -> Result<SharedDirectories> {
        shared_directories::sync_implicit_shared_directory_roots(self).await?;
        loop {
            let expected = self.state.lock().await.shared_directories.clone();
            let roots = match &edit {
                ExplicitRootEdit::Replace(roots) => roots.clone(),
                ExplicitRootEdit::Add(path) => {
                    let mut roots = expected.clone();
                    roots.push(SharedDirectoryRoot {
                        path: path.clone(),
                        monitor_owned: false,
                        shareable: true,
                        accessible: true,
                    });
                    roots
                }
                ExplicitRootEdit::Remove(path) => {
                    let crate::shared_dir_monitor::RootIoResult::Remaining(roots) =
                        crate::shared_dir_monitor::run_root_io(
                            self,
                            crate::shared_dir_monitor::RootIoRequest::Remove(
                                path.clone(),
                                expected.clone(),
                            ),
                        )
                        .await?
                    else {
                        unreachable!()
                    };
                    roots
                }
            };
            let implicit = shared_directories::implicit_shared_directory_roots(self).await?;
            let implicit_paths: HashSet<_> =
                implicit.iter().map(|root| root.path.clone()).collect();
            let first_explicit = implicit.len();
            let candidates = implicit
                .iter()
                .cloned()
                .chain(roots.iter().cloned())
                .collect();
            let crate::shared_dir_monitor::RootIoResult::Inspected(prepared) =
                crate::shared_dir_monitor::run_root_io(
                    self,
                    crate::shared_dir_monitor::RootIoRequest::Replace(candidates, first_explicit),
                )
                .await?
            else {
                unreachable!()
            };
            let prepared = prepared
                .into_iter()
                .map(|(root, _)| root)
                .filter(|root| !implicit_paths.contains(&root.path))
                .collect::<Vec<_>>();
            let owner = self
                .persistence_owner
                .owner(&self.metadata_store, &self.state)?;
            if owner
                .replace_explicit_roots(
                    crate::persistence_owner::category::CategoryCommand::ReplaceRoots {
                        expected,
                        implicit,
                        proposed: prepared,
                        sharing: self.category_sharing_context(),
                        reload: None,
                    },
                    Some(self),
                )
                .await?
            {
                return Ok(self.shared_directories().await);
            }
        }
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
    pub async fn stop_shared_directory_monitor(&self) -> Result<()> {
        shared_dir_monitor::stop_shared_directory_monitor(self).await
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

pub(crate) fn canonical_shared_directory_root(path: &str) -> Result<String> {
    let path = path.trim();
    ensure!(!path.is_empty(), "path must not be empty");
    let canonical = fs::canonicalize(long_path(Path::new(path)))
        .with_context(|| format!("failed to resolve {path}"))?;
    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("failed to inspect {}", canonical.display()))?;
    ensure!(metadata.is_dir(), "path is not a directory");
    Ok(normal_path_display(canonical.display().to_string()))
}

pub(crate) fn removable_shared_directory_root(path: &str) -> Result<String> {
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
