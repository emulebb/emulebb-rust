use super::*;

impl EmulebbCore {
    pub async fn share_local_file(&self, request: LocalShareCreate) -> Result<LocalShare> {
        self.share_local_file_with_progress(request, None).await
    }

    pub(crate) async fn share_local_file_with_progress(
        &self,
        request: LocalShareCreate,
        progress: Option<emulebb_ed2k::ed2k_transfer::LocalIngestProgressObserver>,
    ) -> Result<LocalShare> {
        let source_path = Path::new(&request.path);
        let display_name = match request.name {
            Some(name) => name,
            None => source_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow::anyhow!("local share path has no valid file name"))?
                .to_string(),
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
        self.ed2k_transfers
            .remove_completed_transfer_row(&summary.file_hash)
            .await?;
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
        self.index.lock().await.upsert_file(&IndexedFile {
            ed2k_hash: summary.file_hash.clone(),
            name: summary.display_name.clone(),
            size_bytes: summary.file_size,
            content_type: ed2k_file_type_search_term(&summary.display_name)
                .unwrap_or("unknown")
                .to_string(),
            availability_score: 1,
        })?;
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

    fn local_share_from_entry(&self, entry: MetadataTransferShareEntry) -> LocalShare {
        LocalShare {
            hash: entry.file_hash.clone(),
            name: entry.display_name.clone(),
            size_bytes: entry.file_size,
            part_count: entry.part_count,
            ed2k_link: format!(
                "ed2k://|file|{}|{}|{}|/",
                entry.display_name, entry.file_size, entry.file_hash
            ),
            aich_root: entry.aich_root.clone().unwrap_or_default(),
            transfer_dir: self
                .ed2k_transfers
                .transfer_dir_path(&entry.file_hash)
                .display()
                .to_string(),
            source_path: entry.source_path.clone(),
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
        self.shares()
            .await
            .into_iter()
            .find(|share| share.hash.eq_ignore_ascii_case(hash))
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
        // A metadata PATCH mutates only priority/comment/rating -- none of which
        // are in the eD2k offer set or per-file offer content -- so it changes
        // neither the share status nor the completion state and must not spin up a
        // redundant re-offer session (Publish-G3). Comment/rating already have
        // their own Kad-notes trigger above.
        if shared_file_change_requires_ed2k_reoffer(false, false) {
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
        let items = shared_directory_items(roots.clone()).await;
        let monitor_owned = items
            .iter()
            .filter(|item| item.monitor_owned)
            .map(|item| item.path.clone())
            .collect::<Vec<_>>();
        SharedDirectories {
            roots,
            items,
            monitor_owned,
            // Files still pending the initial hash in the background reload worker.
            hashing_count: shared_directories::hashing_count_snapshot(self),
            reload_progress: reload_progress_snapshot(self),
        }
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

fn canonical_shared_directory_root(path: &str) -> Result<String> {
    let path = path.trim();
    ensure!(!path.is_empty(), "path must not be empty");
    let canonical = fs::canonicalize(long_path(Path::new(path)))
        .with_context(|| format!("failed to resolve {path}"))?;
    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("failed to inspect {}", canonical.display()))?;
    ensure!(metadata.is_dir(), "path is not a directory");
    Ok(canonical.display().to_string())
}

fn removable_shared_directory_root(path: &str) -> Result<String> {
    let path = path.trim();
    ensure!(!path.is_empty(), "path must not be empty");
    match fs::canonicalize(long_path(Path::new(path))) {
        Ok(canonical) => {
            let metadata = fs::metadata(&canonical)
                .with_context(|| format!("failed to inspect {}", canonical.display()))?;
            ensure!(metadata.is_dir(), "path is not a directory");
            Ok(canonical.display().to_string())
        }
        Err(_) => Ok(path.to_string()),
    }
}

fn dedupe_shared_directory_roots(roots: Vec<SharedDirectoryRoot>) -> Vec<SharedDirectoryRoot> {
    let mut seen = HashSet::new();
    roots
        .into_iter()
        .filter(|root| seen.insert(root.path.to_ascii_lowercase()))
        .collect()
}
