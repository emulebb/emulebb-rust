use super::*;

impl EmulebbCore {
    pub(crate) fn transfer_from_manifest(
        &self,
        manifest: &Ed2kResumeManifest,
        state_name: &str,
    ) -> Transfer {
        let parts_total = manifest.pieces.len() as u32;
        // A share-in-place file lives at (and is served from) its original path;
        // a real download reports its internal piece-store payload path.
        let mut transfer = transfer_from_manifest(
            manifest,
            state_name,
            manifest.source_path.clone().unwrap_or_else(|| {
                self.ed2k_transfers
                    .payload_path(&manifest.file_hash)
                    .display()
                    .to_string()
            }),
            self.ed2k_transfers
                .download_speed_bytes_per_sec(&manifest.file_hash),
            self.ed2k_transfers
                .transferring_source_count(&manifest.file_hash),
            self.ed2k_transfers
                .available_part_count(&manifest.file_hash, parts_total),
            self.ed2k_transfers
                .downloaded_session_bytes(&manifest.file_hash),
            self.ed2k_transfers
                .live_download_sources(&manifest.file_hash)
                .len() as u32,
        );
        // Surface persisted addedAt/completedAt from the metadata store.
        if let Ok(Some((created_ms, completed_ms))) = self
            .metadata_store
            .transfer_timestamps_by_hash(&manifest.file_hash)
        {
            transfer.added_at = Some(created_ms);
            transfer.completed_at = completed_ms;
        }
        // Classify "completed download" vs "shared-only file" by directory (eMule
        // semantics, unlike qBittorrent where every complete torrent is also a
        // share). A transfer is a download if it is still downloading, was
        // delivered to an incoming/category dir (`delivered_path` set), or its
        // file resides in the global incoming dir -- which may itself double as a
        // configured shared dir (e.g. the eMule Incoming folder). A file that is
        // only shared from a shared dir (and never downloaded) stays false.
        transfer.in_incoming = !manifest.completed
            || manifest.delivered_path.is_some()
            || path_is_within(&transfer.path, &self.incoming_dir);
        transfer
    }

    pub(crate) async fn set_transfer_state(
        &self,
        hash: &str,
        state_name: &str,
    ) -> Option<Transfer> {
        let mut state = self.state.lock().await;
        let transfer = state.transfers.get_mut(hash)?;
        transfer.state = state_name.to_string();
        Some(transfer.clone())
    }

    pub(crate) async fn set_transfer_control_state(
        &self,
        hash: &str,
        state_name: &str,
    ) -> Result<Option<Transfer>> {
        if self.transfer(hash).await.is_none() {
            return Ok(None);
        }
        let manifest = self
            .ed2k_transfers
            .set_control_state(hash, Some(state_name))
            .await?;
        // Pause/stop must stop the transfer NOW: the driver does not read
        // control_state mid-attempt, so without this an in-flight attempt keeps
        // connecting peers and writing pieces through the rest of the current
        // round and only the next retry is suppressed. Cancel the in-flight
        // attempt so it stops at its next loop-top/mid-round check. Resume
        // re-queues a fresh attempt (its cancel token is recreated then).
        self.cancel_download_attempt(hash).await;
        let mut transfer = self.transfer_from_manifest(&manifest, state_name);
        let mut state = self.state.lock().await;
        apply_persisted_transfer_category(&mut transfer, &manifest, &state.categories);
        if let Some(existing) = state.transfers.get(&transfer.hash) {
            preserve_transfer_public_metadata(&mut transfer, existing);
        }
        state
            .transfers
            .insert(transfer.hash.clone(), transfer.clone());
        Ok(Some(transfer))
    }

    pub async fn resume_transfer(&self, hash: &str) -> Result<Option<Transfer>> {
        let Some(current) = self.transfer(hash).await else {
            return Ok(None);
        };
        if current.state == "completed" {
            return Ok(Some(current));
        }
        anyhow::ensure!(!current.stopped, "stopped transfer cannot be resumed");
        self.ed2k_transfers.set_control_state(hash, None).await?;
        let Some(transfer) = self.set_transfer_state(hash, "downloading").await else {
            return Ok(None);
        };
        self.queue_ed2k_download_attempt(transfer.clone());
        Ok(Some(transfer))
    }

    /// Startup download hydration: load persisted INCOMPLETE downloads into the
    /// in-memory transfer set and queue a download attempt for each, so in-progress
    /// downloads resume after a restart. Mirrors the fact that the MFC oracle's
    /// `CDownloadQueue` resumes every incomplete `.part` file on launch. Without
    /// this, `state.transfers` starts empty (`profile_state.rs`) and every persisted
    /// partial download is abandoned across restarts (evidence: 39 multi-GB partials
    /// stranded on a single restart). Returns the number resumed.
    ///
    /// Skips: completed transfers (delivered/shared, not downloads), user
    /// paused/stopped transfers (`control_state`), share-in-place shared files
    /// (`source_path` set — served from their original path, not downloaded), and
    /// any transfer already present in memory (a REST resume racing startup).
    pub async fn resume_persisted_downloads(&self) -> usize {
        // Load ONLY the incomplete rows, off the async runtime (spawn_blocking) — see
        // `incomplete_manifests`. Loading the full library inline (`manifests`) blocks
        // a tokio worker and starves REST at startup.
        let manifests = match self.ed2k_transfers.incomplete_manifests().await {
            Ok(manifests) => manifests,
            Err(error) => {
                tracing::warn!(
                    "startup download hydration: failed to list persisted transfers: {error:#}"
                );
                return 0;
            }
        };
        // Resume GRADUALLY. Queuing dozens of downloads at once (39 observed on the
        // soak profile) thunder-herds the state lock and the source coordinator on
        // top of the large-library shared reload, starving REST at startup (the
        // control plane wedged in a live test). Let the post-connect startup burst
        // settle, then stagger each resume — eMule's CDownloadQueue likewise drives
        // incomplete files a few at a time, not all in one tick.
        tokio::time::sleep(Duration::from_secs(RESUME_DOWNLOADS_INITIAL_DELAY_SECS)).await;
        let mut resumed = 0usize;
        for manifest in manifests {
            if manifest.completed
                || manifest.source_path.is_some()
                || matches!(
                    manifest.control_state.as_deref(),
                    Some("paused") | Some("stopped")
                )
            {
                continue;
            }
            let mut transfer = self.transfer_from_manifest(&manifest, "downloading");
            {
                let mut state = self.state.lock().await;
                if state.transfers.contains_key(&transfer.hash) {
                    continue;
                }
                apply_persisted_transfer_category(&mut transfer, &manifest, &state.categories);
                state
                    .transfers
                    .insert(transfer.hash.clone(), transfer.clone());
            }
            self.queue_ed2k_download_attempt(transfer);
            resumed = resumed.saturating_add(1);
            tokio::time::sleep(Duration::from_millis(RESUME_DOWNLOADS_STAGGER_MS)).await;
        }
        if resumed > 0 {
            tracing::info!(
                "startup download hydration: resumed {resumed} persisted incomplete downloads (staggered)"
            );
        }
        resumed
    }
}
