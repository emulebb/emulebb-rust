use super::*;

impl EmulebbCore {
    /// A protocol callback can observe only its actual selected execution.
    pub(crate) async fn selected_transfer(
        &self,
        token: emulebb_metadata::JobToken,
    ) -> Result<Option<Transfer>> {
        if !self.download_attempts.owns(token) {
            return Ok(None);
        }
        let Some(job) = self.ed2k_transfers.download_job(token.job_id).await? else {
            return Ok(None);
        };
        if job.token != token
            || job.removed_at_s.is_some()
            || job.storage_failure.is_some()
            || job.intent != emulebb_metadata::DownloadIntent::Started
        {
            return Ok(None);
        }
        drop(job);
        let state = self.state.lock().await;
        let mut transfer = state
            .transfers
            .values()
            .find(|transfer| transfer.job_token() == token)
            .cloned();
        drop(state);
        if let Some(transfer) = &mut transfer {
            self.apply_live_transfer_fields(transfer);
        }
        Ok(transfer)
    }

    /// Refresh only the captured execution. Callers cannot look up a replacement
    /// attempt by hash when their protocol work completes late.
    pub(crate) async fn refresh_transfer_from_manifest(
        &self,
        token: emulebb_metadata::JobToken,
        state_name: &str,
    ) -> Result<Option<Transfer>> {
        let transfer = self
            .refresh_transfer_from_manifest_silent(token, state_name)
            .await?;
        if let Some(transfer) = &transfer {
            self.publish_transfer_updated(transfer.clone());
        }
        Ok(transfer)
    }

    async fn refresh_transfer_from_manifest_silent(
        &self,
        token: emulebb_metadata::JobToken,
        state_name: &str,
    ) -> Result<Option<Transfer>> {
        let Some(manifest) = self.ed2k_transfers.manifest_optional(token).await? else {
            return Ok(None);
        };
        let mut transfer = self.transfer_from_manifest(&manifest, state_name)?;
        let _fence = self.ed2k_transfers.lock_category_publication().await;
        let Some(job) = self.ed2k_transfers.download_job(token.job_id).await? else {
            return Ok(None);
        };
        if job.token != token || job.removed_at_s.is_some() {
            return Ok(None);
        }
        let mut state = self.state.lock().await;
        if state
            .transfers
            .get(&transfer.hash)
            .is_some_and(|current| current.job_token() != token)
        {
            return Ok(None);
        }
        transfer.category_id = job.category_id;
        transfer.category_name = job
            .category_id
            .and_then(|id| state.categories.get(&id))
            .map(|category| category.name.clone());
        transfer.added_at = Some(job.created_at_s);
        transfer.completed_at = job.completed_at_s;
        if let Some(existing) = state.transfers.get(&transfer.hash) {
            preserve_transfer_public_metadata(&mut transfer, existing);
        }
        state
            .transfers
            .insert(transfer.hash.clone(), transfer.clone());
        Ok(Some(transfer))
    }

    async fn refresh_transfer_from_manifest_default(
        &self,
        token: emulebb_metadata::JobToken,
    ) -> Result<Option<Transfer>> {
        let Some(manifest) = self.ed2k_transfers.manifest_optional(token).await? else {
            return Ok(None);
        };
        let state = manifest_default_state_name(&manifest).to_owned();
        drop(manifest);
        self.refresh_transfer_from_manifest_silent(token, &state)
            .await
    }

    pub(crate) fn transfer_from_manifest(
        &self,
        manifest: &Ed2kResumeManifest,
        state_name: &str,
    ) -> Result<Transfer> {
        let parts_total = manifest.pieces.len() as u32;
        let mut transfer = transfer_from_manifest(
            manifest,
            state_name,
            self.ed2k_transfers
                .payload_path(manifest.token.job_id)?
                .display()
                .to_string(),
            self.ed2k_transfers
                .download_speed_bytes_per_sec(manifest.token),
            self.ed2k_transfers
                .transferring_source_count(manifest.token),
            self.ed2k_transfers
                .available_part_count(manifest.token, parts_total),
            self.ed2k_transfers.downloaded_session_bytes(manifest.token),
            self.ed2k_transfers
                .live_download_sources(manifest.token)
                .len() as u32,
        );
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
        Ok(transfer)
    }

    pub(crate) async fn set_transfer_state(
        &self,
        hash: &str,
        state_name: &str,
    ) -> Option<Transfer> {
        let mut state = self.state.lock().await;
        let transfer = state.transfers.get_mut(hash)?;
        transfer.state = state_name.to_string();
        let transfer = transfer.clone();
        drop(state);
        self.publish_transfer_updated(transfer.clone());
        Some(transfer)
    }
}
