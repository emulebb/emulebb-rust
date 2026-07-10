use super::*;

impl EmulebbCore {
    pub async fn download_search_result(
        &self,
        search_id: &str,
        hash: &str,
        request: SearchResultDownloadCreate,
    ) -> Result<Option<Transfer>> {
        ensure_category_selector_is_unambiguous(
            request.category_id,
            request.category_name.as_deref(),
        )?;
        let category = self
            .resolve_transfer_category(request.category_id, request.category_name.as_deref())
            .await?;
        let result = {
            let state = self.state.lock().await;
            state
                .searches
                .get(search_id)
                .and_then(|search| search.results.iter().find(|result| result.hash == hash))
                .cloned()
        };
        let Some(result) = result else {
            return Ok(None);
        };
        self.upsert_transfer_from_parts(
            result.hash,
            result.name,
            result.size_bytes,
            transfer_create_state_name(request.paused),
            Some(category),
        )
        .await
        .map(Some)
    }

    pub async fn create_transfer(&self, request: TransferCreate) -> Result<Transfer> {
        let mut transfers = self.create_transfers(request).await?;
        ensure!(
            transfers.len() == 1,
            "create_transfer requires exactly one transfer link"
        );
        Ok(transfers.remove(0))
    }

    pub async fn create_transfers(&self, request: TransferCreate) -> Result<Vec<Transfer>> {
        ensure_category_selector_is_unambiguous(
            request.category_id,
            request.category_name.as_deref(),
        )?;
        let category = self
            .resolve_transfer_category(request.category_id, request.category_name.as_deref())
            .await?;
        let state_name = transfer_create_state_name(request.paused);
        let links = transfer_create_links(request)?;
        let mut transfers = Vec::with_capacity(links.len());
        for link in links {
            let parsed = parse_ed2k_link(&link)?;
            transfers.push(
                self.upsert_transfer_from_parts(
                    parsed.0,
                    parsed.1,
                    parsed.2,
                    state_name,
                    Some(category.clone()),
                )
                .await?,
            );
        }
        Ok(transfers)
    }

    pub async fn transfers(&self) -> Vec<Transfer> {
        let mut transfers: Vec<Transfer> = self
            .state
            .lock()
            .await
            .transfers
            .values()
            .cloned()
            .collect();
        for transfer in &mut transfers {
            self.apply_live_transfer_fields(transfer);
        }
        transfers
    }

    /// Overlay live in-flight download state onto a (possibly stale) cached
    /// `Transfer`. The cache is only rebuilt on state changes, so an actively
    /// downloading transfer otherwise reports the last-persisted manifest
    /// snapshot (progress/sources 0 until whole 9.28 MB parts verify). The
    /// verified-part `completed_bytes` remains the durable floor; the live
    /// per-block session byte counter and live source set surface real in-flight
    /// progress, speed, and source counts to REST/UI while the transfer runs.
    pub(crate) fn apply_live_transfer_fields(&self, transfer: &mut Transfer) {
        let hash = transfer.hash.as_str();
        let live_bytes = self.ed2k_transfers.downloaded_session_bytes(hash);
        transfer.completed_bytes = transfer
            .completed_bytes
            .max(live_bytes)
            .min(transfer.size_bytes);
        transfer.progress = if transfer.size_bytes == 0 {
            0.0
        } else {
            transfer.completed_bytes as f64 / transfer.size_bytes as f64
        };
        transfer.sources = transfer
            .sources
            .max(self.ed2k_transfers.live_download_sources(hash).len() as u32);
        transfer.sources_transferring = self.ed2k_transfers.transferring_source_count(hash);
        let speed_bps = self.ed2k_transfers.download_speed_bytes_per_sec(hash);
        transfer.download_speed_ki_bps = speed_bps as f64 / 1024.0;
        // Recompute ETA from the live speed + the overlaid completed_bytes (the
        // cached value was computed at manifest-build time and goes stale), and
        // refresh the live count of parts at least one source can serve.
        let remaining = transfer.size_bytes.saturating_sub(transfer.completed_bytes);
        transfer.eta = if speed_bps > 0 && remaining > 0 {
            Some(remaining / speed_bps)
        } else {
            None
        };
        transfer.parts_available = self
            .ed2k_transfers
            .available_part_count(hash, transfer.parts_total);
    }
}
