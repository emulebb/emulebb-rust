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
        let result_and_aich = {
            let state = self.state.lock().await;
            let result = state
                .searches
                .get(search_id)
                .and_then(|search| search.results.iter().find(|result| result.hash == hash))
                .cloned();
            result.map(|result| {
                let observations = state
                    .kad_aich_search_votes
                    .get(&(search_id.to_string(), result.hash.clone()))
                    .map(crate::KadAichSearchVotes::observations)
                    .unwrap_or_default();
                (result, observations)
            })
        };
        let Some((result, aich_observations)) = result_and_aich else {
            return Ok(None);
        };
        ensure!(
            result.size_bytes != 0,
            "search result has no usable file size"
        );
        let source_hints = search_result_source_hints(&result);
        let transfer = self
            .upsert_transfer_from_parts(
                result.hash,
                result.name,
                result.size_bytes,
                transfer_create_state_name(request.paused),
                Some(category),
            )
            .await?;
        if !aich_observations.is_empty() {
            // The search row's hidden AICH string is display metadata only.
            // Trust receives the actual live responder/root observations.
            self.ed2k_transfers
                .record_network_aich_observations(&transfer.hash, &aich_observations)
                .await?;
        }
        for source_hint in source_hints {
            // WHY: server search entries carry an immediately usable source
            // endpoint. Retain every distinct observation so a hash-level
            // result does not force redundant rediscovery after download starts.
            self.ed2k_transfers
                .remember_source(&transfer.hash, source_hint)
                .await?;
        }
        Ok(Some(transfer))
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
            let transfer = self
                .upsert_transfer_from_parts(
                    parsed.file_hash,
                    parsed.name,
                    parsed.size_bytes,
                    state_name,
                    Some(category.clone()),
                )
                .await?;
            for source in parsed.sources {
                self.ed2k_transfers
                    .remember_source(&transfer.hash, source)
                    .await?;
            }
            transfers.push(self.transfer(&transfer.hash).await.unwrap_or(transfer));
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

fn search_result_source_hints(result: &SearchResult) -> Vec<Ed2kSourceHint> {
    let mut sources = result
        .observations
        .iter()
        .filter_map(|observation| {
            observation
                .source_client_id
                .zip(observation.source_client_port)
        })
        .collect::<Vec<_>>();
    if sources.is_empty()
        && let Some(source) = result.source_client_id.zip(result.source_client_port)
    {
        sources.push(source);
    }
    let mut seen = std::collections::HashSet::new();
    sources
        .into_iter()
        .filter(|source| seen.insert(*source))
        .filter_map(|(client_id, tcp_port)| search_source_hint(client_id, tcp_port))
        .collect()
}

fn search_source_hint(client_id: u32, tcp_port: u16) -> Option<Ed2kSourceHint> {
    if client_id < 0x0100_0000 || tcp_port == 0 {
        return None;
    }
    Some(Ed2kSourceHint {
        ip: std::net::Ipv4Addr::from(client_id.to_le_bytes()).to_string(),
        tcp_port,
        user_hash: None,
        connect_options: None,
        file_comment: String::new(),
        file_rating: 0,
    })
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::search_result_source_hints;
    use crate::{SearchResult, SearchResultObservation};

    fn result(client_id: Option<u32>, client_port: Option<u16>) -> SearchResult {
        SearchResult {
            search_id: "1".to_string(),
            r#type: String::new(),
            hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Synthetic.bin".to_string(),
            size_bytes: 1,
            sources: 1,
            complete_sources: 0,
            source_client_id: client_id,
            source_client_port: client_port,
            file_type: String::new(),
            media: Default::default(),
            rating: 0,
            aich_hash: String::new(),
            complete: false,
            directory: String::new(),
            observations: Vec::new(),
        }
    }

    #[test]
    fn high_id_search_source_becomes_immediate_transfer_hint() {
        let hints = search_result_source_hints(&result(
            Some(u32::from_le_bytes([10, 20, 30, 40])),
            Some(4662),
        ));
        let hint = &hints[0];

        assert_eq!(hint.ip, "10.20.30.40");
        assert_eq!(hint.tcp_port, 4662);
        assert_eq!(hint.user_hash, None);
    }

    #[test]
    fn low_id_or_incomplete_search_source_is_not_dialed_directly() {
        assert!(search_result_source_hints(&result(Some(42), Some(4662))).is_empty());
        assert!(search_result_source_hints(&result(Some(0x2800_000A), None)).is_empty());
    }

    #[test]
    fn every_distinct_observed_high_id_becomes_a_transfer_hint() {
        let mut result = result(None, None);
        result.observations = [
            ([10, 20, 30, 40], 4662),
            ([10, 20, 30, 41], 4663),
            ([10, 20, 30, 40], 4662),
        ]
        .into_iter()
        .map(|(ip, port)| SearchResultObservation {
            origin: "global".to_string(),
            name: result.name.clone(),
            size_bytes: result.size_bytes,
            sources: 1,
            complete_sources: 0,
            source_client_id: Some(u32::from_le_bytes(ip)),
            source_client_port: Some(port),
            file_type: String::new(),
            media: Default::default(),
            rating: 0,
            aich_hash: String::new(),
            complete: false,
            directory: String::new(),
            observed_at: Utc::now(),
        })
        .collect();

        let hints = search_result_source_hints(&result);

        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].ip, "10.20.30.40");
        assert_eq!(hints[1].ip, "10.20.30.41");
    }
}
