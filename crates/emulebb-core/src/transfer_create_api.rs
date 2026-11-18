use super::*;
use emulebb_ed2k::ed2k_transfer::RetainedRead;
use emulebb_metadata::{
    DownloadJobRequest, MetadataDownloadInitialPeers, MetadataTransferFileNameObservation,
    MetadataTransferSource,
};

/// Prepared content and peer evidence; no execution state or storage is allocated.
struct DownloadAdmissionInput {
    hash: String,
    name: String,
    size: Option<u64>,
    aich: Option<String>,
    peers: MetadataDownloadInitialPeers,
}

impl EmulebbCore {
    /// Admit exactly one durable job without allocating or hydrating execution.
    pub async fn create_download(
        &self,
        request: DownloadCreate,
    ) -> Result<(bool, RetainedRead<DownloadSummary>)> {
        let (hash, name, size, aich, sources) = match request.source {
            DownloadCreateSource::Ed2kLink { link } => {
                let parsed = parse_ed2k_link(&link)?;
                (
                    parsed.file_hash,
                    parsed.name,
                    Some(parsed.size_bytes),
                    parsed.aich_root.map(hex::encode),
                    parsed.sources,
                )
            }
            DownloadCreateSource::Content {
                hash,
                name,
                size_bytes,
            } => (hash, name, size_bytes, None, Vec::new()),
        };
        let peers = MetadataDownloadInitialPeers {
            sources: sources.into_iter().map(initial_source).collect(),
            observations: Vec::new(),
        };
        self.admit_download(
            DownloadAdmissionInput {
                hash,
                name,
                size,
                aich,
                peers,
            },
            request.category,
            request.intent,
            request.redownload,
        )
        .await
    }

    pub async fn download_search_result(
        &self,
        search_id: &str,
        hash: &str,
        request: SearchResultDownloadCreate,
    ) -> Result<Option<(bool, RetainedRead<DownloadSummary>)>> {
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
        ensure!(
            result.size_bytes > 0,
            "search result has no usable file size"
        );
        let sources = search_result_source_hints(&result)
            .into_iter()
            .map(initial_source)
            .collect();
        let observations = result
            .observations
            .into_iter()
            .map(|observation| {
                let endpoint = observation
                    .source_client_id
                    .zip(observation.source_client_port)
                    .and_then(|(id, port)| search_source_hint(id, port));
                MetadataTransferFileNameObservation {
                    source_ip: endpoint.as_ref().map(|v| v.ip.clone()),
                    source_tcp_port: endpoint.as_ref().map(|v| v.tcp_port),
                    user_hash: None,
                    client_software: String::new(),
                    origin: observation.origin,
                    reporter_endpoint: observation.reporter_endpoint,
                    normalized_name: emulebb_ed2k::normalize_ed2k_file_name(&observation.name),
                    raw_name: observation.name,
                    observed_at_s: observation.observed_at.timestamp(),
                }
            })
            .collect();
        // Live Kad trust votes remain session-local search provenance. The
        // selected execution must consume them; cached search metadata is not trust.
        self.admit_download(
            DownloadAdmissionInput {
                hash: result.hash,
                name: result.name,
                size: Some(result.size_bytes),
                aich: None,
                peers: MetadataDownloadInitialPeers {
                    sources,
                    observations,
                },
            },
            request.category,
            request.intent,
            request.redownload,
        )
        .await
        .map(Some)
    }

    async fn admit_download(
        &self,
        input: DownloadAdmissionInput,
        category: Option<String>,
        intent: emulebb_metadata::DownloadIntent,
        redownload: bool,
    ) -> Result<(bool, RetainedRead<DownloadSummary>)> {
        let DownloadAdmissionInput {
            hash,
            name,
            size,
            aich,
            peers,
        } = input;
        self.persistence_owner.check_coherent_state()?;
        let hash = hash.parse::<Ed2kHash>()?.to_string();
        let request = DownloadJobRequest {
            file_hash: hash,
            display_name: emulebb_ed2k::normalize_ed2k_file_name(&name),
            expected_size_bytes: size,
            piece_size: ED2K_PART_SIZE,
            category_id: None,
            intent,
        };
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        owner
            .create_download(crate::persistence_owner::DownloadCreateCommand {
                request,
                category,
                redownload,
                aich,
                peers,
                runtime: Arc::clone(&self.ed2k_transfers),
                attempts: Arc::clone(&self.download_attempts),
                events: Arc::clone(&self.download_events),
            })
            .await
    }

    /// Overlay live in-flight download state onto a (possibly stale) cached
    /// `Transfer`. The cache is only rebuilt on state changes, so an actively
    /// downloading transfer otherwise reports the last-persisted manifest
    /// snapshot (progress/sources 0 until whole 9.28 MB parts verify). The
    /// verified-part `completed_bytes` remains the durable floor; the live
    /// per-block session byte counter and live source set surface real in-flight
    /// progress, speed, and source counts to REST/UI while the transfer runs.
    pub(crate) fn apply_live_transfer_fields(&self, transfer: &mut Transfer) {
        let token = transfer.job_token();
        let live_bytes = self.ed2k_transfers.downloaded_session_bytes(token);
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
            .max(self.ed2k_transfers.live_download_sources(token).len() as u32);
        transfer.sources_transferring = self.ed2k_transfers.transferring_source_count(token);
        let speed_bps = self.ed2k_transfers.download_speed_bytes_per_sec(token);
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
            .available_part_count(token, transfer.parts_total);
    }
}

fn initial_source(source: Ed2kSourceHint) -> MetadataTransferSource {
    MetadataTransferSource {
        ip: source.ip,
        tcp_port: source.tcp_port,
        user_hash: source.user_hash,
        connect_options: source.connect_options,
        file_comment: source.file_comment,
        file_rating: source.file_rating,
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
            reporter_endpoint: None,
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
