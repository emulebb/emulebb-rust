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
        result_id: &str,
        request: SearchResultDownloadCreate,
    ) -> Result<Option<(bool, RetainedRead<DownloadSummary>)>> {
        let session_id: i64 = search_id.parse().context("invalid search identity")?;
        let claim_id: i64 = result_id
            .parse()
            .context("invalid search result identity")?;
        ensure!(
            session_id > 0 && session_id.to_string() == search_id,
            "invalid search identity"
        );
        ensure!(
            claim_id > 0 && claim_id.to_string() == result_id,
            "invalid search result identity"
        );
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        let crate::LibraryReply {
            value,
            lease: _seed_lease,
        } = owner.search_download_seed(session_id, claim_id).await?;
        let Some(seed) = value else { return Ok(None) };
        let sources = search_source_hints(
            seed.source_client_id.zip(seed.source_client_port),
            seed.observations.iter().filter_map(|member| {
                member
                    .observation
                    .event
                    .metadata
                    .source_client_id
                    .zip(member.observation.event.metadata.source_client_port)
            }),
        )
        .into_iter()
        .map(initial_source)
        .collect();
        let observations = seed
            .observations
            .into_iter()
            .map(|member| {
                let event = member.observation.event;
                let metadata = event.metadata;
                let endpoint = metadata
                    .source_client_id
                    .zip(metadata.source_client_port)
                    .and_then(|(id, port)| search_source_hint(id, port));
                let name = metadata.name.unwrap_or_default();
                MetadataTransferFileNameObservation {
                    source_ip: endpoint.as_ref().map(|v| v.ip.clone()),
                    source_tcp_port: endpoint.as_ref().map(|v| v.tcp_port),
                    user_hash: None,
                    client_software: String::new(),
                    origin: event.origin.as_str().into(),
                    reporter_endpoint: event.reporter_endpoint.map(|v| v.to_string()),
                    normalized_name: emulebb_ed2k::normalize_ed2k_file_name(&name),
                    raw_name: name,
                    observed_at_s: member.last_seen_at_s,
                }
            })
            .collect();
        // Live Kad trust votes remain session-local search provenance. The
        // selected execution must consume them; cached search metadata is not trust.
        self.admit_download(
            DownloadAdmissionInput {
                hash: seed.file_hash,
                name: seed.name,
                size: seed.size_bytes,
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

fn search_source_hints(
    aggregate: Option<(u32, u16)>,
    observations: impl IntoIterator<Item = (u32, u16)>,
) -> Vec<Ed2kSourceHint> {
    let mut sources = observations.into_iter().collect::<Vec<_>>();
    if sources.is_empty()
        && let Some(source) = aggregate
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
    use super::search_source_hints;

    #[test]
    fn high_id_search_source_becomes_immediate_transfer_hint() {
        let hints = search_source_hints(Some((u32::from_le_bytes([10, 20, 30, 40]), 4662)), []);
        assert_eq!(hints[0].ip, "10.20.30.40");
        assert_eq!(hints[0].tcp_port, 4662);
        assert_eq!(hints[0].user_hash, None);
    }
    #[test]
    fn low_id_or_incomplete_search_source_is_not_dialed_directly() {
        assert!(search_source_hints(Some((42, 4662)), []).is_empty());
        assert!(search_source_hints(None, []).is_empty());
        assert!(search_source_hints(Some((0x2800_000A, 0)), []).is_empty());
    }
    #[test]
    fn every_distinct_observed_high_id_becomes_a_transfer_hint() {
        let observations = [
            ([10, 20, 30, 40], 4662),
            ([10, 20, 30, 41], 4663),
            ([10, 20, 30, 40], 4662),
        ]
        .map(|(ip, port)| (u32::from_le_bytes(ip), port));
        let hints = search_source_hints(None, observations);
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].ip, "10.20.30.40");
        assert_eq!(hints[1].ip, "10.20.30.41");
    }
}
