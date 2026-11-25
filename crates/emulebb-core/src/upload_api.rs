use super::*;

/// Owned response allowance, including conservative JSON escaping headroom.
pub const UPLOAD_PAGE_BYTES: usize = 2 * 1024 * 1024;

pub struct UploadPage {
    pub uploads: Vec<Upload>,
    pub next_after: Option<uuid::Uuid>,
    pub has_more: bool,
    pub total: Option<usize>,
}

impl EmulebbCore {
    /// Project only a bounded live waiting page. File-caption reads keep their
    /// independent worker charges; failures propagate instead of omitting facts.
    pub async fn upload_queue_page(
        &self,
        after: Option<uuid::Uuid>,
        limit: usize,
        count_total: bool,
    ) -> Result<emulebb_ed2k::ed2k_transfer::RetainedRead<UploadPage>> {
        let page = self
            .ed2k_transfers
            .upload_queue_page(after, limit, count_total)
            .await?;
        self.project_upload_page(page).await
    }

    pub async fn active_upload_page(
        &self,
        after: Option<uuid::Uuid>,
        limit: usize,
        count_total: bool,
    ) -> Result<emulebb_ed2k::ed2k_transfer::RetainedRead<UploadPage>> {
        let page = self
            .ed2k_transfers
            .active_upload_page(after, limit, count_total)
            .await?;
        self.project_upload_page(page).await
    }

    async fn project_upload_page(
        &self,
        page: emulebb_ed2k::ed2k_transfer::RetainedRead<
            emulebb_ed2k::ed2k_transfer::Ed2kUploadQueuePage,
        >,
    ) -> Result<emulebb_ed2k::ed2k_transfer::RetainedRead<UploadPage>> {
        page.try_project_async(UPLOAD_PAGE_BYTES, |page| async move {
            let mut uploads = Vec::with_capacity(page.entries.len());
            let mut bytes = uploads.capacity() * std::mem::size_of::<Upload>();
            let mut has_more = page.has_more;
            let mut last = None;
            for entry in page.entries {
                let summary = self
                    .ed2k_transfers
                    .upload_file_summary(&entry.file_hash)
                    .await
                    .map_err(upload_read_error)?;
                // Sevenfold text headroom covers simultaneous owned strings and
                // worst-case JSON escaping; scalar fields fit the fixed allowance.
                let text = entry.client_software.as_ref().map_or(0, String::len)
                    + summary.as_deref().map_or(0, |file| file.display_name.len())
                    + 256;
                let row_bytes = text.saturating_mul(7).saturating_add(4096);
                if bytes.saturating_add(row_bytes) > UPLOAD_PAGE_BYTES {
                    anyhow::ensure!(!uploads.is_empty(), LocalMutationError::TooLarge);
                    has_more = true;
                    break;
                }
                bytes += row_bytes;
                last = Some(entry.id);
                let mut upload = upload_from_snapshot(entry, summary.as_deref());
                upload.score_breakdown = None;
                uploads.push(upload);
            }
            Ok(UploadPage {
                uploads,
                next_after: if has_more { last } else { None },
                has_more,
                total: page.total,
            })
        })
        .await
    }

    pub async fn upload_policy_metrics(&self) -> UploadPolicyMetrics {
        upload_policy_metrics_from_capacity(
            self.ed2k_transfers.upload_queue_capacity_snapshot().await,
        )
    }

    pub async fn download_source_metrics(&self) -> DownloadSourceMetrics {
        let state = self.state.lock().await;
        DownloadSourceMetrics {
            candidates: state.download_source_registry.candidate_count(),
            a4af_candidates: state.download_source_registry.a4af_candidate_count(),
            leased_peers: state.download_source_registry.leased_peer_count(),
        }
    }

    /// Live transfer throughput roll-up for the REST `stats` surface.
    pub fn transfer_throughput_stats(&self) -> TransferThroughputStats {
        TransferThroughputStats {
            download_rate_bytes_per_sec: self
                .ed2k_transfers
                .aggregate_download_speed_bytes_per_sec(),
            session_downloaded_bytes: self.ed2k_transfers.session_downloaded_bytes(),
            session_uploaded_bytes: self.ed2k_transfers.session_uploaded_bytes(),
        }
    }

    pub async fn upload(
        &self,
        client_id: &str,
        waiting_queue: bool,
    ) -> Result<Option<emulebb_ed2k::ed2k_transfer::RetainedRead<Upload>>> {
        let Some(entry) = self
            .ed2k_transfers
            .upload_client_snapshot(client_id, waiting_queue)
            .await?
        else {
            return Ok(None);
        };
        entry
            .try_project_async(UPLOAD_PAGE_BYTES, |entry| async move {
                let view = self
                    .ed2k_transfers
                    .upload_file_summary(&entry.file_hash)
                    .await
                    .map_err(upload_read_error)?;
                let text = entry.client_software.as_ref().map_or(0, String::len)
                    + view.as_deref().map_or(0, |file| file.display_name.len())
                    + 256;
                anyhow::ensure!(
                    text.saturating_mul(7).saturating_add(4096) <= UPLOAD_PAGE_BYTES,
                    LocalMutationError::TooLarge
                );
                Ok(upload_from_snapshot(entry, view.as_deref()))
            })
            .await
            .map(Some)
    }

    pub async fn add_upload_client_friend(&self, client_id: &str) -> Result<Option<Friend>> {
        let Some(upload) = self.upload_client_for_control(client_id).await else {
            return Ok(None);
        };
        let Some(user_hash) = upload.user_hash else {
            anyhow::bail!("upload client does not expose a userHash");
        };
        self.add_friend(FriendCreate {
            user_hash: hex::encode(user_hash),
            name: Some(std::net::SocketAddr::new(upload.ip, upload.tcp_port).to_string()),
            browse_key_sha256: None,
        })
        .await
        .map(Some)
    }

    pub async fn remove_upload_client_friend(&self, client_id: &str) -> Result<Option<Friend>> {
        let Some(upload) = self.upload_client_for_control(client_id).await else {
            return Ok(None);
        };
        let Some(user_hash) = upload.user_hash else {
            return Ok(None);
        };
        self.delete_friend(&hex::encode(user_hash)).await
    }

    /// Re-read the configured `ipfilter.dat` and swap it into the live shared
    /// `IpFilter`, mirroring `CIPFilter::Reload`. Because the `IpFilter` backing
    /// is shared across every clone (listener, Kad traversal closure, UDP reask
    /// loop, source-add gate), the new ranges take effect immediately without a
    /// restart. Returns the number of ranges loaded, or `None` when no eD2k
    /// network / ipfilter path is configured.
    pub fn reload_ip_filter(&self) -> Result<Option<usize>> {
        let Some(network) = self.ed2k_network.as_ref() else {
            return Ok(None);
        };
        let Some(path) = network.ip_filter_path.as_ref() else {
            return Ok(None);
        };
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read ipfilter.dat at {}", path.display()))?;
        network
            .ip_filter
            .reload_from(&body, network.ip_filter_level);
        Ok(Some(network.ip_filter.len()))
    }

    pub async fn ban_upload_client(&self, client_id: &str) -> Result<Option<bool>> {
        let Some(upload) = self.upload_client_for_control(client_id).await else {
            return Ok(None);
        };
        // Back the manual ban with the enforced ban store (IP + user hash, 4h
        // CLIENTBANTIME TTL) so it is actually rejected at accept/connect/source
        // add, mirroring eMule's `CUpDownClient::Ban` (UploadClient.cpp:1042 ->
        // CClientList::AddBannedClient).
        self.ed2k_transfers.ban_client(
            match upload.ip {
                std::net::IpAddr::V4(ip) => Some(ip),
                _ => None,
            },
            upload.user_hash,
        );
        Ok(Some(true))
    }

    pub async fn unban_upload_client(&self, client_id: &str) -> Result<Option<bool>> {
        let Some(upload) = self.upload_client_for_control(client_id).await else {
            return Ok(None);
        };
        let hash = upload.user_hash;
        self.ed2k_transfers.ban_store().unban(
            match upload.ip {
                std::net::IpAddr::V4(ip) => Some(ip),
                _ => None,
            },
            hash.as_ref(),
        );
        Ok(Some(false))
    }

    pub async fn remove_upload_client(&self, client_id: &str) -> Result<Option<&'static str>> {
        if self
            .ed2k_transfers
            .release_upload_client(client_id, true)
            .await
        {
            return Ok(Some("queue"));
        }
        if self
            .ed2k_transfers
            .release_upload_client(client_id, false)
            .await
        {
            return Ok(Some("slot"));
        }
        if self.upload_client_for_control(client_id).await.is_none() {
            return Ok(None);
        }
        anyhow::bail!("upload client is not active or queued");
    }

    pub async fn release_upload_slot(&self, client_id: &str) -> Result<Option<()>> {
        let Some(identity) = self.upload_client_for_control(client_id).await else {
            return Ok(None);
        };
        if identity.phase != emulebb_ed2k::ed2k_transfer::Ed2kUploadSessionPhaseSnapshot::Waiting {
            if self
                .ed2k_transfers
                .release_upload_client(client_id, false)
                .await
            {
                return Ok(Some(()));
            }
            return Ok(None);
        }
        anyhow::bail!("client does not currently hold an upload slot")
    }
}

fn upload_read_error(error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<LocalMutationError>().is_some()
        || error.downcast_ref::<PersistenceError>().is_some()
    {
        return error;
    }
    tracing::warn!(%error,"upload caption read failed");
    PersistenceError::Storage("upload caption read failed".into()).into()
}
