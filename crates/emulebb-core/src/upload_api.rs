use super::*;

impl EmulebbCore {
    pub async fn uploads(&self) -> Vec<Upload> {
        self.uploads_by_queue_state(false).await
    }

    pub async fn upload_queue(&self) -> Vec<Upload> {
        self.uploads_by_queue_state(true).await
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

    pub async fn upload(&self, client_id: &str, waiting_queue: bool) -> Option<Upload> {
        self.uploads_by_queue_state(waiting_queue)
            .await
            .into_iter()
            .find(|upload| upload.client_id == client_id)
    }

    pub async fn add_upload_client_friend(&self, client_id: &str) -> Result<Option<Friend>> {
        let Some(upload) = self.upload_client_for_control(client_id).await else {
            return Ok(None);
        };
        let Some(user_hash) = upload.user_hash.as_deref() else {
            anyhow::bail!("upload client does not expose a userHash");
        };
        self.add_friend(FriendCreate {
            user_hash: user_hash.to_string(),
            name: Some(upload.user_name),
        })
        .await
        .map(Some)
    }

    pub async fn remove_upload_client_friend(&self, client_id: &str) -> Result<Option<Friend>> {
        let Some(upload) = self.upload_client_for_control(client_id).await else {
            return Ok(None);
        };
        let Some(user_hash) = upload.user_hash.as_deref() else {
            return Ok(None);
        };
        self.delete_friend(user_hash).await
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
            parse_ban_ip(&upload.address),
            parse_ban_hash(upload.user_hash.as_deref()),
        );
        self.state
            .lock()
            .await
            .banned_source_clients
            .insert(upload.client_id);
        Ok(Some(true))
    }

    pub async fn unban_upload_client(&self, client_id: &str) -> Result<Option<bool>> {
        let Some(upload) = self.upload_client_for_control(client_id).await else {
            return Ok(None);
        };
        let hash = parse_ban_hash(upload.user_hash.as_deref());
        self.ed2k_transfers
            .ban_store()
            .unban(parse_ban_ip(&upload.address), hash.as_ref());
        self.state
            .lock()
            .await
            .banned_source_clients
            .remove(&upload.client_id);
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
        if self.upload(client_id, false).await.is_some() {
            if self
                .ed2k_transfers
                .release_upload_client(client_id, false)
                .await
            {
                return Ok(Some(()));
            }
            return Ok(None);
        }
        if self.upload(client_id, true).await.is_some() {
            anyhow::bail!("client does not currently hold an upload slot");
        }
        Ok(None)
    }
}
