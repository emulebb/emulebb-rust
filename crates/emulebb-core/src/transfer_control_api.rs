use super::*;

impl EmulebbCore {
    pub async fn transfer(&self, hash: &str) -> Option<Transfer> {
        let cached = self.state.lock().await.transfers.get(hash).cloned();
        let mut transfer = match cached {
            Some(transfer) => transfer,
            None => match self.refresh_transfer_from_manifest_default(hash).await {
                Ok(Some(transfer)) => transfer,
                Ok(None) => return None,
                Err(error) => {
                    tracing::warn!("failed to refresh ED2K transfer {hash} from manifest: {error}");
                    return None;
                }
            },
        };
        self.apply_live_transfer_fields(&mut transfer);
        Some(transfer)
    }

    pub async fn update_transfer(
        &self,
        hash: &str,
        request: TransferUpdate,
    ) -> Result<Option<Transfer>> {
        validate_transfer_update_family(&request)?;
        if self.transfer(hash).await.is_none() {
            return Ok(None);
        }
        if let Some(priority) = request.priority.as_deref() {
            let priority = validate_transfer_priority(priority)?.to_string();
            let mut state = self.state.lock().await;
            let Some(transfer) = state.transfers.get_mut(hash) else {
                return Ok(None);
            };
            transfer.priority = priority;
            let transfer = transfer.clone();
            drop(state);
            self.publish_transfer_updated(transfer.clone());
            return Ok(Some(transfer));
        }
        if request.category_id.is_some() || request.category_name.is_some() {
            let (category_id, category_name) = self
                .resolve_transfer_category(request.category_id, request.category_name.as_deref())
                .await?;
            self.ed2k_transfers
                .set_category_id(hash, category_id)
                .await?;
            let mut state = self.state.lock().await;
            let Some(transfer) = state.transfers.get_mut(hash) else {
                return Ok(None);
            };
            transfer.category_id = category_id;
            transfer.category_name = category_name;
            let transfer = transfer.clone();
            drop(state);
            self.publish_transfer_updated(transfer.clone());
            return Ok(Some(transfer));
        }
        let name = normalize_transfer_name(request.name)?;
        let current = self.state.lock().await.transfers.get(hash).cloned();
        if current
            .as_ref()
            .is_some_and(|transfer| matches!(transfer.state.as_str(), "completed" | "completing"))
        {
            anyhow::bail!("completed transfers cannot be renamed through this endpoint");
        }
        let manifest = self
            .ed2k_transfers
            .reconcile_job_metadata(hash, Some(&name), None)
            .await?;
        let state_name = current
            .as_ref()
            .map(|transfer| transfer.state.as_str())
            .unwrap_or_else(|| manifest_default_state_name(&manifest));
        let mut transfer = self.transfer_from_manifest(&manifest, state_name);
        if let Some(existing) = current.as_ref() {
            preserve_transfer_public_metadata(&mut transfer, existing);
        }
        transfer.name = name;
        transfer.ed2k_link = format!(
            "ed2k://|file|{}|{}|{}|/",
            transfer.name, transfer.size_bytes, transfer.hash
        );
        self.state
            .lock()
            .await
            .transfers
            .insert(transfer.hash.clone(), transfer.clone());
        self.publish_transfer_updated(transfer.clone());
        Ok(Some(transfer))
    }

    pub async fn transfer_sources(&self, hash: &str) -> Result<Option<Vec<TransferSource>>> {
        if self.transfer(hash).await.is_none() {
            return Ok(None);
        }
        let manifest = self.ed2k_transfers.manifest(hash).await?;
        let banned = self.state.lock().await.banned_source_clients.clone();
        let mut sources = transfer_sources_from_manifest(&manifest, &banned);
        enrich_sources_with_live(
            &mut sources,
            &self.ed2k_transfers.live_download_sources(hash),
            manifest.pieces.len() as u32,
        );
        Ok(Some(sources))
    }

    /// Transfer details: the transfer plus its per-part breakdown and source
    /// list, mirroring the master `BuildTransferDetailsJson` shape.
    pub async fn transfer_details(&self, hash: &str) -> Result<Option<TransferDetails>> {
        let Some(transfer) = self.transfer(hash).await else {
            return Ok(None);
        };
        let manifest = self.ed2k_transfers.manifest(hash).await?;
        let banned = self.state.lock().await.banned_source_clients.clone();
        let part_total = manifest.pieces.len() as u32;
        let mut sources = transfer_sources_from_manifest(&manifest, &banned);
        enrich_sources_with_live(
            &mut sources,
            &self.ed2k_transfers.live_download_sources(hash),
            part_total,
        );
        let available_sources_per_part = self
            .ed2k_transfers
            .available_sources_per_part(hash, part_total);
        let parts = transfer_parts_from_manifest(&manifest, &available_sources_per_part);
        Ok(Some(TransferDetails {
            transfer,
            parts,
            sources,
        }))
    }

    pub async fn transfer_source(
        &self,
        hash: &str,
        client_id: &str,
    ) -> Result<Option<TransferSource>> {
        validate_source_client_id(client_id)?;
        Ok(self
            .transfer_sources(hash)
            .await?
            .and_then(|sources| source_by_client_id(sources, client_id)))
    }

    pub async fn browse_transfer_source(&self, hash: &str, client_id: &str) -> Result<bool> {
        let Some(source) = self.transfer_source(hash, client_id).await? else {
            return Ok(false);
        };
        ensure!(
            source.view_shared_files,
            "transfer source does not support shared-file browsing"
        );
        Ok(true)
    }

    pub async fn add_transfer_source_friend(
        &self,
        hash: &str,
        client_id: &str,
    ) -> Result<Option<Friend>> {
        let Some(source) = self.transfer_source(hash, client_id).await? else {
            return Ok(None);
        };
        let Some(user_hash) = source.user_hash.as_deref() else {
            anyhow::bail!("transfer source does not expose a userHash");
        };
        self.add_friend(FriendCreate {
            user_hash: user_hash.to_string(),
            name: Some(source_friend_name(&source)),
        })
        .await
        .map(Some)
    }

    pub async fn remove_transfer_source_friend(
        &self,
        hash: &str,
        client_id: &str,
    ) -> Result<Option<Friend>> {
        let Some(source) = self.transfer_source(hash, client_id).await? else {
            return Ok(None);
        };
        let Some(user_hash) = source.user_hash.as_deref() else {
            return Ok(None);
        };
        self.delete_friend(user_hash).await
    }

    pub async fn ban_transfer_source(&self, hash: &str, client_id: &str) -> Result<Option<bool>> {
        let Some(source) = self.transfer_source(hash, client_id).await? else {
            return Ok(None);
        };
        // Back the manual source ban with the enforced ban store (IP + user
        // hash, 4h TTL) so the source is rejected on the next connect / source
        // add (eMule CUpDownClient::Ban).
        self.ed2k_transfers.ban_client(
            parse_ban_ip(&source.ip),
            parse_ban_hash(source.user_hash.as_deref()),
        );
        self.state
            .lock()
            .await
            .banned_source_clients
            .insert(source.client_id);
        Ok(Some(true))
    }

    pub async fn unban_transfer_source(&self, hash: &str, client_id: &str) -> Result<Option<bool>> {
        let Some(source) = self.transfer_source(hash, client_id).await? else {
            return Ok(None);
        };
        let user_hash = parse_ban_hash(source.user_hash.as_deref());
        self.ed2k_transfers
            .ban_store()
            .unban(parse_ban_ip(&source.ip), user_hash.as_ref());
        self.state
            .lock()
            .await
            .banned_source_clients
            .remove(&source.client_id);
        Ok(Some(false))
    }

    pub async fn remove_transfer_source(&self, hash: &str, client_id: &str) -> Result<Option<()>> {
        validate_source_client_id(client_id)?;
        if self.transfer(hash).await.is_none() {
            return Ok(None);
        }
        if !self.ed2k_transfers.remove_source(hash, client_id).await? {
            return Ok(None);
        }
        self.state
            .lock()
            .await
            .banned_source_clients
            .remove(client_id);
        Ok(Some(()))
    }

    pub async fn pause_transfer(&self, hash: &str) -> Result<Option<Transfer>> {
        self.set_transfer_control_state(hash, "paused").await
    }

    pub async fn stop_transfer(&self, hash: &str) -> Result<Option<Transfer>> {
        self.set_transfer_control_state(hash, "stopped").await
    }

    pub async fn recheck_transfer(&self, hash: &str) -> Result<Option<()>> {
        let Some(current) = self.transfer(hash).await else {
            return Ok(None);
        };
        ensure!(
            !matches!(current.state.as_str(), "hashing" | "completing"),
            "transfer is already being hashed or completed"
        );
        // Cancel any in-flight download attempt before re-verifying so the recheck
        // does not race a live piece write for the same hash (state flap; the
        // manifest IO is serialized so there is no corruption, but the recheck
        // must observe a settled on-disk state). The attempt stops at its next
        // cancel check; if recheck finds the transfer still wants data it re-queues
        // a fresh attempt below.
        self.cancel_download_attempt(hash).await;
        // Mark hashing while the on-disk parts are re-verified (oracle forces a
        // full part re-hash on recheck; CPartFile::HashSinglePart per part).
        self.set_transfer_state(hash, "hashing").await;
        // Drive the real re-verification: re-read every part from disk and
        // MD4-check it against the hashset, rewriting piece states + verified
        // ranges + the completed flag (and demoting any corrupted part to Missing
        // so it is re-downloaded). The piece store owns the manifest lock + IO.
        let recheck = self.ed2k_transfers.recheck_transfer(hash).await;
        // Re-derive the public transfer state from the freshly-rewritten manifest
        // (completed -> "completed"; otherwise downloading/queued), regardless of
        // success, so the transfer never gets stuck in "hashing".
        let refreshed = self.refresh_transfer_from_manifest_default(hash).await;
        recheck?;
        match refreshed? {
            Some(transfer) => {
                self.publish_transfer_updated(transfer.clone());
                // If the recheck found corruption (now not complete but with
                // progress), re-engage the download so the demoted parts refetch.
                if transfer.state == "downloading" {
                    self.queue_ed2k_download_attempt(transfer);
                } else if transfer.state == "completed" {
                    // A recheck that confirms a complete file delivers it by name
                    // (covers a manually-rechecked transfer that was never driven
                    // through the download-completion path).
                    self.deliver_completed_transfer(hash).await;
                }
                Ok(Some(()))
            }
            None => Ok(None),
        }
    }

    pub async fn delete_transfer_files(&self, hash: &str) -> Result<Option<Transfer>> {
        let transfer = if let Some(transfer) = self.transfer(hash).await {
            transfer
        } else {
            let Ok(manifest) = self.ed2k_transfers.manifest(hash).await else {
                return Ok(None);
            };
            let state_name = manifest_default_state_name(&manifest);
            self.transfer_from_manifest(&manifest, state_name)
        };
        self.delete_delivered_transfer_file(hash, &transfer).await?;
        if !self.ed2k_transfers.delete_transfer_files(hash).await? {
            return Ok(None);
        }
        self.metadata_store.unmark_unshared_file(hash)?;
        // Cancel any in-flight attempt and free everything it holds for this hash
        // (candidates, leases, active endpoints, the dedup + cancel slots) so the
        // orphan attempt stops churning peers and the hash can be re-created and
        // re-download immediately instead of early-returning on a stale dedup slot.
        self.teardown_download_for_delete(hash).await;
        let mut state = self.state.lock().await;
        state.transfers.remove(hash);
        state.unshared_hashes.remove(hash);
        drop(state);
        self.publish_transfer_removed(hash);
        Ok(Some(transfer))
    }

    async fn delete_delivered_transfer_file(&self, hash: &str, transfer: &Transfer) -> Result<()> {
        let delivered_path = match self.ed2k_transfers.manifest(hash).await {
            Ok(manifest) => {
                if manifest.source_path.is_some() {
                    None
                } else {
                    manifest.delivered_path
                }
            }
            Err(_) => transfer.delivered_path.clone(),
        };
        let Some(path) = delivered_path.as_deref() else {
            return Ok(());
        };
        let path = Path::new(path);
        let long = long_path(path);
        match tokio::fs::remove_file(&long).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to delete delivered transfer file {}",
                    path.display()
                )
            }),
        }
    }

    pub async fn delete_completed_transfer_row(&self, hash: &str) -> Result<Option<Transfer>> {
        let Some(transfer) = self.transfer(hash).await else {
            return Ok(None);
        };
        self.ed2k_transfers
            .remove_completed_transfer_row(hash)
            .await?;
        self.state.lock().await.transfers.remove(hash);
        self.publish_transfer_removed(hash);
        Ok(Some(transfer))
    }

    pub async fn clear_completed_transfer_rows(&self) -> Result<()> {
        let hashes = {
            let state = self.state.lock().await;
            state
                .transfers
                .values()
                .filter(|transfer| transfer.state == "completed")
                .map(|transfer| transfer.hash.clone())
                .collect::<Vec<_>>()
        };
        for hash in hashes {
            self.ed2k_transfers
                .remove_completed_transfer_row(&hash)
                .await?;
            self.state.lock().await.transfers.remove(&hash);
            self.publish_transfer_removed(hash);
        }
        Ok(())
    }
}
