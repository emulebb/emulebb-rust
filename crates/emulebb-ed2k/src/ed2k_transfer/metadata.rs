//! Manifest metadata reconciliation and read views for ED2K transfers.

use std::{net::Ipv4Addr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::{
    JobToken, MetadataLocalShareEntry, MetadataSharedFilePage, MetadataSharedFileQuery,
    MetadataTransferCounts, MetadataVerifiedLocalContent, NativeFileFingerprint,
};
use uuid::Uuid;

use crate::{long_path::long_path, normalize_ed2k_file_name};

use super::hashset::{decode_aich_hash_hex, validate_aich_hashset};
use super::{
    Ed2kAichHashset, Ed2kAichRootOrigin, Ed2kSharedEntry, Ed2kSourceHint, Ed2kTransferJob,
    Ed2kTransferRuntime,
};

impl Ed2kTransferRuntime {
    /// Return persisted transfer counts without hydrating every manifest.
    pub fn transfer_counts(&self) -> Result<MetadataTransferCounts> {
        self.metadata.transfer_counts()
    }

    /// Return persisted transfer counts if the metadata connection is free.
    pub fn try_transfer_counts(&self) -> Result<Option<MetadataTransferCounts>> {
        self.metadata.try_transfer_counts()
    }

    /// Return REST shared-file summaries without hydrating every manifest.
    pub async fn share_entries(&self) -> Result<Vec<MetadataLocalShareEntry>> {
        let metadata = self.metadata.clone();
        tokio::task::spawn_blocking(move || metadata.active_local_share_entries())
            .await
            .map_err(anyhow::Error::from)?
    }

    /// Return one REST shared-file summary by ED2K hash without scanning the catalog.
    pub async fn share_entry(&self, file_hash: &str) -> Result<Option<MetadataLocalShareEntry>> {
        let metadata = self.metadata.clone();
        let file_hash = file_hash.to_owned();
        tokio::task::spawn_blocking(move || metadata.active_local_share_entry(&file_hash))
            .await
            .map_err(anyhow::Error::from)?
    }

    /// Return one REST shared-file summary page without hydrating every manifest.
    pub async fn share_entries_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<MetadataLocalShareEntry>, usize)> {
        let metadata = self.metadata.clone();
        let (entries, total) = tokio::task::spawn_blocking(move || {
            let entries = metadata
                .verified_local_share_page(None, offset.saturating_add(limit))?
                .into_iter()
                .skip(offset)
                .collect::<Vec<_>>();
            Ok::<_, anyhow::Error>((entries, metadata.verified_local_share_count()?))
        })
        .await
        .map_err(anyhow::Error::from)??;
        Ok((entries, total))
    }

    /// Return one filtered, path-ordered REST shared-file page.
    pub async fn query_share_entries(
        &self,
        query: MetadataSharedFileQuery,
    ) -> Result<MetadataSharedFilePage> {
        let metadata = self.metadata.clone();
        tokio::task::spawn_blocking(move || metadata.query_active_local_share_entries(&query))
            .await
            .map_err(anyhow::Error::from)?
    }

    /// Return a keyset page ordered by ED2K hash.
    pub async fn share_entries_after(
        &self,
        after_hash: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<MetadataLocalShareEntry>, usize, bool)> {
        let metadata = self.metadata.clone();
        let after_hash = after_hash.map(str::to_owned);
        let (entries, total, has_more) = tokio::task::spawn_blocking(move || {
            let entries = metadata
                .verified_local_share_page(after_hash.as_deref(), limit.saturating_add(1))?;
            let has_more = entries.len() > limit;
            let entries = entries.into_iter().take(limit).collect::<Vec<_>>();
            Ok::<_, anyhow::Error>((entries, metadata.verified_local_share_count()?, has_more))
        })
        .await
        .map_err(anyhow::Error::from)??;
        Ok((entries, total, has_more))
    }

    /// Ensure a transfer manifest exists for the provided job.
    pub async fn ensure_job(&self, job: &Ed2kTransferJob) -> Result<super::ResidentManifest> {
        self.prepare_download_job_storage(job.token).await?;
        let _lifecycle_guard = self.lock_lifecycle(job.token.job_id).await;
        let _guard = self.lock_manifest(job.token).await;
        self.load_manifest_or_rebuild_unlocked(job).await
    }

    /// A running execution already has an admitted size. Peer claims cannot
    /// change its geometry or its chosen name.
    pub async fn validate_execution_size(
        &self,
        token: JobToken,
        file_size: Option<u64>,
    ) -> Result<()> {
        let job = self
            .download_job(token.job_id)
            .await?
            .context("missing download job")?;
        ensure!(
            job.token == token && job.removed_at_s.is_none(),
            "stale download size callback"
        );
        if let Some(size) = file_size {
            ensure!(
                size > 0 && job.expected_size_bytes == Some(size),
                "peer size claim contradicts admitted execution"
            );
        }
        Ok(())
    }

    /// Explicit operator mutation; peer filename observations never call this.
    pub async fn rename_download_job(&self, token: JobToken, name: &str) -> Result<bool> {
        ensure!(
            name.len() <= 65_536,
            "download name exceeds command allowance"
        );
        let name = normalize_ed2k_file_name(name);
        self.apply_peer_delta(
            token,
            emulebb_metadata::MetadataDownloadPeerDelta::Rename(name),
        )
        .await
    }

    /// Retain a bounded diagnostic observation without changing the chosen name.
    pub async fn remember_source_file_name(
        &self,
        token: JobToken,
        source: Option<Ed2kSourceHint>,
        raw_name: &str,
        client_software: Option<&str>,
        origin: &str,
        server_endpoint: Option<&str>,
    ) -> Result<()> {
        ensure!(
            raw_name.len() <= 65_536
                && client_software.is_none_or(|value| value.len() <= 65_536)
                && origin.len() <= 64
                && server_endpoint.is_none_or(|value| value.len() <= 256),
            "source filename observation exceeds command allowance"
        );
        ensure!(
            source.as_ref().is_none_or(|value| value.ip.len() <= 45
                && value.user_hash.as_ref().is_none_or(|hash| hash.len() == 32)
                && value.file_comment.len() <= 65_536),
            "source metadata exceeds command allowance"
        );
        let raw_name = raw_name.trim();
        let normalized_name = normalize_ed2k_file_name(raw_name);
        ensure!(
            !normalized_name.is_empty(),
            "source filename must not be empty"
        );
        let observation = emulebb_metadata::MetadataTransferFileNameObservation {
            source_ip: source.as_ref().map(|value| value.ip.clone()),
            source_tcp_port: source.as_ref().map(|value| value.tcp_port),
            user_hash: source.as_ref().and_then(|value| value.user_hash.clone()),
            client_software: client_software.unwrap_or_default().to_owned(),
            origin: if origin.is_empty() { "peer" } else { origin }.to_owned(),
            server_endpoint: server_endpoint.map(str::to_owned),
            raw_name: raw_name.to_owned(),
            normalized_name,
            observed_at_s: Utc::now().timestamp(),
        };
        self.apply_peer_delta(
            token,
            emulebb_metadata::MetadataDownloadPeerDelta::ObserveName {
                observation,
                source: source.map(source_to_metadata),
            },
        )
        .await?;
        Ok(())
    }

    /// Persist the canonical ED2K MD4 hashset after validating it against the
    /// expected file hash.
    pub async fn store_md4_hashset(
        &self,
        token: JobToken,
        md4_hashset: Vec<[u8; 16]>,
    ) -> Result<super::ResidentManifest> {
        self.activate_md4_hashes(token, md4_hashset).await?;
        self.manifest(token).await
    }

    /// Activate a peer's part hashset only against an independently trusted
    /// master. Internal tree consistency never establishes content identity.
    #[cfg(test)]
    pub(crate) async fn store_aich_hashset(
        &self,
        token: JobToken,
        aich_hashset: Ed2kAichHashset,
    ) -> Result<super::ResidentManifest> {
        let generation = self.manifest(token).await?.aich_trust_generation;
        self.store_aich_hashset_for_generation(token, aich_hashset, generation)
            .await
    }

    /// A stale response cannot reactivate a retired decision, even if a later
    /// consensus selects the same master again.
    pub(crate) async fn store_aich_hashset_for_generation(
        &self,
        token: JobToken,
        aich_hashset: Ed2kAichHashset,
        expected_generation: u64,
    ) -> Result<super::ResidentManifest> {
        let guard = self.lock_manifest(token).await;
        let mut manifest = self.load_aich_manifest_unlocked(token).await?.edit()?;
        let hash = manifest.file_hash.clone();
        let file_hash = hash.as_str();
        if manifest.aich_trust_generation != expected_generation {
            return manifest.freeze();
        }
        validate_aich_hashset(manifest.file_size, &aich_hashset)?;
        let existing_root = manifest
            .aich_root
            .as_deref()
            .context("AICH hashset requires an independently trusted master")?;
        ensure!(
            decode_aich_hash_hex(existing_root)? == aich_hashset.master_hash,
            "refusing to replace AICH root for {} with conflicting data",
            file_hash
        );
        manifest.aich_hashset = aich_hashset.part_hashes.iter().map(hex::encode).collect();
        manifest.aich_hashset_acquired = true;
        let votes = self
            .aich_root_corroboration
            .lock()
            .expect("aich corroboration mutex poisoned")
            .get(&token)
            .cloned();
        let (manifest, _guard) = self
            .persist_aich_decision(guard, manifest, expected_generation, votes)
            .await?;
        Ok(manifest)
    }

    /// Accept an explicit operator-link AICH master. Local computation and
    /// stock import have separate authority and do not enter this network
    /// observation interface. For roots learned over the
    /// wire from a single peer, use [`record_network_aich_root`] instead, which
    /// requires corroboration before promotion.
    ///
    /// [`record_network_aich_root`]: Self::record_network_aich_root
    pub async fn reconcile_aich_root(
        &self,
        token: JobToken,
        aich_root: Option<[u8; 20]>,
    ) -> Result<super::ResidentManifest> {
        let guard = self.lock_manifest(token).await;
        let mut manifest = self.load_aich_manifest_unlocked(token).await?.edit()?;
        let hash = manifest.file_hash.clone();
        let file_hash = hash.as_str();
        let expected_generation = manifest.aich_trust_generation;
        if let Some(aich_root) = aich_root {
            let encoded = hex::encode(aich_root);
            if let Some(existing_root) = manifest.aich_root.as_deref()
                && existing_root != encoded
                && manifest.aich_root_origin != Some(Ed2kAichRootOrigin::NetworkConsensus)
            {
                anyhow::bail!(
                    "refusing to replace AICH root for {} with conflicting metadata",
                    file_hash
                );
            }
            let origin = match manifest.aich_root_origin {
                Some(
                    origin @ (Ed2kAichRootOrigin::LocalComputed | Ed2kAichRootOrigin::StockImport),
                ) => origin,
                _ => Ed2kAichRootOrigin::OperatorLink,
            };
            if super::aich_trust::set_identity(&mut manifest, Some(encoded), Some(origin))? {
                let (manifest, _guard) = self
                    .persist_aich_decision(guard, manifest, expected_generation, None)
                    .await?;
                return Ok(manifest);
            }
            self.aich_root_corroboration
                .lock()
                .expect("aich corroboration mutex poisoned")
                .remove(&token);
        }
        manifest.freeze()
    }

    /// Record a NETWORK-LEARNED AICH root proposed by one peer at `from_ip`.
    ///
    /// A single peer's word is not authoritative: trusting it blindly would let
    /// a hostile peer authorize ICH part salvage against attacker-chosen
    /// recovery data. Mirroring `CAICHRecoveryHashSet::AddHash`/`SetStatus`
    /// (`SHAHashSet.cpp:998-1018`), the proposed root is only promoted to the
    /// salvage-authorizing `manifest.aich_root` once `>= MINUNIQUEIPS_TOTRUST`
    /// (10) distinct IPs have proposed it AND it accounts for
    /// `>= MINPERCENTAGE_TOTRUST` (92%) of all proposing IPs. Until then the
    /// manifest's root is left unset, so salvage falls back to whole-part
    /// re-download.
    ///
    /// A live consensus keeps collecting votes and may lose trust. Explicit
    /// authority is stable. Stock resumes a persisted accepted root as VERIFIED
    /// (PartFile.cpp FT_AICH_HASH); retain its origin without recreating votes.
    pub async fn record_network_aich_root(
        &self,
        token: JobToken,
        aich_root: Option<[u8; 20]>,
        from_ip: std::net::IpAddr,
    ) -> Result<super::ResidentManifest> {
        let observations = aich_root
            .map(|root| vec![(root, from_ip)])
            .unwrap_or_default();
        self.record_network_aich_observations(token, &observations)
            .await
    }

    /// Record a bounded batch of live, provenance-bearing AICH observations.
    /// The manifest is locked and loaded once, and any resulting promotion is
    /// persisted once. Reported Kad popularity never enters this interface;
    /// every tuple represents one actual network responder.
    pub async fn record_network_aich_observations(
        &self,
        token: JobToken,
        observations: &[([u8; 20], std::net::IpAddr)],
    ) -> Result<super::ResidentManifest> {
        let guard = self.lock_manifest(token).await;
        let mut manifest = self.load_aich_manifest_unlocked(token).await?.edit()?;
        if observations.is_empty() {
            return manifest.freeze();
        }

        if manifest.aich_root.is_some()
            && manifest.aich_root_origin != Some(Ed2kAichRootOrigin::NetworkConsensus)
        {
            return manifest.freeze();
        }

        let mut accumulator = {
            let map = self
                .aich_root_corroboration
                .lock()
                .expect("aich corroboration mutex poisoned");
            // An accepted persisted consensus resumes VERIFIED exactly as
            // stock. Only this runtime's live accumulator is reconsiderable.
            if manifest.aich_root.is_some() && !map.contains_key(&token) {
                return manifest.freeze();
            }
            map.get(&token).cloned().unwrap_or_default()
        };

        for (aich_root, from_ip) in observations {
            let std::net::IpAddr::V4(from_ip) = from_ip else {
                continue;
            };
            accumulator.record(*aich_root, from_ip.octets());
        }
        let promoted = accumulator.trusted_root();

        let origin = promoted.map(|_| Ed2kAichRootOrigin::NetworkConsensus);
        let expected_generation = manifest.aich_trust_generation;
        if super::aich_trust::set_identity(&mut manifest, promoted.map(hex::encode), origin)? {
            let (manifest, _guard) = self
                .persist_aich_decision(guard, manifest, expected_generation, Some(accumulator))
                .await?;
            return Ok(manifest);
        }
        self.aich_root_corroboration
            .lock()
            .expect("aich corroboration mutex poisoned")
            .insert(token, accumulator);
        manifest.freeze()
    }

    /// Retain one endpoint hint without hydrating execution geometry.
    pub async fn remember_source(&self, token: JobToken, source: Ed2kSourceHint) -> Result<()> {
        self.apply_peer_delta(
            token,
            emulebb_metadata::MetadataDownloadPeerDelta::Source {
                source: source_to_metadata(source),
                description_only: false,
            },
        )
        .await?;
        Ok(())
    }

    pub async fn remember_source_file_description(
        &self,
        token: JobToken,
        source: Ed2kSourceHint,
    ) -> Result<()> {
        if source.file_comment.is_empty() && source.file_rating == 0 {
            return Ok(());
        }
        self.apply_peer_delta(
            token,
            emulebb_metadata::MetadataDownloadPeerDelta::Source {
                source: source_to_metadata(source),
                description_only: true,
            },
        )
        .await?;
        Ok(())
    }

    pub async fn remove_source(&self, token: JobToken, client_id: &str) -> Result<bool> {
        let (endpoint, user_hash) = if let Ok(hash) = client_id.parse::<Ed2kHash>() {
            (None, Some(hash.0))
        } else {
            let address = client_id.parse::<std::net::SocketAddrV4>()?;
            (Some((*address.ip(), address.port())), None)
        };
        self.apply_peer_delta(
            token,
            emulebb_metadata::MetadataDownloadPeerDelta::RemoveSource {
                endpoint,
                user_hash,
            },
        )
        .await
    }

    pub async fn remove_source_identity(
        &self,
        token: JobToken,
        source_ip: Ipv4Addr,
        source_tcp_port: u16,
        source_user_hash: Option<[u8; 16]>,
    ) -> Result<bool> {
        self.apply_peer_delta(
            token,
            emulebb_metadata::MetadataDownloadPeerDelta::RemoveSource {
                endpoint: Some((source_ip, source_tcp_port)),
                user_hash: source_user_hash,
            },
        )
        .await
    }

    /// Persist shared-file metadata exposed through the eMuleBB REST contract.
    pub async fn update_shared_file_metadata(
        &self,
        file_hash: &str,
        priority: Option<(&str, bool)>,
        comment_rating: Option<(&str, u8)>,
    ) -> Result<super::Ed2kFileServingView> {
        self.persist_content_metadata(file_hash.parse()?, priority, comment_rating)
            .await?;
        self.serving_view(file_hash).await
    }

    /// Persist the user-facing transfer control state across process restarts.
    /// Resolve the current assignment at the start of a delivery decision.
    pub async fn current_category_id(&self, token: JobToken) -> Result<Option<i64>> {
        let _fence = self.category_assignment_gate.read().await;
        self.current_category_id_fenced(token).await
    }

    /// Hold through authoritative category read and subsequent cache publication.
    pub async fn lock_category_publication(&self) -> tokio::sync::OwnedRwLockReadGuard<()> {
        Arc::clone(&self.category_assignment_gate)
            .read_owned()
            .await
    }

    /// Caller holds the category publication fence.
    pub async fn current_category_id_fenced(&self, token: JobToken) -> Result<Option<i64>> {
        if let Some(category) = self
            .manifest_cache
            .lock()
            .await
            .get(&token.job_id)
            .filter(|m| m.token == token)
            .map(|m| m.category_id)
        {
            return Ok(category);
        }
        let job = self
            .download_job(token.job_id)
            .await?
            .context("download job not found")?;
        ensure!(
            job.token == token,
            "category lookup belongs to a stale execution"
        );
        Ok(job.category_id)
    }

    /// Cache a delivered download as verified local content without rereading
    /// its payload. Root membership must be admitted separately by the caller.
    pub async fn register_delivered_local_content(
        &self,
        token: JobToken,
    ) -> Result<(PathBuf, NativeFileFingerprint)> {
        let _lifecycle_guard = self.lock_lifecycle(token.job_id).await;
        let _guard = self.lock_manifest(token).await;
        let manifest = self.load_manifest_unlocked(token).await?;
        ensure!(
            manifest.completed
                && !manifest.final_rehash_pending
                && manifest.delivery_state == super::Ed2kDeliveryState::Delivered,
            "download is not fully delivered"
        );
        let path = manifest
            .delivered_path
            .clone()
            .context("delivered download has no output path")?;
        let path = long_path(&path);
        let fingerprint = manifest
            .source_fingerprint
            .clone()
            .context("delivered download has no output fingerprint")?;
        let file = super::ingest::open_regular_file_without_follow(&path)?;
        let opened = file.metadata()?;
        let current = super::ingest::native_file_fingerprint_from_handle(&file, &opened)
            .context("delivered output has no stable native fingerprint")?;
        let evidence =
            super::ingest::native_file_identity_evidence_from_handle(&file, &opened, &current)?;
        ensure!(
            fingerprint.safely_matches(&current),
            "delivered output changed since its verified fingerprint was recorded"
        );
        ensure!(
            manifest.md4_hashset_acquired && manifest.aich_hashset_acquired,
            "delivered download has incomplete hashsets"
        );
        let content = MetadataVerifiedLocalContent {
            secondary_identity: evidence.secondary(),
            file_hash: manifest.file_hash.clone(),
            display_name: manifest.display_name.clone(),
            file_size: manifest.file_size,
            part_size: manifest.piece_size,
            md4_hashset: manifest.md4_hashset.clone(),
            aich_root: Some(
                manifest
                    .aich_root
                    .clone()
                    .context("delivered download has no AICH root")?,
            ),
            aich_hashset: manifest.aich_hashset.clone(),
            path: path.clone(),
            fingerprint: fingerprint.clone(),
            upload_priority: manifest.upload_priority.clone(),
            auto_upload_priority: manifest.auto_upload_priority,
            comment: manifest.comment.clone(),
            rating: manifest.rating,
        };
        let metadata = self.metadata.clone();
        tokio::task::spawn_blocking(move || metadata.upsert_verified_local_content(&content))
            .await??;
        Ok((path, fingerprint))
    }

    /// Return local serving metadata even when only part of the
    /// payload has been verified already.
    pub async fn local_entry(&self, file_hash: &Ed2kHash) -> Result<Option<Ed2kSharedEntry>> {
        let hash_hex = file_hash.to_string();
        let token = self.resolve_protocol_job(&hash_hex).await?;
        let _guard = if let Some(token) = token {
            Some(self.lock_manifest(token).await)
        } else {
            None
        };
        Ok(self
            .load_serving_view_optional_unlocked(&hash_hex, token)
            .await?
            .map(|view| Ed2kSharedEntry::from_serving_view(&view)))
    }

    /// Like [`Self::local_entry`] but only returns an entry that may be served
    /// to an inbound peer right now: a fully verified file, or an in-progress
    /// partfile holding at least one complete part ("share while downloading").
    /// Mirrors the master file-request fallback that admits a `downloadqueue`
    /// partfile only with at least one complete part (ListenSocket.cpp).
    pub async fn local_servable_entry(
        &self,
        file_hash: &Ed2kHash,
    ) -> Result<Option<Ed2kSharedEntry>> {
        Ok(self
            .local_entry(file_hash)
            .await?
            .filter(Ed2kSharedEntry::is_servable))
    }

    /// Whether we share or are downloading the file with this hash.
    ///
    /// A serving view resolves shared files and in-progress downloads, mirroring
    /// the oracle ListenSocket.cpp OP_CALLBACK guard
    /// (`sharedfiles->GetFileByID(...) != NULL || downloadqueue->GetFileByID(...)
    /// != NULL`). Used to reject buddy-relayed callbacks for files we do not own.
    pub async fn owns_file(&self, file_hash: &Ed2kHash) -> bool {
        self.local_entry(file_hash)
            .await
            .map(|entry| entry.is_some())
            .unwrap_or(false)
    }

    /// Return the canonical MD4 hashset for this file when known.
    pub async fn md4_hashset(&self, file_hash: &Ed2kHash) -> Result<Option<Vec<[u8; 16]>>> {
        let hash_hex = file_hash.to_string();
        let token = self.resolve_protocol_job(&hash_hex).await?;
        let _guard = if let Some(token) = token {
            Some(self.lock_manifest(token).await)
        } else {
            None
        };
        let Some(manifest) = self
            .load_serving_view_optional_unlocked(&hash_hex, token)
            .await?
        else {
            return Ok(None);
        };
        if !manifest.md4_hashset_acquired {
            return Ok(None);
        }
        manifest
            .md4_hashset
            .iter()
            .map(|hash| {
                let bytes = hex::decode(hash).with_context(|| {
                    format!("invalid stored MD4 hashset entry for {}", file_hash)
                })?;
                let array: [u8; 16] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("stored MD4 hashset entry has wrong length"))?;
                Ok(array)
            })
            .collect::<Result<Vec<_>>>()
            .map(Some)
    }

    /// Return the canonical AICH root plus per-part hashes for this file when known.
    pub(crate) async fn aich_hashset(
        &self,
        file_hash: &Ed2kHash,
    ) -> Result<Option<Ed2kAichHashset>> {
        let hash_hex = file_hash.to_string();
        let token = self.resolve_protocol_job(&hash_hex).await?;
        let _guard = if let Some(token) = token {
            Some(self.lock_manifest(token).await)
        } else {
            None
        };
        let Some(manifest) = self
            .load_serving_view_optional_unlocked(&hash_hex, token)
            .await?
        else {
            return Ok(None);
        };
        if !manifest.aich_hashset_acquired {
            return Ok(None);
        }
        let Some(root) = manifest.aich_root.as_deref() else {
            return Ok(None);
        };
        let hashset = Ed2kAichHashset {
            master_hash: decode_aich_hash_hex(root)?,
            part_hashes: manifest
                .aich_hashset
                .iter()
                .map(|hash| decode_aich_hash_hex(hash))
                .collect::<Result<Vec<_>>>()?,
        };
        validate_aich_hashset(manifest.file_size, &hashset)?;
        Ok(Some(hashset))
    }

    /// Build the OP_AICHANSWER recovery-data body for `part` of a locally
    /// shared, fully verified file, mirroring `CUpDownClient::ProcessAICHRequest`
    /// -> `CAICHRecoveryHashSet::CreatePartRecoveryData`.
    ///
    /// Returns `None` when we cannot serve (file unknown, not fully verified, no
    /// trusted AICH root, requested master hash mismatch, or part too small),
    /// matching the master's always-failure fallback. The returned bytes are the
    /// recovery body that follows the answer header (file hash + part + master).
    pub(crate) async fn create_aich_recovery_data(
        &self,
        file_hash: &Ed2kHash,
        part: u16,
        requested_master_hash: [u8; 20],
    ) -> Result<Option<Vec<u8>>> {
        use super::{ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE};

        let hash_hex = file_hash.to_string();
        let (file_size, aich_root) = {
            let _guard = self.lock_content(&hash_hex).await;
            let Some(manifest) = self
                .load_serving_view_optional_unlocked(&hash_hex, None)
                .await?
            else {
                return Ok(None);
            };
            // Only serve from a fully verified (shared) file.
            if !manifest.completed {
                return Ok(None);
            }
            let Some(root) = manifest.aich_root.as_deref() else {
                return Ok(None);
            };
            let master = decode_aich_hash_hex(root)?;
            (manifest.file_size, master)
        };

        // master ProcessAICHRequest guard: file size > PARTSIZE * nPart + EMBLOCKSIZE
        if aich_root != requested_master_hash {
            return Ok(None);
        }
        if file_size <= ED2K_PART_SIZE * u64::from(part) + ED2K_EMBLOCK_SIZE {
            return Ok(None);
        }

        let Some(permit) = super::aich_answer_cache::try_work() else {
            return Ok(None);
        };
        // WHY: native fingerprint checks still gate sharing, but a network
        // request must never cause payload hashing merely to rebuild metadata.
        let Some(_reader) = self.open_verified_range_reader(file_hash).await? else {
            return Ok(None);
        };
        let metadata = self.metadata.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            super::aich_answer_cache::answer(&metadata, aich_root, file_size, part)
        })
        .await;
        match result {
            Ok(Ok(answer)) => Ok(answer),
            other => {
                tracing::warn!(?other, "AICH recovery cache unavailable");
                Ok(None)
            }
        }
    }

    /// Exact job detail; protocol hashes are resolved only at explicit wire admission.
    pub async fn manifest(&self, token: JobToken) -> Result<super::ResidentManifest> {
        let _guard = self.lock_manifest(token).await;
        self.load_aich_manifest_unlocked(token).await
    }

    pub async fn manifest_optional(
        &self,
        token: JobToken,
    ) -> Result<Option<super::ResidentManifest>> {
        let _guard = self.lock_manifest(token).await;
        if self.load_manifest_optional_unlocked(token).await?.is_none() {
            return Ok(None);
        }
        self.load_aich_manifest_unlocked(token).await.map(Some)
    }

    /// A content-only incoming protocol request resolves the sole current job
    /// once; every subsequent callback retains the returned generation.
    pub(crate) async fn resolve_protocol_job(&self, file_hash: &str) -> Result<Option<JobToken>> {
        let super::local_mutation::job_read::JobReadResult::Exact(job) = self
            .read_job_metadata(super::local_mutation::job_read::JobRead::Latest(
                file_hash.parse::<Ed2kHash>()?.0,
            ))
            .await?
        else {
            unreachable!()
        };
        Ok(job
            .filter(|job| job.removed_at_s.is_none() && job.completed_at_s.is_none())
            .map(|job| job.token))
    }

    pub async fn serving_view(&self, file_hash: &str) -> Result<super::Ed2kFileServingView> {
        let token = self.resolve_protocol_job(file_hash).await?;
        let _job_guard = if let Some(token) = token {
            Some(self.lock_manifest(token).await)
        } else {
            None
        };
        let _content_guard = self.lock_content(file_hash).await;
        self.load_serving_view_optional_unlocked(file_hash, token)
            .await?
            .with_context(|| format!("missing ED2K transfer or shared file {file_hash}"))
    }
}

fn source_to_metadata(source: Ed2kSourceHint) -> emulebb_metadata::MetadataTransferSource {
    emulebb_metadata::MetadataTransferSource {
        ip: source.ip,
        tcp_port: source.tcp_port,
        user_hash: source.user_hash,
        connect_options: source.connect_options,
        file_comment: source.file_comment,
        file_rating: source.file_rating,
    }
}

pub(super) fn transfer_directory_authority_marker_path(
    transfer_dir: &std::path::Path,
    marker_id: Uuid,
) -> std::path::PathBuf {
    transfer_dir.join(format!(
        ".emulebb-delete-authority-{}.tmp",
        marker_id.hyphenated()
    ))
}
