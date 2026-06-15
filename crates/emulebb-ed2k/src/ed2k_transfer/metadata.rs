//! Manifest metadata reconciliation and read views for ED2K transfers.

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use super::hashset::{
    decode_aich_hash_hex, decode_manifest_aich_hashset, expected_md4_hash_count,
    validate_aich_hashset, validate_md4_hashset,
};
use super::manifest::{manifest_has_structural_progress, piece_count};
use super::transfer_sql::manifest_from_metadata;
use super::upload_queue::upload_priority_score;
use super::{
    Ed2kAichHashset, Ed2kPieceState, Ed2kResumeManifest, Ed2kSharedEntry, Ed2kSourceHint,
    Ed2kTransferJob, Ed2kTransferRuntime, Ed2kTransferState,
};

impl Ed2kTransferRuntime {
    /// Ensure a transfer manifest exists for the provided job.
    pub async fn ensure_job(&self, job: &Ed2kTransferJob) -> Result<Ed2kResumeManifest> {
        let _guard = self.manifest_io.lock().await;
        let transfer_dir = self.transfer_dir(&job.file_hash);
        tokio::fs::create_dir_all(&transfer_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to create ED2K transfer directory {}",
                    transfer_dir.display()
                )
            })?;
        self.load_manifest_or_rebuild_unlocked(job).await
    }

    /// Reconcile canonical metadata for an existing transfer after a peer
    /// reveals a better file name or previously unknown file size.
    pub async fn reconcile_job_metadata(
        &self,
        file_hash: &str,
        canonical_name: Option<&str>,
        file_size: Option<u64>,
    ) -> Result<Ed2kResumeManifest> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let mut changed = false;

        if let Some(canonical_name) = canonical_name.map(str::trim)
            && !canonical_name.is_empty()
            && manifest.canonical_name != canonical_name
        {
            manifest.canonical_name = canonical_name.to_string();
            changed = true;
        }

        if let Some(file_size) = file_size.filter(|file_size| *file_size != 0) {
            if manifest.file_size == 0 {
                if manifest_has_structural_progress(&manifest) {
                    anyhow::bail!(
                        "cannot adopt ED2K file size {} for {} after transfer progress already exists",
                        file_size,
                        file_hash
                    );
                }
                manifest.file_size = file_size;
                manifest.pieces = (0..piece_count(file_size, manifest.piece_size))
                    .map(|piece_index| Ed2kPieceState {
                        piece_index,
                        state: Ed2kTransferState::Missing,
                        bytes_written: 0,
                        block_bitmap: None,
                    })
                    .collect();
                changed = true;
            } else if manifest.file_size != file_size {
                anyhow::bail!(
                    "refusing to change ED2K file size for {} from {} to {}",
                    file_hash,
                    manifest.file_size,
                    file_size
                );
            }
        }

        if changed {
            self.store_manifest_unlocked(&manifest).await?;
            self.upsert_verified_catalog_entry(&manifest).await;
        }

        Ok(manifest)
    }

    /// Persist the canonical ED2K MD4 hashset after validating it against the
    /// expected file hash.
    pub async fn store_md4_hashset(
        &self,
        file_hash: &str,
        md4_hashset: Vec<[u8; 16]>,
    ) -> Result<Ed2kResumeManifest> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let expected_hash_count = expected_md4_hash_count(manifest.file_size);
        if md4_hashset.len() != usize::from(expected_hash_count) {
            anyhow::bail!(
                "unexpected MD4 hashset length {} expected {} for {}",
                md4_hashset.len(),
                expected_hash_count,
                file_hash
            );
        }
        validate_md4_hashset(file_hash, &md4_hashset)?;
        manifest.md4_hashset = md4_hashset.iter().map(hex::encode).collect();
        manifest.md4_hashset_acquired = true;
        self.store_manifest_unlocked(&manifest).await?;
        Ok(manifest)
    }

    /// Persist the canonical ED2K AICH root and part hashset after validating
    /// the payload against the expected file size.
    pub(crate) async fn store_aich_hashset(
        &self,
        file_hash: &str,
        aich_hashset: Ed2kAichHashset,
    ) -> Result<Ed2kResumeManifest> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        if let Some(existing_root) = manifest.aich_root.as_deref() {
            let existing_root = decode_aich_hash_hex(existing_root)?;
            if existing_root != aich_hashset.master_hash {
                anyhow::bail!(
                    "refusing to replace AICH root for {} with conflicting data",
                    file_hash
                );
            }
        }
        validate_aich_hashset(manifest.file_size, &aich_hashset)?;
        manifest.aich_root = Some(hex::encode(aich_hashset.master_hash));
        manifest.aich_hashset = aich_hashset.part_hashes.iter().map(hex::encode).collect();
        manifest.aich_hashset_acquired = true;
        self.store_manifest_unlocked(&manifest).await?;
        self.upsert_verified_catalog_entry(&manifest).await;
        Ok(manifest)
    }

    /// Persist only the canonical AICH root learned from peer file metadata.
    pub async fn reconcile_aich_root(
        &self,
        file_hash: &str,
        aich_root: Option<[u8; 20]>,
    ) -> Result<Ed2kResumeManifest> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let mut changed = false;
        if let Some(aich_root) = aich_root {
            let encoded = hex::encode(aich_root);
            if let Some(existing_root) = manifest.aich_root.as_deref() {
                if existing_root != encoded {
                    anyhow::bail!(
                        "refusing to replace AICH root for {} with conflicting metadata",
                        file_hash
                    );
                }
            } else {
                manifest.aich_root = Some(encoded);
                changed = true;
            }
        }
        if changed {
            self.store_manifest_unlocked(&manifest).await?;
            self.upsert_verified_catalog_entry(&manifest).await;
        }
        Ok(manifest)
    }

    /// Record one remembered source hint for a job.
    pub async fn remember_source(&self, file_hash: &str, source: Ed2kSourceHint) -> Result<()> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        if !manifest.sources.contains(&source) {
            manifest.sources.push(source);
            self.store_manifest_unlocked(&manifest).await?;
        }
        Ok(())
    }

    /// Remove one remembered source hint by public source selector.
    pub async fn remove_source(&self, file_hash: &str, client_id: &str) -> Result<bool> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let before = manifest.sources.len();
        manifest.sources.retain(|source| {
            source.user_hash.as_deref() != Some(client_id)
                && format!("{}:{}", source.ip, source.tcp_port) != client_id
        });
        if manifest.sources.len() == before {
            return Ok(false);
        }
        self.store_manifest_unlocked(&manifest).await?;
        Ok(true)
    }

    /// Persist shared-file metadata exposed through the eMuleBB REST contract.
    pub async fn update_shared_file_metadata(
        &self,
        file_hash: &str,
        priority: Option<(&str, bool)>,
        comment_rating: Option<(&str, u8)>,
    ) -> Result<Ed2kResumeManifest> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        if let Some((priority, auto_upload_priority)) = priority {
            manifest.upload_priority = priority.to_string();
            manifest.auto_upload_priority = auto_upload_priority;
        }
        if let Some((comment, rating)) = comment_rating {
            manifest.comment = comment.to_string();
            manifest.rating = rating;
        }
        self.store_manifest_unlocked(&manifest).await?;
        self.upsert_verified_catalog_entry(&manifest).await;
        if priority.is_some() {
            self.upload_queue.lock().await.update_file_priority(
                &manifest.file_hash,
                upload_priority_score(&manifest.upload_priority),
            );
        }
        Ok(manifest)
    }

    /// Persist the user-facing transfer control state across process restarts.
    pub async fn set_control_state(
        &self,
        file_hash: &str,
        control_state: Option<&str>,
    ) -> Result<Ed2kResumeManifest> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        manifest.control_state = control_state.map(str::to_string);
        self.store_manifest_unlocked(&manifest).await?;
        Ok(manifest)
    }

    /// Restore a completed transfer row when the same link is explicitly added again.
    pub async fn restore_transfer_row(&self, file_hash: &str) -> Result<Ed2kResumeManifest> {
        let parsed_hash: Ed2kHash = file_hash.parse()?;
        let file_hash = parsed_hash.to_string();
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(&file_hash).await?;
        if manifest.transfer_row_removed {
            manifest.transfer_row_removed = false;
            self.store_manifest_unlocked(&manifest).await?;
        }
        Ok(manifest)
    }

    /// Remove only a completed transfer row while preserving local files.
    pub async fn remove_completed_transfer_row(
        &self,
        file_hash: &str,
    ) -> Result<Option<Ed2kResumeManifest>> {
        let parsed_hash: Ed2kHash = file_hash.parse()?;
        let file_hash = parsed_hash.to_string();
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(&file_hash).await?;
        if !manifest.completed {
            anyhow::bail!("only completed transfers can be removed without deleting files");
        }
        if manifest.transfer_row_removed {
            return Ok(None);
        }
        manifest.transfer_row_removed = true;
        self.store_manifest_unlocked(&manifest).await?;
        Ok(Some(manifest))
    }

    /// Delete one transfer's manifest, payload, and upload/catalog state.
    pub async fn delete_transfer_files(&self, file_hash: &str) -> Result<bool> {
        let parsed_hash: Ed2kHash = file_hash.parse()?;
        let file_hash = parsed_hash.to_string();
        let _guard = self.manifest_io.lock().await;
        let transfer_dir = self.transfer_dir(&file_hash);
        if self
            .load_manifest_optional_unlocked(&file_hash)
            .await?
            .is_none()
            && !tokio::fs::try_exists(&transfer_dir).await?
        {
            return Ok(false);
        }
        if tokio::fs::try_exists(&transfer_dir).await? {
            tokio::fs::remove_dir_all(&transfer_dir)
                .await
                .with_context(|| {
                    format!(
                        "failed to delete ED2K transfer directory {}",
                        transfer_dir.display()
                    )
                })?;
        }
        self.metadata.delete_transfer_manifest(&file_hash)?;
        self.manifest_cache.lock().await.remove(&file_hash);
        self.manifest_checkpoint_state
            .lock()
            .await
            .remove(&file_hash);
        self.shared_catalog
            .write()
            .await
            .retain(|entry| entry.file_hash != file_hash);
        Ok(true)
    }

    /// Return local manifest-backed file metadata even when only part of the
    /// payload has been verified already.
    pub async fn local_entry(&self, file_hash: &Ed2kHash) -> Result<Option<Ed2kSharedEntry>> {
        let hash_hex = file_hash.to_string();
        let _guard = self.manifest_io.lock().await;
        Ok(self
            .load_manifest_optional_unlocked(&hash_hex)
            .await?
            .map(|manifest| Ed2kSharedEntry::from_manifest(&manifest)))
    }

    /// Whether we share or are downloading the file with this hash.
    ///
    /// A manifest exists for both shared files and in-progress downloads, so a
    /// present manifest mirrors the oracle ListenSocket.cpp OP_CALLBACK guard
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
        let _guard = self.manifest_io.lock().await;
        let Some(manifest) = self.load_manifest_optional_unlocked(&hash_hex).await? else {
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
        let _guard = self.manifest_io.lock().await;
        let Some(manifest) = self.load_manifest_optional_unlocked(&hash_hex).await? else {
            return Ok(None);
        };
        if !manifest.aich_hashset_acquired || manifest.aich_root.is_none() {
            return Ok(None);
        }
        decode_manifest_aich_hashset(&manifest).map(Some)
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
        use super::aich_recovery::AichRecoveryHashSet;
        use super::{ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE};

        let hash_hex = file_hash.to_string();
        let (file_size, aich_root) = {
            let _guard = self.manifest_io.lock().await;
            let Some(manifest) = self.load_manifest_optional_unlocked(&hash_hex).await? else {
                return Ok(None);
            };
            // Only serve from a fully verified (shared) file.
            if !manifest.completed {
                return Ok(None);
            }
            let Some(root) = manifest.aich_root.as_deref() else {
                return Ok(None);
            };
            (manifest.file_size, decode_aich_hash_hex(root)?)
        };

        // master ProcessAICHRequest guard: file size > PARTSIZE * nPart + EMBLOCKSIZE
        if aich_root != requested_master_hash {
            return Ok(None);
        }
        if file_size <= ED2K_PART_SIZE * u64::from(part) + ED2K_EMBLOCK_SIZE {
            return Ok(None);
        }

        // The recovery data needs the whole-file tree (sibling hashes come from
        // other parts), so we read the full verified payload.
        let Some(file_data) = self.read_verified_range(file_hash, 0, file_size).await? else {
            return Ok(None);
        };
        let mut set = AichRecoveryHashSet::new(file_size);
        set.build_from_data(&file_data)?;
        if set.master_hash() != aich_root {
            // local data no longer matches the advertised AICH root
            return Ok(None);
        }
        set.create_part_recovery_data(u64::from(part)).map(Some)
    }

    /// Returns the persisted manifest for orchestration code that needs to read
    /// the current verification or hashset state.
    pub async fn manifest(&self, file_hash: &str) -> Result<Ed2kResumeManifest> {
        let _guard = self.manifest_io.lock().await;
        self.load_manifest_unlocked(file_hash).await
    }

    /// Returns all readable persisted manifests under the transfer root.
    pub async fn manifests(&self) -> Result<Vec<Ed2kResumeManifest>> {
        let _guard = self.manifest_io.lock().await;
        let mut manifests = Vec::new();
        for manifest in self.metadata.transfer_manifests()? {
            let manifest = manifest_from_metadata(manifest)?;
            self.mark_manifest_persisted_unlocked(&manifest).await;
            manifests.push(manifest);
        }
        manifests.sort_by(|left, right| left.file_hash.cmp(&right.file_hash));
        Ok(manifests)
    }
}
