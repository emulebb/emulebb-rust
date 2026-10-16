//! Finished-file delivery.
//!
//! When a transfer completes, its verified payload still lives only in the
//! internal hash-named piece store (`<root>/<hash>/pieces.bin`). This module
//! materializes that payload into an operator-facing file named by the
//! transfer's canonical name, under a destination directory chosen by the
//! caller (a category path, or the global incoming directory). This is the
//! eMule "move the finished file into Incoming/<category> by name" step
//! (`CPartFile::CompleteFile` / `PerformFileComplete`), expressed for the
//! headless piece-store model.
//!
//! MECHANICS. Delivery copies `pieces.bin` to a temp sibling and atomically
//! renames it into place. The operator-facing file must not alias the verified
//! piece store: normal edits to a completed file cannot be allowed to mutate
//! bytes later served under the transfer's ED2K hash. A name collision in the
//! destination is resolved by appending ` (1)`, ` (2)`, … before the extension,
//! matching eMule.
//!
//! The destination directory and the final delivered file path are
//! operator-facing content paths, so every filesystem operation goes through
//! [`long_path`] (Windows long-path boundary; identity elsewhere). The source
//! `pieces.bin` is an internal short path and is used as-is.

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
#[cfg(test)]
use emulebb_metadata::NativePath;
use emulebb_metadata::{
    MetadataTransferDeliveryAttempt, MetadataTransferDeliveryAttemptPhase, NativeFileFingerprint,
};
use md4::{Digest, Md4};
use uuid::Uuid;

use crate::long_path::long_path;

use super::fs_durability::sync_parent_directory;
use super::{ED2K_PART_SIZE, Ed2kTransferRuntime};

#[cfg(test)]
pub(super) const DELIVERY_PENDING_FILE_NAME: &str = "delivery.pending";
#[cfg(test)]
static DELIVERY_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Outcome of a delivery attempt for one completed transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ed2kDeliveryOutcome {
    /// This is a share-in-place file and has no delivery lifecycle.
    NotRequired,
    /// The transfer is not complete yet; nothing was delivered.
    NotCompleted,
    /// Already delivered; the recorded file still exists (idempotent no-op).
    AlreadyDelivered(PathBuf),
    /// The payload was materialized to this path.
    Delivered(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DeliveredOutputIdentity {
    Missing,
    Matching(Option<NativeFileFingerprint>),
    Foreign,
}

impl Ed2kTransferRuntime {
    /// Materialize a completed transfer's payload into `dest_dir` under its
    /// canonical name, recording the delivered path on the manifest so the
    /// operation is idempotent across restarts.
    ///
    /// Returns [`Ed2kDeliveryOutcome::NotRequired`] for a share-in-place file,
    /// [`Ed2kDeliveryOutcome::NotCompleted`] when a download is not yet fully
    /// verified, [`Ed2kDeliveryOutcome::AlreadyDelivered`] when a previously
    /// recorded delivered file still exists, or
    /// [`Ed2kDeliveryOutcome::Delivered`] when a new file was created. The heavy
    /// link/copy runs WITHOUT the manifest IO lock held so a large cross-volume
    /// copy cannot stall other transfers' manifest checkpoints.
    pub async fn materialize_completed_payload(
        &self,
        file_hash: &str,
        dest_dir: &Path,
    ) -> Result<Ed2kDeliveryOutcome> {
        let _lifecycle_guard = self.lock_lifecycle(file_hash).await;
        self.recover_delivery_attempt_unlocked(file_hash).await?;
        // Phase 1: snapshot what we need under the manifest IO lock, then
        // release it before touching the destination filesystem.
        let (display_name, expected_size, expected_hash, recorded_path, recorded_fingerprint) = {
            let _guard = self.lock_manifest(file_hash).await;
            let manifest = self.load_manifest_unlocked(file_hash).await?;
            if manifest.delivery_state == super::Ed2kDeliveryState::NotApplicable {
                return Ok(Ed2kDeliveryOutcome::NotRequired);
            }
            if !manifest.completed || manifest.final_rehash_pending {
                return Ok(Ed2kDeliveryOutcome::NotCompleted);
            }
            let recorded_path = match manifest.delivery_state {
                super::Ed2kDeliveryState::NotApplicable => unreachable!(),
                super::Ed2kDeliveryState::Pending => None,
                super::Ed2kDeliveryState::Delivered => {
                    Some(manifest.delivered_path.clone().with_context(|| {
                        format!(
                            "delivered transfer {} has no recorded output path",
                            manifest.file_hash
                        )
                    })?)
                }
            };
            (
                manifest.display_name.clone(),
                manifest.file_size,
                Ed2kHash::from_str(&manifest.file_hash)
                    .with_context(|| format!("invalid ED2K file hash {}", manifest.file_hash))?
                    .0,
                recorded_path,
                manifest.source_fingerprint.clone(),
            )
        };

        if let Some(recorded_path) = recorded_path {
            match classify_delivered_output(
                &recorded_path,
                recorded_fingerprint.as_ref(),
                expected_size,
                expected_hash,
            )
            .await
            {
                Ok(DeliveredOutputIdentity::Matching(current_fingerprint))
                    if recorded_fingerprint
                        .as_ref()
                        .zip(current_fingerprint.as_ref())
                        .is_some_and(|(recorded, current)| recorded.safely_matches(current)) =>
                {
                    return Ok(Ed2kDeliveryOutcome::AlreadyDelivered(recorded_path));
                }
                Ok(DeliveredOutputIdentity::Matching(_)) => {
                    tracing::warn!(
                        file_hash,
                        path = %recorded_path.display(),
                        "recorded output content matches but native identity changed; refusing to adopt unproven ownership"
                    );
                }
                Ok(DeliveredOutputIdentity::Missing | DeliveredOutputIdentity::Foreign) => {}
                Err(error) => {
                    tracing::warn!(
                        %error,
                        file_hash,
                        path = %recorded_path.display(),
                        "recorded delivered output could not be verified; scheduling redelivery"
                    );
                }
            }

            let _guard = self.lock_manifest(file_hash).await;
            let mut manifest = self.load_manifest_unlocked(file_hash).await?;
            if manifest.delivery_state == super::Ed2kDeliveryState::Delivered
                && manifest.delivered_path.as_ref() == Some(&recorded_path)
            {
                manifest.delivery_state = super::Ed2kDeliveryState::Pending;
                manifest.delivered_path = None;
                manifest.source_fingerprint = None;
                self.store_manifest_unlocked(&manifest).await?;
            }
        }

        let source = self.payload_path(file_hash);
        let installed = self
            .deliver_payload_file(
                file_hash,
                &source,
                dest_dir,
                &display_name,
                expected_size,
                expected_hash,
            )
            .await
            .with_context(|| format!("failed to deliver completed transfer {file_hash}"))?;
        let final_path = installed.path;

        // Phase 2: persist the delivered path under the lock.
        {
            let _guard = self.lock_manifest(file_hash).await;
            let mut manifest = self.load_manifest_unlocked(file_hash).await?;
            manifest.delivery_state = super::Ed2kDeliveryState::Delivered;
            manifest.delivered_path = Some(final_path.clone());
            // Record the delivered file's native fingerprint so a later
            // shared-directory rescan that re-finds this file in a shared
            // Incoming/category dir reuses the download's already-computed
            // hashset instead of re-reading and re-hashing the whole payload
            // (HASH-2; oracle FindKnownFile, SharedFileList.cpp:2138). Only for a
            // real download (`source_path == None`); a share-in-place manifest
            // keeps its own source fingerprint and is never delivered. It is
            // read AFTER the file is in place, through the same `long_path` stat
            // the reload uses, so an unchanged delivered file compares equal on
            // reload (the copy+rename gets a fresh identity that is stable
            // thereafter).
            if manifest.source_path.is_none() {
                manifest.source_fingerprint = Some(installed.fingerprint);
            }
            self.store_manifest_unlocked(&manifest).await?;
        }
        Ok(Ed2kDeliveryOutcome::Delivered(final_path))
    }
}

#[derive(Debug)]
struct InstalledDelivery {
    path: PathBuf,
    fingerprint: NativeFileFingerprint,
}

fn validate_delivery_attempt_paths(attempt: &MetadataTransferDeliveryAttempt) -> Result<()> {
    anyhow::ensure!(
        attempt.target_path.is_absolute() && attempt.staging_path.is_absolute(),
        "delivery attempt {} contains a non-absolute path",
        attempt.attempt_id
    );
    anyhow::ensure!(
        attempt.target_path.file_name().is_some()
            && attempt.target_path.parent().is_some()
            && attempt.target_path.parent() == attempt.staging_path.parent(),
        "delivery attempt {} paths do not share one target parent",
        attempt.attempt_id
    );
    let expected_staging_name = format!(".emulebb-delivery-{}.tmp", attempt.attempt_id);
    anyhow::ensure!(
        attempt
            .staging_path
            .file_name()
            .is_some_and(|name| name == std::ffi::OsStr::new(&expected_staging_name)),
        "delivery attempt {} has an invalid staging name",
        attempt.attempt_id
    );
    Ok(())
}

pub(super) async fn classify_delivered_output(
    path: &Path,
    recorded_fingerprint: Option<&NativeFileFingerprint>,
    expected_size: u64,
    expected_hash: [u8; 16],
) -> Result<DeliveredOutputIdentity> {
    let path = long_path(path);
    let recorded_fingerprint = recorded_fingerprint.cloned();
    tokio::task::spawn_blocking(move || {
        let metadata = match path.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DeliveredOutputIdentity::Missing);
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to stat {}", path.display()));
            }
        };
        if !metadata.file_type().is_file() || metadata.len() != expected_size {
            return Ok(DeliveredOutputIdentity::Foreign);
        }
        let current_fingerprint = super::ingest::native_file_fingerprint(&path);
        if recorded_fingerprint
            .as_ref()
            .zip(current_fingerprint.as_ref())
            .is_some_and(|(recorded, current)| recorded.safely_matches(current))
        {
            return Ok(DeliveredOutputIdentity::Matching(current_fingerprint));
        }
        if compute_ed2k_hash(&path, expected_size)? != Some(expected_hash) {
            return Ok(DeliveredOutputIdentity::Foreign);
        }
        let post_hash_fingerprint = path
            .symlink_metadata()
            .ok()
            .filter(|metadata| metadata.file_type().is_file() && metadata.len() == expected_size)
            .and_then(|_| super::ingest::native_file_fingerprint(&path));
        if current_fingerprint.is_some() && current_fingerprint != post_hash_fingerprint {
            return Ok(DeliveredOutputIdentity::Foreign);
        }
        Ok(DeliveredOutputIdentity::Matching(post_hash_fingerprint))
    })
    .await
    .context("delivered-output identity task failed")?
}

fn delivered_file_fingerprint(path: &Path) -> Option<NativeFileFingerprint> {
    let path = long_path(path);
    let metadata = path.symlink_metadata().ok()?;
    metadata.file_type().is_file().then_some(())?;
    super::ingest::native_file_fingerprint(&path)
}

impl Ed2kTransferRuntime {
    /// Copy `source` (`pieces.bin`) into `dest_dir` under a collision-free file
    /// name. Every temporary artifact is named and owned by a durable delivery
    /// attempt before it is created.
    async fn deliver_payload_file(
        &self,
        file_hash: &str,
        source: &Path,
        dest_dir: &Path,
        display_name: &str,
        expected_size: u64,
        expected_hash: [u8; 16],
    ) -> Result<InstalledDelivery> {
        validate_delivery_source(source, expected_size).await?;
        tokio::fs::create_dir_all(long_path(dest_dir))
            .await
            .with_context(|| {
                format!("failed to create delivery directory {}", dest_dir.display())
            })?;

        let file_name = sanitize_file_name(display_name);
        let (stem, extension) = split_stem_extension(&file_name);
        for index in 0..=u32::MAX {
            let candidate_name = if index == 0 {
                file_name.clone()
            } else {
                match &extension {
                    Some(extension) => format!("{stem} ({index}).{extension}"),
                    None => format!("{stem} ({index})"),
                }
            };
            let target_path = dest_dir.join(candidate_name);
            if path_exists(&target_path).await {
                continue;
            }

            let attempt_id = Uuid::new_v4();
            let staging_path = dest_dir.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
            self.begin_delivery_attempt(file_hash, attempt_id, &target_path, &staging_path)
                .await?;
            stage_delivery_payload(source, &staging_path).await?;
            let staging_fingerprint =
                verify_delivery_fingerprint(&staging_path, expected_size, expected_hash).await?;
            anyhow::ensure!(
                self.mark_delivery_attempt_staged(file_hash, attempt_id, &staging_fingerprint)
                    .await?,
                "delivery attempt {attempt_id} disappeared before staging committed"
            );

            match install_staged_payload(&staging_path, &target_path).await? {
                InstallOutcome::Installed => {
                    let installed_fingerprint =
                        verify_delivery_fingerprint(&target_path, expected_size, expected_hash)
                            .await?;
                    anyhow::ensure!(
                        installed_fingerprint == staging_fingerprint,
                        "installed delivery identity changed at {}",
                        target_path.display()
                    );
                    return Ok(InstalledDelivery {
                        path: target_path,
                        fingerprint: staging_fingerprint,
                    });
                }
                InstallOutcome::AlreadyExists => {
                    remove_if_exists(&staging_path).await?;
                    anyhow::ensure!(
                        self.clear_delivery_attempt(file_hash, attempt_id).await?,
                        "delivery attempt {attempt_id} disappeared during collision cleanup"
                    );
                }
            }
        }
        anyhow::bail!(
            "exhausted collision-free delivery names in {}",
            dest_dir.display()
        )
    }

    async fn begin_delivery_attempt(
        &self,
        file_hash: &str,
        attempt_id: Uuid,
        target_path: &Path,
        staging_path: &Path,
    ) -> Result<MetadataTransferDeliveryAttempt> {
        let metadata = self.metadata.clone();
        let file_hash = file_hash.to_owned();
        let target_path = target_path.to_owned();
        let staging_path = staging_path.to_owned();
        tokio::task::spawn_blocking(move || {
            metadata.begin_transfer_delivery_attempt(
                &file_hash,
                attempt_id,
                &target_path,
                &staging_path,
            )
        })
        .await
        .context("ED2K delivery-attempt prepare task panicked")?
    }

    async fn mark_delivery_attempt_staged(
        &self,
        file_hash: &str,
        attempt_id: Uuid,
        staging_fingerprint: &NativeFileFingerprint,
    ) -> Result<bool> {
        let metadata = self.metadata.clone();
        let file_hash = file_hash.to_owned();
        let staging_fingerprint = staging_fingerprint.clone();
        tokio::task::spawn_blocking(move || {
            metadata.mark_transfer_delivery_attempt_staged(
                &file_hash,
                attempt_id,
                &staging_fingerprint,
            )
        })
        .await
        .context("ED2K delivery-attempt stage task panicked")?
    }

    async fn clear_delivery_attempt(&self, file_hash: &str, attempt_id: Uuid) -> Result<bool> {
        let metadata = self.metadata.clone();
        let file_hash = file_hash.to_owned();
        tokio::task::spawn_blocking(move || {
            metadata.clear_transfer_delivery_attempt(&file_hash, attempt_id)
        })
        .await
        .context("ED2K delivery-attempt cleanup task panicked")?
    }

    async fn delivery_attempt(
        &self,
        file_hash: &str,
    ) -> Result<Option<MetadataTransferDeliveryAttempt>> {
        let metadata = self.metadata.clone();
        let file_hash = file_hash.to_owned();
        tokio::task::spawn_blocking(move || metadata.transfer_delivery_attempt_by_hash(&file_hash))
            .await
            .context("ED2K delivery-attempt load task panicked")?
    }

    pub(super) async fn recover_delivery_attempt_unlocked(&self, file_hash: &str) -> Result<()> {
        let Some(attempt) = self.delivery_attempt(file_hash).await? else {
            return Ok(());
        };
        validate_delivery_attempt_paths(&attempt)?;
        let manifest = {
            let _manifest_guard = self.lock_manifest(file_hash).await;
            self.load_manifest_unlocked(file_hash).await?
        };
        if manifest.delivery_state == super::Ed2kDeliveryState::Delivered {
            remove_if_exists(&attempt.staging_path).await?;
            self.clear_delivery_attempt(file_hash, attempt.attempt_id)
                .await?;
            return Ok(());
        }
        if manifest.delivery_state != super::Ed2kDeliveryState::Pending
            || !manifest.completed
            || manifest.final_rehash_pending
        {
            remove_if_exists(&attempt.staging_path).await?;
            self.clear_delivery_attempt(file_hash, attempt.attempt_id)
                .await?;
            return Ok(());
        }
        if attempt.phase == MetadataTransferDeliveryAttemptPhase::Prepared {
            remove_if_exists(&attempt.staging_path).await?;
            self.clear_delivery_attempt(file_hash, attempt.attempt_id)
                .await?;
            return Ok(());
        }

        let expected_hash = Ed2kHash::from_str(&manifest.file_hash)
            .with_context(|| format!("invalid ED2K file hash {}", manifest.file_hash))?
            .0;
        let target_fingerprint = match classify_delivered_output(
            &attempt.staging_path,
            None,
            manifest.file_size,
            expected_hash,
        )
        .await?
        {
            DeliveredOutputIdentity::Matching(_) => {
                match path_exists(&attempt.target_path).await {
                    false => {
                        match install_staged_payload(&attempt.staging_path, &attempt.target_path)
                            .await?
                        {
                            InstallOutcome::Installed => {}
                            InstallOutcome::AlreadyExists => {
                                remove_if_exists(&attempt.staging_path).await?;
                                self.clear_delivery_attempt(file_hash, attempt.attempt_id)
                                    .await?;
                                return Ok(());
                            }
                        }
                    }
                    true => {
                        if same_regular_file_identity(&attempt.staging_path, &attempt.target_path)
                            .await?
                        {
                            remove_if_exists(&attempt.staging_path).await?;
                        } else {
                            remove_if_exists(&attempt.staging_path).await?;
                            self.clear_delivery_attempt(file_hash, attempt.attempt_id)
                                .await?;
                            return Ok(());
                        }
                    }
                }
                match classify_delivered_output(
                    &attempt.target_path,
                    None,
                    manifest.file_size,
                    expected_hash,
                )
                .await?
                {
                    DeliveredOutputIdentity::Matching(fingerprint) => fingerprint,
                    DeliveredOutputIdentity::Missing | DeliveredOutputIdentity::Foreign => {
                        self.clear_delivery_attempt(file_hash, attempt.attempt_id)
                            .await?;
                        return Ok(());
                    }
                }
            }
            DeliveredOutputIdentity::Missing => {
                sync_parent_directory(&attempt.staging_path).await?;
                match classify_delivered_output(
                    &attempt.target_path,
                    None,
                    manifest.file_size,
                    expected_hash,
                )
                .await?
                {
                    DeliveredOutputIdentity::Matching(fingerprint) => fingerprint,
                    DeliveredOutputIdentity::Missing | DeliveredOutputIdentity::Foreign => {
                        self.clear_delivery_attempt(file_hash, attempt.attempt_id)
                            .await?;
                        return Ok(());
                    }
                }
            }
            DeliveredOutputIdentity::Foreign => {
                remove_if_exists(&attempt.staging_path).await?;
                self.clear_delivery_attempt(file_hash, attempt.attempt_id)
                    .await?;
                return Ok(());
            }
        };

        let _manifest_guard = self.lock_manifest(file_hash).await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        anyhow::ensure!(
            manifest.delivery_state == super::Ed2kDeliveryState::Pending
                && manifest.completed
                && !manifest.final_rehash_pending,
            "transfer {file_hash} changed while recovering delivery attempt {}",
            attempt.attempt_id
        );
        manifest.delivery_state = super::Ed2kDeliveryState::Delivered;
        manifest.delivered_path = Some(attempt.target_path);
        manifest.source_fingerprint = target_fingerprint;
        self.store_manifest_unlocked(&manifest).await
    }

    pub(super) async fn discard_delivery_attempt_for_deletion_unlocked(
        &self,
        file_hash: &str,
        manifest: &super::Ed2kResumeManifest,
    ) -> Result<()> {
        let Some(attempt) = self.delivery_attempt(file_hash).await? else {
            return Ok(());
        };
        validate_delivery_attempt_paths(&attempt)?;
        let mut owned_target_fingerprint = None;
        if attempt.phase == MetadataTransferDeliveryAttemptPhase::Staged {
            let expected_hash = Ed2kHash::from_str(&manifest.file_hash)
                .with_context(|| format!("invalid ED2K file hash {}", manifest.file_hash))?
                .0;
            match classify_delivered_output(
                &attempt.staging_path,
                None,
                manifest.file_size,
                expected_hash,
            )
            .await?
            {
                DeliveredOutputIdentity::Matching(_) => {
                    if path_exists(&attempt.target_path).await
                        && same_regular_file_identity(&attempt.staging_path, &attempt.target_path)
                            .await?
                        && let DeliveredOutputIdentity::Matching(fingerprint) =
                            classify_delivered_output(
                                &attempt.target_path,
                                None,
                                manifest.file_size,
                                expected_hash,
                            )
                            .await?
                    {
                        owned_target_fingerprint = fingerprint;
                    }
                }
                DeliveredOutputIdentity::Missing => {
                    if let DeliveredOutputIdentity::Matching(fingerprint) =
                        classify_delivered_output(
                            &attempt.target_path,
                            None,
                            manifest.file_size,
                            expected_hash,
                        )
                        .await?
                    {
                        owned_target_fingerprint = fingerprint;
                    }
                }
                DeliveredOutputIdentity::Foreign => {}
            }
        }

        if let Some(expected_fingerprint) = owned_target_fingerprint.as_ref() {
            remove_delivery_target_if_unchanged(&attempt.target_path, expected_fingerprint).await?;
        } else if owned_target_fingerprint.is_none() && path_exists(&attempt.target_path).await {
            tracing::warn!(
                file_hash,
                path = %attempt.target_path.display(),
                "preserving delivery-attempt target without sufficient ownership evidence during deletion"
            );
        }
        remove_if_exists(&attempt.staging_path).await?;
        self.clear_delivery_attempt(file_hash, attempt.attempt_id)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
async fn deliver_payload_file(
    source: &Path,
    dest_dir: &Path,
    display_name: &str,
    expected_size: u64,
    expected_hash: [u8; 16],
    _legacy_pending_path: &Path,
) -> Result<PathBuf> {
    validate_delivery_source(source, expected_size).await?;
    tokio::fs::create_dir_all(long_path(dest_dir)).await?;
    let file_name = sanitize_file_name(display_name);
    let (stem, extension) = split_stem_extension(&file_name);
    for index in 0..=u32::MAX {
        let candidate_name = if index == 0 {
            file_name.clone()
        } else {
            match &extension {
                Some(extension) => format!("{stem} ({index}).{extension}"),
                None => format!("{stem} ({index})"),
            }
        };
        let target_path = dest_dir.join(candidate_name);
        if path_exists(&target_path).await {
            continue;
        }
        let staging_path = dest_dir.join(format!(".emulebb-delivery-{}.tmp", Uuid::new_v4()));
        stage_delivery_payload(source, &staging_path).await?;
        let _ = verify_delivery_fingerprint(&staging_path, expected_size, expected_hash).await?;
        match install_staged_payload(&staging_path, &target_path).await? {
            InstallOutcome::Installed => {
                let _ =
                    verify_delivery_fingerprint(&target_path, expected_size, expected_hash).await?;
                return Ok(target_path);
            }
            InstallOutcome::AlreadyExists => remove_if_exists(&staging_path).await?,
        }
    }
    anyhow::bail!(
        "exhausted collision-free delivery names in {}",
        dest_dir.display()
    )
}

async fn validate_delivery_source(source: &Path, expected_size: u64) -> Result<()> {
    let metadata = match tokio::fs::symlink_metadata(source).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && expected_size == 0 => {
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("missing delivery payload {}", source.display());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to stat delivery payload {}", source.display()));
        }
    };
    if !metadata.is_file() {
        anyhow::bail!(
            "delivery payload is not a regular file: {}",
            source.display()
        );
    }
    if metadata.len() != expected_size {
        anyhow::bail!(
            "delivery payload size mismatch for {}: expected {expected_size} bytes, found {}",
            source.display(),
            metadata.len()
        );
    }
    Ok(())
}

async fn verify_delivery_fingerprint(
    path: &Path,
    expected_size: u64,
    expected_hash: [u8; 16],
) -> Result<NativeFileFingerprint> {
    match classify_delivered_output(path, None, expected_size, expected_hash).await? {
        DeliveredOutputIdentity::Matching(Some(fingerprint)) => Ok(fingerprint),
        DeliveredOutputIdentity::Matching(None) => {
            anyhow::bail!(
                "delivered file has no stable native identity: {}",
                path.display()
            );
        }
        DeliveredOutputIdentity::Missing | DeliveredOutputIdentity::Foreign => {
            anyhow::bail!("delivered file failed verification: {}", path.display());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallOutcome {
    Installed,
    AlreadyExists,
}

/// Materialize one independent payload copy at an exact, attempt-owned staging
/// path. The caller persists that path before invoking this function.
async fn stage_delivery_payload(source: &Path, staging_path: &Path) -> Result<()> {
    let source_lp = long_path(source);
    let staging_lp = long_path(staging_path);
    let mut output = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staging_lp)
        .await
        .with_context(|| {
            format!(
                "failed to create delivery staging file {}",
                staging_path.display()
            )
        })?;

    if path_exists(source).await {
        let mut input = tokio::fs::File::open(&source_lp)
            .await
            .with_context(|| format!("failed to open delivery payload {}", source.display()))?;
        tokio::io::copy(&mut input, &mut output)
            .await
            .with_context(|| format!("failed to copy payload {}", source.display()))?;
    }
    output.sync_all().await?;
    drop(output);
    sync_parent_directory(staging_path).await?;
    Ok(())
}

/// Publish a staged file without replacing a pre-existing destination. A hard
/// link is an atomic no-clobber install within the shared parent directory; the
/// staging name is removed immediately after the target link exists.
async fn install_staged_payload(staging_path: &Path, target_path: &Path) -> Result<InstallOutcome> {
    match tokio::fs::hard_link(long_path(staging_path), long_path(target_path)).await {
        Ok(()) => {
            tokio::fs::remove_file(long_path(staging_path))
                .await
                .with_context(|| {
                    format!(
                        "failed to remove installed delivery staging file {}",
                        staging_path.display()
                    )
                })?;
            sync_parent_directory(target_path).await?;
            Ok(InstallOutcome::Installed)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(InstallOutcome::AlreadyExists)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to install delivery staging file {} at {}",
                staging_path.display(),
                target_path.display()
            )
        }),
    }
}

#[cfg(test)]
pub(super) async fn read_pending_delivery_path(path: &Path) -> Result<Option<PathBuf>> {
    let native_path = match tokio::fs::read(path).await {
        Ok(native_path) => native_path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read delivery intent {}", path.display()));
        }
    };
    anyhow::ensure!(
        !native_path.is_empty(),
        "delivery intent {} contains an empty native path",
        path.display()
    );
    Ok(Some(
        NativePath::from_storage(NativePath::platform(), &native_path)
            .with_context(|| format!("invalid delivery intent {}", path.display()))?
            .into_path_buf(),
    ))
}

#[cfg(test)]
pub(super) async fn persist_pending_delivery_path(path: &Path, candidate: &Path) -> Result<()> {
    let sequence = DELIVERY_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = path.with_extension(format!("pending-{sequence}.tmp"));
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .await
        .with_context(|| format!("failed to create delivery intent {}", temp.display()))?;
    use tokio::io::AsyncWriteExt;
    file.write_all(&NativePath::from(candidate).storage_bytes())
        .await?;
    file.sync_all().await?;
    drop(file);
    remove_if_exists(path).await?;
    tokio::fs::rename(&temp, path)
        .await
        .with_context(|| format!("failed to commit delivery intent {}", path.display()))?;
    Ok(())
}

async fn remove_if_exists(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(long_path(path)).await {
        Ok(()) => sync_parent_directory(path).await,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            sync_parent_directory(path).await
        }
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

async fn remove_delivery_target_if_unchanged(
    path: &Path,
    expected_fingerprint: &NativeFileFingerprint,
) -> Result<()> {
    let owned_path = long_path(path);
    let display_path = path.to_path_buf();
    let expected_fingerprint = expected_fingerprint.clone();
    let removed = tokio::task::spawn_blocking(move || -> Result<bool> {
        let metadata = match owned_path.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file() {
            return Ok(false);
        }
        let Some(current_fingerprint) = super::ingest::native_file_fingerprint(&owned_path) else {
            return Ok(false);
        };
        if !expected_fingerprint.safely_matches(&current_fingerprint) {
            return Ok(false);
        }
        match std::fs::remove_file(&owned_path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.into()),
        }
    })
    .await
    .context("delivery target cleanup task panicked")??;
    if !removed {
        tracing::warn!(
            path = %display_path.display(),
            "preserving delivery-attempt target whose native identity changed during deletion"
        );
    } else {
        sync_parent_directory(path).await?;
    }
    Ok(())
}

async fn delivered_file_matches(
    path: &Path,
    expected_size: u64,
    expected_hash: [u8; 16],
) -> Result<bool> {
    classify_delivered_output(path, None, expected_size, expected_hash)
        .await
        .map(|identity| matches!(identity, DeliveredOutputIdentity::Matching(_)))
}

fn compute_ed2k_hash(path: &Path, expected_size: u64) -> Result<Option<[u8; 16]>> {
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to stat {}", path.display()));
        }
    };
    if !metadata.is_file() || metadata.len() != expected_size {
        return Ok(None);
    }
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(0))?;
    let part_count = expected_size.div_ceil(ED2K_PART_SIZE);
    let mut part_hashes = Vec::with_capacity(usize::try_from(part_count).unwrap_or(0));
    let mut remaining = expected_size;
    for _ in 0..part_count {
        let mut hasher = Md4::new();
        let mut part_remaining = remaining.min(ED2K_PART_SIZE);
        let mut buffer = [0u8; 65_536];
        while part_remaining > 0 {
            let length = usize::try_from(part_remaining.min(buffer.len() as u64)).unwrap_or(0);
            file.read_exact(&mut buffer[..length])?;
            hasher.update(&buffer[..length]);
            part_remaining -= length as u64;
        }
        part_hashes.push(<[u8; 16]>::from(hasher.finalize()));
        remaining = remaining.saturating_sub(ED2K_PART_SIZE);
    }
    if expected_size == 0 {
        return Ok(Some(Md4::new().finalize().into()));
    }
    if expected_size < ED2K_PART_SIZE {
        return Ok(part_hashes.first().copied());
    }
    let mut composite = Md4::new();
    for hash in part_hashes {
        composite.update(hash);
    }
    if expected_size.is_multiple_of(ED2K_PART_SIZE) {
        composite.update(<[u8; 16]>::from(Md4::new().finalize()));
    }
    Ok(Some(composite.finalize().into()))
}

async fn path_exists(path: &Path) -> bool {
    tokio::fs::metadata(long_path(path)).await.is_ok()
}

async fn same_regular_file_identity(first: &Path, second: &Path) -> Result<bool> {
    let first_metadata = tokio::fs::symlink_metadata(long_path(first))
        .await
        .with_context(|| {
            format!(
                "failed to inspect delivery staging file {}",
                first.display()
            )
        })?;
    let second_metadata = tokio::fs::symlink_metadata(long_path(second))
        .await
        .with_context(|| format!("failed to inspect delivery target {}", second.display()))?;
    if !first_metadata.file_type().is_file() || !second_metadata.file_type().is_file() {
        return Ok(false);
    }
    let first = long_path(first);
    let second = long_path(second);
    tokio::task::spawn_blocking(move || {
        Ok::<_, anyhow::Error>(file_id::get_file_id(first)? == file_id::get_file_id(second)?)
    })
    .await
    .context("delivery file-identity task panicked")?
}

/// Replace filesystem-reserved characters in a canonical name so it is safe to
/// use as a single path component on Windows and POSIX. Strips trailing dots /
/// spaces (invalid as a Windows file name) and never returns an empty name.
fn sanitize_file_name(name: &str) -> String {
    let mut sanitized: String = name
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            ch if (ch as u32) < 0x20 => '_',
            ch => ch,
        })
        .collect();
    while sanitized.ends_with('.') || sanitized.ends_with(' ') {
        sanitized.pop();
    }
    let mut sanitized = sanitized.trim_start().to_string();
    if sanitized.is_empty() {
        return "download".to_string();
    }
    if is_reserved_windows_leaf(&sanitized) {
        let insertion = sanitized.find('.').unwrap_or(sanitized.len());
        sanitized.insert(insertion, '_');
    }
    sanitized
}

/// Windows treats these basenames as DOS devices even when an extension is
/// present. Protect them on every platform so a download profile remains
/// portable and the delivered file is manageable by ordinary Windows tools.
fn is_reserved_windows_leaf(name: &str) -> bool {
    let candidate = name.trim_end_matches([' ', '.']);
    let stem = candidate.split('.').next().unwrap_or(candidate);
    let upper = stem.to_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$") {
        return true;
    }
    let is_reserved_port = |prefix: &str| {
        let Some(suffix) = upper.strip_prefix(prefix) else {
            return false;
        };
        matches!(
            suffix,
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
    };
    is_reserved_port("COM") || is_reserved_port("LPT")
}

/// Split a file name into `(stem, Some(extension))`, or `(name, None)` when
/// there is no usable extension (no dot, leading-dot dotfile, or empty tail).
fn split_stem_extension(file_name: &str) -> (String, Option<String>) {
    match file_name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() && !extension.is_empty() => {
            (stem.to_string(), Some(extension.to_string()))
        }
        _ => (file_name.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "emulebb-deliver-{}-{nanos}-{seq}",
            std::process::id()
        ))
    }

    #[test]
    fn sanitize_replaces_reserved_characters() {
        assert_eq!(sanitize_file_name("a/b\\c:d*e?.bin"), "a_b_c_d_e_.bin");
        assert_eq!(sanitize_file_name("name."), "name");
        assert_eq!(sanitize_file_name("trailing  "), "trailing");
        assert_eq!(sanitize_file_name(""), "download");
        assert_eq!(sanitize_file_name("Sample.Title.mkv"), "Sample.Title.mkv");
        assert_eq!(sanitize_file_name("CON"), "CON_");
        assert_eq!(sanitize_file_name("nul.txt"), "nul_.txt");
        assert_eq!(sanitize_file_name("COM1.tar.gz"), "COM1_.tar.gz");
        assert_eq!(sanitize_file_name("lpt².log"), "lpt²_.log");
        assert_eq!(sanitize_file_name("CLOCK$.bin"), "CLOCK$_.bin");
    }

    #[test]
    fn split_stem_extension_handles_edge_cases() {
        assert_eq!(
            split_stem_extension("movie.mkv"),
            ("movie".to_string(), Some("mkv".to_string()))
        );
        assert_eq!(
            split_stem_extension("archive.tar.gz"),
            ("archive.tar".to_string(), Some("gz".to_string()))
        );
        assert_eq!(split_stem_extension("noext"), ("noext".to_string(), None));
        assert_eq!(
            split_stem_extension(".dotfile"),
            (".dotfile".to_string(), None)
        );
    }

    #[tokio::test]
    async fn delivers_payload_with_display_name() {
        let dir = temp_dir();
        let source = dir.join("pieces.bin");
        let dest = dir.join("incoming");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(&source, b"payload-bytes").await.unwrap();

        let expected_hash = Md4::digest(b"payload-bytes").into();
        let delivered = deliver_payload_file(
            &source,
            &dest,
            "Sample.Title.mkv",
            13,
            expected_hash,
            &dir.join(DELIVERY_PENDING_FILE_NAME),
        )
        .await
        .unwrap();

        assert_eq!(delivered, dest.join("Sample.Title.mkv"));
        assert_eq!(tokio::fs::read(&delivered).await.unwrap(), b"payload-bytes");
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn collision_appends_numbered_suffix() {
        let dir = temp_dir();
        let source = dir.join("pieces.bin");
        let dest = dir.join("incoming");
        tokio::fs::create_dir_all(&dest).await.unwrap();
        tokio::fs::write(&source, b"data").await.unwrap();
        // Pre-existing file with the canonical name forces a suffix.
        tokio::fs::write(dest.join("clip.mkv"), b"old")
            .await
            .unwrap();

        let expected_hash = Md4::digest(b"data").into();
        let delivered = deliver_payload_file(
            &source,
            &dest,
            "clip.mkv",
            4,
            expected_hash,
            &dir.join(DELIVERY_PENDING_FILE_NAME),
        )
        .await
        .unwrap();

        assert_eq!(delivered, dest.join("clip (1).mkv"));
        assert_eq!(tokio::fs::read(&delivered).await.unwrap(), b"data");
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn empty_payload_delivers_empty_file() {
        let dir = temp_dir();
        // No source file on disk: the zero-byte completed-transfer case.
        let source = dir.join("pieces.bin");
        let dest = dir.join("incoming");
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let expected_hash = Md4::new().finalize().into();
        let delivered = deliver_payload_file(
            &source,
            &dest,
            "empty.dat",
            0,
            expected_hash,
            &dir.join(DELIVERY_PENDING_FILE_NAME),
        )
        .await
        .unwrap();

        assert_eq!(delivered, dest.join("empty.dat"));
        assert_eq!(tokio::fs::read(&delivered).await.unwrap(), b"");
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn truncated_payload_is_rejected_before_destination_creation() {
        let dir = temp_dir();
        let source = dir.join("pieces.bin");
        let dest = dir.join("incoming");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(&source, b"short").await.unwrap();

        let error = deliver_payload_file(
            &source,
            &dest,
            "truncated.bin",
            10,
            Md4::digest(b"ten-bytes!").into(),
            &dir.join(DELIVERY_PENDING_FILE_NAME),
        )
        .await
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("delivery payload size mismatch"),
            "unexpected error: {error:#}"
        );
        assert!(!dest.exists());
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn installed_payload_is_removed_when_hash_verification_fails() {
        let dir = temp_dir();
        let source = dir.join("pieces.bin");
        let dest = dir.join("incoming");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(&source, b"payload-bytes").await.unwrap();
        let delivered = dest.join("wrong-hash.bin");

        let error = deliver_payload_file(
            &source,
            &dest,
            "wrong-hash.bin",
            13,
            [0x55; 16],
            &dir.join(DELIVERY_PENDING_FILE_NAME),
        )
        .await
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("installed delivered file failed verification"),
            "unexpected error: {error:#}"
        );
        assert!(!delivered.exists());
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn legacy_pending_intent_does_not_authorize_target_adoption() {
        let dir = temp_dir();
        let source = dir.join("pieces.bin");
        let dest = dir.join("incoming");
        let pending = dir.join(DELIVERY_PENDING_FILE_NAME);
        tokio::fs::create_dir_all(&dest).await.unwrap();
        tokio::fs::write(&source, b"recovered-payload")
            .await
            .unwrap();
        let installed = dest.join("recovered.bin");
        tokio::fs::write(&installed, b"recovered-payload")
            .await
            .unwrap();
        persist_pending_delivery_path(&pending, &installed)
            .await
            .unwrap();

        let delivered = deliver_payload_file(
            &source,
            &dest,
            "recovered.bin",
            17,
            Md4::digest(b"recovered-payload").into(),
            &pending,
        )
        .await
        .unwrap();

        assert_eq!(delivered, dest.join("recovered (1).bin"));
        assert_eq!(
            tokio::fs::read(&installed).await.unwrap(),
            b"recovered-payload"
        );
        assert_eq!(
            tokio::fs::read(&delivered).await.unwrap(),
            b"recovered-payload"
        );
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pending_intent_roundtrips_non_utf8_native_path() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let dir = temp_dir();
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let pending = dir.join(DELIVERY_PENDING_FILE_NAME);
        let candidate = dir.join(OsString::from_vec(b"delivered-\xff.bin".to_vec()));

        persist_pending_delivery_path(&pending, &candidate)
            .await
            .unwrap();

        assert_eq!(
            read_pending_delivery_path(&pending).await.unwrap(),
            Some(candidate)
        );
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn delivered_output_identity_distinguishes_missing_matching_and_foreign() {
        let dir = temp_dir();
        let matching = dir.join("matching.bin");
        let foreign = dir.join("foreign.bin");
        let missing = dir.join("missing.bin");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(&matching, b"canonical").await.unwrap();
        tokio::fs::write(&foreign, b"unrelated").await.unwrap();
        let expected_hash = Md4::digest(b"canonical").into();

        assert!(matches!(
            classify_delivered_output(&matching, None, 9, expected_hash)
                .await
                .unwrap(),
            DeliveredOutputIdentity::Matching(_)
        ));
        assert_eq!(
            classify_delivered_output(&foreign, None, 9, expected_hash)
                .await
                .unwrap(),
            DeliveredOutputIdentity::Foreign
        );
        assert_eq!(
            classify_delivered_output(&missing, None, 9, expected_hash)
                .await
                .unwrap(),
            DeliveredOutputIdentity::Missing
        );
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn concurrent_same_name_deliveries_never_overwrite() {
        let dir = temp_dir();
        let dest = dir.join("incoming");
        let first_source = dir.join("first.bin");
        let second_source = dir.join("second.bin");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(&first_source, b"first-payload")
            .await
            .unwrap();
        tokio::fs::write(&second_source, b"second-payload")
            .await
            .unwrap();
        let first_pending = dir.join("first.pending");
        let second_pending = dir.join("second.pending");

        let first = deliver_payload_file(
            &first_source,
            &dest,
            "same.bin",
            13,
            Md4::digest(b"first-payload").into(),
            &first_pending,
        );
        let second = deliver_payload_file(
            &second_source,
            &dest,
            "same.bin",
            14,
            Md4::digest(b"second-payload").into(),
            &second_pending,
        );
        let (first_path, second_path) = tokio::join!(first, second);
        let first_path = first_path.unwrap();
        let second_path = second_path.unwrap();

        assert_ne!(first_path, second_path);
        assert_eq!(tokio::fs::read(first_path).await.unwrap(), b"first-payload");
        assert_eq!(
            tokio::fs::read(second_path).await.unwrap(),
            b"second-payload"
        );
        assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 2);
        tokio::fs::remove_dir_all(&dir).await.ok();
    }
}
