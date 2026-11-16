//! Finished-file delivery.
//!
//! When a transfer completes, its verified payload still lives only in the
//! persisted job-specific piece store (`<selected-temp>/<job-id>-<uuid>/pieces.bin`). This module
//! materializes that payload into an operator-facing file named by the
//! transfer's canonical name, under a destination directory chosen by the
//! caller (a category path, or the global incoming directory). This is the
//! eMule "move the finished file into Incoming/<category> by name" step
//! (`CPartFile::CompleteFile` / `PerformFileComplete`), expressed for the
//! headless piece-store model.
//!
//! MECHANICS. Delivery copies `pieces.bin` to a temp sibling and atomically
//! renames it into place when supported. If the filesystem rejects atomic
//! no-replace rename, an exclusively created final file is copied and verified
//! under a durable sharing exclusion. The operator-facing file must not alias the verified
//! piece store: normal edits to a completed file cannot be allowed to mutate
//! bytes later served under the transfer's ED2K hash. A name collision in the
//! destination is resolved by appending `_01`, `_02`, … before the extension.
//!
//! The destination directory and the final delivered file path are
//! operator-facing content paths, so every filesystem operation goes through
//! [`long_path`] (Windows long-path boundary; identity elsewhere). The source
//! `pieces.bin` is an internal short path and is used as-is.

#[cfg(test)]
use std::{
    collections::HashMap,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
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
    JobToken, MetadataTransferDeliveryAttempt, MetadataTransferDeliveryAttemptPhase,
    NativeFileFingerprint,
};
use md4::{Digest, Md4};
use uuid::Uuid;

use crate::long_path::long_path;

use super::fs_durability::{
    AtomicMoveUnsupported, NoReplaceMoveOutcome, move_path_no_replace, sync_file_for_publish,
    sync_parent_directory,
};
use super::{ED2K_PART_SIZE, Ed2kTransferRuntime};

#[cfg(test)]
pub(super) const DELIVERY_PENDING_FILE_NAME: &str = "delivery.pending";
#[cfg(test)]
static DELIVERY_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Outcome of a delivery attempt for one completed transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ed2kDeliveryOutcome {
    /// The transfer is not complete yet; nothing was delivered.
    NotCompleted,
    /// Delivery was durably recorded. Later external loss never creates a new copy.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptArtifactIdentity {
    Missing,
    Owned,
    Foreign,
}

impl Ed2kTransferRuntime {
    /// Materialize a completed transfer's payload into `dest_dir` under its
    /// canonical name, recording the delivered path on the manifest so the
    /// operation is idempotent across restarts.
    ///
    /// Returns [`Ed2kDeliveryOutcome::NotCompleted`] when a download is not yet fully
    /// verified, [`Ed2kDeliveryOutcome::AlreadyDelivered`] when a previously
    /// recorded delivered file still exists, or
    /// [`Ed2kDeliveryOutcome::Delivered`] when a new file was created. The heavy
    /// link/copy runs WITHOUT the manifest IO lock held so a large cross-volume
    /// copy cannot stall other transfers' manifest checkpoints.
    pub async fn materialize_completed_payload(
        &self,
        token: JobToken,
        dest_dir: &Path,
    ) -> Result<Ed2kDeliveryOutcome> {
        let _lifecycle_guard = self.lock_lifecycle(token.job_id).await;
        let metadata = self.metadata.clone();
        let record = tokio::task::spawn_blocking(move || metadata.download_job(token.job_id))
            .await
            .context("delivery job lookup failed")??
            .context("missing delivery job")?;
        anyhow::ensure!(record.token == token, "stale delivery generation");
        let file_hash = record.file_hash.as_str();
        if record.delivery_state == emulebb_metadata::MetadataTransferDeliveryState::Pending
            && record.completed_at_s.is_none()
        {
            self.recover_delivery_attempt_unlocked(token).await?;
        }
        // Phase 1: snapshot what we need under the manifest IO lock, then
        // release it before touching the destination filesystem.
        let (
            display_name,
            expected_size,
            expected_hash,
            recorded_path,
            recorded_fingerprint,
            recorded_ownership,
        ) = {
            let _guard = self.lock_manifest(token).await;
            let manifest = self.load_manifest_unlocked(token).await?;
            if !manifest.completed || manifest.final_rehash_pending {
                return Ok(Ed2kDeliveryOutcome::NotCompleted);
            }
            let recorded_path = match manifest.delivery_state {
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
                manifest.delivery_ownership,
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
                Ok(DeliveredOutputIdentity::Matching(Some(current))) => {
                    if recorded_fingerprint.as_ref() != Some(&current) {
                        // Equal bytes prove delivery, never destructive ownership.
                        // Fence the exact snapshot before retaining the fresh
                        // verification evidence as explicitly unowned output.
                        let guard = self.lock_manifest(token).await;
                        // Busy is a safe pending retry. Do not wait for registry
                        // capacity while retaining this lifecycle/job guard.
                        let receipt = self.local_mutations.submit_delivery_verification(
                            self,
                            token,
                            &recorded_path,
                            recorded_fingerprint.as_ref(),
                            recorded_ownership,
                            &current,
                            guard,
                        )?;
                        receipt
                            .await
                            .context("delivery verification owner stopped")??;
                    }
                    return Ok(Ed2kDeliveryOutcome::AlreadyDelivered(recorded_path));
                }
                Ok(DeliveredOutputIdentity::Matching(None)) => {
                    anyhow::bail!(
                        "matching delivered bytes lack stable native verification evidence"
                    );
                }
                Ok(DeliveredOutputIdentity::Missing | DeliveredOutputIdentity::Foreign) => {
                    // Delivered is already a durable fact, even if a crash
                    // precedes terminal retirement. Later loss/replacement never
                    // authorizes another materialization for this job.
                    return Ok(Ed2kDeliveryOutcome::AlreadyDelivered(recorded_path));
                }
                Err(error) => {
                    return Err(error)
                        .context("recorded delivered output verification remains pending");
                }
            }
        }

        let source = self.payload_path(token.job_id)?;
        let installed = self
            .deliver_payload_file(
                token,
                &source,
                dest_dir,
                &display_name,
                expected_size,
                expected_hash,
            )
            .await
            .with_context(|| format!("failed to deliver completed transfer {file_hash}"))?;
        let final_path = installed.target_path.clone();
        let fingerprint = installed
            .published_fingerprint
            .as_ref()
            .context("published delivery has no fingerprint")?;
        self.commit_recovered_delivery(
            token,
            &installed,
            fingerprint,
            super::Ed2kDeliveryOwnership::Owned,
        )
        .await?;
        Ok(Ed2kDeliveryOutcome::Delivered(final_path))
    }
}

fn delivery_candidate_name(
    file_name: &str,
    stem: &str,
    extension: Option<&str>,
    ordinal: u64,
) -> String {
    if ordinal == 0 {
        return file_name.to_owned();
    }
    let mut index = ordinal;
    let mut width = 2usize;
    let mut limit = 99u64;
    while index > limit {
        index -= limit;
        width += 1;
        limit = limit.saturating_mul(10).saturating_add(9);
    }
    let suffix = format!("_{index:0width$}");
    match extension {
        Some(ext) => format!("{stem}{suffix}.{ext}"),
        None => format!("{stem}{suffix}"),
    }
}

#[derive(Debug, Clone)]
pub(super) struct OwnedDeliveryOutput {
    pub(super) path: PathBuf,
    pub(super) fingerprint: NativeFileFingerprint,
}

struct VerifiedStagingFile {
    file: File,
    fingerprint: NativeFileFingerprint,
}

struct DeliveryPayloadIdentity {
    size: u64,
    hash: [u8; 16],
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

async fn preserve_unproven_prepared_staging(
    file_hash: &str,
    attempt: &MetadataTransferDeliveryAttempt,
) -> Result<()> {
    match tokio::fs::symlink_metadata(long_path(&attempt.staging_path)).await {
        Ok(_) => {
            tracing::warn!(
                file_hash,
                path = %attempt.staging_path.display(),
                "preserving prepared delivery staging occupant without a proven identity"
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            sync_parent_directory(&attempt.staging_path).await
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect prepared delivery staging path {}",
                attempt.staging_path.display()
            )
        }),
    }
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

async fn classify_attempt_artifact(
    path: &Path,
    expected_fingerprint: &NativeFileFingerprint,
    expected_size: u64,
    expected_hash: [u8; 16],
) -> Result<AttemptArtifactIdentity> {
    match classify_delivered_output(
        path,
        Some(expected_fingerprint),
        expected_size,
        expected_hash,
    )
    .await?
    {
        DeliveredOutputIdentity::Missing => Ok(AttemptArtifactIdentity::Missing),
        DeliveredOutputIdentity::Matching(Some(current_fingerprint))
            if current_fingerprint == *expected_fingerprint =>
        {
            Ok(AttemptArtifactIdentity::Owned)
        }
        DeliveredOutputIdentity::Matching(_) | DeliveredOutputIdentity::Foreign => {
            Ok(AttemptArtifactIdentity::Foreign)
        }
    }
}

impl Ed2kTransferRuntime {
    /// Copy `source` (`pieces.bin`) into `dest_dir` under a collision-free file
    /// name. Every temporary artifact is named and owned by a durable delivery
    /// attempt before it is created.
    async fn deliver_payload_file(
        &self,
        token: JobToken,
        source: &Path,
        dest_dir: &Path,
        display_name: &str,
        expected_size: u64,
        expected_hash: [u8; 16],
    ) -> Result<MetadataTransferDeliveryAttempt> {
        validate_delivery_source(source, expected_size).await?;
        tokio::fs::create_dir_all(long_path(dest_dir))
            .await
            .with_context(|| {
                format!("failed to create delivery directory {}", dest_dir.display())
            })?;

        let file_name = sanitize_file_name(display_name);
        let (stem, extension) = split_stem_extension(&file_name);
        for ordinal in 0..=u64::MAX {
            let candidate_name =
                delivery_candidate_name(&file_name, &stem, extension.as_deref(), ordinal);
            let target_path = dest_dir.join(candidate_name);
            if path_exists(&target_path).await {
                continue;
            }
            if self.metadata.delivery_output_is_excluded(&target_path)? {
                std::fs::canonicalize(dest_dir).with_context(|| {
                    format!(
                        "failed to resolve delivery directory {}",
                        dest_dir.display()
                    )
                })?;
                continue;
            }

            let attempt_id = Uuid::new_v4();
            let staging_path = dest_dir.join(format!(".emulebb-delivery-{attempt_id}.tmp"));
            self.begin_delivery_attempt(token, attempt_id, &target_path, &staging_path)
                .await?;
            stage_delivery_payload(source, &staging_path).await?;
            let verified_staging =
                open_verified_staging_file(&staging_path, expected_size, expected_hash).await?;
            let attempt = self
                .mark_delivery_attempt_staged(token, attempt_id, &verified_staging.fingerprint)
                .await?
                .context("delivery attempt disappeared before staging committed")?;

            let installation = match install_staged_payload(&staging_path, &target_path).await {
                Ok(outcome) => outcome,
                Err(error) if error.downcast_ref::<AtomicMoveUnsupported>().is_some() => {
                    let direct = self
                        .publish_direct_copy(
                            token,
                            &attempt,
                            &staging_path,
                            &target_path,
                            verified_staging,
                            DeliveryPayloadIdentity {
                                size: expected_size,
                                hash: expected_hash,
                            },
                        )
                        .await?;
                    if let Some(published) = direct {
                        return Ok(published);
                    }
                    self.clear_delivery_attempt(token, &attempt).await?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            match installation {
                InstallOutcome::Installed => {
                    #[cfg(test)]
                    run_after_publish_move_hook(&target_path);
                    let installed_fingerprint = capture_published_fingerprint(
                        verified_staging.file,
                        &target_path,
                        expected_size,
                        expected_hash,
                    )
                    .await?;
                    return self
                        .mark_delivery_attempt_published(token, attempt_id, &installed_fingerprint)
                        .await?
                        .context("delivery attempt disappeared before publication committed");
                }
                InstallOutcome::AlreadyExists => {
                    drop(verified_staging.file);
                    if !remove_file_if_fingerprint_matches(
                        &staging_path,
                        &verified_staging.fingerprint,
                    )
                    .await?
                    {
                        tracing::warn!(
                            job_id = %token.job_id,
                            path = %staging_path.display(),
                            "preserving delivery staging path whose native identity changed"
                        );
                    }
                    anyhow::ensure!(
                        self.clear_delivery_attempt(token, &attempt).await?,
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

    async fn publish_direct_copy(
        &self,
        token: JobToken,
        attempt: &MetadataTransferDeliveryAttempt,
        staging_path: &Path,
        target_path: &Path,
        verified: VerifiedStagingFile,
        expected: DeliveryPayloadIdentity,
    ) -> Result<Option<MetadataTransferDeliveryAttempt>> {
        use tokio::io::AsyncSeekExt;
        let attempt_id = attempt.attempt_id;

        // WHY: The reservation must survive cancellation and crashes before a
        // partial final-looking file can ever be considered for sharing.
        if !self
            .metadata
            .reserve_delivery_output(token, target_path, attempt_id)?
        {
            drop(verified.file);
            remove_file_if_fingerprint_matches(staging_path, &verified.fingerprint).await?;
            return Ok(None);
        }
        let reservation = self
            .metadata
            .delivery_output_reservation(token.job_id, attempt_id)?
            .context("delivery output reservation disappeared before creation")?;
        self.refresh_complete_shared_catalog().await?;
        let mut output = match tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(long_path(target_path))
            .await
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                anyhow::ensure!(
                    self.metadata
                        .release_delivery_output(token, &reservation, attempt)?,
                    "delivery reservation changed before collision release"
                );
                drop(verified.file);
                remove_file_if_fingerprint_matches(staging_path, &verified.fingerprint).await?;
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        #[cfg(test)]
        run_after_direct_create_hook(target_path).await;
        let mut input = tokio::fs::File::from_std(verified.file);
        input.seek(std::io::SeekFrom::Start(0)).await?;
        tokio::io::copy(&mut input, &mut output).await?;
        let output = output.into_std().await;
        sync_file_for_publish(output.try_clone()?).await?;
        sync_parent_directory(target_path).await?;
        let fingerprint =
            capture_published_fingerprint(output, target_path, expected.size, expected.hash)
                .await?;
        // Keep the barrier until the published journal record is committed.
        let published = self
            .metadata
            .publish_reserved_delivery_attempt(token, attempt_id, &fingerprint)?
            .context("direct delivery reservation disappeared before publication committed")?;
        drop(input);
        remove_file_if_fingerprint_matches(staging_path, &verified.fingerprint).await?;
        Ok(Some(published))
    }

    async fn begin_delivery_attempt(
        &self,
        token: JobToken,
        attempt_id: Uuid,
        target_path: &Path,
        staging_path: &Path,
    ) -> Result<MetadataTransferDeliveryAttempt> {
        let metadata = self.metadata.clone();
        let target_path = target_path.to_owned();
        let staging_path = staging_path.to_owned();
        tokio::task::spawn_blocking(move || {
            metadata.begin_transfer_delivery_attempt(token, attempt_id, &target_path, &staging_path)
        })
        .await
        .context("ED2K delivery-attempt prepare task panicked")?
    }

    async fn mark_delivery_attempt_staged(
        &self,
        token: JobToken,
        attempt_id: Uuid,
        staging_fingerprint: &NativeFileFingerprint,
    ) -> Result<Option<MetadataTransferDeliveryAttempt>> {
        let metadata = self.metadata.clone();
        let staging_fingerprint = staging_fingerprint.clone();
        tokio::task::spawn_blocking(move || {
            metadata.mark_transfer_delivery_attempt_staged(token, attempt_id, &staging_fingerprint)
        })
        .await
        .context("ED2K delivery-attempt stage task panicked")?
    }

    async fn mark_delivery_attempt_published(
        &self,
        token: JobToken,
        attempt_id: Uuid,
        published_fingerprint: &NativeFileFingerprint,
    ) -> Result<Option<MetadataTransferDeliveryAttempt>> {
        let metadata = self.metadata.clone();
        let published_fingerprint = published_fingerprint.clone();
        tokio::task::spawn_blocking(move || {
            metadata.mark_transfer_delivery_attempt_published(
                token,
                attempt_id,
                &published_fingerprint,
            )
        })
        .await
        .context("ED2K delivery-attempt publish task panicked")?
    }

    async fn clear_delivery_attempt(
        &self,
        token: JobToken,
        expected: &MetadataTransferDeliveryAttempt,
    ) -> Result<bool> {
        let metadata = self.metadata.clone();
        let expected = expected.clone();
        tokio::task::spawn_blocking(move || {
            metadata.settle_recovered_delivery_attempt(token, &expected)
        })
        .await
        .context("ED2K delivery-attempt cleanup task panicked")?
    }

    pub(super) async fn delivery_attempt(
        &self,
        token: JobToken,
    ) -> Result<Option<MetadataTransferDeliveryAttempt>> {
        let metadata = self.metadata.clone();
        tokio::task::spawn_blocking(move || metadata.download_job_delivery_attempt(token.job_id))
            .await
            .context("ED2K delivery-attempt load task panicked")?
    }

    pub(super) async fn recover_delivery_attempt_unlocked(&self, token: JobToken) -> Result<()> {
        let Some(attempt) = self.delivery_attempt(token).await? else {
            return Ok(());
        };
        validate_delivery_attempt_paths(&attempt)?;
        if self
            .metadata
            .has_delivery_reservation(token.job_id, attempt.attempt_id)?
        {
            // WHY: A crash may have interrupted direct creation or copying.
            // Preserve both artifacts; their identity cannot be proven here.
            anyhow::bail!(
                "direct delivery reservation remains pending for job {:?}",
                token.job_id
            );
        }
        let manifest = {
            let _manifest_guard = self.lock_manifest(token).await;
            self.load_manifest_unlocked(token).await?
        };
        if manifest.delivery_state == super::Ed2kDeliveryState::Delivered {
            self.clear_delivery_attempt(token, &attempt).await?;
            return Ok(());
        }
        if manifest.delivery_state != super::Ed2kDeliveryState::Pending
            || !manifest.completed
            || manifest.final_rehash_pending
        {
            self.clear_delivery_attempt(token, &attempt).await?;
            return Ok(());
        }
        if attempt.phase == MetadataTransferDeliveryAttemptPhase::Prepared {
            preserve_unproven_prepared_staging(&manifest.file_hash, &attempt).await?;
            self.clear_delivery_attempt(token, &attempt).await?;
            return Ok(());
        }

        let expected_hash = Ed2kHash::from_str(&manifest.file_hash)
            .with_context(|| format!("invalid ED2K file hash {}", manifest.file_hash))?
            .0;
        let staging_fingerprint = attempt.staging_fingerprint.as_ref().with_context(|| {
            format!(
                "delivery attempt {} has no verified staging identity",
                attempt.attempt_id
            )
        })?;
        if attempt.phase == MetadataTransferDeliveryAttemptPhase::Published {
            let published_fingerprint =
                attempt.published_fingerprint.as_ref().with_context(|| {
                    format!(
                        "published delivery attempt {} has no published identity",
                        attempt.attempt_id
                    )
                })?;
            match classify_attempt_artifact(
                &attempt.target_path,
                published_fingerprint,
                manifest.file_size,
                expected_hash,
            )
            .await?
            {
                AttemptArtifactIdentity::Owned => {
                    return self
                        .commit_recovered_delivery(
                            token,
                            &attempt,
                            published_fingerprint,
                            super::Ed2kDeliveryOwnership::Owned,
                        )
                        .await;
                }
                AttemptArtifactIdentity::Missing => {
                    sync_parent_directory(&attempt.target_path).await?;
                }
                AttemptArtifactIdentity::Foreign => {
                    tracing::warn!(
                        job_id = %token.job_id,
                        path = %attempt.target_path.display(),
                        "preserving delivery target whose identity changed after publication"
                    );
                }
            }
            self.clear_delivery_attempt(token, &attempt).await?;
            return Ok(());
        }

        match classify_attempt_artifact(
            &attempt.staging_path,
            staging_fingerprint,
            manifest.file_size,
            expected_hash,
        )
        .await?
        {
            AttemptArtifactIdentity::Owned => {
                let verified_staging = open_verified_staging_file(
                    &attempt.staging_path,
                    manifest.file_size,
                    expected_hash,
                )
                .await?;
                anyhow::ensure!(
                    verified_staging.fingerprint == *staging_fingerprint,
                    "delivery staging identity changed for attempt {}",
                    attempt.attempt_id
                );
                let installation =
                    match install_staged_payload(&attempt.staging_path, &attempt.target_path).await
                    {
                        Ok(outcome) => outcome,
                        Err(error) if error.downcast_ref::<AtomicMoveUnsupported>().is_some() => {
                            if let Some(published) = self
                                .publish_direct_copy(
                                    token,
                                    &attempt,
                                    &attempt.staging_path,
                                    &attempt.target_path,
                                    verified_staging,
                                    DeliveryPayloadIdentity {
                                        size: manifest.file_size,
                                        hash: expected_hash,
                                    },
                                )
                                .await?
                            {
                                return self
                                    .commit_recovered_delivery(
                                        token,
                                        &published,
                                        published
                                            .published_fingerprint
                                            .as_ref()
                                            .context("published attempt lacks fingerprint")?,
                                        super::Ed2kDeliveryOwnership::Owned,
                                    )
                                    .await;
                            }
                            self.clear_delivery_attempt(token, &attempt).await?;
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    };
                match installation {
                    InstallOutcome::Installed => {
                        #[cfg(test)]
                        run_after_publish_move_hook(&attempt.target_path);
                        let published_fingerprint = capture_published_fingerprint(
                            verified_staging.file,
                            &attempt.target_path,
                            manifest.file_size,
                            expected_hash,
                        )
                        .await?;
                        let published = self
                            .mark_delivery_attempt_published(
                                token,
                                attempt.attempt_id,
                                &published_fingerprint,
                            )
                            .await?
                            .context("delivery attempt disappeared before publication committed")?;
                        return self
                            .commit_recovered_delivery(
                                token,
                                &published,
                                &published_fingerprint,
                                super::Ed2kDeliveryOwnership::Owned,
                            )
                            .await;
                    }
                    InstallOutcome::AlreadyExists => {
                        drop(verified_staging.file);
                        if !remove_file_if_fingerprint_matches(
                            &attempt.staging_path,
                            staging_fingerprint,
                        )
                        .await?
                        {
                            tracing::warn!(
                                job_id = %token.job_id,
                                path = %attempt.staging_path.display(),
                                "preserving delivery staging path whose native identity changed"
                            );
                        }
                        self.clear_delivery_attempt(token, &attempt).await?;
                        Ok(())
                    }
                }
            }
            AttemptArtifactIdentity::Missing => {
                sync_parent_directory(&attempt.staging_path).await?;
                match classify_delivered_output(
                    &attempt.target_path,
                    None,
                    manifest.file_size,
                    expected_hash,
                )
                .await?
                {
                    DeliveredOutputIdentity::Matching(Some(current_fingerprint)) => {
                        return self
                            .commit_recovered_delivery(
                                token,
                                &attempt,
                                &current_fingerprint,
                                super::Ed2kDeliveryOwnership::Unowned,
                            )
                            .await;
                    }
                    DeliveredOutputIdentity::Missing => {
                        sync_parent_directory(&attempt.target_path).await?;
                    }
                    DeliveredOutputIdentity::Matching(None) | DeliveredOutputIdentity::Foreign => {
                        tracing::warn!(
                            job_id = %token.job_id,
                            path = %attempt.target_path.display(),
                            "preserving ambiguous delivery target after interrupted publication"
                        );
                    }
                }
                self.clear_delivery_attempt(token, &attempt).await?;
                Ok(())
            }
            AttemptArtifactIdentity::Foreign => {
                tracing::warn!(
                    job_id = %token.job_id,
                    path = %attempt.staging_path.display(),
                    "preserving delivery staging path whose native identity changed"
                );
                self.clear_delivery_attempt(token, &attempt).await?;
                Ok(())
            }
        }
    }

    async fn commit_recovered_delivery(
        &self,
        token: JobToken,
        attempt: &MetadataTransferDeliveryAttempt,
        fingerprint: &NativeFileFingerprint,
        ownership: super::Ed2kDeliveryOwnership,
    ) -> Result<()> {
        let _manifest_guard = self.lock_manifest(token).await;
        let mut manifest = self.load_manifest_unlocked(token).await?.edit()?;
        anyhow::ensure!(
            manifest.delivery_state == super::Ed2kDeliveryState::Pending
                && manifest.completed
                && !manifest.final_rehash_pending,
            "job {token:?} changed while recovering delivery attempt {}",
            attempt.attempt_id
        );
        manifest.delivery_state = super::Ed2kDeliveryState::Delivered;
        manifest.delivery_ownership = ownership;
        manifest.delivered_path = Some(attempt.target_path.clone());
        manifest.source_fingerprint = Some(fingerprint.clone());
        self.store_manifest_unlocked(&manifest).await
    }

    pub(super) async fn discard_delivery_attempt_for_deletion_unlocked(
        &self,
        token: JobToken,
        manifest: &super::Ed2kResumeManifest,
    ) -> Result<Option<OwnedDeliveryOutput>> {
        let Some(attempt) = self.delivery_attempt(token).await? else {
            return Ok(None);
        };
        validate_delivery_attempt_paths(&attempt)?;
        if attempt.phase == MetadataTransferDeliveryAttemptPhase::Prepared {
            preserve_unproven_prepared_staging(&manifest.file_hash, &attempt).await?;
            self.clear_delivery_attempt(token, &attempt).await?;
            return Ok(None);
        }

        let expected_hash = Ed2kHash::from_str(&manifest.file_hash)
            .with_context(|| format!("invalid ED2K file hash {}", manifest.file_hash))?
            .0;
        let staging_fingerprint = attempt.staging_fingerprint.as_ref().with_context(|| {
            format!(
                "staged delivery attempt {} has no verified staging identity",
                attempt.attempt_id
            )
        })?;
        match classify_attempt_artifact(
            &attempt.staging_path,
            staging_fingerprint,
            manifest.file_size,
            expected_hash,
        )
        .await?
        {
            AttemptArtifactIdentity::Owned => {
                if !remove_file_if_fingerprint_matches(&attempt.staging_path, staging_fingerprint)
                    .await?
                {
                    tracing::warn!(
                        job_id = %token.job_id,
                        path = %attempt.staging_path.display(),
                        "preserving delivery staging artifact whose identity changed before deletion"
                    );
                }
            }
            AttemptArtifactIdentity::Missing => {
                sync_parent_directory(&attempt.staging_path).await?;
            }
            AttemptArtifactIdentity::Foreign => {
                tracing::warn!(
                    job_id = %token.job_id,
                    path = %attempt.staging_path.display(),
                    "preserving delivery staging artifact without matching persisted native identity"
                );
            }
        }
        if attempt.phase == MetadataTransferDeliveryAttemptPhase::Published {
            let published_fingerprint =
                attempt.published_fingerprint.as_ref().with_context(|| {
                    format!(
                        "published delivery attempt {} has no published identity",
                        attempt.attempt_id
                    )
                })?;
            return Ok(Some(OwnedDeliveryOutput {
                path: attempt.target_path,
                fingerprint: published_fingerprint.clone(),
            }));
        }
        self.clear_delivery_attempt(token, &attempt).await?;
        Ok(None)
    }
}

#[cfg(test)]
type DirectCreateHook = (
    tokio::sync::oneshot::Sender<()>,
    std::sync::Arc<tokio::sync::Notify>,
);

#[cfg(test)]
fn direct_create_hooks()
-> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, DirectCreateHook>> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, DirectCreateHook>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(Default::default)
}

#[cfg(test)]
pub(super) fn pause_after_direct_create(path: &Path) -> tokio::sync::oneshot::Receiver<()> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    direct_create_hooks().lock().unwrap().insert(
        path.to_owned(),
        (sender, std::sync::Arc::new(tokio::sync::Notify::new())),
    );
    receiver
}

#[cfg(test)]
async fn run_after_direct_create_hook(path: &Path) {
    let hook = direct_create_hooks().lock().unwrap().remove(path);
    if let Some((sender, gate)) = hook {
        let _ = sender.send(());
        gate.notified().await;
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
    for index in 0..=u64::MAX {
        let candidate_name =
            delivery_candidate_name(&file_name, &stem, extension.as_deref(), index);
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

async fn open_verified_staging_file(
    path: &Path,
    expected_size: u64,
    expected_hash: [u8; 16],
) -> Result<VerifiedStagingFile> {
    let path = long_path(path);
    tokio::task::spawn_blocking(move || -> Result<VerifiedStagingFile> {
        let mut file = open_staging_file_without_follow(&path)
            .with_context(|| format!("failed to open delivery staging file {}", path.display()))?;
        let opened_metadata = file.metadata()?;
        let opened_fingerprint =
            super::ingest::native_file_fingerprint_from_handle(&file, &opened_metadata)
                .with_context(|| {
                    format!(
                        "delivery staging file has no stable native identity: {}",
                        path.display()
                    )
                })?;
        anyhow::ensure!(
            opened_fingerprint.size_bytes == expected_size,
            "delivery staging file size changed at {}",
            path.display()
        );
        anyhow::ensure!(
            compute_ed2k_hash_from_handle(&mut file, expected_size)? == expected_hash,
            "delivery staging file failed verification: {}",
            path.display()
        );
        let verified_metadata = file.metadata()?;
        let verified_fingerprint =
            super::ingest::native_file_fingerprint_from_handle(&file, &verified_metadata)
                .with_context(|| {
                    format!(
                        "delivery staging file lost its native identity: {}",
                        path.display()
                    )
                })?;
        anyhow::ensure!(
            opened_fingerprint == verified_fingerprint,
            "delivery staging file changed during verification: {}",
            path.display()
        );
        anyhow::ensure!(
            super::ingest::native_file_fingerprint(&path).as_ref() == Some(&verified_fingerprint),
            "delivery staging path changed during verification: {}",
            path.display()
        );
        Ok(VerifiedStagingFile {
            file,
            fingerprint: verified_fingerprint,
        })
    })
    .await
    .context("delivery staging verification task failed")?
}

async fn capture_published_fingerprint(
    mut file: File,
    target_path: &Path,
    expected_size: u64,
    expected_hash: [u8; 16],
) -> Result<NativeFileFingerprint> {
    let target_path = long_path(target_path);
    tokio::task::spawn_blocking(move || -> Result<NativeFileFingerprint> {
        let metadata = file.metadata()?;
        let fingerprint = super::ingest::native_file_fingerprint_from_handle(&file, &metadata)
            .with_context(|| {
                format!(
                    "published delivery has no stable native identity: {}",
                    target_path.display()
                )
            })?;
        anyhow::ensure!(
            fingerprint.size_bytes == expected_size,
            "published delivery size changed at {}",
            target_path.display()
        );
        anyhow::ensure!(
            compute_ed2k_hash_from_handle(&mut file, expected_size)? == expected_hash,
            "published delivery failed verification: {}",
            target_path.display()
        );
        let verified_metadata = file.metadata()?;
        let verified_fingerprint =
            super::ingest::native_file_fingerprint_from_handle(&file, &verified_metadata)
                .with_context(|| {
                    format!(
                        "published delivery lost its stable native identity: {}",
                        target_path.display()
                    )
                })?;
        anyhow::ensure!(
            fingerprint == verified_fingerprint,
            "published delivery changed during verification: {}",
            target_path.display()
        );
        anyhow::ensure!(
            super::ingest::native_file_fingerprint(&target_path).as_ref()
                == Some(&verified_fingerprint),
            "published delivery path does not identify the staged object: {}",
            target_path.display()
        );
        Ok(verified_fingerprint)
    })
    .await
    .context("delivery publication fingerprint task failed")?
}

#[cfg(test)]
type AfterPublishMoveHook = Box<dyn FnOnce(&Path) + Send>;

#[cfg(test)]
fn after_publish_move_hooks() -> &'static Mutex<HashMap<PathBuf, AfterPublishMoveHook>> {
    static HOOKS: OnceLock<Mutex<HashMap<PathBuf, AfterPublishMoveHook>>> = OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
pub(super) fn set_after_publish_move_hook(target_path: &Path, hook: AfterPublishMoveHook) {
    after_publish_move_hooks()
        .lock()
        .expect("delivery after-publish-move hook mutex poisoned")
        .insert(long_path(target_path), hook);
}

#[cfg(test)]
fn run_after_publish_move_hook(target_path: &Path) {
    let hook = after_publish_move_hooks()
        .lock()
        .expect("delivery after-publish-move hook mutex poisoned")
        .remove(&long_path(target_path));
    if let Some(hook) = hook {
        hook(target_path);
    }
}

#[cfg(windows)]
fn open_staging_file_without_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    };

    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
fn open_staging_file_without_follow(path: &Path) -> std::io::Result<File> {
    super::ingest::open_regular_file_without_follow(path)
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
    sync_file_for_publish(output.into_std().await).await?;
    sync_parent_directory(staging_path).await?;
    Ok(())
}

/// Publish a staged file without replacing a pre-existing destination. The
/// platform move is atomic within the shared parent directory and preserves the
/// staged object's native identity at the final path.
async fn install_staged_payload(staging_path: &Path, target_path: &Path) -> Result<InstallOutcome> {
    match move_path_no_replace(staging_path, target_path)
        .await
        .with_context(|| {
            format!(
                "failed to install delivery staging file {} at {}",
                staging_path.display(),
                target_path.display()
            )
        })? {
        NoReplaceMoveOutcome::Moved => Ok(InstallOutcome::Installed),
        NoReplaceMoveOutcome::AlreadyExists => Ok(InstallOutcome::AlreadyExists),
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

pub(super) fn remove_file_if_fingerprint_matches_retained(
    path: &Path,
    expected_fingerprint: &NativeFileFingerprint,
) -> Result<bool> {
    let owned_path = long_path(path);
    let removed = (|| -> Result<bool> {
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
        if *expected_fingerprint != current_fingerprint {
            return Ok(false);
        }
        #[cfg(test)]
        run_before_fingerprint_remove_hook(&owned_path)?;
        let metadata = match owned_path.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file()
            || super::ingest::native_file_fingerprint(&owned_path).as_ref()
                != Some(expected_fingerprint)
        {
            return Ok(false);
        }
        match std::fs::remove_file(&owned_path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.into()),
        }
    })()?;
    if removed {
        super::fs_durability::sync_parent_directory_retained(path)?;
    }
    Ok(removed)
}

pub(super) async fn remove_file_if_fingerprint_matches(
    path: &Path,
    expected: &NativeFileFingerprint,
) -> Result<bool> {
    let path = path.to_owned();
    let expected = expected.clone();
    tokio::task::spawn_blocking(move || {
        remove_file_if_fingerprint_matches_retained(&path, &expected)
    })
    .await
    .context("delivery target cleanup task panicked")?
}

#[cfg(test)]
type BeforeFingerprintRemoveHook = Box<dyn FnOnce(&Path) -> std::io::Result<()> + Send>;

#[cfg(test)]
fn before_fingerprint_remove_hooks() -> &'static Mutex<HashMap<PathBuf, BeforeFingerprintRemoveHook>>
{
    static HOOKS: OnceLock<Mutex<HashMap<PathBuf, BeforeFingerprintRemoveHook>>> = OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
pub(super) fn set_before_fingerprint_remove_hook(path: &Path, hook: BeforeFingerprintRemoveHook) {
    before_fingerprint_remove_hooks()
        .lock()
        .expect("delivery before-fingerprint-remove hook mutex poisoned")
        .insert(long_path(path), hook);
}

#[cfg(test)]
fn run_before_fingerprint_remove_hook(path: &Path) -> std::io::Result<()> {
    let hook = before_fingerprint_remove_hooks()
        .lock()
        .expect("delivery before-fingerprint-remove hook mutex poisoned")
        .remove(path);
    if let Some(hook) = hook {
        hook(path)?;
    }
    Ok(())
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
    Ok(Some(compute_ed2k_hash_from_handle(
        &mut file,
        expected_size,
    )?))
}

pub(super) fn compute_ed2k_hash_from_handle(
    file: &mut File,
    expected_size: u64,
) -> Result<[u8; 16]> {
    file.seek(SeekFrom::Start(0))?;
    let part_count = expected_size.div_ceil(ED2K_PART_SIZE);
    let mut composite = Md4::new();
    let mut first_part = None;
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
        let digest = <[u8; 16]>::from(hasher.finalize());
        first_part.get_or_insert(digest);
        composite.update(digest);
        remaining = remaining.saturating_sub(ED2K_PART_SIZE);
    }
    if expected_size == 0 {
        return Ok(Md4::new().finalize().into());
    }
    if expected_size < ED2K_PART_SIZE {
        return first_part.context("single-part ED2K hash was not produced");
    }
    if expected_size.is_multiple_of(ED2K_PART_SIZE) {
        composite.update(<[u8; 16]>::from(Md4::new().finalize()));
    }
    Ok(composite.finalize().into())
}

async fn path_exists(path: &Path) -> bool {
    tokio::fs::metadata(long_path(path)).await.is_ok()
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
    #[test]
    fn collision_suffixes_widen_after_each_full_group() {
        use super::delivery_candidate_name;
        let name = |n| delivery_candidate_name("abc.mp3", "abc", Some("mp3"), n);
        assert_eq!(name(0), "abc.mp3");
        assert_eq!(name(1), "abc_01.mp3");
        assert_eq!(name(99), "abc_99.mp3");
        assert_eq!(name(100), "abc_001.mp3");
        assert_eq!(name(1098), "abc_999.mp3");
        assert_eq!(name(1099), "abc_0001.mp3");
    }
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

        assert_eq!(delivered, dest.join("clip_01.mkv"));
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
    async fn hash_verification_failure_prevents_target_publication() {
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
            format!("{error:#}").contains("delivered file failed verification"),
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

        assert_eq!(delivered, dest.join("recovered_01.bin"));
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
