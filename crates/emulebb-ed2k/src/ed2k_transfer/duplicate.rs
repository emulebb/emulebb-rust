use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Context, Result, ensure};
use emulebb_metadata::NativeFileFingerprint;

use super::{Ed2kResumeManifest, Ed2kTransferJob, Ed2kTransferRuntime};

pub(super) struct PresentSharedSource {
    pub(super) path: PathBuf,
    pub(super) fingerprint: NativeFileFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kActiveTransferEvidence {
    pub display_name: String,
    pub file_size: u64,
    pub final_rehash_pending: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed2kCurrentLocalFileKind {
    Shared,
    Delivered,
    ManagedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kCurrentLocalFileEvidence {
    pub display_name: String,
    pub file_size: u64,
    pub path: String,
    pub kind: Ed2kCurrentLocalFileKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kPreviouslyCompletedEvidence {
    pub display_name: String,
    pub file_size: u64,
    pub aich_root: Option<String>,
    pub first_completed_at_ms: i64,
    pub last_completed_at_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ed2kDownloadEvidence {
    pub active_transfer: Option<Ed2kActiveTransferEvidence>,
    pub current_local_files: Vec<Ed2kCurrentLocalFileEvidence>,
    pub previously_completed: Option<Ed2kPreviouslyCompletedEvidence>,
}

impl Ed2kDownloadEvidence {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.active_transfer.is_none()
            && self.current_local_files.is_empty()
            && self.previously_completed.is_none()
    }
}

impl Ed2kTransferRuntime {
    pub async fn download_evidence(&self, file_hash: &str) -> Result<Ed2kDownloadEvidence> {
        let file_hash = file_hash
            .parse::<emulebb_kad_proto::Ed2kHash>()?
            .to_string();
        let _guard = self.lock_manifest(&file_hash).await;
        let manifest = self.load_manifest_optional_unlocked(&file_hash).await?;
        let metadata = self.metadata.clone();
        let evidence_hash = file_hash.clone();
        let (shared_files, history) = tokio::task::spawn_blocking(move || {
            Ok::<_, anyhow::Error>((
                metadata.current_shared_files_by_hash(&evidence_hash)?,
                metadata.download_history_by_hash(&evidence_hash)?,
            ))
        })
        .await
        .context("ED2K duplicate evidence query task panicked")??;

        let active_transfer = manifest
            .as_ref()
            .filter(|manifest| !manifest.completed || manifest.final_rehash_pending)
            .map(|manifest| Ed2kActiveTransferEvidence {
                display_name: manifest.display_name.clone(),
                file_size: manifest.file_size,
                final_rehash_pending: manifest.final_rehash_pending,
            });

        let mut current_local_files = Vec::new();
        let mut seen_paths = BTreeSet::new();
        for shared_file in shared_files {
            push_current_file_if_present(
                &mut current_local_files,
                &mut seen_paths,
                shared_file.display_name,
                shared_file.file_size,
                shared_file.source_path,
                Ed2kCurrentLocalFileKind::Shared,
            )
            .await?;
        }
        if let Some(manifest) = manifest.as_ref().filter(|manifest| manifest.completed) {
            if let Some(source_path) = manifest.source_path.as_deref() {
                push_current_file_if_present(
                    &mut current_local_files,
                    &mut seen_paths,
                    manifest.display_name.clone(),
                    manifest.file_size,
                    PathBuf::from(source_path),
                    Ed2kCurrentLocalFileKind::Shared,
                )
                .await?;
            }
            if let Some(delivered_path) = manifest.delivered_path.as_deref() {
                push_current_file_if_present(
                    &mut current_local_files,
                    &mut seen_paths,
                    manifest.display_name.clone(),
                    manifest.file_size,
                    PathBuf::from(delivered_path),
                    Ed2kCurrentLocalFileKind::Delivered,
                )
                .await?;
            }
            if manifest.source_path.is_none() {
                push_current_file_if_present(
                    &mut current_local_files,
                    &mut seen_paths,
                    manifest.display_name.clone(),
                    manifest.file_size,
                    self.payload_path(&file_hash),
                    Ed2kCurrentLocalFileKind::ManagedPayload,
                )
                .await?;
            }
        }

        Ok(Ed2kDownloadEvidence {
            active_transfer,
            current_local_files,
            previously_completed: history.map(|entry| Ed2kPreviouslyCompletedEvidence {
                display_name: entry.display_name,
                file_size: entry.file_size,
                aich_root: entry.aich_root,
                first_completed_at_ms: entry.first_completed_at_ms,
                last_completed_at_ms: entry.last_completed_at_ms,
            }),
        })
    }

    pub async fn replace_with_download_job(
        &self,
        job: &Ed2kTransferJob,
    ) -> Result<Ed2kResumeManifest> {
        let file_hash = job
            .file_hash
            .parse::<emulebb_kad_proto::Ed2kHash>()?
            .to_string();
        ensure!(
            file_hash == job.file_hash,
            "ED2K transfer job hash is not canonical"
        );
        let _lifecycle_guard = self.lock_lifecycle(&file_hash).await;
        ensure!(
            !self.transfer_deletion_requested(&file_hash).await?,
            "cannot replace ED2K transfer {file_hash} while destructive deletion is pending"
        );
        let _guard = self.lock_manifest(&file_hash).await;
        let existing = self.load_manifest_optional_unlocked(&file_hash).await?;
        if let Some(existing) = existing.as_ref() {
            ensure!(
                existing.completed && !existing.final_rehash_pending,
                "cannot replace active ED2K transfer {file_hash}"
            );
            ensure!(
                existing.file_size == job.file_size,
                "cannot replace ED2K identity {file_hash} with size {} instead of {}",
                job.file_size,
                existing.file_size
            );
        }

        let shared_source = self.first_present_shared_source(&file_hash).await?;
        self.invalidate_payload_handle(&file_hash);
        let transfer_dir = self.transfer_dir(&file_hash);
        if tokio::fs::try_exists(&transfer_dir).await? {
            tokio::fs::remove_dir_all(&transfer_dir)
                .await
                .with_context(|| {
                    format!(
                        "failed to reset ED2K transfer directory {}",
                        transfer_dir.display()
                    )
                })?;
        }

        let mut replacement = Ed2kResumeManifest::new(job);
        if let Some(existing) = existing {
            replacement.md4_hashset_acquired = existing.md4_hashset_acquired;
            replacement.md4_hashset = existing.md4_hashset;
            replacement.aich_hashset_acquired = existing.aich_hashset_acquired;
            replacement.aich_root = existing.aich_root;
            replacement.aich_hashset = existing.aich_hashset;
            replacement.upload_priority = existing.upload_priority;
            replacement.auto_upload_priority = existing.auto_upload_priority;
            replacement.comment = existing.comment;
            replacement.rating = existing.rating;
            replacement.category_id = existing.category_id;
        }
        self.store_manifest_unlocked(&replacement).await?;
        if shared_source.is_none() {
            self.remove_verified_catalog_entry(&file_hash).await;
        }
        Ok(replacement)
    }

    pub(super) async fn first_present_shared_source(
        &self,
        file_hash: &str,
    ) -> Result<Option<PresentSharedSource>> {
        let metadata = self.metadata.clone();
        let file_hash = file_hash.to_string();
        let shared_files =
            tokio::task::spawn_blocking(move || metadata.current_shared_files_by_hash(&file_hash))
                .await
                .context("ED2K shared-source evidence query task panicked")??;
        for shared_file in shared_files {
            let Some(expected_fingerprint) = shared_file.source_fingerprint else {
                continue;
            };
            let path = crate::long_path::long_path(&shared_file.source_path);
            let probe_path = path.clone();
            let current_fingerprint = tokio::task::spawn_blocking(move || {
                super::ingest::native_file_fingerprint(&probe_path)
            })
            .await
            .context("ED2K shared-source fingerprint task panicked")?;
            if expected_fingerprint.size_bytes == shared_file.file_size
                && current_fingerprint
                    .as_ref()
                    .is_some_and(|current| expected_fingerprint.safely_matches(current))
            {
                return Ok(Some(PresentSharedSource {
                    path,
                    fingerprint: expected_fingerprint,
                }));
            }
        }
        Ok(None)
    }
}

async fn push_current_file_if_present(
    evidence: &mut Vec<Ed2kCurrentLocalFileEvidence>,
    seen_paths: &mut BTreeSet<PathBuf>,
    display_name: String,
    file_size: u64,
    path: PathBuf,
    kind: Ed2kCurrentLocalFileKind,
) -> Result<()> {
    if !seen_paths.insert(path.clone()) {
        return Ok(());
    }
    let Ok(metadata) = tokio::fs::metadata(&path).await else {
        return Ok(());
    };
    if !metadata.is_file() || metadata.len() != file_size {
        return Ok(());
    }
    evidence.push(Ed2kCurrentLocalFileEvidence {
        display_name,
        file_size,
        path: path.to_string_lossy().into_owned(),
        kind,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use emulebb_kad_proto::Ed2kHash;
    use tempfile::tempdir;

    use super::*;
    use crate::ed2k_transfer::{Ed2kSharedRange, Ed2kTransferState, new_transfer_job};

    #[tokio::test]
    async fn classifies_absent_active_and_current_shared_identity() {
        let root = tempdir().unwrap();
        let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let absent_hash = Ed2kHash([0x11; 16]).to_string();
        assert!(
            runtime
                .download_evidence(&absent_hash)
                .await
                .unwrap()
                .is_empty()
        );

        let active_hash = Ed2kHash([0x22; 16]);
        runtime
            .ensure_job(&new_transfer_job(active_hash, "active.bin".to_string(), 8))
            .await
            .unwrap();
        let active = runtime
            .download_evidence(&active_hash.to_string())
            .await
            .unwrap();
        assert_eq!(
            active.active_transfer,
            Some(Ed2kActiveTransferEvidence {
                display_name: "active.bin".to_string(),
                file_size: 8,
                final_rehash_pending: false,
            })
        );
        assert!(active.current_local_files.is_empty());
        assert!(active.previously_completed.is_none());

        let shared_path = root.path().join("shared.bin");
        fs::write(&shared_path, b"shared payload").unwrap();
        let shared = runtime
            .ingest_local_file(&shared_path, "shared.bin")
            .await
            .unwrap();
        let shared_evidence = runtime.download_evidence(&shared.file_hash).await.unwrap();
        assert!(shared_evidence.active_transfer.is_none());
        assert_eq!(shared_evidence.current_local_files.len(), 1);
        assert_eq!(
            shared_evidence.current_local_files[0].kind,
            Ed2kCurrentLocalFileKind::Shared
        );
        assert!(shared_evidence.previously_completed.is_none());

        fs::remove_file(shared_path).unwrap();
        assert!(
            runtime
                .download_evidence(&shared.file_hash)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn completion_history_survives_restart_and_payload_removal() {
        let root = tempdir().unwrap();
        let file_hash = Ed2kHash([0x33; 16]);
        let hash = file_hash.to_string();
        let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        runtime
            .ensure_job(&new_transfer_job(file_hash, "download.bin".to_string(), 8))
            .await
            .unwrap();
        fs::write(runtime.payload_path(&hash), b"download").unwrap();
        {
            let _guard = runtime.lock_manifest(&hash).await;
            let mut manifest = runtime.load_manifest_unlocked(&hash).await.unwrap();
            manifest.completed = true;
            manifest.verified_ranges = vec![Ed2kSharedRange { start: 0, end: 8 }];
            manifest.pieces[0].state = Ed2kTransferState::Verified;
            manifest.pieces[0].bytes_written = 8;
            runtime.store_manifest_unlocked(&manifest).await.unwrap();
        }

        let completed = runtime.download_evidence(&hash).await.unwrap();
        assert_eq!(completed.current_local_files.len(), 1);
        assert_eq!(
            completed.current_local_files[0].kind,
            Ed2kCurrentLocalFileKind::ManagedPayload
        );
        assert!(completed.previously_completed.is_some());
        drop(runtime);

        let restarted = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let after_restart = restarted.download_evidence(&hash).await.unwrap();
        assert_eq!(after_restart.current_local_files.len(), 1);
        assert!(after_restart.previously_completed.is_some());

        assert!(restarted.delete_transfer_files(&hash).await.unwrap());
        let after_removal = restarted.download_evidence(&hash).await.unwrap();
        assert!(after_removal.active_transfer.is_none());
        assert!(after_removal.current_local_files.is_empty());
        assert_eq!(
            after_removal.previously_completed.unwrap().display_name,
            "download.bin"
        );
    }

    #[tokio::test]
    async fn pending_deletion_rejects_job_recreation_and_replacement() {
        let root = tempdir().unwrap();
        let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let file_hash = Ed2kHash([0x44; 16]);
        let hash = file_hash.to_string();
        let job = new_transfer_job(file_hash, "pending-delete.bin".to_string(), 8);
        runtime.ensure_job(&job).await.unwrap();
        assert!(
            runtime
                .metadata
                .request_transfer_deletion(&hash, None)
                .unwrap()
        );

        let ensure_error = runtime.ensure_job(&job).await.unwrap_err();
        assert!(
            ensure_error
                .to_string()
                .contains("destructive deletion is pending")
        );

        let replacement_error = runtime.replace_with_download_job(&job).await.unwrap_err();
        assert!(
            replacement_error
                .to_string()
                .contains("destructive deletion is pending")
        );
    }

    #[tokio::test]
    async fn explicit_redownload_preserves_current_share_across_restart() {
        let root = tempdir().unwrap();
        let shared_path = root.path().join("shared-redownload.bin");
        let payload = b"shared redownload payload";
        fs::write(&shared_path, payload).unwrap();
        let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let shared = runtime
            .ingest_local_file(&shared_path, "shared-redownload.bin")
            .await
            .unwrap();
        let file_hash = shared.file_hash.parse::<Ed2kHash>().unwrap();

        let replacement = runtime
            .replace_with_download_job(&new_transfer_job(
                file_hash,
                "fresh-download.bin".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();
        assert!(!replacement.completed);
        assert!(replacement.source_path.is_none());
        let evidence = runtime.download_evidence(&shared.file_hash).await.unwrap();
        assert!(evidence.active_transfer.is_some());
        assert_eq!(evidence.current_local_files.len(), 1);
        assert_eq!(
            runtime
                .read_verified_range(&shared.file_hash.parse().unwrap(), 0, payload.len() as u64,)
                .await
                .unwrap()
                .unwrap(),
            payload
        );
        drop(runtime);

        let restarted = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let restarted_evidence = restarted
            .download_evidence(&shared.file_hash)
            .await
            .unwrap();
        assert!(restarted_evidence.active_transfer.is_some());
        assert_eq!(restarted_evidence.current_local_files.len(), 1);
        assert!(
            restarted
                .shared_catalog()
                .read()
                .await
                .iter()
                .any(|entry| entry.file_hash == shared.file_hash && entry.verified_complete)
        );
    }

    #[tokio::test]
    async fn completed_redownload_serves_canonical_payload_before_shared_duplicate() {
        let root = tempdir().unwrap();
        let shared_path = root.path().join("shared-then-redownloaded.bin");
        let payload = b"canonical redownload payload";
        fs::write(&shared_path, payload).unwrap();
        let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let shared = runtime
            .ingest_local_file(&shared_path, "shared-then-redownloaded.bin")
            .await
            .unwrap();
        let file_hash = shared.file_hash.parse::<Ed2kHash>().unwrap();

        runtime
            .replace_with_download_job(&new_transfer_job(
                file_hash,
                "redownloaded.bin".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();
        runtime
            .append_piece_block(&shared.file_hash, 0, 0, payload.len() as u64, payload)
            .await
            .unwrap();
        assert!(runtime.manifest(&shared.file_hash).await.unwrap().completed);

        fs::write(&shared_path, vec![b'X'; payload.len()]).unwrap();
        assert_eq!(
            runtime
                .read_verified_range(&file_hash, 0, payload.len() as u64)
                .await
                .unwrap()
                .unwrap(),
            payload,
        );
    }
}
