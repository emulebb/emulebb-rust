use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Context, Result};

use super::Ed2kTransferRuntime;

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
                PathBuf::from(shared_file.source_path),
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
}
