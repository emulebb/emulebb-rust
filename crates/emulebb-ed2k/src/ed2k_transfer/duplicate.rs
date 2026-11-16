use std::path::PathBuf;

use anyhow::{Context, Result};
use emulebb_metadata::{MetadataCurrentSharedFile, NativeFileFingerprint};

use super::Ed2kTransferRuntime;

pub(super) struct PresentSharedSource {
    pub(super) path: PathBuf,
    pub(super) metadata_path: PathBuf,
    pub(super) fingerprint: NativeFileFingerprint,
}

/// Select the first active path whose on-disk identity still matches its hash evidence.
pub(super) fn first_present_source(
    shared_files: Vec<MetadataCurrentSharedFile>,
) -> Option<PresentSharedSource> {
    for shared_file in shared_files {
        let Some(expected_fingerprint) = shared_file.source_fingerprint else {
            continue;
        };
        let path = crate::long_path::long_path(&shared_file.source_path);
        let current_fingerprint = super::ingest::native_file_fingerprint(&path);
        if expected_fingerprint.size_bytes == shared_file.file_size
            && current_fingerprint
                .as_ref()
                .is_some_and(|current| expected_fingerprint.safely_matches(current))
        {
            return Some(PresentSharedSource {
                path,
                metadata_path: shared_file.source_path,
                fingerprint: expected_fingerprint,
            });
        }
    }
    None
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
    pub first_completed_at_s: i64,
    pub last_completed_at_s: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kActiveDownloadEvidence {
    pub token: emulebb_metadata::JobToken,
    pub display_name: String,
    pub expected_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ed2kDownloadEvidence {
    pub active_job: Option<Ed2kActiveDownloadEvidence>,
    pub availability: emulebb_metadata::LocalContentAvailability,
    /// At most one matching native copy; this is not a library listing.
    pub present_file: Option<Ed2kCurrentLocalFileEvidence>,
    pub previously_completed: Option<Ed2kPreviouslyCompletedEvidence>,
}

impl Ed2kDownloadEvidence {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.active_job.is_none()
            && self.availability == emulebb_metadata::LocalContentAvailability::ConfirmedAbsent
            && self.previously_completed.is_none()
    }
}

impl Ed2kTransferRuntime {
    /// Retained bounded native evidence. Unknown storage is never absence.
    pub async fn download_evidence(
        &self,
        file_hash: &str,
    ) -> Result<super::local_mutation::read_result::RetainedRead<Ed2kDownloadEvidence>> {
        let hash = file_hash
            .parse::<emulebb_kad_proto::Ed2kHash>()?
            .to_string();
        self.local_mutations
            .submit_availability_read(self, &hash)?
            .await
            .map_err(|_| super::local_mutation::LocalMutationError::Unknown)?
    }

    pub(super) async fn first_present_shared_source(
        &self,
        file_hash: &str,
    ) -> Result<Option<PresentSharedSource>> {
        let metadata = self.metadata.clone();
        let file_hash = file_hash.to_string();
        tokio::task::spawn_blocking(move || {
            let mut cursor = 0;
            while let Some(candidate) = metadata.next_shared_copy(&file_hash, cursor, 65_536)? {
                cursor = candidate.path_id;
                if !super::shared_catalog::category_copy_matches(&candidate) {
                    continue;
                }
                let Some(fingerprint) = candidate.source_fingerprint else {
                    continue;
                };
                if metadata
                    .mark_session_verified_local_path(&candidate.source_path, &fingerprint)?
                {
                    return Ok(Some(PresentSharedSource {
                        path: crate::long_path::long_path(&candidate.source_path),
                        metadata_path: candidate.source_path,
                        fingerprint,
                    }));
                }
            }
            Ok(None)
        })
        .await
        .context("ED2K shared-source evidence query task panicked")?
    }

    /// Whether another persisted source still provides the verified bytes for
    /// this hash after one source path was invalidated or reassigned.
    pub async fn has_present_shared_source(&self, file_hash: &str) -> Result<bool> {
        Ok(self.first_present_shared_source(file_hash).await?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use emulebb_kad_proto::Ed2kHash;
    use tempfile::tempdir;

    use super::*;
    use crate::ed2k_transfer::ED2K_PART_SIZE;
    use crate::ed2k_transfer::test_support::admit_local_share;

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
        let job = super::super::test_support::admit_download_job(
            &runtime,
            active_hash,
            "active.bin".to_string(),
            8,
        );
        runtime.ensure_job(&job).await.unwrap();
        let active = runtime
            .download_evidence(&active_hash.to_string())
            .await
            .unwrap();
        assert_eq!(active.active_job.as_ref().unwrap().token, job.token);
        assert_eq!(
            active.active_job.as_ref().unwrap().expected_size_bytes,
            Some(8)
        );
        assert!(active.present_file.is_none());
        assert!(active.previously_completed.is_none());

        let shared_path = root.path().join("shared.bin");
        fs::write(&shared_path, b"shared payload").unwrap();
        let shared = runtime
            .ingest_local_file(&shared_path, "shared.bin")
            .await
            .unwrap();
        admit_local_share(&runtime, root.path(), &shared_path).await;
        let shared_evidence = runtime.download_evidence(&shared.file_hash).await.unwrap();
        assert!(shared_evidence.active_job.is_none());
        assert!(shared_evidence.present_file.is_some());
        assert_eq!(
            shared_evidence.present_file.as_ref().unwrap().kind,
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
        let file_hash = {
            use md4::Digest;
            Ed2kHash::from_bytes(md4::Md4::digest(b"download").into())
        };
        let hash = file_hash.to_string();
        let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let job = super::super::test_support::admit_download_job(
            &runtime,
            file_hash,
            "download.bin".to_string(),
            8,
        );
        runtime.ensure_job(&job).await.unwrap();
        runtime
            .store_md4_hashset(job.token, Vec::new())
            .await
            .unwrap();
        runtime
            .store_piece_data(job.token, 0, b"download")
            .await
            .unwrap();

        let completed = runtime.download_evidence(&hash).await.unwrap();
        assert!(completed.present_file.is_some());
        assert_eq!(
            completed.present_file.as_ref().unwrap().kind,
            Ed2kCurrentLocalFileKind::ManagedPayload
        );
        assert!(completed.previously_completed.is_some());
        drop(runtime);

        let restarted = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        restarted
            .prepare_download_job_storage(job.token)
            .await
            .unwrap();
        let after_restart = restarted.download_evidence(&hash).await.unwrap();
        assert!(after_restart.present_file.is_some());
        assert!(after_restart.previously_completed.is_some());

        assert!(
            restarted
                .remove_download_job(job.token.job_id, false)
                .await
                .unwrap()
        );
        assert!(
            restarted
                .cleanup_removed_download_job(job.token.job_id)
                .await
                .unwrap()
        );
        let after_removal = restarted.download_evidence(&hash).await.unwrap();
        assert!(after_removal.active_job.is_none());
        assert!(after_removal.present_file.is_none());
        assert_eq!(
            after_removal
                .previously_completed
                .as_ref()
                .unwrap()
                .display_name,
            "download.bin"
        );
    }

    #[tokio::test]
    async fn pending_old_cleanup_does_not_block_a_new_same_content_job() {
        let root = tempdir().unwrap();
        let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let hash = Ed2kHash([0x44; 16]);
        let old =
            super::super::test_support::admit_download_job(&runtime, hash, "old.bin".into(), 8);
        runtime.ensure_job(&old).await.unwrap();
        let old_path = runtime.transfer_dir(old.token.job_id).unwrap();
        fs::write(old_path.join(super::super::PAYLOAD_FILE_NAME), b"old data").unwrap();
        assert!(
            runtime
                .remove_download_job(old.token.job_id, false)
                .await
                .unwrap()
        );
        assert!(runtime.ensure_job(&old).await.is_err());
        let new =
            super::super::test_support::admit_download_job(&runtime, hash, "new.bin".into(), 8);
        assert_ne!(new.token.job_id, old.token.job_id);
        runtime.ensure_job(&new).await.unwrap();
        let new_path = runtime.transfer_dir(new.token.job_id).unwrap();
        assert_ne!(new_path, old_path);
        fs::write(new_path.join(super::super::PAYLOAD_FILE_NAME), b"new data").unwrap();
        assert!(
            runtime
                .cleanup_removed_download_job(old.token.job_id)
                .await
                .unwrap()
        );
        assert_eq!(
            fs::read(new_path.join(super::super::PAYLOAD_FILE_NAME)).unwrap(),
            b"new data"
        );
        assert_eq!(
            runtime
                .metadata
                .latest_download_job(&hash.to_string())
                .unwrap()
                .unwrap()
                .token,
            new.token
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
        admit_local_share(&runtime, root.path(), &shared_path).await;
        let file_hash = shared.file_hash.parse::<Ed2kHash>().unwrap();
        let published = runtime
            .publish_entries_after(None, 200)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].file_hash, shared.file_hash);
        assert_eq!(published[0].display_name, "shared-redownload.bin");
        drop(published);

        let job = super::super::test_support::admit_download_job(
            &runtime,
            file_hash,
            "fresh-download.bin".to_string(),
            payload.len() as u64,
        );
        let replacement = runtime.ensure_job(&job).await.unwrap();
        assert!(!replacement.completed);
        let servable = runtime.serving_view(&shared.file_hash).await.unwrap();
        assert!(servable.completed);
        assert_eq!(
            servable.local_path.as_deref(),
            Some(crate::long_path::long_path(&shared_path).as_path())
        );
        assert_eq!(servable.display_name, "shared-redownload.bin");
        runtime
            .update_shared_file_metadata(
                &shared.file_hash,
                Some(("release", false)),
                Some(("local copy", 4)),
            )
            .await
            .unwrap();
        let servable = runtime.serving_view(&shared.file_hash).await.unwrap();
        assert_eq!(servable.upload_priority, "release");
        assert_eq!(servable.comment, "local copy");
        assert_eq!(servable.rating, 4);
        assert!(!runtime.manifest(job.token).await.unwrap().completed);
        let published = runtime
            .publish_entries_after(None, 200)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].upload_priority, "release");
        assert_eq!(published[0].comment, "local copy");
        drop(published);
        let evidence = runtime.download_evidence(&shared.file_hash).await.unwrap();
        assert!(evidence.active_job.is_some());
        assert!(evidence.present_file.is_some());
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
        restarted
            .prepare_download_job_storage(job.token)
            .await
            .unwrap();
        let restarted_evidence = restarted
            .download_evidence(&shared.file_hash)
            .await
            .unwrap();
        assert!(restarted_evidence.active_job.is_some());
        assert!(restarted_evidence.present_file.is_some());
        let servable = restarted.serving_view(&shared.file_hash).await.unwrap();
        assert!(servable.completed);
        assert_eq!(servable.upload_priority, "release");
        assert_eq!(servable.comment, "local copy");
        assert_eq!(servable.rating, 4);
        assert_eq!(
            servable.local_path.as_deref(),
            Some(crate::long_path::long_path(&shared_path).as_path())
        );
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
    async fn verified_redownload_piece_keeps_complete_local_catalog_entry() {
        let root = tempdir().unwrap();
        let shared_path = root.path().join("complete-local.bin");
        let payload = vec![0x41; ED2K_PART_SIZE as usize + 32];
        fs::write(&shared_path, &payload).unwrap();
        let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let shared = runtime
            .ingest_local_file(&shared_path, "complete-local.bin")
            .await
            .unwrap();
        admit_local_share(&runtime, root.path(), &shared_path).await;
        let local = runtime.serving_view(&shared.file_hash).await.unwrap();
        let hashes = local
            .md4_hashset
            .iter()
            .map(|hash| hex::decode(hash).unwrap().try_into().unwrap())
            .collect();

        let job = super::super::test_support::admit_download_job(
            &runtime,
            shared.file_hash.parse().unwrap(),
            "redownload.bin".to_string(),
            payload.len() as u64,
        );
        runtime.ensure_job(&job).await.unwrap();
        runtime.store_md4_hashset(job.token, hashes).await.unwrap();
        runtime
            .store_piece_data_unfinalized(job.token, 0, &payload[..ED2K_PART_SIZE as usize])
            .await
            .unwrap();

        let catalog = runtime.shared_catalog();
        let catalog = catalog.read().await;
        let entry = catalog
            .entry_by_hash(&shared.file_hash.parse::<Ed2kHash>().unwrap())
            .unwrap();
        assert!(entry.verified_complete);
        assert_eq!(entry.display_name, "complete-local.bin");
        assert_eq!(catalog.completed_verified_len(), 1);
        drop(catalog);
        assert!(!runtime.manifest(job.token).await.unwrap().completed);

        let root_mutation = runtime.begin_category_root_mutation().await.unwrap();
        runtime
            .metadata
            .withdraw_local_file_path(&crate::long_path::long_path(&shared_path))
            .unwrap();
        drop(root_mutation);
        let manifest_guard = runtime.lock_manifest(job.token).await;
        let admitted = runtime
            .authorize_serving_view_unlocked(&shared.file_hash, Some(job.token), Some(local))
            .await
            .unwrap()
            .unwrap();
        assert!(
            !admitted.completed,
            "a stale complete view must fall back to the independent partial source"
        );
        drop(manifest_guard);
        let partial = runtime.serving_view(&shared.file_hash).await.unwrap();
        assert!(!partial.completed);
        let hash = shared.file_hash.parse::<Ed2kHash>().unwrap();
        assert_eq!(
            runtime
                .read_verified_range(&hash, 0, 16)
                .await
                .unwrap()
                .unwrap(),
            payload[..16]
        );
        assert!(
            runtime
                .read_verified_range(&hash, ED2K_PART_SIZE, ED2K_PART_SIZE + 16)
                .await
                .unwrap()
                .is_none()
        );
        runtime
            .refresh_shared_catalog_entry(&shared.file_hash)
            .await
            .unwrap();
        let catalog = runtime.shared_catalog();
        let catalog = catalog.read().await;
        let entry = catalog
            .entry_by_hash(&shared.file_hash.parse::<Ed2kHash>().unwrap())
            .unwrap();
        assert!(!entry.verified_complete);
        assert_eq!(entry.display_name, "redownload.bin");
        assert!(!entry.verified_ranges.is_empty());
    }

    #[tokio::test]
    async fn completed_redownload_serves_payload_after_shared_path_withdrawal() {
        let root = tempdir().unwrap();
        let shared_path = root.path().join("shared-then-redownloaded.bin");
        let payload = b"canonical redownload payload";
        fs::write(&shared_path, payload).unwrap();
        let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let shared = runtime
            .ingest_local_file(&shared_path, "shared-then-redownloaded.bin")
            .await
            .unwrap();
        admit_local_share(&runtime, root.path(), &shared_path).await;
        let file_hash = shared.file_hash.parse::<Ed2kHash>().unwrap();

        let job = super::super::test_support::admit_download_job(
            &runtime,
            file_hash,
            "redownloaded.bin".to_string(),
            payload.len() as u64,
        );
        runtime.ensure_job(&job).await.unwrap();
        runtime
            .store_md4_hashset(job.token, Vec::new())
            .await
            .unwrap();
        runtime
            .append_piece_block(job.token, 0, 0, payload.len() as u64, payload)
            .await
            .unwrap();
        assert!(runtime.manifest(job.token).await.unwrap().completed);

        fs::write(&shared_path, vec![b'X'; payload.len()]).unwrap();
        runtime.refresh_complete_shared_catalog().await.unwrap();
        let catalog = runtime.shared_catalog();
        assert_eq!(
            catalog
                .read()
                .await
                .entry_by_hash(&file_hash)
                .unwrap()
                .display_name,
            "redownloaded.bin"
        );
        assert!(
            runtime
                .read_verified_range(&file_hash, 0, payload.len() as u64)
                .await
                .unwrap()
                .is_none()
        );
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
