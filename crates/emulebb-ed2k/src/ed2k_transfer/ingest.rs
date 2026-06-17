//! Local payload ingest into the ED2K transfer store.

use std::path::Path;

use anyhow::{Context, Result};

use crate::long_path::long_path;

use super::hashset::{build_aich_hashset_from_payload, build_md4_hashset_from_payload};
use super::manifest::{piece_count, rebuild_verified_ranges};
use super::{
    Ed2kLocalIngestSummary, Ed2kPieceState, Ed2kResumeManifest, Ed2kTransferRuntime,
    Ed2kTransferState, PAYLOAD_FILE_NAME, expected_piece_length, new_transfer_job,
};

impl Ed2kTransferRuntime {
    /// Copy a local payload into the canonical ED2K transfer store and expose
    /// it as a fully verified shared file.
    pub async fn ingest_local_file(
        &self,
        source_path: &Path,
        canonical_name: &str,
    ) -> Result<Ed2kLocalIngestSummary> {
        let canonical_name = canonical_name.trim();
        if canonical_name.is_empty() {
            anyhow::bail!("local ED2K ingest requires a non-empty canonical name");
        }
        // Operator-facing shared-file ingest boundary: normalize the operator's
        // source path to the long-path (`\\?\`) form before it is opened/hashed,
        // so a shared file under a deep operator tree (beyond the legacy
        // MAX_PATH limit) can still be read for ingest. The internal piece-store
        // destination (`transfer_dir`/`pieces.bin`) below is deliberately left
        // short-path. (Operator-rule scope: shared-directory trees -- see
        // long_path.rs.)
        let source_path = long_path(source_path);
        let source_path = source_path.canonicalize().with_context(|| {
            format!(
                "failed to resolve local ingest source {}",
                source_path.display()
            )
        })?;
        let metadata = tokio::fs::metadata(&source_path).await.with_context(|| {
            format!(
                "failed to stat local ingest source {}",
                source_path.display()
            )
        })?;
        if metadata.len() == 0 {
            anyhow::bail!("local ED2K ingest does not support zero-sized payloads");
        }

        let _guard = self.manifest_io.lock().await;
        let (file_hash, md4_hashset) =
            build_md4_hashset_from_payload(&source_path, metadata.len())?;
        let job = new_transfer_job(file_hash, canonical_name.to_string(), metadata.len());
        let transfer_dir = self.transfer_dir(&job.file_hash);
        tokio::fs::create_dir_all(&transfer_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to create ED2K transfer directory {}",
                    transfer_dir.display()
                )
            })?;
        let payload_path = transfer_dir.join(PAYLOAD_FILE_NAME);
        let source_matches_payload = payload_path.exists()
            && payload_path.canonicalize().ok().as_deref() == Some(source_path.as_path());
        if !source_matches_payload {
            tokio::fs::copy(&source_path, &payload_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to copy local ingest payload {} -> {}",
                        source_path.display(),
                        payload_path.display()
                    )
                })?;
        }

        let aich_hashset = build_aich_hashset_from_payload(&payload_path, metadata.len())?;
        let mut manifest = Ed2kResumeManifest::new(&job);
        manifest.completed = true;
        manifest.md4_hashset_acquired = true;
        manifest.md4_hashset = md4_hashset.iter().map(hex::encode).collect();
        manifest.aich_hashset_acquired = true;
        manifest.aich_root = Some(hex::encode(aich_hashset.master_hash));
        manifest.aich_hashset = aich_hashset.part_hashes.iter().map(hex::encode).collect();
        manifest.pieces = (0..piece_count(manifest.file_size, manifest.piece_size))
            .map(|piece_index| Ed2kPieceState {
                piece_index,
                state: Ed2kTransferState::Verified,
                bytes_written: expected_piece_length(
                    manifest.file_size,
                    manifest.piece_size,
                    u64::from(piece_index),
                ),
                block_bitmap: None,
            })
            .collect();
        rebuild_verified_ranges(&mut manifest);
        self.store_manifest_unlocked(&manifest).await?;
        self.upsert_verified_catalog_entry(&manifest).await;

        Ok(Ed2kLocalIngestSummary {
            file_hash: manifest.file_hash,
            canonical_name: manifest.canonical_name,
            file_size: manifest.file_size,
            md4_hashset_count: manifest.md4_hashset.len(),
            aich_root: manifest.aich_root.unwrap_or_default(),
            aich_hashset_count: manifest.aich_hashset.len(),
            transfer_dir: transfer_dir.display().to_string(),
        })
    }
}
