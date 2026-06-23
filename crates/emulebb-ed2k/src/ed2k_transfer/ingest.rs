//! Local payload ingest into the ED2K transfer store.

use std::fs::Metadata;
use std::path::Path;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};

use crate::long_path::long_path;

use super::hashset::{build_aich_hashset_from_payload, build_md4_hashset_from_payload};
use super::manifest::{piece_count, rebuild_verified_ranges};
use super::{
    Ed2kLocalIngestSummary, Ed2kPieceState, Ed2kResumeManifest, Ed2kTransferRuntime,
    Ed2kTransferState, expected_piece_length, new_transfer_job,
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
        //
        // WHY (no canonicalize): we used to `canonicalize()` the verbatim path
        // here, but that silently dropped shared files whose paths carry
        // non-ASCII characters (accents/CJK), brackets, or live in subfolders.
        // On Windows `canonicalize` resolves via `GetFinalPathNameByHandle` and
        // returns an OS-re-normalized verbatim (`\\?\`) path; a verbatim path is
        // NOT re-normalized by the OS on later access, so when the canonical
        // Unicode form differs from the form the directory walk produced, the
        // returned path no longer resolves and the subsequent stat fails
        // ("failed to stat local ingest source"), skipping the file. The walk
        // (`collect_shared_directory_files`) already hands us an absolute
        // verbatim path read straight from the on-disk directory entries, so we
        // stat/hash it directly and let the manifest record that same exact path
        // for in-place upload serving -- no canonicalize round-trip is needed.
        let source_path = long_path(source_path);
        let metadata = tokio::fs::metadata(&source_path).await.with_context(|| {
            format!(
                "failed to stat local ingest source {}",
                source_path.display()
            )
        })?;
        if metadata.len() == 0 {
            anyhow::bail!("local ED2K ingest does not support zero-sized payloads");
        }

        // Hash OFF the `manifest_io` lock AND off the async runtime. MD4/AICH read
        // and hash the whole (potentially many-GB) file with blocking `std::fs`,
        // which on a slow disk takes far longer than any HTTP timeout. Holding
        // `manifest_io` across that froze every REST read (they all funnel through
        // `manifests()`), and running the blocking hash inline starved a tokio
        // worker. We therefore compute both hashsets under `spawn_blocking` with no
        // lock held, and only take `manifest_io` for the short manifest write below.
        let md4_len = metadata.len();
        let md4_path = source_path.clone();
        let (file_hash, md4_hashset) =
            tokio::task::spawn_blocking(move || build_md4_hashset_from_payload(&md4_path, md4_len))
                .await
                .context("MD4 hashing task panicked")??;
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
        // Seed the shared, already-complete file IN PLACE: it is served for
        // upload directly from its original on-disk path. We deliberately do NOT
        // copy it into the internal piece store (`transfer_dir/pieces.bin`),
        // which would duplicate the whole (potentially hundreds-of-GB) library
        // on disk, and the manifest records `source_path` so the upload-serving
        // read path resolves to the original file and finished-file delivery
        // skips it (delivery is download-only). The transfer dir still exists to
        // hold the resume manifest; only the payload bytes are never duplicated.
        // AICH/MD4 are computed straight from the original file.
        let aich_len = metadata.len();
        let aich_path = source_path.clone();
        let aich_hashset = tokio::task::spawn_blocking(move || {
            build_aich_hashset_from_payload(&aich_path, aich_len)
        })
        .await
        .context("AICH hashing task panicked")??;
        let mut manifest = Ed2kResumeManifest::new(&job);
        manifest.source_path = Some(source_path.display().to_string());
        // Record the source file's last-modified time so the incremental
        // shared-directory reload can compare it against the on-disk mtime and
        // skip re-hashing an unchanged file. A platform that cannot report mtime
        // simply leaves this `None`, which the reload treats as a miss (re-hash
        // once), so correctness never depends on mtime being available.
        manifest.source_mtime_ms = source_mtime_ms(&metadata);
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
        // Only the manifest write needs `manifest_io`; held briefly (no hashing
        // under it), so concurrent REST reads of `manifests()` are not starved.
        let _guard = self.manifest_io.lock().await;
        self.store_manifest_unlocked(&manifest).await?;
        self.upsert_verified_catalog_entry(&manifest).await;
        drop(_guard);

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

/// Convert a file's last-modified time to Unix milliseconds for the
/// share-in-place reload comparison, or `None` when the platform/filesystem does
/// not report it or the timestamp predates the Unix epoch. Truncating to whole
/// milliseconds keeps the value stable across the round-trip through the
/// `INTEGER` metadata column, so the same unchanged file compares equal on a
/// later reload.
pub(crate) fn source_mtime_ms(metadata: &Metadata) -> Option<i64> {
    let modified = metadata.modified().ok()?;
    let millis = modified.duration_since(UNIX_EPOCH).ok()?.as_millis();
    i64::try_from(millis).ok()
}

/// Stat a resolved long-path source for the incremental reload, returning
/// `(file_size, mtime_ms)`. `None` when the file is missing/unreadable (treated
/// as a miss, so it is (re)hashed). The size pairs with the persisted manifest
/// `file_size` and the mtime with `source_mtime_ms` so a match on all three
/// (plus the path key) lets the reload skip re-hashing.
pub(crate) fn stat_source_identity(source_path: &Path) -> Option<(u64, Option<i64>)> {
    let metadata = std::fs::metadata(source_path).ok()?;
    Some((metadata.len(), source_mtime_ms(&metadata)))
}
