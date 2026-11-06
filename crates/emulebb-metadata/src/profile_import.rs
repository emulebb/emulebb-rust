use std::path::PathBuf;

use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use crate::{
    MetadataContentConflict, MetadataFileImportRecord, MetadataStore, MetadataVerifiedLocalContent,
    NativeFileFingerprint,
    store::{decode_fixed_hex, unix_ms, upsert_local_path},
};

impl MetadataStore {
    /// Enrich already accepted live content without changing its path fingerprint.
    /// This is content-addressed merge, never a way to admit an unmatched file.
    pub fn enrich_live_import(&self, entry: &MetadataFileImportRecord) -> Result<bool> {
        let hash = decode_fixed_hex(&entry.file_hash, 16, "ED2K hash")?;
        let mut conn = self.connection()?;
        let row:Option<(String,Vec<u8>,Vec<u8>,i64,Option<Vec<u8>>)>=conn.query_row(
            "SELECT p.platform,p.native_path,i.verified_fingerprint,f.size_bytes,f.aich_root FROM known_files f JOIN verified_local_content c ON c.known_file_id=f.id JOIN local_file_instances i ON i.known_file_id=f.id JOIN local_paths p ON p.id=i.path_id WHERE f.ed2k_hash=?1 LIMIT 1",
            [hash.clone()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        ).optional()?;
        let Some((platform, path, bytes, size, old_root)) = row else {
            return Ok(false);
        };
        anyhow::ensure!(
            size == entry.file_size as i64,
            MetadataContentConflict("imported content size conflicts with live content")
        );
        let root = entry
            .aich_root
            .as_ref()
            .map(|r| decode_fixed_hex(r, 20, "AICH root"))
            .transpose()?;
        anyhow::ensure!(
            old_root
                .as_ref()
                .zip(root.as_ref())
                .is_none_or(|(a, b)| a == b),
            MetadataContentConflict("imported AICH root conflicts with live identity")
        );
        let path = crate::NativePath::from_storage(&platform, &path)?.into_path_buf();
        let fingerprint = NativeFileFingerprint::from_storage_bytes(&bytes)
            .ok_or_else(|| anyhow::anyhow!("invalid live fingerprint"))?;
        let tx = conn.transaction()?;
        Self::upsert_verified_local_content_tx(
            &tx,
            &MetadataVerifiedLocalContent {
                file_hash: entry.file_hash.clone(),
                display_name: entry.display_name.clone(),
                file_size: entry.file_size,
                part_size: 9_728_000,
                md4_hashset: entry.md4_hashset.clone(),
                aich_root: entry.aich_root.clone(),
                aich_hashset: entry.aich_hashset.clone(),
                path,
                fingerprint,
                upload_priority: entry.upload_priority.clone(),
                auto_upload_priority: entry.auto_upload_priority,
                comment: String::new(),
                rating: 0,
            },
            unix_ms(),
        )?;
        tx.execute(
            "UPDATE known_files SET aich_root=coalesce(aich_root,?2) WHERE ed2k_hash=?1",
            params![hash, root],
        )?;
        tx.execute("UPDATE known_files SET all_time_uploaded_bytes=max(all_time_uploaded_bytes,?2),all_time_upload_requests=max(all_time_upload_requests,?3),all_time_upload_accepts=max(all_time_upload_accepts,?4),last_upload_request_ms=max(last_upload_request_ms,?5) WHERE ed2k_hash=?1",params![hash,i64::try_from(entry.all_time_uploaded_bytes)?,i64::try_from(entry.all_time_upload_requests)?,i64::try_from(entry.all_time_upload_accepts)?,entry.last_upload_request_ms])?;
        tx.commit()?;
        Ok(true)
    }
    /// Accept a stock hash cache for an unchanged file without reading its bytes.
    /// The caller resolves one unambiguous stock identity and captures the
    /// target-native fingerprint from an opened regular file.
    pub fn accept_imported_local_files(
        &self,
        files: &[(MetadataFileImportRecord, PathBuf, NativeFileFingerprint)],
    ) -> Result<()> {
        if files.is_empty() {
            return Ok(());
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let now = unix_ms();
        for (entry, path, fingerprint) in files {
            anyhow::ensure!(
                entry.file_size == fingerprint.size_bytes
                    && entry.modified_s == fingerprint.modified.seconds,
                MetadataContentConflict("imported file metadata differs from the current file")
            );
            let hash = decode_fixed_hex(&entry.file_hash, 16, "ED2K hash")?;
            let old_root: Option<Option<Vec<u8>>> = tx
                .query_row(
                    "SELECT aich_root FROM known_files WHERE ed2k_hash=?1",
                    [hash.clone()],
                    |r| r.get(0),
                )
                .optional()?;
            let incoming_root = entry
                .aich_root
                .as_ref()
                .map(|r| decode_fixed_hex(r, 20, "AICH root"))
                .transpose()?;
            anyhow::ensure!(
                old_root
                    .flatten()
                    .as_ref()
                    .zip(incoming_root.as_ref())
                    .is_none_or(|(old, new)| old == new),
                MetadataContentConflict("imported AICH root conflicts with live identity")
            );
            let path_id = upsert_local_path(&tx, path)?;
            let bound:Option<Vec<u8>>=tx.query_row("SELECT f.ed2k_hash FROM local_file_instances i JOIN known_files f ON f.id=i.known_file_id WHERE i.path_id=?1",[path_id],|r|r.get(0)).optional()?;
            anyhow::ensure!(
                bound.as_ref().is_none_or(|old| old == &hash),
                MetadataContentConflict("import conflicts with existing live path binding")
            );
            // WHY: stock has already hashed these bytes. Rebind its accepted
            // content identity to this platform's fingerprint instead of scheduling
            // a full payload read merely because Rust has not seen the file before.
            Self::upsert_verified_local_content_tx(
                &tx,
                &MetadataVerifiedLocalContent {
                    file_hash: entry.file_hash.clone(),
                    display_name: entry.display_name.clone(),
                    file_size: entry.file_size,
                    part_size: 9_728_000,
                    md4_hashset: entry.md4_hashset.clone(),
                    aich_root: entry.aich_root.clone(),
                    aich_hashset: entry.aich_hashset.clone(),
                    path: path.to_path_buf(),
                    fingerprint: fingerprint.clone(),
                    upload_priority: entry.upload_priority.clone(),
                    auto_upload_priority: entry.auto_upload_priority,
                    comment: String::new(),
                    rating: 0,
                },
                now,
            )?;
            if let Some(root) = &entry.aich_root {
                tx.execute(
                    "UPDATE known_files SET aich_root=coalesce(aich_root,?2) WHERE ed2k_hash=?1",
                    params![hash, decode_fixed_hex(root, 20, "AICH root")?],
                )?;
            }
            tx.execute(
                "UPDATE known_files SET
                all_time_uploaded_bytes = max(all_time_uploaded_bytes, ?2),
                all_time_upload_requests = max(all_time_upload_requests, ?3),
                all_time_upload_accepts = max(all_time_upload_accepts, ?4),
                last_upload_request_ms = max(last_upload_request_ms, ?5)
             WHERE ed2k_hash = ?1",
                params![
                    hash,
                    i64::try_from(entry.all_time_uploaded_bytes)?,
                    i64::try_from(entry.all_time_upload_requests)?,
                    i64::try_from(entry.all_time_upload_accepts)?,
                    entry.last_upload_request_ms
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imported_file(hash: &str) -> MetadataFileImportRecord {
        MetadataFileImportRecord {
            file_hash: hash.to_string(),
            display_name: "sample.bin".to_string(),
            file_size: 1024,
            modified_s: 1_700_000_000,
            md4_hashset: Vec::new(),
            aich_root: None,
            aich_hashset: Vec::new(),
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            all_time_uploaded_bytes: 0,
            all_time_upload_requests: 0,
            all_time_upload_accepts: 0,
            last_upload_request_ms: 0,
        }
    }

    #[test]
    fn accepted_stock_batch_is_atomic_and_requires_matching_file_metadata() {
        let store = MetadataStore::in_memory().unwrap();
        let file = imported_file("00112233445566778899aabbccddeeff");
        let fingerprint = NativeFileFingerprint {
            identity: crate::NativeFileIdentity::Unix {
                device_id: 7,
                inode_number: 11,
            },
            size_bytes: file.file_size,
            modified: crate::NativeFileTimestamp::new(file.modified_s, 0).unwrap(),
            changed: None,
        };
        let mut changed = fingerprint.clone();
        changed.size_bytes += 1;
        let path = std::env::temp_dir().join("stock-cache-sample.bin");
        assert!(
            store
                .accept_imported_local_files(&[
                    (file.clone(), path.clone(), fingerprint.clone()),
                    (file.clone(), path.clone(), changed),
                ])
                .is_err()
        );
        assert_eq!(store.table_count("known_files").unwrap(), 0);
        // No file at this synthetic path is needed: the caller supplies stat
        // evidence and the metadata layer never opens the payload.
        store
            .accept_imported_local_files(&[(file.clone(), path.clone(), fingerprint.clone())])
            .unwrap();
        let mut enriched = file.clone();
        enriched.aich_root = Some("11".repeat(20));
        store
            .accept_imported_local_files(&[(enriched.clone(), path.clone(), fingerprint.clone())])
            .unwrap();
        enriched.aich_root = Some("22".repeat(20));
        assert!(
            store
                .accept_imported_local_files(&[(enriched, path, fingerprint)])
                .is_err()
        );
        assert_eq!(store.table_count("local_file_instances").unwrap(), 1);
        assert_eq!(store.table_count("transfers").unwrap(), 0);
    }
}
