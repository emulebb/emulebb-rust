use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::{
    MetadataCurrentSharedFile, MetadataDownloadHistoryEntry, native_path::path_from_row,
    store::decode_fixed_hex, transfer_model::MetadataTransferManifest,
};

impl super::MetadataStore {
    pub fn download_history_by_hash(
        &self,
        file_hash: &str,
    ) -> Result<Option<MetadataDownloadHistoryEntry>> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        self.connection()?
            .prepare_cached(
                r#"
                SELECT lower(hex(ed2k_hash)), display_name, size_bytes,
                       CASE
                           WHEN aich_root IS NULL THEN NULL
                           ELSE lower(hex(aich_root))
                       END,
                       first_completed_at_ms, last_completed_at_ms
                FROM download_history
                WHERE ed2k_hash = ?1
                "#,
            )?
            .query_row(params![hash], |row| {
                Ok(MetadataDownloadHistoryEntry {
                    file_hash: row.get(0)?,
                    display_name: row.get(1)?,
                    file_size: row.get::<_, i64>(2)? as u64,
                    aich_root: row.get(3)?,
                    first_completed_at_ms: row.get(4)?,
                    last_completed_at_ms: row.get(5)?,
                })
            })
            .optional()
            .map_err(Into::into)
    }

    pub fn current_shared_files_by_hash(
        &self,
        file_hash: &str,
    ) -> Result<Vec<MetadataCurrentSharedFile>> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let mut statement = conn.prepare_cached(
            r#"
            SELECT known_files.display_name, shared_file_sources.file_size,
                   local_paths.platform, local_paths.native_path
            FROM shared_file_sources
            JOIN known_files ON known_files.id = shared_file_sources.known_file_id
            JOIN local_paths ON local_paths.id = shared_file_sources.path_id
            WHERE known_files.ed2k_hash = ?1
            ORDER BY local_paths.display_path
            "#,
        )?;
        let rows = statement.query_map(params![hash], |row| {
            Ok(MetadataCurrentSharedFile {
                display_name: row.get(0)?,
                file_size: row.get::<_, i64>(1)? as u64,
                source_path: path_from_row(row, 2, 3)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

pub(crate) fn record_completed_download(
    tx: &Transaction<'_>,
    manifest: &MetadataTransferManifest,
    hash: &[u8],
    aich_root: Option<&[u8]>,
    now: i64,
) -> Result<()> {
    if !manifest.completed || manifest.final_rehash_pending || manifest.source_path.is_some() {
        return Ok(());
    }

    let existing = tx
        .prepare_cached("SELECT size_bytes, aich_root FROM download_history WHERE ed2k_hash = ?1")?
        .query_row(params![hash], |row| {
            Ok((
                row.get::<_, i64>(0)? as u64,
                row.get::<_, Option<Vec<u8>>>(1)?,
            ))
        })
        .optional()?;
    if let Some((existing_size, existing_aich_root)) = existing {
        ensure!(
            existing_size == manifest.file_size,
            "completed download history for {} has size {existing_size}, not {}",
            manifest.file_hash,
            manifest.file_size
        );
        if let (Some(existing_aich_root), Some(aich_root)) =
            (existing_aich_root.as_deref(), aich_root)
        {
            ensure!(
                existing_aich_root == aich_root,
                "completed download history for {} has a conflicting AICH root",
                manifest.file_hash
            );
        }
    }

    tx.prepare_cached(
        r#"
        INSERT INTO download_history(
            ed2k_hash, size_bytes, display_name, aich_root,
            first_completed_at_ms, last_completed_at_ms
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?5)
        ON CONFLICT(ed2k_hash) DO UPDATE SET
            display_name = excluded.display_name,
            aich_root = coalesce(excluded.aich_root, download_history.aich_root),
            last_completed_at_ms = excluded.last_completed_at_ms
        "#,
    )?
    .execute(params![
        hash,
        manifest.file_size as i64,
        manifest.display_name,
        aich_root,
        now,
    ])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        MetadataStore, MetadataTransferManifest, MetadataTransferPiece, MetadataTransferRange,
    };

    fn completed_download_manifest() -> MetadataTransferManifest {
        MetadataTransferManifest {
            file_hash: "00112233445566778899aabbccddeeff".to_string(),
            display_name: "completed.bin".to_string(),
            file_size: 1024,
            piece_size: 1024,
            completed: true,
            final_rehash_pending: false,
            md4_hashset_acquired: true,
            md4_hashset: Vec::new(),
            aich_hashset_acquired: true,
            aich_root: Some("1111111111111111111111111111111111111111".to_string()),
            aich_hashset: Vec::new(),
            verified_ranges: vec![MetadataTransferRange {
                start: 0,
                end: 1024,
            }],
            pieces: vec![MetadataTransferPiece {
                piece_index: 0,
                state: "Verified".to_string(),
                bytes_written: 1024,
                block_bitmap: None,
                ich_corrupted: false,
            }],
            sources: Vec::new(),
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
            category_id: 0,
            control_state: None,
            transfer_row_removed: false,
            delivered_path: Some("C:\\incoming\\completed.bin".into()),
            source_path: None,
            source_fingerprint: None,
        }
    }

    #[test]
    fn authoritative_download_completion_survives_manifest_deletion() {
        let store = MetadataStore::in_memory().unwrap();
        let manifest = completed_download_manifest();
        store.upsert_transfer_manifest(&manifest).unwrap();
        assert!(store.delete_transfer_manifest(&manifest.file_hash).unwrap());

        let history = store
            .download_history_by_hash(&manifest.file_hash)
            .unwrap()
            .unwrap();
        assert_eq!(history.file_hash, manifest.file_hash);
        assert_eq!(history.display_name, manifest.display_name);
        assert_eq!(history.file_size, manifest.file_size);
        assert_eq!(history.aich_root, manifest.aich_root);
        assert!(history.first_completed_at_ms <= history.last_completed_at_ms);
    }

    #[test]
    fn incomplete_and_share_in_place_manifests_do_not_create_download_history() {
        let store = MetadataStore::in_memory().unwrap();
        let mut manifest = completed_download_manifest();
        manifest.completed = false;
        store.upsert_transfer_manifest(&manifest).unwrap();
        assert!(
            store
                .download_history_by_hash(&manifest.file_hash)
                .unwrap()
                .is_none()
        );

        manifest.completed = true;
        manifest.source_path = Some("C:\\shared\\completed.bin".into());
        store.upsert_transfer_manifest(&manifest).unwrap();
        assert!(
            store
                .download_history_by_hash(&manifest.file_hash)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn repeated_completion_preserves_identity_and_refreshes_metadata() {
        let store = MetadataStore::in_memory().unwrap();
        let mut manifest = completed_download_manifest();
        store.upsert_transfer_manifest(&manifest).unwrap();
        let first = store
            .download_history_by_hash(&manifest.file_hash)
            .unwrap()
            .unwrap();

        manifest.display_name = "renamed.bin".to_string();
        manifest.aich_root = None;
        store.upsert_transfer_manifest(&manifest).unwrap();
        let refreshed = store
            .download_history_by_hash(&manifest.file_hash)
            .unwrap()
            .unwrap();
        assert_eq!(refreshed.display_name, "renamed.bin");
        assert_eq!(refreshed.aich_root, first.aich_root);
        assert_eq!(refreshed.first_completed_at_ms, first.first_completed_at_ms);
        assert!(refreshed.last_completed_at_ms >= first.last_completed_at_ms);
    }

    #[test]
    fn conflicting_completed_identity_rolls_back_manifest_update() {
        let store = MetadataStore::in_memory().unwrap();
        let mut manifest = completed_download_manifest();
        store.upsert_transfer_manifest(&manifest).unwrap();

        manifest.file_size += 1;
        let error = store.upsert_transfer_manifest(&manifest).unwrap_err();
        assert!(error.to_string().contains("has size 1024, not 1025"));
        assert_eq!(
            store
                .transfer_manifest_by_hash(&manifest.file_hash)
                .unwrap()
                .unwrap()
                .file_size,
            1024
        );
    }
}
