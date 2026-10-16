use anyhow::{Result, anyhow, ensure};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::{
    MetadataCurrentSharedFile, MetadataDownloadHistoryEntry, native_path::path_from_row,
    store::decode_fixed_hex, transfer_model::MetadataTransferManifest,
    transfer_store::optional_fingerprint_from_row,
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
                   local_paths.platform, local_paths.native_path,
                   shared_file_sources.source_fingerprint
            FROM shared_file_sources
            JOIN known_files ON known_files.id = shared_file_sources.known_file_id
            JOIN transfers ON transfers.known_file_id = known_files.id
            JOIN local_paths ON local_paths.id = shared_file_sources.path_id
            WHERE known_files.ed2k_hash = ?1
              AND transfers.delete_requested_at_ms IS NULL
            ORDER BY local_paths.display_path
            "#,
        )?;
        let rows = statement.query_map(params![hash], |row| {
            Ok(MetadataCurrentSharedFile {
                display_name: row.get(0)?,
                file_size: row.get::<_, i64>(1)? as u64,
                source_path: path_from_row(row, 2, 3)?,
                source_fingerprint: optional_fingerprint_from_row(row, 4)?,
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
    completed_at_ms: Option<i64>,
    completion_transition: bool,
) -> Result<()> {
    if !records_download_completion(manifest) {
        return Ok(());
    }
    let completed_at_ms = completed_at_ms.ok_or_else(|| {
        anyhow!(
            "completed download {} has no completion timestamp",
            manifest.file_hash
        )
    })?;

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
            last_completed_at_ms = CASE
                WHEN ?6 THEN excluded.last_completed_at_ms
                ELSE download_history.last_completed_at_ms
            END
        "#,
    )?
    .execute(params![
        hash,
        manifest.file_size as i64,
        manifest.display_name,
        aich_root,
        completed_at_ms,
        completion_transition,
    ])?;
    Ok(())
}

pub(crate) fn records_download_completion(manifest: &MetadataTransferManifest) -> bool {
    manifest.completed && !manifest.final_rehash_pending && manifest.source_path.is_none()
}

#[cfg(test)]
mod tests {
    use crate::{
        MetadataStore, MetadataTransferDeliveryOwnership, MetadataTransferDeliveryState,
        MetadataTransferManifest, MetadataTransferPiece, MetadataTransferRange,
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
            delivery_state: MetadataTransferDeliveryState::Delivered,
            delivery_ownership: MetadataTransferDeliveryOwnership::Unowned,
            delivered_path: Some("C:\\incoming\\completed.bin".into()),
            source_path: None,
            source_fingerprint: None,
            payload_fingerprint: None,
        }
    }

    fn transfer_completed_at_ms(store: &MetadataStore, file_hash: &str) -> Option<i64> {
        store
            .transfer_timestamps_by_hash(file_hash)
            .unwrap()
            .unwrap()
            .1
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
        manifest.delivery_state = MetadataTransferDeliveryState::NotApplicable;
        manifest.delivery_ownership = MetadataTransferDeliveryOwnership::None;
        manifest.delivered_path = None;
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
    fn completion_timestamps_only_advance_on_completion_transitions() {
        let store = MetadataStore::in_memory().unwrap();
        let mut manifest = completed_download_manifest();
        manifest.completed = false;
        store.upsert_transfer_manifest(&manifest).unwrap();
        assert_eq!(transfer_completed_at_ms(&store, &manifest.file_hash), None);
        assert!(
            store
                .download_history_by_hash(&manifest.file_hash)
                .unwrap()
                .is_none()
        );

        manifest.completed = true;
        store.upsert_transfer_manifest(&manifest).unwrap();
        const FIRST_COMPLETION_MS: i64 = 1_000;
        {
            let conn = store.connection().unwrap();
            conn.execute(
                "UPDATE transfers SET completed_at_ms = ?1",
                rusqlite::params![FIRST_COMPLETION_MS],
            )
            .unwrap();
            conn.execute(
                r#"
                UPDATE download_history
                SET first_completed_at_ms = ?1, last_completed_at_ms = ?1
                "#,
                rusqlite::params![FIRST_COMPLETION_MS],
            )
            .unwrap();
        }

        manifest.display_name = "renamed.bin".to_string();
        manifest.aich_root = None;
        store.upsert_transfer_manifest(&manifest).unwrap();
        let metadata_refresh = store
            .download_history_by_hash(&manifest.file_hash)
            .unwrap()
            .unwrap();
        assert_eq!(metadata_refresh.display_name, "renamed.bin");
        assert_eq!(
            metadata_refresh.aich_root.as_deref(),
            Some("1111111111111111111111111111111111111111")
        );
        assert_eq!(metadata_refresh.first_completed_at_ms, FIRST_COMPLETION_MS);
        assert_eq!(metadata_refresh.last_completed_at_ms, FIRST_COMPLETION_MS);
        assert_eq!(
            transfer_completed_at_ms(&store, &manifest.file_hash),
            Some(FIRST_COMPLETION_MS)
        );

        manifest.delivery_state = MetadataTransferDeliveryState::Pending;
        manifest.delivery_ownership = MetadataTransferDeliveryOwnership::None;
        manifest.delivered_path = None;
        store.upsert_transfer_manifest(&manifest).unwrap();
        assert_eq!(
            transfer_completed_at_ms(&store, &manifest.file_hash),
            Some(FIRST_COMPLETION_MS)
        );
        assert_eq!(
            store
                .download_history_by_hash(&manifest.file_hash)
                .unwrap()
                .unwrap()
                .last_completed_at_ms,
            FIRST_COMPLETION_MS
        );

        manifest.completed = false;
        manifest.final_rehash_pending = true;
        store.upsert_transfer_manifest(&manifest).unwrap();
        assert_eq!(
            transfer_completed_at_ms(&store, &manifest.file_hash),
            Some(FIRST_COMPLETION_MS)
        );
        assert_eq!(
            store
                .download_history_by_hash(&manifest.file_hash)
                .unwrap()
                .unwrap()
                .last_completed_at_ms,
            FIRST_COMPLETION_MS
        );

        manifest.completed = true;
        manifest.final_rehash_pending = false;
        manifest.display_name = "completed-again.bin".to_string();
        store.upsert_transfer_manifest(&manifest).unwrap();
        let recompleted_at_ms = transfer_completed_at_ms(&store, &manifest.file_hash).unwrap();
        let recompleted_history = store
            .download_history_by_hash(&manifest.file_hash)
            .unwrap()
            .unwrap();
        assert!(recompleted_at_ms > FIRST_COMPLETION_MS);
        assert_eq!(
            recompleted_history.first_completed_at_ms,
            FIRST_COMPLETION_MS
        );
        assert_eq!(recompleted_history.last_completed_at_ms, recompleted_at_ms);
        assert_eq!(recompleted_history.display_name, "completed-again.bin");
    }

    #[test]
    fn only_authoritative_download_completion_starts_timestamps() {
        let rehash_store = MetadataStore::in_memory().unwrap();
        let mut rehash_manifest = completed_download_manifest();
        rehash_manifest.final_rehash_pending = true;
        rehash_store
            .upsert_transfer_manifest(&rehash_manifest)
            .unwrap();
        assert_eq!(
            transfer_completed_at_ms(&rehash_store, &rehash_manifest.file_hash),
            None
        );
        assert!(
            rehash_store
                .download_history_by_hash(&rehash_manifest.file_hash)
                .unwrap()
                .is_none()
        );

        rehash_manifest.final_rehash_pending = false;
        rehash_store
            .upsert_transfer_manifest(&rehash_manifest)
            .unwrap();
        let rehash_completed_at =
            transfer_completed_at_ms(&rehash_store, &rehash_manifest.file_hash).unwrap();
        assert_eq!(
            rehash_store
                .download_history_by_hash(&rehash_manifest.file_hash)
                .unwrap()
                .unwrap()
                .last_completed_at_ms,
            rehash_completed_at
        );

        let shared_store = MetadataStore::in_memory().unwrap();
        let mut shared_manifest = completed_download_manifest();
        shared_manifest.delivery_state = MetadataTransferDeliveryState::NotApplicable;
        shared_manifest.delivery_ownership = MetadataTransferDeliveryOwnership::None;
        shared_manifest.delivered_path = None;
        shared_manifest.source_path = Some("C:\\shared\\completed.bin".into());
        shared_store
            .upsert_transfer_manifest(&shared_manifest)
            .unwrap();
        assert_eq!(
            transfer_completed_at_ms(&shared_store, &shared_manifest.file_hash),
            None
        );
        assert!(
            shared_store
                .download_history_by_hash(&shared_manifest.file_hash)
                .unwrap()
                .is_none()
        );

        shared_manifest.delivery_state = MetadataTransferDeliveryState::Pending;
        shared_manifest.delivery_ownership = MetadataTransferDeliveryOwnership::None;
        shared_manifest.source_path = None;
        shared_store
            .upsert_transfer_manifest(&shared_manifest)
            .unwrap();
        let download_completed_at =
            transfer_completed_at_ms(&shared_store, &shared_manifest.file_hash).unwrap();
        assert_eq!(
            shared_store
                .download_history_by_hash(&shared_manifest.file_hash)
                .unwrap()
                .unwrap()
                .last_completed_at_ms,
            download_completed_at
        );
    }

    #[test]
    fn completion_timestamp_repairs_legacy_null_without_refreshing_history() {
        let store = MetadataStore::in_memory().unwrap();
        let mut manifest = completed_download_manifest();
        store.upsert_transfer_manifest(&manifest).unwrap();
        const HISTORICAL_COMPLETION_MS: i64 = 1_234;
        {
            let conn = store.connection().unwrap();
            conn.execute("UPDATE transfers SET completed_at_ms = NULL", [])
                .unwrap();
            conn.execute(
                r#"
                UPDATE download_history
                SET first_completed_at_ms = ?1, last_completed_at_ms = ?1
                "#,
                rusqlite::params![HISTORICAL_COMPLETION_MS],
            )
            .unwrap();
        }

        manifest.display_name = "legacy-repaired.bin".to_string();
        store.upsert_transfer_manifest(&manifest).unwrap();
        assert_eq!(
            transfer_completed_at_ms(&store, &manifest.file_hash),
            Some(HISTORICAL_COMPLETION_MS)
        );
        let history = store
            .download_history_by_hash(&manifest.file_hash)
            .unwrap()
            .unwrap();
        assert_eq!(history.first_completed_at_ms, HISTORICAL_COMPLETION_MS);
        assert_eq!(history.last_completed_at_ms, HISTORICAL_COMPLETION_MS);
        assert_eq!(history.display_name, "legacy-repaired.bin");
    }

    #[test]
    fn recompletion_does_not_regress_when_wall_clock_moves_backwards() {
        let store = MetadataStore::in_memory().unwrap();
        let manifest = completed_download_manifest();
        store.upsert_transfer_manifest(&manifest).unwrap();
        const FUTURE_COMPLETION_MS: i64 = 9_000_000_000_000;
        {
            let conn = store.connection().unwrap();
            conn.execute(
                "UPDATE transfers SET completed_at_ms = ?1",
                rusqlite::params![FUTURE_COMPLETION_MS],
            )
            .unwrap();
            conn.execute(
                r#"
                UPDATE download_history
                SET first_completed_at_ms = ?1, last_completed_at_ms = ?1
                "#,
                rusqlite::params![FUTURE_COMPLETION_MS],
            )
            .unwrap();
        }

        assert!(store.delete_transfer_manifest(&manifest.file_hash).unwrap());
        assert!(
            store
                .transfer_timestamps_by_hash(&manifest.file_hash)
                .unwrap()
                .is_none()
        );
        store.upsert_transfer_manifest(&manifest).unwrap();

        assert_eq!(
            transfer_completed_at_ms(&store, &manifest.file_hash),
            Some(FUTURE_COMPLETION_MS)
        );
        let history = store
            .download_history_by_hash(&manifest.file_hash)
            .unwrap()
            .unwrap();
        assert_eq!(history.first_completed_at_ms, FUTURE_COMPLETION_MS);
        assert_eq!(history.last_completed_at_ms, FUTURE_COMPLETION_MS);
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
