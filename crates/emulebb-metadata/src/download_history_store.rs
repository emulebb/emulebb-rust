use anyhow::{Context, Result, anyhow, ensure};
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
                       first_completed_at_s, last_completed_at_s
                FROM download_history
                WHERE ed2k_hash = ?1
                "#,
            )?
            .query_row(params![hash], |row| {
                Ok(MetadataDownloadHistoryEntry {
                    file_hash: row.get(0)?,
                    display_name: row.get(1)?,
                    file_size: crate::sql_value::unsigned::<u64>(row, 2)?,
                    aich_root: row.get(3)?,
                    first_completed_at_s: row.get(4)?,
                    last_completed_at_s: row.get(5)?,
                })
            })
            .optional()
            .map_err(Into::into)
    }

    /// Find the next eligible copy by path key, checking blob lengths before allocation.
    pub fn next_shared_copy(
        &self,
        file_hash: &str,
        after_path_id: i64,
        max_path_bytes: usize,
    ) -> Result<Option<crate::MetadataSharedCopyCandidate>> {
        ensure!(
            after_path_id >= 0 && max_path_bytes > 0,
            "invalid shared-copy cursor"
        );
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let mut stmt = conn.prepare_cached(concat!("SELECT i.path_id,length(p.native_path),length(i.verified_fingerprint),i.size_bytes,p.platform,p.native_path,i.verified_fingerprint FROM known_files k JOIN local_file_instances i ON i.known_file_id=k.id JOIN local_paths p ON p.id=i.path_id WHERE k.ed2k_hash=?1 AND i.path_id>?2 AND ", crate::local_catalog::unexcluded_identity_sql!("i"), " AND EXISTS (SELECT 1 FROM shared_file_memberships m JOIN shared_directory_roots r ON r.id=m.root_id WHERE m.path_id=i.path_id AND m.removed_at_ms IS NULL AND r.enabled=1 AND r.deleted_at_ms IS NULL AND r.accessible=1 AND r.shareable=1) ORDER BY i.path_id LIMIT 1"))?;
        let mut rows = stmt.query(params![hash, after_path_id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let path_bytes: i64 = row.get(1)?;
        let fingerprint_bytes: i64 = row.get(2)?;
        ensure!(
            usize::try_from(path_bytes)
                .ok()
                .is_some_and(|value| value <= max_path_bytes)
                && (0..=1024).contains(&fingerprint_bytes),
            "shared copy exceeds reconciliation budget"
        );
        Ok(Some(crate::MetadataSharedCopyCandidate {
            path_id: row.get(0)?,
            file_size: crate::sql_value::unsigned::<u64>(row, 3)?,
            source_path: path_from_row(row, 4, 5)?,
            source_fingerprint: optional_fingerprint_from_row(row, 6)?,
        }))
    }

    pub fn current_shared_files_by_hash(
        &self,
        file_hash: &str,
    ) -> Result<Vec<MetadataCurrentSharedFile>> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let mut statement = conn.prepare_cached(
            concat!(r#"
            SELECT DISTINCT known_files.display_name, local_file_instances.size_bytes,
                   local_paths.platform, local_paths.native_path,
                   local_file_instances.verified_fingerprint
            FROM local_file_instances
            JOIN known_files ON known_files.id = local_file_instances.known_file_id
            JOIN local_paths ON local_paths.id = local_file_instances.path_id
            JOIN shared_file_memberships ON shared_file_memberships.path_id = local_file_instances.path_id
            JOIN shared_directory_roots ON shared_directory_roots.id = shared_file_memberships.root_id
            WHERE known_files.ed2k_hash = ?1
              AND "#, crate::local_catalog::unexcluded_identity_sql!("local_file_instances"), r#"
              AND shared_file_memberships.removed_at_ms IS NULL
              AND shared_directory_roots.enabled = 1
              AND shared_directory_roots.deleted_at_ms IS NULL
              AND shared_directory_roots.accessible = 1
              AND shared_directory_roots.shareable = 1
            ORDER BY local_paths.native_path
            "#),
        )?;
        let rows = statement.query_map(params![hash], |row| {
            let path = path_from_row(row, 2, 3)?;
            let name: String = row.get(0)?;
            Ok(MetadataCurrentSharedFile {
                display_name: crate::NativePath::from(path.as_path())
                    .display_file_name()
                    .unwrap_or(name),
                file_size: crate::sql_value::unsigned::<u64>(row, 1)?,
                source_path: path,
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
    completed_at_s: Option<i64>,
    completion_transition: bool,
) -> Result<()> {
    if !records_download_completion(manifest) {
        return Ok(());
    }
    let completed_at_s = completed_at_s.ok_or_else(|| {
        anyhow!(
            "completed download {} has no completion timestamp",
            manifest.file_hash
        )
    })?;

    let existing = tx
        .prepare_cached("SELECT size_bytes, aich_root FROM download_history WHERE ed2k_hash = ?1")?
        .query_row(params![hash], |row| {
            Ok((
                crate::sql_value::unsigned::<u64>(row, 0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
            ))
        })
        .optional()?;
    if let Some((existing_size, existing_aich_root)) = existing {
        ensure!(
            existing_size
                == manifest
                    .expected_size_bytes
                    .context("verified download has unknown size")?,
            "completed download history for {} has size {existing_size}, not {}",
            manifest.file_hash,
            manifest
                .expected_size_bytes
                .context("verified download has unknown size")?
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
            first_completed_at_s, last_completed_at_s
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?5)
        ON CONFLICT(ed2k_hash) DO UPDATE SET
            display_name = excluded.display_name,
            aich_root = coalesce(excluded.aich_root, download_history.aich_root),
            last_completed_at_s = CASE
                WHEN ?6 THEN excluded.last_completed_at_s
                ELSE download_history.last_completed_at_s
            END
        "#,
    )?
    .execute(params![
        hash,
        i64::try_from(
            manifest
                .expected_size_bytes
                .context("verified download has unknown size")?
        )?,
        manifest.display_name,
        aich_root,
        completed_at_s,
        completion_transition,
    ])?;
    Ok(())
}

pub(crate) fn records_download_completion(manifest: &MetadataTransferManifest) -> bool {
    manifest.completed && !manifest.final_rehash_pending
}

#[cfg(test)]
mod tests {
    use crate::{
        MetadataStore, MetadataTransferDeliveryOwnership, MetadataTransferDeliveryState,
        MetadataTransferManifest, MetadataTransferPiece, MetadataTransferRange,
    };

    fn completed_download_manifest(store: &MetadataStore) -> MetadataTransferManifest {
        MetadataTransferManifest {
            token: store
                .admit_download_job(&crate::DownloadJobRequest {
                    file_hash: "00112233445566778899aabbccddeeff".to_string(),
                    display_name: "completed.bin".to_string(),
                    expected_size_bytes: Some(1024),
                    category_id: None,
                    intent: crate::DownloadIntent::Started,
                    piece_size: 1024,
                })
                .unwrap()
                .job
                .token,
            file_hash: "00112233445566778899aabbccddeeff".to_string(),
            display_name: "completed.bin".to_string(),
            expected_size_bytes: Some(1024),
            piece_size: 1024,
            completed: true,
            final_rehash_pending: false,
            md4_hashset_acquired: true,
            md4_hashset: Vec::new(),
            aich_hashset_acquired: true,
            aich_root: Some("1111111111111111111111111111111111111111".to_string()),
            aich_root_origin: Some("local_computed".to_string()),
            aich_trust_generation: 1,
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
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
            category_id: None,
            intent: crate::DownloadIntent::Started,
            transfer_row_removed: false,
            delivery_state: MetadataTransferDeliveryState::Delivered,
            delivery_ownership: MetadataTransferDeliveryOwnership::Unowned,
            delivered_path: Some("C:\\incoming\\completed.bin".into()),
            source_fingerprint: None,
            payload_fingerprint: None,
        }
    }

    fn transfer_completed_at_s(store: &MetadataStore, id: crate::JobId) -> Option<i64> {
        store.download_job_timestamps(id).unwrap().unwrap().1
    }

    #[test]
    fn authoritative_download_completion_survives_manifest_deletion() {
        let store = MetadataStore::in_memory().unwrap();
        let manifest = completed_download_manifest(&store);
        store.upsert_transfer_manifest(&manifest).unwrap();
        assert!(
            store
                .delete_transfer_manifest(manifest.token.job_id)
                .unwrap()
        );

        let history = store
            .download_history_by_hash(&manifest.file_hash)
            .unwrap()
            .unwrap();
        assert_eq!(history.file_hash, manifest.file_hash);
        assert_eq!(history.display_name, manifest.display_name);
        assert_eq!(history.file_size, manifest.expected_size_bytes.unwrap());
        assert_eq!(history.aich_root, manifest.aich_root);
        assert!(history.first_completed_at_s <= history.last_completed_at_s);
    }

    #[test]
    fn incomplete_manifests_do_not_create_download_history() {
        let store = MetadataStore::in_memory().unwrap();
        let mut manifest = completed_download_manifest(&store);
        manifest.completed = false;
        manifest.delivery_state = MetadataTransferDeliveryState::Pending;
        manifest.delivery_ownership = MetadataTransferDeliveryOwnership::None;
        manifest.delivered_path = None;
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
        let mut manifest = completed_download_manifest(&store);
        manifest.completed = false;
        manifest.delivery_state = MetadataTransferDeliveryState::Pending;
        manifest.delivery_ownership = MetadataTransferDeliveryOwnership::None;
        manifest.delivered_path = None;
        store.upsert_transfer_manifest(&manifest).unwrap();
        assert_eq!(transfer_completed_at_s(&store, manifest.token.job_id), None);
        assert!(
            store
                .download_history_by_hash(&manifest.file_hash)
                .unwrap()
                .is_none()
        );

        manifest.completed = true;
        manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
        manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Unowned;
        manifest.delivered_path = Some(std::env::temp_dir().join("completed.bin"));
        store.upsert_transfer_manifest(&manifest).unwrap();
        const FIRST_COMPLETION_S: i64 = 1_000;
        {
            let conn = store.connection().unwrap();
            conn.execute(
                "UPDATE download_jobs SET completed_at_s = ?1",
                rusqlite::params![FIRST_COMPLETION_S],
            )
            .unwrap();
            conn.execute(
                r#"
                UPDATE download_history
                SET first_completed_at_s = ?1, last_completed_at_s = ?1
                "#,
                rusqlite::params![FIRST_COMPLETION_S],
            )
            .unwrap();
        }

        manifest.display_name = "renamed.bin".to_string();
        manifest.aich_root = None;
        manifest.aich_root_origin = None;
        manifest.aich_hashset_acquired = false;
        store.upsert_transfer_manifest(&manifest).unwrap();
        let metadata_refresh = store
            .download_history_by_hash(&manifest.file_hash)
            .unwrap()
            .unwrap();
        // Checkpoint replay cannot rename the chosen job or its completion fact.
        assert_eq!(metadata_refresh.display_name, "completed.bin");
        assert_eq!(
            store
                .download_job(manifest.token.job_id)
                .unwrap()
                .unwrap()
                .display_name,
            "completed.bin"
        );
        assert_eq!(
            metadata_refresh.aich_root.as_deref(),
            Some("1111111111111111111111111111111111111111")
        );
        assert_eq!(metadata_refresh.first_completed_at_s, FIRST_COMPLETION_S);
        assert_eq!(metadata_refresh.last_completed_at_s, FIRST_COMPLETION_S);
        assert_eq!(
            transfer_completed_at_s(&store, manifest.token.job_id),
            Some(FIRST_COMPLETION_S)
        );

        // A second completion is a distinct attempt; durable Delivered state
        // and the first job's timestamps must never be rewound to manufacture it.
        let first_token = manifest.token;
        store
            .upsert_verified_local_content(&crate::MetadataVerifiedLocalContent {
                secondary_identity: None,
                file_hash: manifest.file_hash.clone(),
                display_name: manifest.display_name.clone(),
                file_size: 1024,
                part_size: 1024,
                md4_hashset: Vec::new(),
                aich_root: metadata_refresh.aich_root.clone(),
                aich_hashset: Vec::new(),
                path: manifest.delivered_path.clone().unwrap(),
                fingerprint: crate::NativeFileFingerprint {
                    identity: crate::NativeFileIdentity::Unix {
                        device_id: 1,
                        inode_number: 2,
                    },
                    size_bytes: 1024,
                    modified: crate::NativeFileTimestamp::new(1, 0).unwrap(),
                    changed: None,
                },
                upload_priority: "normal".into(),
                auto_upload_priority: false,
                comment: String::new(),
                rating: 0,
            })
            .unwrap();
        assert!(store.request_transfer_retirement(first_token).unwrap());
        assert!(
            store
                .finalize_transfer_retirement(first_token.job_id)
                .unwrap()
        );
        let second = store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: manifest.file_hash.clone(),
                display_name: "second.bin".into(),
                expected_size_bytes: Some(1024),
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: 1024,
            })
            .unwrap()
            .job;
        assert_ne!(second.token.job_id, first_token.job_id);
        manifest.token = second.token;
        manifest.delivery_state = MetadataTransferDeliveryState::Pending;
        manifest.delivery_ownership = MetadataTransferDeliveryOwnership::None;
        manifest.delivered_path = None;
        manifest.completed = false;
        manifest.verified_ranges.clear();
        manifest.pieces[0].state = "Missing".into();
        manifest.pieces[0].bytes_written = 0;
        store.upsert_transfer_manifest(&manifest).unwrap();
        assert_eq!(transfer_completed_at_s(&store, second.token.job_id), None);
        assert_eq!(
            transfer_completed_at_s(&store, first_token.job_id),
            Some(FIRST_COMPLETION_S)
        );
        assert_eq!(
            store
                .download_history_by_hash(&manifest.file_hash)
                .unwrap()
                .unwrap()
                .last_completed_at_s,
            FIRST_COMPLETION_S
        );
        manifest.completed = true;
        manifest.display_name = "completed-again.bin".into();
        assert!(
            store
                .apply_download_peer_delta(
                    manifest.token,
                    &crate::MetadataDownloadPeerDelta::Rename(manifest.display_name.clone()),
                )
                .unwrap()
                .changed
        );
        manifest.verified_ranges = vec![MetadataTransferRange {
            start: 0,
            end: 1024,
        }];
        manifest.pieces[0].state = "Verified".into();
        manifest.pieces[0].bytes_written = 1024;
        manifest.delivery_state = MetadataTransferDeliveryState::Delivered;
        manifest.delivery_ownership = MetadataTransferDeliveryOwnership::Unowned;
        manifest.delivered_path = Some(std::env::temp_dir().join("completed-again.bin"));
        store.upsert_transfer_manifest(&manifest).unwrap();
        let recompleted_at_s = transfer_completed_at_s(&store, manifest.token.job_id).unwrap();
        let recompleted_history = store
            .download_history_by_hash(&manifest.file_hash)
            .unwrap()
            .unwrap();
        assert!(recompleted_at_s > FIRST_COMPLETION_S);
        assert_eq!(recompleted_history.first_completed_at_s, FIRST_COMPLETION_S);
        assert_eq!(recompleted_history.last_completed_at_s, recompleted_at_s);
        assert_eq!(recompleted_history.display_name, "completed-again.bin");
        assert_eq!(
            transfer_completed_at_s(&store, first_token.job_id),
            Some(FIRST_COMPLETION_S)
        );
    }

    #[test]
    fn only_authoritative_download_completion_starts_timestamps() {
        let rehash_store = MetadataStore::in_memory().unwrap();
        let mut rehash_manifest = completed_download_manifest(&rehash_store);
        rehash_manifest.final_rehash_pending = true;
        rehash_manifest.delivery_state = MetadataTransferDeliveryState::Pending;
        rehash_manifest.delivery_ownership = MetadataTransferDeliveryOwnership::None;
        rehash_manifest.delivered_path = None;
        rehash_store
            .upsert_transfer_manifest(&rehash_manifest)
            .unwrap();
        assert_eq!(
            transfer_completed_at_s(&rehash_store, rehash_manifest.token.job_id),
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
            transfer_completed_at_s(&rehash_store, rehash_manifest.token.job_id).unwrap();
        assert_eq!(
            rehash_store
                .download_history_by_hash(&rehash_manifest.file_hash)
                .unwrap()
                .unwrap()
                .last_completed_at_s,
            rehash_completed_at
        );
    }

    #[test]
    fn recompletion_does_not_regress_when_wall_clock_moves_backwards() {
        let store = MetadataStore::in_memory().unwrap();
        let mut manifest = completed_download_manifest(&store);
        store.upsert_transfer_manifest(&manifest).unwrap();
        const FUTURE_COMPLETION_MS: i64 = 9_000_000_000_000;
        {
            let conn = store.connection().unwrap();
            conn.execute(
                "UPDATE download_jobs SET completed_at_s = ?1",
                rusqlite::params![FUTURE_COMPLETION_MS],
            )
            .unwrap();
            conn.execute(
                r#"
                UPDATE download_history
                SET first_completed_at_s = ?1, last_completed_at_s = ?1
                "#,
                rusqlite::params![FUTURE_COMPLETION_MS],
            )
            .unwrap();
        }

        assert!(
            store
                .delete_transfer_manifest(manifest.token.job_id)
                .unwrap()
        );
        assert!(
            store
                .download_job_timestamps(manifest.token.job_id)
                .unwrap()
                .is_none()
        );
        manifest.token = completed_download_manifest(&store).token;
        store.upsert_transfer_manifest(&manifest).unwrap();

        assert_eq!(
            transfer_completed_at_s(&store, manifest.token.job_id),
            Some(FUTURE_COMPLETION_MS)
        );
        let history = store
            .download_history_by_hash(&manifest.file_hash)
            .unwrap()
            .unwrap();
        assert_eq!(history.first_completed_at_s, FUTURE_COMPLETION_MS);
        assert_eq!(history.last_completed_at_s, FUTURE_COMPLETION_MS);
    }

    #[test]
    fn conflicting_completed_identity_rolls_back_manifest_update() {
        let store = MetadataStore::in_memory().unwrap();
        let mut manifest = completed_download_manifest(&store);
        store.upsert_transfer_manifest(&manifest).unwrap();

        manifest.expected_size_bytes = manifest.expected_size_bytes.map(|size| size + 1);
        let error = store.upsert_transfer_manifest(&manifest).unwrap_err();
        assert!(error.is::<crate::MetadataContentConflict>());
        assert_eq!(
            store
                .download_job_manifest(manifest.token.job_id)
                .unwrap()
                .unwrap()
                .expected_size_bytes,
            Some(1024)
        );
        store
            .delete_transfer_manifest(manifest.token.job_id)
            .unwrap();
        let error = store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: manifest.file_hash.clone(),
                display_name: manifest.display_name.clone(),
                expected_size_bytes: manifest.expected_size_bytes,
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: manifest.piece_size,
            })
            .unwrap_err();
        assert!(error.is::<crate::MetadataContentConflict>());
        assert_eq!(store.table_count("download_jobs").unwrap(), 0);
    }
}
