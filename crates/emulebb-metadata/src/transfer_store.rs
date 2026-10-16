use std::path::Path;

use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{
    NativeFileFingerprint, NativePath,
    download_history_store::{record_completed_download, records_download_completion},
    native_path::{optional_path_from_row, path_from_row},
    store::{bool_to_i64, decode_fixed_hex, unix_ms, upsert_local_path},
    transfer_model::{
        MetadataDeliveredReuseEntry, MetadataImportedKnownFileEntry,
        MetadataShareInPlaceReloadEntry, MetadataSharedSourceFailure, MetadataTransferCatalogEntry,
        MetadataTransferCounts, MetadataTransferDeliveryState, MetadataTransferManifest,
        MetadataTransferMediaMetadata, MetadataTransferPiece, MetadataTransferPublishEntry,
        MetadataTransferRange, MetadataTransferShareEntry, MetadataTransferSource,
    },
};

impl super::MetadataStore {
    pub fn upsert_transfer_manifest(&self, manifest: &MetadataTransferManifest) -> Result<()> {
        validate_delivery_state(manifest)?;
        let hash = decode_fixed_hex(&manifest.file_hash, 16, "ED2K hash")?;
        let aich_root = optional_fixed_hex(manifest.aich_root.as_deref(), 20, "AICH root")?;
        let now = unix_ms();
        let mut conn = self.connection()?;
        // WHY: this transaction reads deletion authority before writing paths and
        // transfer rows. A deferred WAL transaction can retain a stale read
        // snapshot and fail its write upgrade with SQLITE_BUSY_SNAPSHOT after a
        // concurrent connection commits; acquire the writer slot before reading.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let deletion_requested = tx
            .query_row(
                r#"
                SELECT transfers.delete_requested_at_ms IS NOT NULL
                FROM known_files
                JOIN transfers ON transfers.known_file_id = known_files.id
                WHERE known_files.ed2k_hash = ?1
                "#,
                params![hash],
                |row| row.get::<_, bool>(0),
            )
            .optional()?
            .unwrap_or(false);
        ensure!(
            !deletion_requested,
            "transfer {} has a pending destructive deletion",
            manifest.file_hash
        );
        let previous_completion = tx
            .query_row(
                r#"
                SELECT known_files.completed, transfers.final_rehash_pending,
                       transfers.source_path_id IS NULL, transfers.completed_at_ms
                FROM known_files
                JOIN transfers ON transfers.known_file_id = known_files.id
                WHERE known_files.ed2k_hash = ?1
                "#,
                params![hash],
                |row| {
                    Ok((
                        row.get::<_, bool>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .optional()?;
        let previous_history_completed_at_ms = tx
            .prepare_cached(
                "SELECT last_completed_at_ms FROM download_history WHERE ed2k_hash = ?1",
            )?
            .query_row(params![hash], |row| row.get::<_, i64>(0))
            .optional()?;
        let previous_records_completion = previous_completion
            .map(|(completed, final_rehash_pending, source_path_absent, _)| {
                completed && !final_rehash_pending && source_path_absent
            })
            .unwrap_or(false);
        let records_completion = records_download_completion(manifest);
        let completion_transition = records_completion && !previous_records_completion;
        let previous_completed_at_ms =
            previous_completion.and_then(|(_, _, _, completed_at_ms)| completed_at_ms);
        let completion_timestamp_repair =
            records_completion && previous_records_completion && previous_completed_at_ms.is_none();
        let completion_timestamp_update = completion_transition || completion_timestamp_repair;
        let completed_at_ms = if completion_transition {
            Some(
                now.max(previous_completed_at_ms.unwrap_or(0))
                    .max(previous_history_completed_at_ms.unwrap_or(0)),
            )
        } else if completion_timestamp_repair {
            Some(previous_history_completed_at_ms.unwrap_or(now))
        } else {
            previous_completed_at_ms
        };
        let delivered_path_id = optional_local_path_id(&tx, manifest.delivered_path.as_deref())?;
        let source_path_id = optional_local_path_id(&tx, manifest.source_path.as_deref())?;
        let source_fingerprint = manifest
            .source_fingerprint
            .as_ref()
            .map(NativeFileFingerprint::storage_bytes);
        let payload_fingerprint = manifest
            .payload_fingerprint
            .as_ref()
            .map(NativeFileFingerprint::storage_bytes);

        tx.prepare_cached(
            r#"
            INSERT INTO known_files(
                ed2k_hash, size_bytes, display_name,
                part_size, part_count, completed, md4_hashset_acquired,
                aich_hashset_acquired, aich_root, upload_priority,
                auto_upload_priority, comment, rating,
                first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?14, ?14)
            ON CONFLICT(ed2k_hash) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                display_name = excluded.display_name,
                part_size = excluded.part_size,
                part_count = excluded.part_count,
                completed = excluded.completed,
                md4_hashset_acquired = excluded.md4_hashset_acquired,
                aich_hashset_acquired = excluded.aich_hashset_acquired,
                aich_root = excluded.aich_root,
                upload_priority = excluded.upload_priority,
                auto_upload_priority = excluded.auto_upload_priority,
                comment = excluded.comment,
                rating = excluded.rating,
                last_seen_ms = excluded.last_seen_ms,
                updated_at_ms = excluded.updated_at_ms
            "#,
        )?
        .execute(params![
            hash,
            manifest.file_size as i64,
            manifest.display_name,
            manifest.piece_size as i64,
            manifest.pieces.len() as i64,
            bool_to_i64(manifest.completed),
            bool_to_i64(manifest.md4_hashset_acquired),
            bool_to_i64(manifest.aich_hashset_acquired),
            aich_root,
            manifest.upload_priority,
            bool_to_i64(manifest.auto_upload_priority),
            manifest.comment,
            i64::from(manifest.rating),
            now,
        ])?;
        let known_file_id: i64 = tx
            .prepare_cached("SELECT id FROM known_files WHERE ed2k_hash = ?1")?
            .query_row(
                params![decode_fixed_hex(&manifest.file_hash, 16, "ED2K hash")?],
                |row| row.get(0),
            )?;

        tx.prepare_cached(
            r#"
            INSERT INTO transfers(
                known_file_id, visible_state, final_rehash_pending, control_state, download_priority,
                category_id, payload_directory, delivery_state, delivered_path_id, source_path_id,
                source_fingerprint, payload_fingerprint, created_at_ms, updated_at_ms,
                completed_at_ms, removed_at_ms
            )
            VALUES (?1, ?2, ?13, ?3, 'normal', ?4, ?5, ?14, ?6, ?10, ?11, ?12, ?7, ?7, ?8, ?9)
            ON CONFLICT(known_file_id) DO UPDATE SET
                visible_state = excluded.visible_state,
                final_rehash_pending = excluded.final_rehash_pending,
                control_state = excluded.control_state,
                category_id = excluded.category_id,
                payload_directory = excluded.payload_directory,
                delivery_state = excluded.delivery_state,
                delivered_path_id = excluded.delivered_path_id,
                source_path_id = excluded.source_path_id,
                source_fingerprint = excluded.source_fingerprint,
                payload_fingerprint = excluded.payload_fingerprint,
                updated_at_ms = excluded.updated_at_ms,
                completed_at_ms = CASE
                    WHEN ?15 THEN excluded.completed_at_ms
                    ELSE transfers.completed_at_ms
                END,
                removed_at_ms = excluded.removed_at_ms
            "#,
        )?
        .execute(params![
            known_file_id,
            visible_state(manifest),
            manifest.control_state,
            (manifest.category_id != 0).then_some(i64::from(manifest.category_id)),
            manifest.file_hash,
            delivered_path_id,
            now,
            completed_at_ms,
            if manifest.transfer_row_removed {
                Some(now)
            } else {
                None
            },
            source_path_id,
            source_fingerprint,
            payload_fingerprint,
            bool_to_i64(manifest.final_rehash_pending),
            delivery_state_to_sql(manifest.delivery_state),
            completion_timestamp_update,
        ])?;
        let transfer_id: i64 = tx
            .prepare_cached("SELECT id FROM transfers WHERE known_file_id = ?1")?
            .query_row(params![known_file_id], |row| row.get(0))?;
        if let Some(source_path_id) = source_path_id {
            tx.prepare_cached(
                r#"
                INSERT INTO shared_file_sources(
                    known_file_id, path_id, file_size, source_fingerprint,
                    created_at_ms, updated_at_ms
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                ON CONFLICT(path_id) DO UPDATE SET
                    known_file_id = excluded.known_file_id,
                    file_size = excluded.file_size,
                    source_fingerprint = excluded.source_fingerprint,
                    updated_at_ms = excluded.updated_at_ms
                "#,
            )?
            .execute(params![
                known_file_id,
                source_path_id,
                manifest.file_size as i64,
                manifest
                    .source_fingerprint
                    .as_ref()
                    .map(NativeFileFingerprint::storage_bytes),
                now,
            ])?;
            tx.prepare_cached("DELETE FROM shared_file_scan_failures WHERE path_id = ?1")?
                .execute(params![source_path_id])?;
        }

        replace_transfer_children(&tx, known_file_id, transfer_id, manifest, now)?;
        record_completed_download(
            &tx,
            manifest,
            &hash,
            aich_root.as_deref(),
            completed_at_ms,
            completion_transition,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn transfer_manifest_by_hash(
        &self,
        file_hash: &str,
    ) -> Result<Option<MetadataTransferManifest>> {
        self.transfer_manifest_by_hash_for_deletion_state(file_hash, false)
    }

    /// Read the manifest retained solely to resume a pending destructive
    /// deletion. Normal manifest reads deliberately suppress this row.
    pub fn pending_transfer_deletion_manifest_by_hash(
        &self,
        file_hash: &str,
    ) -> Result<Option<MetadataTransferManifest>> {
        self.transfer_manifest_by_hash_for_deletion_state(file_hash, true)
    }

    fn transfer_manifest_by_hash_for_deletion_state(
        &self,
        file_hash: &str,
        deletion_requested: bool,
    ) -> Result<Option<MetadataTransferManifest>> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let row = conn
            .prepare_cached(
                r#"
                SELECT known_files.id, transfers.id,
                       lower(hex(known_files.ed2k_hash)), known_files.display_name,
                       known_files.size_bytes, coalesce(known_files.part_size, 0),
                       known_files.completed, known_files.md4_hashset_acquired,
                       known_files.aich_hashset_acquired,
                       CASE
                           WHEN known_files.aich_root IS NULL THEN NULL
                           ELSE lower(hex(known_files.aich_root))
                       END,
                       known_files.upload_priority, known_files.auto_upload_priority,
                       known_files.comment, known_files.rating,
                       transfers.category_id, transfers.control_state, transfers.removed_at_ms,
                       delivered_paths.platform, delivered_paths.native_path,
                       source_paths.platform, source_paths.native_path,
                       transfers.source_fingerprint, transfers.payload_fingerprint,
                       transfers.final_rehash_pending, transfers.delivery_state
                FROM known_files
                JOIN transfers ON transfers.known_file_id = known_files.id
                LEFT JOIN local_paths delivered_paths ON delivered_paths.id = transfers.delivered_path_id
                LEFT JOIN local_paths source_paths ON source_paths.id = transfers.source_path_id
                WHERE known_files.ed2k_hash = ?1
                  AND (
                      (?2 = 0 AND transfers.delete_requested_at_ms IS NULL)
                      OR (?2 != 0 AND transfers.delete_requested_at_ms IS NOT NULL)
                  )
                "#,
            )?
            .query_row(params![hash, bool_to_i64(deletion_requested)], |row| {
                Ok(TransferRow {
                    known_file_id: row.get(0)?,
                    transfer_id: row.get(1)?,
                    file_hash: row.get(2)?,
                    display_name: row.get(3)?,
                    file_size: row.get::<_, i64>(4)? as u64,
                    piece_size: row.get::<_, i64>(5)? as u64,
                    completed: row.get::<_, i64>(6)? != 0,
                    md4_hashset_acquired: row.get::<_, i64>(7)? != 0,
                    aich_hashset_acquired: row.get::<_, i64>(8)? != 0,
                    aich_root: row.get(9)?,
                    upload_priority: row.get(10)?,
                    auto_upload_priority: row.get::<_, i64>(11)? != 0,
                    comment: row.get(12)?,
                    rating: row.get::<_, i64>(13)? as u8,
                    category_id: row.get::<_, Option<i64>>(14)?.unwrap_or_default() as u32,
                    control_state: row.get(15)?,
                    transfer_row_removed: row.get::<_, Option<i64>>(16)?.is_some(),
                    delivered_path: optional_path_from_row(row, 17, 18)?,
                    source_path: optional_path_from_row(row, 19, 20)?,
                    source_fingerprint: optional_fingerprint_from_row(row, 21)?,
                    payload_fingerprint: optional_fingerprint_from_row(row, 22)?,
                    final_rehash_pending: row.get::<_, i64>(23)? != 0,
                    delivery_state: row.get(24)?,
                })
            })
            .optional()?;
        row.map(|row| manifest_from_row(&conn, row)).transpose()
    }

    /// Persist ONE piece's progress fields for an already-persisted transfer
    /// manifest — the per-block download checkpoint. This is the lightweight
    /// sibling of `upsert_transfer_manifest`: mid-piece progress only ever
    /// changes the piece row itself (state / bytes_written / block_bitmap /
    /// ich_corrupted), so rewriting every child table (all pieces + both
    /// hashsets + ranges + sources) per received block was pure write
    /// amplification. Structural transitions (piece verified/failed, hashset
    /// acquisition, completion, source changes) still take the full upsert.
    ///
    /// Returns `false` when the transfer or piece row does not exist yet, so
    /// the caller can fall back to the full upsert.
    pub fn checkpoint_transfer_piece_progress(
        &self,
        file_hash: &str,
        piece: &MetadataTransferPiece,
    ) -> Result<bool> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let now = unix_ms();
        let conn = self.connection()?;
        let updated = conn
            .prepare_cached(
                r#"
                UPDATE transfer_pieces
                SET state = ?3, bytes_written = ?4, block_bitmap = ?5,
                    ich_corrupted = ?6, updated_at_ms = ?7
                WHERE piece_index = ?2
                  AND transfer_id = (
                      SELECT transfers.id
                      FROM transfers
                      JOIN known_files ON known_files.id = transfers.known_file_id
                      WHERE known_files.ed2k_hash = ?1
                        AND transfers.delete_requested_at_ms IS NULL
                  )
                "#,
            )?
            .execute(params![
                hash,
                i64::from(piece.piece_index),
                piece.state,
                piece.bytes_written as i64,
                piece.block_bitmap,
                piece.ich_corrupted,
                now,
            ])?;
        Ok(updated != 0)
    }

    /// Add `delta` lifetime-uploaded bytes to a known file (eMule all-time
    /// transferred accounting). No-op for an unknown hash or a zero delta;
    /// returns `true` when a row was updated.
    pub fn add_file_all_time_uploaded(&self, file_hash: &str, delta: u64) -> Result<bool> {
        if delta == 0 {
            return Ok(false);
        }
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let updated = conn
            .prepare_cached(
                r#"
                UPDATE known_files
                SET all_time_uploaded_bytes = all_time_uploaded_bytes + ?2
                WHERE ed2k_hash = ?1
                "#,
            )?
            .execute(params![hash, delta as i64])?;
        Ok(updated != 0)
    }

    /// Record one inbound upload request for a known file.
    pub fn add_file_upload_request(&self, file_hash: &str, at_ms: i64) -> Result<bool> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let updated = conn
            .prepare_cached(
                r#"
                UPDATE known_files
                SET all_time_upload_requests = all_time_upload_requests + 1,
                    last_upload_request_ms = max(last_upload_request_ms, ?2)
                WHERE ed2k_hash = ?1
                "#,
            )?
            .execute(params![hash, at_ms])?;
        Ok(updated != 0)
    }

    /// Record one accepted upload request for a known file.
    pub fn add_file_upload_accept(&self, file_hash: &str) -> Result<bool> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let updated = conn
            .prepare_cached(
                r#"
                UPDATE known_files
                SET all_time_upload_accepts = all_time_upload_accepts + 1
                WHERE ed2k_hash = ?1
                "#,
            )?
            .execute(params![hash])?;
        Ok(updated != 0)
    }

    /// Returns the file's persisted `(all_time_uploaded_bytes, size_bytes)`,
    /// or `None` for an unknown hash (so the caller can mirror eMule's
    /// `pRequestedFile == NULL` early return rather than treating an unknown
    /// file as a zero ratio). The caller computes the all-time upload ratio
    /// (eMule `CKnownFile::GetAllTimeUploadRatio`) so parked, not-yet-flushed
    /// uploaded deltas can be added on top of the persisted total.
    pub fn file_all_time_upload_totals(&self, file_hash: &str) -> Result<Option<(u64, u64)>> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        conn.prepare_cached(
            r#"
            SELECT all_time_uploaded_bytes, size_bytes
            FROM known_files
            WHERE ed2k_hash = ?1
            "#,
        )?
        .query_row(params![hash], |row| {
            Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64))
        })
        .optional()
        .map_err(Into::into)
    }

    /// Returns the persisted `(created_at_ms, completed_at_ms)` for a transfer,
    /// used to surface `addedAt` / `completedAt` in the REST transfer view.
    pub fn transfer_timestamps_by_hash(
        &self,
        file_hash: &str,
    ) -> Result<Option<(i64, Option<i64>)>> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        conn.query_row(
            r#"
            SELECT transfers.created_at_ms, transfers.completed_at_ms
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE known_files.ed2k_hash = ?1
              AND transfers.delete_requested_at_ms IS NULL
            "#,
            params![hash],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn transfer_manifests(&self) -> Result<Vec<MetadataTransferManifest>> {
        self.transfer_manifests_filtered("")
    }

    /// Persisted transfer-list rows only. Completed shared catalog entries whose
    /// transfer row was removed remain available to upload/sharing code but do
    /// not belong in the operator-facing transfer list.
    pub fn active_transfer_manifests(&self) -> Result<Vec<MetadataTransferManifest>> {
        self.transfer_manifests_filtered("AND transfers.removed_at_ms IS NULL")
    }

    /// Persisted INCOMPLETE download manifests only (`known_files.completed = 0`) —
    /// the startup-resume set. Orders of magnitude smaller than the full (mostly
    /// completed) library, so this can be loaded on startup without hauling every
    /// row like `transfer_manifests`.
    pub fn incomplete_transfer_manifests(&self) -> Result<Vec<MetadataTransferManifest>> {
        self.transfer_manifests_filtered("AND known_files.completed = 0")
    }

    /// Every persisted download whose canonical payload is owned by the
    /// internal transfer root. Includes incomplete, completed, and
    /// operator-hidden rows; excludes share-in-place files and pending
    /// destructive deletions.
    pub fn managed_download_transfer_manifests(&self) -> Result<Vec<MetadataTransferManifest>> {
        self.transfer_manifests_filtered("AND transfers.source_path_id IS NULL")
    }

    fn transfer_manifests_filtered(
        &self,
        where_clause: &str,
    ) -> Result<Vec<MetadataTransferManifest>> {
        let conn = self.connection()?;
        let sql = format!(
            r#"
            SELECT known_files.id, transfers.id,
                   lower(hex(known_files.ed2k_hash)), known_files.display_name,
                   known_files.size_bytes, coalesce(known_files.part_size, 0),
                   known_files.completed, known_files.md4_hashset_acquired,
                   known_files.aich_hashset_acquired,
                   CASE
                       WHEN known_files.aich_root IS NULL THEN NULL
                       ELSE lower(hex(known_files.aich_root))
                   END,
                   known_files.upload_priority, known_files.auto_upload_priority,
                   known_files.comment, known_files.rating,
                   transfers.category_id, transfers.control_state, transfers.removed_at_ms,
                   delivered_paths.platform, delivered_paths.native_path,
                   source_paths.platform, source_paths.native_path,
                   transfers.source_fingerprint, transfers.payload_fingerprint,
                   transfers.final_rehash_pending, transfers.delivery_state
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            LEFT JOIN local_paths delivered_paths ON delivered_paths.id = transfers.delivered_path_id
            LEFT JOIN local_paths source_paths ON source_paths.id = transfers.source_path_id
            WHERE transfers.delete_requested_at_ms IS NULL
            {where_clause}
            ORDER BY known_files.ed2k_hash
            "#
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(TransferRow {
                known_file_id: row.get(0)?,
                transfer_id: row.get(1)?,
                file_hash: row.get(2)?,
                display_name: row.get(3)?,
                file_size: row.get::<_, i64>(4)? as u64,
                piece_size: row.get::<_, i64>(5)? as u64,
                completed: row.get::<_, i64>(6)? != 0,
                md4_hashset_acquired: row.get::<_, i64>(7)? != 0,
                aich_hashset_acquired: row.get::<_, i64>(8)? != 0,
                aich_root: row.get(9)?,
                upload_priority: row.get(10)?,
                auto_upload_priority: row.get::<_, i64>(11)? != 0,
                comment: row.get(12)?,
                rating: row.get::<_, i64>(13)? as u8,
                category_id: row.get::<_, Option<i64>>(14)?.unwrap_or_default() as u32,
                control_state: row.get(15)?,
                transfer_row_removed: row.get::<_, Option<i64>>(16)?.is_some(),
                delivered_path: optional_path_from_row(row, 17, 18)?,
                source_path: optional_path_from_row(row, 19, 20)?,
                source_fingerprint: optional_fingerprint_from_row(row, 21)?,
                payload_fingerprint: optional_fingerprint_from_row(row, 22)?,
                final_rehash_pending: row.get::<_, i64>(23)? != 0,
                delivery_state: row.get(24)?,
            })
        })?;
        rows.map(|row| manifest_from_row(&conn, row?))
            .collect::<Result<Vec<_>>>()
    }

    pub fn completed_transfer_catalog_entries(&self) -> Result<Vec<MetadataTransferCatalogEntry>> {
        self.completed_transfer_catalog_entries_filtered(None, usize::MAX)
    }

    /// Return one hash-keyset page of completed shared-catalog entries.
    ///
    /// Startup uses this to expose one publishable server batch without loading
    /// a 100k-file catalog synchronously. The remaining pages can then hydrate
    /// on a blocking worker while REST and network startup continue.
    pub fn completed_transfer_catalog_entries_after(
        &self,
        after_hash: Option<&str>,
        limit: usize,
    ) -> Result<Vec<MetadataTransferCatalogEntry>> {
        self.completed_transfer_catalog_entries_filtered(after_hash, limit)
    }

    fn completed_transfer_catalog_entries_filtered(
        &self,
        after_hash: Option<&str>,
        limit: usize,
    ) -> Result<Vec<MetadataTransferCatalogEntry>> {
        let after_hash = after_hash
            .map(|hash| decode_fixed_hex(hash, 16, "ED2K hash"))
            .transpose()?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), known_files.display_name,
                   known_files.size_bytes,
                   CASE
                       WHEN known_files.aich_root IS NULL THEN NULL
                       ELSE lower(hex(known_files.aich_root))
                   END,
                   known_files.upload_priority, known_files.auto_upload_priority,
                   known_files.comment, known_files.rating,
                   known_files.all_time_uploaded_bytes,
                   known_files.all_time_upload_requests,
                   known_files.all_time_upload_accepts,
                   known_files.last_upload_request_ms,
                   media_paths.platform, media_paths.native_path,
                   known_files.media_artist, known_files.media_album,
                   known_files.media_title, known_files.media_length_seconds,
                   known_files.media_bitrate_kbps, known_files.media_codec,
                   known_files.media_extractor_version
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            LEFT JOIN local_paths media_paths ON media_paths.id = COALESCE(
                transfers.source_path_id,
                (
                    SELECT shared_file_sources.path_id
                    FROM shared_file_sources
                    JOIN local_paths ON local_paths.id = shared_file_sources.path_id
                    WHERE shared_file_sources.known_file_id = known_files.id
                    ORDER BY local_paths.display_path, local_paths.native_path
                    LIMIT 1
                ),
                transfers.delivered_path_id
            )
            WHERE (
                    known_files.completed != 0
                    OR EXISTS (
                        SELECT 1 FROM shared_file_sources
                        WHERE shared_file_sources.known_file_id = known_files.id
                    )
                  )
              AND transfers.delete_requested_at_ms IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM unshared_files
                  WHERE unshared_files.known_file_id = known_files.id
              )
              AND (?1 IS NULL OR known_files.ed2k_hash > ?1)
            ORDER BY known_files.ed2k_hash
            LIMIT ?2
            "#,
        )?;
        let rows = stmt.query_map(params![after_hash, limit], |row| {
            Ok(MetadataTransferCatalogEntry {
                file_hash: row.get(0)?,
                display_name: row.get(1)?,
                file_size: row.get::<_, i64>(2)? as u64,
                aich_root: row.get(3)?,
                upload_priority: row.get(4)?,
                auto_upload_priority: row.get::<_, i64>(5)? != 0,
                comment: row.get(6)?,
                rating: row.get::<_, i64>(7)? as u8,
                all_time_uploaded_bytes: row.get::<_, i64>(8)? as u64,
                all_time_upload_requests: row.get::<_, i64>(9)? as u64,
                all_time_upload_accepts: row.get::<_, i64>(10)? as u64,
                last_upload_request_ms: row.get(11)?,
                media_path: optional_path_from_row(row, 12, 13)?,
                media: MetadataTransferMediaMetadata {
                    artist: row.get(14)?,
                    album: row.get(15)?,
                    title: row.get(16)?,
                    length_seconds: row.get::<_, i64>(17)? as u32,
                    bitrate_kbps: row.get::<_, i64>(18)? as u32,
                    codec: row.get(19)?,
                    extractor_version: row.get::<_, i64>(20)? as u32,
                },
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn transfer_media_metadata(
        &self,
        file_hash: &str,
    ) -> Result<Option<MetadataTransferMediaMetadata>> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        self.connection()?
            .query_row(
                r#"
                SELECT media_artist, media_album, media_title,
                       media_length_seconds, media_bitrate_kbps, media_codec,
                       media_extractor_version
                FROM known_files
                WHERE ed2k_hash = ?1
                "#,
                params![hash],
                |row| {
                    Ok(MetadataTransferMediaMetadata {
                        artist: row.get(0)?,
                        album: row.get(1)?,
                        title: row.get(2)?,
                        length_seconds: row.get::<_, i64>(3)? as u32,
                        bitrate_kbps: row.get::<_, i64>(4)? as u32,
                        codec: row.get(5)?,
                        extractor_version: row.get::<_, i64>(6)? as u32,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn update_transfer_media_metadata(
        &self,
        file_hash: &str,
        media: &MetadataTransferMediaMetadata,
    ) -> Result<bool> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let changed = self.connection()?.execute(
            r#"
            UPDATE known_files
            SET media_artist = ?2,
                media_album = ?3,
                media_title = ?4,
                media_length_seconds = ?5,
                media_bitrate_kbps = ?6,
                media_codec = ?7,
                media_extractor_version = ?8,
                updated_at_ms = ?9
            WHERE ed2k_hash = ?1
            "#,
            params![
                hash,
                media.artist,
                media.album,
                media.title,
                i64::from(media.length_seconds),
                i64::from(media.bitrate_kbps),
                media.codec,
                i64::from(media.extractor_version),
                unix_ms(),
            ],
        )?;
        Ok(changed != 0)
    }

    pub fn share_in_place_reload_entries(&self) -> Result<Vec<MetadataShareInPlaceReloadEntry>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), shared_file_sources.file_size,
                   local_paths.platform, local_paths.native_path,
                   shared_file_sources.source_fingerprint
            FROM shared_file_sources
            JOIN known_files ON known_files.id = shared_file_sources.known_file_id
            JOIN transfers ON transfers.known_file_id = known_files.id
            JOIN local_paths ON local_paths.id = shared_file_sources.path_id
            WHERE transfers.delete_requested_at_ms IS NULL
            ORDER BY local_paths.display_path
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataShareInPlaceReloadEntry {
                file_hash: row.get(0)?,
                file_size: row.get::<_, i64>(1)? as u64,
                source_path: path_from_row(row, 2, 3)?,
                source_fingerprint: optional_fingerprint_from_row(row, 4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Move one share-in-place source to a new filesystem path without
    /// rewriting its hashsets or transfer children.
    ///
    /// A filesystem rename preserves content identity. Routing it through the
    /// full manifest upsert would needlessly rewrite every child row and, more
    /// importantly, would leave the old `shared_file_sources` row beside the
    /// new one. Keep the path move atomic and bounded to the indexed path rows.
    #[expect(
        clippy::too_many_arguments,
        reason = "the source identity and renamed catalog metadata form one atomic update"
    )]
    pub fn relocate_shared_file_source(
        &self,
        file_hash: &str,
        old_source_path: &Path,
        new_source_path: &Path,
        file_size: u64,
        source_fingerprint: Option<&NativeFileFingerprint>,
        display_name: &str,
        content_type: &str,
    ) -> Result<bool> {
        // WHY: a same-hash rename must replace the old path row instead of using
        // manifest upsert, which intentionally permits duplicate source paths.
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let source_fingerprint = source_fingerprint.map(NativeFileFingerprint::storage_bytes);
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let Some(old_path_id) = local_path_id(&tx, old_source_path)? else {
            return Ok(false);
        };
        let new_path_id = upsert_local_path(&tx, new_source_path)?;
        let Some(known_file_id) = tx
            .query_row(
                "SELECT id FROM known_files WHERE ed2k_hash = ?1",
                params![hash],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        else {
            return Ok(false);
        };

        let changed = tx.execute(
            r#"
            UPDATE shared_file_sources
            SET path_id = ?3,
                file_size = ?4,
                source_fingerprint = ?5,
                updated_at_ms = ?6
            WHERE known_file_id = ?1 AND path_id = ?2
            "#,
            params![
                known_file_id,
                old_path_id,
                new_path_id,
                file_size as i64,
                source_fingerprint,
                now,
            ],
        )?;
        if changed == 0 {
            return Ok(false);
        }
        tx.execute(
            r#"
            UPDATE transfers
            SET source_path_id = ?3,
                source_fingerprint = ?4,
                updated_at_ms = ?5
            WHERE known_file_id = ?1 AND source_path_id = ?2
            "#,
            params![
                known_file_id,
                old_path_id,
                new_path_id,
                source_fingerprint,
                now,
            ],
        )?;
        tx.execute(
            r#"
            UPDATE known_files
            SET display_name = ?2,
                content_type = ?3,
                last_seen_ms = ?4,
                updated_at_ms = ?4
            WHERE id = ?1
              AND EXISTS (
                  SELECT 1
                  FROM transfers
                  WHERE transfers.known_file_id = ?1
                    AND transfers.source_path_id = ?5
              )
            "#,
            params![known_file_id, display_name, content_type, now, new_path_id],
        )?;
        tx.execute(
            "DELETE FROM shared_file_scan_failures WHERE path_id IN (?1, ?2)",
            params![old_path_id, new_path_id],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Completed downloads whose delivered file can be reused (not re-hashed) if
    /// a shared-directory rescan re-finds it in a configured shared dir. A real
    /// download has NO `shared_file_sources` row, so without this it looks
    /// brand-new on reload and its whole payload is needlessly re-hashed to
    /// convert it to a share. Only rows that recorded the delivered file's native
    /// fingerprint (captured at delivery for a delivered
    /// download -- `source_path_id IS NULL` distinguishes it from a share-in-place
    /// source) are returned, so an unchanged delivered file is a reload cache hit.
    pub fn completed_delivered_reuse_entries(&self) -> Result<Vec<MetadataDeliveredReuseEntry>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), known_files.size_bytes,
                   delivered_paths.platform, delivered_paths.native_path,
                   transfers.source_fingerprint
            FROM transfers
            JOIN known_files ON known_files.id = transfers.known_file_id
            JOIN local_paths delivered_paths ON delivered_paths.id = transfers.delivered_path_id
            WHERE known_files.completed != 0
              AND transfers.delete_requested_at_ms IS NULL
              AND transfers.delivered_path_id IS NOT NULL
              AND transfers.source_path_id IS NULL
              AND transfers.source_fingerprint IS NOT NULL
            ORDER BY delivered_paths.display_path
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataDeliveredReuseEntry {
                file_hash: row.get(0)?,
                file_size: row.get::<_, i64>(1)? as u64,
                delivered_path: path_from_row(row, 2, 3)?,
                delivered_fingerprint: optional_fingerprint_from_row(row, 4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn upsert_imported_known_file(&self, entry: &MetadataImportedKnownFileEntry) -> Result<()> {
        let hash = decode_fixed_hex(&entry.file_hash, 16, "ED2K hash")?;
        let aich_root = optional_fixed_hex(entry.aich_root.as_deref(), 20, "AICH root")?;
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute(
            r#"
            DELETE FROM imported_known_files
            WHERE ed2k_hash = ?1 AND display_name = ?2 AND size_bytes = ?3 AND modified_s = ?4
            "#,
            params![
                hash,
                entry.display_name,
                entry.file_size as i64,
                entry.modified_s
            ],
        )?;
        tx.execute(
            r#"
            INSERT INTO imported_known_files(
                ed2k_hash, display_name, size_bytes, modified_s, aich_root,
                upload_priority, auto_upload_priority, all_time_uploaded_bytes,
                all_time_upload_requests, all_time_upload_accepts,
                last_upload_request_ms, imported_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            params![
                decode_fixed_hex(&entry.file_hash, 16, "ED2K hash")?,
                entry.display_name,
                entry.file_size as i64,
                entry.modified_s,
                aich_root,
                entry.upload_priority,
                bool_to_i64(entry.auto_upload_priority),
                entry.all_time_uploaded_bytes as i64,
                entry.all_time_upload_requests as i64,
                entry.all_time_upload_accepts as i64,
                entry.last_upload_request_ms,
                now,
            ],
        )?;
        let imported_known_file_id = tx.last_insert_rowid();
        for (index, hash) in entry.md4_hashset.iter().enumerate() {
            tx.execute(
                r#"
                INSERT INTO imported_known_file_md4_hashes(
                    imported_known_file_id, part_index, md4_hash
                )
                VALUES (?1, ?2, ?3)
                "#,
                params![
                    imported_known_file_id,
                    index as i64,
                    decode_fixed_hex(hash, 16, "MD4 part hash")?,
                ],
            )?;
        }
        for (index, hash) in entry.aich_hashset.iter().enumerate() {
            tx.execute(
                r#"
                INSERT INTO imported_known_file_aich_hashes(
                    imported_known_file_id, part_index, aich_hash
                )
                VALUES (?1, ?2, ?3)
                "#,
                params![
                    imported_known_file_id,
                    index as i64,
                    decode_fixed_hex(hash, 20, "AICH part hash")?,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn imported_known_file_identity_matches(
        &self,
        display_name: &str,
        file_size: u64,
        modified_s: i64,
    ) -> Result<Vec<MetadataImportedKnownFileEntry>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, lower(hex(ed2k_hash)), display_name, size_bytes, modified_s,
                   CASE WHEN aich_root IS NULL THEN NULL ELSE lower(hex(aich_root)) END,
                   upload_priority, auto_upload_priority, all_time_uploaded_bytes,
                   all_time_upload_requests, all_time_upload_accepts,
                   last_upload_request_ms
            FROM imported_known_files
            WHERE display_name = ?1 AND size_bytes = ?2 AND modified_s = ?3
            ORDER BY id
            "#,
        )?;
        let rows = stmt.query_map(params![display_name, file_size as i64, modified_s], |row| {
            let id = row.get::<_, i64>(0)?;
            Ok((
                id,
                MetadataImportedKnownFileEntry {
                    file_hash: row.get(1)?,
                    display_name: row.get(2)?,
                    file_size: row.get::<_, i64>(3)? as u64,
                    modified_s: row.get(4)?,
                    md4_hashset: Vec::new(),
                    aich_root: row.get(5)?,
                    aich_hashset: Vec::new(),
                    upload_priority: row.get(6)?,
                    auto_upload_priority: row.get::<_, i64>(7)? != 0,
                    all_time_uploaded_bytes: row.get::<_, i64>(8)? as u64,
                    all_time_upload_requests: row.get::<_, i64>(9)? as u64,
                    all_time_upload_accepts: row.get::<_, i64>(10)? as u64,
                    last_upload_request_ms: row.get(11)?,
                },
            ))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let (id, mut entry) = row?;
            entry.md4_hashset = imported_md4_hashset(&conn, id)?;
            entry.aich_hashset = imported_aich_hashset(&conn, id)?;
            entries.push(entry);
        }
        Ok(entries)
    }

    pub fn imported_known_file_entries(&self) -> Result<Vec<MetadataImportedKnownFileEntry>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, lower(hex(ed2k_hash)), display_name, size_bytes, modified_s,
                   CASE WHEN aich_root IS NULL THEN NULL ELSE lower(hex(aich_root)) END,
                   upload_priority, auto_upload_priority, all_time_uploaded_bytes,
                   all_time_upload_requests, all_time_upload_accepts,
                   last_upload_request_ms
            FROM imported_known_files
            ORDER BY id
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            let id = row.get::<_, i64>(0)?;
            Ok((
                id,
                MetadataImportedKnownFileEntry {
                    file_hash: row.get(1)?,
                    display_name: row.get(2)?,
                    file_size: row.get::<_, i64>(3)? as u64,
                    modified_s: row.get(4)?,
                    md4_hashset: Vec::new(),
                    aich_root: row.get(5)?,
                    aich_hashset: Vec::new(),
                    upload_priority: row.get(6)?,
                    auto_upload_priority: row.get::<_, i64>(7)? != 0,
                    all_time_uploaded_bytes: row.get::<_, i64>(8)? as u64,
                    all_time_upload_requests: row.get::<_, i64>(9)? as u64,
                    all_time_upload_accepts: row.get::<_, i64>(10)? as u64,
                    last_upload_request_ms: row.get(11)?,
                },
            ))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let (id, mut entry) = row?;
            entry.md4_hashset = imported_md4_hashset(&conn, id)?;
            entry.aich_hashset = imported_aich_hashset(&conn, id)?;
            entries.push(entry);
        }
        Ok(entries)
    }

    pub fn apply_imported_known_file_stats(
        &self,
        file_hash: &str,
        entry: &MetadataImportedKnownFileEntry,
    ) -> Result<bool> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let changed = conn.execute(
            r#"
            UPDATE known_files
            SET all_time_uploaded_bytes = max(all_time_uploaded_bytes, ?2),
                all_time_upload_requests = max(all_time_upload_requests, ?3),
                all_time_upload_accepts = max(all_time_upload_accepts, ?4),
                last_upload_request_ms = max(last_upload_request_ms, ?5)
            WHERE ed2k_hash = ?1
            "#,
            params![
                hash,
                entry.all_time_uploaded_bytes as i64,
                entry.all_time_upload_requests as i64,
                entry.all_time_upload_accepts as i64,
                entry.last_upload_request_ms,
            ],
        )?;
        Ok(changed != 0)
    }

    pub fn shared_source_failures(&self) -> Result<Vec<MetadataSharedSourceFailure>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT local_paths.platform, local_paths.native_path,
                   shared_file_scan_failures.file_size,
                   shared_file_scan_failures.source_fingerprint, shared_file_scan_failures.reason,
                   shared_file_scan_failures.created_at_ms, shared_file_scan_failures.updated_at_ms
            FROM shared_file_scan_failures
            JOIN local_paths ON local_paths.id = shared_file_scan_failures.path_id
            ORDER BY local_paths.display_path
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataSharedSourceFailure {
                source_path: path_from_row(row, 0, 1)?,
                file_size: row.get::<_, i64>(2)? as u64,
                source_fingerprint: optional_fingerprint_from_row(row, 3)?,
                reason: row.get(4)?,
                created_at_ms: row.get(5)?,
                updated_at_ms: row.get(6)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn upsert_shared_source_failure(
        &self,
        source_path: &Path,
        file_size: u64,
        source_fingerprint: Option<&NativeFileFingerprint>,
        reason: &str,
    ) -> Result<()> {
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let path_id = upsert_local_path(&tx, source_path)?;
        tx.execute(
            r#"
            INSERT INTO shared_file_scan_failures(
                path_id, file_size, source_fingerprint, reason,
                created_at_ms, updated_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?5)
            ON CONFLICT(path_id) DO UPDATE SET
                file_size = excluded.file_size,
                source_fingerprint = excluded.source_fingerprint,
                reason = excluded.reason,
                updated_at_ms = excluded.updated_at_ms
            "#,
            params![
                path_id,
                file_size as i64,
                source_fingerprint.map(NativeFileFingerprint::storage_bytes),
                reason,
                now
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn clear_shared_source_failure(&self, source_path: &Path) -> Result<bool> {
        let conn = self.connection()?;
        let Some(path_id) = local_path_id(&conn, source_path)? else {
            return Ok(false);
        };
        let deleted = conn.execute(
            "DELETE FROM shared_file_scan_failures WHERE path_id = ?1",
            params![path_id],
        )?;
        Ok(deleted != 0)
    }

    pub fn transfer_counts(&self) -> Result<MetadataTransferCounts> {
        let conn = self.connection()?;
        transfer_counts_from_connection(&conn)
    }

    pub fn try_transfer_counts(&self) -> Result<Option<MetadataTransferCounts>> {
        let Some(conn) = self.try_connection()? else {
            return Ok(None);
        };
        transfer_counts_from_connection(&conn).map(Some)
    }

    pub fn completed_transfer_publish_entries(&self) -> Result<Vec<MetadataTransferPublishEntry>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), known_files.display_name,
                   known_files.size_bytes,
                   CASE
                       WHEN known_files.aich_root IS NULL THEN NULL
                       ELSE lower(hex(known_files.aich_root))
                   END,
                   known_files.upload_priority, known_files.auto_upload_priority,
                   known_files.all_time_uploaded_bytes,
                   known_files.all_time_upload_requests,
                   known_files.all_time_upload_accepts,
                   known_files.last_upload_request_ms,
                   known_files.comment, known_files.rating
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE (
                    known_files.completed != 0
                    OR EXISTS (
                        SELECT 1 FROM transfer_pieces
                        WHERE transfer_pieces.transfer_id = transfers.id
                          AND transfer_pieces.state = 'Verified'
                    )
                    OR EXISTS (
                        SELECT 1 FROM shared_file_sources
                        WHERE shared_file_sources.known_file_id = known_files.id
                    )
                  )
              AND transfers.delete_requested_at_ms IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM unshared_files
                  WHERE unshared_files.known_file_id = known_files.id
              )
            ORDER BY known_files.ed2k_hash
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataTransferPublishEntry {
                file_hash: row.get(0)?,
                display_name: row.get(1)?,
                file_size: row.get::<_, i64>(2)? as u64,
                aich_root: row.get(3)?,
                upload_priority: row.get(4)?,
                auto_upload_priority: row.get::<_, i64>(5)? != 0,
                session_uploaded_bytes: 0,
                session_request_count: 0,
                session_accept_count: 0,
                all_time_uploaded_bytes: row.get::<_, i64>(6)? as u64,
                all_time_upload_requests: row.get::<_, i64>(7)? as u64,
                all_time_upload_accepts: row.get::<_, i64>(8)? as u64,
                last_upload_request_ms: row.get(9)?,
                comment: row.get(10)?,
                rating: row.get::<_, i64>(11)? as u8,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn try_completed_transfer_publish_entries(
        &self,
    ) -> Result<Option<Vec<MetadataTransferPublishEntry>>> {
        let Some(conn) = self.try_connection()? else {
            return Ok(None);
        };
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), known_files.display_name,
                   known_files.size_bytes,
                   CASE
                       WHEN known_files.aich_root IS NULL THEN NULL
                       ELSE lower(hex(known_files.aich_root))
                   END,
                   known_files.upload_priority, known_files.auto_upload_priority,
                   known_files.all_time_uploaded_bytes,
                   known_files.all_time_upload_requests,
                   known_files.all_time_upload_accepts,
                   known_files.last_upload_request_ms,
                   known_files.comment, known_files.rating
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE (
                    known_files.completed != 0
                    OR EXISTS (
                        SELECT 1 FROM transfer_pieces
                        WHERE transfer_pieces.transfer_id = transfers.id
                          AND transfer_pieces.state = 'Verified'
                    )
                  )
              AND transfers.delete_requested_at_ms IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM unshared_files
                  WHERE unshared_files.known_file_id = known_files.id
              )
            ORDER BY known_files.ed2k_hash
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataTransferPublishEntry {
                file_hash: row.get(0)?,
                display_name: row.get(1)?,
                file_size: row.get::<_, i64>(2)? as u64,
                aich_root: row.get(3)?,
                upload_priority: row.get(4)?,
                auto_upload_priority: row.get::<_, i64>(5)? != 0,
                session_uploaded_bytes: 0,
                session_request_count: 0,
                session_accept_count: 0,
                all_time_uploaded_bytes: row.get::<_, i64>(6)? as u64,
                all_time_upload_requests: row.get::<_, i64>(7)? as u64,
                all_time_upload_accepts: row.get::<_, i64>(8)? as u64,
                last_upload_request_ms: row.get(9)?,
                comment: row.get(10)?,
                rating: row.get::<_, i64>(11)? as u8,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map(Some)
            .map_err(Into::into)
    }

    pub fn completed_transfer_share_entries(&self) -> Result<Vec<MetadataTransferShareEntry>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), known_files.display_name,
                   known_files.size_bytes, coalesce(known_files.part_count, 0),
                   effective_paths.platform, effective_paths.native_path,
                   CASE
                       WHEN known_files.aich_root IS NULL THEN NULL
                       ELSE lower(hex(known_files.aich_root))
                   END,
                   known_files.upload_priority, known_files.auto_upload_priority,
                   known_files.all_time_uploaded_bytes,
                   known_files.all_time_upload_requests,
                   known_files.all_time_upload_accepts,
                   known_files.comment, known_files.rating
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            LEFT JOIN local_paths effective_paths ON effective_paths.id = COALESCE(
                transfers.source_path_id,
                (
                    SELECT shared_file_sources.path_id
                    FROM shared_file_sources
                    JOIN local_paths ON local_paths.id = shared_file_sources.path_id
                    WHERE shared_file_sources.known_file_id = known_files.id
                    ORDER BY local_paths.display_path, local_paths.native_path
                    LIMIT 1
                )
            )
            WHERE (
                    known_files.completed != 0
                    OR EXISTS (
                        SELECT 1 FROM shared_file_sources
                        WHERE shared_file_sources.known_file_id = known_files.id
                    )
                  )
              AND transfers.delete_requested_at_ms IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM unshared_files
                  WHERE unshared_files.known_file_id = known_files.id
              )
            ORDER BY known_files.ed2k_hash
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataTransferShareEntry {
                file_hash: row.get(0)?,
                display_name: row.get(1)?,
                file_size: row.get::<_, i64>(2)? as u64,
                part_count: row.get::<_, i64>(3)? as u32,
                source_path: optional_path_from_row(row, 4, 5)?,
                aich_root: row.get(6)?,
                upload_priority: row.get(7)?,
                auto_upload_priority: row.get::<_, i64>(8)? != 0,
                all_time_uploaded_bytes: row.get::<_, i64>(9)? as u64,
                all_time_upload_requests: row.get::<_, i64>(10)? as u64,
                all_time_upload_accepts: row.get::<_, i64>(11)? as u64,
                comment: row.get(12)?,
                rating: row.get::<_, i64>(13)? as u8,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn completed_transfer_share_entry(
        &self,
        file_hash: &str,
    ) -> Result<Option<MetadataTransferShareEntry>> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        conn.query_row(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), known_files.display_name,
                   known_files.size_bytes, coalesce(known_files.part_count, 0),
                   effective_paths.platform, effective_paths.native_path,
                   CASE
                       WHEN known_files.aich_root IS NULL THEN NULL
                       ELSE lower(hex(known_files.aich_root))
                   END,
                   known_files.upload_priority, known_files.auto_upload_priority,
                   known_files.all_time_uploaded_bytes,
                   known_files.all_time_upload_requests,
                   known_files.all_time_upload_accepts,
                   known_files.comment, known_files.rating
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            LEFT JOIN local_paths effective_paths ON effective_paths.id = COALESCE(
                transfers.source_path_id,
                (
                    SELECT shared_file_sources.path_id
                    FROM shared_file_sources
                    JOIN local_paths ON local_paths.id = shared_file_sources.path_id
                    WHERE shared_file_sources.known_file_id = known_files.id
                    ORDER BY local_paths.display_path, local_paths.native_path
                    LIMIT 1
                )
            )
            WHERE known_files.ed2k_hash = ?1
              AND transfers.delete_requested_at_ms IS NULL
              AND (
                    known_files.completed != 0
                    OR EXISTS (
                        SELECT 1 FROM shared_file_sources
                        WHERE shared_file_sources.known_file_id = known_files.id
                    )
                  )
              AND NOT EXISTS (
                  SELECT 1 FROM unshared_files
                  WHERE unshared_files.known_file_id = known_files.id
              )
            LIMIT 1
            "#,
            params![hash],
            |row| {
                Ok(MetadataTransferShareEntry {
                    file_hash: row.get(0)?,
                    display_name: row.get(1)?,
                    file_size: row.get::<_, i64>(2)? as u64,
                    part_count: row.get::<_, i64>(3)? as u32,
                    source_path: optional_path_from_row(row, 4, 5)?,
                    aich_root: row.get(6)?,
                    upload_priority: row.get(7)?,
                    auto_upload_priority: row.get::<_, i64>(8)? != 0,
                    all_time_uploaded_bytes: row.get::<_, i64>(9)? as u64,
                    all_time_upload_requests: row.get::<_, i64>(10)? as u64,
                    all_time_upload_accepts: row.get::<_, i64>(11)? as u64,
                    comment: row.get(12)?,
                    rating: row.get::<_, i64>(13)? as u8,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn completed_transfer_share_entries_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<MetadataTransferShareEntry>, usize)> {
        let total = self.completed_transfer_share_count()?;
        let entries = self.completed_transfer_share_entries_page_rows(offset, limit)?;
        Ok((entries, total))
    }

    /// Read one shared-file page without rescanning the full persisted catalog
    /// for its total. Runtime callers pair this with the in-memory catalog's
    /// maintained completed count.
    pub fn completed_transfer_share_entries_page_rows(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<MetadataTransferShareEntry>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), known_files.display_name,
                   known_files.size_bytes, coalesce(known_files.part_count, 0),
                   effective_paths.platform, effective_paths.native_path,
                   CASE
                       WHEN known_files.aich_root IS NULL THEN NULL
                       ELSE lower(hex(known_files.aich_root))
                   END,
                   known_files.upload_priority, known_files.auto_upload_priority,
                   known_files.all_time_uploaded_bytes,
                   known_files.all_time_upload_requests,
                   known_files.all_time_upload_accepts,
                   known_files.comment, known_files.rating
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            LEFT JOIN local_paths effective_paths ON effective_paths.id = COALESCE(
                transfers.source_path_id,
                (
                    SELECT shared_file_sources.path_id
                    FROM shared_file_sources
                    JOIN local_paths ON local_paths.id = shared_file_sources.path_id
                    WHERE shared_file_sources.known_file_id = known_files.id
                    ORDER BY local_paths.display_path, local_paths.native_path
                    LIMIT 1
                )
            )
            WHERE (
                    known_files.completed != 0
                    OR EXISTS (
                        SELECT 1 FROM shared_file_sources
                        WHERE shared_file_sources.known_file_id = known_files.id
                    )
                  )
              AND transfers.delete_requested_at_ms IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM unshared_files
                  WHERE unshared_files.known_file_id = known_files.id
              )
            ORDER BY known_files.ed2k_hash
            LIMIT ?1 OFFSET ?2
            "#,
        )?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            Ok(MetadataTransferShareEntry {
                file_hash: row.get(0)?,
                display_name: row.get(1)?,
                file_size: row.get::<_, i64>(2)? as u64,
                part_count: row.get::<_, i64>(3)? as u32,
                source_path: optional_path_from_row(row, 4, 5)?,
                aich_root: row.get(6)?,
                upload_priority: row.get(7)?,
                auto_upload_priority: row.get::<_, i64>(8)? != 0,
                all_time_uploaded_bytes: row.get::<_, i64>(9)? as u64,
                all_time_upload_requests: row.get::<_, i64>(10)? as u64,
                all_time_upload_accepts: row.get::<_, i64>(11)? as u64,
                comment: row.get(12)?,
                rating: row.get::<_, i64>(13)? as u8,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn completed_transfer_share_entries_after(
        &self,
        after_hash: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<MetadataTransferShareEntry>, usize, bool)> {
        let total = self.completed_transfer_share_count()?;
        let (entries, has_more) =
            self.completed_transfer_share_entries_after_rows(after_hash, limit)?;
        Ok((entries, total, has_more))
    }

    /// Read one keyset page without a full persisted count scan.
    pub fn completed_transfer_share_entries_after_rows(
        &self,
        after_hash: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<MetadataTransferShareEntry>, bool)> {
        let after_hash = after_hash
            .map(|hash| decode_fixed_hex(hash, 16, "ED2K after hash"))
            .transpose()?;
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), known_files.display_name,
                   known_files.size_bytes, coalesce(known_files.part_count, 0),
                   effective_paths.platform, effective_paths.native_path,
                   CASE
                       WHEN known_files.aich_root IS NULL THEN NULL
                       ELSE lower(hex(known_files.aich_root))
                   END,
                   known_files.upload_priority, known_files.auto_upload_priority,
                   known_files.all_time_uploaded_bytes,
                   known_files.all_time_upload_requests,
                   known_files.all_time_upload_accepts,
                   known_files.comment, known_files.rating
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            LEFT JOIN local_paths effective_paths ON effective_paths.id = COALESCE(
                transfers.source_path_id,
                (
                    SELECT shared_file_sources.path_id
                    FROM shared_file_sources
                    JOIN local_paths ON local_paths.id = shared_file_sources.path_id
                    WHERE shared_file_sources.known_file_id = known_files.id
                    ORDER BY local_paths.display_path, local_paths.native_path
                    LIMIT 1
                )
            )
            WHERE (
                    known_files.completed != 0
                    OR EXISTS (
                        SELECT 1 FROM shared_file_sources
                        WHERE shared_file_sources.known_file_id = known_files.id
                    )
                  )
              AND transfers.delete_requested_at_ms IS NULL
              AND (?1 IS NULL OR known_files.ed2k_hash > ?1)
              AND NOT EXISTS (
                  SELECT 1 FROM unshared_files
                  WHERE unshared_files.known_file_id = known_files.id
              )
            ORDER BY known_files.ed2k_hash
            LIMIT ?2
            "#,
        )?;
        let fetch_limit = limit.saturating_add(1);
        let rows = stmt.query_map(params![after_hash, fetch_limit as i64], |row| {
            Ok(MetadataTransferShareEntry {
                file_hash: row.get(0)?,
                display_name: row.get(1)?,
                file_size: row.get::<_, i64>(2)? as u64,
                part_count: row.get::<_, i64>(3)? as u32,
                source_path: optional_path_from_row(row, 4, 5)?,
                aich_root: row.get(6)?,
                upload_priority: row.get(7)?,
                auto_upload_priority: row.get::<_, i64>(8)? != 0,
                all_time_uploaded_bytes: row.get::<_, i64>(9)? as u64,
                all_time_upload_requests: row.get::<_, i64>(10)? as u64,
                all_time_upload_accepts: row.get::<_, i64>(11)? as u64,
                comment: row.get(12)?,
                rating: row.get::<_, i64>(13)? as u8,
            })
        })?;
        let mut entries = rows.collect::<Result<Vec<_>, _>>()?;
        let has_more = entries.len() > limit;
        entries.truncate(limit);
        Ok((entries, has_more))
    }

    fn completed_transfer_share_count(&self) -> Result<usize> {
        self.connection()?
            .query_row(
                r#"
                SELECT count(*)
                FROM known_files
                JOIN transfers ON transfers.known_file_id = known_files.id
                WHERE (
                        known_files.completed != 0
                        OR EXISTS (
                            SELECT 1 FROM shared_file_sources
                            WHERE shared_file_sources.known_file_id = known_files.id
                        )
                      )
                  AND transfers.delete_requested_at_ms IS NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM unshared_files
                      WHERE unshared_files.known_file_id = known_files.id
                  )
                "#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count as usize)
            .map_err(Into::into)
    }

    pub fn pending_completed_delivery_hashes(&self) -> Result<Vec<String>> {
        self.completed_delivery_hashes("transfers.delivery_state = 'pending'")
    }

    pub fn completed_delivery_reconciliation_hashes(&self) -> Result<Vec<String>> {
        self.completed_delivery_hashes("transfers.delivery_state IN ('pending', 'delivered')")
    }

    fn completed_delivery_hashes(&self, delivery_predicate: &str) -> Result<Vec<String>> {
        let conn = self.connection()?;
        let sql = format!(
            r#"
            SELECT lower(hex(known_files.ed2k_hash))
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE known_files.completed != 0
              AND {delivery_predicate}
              AND transfers.removed_at_ms IS NULL
              AND transfers.delete_requested_at_ms IS NULL
            ORDER BY known_files.ed2k_hash
            "#
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Persist a terminal destructive-delete request before either filesystem
    /// authority is touched. Repeating the request preserves the original
    /// timestamp and remains successful while the transfer row exists.
    pub fn request_transfer_deletion(&self, file_hash: &str) -> Result<bool> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let now = unix_ms();
        let conn = self.connection()?;
        let changed = conn.execute(
            r#"
            UPDATE transfers
            SET delete_requested_at_ms = coalesce(delete_requested_at_ms, ?2),
                updated_at_ms = CASE
                    WHEN delete_requested_at_ms IS NULL THEN ?2
                    ELSE updated_at_ms
                END
            WHERE known_file_id = (
                SELECT id FROM known_files WHERE ed2k_hash = ?1
            )
            "#,
            params![hash, now],
        )?;
        Ok(changed != 0)
    }

    pub fn transfer_deletion_requested(&self, file_hash: &str) -> Result<bool> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        self.connection()?
            .query_row(
                r#"
                SELECT transfers.delete_requested_at_ms IS NOT NULL
                FROM known_files
                JOIN transfers ON transfers.known_file_id = known_files.id
                WHERE known_files.ed2k_hash = ?1
                "#,
                params![hash],
                |row| row.get(0),
            )
            .optional()
            .map(|value| value.unwrap_or(false))
            .map_err(Into::into)
    }

    /// Return every transfer whose destructive-delete intent must be resumed.
    pub fn pending_transfer_deletion_hashes(&self) -> Result<Vec<String>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash))
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE transfers.delete_requested_at_ms IS NOT NULL
            ORDER BY known_files.ed2k_hash
            "#,
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Return every hash which owns an internal download directory. Share-in-
    /// place rows serve their source path directly and therefore do not own a
    /// path beneath the transfer root. Pending deletion rows remain owners
    /// until their strict filesystem cleanup finalizes the metadata row.
    pub fn managed_download_transfer_hashes(&self) -> Result<Vec<String>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash))
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE transfers.source_path_id IS NULL
            ORDER BY known_files.ed2k_hash
            "#,
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn managed_download_transfer_exists(&self, file_hash: &str) -> Result<bool> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        self.connection()?
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM known_files
                    JOIN transfers ON transfers.known_file_id = known_files.id
                    WHERE known_files.ed2k_hash = ?1
                      AND transfers.source_path_id IS NULL
                )
                "#,
                params![hash],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    /// Commit metadata removal only for a transfer with a durable destructive
    /// intent. A missing row or a row without intent is an idempotent no-op.
    pub fn finalize_transfer_deletion(&self, file_hash: &str) -> Result<bool> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let known_file_id = tx
            .query_row(
                r#"
                SELECT known_files.id
                FROM known_files
                JOIN transfers ON transfers.known_file_id = known_files.id
                WHERE known_files.ed2k_hash = ?1
                  AND transfers.delete_requested_at_ms IS NOT NULL
                "#,
                params![hash],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(known_file_id) = known_file_id else {
            return Ok(false);
        };
        delete_known_file(&tx, known_file_id)?;
        tx.commit()?;
        Ok(true)
    }

    pub fn delete_transfer_manifest(&self, file_hash: &str) -> Result<bool> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let known_file_id = tx
            .query_row(
                "SELECT id FROM known_files WHERE ed2k_hash = ?1",
                params![hash],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(known_file_id) = known_file_id else {
            return Ok(false);
        };
        delete_known_file(&tx, known_file_id)?;
        tx.commit()?;
        Ok(true)
    }
}

fn delete_known_file(tx: &rusqlite::Transaction<'_>, known_file_id: i64) -> Result<()> {
    tx.execute(
        "DELETE FROM shared_file_scan_failures WHERE path_id IN (
            SELECT path_id FROM shared_file_sources WHERE known_file_id = ?1
        )",
        params![known_file_id],
    )?;
    tx.execute(
        "DELETE FROM shared_file_sources WHERE known_file_id = ?1",
        params![known_file_id],
    )?;
    tx.execute(
        "DELETE FROM known_files WHERE id = ?1",
        params![known_file_id],
    )?;
    Ok(())
}

#[derive(Debug)]
struct TransferRow {
    known_file_id: i64,
    transfer_id: i64,
    file_hash: String,
    display_name: String,
    file_size: u64,
    piece_size: u64,
    completed: bool,
    final_rehash_pending: bool,
    md4_hashset_acquired: bool,
    aich_hashset_acquired: bool,
    aich_root: Option<String>,
    upload_priority: String,
    auto_upload_priority: bool,
    comment: String,
    rating: u8,
    category_id: u32,
    control_state: Option<String>,
    transfer_row_removed: bool,
    delivered_path: Option<std::path::PathBuf>,
    source_path: Option<std::path::PathBuf>,
    source_fingerprint: Option<NativeFileFingerprint>,
    payload_fingerprint: Option<NativeFileFingerprint>,
    delivery_state: String,
}

fn replace_transfer_children(
    tx: &rusqlite::Transaction<'_>,
    known_file_id: i64,
    transfer_id: i64,
    manifest: &MetadataTransferManifest,
    now: i64,
) -> Result<()> {
    tx.prepare_cached("DELETE FROM transfer_pieces WHERE transfer_id = ?1")?
        .execute(params![transfer_id])?;
    tx.prepare_cached("DELETE FROM ed2k_part_hashes WHERE known_file_id = ?1")?
        .execute(params![known_file_id])?;
    tx.prepare_cached("DELETE FROM aich_part_hashes WHERE known_file_id = ?1")?
        .execute(params![known_file_id])?;
    tx.prepare_cached("DELETE FROM verified_ranges WHERE known_file_id = ?1")?
        .execute(params![known_file_id])?;
    tx.prepare_cached("DELETE FROM transfer_sources WHERE transfer_id = ?1")?
        .execute(params![transfer_id])?;

    let mut insert_piece = tx.prepare_cached(
        r#"
        INSERT INTO transfer_pieces(transfer_id, piece_index, state, bytes_written, block_bitmap, ich_corrupted, updated_at_ms)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
    )?;
    for piece in &manifest.pieces {
        insert_piece.execute(params![
            transfer_id,
            i64::from(piece.piece_index),
            piece.state,
            piece.bytes_written as i64,
            piece.block_bitmap,
            piece.ich_corrupted,
            now,
        ])?;
    }
    drop(insert_piece);
    let mut insert_md4 = tx.prepare_cached(
        r#"
        INSERT INTO ed2k_part_hashes(known_file_id, part_index, md4_hash)
        VALUES (?1, ?2, ?3)
        "#,
    )?;
    for (index, hash) in manifest.md4_hashset.iter().enumerate() {
        insert_md4.execute(params![
            known_file_id,
            index as i64,
            decode_fixed_hex(hash, 16, "MD4 part hash")?,
        ])?;
    }
    drop(insert_md4);
    let mut insert_aich = tx.prepare_cached(
        r#"
        INSERT INTO aich_part_hashes(known_file_id, part_index, aich_hash)
        VALUES (?1, ?2, ?3)
        "#,
    )?;
    for (index, hash) in manifest.aich_hashset.iter().enumerate() {
        insert_aich.execute(params![
            known_file_id,
            index as i64,
            decode_fixed_hex(hash, 20, "AICH part hash")?,
        ])?;
    }
    drop(insert_aich);
    let mut insert_range = tx.prepare_cached(
        r#"
        INSERT INTO verified_ranges(known_file_id, start_offset, end_offset, created_at_ms)
        VALUES (?1, ?2, ?3, ?4)
        "#,
    )?;
    for range in &manifest.verified_ranges {
        insert_range.execute(params![
            known_file_id,
            range.start as i64,
            range.end as i64,
            now
        ])?;
    }
    drop(insert_range);
    let mut insert_source = tx.prepare_cached(
        r#"
        INSERT INTO transfer_sources(
            transfer_id, ip, tcp_port, user_hash, connect_options,
            file_comment, file_rating, first_seen_ms, last_seen_ms
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
        "#,
    )?;
    for source in &manifest.sources {
        insert_source.execute(params![
            transfer_id,
            source.ip,
            i64::from(source.tcp_port),
            optional_fixed_hex(source.user_hash.as_deref(), 16, "source user hash")?,
            source.connect_options.map(i64::from),
            source.file_comment,
            i64::from(source.file_rating),
            now,
        ])?;
    }
    Ok(())
}

fn manifest_from_row(
    conn: &rusqlite::Connection,
    row: TransferRow,
) -> Result<MetadataTransferManifest> {
    Ok(MetadataTransferManifest {
        file_hash: row.file_hash,
        display_name: row.display_name,
        file_size: row.file_size,
        piece_size: row.piece_size,
        completed: row.completed,
        final_rehash_pending: row.final_rehash_pending,
        md4_hashset_acquired: row.md4_hashset_acquired,
        md4_hashset: read_hex_list(
            conn,
            "SELECT lower(hex(md4_hash)) FROM ed2k_part_hashes WHERE known_file_id = ?1 ORDER BY part_index",
            row.known_file_id,
        )?,
        aich_hashset_acquired: row.aich_hashset_acquired,
        aich_root: row.aich_root,
        aich_hashset: read_hex_list(
            conn,
            "SELECT lower(hex(aich_hash)) FROM aich_part_hashes WHERE known_file_id = ?1 ORDER BY part_index",
            row.known_file_id,
        )?,
        verified_ranges: read_ranges(conn, row.known_file_id)?,
        pieces: read_pieces(conn, row.transfer_id)?,
        sources: read_sources(conn, row.transfer_id)?,
        upload_priority: row.upload_priority,
        auto_upload_priority: row.auto_upload_priority,
        comment: row.comment,
        rating: row.rating,
        category_id: row.category_id,
        control_state: row.control_state,
        transfer_row_removed: row.transfer_row_removed,
        delivery_state: delivery_state_from_sql(&row.delivery_state)?,
        delivered_path: row.delivered_path,
        source_path: row.source_path,
        source_fingerprint: row.source_fingerprint,
        payload_fingerprint: row.payload_fingerprint,
    })
}

fn transfer_counts_from_connection(conn: &rusqlite::Connection) -> Result<MetadataTransferCounts> {
    conn.query_row(
        r#"
        SELECT count(*),
               coalesce(sum(CASE
                   WHEN known_files.completed = 0
                        AND transfers.control_state IS NULL
                        AND transfers.visible_state IN ('completing', 'downloading', 'queued')
                   THEN 1 ELSE 0 END), 0),
               coalesce(sum(CASE
                   WHEN known_files.completed != 0 THEN 1 ELSE 0 END), 0)
        FROM transfers
        JOIN known_files ON known_files.id = transfers.known_file_id
        WHERE transfers.removed_at_ms IS NULL
          AND transfers.delete_requested_at_ms IS NULL
        "#,
        [],
        |row| {
            Ok(MetadataTransferCounts {
                total: row.get::<_, i64>(0)? as usize,
                active: row.get::<_, i64>(1)? as usize,
                completed: row.get::<_, i64>(2)? as usize,
            })
        },
    )
    .map_err(Into::into)
}

fn read_hex_list(conn: &rusqlite::Connection, sql: &str, id: i64) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt.query_map(params![id], |row| row.get(0))?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn read_pieces(
    conn: &rusqlite::Connection,
    transfer_id: i64,
) -> Result<Vec<MetadataTransferPiece>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT piece_index, state, bytes_written, block_bitmap, ich_corrupted
        FROM transfer_pieces
        WHERE transfer_id = ?1
        ORDER BY piece_index
        "#,
    )?;
    let rows = stmt.query_map(params![transfer_id], |row| {
        Ok(MetadataTransferPiece {
            piece_index: row.get::<_, i64>(0)? as u32,
            state: row.get(1)?,
            bytes_written: row.get::<_, i64>(2)? as u64,
            block_bitmap: row.get::<_, Option<String>>(3)?,
            ich_corrupted: row.get::<_, bool>(4)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn read_ranges(
    conn: &rusqlite::Connection,
    known_file_id: i64,
) -> Result<Vec<MetadataTransferRange>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT start_offset, end_offset
        FROM verified_ranges
        WHERE known_file_id = ?1
        ORDER BY start_offset, end_offset
        "#,
    )?;
    let rows = stmt.query_map(params![known_file_id], |row| {
        Ok(MetadataTransferRange {
            start: row.get::<_, i64>(0)? as u64,
            end: row.get::<_, i64>(1)? as u64,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn read_sources(
    conn: &rusqlite::Connection,
    transfer_id: i64,
) -> Result<Vec<MetadataTransferSource>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT ip, tcp_port,
               CASE WHEN user_hash IS NULL THEN NULL ELSE lower(hex(user_hash)) END,
               connect_options, file_comment, file_rating
        FROM transfer_sources
        WHERE transfer_id = ?1
        ORDER BY id
        "#,
    )?;
    let rows = stmt.query_map(params![transfer_id], |row| {
        Ok(MetadataTransferSource {
            ip: row.get(0)?,
            tcp_port: row.get::<_, i64>(1)? as u16,
            user_hash: row.get(2)?,
            connect_options: row.get::<_, Option<i64>>(3)?.map(|value| value as u8),
            file_comment: row.get(4)?,
            file_rating: row.get::<_, i64>(5)? as u8,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn imported_md4_hashset(conn: &rusqlite::Connection, imported_id: i64) -> Result<Vec<String>> {
    read_hex_list(
        conn,
        r#"
        SELECT lower(hex(md4_hash))
        FROM imported_known_file_md4_hashes
        WHERE imported_known_file_id = ?1
        ORDER BY part_index
        "#,
        imported_id,
    )
}

fn imported_aich_hashset(conn: &rusqlite::Connection, imported_id: i64) -> Result<Vec<String>> {
    read_hex_list(
        conn,
        r#"
        SELECT lower(hex(aich_hash))
        FROM imported_known_file_aich_hashes
        WHERE imported_known_file_id = ?1
        ORDER BY part_index
        "#,
        imported_id,
    )
}

pub(crate) fn optional_fingerprint_from_row(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<NativeFileFingerprint>> {
    let bytes = row.get::<_, Option<Vec<u8>>>(index)?;
    bytes
        .map(|bytes| {
            NativeFileFingerprint::from_storage_bytes(&bytes).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    index,
                    rusqlite::types::Type::Blob,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid native file fingerprint",
                    )
                    .into(),
                )
            })
        })
        .transpose()
}

fn optional_fixed_hex(
    value: Option<&str>,
    byte_len: usize,
    label: &str,
) -> Result<Option<Vec<u8>>> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(|value| decode_fixed_hex(value, byte_len, label))
        .transpose()
}

fn optional_local_path_id(
    tx: &rusqlite::Transaction<'_>,
    path: Option<&Path>,
) -> Result<Option<i64>> {
    path.filter(|path| !path.as_os_str().is_empty())
        .map(|path| upsert_local_path(tx, path))
        .transpose()
}

fn local_path_id(conn: &rusqlite::Connection, path: &Path) -> Result<Option<i64>> {
    let native_path = NativePath::from(path);
    conn.query_row(
        r#"
        SELECT id
        FROM local_paths
        WHERE platform = ?1 AND native_path = ?2
        "#,
        params![NativePath::platform(), native_path.storage_bytes()],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

fn validate_delivery_state(manifest: &MetadataTransferManifest) -> Result<()> {
    let valid = match manifest.delivery_state {
        MetadataTransferDeliveryState::NotApplicable => {
            manifest.source_path.is_some() && manifest.delivered_path.is_none()
        }
        MetadataTransferDeliveryState::Pending => {
            manifest.source_path.is_none() && manifest.delivered_path.is_none()
        }
        MetadataTransferDeliveryState::Delivered => {
            manifest.source_path.is_none() && manifest.delivered_path.is_some()
        }
    };
    if !valid {
        anyhow::bail!(
            "invalid delivery state {:?} for transfer {}: delivered_path={}, source_path={}",
            manifest.delivery_state,
            manifest.file_hash,
            manifest.delivered_path.is_some(),
            manifest.source_path.is_some()
        );
    }
    if let Some(fingerprint) = manifest.payload_fingerprint.as_ref() {
        ensure!(
            manifest.source_path.is_none()
                && manifest.completed
                && !manifest.final_rehash_pending
                && fingerprint.size_bytes == manifest.file_size,
            "invalid canonical payload fingerprint for transfer {}",
            manifest.file_hash
        );
    }
    Ok(())
}

fn delivery_state_to_sql(state: MetadataTransferDeliveryState) -> &'static str {
    match state {
        MetadataTransferDeliveryState::NotApplicable => "not_applicable",
        MetadataTransferDeliveryState::Pending => "pending",
        MetadataTransferDeliveryState::Delivered => "delivered",
    }
}

fn delivery_state_from_sql(value: &str) -> Result<MetadataTransferDeliveryState> {
    match value {
        "not_applicable" => Ok(MetadataTransferDeliveryState::NotApplicable),
        "pending" => Ok(MetadataTransferDeliveryState::Pending),
        "delivered" => Ok(MetadataTransferDeliveryState::Delivered),
        _ => anyhow::bail!("invalid persisted transfer delivery state {value:?}"),
    }
}

fn visible_state(manifest: &MetadataTransferManifest) -> &'static str {
    if manifest.completed {
        "completed"
    } else if manifest.final_rehash_pending {
        "completing"
    } else if manifest.pieces.iter().any(|piece| piece.bytes_written != 0) {
        "downloading"
    } else {
        "queued"
    }
}

#[cfg(test)]
mod tests;
