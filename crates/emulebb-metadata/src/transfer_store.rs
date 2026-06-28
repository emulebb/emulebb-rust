use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use crate::{
    store::{bool_to_i64, decode_fixed_hex, unix_ms},
    transfer_model::{
        MetadataShareInPlaceReloadEntry, MetadataTransferCatalogEntry, MetadataTransferCounts,
        MetadataTransferManifest, MetadataTransferPiece, MetadataTransferPublishEntry,
        MetadataTransferRange, MetadataTransferShareEntry, MetadataTransferSource,
    },
};

impl super::MetadataStore {
    pub fn upsert_transfer_manifest(&self, manifest: &MetadataTransferManifest) -> Result<()> {
        let hash = decode_fixed_hex(&manifest.file_hash, 16, "ED2K hash")?;
        let aich_root = optional_fixed_hex(manifest.aich_root.as_deref(), 20, "AICH root")?;
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;

        tx.execute(
            r#"
            INSERT INTO content_objects(
                kind, primary_hash_kind, primary_hash, display_name, size_bytes,
                first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES ('ed2k_file', 'ed2k', ?1, ?2, ?3, ?4, ?4, ?4)
            ON CONFLICT(kind, primary_hash_kind, primary_hash) DO UPDATE SET
                display_name = excluded.display_name,
                size_bytes = excluded.size_bytes,
                last_seen_ms = excluded.last_seen_ms,
                updated_at_ms = excluded.updated_at_ms,
                deleted_at_ms = NULL
            "#,
            params![
                hash,
                manifest.canonical_name,
                manifest.file_size as i64,
                now
            ],
        )?;
        let content_object_id: i64 = tx.query_row(
            r#"
            SELECT id FROM content_objects
            WHERE kind = 'ed2k_file' AND primary_hash_kind = 'ed2k' AND primary_hash = ?1
            "#,
            params![decode_fixed_hex(&manifest.file_hash, 16, "ED2K hash")?],
            |row| row.get(0),
        )?;

        tx.execute(
            r#"
            INSERT INTO known_files(
                content_object_id, ed2k_hash, size_bytes, canonical_name,
                part_size, part_count, completed, md4_hashset_acquired,
                aich_hashset_acquired, aich_root, upload_priority,
                auto_upload_priority, comment, rating,
                first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15, ?15)
            ON CONFLICT(ed2k_hash) DO UPDATE SET
                content_object_id = excluded.content_object_id,
                size_bytes = excluded.size_bytes,
                canonical_name = excluded.canonical_name,
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
            params![
                content_object_id,
                decode_fixed_hex(&manifest.file_hash, 16, "ED2K hash")?,
                manifest.file_size as i64,
                manifest.canonical_name,
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
            ],
        )?;
        let known_file_id: i64 = tx.query_row(
            "SELECT id FROM known_files WHERE ed2k_hash = ?1",
            params![decode_fixed_hex(&manifest.file_hash, 16, "ED2K hash")?],
            |row| row.get(0),
        )?;

        tx.execute(
            r#"
            INSERT INTO transfers(
                known_file_id, visible_state, control_state, priority,
                category_id, payload_directory, delivered_path, source_path,
                source_mtime_ms, created_at_ms, updated_at_ms,
                completed_at_ms, removed_at_ms
            )
            VALUES (?1, ?2, ?3, 'normal', ?4, ?5, ?6, ?10, ?11, ?7, ?7, ?8, ?9)
            ON CONFLICT(known_file_id) DO UPDATE SET
                visible_state = excluded.visible_state,
                control_state = excluded.control_state,
                category_id = excluded.category_id,
                payload_directory = excluded.payload_directory,
                delivered_path = excluded.delivered_path,
                source_path = excluded.source_path,
                source_mtime_ms = excluded.source_mtime_ms,
                updated_at_ms = excluded.updated_at_ms,
                completed_at_ms = excluded.completed_at_ms,
                removed_at_ms = excluded.removed_at_ms
            "#,
            params![
                known_file_id,
                visible_state(manifest),
                manifest.control_state,
                (manifest.category_id != 0).then_some(i64::from(manifest.category_id)),
                manifest.file_hash,
                manifest.delivered_path,
                now,
                if manifest.completed { Some(now) } else { None },
                if manifest.transfer_row_removed {
                    Some(now)
                } else {
                    None
                },
                manifest.source_path,
                manifest.source_mtime_ms,
            ],
        )?;
        let transfer_id: i64 = tx.query_row(
            "SELECT id FROM transfers WHERE known_file_id = ?1",
            params![known_file_id],
            |row| row.get(0),
        )?;

        replace_transfer_children(&tx, known_file_id, transfer_id, manifest, now)?;
        tx.commit()?;
        Ok(())
    }

    pub fn transfer_manifest_by_hash(
        &self,
        file_hash: &str,
    ) -> Result<Option<MetadataTransferManifest>> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let row = conn
            .query_row(
                r#"
                SELECT known_files.id, transfers.id,
                       lower(hex(known_files.ed2k_hash)), known_files.canonical_name,
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
                       transfers.delivered_path, transfers.source_path,
                       transfers.source_mtime_ms
                FROM known_files
                JOIN transfers ON transfers.known_file_id = known_files.id
                WHERE known_files.ed2k_hash = ?1
                "#,
                params![hash],
                |row| {
                    Ok(TransferRow {
                        known_file_id: row.get(0)?,
                        transfer_id: row.get(1)?,
                        file_hash: row.get(2)?,
                        canonical_name: row.get(3)?,
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
                        delivered_path: row.get(17)?,
                        source_path: row.get(18)?,
                        source_mtime_ms: row.get(19)?,
                    })
                },
            )
            .optional()?;
        row.map(|row| manifest_from_row(&conn, row)).transpose()
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
        let updated = conn.execute(
            r#"
            UPDATE known_files
            SET all_time_uploaded_bytes = all_time_uploaded_bytes + ?2
            WHERE ed2k_hash = ?1
            "#,
            params![hash, delta as i64],
        )?;
        Ok(updated != 0)
    }

    /// Returns the file's all-time upload ratio scaled to permille
    /// (`all_time_uploaded_bytes * 1000 / size_bytes`, eMule
    /// `CKnownFile::GetAllTimeUploadRatio`), or `None` for an unknown hash (so the
    /// caller can mirror eMule's `pRequestedFile == NULL` early return rather than
    /// treating an unknown file as a zero ratio). A known zero-size file yields
    /// ratio `0`.
    pub fn file_all_time_upload_ratio_permille_opt(&self, file_hash: &str) -> Result<Option<i128>> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let row = conn
            .query_row(
                r#"
                SELECT all_time_uploaded_bytes, size_bytes
                FROM known_files
                WHERE ed2k_hash = ?1
                "#,
                params![hash],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        Ok(row.map(|(uploaded, size)| {
            if size > 0 {
                i128::from(uploaded) * 1000 / i128::from(size)
            } else {
                0
            }
        }))
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
            "#,
            params![hash],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn transfer_manifests(&self) -> Result<Vec<MetadataTransferManifest>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT known_files.id, transfers.id,
                   lower(hex(known_files.ed2k_hash)), known_files.canonical_name,
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
                   transfers.delivered_path, transfers.source_path,
                   transfers.source_mtime_ms
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            ORDER BY known_files.ed2k_hash
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TransferRow {
                known_file_id: row.get(0)?,
                transfer_id: row.get(1)?,
                file_hash: row.get(2)?,
                canonical_name: row.get(3)?,
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
                delivered_path: row.get(17)?,
                source_path: row.get(18)?,
                source_mtime_ms: row.get(19)?,
            })
        })?;
        rows.map(|row| manifest_from_row(&conn, row?))
            .collect::<Result<Vec<_>>>()
    }

    pub fn completed_transfer_catalog_entries(&self) -> Result<Vec<MetadataTransferCatalogEntry>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), known_files.canonical_name,
                   known_files.size_bytes,
                   CASE
                       WHEN known_files.aich_root IS NULL THEN NULL
                       ELSE lower(hex(known_files.aich_root))
                   END
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE known_files.completed != 0
              AND NOT EXISTS (
                  SELECT 1 FROM unshared_files
                  WHERE unshared_files.known_file_id = known_files.id
              )
            ORDER BY known_files.ed2k_hash
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataTransferCatalogEntry {
                file_hash: row.get(0)?,
                canonical_name: row.get(1)?,
                file_size: row.get::<_, i64>(2)? as u64,
                aich_root: row.get(3)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn share_in_place_reload_entries(&self) -> Result<Vec<MetadataShareInPlaceReloadEntry>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), known_files.size_bytes,
                   transfers.source_path, transfers.source_mtime_ms
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE known_files.completed != 0
              AND transfers.source_path IS NOT NULL
              AND transfers.removed_at_ms IS NULL
            ORDER BY transfers.source_path
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataShareInPlaceReloadEntry {
                file_hash: row.get(0)?,
                file_size: row.get::<_, i64>(1)? as u64,
                source_path: row.get(2)?,
                source_mtime_ms: row.get(3)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
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
            SELECT lower(hex(known_files.ed2k_hash)), known_files.canonical_name,
                   known_files.size_bytes,
                   CASE
                       WHEN known_files.aich_root IS NULL THEN NULL
                       ELSE lower(hex(known_files.aich_root))
                   END,
                   known_files.comment, known_files.rating
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE known_files.completed != 0
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
                canonical_name: row.get(1)?,
                file_size: row.get::<_, i64>(2)? as u64,
                aich_root: row.get(3)?,
                comment: row.get(4)?,
                rating: row.get::<_, i64>(5)? as u8,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn completed_transfer_share_entries(&self) -> Result<Vec<MetadataTransferShareEntry>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), known_files.canonical_name,
                   known_files.size_bytes, coalesce(known_files.part_count, 0),
                   CASE
                       WHEN known_files.aich_root IS NULL THEN NULL
                       ELSE lower(hex(known_files.aich_root))
                   END,
                   known_files.upload_priority, known_files.auto_upload_priority,
                   known_files.comment, known_files.rating
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE known_files.completed != 0
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
                canonical_name: row.get(1)?,
                file_size: row.get::<_, i64>(2)? as u64,
                part_count: row.get::<_, i64>(3)? as u32,
                aich_root: row.get(4)?,
                upload_priority: row.get(5)?,
                auto_upload_priority: row.get::<_, i64>(6)? != 0,
                comment: row.get(7)?,
                rating: row.get::<_, i64>(8)? as u8,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn completed_transfer_share_entries_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<MetadataTransferShareEntry>, usize)> {
        let conn = self.connection()?;
        let total = conn.query_row(
            r#"
            SELECT count(*)
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE known_files.completed != 0
              AND NOT EXISTS (
                  SELECT 1 FROM unshared_files
                  WHERE unshared_files.known_file_id = known_files.id
              )
            "#,
            [],
            |row| row.get::<_, i64>(0),
        )? as usize;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), known_files.canonical_name,
                   known_files.size_bytes, coalesce(known_files.part_count, 0),
                   CASE
                       WHEN known_files.aich_root IS NULL THEN NULL
                       ELSE lower(hex(known_files.aich_root))
                   END,
                   known_files.upload_priority, known_files.auto_upload_priority,
                   known_files.comment, known_files.rating
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE known_files.completed != 0
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
                canonical_name: row.get(1)?,
                file_size: row.get::<_, i64>(2)? as u64,
                part_count: row.get::<_, i64>(3)? as u32,
                aich_root: row.get(4)?,
                upload_priority: row.get(5)?,
                auto_upload_priority: row.get::<_, i64>(6)? != 0,
                comment: row.get(7)?,
                rating: row.get::<_, i64>(8)? as u8,
            })
        })?;
        let entries = rows.collect::<Result<Vec<_>, _>>()?;
        Ok((entries, total))
    }

    pub fn pending_completed_delivery_hashes(&self) -> Result<Vec<String>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash))
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE known_files.completed != 0
              AND transfers.delivered_path IS NULL
              AND transfers.source_path IS NULL
              AND transfers.removed_at_ms IS NULL
            ORDER BY known_files.ed2k_hash
            "#,
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn delete_transfer_manifest(&self, file_hash: &str) -> Result<bool> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "DELETE FROM known_files WHERE ed2k_hash = ?1",
            params![hash],
        )?;
        tx.commit()?;
        Ok(changed != 0)
    }
}

#[derive(Debug)]
struct TransferRow {
    known_file_id: i64,
    transfer_id: i64,
    file_hash: String,
    canonical_name: String,
    file_size: u64,
    piece_size: u64,
    completed: bool,
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
    delivered_path: Option<String>,
    source_path: Option<String>,
    source_mtime_ms: Option<i64>,
}

fn replace_transfer_children(
    tx: &rusqlite::Transaction<'_>,
    known_file_id: i64,
    transfer_id: i64,
    manifest: &MetadataTransferManifest,
    now: i64,
) -> Result<()> {
    tx.execute(
        "DELETE FROM transfer_pieces WHERE transfer_id = ?1",
        params![transfer_id],
    )?;
    tx.execute(
        "DELETE FROM ed2k_part_hashes WHERE known_file_id = ?1",
        params![known_file_id],
    )?;
    tx.execute(
        "DELETE FROM aich_part_hashes WHERE known_file_id = ?1",
        params![known_file_id],
    )?;
    tx.execute(
        "DELETE FROM verified_ranges WHERE known_file_id = ?1",
        params![known_file_id],
    )?;
    tx.execute(
        "DELETE FROM transfer_sources WHERE transfer_id = ?1",
        params![transfer_id],
    )?;

    for piece in &manifest.pieces {
        tx.execute(
            r#"
            INSERT INTO transfer_pieces(transfer_id, piece_index, state, bytes_written, block_bitmap, updated_at_ms)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                transfer_id,
                i64::from(piece.piece_index),
                piece.state,
                piece.bytes_written as i64,
                piece.block_bitmap,
                now,
            ],
        )?;
    }
    for (index, hash) in manifest.md4_hashset.iter().enumerate() {
        tx.execute(
            r#"
            INSERT INTO ed2k_part_hashes(known_file_id, part_index, md4_hash)
            VALUES (?1, ?2, ?3)
            "#,
            params![
                known_file_id,
                index as i64,
                decode_fixed_hex(hash, 16, "MD4 part hash")?,
            ],
        )?;
    }
    for (index, hash) in manifest.aich_hashset.iter().enumerate() {
        tx.execute(
            r#"
            INSERT INTO aich_part_hashes(known_file_id, part_index, aich_hash)
            VALUES (?1, ?2, ?3)
            "#,
            params![
                known_file_id,
                index as i64,
                decode_fixed_hex(hash, 20, "AICH part hash")?,
            ],
        )?;
    }
    for range in &manifest.verified_ranges {
        tx.execute(
            r#"
            INSERT INTO verified_ranges(known_file_id, start_offset, end_offset, source_kind, created_at_ms)
            VALUES (?1, ?2, ?3, 'ed2k_transfer', ?4)
            "#,
            params![known_file_id, range.start as i64, range.end as i64, now],
        )?;
    }
    for source in &manifest.sources {
        tx.execute(
            r#"
            INSERT INTO transfer_sources(
                transfer_id, ip, tcp_port, user_hash, first_seen_ms, last_seen_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?5)
            "#,
            params![
                transfer_id,
                source.ip,
                i64::from(source.tcp_port),
                optional_fixed_hex(source.user_hash.as_deref(), 16, "source user hash")?,
                now,
            ],
        )?;
    }
    Ok(())
}

fn manifest_from_row(
    conn: &rusqlite::Connection,
    row: TransferRow,
) -> Result<MetadataTransferManifest> {
    Ok(MetadataTransferManifest {
        file_hash: row.file_hash,
        canonical_name: row.canonical_name,
        file_size: row.file_size,
        piece_size: row.piece_size,
        completed: row.completed,
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
        delivered_path: row.delivered_path,
        source_path: row.source_path,
        source_mtime_ms: row.source_mtime_ms,
    })
}

fn transfer_counts_from_connection(conn: &rusqlite::Connection) -> Result<MetadataTransferCounts> {
    conn.query_row(
        r#"
        SELECT count(*),
               coalesce(sum(CASE
                   WHEN known_files.completed = 0
                        AND transfers.control_state IS NULL
                        AND transfers.visible_state IN ('downloading', 'queued')
                   THEN 1 ELSE 0 END), 0),
               coalesce(sum(CASE
                   WHEN known_files.completed != 0 THEN 1 ELSE 0 END), 0)
        FROM transfers
        JOIN known_files ON known_files.id = transfers.known_file_id
        WHERE transfers.removed_at_ms IS NULL
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
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params![id], |row| row.get(0))?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn read_pieces(
    conn: &rusqlite::Connection,
    transfer_id: i64,
) -> Result<Vec<MetadataTransferPiece>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT piece_index, state, bytes_written, block_bitmap
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
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn read_ranges(
    conn: &rusqlite::Connection,
    known_file_id: i64,
) -> Result<Vec<MetadataTransferRange>> {
    let mut stmt = conn.prepare(
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
    let mut stmt = conn.prepare(
        r#"
        SELECT ip, tcp_port,
               CASE WHEN user_hash IS NULL THEN NULL ELSE lower(hex(user_hash)) END
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
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
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

fn visible_state(manifest: &MetadataTransferManifest) -> &'static str {
    if manifest.completed {
        "completed"
    } else if manifest.control_state.is_some() {
        "controlled"
    } else if manifest.pieces.iter().any(|piece| piece.bytes_written != 0) {
        "downloading"
    } else {
        "queued"
    }
}

#[cfg(test)]
mod tests;
