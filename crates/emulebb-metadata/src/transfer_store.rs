use std::path::Path;

use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use uuid::Uuid;

use crate::{
    DownloadIntent, JobId, JobToken, MetadataDownloadRetirement, NativeFileFingerprint,
    NativeFileIdentity, NativePath,
    download_history_store::{record_completed_download, records_download_completion},
    native_path::{optional_path_from_row, path_from_row},
    store::{bool_to_i64, decode_fixed_hex, unix_ms, upsert_local_path},
    transfer_model::{
        MetadataSharedSourceFailure, MetadataTransferAichIdentity, MetadataTransferCatalogEntry,
        MetadataTransferCounts, MetadataTransferDeletionTombstone,
        MetadataTransferDeletionTombstonePhase, MetadataTransferDeliveryAttempt,
        MetadataTransferDeliveryAttemptPhase, MetadataTransferDeliveryOwnership,
        MetadataTransferDeliveryState, MetadataTransferDirectoryDeletionAuthority,
        MetadataTransferManifest, MetadataTransferMediaMetadata, MetadataTransferPiece,
        MetadataTransferPublishEntry, MetadataTransferRange,
    },
};

// WHY: without statistics SQLite can prefer the broader runnable-job index,
// walking arbitrarily many unfinished jobs to find one delivery candidate.
const PENDING_DELIVERY_PAGE_SQL: &str = "SELECT id FROM download_jobs
    INDEXED BY download_jobs_pending_delivery_page_idx WHERE id>?1
    AND completed=1 AND final_rehash_pending=0 AND terminal_completed_at_s IS NULL
    AND removed_at_s IS NULL AND delete_requested_at_s IS NULL
    AND intent='started' AND storage_failure_code IS NULL ORDER BY id LIMIT ?2";

impl super::MetadataStore {
    pub fn upsert_transfer_manifest(&self, manifest: &MetadataTransferManifest) -> Result<()> {
        self.upsert_transfer_manifest_reconciled(manifest)
            .map(|_| ())
    }

    /// Persist progress while retaining any newer accepted AICH authority. The
    /// returned row is the exact manifest committed, including identity-only
    /// reconciliation; callers must publish this row rather than their stale
    /// input. Piece progress and MD4 verification are never reset here.
    pub fn upsert_transfer_manifest_reconciled(
        &self,
        manifest: &MetadataTransferManifest,
    ) -> Result<MetadataTransferManifest> {
        crate::transfer_validation::validate_manifest(manifest)?;
        ensure!(
            manifest.display_name.len() <= crate::download_job_store::MAX_JOB_TEXT_BYTES,
            "download name exceeds metadata allowance"
        );
        if let Some(path) = manifest.delivered_path.as_deref() {
            crate::download_job_store::validate_job_path(path)?;
        }
        let hash = decode_fixed_hex(&manifest.file_hash, 16, "ED2K hash")?;
        let now = crate::download_job_store::unix_s();
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = crate::download_job_store::read_job(&tx, manifest.token.job_id)?
            .ok_or_else(|| anyhow::anyhow!("download job does not exist"))?;
        ensure!(
            current.token == manifest.token
                && current.file_hash == manifest.file_hash.to_ascii_lowercase(),
            "stale download job identity or execution generation"
        );
        ensure!(
            current.removed_at_s.is_none() && current.completed_at_s.is_none(),
            "removed or terminal download job cannot accept progress"
        );
        let cleanup: bool = tx.query_row("SELECT delete_requested_at_s IS NOT NULL OR EXISTS(
            SELECT 1 FROM download_retirements WHERE job_id=download_jobs.id) FROM download_jobs WHERE id=?1",
            [manifest.token.job_id], |row| row.get(0))?;
        ensure!(!cleanup, "download job has pending cleanup");
        ensure!(
            current.expected_size_bytes == manifest.expected_size_bytes,
            crate::MetadataContentConflict("download attempt has conflicting expected size")
        );
        let persisted_delivery = tx
            .query_row(
                "SELECT p.platform, CASE WHEN length(p.native_path)<=65536 THEN p.native_path END,
                j.delivery_ownership,j.source_fingerprint
             FROM download_jobs j JOIN local_paths p ON p.id=j.delivered_path_id
             WHERE j.id=?1 AND j.delivery_state='delivered'",
                [manifest.token.job_id],
                |row| {
                    Ok((
                        path_from_row(row, 0, 1)?,
                        row.get::<_, String>(2)?,
                        optional_fingerprint_from_row(row, 3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((path, _, _)) = &persisted_delivery {
            ensure!(
                manifest.delivery_state == MetadataTransferDeliveryState::Delivered
                    && manifest.delivered_path.as_ref() == Some(path)
                    && manifest.completed
                    && !manifest.final_rehash_pending,
                "durable delivery cannot be undone by a progress checkpoint"
            );
        }
        let mut reconciled = manifest.clone();
        if let Some((_, ownership, fingerprint)) = persisted_delivery {
            // WHY: a same-generation checkpoint can predate the dedicated
            // evidence refresh. Persisted Unowned/new evidence must win, or a
            // stale Owned clone would recreate destructive output authority.
            reconciled.delivery_ownership = delivery_ownership_from_sql(&ownership)?;
            reconciled.source_fingerprint = fingerprint;
        }
        reconciled.display_name = current.display_name;
        reconciled.expected_size_bytes = current.expected_size_bytes;
        reconciled.intent = current.intent;
        reconciled.transfer_row_removed = current.removed_at_s.is_some();
        reconciled.category_id = current.category_id;
        reconcile_manifest_aich_identity(&tx, &hash, &mut reconciled)?;
        let manifest = &reconciled;
        let aich_root = optional_fixed_hex(manifest.aich_root.as_deref(), 20, "AICH root")?;
        let accepted_root = if manifest.aich_root_origin.as_deref() == Some("network_consensus") {
            None
        } else {
            aich_root.as_deref()
        };
        if let Some(size) = manifest.expected_size_bytes {
            crate::content_identity::check_accepted_identity(
                &tx,
                &hash,
                i64::try_from(size)?,
                aich_root.as_deref(),
            )?;
        }
        let verified = records_download_completion(manifest);
        let previous: (bool, Option<i64>) = tx.query_row(
            "SELECT completed=1 AND final_rehash_pending=0,completed_at_s
            FROM download_jobs WHERE id=?1",
            [manifest.token.job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let transition = verified && !previous.0;
        let history_completed: Option<i64> = tx
            .query_row(
                "SELECT last_completed_at_s FROM download_history WHERE ed2k_hash=?1",
                [&hash],
                |row| row.get(0),
            )
            .optional()?;
        let completed_at = if transition {
            Some(
                now.max(previous.1.unwrap_or(0))
                    .max(history_completed.unwrap_or(0)),
            )
        } else {
            previous.1
        };
        // Only whole-payload verification accepts a size fact. Claims remain on the job.
        if verified {
            let size = manifest
                .expected_size_bytes
                .ok_or_else(|| anyhow::anyhow!("verified job has unknown size"))?;
            tx.execute(
                "UPDATE known_files SET size_bytes=?2,aich_root=coalesce(?3,aich_root),
                aich_root_origin=CASE WHEN ?3 IS NULL THEN aich_root_origin ELSE ?4 END
                WHERE id=(SELECT known_file_id FROM download_jobs WHERE id=?1)",
                params![
                    manifest.token.job_id,
                    i64::try_from(size)?,
                    accepted_root,
                    accepted_root.and(manifest.aich_root_origin.as_deref())
                ],
            )?;
        }
        let delivered_path = optional_local_path_id(&tx, manifest.delivered_path.as_deref())?;
        let source = manifest
            .source_fingerprint
            .as_ref()
            .map(NativeFileFingerprint::storage_bytes);
        let payload = manifest
            .payload_fingerprint
            .as_ref()
            .map(NativeFileFingerprint::storage_bytes);
        tx.execute(
            "UPDATE download_jobs SET expected_size_bytes=?2,display_name=?3,completed=?4,
            md4_hashset_acquired=?5,aich_hashset_acquired=?6,aich_root=?7,aich_root_origin=?8,
            aich_trust_generation=?9,visible_state=?10,final_rehash_pending=?11,
            part_size_bytes=?12,part_count=?13,upload_priority=?14,auto_upload_priority=?15,
            comment=?16,rating=?17,delivery_state=?18,delivery_ownership=?19,delivered_path_id=?20,
            source_fingerprint=?21,payload_fingerprint=?22,updated_at_s=?23,completed_at_s=?24
            WHERE id=?1",
            params![
                manifest.token.job_id,
                manifest
                    .expected_size_bytes
                    .map(i64::try_from)
                    .transpose()?,
                manifest.display_name,
                manifest.completed,
                manifest.md4_hashset_acquired,
                manifest.aich_hashset_acquired,
                aich_root,
                manifest.aich_root_origin,
                i64::try_from(manifest.aich_trust_generation)?,
                visible_state(manifest),
                manifest.final_rehash_pending,
                i64::try_from(manifest.piece_size)?,
                i64::try_from(manifest.pieces.len())?,
                manifest.upload_priority,
                manifest.auto_upload_priority,
                manifest.comment,
                manifest.rating,
                delivery_state_to_sql(manifest.delivery_state),
                delivery_ownership_to_sql(manifest.delivery_ownership),
                delivered_path,
                source,
                payload,
                now,
                completed_at
            ],
        )?;
        replace_transfer_children(&tx, manifest.token.job_id.get(), manifest, now)?;
        record_completed_download(
            &tx,
            manifest,
            &hash,
            accepted_root,
            completed_at,
            transition,
        )?;
        tx.commit()?;
        Ok(reconciled)
    }

    /// Assign a transfer without replacing unrelated progress or content state.
    pub fn assign_transfer_category(&self, id: JobId, category_id: Option<i64>) -> Result<bool> {
        let conn = self.connection()?;
        let changed = conn.execute(
            "UPDATE download_jobs SET category_id=?1 WHERE id=?2",
            params![category_id, id],
        )?;
        Ok(changed != 0)
    }

    /// Read the current assignment without loading transfer children.
    pub fn download_job_category(&self, id: JobId) -> Result<Option<Option<i64>>> {
        let conn = self.connection()?;
        conn.query_row("SELECT t.category_id FROM download_jobs t JOIN known_files k ON k.id=t.known_file_id WHERE t.id=?1", [id], |row| row.get(0)).optional().map_err(Into::into)
    }

    /// Bounded transfer-only projection for restoring a partial share after a root change.
    pub fn partial_share_for_category_reconciliation(
        &self,
        file_hash: &str,
    ) -> Result<Option<crate::MetadataPartialShare>> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let result = Self::partial_share_on_connection(&tx, file_hash)?;
        tx.commit()?;
        Ok(result)
    }

    pub(crate) fn partial_share_on_connection(
        conn: &rusqlite::Connection,
        file_hash: &str,
    ) -> Result<Option<crate::MetadataPartialShare>> {
        const MAX_TEXT_BYTES: i64 = 65_536;
        const MAX_RANGES: i64 = 28_258;
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let header: Option<(i64, i64, i64, i64, u64)> = conn.query_row(
            "SELECT t.id,length(CAST(t.display_name AS BLOB)),length(CAST(t.comment AS BLOB)),length(CAST(t.upload_priority AS BLOB)),t.execution_generation FROM download_jobs t JOIN known_files k ON k.id=t.known_file_id WHERE k.ed2k_hash=?1 AND t.completed=0 AND t.final_rehash_pending=0 AND t.md4_hashset_acquired=1 AND t.removed_at_s IS NULL AND t.delete_requested_at_s IS NULL",
            [&hash], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,crate::sql_value::unsigned::<u64>(row,4)?)),
        ).optional()?;
        let Some((id, name_len, comment_len, priority_len, generation)) = header else {
            return Ok(None);
        };
        ensure!(
            [name_len, comment_len, priority_len]
                .into_iter()
                .all(|n| (0..=MAX_TEXT_BYTES).contains(&n)),
            "partial share text exceeds reconciliation budget"
        );
        let count: i64 = conn.query_row(
            "SELECT count(*) FROM (SELECT 1 FROM download_job_verified_ranges WHERE job_id=?1 LIMIT 28259)",
            [id],
            |row| row.get(0),
        )?;
        ensure!(
            count <= MAX_RANGES,
            "partial share ranges exceed reconciliation budget"
        );
        if count == 0 {
            return Ok(None);
        }
        let (display_name,file_size,aich_root,upload_priority,auto_upload_priority,comment,rating) = conn.query_row(
            "SELECT t.display_name,t.expected_size_bytes,CASE WHEN t.aich_root IS NULL THEN NULL ELSE lower(hex(t.aich_root)) END,t.upload_priority,t.auto_upload_priority,t.comment,t.rating FROM download_jobs t JOIN known_files k ON k.id=t.known_file_id WHERE t.id=?1", [id],
            |row| Ok((row.get::<_,String>(0)?,crate::sql_value::unsigned::<u64>(row,1)?,row.get::<_,Option<String>>(2)?,row.get::<_,String>(3)?,row.get::<_,i64>(4)? != 0,row.get::<_,String>(5)?,row.get::<_,u8>(6)?)),
        )?;
        let mut stmt = conn.prepare_cached("SELECT start_offset,end_offset FROM download_job_verified_ranges WHERE job_id=?1 ORDER BY start_offset,end_offset")?;
        let rows = stmt.query_map([id], |row| {
            Ok(crate::MetadataTransferRange {
                start: crate::sql_value::unsigned::<u64>(row, 0)?,
                end: crate::sql_value::unsigned::<u64>(row, 1)?,
            })
        })?;
        let mut ranges = Vec::with_capacity(usize::try_from(count)?);
        for row in rows {
            ranges.push(row?);
        }
        drop(stmt);
        Ok(Some(crate::MetadataPartialShare {
            job_token: JobToken {
                job_id: JobId::new(id)?,
                generation,
            },
            file_hash: file_hash.to_owned(),
            display_name,
            file_size,
            aich_root,
            upload_priority,
            auto_upload_priority,
            comment,
            rating,
            ranges,
        }))
    }

    /// Exact execution identity read; a stale callback cannot borrow a newer
    /// same-content attempt's network consensus or trust generation.
    pub fn download_job_aich_identity(
        &self,
        token: JobToken,
    ) -> Result<Option<MetadataTransferAichIdentity>> {
        {
            let conn = self.connection()?;
            read_download_job_aich_identity(&conn, token)
        }
    }

    /// Publish bounded identity and sharing state under the existing SQLite mutex. The
    /// captured token is rechecked here, never refreshed after network or I/O.
    pub fn publish_download_job_state<T>(
        &self,
        token: JobToken,
        publish: impl FnOnce(MetadataTransferAichIdentity, bool) -> Result<T>,
    ) -> Result<T> {
        let conn = self.connection()?;
        let identity = read_download_job_aich_identity(&conn, token)?
            .ok_or_else(|| anyhow::anyhow!("stale or missing download job AICH identity"))?;
        let enabled = conn.query_row(
            "SELECT k.sharing_enabled FROM download_jobs j JOIN known_files k ON k.id=j.known_file_id WHERE j.id=?1",
            [token.job_id.get()], |row| row.get(0),
        )?;
        publish(identity, enabled)
    }

    pub fn download_job_manifest(&self, id: JobId) -> Result<Option<MetadataTransferManifest>> {
        self.download_job_manifest_for_deletion_state(id, false)
    }

    /// Read the manifest retained solely to resume a pending destructive
    /// deletion. Normal manifest reads deliberately suppress this row.
    pub fn pending_download_job_deletion_manifest(
        &self,
        id: JobId,
    ) -> Result<Option<MetadataTransferManifest>> {
        self.download_job_manifest_for_deletion_state(id, true)
    }

    fn download_job_manifest_for_deletion_state(
        &self,
        id: JobId,
        deletion_requested: bool,
    ) -> Result<Option<MetadataTransferManifest>> {
        let mut connection = self.connection()?;
        let conn = connection.transaction()?;
        let row = read_transfer_row(&conn, id, deletion_requested)?;
        let result = row.map(|row| manifest_from_row(&conn, row)).transpose()?;
        conn.commit()?;
        Ok(result)
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
                SET all_time_uploaded_bytes = all_time_uploaded_bytes + min(?2, 9223372036854775807 - all_time_uploaded_bytes)
                WHERE ed2k_hash = ?1
                "#,
            )?
            .execute(params![hash, i64::try_from(delta).unwrap_or(i64::MAX)])?;
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
                SET all_time_upload_requests = all_time_upload_requests + min(1, 9223372036854775807 - all_time_upload_requests),
                    last_upload_requested_at_ms = max(last_upload_requested_at_ms, ?2)
                WHERE ed2k_hash = ?1
                "#,
            )?
            .execute(params![hash, at_ms])?;
        Ok(updated != 0)
    }

    /// Returns the file's persisted `(all_time_uploaded_bytes, size_bytes)`,
    /// using accepted size or the sole current job's claim. Returns `None` for
    /// an unknown hash or unknown size (so the caller can mirror eMule's
    /// `pRequestedFile == NULL` early return rather than treating an unknown
    /// file as a zero ratio). The caller computes the all-time upload ratio
    /// (eMule `CKnownFile::GetAllTimeUploadRatio`) so parked, not-yet-flushed
    /// uploaded deltas can be added on top of the persisted total.
    pub fn file_all_time_upload_totals(&self, file_hash: &str) -> Result<Option<(u64, u64)>> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        conn.prepare_cached(
            r#"
            SELECT k.all_time_uploaded_bytes, coalesce(k.size_bytes,j.expected_size_bytes)
            FROM known_files k
            LEFT JOIN download_jobs j ON j.known_file_id=k.id AND j.removed_at_s IS NULL
                AND j.terminal_completed_at_s IS NULL AND j.delete_requested_at_s IS NULL
            WHERE k.ed2k_hash = ?1 AND coalesce(k.size_bytes,j.expected_size_bytes) IS NOT NULL
            "#,
        )?
        .query_row(params![hash], |row| {
            Ok((
                crate::sql_value::unsigned::<u64>(row, 0)?,
                crate::sql_value::unsigned::<u64>(row, 1)?,
            ))
        })
        .optional()
        .map_err(Into::into)
    }

    /// Returns the persisted `(created_at_s, completed_at_s)` for a transfer,
    /// used to surface `addedAt` / `completedAt` in the REST transfer view.
    pub fn download_job_timestamps(&self, id: JobId) -> Result<Option<(i64, Option<i64>)>> {
        let conn = self.connection()?;
        conn.query_row(
            r#"
            SELECT download_jobs.created_at_s, download_jobs.completed_at_s
            FROM known_files
            JOIN download_jobs ON download_jobs.known_file_id = known_files.id
            WHERE download_jobs.id = ?1
              AND download_jobs.delete_requested_at_s IS NULL
            "#,
            params![id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()
        .map_err(Into::into)
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
        ensure!((1..=256).contains(&limit), "invalid catalog page size");
        let after_hash = after_hash
            .map(|hash| decode_fixed_hex(hash, 16, "ED2K hash"))
            .transpose()?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let conn = self.connection()?;
        let representative = crate::local_catalog::representative_path(true);
        let mut stmt = conn.prepare(&format!(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), CASE WHEN length(CAST(verified_local_content.display_name AS BLOB))<=65536 THEN verified_local_content.display_name END,
                   known_files.size_bytes, coalesce(verified_local_content.part_count, 0),
                   CASE
                       WHEN known_files.aich_root IS NULL THEN NULL
                       ELSE lower(hex(known_files.aich_root))
                   END,
                   CASE WHEN length(CAST(verified_local_content.upload_priority AS BLOB))<=65536 THEN verified_local_content.upload_priority END, verified_local_content.auto_upload_priority,
                   CASE WHEN length(CAST(verified_local_content.comment AS BLOB))<=65536 THEN verified_local_content.comment END, verified_local_content.rating,
                   known_files.all_time_uploaded_bytes,
                   known_files.all_time_upload_requests,
                   known_files.all_time_upload_accepts,
                   known_files.last_upload_requested_at_ms,
                   media_paths.platform, CASE WHEN length(CAST(media_paths.native_path AS BLOB))<=65536 THEN media_paths.native_path END,
                   CASE WHEN length(CAST(known_files.media_artist AS BLOB))<=65536 THEN known_files.media_artist END, CASE WHEN length(CAST(known_files.media_album AS BLOB))<=65536 THEN known_files.media_album END,
                   CASE WHEN length(CAST(known_files.media_title AS BLOB))<=65536 THEN known_files.media_title END, known_files.media_length_seconds,
                   known_files.media_bitrate_kbps, CASE WHEN length(CAST(known_files.media_codec AS BLOB))<=65536 THEN known_files.media_codec END,
                   known_files.media_extractor_version, length(CAST(verified_local_content.display_name AS BLOB)),length(CAST(verified_local_content.upload_priority AS BLOB)),length(CAST(verified_local_content.comment AS BLOB)),length(CAST(known_files.media_artist AS BLOB)),length(CAST(known_files.media_album AS BLOB)),length(CAST(known_files.media_title AS BLOB)),length(CAST(known_files.media_codec AS BLOB)),length(CAST(media_paths.native_path AS BLOB))
            FROM known_files
            JOIN verified_local_content ON verified_local_content.known_file_id = known_files.id
            JOIN local_paths media_paths ON media_paths.id = ({representative})
            WHERE (?1 IS NULL OR known_files.ed2k_hash > ?1)
            ORDER BY known_files.ed2k_hash
            LIMIT ?2
            "#
        ))?;
        let mut rows = stmt.query(params![after_hash, limit])?;
        let mut entries = Vec::new();
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            let charge = crate::download_job_store::bounded_row_bytes(
                row,
                &[
                    (22, 65536, 2),
                    (23, 65536, 2),
                    (24, 65536, 2),
                    (25, 65536, 2),
                    (26, 65536, 2),
                    (27, 65536, 2),
                    (28, 65536, 2),
                    (29, 65536, 4),
                ],
            )?;
            if bytes + charge > crate::download_job_store::JOB_PAGE_BYTES {
                ensure!(!entries.is_empty(), "catalog row exceeds page allowance");
                break;
            }
            bytes += charge;
            entries.push(MetadataTransferCatalogEntry {
                file_hash: row.get(0)?,
                display_name: row.get(1)?,
                file_size: crate::sql_value::unsigned::<u64>(row, 2)?,
                part_count: row.get::<_, u32>(3)?,
                aich_root: row.get(4)?,
                upload_priority: row.get(5)?,
                auto_upload_priority: row.get::<_, i64>(6)? != 0,
                comment: row.get(7)?,
                rating: row.get::<_, u8>(8)?,
                all_time_uploaded_bytes: crate::sql_value::unsigned::<u64>(row, 9)?,
                all_time_upload_requests: crate::sql_value::unsigned::<u64>(row, 10)?,
                all_time_upload_accepts: crate::sql_value::unsigned::<u64>(row, 11)?,
                last_upload_request_ms: row.get(12)?,
                media_path: optional_path_from_row(row, 13, 14)?,
                media: MetadataTransferMediaMetadata {
                    artist: row.get(15)?,
                    album: row.get(16)?,
                    title: row.get(17)?,
                    length_seconds: row.get::<_, u32>(18)?,
                    bitrate_kbps: row.get::<_, u32>(19)?,
                    codec: row.get(20)?,
                    extractor_version: row.get::<_, u32>(21)?,
                },
            });
        }
        Ok(entries)
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
                        length_seconds: row.get::<_, u32>(3)?,
                        bitrate_kbps: row.get::<_, u32>(4)?,
                        codec: row.get(5)?,
                        extractor_version: row.get::<_, u32>(6)?,
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
        let conn = self.connection()?;
        Self::update_transfer_media_on_connection(&conn, file_hash, media)
    }

    pub(crate) fn update_transfer_media_on_connection(
        conn: &rusqlite::Connection,
        file_hash: &str,
        media: &MetadataTransferMediaMetadata,
    ) -> Result<bool> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let changed = conn.execute(
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

    pub fn shared_source_failures(&self) -> Result<Vec<MetadataSharedSourceFailure>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT local_paths.platform, local_paths.native_path,
                   shared_file_scan_failures.size_bytes,
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
                file_size: crate::sql_value::unsigned::<u64>(row, 2)?,
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
                path_id, size_bytes, source_fingerprint, reason,
                created_at_ms, updated_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?5)
            ON CONFLICT(path_id) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                source_fingerprint = excluded.source_fingerprint,
                reason = excluded.reason,
                updated_at_ms = excluded.updated_at_ms
            "#,
            params![
                path_id,
                i64::try_from(file_size)?,
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

    pub fn download_publish_entries_after(
        &self,
        after_hash: Option<&str>,
        limit: usize,
    ) -> Result<Vec<MetadataTransferPublishEntry>> {
        {
            let conn = self.connection()?;
            publish_entries_after(&conn, after_hash, limit)
        }
    }
    pub fn try_download_publish_entries_after(
        &self,
        after_hash: Option<&str>,
        limit: usize,
    ) -> Result<Option<Vec<MetadataTransferPublishEntry>>> {
        let Some(conn) = self.try_connection()? else {
            return Ok(None);
        };
        publish_entries_after(&conn, after_hash, limit).map(Some)
    }

    /// Pending preterminal materialization/admission work; history never redelivers automatically.
    pub fn pending_delivery_jobs_after(
        &self,
        after: Option<JobId>,
        limit: usize,
    ) -> Result<Vec<JobId>> {
        ensure!((1..=256).contains(&limit), "invalid delivery job page size");
        let conn = self.connection()?;
        let mut stmt = conn.prepare_cached(PENDING_DELIVERY_PAGE_SQL)?;
        Ok(stmt
            .query_map(
                params![after.map_or(0, JobId::get), i64::try_from(limit)?],
                |row| row.get(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn begin_transfer_delivery_attempt(
        &self,
        token: JobToken,
        attempt_id: Uuid,
        target_path: &Path,
        staging_path: &Path,
    ) -> Result<MetadataTransferDeliveryAttempt> {
        let id = token.job_id;
        ensure!(
            target_path.is_absolute(),
            "delivery target path must be absolute"
        );
        ensure!(
            staging_path.is_absolute(),
            "delivery staging path must be absolute"
        );
        ensure!(
            target_path != staging_path,
            "delivery target and staging paths must differ"
        );
        ensure!(
            target_path.parent().is_some() && target_path.parent() == staging_path.parent(),
            "delivery target and staging paths must share one parent directory"
        );
        ensure!(
            staging_path.file_name().is_some_and(|name| {
                name == std::ffi::OsStr::new(&format!(".emulebb-delivery-{attempt_id}.tmp"))
            }),
            "delivery staging path does not match attempt {attempt_id}"
        );

        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job_id = tx
            .query_row(
                r#"
                SELECT download_jobs.id
                FROM known_files
                JOIN download_jobs ON download_jobs.known_file_id = known_files.id
                WHERE download_jobs.id = ?1 AND download_jobs.execution_generation=?2
                  AND download_jobs.intent='started' AND download_jobs.completed != 0
                  AND download_jobs.final_rehash_pending = 0
                  AND download_jobs.delivery_state = 'pending'
                  AND download_jobs.delivered_path_id IS NULL
                  AND download_jobs.removed_at_s IS NULL
                  AND download_jobs.delete_requested_at_s IS NULL
                "#,
                params![id, i64::try_from(token.generation)?],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(job_id) = job_id else {
            anyhow::bail!("transfer {id} is not eligible for delivery");
        };
        if let Some(existing) = delivery_attempt_by_job(&tx, id)? {
            ensure!(
                existing.attempt_id == attempt_id
                    && existing.target_path == target_path
                    && existing.staging_path == staging_path,
                "transfer {id} already has a different delivery attempt"
            );
            tx.commit()?;
            return Ok(existing);
        }
        let target_path_id = upsert_local_path(&tx, target_path)?;
        let staging_path_id = upsert_local_path(&tx, staging_path)?;
        ensure!(
            target_path_id != staging_path_id,
            "delivery target and staging paths must have distinct native identities"
        );
        let now = crate::download_job_store::unix_s();
        tx.execute(
            r#"
            INSERT INTO download_delivery_attempts(
                job_id, attempt_id, phase, target_path_id, staging_path_id,
                created_at_s, updated_at_s
            )
            VALUES (?1, ?2, 'prepared', ?3, ?4, ?5, ?5)
            "#,
            params![
                job_id,
                attempt_id.hyphenated().to_string(),
                target_path_id,
                staging_path_id,
                now,
            ],
        )?;
        let attempt = delivery_attempt_by_job(&tx, id)?
            .expect("inserted delivery attempt must be queryable in its transaction");
        tx.commit()?;
        Ok(attempt)
    }

    pub fn download_job_delivery_attempt(
        &self,
        id: JobId,
    ) -> Result<Option<MetadataTransferDeliveryAttempt>> {
        let conn = self.connection()?;
        delivery_attempt_by_job(&conn, id)
    }

    pub fn download_delivery_attempts_after(
        &self,
        after: Option<JobId>,
        limit: usize,
    ) -> Result<Vec<MetadataTransferDeliveryAttempt>> {
        ensure!((1..=256).contains(&limit), "invalid delivery page size");
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), download_delivery_attempts.attempt_id,
                   download_delivery_attempts.phase,
                   target_paths.platform, CASE WHEN length(target_paths.native_path)<=65536 THEN target_paths.native_path END,
                   staging_paths.platform, CASE WHEN length(staging_paths.native_path)<=65536 THEN staging_paths.native_path END,
                   CASE WHEN length(download_delivery_attempts.staging_fingerprint)<=1024 THEN download_delivery_attempts.staging_fingerprint END,
                   CASE WHEN length(download_delivery_attempts.published_fingerprint)<=1024 THEN download_delivery_attempts.published_fingerprint END,
                   download_delivery_attempts.created_at_s, download_delivery_attempts.updated_at_s, download_jobs.id, length(target_paths.native_path),length(staging_paths.native_path),length(download_delivery_attempts.staging_fingerprint),length(download_delivery_attempts.published_fingerprint)
            FROM download_delivery_attempts
            JOIN download_jobs ON download_jobs.id = download_delivery_attempts.job_id
            JOIN known_files ON known_files.id = download_jobs.known_file_id
            JOIN local_paths target_paths ON target_paths.id = download_delivery_attempts.target_path_id
            JOIN local_paths staging_paths ON staging_paths.id = download_delivery_attempts.staging_path_id
            WHERE download_jobs.id>?1 ORDER BY download_jobs.id LIMIT ?2
            "#,
        )?;
        let mut rows = stmt.query(params![after.map_or(0, JobId::get), i64::try_from(limit)?])?;
        let mut entries = Vec::new();
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            let charge = delivery_attempt_row_bytes(row)?;
            if bytes + charge > crate::download_job_store::JOB_PAGE_BYTES {
                ensure!(!entries.is_empty(), "delivery row exceeds page allowance");
                break;
            }
            bytes += charge;
            entries.push(delivery_attempt_from_row(row)?);
        }
        Ok(entries)
    }

    pub fn mark_transfer_delivery_attempt_staged(
        &self,
        token: JobToken,
        attempt_id: Uuid,
        staging_fingerprint: &NativeFileFingerprint,
    ) -> Result<Option<MetadataTransferDeliveryAttempt>> {
        let id = token.job_id;
        let now = crate::download_job_store::unix_s();
        let staging_fingerprint = staging_fingerprint.storage_bytes();
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            r#"
            UPDATE download_delivery_attempts
            SET phase = 'staged',
                staging_fingerprint = CASE
                    WHEN phase = 'prepared' THEN ?4
                    ELSE staging_fingerprint
                END,
                updated_at_s = CASE WHEN phase = 'prepared' THEN ?3 ELSE updated_at_s END
            WHERE job_id = (
                SELECT download_jobs.id
                FROM download_jobs
                JOIN known_files ON known_files.id = download_jobs.known_file_id
                WHERE download_jobs.id = ?1 AND download_jobs.execution_generation=?5 AND download_jobs.intent='started'
                  AND download_jobs.completed != 0
                  AND download_jobs.final_rehash_pending = 0
                  AND download_jobs.delivery_state = 'pending'
                  AND download_jobs.delivered_path_id IS NULL
                  AND download_jobs.removed_at_s IS NULL
                  AND download_jobs.delete_requested_at_s IS NULL
            )
              AND attempt_id = ?2
              AND (
                  phase = 'prepared'
                  OR (phase = 'staged' AND staging_fingerprint = ?4)
              )
            "#,
            params![
                id,
                attempt_id.hyphenated().to_string(),
                now,
                staging_fingerprint,
                i64::try_from(token.generation)?,
            ],
        )?;
        let snapshot = if changed != 0 {
            delivery_attempt_by_job(&tx, id)?
        } else {
            None
        };
        tx.commit()?;
        Ok(snapshot)
    }

    pub fn mark_transfer_delivery_attempt_published(
        &self,
        token: JobToken,
        attempt_id: Uuid,
        published_fingerprint: &NativeFileFingerprint,
    ) -> Result<Option<MetadataTransferDeliveryAttempt>> {
        let id = token.job_id;
        let now = crate::download_job_store::unix_s();
        let published_fingerprint = published_fingerprint.storage_bytes();
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            r#"
            UPDATE download_delivery_attempts
            SET phase = 'published',
                published_fingerprint = CASE
                    WHEN phase = 'staged' THEN ?4
                    ELSE published_fingerprint
                END,
                updated_at_s = CASE WHEN phase = 'staged' THEN ?3 ELSE updated_at_s END
            WHERE job_id = (
                SELECT download_jobs.id
                FROM download_jobs
                JOIN known_files ON known_files.id = download_jobs.known_file_id
                WHERE download_jobs.id = ?1 AND download_jobs.execution_generation=?5 AND download_jobs.intent='started'
                  AND download_jobs.completed != 0
                  AND download_jobs.final_rehash_pending = 0
                  AND download_jobs.delivery_state = 'pending'
                  AND download_jobs.delivered_path_id IS NULL
                  AND download_jobs.removed_at_s IS NULL
                  AND download_jobs.delete_requested_at_s IS NULL
            )
              AND attempt_id = ?2
              AND (
                  phase = 'staged'
                  OR (phase = 'published' AND published_fingerprint = ?4)
              )
            "#,
            params![
                id,
                attempt_id.hyphenated().to_string(),
                now,
                published_fingerprint,
                i64::try_from(token.generation)?,
            ],
        )?;
        let snapshot = if changed != 0 {
            delivery_attempt_by_job(&tx, id)?
        } else {
            None
        };
        tx.commit()?;
        Ok(snapshot)
    }

    /// Commit verified direct publication and release its sharing barrier together.
    pub fn publish_reserved_delivery_attempt(
        &self,
        token: JobToken,
        attempt_id: Uuid,
        fingerprint: &NativeFileFingerprint,
    ) -> Result<Option<MetadataTransferDeliveryAttempt>> {
        let job_id = token.job_id;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id = attempt_id.to_string();
        let reserved: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM download_delivery_exclusions WHERE reservation_id = ?1 AND originating_job_id=?2)",
            params![id,job_id],
            |row| row.get(0),
        )?;
        if !reserved {
            return Ok(None);
        }
        let changed = tx.execute(
            "UPDATE download_delivery_attempts SET phase = 'published', published_fingerprint = ?3, updated_at_s = ?4
             WHERE attempt_id = ?1 AND phase = 'staged' AND job_id = (
               SELECT download_jobs.id FROM download_jobs JOIN known_files ON known_files.id = download_jobs.known_file_id
               WHERE download_jobs.id = ?2 AND download_jobs.execution_generation=?5 AND download_jobs.intent='started' AND download_jobs.completed != 0
                 AND download_jobs.final_rehash_pending = 0 AND download_jobs.delivery_state = 'pending'
                 AND download_jobs.removed_at_s IS NULL AND download_jobs.delete_requested_at_s IS NULL)",
            params![id, job_id, fingerprint.storage_bytes(), crate::download_job_store::unix_s(),i64::try_from(token.generation)?],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        tx.execute(
            "DELETE FROM download_delivery_exclusions WHERE reservation_id = ?1 AND originating_job_id=?2",
            params![id,job_id],
        )?;
        let snapshot = delivery_attempt_by_job(&tx, job_id)?;
        tx.commit()?;
        Ok(snapshot)
    }

    /// The token and journal snapshot must be captured before recovery I/O under
    /// the caller's exclusive lifecycle scope, never refreshed after that I/O.
    /// Monotonic phases and immutable fingerprints form the durable state CAS.
    pub fn settle_recovered_delivery_attempt(
        &self,
        token: JobToken,
        expected: &MetadataTransferDeliveryAttempt,
    ) -> Result<bool> {
        if expected.job_id != token.job_id {
            return Ok(false);
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM download_jobs WHERE id=?1 AND execution_generation=?2)",
            params![token.job_id, i64::try_from(token.generation)?],
            |row| row.get(0),
        )?;
        if !current || delivery_attempt_by_job(&tx, token.job_id)?.as_ref() != Some(expected) {
            return Ok(false);
        }
        let changed = tx.execute(
            "DELETE FROM download_delivery_attempts WHERE job_id=?1 AND attempt_id=?2",
            params![token.job_id, expected.attempt_id.to_string()],
        )?;
        tx.commit()?;
        Ok(changed != 0)
    }

    pub fn begin_transfer_deletion_tombstone(
        &self,
        id: JobId,
        tombstone_id: Uuid,
        original_path: &Path,
        tombstone_path: &Path,
        source_fingerprint: &NativeFileFingerprint,
    ) -> Result<MetadataTransferDeletionTombstone> {
        ensure!(
            original_path.is_absolute(),
            "deletion source path must be absolute"
        );
        ensure!(
            tombstone_path.is_absolute(),
            "deletion tombstone path must be absolute"
        );
        ensure!(
            original_path != tombstone_path,
            "deletion source and tombstone paths must differ"
        );
        ensure!(
            original_path.parent().is_some() && original_path.parent() == tombstone_path.parent(),
            "deletion source and tombstone paths must share one parent directory"
        );
        ensure!(
            tombstone_path.file_name().is_some_and(|name| {
                name == std::ffi::OsStr::new(&format!(".emulebb-delete-{tombstone_id}.tmp"))
            }),
            "deletion tombstone path does not match tombstone {tombstone_id}"
        );

        crate::download_job_store::validate_job_path(original_path)?;
        crate::download_job_store::validate_job_path(tombstone_path)?;
        let original = NativePath::from(original_path);
        let source_bytes = source_fingerprint.storage_bytes();
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job_id = tx
            .query_row(
                r#"
                SELECT download_jobs.id
                FROM known_files
                JOIN download_jobs ON download_jobs.known_file_id = known_files.id
                LEFT JOIN local_paths delivered_paths
                  ON delivered_paths.id = download_jobs.delivered_path_id
                WHERE download_jobs.id = ?1
                  AND download_jobs.delete_requested_at_s IS NOT NULL
                  AND (
                      (
                          download_jobs.delivery_state = 'delivered'
                          AND download_jobs.delivery_ownership = 'owned'
                          AND download_jobs.source_fingerprint = ?2
                          AND delivered_paths.platform = ?3
                          AND delivered_paths.native_path = ?4
                      )
                      OR EXISTS (
                          SELECT 1
                          FROM download_delivery_attempts
                          JOIN local_paths attempted_targets
                            ON attempted_targets.id = download_delivery_attempts.target_path_id
                          WHERE download_delivery_attempts.job_id = download_jobs.id
                            AND download_delivery_attempts.phase = 'published'
                            AND download_delivery_attempts.published_fingerprint = ?2
                            AND attempted_targets.platform = ?3
                            AND attempted_targets.native_path = ?4
                      )
                  )
                "#,
                params![
                    id,
                    source_bytes,
                    NativePath::platform(),
                    original.storage_bytes(),
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(job_id) = job_id else {
            anyhow::bail!("transfer {id} has no owned delivered output eligible for tombstoning");
        };
        if let Some(existing) = download_job_deletion_tombstone(&tx, id)? {
            ensure!(
                existing.tombstone_id == tombstone_id
                    && existing.original_path == original_path
                    && existing.tombstone_path == tombstone_path
                    && existing.source_fingerprint == *source_fingerprint,
                "transfer {id} already has a different deletion tombstone"
            );
            tx.commit()?;
            return Ok(existing);
        }
        let original_path_id = upsert_local_path(&tx, original_path)?;
        let tombstone_path_id = upsert_local_path(&tx, tombstone_path)?;
        ensure!(
            original_path_id != tombstone_path_id,
            "deletion source and tombstone paths must have distinct native identities"
        );
        let now = crate::download_job_store::unix_s();
        tx.execute(
            r#"
            INSERT INTO download_delivery_tombstones(
                job_id, tombstone_id, phase, original_path_id,
                tombstone_path_id, source_fingerprint, created_at_s, updated_at_s
            )
            VALUES (?1, ?2, 'prepared', ?3, ?4, ?5, ?6, ?6)
            "#,
            params![
                job_id,
                tombstone_id.hyphenated().to_string(),
                original_path_id,
                tombstone_path_id,
                source_bytes,
                now,
            ],
        )?;
        let tombstone = download_job_deletion_tombstone(&tx, id)?
            .expect("inserted deletion tombstone must be queryable in its transaction");
        tx.commit()?;
        Ok(tombstone)
    }

    pub fn download_job_deletion_tombstone(
        &self,
        id: JobId,
    ) -> Result<Option<MetadataTransferDeletionTombstone>> {
        let conn = self.connection()?;
        download_job_deletion_tombstone(&conn, id)
    }

    pub fn mark_transfer_deletion_tombstone_moved(
        &self,
        id: JobId,
        tombstone_id: Uuid,
        moved_fingerprint: &NativeFileFingerprint,
    ) -> Result<Option<MetadataTransferDeletionTombstone>> {
        let now = crate::download_job_store::unix_s();
        let moved_fingerprint = moved_fingerprint.storage_bytes();
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            r#"
            UPDATE download_delivery_tombstones
            SET phase = 'moved',
                moved_fingerprint = CASE
                    WHEN phase = 'prepared' THEN ?4
                    ELSE moved_fingerprint
                END,
                updated_at_s = CASE WHEN phase = 'prepared' THEN ?3 ELSE updated_at_s END
            WHERE job_id = (
                SELECT download_jobs.id
                FROM download_jobs
                JOIN known_files ON known_files.id = download_jobs.known_file_id
                WHERE download_jobs.id = ?1
                  AND download_jobs.delete_requested_at_s IS NOT NULL
            )
              AND tombstone_id = ?2
              AND (
                  phase = 'prepared'
                  OR (phase = 'moved' AND moved_fingerprint = ?4)
              )
            "#,
            params![
                id,
                tombstone_id.hyphenated().to_string(),
                now,
                moved_fingerprint,
            ],
        )?;
        let snapshot = if changed != 0 {
            download_job_deletion_tombstone(&tx, id)?
        } else {
            None
        };
        tx.commit()?;
        Ok(snapshot)
    }

    pub fn clear_prepared_transfer_deletion_tombstone(
        &self,
        id: JobId,
        tombstone_id: Uuid,
    ) -> Result<bool> {
        let changed = self.connection()?.execute(
            r#"
            DELETE FROM download_delivery_tombstones
            WHERE job_id = (
                SELECT download_jobs.id
                FROM download_jobs
                JOIN known_files ON known_files.id = download_jobs.known_file_id
                WHERE download_jobs.id = ?1
                  AND download_jobs.delete_requested_at_s IS NOT NULL
            )
              AND tombstone_id = ?2
              AND phase = 'prepared'
            "#,
            params![id, tombstone_id.hyphenated().to_string()],
        )?;
        Ok(changed != 0)
    }

    /// Settle an exact snapshot after reclaiming its owned object or deciding
    /// to preserve missing/foreign prepared objects, under durable delete
    /// intent and the same execution generation. Never reacquire a newer token
    /// after filesystem work merely to make a stale completion eligible.
    pub fn settle_recovered_output_tombstone(
        &self,
        token: JobToken,
        expected: &MetadataTransferDeletionTombstone,
    ) -> Result<bool> {
        if expected.job_id != token.job_id {
            return Ok(false);
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM download_jobs WHERE id=?1 AND execution_generation=?2 AND delete_requested_at_s IS NOT NULL)",
            params![token.job_id,i64::try_from(token.generation)?], |row| row.get(0))?;
        if !current
            || download_job_deletion_tombstone(&tx, token.job_id)?.as_ref() != Some(expected)
        {
            return Ok(false);
        }
        let changed = tx.execute(
            "DELETE FROM download_delivery_tombstones WHERE job_id=?1 AND tombstone_id=?2",
            params![token.job_id, expected.tombstone_id.to_string()],
        )?;
        tx.commit()?;
        Ok(changed != 0)
    }

    /// Additional delivered-output deletion intent. Internal pieces always use
    /// the shared retirement journal, independent of this destructive choice.
    pub fn request_transfer_deletion(&self, id: JobId) -> Result<bool> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        request_job_removal(&tx, id, true)?;
        let requested = tx.query_row("SELECT EXISTS(SELECT 1 FROM download_jobs WHERE id=?1 AND delete_requested_at_s IS NOT NULL)",
            [id], |row| row.get::<_,bool>(0))?;
        tx.commit()?;
        Ok(requested)
    }

    pub fn transfer_deletion_requested(&self, id: JobId) -> Result<bool> {
        self.connection()?
            .query_row(
                r#"
                SELECT download_jobs.delete_requested_at_s IS NOT NULL
                FROM known_files
                JOIN download_jobs ON download_jobs.known_file_id = known_files.id
                WHERE download_jobs.id = ?1
                "#,
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map(|value| value.unwrap_or(false))
            .map_err(Into::into)
    }

    /// Refresh current verification after independently proving the recorded
    /// output's bytes. This never restores destructive ownership or replays a
    /// manifest's progress. Terminal completion remains a historical fact.
    pub fn refresh_delivered_verification(
        &self,
        token: JobToken,
        path: &Path,
        expected_fingerprint: Option<&NativeFileFingerprint>,
        expected_ownership: MetadataTransferDeliveryOwnership,
        verified_fingerprint: &NativeFileFingerprint,
    ) -> Result<bool> {
        crate::download_job_store::validate_job_path(path)?;
        let native = NativePath::from(path);
        let changed = self.connection()?.execute(
            "UPDATE download_jobs SET source_fingerprint=?7,delivery_ownership='unowned',updated_at_s=?8
             WHERE id=?1 AND execution_generation=?2 AND removed_at_s IS NULL
               AND delete_requested_at_s IS NULL AND delivery_state='delivered'
               AND delivery_ownership=?6 AND source_fingerprint IS ?5
               AND expected_size_bytes=?9
               AND delivered_path_id IN(SELECT id FROM local_paths WHERE platform=?3 AND native_path=?4)",
            params![token.job_id,i64::try_from(token.generation)?,NativePath::platform(),native.storage_bytes(),
                expected_fingerprint.map(NativeFileFingerprint::storage_bytes),
                delivery_ownership_to_sql(expected_ownership),verified_fingerprint.storage_bytes(),
                crate::download_job_store::unix_s(),i64::try_from(verified_fingerprint.size_bytes)?],
        )?;
        Ok(changed != 0)
    }

    pub fn transfer_retirement_pending(&self, id: JobId) -> Result<bool> {
        self.connection()?
            .query_row(
                r#"
                SELECT EXISTS (
                    SELECT 1 FROM download_retirements
                    JOIN download_jobs ON download_jobs.id = download_retirements.job_id
                    JOIN known_files ON known_files.id = download_jobs.known_file_id
                    WHERE download_jobs.id = ?1
                )
                "#,
                params![id],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    /// Record terminal completion and durably own only its internal piece
    /// directory. The delivered output and verified local content are retained.
    pub fn request_transfer_retirement(&self, token: JobToken) -> Result<bool> {
        let id = token.job_id;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job_id = tx
            .query_row(
                r#"
                SELECT download_jobs.id
                FROM download_jobs
                JOIN known_files ON known_files.id = download_jobs.known_file_id
                JOIN verified_local_content ON verified_local_content.known_file_id = known_files.id
                WHERE download_jobs.id = ?1 AND download_jobs.execution_generation=?2 AND download_jobs.intent='started'
                  AND download_jobs.completed = 1
                  AND download_jobs.final_rehash_pending=0 AND download_jobs.internal_storage_retired=0
                  AND download_jobs.delivery_state = 'delivered'
                  AND download_jobs.removed_at_s IS NULL
                  AND download_jobs.delete_requested_at_s IS NULL
                "#,
                params![id,i64::try_from(token.generation)?],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(job_id) = job_id else {
            return Ok(false);
        };
        tx.execute(
            "UPDATE download_jobs SET terminal_completed_at_s=coalesce(terminal_completed_at_s,?2), updated_at_s=?2 WHERE id=?1",
            params![job_id, crate::download_job_store::unix_s()],
        )?;
        reserve_internal_retirement(&tx, token.job_id)?;
        tx.commit()?;
        Ok(true)
    }

    pub fn pending_transfer_retirement_jobs_after(
        &self,
        after: Option<JobId>,
        limit: usize,
    ) -> Result<Vec<JobId>> {
        ensure!((1..=256).contains(&limit), "invalid job page size");
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT download_jobs.id
            FROM download_retirements
            JOIN download_jobs ON download_jobs.id = download_retirements.job_id
            JOIN known_files ON known_files.id = download_jobs.known_file_id
            WHERE download_jobs.id>?1
            ORDER BY download_jobs.id LIMIT ?2
            "#,
        )?;
        stmt.query_map(
            params![after.map_or(0, JobId::get), i64::try_from(limit)?],
            |row| row.get(0),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
    }

    /// Read one immutable retirement intent; never reconstruct paths from a
    /// content hash or the current temp-directory setting.
    pub fn download_job_retirement(&self, id: JobId) -> Result<Option<MetadataDownloadRetirement>> {
        let conn = self.connection()?;
        read_download_job_retirement(&conn, id)
    }

    /// Drop internal piece bookkeeping after owned directory cleanup. The compact
    /// terminal job, verified local content, and content completion history survive.
    pub fn finalize_transfer_retirement(&self, id: JobId) -> Result<bool> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM download_retirements r JOIN download_jobs j ON j.id=r.job_id
            WHERE r.job_id=?1 AND (j.terminal_completed_at_s IS NOT NULL OR j.removed_at_s IS NOT NULL))",[id],|row| row.get(0))?;
        if !pending {
            return Ok(false);
        }
        // Output journals retain the compact owner row independently. They do
        // not require large internal piece/source/hash children after safe cleanup.
        retire_job_children(&tx, id)?;
        tx.execute("DELETE FROM download_retirements WHERE job_id=?1", [id])?;
        tx.execute(
            "UPDATE download_jobs SET internal_storage_retired=1,updated_at_s=?2 WHERE id=?1",
            params![id, crate::download_job_store::unix_s()],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Return every transfer whose destructive-delete intent must be resumed.
    pub fn pending_transfer_deletion_jobs_after(
        &self,
        after: Option<JobId>,
        limit: usize,
    ) -> Result<Vec<JobId>> {
        ensure!((1..=256).contains(&limit), "invalid job page size");
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT download_jobs.id
            FROM known_files
            JOIN download_jobs ON download_jobs.known_file_id = known_files.id
            WHERE download_jobs.delete_requested_at_s IS NOT NULL AND download_jobs.id>?1
            ORDER BY download_jobs.id LIMIT ?2
            "#,
        )?;
        let rows = stmt.query_map(
            params![after.map_or(0, JobId::get), i64::try_from(limit)?],
            |row| row.get(0),
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Return every hash which owns an internal download directory.
    /// Pending deletion rows remain owners until their strict filesystem
    /// cleanup finalizes the metadata row.
    pub fn managed_download_transfer_jobs_after(
        &self,
        after: Option<JobId>,
        limit: usize,
    ) -> Result<Vec<JobId>> {
        ensure!((1..=256).contains(&limit), "invalid job page size");
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT download_jobs.id
            FROM known_files
            JOIN download_jobs ON download_jobs.known_file_id = known_files.id
            WHERE download_jobs.id>?1 AND download_jobs.internal_storage_retired=0
            ORDER BY download_jobs.id LIMIT ?2
            "#,
        )?;
        let rows = stmt.query_map(
            params![after.map_or(0, JobId::get), i64::try_from(limit)?],
            |row| row.get(0),
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn managed_download_transfer_exists(&self, id: JobId) -> Result<bool> {
        self.connection()?
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM known_files
                    JOIN download_jobs ON download_jobs.known_file_id = known_files.id
                    WHERE download_jobs.id = ?1 AND download_jobs.internal_storage_retired=0
                )
                "#,
                params![id],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    /// Commit metadata removal only for a transfer with a durable destructive
    /// intent. A missing row or a row without intent is an idempotent no-op.
    pub fn finalize_transfer_deletion(&self, id: JobId) -> Result<bool> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let known_file_id = tx
            .query_row(
                r#"
                SELECT known_files.id
                FROM known_files
                JOIN download_jobs ON download_jobs.known_file_id = known_files.id
                WHERE download_jobs.id = ?1
                  AND download_jobs.delete_requested_at_s IS NOT NULL
                "#,
                params![id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(_) = known_file_id else {
            return Ok(false);
        };
        delete_job_row(&tx, id)?;
        tx.commit()?;
        Ok(true)
    }

    pub fn delete_transfer_manifest(&self, id: JobId) -> Result<bool> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let known_file_id = tx
            .query_row(
                "SELECT known_files.id FROM known_files JOIN download_jobs ON download_jobs.known_file_id = known_files.id WHERE download_jobs.id = ?1 AND download_jobs.delete_requested_at_s IS NULL AND (download_jobs.selected_temp_path_id IS NULL OR download_jobs.internal_storage_retired=1)",
                params![id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(_) = known_file_id else {
            return Ok(false);
        };
        delete_job_row(&tx, id)?;
        tx.commit()?;
        Ok(true)
    }
}

fn publish_entries_after(
    conn: &rusqlite::Connection,
    after: Option<&str>,
    limit: usize,
) -> Result<Vec<MetadataTransferPublishEntry>> {
    use crate::download_job_store::{JOB_PAGE_BYTES, MAX_JOB_TEXT_BYTES, bounded_row_bytes};
    ensure!((1..=256).contains(&limit), "invalid publication page size");
    let boundary = after
        .map(|hash| decode_fixed_hex(hash, 16, "ED2K hash"))
        .transpose()?
        .unwrap_or_default();
    let representative = crate::local_catalog::representative_path(true);
    let complete = "c.known_file_id IS NOT NULL AND i.path_id IS NOT NULL";
    let sql=format!("WITH selected AS (SELECT lower(hex(known_files.ed2k_hash)) hash,
        CASE WHEN {complete} THEN c.display_name ELSE t.display_name END name,
        CASE WHEN {complete} THEN known_files.size_bytes ELSE t.expected_size_bytes END size,
        lower(hex(CASE WHEN {complete} THEN c.aich_root ELSE t.aich_root END)) root,
        CASE WHEN {complete} THEN c.upload_priority ELSE t.upload_priority END priority,
        CASE WHEN {complete} THEN c.auto_upload_priority ELSE t.auto_upload_priority END auto,
        known_files.all_time_uploaded_bytes uploaded,known_files.all_time_upload_requests requests,
        known_files.all_time_upload_accepts accepts,known_files.last_upload_requested_at_ms last_request,
        CASE WHEN {complete} THEN c.comment ELSE t.comment END comment,
        CASE WHEN {complete} THEN c.rating ELSE t.rating END rating
        FROM known_files LEFT JOIN verified_local_content c ON c.known_file_id=known_files.id
        LEFT JOIN local_file_instances i ON i.path_id=({representative})
        LEFT JOIN download_jobs t ON t.known_file_id=known_files.id AND t.removed_at_s IS NULL
            AND t.terminal_completed_at_s IS NULL AND t.delete_requested_at_s IS NULL
        WHERE known_files.ed2k_hash>?1 AND (({complete}) OR (t.expected_size_bytes IS NOT NULL
            AND t.final_rehash_pending=0 AND t.md4_hashset_acquired=1 AND EXISTS(SELECT 1 FROM download_job_verified_ranges r WHERE r.job_id=t.id)))
        ORDER BY known_files.ed2k_hash LIMIT ?2)
        SELECT hash,CASE WHEN length(CAST(name AS BLOB))<=65536 THEN name END,size,NULLIF(root,''),
            CASE WHEN length(CAST(priority AS BLOB))<=65536 THEN priority END,auto,uploaded,requests,accepts,last_request,
            CASE WHEN length(CAST(comment AS BLOB))<=65536 THEN comment END,rating,
            length(CAST(name AS BLOB)),length(CAST(priority AS BLOB)),length(CAST(comment AS BLOB)) FROM selected ORDER BY hash");
    let mut stmt = conn.prepare_cached(&sql)?;
    let mut rows = stmt.query(params![boundary, i64::try_from(limit)?])?;
    let mut entries = Vec::new();
    let mut bytes = 0;
    while let Some(row) = rows.next()? {
        let charge = bounded_row_bytes(
            row,
            &[
                (12, MAX_JOB_TEXT_BYTES, 2),
                (13, MAX_JOB_TEXT_BYTES, 2),
                (14, MAX_JOB_TEXT_BYTES, 2),
            ],
        )?;
        if bytes + charge > JOB_PAGE_BYTES {
            ensure!(
                !entries.is_empty(),
                "publication row exceeds page allowance"
            );
            break;
        }
        bytes += charge;
        entries.push(MetadataTransferPublishEntry {
            file_hash: row.get(0)?,
            display_name: row.get(1)?,
            file_size: crate::sql_value::unsigned(row, 2)?,
            aich_root: row.get(3)?,
            upload_priority: row.get(4)?,
            auto_upload_priority: row.get(5)?,
            session_uploaded_bytes: 0,
            session_request_count: 0,
            session_accept_count: 0,
            all_time_uploaded_bytes: crate::sql_value::unsigned(row, 6)?,
            all_time_upload_requests: crate::sql_value::unsigned(row, 7)?,
            all_time_upload_accepts: crate::sql_value::unsigned(row, 8)?,
            last_upload_request_ms: row.get(9)?,
            comment: row.get(10)?,
            rating: row.get(11)?,
        });
    }
    Ok(entries)
}

pub(crate) fn delivery_attempt_by_job(
    conn: &rusqlite::Connection,
    id: JobId,
) -> Result<Option<MetadataTransferDeliveryAttempt>> {
    conn.query_row(
        r#"
        SELECT lower(hex(known_files.ed2k_hash)), download_delivery_attempts.attempt_id,
               download_delivery_attempts.phase,
               target_paths.platform, CASE WHEN length(target_paths.native_path)<=65536 THEN target_paths.native_path END,
               staging_paths.platform, CASE WHEN length(staging_paths.native_path)<=65536 THEN staging_paths.native_path END,
               CASE WHEN length(download_delivery_attempts.staging_fingerprint)<=1024 THEN download_delivery_attempts.staging_fingerprint END,
               CASE WHEN length(download_delivery_attempts.published_fingerprint)<=1024 THEN download_delivery_attempts.published_fingerprint END,
               download_delivery_attempts.created_at_s, download_delivery_attempts.updated_at_s, download_jobs.id, length(target_paths.native_path),length(staging_paths.native_path),length(download_delivery_attempts.staging_fingerprint),length(download_delivery_attempts.published_fingerprint)
        FROM download_delivery_attempts
        JOIN download_jobs ON download_jobs.id = download_delivery_attempts.job_id
        JOIN known_files ON known_files.id = download_jobs.known_file_id
        JOIN local_paths target_paths ON target_paths.id = download_delivery_attempts.target_path_id
        JOIN local_paths staging_paths ON staging_paths.id = download_delivery_attempts.staging_path_id
        WHERE download_jobs.id = ?1
        "#,
        params![id],
        delivery_attempt_from_row,
    )
    .optional()
    .map_err(Into::into)
}

fn download_job_deletion_tombstone(
    conn: &rusqlite::Connection,
    id: JobId,
) -> Result<Option<MetadataTransferDeletionTombstone>> {
    conn.query_row(
        r#"
        SELECT lower(hex(known_files.ed2k_hash)),
               download_delivery_tombstones.tombstone_id,
               download_delivery_tombstones.phase,
               original_paths.platform, CASE WHEN length(original_paths.native_path)<=65536 THEN original_paths.native_path END,
               tombstone_paths.platform, CASE WHEN length(tombstone_paths.native_path)<=65536 THEN tombstone_paths.native_path END,
               CASE WHEN length(download_delivery_tombstones.source_fingerprint)<=1024 THEN download_delivery_tombstones.source_fingerprint END,
               CASE WHEN length(download_delivery_tombstones.moved_fingerprint)<=1024 THEN download_delivery_tombstones.moved_fingerprint END,
               download_delivery_tombstones.created_at_s,
               download_delivery_tombstones.updated_at_s, download_jobs.id,length(original_paths.native_path),length(tombstone_paths.native_path),length(download_delivery_tombstones.source_fingerprint),length(download_delivery_tombstones.moved_fingerprint)
        FROM download_delivery_tombstones
        JOIN download_jobs ON download_jobs.id = download_delivery_tombstones.job_id
        JOIN known_files ON known_files.id = download_jobs.known_file_id
        JOIN local_paths original_paths
          ON original_paths.id = download_delivery_tombstones.original_path_id
        JOIN local_paths tombstone_paths
          ON tombstone_paths.id = download_delivery_tombstones.tombstone_path_id
        WHERE download_jobs.id = ?1
        "#,
        params![id],
        |row| {
            delivery_attempt_row_bytes(row)?;
            let tombstone_id = row.get::<_, String>(1)?.parse::<Uuid>().map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    error.into(),
                )
            })?;
            let phase = match row.get::<_, String>(2)?.as_str() {
                "prepared" => MetadataTransferDeletionTombstonePhase::Prepared,
                "moved" => MetadataTransferDeletionTombstonePhase::Moved,
                value => {
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("invalid deletion tombstone phase {value:?}"),
                        )
                        .into(),
                    ));
                }
            };
            Ok(MetadataTransferDeletionTombstone {
                job_id: row.get(11)?,
                file_hash: row.get(0)?,
                tombstone_id,
                phase,
                original_path: path_from_row(row, 3, 4)?,
                tombstone_path: path_from_row(row, 5, 6)?,
                source_fingerprint: optional_fingerprint_from_row(row, 7)?.ok_or_else(|| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Blob,
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "deletion tombstone is missing its source fingerprint",
                        )
                        .into(),
                    )
                })?,
                moved_fingerprint: optional_fingerprint_from_row(row, 8)?,
                created_at_s: row.get(9)?,
                updated_at_s: row.get(10)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn delivery_attempt_row_bytes(row: &rusqlite::Row<'_>) -> rusqlite::Result<usize> {
    crate::download_job_store::bounded_row_bytes(
        row,
        &[(12, 65536, 4), (13, 65536, 4), (14, 1024, 2), (15, 1024, 2)],
    )
}

fn delivery_attempt_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<MetadataTransferDeliveryAttempt> {
    delivery_attempt_row_bytes(row)?;
    let attempt_id = row.get::<_, String>(1)?;
    let attempt_id = Uuid::parse_str(&attempt_id).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, error.into())
    })?;
    let phase = match row.get::<_, String>(2)?.as_str() {
        "prepared" => MetadataTransferDeliveryAttemptPhase::Prepared,
        "staged" => MetadataTransferDeliveryAttemptPhase::Staged,
        "published" => MetadataTransferDeliveryAttemptPhase::Published,
        value => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                anyhow::anyhow!("invalid delivery attempt phase {value:?}").into(),
            ));
        }
    };
    Ok(MetadataTransferDeliveryAttempt {
        job_id: row.get(11)?,
        file_hash: row.get(0)?,
        attempt_id,
        phase,
        target_path: path_from_row(row, 3, 4)?,
        staging_path: path_from_row(row, 5, 6)?,
        staging_fingerprint: optional_fingerprint_from_row(row, 7)?,
        published_fingerprint: optional_fingerprint_from_row(row, 8)?,
        created_at_s: row.get(9)?,
        updated_at_s: row.get(10)?,
    })
}

fn retire_job_children(tx: &rusqlite::Transaction<'_>, id: JobId) -> Result<()> {
    for table in [
        "download_job_pieces",
        "download_job_sources",
        "download_job_md4_part_hashes",
        "download_job_aich_part_hashes",
        "download_job_verified_ranges",
        "download_job_file_name_observations",
    ] {
        tx.execute(&format!("DELETE FROM {table} WHERE job_id=?1"), [id])?;
    }
    Ok(())
}

pub(crate) fn delete_job_row(tx: &rusqlite::Transaction<'_>, id: JobId) -> Result<()> {
    // Job deletion is not knowledge deletion. Accepted identity, names, origins,
    // upload history and policy remain even after the final job/path disappears.
    ensure!(
        !tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM download_delivery_exclusions WHERE originating_job_id=?1)",
            [id],
            |row| row.get::<_, bool>(0)
        )?,
        "delivery exclusion authority must be settled before job deletion"
    );
    tx.execute("DELETE FROM download_jobs WHERE id=?1", [id])?;
    Ok(())
}

/// One transaction for both removal choices: invalidate callbacks, clear only
/// this job's head, and accept internal retirement before caller cancellation.
pub(crate) fn request_job_removal(
    conn: &rusqlite::Transaction<'_>,
    id: JobId,
    delete_output: bool,
) -> Result<bool> {
    let changed = conn.execute("UPDATE download_jobs SET removed_at_s=coalesce(removed_at_s,?2),
        delete_requested_at_s=CASE WHEN ?3 THEN coalesce(delete_requested_at_s,?2) ELSE delete_requested_at_s END,
        updated_at_s=?2,execution_generation=execution_generation+1
        WHERE id=?1 AND (removed_at_s IS NULL OR (?3 AND delete_requested_at_s IS NULL))
        AND execution_generation<9223372036854775807",
        params![id,crate::download_job_store::unix_s(),delete_output])? != 0;
    if changed {
        conn.execute(
            "UPDATE known_files SET latest_download_job_id=NULL WHERE latest_download_job_id=?1",
            [id],
        )?;
    }
    reserve_internal_retirement(conn, id)?;
    Ok(changed)
}

/// Internal pieces only. This journal never authorizes delivered-output
/// deletion; its path and native authority come from the fixed job allocation.
pub(crate) fn reserve_internal_retirement(
    conn: &rusqlite::Transaction<'_>,
    id: JobId,
) -> Result<()> {
    if read_download_job_retirement(conn, id)?.is_some() {
        return Ok(());
    }
    let source = conn
        .query_row(
            "SELECT p.platform, CASE WHEN length(p.native_path)<=65536 THEN p.native_path END
         FROM download_jobs j LEFT JOIN local_paths p ON p.id=j.storage_path_id
         WHERE j.id=?1 AND j.internal_storage_retired=0
         AND (j.removed_at_s IS NOT NULL OR j.terminal_completed_at_s IS NOT NULL)",
            [id],
            |row| optional_path_from_row(row, 0, 1),
        )
        .optional()?;
    let Some(source) = source else {
        return Ok(());
    };
    let target_path_id = if let Some(source) = source {
        // Persist the physical target before any I/O. A short random sibling
        // also avoids increasing the already accepted allocation path length.
        let target = source.with_file_name(format!(".r-{}", Uuid::new_v4().simple()));
        crate::download_job_store::validate_job_path(&target)?;
        Some(upsert_local_path(conn, &target)?)
    } else {
        None
    };
    conn.execute(
        "INSERT INTO download_retirements(job_id,target_path_id,directory_identity,directory_marker_id)
        SELECT id,?2,storage_directory_identity,
            CASE WHEN storage_directory_identity IS NOT NULL THEN storage_directory_marker_id END
        FROM download_jobs WHERE id=?1 AND internal_storage_retired=0
            AND (removed_at_s IS NOT NULL OR terminal_completed_at_s IS NOT NULL)",
        params![id,target_path_id],
    )?;
    Ok(())
}

fn read_download_job_retirement(
    conn: &rusqlite::Connection,
    id: JobId,
) -> Result<Option<MetadataDownloadRetirement>> {
    Ok(conn.query_row(
        "SELECT source.platform, CASE WHEN length(source.native_path)<=65536 THEN source.native_path END,
            target.platform, CASE WHEN length(target.native_path)<=65536 THEN target.native_path END,
            r.directory_identity,r.directory_marker_id
         FROM download_retirements r JOIN download_jobs j ON j.id=r.job_id
         LEFT JOIN local_paths source ON source.id=j.storage_path_id
         LEFT JOIN local_paths target ON target.id=r.target_path_id WHERE r.job_id=?1",
        [id], |row| Ok(MetadataDownloadRetirement {
            job_id:id, source_path:optional_path_from_row(row,0,1)?,
            target_path:optional_path_from_row(row,2,3)?,
            authority:directory_cleanup_authority_from_row(row,4)?,
        }),
    ).optional()?)
}

fn read_download_job_aich_identity(
    conn: &rusqlite::Connection,
    token: JobToken,
) -> Result<Option<MetadataTransferAichIdentity>> {
    Ok(conn.query_row("SELECT CASE WHEN aich_root IS NULL THEN NULL ELSE lower(hex(aich_root)) END,
        aich_root_origin,aich_trust_generation FROM download_jobs WHERE id=?1 AND execution_generation=?2
        AND removed_at_s IS NULL AND terminal_completed_at_s IS NULL AND delete_requested_at_s IS NULL",
        params![token.job_id,i64::try_from(token.generation)?], |row| Ok(MetadataTransferAichIdentity {
            root: row.get(0)?, origin: row.get(1)?, generation: crate::sql_value::unsigned::<u64>(row,2)?,
        })).optional()?)
}

pub(crate) fn read_transfer_aich_identity(
    conn: &rusqlite::Connection,
    hash: &[u8],
) -> Result<Option<MetadataTransferAichIdentity>> {
    Ok(conn
        .query_row(
            "SELECT CASE WHEN t.aich_root IS NULL THEN NULL ELSE lower(hex(t.aich_root)) END,
                t.aich_root_origin, t.aich_trust_generation
         FROM known_files f JOIN download_jobs t ON t.known_file_id = f.id
         WHERE f.ed2k_hash = ?1 AND t.delete_requested_at_s IS NULL AND t.removed_at_s IS NULL AND t.terminal_completed_at_s IS NULL",
            params![hash],
            |row| {
                Ok(MetadataTransferAichIdentity {
                    root: row.get(0)?,
                    origin: row.get(1)?,
                    generation: crate::sql_value::unsigned::<u64>(row, 2)?,
                })
            },
        )
        .optional()?)
}

fn reconcile_manifest_aich_identity(
    conn: &rusqlite::Connection,
    hash: &[u8],
    manifest: &mut MetadataTransferManifest,
) -> Result<()> {
    let mut identity = MetadataTransferAichIdentity {
        root: manifest.aich_root.take(),
        origin: manifest.aich_root_origin.take(),
        generation: manifest.aich_trust_generation,
    };
    if reconcile_aich_identity(conn, manifest.token, hash, &mut identity)? {
        manifest.aich_hashset.clear();
        manifest.aich_hashset_acquired = false;
    }
    manifest.aich_root = identity.root;
    manifest.aich_root_origin = identity.origin;
    manifest.aich_trust_generation = identity.generation;
    Ok(())
}

pub(crate) fn reconcile_aich_identity(
    conn: &rusqlite::Connection,
    token: JobToken,
    hash: &[u8],
    identity: &mut MetadataTransferAichIdentity,
) -> Result<bool> {
    let mut invalidate_parts = false;
    let current = conn
        .query_row(
            "SELECT CASE WHEN aich_root IS NULL THEN NULL ELSE lower(hex(aich_root)) END,
        aich_root_origin,aich_trust_generation FROM download_jobs WHERE id=?1",
            [token.job_id],
            |row| {
                Ok(MetadataTransferAichIdentity {
                    root: row.get(0)?,
                    origin: row.get(1)?,
                    generation: crate::sql_value::unsigned(row, 2)?,
                })
            },
        )
        .optional()?;
    if let Some(current) = &current
        && identity.generation < current.generation
    {
        // A checkpoint may contain newer payload progress but older authority.
        // Keep the former, and never resurrect its old acquired AICH part set.
        identity.root = current.root.clone();
        identity.origin = current.origin.clone();
        identity.generation = current.generation;
        invalidate_parts = true;
    }
    let accepted = conn
        .query_row(
            "SELECT lower(hex(aich_root)), aich_root_origin FROM known_files
         WHERE ed2k_hash = ?1 AND aich_root IS NOT NULL AND aich_root_origin IS NOT NULL",
            params![hash],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((root, stored_origin)) = accepted {
        if identity.root.is_some() {
            ensure!(
                identity.root.as_ref() == Some(&root),
                crate::MetadataContentConflict("ED2K identity has conflicting AICH root")
            );
        }
        // Preserve legitimate local/import enrichment of the same accepted
        // root; lower-authority checkpoints cannot downgrade its provenance.
        let origin = match identity.origin.as_deref() {
            Some("local_computed") => "local_computed".to_owned(),
            Some("stock_import") if stored_origin != "local_computed" => "stock_import".to_owned(),
            _ => stored_origin,
        };
        if identity.root.as_ref() != Some(&root) || identity.origin.as_ref() != Some(&origin) {
            if identity.root.as_ref() != Some(&root) {
                invalidate_parts = true;
            }
            identity.generation = match current.as_ref() {
                Some(current)
                    if current.root.as_ref() == Some(&root)
                        && current.origin.as_ref() == Some(&origin) =>
                {
                    current.generation
                }
                current => identity.generation.max(
                    current
                        .map_or(0, |current| current.generation)
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("AICH trust generation exhausted"))?,
                ),
            };
            i64::try_from(identity.generation)?;
            identity.root = Some(root);
            identity.origin = Some(origin);
        }
    }
    if let Some(current) = current {
        let minimum_generation =
            if identity.root != current.root || identity.origin != current.origin {
                current
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("AICH trust generation exhausted"))?
            } else {
                current.generation
            };
        identity.generation = identity.generation.max(minimum_generation);
        i64::try_from(identity.generation)?;
    }
    Ok(invalidate_parts)
}

/// Local hashing and trusted stock acceptance update the transfer in the same
/// transaction as accepted identity. Cold readers therefore never combine a
/// new root with an old acquired part set or generation.
pub(crate) fn reconcile_transfer_aich_authority_tx(
    tx: &rusqlite::Transaction<'_>,
    known_file_id: i64,
) -> Result<()> {
    let row = tx
        .query_row(
            "SELECT t.id, f.aich_root, f.aich_root_origin, t.aich_root,
                t.aich_root_origin, t.aich_trust_generation
         FROM known_files f JOIN download_jobs t ON t.known_file_id = f.id
         WHERE f.id = ?1 AND f.aich_root IS NOT NULL
           AND f.aich_root_origin IS NOT NULL AND t.removed_at_s IS NULL AND t.terminal_completed_at_s IS NULL",
            params![known_file_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    crate::sql_value::unsigned::<u64>(row, 5)?,
                ))
            },
        )
        .optional()?;
    let Some((job_id, root, origin, previous_root, previous_origin, generation)) = row else {
        return Ok(());
    };
    let root_changed = previous_root.as_ref() != Some(&root);
    if !root_changed && previous_origin.as_ref() == Some(&origin) {
        return Ok(());
    }
    let generation = generation
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("AICH trust generation exhausted"))?;
    if root_changed {
        tx.execute(
            "DELETE FROM download_job_aich_part_hashes WHERE job_id = ?1",
            params![job_id],
        )?;
    }
    tx.execute(
        "UPDATE download_jobs SET aich_root = ?2, aich_root_origin = ?3,
             aich_trust_generation = ?4,
             aich_hashset_acquired = CASE WHEN ?5 THEN 0 ELSE aich_hashset_acquired END
         WHERE id = ?1",
        params![
            job_id,
            root,
            origin,
            i64::try_from(generation)?,
            root_changed
        ],
    )?;
    Ok(())
}

#[derive(Debug)]
pub(crate) struct TransferRow {
    pub(crate) job_id: i64,
    pub(crate) generation: u64,
    pub(crate) file_hash: String,
    pub(crate) display_name: String,
    pub(crate) expected_size_bytes: Option<u64>,
    pub(crate) piece_size: u64,
    pub(crate) completed: bool,
    pub(crate) final_rehash_pending: bool,
    pub(crate) md4_hashset_acquired: bool,
    pub(crate) aich_hashset_acquired: bool,
    pub(crate) aich_root: Option<String>,
    pub(crate) aich_root_origin: Option<String>,
    pub(crate) aich_trust_generation: u64,
    pub(crate) upload_priority: String,
    pub(crate) auto_upload_priority: bool,
    pub(crate) comment: String,
    pub(crate) rating: u8,
    pub(crate) category_id: Option<i64>,
    pub(crate) intent: String,
    pub(crate) transfer_row_removed: bool,
    pub(crate) delivered_path: Option<std::path::PathBuf>,
    pub(crate) source_fingerprint: Option<NativeFileFingerprint>,
    pub(crate) payload_fingerprint: Option<NativeFileFingerprint>,
    pub(crate) delivery_state: String,
    pub(crate) delivery_ownership: String,
}

fn replace_transfer_children(
    tx: &rusqlite::Transaction<'_>,
    job_id: i64,
    manifest: &MetadataTransferManifest,
    now: i64,
) -> Result<()> {
    let snapshots = [
        crate::snapshot::SnapshotTable::begin(
            tx,
            "download_job_pieces",
            &["job_id", "piece_index"],
        )?,
        crate::snapshot::SnapshotTable::begin(
            tx,
            "download_job_md4_part_hashes",
            &["job_id", "part_index"],
        )?,
        crate::snapshot::SnapshotTable::begin(
            tx,
            "download_job_aich_part_hashes",
            &["job_id", "part_index"],
        )?,
        crate::snapshot::SnapshotTable::begin(
            tx,
            "download_job_verified_ranges",
            &["job_id", "start_offset", "end_offset"],
        )?,
    ];

    let mut insert_piece = tx.prepare_cached(
        r#"
        INSERT INTO temp.incoming_download_job_pieces(job_id, piece_index, state, prefix_bytes, block_bitmap, ich_corrupted, updated_at_s,present_bytes)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7,?8)
        "#,
    )?;
    for piece in &manifest.pieces {
        insert_piece.execute(params![
            job_id,
            i64::from(piece.piece_index),
            piece.state,
            i64::try_from(piece.prefix_bytes)?,
            piece.block_bitmap,
            piece.ich_corrupted,
            now,
            i64::try_from(piece.present_bytes)?,
        ])?;
    }
    drop(insert_piece);
    let mut insert_md4 = tx.prepare_cached(
        r#"
        INSERT INTO temp.incoming_download_job_md4_part_hashes(job_id, part_index, md4_hash)
        VALUES (?1, ?2, ?3)
        "#,
    )?;
    for (index, hash) in manifest.md4_hashset.iter().enumerate() {
        insert_md4.execute(params![
            job_id,
            i64::try_from(index)?,
            decode_fixed_hex(hash, 16, "MD4 part hash")?,
        ])?;
    }
    drop(insert_md4);
    let mut insert_aich = tx.prepare_cached(
        r#"
        INSERT INTO temp.incoming_download_job_aich_part_hashes(job_id, part_index, aich_hash)
        VALUES (?1, ?2, ?3)
        "#,
    )?;
    for (index, hash) in manifest.aich_hashset.iter().enumerate() {
        insert_aich.execute(params![
            job_id,
            i64::try_from(index)?,
            decode_fixed_hex(hash, 20, "AICH part hash")?,
        ])?;
    }
    drop(insert_aich);
    let mut insert_range = tx.prepare_cached(
        r#"
        INSERT INTO temp.incoming_download_job_verified_ranges(job_id, start_offset, end_offset, created_at_s)
        VALUES (?1, ?2, ?3, ?4)
        "#,
    )?;
    for range in &manifest.verified_ranges {
        insert_range.execute(params![
            job_id,
            i64::try_from(range.start)?,
            i64::try_from(range.end)?,
            now
        ])?;
    }
    drop(insert_range);
    // WHY: a whole snapshot may repartition already-full geometry. Remove absent
    // pieces and apply decreases before increases so the checked parent counter
    // never transiently exceeds the payload size. Unchanged rows stay untouched.
    tx.execute("DELETE FROM download_job_pieces WHERE job_id=?1 AND NOT EXISTS(
        SELECT 1 FROM temp.incoming_download_job_pieces p
        WHERE p.job_id=download_job_pieces.job_id AND p.piece_index=download_job_pieces.piece_index)", [job_id])?;
    tx.execute(
        "UPDATE download_job_pieces SET (prefix_bytes,present_bytes,block_bitmap,state,ich_corrupted)=(SELECT p.prefix_bytes,p.present_bytes,p.block_bitmap,p.state,p.ich_corrupted
        FROM temp.incoming_download_job_pieces p WHERE p.job_id=download_job_pieces.job_id
        AND p.piece_index=download_job_pieces.piece_index),updated_at_s=?2
        WHERE job_id=?1 AND present_bytes>(SELECT p.present_bytes
        FROM temp.incoming_download_job_pieces p WHERE p.job_id=download_job_pieces.job_id
        AND p.piece_index=download_job_pieces.piece_index)",
        params![job_id, now],
    )?;
    for snapshot in snapshots {
        snapshot.finish(tx, Some(("job_id", job_id)))?;
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
        token: JobToken {
            job_id: JobId::new(row.job_id)?,
            generation: row.generation,
        },
        expected_size_bytes: row.expected_size_bytes,
        piece_size: row.piece_size,
        completed: row.completed,
        final_rehash_pending: row.final_rehash_pending,
        md4_hashset_acquired: row.md4_hashset_acquired,
        md4_hashset: read_hex_list(
            conn,
            "SELECT lower(hex(md4_hash)) FROM download_job_md4_part_hashes WHERE job_id = ?1 ORDER BY part_index",
            row.job_id,
        )?,
        aich_hashset_acquired: row.aich_hashset_acquired,
        aich_root: row.aich_root,
        aich_root_origin: row.aich_root_origin,
        aich_trust_generation: row.aich_trust_generation,
        aich_hashset: read_hex_list(
            conn,
            "SELECT lower(hex(aich_hash)) FROM download_job_aich_part_hashes WHERE job_id = ?1 ORDER BY part_index",
            row.job_id,
        )?,
        verified_ranges: read_ranges(conn, row.job_id)?,
        pieces: read_pieces(conn, row.job_id)?,
        upload_priority: row.upload_priority,
        auto_upload_priority: row.auto_upload_priority,
        comment: row.comment,
        rating: row.rating,
        category_id: row.category_id,
        intent: DownloadIntent::parse(&row.intent)?,
        transfer_row_removed: row.transfer_row_removed,
        delivery_state: delivery_state_from_sql(&row.delivery_state)?,
        delivery_ownership: delivery_ownership_from_sql(&row.delivery_ownership)?,
        delivered_path: row.delivered_path,
        source_fingerprint: row.source_fingerprint,
        payload_fingerprint: row.payload_fingerprint,
    })
}

fn transfer_counts_from_connection(conn: &rusqlite::Connection) -> Result<MetadataTransferCounts> {
    conn.query_row(
        r#"
        SELECT count(*),
               coalesce(sum(CASE
                   WHEN download_jobs.terminal_completed_at_s IS NULL
                        AND download_jobs.intent = 'started'

                   THEN 1 ELSE 0 END), 0),
               coalesce(sum(CASE
                   WHEN download_jobs.terminal_completed_at_s IS NOT NULL THEN 1 ELSE 0 END), 0)
        FROM download_jobs
        JOIN known_files ON known_files.id = download_jobs.known_file_id
        WHERE download_jobs.removed_at_s IS NULL
          AND download_jobs.delete_requested_at_s IS NULL
        "#,
        [],
        |row| {
            Ok(MetadataTransferCounts {
                total: crate::sql_value::unsigned::<usize>(row, 0)?,
                active: crate::sql_value::unsigned::<usize>(row, 1)?,
                completed: crate::sql_value::unsigned::<usize>(row, 2)?,
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

fn read_pieces(conn: &rusqlite::Connection, job_id: i64) -> Result<Vec<MetadataTransferPiece>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT piece_index, state, prefix_bytes, block_bitmap, ich_corrupted,present_bytes
        FROM download_job_pieces
        WHERE job_id = ?1
        ORDER BY piece_index
        "#,
    )?;
    let rows = stmt.query_map(params![job_id], |row| {
        Ok(MetadataTransferPiece {
            piece_index: row.get::<_, u32>(0)?,
            state: row.get(1)?,
            prefix_bytes: crate::sql_value::unsigned::<u64>(row, 2)?,
            present_bytes: crate::sql_value::unsigned::<u64>(row, 5)?,
            block_bitmap: row.get::<_, Option<String>>(3)?,
            ich_corrupted: row.get::<_, bool>(4)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn read_ranges(conn: &rusqlite::Connection, job_id: i64) -> Result<Vec<MetadataTransferRange>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT start_offset, end_offset
        FROM download_job_verified_ranges
        WHERE job_id = ?1
        ORDER BY start_offset, end_offset
        "#,
    )?;
    let rows = stmt.query_map(params![job_id], |row| {
        Ok(MetadataTransferRange {
            start: crate::sql_value::unsigned::<u64>(row, 0)?,
            end: crate::sql_value::unsigned::<u64>(row, 1)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
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

fn optional_identity_from_row(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<NativeFileIdentity>> {
    let bytes = row.get::<_, Option<Vec<u8>>>(index)?;
    bytes
        .map(|bytes| {
            NativeFileIdentity::from_storage_bytes(&bytes).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    index,
                    rusqlite::types::Type::Blob,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid native file identity",
                    )
                    .into(),
                )
            })
        })
        .transpose()
}

fn directory_cleanup_authority_from_row(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<MetadataTransferDirectoryDeletionAuthority>> {
    let identity = optional_identity_from_row(row, index)?;
    let marker_id = row.get::<_, Option<String>>(index + 1)?;
    match (identity, marker_id) {
        (None, None) => Ok(None),
        (Some(identity), Some(marker_id)) => {
            let marker_id = marker_id.parse::<Uuid>().map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    index + 1,
                    rusqlite::types::Type::Text,
                    error.into(),
                )
            })?;
            Ok(Some(MetadataTransferDirectoryDeletionAuthority {
                identity,
                marker_id,
            }))
        }
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Blob,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "incomplete transfer directory cleanup authority",
            )
            .into(),
        )),
    }
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

fn delivery_state_to_sql(state: MetadataTransferDeliveryState) -> &'static str {
    match state {
        MetadataTransferDeliveryState::Pending => "pending",
        MetadataTransferDeliveryState::Delivered => "delivered",
    }
}

pub(crate) fn delivery_state_from_sql(value: &str) -> Result<MetadataTransferDeliveryState> {
    match value {
        "pending" => Ok(MetadataTransferDeliveryState::Pending),
        "delivered" => Ok(MetadataTransferDeliveryState::Delivered),
        _ => anyhow::bail!("invalid persisted transfer delivery state {value:?}"),
    }
}

fn delivery_ownership_to_sql(ownership: MetadataTransferDeliveryOwnership) -> &'static str {
    match ownership {
        MetadataTransferDeliveryOwnership::None => "none",
        MetadataTransferDeliveryOwnership::Owned => "owned",
        MetadataTransferDeliveryOwnership::Unowned => "unowned",
    }
}

pub(crate) fn delivery_ownership_from_sql(
    value: &str,
) -> Result<MetadataTransferDeliveryOwnership> {
    match value {
        "none" => Ok(MetadataTransferDeliveryOwnership::None),
        "owned" => Ok(MetadataTransferDeliveryOwnership::Owned),
        "unowned" => Ok(MetadataTransferDeliveryOwnership::Unowned),
        _ => anyhow::bail!("invalid persisted transfer delivery ownership {value:?}"),
    }
}

fn visible_state(manifest: &MetadataTransferManifest) -> &'static str {
    if manifest.completed {
        "completed"
    } else if manifest.final_rehash_pending {
        "completing"
    } else if manifest.pieces.iter().any(|piece| piece.prefix_bytes != 0) {
        "downloading"
    } else {
        "queued"
    }
}

#[cfg(test)]
mod tests;

pub(crate) fn read_transfer_row(
    conn: &rusqlite::Connection,
    id: JobId,
    deletion_requested: bool,
) -> Result<Option<TransferRow>> {
    let row = conn
            .prepare_cached(
                r#"
                SELECT download_jobs.id,
                       lower(hex(known_files.ed2k_hash)), download_jobs.display_name,
                       download_jobs.expected_size_bytes, download_jobs.part_size_bytes,
                       download_jobs.completed, download_jobs.md4_hashset_acquired,
                       download_jobs.aich_hashset_acquired,
                       CASE
                           WHEN download_jobs.aich_root IS NULL THEN NULL
                           ELSE lower(hex(download_jobs.aich_root))
                       END,
                       download_jobs.upload_priority, download_jobs.auto_upload_priority,
                       download_jobs.comment, download_jobs.rating,
                       download_jobs.category_id, download_jobs.intent, download_jobs.removed_at_s,
                       delivered_paths.platform, delivered_paths.native_path,
                       download_jobs.source_fingerprint, download_jobs.payload_fingerprint,
                       download_jobs.final_rehash_pending, download_jobs.delivery_state,
                       download_jobs.delivery_ownership,
                       download_jobs.aich_root_origin,
                       download_jobs.aich_trust_generation, download_jobs.execution_generation
                FROM known_files
                JOIN download_jobs ON download_jobs.known_file_id = known_files.id
                LEFT JOIN local_paths delivered_paths ON delivered_paths.id = download_jobs.delivered_path_id
                WHERE download_jobs.id = ?1
                  AND (
                      (?2 = 0 AND download_jobs.delete_requested_at_s IS NULL)
                      OR (?2 != 0 AND download_jobs.delete_requested_at_s IS NOT NULL)
                  )
                "#,
            )?
            .query_row(params![id, bool_to_i64(deletion_requested)], |row| {
                Ok(TransferRow {
                    job_id: row.get(0)?,
                    generation: crate::sql_value::unsigned(row,25)?,
                    file_hash: row.get(1)?,
                    display_name: row.get(2)?,
                    expected_size_bytes: crate::sql_value::optional_unsigned::<u64>(row, 3)?,
                    piece_size: crate::sql_value::unsigned::<u64>(row, 4)?,
                    completed: row.get::<_, i64>(5)? != 0,
                    md4_hashset_acquired: row.get::<_, i64>(6)? != 0,
                    aich_hashset_acquired: row.get::<_, i64>(7)? != 0,
                    aich_root: row.get(8)?,
                    aich_root_origin: row.get(23)?,
                    aich_trust_generation: crate::sql_value::unsigned::<u64>(row, 24)?,
                    upload_priority: row.get(9)?,
                    auto_upload_priority: row.get::<_, i64>(10)? != 0,
                    comment: row.get(11)?,
                    rating: row.get::<_, u8>(12)?,
                    category_id: row.get::<_, Option<i64>>(13)?,
                    intent: row.get(14)?,
                    transfer_row_removed: row.get::<_, Option<i64>>(15)?.is_some(),
                    delivered_path: optional_path_from_row(row, 16, 17)?,
                    source_fingerprint: optional_fingerprint_from_row(row, 18)?,
                    payload_fingerprint: optional_fingerprint_from_row(row, 19)?,
                    final_rehash_pending: row.get::<_, i64>(20)? != 0,
                    delivery_state: row.get(21)?,
                    delivery_ownership: row.get(22)?,
                })
            })
            .optional()?;
    Ok(row)
}
