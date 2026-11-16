//! Admission, explicit latest-job ownership, and bounded job pages.
use crate::{
    DownloadIntent, DownloadJobAdmission, DownloadJobRecord, DownloadJobRequest, JobId, JobToken,
    MetadataContentConflict, MetadataStore,
    native_path::optional_path_from_row,
    store::{decode_fixed_hex, unix_ms, upsert_local_path},
};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};

pub(crate) fn unix_s() -> i64 {
    unix_ms() / 1000
}

pub(crate) const MAX_JOB_TEXT_BYTES: usize = 65_536;
pub(crate) const MAX_JOB_PATH_BYTES: usize = 65_536;
pub(crate) const JOB_PAGE_BYTES: usize = 2 * 1024 * 1024;

pub(crate) fn validate_job_path(path: &std::path::Path) -> Result<()> {
    #[cfg(windows)]
    let bytes = {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .take(MAX_JOB_PATH_BYTES / 2 + 1)
            .count()
            * 2
    };
    #[cfg(not(windows))]
    let bytes = path.as_os_str().as_encoded_bytes().len();
    ensure!(
        bytes <= MAX_JOB_PATH_BYTES,
        "download path exceeds metadata byte allowance"
    );
    Ok(())
}

pub(crate) fn bounded_row_bytes(
    row: &rusqlite::Row<'_>,
    lengths: &[(usize, usize, usize)],
) -> rusqlite::Result<usize> {
    let mut bytes = 2048usize;
    for &(column, limit, multiplier) in lengths {
        let length = crate::sql_value::optional_unsigned::<usize>(row, column)?.unwrap_or(0);
        if length > limit {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                column,
                rusqlite::types::Type::Integer,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "download row exceeds metadata byte allowance",
                )
                .into(),
            ));
        }
        bytes = bytes
            .checked_add(
                length
                    .checked_mul(multiplier)
                    .ok_or(rusqlite::Error::InvalidQuery)?,
            )
            .ok_or(rusqlite::Error::InvalidQuery)?;
    }
    Ok(bytes)
}

/// Decode a fixed UUID directly from SQLite's borrowed bytes. SQLite TEXT
/// length counts characters and stops at NUL, so its CHECK is not a byte cap.
pub(crate) fn bounded_uuid_from_row(
    row: &rusqlite::Row<'_>,
    column: usize,
) -> rusqlite::Result<uuid::Uuid> {
    let value = row.get_ref(column)?.as_str()?;
    if value.len() != 36 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "job UUID exceeds byte bound",
            )
            .into(),
        ));
    }
    uuid::Uuid::parse_str(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

const JOB_COLUMNS: &str = "j.id,j.execution_generation,lower(hex(k.ed2k_hash)),
    CASE WHEN length(CAST(j.display_name AS BLOB))<=65536 THEN j.display_name END,
    k.size_bytes,j.expected_size_bytes,j.category_id,j.intent,p.platform,
    CASE WHEN length(p.native_path)<=65536 THEN p.native_path END,
    j.completed,j.final_rehash_pending,j.delivery_state,j.created_at_s,j.updated_at_s,
    j.terminal_completed_at_s,j.removed_at_s,j.internal_storage_retired,
    length(CAST(j.display_name AS BLOB)),length(p.native_path),
    storage.platform,CASE WHEN length(storage.native_path)<=65536 THEN storage.native_path END,
    j.storage_directory_marker_id,CASE WHEN length(j.storage_directory_identity)<=64 THEN j.storage_directory_identity END,length(storage.native_path),length(j.storage_directory_identity),
    CASE WHEN length(CAST(j.storage_failure_code AS BLOB))<=64 THEN j.storage_failure_code END,
    CASE WHEN length(CAST(j.storage_failure_message AS BLOB))<=4096 THEN j.storage_failure_message END,
    j.storage_failed_at_s,length(CAST(j.storage_failure_code AS BLOB)),length(CAST(j.storage_failure_message AS BLOB))";

fn job_row_bytes(row: &rusqlite::Row<'_>) -> rusqlite::Result<usize> {
    bounded_row_bytes(
        row,
        &[
            (18, MAX_JOB_TEXT_BYTES, 2),
            (19, MAX_JOB_PATH_BYTES, 4),
            (24, MAX_JOB_PATH_BYTES, 4),
            (25, 64, 2),
            (29, 64, 1),
            (30, 4096, 1),
        ],
    )
}

fn row_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<DownloadJobRecord> {
    job_row_bytes(row)?;
    let intent: String = row.get(7)?;
    let delivery: String = row.get(12)?;
    Ok(DownloadJobRecord {
        token: JobToken {
            job_id: row.get(0)?,
            generation: crate::sql_value::unsigned(row, 1)?,
        },
        file_hash: row.get(2)?,
        display_name: row.get(3)?,
        accepted_size_bytes: crate::sql_value::optional_unsigned(row, 4)?,
        expected_size_bytes: crate::sql_value::optional_unsigned(row, 5)?,
        category_id: row.get(6)?,
        intent: match intent.as_str() {
            "started" => DownloadIntent::Started,
            "stopped" => DownloadIntent::Stopped,
            _ => return Err(rusqlite::Error::InvalidQuery),
        },
        selected_temp: optional_path_from_row(row, 8, 9)?,
        storage: optional_path_from_row(row, 20, 21)?
            .map(|path| {
                let marker_id = bounded_uuid_from_row(row, 22)?;
                let identity = row
                    .get::<_, Option<Vec<u8>>>(23)?
                    .map(|bytes| {
                        crate::NativeFileIdentity::from_storage_bytes(&bytes)
                            .ok_or(rusqlite::Error::InvalidQuery)
                    })
                    .transpose()?;
                Ok::<_, rusqlite::Error>(crate::DownloadJobStorage {
                    path,
                    marker_id,
                    identity,
                })
            })
            .transpose()?,
        storage_failure: match (
            row.get_ref(26)?.as_str_or_null()?,
            row.get_ref(27)?.as_str_or_null()?,
            row.get::<_, Option<i64>>(28)?,
        ) {
            (None, None, None) => None,
            (Some(code), Some(message), Some(at)) => Some(
                crate::DownloadJobStorageFailure::new(code, message, at).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        26,
                        rusqlite::types::Type::Text,
                        error.into(),
                    )
                })?,
            ),
            _ => return Err(rusqlite::Error::InvalidQuery),
        },
        payload_verified: row.get::<_, bool>(10)? && !row.get::<_, bool>(11)?,
        delivery_state: match delivery.as_str() {
            "pending" => crate::MetadataTransferDeliveryState::Pending,
            "delivered" => crate::MetadataTransferDeliveryState::Delivered,
            _ => return Err(rusqlite::Error::InvalidQuery),
        },
        created_at_s: row.get(13)?,
        updated_at_s: row.get(14)?,
        completed_at_s: row.get(15)?,
        removed_at_s: row.get(16)?,
        internal_storage_retired: row.get(17)?,
    })
}

pub(crate) fn read_job(conn: &Connection, id: JobId) -> Result<Option<DownloadJobRecord>> {
    let sql = format!(
        "SELECT {JOB_COLUMNS} FROM download_jobs j JOIN known_files k ON k.id=j.known_file_id
        LEFT JOIN local_paths p ON p.id=j.selected_temp_path_id LEFT JOIN local_paths storage ON storage.id=j.storage_path_id WHERE j.id=?1"
    );
    Ok(conn.query_row(&sql, [id], row_job).optional()?)
}

impl MetadataStore {
    /// Allocate identity and latest pointer together. An unfinished duplicate
    /// returns unchanged, including intent, name, category, and fixed storage.
    pub fn admit_download_job(&self, request: &DownloadJobRequest) -> Result<DownloadJobAdmission> {
        let hash = decode_fixed_hex(&request.file_hash, 16, "ED2K hash")?;
        ensure!(
            !request.display_name.trim().is_empty()
                && request.display_name.len() <= MAX_JOB_TEXT_BYTES,
            "download job name is empty or exceeds metadata byte allowance"
        );
        ensure!(request.piece_size > 0, "download piece size is zero");
        let expected = request.expected_size_bytes.map(i64::try_from).transpose()?;
        ensure!(
            expected.is_none_or(|size| size > 0),
            "download size must be positive or unknown"
        );
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing = tx
            .query_row(
                "SELECT j.id FROM download_jobs j JOIN known_files k ON k.id=j.known_file_id
            WHERE k.ed2k_hash=?1 AND j.removed_at_s IS NULL AND j.terminal_completed_at_s IS NULL",
                [&hash],
                |row| row.get::<_, JobId>(0),
            )
            .optional()?;
        if let Some(size) = expected {
            crate::content_identity::check_accepted_identity(&tx, &hash, size, None)?;
        }
        if let Some(id) = existing {
            let job = read_job(&tx, id)?.expect("selected job");
            ensure!(
                job.expected_size_bytes
                    .zip(request.expected_size_bytes)
                    .is_none_or(|(a, b)| a == b),
                MetadataContentConflict("download attempt has conflicting expected size")
            );
            return Ok(DownloadJobAdmission {
                created: false,
                job,
            });
        }
        // Admission records a claim on the job, never accepted size on content.
        tx.execute("INSERT INTO known_files(ed2k_hash,size_bytes,display_name,first_seen_at_ms,last_seen_at_ms,updated_at_ms)
            VALUES(?1,NULL,?2,?3,?3,?3) ON CONFLICT(ed2k_hash) DO NOTHING",
            params![hash, request.display_name, unix_ms()])?;
        let (known, accepted): (i64, Option<i64>) = tx.query_row(
            "SELECT id,size_bytes FROM known_files WHERE ed2k_hash=?1",
            [&hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        ensure!(
            accepted.zip(expected).is_none_or(|(a, b)| a == b),
            MetadataContentConflict("ED2K identity has conflicting file size")
        );
        let expected = expected.or(accepted);
        ensure!(
            expected.is_none_or(|size| size > 0),
            "zero-byte download execution is unsupported"
        );
        tx.execute("INSERT INTO download_jobs(known_file_id,expected_size_bytes,display_name,part_size_bytes,part_count,
            intent,category_id,visible_state,delivery_state,created_at_s,updated_at_s)
            VALUES(?1,?2,?3,?4,0,?5,?6,'queued','pending',?7,?7)",
            params![known,expected,request.display_name,i64::try_from(request.piece_size)?,request.intent.as_str(),request.category_id,unix_s()])?;
        let id = JobId::new(tx.last_insert_rowid())?;
        tx.execute(
            "UPDATE known_files SET latest_download_job_id=?2 WHERE id=?1",
            params![known, id],
        )?;
        let job = read_job(&tx, id)?.expect("inserted job");
        tx.commit()?;
        Ok(DownloadJobAdmission { created: true, job })
    }

    /// A separate claim transition; duplicate admission never enriches an existing attempt.
    pub fn learn_download_job_size(&self, token: JobToken, size: u64) -> Result<bool> {
        ensure!(size > 0, "zero-byte download execution is unsupported");
        let size_sql = i64::try_from(size)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(job) = read_job(&tx, token.job_id)?
            .filter(|j| j.token == token && j.removed_at_s.is_none() && j.completed_at_s.is_none())
        else {
            return Ok(false);
        };
        ensure!(
            job.expected_size_bytes
                .is_none_or(|previous| previous == size),
            MetadataContentConflict("download attempt has conflicting expected size")
        );
        let hash = decode_fixed_hex(&job.file_hash, 16, "ED2K hash")?;
        crate::content_identity::check_accepted_identity(&tx, &hash, size_sql, None)?;
        let changed = tx.execute(
            "UPDATE download_jobs SET expected_size_bytes=?2,updated_at_s=?3
            WHERE id=?1 AND expected_size_bytes IS NULL",
            params![token.job_id, size_sql, unix_s()],
        )?;
        tx.commit()?;
        Ok(changed != 0)
    }

    pub fn download_job(&self, id: JobId) -> Result<Option<DownloadJobRecord>> {
        let conn = self.connection()?;
        read_job(&conn, id)
    }

    pub fn latest_download_job(&self, hash: &str) -> Result<Option<DownloadJobRecord>> {
        let raw = decode_fixed_hex(hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let id = conn
            .query_row(
                "SELECT latest_download_job_id FROM known_files WHERE ed2k_hash=?1",
                [raw],
                |row| row.get::<_, Option<JobId>>(0),
            )
            .optional()?
            .flatten();
        id.map(|id| read_job(&conn, id))
            .transpose()
            .map(Option::flatten)
    }

    /// Logical removal clears only its own head and reserves internal-storage
    /// retirement atomically. Completed output paths are never deletion authority
    /// here; stop is the operation which retains resumable internal pieces.
    pub fn remove_download_job(&self, id: JobId) -> Result<bool> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = crate::transfer_store::request_job_removal(&tx, id, false)?;
        tx.commit()?;
        Ok(changed)
    }

    /// The caller chooses category/global temp before first filesystem work.
    /// Later starts retain that exact path and issue a new callback generation.
    pub fn start_download_job(
        &self,
        token: JobToken,
        selected_temp: &std::path::Path,
    ) -> Result<Option<DownloadJobRecord>> {
        validate_job_path(selected_temp)?;
        ensure!(
            selected_temp.is_absolute(),
            "download temp path must be absolute"
        );
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current = read_job(&tx, token.job_id)?;
        let Some(current) = current.filter(|job| {
            job.token == token && job.removed_at_s.is_none() && job.completed_at_s.is_none()
        }) else {
            return Ok(None);
        };
        let selected = current.selected_temp.as_deref().unwrap_or(selected_temp);
        let path_id = upsert_local_path(&tx, selected)?;
        let (storage_path, marker) = match &current.storage {
            Some(storage) => (storage.path.clone(), storage.marker_id),
            None => {
                let marker = uuid::Uuid::new_v4();
                (selected.join(format!("{}-{marker}", token.job_id)), marker)
            }
        };
        validate_job_path(&storage_path)?;
        let storage_path_id = upsert_local_path(&tx, &storage_path)?;
        let generation = i64::try_from(token.generation)?
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("job generation exhausted"))?;
        tx.execute(
            "UPDATE download_jobs SET selected_temp_path_id=coalesce(selected_temp_path_id,?2),
            execution_generation=?3,intent='started',updated_at_s=?4,
            storage_failure_code=NULL,storage_failure_message=NULL,storage_failed_at_s=NULL,
            storage_path_id=coalesce(storage_path_id,?5),storage_directory_marker_id=coalesce(storage_directory_marker_id,?6) WHERE id=?1",
            params![token.job_id, path_id, generation, unix_s(),storage_path_id,marker.to_string()],
        )?;
        let result = read_job(&tx, token.job_id)?;
        tx.commit()?;
        Ok(result)
    }

    /// Called only after exclusive allocation and marker creation. A stale
    /// creator cannot publish ownership into a newer execution generation.
    pub fn establish_download_job_storage(
        &self,
        token: JobToken,
        identity: crate::NativeFileIdentity,
    ) -> Result<bool> {
        let identity = identity.storage_bytes();
        Ok(self.connection()?.execute("UPDATE download_jobs SET storage_directory_identity=?3,updated_at_s=?4
            WHERE id=?1 AND execution_generation=?2 AND intent='started' AND removed_at_s IS NULL
              AND terminal_completed_at_s IS NULL AND delete_requested_at_s IS NULL AND storage_path_id IS NOT NULL
              AND (storage_directory_identity IS NULL OR storage_directory_identity=?3)",
            params![token.job_id,i64::try_from(token.generation)?,identity,unix_s()])?!=0)
    }

    /// Capture an unfinished attempt's storage fault and fence all its callbacks.
    /// Desired intent is retained; only an admitted explicit start clears it.
    pub fn fail_download_job_storage(
        &self,
        token: JobToken,
        failure: &crate::DownloadJobStorageFailure,
    ) -> Result<crate::DownloadJobStorageFailureOutcome> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let generation = i64::try_from(token.generation)?;
        // WHY: advancing the existing callback fence prevents a late success from
        // erasing the fault or completing delivery from the failed attempt.
        let applied = tx.execute("UPDATE download_jobs SET execution_generation=execution_generation+1,
            storage_failure_code=?3,storage_failure_message=?4,storage_failed_at_s=?5,updated_at_s=?6
            WHERE id=?1 AND execution_generation=?2 AND execution_generation<9223372036854775807
            AND removed_at_s IS NULL AND terminal_completed_at_s IS NULL AND delete_requested_at_s IS NULL",
            params![token.job_id,generation,failure.code(),failure.message(),failure.failed_at_s(),unix_s()])? != 0;
        let job = read_job(&tx, token.job_id)?;
        tx.commit()?;
        Ok(crate::DownloadJobStorageFailureOutcome { applied, job })
    }

    pub fn stop_download_job(&self, token: JobToken) -> Result<bool> {
        let generation = i64::try_from(token.generation)?;
        ensure!(generation < i64::MAX, "job generation exhausted");
        Ok(self.connection()?.execute("UPDATE download_jobs SET intent='stopped',execution_generation=execution_generation+1,
            updated_at_s=?3 WHERE id=?1 AND execution_generation=?2 AND removed_at_s IS NULL AND terminal_completed_at_s IS NULL",
            params![token.job_id,generation,unix_s()])? != 0)
    }

    pub fn download_jobs_after(
        &self,
        after: Option<JobId>,
        limit: usize,
        runnable_only: bool,
    ) -> Result<Vec<DownloadJobRecord>> {
        ensure!((1..=256).contains(&limit), "invalid download job page size");
        let conn = self.connection()?;
        let predicate = if runnable_only {
            "AND j.intent='started' AND j.terminal_completed_at_s IS NULL AND j.storage_failure_code IS NULL"
        } else {
            ""
        };
        let sql=format!("SELECT {JOB_COLUMNS} FROM download_jobs j JOIN known_files k ON k.id=j.known_file_id
            LEFT JOIN local_paths p ON p.id=j.selected_temp_path_id LEFT JOIN local_paths storage ON storage.id=j.storage_path_id WHERE j.id>?1 AND j.removed_at_s IS NULL {predicate}
            ORDER BY j.id LIMIT ?2");
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params![after.map_or(0, JobId::get), i64::try_from(limit)?])?;
        let mut result = Vec::new();
        let mut bytes = 0usize;
        while let Some(row) = rows.next()? {
            let charge = job_row_bytes(row)?;
            if bytes + charge > JOB_PAGE_BYTES {
                ensure!(!result.is_empty(), "download row exceeds page allowance");
                break;
            }
            bytes += charge;
            result.push(row_job(row)?);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
