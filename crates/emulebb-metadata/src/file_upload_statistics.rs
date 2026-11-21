//! Indexed process-local publication of captured file accounting.

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::{
    MetadataFileUploadDelta, MetadataFileUploadTotals, MetadataStore, store::decode_fixed_hex,
};

/// Published process-session counters and effective lifetime facts for one hash.
/// Session counters are connection-local and are never restored from disk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetadataFileUploadStatistics {
    pub session_uploaded_bytes: u64,
    pub session_upload_requests: u64,
    pub session_accepted_uploads: u64,
    pub lifetime: MetadataFileUploadTotals,
}

/// Fixed-size capture taken while publication excludes checkpoint drain/restore.
/// Pending lifetime values are deltas, never absolute runtime watermarks.
#[derive(Debug, Clone, Copy, Default)]
pub struct MetadataFileUploadCapture {
    pub file_hash: [u8; 16],
    pub session_uploaded_bytes: u64,
    pub session_upload_requests: u64,
    pub session_accepted_uploads: u64,
    pub pending: MetadataFileUploadTotals,
}

pub const FILE_UPLOAD_CAPTURE_BATCH: usize = 128;

pub(crate) fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TEMP TABLE session_file_upload_statistics (
            known_file_id INTEGER PRIMARY KEY,
            ed2k_hash BLOB NOT NULL UNIQUE CHECK(length(ed2k_hash)=16),
            uploaded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(uploaded_bytes>=0),
            upload_requests INTEGER NOT NULL DEFAULT 0 CHECK(upload_requests>=0),
            accepted_sessions INTEGER NOT NULL DEFAULT 0 CHECK(accepted_sessions>=0),
            lifetime_bytes INTEGER NOT NULL CHECK(lifetime_bytes>=0),
            lifetime_requests INTEGER NOT NULL CHECK(lifetime_requests>=0),
            lifetime_accepts INTEGER NOT NULL CHECK(lifetime_accepts>=0),
            last_requested_at_s INTEGER CHECK(last_requested_at_s>=0),
            last_uploaded_at_s INTEGER CHECK(last_uploaded_at_s>=0)
         ) STRICT;
         CREATE INDEX temp.session_upload_bytes_idx
            ON session_file_upload_statistics(uploaded_bytes,ed2k_hash);
         CREATE INDEX temp.session_upload_requests_idx
            ON session_file_upload_statistics(upload_requests,ed2k_hash);
         CREATE INDEX temp.session_upload_accepts_idx
            ON session_file_upload_statistics(accepted_sessions,ed2k_hash);
         CREATE INDEX temp.lifetime_upload_bytes_idx ON session_file_upload_statistics(lifetime_bytes,ed2k_hash);
         CREATE INDEX temp.lifetime_upload_requests_idx ON session_file_upload_statistics(lifetime_requests,ed2k_hash);
         CREATE INDEX temp.lifetime_upload_accepts_idx ON session_file_upload_statistics(lifetime_accepts,ed2k_hash);
         CREATE INDEX temp.last_upload_requested_idx ON session_file_upload_statistics(last_requested_at_s,ed2k_hash);
         CREATE INDEX temp.last_uploaded_idx ON session_file_upload_statistics(last_uploaded_at_s,ed2k_hash);
         INSERT INTO session_file_upload_statistics
            SELECT k.id,k.ed2k_hash,0,0,0,k.all_time_uploaded_bytes,k.all_time_upload_requests,
                   k.all_time_upload_accepts,k.last_upload_requested_at_s,k.last_uploaded_at_s
            FROM library_files l CROSS JOIN known_files k ON k.id=l.known_file_id;
         CREATE TEMP TRIGGER session_statistics_accept AFTER INSERT ON main.library_files
         BEGIN
            INSERT INTO session_file_upload_statistics
                SELECT k.id,k.ed2k_hash,0,0,0,k.all_time_uploaded_bytes,k.all_time_upload_requests,
                       k.all_time_upload_accepts,k.last_upload_requested_at_s,k.last_uploaded_at_s
                FROM known_files k WHERE k.id=new.known_file_id;
         END;
         CREATE TEMP TRIGGER session_statistics_remove AFTER DELETE ON main.library_files
         BEGIN DELETE FROM session_file_upload_statistics WHERE known_file_id=old.known_file_id; END;",
    )?;
    Ok(())
}

/// The caller owns the existing durable peer/file checkpoint transaction.
/// Publication is independent and must not add these deltas a second time.
pub(crate) fn apply_delta(
    tx: &Transaction<'_>,
    hash: &[u8],
    delta: &MetadataFileUploadDelta,
) -> Result<()> {
    let bytes = i64::try_from(delta.uploaded_bytes)?;
    let requests = i64::try_from(delta.upload_requests)?;
    let accepted = i64::try_from(delta.accepted_sessions)?;
    // WHY: SQLite promotes overflowing integer sums to REAL. STRICT columns
    // reject that result, rolling back the batch instead of clamping counters.
    tx.prepare_cached(
        "UPDATE known_files SET
            all_time_uploaded_bytes=all_time_uploaded_bytes+?2,
            all_time_upload_requests=all_time_upload_requests+?3,
            all_time_upload_accepts=all_time_upload_accepts+?4,
            last_upload_requested_at_s=CASE WHEN ?5 IS NULL THEN last_upload_requested_at_s
                ELSE max(coalesce(last_upload_requested_at_s,?5),?5) END,
            last_uploaded_at_s=CASE WHEN ?6 IS NULL THEN last_uploaded_at_s
                ELSE max(coalesce(last_uploaded_at_s,?6),?6) END
         WHERE ed2k_hash=?1",
    )?
    .execute(params![
        hash,
        bytes,
        requests,
        accepted,
        delta.last_requested_at_s,
        delta.last_uploaded_at_s
    ])?;
    Ok(())
}

impl MetadataStore {
    /// Publish one bounded batch to TEMP only. Repeating absolute captures is
    /// idempotent. The caller excludes checkpoint drain/commit/restore while
    /// capturing and publishing; capture mutexes must be released before SQL.
    pub fn publish_file_upload_captures(
        &self,
        captures: &[MetadataFileUploadCapture],
    ) -> Result<()> {
        ensure!(
            captures.len() <= FILE_UPLOAD_CAPTURE_BATCH,
            "file statistics batch exceeds allowance"
        );
        if captures.is_empty() {
            return Ok(());
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        {
            let mut write = tx.prepare_cached(
                "INSERT INTO temp.session_file_upload_statistics
                 SELECT k.id,k.ed2k_hash,?2,?3,?4,
                    k.all_time_uploaded_bytes+?5,k.all_time_upload_requests+?6,k.all_time_upload_accepts+?7,
                    CASE WHEN ?8 IS NULL THEN k.last_upload_requested_at_s
                         ELSE max(coalesce(k.last_upload_requested_at_s,?8),?8) END,
                    CASE WHEN ?9 IS NULL THEN k.last_uploaded_at_s
                         ELSE max(coalesce(k.last_uploaded_at_s,?9),?9) END
                 FROM known_files k JOIN library_files l ON l.known_file_id=k.id WHERE k.ed2k_hash=?1
                 ON CONFLICT(known_file_id) DO UPDATE SET
                    uploaded_bytes=excluded.uploaded_bytes,upload_requests=excluded.upload_requests,
                    accepted_sessions=excluded.accepted_sessions,lifetime_bytes=excluded.lifetime_bytes,
                    lifetime_requests=excluded.lifetime_requests,lifetime_accepts=excluded.lifetime_accepts,
                    last_requested_at_s=excluded.last_requested_at_s,last_uploaded_at_s=excluded.last_uploaded_at_s
                 WHERE (uploaded_bytes,upload_requests,accepted_sessions,lifetime_bytes,lifetime_requests,
                        lifetime_accepts,last_requested_at_s,last_uploaded_at_s)
                    IS NOT (excluded.uploaded_bytes,excluded.upload_requests,excluded.accepted_sessions,
                        excluded.lifetime_bytes,excluded.lifetime_requests,excluded.lifetime_accepts,
                        excluded.last_requested_at_s,excluded.last_uploaded_at_s)")?;
            for capture in captures {
                write.execute(params![
                    capture.file_hash.as_slice(),
                    i64::try_from(capture.session_uploaded_bytes)?,
                    i64::try_from(capture.session_upload_requests)?,
                    i64::try_from(capture.session_accepted_uploads)?,
                    i64::try_from(capture.pending.uploaded_bytes)?,
                    i64::try_from(capture.pending.upload_requests)?,
                    i64::try_from(capture.pending.accepted_sessions)?,
                    capture.pending.last_requested_at_s,
                    capture.pending.last_uploaded_at_s
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Read one published accounting snapshot without hydrating a library row
    /// or creating an entry in the runtime's capture ledger.
    pub fn file_upload_statistics(
        &self,
        hash: &str,
    ) -> Result<Option<MetadataFileUploadStatistics>> {
        let hash = decode_fixed_hex(hash, 16, "ED2K library hash")?;
        self.connection()?
            .prepare_cached(
                "SELECT coalesce(s.uploaded_bytes,0),coalesce(s.upload_requests,0),
                coalesce(s.accepted_sessions,0),coalesce(s.lifetime_bytes,k.all_time_uploaded_bytes),
                coalesce(s.lifetime_requests,k.all_time_upload_requests),coalesce(s.lifetime_accepts,k.all_time_upload_accepts),
                CASE WHEN s.known_file_id IS NULL THEN k.last_upload_requested_at_s ELSE s.last_requested_at_s END,
                CASE WHEN s.known_file_id IS NULL THEN k.last_uploaded_at_s ELSE s.last_uploaded_at_s END
             FROM known_files k LEFT JOIN temp.session_file_upload_statistics s
                ON s.ed2k_hash=k.ed2k_hash WHERE k.ed2k_hash=?1",
            )?
            .query_row([hash], |row| {
                Ok(MetadataFileUploadStatistics {
                    session_uploaded_bytes: crate::sql_value::unsigned(row, 0)?,
                    session_upload_requests: crate::sql_value::unsigned(row, 1)?,
                    session_accepted_uploads: crate::sql_value::unsigned(row, 2)?,
                    lifetime: MetadataFileUploadTotals {
                        uploaded_bytes: crate::sql_value::unsigned(row, 3)?,
                        upload_requests: crate::sql_value::unsigned(row, 4)?,
                        accepted_sessions: crate::sql_value::unsigned(row, 5)?,
                        last_requested_at_s: row.get(6)?,
                        last_uploaded_at_s: row.get(7)?,
                    },
                })
            })
            .optional()
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
