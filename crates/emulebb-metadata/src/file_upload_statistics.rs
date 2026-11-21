//! SQL projection of captured file accounting, updated with its durable checkpoint.

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::{
    MetadataFileUploadDelta, MetadataFileUploadTotals, MetadataStore, store::decode_fixed_hex,
};

/// Committed process-session counters and lifetime facts for one known hash.
/// Session counters are connection-local and are never restored from disk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetadataFileUploadStatistics {
    pub session_uploaded_bytes: u64,
    pub session_upload_requests: u64,
    pub session_accepted_uploads: u64,
    pub lifetime: MetadataFileUploadTotals,
}

pub(crate) fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TEMP TABLE session_file_upload_statistics (
            ed2k_hash BLOB PRIMARY KEY CHECK(length(ed2k_hash)=16),
            uploaded_bytes INTEGER NOT NULL CHECK(uploaded_bytes>=0),
            upload_requests INTEGER NOT NULL CHECK(upload_requests>=0),
            accepted_sessions INTEGER NOT NULL CHECK(accepted_sessions>=0)
         ) STRICT, WITHOUT ROWID;
         CREATE INDEX temp.session_upload_bytes_idx
            ON session_file_upload_statistics(uploaded_bytes,ed2k_hash);
         CREATE INDEX temp.session_upload_requests_idx
            ON session_file_upload_statistics(upload_requests,ed2k_hash);
         CREATE INDEX temp.session_upload_accepts_idx
            ON session_file_upload_statistics(accepted_sessions,ed2k_hash);",
    )?;
    Ok(())
}

/// The caller owns the existing peer/file checkpoint transaction. Both
/// projections publish together; a failed checkpoint changes neither one.
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
    // Key by content, not a recyclable numeric row ID. Unknown hashes and
    // empty batches create no process-session accounting record.
    tx.prepare_cached(
        "INSERT INTO temp.session_file_upload_statistics
            SELECT ed2k_hash,?2,?3,?4 FROM known_files
            WHERE ed2k_hash=?1 AND (?2!=0 OR ?3!=0 OR ?4!=0)
         ON CONFLICT(ed2k_hash) DO UPDATE SET
            uploaded_bytes=uploaded_bytes+excluded.uploaded_bytes,
            upload_requests=upload_requests+excluded.upload_requests,
            accepted_sessions=accepted_sessions+excluded.accepted_sessions",
    )?
    .execute(params![hash, bytes, requests, accepted])?;
    Ok(())
}

impl MetadataStore {
    /// Read one committed accounting snapshot without hydrating a library row
    /// or creating an entry in the runtime's capture ledger.
    pub fn file_upload_statistics(
        &self,
        hash: &str,
    ) -> Result<Option<MetadataFileUploadStatistics>> {
        let hash = decode_fixed_hex(hash, 16, "ED2K library hash")?;
        self.connection()?
            .prepare_cached(
                "SELECT coalesce(s.uploaded_bytes,0),coalesce(s.upload_requests,0),
                coalesce(s.accepted_sessions,0),k.all_time_uploaded_bytes,
                k.all_time_upload_requests,k.all_time_upload_accepts,
                k.last_upload_requested_at_s,k.last_uploaded_at_s
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
