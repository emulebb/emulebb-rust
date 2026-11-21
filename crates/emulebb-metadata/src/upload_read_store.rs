//! Cached file captions for upload management; never payload authority.
use anyhow::{Context, Result, ensure};
use rusqlite::{OptionalExtension, Row};

use crate::MetadataStore;

const MAX_NAME_BYTES: usize = 65_536;

/// Scalar file facts for an upload row, without hashsets, paths or part arrays.
/// Names are the cached content/job names, even when the physical copy is offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataUploadFileSummary {
    pub display_name: String,
    pub file_size: u64,
    pub parts_total: u32,
    pub parts_obtained: u32,
}

const COMPLETE_SQL: &str = "SELECT length(CAST(c.display_name AS BLOB)),
    CASE WHEN length(CAST(c.display_name AS BLOB))<=65536 THEN c.display_name END,
    k.size_bytes,c.part_size_bytes
    FROM known_files k CROSS JOIN verified_local_content c ON c.known_file_id=k.id
    WHERE k.ed2k_hash=?1";

const DOWNLOAD_SQL: &str = "SELECT length(CAST(j.display_name AS BLOB)),
    CASE WHEN length(CAST(j.display_name AS BLOB))<=65536 THEN j.display_name END,
    j.expected_size_bytes,j.part_size_bytes,
    (SELECT coalesce(sum(max(0,
        r.end_offset/j.part_size_bytes
        + CASE WHEN r.end_offset=j.expected_size_bytes AND r.end_offset%j.part_size_bytes!=0 THEN 1 ELSE 0 END
        - r.start_offset/j.part_size_bytes
        - CASE WHEN r.start_offset%j.part_size_bytes!=0 THEN 1 ELSE 0 END)),0)
     FROM download_job_verified_ranges r WHERE r.job_id=j.id)
    FROM known_files k CROSS JOIN download_jobs j ON j.known_file_id=k.id
    WHERE k.ed2k_hash=?1 AND j.expected_size_bytes IS NOT NULL";

fn summary(row: &Row<'_>, complete: bool) -> Result<MetadataUploadFileSummary> {
    let name_bytes = usize::try_from(row.get::<_, i64>(0)?)?;
    ensure!(
        name_bytes <= MAX_NAME_BYTES,
        "upload file name exceeds read allowance"
    );
    let file_size = u64::try_from(row.get::<_, i64>(2)?)?;
    let piece_size = u64::try_from(row.get::<_, i64>(3)?)?;
    ensure!(piece_size > 0, "invalid upload file part size");
    let parts_total = u32::try_from(file_size.div_ceil(piece_size))
        .context("upload file part count exceeds u32")?;
    let parts_obtained = if complete { parts_total } else { row.get(4)? };
    ensure!(
        parts_obtained <= parts_total,
        "invalid upload file verified part count"
    );
    Ok(MetadataUploadFileSummary {
        display_name: row.get(1)?,
        file_size,
        parts_total,
        parts_obtained,
    })
}

impl MetadataStore {
    /// Read one hash's cached local content or download facts. Remote observations
    /// alone do not create this view. This performs no filesystem work and grants
    /// no serving eligibility; all protocol admissions retain their own checks.
    pub fn upload_file_summary(
        &self,
        hash: &[u8; 16],
    ) -> Result<Option<MetadataUploadFileSummary>> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let complete = tx
            .prepare_cached(COMPLETE_SQL)?
            .query_row([hash.as_slice()], |row| Ok(summary(row, true)))
            .optional()?;
        if let Some(complete) = complete {
            return complete.map(Some);
        }
        tx.prepare_cached(DOWNLOAD_SQL)?
            .query_row([hash.as_slice()], |row| Ok(summary(row, false)))
            .optional()?
            .transpose()
    }
}

#[cfg(test)]
mod tests;
