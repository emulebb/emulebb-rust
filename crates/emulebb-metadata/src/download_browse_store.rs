//! On-demand job detail and part pages, independent of execution hydration.
use crate::{
    DownloadJobRecord, JobId, MetadataStore, MetadataTransferDeliveryOwnership,
    download_job_store::{
        JOB_COLUMNS, MAX_JOB_PATH_BYTES, bounded_row_bytes, job_row_bytes, row_job,
    },
    native_path::optional_path_from_row,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{OptionalExtension, params};
use std::path::PathBuf;

const PARTS_SQL: &str = "SELECT piece_index,state,present_bytes,ich_corrupted
    FROM download_job_pieces WHERE job_id=?1 AND piece_index>=?2 AND piece_index<?3
    ORDER BY piece_index";

#[derive(Debug)]
pub struct MetadataDownloadDetail {
    pub job: DownloadJobRecord,
    pub delivered_path: Option<PathBuf>,
    pub ownership: MetadataTransferDeliveryOwnership,
}

/// Recorded internal part state. Absence of a row means no checkpointed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataDownloadPart {
    pub index: u32,
    pub start: u64,
    pub end: u64,
    pub size_bytes: u64,
    pub present_bytes: u64,
    pub complete: bool,
    pub corrupted: bool,
}

#[derive(Debug)]
pub struct MetadataDownloadPartPage {
    pub parts: Vec<MetadataDownloadPart>,
    pub next_after: Option<u32>,
    pub has_more: bool,
}

/// Compact durable status for source preparation, never execution hydration.
#[derive(Debug)]
pub struct MetadataDownloadVerifiedParts {
    pub file_size_bytes: u64,
    /// Data parts only; an exact-multiple protocol EOF slice is not included.
    pub verified_parts: Vec<bool>,
}

impl MetadataStore {
    /// Capture geometry and verified checkpoints in one generation-fenced
    /// snapshot. Presence alone must never be advertised as verified content.
    pub fn download_job_verified_parts(
        &self,
        token: crate::JobToken,
    ) -> Result<Option<MetadataDownloadVerifiedParts>> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let geometry = tx
            .query_row(
                "SELECT expected_size_bytes,part_size_bytes FROM download_jobs
            WHERE id=?1 AND execution_generation=?2 AND intent='started'
            AND removed_at_s IS NULL AND terminal_completed_at_s IS NULL
            AND delete_requested_at_s IS NULL AND storage_failure_code IS NULL
            AND internal_storage_retired=0 AND expected_size_bytes>0",
                params![token.job_id, i64::try_from(token.generation)?],
                |row| {
                    Ok((
                        crate::sql_value::unsigned::<u64>(row, 0)?,
                        crate::sql_value::unsigned::<u64>(row, 1)?,
                    ))
                },
            )
            .optional()?;
        let Some((size, part_size)) = geometry else {
            return Ok(None);
        };
        ensure!(part_size > 0, "invalid part size");
        let count = usize::try_from(size.div_ceil(part_size))?;
        ensure!(
            (1..=65534).contains(&count),
            "unsupported source preparation geometry"
        );
        let mut verified_parts = vec![false; count];
        {
            let mut stmt = tx.prepare_cached(
                "SELECT piece_index,present_bytes FROM download_job_pieces
                WHERE job_id=?1 AND state='Verified' ORDER BY piece_index",
            )?;
            let mut rows = stmt.query([token.job_id])?;
            while let Some(row) = rows.next()? {
                let index = crate::sql_value::unsigned::<usize>(row, 0)?;
                ensure!(index < count, "verified part outside job geometry");
                let extent = (size - index as u64 * part_size).min(part_size);
                ensure!(
                    crate::sql_value::unsigned::<u64>(row, 1)? == extent,
                    "invalid verified part extent"
                );
                verified_parts[index] = true;
            }
        }
        tx.commit()?;
        Ok(Some(MetadataDownloadVerifiedParts {
            file_size_bytes: size,
            verified_parts,
        }))
    }

    /// Read one header and its recorded delivery ownership in one snapshot.
    /// Bound native path backing before decoding it; no filesystem probe occurs.
    pub fn download_job_detail(&self, id: JobId) -> Result<Option<MetadataDownloadDetail>> {
        let conn = self.connection()?;
        let sql = format!(
            "SELECT {JOB_COLUMNS},d.platform,
            CASE WHEN length(d.native_path)<=65536 THEN d.native_path END,
            length(d.native_path),j.delivery_ownership
            FROM download_jobs j JOIN known_files k ON k.id=j.known_file_id
            LEFT JOIN local_paths p ON p.id=j.selected_temp_path_id
            LEFT JOIN local_paths storage ON storage.id=j.storage_path_id
            LEFT JOIN local_paths d ON d.id=j.delivered_path_id
            WHERE j.id=?1 AND j.removed_at_s IS NULL"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query([id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let bytes = job_row_bytes(row)?
            .checked_add(bounded_row_bytes(row, &[(34, MAX_JOB_PATH_BYTES, 4)])?)
            .context("download detail size overflow")?;
        ensure!(
            bytes <= 1024 * 1024,
            "download detail exceeds byte allowance"
        );
        let ownership = match row.get_ref(35)?.as_str()? {
            "none" => MetadataTransferDeliveryOwnership::None,
            "owned" => MetadataTransferDeliveryOwnership::Owned,
            "unowned" => MetadataTransferDeliveryOwnership::Unowned,
            _ => anyhow::bail!("invalid delivery ownership"),
        };
        Ok(Some(MetadataDownloadDetail {
            job: row_job(row)?,
            delivered_path: optional_path_from_row(row, 32, 33)?,
            ownership,
        }))
    }

    /// Derive only the requested geometry window and seek its persisted rows
    /// through the existing (job_id,piece_index) primary key. Retired internal
    /// data and unknown geometry have no part rows to expose.
    pub fn download_job_parts_after(
        &self,
        id: JobId,
        after: Option<u32>,
        limit: usize,
    ) -> Result<Option<MetadataDownloadPartPage>> {
        ensure!((1..=256).contains(&limit), "invalid part page size");
        let mut conn = self.connection()?;
        // WHY: geometry and piece checkpoints must describe the same database
        // snapshot, including when another supported connection commits between
        // the header and range reads. Never recover by loading a whole manifest.
        let tx = conn.transaction()?;
        let geometry = tx
            .query_row(
                "SELECT expected_size_bytes,part_size_bytes,internal_storage_retired
             FROM download_jobs WHERE id=?1 AND removed_at_s IS NULL",
                [id],
                |row| {
                    Ok((
                        crate::sql_value::optional_unsigned::<u64>(row, 0)?,
                        crate::sql_value::unsigned::<u64>(row, 1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((size, part_size, retired)) = geometry else {
            return Ok(None);
        };
        let empty = || MetadataDownloadPartPage {
            parts: Vec::new(),
            next_after: None,
            has_more: false,
        };
        let Some(size) = size.filter(|_| !retired) else {
            return Ok(Some(empty()));
        };
        ensure!(part_size > 0, "invalid part size");
        // WHY: queued jobs have a size claim without materialized execution
        // geometry. Derive the view window without allocating that execution.
        let count = u32::try_from(size.div_ceil(part_size))
            .context("part count exceeds supported range")?;
        let start = after.map_or(0, |value| u64::from(value) + 1);
        if start >= u64::from(count) {
            return Ok(Some(empty()));
        }
        let end = (start + limit as u64).min(u64::from(count));
        let mut parts = Vec::with_capacity((end - start) as usize);
        for index in start..end {
            let offset = index
                .checked_mul(part_size)
                .context("part offset overflow")?;
            let extent = (size - offset).min(part_size);
            parts.push(MetadataDownloadPart {
                index: u32::try_from(index)?,
                start: offset,
                end: offset + extent - 1,
                size_bytes: extent,
                present_bytes: 0,
                complete: false,
                corrupted: false,
            });
        }
        {
            let mut stmt = tx.prepare_cached(PARTS_SQL)?;
            let mut rows = stmt.query(params![id, i64::try_from(start)?, i64::try_from(end)?])?;
            while let Some(row) = rows.next()? {
                let index = crate::sql_value::unsigned::<u32>(row, 0)?;
                let part = &mut parts[usize::try_from(u64::from(index) - start)?];
                let present = crate::sql_value::unsigned::<u64>(row, 2)?;
                let complete = match row.get_ref(1)?.as_str()? {
                    "Missing" => false,
                    "Verified" => true,
                    _ => anyhow::bail!("invalid part state"),
                };
                ensure!(
                    present <= part.size_bytes && (!complete || present == part.size_bytes),
                    "invalid checkpointed part extent"
                );
                part.present_bytes = present;
                part.complete = complete;
                part.corrupted = row.get(3)?;
            }
        }
        tx.commit()?;
        let has_more = end < u64::from(count);
        let next_after = if has_more {
            parts.last().map(|part| part.index)
        } else {
            None
        };
        Ok(Some(MetadataDownloadPartPage {
            parts,
            next_after,
            has_more,
        }))
    }
}

#[cfg(test)]
mod tests;
