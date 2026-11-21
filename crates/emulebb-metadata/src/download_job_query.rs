//! Native newest-ID browsing and the fixed download dashboard summary.
use anyhow::{Result, ensure};
use rusqlite::params;

use crate::download_job_store::{JOB_COLUMNS, JOB_PAGE_BYTES, job_row_bytes, row_job};
use crate::{DownloadJobRecord, JobId, MetadataStore};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DownloadJobView {
    #[default]
    Unfinished,
    Completed,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadJobQuery {
    pub view: DownloadJobView,
    /// Resolved internal category ID; None includes every category.
    pub category_id: Option<i64>,
    /// Exclusive numeric boundary in descending order.
    pub before: Option<JobId>,
    pub limit: usize,
}
impl Default for DownloadJobQuery {
    fn default() -> Self {
        Self {
            view: DownloadJobView::Unfinished,
            category_id: None,
            before: None,
            limit: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadJobPage {
    pub jobs: Vec<DownloadJobRecord>,
    pub has_more: bool,
    /// Last returned ID only when more matching rows existed in this read.
    pub next_before: Option<JobId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadJobCounts {
    pub unfinished: u64,
    pub completed: u64,
}
const COUNTS_SQL: &str = "SELECT unfinished,completed FROM download_job_counts WHERE id=1";

fn page_sql(query: &DownloadJobQuery) -> String {
    let (index, view) = match (query.category_id.is_some(), query.view) {
        (false, DownloadJobView::All) => ("download_jobs_visible_page_idx", ""),
        (false, DownloadJobView::Unfinished) => (
            "download_jobs_unfinished_page_idx",
            "AND j.terminal_completed_at_s IS NULL",
        ),
        (false, DownloadJobView::Completed) => (
            "download_jobs_completed_page_idx",
            "AND j.terminal_completed_at_s IS NOT NULL",
        ),
        (true, DownloadJobView::All) => ("download_jobs_category_page_idx", ""),
        (true, DownloadJobView::Unfinished) => (
            "download_jobs_category_unfinished_page_idx",
            "AND j.terminal_completed_at_s IS NULL",
        ),
        (true, DownloadJobView::Completed) => (
            "download_jobs_category_completed_page_idx",
            "AND j.terminal_completed_at_s IS NOT NULL",
        ),
    };
    let category = if query.category_id.is_some() {
        "AND j.category_id=?2"
    } else {
        ""
    };
    let bound = if query.before.is_some() { "<" } else { "<=" };
    format!(
        "SELECT {JOB_COLUMNS} FROM download_jobs j INDEXED BY {index}
        JOIN known_files k ON k.id=j.known_file_id
        LEFT JOIN local_paths p ON p.id=j.selected_temp_path_id
        LEFT JOIN local_paths storage ON storage.id=j.storage_path_id
        WHERE j.removed_at_s IS NULL {view} {category} AND j.id{bound}?1
        ORDER BY j.id DESC LIMIT ?3"
    )
}

impl MetadataStore {
    /// Count queued work without scanning retained jobs. Exclusions are the
    /// sorted, unique runtime attempt/verification cohort, including draining owners.
    /// One SQLite read transaction keeps the summary and exact lookups coherent.
    pub fn waiting_download_count(&self, selected: &[JobId]) -> Result<u64> {
        ensure!(
            selected.windows(2).all(|pair| pair[0] < pair[1]),
            "selected download IDs must be sorted and unique"
        );
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut waiting: u64 = tx.query_row(
            "SELECT awaiting_execution FROM download_job_counts WHERE id=1",
            [],
            |row| crate::sql_value::unsigned(row, 0),
        )?;
        let mut stmt = tx.prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM download_jobs WHERE id=?1
             AND removed_at_s IS NULL AND terminal_completed_at_s IS NULL
             AND delete_requested_at_s IS NULL AND intent='started'
             AND storage_failure_code IS NULL AND expected_size_bytes IS NOT NULL
             AND NOT(completed AND NOT final_rehash_pending))",
        )?;
        // WHY: eligibility can change while an execution drains. Subtract only
        // owners that still belong to the counter, rather than the cohort size.
        for id in selected {
            if stmt.query_row([id], |row| row.get::<_, bool>(0))? {
                waiting = waiting
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("incoherent waiting download count"))?;
            }
        }
        Ok(waiting)
    }

    /// One coherent, byte-bounded read. Subsequent requests are live pages:
    /// inserts above the boundary wait for a fresh traversal; removal, category,
    /// or completion changes may add/remove matches below it. IDs never repeat.
    pub fn download_job_page(&self, query: DownloadJobQuery) -> Result<DownloadJobPage> {
        ensure!(
            (1..=200).contains(&query.limit),
            "invalid download job page size"
        );
        ensure!(
            query.category_id.is_none_or(|id| id > 0),
            "invalid download category ID"
        );
        let conn = self.connection()?;
        let mut stmt = conn.prepare_cached(&page_sql(&query))?;
        let mut rows = stmt.query(params![
            query.before.map_or(i64::MAX, JobId::get),
            query.category_id,
            i64::try_from(query.limit + 1)?
        ])?;
        let mut jobs = Vec::new();
        let mut bytes = 0;
        let mut has_more = false;
        while let Some(row) = rows.next()? {
            // WHY: lookahead establishes existence without hydrating another DTO,
            // including when the byte budget ended before the requested limit.
            if jobs.len() == query.limit {
                has_more = true;
                break;
            }
            let charge = job_row_bytes(row)?;
            if bytes + charge > JOB_PAGE_BYTES {
                ensure!(!jobs.is_empty(), "download row exceeds page allowance");
                has_more = true;
                break;
            }
            bytes += charge;
            jobs.push(row_job(row)?);
        }
        let next_before = if has_more {
            jobs.last().map(|job| job.token.job_id)
        } else {
            None
        };
        Ok(DownloadJobPage {
            jobs,
            has_more,
            next_before,
        })
    }

    /// Fixed-size unremoved historical-completion counts, read atomically from
    /// the single persistence-maintained summary rather than scanning jobs.
    pub fn download_job_counts(&self) -> Result<DownloadJobCounts> {
        Ok(self.connection()?.query_row(COUNTS_SQL, [], |row| {
            Ok(DownloadJobCounts {
                unfinished: crate::sql_value::unsigned(row, 0)?,
                completed: crate::sql_value::unsigned(row, 1)?,
            })
        })?)
    }
}

#[cfg(test)]
mod tests;
