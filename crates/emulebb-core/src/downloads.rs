//! Canonical compact job browsing. Durable history never hydrates execution geometry.
use crate::EmulebbCore;
use anyhow::{Context, Result, ensure};
use emulebb_ed2k::ed2k_transfer::RetainedRead;
use emulebb_metadata::{DownloadIntent, DownloadJobQuery, DownloadJobRecord, JobId, JobToken};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DownloadState {
    Queued,
    WaitingMetadata,
    Downloading,
    Stopping,
    Stopped,
    Verifying,
    Delivering,
    Completed,
    Removing,
    Failed,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadSummary {
    #[serde(with = "crate::rest_model_serde::job_id")]
    pub id: JobId,
    pub hash: String,
    pub name: String,
    pub size_bytes: Option<u64>,
    pub progress: Option<f64>,
    #[serde(serialize_with = "serialize_intent")]
    pub intent: DownloadIntent,
    pub state: DownloadState,
    pub category: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub completed_at: Option<i64>,
}
/// Domain page. The HTTP owner encodes its scope-bound opaque continuation and
/// success envelope; numeric category IDs are never part of a download DTO.
#[derive(Debug)]
pub struct DownloadPage {
    pub downloads: Vec<DownloadSummary>,
    pub next_before: Option<JobId>,
    pub has_more: bool,
}
fn serialize_intent<S: serde::Serializer>(
    intent: &DownloadIntent,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(intent.as_str())
}
pub(crate) fn observed_state(
    job: &DownloadJobRecord,
    running: &[(JobToken, bool)],
    verifying: &[JobToken],
) -> DownloadState {
    if job.completed_at_s.is_some() {
        return DownloadState::Completed;
    }
    if job.removed_at_s.is_some() {
        return DownloadState::Removing;
    }
    if job.storage_failure.is_some() {
        return DownloadState::Failed;
    }
    let attempt = running
        .iter()
        .find(|(token, _)| token.job_id == job.token.job_id);
    if attempt.is_some_and(|(token, cancelled)| *cancelled || *token != job.token) {
        return DownloadState::Stopping;
    }
    if job.intent == DownloadIntent::Stopped {
        return DownloadState::Stopped;
    }
    if job.expected_size_bytes.is_none() {
        return DownloadState::WaitingMetadata;
    }
    if verifying.contains(&job.token) {
        return DownloadState::Verifying;
    }
    if job.payload_verified {
        return DownloadState::Delivering;
    }
    if attempt.is_some() {
        DownloadState::Downloading
    } else {
        DownloadState::Queued
    }
}
impl EmulebbCore {
    /// Read a byte-bounded newest-ID page directly from the canonical provider.
    /// Only the bounded live cohort is consulted for execution overlays.
    pub async fn download_page(
        &self,
        query: DownloadJobQuery,
    ) -> Result<RetainedRead<DownloadPage>> {
        self.persistence_owner.check_coherent_state()?;
        let _fence = self.ed2k_transfers.lock_category_publication().await;
        let page = self.ed2k_transfers.query_download_jobs(query).await?;
        let verifying = self.ed2k_transfers.verifying_downloads().await;
        let running = self.download_attempts.snapshot();
        let state = self.state.lock().await;
        self.persistence_owner.check_coherent_state()?;
        let mut bytes = 4096usize
            .checked_add(
                page.jobs
                    .len()
                    .checked_mul(std::mem::size_of::<DownloadSummary>())
                    .context("download page projection size overflow")?,
            )
            .context("download page projection size overflow")?;
        for job in &page.jobs {
            let category = job
                .category_id
                .map(|id| {
                    state
                        .categories
                        .get(&id)
                        .context("job category is missing from coherent Core state")
                })
                .transpose()?;
            if let Some(category) = category {
                ensure!(
                    category.name.len() <= 64,
                    "category name exceeds canonical bound"
                );
            }
            bytes = bytes
                .checked_add(job.file_hash.capacity())
                .and_then(|bytes| bytes.checked_add(job.display_name.capacity()))
                .and_then(|bytes| {
                    bytes.checked_add(category.map_or(0, |category| category.name.len()))
                })
                .context("download page projection size overflow")?;
        }
        page.try_project(bytes, |page| {
            let mut downloads = Vec::with_capacity(page.jobs.len());
            for job in page.jobs {
                let observed = observed_state(&job, &running, &verifying);
                let progress = job.progress();
                downloads.push(DownloadSummary {
                    id: job.token.job_id,
                    hash: job.file_hash,
                    name: job.display_name,
                    size_bytes: job.expected_size_bytes,
                    progress,
                    intent: job.intent,
                    state: observed,
                    category: job
                        .category_id
                        .and_then(|id| state.categories.get(&id))
                        .map(|category| category.name.clone()),
                    created_at: job.created_at_s,
                    updated_at: job.updated_at_s,
                    completed_at: job.completed_at_s,
                });
            }
            Ok(DownloadPage {
                downloads,
                next_before: page.next_before,
                has_more: page.has_more,
            })
        })
    }
}

#[cfg(test)]
mod tests;

/// A bounded domain page; HTTP owns its opaque cursor and envelope.
#[derive(Debug)]
pub struct DownloadSourcePage {
    pub sources: Vec<crate::DownloadSource>,
    pub next_after: Option<i64>,
    pub has_more: bool,
}

impl EmulebbCore {
    async fn source_projection_job(&self, id: JobId) -> Result<Option<(JobToken, String, u32)>> {
        self.persistence_owner.check_coherent_state()?;
        let Some(job) = self.ed2k_transfers.download_job(id).await? else {
            return Ok(None);
        };
        if job.removed_at_s.is_some() {
            return Ok(None);
        }
        let parts = job.expected_size_bytes.map_or(0, |size| {
            size.div_ceil(emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE)
        });
        Ok(Some((
            job.token,
            job.file_hash.clone(),
            u32::try_from(parts)?,
        )))
    }

    fn source_projection_row(
        &self,
        token: JobToken,
        hash: &str,
        parts: u32,
        row: emulebb_metadata::MetadataDownloadSourceEntry,
        live_text_bytes: &mut usize,
    ) -> Result<crate::DownloadSource> {
        let banned = self.ed2k_transfers.ban_store().is_banned(
            crate::parse_ban_ip(&row.source.ip),
            crate::parse_ban_hash(row.source.user_hash.as_deref()).as_ref(),
        );
        let mut source = crate::download_source_from_record(hash, row, banned, parts);
        crate::apply_download_source_stats(
            &self.ed2k_transfers,
            token,
            &mut source,
            live_text_bytes,
        )?;
        Ok(source)
    }

    /// Browse source diagnostics without activating an execution or fetching any
    /// part geometry. Even a byte-short page retains its exact row frontier.
    pub async fn download_sources_page(
        &self,
        id: JobId,
        after: i64,
        limit: usize,
    ) -> Result<Option<RetainedRead<DownloadSourcePage>>> {
        ensure!(
            (1..=200).contains(&limit) && after >= 0,
            "invalid source page"
        );
        let Some((token, hash, parts)) = self.source_projection_job(id).await? else {
            return Ok(None);
        };
        let page = self
            .ed2k_transfers
            .download_sources_after(token, after, limit)
            .await?;
        let last = page.last().map(|row| row.id);
        let has_more = if let Some(last) = last {
            !self
                .ed2k_transfers
                .download_source_endpoints_after(token, last, 1)
                .await?
                .is_empty()
        } else {
            false
        };
        let projected = page.try_project(2 * 1024 * 1024, |rows| {
            let mut sources = Vec::with_capacity(rows.len());
            let mut live_text_bytes = 64 * 1024;
            for row in rows {
                sources.push(self.source_projection_row(
                    token,
                    &hash,
                    parts,
                    row,
                    &mut live_text_bytes,
                )?);
            }
            Ok(DownloadSourcePage {
                sources,
                next_after: if has_more { last } else { None },
                has_more,
            })
        })?;
        Ok(Some(projected))
    }

    /// Select a source through its native identity index and shared name window.
    pub async fn download_source(
        &self,
        id: JobId,
        client_id: &str,
    ) -> Result<Option<RetainedRead<crate::DownloadSource>>> {
        crate::validate_source_client_id(client_id)?;
        let Some((token, hash, parts)) = self.source_projection_job(id).await? else {
            return Ok(None);
        };
        let selector = if client_id.len() == 32 && !client_id.contains(':') {
            let hash = hex::decode(client_id)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid source hash"))?;
            emulebb_metadata::MetadataDownloadSourceSelector::UserHash(hash)
        } else {
            let (ip, port) = client_id
                .rsplit_once(':')
                .context("invalid source endpoint")?;
            let Ok(ip) = ip.parse::<std::net::Ipv4Addr>() else {
                return Ok(None);
            };
            emulebb_metadata::MetadataDownloadSourceSelector::Endpoint(ip, port.parse()?)
        };
        let source = self.ed2k_transfers.download_source(token, selector).await?;
        if source.is_none() {
            return Ok(None);
        }
        Ok(Some(source.try_project(2 * 1024 * 1024, |source| {
            let mut live_text_bytes = 64 * 1024;
            self.source_projection_row(
                token,
                &hash,
                parts,
                source.expect("checked source"),
                &mut live_text_bytes,
            )
        })?))
    }
}

#[derive(Debug)]
pub struct DownloadCommentPage {
    pub comments: Vec<crate::TransferComment>,
    pub next_after: Option<i64>,
    pub has_more: bool,
}

impl EmulebbCore {
    /// Seek the comment-only index and preserve its bounded continuation.
    /// Neither source-name windows nor execution geometry are loaded.
    pub async fn download_comments_page(
        &self,
        id: JobId,
        after: i64,
        limit: usize,
    ) -> Result<Option<RetainedRead<DownloadCommentPage>>> {
        ensure!(
            (1..=200).contains(&limit) && after >= 0,
            "invalid comment page"
        );
        self.persistence_owner.check_coherent_state()?;
        let Some(job) = self.ed2k_transfers.download_job(id).await? else {
            return Ok(None);
        };
        if job.removed_at_s.is_some() {
            return Ok(None);
        }
        let token = job.token;
        let page = self
            .ed2k_transfers
            .download_comments_after(token, after, limit)
            .await?;
        let mut bytes =
            4096usize + page.comments.len() * std::mem::size_of::<crate::TransferComment>();
        let mut frontier = None;
        let mut consumed = 0;
        for row in &page.comments {
            let charge =
                row.comment.capacity() + row.ip.capacity() * 2 + 64 + job.display_name.len();
            if bytes + charge > 1024 * 1024 {
                break;
            }
            bytes += charge;
            frontier = Some(row.id);
            consumed += 1;
        }
        ensure!(
            page.comments.is_empty() || consumed > 0,
            "comment exceeds projection allowance"
        );
        let has_more = consumed < page.comments.len() || page.has_more;
        let projected = page.try_project(bytes, |page| {
            let mut comments = Vec::with_capacity(consumed);
            for row in page.comments.into_iter().take(consumed) {
                let endpoint = format!("{}:{}", row.ip, row.tcp_port);
                comments.push(crate::TransferComment {
                    source: row.user_hash.unwrap_or_else(|| endpoint.clone()),
                    user_name: Some(endpoint),
                    file_name: job.display_name.clone(),
                    comment: row.comment,
                    rating: row.rating,
                });
            }
            Ok(DownloadCommentPage {
                comments,
                next_after: if has_more { frontier } else { None },
                has_more,
            })
        })?;
        Ok(Some(projected))
    }
}
