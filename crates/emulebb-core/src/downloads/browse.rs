//! Thin on-demand detail and part projections; HTTP owns their envelopes/cursors.
use super::*;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadDetail {
    #[serde(flatten)]
    pub summary: DownloadSummary,
    pub payload_verified: bool,
    pub delivery: DownloadDelivery,
    pub failure: Option<DownloadFailure>,
}

#[cfg(test)]
mod tests;

#[derive(Debug, Serialize)]
pub struct DownloadDelivery {
    pub state: DownloadDeliveryState,
    pub path: Option<String>,
    pub ownership: DownloadDeliveryOwnership,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DownloadDeliveryState {
    Pending,
    Delivered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DownloadDeliveryOwnership {
    None,
    Owned,
    Unowned,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadFailure {
    pub code: String,
    pub message: String,
    pub failed_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadPart {
    pub index: u32,
    /// Inclusive byte offsets.
    pub start: u64,
    pub end: u64,
    pub size_bytes: u64,
    /// Checkpointed internal presence, independent of successful verification.
    pub present_bytes: u64,
    pub complete: bool,
    pub corrupted: bool,
}

#[derive(Debug)]
pub struct DownloadPartPage {
    pub parts: Vec<DownloadPart>,
    pub next_after: Option<u32>,
    pub has_more: bool,
}

impl EmulebbCore {
    pub async fn download_detail(&self, id: JobId) -> Result<Option<RetainedRead<DownloadDetail>>> {
        self.persistence_owner.check_coherent_state()?;
        let _fence = self.ed2k_transfers.lock_category_publication().await;
        let Some(detail) = self.ed2k_transfers.download_detail(id).await? else {
            return Ok(None);
        };
        let mut verifying = self.ed2k_transfers.verifying_downloads().await;
        verifying.extend(self.download_attempts.verifications());
        let running = self.download_attempts.snapshot();
        let state = self.state.lock().await;
        self.persistence_owner.check_coherent_state()?;
        let category = detail
            .job
            .category_id
            .map(|id| {
                state
                    .categories
                    .get(&id)
                    .context("job category is missing from coherent Core state")
            })
            .transpose()?;
        let bytes = 4096
            + detail.job.display_name.capacity()
            + detail.job.file_hash.capacity()
            + category.map_or(0, |value| value.name.len())
            + detail
                .delivered_path
                .as_ref()
                .map_or(0, |path| path.as_os_str().len() * 4)
            + detail.job.storage_failure.as_ref().map_or(0, |failure| {
                2 * (failure.code().len() + failure.message().len())
            });
        Ok(Some(detail.try_project(bytes, |detail| {
            let failure = detail
                .job
                .storage_failure
                .as_ref()
                .map(|value| DownloadFailure {
                    code: value.code().to_owned(),
                    message: value.message().to_owned(),
                    failed_at: value.failed_at_s(),
                });
            let ownership = match detail.ownership {
                emulebb_metadata::MetadataTransferDeliveryOwnership::None => {
                    DownloadDeliveryOwnership::None
                }
                emulebb_metadata::MetadataTransferDeliveryOwnership::Owned => {
                    DownloadDeliveryOwnership::Owned
                }
                emulebb_metadata::MetadataTransferDeliveryOwnership::Unowned => {
                    DownloadDeliveryOwnership::Unowned
                }
            };
            let delivery_state = match detail.job.delivery_state {
                emulebb_metadata::MetadataTransferDeliveryState::Pending => {
                    DownloadDeliveryState::Pending
                }
                emulebb_metadata::MetadataTransferDeliveryState::Delivered => {
                    DownloadDeliveryState::Delivered
                }
            };
            Ok(DownloadDetail {
                payload_verified: detail.job.payload_verified,
                summary: summary_from_job(
                    detail.job,
                    category.map(|value| value.name.as_str()),
                    &running,
                    &verifying,
                ),
                delivery: DownloadDelivery {
                    state: delivery_state,
                    path: detail
                        .delivered_path
                        .as_ref()
                        .map(emulebb_ed2k::long_path::normal_path_display),
                    ownership,
                },
                failure,
            })
        })?))
    }

    pub async fn download_parts_page(
        &self,
        id: JobId,
        after: Option<u32>,
        limit: usize,
    ) -> Result<Option<RetainedRead<DownloadPartPage>>> {
        ensure!((1..=200).contains(&limit), "invalid part page size");
        self.persistence_owner.check_coherent_state()?;
        let Some(page) = self
            .ed2k_transfers
            .download_parts_after(id, after, limit)
            .await?
        else {
            return Ok(None);
        };
        let bytes = 1024 + page.parts.len() * std::mem::size_of::<DownloadPart>();
        Ok(Some(page.try_project(bytes, |page| {
            Ok(DownloadPartPage {
                parts: page
                    .parts
                    .into_iter()
                    .map(|part| DownloadPart {
                        index: part.index,
                        start: part.start,
                        end: part.end,
                        size_bytes: part.size_bytes,
                        present_bytes: part.present_bytes,
                        complete: part.complete,
                        corrupted: part.corrupted,
                    })
                    .collect(),
                next_after: page.next_after,
                has_more: page.has_more,
            })
        })?))
    }
}
