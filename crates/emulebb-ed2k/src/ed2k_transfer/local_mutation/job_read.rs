//! Compact job reads use the same retained registry; no history worker hydration.
use super::*;
use crate::ed2k_transfer as transfer;
use emulebb_metadata::{DownloadJobRecord, JobId};

#[derive(Clone, Copy)]
pub(in crate::ed2k_transfer) enum JobRead {
    Exact(JobId),
    Execution(emulebb_metadata::JobToken),
    Sources(emulebb_metadata::JobToken, i64, usize),
    Endpoints(emulebb_metadata::JobToken, i64, usize),
    Names(emulebb_metadata::JobToken, i64, usize),
    Latest([u8; 16]),
    Publish(Option<[u8; 16]>, usize),
    Page(Option<JobId>, usize, bool),
    Delivery(Option<JobId>, usize),
    Retirement(Option<JobId>, usize),
    Deletion(Option<JobId>, usize),
    Removed(Option<JobId>, usize),
}
pub(in crate::ed2k_transfer) enum JobReadResult {
    Exact(Option<DownloadJobRecord>),
    Execution(Option<transfer::Ed2kResumeManifest>),
    Sources(Vec<emulebb_metadata::MetadataDownloadSourceEntry>),
    Endpoints(Vec<emulebb_metadata::MetadataDownloadSourceEndpoint>),
    Names(Vec<emulebb_metadata::MetadataDownloadNameEntry>),
    Page(Vec<DownloadJobRecord>),
    Ids(Vec<JobId>),
    Publish(Option<Vec<emulebb_metadata::MetadataTransferPublishEntry>>),
}

impl LocalMutationRegistry {
    pub(in crate::ed2k_transfer) fn submit_job_read(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        request: JobRead,
    ) -> Result<oneshot::Receiver<Result<JobReadResult>>> {
        let charge = match request {
            JobRead::Endpoints(_, after, limit) => {
                ensure!(
                    after >= 0 && (1..=256).contains(&limit),
                    "invalid source endpoint page"
                );
                32 * 1024
            }
            JobRead::Sources(_, after, limit) | JobRead::Names(_, after, limit) => {
                ensure!(
                    after >= 0 && (1..=256).contains(&limit),
                    "invalid peer diagnostic page"
                );
                1024 * 1024 + 4096
            }
            JobRead::Page(_, limit, _)
            | JobRead::Delivery(_, limit)
            | JobRead::Retirement(_, limit)
            | JobRead::Deletion(_, limit)
            | JobRead::Removed(_, limit) => {
                ensure!((1..=256).contains(&limit), "invalid job read page size");
                if matches!(request, JobRead::Page(..)) {
                    2 * 1024 * 1024 + 4096
                } else {
                    8192
                }
            }
            JobRead::Publish(_, limit) => {
                ensure!((1..=256).contains(&limit), "invalid publication page");
                2 * 1024 * 1024 + 4096
            }
            JobRead::Latest(_) => 1024 * 1024,
            JobRead::Exact(_) => 1024 * 1024,
            JobRead::Execution(_) => 6 * 1024 * 1024,
        };
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let lease = Self::reserve_unit(&mut state, charge, false, false)?;
        let metadata = runtime.metadata.clone();
        let (sender, receipt) = oneshot::channel();
        Self::spawn_unit(&mut state, lease, move |_capacity| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match request {
                JobRead::Endpoints(token, after, limit) => metadata
                    .download_job_source_endpoints_after(token, after, limit)
                    .map(JobReadResult::Endpoints),
                JobRead::Sources(token, after, limit) => metadata
                    .download_job_sources_after(token, after, limit)
                    .map(JobReadResult::Sources),
                JobRead::Names(token, after, limit) => metadata
                    .download_job_names_after(token, after, limit)
                    .map(JobReadResult::Names),
                JobRead::Exact(id) => metadata.download_job(id).map(JobReadResult::Exact),
                JobRead::Execution(token) => {
                    transfer::transfer_sql::stream_execution_from_metadata(&metadata, token)
                        .map(JobReadResult::Execution)
                }
                JobRead::Publish(after, limit) => metadata
                    .try_download_publish_entries_after(after.map(hex::encode).as_deref(), limit)
                    .map(JobReadResult::Publish),
                JobRead::Latest(hash) => metadata
                    .latest_download_job(&hex::encode(hash))
                    .map(JobReadResult::Exact),
                JobRead::Page(after, limit, runnable) => metadata
                    .download_jobs_after(after, limit, runnable)
                    .map(JobReadResult::Page),
                JobRead::Delivery(after, limit) => metadata
                    .pending_delivery_jobs_after(after, limit)
                    .map(JobReadResult::Ids),
                JobRead::Retirement(after, limit) => metadata
                    .pending_transfer_retirement_jobs_after(after, limit)
                    .map(JobReadResult::Ids),
                JobRead::Removed(after, limit) => metadata
                    .removed_download_jobs_after(after, limit)
                    .map(JobReadResult::Ids),
                JobRead::Deletion(after, limit) => metadata
                    .pending_transfer_deletion_jobs_after(after, limit)
                    .map(JobReadResult::Ids),
            }));
            let (result, outcome) = match result {
                Ok(result) => (result, 0),
                Err(_) => (Err(LocalMutationError::Unknown.into()), 2),
            };
            let _ = sender.send(result);
            outcome
        });
        Ok(receipt)
    }
}
impl transfer::Ed2kTransferRuntime {
    /// Caller must release job/content guards before retrying Busy. No read
    /// waits for registry capacity while a writer could need its held guard.
    pub(in crate::ed2k_transfer) async fn read_job_metadata(
        &self,
        request: JobRead,
    ) -> Result<JobReadResult> {
        self.local_mutations
            .submit_job_read(self, request)?
            .await
            .map_err(|_| LocalMutationError::Unknown)?
    }
    pub async fn download_source_endpoints_after(
        &self,
        token: emulebb_metadata::JobToken,
        after: i64,
        limit: usize,
    ) -> Result<Vec<emulebb_metadata::MetadataDownloadSourceEndpoint>> {
        let JobReadResult::Endpoints(page) = self
            .read_job_metadata(JobRead::Endpoints(token, after, limit))
            .await?
        else {
            unreachable!()
        };
        Ok(page)
    }
    pub async fn download_sources_after(
        &self,
        token: emulebb_metadata::JobToken,
        after: i64,
        limit: usize,
    ) -> Result<Vec<emulebb_metadata::MetadataDownloadSourceEntry>> {
        let JobReadResult::Sources(page) = self
            .read_job_metadata(JobRead::Sources(token, after, limit))
            .await?
        else {
            unreachable!()
        };
        Ok(page)
    }
    pub async fn download_names_after(
        &self,
        token: emulebb_metadata::JobToken,
        after: i64,
        limit: usize,
    ) -> Result<Vec<emulebb_metadata::MetadataDownloadNameEntry>> {
        let JobReadResult::Names(page) = self
            .read_job_metadata(JobRead::Names(token, after, limit))
            .await?
        else {
            unreachable!()
        };
        Ok(page)
    }
    pub async fn download_job(&self, id: JobId) -> Result<Option<DownloadJobRecord>> {
        let JobReadResult::Exact(job) = self.read_job_metadata(JobRead::Exact(id)).await? else {
            unreachable!()
        };
        Ok(job)
    }
    pub async fn download_jobs_after(
        &self,
        after: Option<JobId>,
        limit: usize,
        runnable_only: bool,
    ) -> Result<Vec<DownloadJobRecord>> {
        let JobReadResult::Page(page) = self
            .read_job_metadata(JobRead::Page(after, limit, runnable_only))
            .await?
        else {
            unreachable!()
        };
        Ok(page)
    }
    /// Compact content publisher page. Final outgoing admission still uses the
    /// shared eligibility fence; this read cannot bypass packet-time checks.
    pub async fn publish_entries_after(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Option<Vec<emulebb_metadata::MetadataTransferPublishEntry>>> {
        let after = after
            .map(str::parse::<emulebb_kad_proto::Ed2kHash>)
            .transpose()?
            .map(|hash| hash.0);
        let JobReadResult::Publish(page) = self
            .read_job_metadata(JobRead::Publish(after, limit))
            .await?
        else {
            unreachable!()
        };
        Ok(page)
    }

    pub async fn pending_output_deletion_jobs_after(
        &self,
        after: Option<JobId>,
        limit: usize,
    ) -> Result<Vec<JobId>> {
        let JobReadResult::Ids(ids) = self
            .read_job_metadata(JobRead::Deletion(after, limit))
            .await?
        else {
            unreachable!()
        };
        Ok(ids)
    }

    pub async fn pending_delivery_jobs_after(
        &self,
        after: Option<JobId>,
        limit: usize,
    ) -> Result<Vec<JobId>> {
        let JobReadResult::Ids(ids) = self
            .read_job_metadata(JobRead::Delivery(after, limit))
            .await?
        else {
            unreachable!()
        };
        Ok(ids)
    }
}
