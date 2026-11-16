//! Compact job reads use the same retained registry; no history worker hydration.
use super::read_result::RetainedRead;
use super::*;
use crate::ed2k_transfer as transfer;
use emulebb_metadata::{DownloadJobRecord, JobId};

#[derive(Clone, Copy)]
pub(in crate::ed2k_transfer) enum JobRead {
    Exact(JobId),
    Query(emulebb_metadata::DownloadJobQuery),
    Counts,
    Execution(emulebb_metadata::JobToken),
    SelectExecution(emulebb_metadata::JobToken),
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
    Exact(Option<RetainedRead<DownloadJobRecord>>),
    Query(RetainedRead<emulebb_metadata::DownloadJobPage>),
    Counts(RetainedRead<emulebb_metadata::DownloadJobCounts>),
    Execution(Option<transfer::ResidentManifest>),
    Sources(RetainedRead<Vec<emulebb_metadata::MetadataDownloadSourceEntry>>),
    Endpoints(RetainedRead<Vec<emulebb_metadata::MetadataDownloadSourceEndpoint>>),
    Names(RetainedRead<Vec<emulebb_metadata::MetadataDownloadNameEntry>>),
    Page(RetainedRead<Vec<DownloadJobRecord>>),
    Ids(RetainedRead<Vec<JobId>>),
    Publish(Option<RetainedRead<Vec<emulebb_metadata::MetadataTransferPublishEntry>>>),
}

impl LocalMutationRegistry {
    pub(in crate::ed2k_transfer) fn submit_job_read(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        request: JobRead,
    ) -> Result<oneshot::Receiver<Result<JobReadResult>>> {
        let charge = match request {
            JobRead::Query(query) => {
                ensure!(
                    (1..=200).contains(&query.limit),
                    "invalid download job page size"
                );
                ensure!(
                    query.category_id.is_none_or(|id| id > 0),
                    "invalid download category ID"
                );
                2 * 1024 * 1024 + 4096
            }
            JobRead::Counts => 4096,
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
            JobRead::Execution(_) | JobRead::SelectExecution(_) => 6 * 1024 * 1024,
        };
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let (lease, mut resident) =
            if let JobRead::Execution(token) | JobRead::SelectExecution(token) = request {
                let (resident, lease) = self.residents.reserve_with(token.job_id, || {
                    Self::reserve_unit(&mut state, charge, false, false)
                })?;
                (lease, Some(resident))
            } else {
                (Self::reserve_unit(&mut state, charge, false, false)?, None)
            };
        let metadata = runtime.metadata.clone();
        let cache = Arc::clone(&runtime.manifest_cache);
        let content_locks = Arc::clone(&runtime.content_locks);
        let categories = Arc::clone(&runtime.category_assignment_gate);
        #[cfg(test)]
        let mut gate = state.publication_gate.take();
        let (sender, receipt) = oneshot::channel();
        Self::spawn_unit(&mut state, lease, move |capacity| {
            #[cfg(test)]
            if !matches!(request, JobRead::SelectExecution(_)) {
                if let Some((reached, release)) = gate.take() {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
            }
            // WHY: callers can retain pages after worker completion/reaping. Move
            // the existing charge with the actual backing, never with its sender.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match request {
                JobRead::Query(query) => metadata.download_job_page(query).map(|value| {
                    JobReadResult::Query(RetainedRead::new(value, capacity.take_result()))
                }),
                JobRead::Counts => metadata.download_job_counts().map(|value| {
                    JobReadResult::Counts(RetainedRead::new(value, capacity.take_result()))
                }),
                JobRead::Endpoints(token, after, limit) => metadata
                    .download_job_source_endpoints_after(token, after, limit)
                    .map(|value| {
                        JobReadResult::Endpoints(RetainedRead::new(value, capacity.take_result()))
                    }),
                JobRead::Sources(token, after, limit) => metadata
                    .download_job_sources_after(token, after, limit)
                    .map(|value| {
                        JobReadResult::Sources(RetainedRead::new(value, capacity.take_result()))
                    }),
                JobRead::Names(token, after, limit) => metadata
                    .download_job_names_after(token, after, limit)
                    .map(|value| {
                        JobReadResult::Names(RetainedRead::new(value, capacity.take_result()))
                    }),
                JobRead::Exact(id) => metadata.download_job(id).map(|value| {
                    JobReadResult::Exact(
                        value.map(|value| RetainedRead::new(value, capacity.take_result())),
                    )
                }),
                JobRead::Execution(token) | JobRead::SelectExecution(token) => {
                    let selected = matches!(request, JobRead::SelectExecution(_));
                    let observed = if selected {
                        Some(metadata.capture_download_availability()?)
                    } else {
                        None
                    };
                    let manifest =
                        transfer::transfer_sql::stream_execution_from_metadata(&metadata, token)?;
                    let manifest = manifest
                        .map(|manifest| {
                            resident
                                .take()
                                .expect("admitted resident")
                                .publish(manifest)
                        })
                        .transpose()?;
                    if !selected
                        || manifest
                            .as_ref()
                            .is_none_or(|manifest| manifest.pieces.is_empty())
                    {
                        return Ok(JobReadResult::Execution(manifest));
                    }
                    let manifest = manifest.expect("selected execution geometry");
                    #[cfg(test)]
                    if let Some((reached, release)) = gate.take() {
                        let _ = reached.send(());
                        let _ = release.recv();
                    }
                    let _category = categories.blocking_read();
                    let _content =
                        transfer::store::scoped_lock(&content_locks, manifest.file_hash.clone())
                            .blocking_lock_owned();
                    let mut cache = cache.blocking_lock();
                    if let Some(current) = cache
                        .get(&token.job_id)
                        .filter(|current| current.token == token)
                    {
                        // A current resident owns cache-only progress. A private
                        // SQL snapshot must never replace that live authority.
                        return Ok(JobReadResult::Execution(Some(current.clone())));
                    }
                    metadata
                        .publish_observed_download_execution(
                            token,
                            observed.as_ref().expect("selection observation"),
                            || {
                                cache.insert(token.job_id, manifest.clone());
                                Ok(JobReadResult::Execution(Some(manifest)))
                            },
                        )
                        .map_err(|error| {
                            if error.is::<emulebb_metadata::MetadataAvailabilityChanged>() {
                                LocalMutationError::Busy.into()
                            } else {
                                error
                            }
                        })
                }
                JobRead::Publish(after, limit) => metadata
                    .try_download_publish_entries_after(after.map(hex::encode).as_deref(), limit)
                    .map(|value| {
                        JobReadResult::Publish(
                            value.map(|value| RetainedRead::new(value, capacity.take_result())),
                        )
                    }),
                JobRead::Latest(hash) => {
                    metadata
                        .latest_download_job(&hex::encode(hash))
                        .map(|value| {
                            JobReadResult::Exact(
                                value.map(|value| RetainedRead::new(value, capacity.take_result())),
                            )
                        })
                }
                JobRead::Page(after, limit, runnable) => metadata
                    .download_jobs_after(after, limit, runnable)
                    .map(|value| {
                        JobReadResult::Page(RetainedRead::new(value, capacity.take_result()))
                    }),
                JobRead::Delivery(after, limit) => metadata
                    .pending_delivery_jobs_after(after, limit)
                    .map(|value| {
                        JobReadResult::Ids(RetainedRead::new(value, capacity.take_result()))
                    }),
                JobRead::Retirement(after, limit) => metadata
                    .pending_transfer_retirement_jobs_after(after, limit)
                    .map(|value| {
                        JobReadResult::Ids(RetainedRead::new(value, capacity.take_result()))
                    }),
                JobRead::Removed(after, limit) => metadata
                    .removed_download_jobs_after(after, limit)
                    .map(|value| {
                        JobReadResult::Ids(RetainedRead::new(value, capacity.take_result()))
                    }),
                JobRead::Deletion(after, limit) => metadata
                    .pending_transfer_deletion_jobs_after(after, limit)
                    .map(|value| {
                        JobReadResult::Ids(RetainedRead::new(value, capacity.take_result()))
                    }),
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
    /// Newest-ID native browsing. The existing owner performs SQLite work and
    /// the returned backing keeps its registry charge until final consumption.
    pub async fn query_download_jobs(
        &self,
        query: emulebb_metadata::DownloadJobQuery,
    ) -> Result<RetainedRead<emulebb_metadata::DownloadJobPage>> {
        let JobReadResult::Query(page) = self.read_job_metadata(JobRead::Query(query)).await?
        else {
            unreachable!()
        };
        Ok(page)
    }

    /// Fixed-size historical-completion counters, without scanning job rows.
    pub async fn download_job_counts(
        &self,
    ) -> Result<RetainedRead<emulebb_metadata::DownloadJobCounts>> {
        let JobReadResult::Counts(counts) = self.read_job_metadata(JobRead::Counts).await? else {
            unreachable!()
        };
        Ok(counts)
    }

    pub async fn download_source_endpoints_after(
        &self,
        token: emulebb_metadata::JobToken,
        after: i64,
        limit: usize,
    ) -> Result<RetainedRead<Vec<emulebb_metadata::MetadataDownloadSourceEndpoint>>> {
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
    ) -> Result<RetainedRead<Vec<emulebb_metadata::MetadataDownloadSourceEntry>>> {
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
    ) -> Result<RetainedRead<Vec<emulebb_metadata::MetadataDownloadNameEntry>>> {
        let JobReadResult::Names(page) = self
            .read_job_metadata(JobRead::Names(token, after, limit))
            .await?
        else {
            unreachable!()
        };
        Ok(page)
    }
    pub async fn download_job(&self, id: JobId) -> Result<Option<RetainedRead<DownloadJobRecord>>> {
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
    ) -> Result<RetainedRead<Vec<DownloadJobRecord>>> {
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
    ) -> Result<Option<RetainedRead<Vec<emulebb_metadata::MetadataTransferPublishEntry>>>> {
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
    ) -> Result<RetainedRead<Vec<JobId>>> {
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
    ) -> Result<RetainedRead<Vec<JobId>>> {
        let JobReadResult::Ids(ids) = self
            .read_job_metadata(JobRead::Delivery(after, limit))
            .await?
        else {
            unreachable!()
        };
        Ok(ids)
    }
}

#[cfg(test)]
mod tests;
