//! Retained metadata reads, with execution hydration admitted explicitly.
use super::read_result::RetainedRead;
use super::*;
use crate::ed2k_transfer as transfer;
use anyhow::Context;
use emulebb_metadata::{DownloadJobRecord, JobId};

#[derive(Clone)]
pub(in crate::ed2k_transfer) enum JobRead {
    Exact(JobId),
    Detail(JobId),
    Parts(JobId, Option<u32>, usize),
    VerifiedParts(emulebb_metadata::JobToken),
    Query(emulebb_metadata::DownloadJobQuery),
    Counts,
    Waiting(Vec<JobId>),
    UploadFile([u8; 16]),
    LibraryStatistics([u8; 16]),
    LibraryQuery(emulebb_metadata::LibraryFileQuery),
    LibraryFile([u8; 16]),
    LibraryLocations([u8; 16], i64, usize),
    Scheduling(
        Arc<transfer::Ed2kTransferRuntime>,
        emulebb_metadata::JobToken,
        Option<u64>,
    ),
    TransferCounts,
    Execution(emulebb_metadata::JobToken),
    SelectExecution(emulebb_metadata::JobToken),
    Sources(emulebb_metadata::JobToken, i64, usize),
    SourceAvailability(emulebb_metadata::MetadataDownloadAvailabilityQuery),
    SourceScarcity(emulebb_metadata::MetadataDownloadScarcityQuery),
    LiveSourceScarcity(
        emulebb_metadata::MetadataDownloadScarcityQuery,
        u64,
        Arc<Vec<bool>>,
        std::time::Instant,
    ),
    Comments(emulebb_metadata::JobToken, i64, usize),
    Source(
        emulebb_metadata::JobToken,
        emulebb_metadata::MetadataDownloadSourceSelector,
    ),
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
    Detail(Option<RetainedRead<emulebb_metadata::MetadataDownloadDetail>>),
    Parts(Option<RetainedRead<emulebb_metadata::MetadataDownloadPartPage>>),
    VerifiedParts(Option<RetainedRead<emulebb_metadata::MetadataDownloadVerifiedParts>>),
    Query(RetainedRead<emulebb_metadata::DownloadJobPage>),
    Counts(RetainedRead<emulebb_metadata::DownloadJobCounts>),
    Waiting(RetainedRead<u64>),
    UploadFile(Option<RetainedRead<emulebb_metadata::MetadataUploadFileSummary>>),
    LibraryStatistics(Option<RetainedRead<emulebb_metadata::MetadataFileUploadStatistics>>),
    LibraryQuery(RetainedRead<emulebb_metadata::MetadataLibraryFilePage>),
    LibraryFile(Option<RetainedRead<emulebb_metadata::MetadataLibraryFile>>),
    LibraryLocations(Option<RetainedRead<emulebb_metadata::MetadataLibraryLocationPage>>),
    Scheduling(Option<transfer::DownloadSchedulingState>),
    TransferCounts(RetainedRead<emulebb_metadata::MetadataTransferCounts>),
    Execution(Option<transfer::ResidentManifest>),
    Sources(RetainedRead<Vec<emulebb_metadata::MetadataDownloadSourceEntry>>),
    SourceAvailability(RetainedRead<Vec<emulebb_metadata::MetadataDownloadSourceAvailability>>),
    SourceScarcity(bool),
    Comments(RetainedRead<emulebb_metadata::MetadataDownloadCommentPage>),
    Source(RetainedRead<Option<emulebb_metadata::MetadataDownloadSourceEntry>>),
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
            JobRead::Counts | JobRead::TransferCounts => 4096,
            JobRead::UploadFile(_) => 256 * 1024,
            JobRead::LibraryStatistics(_) => 64 * 1024,
            JobRead::LibraryFile(_) => 2 * 1024 * 1024,
            JobRead::LibraryQuery(ref query) => {
                ensure!(
                    (1..=200).contains(&query.limit)
                        && query.root_id.is_none_or(|id| id > 0)
                        && query.tag.as_ref().is_none_or(|name| name.capacity() <= 64
                            && emulebb_metadata::valid_category_name(name))
                        && query
                            .search
                            .as_ref()
                            .is_none_or(|value| value.capacity() <= 65_536),
                    "invalid library query"
                );
                2 * 1024 * 1024
            }
            JobRead::LibraryLocations(_, after, limit) => {
                ensure!(
                    after >= 0 && (1..=200).contains(&limit),
                    "invalid library location page"
                );
                emulebb_metadata::LIBRARY_READ_MAX_BYTES
            }
            JobRead::Waiting(ref ids) => ids
                .capacity()
                .checked_mul(std::mem::size_of::<JobId>())
                .and_then(|bytes| bytes.checked_add(4096))
                .context("waiting download request size overflow")?,
            JobRead::Scheduling(..) => transfer::download_scheduling::WORK_BYTES,
            JobRead::VerifiedParts(_)
            | JobRead::SourceScarcity(_)
            | JobRead::LiveSourceScarcity(..) => 128 * 1024,
            JobRead::Parts(_, _, limit) => {
                ensure!((1..=256).contains(&limit), "invalid part page size");
                32 * 1024
            }
            JobRead::Source(..) => 1024 * 1024 + 4096,
            JobRead::SourceAvailability(query) => {
                ensure!(
                    (1..=256).contains(&query.limit),
                    "invalid availability page size"
                );
                1024 * 1024 + 4096
            }
            JobRead::Endpoints(_, after, limit) => {
                ensure!(
                    after >= 0 && (1..=256).contains(&limit),
                    "invalid source endpoint page"
                );
                32 * 1024
            }
            JobRead::Sources(_, after, limit)
            | JobRead::Names(_, after, limit)
            | JobRead::Comments(_, after, limit) => {
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
            JobRead::Exact(_) | JobRead::Detail(_) => 1024 * 1024,
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
        let accounting = runtime.parked_credit_flush_parts();
        let cache = Arc::clone(&runtime.manifest_cache);
        let content_locks = Arc::clone(&runtime.content_locks);
        let categories = Arc::clone(&runtime.category_assignment_gate);
        #[cfg(test)]
        let mut gate = state.publication_gate.take();
        let (sender, receipt) = oneshot::channel();
        Self::spawn_unit_reply(&mut state, lease, sender, move |capacity| {
            #[cfg(test)]
            if !matches!(request, JobRead::SelectExecution(_))
                && let Some((reached, release)) = gate.take()
            {
                let _ = reached.send(());
                let _ = release.recv();
            }
            // WHY: callers can retain pages after worker completion/reaping. Move
            // the existing charge with the actual backing, never with its sender.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match request {
                JobRead::Query(query) => metadata.download_job_page(query).map(|value| {
                    JobReadResult::Query(RetainedRead::new(value, capacity.take_result()))
                }),
                JobRead::Scheduling(runtime, token, expected) => runtime
                    .classify_or_yield_download(token, expected)
                    .map(JobReadResult::Scheduling),
                JobRead::Counts => metadata.download_job_counts().map(|value| {
                    JobReadResult::Counts(RetainedRead::new(value, capacity.take_result()))
                }),
                JobRead::Waiting(ids) => metadata.waiting_download_count(&ids).map(|value| {
                    JobReadResult::Waiting(RetainedRead::new(value, capacity.take_result()))
                }),
                JobRead::UploadFile(hash) => metadata.upload_file_summary(&hash).map(|value| {
                    JobReadResult::UploadFile(
                        value.map(|value| RetainedRead::new(value, capacity.take_result())),
                    )
                }),
                JobRead::LibraryStatistics(hash) => {
                    accounting.publish_file_statistics()?;
                    metadata
                        .file_upload_statistics(&hex::encode(hash))
                        .map(|value| {
                            JobReadResult::LibraryStatistics(
                                value.map(|value| RetainedRead::new(value, capacity.take_result())),
                            )
                        })
                }
                JobRead::LibraryQuery(query) => {
                    accounting.publish_file_statistics()?;
                    metadata
                        .library_file_page(&query, emulebb_metadata::LIBRARY_READ_MAX_BYTES)
                        .map(|page| {
                            JobReadResult::LibraryQuery(RetainedRead::new(
                                page,
                                capacity.take_result(),
                            ))
                        })
                }
                JobRead::LibraryFile(hash) => {
                    accounting.publish_file_statistics()?;
                    metadata.library_file(&hash).map(|file| {
                        JobReadResult::LibraryFile(
                            file.map(|file| RetainedRead::new(file, capacity.take_result())),
                        )
                    })
                }
                JobRead::LibraryLocations(hash, after, limit) => metadata
                    .library_locations(
                        &hex::encode(hash),
                        after,
                        limit,
                        emulebb_metadata::LIBRARY_READ_MAX_BYTES,
                    )
                    .map(|value| {
                        JobReadResult::LibraryLocations(
                            value.map(|value| RetainedRead::new(value, capacity.take_result())),
                        )
                    }),
                JobRead::TransferCounts => metadata.transfer_counts().map(|value| {
                    JobReadResult::TransferCounts(RetainedRead::new(value, capacity.take_result()))
                }),
                JobRead::Detail(id) => metadata.download_job_detail(id).map(|value| {
                    JobReadResult::Detail(
                        value.map(|value| RetainedRead::new(value, capacity.take_result())),
                    )
                }),
                JobRead::Parts(id, after, limit) => metadata
                    .download_job_parts_after(id, after, limit)
                    .map(|value| {
                        JobReadResult::Parts(
                            value.map(|value| RetainedRead::new(value, capacity.take_result())),
                        )
                    }),
                JobRead::VerifiedParts(token) => {
                    metadata.download_job_verified_parts(token).map(|value| {
                        JobReadResult::VerifiedParts(
                            value.map(|value| RetainedRead::new(value, capacity.take_result())),
                        )
                    })
                }
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
                JobRead::Comments(token, after, limit) => metadata
                    .download_job_comments_after(token, after, limit)
                    .map(|value| {
                        JobReadResult::Comments(RetainedRead::new(value, capacity.take_result()))
                    }),
                JobRead::Source(token, selector) => {
                    metadata.download_job_source(token, selector).map(|value| {
                        JobReadResult::Source(RetainedRead::new(value, capacity.take_result()))
                    })
                }
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
                    let _content =
                        transfer::store::scoped_lock(&content_locks, manifest.file_hash.clone())
                            .blocking_lock_owned();
                    // Match progress/patch publication: content before category.
                    // A queued category writer must not strand a reader while
                    // it waits for content held by another publication owner.
                    let _category = categories.blocking_read();
                    let mut cache = cache.blocking_lock();
                    if let Some(current) = cache
                        .get(&token.job_id)
                        .filter(|current| current.token == token)
                    {
                        // A current resident owns cache-only progress. A private
                        // SQL snapshot must never replace that live authority.
                        return Ok(JobReadResult::Execution(Some(current.clone())));
                    }
                    let cache_claim = cache.claim_insert()?;
                    metadata
                        .publish_observed_download_execution(
                            token,
                            observed.as_ref().expect("selection observation"),
                            || {
                                cache.insert_claimed(token.job_id, manifest.clone(), cache_claim);
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
                JobRead::LiveSourceScarcity(query, size, available, observed) => {
                    if observed.elapsed() > std::time::Duration::from_secs(30) {
                        Ok(JobReadResult::SourceScarcity(false))
                    } else {
                        metadata
                            .download_job_live_source_has_rare_part(query, size, &available)
                            .map(JobReadResult::SourceScarcity)
                    }
                }
                JobRead::SourceScarcity(query) => metadata
                    .download_job_has_rare_source_part(query)
                    .map(JobReadResult::SourceScarcity),
                JobRead::SourceAvailability(query) => metadata
                    .download_job_source_availability(query)
                    .map(|value| {
                        JobReadResult::SourceAvailability(RetainedRead::new(
                            value,
                            capacity.take_result(),
                        ))
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
            (result, outcome)
        });
        Ok(receipt)
    }
}
impl transfer::Ed2kTransferRuntime {
    /// One retained library summary without a file probe or execution hydration.
    pub async fn library_file(
        &self,
        hash: &str,
    ) -> Result<Option<RetainedRead<emulebb_metadata::MetadataLibraryFile>>> {
        let hash: emulebb_kad_proto::Ed2kHash = hash.parse()?;
        let JobReadResult::LibraryFile(file) =
            self.read_job_metadata(JobRead::LibraryFile(hash.0)).await?
        else {
            unreachable!()
        };
        Ok(file)
    }
    /// A thin library page, with current captured statistics, through the same
    /// admitted owner as other reads. Includes work headroom for name folding.
    pub async fn library_file_page(
        &self,
        query: emulebb_metadata::LibraryFileQuery,
    ) -> Result<RetainedRead<emulebb_metadata::MetadataLibraryFilePage>> {
        let JobReadResult::LibraryQuery(page) =
            self.read_job_metadata(JobRead::LibraryQuery(query)).await?
        else {
            unreachable!()
        };
        Ok(page)
    }
    /// Publish captured counters without checkpointing durable credit, then read
    /// one scalar snapshot through the admitted owner. No execution is hydrated.
    pub async fn library_file_statistics(
        &self,
        hash: &str,
    ) -> Result<Option<RetainedRead<emulebb_metadata::MetadataFileUploadStatistics>>> {
        let hash: emulebb_kad_proto::Ed2kHash = hash.parse()?;
        let JobReadResult::LibraryStatistics(stats) = self
            .read_job_metadata(JobRead::LibraryStatistics(hash.0))
            .await?
        else {
            unreachable!()
        };
        Ok(stats)
    }

    /// Read a bounded cached copy window through the admitted metadata owner.
    /// The result retains its allowance; no file or execution is opened.
    pub async fn library_locations(
        &self,
        hash: &str,
        after: i64,
        limit: usize,
    ) -> Result<Option<RetainedRead<emulebb_metadata::MetadataLibraryLocationPage>>> {
        let hash: emulebb_kad_proto::Ed2kHash = hash.parse()?;
        let JobReadResult::LibraryLocations(page) = self
            .read_job_metadata(JobRead::LibraryLocations(hash.0, after, limit))
            .await?
        else {
            unreachable!()
        };
        Ok(page)
    }

    /// Cached upload captions through the existing bounded metadata worker.
    /// Retained results own their temporary allowance; no manifest is hydrated.
    pub async fn upload_file_summary(
        &self,
        hash: &str,
    ) -> Result<Option<RetainedRead<emulebb_metadata::MetadataUploadFileSummary>>> {
        let hash: emulebb_kad_proto::Ed2kHash = hash.parse()?;
        let JobReadResult::UploadFile(summary) =
            self.read_job_metadata(JobRead::UploadFile(hash.0)).await?
        else {
            unreachable!()
        };
        Ok(summary)
    }

    /// Classify only an already cached/current execution. The shared worker
    /// owns its temporary frequency buffers; cancellation cannot release that
    /// credit before the worker and its resident read loan actually finish.
    pub async fn download_scheduling_state(
        self: &Arc<Self>,
        token: emulebb_metadata::JobToken,
    ) -> Result<Option<transfer::DownloadSchedulingState>> {
        let JobReadResult::Scheduling(state) = self
            .read_job_metadata(JobRead::Scheduling(Arc::clone(self), token, None))
            .await?
        else {
            unreachable!()
        };
        Ok(state)
    }

    /// Recheck current protection and accepted progress before requesting a safe
    /// yield. Capacity remains owned until producers and retirement settle.
    pub async fn request_download_yield(
        self: &Arc<Self>,
        token: emulebb_metadata::JobToken,
        expected_bytes: u64,
    ) -> Result<bool> {
        let JobReadResult::Scheduling(state) = self
            .read_job_metadata(JobRead::Scheduling(
                Arc::clone(self),
                token,
                Some(expected_bytes),
            ))
            .await?
        else {
            unreachable!()
        };
        Ok(state.is_some_and(|state| state.yielding))
    }

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

    /// Await authoritative dashboard counts on the bounded metadata worker.
    pub async fn transfer_counts(
        &self,
    ) -> Result<RetainedRead<emulebb_metadata::MetadataTransferCounts>> {
        let JobReadResult::TransferCounts(counts) =
            self.read_job_metadata(JobRead::TransferCounts).await?
        else {
            unreachable!()
        };
        Ok(counts)
    }

    /// Fixed-size waiting count with sorted unique IDs from the runtime cohort.
    /// The request backing shares the existing byte-accounted metadata worker.
    pub async fn waiting_download_count(&self, selected: Vec<JobId>) -> Result<RetainedRead<u64>> {
        let JobReadResult::Waiting(count) =
            self.read_job_metadata(JobRead::Waiting(selected)).await?
        else {
            unreachable!()
        };
        Ok(count)
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

    /// Current-session observed rarity, computed off the async executor without
    /// hydrating a manifest or retaining an unbounded peer-identity set.
    pub async fn download_source_has_rare_part(
        &self,
        token: emulebb_metadata::JobToken,
        user_hash: [u8; 16],
    ) -> Result<bool> {
        let now = chrono::Utc::now().timestamp().max(0);
        let query = emulebb_metadata::MetadataDownloadScarcityQuery {
            token,
            session_id: self.source_discovery_session,
            observed_since_s: now.saturating_sub(30),
            observed_until_s: now,
            user_hash,
        };
        let JobReadResult::SourceScarcity(rare) = self
            .read_job_metadata(JobRead::SourceScarcity(query))
            .await?
        else {
            unreachable!()
        };
        Ok(rare)
    }

    /// Borrow listener-owned availability through the retained read. This never
    /// stores an inbound socket address as an outbound source hint. Observer
    /// cancellation leaves its shared backing charged until the worker settles.
    pub async fn download_live_source_has_rare_part(
        &self,
        token: emulebb_metadata::JobToken,
        file_size: u64,
        user_hash: [u8; 16],
        available: Arc<Vec<bool>>,
        observed: std::time::Instant,
    ) -> Result<bool> {
        ensure!(
            available.len() <= 65534 && available.capacity() <= 65536,
            "unsupported live source geometry"
        );
        let now = chrono::Utc::now().timestamp().max(0);
        let query = emulebb_metadata::MetadataDownloadScarcityQuery {
            token,
            session_id: self.source_discovery_session,
            observed_since_s: now.saturating_sub(30),
            observed_until_s: now,
            user_hash,
        };
        let JobReadResult::SourceScarcity(rare) = self
            .read_job_metadata(JobRead::LiveSourceScarcity(
                query, file_size, available, observed,
            ))
            .await?
        else {
            unreachable!()
        };
        // Database contention must not renew a captured network observation.
        Ok(rare && observed.elapsed() <= std::time::Duration::from_secs(30))
    }

    /// Current runtime/session observations only. Caller supplies an explicit
    /// freshness interval; persisted status never implies permanent reachability.
    pub async fn download_source_availability_after(
        &self,
        token: emulebb_metadata::JobToken,
        observed_since_s: i64,
        observed_until_s: i64,
        after_source_id: i64,
        limit: usize,
    ) -> Result<RetainedRead<Vec<emulebb_metadata::MetadataDownloadSourceAvailability>>> {
        let query = emulebb_metadata::MetadataDownloadAvailabilityQuery {
            token,
            session_id: self.source_discovery_session,
            observed_since_s,
            observed_until_s,
            after_source_id,
            limit,
        };
        let JobReadResult::SourceAvailability(page) = self
            .read_job_metadata(JobRead::SourceAvailability(query))
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
    pub async fn download_comments_after(
        &self,
        token: emulebb_metadata::JobToken,
        after: i64,
        limit: usize,
    ) -> Result<RetainedRead<emulebb_metadata::MetadataDownloadCommentPage>> {
        let JobReadResult::Comments(page) = self
            .read_job_metadata(JobRead::Comments(token, after, limit))
            .await?
        else {
            unreachable!()
        };
        Ok(page)
    }

    pub async fn download_source(
        &self,
        token: emulebb_metadata::JobToken,
        selector: emulebb_metadata::MetadataDownloadSourceSelector,
    ) -> Result<RetainedRead<Option<emulebb_metadata::MetadataDownloadSourceEntry>>> {
        let JobReadResult::Source(source) = self
            .read_job_metadata(JobRead::Source(token, selector))
            .await?
        else {
            unreachable!()
        };
        Ok(source)
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
    pub async fn download_detail(
        &self,
        id: JobId,
    ) -> Result<Option<RetainedRead<emulebb_metadata::MetadataDownloadDetail>>> {
        let JobReadResult::Detail(detail) = self.read_job_metadata(JobRead::Detail(id)).await?
        else {
            unreachable!()
        };
        Ok(detail)
    }

    pub async fn download_parts_after(
        &self,
        id: JobId,
        after: Option<u32>,
        limit: usize,
    ) -> Result<Option<RetainedRead<emulebb_metadata::MetadataDownloadPartPage>>> {
        let JobReadResult::Parts(page) = self
            .read_job_metadata(JobRead::Parts(id, after, limit))
            .await?
        else {
            unreachable!()
        };
        Ok(page)
    }

    /// Read only durable verification bits for a waiting job. The existing
    /// transient loan follows the returned bitmap; no resident view is created.
    pub async fn download_verified_parts(
        &self,
        token: emulebb_metadata::JobToken,
    ) -> Result<Option<RetainedRead<emulebb_metadata::MetadataDownloadVerifiedParts>>> {
        let JobReadResult::VerifiedParts(parts) = self
            .read_job_metadata(JobRead::VerifiedParts(token))
            .await?
        else {
            unreachable!()
        };
        Ok(parts)
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
