//! Retained logical admission and execution fencing; physical allocation remains separate.
use super::read_result::RetainedRead;
use super::*;
use crate::ed2k_transfer as transfer;
use emulebb_metadata::{
    DownloadJobAdmission, DownloadJobRecord, DownloadJobRequest, DownloadJobStorageFailure,
    DownloadJobStorageFailureOutcome, JobToken, MetadataDownloadInitialPeers,
};
use std::{
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

const CONTROL_WORKSPACE: usize = PUBLICATION_WORKSPACE + 1024 * 1024;

enum Control<'a> {
    Admit(
        &'a DownloadJobRequest,
        bool,
        Option<&'a str>,
        &'a MetadataDownloadInitialPeers,
    ),
    Start(JobToken, &'a Path),
    Begin(JobToken, Option<&'a Path>),
    Learn(JobToken, u64),
    Fail(JobToken, &'a DownloadJobStorageFailure),
}
enum OwnedControl {
    Admit(
        DownloadJobRequest,
        bool,
        Option<String>,
        MetadataDownloadInitialPeers,
    ),
    Start(JobToken, PathBuf),
    Begin(JobToken, Option<PathBuf>),
    Learn(JobToken, u64),
    Fail(JobToken, DownloadJobStorageFailure),
}
enum ControlResult {
    Admission(DownloadJobAdmission),
    Job(Option<DownloadJobRecord>),
    Failure(DownloadJobStorageFailureOutcome),
}
impl ControlResult {
    fn job(&self) -> Option<&DownloadJobRecord> {
        match self {
            Self::Admission(value) => Some(&value.job),
            Self::Job(value) => value.as_ref(),
            Self::Failure(value) => value.job.as_ref(),
        }
    }
}
impl LocalMutationRegistry {
    fn submit_control(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        change: Control<'_>,
    ) -> Result<oneshot::Receiver<Result<RetainedRead<ControlResult>>>> {
        // Validate caller backing before cloning it under the admitted workspace.
        match &change {
            Control::Admit(request, _, aich, initial_peers) => {
                initial_peers.payload_bytes()?;
                ensure!(
                    request.file_hash.len() == 32
                        && request.display_name.len() <= 65_536
                        && aich.is_none_or(|root| root.len() == 40),
                    LocalMutationError::TooLarge
                );
            }
            Control::Start(_, path) => {
                withdrawal_path_charge(path)?;
            }
            Control::Begin(_, path) => {
                if let Some(path) = path {
                    withdrawal_path_charge(path)?;
                }
            }
            Control::Learn(_, _) | Control::Fail(_, _) => {}
        }
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let lease = Self::reserve_unit(&mut state, CONTROL_WORKSPACE, true, false)?;
        let change = match change {
            Control::Admit(request, redownload, aich, initial_peers) => OwnedControl::Admit(
                request.clone(),
                redownload,
                aich.map(str::to_owned),
                initial_peers.clone(),
            ),
            Control::Start(token, path) => OwnedControl::Start(token, path.to_owned()),
            Control::Begin(token, path) => OwnedControl::Begin(token, path.map(Path::to_owned)),
            Control::Learn(token, size) => OwnedControl::Learn(token, size),
            Control::Fail(token, failure) => OwnedControl::Fail(token, failure.clone()),
        };
        let metadata = runtime.metadata.clone();
        let publication = super::publication::ContentPublication::new(runtime);
        let locks = Arc::clone(&runtime.content_locks);
        let eligibility = Arc::clone(&runtime.share_eligibility);
        let cache = Arc::clone(&runtime.manifest_cache);
        let sessions = Arc::clone(&runtime.job_storage);
        let payloads = Arc::clone(&runtime.payload_handles);
        let checkpoints = Arc::clone(&runtime.manifest_checkpoint_state);
        let activity = Arc::clone(&runtime.download_activity);
        let sources = Arc::clone(&runtime.download_sources);
        let votes = Arc::clone(&runtime.aich_root_corroboration);
        let blackboxes = Arc::clone(&runtime.corruption_blackbox);
        let source_exchange = runtime.source_exchange.clone();
        let epoch = Arc::clone(&runtime.category_root_epoch);
        let dirty = Arc::clone(&runtime.category_root_dirty);
        let failed = Arc::clone(&runtime.share_publication_failed);
        let (sender, receipt) = oneshot::channel();
        #[cfg(test)]
        let gate = state.publication_gate.take();
        Self::spawn_unit(&mut state, lease, move |lease| {
            let mut committed = false;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let (hash, old_token) = match &change {
                    OwnedControl::Admit(request, _, _, _) => (request.file_hash.clone(), None),
                    OwnedControl::Start(token, _)
                    | OwnedControl::Begin(token, _)
                    | OwnedControl::Learn(token, _)
                    | OwnedControl::Fail(token, _) => {
                        let Some(job) = metadata.download_job(token.job_id)? else {
                            return Ok(RetainedRead::new(
                                ControlResult::Job(None),
                                lease.take_result(),
                            ));
                        };
                        (job.file_hash, Some(*token))
                    }
                };
                let hash = hash.parse::<emulebb_kad_proto::Ed2kHash>()?;
                // Filesystem capacity and SQL snapshots are acquired before any
                // content/stripe guard. The original worker owns every phase.
                let availability =
                    if let OwnedControl::Admit(request, redownload, _, initial_peers) = &change {
                        let root_cut = epoch.load(Ordering::Acquire);
                        ensure!(root_cut % 2 == 0, LocalMutationError::Busy);
                        let cut = metadata.capture_download_availability()?;
                        let active = metadata.active_download_job(&hash.to_string())?.is_some();
                        let state = if active || *redownload {
                            emulebb_metadata::LocalContentAvailability::Unavailable
                        } else {
                            // Retain all admitted input through the filesystem phase.
                            let input_bytes = 128 * 1024
                                + request.display_name.len()
                                + initial_peers.payload_bytes()?;
                            lease.enter_filesystem(input_bytes, super::availability::WORKSPACE)?;
                            let mut budget = super::availability::ScanBudget::default();
                            let (mut state, present) = super::availability::scan(
                                &metadata,
                                &hash.to_string(),
                                &cut,
                                &mut budget,
                            )?;
                            drop(present);
                            #[cfg(test)]
                            lease.pause_after_probe();
                            // WHY: a physical-only change during a scheduling gap
                            // must not turn stale absence into creation permission.
                            // Both passes share one work budget. After the final
                            // probe neither capacity nor content admission may wait.
                            if state == emulebb_metadata::LocalContentAvailability::ConfirmedAbsent
                            {
                                let (fresh, present) = super::availability::scan(
                                    &metadata,
                                    &hash.to_string(),
                                    &cut,
                                    &mut budget,
                                )?;
                                drop(present);
                                state = fresh;
                            }
                            lease.try_enter_publication(CONTROL_WORKSPACE)?;
                            state
                        };
                        Some((cut, root_cut, state))
                    } else {
                        None
                    };
                let content_lock = transfer::store::scoped_lock(&locks, hash.to_string());
                let content = if matches!(&change, OwnedControl::Admit(..)) {
                    content_lock
                        .try_lock_owned()
                        .ok_or(LocalMutationError::Busy)?
                } else {
                    content_lock.blocking_lock_owned()
                };
                let stripe = eligibility.begin_mutation(&[hash.0])?;
                let result = match &change {
                    OwnedControl::Admit(request, redownload, aich, initial_peers) => {
                        let (cut, root_cut, state) = availability.as_ref().expect("admission cut");
                        let value = metadata.admit_available_download_job(
                            request,
                            emulebb_metadata::DownloadAvailabilityAdmission {
                                cut,
                                availability: *state,
                                redownload: *redownload,
                                aich_root: aich.as_deref(),
                                initial_peers,
                                root_epoch: (&epoch, *root_cut),
                            },
                        )?;
                        committed = value.created;
                        ControlResult::Admission(value)
                    }
                    OwnedControl::Start(token, path) => {
                        let value = metadata.start_download_job(*token, path)?;
                        committed = value.as_ref().is_some_and(|job| job.token != *token);
                        ControlResult::Job(value)
                    }
                    OwnedControl::Begin(token, path) => {
                        let value =
                            metadata.begin_download_job_execution(*token, path.as_deref())?;
                        committed = value.is_some();
                        ControlResult::Job(value)
                    }
                    OwnedControl::Learn(token, size) => {
                        // WHY: size discovery precedes execution hydration. Changing
                        // geometry under an active manifest would lose dirty progress.
                        ensure!(
                            !cache.blocking_lock().contains_key(&token.job_id),
                            "size claim requires an unhydrated execution"
                        );
                        committed = metadata.learn_download_job_size(*token, *size)?;
                        ControlResult::Job(metadata.download_job(token.job_id)?)
                    }
                    OwnedControl::Fail(token, failure) => {
                        let value = metadata.fail_download_job_storage(*token, failure)?;
                        committed = value.applied;
                        ControlResult::Failure(value)
                    }
                };
                #[cfg(test)]
                if let Some((reached, release)) = gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                if committed
                    && let Some(old) = old_token
                    && result.job().is_some_and(|job| job.token != old)
                {
                    // Token-invalidated workers retain their own capabilities;
                    // neither their late cache publication nor later cleanup can
                    // acquire this new generation through a hash lookup.
                    let mut manifests = cache.blocking_lock();
                    if manifests.get(&old.job_id).is_some_and(|m| m.token == old) {
                        manifests.remove(&old.job_id);
                    }
                    drop(manifests);
                    let mut storage = sessions.lock().map_err(|_| LocalMutationError::Unknown)?;
                    if storage.get(&old.job_id).is_some_and(|s| s.token == old) {
                        storage.remove(&old.job_id);
                    }
                    drop(storage);
                    payloads
                        .lock()
                        .map_err(|_| LocalMutationError::Unknown)?
                        .remove(&old);
                    activity
                        .lock()
                        .map_err(|_| LocalMutationError::Unknown)?
                        .remove(&old);
                    sources
                        .lock()
                        .map_err(|_| LocalMutationError::Unknown)?
                        .remove(&old);
                    votes
                        .lock()
                        .map_err(|_| LocalMutationError::Unknown)?
                        .remove(&old);
                    blackboxes
                        .lock()
                        .map_err(|_| LocalMutationError::Unknown)?
                        .remove(&old);
                    checkpoints.blocking_lock().remove(&old);
                    source_exchange.clear(old);
                }
                // The response and projection own disjoint portions of the same
                // admitted workspace; conversion cannot release response charge.
                let retained = lease.split_retained_bytes(1024 * 1024)?;
                if committed {
                    publication.publish(
                        hash,
                        lease,
                        super::publication::PublicationGuards {
                            content,
                            stripe,
                            job: None,
                        },
                    )?;
                }
                Ok(RetainedRead::new(result, retained))
            }));
            let (result, outcome) = match result {
                Ok(Ok(result)) => (Ok(result), 0),
                Ok(Err(error)) if committed => {
                    tracing::error!(%error, "job control committed but publication failed");
                    (Err(LocalMutationError::Committed.into()), 1)
                }
                Ok(Err(error)) => (Err(super::availability::changed_to_busy(error)), 0),
                Err(_) => (Err(LocalMutationError::Unknown.into()), 2),
            };
            if outcome != 0 {
                dirty.store(true, Ordering::Release);
                failed.store(true, Ordering::Release);
            }
            let _ = sender.send(result);
            outcome
        });
        Ok(receipt)
    }
}
impl transfer::Ed2kTransferRuntime {
    /// Native admission preserves active duplicates unchanged. Busy occurs
    /// before effects; after admission the existing owner completes publication.
    pub async fn admit_download_job(
        &self,
        request: &DownloadJobRequest,
        redownload: bool,
        aich_root: Option<&str>,
        initial_peers: &MetadataDownloadInitialPeers,
    ) -> Result<RetainedRead<DownloadJobAdmission>> {
        let result = self
            .local_mutations
            .submit_control(
                self,
                Control::Admit(request, redownload, aich_root, initial_peers),
            )?
            .await
            .map_err(|_| LocalMutationError::Unknown)??;
        Ok(result.map(|result| match result {
            ControlResult::Admission(value) => value,
            _ => unreachable!(),
        }))
    }
    /// Explicit start/retry with idempotent healthy-start semantics. This receipt
    /// does not claim physical storage exists; prepare_download_job_storage owns it.
    pub async fn start_download_job(
        &self,
        token: JobToken,
        selected_temp: &Path,
    ) -> Result<RetainedRead<Option<DownloadJobRecord>>> {
        let result = self
            .local_mutations
            .submit_control(self, Control::Start(token, selected_temp))?
            .await
            .map_err(|_| LocalMutationError::Unknown)??;
        Ok(result.map(|result| match result {
            ControlResult::Job(value) => value,
            _ => unreachable!(),
        }))
    }
    /// Select healthy started work with a fresh callback fence. A missing path
    /// selects discovery only; it creates no logical or physical backing.
    pub async fn begin_download_job_execution(
        &self,
        token: JobToken,
        selected_temp: Option<&Path>,
    ) -> Result<RetainedRead<Option<DownloadJobRecord>>> {
        let result = self
            .local_mutations
            .submit_control(self, Control::Begin(token, selected_temp))?
            .await
            .map_err(|_| LocalMutationError::Unknown)??;
        Ok(result.map(|result| match result {
            ControlResult::Job(value) => value,
            _ => unreachable!(),
        }))
    }
    /// Fill an unknown size before selecting/hydrating network execution.
    pub async fn learn_download_job_size(
        &self,
        token: JobToken,
        size: u64,
    ) -> Result<RetainedRead<Option<DownloadJobRecord>>> {
        let result = self
            .local_mutations
            .submit_control(self, Control::Learn(token, size))?
            .await
            .map_err(|_| LocalMutationError::Unknown)??;
        Ok(result.map(|result| match result {
            ControlResult::Job(value) => value,
            _ => unreachable!(),
        }))
    }
    /// Capture only the failed execution. Stale callbacks return the actual
    /// current record without replacing its fault, intent or completion.
    pub async fn fail_download_job_storage(
        &self,
        token: JobToken,
        failure: &DownloadJobStorageFailure,
    ) -> Result<RetainedRead<DownloadJobStorageFailureOutcome>> {
        let result = self
            .local_mutations
            .submit_control(self, Control::Fail(token, failure))?
            .await
            .map_err(|_| LocalMutationError::Unknown)??;
        Ok(result.map(|result| match result {
            ControlResult::Failure(value) => value,
            ControlResult::Job(None) => DownloadJobStorageFailureOutcome {
                applied: false,
                job: None,
            },
            _ => unreachable!(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> DownloadJobRequest {
        DownloadJobRequest {
            file_hash: "12121212121212121212121212121212".into(),
            display_name: "sample.bin".into(),
            expected_size_bytes: None,
            category_id: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            piece_size: transfer::ED2K_PART_SIZE,
        }
    }
    #[tokio::test]
    async fn selection_fences_old_callbacks_and_discovery_does_not_create_storage() {
        let root = tempfile::tempdir().unwrap();
        let runtime = transfer::Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let admitted = runtime
            .admit_download_job(&request(), false, None, &Default::default())
            .await
            .unwrap();
        let token = admitted.job.token;
        drop(admitted);
        let preparation = runtime
            .begin_download_job_execution(token, None)
            .await
            .unwrap();
        let job = preparation.as_ref().unwrap();
        assert!(job.storage.is_none());
        assert!(job.selected_temp.is_none());
        let prepared_token = job.token;
        drop(preparation);
        let sized = runtime
            .learn_download_job_size(prepared_token, 16)
            .await
            .unwrap();
        drop(sized);
        let selected = runtime
            .begin_download_job_execution(prepared_token, Some(root.path()))
            .await
            .unwrap();
        let selected_token = selected.as_ref().unwrap().token;
        assert_ne!(selected_token, prepared_token);
        drop(selected);
        let manifest = runtime
            .ensure_job(&transfer::new_transfer_job(
                selected_token,
                request().file_hash.parse().unwrap(),
                request().display_name,
                16,
            ))
            .await
            .unwrap();
        drop(manifest);
        let next = runtime
            .begin_download_job_execution(selected_token, Some(root.path()))
            .await
            .unwrap();
        let next_token = next.as_ref().unwrap().token;
        drop(next);
        assert_ne!(next_token, selected_token);
        let failure =
            DownloadJobStorageFailure::new("TEMP_UNAVAILABLE", "Sample storage offline", 1)
                .unwrap();
        let stale = runtime
            .fail_download_job_storage(selected_token, &failure)
            .await
            .unwrap();
        assert!(!stale.applied);
        assert_eq!(stale.job.as_ref().unwrap().token, next_token);
        assert!(stale.job.as_ref().unwrap().storage_failure.is_none());
        drop(stale);
        runtime.local_mutations.seal_and_drain().await.unwrap();
    }
    #[tokio::test]
    async fn control_returns_actual_tokens_preserves_duplicates_and_fences_late_faults() {
        let root = tempfile::tempdir().unwrap();
        let runtime = transfer::Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let admitted = runtime
            .admit_download_job(&request(), false, None, &Default::default())
            .await
            .unwrap();
        assert!(admitted.created);
        let token = admitted.job.token;
        drop(admitted);
        let size = runtime.learn_download_job_size(token, 16).await.unwrap();
        assert_eq!(size.as_ref().unwrap().expected_size_bytes, Some(16));
        drop(size);
        let started = runtime
            .start_download_job(token, root.path())
            .await
            .unwrap();
        let started = started.as_ref().unwrap().token;
        assert_ne!(started, token);
        assert!(!root.path().read_dir().unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(&format!("{}-", token.job_id))
        }));
        let failure =
            DownloadJobStorageFailure::new("TEMP_UNAVAILABLE", "sample storage unavailable", 1)
                .unwrap();
        let fault = runtime
            .fail_download_job_storage(started, &failure)
            .await
            .unwrap();
        assert!(fault.applied);
        let failed_token = fault.job.as_ref().unwrap().token;
        assert_eq!(
            fault.job.as_ref().unwrap().intent,
            emulebb_metadata::DownloadIntent::Started
        );
        drop(fault);
        let mut duplicate = request();
        duplicate.display_name = "other.bin".into();
        duplicate.intent = emulebb_metadata::DownloadIntent::Stopped;
        let duplicate = runtime
            .admit_download_job(&duplicate, true, None, &Default::default())
            .await
            .unwrap();
        assert!(!duplicate.created);
        assert_eq!(duplicate.job.token, failed_token);
        assert_eq!(duplicate.job.display_name, "sample.bin");
        assert_eq!(duplicate.job.storage_failure.as_ref(), Some(&failure));
        drop(duplicate);
        let restart = runtime
            .start_download_job(failed_token, root.path())
            .await
            .unwrap();
        let restarted = restart.as_ref().unwrap().token;
        assert!(restart.as_ref().unwrap().storage_failure.is_none());
        drop(restart);
        let stale = runtime
            .fail_download_job_storage(started, &failure)
            .await
            .unwrap();
        assert!(!stale.applied);
        assert_eq!(stale.job.as_ref().unwrap().token, restarted);
        assert!(stale.job.as_ref().unwrap().storage_failure.is_none());
        drop(stale);
        assert!(
            runtime
                .remove_download_job(restarted.job_id, false)
                .await
                .unwrap()
        );
        let next = runtime
            .admit_download_job(&request(), false, None, &Default::default())
            .await
            .unwrap();
        assert!(next.created);
        let next_token = next.job.token;
        assert_ne!(next_token.job_id, restarted.job_id);
        drop(next);
        let old_attempt = runtime
            .fail_download_job_storage(restarted, &failure)
            .await
            .unwrap();
        assert!(!old_attempt.applied);
        assert_eq!(
            old_attempt.job.as_ref().unwrap().token.job_id,
            restarted.job_id
        );
        drop(old_attempt);
        let next = runtime
            .download_job(next_token.job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(next.token, next_token);
        assert!(next.storage_failure.is_none());
        drop(next);
        runtime.local_mutations.seal_and_drain().await.unwrap();
    }
    #[tokio::test]
    async fn repeated_start_retains_selected_backing_and_repeated_stop_is_unchanged() {
        let root = tempfile::tempdir().unwrap();
        let runtime = transfer::Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let mut input = request();
        input.expected_size_bytes = Some(16);
        let admitted = runtime
            .admit_download_job(&input, false, None, &Default::default())
            .await
            .unwrap();
        let token = admitted.job.token;
        drop(admitted);
        let start_result = runtime
            .start_download_job(token, root.path())
            .await
            .unwrap();
        let started = start_result.as_ref().unwrap().clone();
        drop(start_result);
        let manifest = runtime
            .ensure_job(&transfer::new_transfer_job(
                started.token,
                input.file_hash.parse().unwrap(),
                input.display_name,
                16,
            ))
            .await
            .unwrap();
        // Storage preparation establishes native directory identity. Compare
        // the repeated control with that settled record, not its allocation.
        let prepared = runtime
            .download_job(started.token.job_id)
            .await
            .unwrap()
            .unwrap();
        let prepared_record = (*prepared).clone();
        drop(prepared);
        let repeated = runtime
            .start_download_job(started.token, &root.path().join("other"))
            .await
            .unwrap();
        assert_eq!(repeated.as_ref().unwrap(), &prepared_record);
        let current = runtime.manifest(started.token).await.unwrap();
        assert!(std::ptr::eq(&*manifest, &*current));
        drop(current);
        drop(repeated);
        drop(manifest);

        assert!(runtime.stop_download_job(started.token).await.unwrap());
        let stopped = runtime
            .download_job(started.token.job_id)
            .await
            .unwrap()
            .unwrap();
        assert!(!runtime.stop_download_job(stopped.token).await.unwrap());
        let current = runtime
            .download_job(stopped.token.job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*current, *stopped);
        drop(current);
        drop(stopped);
        runtime.local_mutations.seal_and_drain().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_control_caller_does_not_abandon_publication() {
        let root = tempfile::tempdir().unwrap();
        let runtime = transfer::Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        let registry = Arc::clone(&runtime.local_mutations);
        let (reached, ready) = oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        registry.install_publication_gate(reached, gate);
        let peers = MetadataDownloadInitialPeers {
            sources: vec![emulebb_metadata::MetadataTransferSource {
                ip: "192.0.2.9".into(),
                tcp_port: 4662,
                user_hash: None,
                connect_options: None,
                file_comment: String::new(),
                file_rating: 0,
            }],
            observations: Vec::new(),
        };
        let receipt = registry
            .submit_control(&runtime, Control::Admit(&request(), false, None, &peers))
            .unwrap();
        ready.await.unwrap();
        drop(receipt);
        release.send(()).unwrap();
        registry.seal_and_drain().await.unwrap();
        let job = runtime
            .metadata
            .latest_download_job(&request().file_hash)
            .unwrap()
            .unwrap();
        assert_eq!(job.display_name, "sample.bin");
        assert_eq!(
            runtime
                .metadata
                .download_job_sources_after(job.token, 0, 10)
                .unwrap()[0]
                .source
                .ip,
            "192.0.2.9"
        );
        assert_eq!(registry.state.lock().unwrap().capacity.usage().bytes, 0);
        assert!(!runtime.share_publication_failed.load(Ordering::Acquire));
    }
}
