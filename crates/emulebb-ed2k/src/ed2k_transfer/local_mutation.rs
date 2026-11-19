//! Bounded ownership of accepted local-share mutation units.
//!
//! This registry has no worker loop: each admitted blocking unit uses the
//! existing metadata connection and remains tracked until it terminates.

use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow, ensure};
use tokio::{sync::oneshot, task::JoinSet};

pub(super) mod capacity;
use capacity::{CapacityControl, CapacityLease};
mod availability;
mod content_metadata;
mod ingest;
mod job_aich;
mod job_control;
mod storage_inspection;
mod upload_demand;
pub use storage_inspection::StorageSpaceReservation;
mod job_delivery;
mod job_hash;
mod job_lifecycle;
pub(super) mod job_payload;
mod job_peer;
mod job_progress;
pub(super) mod job_read;
mod job_retirement;
pub(super) mod job_storage;
mod publication;
pub(super) mod read_result;

pub(super) const MAX_UNITS: usize = 4;
const MAX_BYTES: usize = 8 * 1024 * 1024;
// Potentially slow filesystem work cannot occupy the final publication slot or
// its byte headroom. These are sublimits of the existing registry, not new pools.
const MAX_LONG_FS_UNITS: usize = MAX_UNITS - 1;
const MAX_LONG_FS_BYTES: usize = 2 * 1024 * 1024;
// Covers the live and persisted bounded partial projections, their conversion
// buffers, and an exact complete entry plus its publication copy. Path backing
// storage is charged separately before any owner-held clones are made.
const PUBLICATION_WORKSPACE: usize = 4 * 1024 * 1024;

enum PathMutation<'a> {
    Withdraw {
        path: &'a std::path::Path,
        expected: Option<&'a emulebb_metadata::NativeFileFingerprint>,
        queue_rehash: bool,
    },
    Admit {
        root: &'a std::path::Path,
        path: &'a std::path::Path,
        relative: &'a std::path::Path,
        fingerprint: &'a emulebb_metadata::NativeFileFingerprint,
        observed_root: Option<u64>,
    },
}

enum OwnedPathMutation {
    Withdraw {
        path: std::path::PathBuf,
        expected: Option<emulebb_metadata::NativeFileFingerprint>,
    },
    Admit {
        root: std::path::PathBuf,
        path: std::path::PathBuf,
        relative: std::path::PathBuf,
        fingerprint: emulebb_metadata::NativeFileFingerprint,
        observed_root: Option<u64>,
    },
}

#[derive(Debug)]
pub enum LocalMutationError {
    Busy,
    Closing,
    TooLarge,
    Storage,
    Committed,
    Unknown,
}
impl std::fmt::Display for LocalMutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Busy => "local mutation capacity is busy",
            Self::Closing => "local mutation admission is closing",
            Self::TooLarge => "local mutation exceeds the payload bound",
            Self::Storage => "local mutation database operation failed",
            Self::Committed => "local mutation committed but publication failed",
            Self::Unknown => "local mutation outcome is unknown",
        })
    }
}
impl std::error::Error for LocalMutationError {}

fn withdrawal_path_charge(path: &std::path::Path) -> Result<usize> {
    #[cfg(windows)]
    let native_bytes = {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str().encode_wide().count().checked_mul(2)
    };
    #[cfg(not(windows))]
    let native_bytes = Some(path.as_os_str().len());
    let native_bytes = native_bytes.ok_or(LocalMutationError::TooLarge)?;
    if native_bytes > 65_536 {
        return Err(LocalMutationError::TooLarge.into());
    }
    path.as_os_str()
        .len()
        .checked_mul(4)
        .and_then(|n| {
            native_bytes
                .checked_mul(2)
                .and_then(|native| n.checked_add(native))
        })
        .ok_or_else(|| LocalMutationError::TooLarge.into())
}

#[derive(Debug)]
pub(super) struct LocalMutationRegistry {
    pub(super) residents: Arc<super::resident::ResidentControl>,
    state: Mutex<State>,
    join_gate: tokio::sync::Mutex<()>,
    preparation: Arc<std::sync::atomic::AtomicBool>,
    cleanup: Arc<std::sync::atomic::AtomicBool>,
}

impl Default for LocalMutationRegistry {
    fn default() -> Self {
        let state = State::default();
        Self {
            residents: Arc::new(super::resident::ResidentControl::new(Arc::clone(
                &state.capacity,
            ))),
            state: Mutex::new(state),
            join_gate: Default::default(),
            preparation: Default::default(),
            cleanup: Default::default(),
        }
    }
}

#[derive(Debug, Default)]
struct State {
    sealed: bool,
    faulted: bool,
    publication_failed: bool,
    capacity: Arc<CapacityControl>,
    tasks: JoinSet<u8>,
    drain_outcome: Option<bool>,
    #[cfg(test)]
    publication_gate: Option<(oneshot::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    #[cfg(test)]
    drain_pending: Option<oneshot::Sender<()>>,
    #[cfg(test)]
    wait_pending: Option<oneshot::Sender<()>>,
}

impl LocalMutationRegistry {
    /// Reserve under the same admission mutex, before clones or spawning. A
    /// rejected long operation owns no slot; accepted charges survive until its
    /// actual blocking task is reaped, including cancelled receipt/drain waiters.
    /// `work` owns all command captures. Its FnOnce environment drops before
    /// the outer lease, including on unwind; no captured buffers outlive charge.
    fn spawn_unit(
        state: &mut State,
        lease: CapacityLease,
        work: impl FnOnce(&mut CapacityLease) -> u8 + Send + 'static,
    ) {
        Self::spawn_unit_with(state, lease, (), move |lease, _| work(lease));
    }
    /// A successful receipt must not race the prior command's workspace release.
    /// Consume the work closure (and its input captures), release its temporary
    /// lease, then expose the independently charged result to the next caller.
    fn spawn_unit_reply<T: Send + 'static>(
        state: &mut State,
        mut lease: CapacityLease,
        sender: oneshot::Sender<T>,
        work: impl FnOnce(&mut CapacityLease) -> (T, u8) + Send + 'static,
    ) {
        state.tasks.spawn_blocking(move || {
            let (result, outcome) = work(&mut lease);
            drop(lease);
            let _ = sender.send(result);
            outcome
        });
    }
    /// An additional pure control lease (prepared hashing) also outlives every
    /// captured input. Neither control contains the runtime or this task set.
    fn spawn_unit_with<C: Send + 'static>(
        state: &mut State,
        mut lease: CapacityLease,
        control: C,
        work: impl FnOnce(&mut CapacityLease, &C) -> u8 + Send + 'static,
    ) {
        state.tasks.spawn_blocking(move || {
            let outcome = work(&mut lease, &control);
            drop(control);
            drop(lease);
            outcome
        });
    }
    fn reserve_unit(
        state: &mut State,
        bytes: usize,
        eligible: bool,
        physical: bool,
    ) -> Result<CapacityLease> {
        ensure!(!state.sealed, LocalMutationError::Closing);
        ensure!(!state.faulted, LocalMutationError::Unknown);
        ensure!(state.tasks.len() < MAX_UNITS, LocalMutationError::Busy);
        state.capacity.reserve(bytes, eligible, physical)
    }
    fn reserve_long_fs(state: &mut State, bytes: usize) -> Result<CapacityLease> {
        Self::reserve_unit(state, bytes, true, true)
    }
    /// Wait for an admitted unit to actually finish; callers retain only their
    /// current bounded event and hold no registry or invalidation reservation.
    pub(super) fn capacity_revision(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .capacity
            .revision()
    }
    pub(super) async fn wait_for_completion(&self, observed: u64) -> Result<()> {
        let capacity = Arc::clone(
            &self
                .state
                .lock()
                .map_err(|_| LocalMutationError::Unknown)?
                .capacity,
        );
        let changed = capacity.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let _gate = self.join_gate.lock().await;
        std::future::poll_fn(|cx| {
            let Ok(mut state) = self.state.lock() else {
                return std::task::Poll::Ready(Err(LocalMutationError::Unknown.into()));
            };
            if state.sealed {
                return std::task::Poll::Ready(Err(LocalMutationError::Closing.into()));
            }
            if state.faulted {
                return std::task::Poll::Ready(Err(LocalMutationError::Unknown.into()));
            }
            if capacity.revision() != observed {
                return std::task::Poll::Ready(Ok(()));
            }
            let _ = std::future::Future::poll(changed.as_mut(), cx);
            match state.tasks.poll_join_next(cx) {
                std::task::Poll::Pending => {
                    #[cfg(test)]
                    if let Some(sender) = state.wait_pending.take() {
                        let _ = sender.send(());
                    }
                    std::task::Poll::Pending
                }
                std::task::Poll::Ready(None) => std::task::Poll::Pending,
                std::task::Poll::Ready(Some(Ok(outcome))) => {
                    state.publication_failed |= outcome == 1;
                    state.faulted |= outcome == 2;
                    if state.faulted {
                        std::task::Poll::Ready(Err(LocalMutationError::Unknown.into()))
                    } else {
                        std::task::Poll::Ready(Ok(()))
                    }
                }
                std::task::Poll::Ready(Some(Err(_))) => {
                    state.faulted = true;
                    std::task::Poll::Ready(Err(LocalMutationError::Unknown.into()))
                }
            }
        })
        .await
    }
    #[cfg(test)]
    pub(super) fn install_publication_gate(
        &self,
        reached: oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        self.state.lock().unwrap().publication_gate = Some((reached, release));
    }

    #[cfg(test)]
    pub(super) fn signal_next_pending_drain(&self) -> oneshot::Receiver<()> {
        let (sender, receiver) = oneshot::channel();
        self.state.lock().unwrap().drain_pending = Some(sender);
        receiver
    }

    #[cfg(test)]
    pub(super) fn signal_next_pending_wait(&self) -> oneshot::Receiver<()> {
        let (sender, receiver) = oneshot::channel();
        self.state.lock().unwrap().wait_pending = Some(sender);
        receiver
    }
    fn reap(state: &mut State) {
        // The capacity lease releases actual backing independently of joining.
        // Reaping only records the completed unit's durable outcome.
        while let Some(result) = state.tasks.try_join_next() {
            match result {
                Ok(outcome) => {
                    state.publication_failed |= outcome == 1;
                    state.faulted |= outcome == 2;
                }
                Err(_) => state.faulted = true,
            }
        }
    }

    /// Admit a typed stale-source withdrawal before cloning its payload.
    pub(super) fn submit_withdrawal(
        &self,
        runtime: &super::Ed2kTransferRuntime,
        hash: &str,
        path: &std::path::Path,
        expected: Option<&emulebb_metadata::NativeFileFingerprint>,
        queue_rehash: bool,
        manifest_guard: super::store::ScopedLockGuard<String>,
        stripe_guard: super::SharedFileMutation,
    ) -> Result<oneshot::Receiver<Result<usize>>> {
        self.submit_path_mutation(
            runtime,
            hash,
            PathMutation::Withdraw {
                path,
                expected,
                queue_rehash,
            },
            manifest_guard,
            stripe_guard,
        )
    }

    /// Admit one verified copy with its catalog publication owned by the registry.
    pub(super) fn submit_admission(
        &self,
        runtime: &super::Ed2kTransferRuntime,
        hash: &str,
        root: &std::path::Path,
        path: &std::path::Path,
        relative: &std::path::Path,
        fingerprint: &emulebb_metadata::NativeFileFingerprint,
        observed_root: Option<u64>,
        manifest_guard: super::store::ScopedLockGuard<String>,
        stripe_guard: super::SharedFileMutation,
    ) -> Result<oneshot::Receiver<Result<usize>>> {
        self.submit_path_mutation(
            runtime,
            hash,
            PathMutation::Admit {
                root,
                path,
                relative,
                fingerprint,
                observed_root,
            },
            manifest_guard,
            stripe_guard,
        )
    }

    fn submit_path_mutation(
        &self,
        runtime: &super::Ed2kTransferRuntime,
        hash: &str,
        mutation: PathMutation<'_>,
        manifest_guard: super::store::ScopedLockGuard<String>,
        stripe_guard: super::SharedFileMutation,
    ) -> Result<oneshot::Receiver<Result<usize>>> {
        let path_bytes = match &mutation {
            PathMutation::Withdraw { path, .. } => withdrawal_path_charge(path)?,
            PathMutation::Admit {
                root,
                path,
                relative,
                ..
            } => {
                let root_bytes = withdrawal_path_charge(root)?;
                let path_bytes = withdrawal_path_charge(path)?;
                let relative_bytes = withdrawal_path_charge(relative)?;
                root_bytes
                    .checked_add(path_bytes)
                    .and_then(|n| n.checked_add(relative_bytes))
                    .ok_or(LocalMutationError::TooLarge)?
            }
        };
        let charge = PUBLICATION_WORKSPACE
            .checked_add(path_bytes)
            .and_then(|n| n.checked_add(hash.len()))
            .ok_or(LocalMutationError::TooLarge)?;
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let mut lease = Self::reserve_unit(&mut state, charge, true, false)?;
        let invalidation = if let PathMutation::Withdraw {
            path,
            queue_rehash: true,
            ..
        } = &mutation
        {
            match runtime.shared_source_invalidations.reserve(
                super::Ed2kSharedSourceInvalidation {
                    file_hash: hash.to_owned(),
                    source_path: path.to_path_buf(),
                },
                &mut lease,
            ) {
                Ok(reservation) => Some(reservation),
                Err(error) => {
                    tracing::debug!(%error, "local invalidation reservation unavailable");
                    return Err(LocalMutationError::Busy.into());
                }
            }
        } else {
            None
        };
        let metadata = runtime.metadata.clone();
        let publication = publication::ContentPublication::new(runtime);
        let root_epoch = Arc::clone(&runtime.category_root_epoch);
        let root_dirty = Arc::clone(&runtime.category_root_dirty);
        let publication_failed = Arc::clone(&runtime.share_publication_failed);
        let demand_revision = Arc::clone(&runtime.shared_publish_demand_revision);
        let demand_notify = Arc::clone(&runtime.shared_publish_demand_notify);
        let hash = hash.to_owned();
        let mutation = match mutation {
            PathMutation::Withdraw { path, expected, .. } => OwnedPathMutation::Withdraw {
                path: path.to_path_buf(),
                expected: expected.cloned(),
            },
            PathMutation::Admit {
                root,
                path,
                relative,
                fingerprint,
                observed_root,
            } => OwnedPathMutation::Admit {
                root: root.to_path_buf(),
                path: path.to_path_buf(),
                relative: relative.to_path_buf(),
                fingerprint: fingerprint.clone(),
                observed_root,
            },
        };
        let (response, receive) = oneshot::channel();
        #[cfg(test)]
        let publication_gate = state.publication_gate.take();
        Self::spawn_unit(&mut state, lease, move |lease| {
            let mut _manifest_guard = Some(manifest_guard);
            let mut _stripe_guard = Some(stripe_guard);
            let mut committed = false;
            let operation = || -> Result<usize> {
                let epoch = root_epoch.load(std::sync::atomic::Ordering::Acquire);
                if !epoch.is_multiple_of(2) {
                    return Err(LocalMutationError::Busy.into());
                }
                let parsed: emulebb_kad_proto::Ed2kHash = hash.parse()?;
                let changed = match mutation {
                    OwnedPathMutation::Withdraw { path, expected } => {
                        let (changed, _, partial) = metadata.withdraw_shared_path_with_projection(
                            &path,
                            &hash,
                            expected.as_ref(),
                        )?;
                        drop(partial);
                        changed
                    }
                    OwnedPathMutation::Admit {
                        root,
                        path,
                        relative,
                        fingerprint,
                        observed_root,
                    } => {
                        let admission = metadata.admit_shared_path_with_projection(
                            &root,
                            &path,
                            &relative,
                            &fingerprint,
                            &hash,
                            observed_root.map(|expected| (root_epoch.as_ref(), expected)),
                        );
                        let admission = match admission {
                            Err(error) if error.is::<emulebb_metadata::ObservedRootChanged>() => {
                                return Err(LocalMutationError::Busy.into());
                            }
                            other => other?,
                        };
                        let Some((entry, partial)) = admission else {
                            return Ok(0);
                        };
                        drop(entry);
                        drop(partial);
                        1
                    }
                };
                committed = true;
                #[cfg(test)]
                if let Some((reached, release)) = publication_gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                publication.publish(
                    parsed,
                    lease,
                    publication::PublicationGuards {
                        content: _manifest_guard.take().unwrap(),
                        stripe: _stripe_guard.take().unwrap(),
                        job: None,
                    },
                )?;
                if changed > 0
                    && let Some(invalidation) = invalidation
                {
                    invalidation.commit()?;
                }
                Ok(changed)
            };
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
            match outcome {
                Ok(result) => {
                    let failed = u8::from(committed && result.is_err());
                    if failed != 0 {
                        root_dirty.store(true, std::sync::atomic::Ordering::Release);
                        publication_failed.store(true, std::sync::atomic::Ordering::Release);
                    }
                    let result = match result {
                        Ok(value) => Ok(value),
                        Err(error) if committed => {
                            tracing::error!(%error, "local mutation committed but publication failed");
                            Err(LocalMutationError::Committed.into())
                        }
                        Err(error) if error.is::<LocalMutationError>() => Err(error),
                        Err(error) => {
                            tracing::warn!(%error, "local mutation failed before commit");
                            Err(LocalMutationError::Storage.into())
                        }
                    };
                    // Wake publishers only once the completed unit's stripe is
                    // readable; otherwise the wake can observe Busy and be lost.
                    drop(_stripe_guard);
                    drop(_manifest_guard);
                    if result.is_ok() {
                        demand_revision.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                        demand_notify.notify_waiters();
                    }
                    let _ = response.send(result);
                    failed
                }
                Err(_) => {
                    root_dirty.store(true, std::sync::atomic::Ordering::Release);
                    publication_failed.store(true, std::sync::atomic::Ordering::Release);
                    let _ = response.send(Err(LocalMutationError::Unknown.into()));
                    2
                }
            }
        });
        Ok(receive)
    }

    pub(super) async fn seal_and_drain(&self) -> Result<()> {
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow!("local mutation registry failed"))?;
            state.sealed = true;
            state.capacity.wake();
        }
        let _gate = self.join_gate.lock().await;
        std::future::poll_fn(|cx| {
            let Ok(mut state) = self.state.lock() else {
                return std::task::Poll::Ready(Err(anyhow!("local mutation registry failed")));
            };
            if let Some(failed) = state.drain_outcome {
                return std::task::Poll::Ready(if failed {
                    Err(anyhow!("local mutation drain failed"))
                } else {
                    Ok(())
                });
            }
            loop {
                match state.tasks.poll_join_next(cx) {
                    std::task::Poll::Pending => {
                        #[cfg(test)]
                        if let Some(sender) = state.drain_pending.take() {
                            let _ = sender.send(());
                        }
                        return std::task::Poll::Pending;
                    }
                    std::task::Poll::Ready(Some(Ok(outcome))) => {
                        state.publication_failed |= outcome == 1;
                        state.faulted |= outcome == 2;
                    }
                    std::task::Poll::Ready(Some(Err(_))) => state.faulted = true,
                    std::task::Poll::Ready(None) => {
                        let failed = state.faulted || state.publication_failed;
                        state.drain_outcome = Some(failed);
                        return std::task::Poll::Ready(if failed {
                            Err(anyhow!("local mutation drain failed"))
                        } else {
                            Ok(())
                        });
                    }
                }
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[cfg(windows)]
    #[test]
    fn unicode_long_path_uses_native_length_not_utf8_length() {
        let legal = "漢".repeat(30_000);
        assert!(legal.len() > 65_536);
        assert!(withdrawal_path_charge(std::path::Path::new(&legal)).is_ok());
        let too_long = "漢".repeat(32_769);
        assert!(withdrawal_path_charge(std::path::Path::new(&too_long)).is_err());
    }

    #[tokio::test]
    async fn long_filesystem_units_leave_publication_slot_and_bytes_until_finished() {
        let registry = LocalMutationRegistry::default();
        let mut releases = Vec::new();
        {
            let mut state = registry.state.lock().unwrap();
            // One prepared representation (separately charged), plus two
            // allocation-sized buffers: all are actual retained blocking tasks.
            for bytes in [0, 1024 * 1024, 1024 * 1024] {
                let lease = LocalMutationRegistry::reserve_long_fs(&mut state, bytes).unwrap();
                let (release, wait) = std::sync::mpsc::channel();
                releases.push(release);
                state.tasks.spawn_blocking(move || {
                    let _lease = lease;
                    wait.recv().unwrap();
                    0
                });
            }
            assert!(LocalMutationRegistry::reserve_long_fs(&mut state, 0).is_err());
            assert_eq!(state.tasks.len(), 3);
            assert_eq!(state.capacity.usage().long_fs_units, 3);
            assert_eq!(state.capacity.usage().bytes, MAX_LONG_FS_BYTES);
        }
        // The worst accepted native path representation is UTF-16 on Windows
        // with three UTF-8 bytes per code unit. Reserve three such paths plus
        // the ordinary publication workspace and content key.
        #[cfg(windows)]
        let largest_path = "漢".repeat(32_768);
        #[cfg(not(windows))]
        let largest_path = "x".repeat(65_536);
        let ordinary = PUBLICATION_WORKSPACE
            + 3 * withdrawal_path_charge(std::path::Path::new(&largest_path)).unwrap()
            + 32;
        let (published, publication) = oneshot::channel();
        {
            let mut state = registry.state.lock().unwrap();
            assert!(state.capacity.usage().bytes + ordinary <= MAX_BYTES);
            assert!(state.tasks.len() < MAX_UNITS);
            let lease =
                LocalMutationRegistry::reserve_unit(&mut state, ordinary, false, false).unwrap();
            state.tasks.spawn_blocking(move || {
                let _lease = lease;
                published.send(()).unwrap();
                0
            });
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), publication)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            registry
                .state
                .lock()
                .unwrap()
                .capacity
                .usage()
                .long_fs_units,
            3
        );
        for release in releases {
            release.send(()).unwrap();
        }
        registry.seal_and_drain().await.unwrap();
        let state = registry.state.lock().unwrap();
        assert_eq!(state.capacity.usage().long_fs_units, 0);
        assert_eq!(state.capacity.usage().long_fs_bytes, 0);
        assert_eq!(state.capacity.usage().bytes, 0);
    }

    #[tokio::test]
    async fn cancelled_drain_keeps_the_blocking_unit_tracked() {
        let registry = Arc::new(LocalMutationRegistry::default());
        let (started, ready) = oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let published = Arc::new(AtomicBool::new(false));
        {
            let mut state = registry.state.lock().unwrap();
            let lease = LocalMutationRegistry::reserve_unit(&mut state, 1, false, false).unwrap();
            let published = Arc::clone(&published);
            state.tasks.spawn_blocking(move || {
                let _lease = lease;
                let _ = started.send(());
                gate.recv().unwrap();
                published.store(true, Ordering::Release);
                0
            });
        }
        ready.await.unwrap();
        let first_pending = registry.signal_next_pending_drain();
        let first = {
            let registry = Arc::clone(&registry);
            tokio::spawn(async move { registry.seal_and_drain().await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), first_pending)
            .await
            .expect("first drain did not reach the pending join")
            .unwrap();
        first.abort();
        let _ = first.await;
        let second_pending = registry.signal_next_pending_drain();
        let second = {
            let registry = Arc::clone(&registry);
            tokio::spawn(async move { registry.seal_and_drain().await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), second_pending)
            .await
            .expect("second drain did not reach the pending join")
            .unwrap();
        assert!(!second.is_finished());
        release.send(()).unwrap();
        second.await.unwrap().unwrap();
        assert!(published.load(Ordering::Acquire));
    }
    #[tokio::test]
    async fn phase_wait_releases_buffers_and_wakes_without_reentering_cancelled_drain() {
        let registry = Arc::new(LocalMutationRegistry::default());
        let (free_fs, held_fs) = std::sync::mpsc::channel();
        let (result_send, result_receive) = oneshot::channel();
        let capacity = Arc::clone(&registry.state.lock().unwrap().capacity);
        let waiting = capacity.phase_wait_signal();
        {
            let mut state = registry.state.lock().unwrap();
            let held =
                LocalMutationRegistry::reserve_long_fs(&mut state, MAX_LONG_FS_BYTES).unwrap();
            state.tasks.spawn_blocking(move || {
                let _lease = held;
                let bytes = vec![0u8; MAX_LONG_FS_BYTES];
                held_fs.recv().unwrap();
                drop(bytes);
                0
            });
            let mut phase =
                LocalMutationRegistry::reserve_unit(&mut state, PUBLICATION_WORKSPACE, true, false)
                    .unwrap();
            state.tasks.spawn_blocking(move || {
                let sql_buffers = vec![0u8; PUBLICATION_WORKSPACE];
                drop(sql_buffers);
                phase
                    .enter_filesystem(128 * 1024, MAX_LONG_FS_BYTES)
                    .unwrap();
                let result = phase.take_result();
                let _ = result_send.send(result);
                0
            });
        }
        waiting.await.unwrap();
        assert_eq!(capacity.usage().bytes, MAX_LONG_FS_BYTES + 128 * 1024);
        assert_eq!(capacity.usage().long_fs_units, 2);
        // A third potentially long unit reserves the final eligible slot;
        // a fourth such admission cannot consume the ordinary headroom.
        let third = {
            let mut state = registry.state.lock().unwrap();
            LocalMutationRegistry::reserve_unit(&mut state, 0, true, false).unwrap()
        };
        assert!(capacity.reserve(0, true, false).is_err());
        let ordinary = capacity
            .reserve(PUBLICATION_WORKSPACE, false, false)
            .unwrap();
        drop(ordinary);
        drop(third);
        let pending = registry.signal_next_pending_drain();
        let drain = {
            let registry = Arc::clone(&registry);
            tokio::spawn(async move { registry.seal_and_drain().await })
        };
        pending.await.unwrap();
        drain.abort();
        let _ = drain.await;
        // Actual worker completion wakes the phase waiter even with no active
        // JoinSet consumer. A recursive join-gate design deadlocks here.
        free_fs.send(()).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), result_receive)
            .await
            .unwrap()
            .unwrap();
        registry.seal_and_drain().await.unwrap();
        assert_eq!(capacity.usage().long_fs_units, 0);
        assert_eq!(capacity.usage().bytes, MAX_LONG_FS_BYTES);
        drop(result);
        assert_eq!(capacity.usage().bytes, 0);
    }
    #[tokio::test]
    async fn maximum_native_invalidation_backing_stays_charged_through_phase_queue_and_ack() {
        use crate::ed2k_transfer::{
            Ed2kSharedSourceInvalidation, Ed2kSharedSourceInvalidationSignal,
        };
        let registry = Arc::new(LocalMutationRegistry::default());
        let signal = Ed2kSharedSourceInvalidationSignal::default();
        let capacity = Arc::clone(&registry.state.lock().unwrap().capacity);
        let waiting = capacity.phase_wait_signal();
        let (free_fs, held_fs) = std::sync::mpsc::channel();
        let (reply, receipt) = oneshot::channel();
        #[cfg(windows)]
        let path = std::path::PathBuf::from("漢".repeat(32_768));
        #[cfg(not(windows))]
        let path = std::path::PathBuf::from("x".repeat(65_536));
        let initial = PUBLICATION_WORKSPACE + withdrawal_path_charge(&path).unwrap() + 32;
        let invalidation = Ed2kSharedSourceInvalidation {
            source_path: path,
            file_hash: "a".repeat(32),
        };
        let native_capacity = invalidation.source_path.capacity();
        let backing = invalidation.backing_bytes().unwrap();
        assert_eq!(
            backing,
            native_capacity
                + invalidation.file_hash.capacity()
                + std::mem::size_of::<Ed2kSharedSourceInvalidation>()
                + 2 * std::mem::size_of::<usize>()
        );
        #[cfg(windows)]
        assert_eq!(native_capacity, 98_304);
        {
            let mut state = registry.state.lock().unwrap();
            let held =
                LocalMutationRegistry::reserve_long_fs(&mut state, MAX_LONG_FS_BYTES).unwrap();
            LocalMutationRegistry::spawn_unit(&mut state, held, move |_| {
                held_fs.recv().unwrap();
                0
            });
            let mut phase =
                LocalMutationRegistry::reserve_unit(&mut state, initial, true, false).unwrap();
            let reservation = signal.reserve(invalidation, &mut phase).unwrap();
            {
                let queued = signal.state.lock().unwrap();
                let owned = &reservation.invalidation.as_ref().unwrap().value;
                let scheduled = queued.scheduled.iter().next().unwrap();
                // The coalescing key shares the same allocation, not a second
                // uncharged native path hidden in the scheduling set.
                assert!(Arc::ptr_eq(owned, scheduled));
                assert_eq!(Arc::strong_count(owned), 2);
                assert!(queued.pending.is_empty());
            }
            LocalMutationRegistry::spawn_unit(&mut state, phase, move |phase| {
                phase
                    .enter_filesystem(128 * 1024, MAX_LONG_FS_BYTES)
                    .unwrap();
                reservation.commit().unwrap();
                let _ = reply.send(());
                0
            });
        }
        waiting.await.unwrap();
        assert_eq!(
            capacity.usage().bytes,
            MAX_LONG_FS_BYTES + 128 * 1024 + backing
        );
        assert_eq!(capacity.usage().long_fs_bytes, MAX_LONG_FS_BYTES);
        assert_eq!(capacity.usage().long_fs_units, 2);
        let third = capacity.reserve(0, true, false).unwrap();
        assert!(capacity.reserve(0, true, false).is_err());
        let ordinary = capacity
            .reserve(PUBLICATION_WORKSPACE, false, false)
            .unwrap();
        drop(ordinary);
        drop(third);
        drop(receipt); // Caller cancellation cannot lose accepted queue ownership.
        let pending = registry.signal_next_pending_drain();
        let drain = {
            let registry = Arc::clone(&registry);
            tokio::spawn(async move { registry.seal_and_drain().await })
        };
        pending.await.unwrap();
        drain.abort();
        let _ = drain.await;
        free_fs.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), registry.seal_and_drain())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(capacity.usage().long_fs_units, 0);
        assert_eq!(capacity.usage().long_fs_bytes, 0);
        assert_eq!(capacity.usage().bytes, backing);
        let event = signal.try_recv().unwrap();
        assert_eq!(event.invalidation().source_path.capacity(), native_capacity);
        assert_eq!(event.invalidation().file_hash, "a".repeat(32));
        drop(event); // Cancelled consumer requeues the same backing and lease.
        assert_eq!(capacity.usage().bytes, backing);
        signal.try_recv().unwrap().acknowledge();
        assert_eq!(capacity.usage().bytes, 0);
        assert!(signal.try_recv().is_none());
        assert!(signal.state.lock().unwrap().scheduled.is_empty());
    }

    #[tokio::test]
    async fn captured_buffers_drop_before_prepared_control_and_capacity_release() {
        struct Captured {
            bytes: Vec<u8>,
            dropped: Arc<AtomicBool>,
        }
        impl Captured {
            fn size(&self) -> usize {
                self.bytes.len()
            }
        }
        impl Drop for Captured {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }
        struct Control {
            dropped: Arc<AtomicBool>,
            capacity: Arc<CapacityControl>,
            done: Option<oneshot::Sender<(bool, usize)>>,
        }
        impl Drop for Control {
            fn drop(&mut self) {
                let _ = self.done.take().unwrap().send((
                    self.dropped.load(Ordering::Acquire),
                    self.capacity.usage().bytes,
                ));
            }
        }
        let registry = LocalMutationRegistry::default();
        let dropped = Arc::new(AtomicBool::new(false));
        let (done, ready) = oneshot::channel();
        {
            let mut state = registry.state.lock().unwrap();
            let lease =
                LocalMutationRegistry::reserve_unit(&mut state, 4096, false, false).unwrap();
            let control = Control {
                dropped: Arc::clone(&dropped),
                capacity: Arc::clone(&state.capacity),
                done: Some(done),
            };
            let captured = Captured {
                bytes: vec![0; 1024],
                dropped,
            };
            LocalMutationRegistry::spawn_unit_with(&mut state, lease, control, move |_, _| {
                assert_eq!(captured.size(), 1024);
                0
            });
        }
        assert_eq!(ready.await.unwrap(), (true, 4096));
        registry.seal_and_drain().await.unwrap();
        assert_eq!(registry.state.lock().unwrap().capacity.usage().bytes, 0);
    }

    #[tokio::test]
    async fn command_receipt_follows_capture_and_workspace_release_but_keeps_result_charged() {
        struct Captured {
            bytes: Vec<u8>,
            capacity: Arc<CapacityControl>,
            observed: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Captured {
            fn len(&self) -> usize {
                self.bytes.len()
            }
        }
        impl Drop for Captured {
            fn drop(&mut self) {
                self.observed
                    .store(self.capacity.usage().bytes, Ordering::Release);
            }
        }
        let registry = LocalMutationRegistry::default();
        let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (sender, receipt) = oneshot::channel();
        {
            let mut state = registry.state.lock().unwrap();
            let lease =
                LocalMutationRegistry::reserve_unit(&mut state, 4096, false, false).unwrap();
            let captured = Captured {
                bytes: vec![0; 1024],
                capacity: Arc::clone(&state.capacity),
                observed: Arc::clone(&observed),
            };
            LocalMutationRegistry::spawn_unit_reply(&mut state, lease, sender, move |lease| {
                assert_eq!(captured.len(), 1024);
                (lease.split_retained_bytes(512).unwrap(), 0)
            });
        }
        let result_lease = receipt.await.unwrap();
        assert_eq!(observed.load(Ordering::Acquire), 4096);
        assert_eq!(registry.state.lock().unwrap().capacity.usage().bytes, 512);
        // The very next command can use all temporary capacity that the prior
        // receipt promises is no longer needed, without a retry or sleep.
        {
            let mut state = registry.state.lock().unwrap();
            let next =
                LocalMutationRegistry::reserve_unit(&mut state, MAX_BYTES - 512, false, false)
                    .unwrap();
            drop(next);
        }
        drop(result_lease);
        registry.seal_and_drain().await.unwrap();
        assert_eq!(registry.state.lock().unwrap().capacity.usage().bytes, 0);
    }
}
