//! Bounded ownership of accepted local-share mutation units.
//!
//! This registry has no worker loop: each admitted blocking unit uses the
//! existing metadata connection and remains tracked until it terminates.

use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow, ensure};
use tokio::{sync::oneshot, task::JoinSet};

const MAX_UNITS: usize = 4;
const MAX_BYTES: usize = 8 * 1024 * 1024;
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

#[derive(Debug, Default)]
pub(super) struct LocalMutationRegistry {
    state: Mutex<State>,
    join_gate: tokio::sync::Mutex<()>,
}

#[derive(Debug, Default)]
struct State {
    sealed: bool,
    faulted: bool,
    publication_failed: bool,
    bytes: usize,
    tasks: JoinSet<(usize, u8)>,
    drain_outcome: Option<bool>,
    #[cfg(test)]
    publication_gate: Option<(oneshot::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    #[cfg(test)]
    drain_pending: Option<oneshot::Sender<()>>,
    #[cfg(test)]
    wait_pending: Option<oneshot::Sender<()>>,
}

impl LocalMutationRegistry {
    /// Wait for an admitted unit to actually finish; callers retain only their
    /// current bounded event and hold no registry or invalidation reservation.
    pub(super) async fn wait_for_completion(&self) -> Result<()> {
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
            match state.tasks.poll_join_next(cx) {
                std::task::Poll::Pending => {
                    #[cfg(test)]
                    if let Some(sender) = state.wait_pending.take() {
                        let _ = sender.send(());
                    }
                    std::task::Poll::Pending
                }
                std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
                std::task::Poll::Ready(Some(Ok((bytes, outcome)))) => {
                    state.bytes -= bytes;
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
        // Keep the full charge until the completed unit is reaped; it is a
        // conservative reservation even after its owned buffers have dropped.
        while let Some(result) = state.tasks.try_join_next() {
            match result {
                Ok((bytes, outcome)) => {
                    state.bytes -= bytes;
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
        manifest_guard: tokio::sync::OwnedMutexGuard<()>,
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
        manifest_guard: tokio::sync::OwnedMutexGuard<()>,
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
        manifest_guard: tokio::sync::OwnedMutexGuard<()>,
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
        if state.sealed {
            return Err(LocalMutationError::Closing.into());
        }
        if state.faulted {
            return Err(LocalMutationError::Unknown.into());
        }
        if state.tasks.len() >= MAX_UNITS
            || state
                .bytes
                .checked_add(charge)
                .is_none_or(|n| n > MAX_BYTES)
        {
            return Err(LocalMutationError::Busy.into());
        }
        state.bytes += charge;
        let invalidation = if let PathMutation::Withdraw {
            path,
            queue_rehash: true,
            ..
        } = &mutation
        {
            match runtime
                .shared_source_invalidations
                .reserve(super::Ed2kSharedSourceInvalidation {
                    file_hash: hash.to_owned(),
                    source_path: path.to_path_buf(),
                }) {
                Ok(reservation) => Some(reservation),
                Err(error) => {
                    state.bytes -= charge;
                    tracing::debug!(%error, "local invalidation reservation unavailable");
                    return Err(LocalMutationError::Busy.into());
                }
            }
        } else {
            None
        };
        let metadata = runtime.metadata.clone();
        let catalog = Arc::clone(&runtime.shared_catalog);
        let manifests = Arc::clone(&runtime.manifest_cache);
        let root_epoch = Arc::clone(&runtime.category_root_epoch);
        let root_dirty = Arc::clone(&runtime.category_root_dirty);
        let publication_failed = Arc::clone(&runtime.share_publication_failed);
        let generation = Arc::clone(&runtime.shared_catalog_generation);
        let hashes = Arc::clone(&runtime.servable_shared_hash_cache);
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
        state.tasks.spawn_blocking(move || {
            let _manifest_guard = manifest_guard;
            let _stripe_guard = stripe_guard;
            let mut committed = false;
            let operation = || {
                let epoch = root_epoch.load(std::sync::atomic::Ordering::Acquire);
                if epoch % 2 != 0 { return Err(LocalMutationError::Busy.into()); }
                let cached_partial = {
                    let cache = manifests.blocking_lock();
                    match cache.get(&hash) {
                        Some(manifest)
                            if !manifest.completed
                                && !manifest.final_rehash_pending
                                && manifest.md4_hashset_acquired
                                && !manifest.transfer_row_removed
                                && !manifest.verified_ranges.is_empty() =>
                        {
                            ensure!(
                                manifest.display_name.len() <= 65_536
                                    && manifest.comment.len() <= 65_536
                                    && manifest.upload_priority.len() <= 65_536
                                    && manifest.aich_root.as_ref().is_none_or(|root| root.len() <= 40)
                                    && manifest.verified_ranges.len() <= 28_258
                                    && manifest.file_size <= 0x4000000000,
                                "live partial projection exceeds bound"
                            );
                            Some(Some(emulebb_metadata::MetadataPartialShare {
                                    file_hash: hash.clone(),
                                    display_name: manifest.display_name.clone(),
                                    file_size: manifest.file_size,
                                    aich_root: manifest.aich_root.clone(),
                                    upload_priority: manifest.upload_priority.clone(),
                                    auto_upload_priority: manifest.auto_upload_priority,
                                    comment: manifest.comment.clone(),
                                    rating: manifest.rating,
                                    ranges: manifest
                                        .verified_ranges
                                        .iter()
                                        .map(|range| emulebb_metadata::MetadataTransferRange {
                                            start: range.start,
                                            end: range.end,
                                        })
                                        .collect(),
                                }))
                        }
                        Some(_) => Some(None),
                        None => None,
                    }
                };
                let cached_partial = cached_partial.map(|partial| {
                    partial.map(super::Ed2kSharedEntry::from_partial_share)
                });
                let parsed: emulebb_kad_proto::Ed2kHash = hash.parse()?;
                let (changed, complete_entry, complete, stored_partial) = match mutation {
                    OwnedPathMutation::Withdraw { path, expected } => {
                        let (changed, complete, partial) = metadata
                            .withdraw_shared_path_with_projection(&path, &hash, expected.as_ref())?;
                        (changed, None, complete, partial)
                    }
                    OwnedPathMutation::Admit { root, path, relative, fingerprint, observed_root } => {
                        let admission = metadata.admit_shared_path_with_projection(
                            &root, &path, &relative, &fingerprint, &hash,
                            observed_root.map(|expected| (root_epoch.as_ref(), expected)),
                        );
                        let admission = match admission {
                            Err(error) if error.is::<emulebb_metadata::ObservedRootChanged>() => return Err(LocalMutationError::Busy.into()),
                            other => other?,
                        };
                        let Some((entry, partial)) = admission else {
                            return Ok(0);
                        };
                        committed = true;
                        // The exact admitted path supplies the complete entry; a
                        // representative-path query could select an unverified copy.
                        let entry = super::transfer_sql::shared_entry_from_catalog_entry(entry)?;
                        (1, Some(entry), true, partial)
                    }
                };
                committed = true;
                #[cfg(test)]
                if let Some((reached, release)) = publication_gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                let mut projection = Some((complete, stored_partial));
                let mut projection_epoch = epoch;
                for _ in 0..100 {
                    let current_epoch = root_epoch.load(std::sync::atomic::Ordering::Acquire);
                    if current_epoch % 2 != 0 {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    if projection.is_none() || current_epoch != projection_epoch {
                        projection = Some(metadata.shared_path_projection(&hash)?);
                        projection_epoch = current_epoch;
                    }
                    let (complete, stored_partial) =
                        projection.take().expect("current share projection");
                    // Build bounded replacements before taking the catalog lock.
                    let mut replacement = if complete {
                        complete_entry.clone()
                    } else {
                        cached_partial.clone().unwrap_or_else(|| {
                            stored_partial.map(super::Ed2kSharedEntry::from_partial_share)
                        })
                    };
                    let mut entries = catalog.blocking_write();
                    if root_epoch.load(std::sync::atomic::Ordering::Acquire) != projection_epoch {
                        projection = None;
                        drop(entries);
                        continue;
                    }
                    if complete && complete_entry.is_none() {
                        ensure!(
                            entries
                                .entry_by_hash(&parsed)
                                .is_some_and(|entry| entry.verified_complete),
                            "local withdrawal committed without a complete catalog entry"
                        );
                    } else {
                        if let (Some(current), Some(next)) =
                            (entries.entry_by_hash(&parsed), replacement.as_mut())
                        {
                            next.publish = current.publish.clone();
                            next.all_time_uploaded_bytes = current.all_time_uploaded_bytes;
                        }
                        entries.upsert_verified(parsed, replacement);
                        generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                        hashes
                            .lock()
                            .map_err(|_| anyhow!("share cache lock poisoned"))?
                            .hashes = None;
                    }
                    drop(entries);
                    if changed > 0 {
                        if let Some(invalidation) = invalidation { invalidation.commit()?; }
                    }
                    return Ok(changed);
                }
                Err(anyhow!(
                    "local mutation committed but root publication could not stabilize"
                ))
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
                        Err(error) if committed => { tracing::error!(%error, "local mutation committed but publication failed"); Err(LocalMutationError::Committed.into()) },
                        Err(error) if error.is::<LocalMutationError>() => Err(error),
                        Err(error) => { tracing::warn!(%error, "local mutation failed before commit"); Err(LocalMutationError::Storage.into()) },
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
                    (charge, failed)
                }
                Err(_) => {
                    root_dirty.store(true, std::sync::atomic::Ordering::Release);
                    publication_failed.store(true, std::sync::atomic::Ordering::Release);
                    let _ = response.send(Err(LocalMutationError::Unknown.into()));
                    (charge, 2)
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
                    std::task::Poll::Ready(Some(Ok((bytes, outcome)))) => {
                        state.bytes -= bytes;
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
    async fn cancelled_drain_keeps_the_blocking_unit_tracked() {
        let registry = Arc::new(LocalMutationRegistry::default());
        let (started, ready) = oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let published = Arc::new(AtomicBool::new(false));
        {
            let mut state = registry.state.lock().unwrap();
            state.bytes = 1;
            let published = Arc::clone(&published);
            state.tasks.spawn_blocking(move || {
                let _ = started.send(());
                gate.recv().unwrap();
                published.store(true, Ordering::Release);
                (1, 0)
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
}
