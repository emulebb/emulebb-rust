//! Live shared-directory monitoring (auto-pickup) for the configured shared
//! roots (eMule's `CSharedFileList` directory auto-monitor parity).
//!
//! # Design
//!
//! The OS file-system watcher (`notify`) is inherently blocking/callback driven
//! and runs on its **own thread**; the rest of the core is async (tokio). We
//! bridge the two with the established pattern:
//!
//! ```text
//!   notify watcher thread --(debounced batches)--> bounded mpsc --> tokio consumer task
//! ```
//!
//! * **Debouncing.** A single logical change (a file copied in, an editor's
//!   save-and-rename, a directory delete) produces a *burst* of raw FS events.
//!   We run the events through `notify-debouncer-full`, which collapses a burst
//!   into settled events. The settle window also means we never act on a file
//!   that is still being written: we only hash it once its events have settled.
//! * **Recursive per root.** Each configured root is watched recursively,
//!   matching the manual full-tree scan.
//! * **Thread -> channel -> tokio bridge.** The debouncer's event handler is a
//!   small closure that classifies the settled events into [`MonitorAction`]s
//!   (the pure decision -- share vs. remove) and forwards them over a bounded
//!   `tokio::sync::mpsc` channel. Overflow collapses into one authoritative
//!   reconciliation request instead of accumulating unbounded path work. The
//!   async consumer applies each action via the existing share / un-share core
//!   paths so MD4/AICH/catalog stay consistent.
//! * **Graceful degradation.** Watching one root can fail (a vanished path; on
//!   Linux a large recursive tree can exhaust the inotify watch limit). We log
//!   and continue with the other roots rather than crashing the daemon: that
//!   root simply degrades to scan-on-demand (the manual
//!   `reload_shared_directories` fallback still covers it).
//!
//! The OS watcher itself is impossible to unit-test deterministically, so the
//! testable seam is [`classify_event`] / [`actions_for_events`]: given a settled
//! debounced event, decide whether it means *share this path* or *drop this
//! path*. The tests exercise that decision plus the consumer's in-order
//! forwarding to the applier, which is the single authority on whether a
//! Share/Remove actually has an effect.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use notify_debouncer_full::notify::event::{ModifyKind, RenameMode};
use notify_debouncer_full::notify::{EventKind, RecursiveMode};
use notify_debouncer_full::{
    DebounceEventResult, DebouncedEvent, Debouncer, RecommendedCache, new_debouncer,
};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::shared_directories::{SharedDirectoryRoot, load_shared_file_exclusion_policy};

/// Settle window before a burst of raw FS events for one logical change is
/// emitted as a settled event. Long enough that a file copied in is fully
/// written before we hash it, short enough that auto-pickup still feels live.
/// (eMule re-scans shared dirs on a coarse timer; a 2s settle is well within
/// that responsiveness while avoiding mid-write hashing.)
const SETTLE_WINDOW: Duration = Duration::from_secs(2);

/// Maximum settled path actions retained while the serial async applier is
/// busy. Normal bursts stay on the direct path; larger bursts collapse into a
/// full reconciliation so memory use is independent of watcher event volume.
const ACTION_CHANNEL_CAPACITY: usize = 256;

const TARGETED_REHASH_DEBOUNCE: Duration = Duration::from_secs(2);
const TARGETED_REHASH_RETRY_DELAY: Duration = Duration::from_secs(2);
const TARGETED_REHASH_MAX_ATTEMPTS: usize = 3;

/// `notify` 8.x uses one fixed 16 KiB `ReadDirectoryChangesW` buffer for a
/// recursive Windows watch. Even a modest settled mutation burst can mean an
/// earlier buffer overflow was silently dropped (renames are especially costly
/// because they contribute old-name and new-name records). Follow such a burst
/// with one incremental scan. A single-file operation keeps the direct fast
/// path; two settled actions are enough to protect against the very short tail
/// that Windows can deliver after discarding an overflowed buffer.
#[cfg(target_os = "windows")]
const WINDOWS_EVENT_BURST_RECONCILE_THRESHOLD: usize = 2;

/// The decision distilled from a settled debounced event: what the consumer
/// should do with a given path. This is the pure, unit-testable core of the
/// monitor (the OS watcher around it cannot be tested deterministically).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MonitorAction {
    /// A file appeared or changed under a shared root -- (re)share it. Sharing an
    /// already-shared identical file is a cheap no-op (the ingest path is keyed
    /// by content hash), so re-sharing is safe.
    Share(PathBuf),
    /// A file was removed or renamed away from under a shared root -- drop it
    /// from the shared catalog.
    Remove(PathBuf),
    /// A file moved within a watched tree. Content identity is preserved, so
    /// the applier can relocate the persisted source path without rehashing.
    Rename { from: PathBuf, to: PathBuf },
    /// The backend reported only one side of a rename. Reconcile the complete
    /// configured tree because an OS watcher buffer may have dropped adjacent
    /// events from the same burst.
    Reconcile,
}

/// Classify a single settled debounced event into zero or more actions.
///
/// `notify`'s settled event kinds map cleanly onto our three intents:
/// * `Create` / `Modify(Data|Any|Metadata)` -> the path now holds content we
///   should share.
/// * `Remove` -> the path no longer holds the content it had, so drop it.
/// * A paired rename carries `[from, to]`: relocate the source identity without
///   rehashing unchanged content.
/// * An unpaired rename requests one incremental reconciliation scan. It may be
///   a legitimate move across the watch boundary, or evidence that the native
///   watcher dropped the other side of a larger burst.
///
/// We intentionally do not try to stat the path here (it may already be gone for
/// a remove, or still settling); the consumer decides share-vs-skip when it
/// actually touches the filesystem.
pub(crate) fn classify_event(event: &DebouncedEvent) -> Vec<MonitorAction> {
    if event.need_rescan() {
        return vec![MonitorAction::Reconcile];
    }
    // Map every path of the event to the same action variant.
    let map_paths = |variant: fn(PathBuf) -> MonitorAction| -> Vec<MonitorAction> {
        event.paths.iter().cloned().map(variant).collect()
    };
    match event.kind {
        EventKind::Create(_)
        | EventKind::Modify(
            ModifyKind::Data(_) | ModifyKind::Metadata(_) | ModifyKind::Any | ModifyKind::Other,
        ) => map_paths(MonitorAction::Share),
        EventKind::Modify(ModifyKind::Name(rename_mode)) => match rename_mode {
            // A paired rename preserves file identity and must not be expanded
            // into unshare + full re-ingest for a large library.
            RenameMode::Both => match (event.paths.first(), event.paths.get(1)) {
                (Some(from), Some(to)) => vec![MonitorAction::Rename {
                    from: from.clone(),
                    to: to.clone(),
                }],
                _ => Vec::new(),
            },
            // An unpaired rename is also the only portable signal left after
            // a native watcher buffer overflow. A full incremental scan is
            // required to discover every path the kernel could not report.
            RenameMode::To | RenameMode::From => vec![MonitorAction::Reconcile],
            // Some backends label a paired [from, to] event as Any/Other. Keep
            // that pair when present; a single ambiguous path needs the same
            // reconciliation safety net as an unpaired From/To event.
            RenameMode::Any | RenameMode::Other => {
                match (event.paths.first(), event.paths.get(1)) {
                    (Some(from), Some(to)) => vec![MonitorAction::Rename {
                        from: from.clone(),
                        to: to.clone(),
                    }],
                    _ => vec![MonitorAction::Reconcile],
                }
            }
        },
        EventKind::Remove(_) => map_paths(MonitorAction::Remove),
        // Access / Other / Any: no shared-catalog consequence.
        EventKind::Access(_) | EventKind::Other | EventKind::Any => Vec::new(),
    }
}

/// Flatten a settled batch of debounced events into the ordered action list.
pub(crate) fn actions_for_events(events: &[DebouncedEvent]) -> Vec<MonitorAction> {
    let actions = events.iter().flat_map(classify_event).collect::<Vec<_>>();
    #[cfg(target_os = "windows")]
    {
        let mut actions = actions;
        let catalog_action_count = actions
            .iter()
            .filter(|action| !matches!(action, MonitorAction::Reconcile))
            .count();
        if catalog_action_count >= WINDOWS_EVENT_BURST_RECONCILE_THRESHOLD {
            actions.push(MonitorAction::Reconcile);
        }
        actions
    }
    #[cfg(not(target_os = "windows"))]
    {
        actions
    }
}

/// Collapse a queued event burst to the final intent for each path.
///
/// Large copies and in-place rewrites can produce several settled events for
/// the same file while the serial hashing consumer is busy. Keeping only the
/// last intent avoids redundant full-file reads and also bounds the pending
/// work to the number of distinct paths. Paired renames remain atomic actions;
/// duplicate pairs and reconciliation requests are collapsed independently
/// from final per-path intents.
fn coalesce_actions(actions: Vec<MonitorAction>) -> Vec<MonitorAction> {
    let mut by_path: HashMap<PathBuf, (usize, MonitorAction)> = HashMap::new();
    let mut renames: HashMap<(PathBuf, PathBuf), (usize, MonitorAction)> = HashMap::new();
    let mut reconcile = None;
    for (sequence, action) in actions.into_iter().enumerate() {
        match &action {
            MonitorAction::Share(path) | MonitorAction::Remove(path) => {
                by_path.insert(path.clone(), (sequence, action));
            }
            MonitorAction::Rename { from, to } => {
                renames.insert((from.clone(), to.clone()), (sequence, action));
            }
            MonitorAction::Reconcile => reconcile = Some((sequence, action)),
        }
    }
    // Reconciliation is the sole authority for a burst. Running the individual
    // actions beside a detached reload can interleave two catalog writers and
    // leave the durable rows ahead of the in-memory catalog. The full scan sees
    // the final settled filesystem state, so the per-path work is redundant.
    if reconcile.is_some() {
        return vec![MonitorAction::Reconcile];
    }
    // A backend can emit a paired rename plus a redundant destination Modify.
    // Relocation already compares the final destination identity and rehashes
    // it when needed, so a Share for either endpoint would only race relocation
    // and create a duplicate source row. A final Remove for the destination is
    // retained because rename-then-delete is a distinct settled outcome.
    for (_, action) in renames.values() {
        let MonitorAction::Rename { from, to } = action else {
            unreachable!("rename map contains only rename actions");
        };
        by_path.remove(from);
        if by_path
            .get(to)
            .is_some_and(|(_, action)| matches!(action, MonitorAction::Share(_)))
        {
            by_path.remove(to);
        }
    }
    let mut coalesced = by_path.into_values().collect::<Vec<_>>();
    coalesced.extend(renames.into_values());
    coalesced.extend(reconcile);
    coalesced.sort_by_key(|(sequence, _)| *sequence);
    coalesced.into_iter().map(|(_, action)| action).collect()
}

/// Non-blocking ingress from the watcher callback into the async consumer.
///
/// Once the bounded queue fills, the first overflow latches a reconciliation
/// request. Further callbacks skip redundant path actions until the consumer
/// drains the queue and takes ownership of that request. The filesystem scan
/// then observes the authoritative final state for every skipped action.
struct MonitorIngress {
    action_tx: Sender<MonitorAction>,
    reconcile_required: Arc<AtomicBool>,
}

impl MonitorIngress {
    fn try_send_actions(&self, actions: impl IntoIterator<Item = MonitorAction>) {
        if self.reconcile_required.load(Ordering::Acquire) {
            return;
        }

        for action in actions {
            match self.action_tx.try_send(action) {
                Ok(()) => {}
                Err(TrySendError::Closed(_)) => return,
                Err(TrySendError::Full(_)) => {
                    // WHY: blocking the notify callback can stall the platform
                    // watcher, while retaining every path permits remote/local
                    // mutation bursts to grow memory without bound. One full
                    // scan preserves eventual final intent for the whole burst.
                    if !self.reconcile_required.swap(true, Ordering::AcqRel) {
                        tracing::warn!(
                            capacity = ACTION_CHANNEL_CAPACITY,
                            "shared-directory watcher ingress overflowed; scheduling reconciliation",
                        );
                    }
                    return;
                }
            }
        }
    }
}

fn monitor_action_channel(
    capacity: usize,
) -> (MonitorIngress, Receiver<MonitorAction>, Arc<AtomicBool>) {
    let (action_tx, action_rx) = tokio::sync::mpsc::channel(capacity);
    let reconcile_required = Arc::new(AtomicBool::new(false));
    (
        MonitorIngress {
            action_tx,
            reconcile_required: Arc::clone(&reconcile_required),
        },
        action_rx,
        reconcile_required,
    )
}

/// Handle to a running shared-directory monitor.
///
/// Owns the `notify` debouncer (its `Drop` stops the watcher thread) and the
/// `JoinHandle` of the tokio consumer task. Dropping or [`stop`](Self::stop)ing
/// it tears both down so neither the watcher thread nor the consumer task leaks
/// across a disconnect / reconfigure.
pub(crate) struct SharedDirMonitor {
    /// Held purely for its RAII `Drop`: dropping the debouncer stops/joins the
    /// OS watcher thread. Never read after construction (the watch set is fixed
    /// at start), hence the allow.
    _debouncer: Debouncer<notify_debouncer_full::notify::RecommendedWatcher, RecommendedCache>,
    consumer: tokio::task::JoinHandle<()>,
}

impl SharedDirMonitor {
    /// Stop the monitor: drop it so the debouncer's `Drop` stops the OS watcher
    /// thread and the [`SharedDirMonitor`] `Drop` aborts the consumer task.
    pub(crate) fn stop(self) {
        // Explicit drop documents intent; the Drop impl does the teardown.
        drop(self);
    }
}

impl Drop for SharedDirMonitor {
    fn drop(&mut self) {
        // If the monitor is dropped without an explicit stop (e.g. the holding
        // Option is replaced), still abort the consumer task so it does not leak.
        // The debouncer's own Drop stops the watcher thread.
        self.consumer.abort();
    }
}

/// Spawn the watcher + consumer for the given roots.
///
/// `apply` receives each [`MonitorAction`] and applies it (share / remove) on
/// the async side; it is the bridge back into the core's existing share / unshare
/// paths. Returns `None` only when *no* root could be watched (all failed) -- in
/// that case the daemon falls back entirely to scan-on-demand. A partial success
/// (some roots watched, some failed) still returns a monitor for the ones that
/// worked.
pub(crate) fn start_monitor<F, Fut>(
    roots: &[SharedDirectoryRoot],
    apply: F,
) -> Option<SharedDirMonitor>
where
    F: Fn(MonitorAction) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    if roots.is_empty() {
        return None;
    }

    // notify watcher thread -> tokio consumer bridge. The debouncer's event
    // handler runs on the watcher thread; it must not block. A full bounded
    // queue therefore latches one authoritative reconciliation instead of
    // waiting or retaining unbounded per-path work.
    let (ingress, action_rx, reconcile_required) = monitor_action_channel(ACTION_CHANNEL_CAPACITY);

    let handler = move |result: DebounceEventResult| match result {
        Ok(events) => {
            ingress.try_send_actions(coalesce_actions(actions_for_events(&events)));
        }
        Err(errors) => {
            for error in errors {
                tracing::warn!(error = %error, "shared-directory watcher reported an error");
            }
        }
    };

    let mut debouncer = match new_debouncer(SETTLE_WINDOW, None, handler) {
        Ok(debouncer) => debouncer,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "failed to create shared-directory watcher; auto-pickup disabled (scan-on-demand still works)",
            );
            return None;
        }
    };

    let mut watched_root_count = 0usize;
    for root in roots {
        if !root.accessible {
            continue;
        }
        let path = Path::new(&root.path);
        match debouncer.watch(path, RecursiveMode::Recursive) {
            Ok(()) => {
                // notify-debouncer-full 0.7 manages the file-id cache roots
                // together with the watcher registration.
                watched_root_count += 1;
                tracing::info!(
                    root = %root.path,
                    "watching shared directory for auto-pickup",
                );
            }
            Err(error) => {
                // Graceful degradation: one unwatchable root (vanished path, or
                // on Linux the inotify watch limit on a huge recursive tree) must
                // not crash the daemon. Log and continue; that root degrades to
                // scan-on-demand via reload_shared_directories.
                tracing::warn!(
                    root = %root.path,
                    error = %error,
                    "failed to watch shared directory; degrading it to scan-on-demand",
                );
            }
        }
    }

    if watched_root_count == 0 {
        // No root could be watched -- nothing to consume; drop the debouncer.
        drop(debouncer);
        return None;
    }

    let consumer = tokio::spawn(run_consumer(action_rx, reconcile_required, apply));
    Some(SharedDirMonitor {
        _debouncer: debouncer,
        consumer,
    })
}

/// Consume settled actions and apply them in order.
///
/// The consumer drains all immediately queued actions into one coalesced burst
/// before forwarding the final intent for each distinct path to the applier.
/// The applier is the single authority: a `Share` goes through the (cheap,
/// hash-keyed) ingest path, a `Remove` resolves the vanished path's hash, and a
/// paired `Rename` moves the source identity without hashing. Resolution uses
/// the core's `monitor_shared_hashes` map -- which records BOTH files
/// the live monitor picked up AND the shares created by the initial startup
/// reload -- and no-ops when the path was never shared.
///
/// A consumer-local "have I shared this path?" set was previously used to skip
/// removes of never-shared paths, but it could only ever have seen shares the
/// live monitor itself applied. That made it wrongly swallow a `Remove` for a
/// file the startup reload had shared, leaving a deleted file offered/published
/// until a manual reload. Keeping the gate solely in the applier (against the
/// authoritative `monitor_shared_hashes` map) is what closes that gap, without
/// two maps redundantly tracking the same "is this shared?" question. Burst
/// coalescing is intentionally stateless: the applier remains authoritative.
async fn run_consumer<F, Fut>(
    mut action_rx: Receiver<MonitorAction>,
    reconcile_required: Arc<AtomicBool>,
    apply: F,
) where
    F: Fn(MonitorAction) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    while let Some(first) = action_rx.recv().await {
        let mut pending = vec![first];
        while let Ok(action) = action_rx.try_recv() {
            pending.push(action);
        }

        if reconcile_required.load(Ordering::Acquire) {
            // Keep the latch set while draining so watcher callbacks continue
            // collapsing into this same authoritative scan. Clearing it before
            // the await lets events that happen during reconciliation queue for
            // a subsequent final-intent pass.
            while action_rx.try_recv().is_ok() {}
            reconcile_required.store(false, Ordering::Release);
            apply(MonitorAction::Reconcile).await;
            continue;
        }

        for action in coalesce_actions(pending) {
            apply(action).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Core orchestration (kept out of lib.rs to respect its frozen line budget).
//
// These free functions take `&EmulebbCore` and drive the monitor lifecycle plus
// the auto-share / auto-remove application of monitor actions. They access the
// core's private `state` / `shared_dir_monitor` fields directly (a child module
// may read its ancestor's private items) and reuse the public `share_local_file`
// / `unshare_file` ingest/catalog paths so MD4/AICH/catalog stay consistent.
// ---------------------------------------------------------------------------

use emulebb_ed2k::ed2k_transfer::{
    Ed2kSharedSourceInvalidation, Ed2kSharedSourceInvalidationSignal,
};
use emulebb_ed2k::long_path::long_path;

use crate::EmulebbCore;
use crate::shared_directories::{
    forget_stale_shares, refresh_shared_directory_row, register_monitor_shared_hash,
};

/// Canonical key for the `monitor_shared_hashes` source-path -> hash map.
///
/// The live watcher reports raw paths (it watches the raw configured root),
/// while the startup reload walks the root through [`long_path`] and so sees the
/// verbatim (`\\?\`) form. Both the auto-share/auto-remove sites here and the
/// reload registration route their path through [`long_path`] (idempotent: a
/// verbatim path stays verbatim) so a startup share and a later live Remove of
/// the same file resolve to the SAME key regardless of which side observed it.
fn monitor_shared_key(path: &Path) -> PathBuf {
    long_path(path)
}

#[derive(Debug, Clone, Copy)]
struct TargetedRehashPolicy {
    debounce: Duration,
    retry_delay: Duration,
    max_attempts: usize,
}

impl Default for TargetedRehashPolicy {
    fn default() -> Self {
        Self {
            debounce: TARGETED_REHASH_DEBOUNCE,
            retry_delay: TARGETED_REHASH_RETRY_DELAY,
            max_attempts: TARGETED_REHASH_MAX_ATTEMPTS,
        }
    }
}

enum TargetedRehashOutcome {
    Complete,
    Retry(anyhow::Error),
}

fn start_shared_source_reconcile_worker(core: &EmulebbCore) {
    let mut worker = core.shared_source_reconcile_worker.lock().unwrap();
    if worker.as_ref().is_some_and(|worker| !worker.is_finished()) {
        return;
    }
    if let Some(finished) = worker.take() {
        finished.abort();
    }
    let signal = core.ed2k_transfers.shared_source_invalidation_signal();
    let reconciler = core.clone();
    *worker = Some(tokio::spawn(run_shared_source_reconcile_worker(
        reconciler,
        signal,
        TargetedRehashPolicy::default(),
    )));
}

async fn run_shared_source_reconcile_worker(
    core: EmulebbCore,
    signal: Ed2kSharedSourceInvalidationSignal,
    policy: TargetedRehashPolicy,
) {
    loop {
        let lease = signal.recv().await;
        let invalidation = lease.invalidation().clone();
        if !policy.debounce.is_zero() {
            tokio::time::sleep(policy.debounce).await;
        }

        let attempts = policy.max_attempts.max(1);
        if let Err(error) = run_targeted_rehash_attempts(policy, || {
            reconcile_invalidated_shared_source(&core, &invalidation)
        })
        .await
        {
            tracing::warn!(
                path = %invalidation.source_path.display(),
                stale_hash = %invalidation.file_hash,
                attempts,
                error = %error,
                "targeted shared-source reconciliation exhausted its retry budget",
            );
        }
        lease.acknowledge();
    }
}

async fn run_targeted_rehash_attempts<F, Fut>(
    policy: TargetedRehashPolicy,
    mut reconcile: F,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = TargetedRehashOutcome>,
{
    let max_attempts = policy.max_attempts.max(1);
    for attempt in 1..=max_attempts {
        match reconcile().await {
            TargetedRehashOutcome::Complete => return Ok(()),
            TargetedRehashOutcome::Retry(_error) if attempt < max_attempts => {
                let delay = policy.retry_delay.saturating_mul(attempt as u32);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
            TargetedRehashOutcome::Retry(error) => return Err(error),
        }
    }
    unreachable!("the targeted re-hash attempt loop always returns")
}

async fn reconcile_invalidated_shared_source(
    core: &EmulebbCore,
    invalidation: &Ed2kSharedSourceInvalidation,
) -> TargetedRehashOutcome {
    let key = monitor_shared_key(&invalidation.source_path);
    let metadata = match tokio::fs::metadata(&key).await {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => {
            return finish_unavailable_invalidated_source(core, invalidation, &key).await;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return finish_unavailable_invalidated_source(core, invalidation, &key).await;
        }
        Err(error) => {
            return TargetedRehashOutcome::Retry(anyhow::Error::new(error).context(format!(
                "failed to inspect invalidated shared source {}",
                key.display()
            )));
        }
    };

    match load_shared_file_exclusion_policy(core) {
        Ok(policy) if policy.should_ignore(&key, &metadata) => {
            return finish_unavailable_invalidated_source(core, invalidation, &key).await;
        }
        Ok(_) => {}
        Err(error) => return TargetedRehashOutcome::Retry(error),
    }

    let (_, _file_size, source_fingerprint) =
        emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime::scanned_source_identity_from_metadata(
            &key, &metadata,
        );
    match core
        .share_native_local_file_with_progress(&key, None, None)
        .await
    {
        Ok(share) => {
            let replaced =
                register_monitor_shared_hash(core, key, &share.hash, source_fingerprint).await;
            let mut stale_hashes = vec![invalidation.file_hash.clone()];
            if let Some(replaced) = replaced
                && !stale_hashes
                    .iter()
                    .any(|hash| hash.eq_ignore_ascii_case(&replaced.hash))
            {
                stale_hashes.push(replaced.hash);
            }
            for stale_hash in stale_hashes {
                if stale_hash.eq_ignore_ascii_case(&share.hash) {
                    continue;
                }
                match stale_hash_is_still_present(core, &stale_hash).await {
                    Ok(true) => {}
                    Ok(false) => forget_stale_shares(core, &[stale_hash], &share.hash).await,
                    Err(error) => return TargetedRehashOutcome::Retry(error),
                }
            }
            tracing::info!(
                path = %invalidation.source_path.display(),
                stale_hash = %invalidation.file_hash,
                new_hash = %share.hash,
                "re-hashed invalidated shared source",
            );
            TargetedRehashOutcome::Complete
        }
        Err(error) => TargetedRehashOutcome::Retry(error),
    }
}

async fn finish_unavailable_invalidated_source(
    core: &EmulebbCore,
    invalidation: &Ed2kSharedSourceInvalidation,
    key: &Path,
) -> TargetedRehashOutcome {
    {
        let mut state = core.state.lock().await;
        if state
            .monitor_shared_hashes
            .get(key)
            .is_some_and(|entry| entry.hash.eq_ignore_ascii_case(&invalidation.file_hash))
        {
            state.monitor_shared_hashes.remove(key);
        }
    }
    match stale_hash_is_still_present(core, &invalidation.file_hash).await {
        Ok(true) => TargetedRehashOutcome::Complete,
        Ok(false) => {
            forget_stale_shares(core, &[invalidation.file_hash.clone()], "").await;
            TargetedRehashOutcome::Complete
        }
        Err(error) => TargetedRehashOutcome::Retry(error),
    }
}

async fn stale_hash_is_still_present(core: &EmulebbCore, file_hash: &str) -> anyhow::Result<bool> {
    if core
        .state
        .lock()
        .await
        .monitor_shared_hashes
        .values()
        .any(|entry| entry.hash.eq_ignore_ascii_case(file_hash))
    {
        return Ok(true);
    }
    core.ed2k_transfers
        .has_present_shared_source(file_hash)
        .await
}

/// (Re)start the live shared-directory auto-pickup monitor for the configured
/// roots. Tears down any previous monitor first, then watches each accessible
/// root recursively. On a settled create/modify the file is
/// auto-shared via [`EmulebbCore::share_local_file`]; on a settled
/// remove/rename-away it is dropped from the shared catalog. Tolerant of a
/// per-root watch failure (logged; that root degrades to scan-on-demand).
pub(crate) async fn start_shared_directory_monitor(core: &EmulebbCore) {
    // Drop any existing monitor before rebuilding the watch set.
    stop_shared_directory_monitor(core);
    start_shared_source_reconcile_worker(core);

    let roots = core.state.lock().await.shared_directories.clone();
    let roots = roots
        .iter()
        .map(refresh_shared_directory_row)
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return;
    }

    let applier = core.clone();
    let monitor = start_monitor(&roots, move |action| {
        let applier = applier.clone();
        async move {
            match action {
                MonitorAction::Share(path) => auto_share_monitored_path(&applier, &path).await,
                MonitorAction::Remove(path) => auto_unshare_monitored_path(&applier, &path).await,
                MonitorAction::Rename { from, to } => {
                    auto_relocate_monitored_path(&applier, &from, &to).await
                }
                MonitorAction::Reconcile => {
                    if let Err(error) = applier.reload_shared_directories_detached().await {
                        tracing::warn!(
                            error = %error,
                            "failed to schedule shared-directory watcher reconciliation",
                        );
                    } else {
                        // Keep the serial watcher consumer behind the reload so
                        // later event batches cannot mutate the catalog while
                        // reconciliation is rebuilding it. The detached worker
                        // still retains one hash worker per physical disk.
                        while applier
                            .shared_reload_running
                            .load(std::sync::atomic::Ordering::Acquire)
                            || applier
                                .shared_reload_pending
                                .load(std::sync::atomic::Ordering::Acquire)
                        {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
    });

    *core.shared_dir_monitor.lock().unwrap() = monitor;
}

/// Relocate an already-shared source after a paired filesystem rename.
///
/// Renaming a 100k-file library cohort must be metadata-only: unshare + ingest
/// would reread unchanged payload bytes, churn the catalog, and briefly make the
/// file unavailable. If the native fingerprint changed during the move, relocate first and
/// then let the regular share path rehash exactly once from the destination.
async fn auto_relocate_monitored_path(core: &EmulebbCore, from: &Path, to: &Path) {
    // WHY: expanding a paired rename into Remove + Share globally unshares the
    // hash, rereads unchanged content, and leaves stale source rows when a large
    // burst outruns the serial consumer. Preserve the source identity atomically.
    let old_key = monitor_shared_key(from);
    let new_key = monitor_shared_key(to);
    let previous = core
        .state
        .lock()
        .await
        .monitor_shared_hashes
        .get(&old_key)
        .cloned();
    let Some(previous) = previous else {
        auto_share_monitored_path(core, to).await;
        return;
    };
    let metadata = match tokio::fs::metadata(&new_key).await {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => {
            auto_unshare_monitored_path(core, from).await;
            return;
        }
    };
    match load_shared_file_exclusion_policy(core) {
        Ok(policy) if policy.should_ignore(&new_key, &metadata) => {
            auto_unshare_monitored_path(core, from).await;
            return;
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(
                path = %to.display(),
                error = %error,
                "failed to load shared-file exclusions for monitored rename",
            );
            return;
        }
    }
    let (_, file_size, source_fingerprint) =
        emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime::scanned_source_identity_from_metadata(
            &new_key, &metadata,
        );
    let identity_unchanged = previous
        .source_fingerprint
        .as_ref()
        .zip(source_fingerprint.as_ref())
        .is_some_and(|(stored, current)| stored.safely_matches(current));
    let persisted_fingerprint = source_fingerprint.clone().filter(|_| identity_unchanged);
    let Some(display_name) =
        emulebb_metadata::NativePath::from(new_key.as_path()).display_file_name()
    else {
        tracing::warn!(path = %to.display(), "renamed shared file has no valid file name");
        return;
    };
    let content_type = crate::ed2k_file_type_search_term(&display_name).unwrap_or("unknown");
    match core
        .ed2k_transfers
        .relocate_shared_source(
            &previous.hash,
            &old_key,
            &new_key,
            file_size,
            persisted_fingerprint,
            &display_name,
            content_type,
        )
        .await
    {
        Ok(true) => {
            let mut state = core.state.lock().await;
            state.monitor_shared_hashes.remove(&old_key);
            state.monitor_shared_hashes.insert(
                new_key,
                crate::core_state::MonitoredSharedFile {
                    hash: previous.hash,
                    source_fingerprint,
                },
            );
            drop(state);
            core.queue_ed2k_shared_catalog_publish();
            if !identity_unchanged {
                auto_share_monitored_path(core, to).await;
            }
        }
        Ok(false) => {
            tracing::warn!(
                from = %from.display(),
                to = %to.display(),
                "monitored rename source was absent from persisted share metadata",
            );
            auto_share_monitored_path(core, to).await;
        }
        Err(error) => {
            tracing::warn!(
                from = %from.display(),
                to = %to.display(),
                error = %error,
                "failed to relocate monitored shared file metadata",
            );
        }
    }
}

/// Stop the live shared-directory monitor (if running). Idempotent.
pub(crate) fn stop_shared_directory_monitor(core: &EmulebbCore) {
    if let Some(monitor) = core.shared_dir_monitor.lock().unwrap().take() {
        monitor.stop();
    }
    if let Some(worker) = core.shared_source_reconcile_worker.lock().unwrap().take() {
        worker.abort();
    }
}

/// Auto-share a file picked up by the live monitor. Goes through the same ingest
/// path as a manual share (MD4/AICH/catalog consistent), then records the
/// source-path -> hash mapping so a later remove can resolve it. Re-sharing an
/// already-shared identical file is cheap/idempotent. A vanished/unreadable file
/// (settled then disappeared) is logged and skipped, not propagated.
async fn auto_share_monitored_path(core: &EmulebbCore, path: &Path) {
    let key = monitor_shared_key(path);
    let metadata = match tokio::fs::metadata(&key).await {
        Ok(metadata) if metadata.is_file() => metadata,
        // Windows can report an ambiguous rename/modify event for a path that
        // has already disappeared. Reconcile it as a removal so the old hash is
        // not left offered until a manual reload. Directory events are harmless
        // because directories never have an entry in the path -> share map.
        Ok(_) => {
            auto_unshare_monitored_path(core, path).await;
            return;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            auto_unshare_monitored_path(core, path).await;
            return;
        }
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "failed to stat monitored file (skipping)",
            );
            return;
        }
    };
    let (_, _file_size, source_fingerprint) =
        emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime::scanned_source_identity_from_metadata(
            &key, &metadata,
        );
    let previous = core
        .state
        .lock()
        .await
        .monitor_shared_hashes
        .get(&key)
        .cloned();
    if previous.as_ref().is_some_and(|entry| {
        entry
            .source_fingerprint
            .as_ref()
            .zip(source_fingerprint.as_ref())
            .is_some_and(|(stored, current)| stored.safely_matches(current))
    }) {
        // Another event in the same logical write burst already ingested this
        // settled identity. A stat is enough; do not re-read the payload.
        return;
    }
    match core
        .share_native_local_file_with_progress(path, None, None)
        .await
    {
        Ok(share) => {
            let replaced =
                register_monitor_shared_hash(core, key, &share.hash, source_fingerprint).await;
            if let Some(replaced) = replaced
                && !replaced.hash.eq_ignore_ascii_case(&share.hash)
            {
                let old_hash_still_referenced = core
                    .state
                    .lock()
                    .await
                    .monitor_shared_hashes
                    .values()
                    .any(|entry| entry.hash.eq_ignore_ascii_case(&replaced.hash));
                if !old_hash_still_referenced {
                    forget_stale_shares(core, &[replaced.hash], &share.hash).await;
                }
            }
            tracing::debug!(path = %path.display(), hash = %share.hash, "auto-shared monitored file");
        }
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "failed to auto-share monitored file (skipping)",
            );
        }
    }
}

/// Auto-remove a file the live monitor saw removed / renamed away. The file is
/// already gone (cannot be re-hashed), so we resolve the catalog hash from the
/// `monitor_shared_hashes` source-path -> hash map and drop it via the existing
/// un-share catalog path. That map is populated both here at auto-share time AND
/// by the startup reload (see `reload_shared_directories`), so a file shared by
/// the initial reload is de-offered/de-published on delete exactly like one the
/// live monitor added. A path we never shared is a no-op.
async fn auto_unshare_monitored_path(core: &EmulebbCore, path: &Path) {
    let shared_file = {
        let mut state = core.state.lock().await;
        state
            .monitor_shared_hashes
            .remove(&monitor_shared_key(path))
    };
    let Some(shared_file) = shared_file else {
        return;
    };
    let hash = shared_file.hash;
    match core.unshare_file(&hash).await {
        Ok(Some(_)) => {
            tracing::debug!(path = %path.display(), %hash, "auto-removed monitored file from shared catalog");
        }
        // Already gone from the catalog (e.g. manually un-shared) -- fine.
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %hash,
                error = %error,
                "failed to auto-remove monitored file from shared catalog",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify_debouncer_full::notify::Event;
    use notify_debouncer_full::notify::event::{CreateKind, Flag, RemoveKind};
    use std::sync::Mutex;
    use std::time::Instant;

    fn debounced(kind: EventKind, paths: Vec<&str>) -> DebouncedEvent {
        let event = Event {
            kind,
            paths: paths.into_iter().map(PathBuf::from).collect(),
            attrs: Default::default(),
        };
        DebouncedEvent {
            event,
            time: Instant::now(),
        }
    }

    fn share(path: &str) -> MonitorAction {
        MonitorAction::Share(PathBuf::from(path))
    }
    fn remove(path: &str) -> MonitorAction {
        MonitorAction::Remove(PathBuf::from(path))
    }
    fn rename(from: &str, to: &str) -> MonitorAction {
        MonitorAction::Rename {
            from: PathBuf::from(from),
            to: PathBuf::from(to),
        }
    }
    fn reconcile() -> MonitorAction {
        MonitorAction::Reconcile
    }
    fn name(mode: RenameMode) -> EventKind {
        EventKind::Modify(ModifyKind::Name(mode))
    }

    #[test]
    fn create_event_classifies_as_share() {
        let event = debounced(EventKind::Create(CreateKind::File), vec!["/share/a.dat"]);
        assert_eq!(classify_event(&event), vec![share("/share/a.dat")]);
    }

    #[test]
    fn data_modify_event_classifies_as_share() {
        let kind = EventKind::Modify(ModifyKind::Data(
            notify_debouncer_full::notify::event::DataChange::Content,
        ));
        let event = debounced(kind, vec!["/share/b.dat"]);
        assert_eq!(classify_event(&event), vec![share("/share/b.dat")]);
    }

    #[test]
    fn remove_event_classifies_as_remove() {
        let event = debounced(EventKind::Remove(RemoveKind::File), vec!["/share/c.dat"]);
        assert_eq!(classify_event(&event), vec![remove("/share/c.dat")]);
    }

    #[test]
    fn unpaired_rename_requests_full_reconciliation() {
        let to = debounced(name(RenameMode::To), vec!["/share/new.dat"]);
        assert_eq!(classify_event(&to), vec![reconcile()]);
        let from = debounced(name(RenameMode::From), vec!["/share/old.dat"]);
        assert_eq!(classify_event(&from), vec![reconcile()]);
    }

    #[test]
    fn both_rename_preserves_the_path_pair() {
        let event = debounced(
            name(RenameMode::Both),
            vec!["/share/old.dat", "/share/new.dat"],
        );
        assert_eq!(
            classify_event(&event),
            vec![rename("/share/old.dat", "/share/new.dat")]
        );
    }

    #[test]
    fn ambiguous_two_path_rename_preserves_the_path_pair() {
        let event = debounced(
            name(RenameMode::Any),
            vec!["/share/old.dat", "/share/new.dat"],
        );
        assert_eq!(
            classify_event(&event),
            vec![rename("/share/old.dat", "/share/new.dat")]
        );
    }

    #[test]
    fn access_event_yields_no_action() {
        let event = debounced(
            EventKind::Access(notify_debouncer_full::notify::event::AccessKind::Read),
            vec!["/share/x.dat"],
        );
        assert!(classify_event(&event).is_empty());
    }

    #[test]
    fn backend_rescan_notice_requests_reconciliation() {
        let event = Event::new(EventKind::Other).set_flag(Flag::Rescan);
        let event = DebouncedEvent {
            event,
            time: Instant::now(),
        };
        assert_eq!(classify_event(&event), vec![reconcile()]);
    }

    #[test]
    fn actions_for_events_flattens_a_batch_in_order() {
        let events = vec![
            debounced(EventKind::Create(CreateKind::File), vec!["/s/a.dat"]),
            debounced(EventKind::Remove(RemoveKind::File), vec!["/s/b.dat"]),
        ];
        #[cfg(not(target_os = "windows"))]
        let expected = vec![share("/s/a.dat"), remove("/s/b.dat")];
        #[cfg(target_os = "windows")]
        let expected = vec![share("/s/a.dat"), remove("/s/b.dat"), reconcile()];
        assert_eq!(actions_for_events(&events), expected);
    }

    #[test]
    fn coalesce_actions_keeps_only_each_paths_final_intent() {
        assert_eq!(
            coalesce_actions(vec![
                share("/s/a.dat"),
                share("/s/b.dat"),
                remove("/s/a.dat"),
                share("/s/a.dat"),
                remove("/s/b.dat"),
            ]),
            vec![share("/s/a.dat"), remove("/s/b.dat")]
        );
    }

    #[test]
    fn coalesce_actions_deduplicates_rename_and_suppresses_endpoint_share() {
        assert_eq!(
            coalesce_actions(vec![
                rename("/s/a.dat", "/s/b.dat"),
                rename("/s/a.dat", "/s/b.dat"),
                share("/s/b.dat"),
            ]),
            vec![rename("/s/a.dat", "/s/b.dat")],
        );
    }

    #[test]
    fn coalesce_actions_keeps_destination_remove_after_rename() {
        assert_eq!(
            coalesce_actions(vec![rename("/s/a.dat", "/s/b.dat"), remove("/s/b.dat"),]),
            vec![rename("/s/a.dat", "/s/b.dat"), remove("/s/b.dat")],
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_rename_burst_requests_follow_up_reconciliation() {
        let events = (0..WINDOWS_EVENT_BURST_RECONCILE_THRESHOLD)
            .map(|index| {
                let event = Event {
                    kind: name(RenameMode::Both),
                    paths: vec![
                        PathBuf::from(format!("C:/share/old-{index}.bin")),
                        PathBuf::from(format!("C:/share/new-{index}.bin")),
                    ],
                    attrs: Default::default(),
                };
                DebouncedEvent {
                    event,
                    time: Instant::now(),
                }
            })
            .collect::<Vec<_>>();
        let actions = actions_for_events(&events);
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, MonitorAction::Rename { .. }))
                .count(),
            WINDOWS_EVENT_BURST_RECONCILE_THRESHOLD,
        );
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, MonitorAction::Reconcile))
                .count(),
            1,
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_create_burst_requests_follow_up_reconciliation() {
        let events = (0..WINDOWS_EVENT_BURST_RECONCILE_THRESHOLD)
            .map(|index| {
                let event = Event {
                    kind: EventKind::Create(CreateKind::File),
                    paths: vec![PathBuf::from(format!("C:/share/new-{index}.bin"))],
                    attrs: Default::default(),
                };
                DebouncedEvent {
                    event,
                    time: Instant::now(),
                }
            })
            .collect::<Vec<_>>();
        let actions = actions_for_events(&events);
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, MonitorAction::Share(_)))
                .count(),
            WINDOWS_EVENT_BURST_RECONCILE_THRESHOLD,
        );
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, MonitorAction::Reconcile))
                .count(),
            1,
        );
    }

    #[test]
    fn coalesce_actions_schedules_only_one_reconciliation_per_burst() {
        assert_eq!(
            coalesce_actions(vec![
                reconcile(),
                share("/s/a.dat"),
                reconcile(),
                remove("/s/b.dat"),
            ]),
            vec![reconcile()],
        );
    }

    /// Drive `run_consumer` over `inputs` and return the actions it actually
    /// applied -- the consumer's in-order forwarding seam (the OS watcher
    /// cannot be tested deterministically).
    async fn applied_actions(inputs: Vec<MonitorAction>) -> Vec<MonitorAction> {
        let applied: Arc<Mutex<Vec<MonitorAction>>> = Arc::new(Mutex::new(Vec::new()));
        let (ingress, rx, reconcile_required) = monitor_action_channel(inputs.len().max(1));
        ingress.try_send_actions(inputs);
        drop(ingress);
        let sink = Arc::clone(&applied);
        let consumer = tokio::spawn(run_consumer(rx, reconcile_required, move |action| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().unwrap().push(action);
            }
        }));
        consumer.await.unwrap();
        Arc::try_unwrap(applied).unwrap().into_inner().unwrap()
    }

    #[test]
    fn bounded_ingress_caps_large_burst_and_latches_one_reconcile() {
        const TEST_CAPACITY: usize = 4;
        let (ingress, mut rx, reconcile_required) = monitor_action_channel(TEST_CAPACITY);
        let burst = (0..10_000)
            .map(|index| share(&format!("/s/{index}.dat")))
            .collect::<Vec<_>>();

        ingress.try_send_actions(burst);

        assert!(reconcile_required.load(Ordering::Acquire));
        assert_eq!(
            std::iter::from_fn(|| rx.try_recv().ok()).count(),
            TEST_CAPACITY,
        );
        ingress.try_send_actions([share("/s/after-overflow.dat")]);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn overflow_reconciles_each_episode_then_preserves_later_final_intent() {
        let applied: Arc<Mutex<Vec<MonitorAction>>> = Arc::new(Mutex::new(Vec::new()));
        let reconcile_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reconcile_started = Arc::new(tokio::sync::Notify::new());
        let release_reconcile = Arc::new(tokio::sync::Notify::new());
        let (ingress, rx, reconcile_required) = monitor_action_channel(2);

        ingress.try_send_actions([
            share("/s/pre-overflow-a.dat"),
            remove("/s/pre-overflow-b.dat"),
            share("/s/triggers-overflow.dat"),
        ]);

        let sink = Arc::clone(&applied);
        let count = Arc::clone(&reconcile_count);
        let started = Arc::clone(&reconcile_started);
        let release = Arc::clone(&release_reconcile);
        let consumer = tokio::spawn(run_consumer(rx, reconcile_required, move |action| {
            let sink = Arc::clone(&sink);
            let count = Arc::clone(&count);
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            async move {
                sink.lock().unwrap().push(action.clone());
                if action == MonitorAction::Reconcile {
                    count.fetch_add(1, Ordering::AcqRel);
                    started.notify_one();
                    release.notified().await;
                }
            }
        }));

        tokio::time::timeout(Duration::from_secs(1), reconcile_started.notified())
            .await
            .expect("overflow reconciliation did not start");
        ingress.try_send_actions([
            share("/s/during-reconcile-a.dat"),
            remove("/s/during-reconcile-b.dat"),
            share("/s/triggers-follow-up-overflow.dat"),
        ]);
        release_reconcile.notify_one();

        tokio::time::timeout(Duration::from_secs(1), reconcile_started.notified())
            .await
            .expect("follow-up overflow reconciliation did not start");
        assert_eq!(reconcile_count.load(Ordering::Acquire), 2);
        ingress.try_send_actions([remove("/s/final.dat"), share("/s/final.dat")]);
        drop(ingress);
        release_reconcile.notify_one();
        consumer.await.unwrap();

        assert_eq!(
            Arc::try_unwrap(applied).unwrap().into_inner().unwrap(),
            vec![reconcile(), reconcile(), share("/s/final.dat")],
        );
    }

    /// The consumer forwards the final queued intent for each path, including a
    /// Remove of a path it never saw a Share for. The decision to actually
    /// un-share (or no-op an unknown path) remains in the applier.
    #[tokio::test]
    async fn consumer_coalesces_queued_actions_and_preserves_final_order() {
        let applied = applied_actions(vec![
            share("/s/a.dat"),
            remove("/s/a.dat"),
            remove("/s/b.dat"),
        ])
        .await;
        assert_eq!(applied, vec![remove("/s/a.dat"), remove("/s/b.dat")]);
    }

    /// Remove-then-readd: a Share after a Remove is forwarded and re-shares.
    #[tokio::test]
    async fn consumer_reshares_after_remove() {
        let applied = applied_actions(vec![
            share("/s/a.dat"),
            remove("/s/a.dat"),
            share("/s/a.dat"),
        ])
        .await;
        assert_eq!(applied, vec![share("/s/a.dat")]);
    }

    /// A file shared by the INITIAL startup reload (never touched by the live
    /// monitor) is registered in `monitor_shared_hashes`, so when its source is
    /// deleted at runtime the monitor's Remove path resolves the hash and drops
    /// it from the shared catalog -- the HASH-1 gap. Drives the reload + the
    /// monitor's `auto_unshare_monitored_path` directly (the OS watcher cannot be
    /// tested deterministically) to prove the de-offer happens.
    #[tokio::test]
    async fn startup_reload_share_is_de_offered_when_source_deleted() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "emulebb-monitor-startup-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("Deleted.At.Runtime.bin");
        std::fs::write(&source, b"startup shared payload").unwrap();

        let core =
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
        core.state.lock().await.shared_directories = vec![SharedDirectoryRoot {
            path: root.display().to_string(),
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }];

        // The startup reload shares the file and registers its source path.
        let shares = crate::shared_directories::reload_shared_directories(&core)
            .await
            .unwrap();
        assert_eq!(shares.len(), 1);
        let hash = shares[0].hash.clone();
        assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 1);
        assert_eq!(
            core.state
                .lock()
                .await
                .monitor_shared_hashes
                .get(&monitor_shared_key(&source))
                .map(|entry| entry.hash.as_str()),
            Some(hash.as_str()),
            "startup reload must register the shared source path -> hash so a live \
             Remove can resolve it",
        );

        // Operator deletes the startup-shared file at runtime; the live monitor
        // reports a Remove for the (now-gone) path.
        std::fs::remove_file(&source).unwrap();
        auto_unshare_monitored_path(&core, &source).await;

        assert_eq!(
            core.ed2k_transfers.shared_catalog_count().await,
            0,
            "the deleted startup-shared file must be de-offered/de-published",
        );
        assert!(core.share(&hash).await.is_none());
        assert!(
            !core
                .state
                .lock()
                .await
                .monitor_shared_hashes
                .contains_key(&monitor_shared_key(&source)),
            "the removed path must be dropped from the tracking map",
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn monitored_file_is_not_shared_when_exactly_excluded() {
        let root = std::env::temp_dir().join(format!(
            "emulebb-monitor-excluded-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("Excluded.At.Runtime.bin");
        std::fs::write(&source, b"excluded monitored payload").unwrap();
        let core =
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
        core.metadata_store
            .add_shared_file_exclusion(&monitor_shared_key(&source))
            .unwrap();

        auto_share_monitored_path(&core, &source).await;

        assert!(core.shares().await.is_empty());
        assert!(
            !core
                .state
                .lock()
                .await
                .monitor_shared_hashes
                .contains_key(&monitor_shared_key(&source))
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn monitored_change_replaces_old_hash_and_duplicate_event_is_a_noop() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "emulebb-monitor-modify-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("Modified.At.Runtime.bin");
        std::fs::write(&source, b"before").unwrap();

        let core =
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
        auto_share_monitored_path(&core, &source).await;
        let old_hash = core.shares().await[0].hash.clone();
        assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 1);

        std::fs::write(&source, b"after payload with a different size").unwrap();
        auto_share_monitored_path(&core, &source).await;
        let new_hash = core.shares().await[0].hash.clone();
        assert_ne!(old_hash, new_hash);
        assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 1);
        assert!(core.share(&old_hash).await.is_none());
        assert_eq!(core.metadata_store.table_count("known_files").unwrap(), 1);

        // A duplicate settled event for the same native fingerprint must not
        // ingest or create another catalog row.
        auto_share_monitored_path(&core, &source).await;
        assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 1);
        assert_eq!(core.metadata_store.table_count("known_files").unwrap(), 1);

        // An ambiguous Share event received after disappearance reconciles as a
        // removal, covering Windows rename/delete notifications.
        std::fs::remove_file(&source).unwrap();
        auto_share_monitored_path(&core, &source).await;
        assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 0);
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn upload_invalidation_rehashes_stable_replacement_without_full_reload() {
        use emulebb_kad_proto::Ed2kHash;
        use std::str::FromStr;
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "emulebb-targeted-rehash-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("Changed.After.Import.bin");
        let original = root.join("Changed.After.Import.original.bin");
        let trusted = vec![0x41; 4096];
        let replacement = vec![0x92; 8192];
        std::fs::write(&source, &trusted).unwrap();

        let core =
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
        auto_share_monitored_path(&core, &source).await;
        let old_hash = core.shares().await[0].hash.clone();
        let old_hash_value = Ed2kHash::from_str(&old_hash).unwrap();
        let signal = core.ed2k_transfers.shared_source_invalidation_signal();
        let worker = tokio::spawn(run_shared_source_reconcile_worker(
            core.clone(),
            signal.clone(),
            TargetedRehashPolicy {
                debounce: Duration::ZERO,
                retry_delay: Duration::ZERO,
                max_attempts: 3,
            },
        ));

        std::fs::rename(&source, &original).unwrap();
        std::fs::write(&source, &replacement).unwrap();
        assert!(
            core.ed2k_transfers
                .read_verified_range(&old_hash_value, 0, trusted.len() as u64)
                .await
                .unwrap()
                .is_none()
        );

        let new_hash = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let shares = core.shares().await;
                if shares.len() == 1 && !shares[0].hash.eq_ignore_ascii_case(&old_hash) {
                    break shares[0].hash.clone();
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("targeted re-hash should complete");

        assert_ne!(new_hash, old_hash);
        assert!(core.share(&old_hash).await.is_none());
        assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 1);
        assert!(!core.shared_reload_running.load(Ordering::Acquire));
        assert!(!core.shared_reload_pending.load(Ordering::Acquire));
        assert!(signal.try_recv().is_none());
        worker.abort();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn unavailable_invalidated_source_stays_withdrawn_without_retry_loop() {
        use emulebb_kad_proto::Ed2kHash;
        use std::str::FromStr;
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "emulebb-targeted-missing-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("Unavailable.bin");
        let payload = vec![0x51; 4096];
        std::fs::write(&source, &payload).unwrap();

        let core =
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
        auto_share_monitored_path(&core, &source).await;
        let old_hash = core.shares().await[0].hash.clone();
        let old_hash_value = Ed2kHash::from_str(&old_hash).unwrap();
        let signal = core.ed2k_transfers.shared_source_invalidation_signal();
        let worker = tokio::spawn(run_shared_source_reconcile_worker(
            core.clone(),
            signal.clone(),
            TargetedRehashPolicy {
                debounce: Duration::ZERO,
                retry_delay: Duration::ZERO,
                max_attempts: 3,
            },
        ));

        std::fs::remove_file(&source).unwrap();
        assert!(
            core.ed2k_transfers
                .read_verified_range(&old_hash_value, 0, payload.len() as u64)
                .await
                .unwrap()
                .is_none()
        );

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if core.ed2k_transfers.manifest(&old_hash).await.is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("missing invalidated source should be retired");
        tokio::task::yield_now().await;
        assert!(core.shares().await.is_empty());
        assert!(signal.try_recv().is_none());
        worker.abort();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn targeted_rehash_retry_budget_is_finite() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = Arc::new(AtomicUsize::new(0));
        let counted_attempts = Arc::clone(&attempts);
        let result = run_targeted_rehash_attempts(
            TargetedRehashPolicy {
                debounce: Duration::ZERO,
                retry_delay: Duration::ZERO,
                max_attempts: 3,
            },
            move || {
                counted_attempts.fetch_add(1, Ordering::Relaxed);
                async { TargetedRehashOutcome::Retry(anyhow::anyhow!("still changing")) }
            },
        )
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn monitored_rename_relocates_source_without_rehash_or_duplicate_row() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "emulebb-monitor-rename-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        let renamed_dir = root.join("renamed");
        std::fs::create_dir_all(&renamed_dir).unwrap();
        let source = root.join("Before.bin");
        let destination = renamed_dir.join("After.bin");
        std::fs::write(&source, b"rename preserves this payload").unwrap();

        let core =
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
        auto_share_monitored_path(&core, &source).await;
        let hash = core.shares().await[0].hash.clone();
        std::fs::rename(&source, &destination).unwrap();

        auto_relocate_monitored_path(&core, &source, &destination).await;

        let shares = core.shares().await;
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].hash, hash);
        assert_eq!(shares[0].name, "After.bin");
        assert_eq!(
            shares[0].source_path.as_deref(),
            Some(destination.display().to_string().as_str()),
        );
        assert_eq!(core.metadata_store.table_count("known_files").unwrap(), 1);
        assert_eq!(
            core.metadata_store
                .table_count("shared_file_sources")
                .unwrap(),
            1,
        );
        let state = core.state.lock().await;
        assert!(
            !state
                .monitor_shared_hashes
                .contains_key(&monitor_shared_key(&source))
        );
        assert_eq!(
            state
                .monitor_shared_hashes
                .get(&monitor_shared_key(&destination))
                .map(|entry| entry.hash.as_str()),
            Some(hash.as_str()),
        );
        drop(state);
        std::fs::remove_dir_all(&root).ok();
    }
}
