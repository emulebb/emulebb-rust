//! Optional recursive shared-directory watching with settled, bounded action batches.
//!
//! Known path changes use the verified share/remove/relocate owners. Event loss,
//! failed subscriptions and observation gaps persist scan-required state against
//! captured root IDs. They never schedule a full scan. Explicit/startup scans
//! acknowledge only losses covered by their captured scan watermark.
//!
//! The native debouncer still owns upstream event/cache state; the admission and
//! coalescing limits here bound the downstream path work, not that upstream cache.
use anyhow::Context;
use emulebb_metadata::NativeFileFingerprint;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use notify_debouncer_full::notify::event::{CreateKind, ModifyKind, RemoveKind, RenameMode};
use notify_debouncer_full::notify::{EventKind, RecursiveMode};
use notify_debouncer_full::{
    DebounceEventResult, DebouncedEvent, Debouncer, RecommendedCache, new_debouncer,
};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::shared_directories::{SharedDirectoryRoot, load_shared_file_ignore_policy};

/// Settle window before a burst of raw FS events for one logical change is
/// emitted as a settled event. Long enough that a file copied in is fully
/// written before we hash it, short enough that auto-pickup still feels live.
/// (eMule re-scans shared dirs on a coarse timer; a 2s settle is well within
/// that responsiveness while avoiding mid-write hashing.)
const SETTLE_WINDOW: Duration = Duration::from_secs(2);

/// Maximum settled path actions retained while the serial async applier is
/// busy. Larger settled bursts collapse into a scan-required notice.
const ACTION_CHANNEL_CAPACITY: usize = 256;

const TARGETED_REHASH_DEBOUNCE: Duration = Duration::from_secs(2);
const TARGETED_REHASH_RETRY_DELAY: Duration = Duration::from_secs(2);
const TARGETED_REHASH_MAX_ATTEMPTS: usize = 3;

/// Coalesce watch refreshes while retaining any scan not already owned by a
/// committed root command. A watch-only notification cannot erase scan intent.
#[derive(Default)]
pub(crate) struct RootChangeSignal {
    wake: tokio::sync::Notify,
    scan: AtomicBool,
}

impl RootChangeSignal {
    pub(crate) fn watch_changed(&self) {
        self.wake.notify_one();
    }

    pub(crate) fn scan_required(&self) {
        self.scan.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    async fn notified(&self) {
        self.wake.notified().await;
    }

    fn take_scan_request(&self) -> bool {
        self.scan.swap(false, Ordering::AcqRel)
    }
}

/// `notify` 8.x uses one fixed 16 KiB `ReadDirectoryChangesW` buffer for a
/// recursive Windows watch. Even a modest settled mutation burst can mean an
/// earlier buffer overflow was silently dropped (renames are especially costly
/// because they contribute old-name and new-name records). Flag such a burst
/// for an explicit scan. A single-file operation keeps the direct fast
/// path; two settled actions are enough to protect against the very short tail
/// that Windows can deliver after discarding an overflowed buffer.
#[cfg(target_os = "windows")]
const WINDOWS_EVENT_BURST_LOSS_THRESHOLD: usize = 2;

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
    /// Known/possible loss for these paths. Empty means unknown scope; the
    /// captured subscribed root IDs are flagged for an explicit scan.
    ScanRequired(Vec<PathBuf>),
}

/// Classify a single settled debounced event into zero or more actions.
///
/// `notify`'s settled event kinds map cleanly onto our three intents:
/// * `Create` / `Modify(Data|Any|Metadata)` -> the path now holds content we
///   should share.
/// * `Remove` -> the path no longer holds the content it had, so drop it.
/// * A paired rename carries `[from, to]`: relocate the source identity without
///   rehashing unchanged content.
/// * An unpaired rename flags its paths for an explicit scan. It may be
///   a legitimate move across the watch boundary, or evidence that the native
///   watcher dropped the other side of a larger burst.
///
/// We intentionally do not try to stat the path here (it may already be gone for
/// a remove, or still settling); the consumer decides share-vs-skip when it
/// actually touches the filesystem.
pub(crate) fn classify_event(event: &DebouncedEvent) -> Vec<MonitorAction> {
    if event.need_rescan() {
        return vec![MonitorAction::ScanRequired(event.paths.clone())];
    }
    // Map every path of the event to the same action variant.
    let map_paths = |variant: fn(PathBuf) -> MonitorAction| -> Vec<MonitorAction> {
        event.paths.iter().cloned().map(variant).collect()
    };
    match event.kind {
        // A directory notification does not enumerate all descendants. Native
        // recursive registration can miss children created before it catches up.
        EventKind::Create(CreateKind::Folder) | EventKind::Remove(RemoveKind::Folder) => {
            vec![MonitorAction::ScanRequired(event.paths.clone())]
        }
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
            RenameMode::To | RenameMode::From => {
                vec![MonitorAction::ScanRequired(event.paths.clone())]
            }
            // Some backends label a paired [from, to] event as Any/Other. Keep
            // that pair when present; a single ambiguous path needs the same
            // reconciliation safety net as an unpaired From/To event.
            RenameMode::Any | RenameMode::Other => {
                match (event.paths.first(), event.paths.get(1)) {
                    (Some(from), Some(to)) => vec![MonitorAction::Rename {
                        from: from.clone(),
                        to: to.clone(),
                    }],
                    _ => vec![MonitorAction::ScanRequired(event.paths.clone())],
                }
            }
        },
        EventKind::Remove(RemoveKind::File) => map_paths(MonitorAction::Remove),
        EventKind::Remove(_) => {
            let mut actions = map_paths(MonitorAction::Remove);
            actions.push(MonitorAction::ScanRequired(event.paths.clone()));
            actions
        }
        EventKind::Other | EventKind::Any => vec![MonitorAction::ScanRequired(event.paths.clone())],
        EventKind::Access(_) => Vec::new(),
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
            .filter(|action| !matches!(action, MonitorAction::ScanRequired(_)))
            .count();
        if catalog_action_count >= WINDOWS_EVENT_BURST_LOSS_THRESHOLD {
            actions.push(MonitorAction::ScanRequired(
                events
                    .iter()
                    .flat_map(|event| event.paths.iter().cloned())
                    .collect(),
            ));
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
/// duplicate pairs and loss notices are collapsed independently
/// from final per-path intents.
fn coalesce_actions(actions: Vec<MonitorAction>) -> Vec<MonitorAction> {
    let mut by_path: HashMap<PathBuf, (usize, MonitorAction)> = HashMap::new();
    let mut renames: HashMap<(PathBuf, PathBuf), (usize, MonitorAction)> = HashMap::new();
    let mut loss_sequence = None;
    let mut loss_paths = HashSet::new();
    let mut global_loss = false;
    for (sequence, action) in actions.into_iter().enumerate() {
        match &action {
            MonitorAction::Share(path) | MonitorAction::Remove(path) => {
                by_path.insert(path.clone(), (sequence, action));
            }
            MonitorAction::Rename { from, to } => {
                renames.insert((from.clone(), to.clone()), (sequence, action));
            }
            MonitorAction::ScanRequired(paths) => {
                loss_sequence = Some(sequence);
                global_loss |= paths.is_empty();
                loss_paths.extend(paths.iter().cloned());
            }
        }
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
    if let Some(sequence) = loss_sequence {
        let mut paths = if global_loss {
            Vec::new()
        } else {
            loss_paths.into_iter().collect::<Vec<_>>()
        };
        paths.sort_unstable();
        coalesced.push((sequence, MonitorAction::ScanRequired(paths)));
    }
    coalesced.sort_by_key(|(sequence, _)| *sequence);
    coalesced.into_iter().map(|(_, action)| action).collect()
}

/// Non-blocking ingress from the watcher callback into the async consumer.
///
/// Overflow latches one unknown-scope loss notice. Further callbacks skip path
/// actions until the consumer takes ownership of that notice. Recovery is an
/// explicit scan; no callback waits for database work or starts a scan.
#[derive(Clone)]
struct MonitorIngress {
    action_tx: Sender<MonitorAction>,
    scan_required: Arc<AtomicBool>,
    native_faulted: Arc<AtomicBool>,
}

impl MonitorIngress {
    fn require_scan(&self) {
        self.scan_required.store(true, Ordering::Release);
        // A loss can arrive without a queued path event (for example, an OS
        // rescan notice). Wake the consumer without blocking the callback.
        let _ = self
            .action_tx
            .try_send(MonitorAction::ScanRequired(Vec::new()));
    }

    fn try_send_actions(&self, actions: impl IntoIterator<Item = MonitorAction>) {
        if self.scan_required.load(Ordering::Acquire) {
            return;
        }

        for action in actions {
            match self.action_tx.try_send(action) {
                Ok(()) => {}
                Err(TrySendError::Closed(_)) => return,
                Err(TrySendError::Full(_)) => {
                    // WHY: blocking the notify callback can stall the platform
                    // watcher, while retaining every path permits remote/local
                    // mutation bursts to grow memory without bound. Persist
                    // uncertainty so an explicit scan can recover dropped work.
                    if !self.scan_required.swap(true, Ordering::AcqRel) {
                        tracing::warn!(
                            capacity = ACTION_CHANNEL_CAPACITY,
                            "shared-directory watcher ingress overflowed; explicit scan required",
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
    let scan_required = Arc::new(AtomicBool::new(false));
    (
        MonitorIngress {
            action_tx,
            scan_required: Arc::clone(&scan_required),
            native_faulted: Arc::new(AtomicBool::new(false)),
        },
        action_rx,
        scan_required,
    )
}

/// Handle to a running shared-directory monitor.
///
/// Owns the `notify` debouncer (its `Drop` stops the watcher thread) and the
/// `JoinHandle` of the tokio consumer task. Dropping or [`stop`](Self::stop)ing
/// it tears both down so neither the watcher thread nor the consumer task leaks
/// across a disconnect / reconfigure.
pub(crate) struct SharedDirMonitor {
    /// Re-register roots in place after event loss; dropping this joins the
    /// native watcher without leaving an unowned thread.
    debouncer:
        Option<Debouncer<notify_debouncer_full::notify::RecommendedWatcher, RecommendedCache>>,
    watched_roots: Vec<PathBuf>,
    binding_ids: Arc<Vec<(PathBuf, i64)>>,
    native_faulted: Arc<AtomicBool>,
    consumer: tokio::task::JoinHandle<()>,
    stop: tokio::sync::watch::Sender<bool>,
}

impl SharedDirMonitor {
    fn matches(&self, roots: &[SharedDirectoryRoot], ids: &[(PathBuf, i64)]) -> bool {
        if self.debouncer.is_none()
            || self.native_faulted.load(Ordering::Acquire)
            || self.binding_ids.as_slice() != ids
        {
            return false;
        }
        let mut expected = roots
            .iter()
            .filter(|root| root.watch_enabled && root.accessible)
            .map(|root| monitor_shared_key(Path::new(&root.path)))
            .collect::<Vec<_>>();
        let mut actual = self
            .watched_roots
            .iter()
            .map(|path| monitor_shared_key(path))
            .collect::<Vec<_>>();
        expected.sort_unstable();
        actual.sort_unstable();
        expected == actual
    }

    /// Restore native recursive coverage before an explicit/startup scan.
    /// Existing registrations stay installed while new directories are added.
    #[cfg(target_os = "linux")]
    fn refresh_watch_coverage(&mut self) -> usize {
        let Some(debouncer) = self.debouncer.as_mut() else {
            return 0;
        };
        let mut refreshed = 0;
        for root in &self.watched_roots {
            match debouncer.watch(root, RecursiveMode::Recursive) {
                Ok(()) => refreshed += 1,
                Err(error) => tracing::warn!(
                    root = %root.display(), %error,
                    "failed to restore shared-directory recursive watch coverage",
                ),
            }
        }
        refreshed
    }

    /// Stop native callbacks, cancel ordinary path work and join final loss writes.
    pub(crate) async fn stop(&mut self) -> anyhow::Result<()> {
        self.stop.send_replace(true);
        self.debouncer.take();
        match (&mut self.consumer).await {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
        }
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
/// paths. Returns `None` when no accessible root opts into watching. Failed
/// subscriptions retain an owned consumer so their loss notices are persisted.
pub(crate) fn start_monitor<F, Fut>(
    roots: &[SharedDirectoryRoot],
    apply: F,
) -> Option<SharedDirMonitor>
where
    F: Fn(MonitorAction) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    if roots
        .iter()
        .all(|root| !root.watch_enabled || !root.accessible)
    {
        return None;
    }

    // notify watcher thread -> tokio consumer bridge. The debouncer's event
    // handler runs on the watcher thread; it must not block. A full bounded
    // queue therefore latches one loss notice instead of waiting or retaining
    // work proportional to the mutation volume.
    let (ingress, action_rx, scan_required) = monitor_action_channel(ACTION_CHANNEL_CAPACITY);
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let native_faulted = Arc::clone(&ingress.native_faulted);

    let error_ingress = ingress.clone();
    let handler = move |result: DebounceEventResult| match result {
        Ok(events) => {
            if events.iter().any(|event| event.need_rescan()) {
                ingress.native_faulted.store(true, Ordering::Release);
            }
            // WHY: bound allocation before flattening/coalescing a settled
            // batch. An oversized batch has unknown loss scope, so flag every
            // subscribed root instead of allocating work proportional to it.
            if events.len() > ACTION_CHANNEL_CAPACITY
                || events.iter().map(|event| event.paths.len()).sum::<usize>()
                    > ACTION_CHANNEL_CAPACITY
            {
                ingress.require_scan();
                return;
            }
            ingress.try_send_actions(coalesce_actions(actions_for_events(&events)));
        }
        Err(errors) => {
            ingress.native_faulted.store(true, Ordering::Release);
            if errors.len() > ACTION_CHANNEL_CAPACITY {
                ingress.require_scan();
                return;
            }
            for error in errors {
                tracing::warn!(error = %error, "shared-directory watcher reported an error");
                if error.paths.len() > ACTION_CHANNEL_CAPACITY {
                    ingress.require_scan();
                    return;
                }
                ingress.try_send_actions([MonitorAction::ScanRequired(error.paths)]);
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
            error_ingress.try_send_actions([MonitorAction::ScanRequired(Vec::new())]);
            return Some(SharedDirMonitor {
                debouncer: None,
                watched_roots: Vec::new(),
                binding_ids: Arc::new(Vec::new()),
                native_faulted,
                consumer: tokio::spawn(run_consumer(action_rx, scan_required, stop_rx, apply)),
                stop,
            });
        }
    };

    let mut watched_roots = Vec::new();
    for root in roots {
        if !root.watch_enabled || !root.accessible {
            continue;
        }
        let path = Path::new(&root.path);
        match debouncer.watch(path, RecursiveMode::Recursive) {
            Ok(()) => {
                // notify-debouncer-full 0.7 manages the file-id cache roots
                // together with the watcher registration.
                watched_roots.push(path.to_path_buf());
                tracing::info!(
                    root = %root.path,
                    "watching shared directory for auto-pickup",
                );
            }
            Err(error) => {
                error_ingress
                    .try_send_actions([MonitorAction::ScanRequired(vec![path.to_path_buf()])]);
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

    // Registration closes the unobserved interval before this subscription.
    // A scan already in flight must not acknowledge that interval accidentally.
    error_ingress.try_send_actions([MonitorAction::ScanRequired(watched_roots.clone())]);
    let consumer = tokio::spawn(run_consumer(action_rx, scan_required, stop_rx, apply));
    Some(SharedDirMonitor {
        debouncer: Some(debouncer),
        watched_roots,
        binding_ids: Arc::new(Vec::new()),
        native_faulted,
        consumer,
        stop,
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
    scan_required: Arc<AtomicBool>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    apply: F,
) where
    F: Fn(MonitorAction) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    while let Some(first) = action_rx.recv().await {
        let mut pending = vec![first];
        for _ in 1..ACTION_CHANNEL_CAPACITY {
            match action_rx.try_recv() {
                Ok(action) => pending.push(action),
                Err(_) => break,
            }
        }

        if scan_required.load(Ordering::Acquire) {
            // Keep the latch set while draining so watcher callbacks continue
            // collapsing into this loss episode. Clear before the await so a
            // newer episode can advance the durable revision independently.
            while action_rx.try_recv().is_ok() {}
            scan_required.store(false, Ordering::Release);
            apply(MonitorAction::ScanRequired(Vec::new())).await;
            continue;
        }

        for action in coalesce_actions(pending) {
            if matches!(action, MonitorAction::ScanRequired(_)) {
                apply(action).await;
            } else if !*stop.borrow() {
                tokio::select! {
                    biased;
                    _ = stop.changed() => {},
                    _ = apply(action) => {},
                }
            }
        }
    }
    if *stop.borrow() {
        // WHY: stopping drops unsettled debouncer state and opens an observation
        // gap. Persist that uncertainty before joining the consumer; ordinary
        // path work is cancelled, while admitted SQL remains owned and drained.
        apply(MonitorAction::ScanRequired(Vec::new())).await;
    }
}

// ---------------------------------------------------------------------------
// Core orchestration (kept out of lib.rs to respect its frozen line budget).
//
// These free functions take `&EmulebbCore` and drive the monitor lifecycle plus
// the auto-share / auto-remove application of monitor actions. They access the
// core's private `state` / `shared_dir_monitor` fields directly (a child module
// may read its ancestor's private items) and use the same verified local-content
// and root-membership operations as the manual share path.
// ---------------------------------------------------------------------------

use emulebb_ed2k::ed2k_transfer::{
    Ed2kSharedSourceInvalidation, Ed2kSharedSourceInvalidationSignal,
};
use emulebb_ed2k::long_path::{long_path, normal_path_display};

use crate::EmulebbCore;
use crate::shared_directories::{forget_stale_shares, register_monitor_shared_hash};

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

async fn start_shared_source_reconcile_worker(core: &EmulebbCore) {
    let mut worker = core.shared_source_reconcile_worker.lock().await;
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

pub(crate) async fn start_shared_root_health_worker(core: &EmulebbCore) {
    let mut worker = core.shared_root_health_worker.lock().await;
    if core.lifecycle_state_name() != "running" {
        return;
    }
    if worker.as_ref().is_some_and(|worker| !worker.is_finished()) {
        return;
    }
    if let Some(finished) = worker.take() {
        finished.abort();
    }
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    *core.category_probe_sender.lock().unwrap() = Some(sender);
    *worker = Some(tokio::spawn(run_shared_root_health_worker(
        core.clone(),
        receiver,
    )));
}

async fn run_category_probe(
    core: &EmulebbCore,
    job: crate::persistence_owner::category::CategoryProbeJob,
) {
    // The handle survives cancellation of this health generation. A later
    // generation waits for the same slot before starting another probe.
    let mut slot = core.category_probe_slot.lock().await;
    if let Some(previous) = slot.as_mut() {
        #[cfg(test)]
        if let Some(waiting) = core.category_probe_waiting.lock().unwrap().take() {
            let _ = waiting.send(());
        }
        let _ = previous.await;
        slot.take();
    }
    let crate::persistence_owner::category::CategoryProbeJob {
        candidate,
        lease,
        response,
    } = job;
    #[cfg(test)]
    let gate = core.category_probe_gate.lock().unwrap().take();
    *slot = Some(tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        if let Some((entered, release)) = gate {
            let _ = entered.send(());
            let _ = release.recv();
        }
        let matches = emulebb_ed2k::ed2k_transfer::category_copy_matches(&candidate);
        (candidate, matches, lease)
    }));
    if let Some(task) = slot.as_mut()
        && let Ok(result) = task.await
    {
        let _ = response.send(result);
    }
    slot.take();
}

async fn run_shared_root_health_worker(
    core: EmulebbCore,
    mut probes: tokio::sync::mpsc::Receiver<crate::persistence_owner::category::CategoryProbeJob>,
) {
    let roots = match crate::shared_directories::effective_shared_directory_roots(&core).await {
        Ok(roots) => roots,
        Err(error) => {
            tracing::warn!(%error, "failed to load shared roots for health monitor");
            return;
        }
    };
    let mut root_availability = roots
        .into_iter()
        .map(|root| (PathBuf::from(root.path), root.accessible))
        .collect::<HashMap<_, _>>();
    let mut pending_rejoin = HashMap::new();
    let mut root_check = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(2),
        Duration::from_secs(2),
    );
    loop {
        let change = tokio::select! {
            _ = root_check.tick() => None,
            _ = core.shared_root_change.notified() => Some(core.shared_root_change.take_scan_request()),
            Some(job) = probes.recv() => {
                run_category_probe(&core, job).await;
                continue;
            }
        };
        let health_round = async {
            if let Err(error) =
                reconcile_root_health(&core, &mut root_availability, &mut pending_rejoin, change)
                    .await
            {
                tracing::warn!(%error, "failed to reconcile shared-root availability");
            }
        };
        tokio::pin!(health_round);
        loop {
            tokio::select! {
                _ = &mut health_round => break,
                Some(job) = probes.recv() => run_category_probe(&core, job).await,
            }
        }
    }
}

async fn reconcile_root_health(
    core: &EmulebbCore,
    previous: &mut HashMap<PathBuf, bool>,
    pending_rejoin: &mut HashMap<PathBuf, Option<i64>>,
    change: Option<bool>,
) -> anyhow::Result<()> {
    if change.is_some() {
        previous.clear();
    }
    // WHY: an explicit root command already owns a reserved scan. Treating its
    // watch refresh as recovery queues another full inventory after that scan.
    reconcile_root_availability(core, previous, pending_rejoin, change.is_none()).await?;
    if let Some(scan_required) = change
        && core.lifecycle_state_name() == "running"
    {
        rebuild_shared_directory_watch(core).await;
        if scan_required {
            core.reload_shared_directories_detached().await?;
        }
    }
    Ok(())
}

pub(crate) enum RootIoRequest {
    #[cfg(target_os = "linux")]
    RefreshWatchCoverage(
        Arc<tokio::sync::Mutex<Option<SharedDirMonitor>>>,
        tokio::sync::OwnedMutexGuard<()>,
    ),
    Inspect(Vec<SharedDirectoryRoot>),
    InspectDelivery(Vec<SharedDirectoryRoot>, PathBuf, NativeFileFingerprint),
    Canonical(Vec<String>),
}

pub(crate) enum RootIoResult {
    #[cfg(target_os = "linux")]
    WatchesRefreshed(usize),
    Inspected(Vec<(SharedDirectoryRoot, bool)>),
    Canonical(Vec<String>),
}

pub(crate) enum RootSqlResult {
    Mutation(bool),
    Descriptors(Vec<emulebb_metadata::MetadataSharedDirectoryRoot>),
}

pub(crate) async fn run_root_io(
    core: &EmulebbCore,
    request: RootIoRequest,
) -> anyhow::Result<RootIoResult> {
    let mut slot = core.shared_root_snapshot.lock().await;
    if let Some(previous) = slot.as_mut() {
        let _ = previous.await;
        slot.take();
    }
    #[cfg(test)]
    let gate = core.shared_root_io_gate.lock().unwrap().take();
    *slot = Some(tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        if let Some((entered, release)) = gate {
            let _ = entered.send(());
            let _ = release.recv();
        }
        let request = match request {
            RootIoRequest::InspectDelivery(roots, path, fingerprint) => {
                let candidate = emulebb_metadata::MetadataSharedCopyCandidate {
                    path_id: 0,
                    source_path: path,
                    file_size: fingerprint.size_bytes,
                    source_fingerprint: Some(fingerprint),
                };
                if !emulebb_ed2k::ed2k_transfer::category_copy_matches(&candidate) {
                    return Ok(RootIoResult::Inspected(Vec::new()));
                }
                RootIoRequest::Inspect(roots)
            }
            request => request,
        };
        match request {
            #[cfg(target_os = "linux")]
            RootIoRequest::RefreshWatchCoverage(monitor, _gate) => {
                let mut slot = monitor.blocking_lock();
                Ok(RootIoResult::WatchesRefreshed(
                    slot.as_mut()
                        .map_or(0, SharedDirMonitor::refresh_watch_coverage),
                ))
            }
            RootIoRequest::Inspect(roots) => {
                let roots = crate::shared_directories::consolidate_shared_directory_roots(
                    roots
                        .into_iter()
                        .map(|root| emulebb_metadata::MetadataSharedDirectoryRoot {
                            path: root.path,
                            watch_enabled: root.watch_enabled,
                            monitor_owned: root.monitor_owned,
                            shareable: root.shareable,
                            accessible: root.accessible,
                        }),
                );
                Ok(RootIoResult::Inspected(
                    roots
                        .into_iter()
                        .map(|root| {
                            let observed = long_path(Path::new(&root.path)).is_dir();
                            (
                                SharedDirectoryRoot {
                                    path: root.path,
                                    watch_enabled: root.watch_enabled,
                                    monitor_owned: root.monitor_owned,
                                    shareable: root.shareable,
                                    accessible: root.accessible,
                                },
                                observed,
                            )
                        })
                        .collect(),
                ))
            }
            RootIoRequest::Canonical(paths) => Ok(RootIoResult::Canonical(
                paths
                    .iter()
                    .map(|path| crate::shared_file_api::canonical_shared_directory_root(path))
                    .collect::<anyhow::Result<_>>()?,
            )),
            RootIoRequest::InspectDelivery(..) => unreachable!(),
        }
    }));
    let result = slot.as_mut().expect("root snapshot is installed").await;
    slot.take();
    result.map_err(|_| crate::persistence_owner::PersistenceError::Worker)?
}

async fn root_availability_snapshot(core: &EmulebbCore) -> anyhow::Result<HashMap<PathBuf, bool>> {
    let roots = crate::shared_directories::root_descriptors(core).await?;
    let RootIoResult::Inspected(roots) = run_root_io(core, RootIoRequest::Inspect(roots)).await?
    else {
        unreachable!()
    };
    Ok(roots
        .into_iter()
        .map(|(root, observed)| (PathBuf::from(root.path), observed))
        .collect())
}

/// Settle a metadata-owning root update before the profile lease is released.
pub(crate) async fn drain_root_sql(core: &EmulebbCore) -> anyhow::Result<()> {
    let mut slot = core.shared_root_sql.lock().await;
    if let Some(task) = slot.as_mut() {
        let result = task.await;
        slot.take();
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                core.shared_root_fault.store(true, Ordering::Release);
                return Err(error);
            }
            Err(error) => {
                core.shared_root_fault.store(true, Ordering::Release);
                return Err(error.into());
            }
        }
    }
    if core.shared_root_unpublished.load(Ordering::Acquire) {
        anyhow::bail!("root accessibility update committed before health publication stopped");
    }
    if core.shared_root_fault.load(Ordering::Acquire) {
        anyhow::bail!("root SQL worker previously failed");
    }
    Ok(())
}

async fn reconcile_root_availability(
    core: &EmulebbCore,
    previous: &mut HashMap<PathBuf, bool>,
    pending_rejoin: &mut HashMap<PathBuf, Option<i64>>,
    allow_recovery_scan: bool,
) -> anyhow::Result<()> {
    let current = root_availability_snapshot(core).await?;
    let changed = current
        .iter()
        .filter(|(path, accessible)| previous.get(*path) != Some(*accessible))
        .map(|(path, accessible)| (path.clone(), *accessible))
        .collect::<Vec<_>>();
    let missing = current
        .iter()
        .filter(|(_, accessible)| !**accessible)
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    if changed.is_empty() && missing.is_empty() && pending_rejoin.is_empty() {
        return Ok(());
    }
    for (path, accessible) in &changed {
        if *accessible {
            pending_rejoin.insert(
                path.clone(),
                core.metadata_store.shared_root_last_scan_ms(path)?,
            );
        } else {
            pending_rejoin.remove(path);
        }
    }
    pending_rejoin.retain(|path, _| current.get(path) == Some(&true));
    let mut withdrawn = false;
    for root in &missing {
        let root = root.clone();
        let unpublished = Arc::clone(&core.shared_root_unpublished);
        #[cfg(test)]
        let gate = core.shared_root_sql_gate.lock().unwrap().take();
        let root_mutation = core.ed2k_transfers.begin_category_root_mutation().await?;
        let mut slot = core.shared_root_sql.lock().await;
        if core.lifecycle_state_name() != "running" {
            return Err(crate::persistence_owner::PersistenceError::Closing.into());
        }
        if let Some(previous) = slot.as_mut() {
            let result = previous.await;
            slot.take();
            match result {
                Ok(Ok(RootSqlResult::Mutation(changed))) => withdrawn |= changed,
                Ok(Ok(RootSqlResult::Descriptors(_))) => {}
                Ok(Err(error)) => {
                    core.shared_root_fault.store(true, Ordering::Release);
                    return Err(error);
                }
                Err(error) => {
                    core.shared_root_fault.store(true, Ordering::Release);
                    return Err(error.into());
                }
            }
        }
        if core.lifecycle_state_name() != "running" {
            return Err(crate::persistence_owner::PersistenceError::Closing.into());
        }
        let metadata = core.metadata_store.clone();
        *slot = Some(tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            if let Some((entered, release)) = gate {
                let _ = entered.send(());
                let _ = release.recv();
            }
            let _root_mutation = root_mutation;
            let changed = metadata.set_shared_root_accessible(&root, false)?;
            if changed {
                unpublished.store(true, Ordering::Release);
            }
            Ok(RootSqlResult::Mutation(changed))
        }));
        let result = slot.as_mut().expect("root update is installed").await;
        slot.take();
        match result {
            Ok(Ok(RootSqlResult::Mutation(changed))) => withdrawn |= changed,
            Ok(Ok(RootSqlResult::Descriptors(_))) => unreachable!(),
            Ok(Err(error)) => return Err(error),
            Err(error) => {
                core.shared_root_fault.store(true, Ordering::Release);
                return Err(error.into());
            }
        }
    }
    {
        let mut state = core.state.lock().await;
        for root in &mut state.shared_directories {
            if let Some((_, accessible)) = changed
                .iter()
                .find(|(path, _)| normal_path_display(path) == root.path)
            {
                root.accessible = *accessible;
                root.shareable = *accessible;
            }
        }
    }
    if withdrawn {
        core.ed2k_transfers
            .refresh_complete_shared_catalog()
            .await?;
        core.queue_ed2k_shared_catalog_publish();
        core.shared_root_unpublished.store(false, Ordering::Release);
    }
    let recovered = changed.iter().any(|(_, accessible)| *accessible);
    if !core.shared_reload_running.load(Ordering::Acquire) {
        let mut scanned = Vec::new();
        for (path, baseline) in pending_rejoin.iter() {
            let last_scan = core.metadata_store.shared_root_last_scan_ms(path)?;
            if last_scan.is_some() && last_scan != *baseline {
                scanned.push(path.clone());
            }
        }
        for path in scanned {
            pending_rejoin.remove(&path);
        }
    }
    if allow_recovery_scan
        && (recovered
            || (!pending_rejoin.is_empty() && !core.shared_reload_running.load(Ordering::Acquire)))
    {
        core.reload_shared_directories_detached().await?;
    }
    *previous = current;
    Ok(())
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

    match load_shared_file_ignore_policy(core) {
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
            let replaced = register_monitor_shared_hash(
                core,
                key.clone(),
                &share.hash,
                source_fingerprint.clone(),
            )
            .await;
            if let Some(fingerprint) = source_fingerprint.as_ref()
                && let Err(error) = admit_monitored_path(core, &key, fingerprint, &share.hash).await
            {
                tracing::warn!(path = %key.display(), %error, "failed to admit monitored shared file");
            }
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
    if let Err(error) = core
        .ed2k_transfers
        .withdraw_monitored_shared_path(&invalidation.file_hash, key)
        .await
    {
        return TargetedRehashOutcome::Retry(error);
    }
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
            forget_stale_shares(core, std::slice::from_ref(&invalidation.file_hash), "").await;
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
    Ok(core
        .metadata_store
        .active_local_file_by_hash(file_hash)?
        .is_some())
}

pub(crate) async fn admit_monitored_path(
    core: &EmulebbCore,
    path: &Path,
    fingerprint: &NativeFileFingerprint,
    file_hash: &str,
) -> anyhow::Result<bool> {
    admit_verified_path(core, path, fingerprint, file_hash, false).await
}

/// Capture only matching ordinary roots using the existing tracked descriptor
/// and filesystem providers. Ingest validates this observation again in its
/// binding transaction; no membership handoff remains in the caller.
pub(crate) async fn prepare_ingest_roots(
    core: &EmulebbCore,
    path: &Path,
) -> anyhow::Result<Vec<emulebb_metadata::MetadataIngestRoot>> {
    for _ in 0..16 {
        let epoch = core.ed2k_transfers.root_observation_epoch().await;
        let roots = crate::shared_directories::root_descriptors(core).await?;
        let RootIoResult::Inspected(roots) =
            run_root_io(core, RootIoRequest::Inspect(roots)).await?
        else {
            unreachable!()
        };
        let mut matching = Vec::new();
        for (root, observed) in roots {
            if !root.shareable || !root.accessible || !observed {
                continue;
            }
            let root_path = PathBuf::from(root.path);
            let normalized = long_path(&root_path);
            if let Ok(relative) = path.strip_prefix(&normalized)
                && !relative.as_os_str().is_empty()
            {
                matching.push(emulebb_metadata::MetadataIngestRoot {
                    root: root_path,
                    relative: relative.to_path_buf(),
                });
            }
        }
        if core.ed2k_transfers.root_observation_epoch().await == epoch {
            return Ok(matching);
        }
    }
    Err(emulebb_ed2k::ed2k_transfer::LocalMutationError::Busy.into())
}

pub(crate) async fn admit_delivered_path(
    core: &EmulebbCore,
    path: &Path,
    fingerprint: &NativeFileFingerprint,
    file_hash: &str,
) -> anyhow::Result<bool> {
    admit_verified_path(core, path, fingerprint, file_hash, true).await
}

async fn admit_verified_path(
    core: &EmulebbCore,
    path: &Path,
    fingerprint: &NativeFileFingerprint,
    file_hash: &str,
    recover_observed_root: bool,
) -> anyhow::Result<bool> {
    for _ in 0..16 {
        let epoch = if recover_observed_root {
            Some(core.ed2k_transfers.root_observation_epoch().await)
        } else {
            None
        };
        let roots = crate::shared_directories::root_descriptors(core).await?;
        let request = if recover_observed_root {
            RootIoRequest::InspectDelivery(roots, path.to_path_buf(), fingerprint.clone())
        } else {
            RootIoRequest::Inspect(roots)
        };
        let RootIoResult::Inspected(roots) = run_root_io(core, request).await? else {
            unreachable!()
        };
        let mut admitted = false;
        let mut retry = false;
        for (root, observed) in roots {
            if !root.shareable || !observed || (!root.accessible && !recover_observed_root) {
                continue;
            }
            let root_path = PathBuf::from(&root.path);
            let normalized_root = long_path(&root_path);
            let Ok(relative) = path.strip_prefix(&normalized_root) else {
                continue;
            };
            match core
                .ed2k_transfers
                .admit_monitored_shared_path(
                    file_hash,
                    &root_path,
                    path,
                    relative,
                    fingerprint,
                    epoch,
                )
                .await
            {
                Ok(value) => admitted |= value,
                Err(error)
                    if recover_observed_root
                        && matches!(
                            error.downcast_ref::<emulebb_ed2k::ed2k_transfer::LocalMutationError>(),
                            Some(emulebb_ed2k::ed2k_transfer::LocalMutationError::Busy)
                        ) =>
                {
                    retry = true;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        if retry {
            tokio::task::yield_now().await;
            continue;
        }
        if admitted {
            core.queue_ed2k_shared_catalog_publish();
        }
        return Ok(admitted);
    }
    Err(emulebb_ed2k::ed2k_transfer::LocalMutationError::Busy.into())
}

/// (Re)start the live shared-directory auto-pickup monitor for the configured
/// roots. Tears down any previous monitor first, then watches each accessible
/// root recursively. On a settled create/modify the file is
/// auto-shared via [`EmulebbCore::share_local_file`]; on a settled
/// remove/rename-away it is dropped from the shared catalog. Tolerant of a
/// per-root watch failure (logged; that root degrades to scan-on-demand).
pub(crate) async fn start_shared_directory_monitor(core: &EmulebbCore) {
    let _lifecycle = core.shared_monitor_lifecycle.lock().await;
    // Drop any existing monitor before rebuilding the watch set.
    if let Err(error) = stop_monitor_locked(core).await {
        tracing::warn!(%error, "failed to join prior shared monitor");
        return;
    }
    if core.lifecycle_state_name() != "running" {
        return;
    }
    core.shared_monitor_stopped.store(false, Ordering::Release);
    start_shared_source_reconcile_worker(core).await;
    start_shared_root_health_worker(core).await;

    if let Err(error) = crate::shared_directories::sync_implicit_shared_directory_roots(core).await
    {
        tracing::warn!(%error, "failed to synchronize implicit shared roots");
        return;
    }
    rebuild_shared_directory_watch(core).await;
}

async fn watched_root_identities(core: &EmulebbCore) -> anyhow::Result<Vec<(PathBuf, i64)>> {
    let mut roots = Vec::new();
    let mut after = 0;
    loop {
        let page = core.library_root_page(after, 100).await?;
        for root in &page.value().roots {
            if root.watch_enabled {
                roots.push((monitor_shared_key(Path::new(&root.path)), root.id.parse()?));
            }
        }
        match page.value().next_id {
            Some(next) => after = next,
            None => return Ok(roots),
        }
    }
}

/// Re-arm native coverage only as part of an explicit/startup scan, using the
/// same gate order as rebuild/stop before the tracked root I/O worker.
#[cfg(target_os = "linux")]
pub(crate) async fn refresh_shared_watch_for_scan(core: &EmulebbCore) -> anyhow::Result<()> {
    // Retain the gate inside the tracked job: cancellation must not let a
    // rebuild hold the monitor while waiting for this job to lock that monitor.
    let gate = Arc::clone(&core.shared_watcher_gate).lock_owned().await;
    if core.shared_monitor_stopped.load(Ordering::Acquire) {
        return Ok(());
    }
    match run_root_io(
        core,
        RootIoRequest::RefreshWatchCoverage(Arc::clone(&core.shared_dir_monitor), gate),
    )
    .await?
    {
        RootIoResult::WatchesRefreshed(roots) => {
            tracing::debug!(roots, "refreshed native watch coverage for explicit scan");
            Ok(())
        }
        _ => unreachable!(),
    }
}

async fn mark_watcher_loss(
    core: &EmulebbCore,
    roots: &[(PathBuf, i64)],
    paths: &[PathBuf],
) -> anyhow::Result<()> {
    let paths = paths
        .iter()
        .map(|path| monitor_shared_key(path))
        .collect::<Vec<_>>();
    let affected = |root: &Path| {
        paths
            .iter()
            .any(|path| path.starts_with(root) || root.starts_with(path))
    };
    // Unknown backend/overflow scope flags every subscription. Otherwise bind
    // the notice to the captured immutable IDs, never a replacement at its path.
    let unknown = paths.is_empty() || !roots.iter().any(|(root, _)| affected(root));
    let owner = core
        .persistence_owner
        .owner(&core.metadata_store, &core.state)?;
    for (root, id) in roots {
        if unknown || affected(root) {
            owner.mark_root_scan_required(*id).await?;
        }
    }
    Ok(())
}

async fn rebuild_shared_directory_watch(core: &EmulebbCore) {
    let _gate = core.shared_watcher_gate.lock().await;
    if core.lifecycle_state_name() != "running"
        || core.shared_monitor_stopped.load(Ordering::Acquire)
    {
        return;
    }
    let roots = match crate::shared_directories::root_descriptors(core).await {
        Ok(roots) => roots,
        Err(error) => {
            tracing::warn!(%error, "failed to load roots for watcher");
            return;
        }
    };
    let roots = match run_root_io(core, RootIoRequest::Inspect(roots)).await {
        Ok(RootIoResult::Inspected(roots)) => roots
            .into_iter()
            .map(|(mut root, observed)| {
                root.accessible = observed;
                root
            })
            .collect::<Vec<_>>(),
        Ok(_) => unreachable!(),
        Err(error) => {
            tracing::warn!(%error, "failed to inspect watcher roots");
            return;
        }
    };
    let root_ids = match watched_root_identities(core).await {
        Ok(roots) => Arc::new(roots),
        Err(error) => {
            if core.lifecycle_state_name() == "running"
                && !core.shared_monitor_stopped.load(Ordering::Acquire)
            {
                core.shared_monitor_fault.store(true, Ordering::Release);
            }
            tracing::warn!(%error, "failed to bind watcher root identities");
            return;
        }
    };
    let mut slot = core.shared_dir_monitor.lock().await;
    // WHY: root notifications can outlive the command/startup that already
    // installed the same subscriptions. Replacing a healthy identical watcher
    // drops unsettled events and creates a gap where a one-time write is lost.
    if slot
        .as_ref()
        .is_some_and(|monitor| monitor.matches(&roots, &root_ids))
    {
        return;
    }
    if let Some(monitor) = slot.as_mut() {
        if let Err(error) = monitor.stop().await {
            core.shared_monitor_fault.store(true, Ordering::Release);
            tracing::warn!(%error, "failed to join shared monitor consumer");
        }
        slot.take();
    }
    if core.lifecycle_state_name() != "running"
        || core.shared_monitor_stopped.load(Ordering::Acquire)
    {
        return;
    }
    let binding_ids = Arc::clone(&root_ids);
    let applier = core.clone();
    let monitor = start_monitor(&roots, move |action| {
        let applier = applier.clone();
        let root_ids = Arc::clone(&root_ids);
        async move { apply_monitor_action(&applier, &root_ids, action).await }
    });

    *slot = monitor.map(|mut monitor| {
        monitor.binding_ids = binding_ids;
        monitor
    });
    if core.lifecycle_state_name() != "running"
        || core.shared_monitor_stopped.load(Ordering::Acquire)
    {
        if let Some(monitor) = slot.as_mut()
            && let Err(error) = monitor.stop().await
        {
            core.shared_monitor_fault.store(true, Ordering::Release);
            tracing::warn!(%error, "failed to join stopped shared monitor consumer");
        }
        slot.take();
    }
}

async fn apply_monitor_action(core: &EmulebbCore, roots: &[(PathBuf, i64)], action: MonitorAction) {
    // WHY: replacement membership belongs to the walk's snapshot. Serialize
    // ordinary watcher edits behind that scan so it cannot prune a newer edit.
    // Keep loss writes independent: scan/stop lock ordering requires their drain
    // to finish even while a scan owns this gate. The caller can cancel only the
    // ordinary lock wait/work; accepted mutations retain their existing owner.
    let _scan = if matches!(action, MonitorAction::ScanRequired(_)) {
        None
    } else {
        Some(core.shared_reload_gate.lock().await)
    };
    let loss = match action {
        MonitorAction::Share(path) => auto_share_monitored_path(core, &path)
            .await
            .then(|| vec![path]),
        MonitorAction::Remove(path) => {
            auto_unshare_monitored_path(core, &path).await;
            None
        }
        MonitorAction::Rename { from, to } => auto_relocate_monitored_path(core, &from, &to)
            .await
            .then(|| vec![from, to]),
        MonitorAction::ScanRequired(paths) => Some(paths),
    };
    drop(_scan);
    if let Some(paths) = loss
        && let Err(error) = mark_watcher_loss(core, roots, &paths).await
    {
        core.shared_monitor_fault.store(true, Ordering::Release);
        tracing::warn!(%error, "failed to persist watcher loss; explicit scan required");
    }
}

/// Relocate an already-shared source after a paired filesystem rename.
///
/// Renaming a 100k-file library cohort must be metadata-only: unshare + ingest
/// would reread unchanged payload bytes, churn the catalog, and briefly make the
/// file unavailable. If the native fingerprint changed during the move, relocate first and
/// then let the regular share path rehash exactly once from the destination.
/// Returns true for a directory destination whose descendants require a scan.
async fn auto_relocate_monitored_path(core: &EmulebbCore, from: &Path, to: &Path) -> bool {
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
        return auto_share_monitored_path(core, to).await;
    };
    let metadata = match tokio::fs::metadata(&new_key).await {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(metadata) if metadata.is_dir() => {
            auto_unshare_monitored_path(core, from).await;
            return true;
        }
        _ => {
            auto_unshare_monitored_path(core, from).await;
            return false;
        }
    };
    match load_shared_file_ignore_policy(core) {
        Ok(policy) if policy.should_ignore(&new_key, &metadata) => {
            auto_unshare_monitored_path(core, from).await;
            return false;
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(
                path = %to.display(),
                error = %error,
                "failed to load shared-file exclusions for monitored rename",
            );
            return false;
        }
    }
    let (_, _file_size, source_fingerprint) =
        emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime::scanned_source_identity_from_metadata(
            &new_key, &metadata,
        );
    let identity_unchanged = previous
        .source_fingerprint
        .as_ref()
        .zip(source_fingerprint.as_ref())
        .is_some_and(|(stored, current)| stored.safely_matches(current));
    if !identity_unchanged {
        auto_unshare_monitored_path(core, from).await;
        return auto_share_monitored_path(core, to).await;
    }
    let Some(fingerprint) = source_fingerprint.as_ref() else {
        return false;
    };
    let metadata = core.metadata_store.clone();
    let new_path = new_key.clone();
    let hash = previous.hash.clone();
    let cached_fingerprint = fingerprint.clone();
    let cache_result = tokio::task::spawn_blocking(move || {
        let existing = metadata
            .reusable_local_file_by_identity(&cached_fingerprint)?
            .context("renamed source has no matching verified identity evidence")?;
        anyhow::ensure!(
            existing.file_hash == hash,
            "renamed source identity belongs to different content"
        );
        let evidence = emulebb_metadata::NativeFileIdentityEvidence::new(
            cached_fingerprint.identity,
            existing.secondary_identity,
        )?;
        metadata.upsert_local_file_instance(&new_path, &hash, &cached_fingerprint, evidence)
    })
    .await;
    match cache_result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::warn!(from = %from.display(), to = %to.display(), %error, "failed to cache renamed shared path");
            return false;
        }
        Err(error) => {
            tracing::warn!(from = %from.display(), to = %to.display(), %error, "renamed shared path cache task panicked");
            return false;
        }
    }
    match admit_monitored_path(core, &new_key, fingerprint, &previous.hash).await {
        Ok(true) => {
            if let Err(error) = core
                .ed2k_transfers
                .withdraw_monitored_shared_path(&previous.hash, &old_key)
                .await
            {
                tracing::warn!(from = %from.display(), %error, "failed to withdraw renamed old path");
                return false;
            }
            let current_hash = previous.hash.clone();
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
            if let Err(error) = core
                .ed2k_transfers
                .refresh_shared_catalog_entry(&current_hash)
                .await
            {
                tracing::warn!(%error, "failed to refresh catalog after monitored rename");
            }
        }
        Ok(false) => auto_unshare_monitored_path(core, from).await,
        Err(error) => {
            tracing::warn!(from = %from.display(), to = %to.display(), %error, "failed to admit renamed shared path")
        }
    }
    false
}

/// Stop the live shared-directory monitor (if running). Idempotent.
pub(crate) async fn stop_shared_directory_monitor(core: &EmulebbCore) -> anyhow::Result<()> {
    let _lifecycle = core.shared_monitor_lifecycle.lock().await;
    stop_monitor_locked(core).await
}

async fn stop_worker(
    slot: &tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
) -> anyhow::Result<()> {
    let mut slot = slot.lock().await;
    if let Some(worker) = slot.as_mut() {
        worker.abort();
        let result = worker.await;
        slot.take();
        if let Err(error) = result
            && !error.is_cancelled()
        {
            return Err(error.into());
        }
    }
    Ok(())
}

async fn stop_monitor_locked(core: &EmulebbCore) -> anyhow::Result<()> {
    core.shared_monitor_stopped.store(true, Ordering::Release);
    core.category_probe_sender.lock().unwrap().take();
    let health = stop_worker(&core.shared_root_health_worker).await;
    if health.is_err() {
        core.shared_monitor_fault.store(true, Ordering::Release);
    }
    let reconcile = stop_worker(&core.shared_source_reconcile_worker).await;
    if reconcile.is_err() {
        core.shared_monitor_fault.store(true, Ordering::Release);
    }
    let _watcher = core.shared_watcher_gate.lock().await;
    let mut slot = core.shared_dir_monitor.lock().await;
    let monitor = if let Some(monitor) = slot.as_mut() {
        monitor.stop().await
    } else {
        Ok(())
    };
    if monitor.is_err() {
        core.shared_monitor_fault.store(true, Ordering::Release);
    }
    slot.take();
    health.and(reconcile).and(monitor)?;
    if core.shared_monitor_fault.load(Ordering::Acquire) {
        anyhow::bail!("shared monitor consumer failed during a prior rebuild");
    }
    Ok(())
}

/// Auto-share a file picked up by the live monitor. Goes through the same ingest
/// path as a manual share (MD4/AICH/catalog consistent), then records the
/// source-path -> hash mapping so a later remove can resolve it. Re-sharing an
/// already-shared identical file is cheap/idempotent. A vanished/unreadable file
/// (settled then disappeared) is logged and skipped, not propagated.
/// Returns true when the existing metadata read discovers a directory event.
async fn auto_share_monitored_path(core: &EmulebbCore, path: &Path) -> bool {
    let key = monitor_shared_key(path);
    let metadata = match tokio::fs::metadata(&key).await {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(metadata) if metadata.is_dir() => {
            auto_unshare_monitored_path(core, path).await;
            return true;
        }
        // Windows can report an ambiguous rename/modify event for a path that
        // has already disappeared. Reconcile it as a removal so the old hash is
        // not left offered until a manual reload. Other non-file types cannot
        // contribute a verified file entry.
        Ok(_) => {
            auto_unshare_monitored_path(core, path).await;
            return false;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            auto_unshare_monitored_path(core, path).await;
            return false;
        }
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "failed to stat monitored file (skipping)",
            );
            return false;
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
        return false;
    }
    // WHY: an unpaired destination event is a common Windows rename shape.
    // Reuse a vanished path's verified native identity before starting a full
    // MD4/AICH pass, while a still-present hard link remains an independent path.
    let prior_paths = core
        .state
        .lock()
        .await
        .monitor_shared_hashes
        .iter()
        .filter(|(old_path, entry)| {
            old_path.as_path() != key.as_path()
                && entry
                    .source_fingerprint
                    .as_ref()
                    .zip(source_fingerprint.as_ref())
                    .is_some_and(|(stored, current)| stored.safely_matches(current))
        })
        .map(|(old_path, _)| old_path.clone())
        .collect::<Vec<_>>();
    for old_path in prior_paths {
        if tokio::fs::symlink_metadata(&old_path)
            .await
            .is_ok_and(|metadata| metadata.file_type().is_file())
        {
            continue;
        }
        if Box::pin(auto_relocate_monitored_path(core, &old_path, &key)).await {
            return true;
        }
        if core
            .metadata_store
            .local_file_has_root_membership(&key)
            .unwrap_or(false)
        {
            return false;
        }
    }
    match core
        .share_native_local_file_with_progress(path, None, None)
        .await
    {
        Ok(share) => {
            let replaced = register_monitor_shared_hash(
                core,
                key.clone(),
                &share.hash,
                source_fingerprint.clone(),
            )
            .await;
            let admitted = if let Some(fingerprint) = source_fingerprint.as_ref() {
                match admit_monitored_path(core, &key, fingerprint, &share.hash).await {
                    Ok(admitted) => admitted,
                    Err(error) => {
                        tracing::warn!(path = %key.display(), %error, "failed to admit monitored shared file");
                        false
                    }
                }
            } else {
                false
            };
            if admitted {
                // WHY: Windows can report only a destination Share for a rename.
                // Retire vanished paths for this hash so the deterministic first
                // eligible filename cannot keep advertising the old name.
                let aliases = core
                    .state
                    .lock()
                    .await
                    .monitor_shared_hashes
                    .iter()
                    .filter(|(path, entry)| {
                        path.as_path() != key.as_path()
                            && entry.hash.eq_ignore_ascii_case(&share.hash)
                    })
                    .map(|(path, _)| path.clone())
                    .collect::<Vec<_>>();
                for alias in aliases {
                    if !tokio::fs::symlink_metadata(&alias)
                        .await
                        .is_ok_and(|metadata| metadata.file_type().is_file())
                    {
                        auto_unshare_monitored_path(core, &alias).await;
                    }
                }
            }
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
    false
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
    let key = monitor_shared_key(path);
    let withdrawn = core
        .ed2k_transfers
        .withdraw_monitored_shared_path(&hash, &key)
        .await;
    match withdrawn {
        Ok(_) => {
            if let Err(error) = core
                .ed2k_transfers
                .refresh_shared_catalog_entry(&hash)
                .await
            {
                tracing::warn!(path = %path.display(), %hash, %error, "failed to refresh catalog after monitored removal");
            } else {
                core.queue_ed2k_shared_catalog_publish();
                tracing::debug!(path = %path.display(), %hash, "withdrew monitored shared path");
            }
        }
        Err(error) => {
            tracing::warn!(path = %path.display(), %hash, %error, "failed to withdraw monitored path")
        }
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn coalesced_watch_refresh_keeps_an_unowned_scan_request() {
        let signal = super::RootChangeSignal::default();
        signal.scan_required();
        signal.watch_changed();
        signal.notified().await;
        assert!(signal.take_scan_request());
        signal.watch_changed();
        signal.notified().await;
        assert!(!signal.take_scan_request());
        signal.watch_changed();
        signal.scan_required();
        signal.notified().await;
        assert!(signal.take_scan_request());
    }

    #[tokio::test]
    async fn root_watch_refresh_does_not_repeat_a_reserved_scan() {
        let core = crate::EmulebbCore::new_in_memory(
            "test",
            emulebb_index::FileIndex::in_memory().unwrap(),
        )
        .unwrap();
        let root = crate::unique_runtime_dir("root-scan-owner");
        let execution = core.shared_reload_gate.lock().await;
        core.create_library_root(&root.to_string_lossy(), false)
            .await
            .unwrap()
            .unwrap();
        core.shared_root_change.notified().await;
        let scan_required = core.shared_root_change.take_scan_request();
        assert!(!scan_required, "the committed root command owns this scan");
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while core
                .shared_reload_pending
                .load(std::sync::atomic::Ordering::Acquire)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            core.shared_reload_running
                .load(std::sync::atomic::Ordering::Acquire)
        );
        let mut previous = std::collections::HashMap::new();
        let mut pending = std::collections::HashMap::new();
        super::reconcile_root_health(&core, &mut previous, &mut pending, Some(scan_required))
            .await
            .unwrap();
        assert!(
            !core
                .shared_reload_pending
                .load(std::sync::atomic::Ordering::Acquire),
            "watch refresh must not schedule a second full inventory"
        );
        // Category changes have no pre-reserved scan and must retain one.
        super::reconcile_root_health(&core, &mut previous, &mut pending, Some(true))
            .await
            .unwrap();
        assert!(
            core.shared_reload_pending
                .load(std::sync::atomic::Ordering::Acquire)
        );
        drop(execution);
        core.drain_persistence().await.unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    use super::*;
    use emulebb_metadata::MetadataSharedDirectoryRoot;
    use notify_debouncer_full::notify::Event;
    use notify_debouncer_full::notify::event::{CreateKind, Flag, RemoveKind};
    use std::future::{Future, poll_fn};
    use std::sync::Mutex;
    use std::task::Poll;
    use std::time::Instant;

    #[test]
    fn unwatched_roots_do_not_create_a_native_monitor() {
        let monitor = start_monitor(
            &[SharedDirectoryRoot {
                path: std::env::temp_dir().display().to_string(),
                watch_enabled: false,
                monitor_owned: false,
                shareable: true,
                accessible: true,
            }],
            |_| async { panic!("an unwatched root must not deliver actions") },
        );
        assert!(monitor.is_none());
    }

    #[tokio::test]
    async fn redundant_root_refresh_retains_the_native_subscription() {
        let base =
            std::env::temp_dir().join(format!("watch-subscription-{}", uuid::Uuid::new_v4()));
        let root = base.join("shared");
        std::fs::create_dir_all(&root).unwrap();
        let core = EmulebbCore::new_in_memory(
            "watch-subscription",
            emulebb_index::FileIndex::in_memory().unwrap(),
        )
        .unwrap()
        .with_incoming_dir(base.join("incoming"));
        core.create_library_root(&root.display().to_string(), true)
            .await
            .unwrap()
            .unwrap();
        core.start_shared_directory_monitor().await;
        let original = core
            .shared_dir_monitor
            .lock()
            .await
            .as_ref()
            .unwrap()
            .stop
            .clone();
        rebuild_shared_directory_watch(&core).await;
        let current = core
            .shared_dir_monitor
            .lock()
            .await
            .as_ref()
            .unwrap()
            .stop
            .clone();
        assert!(
            original.same_channel(&current),
            "identical root refresh must retain the native subscription"
        );
        core.drain_persistence().await.unwrap();
        drop(core);
        std::fs::remove_dir_all(base).unwrap();
    }

    /// Model a missed native directory-registration event independently of
    /// kernel queue timing, then prove the existing consumer sees later writes.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tracked_watch_refresh_restores_missing_recursive_subscription() {
        let root =
            std::env::temp_dir().join(format!("emulebb-watch-refresh-{}", uuid::Uuid::new_v4()));
        let nested = root.join("nested");
        let target = nested.join("after-refresh.bin");
        std::fs::create_dir_all(&nested).unwrap();
        let core = EmulebbCore::new_in_memory(
            "watch-refresh",
            emulebb_index::FileIndex::in_memory().unwrap(),
        )
        .unwrap();
        let observed = Arc::new(tokio::sync::Notify::new());
        let signal = Arc::clone(&observed);
        let expected = target.clone();
        let mut monitor = start_monitor(
            &[SharedDirectoryRoot {
                path: root.to_string_lossy().into_owned(),
                accessible: true,
                watch_enabled: true,
                monitor_owned: false,
                shareable: true,
            }],
            move |action| {
                let signal = Arc::clone(&signal);
                let matches = action == MonitorAction::Share(expected.clone());
                async move {
                    if matches {
                        signal.notify_one();
                    }
                }
            },
        )
        .unwrap();
        // Root registration initially includes the child. Remove only that
        // native subscription, leaving the directory and consumer in place.
        monitor
            .debouncer
            .as_mut()
            .unwrap()
            .unwatch(&nested)
            .unwrap();
        *core.shared_dir_monitor.lock().await = Some(monitor);
        let result = run_root_io(
            &core,
            RootIoRequest::RefreshWatchCoverage(
                Arc::clone(&core.shared_dir_monitor),
                Arc::clone(&core.shared_watcher_gate).lock_owned().await,
            ),
        )
        .await
        .unwrap();
        assert!(matches!(result, RootIoResult::WatchesRefreshed(1)));
        std::fs::write(&target, b"changed after repaired subscription").unwrap();
        tokio::time::timeout(Duration::from_secs(20), observed.notified())
            .await
            .expect("repaired recursive watch did not deliver the file event");
        stop_shared_directory_monitor(&core).await.unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn cancelled_stop_retains_the_join_for_the_next_stop() {
        let core = Arc::new(
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap(),
        );
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        *core.shared_root_health_worker.lock().await =
            Some(tokio::task::spawn_blocking(move || {
                let _ = entered.send(());
                let _ = release_rx.recv();
            }));
        tokio::time::timeout(Duration::from_secs(5), entered_rx)
            .await
            .unwrap()
            .unwrap();
        let mut first = Box::pin(core.stop_shared_directory_monitor());
        assert!(
            poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(first);
        let mut second = Box::pin(core.stop_shared_directory_monitor());
        assert!(
            poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .unwrap()
            .unwrap();
        assert!(core.shared_root_health_worker.lock().await.is_none());
    }

    #[tokio::test]
    async fn cancelled_stop_keeps_an_already_observed_worker_failure() {
        let core = Arc::new(
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap(),
        );
        let failed: tokio::task::JoinHandle<()> =
            tokio::spawn(async { panic!("injected monitor worker failure") });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !failed.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        *core.shared_root_health_worker.lock().await = Some(failed);
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        *core.shared_source_reconcile_worker.lock().await =
            Some(tokio::task::spawn_blocking(move || {
                let _ = entered.send(());
                let _ = release_rx.recv();
            }));
        tokio::time::timeout(Duration::from_secs(5), entered_rx)
            .await
            .unwrap()
            .unwrap();
        let mut first = Box::pin(core.stop_shared_directory_monitor());
        assert!(
            poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(first);
        let mut second = Box::pin(core.stop_shared_directory_monitor());
        assert!(
            poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        release.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), second)
                .await
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test]
    async fn public_drain_stops_monitor_and_prevents_rearming_root_sql() {
        let core =
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            core.start_shared_directory_monitor(),
        )
        .await
        .unwrap();
        assert!(core.shared_root_health_worker.lock().await.is_some());
        tokio::time::timeout(Duration::from_secs(5), core.drain_persistence())
            .await
            .unwrap()
            .unwrap();
        assert!(core.shared_root_health_worker.lock().await.is_none());
        assert!(core.shared_source_reconcile_worker.lock().await.is_none());
        core.shared_root_change.scan_required();
        tokio::time::timeout(
            Duration::from_secs(5),
            core.start_shared_directory_monitor(),
        )
        .await
        .unwrap();
        assert!(core.shared_root_health_worker.lock().await.is_none());
        assert!(core.shared_root_sql.lock().await.is_none());
        assert!(
            crate::shared_directories::implicit_shared_directory_roots(&core)
                .await
                .is_err()
        );
        assert!(
            crate::shared_directories::sync_implicit_shared_directory_roots(&core)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cancelled_root_probe_retains_the_single_io_slot() {
        let core = Arc::new(
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap(),
        );
        let root = crate::unique_runtime_dir("retained-root-probe");
        configure_test_shared_root(&core, &root).await;
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        *core.shared_root_io_gate.lock().unwrap() = Some((entered, release_rx));
        let first = {
            let core = Arc::clone(&core);
            tokio::spawn(async move { root_availability_snapshot(&core).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered_rx)
            .await
            .unwrap()
            .unwrap();
        first.abort();
        let _ = first.await;
        assert!(core.shared_root_snapshot.lock().await.is_some());
        let mut second = Box::pin(root_availability_snapshot(&core));
        assert!(
            poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        release.send(()).unwrap();
        let observed = tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .unwrap()
            .unwrap();
        assert!(observed.values().any(|accessible| *accessible));
    }

    #[tokio::test]
    async fn terminal_drain_rejects_root_sql_after_late_path_io() {
        let core = Arc::new(
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap(),
        );
        let root = crate::unique_runtime_dir("late-root-admission");
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        *core.shared_root_io_gate.lock().unwrap() = Some((entered, release_rx));
        let add = {
            let core = Arc::clone(&core);
            let root = root.clone();
            tokio::spawn(async move {
                core.create_library_root(&root.to_string_lossy(), false)
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), entered_rx)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), core.drain_persistence())
            .await
            .unwrap()
            .unwrap();
        release.send(()).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), add)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<crate::persistence_owner::PersistenceError>(),
            Some(crate::persistence_owner::PersistenceError::Closing)
        ));
        assert!(core.shared_root_sql.lock().await.is_none());
        assert!(
            core.metadata_store
                .shared_directory_roots()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn cancelled_start_retains_implicit_root_sql_for_terminal_drain() {
        let core = Arc::new(
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap(),
        );
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        *core.shared_implicit_sql_gate.lock().unwrap() = Some((entered, release_rx));
        let start = {
            let core = Arc::clone(&core);
            tokio::spawn(async move { core.start_shared_directory_monitor().await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered_rx)
            .await
            .unwrap()
            .unwrap();
        start.abort();
        let _ = start.await;
        tokio::time::timeout(Duration::from_secs(5), core.stop_shared_directory_monitor())
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), core.shared_root_sql.lock())
                .await
                .unwrap()
                .is_some()
        );
        let mut drain = Box::pin(core.drain_persistence());
        assert!(
            poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        release.send(()).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), drain)
            .await
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("committed"));
        assert!(core.shared_root_health_worker.lock().await.is_none());
    }

    #[tokio::test]
    async fn stopped_health_retains_actual_root_sql_until_settled() {
        let profile = crate::unique_runtime_dir("held-root-sql-profile");
        let lock_path = profile.join(".emulebb-profile.lock");
        let open_lock = || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)
                .unwrap()
        };
        let lease = Arc::new(emulebb_metadata::ProfileLeaseGuard::try_lock(open_lock()).unwrap());
        let store = emulebb_metadata::MetadataStore::open_with_profile_lease(
            profile.join("metadata.sqlite"),
            lease,
        )
        .unwrap();
        let core = Arc::new(
            EmulebbCore::new(
                "test",
                emulebb_index::FileIndex::from_metadata_store(store),
                profile.join("transfers"),
            )
            .unwrap(),
        );
        let root = crate::unique_runtime_dir("held-root-sql").join("missing");
        std::fs::create_dir_all(&core.incoming_dir).unwrap();
        configure_test_shared_root(&core, &root).await;
        let roots = crate::shared_directories::effective_shared_directory_roots(&core)
            .await
            .unwrap();
        let missing: Vec<_> = roots
            .iter()
            .filter(|item| !long_path(Path::new(&item.path)).is_dir())
            .collect();
        assert_eq!(missing.len(), 1);
        assert_eq!(
            crate::shared_directories::shared_root_comparison_key(Path::new(&missing[0].path)),
            crate::shared_directories::shared_root_comparison_key(&root)
        );
        assert!(core.metadata_store.shared_directory_roots().unwrap()[0].accessible);
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        *core.shared_root_sql_gate.lock().unwrap() = Some((entered, release_rx));
        let worker = {
            let core = Arc::clone(&core);
            let root = root.clone();
            tokio::spawn(async move {
                let mut previous = HashMap::from([(root, true)]);
                let mut pending = HashMap::new();
                let _ = reconcile_root_availability(&core, &mut previous, &mut pending, true).await;
            })
        };
        *core.shared_root_health_worker.lock().await = Some(worker);
        tokio::time::timeout(Duration::from_secs(5), entered_rx)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), core.stop_shared_directory_monitor())
            .await
            .unwrap()
            .unwrap();
        let mut drain = Box::pin(drain_root_sql(&core));
        assert!(
            poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        assert!(matches!(
            emulebb_metadata::ProfileLeaseGuard::try_lock(open_lock()),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        release.send(()).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), drain)
            .await
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("committed"));
        let native = emulebb_metadata::NativePath::from(root.as_path());
        let conn = rusqlite::Connection::open(profile.join("metadata.sqlite")).unwrap();
        let accessible: bool = conn.query_row(
            "SELECT r.accessible FROM shared_directory_roots r JOIN local_paths p ON p.id=r.path_id WHERE p.platform=?1 AND p.native_path=?2",
            rusqlite::params![emulebb_metadata::NativePath::platform(), native.storage_bytes()],
            |row| row.get(0),
        ).unwrap();
        assert!(!accessible);
        drop(conn);
        drop(core);
        let next = emulebb_metadata::ProfileLeaseGuard::try_lock(open_lock()).unwrap();
        drop(next);
    }

    #[tokio::test]
    async fn repeated_root_drains_retain_the_worker_failure() {
        let core =
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
        *core.shared_root_sql.lock().await = Some(tokio::task::spawn_blocking(|| {
            Err(anyhow::anyhow!("injected root SQL failure"))
        }));
        assert!(
            tokio::time::timeout(Duration::from_secs(5), drain_root_sql(&core))
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(5), drain_root_sql(&core))
                .await
                .unwrap()
                .is_err()
        );
    }

    async fn configure_test_shared_root(core: &EmulebbCore, root: &Path) {
        core.state.lock().await.shared_directories = vec![SharedDirectoryRoot {
            path: root.display().to_string(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }];
        let mut metadata = core.metadata_store.clone();
        metadata
            .replace_shared_directory_roots(&[MetadataSharedDirectoryRoot {
                path: root.display().to_string(),
                watch_enabled: false,
                monitor_owned: false,
                shareable: true,
                accessible: true,
            }])
            .unwrap();
    }

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
    fn loss_notice(paths: &[&str]) -> MonitorAction {
        MonitorAction::ScanRequired(paths.iter().map(PathBuf::from).collect())
    }

    #[tokio::test]
    async fn scan_gate_delays_native_path_work_without_blocking_loss_state() {
        let core = EmulebbCore::new_in_memory(
            "watch-scan-order",
            emulebb_index::FileIndex::in_memory().unwrap(),
        )
        .unwrap();
        let path = std::env::temp_dir().join("watch-scan-order");
        let root = core
            .metadata_store
            .create_library_root(&path, true, true)
            .unwrap()
            .unwrap();
        let roots = watched_root_identities(&core).await.unwrap();
        let scan = core.shared_reload_gate.lock().await;
        let mut change = Box::pin(apply_monitor_action(
            &core,
            &roots,
            MonitorAction::Share(path.join("sample.bin")),
        ));
        let observed =
            std::future::poll_fn(|context| Poll::Ready(change.as_mut().poll(context))).await;
        assert!(matches!(observed, Poll::Pending));
        apply_monitor_action(&core, &roots, MonitorAction::ScanRequired(vec![path])).await;
        assert!(
            core.library_root(root.id)
                .await
                .unwrap()
                .value()
                .as_ref()
                .unwrap()
                .scan_required
        );
        drop(change);
        drop(scan);
        core.drain_persistence().await.unwrap();
    }

    #[tokio::test]
    async fn loss_scope_uses_subscription_ids_and_never_schedules_a_scan() {
        let core = EmulebbCore::new_in_memory(
            "watch-loss",
            emulebb_index::FileIndex::in_memory().unwrap(),
        )
        .unwrap();
        let base = std::env::temp_dir().join("watch-loss-scope");
        let first_path = base.join("one");
        let second_path = base.join("two");
        let first = core
            .metadata_store
            .create_library_root(&first_path, true, true)
            .unwrap()
            .unwrap();
        let second = core
            .metadata_store
            .create_library_root(&second_path, true, true)
            .unwrap()
            .unwrap();
        let roots = watched_root_identities(&core).await.unwrap();
        mark_watcher_loss(&core, &roots, &[first_path.join("sample.bin")])
            .await
            .unwrap();
        assert!(
            core.library_root(first.id)
                .await
                .unwrap()
                .value()
                .as_ref()
                .unwrap()
                .scan_required
        );
        assert!(
            !core
                .library_root(second.id)
                .await
                .unwrap()
                .value()
                .as_ref()
                .unwrap()
                .scan_required
        );
        assert!(!core.shared_reload_running.load(Ordering::Acquire));
        assert!(!core.shared_reload_pending.load(Ordering::Acquire));
        core.metadata_store.delete_library_root(first.id).unwrap();
        let replacement = core
            .metadata_store
            .create_library_root(&first_path, true, true)
            .unwrap()
            .unwrap();
        mark_watcher_loss(&core, &roots, &[first_path])
            .await
            .unwrap();
        assert!(
            !core
                .library_root(replacement.id)
                .await
                .unwrap()
                .value()
                .as_ref()
                .unwrap()
                .scan_required
        );
        // The final notice is drain-owned after ordinary API writes close.
        core.stop_persistence_admission().unwrap();
        mark_watcher_loss(&core, &roots, &[]).await.unwrap();
        assert!(
            core.metadata_store
                .library_root(second.id)
                .unwrap()
                .unwrap()
                .scan_required
        );
        core.drain_persistence().await.unwrap();
    }

    #[tokio::test]
    async fn stopping_cancels_path_work_but_drains_loss_and_observation_gap() {
        let (ingress, rx, required) = monitor_action_channel(4);
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let started = Arc::new(tokio::sync::Notify::new());
        let applied = Arc::new(Mutex::new(Vec::new()));
        ingress.try_send_actions([share("/root/busy.bin"), loss_notice(&["/root/changed.bin"])]);
        let signal = Arc::clone(&started);
        let sink = Arc::clone(&applied);
        let consumer = tokio::spawn(run_consumer(rx, required, stop_rx, move |action| {
            let signal = Arc::clone(&signal);
            let sink = Arc::clone(&sink);
            async move {
                if matches!(action, MonitorAction::Share(_)) {
                    signal.notify_one();
                    std::future::pending::<()>().await;
                }
                sink.lock().unwrap().push(action);
            }
        }));
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .unwrap();
        stop.send_replace(true);
        drop(ingress);
        tokio::time::timeout(Duration::from_secs(1), consumer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            *applied.lock().unwrap(),
            vec![loss_notice(&["/root/changed.bin"]), loss_notice(&[])]
        );
    }

    #[tokio::test]
    async fn loss_without_path_work_wakes_an_empty_consumer() {
        let (ingress, rx, required) = monitor_action_channel(4);
        ingress.require_scan();
        let (_stop, stop_rx) = tokio::sync::watch::channel(false);
        drop(ingress);
        let applied = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&applied);
        run_consumer(rx, required, stop_rx, move |action| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().unwrap().push(action);
            }
        })
        .await;
        assert_eq!(*applied.lock().unwrap(), vec![loss_notice(&[])]);
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
    fn subtree_and_unknown_events_report_incomplete_scope() {
        for kind in [
            EventKind::Create(CreateKind::Folder),
            EventKind::Remove(RemoveKind::Folder),
            EventKind::Any,
            EventKind::Other,
        ] {
            let event = debounced(kind, vec!["/share/subtree"]);
            assert_eq!(
                classify_event(&event),
                vec![loss_notice(&["/share/subtree"])]
            );
        }
    }

    #[test]
    fn untyped_removal_keeps_file_work_and_reports_possible_subtree_loss() {
        for kind in [RemoveKind::Any, RemoveKind::Other] {
            let event = debounced(EventKind::Remove(kind), vec!["/share/subtree"]);
            assert_eq!(
                classify_event(&event),
                vec![remove("/share/subtree"), loss_notice(&["/share/subtree"])]
            );
        }
    }

    #[tokio::test]
    async fn subtree_notifications_recover_only_by_explicit_scan_and_preserve_content_hashes() {
        let root = std::env::temp_dir().join(format!("watch-subtree-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let core = EmulebbCore::new_in_memory(
            "watch-subtree",
            emulebb_index::FileIndex::in_memory().unwrap(),
        )
        .unwrap();
        configure_test_shared_root(&core, &root).await;
        let id = core.metadata_store.library_root_page(0, 100).unwrap().items[0].id;
        core.patch_library_root_watch(id, true)
            .await
            .unwrap()
            .unwrap();
        let bindings = watched_root_identities(&core).await.unwrap();
        let branch = root.join("branch");
        std::fs::create_dir_all(&branch).unwrap();
        std::fs::write(branch.join("sample.bin"), b"subtree payload").unwrap();

        // An untyped create is identified by the existing stat, without a
        // recursive event expansion or an automatic inventory walk.
        apply_monitor_action(&core, &bindings, MonitorAction::Share(branch.clone())).await;
        assert!(
            core.library_root(id)
                .await
                .unwrap()
                .value()
                .as_ref()
                .unwrap()
                .scan_required
        );
        assert!(!core.shared_reload_running.load(Ordering::Acquire));
        assert!(!core.shared_reload_pending.load(Ordering::Acquire));
        assert!(core.shares().await.is_empty());
        core.reload_shared_directories().await.unwrap();
        assert!(
            !core
                .library_root(id)
                .await
                .unwrap()
                .value()
                .as_ref()
                .unwrap()
                .scan_required
        );
        let hash = core.shares().await[0].hash.clone();

        let moved = root.join("moved");
        std::fs::rename(&branch, &moved).unwrap();
        apply_monitor_action(
            &core,
            &bindings,
            MonitorAction::Rename {
                from: branch,
                to: moved.clone(),
            },
        )
        .await;
        assert!(
            core.library_root(id)
                .await
                .unwrap()
                .value()
                .as_ref()
                .unwrap()
                .scan_required
        );
        assert!(!core.shared_reload_running.load(Ordering::Acquire));
        core.reload_shared_directories().await.unwrap();
        let shares = core.shares().await;
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].hash, hash);
        assert_eq!(
            shares[0].path,
            moved.join("sample.bin").display().to_string()
        );
        assert_eq!(core.metadata_store.table_count("known_files").unwrap(), 1);
        assert!(
            !core
                .library_root(id)
                .await
                .unwrap()
                .value()
                .as_ref()
                .unwrap()
                .scan_required
        );

        std::fs::remove_dir_all(&moved).unwrap();
        let notice = debounced(
            EventKind::Remove(RemoveKind::Folder),
            vec![moved.to_str().unwrap()],
        );
        for action in classify_event(&notice) {
            apply_monitor_action(&core, &bindings, action).await;
        }
        assert!(
            core.library_root(id)
                .await
                .unwrap()
                .value()
                .as_ref()
                .unwrap()
                .scan_required
        );
        assert!(!core.shared_reload_running.load(Ordering::Acquire));
        core.reload_shared_directories().await.unwrap();
        assert!(core.shares().await.is_empty());
        assert!(
            !core
                .library_root(id)
                .await
                .unwrap()
                .value()
                .as_ref()
                .unwrap()
                .scan_required
        );
        core.drain_persistence().await.unwrap();
        drop(core);
        std::fs::remove_dir_all(root).unwrap();
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
    fn unpaired_rename_flags_its_affected_path() {
        let to = debounced(name(RenameMode::To), vec!["/share/new.dat"]);
        assert_eq!(classify_event(&to), vec![loss_notice(&["/share/new.dat"])]);
        let from = debounced(name(RenameMode::From), vec!["/share/old.dat"]);
        assert_eq!(
            classify_event(&from),
            vec![loss_notice(&["/share/old.dat"])]
        );
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
    fn backend_rescan_notice_reports_loss() {
        let event = Event::new(EventKind::Other).set_flag(Flag::Rescan);
        let event = DebouncedEvent {
            event,
            time: Instant::now(),
        };
        assert_eq!(classify_event(&event), vec![loss_notice(&[])]);
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
        let expected = vec![
            share("/s/a.dat"),
            remove("/s/b.dat"),
            loss_notice(&["/s/a.dat", "/s/b.dat"]),
        ];
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
    fn windows_rename_burst_reports_possible_loss() {
        let events = (0..WINDOWS_EVENT_BURST_LOSS_THRESHOLD)
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
            WINDOWS_EVENT_BURST_LOSS_THRESHOLD,
        );
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, MonitorAction::ScanRequired(_)))
                .count(),
            1,
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_create_burst_reports_possible_loss() {
        let events = (0..WINDOWS_EVENT_BURST_LOSS_THRESHOLD)
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
            WINDOWS_EVENT_BURST_LOSS_THRESHOLD,
        );
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, MonitorAction::ScanRequired(_)))
                .count(),
            1,
        );
    }

    #[test]
    fn coalesce_actions_keeps_known_changes_beside_one_loss_notice() {
        assert_eq!(
            coalesce_actions(vec![
                loss_notice(&[]),
                share("/s/a.dat"),
                loss_notice(&[]),
                remove("/s/b.dat"),
            ]),
            vec![share("/s/a.dat"), loss_notice(&[]), remove("/s/b.dat")],
        );
    }

    /// Drive `run_consumer` over `inputs` and return the actions it actually
    /// applied -- the consumer's in-order forwarding seam (the OS watcher
    /// cannot be tested deterministically).
    async fn applied_actions(inputs: Vec<MonitorAction>) -> Vec<MonitorAction> {
        let applied: Arc<Mutex<Vec<MonitorAction>>> = Arc::new(Mutex::new(Vec::new()));
        let (ingress, rx, scan_required) = monitor_action_channel(inputs.len().max(1));
        ingress.try_send_actions(inputs);
        drop(ingress);
        let sink = Arc::clone(&applied);
        let (_stop, stop_rx) = tokio::sync::watch::channel(false);
        let consumer = tokio::spawn(run_consumer(rx, scan_required, stop_rx, move |action| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().unwrap().push(action);
            }
        }));
        consumer.await.unwrap();
        Arc::try_unwrap(applied).unwrap().into_inner().unwrap()
    }

    #[test]
    fn bounded_ingress_caps_large_burst_and_latches_one_loss() {
        const TEST_CAPACITY: usize = 4;
        let (ingress, mut rx, scan_required) = monitor_action_channel(TEST_CAPACITY);
        let burst = (0..10_000)
            .map(|index| share(&format!("/s/{index}.dat")))
            .collect::<Vec<_>>();

        ingress.try_send_actions(burst);

        assert!(scan_required.load(Ordering::Acquire));
        assert_eq!(
            std::iter::from_fn(|| rx.try_recv().ok()).count(),
            TEST_CAPACITY,
        );
        ingress.try_send_actions([share("/s/after-overflow.dat")]);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn overflow_flags_each_episode_then_preserves_later_final_intent() {
        let applied: Arc<Mutex<Vec<MonitorAction>>> = Arc::new(Mutex::new(Vec::new()));
        let loss_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let loss_started = Arc::new(tokio::sync::Notify::new());
        let release_loss = Arc::new(tokio::sync::Notify::new());
        let (ingress, rx, scan_required) = monitor_action_channel(2);

        ingress.try_send_actions([
            share("/s/pre-overflow-a.dat"),
            remove("/s/pre-overflow-b.dat"),
            share("/s/triggers-overflow.dat"),
        ]);

        let sink = Arc::clone(&applied);
        let count = Arc::clone(&loss_count);
        let started = Arc::clone(&loss_started);
        let release = Arc::clone(&release_loss);
        let (_stop, stop_rx) = tokio::sync::watch::channel(false);
        let consumer = tokio::spawn(run_consumer(rx, scan_required, stop_rx, move |action| {
            let sink = Arc::clone(&sink);
            let count = Arc::clone(&count);
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            async move {
                sink.lock().unwrap().push(action.clone());
                if matches!(action, MonitorAction::ScanRequired(_)) {
                    count.fetch_add(1, Ordering::AcqRel);
                    started.notify_one();
                    release.notified().await;
                }
            }
        }));

        tokio::time::timeout(Duration::from_secs(1), loss_started.notified())
            .await
            .expect("overflow loss recording did not start");
        ingress.try_send_actions([
            share("/s/during-reconcile-a.dat"),
            remove("/s/during-reconcile-b.dat"),
            share("/s/triggers-follow-up-overflow.dat"),
        ]);
        release_loss.notify_one();

        tokio::time::timeout(Duration::from_secs(1), loss_started.notified())
            .await
            .expect("follow-up overflow loss recording did not start");
        assert_eq!(loss_count.load(Ordering::Acquire), 2);
        ingress.try_send_actions([remove("/s/final.dat"), share("/s/final.dat")]);
        drop(ingress);
        release_loss.notify_one();
        consumer.await.unwrap();

        assert_eq!(
            Arc::try_unwrap(applied).unwrap().into_inner().unwrap(),
            vec![loss_notice(&[]), loss_notice(&[]), share("/s/final.dat")],
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
        configure_test_shared_root(&core, &root).await;

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
    async fn unavailable_root_withdraws_and_rejoins_after_reload() {
        let parent = std::env::temp_dir().join(format!(
            "emulebb-monitor-root-health-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4(),
        ));
        let root = parent.join("library");
        let offline = parent.join("offline");
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("Library.bin");
        std::fs::write(&source, b"verified local payload").unwrap();
        let core =
            EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap())
                .unwrap();
        configure_test_shared_root(&core, &root).await;
        auto_share_monitored_path(&core, &source).await;
        let hash = core.shares().await[0].hash.clone();
        let mut availability = root_availability_snapshot(&core).await.unwrap();
        let mut pending_rejoin = HashMap::new();

        std::fs::rename(&root, &offline).unwrap();
        reconcile_root_availability(&core, &mut availability, &mut pending_rejoin, true)
            .await
            .unwrap();
        assert!(core.shares().await.is_empty());
        assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 0);
        assert!(
            core.metadata_store
                .active_local_file_by_hash(&hash)
                .unwrap()
                .is_none()
        );
        // An in-flight scan may commit an old root snapshot after withdrawal.
        core.metadata_store
            .set_shared_root_accessible(&root, true)
            .unwrap();
        reconcile_root_availability(&core, &mut availability, &mut pending_rejoin, true)
            .await
            .unwrap();
        assert!(
            core.metadata_store
                .active_local_file_by_hash(&hash)
                .unwrap()
                .is_none()
        );

        std::fs::rename(&offline, &root).unwrap();
        reconcile_root_availability(&core, &mut availability, &mut pending_rejoin, true)
            .await
            .unwrap();
        assert!(pending_rejoin.contains_key(&root));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if core.share(&hash).await.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("reappeared root should rejoin after reload");
        tokio::time::timeout(Duration::from_secs(5), async {
            while core.shared_reload_running.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("rejoin reload should finish");
        reconcile_root_availability(&core, &mut availability, &mut pending_rejoin, true)
            .await
            .unwrap();
        assert!(pending_rejoin.is_empty());
        std::fs::remove_dir_all(&parent).ok();
    }

    #[tokio::test]
    async fn monitored_file_is_not_shared_when_pattern_ignored() {
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
            .add_shared_file_ignore_pattern("Excluded.*.bin")
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
        configure_test_shared_root(&core, &root).await;
        auto_share_monitored_path(&core, &source).await;
        let old_hash = core.shares().await[0].hash.clone();
        assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 1);

        std::fs::write(&source, b"after payload with a different size").unwrap();
        auto_share_monitored_path(&core, &source).await;
        let new_hash = core.shares().await[0].hash.clone();
        assert_ne!(old_hash, new_hash);
        assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 1);
        assert!(core.share(&old_hash).await.is_none());
        assert_eq!(core.metadata_store.table_count("known_files").unwrap(), 2);

        // A duplicate settled event for the same native fingerprint must not
        // ingest or create another catalog row.
        auto_share_monitored_path(&core, &source).await;
        assert_eq!(core.ed2k_transfers.shared_catalog_count().await, 1);
        assert_eq!(core.metadata_store.table_count("known_files").unwrap(), 2);

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
        configure_test_shared_root(&core, &root).await;
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
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if core.ed2k_transfers.shared_catalog_count().await == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("targeted re-hash must update the live catalog");
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
        configure_test_shared_root(&core, &root).await;
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
            while core.share(&old_hash).await.is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("missing shared source should be withdrawn");
        assert!(
            core.download_page(Default::default())
                .await
                .unwrap()
                .downloads
                .is_empty()
        );
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
        configure_test_shared_root(&core, &root).await;
        auto_share_monitored_path(&core, &source).await;
        let hash = core.shares().await[0].hash.clone();
        std::fs::rename(&source, &destination).unwrap();

        assert!(!auto_relocate_monitored_path(&core, &source, &destination).await);

        assert!(
            core.metadata_store
                .local_file_instance(&monitor_shared_key(&destination))
                .unwrap()
                .is_some()
        );
        assert!(
            core.metadata_store
                .local_file_has_root_membership(&monitor_shared_key(&destination))
                .unwrap()
        );
        assert_eq!(
            core.metadata_store.active_shared_content_count().unwrap(),
            1
        );
        let shares = core.shares().await;
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].hash, hash);
        assert_eq!(shares[0].name, "After.bin");
        assert_eq!(shares[0].path, destination.display().to_string(),);
        assert_eq!(core.metadata_store.table_count("known_files").unwrap(), 1);
        assert_eq!(
            core.metadata_store
                .table_count("local_file_instances")
                .unwrap(),
            2
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
