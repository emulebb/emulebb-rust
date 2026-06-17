//! Live shared-directory monitoring (auto-pickup) for the configured shared
//! roots -- the runtime that makes [`SharedDirectoryRoot::monitor_owned`] real
//! (eMule's `CSharedFileList` directory auto-monitor parity).
//!
//! # Design
//!
//! The OS file-system watcher (`notify`) is inherently blocking/callback driven
//! and runs on its **own thread**; the rest of the core is async (tokio). We
//! bridge the two with the established pattern:
//!
//! ```text
//!   notify watcher thread --(debounced batches)--> mpsc channel --> tokio consumer task
//! ```
//!
//! * **Debouncing.** A single logical change (a file copied in, an editor's
//!   save-and-rename, a directory delete) produces a *burst* of raw FS events.
//!   We run the events through `notify-debouncer-full`, which collapses a burst
//!   into settled events. The settle window also means we never act on a file
//!   that is still being written: we only hash it once its events have settled.
//! * **Recursive per root.** Each configured root is watched with the
//!   [`RecursiveMode`] that matches `root.recursive` (recursive vs. the
//!   immediate directory only), exactly like the manual scan's depth handling.
//! * **Thread -> channel -> tokio bridge.** The debouncer's event handler is a
//!   small closure that classifies the settled events into [`MonitorAction`]s
//!   (the pure decision -- share vs. remove) and forwards them over a
//!   `tokio::sync::mpsc` channel. The async consumer applies each action via the
//!   existing share / un-share core paths so MD4/AICH/catalog stay consistent.
//! * **Graceful degradation.** Watching one root can fail (a vanished path; on
//!   Linux a large recursive tree can exhaust the inotify watch limit). We log
//!   and continue with the other roots rather than crashing the daemon: that
//!   root simply degrades to scan-on-demand (the manual
//!   `reload_shared_directories` fallback still covers it).
//!
//! The OS watcher itself is impossible to unit-test deterministically, so the
//! testable seam is [`classify_event`] / [`actions_for_events`]: given a settled
//! debounced event, decide whether it means *share this path* or *drop this
//! path*. The tests exercise that decision plus the consumer's path-keyed
//! idempotency / removal bookkeeping.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use notify_debouncer_full::notify::event::{ModifyKind, RenameMode};
use notify_debouncer_full::notify::{EventKind, RecursiveMode, Watcher};
use notify_debouncer_full::{
    DebounceEventResult, DebouncedEvent, Debouncer, FileIdMap, new_debouncer,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::shared_directories::SharedDirectoryRoot;

/// Settle window before a burst of raw FS events for one logical change is
/// emitted as a settled event. Long enough that a file copied in is fully
/// written before we hash it, short enough that auto-pickup still feels live.
/// (eMule re-scans shared dirs on a coarse timer; a 2s settle is well within
/// that responsiveness while avoiding mid-write hashing.)
const SETTLE_WINDOW: Duration = Duration::from_secs(2);

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
}

/// Classify a single settled debounced event into zero or more actions.
///
/// `notify`'s settled event kinds map cleanly onto our two intents:
/// * `Create` / `Modify(Data|Any|Metadata)` / a rename *to* a path -> the path
///   now holds content we should share.
/// * `Remove` / a rename *from* a path -> the path no longer holds the content
///   it had, so drop it.
/// * A `Both`-mode rename carries `[from, to]`: drop the old path, share the
///   new one.
///
/// We intentionally do not try to stat the path here (it may already be gone for
/// a remove, or still settling); the consumer decides share-vs-skip when it
/// actually touches the filesystem.
pub(crate) fn classify_event(event: &DebouncedEvent) -> Vec<MonitorAction> {
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
            // A both-leg rename carries [from, to]: drop the source, share the dest.
            RenameMode::Both => {
                let mut actions = Vec::new();
                if let Some(from) = event.paths.first() {
                    actions.push(MonitorAction::Remove(from.clone()));
                }
                if let Some(to) = event.paths.get(1) {
                    actions.push(MonitorAction::Share(to.clone()));
                }
                actions
            }
            // A rename *to* a watched path makes it appear (auto-pickup).
            RenameMode::To => map_paths(MonitorAction::Share),
            // A rename *from* a watched path makes it disappear.
            RenameMode::From => map_paths(MonitorAction::Remove),
            // Ambiguous rename: be conservative and treat each path as a share
            // candidate (the consumer skips paths that are already gone).
            RenameMode::Any | RenameMode::Other => map_paths(MonitorAction::Share),
        },
        EventKind::Remove(_) => map_paths(MonitorAction::Remove),
        // Access / Other / Any: no shared-catalog consequence.
        EventKind::Access(_) | EventKind::Other | EventKind::Any => Vec::new(),
    }
}

/// Flatten a settled batch of debounced events into the ordered action list.
pub(crate) fn actions_for_events(events: &[DebouncedEvent]) -> Vec<MonitorAction> {
    events.iter().flat_map(classify_event).collect()
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
    #[allow(dead_code)]
    debouncer: Debouncer<notify_debouncer_full::notify::RecommendedWatcher, FileIdMap>,
    consumer: tokio::task::JoinHandle<()>,
    /// The roots actually being watched (used to report which roots became
    /// `monitor_owned`).
    watched_roots: Vec<String>,
}

impl SharedDirMonitor {
    /// Paths of the roots that are actually being watched, so the caller can mark
    /// exactly those `monitor_owned = true`.
    pub(crate) fn watched_roots(&self) -> &[String] {
        &self.watched_roots
    }

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
    // handler runs on the watcher thread; it must not block, so it only
    // classifies + forwards over an unbounded tokio channel (a non-blocking send
    // that is safe to call from a non-async thread).
    let (action_tx, action_rx): (
        UnboundedSender<MonitorAction>,
        UnboundedReceiver<MonitorAction>,
    ) = tokio::sync::mpsc::unbounded_channel();

    let handler = move |result: DebounceEventResult| match result {
        Ok(events) => {
            for action in actions_for_events(&events) {
                // Receiver gone == monitor stopped; drop silently.
                let _ = action_tx.send(action);
            }
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

    let mut watched_roots = Vec::new();
    for root in roots {
        if !root.accessible {
            continue;
        }
        let mode = if root.recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        let path = Path::new(&root.path);
        match debouncer.watcher().watch(path, mode) {
            Ok(()) => {
                // Keep the file-id cache in sync so rename stitching works.
                debouncer.cache().add_root(path, mode);
                watched_roots.push(root.path.clone());
                tracing::info!(
                    root = %root.path,
                    recursive = root.recursive,
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

    if watched_roots.is_empty() {
        // No root could be watched -- nothing to consume; drop the debouncer.
        drop(debouncer);
        return None;
    }

    let consumer = tokio::spawn(run_consumer(action_rx, apply));
    Some(SharedDirMonitor {
        debouncer,
        consumer,
        watched_roots,
    })
}

/// Consume settled actions and apply them, with path-keyed idempotency.
///
/// The consumer keeps a small set of paths it has already shared so a repeated
/// `Share` for an unchanged path is dropped before it even reaches the (cheap,
/// hash-keyed) ingest path, and a `Remove` for a path it never shared is a
/// no-op. A `Share` after a `Remove` (remove-then-readd) correctly re-shares.
async fn run_consumer<F, Fut>(mut action_rx: UnboundedReceiver<MonitorAction>, apply: F)
where
    F: Fn(MonitorAction) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    // path -> last action applied, used purely to coalesce duplicate shares and
    // skip removes of never-shared paths. Authoritative dedup still lives in the
    // hash-keyed share path; this is a cheap front-line filter.
    let mut shared_paths: HashMap<PathBuf, ()> = HashMap::new();
    while let Some(action) = action_rx.recv().await {
        match &action {
            MonitorAction::Share(path) => {
                // A modify on a file we already shared still goes through (the
                // content may have changed and re-ingest is hash-cheap if not),
                // but we always record it as shared.
                shared_paths.insert(path.clone(), ());
                apply(action).await;
            }
            MonitorAction::Remove(path) => {
                // Only act if we believe we shared it; otherwise the un-share is
                // a guaranteed no-op and we can skip the lookup.
                let was_shared = shared_paths.remove(path).is_some();
                if was_shared {
                    apply(action).await;
                }
            }
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

use crate::shared_directories::refresh_shared_directory_row;
use crate::{EmulebbCore, LocalShareCreate};

/// (Re)start the live shared-directory auto-pickup monitor for the configured
/// roots. Tears down any previous monitor first, then watches each accessible
/// root (recursive per `root.recursive`). On a settled create/modify the file is
/// auto-shared via [`EmulebbCore::share_local_file`]; on a settled
/// remove/rename-away it is dropped from the shared catalog. The roots actually
/// watched are marked `monitor_owned = true`. Tolerant of a per-root watch
/// failure (logged; that root degrades to scan-on-demand).
pub(crate) async fn start_shared_directory_monitor(core: &EmulebbCore) {
    // Drop any existing monitor before rebuilding the watch set.
    stop_shared_directory_monitor(core);

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
            }
        }
    });

    let watched_roots = monitor
        .as_ref()
        .map(|monitor| monitor.watched_roots().to_vec())
        .unwrap_or_default();

    // Mark exactly the roots we are actually watching as monitor_owned, so the
    // metadata-only flag finally reflects a real running watch.
    if !watched_roots.is_empty() {
        let mut state = core.state.lock().await;
        for root in state.shared_directories.iter_mut() {
            root.monitor_owned = watched_roots.iter().any(|watched| watched == &root.path);
        }
    }

    *core.shared_dir_monitor.lock().unwrap() = monitor;
}

/// Stop the live shared-directory monitor (if running). Idempotent.
pub(crate) fn stop_shared_directory_monitor(core: &EmulebbCore) {
    if let Some(monitor) = core.shared_dir_monitor.lock().unwrap().take() {
        monitor.stop();
    }
}

/// Auto-share a file picked up by the live monitor. Goes through the same ingest
/// path as a manual share (MD4/AICH/catalog consistent), then records the
/// source-path -> hash mapping so a later remove can resolve it. Re-sharing an
/// already-shared identical file is cheap/idempotent. A vanished/unreadable file
/// (settled then disappeared) is logged and skipped, not propagated.
async fn auto_share_monitored_path(core: &EmulebbCore, path: &Path) {
    // Only auto-share regular files; a directory event under a recursive root
    // would otherwise hit the ingest path with a directory.
    if !path.is_file() {
        return;
    }
    match core
        .share_local_file(LocalShareCreate {
            path: path.display().to_string(),
            name: None,
        })
        .await
    {
        Ok(share) => {
            core.state
                .lock()
                .await
                .monitor_shared_hashes
                .insert(path.to_path_buf(), share.hash.clone());
            tracing::info!(path = %path.display(), hash = %share.hash, "auto-shared monitored file");
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
/// source-path -> hash map recorded at auto-share time and drop it via the
/// existing un-share catalog path. A path we never auto-shared is a no-op.
async fn auto_unshare_monitored_path(core: &EmulebbCore, path: &Path) {
    let hash = {
        let mut state = core.state.lock().await;
        state.monitor_shared_hashes.remove(path)
    };
    let Some(hash) = hash else {
        return;
    };
    match core.unshare_file(&hash).await {
        Ok(Some(_)) => {
            tracing::info!(path = %path.display(), %hash, "auto-removed monitored file from shared catalog");
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
    use notify_debouncer_full::notify::event::{CreateKind, RemoveKind};
    use std::sync::Arc;
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
    fn rename_to_classifies_as_share_rename_from_as_remove() {
        let to = debounced(name(RenameMode::To), vec!["/share/new.dat"]);
        assert_eq!(classify_event(&to), vec![share("/share/new.dat")]);
        let from = debounced(name(RenameMode::From), vec!["/share/old.dat"]);
        assert_eq!(classify_event(&from), vec![remove("/share/old.dat")]);
    }

    #[test]
    fn both_rename_drops_source_and_shares_destination() {
        let event = debounced(
            name(RenameMode::Both),
            vec!["/share/old.dat", "/share/new.dat"],
        );
        assert_eq!(
            classify_event(&event),
            vec![remove("/share/old.dat"), share("/share/new.dat")]
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
    fn actions_for_events_flattens_a_batch_in_order() {
        let events = vec![
            debounced(EventKind::Create(CreateKind::File), vec!["/s/a.dat"]),
            debounced(EventKind::Remove(RemoveKind::File), vec!["/s/b.dat"]),
        ];
        assert_eq!(
            actions_for_events(&events),
            vec![share("/s/a.dat"), remove("/s/b.dat")]
        );
    }

    /// Drive `run_consumer` over `inputs` and return the actions it actually
    /// applied -- the consumer's idempotency / bookkeeping seam (the OS watcher
    /// cannot be tested deterministically).
    async fn applied_actions(inputs: Vec<MonitorAction>) -> Vec<MonitorAction> {
        let applied: Arc<Mutex<Vec<MonitorAction>>> = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let sink = Arc::clone(&applied);
        let consumer = tokio::spawn(run_consumer(rx, move |action| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().unwrap().push(action);
            }
        }));
        for action in inputs {
            tx.send(action).unwrap();
        }
        drop(tx);
        consumer.await.unwrap();
        Arc::try_unwrap(applied).unwrap().into_inner().unwrap()
    }

    /// Share a created path once, skip a remove of a never-shared path, apply a
    /// remove only for a path that was shared.
    #[tokio::test]
    async fn consumer_shares_then_removes_and_skips_unknown_removes() {
        let applied = applied_actions(vec![
            share("/s/a.dat"),
            remove("/s/a.dat"),
            remove("/s/b.dat"),
        ])
        .await;
        assert_eq!(applied, vec![share("/s/a.dat"), remove("/s/a.dat")]);
    }

    /// Remove-then-readd: a Share after a Remove must re-share (the bookkeeping
    /// is cleared by the Remove).
    #[tokio::test]
    async fn consumer_reshares_after_remove() {
        let applied = applied_actions(vec![
            share("/s/a.dat"),
            remove("/s/a.dat"),
            share("/s/a.dat"),
        ])
        .await;
        assert_eq!(
            applied,
            vec![share("/s/a.dat"), remove("/s/a.dat"), share("/s/a.dat")]
        );
    }
}
