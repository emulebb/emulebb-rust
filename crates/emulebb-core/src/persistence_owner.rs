//! Bounded ordered persistence for durable mutations.

use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex, mpsc},
    time::Instant,
};
use tokio::sync::{Mutex, mpsc as async_mpsc, oneshot};

use crate::{Friend, core_state::CoreState, kad_persistence, profile_state};
use emulebb_kad_dht::{DhtNode, RoutingProjection, RoutingSnapshotContact};
use emulebb_metadata::{
    KAD_ROUTING_MAX_CONTACTS, KadNodeId, KadRoutingContact, KadRoutingSnapshot, MetadataStore,
};

pub(crate) mod category;
mod download;
mod download_patch;
mod kad;

#[cfg(test)]
mod download_tests;
#[cfg(test)]
#[path = "persistence_owner/kad_tests.rs"]
mod kad_tests;
#[cfg(test)]
mod tests;

const MAX_SLOTS: usize = 64;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const KAD_INGRESS_PREPARATION_BYTES: usize = 2 * crate::NODES_DAT_MAX_BYTES;
// Charge four copies of variable backing storage for request, worker/SQL
// conversion, cache publication and response, plus fixed command overhead.
// Allocator bookkeeping and thread stacks are outside this payload budget.
const FIXED_CHARGE: usize = 1024;
// Reserve for the next power-of-two allocation as well as an exact-capacity
// allocation; capacity is checked before filling a returned buffer.
const KAD_RESERVED_CAPACITY: usize = 16_384;

#[derive(Debug, Clone)]
pub enum PersistenceError {
    Busy,
    TooLarge,
    Closing,
    Storage(String),
    Worker,
    CommittedAfterWorkerFailure,
    CommittedPublicationFailed,
    CommitUnknown,
}

impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => f.write_str("persistence capacity is exhausted"),
            Self::TooLarge => f.write_str("persistence request exceeds the payload limit"),
            Self::Closing => f.write_str("persistence is shutting down"),
            Self::Storage(error) => write!(f, "persistence failed: {error}"),
            Self::Worker => f.write_str("persistence worker failed"),
            Self::CommittedAfterWorkerFailure => {
                f.write_str("persistence committed despite a worker failure")
            }
            Self::CommittedPublicationFailed => {
                f.write_str("persistence committed but derived publication did not complete")
            }
            Self::CommitUnknown => {
                f.write_str("persistence outcome is unknown after a worker failure")
            }
        }
    }
}
impl std::error::Error for PersistenceError {}

#[derive(Debug, Clone, Copy)]
pub struct CategoryNameConflict;
impl std::fmt::Display for CategoryNameConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("category name already exists")
    }
}
impl std::error::Error for CategoryNameConflict {}

enum Command {
    Add { hash: String, name: String },
    Delete { hash: String },
    Category(category::CategoryCommand),
    Downloads(download::DownloadCommand),
    KadLoad,
    KadIdentity,
    KadAttach(DhtNode),
    KadCheckpoint { dht: DhtNode, final_snapshot: bool },
    KadImport { input: KadInput, pending_only: bool },
}

enum Response {
    Friend(Option<Friend>),
    Category(Result<Option<crate::Category>, CategoryNameConflict>),
    Downloads(crate::DownloadControlBatch),
    DownloadPatched(Result<crate::DownloadChange, emulebb_metadata::DownloadPatchError>),
    Roots(bool),
    KadLoaded(LeasedKadSnapshot),
    KadIdentity(KadNodeId),
    KadAttached(KadAttachGuard),
    KadCheckpointed,
    KadImported(Result<usize, String>),
}

/// Keeps a returned snapshot charged independently of a request slot.
pub(crate) struct LeasedKadSnapshot {
    snapshot: KadRoutingSnapshot,
    _lease: ByteLease,
}

impl LeasedKadSnapshot {
    pub(crate) fn snapshot(&self) -> &KadRoutingSnapshot {
        &self.snapshot
    }
}

struct Request {
    command: Command,
    permit: Permit,
    response: oneshot::Sender<Result<Response, PersistenceError>>,
    enqueued: Instant,
    handoff: Option<oneshot::Receiver<()>>,
    released: oneshot::Sender<()>,
}

struct ActiveCategory {
    request: Request,
    result: Result<Response, PersistenceError>,
    completion: Pin<Box<dyn Future<Output = Result<(), PersistenceError>> + Send>>,
}

/// Dropping an uncommitted startup handoff retires its unpublished DHT.
pub(crate) struct KadAttachGuard(Option<oneshot::Sender<()>>);

impl KadAttachGuard {
    pub(crate) fn commit(mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

struct Admission {
    sender: Option<async_mpsc::Sender<Request>>,
    stopping: bool,
    cancel_ingress: tokio_util::sync::CancellationToken,
    quota: Arc<StdMutex<Quota>>,
}

struct Quota {
    faulted: bool,
    slots: usize,
    bytes: usize,
    available: Arc<tokio::sync::Notify>,
}

struct Permit {
    quota: Arc<StdMutex<Quota>>,
    bytes: usize,
}

pub(crate) struct ByteLease {
    quota: Arc<StdMutex<Quota>>,
    bytes: usize,
}

struct KadInput {
    bytes: Vec<u8>,
    _ingress: ByteLease,
}

/// A bounded discovery response reservation, released on cancellation.
pub(crate) struct KadImportReservation {
    lease: ByteLease,
    cancellation: tokio_util::sync::CancellationToken,
}

impl KadImportReservation {
    /// Resolve when shutdown cancels pre-enqueue discovery preparation.
    pub(crate) async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    /// The transport frame is gone once body collection returns.
    pub(crate) fn finish_preparation(&mut self) -> Result<(), PersistenceError> {
        let extra = self
            .lease
            .bytes
            .checked_sub(crate::NODES_DAT_MAX_BYTES)
            .ok_or(PersistenceError::Worker)?;
        let mut quota = self
            .lease
            .quota
            .lock()
            .map_err(|_| PersistenceError::Worker)?;
        quota.bytes -= extra;
        self.lease.bytes -= extra;
        quota.available.notify_waiters();
        Ok(())
    }
}

struct KadRuntime {
    dht: Option<DhtNode>,
    instance: emulebb_kad_dht::DhtInstance,
    revision: i64,
    finished: bool,
    baseline: Option<(RoutingProjection, ByteLease)>,
}

impl Drop for ByteLease {
    fn drop(&mut self) {
        if let Ok(mut quota) = self.quota.lock() {
            quota.bytes -= self.bytes;
            quota.available.notify_waiters();
        }
    }
}

impl Permit {
    fn transfer_bytes(&mut self, bytes: usize) -> Result<ByteLease, PersistenceError> {
        if bytes > self.bytes {
            return Err(PersistenceError::TooLarge);
        }
        self.bytes -= bytes;
        Ok(ByteLease {
            quota: Arc::clone(&self.quota),
            bytes,
        })
    }
    fn extend(&mut self, extra: usize) -> Result<(), PersistenceError> {
        if self.bytes.checked_add(extra).is_none_or(|n| n > MAX_BYTES) {
            return Err(PersistenceError::TooLarge);
        }
        let mut quota = self.quota.lock().map_err(|_| PersistenceError::Worker)?;
        let bytes = quota
            .bytes
            .checked_add(extra)
            .ok_or(PersistenceError::Busy)?;
        if bytes > MAX_BYTES {
            return Err(PersistenceError::Busy);
        }
        quota.bytes = bytes;
        self.bytes += extra;
        Ok(())
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut quota) = self.quota.lock() {
            quota.slots -= 1;
            quota.bytes -= self.bytes;
            quota.available.notify_waiters();
        }
    }
}

enum DbCommand {
    Add(Friend),
    Delete(Friend),
    Category(category::CategoryDbCommand),
    KadLoad,
    KadIdentity,
    KadReplace {
        expected_revision: i64,
        contacts: Vec<KadRoutingContact>,
    },
    KadMerge {
        input: KadInput,
        seed: Vec<RoutingSnapshotContact>,
        identity: KadNodeId,
        revision: i64,
        pending_only: bool,
    },
}

enum KadMergeOutcome {
    Invalid(String),
    Conflict,
    NoAccepted,
    Applied {
        revision: i64,
        accepted: usize,
        records: Vec<RoutingSnapshotContact>,
    },
}

enum DbResponse {
    Friend(Friend, bool),
    Category(category::CategoryWrite),
    KadLoaded(KadRoutingSnapshot),
    KadIdentity(KadNodeId),
    KadReplaced(Option<i64>),
    KadMerged(KadMergeOutcome),
}
struct DbRequest {
    command: DbCommand,
    response: oneshot::Sender<Result<DbResponse, PersistenceError>>,
}

#[derive(Default)]
pub(crate) struct PersistenceSlot {
    inner: StdMutex<SlotState>,
}

#[derive(Default)]
struct SlotState {
    closed: bool,
    stopping: bool,
    owner: Option<Arc<PersistenceOwner>>,
}

impl PersistenceSlot {
    pub(crate) fn stop_regular_admission(&self) -> Result<(), PersistenceError> {
        let mut slot = self.inner.lock().map_err(|_| PersistenceError::Worker)?;
        slot.stopping = true;
        if let Some(owner) = &slot.owner {
            let mut admission = owner
                .admission
                .lock()
                .map_err(|_| PersistenceError::Worker)?;
            admission.stopping = true;
            admission.cancel_ingress.cancel();
        }
        Ok(())
    }
    pub(crate) fn check_coherent_state(&self) -> Result<(), PersistenceError> {
        let slot = self.inner.lock().map_err(|_| PersistenceError::Worker)?;
        if let Some(owner) = &slot.owner {
            let admission = owner
                .admission
                .lock()
                .map_err(|_| PersistenceError::Worker)?;
            if admission
                .quota
                .lock()
                .map_err(|_| PersistenceError::Worker)?
                .faulted
            {
                return Err(PersistenceError::CommitUnknown);
            }
        }
        Ok(())
    }
    pub(crate) fn owner(
        &self,
        store: &MetadataStore,
        state: &Arc<Mutex<CoreState>>,
    ) -> Result<Arc<PersistenceOwner>, PersistenceError> {
        let mut slot = self.inner.lock().map_err(|_| PersistenceError::Worker)?;
        if slot.closed {
            return Err(PersistenceError::Closing);
        }
        if let Some(owner) = &slot.owner {
            return Ok(Arc::clone(owner));
        }
        if slot.stopping {
            return Err(PersistenceError::Closing);
        }
        let owner = PersistenceOwner::start(store.clone(), Arc::clone(state))?;
        slot.owner = Some(Arc::clone(&owner));
        Ok(owner)
    }

    pub(crate) async fn close_and_drain(&self) -> Result<(), PersistenceError> {
        let owner = {
            let mut slot = self.inner.lock().map_err(|_| PersistenceError::Worker)?;
            slot.closed = true;
            slot.owner.clone()
        };
        if let Some(owner) = owner {
            owner.close_and_drain().await
        } else {
            Ok(())
        }
    }
}

/// One coordinator and one blocking worker. Clones share admission and ordering.
pub(crate) struct PersistenceOwner {
    admission: Arc<StdMutex<Admission>>,
    join: Mutex<DrainState>,
    #[cfg(test)]
    fault: Arc<std::sync::atomic::AtomicU8>,
    #[cfg(test)]
    publication_gate: Arc<StdMutex<Option<Arc<PublicationGate>>>>,
    #[cfg(test)]
    worker_started: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    category_page_gate: Arc<StdMutex<Option<(oneshot::Sender<()>, mpsc::Receiver<()>)>>>,
    #[cfg(test)]
    final_quota_wait: Arc<tokio::sync::Notify>,
}

#[cfg(test)]
#[derive(Default)]
struct PublicationGate {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

struct DrainState {
    join: Option<tokio::task::JoinHandle<Result<(), PersistenceError>>>,
    outcome: Option<Result<(), PersistenceError>>,
}

impl PersistenceOwner {
    pub(crate) fn start(
        store: MetadataStore,
        state: Arc<Mutex<CoreState>>,
    ) -> Result<Arc<Self>, PersistenceError> {
        let (db_tx, db_rx) = mpsc::sync_channel::<DbRequest>(1);
        #[cfg(test)]
        let fault = Arc::new(std::sync::atomic::AtomicU8::new(0));
        #[cfg(test)]
        let worker_fault = Arc::clone(&fault);
        #[cfg(test)]
        let worker_started = Arc::new(tokio::sync::Notify::new());
        #[cfg(test)]
        let worker_started_signal = Arc::clone(&worker_started);
        #[cfg(test)]
        let publication_gate = Arc::new(StdMutex::new(None::<Arc<PublicationGate>>));
        #[cfg(test)]
        let coordinator_gate = Arc::clone(&publication_gate);
        #[cfg(test)]
        let category_page_gate = Arc::new(StdMutex::new(
            None::<(oneshot::Sender<()>, mpsc::Receiver<()>)>,
        ));
        #[cfg(test)]
        let worker_page_gate = Arc::clone(&category_page_gate);
        #[cfg(test)]
        let final_quota_wait = Arc::new(tokio::sync::Notify::new());
        let worker = std::thread::Builder::new()
            .name("emulebb-persistence".into())
            .spawn(move || {
                while let Ok(request) = db_rx.recv() {
                    if matches!(&request.command, DbCommand::Category(_)) {
                        let DbRequest { command, response } = request;
                        let DbCommand::Category(command) = command else {
                            unreachable!()
                        };
                        #[cfg(test)]
                        if matches!(&command, category::CategoryDbCommand::RootPage { after, .. } if *after > 0) {
                            let gate = worker_page_gate.lock().unwrap().take();
                            if let Some((entered, release)) = gate {
                                let _ = entered.send(());
                                let _ = release.recv();
                            }
                        }
                        let outcome =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                category::execute(&store, command)
                            }));
                        let result = match outcome {
                            Ok(Ok(value)) => Ok(DbResponse::Category(value)),
                            Ok(Err(error)) => {
                                tracing::warn!(%error, "category persistence failed");
                                Err(error.downcast::<PersistenceError>().unwrap_or_else(|_| {
                                    PersistenceError::Storage("database operation failed".into())
                                }))
                            }
                            Err(_) => Err(PersistenceError::CommitUnknown),
                        };
                        let _ = response.send(result);
                        continue;
                    }
                    if matches!(&request.command, DbCommand::KadMerge { .. }) {
                        let DbRequest { command, response } = request;
                        let DbCommand::KadMerge {
                            input,
                            seed,
                            identity,
                            revision,
                            pending_only,
                        } = command
                        else {
                            unreachable!()
                        };
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            kad::merge_in_worker(
                                &store,
                                input,
                                seed,
                                identity,
                                revision,
                                pending_only,
                                #[cfg(test)]
                                &worker_started_signal,
                            )
                        }));
                        let result = match result {
                            Ok(Ok(outcome)) => Ok(DbResponse::KadMerged(outcome)),
                            Ok(Err(error)) => Err(error),
                            Err(_) => Err(PersistenceError::CommitUnknown),
                        };
                        let _ = response.send(result);
                        continue;
                    }
                    if matches!(
                        &request.command,
                        DbCommand::KadLoad | DbCommand::KadIdentity | DbCommand::KadReplace { .. }
                    ) {
                        let writing = matches!(
                            &request.command,
                            DbCommand::KadIdentity | DbCommand::KadReplace { .. }
                        );
                        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                            || match &request.command {
                                DbCommand::KadLoad => {
                                    store.load_kad_routing_snapshot().map(DbResponse::KadLoaded)
                                }
                                DbCommand::KadIdentity => store
                                    .load_or_create_kad_node_id()
                                    .map(DbResponse::KadIdentity),
                                DbCommand::KadReplace {
                                    expected_revision,
                                    contacts,
                                } => store
                                    .checkpoint_kad_routing_snapshot(*expected_revision, contacts)
                                    .map(DbResponse::KadReplaced),
                                _ => unreachable!(),
                            },
                        ));
                        let result = match outcome {
                            Ok(Ok(value)) => Ok(value),
                            Ok(Err(error)) => {
                                tracing::warn!(%error, "Kad persistence SQL failed");
                                Err(PersistenceError::Storage(
                                    "database operation failed".into(),
                                ))
                            }
                            Err(_) if writing => Err(PersistenceError::CommitUnknown),
                            Err(_) => Err(PersistenceError::Worker),
                        };
                        // WHY: the coordinator can release the request charge
                        // as soon as it receives the response.
                        drop(request.command);
                        let _ = request.response.send(result);
                        continue;
                    }
                    #[cfg(test)]
                    let injected = worker_fault.swap(0, std::sync::atomic::Ordering::SeqCst);
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let started = Instant::now();
                        #[cfg(test)]
                        if injected == 3 {
                            panic!("injected pre-commit worker failure");
                        }
                        #[cfg(test)]
                        worker_started_signal.notify_one();
                        let result = match &request.command {
                            DbCommand::Add(friend) => profile_state::persist_friend(&store, friend),
                            DbCommand::Delete(friend) => {
                                store.delete_friend_timed(&friend.user_hash)
                            }
                            DbCommand::Category(_)
                            | DbCommand::KadLoad
                            | DbCommand::KadIdentity
                            | DbCommand::KadReplace { .. }
                            | DbCommand::KadMerge { .. } => unreachable!(),
                        };
                        #[cfg(test)]
                        if injected != 0 && result.is_ok() {
                            panic!("injected post-commit worker failure");
                        }
                        tracing::debug!(
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "persistence SQL completed"
                        );
                        result
                            .map(|timing| {
                                tracing::debug!(
                                    connection_wait_ms = timing.connection_wait.as_millis() as u64,
                                    execution_commit_ms = timing.execution.as_millis() as u64,
                                    "persistence database timing"
                                );
                            })
                            .map_err(|error| {
                                tracing::warn!(%error, "persistence SQL failed");
                                PersistenceError::Storage("database write failed".into())
                            })
                    }));
                    let result = match result {
                        Ok(Ok(())) => Ok(false),
                        Ok(Err(error)) => Err(error),
                        Err(_) => {
                            // The coordinator is the sole friend writer and has
                            // established absent/add or present/delete before SQL.
                            // Query only this key, never the unbounded friend list.
                            let postcondition = || match &request.command {
                                DbCommand::Add(friend) => store.friend_matches(
                                    &friend.user_hash,
                                    &friend.name,
                                    friend.address.as_deref(),
                                    friend.port,
                                    friend.last_seen.map(|time| time.timestamp_millis()),
                                ),
                                DbCommand::Delete(friend) => {
                                    store.has_friend(&friend.user_hash).map(|present| !present)
                                }
                                DbCommand::Category(_)
                                | DbCommand::KadLoad
                                | DbCommand::KadIdentity
                                | DbCommand::KadReplace { .. }
                                | DbCommand::KadMerge { .. } => {
                                    unreachable!()
                                }
                            };
                            #[cfg(test)]
                            let observed = if injected == 2 {
                                Err(anyhow::anyhow!("injected unavailable read"))
                            } else {
                                postcondition()
                            };
                            #[cfg(not(test))]
                            let observed = postcondition();
                            match observed {
                                Ok(true) => Ok(true),
                                Ok(false) => Err(PersistenceError::Worker),
                                Err(_) => Err(PersistenceError::CommitUnknown),
                            }
                        }
                    }
                    .map(|recovered| {
                        let friend = match request.command {
                            DbCommand::Add(friend) | DbCommand::Delete(friend) => friend,
                            DbCommand::Category(_)
                            | DbCommand::KadLoad
                            | DbCommand::KadIdentity
                            | DbCommand::KadReplace { .. }
                            | DbCommand::KadMerge { .. } => unreachable!(),
                        };
                        DbResponse::Friend(friend, recovered)
                    });
                    let _ = request.response.send(result);
                }
            })
            .map_err(|_| PersistenceError::Worker)?;
        let (sender, mut receiver) = async_mpsc::channel::<Request>(MAX_SLOTS);
        let quota = Arc::new(StdMutex::new(Quota {
            faulted: false,
            slots: 0,
            bytes: 0,
            available: Arc::new(tokio::sync::Notify::new()),
        }));
        let admission = Arc::new(StdMutex::new(Admission {
            sender: Some(sender),
            stopping: false,
            cancel_ingress: tokio_util::sync::CancellationToken::new(),
            quota: Arc::clone(&quota),
        }));
        let coordinator_admission = Arc::downgrade(&admission);
        let coordinator_shutdown = admission
            .lock()
            .map_err(|_| PersistenceError::Worker)?
            .cancel_ingress
            .clone();
        let join = tokio::spawn(async move {
            let mut failures = false;
            let mut publication_failures = false;
            let mut kad_runtime = None;
            let mut active_category: Option<ActiveCategory> = None;
            let mut parked_categories = VecDeque::new();
            let mut receiver_closed = false;
            loop {
                let mut request = if active_category.is_none() && !parked_categories.is_empty() {
                    parked_categories
                        .pop_front()
                        .expect("nonempty category queue")
                } else if let Some(active) = active_category.as_mut() {
                    tokio::select! {
                        outcome = &mut active.completion => {
                            let active = active_category.take().expect("active category");
                            let result = match outcome {
                                Ok(()) => active.result,
                                Err(error) => {
                                    tracing::error!(%error, "category committed but derived publication failed");
                                    publication_failures = true;
                                    Err(PersistenceError::CommittedPublicationFailed)
                                }
                            };
                            let Request { response, permit, released, .. } = active.request;
                            let _ = response.send(result);
                            drop(permit);
                            let _ = released.send(());
                            continue;
                        }
                        next = receiver.recv(), if !receiver_closed => {
                            match next {
                                Some(request) if matches!(&request.command, Command::Category(_)) => {
                                    parked_categories.push_back(request);
                                    continue;
                                }
                                Some(request) => request,
                                None => { receiver_closed = true; continue; }
                            }
                        }
                    }
                } else if receiver_closed {
                    break;
                } else {
                    match receiver.recv().await {
                        Some(request) => request,
                        None => {
                            receiver_closed = true;
                            continue;
                        }
                    }
                };
                let category_command = matches!(&request.command, Command::Category(_));
                tracing::debug!(
                    queue_ms = request.enqueued.elapsed().as_millis() as u64,
                    "persistence request admitted to worker"
                );
                let faulted = quota.lock().map_err(|_| PersistenceError::Worker)?.faulted;
                let mut category_continuation = None;
                let result = if faulted {
                    Err(PersistenceError::CommitUnknown)
                } else {
                    process(
                        &state,
                        &db_tx,
                        &mut request,
                        &mut kad_runtime,
                        &mut category_continuation,
                        #[cfg(test)]
                        &coordinator_gate,
                    )
                    .await
                };
                if (matches!(&result, Err(PersistenceError::CommitUnknown))
                    || (category_command
                        && matches!(&result, Err(PersistenceError::CommittedAfterWorkerFailure))))
                    && !faulted
                {
                    // Serialize the fault with readers of the cache. No reader can
                    // report this domain as coherent after the uncertain outcome.
                    if let Some(shared) = coordinator_admission.upgrade() {
                        let _state = state.lock().await;
                        let mut admission = shared.lock().map_err(|_| PersistenceError::Worker)?;
                        quota.lock().map_err(|_| PersistenceError::Worker)?.faulted = true;
                        admission.cancel_ingress.cancel();
                        admission.sender.take();
                    } else {
                        quota.lock().map_err(|_| PersistenceError::Worker)?.faulted = true;
                    }
                }
                // WHY: a completed request failure was already returned and
                // does not mean the worker failed to drain. Preserve worker
                // and uncertain-commit faults.
                publication_failures |=
                    matches!(&result, Err(PersistenceError::CommittedPublicationFailed));
                failures |= matches!(
                    &result,
                    Err(PersistenceError::Worker
                        | PersistenceError::CommitUnknown
                        | PersistenceError::CommittedAfterWorkerFailure)
                );
                if let Some(continuation) = category_continuation {
                    active_category = Some(ActiveCategory {
                        request,
                        result,
                        completion: Box::pin(
                            continuation.run(db_tx.clone(), coordinator_shutdown.clone()),
                        ),
                    });
                    continue;
                }
                let Request {
                    response,
                    handoff,
                    permit,
                    released,
                    ..
                } = request;
                if let Some(handoff) = handoff {
                    // The attach projection has its own resident byte lease;
                    // fence later commands on the handoff, not on the temporary
                    // payload reservation that startup has already consumed.
                    drop(permit);
                    let _ = released.send(());
                    let _ = response.send(result);
                    if handoff.await.is_err() {
                        if let Some(runtime) = kad_runtime.take() {
                            if let Some(dht) = runtime.dht {
                                dht.seal_persistence().await;
                            }
                        }
                    }
                } else {
                    let _ = response.send(result);
                    drop(permit);
                    let _ = released.send(());
                }
            }
            drop(db_tx);
            let joined = tokio::task::spawn_blocking(move || worker.join())
                .await
                .is_ok_and(|result| result.is_ok());
            if failures || !joined {
                Err(PersistenceError::Worker)
            } else if publication_failures {
                Err(PersistenceError::CommittedPublicationFailed)
            } else {
                Ok(())
            }
        });
        Ok(Arc::new(Self {
            admission,
            join: Mutex::new(DrainState {
                join: Some(join),
                outcome: None,
            }),
            #[cfg(test)]
            fault,
            #[cfg(test)]
            publication_gate,
            #[cfg(test)]
            worker_started,
            #[cfg(test)]
            category_page_gate,
            #[cfg(test)]
            final_quota_wait,
        }))
    }

    pub(crate) async fn add(&self, hash: String, name: String) -> Result<Friend, PersistenceError> {
        self.submit(Command::Add { hash, name })
            .await?
            .ok_or(PersistenceError::Worker)
    }
    pub(crate) async fn delete(&self, hash: String) -> Result<Option<Friend>, PersistenceError> {
        self.submit(Command::Delete { hash }).await
    }
    async fn submit(&self, command: Command) -> Result<Option<Friend>, PersistenceError> {
        let payload = match &command {
            Command::Add { hash, name } => hash
                .capacity()
                .checked_add(name.capacity())
                .ok_or(PersistenceError::TooLarge)?,
            Command::Delete { hash } => hash.capacity(),
            Command::Category(_)
            | Command::Downloads(_)
            | Command::KadLoad
            | Command::KadIdentity
            | Command::KadAttach(_)
            | Command::KadCheckpoint { .. }
            | Command::KadImport { .. } => {
                unreachable!()
            }
        };
        let charge = FIXED_CHARGE
            .checked_add(payload.checked_mul(4).ok_or(PersistenceError::TooLarge)?)
            .ok_or(PersistenceError::TooLarge)?;
        match self.submit_reserved(charge, || Ok(command)).await? {
            Response::Friend(friend) => Ok(friend),
            _ => Err(PersistenceError::Worker),
        }
    }

    async fn submit_reserved(
        &self,
        charge: usize,
        make_command: impl FnOnce() -> Result<Command, PersistenceError>,
    ) -> Result<Response, PersistenceError> {
        self.submit_reserved_inner(charge, false, make_command)
            .await
    }

    async fn submit_reserved_inner(
        &self,
        charge: usize,
        final_snapshot: bool,
        make_command: impl FnOnce() -> Result<Command, PersistenceError>,
    ) -> Result<Response, PersistenceError> {
        let (response, receive) = oneshot::channel();
        let (released, release_complete) = oneshot::channel();
        let is_attach;
        {
            let admission = self
                .admission
                .lock()
                .map_err(|_| PersistenceError::Worker)?;
            let mut quota = admission
                .quota
                .lock()
                .map_err(|_| PersistenceError::Worker)?;
            if admission.sender.is_none() {
                return Err(if quota.faulted {
                    PersistenceError::CommitUnknown
                } else {
                    PersistenceError::Closing
                });
            }
            if admission.stopping && !final_snapshot {
                return Err(PersistenceError::Closing);
            }
            if charge > MAX_BYTES {
                return Err(PersistenceError::TooLarge);
            }
            if quota.slots >= MAX_SLOTS
                || quota
                    .bytes
                    .checked_add(charge)
                    .is_none_or(|n| n > MAX_BYTES)
            {
                return Err(PersistenceError::Busy);
            }
            quota.slots += 1;
            quota.bytes += charge;
            let permit = Permit {
                quota: Arc::clone(&admission.quota),
                bytes: charge,
            };
            drop(quota);
            let command = make_command()?;
            is_attach = matches!(&command, Command::KadAttach(_));
            // Sending under the same lock makes close/admission a single boundary.
            let sender = admission.sender.as_ref().expect("checked sender").clone();
            let sent = sender.try_send(Request {
                command,
                permit,
                response,
                enqueued: Instant::now(),
                handoff: None,
                released,
            });
            drop(admission);
            if let Err(error) = sent {
                return Err(match error {
                    async_mpsc::error::TrySendError::Full(_) => PersistenceError::Busy,
                    async_mpsc::error::TrySendError::Closed(_) => PersistenceError::Worker,
                });
            }
        }
        let result = receive.await.map_err(|_| PersistenceError::Worker)?;
        if !is_attach {
            release_complete
                .await
                .map_err(|_| PersistenceError::Worker)?;
        }
        result
    }
    pub(crate) async fn close_and_drain(&self) -> Result<(), PersistenceError> {
        {
            let mut admission = self
                .admission
                .lock()
                .map_err(|_| PersistenceError::Worker)?;
            admission.cancel_ingress.cancel();
            admission.sender.take();
        }
        let mut drain = self.join.lock().await;
        if let Some(join) = drain.join.as_mut() {
            let outcome = join.await.unwrap_or(Err(PersistenceError::Worker));
            drain.join.take();
            drain.outcome = Some(outcome);
        }
        drain
            .outcome
            .clone()
            .unwrap_or(Err(PersistenceError::Worker))
    }
}

async fn process(
    state: &Arc<Mutex<CoreState>>,
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
    kad_runtime: &mut Option<KadRuntime>,
    category_continuation: &mut Option<category::CategoryContinuation>,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    if matches!(&request.command, Command::Downloads(_)) {
        return download::process(
            request,
            #[cfg(test)]
            publication_gate,
        )
        .await;
    }
    if matches!(&request.command, Command::Category(_)) {
        return category::process(
            state,
            db,
            request,
            category_continuation,
            #[cfg(test)]
            publication_gate,
        )
        .await;
    }
    if matches!(
        &request.command,
        Command::KadAttach(_) | Command::KadCheckpoint { .. } | Command::KadImport { .. }
    ) {
        return kad::process_runtime(db, request, kad_runtime).await;
    }
    if matches!(&request.command, Command::KadLoad | Command::KadIdentity) {
        let command = match std::mem::replace(&mut request.command, Command::KadLoad) {
            Command::KadLoad => DbCommand::KadLoad,
            Command::KadIdentity => DbCommand::KadIdentity,
            _ => unreachable!(),
        };
        let (response, receive) = oneshot::channel();
        db.send(DbRequest { command, response })
            .map_err(|_| PersistenceError::Worker)?;
        return match receive
            .await
            .map_err(|_| PersistenceError::CommitUnknown)??
        {
            DbResponse::KadLoaded(snapshot) => {
                let bytes = snapshot
                    .contacts
                    .capacity()
                    .checked_mul(std::mem::size_of::<KadRoutingContact>())
                    .ok_or(PersistenceError::TooLarge)?;
                let lease = request.permit.transfer_bytes(bytes)?;
                Ok(Response::KadLoaded(LeasedKadSnapshot {
                    snapshot,
                    _lease: lease,
                }))
            }
            DbResponse::KadIdentity(id) => Ok(Response::KadIdentity(id)),
            DbResponse::KadReplaced(_) => Err(PersistenceError::Worker),
            DbResponse::KadMerged(_) => Err(PersistenceError::Worker),
            DbResponse::Friend(..) | DbResponse::Category(..) => Err(PersistenceError::Worker),
        };
    }
    let prepared = {
        let state = state.lock().await;
        match &request.command {
            Command::Add { hash, name } => {
                if let Some(existing) = state.friends.get(hash) {
                    request.permit.extend(friend_charge(existing)?)?;
                    return Ok(Response::Friend(Some(existing.clone())));
                }
                DbCommand::Add(Friend {
                    user_hash: hash.clone(),
                    name: name.clone(),
                    last_seen: None,
                    address: None,
                    port: 0,
                })
            }
            Command::Delete { hash } => {
                let Some(existing) = state.friends.get(hash) else {
                    return Ok(Response::Friend(None));
                };
                request.permit.extend(friend_charge(existing)?)?;
                DbCommand::Delete(existing.clone())
            }
            Command::Category(_)
            | Command::Downloads(_)
            | Command::KadLoad
            | Command::KadIdentity
            | Command::KadAttach(_)
            | Command::KadCheckpoint { .. }
            | Command::KadImport { .. } => {
                unreachable!()
            }
        }
    };
    let deleting = matches!(prepared, DbCommand::Delete(_));
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: prepared,
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    let outcome = receive
        .await
        .map_err(|_| PersistenceError::CommitUnknown)??;
    let DbResponse::Friend(friend, recovered) = outcome else {
        return Err(PersistenceError::Worker);
    };
    #[cfg(test)]
    let gate = publication_gate.lock().unwrap().clone();
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    let publication = Instant::now();
    let mut state = state.lock().await;
    if deleting {
        state.friends.remove(&friend.user_hash);
    } else {
        state
            .friends
            .insert(friend.user_hash.clone(), friend.clone());
    }
    tracing::debug!(
        publication_ms = publication.elapsed().as_millis() as u64,
        "persistence publication completed"
    );
    if recovered {
        Err(PersistenceError::CommittedAfterWorkerFailure)
    } else {
        Ok(Response::Friend(Some(friend)))
    }
}

fn friend_charge(friend: &Friend) -> Result<usize, PersistenceError> {
    friend
        .user_hash
        .capacity()
        .checked_add(friend.name.capacity())
        .and_then(|n| n.checked_add(friend.address.as_ref().map_or(0, String::capacity)))
        .and_then(|n| n.checked_mul(4))
        .ok_or(PersistenceError::Busy)
}
