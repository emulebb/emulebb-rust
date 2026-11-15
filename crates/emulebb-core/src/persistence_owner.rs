//! Bounded ordered persistence for migrated mutations.

use std::{
    sync::{Arc, Mutex as StdMutex, mpsc},
    time::Instant,
};
use tokio::sync::{Mutex, mpsc as async_mpsc, oneshot};

use crate::{Friend, core_state::CoreState, profile_state};
use emulebb_metadata::{
    KAD_ROUTING_MAX_CONTACTS, KadNodeId, KadRoutingContact, KadRoutingSnapshot, MetadataStore,
};

#[cfg(test)]
mod tests;

const MAX_SLOTS: usize = 64;
const MAX_BYTES: usize = 8 * 1024 * 1024;
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
            Self::CommitUnknown => {
                f.write_str("persistence outcome is unknown after a worker failure")
            }
        }
    }
}
impl std::error::Error for PersistenceError {}

enum Command {
    Add {
        hash: String,
        name: String,
    },
    Delete {
        hash: String,
    },
    KadLoad,
    KadIdentity,
    KadInitialize {
        expected_revision: i64,
        contacts: Vec<KadRoutingContact>,
    },
}

enum Response {
    Friend(Option<Friend>),
    KadLoaded(LeasedKadSnapshot),
    KadIdentity(KadNodeId),
    KadInitialized(Option<i64>),
}

/// Keeps a returned snapshot charged independently of a request slot.
pub(crate) struct LeasedKadSnapshot {
    snapshot: KadRoutingSnapshot,
    _lease: ByteLease,
}

impl LeasedKadSnapshot {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "RUST-FEAT-062 Kad runtime integration follows this owner boundary"
        )
    )]
    pub(crate) fn snapshot(&self) -> &KadRoutingSnapshot {
        &self.snapshot
    }
}

struct Request {
    command: Command,
    permit: Permit,
    response: oneshot::Sender<Result<Response, PersistenceError>>,
    enqueued: Instant,
}

struct Admission {
    sender: Option<async_mpsc::Sender<Request>>,
    quota: Arc<StdMutex<Quota>>,
}

struct Quota {
    faulted: bool,
    slots: usize,
    bytes: usize,
}

struct Permit {
    quota: Arc<StdMutex<Quota>>,
    bytes: usize,
}

struct ByteLease {
    quota: Arc<StdMutex<Quota>>,
    bytes: usize,
}

impl Drop for ByteLease {
    fn drop(&mut self) {
        if let Ok(mut quota) = self.quota.lock() {
            quota.bytes -= self.bytes;
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
        }
    }
}

enum DbCommand {
    Add(Friend),
    Delete(Friend),
    KadLoad,
    KadIdentity,
    KadInitialize {
        expected_revision: i64,
        contacts: Vec<KadRoutingContact>,
    },
}

enum DbResponse {
    Friend(Friend, bool),
    KadLoaded(KadRoutingSnapshot),
    KadIdentity(KadNodeId),
    KadInitialized(Option<i64>),
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
    owner: Option<Arc<PersistenceOwner>>,
}

impl PersistenceSlot {
    pub(crate) fn check_friend_state(&self) -> Result<(), PersistenceError> {
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
        let worker = std::thread::Builder::new()
            .name("emulebb-persistence".into())
            .spawn(move || {
                while let Ok(request) = db_rx.recv() {
                    if matches!(
                        &request.command,
                        DbCommand::KadLoad
                            | DbCommand::KadIdentity
                            | DbCommand::KadInitialize { .. }
                    ) {
                        let writing = matches!(
                            &request.command,
                            DbCommand::KadIdentity | DbCommand::KadInitialize { .. }
                        );
                        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                            || match &request.command {
                                DbCommand::KadLoad => {
                                    store.load_kad_routing_snapshot().map(DbResponse::KadLoaded)
                                }
                                DbCommand::KadIdentity => store
                                    .load_or_create_kad_node_id()
                                    .map(DbResponse::KadIdentity),
                                DbCommand::KadInitialize {
                                    expected_revision,
                                    contacts,
                                } => store
                                    .replace_kad_routing_snapshot(
                                        *expected_revision,
                                        true,
                                        contacts,
                                    )
                                    .map(DbResponse::KadInitialized),
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
                            DbCommand::KadLoad
                            | DbCommand::KadIdentity
                            | DbCommand::KadInitialize { .. } => unreachable!(),
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
                                DbCommand::KadLoad
                                | DbCommand::KadIdentity
                                | DbCommand::KadInitialize { .. } => {
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
                            DbCommand::KadLoad
                            | DbCommand::KadIdentity
                            | DbCommand::KadInitialize { .. } => unreachable!(),
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
        }));
        let admission = Arc::new(StdMutex::new(Admission {
            sender: Some(sender),
            quota: Arc::clone(&quota),
        }));
        let coordinator_admission = Arc::downgrade(&admission);
        let join = tokio::spawn(async move {
            let mut failures = false;
            while let Some(mut request) = receiver.recv().await {
                tracing::debug!(
                    queue_ms = request.enqueued.elapsed().as_millis() as u64,
                    "persistence request admitted to worker"
                );
                let faulted = quota.lock().map_err(|_| PersistenceError::Worker)?.faulted;
                let result = if faulted {
                    Err(PersistenceError::CommitUnknown)
                } else {
                    process(
                        &state,
                        &db_tx,
                        &mut request,
                        #[cfg(test)]
                        &coordinator_gate,
                    )
                    .await
                };
                if matches!(&result, Err(PersistenceError::CommitUnknown)) && !faulted {
                    // Serialize the fault with readers of the cache. No reader can
                    // report this domain as coherent after the uncertain outcome.
                    if let Some(shared) = coordinator_admission.upgrade() {
                        let _state = state.lock().await;
                        let mut admission = shared.lock().map_err(|_| PersistenceError::Worker)?;
                        quota.lock().map_err(|_| PersistenceError::Worker)?.faulted = true;
                        admission.sender.take();
                    } else {
                        quota.lock().map_err(|_| PersistenceError::Worker)?.faulted = true;
                    }
                }
                // WHY: a completed request failure was already returned and
                // does not mean the worker failed to drain. Preserve worker
                // and uncertain-commit faults.
                failures |= matches!(
                    &result,
                    Err(PersistenceError::Worker
                        | PersistenceError::CommitUnknown
                        | PersistenceError::CommittedAfterWorkerFailure)
                );
                let _ = request.response.send(result);
                // Request retains its permit until commit and publication complete.
            }
            drop(db_tx);
            let joined = tokio::task::spawn_blocking(move || worker.join())
                .await
                .is_ok_and(|result| result.is_ok());
            if failures || !joined {
                Err(PersistenceError::Worker)
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
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "RUST-FEAT-062 Kad runtime integration follows this owner boundary"
        )
    )]
    pub(crate) async fn load_or_create_kad_node_id(&self) -> Result<KadNodeId, PersistenceError> {
        match self
            .submit_reserved(FIXED_CHARGE, || Ok(Command::KadIdentity))
            .await?
        {
            Response::KadIdentity(id) => Ok(id),
            _ => Err(PersistenceError::Worker),
        }
    }
    async fn submit(&self, command: Command) -> Result<Option<Friend>, PersistenceError> {
        let payload = match &command {
            Command::Add { hash, name } => hash
                .capacity()
                .checked_add(name.capacity())
                .ok_or(PersistenceError::TooLarge)?,
            Command::Delete { hash } => hash.capacity(),
            Command::KadLoad | Command::KadIdentity | Command::KadInitialize { .. } => {
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

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "RUST-FEAT-062 Kad runtime integration follows this owner boundary"
        )
    )]
    pub(crate) async fn load_kad(&self) -> Result<LeasedKadSnapshot, PersistenceError> {
        match self
            .submit_reserved(kad_charge()?, || Ok(Command::KadLoad))
            .await?
        {
            Response::KadLoaded(snapshot) => Ok(snapshot),
            _ => Err(PersistenceError::Worker),
        }
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "RUST-FEAT-062 Kad runtime integration follows this owner boundary"
        )
    )]
    pub(crate) async fn initialize_kad_pending(
        &self,
        expected_revision: i64,
        contacts: &[KadRoutingContact],
    ) -> Result<Option<i64>, PersistenceError> {
        if contacts.len() > KAD_ROUTING_MAX_CONTACTS {
            return Err(PersistenceError::TooLarge);
        }
        match self
            .submit_reserved(kad_charge()?, || {
                let mut owned = Vec::with_capacity(contacts.len());
                if owned.capacity() > KAD_RESERVED_CAPACITY {
                    return Err(PersistenceError::TooLarge);
                }
                owned.extend_from_slice(contacts);
                Ok(Command::KadInitialize {
                    expected_revision,
                    contacts: owned,
                })
            })
            .await?
        {
            Response::KadInitialized(revision) => Ok(revision),
            _ => Err(PersistenceError::Worker),
        }
    }

    async fn submit_reserved(
        &self,
        charge: usize,
        make_command: impl FnOnce() -> Result<Command, PersistenceError>,
    ) -> Result<Response, PersistenceError> {
        let (response, receive) = oneshot::channel();
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
            // Sending under the same lock makes close/admission a single boundary.
            let sender = admission.sender.as_ref().expect("checked sender").clone();
            let sent = sender.try_send(Request {
                command,
                permit,
                response,
                enqueued: Instant::now(),
            });
            drop(admission);
            if let Err(error) = sent {
                return Err(match error {
                    async_mpsc::error::TrySendError::Full(_) => PersistenceError::Busy,
                    async_mpsc::error::TrySendError::Closed(_) => PersistenceError::Worker,
                });
            }
        }
        receive.await.map_err(|_| PersistenceError::Worker)?
    }
    pub(crate) async fn close_and_drain(&self) -> Result<(), PersistenceError> {
        self.admission
            .lock()
            .map_err(|_| PersistenceError::Worker)?
            .sender
            .take();
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

fn kad_charge() -> Result<usize, PersistenceError> {
    KAD_RESERVED_CAPACITY
        .checked_mul(std::mem::size_of::<KadRoutingContact>())
        .and_then(|bytes| bytes.checked_add(FIXED_CHARGE))
        .ok_or(PersistenceError::TooLarge)
}

async fn process(
    state: &Arc<Mutex<CoreState>>,
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    if matches!(
        &request.command,
        Command::KadLoad | Command::KadIdentity | Command::KadInitialize { .. }
    ) {
        let command = match std::mem::replace(&mut request.command, Command::KadLoad) {
            Command::KadLoad => DbCommand::KadLoad,
            Command::KadIdentity => DbCommand::KadIdentity,
            Command::KadInitialize {
                expected_revision,
                contacts,
            } => DbCommand::KadInitialize {
                expected_revision,
                contacts,
            },
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
            DbResponse::KadInitialized(revision) => Ok(Response::KadInitialized(revision)),
            DbResponse::KadIdentity(id) => Ok(Response::KadIdentity(id)),
            DbResponse::Friend(..) => Err(PersistenceError::Worker),
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
            Command::KadLoad | Command::KadIdentity | Command::KadInitialize { .. } => {
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
