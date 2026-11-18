//! Search removal shares ordering and disconnect ownership with ingestion.
use super::*;
use crate::search_queue::SearchQueue;

type Queue = Arc<parking_lot::Mutex<SearchQueue>>;

pub(super) struct SearchCommand {
    mutation: Mutation,
    queue: Queue,
}

#[derive(Clone, Copy)]
enum Mutation {
    Remove(Option<i64>),
    Stop(i64),
}

impl PersistenceOwner {
    pub(crate) async fn remove_search_sessions(
        &self,
        id: Option<i64>,
        queue: &Queue,
    ) -> Result<bool, PersistenceError> {
        self.mutate_search_sessions(Mutation::Remove(id), queue)
            .await
    }

    pub(crate) async fn stop_search_session(
        &self,
        id: i64,
        queue: &Queue,
    ) -> Result<bool, PersistenceError> {
        self.mutate_search_sessions(Mutation::Stop(id), queue).await
    }

    async fn mutate_search_sessions(
        &self,
        mutation: Mutation,
        queue: &Queue,
    ) -> Result<bool, PersistenceError> {
        match self
            .submit_reserved(FIXED_CHARGE + 128, || {
                Ok(Command::SearchSessions(SearchCommand {
                    mutation,
                    queue: Arc::clone(queue),
                }))
            })
            .await?
        {
            Response::SearchMutated(removed) => Ok(removed),
            _ => Err(PersistenceError::Worker),
        }
    }
}

pub(super) async fn process(
    state: &Arc<Mutex<CoreState>>,
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    let Command::SearchSessions(command) =
        std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    // Coordinate with create/retry using state -> queue ordering. SQLite runs
    // on the existing blocking worker; the admitted coordinator owns publication.
    let mut state = state.lock().await;
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: match command.mutation {
            Mutation::Remove(id) => DbCommand::SearchRemove(id),
            Mutation::Stop(id) => DbCommand::SearchStop(id),
        },
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    let DbResponse::SearchMutated(persisted) = receive
        .await
        .map_err(|_| PersistenceError::CommitUnknown)??
    else {
        return Err(PersistenceError::Worker);
    };
    #[cfg(test)]
    let gate = publication_gate.lock().unwrap().clone();
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    let id = match command.mutation {
        Mutation::Remove(id) => id,
        Mutation::Stop(id) => Some(id),
    };
    let changed = match id {
        Some(id) => {
            let id = id.to_string();
            let queued = command.queue.lock().remove_pending(&id);
            let cancelled = state.search_cancels.remove(&id).is_some_and(|cancel| {
                cancel.cancel();
                true
            });
            let cached = state.searches.remove(&id).is_some();
            if matches!(command.mutation, Mutation::Remove(_)) {
                state.kad_aich_search_votes.remove_session(&id);
            }
            persisted || queued || cancelled || cached
        }
        None => {
            command.queue.lock().clear_pending();
            for (_, cancel) in state.search_cancels.drain() {
                cancel.cancel();
            }
            state.searches.clear();
            state.kad_aich_search_votes.clear();
            persisted
        }
    };
    Ok(Response::SearchMutated(changed))
}

#[cfg(test)]
mod tests;
