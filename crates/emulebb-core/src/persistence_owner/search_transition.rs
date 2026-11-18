//! Header-only search transitions owned through SQL and derived publication.
use super::*;
use crate::{KadAichSearchVotes, SearchProgress};
use std::collections::HashMap;

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    Queued,
    Running,
    Completed,
    Error,
}
impl Phase {
    fn status(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Error => "error",
        }
    }
}

pub(crate) struct Transition {
    pub id: String,
    pub phase: Phase,
    pub reason: Option<String>,
    pub method: Option<String>,
    pub method_token: &'static str,
    pub votes: Option<HashMap<String, KadAichSearchVotes>>,
}

impl PersistenceOwner {
    pub(crate) async fn transition_search(
        &self,
        transition: Transition,
    ) -> Result<(), PersistenceError> {
        let votes = transition
            .votes
            .as_ref()
            .map_or(Some(0usize), |votes| {
                votes.iter().try_fold(
                    votes
                        .capacity()
                        .checked_mul(std::mem::size_of::<(String, KadAichSearchVotes)>())?,
                    |bytes, (hash, votes)| {
                        bytes
                            .checked_add(hash.capacity())?
                            .checked_add(votes.payload_bytes())
                    },
                )
            })
            .ok_or(PersistenceError::TooLarge)?;
        let charge = transition
            .id
            .capacity()
            .checked_add(transition.reason.as_ref().map_or(0, String::capacity))
            .and_then(|bytes| {
                bytes.checked_add(transition.method.as_ref().map_or(0, String::capacity))
            })
            .and_then(|bytes| bytes.checked_add(votes))
            .and_then(|bytes| bytes.checked_mul(4))
            // Validated header strings, progress, and SQL/diagnostic copies.
            .and_then(|bytes| bytes.checked_add(FIXED_CHARGE + 64 * 1024))
            .ok_or(PersistenceError::TooLarge)?;
        let available = {
            let admission = self
                .admission
                .lock()
                .map_err(|_| PersistenceError::Worker)?;
            let quota = admission
                .quota
                .lock()
                .map_err(|_| PersistenceError::Worker)?;
            Arc::clone(&quota.available)
        };
        let mut transition = Some(transition);
        loop {
            let notified = available.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self
                .submit_reserved(charge, || {
                    Ok(Command::SearchTransition(
                        transition.take().ok_or(PersistenceError::Worker)?,
                    ))
                })
                .await
            {
                Err(PersistenceError::Busy) => notified.await,
                Ok(Response::SearchTransitioned) => return Ok(()),
                Ok(_) => return Err(PersistenceError::Worker),
                Err(error) => return Err(error),
            }
        }
    }
}

pub(super) async fn process(
    state: &Arc<Mutex<CoreState>>,
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    let Command::SearchTransition(command) =
        std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    let mut state = state.lock().await;
    let Some(current) = state.searches.get(&command.id) else {
        return Ok(Response::SearchTransitioned);
    };
    if !matches!(current.status.as_str(), "queued" | "running") {
        return Ok(Response::SearchTransitioned);
    }
    let mut header = crate::search_state::search_to_metadata(current);
    header.status = command.phase.status().into();
    header.status_reason.clone_from(&command.reason);
    if let Some(method) = &command.method {
        header.resolved_method = Some(method.clone());
    }
    let updated_at = chrono::Utc::now();
    header.updated_at_s = updated_at.timestamp();
    header.completed_at_s =
        matches!(command.phase, Phase::Completed).then_some(header.updated_at_s);
    let id = command.id.parse().map_err(|_| PersistenceError::Worker)?;
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::SearchUpdate(
            id,
            header,
            command
                .votes
                .as_ref()
                .map(|votes| votes.keys().cloned().collect())
                .unwrap_or_default(),
        ),
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    let DbResponse::SearchUpdated(receipt) = receive
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
    let current = state
        .searches
        .get_mut(&command.id)
        .ok_or(PersistenceError::CommittedPublicationFailed)?;
    current.status = command.phase.status().into();
    current.status_reason = command.reason;
    if let Some(method) = command.method {
        current.resolved_method = Some(method);
    }
    match command.phase {
        Phase::Queued => current.progress = SearchProgress::new("queued", 0, None, ""),
        Phase::Running => current.progress = SearchProgress::new("starting", 0, None, ""),
        Phase::Completed => {
            current.progress.phase = "completed".into();
            if let Some(total) = current.progress.total_units {
                current.progress.completed_units = total;
            }
        }
        Phase::Error => current.progress.phase = "failed".into(),
    }
    current.updated_at = updated_at;
    let terminal = matches!(command.phase, Phase::Completed | Phase::Error);
    if terminal {
        crate::diag_sched::keyword_search(
            &command.id,
            &current.spec.query,
            command.method_token,
            usize::try_from(receipt.result_count).unwrap_or(usize::MAX),
            &current.status,
            current.status_reason.as_deref(),
        );
        state
            .kad_aich_search_votes
            .retain(|(_, id), _| id != &command.id);
        if let Some(mut votes) = command.votes {
            for hash in receipt.accepted_hashes {
                if let Some(votes) = votes.remove(&hash) {
                    state
                        .kad_aich_search_votes
                        .insert((hash, command.id.clone()), votes);
                }
            }
        }
        // Settled sessions are browsed from SQLite; keep runtime state active-only.
        state.searches.remove(&command.id);
        if let Some(cancel) = state.search_cancels.remove(&command.id) {
            if matches!(command.phase, Phase::Error) {
                cancel.cancel();
            }
        }
    }
    Ok(Response::SearchTransitioned)
}

#[cfg(test)]
mod tests;
