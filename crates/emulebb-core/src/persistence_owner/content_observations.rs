//! Network evidence shares the profile's bounded ordered SQL owner.

use super::*;
use emulebb_metadata::{
    CONTENT_OBSERVATION_BATCH_BYTES, CONTENT_OBSERVATION_BATCH_ITEMS,
    MetadataContentObservationEvent, MetadataObservationCommitUncertain,
};

impl PersistenceOwner {
    pub(crate) async fn observe_content(
        &self,
        events: &[MetadataContentObservationEvent],
    ) -> Result<(), PersistenceError> {
        if events.len() > CONTENT_OBSERVATION_BATCH_ITEMS {
            return Err(PersistenceError::TooLarge);
        }
        let payload = events
            .iter()
            .try_fold(0usize, |bytes, event| {
                bytes.checked_add(event.payload_bytes()?)
            })
            .ok_or(PersistenceError::TooLarge)?;
        if payload > CONTENT_OBSERVATION_BATCH_BYTES {
            return Err(PersistenceError::TooLarge);
        }
        let charge = payload
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(FIXED_CHARGE))
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
        loop {
            let notified = available.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self
                .submit_reserved(charge, || Ok(Command::ContentObservations(events.to_vec())))
                .await
            {
                // WHY: only Busy proves no handoff occurred. Await admission
                // capacity instead of replaying an uncertain or failed write.
                Err(PersistenceError::Busy) => notified.await,
                Ok(Response::ContentObserved) => return Ok(()),
                Ok(_) => return Err(PersistenceError::Worker),
                Err(error) => return Err(error),
            }
        }
    }
}

pub(super) fn execute(
    store: &MetadataStore,
    events: &[MetadataContentObservationEvent],
) -> Result<(), PersistenceError> {
    store
        .ingest_content_observations(events)
        .map(|_| ())
        .map_err(|error| {
            if error
                .downcast_ref::<MetadataObservationCommitUncertain>()
                .is_some()
            {
                PersistenceError::CommitUnknown
            } else {
                tracing::warn!(%error, "content observation persistence failed");
                PersistenceError::Storage("database operation failed".into())
            }
        })
}

pub(super) async fn process(
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    let Command::ContentObservations(events) =
        std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    #[cfg(test)]
    let gate = publication_gate.lock().unwrap().clone();
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::ContentObservations(events),
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    match receive
        .await
        .map_err(|_| PersistenceError::CommitUnknown)??
    {
        DbResponse::ContentObserved => Ok(Response::ContentObserved),
        _ => Err(PersistenceError::Worker),
    }
}

#[cfg(test)]
mod tests;
