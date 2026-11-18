//! Network evidence shares the profile's bounded ordered SQL owner.

use super::*;
use emulebb_metadata::{
    CONTENT_OBSERVATION_BATCH_BYTES, CONTENT_OBSERVATION_BATCH_ITEMS,
    MetadataContentObservationEvent, MetadataObservationCommitUncertain,
};

#[derive(Clone)]
pub(crate) struct SearchPublication {
    pub state: Arc<Mutex<CoreState>>,
    pub search_id: String,
    pub request: crate::SearchCreate,
    pub result: crate::SearchResult,
}

pub(super) struct ObservationCommand {
    events: Vec<MetadataContentObservationEvent>,
    publication: Option<SearchPublication>,
}

impl SearchPublication {
    fn payload_bytes(&self) -> Option<usize> {
        let request = &self.request;
        let result = &self.result;
        let mut bytes = std::mem::size_of::<Self>();
        for value in [
            &self.search_id,
            &request.query,
            &request.method,
            &request.r#type,
            &request.extension,
            &request.codec,
            &request.title,
            &request.album,
            &request.artist,
            &result.search_id,
            &result.r#type,
            &result.hash,
            &result.name,
            &result.file_type,
            &result.aich_hash,
            &result.directory,
        ] {
            bytes = bytes.checked_add(value.len())?;
        }
        bytes = bytes.checked_add(media_bytes(&result.media)?)?;
        bytes = bytes.checked_add(
            result
                .observations
                .len()
                .checked_mul(std::mem::size_of::<crate::SearchResultObservation>())?,
        )?;
        for observation in &result.observations {
            for value in [
                &observation.origin,
                &observation.name,
                &observation.file_type,
                &observation.aich_hash,
                &observation.directory,
            ] {
                bytes = bytes.checked_add(value.len())?;
            }
            bytes = bytes.checked_add(
                observation
                    .reporter_endpoint
                    .as_ref()
                    .map_or(0, String::len),
            )?;
            bytes = bytes.checked_add(media_bytes(&observation.media)?)?;
        }
        Some(bytes)
    }
}

fn media_bytes(media: &crate::SearchResultMedia) -> Option<usize> {
    [&media.artist, &media.album, &media.title, &media.codec]
        .into_iter()
        .try_fold(0usize, |bytes, value| bytes.checked_add(value.len()))
}

impl PersistenceOwner {
    pub(crate) async fn observe_content(
        &self,
        events: &[MetadataContentObservationEvent],
        publication: Option<&SearchPublication>,
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
        let publication_bytes = match publication {
            Some(publication) => publication
                .payload_bytes()
                .ok_or(PersistenceError::TooLarge)?,
            None => 0,
        };
        let charge = payload
            .checked_add(publication_bytes)
            .ok_or(PersistenceError::TooLarge)?
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
                .submit_reserved(charge, || {
                    Ok(Command::ContentObservations(ObservationCommand {
                        events: events.to_vec(),
                        publication: publication.cloned(),
                    }))
                })
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
    let Command::ContentObservations(ObservationCommand {
        events,
        publication,
    }) = std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::ContentObservations(events),
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    let response = match receive
        .await
        .map_err(|_| PersistenceError::CommitUnknown)??
    {
        DbResponse::ContentObserved => Response::ContentObserved,
        _ => return Err(PersistenceError::Worker),
    };
    #[cfg(test)]
    let gate = publication_gate.lock().unwrap().clone();
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    // WHY: the admitted request owns publication after SQL. A disconnected
    // producer must not strand durable evidence outside its collecting session.
    if let Some(publication) = publication {
        crate::search_state::publish_observation(
            &publication.state,
            &publication.search_id,
            &publication.request,
            publication.result,
        )
        .await;
    }
    Ok(response)
}

#[cfg(test)]
mod tests;
