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
        let r = &self.request;
        [
            &self.search_id,
            &r.query,
            &r.method,
            &r.r#type,
            &r.extension,
            &r.codec,
            &r.title,
            &r.album,
            &r.artist,
        ]
        .into_iter()
        .try_fold(std::mem::size_of::<Self>(), |n, v| n.checked_add(v.len()))?
        .checked_add(result_bytes(&self.result)?)
    }
}

fn result_bytes(result: &crate::SearchResult) -> Option<usize> {
    let mut bytes = std::mem::size_of::<crate::SearchResult>();
    for value in [
        &result.id,
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

struct PreparedProjection {
    name_votes: Vec<emulebb_metadata::MetadataSearchNameVote>,
    fields: Vec<emulebb_metadata::MetadataSearchResultFields>,
}

async fn prepare_projection(
    publication: &SearchPublication,
    permit: &mut Permit,
) -> Result<Option<PreparedProjection>, PersistenceError> {
    let mut accepted = vec![publication.result.clone()];
    crate::search_query::apply_search_filters(&mut accepted, &publication.request);
    let Some(result) = accepted.pop() else {
        return Ok(None);
    };
    let state = publication.state.lock().await;
    let Some(search) = state.searches.get(&publication.search_id) else {
        return Ok(None);
    };
    if !matches!(search.status.as_str(), "queued" | "running") {
        return Ok(None);
    }
    drop(state);
    let vote_bytes = result
        .observations
        .iter()
        .try_fold(0usize, |bytes, observation| {
            bytes.checked_add(observation.name.len().checked_mul(6)?.checked_add(256)?)
        })
        .ok_or(PersistenceError::TooLarge)?;
    permit.extend(vote_bytes)?;
    let name_votes = crate::search_state::projection_name_votes(&result)
        .map_err(|_| PersistenceError::Worker)?;
    // Reserve the bounded SQL summary receipt before admitting its allocation.
    permit.extend(512 * 1024)?;
    let fields = crate::search_state::result_fields(&result);
    Ok(Some(PreparedProjection { name_votes, fields }))
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
                    Ok(Command::ContentObservations(Box::new(ObservationCommand {
                        events: events.to_vec(),
                        publication: publication.cloned(),
                    })))
                })
                .await
            {
                // WHY: only Busy proves no handoff occurred. Await admission
                // capacity instead of replaying an uncertain or failed write.
                Err(PersistenceError::Busy) => notified.await,
                Ok(Response::ContentObserved(result)) => return result,
                Ok(_) => return Err(PersistenceError::Worker),
                Err(error) => return Err(error),
            }
        }
    }
}

pub(super) fn execute(
    store: &MetadataStore,
    events: &[MetadataContentObservationEvent],
    projection: Option<&emulebb_metadata::MetadataSearchProjection>,
) -> Result<Option<emulebb_metadata::MetadataSearchPublication>, PersistenceError> {
    let result = match projection {
        Some(projection) => store.ingest_search_observations(events, projection),
        None => store.ingest_content_observations(events).map(|_| None),
    };
    result.map_err(|error| {
        if error
            .downcast_ref::<MetadataObservationCommitUncertain>()
            .is_some()
        {
            PersistenceError::CommitUnknown
        } else {
            tracing::warn!(%error,"content observation persistence failed");
            PersistenceError::Storage("database operation failed".into())
        }
    })
}

pub(super) async fn process(
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    let Command::ContentObservations(command) =
        std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    let ObservationCommand {
        events,
        publication,
    } = *command;
    let mut candidate = match publication.as_ref() {
        Some(publication) => match prepare_projection(publication, &mut request.permit).await {
            // This command was admitted but has not reached SQL. Report its
            // capacity refusal once; retrying here would wake on its own permit
            // release and spin while another reader retained the needed bytes.
            Err(PersistenceError::Busy) => {
                return Ok(Response::ContentObserved(Err(PersistenceError::Busy)));
            }
            other => other?,
        },
        None => None,
    };
    let projection = publication
        .as_ref()
        .zip(candidate.as_mut())
        .map(|(publication, prepared)| {
            Ok::<_, PersistenceError>(emulebb_metadata::MetadataSearchProjection {
                session_id: publication
                    .search_id
                    .parse()
                    .map_err(|_| PersistenceError::Worker)?,
                fields: std::mem::take(&mut prepared.fields),
                name_votes: std::mem::take(&mut prepared.name_votes),
            })
        })
        .transpose()?;
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::ContentObservations { events, projection },
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    let committed = match receive
        .await
        .map_err(|_| PersistenceError::CommitUnknown)??
    {
        DbResponse::ContentObserved(committed) => committed,
        _ => return Err(PersistenceError::Worker),
    };
    #[cfg(test)]
    let gate = publication_gate.lock().unwrap().clone();
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    // WHY: the admitted request owns activity publication after SQL. A caller
    // disconnect must not leave runtime activity metadata stale after commit.
    if committed.is_some()
        && let Some(publication) = publication
    {
        crate::search_state::publish_search_activity(&publication.state, &publication.search_id)
            .await;
    }
    Ok(Response::ContentObserved(Ok(())))
}

#[cfg(test)]
pub(super) mod tests;
