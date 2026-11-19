//! Owned creation commits identity before publishing the queue/cache entry.
use super::*;
use crate::{EmulebbCore, Search, SearchCreate};

pub(super) struct CreateCommand {
    core: Box<EmulebbCore>,
    request: SearchCreate,
}

impl PersistenceOwner {
    pub(crate) async fn create_search_session(
        &self,
        core: &EmulebbCore,
        request: &SearchCreate,
    ) -> Result<anyhow::Result<Search>, PersistenceError> {
        let bytes = [
            &request.query,
            &request.method,
            &request.r#type,
            &request.extension,
            &request.codec,
            &request.title,
            &request.album,
            &request.artist,
        ]
        .into_iter()
        .try_fold(0usize, |bytes, value| bytes.checked_add(value.capacity()))
        .and_then(|bytes| bytes.checked_add(core.version.capacity()))
        .and_then(|bytes| bytes.checked_add(core.transfer_root.capacity()))
        .and_then(|bytes| bytes.checked_add(core.profile_dir.capacity()))
        .and_then(|bytes| bytes.checked_add(core.incoming_dir.capacity()))
        // Cover prepared queue/spec/normalized SQL copies as well as cache,
        // response, and the narrow runtime context before starting the drain.
        .and_then(|bytes| bytes.checked_mul(6))
        .and_then(|bytes| bytes.checked_add(FIXED_CHARGE + std::mem::size_of::<EmulebbCore>()))
        .ok_or(PersistenceError::TooLarge)?;
        match self
            .submit_reserved(bytes, || {
                Ok(Command::SearchCreate(CreateCommand {
                    core: Box::new(core.clone()),
                    request: request.clone(),
                }))
            })
            .await?
        {
            Response::SearchCreated(result) => Ok(result),
            _ => Err(PersistenceError::Worker),
        }
    }
}

pub(crate) async fn insert(
    db: &mpsc::SyncSender<DbRequest>,
    search: &Search,
) -> anyhow::Result<String> {
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::SearchCreate(crate::search_state::search_to_metadata(search)),
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    match receive
        .await
        .map_err(|_| PersistenceError::CommitUnknown)??
    {
        DbResponse::SearchCreated(id) => Ok(id?.to_string()),
        _ => Err(PersistenceError::Worker.into()),
    }
}

pub(super) async fn process(
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    let Command::SearchCreate(command) = std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    let outcome = command
        .core
        .create_search_owned(
            command.request,
            db,
            #[cfg(test)]
            publication_gate,
        )
        .await;
    // Preserve persistence faults at the coordinator boundary; validation errors
    // stay domain errors and do not fault the owner or allocate a durable ID.
    if let Err(error) = &outcome
        && let Some(error) = error.downcast_ref::<PersistenceError>()
    {
        return Err(error.clone());
    }
    Ok(Response::SearchCreated(outcome))
}

#[cfg(test)]
mod tests;
