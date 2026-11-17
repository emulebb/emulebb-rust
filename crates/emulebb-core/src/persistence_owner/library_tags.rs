//! Tag commands use the existing profile coordinator and blocking SQL worker.
use super::*;
use crate::LibraryReply;
use crate::library_tags::{
    LibraryTag, LibraryTagAssignment, LibraryTagChange, LibraryTagPage, LibraryTagRequest,
    LibraryTagValue,
};
use emulebb_metadata::LibraryTagError;

// Covers 200 names of at most 64 bytes, vector capacity, and response projection.
// Reserve before SQL so a successful commit never needs another admission wait.
use crate::library_policy::RESULT_BYTES;
pub(super) type Outcome = Result<LibraryTagValue, LibraryTagError>;

fn domain<T>(result: anyhow::Result<T>) -> Result<Result<T, LibraryTagError>, PersistenceError> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(error) => match error.downcast_ref::<LibraryTagError>() {
            Some(error) => Ok(Err(*error)),
            None => {
                tracing::warn!(%error, "library tag persistence failed");
                Err(PersistenceError::Storage(
                    "database operation failed".into(),
                ))
            }
        },
    }
}

fn page(value: emulebb_metadata::MetadataLibraryTagPage) -> LibraryTagPage {
    LibraryTagPage {
        tags: value
            .tags
            .into_iter()
            .map(|tag| LibraryTag { name: tag.name })
            .collect(),
        next_after: value.next_after,
        has_more: value.has_more,
    }
}

pub(super) fn execute(
    store: &MetadataStore,
    command: LibraryTagRequest,
) -> Result<Outcome, PersistenceError> {
    let value = match command {
        LibraryTagRequest::Create(name) => store
            .create_library_tag(&name)
            .map(|tag| LibraryTagValue::Tag(Some(LibraryTag { name: tag.name }))),
        LibraryTagRequest::Get(name) => store
            .library_tag(&name)
            .map(|tag| LibraryTagValue::Tag(tag.map(|tag| LibraryTag { name: tag.name }))),
        LibraryTagRequest::Delete(name) => store
            .delete_library_tag(&name)
            .map(LibraryTagValue::Deleted),
        LibraryTagRequest::Page { hash, after, limit } => match hash {
            Some(hash) => store
                .library_file_tags_page(&hash, after.as_deref(), limit)
                .map(|value| LibraryTagValue::Page(value.map(page))),
            None => store
                .library_tags_page(after.as_deref(), limit)
                .map(|value| LibraryTagValue::Page(Some(page(value)))),
        },
        LibraryTagRequest::Change {
            tag,
            hashes,
            assigned,
        } => {
            match domain(store.library_tag(&tag))? {
                Ok(Some(_)) => {}
                Ok(None) => return Ok(Err(LibraryTagError::NotFound)),
                Err(error) => return Ok(Err(error)),
            }
            let mut results = Vec::with_capacity(hashes.len());
            for hash in hashes {
                let change = match store.set_library_file_tag(&hash, &tag, assigned) {
                    Ok(true) => LibraryTagChange::Changed,
                    Ok(false) => LibraryTagChange::Unchanged,
                    Err(error)
                        if error.downcast_ref::<LibraryTagError>()
                            == Some(&LibraryTagError::UnknownFile) =>
                    {
                        LibraryTagChange::NotFound
                    }
                    Err(error) => {
                        tracing::warn!(%error, "library tag item failed");
                        LibraryTagChange::StorageFailed
                    }
                };
                results.push(LibraryTagAssignment { hash, change });
            }
            return Ok(Ok(LibraryTagValue::Assignments(results)));
        }
    };
    domain(value)
}

impl PersistenceOwner {
    pub(crate) async fn library_tags(
        &self,
        request: &LibraryTagRequest,
    ) -> Result<Result<LibraryReply<LibraryTagValue>, LibraryTagError>, PersistenceError> {
        let charge = request
            .payload_bytes()
            .and_then(|bytes| bytes.checked_mul(4))
            .and_then(|bytes| bytes.checked_add(FIXED_CHARGE + RESULT_BYTES))
            .ok_or(PersistenceError::TooLarge)?;
        match self
            .submit_reserved(charge, || Ok(Command::LibraryTags(request.clone())))
            .await?
        {
            Response::LibraryTags(value) => Ok(value),
            _ => Err(PersistenceError::Worker),
        }
    }
}

pub(super) async fn process(
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    let Command::LibraryTags(command) = std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    let writing = command.writes();
    let lease = request.permit.transfer_bytes(RESULT_BYTES)?;
    #[cfg(test)]
    let gate = publication_gate.lock().unwrap().clone();
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::LibraryTags(command),
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    let result = receive.await.map_err(|_| {
        if writing {
            PersistenceError::CommitUnknown
        } else {
            PersistenceError::Worker
        }
    })??;
    let DbResponse::LibraryTags(value) = result else {
        return Err(PersistenceError::Worker);
    };
    Ok(Response::LibraryTags(
        value.map(|value| LibraryReply { value, lease }),
    ))
}

#[cfg(test)]
mod tests;
