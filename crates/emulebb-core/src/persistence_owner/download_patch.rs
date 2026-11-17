//! Combined job edits retain one existing owner through SQL and publication.
use super::category::{CategoryCommand, CategoryDbCommand, CategoryWrite};
use super::*;
use crate::{DownloadChange, DownloadUpdate, download_attempts::DownloadAttemptControl};
use emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime;
use emulebb_metadata::{DownloadPatchError, JobId, MetadataDownloadPatch};

pub(crate) struct DownloadPatchCommand {
    id: JobId,
    update: DownloadUpdate,
    runtime: Arc<Ed2kTransferRuntime>,
    attempts: Arc<DownloadAttemptControl>,
}

impl DownloadPatchCommand {
    pub(super) fn bytes(&self) -> usize {
        update_bytes(&self.update)
    }
}

fn update_bytes(update: &DownloadUpdate) -> usize {
    update
        .name
        .as_ref()
        .map_or(0, String::capacity)
        .saturating_add(
            update
                .category
                .as_ref()
                .and_then(Option::as_ref)
                .map_or(0, String::capacity),
        )
}

impl PersistenceOwner {
    pub(crate) async fn patch_download(
        &self,
        id: JobId,
        update: &DownloadUpdate,
        runtime: &Arc<Ed2kTransferRuntime>,
        attempts: &Arc<DownloadAttemptControl>,
    ) -> Result<Result<DownloadChange, DownloadPatchError>, PersistenceError> {
        let charge = update_bytes(update)
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(FIXED_CHARGE + 1024 * 1024))
            .ok_or(PersistenceError::TooLarge)?;
        match self
            .submit_reserved(charge, || {
                Ok(Command::Category(CategoryCommand::PatchDownload(
                    DownloadPatchCommand {
                        id,
                        update: update.clone(),
                        runtime: Arc::clone(runtime),
                        attempts: Arc::clone(attempts),
                    },
                )))
            })
            .await?
        {
            Response::DownloadPatched(value) => Ok(value),
            _ => Err(PersistenceError::Worker),
        }
    }
}

pub(super) async fn process(
    state: &Arc<Mutex<CoreState>>,
    db: &mpsc::SyncSender<DbRequest>,
    command: DownloadPatchCommand,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    let category_id = match command.update.category {
        None => None,
        Some(None) => Some(None),
        Some(Some(name)) => {
            let state = state.lock().await;
            let Some(category) = state
                .categories
                .values()
                .find(|category| category.name.eq_ignore_ascii_case(&name))
            else {
                return Ok(Response::DownloadPatched(Err(
                    DownloadPatchError::CategoryNotFound,
                )));
            };
            Some(Some(category.id))
        }
    };
    let patch = MetadataDownloadPatch {
        name: command
            .update
            .name
            .map(|name| emulebb_ed2k::normalize_ed2k_file_name(&name)),
        category_id,
        size_bytes: command.update.size_bytes,
    };
    let publication = match command
        .runtime
        .prepare_download_patch(command.id, &patch)
        .await
    {
        Ok(Some(publication)) => publication,
        Ok(None) => return Ok(Response::DownloadPatched(Ok(DownloadChange::NotFound))),
        Err(error) => {
            if let Some(error) = error.downcast_ref::<DownloadPatchError>() {
                return Ok(Response::DownloadPatched(Err(*error)));
            }
            return Err(
                match error.downcast_ref::<emulebb_ed2k::ed2k_transfer::LocalMutationError>() {
                    Some(emulebb_ed2k::ed2k_transfer::LocalMutationError::Busy) => {
                        PersistenceError::Busy
                    }
                    Some(emulebb_ed2k::ed2k_transfer::LocalMutationError::Closing) => {
                        PersistenceError::Closing
                    }
                    Some(emulebb_ed2k::ed2k_transfer::LocalMutationError::TooLarge) => {
                        PersistenceError::TooLarge
                    }
                    Some(emulebb_ed2k::ed2k_transfer::LocalMutationError::Unknown) => {
                        PersistenceError::CommitUnknown
                    }
                    _ => PersistenceError::Worker,
                },
            );
        }
    };
    let _fence = publication.retain_fence();
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::Category(CategoryDbCommand::PatchDownload {
            patch,
            publication,
            runtime: Arc::clone(&command.runtime),
        }),
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    let DbResponse::Category(CategoryWrite::DownloadPatched(value)) = receive
        .await
        .map_err(|_| PersistenceError::CommitUnknown)??
    else {
        return Err(PersistenceError::Worker);
    };
    let value = match value {
        Err(error) => return Ok(Response::DownloadPatched(Err(error))),
        Ok(None) => return Ok(Response::DownloadPatched(Ok(DownloadChange::NotFound))),
        Ok(Some(value)) => value,
    };
    #[cfg(test)]
    let gate = publication_gate.lock().unwrap().clone();
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    let mut state = state.lock().await;
    let category_name = value
        .category_id
        .and_then(|id| state.categories.get(&id))
        .map(|category| category.name.clone());
    if let Some(transfer) = state.transfers.get_mut(&command.id.to_string()) {
        transfer.name = value.name;
        transfer.category_id = value.category_id;
        transfer.category_name = category_name;
        if let Some(size) = value.size_bytes {
            transfer.size_bytes = size;
        }
    }
    drop(state);
    if value.size_changed {
        command.attempts.cancel_through(value.token);
    }
    if value.changed {
        command.attempts.changed.notify_one();
    }
    Ok(Response::DownloadPatched(Ok(if value.changed {
        DownloadChange::Changed
    } else {
        DownloadChange::Unchanged
    })))
}

#[cfg(test)]
mod tests;
