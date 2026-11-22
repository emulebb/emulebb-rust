//! One retained owner spans durable metadata and both network publications.
use super::*;
use crate::{Ed2kRuntime, EmulebbCore, SharedFileUpdate};
use emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime;
use std::collections::HashSet;

pub(super) struct MetadataCommand {
    hash: String,
    priority: Option<(String, bool)>,
    comment_rating: Option<(String, u8)>,
    runtime: MetadataRuntime,
}

struct MetadataRuntime {
    transfers: Arc<Ed2kTransferRuntime>,
    ed2k: Arc<Mutex<Option<Ed2kRuntime>>>,
    notes_dirty: Arc<StdMutex<HashSet<String>>>,
    publisher: crate::shared_catalog_publisher::SharedCatalogPublisher,
}

impl EmulebbCore {
    /// Edit an existing client hash, including one without an available copy.
    /// Admission retains ownership until SQL, catalogue and network state agree.
    pub async fn edit_library_file_metadata(
        &self,
        hash: &str,
        request: &SharedFileUpdate,
    ) -> anyhow::Result<bool> {
        crate::library_policy::validate_hash(hash)?;
        let priority = request
            .priority
            .as_deref()
            .map(crate::views::validate_shared_upload_priority)
            .transpose()?;
        let comment_rating = crate::views::validate_shared_file_comment_rating(request)?;
        anyhow::ensure!(
            priority.is_some() || comment_rating.is_some(),
            "metadata edit requires priority, comment, or rating"
        );
        let payload = hash
            .len()
            .checked_add(priority.map_or(0, |value| value.0.len()))
            .and_then(|bytes| bytes.checked_add(comment_rating.as_ref().map_or(0, |v| v.0.len())))
            .and_then(|bytes| bytes.checked_mul(4))
            .and_then(|bytes| bytes.checked_add(FIXED_CHARGE))
            .ok_or(PersistenceError::TooLarge)?;
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        match owner
            .submit_reserved(payload, || {
                Ok(Command::LibraryMetadata(MetadataCommand {
                    hash: hash.to_owned(),
                    priority: priority.map(|(value, auto)| (value.to_owned(), auto)),
                    comment_rating: comment_rating
                        .map(|(value, rating)| (value.to_owned(), rating)),
                    runtime: MetadataRuntime {
                        transfers: Arc::clone(&self.ed2k_transfers),
                        ed2k: Arc::clone(&self.ed2k_runtime),
                        notes_dirty: Arc::clone(&self.kad_notes_dirty),
                        publisher: crate::shared_catalog_publisher::SharedCatalogPublisher::new(
                            self,
                        ),
                    },
                }))
            })
            .await?
        {
            Response::LibraryMetadata(found) => Ok(found),
            _ => Err(PersistenceError::Worker.into()),
        }
    }
}

pub(super) async fn process(
    request: &mut Request,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    let Command::LibraryMetadata(command) =
        std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    let edit = command
        .runtime
        .transfers
        .update_library_file_metadata(
            &command.hash,
            command
                .priority
                .as_ref()
                .map(|(value, auto)| (value.as_str(), *auto)),
            command
                .comment_rating
                .as_ref()
                .map(|(value, rating)| (value.as_str(), *rating)),
        )
        .await
        .map_err(|error| {
            error
                .downcast_ref::<emulebb_ed2k::ed2k_transfer::LocalMutationError>()
                .map(PersistenceError::from)
                .unwrap_or_else(|| PersistenceError::Storage("database operation failed".into()))
        })?;
    let Some(edit) = edit else {
        return Ok(Response::LibraryMetadata(false));
    };
    #[cfg(test)]
    let gate = publication_gate.lock().unwrap().clone();
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    if edit.notes_changed {
        command
            .runtime
            .notes_dirty
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(command.hash.clone());
    }
    if edit.rating_changed || edit.publish_status_changed {
        let state = command
            .runtime
            .ed2k
            .lock()
            .await
            .as_ref()
            .map(|runtime| Arc::clone(&runtime.server_state));
        if let Some(state) = state {
            state
                .read()
                .await
                .offer_files_publication
                .mark_queued(command.hash.parse().expect("validated library hash"));
        }
        command.runtime.publisher.queue();
    }
    Ok(Response::LibraryMetadata(true))
}

#[cfg(test)]
mod tests;
