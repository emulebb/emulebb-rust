//! Bulk sharing uses the existing coordinator and retained native mutation owner.
use super::*;
use crate::library_policy::RESULT_BYTES;
use crate::{LibraryFileChange, LibraryReply, LibrarySharingOutcome, LibrarySharingRequest};
use emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime;

pub(super) struct SharingCommand {
    request: LibrarySharingRequest,
    runtime: Arc<Ed2kTransferRuntime>,
}

impl PersistenceOwner {
    pub(crate) async fn library_sharing(
        &self,
        request: &LibrarySharingRequest,
        runtime: impl FnOnce() -> Arc<Ed2kTransferRuntime>,
    ) -> Result<LibraryReply<Vec<LibrarySharingOutcome>>, PersistenceError> {
        let charge = request
            .payload_bytes()
            .and_then(|bytes| bytes.checked_mul(4))
            .and_then(|bytes| bytes.checked_add(FIXED_CHARGE + RESULT_BYTES))
            .ok_or(PersistenceError::TooLarge)?;
        match self
            .submit_reserved(charge, || {
                Ok(Command::LibrarySharing(SharingCommand {
                    request: request.clone(),
                    runtime: runtime(),
                }))
            })
            .await?
        {
            Response::LibrarySharing(reply) => Ok(reply),
            _ => Err(PersistenceError::Worker),
        }
    }
}

pub(super) async fn process(
    request: &mut Request,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    let Command::LibrarySharing(command) =
        std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    let lease = request.permit.transfer_bytes(RESULT_BYTES)?;
    #[cfg(test)]
    let gate = publication_gate.lock().unwrap().clone();
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    let mut results = Vec::with_capacity(command.request.hashes.len());
    for hash in command.request.hashes {
        let value = hash.parse().expect("validated library hash selection");
        let outcome = match command
            .runtime
            .set_library_sharing_enabled(value, command.request.enabled)
            .await
        {
            Ok(Some(true)) => Ok(LibraryFileChange::Changed),
            Ok(Some(false)) => Ok(LibraryFileChange::Unchanged),
            Ok(None) => Ok(LibraryFileChange::NotFound),
            Err(error) => {
                tracing::warn!(%error, "library sharing item failed");
                Err(error
                    .downcast_ref::<emulebb_ed2k::ed2k_transfer::LocalMutationError>()
                    .map(PersistenceError::from)
                    .unwrap_or_else(|| {
                        PersistenceError::Storage("database operation failed".into())
                    }))
            }
        };
        results.push(LibrarySharingOutcome { hash, outcome });
    }
    Ok(Response::LibrarySharing(LibraryReply {
        value: results,
        lease,
    }))
}

#[cfg(test)]
mod tests;
