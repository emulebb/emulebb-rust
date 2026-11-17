//! Bounded admission and disconnect-independent completion of job controls.
use super::*;
use crate::download_controls::DownloadControlContext;
use crate::{DownloadAction, DownloadControlBatch, DownloadControlResult};
use emulebb_metadata::JobId;
use std::path::Path;

pub(super) struct DownloadCommand {
    action: DownloadAction,
    ids: Vec<JobId>,
    context: DownloadControlContext,
}

impl DownloadCommand {
    pub(super) fn is_verification(&self) -> bool {
        matches!(self.action, DownloadAction::Verify)
    }
}

/// Verification is still profile-owned and quota-bounded, but long filesystem
/// reads must not block unrelated profile commands. Closing the owner drains it.
pub(super) fn finish(
    outcome: Result<(Request, Result<Response, PersistenceError>), tokio::task::JoinError>,
) -> Result<(), PersistenceError> {
    let (request, result) = outcome.map_err(|error| {
        tracing::error!(%error, "owned download control task failed");
        PersistenceError::Worker
    })?;
    let failed = matches!(
        result,
        Err(PersistenceError::Worker | PersistenceError::CommitUnknown)
    );
    let Request {
        response,
        permit,
        released,
        ..
    } = request;
    let _ = response.send(result);
    drop(permit);
    let _ = released.send(());
    if failed {
        Err(PersistenceError::Worker)
    } else {
        Ok(())
    }
}

impl PersistenceOwner {
    pub(crate) async fn downloads(
        &self,
        action: DownloadAction,
        ids: &[JobId],
        root: &Path,
        context: impl FnOnce() -> DownloadControlContext,
    ) -> Result<DownloadControlBatch, PersistenceError> {
        // Charge request IDs, returned results, and platform path backing before
        // copying any of them. Per-item failures are fixed-size domain values.
        let charge = ids
            .len()
            .checked_mul(
                2 * (std::mem::size_of::<JobId>() + std::mem::size_of::<DownloadControlResult>()),
            )
            .and_then(|bytes| {
                root.as_os_str()
                    .len()
                    .checked_mul(4)
                    .and_then(|path| bytes.checked_add(path))
            })
            .and_then(|bytes| bytes.checked_add(FIXED_CHARGE))
            .ok_or(PersistenceError::TooLarge)?;
        match self
            .submit_reserved(charge, || {
                Ok(Command::Downloads(DownloadCommand {
                    action,
                    ids: ids.to_vec(),
                    context: context(),
                }))
            })
            .await?
        {
            Response::Downloads(batch) => Ok(batch),
            _ => Err(PersistenceError::Worker),
        }
    }
}

pub(super) async fn process(
    request: &mut Request,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    let Command::Downloads(command) = std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    let mut results = Vec::with_capacity(command.ids.len());
    let result_bytes = results
        .capacity()
        .checked_mul(std::mem::size_of::<DownloadControlResult>())
        .ok_or(PersistenceError::TooLarge)?;
    let lease = request.permit.transfer_bytes(result_bytes)?;
    for id in command.ids {
        #[cfg(test)]
        let gate = publication_gate.lock().unwrap().clone();
        #[cfg(test)]
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        // WHY: admission transfers ownership of the entire batch. A dropped
        // response or a failed item cannot abandon cancellation/publication or
        // silently skip later request-order items.
        results.push(command.context.apply(command.action, id).await);
    }
    Ok(Response::Downloads(DownloadControlBatch {
        results,
        _lease: lease,
    }))
}
