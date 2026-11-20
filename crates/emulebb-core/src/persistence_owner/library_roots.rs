//! Root reads share the existing ordered SQL worker and retain their reply quota.
use super::*;
use crate::library_roots::{LibraryRootPage, Query, Value};

// A page holds at most 32 KiB of native path bytes, or one path up to 64 KiB.
// This covers native storage, escaped display/JSON projection, vector backing
// and allocation rounding. Allocator bookkeeping remains outside payload quota.
pub(super) const RESULT_BYTES: usize = 1024 * 1024;

pub(super) fn load(store: &MetadataStore, query: &Query) -> anyhow::Result<Value> {
    Ok(match query {
        Query::Get(id) => Value::Root(store.library_root(*id)?.map(Into::into)),
        Query::Page { after, limit } => {
            let page = store.library_root_page(*after, *limit)?;
            Value::Page(LibraryRootPage {
                roots: page.items.into_iter().map(Into::into).collect(),
                total: page.total,
                next_id: page.next_id,
            })
        }
    })
}

impl PersistenceOwner {
    /// Admit one fixed-size loss marker into the existing cancellation-safe SQL owner.
    pub(crate) async fn mark_root_scan_required(&self, id: i64) -> Result<(), PersistenceError> {
        // Loss markers are drain-owned, like the final Kad capture: stopping
        // regular admission must not discard an existing producer's final state.
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
                .submit_reserved_inner(FIXED_CHARGE, true, || Ok(Command::RootLoss(id)))
                .await
            {
                // WHY: Busy proves no handoff occurred. Use the same admission
                // backpressure as observations/final Kad, never replay SQL after
                // an uncertain or failed write and never discard a loss for load.
                Err(PersistenceError::Busy) => notified.await,
                Ok(Response::RootLoss) => return Ok(()),
                Ok(_) => return Err(PersistenceError::Worker),
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) async fn read_library_roots(
        &self,
        query: Query,
    ) -> Result<crate::LibraryReply<Value>, PersistenceError> {
        match self
            .submit_reserved(FIXED_CHARGE + RESULT_BYTES, || Ok(Command::RootRead(query)))
            .await?
        {
            Response::RootRead(reply) => Ok(reply),
            _ => Err(PersistenceError::Worker),
        }
    }
}

pub(super) async fn process(
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
) -> Result<Response, PersistenceError> {
    let Command::RootRead(query) = std::mem::replace(&mut request.command, Command::KadLoad) else {
        unreachable!()
    };
    let lease = request.permit.transfer_bytes(RESULT_BYTES)?;
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::RootRead(query),
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    let DbResponse::RootRead(value) = receive.await.map_err(|_| PersistenceError::Worker)?? else {
        return Err(PersistenceError::Worker);
    };
    Ok(Response::RootRead(crate::LibraryReply { value, lease }))
}

#[cfg(test)]
mod tests;

pub(super) async fn process_loss(
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
) -> Result<Response, PersistenceError> {
    let Command::RootLoss(id) = std::mem::replace(&mut request.command, Command::KadLoad) else {
        unreachable!()
    };
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::RootLoss(id),
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    match receive.await.map_err(|_| PersistenceError::Worker)?? {
        DbResponse::RootLoss => Ok(Response::RootLoss),
        _ => Err(PersistenceError::Worker),
    }
}
