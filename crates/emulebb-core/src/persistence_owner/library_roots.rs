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
