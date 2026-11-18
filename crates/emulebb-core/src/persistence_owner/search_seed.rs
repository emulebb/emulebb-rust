//! Indexed, bounded selection of download evidence from permanent membership.
use super::*;
use emulebb_metadata::MetadataSearchDownloadSeed;

const SEED_BYTES: usize = 512 * 1024;
impl PersistenceOwner {
    pub(crate) async fn search_download_seed(
        &self,
        session_id: i64,
        claim_id: i64,
    ) -> Result<crate::LibraryReply<Option<MetadataSearchDownloadSeed>>, PersistenceError> {
        match self
            .submit_reserved(FIXED_CHARGE + SEED_BYTES, || {
                Ok(Command::SearchSeed {
                    session_id,
                    claim_id,
                })
            })
            .await?
        {
            Response::SearchSeed(seed) => Ok(seed),
            _ => Err(PersistenceError::Worker),
        }
    }
}

pub(super) async fn process(
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
) -> Result<Response, PersistenceError> {
    let Command::SearchSeed {
        session_id,
        claim_id,
    } = std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    let lease = request.permit.transfer_bytes(SEED_BYTES)?;
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::SearchSeed {
            session_id,
            claim_id,
        },
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    let DbResponse::SearchSeed(value) = receive.await.map_err(|_| PersistenceError::Worker)??
    else {
        return Err(PersistenceError::Worker);
    };
    Ok(Response::SearchSeed(crate::LibraryReply { value, lease }))
}

#[cfg(test)]
mod tests;
