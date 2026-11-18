//! Indexed search reads share the bounded SQL owner and retain their reply charge.
use super::*;
use emulebb_metadata::{
    MetadataSearchDownloadSeed, MetadataSearchHeader, MetadataSearchPage,
    MetadataSearchResultHeader, MetadataSearchResultObservation,
};

pub(super) enum Query {
    Headers {
        before: Option<i64>,
        limit: usize,
    },
    Header(i64),
    Results {
        session: i64,
        after: i64,
        limit: usize,
    },
    Result {
        session: i64,
        claim: i64,
    },
    Observations {
        session: i64,
        claim: i64,
        after: i64,
        limit: usize,
    },
    Seed {
        session: i64,
        claim: i64,
    },
}
pub(super) enum Value {
    Headers(MetadataSearchPage<MetadataSearchHeader>),
    Header(Option<MetadataSearchHeader>),
    Results(Option<MetadataSearchPage<MetadataSearchResultHeader>>),
    Result(Option<MetadataSearchResultHeader>),
    Observations(Option<MetadataSearchPage<MetadataSearchResultObservation>>),
    Seed(Option<MetadataSearchDownloadSeed>),
}
impl Query {
    fn bytes(&self) -> usize {
        match self {
            Self::Results { .. } => 1024 * 1024,
            Self::Result { .. } | Self::Seed { .. } => 512 * 1024,
            _ => 256 * 1024,
        }
    }
    fn valid(&self) -> bool {
        let page = |after: i64, limit: usize| after >= 0 && (1..=200).contains(&limit);
        match self {
            Self::Headers { before, limit } => before.is_none_or(|id| id > 0) && page(0, *limit),
            Self::Header(id) => *id > 0,
            Self::Results {
                session,
                after,
                limit,
            } => *session > 0 && page(*after, *limit),
            Self::Result { session, claim } | Self::Seed { session, claim } => {
                *session > 0 && *claim > 0
            }
            Self::Observations {
                session,
                claim,
                after,
                limit,
            } => *session > 0 && *claim > 0 && page(*after, *limit),
        }
    }
}

impl PersistenceOwner {
    async fn read_search(
        &self,
        query: Query,
    ) -> Result<crate::LibraryReply<Value>, PersistenceError> {
        if !query.valid() {
            return Err(PersistenceError::TooLarge);
        }
        let bytes = query.bytes();
        match self
            .submit_reserved(FIXED_CHARGE + bytes, || Ok(Command::SearchRead(query)))
            .await?
        {
            Response::SearchRead(value) => Ok(value),
            _ => Err(PersistenceError::Worker),
        }
    }
    pub(crate) async fn search_download_seed(
        &self,
        session_id: i64,
        claim_id: i64,
    ) -> Result<crate::LibraryReply<Option<MetadataSearchDownloadSeed>>, PersistenceError> {
        let reply = self
            .read_search(Query::Seed {
                session: session_id,
                claim: claim_id,
            })
            .await?;
        let Value::Seed(value) = reply.value else {
            return Err(PersistenceError::Worker);
        };
        Ok(crate::LibraryReply {
            value,
            lease: reply.lease,
        })
    }
    pub(crate) async fn search_headers_page(
        &self,
        before: Option<i64>,
        limit: usize,
    ) -> Result<crate::LibraryReply<MetadataSearchPage<MetadataSearchHeader>>, PersistenceError>
    {
        let reply = self.read_search(Query::Headers { before, limit }).await?;
        let Value::Headers(value) = reply.value else {
            return Err(PersistenceError::Worker);
        };
        Ok(crate::LibraryReply {
            value,
            lease: reply.lease,
        })
    }
    pub(crate) async fn search_header(
        &self,
        id: i64,
    ) -> Result<crate::LibraryReply<Option<MetadataSearchHeader>>, PersistenceError> {
        let reply = self.read_search(Query::Header(id)).await?;
        let Value::Header(value) = reply.value else {
            return Err(PersistenceError::Worker);
        };
        Ok(crate::LibraryReply {
            value,
            lease: reply.lease,
        })
    }
    pub(crate) async fn search_result_headers_page(
        &self,
        session: i64,
        after: i64,
        limit: usize,
    ) -> Result<
        crate::LibraryReply<Option<MetadataSearchPage<MetadataSearchResultHeader>>>,
        PersistenceError,
    > {
        let reply = self
            .read_search(Query::Results {
                session,
                after,
                limit,
            })
            .await?;
        let Value::Results(value) = reply.value else {
            return Err(PersistenceError::Worker);
        };
        Ok(crate::LibraryReply {
            value,
            lease: reply.lease,
        })
    }
    pub(crate) async fn search_result_header(
        &self,
        session: i64,
        claim: i64,
    ) -> Result<crate::LibraryReply<Option<MetadataSearchResultHeader>>, PersistenceError> {
        let reply = self.read_search(Query::Result { session, claim }).await?;
        let Value::Result(value) = reply.value else {
            return Err(PersistenceError::Worker);
        };
        Ok(crate::LibraryReply {
            value,
            lease: reply.lease,
        })
    }
    pub(crate) async fn search_result_observations_page(
        &self,
        session: i64,
        claim: i64,
        after: i64,
        limit: usize,
    ) -> Result<
        crate::LibraryReply<Option<MetadataSearchPage<MetadataSearchResultObservation>>>,
        PersistenceError,
    > {
        let reply = self
            .read_search(Query::Observations {
                session,
                claim,
                after,
                limit,
            })
            .await?;
        let Value::Observations(value) = reply.value else {
            return Err(PersistenceError::Worker);
        };
        Ok(crate::LibraryReply {
            value,
            lease: reply.lease,
        })
    }
}

pub(super) fn load(store: &MetadataStore, query: &Query) -> anyhow::Result<Value> {
    Ok(match query {
        Query::Headers { before, limit } => {
            Value::Headers(store.search_headers_page(*before, *limit)?)
        }
        Query::Header(id) => Value::Header(store.search_header(*id)?),
        Query::Results {
            session,
            after,
            limit,
        } => Value::Results(store.search_result_headers_page(*session, *after, *limit)?),
        Query::Result { session, claim } => {
            Value::Result(store.search_result_header(*session, *claim)?)
        }
        Query::Observations {
            session,
            claim,
            after,
            limit,
        } => Value::Observations(
            store.search_result_observations_page(*session, *claim, *after, *limit)?,
        ),
        Query::Seed { session, claim } => {
            Value::Seed(store.search_download_seed(*session, *claim)?)
        }
    })
}
pub(super) async fn process(
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
) -> Result<Response, PersistenceError> {
    let Command::SearchRead(query) = std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    let lease = request.permit.transfer_bytes(query.bytes())?;
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::SearchRead(query),
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    let DbResponse::SearchRead(value) = receive.await.map_err(|_| PersistenceError::Worker)??
    else {
        return Err(PersistenceError::Worker);
    };
    Ok(Response::SearchRead(crate::LibraryReply { value, lease }))
}
#[cfg(test)]
mod tests;
