//! Admitted server catalog reads; runtime connection presentation is separate.
use anyhow::Result;
use emulebb_metadata::{
    MetadataServerPage, MetadataServerQuery, MetadataServerReadError, MetadataServerRecord,
};

use crate::{EmulebbCore, LocalMutationError, PersistenceError, RetainedRead};

fn read_error(error: anyhow::Error) -> anyhow::Error {
    match error.downcast_ref::<MetadataServerReadError>() {
        Some(MetadataServerReadError::InvalidQuery) => return error,
        Some(MetadataServerReadError::RowTooLarge) => return PersistenceError::TooLarge.into(),
        None => {}
    }
    if error.is::<LocalMutationError>() || error.is::<PersistenceError>() {
        return error;
    }
    tracing::warn!(%error,"server metadata read failed");
    PersistenceError::Storage("server metadata read failed".into()).into()
}

impl EmulebbCore {
    /// Fetch one persisted page without walking configured or cached server lists.
    /// Backing keeps the Native read allowance until conversion or final drop.
    pub async fn server_page(
        &self,
        query: MetadataServerQuery,
    ) -> Result<RetainedRead<MetadataServerPage>> {
        self.persistence_owner.check_coherent_state()?;
        let page = self
            .ed2k_transfers
            .server_page(query)
            .await
            .map_err(read_error)?;
        self.persistence_owner.check_coherent_state()?;
        Ok(page)
    }

    /// Storage/admission failures remain errors; only an absent live ID is None.
    pub async fn server_by_id(
        &self,
        id: i64,
    ) -> Result<Option<RetainedRead<MetadataServerRecord>>> {
        self.persistence_owner.check_coherent_state()?;
        let server = self
            .ed2k_transfers
            .server_by_id(id)
            .await
            .map_err(read_error)?;
        self.persistence_owner.check_coherent_state()?;
        Ok(server)
    }
}
