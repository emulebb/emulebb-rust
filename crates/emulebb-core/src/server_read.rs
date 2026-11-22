//! Admitted server catalog reads; runtime connection presentation is separate.
use anyhow::Result;
use emulebb_metadata::{
    MetadataServerPage, MetadataServerQuery, MetadataServerReadError, MetadataServerRecord,
};

use crate::{EmulebbCore, LocalMutationError, PersistenceError, RetainedRead};

/// Saved server identity and its current connection presentation.
#[derive(Debug, serde::Serialize)]
pub struct ServerResource {
    pub id: String,
    #[serde(flatten)]
    pub server: crate::ServerInfo,
}

/// One bounded catalog page, independent of configured runtime lists.
pub struct ServerResourcePage {
    pub servers: Vec<ServerResource>,
    pub next_after_id: Option<i64>,
    pub has_more: bool,
    pub total: Option<u64>,
}

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
    fn present_server_record(
        &self,
        record: MetadataServerRecord,
        connected: Option<&str>,
        connecting: Option<&str>,
        details: &crate::views::ServerLiveDetails,
    ) -> ServerResource {
        let mut server = crate::profile_state::server_from_metadata(record.server);
        crate::views::apply_server_connection_flags(&mut server, connected, connecting);
        if server.current {
            crate::views::apply_server_live_details(&mut server, details);
        }
        self.apply_hostname_to_server(&mut server);
        ServerResource {
            id: record.id.to_string(),
            server,
        }
    }

    /// Present only the admitted page; projection backing has its own allowance.
    pub async fn server_resource_page(
        &self,
        query: MetadataServerQuery,
    ) -> Result<RetainedRead<ServerResourcePage>> {
        self.server_page(query)
            .await?
            .try_project_async(
                2 * emulebb_metadata::SERVER_READ_MAX_BYTES,
                |page| async move {
                    let connection = self.ed2k_server_connection_view().await;
                    Ok(ServerResourcePage {
                        servers: page
                            .servers
                            .into_iter()
                            .map(|record| {
                                self.present_server_record(
                                    record,
                                    connection.0.as_deref(),
                                    connection.1.as_deref(),
                                    &connection.2,
                                )
                            })
                            .collect(),
                        next_after_id: page.next_after_id,
                        has_more: page.has_more,
                        total: page.total,
                    })
                },
            )
            .await
    }

    /// Present one live immutable ID without materializing the whole catalog.
    pub async fn server_resource(&self, id: i64) -> Result<Option<RetainedRead<ServerResource>>> {
        let Some(record) = self.server_by_id(id).await? else {
            return Ok(None);
        };
        record
            .try_project_async(
                2 * emulebb_metadata::SERVER_READ_MAX_BYTES,
                |record| async move {
                    let connection = self.ed2k_server_connection_view().await;
                    Ok(self.present_server_record(
                        record,
                        connection.0.as_deref(),
                        connection.1.as_deref(),
                        &connection.2,
                    ))
                },
            )
            .await
            .map(Some)
    }

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
