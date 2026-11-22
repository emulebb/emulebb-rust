//! Retained ID-addressed server writes and derived connection-plan publication.
use super::*;
use crate::{EmulebbCore, server_list::ServerPlanPublisher};
use emulebb_metadata::{
    MetadataServer, MetadataServerCreate, MetadataServerImport, MetadataServerUpdate,
    ServerEndpointConflict,
};

pub(super) enum SqlCommand {
    Create(MetadataServerCreate),
    Import(MetadataServerImport),
    ImportMet(Vec<u8>),
    ReadImported(i64),
    Update(i64, MetadataServerUpdate),
    Delete(i64),
}

pub(super) struct ServerCommand {
    operation: SqlCommand,
    publisher: ServerPlanPublisher,
    _ingress: Option<ByteLease>,
}

pub(super) enum ServerWrite {
    Created(i64, MetadataServer),
    Imported(i64, MetadataServer),
    ImportedMet(Vec<i64>),
    ImportRejected(String),
    Updated(MetadataServer, MetadataServerUpdate),
    Deleted(String),
    Missing,
}

pub(super) enum ServerOutcome {
    Identity(i64),
    Imported(Result<usize, String>),
    Changed(bool),
}

fn readable_record(
    server: &MetadataServer,
    update: Option<&MetadataServerUpdate>,
) -> Result<(), PersistenceError> {
    let priority = update
        .and_then(|value| value.priority.as_deref())
        .unwrap_or(&server.server_priority);
    readable_payload(
        [
            server.address.len(),
            server.name.len(),
            server.description.len(),
            server.dynamic_host.len(),
            priority.len(),
            server.version.len(),
        ],
        server.auxiliary_ports.len(),
    )
}

fn readable_payload(
    strings: impl IntoIterator<Item = usize>,
    ports: usize,
) -> Result<(), PersistenceError> {
    let text = strings
        .into_iter()
        .try_fold(0usize, |sum, size| sum.checked_add(size))
        .and_then(|size| {
            ports
                .checked_mul(6)
                .and_then(|ports| size.checked_add(ports))
        })
        .and_then(|size| size.checked_mul(4))
        .and_then(|size| {
            size.checked_add(
                16 * 1024 + std::mem::size_of::<emulebb_metadata::MetadataServerRecord>(),
            )
        })
        .ok_or(PersistenceError::TooLarge)?;
    // WHY: a successful mutation must not create a resource its bounded point
    // reader cannot return. Check projected text/CSV backing before SQL commits.
    if text > emulebb_metadata::SERVER_READ_MAX_BYTES {
        return Err(PersistenceError::TooLarge);
    }
    Ok(())
}

fn charge(
    strings: impl IntoIterator<Item = usize>,
    extra: usize,
) -> Result<usize, PersistenceError> {
    strings
        .into_iter()
        .try_fold(extra, |bytes, size| {
            bytes.checked_add(size).ok_or(PersistenceError::TooLarge)
        })?
        .checked_mul(4)
        .and_then(|bytes| {
            bytes.checked_add(FIXED_CHARGE + 2 * emulebb_metadata::SERVER_READ_MAX_BYTES)
        })
        .ok_or(PersistenceError::TooLarge)
}

impl EmulebbCore {
    /// Create an unobserved server and publish derived runtime state.
    /// Explicit creation never merges into an existing live endpoint.
    pub async fn create_server_resource(
        &self,
        server: &MetadataServerCreate,
    ) -> anyhow::Result<i64> {
        crate::views::validate_server_priority(&server.priority)?;
        let lengths = [server.address.len(), server.priority.len()];
        readable_payload(lengths, 0)?;
        let bytes = charge(lengths, 0)?;
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        match owner
            .submit_reserved(bytes, || {
                Ok(Command::Servers(ServerCommand {
                    operation: SqlCommand::Create(server.clone()),
                    publisher: ServerPlanPublisher::new(self),
                    _ingress: None,
                }))
            })
            .await?
        {
            Response::Servers(Ok(ServerOutcome::Identity(id))) => Ok(id),
            Response::Servers(Err(error)) => Err(error.into()),
            _ => Err(PersistenceError::Worker.into()),
        }
    }

    /// Merge one import observation under the same retained publication fence.
    pub async fn import_server_resource(
        &self,
        server: &MetadataServerImport,
    ) -> anyhow::Result<i64> {
        let lengths = [
            server.address.len(),
            server.name.as_ref().map_or(0, String::len),
        ];
        readable_payload(lengths, 0)?;
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        match owner
            .submit_reserved(charge(lengths, 0)?, || {
                Ok(Command::Servers(ServerCommand {
                    operation: SqlCommand::Import(server.clone()),
                    publisher: ServerPlanPublisher::new(self),
                    _ingress: None,
                }))
            })
            .await?
        {
            Response::Servers(Ok(ServerOutcome::Identity(id))) => Ok(id),
            Response::Servers(Err(error)) => Err(error.into()),
            _ => Err(PersistenceError::Worker.into()),
        }
    }

    /// Save selected fields by durable ID, retaining ownership after disconnect.
    pub async fn update_server_resource(
        &self,
        id: i64,
        update: &MetadataServerUpdate,
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(id > 0, "invalid server ID");
        if let Some(priority) = update.priority.as_deref() {
            crate::views::validate_server_priority(priority)?;
        }
        let bytes = charge([update.priority.as_ref().map_or(0, String::len)], 0)?;
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        match owner
            .submit_reserved(bytes, || {
                Ok(Command::Servers(ServerCommand {
                    operation: SqlCommand::Update(id, update.clone()),
                    publisher: ServerPlanPublisher::new(self),
                    _ingress: None,
                }))
            })
            .await?
        {
            Response::Servers(Ok(ServerOutcome::Changed(found))) => Ok(found),
            Response::Servers(Err(error)) => Err(error.into()),
            _ => Err(PersistenceError::Worker.into()),
        }
    }

    /// Retire a saved server and remove it from current connection eligibility.
    pub async fn delete_server_resource(&self, id: i64) -> anyhow::Result<bool> {
        anyhow::ensure!(id > 0, "invalid server ID");
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        match owner
            .submit_reserved(charge([], 0)?, || {
                Ok(Command::Servers(ServerCommand {
                    operation: SqlCommand::Delete(id),
                    publisher: ServerPlanPublisher::new(self),
                    _ingress: None,
                }))
            })
            .await?
        {
            Response::Servers(Ok(ServerOutcome::Changed(found))) => Ok(found),
            Response::Servers(Err(error)) => Err(error.into()),
            _ => Err(PersistenceError::Worker.into()),
        }
    }
}

impl PersistenceOwner {
    pub(crate) async fn import_server_met_owned(
        &self,
        bytes: Vec<u8>,
        reservation: DiscoveryImportReservation,
        publisher: ServerPlanPublisher,
    ) -> Result<Result<usize, String>, PersistenceError> {
        if bytes.len() > crate::SERVER_MET_MAX_BYTES
            || bytes.capacity() > crate::SERVER_MET_MAX_BYTES
        {
            return Err(PersistenceError::TooLarge);
        }
        if reservation.payload_bytes != crate::SERVER_MET_MAX_BYTES
            || !Arc::ptr_eq(
                &self
                    .admission
                    .lock()
                    .map_err(|_| PersistenceError::Worker)?
                    .quota,
                &reservation.lease.quota,
            )
        {
            return Err(PersistenceError::Worker);
        }
        // One rich SQL read/publication pair plus the bounded document's decode
        // vector, strings and ID result, independent of existing catalog size.
        let charge = FIXED_CHARGE
            + 2 * emulebb_metadata::SERVER_READ_MAX_BYTES
            + 16 * crate::SERVER_MET_MAX_BYTES;
        match self
            .submit_reserved(charge, || {
                Ok(Command::Servers(ServerCommand {
                    operation: SqlCommand::ImportMet(bytes),
                    publisher,
                    _ingress: Some(reservation.lease),
                }))
            })
            .await?
        {
            Response::Servers(Ok(ServerOutcome::Imported(result))) => Ok(result),
            _ => Err(PersistenceError::Worker),
        }
    }
}

pub(super) fn execute(
    store: &MetadataStore,
    operation: SqlCommand,
) -> anyhow::Result<Result<ServerWrite, ServerEndpointConflict>> {
    match operation {
        SqlCommand::Create(server) => match store.create_server_resource(server) {
            Ok(record) => Ok(Ok(ServerWrite::Created(record.id, record.server))),
            Err(error) if error.is::<ServerEndpointConflict>() => Ok(Err(ServerEndpointConflict)),
            Err(error) => Err(error),
        },
        SqlCommand::Import(input) => {
            let record = store.import_server_resource(&input)?;
            Ok(Ok(ServerWrite::Imported(record.id, record.server)))
        }
        SqlCommand::ImportMet(bytes) => {
            let entries = match emulebb_ed2k::ed2k_server::parse_server_met(&bytes) {
                Ok(entries) if !entries.is_empty() => entries,
                Ok(_) => {
                    return Ok(Ok(ServerWrite::ImportRejected(
                        "server.met contains no usable records".into(),
                    )));
                }
                Err(error) => return Ok(Ok(ServerWrite::ImportRejected(error.to_string()))),
            };
            let ids = store.import_server_resources(entries.into_iter().map(|entry| {
                MetadataServerImport {
                    address: entry.ip.to_string(),
                    port: entry.port,
                    name: entry.name,
                }
            }))?;
            tracing::info!(accepted = ids.len(), "server.met import committed");
            Ok(Ok(ServerWrite::ImportedMet(ids)))
        }
        SqlCommand::ReadImported(id) => {
            let record = store
                .server_by_id(id)?
                .ok_or(PersistenceError::CommittedPublicationFailed)?;
            Ok(Ok(ServerWrite::Imported(record.id, record.server)))
        }
        SqlCommand::Update(id, update) => {
            let Some(record) = store.server_by_id(id)? else {
                return Ok(Ok(ServerWrite::Missing));
            };
            readable_record(&record.server, Some(&update))?;
            if !store.update_server_resource(id, &update)? {
                return Ok(Ok(ServerWrite::Missing));
            }
            Ok(Ok(ServerWrite::Updated(record.server, update)))
        }
        SqlCommand::Delete(id) => {
            let Some(record) = store.server_by_id(id)? else {
                return Ok(Ok(ServerWrite::Missing));
            };
            if !store.delete_server_resource(id)? {
                return Ok(Ok(ServerWrite::Missing));
            }
            Ok(Ok(ServerWrite::Deleted(record.server.endpoint())))
        }
    }
}

fn publish_imported(state: &mut CoreState, snapshot: MetadataServer) {
    let endpoint = snapshot.endpoint();
    let name = snapshot.name.clone();
    let server = state
        .servers
        .entry(endpoint.clone())
        .or_insert_with(|| profile_state::server_from_metadata(snapshot));
    // Import carries only a reported name; retain current controls
    // and health rather than publishing a stale whole-row snapshot.
    server.name = name;
    if server.enabled {
        state.disabled_servers.remove(&endpoint);
    } else {
        state.disabled_servers.insert(endpoint);
    }
}

pub(super) async fn process(
    state: &Arc<Mutex<CoreState>>,
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    let Command::Servers(command) = std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    // Share the same fence with protocol feedback and discovery writers so
    // no stale whole-record publication can overtake the SQL/cache window.
    let _mutation = command.publisher.lock_mutation().await;
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::Servers(command.operation),
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    let DbResponse::Servers(outcome) = receive
        .await
        .map_err(|_| PersistenceError::CommitUnknown)??
    else {
        return Err(PersistenceError::Worker);
    };
    let write = match outcome {
        Ok(ServerWrite::ImportRejected(error)) => {
            return Ok(Response::Servers(Ok(ServerOutcome::Imported(Err(error)))));
        }
        Ok(ServerWrite::Missing) => {
            return Ok(Response::Servers(Ok(ServerOutcome::Changed(false))));
        }
        Ok(write) => write,
        Err(error) => return Ok(Response::Servers(Err(error))),
    };
    #[cfg(test)]
    let gate = publication_gate.lock().unwrap().clone();
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    let write = match write {
        ServerWrite::ImportedMet(ids) => {
            let count = ids.len();
            for id in ids {
                let (response, receive) = oneshot::channel();
                db.send(DbRequest {
                    command: DbCommand::Servers(SqlCommand::ReadImported(id)),
                    response,
                })
                .map_err(|_| PersistenceError::CommittedPublicationFailed)?;
                let reply = receive
                    .await
                    .map_err(|_| PersistenceError::CommittedPublicationFailed)?
                    .map_err(|_| PersistenceError::CommittedPublicationFailed)?;
                let DbResponse::Servers(Ok(ServerWrite::Imported(_, snapshot))) = reply else {
                    return Err(PersistenceError::CommittedPublicationFailed);
                };
                publish_imported(&mut *state.lock().await, snapshot);
            }
            command
                .publisher
                .refresh()
                .await
                .map_err(|_| PersistenceError::CommittedPublicationFailed)?;
            return Ok(Response::Servers(Ok(ServerOutcome::Imported(Ok(count)))));
        }
        write => write,
    };
    let outcome = {
        let mut state = state.lock().await;
        match write {
            ServerWrite::Created(id, server) => {
                let endpoint = server.endpoint();
                if server.enabled {
                    state.disabled_servers.remove(&endpoint);
                } else {
                    state.disabled_servers.insert(endpoint.clone());
                }
                state.server_control_overrides.remove(&endpoint);
                state
                    .servers
                    .insert(endpoint, profile_state::server_from_metadata(server));
                ServerOutcome::Identity(id)
            }
            ServerWrite::Imported(id, snapshot) => {
                publish_imported(&mut state, snapshot);
                ServerOutcome::Identity(id)
            }
            ServerWrite::Updated(snapshot, update) => {
                let endpoint = snapshot.endpoint();
                // WHY: publish selected operator fields into the current cache,
                // preserving newer health observations from network feedback.
                let server = state
                    .servers
                    .entry(endpoint.clone())
                    .or_insert_with(|| profile_state::server_from_metadata(snapshot));
                if let Some(priority) = update.priority.as_ref() {
                    server.priority = priority.clone();
                }
                if let Some(static_server) = update.static_server {
                    server.static_server = static_server;
                }
                if let Some(enabled) = update.enabled {
                    server.enabled = enabled;
                }
                let enabled = server.enabled;
                if enabled {
                    state.disabled_servers.remove(&endpoint);
                } else {
                    state.disabled_servers.insert(endpoint.clone());
                }
                let overlay = state.server_control_overrides.entry(endpoint).or_default();
                if let Some(priority) = update.priority {
                    overlay.priority = Some(priority);
                }
                if let Some(static_server) = update.static_server {
                    overlay.static_server = Some(static_server);
                }
                if let Some(enabled) = update.enabled {
                    overlay.enabled = Some(enabled);
                }
                ServerOutcome::Changed(true)
            }
            ServerWrite::Deleted(endpoint) => {
                state.servers.remove(&endpoint);
                state.server_control_overrides.remove(&endpoint);
                state.disabled_servers.insert(endpoint);
                ServerOutcome::Changed(true)
            }
            ServerWrite::Missing | ServerWrite::ImportedMet(_) | ServerWrite::ImportRejected(_) => {
                unreachable!()
            }
        }
    };
    command
        .publisher
        .refresh()
        .await
        .map_err(|_| PersistenceError::CommittedPublicationFailed)?;
    Ok(Response::Servers(Ok(outcome)))
}

#[cfg(test)]
mod tests;
