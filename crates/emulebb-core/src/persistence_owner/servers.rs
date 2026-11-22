//! Retained ID-addressed server writes and derived connection-plan publication.
use super::*;
use crate::{EmulebbCore, server_list::ServerPlanPublisher};
use emulebb_metadata::{MetadataServer, MetadataServerUpdate, ServerEndpointConflict};

pub(super) enum SqlCommand {
    Create(Box<MetadataServer>),
    Update(i64, MetadataServerUpdate),
    Delete(i64),
}

pub(super) struct ServerCommand {
    operation: SqlCommand,
    publisher: ServerPlanPublisher,
}

pub(super) enum ServerWrite {
    Created(i64, MetadataServer),
    Updated(MetadataServer, MetadataServerUpdate),
    Deleted(String),
    Missing,
}

pub(super) enum ServerOutcome {
    Created(i64),
    Changed(bool),
}

fn readable_record(
    server: &MetadataServer,
    update: Option<&MetadataServerUpdate>,
) -> Result<(), PersistenceError> {
    let name = update
        .and_then(|value| value.name.as_deref())
        .unwrap_or(&server.name);
    let priority = update
        .and_then(|value| value.priority.as_deref())
        .unwrap_or(&server.server_priority);
    let text = [
        server.address.len(),
        name.len(),
        server.description.len(),
        server.dynamic_host.len(),
        priority.len(),
        server.version.len(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, size| sum.checked_add(size))
    .and_then(|size| {
        server
            .auxiliary_ports
            .len()
            .checked_mul(6)
            .and_then(|ports| size.checked_add(ports))
    })
    .and_then(|size| size.checked_mul(4))
    .and_then(|size| {
        size.checked_add(16 * 1024 + std::mem::size_of::<emulebb_metadata::MetadataServerRecord>())
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
    /// Persist a canonical server record and publish derived runtime state.
    /// Explicit creation never merges into an existing live endpoint.
    pub async fn create_server_resource(&self, server: &MetadataServer) -> anyhow::Result<i64> {
        crate::views::validate_server_priority(&server.server_priority)?;
        readable_record(server, None)?;
        let bytes = charge(
            [
                server.address.len(),
                server.name.len(),
                server.description.len(),
                server.dynamic_host.len(),
                server.server_priority.len(),
                server.version.len(),
            ],
            server
                .auxiliary_ports
                .len()
                .checked_mul(2)
                .ok_or(PersistenceError::TooLarge)?,
        )?;
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        match owner
            .submit_reserved(bytes, || {
                Ok(Command::Servers(ServerCommand {
                    operation: SqlCommand::Create(Box::new(server.clone())),
                    publisher: ServerPlanPublisher::new(self),
                }))
            })
            .await?
        {
            Response::Servers(Ok(ServerOutcome::Created(id))) => Ok(id),
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
        let bytes = charge(
            [
                update.name.as_ref().map_or(0, String::len),
                update.priority.as_ref().map_or(0, String::len),
            ],
            0,
        )?;
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        match owner
            .submit_reserved(bytes, || {
                Ok(Command::Servers(ServerCommand {
                    operation: SqlCommand::Update(id, update.clone()),
                    publisher: ServerPlanPublisher::new(self),
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

pub(super) fn execute(
    store: &MetadataStore,
    operation: SqlCommand,
) -> anyhow::Result<Result<ServerWrite, ServerEndpointConflict>> {
    match operation {
        SqlCommand::Create(server) => match store.create_server_resource(&server) {
            Ok(id) => Ok(Ok(ServerWrite::Created(id, *server))),
            Err(error) if error.is::<ServerEndpointConflict>() => Ok(Err(ServerEndpointConflict)),
            Err(error) => Err(error),
        },
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
                state.server_overrides.remove(&endpoint);
                state
                    .servers
                    .insert(endpoint, profile_state::server_from_metadata(server));
                ServerOutcome::Created(id)
            }
            ServerWrite::Updated(snapshot, update) => {
                let endpoint = snapshot.endpoint();
                // WHY: publish selected operator fields into the current cache,
                // preserving newer health observations from network feedback.
                let server = state
                    .servers
                    .entry(endpoint.clone())
                    .or_insert_with(|| profile_state::server_from_metadata(snapshot));
                if let Some(name) = update.name.as_ref() {
                    server.name = name.clone();
                }
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
                let overlay = state.server_overrides.entry(endpoint).or_default();
                if let Some(name) = update.name {
                    overlay.name = Some(name);
                }
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
                state.server_overrides.remove(&endpoint);
                state.disabled_servers.insert(endpoint);
                ServerOutcome::Changed(true)
            }
            ServerWrite::Missing => unreachable!(),
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
