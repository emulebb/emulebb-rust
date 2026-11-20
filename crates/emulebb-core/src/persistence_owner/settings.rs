//! Canonical settings share the profile queue, SQL worker and retained quota.
use super::*;
use crate::settings::{SettingsMutationError, SettingsSnapshot};
use emulebb_metadata::{MetadataAppSettings, MetadataSettingsWriteError};
use emulebb_settings::product::{
    MAX_SAVED_BYTES, SettingsApplicationPlan, SettingsApplicationStatus, SettingsEdit,
    SettingsError, SettingsPatch, SettingsRevision,
};

pub(super) const RESULT_BYTES: usize = 1024 * 1024;
pub(super) type Outcome = Result<crate::LibraryReply<SettingsSnapshot>, SettingsMutationError>;

pub(super) enum SettingsCommand {
    Read,
    Write(Box<SettingsUpdate>),
}
pub(super) struct SettingsUpdate {
    core: crate::EmulebbCore,
    patch: SettingsPatch,
}
pub(super) enum SqlCommand {
    Read,
    Write {
        expected: SettingsRevision,
        edit: Box<SettingsEdit>,
    },
}
impl SqlCommand {
    pub(super) fn writes(&self) -> bool {
        matches!(self, Self::Write { .. })
    }
}
pub(super) enum SqlOutcome {
    Read(MetadataAppSettings),
    Write(Result<MetadataAppSettings, SettingsMutationError>),
}

fn storage(error: anyhow::Error) -> PersistenceError {
    tracing::warn!(%error, "canonical settings persistence failed");
    PersistenceError::Storage("database operation failed".into())
}

pub(super) fn execute(
    store: &MetadataStore,
    command: &SqlCommand,
) -> Result<SqlOutcome, PersistenceError> {
    match command {
        SqlCommand::Read => store
            .load_app_settings()
            .map(SqlOutcome::Read)
            .map_err(storage),
        SqlCommand::Write { expected, edit } => {
            match store.compare_and_set_app_settings(*expected, edit) {
                Ok(value) => Ok(SqlOutcome::Write(Ok(value))),
                Err(error) => {
                    if let Some(domain) = error.downcast_ref::<MetadataSettingsWriteError>() {
                        return match domain {
                            MetadataSettingsWriteError::Conflict { actual } => {
                                Ok(SqlOutcome::Write(Err(SettingsMutationError::Conflict {
                                    actual: *actual,
                                })))
                            }
                            MetadataSettingsWriteError::CommitUncertain(_) => {
                                Err(PersistenceError::CommitUnknown)
                            }
                        };
                    }
                    if let Some(domain) = error.downcast_ref::<SettingsError>() {
                        return Ok(SqlOutcome::Write(Err(SettingsMutationError::Invalid(
                            domain.clone(),
                        ))));
                    }
                    Err(storage(error))
                }
            }
        }
    }
}

async fn sql(
    db: &mpsc::SyncSender<DbRequest>,
    command: SqlCommand,
) -> Result<SqlOutcome, PersistenceError> {
    let writing = command.writes();
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::Settings(command),
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    let result = receive.await.map_err(|_| {
        if writing {
            PersistenceError::CommitUnknown
        } else {
            PersistenceError::Worker
        }
    })??;
    match result {
        DbResponse::Settings(value) => Ok(*value),
        _ => Err(if writing {
            PersistenceError::CommitUnknown
        } else {
            PersistenceError::Worker
        }),
    }
}

impl PersistenceOwner {
    pub(crate) async fn read_settings(
        &self,
    ) -> Result<crate::LibraryReply<SettingsSnapshot>, PersistenceError> {
        match self
            .submit_reserved(FIXED_CHARGE + RESULT_BYTES + 2 * MAX_SAVED_BYTES, || {
                Ok(Command::Settings(SettingsCommand::Read))
            })
            .await?
        {
            Response::Settings(value) => (*value).map_err(|_| PersistenceError::Worker),
            _ => Err(PersistenceError::Worker),
        }
    }
    pub(crate) async fn write_settings(
        &self,
        core: &crate::EmulebbCore,
        patch: &SettingsPatch,
    ) -> Result<Outcome, PersistenceError> {
        let bytes = match patch.payload_bytes() {
            Ok(bytes) => bytes,
            Err(error) => return Ok(Err(SettingsMutationError::Invalid(error))),
        };
        let charge = bytes
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(FIXED_CHARGE + RESULT_BYTES + 4 * MAX_SAVED_BYTES))
            .ok_or(PersistenceError::TooLarge)?;
        match self
            .submit_reserved(charge, || {
                Ok(Command::Settings(SettingsCommand::Write(Box::new(
                    SettingsUpdate {
                        core: core.clone(),
                        patch: patch.clone(),
                    },
                ))))
            })
            .await?
        {
            Response::Settings(value) => Ok(*value),
            _ => Err(PersistenceError::Worker),
        }
    }
}

fn invalid(error: SettingsError) -> Result<Response, PersistenceError> {
    Ok(Response::Settings(Box::new(Err(
        SettingsMutationError::Invalid(error),
    ))))
}

pub(super) async fn process(
    state: &Arc<Mutex<CoreState>>,
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    let Command::Settings(command) = std::mem::replace(&mut request.command, Command::KadLoad)
    else {
        unreachable!()
    };
    let lease = request.permit.transfer_bytes(RESULT_BYTES)?;
    let SqlOutcome::Read(current) = sql(db, SqlCommand::Read).await? else {
        return Err(PersistenceError::Worker);
    };
    let admitted = state.lock().await.settings.clone();
    match command {
        SettingsCommand::Read => {
            let desired = current.saved.values();
            let application = SettingsApplicationStatus::new(
                desired.differing_keys(admitted.values()),
                admitted.application().failed().to_vec(),
            )
            .map_err(|_| PersistenceError::Worker)?;
            let value = SettingsSnapshot::new(current, admitted.values().clone(), application)
                .map_err(|_| PersistenceError::Worker)?;
            Ok(Response::Settings(Box::new(Ok(crate::LibraryReply {
                value,
                lease,
            }))))
        }
        SettingsCommand::Write(update) => {
            let SettingsUpdate { core, patch } = *update;
            let (expected, edit) = patch.into_parts();
            if current.revision != expected {
                return Ok(Response::Settings(Box::new(Err(
                    SettingsMutationError::Conflict {
                        actual: current.revision,
                    },
                ))));
            }
            let saved = match current.saved.edited(&edit) {
                Ok(value) => value,
                Err(error) => return invalid(error),
            };
            let revision = match expected.checked_next() {
                Ok(value) => value,
                Err(_) => {
                    return Ok(Response::Settings(Box::new(Err(
                        SettingsMutationError::RevisionExhausted,
                    ))));
                }
            };
            let plan = match SettingsApplicationPlan::new(admitted.values(), &saved.values()) {
                Ok(value) => value,
                Err(error) => return invalid(error),
            };
            let application =
                SettingsApplicationStatus::new(plan.pending_restart().to_vec(), Vec::new())
                    .map_err(|_| PersistenceError::Worker)?;
            let predicted = MetadataAppSettings { revision, saved };
            // Exact read sizing completes before SQL. A committed write never
            // waits for another response reservation or snapshot allocation check.
            let value = match SettingsSnapshot::new(
                predicted.clone(),
                plan.candidate().clone(),
                application.clone(),
            ) {
                Ok(value) => value,
                Err(error) => return invalid(error),
            };
            match sql(
                db,
                SqlCommand::Write {
                    expected,
                    edit: Box::new(edit),
                },
            )
            .await?
            {
                SqlOutcome::Write(Ok(committed)) if committed == predicted => {}
                SqlOutcome::Write(Err(error)) => {
                    return Ok(Response::Settings(Box::new(Err(error))));
                }
                _ => return Err(PersistenceError::CommitUnknown),
            }
            #[cfg(test)]
            let gate = publication_gate.lock().unwrap().clone();
            #[cfg(test)]
            if let Some(gate) = gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            if plan.candidate() != admitted.values() {
                core.apply_live_settings(plan.candidate()).await;
            }
            state
                .lock()
                .await
                .settings
                .publish(plan.candidate().clone(), application);
            Ok(Response::Settings(Box::new(Ok(crate::LibraryReply {
                value,
                lease,
            }))))
        }
    }
}

#[cfg(test)]
mod tests;
