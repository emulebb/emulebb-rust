//! Category mutations serialized with the profile persistence owner.
use super::*;
use crate::Category;
use emulebb_ed2k::ed2k_transfer::CategoryCacheMutation;
use emulebb_metadata::MetadataCategory;

pub(super) const CATEGORY_PROBE_BYTES: usize = 256 * 1024;

/// One bounded filesystem probe; its lease follows the actual blocking work.
pub(crate) struct CategoryProbeJob {
    pub candidate: emulebb_metadata::MetadataSharedCopyCandidate,
    pub lease: ByteLease,
    pub response: oneshot::Sender<(
        emulebb_metadata::MetadataSharedCopyCandidate,
        bool,
        ByteLease,
    )>,
}

pub(super) struct CategoryContinuation {
    sharing: CategorySharingContext,
    roots: Vec<RootMembershipScope>,
    lease: ByteLease,
    clean_epoch: Option<u64>,
}

#[derive(Clone)]
pub(super) enum RootMembershipScope {
    Path(std::path::PathBuf),
    Id(i64),
}

impl CategoryContinuation {
    pub(super) async fn run(
        self,
        db: mpsc::SyncSender<DbRequest>,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Result<(), PersistenceError> {
        let mut lease = self.lease;
        for root in self.roots {
            lease =
                reconcile_removed_root(&db, &self.sharing, root, lease, shutdown.clone()).await?;
        }
        if let Some(epoch) = self.clean_epoch {
            self.sharing
                .runtime
                .finish_scoped_root_publication(epoch)
                .await;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct CategorySharingContext {
    pub runtime: Arc<emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime>,
    pub incoming: Arc<std::path::PathBuf>,
    pub root_change: Arc<crate::shared_dir_monitor::RootChangeSignal>,
    pub probe_sender: std::sync::Weak<StdMutex<Option<async_mpsc::Sender<CategoryProbeJob>>>>,
}

pub(crate) enum CategoryCommand {
    CreateRoot {
        path: String,
        watch_enabled: bool,
        sharing: CategorySharingContext,
        reload: crate::shared_directories::ReloadReservation,
    },
    DeleteRoot {
        id: i64,
        sharing: CategorySharingContext,
    },
    CreateDownload(super::download_create::DownloadCreateCommand),
    PatchDownload(super::download_patch::DownloadPatchCommand),
    Create {
        value: Category,
        sharing: CategorySharingContext,
    },
    Update {
        id: i64,
        temp: Option<Option<String>>,
        destination: Option<Option<String>>,
        comment: Option<String>,
        sharing: CategorySharingContext,
    },
    Delete {
        id: i64,
        sharing: CategorySharingContext,
    },
    PatchRootWatch {
        id: i64,
        enabled: bool,
        sharing: CategorySharingContext,
    },
}

pub(super) enum CategoryDbCommand {
    CreateRoot(String, bool),
    DeleteRoot(i64),
    PatchRootWatch(i64, bool),
    PatchDownload {
        patch: emulebb_metadata::MetadataDownloadPatch,
        publication: emulebb_ed2k::ed2k_transfer::PreparedDownloadPatch,
        runtime: Arc<emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime>,
    },
    Create(Category, Arc<std::path::PathBuf>),
    Update(Category, Arc<std::path::PathBuf>),
    Delete(Category, Arc<std::path::PathBuf>, CategoryCacheMutation),
    RootPage {
        root: RootMembershipScope,
        after: i64,
    },
    NextCopy {
        hash: [u8; 16],
        after: i64,
    },
    MarkCopy(emulebb_metadata::MetadataSharedCopyCandidate),
    Partial([u8; 16]),
}

pub(super) enum CategoryWrite {
    RootCreated(Option<emulebb_metadata::MetadataLibraryRoot>),
    RootDeleted(emulebb_metadata::MetadataLibraryRootDelete),
    RootWatch(Option<emulebb_metadata::MetadataLibraryRoot>),
    DownloadPatched(
        Result<
            Option<emulebb_metadata::MetadataDownloadPatched>,
            emulebb_metadata::DownloadPatchError,
        >,
    ),
    Category(Option<MetadataCategory>),
    RootPage(Vec<(i64, [u8; 16])>),
    Copy(Option<emulebb_metadata::MetadataSharedCopyCandidate>),
    Marked(bool),
    Partial(Option<emulebb_metadata::MetadataPartialShare>),
}

fn metadata(category: &Category) -> MetadataCategory {
    MetadataCategory {
        id: category.id,
        name: category.name.clone(),
        temp_dir: category.temp_dir.clone(),
        destination_dir: category.destination_dir.clone(),
        comment: category.comment.clone(),
    }
}

pub(super) fn execute(
    store: &MetadataStore,
    command: CategoryDbCommand,
) -> anyhow::Result<CategoryWrite> {
    match command {
        CategoryDbCommand::CreateRoot(path, watch_enabled) => store
            .create_library_root(std::path::Path::new(&path), watch_enabled, true)
            .map(CategoryWrite::RootCreated),
        CategoryDbCommand::DeleteRoot(id) => store
            .delete_library_root(id)
            .map(CategoryWrite::RootDeleted),
        CategoryDbCommand::PatchRootWatch(id, enabled) => store
            .patch_library_root_watch(id, enabled)
            .map(CategoryWrite::RootWatch),
        CategoryDbCommand::PatchDownload {
            patch,
            publication,
            runtime,
        } => {
            let outcome = match store.patch_download_job(publication.token(), &patch) {
                Ok(outcome) => outcome,
                Err(error) => {
                    return match error.downcast::<emulebb_metadata::DownloadPatchError>() {
                        Ok(error) => Ok(CategoryWrite::DownloadPatched(Err(error))),
                        Err(error) => Err(error),
                    };
                }
            };
            if let Some(value) = &outcome {
                runtime
                    .publish_download_patch(publication, value)
                    .map_err(|_| PersistenceError::CommittedPublicationFailed)?;
            }
            Ok(CategoryWrite::DownloadPatched(Ok(outcome)))
        }
        CategoryDbCommand::Create(value, incoming) => store
            .create_category(
                &value.name,
                value.temp_dir.as_deref(),
                value.destination_dir.as_deref(),
                &value.comment,
                &incoming,
            )
            .map(|v| CategoryWrite::Category(Some(v))),
        CategoryDbCommand::Update(value, incoming) => {
            let value = metadata(&value);
            Ok(CategoryWrite::Category(
                store.update_category(&value, &incoming)?.then_some(value),
            ))
        }
        CategoryDbCommand::Delete(value, incoming, publication) => {
            let changed = store.delete_category(value.id, &incoming)?;
            if changed {
                publication
                    .publish()
                    .map_err(|_| PersistenceError::CommittedPublicationFailed)?;
            }
            Ok(CategoryWrite::Category(changed.then(|| metadata(&value))))
        }
        CategoryDbCommand::RootPage { root, after } => match root {
            RootMembershipScope::Path(path) => store.category_root_hash_page(&path, after, 128),
            RootMembershipScope::Id(id) => store.library_root_hash_page(id, after, 128),
        }
        .map(CategoryWrite::RootPage),
        CategoryDbCommand::NextCopy { hash, after } => store
            .next_shared_copy(&hex::encode(hash), after, 65_536)
            .map(CategoryWrite::Copy),
        CategoryDbCommand::MarkCopy(candidate) => match candidate.source_fingerprint {
            Some(fingerprint) => store
                .mark_session_verified_local_path(&candidate.source_path, &fingerprint)
                .map(CategoryWrite::Marked),
            None => Ok(CategoryWrite::Marked(false)),
        },
        CategoryDbCommand::Partial(hash) => store
            .partial_share_for_category_reconciliation(&hex::encode(hash))
            .map(CategoryWrite::Partial),
    }
}

fn category_bytes(value: &Category) -> usize {
    value
        .name
        .capacity()
        .saturating_add(value.comment.capacity())
        .saturating_add(value.temp_dir.as_ref().map_or(0, String::capacity))
        .saturating_add(value.destination_dir.as_ref().map_or(0, String::capacity))
}

impl CategoryCommand {
    fn bytes(&self) -> usize {
        match self {
            Self::CreateDownload(command) => command.bytes(),
            Self::PatchDownload(command) => command.bytes(),
            Self::Create { value, sharing } => {
                category_bytes(value).saturating_add(sharing.incoming.as_os_str().len())
            }
            Self::Update {
                temp,
                destination,
                comment,
                sharing,
                ..
            } => 0usize
                .saturating_add(
                    temp.as_ref()
                        .and_then(Option::as_ref)
                        .map_or(0, String::capacity),
                )
                .saturating_add(
                    destination
                        .as_ref()
                        .and_then(Option::as_ref)
                        .map_or(0, String::capacity),
                )
                .saturating_add(comment.as_ref().map_or(0, String::capacity))
                .saturating_add(sharing.incoming.as_os_str().len()),
            Self::Delete { sharing, .. } => sharing.incoming.as_os_str().len(),
            Self::PatchRootWatch { .. } | Self::DeleteRoot { .. } => 0,
            Self::CreateRoot { path, .. } => path.capacity(),
        }
    }
}

impl PersistenceOwner {
    pub(crate) async fn create_root(
        &self,
        path: String,
        watch_enabled: bool,
        core: &crate::EmulebbCore,
    ) -> Result<Option<emulebb_metadata::MetadataLibraryRoot>, PersistenceError> {
        let charge = path
            .capacity()
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(FIXED_CHARGE + CATEGORY_PROBE_BYTES))
            .ok_or(PersistenceError::TooLarge)?;
        match self
            .submit_reserved(charge, || {
                Ok(Command::Category(CategoryCommand::CreateRoot {
                    path,
                    watch_enabled,
                    sharing: core.category_sharing_context(),
                    reload: crate::shared_directories::reserve_root_reload(core)?,
                }))
            })
            .await?
        {
            Response::RootCreated(root) => Ok(root),
            _ => Err(PersistenceError::Worker),
        }
    }

    pub(crate) async fn delete_root(
        &self,
        id: i64,
        sharing: CategorySharingContext,
    ) -> Result<emulebb_metadata::MetadataLibraryRootDelete, PersistenceError> {
        const PUBLICATION_WORKSPACE: usize = 4 * 1024 * 1024;
        match self
            .submit_reserved(FIXED_CHARGE + PUBLICATION_WORKSPACE, || {
                Ok(Command::Category(CategoryCommand::DeleteRoot {
                    id,
                    sharing,
                }))
            })
            .await?
        {
            Response::RootDeleted(result) => Ok(result),
            _ => Err(PersistenceError::Worker),
        }
    }

    pub(crate) async fn patch_root_watch(
        &self,
        id: i64,
        enabled: bool,
        sharing: CategorySharingContext,
    ) -> Result<Option<emulebb_metadata::MetadataLibraryRoot>, PersistenceError> {
        // Reserve native path and publication workspace before committing the edit.
        let charge = FIXED_CHARGE + CATEGORY_PROBE_BYTES;
        match self
            .submit_reserved(charge, || {
                Ok(Command::Category(CategoryCommand::PatchRootWatch {
                    id,
                    enabled,
                    sharing,
                }))
            })
            .await?
        {
            Response::RootWatch(root) => Ok(root),
            _ => Err(PersistenceError::Worker),
        }
    }

    pub(crate) async fn category(
        &self,
        command: CategoryCommand,
    ) -> Result<Result<Option<Category>, CategoryNameConflict>, PersistenceError> {
        // Reserve the root-page, one bounded copy and partial-entry workspace
        // before admission; queued commands cannot strand a committed update.
        const PUBLICATION_WORKSPACE: usize = 4 * 1024 * 1024;
        let workspace = if matches!(
            &command,
            CategoryCommand::Delete { .. }
                | CategoryCommand::Update {
                    destination: Some(_),
                    ..
                }
        ) {
            PUBLICATION_WORKSPACE
        } else {
            0
        };
        let charge = command
            .bytes()
            .checked_mul(4)
            .and_then(|n| n.checked_add(FIXED_CHARGE + workspace))
            .ok_or(PersistenceError::TooLarge)?;
        match self
            .submit_reserved(charge, || Ok(Command::Category(command)))
            .await?
        {
            Response::Category(result) => Ok(result),
            _ => Err(PersistenceError::Worker),
        }
    }
}

pub(super) async fn process(
    state: &Arc<Mutex<CoreState>>,
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
    continuation: &mut Option<CategoryContinuation>,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> Result<Response, PersistenceError> {
    let command = std::mem::replace(&mut request.command, Command::KadLoad);
    let Command::Category(command) = command else {
        unreachable!()
    };
    let command = match command {
        CategoryCommand::CreateRoot {
            path,
            watch_enabled,
            sharing,
            reload,
        } => {
            let mutation = sharing
                .runtime
                .begin_category_root_mutation()
                .await
                .map_err(|_| PersistenceError::Worker)?;
            let (response, receive) = oneshot::channel();
            db.send(DbRequest {
                command: DbCommand::Category(CategoryDbCommand::CreateRoot(path, watch_enabled)),
                response,
            })
            .map_err(|_| PersistenceError::Worker)?;
            let DbResponse::Category(CategoryWrite::RootCreated(root)) = receive
                .await
                .map_err(|_| PersistenceError::CommitUnknown)??
            else {
                return Err(PersistenceError::Worker);
            };
            #[cfg(test)]
            {
                let gate = publication_gate.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.entered.notify_one();
                    gate.release.notified().await;
                }
            }
            if let Some(root) = &root {
                state
                    .lock()
                    .await
                    .shared_directories
                    .push(crate::SharedDirectoryRoot {
                        path: emulebb_metadata::NativePath::from(root.path.as_path())
                            .display_path(),
                        watch_enabled: root.watch_enabled,
                        monitor_owned: false,
                        shareable: root.shareable,
                        accessible: root.accessible,
                    });
                reload
                    .arm()
                    .map_err(|_| PersistenceError::CommittedPublicationFailed)?;
                sharing.root_change.watch_changed();
            }
            if let Some(epoch) = mutation.finish() {
                sharing.runtime.finish_scoped_root_publication(epoch).await;
            }
            return Ok(Response::RootCreated(root));
        }
        CategoryCommand::DeleteRoot { id, sharing } => {
            let mutation = sharing
                .runtime
                .begin_category_root_mutation()
                .await
                .map_err(|_| PersistenceError::Worker)?;
            let (response, receive) = oneshot::channel();
            db.send(DbRequest {
                command: DbCommand::Category(CategoryDbCommand::DeleteRoot(id)),
                response,
            })
            .map_err(|_| PersistenceError::Worker)?;
            let DbResponse::Category(CategoryWrite::RootDeleted(result)) = receive
                .await
                .map_err(|_| PersistenceError::CommitUnknown)??
            else {
                return Err(PersistenceError::Worker);
            };
            #[cfg(test)]
            {
                let gate = publication_gate.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.entered.notify_one();
                    gate.release.notified().await;
                }
            }
            if let emulebb_metadata::MetadataLibraryRootDelete::Deleted(root) = &result {
                let display =
                    emulebb_metadata::NativePath::from(root.path.as_path()).display_path();
                state
                    .lock()
                    .await
                    .shared_directories
                    .retain(|cached| cached.path != display);
                let clean_epoch = mutation.finish();
                sharing.root_change.watch_changed();
                let lease = request
                    .permit
                    .transfer_bytes(CATEGORY_PROBE_BYTES)
                    .map_err(|_| PersistenceError::CommittedPublicationFailed)?;
                *continuation = Some(CategoryContinuation {
                    sharing,
                    roots: vec![RootMembershipScope::Id(root.id)],
                    lease,
                    clean_epoch,
                });
            } else if let Some(epoch) = mutation.finish() {
                sharing.runtime.finish_scoped_root_publication(epoch).await;
            }
            return Ok(Response::RootDeleted(result));
        }
        CategoryCommand::PatchRootWatch {
            id,
            enabled,
            sharing,
        } => {
            let mutation = sharing
                .runtime
                .begin_category_root_mutation()
                .await
                .map_err(|_| PersistenceError::Worker)?;
            let (response, receive) = oneshot::channel();
            db.send(DbRequest {
                command: DbCommand::Category(CategoryDbCommand::PatchRootWatch(id, enabled)),
                response,
            })
            .map_err(|_| PersistenceError::Worker)?;
            let DbResponse::Category(CategoryWrite::RootWatch(root)) = receive
                .await
                .map_err(|_| PersistenceError::CommitUnknown)??
            else {
                return Err(PersistenceError::Worker);
            };
            #[cfg(test)]
            {
                let gate = publication_gate.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.entered.notify_one();
                    gate.release.notified().await;
                }
            }
            if let Some(root) = &root {
                let display =
                    emulebb_metadata::NativePath::from(root.path.as_path()).display_path();
                for cached in &mut state.lock().await.shared_directories {
                    if cached.path == display {
                        cached.watch_enabled = root.watch_enabled;
                    }
                }
                // WHY: a watch edit changes subscriptions only; it must not reserve
                // a catalog scan or disturb another root's cached health.
                sharing.root_change.watch_changed();
            }
            if let Some(epoch) = mutation.finish() {
                sharing.runtime.finish_scoped_root_publication(epoch).await;
            }
            return Ok(Response::RootWatch(root));
        }
        CategoryCommand::CreateDownload(command) => {
            return Ok(Response::DownloadCreated(
                super::download_create::process(
                    state,
                    command,
                    #[cfg(test)]
                    publication_gate,
                )
                .await,
            ));
        }
        CategoryCommand::PatchDownload(command) => {
            return super::download_patch::process(
                state,
                db,
                command,
                #[cfg(test)]
                publication_gate,
            )
            .await;
        }
        command => command,
    };
    let sharing = match &command {
        CategoryCommand::Create { sharing, .. }
        | CategoryCommand::Update { sharing, .. }
        | CategoryCommand::Delete { sharing, .. } => Some(sharing.clone()),
        CategoryCommand::PatchRootWatch { .. }
        | CategoryCommand::CreateRoot { .. }
        | CategoryCommand::DeleteRoot { .. } => {
            unreachable!()
        }
        CategoryCommand::PatchDownload(_) | CategoryCommand::CreateDownload(_) => None,
    };
    let mut publication = match &command {
        CategoryCommand::Delete { id, sharing } => {
            Some(sharing.runtime.prepare_category_removal(*id).await)
        }
        _ => None,
    }
    .transpose()
    .map_err(|error| {
        match error.downcast_ref::<emulebb_ed2k::ed2k_transfer::LocalMutationError>() {
            Some(emulebb_ed2k::ed2k_transfer::LocalMutationError::Busy) => PersistenceError::Busy,
            _ => PersistenceError::Worker,
        }
    })?;
    let _category_fence = publication
        .as_ref()
        .map(CategoryCacheMutation::retain_fence);
    let (prepared, deleting, old_root, root_changed) = {
        let state = state.lock().await;
        let (category, deleting, creating) = match command {
            CategoryCommand::Create { value, .. } => (value, false, true),
            CategoryCommand::Update {
                id,
                temp,
                destination,
                comment,
                ..
            } => {
                let Some(existing) = state.categories.get(&id) else {
                    return Ok(Response::Category(Ok(None)));
                };
                request.permit.extend(
                    category_bytes(existing)
                        .checked_mul(4)
                        .ok_or(PersistenceError::TooLarge)?,
                )?;
                let mut value = existing.clone();
                if let Some(temp) = temp {
                    value.temp_dir = temp;
                }
                if let Some(destination) = destination {
                    value.destination_dir = destination;
                }
                if let Some(comment) = comment {
                    value.comment = comment;
                }
                (value, false, false)
            }
            CategoryCommand::PatchDownload(_) | CategoryCommand::CreateDownload(_) => {
                unreachable!()
            }
            CategoryCommand::PatchRootWatch { .. }
            | CategoryCommand::CreateRoot { .. }
            | CategoryCommand::DeleteRoot { .. } => {
                unreachable!()
            }
            CategoryCommand::Delete { id, .. } => {
                let Some(existing) = state.categories.get(&id) else {
                    return Ok(Response::Category(Ok(None)));
                };
                request.permit.extend(
                    category_bytes(existing)
                        .checked_mul(4)
                        .ok_or(PersistenceError::TooLarge)?,
                )?;
                (existing.clone(), true, false)
            }
        };
        if !deleting
            && state.categories.values().any(|other| {
                !deleting
                    && other.id != category.id
                    && other.name.eq_ignore_ascii_case(&category.name)
            })
        {
            return Ok(Response::Category(Err(CategoryNameConflict)));
        }
        let previous_destination = if creating {
            None
        } else {
            state
                .categories
                .get(&category.id)
                .and_then(|value| value.destination_dir.as_ref())
                .cloned()
        };
        let root_changed = if deleting {
            previous_destination.is_some()
        } else {
            previous_destination != category.destination_dir
        };
        let old_root = if root_changed {
            previous_destination
        } else {
            None
        };
        let prepared = if creating {
            CategoryDbCommand::Create(
                category,
                sharing
                    .as_ref()
                    .expect("category sharing context")
                    .incoming
                    .clone(),
            )
        } else if deleting {
            CategoryDbCommand::Delete(
                category,
                sharing
                    .as_ref()
                    .expect("category sharing context")
                    .incoming
                    .clone(),
                publication.take().expect("prepared category removal"),
            )
        } else {
            CategoryDbCommand::Update(
                category,
                sharing
                    .as_ref()
                    .expect("category sharing context")
                    .incoming
                    .clone(),
            )
        };
        (prepared, deleting, old_root, root_changed)
    };
    let root_mutation = if root_changed {
        match sharing.as_ref() {
            Some(context) => Some(
                context
                    .runtime
                    .begin_category_root_mutation()
                    .await
                    .map_err(|_| PersistenceError::Worker)?,
            ),
            None => None,
        }
    } else {
        None
    };
    let (response, receive) = oneshot::channel();
    db.send(DbRequest {
        command: DbCommand::Category(prepared),
        response,
    })
    .map_err(|_| PersistenceError::Worker)?;
    let DbResponse::Category(CategoryWrite::Category(value)) = receive
        .await
        .map_err(|_| PersistenceError::CommitUnknown)??
    else {
        return Err(PersistenceError::Worker);
    };
    let Some(value) = value else {
        return Ok(Response::Category(Ok(None)));
    };
    let category = profile_state::category_from_metadata(value);
    let mut state = state.lock().await;
    if deleting {
        state.categories.remove(&category.id);
        for transfer in state.transfers.values_mut() {
            if transfer.category_id == Some(category.id) {
                transfer.category_id = None;
                transfer.category_name = None;
            }
        }
    } else {
        for transfer in state.transfers.values_mut() {
            if transfer.category_id == Some(category.id) {
                transfer.category_name = Some(category.name.clone());
            }
        }
        state.categories.insert(category.id, category.clone());
    }
    drop(state);
    let clean_epoch = root_mutation.and_then(|mutation| mutation.finish());
    drop(_category_fence);
    if let Some(sharing) = sharing
        && root_changed
    {
        sharing.root_change.scan_required();
        if let Some(old_root) = old_root {
            let lease = request
                .permit
                .transfer_bytes(CATEGORY_PROBE_BYTES)
                .map_err(|_| PersistenceError::CommittedPublicationFailed)?;
            *continuation = Some(CategoryContinuation {
                sharing,
                roots: vec![RootMembershipScope::Path(std::path::PathBuf::from(
                    old_root,
                ))],
                lease,
                clean_epoch,
            });
        } else if let Some(epoch) = clean_epoch {
            sharing.runtime.finish_scoped_root_publication(epoch).await;
        }
    }
    Ok(Response::Category(Ok(Some(category))))
}

async fn reconcile_removed_root(
    db: &mpsc::SyncSender<DbRequest>,
    sharing: &CategorySharingContext,
    root: RootMembershipScope,
    mut lease: ByteLease,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<ByteLease, PersistenceError> {
    let runtime = &sharing.runtime;
    let mut after = 0;
    loop {
        if shutdown.is_cancelled() {
            return Err(PersistenceError::Closing);
        }
        let (response, receive) = oneshot::channel();
        db.send(DbRequest {
            command: DbCommand::Category(CategoryDbCommand::RootPage {
                root: root.clone(),
                after,
            }),
            response,
        })
        .map_err(|_| PersistenceError::Worker)?;
        let DbResponse::Category(CategoryWrite::RootPage(page)) =
            receive.await.map_err(|_| PersistenceError::Worker)??
        else {
            return Err(PersistenceError::Worker);
        };
        if shutdown.is_cancelled() {
            return Err(PersistenceError::Closing);
        }
        if page.is_empty() {
            return Ok(lease);
        }
        for (cursor, hash) in page {
            after = cursor;
            loop {
                if shutdown.is_cancelled() {
                    return Err(PersistenceError::Closing);
                }
                let revision = runtime
                    .watch_category_catalog_hash(hash)
                    .await
                    .map_err(|_| PersistenceError::Worker)?;
                let mut cursor = 0;
                let decision = loop {
                    let (response, receive) = oneshot::channel();
                    db.send(DbRequest {
                        command: DbCommand::Category(CategoryDbCommand::NextCopy {
                            hash,
                            after: cursor,
                        }),
                        response,
                    })
                    .map_err(|_| PersistenceError::Worker)?;
                    let DbResponse::Category(CategoryWrite::Copy(candidate)) =
                        receive.await.map_err(|_| PersistenceError::Worker)??
                    else {
                        return Err(PersistenceError::Worker);
                    };
                    if shutdown.is_cancelled() {
                        return Err(PersistenceError::Closing);
                    }
                    let Some(candidate) = candidate else {
                        let (response, receive) = oneshot::channel();
                        db.send(DbRequest {
                            command: DbCommand::Category(CategoryDbCommand::Partial(hash)),
                            response,
                        })
                        .map_err(|_| PersistenceError::Worker)?;
                        let DbResponse::Category(CategoryWrite::Partial(partial)) =
                            receive.await.map_err(|_| PersistenceError::Worker)??
                        else {
                            return Err(PersistenceError::Worker);
                        };
                        if shutdown.is_cancelled() {
                            return Err(PersistenceError::Closing);
                        }
                        break match partial {
                            Some(partial) => {
                                emulebb_ed2k::ed2k_transfer::CategoryCatalogDecision::Partial(
                                    partial,
                                )
                            }
                            None => emulebb_ed2k::ed2k_transfer::CategoryCatalogDecision::Remove,
                        };
                    };
                    cursor = candidate.path_id;
                    let sender = sharing
                        .probe_sender
                        .upgrade()
                        .ok_or(PersistenceError::Worker)?;
                    let sender = sender
                        .lock()
                        .map_err(|_| PersistenceError::Worker)?
                        .clone()
                        .ok_or(PersistenceError::Worker)?;
                    let (response, receive) = oneshot::channel();
                    sender
                        .try_send(CategoryProbeJob {
                            candidate,
                            lease,
                            response,
                        })
                        .map_err(|_| PersistenceError::Worker)?;
                    let (candidate, matches, returned_lease) = tokio::select! {
                        result = receive => result.map_err(|_| PersistenceError::Worker)?,
                        _ = shutdown.cancelled() => return Err(PersistenceError::Closing),
                    };
                    lease = returned_lease;
                    if matches {
                        let (response, receive) = oneshot::channel();
                        db.send(DbRequest {
                            command: DbCommand::Category(CategoryDbCommand::MarkCopy(candidate)),
                            response,
                        })
                        .map_err(|_| PersistenceError::Worker)?;
                        let DbResponse::Category(CategoryWrite::Marked(marked)) =
                            receive.await.map_err(|_| PersistenceError::Worker)??
                        else {
                            return Err(PersistenceError::Worker);
                        };
                        if shutdown.is_cancelled() {
                            return Err(PersistenceError::Closing);
                        }
                        if marked {
                            break emulebb_ed2k::ed2k_transfer::CategoryCatalogDecision::Keep;
                        }
                    }
                };
                if shutdown.is_cancelled() {
                    return Err(PersistenceError::Closing);
                }
                if runtime
                    .publish_category_catalog_decision(hash, revision, decision)
                    .await
                    .map_err(|_| PersistenceError::Worker)?
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
    }
}
