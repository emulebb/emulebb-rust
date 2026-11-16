//! Serialized Kad routing operations on the shared persistence coordinator.

use super::*;

pub(super) async fn process_runtime(
    db: &mpsc::SyncSender<DbRequest>,
    request: &mut Request,
    kad_runtime: &mut Option<KadRuntime>,
) -> Result<Response, PersistenceError> {
    if matches!(
        &request.command,
        Command::KadAttach(_) | Command::KadCheckpoint { .. } | Command::KadImport { .. }
    ) {
        let command = std::mem::replace(&mut request.command, Command::KadLoad);
        match command {
            Command::KadAttach(dht) => {
                if kad_runtime
                    .as_ref()
                    .is_some_and(|runtime| !runtime.finished)
                {
                    return Err(PersistenceError::Busy);
                }
                let (response, receive) = oneshot::channel();
                db.send(DbRequest {
                    command: DbCommand::KadLoad,
                    response,
                })
                .map_err(|_| PersistenceError::Worker)?;
                let DbResponse::KadLoaded(saved) =
                    receive.await.map_err(|_| PersistenceError::Worker)??
                else {
                    return Err(PersistenceError::Worker);
                };
                let mut records = Vec::with_capacity(saved.contacts.len());
                if records.capacity() > KAD_RESERVED_CAPACITY {
                    return Err(PersistenceError::TooLarge);
                }
                records.extend(saved.contacts.iter().map(kad_persistence::from_metadata));
                let outcome = dht
                    .restore_routing_snapshot(&records, std::time::SystemTime::now())
                    .await
                    .map_err(|_| PersistenceError::Storage("invalid Kad routing state".into()))?;
                drop(records);
                let baseline = if outcome.expired == 0 && outcome.rejected == 0 {
                    let projection = dht
                        .capture_routing_projection()
                        .await
                        .map_err(|_| PersistenceError::Worker)?;
                    let bytes = projection
                        .keys
                        .capacity()
                        .checked_mul(std::mem::size_of::<emulebb_kad_dht::RoutingKeyProjection>())
                        .ok_or(PersistenceError::TooLarge)?;
                    Some((projection, request.permit.transfer_bytes(bytes)?))
                } else {
                    None
                };
                *kad_runtime = Some(KadRuntime {
                    instance: dht.instance(),
                    dht: Some(dht),
                    revision: saved.revision,
                    finished: false,
                    baseline,
                });
                let (handoff, accepted) = oneshot::channel();
                request.handoff = Some(accepted);
                return Ok(Response::KadAttached(KadAttachGuard(Some(handoff))));
            }
            Command::KadCheckpoint {
                dht,
                final_snapshot,
            } => {
                let runtime = kad_runtime.as_mut().ok_or(PersistenceError::Closing)?;
                if !runtime.instance.matches(&dht) {
                    return Err(PersistenceError::Closing);
                }
                if runtime.finished {
                    return Ok(Response::KadCheckpointed);
                }
                if final_snapshot {
                    dht.seal_persistence().await;
                }
                let projection = dht
                    .capture_routing_projection()
                    .await
                    .map_err(|_| PersistenceError::Worker)?;
                if let Some((baseline, _)) = &mut runtime.baseline {
                    if !projection.differs_from(baseline) {
                        baseline.token = projection.token;
                        if final_snapshot {
                            runtime.finished = true;
                            runtime.baseline = None;
                            runtime.dht = None;
                        }
                        return Ok(Response::KadCheckpointed);
                    }
                }
                drop(projection);
                let (projection, records) = dht
                    .capture_routing_bundle()
                    .await
                    .map_err(|_| PersistenceError::Worker)?;
                let mut contacts = Vec::with_capacity(records.len());
                if contacts.capacity() > KAD_RESERVED_CAPACITY {
                    return Err(PersistenceError::TooLarge);
                }
                contacts.extend(records.iter().map(kad_persistence::to_metadata));
                drop(records);
                let (response, receive) = oneshot::channel();
                db.send(DbRequest {
                    command: DbCommand::KadReplace {
                        expected_revision: runtime.revision,
                        contacts,
                    },
                    response,
                })
                .map_err(|_| PersistenceError::Worker)?;
                let DbResponse::KadReplaced(revision) = receive
                    .await
                    .map_err(|_| PersistenceError::CommitUnknown)??
                else {
                    return Err(PersistenceError::Worker);
                };
                runtime.revision = revision
                    .ok_or_else(|| PersistenceError::Storage("Kad revision conflict".into()))?;
                let bytes = projection
                    .keys
                    .capacity()
                    .checked_mul(std::mem::size_of::<emulebb_kad_dht::RoutingKeyProjection>())
                    .ok_or(PersistenceError::TooLarge)?;
                let lease = request.permit.transfer_bytes(bytes)?;
                runtime.baseline = Some((projection, lease));
                if final_snapshot {
                    runtime.finished = true;
                    runtime.baseline = None;
                    runtime.dht = None;
                }
                return Ok(Response::KadCheckpointed);
            }
            Command::KadImport {
                input,
                pending_only,
            } => {
                let identity = if let Some(runtime) =
                    kad_runtime.as_ref().filter(|runtime| !runtime.finished)
                {
                    KadNodeId::try_from(
                        runtime
                            .dht
                            .as_ref()
                            .ok_or(PersistenceError::Closing)?
                            .own_id()
                            .0,
                    )
                    .map_err(|_| PersistenceError::Worker)?
                } else {
                    let (response, receive) = oneshot::channel();
                    db.send(DbRequest {
                        command: DbCommand::KadIdentity,
                        response,
                    })
                    .map_err(|_| PersistenceError::Worker)?;
                    let DbResponse::KadIdentity(identity) = receive
                        .await
                        .map_err(|_| PersistenceError::CommitUnknown)??
                    else {
                        return Err(PersistenceError::Worker);
                    };
                    identity
                };
                let (response, receive) = oneshot::channel();
                db.send(DbRequest {
                    command: DbCommand::KadLoad,
                    response,
                })
                .map_err(|_| PersistenceError::Worker)?;
                let DbResponse::KadLoaded(saved) =
                    receive.await.map_err(|_| PersistenceError::Worker)??
                else {
                    return Err(PersistenceError::Worker);
                };
                if pending_only
                    && saved.initialization
                        == emulebb_metadata::DiscoveryInitializationStatus::Initialized
                {
                    return Ok(Response::KadImported(Ok(0)));
                }
                let revision = saved.revision;
                let seed = if let Some(runtime) =
                    kad_runtime.as_ref().filter(|runtime| !runtime.finished)
                {
                    let (_, current) = runtime
                        .dht
                        .as_ref()
                        .ok_or(PersistenceError::Closing)?
                        .capture_routing_bundle()
                        .await
                        .map_err(|_| PersistenceError::Worker)?;
                    current
                } else {
                    let mut records = Vec::with_capacity(saved.contacts.len());
                    if records.capacity() > KAD_RESERVED_CAPACITY {
                        return Err(PersistenceError::TooLarge);
                    }
                    records.extend(saved.contacts.iter().map(kad_persistence::from_metadata));
                    records
                };
                drop(saved);
                let (response, receive) = oneshot::channel();
                db.send(DbRequest {
                    command: DbCommand::KadMerge {
                        input,
                        seed,
                        identity,
                        revision,
                        pending_only,
                    },
                    response,
                })
                .map_err(|_| PersistenceError::Worker)?;
                let DbResponse::KadMerged(outcome) = receive
                    .await
                    .map_err(|_| PersistenceError::CommitUnknown)??
                else {
                    return Err(PersistenceError::Worker);
                };
                let (updated, accepted, records) = match outcome {
                    KadMergeOutcome::Invalid(error) => {
                        return Ok(Response::KadImported(Err(error)));
                    }
                    KadMergeOutcome::Conflict | KadMergeOutcome::NoAccepted => {
                        return Ok(Response::KadImported(Ok(0)));
                    }
                    KadMergeOutcome::Applied {
                        revision,
                        accepted,
                        records,
                    } => (revision, accepted, records),
                };
                if let Some(runtime) = kad_runtime.as_mut().filter(|runtime| !runtime.finished) {
                    let published = runtime
                        .dht
                        .as_ref()
                        .ok_or(PersistenceError::Closing)?
                        .restore_routing_snapshot(&records, std::time::SystemTime::now())
                        .await
                        .map_err(|_| PersistenceError::CommitUnknown)?;
                    tracing::debug!(
                        applied = published.accepted,
                        rejected = published.rejected,
                        "Kad source delta published to live routing"
                    );
                    runtime.revision = updated;
                    runtime.baseline = None;
                }
                return Ok(Response::KadImported(Ok(accepted)));
            }
            _ => unreachable!(),
        }
    }
    Err(PersistenceError::Worker)
}

pub(super) fn merge_in_worker(
    store: &MetadataStore,
    mut input: KadInput,
    seed: Vec<RoutingSnapshotContact>,
    identity: KadNodeId,
    revision: i64,
    pending_only: bool,
    #[cfg(test)] worker_started: &tokio::sync::Notify,
) -> Result<KadMergeOutcome, PersistenceError> {
    let mut table = emulebb_kad_routing::RoutingTable::new(emulebb_kad_proto::NodeId::from_bytes(
        *identity.as_bytes(),
    ));
    for record in &seed {
        let contact = emulebb_kad_routing::Contact::try_from(record)
            .map_err(|_| PersistenceError::Storage("invalid Kad routing state".into()))?;
        if !contact
            .expires_at
            .is_some_and(|expiry| expiry <= std::time::SystemTime::now())
        {
            if !table.merge_restored_contact(contact).unwrap_or(false) {
                return Err(PersistenceError::Storage(
                    "saved Kad contacts could not be re-admitted".into(),
                ));
            }
        }
    }
    drop(seed);
    let mut source_ids = std::collections::HashSet::with_capacity(KAD_ROUTING_MAX_CONTACTS);
    if source_ids.capacity() > KAD_RESERVED_CAPACITY {
        return Err(PersistenceError::TooLarge);
    }
    let mut observed_accepted = 0usize;
    let mut rejected = 0usize;
    let parsed = emulebb_kad_dht::bootstrap::visit_nodes_dat(&input.bytes, |entry| {
        if entry.node_id == emulebb_kad_proto::NodeId::ZERO
            || entry.node_id.0 == *identity.as_bytes()
        {
            rejected += 1;
            return;
        }
        let mut contact = emulebb_kad_routing::Contact::new(
            entry.node_id,
            entry.ip,
            entry.udp_port,
            entry.tcp_port,
            entry.version,
        );
        contact.udp_key = entry.udp_key;
        contact.udp_key_ip = entry.udp_key_ip;
        contact.verified = entry.verified;
        if table
            .merge_restored_contact(contact)
            .is_ok_and(|accepted| accepted)
        {
            observed_accepted += 1;
            if source_ids.len() == KAD_ROUTING_MAX_CONTACTS {
                source_ids.retain(|id| table.get(id).is_some());
            }
            source_ids.insert(entry.node_id);
        } else {
            rejected += 1;
        }
    });
    // WHY: release the body first but retain its byte lease while the worker
    // materializes and commits the simultaneous routing/output buffers.
    input.bytes = Vec::new();
    let declared = match parsed {
        Ok(count) => count,
        Err(_) => {
            return Ok(KadMergeOutcome::Invalid("invalid nodes.dat source".into()));
        }
    };
    if observed_accepted == 0 {
        return Ok(KadMergeOutcome::NoAccepted);
    }
    let scratch_bytes = table.owned_bytes();
    if scratch_bytes > kad_scratch_tree_bound()? {
        return Err(PersistenceError::TooLarge);
    }
    tracing::info!(
        declared,
        observed_accepted,
        rejected,
        filtered = declared.saturating_sub(observed_accepted + rejected),
        retained = table.len(),
        scratch_bytes,
        "Kad source routing admission completed"
    );
    let mut contacts = Vec::with_capacity(table.len());
    let mut records = Vec::with_capacity(table.len());
    if records.capacity() > KAD_RESERVED_CAPACITY || contacts.capacity() > KAD_RESERVED_CAPACITY {
        return Err(PersistenceError::TooLarge);
    }
    let mut invalid = false;
    table.visit_contacts(|contact| match RoutingSnapshotContact::try_from(contact) {
        Ok(record) => {
            contacts.push(kad_persistence::to_metadata(&record));
            if source_ids.contains(&contact.id) {
                records.push(record);
            }
        }
        Err(_) => invalid = true,
    });
    drop(table);
    drop(source_ids);
    if invalid {
        return Err(PersistenceError::Storage(
            "invalid Kad routing state".into(),
        ));
    }
    let accepted = records.len();
    #[cfg(test)]
    worker_started.notify_one();
    let revision = store
        .replace_kad_routing_snapshot(revision, pending_only, &contacts)
        .map_err(|_| PersistenceError::Storage("database operation failed".into()))?;
    drop(contacts);
    drop(input);
    match revision {
        Some(revision) => Ok(KadMergeOutcome::Applied {
            revision,
            accepted,
            records,
        }),
        None => Ok(KadMergeOutcome::Conflict),
    }
}

impl PersistenceOwner {
    pub(crate) fn reserve_kad_ingress(&self) -> Result<KadImportReservation, PersistenceError> {
        let admission = self
            .admission
            .lock()
            .map_err(|_| PersistenceError::Worker)?;
        let mut quota = admission
            .quota
            .lock()
            .map_err(|_| PersistenceError::Worker)?;
        if admission.sender.is_none() || admission.stopping {
            return Err(PersistenceError::Closing);
        }
        let bytes = quota
            .bytes
            .checked_add(KAD_INGRESS_PREPARATION_BYTES)
            .ok_or(PersistenceError::Busy)?;
        if bytes > MAX_BYTES {
            return Err(PersistenceError::Busy);
        }
        quota.bytes = bytes;
        Ok(KadImportReservation {
            lease: ByteLease {
                quota: Arc::clone(&admission.quota),
                bytes: KAD_INGRESS_PREPARATION_BYTES,
            },
            cancellation: admission.cancel_ingress.clone(),
        })
    }

    pub(crate) async fn load_or_create_kad_node_id(&self) -> Result<KadNodeId, PersistenceError> {
        match self
            .submit_reserved(FIXED_CHARGE, || Ok(Command::KadIdentity))
            .await?
        {
            Response::KadIdentity(id) => Ok(id),
            _ => Err(PersistenceError::Worker),
        }
    }

    pub(crate) async fn attach_kad(
        &self,
        dht: &DhtNode,
    ) -> Result<KadAttachGuard, PersistenceError> {
        match self
            .submit_reserved(kad_runtime_charge()?, || {
                Ok(Command::KadAttach(dht.clone()))
            })
            .await?
        {
            Response::KadAttached(handoff) => Ok(handoff),
            _ => Err(PersistenceError::Worker),
        }
    }

    pub(crate) async fn checkpoint_kad(
        &self,
        dht: &DhtNode,
        final_snapshot: bool,
    ) -> Result<(), PersistenceError> {
        match self
            .submit_reserved_inner(kad_runtime_charge()?, final_snapshot, || {
                Ok(Command::KadCheckpoint {
                    dht: dht.clone(),
                    final_snapshot,
                })
            })
            .await?
        {
            Response::KadCheckpointed => Ok(()),
            _ => Err(PersistenceError::Worker),
        }
    }

    pub(crate) async fn finish_kad(&self, dht: &DhtNode) -> Result<(), PersistenceError> {
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
            match self.checkpoint_kad(dht, true).await {
                Err(PersistenceError::Busy) => notified.await,
                other => return other,
            }
        }
    }

    pub(crate) async fn import_kad_owned(
        &self,
        bytes: Vec<u8>,
        pending_only: bool,
        reservation: KadImportReservation,
    ) -> Result<Result<usize, String>, PersistenceError> {
        let input = KadInput {
            bytes,
            _ingress: reservation.lease,
        };
        if input.bytes.len() > crate::NODES_DAT_MAX_BYTES
            || input.bytes.capacity() > crate::NODES_DAT_MAX_BYTES
        {
            return Err(PersistenceError::TooLarge);
        }
        {
            let admission = self
                .admission
                .lock()
                .map_err(|_| PersistenceError::Worker)?;
            if !Arc::ptr_eq(&admission.quota, &input._ingress.quota) {
                return Err(PersistenceError::Worker);
            }
        }
        let charge = kad_import_charge()?
            .checked_sub(crate::NODES_DAT_MAX_BYTES)
            .ok_or(PersistenceError::Worker)?;
        match self
            .submit_reserved(charge, || {
                Ok(Command::KadImport {
                    input,
                    pending_only,
                })
            })
            .await?
        {
            Response::KadImported(result) => Ok(result),
            _ => Err(PersistenceError::Worker),
        }
    }

    pub(crate) async fn load_kad(&self) -> Result<LeasedKadSnapshot, PersistenceError> {
        match self
            .submit_reserved(kad_charge()?, || Ok(Command::KadLoad))
            .await?
        {
            Response::KadLoaded(snapshot) => Ok(snapshot),
            _ => Err(PersistenceError::Worker),
        }
    }
}

pub(super) fn kad_charge() -> Result<usize, PersistenceError> {
    KAD_RESERVED_CAPACITY
        .checked_mul(std::mem::size_of::<KadRoutingContact>())
        .and_then(|bytes| bytes.checked_add(FIXED_CHARGE))
        .ok_or(PersistenceError::TooLarge)
}

pub(super) fn kad_runtime_charge() -> Result<usize, PersistenceError> {
    let per_contact = std::mem::size_of::<KadRoutingContact>()
        + std::mem::size_of::<RoutingSnapshotContact>()
        + std::mem::size_of::<emulebb_kad_routing::Contact>()
        + 2 * std::mem::size_of::<emulebb_kad_dht::RoutingKeyProjection>()
        + std::mem::size_of::<(std::net::Ipv4Addr, Option<u32>)>()
        + 4 * std::mem::size_of::<emulebb_kad_proto::NodeId>();
    KAD_RESERVED_CAPACITY
        .checked_mul(per_contact)
        .and_then(|bytes| bytes.checked_add(FIXED_CHARGE))
        .ok_or(PersistenceError::TooLarge)
}

pub(super) fn kad_scratch_tree_bound() -> Result<usize, PersistenceError> {
    // WHY: can_split bounds internal nodes: all nodes below KBASE, then at
    // most KK nodes at each remaining depth. Each leaf has at most K contacts.
    let splits = (1usize << emulebb_kad_proto::KBASE) - 1
        + emulebb_kad_proto::KK * (127 - emulebb_kad_proto::KBASE);
    let zones = 1 + 2 * splits;
    let leaves = 1 + splits;
    zones
        .checked_mul(std::mem::size_of::<emulebb_kad_routing::RoutingZone>())
        .and_then(|n| {
            n.checked_add(
                (leaves + 3)
                    * emulebb_kad_proto::K.next_power_of_two()
                    * std::mem::size_of::<emulebb_kad_routing::Contact>(),
            )
        })
        .and_then(|n| {
            n.checked_add(
                2 * KAD_RESERVED_CAPACITY
                    * (std::mem::size_of::<(std::net::Ipv4Addr, usize)>()
                        + std::mem::size_of::<([u8; 3], usize)>()
                        + 2),
            )
        })
        .ok_or(PersistenceError::TooLarge)
}

pub(super) fn kad_import_charge() -> Result<usize, PersistenceError> {
    let tree = kad_scratch_tree_bound()?;
    let snapshot = KAD_RESERVED_CAPACITY
        .checked_mul(std::mem::size_of::<RoutingSnapshotContact>())
        .ok_or(PersistenceError::TooLarge)?;
    let loaded = KAD_RESERVED_CAPACITY
        .checked_mul(
            std::mem::size_of::<KadRoutingContact>()
                + std::mem::size_of::<emulebb_kad_dht::RoutingKeyProjection>()
                + std::mem::size_of::<(std::net::Ipv4Addr, Option<u32>)>(),
        )
        .ok_or(PersistenceError::TooLarge)?;
    let ids = 2usize
        .checked_mul(KAD_RESERVED_CAPACITY)
        .and_then(|n| n.checked_mul(std::mem::size_of::<emulebb_kad_proto::NodeId>() + 1))
        .ok_or(PersistenceError::TooLarge)?;
    let preparation = tree
        .max(loaded)
        .checked_add(snapshot)
        .and_then(|n| n.checked_add(ids))
        .and_then(|n| n.checked_add(crate::NODES_DAT_MAX_BYTES))
        .ok_or(PersistenceError::TooLarge)?;
    let publication = tree
        .checked_add(ids)
        .and_then(|n| n.checked_add(snapshot))
        .and_then(|n| {
            n.checked_add(KAD_RESERVED_CAPACITY * std::mem::size_of::<KadRoutingContact>())
        })
        .ok_or(PersistenceError::TooLarge)?;
    preparation
        .max(publication)
        .checked_add(FIXED_CHARGE)
        .ok_or(PersistenceError::TooLarge)
}
