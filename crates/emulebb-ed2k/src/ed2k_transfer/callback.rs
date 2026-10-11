//! LowID callback admission tickets and legacy intent bookkeeping.

use std::{
    collections::{HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use super::{
    ED2K_CALLBACK_TICKET_MAX_LIFETIME, Ed2kCallbackClaim, Ed2kCallbackClaimError,
    Ed2kCallbackClaimToken, Ed2kCallbackDispatchOutcome, Ed2kCallbackDispatchPermit,
    Ed2kCallbackDownload, Ed2kCallbackHelloIdentity, Ed2kCallbackIntent, Ed2kCallbackPeer,
    Ed2kCallbackReservation, Ed2kCallbackRoute, Ed2kCallbackTicketError, Ed2kCallbackTicketId,
    Ed2kCallbackTicketRequest, Ed2kTransferRuntime,
};

const CALLBACK_TICKET_CAPACITY: usize = 1_024;
const CALLBACK_TICKET_DOWNLOAD_CAPACITY: usize = 256;
const CALLBACK_CLAIM_DOWNLOAD_CAPACITY: usize = 256;
const CALLBACK_CLAIM_LEASE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallbackTicketState {
    Reserved,
    /// One linear dispatch guard owns the queued or in-progress wire request.
    /// The guard settles or rolls this state back synchronously on drop, so it
    /// must not be reaped at the reservation deadline while socket delivery is
    /// still being classified.
    Dispatching,
    Armed,
    Leased {
        generation: u64,
        lease_deadline: Instant,
        prior_state: CallbackTicketReadyState,
    },
    SessionOwned {
        generation: u64,
        prior_state: CallbackTicketReadyState,
    },
    /// A callback connection was consumed before these files could use it.
    /// The next matching scheduler reservation must originate a fresh callback.
    NeedsDispatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallbackTicketReadyState {
    Reserved,
    Dispatching,
    Armed,
}

impl From<CallbackTicketReadyState> for CallbackTicketState {
    fn from(state: CallbackTicketReadyState) -> Self {
        match state {
            CallbackTicketReadyState::Reserved => Self::Reserved,
            CallbackTicketReadyState::Dispatching => Self::Dispatching,
            CallbackTicketReadyState::Armed => Self::Armed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallbackTicketRecord {
    id: Ed2kCallbackTicketId,
    route: Ed2kCallbackRoute,
    peer: Ed2kCallbackPeer,
    downloads: Vec<Ed2kCallbackDownload>,
    expires_at: Instant,
    redispatch_lifetime: Duration,
    cancel_restores_needs_dispatch: bool,
    state: CallbackTicketState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallbackFallbackKey {
    Server {
        server_endpoint: SocketAddr,
        client_id: u32,
    },
    Endpoint {
        ip: Ipv4Addr,
        tcp_port: u16,
    },
}

#[derive(Debug)]
pub(super) struct CallbackTicketStore {
    next_ticket_id: u64,
    next_lease_generation: u64,
    ticket_capacity: usize,
    download_capacity: usize,
    tickets: VecDeque<CallbackTicketRecord>,
}

/// Cancellation-safe ownership of one callback request while its wire
/// delivery is queued or in progress.
///
/// Dispatching tickets remain claimable and cannot expire underneath the
/// socket write. Dropping this guard conservatively arms admission because an
/// aborted future cannot prove that delivery never began; explicit known-not-
/// sent cancellation remains available and consumes it exactly once.
#[derive(Debug)]
pub struct Ed2kCallbackDispatchGuard {
    store: Arc<StdMutex<CallbackTicketStore>>,
    permit: Option<Ed2kCallbackDispatchPermit>,
}

impl Ed2kCallbackDispatchGuard {
    /// Exact pre-dispatch deadline established by ticket reservation.
    pub fn expires_at(&self) -> Instant {
        self.permit
            .as_ref()
            .expect("live dispatch guard always owns a permit")
            .expires_at()
    }

    /// Arm the ticket after the request was sent or delivery became ambiguous.
    pub fn mark_dispatched(mut self) -> Ed2kCallbackDispatchOutcome {
        let permit = self
            .permit
            .take()
            .expect("live dispatch guard always owns a permit");
        self.store
            .lock()
            .unwrap()
            .mark_dispatched(permit, Instant::now())
    }

    /// Roll back the exact reservation after delivery was proven not to start.
    pub fn cancel(mut self) -> bool {
        let permit = self
            .permit
            .take()
            .expect("live dispatch guard always owns a permit");
        self.store.lock().unwrap().cancel(permit, Instant::now())
    }
}

impl Drop for Ed2kCallbackDispatchGuard {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let _ = self
            .store
            .lock()
            .unwrap()
            .mark_dispatched(permit, Instant::now());
    }
}

#[derive(Debug)]
struct CallbackSessionToken {
    generation: u64,
}

/// Exclusive ownership of one admitted callback peer's pending file set.
///
/// Dropping the guard after cancellation, panic, or an early protocol outcome
/// returns every unacknowledged file to `NeedsDispatch` synchronously.
#[derive(Debug)]
pub(crate) struct Ed2kCallbackSessionClaim {
    store: Arc<StdMutex<CallbackTicketStore>>,
    token: Option<CallbackSessionToken>,
}

impl Default for CallbackTicketStore {
    fn default() -> Self {
        Self::new(CALLBACK_TICKET_CAPACITY, CALLBACK_TICKET_DOWNLOAD_CAPACITY)
    }
}

impl Ed2kCallbackTicketRequest {
    /// Build a ticket for a classic server callback.
    pub fn server(
        server_endpoint: SocketAddr,
        client_id: u32,
        expected_user_hash: Option<[u8; 16]>,
        source_tcp_port: u16,
        download: Ed2kCallbackDownload,
        valid_for: Duration,
    ) -> Result<Self, Ed2kCallbackTicketError> {
        validate_ticket_request(Self {
            route: Ed2kCallbackRoute::Server { server_endpoint },
            peer: Ed2kCallbackPeer {
                client_id,
                expected_user_hash,
                source_ip: None,
                source_tcp_port,
            },
            download,
            valid_for,
        })
    }

    /// Build a ticket for a Kad buddy-relayed callback.
    #[allow(
        clippy::too_many_arguments,
        reason = "typed protocol identity constructor"
    )]
    pub fn kad_buddy(
        buddy_id: [u8; 16],
        buddy_endpoint: Option<SocketAddr>,
        client_id: u32,
        user_hash: [u8; 16],
        source_ip: Ipv4Addr,
        source_tcp_port: u16,
        download: Ed2kCallbackDownload,
        valid_for: Duration,
    ) -> Result<Self, Ed2kCallbackTicketError> {
        validate_ticket_request(Self {
            route: Ed2kCallbackRoute::KadBuddy {
                buddy_id,
                buddy_endpoint,
            },
            peer: Ed2kCallbackPeer {
                client_id,
                expected_user_hash: Some(user_hash),
                source_ip: Some(source_ip),
                source_tcp_port,
            },
            download,
            valid_for,
        })
    }

    /// Build a ticket for a direct UDP callback to a firewalled Kad source.
    pub fn direct_udp(
        source_endpoint: SocketAddr,
        client_id: u32,
        user_hash: [u8; 16],
        source_tcp_port: u16,
        download: Ed2kCallbackDownload,
        valid_for: Duration,
    ) -> Result<Self, Ed2kCallbackTicketError> {
        let source_ip = match source_endpoint.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        };
        validate_ticket_request(Self {
            route: Ed2kCallbackRoute::DirectUdp { source_endpoint },
            peer: Ed2kCallbackPeer {
                client_id,
                expected_user_hash: Some(user_hash),
                source_ip,
                source_tcp_port,
            },
            download,
            valid_for,
        })
    }
}

fn validate_ticket_request(
    mut request: Ed2kCallbackTicketRequest,
) -> Result<Ed2kCallbackTicketRequest, Ed2kCallbackTicketError> {
    if request.valid_for.is_zero() {
        return Err(Ed2kCallbackTicketError::ZeroLifetime);
    }
    if request.valid_for > ED2K_CALLBACK_TICKET_MAX_LIFETIME {
        return Err(Ed2kCallbackTicketError::LifetimeTooLong);
    }
    if request.peer.source_tcp_port == 0 {
        return Err(Ed2kCallbackTicketError::ZeroTcpPort);
    }
    match request.route {
        Ed2kCallbackRoute::Server { server_endpoint } => {
            if !is_valid_ipv4_endpoint(server_endpoint) {
                return Err(Ed2kCallbackTicketError::InvalidServerEndpoint);
            }
            if request.peer.client_id == 0 || request.peer.client_id >= 0x0100_0000 {
                return Err(Ed2kCallbackTicketError::InvalidServerClientId);
            }
            if request.peer.expected_user_hash == Some([0; 16]) {
                request.peer.expected_user_hash = None;
            }
            request.peer.source_ip = None;
        }
        Ed2kCallbackRoute::KadBuddy {
            buddy_id,
            buddy_endpoint,
        } => {
            if buddy_id == [0; 16] {
                return Err(Ed2kCallbackTicketError::InvalidBuddyId);
            }
            if buddy_endpoint.is_some_and(|endpoint| !is_valid_ipv4_endpoint(endpoint)) {
                return Err(Ed2kCallbackTicketError::InvalidBuddyEndpoint);
            }
            if request
                .peer
                .expected_user_hash
                .is_none_or(|hash| hash == [0; 16])
            {
                return Err(Ed2kCallbackTicketError::MissingUserHash);
            }
            if request.peer.source_ip.is_none_or(|ip| ip.is_unspecified()) {
                return Err(Ed2kCallbackTicketError::InvalidBuddyEndpoint);
            }
        }
        Ed2kCallbackRoute::DirectUdp { source_endpoint } => {
            let IpAddr::V4(endpoint_ip) = source_endpoint.ip() else {
                return Err(Ed2kCallbackTicketError::InvalidDirectEndpoint);
            };
            if endpoint_ip.is_unspecified()
                || source_endpoint.port() == 0
                || request.peer.source_ip != Some(endpoint_ip)
            {
                return Err(Ed2kCallbackTicketError::InvalidDirectEndpoint);
            }
            if request
                .peer
                .expected_user_hash
                .is_none_or(|hash| hash == [0; 16])
            {
                return Err(Ed2kCallbackTicketError::MissingUserHash);
            }
        }
    }
    Ok(request)
}

fn is_valid_ipv4_endpoint(endpoint: SocketAddr) -> bool {
    matches!(endpoint.ip(), IpAddr::V4(ip) if !ip.is_unspecified()) && endpoint.port() != 0
}

fn merge_ticket_download(
    ticket: &mut CallbackTicketRecord,
    peer: &Ed2kCallbackPeer,
    download: Ed2kCallbackDownload,
    download_capacity: usize,
) -> Result<(), Ed2kCallbackTicketError> {
    let existing_index = ticket
        .downloads
        .iter()
        .position(|existing| existing.file_hash == download.file_hash);
    if existing_index.is_none() && ticket.downloads.len() >= download_capacity {
        return Err(Ed2kCallbackTicketError::DownloadCapacity);
    }

    ticket.peer.expected_user_hash = ticket.peer.expected_user_hash.or(peer.expected_user_hash);
    if let Some(index) = existing_index {
        ticket.downloads[index] = download;
    } else {
        ticket.downloads.push(download);
    }
    Ok(())
}

fn ticket_can_accept_download(
    ticket: &CallbackTicketRecord,
    download: &Ed2kCallbackDownload,
    download_capacity: usize,
) -> bool {
    ticket
        .downloads
        .iter()
        .any(|existing| existing.file_hash == download.file_hash)
        || ticket.downloads.len() < download_capacity
}

impl CallbackTicketStore {
    fn new(ticket_capacity: usize, download_capacity: usize) -> Self {
        Self {
            next_ticket_id: 1,
            next_lease_generation: 1,
            ticket_capacity,
            download_capacity,
            tickets: VecDeque::new(),
        }
    }

    fn reserve(
        &mut self,
        request: Ed2kCallbackTicketRequest,
        now: Instant,
    ) -> Result<Ed2kCallbackReservation, Ed2kCallbackTicketError> {
        self.reap(now);
        let request = validate_ticket_request(request)?;
        let expires_at = now
            .checked_add(request.valid_for)
            .ok_or(Ed2kCallbackTicketError::DeadlineOverflow)?;

        if let Some(generation) = self.active_session_generation_for(&request.route, &request.peer)
        {
            let candidate_index = self.tickets.iter().position(|ticket| {
                ticket.route == request.route
                    && peers_can_merge(&ticket.route, &ticket.peer, &request.peer)
                    && (matches!(
                        ticket.state,
                        CallbackTicketState::SessionOwned {
                            generation: owned_generation,
                            ..
                        } if owned_generation == generation
                    ) || ticket.state == CallbackTicketState::NeedsDispatch)
            });
            if self.session_can_accept_download(
                generation,
                candidate_index,
                request.download.file_hash,
            ) {
                if let Some(index) = candidate_index {
                    let ticket = &mut self.tickets[index];
                    merge_ticket_download(
                        ticket,
                        &request.peer,
                        request.download,
                        self.download_capacity,
                    )?;
                    ticket.redispatch_lifetime = ticket.redispatch_lifetime.max(request.valid_for);
                    ticket.cancel_restores_needs_dispatch = false;
                    ticket.state = CallbackTicketState::SessionOwned {
                        generation,
                        prior_state: CallbackTicketReadyState::Armed,
                    };
                    return Ok(Ed2kCallbackReservation::Joined {
                        ticket_id: ticket.id,
                    });
                }

                if self.tickets.len() >= self.ticket_capacity {
                    return Err(Ed2kCallbackTicketError::TicketCapacity);
                }
                let id = self.allocate_ticket_id()?;
                self.tickets.push_back(CallbackTicketRecord {
                    id,
                    route: request.route,
                    peer: request.peer,
                    downloads: vec![request.download],
                    expires_at,
                    redispatch_lifetime: request.valid_for,
                    cancel_restores_needs_dispatch: false,
                    state: CallbackTicketState::SessionOwned {
                        generation,
                        prior_state: CallbackTicketReadyState::Armed,
                    },
                });
                return Ok(Ed2kCallbackReservation::Joined { ticket_id: id });
            }
        }

        if let Some(index) = self.tickets.iter().position(|ticket| {
            ticket.state == CallbackTicketState::NeedsDispatch
                && ticket.route == request.route
                && peers_can_merge(&ticket.route, &ticket.peer, &request.peer)
        }) {
            if !ticket_can_accept_download(
                &self.tickets[index],
                &request.download,
                self.download_capacity,
            ) {
                return Err(Ed2kCallbackTicketError::DownloadCapacity);
            }
            let id = self.allocate_ticket_id()?;
            let ticket = &mut self.tickets[index];
            merge_ticket_download(
                ticket,
                &request.peer,
                request.download,
                self.download_capacity,
            )?;
            ticket.id = id;
            ticket.expires_at = expires_at;
            ticket.redispatch_lifetime = request.valid_for;
            ticket.cancel_restores_needs_dispatch = true;
            ticket.state = CallbackTicketState::Reserved;
            return Ok(Ed2kCallbackReservation::Dispatch(
                Ed2kCallbackDispatchPermit {
                    ticket_id: ticket.id,
                    expires_at: ticket.expires_at,
                },
            ));
        }

        if let Some(ticket) = self.tickets.iter_mut().find(|ticket| {
            matches!(
                ticket.state,
                CallbackTicketState::Reserved
                    | CallbackTicketState::Dispatching
                    | CallbackTicketState::Armed
            ) && ticket.route == request.route
                && peers_can_merge(&ticket.route, &ticket.peer, &request.peer)
        }) {
            merge_ticket_download(
                ticket,
                &request.peer,
                request.download,
                self.download_capacity,
            )?;
            ticket.redispatch_lifetime = ticket.redispatch_lifetime.max(request.valid_for);
            return Ok(Ed2kCallbackReservation::Joined {
                ticket_id: ticket.id,
            });
        }

        if self.tickets.len() >= self.ticket_capacity {
            return Err(Ed2kCallbackTicketError::TicketCapacity);
        }
        let id = self.allocate_ticket_id()?;
        self.tickets.push_back(CallbackTicketRecord {
            id,
            route: request.route,
            peer: request.peer,
            downloads: vec![request.download],
            expires_at,
            redispatch_lifetime: request.valid_for,
            cancel_restores_needs_dispatch: false,
            state: CallbackTicketState::Reserved,
        });
        Ok(Ed2kCallbackReservation::Dispatch(
            Ed2kCallbackDispatchPermit {
                ticket_id: id,
                expires_at,
            },
        ))
    }

    fn allocate_ticket_id(&mut self) -> Result<Ed2kCallbackTicketId, Ed2kCallbackTicketError> {
        let id = Ed2kCallbackTicketId(self.next_ticket_id);
        self.next_ticket_id = self
            .next_ticket_id
            .checked_add(1)
            .ok_or(Ed2kCallbackTicketError::IdentifierExhausted)?;
        Ok(id)
    }

    fn active_session_generation_for(
        &self,
        route: &Ed2kCallbackRoute,
        peer: &Ed2kCallbackPeer,
    ) -> Option<u64> {
        self.tickets.iter().find_map(|ticket| {
            let CallbackTicketState::SessionOwned { generation, .. } = ticket.state else {
                return None;
            };
            let matches = if let Some(user_hash) = peer.expected_user_hash {
                ticket.peer.expected_user_hash == Some(user_hash)
            } else {
                ticket.route == *route && peers_can_merge(route, &ticket.peer, peer)
            };
            matches.then_some(generation)
        })
    }

    fn session_can_accept_download(
        &self,
        generation: u64,
        candidate_index: Option<usize>,
        file_hash: emulebb_kad_proto::Ed2kHash,
    ) -> bool {
        let mut hashes = self
            .tickets
            .iter()
            .filter(|ticket| {
                matches!(
                    ticket.state,
                    CallbackTicketState::SessionOwned {
                        generation: owned_generation,
                        ..
                    } if owned_generation == generation
                )
            })
            .flat_map(|ticket| ticket.downloads.iter().map(|download| download.file_hash))
            .collect::<HashSet<_>>();
        if let Some(index) = candidate_index
            && self.tickets[index].state == CallbackTicketState::NeedsDispatch
        {
            hashes.extend(
                self.tickets[index]
                    .downloads
                    .iter()
                    .map(|download| download.file_hash),
            );
        }
        hashes.insert(file_hash);
        hashes.len() <= CALLBACK_CLAIM_DOWNLOAD_CAPACITY
    }

    fn begin_dispatch(&mut self, permit: &Ed2kCallbackDispatchPermit, now: Instant) -> bool {
        self.reap(now);
        let Some(ticket) = self
            .tickets
            .iter_mut()
            .find(|ticket| ticket.id == permit.ticket_id)
        else {
            return false;
        };
        match &mut ticket.state {
            CallbackTicketState::Reserved => ticket.state = CallbackTicketState::Dispatching,
            CallbackTicketState::Leased { prior_state, .. }
                if *prior_state == CallbackTicketReadyState::Reserved =>
            {
                *prior_state = CallbackTicketReadyState::Dispatching;
            }
            CallbackTicketState::SessionOwned { prior_state, .. }
                if *prior_state == CallbackTicketReadyState::Reserved =>
            {
                *prior_state = CallbackTicketReadyState::Dispatching;
            }
            CallbackTicketState::Dispatching
            | CallbackTicketState::Armed
            | CallbackTicketState::Leased { .. }
            | CallbackTicketState::SessionOwned { .. }
            | CallbackTicketState::NeedsDispatch => return false,
        }
        true
    }

    fn mark_dispatched(
        &mut self,
        permit: Ed2kCallbackDispatchPermit,
        now: Instant,
    ) -> Ed2kCallbackDispatchOutcome {
        let Some(ticket) = self
            .tickets
            .iter_mut()
            .find(|ticket| ticket.id == permit.ticket_id)
        else {
            self.reap(now);
            return Ed2kCallbackDispatchOutcome::Settled;
        };
        match &mut ticket.state {
            CallbackTicketState::Reserved | CallbackTicketState::Dispatching => {
                ticket.state = CallbackTicketState::Armed;
            }
            CallbackTicketState::Leased { prior_state, .. }
                if matches!(
                    prior_state,
                    CallbackTicketReadyState::Reserved | CallbackTicketReadyState::Dispatching
                ) =>
            {
                *prior_state = CallbackTicketReadyState::Armed;
            }
            CallbackTicketState::SessionOwned { prior_state, .. }
                if matches!(
                    prior_state,
                    CallbackTicketReadyState::Reserved | CallbackTicketReadyState::Dispatching
                ) =>
            {
                *prior_state = CallbackTicketReadyState::Armed;
            }
            CallbackTicketState::Armed
            | CallbackTicketState::Leased { .. }
            | CallbackTicketState::SessionOwned { .. }
            | CallbackTicketState::NeedsDispatch => {
                return Ed2kCallbackDispatchOutcome::Settled;
            }
        }
        if let Some(deadline) = now.checked_add(ticket.redispatch_lifetime) {
            ticket.expires_at = deadline;
        }
        Ed2kCallbackDispatchOutcome::Armed
    }

    fn cancel(&mut self, permit: Ed2kCallbackDispatchPermit, now: Instant) -> bool {
        let mut index = self.tickets.iter().position(|ticket| {
            ticket.id == permit.ticket_id
                && matches!(
                    ticket.state,
                    CallbackTicketState::Reserved | CallbackTicketState::Dispatching
                )
        });
        if index.is_none() {
            self.reap(now);
            index = self.tickets.iter().position(|ticket| {
                ticket.id == permit.ticket_id
                    && matches!(
                        ticket.state,
                        CallbackTicketState::Reserved | CallbackTicketState::Dispatching
                    )
            });
        }
        let Some(index) = index else {
            if let Some(ticket) = self
                .tickets
                .iter_mut()
                .find(|ticket| ticket.id == permit.ticket_id)
            {
                match &mut ticket.state {
                    CallbackTicketState::Leased { prior_state, .. }
                    | CallbackTicketState::SessionOwned { prior_state, .. }
                        if *prior_state == CallbackTicketReadyState::Dispatching =>
                    {
                        *prior_state = CallbackTicketReadyState::Reserved;
                    }
                    _ => {}
                }
            }
            return false;
        };
        if self.tickets[index].cancel_restores_needs_dispatch {
            if let Some(deadline) = now.checked_add(self.tickets[index].redispatch_lifetime) {
                self.tickets[index].expires_at = deadline;
            }
            self.tickets[index].state = CallbackTicketState::NeedsDispatch;
        } else {
            self.tickets.remove(index);
        }
        self.reap(now);
        true
    }

    fn lease(
        &mut self,
        hello: Ed2kCallbackHelloIdentity,
        now: Instant,
    ) -> Result<Option<Ed2kCallbackClaim>, Ed2kCallbackClaimError> {
        self.reap(now);

        let strong_hash_match = self.tickets.iter().any(|ticket| {
            ticket.state.is_claimable()
                && hello.user_hash != [0; 16]
                && ticket.peer.expected_user_hash == Some(hello.user_hash)
        });
        let candidate_ids = if strong_hash_match {
            self.tickets
                .iter()
                .filter(|ticket| {
                    ticket.state.is_claimable()
                        && ticket.peer.expected_user_hash == Some(hello.user_hash)
                })
                .map(|ticket| ticket.id)
                .collect::<Vec<_>>()
        } else {
            let mut selected_key = None;
            for ticket in self
                .tickets
                .iter()
                .filter(|ticket| ticket.state.is_claimable())
            {
                let Some(key) = fallback_match_key(ticket, hello) else {
                    continue;
                };
                if selected_key.is_some_and(|selected| selected != key) {
                    return Err(Ed2kCallbackClaimError::AmbiguousPeer);
                }
                selected_key = Some(key);
            }
            let Some(selected_key) = selected_key else {
                return Ok(None);
            };
            self.tickets
                .iter()
                .filter(|ticket| {
                    ticket.state.is_claimable()
                        && fallback_match_key(ticket, hello) == Some(selected_key)
                })
                .map(|ticket| ticket.id)
                .collect::<Vec<_>>()
        };
        if candidate_ids.is_empty() {
            return Ok(None);
        }

        let candidate_id_set = candidate_ids.iter().copied().collect::<HashSet<_>>();
        let mut selected_ids = Vec::new();
        let mut downloads = Vec::new();
        let mut seen_file_hashes = HashSet::new();
        for ticket in self
            .tickets
            .iter()
            .filter(|ticket| candidate_id_set.contains(&ticket.id))
        {
            let new_downloads = ticket
                .downloads
                .iter()
                .filter(|download| !seen_file_hashes.contains(&download.file_hash))
                .cloned()
                .collect::<Vec<_>>();
            if downloads.len() + new_downloads.len() > CALLBACK_CLAIM_DOWNLOAD_CAPACITY {
                continue;
            }
            selected_ids.push(ticket.id);
            for download in new_downloads {
                seen_file_hashes.insert(download.file_hash);
                downloads.push(download);
            }
        }
        if selected_ids.is_empty() {
            return Err(Ed2kCallbackClaimError::ClaimCapacity);
        }

        let generation = self.next_lease_generation;
        self.next_lease_generation = self
            .next_lease_generation
            .checked_add(1)
            .ok_or(Ed2kCallbackClaimError::IdentifierExhausted)?;
        let lease_deadline = now
            .checked_add(CALLBACK_CLAIM_LEASE)
            .ok_or(Ed2kCallbackClaimError::DeadlineOverflow)?;
        let selected_id_set = selected_ids.iter().copied().collect::<HashSet<_>>();
        for ticket in self
            .tickets
            .iter_mut()
            .filter(|ticket| selected_id_set.contains(&ticket.id))
        {
            let prior_state = match ticket.state {
                CallbackTicketState::Reserved => CallbackTicketReadyState::Reserved,
                CallbackTicketState::Dispatching => CallbackTicketReadyState::Dispatching,
                CallbackTicketState::Armed => CallbackTicketReadyState::Armed,
                CallbackTicketState::Leased { .. }
                | CallbackTicketState::SessionOwned { .. }
                | CallbackTicketState::NeedsDispatch => {
                    continue;
                }
            };
            ticket.state = CallbackTicketState::Leased {
                generation,
                lease_deadline,
                prior_state,
            };
        }
        Ok(Some(Ed2kCallbackClaim {
            token: Ed2kCallbackClaimToken {
                ticket_ids: selected_ids,
                generation,
            },
            downloads,
        }))
    }

    fn commit(
        &mut self,
        token: &Ed2kCallbackClaimToken,
        now: Instant,
    ) -> Result<(), Ed2kCallbackClaimError> {
        self.reap(now);
        if !self.lease_token_is_current(token) {
            return Err(Ed2kCallbackClaimError::StaleClaim);
        }
        self.tickets
            .retain(|ticket| !token.ticket_ids.contains(&ticket.id));
        Ok(())
    }

    fn claim_session(
        &mut self,
        hello: Ed2kCallbackHelloIdentity,
        now: Instant,
    ) -> Result<Option<CallbackSessionToken>, Ed2kCallbackClaimError> {
        let Some(claim) = self.lease(hello, now)? else {
            return Ok(None);
        };
        let token = claim.token;
        let ticket_ids = token.ticket_ids.iter().copied().collect::<HashSet<_>>();
        for ticket in self
            .tickets
            .iter_mut()
            .filter(|ticket| ticket_ids.contains(&ticket.id))
        {
            let CallbackTicketState::Leased {
                generation,
                prior_state,
                ..
            } = ticket.state
            else {
                unreachable!("token validity requires every ticket to be leased")
            };
            if hello.user_hash != [0; 16] && ticket.peer.expected_user_hash.is_none() {
                ticket.peer.expected_user_hash = Some(hello.user_hash);
            }
            ticket.state = CallbackTicketState::SessionOwned {
                generation,
                prior_state,
            };
        }
        Ok(Some(CallbackSessionToken {
            generation: token.generation,
        }))
    }

    fn session_current(
        &mut self,
        token: &CallbackSessionToken,
        now: Instant,
    ) -> Result<Option<Ed2kCallbackDownload>, Ed2kCallbackClaimError> {
        self.reap(now);
        if !self.session_token_is_current(token) {
            return Err(Ed2kCallbackClaimError::StaleClaim);
        }
        Ok(self
            .tickets
            .iter()
            .filter(|ticket| {
                matches!(
                    ticket.state,
                    CallbackTicketState::SessionOwned { generation, .. }
                        if generation == token.generation
                )
            })
            .find_map(|ticket| ticket.downloads.first().cloned()))
    }

    fn acknowledge_session_current(
        &mut self,
        token: &CallbackSessionToken,
        now: Instant,
    ) -> Result<(), Ed2kCallbackClaimError> {
        let Some(current) = self.session_current(token, now)? else {
            return Ok(());
        };
        for ticket in self.tickets.iter_mut().filter(|ticket| {
            matches!(
                ticket.state,
                CallbackTicketState::SessionOwned { generation, .. }
                    if generation == token.generation
            )
        }) {
            ticket
                .downloads
                .retain(|download| download.file_hash != current.file_hash);
        }
        Ok(())
    }

    fn finish_session(
        &mut self,
        token: &CallbackSessionToken,
        now: Instant,
    ) -> Result<(), Ed2kCallbackClaimError> {
        self.reap(now);
        if !self.session_token_is_current(token) {
            return Err(Ed2kCallbackClaimError::StaleClaim);
        }
        let redispatch_deadlines = self
            .tickets
            .iter()
            .filter(|ticket| {
                matches!(
                    ticket.state,
                    CallbackTicketState::SessionOwned { generation, .. }
                        if generation == token.generation
                ) && !ticket.downloads.is_empty()
            })
            .map(|ticket| {
                now.checked_add(ticket.redispatch_lifetime)
                    .map(|deadline| (ticket.id, deadline))
                    .ok_or(Ed2kCallbackClaimError::DeadlineOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for ticket in self.tickets.iter_mut().filter(|ticket| {
            matches!(
                ticket.state,
                CallbackTicketState::SessionOwned { generation, .. }
                    if generation == token.generation
            )
        }) {
            if let Some((_, deadline)) = redispatch_deadlines
                .iter()
                .find(|(ticket_id, _)| *ticket_id == ticket.id)
            {
                ticket.expires_at = *deadline;
                ticket.state = CallbackTicketState::NeedsDispatch;
            }
        }
        self.tickets.retain(|ticket| {
            !matches!(
                ticket.state,
                CallbackTicketState::SessionOwned { generation, .. }
                    if generation == token.generation
            ) || !ticket.downloads.is_empty()
        });
        Ok(())
    }

    fn release(
        &mut self,
        token: &Ed2kCallbackClaimToken,
        now: Instant,
    ) -> Result<(), Ed2kCallbackClaimError> {
        self.reap(now);
        if !self.lease_token_is_current(token) {
            return Err(Ed2kCallbackClaimError::StaleClaim);
        }
        for ticket in self
            .tickets
            .iter_mut()
            .filter(|ticket| token.ticket_ids.contains(&ticket.id))
        {
            let CallbackTicketState::Leased { prior_state, .. } = ticket.state else {
                unreachable!("token validity requires every ticket to be leased")
            };
            ticket.state = prior_state.into();
        }
        self.reap(now);
        Ok(())
    }

    fn lease_token_is_current(&self, token: &Ed2kCallbackClaimToken) -> bool {
        !token.ticket_ids.is_empty()
            && token.ticket_ids.iter().all(|ticket_id| {
                self.tickets.iter().any(|ticket| {
                    ticket.id == *ticket_id
                        && matches!(
                            ticket.state,
                            CallbackTicketState::Leased { generation, .. }
                                if generation == token.generation
                        )
                })
            })
    }

    fn session_token_is_current(&self, token: &CallbackSessionToken) -> bool {
        self.tickets.iter().any(|ticket| {
            matches!(
                ticket.state,
                CallbackTicketState::SessionOwned { generation, .. }
                    if generation == token.generation
            )
        })
    }

    fn reap(&mut self, now: Instant) {
        self.tickets.retain_mut(|ticket| match ticket.state {
            CallbackTicketState::Reserved
            | CallbackTicketState::Armed
            | CallbackTicketState::NeedsDispatch => ticket.expires_at > now,
            CallbackTicketState::Dispatching => true,
            CallbackTicketState::Leased {
                lease_deadline,
                prior_state,
                ..
            } if lease_deadline <= now => {
                ticket.state = prior_state.into();
                prior_state == CallbackTicketReadyState::Dispatching || ticket.expires_at > now
            }
            CallbackTicketState::Leased { .. } => true,
            CallbackTicketState::SessionOwned { .. } => true,
        });
    }
}

impl CallbackTicketState {
    fn is_claimable(self) -> bool {
        matches!(self, Self::Reserved | Self::Dispatching | Self::Armed)
    }
}

fn peers_can_merge(
    route: &Ed2kCallbackRoute,
    existing: &Ed2kCallbackPeer,
    incoming: &Ed2kCallbackPeer,
) -> bool {
    if matches!(
        (existing.expected_user_hash, incoming.expected_user_hash),
        (Some(left), Some(right)) if left != right
    ) {
        return false;
    }
    if existing.expected_user_hash.is_some() && incoming.expected_user_hash.is_some() {
        return true;
    }
    match route {
        Ed2kCallbackRoute::Server { .. } => existing.client_id == incoming.client_id,
        Ed2kCallbackRoute::KadBuddy { .. } | Ed2kCallbackRoute::DirectUdp { .. } => {
            existing.source_ip == incoming.source_ip
                && existing.source_ip.is_some()
                && existing.source_tcp_port == incoming.source_tcp_port
        }
    }
}

fn fallback_match_key(
    ticket: &CallbackTicketRecord,
    hello: Ed2kCallbackHelloIdentity,
) -> Option<CallbackFallbackKey> {
    if ticket.peer.expected_user_hash.is_some() {
        return None;
    }
    match ticket.route {
        Ed2kCallbackRoute::Server { server_endpoint }
            if hello.server_endpoint == Some(server_endpoint)
                && hello.client_id == ticket.peer.client_id =>
        {
            Some(CallbackFallbackKey::Server {
                server_endpoint,
                client_id: ticket.peer.client_id,
            })
        }
        Ed2kCallbackRoute::KadBuddy { .. } | Ed2kCallbackRoute::DirectUdp { .. } => {
            let source_ip = ticket.peer.source_ip?;
            if hello.peer_ip != Some(source_ip) || ticket.peer.source_tcp_port != hello.tcp_port {
                return None;
            }
            Some(CallbackFallbackKey::Endpoint {
                ip: source_ip,
                tcp_port: hello.tcp_port,
            })
        }
        _ => None,
    }
}

impl Ed2kCallbackSessionClaim {
    /// Return the next peer-centric callback download without consuming it.
    pub(crate) fn current(&self) -> Result<Option<Ed2kCallbackDownload>, Ed2kCallbackClaimError> {
        let token = self
            .token
            .as_ref()
            .expect("live callback claim always owns a token");
        self.store
            .lock()
            .unwrap()
            .session_current(token, Instant::now())
    }

    /// Consume the current file after one successful protocol outcome. The
    /// same hash is removed from every selected ticket before advancing A4AF.
    pub(crate) fn acknowledge_current(&mut self) -> Result<(), Ed2kCallbackClaimError> {
        let token = self
            .token
            .as_ref()
            .expect("live callback claim always owns a token");
        self.store
            .lock()
            .unwrap()
            .acknowledge_session_current(token, Instant::now())
    }

    /// Finish session ownership explicitly. Dropping the guard provides the
    /// same cleanup for task cancellation and unwinding.
    pub(crate) fn finish(mut self) -> Result<(), Ed2kCallbackClaimError> {
        let token = self
            .token
            .take()
            .expect("live callback claim always owns a token");
        self.store
            .lock()
            .unwrap()
            .finish_session(&token, Instant::now())
    }
}

impl Drop for Ed2kCallbackSessionClaim {
    fn drop(&mut self) {
        let Some(token) = self.token.take() else {
            return;
        };
        let _ = self
            .store
            .lock()
            .unwrap()
            .finish_session(&token, Instant::now());
    }
}

impl Ed2kTransferRuntime {
    /// Reserve callback work before dispatching the corresponding network request.
    pub async fn reserve_callback_ticket(
        &self,
        request: Ed2kCallbackTicketRequest,
    ) -> Result<Ed2kCallbackReservation, Ed2kCallbackTicketError> {
        self.reserve_callback_ticket_at(request, Instant::now())
            .await
    }

    async fn reserve_callback_ticket_at(
        &self,
        request: Ed2kCallbackTicketRequest,
        now: Instant,
    ) -> Result<Ed2kCallbackReservation, Ed2kCallbackTicketError> {
        self.callback_tickets.lock().unwrap().reserve(request, now)
    }

    /// Move a reservation under cancellation-safe dispatch ownership.
    ///
    /// `None` means a fast callback or expiry already settled the reservation,
    /// so the caller must not originate another wire request.
    pub fn begin_callback_ticket_dispatch(
        &self,
        permit: Ed2kCallbackDispatchPermit,
    ) -> Option<Ed2kCallbackDispatchGuard> {
        let began = self
            .callback_tickets
            .lock()
            .unwrap()
            .begin_dispatch(&permit, Instant::now());
        began.then(|| Ed2kCallbackDispatchGuard {
            store: Arc::clone(&self.callback_tickets),
            permit: Some(permit),
        })
    }

    /// Mark a callback dispatch successful. A fast inbound lease records this
    /// transition transactionally so a later release restores `Armed`.
    pub async fn mark_callback_ticket_dispatched(
        &self,
        permit: Ed2kCallbackDispatchPermit,
    ) -> Ed2kCallbackDispatchOutcome {
        self.mark_callback_ticket_dispatched_at(permit, Instant::now())
            .await
    }

    async fn mark_callback_ticket_dispatched_at(
        &self,
        permit: Ed2kCallbackDispatchPermit,
        now: Instant,
    ) -> Ed2kCallbackDispatchOutcome {
        self.callback_tickets
            .lock()
            .unwrap()
            .mark_dispatched(permit, now)
    }

    /// Cancel one exact reservation after a proven not-sent dispatch failure.
    /// Cancellation cannot invalidate a ticket already leased by a callback.
    pub async fn cancel_callback_ticket(&self, permit: Ed2kCallbackDispatchPermit) -> bool {
        self.cancel_callback_ticket_at(permit, Instant::now()).await
    }

    async fn cancel_callback_ticket_at(
        &self,
        permit: Ed2kCallbackDispatchPermit,
        now: Instant,
    ) -> bool {
        self.callback_tickets.lock().unwrap().cancel(permit, now)
    }

    /// Lease all pending A4AF work proven to belong to an inbound HELLO identity.
    pub(crate) async fn lease_callback_tickets(
        &self,
        hello: Ed2kCallbackHelloIdentity,
    ) -> Result<Option<Ed2kCallbackClaim>, Ed2kCallbackClaimError> {
        self.lease_callback_tickets_at(hello, Instant::now()).await
    }

    async fn lease_callback_tickets_at(
        &self,
        hello: Ed2kCallbackHelloIdentity,
        now: Instant,
    ) -> Result<Option<Ed2kCallbackClaim>, Ed2kCallbackClaimError> {
        self.callback_tickets.lock().unwrap().lease(hello, now)
    }

    /// Consume a callback claim after the admitted peer session has adopted it.
    pub(crate) async fn commit_callback_claim(
        &self,
        token: &Ed2kCallbackClaimToken,
    ) -> Result<(), Ed2kCallbackClaimError> {
        self.commit_callback_claim_at(token, Instant::now()).await
    }

    async fn commit_callback_claim_at(
        &self,
        token: &Ed2kCallbackClaimToken,
        now: Instant,
    ) -> Result<(), Ed2kCallbackClaimError> {
        self.callback_tickets.lock().unwrap().commit(token, now)
    }

    /// Atomically admit one matching HELLO into cancellation-safe live-session
    /// ownership. No short lease remains active across peer network I/O.
    pub(crate) fn claim_callback_session(
        &self,
        hello: Ed2kCallbackHelloIdentity,
    ) -> Result<Option<Ed2kCallbackSessionClaim>, Ed2kCallbackClaimError> {
        self.claim_callback_session_at(hello, Instant::now())
    }

    fn claim_callback_session_at(
        &self,
        hello: Ed2kCallbackHelloIdentity,
        now: Instant,
    ) -> Result<Option<Ed2kCallbackSessionClaim>, Ed2kCallbackClaimError> {
        let token = self
            .callback_tickets
            .lock()
            .unwrap()
            .claim_session(hello, now)?;
        Ok(token.map(|token| Ed2kCallbackSessionClaim {
            store: Arc::clone(&self.callback_tickets),
            token: Some(token),
        }))
    }

    /// Re-arm an admission claim which failed before the callback session adopted it.
    pub(crate) async fn release_callback_claim(
        &self,
        token: &Ed2kCallbackClaimToken,
    ) -> Result<(), Ed2kCallbackClaimError> {
        self.release_callback_claim_at(token, Instant::now()).await
    }

    async fn release_callback_claim_at(
        &self,
        token: &Ed2kCallbackClaimToken,
        now: Instant,
    ) -> Result<(), Ed2kCallbackClaimError> {
        self.callback_tickets.lock().unwrap().release(token, now)
    }

    /// Register one pending LowID callback download intent.
    pub async fn register_callback_intent(&self, intent: Ed2kCallbackIntent) {
        let mut intents = self.callback_intents.write().await;
        if !intents.iter().any(|existing| existing == &intent) {
            intents.push(intent);
        }
    }

    /// Claim the oldest pending LowID callback intent for the specified peer client-id.
    pub async fn claim_callback_intent(&self, client_id: u32) -> Option<Ed2kCallbackIntent> {
        let mut intents = self.callback_intents.write().await;
        let index = intents
            .iter()
            .position(|intent| intent.client_id == client_id)?;
        Some(intents.remove(index))
    }

    /// Claim the complete peer-centric callback source set in registration
    /// order. One LowID connect-back can then negotiate every wanted file over
    /// that already-established socket instead of consuming one intent and
    /// requiring another server/Kad callback for each A4AF relation.
    pub async fn claim_callback_intents(&self, client_id: u32) -> Vec<Ed2kCallbackIntent> {
        let mut intents = self.callback_intents.write().await;
        let mut claimed = Vec::new();
        let mut retained = Vec::with_capacity(intents.len());
        for intent in intents.drain(..) {
            if intent.client_id == client_id {
                claimed.push(intent);
            } else {
                retained.push(intent);
            }
        }
        *intents = retained;
        claimed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ed2k_transfer::Ed2kSourceHint, paths::unique_test_dir};

    fn download(hash_byte: u8) -> Ed2kCallbackDownload {
        Ed2kCallbackDownload {
            file_hash: emulebb_kad_proto::Ed2kHash::from_bytes([hash_byte; 16]),
            display_name: format!("{hash_byte}.bin"),
            file_size: u64::from(hash_byte),
            source: Ed2kSourceHint {
                ip: "192.0.2.1".to_string(),
                tcp_port: 4662,
                user_hash: None,
                connect_options: None,
                file_comment: String::new(),
                file_rating: 0,
            },
        }
    }

    fn indexed_download(index: u16) -> Ed2kCallbackDownload {
        let mut value = download(index as u8);
        let mut hash = [0; 16];
        hash[..2].copy_from_slice(&index.to_le_bytes());
        value.file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(hash);
        value.display_name = format!("{index}.bin");
        value
    }

    fn server_request(
        server: SocketAddr,
        client_id: u32,
        hash_byte: u8,
    ) -> Ed2kCallbackTicketRequest {
        Ed2kCallbackTicketRequest::server(
            server,
            client_id,
            None,
            4662,
            download(hash_byte),
            Duration::from_secs(45),
        )
        .unwrap()
    }

    fn direct_request(
        source_endpoint: SocketAddr,
        user_hash: [u8; 16],
        hash_byte: u8,
    ) -> Ed2kCallbackTicketRequest {
        Ed2kCallbackTicketRequest::direct_udp(
            source_endpoint,
            17,
            user_hash,
            4662,
            download(hash_byte),
            Duration::from_secs(45),
        )
        .unwrap()
    }

    fn dispatch_permit(reservation: Ed2kCallbackReservation) -> Ed2kCallbackDispatchPermit {
        match reservation {
            Ed2kCallbackReservation::Dispatch(permit) => permit,
            Ed2kCallbackReservation::Joined { .. } => {
                panic!("expected callback dispatch ownership")
            }
        }
    }

    fn hello(
        server: Option<SocketAddr>,
        client_id: u32,
        user_hash: [u8; 16],
    ) -> Ed2kCallbackHelloIdentity {
        Ed2kCallbackHelloIdentity {
            user_hash,
            client_id,
            server_endpoint: server,
            peer_ip: Some(Ipv4Addr::new(192, 0, 2, 1)),
            tcp_port: 4662,
        }
    }

    fn intent(client_id: u32, hash_byte: u8) -> Ed2kCallbackIntent {
        Ed2kCallbackIntent {
            client_id,
            file_hash: hex::encode([hash_byte; 16]),
            display_name: format!("{hash_byte}.bin"),
            file_size: u64::from(hash_byte),
            source: download(hash_byte).source,
        }
    }

    #[tokio::test]
    async fn callback_claim_collects_one_peers_full_a4af_set_in_order() {
        let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(
            "ed2k-callback-a4af-intent-claim",
        ))
        .unwrap();
        runtime.register_callback_intent(intent(17, 1)).await;
        runtime.register_callback_intent(intent(23, 2)).await;
        runtime.register_callback_intent(intent(17, 3)).await;

        let claimed = runtime.claim_callback_intents(17).await;
        assert_eq!(
            claimed
                .iter()
                .map(|intent| intent.file_hash.as_str())
                .collect::<Vec<_>>(),
            vec![hex::encode([1; 16]), hex::encode([3; 16])]
        );
        assert_eq!(runtime.claim_callback_intent(23).await, Some(intent(23, 2)));
        assert!(runtime.claim_callback_intents(17).await.is_empty());
    }

    #[tokio::test]
    async fn ticket_claim_is_scoped_to_the_server_low_id_namespace() {
        let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(
            "ed2k-callback-ticket-server-scope",
        ))
        .unwrap();
        let now = Instant::now();
        let server_a = "192.0.2.10:4661".parse().unwrap();
        let server_b = "192.0.2.20:4661".parse().unwrap();
        runtime
            .reserve_callback_ticket_at(server_request(server_a, 17, 1), now)
            .await
            .unwrap();
        runtime
            .reserve_callback_ticket_at(server_request(server_b, 17, 2), now)
            .await
            .unwrap();

        assert!(
            runtime
                .lease_callback_tickets_at(hello(None, 17, [0x55; 16]), now)
                .await
                .unwrap()
                .is_none()
        );

        let claim = runtime
            .lease_callback_tickets_at(hello(Some(server_b), 17, [0x55; 16]), now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim.downloads, vec![download(2)]);
        assert!(
            runtime
                .commit_callback_claim_at(&claim.token, now)
                .await
                .is_ok()
        );

        let remaining = runtime
            .lease_callback_tickets_at(hello(Some(server_a), 17, [0x66; 16]), now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(remaining.downloads, vec![download(1)]);
    }

    #[tokio::test]
    async fn known_user_hash_matches_before_route_fallback_and_mismatch_never_falls_back() {
        let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(
            "ed2k-callback-ticket-hash-first",
        ))
        .unwrap();
        let now = Instant::now();
        let server: SocketAddr = "192.0.2.10:4661".parse().unwrap();
        let mut request = server_request(server, 17, 1);
        request.peer.expected_user_hash = Some([0x44; 16]);
        runtime
            .reserve_callback_ticket_at(request, now)
            .await
            .unwrap();

        assert!(
            runtime
                .lease_callback_tickets_at(hello(Some(server), 17, [0x45; 16]), now)
                .await
                .unwrap()
                .is_none()
        );
        let claim = runtime
            .lease_callback_tickets_at(hello(None, 999, [0x44; 16]), now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim.downloads, vec![download(1)]);
    }

    #[tokio::test]
    async fn reservation_merges_a4af_without_extending_expiry() {
        let runtime =
            Ed2kTransferRuntime::load_or_create(&unique_test_dir("ed2k-callback-ticket-a4af"))
                .unwrap();
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let first = dispatch_permit(
            runtime
                .reserve_callback_ticket_at(server_request(server, 17, 1), now)
                .await
                .unwrap(),
        );
        let mut second_request = server_request(server, 17, 2);
        second_request.peer.source_tcp_port = 4663;
        let second = runtime
            .reserve_callback_ticket_at(second_request, now + Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(
            second,
            Ed2kCallbackReservation::Joined {
                ticket_id: first.ticket_id,
            }
        );
        assert_eq!(
            runtime.mark_callback_ticket_dispatched_at(first, now).await,
            Ed2kCallbackDispatchOutcome::Armed
        );

        assert!(
            runtime
                .lease_callback_tickets_at(
                    hello(Some(server), 17, [0x55; 16]),
                    now + Duration::from_secs(45),
                )
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn cancellation_removes_only_the_dispatch_owners_ticket() {
        let runtime =
            Ed2kTransferRuntime::load_or_create(&unique_test_dir("ed2k-callback-ticket-cancel"))
                .unwrap();
        let now = Instant::now();
        let server_a = "192.0.2.10:4661".parse().unwrap();
        let server_b = "192.0.2.20:4661".parse().unwrap();
        let cancelled = dispatch_permit(
            runtime
                .reserve_callback_ticket_at(server_request(server_a, 17, 1), now)
                .await
                .unwrap(),
        );
        let surviving = dispatch_permit(
            runtime
                .reserve_callback_ticket_at(server_request(server_b, 17, 2), now)
                .await
                .unwrap(),
        );

        assert!(runtime.cancel_callback_ticket_at(cancelled, now).await);
        assert_eq!(
            runtime
                .mark_callback_ticket_dispatched_at(surviving, now)
                .await,
            Ed2kCallbackDispatchOutcome::Armed
        );
        let claim = runtime
            .lease_callback_tickets_at(hello(Some(server_b), 17, [0x55; 16]), now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim.downloads, vec![download(2)]);
    }

    #[test]
    fn bounded_store_rejects_without_evicting_and_expiry_frees_capacity() {
        let now = Instant::now();
        let server_a = "192.0.2.10:4661".parse().unwrap();
        let server_b = "192.0.2.20:4661".parse().unwrap();
        let mut store = CallbackTicketStore::new(1, 1);
        let mut first = server_request(server_a, 17, 1);
        first.valid_for = Duration::from_secs(1);
        store.reserve(first, now).unwrap();
        assert_eq!(
            store.reserve(server_request(server_b, 17, 2), now),
            Err(Ed2kCallbackTicketError::TicketCapacity)
        );
        assert!(
            store
                .reserve(
                    server_request(server_b, 17, 2),
                    now + Duration::from_secs(1),
                )
                .is_ok()
        );
    }

    #[test]
    fn direct_udp_ticket_joins_a4af_only_on_the_same_route_and_peer_hash() {
        let now = Instant::now();
        let source_a: SocketAddr = "192.0.2.1:4672".parse().unwrap();
        let source_b: SocketAddr = "192.0.2.1:4673".parse().unwrap();
        let mut store = CallbackTicketStore::default();

        assert!(matches!(
            store.reserve(direct_request(source_a, [0x44; 16], 1), now),
            Ok(Ed2kCallbackReservation::Dispatch(_))
        ));
        assert!(matches!(
            store.reserve(direct_request(source_a, [0x44; 16], 2), now),
            Ok(Ed2kCallbackReservation::Joined { .. })
        ));
        assert!(matches!(
            store.reserve(direct_request(source_b, [0x44; 16], 3), now),
            Ok(Ed2kCallbackReservation::Dispatch(_))
        ));
        assert!(matches!(
            store.reserve(direct_request(source_a, [0x55; 16], 4), now),
            Ok(Ed2kCallbackReservation::Dispatch(_))
        ));

        assert_eq!(store.tickets.len(), 3);
        assert_eq!(store.tickets[0].downloads, vec![download(1), download(2)]);
    }

    #[test]
    fn dispatching_ticket_survives_its_queue_deadline_then_arms_from_settlement_time() {
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let mut store = CallbackTicketStore::default();
        let permit = dispatch_permit(store.reserve(server_request(server, 17, 1), now).unwrap());
        assert_eq!(permit.expires_at(), now + Duration::from_secs(45));
        assert!(store.begin_dispatch(&permit, now));

        let settled_at = now + Duration::from_secs(60);
        store.reap(settled_at);
        assert_eq!(store.tickets[0].state, CallbackTicketState::Dispatching);
        assert_eq!(
            store.mark_dispatched(permit, settled_at),
            Ed2kCallbackDispatchOutcome::Armed
        );
        store.reap(settled_at + Duration::from_secs(44));
        assert_eq!(store.tickets.len(), 1);
        store.reap(settled_at + Duration::from_secs(45));
        assert!(store.tickets.is_empty());
    }

    #[tokio::test]
    async fn dropped_dispatch_guard_conservatively_arms_the_reservation() {
        let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(
            "ed2k-callback-ticket-dispatch-guard-drop",
        ))
        .unwrap();
        let server = "192.0.2.10:4661".parse().unwrap();
        let permit = dispatch_permit(
            runtime
                .reserve_callback_ticket(server_request(server, 17, 1))
                .await
                .unwrap(),
        );
        let guard = runtime.begin_callback_ticket_dispatch(permit).unwrap();
        drop(guard);

        let claim = runtime
            .lease_callback_tickets(hello(Some(server), 17, [0x55; 16]))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim.downloads, vec![download(1)]);
    }

    #[tokio::test]
    async fn released_claim_rearms_but_committed_claim_is_consumed() {
        let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(
            "ed2k-callback-ticket-settlement",
        ))
        .unwrap();
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        runtime
            .reserve_callback_ticket_at(server_request(server, 17, 1), now)
            .await
            .unwrap();
        let observed = hello(Some(server), 17, [0x55; 16]);
        let first = runtime
            .lease_callback_tickets_at(observed, now)
            .await
            .unwrap()
            .unwrap();
        assert!(
            runtime
                .release_callback_claim_at(&first.token, now)
                .await
                .is_ok()
        );
        let second = runtime
            .lease_callback_tickets_at(observed, now)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(first.token.generation, second.token.generation);
        assert!(
            runtime
                .commit_callback_claim_at(&second.token, now)
                .await
                .is_ok()
        );
        assert!(
            runtime
                .lease_callback_tickets_at(observed, now)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn expired_lease_rearms_with_a_new_generation_and_rejects_the_stale_token() {
        let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(
            "ed2k-callback-ticket-stale-lease",
        ))
        .unwrap();
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        runtime
            .reserve_callback_ticket_at(server_request(server, 17, 1), now)
            .await
            .unwrap();
        let observed = hello(Some(server), 17, [0x55; 16]);
        let stale = runtime
            .lease_callback_tickets_at(observed, now)
            .await
            .unwrap()
            .unwrap();
        let replacement = runtime
            .lease_callback_tickets_at(observed, now + CALLBACK_CLAIM_LEASE)
            .await
            .unwrap()
            .unwrap();

        assert_ne!(stale.token.generation, replacement.token.generation);
        assert_eq!(
            runtime
                .commit_callback_claim_at(&stale.token, now + CALLBACK_CLAIM_LEASE)
                .await,
            Err(Ed2kCallbackClaimError::StaleClaim)
        );
        assert!(
            runtime
                .commit_callback_claim_at(&replacement.token, now + CALLBACK_CLAIM_LEASE)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn cancellation_cannot_invalidate_a_fast_inbound_claim() {
        let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(
            "ed2k-callback-ticket-cancel-race",
        ))
        .unwrap();
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let permit = dispatch_permit(
            runtime
                .reserve_callback_ticket_at(server_request(server, 17, 1), now)
                .await
                .unwrap(),
        );
        let claim = runtime
            .lease_callback_tickets_at(hello(Some(server), 17, [0x55; 16]), now)
            .await
            .unwrap()
            .unwrap();

        assert!(!runtime.cancel_callback_ticket_at(permit, now).await);
        assert!(
            runtime
                .commit_callback_claim_at(&claim.token, now)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn released_reserved_claim_restores_the_dispatch_permit() {
        let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(
            "ed2k-callback-ticket-release-reserved",
        ))
        .unwrap();
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let permit = dispatch_permit(
            runtime
                .reserve_callback_ticket_at(server_request(server, 17, 1), now)
                .await
                .unwrap(),
        );
        let claim = runtime
            .lease_callback_tickets_at(hello(Some(server), 17, [0x55; 16]), now)
            .await
            .unwrap()
            .unwrap();

        runtime
            .release_callback_claim_at(&claim.token, now)
            .await
            .unwrap();
        assert!(runtime.cancel_callback_ticket_at(permit, now).await);
    }

    #[tokio::test]
    async fn successful_dispatch_during_a_fast_lease_restores_armed_state() {
        let runtime =
            Ed2kTransferRuntime::load_or_create(&unique_test_dir("ed2k-callback-ticket-fast-arm"))
                .unwrap();
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let permit = dispatch_permit(
            runtime
                .reserve_callback_ticket_at(server_request(server, 17, 1), now)
                .await
                .unwrap(),
        );
        let claim = runtime
            .lease_callback_tickets_at(hello(Some(server), 17, [0x55; 16]), now)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            runtime
                .mark_callback_ticket_dispatched_at(permit, now)
                .await,
            Ed2kCallbackDispatchOutcome::Armed
        );
        runtime
            .release_callback_claim_at(&claim.token, now)
            .await
            .unwrap();
        assert_eq!(
            runtime.callback_tickets.lock().unwrap().tickets[0].state,
            CallbackTicketState::Armed
        );
    }

    #[tokio::test]
    async fn expired_reserved_lease_restores_the_dispatch_permit() {
        let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(
            "ed2k-callback-ticket-expired-reserved",
        ))
        .unwrap();
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let permit = dispatch_permit(
            runtime
                .reserve_callback_ticket_at(server_request(server, 17, 1), now)
                .await
                .unwrap(),
        );
        let claim = runtime
            .lease_callback_tickets_at(hello(Some(server), 17, [0x55; 16]), now)
            .await
            .unwrap()
            .unwrap();

        assert!(
            runtime
                .cancel_callback_ticket_at(permit, now + CALLBACK_CLAIM_LEASE)
                .await
        );
        assert_eq!(
            runtime
                .commit_callback_claim_at(&claim.token, now + CALLBACK_CLAIM_LEASE)
                .await,
            Err(Ed2kCallbackClaimError::StaleClaim)
        );
    }

    #[tokio::test]
    async fn releasing_after_original_expiry_removes_the_ticket() {
        let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(
            "ed2k-callback-ticket-release-expired",
        ))
        .unwrap();
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let mut request = server_request(server, 17, 1);
        request.valid_for = Duration::from_secs(1);
        runtime
            .reserve_callback_ticket_at(request, now)
            .await
            .unwrap();
        let observed = hello(Some(server), 17, [0x55; 16]);
        let claim = runtime
            .lease_callback_tickets_at(observed, now)
            .await
            .unwrap()
            .unwrap();

        assert!(
            runtime
                .release_callback_claim_at(&claim.token, now + Duration::from_secs(1))
                .await
                .is_ok()
        );
        assert!(
            runtime
                .lease_callback_tickets_at(observed, now + Duration::from_secs(1))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn dropped_session_claim_rearms_only_unacknowledged_a4af_work() {
        let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(
            "ed2k-callback-session-drop-a4af",
        ))
        .unwrap();
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let permit = dispatch_permit(
            runtime
                .reserve_callback_ticket_at(server_request(server, 17, 1), now)
                .await
                .unwrap(),
        );
        assert!(matches!(
            runtime
                .reserve_callback_ticket_at(server_request(server, 17, 2), now)
                .await
                .unwrap(),
            Ed2kCallbackReservation::Joined { .. }
        ));
        assert_eq!(
            runtime
                .mark_callback_ticket_dispatched_at(permit, now)
                .await,
            Ed2kCallbackDispatchOutcome::Armed
        );

        let mut claim = runtime
            .claim_callback_session_at(hello(Some(server), 17, [0x55; 16]), now)
            .unwrap()
            .unwrap();
        assert_eq!(claim.current().unwrap(), Some(download(1)));
        claim.acknowledge_current().unwrap();
        assert_eq!(claim.current().unwrap(), Some(download(2)));
        drop(claim);

        let tickets = runtime.callback_tickets.lock().unwrap();
        assert_eq!(tickets.tickets.len(), 1);
        assert_eq!(tickets.tickets[0].state, CallbackTicketState::NeedsDispatch);
        assert_eq!(tickets.tickets[0].downloads, vec![download(2)]);
    }

    #[test]
    fn session_owned_work_cannot_be_reaped_or_reclaimed_after_the_short_lease() {
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let observed = hello(Some(server), 17, [0x55; 16]);
        let mut store = CallbackTicketStore::default();
        store.reserve(server_request(server, 17, 1), now).unwrap();
        let token = store.claim_session(observed, now).unwrap().unwrap();

        assert!(
            store
                .lease(observed, now + CALLBACK_CLAIM_LEASE)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.session_current(&token, now + CALLBACK_CLAIM_LEASE),
            Ok(Some(download(1)))
        );
    }

    #[test]
    fn acknowledging_a_duplicate_hash_consumes_every_selected_ticket_copy() {
        let now = Instant::now();
        let server_a = "192.0.2.10:4661".parse().unwrap();
        let server_b = "192.0.2.20:4661".parse().unwrap();
        let mut first = server_request(server_a, 17, 1);
        first.peer.expected_user_hash = Some([0x44; 16]);
        let mut second = server_request(server_b, 23, 1);
        second.peer.expected_user_hash = Some([0x44; 16]);
        let mut store = CallbackTicketStore::default();
        store.reserve(first, now).unwrap();
        store.reserve(second, now).unwrap();

        let token = store
            .claim_session(hello(None, 999, [0x44; 16]), now)
            .unwrap()
            .unwrap();
        store.acknowledge_session_current(&token, now).unwrap();
        store.finish_session(&token, now).unwrap();
        assert!(store.tickets.is_empty());
    }

    #[test]
    fn work_joined_during_a_session_is_returned_for_fresh_dispatch() {
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let observed = hello(Some(server), 17, [0x55; 16]);
        let mut store = CallbackTicketStore::default();
        store.reserve(server_request(server, 17, 1), now).unwrap();
        let token = store.claim_session(observed, now).unwrap().unwrap();
        store.acknowledge_session_current(&token, now).unwrap();

        assert!(matches!(
            store.reserve(server_request(server, 17, 2), now),
            Ok(Ed2kCallbackReservation::Joined { .. })
        ));
        assert_eq!(store.session_current(&token, now), Ok(Some(download(2))));
        store.finish_session(&token, now).unwrap();
        let previous_ticket_id = store.tickets[0].id;
        assert_eq!(store.tickets[0].state, CallbackTicketState::NeedsDispatch);
        let permit = dispatch_permit(
            store
                .reserve(server_request(server, 17, 2), now + Duration::from_secs(1))
                .unwrap(),
        );
        assert_ne!(permit.ticket_id, previous_ticket_id);
    }

    #[test]
    fn stale_permits_cannot_mutate_a_fresh_redispatch_epoch() {
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let observed = hello(Some(server), 17, [0x55; 16]);

        let mut mark_store = CallbackTicketStore::default();
        let stale_mark = dispatch_permit(
            mark_store
                .reserve(server_request(server, 17, 1), now)
                .unwrap(),
        );
        let owner = mark_store.claim_session(observed, now).unwrap().unwrap();
        mark_store.finish_session(&owner, now).unwrap();
        let fresh_mark = dispatch_permit(
            mark_store
                .reserve(server_request(server, 17, 1), now)
                .unwrap(),
        );
        assert_ne!(stale_mark.ticket_id, fresh_mark.ticket_id);
        assert_eq!(
            mark_store.mark_dispatched(stale_mark, now),
            Ed2kCallbackDispatchOutcome::Settled
        );
        assert_eq!(
            mark_store.mark_dispatched(fresh_mark, now),
            Ed2kCallbackDispatchOutcome::Armed
        );

        let mut cancel_store = CallbackTicketStore::default();
        let stale_cancel = dispatch_permit(
            cancel_store
                .reserve(server_request(server, 17, 1), now)
                .unwrap(),
        );
        let owner = cancel_store.claim_session(observed, now).unwrap().unwrap();
        cancel_store.finish_session(&owner, now).unwrap();
        let fresh_cancel = dispatch_permit(
            cancel_store
                .reserve(server_request(server, 17, 1), now)
                .unwrap(),
        );
        assert_ne!(stale_cancel.ticket_id, fresh_cancel.ticket_id);
        assert!(!cancel_store.cancel(stale_cancel, now));
        assert!(cancel_store.cancel(fresh_cancel, now));
    }

    #[test]
    fn cancelled_residual_dispatch_preserves_the_complete_retry_set() {
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let observed = hello(Some(server), 17, [0x55; 16]);
        let mut store = CallbackTicketStore::default();
        store.reserve(server_request(server, 17, 1), now).unwrap();
        store.reserve(server_request(server, 17, 2), now).unwrap();
        let owner = store.claim_session(observed, now).unwrap().unwrap();
        store.acknowledge_session_current(&owner, now).unwrap();
        store.finish_session(&owner, now).unwrap();

        let failed = dispatch_permit(store.reserve(server_request(server, 17, 2), now).unwrap());
        assert!(store.cancel(failed, now));
        assert_eq!(store.tickets.len(), 1);
        assert_eq!(store.tickets[0].state, CallbackTicketState::NeedsDispatch);
        assert_eq!(store.tickets[0].downloads, vec![download(2)]);

        assert!(matches!(
            store.reserve(server_request(server, 17, 2), now),
            Ok(Ed2kCallbackReservation::Dispatch(_))
        ));
    }

    #[test]
    fn same_hash_work_from_another_route_joins_the_active_peer_session() {
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let user_hash = [0x44; 16];
        let mut first = server_request(server, 17, 1);
        first.peer.expected_user_hash = Some(user_hash);
        let mut store = CallbackTicketStore::default();
        store.reserve(first, now).unwrap();
        let owner = store
            .claim_session(hello(None, 999, user_hash), now)
            .unwrap()
            .unwrap();

        let joined = Ed2kCallbackTicketRequest::kad_buddy(
            [0x22; 16],
            None,
            23,
            user_hash,
            Ipv4Addr::new(192, 0, 2, 1),
            4662,
            download(2),
            Duration::from_secs(45),
        )
        .unwrap();
        assert!(matches!(
            store.reserve(joined, now),
            Ok(Ed2kCallbackReservation::Joined { .. })
        ));
        assert_eq!(store.session_current(&owner, now), Ok(Some(download(1))));
        store.acknowledge_session_current(&owner, now).unwrap();
        assert_eq!(store.session_current(&owner, now), Ok(Some(download(2))));
        store.finish_session(&owner, now).unwrap();

        assert_eq!(store.tickets.len(), 1);
        assert!(matches!(
            store.tickets[0].route,
            Ed2kCallbackRoute::KadBuddy { .. }
        ));
        assert_eq!(store.tickets[0].state, CallbackTicketState::NeedsDispatch);
        assert_eq!(store.tickets[0].downloads, vec![download(2)]);
    }

    #[test]
    fn same_route_join_cannot_bypass_the_live_session_file_bound() {
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let user_hash = [0x44; 16];
        let mut store = CallbackTicketStore::default();
        for index in 0..128u16 {
            let mut request = server_request(server, 17, 1);
            request.peer.expected_user_hash = Some(user_hash);
            request.download = indexed_download(index);
            store.reserve(request, now).unwrap();
        }
        for index in 128..256u16 {
            let request = Ed2kCallbackTicketRequest::kad_buddy(
                [0x22; 16],
                None,
                23,
                user_hash,
                Ipv4Addr::new(192, 0, 2, 1),
                4662,
                indexed_download(index),
                Duration::from_secs(45),
            )
            .unwrap();
            store.reserve(request, now).unwrap();
        }
        let owner = store
            .claim_session(hello(None, 999, user_hash), now)
            .unwrap()
            .unwrap();
        assert_eq!(
            store
                .tickets
                .iter()
                .filter(|ticket| matches!(ticket.state, CallbackTicketState::SessionOwned { .. }))
                .flat_map(|ticket| ticket.downloads.iter().map(|download| download.file_hash))
                .collect::<HashSet<_>>()
                .len(),
            CALLBACK_CLAIM_DOWNLOAD_CAPACITY
        );

        let mut overflow = server_request(server, 17, 1);
        overflow.peer.expected_user_hash = Some(user_hash);
        overflow.download = indexed_download(256);
        assert!(matches!(
            store.reserve(overflow, now),
            Ok(Ed2kCallbackReservation::Dispatch(_))
        ));
        assert!(store.session_current(&owner, now).unwrap().is_some());
        assert_eq!(
            store
                .tickets
                .iter()
                .filter(|ticket| matches!(ticket.state, CallbackTicketState::SessionOwned { .. }))
                .flat_map(|ticket| ticket.downloads.iter().map(|download| download.file_hash))
                .collect::<HashSet<_>>()
                .len(),
            CALLBACK_CLAIM_DOWNLOAD_CAPACITY
        );
    }

    #[test]
    fn live_session_cannot_absorb_an_oversized_residual_ticket() {
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let user_hash = [0x44; 16];
        let mut store = CallbackTicketStore::default();
        for index in 0..200u16 {
            let mut request = server_request(server, 17, 1);
            request.peer.expected_user_hash = Some(user_hash);
            request.download = indexed_download(index);
            store.reserve(request, now).unwrap();
        }
        for index in 200..300u16 {
            let request = Ed2kCallbackTicketRequest::kad_buddy(
                [0x22; 16],
                None,
                23,
                user_hash,
                Ipv4Addr::new(192, 0, 2, 1),
                4662,
                indexed_download(index),
                Duration::from_secs(45),
            )
            .unwrap();
            store.reserve(request, now).unwrap();
        }
        let residual_index = store
            .tickets
            .iter()
            .position(|ticket| matches!(ticket.route, Ed2kCallbackRoute::KadBuddy { .. }))
            .unwrap();
        store.tickets[residual_index].state = CallbackTicketState::NeedsDispatch;
        let owner = store
            .claim_session(hello(None, 999, user_hash), now)
            .unwrap()
            .unwrap();

        let retry = Ed2kCallbackTicketRequest::kad_buddy(
            [0x22; 16],
            None,
            23,
            user_hash,
            Ipv4Addr::new(192, 0, 2, 1),
            4662,
            indexed_download(200),
            Duration::from_secs(45),
        )
        .unwrap();
        assert!(matches!(
            store.reserve(retry, now),
            Ok(Ed2kCallbackReservation::Dispatch(_))
        ));
        assert_eq!(store.tickets[residual_index].downloads.len(), 100);
        assert_eq!(
            store.tickets[residual_index].state,
            CallbackTicketState::Reserved
        );
        assert_eq!(
            store
                .tickets
                .iter()
                .filter(|ticket| matches!(ticket.state, CallbackTicketState::SessionOwned { .. }))
                .flat_map(|ticket| ticket.downloads.iter().map(|download| download.file_hash))
                .collect::<HashSet<_>>()
                .len(),
            200
        );
        assert!(store.session_current(&owner, now).unwrap().is_some());
    }

    #[test]
    fn fallback_admission_pins_the_observed_hash_before_concurrent_joins() {
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let admitted_hash = [0x44; 16];
        let mut store = CallbackTicketStore::default();
        store.reserve(server_request(server, 17, 1), now).unwrap();
        let owner = store
            .claim_session(hello(Some(server), 17, admitted_hash), now)
            .unwrap()
            .unwrap();
        assert_eq!(
            store.tickets[0].peer.expected_user_hash,
            Some(admitted_hash)
        );

        let mut conflicting = server_request(server, 17, 2);
        conflicting.peer.expected_user_hash = Some([0x45; 16]);
        assert!(matches!(
            store.reserve(conflicting, now),
            Ok(Ed2kCallbackReservation::Dispatch(_))
        ));
        assert_eq!(store.session_current(&owner, now), Ok(Some(download(1))));
    }

    #[test]
    fn late_dispatch_mark_after_complete_session_is_explicitly_settled() {
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let observed = hello(Some(server), 17, [0x55; 16]);
        let mut store = CallbackTicketStore::default();
        let permit = dispatch_permit(store.reserve(server_request(server, 17, 1), now).unwrap());
        let owner = store.claim_session(observed, now).unwrap().unwrap();
        store.acknowledge_session_current(&owner, now).unwrap();
        store.finish_session(&owner, now).unwrap();

        assert_eq!(
            store.mark_dispatched(permit, now),
            Ed2kCallbackDispatchOutcome::Settled
        );
    }

    #[test]
    fn session_residuals_receive_a_fresh_bounded_redispatch_deadline() {
        let now = Instant::now();
        let after_original_expiry = now + Duration::from_secs(2);
        let server = "192.0.2.10:4661".parse().unwrap();
        let observed = hello(Some(server), 17, [0x55; 16]);
        let mut first = server_request(server, 17, 1);
        first.valid_for = Duration::from_secs(1);
        let mut store = CallbackTicketStore::default();
        store.reserve(first, now).unwrap();
        let owner = store.claim_session(observed, now).unwrap().unwrap();

        assert!(matches!(
            store.reserve(server_request(server, 17, 2), after_original_expiry),
            Ok(Ed2kCallbackReservation::Joined { .. })
        ));
        store
            .acknowledge_session_current(&owner, after_original_expiry)
            .unwrap();
        store.finish_session(&owner, after_original_expiry).unwrap();

        assert_eq!(store.tickets.len(), 1);
        assert_eq!(store.tickets[0].downloads, vec![download(2)]);
        assert_eq!(store.tickets[0].state, CallbackTicketState::NeedsDispatch);
        assert_eq!(
            store.tickets[0].expires_at,
            after_original_expiry + Duration::from_secs(45)
        );
    }

    #[test]
    fn capacity_failure_does_not_partially_strengthen_ticket_identity() {
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let mut store = CallbackTicketStore::new(2, 1);
        store.reserve(server_request(server, 17, 1), now).unwrap();
        let original = store.tickets[0].clone();
        let mut rejected = server_request(server, 17, 2);
        rejected.peer.expected_user_hash = Some([0x44; 16]);

        assert_eq!(
            store.reserve(rejected, now),
            Err(Ed2kCallbackTicketError::DownloadCapacity)
        );
        assert_eq!(store.tickets[0], original);
    }

    #[test]
    fn fast_dispatch_completion_is_recorded_while_the_session_owns_the_ticket() {
        let now = Instant::now();
        let server = "192.0.2.10:4661".parse().unwrap();
        let mut store = CallbackTicketStore::default();
        let permit = dispatch_permit(store.reserve(server_request(server, 17, 1), now).unwrap());
        let token = store
            .claim_session(hello(Some(server), 17, [0x55; 16]), now)
            .unwrap()
            .unwrap();

        assert_eq!(
            store.mark_dispatched(permit, now),
            Ed2kCallbackDispatchOutcome::Armed
        );
        assert!(matches!(
            store.tickets[0].state,
            CallbackTicketState::SessionOwned {
                prior_state: CallbackTicketReadyState::Armed,
                ..
            }
        ));
        store.finish_session(&token, now).unwrap();
        assert_eq!(store.tickets[0].state, CallbackTicketState::NeedsDispatch);
    }

    #[test]
    fn ticket_constructors_reject_unclaimable_protocol_identity() {
        let server: SocketAddr = "192.0.2.10:4661".parse().unwrap();
        let normalized = Ed2kCallbackTicketRequest::server(
            server,
            17,
            Some([0; 16]),
            4662,
            download(1),
            Duration::from_secs(45),
        )
        .unwrap();
        assert_eq!(normalized.peer.expected_user_hash, None);
        assert!(matches!(
            Ed2kCallbackTicketRequest::server(
                server,
                17,
                None,
                0,
                download(1),
                Duration::from_secs(45),
            ),
            Err(Ed2kCallbackTicketError::ZeroTcpPort)
        ));
        assert!(matches!(
            Ed2kCallbackTicketRequest::server(
                server,
                17,
                None,
                4662,
                download(1),
                ED2K_CALLBACK_TICKET_MAX_LIFETIME + Duration::from_secs(1),
            ),
            Err(Ed2kCallbackTicketError::LifetimeTooLong)
        ));
        assert!(matches!(
            Ed2kCallbackTicketRequest::kad_buddy(
                [0; 16],
                None,
                17,
                [0x33; 16],
                Ipv4Addr::new(192, 0, 2, 1),
                4662,
                download(1),
                Duration::from_secs(45),
            ),
            Err(Ed2kCallbackTicketError::InvalidBuddyId)
        ));
        assert!(matches!(
            Ed2kCallbackTicketRequest::kad_buddy(
                [0x22; 16],
                None,
                17,
                [0; 16],
                Ipv4Addr::new(192, 0, 2, 1),
                4662,
                download(1),
                Duration::from_secs(45),
            ),
            Err(Ed2kCallbackTicketError::MissingUserHash)
        ));
        assert!(matches!(
            Ed2kCallbackTicketRequest::direct_udp(
                "[2001:db8::1]:4672".parse().unwrap(),
                17,
                [0x33; 16],
                4662,
                download(1),
                Duration::from_secs(45),
            ),
            Err(Ed2kCallbackTicketError::InvalidDirectEndpoint)
        ));
    }

    #[test]
    fn oversized_hash_first_work_is_split_across_bounded_claims() {
        let now = Instant::now();
        let server_a: SocketAddr = "192.0.2.10:4661".parse().unwrap();
        let server_b: SocketAddr = "192.0.2.20:4661".parse().unwrap();
        let mut store = CallbackTicketStore::default();
        for index in 0..258u16 {
            let mut request = server_request(if index < 129 { server_a } else { server_b }, 17, 1);
            request.peer.expected_user_hash = Some([0x44; 16]);
            let mut hash = [0; 16];
            hash[..2].copy_from_slice(&index.to_le_bytes());
            request.download.file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(hash);
            store.reserve(request, now).unwrap();
        }

        let first = store
            .lease(hello(None, 999, [0x44; 16]), now)
            .unwrap()
            .unwrap();
        assert_eq!(first.downloads.len(), 129);
        store.commit(&first.token, now).unwrap();
        let second = store
            .lease(hello(None, 999, [0x44; 16]), now)
            .unwrap()
            .unwrap();
        assert_eq!(second.downloads.len(), 129);
    }
}
