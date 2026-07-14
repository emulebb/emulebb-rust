//! The client-to-client UDP source-reask runtime loop (`docs/design/udp-source-reask.md`
//! §4.2-§4.6). Lives in `emulebb-ed2k` because it composes the crate-internal
//! [`super::ReaskService`] with the shared Kad UDP socket via [`DhtNode`]; core
//! spawns it (on by default, gated by `Ed2kRuntimeConfig.enable_udp_reask`).
//!
//! It registers a foreign-datagram handler on the shared socket (inbound reask
//! packets that fail Kad decode arrive here) and `select!`s that against a
//! periodic tick. All reask *decisions* live in the I/O-free
//! [`super::ReaskService`]; this is the thin async shell doing the socket I/O.
//!
//! Wired directions: the uploader **reciprocity** answer; the downloader
//! **detach hook** (a queued UDP-eligible source detaches onto periodic reask,
//! dropped on `RetryTcp`); the **downloader origination** of
//! `OP_REASKCALLBACKUDP` to a LowID source's buddy; and the **buddy relay** legs
//! (relay an inbound `OP_REASKCALLBACKUDP` as `OP_REASKCALLBACKTCP`, and answer a
//! relayed reask over UDP) — both via [`super::buddy_relay`]. Gated behind
//! `enable_udp_reask` (on by default).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use emulebb_kad_dht::{DhtNode, ForeignDatagramHandler};
use emulebb_kad_proto::Ed2kHash;
use tokio::sync::mpsc;
use tracing::{debug, trace};

use super::service::{ReaskInboundOutcome, ReaskService, ReaskTickPacing, TransferReaskInfo};
use super::state::{ReaskAction, ReaskSource};
use crate::buddy_socket::BuddySocketRegistry;
use crate::ed2k_transfer::Ed2kTransferRuntime;
use crate::ipfilter::IpFilter;
use crate::reachability::ExternalReachability;

/// A command from a download session to the reask loop: detach a just-queued
/// source onto UDP reask, or drop one that no longer needs reasking. Public so
/// core can carry the channel; constructed in-crate by the download session.
#[derive(Debug, Clone)]
pub enum ReaskCommand {
    /// Detach a source that queued us (eMuleBB §4.1 `QueuedDetached` transition),
    /// carrying its endpoint + buddy knowledge ([`ReaskDetachArgs`]).
    Register(ReaskDetachArgs),
    /// Drop a source by endpoint (transfer completed / no longer wanted).
    Remove { endpoint: (Ipv4Addr, u16) },
    /// Flag a source as No Needed Parts by endpoint (a TCP session just learned
    /// the peer serves no part we still need, oracle `DS_NONEEDEDPARTS`): its
    /// reask cadence doubles to `FILEREASKTIME * 2` (oracle `GetTimeUntilReask`,
    /// DownloadClient.cpp:2425-2431). Unknown endpoints are a no-op.
    MarkNoNeededParts { endpoint: (Ipv4Addr, u16) },
    /// Answer a buddy-relayed `OP_REASKCALLBACKTCP` over UDP (we are the firewalled
    /// *source*): answer the downloader at `dest` like an inbound `OP_REASKFILEPING`
    /// (oracle ListenSocket.cpp). Only the file hash is carried (reciprocity key).
    AnswerCallbackTcp {
        dest: SocketAddr,
        file_hash: Ed2kHash,
    },
    /// Originate an `OP_DIRECTCALLBACKREQ` to a firewalled type-6 source's Kad
    /// UDP endpoint so it TCP-connects back to us (oracle `CCS_DIRECTCALLBACK`).
    /// Sent over the shared client-UDP socket, obfuscated toward the source when
    /// its crypt key is known.
    SendDirectCallback(DirectCallbackArgs),
}

/// Inputs for [`ReaskSourceHandle::send_direct_callback`]: everything the loop
/// needs to encode and address a single `OP_DIRECTCALLBACKREQ`.
#[derive(Debug, Clone)]
pub struct DirectCallbackArgs {
    /// The source's Kad UDP endpoint (its eD2k IP + advertised `FT_SOURCEUPORT`).
    pub dest: SocketAddr,
    /// Our externally-advertised eD2k TCP port the source connects back to.
    pub our_tcp_port: u16,
    /// Our eD2k user hash (identifies the connect-back to the source).
    pub our_user_hash: [u8; 16],
    /// Our connect options (`GetMyConnectOptions(true, false)`).
    pub connect_options: u8,
    /// The source's user hash — obfuscation key material.
    pub dest_user_hash: Option<[u8; 16]>,
    /// Whether to obfuscate toward the source (`ShouldReceiveCryptUDPPackets`).
    pub obfuscate: bool,
}

/// Receiver end of the detach-command channel, owned by the reask loop.
pub type ReaskCommandReceiver = mpsc::Receiver<ReaskCommand>;

/// Inputs for [`ReaskSourceHandle::detach`]: the just-queued source's endpoint +
/// the buddy knowledge that gates a LowID buddy-relayed reask. Built by the
/// download session from the connected source's hello profile.
#[derive(Debug, Clone)]
pub struct ReaskDetachArgs {
    pub file_hash: Ed2kHash,
    pub endpoint: (Ipv4Addr, u16),
    /// The source's eD2k **TCP** port. Core's lease bookkeeping
    /// (`active_download_peer_endpoints` + the download source registry) is keyed
    /// by `(ip, tcp_port)` while `endpoint` is the UDP routing key, so the loop
    /// must address `SourceReleased` events by `(endpoint.ip, tcp_port)` or the
    /// release never matches and the lease leaks (RUST-PAR-017 DL-11).
    pub tcp_port: u16,
    pub udp_version: u8,
    /// Delay before the first detached UDP reask is due.
    ///
    /// `Duration::ZERO` is used for sources that have not just been asked over
    /// TCP. TCP-queued sources pass `FILE_REASK_TIME`, because MFC stamps
    /// `SetLastAskedTime()` when the TCP file request is sent and does not
    /// immediately reask the same source over UDP.
    pub initial_reask_delay: Duration,
    pub user_hash: Option<[u8; 16]>,
    pub should_crypt: bool,
    /// Source is a firewalled LowID client (oracle `HasLowID()`).
    pub low_id: bool,
    /// Source's Kad buddy endpoint from its hello (`GetBuddyIP`/`GetBuddyPort`).
    pub buddy_endpoint: Option<(Ipv4Addr, u16)>,
    /// Source's buddy id (`GetBuddyID`), only known via Kad source-finding.
    pub buddy_id: Option<[u8; 16]>,
}

/// Cloneable sender handle a download session uses to detach a queued source.
#[derive(Debug, Clone)]
pub struct ReaskSourceHandle(mpsc::Sender<ReaskCommand>);

impl ReaskSourceHandle {
    /// Detach a queued source onto UDP reask. Best-effort: a full/closed channel
    /// silently drops the command (the source just stays on its TCP path).
    pub(crate) fn detach(&self, args: ReaskDetachArgs) {
        let _ = self.0.try_send(ReaskCommand::Register(args));
    }

    /// Register a firewalled LowID Kad source (oracle source types 3/5) directly
    /// onto UDP reask, bypassing TCP: such a source is reachable only via its Kad
    /// buddy, so it never gets a direct TCP session to detach from. The reask loop
    /// then originates an `OP_REASKCALLBACKUDP` to the buddy on the normal cadence
    /// (oracle `CDownloadQueue::KademliaSearchFile` types 3/5 + `UDPReaskForDownload`
    /// LowID branch). Best-effort: a full/closed channel drops the registration
    /// (the source stays a server-callback candidate). Returns whether it was sent.
    pub fn register_kad_buddy_source(&self, args: ReaskDetachArgs) -> bool {
        self.0.try_send(ReaskCommand::Register(args)).is_ok()
    }

    /// Drop a source from reask state by endpoint. Best-effort.
    pub(crate) fn remove(&self, endpoint: (Ipv4Addr, u16)) {
        let _ = self.0.try_send(ReaskCommand::Remove { endpoint });
    }

    /// Flag a detached source as No Needed Parts (oracle `DS_NONEEDEDPARTS`):
    /// its UDP reasks switch to the doubled `FILEREASKTIME * 2` cadence (oracle
    /// `GetTimeUntilReask`, DownloadClient.cpp:2425-2431). Best-effort: a
    /// full/closed channel or an unknown endpoint silently no-ops (the source
    /// keeps its normal cadence).
    pub fn mark_no_needed_parts(&self, endpoint: (Ipv4Addr, u16)) {
        let _ = self
            .0
            .try_send(ReaskCommand::MarkNoNeededParts { endpoint });
    }

    /// Answer a buddy-relayed `OP_REASKCALLBACKTCP` over UDP (we are the source).
    /// Best-effort: a full/closed channel drops the answer (downloader retries/TCP).
    pub(crate) fn answer_callback_tcp(&self, dest: std::net::SocketAddr, file_hash: Ed2kHash) {
        let _ = self
            .0
            .try_send(ReaskCommand::AnswerCallbackTcp { dest, file_hash });
    }

    /// Originate an `OP_DIRECTCALLBACKREQ` to a firewalled type-6 source. The
    /// loop encodes/obfuscates it and sends it over the shared client-UDP
    /// socket. Best-effort: a full/closed channel drops it (the source stays a
    /// server/Kad-callback candidate). Returns whether it was queued.
    pub fn send_direct_callback(&self, args: DirectCallbackArgs) -> bool {
        self.0
            .try_send(ReaskCommand::SendDirectCallback(args))
            .is_ok()
    }
}

/// Create the detach-command channel: the handle goes to download sessions, the
/// receiver to [`run_ed2k_udp_reask_loop`].
pub fn reask_command_channel() -> (ReaskSourceHandle, ReaskCommandReceiver) {
    let (tx, rx) = mpsc::channel(REASK_COMMAND_CHANNEL_BOUND);
    (ReaskSourceHandle(tx), rx)
}

/// A typed event the reask loop raises for core to act on (alert-style). Events
/// flow loop -> core; commands flow core -> loop ([`ReaskCommand`]).
#[derive(Debug, Clone)]
pub enum ReaskEvent {
    /// A detached source's UDP lease must be released back to core: its endpoint is
    /// still held in core's `active_download_peer_endpoints` + download source
    /// registry. The loop raises this whenever it drops a detached source, so core
    /// frees the lease and a later cycle (or the following `SourceReady`) reconnects
    /// it over TCP. Must precede the `SourceReady` for the same source.
    ///
    /// `endpoint` is the source's **TCP** endpoint (`ReaskDetachArgs::tcp_port`) —
    /// the key core leased it under — NOT the UDP endpoint the loop routes on;
    /// core matches it directly against its TCP-keyed lease sets.
    SourceReleased { endpoint: (Ipv4Addr, u16) },
    /// A detached source UDP-answered `OP_FILENOTFOUND` for `file_hash` (oracle
    /// `CUpDownClient::UDPReaskFNF`, `DownloadClient.cpp:1774-1795`): besides the
    /// `SourceReleased` that follows, core dead-lists the (source, file) pair for
    /// the oracle 45-minute block, exactly like the TCP `OP_FILEREQANSNOFIL` path.
    /// `endpoint` is the peer's UDP endpoint (the only key the loop holds); core
    /// resolves the full source identity from its registry by (ip, file).
    SourceDead {
        file_hash: Ed2kHash,
        endpoint: (Ipv4Addr, u16),
    },
    /// A queued source for `file_hash` reported a queue rank at/under the re-engage
    /// threshold: a slot is imminent, so core reconnects over TCP now. The loop has
    /// already removed the source + released its lease via a preceding `SourceReleased`.
    SourceReady { file_hash: Ed2kHash },
    /// An inbound `OP_DIRECTCALLBACKREQ` arrived: a peer that cannot reach us over
    /// TCP (we are the firewalled LowID side that advertised direct UDP callback)
    /// asks us to connect out to it. Core verifies the firewalled gate
    /// (oracle `Kademlia::IsRunning() && Kademlia::IsFirewalled()`) and TCP-connects
    /// out to `(requester_ip, tcp_port)` with the requester's user hash + connect
    /// options. The loop has no TCP-connect/identity state, so core acts on this.
    DirectCallbackReq {
        requester_ip: Ipv4Addr,
        tcp_port: u16,
        user_hash: [u8; 16],
        connect_options: u8,
    },
}

/// Receiver end of the reask-event channel, owned by core's re-engage consumer.
pub type ReaskEventReceiver = mpsc::UnboundedReceiver<ReaskEvent>;
/// Sender end, held by [`run_ed2k_udp_reask_loop`].
pub type ReaskEventSender = mpsc::UnboundedSender<ReaskEvent>;

/// Create the reask-event channel: the sender goes to [`run_ed2k_udp_reask_loop`],
/// the receiver to core's re-engage consumer. Unbounded because events are rare
/// (only low-rank acks) and the loop must never block raising one.
pub fn reask_event_channel() -> (ReaskEventSender, ReaskEventReceiver) {
    mpsc::unbounded_channel()
}

/// How long to wait for a reask reply before counting it a UDP failure.
const REASK_REPLY_TIMEOUT: Duration = Duration::from_secs(30);
/// How often the loop checks for due reasks + drains timed-out ones. Sources
/// reask on the ~29 min `FILE_REASK_TIME` cadence, so a coarse tick suffices.
const REASK_TICK_INTERVAL: Duration = Duration::from_secs(30);
/// Bound on the inbound channel so a flood of non-Kad datagrams cannot grow it
/// without limit; excess is dropped (the sender forces a TCP reconnect anyway).
const REASK_INBOUND_CHANNEL_BOUND: usize = 256;
/// Bound on the detach-command channel; a full channel just drops the detach
/// (the source keeps its TCP behaviour), so a modest bound is safe.
const REASK_COMMAND_CHANNEL_BOUND: usize = 256;
/// Reconnect a queued source over TCP when an `OP_REASKACK` rank is at/below this:
/// a slot is imminent, so claim it now (eMule reconnects near the queue front).
/// Conservative to avoid premature reconnects on still-deep ranks.
const REENGAGE_RANK_THRESHOLD: u16 = 4;

/// Hex preview of a datagram for reask packet-trace diagnostics (capped so a
/// stray large datagram cannot blow up the log line).
fn hex_preview(bytes: &[u8]) -> String {
    const MAX: usize = 64;
    let shown = &bytes[..bytes.len().min(MAX)];
    let mut out = String::with_capacity(shown.len() * 2 + 8);
    for b in shown {
        out.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > MAX {
        out.push_str(&format!("…(+{} more)", bytes.len() - MAX));
    }
    out
}

/// Run the UDP source-reask loop until `shutdown` is set. Spawned by core only
/// when `enable_udp_reask` is on (the default); the flag exists so the transport
/// can be disabled to fall back to the held-TCP path if needed.
#[expect(
    clippy::too_many_arguments,
    reason = "flat protocol or runtime boundary"
)]
pub async fn run_ed2k_udp_reask_loop(
    dht: DhtNode,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    mut commands: ReaskCommandReceiver,
    events: ReaskEventSender,
    user_hash: [u8; 16],
    udp_version: u8,
    public_ip: ExternalReachability,
    ip_filter: IpFilter,
    buddy_registry: BuddySocketRegistry,
    shutdown: Arc<AtomicBool>,
) {
    let mut service = ReaskService::new(user_hash, udp_version, public_ip.clone());

    // Inbound: the foreign-datagram handler runs in the Kad recv loop (sync), so
    // it just forwards the raw datagram to this task over a bounded channel.
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(REASK_INBOUND_CHANNEL_BOUND);
    let handler: ForeignDatagramHandler = Arc::new(move |data: &[u8], from: SocketAddr| {
        // `try_send` is non-blocking; if the channel is full or closed we decline
        // (return false) so the Kad recv loop keeps its normal decode-failure path.
        tx.try_send((data.to_vec(), from)).is_ok()
    });
    if !dht.set_foreign_datagram_handler(handler) {
        debug!("ed2k udp reask: a foreign-datagram handler was already registered; loop idle");
        return;
    }

    let mut ticker = tokio::time::interval(REASK_TICK_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    debug!("ed2k udp reask loop started");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        tokio::select! {
            maybe = rx.recv() => {
                let Some((data, from)) = maybe else { break };
                handle_inbound_datagram(
                    &mut service, &dht, &transfer_runtime, &events, &ip_filter,
                    &buddy_registry, user_hash, public_ip.octets(), &data, from,
                )
                .await;
            }
            maybe = commands.recv() => {
                let Some(command) = maybe else { break };
                // AnswerCallbackTcp / SendDirectCallback need async UDP I/O
                // (handled here); the rest are sync.
                match command {
                    ReaskCommand::AnswerCallbackTcp { dest, file_hash } => {
                        super::buddy_relay::answer_buddy_relayed_reask(
                            &dht, &transfer_runtime, public_ip.octets(), dest, file_hash,
                        )
                        .await;
                    }
                    ReaskCommand::SendDirectCallback(args) => {
                        send_direct_callback_req(&dht, public_ip.octets(), args).await;
                    }
                    other => apply_reask_command(&mut service, &events, other),
                }
            }
            _ = ticker.tick() => {
                drive_reask_tick(&mut service, &dht, &transfer_runtime, &events).await;
            }
        }
    }
    debug!("ed2k udp reask loop stopped");
}

/// Decide the loop->core events for a routed downloader reply. Pure so the
/// re-engage / lease-release ordering is unit-testable without socket I/O.
///
/// Invariant: a `SourceReleased` is always emitted *before* a `SourceReady` so
/// core frees the held UDP lease before the re-engage attempt re-acquires it
/// (else `acquire_direct_download_source_leases` defers it forever — the B1 leak).
fn routed_reply_events(
    action: ReaskAction,
    file_hash: Ed2kHash,
    endpoint: (Ipv4Addr, u16),
    lease_endpoint: (Ipv4Addr, u16),
) -> Vec<ReaskEvent> {
    match action {
        // Slot imminent: release the lease, then ask core to reconnect over TCP.
        // The release carries the TCP lease key, not the UDP routing endpoint
        // (core's lease sets are TCP-keyed; RUST-PAR-017 DL-11).
        ReaskAction::UpdatedRank(rank) if rank <= REENGAGE_RANK_THRESHOLD => vec![
            ReaskEvent::SourceReleased {
                endpoint: lease_endpoint,
            },
            ReaskEvent::SourceReady { file_hash },
        ],
        // Uploader no longer has the file (OP_FILENOTFOUND): dead-list it first
        // (oracle UDPReaskFNF AddDeadSource, DownloadClient.cpp:1781), then free
        // its lease. Order matters: the dead-list gate must be in place before
        // the released source becomes re-acquirable. SourceDead keeps the UDP
        // endpoint (core's FNF resolver keys on the IP only); the release again
        // carries the TCP lease key.
        ReaskAction::DropSource => vec![
            ReaskEvent::SourceDead {
                file_hash,
                endpoint,
            },
            ReaskEvent::SourceReleased {
                endpoint: lease_endpoint,
            },
        ],
        // Still queued / transient: keep the source on UDP reask, lease unchanged.
        _ => Vec::new(),
    }
}

/// Whether an inbound reask datagram's source IP is filtered/banned and must be
/// dropped (IPv4-only; a non-V4 sender is dropped as a non-client too). Pure so
/// the IP-filter enforcement is unit-testable without socket I/O.
fn is_filtered_reask_source(from: SocketAddr, ip_filter: &IpFilter) -> bool {
    match from {
        SocketAddr::V4(v4) => ip_filter.is_filtered(*v4.ip()),
        SocketAddr::V6(_) => true,
    }
}

fn udp_reask_sent_body() -> serde_json::Value {
    serde_json::json!({ "outcome": "sent", "transport": "udp", "reaskCount": 1 })
}

/// Route one inbound datagram through the service and act on the outcome.
#[expect(
    clippy::too_many_arguments,
    reason = "flat protocol or runtime boundary"
)]
async fn handle_inbound_datagram(
    service: &mut ReaskService,
    dht: &DhtNode,
    transfer_runtime: &Ed2kTransferRuntime,
    events: &ReaskEventSender,
    ip_filter: &IpFilter,
    buddy_registry: &BuddySocketRegistry,
    our_user_hash: [u8; 16],
    our_public_ip: [u8; 4],
    data: &[u8],
    from: SocketAddr,
) {
    // Drop datagrams from a filtered IP first (master ClientUDPSocket.cpp:129
    // IsFiltered).
    if is_filtered_reask_source(from, ip_filter) {
        trace!("ed2k udp reask: dropping inbound datagram from filtered IP {from}");
        return;
    }
    // Drop datagrams from a banned IP (master ClientUDPSocket.cpp:129
    // IsBannedClient(sin_addr)). The user-hash half of a ban is not knowable from
    // a bare UDP datagram, so only the IP key is checked here.
    if let SocketAddr::V4(v4) = from
        && transfer_runtime.is_client_banned(Some(*v4.ip()), None)
    {
        trace!("ed2k udp reask: dropping inbound datagram from banned IP {from}");
        return;
    }
    trace!(
        "ed2k udp reask: PKT-IN <- {from} ({} bytes) hex={}",
        data.len(),
        hex_preview(data)
    );
    super::dump::dump_client_udp_recv(from, &our_user_hash, our_public_ip, data);
    match service.handle_inbound(data, from, Instant::now()) {
        ReaskInboundOutcome::RoutedReply {
            file_hash,
            endpoint,
            lease_endpoint,
            action,
        } => {
            trace!("ed2k udp reask: routed reply from {from}: {action:?} (file {file_hash})");
            // A re-engageable rank means we hand the source back to TCP first.
            if matches!(action, ReaskAction::UpdatedRank(rank) if rank <= REENGAGE_RANK_THRESHOLD) {
                service.remove_source(endpoint.0, endpoint.1);
            }
            // Emit loop->core events (lease release ordered before any re-engage).
            for event in routed_reply_events(action, file_hash, endpoint, lease_endpoint) {
                if let ReaskEvent::SourceReady { file_hash } = &event {
                    trace!("ed2k udp reask: re-engage SourceReady for {file_hash}");
                }
                let _ = events.send(event);
            }
        }
        ReaskInboundOutcome::AnswerNeeded { ping, from } => {
            // Answer the peer's OP_REASKFILEPING from upload-queue/catalog state.
            match transfer_runtime
                .reask_reciprocity_reply(&ping, from, our_public_ip)
                .await
            {
                Some(reply) => {
                    if let Err(err) = dht.send_raw_datagram(from, &reply.bytes).await {
                        trace!("ed2k udp reask: reciprocity reply to {from} failed: {err}");
                    } else {
                        super::dump::dump_client_udp_send(from, &reply);
                    }
                }
                // Deliberate silence (force TCP / file mismatch); nothing to send.
                None => trace!("ed2k udp reask: inbound reask from {from} answered with silence"),
            }
        }
        ReaskInboundOutcome::BuddyRelay { callback, from } => {
            // The relay forwards the post-buddy-id tail verbatim (oracle
            // ClientUDPSocket.cpp memcpy(packet+16)), so our udp_version does not
            // gate it.
            super::buddy_relay::relay_buddy_reask_callback(buddy_registry, &callback, from);
        }
        ReaskInboundOutcome::DirectCallbackReq { req, from } => {
            // We have no TCP-connect / hello-identity / firewalled-verdict state
            // here, so raise an event for core to gate (Kademlia::IsRunning() &&
            // IsFirewalled()) and connect out (oracle ClientUDPSocket.cpp
            // OP_DIRECTCALLBACKREQ -> TryToConnectOrDelete). IPv4-only: a non-V4
            // requester can never be a client source, so it is dropped.
            if let SocketAddr::V4(v4) = from {
                trace!(
                    "ed2k udp reask: inbound OP_DIRECTCALLBACKREQ from {from} \
                     (tcp_port={}); raising connect-out event",
                    req.tcp_port
                );
                let _ = events.send(ReaskEvent::DirectCallbackReq {
                    requester_ip: *v4.ip(),
                    tcp_port: req.tcp_port,
                    user_hash: req.user_hash,
                    connect_options: req.connect_options,
                });
            } else {
                trace!(
                    "ed2k udp reask: dropping OP_DIRECTCALLBACKREQ from non-IPv4 requester {from}"
                );
            }
        }
        ReaskInboundOutcome::Ignored => {}
    }
}

/// Apply a download session's detach command to the reask source state.
fn apply_reask_command(
    service: &mut ReaskService,
    events: &ReaskEventSender,
    command: ReaskCommand,
) {
    match command {
        ReaskCommand::Register(args) => {
            let ReaskDetachArgs {
                file_hash,
                endpoint,
                tcp_port,
                udp_version,
                initial_reask_delay,
                user_hash,
                should_crypt,
                low_id,
                buddy_endpoint,
                buddy_id,
            } = args;
            let now = Instant::now();
            let mut source = ReaskSource::new(endpoint, file_hash, udp_version, now)
                .with_lease_endpoint((endpoint.0, tcp_port));
            source.next_reask = now + initial_reask_delay;
            if let Some(hash) = user_hash {
                source = source.with_obfuscation(hash, should_crypt);
            }
            source = source.with_buddy(low_id, buddy_endpoint, buddy_id);
            trace!(
                "ed2k udp reask: detaching source {}:{} for {} onto UDP reask",
                endpoint.0, endpoint.1, file_hash
            );
            service.register_source(file_hash, source);
        }
        ReaskCommand::Remove { endpoint } => {
            // Only release the lease if this endpoint was a detached source we held;
            // a Remove for an unknown endpoint must not free a lease core never gave
            // us. The release carries the source's TCP lease key, not the UDP
            // routing endpoint (core's lease sets are TCP-keyed).
            if let Some(lease_endpoint) = service.remove_source(endpoint.0, endpoint.1) {
                let _ = events.send(ReaskEvent::SourceReleased {
                    endpoint: lease_endpoint,
                });
            }
        }
        ReaskCommand::MarkNoNeededParts { endpoint } => {
            // NNP flag (oracle DS_NONEEDEDPARTS): double the source's reask
            // cadence. No event owed — the lease/registry hold is core-side.
            service.mark_no_needed_parts(endpoint.0, endpoint.1, Instant::now());
        }
        // Handled inline in the loop (needs async I/O); never routed here.
        ReaskCommand::AnswerCallbackTcp { .. } | ReaskCommand::SendDirectCallback(_) => {}
    }
}

/// Originate one `OP_DIRECTCALLBACKREQ` over the shared client-UDP socket (we
/// are a downloader asking a firewalled type-6 source to connect back). Mirrors
/// the oracle `CCS_DIRECTCALLBACK` send: our TCP port + userhash + connect
/// options, obfuscated toward the source when its crypt key is known.
async fn send_direct_callback_req(dht: &DhtNode, our_public_ip: [u8; 4], args: DirectCallbackArgs) {
    let target = super::outbound::OutboundReaskTarget {
        dest_user_hash: args.dest_user_hash.unwrap_or([0u8; 16]),
        our_public_ip,
        obfuscate: args.obfuscate && args.dest_user_hash.is_some(),
    };
    let datagram = super::outbound::build_direct_callback_req_datagram(
        args.our_tcp_port,
        &args.our_user_hash,
        args.connect_options,
        &target,
    );
    match dht.send_raw_datagram(args.dest, &datagram.bytes).await {
        Ok(()) => {
            super::dump::dump_client_udp_send(args.dest, &datagram);
            trace!("ed2k udp: sent OP_DIRECTCALLBACKREQ to {}", args.dest);
        }
        Err(err) => trace!(
            "ed2k udp: OP_DIRECTCALLBACKREQ to {} failed: {err}",
            args.dest
        ),
    }
}

/// Drive one reask tick: send due reask pings and account timed-out reasks.
/// Per-file transfer info (our part availability) is pulled from the transfer
/// runtime before the sync `tick`, since the source state lives in the service.
async fn drive_reask_tick(
    service: &mut ReaskService,
    dht: &DhtNode,
    transfer_runtime: &Ed2kTransferRuntime,
    events: &ReaskEventSender,
) {
    // Pre-fetch each file's reask info so the sync `tick` closure can look it up.
    let mut info_by_file: std::collections::HashMap<Ed2kHash, TransferReaskInfo> =
        std::collections::HashMap::new();
    for file_hash in service.registered_file_hashes() {
        let info = transfer_runtime.reask_transfer_info(&file_hash).await;
        info_by_file.insert(file_hash, info);
    }

    // Global reask pacing / round-robin (eMule CDownloadQueue::Process
    // m_udcounter + SendNextUDPPacket): the shared coordinator round-robins which
    // file gets a reask slot this tick and enforces a global inter-reask floor,
    // and gates each file on the per-file UDP source cap
    // (GetMaxSourcePerFileUDP > GetSourceCount). `next_reask_file_slot` returns
    // None when the global inter-reask floor has not elapsed; even then we never
    // send beyond the per-file UDP cap, so the None branch still runs the paced
    // tick with the `admit_udp` gate (rotate_offset 0) rather than the unbounded
    // tick that would bypass the cap (master m_udcounter intent). The per-source
    // 29-min due gate (due_datagrams) holds either way (paced only suppresses).
    let registered_file_count = info_by_file.len();
    let rotate_offset = transfer_runtime.next_reask_file_slot(registered_file_count);
    let info_lookup = |file_hash: &Ed2kHash| {
        info_by_file
            .get(file_hash)
            .cloned()
            .unwrap_or(TransferReaskInfo {
                part_status: None,
                complete_source_count: 0,
            })
    };
    let admit_udp = |_file_hash: &Ed2kHash, source_count: usize| {
        transfer_runtime.can_reask_file_via_udp(source_count)
    };
    let out = service.tick_paced(
        Instant::now(),
        REASK_REPLY_TIMEOUT,
        info_lookup,
        &ReaskTickPacing {
            rotate_offset: rotate_offset.unwrap_or(0),
            admit: Some(&admit_udp),
        },
    );
    for (addr, datagram) in out.send {
        match dht.send_raw_datagram(addr, &datagram.bytes).await {
            Ok(()) => {
                super::dump::dump_client_udp_send(addr, &datagram);
                trace!(
                    "ed2k udp reask: PKT-OUT reask ping -> {addr} ({} bytes) hex={}",
                    datagram.bytes.len(),
                    hex_preview(&datagram.bytes),
                );
                // `reask_sent` (uniform-diagnostics-v2 schema §3.5): a UDP source
                // reask actually went out on the wire to `addr`.
                crate::diag_event::emit(
                    "sched",
                    "reask_sent",
                    "info",
                    serde_json::json!({ "peer": addr.to_string() }),
                    udp_reask_sent_body(),
                );
            }
            Err(err) => trace!("ed2k udp reask: send to {addr} failed: {err}"),
        }
    }
    for (addr, action) in out.timed_out {
        trace!("ed2k udp reask: reask to {addr} timed out: {action:?}");
        // On RetryTcp the source exhausted its UDP-reask budget: drop it + release
        // its lease so core's next cycle re-acquires it over TCP. (RetryUdp keeps reasking.)
        if matches!(action, ReaskAction::RetryTcp)
            && let SocketAddr::V4(v4) = addr
        {
            let endpoint = (*v4.ip(), v4.port());
            if let Some(lease_endpoint) = service.remove_source(endpoint.0, endpoint.1) {
                let _ = events.send(ReaskEvent::SourceReleased {
                    endpoint: lease_endpoint,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests;
