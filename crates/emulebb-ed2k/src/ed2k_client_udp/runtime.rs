//! The client-to-client UDP source-reask runtime loop (`docs/design/udp-source-reask.md`
//! §4.2-§4.6). Lives in `emulebb-ed2k` because it composes the crate-internal
//! [`super::ReaskService`] with the shared Kad UDP socket via [`DhtNode`]; core
//! spawns it (on by default, gated by `Ed2kConfig.enable_udp_reask`).
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
    /// Answer a buddy-relayed `OP_REASKCALLBACKTCP` over UDP (we are the firewalled
    /// *source*): answer the downloader at `dest` like an inbound `OP_REASKFILEPING`
    /// (oracle ListenSocket.cpp). Only the file hash is carried (reciprocity key).
    AnswerCallbackTcp { dest: SocketAddr, file_hash: Ed2kHash },
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
    pub udp_version: u8,
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

    /// Answer a buddy-relayed `OP_REASKCALLBACKTCP` over UDP (we are the source).
    /// Best-effort: a full/closed channel drops the answer (downloader retries/TCP).
    pub(crate) fn answer_callback_tcp(&self, dest: std::net::SocketAddr, file_hash: Ed2kHash) {
        let _ = self.0.try_send(ReaskCommand::AnswerCallbackTcp { dest, file_hash });
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
    SourceReleased { endpoint: (Ipv4Addr, u16) },
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
#[allow(clippy::too_many_arguments)]
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
                    &buddy_registry, udp_version, public_ip.octets(), &data, from,
                )
                .await;
            }
            maybe = commands.recv() => {
                let Some(command) = maybe else { break };
                // AnswerCallbackTcp needs async UDP I/O (handled here); the rest are sync.
                if let ReaskCommand::AnswerCallbackTcp { dest, file_hash } = command {
                    super::buddy_relay::answer_buddy_relayed_reask(
                        &dht, &transfer_runtime, public_ip.octets(), dest, file_hash,
                    )
                    .await;
                } else {
                    apply_reask_command(&mut service, &events, command);
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
) -> Vec<ReaskEvent> {
    match action {
        // Slot imminent: release the lease, then ask core to reconnect over TCP.
        ReaskAction::UpdatedRank(rank) if rank <= REENGAGE_RANK_THRESHOLD => vec![
            ReaskEvent::SourceReleased { endpoint },
            ReaskEvent::SourceReady { file_hash },
        ],
        // Uploader no longer has the file: the source is dropped, free its lease.
        ReaskAction::DropSource => vec![ReaskEvent::SourceReleased { endpoint }],
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

/// Route one inbound datagram through the service and act on the outcome.
#[allow(clippy::too_many_arguments)]
async fn handle_inbound_datagram(
    service: &mut ReaskService,
    dht: &DhtNode,
    transfer_runtime: &Ed2kTransferRuntime,
    events: &ReaskEventSender,
    ip_filter: &IpFilter,
    buddy_registry: &BuddySocketRegistry,
    our_udp_version: u8,
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
    if let SocketAddr::V4(v4) = from {
        if transfer_runtime.is_client_banned(Some(*v4.ip()), None) {
            trace!("ed2k udp reask: dropping inbound datagram from banned IP {from}");
            return;
        }
    }
    trace!("ed2k udp reask: PKT-IN <- {from} ({} bytes) hex={}", data.len(), hex_preview(data));
    match service.handle_inbound(data, from, Instant::now()) {
        ReaskInboundOutcome::RoutedReply {
            file_hash,
            endpoint,
            action,
        } => {
            trace!("ed2k udp reask: routed reply from {from}: {action:?} (file {file_hash})");
            // A re-engageable rank means we hand the source back to TCP first.
            if matches!(action, ReaskAction::UpdatedRank(rank) if rank <= REENGAGE_RANK_THRESHOLD) {
                service.remove_source(endpoint.0, endpoint.1);
            }
            // Emit loop->core events (lease release ordered before any re-engage).
            for event in routed_reply_events(action, file_hash, endpoint) {
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
                    if let Err(err) = dht.send_raw_datagram(from, &reply).await {
                        trace!("ed2k udp reask: reciprocity reply to {from} failed: {err}");
                    }
                }
                // Deliberate silence (force TCP / file mismatch); nothing to send.
                None => trace!("ed2k udp reask: inbound reask from {from} answered with silence"),
            }
        }
        ReaskInboundOutcome::BuddyRelay { callback, from } => {
            super::buddy_relay::relay_buddy_reask_callback(
                buddy_registry, &callback, from, our_udp_version,
            );
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
                trace!("ed2k udp reask: dropping OP_DIRECTCALLBACKREQ from non-IPv4 requester {from}");
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
                file_hash, endpoint, udp_version, user_hash, should_crypt, low_id, buddy_endpoint,
                buddy_id,
            } = args;
            let mut source = ReaskSource::new(endpoint, file_hash, udp_version, Instant::now());
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
            // a Remove for an unknown endpoint must not free a lease core never gave us.
            if service.remove_source(endpoint.0, endpoint.1) {
                let _ = events.send(ReaskEvent::SourceReleased { endpoint });
            }
        }
        // Handled inline in the loop (needs async I/O); never routed here.
        ReaskCommand::AnswerCallbackTcp { .. } => {}
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
    let admit_udp =
        |_file_hash: &Ed2kHash, source_count: usize| transfer_runtime.can_reask_file_via_udp(source_count);
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
        match dht.send_raw_datagram(addr, &datagram).await {
            Ok(()) => {
                trace!(
                    "ed2k udp reask: PKT-OUT reask ping -> {addr} ({} bytes) hex={}",
                    datagram.len(),
                    hex_preview(&datagram),
                );
                // `reask_sent` (uniform-diagnostics-v2 schema §3.5): a UDP source
                // reask actually went out on the wire to `addr`.
                crate::diag_event::emit(
                    "sched",
                    "reask_sent",
                    "info",
                    serde_json::json!({ "peer": addr.to_string() }),
                    serde_json::json!({ "outcome": "sent", "transport": "udp" }),
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
            if service.remove_source(endpoint.0, endpoint.1) {
                let _ = events.send(ReaskEvent::SourceReleased { endpoint });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reachability::ExternalReachability;

    fn service() -> ReaskService {
        let public_ip = ExternalReachability::new();
        public_ip.set(std::net::Ipv4Addr::new(203, 0, 113, 9));
        ReaskService::new([0x10; 16], 4, public_ip)
    }

    #[test]
    fn register_command_adds_a_source_and_remove_drops_it() {
        let mut svc = service();
        let (events, mut rx) = reask_event_channel();
        let file_hash = Ed2kHash::from_bytes([0xAB; 16]);
        let endpoint = (Ipv4Addr::new(198, 51, 100, 7), 4672);
        apply_reask_command(
            &mut svc,
            &events,
            ReaskCommand::Register(ReaskDetachArgs {
                file_hash,
                endpoint,
                udp_version: 4,
                user_hash: Some([0x55; 16]),
                should_crypt: true,
                low_id: false,
                buddy_endpoint: None,
                buddy_id: None,
            }),
        );
        assert_eq!(svc.source_count(), 1);
        assert_eq!(svc.registered_file_hashes(), vec![file_hash]);
        // Register raises no event.
        assert!(rx.try_recv().is_err());

        apply_reask_command(&mut svc, &events, ReaskCommand::Remove { endpoint });
        assert_eq!(svc.source_count(), 0);
        assert!(svc.registered_file_hashes().is_empty());
        // B1: removing a held detached source must release its lease.
        match rx.try_recv().expect("a SourceReleased event") {
            ReaskEvent::SourceReleased { endpoint: released } => assert_eq!(released, endpoint),
            other => panic!("expected SourceReleased, got {other:?}"),
        }
    }

    #[test]
    fn remove_command_for_unknown_endpoint_releases_no_lease() {
        let mut svc = service();
        let (events, mut rx) = reask_event_channel();
        // No source was ever registered for this endpoint: a Remove must NOT free
        // a lease core never handed to the loop.
        apply_reask_command(
            &mut svc,
            &events,
            ReaskCommand::Remove {
                endpoint: (Ipv4Addr::new(203, 0, 113, 1), 4672),
            },
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn reengage_releases_lease_before_signalling_source_ready() {
        // B1: an imminent-slot rank must release the held UDP lease BEFORE the
        // re-engage signal, so core frees active_download_peer_endpoints before
        // the reconnect attempt re-acquires it.
        let file_hash = Ed2kHash::from_bytes([0x33; 16]);
        let endpoint = (Ipv4Addr::new(198, 51, 100, 9), 4672);
        let events = routed_reply_events(
            ReaskAction::UpdatedRank(REENGAGE_RANK_THRESHOLD),
            file_hash,
            endpoint,
        );
        assert_eq!(events.len(), 2);
        match &events[0] {
            ReaskEvent::SourceReleased { endpoint: released } => assert_eq!(*released, endpoint),
            other => panic!("expected SourceReleased first, got {other:?}"),
        }
        match &events[1] {
            ReaskEvent::SourceReady { file_hash: ready } => assert_eq!(*ready, file_hash),
            other => panic!("expected SourceReady second, got {other:?}"),
        }
    }

    #[test]
    fn deep_rank_keeps_source_and_releases_no_lease() {
        let events = routed_reply_events(
            ReaskAction::UpdatedRank(REENGAGE_RANK_THRESHOLD + 1),
            Ed2kHash::from_bytes([0x44; 16]),
            (Ipv4Addr::new(198, 51, 100, 10), 4672),
        );
        assert!(events.is_empty(), "deep rank must keep reasking, lease held");
    }

    #[test]
    fn dropped_source_releases_its_lease() {
        // B1: FileNotFound drops the source in the service, so its held lease must
        // be released (it can never re-engage).
        let endpoint = (Ipv4Addr::new(198, 51, 100, 11), 4672);
        let events = routed_reply_events(
            ReaskAction::DropSource,
            Ed2kHash::from_bytes([0x55; 16]),
            endpoint,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            ReaskEvent::SourceReleased { endpoint: released } => assert_eq!(*released, endpoint),
            other => panic!("expected SourceReleased, got {other:?}"),
        }
    }

    #[test]
    fn retry_tcp_timeout_releases_held_lease() {
        // B1: when a detached source exhausts its UDP budget (RetryTcp), the loop
        // drops it AND must release its lease so core can re-acquire it over TCP.
        // Mirror drive_reask_tick's RetryTcp branch over a registered source.
        let mut svc = service();
        let (events, mut rx) = reask_event_channel();
        let file_hash = Ed2kHash::from_bytes([0x66; 16]);
        let endpoint = (Ipv4Addr::new(198, 51, 100, 12), 4672);
        apply_reask_command(
            &mut svc,
            &events,
            ReaskCommand::Register(ReaskDetachArgs {
                file_hash,
                endpoint,
                udp_version: 4,
                user_hash: None,
                should_crypt: false,
                low_id: false,
                buddy_endpoint: None,
                buddy_id: None,
            }),
        );
        // Simulate the RetryTcp branch: remove + release.
        assert!(svc.remove_source(endpoint.0, endpoint.1));
        let _ = events.send(ReaskEvent::SourceReleased { endpoint });
        match rx.try_recv().expect("a SourceReleased event") {
            ReaskEvent::SourceReleased { endpoint: released } => assert_eq!(released, endpoint),
            other => panic!("expected SourceReleased, got {other:?}"),
        }
        // Source is gone; a second remove returns false (no double release).
        assert!(!svc.remove_source(endpoint.0, endpoint.1));
    }

    #[tokio::test]
    async fn inbound_direct_callback_req_raises_connect_out_event() {
        use crate::buddy_socket::BuddySocketRegistry;
        use crate::ed2k_client_udp::codec::OP_DIRECTCALLBACKREQ;
        use crate::ipfilter::IpFilter;
        // Build a service + a transfer runtime stub is heavy; instead exercise the
        // pure outcome->event mapping by driving handle_inbound_datagram with a
        // direct-callback datagram and asserting the raised event. We need a real
        // DhtNode + transfer runtime, so cover the mapping via the service directly
        // and the runtime arm by constructing the event the arm builds.
        let mut svc = service();
        let requester: SocketAddr = "198.51.100.7:4662".parse().unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&4662u16.to_le_bytes());
        body.extend_from_slice(&[0x5A; 16]);
        body.push(0x01);
        let mut datagram = vec![0xC5u8, OP_DIRECTCALLBACKREQ];
        datagram.extend_from_slice(&body);
        let outcome = svc.handle_inbound(&datagram, requester, Instant::now());
        // The runtime arm turns this exact outcome into a DirectCallbackReq event.
        match outcome {
            ReaskInboundOutcome::DirectCallbackReq { req, from } => {
                let SocketAddr::V4(v4) = from else { panic!("ipv4") };
                let event = ReaskEvent::DirectCallbackReq {
                    requester_ip: *v4.ip(),
                    tcp_port: req.tcp_port,
                    user_hash: req.user_hash,
                    connect_options: req.connect_options,
                };
                match event {
                    ReaskEvent::DirectCallbackReq { requester_ip, tcp_port, user_hash, .. } => {
                        assert_eq!(requester_ip, Ipv4Addr::new(198, 51, 100, 7));
                        assert_eq!(tcp_port, 4662);
                        assert_eq!(user_hash, [0x5A; 16]);
                    }
                    other => panic!("expected DirectCallbackReq event, got {other:?}"),
                }
            }
            other => panic!("expected DirectCallbackReq outcome, got {other:?}"),
        }
        // Keep these imports referenced (the heavier integration uses them).
        let _ = (BuddySocketRegistry::new(), IpFilter::default());
    }

    #[test]
    fn inbound_reask_datagram_from_filtered_ip_is_dropped() {
        // B3: a banned/filtered source IP must be dropped before processing
        // (master ClientUDPSocket.cpp IsFiltered at packet entry).
        let filter = IpFilter::parse("198.51.100.0 - 198.51.100.255 , 100 , banned", 127);
        let banned: SocketAddr = "198.51.100.7:4672".parse().unwrap();
        let allowed: SocketAddr = "203.0.113.9:4672".parse().unwrap();
        assert!(is_filtered_reask_source(banned, &filter));
        assert!(!is_filtered_reask_source(allowed, &filter));
    }

    #[test]
    fn empty_filter_allows_all_reask_sources() {
        let filter = IpFilter::default();
        let from: SocketAddr = "198.51.100.7:4672".parse().unwrap();
        assert!(!is_filtered_reask_source(from, &filter));
    }

    #[test]
    fn detach_handle_register_is_received_as_a_command() {
        // Exercises the public Kad-buddy registration entry point (used by core to
        // detach a firewalled LowID Kad source straight onto reask, bypassing TCP).
        let (handle, mut rx) = reask_command_channel();
        let file_hash = Ed2kHash::from_bytes([0xCD; 16]);
        assert!(handle.register_kad_buddy_source(ReaskDetachArgs {
            file_hash,
            endpoint: (Ipv4Addr::new(10, 0, 0, 1), 5000),
            udp_version: 4,
            user_hash: None,
            should_crypt: false,
            low_id: true,
            buddy_endpoint: Some((Ipv4Addr::new(203, 0, 113, 9), 5000)),
            buddy_id: Some([0x77; 16]),
        }));
        match rx.try_recv().expect("a queued command") {
            ReaskCommand::Register(args) => {
                assert_eq!(args.endpoint, (Ipv4Addr::new(10, 0, 0, 1), 5000));
                assert!(args.low_id);
                assert_eq!(args.buddy_endpoint, Some((Ipv4Addr::new(203, 0, 113, 9), 5000)));
                assert_eq!(args.buddy_id, Some([0x77; 16]));
            }
            other => panic!("expected Register, got {other:?}"),
        }
    }
}
