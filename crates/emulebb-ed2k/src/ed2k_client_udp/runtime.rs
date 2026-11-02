//! The client-to-client UDP source-reask runtime loop (`docs/design/udp-source-reask.md`
//! §4.2-§4.6). Lives in `emulebb-ed2k` because it composes the crate-internal
//! [`super::ReaskService`] with the shared Kad UDP socket via [`DhtNode`]; core
//! always spawns it so direct callbacks and port tests remain reachable, while
//! `Ed2kRuntimeConfig.enable_udp_reask` gates only source-reask behavior.
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
//! relayed reask over UDP) — both via [`super::buddy_relay`]. Those reask and
//! buddy-relay paths are gated behind `enable_udp_reask` (on by default);
//! direct callbacks and port tests are independent client-UDP control paths.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use emulebb_kad_dht::{DhtNode, ForeignDatagramHandler};
use emulebb_kad_proto::Ed2kHash;
#[cfg(feature = "packet-diagnostics")]
use tokio::sync::oneshot;
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing::{debug, trace};

use super::codec::ReaskAckPartStatus;
use super::dispatch::{
    InboundReaskMessage, InboundReaskParseError, classify_inbound_reask_datagram,
};
use super::dump::ClientUdpDumpOutcome;
use super::service::{
    ReaskIgnoredReason, ReaskInboundOutcome, ReaskService, ReaskTickPacing, TransferReaskInfo,
};
use super::state::{ReaskAction, ReaskSource};
use super::transport::{ClientUdpSendRole, send_client_udp_datagram};
use crate::buddy_socket::{BuddySocketRegistry, OutboundBuddyToken};
use crate::ed2k_server::Ed2kServerState;
use crate::ed2k_transfer::Ed2kTransferRuntime;
use crate::ipfilter::IpFilter;
use crate::kad_firewall::KadFirewallState;
use crate::port_test::PortTestRegistry;
use crate::reachability::ExternalReachability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpFirewallAuthority {
    ServerHighId,
    KadOpen,
    ServerLowId,
    KadFirewalled,
    NoOpenAuthority,
}

impl TcpFirewallAuthority {
    #[cfg(feature = "packet-diagnostics")]
    const fn diagnostic_name(self) -> &'static str {
        match self {
            Self::ServerHighId => "server_high_id",
            Self::KadOpen => "kad_open",
            Self::ServerLowId => "server_low_id",
            Self::KadFirewalled => "kad_firewalled",
            Self::NoOpenAuthority => "no_open_authority",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TcpFirewallVerdict {
    firewalled: bool,
    authority: TcpFirewallAuthority,
    server_connected: bool,
    server_firewalled: Option<bool>,
    kad_connected: bool,
    kad_firewalled: Option<bool>,
}

fn resolve_tcp_firewall_verdict(
    server_connected: bool,
    server_firewalled: Option<bool>,
    kad_connected: bool,
    kad_firewalled: Option<bool>,
) -> TcpFirewallVerdict {
    let server_open = server_connected && server_firewalled == Some(false);
    let kad_open = kad_connected && kad_firewalled == Some(false);
    let authority = if server_open {
        TcpFirewallAuthority::ServerHighId
    } else if kad_open {
        TcpFirewallAuthority::KadOpen
    } else if server_connected && server_firewalled == Some(true) {
        TcpFirewallAuthority::ServerLowId
    } else if kad_connected && kad_firewalled == Some(true) {
        TcpFirewallAuthority::KadFirewalled
    } else {
        TcpFirewallAuthority::NoOpenAuthority
    };
    TcpFirewallVerdict {
        firewalled: !(server_open || kad_open),
        authority,
        server_connected,
        server_firewalled,
        kad_connected,
        kad_firewalled,
    }
}

async fn current_tcp_firewall_verdict(
    dht: &DhtNode,
    server_state: &RwLock<Ed2kServerState>,
    kad_firewall: &Mutex<KadFirewallState>,
) -> TcpFirewallVerdict {
    let (server_connected, server_firewalled) = {
        let server = server_state.read().await;
        (server.connected, server.tcp_firewalled())
    };
    let kad_connected = dht.is_bootstrapped();
    let kad_firewalled = kad_firewall.lock().await.tcp_firewalled();
    resolve_tcp_firewall_verdict(
        server_connected,
        server_firewalled,
        kad_connected,
        kad_firewalled,
    )
}

/// A command from a download session to the reask loop: detach a just-queued
/// source onto UDP reask, or drop one that no longer needs reasking. Public so
/// core can carry the channel; constructed in-crate by the download session.
#[derive(Debug)]
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
    /// (oracle ListenSocket.cpp). The buddy-forwarded request body is retained so
    /// requester part status and complete-source count survive the relay.
    AnswerCallbackTcp {
        buddy_token: OutboundBuddyToken,
        dest: SocketAddr,
        forwarded_reask: Vec<u8>,
    },
    /// Diagnostics-only ordered wake. The control plane first enqueues the normal
    /// `Register` command, then this command on the same channel. FIFO processing
    /// guarantees the existing production tick observes the registered source.
    #[cfg(feature = "packet-diagnostics")]
    DiagnosticWakeTick { completed: oneshot::Sender<()> },
    #[cfg(feature = "packet-diagnostics")]
    DiagnosticWakeDirectSource {
        source: DiagnosticQueuedSourceReask,
        completed: oneshot::Sender<Result<(), &'static str>>,
    },
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

#[cfg(feature = "packet-diagnostics")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticQueuedSourceReask {
    pub file_hash: Ed2kHash,
    pub source_ip: Ipv4Addr,
    pub source_tcp_port: u16,
    pub source_udp_port: u16,
    pub source_user_hash: [u8; 16],
    pub source_udp_version: u8,
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

    /// Run the real production reask tick promptly after an ordered diagnostics
    /// registration. This does not construct or send a packet itself.
    #[cfg(feature = "packet-diagnostics")]
    pub async fn diagnostic_wake_tick(&self) -> Result<(), &'static str> {
        const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
        tokio::time::timeout(CONTROL_TIMEOUT, async {
            let (completed, completion) = oneshot::channel();
            self.0
                .send(ReaskCommand::DiagnosticWakeTick { completed })
                .await
                .map_err(|_| "reask command channel is closed")?;
            completion
                .await
                .map_err(|_| "reask loop ended before the diagnostics tick completed")
        })
        .await
        .map_err(|_| "timed out waiting for the diagnostics reask tick")?
    }

    #[cfg(feature = "packet-diagnostics")]
    pub async fn diagnostic_wake_direct_source(
        &self,
        source: DiagnosticQueuedSourceReask,
    ) -> Result<(), &'static str> {
        const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
        tokio::time::timeout(CONTROL_TIMEOUT, async {
            let (completed, completion) = oneshot::channel();
            self.0
                .send(ReaskCommand::DiagnosticWakeDirectSource { source, completed })
                .await
                .map_err(|_| "reask command channel is closed")?;
            completion
                .await
                .map_err(|_| "reask loop ended before the diagnostics source wake completed")?
        })
        .await
        .map_err(|_| "timed out waiting for the diagnostics source reask")?
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
    pub(crate) fn answer_callback_tcp(
        &self,
        buddy_token: OutboundBuddyToken,
        dest: std::net::SocketAddr,
        forwarded_reask: Vec<u8>,
    ) {
        let _ = self.0.try_send(ReaskCommand::AnswerCallbackTcp {
            buddy_token,
            dest,
            forwarded_reask,
        });
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

/// Run the shared client-UDP ingress and source-reask loop until `shutdown` is
/// set. Core always spawns it for direct callbacks and port tests; when
/// `enable_udp_reask` is off, commands, ticks, reask packets, and buddy-relay
/// packets remain disabled so queued sources fall back to the held-TCP path.
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
    server_state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    ip_filter: IpFilter,
    buddy_registry: BuddySocketRegistry,
    port_test_registry: PortTestRegistry,
    reask_enabled: bool,
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
                    &buddy_registry, &port_test_registry, reask_enabled, user_hash,
                    udp_version, public_ip.octets(), &data, from,
                )
                .await;
            }
            maybe = commands.recv(), if reask_enabled => {
                let Some(command) = maybe else { break };
                // AnswerCallbackTcp needs async UDP I/O; the rest are sync.
                match command {
                    ReaskCommand::AnswerCallbackTcp {
                        buddy_token,
                        dest,
                        forwarded_reask,
                    } => process_answer_callback_tcp(
                        &dht,
                        &transfer_runtime,
                        public_ip.octets(),
                        &buddy_registry,
                        buddy_token,
                        dest,
                        &forwarded_reask,
                        udp_version,
                    )
                    .await,
                    #[cfg(feature = "packet-diagnostics")]
                    ReaskCommand::DiagnosticWakeTick { completed } => {
                        let firewall =
                            current_tcp_firewall_verdict(&dht, &server_state, &kad_firewall).await;
                        drive_reask_tick(
                            &mut service,
                            &dht,
                            &transfer_runtime,
                            &events,
                            firewall,
                        )
                        .await;
                        let _ = completed.send(());
                    }
                    #[cfg(feature = "packet-diagnostics")]
                    ReaskCommand::DiagnosticWakeDirectSource { source, completed } => {
                        let endpoint = (source.source_ip, source.source_udp_port);
                        let armed = service.diagnostic_arm_direct_source(
                            source.file_hash,
                            endpoint,
                            (source.source_ip, source.source_tcp_port),
                            source.source_user_hash,
                            source.source_udp_version,
                            Instant::now(),
                        );
                        if !armed {
                            let _ = completed.send(Err(
                                "queued direct source identity was not registered or was not eligible",
                            ));
                            continue;
                        }
                        let firewall =
                            current_tcp_firewall_verdict(&dht, &server_state, &kad_firewall).await;
                        drive_reask_tick(
                            &mut service,
                            &dht,
                            &transfer_runtime,
                            &events,
                            firewall,
                        )
                        .await;
                        let result = if service
                            .per_file_source_pending(source.file_hash, endpoint)
                        {
                            Ok(())
                        } else {
                            Err("production UDP reask tick did not open the pending reply gate")
                        };
                        let _ = completed.send(result);
                    }
                    other => apply_reask_command(&mut service, &events, other),
                }
            }
            _ = ticker.tick(), if reask_enabled => {
                let firewall =
                    current_tcp_firewall_verdict(&dht, &server_state, &kad_firewall).await;
                drive_reask_tick(
                    &mut service,
                    &dht,
                    &transfer_runtime,
                    &events,
                    firewall,
                )
                .await;
            }
        }
    }
    debug!("ed2k udp reask loop stopped");
}

#[expect(
    clippy::too_many_arguments,
    reason = "flat protocol or runtime boundary"
)]
async fn process_answer_callback_tcp(
    dht: &DhtNode,
    transfer_runtime: &Ed2kTransferRuntime,
    our_public_ip: [u8; 4],
    buddy_registry: &BuddySocketRegistry,
    buddy_token: OutboundBuddyToken,
    dest: SocketAddr,
    forwarded_reask: &[u8],
    udp_version: u8,
) {
    if !buddy_registry.is_current_outbound(buddy_token) {
        debug!("ed2k udp reask: ignoring OP_REASKCALLBACKTCP from replaced outbound buddy link");
        return;
    }
    match super::codec::decode_reask_file_ping(forwarded_reask, udp_version) {
        Ok(ping) => {
            super::buddy_relay::answer_buddy_relayed_reask(
                dht,
                transfer_runtime,
                our_public_ip,
                dest,
                ping,
            )
            .await;
        }
        Err(error) => {
            debug!("ed2k udp reask: malformed buddy-relayed requester state from {dest}: {error:#}")
        }
    }
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

/// Resolve the ACK's wire representation into the source bitmap used by the
/// live transfer registry. Stock encodes a complete source as part-count zero;
/// legacy ACKs carry no status and must leave the previous bitmap untouched.
fn resolved_reask_ack_bitmap(
    part_status: &ReaskAckPartStatus,
    expected_part_count: Option<usize>,
) -> Option<Vec<bool>> {
    match part_status {
        ReaskAckPartStatus::NotIncluded => None,
        ReaskAckPartStatus::CompleteSource => expected_part_count.map(|count| vec![true; count]),
        ReaskAckPartStatus::Bitmap(parts) => Some(parts.clone()),
    }
}

fn reask_source_has_no_needed_parts(ours: &[bool], source: &[bool]) -> bool {
    !source
        .iter()
        .zip(ours)
        .any(|(source_has_part, we_have_part)| *source_has_part && !*we_have_part)
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
    port_test_registry: &PortTestRegistry,
    reask_enabled: bool,
    our_user_hash: [u8; 16],
    udp_version: u8,
    our_public_ip: [u8; 4],
    data: &[u8],
    from: SocketAddr,
) {
    if !from.is_ipv4() {
        super::dump::dump_client_udp_recv(
            from,
            &our_user_hash,
            data,
            ClientUdpDumpOutcome::Dropped,
            Some("non_ipv4".to_string()),
        );
        trace!("ed2k udp reask: dropping inbound datagram from non-IPv4 endpoint {from}");
        return;
    }
    // Drop datagrams from a filtered IP first (master ClientUDPSocket.cpp:129
    // IsFiltered).
    if is_filtered_reask_source(from, ip_filter) {
        super::dump::dump_client_udp_recv(
            from,
            &our_user_hash,
            data,
            ClientUdpDumpOutcome::Dropped,
            Some("filtered_ip".to_string()),
        );
        trace!("ed2k udp reask: dropping inbound datagram from filtered IP {from}");
        return;
    }
    // Drop datagrams from a banned IP (master ClientUDPSocket.cpp:129
    // IsBannedClient(sin_addr)). The user-hash half of a ban is not knowable from
    // a bare UDP datagram, so only the IP key is checked here.
    if let SocketAddr::V4(v4) = from
        && transfer_runtime.is_client_banned(Some(*v4.ip()), None)
    {
        super::dump::dump_client_udp_recv(
            from,
            &our_user_hash,
            data,
            ClientUdpDumpOutcome::Dropped,
            Some("banned_ip".to_string()),
        );
        trace!("ed2k udp reask: dropping inbound datagram from banned IP {from}");
        return;
    }
    trace!(
        "ed2k udp reask: PKT-IN <- {from} ({} bytes) hex={}",
        data.len(),
        hex_preview(data)
    );
    #[cfg(feature = "packet-diagnostics")]
    let mut reply_applied_diagnostic = None;
    let (diagnostic_outcome, diagnostic_note) = if !reask_enabled {
        handle_reask_disabled_datagram(
            events,
            port_test_registry,
            our_user_hash,
            udp_version,
            data,
            from,
        )
    } else {
        let received_at = Instant::now();
        let outcome = service.handle_inbound(data, from, received_at);
        match outcome {
            ReaskInboundOutcome::RoutedReply {
                file_hash,
                endpoint,
                lease_endpoint,
                ack_part_status,
                request_part_status,
                #[cfg(feature = "packet-diagnostics")]
                diagnostic_identity,
                #[cfg(feature = "packet-diagnostics")]
                request_pending_after,
                #[cfg(feature = "packet-diagnostics")]
                remote_queue_full_after,
                action,
            } => {
                trace!("ed2k udp reask: routed reply from {from}: {action:?} (file {file_hash})");
                #[cfg(feature = "packet-diagnostics")]
                let mut part_status_after = None;
                #[cfg(feature = "packet-diagnostics")]
                let mut no_needed_parts_after = None;
                #[cfg(feature = "packet-diagnostics")]
                let mut queue_rank_applied = false;
                if let ReaskAction::UpdatedRank(rank) = action {
                    let peer = SocketAddr::new(lease_endpoint.0.into(), lease_endpoint.1);
                    let _queue_rank_applied = transfer_runtime.note_download_source_queue_rank(
                        &file_hash.to_string(),
                        peer,
                        u32::from(rank),
                    );
                    #[cfg(feature = "packet-diagnostics")]
                    {
                        queue_rank_applied = _queue_rank_applied;
                    }
                    if let Some(part_status) = ack_part_status.as_ref()
                        && let Some(source_bitmap) = resolved_reask_ack_bitmap(
                            part_status,
                            request_part_status.as_ref().map(Vec::len),
                        )
                    {
                        let no_needed_parts = request_part_status.as_deref().map(|our_bitmap| {
                            reask_source_has_no_needed_parts(our_bitmap, &source_bitmap)
                        });
                        #[cfg(feature = "packet-diagnostics")]
                        let diagnostic_source_bitmap = source_bitmap.clone();
                        let part_status_applied = transfer_runtime
                            .note_download_source_part_bitmap(
                                &file_hash.to_string(),
                                peer,
                                None,
                                None,
                                source_bitmap,
                            );
                        if part_status_applied && let Some(no_needed_parts) = no_needed_parts {
                            let _no_needed_parts_applied = service.set_no_needed_parts(
                                endpoint.0,
                                endpoint.1,
                                no_needed_parts,
                                received_at,
                            );
                            #[cfg(feature = "packet-diagnostics")]
                            if _no_needed_parts_applied {
                                no_needed_parts_after = Some(no_needed_parts);
                            }
                        }
                        #[cfg(feature = "packet-diagnostics")]
                        if part_status_applied {
                            part_status_after = Some(diagnostic_source_bitmap);
                        }
                    }
                }
                #[cfg(feature = "packet-diagnostics")]
                {
                    let application = ack_part_status.as_ref().map(|part_status| {
                        super::sched_diag::UdpReaskReplyApplicationDiagnostic {
                            queue_rank_applied,
                            part_status_included: !matches!(
                                part_status,
                                ReaskAckPartStatus::NotIncluded
                            ),
                            wire_part_count: part_status.wire_part_count(),
                            part_status_after,
                            no_needed_parts_after,
                        }
                    });
                    reply_applied_diagnostic = Some((
                        file_hash,
                        diagnostic_identity,
                        action,
                        request_pending_after,
                        remote_queue_full_after,
                        application,
                    ));
                }
                // A re-engageable rank means we hand the source back to TCP first.
                if matches!(action, ReaskAction::UpdatedRank(rank) if rank <= REENGAGE_RANK_THRESHOLD)
                {
                    service.remove_source(endpoint.0, endpoint.1);
                }
                // Emit loop->core events (lease release ordered before any re-engage).
                let mut delivered = true;
                for event in routed_reply_events(action, file_hash, endpoint, lease_endpoint) {
                    if let ReaskEvent::SourceReady { file_hash } = &event {
                        trace!("ed2k udp reask: re-engage SourceReady for {file_hash}");
                    }
                    delivered &= events.send(event).is_ok();
                }
                if delivered {
                    (
                        ClientUdpDumpOutcome::Accepted,
                        Some(format!(
                            "routed_reply action={action:?} file_hash={file_hash}"
                        )),
                    )
                } else {
                    (
                        ClientUdpDumpOutcome::Dropped,
                        Some("core_event_channel_closed".to_string()),
                    )
                }
            }
            ReaskInboundOutcome::AnswerNeeded { ping, from } => {
                // Record the accepted request before any reply attempt. The
                // packet event is the causal receive boundary; emitting it after
                // the async send inverted request/ACK order in converged traces.
                super::dump::dump_client_udp_recv(
                    from,
                    &our_user_hash,
                    data,
                    ClientUdpDumpOutcome::Accepted,
                    Some("answer_needed".to_string()),
                );
                // Answer the peer's OP_REASKFILEPING from upload-queue/catalog state.
                match transfer_runtime
                    .reask_reciprocity_reply(&ping, from, our_public_ip)
                    .await
                {
                    Some(reply) => {
                        if let Err(err) = send_client_udp_datagram(
                            dht,
                            from,
                            ClientUdpSendRole::ReciprocityReply,
                            &reply,
                        )
                        .await
                        {
                            trace!("ed2k udp reask: reciprocity reply to {from} failed: {err}");
                        }
                    }
                    // Deliberate silence (force TCP / file mismatch); nothing to send.
                    None => {
                        trace!("ed2k udp reask: inbound reask from {from} answered with silence")
                    }
                }
                return;
            }
            ReaskInboundOutcome::BuddyRelay { callback, from } => {
                // The relay forwards the post-buddy-id tail verbatim (oracle
                // ClientUDPSocket.cpp memcpy(packet+16)), so our udp_version does not
                // gate it.
                if super::buddy_relay::relay_buddy_reask_callback(buddy_registry, &callback, from) {
                    (
                        ClientUdpDumpOutcome::Accepted,
                        Some("buddy_relayed".to_string()),
                    )
                } else {
                    (
                        ClientUdpDumpOutcome::Dropped,
                        Some("buddy_not_registered".to_string()),
                    )
                }
            }
            ReaskInboundOutcome::DirectCallbackReq { req, from } => {
                if raise_direct_callback_event(events, req, from) {
                    (
                        ClientUdpDumpOutcome::Accepted,
                        Some("direct_callback_raised".to_string()),
                    )
                } else {
                    (
                        ClientUdpDumpOutcome::Dropped,
                        Some("direct_callback_not_delivered".to_string()),
                    )
                }
            }
            ReaskInboundOutcome::PortTest { from } => {
                if acknowledge_port_test(port_test_registry, from) {
                    (
                        ClientUdpDumpOutcome::Accepted,
                        Some("port_test_acknowledged".to_string()),
                    )
                } else {
                    (
                        ClientUdpDumpOutcome::Ignored,
                        Some("port_test_not_pending".to_string()),
                    )
                }
            }
            ReaskInboundOutcome::Ignored(reason) => ignored_reason_disposition(&reason),
        }
    };
    super::dump::dump_client_udp_recv(
        from,
        &our_user_hash,
        data,
        diagnostic_outcome,
        diagnostic_note,
    );
    #[cfg(feature = "packet-diagnostics")]
    if let Some((
        file_hash,
        diagnostic_identity,
        action,
        request_pending_after,
        remote_queue_full_after,
        application,
    )) = reply_applied_diagnostic
    {
        super::sched_diag::udp_reask_reply_applied(
            file_hash,
            diagnostic_identity,
            action,
            request_pending_after,
            remote_queue_full_after,
            application,
        );
    }
}

fn handle_reask_disabled_datagram(
    events: &ReaskEventSender,
    port_test_registry: &PortTestRegistry,
    our_user_hash: [u8; 16],
    udp_version: u8,
    data: &[u8],
    from: SocketAddr,
) -> (ClientUdpDumpOutcome, Option<String>) {
    let SocketAddr::V4(from_v4) = from else {
        return (ClientUdpDumpOutcome::Dropped, Some("non_ipv4".to_string()));
    };
    match classify_inbound_reask_datagram(data, from_v4.ip().octets(), &our_user_hash, udp_version)
    {
        Ok(InboundReaskMessage::DirectCallbackReq(req)) => {
            if raise_direct_callback_event(events, req, from) {
                (
                    ClientUdpDumpOutcome::Accepted,
                    Some("direct_callback_raised".to_string()),
                )
            } else {
                (
                    ClientUdpDumpOutcome::Dropped,
                    Some("direct_callback_not_delivered".to_string()),
                )
            }
        }
        Ok(InboundReaskMessage::PortTest) => {
            if acknowledge_port_test(port_test_registry, from) {
                (
                    ClientUdpDumpOutcome::Accepted,
                    Some("port_test_acknowledged".to_string()),
                )
            } else {
                (
                    ClientUdpDumpOutcome::Ignored,
                    Some("port_test_not_pending".to_string()),
                )
            }
        }
        // Source reask and buddy relay stay disabled. In particular, do not
        // route them through ReaskService, which could answer or mutate state.
        Ok(_) => (
            ClientUdpDumpOutcome::Ignored,
            Some("reask_disabled".to_string()),
        ),
        Err(error) => parse_error_disposition(&error),
    }
}

fn parse_error_disposition(
    error: &InboundReaskParseError,
) -> (ClientUdpDumpOutcome, Option<String>) {
    let outcome = match error {
        InboundReaskParseError::UnknownOpcode { .. } => ClientUdpDumpOutcome::Ignored,
        InboundReaskParseError::Undecodable | InboundReaskParseError::Malformed { .. } => {
            ClientUdpDumpOutcome::Dropped
        }
    };
    (outcome, Some(format!("{}: {error}", error.reason())))
}

fn ignored_reason_disposition(
    reason: &ReaskIgnoredReason,
) -> (ClientUdpDumpOutcome, Option<String>) {
    match reason {
        ReaskIgnoredReason::Parse(error) => parse_error_disposition(error),
        ReaskIgnoredReason::NonIpv4 => (
            ClientUdpDumpOutcome::Dropped,
            Some(reason.reason().to_string()),
        ),
        ReaskIgnoredReason::UnregisteredEndpoint
        | ReaskIgnoredReason::MissingSourceSet
        | ReaskIgnoredReason::UnsolicitedReply => (
            ClientUdpDumpOutcome::Ignored,
            Some(reason.reason().to_string()),
        ),
    }
}

fn raise_direct_callback_event(
    events: &ReaskEventSender,
    req: super::codec::DirectCallbackReq,
    from: SocketAddr,
) -> bool {
    // We have no TCP-connect / hello-identity / firewalled-verdict state here,
    // so raise an event for core to gate (Kademlia::IsRunning() &&
    // IsFirewalled()) and connect out (oracle ClientUDPSocket.cpp
    // OP_DIRECTCALLBACKREQ -> TryToConnectOrDelete). IPv4-only: a non-V4
    // requester can never be a client source, so it is dropped.
    if let SocketAddr::V4(v4) = from {
        trace!(
            "ed2k client udp: inbound OP_DIRECTCALLBACKREQ from {from} \
             (tcp_port={}); raising connect-out event",
            req.tcp_port
        );
        events
            .send(ReaskEvent::DirectCallbackReq {
                requester_ip: *v4.ip(),
                tcp_port: req.tcp_port,
                user_hash: req.user_hash,
                connect_options: req.connect_options,
            })
            .is_ok()
    } else {
        trace!("ed2k client udp: dropping OP_DIRECTCALLBACKREQ from non-IPv4 requester {from}");
        false
    }
}

fn acknowledge_port_test(port_test_registry: &PortTestRegistry, from: SocketAddr) -> bool {
    let acknowledged = port_test_registry.acknowledge_udp_probe();
    debug!("ed2k udp port test probe from {from}: tcp_result_sent={acknowledged}");
    acknowledged
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
            #[cfg(feature = "packet-diagnostics")]
            let diagnostic_identity = source.diagnostic_identity();
            trace!(
                "ed2k udp reask: detaching source {}:{} for {} onto UDP reask",
                endpoint.0, endpoint.1, file_hash
            );
            service.register_source(file_hash, source);
            #[cfg(feature = "packet-diagnostics")]
            super::sched_diag::udp_reask_source_registered(file_hash, diagnostic_identity);
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
        ReaskCommand::AnswerCallbackTcp { .. } => {}
        #[cfg(feature = "packet-diagnostics")]
        ReaskCommand::DiagnosticWakeTick { .. } => {}
        #[cfg(feature = "packet-diagnostics")]
        ReaskCommand::DiagnosticWakeDirectSource { .. } => {}
    }
}

fn settle_reask_send<E>(
    service: &mut ReaskService,
    source_endpoint: (Ipv4Addr, u16),
    request_part_status: Option<Vec<bool>>,
    result: Result<(), E>,
    sent_at: Instant,
) -> Result<bool, E> {
    result.map(|()| service.mark_reask_sent(source_endpoint, request_part_status, sent_at))
}

/// Drive one reask tick: send due reask pings and account timed-out reasks.
/// Per-file transfer info (our part availability) is pulled from the transfer
/// runtime before the sync `tick`, since the source state lives in the service.
async fn drive_reask_tick(
    service: &mut ReaskService,
    dht: &DhtNode,
    transfer_runtime: &Ed2kTransferRuntime,
    events: &ReaskEventSender,
    firewall: TcpFirewallVerdict,
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
    for send in out.send {
        dispatch_scheduled_reask(service, dht, send, firewall).await;
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

async fn dispatch_scheduled_reask(
    service: &mut ReaskService,
    dht: &DhtNode,
    send: super::outbound::ReaskSend,
    firewall: TcpFirewallVerdict,
) {
    let source_endpoint = send.source_endpoint;
    let addr = send.destination;
    let role = if send.datagram.opcode == super::codec::OP_REASKCALLBACKUDP {
        ClientUdpSendRole::BuddyRelayRequest
    } else {
        ClientUdpSendRole::ReaskRequest
    };
    #[cfg(feature = "packet-diagnostics")]
    super::sched_diag::udp_reask_schedule_decision(&send);
    if firewall.firewalled {
        #[cfg(feature = "packet-diagnostics")]
        super::sched_diag::udp_reask_decision_local_firewalled(
            &send,
            super::sched_diag::UdpReaskFirewallDiagnostic {
                authority: firewall.authority.diagnostic_name(),
                server_connected: firewall.server_connected,
                server_firewalled: firewall.server_firewalled,
                kad_connected: firewall.kad_connected,
                kad_firewalled: firewall.kad_firewalled,
            },
        );
        trace!(
            ?source_endpoint,
            destination = %addr,
            authority = ?firewall.authority,
            server_connected = firewall.server_connected,
            server_firewalled = ?firewall.server_firewalled,
            kad_connected = firewall.kad_connected,
            kad_firewalled = ?firewall.kad_firewalled,
            "ed2k udp reask: skipping scheduled send because the local client is firewalled"
        );
        return;
    }
    #[cfg(feature = "packet-diagnostics")]
    super::sched_diag::udp_reask_decision(&send);
    let result = send_client_udp_datagram(dht, addr, role, &send.datagram).await;
    match settle_reask_send(
        service,
        source_endpoint,
        send.request_part_status,
        result,
        Instant::now(),
    ) {
        Ok(marked) => {
            debug_assert!(marked, "scheduled reask source disappeared during send");
            if !marked {
                debug!(
                    ?source_endpoint,
                    destination = %addr,
                    "ed2k udp reask: successful send could not open source reply gate"
                );
            }
            trace!(
                "ed2k udp reask: PKT-OUT reask ping -> {addr} ({} bytes) hex={}",
                send.datagram.bytes.len(),
                hex_preview(&send.datagram.bytes),
            );
            if marked {
                // `reask_sent` (uniform-diagnostics-v2 schema §3.5): a UDP
                // source reask actually went out and opened its reply gate.
                crate::diag_event::emit(
                    "sched",
                    "reask_sent",
                    "info",
                    serde_json::json!({ "peer": addr.to_string() }),
                    udp_reask_sent_body(),
                );
            }
        }
        Err(err) => {
            trace!(
                "ed2k udp reask: send to {addr} for source {:?} failed: {err}",
                source_endpoint
            );
        }
    }
}

#[cfg(test)]
mod tests;
