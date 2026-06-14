//! The client-to-client UDP source-reask runtime loop (`docs/design/udp-source-reask.md`
//! §4.2-§4.6). Lives in `emulebb-ed2k` because it composes the crate-internal
//! [`super::ReaskService`] with the shared Kad UDP socket via [`DhtNode`]; core
//! spawns it (off by default, gated by `Ed2kConfig.enable_udp_reask`).
//!
//! It registers a foreign-datagram handler on the shared socket (inbound reask
//! packets that fail Kad decode arrive here), forwards them to an async task over
//! a channel, and `select!`s that against a periodic tick that drives outbound
//! reasks. All reask *decisions* live in the I/O-free [`super::ReaskService`];
//! this is the thin async shell that performs the socket I/O.
//!
//! Wiring still pending (the live-validated next slice, flagged inline): the
//! download-session **detach hook** (`register_source` when a peer queues us).
//! The uploader **reciprocity** answer is wired (via the runtime's global
//! upload-queue `(ip,udp_port)` lookup). Until the detach hook lands the loop
//! holds no downloader sources, so it only answers inbound pings — it is
//! structurally complete and inert as a downloader.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use emulebb_kad_dht::{DhtNode, ForeignDatagramHandler};
use tokio::sync::mpsc;
use tracing::{debug, trace};

use super::service::{ReaskInboundOutcome, ReaskService, TransferReaskInfo};
use crate::ed2k_transfer::Ed2kTransferRuntime;
use crate::public_ip::SharedPublicIp;

/// How long to wait for a reask reply before counting it a UDP failure.
const REASK_REPLY_TIMEOUT: Duration = Duration::from_secs(30);
/// How often the loop checks for due reasks + drains timed-out ones. Sources
/// reask on the ~29 min `FILE_REASK_TIME` cadence, so a coarse tick suffices.
const REASK_TICK_INTERVAL: Duration = Duration::from_secs(30);
/// Bound on the inbound channel so a flood of non-Kad datagrams cannot grow it
/// without limit; excess is dropped (the sender forces a TCP reconnect anyway).
const REASK_INBOUND_CHANNEL_BOUND: usize = 256;

/// Run the UDP source-reask loop until `shutdown` is set. Spawned by core only
/// when `enable_udp_reask` is on; off by default because the transport must be
/// wire-validated before it is trusted.
pub async fn run_ed2k_udp_reask_loop(
    dht: DhtNode,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    user_hash: [u8; 16],
    udp_version: u8,
    public_ip: SharedPublicIp,
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
                    &mut service,
                    &dht,
                    &transfer_runtime,
                    public_ip.octets(),
                    &data,
                    from,
                )
                .await;
            }
            _ = ticker.tick() => {
                drive_reask_tick(&mut service, &dht).await;
            }
        }
    }
    debug!("ed2k udp reask loop stopped");
}

/// Route one inbound datagram through the service and act on the outcome.
async fn handle_inbound_datagram(
    service: &mut ReaskService,
    dht: &DhtNode,
    transfer_runtime: &Ed2kTransferRuntime,
    our_public_ip: [u8; 4],
    data: &[u8],
    from: SocketAddr,
) {
    match service.handle_inbound(data, from, Instant::now()) {
        ReaskInboundOutcome::RoutedReply(action) => {
            trace!("ed2k udp reask: routed reply from {from}: {action:?}");
            // TODO(reask-tcp-fallback): on RetryTcp, ask the download runtime to
            // reconnect+SETREQFILEID for this source.
        }
        ReaskInboundOutcome::AnswerNeeded { ping, from } => {
            // Answer the peer's OP_REASKFILEPING from the global upload-queue +
            // shared-catalog state (eMule's OP_REASKFILEPING reaction table).
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
                None => trace!(
                    "ed2k udp reask: inbound reask for {} from {from} answered with silence",
                    ping.file_hash
                ),
            }
        }
        ReaskInboundOutcome::Ignored => {}
    }
}

/// Drive one reask tick: send due reask pings and account timed-out reasks.
async fn drive_reask_tick(service: &mut ReaskService, dht: &DhtNode) {
    // TODO(reask-transfer-info): supply real per-file part status + complete-source
    // count once the download-session detach hook registers sources. With no
    // sources registered this closure is never invoked.
    let out = service.tick(Instant::now(), REASK_REPLY_TIMEOUT, |_file_hash| {
        TransferReaskInfo {
            part_status: None,
            complete_source_count: 0,
        }
    });
    for (addr, datagram) in out.send {
        if let Err(err) = dht.send_raw_datagram(addr, &datagram).await {
            trace!("ed2k udp reask: send to {addr} failed: {err}");
        }
    }
    for (addr, action) in out.timed_out {
        trace!("ed2k udp reask: reask to {addr} timed out: {action:?}");
        // TODO(reask-tcp-fallback): RetryTcp -> drive a TCP reconnect reask.
    }
}
