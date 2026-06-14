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
//! Both directions are wired (off by default): the uploader **reciprocity**
//! answer (via the runtime's global upload-queue `(ip,udp_port)` lookup) and the
//! downloader **detach hook** — a download session that gets queued on a
//! UDP-eligible peer sends a [`ReaskCommand`] over the command channel; the loop
//! registers it as a `QueuedDetached` source and keeps its slot warm by periodic
//! UDP reask (real per-file part status pulled from the transfer runtime). When a
//! source exhausts its UDP-reask budget (`RetryTcp`), the loop drops it so core's
//! normal source acquisition re-engages it over TCP. The whole loop stays gated
//! behind `enable_udp_reask` until live-validated.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use emulebb_kad_dht::{DhtNode, ForeignDatagramHandler};
use emulebb_kad_proto::Ed2kHash;
use tokio::sync::mpsc;
use tracing::{debug, trace};

use super::service::{ReaskInboundOutcome, ReaskService, TransferReaskInfo};
use super::state::{ReaskAction, ReaskSource};
use crate::ed2k_transfer::Ed2kTransferRuntime;
use crate::public_ip::SharedPublicIp;

/// A command from a download session to the reask loop: detach a just-queued
/// source onto UDP reask, or drop one that no longer needs reasking. Public so
/// core can carry the channel; constructed in-crate by the download session.
#[derive(Debug, Clone)]
pub enum ReaskCommand {
    /// Detach a source that queued us (eMuleBB §4.1 `QueuedDetached` transition).
    Register {
        file_hash: Ed2kHash,
        endpoint: (Ipv4Addr, u16),
        udp_version: u8,
        user_hash: Option<[u8; 16]>,
        should_crypt: bool,
    },
    /// Drop a source by endpoint (transfer completed / no longer wanted).
    Remove { endpoint: (Ipv4Addr, u16) },
}

/// Receiver end of the detach-command channel, owned by the reask loop.
pub type ReaskCommandReceiver = mpsc::Receiver<ReaskCommand>;

/// Cloneable sender handle a download session uses to detach a queued source.
#[derive(Debug, Clone)]
pub struct ReaskSourceHandle(mpsc::Sender<ReaskCommand>);

impl ReaskSourceHandle {
    /// Detach a queued source onto UDP reask. Best-effort: a full/closed channel
    /// silently drops the command (the source just stays on its TCP path).
    pub(crate) fn detach(
        &self,
        file_hash: Ed2kHash,
        endpoint: (Ipv4Addr, u16),
        udp_version: u8,
        user_hash: Option<[u8; 16]>,
        should_crypt: bool,
    ) {
        let _ = self.0.try_send(ReaskCommand::Register {
            file_hash,
            endpoint,
            udp_version,
            user_hash,
            should_crypt,
        });
    }

    /// Drop a source from reask state by endpoint. Best-effort.
    pub(crate) fn remove(&self, endpoint: (Ipv4Addr, u16)) {
        let _ = self.0.try_send(ReaskCommand::Remove { endpoint });
    }
}

/// Create the detach-command channel: the handle goes to download sessions, the
/// receiver to [`run_ed2k_udp_reask_loop`].
pub fn reask_command_channel() -> (ReaskSourceHandle, ReaskCommandReceiver) {
    let (tx, rx) = mpsc::channel(REASK_COMMAND_CHANNEL_BOUND);
    (ReaskSourceHandle(tx), rx)
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

/// Run the UDP source-reask loop until `shutdown` is set. Spawned by core only
/// when `enable_udp_reask` is on; off by default because the transport must be
/// wire-validated before it is trusted.
pub async fn run_ed2k_udp_reask_loop(
    dht: DhtNode,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    mut commands: ReaskCommandReceiver,
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
            maybe = commands.recv() => {
                let Some(command) = maybe else { break };
                apply_reask_command(&mut service, command);
            }
            _ = ticker.tick() => {
                drive_reask_tick(&mut service, &dht, &transfer_runtime).await;
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

/// Apply a download session's detach command to the reask source state.
fn apply_reask_command(service: &mut ReaskService, command: ReaskCommand) {
    match command {
        ReaskCommand::Register {
            file_hash,
            endpoint,
            udp_version,
            user_hash,
            should_crypt,
        } => {
            let mut source = ReaskSource::new(endpoint, file_hash, udp_version, Instant::now());
            if let Some(hash) = user_hash {
                source = source.with_obfuscation(hash, should_crypt);
            }
            trace!(
                "ed2k udp reask: detaching source {}:{} for {} onto UDP reask",
                endpoint.0, endpoint.1, file_hash
            );
            service.register_source(file_hash, source);
        }
        ReaskCommand::Remove { endpoint } => {
            service.remove_source(endpoint.0, endpoint.1);
        }
    }
}

/// Drive one reask tick: send due reask pings and account timed-out reasks.
/// Per-file transfer info (our part availability) is pulled from the transfer
/// runtime before the sync `tick`, since the source state lives in the service.
async fn drive_reask_tick(
    service: &mut ReaskService,
    dht: &DhtNode,
    transfer_runtime: &Ed2kTransferRuntime,
) {
    // Pre-fetch each registered file's reask info (async manifest read) so the
    // sync `tick` closure can look it up without blocking.
    let mut info_by_file: std::collections::HashMap<Ed2kHash, TransferReaskInfo> =
        std::collections::HashMap::new();
    for file_hash in service.registered_file_hashes() {
        let info = transfer_runtime.reask_transfer_info(&file_hash).await;
        info_by_file.insert(file_hash, info);
    }

    let out = service.tick(Instant::now(), REASK_REPLY_TIMEOUT, |file_hash| {
        info_by_file
            .get(file_hash)
            .cloned()
            .unwrap_or(TransferReaskInfo {
                part_status: None,
                complete_source_count: 0,
            })
    });
    for (addr, datagram) in out.send {
        match dht.send_raw_datagram(addr, &datagram).await {
            Ok(()) => trace!("ed2k udp reask: sent reask ping to {addr} ({} bytes)", datagram.len()),
            Err(err) => trace!("ed2k udp reask: send to {addr} failed: {err}"),
        }
    }
    for (addr, action) in out.timed_out {
        trace!("ed2k udp reask: reask to {addr} timed out: {action:?}");
        // On RetryTcp the source has exhausted its UDP-reask budget (failure ratio
        // tripped). Drop it from reask state so it returns to the normal TCP path:
        // it stays in the transfer's remembered sources, so core's next download
        // cycle re-acquires and reconnects it over TCP. (RetryUdp keeps reasking.)
        if matches!(action, ReaskAction::RetryTcp)
            && let SocketAddr::V4(v4) = addr
        {
            service.remove_source(*v4.ip(), v4.port());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_ip::SharedPublicIp;

    fn service() -> ReaskService {
        let public_ip = SharedPublicIp::new();
        public_ip.set(std::net::Ipv4Addr::new(203, 0, 113, 9));
        ReaskService::new([0x10; 16], 4, public_ip)
    }

    #[test]
    fn register_command_adds_a_source_and_remove_drops_it() {
        let mut svc = service();
        let file_hash = Ed2kHash::from_bytes([0xAB; 16]);
        let endpoint = (Ipv4Addr::new(198, 51, 100, 7), 4672);
        apply_reask_command(
            &mut svc,
            ReaskCommand::Register {
                file_hash,
                endpoint,
                udp_version: 4,
                user_hash: Some([0x55; 16]),
                should_crypt: true,
            },
        );
        assert_eq!(svc.source_count(), 1);
        assert_eq!(svc.registered_file_hashes(), vec![file_hash]);

        apply_reask_command(&mut svc, ReaskCommand::Remove { endpoint });
        assert_eq!(svc.source_count(), 0);
        assert!(svc.registered_file_hashes().is_empty());
    }

    #[test]
    fn detach_handle_register_is_received_as_a_command() {
        let (handle, mut rx) = reask_command_channel();
        let file_hash = Ed2kHash::from_bytes([0xCD; 16]);
        handle.detach(file_hash, (Ipv4Addr::new(10, 0, 0, 1), 5000), 4, None, false);
        match rx.try_recv().expect("a queued command") {
            ReaskCommand::Register { endpoint, .. } => {
                assert_eq!(endpoint, (Ipv4Addr::new(10, 0, 0, 1), 5000));
            }
            other => panic!("expected Register, got {other:?}"),
        }
    }
}
