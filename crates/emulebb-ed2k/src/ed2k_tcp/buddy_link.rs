//! Outbound Kad buddy leg: the persistent TCP connection a firewalled (LowID)
//! client keeps to *its* buddy.
//!
//! When we are TCP-firewalled and have acquired a buddy (`FINDBUDDY_RES`
//! verified, oracle `RequestBuddy`), the oracle keeps a TCP socket open to that
//! buddy and pings it with `OP_BUDDYPING` once per upkeep window so the buddy
//! keeps relaying callbacks to us. When a third party wants us as a source, it
//! sends `KADEMLIA_CALLBACK_REQ` to our buddy, which relays an `OP_CALLBACK`
//! down this held socket; we then TCP-connect out to the requester (the standard
//! firewalled callback completion).
//!
//! This task owns the buddy [`Ed2kTransport`] for the lifetime of the buddy
//! relationship, registers itself in the [`BuddySocketRegistry`] outbound slot,
//! and on the socket dropping evicts itself and notifies the caller so the
//! buddy-management loop re-searches (oracle buddy-loss `SetFindBuddy`).
//!
//! Oracle references (do not modify):
//! - `srchybrid/ClientList.cpp` buddy upkeep: `KS_CONNECTED_BUDDY` sends
//!   `OP_BUDDYPING` while `IsFirewalled() && SendBuddyPingPong()`; buddy-loss
//!   triggers `SetFindBuddy()`.
//! - `srchybrid/UpDownClient.h` `SendBuddyPingPong` / `SetLastBuddyPingPongTime`
//!   (`MIN2MS(10)` cadence).
//! - `srchybrid/ListenSocket.cpp` `OP_CALLBACK` relayed to the firewalled client.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::buddy_socket::BuddySocketRegistry;
use crate::ed2k_transfer::Ed2kTransferRuntime;

use super::codec::{decode_kad_callback_payload, decode_reask_callback_tcp_payload};
use super::firewall_helper::{complete_authorized_kad_callback, is_connection_shutdown_error};
use super::hello::{build_hello_responses, encode_emule_info_answer, encode_hello_request};
use super::transport::{Ed2kTransport, EmuleTcpPacket};
use super::{
    Ed2kHelloIdentity, OP_BUDDYPING, OP_BUDDYPONG, OP_CALLBACK, OP_EDONKEYPROT, OP_EMULEINFO,
    OP_EMULEINFOANSWER, OP_EMULEPROT, OP_HELLO, OP_HELLOANSWER, OP_REASKCALLBACKTCP,
};
use crate::ed2k_client_udp::ReaskSourceHandle;

/// Buddy keepalive cadence. The oracle sets the next allowed buddy ping to
/// `now + MIN2MS(10)` (`SetLastBuddyPingPongTime`) and sends one whenever
/// `SendBuddyPingPong()` (now past that mark) is true during upkeep, i.e. once
/// every ten minutes.
const BUDDY_PING_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How long to wait for an inbound packet (incl. `OP_CALLBACK`) before checking
/// the ping/shutdown timers. Kept short so shutdown and the ping cadence stay
/// responsive without busy-looping.
const BUDDY_READ_POLL: Duration = Duration::from_secs(15);

/// Inputs for the outbound buddy link task.
pub struct OutboundBuddyLinkOptions {
    /// VPN/tunnel bind IP for the buddy socket and any callback connect-out.
    pub bind_ip: Ipv4Addr,
    /// The buddy's TCP endpoint (its source IP + the TCP port it returned).
    pub buddy_addr: SocketAddr,
    /// The buddy's eD2k user hash (used for registry identity + obfuscation).
    pub buddy_user_hash: [u8; 16],
    /// Connect-option byte the buddy advertised in `FINDBUDDY_RES`.
    pub buddy_connect_options: u8,
    /// Our hello identity, so the buddy recognizes us as its incoming buddy.
    pub hello_identity: Ed2kHelloIdentity,
    /// Our own Kad id, used to validate the `uCheck` field of a relayed
    /// OP_CALLBACK (oracle ListenSocket.cpp: `check XOR allones == GetKadID()`).
    pub own_kad_id: [u8; 16],
    /// Transfer runtime, used to confirm the relayed callback file is one we
    /// share or download before connecting out (oracle GetFileByID guard).
    pub transfer_runtime: Arc<Ed2kTransferRuntime>,
    /// The shared buddy-socket registry (outbound slot).
    pub registry: BuddySocketRegistry,
    /// Handle to the UDP reask loop, so a buddy-relayed `OP_REASKCALLBACKTCP` can
    /// be answered over UDP (source side). `None` when the reask transport is
    /// disabled; the relay is then decoded-and-logged only (the downloader retries
    /// or falls back to TCP), exactly as when no buddy is available.
    pub reask_handle: Option<ReaskSourceHandle>,
    /// Connect/IO timeout.
    pub timeout: Duration,
    /// Notified once the buddy link has dropped, so the buddy-management loop can
    /// re-search (oracle buddy-loss `SetFindBuddy`).
    pub lost: Arc<Notify>,
    /// Cancellation handle held by the buddy-management loop: cancelled when the
    /// buddy relationship is no longer warranted (we stopped being firewalled, or
    /// Kad disconnected), which tears the link down and stops the keepalive pings
    /// so we release the remote helper's single buddy slot promptly instead of
    /// waiting for the socket to die (oracle drops the buddy socket on HighID /
    /// Kad-disconnect, `ClientList.cpp:770-780`).
    pub cancel: CancellationToken,
}

/// Hold a persistent TCP connection to our buddy: connect + hello, register in
/// the outbound slot, ping at the oracle cadence, and complete firewalled
/// callbacks the buddy relays to us. Returns when the socket drops; on return
/// the outbound slot is evicted and `lost` is notified.
pub async fn run_outbound_buddy_link(options: OutboundBuddyLinkOptions) -> Result<()> {
    let OutboundBuddyLinkOptions {
        bind_ip,
        buddy_addr,
        buddy_user_hash,
        buddy_connect_options,
        hello_identity,
        own_kad_id,
        transfer_runtime,
        registry,
        reask_handle,
        timeout,
        lost,
        cancel,
    } = options;

    let buddy_ip = match buddy_addr.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => anyhow::bail!("IPv6 buddy connections are not supported: {buddy_addr}"),
    };

    // If the relationship was already cancelled while the connect was queued,
    // don't even open the socket.
    if cancel.is_cancelled() {
        lost.notify_one();
        return Ok(());
    }

    let mut transport = connect_and_hello_buddy(
        bind_ip,
        buddy_addr,
        buddy_user_hash,
        buddy_connect_options,
        hello_identity,
        timeout,
    )
    .await
    .with_context(|| format!("failed to establish buddy link to {buddy_addr}"))?;

    registry.register_outbound(buddy_ip, buddy_user_hash);
    info!(
        "established outbound Kad buddy link to {buddy_addr} transport={}",
        transport.mode.as_str()
    );

    // LOWID-G9a: the oracle's first buddy ping comes a full interval after the
    // buddy client object is created (its ctor arms m_dwLastBuddyPingPongTime to
    // now + MIN2MS(10), BaseClient.cpp:194 / UpDownClient.h:189), so
    // SendBuddyPingPong() first becomes true ~10 min later. Arm the first tick a
    // full interval out rather than firing at t=0.
    let mut ping_timer = tokio::time::interval_at(
        tokio::time::Instant::now() + BUDDY_PING_INTERVAL,
        BUDDY_PING_INTERVAL,
    );
    ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let result = drive_buddy_link(
        &mut transport,
        &mut ping_timer,
        bind_ip,
        buddy_addr,
        hello_identity,
        own_kad_id,
        &transfer_runtime,
        reask_handle.as_ref(),
        &cancel,
    )
    .await;

    registry.evict_outbound();
    lost.notify_one();
    match &result {
        Ok(()) => info!("outbound Kad buddy link to {buddy_addr} closed; will re-search"),
        Err(error) => debug!("outbound Kad buddy link to {buddy_addr} ended: {error:#}"),
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn drive_buddy_link(
    transport: &mut Ed2kTransport,
    ping_timer: &mut tokio::time::Interval,
    bind_ip: Ipv4Addr,
    buddy_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    own_kad_id: [u8; 16],
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    reask_handle: Option<&ReaskSourceHandle>,
    cancel: &CancellationToken,
) -> Result<()> {
    loop {
        let read = tokio::time::timeout(BUDDY_READ_POLL, transport.read_packet());
        tokio::select! {
            biased;
            // The buddy-management loop cancels this token when the relationship
            // is no longer warranted (HighID / Kad-disconnect); stop the keepalive
            // and drop the socket so the remote helper's buddy slot is freed.
            () = cancel.cancelled() => return Ok(()),
            _ = ping_timer.tick() => {
                let ping = super::codec::encode_buddy_ping();
                transport
                    .write_all(&ping)
                    .await
                    .with_context(|| format!("failed to send OP_BUDDYPING to buddy {buddy_addr}"))?;
                debug!("sent OP_BUDDYPING to buddy {buddy_addr}");
            }
            outcome = read => {
                match outcome {
                    // Idle read timeout: loop back so the ping timer can fire.
                    Err(_) => continue,
                    Ok(Ok(None)) => return Ok(()),
                    Ok(Ok(Some(packet))) => {
                        if !handle_buddy_packet(
                            transport,
                            bind_ip,
                            buddy_addr,
                            hello_identity,
                            own_kad_id,
                            transfer_runtime,
                            reask_handle,
                            packet,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                    Ok(Err(error)) if is_connection_shutdown_error(&error) => return Ok(()),
                    Ok(Err(error)) => {
                        return Err(error)
                            .with_context(|| format!("buddy link read failed from {buddy_addr}"));
                    }
                }
            }
        }
    }
}

/// Handle one inbound packet on the held buddy socket. Returns `false` to close.
#[allow(clippy::too_many_arguments)]
async fn handle_buddy_packet(
    transport: &mut Ed2kTransport,
    bind_ip: Ipv4Addr,
    buddy_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    own_kad_id: [u8; 16],
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    reask_handle: Option<&ReaskSourceHandle>,
    packet: EmuleTcpPacket,
) -> Result<bool> {
    match (packet.protocol, packet.opcode) {
        (OP_EMULEPROT, OP_CALLBACK) => {
            let callback = decode_kad_callback_payload(&packet.payload)?;
            info!(
                "buddy {buddy_addr} relayed OP_CALLBACK file_hash={} requester={}:{}",
                callback.file_hash, callback.peer_ip, callback.peer_tcp_port
            );
            // Validate the relayed callback and complete it through the shared
            // guard (oracle ListenSocket.cpp OP_CALLBACK: uCheck-complement ==
            // our Kad id AND the file is shared/downloaded), so a malicious buddy
            // cannot induce spurious connect-outs. The same guard runs on the
            // inbound listener session, so the two acceptance surfaces stay in
            // lock-step.
            complete_authorized_kad_callback(
                bind_ip,
                own_kad_id,
                transfer_runtime,
                hello_identity,
                &callback,
                &format!("buddy {buddy_addr}"),
            )
            .await;
            Ok(true)
        }
        (OP_EMULEPROT, OP_REASKCALLBACKTCP) => {
            // Source side: our buddy relayed a reask from a downloader that could
            // not reach us over client UDP. The frame carries the downloader's UDP
            // endpoint + the requested file; answer it over UDP exactly as an
            // inbound OP_REASKFILEPING (oracle ListenSocket.cpp OP_REASKCALLBACKTCP).
            match decode_reask_callback_tcp_payload(&packet.payload) {
                Ok(reask) => {
                    if let Some(handle) = reask_handle {
                        let dest = SocketAddr::new(IpAddr::V4(reask.dest_ip), reask.dest_port);
                        // The answer is derived from the file hash + our live
                        // upload-queue/catalog state (the relaying downloader's
                        // udp-version/partstatus tail is not needed to answer).
                        handle.answer_callback_tcp(dest, reask.file_hash);
                        debug!(
                            "buddy {buddy_addr} relayed OP_REASKCALLBACKTCP file_hash={} \
                             requester={dest}; answering over UDP",
                            reask.file_hash
                        );
                    } else {
                        debug!(
                            "buddy {buddy_addr} relayed OP_REASKCALLBACKTCP file_hash={} but UDP \
                             reask is disabled; ignoring (downloader will retry/TCP)",
                            reask.file_hash
                        );
                    }
                }
                Err(error) => debug!(
                    "ignoring malformed OP_REASKCALLBACKTCP from buddy {buddy_addr}: {error:#}"
                ),
            }
            Ok(true)
        }
        // The buddy answers our ping with a pong; just keep the link alive.
        (OP_EMULEPROT, OP_BUDDYPONG) | (OP_EMULEPROT, OP_BUDDYPING) => {
            debug!(
                "received buddy keepalive opcode=0x{:02X} from {buddy_addr}",
                packet.opcode
            );
            Ok(true)
        }
        // Late hello/info chatter from the buddy: answer info, otherwise ignore.
        (OP_EDONKEYPROT, OP_HELLO) => {
            for reply in build_hello_responses(&packet.payload, hello_identity)? {
                transport.write_all(&reply).await.with_context(|| {
                    format!("failed to reply to OP_HELLO from buddy {buddy_addr}")
                })?;
            }
            Ok(true)
        }
        (OP_EMULEPROT, OP_EMULEINFO) => {
            let reply = encode_emule_info_answer(hello_identity.udp_port);
            transport.write_all(&reply).await.with_context(|| {
                format!("failed to send OP_EMULEINFOANSWER to buddy {buddy_addr}")
            })?;
            Ok(true)
        }
        (OP_EDONKEYPROT, OP_HELLOANSWER) | (OP_EMULEPROT, OP_EMULEINFOANSWER) => Ok(true),
        // Any other opcode on the buddy link is unexpected; ignore but keep open.
        _ => {
            debug!(
                "ignoring unexpected buddy-link packet protocol=0x{:02X} opcode=0x{:02X} from {buddy_addr}",
                packet.protocol, packet.opcode
            );
            Ok(true)
        }
    }
}

/// Connect out to the buddy and complete the hello side channel so the buddy
/// recognizes us as its incoming buddy, returning the held transport.
async fn connect_and_hello_buddy(
    bind_ip: Ipv4Addr,
    buddy_addr: SocketAddr,
    buddy_user_hash: [u8; 16],
    buddy_connect_options: u8,
    hello_identity: Ed2kHelloIdentity,
    timeout: Duration,
) -> Result<Ed2kTransport> {
    let mut transport = Ed2kTransport::connect_outgoing(
        bind_ip,
        buddy_addr,
        hello_identity.connect_options,
        Some(buddy_user_hash),
        Some(buddy_connect_options),
        timeout,
    )
    .await?;

    let hello_packet = encode_hello_request(hello_identity);
    tokio::time::timeout(timeout, transport.write_all(&hello_packet))
        .await
        .with_context(|| format!("timed out sending OP_HELLO to buddy {buddy_addr}"))??;

    // Drive the hello exchange to completion (HELLOANSWER or a HELLO from the
    // buddy) so it has our identity before we start the keepalive.
    let deadline = tokio::time::Instant::now() + timeout.min(Duration::from_secs(5));
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = match tokio::time::timeout(remaining, transport.read_packet()).await {
            Ok(Ok(Some(packet))) => packet,
            Ok(Ok(None)) => break,
            Ok(Err(error)) if is_connection_shutdown_error(&error) => break,
            Ok(Err(error)) => {
                return Err(error)
                    .with_context(|| format!("failed to read hello from buddy {buddy_addr}"));
            }
            Err(_) => break,
        };
        match (packet.protocol, packet.opcode) {
            (OP_EDONKEYPROT, OP_HELLO) => {
                for reply in build_hello_responses(&packet.payload, hello_identity)? {
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to reply to OP_HELLO from buddy {buddy_addr}")
                    })?;
                }
                break;
            }
            (OP_EDONKEYPROT, OP_HELLOANSWER) | (OP_EMULEPROT, OP_EMULEINFOANSWER) => break,
            (OP_EMULEPROT, OP_EMULEINFO) => {
                let reply = encode_emule_info_answer(hello_identity.udp_port);
                transport.write_all(&reply).await.with_context(|| {
                    format!("failed to send OP_EMULEINFOANSWER to buddy {buddy_addr}")
                })?;
            }
            _ => {}
        }
    }

    Ok(transport)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::sync::CancellationToken;

    use super::super::Ed2kHelloIdentity;
    use super::super::transport::{Ed2kTransport, Ed2kTransportMode};
    use super::drive_buddy_link;
    use crate::ed2k_transfer::Ed2kTransferRuntime;

    fn dummy_hello_identity() -> Ed2kHelloIdentity {
        Ed2kHelloIdentity {
            user_hash: [0xCD; 16],
            client_id: 0,
            tcp_port: 4662,
            udp_port: 4672,
            server_ip: 0,
            server_port: 0,
            connect_options: 0,
            direct_udp_callback: false,
        }
    }

    /// LOWID-G8: cancelling the buddy link's token must stop the keepalive loop
    /// (and thus the OP_BUDDYPINGs) instead of running until the socket dies, so
    /// the remote helper's single buddy slot is freed promptly when we stop being
    /// firewalled / Kad disconnects.
    #[tokio::test]
    async fn buddy_link_stops_and_stops_pinging_when_cancelled() {
        // A fake buddy peer that accepts the connection and then stays silent, so
        // the driver would otherwise idle on its ping/read timers indefinitely.
        // Bind X_LOCAL_IP (never a loopback literal: the VPN split tunnel breaks
        // 127.0.0.1). CI exports X_LOCAL_IP=127.0.0.1.
        let bind_ip = crate::test_bind_ip();
        let listener = TcpListener::bind((bind_ip, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Hold the connection open (never send), and never observe an inbound
            // OP_BUDDYPING (the first ping is a full interval away).
            let mut buf = [0u8; 64];
            let _ = tokio::time::timeout(Duration::from_secs(3), sock.read(&mut buf)).await;
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let mut transport = Ed2kTransport::from_parts(
            client,
            VecDeque::new(),
            None,
            None,
            Ed2kTransportMode::Plaintext,
        );
        // First tick a full interval out (LOWID-G9a), so no ping fires during the test.
        let mut ping_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + super::BUDDY_PING_INTERVAL,
            super::BUDDY_PING_INTERVAL,
        );

        let tmp = tempfile::tempdir().unwrap();
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(tmp.path()).unwrap());
        let cancel = CancellationToken::new();
        let hello = dummy_hello_identity();

        let driver = drive_buddy_link(
            &mut transport,
            &mut ping_timer,
            bind_ip,
            SocketAddr::new(std::net::IpAddr::V4(bind_ip), addr.port()),
            hello,
            [0xAB; 16],
            &transfer_runtime,
            None,
            &cancel,
        );
        tokio::pin!(driver);

        let cancel_signal = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel_signal.cancel();
        });

        let outcome = tokio::time::timeout(Duration::from_secs(2), &mut driver).await;
        assert!(
            outcome.is_ok(),
            "drive_buddy_link did not return promptly after cancellation"
        );
        assert!(outcome.unwrap().is_ok());
        server.abort();
    }
}
