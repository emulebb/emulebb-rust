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
use emulebb_kad_dht::DhtNode;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::buddy_socket::BuddySocketRegistry;
use crate::ed2k_transfer::Ed2kTransferRuntime;

use super::buddy_liveness::BuddyLiveness;
use super::codec::decode_reask_callback_tcp_payload;
use super::firewall_helper::{
    complete_authorized_kad_callback, decode_kad_callback_if_running, is_connection_shutdown_error,
};
use super::hello::{build_hello_responses, encode_emule_info_answer, encode_hello_request};
use super::transport::{Ed2kTransport, EmuleTcpPacket};
use super::{
    Ed2kCallbackSessionHandle, Ed2kHelloIdentity, OP_BUDDYPING, OP_BUDDYPONG, OP_CALLBACK,
    OP_EDONKEYPROT, OP_EMULEINFO, OP_EMULEINFOANSWER, OP_EMULEPROT, OP_HELLO, OP_HELLOANSWER,
    OP_REASKCALLBACKTCP, decode_kad_callback_payload,
};
use crate::ed2k_client_udp::ReaskSourceHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuddyLinkEnd {
    Cancelled,
    PeerClosed,
    ReceiveTimedOut,
}

/// Inputs for the outbound buddy link task.
pub struct OutboundBuddyLinkOptions {
    /// VPN/tunnel bind IP for the buddy socket.
    pub bind_ip: Ipv4Addr,
    /// The buddy's TCP endpoint (its source IP + the TCP port it returned).
    pub buddy_addr: SocketAddr,
    /// The buddy's eD2k user hash (used for registry identity + obfuscation).
    pub buddy_user_hash: [u8; 16],
    /// Connect-option byte the buddy advertised in `FINDBUDDY_RES`.
    pub buddy_connect_options: u8,
    /// Our hello identity, so the buddy recognizes us as its incoming buddy.
    pub hello_identity: Ed2kHelloIdentity,
    /// Live Kad state and identity used to gate and validate relayed
    /// `OP_CALLBACK` frames (oracle requires `CKademlia::IsRunning()` and
    /// `check XOR allones == GetKadID()`).
    pub dht: DhtNode,
    /// Transfer runtime, used to confirm the relayed callback file is one we
    /// share or download before connecting out (oracle GetFileByID guard).
    pub transfer_runtime: Arc<Ed2kTransferRuntime>,
    /// Listener-owned dispatcher for callbacks relayed over this buddy link.
    pub callback_sessions: Ed2kCallbackSessionHandle,
    /// The shared buddy-socket registry (outbound slot).
    pub registry: BuddySocketRegistry,
    /// Handle to the UDP reask loop, so a buddy-relayed `OP_REASKCALLBACKTCP` can
    /// be answered over UDP (source side). `None` when the reask transport is
    /// disabled; the relay is then decoded-and-logged only (the downloader retries
    /// or falls back to TCP), exactly as when no buddy is available.
    pub reask_handle: Option<ReaskSourceHandle>,
    /// Connect/IO timeout.
    pub timeout: Duration,
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
/// the outbound slot is evicted and the termination reason is returned.
pub async fn run_outbound_buddy_link(options: OutboundBuddyLinkOptions) -> Result<BuddyLinkEnd> {
    let OutboundBuddyLinkOptions {
        bind_ip,
        buddy_addr,
        buddy_user_hash,
        buddy_connect_options,
        hello_identity,
        dht,
        transfer_runtime,
        callback_sessions,
        registry,
        reask_handle,
        timeout,
        cancel,
    } = options;

    let buddy_ip = match buddy_addr.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => anyhow::bail!("IPv6 buddy connections are not supported: {buddy_addr}"),
    };

    // If the relationship was already cancelled while the connect was queued,
    // don't even open the socket.
    if cancel.is_cancelled() {
        return Ok(BuddyLinkEnd::Cancelled);
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

    let result = drive_buddy_link(
        &mut transport,
        buddy_addr,
        hello_identity,
        &dht,
        &transfer_runtime,
        &callback_sessions,
        reask_handle.as_ref(),
        &cancel,
    )
    .await;

    if !registry.evict_outbound_if(buddy_ip, buddy_user_hash) {
        debug!(
            "outbound Kad buddy link to {buddy_addr} ended after its registry slot was replaced"
        );
    }
    match &result {
        Ok(BuddyLinkEnd::Cancelled) => {
            info!("outbound Kad buddy link to {buddy_addr} cancelled")
        }
        Ok(BuddyLinkEnd::PeerClosed) => {
            info!("outbound Kad buddy link to {buddy_addr} closed; will re-search")
        }
        Ok(BuddyLinkEnd::ReceiveTimedOut) => {
            info!("outbound Kad buddy link to {buddy_addr} receive-timed out; will re-search")
        }
        Err(error) => debug!("outbound Kad buddy link to {buddy_addr} ended: {error:#}"),
    }
    result
}

#[expect(
    clippy::too_many_arguments,
    reason = "flat protocol or runtime boundary"
)]
async fn drive_buddy_link(
    transport: &mut Ed2kTransport,
    buddy_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    dht: &DhtNode,
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    callback_sessions: &Ed2kCallbackSessionHandle,
    reask_handle: Option<&ReaskSourceHandle>,
    cancel: &CancellationToken,
) -> Result<BuddyLinkEnd> {
    let mut liveness = BuddyLiveness::new(tokio::time::Instant::now());
    loop {
        tokio::select! {
            biased;
            // The buddy-management loop cancels this token when the relationship
            // is no longer warranted (HighID / Kad-disconnect); stop the keepalive
            // and drop the socket so the remote helper's buddy slot is freed.
            () = cancel.cancelled() => return Ok(BuddyLinkEnd::Cancelled),
            () = tokio::time::sleep_until(liveness.receive_deadline()) => {
                return Ok(BuddyLinkEnd::ReceiveTimedOut);
            }
            () = tokio::time::sleep_until(liveness.next_ping_at()) => {
                let ping = super::codec::encode_buddy_ping();
                transport
                    .write_all(&ping)
                    .await
                    .with_context(|| format!("failed to send OP_BUDDYPING to buddy {buddy_addr}"))?;
                liveness.record_ping_sent(tokio::time::Instant::now());
                debug!("sent OP_BUDDYPING to buddy {buddy_addr}");
            }
            outcome = transport.read_packet_diagnostic("kad_buddy", buddy_addr, "session") => {
                match outcome {
                    Ok(None) => return Ok(BuddyLinkEnd::PeerClosed),
                    Ok(Some(packet)) => {
                        match handle_buddy_packet(
                            transport,
                            buddy_addr,
                            hello_identity,
                            dht,
                            transfer_runtime,
                            callback_sessions,
                            reask_handle,
                            packet,
                        )
                        .await? {
                            BuddyPacketActivity::None => {}
                            BuddyPacketActivity::Received => {
                                liveness.record_received(tokio::time::Instant::now());
                            }
                            BuddyPacketActivity::Keepalive => {
                                liveness.record_keepalive_received(tokio::time::Instant::now());
                            }
                        }
                    }
                    Err(error) if is_connection_shutdown_error(&error) => {
                        return Ok(BuddyLinkEnd::PeerClosed);
                    }
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("buddy link read failed from {buddy_addr}"));
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuddyPacketActivity {
    None,
    Received,
    Keepalive,
}

/// Handle one inbound packet on the held buddy socket.
#[expect(
    clippy::too_many_arguments,
    reason = "flat protocol or runtime boundary"
)]
async fn handle_buddy_packet(
    transport: &mut Ed2kTransport,
    buddy_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    dht: &DhtNode,
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    callback_sessions: &Ed2kCallbackSessionHandle,
    reask_handle: Option<&ReaskSourceHandle>,
    packet: EmuleTcpPacket,
) -> Result<BuddyPacketActivity> {
    match (packet.protocol, packet.opcode) {
        (OP_EMULEPROT, OP_CALLBACK) => {
            let source = format!("buddy {buddy_addr}");
            if let Err(error) = decode_kad_callback_payload(&packet.payload) {
                if dht.is_running() {
                    return Err(error);
                }
                debug!(
                    "ignoring malformed {source} OP_CALLBACK while Kad is not running: {error:#}"
                );
                return Ok(BuddyPacketActivity::None);
            }
            let Some(callback) = decode_kad_callback_if_running(dht, &packet.payload, &source)?
            else {
                return Ok(BuddyPacketActivity::Received);
            };
            debug!(
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
                dht,
                transfer_runtime,
                callback_sessions,
                &callback,
                &source,
            )
            .await;
            Ok(BuddyPacketActivity::Received)
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
                        handle.answer_callback_tcp(dest, reask.forwarded_reask);
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
                Err(error) => {
                    debug!(
                        "ignoring malformed OP_REASKCALLBACKTCP from buddy {buddy_addr}: {error:#}"
                    );
                    return Ok(BuddyPacketActivity::None);
                }
            }
            Ok(BuddyPacketActivity::Received)
        }
        (OP_EMULEPROT, OP_BUDDYPONG) | (OP_EMULEPROT, OP_BUDDYPING) => {
            if !packet.payload.is_empty() {
                debug!(
                    "ignoring malformed buddy keepalive opcode=0x{:02X} payload_len={} from {buddy_addr}",
                    packet.opcode,
                    packet.payload.len()
                );
                return Ok(BuddyPacketActivity::None);
            }
            if packet.opcode == OP_BUDDYPING {
                transport
                    .write_all(&super::codec::encode_buddy_pong())
                    .await
                    .with_context(|| {
                        format!("failed to send OP_BUDDYPONG to buddy {buddy_addr}")
                    })?;
            }
            debug!(
                "received buddy keepalive opcode=0x{:02X} from {buddy_addr}",
                packet.opcode
            );
            Ok(BuddyPacketActivity::Keepalive)
        }
        // Late hello/info chatter from the buddy: answer info, otherwise ignore.
        (OP_EDONKEYPROT, OP_HELLO) => {
            for reply in build_hello_responses(&packet.payload, hello_identity)? {
                transport.write_all(&reply).await.with_context(|| {
                    format!("failed to reply to OP_HELLO from buddy {buddy_addr}")
                })?;
            }
            Ok(BuddyPacketActivity::Received)
        }
        (OP_EMULEPROT, OP_EMULEINFO) => {
            let reply = encode_emule_info_answer(hello_identity.udp_port);
            transport.write_all(&reply).await.with_context(|| {
                format!("failed to send OP_EMULEINFOANSWER to buddy {buddy_addr}")
            })?;
            Ok(BuddyPacketActivity::Received)
        }
        (OP_EDONKEYPROT, OP_HELLOANSWER) | (OP_EMULEPROT, OP_EMULEINFOANSWER) => {
            Ok(BuddyPacketActivity::Received)
        }
        // Any other opcode on the buddy link is unexpected; ignore but keep open.
        _ => {
            debug!(
                "ignoring unexpected buddy-link packet protocol=0x{:02X} opcode=0x{:02X} from {buddy_addr}",
                packet.protocol, packet.opcode
            );
            Ok(BuddyPacketActivity::None)
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
        let packet = match tokio::time::timeout(
            remaining,
            transport.read_packet_diagnostic("kad_buddy", buddy_addr, "hello_exchange"),
        )
        .await
        {
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

    use emulebb_kad_dht::{DhtConfig, DhtNode};
    use emulebb_kad_proto::NodeId;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::sync::CancellationToken;

    use super::super::transport::{Ed2kTransport, Ed2kTransportMode};
    use super::super::{
        Ed2kHelloIdentity, EmuleTcpPacket, OP_BUDDYPING, OP_BUDDYPONG, OP_CALLBACK, OP_EMULEPROT,
        OP_REASKCALLBACKTCP, encode_packet,
    };
    use super::{BuddyLinkEnd, BuddyPacketActivity, drive_buddy_link, handle_buddy_packet};
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

    async fn spawn_buddy_driver() -> (
        tokio::task::JoinHandle<anyhow::Result<BuddyLinkEnd>>,
        Ed2kTransport,
        CancellationToken,
    ) {
        let bind_ip = crate::test_bind_ip();
        let listener = TcpListener::bind((bind_ip, 0)).await.unwrap();
        let buddy_addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(buddy_addr).await.unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        let mut transport = Ed2kTransport::from_parts(
            client,
            VecDeque::new(),
            None,
            None,
            Ed2kTransportMode::Plaintext,
        );
        let peer = Ed2kTransport::from_parts(
            peer,
            VecDeque::new(),
            None,
            None,
            Ed2kTransportMode::Plaintext,
        );
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(SocketAddr::from((bind_ip, 0))),
            node_id: NodeId::from_bytes([0xAB; 16]),
            udp_key: 0x1122_3344,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let transfer_runtime =
            Arc::new(Ed2kTransferRuntime::load_or_create(temp_dir.path()).unwrap());
        let (callback_sessions, callback_session_inbox) =
            super::super::ed2k_callback_session_channel();
        let cancel = CancellationToken::new();
        let driver_cancel = cancel.clone();
        let driver = tokio::spawn(async move {
            let _temp_dir = temp_dir;
            let _callback_session_inbox = callback_session_inbox;
            drive_buddy_link(
                &mut transport,
                buddy_addr,
                dummy_hello_identity(),
                &dht,
                &transfer_runtime,
                &callback_sessions,
                None,
                &driver_cancel,
            )
            .await
        });
        tokio::task::yield_now().await;
        (driver, peer, cancel)
    }

    /// The held buddy link follows the same stock pre-parse Kad-running gate as
    /// an ordinary inbound client session. Malformed stopped-Kad traffic is
    /// ignored and the persistent relay connection remains usable.
    #[tokio::test]
    async fn stopped_kad_ignores_malformed_callback_without_closing_buddy_link() {
        let bind_ip = crate::test_bind_ip();
        let listener = TcpListener::bind((bind_ip, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (_server, _) = listener.accept().await.unwrap();
        let mut transport = Ed2kTransport::from_parts(
            client,
            VecDeque::new(),
            None,
            None,
            Ed2kTransportMode::Plaintext,
        );
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(SocketAddr::from((bind_ip, 0))),
            node_id: NodeId::from_bytes([0xAB; 16]),
            udp_key: 0x1122_3344,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        dht.set_running(false);
        let tmp = tempfile::tempdir().unwrap();
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(tmp.path()).unwrap());
        let (callback_sessions, _callback_session_inbox) =
            super::super::ed2k_callback_session_channel();

        assert_eq!(
            handle_buddy_packet(
                &mut transport,
                addr,
                dummy_hello_identity(),
                &dht,
                &transfer_runtime,
                &callback_sessions,
                None,
                EmuleTcpPacket {
                    protocol: OP_EMULEPROT,
                    opcode: OP_CALLBACK,
                    payload: vec![0x01],
                },
            )
            .await
            .unwrap(),
            BuddyPacketActivity::None
        );
    }

    /// LOWID-G8: cancelling the buddy link's token must stop the keepalive loop
    /// (and thus the OP_BUDDYPINGs) instead of running until the socket dies, so
    /// the remote helper's single buddy slot is freed promptly when we stop being
    /// firewalled / Kad disconnects.
    #[tokio::test(start_paused = true)]
    async fn buddy_link_stops_and_stops_pinging_when_cancelled() {
        let (driver, _peer, cancel) = spawn_buddy_driver().await;
        cancel.cancel();
        assert_eq!(driver.await.unwrap().unwrap(), BuddyLinkEnd::Cancelled);
    }

    #[tokio::test(start_paused = true)]
    async fn silent_buddy_expires_while_outbound_pings_succeed() {
        let (driver, mut peer, _cancel) = spawn_buddy_driver().await;

        for _ in 0..2 {
            tokio::time::advance(Duration::from_secs(10 * 60)).await;
            for _ in 0..3 {
                tokio::task::yield_now().await;
            }
            assert!(!driver.is_finished());
        }
        tokio::time::advance(Duration::from_secs(5 * 60)).await;

        assert_eq!(
            driver.await.unwrap().unwrap(),
            BuddyLinkEnd::ReceiveTimedOut
        );

        let mut ping_count = 0;
        while let Some(packet) = peer.read_packet().await.unwrap() {
            assert_eq!(packet.protocol, OP_EMULEPROT);
            assert_eq!(packet.opcode, OP_BUDDYPING);
            assert!(packet.payload.is_empty());
            ping_count += 1;
        }
        assert_eq!(ping_count, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn valid_inbound_ping_is_answered_and_refreshes_receive_liveness() {
        let (driver, mut peer, _cancel) = spawn_buddy_driver().await;

        tokio::time::advance(Duration::from_secs(9 * 60)).await;
        peer.write_all(&encode_packet(OP_EMULEPROT, OP_BUDDYPING, &[]))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        let pong = peer.read_packet().await.unwrap().unwrap();
        assert_eq!(pong.protocol, OP_EMULEPROT);
        assert_eq!(pong.opcode, OP_BUDDYPONG);
        assert!(pong.payload.is_empty());

        tokio::time::advance(Duration::from_secs(16 * 60)).await;
        assert!(!driver.is_finished());

        tokio::time::advance(Duration::from_secs(9 * 60)).await;
        assert_eq!(
            driver.await.unwrap().unwrap(),
            BuddyLinkEnd::ReceiveTimedOut
        );
    }

    #[tokio::test(start_paused = true)]
    async fn malformed_and_partial_traffic_do_not_refresh_receive_liveness() {
        let (driver, mut peer, _cancel) = spawn_buddy_driver().await;

        tokio::time::advance(Duration::from_secs(24 * 60)).await;
        peer.write_all(&encode_packet(OP_EMULEPROT, OP_REASKCALLBACKTCP, &[1]))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        let partial = encode_packet(OP_EMULEPROT, OP_BUDDYPONG, &[]);
        peer.write_all(&partial[..3]).await.unwrap();
        tokio::time::advance(Duration::from_secs(60)).await;

        assert_eq!(
            driver.await.unwrap().unwrap(),
            BuddyLinkEnd::ReceiveTimedOut
        );
    }
}
