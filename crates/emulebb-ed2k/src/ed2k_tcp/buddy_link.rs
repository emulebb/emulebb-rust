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
use tracing::{debug, info};

use crate::buddy_socket::BuddySocketRegistry;
use crate::ed2k_transfer::Ed2kTransferRuntime;

use super::codec::decode_kad_callback_payload;
use super::firewall_helper::{connect_callback_peer, is_connection_shutdown_error};
use super::hello::{build_hello_responses, encode_emule_info_answer, encode_hello_request};
use super::transport::{Ed2kTransport, EmuleTcpPacket};
use super::{
    ED2K_CONNECTION_IDLE_TIMEOUT, Ed2kHelloIdentity, OP_BUDDYPING, OP_BUDDYPONG, OP_CALLBACK,
    OP_EDONKEYPROT, OP_EMULEINFO, OP_EMULEINFOANSWER, OP_EMULEPROT, OP_HELLO, OP_HELLOANSWER,
};

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
    /// Connect/IO timeout.
    pub timeout: Duration,
    /// Notified once the buddy link has dropped, so the buddy-management loop can
    /// re-search (oracle buddy-loss `SetFindBuddy`).
    pub lost: Arc<Notify>,
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
        timeout,
        lost,
    } = options;

    let buddy_ip = match buddy_addr.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => anyhow::bail!("IPv6 buddy connections are not supported: {buddy_addr}"),
    };

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

    // Send an initial ping right away so the buddy immediately treats us as live,
    // then ping at the oracle cadence.
    let mut ping_timer = tokio::time::interval(BUDDY_PING_INTERVAL);
    ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let result = drive_buddy_link(
        &mut transport,
        &mut ping_timer,
        bind_ip,
        buddy_addr,
        hello_identity,
        own_kad_id,
        &transfer_runtime,
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

async fn drive_buddy_link(
    transport: &mut Ed2kTransport,
    ping_timer: &mut tokio::time::Interval,
    bind_ip: Ipv4Addr,
    buddy_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    own_kad_id: [u8; 16],
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
) -> Result<()> {
    loop {
        let read = tokio::time::timeout(BUDDY_READ_POLL, transport.read_packet());
        tokio::select! {
            biased;
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
async fn handle_buddy_packet(
    transport: &mut Ed2kTransport,
    bind_ip: Ipv4Addr,
    buddy_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    own_kad_id: [u8; 16],
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    packet: EmuleTcpPacket,
) -> Result<bool> {
    match (packet.protocol, packet.opcode) {
        (OP_EMULEPROT, OP_CALLBACK) => {
            let callback = decode_kad_callback_payload(&packet.payload)?;
            info!(
                "buddy {buddy_addr} relayed OP_CALLBACK file_hash={} requester={}:{}",
                callback.file_hash, callback.peer_ip, callback.peer_tcp_port
            );
            // Validate the relayed callback before connecting out, mirroring the
            // oracle ListenSocket.cpp OP_CALLBACK guard so a malicious buddy
            // cannot induce spurious connect-outs:
            //   (a) uCheck XOR allones must equal our own Kad id, and
            //   (b) the file must be one we share or download.
            if !buddy_callback_check_matches(callback.buddy_check, own_kad_id) {
                debug!(
                    "dropping buddy {buddy_addr} OP_CALLBACK: uCheck does not match our Kad id"
                );
                return Ok(true);
            }
            if !transfer_runtime.owns_file(&callback.file_hash).await {
                debug!(
                    "dropping buddy {buddy_addr} OP_CALLBACK: file {} is neither shared nor downloaded",
                    callback.file_hash
                );
                return Ok(true);
            }
            // Firewalled callback completion: connect out to the requester so it
            // can reach us (oracle CUpDownClient buddy-callback path). Skip
            // obviously invalid endpoints.
            if callback.peer_tcp_port != 0 && !callback.peer_ip.is_unspecified() {
                let requester =
                    SocketAddr::new(IpAddr::V4(callback.peer_ip), callback.peer_tcp_port);
                tokio::spawn(async move {
                    match connect_callback_peer(
                        bind_ip,
                        requester,
                        hello_identity,
                        None,
                        None,
                        ED2K_CONNECTION_IDLE_TIMEOUT,
                    )
                    .await
                    {
                        Ok(mode) => info!(
                            "Kad firewalled-callback connect-out to {requester} completed \
                             transport={}",
                            mode.as_str()
                        ),
                        Err(error) => debug!(
                            "Kad firewalled-callback connect-out to {requester} failed: {error:#}"
                        ),
                    }
                });
            }
            Ok(true)
        }
        // The buddy answers our ping with a pong; just keep the link alive.
        (OP_EMULEPROT, OP_BUDDYPONG) | (OP_EMULEPROT, OP_BUDDYPING) => {
            debug!("received buddy keepalive opcode=0x{:02X} from {buddy_addr}", packet.opcode);
            Ok(true)
        }
        // Late hello/info chatter from the buddy: answer info, otherwise ignore.
        (OP_EDONKEYPROT, OP_HELLO) => {
            for reply in build_hello_responses(&packet.payload, hello_identity)? {
                transport
                    .write_all(&reply)
                    .await
                    .with_context(|| format!("failed to reply to OP_HELLO from buddy {buddy_addr}"))?;
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

/// Validate a relayed OP_CALLBACK `uCheck` against our own Kad id.
///
/// The oracle (ListenSocket.cpp OP_CALLBACK) reads `uCheck`, XORs it with the
/// all-ones CUInt128, and only proceeds when the result equals its own Kad id.
/// XOR with all-ones is the bitwise complement, so this is equivalent to
/// `!uCheck[i] == own_kad_id[i]` for every byte.
fn buddy_callback_check_matches(buddy_check: [u8; 16], own_kad_id: [u8; 16]) -> bool {
    buddy_check
        .iter()
        .zip(own_kad_id.iter())
        .all(|(check, own)| !check == *own)
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
    use super::buddy_callback_check_matches;

    #[test]
    fn callback_check_accepts_complement_of_our_kad_id() {
        let own = [0xABu8; 16];
        // The requester places `own XOR allones` (= complement) into uCheck.
        let check = own.map(|byte| !byte);
        assert!(buddy_callback_check_matches(check, own));
    }

    #[test]
    fn callback_check_rejects_mismatched_check_value() {
        let own = [0xABu8; 16];
        // Echoing our id verbatim (not the complement) must be rejected.
        assert!(!buddy_callback_check_matches(own, own));
        // An unrelated value is rejected.
        assert!(!buddy_callback_check_matches([0x00u8; 16], own));
        // A single flipped byte breaks the match.
        let mut almost = own.map(|byte| !byte);
        almost[7] ^= 0x01;
        assert!(!buddy_callback_check_matches(almost, own));
    }
}
