use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tracing::{debug, info};

use emulebb_kad_dht::DhtNode;

use crate::ed2k_transfer::Ed2kTransferRuntime;

use super::codec::KadCallbackRequest;
use super::dump::{
    dump_ed2k_tcp_helper_meta, dump_ed2k_tcp_helper_recv, dump_ed2k_tcp_helper_send,
};
use super::hello::{decode_hello_answer_profile, decode_hello_profile, encode_hello_answer};
use super::{
    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, ED2K_SECURE_IDENT_SIGNATURE_NEEDED,
    EMULE_CRYPT_REQUESTS, EMULE_CRYPT_SUPPORTS, Ed2kHelloIdentity, Ed2kPeerConnectMode,
    Ed2kPeerSecureIdentState, Ed2kSecureIdent, Ed2kTransport, Ed2kTransportMode, EmuleTcpPacket,
    FIREWALL_HELPER_POST_REQUEST_KEEPALIVE_SECS, FirewallCheckUdpRequest, OP_EDONKEYPROT,
    OP_EMULEINFO, OP_EMULEINFOANSWER, OP_EMULEPROT, OP_FWCHECKUDPREQ, OP_HELLO, OP_HELLOANSWER,
    OP_KAD_FWTCPCHECK_ACK, OP_PUBLICKEY, OP_SECIDENTSTATE, OP_SIGNATURE, begin_secure_ident_probe,
    build_hello_responses, decode_public_key_payload, decode_secident_state,
    encode_emule_info_answer, encode_hello_request, encode_packet, encode_secident_state,
    random_nonzero_u32, reply_with_firewall_udp, try_send_secure_ident_signature,
};

/// Immutable session metadata shared by one outgoing TCP helper exchange.
#[derive(Clone, Copy)]
struct FirewallHelperContext<'a> {
    helper_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    kad_udp_port: u16,
    secure_ident: &'a Ed2kSecureIdent,
    dht: Option<&'a DhtNode>,
}

async fn drive_firewall_helper_hello_exchange(
    transport: &mut Ed2kTransport,
    context: FirewallHelperContext<'_>,
    peer_secure_ident: &mut Ed2kPeerSecureIdentState,
    timeout: Duration,
) -> Result<bool> {
    let mut hello_completed = false;
    let hello_packet = encode_hello_request(context.hello_identity);
    dump_ed2k_tcp_helper_send(
        context.helper_addr,
        transport.mode,
        "hello_request",
        &hello_packet,
    );
    tokio::time::timeout(timeout, transport.write_all(&hello_packet))
        .await
        .with_context(|| format!("timed out sending OP_HELLO to {}", context.helper_addr))??;

    // The oracle only advances the dedicated UDP firewall-check flow once the
    // HELLO side channel actually answered. Keep this bounded, but do not fall
    // through to OP_FWCHECKUDPREQ after a short silent timeout.
    let exchange_deadline = tokio::time::Instant::now() + timeout.min(Duration::from_secs(3));
    while tokio::time::Instant::now() < exchange_deadline {
        let remaining = exchange_deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = match tokio::time::timeout(remaining, transport.read_packet()).await {
            Ok(Ok(Some(packet))) => packet,
            Ok(Ok(None)) => {
                dump_ed2k_tcp_helper_meta(
                    context.helper_addr,
                    Some(transport.mode),
                    "hello_exchange_closed",
                    || ("connection closed before helper hello exchange completed").into(),
                );
                break;
            }
            Ok(Err(error)) if is_connection_shutdown_error(&error) => break,
            Ok(Err(error)) => {
                dump_ed2k_tcp_helper_meta(
                    context.helper_addr,
                    Some(transport.mode),
                    "hello_exchange_error",
                    || error.to_string(),
                );
                return Err(error).with_context(|| {
                    format!("failed to read eD2k packet from {}", context.helper_addr)
                });
            }
            Err(_) => break,
        };
        let packet_completed_hello = helper_packet_completes_hello(&packet);
        if !handle_firewall_helper_packet(
            transport,
            context,
            peer_secure_ident,
            "hello_exchange",
            packet,
        )
        .await?
        {
            break;
        }
        hello_completed |= packet_completed_hello;
        if hello_completed {
            break;
        }
    }

    Ok(hello_completed)
}

fn helper_packet_completes_hello(packet: &EmuleTcpPacket) -> bool {
    matches!(
        (packet.protocol, packet.opcode),
        (OP_EDONKEYPROT, OP_HELLO) | (OP_EDONKEYPROT, OP_HELLOANSWER)
    )
}

async fn handle_firewall_helper_packet(
    transport: &mut Ed2kTransport,
    context: FirewallHelperContext<'_>,
    peer_secure_ident: &mut Ed2kPeerSecureIdentState,
    phase: &str,
    packet: EmuleTcpPacket,
) -> Result<bool> {
    dump_ed2k_tcp_helper_recv(context.helper_addr, transport.mode, phase, &packet);

    match (packet.protocol, packet.opcode) {
        (OP_EDONKEYPROT, OP_HELLO) => {
            let hello_profile = decode_hello_profile(&packet.payload)?;
            let reply = encode_hello_answer(context.hello_identity);
            dump_ed2k_tcp_helper_send(context.helper_addr, transport.mode, "hello_answer", &reply);
            transport.write_all(&reply).await.with_context(|| {
                format!("failed to send OP_HELLOANSWER to {}", context.helper_addr)
            })?;
            if hello_profile.supports_secure_ident && !peer_secure_ident.requested_peer_key {
                let request = begin_secure_ident_probe(peer_secure_ident);
                dump_ed2k_tcp_helper_send(
                    context.helper_addr,
                    transport.mode,
                    "secure_ident_probe",
                    &request,
                );
                transport.write_all(&request).await.with_context(|| {
                    format!("failed to send OP_SECIDENTSTATE to {}", context.helper_addr)
                })?;
            }
        }
        (OP_EDONKEYPROT, OP_HELLOANSWER) => {
            // Oracle behavior: a mule-style HELLOANSWER already satisfies the
            // "both info packets received" gate, so the helper immediately
            // starts secure-ident before it sends OP_FWCHECKUDPREQ.
            let hello_profile = decode_hello_answer_profile(&packet.payload)?;
            if hello_profile.supports_secure_ident && !peer_secure_ident.requested_peer_key {
                let request = begin_secure_ident_probe(peer_secure_ident);
                dump_ed2k_tcp_helper_send(
                    context.helper_addr,
                    transport.mode,
                    "secure_ident_probe",
                    &request,
                );
                transport.write_all(&request).await.with_context(|| {
                    format!("failed to send OP_SECIDENTSTATE to {}", context.helper_addr)
                })?;
            }
        }
        (OP_EMULEPROT, OP_EMULEINFO) => {
            let reply = encode_emule_info_answer(context.kad_udp_port);
            dump_ed2k_tcp_helper_send(
                context.helper_addr,
                transport.mode,
                "emule_info_answer",
                &reply,
            );
            transport.write_all(&reply).await.with_context(|| {
                format!(
                    "failed to send OP_EMULEINFOANSWER to {}",
                    context.helper_addr
                )
            })?;
        }
        (OP_EMULEPROT, OP_EMULEINFOANSWER) => {}
        (OP_EMULEPROT, OP_SECIDENTSTATE) => {
            let (state, challenge) = decode_secident_state(&packet.payload)?;
            peer_secure_ident.peer_challenge_from = Some(challenge);
            if state != 0 {
                peer_secure_ident.pending_signature = true;
            }
            if state == ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED {
                let public_key = encode_packet(
                    OP_EMULEPROT,
                    OP_PUBLICKEY,
                    &context.secure_ident.public_key_payload()?,
                );
                dump_ed2k_tcp_helper_send(
                    context.helper_addr,
                    transport.mode,
                    "public_key",
                    &public_key,
                );
                transport.write_all(&public_key).await.with_context(|| {
                    format!("failed to send OP_PUBLICKEY to {}", context.helper_addr)
                })?;
            }
            if !try_send_secure_ident_signature(
                transport,
                context.helper_addr,
                context.secure_ident,
                peer_secure_ident,
                "udp_firewall_check",
            )
            .await?
                && state == ED2K_SECURE_IDENT_SIGNATURE_NEEDED
                && !peer_secure_ident.requested_peer_key
            {
                let challenge_for = random_nonzero_u32();
                peer_secure_ident.challenge_for = Some(challenge_for);
                peer_secure_ident.pending_signature = true;
                peer_secure_ident.requested_peer_key = true;
                let request = encode_secident_state(
                    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                    challenge_for,
                );
                dump_ed2k_tcp_helper_send(
                    context.helper_addr,
                    transport.mode,
                    "secure_ident_probe",
                    &request,
                );
                transport.write_all(&request).await.with_context(|| {
                    format!(
                        "failed to send fallback OP_SECIDENTSTATE to {}",
                        context.helper_addr
                    )
                })?;
            }
        }
        (OP_EMULEPROT, OP_PUBLICKEY) => {
            peer_secure_ident.peer_public_key = Some(decode_public_key_payload(&packet.payload)?);
            let _ = try_send_secure_ident_signature(
                transport,
                context.helper_addr,
                context.secure_ident,
                peer_secure_ident,
                "udp_firewall_check",
            )
            .await?;
        }
        (OP_EMULEPROT, OP_SIGNATURE) => {}
        (OP_EMULEPROT, OP_FWCHECKUDPREQ) => {
            // Oracle peers can ask us for their UDP firewall check on any
            // established client TCP session, including the same helper session
            // we opened first. Mirror that bidirectional behavior here.
            if let Some(dht) = context.dht {
                let request = FirewallCheckUdpRequest::decode(&packet.payload)?;
                dump_ed2k_tcp_helper_meta(
                    context.helper_addr,
                    Some(transport.mode),
                    "peer_fwcheck_request",
                    || {
                        format!(
                            "internal_udp_port={} external_udp_port={} sender_udp_key={}",
                            request.internal_udp_port,
                            request.external_udp_port,
                            request.sender_udp_key
                        )
                    },
                );
                reply_with_firewall_udp(dht, context.helper_addr.ip(), request).await?;
                return Ok(true);
            }
            return Ok(false);
        }
        _ => return Ok(false),
    }

    Ok(true)
}

/// Send one `OP_FWCHECKUDPREQ` to a helper peer over eD2k TCP.
pub async fn request_udp_firewall_check(
    dht: Option<DhtNode>,
    bind_ip: Ipv4Addr,
    helper_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    secure_ident: Arc<Ed2kSecureIdent>,
    request: FirewallCheckUdpRequest,
    timeout: Duration,
) -> Result<()> {
    let mut transport = match Ed2kTransport::connect_outgoing(
        bind_ip,
        helper_addr,
        hello_identity.connect_options,
        None,
        None,
        timeout,
    )
    .await
    {
        Ok(transport) => transport,
        Err(error) => {
            dump_ed2k_tcp_helper_meta(helper_addr, None, "connect_error", || error.to_string());
            return Err(error);
        }
    };
    dump_ed2k_tcp_helper_meta(helper_addr, Some(transport.mode), "connect_ok", || {
        format!(
            "client_id={} server_ip={} server_port={} direct_udp_callback={}",
            hello_identity.client_id,
            Ipv4Addr::from(hello_identity.server_ip.to_le_bytes()),
            hello_identity.server_port,
            hello_identity.direct_udp_callback
        )
    });
    let helper_context = FirewallHelperContext {
        helper_addr,
        hello_identity,
        kad_udp_port: hello_identity.udp_port,
        secure_ident: &secure_ident,
        dht: dht.as_ref(),
    };
    let mut peer_secure_ident = Ed2kPeerSecureIdentState::default();
    let hello_completed = drive_firewall_helper_hello_exchange(
        &mut transport,
        helper_context,
        &mut peer_secure_ident,
        timeout,
    )
    .await?;
    if !hello_completed {
        dump_ed2k_tcp_helper_meta(
            helper_addr,
            Some(transport.mode),
            "hello_exchange_incomplete",
            || ("helper never completed HELLO before firewall request").into(),
        );
        anyhow::bail!("helper {helper_addr} did not complete HELLO before OP_FWCHECKUDPREQ");
    }
    let payload = request.encode();
    let packet = encode_packet(OP_EMULEPROT, OP_FWCHECKUDPREQ, &payload);
    dump_ed2k_tcp_helper_send(helper_addr, transport.mode, "fwcheck_request", &packet);
    tokio::time::timeout(timeout, transport.write_all(&packet))
        .await
        .with_context(|| format!("timed out sending OP_FWCHECKUDPREQ to {helper_addr}"))??;

    // Keep the helper TCP session around briefly so peers that finish their
    // hello side channel after receiving the request do not see an immediate
    // disconnect before scheduling the UDP callback.
    let post_fwcheck_deadline = tokio::time::Instant::now()
        + timeout.min(Duration::from_secs(
            FIREWALL_HELPER_POST_REQUEST_KEEPALIVE_SECS,
        ));
    while tokio::time::Instant::now() < post_fwcheck_deadline {
        let remaining =
            post_fwcheck_deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = match tokio::time::timeout(remaining, transport.read_packet()).await {
            Ok(Ok(Some(packet))) => packet,
            Ok(Ok(None)) => {
                dump_ed2k_tcp_helper_meta(
                    helper_addr,
                    Some(transport.mode),
                    "post_fwcheck_closed",
                    || ("connection closed after firewall request").into(),
                );
                break;
            }
            Ok(Err(error)) if is_connection_shutdown_error(&error) => break,
            Ok(Err(error)) => {
                dump_ed2k_tcp_helper_meta(
                    helper_addr,
                    Some(transport.mode),
                    "post_fwcheck_error",
                    || error.to_string(),
                );
                break;
            }
            Err(_) => break,
        };
        if !handle_firewall_helper_packet(
            &mut transport,
            helper_context,
            &mut peer_secure_ident,
            "post_fwcheck",
            packet,
        )
        .await?
        {
            break;
        }
    }
    Ok(())
}

/// Validate a received Kad `OP_CALLBACK` `uCheck` against our own Kad id.
///
/// The oracle (`ListenSocket.cpp:1609-1612`) reads `uCheck`, XORs it with the
/// all-ones `CUInt128`, and only proceeds when the result equals its own Kad id.
/// XOR with all-ones is the bitwise complement, so this is equivalent to
/// `!uCheck[i] == own_kad_id[i]` for every byte.
#[must_use]
pub(crate) fn kad_callback_check_matches(buddy_check: [u8; 16], own_kad_id: [u8; 16]) -> bool {
    buddy_check
        .iter()
        .zip(own_kad_id.iter())
        .all(|(check, own)| !check == *own)
}

/// Whether a received `OP_CALLBACK` is authorized to induce a connect-out,
/// mirroring the oracle `ListenSocket.cpp:1596-1633` guard: (1) `uCheck XOR
/// all-ones == our own Kad id`, and (2) the referenced file is one we share or
/// are downloading. The oracle applies this same guard on any inbound client
/// socket (the buddy relay leg is a normal `CClientReqSocket`), so both the
/// inbound listener session and the outbound buddy link route through here to
/// avoid drifting.
///
/// The oracle also requires `CKademlia::IsRunning()`; a rust `OP_CALLBACK`
/// handler only runs with the Kad `DhtNode` live, so that half is structurally
/// satisfied by the caller and not re-checked here.
pub(crate) async fn kad_callback_is_authorized(
    own_kad_id: [u8; 16],
    transfer_runtime: &Ed2kTransferRuntime,
    callback: &KadCallbackRequest,
) -> bool {
    kad_callback_check_matches(callback.buddy_check, own_kad_id)
        && transfer_runtime.owns_file(&callback.file_hash).await
}

/// Validate a received Kad `OP_CALLBACK` and, when authorized, connect out to
/// the requester so the firewalled requester can reach us (oracle
/// `ListenSocket.cpp:1596-1633` -> `TryToConnectOrDelete`). Returns whether the
/// callback was accepted (a spawned connect-out started); an unauthorized or
/// obviously invalid endpoint is dropped silently, exactly like the oracle.
///
/// Shared by the inbound listener session and the outbound buddy link so the two
/// acceptance surfaces cannot diverge.
pub(crate) async fn complete_authorized_kad_callback(
    bind_ip: Ipv4Addr,
    own_kad_id: [u8; 16],
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    hello_identity: Ed2kHelloIdentity,
    callback: &KadCallbackRequest,
    source: &str,
) -> bool {
    if !kad_callback_is_authorized(own_kad_id, transfer_runtime, callback).await {
        debug!(
            "dropping {source} OP_CALLBACK file_hash={} requester={}:{}: failed uCheck / \
             unshared-file guard",
            callback.file_hash, callback.peer_ip, callback.peer_tcp_port
        );
        return false;
    }
    // Skip obviously invalid endpoints (oracle constructs a client only for a
    // real (ip, tcp) pair).
    if callback.peer_tcp_port == 0 || callback.peer_ip.is_unspecified() {
        return false;
    }
    let requester = SocketAddr::new(IpAddr::V4(callback.peer_ip), callback.peer_tcp_port);
    tokio::spawn(async move {
        match connect_callback_peer(
            bind_ip,
            requester,
            hello_identity,
            None,
            None,
            super::ED2K_CONNECTION_IDLE_TIMEOUT,
        )
        .await
        {
            Ok(mode) => info!(
                "Kad firewalled-callback connect-out to {requester} completed transport={}",
                mode.as_str()
            ),
            Err(error) => {
                debug!("Kad firewalled-callback connect-out to {requester} failed: {error:#}")
            }
        }
    });
    true
}

/// Mirror the oracle's active peer callback path by opening an outgoing eD2k
/// client connection and immediately sending `OP_HELLO`.
pub async fn connect_callback_peer(
    bind_ip: Ipv4Addr,
    peer_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    peer_user_hash: Option<[u8; 16]>,
    peer_connect_options: Option<u8>,
    timeout: Duration,
) -> Result<Ed2kPeerConnectMode> {
    let mut transport = Ed2kTransport::connect_outgoing(
        bind_ip,
        peer_addr,
        hello_identity.connect_options,
        peer_user_hash,
        peer_connect_options,
        timeout,
    )
    .await?;
    let mode = match transport.mode {
        Ed2kTransportMode::Plaintext => Ed2kPeerConnectMode::Plaintext,
        Ed2kTransportMode::Obfuscated => Ed2kPeerConnectMode::Obfuscated,
    };

    let hello_packet = encode_hello_request(hello_identity);
    tokio::time::timeout(timeout, transport.write_all(&hello_packet))
        .await
        .with_context(|| format!("timed out sending OP_HELLO to callback peer {peer_addr}"))??;

    loop {
        let packet = match tokio::time::timeout(
            super::ED2K_CONNECTION_IDLE_TIMEOUT,
            transport.read_packet(),
        )
        .await
        {
            Ok(Ok(packet)) => packet,
            Ok(Err(error)) if is_connection_shutdown_error(&error) => return Ok(mode),
            Ok(Err(error)) => {
                return Err(error)
                    .with_context(|| format!("failed to read eD2k packet from {peer_addr}"));
            }
            Err(_) => return Ok(mode),
        };
        let Some(packet) = packet else {
            return Ok(mode);
        };
        match (packet.protocol, packet.opcode) {
            (OP_EDONKEYPROT, OP_HELLO) => {
                for reply in build_hello_responses(&packet.payload, hello_identity)? {
                    transport
                        .write_all(&reply)
                        .await
                        .with_context(|| format!("failed to reply to OP_HELLO from {peer_addr}"))?;
                }
            }
            (OP_EDONKEYPROT, OP_HELLOANSWER)
            | (OP_EMULEPROT, OP_EMULEINFOANSWER)
            | (OP_EMULEPROT, OP_EMULEINFO) => {
                if packet.opcode == OP_EMULEINFO {
                    let reply = encode_emule_info_answer(hello_identity.udp_port);
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send OP_EMULEINFOANSWER to {peer_addr}")
                    })?;
                }
                return Ok(mode);
            }
            _ => return Ok(mode),
        }
    }
}

/// Mirror the modern Kad TCP firewall-check result path. Stock eMule opens an
/// eD2k client connection, sends its normal `OP_HELLO`, then reports TCP reachability
/// with `OP_KAD_FWTCPCHECK_ACK` on that same connection.
pub async fn send_kad_firewall_tcp_ack(
    bind_ip: Ipv4Addr,
    peer_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    peer_user_hash: [u8; 16],
    peer_connect_options: u8,
    timeout: Duration,
) -> Result<Ed2kPeerConnectMode> {
    let mut transport = Ed2kTransport::connect_outgoing(
        bind_ip,
        peer_addr,
        hello_identity.connect_options,
        Some(peer_user_hash),
        Some(peer_connect_options),
        timeout,
    )
    .await?;
    let mode = match transport.mode {
        Ed2kTransportMode::Plaintext => Ed2kPeerConnectMode::Plaintext,
        Ed2kTransportMode::Obfuscated => Ed2kPeerConnectMode::Obfuscated,
    };

    let hello_packet = encode_hello_request(hello_identity);
    tokio::time::timeout(timeout, transport.write_all(&hello_packet))
        .await
        .with_context(|| {
            format!("timed out sending OP_HELLO for Kad TCP firewall ACK to {peer_addr}")
        })??;

    let ack = encode_packet(OP_EMULEPROT, OP_KAD_FWTCPCHECK_ACK, &[]);
    tokio::time::timeout(timeout, transport.write_all(&ack))
        .await
        .with_context(|| {
            format!("timed out sending OP_KAD_FWTCPCHECK_ACK to Kad firewall peer {peer_addr}")
        })??;

    Ok(mode)
}

/// Return the eMule TCP/Kad connect-option bits mirrored from the oracle
/// `GetMyConnectOptions(true, false)` path, minus the direct-callback flag.
#[must_use]
pub const fn emule_connect_options(obfuscation_enabled: bool) -> u8 {
    if obfuscation_enabled {
        EMULE_CRYPT_SUPPORTS | EMULE_CRYPT_REQUESTS
    } else {
        0
    }
}

pub(crate) fn is_connection_shutdown_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some_and(|io_error| {
            matches!(
                io_error.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use emulebb_kad_proto::Ed2kHash;

    use super::super::codec::KadCallbackRequest;
    use super::{kad_callback_check_matches, kad_callback_is_authorized};
    use crate::ed2k_transfer::{Ed2kTransferRuntime, new_transfer_job};

    fn callback(buddy_check: [u8; 16], file_hash: Ed2kHash) -> KadCallbackRequest {
        KadCallbackRequest {
            buddy_check,
            file_hash,
            peer_ip: Ipv4Addr::new(203, 0, 113, 7),
            peer_tcp_port: 4662,
            trailing_len: 0,
        }
    }

    #[test]
    fn check_matches_only_the_complement_of_our_kad_id() {
        let own = [0xABu8; 16];
        // The requester places `own XOR allones` (= complement) into uCheck.
        assert!(kad_callback_check_matches(own.map(|b| !b), own));
        // Echoing our id verbatim (not the complement) must be rejected.
        assert!(!kad_callback_check_matches(own, own));
        assert!(!kad_callback_check_matches([0u8; 16], own));
        // A single flipped byte breaks the match.
        let mut almost = own.map(|b| !b);
        almost[7] ^= 0x01;
        assert!(!kad_callback_check_matches(almost, own));
    }

    /// LOWID-G3: an unguarded OP_CALLBACK (wrong uCheck, or a file we neither
    /// share nor download) must NOT be authorized, so the listener session and
    /// buddy link never connect out for it.
    #[tokio::test]
    async fn unauthorized_callback_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = Ed2kTransferRuntime::load_or_create(tmp.path()).unwrap();
        let own = [0xABu8; 16];

        // Wrong uCheck (echoes our id verbatim) is rejected even for a file we own.
        let owned = Ed2kHash::from_bytes([0x11; 16]);
        runtime
            .ensure_job(&new_transfer_job(owned, "owned".into(), 1))
            .await
            .unwrap();
        assert!(!kad_callback_is_authorized(own, &runtime, &callback(own, owned)).await);

        // Correct uCheck but an unshared/undownloaded file is rejected.
        let unknown = Ed2kHash::from_bytes([0x22; 16]);
        assert!(
            !kad_callback_is_authorized(own, &runtime, &callback(own.map(|b| !b), unknown)).await
        );
    }

    /// LOWID-G3: a valid OP_CALLBACK (uCheck == complement of our Kad id AND a
    /// file we own) is authorized, so the connect-out proceeds.
    #[tokio::test]
    async fn authorized_callback_is_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = Ed2kTransferRuntime::load_or_create(tmp.path()).unwrap();
        let own = [0xABu8; 16];
        let owned = Ed2kHash::from_bytes([0x33; 16]);
        runtime
            .ensure_job(&new_transfer_job(owned, "owned".into(), 1))
            .await
            .unwrap();
        assert!(kad_callback_is_authorized(own, &runtime, &callback(own.map(|b| !b), owned)).await);
    }
}
