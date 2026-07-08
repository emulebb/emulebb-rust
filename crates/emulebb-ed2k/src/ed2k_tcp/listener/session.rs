use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result};
use tokio::{
    net::TcpStream,
    sync::{Mutex, RwLock},
};
use tracing::{debug, info};

use emulebb_kad_dht::DhtNode;
use emulebb_kad_proto::{Ed2kHash, FirewallUdp, KadPacket, NodeId};
use tokio::sync::mpsc;

use crate::{
    buddy_socket::BuddySocketRegistry,
    ed2k_server::Ed2kServerState,
    ed2k_transfer::{Ed2kTransferRuntime, Ed2kUploadPeerIdentity, Ed2kUploadPendingPromotion},
    kad_firewall::KadFirewallState,
};

use super::super::codec::{
    decode_aich_recovery_answer_payload, decode_aich_recovery_request_payload,
    decode_exact_file_hash_payload, decode_kad_callback_payload, decode_optional_file_hash_payload,
    encode_aich_recovery_answer, encode_aich_recovery_failure_answer, encode_buddy_pong,
    encode_port_test_answer, encode_public_ip_answer,
};
use super::super::download::{
    DownloadSessionOptions, Ed2kPeerDownloadOutcome, drive_download_session,
};
use super::super::dump::{
    dump_ed2k_tcp_listener_meta, dump_ed2k_tcp_listener_recv, dump_ed2k_tcp_listener_send,
};
use super::super::hello::{
    DecodedHelloProfile, build_hello_responses, decode_emule_info_profile, decode_hello_profile,
    encode_emule_info_answer, encode_hello_request,
};
use super::super::identity::{Ed2kPeerSecureIdentState, begin_secure_ident_probe};
use super::super::{
    ED2K_CONNECTION_IDLE_TIMEOUT, Ed2kHelloIdentity, Ed2kSecureIdent, Ed2kTransport,
    FirewallCheckUdpRequest, OP_AICHANSWER, OP_AICHFILEHASHREQ, OP_AICHREQUEST,
    OP_ASKSHAREDDENIEDANS, OP_ASKSHAREDDIRS, OP_ASKSHAREDDIRSANS, OP_ASKSHAREDFILES,
    OP_ASKSHAREDFILESANSWER, OP_ASKSHAREDFILESDIR, OP_ASKSHAREDFILESDIRANS, OP_BUDDYPING,
    OP_BUDDYPONG, OP_CALLBACK, OP_CANCELTRANSFER, OP_CHANGE_CLIENT_ID, OP_CHANGE_SLOT,
    OP_CHATCAPTCHAREQ, OP_CHATCAPTCHARES, OP_EDONKEYPROT, OP_EMULEINFO, OP_EMULEINFOANSWER,
    OP_EMULEPROT, OP_END_OF_DOWNLOAD, OP_FILEDESC, OP_FWCHECKUDPREQ, OP_HASHSETREQUEST,
    OP_HASHSETREQUEST2, OP_HELLO, OP_HELLOANSWER, OP_KAD_FWTCPCHECK_ACK, OP_MESSAGE,
    OP_MULTIPACKET, OP_MULTIPACKET_EXT, OP_MULTIPACKET_EXT2, OP_OUTOFPARTREQS, OP_PORTTEST,
    OP_PREVIEWANSWER, OP_PUBLICIP_ANSWER, OP_PUBLICIP_REQ, OP_PUBLICKEY, OP_QUEUERANK,
    OP_QUEUERANKING, OP_REASKCALLBACKTCP, OP_REQUESTFILENAME, OP_REQUESTPARTS, OP_REQUESTPARTS_I64,
    OP_REQUESTPREVIEW, OP_REQUESTSOURCES, OP_REQUESTSOURCES2, OP_SECIDENTSTATE, OP_SETREQFILEID,
    OP_SIGNATURE, OP_STARTUPLOADREQ, apply_server_state, handle_aich_recovery_answer,
};
use super::super::firewall_helper::complete_authorized_kad_callback;

mod browse;
mod notify;
mod secure_ident;
mod shared_file;
mod upload_payload;
mod upload_queue;

use shared_file::{
    handle_aich_file_hash_request, handle_hashset_request, handle_hashset_request2,
    handle_multipacket_ext2_request, handle_multipacket_request, handle_request_filename,
    handle_set_req_file_id, handle_source_request,
};
use upload_payload::{UploadPayloadOutcome, UploadPayloadRequest, serve_upload_payload};
use upload_queue::{ListenerQueuePoll, ListenerUploadQueue};

/// Transport source for one eD2k peer session: an accepted inbound socket, or
/// an already-established OUTBOUND connection dialed to hand an upload slot to
/// a disconnected waiter (oracle `AddUpNextClient` US_CONNECTING connect-out,
/// UploadQueue.cpp:327-361).
pub(in crate::ed2k_tcp) enum Ed2kSessionSource {
    Inbound(TcpStream),
    PromotedUpload {
        // Boxed: the established transport dwarfs the plain inbound socket
        // (clippy::large_enum_variant).
        transport: Box<Ed2kTransport>,
        grant: Box<Ed2kUploadPendingPromotion>,
    },
}

pub(in crate::ed2k_tcp) struct Ed2kConnectionContext<'a> {
    pub(in crate::ed2k_tcp) dht: &'a DhtNode,
    pub(in crate::ed2k_tcp) server_state: &'a Arc<RwLock<Ed2kServerState>>,
    pub(in crate::ed2k_tcp) kad_firewall: &'a Arc<Mutex<KadFirewallState>>,
    pub(in crate::ed2k_tcp) secure_ident: &'a Arc<Ed2kSecureIdent>,
    pub(in crate::ed2k_tcp) transfer_runtime: &'a Arc<Ed2kTransferRuntime>,
    pub(in crate::ed2k_tcp) hello_identity: Ed2kHelloIdentity,
    /// External reachability (advertised external TCP/UDP ports), read at send time.
    pub(in crate::ed2k_tcp) reachability: &'a crate::reachability::ExternalReachability,
    /// Persistent Kad buddy-socket registry: an inbound buddy holds this session
    /// open so `handle_kad_callback_req` can relay `OP_CALLBACK` down it.
    pub(in crate::ed2k_tcp) buddy_registry: &'a BuddySocketRegistry,
}

#[allow(clippy::cognitive_complexity)]
pub(in crate::ed2k_tcp) async fn handle_connection(
    source: Ed2kSessionSource,
    peer_addr: SocketAddr,
    context: Ed2kConnectionContext<'_>,
) -> Result<()> {
    let Ed2kConnectionContext {
        dht,
        server_state,
        kad_firewall,
        secure_ident,
        transfer_runtime,
        hello_identity,
        reachability,
        buddy_registry,
    } = context;
    let kad_udp_port = dht
        .bind_addr()
        .context("failed to resolve Kad bind address for eD2k hello response")?
        .port();
    let response_identity = Ed2kHelloIdentity {
        // Advertise the externally-reachable ports (UPnP-mapped when known), read
        // dynamically here so a mapping learned after startup is reflected: peers
        // locate us for UDP source-reask by (ip, udp_port) and reach us for
        // incoming connections on the advertised tcp_port.
        udp_port: reachability.advertised_udp_port(kad_udp_port),
        tcp_port: reachability.advertised_tcp_port(hello_identity.tcp_port),
        ..hello_identity
    };
    let response_identity =
        enrich_hello_identity(response_identity, server_state, kad_firewall).await;
    let (mut transport, promoted_grant) = match source {
        Ed2kSessionSource::Inbound(stream) => {
            let local_addr = stream.local_addr().with_context(|| {
                format!("failed to resolve local eD2k listener address for {peer_addr}")
            })?;
            dump_ed2k_tcp_listener_meta(
                peer_addr,
                None,
                "tcp_accept",
                format!("local_addr={local_addr}"),
            );
            let transport = match tokio::time::timeout(
                ED2K_CONNECTION_IDLE_TIMEOUT,
                Ed2kTransport::accept(stream, hello_identity.user_hash),
            )
            .await
            {
                Ok(Ok(transport)) => transport,
                Ok(Err(error)) => {
                    dump_ed2k_tcp_listener_meta(
                        peer_addr,
                        None,
                        "accept_failed",
                        format!("local_addr={local_addr} error={error:#}"),
                    );
                    return Err(error).with_context(|| {
                        format!("failed to accept inbound eD2k peer transport from {peer_addr}")
                    });
                }
                Err(_) => {
                    dump_ed2k_tcp_listener_meta(
                        peer_addr,
                        None,
                        "accept_timeout",
                        format!(
                            "local_addr={local_addr} idle_timeout_secs={}",
                            ED2K_CONNECTION_IDLE_TIMEOUT.as_secs()
                        ),
                    );
                    anyhow::bail!("timed out waiting for initial eD2k peer bytes");
                }
            };
            (transport, None)
        }
        // A slot grant for a disconnected waiter arrives on a connection WE
        // dialed (master AddUpNextClient US_CONNECTING connect-out); the
        // transport handshake already happened in the promote driver.
        Ed2kSessionSource::PromotedUpload { transport, grant } => {
            dump_ed2k_tcp_listener_meta(
                peer_addr,
                Some(transport.mode),
                "promote_connect",
                format!("file_hash={}", grant.file_hash),
            );
            (*transport, Some(*grant))
        }
    };
    let local_addr = transport
        .stream
        .local_addr()
        .with_context(|| format!("failed to resolve local eD2k session address for {peer_addr}"))?;
    transport
        .stream
        .set_nodelay(true)
        .with_context(|| format!("failed to enable TCP_NODELAY for peer {peer_addr}"))?;
    debug!(
        "eD2k TCP peer session with {peer_addr} transport={}",
        transport.mode.as_str()
    );
    if promoted_grant.is_none() {
        dump_ed2k_tcp_listener_meta(
            peer_addr,
            Some(transport.mode),
            "accept",
            format!("udp_port={kad_udp_port}"),
        );
    }
    let mut peer_secure_ident = Ed2kPeerSecureIdentState::default();
    let mut requested_file_hash: Option<Ed2kHash> = None;
    let mut peer_supports_aich = false;
    let mut peer_supports_file_identifiers = false;
    // Peer's advertised comment-acceptance version (oracle m_byAcceptCommentVer);
    // gates whether we propagate our user-set comment/rating via OP_FILEDESC.
    let mut peer_accept_comment_version: u8 = 0;
    let mut peer_upload_identity = upload_peer_identity_from_socket(peer_addr);
    let mut upload_queue = ListenerUploadQueue::new();
    // Inbound Kad buddy hold: set once this connecting peer is recognized as the
    // firewalled client we agreed to serve as a buddy (oracle KS_INCOMING_BUDDY
    // -> KS_CONNECTED_BUDDY). While held, we answer OP_BUDDYPING with OP_BUDDYPONG
    // and forward relayed OP_CALLBACK frames pushed by handle_kad_callback_req.
    let mut buddy_hold: Option<InboundBuddyHold> = None;
    // Phase B identity-spoofing guard: the first advertised user hash this
    // connection binds; a later hello presenting a DIFFERENT hash is credit-farming
    // impersonation (rust attributes credit by user hash) and is banned + dropped.
    let mut bound_user_hash: Option<[u8; 16]> = None;
    // Phase C file-request-flood guard: count requests for files we do not serve;
    // a flood of these is a share-probe and the peer is banned (MFC file_request_flood).
    let mut failed_file_req_count: u32 = 0;

    // A promoted-upload outbound session announces itself and pushes the slot
    // grant before entering the dispatch loop: the oracle sends OP_HELLO and
    // then OP_ACCEPTUPLOADREQ on the fresh connection it opened for the
    // promoted waiter (ConnectionEstablished, BaseClient.cpp:1634-1641).
    if let Some(grant) = promoted_grant {
        peer_upload_identity = grant.peer.clone();
        peer_upload_identity.should_crypt = transport.mode.is_obfuscated();
        bound_user_hash = grant.peer.user_hash;
        let file_hash = Ed2kHash::from_str(&grant.file_hash)
            .with_context(|| format!("invalid promoted upload file hash {}", grant.file_hash))?;
        requested_file_hash = Some(file_hash);
        let hello_packet = encode_hello_request(response_identity);
        dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "hello_request", &hello_packet);
        transport.write_all(&hello_packet).await.with_context(|| {
            format!("failed to send OP_HELLO to promoted upload peer {peer_addr}")
        })?;
        let attached = upload_queue
            .attach_promoted_grant(
                transfer_runtime,
                &grant.peer,
                grant.handle,
                file_hash,
                &mut transport,
                peer_addr,
            )
            .await?;
        if !attached {
            // The grant went stale while connecting (aged out or re-owned by an
            // inbound reconnect): nothing to serve on this connection.
            return Ok(());
        }
    }

    // Run the session loop inside a fallible async scope so that EVERY exit
    // path -- a clean `break`, a propagated `?` I/O error, or any other early
    // return from the loop body -- lands in `result` and falls through to the
    // unconditional `upload_queue.release(...)` below. The master frees an
    // ACTIVE slot on teardown (`CUpDownClient::Disconnected` removes
    // US_UPLOADING/US_CONNECTING, BaseClient.cpp:1172-1175) while a waiting
    // queue entry survives the disconnect (BaseClient.cpp:1229); the runtime
    // release applies exactly that split. Without this wrapper an in-loop `?`
    // would skip the release and leave the slot pinned until the idle reaper
    // reclaimed it.
    // Last time the peer actually sent us a packet: feeds the waiting-connection
    // idle close (oracle socket timeout) inside poll_on_timeout.
    let mut last_packet_at = tokio::time::Instant::now();
    let result: Result<()> = async {
        loop {
        let read_timeout = upload_queue.read_timeout();
        // While serving as an inbound buddy, also drain relay frames (OP_CALLBACK)
        // that handle_kad_callback_req pushes down this held socket.
        let packet = if let Some(hold) = buddy_hold.as_mut() {
            tokio::select! {
                biased;
                relay = hold.relay_rx.recv() => {
                    match relay {
                        Some(frame) => {
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "buddy_callback_relay",
                                &frame,
                            );
                            transport.write_all(&frame).await.with_context(|| {
                                format!("failed to relay OP_CALLBACK to buddy {peer_addr}")
                            })?;
                            continue;
                        }
                        // Registry dropped the sender (buddy relation cleared).
                        None => {
                            buddy_hold = None;
                            continue;
                        }
                    }
                }
                read = tokio::time::timeout(read_timeout, transport.read_packet()) => {
                    match read {
                        Ok(packet) => packet
                            .with_context(|| format!("failed to read eD2k packet from {peer_addr}"))?,
                        Err(_) => match upload_queue
                            .poll_on_timeout(
                                transfer_runtime,
                                &mut transport,
                                peer_addr,
                                last_packet_at.elapsed(),
                            )
                            .await?
                        {
                            ListenerQueuePoll::Continue => continue,
                            ListenerQueuePoll::Close => break Ok(()),
                        },
                    }
                }
            }
        } else {
            match tokio::time::timeout(read_timeout, transport.read_packet()).await {
                Ok(packet) => {
                    packet.with_context(|| format!("failed to read eD2k packet from {peer_addr}"))?
                }
                Err(_) => match upload_queue
                    .poll_on_timeout(
                        transfer_runtime,
                        &mut transport,
                        peer_addr,
                        last_packet_at.elapsed(),
                    )
                    .await?
                {
                    ListenerQueuePoll::Continue => continue,
                    ListenerQueuePoll::Close => break Ok(()),
                },
            }
        };
        let Some(packet) = packet else {
            break Ok(());
        };
        last_packet_at = tokio::time::Instant::now();
        dump_ed2k_tcp_listener_recv(peer_addr, transport.mode, "session", &packet);

        match (packet.protocol, packet.opcode) {
            (OP_EDONKEYPROT, OP_HELLO) => {
                let hello_profile = decode_hello_profile(&packet.payload)?;
                // Phase B: a re-hello presenting a different user hash than the one
                // already bound is credit-farming impersonation -> ban + drop
                // (MFC identity_userhash_changed -> Ban()).
                if let Some(prior_hash) = bound_user_hash
                    && prior_hash != hello_profile.identity.user_hash
                {
                    let ban_ip = match peer_addr {
                        SocketAddr::V4(v4) => Some(*v4.ip()),
                        SocketAddr::V6(_) => None,
                    };
                    transfer_runtime
                        .ban_client(ban_ip, Some(hello_profile.identity.user_hash));
                    crate::ed2k_transfer::diag_bad_peer::identity_userhash_changed(
                        &peer_addr.to_string(),
                        Some(hello_profile.identity.user_hash),
                    );
                    debug!(
                        "banning {peer_addr}: user hash changed mid-connection (impersonation)"
                    );
                    break Ok(());
                }
                bound_user_hash = Some(hello_profile.identity.user_hash);
                peer_supports_aich = hello_profile.supports_aich;
                peer_supports_file_identifiers = hello_profile.supports_file_identifiers;
                // The modern hello MISCOPTIONS1 carries m_byAcceptCommentVer
                // (bits 4-7). Capture it so OP_REQUESTFILENAME can answer with
                // OP_FILEDESC when we have a comment/rating to share.
                peer_accept_comment_version =
                    hello_profile.misc_options1.accept_comment_version;
                peer_upload_identity =
                    upload_peer_identity_from_hello(peer_addr, &hello_profile);
                // Obfuscate UDP reasks to peers whose TCP session is obfuscated.
                peer_upload_identity.should_crypt = transport.mode.is_obfuscated();
                // Feed the upload-score `banned` flag from the ban store now that
                // we know the peer's user hash (eMule `CUpDownClient::IsBanned`
                // -> upload score 0). Either the IP or the hash being banned
                // zeroes the score, exactly like `IsBannedClient(pClient)`.
                let peer_ban_ip = match peer_addr {
                    SocketAddr::V4(v4) => Some(*v4.ip()),
                    SocketAddr::V6(_) => None,
                };
                peer_upload_identity.banned = transfer_runtime
                    .is_client_banned(peer_ban_ip, Some(&hello_profile.identity.user_hash));
                debug!(
                    "received eD2k OP_HELLO from {peer_addr} transport={} mule_hello={}",
                    transport.mode.as_str(),
                    hello_profile.is_mule_hello,
                );
                // If this connecting peer is the firewalled client we agreed to be
                // a buddy for, hold the session open and register a relay writer so
                // handle_kad_callback_req can push OP_CALLBACK down it (oracle
                // KS_INCOMING_BUDDY connecting -> KS_CONNECTED_BUDDY).
                if buddy_hold.is_none()
                    && let IpAddr::V4(peer_ip) = peer_addr.ip()
                    && let Some(buddy_id) =
                        buddy_registry.match_connecting_peer(peer_ip, hello_profile.identity.user_hash)
                {
                    let (relay_tx, relay_rx) = mpsc::unbounded_channel();
                    if buddy_registry.attach_inbound(buddy_id, relay_tx) {
                        info!(
                            "holding inbound Kad buddy session for {peer_addr} \
                                     (buddy_id={buddy_id})"
                        );
                        buddy_hold = Some(InboundBuddyHold {
                            buddy_id,
                            relay_rx,
                            // LOWID-G9b: the oracle arms the ping/pong marker when
                            // the buddy client object is created (ctor), so the
                            // first pong is gated ~13 min out, not answered
                            // immediately. Seed the watermark at hold creation.
                            last_buddy_pingpong_at: Some(std::time::Instant::now()),
                        });
                    }
                }
                for reply in build_hello_responses(&packet.payload, response_identity)? {
                    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "hello_reply", &reply);
                    transport
                        .write_all(&reply)
                        .await
                        .with_context(|| format!("failed to reply to OP_HELLO from {peer_addr}"))?;
                }
                // SUI level + our HighID IP for V1/V2 outbound signature selection.
                peer_secure_ident.peer_sec_ident = hello_profile.misc_options1.secure_ident;
                peer_secure_ident.our_external_ip = reachability.get();
                if hello_profile.supports_secure_ident && !peer_secure_ident.requested_peer_key {
                    let request = begin_secure_ident_probe(&mut peer_secure_ident);
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "secure_ident_probe",
                        &request,
                    );
                    transport.write_all(&request).await.with_context(|| {
                        format!("failed to send OP_SECIDENTSTATE to {peer_addr}")
                    })?;
                }
                if let Some(callback_intent) = transfer_runtime
                    .claim_callback_intent(hello_profile.identity.client_id)
                    .await
                {
                    let file_hash =
                        Ed2kHash::from_str(&callback_intent.file_hash).with_context(|| {
                            format!(
                                "invalid callback file hash {} for client_id={}",
                                callback_intent.file_hash, callback_intent.client_id
                            )
                        })?;
                    info!(
                        "claimed inbound ED2K callback download file_hash={} client_id={} peer={peer_addr}",
                        callback_intent.file_hash, callback_intent.client_id
                    );
                    match drive_download_session(DownloadSessionOptions {
                        transport: &mut transport,
                        peer_addr,
                        hello_identity: response_identity,
                        secure_ident: secure_ident.as_ref(),
                        transfer_runtime,
                        file_hash,
                        file_hash_hex: &callback_intent.file_hash,
                        timeout: ED2K_CONNECTION_IDLE_TIMEOUT,
                        send_initial_requests: true,
                        source_exchange_allowed: true,
                        initial_hello_complete: true,
                        initial_secure_ident_started: true,
                        peer_user_hash: Some(hello_profile.identity.user_hash),
                        peer_connect_options: Some(hello_profile.connect_options),
                        // Inbound callback downloads stay on TCP; UDP-reask detach
                        // is driven only from the outbound download driver.
                        reask_register: None,
                    })
                    .await?
                    {
                        Ed2kPeerDownloadOutcome::Completed => break Ok(()),
                        Ed2kPeerDownloadOutcome::AcceptedButIncomplete => break Ok(()),
                        Ed2kPeerDownloadOutcome::QueuedDetachedForUdpReask => break Ok(()),
                        // Inbound callback downloads have no cross-transfer driver to
                        // run the A4AF-lite swap; treat NNP like accepted-incomplete.
                        Ed2kPeerDownloadOutcome::NoNeededParts => break Ok(()),
                        // Same for FNF: the session already ends here; dead-listing
                        // is driven from the outbound download driver.
                        Ed2kPeerDownloadOutcome::FileNotFound => break Ok(()),
                    }
                }
            }
            (OP_EDONKEYPROT, OP_HELLOANSWER) => {
                debug!(
                    "received eD2k OP_HELLOANSWER from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
            }
            (OP_EMULEPROT, OP_MULTIPACKET) | (OP_EMULEPROT, OP_MULTIPACKET_EXT) => {
                requested_file_hash = handle_multipacket_request(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    packet.opcode,
                    &packet.payload,
                    peer_supports_aich,
                    peer_supports_file_identifiers,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_MULTIPACKET_EXT2) => {
                requested_file_hash = handle_multipacket_ext2_request(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EDONKEYPROT, OP_REQUESTFILENAME) => {
                requested_file_hash = handle_request_filename(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    &packet.payload,
                    peer_accept_comment_version,
                )
                .await?;
            }
            (OP_EDONKEYPROT, OP_SETREQFILEID) => {
                requested_file_hash = handle_set_req_file_id(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EDONKEYPROT, OP_STARTUPLOADREQ) => {
                let requested =
                    decode_exact_file_hash_payload(&packet.payload, "OP_STARTUPLOADREQ")?;
                requested_file_hash = Some(requested);
                if transfer_runtime.local_servable_entry(&requested).await?.is_some() {
                    let mut peer_identity = peer_upload_identity.clone();
                    peer_identity.firewall_context =
                        upload_firewall_context(server_state, kad_firewall).await;
                    // `None` where the oracle is silent (rejected admission /
                    // waiting rank toward a plain-eDonkey peer).
                    if let Some(reply) = upload_queue
                        .start_upload_reply(transfer_runtime, peer_identity, &requested)
                        .await
                    {
                        dump_ed2k_tcp_listener_send(
                            peer_addr,
                            transport.mode,
                            "start_upload",
                            &reply,
                        );
                        transport.write_all(&reply).await.with_context(|| {
                            format!("failed to send OP_STARTUPLOADREQ response to {peer_addr}")
                        })?;
                    }
                } else {
                    // An OP_STARTUPLOADREQ for a file we do not serve gets NO
                    // reply: the oracle only does CheckFailedFileIdReqs
                    // bookkeeping (ListenSocket.cpp:706-707). Unlike the
                    // file-request opcodes, no OP_FILEREQANSNOFIL is sent. The
                    // failed request still counts toward the share-probe flood
                    // ban, and the dump keeps the event visible locally.
                    failed_file_req_count += 1;
                    dump_ed2k_tcp_listener_meta(
                        peer_addr,
                        Some(transport.mode),
                        "start_upload_unknown_file",
                        format!("file_hash={requested} failed_file_req_count={failed_file_req_count}"),
                    );
                }
                if failed_file_req_count >= crate::ed2k_transfer::diag_bad_peer::FAILED_FILE_REQ_FLOOD_THRESHOLD
                {
                    let ban_ip = match peer_addr {
                        SocketAddr::V4(v4) => Some(*v4.ip()),
                        SocketAddr::V6(_) => None,
                    };
                    transfer_runtime.ban_client(ban_ip, peer_upload_identity.user_hash);
                    crate::ed2k_transfer::diag_bad_peer::file_request_flood(
                        &peer_addr.to_string(),
                        peer_upload_identity.user_hash,
                        failed_file_req_count,
                    );
                    debug!("banning {peer_addr}: failed file-id request flood");
                    break Ok(());
                }
            }
            (OP_EDONKEYPROT, OP_CANCELTRANSFER) => {
                upload_queue.note_close_reason("peer_cancelled");
                upload_queue.release(transfer_runtime).await;
                break Ok(());
            }
            (OP_EDONKEYPROT, OP_END_OF_DOWNLOAD) => {
                let ended_hash = decode_optional_file_hash_payload(&packet.payload);
                dump_ed2k_tcp_listener_meta(
                    peer_addr,
                    Some(transport.mode),
                    "end_of_download",
                    format!(
                        "file_hash={} payload_len={}",
                        ended_hash.map_or_else(|| "none".to_string(), |hash| hash.to_string()),
                        packet.payload.len()
                    ),
                );
                // Release the granted slot ONLY when the END is for the file the
                // slot is keyed on, so END_OF_DOWNLOAD(B) can't release a slot
                // held for A (requested_file_hash is mutable and overwritten by
                // every file-touching handler). Still close the connection when
                // the peer signals end for the file it is currently working on.
                let ends_slot = upload_queue.slot_file_hash() == ended_hash;
                if ends_slot {
                    upload_queue.note_close_reason("end_of_download");
                    upload_queue.release(transfer_runtime).await;
                }
                if ends_slot || requested_file_hash == ended_hash {
                    break Ok(());
                }
            }
            (OP_EDONKEYPROT, OP_OUTOFPARTREQS) => {
                notify::handle_out_of_part_requests(&transport, peer_addr);
            }
            (OP_EDONKEYPROT, OP_CHANGE_CLIENT_ID) => {
                notify::handle_change_client_id(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EDONKEYPROT, OP_CHANGE_SLOT) => {
                notify::handle_change_slot(&transport, peer_addr, &packet.payload);
            }
            (OP_EDONKEYPROT, OP_MESSAGE) => {
                notify::handle_client_message(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EDONKEYPROT, OP_ASKSHAREDFILES) => {
                browse::handle_ask_shared_files(&mut transport, peer_addr, packet.payload.len())
                    .await?;
            }
            (OP_EDONKEYPROT, OP_ASKSHAREDDIRS) => {
                browse::handle_ask_shared_dirs(&mut transport, peer_addr, packet.payload.len())
                    .await?;
            }
            (OP_EDONKEYPROT, OP_ASKSHAREDFILESDIR) => {
                browse::handle_ask_shared_files_dir(&mut transport, peer_addr, &packet.payload)
                    .await?;
            }
            (OP_EDONKEYPROT, OP_ASKSHAREDFILESANSWER) => {
                browse::handle_ask_shared_files_answer(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EDONKEYPROT, OP_ASKSHAREDDIRSANS) => {
                browse::handle_ask_shared_dirs_answer(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EDONKEYPROT, OP_ASKSHAREDFILESDIRANS) => {
                browse::handle_ask_shared_files_dir_answer(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EDONKEYPROT, OP_ASKSHAREDDENIEDANS) => {
                browse::handle_ask_shared_denied_answer(&transport, peer_addr, packet.payload.len());
            }
            (OP_EDONKEYPROT, OP_QUEUERANK) => {
                notify::handle_edonkey_queue_rank(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EMULEPROT, OP_QUEUERANKING) => {
                notify::handle_emule_queue_ranking(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EDONKEYPROT, OP_HASHSETREQUEST) => {
                requested_file_hash = handle_hashset_request(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_HASHSETREQUEST2) => {
                requested_file_hash = handle_hashset_request2(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_REQUESTSOURCES) | (OP_EMULEPROT, OP_REQUESTSOURCES2) => {
                requested_file_hash = handle_source_request(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    packet.opcode,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_AICHFILEHASHREQ) => {
                requested_file_hash = handle_aich_file_hash_request(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    &packet.payload,
                    peer_supports_aich,
                )
                .await?;
            }
            (OP_EDONKEYPROT, OP_REQUESTPARTS) | (OP_EMULEPROT, OP_REQUESTPARTS_I64) => {
                let mut peer_identity = peer_upload_identity.clone();
                peer_identity.firewall_context =
                    upload_firewall_context(server_state, kad_firewall).await;
                match serve_upload_payload(UploadPayloadRequest {
                    transfer_runtime,
                    upload_queue: &mut upload_queue,
                    peer_upload_identity: peer_identity,
                    peer_ident_verified: peer_secure_ident.peer_ident_verified,
                    transport: &mut transport,
                    peer_addr,
                    opcode: packet.opcode,
                    payload: &packet.payload,
                })
                .await?
                {
                    UploadPayloadOutcome::Continue { requested } => {
                        requested_file_hash = Some(requested);
                    }
                    UploadPayloadOutcome::Close => {
                        break Ok(());
                    }
                }
            }
            (OP_EMULEPROT, OP_EMULEINFO) => {
                debug!(
                    "received eMule OP_EMULEINFO from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
                // Capture the peer's advertised eD2k UDP version + port so a later
                // UDP reask reply (OP_REASKACK) can gate its leading partstatus on
                // the peer's udp_version, mirroring eMule's GetUDPVersion() > 3.
                if let Ok(profile) = decode_emule_info_profile(&packet.payload) {
                    peer_upload_identity.udp_version = profile.udp_version;
                    if peer_upload_identity.udp_port.is_none() && profile.udp_port != 0 {
                        peer_upload_identity.udp_port = Some(profile.udp_port);
                    }
                    // OP_EMULEINFO carries the real eMule compatibility version
                    // byte (eMule m_byEmuleVersion), used for the old-client
                    // upload-score penalty; an OP_EMULEINFO sender is an eMule
                    // client (IsEmuleClient()).
                    peer_upload_identity.emule_version = profile.emule_version;
                    peer_upload_identity.is_emule_client = true;
                    // OP_EMULEINFO can also advertise comment acceptance (oracle
                    // BaseClient.cpp ProcessMuleInfoPacket m_byAcceptCommentVer);
                    // honour it without downgrading a higher hello-advertised one.
                    if profile.accepts_comments && peer_accept_comment_version == 0 {
                        peer_accept_comment_version = 1;
                    }
                }
                let reply = encode_emule_info_answer(reachability.advertised_udp_port(kad_udp_port));
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "emule_info_answer", &reply);
                transport
                    .write_all(&reply)
                    .await
                    .with_context(|| format!("failed to send OP_EMULEINFOANSWER to {peer_addr}"))?;
            }
            (OP_EMULEPROT, OP_EMULEINFOANSWER) => {
                debug!(
                    "received eMule OP_EMULEINFOANSWER from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
            }
            (OP_EMULEPROT, OP_SECIDENTSTATE) => {
                secure_ident::handle_secident_state(
                    &mut transport,
                    peer_addr,
                    secure_ident,
                    &mut peer_secure_ident,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_PUBLICKEY) => {
                secure_ident::handle_public_key(
                    &mut transport,
                    peer_addr,
                    secure_ident,
                    &mut peer_secure_ident,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_SIGNATURE) => {
                secure_ident::handle_signature(
                    &transport,
                    peer_addr,
                    secure_ident,
                    &mut peer_secure_ident,
                    &mut peer_upload_identity,
                    transfer_runtime,
                    reachability.get(),
                    &packet.payload,
                );
            }
            (OP_EMULEPROT, OP_PUBLICIP_REQ) => {
                debug!(
                    "received eMule OP_PUBLICIP_REQ from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
                if let IpAddr::V4(peer_ip) = peer_addr.ip() {
                    let reply = encode_public_ip_answer(peer_ip);
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "public_ip_answer",
                        &reply,
                    );
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send OP_PUBLICIP_ANSWER to {peer_addr}")
                    })?;
                }
            }
            (OP_EMULEPROT, OP_PUBLICIP_ANSWER) => {
                notify::handle_public_ip_answer(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EMULEPROT, OP_CALLBACK) => {
                let callback = decode_kad_callback_payload(&packet.payload)?;
                dump_ed2k_tcp_listener_meta(
                    peer_addr,
                    Some(transport.mode),
                    "kad_callback",
                    format!(
                        "file_hash={} callback_peer={}:{} buddy_check={} trailing_len={}",
                        callback.file_hash,
                        callback.peer_ip,
                        callback.peer_tcp_port,
                        hex::encode(callback.buddy_check),
                        callback.trailing_len
                    ),
                );
                // Firewalled-callback completion (oracle ListenSocket.cpp:1596-1633
                // OP_CALLBACK): the requester wants us — the firewalled LowID
                // source — to TCP-connect out so it can reach us. The oracle
                // processes OP_CALLBACK on ANY inbound client socket (not only the
                // buddy relay leg), gated by the same guard: Kad running, the
                // uCheck-complement equals our own Kad id, and the referenced file
                // is shared/downloaded. Route through the shared guard so this
                // inbound path cannot drift from the buddy-link path and cannot be
                // abused as a connect-back reflector/probe.
                let bind_ip = match local_addr.ip() {
                    IpAddr::V4(ip) => ip,
                    IpAddr::V6(_) => {
                        debug!(
                            "skipping Kad callback connect-out for {peer_addr}: IPv6 bind \
                             address unsupported"
                        );
                        continue;
                    }
                };
                complete_authorized_kad_callback(
                    bind_ip,
                    dht.own_id().0,
                    transfer_runtime,
                    response_identity,
                    &callback,
                    &format!("inbound {peer_addr}"),
                )
                .await;
            }
            (OP_EMULEPROT, OP_REASKCALLBACKTCP) => {
                notify::handle_reask_callback_tcp(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EMULEPROT, OP_CHATCAPTCHAREQ) => {
                notify::handle_chat_captcha_request(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EMULEPROT, OP_CHATCAPTCHARES) => {
                notify::handle_chat_captcha_result(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EMULEPROT, OP_PORTTEST) => {
                debug!(
                    "received eMule OP_PORTTEST from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
                let reply = encode_port_test_answer();
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "port_test", &reply);
                transport
                    .write_all(&reply)
                    .await
                    .with_context(|| format!("failed to send OP_PORTTEST to {peer_addr}"))?;
            }
            (OP_EMULEPROT, OP_FWCHECKUDPREQ) => {
                debug!(
                    "received eMule OP_FWCHECKUDPREQ from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
                let request = FirewallCheckUdpRequest::decode(&packet.payload)?;
                dump_ed2k_tcp_listener_meta(
                    peer_addr,
                    Some(transport.mode),
                    "fwcheck_request",
                    format!(
                        "internal_udp_port={} external_udp_port={} sender_udp_key={}",
                        request.internal_udp_port,
                        request.external_udp_port,
                        request.sender_udp_key
                    ),
                );
                reply_with_firewall_udp(dht, peer_addr.ip(), request).await?;
            }
            (OP_EMULEPROT, OP_KAD_FWTCPCHECK_ACK) => {
                // A helper we asked (via KADEMLIA2_FIREWALLED2_REQ) connected back
                // to our eD2k listener and confirmed our TCP port is open. Count
                // it as an open observation, but only from an IP we actually
                // probed (oracle ListenSocket.cpp: IsKadFirewallCheckIP ->
                // IncFirewalled).
                let accepted = kad_firewall
                    .lock()
                    .await
                    .record_tcp_open_ack(peer_addr.ip(), chrono::Utc::now());
                dump_ed2k_tcp_listener_meta(
                    peer_addr,
                    Some(transport.mode),
                    "kad_firewall_tcp_ack",
                    format!("received=true accepted={accepted}"),
                );
            }
            (OP_EMULEPROT, OP_BUDDYPING) => {
                dump_ed2k_tcp_listener_meta(
                    peer_addr,
                    Some(transport.mode),
                    "kad_buddy_ping",
                    format!("held_buddy={}", buddy_hold.is_some()),
                );
                // Oracle ListenSocket.cpp: answer OP_BUDDYPING with OP_BUDDYPONG
                // only when the pinger is the buddy we serve (buddy == client) and
                // not too soon (AllowIncomingBuddyPingPong, MIN2MS(3)); after a
                // reply record the time (SetLastBuddyPingPongTime).
                if let Some(hold) = buddy_hold.as_mut() {
                    if hold.allow_incoming_buddy_pingpong() {
                        let pong = encode_buddy_pong();
                        transport.write_all(&pong).await.with_context(|| {
                            format!("failed to send OP_BUDDYPONG to buddy {peer_addr}")
                        })?;
                        hold.last_buddy_pingpong_at = Some(std::time::Instant::now());
                    } else {
                        debug!(
                            "ignoring OP_BUDDYPING from buddy {peer_addr}: within pingpong cooldown"
                        );
                    }
                }
            }
            (OP_EMULEPROT, OP_BUDDYPONG) => {
                notify::handle_buddy_pong(&transport, peer_addr, buddy_hold.is_some());
            }
            (OP_EMULEPROT, OP_FILEDESC) => {
                notify::handle_file_desc(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EMULEPROT, OP_REQUESTPREVIEW) => {
                notify::handle_preview_request(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EMULEPROT, OP_PREVIEWANSWER) => {
                notify::handle_preview_answer(&transport, peer_addr, &packet.payload)?;
            }
            (OP_EMULEPROT, OP_AICHREQUEST) => {
                let request = decode_aich_recovery_request_payload(&packet.payload)?;
                dump_ed2k_tcp_listener_meta(
                    peer_addr,
                    Some(transport.mode),
                    "aich_recovery_request",
                    format!(
                        "file_hash={} part={} master_hash={}",
                        request.file_hash,
                        request.part,
                        hex::encode(request.master_hash)
                    ),
                );
                let recovery = transfer_runtime
                    .create_aich_recovery_data(&request.file_hash, request.part, request.master_hash)
                    .await
                    .unwrap_or(None);
                let (reply, dump_tag) = match recovery {
                    Some(body) => (
                        encode_aich_recovery_answer(
                            &request.file_hash,
                            request.part,
                            request.master_hash,
                            &body,
                        ),
                        "aich_recovery_answer",
                    ),
                    None => (
                        encode_aich_recovery_failure_answer(&request.file_hash),
                        "aich_recovery_failure",
                    ),
                };
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, dump_tag, &reply);
                transport.write_all(&reply).await.with_context(|| {
                    format!("failed to send OP_AICHANSWER to {peer_addr}")
                })?;
            }
            (OP_EMULEPROT, OP_AICHANSWER) => {
                let answer = decode_aich_recovery_answer_payload(&packet.payload)?;
                dump_ed2k_tcp_listener_meta(
                    peer_addr,
                    Some(transport.mode),
                    "aich_recovery_answer",
                    format!(
                        "file_hash={} part={:?} master_hash={} recovery_payload_len={}",
                        answer.file_hash,
                        answer.part,
                        answer
                            .master_hash
                            .map(hex::encode)
                            .unwrap_or_else(|| "none".to_string()),
                        answer.recovery_payload_len
                    ),
                );
                let answer_file_hash = answer.file_hash.to_string();
                handle_aich_recovery_answer(
                    transfer_runtime,
                    &answer_file_hash,
                    &answer,
                    &packet.payload,
                    peer_addr,
                    transport.mode,
                )
                .await?;
            }
            _ => {
                // Phase A defensive diagnostic: an inbound peer packet the dispatcher
                // does not handle; rust drops the connection (already defensive).
                crate::ed2k_transfer::diag_bad_peer::packet_unknown_client_tcp_packet(
                    &peer_addr.to_string(),
                    None,
                    packet.protocol,
                    packet.opcode,
                    packet.payload.len(),
                );
                if let Some(requested_file_hash) = requested_file_hash {
                    debug!(
                        "closing eD2k connection from {peer_addr}: unsupported protocol=0x{:02X} opcode=0x{:02X} requested_file_hash={requested_file_hash}",
                        packet.protocol, packet.opcode
                    );
                    break Ok(());
                }
                debug!(
                    "closing eD2k connection from {peer_addr}: unsupported protocol=0x{:02X} opcode=0x{:02X}",
                    packet.protocol, packet.opcode
                );
                break Ok(());
            }
        }
        }
    }
    .await;

    upload_queue.release(transfer_runtime).await;
    // Release the inbound buddy slot when the held session ends so the
    // buddy-management loop can re-establish on a reconnect (oracle buddy-loss).
    if let Some(hold) = buddy_hold {
        buddy_registry.detach_inbound(hold.buddy_id);
        debug!("released inbound Kad buddy session for {peer_addr}");
    }
    result
}

/// Oracle `AllowIncomingBuddyPingPong()` cadence (LOWID-G9b): after sending an
/// `OP_BUDDYPONG` the oracle arms `m_dwLastBuddyPingPongTime` to `now + MIN2MS(10)`
/// (`SetLastBuddyPingPongTime`, UpDownClient.h:189) and only allows the next pong
/// once `now >= m_dwLastBuddyPingPongTime + MIN2MS(3)`
/// (`AllowIncomingBuddyPingPong`, UpDownClient.h:188) — i.e. ~13 minutes after the
/// last reply. Since the firewalled buddy pings every 10 minutes, this makes us
/// pong every *other* ping (a flat 3-minute gate would pong every ping).
const BUDDY_PINGPONG_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(13 * 60);

/// Inbound Kad buddy hold state owned by a held listener session.
struct InboundBuddyHold {
    buddy_id: NodeId,
    relay_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    /// When we last answered/observed a buddy ping/pong, gating the next allowed
    /// reply (oracle `SetLastBuddyPingPongTime` / `AllowIncomingBuddyPingPong`).
    /// Seeded at hold creation (LOWID-G9b), mirroring the oracle arming the marker
    /// in the buddy client ctor, so the first pong waits the full gate.
    last_buddy_pingpong_at: Option<std::time::Instant>,
}

impl InboundBuddyHold {
    /// Whether an incoming `OP_BUDDYPING` may be answered now, mirroring the
    /// oracle `AllowIncomingBuddyPingPong()` 3-minute minimum interval.
    fn allow_incoming_buddy_pingpong(&self) -> bool {
        allow_buddy_pingpong_at(self.last_buddy_pingpong_at, std::time::Instant::now())
    }
}

/// Pure 3-minute buddy ping/pong gate (oracle `AllowIncomingBuddyPingPong`),
/// split out so the cadence is deterministically unit-testable.
fn allow_buddy_pingpong_at(last: Option<std::time::Instant>, now: std::time::Instant) -> bool {
    match last {
        None => true,
        Some(last) => now.saturating_duration_since(last) >= BUDDY_PINGPONG_MIN_INTERVAL,
    }
}

fn upload_peer_identity_from_socket(peer_addr: SocketAddr) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        ip: peer_addr.ip(),
        tcp_port: peer_addr.port(),
        udp_port: None,
        udp_version: 0,
        should_crypt: false,
        user_hash: None,
        client_id: None,
        friend_slot: false,
        ident_verified: false,
        ident_bad_guy: false,
        gpl_evildoer: false,
        banned: false,
        emule_version: 0,
        is_emule_client: false,
        kad_port: 0,
        supports_direct_udp_callback: false,
        firewall_context: crate::ed2k_transfer::Ed2kUploadFirewallContext::default(),
        client_software: None,
    }
}

fn upload_peer_identity_from_hello(
    peer_addr: SocketAddr,
    profile: &DecodedHelloProfile,
) -> Ed2kUploadPeerIdentity {
    let remote_hello = &profile.identity;
    Ed2kUploadPeerIdentity {
        ip: peer_addr.ip(),
        tcp_port: if remote_hello.tcp_port == 0 {
            peer_addr.port()
        } else {
            remote_hello.tcp_port
        },
        udp_port: (remote_hello.udp_port != 0).then_some(remote_hello.udp_port),
        // udp_version is learned later from OP_EMULEINFO; should_crypt + ident_verified
        // are set by the caller (live transport mode / verified secure-ident signature).
        udp_version: 0,
        should_crypt: false,
        user_hash: Some(remote_hello.user_hash),
        client_id: Some(remote_hello.client_id),
        friend_slot: false,
        ident_verified: false,
        ident_bad_guy: false,
        // GPL-breaker mod-version verdict (eMule CheckForGPLEvilDoer), parsed from
        // the hello CT_MOD_VERSION string.
        gpl_evildoer: profile.gpl_evildoer,
        banned: false,
        // eMule sets m_byEmuleVersion = 0x99 for a CT_EMULE_VERSION mule hello; a
        // real (older) version byte arrives later via OP_EMULEINFO.
        emule_version: if profile.is_mule_hello { 0x99 } else { 0 },
        is_emule_client: profile.is_mule_hello,
        // Peer Kad port (high 16 of CT_EMULE_UDPPORTS): a Kad-reachable peer is
        // exempt from the firewalled-LowID callback admission guard.
        kad_port: remote_hello.kad_port,
        // MISCOPTIONS2 bit 12: lets the promote driver reach a firewalled LowID
        // waiter with OP_DIRECTCALLBACKREQ instead of dropping the grant.
        supports_direct_udp_callback: profile.supports_direct_udp_callback,
        // Set per-request by the OP_STARTUPLOADREQ / OP_REQUESTPARTS handlers from
        // the live server/Kad firewall state; defaults to non-firewalled here.
        firewall_context: crate::ed2k_transfer::Ed2kUploadFirewallContext::default(),
        client_software: profile.client_software.clone(),
    }
}

pub(crate) async fn reply_with_firewall_udp(
    dht: &DhtNode,
    peer_ip: IpAddr,
    request: FirewallCheckUdpRequest,
) -> Result<()> {
    if request.internal_udp_port == 0 {
        return Ok(());
    }

    let ports = if request.external_udp_port != 0
        && request.external_udp_port != request.internal_udp_port
    {
        vec![request.internal_udp_port, request.external_udp_port]
    } else {
        vec![request.internal_udp_port]
    };

    let error_code = match peer_ip {
        IpAddr::V4(ip) => {
            if dht
                .routing_contacts()
                .await
                .iter()
                .any(|contact| contact.ip == ip)
            {
                1u8
            } else {
                0u8
            }
        }
        IpAddr::V6(_) => 1,
    };

    for port in ports.into_iter().filter(|port| *port != 0) {
        let target = SocketAddr::new(peer_ip, port);
        if request.sender_udp_key != 0 {
            dht.register_peer_key(target, request.sender_udp_key);
        }
        dht.send_packet(
            target,
            &KadPacket::FirewallUdp(FirewallUdp {
                error_code,
                udp_port: port,
            }),
        )
        .await
        .with_context(|| format!("failed to send KADEMLIA2_FIREWALLUDP to {target}"))?;
    }
    Ok(())
}

async fn enrich_hello_identity(
    identity: Ed2kHelloIdentity,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
) -> Ed2kHelloIdentity {
    let mut identity = {
        let state = server_state.read().await;
        apply_server_state(identity, &state)
    };
    let firewall = kad_firewall.lock().await;
    identity.direct_udp_callback = identity.client_id != 0
        && identity.client_id < 0x0100_0000
        && firewall.udp_verified
        && firewall.udp_open;
    identity
}

/// Build the firewalled-LowID callback admission context (master
/// `AddClientToQueue` opening guard) from our live server + Kad firewall state.
///
/// `we_are_connected` mirrors `theApp.IsConnected()` (an eD2k server session or a
/// firewall-verified open Kad UDP path), and `we_are_firewalled` mirrors
/// `theApp.IsFirewalled()` (server-assigned LowID or a Kad TCP-firewalled
/// verdict). `peer_on_same_server` is `false`: an inbound peer's server is not
/// known at the listener, and the master treats an unknown peer server
/// (`GetServerIP()` 0) as a different server (`IsLocalServer` false).
async fn upload_firewall_context(
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
) -> crate::ed2k_transfer::Ed2kUploadFirewallContext {
    let (server_connected, server_low_id) = {
        let state = server_state.read().await;
        (state.connected, state.tcp_firewalled().unwrap_or(false))
    };
    let (kad_connected, kad_tcp_firewalled) = {
        let firewall = kad_firewall.lock().await;
        (
            firewall.udp_verified && firewall.udp_open,
            firewall.tcp_firewalled().unwrap_or(false),
        )
    };
    crate::ed2k_transfer::Ed2kUploadFirewallContext {
        we_are_connected: server_connected || kad_connected,
        we_are_firewalled: server_low_id || kad_tcp_firewalled,
        peer_on_same_server: false,
    }
}

#[cfg(test)]
mod tests {
    use super::{BUDDY_PINGPONG_MIN_INTERVAL, allow_buddy_pingpong_at};
    use std::time::{Duration, Instant};

    #[test]
    fn buddy_pingpong_gate_is_thirteen_minutes_and_pongs_every_other_ping() {
        // LOWID-G9b: the pong gate is ~13 minutes (MIN2MS(10)+MIN2MS(3)), so with
        // the firewalled buddy pinging every 10 minutes we pong every other ping.
        assert_eq!(BUDDY_PINGPONG_MIN_INTERVAL, Duration::from_secs(13 * 60));

        // Seeded at hold creation: the first ping (well before the gate) is NOT
        // answered, mirroring the oracle arming the marker in the buddy ctor.
        let created = Instant::now();
        let ping_interval = Duration::from_secs(10 * 60);
        // First ping ~10 min after creation: within the 13-min gate -> suppressed.
        assert!(!allow_buddy_pingpong_at(Some(created), created + ping_interval));

        // Simulate answering a pong at t (arms the marker to t), then the next
        // ping 10 min later is suppressed and the one after (20 min) is answered.
        let t = created + ping_interval + Duration::from_secs(30);
        assert!(!allow_buddy_pingpong_at(Some(t), t + ping_interval));
        assert!(allow_buddy_pingpong_at(Some(t), t + 2 * ping_interval));

        // Boundary: exactly at the gate is allowed, just before is not.
        assert!(!allow_buddy_pingpong_at(
            Some(t),
            t + BUDDY_PINGPONG_MIN_INTERVAL - Duration::from_secs(1)
        ));
        assert!(allow_buddy_pingpong_at(Some(t), t + BUDDY_PINGPONG_MIN_INTERVAL));
    }
}
