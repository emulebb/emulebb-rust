use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use crate::ed2k_transfer::{
    Ed2kResumeManifest, Ed2kSourceHint, Ed2kTransferRuntime, Ed2kTransferState, diag_bad_peer,
};

use super::super::{
    DecodedEmuleInfoProfile, Ed2kFileIdentifier, Ed2kHelloIdentity, Ed2kSecureIdent, Ed2kTransport,
    OP_ACCEPTUPLOADREQ, OP_AICHANSWER, OP_AICHFILEHASHANS, OP_AICHREQUEST, OP_ANSWERSOURCES,
    OP_ANSWERSOURCES2, OP_ASKSHAREDDENIEDANS, OP_ASKSHAREDDIRS, OP_ASKSHAREDDIRSANS,
    OP_ASKSHAREDFILES, OP_ASKSHAREDFILESANSWER, OP_ASKSHAREDFILESDIR, OP_ASKSHAREDFILESDIRANS,
    OP_BUDDYPING, OP_BUDDYPONG, OP_CALLBACK, OP_CANCELTRANSFER, OP_CHANGE_CLIENT_ID,
    OP_CHANGE_SLOT, OP_CHATCAPTCHAREQ, OP_CHATCAPTCHARES, OP_COMPRESSEDPART, OP_COMPRESSEDPART_I64,
    OP_EDONKEYPROT, OP_EMULEINFO, OP_EMULEINFOANSWER, OP_EMULEPROT, OP_END_OF_DOWNLOAD,
    OP_FILEDESC, OP_FILEREQANSNOFIL, OP_FILESTATUS, OP_HASHSETANSWER, OP_HASHSETANSWER2, OP_HELLO,
    OP_HELLOANSWER, OP_KAD_FWTCPCHECK_ACK, OP_MESSAGE, OP_MULTIPACKETANSWER,
    OP_MULTIPACKETANSWER_EXT2, OP_OUTOFPARTREQS, OP_PORTTEST, OP_PREVIEWANSWER, OP_PUBLICIP_ANSWER,
    OP_PUBLICIP_REQ, OP_PUBLICKEY, OP_QUEUERANK, OP_QUEUERANKING, OP_REASKCALLBACKTCP,
    OP_REQFILENAMEANSWER, OP_REQUESTPREVIEW, OP_SECIDENTSTATE, OP_SENDINGPART, OP_SENDINGPART_I64,
    OP_SETREQFILEID, OP_SIGNATURE, SourceExchangePeer, begin_secure_ident_probe,
    build_hello_responses, decode_aich_file_hash_answer, decode_aich_recovery_answer_payload,
    decode_aich_recovery_request_payload, decode_answer_sources_payload,
    decode_answer_sources2_payload, decode_client_id_change_payload, decode_client_message_payload,
    decode_edonkey_queue_rank_payload, decode_emule_info_profile,
    decode_emule_queue_ranking_payload, decode_exact_file_hash_payload,
    decode_file_status_availability, decode_file_status_body_availability, decode_hashset_answer,
    decode_hashset_answer2, decode_hello_answer_profile, decode_hello_profile,
    decode_optional_file_hash_payload, decode_request_filename_answer,
    decode_request_filename_answer_body, dump_ed2k_tcp_download_meta, dump_ed2k_tcp_download_recv,
    dump_ed2k_tcp_download_send, encode_aich_recovery_answer, encode_aich_recovery_failure_answer,
    encode_emule_info_answer, encode_packet, encode_port_test_answer, encode_public_ip_answer,
    handle_aich_recovery_answer, is_connection_shutdown_error, validate_file_status_part_count,
};
use super::{
    ActiveDownloadPiece, AichRecoveryRequestState, DownloadRequestWindowOutcome,
    DownloadRequestWindowState, PendingCompressedPart, PendingPartRequest,
    flush_buffered_download_prefixes, next_download_read_timeout, pump_aich_recovery_requests,
    pump_download_request_window, reconcile_download_manifest_metadata,
};
mod browse;
mod notify;
mod parts;
mod reask_detach;
mod secure_ident;
mod startup;
mod state;

use parts::{DownloadPartPacket, handle_download_part_packet};
use reask_detach::incomplete_or_detached_queued_source;
use startup::{DownloadStartupStep, HASHSET_STALL_UPLOAD_FALLBACK, advance_download_startup};
use state::DownloadSessionState;

fn apply_emule_info_profile(
    session_state: &mut DownloadSessionState,
    profile: DecodedEmuleInfoProfile,
) {
    session_state.remote_source_exchange_version = profile.source_exchange_version;
    session_state.remote_supports_source_exchange = profile.supports_source_exchange;
    session_state.remote_supports_source_exchange2 = false;
    session_state.remote_supports_secure_ident = profile.supports_secure_ident;
    tracing::debug!(
        "applied OP_EMULEINFO profile: udp_port={} udp_version={}",
        profile.udp_port,
        profile.udp_version,
    );
    // udp_port is normally learned from the hello (CT_EMULE_UDPPORTS); only let
    // OP_EMULEINFO fill it when the hello did not. udp_version is an OP_EMULEINFO
    // field (ET_UDPVER), so always take it from here.
    if profile.udp_port != 0 {
        session_state.peer_udp_port = profile.udp_port;
    }
    if profile.udp_version != 0 {
        session_state.peer_udp_version = profile.udp_version;
    }
}

/// Outcome of one outbound ED2K peer download attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed2kPeerDownloadOutcome {
    /// The peer contributed enough data for the manifest to complete.
    Completed,
    /// The peer accepted the session but the transfer did not complete before the
    /// peer closed or the attempt timed out.
    AcceptedButIncomplete,
    /// The peer queued us and is UDP-reask eligible, so the session detached its TCP
    /// socket onto the UDP reask loop (eMuleBB `QueuedDetached`); the driver must not
    /// reconnect (the reask loop keeps the slot warm + re-engages on UDP failure).
    QueuedDetachedForUdpReask,
    /// The peer reported No Needed Parts for this file (eMuleBB `OP_OUTOFPARTREQS`
    /// / `DS_NONEEDEDPARTS`): we already hold every part it offers, or it lacks the
    /// parts we still need. The driver runs the A4AF-lite NNP swap
    /// (`CUpDownClient::SwapToAnotherFile`): if the source serves another wanted
    /// file in the registry it is swapped to that file instead of being dropped.
    NoNeededParts,
}

pub(in crate::ed2k_tcp) struct DownloadSessionOptions<'a> {
    pub(in crate::ed2k_tcp) transport: &'a mut Ed2kTransport,
    pub(in crate::ed2k_tcp) peer_addr: SocketAddr,
    pub(in crate::ed2k_tcp) hello_identity: Ed2kHelloIdentity,
    pub(in crate::ed2k_tcp) secure_ident: &'a Ed2kSecureIdent,
    pub(in crate::ed2k_tcp) transfer_runtime: &'a Ed2kTransferRuntime,
    pub(in crate::ed2k_tcp) file_hash: Ed2kHash,
    pub(in crate::ed2k_tcp) file_hash_hex: &'a str,
    pub(in crate::ed2k_tcp) timeout: Duration,
    pub(in crate::ed2k_tcp) send_initial_requests: bool,
    pub(in crate::ed2k_tcp) source_exchange_allowed: bool,
    pub(in crate::ed2k_tcp) initial_hello_complete: bool,
    pub(in crate::ed2k_tcp) initial_secure_ident_started: bool,
    pub(in crate::ed2k_tcp) peer_user_hash: Option<[u8; 16]>,
    pub(in crate::ed2k_tcp) peer_connect_options: Option<u8>,
    /// When set (UDP reask enabled), a queued + UDP-eligible source detaches its TCP
    /// socket onto UDP reask via this handle. `None` keeps the legacy TCP-only path.
    pub(in crate::ed2k_tcp) reask_register: Option<crate::ed2k_client_udp::ReaskSourceHandle>,
}

pub(in crate::ed2k_tcp) async fn drive_download_session(
    options: DownloadSessionOptions<'_>,
) -> Result<Ed2kPeerDownloadOutcome> {
    let DownloadSessionOptions {
        transport,
        peer_addr,
        hello_identity,
        secure_ident,
        transfer_runtime,
        file_hash,
        file_hash_hex,
        timeout,
        send_initial_requests,
        source_exchange_allowed,
        initial_hello_complete,
        initial_secure_ident_started,
        peer_user_hash,
        peer_connect_options,
        reask_register,
    } = options;
    const QUEUE_RANK_GRACE: Duration = Duration::from_secs(75);
    const PART_RESPONSE_GRACE: Duration = Duration::from_secs(75);
    // eMule keeps a pending block scheduler that is broader than one live wire
    // request. We mirror that with one claimed piece, a queued-vs-unqueued
    // block list, and wire packets that carry up to three queued ranges.
    let mut pending_part_requests: Vec<PendingPartRequest> = Vec::new();
    let mut pending_compressed_parts: Vec<PendingCompressedPart> = Vec::new();
    let mut manifest = transfer_runtime.manifest(file_hash_hex).await?;
    let mut request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
    let mut session_state = DownloadSessionState::new(
        initial_hello_complete,
        initial_secure_ident_started,
        source_exchange_allowed,
        peer_user_hash,
        peer_connect_options,
    );

    let session_result = async {
        loop {
            if manifest.completed {
                return Ok(Ed2kPeerDownloadOutcome::Completed);
            }

            advance_download_startup(DownloadStartupStep {
                transport,
                peer_addr,
                secure_ident,
                transfer_runtime,
                file_hash: &file_hash,
                file_hash_hex,
                send_initial_requests,
                manifest: &mut manifest,
                request_file_identifier: &request_file_identifier,
                session_state: &mut session_state,
            })
            .await?;

            if manifest.md4_hashset_acquired && session_state.upload_accepted {
                match pump_download_request_window(
                    transport,
                    peer_addr,
                    DownloadRequestWindowState {
                        transfer_runtime,
                        file_hash: &file_hash,
                        file_hash_hex,
                        file_size: manifest.file_size,
                        manifest: &manifest,
                        active_piece_request: &mut session_state.active_piece_request,
                        pending_part_requests: &mut pending_part_requests,
                        peer_part_bitmap: session_state.peer_part_bitmap.as_deref(),
                        upload_accepted_at: session_state.upload_accepted_at
                            .unwrap_or_else(tokio::time::Instant::now),
                        completed_block_count: session_state.completed_block_count,
                        session_payload_down: session_state.session_payload_down,
                        part_response_grace: PART_RESPONSE_GRACE,
                    },
                )
                .await?
                {
                    DownloadRequestWindowOutcome::RequestSent(next_deadline) => {
                        session_state.part_response_deadline = Some(next_deadline);
                    }
                    DownloadRequestWindowOutcome::NoClaimablePart => {
                        // WHY: an accepted upload slot with no locally claimable block is
                        // useful to neither peer. Mirror MFC SendBlockRequests by freeing
                        // the remote slot immediately instead of idling until timeout.
                        let cancel = encode_packet(OP_EDONKEYPROT, OP_CANCELTRANSFER, &[]);
                        dump_ed2k_tcp_download_send(
                            peer_addr,
                            transport.mode,
                            "cancel_no_needed_parts",
                            &cancel,
                        );
                        transport.write_all(&cancel).await.with_context(|| {
                            format!("failed to send OP_CANCELTRANSFER to {peer_addr}")
                        })?;
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            Some(transport.mode),
                            "no_needed_parts_request_window",
                            format!("file_hash={file_hash_hex}"),
                        );
                        return Ok(Ed2kPeerDownloadOutcome::NoNeededParts);
                    }
                    DownloadRequestWindowOutcome::Idle => {}
                }
            }

            let fallback_poll_delay = if send_initial_requests
                && session_state.hello_complete
                && session_state.hashset_requested
                && !manifest.md4_hashset_acquired
                && !session_state.upload_requested
            {
                session_state.hashset_requested_at.map(|requested_at| {
                    HASHSET_STALL_UPLOAD_FALLBACK.saturating_sub(requested_at.elapsed())
                })
            } else {
                None
            };
            let now = tokio::time::Instant::now();
            let read_timeout = next_download_read_timeout(
                now,
                timeout,
                fallback_poll_delay,
                session_state.queued_until,
                session_state.part_response_deadline,
            );
            let packet = match tokio::time::timeout(read_timeout, transport.read_packet()).await {
                Ok(Ok(Some(packet))) => packet,
                Ok(Ok(None)) => {
                    if session_state.hello_complete {
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            Some(transport.mode),
                            "peer_closed_incomplete",
                            format!("file_hash={file_hash_hex}"),
                        );
                        return Ok(incomplete_or_detached_queued_source(
                            &reask_register,
                            peer_addr,
                            file_hash,
                            &session_state,
                            transport.mode.is_obfuscated(),
                        ));
                    }
                    anyhow::bail!("peer {peer_addr} closed ED2K download session");
                }
                Ok(Err(error)) => {
                    if session_state.hello_complete && is_connection_shutdown_error(&error) {
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            Some(transport.mode),
                            "peer_shutdown_incomplete",
                            format!("file_hash={file_hash_hex}"),
                        );
                        return Ok(incomplete_or_detached_queued_source(
                            &reask_register,
                            peer_addr,
                            file_hash,
                            &session_state,
                            transport.mode.is_obfuscated(),
                        ));
                    }
                    return Err(error)
                        .with_context(|| format!("failed to read eD2k packet from {peer_addr}"));
                }
                Err(_) => {
                    if fallback_poll_delay.is_some() {
                        continue;
                    }
                    if session_state.queued_until.is_some_and(|deadline| tokio::time::Instant::now() < deadline) {
                        continue;
                    }
                    if !pending_part_requests.iter().any(|request| request.queued) {
                        session_state.part_response_deadline = None;
                    }
                    if session_state.part_response_deadline
                        .is_some_and(|deadline| tokio::time::Instant::now() < deadline)
                    {
                        continue;
                    }
                    if session_state.hello_complete {
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            Some(transport.mode),
                            "peer_timeout_incomplete",
                            format!("file_hash={file_hash_hex}"),
                        );
                        // Parity with MFC CUpDownClient::CheckDownloadTimeout: a
                        // requested source that stalled past the part-response
                        // deadline is surfaced as a bad_peer event — split on
                        // session_payload_down (= GetSessionPayloadDown()): 0 => it
                        // sent no payload at all (download_first_payload_timeout),
                        // >0 => it stalled mid-transfer (download_idle_timeout).
                        if session_state.session_payload_down == 0 {
                            diag_bad_peer::download_first_payload_timeout(
                                &peer_addr.to_string(),
                                session_state.peer_user_hash,
                                file_hash_hex,
                            );
                        } else {
                            diag_bad_peer::download_idle_timeout(
                                &peer_addr.to_string(),
                                session_state.peer_user_hash,
                                file_hash_hex,
                            );
                        }
                        return Ok(incomplete_or_detached_queued_source(
                            &reask_register,
                            peer_addr,
                            file_hash,
                            &session_state,
                            transport.mode.is_obfuscated(),
                        ));
                    }
                    anyhow::bail!("timed out waiting for ED2K peer packet from {peer_addr}");
                }
            };
            dump_ed2k_tcp_download_recv(peer_addr, transport.mode, "session", &packet);

            match (packet.protocol, packet.opcode) {
                (OP_EDONKEYPROT, OP_HELLO) => {
                    let hello_profile = decode_hello_profile(&packet.payload)?;
                    for reply in build_hello_responses(&packet.payload, hello_identity)? {
                        dump_ed2k_tcp_download_send(peer_addr, transport.mode, "hello_reply", &reply);
                        transport.write_all(&reply).await.with_context(|| {
                            format!("failed to reply to OP_HELLO during download with {peer_addr}")
                        })?;
                    }
                    session_state.hello_complete = true;
                    session_state.peer_user_hash = Some(hello_profile.identity.user_hash);
                    session_state.peer_connect_options = Some(hello_profile.connect_options);
                    if hello_profile.identity.udp_port != 0 {
                        session_state.peer_udp_port = hello_profile.identity.udp_port;
                    }
                    session_state.capture_peer_buddy(&hello_profile);
                    session_state.remote_supports_aich = hello_profile.supports_aich;
                    session_state.remote_supports_secure_ident = hello_profile.supports_secure_ident;
                    session_state.peer_secure_ident.peer_sec_ident = hello_profile.misc_options1.secure_ident;
                    session_state.remote_supports_file_identifiers = hello_profile.supports_file_identifiers;
                    session_state.remote_supports_multipacket = hello_profile.supports_multipacket;
                    session_state.remote_supports_ext_multipacket =
                        hello_profile.supports_ext_multipacket;
                    session_state.remote_source_exchange_version =
                        hello_profile.source_exchange_version;
                    session_state.remote_supports_source_exchange = hello_profile.supports_source_exchange;
                    session_state.remote_supports_source_exchange2 = hello_profile.supports_source_exchange2;
                    if hello_profile.supports_secure_ident
                        && !session_state.peer_secure_ident.requested_peer_key
                    {
                        let secure_ident_probe = begin_secure_ident_probe(&mut session_state.peer_secure_ident);
                        dump_ed2k_tcp_download_send(
                            peer_addr,
                            transport.mode,
                            "secure_ident_probe",
                            &secure_ident_probe,
                        );
                        transport
                            .write_all(&secure_ident_probe)
                            .await
                            .with_context(|| {
                                format!("failed to send OP_SECIDENTSTATE to {peer_addr}")
                            })?;
                        session_state.secure_ident_started = true;
                    }
                }
                (OP_EDONKEYPROT, OP_HELLOANSWER) => {
                    let hello_profile = decode_hello_answer_profile(&packet.payload)?;
                    session_state.hello_complete = true;
                    session_state.peer_user_hash = Some(hello_profile.identity.user_hash);
                    session_state.peer_connect_options = Some(hello_profile.connect_options);
                    // The peer's eD2k UDP port rides in the hello (CT_EMULE_UDPPORTS);
                    // capture it for UDP-reask detach (udp_version comes from OP_EMULEINFO).
                    if hello_profile.identity.udp_port != 0 {
                        session_state.peer_udp_port = hello_profile.identity.udp_port;
                    }
                    session_state.capture_peer_buddy(&hello_profile);
                    session_state.remote_supports_aich = hello_profile.supports_aich;
                    session_state.remote_supports_secure_ident = hello_profile.supports_secure_ident;
                    session_state.peer_secure_ident.peer_sec_ident = hello_profile.misc_options1.secure_ident;
                    session_state.remote_supports_file_identifiers = hello_profile.supports_file_identifiers;
                    session_state.remote_supports_multipacket = hello_profile.supports_multipacket;
                    session_state.remote_supports_ext_multipacket =
                        hello_profile.supports_ext_multipacket;
                    session_state.remote_source_exchange_version =
                        hello_profile.source_exchange_version;
                    session_state.remote_supports_source_exchange = hello_profile.supports_source_exchange;
                    session_state.remote_supports_source_exchange2 = hello_profile.supports_source_exchange2;
                    if send_initial_requests
                        && hello_profile.supports_secure_ident
                        && !session_state.peer_secure_ident.requested_peer_key
                    {
                        let secure_ident_probe = begin_secure_ident_probe(&mut session_state.peer_secure_ident);
                        dump_ed2k_tcp_download_send(
                            peer_addr,
                            transport.mode,
                            "secure_ident_probe",
                            &secure_ident_probe,
                        );
                        transport
                            .write_all(&secure_ident_probe)
                            .await
                            .with_context(|| {
                                format!("failed to send OP_SECIDENTSTATE to {peer_addr}")
                            })?;
                        session_state.secure_ident_started = true;
                    }
                }
                (OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ) => {
                    session_state.upload_accepted = true;
                    session_state.upload_accepted_at.get_or_insert_with(tokio::time::Instant::now);
                    session_state.queued_until = None;
                }
                (OP_EMULEPROT, OP_EMULEINFO) => {
                    let emule_info_profile = decode_emule_info_profile(&packet.payload)?;
                    apply_emule_info_profile(&mut session_state, emule_info_profile);
                    transport
                        .write_all(&encode_emule_info_answer(hello_identity.udp_port))
                        .await
                        .with_context(|| {
                            format!("failed to send OP_EMULEINFOANSWER to {peer_addr}")
                        })?;
                }
                (OP_EMULEPROT, OP_EMULEINFOANSWER) => {
                    let emule_info_profile = decode_emule_info_profile(&packet.payload)?;
                    apply_emule_info_profile(&mut session_state, emule_info_profile);
                }
                (OP_EMULEPROT, OP_SECIDENTSTATE) => {
                    secure_ident::handle_secident_state(
                        transport,
                        peer_addr,
                        secure_ident,
                        &mut session_state,
                        &packet.payload,
                    )
                    .await?;
                }
                (OP_EMULEPROT, OP_PUBLICKEY) => {
                    secure_ident::handle_public_key(
                        transport,
                        peer_addr,
                        secure_ident,
                        &mut session_state,
                        &packet.payload,
                    )
                    .await?;
                }
                (OP_EMULEPROT, OP_SIGNATURE) => {
                    secure_ident::handle_signature(
                        transport,
                        peer_addr,
                        secure_ident,
                        &mut session_state,
                        transfer_runtime,
                        &packet.payload,
                    );
                }
                (OP_EMULEPROT, OP_PUBLICIP_REQ) => {
                    if let std::net::IpAddr::V4(peer_ip) = peer_addr.ip() {
                        let reply = encode_public_ip_answer(peer_ip);
                        dump_ed2k_tcp_download_send(
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
                    notify::handle_public_ip_answer(transport, peer_addr, &packet.payload)?;
                }
                (OP_EMULEPROT, OP_CALLBACK) => {
                    notify::handle_kad_callback(transport, peer_addr, &packet.payload)?;
                }
                (OP_EMULEPROT, OP_REASKCALLBACKTCP) => {
                    notify::handle_reask_callback_tcp(transport, peer_addr, &packet.payload)?;
                }
                (OP_EMULEPROT, OP_CHATCAPTCHAREQ) => {
                    notify::handle_chat_captcha_request(transport, peer_addr, &packet.payload)?;
                }
                (OP_EMULEPROT, OP_CHATCAPTCHARES) => {
                    notify::handle_chat_captcha_result(transport, peer_addr, &packet.payload)?;
                }
                (OP_EMULEPROT, OP_PORTTEST) => {
                    let reply = encode_port_test_answer();
                    dump_ed2k_tcp_download_send(peer_addr, transport.mode, "port_test", &reply);
                    transport
                        .write_all(&reply)
                        .await
                        .with_context(|| format!("failed to send OP_PORTTEST to {peer_addr}"))?;
                }
                (OP_EMULEPROT, OP_KAD_FWTCPCHECK_ACK) => {
                    notify::handle_kad_firewall_tcp_ack(transport, peer_addr);
                }
                (OP_EMULEPROT, OP_BUDDYPING) | (OP_EMULEPROT, OP_BUDDYPONG) => {
                    notify::handle_buddy_ping_pong(transport, peer_addr, packet.opcode);
                }
                (OP_EDONKEYPROT, OP_HASHSETANSWER) => {
                    let (returned_hash, hashset) = decode_hashset_answer(&packet.payload)?;
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "peer {peer_addr} returned hashset for unexpected file {}",
                            returned_hash
                        );
                    }
                    manifest = transfer_runtime
                        .store_md4_hashset(file_hash_hex, hashset)
                        .await?;
                }
                (OP_EMULEPROT, OP_HASHSETANSWER2) => {
                    let hashset_answer = decode_hashset_answer2(&packet.payload)?;
                    if !request_file_identifier
                        .matches_relaxed(&hashset_answer.file_identifier)
                    {
                        anyhow::bail!(
                            "peer {peer_addr} returned OP_HASHSETANSWER2 for unexpected file {}",
                            hashset_answer.file_identifier.file_hash
                        );
                    }
                    if hashset_answer.file_identifier.aich_root.is_some() {
                        session_state.peer_advertised_aich_root = true;
                    }
                    reconcile_download_manifest_metadata(
                        transfer_runtime,
                        file_hash_hex,
                        peer_addr,
                        &mut manifest,
                        &mut request_file_identifier,
                        &hashset_answer.file_identifier,
                        None,
                    )
                    .await?;
                    if let Some(hashset) = hashset_answer.md4_hashset {
                        manifest = transfer_runtime
                            .store_md4_hashset(file_hash_hex, hashset)
                            .await?;
                    }
                    if let Some(hashset) = hashset_answer.aich_hashset {
                        manifest = transfer_runtime
                            .store_aich_hashset(file_hash_hex, hashset)
                            .await?;
                        request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
                    }
                }
                (OP_EDONKEYPROT, OP_REQFILENAMEANSWER) => {
                    let (returned_hash, returned_file_name) =
                        decode_request_filename_answer(&packet.payload)?;
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "OP_REQFILENAMEANSWER hash mismatch {} expected {}",
                            returned_hash,
                            file_hash
                        );
                    }
                    manifest = transfer_runtime
                        .reconcile_job_metadata(
                            file_hash_hex,
                            Some(returned_file_name.as_str()),
                            None,
                        )
                        .await?;
                    request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
                    session_state.startup_file_response_received = true;
                }
                (OP_EDONKEYPROT, OP_FILESTATUS) => {
                    let (returned_hash, availability) =
                        decode_file_status_availability(&packet.payload)?;
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "peer {peer_addr} returned file status for unexpected file {}",
                            returned_hash
                        );
                    }
                    validate_file_status_part_count(
                        u16::try_from(availability.len()).unwrap_or(u16::MAX),
                        manifest.file_size,
                    )?;
                    let bitmap = record_source_part_availability(
                        transfer_runtime,
                        file_hash_hex,
                        peer_addr,
                        session_state.peer_user_hash,
                        session_state.peer_connect_options,
                        availability,
                        manifest.pieces.len(),
                    );
                    if !peer_holds_needed_part(&manifest, &bitmap) {
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            Some(transport.mode),
                            "no_needed_parts_filestatus",
                            format!("file_hash={file_hash_hex}"),
                        );
                        return Ok(Ed2kPeerDownloadOutcome::NoNeededParts);
                    }
                    session_state.peer_part_bitmap = Some(bitmap);
                    session_state.startup_file_response_received = true;
                }
                (OP_EMULEPROT, OP_MULTIPACKETANSWER) => {
                    let returned_hash = Ed2kHash::from_bytes(
                        packet
                            .payload
                            .get(..16)
                            .context("short OP_MULTIPACKETANSWER file hash")?
                            .try_into()?,
                    );
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "peer {peer_addr} returned OP_MULTIPACKETANSWER for unexpected file {}",
                            returned_hash
                        );
                    }
                    let mut remaining = &packet.payload[16..];
                    let mut returned_file_name = None;
                    let mut returned_aich_root = None;
                    while let Some((&sub_opcode, rest)) = remaining.split_first() {
                        remaining = rest;
                        match sub_opcode {
                            OP_REQFILENAMEANSWER => {
                                let (file_name, rest) =
                                    decode_request_filename_answer_body(remaining)?;
                                remaining = rest;
                                returned_file_name = Some(file_name);
                            }
                            OP_FILESTATUS => {
                                let (availability, rest) =
                                    decode_file_status_body_availability(remaining)?;
                                validate_file_status_part_count(
                                    u16::try_from(availability.len()).unwrap_or(u16::MAX),
                                    manifest.file_size,
                                )?;
                                session_state.peer_part_bitmap =
                                    Some(record_source_part_availability(
                                        transfer_runtime,
                                        file_hash_hex,
                                        peer_addr,
                                        session_state.peer_user_hash,
                                        session_state.peer_connect_options,
                                        availability,
                                        manifest.pieces.len(),
                                    ));
                                remaining = rest;
                            }
                            OP_AICHFILEHASHANS => {
                                if remaining.len() < 20 {
                                    anyhow::bail!(
                                        "short OP_MULTIPACKETANSWER AICH root {}",
                                        remaining.len()
                                    );
                                }
                                returned_aich_root = Some(remaining[..20].try_into()?);
                                remaining = &remaining[20..];
                            }
                            _ => {
                                diag_bad_peer::packet_invalid_multipacket_subopcode(
                                    &peer_addr.to_string(),
                                    session_state.peer_user_hash,
                                    sub_opcode,
                                );
                                anyhow::bail!(
                                    "unsupported OP_MULTIPACKETANSWER sub-op 0x{sub_opcode:02X}"
                                );
                            }
                        }
                    }
                    if returned_aich_root.is_some() {
                        session_state.peer_advertised_aich_root = true;
                    }
                    manifest = transfer_runtime
                        .record_network_aich_root(
                            file_hash_hex,
                            returned_aich_root,
                            peer_addr.ip(),
                        )
                        .await?;
                    manifest = transfer_runtime
                        .reconcile_job_metadata(
                            file_hash_hex,
                            returned_file_name.as_deref(),
                            None,
                        )
                        .await?;
                    request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
                    if let Some(bitmap) = session_state.peer_part_bitmap.as_deref()
                        && !peer_holds_needed_part(&manifest, bitmap)
                    {
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            Some(transport.mode),
                            "no_needed_parts_multipacket",
                            format!("file_hash={file_hash_hex}"),
                        );
                        return Ok(Ed2kPeerDownloadOutcome::NoNeededParts);
                    }
                    session_state.startup_file_response_received = true;
                }
                (OP_EMULEPROT, OP_MULTIPACKETANSWER_EXT2) => {
                    let (returned_identifier, mut remaining) =
                        Ed2kFileIdentifier::decode(&packet.payload)?;
                    if !request_file_identifier.matches_relaxed(&returned_identifier) {
                        anyhow::bail!(
                            "peer {peer_addr} returned OP_MULTIPACKETANSWER_EXT2 for unexpected file {}",
                            returned_identifier.file_hash
                        );
                    }
                    let mut returned_file_name = None;
                    while let Some((&sub_opcode, rest)) = remaining.split_first() {
                        remaining = rest;
                        match sub_opcode {
                            OP_REQFILENAMEANSWER => {
                                let (file_name, rest) =
                                    decode_request_filename_answer_body(remaining)?;
                                remaining = rest;
                                returned_file_name = Some(file_name);
                            }
                            OP_FILESTATUS => {
                                let (availability, rest) =
                                    decode_file_status_body_availability(remaining)?;
                                validate_file_status_part_count(
                                    u16::try_from(availability.len()).unwrap_or(u16::MAX),
                                    manifest.file_size,
                                )?;
                                session_state.peer_part_bitmap =
                                    Some(record_source_part_availability(
                                        transfer_runtime,
                                        file_hash_hex,
                                        peer_addr,
                                        session_state.peer_user_hash,
                                        session_state.peer_connect_options,
                                        availability,
                                        manifest.pieces.len(),
                                    ));
                                remaining = rest;
                            }
                            _ => {
                                diag_bad_peer::packet_invalid_multipacket_subopcode(
                                    &peer_addr.to_string(),
                                    session_state.peer_user_hash,
                                    sub_opcode,
                                );
                                anyhow::bail!(
                                    "unsupported OP_MULTIPACKETANSWER_EXT2 sub-op 0x{sub_opcode:02X}"
                                );
                            }
                        }
                    }
                    if returned_identifier.aich_root.is_some() {
                        session_state.peer_advertised_aich_root = true;
                    }
                    reconcile_download_manifest_metadata(
                        transfer_runtime,
                        file_hash_hex,
                        peer_addr,
                        &mut manifest,
                        &mut request_file_identifier,
                        &returned_identifier,
                        returned_file_name.as_deref(),
                    )
                    .await?;
                    if let Some(bitmap) = session_state.peer_part_bitmap.as_deref()
                        && !peer_holds_needed_part(&manifest, bitmap)
                    {
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            Some(transport.mode),
                            "no_needed_parts_multipacket_ext2",
                            format!("file_hash={file_hash_hex}"),
                        );
                        return Ok(Ed2kPeerDownloadOutcome::NoNeededParts);
                    }
                    session_state.startup_file_response_received = true;
                }
                (OP_EMULEPROT, OP_AICHFILEHASHANS) => {
                    let (returned_hash, aich_root) = decode_aich_file_hash_answer(&packet.payload)?;
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "peer {peer_addr} returned AICH file hash for unexpected file {}",
                            returned_hash
                        );
                    }
                    session_state.peer_advertised_aich_root = true;
                    manifest = transfer_runtime
                        .record_network_aich_root(
                            file_hash_hex,
                            Some(aich_root),
                            peer_addr.ip(),
                        )
                        .await?;
                    request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
                }
                (OP_EDONKEYPROT, OP_SETREQFILEID) => {
                    // Non-oracle peers sometimes echo the file id again instead of
                    // the expected file-status payload. Stay tolerant, but do not
                    // treat it as the startup gate that oracle-like peers rely on.
                }
                (OP_EMULEPROT, OP_ANSWERSOURCES2) => {
                    let (answer_hash, sources) = decode_answer_sources2_payload(&packet.payload)?;
                    remember_source_exchange_sources(
                        transfer_runtime,
                        file_hash,
                        file_hash_hex,
                        answer_hash,
                        sources,
                    )
                    .await?;
                }
                (OP_EMULEPROT, OP_ANSWERSOURCES) => {
                    // SX2-only (REF-002 / sx1-live-source-exchange omission): we
                    // never solicit OP_REQUESTSOURCES, so an unsolicited legacy SX1
                    // OP_ANSWERSOURCES is decoded for the diagnostic dump only and
                    // its sources are NOT ingested. SX2 (OP_ANSWERSOURCES2 above)
                    // stays fully active.
                    let decoded = decode_answer_sources_payload(
                        &packet.payload,
                        session_state.remote_source_exchange_version,
                    );
                    let source_count = decoded.map(|(_, sources)| sources.len()).unwrap_or(0);
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "answer_sources_sx1_ignored",
                        format!("file_hash={file_hash_hex} sources={source_count} (SX1 ignored)"),
                    );
                }
                (OP_EDONKEYPROT, OP_QUEUERANK) => {
                    let rank = decode_edonkey_queue_rank_payload(&packet.payload)?;
                    session_state.queued_until = Some(tokio::time::Instant::now() + QUEUE_RANK_GRACE);
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "queue_ranking",
                        format!("file_hash={file_hash_hex} rank={rank} protocol=edonkey"),
                    );
                }
                (OP_EMULEPROT, OP_QUEUERANKING) => {
                    let rank = decode_emule_queue_ranking_payload(&packet.payload)?;
                    session_state.queued_until = Some(tokio::time::Instant::now() + QUEUE_RANK_GRACE);
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "queue_ranking",
                        format!("file_hash={file_hash_hex} rank={rank} protocol=emule"),
                    );
                }
                (OP_EDONKEYPROT, OP_END_OF_DOWNLOAD) => {
                    let ended_hash = decode_optional_file_hash_payload(&packet.payload);
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "end_of_download",
                        format!(
                            "file_hash={} payload_len={}",
                            ended_hash.map_or_else(|| "none".to_string(), |hash| hash.to_string()),
                            packet.payload.len()
                        ),
                    );
                    if ended_hash == Some(file_hash) {
                        return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                    }
                }
                (OP_EDONKEYPROT, OP_OUTOFPARTREQS) => {
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "out_of_part_requests",
                        format!("file_hash={file_hash_hex}"),
                    );
                    diag_bad_peer::download_out_of_part_reqs(
                        &peer_addr.to_string(),
                        session_state.peer_user_hash,
                        file_hash_hex,
                    );
                    // No Needed Parts (eMuleBB DS_NONEEDEDPARTS): the driver may swap
                    // this source to another wanted file it serves (A4AF-lite
                    // SwapToAnotherFile) rather than drop it.
                    return Ok(Ed2kPeerDownloadOutcome::NoNeededParts);
                }
                (OP_EDONKEYPROT, OP_CHANGE_CLIENT_ID) => {
                    let change = decode_client_id_change_payload(&packet.payload)?;
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "change_client_id",
                        format!(
                            "new_user_id={} new_server_ip={} trailing_len={}",
                            change.new_user_id, change.new_server_ip, change.trailing_len
                        ),
                    );
                }
                (OP_EDONKEYPROT, OP_CHANGE_SLOT) => {
                    let changed_file = decode_optional_file_hash_payload(&packet.payload);
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "change_slot",
                        format!(
                            "file_hash={} payload_len={}",
                            changed_file
                                .map_or_else(|| "none".to_string(), |hash| hash.to_string()),
                            packet.payload.len()
                        ),
                    );
                }
                (OP_EDONKEYPROT, OP_MESSAGE) => {
                    let message = decode_client_message_payload(&packet.payload)?;
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "client_message",
                        format!(
                            "message_len={} accepted_len={}",
                            message.message_len, message.accepted_len
                        ),
                    );
                }
                (OP_EDONKEYPROT, OP_ASKSHAREDFILES) => {
                    browse::handle_ask_shared_files(transport, peer_addr, packet.payload.len())
                        .await?;
                }
                (OP_EDONKEYPROT, OP_ASKSHAREDDIRS) => {
                    browse::handle_ask_shared_dirs(transport, peer_addr, packet.payload.len())
                        .await?;
                }
                (OP_EDONKEYPROT, OP_ASKSHAREDFILESDIR) => {
                    browse::handle_ask_shared_files_dir(transport, peer_addr, &packet.payload)
                        .await?;
                }
                (OP_EDONKEYPROT, OP_ASKSHAREDFILESANSWER) => {
                    browse::handle_ask_shared_files_answer(transport, peer_addr, &packet.payload)?;
                }
                (OP_EDONKEYPROT, OP_ASKSHAREDDIRSANS) => {
                    browse::handle_ask_shared_dirs_answer(transport, peer_addr, &packet.payload)?;
                }
                (OP_EDONKEYPROT, OP_ASKSHAREDFILESDIRANS) => {
                    browse::handle_ask_shared_files_dir_answer(
                        transport,
                        peer_addr,
                        &packet.payload,
                    )?;
                }
                (OP_EDONKEYPROT, OP_ASKSHAREDDENIEDANS) => {
                    browse::handle_ask_shared_denied_answer(
                        transport,
                        peer_addr,
                        packet.payload.len(),
                    );
                }
                (OP_EMULEPROT, OP_FILEDESC) => {
                    notify::handle_file_desc(transport, peer_addr, file_hash_hex, &packet.payload)?;
                }
                (OP_EMULEPROT, OP_REQUESTPREVIEW) => {
                    notify::handle_preview_request(transport, peer_addr, &packet.payload)?;
                }
                (OP_EMULEPROT, OP_PREVIEWANSWER) => {
                    notify::handle_preview_answer(transport, peer_addr, &packet.payload)?;
                }
                (OP_EMULEPROT, OP_AICHREQUEST) => {
                    let request = decode_aich_recovery_request_payload(&packet.payload)?;
                    dump_ed2k_tcp_download_meta(
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
                        .create_aich_recovery_data(
                            &request.file_hash,
                            request.part,
                            request.master_hash,
                        )
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
                    dump_ed2k_tcp_download_send(peer_addr, transport.mode, dump_tag, &reply);
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send OP_AICHANSWER to {peer_addr}")
                    })?;
                }
                (OP_EMULEPROT, OP_AICHANSWER) => {
                    let answer = decode_aich_recovery_answer_payload(&packet.payload)?;
                    dump_ed2k_tcp_download_meta(
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
                    // Clear the in-flight marker so this part can be re-requested
                    // later if the salvage still leaves it corrupt.
                    if let Some(answered_part) = answer.part {
                        session_state
                            .aich_requests_inflight
                            .retain(|part| *part != answered_part);
                    }
                    handle_aich_recovery_answer(
                        transfer_runtime,
                        file_hash_hex,
                        &answer,
                        &packet.payload,
                        peer_addr,
                        transport.mode,
                    )
                    .await?;
                }
                (OP_EDONKEYPROT, OP_FILEREQANSNOFIL) => {
                    let missing_hash =
                        decode_exact_file_hash_payload(&packet.payload, "OP_FILEREQANSNOFIL")?;
                    if missing_hash != file_hash {
                        anyhow::bail!(
                            "peer {peer_addr} returned OP_FILEREQANSNOFIL for unexpected file {}",
                            missing_hash
                        );
                    }
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "file_req_ans_nofil",
                        format!("file_hash={file_hash_hex}"),
                    );
                    return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                }
                (OP_EDONKEYPROT, OP_SENDINGPART)
                | (OP_EMULEPROT, OP_SENDINGPART_I64)
                | (OP_EMULEPROT, OP_COMPRESSEDPART)
                | (OP_EMULEPROT, OP_COMPRESSEDPART_I64) => {
                    if let Some(outcome) = handle_download_part_packet(DownloadPartPacket {
                            transfer_runtime,
                            file_hash: &file_hash,
                            file_hash_hex,
                            pending_part_requests: &mut pending_part_requests,
                            pending_compressed_parts: &mut pending_compressed_parts,
                            manifest: &mut manifest,
                            session_state: &mut session_state,
                            peer_addr,
                            transport_mode: transport.mode,
                            packet: &packet,
                        })
                        .await?
                    {
                        return Ok(outcome);
                    }
                }
                _ => {}
            }

            // A part that just failed MD4 verification needs AICH/ICH recovery
            // (master CPartFile::HashSinglePart failure -> RequestAICHRecovery).
            // Solicit recovery from this peer when it supports AICH and we hold
            // a trusted AICH root, so only the corrupt blocks are re-downloaded.
            pump_aich_recovery_requests(
                transport,
                peer_addr,
                &file_hash,
                file_hash_hex,
                &manifest,
                AichRecoveryRequestState {
                    pending: &mut session_state.pending_aich_recovery_parts,
                    inflight: &mut session_state.aich_requests_inflight,
                    peer_part_bitmap: session_state.peer_part_bitmap.as_deref(),
                    remote_supports_aich: session_state.remote_supports_aich,
                },
            )
            .await?;
        }
    }
    .await;

    if matches!(
        &session_result,
        Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete)
    ) {
        // The session is ending; any part that fails MD4 here cannot be
        // recovered over this connection, so the recovery queue is discarded.
        let mut teardown_recovery_parts = Vec::new();
        let teardown_peer_user_hash = session_state.peer_user_hash;
        let teardown_peer_connect_options = session_state.peer_connect_options;
        let teardown_credit_user_hash = session_state.verified_credit_user_hash();
        flush_buffered_download_prefixes(
            transfer_runtime,
            file_hash_hex,
            &mut pending_part_requests,
            &mut session_state.active_piece_request,
            &mut manifest,
            peer_addr,
            transport.mode,
            teardown_peer_user_hash,
            teardown_peer_connect_options,
            teardown_credit_user_hash,
            &mut teardown_recovery_parts,
        )
        .await?;
    }

    if let Some(active_piece) = session_state.active_piece_request.or_else(|| {
        pending_part_requests
            .first()
            .map(|request| ActiveDownloadPiece {
                piece_index: request.piece_index,
                next_offset: request.end,
                piece_end: request.end,
            })
    }) {
        transfer_runtime
            .release_piece_request(file_hash_hex, active_piece.piece_index)
            .await?;
    }

    session_result
}

async fn remember_source_exchange_sources(
    transfer_runtime: &Ed2kTransferRuntime,
    expected_hash: Ed2kHash,
    file_hash_hex: &str,
    answer_hash: Ed2kHash,
    sources: Vec<SourceExchangePeer>,
) -> Result<()> {
    if answer_hash != expected_hash {
        return Ok(());
    }

    transfer_runtime
        .note_source_exchange_answer(file_hash_hex, std::time::Instant::now())
        .await;

    for source in sources {
        if source.tcp_port == 0 || source.ip == [0, 0, 0, 0] {
            continue;
        }
        transfer_runtime
            .remember_source(
                file_hash_hex,
                Ed2kSourceHint {
                    ip: Ipv4Addr::from(source.ip).to_string(),
                    tcp_port: source.tcp_port,
                    user_hash: source.user_hash.map(hex::encode),
                },
            )
            .await?;
    }

    Ok(())
}

/// Records a peer's advertised per-part availability into the live download
/// source registry. An empty `availability` (OP_FILESTATUS part_count 0) means
/// the peer holds the complete file, mapped to an all-available bitmap.
/// Returns the resolved bitmap so the caller can also gate part picking on the
/// connected peer's availability for this session.
fn record_source_part_availability(
    transfer_runtime: &Ed2kTransferRuntime,
    file_hash_hex: &str,
    peer_addr: SocketAddr,
    peer_user_hash: Option<[u8; 16]>,
    peer_connect_options: Option<u8>,
    availability: Vec<bool>,
    manifest_part_count: usize,
) -> Vec<bool> {
    let bitmap = if availability.is_empty() {
        vec![true; manifest_part_count]
    } else {
        availability
    };
    transfer_runtime.note_download_source_part_bitmap(
        file_hash_hex,
        peer_addr,
        peer_user_hash,
        peer_connect_options,
        bitmap.clone(),
    );
    bitmap
}

/// Whether the connected peer advertises at least one part we still need.
///
/// A part is "needed" while it is not yet `Verified` (Missing/Requested/Written).
/// The peer holds nothing needed when, for every part it advertises, our copy is
/// already complete-and-verified. This mirrors the master `ProcessFileStatus`
/// `IsPartAvailable` scan (`DownloadClient.cpp` `ProcessFileStatus`): if the peer
/// offers no part we still want, the source is `DS_NONEEDEDPARTS`.
///
/// Note: this must only be consulted when the manifest is *not* complete (the
/// downloader loop returns `Completed` before reaching the session body when the
/// whole file is verified), so a `false` here is a genuine No-Needed-Parts
/// source, never a finished download.
#[must_use]
fn peer_holds_needed_part(manifest: &Ed2kResumeManifest, peer_bitmap: &[bool]) -> bool {
    manifest.pieces.iter().enumerate().any(|(position, piece)| {
        piece.state != Ed2kTransferState::Verified
            && peer_bitmap.get(position).copied().unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::{Ed2kResumeManifest, Ed2kTransferState, peer_holds_needed_part};
    use crate::ed2k_transfer::{Ed2kPieceState, Ed2kTransferJob};

    fn manifest_with_states(states: &[Ed2kTransferState]) -> Ed2kResumeManifest {
        let job = Ed2kTransferJob {
            file_hash: "0".repeat(32),
            canonical_name: "sample.bin".to_string(),
            file_size: u64::try_from(states.len()).unwrap_or(0) * 9_728_000,
            piece_size: 9_728_000,
        };
        let mut manifest = Ed2kResumeManifest::new(&job);
        manifest.pieces = states
            .iter()
            .enumerate()
            .map(|(index, state)| Ed2kPieceState {
                piece_index: u32::try_from(index).unwrap_or(0),
                state: *state,
                bytes_written: 0,
                block_bitmap: None,
            })
            .collect();
        manifest
    }

    #[test]
    fn peer_offering_only_already_verified_parts_is_no_needed_parts() {
        let manifest =
            manifest_with_states(&[Ed2kTransferState::Verified, Ed2kTransferState::Missing]);
        let peer_bitmap = [true, false];
        assert!(!peer_holds_needed_part(&manifest, &peer_bitmap));
    }

    #[test]
    fn peer_offering_a_part_we_still_need_is_not_no_needed_parts() {
        let manifest =
            manifest_with_states(&[Ed2kTransferState::Verified, Ed2kTransferState::Missing]);
        let peer_bitmap = [true, true];
        assert!(peer_holds_needed_part(&manifest, &peer_bitmap));
    }

    #[test]
    fn requested_part_still_counts_as_needed() {
        let manifest =
            manifest_with_states(&[Ed2kTransferState::Verified, Ed2kTransferState::Requested]);
        let peer_bitmap = [false, true];
        assert!(peer_holds_needed_part(&manifest, &peer_bitmap));
    }

    #[test]
    fn shorter_peer_bitmap_treats_absent_slots_as_unavailable() {
        let manifest =
            manifest_with_states(&[Ed2kTransferState::Verified, Ed2kTransferState::Missing]);
        let peer_bitmap = [true];
        assert!(!peer_holds_needed_part(&manifest, &peer_bitmap));
    }
}
