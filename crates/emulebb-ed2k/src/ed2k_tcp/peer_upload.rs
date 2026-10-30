use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use tokio::sync::{Mutex, RwLock};

use crate::{
    ed2k_server::Ed2kServerState,
    ed2k_string::Ed2kStringEncoding,
    ed2k_transfer::{Ed2kTransferRuntime, Ed2kUploadPeerIdentity},
    kad_firewall::KadFirewallState,
};

use super::{
    Ed2kPeerDispatcher, EmuleTcpPacket, OP_AICHFILEHASHREQ, OP_CANCELTRANSFER, OP_EDONKEYPROT,
    OP_EMULEPROT, OP_END_OF_DOWNLOAD, OP_HASHSETREQUEST, OP_HASHSETREQUEST2, OP_MULTIPACKET,
    OP_MULTIPACKET_EXT, OP_MULTIPACKET_EXT2, OP_REQUESTFILENAME, OP_REQUESTPARTS,
    OP_REQUESTPARTS_I64, OP_REQUESTSOURCES, OP_REQUESTSOURCES2, OP_SETREQFILEID, OP_STARTUPLOADREQ,
    decode_exact_file_hash_payload, decode_optional_file_hash_payload,
    dump::dump_ed2k_tcp_listener_meta,
    hello::{DecodedEmuleInfoProfile, DecodedHelloProfile},
    listener::session::{
        PeerHelloStateRefs, apply_peer_hello_profile,
        shared_file::{
            RequesterFileState, SourceExchangeResponseThrottle, handle_aich_file_hash_request,
            handle_hashset_request, handle_hashset_request2, handle_multipacket_ext2_request,
            handle_multipacket_request, handle_request_filename, handle_set_req_file_id,
            handle_source_request,
        },
        upload_firewall_context,
        upload_payload::{UploadPayloadOutcome, UploadPayloadRequest, serve_upload_payload},
        upload_peer_identity_from_socket,
        upload_queue::{ListenerQueuePoll, ListenerUploadQueue},
    },
};

/// Live server/Kad posture needed for stock LowID upload admission.
#[derive(Clone)]
pub struct Ed2kPeerUploadContext {
    pub server_state: Arc<RwLock<Ed2kServerState>>,
    pub kad_firewall: Arc<Mutex<KadFirewallState>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ed2k_tcp) enum PeerUploadDispatch {
    Unhandled,
    Handled,
    /// The upload facet consumed the frame, but the download facet must also
    /// observe it because `OP_END_OF_DOWNLOAD` is role-ambiguous on a duplex
    /// connection.
    ContinueDispatch,
    ClosePeer,
}

/// Upload-side state attached to one physical peer connection.
///
/// This state is intentionally independent from connection direction. The
/// dispatcher remains the sole socket owner, while this facet borrows it to
/// answer upload requests arriving on an outbound-established download socket.
pub(in crate::ed2k_tcp) struct PeerUploadFacet {
    requested_file_hash: Option<Ed2kHash>,
    requester_file_state: Option<RequesterFileState>,
    source_exchange_throttle: SourceExchangeResponseThrottle,
    peer_supports_aich: bool,
    peer_supports_secure_ident: bool,
    peer_supports_file_identifiers: bool,
    peer_supports_unicode: bool,
    peer_accept_comment_version: u8,
    peer_upload_identity: Ed2kUploadPeerIdentity,
    upload_queue: ListenerUploadQueue,
    failed_file_req_count: u32,
    bound_user_hash: Option<[u8; 16]>,
    last_packet_at: tokio::time::Instant,
}

impl PeerUploadFacet {
    pub(in crate::ed2k_tcp) fn new(peer_addr: SocketAddr, transport_is_obfuscated: bool) -> Self {
        let mut peer_upload_identity = upload_peer_identity_from_socket(peer_addr);
        peer_upload_identity.should_crypt = transport_is_obfuscated;
        Self {
            requested_file_hash: None,
            requester_file_state: None,
            source_exchange_throttle: SourceExchangeResponseThrottle::default(),
            peer_supports_aich: false,
            peer_supports_secure_ident: false,
            peer_supports_file_identifiers: false,
            peer_supports_unicode: false,
            peer_accept_comment_version: 0,
            peer_upload_identity,
            upload_queue: ListenerUploadQueue::new(),
            failed_file_req_count: 0,
            bound_user_hash: None,
            last_packet_at: tokio::time::Instant::now(),
        }
    }

    pub(in crate::ed2k_tcp) async fn bind_hello(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        peer_addr: SocketAddr,
        transport_is_obfuscated: bool,
        profile: &DecodedHelloProfile,
    ) -> bool {
        let accepted = apply_peer_hello_profile(
            PeerHelloStateRefs {
                bound_user_hash: &mut self.bound_user_hash,
                supports_aich: &mut self.peer_supports_aich,
                supports_secure_ident: &mut self.peer_supports_secure_ident,
                supports_file_identifiers: &mut self.peer_supports_file_identifiers,
                supports_unicode: &mut self.peer_supports_unicode,
                accept_comment_version: &mut self.peer_accept_comment_version,
                upload_identity: &mut self.peer_upload_identity,
            },
            transfer_runtime,
            peer_addr,
            transport_is_obfuscated,
            profile,
        );
        if accepted {
            let _ = self
                .upload_queue
                .refresh_peer_state(transfer_runtime, &self.peer_upload_identity)
                .await;
        }
        accepted
    }

    pub(in crate::ed2k_tcp) async fn apply_emule_info(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        profile: &DecodedEmuleInfoProfile,
    ) {
        self.peer_upload_identity.udp_version = profile.udp_version;
        if self.peer_upload_identity.udp_port.is_none() && profile.udp_port != 0 {
            self.peer_upload_identity.udp_port = Some(profile.udp_port);
        }
        self.peer_upload_identity.emule_version = profile.emule_version;
        self.peer_upload_identity.is_emule_client = true;
        self.peer_supports_secure_ident |= profile.supports_secure_ident;
        if profile.accepts_comments && self.peer_accept_comment_version == 0 {
            self.peer_accept_comment_version = 1;
        }
        let _ = self
            .upload_queue
            .refresh_peer_state(transfer_runtime, &self.peer_upload_identity)
            .await;
    }

    pub(in crate::ed2k_tcp) fn read_timeout(&self) -> Option<Duration> {
        self.upload_queue
            .is_attached()
            .then(|| self.upload_queue.read_timeout())
    }

    pub(in crate::ed2k_tcp) fn note_packet(&mut self) {
        self.last_packet_at = tokio::time::Instant::now();
    }

    pub(in crate::ed2k_tcp) async fn poll_on_timeout(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        transport: &mut Ed2kPeerDispatcher,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        if !self.upload_queue.is_attached() {
            return Ok(());
        }
        if matches!(
            self.upload_queue
                .poll_on_timeout(
                    transfer_runtime,
                    transport,
                    peer_addr,
                    self.last_packet_at.elapsed(),
                )
                .await?,
            ListenerQueuePoll::Close
        ) {
            self.upload_queue.release(transfer_runtime).await;
            self.requested_file_hash = None;
        }
        Ok(())
    }

    pub(in crate::ed2k_tcp) async fn release(&mut self, transfer_runtime: &Ed2kTransferRuntime) {
        self.upload_queue.release(transfer_runtime).await;
        self.requested_file_hash = None;
    }

    pub(in crate::ed2k_tcp) async fn handle_packet(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        upload_context: Option<&Ed2kPeerUploadContext>,
        peer_ident_verified: bool,
        transport: &mut Ed2kPeerDispatcher,
        peer_addr: SocketAddr,
        packet: &EmuleTcpPacket,
    ) -> Result<PeerUploadDispatch> {
        let string_encoding = Ed2kStringEncoding::from_unicode_support(self.peer_supports_unicode);
        match (packet.protocol, packet.opcode) {
            (OP_EMULEPROT, OP_MULTIPACKET | OP_MULTIPACKET_EXT) => {
                self.requested_file_hash = handle_multipacket_request(
                    transfer_runtime,
                    transport,
                    peer_addr,
                    packet.opcode,
                    &packet.payload,
                    self.peer_supports_aich,
                    self.peer_supports_file_identifiers,
                    string_encoding,
                    &mut self.requester_file_state,
                    &mut self.source_exchange_throttle,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_MULTIPACKET_EXT2) => {
                self.requested_file_hash = handle_multipacket_ext2_request(
                    transfer_runtime,
                    transport,
                    peer_addr,
                    &packet.payload,
                    string_encoding,
                    &mut self.requester_file_state,
                    &mut self.source_exchange_throttle,
                )
                .await?;
            }
            (OP_EDONKEYPROT, OP_REQUESTFILENAME) => {
                self.requested_file_hash = handle_request_filename(
                    transfer_runtime,
                    transport,
                    peer_addr,
                    &packet.payload,
                    self.peer_accept_comment_version,
                    string_encoding,
                    &mut self.requester_file_state,
                )
                .await?;
            }
            (OP_EDONKEYPROT, OP_SETREQFILEID) => {
                self.requested_file_hash =
                    handle_set_req_file_id(transfer_runtime, transport, peer_addr, &packet.payload)
                        .await?;
            }
            (OP_EDONKEYPROT, OP_STARTUPLOADREQ) => {
                let requested =
                    decode_exact_file_hash_payload(&packet.payload, "OP_STARTUPLOADREQ")?;
                self.requested_file_hash = Some(requested);
                if transfer_runtime
                    .local_servable_entry(&requested)
                    .await?
                    .is_some()
                {
                    let peer_identity = self.peer_identity_for_admission(upload_context).await;
                    if let Some(reply) = self
                        .upload_queue
                        .start_upload_reply(transfer_runtime, peer_identity, &requested)
                        .await
                    {
                        transport
                            .write_all_diagnostic(
                                "native_download",
                                peer_addr,
                                "start_upload",
                                &reply,
                            )
                            .await
                            .with_context(|| {
                                format!("failed to send OP_STARTUPLOADREQ response to {peer_addr}")
                            })?;
                    }
                } else {
                    self.failed_file_req_count = self.failed_file_req_count.saturating_add(1);
                    dump_ed2k_tcp_listener_meta(
                        peer_addr,
                        Some(transport.mode),
                        "start_upload_unknown_file",
                        || {
                            format!(
                                "file_hash={requested} failed_file_req_count={}",
                                self.failed_file_req_count
                            )
                        },
                    );
                }
                if self.failed_file_req_count
                    >= crate::ed2k_transfer::diag_bad_peer::FAILED_FILE_REQ_FLOOD_THRESHOLD
                {
                    let ban_ip = match peer_addr {
                        SocketAddr::V4(v4) => Some(*v4.ip()),
                        SocketAddr::V6(_) => None,
                    };
                    transfer_runtime.ban_client(ban_ip, self.peer_upload_identity.user_hash);
                    crate::ed2k_transfer::diag_bad_peer::file_request_flood(
                        &peer_addr.to_string(),
                        self.peer_upload_identity.user_hash,
                        self.failed_file_req_count,
                    );
                    return Ok(PeerUploadDispatch::ClosePeer);
                }
            }
            (OP_EDONKEYPROT, OP_CANCELTRANSFER) => {
                self.upload_queue.note_close_reason("peer_cancelled");
                self.release(transfer_runtime).await;
            }
            (OP_EDONKEYPROT, OP_END_OF_DOWNLOAD) => {
                let ended_hash = decode_optional_file_hash_payload(&packet.payload);
                dump_ed2k_tcp_listener_meta(
                    peer_addr,
                    Some(transport.mode),
                    "end_of_download",
                    || {
                        format!(
                            "file_hash={} payload_len={}",
                            ended_hash.map_or_else(|| "none".to_string(), |hash| hash.to_string()),
                            packet.payload.len()
                        )
                    },
                );
                if self.upload_queue.slot_file_hash() == ended_hash {
                    self.upload_queue.note_close_reason("end_of_download");
                    self.release(transfer_runtime).await;
                }
                return Ok(PeerUploadDispatch::ContinueDispatch);
            }
            (OP_EDONKEYPROT, OP_HASHSETREQUEST) => {
                self.requested_file_hash =
                    handle_hashset_request(transfer_runtime, transport, peer_addr, &packet.payload)
                        .await?;
            }
            (OP_EMULEPROT, OP_HASHSETREQUEST2) => {
                self.requested_file_hash = handle_hashset_request2(
                    transfer_runtime,
                    transport,
                    peer_addr,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_REQUESTSOURCES | OP_REQUESTSOURCES2) => {
                self.requested_file_hash = handle_source_request(
                    transfer_runtime,
                    transport,
                    peer_addr,
                    packet.opcode,
                    &packet.payload,
                    self.requester_file_state.as_ref(),
                    &mut self.source_exchange_throttle,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_AICHFILEHASHREQ) => {
                self.requested_file_hash = handle_aich_file_hash_request(
                    transfer_runtime,
                    transport,
                    peer_addr,
                    &packet.payload,
                    self.peer_supports_aich,
                )
                .await?;
            }
            (OP_EDONKEYPROT, OP_REQUESTPARTS) | (OP_EMULEPROT, OP_REQUESTPARTS_I64) => {
                let peer_identity = self.peer_identity_for_admission(upload_context).await;
                match serve_upload_payload(UploadPayloadRequest {
                    transfer_runtime,
                    upload_queue: &mut self.upload_queue,
                    peer_upload_identity: peer_identity,
                    peer_ident_verified,
                    peer_supports_secure_ident: self.peer_supports_secure_ident,
                    transport,
                    peer_addr,
                    opcode: packet.opcode,
                    payload: &packet.payload,
                })
                .await?
                {
                    UploadPayloadOutcome::Continue { requested } => {
                        self.requested_file_hash = Some(requested);
                    }
                    UploadPayloadOutcome::Close => {
                        self.release(transfer_runtime).await;
                    }
                }
            }
            _ => return Ok(PeerUploadDispatch::Unhandled),
        }
        Ok(PeerUploadDispatch::Handled)
    }

    async fn peer_identity_for_admission(
        &self,
        upload_context: Option<&Ed2kPeerUploadContext>,
    ) -> Ed2kUploadPeerIdentity {
        let mut peer_identity = self.peer_upload_identity.clone();
        if let Some(context) = upload_context {
            peer_identity.firewall_context = upload_firewall_context(
                &context.server_state,
                &context.kad_firewall,
                peer_identity.server_endpoint,
            )
            .await;
        }
        peer_identity
    }
}
