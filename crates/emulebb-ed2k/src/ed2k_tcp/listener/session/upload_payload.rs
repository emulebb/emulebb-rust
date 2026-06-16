use std::net::SocketAddr;

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_tcp::{Ed2kTransport, OP_REQUESTPARTS_I64},
    ed2k_transfer::{Ed2kTransferRuntime, Ed2kUploadPeerIdentity},
};

use super::{
    super::super::codec::{
        build_upload_part_packets, decode_request_parts_payload, encode_file_req_ans_nofil,
    },
    super::super::dump::dump_ed2k_tcp_listener_send,
    upload_queue::{ListenerQueueDecision, ListenerUploadQueue},
};

pub(in crate::ed2k_tcp) struct UploadPayloadRequest<'a> {
    pub(in crate::ed2k_tcp) transfer_runtime: &'a Ed2kTransferRuntime,
    pub(in crate::ed2k_tcp) upload_queue: &'a mut ListenerUploadQueue,
    pub(in crate::ed2k_tcp) peer_upload_identity: Ed2kUploadPeerIdentity,
    /// Whether the peer's secure-ident signature was RSA-verified
    /// (`CClientCreditsList::VerifyIdent` -> `IS_IDENTIFIED`). Credits are
    /// attributed to the peer's user hash only when this is true, so an
    /// unverified peer cannot spoof another client's credit-store identity.
    pub(in crate::ed2k_tcp) peer_ident_verified: bool,
    pub(in crate::ed2k_tcp) transport: &'a mut Ed2kTransport,
    pub(in crate::ed2k_tcp) peer_addr: SocketAddr,
    pub(in crate::ed2k_tcp) opcode: u8,
    pub(in crate::ed2k_tcp) payload: &'a [u8],
}

pub(in crate::ed2k_tcp) enum UploadPayloadOutcome {
    Continue { requested: Ed2kHash },
    Close,
}

pub(in crate::ed2k_tcp) async fn serve_upload_payload(
    request: UploadPayloadRequest<'_>,
) -> Result<UploadPayloadOutcome> {
    let UploadPayloadRequest {
        transfer_runtime,
        upload_queue,
        peer_upload_identity,
        peer_ident_verified,
        transport,
        peer_addr,
        opcode,
        payload,
    } = request;
    let is_i64 = opcode == OP_REQUESTPARTS_I64;
    let (requested, ranges) = decode_request_parts_payload(payload, is_i64)?;
    // Only a cryptographically verified peer may be credited: the credit store is
    // keyed on the user hash and feeds the upload score, so an unverified hash is
    // spoofable (eMule attributes credits only in IS_IDENTIFIED).
    let peer_user_hash = if peer_ident_verified {
        peer_upload_identity.user_hash
    } else {
        None
    };
    // Serve a fully verified file or an in-progress partfile holding at least one
    // complete part; a range inside a not-yet-complete part is skipped below by
    // read_verified_range returning None (master serves only complete parts).
    let Some(shared) = transfer_runtime.local_servable_entry(&requested).await? else {
        let reply = encode_file_req_ans_nofil(&requested);
        dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "request_parts_nofil", &reply);
        transport
            .write_all(&reply)
            .await
            .with_context(|| format!("failed to send OP_FILEREQANSNOFIL to {peer_addr}"))?;
        return Ok(UploadPayloadOutcome::Continue { requested });
    };

    match upload_queue
        .ensure_session_for_parts(
            transfer_runtime,
            peer_upload_identity,
            &requested,
            transport,
            peer_addr,
        )
        .await?
    {
        ListenerQueueDecision::Granted => {}
        ListenerQueueDecision::Waiting | ListenerQueueDecision::Stale => {
            return Ok(UploadPayloadOutcome::Continue { requested });
        }
    }
    match upload_queue
        .note_request_parts(transfer_runtime, transport, peer_addr)
        .await?
    {
        ListenerQueueDecision::Granted => {}
        ListenerQueueDecision::Waiting => return Ok(UploadPayloadOutcome::Continue { requested }),
        ListenerQueueDecision::Stale => return Ok(UploadPayloadOutcome::Close),
    }

    for (start, end) in ranges {
        let Some(bytes) = transfer_runtime
            .read_verified_range(&requested, start, end)
            .await?
        else {
            continue;
        };
        for reply in build_upload_part_packets(
            &requested,
            &shared.canonical_name,
            start,
            end,
            &bytes,
            is_i64,
        )? {
            dump_ed2k_tcp_listener_send(peer_addr, transport.mode, reply.phase, &reply.packet);
            let reservation = transfer_runtime
                .reserve_upload_payload_budget(
                    u64::try_from(reply.packet.len()).unwrap_or(u64::MAX),
                )
                .await;
            if !reservation.delay.is_zero() {
                tokio::time::sleep(reservation.delay).await;
            }
            transport
                .write_all(&reply.packet)
                .await
                .with_context(|| format!("failed to send ED2K upload payload to {peer_addr}"))?;
        }
        if let Some(user_hash) = peer_user_hash {
            transfer_runtime.add_peer_credit_delta(
                user_hash,
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                0,
            )?;
        }
        // Credit the served file's lifetime-uploaded counter so its all-time
        // upload ratio (eMule CKnownFile::GetAllTimeUploadRatio) reflects served
        // bytes, feeding the upload-queue low-ratio score bonus.
        transfer_runtime
            .add_file_all_time_uploaded(&requested, u64::try_from(bytes.len()).unwrap_or(u64::MAX))?;
        upload_queue
            .note_payload_sent(
                transfer_runtime,
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            )
            .await;
    }

    Ok(UploadPayloadOutcome::Continue { requested })
}
