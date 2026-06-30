use std::{net::SocketAddr, time::Instant};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

#[cfg(feature = "packet-diagnostics")]
use crate::ed2k_transfer::diag_sched;
use crate::{
    ed2k_tcp::{Ed2kTransport, OP_REQUESTPARTS_I64},
    ed2k_transfer::{
        ED2K_EMBLOCK_SIZE, Ed2kTransferRuntime, Ed2kUploadPeerIdentity, Ed2kUploadRangeAdmission,
    },
};

use super::{
    super::super::codec::{
        build_upload_part_packets, decode_request_parts_payload, encode_file_req_ans_nofil,
    },
    super::super::dump::dump_ed2k_tcp_listener_send,
    upload_queue::{ListenerQueueDecision, ListenerUploadQueue},
};

const MAX_UPLOAD_REQUEST_RANGE_BYTES: u64 = ED2K_EMBLOCK_SIZE * 3;

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

#[derive(Default)]
struct UploadRequestDiag {
    requested_ranges: usize,
    served_ranges: usize,
    skipped_ranges: usize,
    requested_bytes: u64,
    served_bytes: u64,
    sent_payload_bytes: u64,
    payload_packets: usize,
    throttle_delay_ms: u64,
    verified_reader_open_ms: u64,
    payload_read_ms: u64,
    first_skip_reason: Option<&'static str>,
}

impl UploadRequestDiag {
    fn from_ranges(ranges: &[(u64, u64)]) -> Self {
        Self {
            requested_ranges: ranges.len(),
            requested_bytes: ranges
                .iter()
                .map(|(start, end)| end.saturating_sub(*start))
                .sum(),
            ..Self::default()
        }
    }

    fn note_skip(&mut self, reason: &'static str) {
        self.skipped_ranges += 1;
        self.first_skip_reason.get_or_insert(reason);
    }
}

fn emit_upload_request_outcome(
    peer_upload_identity: &Ed2kUploadPeerIdentity,
    requested: &Ed2kHash,
    outcome: &str,
    diag: &UploadRequestDiag,
) {
    #[cfg(not(feature = "packet-diagnostics"))]
    {
        let _ = (peer_upload_identity, requested, outcome, diag);
    }
    #[cfg(feature = "packet-diagnostics")]
    {
        let peer = diag_sched::peer_label(peer_upload_identity.ip, peer_upload_identity.tcp_port);
        let file_hash = requested.to_string();
        diag_sched::upload_request_outcome(
            &peer,
            peer_upload_identity.user_hash,
            &file_hash,
            outcome,
            diag.requested_ranges,
            diag.served_ranges,
            diag.skipped_ranges,
            diag.requested_bytes,
            diag.served_bytes,
            diag.payload_packets,
            diag.throttle_delay_ms,
            diag.verified_reader_open_ms,
            diag.payload_read_ms,
            diag.first_skip_reason,
        );
    }
}

fn emit_upload_payload_accounting(
    peer_upload_identity: &Ed2kUploadPeerIdentity,
    requested: &Ed2kHash,
    shared_complete: bool,
    diag: &UploadRequestDiag,
) {
    #[cfg(not(feature = "packet-diagnostics"))]
    {
        let _ = (peer_upload_identity, requested, shared_complete, diag);
    }
    #[cfg(feature = "packet-diagnostics")]
    {
        if diag.served_bytes == 0 {
            return;
        }
        let peer = diag_sched::peer_label(peer_upload_identity.ip, peer_upload_identity.tcp_port);
        let file_hash = requested.to_string();
        let complete_bytes = if shared_complete {
            diag.served_bytes
        } else {
            0
        };
        let part_file_bytes = if shared_complete {
            0
        } else {
            diag.served_bytes
        };
        diag_sched::upload_payload_accounting(
            &peer,
            peer_upload_identity.user_hash,
            &file_hash,
            diag.served_bytes,
            diag.sent_payload_bytes,
            complete_bytes,
            part_file_bytes,
        );
    }
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
    let mut request_diag = UploadRequestDiag::from_ranges(&ranges);
    transfer_runtime.note_file_upload_request(&requested).await;
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
        request_diag.note_skip("noServableEntry");
        emit_upload_request_outcome(
            &peer_upload_identity,
            &requested,
            "noServableEntry",
            &request_diag,
        );
        return Ok(UploadPayloadOutcome::Continue { requested });
    };

    let queue_decision = upload_queue
        .ensure_session_for_parts(
            transfer_runtime,
            peer_upload_identity.clone(),
            &requested,
            transport,
            peer_addr,
        )
        .await?;
    match queue_decision {
        ListenerQueueDecision::Granted => {}
        ListenerQueueDecision::Waiting => {
            let outcome = "queueWaitingBeforeRequest";
            request_diag.note_skip(outcome);
            emit_upload_request_outcome(&peer_upload_identity, &requested, outcome, &request_diag);
            return Ok(UploadPayloadOutcome::Continue { requested });
        }
        ListenerQueueDecision::Stale => {
            let outcome = "queueStaleBeforeRequest";
            request_diag.note_skip(outcome);
            emit_upload_request_outcome(&peer_upload_identity, &requested, outcome, &request_diag);
            return Ok(UploadPayloadOutcome::Continue { requested });
        }
    }
    match upload_queue
        .note_request_parts(transfer_runtime, transport, peer_addr)
        .await?
    {
        ListenerQueueDecision::Granted => {}
        ListenerQueueDecision::Waiting => {
            let outcome = "queueWaitingAfterRequest";
            request_diag.note_skip(outcome);
            emit_upload_request_outcome(&peer_upload_identity, &requested, outcome, &request_diag);
            return Ok(UploadPayloadOutcome::Continue { requested });
        }
        ListenerQueueDecision::Stale => {
            let outcome = "queueStaleAfterRequest";
            request_diag.note_skip(outcome);
            emit_upload_request_outcome(&peer_upload_identity, &requested, outcome, &request_diag);
            return Ok(UploadPayloadOutcome::Close);
        }
    }
    transfer_runtime.note_file_upload_accept(&requested).await;
    let verified_reader_open_start = Instant::now();
    let Some(mut verified_reader) = transfer_runtime
        .open_verified_range_reader(&requested)
        .await?
    else {
        request_diag.note_skip("noVerifiedReader");
        emit_upload_request_outcome(
            &peer_upload_identity,
            &requested,
            "noPayload",
            &request_diag,
        );
        return Ok(UploadPayloadOutcome::Continue { requested });
    };
    request_diag.verified_reader_open_ms =
        u64::try_from(verified_reader_open_start.elapsed().as_millis()).unwrap_or(u64::MAX);

    for (start, end) in ranges {
        // FIX (memory-amplification DoS): never read or buffer a whole
        // peer-requested range at once. The range size is peer-controlled and
        // uncapped (a complete file is one verified `[0, file_size]` span, so a
        // peer can request the entire file in a single range), and the old path
        // allocated `vec![0u8; end - start]` per range — a multi-GB resident
        // spike per packet, repeatable across connections. eMule serves through
        // the disk-IO thread in EMBLOCKSIZE (184_320) chunks and a conforming
        // downloader never requests more than one EMBLOCKSIZE per range, so we
        // walk the range in EMBLOCKSIZE fragments: the per-read allocation is
        // bounded to one block regardless of the requested span, and a
        // legitimate <=EMBLOCKSIZE request is served in a single fragment
        // (exactly the bytes asked for).
        if end <= start {
            request_diag.note_skip("emptyRange");
            continue;
        }
        if end.saturating_sub(start) > MAX_UPLOAD_REQUEST_RANGE_BYTES {
            request_diag.note_skip("rangeTooLarge");
            continue;
        }
        match upload_queue
            .note_range_request(transfer_runtime, start, end)
            .await
        {
            (ListenerQueueDecision::Granted, Ed2kUploadRangeAdmission::Accepted) => {}
            (ListenerQueueDecision::Granted, Ed2kUploadRangeAdmission::DuplicateDone) => {
                request_diag.note_skip("duplicateDone");
                continue;
            }
            (ListenerQueueDecision::Waiting, _) => {
                request_diag.note_skip("queueWaitingBeforeRange");
                continue;
            }
            (ListenerQueueDecision::Stale, _) => {
                request_diag.note_skip("queueStaleBeforeRange");
                break;
            }
        }
        let mut fragment_start = start;
        let mut range_served = false;
        while fragment_start < end {
            let fragment_end = fragment_start.saturating_add(ED2K_EMBLOCK_SIZE).min(end);
            let payload_read_start = Instant::now();
            let read_result = verified_reader
                .read_range(fragment_start, fragment_end)
                .await?;
            request_diag.payload_read_ms = request_diag.payload_read_ms.saturating_add(
                u64::try_from(payload_read_start.elapsed().as_millis()).unwrap_or(u64::MAX),
            );
            let Some(bytes) = read_result else {
                // A fragment that is not (fully) verified ends serving of this
                // range; the master likewise serves only complete parts.
                request_diag.note_skip("unverifiedRange");
                break;
            };
            let fragment_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            let replies = build_upload_part_packets(
                &requested,
                &shared.canonical_name,
                fragment_start,
                fragment_end,
                &bytes,
                is_i64,
            )?;
            request_diag.payload_packets += replies.len();
            for reply in replies {
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, reply.phase, &reply.packet);
                let packet_len = u64::try_from(reply.packet.len()).unwrap_or(u64::MAX);
                request_diag.sent_payload_bytes =
                    request_diag.sent_payload_bytes.saturating_add(packet_len);
                let reservation = transfer_runtime
                    .reserve_upload_payload_budget(packet_len)
                    .await;
                if !reservation.delay.is_zero() {
                    let delay_ms = u64::try_from(reservation.delay.as_millis()).unwrap_or(u64::MAX);
                    request_diag.throttle_delay_ms =
                        request_diag.throttle_delay_ms.saturating_add(delay_ms);
                    tokio::time::sleep(reservation.delay).await;
                }
                transport.write_all(&reply.packet).await.with_context(|| {
                    format!("failed to send ED2K upload payload to {peer_addr}")
                })?;
            }
            request_diag.served_bytes = request_diag.served_bytes.saturating_add(fragment_bytes);
            range_served = true;
            if let Some(user_hash) = peer_user_hash {
                transfer_runtime.add_peer_credit_delta(user_hash, fragment_bytes, 0)?;
            }
            // Credit the served file's lifetime-uploaded counter so its all-time
            // upload ratio (eMule CKnownFile::GetAllTimeUploadRatio) reflects
            // served bytes, feeding the upload-queue low-ratio score bonus.
            transfer_runtime.add_file_all_time_uploaded(&requested, fragment_bytes)?;
            // FIX (slot-recycle window): refresh activity per fragment, not only
            // per completed range. A large range fragmented over a slow link can
            // otherwise exceed `upload_timeout` between activity touches and let
            // another task's `reap_expired_sessions` recycle the active slot
            // mid-serve. `note_payload_sent` refreshes `last_activity` and adds
            // exactly the bytes just sent, so accounting stays correct (each
            // fragment is counted once).
            upload_queue
                .note_payload_sent(transfer_runtime, fragment_bytes)
                .await;
            fragment_start = fragment_end;
        }
        if range_served {
            request_diag.served_ranges += 1;
        }
        if range_served && fragment_start >= end {
            let _ = upload_queue
                .note_range_served(transfer_runtime, start, end)
                .await;
        }
    }

    let outcome = if request_diag.served_bytes == 0 {
        if request_diag.first_skip_reason == Some("duplicateDone") {
            "duplicateDone"
        } else {
            "noPayload"
        }
    } else if request_diag.served_bytes >= request_diag.requested_bytes
        && request_diag.skipped_ranges == 0
    {
        "served"
    } else {
        "partial"
    };
    emit_upload_request_outcome(&peer_upload_identity, &requested, outcome, &request_diag);
    emit_upload_payload_accounting(
        &peer_upload_identity,
        &requested,
        shared.verified_complete,
        &request_diag,
    );

    Ok(UploadPayloadOutcome::Continue { requested })
}
