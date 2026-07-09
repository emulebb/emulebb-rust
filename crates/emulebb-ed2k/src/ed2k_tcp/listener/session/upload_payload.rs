use std::{net::SocketAddr, time::Instant};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

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
    /// Whether the peer advertised secure-ident support in its hello
    /// (`hello_profile.supports_secure_ident`). A peer that does NOT support it
    /// is a legacy client (eMule IS_NOTAVAILABLE) and is still credited; a peer
    /// that DOES support it but has not verified yet is skipped. See
    /// [`credit_accrual_allowed`].
    pub(in crate::ed2k_tcp) peer_supports_secure_ident: bool,
    pub(in crate::ed2k_tcp) transport: &'a mut Ed2kTransport,
    pub(in crate::ed2k_tcp) peer_addr: SocketAddr,
    pub(in crate::ed2k_tcp) opcode: u8,
    pub(in crate::ed2k_tcp) payload: &'a [u8],
}

pub(in crate::ed2k_tcp) enum UploadPayloadOutcome {
    Continue { requested: Ed2kHash },
    Close,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum UploadRangePlan {
    Accepted,
    /// The peer re-requested a block already completed/served in its slot
    /// (queue `Ed2kUploadRangeAdmission::DuplicateDone`, MFC `m_DoneBlocks_keys`).
    DuplicateDone,
    /// The peer repeated a block already queued (pending) within THIS request
    /// batch (MFC `m_BlockRequests_keys`), the queued sibling of the done case.
    DuplicateQueued,
    Empty,
    QueueStale,
    QueueWaiting,
    TooLarge,
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
    read_cache_hits: usize,
    read_cache_misses: usize,
    read_disk_bytes: u64,
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
        diag.read_cache_hits,
        diag.read_cache_misses,
        diag.read_disk_bytes,
        diag.first_skip_reason,
    );
}

fn emit_upload_payload_accounting(
    peer_upload_identity: &Ed2kUploadPeerIdentity,
    requested: &Ed2kHash,
    shared_complete: bool,
    diag: &UploadRequestDiag,
) {
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

pub(in crate::ed2k_tcp) async fn serve_upload_payload(
    request: UploadPayloadRequest<'_>,
) -> Result<UploadPayloadOutcome> {
    let UploadPayloadRequest {
        transfer_runtime,
        upload_queue,
        peer_upload_identity,
        peer_ident_verified,
        peer_supports_secure_ident,
        transport,
        peer_addr,
        opcode,
        payload,
    } = request;
    let is_i64 = opcode == OP_REQUESTPARTS_I64;
    let (requested, ranges) = decode_request_parts_payload(payload, is_i64)?;
    let mut request_diag = UploadRequestDiag::from_ranges(&ranges);
    // MFC repeat_block_request parity: surface a peer re-requesting the exact same
    // block within the observation window. Observe-only -- the ranges are still
    // served below; this only emits the bad_peer diagnostic so rust/MFC bad-peer
    // traces line up. Empty (0,0) padding slots are skipped.
    for &(start, end) in &ranges {
        if end > start
            && let Some(repeat_count) = upload_queue.note_block_request(&requested, start, end)
        {
            crate::ed2k_transfer::diag_bad_peer::repeat_block_request(
                &peer_addr.to_string(),
                peer_upload_identity.user_hash,
                &hex::encode(requested.0),
                start,
                end,
                start / crate::ed2k_transfer::ED2K_PART_SIZE,
                repeat_count,
            );
        }
    }
    transfer_runtime.note_file_upload_request(&requested).await;
    // eMule credit-accrual gate (CClientCredits::AddUploaded, ClientCredits.cpp
    // :99-113): credit a verified peer (IS_IDENTIFIED) or a legacy peer with no
    // secure-ident support (IS_NOTAVAILABLE), but skip a crypto-capable peer
    // that has not verified yet -- the credit store is keyed on the user hash
    // and feeds the upload score, so such a hash is spoofable.
    let peer_user_hash = if crate::ed2k_tcp::credit_accrual_allowed(
        peer_ident_verified,
        peer_supports_secure_ident,
    ) {
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
            // RUST-PAR-021 GAP4: a cooled queued peer that sends a valid block
            // request proves renewed demand, which clears its retry/slow/no-request
            // upload cooldown once per window (oracle AddReqBlock ->
            // ClearUploadRetryCooldown, UploadClient.cpp:613-627). The servable
            // entry above establishes the file is known; a range with end > start
            // is the valid block request (bRequestRangeValid).
            if ranges.iter().any(|&(start, end)| end > start) {
                upload_queue
                    .note_queued_block_request(transfer_runtime, &peer_upload_identity)
                    .await;
            }
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
    let Some(mut verified_reader) = upload_queue
        .take_verified_reader(transfer_runtime, &requested)
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
    let reader_cache_hits_before = verified_reader.cache_hit_count();
    let reader_cache_misses_before = verified_reader.cache_miss_count();
    let reader_disk_bytes_before = verified_reader.disk_read_bytes();

    let mut range_plan = Vec::with_capacity(ranges.len());
    let mut accepted_ranges = Vec::with_capacity(ranges.len());
    for &(start, end) in &ranges {
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
            range_plan.push(UploadRangePlan::Empty);
            continue;
        }
        if end.saturating_sub(start) > MAX_UPLOAD_REQUEST_RANGE_BYTES {
            range_plan.push(UploadRangePlan::TooLarge);
            continue;
        }
        let plan = match upload_queue
            .note_range_request(transfer_runtime, start, end)
            .await
        {
            (ListenerQueueDecision::Granted, Ed2kUploadRangeAdmission::Accepted) => {
                if accepted_ranges
                    .iter()
                    .any(|&(accepted_start, accepted_end)| {
                        accepted_start == start && accepted_end == end
                    })
                {
                    UploadRangePlan::DuplicateQueued
                } else {
                    accepted_ranges.push((start, end));
                    UploadRangePlan::Accepted
                }
            }
            (ListenerQueueDecision::Granted, Ed2kUploadRangeAdmission::DuplicateDone) => {
                UploadRangePlan::DuplicateDone
            }
            (ListenerQueueDecision::Waiting, _) => UploadRangePlan::QueueWaiting,
            (ListenerQueueDecision::Stale, _) => UploadRangePlan::QueueStale,
        };
        range_plan.push(plan);
        if plan == UploadRangePlan::QueueStale {
            break;
        }
    }

    for (range_index, &(start, end)) in ranges.iter().enumerate() {
        match range_plan
            .get(range_index)
            .copied()
            .unwrap_or(UploadRangePlan::QueueStale)
        {
            UploadRangePlan::Accepted => {}
            UploadRangePlan::DuplicateDone => {
                request_diag.note_skip("duplicateDone");
                // MFC AddReqBlock reject-duplicate-done-block: the peer asked for
                // a block already completed in its slot; reject and surface the
                // bad_peer event (repeatCount from the process-global rejection
                // ledger, no `behavior` key — oracle conformance).
                crate::ed2k_transfer::diag_bad_peer::upload_duplicate_done_block_rejected(
                    &peer_addr.to_string(),
                    peer_upload_identity.user_hash,
                    &hex::encode(requested.0),
                    start,
                    end,
                    start / crate::ed2k_transfer::ED2K_PART_SIZE,
                );
                continue;
            }
            UploadRangePlan::DuplicateQueued => {
                request_diag.note_skip("duplicateQueued");
                // MFC AddReqBlock reject-duplicate-queued-block: the peer repeated
                // a block already queued in its slot within this request batch.
                crate::ed2k_transfer::diag_bad_peer::upload_duplicate_queued_block_rejected(
                    &peer_addr.to_string(),
                    peer_upload_identity.user_hash,
                    &hex::encode(requested.0),
                    start,
                    end,
                    start / crate::ed2k_transfer::ED2K_PART_SIZE,
                );
                continue;
            }
            UploadRangePlan::Empty => {
                request_diag.note_skip("emptyRange");
                continue;
            }
            UploadRangePlan::QueueStale => {
                request_diag.note_skip("queueStaleBeforeRange");
                break;
            }
            UploadRangePlan::QueueWaiting => {
                request_diag.note_skip("queueWaitingBeforeRange");
                continue;
            }
            UploadRangePlan::TooLarge => {
                request_diag.note_skip("rangeTooLarge");
                continue;
            }
        }
        let mut fragment_start = start;
        let mut range_served = false;
        while fragment_start < end {
            let fragment_end = fragment_start.saturating_add(ED2K_EMBLOCK_SIZE).min(end);
            let next_range_is_contiguous_accepted = ranges
                .get(range_index + 1)
                .zip(range_plan.get(range_index + 1))
                .is_some_and(|(&(next_start, _), plan)| {
                    *plan == UploadRangePlan::Accepted && next_start == fragment_end
                });
            let more_fragments_in_range = fragment_end < end;
            let read_ahead_bytes = if more_fragments_in_range || next_range_is_contiguous_accepted {
                MAX_UPLOAD_REQUEST_RANGE_BYTES
            } else {
                fragment_end.saturating_sub(fragment_start)
            };
            let payload_read_start = Instant::now();
            let read_result = verified_reader
                .read_range_with_read_ahead(fragment_start, fragment_end, read_ahead_bytes)
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
    request_diag.read_cache_hits = verified_reader
        .cache_hit_count()
        .saturating_sub(reader_cache_hits_before);
    request_diag.read_cache_misses = verified_reader
        .cache_miss_count()
        .saturating_sub(reader_cache_misses_before);
    request_diag.read_disk_bytes = verified_reader
        .disk_read_bytes()
        .saturating_sub(reader_disk_bytes_before);

    let outcome = if request_diag.served_bytes == 0 {
        match request_diag.first_skip_reason {
            Some("duplicateDone") => "duplicateDone",
            Some("duplicateQueued") => "duplicateQueued",
            _ => "noPayload",
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
    upload_queue.store_verified_reader(&requested, verified_reader);

    Ok(UploadPayloadOutcome::Continue { requested })
}
