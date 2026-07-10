//! OP_SENDINGPART / OP_COMPRESSEDPART receive path for the download session.
//!
//! Mirrors the oracle's tolerant `ProcessBlockPacket` (DownloadClient.cpp):
//! a stale / duplicate / out-of-order block payload is DROPPED and counted
//! (:1531-1553), never fatal on its own; only the 32-in-15s stale-packet guard
//! cancels the transfer (:2690-2712, constants :70-71). Duplicate payload that
//! only re-sends already-received bytes is consumed gracefully (:1421-1487),
//! and a zlib stream error ignores the remainder of that 180 K stream while
//! keeping the connection (:1300-1308, :1394-1411).

use std::net::SocketAddr;

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use flate2::Decompress;

use crate::{
    ed2k_tcp::{
        Ed2kTransport, Ed2kTransportMode, EmuleTcpPacket, OP_CANCELTRANSFER, OP_COMPRESSEDPART,
        OP_COMPRESSEDPART_I64, OP_EDONKEYPROT, OP_SENDINGPART_I64,
        decode_compressed_part_fragment, decode_sending_part_payload,
        dump_ed2k_tcp_download_meta, dump_ed2k_tcp_download_send, encode_packet,
        inflate_compressed_part_fragment,
    },
    ed2k_transfer::{Ed2kResumeManifest, Ed2kTransferRuntime, diag_bad_peer},
};

use super::{
    super::{
        PendingCompressedPart, PendingPartRequest, ReadyDownloadBlocks, flush_ready_download_blocks,
        stale_guard::STALE_BLOCK_PACKET_WINDOW,
    },
    Ed2kPeerDownloadOutcome,
    state::DownloadSessionState,
};

pub(super) struct DownloadPartPacket<'a> {
    pub(super) transport: &'a mut Ed2kTransport,
    pub(super) transfer_runtime: &'a Ed2kTransferRuntime,
    pub(super) file_hash: &'a Ed2kHash,
    pub(super) file_hash_hex: &'a str,
    pub(super) pending_part_requests: &'a mut Vec<PendingPartRequest>,
    pub(super) pending_compressed_parts: &'a mut Vec<PendingCompressedPart>,
    pub(super) manifest: &'a mut Ed2kResumeManifest,
    pub(super) session_state: &'a mut DownloadSessionState,
    pub(super) peer_addr: SocketAddr,
    pub(super) packet: &'a EmuleTcpPacket,
}

pub(super) async fn handle_download_part_packet(
    part_packet: DownloadPartPacket<'_>,
) -> Result<Option<Ed2kPeerDownloadOutcome>> {
    let DownloadPartPacket {
        transport,
        transfer_runtime,
        file_hash,
        file_hash_hex,
        pending_part_requests,
        pending_compressed_parts,
        manifest,
        session_state,
        peer_addr,
        packet,
    } = part_packet;
    let transport_mode = transport.mode;
    let use_i64 = packet.opcode == OP_SENDINGPART_I64 || packet.opcode == OP_COMPRESSEDPART_I64;

    if packet.opcode == OP_COMPRESSEDPART || packet.opcode == OP_COMPRESSEDPART_I64 {
        let (returned_hash, start, advertised_compressed_len, compressed_fragment) =
            decode_compressed_part_fragment(&packet.payload, use_i64)?;
        if &returned_hash != file_hash {
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "unexpected_part_hash",
                format!(
                    "expected_file_hash={file_hash_hex} returned_file_hash={returned_hash} start={start} compressed_len={advertised_compressed_len}"
                ),
            );
            return Ok(None);
        }
        if !pending_part_requests.iter().any(|request| request.queued) {
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "unexpected_compressed_part_without_queued_request",
                format!(
                    "file_hash={file_hash_hex} start={start} compressed_len={advertised_compressed_len}"
                ),
            );
            let has_pending_blocks = has_sent_block_requests(pending_part_requests);
            return drop_stale_block_packet(StaleBlockPacketDrop {
                transport,
                session_state,
                peer_addr,
                file_hash_hex,
                has_pending_blocks,
                duplicate: false,
            })
            .await;
        }
        let Some(pending_index) = pending_part_requests.iter().position(|request| {
            request.queued && request.start == start && request.end > request.start
        }) else {
            // The stream matches no pending block: drop the packet and count it
            // (oracle :1531-1553), never tear the session down on one packet.
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "unexpected_compressed_part_range",
                format!(
                    "file_hash={file_hash_hex} start={start} compressed_len={advertised_compressed_len} pending={pending_part_requests:?}",
                ),
            );
            let has_pending_blocks = has_sent_block_requests(pending_part_requests);
            return drop_stale_block_packet(StaleBlockPacketDrop {
                transport,
                session_state,
                peer_addr,
                file_hash_hex,
                has_pending_blocks,
                duplicate: false,
            })
            .await;
        };
        let expected_request = pending_part_requests[pending_index].clone();
        let expected_part = expected_request.piece_index;
        let expected_start = expected_request.start;
        let expected_end = expected_request.end;
        let compressed_index = if let Some(index) =
            pending_compressed_parts.iter().position(|pending| {
                pending.piece_index == expected_part
                    && pending.start == expected_start
                    && pending.end == expected_end
            }) {
            if pending_compressed_parts[index].zstream_error {
                // The stream already errored: ignore all further payload for
                // this block, but keep the connection (oracle :1300-1308).
                dump_ed2k_tcp_download_meta(
                    peer_addr,
                    Some(transport_mode),
                    "compressed_part_ignored_zstream_error",
                    format!(
                        "file_hash={file_hash_hex} piece_index={expected_part} start={start} compressed_len={advertised_compressed_len}"
                    ),
                );
                return Ok(None);
            }
            if pending_compressed_parts[index].advertised_compressed_len
                != advertised_compressed_len
            {
                // The peer changed the stream framing mid-block: the stream is
                // unrecoverable, but the next 180 K stream can be valid again
                // (oracle zstream-error disposition, :1394-1411).
                pending_compressed_parts[index].zstream_error = true;
                dump_ed2k_tcp_download_meta(
                    peer_addr,
                    Some(transport_mode),
                    "compressed_part_framing_changed",
                    format!(
                        "file_hash={file_hash_hex} piece_index={expected_part} start={start} advertised={advertised_compressed_len} expected_advertised={}",
                        pending_compressed_parts[index].advertised_compressed_len
                    ),
                );
                return Ok(None);
            }
            index
        } else {
            pending_compressed_parts.push(PendingCompressedPart {
                piece_index: expected_part,
                start: expected_start,
                end: expected_end,
                advertised_compressed_len,
                compressed_received: 0,
                uncompressed_written: 0,
                inflater: Decompress::new(true),
                zstream_error: false,
            });
            pending_compressed_parts.len() - 1
        };
        let inflate_result = {
            let pending = &mut pending_compressed_parts[compressed_index];
            inflate_compressed_part_fragment(pending, compressed_fragment)
        };
        let (bytes, finished) = match inflate_result {
            Ok(inflated) => inflated,
            Err(error) => {
                // A zlib error on one 180 K stream is not fatal: ignore the
                // remainder of that stream and keep downloading (oracle
                // :1394-1411 — "no need to disconnect the sending client").
                pending_compressed_parts[compressed_index].zstream_error = true;
                dump_ed2k_tcp_download_meta(
                    peer_addr,
                    Some(transport_mode),
                    "compressed_part_zstream_error",
                    format!(
                        "file_hash={file_hash_hex} piece_index={expected_part} start={start} error={error:#}"
                    ),
                );
                return Ok(None);
            }
        };
        let stream_end = {
            let pending = &pending_compressed_parts[compressed_index];
            pending.start + pending.uncompressed_written
        };
        if !bytes.is_empty() {
            let stream_start = stream_end
                .checked_sub(u64::try_from(bytes.len()).unwrap_or(0))
                .unwrap_or(start);
            let expected_received_start = pending_part_requests[pending_index].received_end;
            if stream_start != expected_received_start || stream_end > expected_end {
                // Corrupt stream positioning (oracle :1394-1400 corrupt
                // compressed range): drop the stream, keep the session.
                pending_compressed_parts[compressed_index].zstream_error = true;
                dump_ed2k_tcp_download_meta(
                    peer_addr,
                    Some(transport_mode),
                    "out_of_order_compressed_part_range",
                    format!(
                        "file_hash={file_hash_hex} piece_index={expected_part} expected_start={expected_received_start} start={stream_start} end={stream_end} pending={pending_part_requests:?}",
                    ),
                );
                return Ok(None);
            }
            pending_part_requests[pending_index].buffer_response_bytes(
                stream_start,
                stream_end,
                &bytes,
            )?;
            // Useful download progress clears the stale-packet window (oracle
            // ResetDownloadStaleBlockPacketGuard on written payload).
            session_state.stale_block_guard.reset();
        }
        let piece_len = expected_end - expected_start;
        let pending = &pending_compressed_parts[compressed_index];
        if pending.uncompressed_written > piece_len
            || (finished && pending.uncompressed_written != piece_len)
        {
            // Oversized or truncated stream: unrecoverable for this block, but
            // never fatal for the connection (oracle zstream-error disposition).
            let uncompressed_written = pending.uncompressed_written;
            pending_compressed_parts[compressed_index].zstream_error = true;
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "compressed_part_stream_length_mismatch",
                format!(
                    "file_hash={file_hash_hex} piece_index={expected_part} wrote={uncompressed_written} expected={piece_len} finished={finished}"
                ),
            );
        } else if pending.uncompressed_written == piece_len {
            pending_compressed_parts.remove(compressed_index);
        }
        flush_download_blocks(FlushDownloadBlocks {
            transfer_runtime,
            file_hash_hex,
            pending_part_requests,
            manifest,
            session_state,
            peer_addr,
            transport_mode,
        })
        .await?;
    } else {
        let (returned_hash, start, end, bytes) =
            decode_sending_part_payload(&packet.payload, use_i64)?;
        if &returned_hash != file_hash {
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "unexpected_part_hash",
                format!(
                    "expected_file_hash={file_hash_hex} returned_file_hash={returned_hash} start={start} end={end}"
                ),
            );
            return Ok(None);
        }
        // A block whose compressed stream already errored ignores ALL further
        // payload for the block, packed or not (oracle :1300-1308).
        if pending_compressed_parts
            .iter()
            .any(|pending| pending.zstream_error && start >= pending.start && start < pending.end)
        {
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "part_ignored_zstream_error",
                format!("file_hash={file_hash_hex} start={start} end={end}"),
            );
            return Ok(None);
        }
        if !pending_part_requests.iter().any(|request| request.queued) {
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "unexpected_part_without_queued_request",
                format!("file_hash={file_hash_hex} start={start} end={end}"),
            );
            let has_pending_blocks = has_sent_block_requests(pending_part_requests);
            return drop_stale_block_packet(StaleBlockPacketDrop {
                transport,
                session_state,
                peer_addr,
                file_hash_hex,
                has_pending_blocks,
                duplicate: false,
            })
            .await;
        }
        let payload_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if let Some(pending_index) = pending_part_requests
            .iter()
            .position(|request| request.matches_uncompressed_fragment(start, end))
        {
            if end != start.saturating_add(payload_len) {
                // Advertised range and carried byte count disagree: malformed
                // frame, drop it without ending the session.
                dump_ed2k_tcp_download_meta(
                    peer_addr,
                    Some(transport_mode),
                    "unexpected_part_length",
                    format!(
                        "file_hash={file_hash_hex} start={start} end={end} payload_len={payload_len}"
                    ),
                );
                let has_pending_blocks = has_sent_block_requests(pending_part_requests);
                return drop_stale_block_packet(StaleBlockPacketDrop {
                    transport,
                    session_state,
                    peer_addr,
                    file_hash_hex,
                    has_pending_blocks,
                    duplicate: false,
                })
                .await;
            }
            pending_part_requests[pending_index].buffer_response_bytes(start, end, bytes)?;
            session_state.stale_block_guard.reset();
        } else if let Some(pending_index) = pending_part_requests.iter().position(|request| {
            request.queued
                && request.start <= start
                && start < request.received_end
                && end <= request.end
        }) {
            // Duplicate payload overlapping already-received bytes of a pending
            // block (oracle :1421-1487): consume it gracefully instead of
            // erroring — buffer only the new tail (if any), so a duplicate that
            // reaches the block boundary still advances/clears the reservation.
            let received_end = pending_part_requests[pending_index].received_end;
            if end > received_end && end == start.saturating_add(payload_len) {
                let skip = usize::try_from(received_end - start)
                    .context("duplicate block prefix exceeds usize")?;
                pending_part_requests[pending_index].buffer_response_bytes(
                    received_end,
                    end,
                    &bytes[skip..],
                )?;
                session_state.stale_block_guard.reset();
                dump_ed2k_tcp_download_meta(
                    peer_addr,
                    Some(transport_mode),
                    "duplicate_part_prefix_consumed",
                    format!(
                        "file_hash={file_hash_hex} start={start} end={end} received_end={received_end}"
                    ),
                );
            } else {
                // Fully duplicate payload: no useful progress, drop and count
                // it (oracle bDuplicateZeroWrite stale accounting).
                dump_ed2k_tcp_download_meta(
                    peer_addr,
                    Some(transport_mode),
                    "duplicate_part_range",
                    format!(
                        "file_hash={file_hash_hex} start={start} end={end} received_end={received_end}"
                    ),
                );
                let has_pending_blocks = has_sent_block_requests(pending_part_requests);
                return drop_stale_block_packet(StaleBlockPacketDrop {
                    transport,
                    session_state,
                    peer_addr,
                    file_hash_hex,
                    has_pending_blocks,
                    duplicate: true,
                })
                .await;
            }
        } else {
            // Payload matching no pending block: drop the packet and count it
            // (oracle :1531-1553), never tear the session down on one packet.
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "unexpected_part_range",
                format!(
                    "file_hash={file_hash_hex} start={start} end={end} pending={pending_part_requests:?}",
                ),
            );
            let has_pending_blocks = has_sent_block_requests(pending_part_requests);
            return drop_stale_block_packet(StaleBlockPacketDrop {
                transport,
                session_state,
                peer_addr,
                file_hash_hex,
                has_pending_blocks,
                duplicate: false,
            })
            .await;
        }
        flush_download_blocks(FlushDownloadBlocks {
            transfer_runtime,
            file_hash_hex,
            pending_part_requests,
            manifest,
            session_state,
            peer_addr,
            transport_mode,
        })
        .await?;
    }

    Ok(None)
}

/// REG-6: whether we have actually SENT block requests to this peer (mirrors the
/// oracle's `m_PendingBlocks_list.IsEmpty()` gate, DownloadClient.cpp:2692, where
/// the list holds requests already put on the wire). A `PendingPartRequest` is
/// pushed when a block is planned but only marked `queued` once its
/// OP_REQUESTPARTS has been written (window.rs). Arming the stale guard on merely
/// planned-but-unsent requests would let a peer that streams payload without our
/// having asked trip the 32-in-15s cancel, where the oracle would only drop the
/// packets.
fn has_sent_block_requests(pending_part_requests: &[PendingPartRequest]) -> bool {
    pending_part_requests.iter().any(|request| request.queued)
}

struct StaleBlockPacketDrop<'a> {
    transport: &'a mut Ed2kTransport,
    session_state: &'a mut DownloadSessionState,
    peer_addr: SocketAddr,
    file_hash_hex: &'a str,
    has_pending_blocks: bool,
    duplicate: bool,
}

/// Drop one stale/duplicate block packet WITHOUT ending the session (oracle
/// DownloadClient.cpp:1531-1553) and cancel the transfer only when the
/// 32-in-15s guard trips (:2690-2712): send OP_CANCELTRANSFER and requeue the
/// source, the rust analog of `SendCancelTransfer` + `DS_ONQUEUE`.
async fn drop_stale_block_packet(
    drop: StaleBlockPacketDrop<'_>,
) -> Result<Option<Ed2kPeerDownloadOutcome>> {
    let StaleBlockPacketDrop {
        transport,
        session_state,
        peer_addr,
        file_hash_hex,
        has_pending_blocks,
        duplicate,
    } = drop;
    let abort = session_state
        .stale_block_guard
        .note_stale_packet(tokio::time::Instant::now(), has_pending_blocks);
    let stale_count = session_state.stale_block_guard.window_count();
    diag_bad_peer::download_stale_block_packet_dropped(
        &peer_addr.to_string(),
        session_state.peer_user_hash,
        file_hash_hex,
        duplicate,
        stale_count,
    );
    if !abort {
        return Ok(None);
    }
    let window_ms = u64::try_from(STALE_BLOCK_PACKET_WINDOW.as_millis()).unwrap_or(u64::MAX);
    if duplicate {
        diag_bad_peer::download_stale_duplicate_block_abort(
            &peer_addr.to_string(),
            session_state.peer_user_hash,
            file_hash_hex,
            stale_count,
            window_ms,
        );
    } else {
        diag_bad_peer::download_stale_block_packet_abort(
            &peer_addr.to_string(),
            session_state.peer_user_hash,
            file_hash_hex,
            stale_count,
            window_ms,
        );
    }
    let cancel = encode_packet(OP_EDONKEYPROT, OP_CANCELTRANSFER, &[]);
    dump_ed2k_tcp_download_send(peer_addr, transport.mode, "cancel_stale_block_packets", &cancel);
    transport
        .write_all(&cancel)
        .await
        .with_context(|| format!("failed to send OP_CANCELTRANSFER to {peer_addr}"))?;
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "stale_block_packet_abort",
        format!("file_hash={file_hash_hex} stale_packets={stale_count} duplicate={duplicate}"),
    );
    Ok(Some(Ed2kPeerDownloadOutcome::AcceptedButIncomplete))
}

struct FlushDownloadBlocks<'a> {
    transfer_runtime: &'a Ed2kTransferRuntime,
    file_hash_hex: &'a str,
    pending_part_requests: &'a mut Vec<PendingPartRequest>,
    manifest: &'a mut Ed2kResumeManifest,
    session_state: &'a mut DownloadSessionState,
    peer_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
}

async fn flush_download_blocks(blocks: FlushDownloadBlocks<'_>) -> Result<()> {
    let FlushDownloadBlocks {
        transfer_runtime,
        file_hash_hex,
        pending_part_requests,
        manifest,
        session_state,
        peer_addr,
        transport_mode,
    } = blocks;
    let peer_user_hash = session_state.peer_user_hash;
    let peer_connect_options = session_state.peer_connect_options;
    let credit_user_hash = session_state.verified_credit_user_hash();
    flush_ready_download_blocks(ReadyDownloadBlocks {
        transfer_runtime,
        file_hash_hex,
        pending_part_requests,
        active_piece_request: &mut session_state.active_piece_request,
        manifest,
        peer_addr,
        transport_mode,
        completed_block_count: &mut session_state.completed_block_count,
        session_payload_down: &mut session_state.session_payload_down,
        part_response_deadline: &mut session_state.part_response_deadline,
        peer_user_hash,
        peer_connect_options,
        credit_user_hash,
        aich_recovery_parts: &mut session_state.pending_aich_recovery_parts,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::{PendingPartRequest, has_sent_block_requests};

    /// REG-6: the stale guard arms on SENT block requests only (oracle
    /// `m_PendingBlocks_list`, DownloadClient.cpp:2692), not on planned-but-unsent
    /// ones — a `PendingPartRequest` is `queued` only after its OP_REQUESTPARTS is
    /// on the wire. Payload arriving before we sent any request must not arm the
    /// 32-in-15s cancel; payload after a request was sent does.
    #[test]
    fn stale_guard_arms_only_on_sent_block_requests() {
        // Planned but not yet sent (queued == false): guard stays disarmed, so
        // stray payload is merely dropped, never counted toward the cancel.
        let planned = PendingPartRequest::new(0, 0, 100);
        assert!(!has_sent_block_requests(std::slice::from_ref(&planned)));

        // Once OP_REQUESTPARTS is written the request is `queued`: guard arms.
        let mut sent = PendingPartRequest::new(1, 100, 200);
        sent.queued = true;
        assert!(has_sent_block_requests(std::slice::from_ref(&sent)));

        // A mix arms as soon as any request is on the wire.
        assert!(has_sent_block_requests(&[planned, sent]));

        // No requests at all: disarmed.
        assert!(!has_sent_block_requests(&[]));
    }
}
