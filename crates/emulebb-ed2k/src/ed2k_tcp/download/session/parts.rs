use std::net::SocketAddr;

use anyhow::Result;
use emulebb_kad_proto::Ed2kHash;
use flate2::Decompress;

use crate::{
    ed2k_tcp::{
        Ed2kTransportMode, EmuleTcpPacket, OP_COMPRESSEDPART, OP_COMPRESSEDPART_I64,
        OP_SENDINGPART_I64, decode_compressed_part_fragment, decode_sending_part_payload,
        dump_ed2k_tcp_download_meta, inflate_compressed_part_fragment,
    },
    ed2k_transfer::{Ed2kResumeManifest, Ed2kTransferRuntime},
};

use super::{
    super::{
        PendingCompressedPart, PendingPartRequest, ReadyDownloadBlocks, flush_ready_download_blocks,
    },
    Ed2kPeerDownloadOutcome,
    state::DownloadSessionState,
};

pub(super) struct DownloadPartPacket<'a> {
    pub(super) transfer_runtime: &'a Ed2kTransferRuntime,
    pub(super) file_hash: &'a Ed2kHash,
    pub(super) file_hash_hex: &'a str,
    pub(super) pending_part_requests: &'a mut Vec<PendingPartRequest>,
    pub(super) pending_compressed_parts: &'a mut Vec<PendingCompressedPart>,
    pub(super) manifest: &'a mut Ed2kResumeManifest,
    pub(super) session_state: &'a mut DownloadSessionState,
    pub(super) peer_addr: SocketAddr,
    pub(super) transport_mode: Ed2kTransportMode,
    pub(super) packet: &'a EmuleTcpPacket,
}

pub(super) async fn handle_download_part_packet(
    part_packet: DownloadPartPacket<'_>,
) -> Result<Option<Ed2kPeerDownloadOutcome>> {
    let DownloadPartPacket {
        transfer_runtime,
        file_hash,
        file_hash_hex,
        pending_part_requests,
        pending_compressed_parts,
        manifest,
        session_state,
        peer_addr,
        transport_mode,
        packet,
    } = part_packet;
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
            return Ok(Some(Ed2kPeerDownloadOutcome::AcceptedButIncomplete));
        }
        let Some(pending_index) = pending_part_requests.iter().position(|request| {
            request.queued && request.start == start && request.end > request.start
        }) else {
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "unexpected_compressed_part_range",
                format!(
                    "file_hash={file_hash_hex} start={start} compressed_len={advertised_compressed_len} pending={pending_part_requests:?}",
                ),
            );
            return Ok(Some(Ed2kPeerDownloadOutcome::AcceptedButIncomplete));
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
            let pending = &pending_compressed_parts[index];
            if pending.advertised_compressed_len != advertised_compressed_len {
                anyhow::bail!(
                    "peer {peer_addr} changed compressed-part framing for piece {expected_part} start={}..{} advertised={} expected={}..{} advertised={}",
                    pending.start,
                    pending.end,
                    pending.advertised_compressed_len,
                    expected_start,
                    expected_end,
                    advertised_compressed_len
                );
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
            });
            pending_compressed_parts.len() - 1
        };
        let (bytes, finished) = {
            let pending = &mut pending_compressed_parts[compressed_index];
            inflate_compressed_part_fragment(pending, compressed_fragment)?
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
            if stream_start != expected_received_start {
                dump_ed2k_tcp_download_meta(
                    peer_addr,
                    Some(transport_mode),
                    "out_of_order_compressed_part_range",
                    format!(
                        "file_hash={file_hash_hex} piece_index={expected_part} expected_start={expected_received_start} start={stream_start} end={stream_end} pending={pending_part_requests:?}",
                    ),
                );
                return Ok(Some(Ed2kPeerDownloadOutcome::AcceptedButIncomplete));
            }
            pending_part_requests[pending_index].buffer_response_bytes(
                stream_start,
                stream_end,
                &bytes,
            )?;
        }
        let piece_len = expected_end - expected_start;
        let pending = &pending_compressed_parts[compressed_index];
        if pending.uncompressed_written > piece_len {
            anyhow::bail!(
                "peer {peer_addr} decompressed beyond requested piece boundary for piece {expected_part}: wrote {} expected {}",
                pending.uncompressed_written,
                piece_len
            );
        }
        if finished && pending.uncompressed_written != piece_len {
            anyhow::bail!(
                "peer {peer_addr} ended compressed stream early for piece {expected_part}: wrote {} expected {}",
                pending.uncompressed_written,
                piece_len
            );
        }
        if pending.uncompressed_written == piece_len {
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
        if !pending_part_requests.iter().any(|request| request.queued) {
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "unexpected_part_without_queued_request",
                format!("file_hash={file_hash_hex} start={start} end={end}"),
            );
            return Ok(Some(Ed2kPeerDownloadOutcome::AcceptedButIncomplete));
        }
        let Some(pending_index) = pending_part_requests
            .iter()
            .position(|request| request.matches_uncompressed_fragment(start, end))
        else {
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "unexpected_part_range",
                format!(
                    "file_hash={file_hash_hex} start={start} end={end} pending={pending_part_requests:?}",
                ),
            );
            return Ok(Some(Ed2kPeerDownloadOutcome::AcceptedButIncomplete));
        };
        let expected_request = pending_part_requests[pending_index].clone();
        let expected_start = expected_request.start;
        if start < expected_start {
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "unexpected_part_fragment_start",
                format!(
                    "file_hash={file_hash_hex} expected_start={expected_start} start={start} end={end} pending={pending_part_requests:?}",
                ),
            );
            return Ok(Some(Ed2kPeerDownloadOutcome::AcceptedButIncomplete));
        }
        pending_part_requests[pending_index].buffer_response_bytes(start, end, &bytes)?;
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
        peer_user_hash: session_state.peer_user_hash,
    })
    .await
}
