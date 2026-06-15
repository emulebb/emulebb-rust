use std::net::SocketAddr;

use anyhow::Result;
use flate2::Decompress;

use crate::ed2k_transfer::{Ed2kResumeManifest, Ed2kTransferRuntime};

use super::super::{Ed2kFileIdentifier, Ed2kTransportMode, dump_ed2k_tcp_download_meta};
use super::window::{ActiveDownloadPiece, PendingPartRequest};

/// Incremental inflate state for one pending compressed part stream.
///
/// Real eMule peers can split one compressed block across multiple
/// `OP_COMPRESSEDPART` frames. The per-packet header repeats the block start
/// and the total compressed stream length, while the payload only carries one
/// fragment of the zlib stream.
pub(in crate::ed2k_tcp) struct PendingCompressedPart {
    pub(in crate::ed2k_tcp) piece_index: u32,
    pub(in crate::ed2k_tcp) start: u64,
    pub(in crate::ed2k_tcp) end: u64,
    pub(in crate::ed2k_tcp) advertised_compressed_len: usize,
    pub(in crate::ed2k_tcp) compressed_received: usize,
    pub(in crate::ed2k_tcp) uncompressed_written: u64,
    pub(in crate::ed2k_tcp) inflater: Decompress,
}

pub(in crate::ed2k_tcp) struct ReadyDownloadBlocks<'a> {
    pub(in crate::ed2k_tcp) transfer_runtime: &'a Ed2kTransferRuntime,
    pub(in crate::ed2k_tcp) file_hash_hex: &'a str,
    pub(in crate::ed2k_tcp) pending_part_requests: &'a mut Vec<PendingPartRequest>,
    pub(in crate::ed2k_tcp) active_piece_request: &'a mut Option<ActiveDownloadPiece>,
    pub(in crate::ed2k_tcp) manifest: &'a mut Ed2kResumeManifest,
    pub(in crate::ed2k_tcp) peer_addr: SocketAddr,
    pub(in crate::ed2k_tcp) transport_mode: Ed2kTransportMode,
    pub(in crate::ed2k_tcp) completed_block_count: &'a mut usize,
    pub(in crate::ed2k_tcp) session_payload_down: &'a mut u64,
    pub(in crate::ed2k_tcp) part_response_deadline: &'a mut Option<tokio::time::Instant>,
    pub(in crate::ed2k_tcp) peer_user_hash: Option<[u8; 16]>,
}

pub(in crate::ed2k_tcp) async fn flush_ready_download_blocks(
    blocks: ReadyDownloadBlocks<'_>,
) -> Result<()> {
    let ReadyDownloadBlocks {
        transfer_runtime,
        file_hash_hex,
        pending_part_requests,
        active_piece_request,
        manifest,
        peer_addr,
        transport_mode,
        completed_block_count,
        session_payload_down,
        part_response_deadline,
        peer_user_hash,
    } = blocks;
    while pending_part_requests
        .first()
        .is_some_and(|request| request.queued && request.is_ready())
    {
        let request = pending_part_requests.remove(0);
        let (piece_completed, refreshed_manifest) = transfer_runtime
            .append_or_salvage_block_with_manifest(
                file_hash_hex,
                request.piece_index,
                request.start,
                request.end,
                &request.response_bytes,
            )
            .await?;
        *manifest = refreshed_manifest;
        if piece_completed {
            *active_piece_request = None;
        }
        dump_ed2k_tcp_download_meta(
            peer_addr,
            Some(transport_mode),
            "piece_block_flushed",
            format!(
                "file_hash={file_hash_hex} piece_index={} start={} end={} completed={}",
                request.piece_index, request.start, request.end, manifest.completed
            ),
        );
        *completed_block_count = completed_block_count.saturating_add(1);
        let downloaded_bytes = request.end.saturating_sub(request.start);
        *session_payload_down = session_payload_down.saturating_add(downloaded_bytes);
        if let Some(user_hash) = peer_user_hash {
            transfer_runtime.add_peer_credit_delta(user_hash, 0, downloaded_bytes)?;
        }
        transfer_runtime.note_download_payload_bytes(file_hash_hex, downloaded_bytes);
        transfer_runtime.note_download_source_bytes(
            file_hash_hex,
            peer_addr,
            peer_user_hash,
            downloaded_bytes,
        );
    }
    if !pending_part_requests.iter().any(|request| request.queued) {
        *part_response_deadline = None;
    }
    Ok(())
}

pub(in crate::ed2k_tcp) async fn flush_buffered_download_prefixes(
    transfer_runtime: &Ed2kTransferRuntime,
    file_hash_hex: &str,
    pending_part_requests: &mut Vec<PendingPartRequest>,
    active_piece_request: &mut Option<ActiveDownloadPiece>,
    manifest: &mut Ed2kResumeManifest,
    peer_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    peer_user_hash: Option<[u8; 16]>,
) -> Result<()> {
    loop {
        let Some(first_request) = pending_part_requests.first() else {
            break;
        };
        if !first_request.queued || first_request.response_bytes.is_empty() {
            break;
        }
        // The contiguous prefix flush only applies to non-salvage parts: a part
        // mid ICH salvage tracks presence by whole-block bitmap and rejects
        // partial-block writes, so leave its incomplete request to be
        // re-requested by the gap-aware window next session.
        if manifest
            .pieces
            .iter()
            .find(|piece| piece.piece_index == first_request.piece_index)
            .is_some_and(|piece| piece.has_block_bitmap())
        {
            break;
        }

        let (piece_index, start, end, bytes, request_complete) = {
            let request = &mut pending_part_requests[0];
            let bytes = std::mem::take(&mut request.response_bytes);
            let start = request.start;
            let end = request.received_end;
            request.start = end;
            (
                request.piece_index,
                start,
                end,
                bytes,
                request.start == request.end,
            )
        };

        let (piece_completed, refreshed_manifest) = transfer_runtime
            .append_piece_block_with_manifest(file_hash_hex, piece_index, start, end, &bytes)
            .await?;
        *manifest = refreshed_manifest;
        if piece_completed {
            *active_piece_request = None;
        }
        if let Some(user_hash) = peer_user_hash {
            transfer_runtime.add_peer_credit_delta(user_hash, 0, end.saturating_sub(start))?;
        }
        transfer_runtime.note_download_payload_bytes(file_hash_hex, end.saturating_sub(start));
        transfer_runtime.note_download_source_bytes(
            file_hash_hex,
            peer_addr,
            peer_user_hash,
            end.saturating_sub(start),
        );
        dump_ed2k_tcp_download_meta(
            peer_addr,
            Some(transport_mode),
            "piece_prefix_flushed",
            format!(
                "file_hash={file_hash_hex} piece_index={piece_index} start={start} end={end} completed={}",
                manifest.completed
            ),
        );

        if request_complete {
            pending_part_requests.remove(0);
            continue;
        }
        break;
    }
    Ok(())
}

pub(in crate::ed2k_tcp) async fn reconcile_download_manifest_metadata(
    transfer_runtime: &Ed2kTransferRuntime,
    file_hash_hex: &str,
    manifest: &mut Ed2kResumeManifest,
    request_file_identifier: &mut Ed2kFileIdentifier,
    peer_file_identifier: &Ed2kFileIdentifier,
    peer_file_name: Option<&str>,
) -> Result<()> {
    let learned_size = peer_file_identifier.file_size;
    let learned_name = peer_file_name
        .map(str::trim)
        .filter(|name| !name.is_empty());
    if learned_size.is_none() && learned_name.is_none() && peer_file_identifier.aich_root.is_none()
    {
        return Ok(());
    }

    *manifest = transfer_runtime
        .reconcile_job_metadata(file_hash_hex, learned_name, learned_size)
        .await?;
    *manifest = transfer_runtime
        .reconcile_aich_root(file_hash_hex, peer_file_identifier.aich_root)
        .await?;
    *request_file_identifier = Ed2kFileIdentifier::from_manifest(manifest)?;
    Ok(())
}
