use std::net::SocketAddr;

use anyhow::Result;
use flate2::Decompress;

use crate::ed2k_transfer::{Ed2kResumeManifest, Ed2kTransferRuntime, PieceWriteOutcome};

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
    /// The stream hit a zlib/framing error and cannot be recovered; all further
    /// payload for this block is ignored WITHOUT killing the connection, because
    /// the peer's next 180 K stream can be valid again (oracle
    /// `Pending_Block_Struct::fZStreamError`, DownloadClient.cpp:1394-1411 sets
    /// it, :1300-1308 ignores subsequent payload for the flagged block).
    pub(in crate::ed2k_tcp) zstream_error: bool,
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
    pub(in crate::ed2k_tcp) peer_connect_options: Option<u8>,
    /// The peer user hash to attribute *download credit* to, set to `Some` only
    /// when the peer's secure identity is cryptographically verified (eMule
    /// `CClientCredits::AddDownloaded` early-returns for IS_IDFAILED/IDBADGUY/
    /// IDNEEDED when crypto is available; `ClientCredits.cpp:83-91`). Distinct
    /// from `peer_user_hash`, which is the hello-claimed hash used for ban
    /// attribution + live source display and must NOT gate credit.
    pub(in crate::ed2k_tcp) credit_user_hash: Option<[u8; 16]>,
    /// Parts whose MD4 verification just failed; the session drains these to
    /// solicit AICH/ICH recovery from the peer (master `RequestAICHRecovery`).
    pub(in crate::ed2k_tcp) aich_recovery_parts: &'a mut Vec<u16>,
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
        peer_connect_options,
        credit_user_hash,
        aich_recovery_parts,
    } = blocks;
    while pending_part_requests
        .first()
        .is_some_and(|request| request.queued && request.is_ready())
    {
        let request = pending_part_requests.remove(0);
        // Reserve global download budget for this block's inbound payload before
        // consuming it, so the shared token bucket paces all concurrent transfer
        // tasks together (mirrors the upload side reserving before each payload
        // write). A no-op when the download limit is 0 (unlimited).
        reserve_download_budget(transfer_runtime, request.response_bytes.len()).await;
        record_received_range(
            transfer_runtime,
            file_hash_hex,
            peer_addr,
            peer_user_hash,
            request.start,
            request.end,
        );
        let (outcome, refreshed_manifest) = transfer_runtime
            .append_or_salvage_block_with_manifest(
                file_hash_hex,
                request.piece_index,
                request.start,
                request.end,
                &request.response_bytes,
            )
            .await?;
        *manifest = refreshed_manifest;
        if outcome.is_completed() {
            *active_piece_request = None;
        }
        if manifest.completed {
            // The oracle frees the blackbox when the part file completes
            // (`m_CorruptionBlackBox.Free()`, PartFile.cpp:3800).
            transfer_runtime.cbb_free(file_hash_hex);
        }
        if let Some(failed_part) = verification_failed_part(outcome) {
            *active_piece_request = None;
            push_unique(aich_recovery_parts, failed_part);
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
        if let Some(user_hash) = credit_user_hash {
            transfer_runtime.add_peer_credit_delta(user_hash, 0, downloaded_bytes)?;
        }
        transfer_runtime.note_download_payload_bytes(file_hash_hex, downloaded_bytes);
        transfer_runtime.note_download_source_bytes(
            file_hash_hex,
            peer_addr,
            peer_user_hash,
            peer_connect_options,
            downloaded_bytes,
        );
    }
    if !pending_part_requests.iter().any(|request| request.queued) {
        *part_response_deadline = None;
    }
    Ok(())
}

/// Await the global download-rate reservation for one inbound block before it
/// is consumed, so the shared token bucket paces every concurrent transfer
/// task together (the download-side counterpart to the upload payload
/// reservation). A no-op when the limit is 0 (unlimited).
async fn reserve_download_budget(transfer_runtime: &Ed2kTransferRuntime, byte_count: usize) {
    let reservation = transfer_runtime
        .reserve_download_payload_budget(u64::try_from(byte_count).unwrap_or(u64::MAX))
        .await;
    if !reservation.delay.is_zero() {
        tokio::time::sleep(reservation.delay).await;
    }
}

/// Record which peer sent the byte range `[start, end)` in the per-transfer
/// corruption blackbox (oracle `CPartFile::WriteToBuffer` ->
/// `m_CorruptionBlackBox.ReceivedData`, PartFile.cpp:4951). An MD4 part-hash
/// failure alone never bans the sender: the oracle only gaps the part and
/// solicits AICH recovery (PartFile.cpp:5184-5199); the ban decision is the
/// AICH-verdict `EvaluateData` 32%-corrupt-share path
/// (CorruptionBlackBox.cpp:233-309), fed from the salvage flow. Recording the
/// actual writer per range keeps parts resumed across peers attributed to the
/// correct sender for each byte range.
fn record_received_range(
    transfer_runtime: &Ed2kTransferRuntime,
    file_hash_hex: &str,
    peer_addr: SocketAddr,
    peer_user_hash: Option<[u8; 16]>,
    start: u64,
    end: u64,
) {
    if let SocketAddr::V4(v4) = peer_addr {
        transfer_runtime.cbb_record_received_data(
            file_hash_hex,
            start,
            end,
            *v4.ip(),
            peer_user_hash,
        );
    }
}

/// Map a write outcome to a verification-failed part index (as a u16 part) so
/// the session can request AICH recovery for it.
fn verification_failed_part(outcome: PieceWriteOutcome) -> Option<u16> {
    outcome
        .verification_failed_part()
        .and_then(|part| u16::try_from(part).ok())
}

/// Append a part to the recovery queue only if it is not already pending, so a
/// part is not re-requested while an answer is still outstanding (master
/// `IsClientRequestPending`).
fn push_unique(parts: &mut Vec<u16>, part: u16) {
    if !parts.contains(&part) {
        parts.push(part);
    }
}

#[expect(clippy::too_many_arguments)]
pub(in crate::ed2k_tcp) async fn flush_buffered_download_prefixes(
    transfer_runtime: &Ed2kTransferRuntime,
    file_hash_hex: &str,
    pending_part_requests: &mut Vec<PendingPartRequest>,
    active_piece_request: &mut Option<ActiveDownloadPiece>,
    manifest: &mut Ed2kResumeManifest,
    peer_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    peer_user_hash: Option<[u8; 16]>,
    peer_connect_options: Option<u8>,
    credit_user_hash: Option<[u8; 16]>,
    aich_recovery_parts: &mut Vec<u16>,
) -> Result<()> {
    while let Some(first_request) = pending_part_requests.first() {
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

        // Reserve global download budget for this contiguous prefix's inbound
        // payload before consuming it, so the shared token bucket paces all
        // concurrent transfer tasks together. A no-op when unlimited.
        reserve_download_budget(transfer_runtime, bytes.len()).await;
        record_received_range(
            transfer_runtime,
            file_hash_hex,
            peer_addr,
            peer_user_hash,
            start,
            end,
        );
        let (outcome, refreshed_manifest) = transfer_runtime
            .append_piece_block_with_manifest(file_hash_hex, piece_index, start, end, &bytes)
            .await?;
        *manifest = refreshed_manifest;
        if outcome.is_completed() {
            *active_piece_request = None;
        }
        if manifest.completed {
            // The oracle frees the blackbox when the part file completes
            // (`m_CorruptionBlackBox.Free()`, PartFile.cpp:3800).
            transfer_runtime.cbb_free(file_hash_hex);
        }
        if let Some(failed_part) = verification_failed_part(outcome) {
            *active_piece_request = None;
            push_unique(aich_recovery_parts, failed_part);
        }
        if let Some(user_hash) = credit_user_hash {
            transfer_runtime.add_peer_credit_delta(user_hash, 0, end.saturating_sub(start))?;
        }
        transfer_runtime.note_download_payload_bytes(file_hash_hex, end.saturating_sub(start));
        transfer_runtime.note_download_source_bytes(
            file_hash_hex,
            peer_addr,
            peer_user_hash,
            peer_connect_options,
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
    peer_addr: SocketAddr,
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
    // The AICH root here is network-learned from a single peer, so it must be
    // corroborated before it can authorize salvage (mirrors the master's
    // untrusted-hash accumulation).
    *manifest = transfer_runtime
        .record_network_aich_root(
            file_hash_hex,
            peer_file_identifier.aich_root,
            peer_addr.ip(),
        )
        .await?;
    *request_file_identifier = Ed2kFileIdentifier::from_manifest(manifest)?;
    Ok(())
}
