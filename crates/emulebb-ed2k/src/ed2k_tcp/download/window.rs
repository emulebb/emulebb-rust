use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use crate::ed2k_transfer::{
    ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kTransferRuntime,
    expected_piece_length,
};

use super::super::{
    Ed2kTransport, dump_ed2k_tcp_download_meta, dump_ed2k_tcp_download_send,
    encode_request_parts_batch,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ed2k_tcp) struct ActiveDownloadPiece {
    pub(in crate::ed2k_tcp) piece_index: u32,
    pub(in crate::ed2k_tcp) next_offset: u64,
    pub(in crate::ed2k_tcp) piece_end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::ed2k_tcp) struct PendingPartRequest {
    pub(in crate::ed2k_tcp) piece_index: u32,
    pub(in crate::ed2k_tcp) start: u64,
    pub(in crate::ed2k_tcp) end: u64,
    pub(in crate::ed2k_tcp) queued: bool,
    pub(in crate::ed2k_tcp) received_end: u64,
    pub(in crate::ed2k_tcp) response_bytes: Vec<u8>,
}

impl PendingPartRequest {
    pub(in crate::ed2k_tcp) fn new(piece_index: u32, start: u64, end: u64) -> Self {
        Self {
            piece_index,
            start,
            end,
            queued: false,
            received_end: start,
            response_bytes: Vec::new(),
        }
    }

    pub(in crate::ed2k_tcp) fn matches_uncompressed_fragment(&self, start: u64, end: u64) -> bool {
        self.queued && self.received_end == start && end >= start && end <= self.end
    }

    pub(in crate::ed2k_tcp) fn buffer_response_bytes(
        &mut self,
        start: u64,
        end: u64,
        bytes: &[u8],
    ) -> Result<()> {
        let data_len = u64::try_from(bytes.len()).context("response block exceeds u64 length")?;
        let expected_end = start.saturating_add(data_len);
        if start != self.received_end || end != expected_end || end > self.end {
            anyhow::bail!(
                "unexpected response range {start}..{end} for pending block {}..{} received_end={}",
                self.start,
                self.end,
                self.received_end
            );
        }
        self.response_bytes.extend_from_slice(bytes);
        self.received_end = end;
        Ok(())
    }

    pub(in crate::ed2k_tcp) fn is_ready(&self) -> bool {
        self.received_end == self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ed2k_tcp) struct DownloadWindowLimits {
    pub(in crate::ed2k_tcp) max_pending_blocks: usize,
    pub(in crate::ed2k_tcp) min_pending_blocks: usize,
}

pub(in crate::ed2k_tcp) struct DownloadRequestWindowState<'a> {
    pub(in crate::ed2k_tcp) transfer_runtime: &'a Ed2kTransferRuntime,
    pub(in crate::ed2k_tcp) file_hash: &'a Ed2kHash,
    pub(in crate::ed2k_tcp) file_hash_hex: &'a str,
    pub(in crate::ed2k_tcp) file_size: u64,
    pub(in crate::ed2k_tcp) manifest: &'a Ed2kResumeManifest,
    pub(in crate::ed2k_tcp) active_piece_request: &'a mut Option<ActiveDownloadPiece>,
    pub(in crate::ed2k_tcp) pending_part_requests: &'a mut Vec<PendingPartRequest>,
    pub(in crate::ed2k_tcp) upload_accepted_at: tokio::time::Instant,
    pub(in crate::ed2k_tcp) completed_block_count: usize,
    pub(in crate::ed2k_tcp) session_payload_down: u64,
    pub(in crate::ed2k_tcp) part_response_grace: Duration,
}

pub(in crate::ed2k_tcp) async fn pump_download_request_window(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    state: DownloadRequestWindowState<'_>,
) -> Result<Option<tokio::time::Instant>> {
    let DownloadRequestWindowState {
        transfer_runtime,
        file_hash,
        file_hash_hex,
        file_size,
        manifest,
        active_piece_request,
        pending_part_requests,
        upload_accepted_at,
        completed_block_count,
        session_payload_down,
        part_response_grace,
    } = state;
    let window = select_download_window_limits(
        manifest,
        completed_block_count,
        session_payload_down,
        upload_accepted_at,
    );
    if pending_part_requests.len() < window.min_pending_blocks {
        while pending_part_requests.len() < window.max_pending_blocks {
            if active_piece_request.is_none() {
                let Some(next_part) = transfer_runtime
                    .claim_next_missing_part(file_hash_hex)
                    .await?
                else {
                    break;
                };
                let piece_start = u64::from(next_part.piece_index) * ED2K_PART_SIZE;
                let piece_end = (piece_start + ED2K_PART_SIZE).min(file_size);
                *active_piece_request = Some(ActiveDownloadPiece {
                    piece_index: next_part.piece_index,
                    next_offset: piece_start + next_part.bytes_written,
                    piece_end,
                });
            }
            let Some(active_piece) = active_piece_request.as_mut() else {
                break;
            };
            // Skip over blocks already present in this part's salvage bitmap so
            // an ICH-recovered part re-requests only the corrupt (gap) blocks.
            // For a normal contiguous part the bitmap is the contiguous prefix
            // up to `bytes_written`, so this advance is a no-op.
            advance_over_present_blocks(manifest, active_piece);
            if active_piece.next_offset >= active_piece.piece_end {
                break;
            }
            let end = (active_piece.next_offset + ED2K_EMBLOCK_SIZE).min(active_piece.piece_end);
            pending_part_requests.push(PendingPartRequest::new(
                active_piece.piece_index,
                active_piece.next_offset,
                end,
            ));
            active_piece.next_offset = end;
        }
    }

    let mut request_indices = Vec::with_capacity(3);
    let mut requested_ranges = Vec::with_capacity(3);
    for (index, request) in pending_part_requests.iter().enumerate() {
        if request.queued {
            continue;
        }
        request_indices.push(index);
        requested_ranges.push((request.start, request.end));
        if request_indices.len() >= 3 {
            break;
        }
    }
    if requested_ranges.is_empty() {
        return Ok(None);
    }

    let request_parts = encode_request_parts_batch(file_hash, &requested_ranges)?;
    dump_ed2k_tcp_download_send(peer_addr, transport.mode, "request_parts", &request_parts);
    transport
        .write_all(&request_parts)
        .await
        .with_context(|| format!("failed to send OP_REQUESTPARTS to {peer_addr}"))?;
    for index in request_indices {
        pending_part_requests[index].queued = true;
    }
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "request_window",
        format!(
            "file_hash={file_hash_hex} queued={} total_pending={} max_pending={} min_pending={}",
            requested_ranges.len(),
            pending_part_requests.len(),
            window.max_pending_blocks,
            window.min_pending_blocks
        ),
    );
    Ok(Some(tokio::time::Instant::now() + part_response_grace))
}

/// Advance `active_piece.next_offset` past any blocks already marked present in
/// the part's salvage bitmap, so re-download targets only the missing (gap)
/// blocks. A no-op for contiguous parts (the bitmap is the prefix up to
/// `bytes_written`, which `next_offset` already starts beyond).
fn advance_over_present_blocks(
    manifest: &Ed2kResumeManifest,
    active_piece: &mut ActiveDownloadPiece,
) {
    let Some(piece) = manifest
        .pieces
        .iter()
        .find(|piece| piece.piece_index == active_piece.piece_index)
    else {
        return;
    };
    if !piece.has_block_bitmap() {
        return;
    }
    let piece_start = u64::from(active_piece.piece_index) * ED2K_PART_SIZE;
    let part_len = active_piece.piece_end - piece_start;
    while active_piece.next_offset < active_piece.piece_end {
        let rel = active_piece.next_offset - piece_start;
        match piece.present_block_end(part_len, rel) {
            Some(block_end_rel) => active_piece.next_offset = piece_start + block_end_rel,
            None => break,
        }
    }
}

#[must_use]
pub(in crate::ed2k_tcp) fn select_download_window_limits(
    manifest: &Ed2kResumeManifest,
    completed_block_count: usize,
    session_payload_down: u64,
    upload_accepted_at: tokio::time::Instant,
) -> DownloadWindowLimits {
    if completed_block_count == 0 || session_payload_down == 0 {
        return DownloadWindowLimits {
            max_pending_blocks: 1,
            min_pending_blocks: 1,
        };
    }

    let remaining_bytes = remaining_unverified_bytes(manifest);
    let elapsed_secs = upload_accepted_at.elapsed().as_secs_f64().max(0.001);
    let download_rate = session_payload_down as f64 / elapsed_secs;

    let (max_pending_blocks, block_delta) = if remaining_bytes <= ED2K_PART_SIZE * 4 {
        if completed_block_count < 2 || download_rate < 600.0 || session_payload_down < 40 * 1024 {
            (1usize, 0usize)
        } else if download_rate < 1200.0 {
            (2usize, 0usize)
        } else {
            (3usize, 1usize)
        }
    } else if completed_block_count >= 3 && download_rate > 75.0 * 1024.0 {
        (6usize, 2usize)
    } else {
        (3usize, 1usize)
    };

    DownloadWindowLimits {
        max_pending_blocks,
        min_pending_blocks: max_pending_blocks.saturating_sub(block_delta).max(1),
    }
}

#[must_use]
fn remaining_unverified_bytes(manifest: &Ed2kResumeManifest) -> u64 {
    manifest
        .pieces
        .iter()
        .map(|piece| {
            let piece_len = expected_piece_length(
                manifest.file_size,
                manifest.piece_size,
                u64::from(piece.piece_index),
            );
            piece_len.saturating_sub(piece.bytes_written)
        })
        .sum()
}

/// Pick the next ED2K download read wait so queue and part-response grace
/// windows are enforced even when the caller configured a much larger session
/// timeout.
#[must_use]
pub(in crate::ed2k_tcp) fn next_download_read_timeout(
    now: tokio::time::Instant,
    base_timeout: Duration,
    fallback_poll_delay: Option<Duration>,
    queued_until: Option<tokio::time::Instant>,
    part_response_deadline: Option<tokio::time::Instant>,
) -> Duration {
    let mut read_timeout =
        fallback_poll_delay.map_or(base_timeout, |delay| base_timeout.min(delay));
    if let Some(deadline) = queued_until {
        read_timeout = read_timeout.min(deadline.saturating_duration_since(now));
    }
    if let Some(deadline) = part_response_deadline {
        read_timeout = read_timeout.min(deadline.saturating_duration_since(now));
    }
    read_timeout
}
