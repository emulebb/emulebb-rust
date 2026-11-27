//! Shared OP_AICHANSWER -> ICH salvage handling for the download and listener
//! sessions.
//!
//! On a verified recovery answer for a corrupt part, this drives the
//! `Ed2kTransferRuntime` salvage flow (`begin_part_salvage`): the good 180 KB
//! blocks are kept (marked present in the persisted per-part bitmap) and only
//! the corrupt blocks are returned to the missing pool for re-download by the
//! gap-aware download window, then MD4 re-verified once all blocks are present.
//! Mirrors `CPartFile::AICHRecoveryDataAvailable`.

use std::net::SocketAddr;

use anyhow::Result;

use crate::ed2k_transfer::Ed2kTransferRuntime;

use super::codec::AichRecoveryAnswer;
use super::{Ed2kTransportMode, dump_ed2k_tcp_download_meta};

/// Byte length of the OP_AICHANSWER header before the recovery body:
/// `<file hash 16><part u16><master hash 20>`.
const AICH_ANSWER_HEADER_LEN: usize = 38;

/// Process a decoded OP_AICHANSWER, performing block-level salvage when the
/// answer carries a recovery body for a part we are downloading.
pub(super) async fn handle_aich_recovery_answer(
    transfer_runtime: &Ed2kTransferRuntime,
    pending: &mut Option<crate::ed2k_transfer::AichRecoveryPermit>,
    history: &mut super::download::AichRequestHistory,
    answer: &AichRecoveryAnswer,
    packet_payload: &[u8],
    peer_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
) -> Result<()> {
    let Some(request) = pending.as_ref() else {
        return Ok(());
    };
    if request.expired() {
        pending.take();
        return Ok(());
    }
    if !request.matches(answer.file_hash, answer.part, answer.master_hash)
        || (answer.part.is_none() && !history.unambiguous_failure(answer.file_hash))
    {
        return Ok(());
    }
    let request = pending.take().expect("matched recovery request");
    let file_hash_hex = answer.file_hash;
    let Some(part) = answer.part else {
        // A bare 16-byte answer is the peer's recovery-unavailable failure form.
        dump_ed2k_tcp_download_meta(
            peer_addr,
            Some(transport_mode),
            "aich_recovery_unavailable",
            || format!("file_hash={file_hash_hex}"),
        );
        return Ok(());
    };
    if packet_payload.len() <= AICH_ANSWER_HEADER_LEN {
        dump_ed2k_tcp_download_meta(
            peer_addr,
            Some(transport_mode),
            "aich_recovery_empty_body",
            || format!("file_hash={file_hash_hex} part={part}"),
        );
        return Ok(());
    }
    let recovery_body = &packet_payload[AICH_ANSWER_HEADER_LEN..];

    match transfer_runtime
        .salvage_requested_part(request, recovery_body)
        .await
    {
        Ok(Some(outcome)) => {
            history.accepted_proof(answer.file_hash, part);
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "aich_salvage_started",
                || {
                    format!(
                        "file_hash={file_hash_hex} part={part} recovered_blocks={} needed_blocks={}",
                        outcome.recovered_ranges.len(),
                        outcome.needed_ranges.len()
                    )
                },
            );
        }
        Ok(None) => {
            // No trusted root, master mismatch, part not corrupt, or unknown
            // part: nothing to salvage.
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "aich_salvage_skipped",
                || format!("file_hash={file_hash_hex} part={part}"),
            );
        }
        Err(error) => {
            // Recovery data failed verification against the trusted master hash;
            // fall back to whole-part re-download (the part stays as-is).
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "aich_salvage_failed",
                || format!("file_hash={file_hash_hex} part={part} error={error}"),
            );
        }
    }
    Ok(())
}
