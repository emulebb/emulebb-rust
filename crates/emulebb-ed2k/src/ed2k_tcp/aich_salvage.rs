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
    file_hash_hex: &str,
    answer: &AichRecoveryAnswer,
    packet_payload: &[u8],
    peer_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
) -> Result<()> {
    let (Some(part), Some(master_hash)) = (answer.part, answer.master_hash) else {
        // A bare 16-byte answer is the peer's recovery-unavailable failure form.
        dump_ed2k_tcp_download_meta(
            peer_addr,
            Some(transport_mode),
            "aich_recovery_unavailable",
            || (format!("file_hash={file_hash_hex}")).into(),
        );
        return Ok(());
    };
    if packet_payload.len() <= AICH_ANSWER_HEADER_LEN {
        dump_ed2k_tcp_download_meta(
            peer_addr,
            Some(transport_mode),
            "aich_recovery_empty_body",
            || (format!("file_hash={file_hash_hex} part={part}")).into(),
        );
        return Ok(());
    }
    let recovery_body = &packet_payload[AICH_ANSWER_HEADER_LEN..];

    match transfer_runtime
        .begin_part_salvage(file_hash_hex, part, master_hash, recovery_body)
        .await
    {
        Ok(Some(outcome)) => {
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "aich_salvage_started",
                || (format!(
                    "file_hash={file_hash_hex} part={part} recovered_blocks={} needed_blocks={}",
                    outcome.recovered_ranges.len(),
                    outcome.needed_ranges.len()
                )).into(),
            );
        }
        Ok(None) => {
            // No trusted root, master mismatch, part not corrupt, or unknown
            // part: nothing to salvage.
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "aich_salvage_skipped",
                || (format!("file_hash={file_hash_hex} part={part}")).into(),
            );
        }
        Err(error) => {
            // Recovery data failed verification against the trusted master hash;
            // fall back to whole-part re-download (the part stays as-is).
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport_mode),
                "aich_salvage_failed",
                || (format!("file_hash={file_hash_hex} part={part} error={error}")).into(),
            );
        }
    }
    Ok(())
}
