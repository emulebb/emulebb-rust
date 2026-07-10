//! Solicit AICH/ICH block recovery for parts that fail MD4 verification.
//!
//! When a downloaded part fails its MD4 re-check, eMule does not discard the
//! whole part: `CPartFile::HashSinglePart` failure drives
//! `CPartFile::RequestAICHRecovery`, which asks a source that supports AICH and
//! holds the part for the part's recovery data (`CUpDownClient::SendAICHRequest`
//! -> OP_AICHREQUEST). The inbound OP_AICHANSWER then drives block-level salvage
//! so only the corrupt 180 KB blocks are re-downloaded.
//!
//! This module emits the OP_AICHREQUEST leg from the active download session.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use crate::ed2k_transfer::{
    ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE, Ed2kResumeManifest, decode_aich_hash_hex,
};

use super::super::{
    Ed2kTransport, dump_ed2k_tcp_download_meta, dump_ed2k_tcp_download_send,
    encode_aich_recovery_request,
};

/// Mutable per-session AICH-recovery request bookkeeping.
pub(in crate::ed2k_tcp) struct AichRecoveryRequestState<'a> {
    /// Parts whose MD4 verification just failed and need an OP_AICHREQUEST.
    pub(in crate::ed2k_tcp) pending: &'a mut Vec<u16>,
    /// Parts with an OP_AICHREQUEST already sent and awaiting an answer (master
    /// `CAICHRecoveryHashSet::IsClientRequestPending`).
    pub(in crate::ed2k_tcp) inflight: &'a mut Vec<u16>,
    /// Connected peer's advertised per-part availability (OP_FILESTATUS).
    pub(in crate::ed2k_tcp) peer_part_bitmap: Option<&'a [bool]>,
    /// Whether the peer advertised AICH support in its HELLO.
    pub(in crate::ed2k_tcp) remote_supports_aich: bool,
}

/// Drain the queue of parts that failed MD4 verification, soliciting AICH/ICH
/// recovery from the connected peer for each.
///
/// A request is sent only when:
///  - we hold a trusted AICH master root for the file (manifest `aich_root`),
///  - the peer advertised AICH support (HELLO `supports_aich`),
///  - the part is large enough to carry recovery data (master
///    `m_nFileSize > PARTSIZE * nPart + EMBLOCKSIZE`),
///  - the peer holds the part (its OP_FILESTATUS bitmap), and
///  - no request for the part is already outstanding (master
///    `IsClientRequestPending`).
///
/// Parts that cannot be requested now are dropped from the queue; the whole-part
/// re-download fallback still applies via the normal missing-part path.
pub(in crate::ed2k_tcp) async fn pump_aich_recovery_requests(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    file_hash: &Ed2kHash,
    file_hash_hex: &str,
    manifest: &Ed2kResumeManifest,
    state: AichRecoveryRequestState<'_>,
) -> Result<()> {
    if state.pending.is_empty() {
        return Ok(());
    }
    let pending = std::mem::take(state.pending);

    // A trusted AICH root is required to validate any recovery answer.
    let Some(master_hash) = manifest
        .aich_root
        .as_deref()
        .and_then(|root_hex| decode_aich_hash_hex(root_hex).ok())
    else {
        dump_ed2k_tcp_download_meta(
            peer_addr,
            Some(transport.mode),
            "aich_request_skipped_no_root",
            || (format!("file_hash={file_hash_hex} parts={pending:?}")).into(),
        );
        return Ok(());
    };
    if !state.remote_supports_aich {
        dump_ed2k_tcp_download_meta(
            peer_addr,
            Some(transport.mode),
            "aich_request_skipped_peer_unsupported",
            || (format!("file_hash={file_hash_hex} parts={pending:?}")).into(),
        );
        return Ok(());
    }

    for part in pending {
        if state.inflight.contains(&part) {
            continue;
        }
        // Master guard: the part must be able to carry recovery data.
        let part_start = u64::from(part) * ED2K_PART_SIZE;
        if manifest.file_size <= part_start + ED2K_EMBLOCK_SIZE {
            continue;
        }
        // Only ask a peer that holds the part.
        let peer_has_part = state
            .peer_part_bitmap
            .is_none_or(|bitmap| bitmap.get(part as usize).copied().unwrap_or(false));
        if !peer_has_part {
            continue;
        }
        let request = encode_aich_recovery_request(file_hash, part, master_hash);
        dump_ed2k_tcp_download_send(peer_addr, transport.mode, "aich_recovery_request", &request);
        transport
            .write_all(&request)
            .await
            .with_context(|| format!("failed to send OP_AICHREQUEST to {peer_addr}"))?;
        state.inflight.push(part);
    }
    Ok(())
}
