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

use crate::ed2k_transfer::{AichRecoveryPermit, Ed2kResumeManifest, Ed2kTransferRuntime};

use super::super::{Ed2kTransport, dump_ed2k_tcp_download_meta, encode_aich_recovery_request};

/// Stock answers carry no request ID. Retain a bounded receipt history on the
/// physical stream across A4AF file switches. A fresh stream starts empty.
#[derive(Debug, Default)]
pub(in crate::ed2k_tcp) struct AichRequestHistory(Vec<RecoveryReceipt>);

#[derive(Debug)]
struct RecoveryReceipt {
    file: Ed2kHash,
    part: u16,
    received_proof: bool,
}

impl AichRequestHistory {
    fn may_send(&self, file: Ed2kHash, part: u16) -> bool {
        self.0.len() < 256
            && !self
                .0
                .iter()
                .any(|receipt| (receipt.file, receipt.part) == (file, part))
    }

    pub(in crate::ed2k_tcp) fn unambiguous_failure(&self, file: Ed2kHash) -> bool {
        self.0
            .iter()
            .filter(|receipt| receipt.file == file && !receipt.received_proof)
            .count()
            == 1
    }

    fn sent(&mut self, file: Ed2kHash, part: u16) {
        self.0.push(RecoveryReceipt {
            file,
            part,
            received_proof: false,
        });
    }

    pub(in crate::ed2k_tcp) fn accepted_proof(&mut self, file: Ed2kHash, part: u16) {
        if let Some(receipt) = self
            .0
            .iter_mut()
            .find(|receipt| (receipt.file, receipt.part) == (file, part))
        {
            receipt.received_proof = true;
        }
    }
}

/// Mutable per-session AICH-recovery request bookkeeping.
pub(in crate::ed2k_tcp) struct AichRecoveryRequestState<'a> {
    /// Parts whose MD4 verification just failed and need an OP_AICHREQUEST.
    pub(in crate::ed2k_tcp) pending: &'a mut Vec<u16>,
    /// Parts with an OP_AICHREQUEST already sent and awaiting an answer (master
    /// `CAICHRecoveryHashSet::IsClientRequestPending`).
    pub(in crate::ed2k_tcp) inflight: &'a mut Option<AichRecoveryPermit>,
    pub(in crate::ed2k_tcp) runtime: &'a Ed2kTransferRuntime,
    pub(in crate::ed2k_tcp) peer_hash: Option<[u8; 16]>,
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
    if state
        .inflight
        .as_ref()
        .is_some_and(AichRecoveryPermit::expired)
    {
        *state.inflight = None;
    }
    if state.pending.is_empty() || state.inflight.is_some() {
        return Ok(());
    }
    if !state.remote_supports_aich {
        dump_ed2k_tcp_download_meta(
            peer_addr,
            Some(transport.mode),
            "aich_request_skipped_peer_unsupported",
            || format!("file_hash={file_hash_hex}"),
        );
        return Ok(());
    }

    while let Some(part) = state.pending.pop() {
        if !transport.aich_request_history.may_send(*file_hash, part) {
            continue;
        }
        // Only ask a peer that holds the part.
        let peer_has_part = state
            .peer_part_bitmap
            .is_none_or(|bitmap| bitmap.get(part as usize).copied().unwrap_or(false));
        if !peer_has_part {
            continue;
        }
        let Some(permit) = state
            .runtime
            .reserve_aich_recovery(manifest.token, part, peer_addr, state.peer_hash)
            .await?
        else {
            continue;
        };
        let request = encode_aich_recovery_request(file_hash, part, permit.master());
        transport
            .write_all_diagnostic(
                "native_download",
                peer_addr,
                "aich_recovery_request",
                &request,
            )
            .await
            .with_context(|| format!("failed to send OP_AICHREQUEST to {peer_addr}"))?;
        transport.aich_request_history.sent(*file_hash, part);
        *state.inflight = Some(permit);
        break;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_history_keeps_duplicate_and_bare_answers_correlated_across_file_switches() {
        let first = Ed2kHash([1; 16]);
        let second = Ed2kHash([2; 16]);
        let mut history = AichRequestHistory::default();
        history.sent(first, 1);
        history.sent(second, 1);
        assert!(history.unambiguous_failure(first));
        assert!(!history.may_send(first, 1));
        assert!(history.may_send(first, 2));
        history.sent(first, 2);
        assert!(!history.unambiguous_failure(first));
        assert!(history.unambiguous_failure(second));
        history.accepted_proof(first, 1);
        assert!(history.unambiguous_failure(first));
    }
}
