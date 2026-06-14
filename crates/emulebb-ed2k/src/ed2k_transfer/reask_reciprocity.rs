//! Uploader-side UDP source-reask reciprocity wired to the live runtime state.
//!
//! Bridges the I/O-free reciprocity decision
//! ([`crate::ed2k_client_udp::reciprocity`]) to the runtime's two sources of
//! truth — the global upload queue (who is queued on us, where they sit) and the
//! shared catalog (what we actually serve) — mirroring eMule's
//! `OP_REASKFILEPING` handler (`ClientUDPSocket.cpp`), where the answer is gated
//! on `GetWaitingClientByIP_UDP` + the requested `reqfile`.
//!
//! Kept off the live path until the reask transport is wire-validated; the
//! gated [`crate::ed2k_client_udp::runtime`] loop calls this on `AnswerNeeded`.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use emulebb_kad_proto::Ed2kHash;

use crate::ed2k_client_udp::codec::ReaskFilePing;
use crate::ed2k_client_udp::reciprocity::{
    InboundReaskRequest, ReciprocityReplyFraming, build_reciprocity_reply,
};
use crate::ed2k_client_udp::service::TransferReaskInfo;

use super::Ed2kTransferRuntime;
use super::model::Ed2kTransferState;
use super::upload_queue::Ed2kUploadSessionPhaseSnapshot;

impl Ed2kTransferRuntime {
    /// Build the uploader's reply to an inbound `OP_REASKFILEPING` (or `None` for
    /// the deliberate-silence cases). Locates the sender in the global upload
    /// queue by `(ip, udp_port)`, consults the shared catalog for the requested
    /// file, and composes [`build_reciprocity_reply`].
    pub(crate) async fn reask_reciprocity_reply(
        &self,
        ping: &ReaskFilePing,
        from: SocketAddr,
        our_public_ip: [u8; 4],
    ) -> Option<Vec<u8>> {
        // IPv4-only client: a non-V4 sender cannot be one of our queued peers.
        let SocketAddr::V4(v4) = from else { return None };
        let sender_ip = IpAddr::V4(*v4.ip());
        let sender_udp_port = v4.port();
        let requested_hex = ping.file_hash.to_string();

        // `reqfile != NULL`: we serve a verified-complete copy of the requested file.
        let file_shared = {
            let catalog = self.shared_catalog.read().await;
            catalog
                .iter()
                .any(|e| e.verified_complete && e.file_hash.eq_ignore_ascii_case(&requested_hex))
        };

        let (snapshot, queue_size) = {
            let mut queue = self.upload_queue.lock().await;
            let snapshot = queue.snapshot(Instant::now());
            (snapshot, queue.config().waiting_capacity as u32)
        };

        // Among clients sharing the sender IP, locate the one on this UDP port
        // (eMule `GetWaitingClientByIP_UDP`). More than one IP match with none on
        // the port is the port-mapping ambiguity that forces a TCP connect.
        let same_ip: Vec<_> = snapshot.iter().filter(|e| e.ip == sender_ip).collect();
        let located = same_ip
            .iter()
            .copied()
            .find(|e| e.udp_port == Some(sender_udp_port));
        let waiting_user_count = snapshot
            .iter()
            .filter(|e| matches!(e.phase, Ed2kUploadSessionPhaseSnapshot::Waiting))
            .count() as u32;

        let req = InboundReaskRequest {
            file_shared,
            sender_located: located.is_some(),
            file_matches: located
                .is_some_and(|e| e.file_hash.eq_ignore_ascii_case(&requested_hex)),
            waiting_position: located.and_then(|e| e.queue_rank).unwrap_or(0),
            sender_multiple_ip_unknown: located.is_none() && same_ip.len() > 1,
            waiting_user_count,
            queue_size,
        };

        // Framing comes from the located client; for an unlocated FileNotFound /
        // QueueFull we have no hash/crypt context, so reply in the clear.
        let framing = ReciprocityReplyFraming {
            peer_udp_version: located.map_or(0, |e| e.udp_version),
            dest_user_hash: located.and_then(|e| e.user_hash).unwrap_or_default(),
            should_crypt: located.is_some_and(|e| e.should_crypt && e.user_hash.is_some()),
            // We only advertise verified-complete shares for upload, so our part
            // availability is full (`None` = complete, no partstatus bitmap).
            our_part_status: None,
        };

        build_reciprocity_reply(&req, &framing, our_public_ip)
    }

    /// Our downloader-side reask facts for one file: the part-availability bitmap
    /// to advertise in an outbound `OP_REASKFILEPING` (verified pieces, only for
    /// an incomplete partfile) and our complete-source count. Mirrors the
    /// partstatus eMule sends with a reask when `GetUDPVersion() > 3`.
    pub(crate) async fn reask_transfer_info(&self, file_hash: &Ed2kHash) -> TransferReaskInfo {
        let hex = file_hash.to_string();
        match self.manifest(&hex).await {
            // Incomplete partfile: advertise which pieces we already hold.
            Ok(manifest) if !manifest.completed && !manifest.pieces.is_empty() => {
                let part_status = manifest
                    .pieces
                    .iter()
                    .map(|piece| piece.state == Ed2kTransferState::Verified)
                    .collect();
                TransferReaskInfo {
                    part_status: Some(part_status),
                    // Complete-source accounting is not tracked here yet; 0 is the
                    // honest hint (the field is optional, udp_version > 2).
                    complete_source_count: 0,
                }
            }
            // Complete / unknown file: no partfile bitmap.
            _ => TransferReaskInfo {
                part_status: None,
                complete_source_count: 0,
            },
        }
    }
}
