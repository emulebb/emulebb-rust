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
use crate::ed2k_client_udp::outbound::ClientUdpDatagram;
use crate::ed2k_client_udp::reciprocity::{
    InboundReaskRequest, ReciprocityReplyFraming, build_reciprocity_reply_packet,
};
use crate::ed2k_client_udp::service::TransferReaskInfo;

use super::model::Ed2kTransferState;
use super::upload_queue::Ed2kWaitingReaskLookup;
use super::{Ed2kSharedEntry, Ed2kTransferRuntime};

impl Ed2kTransferRuntime {
    /// Build the uploader's reply to an inbound `OP_REASKFILEPING` (or `None` for
    /// the deliberate-silence cases). Locates the sender in the global upload
    /// queue by stock `(ip, udp_port, allow_unique_ip_fallback=true)` semantics,
    /// consults the shared catalog for the requested file, and composes
    /// [`build_reciprocity_reply_packet`].
    pub(crate) async fn reask_reciprocity_reply(
        &self,
        ping: &ReaskFilePing,
        from: SocketAddr,
        our_public_ip: [u8; 4],
    ) -> Option<ClientUdpDatagram> {
        // IPv4-only client: a non-V4 sender cannot be one of our queued peers.
        let SocketAddr::V4(v4) = from else {
            return None;
        };
        let sender_ip = IpAddr::V4(*v4.ip());
        let sender_udp_port = v4.port();
        let requested_hex = ping.file_hash.to_string();

        // `reqfile != NULL`: we serve the requested file — either a verified
        // complete copy or an in-progress partfile with at least one complete
        // part ("share while downloading"). `our_part_status` then advertises the
        // partfile's verified parts, mirroring eMule's OP_REASKFILEPING handler
        // answering `WritePartStatus` for an `IsPartFile()` reqfile.
        //
        // The by-hash index resolves the unique non-hint entry in O(1); a bare
        // compatibility hint is never indexed and never servable, so the follow-up
        // `is_servable` filter reproduces the previous `find(servable && hash)` scan.
        let serving_entry = {
            let catalog = self.shared_catalog.read().await;
            catalog
                .index_by_hash(&ping.file_hash)
                .map(|idx| catalog[idx].clone())
                .filter(Ed2kSharedEntry::is_servable)
        };
        let file_shared = serving_entry.is_some();
        let our_part_status = serving_entry.and_then(|e| {
            // A complete file advertises full availability (`None` = complete, no
            // partstatus bitmap); a partfile advertises its per-part bitmap.
            (!e.verified_complete && !e.complete_parts.is_empty()).then(|| e.complete_parts.clone())
        });

        let now = Instant::now();
        let (lookup, waiting_user_count, queue_size) = {
            let mut queue = self.upload_queue.lock().await;
            let lookup = queue.lookup_waiting_reask_client(sender_ip, sender_udp_port, now);
            let waiting_user_count = queue.waiting_user_count();
            // eMule QUEUEFULL margin compares against the configured soft queue
            // size (thePrefs.GetQueueSize()), not the structural waiting_capacity.
            let queue_size = queue.config().soft_queue_size;

            if let Some(client) = lookup.client()
                && client.file_hash.eq_ignore_ascii_case(&requested_hex)
            {
                queue.refresh_waiting_reask_state(
                    client,
                    ping.part_status.clone(),
                    ping.complete_source_count,
                    now,
                );
            }
            (lookup, waiting_user_count, queue_size)
        };

        let located = lookup.client();

        let req = InboundReaskRequest {
            file_shared,
            sender_located: located.is_some(),
            file_matches: located.is_some_and(|e| e.file_hash.eq_ignore_ascii_case(&requested_hex)),
            waiting_position: located.map_or(0, |e| e.queue_rank),
            sender_multiple_ip_unknown: matches!(&lookup, Ed2kWaitingReaskLookup::Ambiguous),
            waiting_user_count,
            queue_size,
        };

        // Framing comes from the located client; for an unlocated FileNotFound /
        // QueueFull we have no hash/crypt context, so reply in the clear.
        let framing = ReciprocityReplyFraming {
            peer_udp_version: located.map_or(0, |e| e.udp_version),
            dest_user_hash: located.and_then(|e| e.user_hash).unwrap_or_default(),
            should_crypt: located.is_some_and(|e| e.should_crypt && e.user_hash.is_some()),
            our_part_status,
        };

        build_reciprocity_reply_packet(&req, &framing, our_public_ip)
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
                let total_parts = manifest.pieces.len();
                let part_status = manifest
                    .pieces
                    .iter()
                    .map(|piece| piece.state == Ed2kTransferState::Verified)
                    .collect();
                // Complete-source hint: live sources advertising every part
                // (eMule `m_nCompleteSourcesCount`). Optional, gated on udp_version > 2.
                let complete_source_count = self
                    .live_download_sources(&hex)
                    .iter()
                    .filter(|source| source.available_parts as usize == total_parts)
                    .count()
                    .min(u16::MAX as usize) as u16;
                TransferReaskInfo {
                    part_status: Some(part_status),
                    complete_source_count,
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
