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

#[cfg(feature = "packet-diagnostics")]
use std::{fmt, time::Duration};

use emulebb_kad_proto::Ed2kHash;

use crate::ed2k_client_udp::codec::ReaskFilePing;
use crate::ed2k_client_udp::outbound::ClientUdpDatagram;
#[cfg(feature = "packet-diagnostics")]
use crate::ed2k_client_udp::reciprocity::QUEUE_FULL_MARGIN;
use crate::ed2k_client_udp::reciprocity::{
    InboundReaskRequest, ReciprocityReplyFraming, build_reciprocity_reply_packet,
};
use crate::ed2k_client_udp::service::TransferReaskInfo;

use super::model::Ed2kTransferState;
use super::upload_queue::Ed2kWaitingReaskLookup;
use super::{Ed2kSharedEntry, Ed2kTransferRuntime};

#[cfg(feature = "packet-diagnostics")]
const DIAGNOSTIC_QUEUE_PRESSURE_TTL: Duration = Duration::from_secs(30);

/// Receipt for one diagnostics-only client-UDP queue-pressure prerequisite.
///
/// The fixture does not inject or apply a packet. It supplies the stock
/// near-full waiting-user fact to one exact inbound reask after the harness has
/// removed that sender from the real waiting queue.
#[cfg(feature = "packet-diagnostics")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticClientUdpQueuePressureReceipt {
    pub fixture_id: u64,
    pub file_hash: Ed2kHash,
    pub source_endpoint: SocketAddr,
    pub actual_waiting_user_count: u32,
    pub effective_waiting_user_count: u32,
    pub queue_size: u32,
    pub expires_after_millis: u64,
}

#[cfg(feature = "packet-diagnostics")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticClientUdpQueuePressureErrorKind {
    FileNotShared,
    SenderStillQueued,
    SenderAmbiguous,
}

#[cfg(feature = "packet-diagnostics")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticClientUdpQueuePressureError {
    pub kind: DiagnosticClientUdpQueuePressureErrorKind,
    message: String,
}

#[cfg(feature = "packet-diagnostics")]
impl fmt::Display for DiagnosticClientUdpQueuePressureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

#[cfg(feature = "packet-diagnostics")]
impl std::error::Error for DiagnosticClientUdpQueuePressureError {}

#[cfg(feature = "packet-diagnostics")]
#[derive(Debug, Clone, Copy)]
struct ArmedClientUdpQueuePressure {
    receipt: DiagnosticClientUdpQueuePressureReceipt,
    expires_at: Instant,
}

#[cfg(feature = "packet-diagnostics")]
#[derive(Debug, Default)]
pub(super) struct DiagnosticClientUdpQueuePressureState {
    next_fixture_id: u64,
    armed: Option<ArmedClientUdpQueuePressure>,
}

#[cfg(feature = "packet-diagnostics")]
impl DiagnosticClientUdpQueuePressureState {
    fn arm(
        &mut self,
        file_hash: Ed2kHash,
        source_endpoint: SocketAddr,
        actual_waiting_user_count: u32,
        queue_size: u32,
        now: Instant,
    ) -> DiagnosticClientUdpQueuePressureReceipt {
        self.next_fixture_id = self.next_fixture_id.saturating_add(1).max(1);
        let effective_waiting_user_count = queue_size
            .saturating_sub(QUEUE_FULL_MARGIN)
            .saturating_add(1);
        let receipt = DiagnosticClientUdpQueuePressureReceipt {
            fixture_id: self.next_fixture_id,
            file_hash,
            source_endpoint,
            actual_waiting_user_count,
            effective_waiting_user_count,
            queue_size,
            expires_after_millis: DIAGNOSTIC_QUEUE_PRESSURE_TTL.as_millis() as u64,
        };
        self.armed = Some(ArmedClientUdpQueuePressure {
            receipt,
            expires_at: now + DIAGNOSTIC_QUEUE_PRESSURE_TTL,
        });
        receipt
    }

    fn consume(
        &mut self,
        file_hash: Ed2kHash,
        source_endpoint: SocketAddr,
        queue_size: u32,
        now: Instant,
    ) -> Option<DiagnosticClientUdpQueuePressureReceipt> {
        let armed = self.armed?;
        if now >= armed.expires_at {
            self.armed = None;
            return None;
        }
        if armed.receipt.file_hash != file_hash
            || armed.receipt.source_endpoint != source_endpoint
            || armed.receipt.queue_size != queue_size
        {
            return None;
        }
        self.armed.take().map(|fixture| fixture.receipt)
    }
}

impl Ed2kTransferRuntime {
    /// Arm one exact, expiring, one-shot queue-pressure prerequisite for the
    /// diagnostics build. The sender must already be absent from the real
    /// waiting queue and the requested file must remain servable.
    #[cfg(feature = "packet-diagnostics")]
    pub async fn arm_diagnostic_client_udp_queue_pressure(
        &self,
        file_hash: Ed2kHash,
        source_endpoint: SocketAddr,
    ) -> Result<DiagnosticClientUdpQueuePressureReceipt, DiagnosticClientUdpQueuePressureError>
    {
        let file_shared = {
            let catalog = self.shared_catalog.read().await;
            catalog
                .index_by_hash(&file_hash)
                .map(|index| catalog[index].is_servable())
                .unwrap_or(false)
        };
        if !file_shared {
            return Err(diagnostic_queue_pressure_error(
                DiagnosticClientUdpQueuePressureErrorKind::FileNotShared,
                "requested file is not shared",
            ));
        }

        let now = Instant::now();
        let (lookup, actual_waiting_user_count, queue_size) = {
            let mut queue = self.upload_queue.lock().await;
            let lookup = queue.lookup_waiting_reask_client(
                source_endpoint.ip(),
                source_endpoint.port(),
                now,
            );
            (
                lookup,
                queue.waiting_user_count(),
                queue.config().soft_queue_size,
            )
        };
        match lookup {
            Ed2kWaitingReaskLookup::Missing => {}
            Ed2kWaitingReaskLookup::Ambiguous => {
                return Err(diagnostic_queue_pressure_error(
                    DiagnosticClientUdpQueuePressureErrorKind::SenderAmbiguous,
                    "multiple waiting clients still share the source IP",
                ));
            }
            Ed2kWaitingReaskLookup::Exact(_) | Ed2kWaitingReaskLookup::UniqueIpFallback(_) => {
                return Err(diagnostic_queue_pressure_error(
                    DiagnosticClientUdpQueuePressureErrorKind::SenderStillQueued,
                    "source is still present in the upload waiting queue",
                ));
            }
        }

        Ok(self.client_udp_queue_pressure.lock().unwrap().arm(
            file_hash,
            source_endpoint,
            actual_waiting_user_count,
            queue_size,
            now,
        ))
    }

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
        let (lookup, actual_waiting_user_count, queue_size) = {
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
        #[cfg(feature = "packet-diagnostics")]
        let waiting_user_count = {
            let mut effective = actual_waiting_user_count;
            if file_shared
                && matches!(lookup, Ed2kWaitingReaskLookup::Missing)
                && let Some(fixture) = self.client_udp_queue_pressure.lock().unwrap().consume(
                    ping.file_hash,
                    from,
                    queue_size,
                    now,
                )
            {
                effective = fixture.effective_waiting_user_count;
                crate::diag_event::emit(
                    "sched",
                    "client_udp_queue_pressure_fixture_consumed",
                    "info",
                    serde_json::json!({
                        "fileHash": requested_hex,
                        "peer": from.to_string(),
                    }),
                    serde_json::json!({
                        "outcome": "consumed",
                        "fixtureId": fixture.fixture_id,
                        "actualWaitingUserCount": actual_waiting_user_count,
                        "effectiveWaitingUserCount": fixture.effective_waiting_user_count,
                        "queueSize": queue_size,
                        "queueFullMargin": QUEUE_FULL_MARGIN,
                    }),
                );
            }
            effective
        };
        #[cfg(not(feature = "packet-diagnostics"))]
        let waiting_user_count = actual_waiting_user_count;

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
                // Complete-source hint: retained source status advertising every part
                // (eMule `m_nCompleteSourcesCount`). Optional, gated on udp_version > 2.
                let complete_source_count = self.known_complete_source_count(&hex, total_parts);
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

#[cfg(feature = "packet-diagnostics")]
fn diagnostic_queue_pressure_error(
    kind: DiagnosticClientUdpQueuePressureErrorKind,
    message: impl Into<String>,
) -> DiagnosticClientUdpQueuePressureError {
    DiagnosticClientUdpQueuePressureError {
        kind,
        message: message.into(),
    }
}

#[cfg(all(test, feature = "packet-diagnostics"))]
mod diagnostic_queue_pressure_tests {
    use super::*;

    #[test]
    fn expired_fixture_is_cleared_without_matching() {
        let now = Instant::now();
        let file_hash = Ed2kHash::from_bytes([0xE1; 16]);
        let source = "192.0.2.20:4672".parse().unwrap();
        let mut state = DiagnosticClientUdpQueuePressureState::default();
        state.arm(file_hash, source, 3, 2_000, now);

        assert_eq!(
            state.consume(
                file_hash,
                source,
                2_000,
                now + DIAGNOSTIC_QUEUE_PRESSURE_TTL,
            ),
            None
        );
        assert!(state.armed.is_none());
    }
}
