use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use emulebb_kad_proto::{KadPacket, pack_kad_packet};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::debug;

use super::packet_info::{
    is_publish_opcode, opcode_name, outbound_transport_reason, targeted_request_reply,
};
use super::{PendingEntry, ReceivedKadPacket, RpcInner, RpcManager, RpcWorkClass};
use crate::error::NetError;
use crate::obfuscation::{ObfuscationLayer, OutboundKadEncryptionMode};
use crate::rate_limit::RateLimiter;
use crate::wire_dump::{KadUdpDumpSummary, KadUdpOutcome, dump_kad_udp_packet};

const DETACHED_REQUEST_LIFETIME: Duration = Duration::from_secs(180);

/// RAII guard that guarantees a pending-request entry is removed from the
/// `RpcManager` map exactly once, even if the awaiting request future is
/// dropped (cancelled/aborted) before it can run its own removal arms.
///
/// Traversal lookups routinely abort outstanding query tasks the moment the
/// closest set converges (`JoinSet::abort_all`), so the awaiting
/// `timeout(rx)` future of an aborted task never resolves and never runs the
/// inline `pending.remove(&id)` arms. Without this guard those entries leak,
/// and every inbound RES then pays an O(n) scan over the ever-growing map.
struct PendingGuard {
    inner: Arc<RpcInner>,
    id: u64,
    /// Set once the entry has been removed by an explicit path so the Drop
    /// removal becomes a no-op (avoids a redundant lock acquisition).
    removed: bool,
}

impl PendingGuard {
    fn new(inner: Arc<RpcInner>, id: u64) -> Self {
        Self {
            inner,
            id,
            removed: false,
        }
    }

    /// Remove the entry now and return it, marking the guard satisfied so Drop
    /// does no further work.
    fn take(&mut self) -> Option<PendingEntry> {
        if self.removed {
            return None;
        }
        self.removed = true;
        self.inner.pending.lock().remove(&self.id)
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if !self.removed
            && let Some(entry) = self.inner.pending.lock().remove(&self.id)
        {
            emit_rpc_terminal(self.id, &entry, None, "cancelled", None);
        }
    }
}

pub(super) fn emit_rpc_terminal(
    request_id: u64,
    entry: &PendingEntry,
    response_opcode: Option<u8>,
    outcome: &'static str,
    detail: Option<&str>,
) {
    crate::diag_event::kad_rpc_lifecycle(
        request_id,
        entry.remote_addr,
        entry.request_opcode,
        entry.expected_opcode,
        response_opcode,
        entry.work_class,
        entry.timeout_duration,
        entry.created_at.elapsed(),
        outcome,
        detail,
    );
}

impl RpcManager {
    /// Send a packet to addr and wait for a response matching expected_opcode.
    /// Respects the rate limiter.
    pub async fn request(
        &self,
        addr: SocketAddr,
        packet: &KadPacket,
        expected_opcode: u8,
        timeout_duration: Duration,
    ) -> Result<KadPacket, NetError> {
        self.request_with_class(
            addr,
            packet,
            expected_opcode,
            timeout_duration,
            RpcWorkClass::Interactive,
        )
        .await
    }

    /// Send a packet to addr and wait for a response matching expected_opcode.
    /// Respects both the global safety cap and the selected work-class budget.
    pub async fn request_with_class(
        &self,
        addr: SocketAddr,
        packet: &KadPacket,
        expected_opcode: u8,
        timeout_duration: Duration,
        work_class: RpcWorkClass,
    ) -> Result<KadPacket, NetError> {
        self.request_with_class_and_metadata(
            addr,
            packet,
            expected_opcode,
            timeout_duration,
            work_class,
        )
        .await
        .map(|response| response.packet)
    }

    /// Wait for a correlated response and retain its actual envelope metadata.
    pub async fn request_with_class_and_metadata(
        &self,
        addr: SocketAddr,
        packet: &KadPacket,
        expected_opcode: u8,
        timeout_duration: Duration,
        work_class: RpcWorkClass,
    ) -> Result<ReceivedKadPacket, NetError> {
        if !self.kad_enabled() {
            return Err(NetError::KadStopped);
        }
        let (tx, rx) = oneshot::channel();
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);

        {
            let mut pending = self.inner.pending.lock();
            pending.insert(
                id,
                PendingEntry {
                    remote_addr: addr,
                    request_opcode: packet.opcode(),
                    expected_opcode,
                    work_class,
                    timeout_duration,
                    response_target: targeted_request_reply(packet).map(|(_, target)| target),
                    dispatched_at: None,
                    tx: Some(tx),
                    created_at: std::time::Instant::now(),
                },
            );
        }

        // From here on the entry is owned by an RAII guard: if this future is
        // dropped (e.g. a converged traversal aborts its query tasks) before any
        // explicit removal arm runs, Drop still evicts the entry so it cannot
        // leak. Each explicit arm uses `guard.take()` to consume it deterministically.
        let mut guard = PendingGuard::new(Arc::clone(&self.inner), id);
        crate::diag_event::kad_rpc_lifecycle(
            id,
            addr,
            packet.opcode(),
            expected_opcode,
            None,
            work_class,
            timeout_duration,
            Duration::ZERO,
            "attempted",
            None,
        );

        if is_publish_opcode(packet.opcode()) || is_publish_opcode(expected_opcode) {
            debug!(
                "kad publish pending add pending_id={} request_opcode={} expected_opcode={} to={} timeout_ms={}",
                id,
                opcode_name(packet.opcode()),
                opcode_name(expected_opcode),
                addr,
                timeout_duration.as_millis(),
            );
        }

        if let Err(e) = self
            .send_with_class_for_request(addr, packet, work_class, Some(id), None)
            .await
        {
            if let Some(entry) = guard.take() {
                emit_rpc_terminal(id, &entry, None, "transport_failed", Some(&e.to_string()));
            }
            return Err(e);
        }

        match timeout(timeout_duration, rx).await {
            Ok(Ok(pkt)) => {
                // The receive loop already removed the entry on match; mark the
                // guard satisfied so its Drop does not re-lock the map.
                guard.take();
                Ok(pkt)
            }
            Ok(Err(_)) => {
                if let Some(entry) = guard.take() {
                    emit_rpc_terminal(id, &entry, None, "channel_closed", None);
                }
                Err(NetError::ChannelClosed)
            }
            Err(_) => {
                let entry = guard.take();
                let elapsed_ms = entry
                    .as_ref()
                    .map(|entry| entry.created_at.elapsed().as_millis())
                    .unwrap_or_default();
                if let Some(entry) = entry.as_ref() {
                    emit_rpc_terminal(id, entry, None, "timeout", None);
                }
                if is_publish_opcode(packet.opcode()) || is_publish_opcode(expected_opcode) {
                    debug!(
                        "kad publish pending timeout pending_id={} request_opcode={} expected_opcode={} to={} age_ms={}",
                        id,
                        opcode_name(packet.opcode()),
                        opcode_name(expected_opcode),
                        addr,
                        elapsed_ms,
                    );
                }
                let secs = timeout_duration.as_secs();
                Err(NetError::Timeout { addr, secs })
            }
        }
    }

    /// Send a packet without waiting for a response.
    /// Respects the rate limiter.
    pub async fn send(&self, addr: SocketAddr, packet: &KadPacket) -> Result<(), NetError> {
        self.send_with_class(addr, packet, RpcWorkClass::Interactive)
            .await
    }

    /// Send a packet without waiting for a response.
    /// Respects both the global safety cap and the selected work-class budget.
    pub async fn send_with_class(
        &self,
        addr: SocketAddr,
        packet: &KadPacket,
        work_class: RpcWorkClass,
    ) -> Result<(), NetError> {
        self.send_with_class_for_request(addr, packet, work_class, None, None)
            .await
    }

    /// Acknowledge a keyed publish reply at its observed endpoint, using the
    /// reply's own sender key even when peer-key learning is disabled.
    pub async fn send_publish_response_ack(
        &self,
        response: &ReceivedKadPacket,
        work_class: RpcWorkClass,
    ) -> Result<(), NetError> {
        let Some(key) = response.sender_verify_key.filter(|&key| key != 0) else {
            return Ok(());
        };
        self.send_with_class_for_request(
            response.from,
            &KadPacket::PublishResAck,
            work_class,
            None,
            Some((key, response.key_epoch)),
        )
        .await
    }

    async fn send_with_class_for_request(
        &self,
        addr: SocketAddr,
        packet: &KadPacket,
        work_class: RpcWorkClass,
        request_id: Option<u64>,
        reply_key: Option<(u32, u64)>,
    ) -> Result<(), NetError> {
        if !self.kad_enabled() {
            dump_kad_udp_packet(
                "send",
                addr,
                &[],
                &[],
                KadUdpDumpSummary {
                    request_id,
                    opcode: Some(packet.opcode()),
                    opcode_name: Some(opcode_name(packet.opcode())),
                    drop_reason: Some("kad_stopped"),
                    detail: Some(NetError::KadStopped.to_string()),
                    outcome: KadUdpOutcome::SendRejected,
                    ..KadUdpDumpSummary::default()
                },
            );
            return Err(NetError::KadStopped);
        }
        let budget_started = std::time::Instant::now();
        self.rate_limiter_for_class(work_class).acquire().await;
        self.inner.global_rate_limiter.acquire().await;
        let wait_millis = budget_started.elapsed().as_millis() as u64;
        self.inner
            .observability
            .lock()
            .record_work_class_send(work_class, wait_millis);
        // eMule packs any Kad datagram whose cleartext exceeds 200 bytes
        // (0xE4 -> 0xE5, zlib body); a stock node always does, so pack before
        // obfuscation to stay wire-identical (the header byte rides inside the
        // encrypted body).
        let encoded = match packet.encode() {
            Ok(encoded) => pack_kad_packet(encoded),
            Err(error) => {
                dump_kad_udp_packet(
                    "send",
                    addr,
                    &[],
                    &[],
                    KadUdpDumpSummary {
                        request_id,
                        opcode: Some(packet.opcode()),
                        opcode_name: Some(opcode_name(packet.opcode())),
                        drop_reason: Some("encode_failed"),
                        detail: Some(error.to_string()),
                        outcome: KadUdpOutcome::SendRejected,
                        ..KadUdpDumpSummary::default()
                    },
                );
                return Err(error.into());
            }
        };
        let mut outbound = self
            .inner
            .obfuscation
            .inspect_outbound(addr, packet.opcode());
        if let Some((key, epoch)) = reply_key {
            let IpAddr::V4(ip) = addr.ip() else {
                return Ok(());
            };
            if self.inner.obfuscation.peer_key_epoch() != epoch {
                return Ok(());
            }
            outbound.mode = OutboundKadEncryptionMode::ReceiverVerifyKey;
            outbound.receiver_verify_key = Some(key);
            outbound.sender_verify_key = Some(self.inner.obfuscation.verify_key_for_ip(ip));
        }
        debug!(
            "kad send opcode={} to={} mode={} reason={} peer_version={} receiver_verify_key={} sender_verify_key={} peer_node_id={}",
            opcode_name(packet.opcode()),
            addr,
            outbound.mode.as_str(),
            outbound_transport_reason(packet.opcode(), outbound),
            outbound
                .peer_kad_version
                .map_or_else(|| "-".to_string(), |version| version.to_string()),
            outbound.receiver_verify_key.unwrap_or_default(),
            outbound.sender_verify_key.unwrap_or_default(),
            outbound
                .peer_node_id
                .map(|node_id| node_id.to_string())
                .unwrap_or_else(|| "-".to_string()),
        );
        let wire = ObfuscationLayer::encrypt_outbound(outbound, &encoded);
        self.inner.recent_udp.lock().record_send(addr.ip())?;
        let targeted_reply = targeted_request_reply(packet);
        let mut detached_guard = None;
        {
            let mut pending = self.inner.pending.lock();
            if !self.kad_enabled() {
                return Err(NetError::KadStopped);
            }
            if let Some(id) = request_id {
                let Some(entry) = pending.get_mut(&id) else {
                    return Err(NetError::KadStopped);
                };
                entry.dispatched_at = Some(std::time::Instant::now());
            } else if let Some((expected_opcode, target)) = targeted_reply {
                let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
                pending.retain(|_, entry| entry.is_live());
                let now = std::time::Instant::now();
                pending.insert(
                    id,
                    PendingEntry {
                        remote_addr: addr,
                        request_opcode: packet.opcode(),
                        expected_opcode,
                        response_target: Some(target),
                        work_class,
                        timeout_duration: DETACHED_REQUEST_LIFETIME,
                        dispatched_at: Some(now),
                        tx: None,
                        created_at: now,
                    },
                );
                detached_guard = Some(PendingGuard::new(Arc::clone(&self.inner), id));
            }
        }
        // WHY: opcode-only tracking cannot distinguish outstanding targets.
        // Both awaited and detached targeted requests use the pending map.
        if targeted_reply.is_none() {
            self.inner
                .outbound_tracker
                .lock()
                .record(addr.ip(), packet.opcode());
        }
        if is_publish_opcode(packet.opcode()) {
            let crypt_target = outbound
                .peer_node_id
                .map(|node_id| node_id.to_string())
                .unwrap_or_else(|| "-".to_string());
            debug!(
                "kad publish send opcode={} to={} payload_len={} wire_len={} mode={} receiver_verify_key={} sender_verify_key={} crypt_target={}",
                opcode_name(packet.opcode()),
                addr,
                encoded.len(),
                wire.len(),
                outbound.mode.as_str(),
                outbound.receiver_verify_key.unwrap_or_default(),
                outbound.sender_verify_key.unwrap_or_default(),
                crypt_target,
            );
        }
        let send_result = self.inner.transport.send_raw(addr, &wire).await;
        let (outcome, drop_reason, detail) = match &send_result {
            Ok(()) => (KadUdpOutcome::SendSucceeded, None, None),
            Err(error) => (
                KadUdpOutcome::SendFailed,
                Some("transport_failed"),
                Some(error.to_string()),
            ),
        };
        if send_result.is_ok() {
            if let Some(guard) = &mut detached_guard {
                guard.removed = true;
            }
        } else if targeted_reply.is_none() {
            self.inner
                .outbound_tracker
                .lock()
                .remove_latest(addr.ip(), packet.opcode());
        }
        dump_kad_udp_packet(
            "send",
            addr,
            &wire,
            &encoded,
            KadUdpDumpSummary {
                request_id,
                protocol: encoded.first().copied(),
                opcode: Some(packet.opcode()),
                opcode_name: Some(opcode_name(packet.opcode())),
                raw_obfuscated: !matches!(outbound.mode, OutboundKadEncryptionMode::Plaintext),
                transport_mode: Some(outbound.mode.as_str()),
                requested_obfuscation: Some(!matches!(
                    outbound.mode,
                    OutboundKadEncryptionMode::Plaintext
                )),
                receiver_verify_key: outbound.receiver_verify_key,
                sender_verify_key: outbound.sender_verify_key,
                receiver_verify_key_valid: None,
                tracked_request_opcode: None,
                outcome,
                tracker_bucket: None,
                tracker_action: None,
                tracker_observed_packets: None,
                tracker_max_packets: None,
                drop_reason,
                detail,
            },
        );
        send_result
    }

    fn rate_limiter_for_class(&self, work_class: RpcWorkClass) -> &RateLimiter {
        match work_class {
            RpcWorkClass::Interactive => &self.inner.interactive_rate_limiter,
            RpcWorkClass::Harvest => &self.inner.harvest_rate_limiter,
            RpcWorkClass::Maintenance => &self.inner.maintenance_rate_limiter,
            RpcWorkClass::Publish => &self.inner.publish_rate_limiter,
        }
    }
}
