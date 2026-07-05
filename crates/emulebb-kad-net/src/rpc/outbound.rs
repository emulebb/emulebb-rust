use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use emulebb_kad_proto::{KadPacket, pack_kad_packet};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::debug;

use super::packet_info::{is_publish_opcode, opcode_name, outbound_transport_reason};
use super::{PendingEntry, RpcInner, RpcManager, RpcWorkClass};
use crate::error::NetError;
use crate::obfuscation::OutboundKadEncryptionMode;
use crate::rate_limit::RateLimiter;
use crate::wire_dump::{KadUdpDumpSummary, dump_kad_udp_packet};

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
        self.inner.pending.lock().unwrap().remove(&self.id)
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if !self.removed {
            self.inner.pending.lock().unwrap().remove(&self.id);
        }
    }
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
        let (tx, rx) = oneshot::channel();
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);

        {
            let mut pending = self.inner.pending.lock().unwrap();
            pending.insert(
                id,
                PendingEntry {
                    remote_addr: addr,
                    request_opcode: packet.opcode(),
                    expected_opcode,
                    tx,
                    created_at: std::time::Instant::now(),
                },
            );
        }

        // From here on the entry is owned by an RAII guard: if this future is
        // dropped (e.g. a converged traversal aborts its query tasks) before any
        // explicit removal arm runs, Drop still evicts the entry so it cannot
        // leak. Each explicit arm uses `guard.take()` to consume it deterministically.
        let mut guard = PendingGuard::new(Arc::clone(&self.inner), id);

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

        if let Err(e) = self.send_with_class(addr, packet, work_class).await {
            guard.take();
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
                guard.take();
                Err(NetError::ChannelClosed)
            }
            Err(_) => {
                let elapsed_ms = guard
                    .take()
                    .map(|entry| entry.created_at.elapsed().as_millis())
                    .unwrap_or_default();
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
        let budget_started = std::time::Instant::now();
        self.rate_limiter_for_class(work_class).acquire().await;
        self.inner.global_rate_limiter.acquire().await;
        let wait_millis = budget_started.elapsed().as_millis() as u64;
        self.inner
            .observability
            .lock()
            .unwrap()
            .record_work_class_send(work_class, wait_millis);
        // eMule packs any Kad datagram whose cleartext exceeds 200 bytes
        // (0xE4 -> 0xE5, zlib body); a stock node always does, so pack before
        // obfuscation to stay wire-identical (the header byte rides inside the
        // encrypted body).
        let encoded = pack_kad_packet(packet.encode()?);
        let outbound = self
            .inner
            .obfuscation
            .inspect_outbound(addr, packet.opcode());
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
        let wire = self
            .inner
            .obfuscation
            .encrypt(addr, packet.opcode(), &encoded);
        self.inner
            .outbound_tracker
            .lock()
            .unwrap()
            .record(addr.ip(), packet.opcode());
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
        dump_kad_udp_packet(
            "send",
            addr,
            &wire,
            &encoded,
            KadUdpDumpSummary {
                protocol: encoded.first().copied().unwrap_or_default(),
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
                drop_reason: None,
                tracker_bucket: None,
                tracker_action: None,
                tracker_observed_packets: None,
                tracker_max_packets: None,
            },
        );
        self.inner.transport.send_raw(addr, &wire).await
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
