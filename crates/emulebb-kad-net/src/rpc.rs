//! Kad RPC manager and runtime observability surface.
//!
//! `RpcManager` is the stateful boundary where raw datagrams become typed Kad
//! packets, obfuscation state is updated, pending requests are matched, and the
//! oracle-shaped packet tracker decides whether unsolicited traffic should be
//! accepted or dropped.

mod config;
mod observability;
mod outbound;
mod packet_info;
mod peer_state;
mod receive_loop;

pub use config::{MassiveFloodHandler, RpcClassBudgetConfig, RpcConfig, RpcWorkClass};
use observability::RpcObservabilityState;
pub use observability::{
    RpcObservabilitySnapshot, RpcResponseOpcodeSnapshot, RpcTrackerBucketSnapshot,
    RpcWorkClassSnapshot,
};

use crate::obfuscation::ObfuscationLayer;
use crate::rate_limit::RateLimiter;
use crate::tracker::{OutboundRequestTracker, PacketTracker};
use crate::transport::Transport;
use emulebb_kad_proto::KadPacket;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::{broadcast, oneshot};

struct PendingEntry {
    remote_addr: SocketAddr,
    request_opcode: u8,
    expected_opcode: u8,
    tx: oneshot::Sender<KadPacket>,
    created_at: std::time::Instant,
}

/// Unsolicited Kad packet plus the transport metadata the oracle uses for
/// HELLO verification and reply shaping.
#[derive(Debug, Clone)]
pub struct ReceivedKadPacket {
    /// Decoded Kad payload.
    pub packet: KadPacket,
    /// Remote endpoint that sent the packet.
    pub from: SocketAddr,
    /// Whether the packet arrived through Kad UDP obfuscation.
    pub was_obfuscated: bool,
    /// Sender verify key recovered from the encrypted trailer, when present.
    pub sender_verify_key: Option<u32>,
    /// Whether the sender proved our receiver verify key instead of using
    /// NodeID-mode request obfuscation.
    pub receiver_verify_key_valid: bool,
}

/// Handler for inbound datagrams that fail Kad decode — e.g. eD2k client UDP
/// reask packets that share the Kad UDP port. Returns `true` if it consumed the
/// datagram (the recv loop then skips the Kad decode-failure path). Registered
/// post-construction by the eD2k layer via
/// [`RpcManager::set_foreign_datagram_handler`]; unset means no foreign handling
/// (exactly the prior behaviour).
pub type ForeignDatagramHandler = Arc<dyn Fn(&[u8], SocketAddr) -> bool + Send + Sync>;

struct RpcInner {
    transport: Arc<dyn Transport>,
    obfuscation: ObfuscationLayer,
    /// Optional handler for non-Kad inbound datagrams (e.g. eD2k reask on the
    /// shared port). Late-bound and at-most-once; `None` until the eD2k layer
    /// registers it.
    foreign_datagram_handler: OnceLock<ForeignDatagramHandler>,
    global_rate_limiter: RateLimiter,
    interactive_rate_limiter: RateLimiter,
    harvest_rate_limiter: RateLimiter,
    maintenance_rate_limiter: RateLimiter,
    publish_rate_limiter: RateLimiter,
    max_outbound_pps: u32,
    class_budgets: RpcClassBudgetConfig,
    tracker: Mutex<PacketTracker>,
    outbound_tracker: Mutex<OutboundRequestTracker>,
    pending: Mutex<HashMap<u64, PendingEntry>>,
    next_id: AtomicU64,
    unsolicited_tx: broadcast::Sender<ReceivedKadPacket>,
    observability: Mutex<RpcObservabilityState>,
    massive_flood_handler: Option<MassiveFloodHandler>,
}

pub struct RpcManager {
    inner: Arc<RpcInner>,
}

impl Clone for RpcManager {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl RpcManager {
    /// Create a new RpcManager. Call `start()` to begin receiving.
    pub fn new(
        transport: impl Transport,
        obfuscation: ObfuscationLayer,
        config: RpcConfig,
    ) -> Self {
        let (unsolicited_tx, _) = broadcast::channel(config.broadcast_capacity);
        let inner = Arc::new(RpcInner {
            transport: Arc::new(transport),
            obfuscation,
            foreign_datagram_handler: OnceLock::new(),
            global_rate_limiter: RateLimiter::new(config.max_outbound_pps),
            interactive_rate_limiter: RateLimiter::new(
                config
                    .class_budgets
                    .max_outbound_pps_for(RpcWorkClass::Interactive),
            ),
            harvest_rate_limiter: RateLimiter::new(
                config
                    .class_budgets
                    .max_outbound_pps_for(RpcWorkClass::Harvest),
            ),
            maintenance_rate_limiter: RateLimiter::new(
                config
                    .class_budgets
                    .max_outbound_pps_for(RpcWorkClass::Maintenance),
            ),
            publish_rate_limiter: RateLimiter::new(
                config
                    .class_budgets
                    .max_outbound_pps_for(RpcWorkClass::Publish),
            ),
            max_outbound_pps: config.max_outbound_pps,
            class_budgets: config.class_budgets,
            tracker: Mutex::new(PacketTracker::new(
                config.max_inbound_per_ip,
                config.max_inbound_search_res_per_ip,
                config.flood_window,
                config.request_tracking_window,
            )),
            outbound_tracker: Mutex::new(OutboundRequestTracker::new(Duration::from_secs(180))),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            unsolicited_tx,
            observability: Mutex::new(RpcObservabilityState::default()),
            massive_flood_handler: config.massive_flood_handler,
        });
        Self { inner }
    }

    /// Register a handler for inbound datagrams that are not Kad packets (e.g.
    /// eD2k client UDP reask sharing the Kad port). Late-bound and at-most-once;
    /// returns `false` if a handler was already set. Until set, such datagrams
    /// follow the unchanged Kad decode-failure path.
    pub fn set_foreign_datagram_handler(&self, handler: ForeignDatagramHandler) -> bool {
        self.inner.foreign_datagram_handler.set(handler).is_ok()
    }

    /// Send an already-framed datagram on the shared UDP socket. For eD2k client
    /// UDP reask sharing the Kad port: the bytes are framed + obfuscated by the
    /// eD2k layer and must NOT be Kad-encoded, so this bypasses Kad packet
    /// construction and the caller owns all framing. Pairs with
    /// [`Self::set_foreign_datagram_handler`] for the reply/ticker send path.
    pub async fn send_raw_datagram(
        &self,
        addr: SocketAddr,
        data: &[u8],
    ) -> Result<(), crate::error::NetError> {
        self.inner.transport.send_raw(addr, data).await
    }
}

#[cfg(test)]
mod tests;
