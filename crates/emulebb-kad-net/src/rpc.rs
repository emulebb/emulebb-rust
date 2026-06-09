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
use std::sync::{Arc, Mutex};
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

struct RpcInner {
    transport: Arc<dyn Transport>,
    obfuscation: ObfuscationLayer,
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
}

#[cfg(test)]
mod tests;
