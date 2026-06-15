//! Stateful Kad node runtime built on top of routing, transport, and traversal.
//!
//! `DhtNode` owns the local node identity, the routing table, and the RPC
//! manager. Public methods here represent observable protocol operations such as
//! bootstrap, lookup, search, and publish, so their docs should explain the
//! wire-facing role of each call rather than only the local implementation.

mod bootstrap;
mod config;
mod contact_helpers;
mod legacy_challenge;
mod publish;
mod routing;
mod search;
mod transport;

use legacy_challenge::LegacyChallengeTracker;

pub use config::DhtConfig;
use contact_helpers::expire_contact_for_massive_flood;

use crate::error::DhtError;
use emulebb_kad_net::{
    ForeignDatagramHandler, ObfuscationLayer, ReceivedKadPacket, RpcConfig, RpcManager,
    RpcObservabilitySnapshot, UdpTransport,
};
use emulebb_kad_proto::{KadUdpKey, NodeId};
use emulebb_kad_routing::RoutingTable;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::{Mutex, Semaphore};

struct DhtInner {
    own_id: NodeId,
    routing_table: Arc<Mutex<RoutingTable>>,
    rpc: RpcManager,
    config: DhtConfig,
    /// Semaphore for limiting concurrent searches. Reserved for future use.
    #[allow(dead_code)]
    semaphore: Semaphore,
    bootstrapped: std::sync::atomic::AtomicBool,
    /// Pending pre-v8 contact-verification challenges (oracle
    /// `CPacketTracking::listChallengeRequests`).
    legacy_challenges: Mutex<LegacyChallengeTracker>,
}

/// The top-level DHT node. Clone-able (backed by Arc).
pub struct DhtNode {
    inner: Arc<DhtInner>,
}

impl Clone for DhtNode {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl DhtNode {
    /// Create a new DhtNode. Does NOT bind the socket or start any tasks.
    /// Call `start()` to begin.
    pub async fn new(mut config: DhtConfig) -> Result<Self, DhtError> {
        use rand::Rng;

        // Generate random node ID if not set
        if config.node_id == NodeId::ZERO {
            let bytes: [u8; 16] = rand::thread_rng().r#gen();
            config.node_id = NodeId::from_bytes(bytes);
        }

        // Generate random UDP key if not set
        if config.udp_key == 0 {
            config.udp_key = rand::thread_rng().r#gen();
        }

        let bind_addr = config.bind_addr.ok_or(DhtError::MissingBindAddr)?;
        // Pin the Kad UDP socket's egress to the VPN tunnel interface when known
        // (IP_UNICAST_IF) so split-tunnel routing cannot leak Kad/reask onto LAN.
        let transport = UdpTransport::bind_pinned(bind_addr, config.bind_if_index).await?;
        let obfuscation =
            ObfuscationLayer::new(config.node_id, config.udp_key, config.obfuscation_enabled);
        let routing_table = Arc::new(Mutex::new(RoutingTable::with_max_size(
            config.node_id,
            config.max_routing_table_size,
        )));
        let flood_routing_table = Arc::clone(&routing_table);
        let rpc = RpcManager::new(
            transport,
            obfuscation,
            RpcConfig {
                max_outbound_pps: config.max_outbound_pps,
                class_budgets: config.class_budgets,
                massive_flood_handler: Some(Arc::new(move |addr| {
                    let flood_routing_table = Arc::clone(&flood_routing_table);
                    tokio::spawn(async move {
                        expire_contact_for_massive_flood(&flood_routing_table, addr).await;
                    });
                })),
                ..RpcConfig::default()
            },
        );

        let semaphore = Semaphore::new(config.max_concurrent_searches);

        Ok(Self {
            inner: Arc::new(DhtInner {
                own_id: config.node_id,
                routing_table,
                rpc,
                config,
                semaphore,
                bootstrapped: std::sync::atomic::AtomicBool::new(false),
                legacy_challenges: Mutex::new(LegacyChallengeTracker::default()),
            }),
        })
    }

    /// Start the receive loop. Must be called before any DHT operations.
    /// Returns the JoinHandle for the background task.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        self.inner.rpc.start()
    }

    /// Our node ID.
    pub fn own_id(&self) -> NodeId {
        self.inner.own_id
    }

    /// Our UDP anti-spoofing key.
    pub fn udp_key(&self) -> u32 {
        self.inner.config.udp_key
    }

    /// Derive the Kad UDP verify key we should announce to a specific peer IP.
    pub fn verify_key_for_ip(&self, ip: Ipv4Addr) -> u32 {
        self.inner.rpc.verify_key_for_ip(ip)
    }

    /// Return the latest peer UDP key learned for this endpoint's IP, when available.
    pub fn known_peer_key(&self, addr: SocketAddr) -> Option<KadUdpKey> {
        self.inner.rpc.known_peer_key(addr).map(KadUdpKey::new)
    }

    /// Actual UDP bind address.
    pub fn bind_addr(&self) -> Result<SocketAddr, DhtError> {
        Ok(self.inner.rpc.local_addr()?)
    }

    /// Current routing table size.
    pub fn routing_table_size(&self) -> usize {
        match self.inner.routing_table.try_lock() {
            Ok(rt) => rt.len(),
            Err(_) => 0,
        }
    }

    /// True if the routing table has enough contacts to operate.
    pub fn is_bootstrapped(&self) -> bool {
        self.inner
            .bootstrapped
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Subscribe to unsolicited incoming Kad packets.
    pub fn subscribe_packets(&self) -> broadcast::Receiver<ReceivedKadPacket> {
        self.inner.rpc.subscribe()
    }

    /// Snapshot Kad RPC tracker behavior for operator-facing observability.
    #[must_use]
    pub fn rpc_observability(&self) -> RpcObservabilitySnapshot {
        self.inner.rpc.observability()
    }

    /// Register a handler for inbound UDP datagrams that are not Kad packets —
    /// e.g. eD2k client UDP reask sharing the Kad port. Pass-through to the inner
    /// RPC manager; at-most-once, `None` until set (no foreign handling). See
    /// `RpcManager::set_foreign_datagram_handler`.
    pub fn set_foreign_datagram_handler(&self, handler: ForeignDatagramHandler) -> bool {
        self.inner.rpc.set_foreign_datagram_handler(handler)
    }

    /// Send an already-framed datagram on the shared Kad UDP socket without Kad
    /// encoding — for eD2k reask replies + the per-transfer ticker. Pass-through
    /// to `RpcManager::send_raw_datagram`.
    pub async fn send_raw_datagram(
        &self,
        addr: SocketAddr,
        data: &[u8],
    ) -> Result<(), DhtError> {
        self.inner.rpc.send_raw_datagram(addr, data).await?;
        Ok(())
    }
}
