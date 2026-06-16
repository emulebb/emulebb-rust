//! Stateful Kad node runtime built on top of routing, transport, and traversal.
//!
//! `DhtNode` owns the local node identity, the routing table, and the RPC
//! manager. Public methods here represent observable protocol operations such as
//! bootstrap, lookup, search, and publish, so their docs should explain the
//! wire-facing role of each call rather than only the local implementation.

mod bootstrap;
pub(crate) mod concurrency;
mod config;
mod contact_helpers;
mod legacy_challenge;
mod publish;
mod routing;
mod search;
mod transport;

use concurrency::SearchConcurrency;
use legacy_challenge::LegacyChallengeTracker;

pub use config::DhtConfig;
use contact_helpers::expire_contact_for_massive_flood;

use crate::error::DhtError;
use emulebb_kad_net::{
    ForeignDatagramHandler, ObfuscationLayer, ReceivedKadPacket, RpcConfig, RpcManager,
    RpcObservabilitySnapshot, UdpTransport,
};
use emulebb_kad_proto::{KadUdpKey, NodeId};
use emulebb_kad_routing::{Contact, RoutingTable};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

struct DhtInner {
    own_id: NodeId,
    routing_table: Arc<Mutex<RoutingTable>>,
    rpc: RpcManager,
    config: DhtConfig,
    /// Per-target dedup + bounded concurrency for search/publish traversals
    /// (oracle `CSearchManager::AlreadySearchingFor` + the concurrent-search
    /// cap). Acquired around every `run_traversal` invocation.
    search_concurrency: SearchConcurrency,
    bootstrapped: std::sync::atomic::AtomicBool,
    /// Pending pre-v8 contact-verification challenges (oracle
    /// `CPacketTracking::listChallengeRequests`).
    legacy_challenges: Mutex<LegacyChallengeTracker>,
    /// Optional per-`RES`-contact ip-filter hook, bridged from the live ed2k
    /// `IpFilter` by core at startup (set once). Applied in traversal's
    /// `sanitize_res_contacts` (oracle KademliaUDPListener.cpp:830-857).
    ip_filter: std::sync::OnceLock<crate::traversal::KadIpFilter>,
    /// Sender side of the RES-contact ingestion channel (oracle `AddUnfiltered`):
    /// every good RES contact learned during any traversal is forwarded here and
    /// drained into the routing table by the task spawned in [`DhtNode::start`].
    res_contact_tx: mpsc::UnboundedSender<LearnedResContact>,
}

/// A good `KADEMLIA2_RES` contact learned during traversal, carried over the
/// ingestion channel to the routing-table drain task (oracle `AddUnfiltered`).
#[derive(Debug, Clone, Copy)]
struct LearnedResContact {
    id: NodeId,
    ip: Ipv4Addr,
    udp_port: u16,
    tcp_port: u16,
    version: u8,
}

/// Routing-table contact counts for the `kad_event` `routing_summary`
/// diagnostic. Mirrors the oracle `SKadContactSummary` `total` / `verified` /
/// `with_udp_key` fields used by the master's `LogRoutingSummary`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KadRoutingSummaryCounts {
    /// Total routing-table contacts (oracle `total`).
    pub total: usize,
    /// Contacts that completed the verified path (oracle `verified`).
    pub verified: usize,
    /// Contacts carrying a non-zero peer UDP anti-spoofing key (oracle
    /// `with_udp_key`).
    pub with_udp_key: usize,
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

        let search_concurrency = SearchConcurrency::new(config.max_concurrent_searches);

        // RES-contact ingestion channel (oracle AddUnfiltered): a dedicated drain
        // task owns the routing-table add-path so traversal can fire-and-forget
        // every good RES contact without blocking the lookup loop on the lock.
        let (res_contact_tx, res_contact_rx) = mpsc::unbounded_channel::<LearnedResContact>();
        spawn_res_contact_drain(Arc::clone(&routing_table), rpc.clone(), res_contact_rx);

        Ok(Self {
            inner: Arc::new(DhtInner {
                own_id: config.node_id,
                routing_table,
                rpc,
                config,
                search_concurrency,
                bootstrapped: std::sync::atomic::AtomicBool::new(false),
                legacy_challenges: Mutex::new(LegacyChallengeTracker::default()),
                ip_filter: std::sync::OnceLock::new(),
                res_contact_tx,
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

    /// Routing-table contact counts for the `kad_event` `routing_summary`
    /// diagnostic (uniform-diagnostics-v2): total contacts, the verified subset,
    /// and the subset carrying a non-zero peer UDP anti-spoofing key. Mirrors the
    /// oracle `SKadContactSummary` `total` / `verified` / `with_udp_key` fields.
    pub async fn routing_summary_counts(&self) -> KadRoutingSummaryCounts {
        let rt = self.inner.routing_table.lock().await;
        let mut counts = KadRoutingSummaryCounts {
            total: rt.len(),
            verified: 0,
            with_udp_key: 0,
        };
        for contact in rt.all_contacts() {
            if contact.verified {
                counts.verified += 1;
            }
            if contact.udp_key != KadUdpKey::ZERO {
                counts.with_udp_key += 1;
            }
        }
        counts
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

    /// Install the per-`RES`-contact ip-filter hook (bridged from the live ed2k
    /// `IpFilter` by core). Set-once at startup; a later call is a no-op (returns
    /// `false`). Traversal applies it in `sanitize_res_contacts` to drop
    /// filtered/banned IPs from `RES` answers (oracle KademliaUDPListener.cpp
    /// per-contact `IsFiltered` drop).
    pub fn set_ip_filter(&self, filter: crate::traversal::KadIpFilter) -> bool {
        self.inner.ip_filter.set(filter).is_ok()
    }

    /// The installed ip-filter hook, if any, cloned for a traversal config.
    pub(crate) fn ip_filter(&self) -> Option<crate::traversal::KadIpFilter> {
        self.inner.ip_filter.get().cloned()
    }

    /// A RES-contact sink bound to this node's routing-table ingestion channel
    /// (oracle `AddUnfiltered`). Threaded into every traversal config the node
    /// builds so good RES contacts populate the routing table as they arrive.
    pub(crate) fn res_contact_sink(&self) -> crate::traversal::KadResContactSink {
        let tx = self.inner.res_contact_tx.clone();
        Arc::new(move |entry: &emulebb_kad_proto::packet::ContactEntry| {
            // Skip obviously unusable entries (the traversal sanitizer already
            // dropped Kad1/filtered/clustered ones, but guard the basics).
            if entry.ip == 0 || entry.udp_port == 0 {
                return;
            }
            let tcp_port = if entry.tcp_port != 0 {
                entry.tcp_port
            } else {
                entry.udp_port
            };
            // Fire-and-forget: a closed channel just means the node is shutting
            // down, so a dropped contact is harmless.
            let _ = tx.send(LearnedResContact {
                id: entry.node_id,
                ip: entry.ip_addr(),
                udp_port: entry.udp_port,
                tcp_port,
                version: entry.version,
            });
        })
    }

    /// Acquire a per-target search/publish concurrency permit (oracle
    /// `CSearchManager::AlreadySearchingFor` + concurrent-search cap).
    ///
    /// Returns `None` when a traversal for the same target is already in flight,
    /// so the caller drops/coalesces the duplicate; otherwise it waits for a free
    /// concurrency slot and returns an RAII permit that frees the slot and the
    /// target on drop (every exit path, including unwind).
    pub(crate) async fn acquire_search_permit(
        &self,
        target: NodeId,
    ) -> Option<concurrency::SearchPermit> {
        self.inner.search_concurrency.acquire(target).await
    }

    /// A clone of this node's search/publish concurrency guard, for the streaming
    /// search builders that acquire the permit inside their spawned task (they
    /// return the stream synchronously and so cannot `.await` here).
    pub(crate) fn search_concurrency(&self) -> concurrency::SearchConcurrency {
        self.inner.search_concurrency.clone()
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

/// Drain learned `RES` contacts into the routing table (oracle `AddUnfiltered`).
///
/// Runs for the life of the node; exits when every sender is dropped. Each
/// contact passes through the same routing-table guards as any other add (IP /
/// `/24` limits, anti-hijack UDP-key update rule in `RoutingBin::try_add`, and
/// the full+unsplittable weak-replacement path), so the only difference from the
/// final-closest-set add is that *every* answered contact is offered, not just
/// the ones that survive into the lookup result.
fn spawn_res_contact_drain(
    routing_table: Arc<Mutex<RoutingTable>>,
    rpc: RpcManager,
    mut rx: mpsc::UnboundedReceiver<LearnedResContact>,
) {
    tokio::spawn(async move {
        while let Some(learned) = rx.recv().await {
            let addr = SocketAddr::new(IpAddr::V4(learned.ip), learned.udp_port);
            // Register the peer identity/version so subsequent sends carry the
            // right id/version, mirroring DhtNode::add_contact.
            rpc.register_peer_identity(addr, learned.id);
            rpc.register_peer_version(addr, learned.version);
            let mut contact = Contact::new(
                learned.id,
                learned.ip,
                learned.udp_port,
                learned.tcp_port,
                learned.version,
            );
            // Carry the latest known anti-spoof key for this IP, if any, so the
            // anti-hijack update guard is satisfied on a refresh.
            if let Some(key) = rpc.known_peer_key(addr) {
                contact.udp_key = KadUdpKey::new(key);
            }
            let _ = routing_table.lock().await.add_contact(contact);
        }
    });
}
