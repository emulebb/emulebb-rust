use emulebb_kad_net::RpcClassBudgetConfig;
use emulebb_kad_proto::NodeId;
use std::net::SocketAddr;
use std::time::Duration;

/// Configuration for DhtNode.
#[derive(Debug, Clone)]
pub struct DhtConfig {
    /// UDP bind address.
    pub bind_addr: SocketAddr,
    /// Our Kad2 node ID. All-zeros = generate random on start.
    pub node_id: NodeId,
    /// Max contacts in routing table.
    pub max_routing_table_size: usize,
    /// Minimum number of routing contacts required before the node is treated as bootstrapped.
    pub bootstrap_min_routing_contacts: usize,
    /// Max concurrent searches (semaphore).
    pub max_concurrent_searches: usize,
    /// Search timeout.
    pub search_timeout: Duration,
    /// Store/publish timeout.
    pub store_timeout: Duration,
    /// Republish interval.
    pub republish_interval: Duration,
    /// Maximum number of closest contacts to publish to per publish round.
    pub publish_contact_fanout: usize,
    /// Max outbound packets per second. 0 = unlimited.
    pub max_outbound_pps: u32,
    /// Per-class outbound budgets layered underneath `max_outbound_pps`.
    pub class_budgets: RpcClassBudgetConfig,
    /// Max number of phase-2 search packets to send after traversal.
    pub search_phase2_fanout: usize,
    /// Harvest-oriented keyword result cap.
    pub keyword_result_cap: usize,
    /// Harvest-oriented source result cap.
    pub source_result_cap: usize,
    /// Harvest-oriented notes result cap.
    pub notes_result_cap: usize,
    /// Obfuscation enabled.
    pub obfuscation_enabled: bool,
    /// Our UDP key (anti-spoofing). 0 = generate random.
    pub udp_key: u32,
    /// Bootstrap sources: binary nodes.dat content.
    pub nodes_dat: Option<Vec<u8>>,
    /// Bootstrap sources: plain text format.
    pub nodes_text: Option<String>,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:4672".parse().unwrap(),
            node_id: NodeId::ZERO,
            max_routing_table_size: 12000,
            bootstrap_min_routing_contacts: 10,
            max_concurrent_searches: 5,
            search_timeout: Duration::from_secs(45),
            store_timeout: Duration::from_secs(140),
            republish_interval: Duration::from_secs(18000),
            publish_contact_fanout: 4,
            max_outbound_pps: 8,
            class_budgets: RpcClassBudgetConfig::default(),
            search_phase2_fanout: 50,
            keyword_result_cap: 5000,
            source_result_cap: 1000,
            notes_result_cap: 1000,
            obfuscation_enabled: true,
            udp_key: 0,
            nodes_dat: None,
            nodes_text: None,
        }
    }
}
