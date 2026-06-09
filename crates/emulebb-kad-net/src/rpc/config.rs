use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Callback invoked when the tracker hits the oracle's massive-flood tier.
pub type MassiveFloodHandler = Arc<dyn Fn(SocketAddr) + Send + Sync>;

/// Logical outbound work class used for Kad scheduling and observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpcWorkClass {
    Interactive,
    Harvest,
    Maintenance,
    Publish,
}

impl RpcWorkClass {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Harvest => "harvest",
            Self::Maintenance => "maintenance",
            Self::Publish => "publish",
        }
    }
}

/// Per-class packet budgets layered underneath the global outbound safety cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcClassBudgetConfig {
    pub interactive_max_outbound_pps: u32,
    pub harvest_max_outbound_pps: u32,
    pub maintenance_max_outbound_pps: u32,
    pub publish_max_outbound_pps: u32,
}

impl RpcClassBudgetConfig {
    #[must_use]
    pub fn max_outbound_pps_for(self, work_class: RpcWorkClass) -> u32 {
        match work_class {
            RpcWorkClass::Interactive => self.interactive_max_outbound_pps,
            RpcWorkClass::Harvest => self.harvest_max_outbound_pps,
            RpcWorkClass::Maintenance => self.maintenance_max_outbound_pps,
            RpcWorkClass::Publish => self.publish_max_outbound_pps,
        }
    }
}

impl Default for RpcClassBudgetConfig {
    fn default() -> Self {
        Self {
            interactive_max_outbound_pps: 4,
            harvest_max_outbound_pps: 1,
            maintenance_max_outbound_pps: 1,
            publish_max_outbound_pps: 1,
        }
    }
}

/// Configuration for RpcManager.
pub struct RpcConfig {
    /// Max outbound packets per second. 0 = unlimited.
    pub max_outbound_pps: u32,
    /// Per-class budgets layered underneath `max_outbound_pps`.
    pub class_budgets: RpcClassBudgetConfig,
    /// Max inbound control packets per IP per flood window before flood-blocking.
    pub max_inbound_per_ip: u32,
    /// Max inbound SEARCH_RES packets per IP per second before flood-blocking.
    pub max_inbound_search_res_per_ip: u32,
    /// Duration for flood-tracking window.
    pub flood_window: Duration,
    /// Duration for oracle-shaped inbound search/publish request tracking.
    pub request_tracking_window: Duration,
    /// Capacity of the unsolicited broadcast channel.
    pub broadcast_capacity: usize,
    /// Optional callback fired when a tracked request crosses the oracle's
    /// massive-flood threshold and should trigger contact expiry.
    pub massive_flood_handler: Option<MassiveFloodHandler>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            max_outbound_pps: 8,
            class_budgets: RpcClassBudgetConfig::default(),
            max_inbound_per_ip: 20,
            max_inbound_search_res_per_ip: 256,
            flood_window: Duration::from_secs(1),
            request_tracking_window: Duration::from_secs(60),
            broadcast_capacity: 256,
            massive_flood_handler: None,
        }
    }
}
