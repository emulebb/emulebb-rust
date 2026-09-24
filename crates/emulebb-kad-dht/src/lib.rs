pub mod bootstrap;
pub mod error;
pub mod node;
pub mod publish;
pub mod search;
pub mod traversal;
pub mod types;

pub use emulebb_kad_net::{
    ForeignDatagramHandler, ReceivedKadPacket, RpcClassBudgetConfig, RpcObservabilitySnapshot,
    RpcWorkClass, RpcWorkClassSnapshot, socket_opts,
};
pub use error::DhtError;
pub use node::{DhtConfig, DhtNode, KadRoutingContactSnapshot, KadRoutingSummaryCounts};
pub use publish::{KeywordPublishEntry, PublishAttemptStats};
pub use types::{FirewallCheckHelper, NoteResult, SearchResult, SourceResult};

/// Same-machine bind IP for tests that open a real socket.
#[cfg(test)]
pub(crate) fn test_bind_ip() -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::LOCALHOST
}
