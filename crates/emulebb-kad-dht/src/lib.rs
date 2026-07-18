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

/// LAN bind IP for tests that open a real socket — always `X_LOCAL_IP`, never a
/// loopback literal (the operator's VPN split tunnel breaks 127.0.0.1 -> os
/// error 10049; CI exports `X_LOCAL_IP=127.0.0.1`). Panics if unset so the
/// loopback habit can't creep back in via a silent default.
#[cfg(test)]
pub(crate) fn test_bind_ip() -> std::net::Ipv4Addr {
    std::env::var("X_LOCAL_IP")
        .expect("X_LOCAL_IP must be set for emulebb-kad-dht socket-binding tests")
        .parse()
        .expect("X_LOCAL_IP must be an IPv4 address")
}
