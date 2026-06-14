//! Kad UDP transport, obfuscation, request tracking, and wire-dump support.
//!
//! This crate owns the state machines that sit between raw UDP datagrams and
//! typed Kad packets. The exported API is intentionally small because the
//! observable behavior is mostly in transport mode selection, pending-request
//! tracking, and flood handling.

pub mod error;
pub mod obfuscation;
pub mod rate_limit;
pub mod rpc;
pub mod tracker;
pub mod transport;
mod wire_dump;

pub use error::NetError;
pub use obfuscation::ObfuscationLayer;
pub use rate_limit::RateLimiter;
pub use rpc::{
    ForeignDatagramHandler, ReceivedKadPacket, RpcClassBudgetConfig, RpcConfig, RpcManager,
    RpcObservabilitySnapshot, RpcResponseOpcodeSnapshot, RpcTrackerBucketSnapshot, RpcWorkClass,
    RpcWorkClassSnapshot,
};
pub use tracker::PacketTracker;
pub use transport::{MockTransport, Transport, UdpTransport};
