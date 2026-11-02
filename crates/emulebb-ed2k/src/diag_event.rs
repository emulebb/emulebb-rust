//! Shared diagnostic-event facade for eD2K and core producers.
//!
//! Serialization, process-wide sequencing, segmented rotation, retention, and
//! writer health live in the dependency-neutral `emulebb-diagnostics` crate.

use std::net::SocketAddr;

use emulebb_kad_proto::NodeId;
use serde_json::{Value, json};

pub use emulebb_diagnostics::DiagWriterHealth;

pub fn emit(
    family: &'static str,
    event: &'static str,
    severity: &'static str,
    keys: Value,
    body: Value,
) {
    let _ = emulebb_diagnostics::emit(family, event, severity, keys, body);
}

pub fn writer_health() -> DiagWriterHealth {
    emulebb_diagnostics::writer_health()
}

pub fn kad_buddy_socket_attached(
    peer: SocketAddr,
    peer_hash: [u8; 16],
    buddy_id: NodeId,
    advertised_tcp_port: u16,
) {
    emit(
        "kad_event",
        "buddy_socket",
        "info",
        json!({
            "peer": peer.to_string(),
            "peerHash": hex::encode(peer_hash),
        }),
        json!({
            "milestone": "buddy_socket_attached",
            "action": "attach",
            "outcome": "attached",
            "buddyId": buddy_id.to_string(),
            "clientHash": hex::encode(peer_hash),
            "advertisedTcpPort": advertised_tcp_port,
        }),
    );
}
