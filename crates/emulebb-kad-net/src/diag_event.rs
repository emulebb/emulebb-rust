//! Shared diagnostic-event facade plus Kad-specific typed helpers.

use serde_json::Value;

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

#[cfg(feature = "packet-diagnostics")]
pub fn kad_event_bootstrap_contact_added(peer: std::net::SocketAddr) {
    emit(
        "kad_event",
        "bootstrap",
        "info",
        serde_json::json!({ "peer": peer.to_string() }),
        serde_json::json!({ "milestone": "bootstrap_contact_added", "action": "observe" }),
    );
}

#[cfg(not(feature = "packet-diagnostics"))]
pub fn kad_event_bootstrap_contact_added(_peer: std::net::SocketAddr) {}

#[cfg(feature = "packet-diagnostics")]
pub fn bad_peer_kad_drop(
    event: &'static str,
    severity: &'static str,
    behavior: &'static str,
    reason: &str,
    peer: std::net::SocketAddr,
    repeat_count: u32,
    window_seconds: u64,
) {
    emit(
        "bad_peer",
        event,
        severity,
        serde_json::json!({ "peer": peer.to_string() }),
        serde_json::json!({
            "behavior": behavior,
            "action": bad_peer_action_for_behavior(behavior),
            "reason": reason,
            "repeatCount": repeat_count,
            "windowSeconds": window_seconds,
        }),
    );
}

#[cfg(not(feature = "packet-diagnostics"))]
pub fn bad_peer_kad_drop(
    _event: &'static str,
    _severity: &'static str,
    _behavior: &'static str,
    _reason: &str,
    _peer: std::net::SocketAddr,
    _repeat_count: u32,
    _window_seconds: u64,
) {
}

#[cfg(any(feature = "packet-diagnostics", test))]
fn bad_peer_action_for_behavior(behavior: &str) -> &'static str {
    if behavior == "anti_flood_ban" {
        "ban"
    } else {
        "drop"
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bad_peer_action_for_behavior, bad_peer_kad_drop, kad_event_bootstrap_contact_added,
    };

    #[test]
    fn bad_peer_action_matches_behavior() {
        assert_eq!(bad_peer_action_for_behavior("anti_flood_ban"), "ban");
        assert_eq!(bad_peer_action_for_behavior("anti_flood_drop"), "drop");
        assert_eq!(bad_peer_action_for_behavior("other_bad_peer"), "drop");
    }

    #[test]
    fn typed_helpers_emit_without_panicking() {
        kad_event_bootstrap_contact_added("1.2.3.4:4672".parse().unwrap());
        bad_peer_kad_drop(
            "anti_flood_ban",
            "high",
            "anti_flood_ban",
            "tracker_massive_drop",
            "5.6.7.8:4672".parse().unwrap(),
            42,
            10,
        );
        bad_peer_kad_drop(
            "anti_flood_drop",
            "medium",
            "anti_flood_drop",
            "tracker_drop",
            "5.6.7.8:4672".parse().unwrap(),
            7,
            10,
        );
    }
}
