//! Shared diagnostic-event facade plus Kad-specific typed helpers.

use serde_json::Value;
use std::{net::SocketAddr, time::Duration};

use crate::rpc::RpcWorkClass;

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
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the diagnostic event contract"
)]
pub(crate) fn kad_rpc_lifecycle(
    request_id: u64,
    peer: SocketAddr,
    request_opcode: u8,
    expected_opcode: u8,
    response_opcode: Option<u8>,
    work_class: RpcWorkClass,
    timeout_duration: Duration,
    elapsed: Duration,
    outcome: &'static str,
    detail: Option<&str>,
) {
    let (severity, keys, body) = kad_rpc_event_parts(
        request_id,
        peer,
        request_opcode,
        expected_opcode,
        response_opcode,
        work_class,
        timeout_duration,
        elapsed,
        outcome,
        detail,
    );
    emit("kad_event", "rpc", severity, keys, body);
}

#[cfg(not(feature = "packet-diagnostics"))]
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the diagnostic event contract"
)]
pub(crate) fn kad_rpc_lifecycle(
    _request_id: u64,
    _peer: SocketAddr,
    _request_opcode: u8,
    _expected_opcode: u8,
    _response_opcode: Option<u8>,
    _work_class: RpcWorkClass,
    _timeout_duration: Duration,
    _elapsed: Duration,
    _outcome: &'static str,
    _detail: Option<&str>,
) {
}

#[cfg(any(feature = "packet-diagnostics", test))]
#[expect(
    clippy::too_many_arguments,
    reason = "builds one complete diagnostic event"
)]
fn kad_rpc_event_parts(
    request_id: u64,
    peer: SocketAddr,
    request_opcode: u8,
    expected_opcode: u8,
    response_opcode: Option<u8>,
    work_class: RpcWorkClass,
    timeout_duration: Duration,
    elapsed: Duration,
    outcome: &'static str,
    detail: Option<&str>,
) -> (&'static str, Value, Value) {
    let severity = match outcome {
        "attempted" | "response" => "info",
        _ => "warning",
    };
    let mut body = serde_json::json!({
        "milestone": "rpc_request",
        "action": outcome,
        "outcome": outcome,
        "requestOpcode": request_opcode,
        "expectedOpcode": expected_opcode,
        "workClass": work_class.label(),
        "timeoutMillis": timeout_duration.as_millis(),
        "elapsedMillis": elapsed.as_millis(),
    });
    if let Some(response_opcode) = response_opcode {
        body["responseOpcode"] = serde_json::json!(response_opcode);
    }
    if let Some(detail) = detail {
        body["detail"] = serde_json::json!(detail);
    }
    (
        severity,
        serde_json::json!({
            "requestId": request_id,
            "peer": peer.to_string(),
        }),
        body,
    )
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
        kad_rpc_event_parts,
    };
    use crate::rpc::RpcWorkClass;
    use std::time::Duration;

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

    #[test]
    fn kad_rpc_event_carries_stable_request_lifecycle_context() {
        let peer = "198.51.100.2:4672".parse().unwrap();
        let (severity, keys, body) = kad_rpc_event_parts(
            42,
            peer,
            0x21,
            0x29,
            Some(0x29),
            RpcWorkClass::Interactive,
            Duration::from_secs(5),
            Duration::from_millis(125),
            "response",
            None,
        );

        assert_eq!(severity, "info");
        assert_eq!(keys["requestId"], 42);
        assert_eq!(keys["peer"], peer.to_string());
        assert_eq!(body["milestone"], "rpc_request");
        assert_eq!(body["action"], "response");
        assert_eq!(body["requestOpcode"], 0x21);
        assert_eq!(body["expectedOpcode"], 0x29);
        assert_eq!(body["responseOpcode"], 0x29);
        assert_eq!(body["workClass"], "interactive");
        assert_eq!(body["timeoutMillis"], 5_000);
        assert_eq!(body["elapsedMillis"], 125);
    }
}
