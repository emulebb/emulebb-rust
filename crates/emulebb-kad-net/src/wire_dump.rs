//! Unified Kad UDP diagnostics for protocol parity work.

use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum KadUdpOutcome {
    #[default]
    Accepted,
    Dropped,
    SendSucceeded,
    SendFailed,
    SendRejected,
}

impl KadUdpOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Dropped => "dropped",
            Self::SendSucceeded => "send_succeeded",
            Self::SendFailed => "send_failed",
            Self::SendRejected => "send_rejected",
        }
    }

    fn is_failure(self) -> bool {
        matches!(self, Self::Dropped | Self::SendFailed | Self::SendRejected)
    }
}

/// Stable metadata emitted for a single Kad UDP packet dump line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KadUdpDumpSummary {
    /// Kad protocol header byte after decode.
    pub protocol: Option<u8>,
    /// Kad opcode, when available.
    pub opcode: Option<u8>,
    /// Stable Kad opcode label, when available.
    pub opcode_name: Option<&'static str>,
    /// Whether the raw on-wire packet used Kad obfuscation.
    pub raw_obfuscated: bool,
    /// Final transport mode bucket used on the wire.
    pub transport_mode: Option<&'static str>,
    /// Whether the sender explicitly requested obfuscation for this packet.
    pub requested_obfuscation: Option<bool>,
    /// Receiver verify key referenced by the packet, when known.
    pub receiver_verify_key: Option<u32>,
    /// Sender verify key carried by the packet, when known.
    pub sender_verify_key: Option<u32>,
    /// Whether the inbound packet proved our receiver verify key.
    pub receiver_verify_key_valid: Option<bool>,
    /// Matched or inferred paired request opcode for a response, when known.
    pub tracked_request_opcode: Option<&'static str>,
    /// Stable drop reason recorded at the receive boundary, when the packet was not accepted.
    pub drop_reason: Option<&'static str>,
    /// Exact local diagnostic detail for decode or policy failures.
    pub detail: Option<String>,
    /// Terminal disposition for this receive or send operation.
    pub outcome: KadUdpOutcome,
    /// Oracle-shaped tracker bucket label, when one applied.
    pub tracker_bucket: Option<&'static str>,
    /// Oracle-shaped tracker action label, when a tracked inbound request was classified.
    pub tracker_action: Option<&'static str>,
    /// Number of packets observed in the current tracker window for this bucket.
    pub tracker_observed_packets: Option<u32>,
    /// Maximum packets allowed in the current tracker window for this bucket.
    pub tracker_max_packets: Option<u32>,
}

fn udp_trace_key(peer: SocketAddr) -> String {
    format!("kad:{}", peer)
}

fn udp_state_label(summary: &KadUdpDumpSummary) -> String {
    summary
        .opcode_name
        .map(str::to_string)
        .unwrap_or_else(|| "packet".to_string())
}

fn udp_state_id(direction: &str, summary: &KadUdpDumpSummary) -> String {
    format!(
        "kad.{}.{}",
        direction,
        summary.opcode_name.unwrap_or("packet").to_ascii_lowercase()
    )
}

/// Emit one exact Kad UDP packet record to the bounded unified diagnostics stream.
#[cfg(feature = "packet-diagnostics")]
pub fn dump_kad_udp_packet(
    direction: &'static str,
    peer: SocketAddr,
    wire_payload: &[u8],
    decoded_payload: &[u8],
    summary: KadUdpDumpSummary,
) {
    emit_kad_udp_diag_event(direction, peer, wire_payload, decoded_payload, &summary);
}

#[cfg(not(feature = "packet-diagnostics"))]
pub fn dump_kad_udp_packet(
    _direction: &'static str,
    _peer: SocketAddr,
    _wire_payload: &[u8],
    _decoded_payload: &[u8],
    _summary: KadUdpDumpSummary,
) {
}

#[cfg(feature = "packet-diagnostics")]
fn emit_kad_udp_diag_event(
    direction: &'static str,
    peer: SocketAddr,
    wire_payload: &[u8],
    decoded_payload: &[u8],
    summary: &KadUdpDumpSummary,
) {
    let (severity, keys, body) =
        kad_udp_diag_event_parts(direction, peer, wire_payload, decoded_payload, summary);
    crate::diag_event::emit("kad_udp", "packet", severity, keys, body);
}

#[cfg(any(feature = "packet-diagnostics", test))]
fn kad_udp_diag_event_parts(
    direction: &'static str,
    peer: SocketAddr,
    wire_payload: &[u8],
    decoded_payload: &[u8],
    summary: &KadUdpDumpSummary,
) -> (&'static str, serde_json::Value, serde_json::Value) {
    let severity = if summary.outcome.is_failure() {
        "warning"
    } else {
        "info"
    };
    let mut keys = serde_json::Map::new();
    keys.insert("peer".to_string(), serde_json::json!(peer.to_string()));
    if let Some(protocol) = summary.protocol {
        keys.insert("protocolMarker".to_string(), serde_json::json!(protocol));
    }
    if let Some(opcode) = summary.opcode {
        keys.insert("opcode".to_string(), serde_json::json!(opcode));
    }

    let mut body = serde_json::Map::new();
    body.insert("direction".to_string(), serde_json::json!(direction));
    body.insert(
        "outcome".to_string(),
        serde_json::json!(summary.outcome.as_str()),
    );
    body.insert(
        "traceKey".to_string(),
        serde_json::json!(udp_trace_key(peer)),
    );
    body.insert(
        "stateId".to_string(),
        serde_json::json!(udp_state_id(direction, summary)),
    );
    body.insert(
        "stateLabel".to_string(),
        serde_json::json!(udp_state_label(summary)),
    );
    body.insert("flow".to_string(), serde_json::json!("kad"));
    if let Some(protocol) = summary.protocol {
        body.insert("protocolMarker".to_string(), serde_json::json!(protocol));
    }
    if let Some(opcode) = summary.opcode {
        body.insert("opcode".to_string(), serde_json::json!(opcode));
    }
    if let Some(opcode_name) = summary.opcode_name {
        body.insert("opcodeName".to_string(), serde_json::json!(opcode_name));
    }
    body.insert("wireLen".to_string(), serde_json::json!(wire_payload.len()));
    body.insert(
        "wireHex".to_string(),
        serde_json::json!(encode_hex_upper(wire_payload)),
    );
    body.insert(
        "decodedLen".to_string(),
        serde_json::json!(decoded_payload.len()),
    );
    body.insert(
        "decodedHex".to_string(),
        serde_json::json!(encode_hex_upper(decoded_payload)),
    );
    body.insert(
        "rawObfuscated".to_string(),
        serde_json::json!(summary.raw_obfuscated),
    );
    if let Some(requested) = summary.requested_obfuscation {
        body.insert(
            "requestedObfuscation".to_string(),
            serde_json::json!(requested),
        );
    }
    if let Some(transport_mode) = summary.transport_mode {
        body.insert(
            "transportMode".to_string(),
            serde_json::json!(transport_mode),
        );
    }
    if let Some(receiver_verify_key) = summary.receiver_verify_key {
        body.insert(
            "receiverVerifyKey".to_string(),
            serde_json::json!(receiver_verify_key),
        );
    }
    if let Some(sender_verify_key) = summary.sender_verify_key {
        body.insert(
            "senderVerifyKey".to_string(),
            serde_json::json!(sender_verify_key),
        );
    }
    if let Some(valid) = summary.receiver_verify_key_valid {
        body.insert(
            "receiverVerifyKeyValid".to_string(),
            serde_json::json!(valid),
        );
    }
    if let Some(tracked) = summary.tracked_request_opcode {
        body.insert(
            "trackedRequestOpcode".to_string(),
            serde_json::json!(tracked),
        );
    }
    if let Some(drop_reason) = summary.drop_reason {
        body.insert("dropReason".to_string(), serde_json::json!(drop_reason));
    }
    if let Some(detail) = summary.detail.as_deref() {
        body.insert("detail".to_string(), serde_json::json!(detail));
    }
    if let Some(tracker_bucket) = summary.tracker_bucket {
        body.insert(
            "trackerBucket".to_string(),
            serde_json::json!(tracker_bucket),
        );
    }
    if let Some(tracker_action) = summary.tracker_action {
        body.insert(
            "trackerAction".to_string(),
            serde_json::json!(tracker_action),
        );
    }
    if let Some(observed_packets) = summary.tracker_observed_packets {
        body.insert(
            "trackerObservedPackets".to_string(),
            serde_json::json!(observed_packets),
        );
    }
    if let Some(max_packets) = summary.tracker_max_packets {
        body.insert(
            "trackerMaxPackets".to_string(),
            serde_json::json!(max_packets),
        );
    }

    (
        severity,
        serde_json::Value::Object(keys),
        serde_json::Value::Object(body),
    )
}

fn encode_hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0F) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{KadUdpDumpSummary, KadUdpOutcome, encode_hex_upper, kad_udp_diag_event_parts};
    use std::net::SocketAddr;

    #[test]
    fn encode_hex_upper_matches_oracle_style() {
        assert_eq!(encode_hex_upper(&[0xE4, 0x21, 0xAB, 0x00]), "E421AB00");
    }

    #[test]
    fn encode_hex_upper_preserves_payloads_larger_than_the_former_cap() {
        let payload = vec![0xAB; 4 * 1024 + 1];
        let encoded = encode_hex_upper(&payload);
        assert_eq!(encoded.len(), payload.len() * 2);
        assert!(encoded.ends_with("AB"));
    }

    #[test]
    fn common_event_keeps_exact_tracker_drop_evidence() {
        let summary = KadUdpDumpSummary {
            protocol: Some(0xE4),
            opcode: Some(0x21),
            opcode_name: Some("KADEMLIA2_HELLO_REQ"),
            raw_obfuscated: true,
            transport_mode: Some("receiver_verify_key"),
            drop_reason: Some("tracker_drop"),
            outcome: KadUdpOutcome::Dropped,
            tracker_bucket: Some("hello_req"),
            tracker_action: Some("drop"),
            tracker_observed_packets: Some(4),
            tracker_max_packets: Some(3),
            ..KadUdpDumpSummary::default()
        };
        let peer: SocketAddr = "198.51.100.1:4672".parse().unwrap();
        let (severity, keys, body) =
            kad_udp_diag_event_parts("recv", peer, &[0xAA, 0xBB], &[0xE4, 0x21], &summary);

        assert_eq!(severity, "warning");
        assert_eq!(keys["peer"], peer.to_string());
        assert_eq!(body["outcome"], "dropped");
        assert_eq!(body["traceKey"], "kad:198.51.100.1:4672");
        assert_eq!(body["stateId"], "kad.recv.kademlia2_hello_req");
        assert_eq!(body["stateLabel"], "KADEMLIA2_HELLO_REQ");
        assert_eq!(body["flow"], "kad");
        assert_eq!(body["dropReason"], "tracker_drop");
        assert_eq!(body["wireHex"], "AABB");
        assert_eq!(body["decodedHex"], "E421");
        assert_eq!(body["trackerBucket"], "hello_req");
        assert_eq!(body["trackerAction"], "drop");
        assert_eq!(body["trackerObservedPackets"], 4);
        assert_eq!(body["trackerMaxPackets"], 3);
    }

    #[test]
    fn rejected_send_omits_unknown_protocol_bytes() {
        let summary = KadUdpDumpSummary {
            opcode: Some(0x21),
            opcode_name: Some("KADEMLIA2_REQ"),
            drop_reason: Some("encode_failed"),
            detail: Some("exact encoder error".to_string()),
            outcome: KadUdpOutcome::SendRejected,
            ..KadUdpDumpSummary::default()
        };
        let peer: SocketAddr = "198.51.100.1:4672".parse().unwrap();
        let (severity, keys, body) = kad_udp_diag_event_parts("send", peer, &[], &[], &summary);

        assert_eq!(severity, "warning");
        assert!(keys.get("protocolMarker").is_none());
        assert!(body.get("protocolMarker").is_none());
        assert_eq!(body["outcome"], "send_rejected");
        assert_eq!(body["dropReason"], "encode_failed");
        assert_eq!(body["detail"], "exact encoder error");
    }
}
