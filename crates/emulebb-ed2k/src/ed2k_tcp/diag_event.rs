//! `family:"ed2k_tcp"` `diag_event_v2` mapping.
//!
//! Maps an [`Ed2kTcpDiagnosticRecord`] into the converged `ed2k_tcp`
//! `diag_event_v2` envelope and forwards it to the shared writer. Kept in its
//! own module because diagnostics-envelope mapping is a separate responsibility
//! from packet capture.

#![cfg_attr(
    not(feature = "packet-diagnostics"),
    expect(
        dead_code,
        reason = "TCP diagnostic event mapping is inert without its feature"
    )
)]

use serde_json::{Map, Value, json};

use super::dump::Ed2kTcpDiagnosticRecord;

/// Emit one converged `ed2k_tcp` `diag_event_v2` record. Optional `keys`/`body`
/// fields are omitted when absent rather than faked.
pub(super) fn emit_ed2k_tcp_diag_event(record: &Ed2kTcpDiagnosticRecord<'_>) {
    let (event, severity, keys, body) = ed2k_tcp_diag_event_parts(record);
    crate::diag_event::emit("ed2k_tcp", event, severity, keys, body);
}

fn ed2k_tcp_diag_event_parts(
    record: &Ed2kTcpDiagnosticRecord<'_>,
) -> (&'static str, &'static str, Value, Value) {
    let mut keys = Map::new();
    keys.insert("peer".to_string(), json!(record.remote_addr));
    if let Some(peer_hash) = record.peer_hash {
        keys.insert("peerHash".to_string(), json!(hex::encode(peer_hash)));
    }
    if let Some(file_hash) = record.file_hash {
        keys.insert("fileHash".to_string(), json!(hex::encode(file_hash)));
    }
    if let Some(protocol_marker) = record.protocol_marker {
        keys.insert("protocolMarker".to_string(), json!(protocol_marker));
    }
    if let Some(opcode) = record.opcode {
        keys.insert("opcode".to_string(), json!(opcode));
    }

    let mut body = Map::new();
    body.insert("direction".to_string(), json!(record.direction));
    body.insert("outcome".to_string(), json!(record.outcome));
    if let Some(protocol_marker) = record.protocol_marker {
        body.insert("protocolMarker".to_string(), json!(protocol_marker));
    }
    if let Some(protocol_name) = record.protocol {
        body.insert("protocolName".to_string(), json!(protocol_name));
    }
    if let Some(opcode) = record.opcode {
        body.insert("opcode".to_string(), json!(opcode));
    }
    if let Some(opcode_name) = record.opcode_name {
        body.insert("opcodeName".to_string(), json!(opcode_name));
    }
    if let Some(raw_len) = record.raw_len {
        body.insert("rawLen".to_string(), json!(raw_len));
    }
    if let Some(raw_hex) = record.raw_hex.as_deref() {
        body.insert("rawHex".to_string(), json!(raw_hex));
    }
    if let Some(clear_frame_len) = record.clear_frame_len {
        body.insert("clearFrameLen".to_string(), json!(clear_frame_len));
    }
    if let Some(clear_frame_hex) = record.clear_frame_hex.as_deref() {
        body.insert("clearFrameHex".to_string(), json!(clear_frame_hex));
    }
    if let Some(attempted_len) = record.attempted_len {
        body.insert("attemptedLen".to_string(), json!(attempted_len));
    }
    if let Some(written_len) = record.written_len {
        body.insert("writtenLen".to_string(), json!(written_len));
    }
    if let Some(payload_len) = record.payload_len {
        body.insert("payloadLen".to_string(), json!(payload_len));
    }
    if let Some(payload_hex) = record.payload_hex.as_deref() {
        body.insert("payloadHex".to_string(), json!(payload_hex));
    }
    if let Some(truncated) = record.payload_hex_truncated {
        body.insert("payloadHexTruncated".to_string(), json!(truncated));
    }
    if let Some(obfuscated) = record.obfuscated {
        body.insert("obfuscated".to_string(), json!(obfuscated));
    }
    body.insert("transportMode".to_string(), json!(record.transport_mode));
    body.insert("flow".to_string(), json!(record.flow));
    body.insert("phase".to_string(), json!(record.phase));
    body.insert("traceKey".to_string(), json!(record.trace_key));
    body.insert("stateId".to_string(), json!(record.state_id));
    body.insert("stateLabel".to_string(), json!(record.state_label));
    if let Some(note) = record.note.as_deref() {
        body.insert("note".to_string(), json!(note));
    }

    let severity = if matches!(
        record.outcome,
        "dropped" | "recv_cancelled" | "send_failed" | "send_cancelled"
    ) {
        "warning"
    } else {
        "info"
    };
    (
        record.event,
        severity,
        Value::Object(keys),
        Value::Object(body),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record<'a>(
        event: &'static str,
        direction: &'a str,
        outcome: &'a str,
    ) -> Ed2kTcpDiagnosticRecord<'a> {
        Ed2kTcpDiagnosticRecord {
            event,
            trace_key: "native_download:198.51.100.2:4662".to_string(),
            state_id: "native_download.session".to_string(),
            state_label: "session",
            flow: "native_download",
            phase: "session",
            direction,
            outcome,
            remote_addr: "198.51.100.2:4662".to_string(),
            peer_hash: None,
            file_hash: None,
            transport_mode: "obfuscated",
            obfuscated: Some(true),
            protocol: None,
            protocol_marker: None,
            opcode: None,
            opcode_name: None,
            raw_len: None,
            raw_hex: None,
            clear_frame_len: None,
            clear_frame_hex: None,
            attempted_len: None,
            written_len: None,
            payload_len: None,
            payload_hex: None,
            payload_hex_truncated: None,
            note: None,
        }
    }

    #[test]
    fn peer_tcp_state_event_preserves_trace_context() {
        let record = record("state", "meta", "meta");
        let (event, severity, keys, body) = ed2k_tcp_diag_event_parts(&record);

        assert_eq!(event, "state");
        assert_eq!(severity, "info");
        assert_eq!(keys["peer"], "198.51.100.2:4662");
        assert_eq!(body["traceKey"], "native_download:198.51.100.2:4662");
        assert_eq!(body["stateId"], "native_download.session");
        assert_eq!(body["stateLabel"], "session");
    }

    #[test]
    fn peer_tcp_handshake_keeps_distinct_event_classification() {
        let record = record("obfuscation_handshake", "send", "send_succeeded");
        let (event, _, _, body) = ed2k_tcp_diag_event_parts(&record);

        assert_eq!(event, "obfuscation_handshake");
        assert_eq!(body["traceKey"], "native_download:198.51.100.2:4662");
    }

    #[test]
    fn peer_tcp_packet_exposes_join_keys_when_known() {
        let mut record = record("packet", "recv", "accepted");
        record.peer_hash = Some([0x11; 16]);
        record.file_hash = Some([0x22; 16]);
        let (_, _, keys, _) = ed2k_tcp_diag_event_parts(&record);

        assert_eq!(keys["peerHash"], "11111111111111111111111111111111");
        assert_eq!(keys["fileHash"], "22222222222222222222222222222222");
    }
}
