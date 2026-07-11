//! `family:"ed2k_tcp"` `diag_event_v1` mapping (uniform-diagnostics-v2, lane D2).
//!
//! Re-shapes an [`Ed2kTcpDumpRecord`] (the legacy `ed2k_packet_v1` record) into
//! the converged `ed2k_tcp` `diag_event_v1` envelope (schema §3.1) and forwards
//! it to the shared writer. Kept in its own module because diagnostics-envelope
//! mapping is a separate responsibility from packet capture. Both writes are
//! behind the `packet-diagnostics` feature: the only caller
//! (`dump.rs::dump_ed2k_tcp_record`) is invoked solely from the feature-gated
//! send/recv/meta builders.

#![cfg_attr(not(feature = "packet-diagnostics"), allow(dead_code))]

use serde_json::{Map, Value, json};

use super::dump::Ed2kTcpDumpRecord;

/// Emit the converged `ed2k_tcp` `diag_event_v1` record from the same data that
/// built the legacy `ed2k_packet_v1` record. Optional `keys`/`body` fields are
/// omitted when absent rather than faked (`peerHash`/`fileHash` are not known at
/// this layer, so they are not emitted).
pub(super) fn emit_ed2k_tcp_diag_event(record: &Ed2kTcpDumpRecord<'_>) {
    let mut keys = Map::new();
    keys.insert("peer".to_string(), json!(record.remote_addr));
    if let Some(protocol_marker) = record.protocol_marker {
        keys.insert("protocolMarker".to_string(), json!(protocol_marker));
    }
    if let Some(opcode) = record.opcode {
        keys.insert("opcode".to_string(), json!(opcode));
    }

    let mut body = Map::new();
    body.insert("direction".to_string(), json!(record.direction));
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
    if let Some(payload_len) = record.payload_len {
        body.insert("payloadLen".to_string(), json!(payload_len));
    }
    if let Some(payload_hex) = record.payload_hex.as_deref() {
        body.insert("payloadHex".to_string(), json!(payload_hex));
    }
    if let Some(truncated) = record.payload_hex_truncated {
        body.insert("payloadHexTruncated".to_string(), json!(truncated));
    }
    // `obfuscated` (C): real on-wire state derived from the transport-mode label.
    // Pre-handshake meta events use `unknown`; omitting the field there avoids
    // reporting a false plaintext verdict before the transport exists.
    if let Some(obfuscated) = transport_mode_obfuscated(record.transport_mode) {
        body.insert("obfuscated".to_string(), json!(obfuscated));
    }
    body.insert("transportMode".to_string(), json!(record.transport_mode));
    body.insert("flow".to_string(), json!(record.flow));
    body.insert("phase".to_string(), json!(record.phase));
    if let Some(note) = record.note.as_deref() {
        body.insert("note".to_string(), json!(note));
    }

    crate::diag_event::emit(
        "ed2k_tcp",
        "packet",
        "info",
        Value::Object(keys),
        Value::Object(body),
    );
}

/// Whether an `Ed2kTransportMode` label denotes a known obfuscated on-wire transport.
fn transport_mode_obfuscated(transport_mode: &str) -> Option<bool> {
    match transport_mode {
        "unknown" => None,
        _ => Some(transport_mode.contains("obfusc") || transport_mode.contains("crypt")),
    }
}

#[cfg(test)]
mod tests {
    use super::transport_mode_obfuscated;

    #[test]
    fn transport_obfuscation_is_omitted_until_mode_is_known() {
        assert_eq!(transport_mode_obfuscated("unknown"), None);
        assert_eq!(transport_mode_obfuscated("plaintext"), Some(false));
        assert_eq!(transport_mode_obfuscated("obfuscated"), Some(true));
    }
}
