//! `family:"ed2k_tcp"` `diag_event_v2` mapping.
//!
//! Re-shapes an [`Ed2kTcpDumpRecord`] (the legacy `ed2k_packet_v1` record) into
//! the converged `ed2k_tcp` `diag_event_v2` envelope and forwards
//! it to the shared writer. Kept in its own module because diagnostics-envelope
//! mapping is a separate responsibility from packet capture. Both writes are
//! behind the `packet-diagnostics` feature: the only caller
//! (`dump.rs::dump_ed2k_tcp_record`) is invoked solely from the feature-gated
//! send/recv/meta builders.

#![cfg_attr(
    not(feature = "packet-diagnostics"),
    expect(
        dead_code,
        reason = "TCP diagnostic event mapping is inert without its feature"
    )
)]

use serde_json::{Map, Value, json};

use super::dump::Ed2kTcpDumpRecord;

/// Emit the converged `ed2k_tcp` `diag_event_v2` record from the same data that
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
    if let Some(note) = record.note.as_deref() {
        body.insert("note".to_string(), json!(note));
    }

    let severity = if matches!(record.outcome, "dropped" | "send_failed" | "send_cancelled") {
        "warning"
    } else {
        "info"
    };
    crate::diag_event::emit(
        "ed2k_tcp",
        "packet",
        severity,
        Value::Object(keys),
        Value::Object(body),
    );
}
