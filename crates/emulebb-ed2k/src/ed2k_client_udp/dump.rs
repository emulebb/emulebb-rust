// Gated by the `packet-diagnostics` Cargo feature. Release builds without the
// feature compile the unified diagnostic emitters to no-ops.
#![cfg_attr(
    not(feature = "packet-diagnostics"),
    expect(
        dead_code,
        unused_imports,
        reason = "UDP diagnostic machinery is inert without its feature"
    )
)]

use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::{Map, Value, json};

use super::codec::{
    OP_DIRECTCALLBACKREQ, OP_FILENOTFOUND, OP_PORTTEST, OP_QUEUEFULL, OP_REASKACK,
    OP_REASKCALLBACKUDP, OP_REASKFILEPING,
};
use super::outbound::ClientUdpDatagram;
use super::transport::ClientUdpSendRole;
use crate::ed2k_client_udp_obfuscation::deobfuscate_client_udp;

const OP_EMULEPROT_MARKER: u8 = 0xC5;

#[derive(Debug)]
struct ClientUdpDiagnosticRecord<'a> {
    trace_key: String,
    state_id: &'static str,
    state_label: &'static str,
    flow: &'static str,
    phase: &'static str,
    direction: &'a str,
    outcome: ClientUdpDumpOutcome,
    send_attempt_id: Option<u64>,
    role: Option<&'static str>,
    remote_addr: String,
    transport_mode: &'a str,
    obfuscated: Option<bool>,
    protocol: Option<&'static str>,
    protocol_marker: Option<u8>,
    opcode: Option<u8>,
    opcode_name: Option<&'static str>,
    raw_len: usize,
    raw_hex: String,
    attempted_len: Option<usize>,
    payload_len: Option<usize>,
    payload_hex: Option<String>,
    payload_hex_truncated: Option<bool>,
    note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClientUdpDumpOutcome {
    Attempted,
    Accepted,
    Ignored,
    Dropped,
    SendSucceeded,
    SendFailed,
    SendCancelled,
}

impl ClientUdpDumpOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Attempted => "attempted",
            Self::Accepted => "accepted",
            Self::Ignored => "ignored",
            Self::Dropped => "dropped",
            Self::SendSucceeded => "send_succeeded",
            Self::SendFailed => "send_failed",
            Self::SendCancelled => "send_cancelled",
        }
    }

    const fn severity(self) -> &'static str {
        match self {
            Self::Dropped | Self::SendFailed | Self::SendCancelled => "warning",
            Self::Attempted | Self::Accepted | Self::Ignored | Self::SendSucceeded => "info",
        }
    }
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_client_udp_send_attempt(
    remote_addr: SocketAddr,
    role: ClientUdpSendRole,
    datagram: &ClientUdpDatagram,
    attempt_id: u64,
) {
    let raw_hex = exact_packet_hex(&datagram.bytes);
    let payload_hex = exact_packet_hex(&datagram.payload);
    emit_client_udp_packet(&ClientUdpDiagnosticRecord {
        trace_key: client_udp_trace_key(remote_addr),
        state_id: role.state_id(),
        state_label: role.state_label(),
        flow: "client_udp",
        phase: role.phase(),
        direction: "send",
        outcome: ClientUdpDumpOutcome::Attempted,
        send_attempt_id: Some(attempt_id),
        role: Some(role.as_str()),
        remote_addr: remote_addr.to_string(),
        transport_mode: if datagram.obfuscated {
            "obfuscated"
        } else {
            "plaintext"
        },
        obfuscated: Some(datagram.obfuscated),
        protocol: Some("emule"),
        protocol_marker: Some(datagram.protocol_marker),
        opcode: Some(datagram.opcode),
        opcode_name: Some(client_udp_opcode_name(datagram.opcode)),
        raw_len: datagram.bytes.len(),
        raw_hex,
        attempted_len: Some(datagram.bytes.len()),
        payload_len: Some(datagram.payload.len()),
        payload_hex: Some(payload_hex),
        payload_hex_truncated: Some(false),
        note: None,
    });
}

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_client_udp_recv(
    _remote_addr: SocketAddr,
    _our_user_hash: &[u8; 16],
    _datagram: &[u8],
    _outcome: ClientUdpDumpOutcome,
    _note: Option<String>,
) {
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_client_udp_recv(
    remote_addr: SocketAddr,
    our_user_hash: &[u8; 16],
    datagram: &[u8],
    outcome: ClientUdpDumpOutcome,
    note: Option<String>,
) {
    let raw_hex = exact_packet_hex(datagram);
    let decoded = decode_client_udp_for_dump(our_user_hash, remote_addr, datagram);
    let transport_mode = decoded.as_ref().map_or_else(
        || {
            if datagram.first() == Some(&OP_EMULEPROT_MARKER) {
                "plaintext"
            } else {
                "unknown"
            }
        },
        |decoded| decoded.transport_mode,
    );
    let payload_len = decoded.as_ref().map(|decoded| decoded.payload.len());
    let payload_hex = decoded
        .as_ref()
        .map(|decoded| exact_packet_hex(&decoded.payload));
    let diagnostic_state =
        client_udp_diagnostic_state(decoded.as_ref().map(|decoded| decoded.opcode));
    emit_client_udp_packet(&ClientUdpDiagnosticRecord {
        trace_key: client_udp_trace_key(remote_addr),
        state_id: diagnostic_state.state_id,
        state_label: diagnostic_state.state_label,
        flow: "client_udp",
        phase: diagnostic_state.phase,
        direction: "recv",
        outcome,
        send_attempt_id: None,
        role: None,
        remote_addr: remote_addr.to_string(),
        transport_mode,
        obfuscated: match transport_mode {
            "obfuscated" => Some(true),
            "plaintext" => Some(false),
            _ => None,
        },
        protocol: decoded
            .as_ref()
            .map(|decoded| client_udp_protocol_name(decoded.protocol_marker)),
        protocol_marker: decoded.as_ref().map(|decoded| decoded.protocol_marker),
        opcode: decoded.as_ref().map(|decoded| decoded.opcode),
        opcode_name: decoded
            .as_ref()
            .map(|decoded| client_udp_opcode_name(decoded.opcode)),
        raw_len: datagram.len(),
        raw_hex,
        attempted_len: None,
        payload_len,
        payload_hex,
        payload_hex_truncated: payload_len.map(|_| false),
        note,
    });
}

#[cfg(feature = "packet-diagnostics")]
struct DecodedClientUdpDatagram {
    protocol_marker: u8,
    opcode: u8,
    payload: Vec<u8>,
    transport_mode: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClientUdpDiagnosticState {
    state_id: &'static str,
    state_label: &'static str,
    phase: &'static str,
}

#[cfg(feature = "packet-diagnostics")]
fn decode_client_udp_for_dump(
    our_user_hash: &[u8; 16],
    remote_addr: SocketAddr,
    datagram: &[u8],
) -> Option<DecodedClientUdpDatagram> {
    if datagram.len() >= 2 && datagram[0] == OP_EMULEPROT_MARKER {
        return Some(DecodedClientUdpDatagram {
            protocol_marker: datagram[0],
            opcode: datagram[1],
            payload: datagram[2..].to_vec(),
            transport_mode: "plaintext",
        });
    }
    let SocketAddr::V4(remote_addr) = remote_addr else {
        return None;
    };
    let plain = deobfuscate_client_udp(our_user_hash, remote_addr.ip().octets(), datagram)?;
    if plain.len() < 2 {
        return None;
    }
    Some(DecodedClientUdpDatagram {
        protocol_marker: plain[0],
        opcode: plain[1],
        payload: plain[2..].to_vec(),
        transport_mode: "obfuscated",
    })
}

fn client_udp_opcode_name(opcode: u8) -> &'static str {
    match opcode {
        OP_REASKFILEPING => "OP_REASKFILEPING",
        OP_REASKACK => "OP_REASKACK",
        OP_FILENOTFOUND => "OP_FILENOTFOUND",
        OP_QUEUEFULL => "OP_QUEUEFULL",
        OP_REASKCALLBACKUDP => "OP_REASKCALLBACKUDP",
        OP_DIRECTCALLBACKREQ => "OP_DIRECTCALLBACKREQ",
        OP_PORTTEST => "OP_PORTTEST",
        _ => "UNKNOWN",
    }
}

fn client_udp_diagnostic_state(opcode: Option<u8>) -> ClientUdpDiagnosticState {
    match opcode {
        Some(OP_REASKFILEPING) => ClientUdpDiagnosticState {
            state_id: "client_udp.reask",
            state_label: "reask",
            phase: "reask_request",
        },
        Some(OP_REASKACK | OP_FILENOTFOUND | OP_QUEUEFULL) => ClientUdpDiagnosticState {
            state_id: "client_udp.reask",
            state_label: "reask",
            phase: "reask_reply",
        },
        Some(OP_REASKCALLBACKUDP) => ClientUdpDiagnosticState {
            state_id: "client_udp.buddy_relay",
            state_label: "buddy_relay",
            phase: "buddy_relay_request",
        },
        Some(OP_DIRECTCALLBACKREQ) => ClientUdpDiagnosticState {
            state_id: "client_udp.direct_callback",
            state_label: "direct_callback",
            phase: "direct_callback_request",
        },
        Some(OP_PORTTEST) => ClientUdpDiagnosticState {
            state_id: "client_udp.port_test",
            state_label: "port_test",
            phase: "port_test",
        },
        Some(_) | None => ClientUdpDiagnosticState {
            state_id: "client_udp.unknown",
            state_label: "unknown",
            phase: "unknown",
        },
    }
}

fn client_udp_protocol_name(protocol_marker: u8) -> &'static str {
    match protocol_marker {
        OP_EMULEPROT_MARKER => "emule",
        _ => "unknown",
    }
}

fn client_udp_trace_key(remote_addr: SocketAddr) -> String {
    format!("client_udp:{remote_addr}")
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn next_client_udp_send_attempt_id() -> u64 {
    static NEXT_SEND_ATTEMPT_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_SEND_ATTEMPT_ID.fetch_add(1, Ordering::Relaxed)
}

fn exact_packet_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(feature = "packet-diagnostics")]
fn emit_client_udp_packet(record: &ClientUdpDiagnosticRecord<'_>) {
    let (family, severity, keys, body) = client_udp_diag_event_parts(record);
    crate::diag_event::emit(family, "packet", severity, keys, body);
}

#[cfg(any(feature = "packet-diagnostics", test))]
fn client_udp_diag_event_parts(
    record: &ClientUdpDiagnosticRecord<'_>,
) -> (&'static str, &'static str, Value, Value) {
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
    body.insert("outcome".to_string(), json!(record.outcome.as_str()));
    if let Some(send_attempt_id) = record.send_attempt_id {
        keys.insert("sendAttemptId".to_string(), json!(send_attempt_id));
        body.insert("sendAttemptId".to_string(), json!(send_attempt_id));
    }
    if let Some(role) = record.role {
        body.insert("role".to_string(), json!(role));
    }
    body.insert("stateId".to_string(), json!(record.state_id));
    body.insert("stateLabel".to_string(), json!(record.state_label));
    body.insert("traceKey".to_string(), json!(record.trace_key));
    body.insert("flow".to_string(), json!(record.flow));
    body.insert("phase".to_string(), json!(record.phase));
    body.insert("transportMode".to_string(), json!(record.transport_mode));
    if let Some(obfuscated) = record.obfuscated {
        body.insert("obfuscated".to_string(), json!(obfuscated));
    }
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
    body.insert("rawLen".to_string(), json!(record.raw_len));
    body.insert("rawHex".to_string(), json!(record.raw_hex));
    if let Some(attempted_len) = record.attempted_len {
        body.insert("attemptedLen".to_string(), json!(attempted_len));
    }
    if let Some(payload_len) = record.payload_len {
        body.insert("payloadLen".to_string(), json!(payload_len));
    }
    if let Some(payload_hex) = record.payload_hex.as_deref() {
        body.insert("payloadHex".to_string(), json!(payload_hex));
    }
    if let Some(payload_hex_truncated) = record.payload_hex_truncated {
        body.insert(
            "payloadHexTruncated".to_string(),
            json!(payload_hex_truncated),
        );
    }
    if let Some(note) = record.note.as_deref() {
        body.insert("note".to_string(), json!(note));
    }

    (
        "ed2k_client_udp",
        record.outcome.severity(),
        Value::Object(keys),
        Value::Object(body),
    )
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn emit_client_udp_send_outcome(
    remote_addr: SocketAddr,
    role: ClientUdpSendRole,
    datagram: &ClientUdpDatagram,
    attempt_id: u64,
    outcome: ClientUdpDumpOutcome,
    delivery_known: bool,
    note: Option<String>,
) {
    let (severity, keys, body) = client_udp_send_outcome_parts(
        remote_addr,
        role,
        datagram,
        attempt_id,
        outcome,
        delivery_known,
        note.as_deref(),
    );
    crate::diag_event::emit("ed2k_client_udp", "send_outcome", severity, keys, body);
}

#[cfg(any(feature = "packet-diagnostics", test))]
fn client_udp_send_outcome_parts(
    remote_addr: SocketAddr,
    role: ClientUdpSendRole,
    datagram: &ClientUdpDatagram,
    attempt_id: u64,
    outcome: ClientUdpDumpOutcome,
    delivery_known: bool,
    note: Option<&str>,
) -> (&'static str, Value, Value) {
    let keys = json!({
        "peer": remote_addr.to_string(),
        "protocolMarker": datagram.protocol_marker,
        "opcode": datagram.opcode,
        "sendAttemptId": attempt_id,
    });
    let mut body = Map::new();
    body.insert("direction".to_string(), json!("send"));
    body.insert("outcome".to_string(), json!(outcome.as_str()));
    body.insert("deliveryKnown".to_string(), json!(delivery_known));
    body.insert("sendAttemptId".to_string(), json!(attempt_id));
    body.insert("role".to_string(), json!(role.as_str()));
    body.insert("stateId".to_string(), json!(role.state_id()));
    body.insert("stateLabel".to_string(), json!(role.state_label()));
    body.insert(
        "traceKey".to_string(),
        json!(client_udp_trace_key(remote_addr)),
    );
    body.insert("flow".to_string(), json!("client_udp"));
    body.insert("phase".to_string(), json!(role.phase()));
    body.insert(
        "protocolMarker".to_string(),
        json!(datagram.protocol_marker),
    );
    body.insert("protocolName".to_string(), json!("emule"));
    body.insert("opcode".to_string(), json!(datagram.opcode));
    body.insert(
        "opcodeName".to_string(),
        json!(client_udp_opcode_name(datagram.opcode)),
    );
    body.insert("attemptedLen".to_string(), json!(datagram.bytes.len()));
    if let Some(note) = note {
        body.insert("note".to_string(), json!(note));
    }
    (outcome.severity(), keys, Value::Object(body))
}

#[cfg(test)]
mod tests {
    use super::{
        ClientUdpDiagnosticRecord, ClientUdpDumpOutcome, OP_DIRECTCALLBACKREQ, OP_PORTTEST,
        OP_REASKACK, OP_REASKCALLBACKUDP, OP_REASKFILEPING, client_udp_diag_event_parts,
        client_udp_diagnostic_state, client_udp_opcode_name, client_udp_send_outcome_parts,
        exact_packet_hex,
    };
    use crate::ed2k_client_udp::outbound::{
        ClientUdpDatagram, OutboundReaskTarget, build_reask_file_ping_datagram,
    };
    use crate::ed2k_client_udp::transport::ClientUdpSendRole;
    use emulebb_kad_proto::Ed2kHash;

    #[test]
    fn client_udp_packet_hex_preserves_payloads_larger_than_the_former_cap() {
        let payload = vec![0xEF; 4 * 1024 + 1];
        let encoded = exact_packet_hex(&payload);
        assert_eq!(encoded.len(), payload.len() * 2);
        assert!(encoded.ends_with("ef"));
    }

    #[test]
    fn client_udp_dump_names_reask_opcodes() {
        assert_eq!(client_udp_opcode_name(OP_REASKFILEPING), "OP_REASKFILEPING");
        assert_eq!(client_udp_opcode_name(OP_REASKACK), "OP_REASKACK");
        assert_eq!(
            client_udp_opcode_name(OP_REASKCALLBACKUDP),
            "OP_REASKCALLBACKUDP"
        );
        assert_eq!(
            client_udp_opcode_name(OP_DIRECTCALLBACKREQ),
            "OP_DIRECTCALLBACKREQ"
        );
        assert_eq!(client_udp_opcode_name(OP_PORTTEST), "OP_PORTTEST");
        assert_eq!(client_udp_opcode_name(0xFF), "UNKNOWN");
    }

    #[test]
    fn client_udp_receive_state_tracks_opcode_role() {
        let reask = client_udp_diagnostic_state(Some(OP_REASKFILEPING));
        assert_eq!(reask.state_id, "client_udp.reask");
        assert_eq!(reask.phase, "reask_request");

        let reply = client_udp_diagnostic_state(Some(OP_REASKACK));
        assert_eq!(reply.state_id, "client_udp.reask");
        assert_eq!(reply.phase, "reask_reply");

        let buddy = client_udp_diagnostic_state(Some(OP_REASKCALLBACKUDP));
        assert_eq!(buddy.state_id, "client_udp.buddy_relay");
        assert_eq!(buddy.phase, "buddy_relay_request");

        let callback = client_udp_diagnostic_state(Some(OP_DIRECTCALLBACKREQ));
        assert_eq!(callback.state_id, "client_udp.direct_callback");
        assert_eq!(callback.phase, "direct_callback_request");

        let port_test = client_udp_diagnostic_state(Some(OP_PORTTEST));
        assert_eq!(port_test.state_id, "client_udp.port_test");
        assert_eq!(port_test.phase, "port_test");

        let unknown = client_udp_diagnostic_state(Some(0x01));
        assert_eq!(unknown.state_id, "client_udp.unknown");
        assert_eq!(unknown.phase, "unknown");
    }

    #[test]
    fn client_udp_common_event_preserves_exact_wire_and_payload() {
        let raw = vec![0x11; 4 * 1024 + 1];
        let payload = vec![0x22; 4 * 1024 + 1];
        let record = ClientUdpDiagnosticRecord {
            trace_key: "client_udp:198.51.100.2:4672".to_string(),
            state_id: "client_udp.reask",
            state_label: "reask",
            flow: "client_udp",
            phase: "reask",
            direction: "send",
            outcome: ClientUdpDumpOutcome::Attempted,
            send_attempt_id: Some(7),
            role: Some("reask_request"),
            remote_addr: "198.51.100.2:4672".to_string(),
            transport_mode: "obfuscated",
            obfuscated: Some(true),
            protocol: Some("emule"),
            protocol_marker: Some(0xC5),
            opcode: Some(OP_REASKFILEPING),
            opcode_name: Some(client_udp_opcode_name(OP_REASKFILEPING)),
            raw_len: raw.len(),
            raw_hex: exact_packet_hex(&raw),
            attempted_len: Some(raw.len()),
            payload_len: Some(payload.len()),
            payload_hex: Some(exact_packet_hex(&payload)),
            payload_hex_truncated: Some(false),
            note: None,
        };

        let (family, severity, keys, body) = client_udp_diag_event_parts(&record);
        assert_eq!(family, "ed2k_client_udp");
        assert_eq!(severity, "info");
        assert_eq!(keys["peer"], "198.51.100.2:4672");
        assert_eq!(keys["protocolMarker"], 0xC5);
        assert_eq!(keys["opcode"], OP_REASKFILEPING);
        assert_eq!(body["direction"], "send");
        assert_eq!(keys["sendAttemptId"], 7);
        assert_eq!(body["outcome"], "attempted");
        assert_eq!(body["sendAttemptId"], 7);
        assert_eq!(body["role"], "reask_request");
        assert_eq!(body["transportMode"], "obfuscated");
        assert_eq!(body["obfuscated"], true);
        assert_eq!(body["stateId"], "client_udp.reask");
        assert_eq!(body["traceKey"], "client_udp:198.51.100.2:4672");
        assert_eq!(body["rawLen"], raw.len());
        assert_eq!(body["attemptedLen"], raw.len());
        assert_eq!(body["rawHex"].as_str().unwrap().len(), raw.len() * 2);
        assert_eq!(body["payloadLen"], payload.len());
        assert_eq!(
            body["payloadHex"].as_str().unwrap().len(),
            payload.len() * 2
        );
        assert_eq!(body["payloadHexTruncated"], false);
    }

    #[test]
    fn client_udp_common_event_preserves_dropped_undecodable_wire() {
        let raw = vec![0x42; 24];
        let record = ClientUdpDiagnosticRecord {
            trace_key: "client_udp:198.51.100.2:4672".to_string(),
            state_id: "client_udp.reask",
            state_label: "reask",
            flow: "client_udp",
            phase: "reask",
            direction: "recv",
            outcome: ClientUdpDumpOutcome::Dropped,
            send_attempt_id: None,
            role: None,
            remote_addr: "198.51.100.2:4672".to_string(),
            transport_mode: "unknown",
            obfuscated: None,
            protocol: None,
            protocol_marker: None,
            opcode: None,
            opcode_name: None,
            raw_len: raw.len(),
            raw_hex: exact_packet_hex(&raw),
            attempted_len: None,
            payload_len: None,
            payload_hex: None,
            payload_hex_truncated: None,
            note: Some("undecodable".to_string()),
        };

        let (family, severity, keys, body) = client_udp_diag_event_parts(&record);
        assert_eq!(family, "ed2k_client_udp");
        assert_eq!(severity, "warning");
        assert_eq!(keys["peer"], "198.51.100.2:4672");
        assert_eq!(body["outcome"], "dropped");
        assert_eq!(body["transportMode"], "unknown");
        assert!(body.get("obfuscated").is_none());
        assert!(body.get("payloadHex").is_none());
        assert_eq!(body["rawHex"].as_str().unwrap().len(), raw.len() * 2);
        assert_eq!(body["note"], "undecodable");
    }

    #[test]
    fn client_udp_send_terminal_event_correlates_without_repeating_payload() {
        let datagram = ClientUdpDatagram {
            bytes: vec![0xC5, OP_DIRECTCALLBACKREQ, 0x01, 0x02],
            protocol_marker: 0xC5,
            opcode: OP_DIRECTCALLBACKREQ,
            payload: vec![0x01, 0x02],
            obfuscated: false,
        };
        let (severity, keys, body) = client_udp_send_outcome_parts(
            "198.51.100.2:4672".parse().unwrap(),
            ClientUdpSendRole::DirectCallbackRequest,
            &datagram,
            9,
            ClientUdpDumpOutcome::SendCancelled,
            false,
            Some("cancelled in test"),
        );

        assert_eq!(severity, "warning");
        assert_eq!(keys["sendAttemptId"], 9);
        assert_eq!(body["outcome"], "send_cancelled");
        assert_eq!(body["deliveryKnown"], false);
        assert_eq!(body["role"], "direct_callback_request");
        assert_eq!(body["stateId"], "client_udp.direct_callback");
        assert_eq!(body["phase"], "direct_callback_request");
        assert_eq!(body["attemptedLen"], datagram.bytes.len());
        assert!(body.get("rawHex").is_none());
        assert!(body.get("payloadHex").is_none());
        assert_eq!(body["note"], "cancelled in test");
    }

    #[test]
    #[cfg(feature = "packet-diagnostics")]
    fn client_udp_dump_decodes_obfuscated_datagram_for_opcode_metadata() {
        let dest_hash = [0x21; 16];
        let sender_ip = [203, 0, 113, 9];
        let file_hash = Ed2kHash::from_bytes([0xAB; 16]);
        let target = OutboundReaskTarget {
            dest_user_hash: dest_hash,
            our_public_ip: sender_ip,
            obfuscate: true,
        };
        let datagram = build_reask_file_ping_datagram(&file_hash, None, 1, 4, &target);
        let remote_addr = std::net::SocketAddr::from((sender_ip, 4672));
        let decoded = super::decode_client_udp_for_dump(&dest_hash, remote_addr, &datagram)
            .expect("obfuscated datagram decoded from sender endpoint");
        assert_eq!(decoded.protocol_marker, 0xC5);
        assert_eq!(decoded.opcode, OP_REASKFILEPING);
        assert_eq!(decoded.transport_mode, "obfuscated");
    }

    #[test]
    #[cfg(feature = "packet-diagnostics")]
    fn client_udp_dump_rejects_non_client_foreign_datagrams() {
        let remote_addr = std::net::SocketAddr::from(([203, 0, 113, 9], 4672));
        assert!(super::decode_client_udp_for_dump(&[0x21; 16], remote_addr, &[1]).is_none());
    }
}
