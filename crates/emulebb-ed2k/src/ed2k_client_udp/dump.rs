// Gated by the `packet-diagnostics` Cargo feature, like the TCP/server packet
// dumps. Release builds without the feature compile the writers to no-ops.
#![cfg_attr(
    not(feature = "packet-diagnostics"),
    expect(
        dead_code,
        unused_imports,
        reason = "UDP diagnostic machinery is inert without its feature"
    )
)]

use std::{
    fs,
    net::SocketAddr,
    sync::{
        Mutex as StdMutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use chrono::SecondsFormat;
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::codec::{
    OP_DIRECTCALLBACKREQ, OP_FILENOTFOUND, OP_PORTTEST, OP_QUEUEFULL, OP_REASKACK,
    OP_REASKCALLBACKUDP, OP_REASKFILEPING,
};
use super::outbound::ClientUdpDatagram;
use crate::ed2k_client_udp_obfuscation::deobfuscate_client_udp;

const CLIENT_UDP_DUMP_FILE_PREFIX: &str = "emulebb-rust-ed2k-client-udp-dump-";
const OP_EMULEPROT_MARKER: u8 = 0xC5;
const CLIENT_UDP_LIVE_SYNC_EVERY: u64 = 128;

#[derive(Debug, Serialize)]
struct ClientUdpDumpRecord<'a> {
    schema: &'static str,
    source: &'static str,
    ts_utc: String,
    event_seq: u64,
    trace_key: String,
    state_id: &'static str,
    state_label: &'static str,
    flow: &'static str,
    phase: &'static str,
    direction: &'a str,
    outcome: &'static str,
    remote_addr: String,
    transport_mode: &'a str,
    obfuscated: Option<bool>,
    protocol: Option<&'static str>,
    protocol_marker: Option<u8>,
    opcode: Option<u8>,
    opcode_name: Option<&'static str>,
    raw_len: usize,
    raw_hex: String,
    payload_len: Option<usize>,
    payload_hex: Option<String>,
    payload_hex_truncated: Option<bool>,
    note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClientUdpDumpOutcome {
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
            Self::Accepted | Self::Ignored | Self::SendSucceeded => "info",
        }
    }
}

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_client_udp_send(_remote_addr: SocketAddr, _datagram: &ClientUdpDatagram) {}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_client_udp_send(remote_addr: SocketAddr, datagram: &ClientUdpDatagram) {
    let raw_hex = exact_packet_hex(&datagram.bytes);
    let payload_hex = exact_packet_hex(&datagram.payload);
    dump_client_udp_record(&ClientUdpDumpRecord {
        schema: "ed2k_packet_v1",
        source: "emulebb-rust",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: next_client_udp_dump_event_seq(),
        trace_key: client_udp_trace_key(remote_addr),
        state_id: "client_udp.reask",
        state_label: "reask",
        flow: "client_udp",
        phase: "reask",
        direction: "send",
        outcome: ClientUdpDumpOutcome::SendSucceeded.as_str(),
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
    dump_client_udp_record(&ClientUdpDumpRecord {
        schema: "ed2k_packet_v1",
        source: "emulebb-rust",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: next_client_udp_dump_event_seq(),
        trace_key: client_udp_trace_key(remote_addr),
        state_id: "client_udp.reask",
        state_label: "reask",
        flow: "client_udp",
        phase: "reask",
        direction: "recv",
        outcome: outcome.as_str(),
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

fn client_udp_protocol_name(protocol_marker: u8) -> &'static str {
    match protocol_marker {
        OP_EMULEPROT_MARKER => "emule",
        _ => "unknown",
    }
}

fn client_udp_trace_key(remote_addr: SocketAddr) -> String {
    format!("client_udp:{remote_addr}")
}

fn next_client_udp_dump_event_seq() -> u64 {
    static NEXT_EVENT_SEQ: AtomicU64 = AtomicU64::new(1);
    NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Open (create/append) the ed2k client-UDP dump file under `EMULEBB_RUST_LOG_DIR`.
/// `None` when the env var is unset or the file cannot be created. Kept separate
/// from the `OnceLock` cell so callers RE-ATTEMPT the open while the handle is
/// still `None` (an early first-access must not permanently disable the dump).
fn open_client_udp_dump_file() -> Option<fs::File> {
    let dir = std::env::var("EMULEBB_RUST_LOG_DIR")
        .ok()
        .map(std::path::PathBuf::from)?;
    fs::create_dir_all(&dir).ok()?;
    let path = dir.join(format!(
        "{}{}.jsonl",
        CLIENT_UDP_DUMP_FILE_PREFIX,
        chrono::Utc::now().format("%Y.%m.%d-%H.%M.%S")
    ));
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
}

fn client_udp_dump_file() -> &'static StdMutex<Option<fs::File>> {
    static DUMP_FILE: OnceLock<StdMutex<Option<fs::File>>> = OnceLock::new();
    DUMP_FILE.get_or_init(|| StdMutex::new(None))
}

fn exact_packet_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(feature = "packet-diagnostics")]
fn dump_client_udp_record(record: &ClientUdpDumpRecord<'_>) {
    emit_client_udp_diag_event(record);
    let Ok(line) = serde_json::to_string(record) else {
        return;
    };
    let Ok(mut guard) = client_udp_dump_file().lock() else {
        return;
    };
    if guard.is_none() {
        *guard = open_client_udp_dump_file();
    }
    let Some(file) = guard.as_mut() else {
        return;
    };
    let _ = std::io::Write::write_all(file, line.as_bytes());
    let _ = std::io::Write::write_all(file, b"\n");
    let _ = std::io::Write::flush(file);
    maybe_sync_client_udp_dump(file);
}

#[cfg(feature = "packet-diagnostics")]
fn emit_client_udp_diag_event(record: &ClientUdpDumpRecord<'_>) {
    let (family, severity, keys, body) = client_udp_diag_event_parts(record);
    crate::diag_event::emit(family, "packet", severity, keys, body);
}

#[cfg(any(feature = "packet-diagnostics", test))]
fn client_udp_diag_event_parts(
    record: &ClientUdpDumpRecord<'_>,
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
    body.insert("outcome".to_string(), json!(record.outcome));
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

    let severity = match record.outcome {
        "dropped" | "send_failed" => ClientUdpDumpOutcome::Dropped.severity(),
        _ => ClientUdpDumpOutcome::Accepted.severity(),
    };
    (
        "ed2k_client_udp",
        severity,
        Value::Object(keys),
        Value::Object(body),
    )
}

#[cfg(feature = "packet-diagnostics")]
fn maybe_sync_client_udp_dump(file: &fs::File) {
    static CLIENT_UDP_LIVE_SYNC_COUNTER: AtomicU64 = AtomicU64::new(0);
    if CLIENT_UDP_LIVE_SYNC_COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .is_multiple_of(CLIENT_UDP_LIVE_SYNC_EVERY)
    {
        let _ = file.sync_data();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CLIENT_UDP_DUMP_FILE_PREFIX, ClientUdpDumpOutcome, ClientUdpDumpRecord,
        OP_DIRECTCALLBACKREQ, OP_PORTTEST, OP_REASKACK, OP_REASKCALLBACKUDP, OP_REASKFILEPING,
        client_udp_diag_event_parts, client_udp_opcode_name, exact_packet_hex,
    };
    use crate::ed2k_client_udp::outbound::{OutboundReaskTarget, build_reask_file_ping_datagram};
    use emulebb_kad_proto::Ed2kHash;

    #[test]
    fn client_udp_dump_prefix_uses_emulebb_rust_name() {
        assert_eq!(
            CLIENT_UDP_DUMP_FILE_PREFIX,
            "emulebb-rust-ed2k-client-udp-dump-"
        );
    }

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
    fn client_udp_common_event_preserves_exact_wire_and_payload() {
        let raw = vec![0x11; 4 * 1024 + 1];
        let payload = vec![0x22; 4 * 1024 + 1];
        let record = ClientUdpDumpRecord {
            schema: "ed2k_packet_v1",
            source: "emulebb-rust",
            ts_utc: "2026-10-24T00:00:00.000Z".to_string(),
            event_seq: 1,
            trace_key: "client_udp:198.51.100.2:4672".to_string(),
            state_id: "client_udp.reask",
            state_label: "reask",
            flow: "client_udp",
            phase: "reask",
            direction: "send",
            outcome: ClientUdpDumpOutcome::SendSucceeded.as_str(),
            remote_addr: "198.51.100.2:4672".to_string(),
            transport_mode: "obfuscated",
            obfuscated: Some(true),
            protocol: Some("emule"),
            protocol_marker: Some(0xC5),
            opcode: Some(OP_REASKFILEPING),
            opcode_name: Some(client_udp_opcode_name(OP_REASKFILEPING)),
            raw_len: raw.len(),
            raw_hex: exact_packet_hex(&raw),
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
        assert_eq!(body["outcome"], "send_succeeded");
        assert_eq!(body["transportMode"], "obfuscated");
        assert_eq!(body["obfuscated"], true);
        assert_eq!(body["stateId"], "client_udp.reask");
        assert_eq!(body["traceKey"], "client_udp:198.51.100.2:4672");
        assert_eq!(body["rawLen"], raw.len());
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
        let record = ClientUdpDumpRecord {
            schema: "ed2k_packet_v1",
            source: "emulebb-rust",
            ts_utc: "2026-10-24T00:00:00.000Z".to_string(),
            event_seq: 2,
            trace_key: "client_udp:198.51.100.2:4672".to_string(),
            state_id: "client_udp.reask",
            state_label: "reask",
            flow: "client_udp",
            phase: "reask",
            direction: "recv",
            outcome: ClientUdpDumpOutcome::Dropped.as_str(),
            remote_addr: "198.51.100.2:4672".to_string(),
            transport_mode: "unknown",
            obfuscated: None,
            protocol: None,
            protocol_marker: None,
            opcode: None,
            opcode_name: None,
            raw_len: raw.len(),
            raw_hex: exact_packet_hex(&raw),
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
