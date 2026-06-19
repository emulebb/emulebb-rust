// Gated by the `packet-diagnostics` Cargo feature, like the TCP/server packet
// dumps. Release builds without the feature compile the writers to no-ops.
#![cfg_attr(not(feature = "packet-diagnostics"), allow(dead_code, unused_imports))]

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

use super::codec::{
    OP_DIRECTCALLBACKREQ, OP_FILENOTFOUND, OP_QUEUEFULL, OP_REASKACK, OP_REASKCALLBACKUDP,
    OP_REASKFILEPING,
};
use super::outbound::ClientUdpDatagram;
use crate::ed2k_client_udp_obfuscation::deobfuscate_client_udp;

const CLIENT_UDP_DUMP_FILE_PREFIX: &str = "emulebb-rust-ed2k-client-udp-dump-";
const OP_EMULEPROT_MARKER: u8 = 0xC5;
const MAX_CLIENT_UDP_DUMP_HEX_BYTES: usize = 4 * 1024;

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
    remote_addr: String,
    transport_mode: &'a str,
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

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_client_udp_send(_remote_addr: SocketAddr, _datagram: &ClientUdpDatagram) {}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_client_udp_send(remote_addr: SocketAddr, datagram: &ClientUdpDatagram) {
    let (raw_hex, _) = capped_packet_hex(&datagram.bytes);
    let (payload_hex, payload_hex_truncated) = capped_packet_hex(&datagram.payload);
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
        remote_addr: remote_addr.to_string(),
        transport_mode: if datagram.obfuscated {
            "obfuscated"
        } else {
            "plaintext"
        },
        protocol: Some("emule"),
        protocol_marker: Some(datagram.protocol_marker),
        opcode: Some(datagram.opcode),
        opcode_name: Some(client_udp_opcode_name(datagram.opcode)),
        raw_len: datagram.bytes.len(),
        raw_hex,
        payload_len: Some(datagram.payload.len()),
        payload_hex: Some(payload_hex),
        payload_hex_truncated: Some(payload_hex_truncated),
        note: None,
    });
}

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_client_udp_recv(
    _remote_addr: SocketAddr,
    _our_user_hash: &[u8; 16],
    _sender_ip: [u8; 4],
    _datagram: &[u8],
) {
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_client_udp_recv(
    remote_addr: SocketAddr,
    our_user_hash: &[u8; 16],
    sender_ip: [u8; 4],
    datagram: &[u8],
) {
    let Some(decoded) = decode_client_udp_for_dump(our_user_hash, sender_ip, datagram) else {
        return;
    };
    let (raw_hex, _) = capped_packet_hex(datagram);
    let (payload_hex, payload_hex_truncated) = capped_packet_hex(&decoded.payload);
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
        remote_addr: remote_addr.to_string(),
        transport_mode: decoded.transport_mode,
        protocol: Some(client_udp_protocol_name(decoded.protocol_marker)),
        protocol_marker: Some(decoded.protocol_marker),
        opcode: Some(decoded.opcode),
        opcode_name: Some(client_udp_opcode_name(decoded.opcode)),
        raw_len: datagram.len(),
        raw_hex,
        payload_len: Some(decoded.payload.len()),
        payload_hex: Some(payload_hex),
        payload_hex_truncated: Some(payload_hex_truncated),
        note: None,
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
    sender_ip: [u8; 4],
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
    let plain = deobfuscate_client_udp(our_user_hash, sender_ip, datagram)?;
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

fn client_udp_dump_file() -> &'static StdMutex<Option<fs::File>> {
    static DUMP_FILE: OnceLock<StdMutex<Option<fs::File>>> = OnceLock::new();
    DUMP_FILE.get_or_init(|| {
        let file = std::env::var("EMULEBB_RUST_LOG_DIR")
            .ok()
            .map(std::path::PathBuf::from)
            .and_then(|dir| {
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
            });
        StdMutex::new(file)
    })
}

fn capped_packet_hex(bytes: &[u8]) -> (String, bool) {
    if bytes.len() > MAX_CLIENT_UDP_DUMP_HEX_BYTES {
        (hex::encode(&bytes[..MAX_CLIENT_UDP_DUMP_HEX_BYTES]), true)
    } else {
        (hex::encode(bytes), false)
    }
}

#[cfg(feature = "packet-diagnostics")]
fn dump_client_udp_record(record: &ClientUdpDumpRecord<'_>) {
    let Ok(line) = serde_json::to_string(record) else {
        return;
    };
    let Ok(mut guard) = client_udp_dump_file().lock() else {
        return;
    };
    let Some(file) = guard.as_mut() else {
        return;
    };
    let _ = std::io::Write::write_all(file, line.as_bytes());
    let _ = std::io::Write::write_all(file, b"\n");
}

#[cfg(test)]
mod tests {
    use super::{
        CLIENT_UDP_DUMP_FILE_PREFIX, OP_DIRECTCALLBACKREQ, OP_REASKACK, OP_REASKCALLBACKUDP,
        OP_REASKFILEPING, client_udp_opcode_name,
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
        assert_eq!(client_udp_opcode_name(0xFF), "UNKNOWN");
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
        let decoded = super::decode_client_udp_for_dump(&dest_hash, sender_ip, &datagram)
            .expect("obfuscated datagram decoded");
        assert_eq!(decoded.protocol_marker, 0xC5);
        assert_eq!(decoded.opcode, OP_REASKFILEPING);
        assert_eq!(decoded.transport_mode, "obfuscated");
    }

    #[test]
    #[cfg(feature = "packet-diagnostics")]
    fn client_udp_dump_rejects_non_client_foreign_datagrams() {
        assert!(super::decode_client_udp_for_dump(&[0x21; 16], [203, 0, 113, 9], &[1]).is_none());
    }
}
