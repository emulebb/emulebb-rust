// Gated by the `packet-diagnostics` Cargo feature (matches the client dump and
// eMuleBB's EMULEBB_ENABLE_PACKET_DIAGNOSTICS): off-by-default builds compile the
// server dump out (emitters become no-ops, record machinery is dead-eliminated).
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

use super::{
    OP_CALLBACK_FAIL, OP_CALLBACKREQUEST, OP_CALLBACKREQUESTED, OP_FOUNDSOURCES,
    OP_FOUNDSOURCES_OBFU, OP_GETSERVERLIST, OP_GETSOURCES, OP_GETSOURCES_OBFU, OP_GLOBFOUNDSOURCES,
    OP_GLOBGETSOURCES, OP_GLOBGETSOURCES2, OP_GLOBSEARCHREQ, OP_GLOBSEARCHREQ2, OP_GLOBSEARCHREQ3,
    OP_GLOBSEARCHRES, OP_GLOBSERVSTATREQ, OP_GLOBSERVSTATRES, OP_IDCHANGE, OP_LOGINREQUEST,
    OP_OFFERFILES, OP_QUERY_MORE_RESULT, OP_REJECT, OP_SEARCHREQUEST, OP_SEARCHRESULT,
    OP_SERVERIDENT, OP_SERVERLIST, OP_SERVERMESSAGE, OP_SERVERSTATUS, ResolvedServerEntry,
    ServerSession,
};

const ED2K_SERVER_DUMP_FILE_PREFIX: &str = "emulebb-rust-ed2k-server-dump-";

/// eD2k server protocol marker (OP_EDONKEYPROT) — server packets ride the eD2k
/// protocol byte, same as the converged client/server packet diagnostics.
const OP_EDONKEYPROT_MARKER: u8 = 0xE3;
/// Payload hex cap, matching the client dump + eMuleBB diagnostic build.
const MAX_SERVER_DUMP_HEX_BYTES: usize = 4 * 1024;

/// One server-flow packet in the converged `ed2k_packet_v1` shape (flow="server"),
/// so client<->server traces diff 1:1 against eMuleBB's server-packet emitter.
/// Carries server-session extras (role/trace_id) the diff harness ignores.
#[derive(Debug, Serialize)]
struct Ed2kServerDumpRecord<'a> {
    schema: &'static str,
    source: &'static str,
    ts_utc: String,
    event_seq: u64,
    trace_id: u64,
    trace_key: String,
    state_id: String,
    state_label: &'a str,
    role: &'a str,
    flow: &'static str,
    phase: &'a str,
    direction: &'a str,
    remote_addr: String,
    transport_mode: &'a str,
    protocol: Option<&'static str>,
    protocol_marker: Option<u8>,
    opcode: Option<u8>,
    opcode_name: Option<&'static str>,
    payload_len: Option<usize>,
    payload_hex: Option<String>,
    payload_hex_truncated: Option<bool>,
    note: Option<String>,
}

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_ed2k_server_meta(_session: &ServerSession, _note: impl Into<String>) {}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_ed2k_server_meta(session: &ServerSession, note: impl Into<String>) {
    let record = Ed2kServerDumpRecord {
        schema: "ed2k_packet_v1",
        source: "emulebb-rust",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: next_ed2k_server_dump_event_seq(),
        trace_id: session.trace_id,
        trace_key: ed2k_server_trace_key(session),
        state_id: ed2k_server_state_id(session),
        state_label: session.phase.as_str(),
        role: session.trace_role,
        flow: "server",
        phase: session.phase.as_str(),
        direction: "meta",
        remote_addr: session.endpoint.to_string(),
        transport_mode: if session.send_cipher.is_some() {
            "obfuscated"
        } else {
            "plaintext"
        },
        protocol: None,
        protocol_marker: None,
        opcode: None,
        opcode_name: None,
        payload_len: None,
        payload_hex: None,
        payload_hex_truncated: None,
        note: Some(note.into()),
    };
    dump_ed2k_server_record(&record);
}

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_ed2k_server_packet(
    _session: &ServerSession,
    _direction: &'static str,
    _opcode: u8,
    _payload: &[u8],
) {
}

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_ed2k_server_udp_packet(
    _server: &ResolvedServerEntry,
    _direction: &'static str,
    _remote_addr: SocketAddr,
    _transport_mode: &'static str,
    _opcode: u8,
    _payload: &[u8],
) {
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_ed2k_server_udp_packet(
    server: &ResolvedServerEntry,
    direction: &'static str,
    remote_addr: SocketAddr,
    transport_mode: &'static str,
    opcode: u8,
    payload: &[u8],
) {
    let direction = match direction {
        "tx" => "send",
        "rx" => "recv",
        other => other,
    };
    let truncated = payload.len() > MAX_SERVER_DUMP_HEX_BYTES;
    let payload_hex = if truncated {
        hex::encode(&payload[..MAX_SERVER_DUMP_HEX_BYTES])
    } else {
        hex::encode(payload)
    };
    let base_endpoint = server.base_endpoint();
    let record = Ed2kServerDumpRecord {
        schema: "ed2k_packet_v1",
        source: "emulebb-rust",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: next_ed2k_server_dump_event_seq(),
        trace_id: 0,
        trace_key: format!("server:udp:{base_endpoint}"),
        state_id: format!("server.udp.{direction}"),
        state_label: "udp",
        role: "udp",
        flow: "server",
        phase: "udp",
        direction,
        remote_addr: remote_addr.to_string(),
        transport_mode,
        protocol: Some("ed2k"),
        protocol_marker: Some(OP_EDONKEYPROT_MARKER),
        opcode: Some(opcode),
        opcode_name: Some(server_opcode_name(opcode)),
        payload_len: Some(payload.len()),
        payload_hex: Some(payload_hex),
        payload_hex_truncated: Some(truncated),
        note: None,
    };
    dump_ed2k_server_record(&record);
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_ed2k_server_packet(
    session: &ServerSession,
    direction: &'static str,
    opcode: u8,
    payload: &[u8],
) {
    // Normalize the wire direction to the shared send/recv vocabulary so the
    // packet-trace diff harness aligns these with eMuleBB's server packets.
    let direction = match direction {
        "tx" => "send",
        "rx" => "recv",
        other => other,
    };
    let truncated = payload.len() > MAX_SERVER_DUMP_HEX_BYTES;
    let payload_hex = if truncated {
        hex::encode(&payload[..MAX_SERVER_DUMP_HEX_BYTES])
    } else {
        hex::encode(payload)
    };
    let record = Ed2kServerDumpRecord {
        schema: "ed2k_packet_v1",
        source: "emulebb-rust",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: next_ed2k_server_dump_event_seq(),
        trace_id: session.trace_id,
        trace_key: ed2k_server_trace_key(session),
        state_id: ed2k_server_state_id(session),
        state_label: session.phase.as_str(),
        role: session.trace_role,
        flow: "server",
        phase: session.phase.as_str(),
        direction,
        remote_addr: session.endpoint.to_string(),
        transport_mode: if session.send_cipher.is_some() {
            "obfuscated"
        } else {
            "plaintext"
        },
        protocol: Some("ed2k"),
        protocol_marker: Some(OP_EDONKEYPROT_MARKER),
        opcode: Some(opcode),
        opcode_name: Some(server_opcode_name(opcode)),
        payload_len: Some(payload.len()),
        payload_hex: Some(payload_hex),
        payload_hex_truncated: Some(truncated),
        note: None,
    };
    dump_ed2k_server_record(&record);
}

fn next_ed2k_server_dump_event_seq() -> u64 {
    static NEXT_EVENT_SEQ: AtomicU64 = AtomicU64::new(1);
    NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed)
}

fn ed2k_server_trace_key(session: &ServerSession) -> String {
    format!(
        "server:{}:{}:{}",
        session.trace_role, session.trace_id, session.endpoint
    )
}

fn ed2k_server_state_id(session: &ServerSession) -> String {
    format!("server.{}.{}", session.trace_role, session.phase.as_str())
}

fn ed2k_server_dump_file() -> &'static StdMutex<Option<fs::File>> {
    static DUMP_FILE: OnceLock<StdMutex<Option<fs::File>>> = OnceLock::new();
    DUMP_FILE.get_or_init(|| {
        let file = std::env::var("EMULEBB_RUST_LOG_DIR")
            .ok()
            .map(std::path::PathBuf::from)
            .and_then(|dir| {
                fs::create_dir_all(&dir).ok()?;
                let path = dir.join(format!(
                    "{}{}.jsonl",
                    ED2K_SERVER_DUMP_FILE_PREFIX,
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

fn dump_ed2k_server_record(record: &Ed2kServerDumpRecord<'_>) {
    let Ok(line) = serde_json::to_string(record) else {
        return;
    };
    let Ok(mut guard) = ed2k_server_dump_file().lock() else {
        return;
    };
    let Some(file) = guard.as_mut() else {
        return;
    };
    let _ = std::io::Write::write_all(file, line.as_bytes());
    let _ = std::io::Write::write_all(file, b"\n");
}

fn server_opcode_name(opcode: u8) -> &'static str {
    match opcode {
        OP_LOGINREQUEST => "OP_LOGINREQUEST",
        OP_GETSERVERLIST => "OP_GETSERVERLIST",
        OP_OFFERFILES => "OP_OFFERFILES",
        OP_SEARCHREQUEST => "OP_SEARCHREQUEST",
        OP_GETSOURCES => "OP_GETSOURCES",
        OP_GETSOURCES_OBFU => "OP_GETSOURCES_OBFU",
        OP_QUERY_MORE_RESULT => "OP_QUERY_MORE_RESULT",
        OP_SERVERLIST => "OP_SERVERLIST",
        OP_SEARCHRESULT => "OP_SEARCHRESULT",
        OP_SERVERSTATUS => "OP_SERVERSTATUS",
        OP_CALLBACKREQUEST => "OP_CALLBACKREQUEST",
        OP_CALLBACKREQUESTED => "OP_CALLBACKREQUESTED",
        OP_CALLBACK_FAIL => "OP_CALLBACK_FAIL",
        OP_SERVERMESSAGE => "OP_SERVERMESSAGE",
        OP_IDCHANGE => "OP_IDCHANGE",
        OP_SERVERIDENT => "OP_SERVERIDENT",
        OP_FOUNDSOURCES => "OP_FOUNDSOURCES",
        OP_FOUNDSOURCES_OBFU => "OP_FOUNDSOURCES_OBFU",
        OP_GLOBSEARCHREQ => "OP_GLOBSEARCHREQ",
        OP_GLOBSEARCHREQ2 => "OP_GLOBSEARCHREQ2",
        OP_GLOBSEARCHREQ3 => "OP_GLOBSEARCHREQ3",
        OP_GLOBSEARCHRES => "OP_GLOBSEARCHRES",
        OP_GLOBGETSOURCES => "OP_GLOBGETSOURCES",
        OP_GLOBGETSOURCES2 => "OP_GLOBGETSOURCES2",
        OP_GLOBFOUNDSOURCES => "OP_GLOBFOUNDSOURCES",
        OP_GLOBSERVSTATREQ => "OP_GLOBSERVSTATREQ",
        OP_GLOBSERVSTATRES => "OP_GLOBSERVSTATRES",
        OP_REJECT => "OP_REJECT",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ED2K_SERVER_DUMP_FILE_PREFIX, OP_CALLBACKREQUEST, OP_GLOBFOUNDSOURCES, OP_GLOBSEARCHREQ,
        OP_GLOBSEARCHREQ2, OP_GLOBSEARCHREQ3, OP_GLOBSEARCHRES, server_opcode_name,
    };

    #[test]
    fn server_dump_prefix_uses_emulebb_rust_name() {
        assert_eq!(
            ED2K_SERVER_DUMP_FILE_PREFIX,
            "emulebb-rust-ed2k-server-dump-"
        );
    }

    #[test]
    fn server_dump_names_global_udp_opcodes() {
        assert_eq!(server_opcode_name(OP_CALLBACKREQUEST), "OP_CALLBACKREQUEST");
        assert_eq!(server_opcode_name(OP_GLOBSEARCHREQ), "OP_GLOBSEARCHREQ");
        assert_eq!(server_opcode_name(OP_GLOBSEARCHREQ2), "OP_GLOBSEARCHREQ2");
        assert_eq!(server_opcode_name(OP_GLOBSEARCHREQ3), "OP_GLOBSEARCHREQ3");
        assert_eq!(server_opcode_name(OP_GLOBSEARCHRES), "OP_GLOBSEARCHRES");
        assert_eq!(
            server_opcode_name(OP_GLOBFOUNDSOURCES),
            "OP_GLOBFOUNDSOURCES"
        );
    }
}
