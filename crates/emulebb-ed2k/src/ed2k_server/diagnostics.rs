use std::{
    fs,
    sync::{
        Mutex as StdMutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use chrono::SecondsFormat;
use serde::Serialize;

use super::{
    OP_CALLBACK_FAIL, OP_CALLBACKREQUESTED, OP_FOUNDSOURCES, OP_FOUNDSOURCES_OBFU,
    OP_GETSERVERLIST, OP_GETSOURCES, OP_GETSOURCES_OBFU, OP_IDCHANGE, OP_LOGINREQUEST,
    OP_OFFERFILES, OP_QUERY_MORE_RESULT, OP_REJECT, OP_SEARCHREQUEST, OP_SEARCHRESULT,
    OP_SERVERIDENT, OP_SERVERLIST, OP_SERVERMESSAGE, OP_SERVERSTATUS, ServerSession,
};

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
    phase: &'a str,
    direction: &'a str,
    endpoint: String,
    transport: &'a str,
    opcode: Option<String>,
    opcode_name: Option<&'static str>,
    payload_len: Option<usize>,
    payload_hex: Option<String>,
    note: Option<String>,
}

pub(super) fn dump_ed2k_server_meta(session: &ServerSession, note: impl Into<String>) {
    let record = Ed2kServerDumpRecord {
        schema: "ed2k_server_session_v1",
        source: "emulebb-rust",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: next_ed2k_server_dump_event_seq(),
        trace_id: session.trace_id,
        trace_key: ed2k_server_trace_key(session),
        state_id: ed2k_server_state_id(session),
        state_label: session.phase.as_str(),
        role: session.trace_role,
        phase: session.phase.as_str(),
        direction: "meta",
        endpoint: session.endpoint.to_string(),
        transport: if session.send_cipher.is_some() {
            "obfuscated"
        } else {
            "plaintext"
        },
        opcode: None,
        opcode_name: None,
        payload_len: None,
        payload_hex: None,
        note: Some(note.into()),
    };
    dump_ed2k_server_record(&record);
}

pub(super) fn dump_ed2k_server_packet(
    session: &ServerSession,
    direction: &'static str,
    opcode: u8,
    payload: &[u8],
) {
    let record = Ed2kServerDumpRecord {
        schema: "ed2k_server_session_v1",
        source: "emulebb-rust",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: next_ed2k_server_dump_event_seq(),
        trace_id: session.trace_id,
        trace_key: ed2k_server_trace_key(session),
        state_id: ed2k_server_state_id(session),
        state_label: session.phase.as_str(),
        role: session.trace_role,
        phase: session.phase.as_str(),
        direction,
        endpoint: session.endpoint.to_string(),
        transport: if session.send_cipher.is_some() {
            "obfuscated"
        } else {
            "plaintext"
        },
        opcode: Some(format!("0x{opcode:02X}")),
        opcode_name: Some(server_opcode_name(opcode)),
        payload_len: Some(payload.len()),
        payload_hex: Some(hex::encode(payload)),
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
                    "agent-ed2k-server-dump-{}.jsonl",
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
        OP_CALLBACKREQUESTED => "OP_CALLBACKREQUESTED",
        OP_CALLBACK_FAIL => "OP_CALLBACK_FAIL",
        OP_SERVERMESSAGE => "OP_SERVERMESSAGE",
        OP_IDCHANGE => "OP_IDCHANGE",
        OP_SERVERIDENT => "OP_SERVERIDENT",
        OP_FOUNDSOURCES => "OP_FOUNDSOURCES",
        OP_FOUNDSOURCES_OBFU => "OP_FOUNDSOURCES_OBFU",
        OP_REJECT => "OP_REJECT",
        _ => "UNKNOWN",
    }
}
