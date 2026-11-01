// Gated by the `packet-diagnostics` Cargo feature: off-by-default builds keep
// only no-op call boundaries and compile all unified diagnostic machinery out.
use std::net::SocketAddr;

#[cfg(feature = "packet-diagnostics")]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(any(feature = "packet-diagnostics", test))]
use serde_json::{Map, Value, json};

#[cfg(any(feature = "packet-diagnostics", test))]
use super::{
    OP_CALLBACK_FAIL, OP_CALLBACKREQUEST, OP_CALLBACKREQUESTED, OP_FOUNDSOURCES,
    OP_FOUNDSOURCES_OBFU, OP_GETSERVERLIST, OP_GETSOURCES, OP_GETSOURCES_OBFU, OP_GLOBCALLBACKREQ,
    OP_GLOBFOUNDSOURCES, OP_GLOBGETSOURCES, OP_GLOBGETSOURCES2, OP_GLOBSEARCHREQ,
    OP_GLOBSEARCHREQ2, OP_GLOBSEARCHREQ3, OP_GLOBSEARCHRES, OP_GLOBSERVSTATREQ, OP_GLOBSERVSTATRES,
    OP_IDCHANGE, OP_LOGINREQUEST, OP_OFFERFILES, OP_PACKEDPROT, OP_QUERY_MORE_RESULT, OP_REJECT,
    OP_SEARCHREQUEST, OP_SEARCHRESULT, OP_SERVER_DESC_REQ, OP_SERVER_DESC_RES, OP_SERVER_LIST_REQ,
    OP_SERVER_LIST_REQ2, OP_SERVER_LIST_RES, OP_SERVERIDENT, OP_SERVERLIST, OP_SERVERMESSAGE,
    OP_SERVERSTATUS,
};
use super::{ResolvedServerEntry, ServerSession};

/// eD2k server protocol marker (OP_EDONKEYPROT) — server packets ride the eD2k
/// protocol byte unless the server advertised packed payload support.
#[cfg(any(feature = "packet-diagnostics", test))]
const OP_EDONKEYPROT_MARKER: u8 = 0xE3;
/// One server-flow diagnostic record, normalized into the converged
/// `diag_event_v2` envelope so client<->server traces diff 1:1 against eMuleBB's
/// server-packet emitter. Carries server-session extras (role/trace_id) the diff
/// harness ignores.
#[cfg(any(feature = "packet-diagnostics", test))]
#[derive(Debug)]
struct Ed2kServerDumpRecord<'a> {
    trace_id: u64,
    trace_key: String,
    state_id: String,
    state_label: &'a str,
    role: &'a str,
    flow: &'static str,
    phase: &'a str,
    direction: &'a str,
    outcome: &'a str,
    send_attempt_id: Option<u64>,
    remote_addr: String,
    transport_mode: &'a str,
    obfuscated: Option<bool>,
    protocol: Option<&'static str>,
    protocol_marker: Option<u8>,
    opcode: Option<u8>,
    opcode_name: Option<&'static str>,
    raw_len: Option<usize>,
    raw_hex: Option<String>,
    clear_frame_len: Option<usize>,
    clear_frame_hex: Option<String>,
    payload_len: Option<usize>,
    payload_hex: Option<String>,
    payload_hex_truncated: Option<bool>,
    note: Option<String>,
}

#[cfg(feature = "packet-diagnostics")]
pub(super) struct Ed2kServerPacketCapture<'a> {
    pub(super) direction: &'static str,
    pub(super) transport_mode: &'static str,
    pub(super) obfuscated: Option<bool>,
    pub(super) protocol_marker: Option<u8>,
    pub(super) opcode: Option<u8>,
    pub(super) raw: &'a [u8],
    pub(super) clear_frame: Option<&'a [u8]>,
    pub(super) payload: Option<&'a [u8]>,
    pub(super) outcome: &'static str,
    pub(super) note: Option<String>,
}

#[cfg(any(feature = "packet-diagnostics", test))]
struct Ed2kServerSendContext {
    family: &'static str,
    attempt_id: u64,
    trace_id: u64,
    trace_key: String,
    state_id: String,
    state_label: &'static str,
    role: &'static str,
    phase: &'static str,
    remote_addr: String,
    transport_mode: &'static str,
    obfuscated: Option<bool>,
    protocol_marker: Option<u8>,
    opcode: Option<u8>,
    attempted_len: usize,
}

#[cfg(any(feature = "packet-diagnostics", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ed2kServerSendOutcome {
    Succeeded,
    Failed,
    Cancelled,
}

#[cfg(any(feature = "packet-diagnostics", test))]
impl Ed2kServerSendOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "send_succeeded",
            Self::Failed => "send_failed",
            Self::Cancelled => "send_cancelled",
        }
    }

    const fn severity(self) -> &'static str {
        match self {
            Self::Succeeded => "info",
            Self::Failed | Self::Cancelled => "warning",
        }
    }
}

#[cfg(feature = "packet-diagnostics")]
pub(super) struct Ed2kServerSendAttempt {
    context: Ed2kServerSendContext,
    completed: bool,
}

#[cfg(feature = "packet-diagnostics")]
impl Ed2kServerSendAttempt {
    pub(super) fn tcp(session: &ServerSession, capture: Ed2kServerPacketCapture<'_>) -> Self {
        let attempt_id = next_ed2k_server_send_attempt_id();
        let context = Ed2kServerSendContext {
            family: "ed2k_tcp",
            attempt_id,
            trace_id: session.trace_id,
            trace_key: ed2k_server_trace_key(session),
            state_id: ed2k_server_state_id(session),
            state_label: session.phase.as_str(),
            role: session.trace_role,
            phase: session.phase.as_str(),
            remote_addr: session.endpoint.to_string(),
            transport_mode: capture.transport_mode,
            obfuscated: capture.obfuscated,
            protocol_marker: capture.protocol_marker,
            opcode: capture.opcode,
            attempted_len: capture.raw.len(),
        };
        dump_ed2k_server_packet_with_attempt(session, capture, Some(attempt_id));
        Self {
            context,
            completed: false,
        }
    }

    pub(super) fn udp(
        server: Option<&ResolvedServerEntry>,
        remote_addr: SocketAddr,
        capture: Ed2kServerPacketCapture<'_>,
    ) -> Self {
        let attempt_id = next_ed2k_server_send_attempt_id();
        let base_endpoint = server
            .map(ResolvedServerEntry::base_endpoint)
            .unwrap_or(remote_addr);
        let context = Ed2kServerSendContext {
            family: "ed2k_server_udp",
            attempt_id,
            trace_id: 0,
            trace_key: format!("server:udp:{base_endpoint}"),
            state_id: "server.udp.send".to_string(),
            state_label: "udp",
            role: "udp",
            phase: "udp",
            remote_addr: remote_addr.to_string(),
            transport_mode: capture.transport_mode,
            obfuscated: capture.obfuscated,
            protocol_marker: capture.protocol_marker,
            opcode: capture.opcode,
            attempted_len: capture.raw.len(),
        };
        dump_ed2k_server_udp_packet_with_attempt(server, remote_addr, 0, capture, Some(attempt_id));
        Self {
            context,
            completed: false,
        }
    }

    fn settle(
        &mut self,
        outcome: Ed2kServerSendOutcome,
        delivery_known: bool,
        note: Option<String>,
    ) {
        self.completed = true;
        emit_ed2k_server_send_outcome(&self.context, outcome, delivery_known, note.as_deref());
    }

    pub(super) fn succeeded(mut self) {
        self.settle(Ed2kServerSendOutcome::Succeeded, true, None);
    }

    pub(super) fn failed(mut self, error: String) {
        self.settle(Ed2kServerSendOutcome::Failed, true, Some(error));
    }
}

#[cfg(feature = "packet-diagnostics")]
impl Drop for Ed2kServerSendAttempt {
    fn drop(&mut self) {
        if !self.completed {
            self.settle(
                Ed2kServerSendOutcome::Cancelled,
                false,
                Some(format!(
                    "server {} send future cancelled before completion",
                    if self.context.role == "udp" {
                        "UDP"
                    } else {
                        "TCP"
                    }
                )),
            );
        }
    }
}

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_ed2k_server_meta(_session: &ServerSession, _note: impl Into<String>) {}

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_ed2k_server_status_applied(_session: &ServerSession, _users: u32, _files: u32) {}

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_ed2k_server_ident_applied(
    _session: &ServerSession,
    _name: Option<&str>,
    _description: Option<&str>,
) {
}

#[cfg(not(feature = "packet-diagnostics"))]
#[expect(
    clippy::too_many_arguments,
    reason = "flat diagnostic correlation fields"
)]
pub(super) fn dump_ed2k_server_source_result_applied(
    _endpoint: &str,
    _trace_id: u64,
    _transport_mode: &'static str,
    _response_opcode: u8,
    _file_hash: emulebb_kad_proto::Ed2kHash,
    _wire_source_count: usize,
    _source_count_before: usize,
    _source_count_after: usize,
) {
}

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_ed2k_server_loop_meta(
    _endpoint: &str,
    _phase: &'static str,
    _note: impl Into<String>,
) {
}

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_ed2k_server_transport_fallback(
    _endpoint: &str,
    _trace_id: u64,
    _from_transport_mode: &'static str,
    _to_transport_mode: &'static str,
    _error: &str,
) {
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_ed2k_server_meta(session: &ServerSession, note: impl Into<String>) {
    let record = Ed2kServerDumpRecord {
        trace_id: session.trace_id,
        trace_key: ed2k_server_trace_key(session),
        state_id: ed2k_server_state_id(session),
        state_label: session.phase.as_str(),
        role: session.trace_role,
        flow: "server",
        phase: session.phase.as_str(),
        direction: "meta",
        outcome: "meta",
        send_attempt_id: None,
        remote_addr: session.endpoint.to_string(),
        transport_mode: if session.send_cipher.is_some() {
            "obfuscated"
        } else {
            "plaintext"
        },
        obfuscated: Some(session.send_cipher.is_some()),
        protocol: None,
        protocol_marker: None,
        opcode: None,
        opcode_name: None,
        raw_len: None,
        raw_hex: None,
        clear_frame_len: None,
        clear_frame_hex: None,
        payload_len: None,
        payload_hex: None,
        payload_hex_truncated: None,
        note: Some(note.into()),
    };
    emit_ed2k_server_diag_event(&record);
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_ed2k_server_status_applied(session: &ServerSession, users: u32, files: u32) {
    let (keys, body) = ed2k_server_status_applied_parts(
        &session.endpoint.to_string(),
        session.trace_id,
        session.trace_role,
        session.phase.as_str(),
        session.send_cipher.is_some(),
        users,
        files,
    );
    crate::diag_event::emit("ed2k_tcp", "server_status_applied", "info", keys, body);
}

#[cfg(any(feature = "packet-diagnostics", test))]
fn ed2k_server_status_applied_parts(
    endpoint: &str,
    trace_id: u64,
    role: &str,
    phase: &str,
    obfuscated: bool,
    users: u32,
    files: u32,
) -> (Value, Value) {
    server_tcp_metadata_applied_parts(
        endpoint,
        trace_id,
        role,
        phase,
        obfuscated,
        OP_SERVERSTATUS,
        "OP_SERVERSTATUS",
        json!({
            "users": users,
            "files": files,
        }),
    )
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_ed2k_server_ident_applied(
    session: &ServerSession,
    name: Option<&str>,
    description: Option<&str>,
) {
    let (keys, body) = ed2k_server_ident_applied_parts(
        &session.endpoint.to_string(),
        session.trace_id,
        session.trace_role,
        session.phase.as_str(),
        session.send_cipher.is_some(),
        name,
        description,
    );
    crate::diag_event::emit("ed2k_tcp", "server_ident_applied", "info", keys, body);
}

#[cfg(any(feature = "packet-diagnostics", test))]
fn ed2k_server_ident_applied_parts(
    endpoint: &str,
    trace_id: u64,
    role: &str,
    phase: &str,
    obfuscated: bool,
    name: Option<&str>,
    description: Option<&str>,
) -> (Value, Value) {
    server_tcp_metadata_applied_parts(
        endpoint,
        trace_id,
        role,
        phase,
        obfuscated,
        OP_SERVERIDENT,
        "OP_SERVERIDENT",
        json!({
            "name": name,
            "description": description,
        }),
    )
}

#[cfg(any(feature = "packet-diagnostics", test))]
#[expect(
    clippy::too_many_arguments,
    reason = "flat diagnostic correlation and decoded metadata fields"
)]
fn server_tcp_metadata_applied_parts(
    endpoint: &str,
    trace_id: u64,
    role: &str,
    phase: &str,
    obfuscated: bool,
    opcode: u8,
    opcode_name: &str,
    fields: Value,
) -> (Value, Value) {
    let transport_mode = if obfuscated {
        "obfuscated"
    } else {
        "plaintext"
    };
    let trace_key = format!("server:{role}:{trace_id}:{endpoint}");
    let state_id = format!("server.{role}.{phase}");
    let mut body = fields.as_object().cloned().unwrap_or_default();
    body.extend(Map::from_iter([
        ("direction".to_string(), json!("meta")),
        ("outcome".to_string(), json!("applied")),
        ("protocolMarker".to_string(), json!(OP_EDONKEYPROT_MARKER)),
        ("protocolName".to_string(), json!("ed2k")),
        ("opcode".to_string(), json!(opcode)),
        ("opcodeName".to_string(), json!(opcode_name)),
        ("obfuscated".to_string(), json!(obfuscated)),
        ("transportMode".to_string(), json!(transport_mode)),
        ("flow".to_string(), json!("server")),
        ("phase".to_string(), json!(phase)),
        ("role".to_string(), json!(role)),
        ("traceId".to_string(), json!(trace_id)),
        ("traceKey".to_string(), json!(trace_key)),
        ("stateId".to_string(), json!(state_id)),
        ("stateLabel".to_string(), json!(phase)),
    ]));
    (
        json!({
            "peer": endpoint,
            "traceId": trace_id,
            "protocolMarker": OP_EDONKEYPROT_MARKER,
            "opcode": opcode,
        }),
        Value::Object(body),
    )
}

#[cfg(feature = "packet-diagnostics")]
#[expect(
    clippy::too_many_arguments,
    reason = "flat diagnostic correlation fields"
)]
pub(super) fn dump_ed2k_server_source_result_applied(
    endpoint: &str,
    trace_id: u64,
    transport_mode: &'static str,
    response_opcode: u8,
    file_hash: emulebb_kad_proto::Ed2kHash,
    wire_source_count: usize,
    source_count_before: usize,
    source_count_after: usize,
) {
    let (keys, body) = ed2k_server_source_result_applied_parts(
        endpoint,
        trace_id,
        transport_mode,
        response_opcode,
        file_hash,
        wire_source_count,
        source_count_before,
        source_count_after,
    );
    crate::diag_event::emit("ed2k_tcp", "source_result_applied", "info", keys, body);
}

#[cfg(any(feature = "packet-diagnostics", test))]
#[expect(
    clippy::too_many_arguments,
    reason = "flat diagnostic correlation fields"
)]
fn ed2k_server_source_result_applied_parts(
    endpoint: &str,
    trace_id: u64,
    transport_mode: &'static str,
    response_opcode: u8,
    file_hash: emulebb_kad_proto::Ed2kHash,
    wire_source_count: usize,
    source_count_before: usize,
    source_count_after: usize,
) -> (Value, Value) {
    let obfuscated = response_opcode == OP_FOUNDSOURCES_OBFU;
    let opcode_name = if obfuscated {
        "OP_FOUNDSOURCES_OBFU"
    } else {
        "OP_FOUNDSOURCES"
    };
    (
        json!({
            "peer": endpoint,
            "fileHash": file_hash.to_string(),
            "opcode": response_opcode,
            "protocolMarker": OP_EDONKEYPROT_MARKER,
            "traceId": trace_id,
        }),
        json!({
            "flow": "server",
            "phase": "source_search",
            "direction": "recv",
            "protocolMarker": OP_EDONKEYPROT_MARKER,
            "opcode": response_opcode,
            "opcodeName": opcode_name,
            "traceId": trace_id,
            "transportMode": transport_mode,
            "obfuscated": obfuscated,
            "stateId": "server.source.result_applied",
            "milestone": "result_applied",
            "wireSourceCount": wire_source_count,
            "sourceCountBefore": source_count_before,
            "sourceCountAfter": source_count_after,
            "outcome": "applied",
        }),
    )
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_ed2k_server_loop_meta(
    endpoint: &str,
    phase: &'static str,
    note: impl Into<String>,
) {
    let record = Ed2kServerDumpRecord {
        trace_id: 0,
        trace_key: format!("server:background:loop:{endpoint}"),
        state_id: format!("server.background.{phase}"),
        state_label: phase,
        role: "background",
        flow: "server",
        phase,
        direction: "meta",
        outcome: "meta",
        send_attempt_id: None,
        remote_addr: endpoint.to_string(),
        transport_mode: "unknown",
        obfuscated: None,
        protocol: None,
        protocol_marker: None,
        opcode: None,
        opcode_name: None,
        raw_len: None,
        raw_hex: None,
        clear_frame_len: None,
        clear_frame_hex: None,
        payload_len: None,
        payload_hex: None,
        payload_hex_truncated: None,
        note: Some(note.into()),
    };
    emit_ed2k_server_diag_event(&record);
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_ed2k_server_transport_fallback(
    endpoint: &str,
    trace_id: u64,
    from_transport_mode: &'static str,
    to_transport_mode: &'static str,
    error: &str,
) {
    let (family, event, severity, keys, body) = ed2k_server_transport_fallback_parts(
        endpoint,
        trace_id,
        from_transport_mode,
        to_transport_mode,
        error,
    );
    crate::diag_event::emit(family, event, severity, keys, body);
}

#[cfg(any(feature = "packet-diagnostics", test))]
fn ed2k_server_transport_fallback_parts(
    endpoint: &str,
    trace_id: u64,
    from_transport_mode: &'static str,
    to_transport_mode: &'static str,
    error: &str,
) -> (&'static str, &'static str, &'static str, Value, Value) {
    (
        "ed2k_tcp",
        "transport_fallback",
        "warning",
        json!({
            "peer": endpoint,
            "flow": "server",
            "traceId": trace_id,
        }),
        json!({
            "flow": "server",
            "phase": "connection",
            "outcome": "retrying",
            "fromTransportMode": from_transport_mode,
            "toTransportMode": to_transport_mode,
            "error": error,
            "traceId": trace_id,
        }),
    )
}

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_ed2k_server_packet(
    _session: &ServerSession,
    _direction: &'static str,
    _protocol_marker: u8,
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
    _trace_id: u64,
) {
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_ed2k_server_udp_packet(
    server: Option<&ResolvedServerEntry>,
    remote_addr: SocketAddr,
    trace_id: u64,
    capture: Ed2kServerPacketCapture<'_>,
) {
    dump_ed2k_server_udp_packet_with_attempt(server, remote_addr, trace_id, capture, None);
}

#[cfg(feature = "packet-diagnostics")]
fn dump_ed2k_server_udp_packet_with_attempt(
    server: Option<&ResolvedServerEntry>,
    remote_addr: SocketAddr,
    trace_id: u64,
    capture: Ed2kServerPacketCapture<'_>,
    send_attempt_id: Option<u64>,
) {
    let direction = match capture.direction {
        "tx" => "send",
        "rx" => "recv",
        other => other,
    };
    let base_endpoint = server
        .map(ResolvedServerEntry::base_endpoint)
        .unwrap_or(remote_addr);
    let trace_key = if trace_id == 0 {
        format!("server:udp:{base_endpoint}")
    } else {
        format!("server:udp:{trace_id}:{remote_addr}")
    };
    let record = Ed2kServerDumpRecord {
        trace_id,
        trace_key,
        state_id: format!("server.udp.{direction}"),
        state_label: "udp",
        role: "udp",
        flow: "server",
        phase: "udp",
        direction,
        outcome: capture.outcome,
        send_attempt_id,
        remote_addr: remote_addr.to_string(),
        transport_mode: capture.transport_mode,
        obfuscated: capture.obfuscated,
        protocol: capture.protocol_marker.map(server_protocol_name),
        protocol_marker: capture.protocol_marker,
        opcode: capture.opcode,
        opcode_name: capture.opcode.map(server_opcode_name),
        raw_len: Some(capture.raw.len()),
        raw_hex: Some(exact_packet_hex(capture.raw)),
        clear_frame_len: capture.clear_frame.map(<[u8]>::len),
        clear_frame_hex: capture.clear_frame.map(exact_packet_hex),
        payload_len: capture.payload.map(<[u8]>::len),
        payload_hex: capture.payload.map(exact_packet_hex),
        payload_hex_truncated: capture.payload.map(|_| false),
        note: capture.note,
    };
    emit_ed2k_server_diag_event(&record);
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_ed2k_server_packet(
    session: &ServerSession,
    capture: Ed2kServerPacketCapture<'_>,
) {
    dump_ed2k_server_packet_with_attempt(session, capture, None);
}

#[cfg(feature = "packet-diagnostics")]
fn dump_ed2k_server_packet_with_attempt(
    session: &ServerSession,
    capture: Ed2kServerPacketCapture<'_>,
    send_attempt_id: Option<u64>,
) {
    // Normalize the wire direction to the shared send/recv vocabulary so the
    // packet-trace diff harness aligns these with eMuleBB's server packets.
    let direction = match capture.direction {
        "tx" => "send",
        "rx" => "recv",
        other => other,
    };
    let record = Ed2kServerDumpRecord {
        trace_id: session.trace_id,
        trace_key: ed2k_server_trace_key(session),
        state_id: ed2k_server_state_id(session),
        state_label: session.phase.as_str(),
        role: session.trace_role,
        flow: "server",
        phase: session.phase.as_str(),
        direction,
        outcome: capture.outcome,
        send_attempt_id,
        remote_addr: session.endpoint.to_string(),
        transport_mode: capture.transport_mode,
        obfuscated: capture.obfuscated,
        protocol: capture.protocol_marker.map(server_protocol_name),
        protocol_marker: capture.protocol_marker,
        opcode: capture.opcode,
        opcode_name: capture.opcode.map(server_opcode_name),
        raw_len: Some(capture.raw.len()),
        raw_hex: Some(exact_packet_hex(capture.raw)),
        clear_frame_len: capture.clear_frame.map(<[u8]>::len),
        clear_frame_hex: capture.clear_frame.map(exact_packet_hex),
        payload_len: capture.payload.map(<[u8]>::len),
        payload_hex: capture.payload.map(exact_packet_hex),
        payload_hex_truncated: capture.payload.map(|_| false),
        note: capture.note,
    };
    emit_ed2k_server_diag_event(&record);
}

#[cfg(any(feature = "packet-diagnostics", test))]
fn server_protocol_name(protocol_marker: u8) -> &'static str {
    match protocol_marker {
        OP_EDONKEYPROT_MARKER => "ed2k",
        OP_PACKEDPROT => "packed",
        _ => "unknown",
    }
}

#[cfg(any(feature = "packet-diagnostics", test))]
fn exact_packet_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(feature = "packet-diagnostics")]
fn next_ed2k_server_send_attempt_id() -> u64 {
    static NEXT_SEND_ATTEMPT_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_SEND_ATTEMPT_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(feature = "packet-diagnostics")]
fn ed2k_server_trace_key(session: &ServerSession) -> String {
    format!(
        "server:{}:{}:{}",
        session.trace_role, session.trace_id, session.endpoint
    )
}

#[cfg(feature = "packet-diagnostics")]
fn ed2k_server_state_id(session: &ServerSession) -> String {
    format!("server.{}.{}", session.trace_role, session.phase.as_str())
}

#[cfg(feature = "packet-diagnostics")]
fn emit_ed2k_server_diag_event(record: &Ed2kServerDumpRecord<'_>) {
    let (family, event, severity, keys, body) = ed2k_server_diag_event_parts(record);
    crate::diag_event::emit(family, event, severity, keys, body);
}

#[cfg(any(feature = "packet-diagnostics", test))]
fn ed2k_server_diag_event_parts(
    record: &Ed2kServerDumpRecord<'_>,
) -> (&'static str, &'static str, &'static str, Value, Value) {
    let family = if record.role == "udp" {
        "ed2k_server_udp"
    } else {
        "ed2k_tcp"
    };
    let event = if record.direction == "meta" {
        "state"
    } else {
        "packet"
    };
    let severity = if matches!(record.outcome, "dropped" | "send_failed") {
        "warning"
    } else {
        "info"
    };

    let mut keys = Map::new();
    keys.insert("peer".to_string(), json!(record.remote_addr));
    if record.role == "udp" && record.trace_id > 0 {
        keys.insert("traceId".to_string(), json!(record.trace_id));
    }
    if let Some(send_attempt_id) = record.send_attempt_id {
        keys.insert("sendAttemptId".to_string(), json!(send_attempt_id));
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
    if let Some(send_attempt_id) = record.send_attempt_id {
        body.insert("sendAttemptId".to_string(), json!(send_attempt_id));
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
    body.insert("role".to_string(), json!(record.role));
    body.insert("traceId".to_string(), json!(record.trace_id));
    body.insert("traceKey".to_string(), json!(record.trace_key));
    body.insert("stateId".to_string(), json!(record.state_id));
    body.insert("stateLabel".to_string(), json!(record.state_label));
    if let Some(note) = record.note.as_deref() {
        body.insert("note".to_string(), json!(note));
    }

    (
        family,
        event,
        severity,
        Value::Object(keys),
        Value::Object(body),
    )
}

#[cfg(feature = "packet-diagnostics")]
fn emit_ed2k_server_send_outcome(
    context: &Ed2kServerSendContext,
    outcome: Ed2kServerSendOutcome,
    delivery_known: bool,
    note: Option<&str>,
) {
    let (family, severity, keys, body) =
        ed2k_server_send_outcome_parts(context, outcome, delivery_known, note);
    crate::diag_event::emit(family, "send_outcome", severity, keys, body);
}

#[cfg(any(feature = "packet-diagnostics", test))]
fn ed2k_server_send_outcome_parts(
    context: &Ed2kServerSendContext,
    outcome: Ed2kServerSendOutcome,
    delivery_known: bool,
    note: Option<&str>,
) -> (&'static str, &'static str, Value, Value) {
    let mut keys = Map::new();
    keys.insert("peer".to_string(), json!(context.remote_addr));
    keys.insert("sendAttemptId".to_string(), json!(context.attempt_id));
    if let Some(protocol_marker) = context.protocol_marker {
        keys.insert("protocolMarker".to_string(), json!(protocol_marker));
    }
    if let Some(opcode) = context.opcode {
        keys.insert("opcode".to_string(), json!(opcode));
    }

    let mut body = Map::new();
    body.insert("direction".to_string(), json!("send"));
    body.insert("outcome".to_string(), json!(outcome.as_str()));
    body.insert("deliveryKnown".to_string(), json!(delivery_known));
    body.insert("sendAttemptId".to_string(), json!(context.attempt_id));
    body.insert("traceId".to_string(), json!(context.trace_id));
    body.insert("traceKey".to_string(), json!(context.trace_key));
    body.insert("stateId".to_string(), json!(context.state_id));
    body.insert("stateLabel".to_string(), json!(context.state_label));
    body.insert("role".to_string(), json!(context.role));
    body.insert("flow".to_string(), json!("server"));
    body.insert("phase".to_string(), json!(context.phase));
    body.insert("transportMode".to_string(), json!(context.transport_mode));
    body.insert("attemptedLen".to_string(), json!(context.attempted_len));
    if let Some(obfuscated) = context.obfuscated {
        body.insert("obfuscated".to_string(), json!(obfuscated));
    }
    if let Some(protocol_marker) = context.protocol_marker {
        body.insert("protocolMarker".to_string(), json!(protocol_marker));
        body.insert(
            "protocolName".to_string(),
            json!(server_protocol_name(protocol_marker)),
        );
    }
    if let Some(opcode) = context.opcode {
        body.insert("opcode".to_string(), json!(opcode));
        body.insert("opcodeName".to_string(), json!(server_opcode_name(opcode)));
    }
    if let Some(note) = note {
        body.insert("note".to_string(), json!(note));
    }

    (
        context.family,
        outcome.severity(),
        Value::Object(keys),
        Value::Object(body),
    )
}

#[cfg(any(feature = "packet-diagnostics", test))]
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
        OP_GLOBCALLBACKREQ => "OP_GLOBCALLBACKREQ",
        OP_GLOBSERVSTATREQ => "OP_GLOBSERVSTATREQ",
        OP_GLOBSERVSTATRES => "OP_GLOBSERVSTATRES",
        OP_SERVER_LIST_REQ => "OP_SERVER_LIST_REQ",
        OP_SERVER_LIST_RES => "OP_SERVER_LIST_RES",
        OP_SERVER_DESC_REQ => "OP_SERVER_DESC_REQ",
        OP_SERVER_DESC_RES => "OP_SERVER_DESC_RES",
        OP_SERVER_LIST_REQ2 => "OP_SERVER_LIST_REQ2",
        OP_REJECT => "OP_REJECT",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Ed2kServerDumpRecord, Ed2kServerSendContext, Ed2kServerSendOutcome, OP_CALLBACKREQUEST,
        OP_EDONKEYPROT_MARKER, OP_FOUNDSOURCES, OP_GLOBCALLBACKREQ, OP_GLOBFOUNDSOURCES,
        OP_GLOBSEARCHREQ, OP_GLOBSEARCHREQ2, OP_GLOBSEARCHREQ3, OP_GLOBSEARCHRES,
        OP_GLOBSERVSTATREQ, OP_GLOBSERVSTATRES, OP_PACKEDPROT, OP_SERVER_DESC_RES,
        OP_SERVER_LIST_REQ, OP_SERVER_LIST_REQ2, OP_SERVER_LIST_RES, OP_SERVERIDENT,
        OP_SERVERSTATUS, ed2k_server_diag_event_parts, ed2k_server_ident_applied_parts,
        ed2k_server_send_outcome_parts, ed2k_server_source_result_applied_parts,
        ed2k_server_status_applied_parts, ed2k_server_transport_fallback_parts, exact_packet_hex,
        server_opcode_name, server_protocol_name,
    };
    use emulebb_kad_proto::Ed2kHash;

    #[test]
    fn server_status_applied_event_is_causally_correlated() {
        let (keys, body) = ed2k_server_status_applied_parts(
            "127.0.0.1:4661",
            7,
            "background",
            "connected",
            true,
            3,
            2,
        );

        assert_eq!(keys["peer"], "127.0.0.1:4661");
        assert_eq!(keys["traceId"], 7);
        assert_eq!(keys["opcode"], OP_SERVERSTATUS);
        assert_eq!(body["outcome"], "applied");
        assert_eq!(body["transportMode"], "obfuscated");
        assert_eq!(body["users"], 3);
        assert_eq!(body["files"], 2);
        assert_eq!(body["traceKey"], "server:background:7:127.0.0.1:4661");
    }

    #[test]
    fn server_ident_applied_event_preserves_decoded_metadata() {
        let (keys, body) = ed2k_server_ident_applied_parts(
            "127.0.0.1:4661",
            8,
            "background",
            "connected",
            false,
            Some("deterministic-server"),
            Some("deterministic-description"),
        );

        assert_eq!(keys["opcode"], OP_SERVERIDENT);
        assert_eq!(body["outcome"], "applied");
        assert_eq!(body["transportMode"], "plaintext");
        assert_eq!(body["name"], "deterministic-server");
        assert_eq!(body["description"], "deterministic-description");
        assert_eq!(body["traceId"], 8);
    }

    #[test]
    fn server_source_result_applied_event_preserves_causal_registry_counts() {
        let file_hash = Ed2kHash::from_bytes([0x22; 16]);
        let (keys, body) = ed2k_server_source_result_applied_parts(
            "127.0.0.1:4661",
            9,
            "plaintext",
            OP_FOUNDSOURCES,
            file_hash,
            1,
            0,
            1,
        );

        assert_eq!(keys["peer"], "127.0.0.1:4661");
        assert_eq!(keys["fileHash"], file_hash.to_string());
        assert_eq!(keys["traceId"], 9);
        assert_eq!(keys["opcode"], OP_FOUNDSOURCES);
        assert_eq!(body["stateId"], "server.source.result_applied");
        assert_eq!(body["milestone"], "result_applied");
        assert_eq!(body["wireSourceCount"], 1);
        assert_eq!(body["sourceCountBefore"], 0);
        assert_eq!(body["sourceCountAfter"], 1);
        assert_eq!(body["outcome"], "applied");
    }

    #[test]
    fn server_transport_fallback_is_structured_for_cross_client_evidence() {
        let (family, event, severity, keys, body) = ed2k_server_transport_fallback_parts(
            "198.51.100.4:4661",
            17,
            "obfuscated",
            "plaintext",
            "server closed crypt negotiation",
        );

        assert_eq!(family, "ed2k_tcp");
        assert_eq!(event, "transport_fallback");
        assert_eq!(severity, "warning");
        assert_eq!(keys["peer"], "198.51.100.4:4661");
        assert_eq!(keys["flow"], "server");
        assert_eq!(keys["traceId"], 17);
        assert_eq!(body["phase"], "connection");
        assert_eq!(body["outcome"], "retrying");
        assert_eq!(body["fromTransportMode"], "obfuscated");
        assert_eq!(body["toTransportMode"], "plaintext");
        assert_eq!(body["error"], "server closed crypt negotiation");
        assert_eq!(body["traceId"], 17);
    }

    #[test]
    fn server_tcp_send_outcome_preserves_attempt_correlation_and_terminal_state() {
        let context = Ed2kServerSendContext {
            family: "ed2k_tcp",
            attempt_id: 42,
            trace_id: 7,
            trace_key: "server:background:7:198.51.100.1:4661".to_string(),
            state_id: "server.background.connected".to_string(),
            state_label: "connected",
            role: "background",
            phase: "connected",
            remote_addr: "198.51.100.1:4661".to_string(),
            transport_mode: "plaintext",
            obfuscated: Some(false),
            protocol_marker: Some(OP_EDONKEYPROT_MARKER),
            opcode: Some(OP_CALLBACKREQUEST),
            attempted_len: 73,
        };

        let (family, severity, keys, body) =
            ed2k_server_send_outcome_parts(&context, Ed2kServerSendOutcome::Succeeded, true, None);
        assert_eq!(family, "ed2k_tcp");
        assert_eq!(severity, "info");
        assert_eq!(keys["sendAttemptId"], 42);
        assert_eq!(body["outcome"], "send_succeeded");
        assert_eq!(body["deliveryKnown"], true);
        assert_eq!(body["attemptedLen"], 73);
        assert_eq!(body["traceKey"], context.trace_key);
        assert_eq!(body["stateId"], context.state_id);

        let (_, severity, _, body) = ed2k_server_send_outcome_parts(
            &context,
            Ed2kServerSendOutcome::Cancelled,
            false,
            Some("cancelled"),
        );
        assert_eq!(severity, "warning");
        assert_eq!(body["outcome"], "send_cancelled");
        assert_eq!(body["deliveryKnown"], false);
        assert_eq!(body["note"], "cancelled");
    }

    #[test]
    fn server_udp_send_outcome_uses_distinct_family_and_server_trace() {
        let context = Ed2kServerSendContext {
            family: "ed2k_server_udp",
            attempt_id: 43,
            trace_id: 0,
            trace_key: "server:udp:198.51.100.2:4661".to_string(),
            state_id: "server.udp.send".to_string(),
            state_label: "udp",
            role: "udp",
            phase: "udp",
            remote_addr: "198.51.100.2:4665".to_string(),
            transport_mode: "obfuscated",
            obfuscated: Some(true),
            protocol_marker: Some(OP_EDONKEYPROT_MARKER),
            opcode: Some(OP_GLOBSERVSTATREQ),
            attempted_len: 12,
        };

        let (family, severity, keys, body) = ed2k_server_send_outcome_parts(
            &context,
            Ed2kServerSendOutcome::Failed,
            true,
            Some("send failed"),
        );
        assert_eq!(family, "ed2k_server_udp");
        assert_eq!(severity, "warning");
        assert_eq!(keys["peer"], "198.51.100.2:4665");
        assert!(keys.get("traceId").is_none());
        assert_eq!(keys["sendAttemptId"], 43);
        assert_eq!(body["outcome"], "send_failed");
        assert_eq!(body["traceKey"], "server:udp:198.51.100.2:4661");
        assert_eq!(body["stateId"], "server.udp.send");
        assert_eq!(body["transportMode"], "obfuscated");
        assert_eq!(body["note"], "send failed");
    }

    #[test]
    fn server_common_event_preserves_payloads_larger_than_the_former_cap() {
        let payload = vec![0xCD; 4 * 1024 + 1];
        let raw = vec![0xAB; payload.len() + 6];
        let clear_frame = vec![0xBC; payload.len() + 6];
        let record = Ed2kServerDumpRecord {
            trace_id: 7,
            trace_key: "server:background:7:198.51.100.1:4661".to_string(),
            state_id: "server.background.connected".to_string(),
            state_label: "connected",
            role: "background",
            flow: "server",
            phase: "connected",
            direction: "send",
            outcome: "attempted",
            send_attempt_id: Some(17),
            remote_addr: "198.51.100.1:4661".to_string(),
            transport_mode: "plaintext",
            obfuscated: Some(false),
            protocol: Some("ed2k"),
            protocol_marker: Some(OP_EDONKEYPROT_MARKER),
            opcode: Some(OP_GLOBSEARCHRES),
            opcode_name: Some(server_opcode_name(OP_GLOBSEARCHRES)),
            raw_len: Some(raw.len()),
            raw_hex: Some(exact_packet_hex(&raw)),
            clear_frame_len: Some(clear_frame.len()),
            clear_frame_hex: Some(exact_packet_hex(&clear_frame)),
            payload_len: Some(payload.len()),
            payload_hex: Some(exact_packet_hex(&payload)),
            payload_hex_truncated: Some(false),
            note: None,
        };

        let (family, event, severity, keys, body) = ed2k_server_diag_event_parts(&record);
        assert_eq!(family, "ed2k_tcp");
        assert_eq!(event, "packet");
        assert_eq!(severity, "info");
        assert_eq!(keys["peer"], "198.51.100.1:4661");
        assert_eq!(keys["sendAttemptId"], 17);
        assert_eq!(body["outcome"], "attempted");
        assert_eq!(body["sendAttemptId"], 17);
        assert_eq!(body["traceKey"], "server:background:7:198.51.100.1:4661");
        assert_eq!(body["stateId"], "server.background.connected");
        assert_eq!(body["stateLabel"], "connected");
        assert_eq!(body["obfuscated"], false);
        assert_eq!(body["rawLen"], raw.len());
        assert_eq!(body["rawHex"].as_str().unwrap().len(), raw.len() * 2);
        assert_eq!(body["clearFrameLen"], clear_frame.len());
        assert_eq!(
            body["clearFrameHex"].as_str().unwrap().len(),
            clear_frame.len() * 2
        );
        assert_eq!(body["payloadLen"], payload.len());
        assert_eq!(
            body["payloadHex"].as_str().unwrap().len(),
            payload.len() * 2
        );
        assert_eq!(body["payloadHexTruncated"], false);
    }

    #[test]
    fn server_udp_reply_packet_preserves_positive_correlation() {
        let record = Ed2kServerDumpRecord {
            trace_id: 41,
            trace_key: "server:udp:41:198.51.100.2:4665".to_string(),
            state_id: "server.udp.recv".to_string(),
            state_label: "udp",
            role: "udp",
            flow: "server",
            phase: "udp",
            direction: "recv",
            outcome: "accepted",
            send_attempt_id: None,
            remote_addr: "198.51.100.2:4665".to_string(),
            transport_mode: "obfuscated",
            obfuscated: Some(true),
            protocol: Some("ed2k"),
            protocol_marker: Some(OP_EDONKEYPROT_MARKER),
            opcode: Some(OP_GLOBSERVSTATRES),
            opcode_name: Some(server_opcode_name(OP_GLOBSERVSTATRES)),
            raw_len: Some(4),
            raw_hex: Some("1234abcd".to_string()),
            clear_frame_len: Some(4),
            clear_frame_hex: Some("e398abcd".to_string()),
            payload_len: Some(2),
            payload_hex: Some("abcd".to_string()),
            payload_hex_truncated: Some(false),
            note: None,
        };

        let (family, event, severity, keys, body) = ed2k_server_diag_event_parts(&record);
        assert_eq!(family, "ed2k_server_udp");
        assert_eq!(event, "packet");
        assert_eq!(severity, "info");
        assert_eq!(keys["peer"], "198.51.100.2:4665");
        assert_eq!(keys["opcode"], OP_GLOBSERVSTATRES);
        assert_eq!(body["obfuscated"], true);
        assert_eq!(body["traceId"], 41);
        assert_eq!(body["traceKey"], "server:udp:41:198.51.100.2:4665");
        assert_eq!(body["opcodeName"], "OP_GLOBSERVSTATRES");
    }

    #[test]
    fn server_udp_drop_keeps_raw_bytes_without_faking_decoded_stages() {
        let record = Ed2kServerDumpRecord {
            trace_id: 0,
            trace_key: "server:udp:198.51.100.2:4665".to_string(),
            state_id: "server.udp.recv".to_string(),
            state_label: "udp",
            role: "udp",
            flow: "server",
            phase: "udp",
            direction: "recv",
            outcome: "dropped",
            send_attempt_id: None,
            remote_addr: "198.51.100.2:4665".to_string(),
            transport_mode: "obfuscated",
            obfuscated: Some(true),
            protocol: None,
            protocol_marker: None,
            opcode: None,
            opcode_name: None,
            raw_len: Some(4),
            raw_hex: Some("1234abcd".to_string()),
            clear_frame_len: None,
            clear_frame_hex: None,
            payload_len: None,
            payload_hex: None,
            payload_hex_truncated: None,
            note: Some("decode failed".to_string()),
        };

        let (family, event, severity, _, body) = ed2k_server_diag_event_parts(&record);
        assert_eq!(family, "ed2k_server_udp");
        assert_eq!(event, "packet");
        assert_eq!(severity, "warning");
        assert_eq!(body["outcome"], "dropped");
        assert_eq!(body["rawHex"], "1234abcd");
        assert!(body.get("clearFrameHex").is_none());
        assert!(body.get("payloadHex").is_none());
    }

    #[test]
    fn server_meta_record_is_a_state_event_with_correlation() {
        let record = Ed2kServerDumpRecord {
            trace_id: 11,
            trace_key: "server:background:11:198.51.100.3:4661".to_string(),
            state_id: "server.background.connected".to_string(),
            state_label: "connected",
            role: "background",
            flow: "server",
            phase: "connected",
            direction: "meta",
            outcome: "meta",
            send_attempt_id: None,
            remote_addr: "198.51.100.3:4661".to_string(),
            transport_mode: "plaintext",
            obfuscated: Some(false),
            protocol: None,
            protocol_marker: None,
            opcode: None,
            opcode_name: None,
            raw_len: None,
            raw_hex: None,
            clear_frame_len: None,
            clear_frame_hex: None,
            payload_len: None,
            payload_hex: None,
            payload_hex_truncated: None,
            note: Some("connected".to_string()),
        };

        let (family, event, severity, _, body) = ed2k_server_diag_event_parts(&record);
        assert_eq!(family, "ed2k_tcp");
        assert_eq!(event, "state");
        assert_eq!(severity, "info");
        assert_eq!(body["traceId"], 11);
        assert_eq!(body["traceKey"], "server:background:11:198.51.100.3:4661");
        assert_eq!(body["stateId"], "server.background.connected");
        assert_eq!(body["stateLabel"], "connected");
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
        assert_eq!(server_opcode_name(OP_GLOBCALLBACKREQ), "OP_GLOBCALLBACKREQ");
        assert_eq!(server_opcode_name(OP_GLOBSERVSTATRES), "OP_GLOBSERVSTATRES");
        assert_eq!(server_opcode_name(OP_SERVER_LIST_REQ), "OP_SERVER_LIST_REQ");
        assert_eq!(server_opcode_name(OP_SERVER_LIST_RES), "OP_SERVER_LIST_RES");
        assert_eq!(server_opcode_name(OP_SERVER_DESC_RES), "OP_SERVER_DESC_RES");
        assert_eq!(
            server_opcode_name(OP_SERVER_LIST_REQ2),
            "OP_SERVER_LIST_REQ2"
        );
    }

    #[test]
    fn server_protocol_name_reports_packed_framing() {
        assert_eq!(server_protocol_name(OP_EDONKEYPROT_MARKER), "ed2k");
        assert_eq!(server_protocol_name(OP_PACKEDPROT), "packed");
        assert_eq!(server_protocol_name(0x7F), "unknown");
    }
}
