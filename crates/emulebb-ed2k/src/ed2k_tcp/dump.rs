// Exact peer diagnostics are gated by the `packet-diagnostics` Cargo feature.
// When the feature is off the public wrappers below become no-ops and the
// record machinery is dead-code-eliminated, so release builds carry zero cost.
#![cfg_attr(
    not(feature = "packet-diagnostics"),
    expect(
        dead_code,
        unused_imports,
        reason = "TCP diagnostic machinery is inert without its feature"
    )
)]

use std::{borrow::Cow, net::SocketAddr};

use super::{
    Ed2kTransportMode, EmuleTcpPacket, OP_ACCEPTUPLOADREQ, OP_AICHANSWER, OP_AICHFILEHASHANS,
    OP_AICHFILEHASHREQ, OP_AICHREQUEST, OP_ANSWERSOURCES, OP_ANSWERSOURCES2, OP_ASKSHAREDDENIEDANS,
    OP_ASKSHAREDDIRS, OP_ASKSHAREDDIRSANS, OP_ASKSHAREDFILES, OP_ASKSHAREDFILESANSWER,
    OP_ASKSHAREDFILESDIR, OP_ASKSHAREDFILESDIRANS, OP_BUDDYPING, OP_BUDDYPONG, OP_CALLBACK,
    OP_CANCELTRANSFER, OP_CHANGE_CLIENT_ID, OP_CHANGE_SLOT, OP_CHATCAPTCHAREQ, OP_CHATCAPTCHARES,
    OP_COMPRESSEDPART, OP_COMPRESSEDPART_I64, OP_EDONKEYPROT, OP_EMULEINFO, OP_EMULEINFOANSWER,
    OP_EMULEPROT, OP_END_OF_DOWNLOAD, OP_FILEDESC, OP_FILEREQANSNOFIL, OP_FILESTATUS,
    OP_FWCHECKUDPREQ, OP_HASHSETANSWER, OP_HASHSETANSWER2, OP_HASHSETREQUEST, OP_HASHSETREQUEST2,
    OP_HELLO, OP_HELLOANSWER, OP_KAD_FWTCPCHECK_ACK, OP_MESSAGE, OP_MULTIPACKET,
    OP_MULTIPACKET_EXT, OP_MULTIPACKET_EXT2, OP_MULTIPACKETANSWER, OP_MULTIPACKETANSWER_EXT2,
    OP_OUTOFPARTREQS, OP_PACKEDPROT, OP_PEERCACHE_ACK, OP_PEERCACHE_ANSWER, OP_PEERCACHE_QUERY,
    OP_PORTTEST, OP_PREVIEWANSWER, OP_PUBLICIP_ANSWER, OP_PUBLICIP_REQ, OP_PUBLICKEY, OP_QUEUERANK,
    OP_QUEUERANKING, OP_REASKCALLBACKTCP, OP_REQFILENAMEANSWER, OP_REQUESTFILENAME,
    OP_REQUESTPARTS, OP_REQUESTPARTS_I64, OP_REQUESTPREVIEW, OP_REQUESTSOURCES, OP_REQUESTSOURCES2,
    OP_SECIDENTSTATE, OP_SENDINGPART, OP_SENDINGPART_I64, OP_SETREQFILEID, OP_SIGNATURE,
    OP_STARTUPLOADREQ, TCP_PACKET_HEADER_LEN,
};

#[derive(Debug)]
pub(super) struct Ed2kTcpDiagnosticRecord<'a> {
    pub(super) event: &'static str,
    pub(super) trace_key: String,
    pub(super) state_id: String,
    pub(super) state_label: &'a str,
    pub(super) flow: &'static str,
    pub(super) phase: &'a str,
    pub(super) direction: &'a str,
    pub(super) outcome: &'a str,
    pub(super) remote_addr: String,
    pub(super) peer_hash: Option<[u8; 16]>,
    pub(super) file_hash: Option<[u8; 16]>,
    pub(super) transport_mode: &'a str,
    pub(super) obfuscated: Option<bool>,
    pub(super) protocol: Option<&'static str>,
    pub(super) protocol_marker: Option<u8>,
    pub(super) opcode: Option<u8>,
    pub(super) opcode_name: Option<&'static str>,
    pub(super) raw_len: Option<usize>,
    pub(super) raw_hex: Option<String>,
    pub(super) clear_frame_len: Option<usize>,
    pub(super) clear_frame_hex: Option<String>,
    pub(super) attempted_len: Option<usize>,
    pub(super) written_len: Option<usize>,
    pub(super) payload_len: Option<usize>,
    pub(super) payload_hex: Option<String>,
    pub(super) payload_hex_truncated: Option<bool>,
    pub(super) note: Option<String>,
}

fn exact_packet_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn hash_at(payload: &[u8], offset: usize) -> Option<[u8; 16]> {
    payload.get(offset..offset + 16)?.try_into().ok()
}

fn ed2k_tcp_file_hash(protocol: u8, opcode: u8, payload: &[u8]) -> Option<[u8; 16]> {
    let offset = match (protocol, opcode) {
        (
            OP_EDONKEYPROT,
            OP_END_OF_DOWNLOAD | OP_FILEREQANSNOFIL | OP_FILESTATUS | OP_HASHSETANSWER
            | OP_HASHSETREQUEST | OP_REQFILENAMEANSWER | OP_REQUESTFILENAME | OP_REQUESTPARTS
            | OP_SENDINGPART | OP_SETREQFILEID | OP_STARTUPLOADREQ,
        )
        | (
            OP_EMULEPROT,
            OP_AICHANSWER
            | OP_AICHFILEHASHANS
            | OP_AICHFILEHASHREQ
            | OP_AICHREQUEST
            | OP_ANSWERSOURCES
            | OP_COMPRESSEDPART
            | OP_COMPRESSEDPART_I64
            | OP_MULTIPACKET
            | OP_MULTIPACKETANSWER
            | OP_MULTIPACKET_EXT
            | OP_REQUESTSOURCES
            | OP_SENDINGPART_I64,
        ) => 0,
        (OP_EMULEPROT, OP_ANSWERSOURCES2) => 1,
        (OP_EMULEPROT, OP_REQUESTSOURCES2) => 3,
        (
            OP_EMULEPROT,
            OP_HASHSETANSWER2
            | OP_HASHSETREQUEST2
            | OP_MULTIPACKETANSWER_EXT2
            | OP_MULTIPACKET_EXT2,
        ) => 1,
        _ => return None,
    };
    hash_at(payload, offset)
}

fn ed2k_tcp_trace_key(flow: &'static str, remote_addr: SocketAddr) -> String {
    format!("{flow}:{remote_addr}")
}

fn ed2k_tcp_state_id(flow: &'static str, phase: &str) -> String {
    format!("{flow}.{phase}")
}

fn ed2k_protocol_name(protocol: u8) -> &'static str {
    match protocol {
        OP_EDONKEYPROT => "ed2k",
        OP_EMULEPROT => "emule",
        OP_PACKEDPROT => "packed",
        _ => "unknown",
    }
}

fn ed2k_opcode_name(protocol: u8, opcode: u8) -> &'static str {
    match (protocol, opcode) {
        (OP_EDONKEYPROT, OP_HELLO) => "OP_HELLO",
        (OP_EDONKEYPROT, OP_HELLOANSWER) => "OP_HELLOANSWER",
        (OP_EMULEPROT, OP_COMPRESSEDPART) => "OP_COMPRESSEDPART",
        (OP_EDONKEYPROT, OP_SENDINGPART) => "OP_SENDINGPART",
        (OP_EDONKEYPROT, OP_REQUESTPARTS) => "OP_REQUESTPARTS",
        (OP_EDONKEYPROT, OP_FILEREQANSNOFIL) => "OP_FILEREQANSNOFIL",
        (OP_EDONKEYPROT, OP_ASKSHAREDFILES) => "OP_ASKSHAREDFILES",
        (OP_EDONKEYPROT, OP_ASKSHAREDFILESANSWER) => "OP_ASKSHAREDFILESANSWER",
        (OP_EDONKEYPROT, OP_SETREQFILEID) => "OP_SETREQFILEID",
        (OP_EDONKEYPROT, OP_FILESTATUS) => "OP_FILESTATUS",
        (OP_EDONKEYPROT, OP_HASHSETREQUEST) => "OP_HASHSETREQUEST",
        (OP_EDONKEYPROT, OP_HASHSETANSWER) => "OP_HASHSETANSWER",
        (OP_EDONKEYPROT, OP_STARTUPLOADREQ) => "OP_STARTUPLOADREQ",
        (OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ) => "OP_ACCEPTUPLOADREQ",
        (OP_EDONKEYPROT, OP_CANCELTRANSFER) => "OP_CANCELTRANSFER",
        (OP_EDONKEYPROT, OP_CHANGE_CLIENT_ID) => "OP_CHANGE_CLIENT_ID",
        (OP_EDONKEYPROT, OP_CHANGE_SLOT) => "OP_CHANGE_SLOT",
        (OP_EDONKEYPROT, OP_MESSAGE) => "OP_MESSAGE",
        (OP_EDONKEYPROT, OP_END_OF_DOWNLOAD) => "OP_END_OF_DOWNLOAD",
        (OP_EDONKEYPROT, OP_OUTOFPARTREQS) => "OP_OUTOFPARTREQS",
        (OP_EDONKEYPROT, OP_ASKSHAREDDIRS) => "OP_ASKSHAREDDIRS",
        (OP_EDONKEYPROT, OP_ASKSHAREDFILESDIR) => "OP_ASKSHAREDFILESDIR",
        (OP_EDONKEYPROT, OP_ASKSHAREDDIRSANS) => "OP_ASKSHAREDDIRSANS",
        (OP_EDONKEYPROT, OP_ASKSHAREDFILESDIRANS) => "OP_ASKSHAREDFILESDIRANS",
        (OP_EDONKEYPROT, OP_ASKSHAREDDENIEDANS) => "OP_ASKSHAREDDENIEDANS",
        (OP_EDONKEYPROT, OP_REQUESTFILENAME) => "OP_REQUESTFILENAME",
        (OP_EDONKEYPROT, OP_REQFILENAMEANSWER) => "OP_REQFILENAMEANSWER",
        (OP_EMULEPROT, OP_REQUESTSOURCES) => "OP_REQUESTSOURCES",
        (OP_EMULEPROT, OP_ANSWERSOURCES) => "OP_ANSWERSOURCES",
        (OP_EMULEPROT, OP_REQUESTSOURCES2) => "OP_REQUESTSOURCES2",
        (OP_EMULEPROT, OP_ANSWERSOURCES2) => "OP_ANSWERSOURCES2",
        (OP_EMULEPROT, OP_REQUESTPREVIEW) => "OP_REQUESTPREVIEW",
        (OP_EMULEPROT, OP_PREVIEWANSWER) => "OP_PREVIEWANSWER",
        (OP_EMULEPROT, OP_AICHREQUEST) => "OP_AICHREQUEST",
        (OP_EMULEPROT, OP_AICHANSWER) => "OP_AICHANSWER",
        (OP_EMULEPROT, OP_AICHFILEHASHANS) => "OP_AICHFILEHASHANS",
        (OP_EMULEPROT, OP_AICHFILEHASHREQ) => "OP_AICHFILEHASHREQ",
        (OP_EMULEPROT, OP_EMULEINFO) => "OP_EMULEINFO",
        (OP_EMULEPROT, OP_EMULEINFOANSWER) => "OP_EMULEINFOANSWER",
        (OP_EDONKEYPROT, OP_QUEUERANK) => "OP_QUEUERANK",
        (OP_EMULEPROT, OP_QUEUERANKING) => "OP_QUEUERANKING",
        (OP_EMULEPROT, OP_FILEDESC) => "OP_FILEDESC",
        (OP_EMULEPROT, OP_COMPRESSEDPART_I64) => "OP_COMPRESSEDPART_I64",
        (OP_EMULEPROT, OP_SENDINGPART_I64) => "OP_SENDINGPART_I64",
        (OP_EMULEPROT, OP_REQUESTPARTS_I64) => "OP_REQUESTPARTS_I64",
        (OP_EMULEPROT, OP_CHATCAPTCHAREQ) => "OP_CHATCAPTCHAREQ",
        (OP_EMULEPROT, OP_CHATCAPTCHARES) => "OP_CHATCAPTCHARES",
        (OP_EMULEPROT, OP_HASHSETREQUEST2) => "OP_HASHSETREQUEST2",
        (OP_EMULEPROT, OP_HASHSETANSWER2) => "OP_HASHSETANSWER2",
        (OP_EMULEPROT, OP_MULTIPACKET) => "OP_MULTIPACKET",
        (OP_EMULEPROT, OP_MULTIPACKET_EXT) => "OP_MULTIPACKET_EXT",
        (OP_EMULEPROT, OP_MULTIPACKET_EXT2) => "OP_MULTIPACKET_EXT2",
        (OP_EMULEPROT, OP_MULTIPACKETANSWER) => "OP_MULTIPACKETANSWER",
        (OP_EMULEPROT, OP_MULTIPACKETANSWER_EXT2) => "OP_MULTIPACKETANSWER_EXT2",
        (OP_EMULEPROT, OP_PEERCACHE_QUERY) => "OP_PEERCACHE_QUERY",
        (OP_EMULEPROT, OP_PEERCACHE_ANSWER) => "OP_PEERCACHE_ANSWER",
        (OP_EMULEPROT, OP_PEERCACHE_ACK) => "OP_PEERCACHE_ACK",
        (OP_EMULEPROT, OP_PUBLICKEY) => "OP_PUBLICKEY",
        (OP_EMULEPROT, OP_SIGNATURE) => "OP_SIGNATURE",
        (OP_EMULEPROT, OP_SECIDENTSTATE) => "OP_SECIDENTSTATE",
        (OP_EMULEPROT, OP_PUBLICIP_REQ) => "OP_PUBLICIP_REQ",
        (OP_EMULEPROT, OP_PUBLICIP_ANSWER) => "OP_PUBLICIP_ANSWER",
        (OP_EMULEPROT, OP_CALLBACK) => "OP_CALLBACK",
        (OP_EMULEPROT, OP_REASKCALLBACKTCP) => "OP_REASKCALLBACKTCP",
        (OP_EMULEPROT, OP_PORTTEST) | (OP_EDONKEYPROT, OP_PORTTEST) => "OP_PORTTEST",
        (OP_EMULEPROT, OP_KAD_FWTCPCHECK_ACK) => "OP_KAD_FWTCPCHECK_ACK",
        (OP_EMULEPROT, OP_BUDDYPING) => "OP_BUDDYPING",
        (OP_EMULEPROT, OP_BUDDYPONG) => "OP_BUDDYPONG",
        (OP_EMULEPROT, OP_FWCHECKUDPREQ) => "OP_FWCHECKUDPREQ",
        _ => "UNKNOWN",
    }
}

fn oracle_ed2k_send_phase(flow: &'static str, protocol: u8, opcode: u8) -> Option<&'static str> {
    let phase = match (protocol, opcode) {
        (OP_EDONKEYPROT, OP_HELLO) => "hello_request",
        (OP_EDONKEYPROT, OP_HELLOANSWER) => "hello_answer",
        (OP_EDONKEYPROT, OP_REQFILENAMEANSWER) => "filename_answer",
        (OP_EDONKEYPROT, OP_FILESTATUS) => "file_status",
        (OP_EMULEPROT, OP_EMULEINFO) => "mule_info",
        (OP_EMULEPROT, OP_EMULEINFOANSWER) => "mule_info_answer",
        (OP_EMULEPROT, OP_PUBLICKEY) => "public_key",
        (OP_EMULEPROT, OP_SIGNATURE) => "signature",
        (OP_EMULEPROT, OP_SECIDENTSTATE) => "secure_ident_probe",
        (OP_EMULEPROT, OP_PUBLICIP_REQ) => "public_ip_request",
        (OP_EMULEPROT, OP_PUBLICIP_ANSWER) => "public_ip_answer",
        (OP_EMULEPROT, OP_PORTTEST) | (OP_EDONKEYPROT, OP_PORTTEST) => "port_test",
        (OP_EMULEPROT, OP_KAD_FWTCPCHECK_ACK) => "kad_firewall_tcp_ack",
        (OP_EMULEPROT, OP_BUDDYPING) | (OP_EMULEPROT, OP_BUDDYPONG) => "kad_buddy_ping_pong",
        (OP_EDONKEYPROT, OP_CHANGE_SLOT) => "change_slot",
        (OP_EDONKEYPROT, OP_MESSAGE) => "client_message",
        (OP_EDONKEYPROT, OP_ASKSHAREDFILES) => "ask_shared_files",
        (OP_EDONKEYPROT, OP_ASKSHAREDFILESANSWER) => "shared_files_answer",
        (OP_EDONKEYPROT, OP_ASKSHAREDDIRS) => "ask_shared_dirs",
        (OP_EDONKEYPROT, OP_ASKSHAREDFILESDIR) => "ask_shared_files_dir",
        (OP_EDONKEYPROT, OP_ASKSHAREDDIRSANS) => "shared_dirs_answer",
        (OP_EDONKEYPROT, OP_ASKSHAREDFILESDIRANS) => "shared_files_dir_answer",
        (OP_EDONKEYPROT, OP_ASKSHAREDDENIEDANS) => "shared_browse_denied",
        (OP_EMULEPROT, OP_REQUESTPREVIEW) => "preview_request",
        (OP_EMULEPROT, OP_PREVIEWANSWER) => "preview_answer",
        (OP_EMULEPROT, OP_CALLBACK) => "kad_callback",
        (OP_EMULEPROT, OP_REASKCALLBACKTCP) => "reask_callback_tcp",
        (OP_EMULEPROT, OP_CHATCAPTCHAREQ) => "chat_captcha_request",
        (OP_EMULEPROT, OP_CHATCAPTCHARES) => "chat_captcha_result",
        (OP_EMULEPROT, OP_AICHREQUEST) => "aich_recovery_request",
        (OP_EMULEPROT, OP_AICHANSWER) => "aich_recovery_answer",
        (OP_EMULEPROT, OP_FWCHECKUDPREQ) => "fwcheck_request",
        _ => match flow {
            // The oracle emits generic per-session labels for ordinary listener and
            // downloader traffic, and only uses dedicated phase names for a small
            // parity-critical subset.
            "listener" | "native_download" => "session",
            "udp_firewall_check" => "hello_exchange",
            _ => return None,
        },
    };
    Some(phase)
}

fn oracle_ed2k_recv_phase(flow: &'static str, protocol: u8, opcode: u8) -> Option<&'static str> {
    let phase = match (protocol, opcode) {
        (OP_EMULEPROT, OP_FWCHECKUDPREQ) => "fwcheck_request",
        _ => match flow {
            "listener" | "native_download" => "session",
            "udp_firewall_check" => "hello_exchange",
            _ => return None,
        },
    };
    Some(phase)
}

pub(super) fn canonical_ed2k_send_phase<'a>(
    flow: &'static str,
    fallback: &'a str,
    protocol: Option<u8>,
    opcode: Option<u8>,
) -> Cow<'a, str> {
    if let Some((protocol, opcode)) = protocol.zip(opcode)
        && let Some(phase) = oracle_ed2k_send_phase(flow, protocol, opcode)
    {
        return Cow::Borrowed(phase);
    }

    Cow::Borrowed(fallback)
}

pub(super) fn canonical_ed2k_recv_phase<'a>(
    flow: &'static str,
    fallback: &'a str,
    protocol: u8,
    opcode: u8,
) -> Cow<'a, str> {
    if let Some(phase) = oracle_ed2k_recv_phase(flow, protocol, opcode) {
        return Cow::Borrowed(phase);
    }

    Cow::Borrowed(fallback)
}

fn emit_ed2k_tcp_record(record: &Ed2kTcpDiagnosticRecord<'_>) {
    super::diag_event::emit_ed2k_tcp_diag_event(record);
}

#[cfg(feature = "packet-diagnostics")]
fn dump_ed2k_tcp_meta(
    flow: &'static str,
    remote_addr: SocketAddr,
    transport_mode: Option<Ed2kTransportMode>,
    phase: &str,
    note: impl FnOnce() -> String,
) {
    let record = Ed2kTcpDiagnosticRecord {
        event: "state",
        trace_key: ed2k_tcp_trace_key(flow, remote_addr),
        state_id: ed2k_tcp_state_id(flow, phase),
        state_label: phase,
        flow,
        phase,
        direction: "meta",
        outcome: "meta",
        remote_addr: remote_addr.to_string(),
        peer_hash: None,
        file_hash: None,
        transport_mode: transport_mode.map_or("unknown", Ed2kTransportMode::as_str),
        obfuscated: transport_mode.map(Ed2kTransportMode::is_obfuscated),
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
        note: Some(note()),
    };
    emit_ed2k_tcp_record(&record);
}

#[cfg(feature = "packet-diagnostics")]
#[expect(clippy::too_many_arguments, reason = "flat diagnostic packet boundary")]
pub(super) fn dump_ed2k_tcp_recv_capture(
    flow: &'static str,
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    peer_hash: Option<[u8; 16]>,
    packet: &EmuleTcpPacket,
    raw: &[u8],
    clear_frame: &[u8],
) {
    let canonical_phase = canonical_ed2k_recv_phase(flow, phase, packet.protocol, packet.opcode);
    let payload_hex = exact_packet_hex(&packet.payload);
    let record = Ed2kTcpDiagnosticRecord {
        event: "packet",
        trace_key: ed2k_tcp_trace_key(flow, remote_addr),
        state_id: ed2k_tcp_state_id(flow, canonical_phase.as_ref()),
        state_label: canonical_phase.as_ref(),
        flow,
        phase: canonical_phase.as_ref(),
        direction: "recv",
        outcome: "accepted",
        remote_addr: remote_addr.to_string(),
        peer_hash,
        file_hash: ed2k_tcp_file_hash(packet.protocol, packet.opcode, &packet.payload),
        transport_mode: transport_mode.as_str(),
        obfuscated: Some(transport_mode.is_obfuscated()),
        protocol: Some(ed2k_protocol_name(packet.protocol)),
        protocol_marker: Some(packet.protocol),
        opcode: Some(packet.opcode),
        opcode_name: Some(ed2k_opcode_name(packet.protocol, packet.opcode)),
        raw_len: Some(raw.len()),
        raw_hex: Some(exact_packet_hex(raw)),
        clear_frame_len: Some(clear_frame.len()),
        clear_frame_hex: Some(exact_packet_hex(clear_frame)),
        attempted_len: None,
        written_len: None,
        payload_len: Some(packet.payload.len()),
        payload_hex: Some(payload_hex),
        payload_hex_truncated: Some(false),
        note: None,
    };
    emit_ed2k_tcp_record(&record);
}

#[cfg(feature = "packet-diagnostics")]
pub(super) fn dump_ed2k_tcp_handshake_step(
    flow: &'static str,
    remote_addr: SocketAddr,
    phase: &'static str,
    direction: &'static str,
    outcome: &'static str,
    raw: &[u8],
    clear: &[u8],
) {
    let record = Ed2kTcpDiagnosticRecord {
        event: "obfuscation_handshake",
        trace_key: ed2k_tcp_trace_key(flow, remote_addr),
        state_id: ed2k_tcp_state_id(flow, phase),
        state_label: phase,
        flow,
        phase,
        direction,
        outcome,
        remote_addr: remote_addr.to_string(),
        peer_hash: None,
        file_hash: None,
        transport_mode: Ed2kTransportMode::Obfuscated.as_str(),
        obfuscated: Some(true),
        protocol: None,
        protocol_marker: None,
        opcode: None,
        opcode_name: None,
        raw_len: Some(raw.len()),
        raw_hex: Some(exact_packet_hex(raw)),
        clear_frame_len: Some(clear.len()),
        clear_frame_hex: Some(exact_packet_hex(clear)),
        attempted_len: (direction == "send").then_some(raw.len()),
        written_len: (direction == "send").then_some(raw.len()),
        payload_len: None,
        payload_hex: None,
        payload_hex_truncated: None,
        note: Some("eD2K TCP obfuscation handshake".to_string()),
    };
    emit_ed2k_tcp_record(&record);
}

#[cfg(feature = "packet-diagnostics")]
#[expect(clippy::too_many_arguments, reason = "flat diagnostic packet boundary")]
pub(super) fn dump_ed2k_tcp_recv_terminal(
    flow: &'static str,
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    peer_hash: Option<[u8; 16]>,
    raw: &[u8],
    clear_frame: &[u8],
    outcome: &'static str,
    detail: String,
) {
    let protocol = clear_frame.first().copied();
    let opcode = clear_frame.get(TCP_PACKET_HEADER_LEN - 1).copied();
    let canonical_phase = protocol.zip(opcode).map_or_else(
        || Cow::Borrowed(phase),
        |(protocol, opcode)| canonical_ed2k_recv_phase(flow, phase, protocol, opcode),
    );
    let record = Ed2kTcpDiagnosticRecord {
        event: "packet",
        trace_key: ed2k_tcp_trace_key(flow, remote_addr),
        state_id: ed2k_tcp_state_id(flow, canonical_phase.as_ref()),
        state_label: canonical_phase.as_ref(),
        flow,
        phase: canonical_phase.as_ref(),
        direction: "recv",
        outcome,
        remote_addr: remote_addr.to_string(),
        peer_hash,
        file_hash: protocol.zip(opcode).and_then(|(protocol, opcode)| {
            ed2k_tcp_file_hash(protocol, opcode, clear_frame.get(TCP_PACKET_HEADER_LEN..)?)
        }),
        transport_mode: transport_mode.as_str(),
        obfuscated: Some(transport_mode.is_obfuscated()),
        protocol: protocol.map(ed2k_protocol_name),
        protocol_marker: protocol,
        opcode,
        opcode_name: protocol
            .zip(opcode)
            .map(|(protocol, opcode)| ed2k_opcode_name(protocol, opcode)),
        raw_len: Some(raw.len()),
        raw_hex: Some(exact_packet_hex(raw)),
        clear_frame_len: (!clear_frame.is_empty()).then_some(clear_frame.len()),
        clear_frame_hex: (!clear_frame.is_empty()).then(|| exact_packet_hex(clear_frame)),
        attempted_len: None,
        written_len: None,
        payload_len: None,
        payload_hex: None,
        payload_hex_truncated: None,
        note: Some(detail),
    };
    emit_ed2k_tcp_record(&record);
}

#[cfg(feature = "packet-diagnostics")]
#[expect(clippy::too_many_arguments, reason = "flat diagnostic packet boundary")]
pub(super) fn dump_ed2k_tcp_send_capture(
    flow: &'static str,
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    peer_hash: Option<[u8; 16]>,
    clear_frame: &[u8],
    raw: &[u8],
    attempted_len: usize,
    outcome: &'static str,
    detail: Option<String>,
) {
    let protocol = clear_frame.first().copied();
    let opcode = clear_frame.get(TCP_PACKET_HEADER_LEN - 1).copied();
    let payload =
        (clear_frame.len() > TCP_PACKET_HEADER_LEN).then(|| &clear_frame[TCP_PACKET_HEADER_LEN..]);
    let canonical_phase = canonical_ed2k_send_phase(flow, phase, protocol, opcode);
    let record = Ed2kTcpDiagnosticRecord {
        event: "packet",
        trace_key: ed2k_tcp_trace_key(flow, remote_addr),
        state_id: ed2k_tcp_state_id(flow, canonical_phase.as_ref()),
        state_label: canonical_phase.as_ref(),
        flow,
        phase: canonical_phase.as_ref(),
        direction: "send",
        outcome,
        remote_addr: remote_addr.to_string(),
        peer_hash,
        file_hash: protocol
            .zip(opcode)
            .and_then(|(protocol, opcode)| ed2k_tcp_file_hash(protocol, opcode, payload?)),
        transport_mode: transport_mode.as_str(),
        obfuscated: Some(transport_mode.is_obfuscated()),
        protocol: protocol.map(ed2k_protocol_name),
        protocol_marker: protocol,
        opcode,
        opcode_name: protocol
            .zip(opcode)
            .map(|(protocol, opcode)| ed2k_opcode_name(protocol, opcode)),
        raw_len: Some(raw.len()),
        raw_hex: Some(exact_packet_hex(raw)),
        clear_frame_len: Some(clear_frame.len()),
        clear_frame_hex: Some(exact_packet_hex(clear_frame)),
        attempted_len: Some(attempted_len),
        written_len: Some(raw.len()),
        payload_len: payload.map(<[u8]>::len),
        payload_hex: payload.map(exact_packet_hex),
        payload_hex_truncated: payload.map(|_| false),
        note: detail,
    };
    emit_ed2k_tcp_record(&record);
}

// No-op variants compiled when the `packet-diagnostics` feature is off, so the
// public wrappers (called from the hot eD2k paths) cost nothing in release builds.
#[cfg(not(feature = "packet-diagnostics"))]
fn dump_ed2k_tcp_meta(
    _flow: &'static str,
    _remote_addr: SocketAddr,
    _transport_mode: Option<Ed2kTransportMode>,
    _phase: &str,
    _note: impl FnOnce() -> String,
) {
}

#[cfg(not(feature = "packet-diagnostics"))]
pub(super) fn dump_ed2k_tcp_handshake_step(
    _flow: &'static str,
    _remote_addr: SocketAddr,
    _phase: &'static str,
    _direction: &'static str,
    _outcome: &'static str,
    _raw: &[u8],
    _clear: &[u8],
) {
}

pub(super) fn dump_ed2k_tcp_helper_meta(
    remote_addr: SocketAddr,
    transport_mode: Option<Ed2kTransportMode>,
    phase: &str,
    note: impl FnOnce() -> String,
) {
    dump_ed2k_tcp_meta(
        "udp_firewall_check",
        remote_addr,
        transport_mode,
        phase,
        note,
    );
}

pub(super) fn dump_ed2k_tcp_listener_meta(
    remote_addr: SocketAddr,
    transport_mode: Option<Ed2kTransportMode>,
    phase: &str,
    note: impl FnOnce() -> String,
) {
    dump_ed2k_tcp_meta("listener", remote_addr, transport_mode, phase, note);
}

pub(crate) fn dump_ed2k_tcp_download_meta(
    remote_addr: SocketAddr,
    transport_mode: Option<Ed2kTransportMode>,
    phase: &str,
    note: impl FnOnce() -> String,
) {
    dump_ed2k_tcp_meta("native_download", remote_addr, transport_mode, phase, note);
}

#[cfg(test)]
mod tests {
    use super::{
        OP_EMULEPROT, OP_REQUESTSOURCES2, OP_SIGNATURE, canonical_ed2k_send_phase,
        ed2k_tcp_file_hash, exact_packet_hex,
    };

    #[test]
    fn packet_hex_preserves_payloads_larger_than_the_former_cap() {
        let payload = vec![0xAB; 4 * 1024 + 1];
        let encoded = exact_packet_hex(&payload);
        assert_eq!(encoded.len(), payload.len() * 2);
        assert!(encoded.ends_with("ab"));
    }

    #[test]
    fn secure_ident_signature_send_phase_matches_mfc_oracle() {
        assert_eq!(
            canonical_ed2k_send_phase(
                "native_download",
                "fallback",
                Some(OP_EMULEPROT),
                Some(OP_SIGNATURE)
            ),
            "signature"
        );
    }

    #[test]
    fn packet_file_hash_uses_opcode_specific_offsets() {
        let expected = [0xAB; 16];
        let mut payload = vec![4, 0, 0];
        payload.extend_from_slice(&expected);
        assert_eq!(
            ed2k_tcp_file_hash(OP_EMULEPROT, OP_REQUESTSOURCES2, &payload),
            Some(expected)
        );
        assert_eq!(
            ed2k_tcp_file_hash(OP_EMULEPROT, OP_SIGNATURE, &payload),
            None
        );
    }
}
