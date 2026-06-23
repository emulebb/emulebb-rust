// The packet dump is gated by the `packet-diagnostics` Cargo feature (the
// equivalent of eMuleBB's EMULEBB_ENABLE_PACKET_DIAGNOSTICS #ifdef). When the
// feature is off the public dump wrappers below become no-ops and the record
// machinery is dead-code-eliminated, so release builds carry zero dump cost.
#![cfg_attr(not(feature = "packet-diagnostics"), allow(dead_code, unused_imports))]

use std::{
    borrow::Cow,
    fs,
    io::Write,
    net::SocketAddr,
    sync::{
        Mutex as StdMutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use chrono::SecondsFormat;
use serde::Serialize;

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
    OP_OUTOFPARTREQS, OP_PACKEDPROT, OP_PORTTEST, OP_PREVIEWANSWER, OP_PUBLICIP_ANSWER,
    OP_PUBLICIP_REQ, OP_PUBLICKEY, OP_QUEUERANK, OP_QUEUERANKING, OP_REASKCALLBACKTCP,
    OP_REQFILENAMEANSWER, OP_REQUESTFILENAME, OP_REQUESTPARTS, OP_REQUESTPARTS_I64,
    OP_REQUESTPREVIEW, OP_REQUESTSOURCES, OP_REQUESTSOURCES2, OP_SECIDENTSTATE, OP_SENDINGPART,
    OP_SENDINGPART_I64, OP_SETREQFILEID, OP_SIGNATURE, OP_STARTUPLOADREQ, TCP_PACKET_HEADER_LEN,
    encode_packet,
};

const ED2K_TCP_DUMP_FILE_PREFIX: &str = "emulebb-rust-ed2k-tcp-dump-";

#[derive(Debug, Serialize)]
pub(super) struct Ed2kTcpDumpRecord<'a> {
    schema: &'static str,
    source: &'static str,
    ts_utc: String,
    event_seq: u64,
    trace_key: String,
    state_id: String,
    state_label: &'a str,
    pub(super) flow: &'static str,
    pub(super) phase: &'a str,
    pub(super) direction: &'a str,
    pub(super) remote_addr: String,
    pub(super) transport_mode: &'a str,
    pub(super) protocol: Option<&'static str>,
    pub(super) protocol_marker: Option<u8>,
    pub(super) opcode: Option<u8>,
    pub(super) opcode_name: Option<&'static str>,
    pub(super) raw_len: Option<usize>,
    pub(super) raw_hex: Option<String>,
    pub(super) payload_len: Option<usize>,
    pub(super) payload_hex: Option<String>,
    pub(super) payload_hex_truncated: Option<bool>,
    pub(super) note: Option<String>,
}

/// Cap on hex-encoded bytes emitted per packet, matching the eMuleBB diagnostic
/// build (`kMaxPacketDiagnosticsPayloadHexBytes` = 4 KiB) so the two clients'
/// packet dumps stay byte-for-byte comparable.
const MAX_PACKET_DUMP_HEX_BYTES: usize = 4 * 1024;

/// Hex-encode up to `MAX_PACKET_DUMP_HEX_BYTES` bytes, returning the hex string
/// and whether the source was truncated (matching eMuleBB's `payload_hex` +
/// `payload_hex_truncated`).
fn capped_packet_hex(bytes: &[u8]) -> (String, bool) {
    if bytes.len() > MAX_PACKET_DUMP_HEX_BYTES {
        (hex::encode(&bytes[..MAX_PACKET_DUMP_HEX_BYTES]), true)
    } else {
        (hex::encode(bytes), false)
    }
}

fn ed2k_tcp_dump_event_seq() -> u64 {
    static NEXT_EVENT_SEQ: AtomicU64 = AtomicU64::new(1);
    NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed)
}

fn ed2k_tcp_trace_key(flow: &'static str, remote_addr: SocketAddr) -> String {
    format!("{flow}:{remote_addr}")
}

fn ed2k_tcp_state_id(flow: &'static str, phase: &str) -> String {
    format!("{flow}.{phase}")
}

fn ed2k_tcp_dump_file() -> &'static StdMutex<Option<fs::File>> {
    static DUMP_FILE: OnceLock<StdMutex<Option<fs::File>>> = OnceLock::new();
    DUMP_FILE.get_or_init(|| {
        let file = std::env::var("EMULEBB_RUST_LOG_DIR")
            .ok()
            .map(std::path::PathBuf::from)
            .and_then(|dir| {
                fs::create_dir_all(&dir).ok()?;
                let path = dir.join(format!(
                    "{}{}.jsonl",
                    ED2K_TCP_DUMP_FILE_PREFIX,
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

/// Whether to SKIP dumping this packet because it is a high-volume bulk file-data
/// packet (OP_SENDINGPART / OP_COMPRESSEDPART, 32- and 64-bit) past its sample.
///
/// At download/upload throughput these data packets arrive thousands per second;
/// each dumped line ALSO emits a converged `diag_event`, so an unsampled dump
/// reaches tens of GB in a long soak. The control-plane packets (HELLO, SUI,
/// REQUESTPARTS, MULTIPACKET, ...) carry the parity signal and are never skipped;
/// for the bulk data opcodes we keep the first `HEAD` of each (coverage + sample
/// structure) then 1-in-`EVERY` for long-soak liveness. Returns false for any
/// non-bulk packet (never skipped).
#[cfg(feature = "packet-diagnostics")]
fn should_skip_bulk_packet(protocol: u8, opcode: u8) -> bool {
    static SENDINGPART: AtomicU64 = AtomicU64::new(0);
    static COMPRESSEDPART: AtomicU64 = AtomicU64::new(0);
    static SENDINGPART_I64: AtomicU64 = AtomicU64::new(0);
    static COMPRESSEDPART_I64: AtomicU64 = AtomicU64::new(0);
    const HEAD: u64 = 64;
    const EVERY: u64 = 8192;
    let counter = match (protocol, opcode) {
        (OP_EDONKEYPROT, OP_SENDINGPART) => &SENDINGPART,
        (OP_EMULEPROT, OP_COMPRESSEDPART) => &COMPRESSEDPART,
        (OP_EMULEPROT, OP_SENDINGPART_I64) => &SENDINGPART_I64,
        (OP_EMULEPROT, OP_COMPRESSEDPART_I64) => &COMPRESSEDPART_I64,
        _ => return false,
    };
    let n = counter.fetch_add(1, Ordering::Relaxed);
    !(n < HEAD || n % EVERY == 0)
}

fn dump_ed2k_tcp_record(record: &Ed2kTcpDumpRecord<'_>) {
    if let Ok(line) = serde_json::to_string(record)
        && let Ok(mut guard) = ed2k_tcp_dump_file().lock()
        && let Some(file) = guard.as_mut()
    {
        let _ = writeln!(file, "{line}");
    }

    // uniform-diagnostics-v2 (lane D2): also emit the converged `ed2k_tcp`
    // `diag_event_v1` record from the SAME data (schema §3.1). The legacy
    // `ed2k_packet_v1` line above is kept during migration. Both writes are
    // already behind the `packet-diagnostics` feature (the only callers of this
    // fn are the feature-gated send/recv/meta builders). The mapping itself lives
    // in the sibling `diag_event` module to keep this file within budget.
    super::diag_event::emit_ed2k_tcp_diag_event(record);
}

#[cfg(feature = "packet-diagnostics")]
fn dump_ed2k_tcp_meta(
    flow: &'static str,
    remote_addr: SocketAddr,
    transport_mode: Option<Ed2kTransportMode>,
    phase: &str,
    note: impl Into<String>,
) {
    let record = Ed2kTcpDumpRecord {
        schema: "ed2k_packet_v1",
        source: "emulebb-rust",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: ed2k_tcp_dump_event_seq(),
        trace_key: ed2k_tcp_trace_key(flow, remote_addr),
        state_id: ed2k_tcp_state_id(flow, phase),
        state_label: phase,
        flow,
        phase,
        direction: "meta",
        remote_addr: remote_addr.to_string(),
        transport_mode: transport_mode.map_or("unknown", Ed2kTransportMode::as_str),
        protocol: None,
        protocol_marker: None,
        opcode: None,
        opcode_name: None,
        raw_len: None,
        raw_hex: None,
        payload_len: None,
        payload_hex: None,
        payload_hex_truncated: None,
        note: Some(note.into()),
    };
    dump_ed2k_tcp_record(&record);
}

#[cfg(feature = "packet-diagnostics")]
fn dump_ed2k_tcp_send(
    flow: &'static str,
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    bytes: &[u8],
) {
    let protocol = bytes.first().copied();
    let opcode = bytes.get(5).copied();
    if let (Some(p), Some(o)) = (protocol, opcode)
        && should_skip_bulk_packet(p, o)
    {
        return;
    }
    let payload = if bytes.len() > TCP_PACKET_HEADER_LEN {
        Some(&bytes[TCP_PACKET_HEADER_LEN..])
    } else {
        None
    };
    let canonical_phase = canonical_ed2k_send_phase(flow, phase, protocol, opcode);
    let (raw_hex, _) = capped_packet_hex(bytes);
    let (payload_hex, payload_hex_truncated) = match payload {
        Some(payload) => {
            let (hex, truncated) = capped_packet_hex(payload);
            (Some(hex), Some(truncated))
        }
        None => (None, None),
    };
    let record = Ed2kTcpDumpRecord {
        schema: "ed2k_packet_v1",
        source: "emulebb-rust",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: ed2k_tcp_dump_event_seq(),
        trace_key: ed2k_tcp_trace_key(flow, remote_addr),
        state_id: ed2k_tcp_state_id(flow, canonical_phase.as_ref()),
        state_label: canonical_phase.as_ref(),
        flow,
        phase: canonical_phase.as_ref(),
        direction: "send",
        remote_addr: remote_addr.to_string(),
        transport_mode: transport_mode.as_str(),
        protocol: protocol.map(ed2k_protocol_name),
        protocol_marker: protocol,
        opcode,
        opcode_name: protocol.zip(opcode).map(|(p, o)| ed2k_opcode_name(p, o)),
        raw_len: Some(bytes.len()),
        raw_hex: Some(raw_hex),
        payload_len: payload.map(<[u8]>::len),
        payload_hex,
        payload_hex_truncated,
        note: None,
    };
    dump_ed2k_tcp_record(&record);
}

#[cfg(feature = "packet-diagnostics")]
fn dump_ed2k_tcp_recv(
    flow: &'static str,
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    packet: &EmuleTcpPacket,
) {
    if should_skip_bulk_packet(packet.protocol, packet.opcode) {
        return;
    }
    let canonical_phase = canonical_ed2k_recv_phase(flow, phase, packet.protocol, packet.opcode);
    let (raw_hex, _) = capped_packet_hex(&encode_packet(
        packet.protocol,
        packet.opcode,
        &packet.payload,
    ));
    let (payload_hex, payload_hex_truncated) = capped_packet_hex(&packet.payload);
    let record = Ed2kTcpDumpRecord {
        schema: "ed2k_packet_v1",
        source: "emulebb-rust",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: ed2k_tcp_dump_event_seq(),
        trace_key: ed2k_tcp_trace_key(flow, remote_addr),
        state_id: ed2k_tcp_state_id(flow, canonical_phase.as_ref()),
        state_label: canonical_phase.as_ref(),
        flow,
        phase: canonical_phase.as_ref(),
        direction: "recv",
        remote_addr: remote_addr.to_string(),
        transport_mode: transport_mode.as_str(),
        protocol: Some(ed2k_protocol_name(packet.protocol)),
        protocol_marker: Some(packet.protocol),
        opcode: Some(packet.opcode),
        opcode_name: Some(ed2k_opcode_name(packet.protocol, packet.opcode)),
        raw_len: Some(TCP_PACKET_HEADER_LEN + packet.payload.len()),
        raw_hex: Some(raw_hex),
        payload_len: Some(packet.payload.len()),
        payload_hex: Some(payload_hex),
        payload_hex_truncated: Some(payload_hex_truncated),
        note: None,
    };
    dump_ed2k_tcp_record(&record);
}

// No-op variants compiled when the `packet-diagnostics` feature is off, so the
// public wrappers (called from the hot eD2k paths) cost nothing in release builds.
#[cfg(not(feature = "packet-diagnostics"))]
fn dump_ed2k_tcp_meta(
    _flow: &'static str,
    _remote_addr: SocketAddr,
    _transport_mode: Option<Ed2kTransportMode>,
    _phase: &str,
    _note: impl Into<String>,
) {
}

#[cfg(not(feature = "packet-diagnostics"))]
fn dump_ed2k_tcp_send(
    _flow: &'static str,
    _remote_addr: SocketAddr,
    _transport_mode: Ed2kTransportMode,
    _phase: &str,
    _bytes: &[u8],
) {
}

#[cfg(not(feature = "packet-diagnostics"))]
fn dump_ed2k_tcp_recv(
    _flow: &'static str,
    _remote_addr: SocketAddr,
    _transport_mode: Ed2kTransportMode,
    _phase: &str,
    _packet: &EmuleTcpPacket,
) {
}

pub(super) fn dump_ed2k_tcp_helper_meta(
    remote_addr: SocketAddr,
    transport_mode: Option<Ed2kTransportMode>,
    phase: &str,
    note: impl Into<String>,
) {
    dump_ed2k_tcp_meta(
        "udp_firewall_check",
        remote_addr,
        transport_mode,
        phase,
        note,
    );
}

pub(super) fn dump_ed2k_tcp_helper_send(
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    bytes: &[u8],
) {
    dump_ed2k_tcp_send(
        "udp_firewall_check",
        remote_addr,
        transport_mode,
        phase,
        bytes,
    );
}

pub(super) fn dump_ed2k_tcp_helper_recv(
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    packet: &EmuleTcpPacket,
) {
    dump_ed2k_tcp_recv(
        "udp_firewall_check",
        remote_addr,
        transport_mode,
        phase,
        packet,
    );
}

pub(super) fn dump_ed2k_tcp_listener_meta(
    remote_addr: SocketAddr,
    transport_mode: Option<Ed2kTransportMode>,
    phase: &str,
    note: impl Into<String>,
) {
    dump_ed2k_tcp_meta("listener", remote_addr, transport_mode, phase, note);
}

pub(super) fn dump_ed2k_tcp_listener_send(
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    bytes: &[u8],
) {
    dump_ed2k_tcp_send("listener", remote_addr, transport_mode, phase, bytes);
}

pub(super) fn dump_ed2k_tcp_listener_recv(
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    packet: &EmuleTcpPacket,
) {
    dump_ed2k_tcp_recv("listener", remote_addr, transport_mode, phase, packet);
}

pub(crate) fn dump_ed2k_tcp_download_meta(
    remote_addr: SocketAddr,
    transport_mode: Option<Ed2kTransportMode>,
    phase: &str,
    note: impl Into<String>,
) {
    dump_ed2k_tcp_meta("native_download", remote_addr, transport_mode, phase, note);
}

pub(super) fn dump_ed2k_tcp_download_send(
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    bytes: &[u8],
) {
    dump_ed2k_tcp_send("native_download", remote_addr, transport_mode, phase, bytes);
}

pub(super) fn dump_ed2k_tcp_download_recv(
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    packet: &EmuleTcpPacket,
) {
    dump_ed2k_tcp_recv(
        "native_download",
        remote_addr,
        transport_mode,
        phase,
        packet,
    );
}

#[cfg(test)]
mod tests {
    use super::{ED2K_TCP_DUMP_FILE_PREFIX, OP_EMULEPROT, OP_SIGNATURE, canonical_ed2k_send_phase};

    #[test]
    fn tcp_dump_prefix_uses_emulebb_rust_name() {
        assert_eq!(ED2K_TCP_DUMP_FILE_PREFIX, "emulebb-rust-ed2k-tcp-dump-");
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
}
