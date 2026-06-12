//! Oracle-shaped UDP JSONL dump for Kad parity work.

use chrono::Local;
use serde::Serialize;
use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use tracing::warn;

const EMULEBB_RUST_TMP_DIR_ENV: &str = "EMULEBB_RUST_TMP_DIR";
const EMULEBB_RUST_LOG_DIR_ENV: &str = "EMULEBB_RUST_LOG_DIR";
const EMULEBB_WORKSPACE_OUTPUT_ROOT_ENV: &str = "EMULEBB_WORKSPACE_OUTPUT_ROOT";
const DEFAULT_WORKSPACE_TMP_DIR_NAME: &str = "emulebb-rust";
const DUMP_FILE_PREFIX: &str = "emulebb-rust-kad-udp-dump-";
const DUMP_FILE_SUFFIX: &str = ".jsonl";

static UDP_DUMP_WRITER: OnceLock<Option<UdpDumpWriter>> = OnceLock::new();

/// Stable metadata emitted for a single Kad UDP packet dump line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KadUdpDumpSummary {
    /// Kad protocol header byte after decode.
    pub protocol: u8,
    /// Kad opcode, when available.
    pub opcode: Option<u8>,
    /// Stable Kad opcode label, when available.
    pub opcode_name: Option<&'static str>,
    /// Whether the raw on-wire packet used Kad obfuscation.
    pub raw_obfuscated: bool,
    /// Final transport mode bucket used on the wire.
    pub transport_mode: Option<&'static str>,
    /// Whether the sender explicitly requested obfuscation for this packet.
    pub requested_obfuscation: Option<bool>,
    /// Receiver verify key referenced by the packet, when known.
    pub receiver_verify_key: Option<u32>,
    /// Sender verify key carried by the packet, when known.
    pub sender_verify_key: Option<u32>,
    /// Whether the inbound packet proved our receiver verify key.
    pub receiver_verify_key_valid: Option<bool>,
    /// Matched or inferred paired request opcode for a response, when known.
    pub tracked_request_opcode: Option<&'static str>,
    /// Stable drop reason recorded at the receive boundary, when the packet was not accepted.
    pub drop_reason: Option<&'static str>,
    /// Oracle-shaped tracker bucket label, when one applied.
    pub tracker_bucket: Option<&'static str>,
    /// Oracle-shaped tracker action label, when a tracked inbound request was classified.
    pub tracker_action: Option<&'static str>,
    /// Number of packets observed in the current tracker window for this bucket.
    pub tracker_observed_packets: Option<u32>,
    /// Maximum packets allowed in the current tracker window for this bucket.
    pub tracker_max_packets: Option<u32>,
}

impl KadUdpDumpSummary {
    fn summary_string(&self) -> String {
        let mut parts = vec![format!("protocol=0x{:02X}", self.protocol)];
        if let Some(opcode) = self.opcode {
            parts.push(format!("opcode=0x{opcode:02X}"));
        }
        if let Some(opcode_name) = self.opcode_name {
            parts.push(format!("opcode_name={opcode_name}"));
        }
        parts.push(format!("raw_obfuscated={}", yes_no(self.raw_obfuscated)));
        if let Some(transport_mode) = self.transport_mode {
            parts.push(format!("transport_mode={transport_mode}"));
        }
        if let Some(requested_obfuscation) = self.requested_obfuscation {
            parts.push(format!(
                "requested_obfuscation={}",
                yes_no(requested_obfuscation)
            ));
        }
        if let Some(receiver_verify_key) = self.receiver_verify_key {
            parts.push(format!("receiver_verify_key={receiver_verify_key}"));
        }
        if let Some(sender_verify_key) = self.sender_verify_key {
            parts.push(format!("sender_verify_key={sender_verify_key}"));
        }
        if let Some(receiver_verify_key_valid) = self.receiver_verify_key_valid {
            parts.push(format!(
                "receiver_verify_key_valid={}",
                yes_no(receiver_verify_key_valid)
            ));
        }
        if let Some(tracked_request_opcode) = self.tracked_request_opcode {
            parts.push(format!("tracked_request_opcode={tracked_request_opcode}"));
        }
        if let Some(drop_reason) = self.drop_reason {
            parts.push(format!("drop_reason={drop_reason}"));
        }
        if let Some(tracker_bucket) = self.tracker_bucket {
            parts.push(format!("tracker_bucket={tracker_bucket}"));
        }
        if let Some(tracker_action) = self.tracker_action {
            parts.push(format!("tracker_action={tracker_action}"));
        }
        if let Some(tracker_observed_packets) = self.tracker_observed_packets {
            parts.push(format!(
                "tracker_observed_packets={tracker_observed_packets}"
            ));
        }
        if let Some(tracker_max_packets) = self.tracker_max_packets {
            parts.push(format!("tracker_max_packets={tracker_max_packets}"));
        }
        parts.join(" ")
    }
}

#[derive(Debug)]
struct UdpDumpWriter {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
}

#[derive(Debug, Serialize)]
struct UdpDumpRecord {
    schema: &'static str,
    source: &'static str,
    ts: String,
    event_seq: u64,
    trace_key: String,
    state_id: String,
    state_label: String,
    direction: &'static str,
    family: &'static str,
    peer: String,
    wire_len: usize,
    wire_hex: String,
    decoded_len: usize,
    decoded_hex: String,
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    opcode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    opcode_name: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_obfuscated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport_mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_obfuscation: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receiver_verify_key: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_verify_key: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receiver_verify_key_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tracked_request_opcode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    drop_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tracker_bucket: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tracker_action: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tracker_observed_packets: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tracker_max_packets: Option<u32>,
}

fn next_udp_dump_event_seq() -> u64 {
    static NEXT_EVENT_SEQ: AtomicU64 = AtomicU64::new(1);
    NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed)
}

fn udp_trace_key(peer: SocketAddr) -> String {
    format!("kad:{}", peer)
}

fn udp_state_label(summary: &KadUdpDumpSummary) -> String {
    summary
        .opcode_name
        .map(str::to_string)
        .unwrap_or_else(|| "packet".to_string())
}

fn udp_state_id(direction: &str, summary: &KadUdpDumpSummary) -> String {
    format!(
        "kad.{}.{}",
        direction,
        summary.opcode_name.unwrap_or("packet").to_ascii_lowercase()
    )
}

/// Append one oracle-shaped Kad UDP packet record to the current eMuleBB Rust dump file.
pub fn dump_kad_udp_packet(
    direction: &'static str,
    peer: SocketAddr,
    wire_payload: &[u8],
    decoded_payload: &[u8],
    summary: KadUdpDumpSummary,
) {
    let Some(writer) = udp_dump_writer() else {
        return;
    };

    let record = UdpDumpRecord {
        schema: "udp_packet_v1",
        source: "emulebb-rust",
        ts: Local::now().format("%Y-%m-%dT%H:%M:%S%.3f").to_string(),
        event_seq: next_udp_dump_event_seq(),
        trace_key: udp_trace_key(peer),
        state_id: udp_state_id(direction, &summary),
        state_label: udp_state_label(&summary),
        direction,
        family: "kad",
        peer: peer.to_string(),
        wire_len: wire_payload.len(),
        wire_hex: encode_hex_upper(wire_payload),
        decoded_len: decoded_payload.len(),
        decoded_hex: encode_hex_upper(decoded_payload),
        summary: summary.summary_string(),
        protocol: Some(format!("0x{:02X}", summary.protocol)),
        opcode: summary.opcode.map(|opcode| format!("0x{opcode:02X}")),
        opcode_name: summary.opcode_name,
        raw_obfuscated: Some(summary.raw_obfuscated),
        transport_mode: summary.transport_mode,
        requested_obfuscation: summary.requested_obfuscation,
        receiver_verify_key: summary.receiver_verify_key,
        sender_verify_key: summary.sender_verify_key,
        receiver_verify_key_valid: summary.receiver_verify_key_valid,
        tracked_request_opcode: summary.tracked_request_opcode,
        drop_reason: summary.drop_reason,
        tracker_bucket: summary.tracker_bucket,
        tracker_action: summary.tracker_action,
        tracker_observed_packets: summary.tracker_observed_packets,
        tracker_max_packets: summary.tracker_max_packets,
    };

    let Ok(mut guard) = writer.writer.lock() else {
        warn!("failed to lock Kad UDP dump writer");
        return;
    };

    if serde_json::to_writer(&mut *guard, &record).is_err() || guard.write_all(b"\n").is_err() {
        warn!(
            "failed to write Kad UDP dump line to {}",
            writer.path.display()
        );
        return;
    }

    if let Err(error) = guard.flush() {
        warn!(
            "failed to flush Kad UDP dump writer at {}: {}",
            writer.path.display(),
            error
        );
    }
}

fn udp_dump_writer() -> Option<&'static UdpDumpWriter> {
    UDP_DUMP_WRITER.get_or_init(init_udp_dump_writer).as_ref()
}

fn init_udp_dump_writer() -> Option<UdpDumpWriter> {
    let log_dir = workspace_log_dir();
    if let Err(error) = fs::create_dir_all(&log_dir) {
        warn!(
            "failed to create Kad UDP dump directory {}: {}",
            log_dir.display(),
            error
        );
        return None;
    }

    let file_name = format!(
        "{}{}{}",
        DUMP_FILE_PREFIX,
        Local::now().format("%Y.%m.%d-%H.%M.%S"),
        DUMP_FILE_SUFFIX
    );
    let path = log_dir.join(file_name);
    let file = match File::create(&path) {
        Ok(file) => file,
        Err(error) => {
            warn!(
                "failed to create Kad UDP dump file {}: {}",
                path.display(),
                error
            );
            return None;
        }
    };

    Some(UdpDumpWriter {
        path,
        writer: Mutex::new(BufWriter::new(file)),
    })
}

fn workspace_log_dir() -> PathBuf {
    read_env_path(EMULEBB_RUST_LOG_DIR_ENV).unwrap_or_else(workspace_tmp_dir)
}

fn workspace_tmp_dir() -> PathBuf {
    read_env_path(EMULEBB_RUST_TMP_DIR_ENV)
        .or_else(|| {
            read_env_path(EMULEBB_WORKSPACE_OUTPUT_ROOT_ENV)
                .map(|root| root.join("tmp").join(DEFAULT_WORKSPACE_TMP_DIR_NAME))
        })
        .unwrap_or_else(|| env::temp_dir().join(DEFAULT_WORKSPACE_TMP_DIR_NAME))
}

fn read_env_path(name: &str) -> Option<PathBuf> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn encode_hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0F) as usize] as char);
    }
    output
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_WORKSPACE_TMP_DIR_NAME, DUMP_FILE_PREFIX, EMULEBB_RUST_LOG_DIR_ENV,
        EMULEBB_RUST_TMP_DIR_ENV, KadUdpDumpSummary, encode_hex_upper,
    };

    #[test]
    fn encode_hex_upper_matches_oracle_style() {
        assert_eq!(encode_hex_upper(&[0xE4, 0x21, 0xAB, 0x00]), "E421AB00");
    }

    #[test]
    fn summary_string_is_machine_friendly() {
        let summary = KadUdpDumpSummary {
            protocol: 0xE4,
            opcode: Some(0x21),
            opcode_name: Some("KADEMLIA2_HELLO_REQ"),
            raw_obfuscated: true,
            transport_mode: Some("receiver_verify_key"),
            requested_obfuscation: Some(true),
            receiver_verify_key: Some(123),
            sender_verify_key: Some(456),
            receiver_verify_key_valid: Some(true),
            tracked_request_opcode: Some("KADEMLIA2_HELLO_REQ"),
            drop_reason: Some("tracker_drop"),
            tracker_bucket: Some("hello_req"),
            tracker_action: Some("drop"),
            tracker_observed_packets: Some(4),
            tracker_max_packets: Some(3),
        };

        assert_eq!(
            summary.summary_string(),
            "protocol=0xE4 opcode=0x21 opcode_name=KADEMLIA2_HELLO_REQ raw_obfuscated=yes transport_mode=receiver_verify_key requested_obfuscation=yes receiver_verify_key=123 sender_verify_key=456 receiver_verify_key_valid=yes tracked_request_opcode=KADEMLIA2_HELLO_REQ drop_reason=tracker_drop tracker_bucket=hello_req tracker_action=drop tracker_observed_packets=4 tracker_max_packets=3"
        );
    }

    #[test]
    fn dump_defaults_use_emulebb_rust_names() {
        assert_eq!(EMULEBB_RUST_TMP_DIR_ENV, "EMULEBB_RUST_TMP_DIR");
        assert_eq!(EMULEBB_RUST_LOG_DIR_ENV, "EMULEBB_RUST_LOG_DIR");
        assert_eq!(DEFAULT_WORKSPACE_TMP_DIR_NAME, "emulebb-rust");
        assert_eq!(DUMP_FILE_PREFIX, "emulebb-rust-kad-udp-dump-");
    }
}
