//! `diag_event_v1` unified diagnostic event writer (uniform-diagnostics-v2, lane
//! D2) — `emulebb-kad-net` twin of the `emulebb-ed2k` shim.
//!
//! `emulebb-kad-net` does not depend on `emulebb-ed2k` (and must not, to avoid a
//! dependency cycle), so it carries its own copy of the identical `diag_event_v1`
//! JSONL format. Every shim in one process writes to the SAME file
//! `emulebb-rust-diag-<pid>.jsonl` in append mode, so the kad_udp records this
//! crate emits interleave with the ed2k_tcp/sched records the ed2k+core shim
//! emits. See `crates/emulebb-ed2k/src/diag_event.rs` for the full rationale.
//!
//! Gating (schema §5): runtime-gated by `EMULEBB_RUST_LOG_DIR` presence; the Kad
//! UDP packet family carries no Cargo feature gate (kad/sched families are env-
//! gated only). When the env var is unset, [`emit`] is a cheap no-op.

use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};

use chrono::SecondsFormat;
use serde::Serialize;
use serde_json::Value;
use tracing::warn;

const EMULEBB_RUST_LOG_DIR_ENV: &str = "EMULEBB_RUST_LOG_DIR";
const DIAG_EVENT_FILE_PREFIX: &str = "emulebb-rust-diag-";

static DIAG_EVENT_WRITER: OnceLock<Option<DiagEventWriter>> = OnceLock::new();

#[derive(Debug)]
struct DiagEventWriter {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
}

/// One `diag_event_v1` envelope (schema §2). `keys` / `body` are arbitrary JSON
/// objects supplied by the call site.
#[derive(Debug, Serialize)]
struct DiagEventRecord {
    schema: &'static str,
    client: &'static str,
    ts: String,
    seq: u64,
    family: &'static str,
    event: &'static str,
    severity: &'static str,
    keys: Value,
    body: Value,
}

fn next_seq() -> u64 {
    static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);
    NEXT_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Append one `diag_event_v1` record. No-op when `EMULEBB_RUST_LOG_DIR` is unset.
pub fn emit(
    family: &'static str,
    event: &'static str,
    severity: &'static str,
    keys: Value,
    body: Value,
) {
    let Some(writer) = diag_event_writer() else {
        return;
    };
    let record = DiagEventRecord {
        schema: "diag_event_v1",
        client: "rust",
        ts: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        seq: next_seq(),
        family,
        event,
        severity,
        keys,
        body,
    };
    let Ok(mut guard) = writer.writer.lock() else {
        warn!("failed to lock diag_event writer");
        return;
    };
    if serde_json::to_writer(&mut *guard, &record).is_err() || guard.write_all(b"\n").is_err() {
        warn!(
            "failed to write diag_event line to {}",
            writer.path.display()
        );
        return;
    }
    let _ = guard.flush();
}

/// `family:"kad_event"` `bootstrap` milestone `bootstrap_contact_added`
/// (uniform-diagnostics-v2 §3.3): a contact was added to the routing table from a
/// bootstrap response. `peer` is the contact's `ip:port` (Kad UDP endpoint).
/// Typed wrapper so `emulebb-kad-dht` need not depend on `serde_json` directly.
/// No-op when `EMULEBB_RUST_LOG_DIR` is unset.
pub fn kad_event_bootstrap_contact_added(peer: std::net::SocketAddr) {
    emit(
        "kad_event",
        "bootstrap",
        "info",
        serde_json::json!({ "peer": peer.to_string() }),
        serde_json::json!({ "milestone": "bootstrap_contact_added", "action": "observe" }),
    );
}

/// `family:"bad_peer"` abuse event (uniform-diagnostics-v2 §3.4): a Kad UDP peer
/// was dropped by the public-network anti-flood guard. `behavior` is the abuse
/// classification (e.g. `anti_flood_ban`, `anti_flood_drop`), `reason` the
/// drop classification (e.g. the tracker bucket/action label). `repeat_count` is
/// the observed packet count in the tracker window; `window_seconds` the window.
/// Only `peer` is known at the Kad UDP layer, so `peerHash`/`fileHash`/`searchId`
/// are omitted (not faked). No-op when `EMULEBB_RUST_LOG_DIR` is unset.
pub fn bad_peer_kad_drop(
    event: &'static str,
    severity: &'static str,
    behavior: &'static str,
    reason: &str,
    peer: std::net::SocketAddr,
    repeat_count: u32,
    window_seconds: u64,
) {
    emit(
        "bad_peer",
        event,
        severity,
        serde_json::json!({ "peer": peer.to_string() }),
        serde_json::json!({
            "behavior": behavior,
            "action": "drop",
            "reason": reason,
            "repeatCount": repeat_count,
            "windowSeconds": window_seconds,
        }),
    );
}

fn diag_event_writer() -> Option<&'static DiagEventWriter> {
    DIAG_EVENT_WRITER
        .get_or_init(init_diag_event_writer)
        .as_ref()
}

fn init_diag_event_writer() -> Option<DiagEventWriter> {
    let dir = read_env_path(EMULEBB_RUST_LOG_DIR_ENV)?;
    if let Err(error) = fs::create_dir_all(&dir) {
        warn!(
            "failed to create diag_event directory {}: {}",
            dir.display(),
            error
        );
        return None;
    }
    let path = dir.join(format!(
        "{DIAG_EVENT_FILE_PREFIX}{}.jsonl",
        std::process::id()
    ));
    let file = match fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => file,
        Err(error) => {
            warn!(
                "failed to open diag_event file {}: {}",
                path.display(),
                error
            );
            return None;
        }
    };
    Some(DiagEventWriter {
        path,
        writer: Mutex::new(BufWriter::new(file)),
    })
}

fn read_env_path(name: &str) -> Option<PathBuf> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::{DIAG_EVENT_FILE_PREFIX, bad_peer_kad_drop, kad_event_bootstrap_contact_added};

    #[test]
    fn diag_event_file_prefix_uses_emulebb_rust_name() {
        assert_eq!(DIAG_EVENT_FILE_PREFIX, "emulebb-rust-diag-");
    }

    #[test]
    fn typed_helpers_emit_without_panicking() {
        // Exercises the bad_peer + kad_event(bootstrap) builder paths. Writes a
        // real record only when EMULEBB_RUST_LOG_DIR is set (used by the lane-E
        // trace-capture run); otherwise a cheap no-op.
        kad_event_bootstrap_contact_added("1.2.3.4:4672".parse().unwrap());
        bad_peer_kad_drop(
            "anti_flood_ban",
            "high",
            "anti_flood_ban",
            "tracker_massive_drop",
            "5.6.7.8:4672".parse().unwrap(),
            42,
            10,
        );
        bad_peer_kad_drop(
            "anti_flood_drop",
            "medium",
            "anti_flood_drop",
            "tracker_drop",
            "5.6.7.8:4672".parse().unwrap(),
            7,
            10,
        );
    }
}
