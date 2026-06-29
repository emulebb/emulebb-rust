//! `diag_event_v1` unified diagnostic event writer (uniform-diagnostics-v2, lane
//! D2). One JSONL object per line under `EMULEBB_RUST_LOG_DIR`, mirroring the
//! envelope in `docs/diagnostics/diag-event-v1-schema.md` §2.
//!
//! Writer placement: the `diag_event_v1` surface must be reachable from
//! `emulebb-ed2k`, `emulebb-core`, and `emulebb-kad-net`. The only crate all
//! three share is `emulebb-kad-proto` (a pure codec crate with no serde_json /
//! chrono), so hosting the writer there would be a bad layering choice. Instead
//! each crate carries a small emit shim writing the IDENTICAL JSONL format to a
//! file named `emulebb-rust-diag-<pid>.jsonl` (append mode) so every shim in one
//! process converges on the SAME file. `emulebb-core` depends on `emulebb-ed2k`
//! and reuses THIS module directly (so there are only two copies of the format:
//! this one for ed2k+core, and a twin in `emulebb-kad-net`). `seq` is a
//! per-module monotonic counter, which the harness treats as client-specific
//! intra-side ordering only (schema §2), so a per-module counter is sufficient.
//!
//! Gating (schema §5): the writer is runtime-gated by `EMULEBB_RUST_LOG_DIR`.
//! Packet families are ADDITIONALLY behind the `packet-diagnostics` Cargo
//! feature at their call sites (the eD2k TCP dump). Kad/sched families are gated
//! by the env var alone. When `EMULEBB_RUST_LOG_DIR` is unset, [`writer`] caches
//! `None` once and every [`emit`] is a cheap no-op.

#![cfg_attr(not(feature = "packet-diagnostics"), allow(dead_code))]

use std::{
    fs,
    io::Write,
    sync::{
        Mutex as StdMutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use chrono::SecondsFormat;
use serde::Serialize;
use serde_json::Value;

const DIAG_EVENT_FILE_PREFIX: &str = "emulebb-rust-diag-";

/// One `diag_event_v1` envelope (schema §2). `keys` and `body` are arbitrary
/// JSON objects supplied by the call site so each family maps its own §3 fields.
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

fn writer() -> &'static StdMutex<Option<fs::File>> {
    static DIAG_FILE: OnceLock<StdMutex<Option<fs::File>>> = OnceLock::new();
    DIAG_FILE.get_or_init(|| {
        let file = std::env::var("EMULEBB_RUST_LOG_DIR")
            .ok()
            .map(std::path::PathBuf::from)
            .and_then(|dir| {
                fs::create_dir_all(&dir).ok()?;
                let path = dir.join(format!(
                    "{DIAG_EVENT_FILE_PREFIX}{}.jsonl",
                    std::process::id()
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

/// Append one `diag_event_v1` record. `keys` / `body` are pre-built JSON values
/// (use [`serde_json::json!`]); omit optional fields rather than emitting fake
/// data. No-op when `EMULEBB_RUST_LOG_DIR` is unset.
pub fn emit(
    family: &'static str,
    event: &'static str,
    severity: &'static str,
    keys: Value,
    body: Value,
) {
    let Ok(mut guard) = writer().lock() else {
        return;
    };
    let Some(file) = guard.as_mut() else {
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
    let Some(line) = encode_record_line(&record) else {
        return;
    };
    let _ = file.write_all(&line);
    let _ = file.flush();
}

fn encode_record_line(record: &DiagEventRecord) -> Option<Vec<u8>> {
    let mut line = serde_json::to_vec(record).ok()?;
    line.push(b'\n');
    Some(line)
}

#[cfg(test)]
mod tests {
    use super::{DIAG_EVENT_FILE_PREFIX, DiagEventRecord, encode_record_line};
    use serde_json::json;

    #[test]
    fn diag_event_file_prefix_uses_emulebb_rust_name() {
        assert_eq!(DIAG_EVENT_FILE_PREFIX, "emulebb-rust-diag-");
    }

    #[test]
    fn encoded_diag_event_line_is_single_json_record_with_newline() {
        let record = DiagEventRecord {
            schema: "diag_event_v1",
            client: "rust",
            ts: "2026-06-18T00:00:00.000Z".to_string(),
            seq: 1,
            family: "sched",
            event: "source_dropped",
            severity: "info",
            keys: json!({"peer": "192.0.2.10:4662"}),
            body: json!({"outcome": "dropped"}),
        };

        let line = encode_record_line(&record).expect("line encoded");
        assert_eq!(line.last(), Some(&b'\n'));
        let without_newline = &line[..line.len() - 1];
        let decoded: serde_json::Value = serde_json::from_slice(without_newline).unwrap();
        assert_eq!(decoded["schema"], "diag_event_v1");
        assert_eq!(decoded["family"], "sched");
    }
}
