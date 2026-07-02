//! `family:"sched"` `diag_event_v1` emitters (uniform-diagnostics-v2, lane D2).
//!
//! These build the `keys` + `body` for the internal-scheduling events (schema
//! §3.5) from real call-site data and forward them to the shared writer
//! (`emulebb_ed2k::diag_event::emit`). They live in `emulebb-core` because the
//! cross-transfer source/connection decisions they observe (the download driver
//! + source registry) live here. Emit is a cheap no-op when `EMULEBB_RUST_LOG_DIR`
//!   is unset, so the call sites need no extra gating.
//!
//! No field is ever faked: optional `keys` (`peerHash`, `fileHash`) are omitted
//! when the call site does not have them.

use emulebb_ed2k::diag_event::emit;
use emulebb_ed2k::ed2k_server::Ed2kFoundSource;
use emulebb_ed2k::ed2k_transfer::Ed2kConnectionBudgetDecision;
use serde_json::{Map, Value, json};

const FAMILY: &str = "sched";

fn peer_string(source: &Ed2kFoundSource) -> String {
    format!("{}:{}", source.ip, source.tcp_port)
}

fn insert_source_keys(
    keys: &mut Map<String, Value>,
    source: &Ed2kFoundSource,
    file_hash_hex: &str,
) {
    keys.insert("peer".to_string(), json!(peer_string(source)));
    if let Some(user_hash) = source.user_hash {
        keys.insert("peerHash".to_string(), json!(hex::encode(user_hash)));
    }
    keys.insert("fileHash".to_string(), json!(file_hash_hex));
}

/// `conn_budget` (schema §3.5): the global connection-budget admit/deny decision
/// at the download driver's source-connect site.
pub(crate) fn conn_budget(
    decision: Ed2kConnectionBudgetDecision,
    file_hash_hex: &str,
    source: &Ed2kFoundSource,
) {
    let mut keys = Map::new();
    insert_source_keys(&mut keys, source, file_hash_hex);

    let mut body = Map::new();
    body.insert(
        "outcome".to_string(),
        json!(if decision.admitted { "admit" } else { "deny" }),
    );
    body.insert(
        "activeConnections".to_string(),
        json!(decision.active_connections),
    );
    body.insert("connectionCap".to_string(), json!(decision.connection_cap));
    if let Some(reason) = decision.deny_reason {
        body.insert("denyReason".to_string(), json!(reason.as_str()));
    }
    let severity = if decision.admitted { "info" } else { "low" };
    emit(
        FAMILY,
        "conn_budget",
        severity,
        Value::Object(keys),
        Value::Object(body),
    );
}

/// `source_engaged` (schema §3.5): a source begins being served for a file.
pub(crate) fn source_engaged(file_hash_hex: &str, source: &Ed2kFoundSource) {
    let mut keys = Map::new();
    insert_source_keys(&mut keys, source, file_hash_hex);
    let body = json!({ "outcome": "engaged" });
    emit(FAMILY, "source_engaged", "info", Value::Object(keys), body);
}

/// `source_dropped` (schema §3.5): a source is dropped from a file.
pub(crate) fn source_dropped(file_hash_hex: &str, source: &Ed2kFoundSource) {
    let mut keys = Map::new();
    insert_source_keys(&mut keys, source, file_hash_hex);
    let body = json!({ "outcome": "dropped" });
    emit(FAMILY, "source_dropped", "info", Value::Object(keys), body);
}

/// `source_swapped` (schema §3.5): an A4AF / NoNeededParts move of a source to a
/// different wanted file (`swapReason:"nnp"`).
pub(crate) fn source_swapped(
    current_file_hash_hex: &str,
    swap_target_file_hash_hex: &str,
    source: &Ed2kFoundSource,
) {
    let mut keys = Map::new();
    insert_source_keys(&mut keys, source, current_file_hash_hex);
    let body = json!({
        "outcome": "swapped",
        "swapReason": "nnp",
        "swapTargetFileHash": swap_target_file_hash_hex,
    });
    emit(FAMILY, "source_swapped", "info", Value::Object(keys), body);
}

/// `source_count` (schema §3.5): periodic download-source picture snapshot, for
/// parity with MFC `DiagEventLogDownloadSourceCount`. Field mapping to rust's
/// source registry: `sourceCount` = total live candidates; `validSourceCount` =
/// leased (actively engaged) sources; `nnpSourceCount` is 0 (rust does not keep a
/// NoNeededParts aggregate on the registry); `a4afFileCount` = A4AF-lite candidate
/// count (source-based). Keys are empty, matching MFC.
pub(crate) fn source_count(
    source_count: usize,
    valid_source_count: usize,
    nnp_source_count: usize,
    a4af_file_count: usize,
) {
    let body = json!({
        "sourceCount": source_count,
        "validSourceCount": valid_source_count,
        "nnpSourceCount": nnp_source_count,
        "a4afFileCount": a4af_file_count,
    });
    emit(FAMILY, "source_count", "info", Value::Object(Map::new()), body);
}
