//! `family:"sched"` `diag_event_v1` emitters (uniform-diagnostics-v2, lane D2).
//!
//! These build the `keys` + `body` for the internal-scheduling events (schema
//! §3.5) from real call-site data and forward them to the shared writer
//! (`emulebb_ed2k::diag_event::emit`). They live in `emulebb-core` because the
//! cross-transfer source/connection decisions they observe (the download driver
//! + source registry) live here. Emit is compiled to a no-op unless
//! `packet-diagnostics` is enabled and then remains runtime-gated by
//! `EMULEBB_RUST_LOG_DIR`.
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

/// `source_conn_budget`: rust's OUTBOUND download-source connect-budget gate
/// (admit/deny a new connection to a download source). Named distinctly from the
/// MFC oracle's `conn_budget`, which is the INBOUND listen-accept cap
/// (`DiagEventLogSchedConnBudgetDeny`, deny-only, empty keys) — a different gate,
/// so sharing the name would misalign a rust-vs-MFC diff. (Follow-up: emit a
/// matching `conn_budget` at rust's own inbound-accept cap to cover the oracle.)
pub(crate) fn source_conn_budget(
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
        "source_conn_budget",
        severity,
        Value::Object(keys),
        Value::Object(body),
    );
}

/// `download_attempt_outcome`: the terminal decision of one outbound download
/// attempt for a file — the counters that gate the queued-vs-downloading return in
/// `run_ed2k_download_attempt`. Rust-only instrumentation (no oracle analogue); lets
/// a soak see, per attempt, whether the transfer engaged/queued at any source and
/// why it ended in `state`, so the persistent-reask behaviour can be judged from
/// evidence rather than inferred. `keys.fileHash` only (whole-file decision).
#[allow(clippy::too_many_arguments)]
pub(crate) fn download_attempt_outcome(
    file_hash_hex: &str,
    state: &str,
    sources_remaining: usize,
    had_direct_sources: bool,
    accepted_incomplete_peers: u32,
    callback_sources_requested: usize,
    deferred_active_direct: bool,
    manifest_progress: bool,
    requery_rounds: usize,
) {
    let mut keys = Map::new();
    keys.insert("fileHash".to_string(), json!(file_hash_hex));
    let body = json!({
        "state": state,
        "sourcesRemaining": sources_remaining,
        "hadDirectSources": had_direct_sources,
        "acceptedIncompletePeers": accepted_incomplete_peers,
        "callbackSourcesRequested": callback_sources_requested,
        "deferredActiveDirect": deferred_active_direct,
        "manifestProgress": manifest_progress,
        "requeryRounds": requery_rounds,
    });
    let severity = if state == "queued" { "low" } else { "info" };
    emit(
        FAMILY,
        "download_attempt_outcome",
        severity,
        Value::Object(keys),
        body,
    );
}

/// `download_task_settled`: a background download task for a file is exiting, with
/// `willReask` = whether it schedules a re-drive. Rust-only; makes the "task dies on
/// queued and is never re-asked" defect (and its fix) directly visible.
pub(crate) fn download_task_settled(file_hash_hex: &str, state: &str, will_reask: bool) {
    let mut keys = Map::new();
    keys.insert("fileHash".to_string(), json!(file_hash_hex));
    let body = json!({ "state": state, "willReask": will_reask });
    emit(
        FAMILY,
        "download_task_settled",
        "info",
        Value::Object(keys),
        body,
    );
}

/// `download_attempt_started`: a queued background download attempt actually
/// entered its body (post-dedup, pre-source-acquisition). Rust-only breadcrumb;
/// `blocked: true` means the dedup slot was still held and the attempt died
/// silently instead. Pairs with `download_attempt_outcome`/`download_task_settled`
/// so a spawned-but-stuck attempt is visible in the diag stream.
pub(crate) fn download_attempt_started(file_hash_hex: &str, blocked: bool) {
    let mut keys = Map::new();
    keys.insert("fileHash".to_string(), json!(file_hash_hex));
    let body = json!({ "blocked": blocked });
    emit(
        FAMILY,
        "download_attempt_started",
        if blocked { "low" } else { "info" },
        Value::Object(keys),
        body,
    );
}

/// `download_retry_outcome`: the delayed background retry for a "downloading"
/// exit woke up and either re-queued the attempt or died, with the transfer
/// state it observed. Rust-only; pairs with `download_task_settled` so a
/// deferred transfer that never re-attempts is attributable from the diag
/// stream (retry-died vs attempt-never-scheduled).
pub(crate) fn download_retry_outcome(file_hash_hex: &str, observed_state: &str, requeued: bool) {
    let mut keys = Map::new();
    keys.insert("fileHash".to_string(), json!(file_hash_hex));
    let body = json!({ "observedState": observed_state, "requeued": requeued });
    emit(
        FAMILY,
        "download_retry_outcome",
        if requeued { "info" } else { "low" },
        Value::Object(keys),
        body,
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

/// `source_dead_listed` (source-drop family, §3.5 shape): a source answered our
/// file request with file-not-found — TCP `OP_FILEREQANSNOFIL`, UDP
/// `OP_FILENOTFOUND`, or an AICH-root mismatch treated like FNF — and was put on
/// the per-file dead-source list for the 45-minute oracle block
/// (`CPartFile::m_DeadSourceList.AddDeadSource`, `ListenSocket.cpp:645-661` /
/// `DownloadClient.cpp:1781` / `:2979`). The matching registry removal still
/// emits `source_dropped`; this event carries the WHY (`reason`) + block length
/// so soak diffing can attribute the drop to the FNF path.
pub(crate) fn source_dead_listed(file_hash_hex: &str, source: &Ed2kFoundSource, reason: &str) {
    let mut keys = Map::new();
    insert_source_keys(&mut keys, source, file_hash_hex);
    let body = json!({
        "outcome": "dead_listed",
        "reason": reason,
        "blockSecs": crate::ed2k_dead_source_list::DEAD_SOURCE_BLOCK.as_secs(),
    });
    emit(
        FAMILY,
        "source_dead_listed",
        "info",
        Value::Object(keys),
        body,
    );
}

/// `source_nnp_held` (source family, §3.5 shape): a source answered with a file
/// status offering no part we still need (oracle `DS_NONEEDEDPARTS`,
/// DownloadClient.cpp:848-852) and is HELD for the doubled reask cycle
/// (`FILEREASKTIME * 2`, DownloadClient.cpp:2425-2431) instead of dropped: it
/// stays in the download source registry and is re-asked after `holdSecs` in
/// case it acquired needed parts since. Distinct from `source_dead_listed`
/// (FNF): an NNP source is kept and re-asked, never dead-listed.
pub(crate) fn source_nnp_held(file_hash_hex: &str, source: &Ed2kFoundSource) {
    let mut keys = Map::new();
    insert_source_keys(&mut keys, source, file_hash_hex);
    let body = json!({
        "outcome": "nnp_held",
        "holdSecs": crate::download_source_registry::NNP_REASK_HOLD.as_secs(),
    });
    emit(FAMILY, "source_nnp_held", "info", Value::Object(keys), body);
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

/// `keyword_search`: a user-facing keyword search completed. Converged parity of the
/// MFC oracle search path — captures the network method used and how many results
/// came back, so rust-vs-oracle search behaviour is diffable from the diag stream.
/// Privacy: the query text is NOT logged (only its length + result count + method),
/// so search terms never reach the diagnostics. `keys` empty (whole-search event).
pub(crate) fn keyword_search(method: &str, result_count: usize, query_len: usize, status: &str) {
    let body = json!({
        "method": method,
        "resultCount": result_count,
        "queryLen": query_len,
        "status": status,
    });
    emit(
        FAMILY,
        "keyword_search",
        "info",
        Value::Object(Map::new()),
        body,
    );
}

/// `keyword_search_queue`: rust-only superset event tracing the connection-aware
/// search queue lifecycle — `outcome` is `queued` (submitted while the backend
/// was not ready), `rejected` (duplicate/cap at enqueue), `drained` (dispatched
/// once the backend became ready), `retry` (send interrupted mid-flight,
/// re-queued), `retry-exhausted`, or `expired` (max queue wait exceeded).
/// Privacy: like `keyword_search`, the query text is never logged — only the
/// requested method, the machine reason token, and the attempt count.
pub(crate) fn keyword_search_queue(
    outcome: &str,
    method: &str,
    reason: Option<&str>,
    attempts: u32,
) {
    let mut body = Map::new();
    body.insert("outcome".to_string(), json!(outcome));
    body.insert("method".to_string(), json!(method));
    if let Some(reason) = reason {
        body.insert("reason".to_string(), json!(reason));
    }
    body.insert("attempts".to_string(), json!(attempts));
    let severity = match outcome {
        "drained" => "info",
        _ => "low",
    };
    emit(
        FAMILY,
        "keyword_search_queue",
        severity,
        Value::Object(Map::new()),
        Value::Object(body),
    );
}

/// `source_count` (schema §3.5): periodic download-source picture snapshot, for
/// parity with MFC `DiagEventLogDownloadSourceCount`. Field mapping to rust's
/// source registry: `sourceCount` = total live candidates; `validSourceCount` =
/// leased (actively engaged) sources; `nnpSourceCount` = (source, file) pairs
/// under an active No-Needed-Parts hold (the MFC `DS_NONEEDEDPARTS` aggregate);
/// `a4afFileCount` = A4AF-lite candidate count (source-based). Keys are empty,
/// matching MFC.
pub(crate) fn source_count(
    source_count: usize,
    valid_source_count: usize,
    nnp_source_count: usize,
    a4af_file_count: usize,
    transferring_source_count: usize,
) {
    let body = json!({
        "sourceCount": source_count,
        "validSourceCount": valid_source_count,
        "nnpSourceCount": nnp_source_count,
        "a4afFileCount": a4af_file_count,
        // `transferringSourceCount` = sources with a live download connection this
        // round (rust `active_download_peer_endpoints`), the parity of MFC
        // `GetTransferringSrcCount` (DS_DOWNLOADING). This is the key convergence
        // metric: leased-but-not-transferring (validSourceCount >> this) is the
        // stall signature (many engaged sources, none moving bytes).
        "transferringSourceCount": transferring_source_count,
    });
    emit(
        FAMILY,
        "source_count",
        "info",
        Value::Object(Map::new()),
        body,
    );
}
