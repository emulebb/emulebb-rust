//! `family:"sched"` `diag_event_v1` emitters for the inbound upload queue
//! (uniform-diagnostics-v2, lane D2). These mirror the download-side sched
//! emitters in `emulebb-core` (`diag_sched.rs`) for the upload scheduling
//! surface the eMuleBB master exposes via `LogUploadSlotDiagnostics`
//! (`UploadQueue.cpp`): slot open/close/recycle, queue rank, and the slot
//! capacity snapshot. See `docs/diagnostics/diag-event-v1-schema.md` §3.5.
//!
//! They build the `keys` + `body` from real call-site data and forward to the
//! shared writer (`crate::diag_event::emit`), which is a cheap no-op unless
//! `EMULEBB_RUST_LOG_DIR` is set, so the call sites need no extra gating. No
//! field is ever faked: an optional key (`peerHash`) is omitted when the call
//! site does not have the peer user hash.

use std::net::IpAddr;

use serde_json::{Map, Value, json};

use crate::diag_event::emit;

const FAMILY: &str = "sched";

/// Build the §3.5 `keys` object for an upload-slot event. `peer` is the stable
/// `ip:port` advertised peer endpoint (matching the upload-queue session key, so
/// the harness aligns slot events across both clients by the same identity).
fn upload_keys(peer: &str, peer_hash: Option<[u8; 16]>, file_hash: &str) -> Value {
    let mut keys = Map::new();
    keys.insert("peer".to_string(), json!(peer));
    if let Some(user_hash) = peer_hash {
        keys.insert("peerHash".to_string(), json!(hex::encode(user_hash)));
    }
    keys.insert("fileHash".to_string(), json!(file_hash));
    Value::Object(keys)
}

/// `peer` label (`ip:port`) for an advertised peer endpoint.
pub(crate) fn peer_label(ip: IpAddr, tcp_port: u16) -> String {
    format!("{ip}:{tcp_port}")
}

/// `upload_slot_opened` (schema §3.5): a peer is granted an upload slot
/// (OP_ACCEPTUPLOADREQ sent), the master `AddUpNextClient` transition.
pub(crate) fn upload_slot_opened(peer: &str, peer_hash: Option<[u8; 16]>, file_hash: &str) {
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({ "outcome": "opened" });
    emit(FAMILY, "upload_slot_opened", "info", keys, body);
}

/// `upload_slot_closed` (schema §3.5): an upload slot/queue entry is released on
/// disconnect or explicit cancel.
pub(crate) fn upload_slot_closed(peer: &str, peer_hash: Option<[u8; 16]>, file_hash: &str) {
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({ "outcome": "closed" });
    emit(FAMILY, "upload_slot_closed", "info", keys, body);
}

/// `upload_slot_recycled` (schema §3.5): an idle/timed-out active slot is
/// reclaimed by the queue (master `activeNoRequestRecycle*`), distinct from a
/// peer-initiated close.
pub(crate) fn upload_slot_recycled(
    peer: &str,
    peer_hash: Option<[u8; 16]>,
    file_hash: &str,
    reason: &str,
    slot_age_ms: u64,
    idle_ms: u64,
    uploaded_bytes: u64,
    slot_rate_bytes_per_sec: u64,
    active_before: usize,
    waiting_before: usize,
) {
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({
        "outcome": "recycled",
        "reason": reason,
        "slotAgeMs": slot_age_ms,
        "idleMs": idle_ms,
        "uploadedBytes": uploaded_bytes,
        "slotRateBytesPerSec": slot_rate_bytes_per_sec,
        "activeBefore": active_before,
        "waitingBefore": waiting_before,
    });
    emit(FAMILY, "upload_slot_recycled", "low", keys, body);
}

/// `queue_rank` (schema §3.5): a waiting peer's rank as sent on the wire
/// (OP_QUEUERANKING), the master per-slot `state=waiting` rank.
pub(crate) fn queue_rank(peer: &str, peer_hash: Option<[u8; 16]>, file_hash: &str, rank: u16) {
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({ "outcome": "waiting", "queueRank": rank });
    emit(FAMILY, "queue_rank", "info", keys, body);
}

/// `upload_request_outcome` (schema extension): one OP_REQUESTPARTS admission and
/// payload-serving result. This fills the parity gap between "request accepted"
/// and "payload packet left the socket", without logging file names or payload.
pub(crate) fn upload_request_outcome(
    peer: &str,
    peer_hash: Option<[u8; 16]>,
    file_hash: &str,
    outcome: &str,
    requested_ranges: usize,
    served_ranges: usize,
    skipped_ranges: usize,
    requested_bytes: u64,
    served_bytes: u64,
    payload_packets: usize,
    throttle_delay_ms: u64,
    first_skip_reason: Option<&str>,
) {
    let keys = upload_keys(peer, peer_hash, file_hash);
    let mut body = json!({
        "outcome": outcome,
        "requestedRanges": requested_ranges,
        "servedRanges": served_ranges,
        "skippedRanges": skipped_ranges,
        "requestedBytes": requested_bytes,
        "servedBytes": served_bytes,
        "payloadPackets": payload_packets,
        "throttleDelayMs": throttle_delay_ms,
    });
    if let (Value::Object(fields), Some(reason)) = (&mut body, first_skip_reason) {
        fields.insert("firstSkipReason".to_string(), json!(reason));
    }
    emit(FAMILY, "upload_request_outcome", "info", keys, body);
}

/// `capacity_snapshot` (schema §3.5): the rate-aware upload-slot capacity gauge
/// (master upload-slot summary `baseSlotTarget`/`effectiveSlotCap`/`activeSlots`).
/// Rust has no periodic upload-queue tick (its slot scheduling is driven per
/// connection), so this is emitted whenever the capacity is inspected rather
/// than on a fixed timer — a cadence difference the structural harness tolerates.
pub(crate) fn capacity_snapshot(
    base_slots: usize,
    elastic_slots: usize,
    effective_slot_cap: usize,
    active_sessions: usize,
    waiting_sessions: usize,
    upload_rate_bytes_per_sec: u64,
    upload_limit_bytes_per_sec: u64,
    elastic_underfill_bytes_per_sec: u64,
    elastic_underfill: bool,
    underfill_since_ms: Option<u64>,
) {
    let body = json!({
        "baseSlots": base_slots,
        "elasticSlots": elastic_slots,
        "effectiveSlotCap": effective_slot_cap,
        "activeSlots": active_sessions,
        "waitingSessions": waiting_sessions,
        "uploadRateBytesPerSec": upload_rate_bytes_per_sec,
        "uploadLimitBytesPerSec": upload_limit_bytes_per_sec,
        "elasticUnderfillBytesPerSec": elastic_underfill_bytes_per_sec,
        "elasticUnderfill": elastic_underfill,
        "underfillSinceMs": underfill_since_ms,
    });
    emit(
        FAMILY,
        "capacity_snapshot",
        "info",
        Value::Object(Map::new()),
        body,
    );
}
