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
pub(crate) fn upload_keys(peer: &str, peer_hash: Option<[u8; 16]>, file_hash: &str) -> Value {
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
/// `out_of_part_reqs` (schema extension): rust recycled a *granted* upload slot
/// and sent OP_OUTOFPARTREQS to send the downloader back to the waiting queue
/// (rather than dropping it into a churn-reconnect), mirroring MFC
/// `CUpDownClient::SendOutOfPartReqsAndAddToWaitingQueue`. Emitting it as a
/// diag_event lets the graceful-requeue rate diff rust vs MFC — the check for
/// whether slot recycling is quietly shedding upload demand.
pub(crate) fn out_of_part_reqs(peer: &str, peer_hash: Option<[u8; 16]>, file_hash: &str) {
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({ "action": "requeue", "signal": "out_of_part_reqs" });
    emit(FAMILY, "out_of_part_reqs", "low", keys, body);
}

pub(crate) fn upload_slot_closed(
    peer: &str,
    peer_hash: Option<[u8; 16]>,
    file_hash: &str,
    reason: &str,
) {
    let keys = upload_keys(peer, peer_hash, file_hash);
    // `reason` is the upload-funnel close cause (peer_cancelled | end_of_download |
    // slot_recycled | rejected_never_granted | peer_disconnected) so rust vs MFC
    // "why did the upload peer leave" distributions diff directly.
    let body = json!({ "outcome": "closed", "reason": reason });
    emit(FAMILY, "upload_slot_closed", "info", keys, body);
}

/// `upload_slot_recycled` (schema §3.5): an idle/timed-out active slot is
/// reclaimed by the queue (master `activeNoRequestRecycle*`), distinct from a
/// peer-initiated close.
#[allow(clippy::too_many_arguments)]
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
#[allow(clippy::too_many_arguments)]
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
    verified_reader_open_ms: u64,
    payload_read_ms: u64,
    read_cache_hits: usize,
    read_cache_misses: usize,
    read_disk_bytes: u64,
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
        "verifiedReaderOpenMs": verified_reader_open_ms,
        "payloadReadMs": payload_read_ms,
        "readCacheHits": read_cache_hits,
        "readCacheMisses": read_cache_misses,
        "readDiskBytes": read_disk_bytes,
    });
    if let (Value::Object(fields), Some(reason)) = (&mut body, first_skip_reason) {
        fields.insert("firstSkipReason".to_string(), json!(reason));
    }
    emit(FAMILY, "upload_request_outcome", "info", keys, body);
}

/// `upload_payload_accounting` (schema extension): aggregate payload bytes sent
/// for one served OP_REQUESTPARTS packet. Mirrors the MFC diagnostics event so
/// live parity runs can compare file bytes versus protocol packet bytes.
pub(crate) fn upload_payload_accounting(
    peer: &str,
    peer_hash: Option<[u8; 16]>,
    file_hash: &str,
    sent_file_bytes: u64,
    sent_payload_bytes: u64,
    sent_complete_file_bytes: u64,
    sent_part_file_bytes: u64,
) {
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({
        "outcome": "sent",
        "sentFileBytes": sent_file_bytes,
        "sentPayloadBytes": sent_payload_bytes,
        "sentCompleteFileBytes": sent_complete_file_bytes,
        "sentPartFileBytes": sent_part_file_bytes,
    });
    emit(FAMILY, "upload_payload_accounting", "info", keys, body);
}

/// `capacity_snapshot` (schema §3.5): the rate-aware upload-slot capacity gauge
/// (master upload-slot summary `baseSlotTarget`/`effectiveSlotCap`/`activeSlots`).
/// Rust has no periodic upload-queue tick (its slot scheduling is driven per
/// connection), so this is emitted whenever the capacity is inspected rather
/// than on a fixed timer — a cadence difference the structural harness tolerates.
#[allow(clippy::too_many_arguments)]
pub(crate) fn capacity_snapshot(
    base_slots: usize,
    elastic_slots: usize,
    effective_slot_cap: usize,
    active_sessions: usize,
    waiting_sessions: usize,
    active_granted_sessions: usize,
    active_uploading_sessions: usize,
    active_never_uploaded_sessions: usize,
    active_productive_sessions: usize,
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
        "activeGrantedSessions": active_granted_sessions,
        "activeUploadingSessions": active_uploading_sessions,
        "activeNeverUploadedSessions": active_never_uploaded_sessions,
        "activeProductiveSessions": active_productive_sessions,
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

/// `shared_publish_offer_batch`: one ED2K `OP_OFFERFILES` server publish batch.
/// Hash samples are enough to align Rust/MFC batch selection without leaking
/// private filenames or paths.
#[cfg(feature = "packet-diagnostics")]
#[allow(clippy::too_many_arguments)] // a flat diagnostics record builder; each field is a distinct dump column
pub(crate) fn shared_publish_offer_batch(
    server: &str,
    entries_sent: usize,
    total_entries: usize,
    cursor_before: usize,
    next_cursor: usize,
    offer_limit: usize,
    wrapped: bool,
    skipped_duplicate_batch: bool,
    file_hashes: Vec<String>,
) {
    let keys = json!({ "server": server });
    // `offerLimit` (per-batch cap) and `pendingBefore` (entries still to advertise
    // when this batch started) mirror the MFC oracle body; cursorBefore/nextCursor
    // are rust's extra cursor detail (allowed superset).
    let pending_before = total_entries.saturating_sub(cursor_before);
    let body = json!({
        "entriesSent": entries_sent,
        "totalEntries": total_entries,
        "pendingBefore": pending_before,
        "offerLimit": offer_limit,
        "cursorBefore": cursor_before,
        "nextCursor": next_cursor,
        "wrapped": wrapped,
        "skippedDuplicateBatch": skipped_duplicate_batch,
        "fileHashes": file_hashes,
    });
    emit(FAMILY, "shared_publish_offer_batch", "info", keys, body);
}
