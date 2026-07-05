//! `family:"bad_peer"` `diag_event_v1` emitters for the inbound upload path and
//! the outbound download path (first-payload timeout).
//!
//! Mirrors the eMuleBB (MFC) `BadPeerDiagnosticsSeams` bad-peer events so the
//! two clients' diagnostics diff cleanly (`diag_event_diff.py`). Emits go through
//! the shared writer (`crate::diag_event::emit`), a cheap no-op unless packet
//! diagnostics are enabled.

use serde_json::json;

use crate::diag_event::emit;

use super::diag_sched::upload_keys;

/// `peer`-only keys for a packet-level bad_peer event (no file/context). `peerHash`
/// is included only when the peer's user hash is already known (post-hello).
fn packet_keys(peer: &str, peer_hash: Option<[u8; 16]>) -> serde_json::Value {
    let mut keys = serde_json::Map::new();
    keys.insert("peer".to_string(), json!(peer));
    if let Some(user_hash) = peer_hash {
        keys.insert("peerHash".to_string(), json!(hex::encode(user_hash)));
    }
    serde_json::Value::Object(keys)
}

/// `packet_unknown_client_tcp_packet`: an inbound peer TCP packet whose
/// protocol/opcode the eD2K dispatcher does not handle; the connection is dropped.
/// Mirrors MFC `packet_unknown_client_tcp_packet` (severity medium,
/// `action:"disconnect"`). protocol/opcode/payloadBytes are informational evidence
/// (not diff-comparable body fields), so this cannot introduce a conformance gap.
pub(crate) fn packet_unknown_client_tcp_packet(
    peer: &str,
    peer_hash: Option<[u8; 16]>,
    protocol: u8,
    opcode: u8,
    payload_bytes: usize,
) {
    let keys = packet_keys(peer, peer_hash);
    let body = json!({
        "action": "disconnect",
        "reason": "Unknown client TCP packet",
        "protocol": protocol,
        "opcode": opcode,
        "payloadBytes": payload_bytes,
    });
    emit(
        "bad_peer",
        "packet_unknown_client_tcp_packet",
        "medium",
        keys,
        body,
    );
}

/// Failed file-id requests before a peer is treated as a probe flooder and banned
/// (MFC `m_fFailedFileIdReqs == 6`).
pub(crate) const FAILED_FILE_REQ_FLOOD_THRESHOLD: u32 = 6;

/// `file_request_flood`: a peer repeatedly requested files we do not serve (failed
/// file-id requests) — a share-probe flood. Banned (IP + hash) and dropped. Mirrors
/// MFC `file_request_flood` (severity high, `action:"ban"`).
pub(crate) fn file_request_flood(peer: &str, peer_hash: Option<[u8; 16]>, failed_requests: u32) {
    let keys = packet_keys(peer, peer_hash);
    let body = json!({
        "action": "ban",
        "reason": "FileReq flood",
        "failedFileIdRequests": failed_requests,
    });
    emit("bad_peer", "file_request_flood", "high", keys, body);
}

/// `identity_userhash_changed`: a peer advertised a DIFFERENT user hash on the same
/// connection after one was already bound — credit-farming / impersonation, since
/// rust attributes upload/download credit by user hash. The peer is banned (IP +
/// new hash) and dropped. Mirrors MFC `identity_userhash_changed` (severity high,
/// `action:"ban"`). `action` is the only diff-comparable body field, so this is
/// conformance-safe.
pub(crate) fn identity_userhash_changed(peer: &str, peer_hash: Option<[u8; 16]>) {
    let keys = packet_keys(peer, peer_hash);
    let body = json!({
        "action": "ban",
        "reason": "Userhash changed",
    });
    emit("bad_peer", "identity_userhash_changed", "high", keys, body);
}

/// `packet_invalid_multipacket_subopcode`: a peer sent a multipacket carrying a
/// sub-opcode the decoder does not accept. Mirrors MFC
/// `packet_invalid_multipacket_subopcode` (severity medium). rust aborts the
/// connection on the bad sub-op (more defensive than the oracle's reject); the
/// `subOpcode` is informational evidence.
pub(crate) fn packet_invalid_multipacket_subopcode(
    peer: &str,
    peer_hash: Option<[u8; 16]>,
    sub_opcode: u8,
) {
    let keys = packet_keys(peer, peer_hash);
    let body = json!({
        "action": "disconnect",
        "reason": "Invalid multipacket sub-opcode",
        "subOpcode": sub_opcode,
    });
    emit(
        "bad_peer",
        "packet_invalid_multipacket_subopcode",
        "medium",
        keys,
        body,
    );
}

/// Observation window for repeat-block detection, matching the MFC bad-peer
/// ledger window (`windowSeconds: 3600`).
pub(crate) const REPEAT_BLOCK_WINDOW_SECS: u64 = 3600;

/// Observation window for repeat same-file upload churn, matching the MFC
/// bad-peer ledger window (`windowSeconds: 3600`).
pub(crate) const REPEAT_FILE_WINDOW_SECS: u64 = 3600;

/// `repeat_block_request`: a peer re-requested the exact same upload block within
/// the observation window. Mirrors MFC `LogUploadBlockRequestBehavior` ->
/// `repeat_block_request` (oracle `CSharedFileList`). Observe-only: the block is
/// still served; this only surfaces the behavior so rust/MFC bad-peer traces
/// line up. `part_index` is `start_offset / ED2K_PART_SIZE`, as MFC reports it.
pub(crate) fn repeat_block_request(
    peer: &str,
    peer_hash: Option<[u8; 16]>,
    file_hash: &str,
    start_offset: u64,
    end_offset: u64,
    part_index: u64,
    repeat_count: u32,
) {
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({
        "action": "observe",
        "behavior": "repeat_block_request",
        "reason": "Repeated same upload block request",
        "repeatCount": repeat_count,
        "windowSeconds": REPEAT_BLOCK_WINDOW_SECS,
        "startOffset": start_offset,
        "endOffset": end_offset,
        "partIndex": part_index,
    });
    emit("bad_peer", "repeat_block_request", "medium", keys, body);
}

/// Process-global rejection ledger backing `upload_duplicate_done_block_rejected`
/// and `upload_duplicate_queued_block_rejected`.
///
/// WHY global (not per-connection): MFC counts these rejections in a
/// process-wide map (`g_badPeerBehaviorLedger`, `UpdateBehaviorLedger`) keyed
/// `peerKey|block|fileHash|start|end`, so a peer that reconnects and re-requests
/// the same already-served block keeps accumulating `repeatCount` across
/// connections within the hour. Keying this per-connection (as the observe-only
/// `repeat_block_request` ledger does, which counts *requests*, not rejections)
/// under-counts vs the oracle and was one of the two causes of the RUST-FEAT-025
/// revert (`045a781`). This ledger counts REJECTION emissions, globally, per
/// `(peer_key, file_hash, start, end)`.
mod duplicate_block_ledger {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use super::REPEAT_BLOCK_WINDOW_SECS;

    /// Cleanup sweep cadence (MFC `kBadPeerBehaviorLedgerCleanupMs = SEC2MS(60)`).
    const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
    /// Hard cap so a flood of distinct `(peer, block)` keys cannot grow the map
    /// without bound between sweeps; the oldest entries are dropped first.
    const MAX_ENTRIES: usize = 4096;

    struct Entry {
        first_seen: Instant,
        last_seen: Instant,
        count: u32,
    }

    struct Ledger {
        entries: HashMap<(String, String, u64, u64), Entry>,
        last_cleanup: Instant,
    }

    fn ledger() -> &'static Mutex<Ledger> {
        static LEDGER: OnceLock<Mutex<Ledger>> = OnceLock::new();
        LEDGER.get_or_init(|| {
            Mutex::new(Ledger {
                entries: HashMap::new(),
                last_cleanup: Instant::now(),
            })
        })
    }

    /// Record one rejection for `(peer_key, file_hash, start, end)` and return the
    /// in-window rejection count (1 on the first rejection, matching the oracle
    /// `SBadPeerBehaviorLedgerState::uCount` semantics).
    pub(super) fn record(peer_key: &str, file_hash: &str, start: u64, end: u64) -> u32 {
        let window = Duration::from_secs(REPEAT_BLOCK_WINDOW_SECS);
        let now = Instant::now();
        let mut ledger = match ledger().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if now.duration_since(ledger.last_cleanup) >= CLEANUP_INTERVAL {
            ledger.last_cleanup = now;
            ledger
                .entries
                .retain(|_, entry| now.duration_since(entry.last_seen) < window);
        }
        let key = (peer_key.to_string(), file_hash.to_string(), start, end);
        let expired = ledger
            .entries
            .get(&key)
            .is_some_and(|entry| now.duration_since(entry.last_seen) >= window);
        if expired {
            ledger.entries.remove(&key);
        }
        if let Some(entry) = ledger.entries.get_mut(&key) {
            entry.last_seen = now;
            entry.count = entry.count.saturating_add(1);
            return entry.count;
        }
        if ledger.entries.len() >= MAX_ENTRIES
            && let Some(oldest) = ledger
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.first_seen)
                .map(|(k, _)| k.clone())
        {
            ledger.entries.remove(&oldest);
        }
        ledger.entries.insert(
            key,
            Entry {
                first_seen: now,
                last_seen: now,
                count: 1,
            },
        );
        1
    }

    #[cfg(test)]
    pub(super) fn reset() {
        let mut ledger = match ledger().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        ledger.entries.clear();
        ledger.last_cleanup = Instant::now();
    }
}

/// The MFC bad-peer ledger peer key: the user hash when known (`hash:<md4>`),
/// else the source IP (`ip:<addr>`), matching `PeerBehaviorKey`. Kept internal to
/// the duplicate-block emitters so the `repeatCount` accumulates per identity the
/// same way the oracle does across reconnects.
fn behavior_peer_key(peer: &str, peer_hash: Option<[u8; 16]>) -> String {
    match peer_hash {
        Some(hash) => format!("hash:{}", hex::encode(hash)),
        None => format!("ip:{}", peer.rsplit_once(':').map_or(peer, |(ip, _)| ip)),
    }
}

/// `upload_duplicate_done_block_rejected`: a peer requested an upload block that is
/// already completed/served in its slot, so we reject the range instead of
/// re-serving it. Mirrors MFC `CUpDownClient::AddReqBlock` -> bad_peer
/// `upload_duplicate_done_block_rejected` (`action:"reject_block_request"`,
/// severity medium). `repeatCount`/`windowSeconds` come from the process-global
/// rejection ledger (see [`duplicate_block_ledger`]); the body carries NO
/// `behavior` key (the oracle adapter sets `behavior` only for the observe-only
/// `repeat_*` events — including it here would fail the rust-superset conformance
/// diff, the second cause of the RUST-FEAT-025 revert). `part_index` is
/// `start_offset / ED2K_PART_SIZE`, as MFC reports it.
pub(crate) fn upload_duplicate_done_block_rejected(
    peer: &str,
    peer_hash: Option<[u8; 16]>,
    file_hash: &str,
    start_offset: u64,
    end_offset: u64,
    part_index: u64,
) {
    let repeat_count = duplicate_block_ledger::record(
        &behavior_peer_key(peer, peer_hash),
        file_hash,
        start_offset,
        end_offset,
    );
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({
        "action": "reject_block_request",
        "reason": "Duplicate upload block request already completed in slot",
        "repeatCount": repeat_count,
        "windowSeconds": REPEAT_BLOCK_WINDOW_SECS,
        "startOffset": start_offset,
        "endOffset": end_offset,
        "partIndex": part_index,
    });
    emit(
        "bad_peer",
        "upload_duplicate_done_block_rejected",
        "medium",
        keys,
        body,
    );
}

/// `upload_duplicate_queued_block_rejected`: a peer re-requested an upload block
/// that is already QUEUED (pending) in its slot, so we reject the duplicate.
/// Mirrors MFC `CUpDownClient::AddReqBlock` -> bad_peer
/// `upload_duplicate_queued_block_rejected` (`action:"reject_block_request"`,
/// severity medium), the sibling of the done-block case above (the reverted
/// RUST-FEAT-025 mislabeled this queued branch as the done branch). Same
/// process-global rejection ledger, same no-`behavior` body shape.
pub(crate) fn upload_duplicate_queued_block_rejected(
    peer: &str,
    peer_hash: Option<[u8; 16]>,
    file_hash: &str,
    start_offset: u64,
    end_offset: u64,
    part_index: u64,
) {
    let repeat_count = duplicate_block_ledger::record(
        &behavior_peer_key(peer, peer_hash),
        file_hash,
        start_offset,
        end_offset,
    );
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({
        "action": "reject_block_request",
        "reason": "Duplicate upload block request already queued in slot",
        "repeatCount": repeat_count,
        "windowSeconds": REPEAT_BLOCK_WINDOW_SECS,
        "startOffset": start_offset,
        "endOffset": end_offset,
        "partIndex": part_index,
    });
    emit(
        "bad_peer",
        "upload_duplicate_queued_block_rejected",
        "medium",
        keys,
        body,
    );
}

/// `repeat_file_request`: the same peer (re)started an upload session for the same
/// file more than once within the observation window. Mirrors MFC
/// `TrackUploadFileBehavior` -> `repeat_file_request` (oracle `CUploadQueue`).
/// Observe-only: the upload proceeds; this only surfaces same-file churn (a peer
/// that keeps dropping and reconnecting for one file) so bad-peer traces line up.
pub(crate) fn repeat_file_request(
    peer: &str,
    peer_hash: Option<[u8; 16]>,
    file_hash: &str,
    repeat_count: u32,
) {
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({
        "action": "observe",
        "behavior": "repeat_file_request",
        "reason": "Repeated same-file upload churn",
        "repeatCount": repeat_count,
        "windowSeconds": REPEAT_FILE_WINDOW_SECS,
    });
    emit("bad_peer", "repeat_file_request", "medium", keys, body);
}

/// `download_first_payload_timeout`: a download source we requested parts from
/// sent no payload before the first-payload deadline elapsed (rust's
/// `part_response_deadline` expiring while `session_payload_down == 0`), so we
/// drop / requeue it. Mirrors MFC `CUpDownClient::CheckDownloadTimeout` -> bad_peer
/// `download_first_payload_timeout` (`action:"cancel_transfer"`, gated on
/// `GetSessionPayloadDown()==0` + idle >= `kDownloadFirstPayloadTimeoutMs`). This
/// is the download-side counterpart to the upload-path bad-peer events above;
/// `upload_keys` is reused only as the generic peer/peerHash/fileHash key builder.
pub(crate) fn download_first_payload_timeout(
    peer: &str,
    peer_hash: Option<[u8; 16]>,
    file_hash: &str,
) {
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({
        "action": "cancel_transfer",
        "reason": "First payload timeout",
    });
    emit(
        "bad_peer",
        "download_first_payload_timeout",
        "medium",
        keys,
        body,
    );
}

/// `download_idle_timeout`: a download source that HAD sent payload this session
/// then stalled past the part-response deadline (`session_payload_down > 0`), so we
/// drop / requeue it. Mirrors MFC `CUpDownClient::CheckDownloadTimeout` -> bad_peer
/// `download_idle_timeout` (`action:"cancel_transfer"`), the mid-transfer-stall
/// counterpart to `download_first_payload_timeout` (no payload at all).
pub(crate) fn download_idle_timeout(peer: &str, peer_hash: Option<[u8; 16]>, file_hash: &str) {
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({
        "action": "cancel_transfer",
        "reason": "Download idle timeout",
    });
    emit("bad_peer", "download_idle_timeout", "medium", keys, body);
}

/// `download_out_of_part_reqs`: a download source reported No Needed Parts for our
/// file (it sent `OP_OUTOFPARTREQS`). Mirrors MFC `CUpDownClient` -> bad_peer
/// `download_out_of_part_reqs` (severity `low`, `action:"state_on_queue"`). rust's
/// driver may A4AF-swap the source rather than drop it, matching the oracle's
/// on-queue disposition. (The oracle's escalated quarantine/cooldown variants for
/// repeated OP_OutOfPartReqs abuse are a separate anti-abuse detector rust lacks.)
pub(crate) fn download_out_of_part_reqs(peer: &str, peer_hash: Option<[u8; 16]>, file_hash: &str) {
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({
        "action": "state_on_queue",
        "reason": "Remote sent OP_OutOfPartReqs",
    });
    emit("bad_peer", "download_out_of_part_reqs", "low", keys, body);
}

/// `upload_no_request_recycle` / `upload_slow_rate_recycle`: an active upload slot
/// was reclaimed under sustained underfill — either it never uploaded
/// (`noRequestUnderfill`) or it uploaded below the slow-rate threshold
/// (`slowUnderfill`). Maps rust's underfill-recycle reason to the corresponding MFC
/// bad_peer recycle event (`action:"cooldown"`, MFC `CUploadQueue`). Timeout-based
/// recycles (waiting/granted/upload timeout) have no distinct MFC recycle event, and
/// rust does not split slow vs zero rate (the oracle's `upload_zero_rate_recycle` /
/// `upload_stalled_zero_rate_recycle` fold into `slowUnderfill`), so those are left
/// unemitted rather than mislabelled.
pub(crate) fn upload_recycle(
    peer: &str,
    peer_hash: Option<[u8; 16]>,
    file_hash: &str,
    recycle_reason: &str,
) {
    let event = match recycle_reason {
        "noRequestUnderfill" => "upload_no_request_recycle",
        "slowUnderfill" => "upload_slow_rate_recycle",
        _ => return,
    };
    let keys = upload_keys(peer, peer_hash, file_hash);
    let body = json!({
        "action": "cooldown",
        "reason": "Upload slot recycled under sustained underfill",
    });
    emit("bad_peer", event, "medium", keys, body);
}

#[cfg(test)]
mod tests {
    use super::{behavior_peer_key, duplicate_block_ledger};

    #[test]
    fn behavior_peer_key_prefers_user_hash_then_ip() {
        assert_eq!(
            behavior_peer_key("198.51.100.7:4662", Some([0xAB; 16])),
            format!("hash:{}", "ab".repeat(16))
        );
        // No hash yet: fall back to the source IP, dropping the ephemeral port
        // (MFC PeerBehaviorKey keys on IP, not IP:port).
        assert_eq!(
            behavior_peer_key("198.51.100.7:4662", None),
            "ip:198.51.100.7"
        );
    }

    #[test]
    fn rejection_ledger_counts_per_peer_block_and_starts_each_key_at_one() {
        duplicate_block_ledger::reset();
        let peer = "hash:aa";
        let file = "ffffffffffffffffffffffffffffffff";
        // Same (peer, file, block) accumulates: 1, 2, 3 (oracle uCount).
        assert_eq!(duplicate_block_ledger::record(peer, file, 0, 180_000), 1);
        assert_eq!(duplicate_block_ledger::record(peer, file, 0, 180_000), 2);
        assert_eq!(duplicate_block_ledger::record(peer, file, 0, 180_000), 3);
        // A different block for the same peer/file is an independent key.
        assert_eq!(
            duplicate_block_ledger::record(peer, file, 180_000, 360_000),
            1
        );
        // A different peer for the same block is an independent key.
        assert_eq!(
            duplicate_block_ledger::record("hash:bb", file, 0, 180_000),
            1
        );
        // A different file for the same peer/block is an independent key.
        assert_eq!(
            duplicate_block_ledger::record(peer, "00000000000000000000000000000000", 0, 180_000),
            1
        );
        duplicate_block_ledger::reset();
    }
}
