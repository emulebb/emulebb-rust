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
    emit("bad_peer", "download_first_payload_timeout", "medium", keys, body);
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
