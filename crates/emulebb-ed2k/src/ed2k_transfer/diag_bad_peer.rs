//! `family:"bad_peer"` `diag_event_v1` emitters for the inbound upload path.
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
