//! Upload session rotation caps (oracle `CheckForTimeOver`,
//! UploadQueue.cpp:2407-2467): a slot past its per-session transferred-bytes
//! cap (default 90% of the file, PreferenceValidationSeams.h:48) or wall-clock
//! time cap (default 7200 s, :53) recycles through the shared
//! OUTOFPARTREQS + requeue-at-tail path -- but only when a queued replacement
//! is available, and never while the underfilled line is being filled
//! productively by that slot (`ShouldRotateBroadbandLimitedUploadSession`,
//! UploadQueueSeams.h:677-685).

use std::time::{Duration, Instant};

use crate::ed2k_transfer::{
    Ed2kUploadQueueConfig, Ed2kUploadSessionHandle, Ed2kUploadSessionStatus,
    upload_queue::Ed2kUploadQueueState,
};

use super::upload_queue_support::upload_peer;

const FILE_HASH: &str = "00112233445566778899aabbccddeeff";

fn rotation_config() -> Ed2kUploadQueueConfig {
    Ed2kUploadQueueConfig {
        active_slots: 1,
        elastic_percent: 0,
        upload_limit_bytes_per_sec: 0,
        elastic_underfill_bytes_per_sec: 0,
        elastic_underfill: Duration::from_secs(10),
        waiting_capacity: 8,
        soft_queue_size: 10_000,
        // Long enough that no fixture waiter ages out below the 7200 s time cap.
        waiting_timeout: Duration::from_secs(100_000),
        granted_timeout: Duration::from_secs(30),
        upload_timeout: Duration::from_secs(3_600),
        session_transfer_percent: 90,
        session_time_limit: Duration::from_secs(7_200),
    }
}

fn begin(
    state: &mut Ed2kUploadQueueState,
    octet: u8,
    marker: u8,
    connection_id: u64,
    file_size: u64,
    now: Instant,
) -> (Ed2kUploadSessionHandle, Ed2kUploadSessionStatus) {
    let peer = upload_peer(octet, marker, 0x0A00_0000 + u32::from(octet));
    let handle = Ed2kUploadSessionHandle::new(peer, FILE_HASH.to_string(), connection_id);
    let status = state.begin_session(
        handle.key().clone(),
        connection_id,
        now,
        7,     // default file priority score
        1_000, // neutral credit ratio (permille)
        1_000, // all-time upload ratio at/above the low-ratio threshold
        file_size,
    );
    (handle, status)
}

#[test]
fn transfer_cap_rotates_only_when_a_replacement_waits() {
    let mut state = Ed2kUploadQueueState::new(rotation_config());
    let t0 = Instant::now();
    let (active, status) = begin(&mut state, 1, 0x21, 1, 1_000, t0);
    assert_eq!(status, Ed2kUploadSessionStatus::Granted);

    // 950 of 1000 bytes: past the 90% cap (ceil -> 900), but with no queued
    // replacement the slot is retained (oracle ForceNewClient gate).
    state.note_uploaded_bytes(&active, 950, t0 + Duration::from_secs(1));
    assert_eq!(
        state.poll_session(&active, t0 + Duration::from_secs(2), false),
        Ed2kUploadSessionStatus::Granted
    );

    // A queued replacement arrives: the capped slot rotates to it.
    let (waiter, waiter_status) = begin(&mut state, 2, 0x22, 2, 1_000, t0 + Duration::from_secs(3));
    assert_eq!(waiter_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
    assert_eq!(
        state.poll_session(&active, t0 + Duration::from_secs(4), false),
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
    assert_eq!(
        state.poll_session(&waiter, t0 + Duration::from_secs(4), false),
        Ed2kUploadSessionStatus::Granted
    );
}

#[test]
fn time_cap_rotates_only_when_a_replacement_waits() {
    let mut config = rotation_config();
    config.session_transfer_percent = 0; // isolate the time cap (no byte cap)
    // Isolate the wall-clock TIME cap from the slow-slot recycle: since
    // RUST-PAR-024 GAP-1 the per-slot datarate is a 10 s SLIDING WINDOW (oracle
    // GetUploadDatarate over m_AverageUDR_hist, UploadClient.cpp:860-878), NOT a
    // lifetime average, so a slot that bursts once then idles reads 0 B/s and would
    // be slow-recycled once past `upload_timeout`. That is a DIFFERENT mechanism
    // (CheckForTimeOver's rate path) from the time cap under test; push
    // `upload_timeout` far out so only the 7200 s time branch can rotate here, the
    // same way the no-request/cooldown fixtures neutralize unrelated gates.
    config.upload_timeout = Duration::from_secs(100_000);
    let mut state = Ed2kUploadQueueState::new(config);
    let t0 = Instant::now();
    let (active, status) = begin(&mut state, 1, 0x31, 1, 0, t0);
    assert_eq!(status, Ed2kUploadSessionStatus::Granted);
    // A single payload keeps `uploaded_bytes > 0` (cumulative, never decays), so the
    // holder is never caught by the 0-byte no-request recycle; the time cap alone
    // governs its rotation.
    state.note_uploaded_bytes(&active, 32 * 1024 * 1024, t0);
    let (waiter, waiter_status) = begin(&mut state, 2, 0x32, 2, 0, t0 + Duration::from_secs(5));
    assert_eq!(waiter_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    // Within the 7200 s session window the productive slot holds even with a waiter.
    assert_eq!(
        state.poll_session(&active, t0 + Duration::from_secs(7_199), false),
        Ed2kUploadSessionStatus::Granted
    );
    // Past it, the slot rotates to the waiter.
    assert_eq!(
        state.poll_session(&active, t0 + Duration::from_secs(7_201), false),
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
    assert_eq!(
        state.poll_session(&waiter, t0 + Duration::from_secs(7_201), false),
        Ed2kUploadSessionStatus::Granted
    );
}

#[test]
fn underfilled_line_retains_a_productive_capped_slot() {
    let mut config = rotation_config();
    config.upload_limit_bytes_per_sec = 100_000;
    config.elastic_underfill_bytes_per_sec = 10_000;
    let mut state = Ed2kUploadQueueState::new(config);
    let t0 = Instant::now();
    // 1 MB file: the 90% cap is 900_000 bytes.
    let (active, status) = begin(&mut state, 1, 0x41, 1, 1_000_000, t0);
    assert_eq!(status, Ed2kUploadSessionStatus::Granted);
    let (waiter, waiter_status) = begin(&mut state, 2, 0x42, 2, 1_000_000, t0);
    assert_eq!(waiter_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    // Sustain ~80 KB/s across the first 12 s (12 x 80 KB = 960 KB, past the 900 KB
    // cap). RUST-PAR-024 GAP-1: the per-slot productive rate is now the 10 s
    // SLIDING WINDOW (oracle GetUploadDatarate over m_AverageUDR_hist,
    // UploadClient.cpp:860-878), NOT a lifetime average, so the slot reads
    // "productive" only while it keeps feeding that window -- a single early burst
    // would read 0 B/s by +12 s.
    for second in 1..=12u64 {
        state.note_uploaded_bytes(&active, 80_000, t0 + Duration::from_secs(second));
    }

    // At +12 s the 10 s window holds ~88 KB/s (10 in-window samples over a ~9 s
    // span): above the productive bar (75% of the 100 KB/s single-slot target =
    // 75 KB/s) while the line is underfilled (aggregate ~87 KB/s, spare ~13 KB/s >=
    // the 10 KB/s margin) -> the capped slot is retained (oracle
    // ShouldRotateBroadbandLimitedUploadSession, UploadQueueSeams.h:683-684).
    assert_eq!(
        state.poll_session(&active, t0 + Duration::from_secs(12), false),
        Ed2kUploadSessionStatus::Granted
    );

    // +24 s, no feed since +12 s: the 10 s per-slot window has fully drained to
    // 0 B/s -- still underfilled (the 30 s aggregate window keeps ~42 KB/s) but no
    // longer productive -> the byte cap now rotates the slot to the waiter.
    assert_eq!(
        state.poll_session(&active, t0 + Duration::from_secs(24), false),
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
    assert_eq!(
        state.poll_session(&waiter, t0 + Duration::from_secs(24), false),
        Ed2kUploadSessionStatus::Granted
    );
}

#[test]
fn rotated_session_requeues_at_tail_with_fresh_wait_start() {
    let mut state = Ed2kUploadQueueState::new(rotation_config());
    let t0 = Instant::now();
    let (active, status) = begin(&mut state, 1, 0x51, 1, 1_000, t0);
    assert_eq!(status, Ed2kUploadSessionStatus::Granted);
    let (first_waiter, first_status) =
        begin(&mut state, 2, 0x52, 2, 1_000, t0 + Duration::from_secs(1));
    assert_eq!(first_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
    let (second_waiter, second_status) =
        begin(&mut state, 3, 0x53, 3, 1_000, t0 + Duration::from_secs(2));
    assert_eq!(second_status, Ed2kUploadSessionStatus::Waiting { rank: 2 });

    state.note_uploaded_bytes(&active, 950, t0 + Duration::from_secs(3));

    // Rotation: the longest-waiting peer takes the slot; the capped peer is
    // demoted BEHIND the remaining older waiter with a fresh wait start
    // (oracle SendOutOfPartReqsAndAddToWaitingQueue tail requeue,
    // UploadQueue.cpp:881-885).
    let t_rotate = t0 + Duration::from_secs(10);
    assert_eq!(
        state.poll_session(&active, t_rotate, false),
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );
    assert_eq!(
        state.poll_session(&first_waiter, t_rotate, false),
        Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        state.poll_session(&second_waiter, t_rotate, false),
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );

    // Fresh wait-start and cleared per-session upload counters.
    let snapshot = state.snapshot(t_rotate);
    let requeued = snapshot
        .iter()
        .find(|entry| entry.client_id == Some(0x0A00_0001))
        .expect("requeued session present in snapshot");
    assert_eq!(requeued.wait_time_ms, 0);
    assert_eq!(requeued.uploaded_bytes, 0);
}

/// REG-1: a BANNED client is refused at admission (master `AddClientToQueue`
/// `if (client->IsBanned()) return;`, UploadQueue.cpp:1854) — it never occupies
/// or is queued for a slot, so it can never reach the session-cap recycle at all.
/// The round-17 recycle-drop (bRequeue=false, UploadQueue.cpp:2320-2321) remains
/// in `reap_expired_sessions` as the defensive later gate for a session banned
/// after admission.
#[test]
fn banned_peer_is_refused_at_admission_before_any_slot() {
    let mut state = Ed2kUploadQueueState::new(rotation_config());
    let t0 = Instant::now();
    let mut banned_peer = upload_peer(1, 0x61, 0x0A00_0001);
    banned_peer.banned = true;
    let handle = Ed2kUploadSessionHandle::new(banned_peer, FILE_HASH.to_string(), 1);
    let status = state.begin_session(handle.key().clone(), 1, t0, 7, 1_000, 1_000, 1_000);
    assert_eq!(status, Ed2kUploadSessionStatus::Rejected);

    // The banned peer created no queue entry, so the free slot goes straight to
    // the next (clean) waiter at admission.
    let (_waiter, waiter_status) =
        begin(&mut state, 2, 0x62, 2, 1_000, t0 + Duration::from_secs(2));
    assert_eq!(waiter_status, Ed2kUploadSessionStatus::Granted);
}

#[test]
fn friend_slot_is_exempt_from_session_caps() {
    let mut state = Ed2kUploadQueueState::new(rotation_config());
    let t0 = Instant::now();
    let mut friend = upload_peer(1, 0x71, 0x0A00_0001);
    friend.friend_slot = true;
    let handle = Ed2kUploadSessionHandle::new(friend, FILE_HASH.to_string(), 1);
    let status = state.begin_session(handle.key().clone(), 1, t0, 7, 1_000, 1_000, 1_000);
    assert_eq!(status, Ed2kUploadSessionStatus::Granted);
    state.note_uploaded_bytes(&handle, 950, t0 + Duration::from_secs(1));
    let (_waiter, waiter_status) =
        begin(&mut state, 2, 0x72, 2, 1_000, t0 + Duration::from_secs(2));
    assert_eq!(waiter_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    // Friend slots never rotate on the session caps (oracle CheckForTimeOver
    // early return, UploadQueue.cpp:2303-2304).
    assert_eq!(
        state.poll_session(&handle, t0 + Duration::from_secs(7_300), false),
        Ed2kUploadSessionStatus::Granted
    );
}
