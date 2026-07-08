//! Upload slot-open pacing (RUST-PAR-020 U-GAP1): below 100 KB/s aggregate
//! upload datarate the fork opens at most ONE new upload slot per second (oracle
//! `CUploadQueue::Process` opens one client per tick via `ForceNewClient`,
//! UploadQueue.cpp:821-823, gated by `curTick < m_nLastStartUpload + SEC2MS(1) &&
//! datarate < 102400`, UploadQueue.cpp:972). At/above 100 KB/s the pipe is
//! already busy and the 1/sec gate is bypassed, so a backlog may burst open.

use std::time::{Duration, Instant};

use crate::ed2k_transfer::{
    Ed2kUploadQueueConfig, Ed2kUploadSessionHandle, Ed2kUploadSessionStatus,
    upload_queue::Ed2kUploadQueueState,
};

use super::upload_queue_support::upload_peer;

const FILE_HASH: &str = "00112233445566778899aabbccddeeff";

/// Five base slots so the pacing gate (which only bites once the base fills past
/// `MIN_UP_CLIENTS_ALLOWED` = 2) is exercised, with every session/idle/recycle
/// timer pushed far out so only the slot-open pacing decides promotions.
fn pacing_config() -> Ed2kUploadQueueConfig {
    Ed2kUploadQueueConfig {
        active_slots: 5,
        elastic_percent: 0,
        upload_limit_bytes_per_sec: 0,
        elastic_underfill_bytes_per_sec: 0,
        elastic_underfill: Duration::from_secs(10),
        waiting_capacity: 32,
        soft_queue_size: 10_000,
        waiting_timeout: Duration::from_secs(100_000),
        granted_timeout: Duration::from_secs(100_000),
        upload_timeout: Duration::from_secs(100_000),
        session_transfer_percent: 0,
        session_time_limit: Duration::ZERO,
    }
}

fn begin(
    state: &mut Ed2kUploadQueueState,
    octet: u8,
    now: Instant,
) -> (Ed2kUploadSessionHandle, Ed2kUploadSessionStatus) {
    let connection_id = u64::from(octet);
    let peer = upload_peer(octet, octet, 0x0A00_0000 + u32::from(octet));
    let handle = Ed2kUploadSessionHandle::new(peer, FILE_HASH.to_string(), connection_id);
    let status = state.begin_session(
        handle.key().clone(),
        connection_id,
        now,
        7,     // default file priority score
        1_000, // neutral credit ratio (permille)
        1_000, // all-time upload ratio at/above the low-ratio threshold
        0,     // file size (unknown; session caps disabled in this fixture)
    );
    (handle, status)
}

/// Fill all five base slots and queue three extra waiters. The inline grants are
/// not paced (a single connect opens exactly one slot), so all five start active.
fn fill_slots_and_backlog(
    state: &mut Ed2kUploadQueueState,
    now: Instant,
) -> Vec<Ed2kUploadSessionHandle> {
    let mut handles = Vec::new();
    for octet in 1..=5u8 {
        let (handle, status) = begin(state, octet, now);
        assert_eq!(status, Ed2kUploadSessionStatus::Granted, "slot {octet}");
        handles.push(handle);
    }
    for octet in 6..=8u8 {
        let (handle, status) = begin(state, octet, now);
        assert!(
            matches!(status, Ed2kUploadSessionStatus::Waiting { .. }),
            "waiter {octet}: {status:?}"
        );
        handles.push(handle);
    }
    handles
}

/// Below 100 KB/s: three slots freed at once refill one per second, never all in
/// a single pass.
#[test]
fn slow_line_opens_at_most_one_slot_per_second() {
    let mut state = Ed2kUploadQueueState::new(pacing_config());
    let t0 = Instant::now();
    let handles = fill_slots_and_backlog(&mut state, t0);
    let (w6, w7, w8) = (&handles[5], &handles[6], &handles[7]);

    // Free three base slots at t0. The inline grants stamped the pacing clock at
    // t0, so the promote triggered by each release is blocked (< 1 s elapsed,
    // datarate 0): all three slots stay open and all three waiters keep waiting.
    for handle in &handles[0..3] {
        state.release_session(handle, t0);
    }
    assert!(matches!(
        state.poll_session(w6, t0, false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));
    assert!(matches!(
        state.poll_session(w7, t0, false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));
    assert!(matches!(
        state.poll_session(w8, t0, false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));

    // +1 s: exactly one slot opens (the best waiter); the other two are deferred.
    assert_eq!(
        state.poll_session(w6, t0 + Duration::from_secs(1), false),
        Ed2kUploadSessionStatus::Granted
    );
    assert!(matches!(
        state.poll_session(w7, t0 + Duration::from_secs(1), false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));
    assert!(matches!(
        state.poll_session(w8, t0 + Duration::from_secs(1), false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));

    // +2 s: the next slot opens.
    assert_eq!(
        state.poll_session(w7, t0 + Duration::from_secs(2), false),
        Ed2kUploadSessionStatus::Granted
    );
    assert!(matches!(
        state.poll_session(w8, t0 + Duration::from_secs(2), false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));

    // +3 s: the last waiter takes the final freed slot.
    assert_eq!(
        state.poll_session(w8, t0 + Duration::from_secs(3), false),
        Ed2kUploadSessionStatus::Granted
    );
}

/// At/above 100 KB/s: the 1/sec gate is bypassed, so three slots freed at once
/// all refill in a single promote pass.
#[test]
fn busy_line_bursts_all_freed_slots_in_one_pass() {
    let mut state = Ed2kUploadQueueState::new(pacing_config());
    let t0 = Instant::now();
    let handles = fill_slots_and_backlog(&mut state, t0);
    let (a4, w6, w7, w8) = (&handles[3], &handles[5], &handles[6], &handles[7]);

    // Drive one surviving active slot well above the 100 KB/s busy-pipe
    // threshold: 500 KB starting at t0 reads as 250 KB/s by t0+2s.
    state.note_uploaded_bytes(a4, 500_000, t0);

    // Free three base slots at t0 (datarate still 0 at t0, elapsed 0): the
    // releases are paced off, so all three stay open with three waiters queued.
    for handle in &handles[0..3] {
        state.release_session(handle, t0);
    }
    assert!(matches!(
        state.poll_session(w6, t0, false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));

    // +2 s: the aggregate datarate is now ~250 KB/s, so a single promote pass
    // bursts open all three freed slots.
    assert_eq!(
        state.poll_session(w6, t0 + Duration::from_secs(2), false),
        Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        state.poll_session(w7, t0 + Duration::from_secs(2), false),
        Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        state.poll_session(w8, t0 + Duration::from_secs(2), false),
        Ed2kUploadSessionStatus::Granted
    );
}
