//! Slow/idle upload-slot recycle window (RUST-PAR-020 U-GAP2): the fork tracks
//! TWO sustained-underfill windows off the same underfill-since clock -- a 2 s
//! window that gates slow/idle active-slot RECYCLING
//! (`HasSustainedBroadbandUnderfill`, UploadQueue.cpp:1047-1050, via
//! `ShouldTrackSlowUploadSlots`, :1114) and a 10 s window that gates elastic slot
//! OPENING (`HasSustainedElasticBroadbandUnderfill`, UploadQueue.cpp:1052-1055,
//! via `AcceptNewClient`). The recycle window must be 2 s while elastic opening
//! keeps the config-driven 10 s window.

use std::time::{Duration, Instant};

use crate::ed2k_transfer::{
    Ed2kUploadQueueConfig, Ed2kUploadSessionHandle, Ed2kUploadSessionStatus,
    upload_queue::Ed2kUploadQueueState,
};

use super::upload_queue_support::upload_peer;

const FILE_HASH: &str = "00112233445566778899aabbccddeeff";

/// One base slot with elastic room, an underfilled 100 KB/s budget, and a 10 s
/// elastic-open window. `granted_timeout` is 1 s so the idle-recycle test can
/// isolate the 2 s underfill window from the grant-idle timer.
fn recycle_window_config() -> Ed2kUploadQueueConfig {
    Ed2kUploadQueueConfig {
        active_slots: 1,
        elastic_percent: 100,
        upload_limit_bytes_per_sec: 100 * 1024,
        elastic_underfill_bytes_per_sec: 50 * 1024,
        elastic_underfill: Duration::from_secs(10),
        waiting_capacity: 8,
        soft_queue_size: 10_000,
        waiting_timeout: Duration::from_secs(100_000),
        granted_timeout: Duration::from_secs(1),
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

/// A slow/idle active slot is recycled once the underfill has been sustained for
/// 2 s -- NOT the 10 s elastic-open window.
#[test]
fn idle_active_slot_recycles_after_two_seconds_underfill() {
    let mut state = Ed2kUploadQueueState::new(recycle_window_config());
    let t0 = Instant::now();
    let (active, active_status) = begin(&mut state, 1, t0);
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    let (waiter, waiter_status) = begin(&mut state, 2, t0);
    assert!(matches!(
        waiter_status,
        Ed2kUploadSessionStatus::Waiting { .. }
    ));

    // +1.5 s: the grant-idle timer (1 s) has elapsed, but the 2 s sustained-
    // underfill window has NOT, so the idle slot is retained.
    assert_eq!(
        state.poll_session(&active, t0 + Duration::from_millis(1_500), false),
        Ed2kUploadSessionStatus::Granted
    );

    // +3 s: the 2 s underfill window is sustained, so the idle slot is recycled
    // (demoted to the waiting queue) and the waiter takes the freed slot -- well
    // before the 10 s elastic-open window.
    assert!(matches!(
        state.poll_session(&active, t0 + Duration::from_secs(3), false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));
    assert_eq!(
        state.poll_session(&waiter, t0 + Duration::from_secs(3), false),
        Ed2kUploadSessionStatus::Granted
    );
}

/// Elastic slot OPENING still waits the full 10 s window: a productive base slot
/// that holds its slot does not let a waiter in via an elastic slot at 2 s.
#[test]
fn elastic_slot_opening_still_waits_ten_seconds() {
    let mut state = Ed2kUploadQueueState::new(recycle_window_config());
    let t0 = Instant::now();
    let (active, active_status) = begin(&mut state, 1, t0);
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    // Mark the base slot productive so it is never eligible for the slow/idle
    // recycle (uploaded_bytes > 0, and upload_timeout is far out): the only way
    // the waiter can activate is a NEWLY OPENED elastic slot.
    state.note_uploaded_bytes(&active, 1, t0);
    let (waiter, waiter_status) = begin(&mut state, 2, t0);
    assert!(matches!(
        waiter_status,
        Ed2kUploadSessionStatus::Waiting { .. }
    ));

    // +3 s: past the 2 s recycle window but well short of the 10 s elastic-open
    // window -> no elastic slot opens, the waiter stays queued.
    assert!(matches!(
        state.poll_session(&waiter, t0 + Duration::from_secs(3), false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));

    // +11 s: the 10 s elastic-open window is sustained -> the elastic slot opens
    // and the waiter is granted while the base slot keeps uploading.
    assert_eq!(
        state.poll_session(&waiter, t0 + Duration::from_secs(11), false),
        Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        state.poll_session(&active, t0 + Duration::from_secs(11), false),
        Ed2kUploadSessionStatus::Granted
    );
}

/// RUST-PAR-024 GAP-1: a slot that uploaded a fast BURST and then stalls is
/// slow-recycled once its per-slot datarate meter decays below the slow bar --
/// which now happens within the 10 s window (oracle `GetUploadDatarate` over the
/// 10 s `m_AverageUDR_hist`, UploadClient.cpp:860-878). Under the OLD lifetime
/// cumulative average the same slot read `bytes / elapsed` ~= 1 MB/s forever and
/// would never fall under the slow bar, holding the slot for thousands of seconds.
#[test]
fn burst_then_stall_slot_is_slow_recycled_within_the_ten_second_window() {
    // Unlimited upload so the recycle signal is pure slot scarcity (no aggregate-
    // budget underfill gate), a short 5 s upload timeout so the slow branch is
    // reachable quickly, and a far-out granted-idle timer so ONLY the slow-rate
    // path (not the 0-byte no-request path) can recycle this productive slot.
    let config = Ed2kUploadQueueConfig {
        active_slots: 1,
        elastic_percent: 0,
        upload_limit_bytes_per_sec: 0,
        elastic_underfill_bytes_per_sec: 0,
        elastic_underfill: Duration::from_secs(10),
        waiting_capacity: 8,
        soft_queue_size: 10_000,
        waiting_timeout: Duration::from_secs(100_000),
        granted_timeout: Duration::from_secs(100_000),
        upload_timeout: Duration::from_secs(5),
        session_transfer_percent: 0,
        session_time_limit: Duration::ZERO,
    };
    let mut state = Ed2kUploadQueueState::new(config);
    let t0 = Instant::now();
    let (active, active_status) = begin(&mut state, 1, t0);
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    let (waiter, waiter_status) = begin(&mut state, 2, t0);
    assert!(matches!(
        waiter_status,
        Ed2kUploadSessionStatus::Waiting { .. }
    ));

    // A 10 MB burst at t0, then silence.
    state.note_uploaded_bytes(&active, 10 * 1024 * 1024, t0);

    // +6 s: past the 5 s upload timeout, but the burst is still inside the 10 s
    // per-slot window, so the datarate reads ~1.7 MB/s -- far above the 1 KiB/s
    // slow bar -> the productive slot is RETAINED.
    assert_eq!(
        state.poll_session(&active, t0 + Duration::from_secs(6), false),
        Ed2kUploadSessionStatus::Granted
    );

    // +11 s: the burst has aged out of the 10 s window, so the per-slot datarate
    // has decayed to 0 B/s (the lifetime meter would still read ~950 KB/s). Now
    // below the slow bar and past the upload timeout -> the slot is slow-recycled
    // and the waiter takes the freed slot.
    assert!(matches!(
        state.poll_session(&active, t0 + Duration::from_secs(11), false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));
    assert_eq!(
        state.poll_session(&waiter, t0 + Duration::from_secs(11), false),
        Ed2kUploadSessionStatus::Granted
    );
}
