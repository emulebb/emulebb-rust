//! Upload slot-open pacing (RUST-PAR-020 U-GAP1 + RUST-PAR-021 GAP1): below
//! 100 KB/s aggregate upload datarate the fork opens at most ONE new upload slot
//! per second (oracle `CUploadQueue::Process` opens one client per tick via
//! `ForceNewClient`, UploadQueue.cpp:821-823, gated by `curTick <
//! m_nLastStartUpload + SEC2MS(1) && datarate < 102400`, UploadQueue.cpp:972).
//! At/above 100 KB/s the pipe is already busy and the 1/sec gate is bypassed, so
//! a backlog may burst open. RUST-PAR-021 GAP1 extends the pace to the inline
//! grant of a just-connecting peer: it may open a free slot only when the pace
//! allows a new open AND it is the best-admissible candidate, so an arrival never
//! opens a pace-deferred slot early nor jumps a higher-ranked waiter.

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

/// Below `MIN_UP_CLIENTS_ALLOWED` (2) the base slots open immediately; beyond it
/// the inline grant is paced 1/sec (RUST-PAR-021 GAP1), so filling five base
/// slots on an idle line takes three seconds, not one instant.
#[test]
fn inline_grant_is_paced_beyond_min_up_clients() {
    let mut state = Ed2kUploadQueueState::new(pacing_config());
    let t0 = Instant::now();
    // The first two connects open immediately (base fill below MIN_UP_CLIENTS).
    let (_p1, s1) = begin(&mut state, 1, t0);
    let (_p2, s2) = begin(&mut state, 2, t0);
    assert_eq!(s1, Ed2kUploadSessionStatus::Granted);
    assert_eq!(s2, Ed2kUploadSessionStatus::Granted);
    // The third connect finds a free slot but the pace defers it: it waits.
    let (p3, s3) = begin(&mut state, 3, t0);
    assert!(
        matches!(s3, Ed2kUploadSessionStatus::Waiting { .. }),
        "third slot must be paced, got {s3:?}"
    );
    // +1 s: the pace has elapsed, so the deferred slot now opens.
    assert_eq!(
        state.poll_session(&p3, t0 + Duration::from_secs(1), false),
        Ed2kUploadSessionStatus::Granted
    );
}

/// Fill all five base slots and queue three extra waiters. Because the inline
/// grant is now paced, the base fill spans three seconds (two immediate, three
/// paced 1/sec); the returned instant is when all five slots are active.
fn fill_slots_and_backlog(
    state: &mut Ed2kUploadQueueState,
    t0: Instant,
) -> (Vec<Ed2kUploadSessionHandle>, Instant) {
    let mut handles = Vec::new();
    // Slots 1-2 open immediately (below MIN_UP_CLIENTS_ALLOWED).
    for octet in 1..=2u8 {
        let (handle, status) = begin(state, octet, t0);
        assert_eq!(status, Ed2kUploadSessionStatus::Granted, "slot {octet}");
        handles.push(handle);
    }
    // Slots 3-5 connect now but are pace-deferred to the waiting queue.
    for octet in 3..=5u8 {
        let (handle, status) = begin(state, octet, t0);
        assert!(
            matches!(status, Ed2kUploadSessionStatus::Waiting { .. }),
            "paced slot {octet}: {status:?}"
        );
        handles.push(handle);
    }
    // A poll one second apart opens each pace-deferred base slot in turn.
    for (index, octet) in (3..=5u8).enumerate() {
        let at = t0 + Duration::from_secs(1 + index as u64);
        assert_eq!(
            state.poll_session(&handles[usize::from(octet) - 1], at, false),
            Ed2kUploadSessionStatus::Granted,
            "paced open of slot {octet}"
        );
    }
    let t_base = t0 + Duration::from_secs(3);
    // Three extra waiters queue behind the now-full base.
    for octet in 6..=8u8 {
        let (handle, status) = begin(state, octet, t_base);
        assert!(
            matches!(status, Ed2kUploadSessionStatus::Waiting { .. }),
            "waiter {octet}: {status:?}"
        );
        handles.push(handle);
    }
    (handles, t_base)
}

/// Below 100 KB/s: three slots freed at once refill one per second, never all in
/// a single pass.
#[test]
fn slow_line_opens_at_most_one_slot_per_second() {
    let mut state = Ed2kUploadQueueState::new(pacing_config());
    let t0 = Instant::now();
    let (handles, t_base) = fill_slots_and_backlog(&mut state, t0);
    let (w6, w7, w8) = (&handles[5], &handles[6], &handles[7]);

    // Free three base slots at t_base. The last base open stamped the pacing
    // clock at t_base, so the promote triggered by each release is blocked
    // (< 1 s elapsed, datarate 0): all three slots stay open, the waiters wait.
    for handle in &handles[0..3] {
        state.release_session(handle, t_base);
    }
    assert!(matches!(
        state.poll_session(w6, t_base, false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));
    assert!(matches!(
        state.poll_session(w7, t_base, false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));
    assert!(matches!(
        state.poll_session(w8, t_base, false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));

    // +1 s: exactly one slot opens (the best waiter); the other two are deferred.
    assert_eq!(
        state.poll_session(w6, t_base + Duration::from_secs(1), false),
        Ed2kUploadSessionStatus::Granted
    );
    assert!(matches!(
        state.poll_session(w7, t_base + Duration::from_secs(1), false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));
    assert!(matches!(
        state.poll_session(w8, t_base + Duration::from_secs(1), false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));

    // +2 s: the next slot opens.
    assert_eq!(
        state.poll_session(w7, t_base + Duration::from_secs(2), false),
        Ed2kUploadSessionStatus::Granted
    );
    assert!(matches!(
        state.poll_session(w8, t_base + Duration::from_secs(2), false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));

    // +3 s: the last waiter takes the final freed slot.
    assert_eq!(
        state.poll_session(w8, t_base + Duration::from_secs(3), false),
        Ed2kUploadSessionStatus::Granted
    );
}

/// At/above 100 KB/s: the 1/sec gate is bypassed, so three slots freed at once
/// all refill in a single promote pass.
#[test]
fn busy_line_bursts_all_freed_slots_in_one_pass() {
    let mut state = Ed2kUploadQueueState::new(pacing_config());
    let t0 = Instant::now();
    let (handles, t_base) = fill_slots_and_backlog(&mut state, t0);
    let (a4, w6, w7, w8) = (&handles[3], &handles[5], &handles[6], &handles[7]);

    // Drive one surviving active slot well above the 100 KB/s busy-pipe
    // threshold: 500 KB starting at t_base reads as 250 KB/s by t_base+2s.
    state.note_uploaded_bytes(a4, 500_000, t_base);

    // Free three base slots at t_base (datarate still 0 at t_base, elapsed 0): the
    // releases are paced off, so all three stay open with three waiters queued.
    for handle in &handles[0..3] {
        state.release_session(handle, t_base);
    }
    assert!(matches!(
        state.poll_session(w6, t_base, false),
        Ed2kUploadSessionStatus::Waiting { .. }
    ));

    // +2 s: the aggregate datarate is now ~250 KB/s, so a single promote pass
    // bursts open all three freed slots.
    assert_eq!(
        state.poll_session(w6, t_base + Duration::from_secs(2), false),
        Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        state.poll_session(w7, t_base + Duration::from_secs(2), false),
        Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        state.poll_session(w8, t_base + Duration::from_secs(2), false),
        Ed2kUploadSessionStatus::Granted
    );
}

/// Three base slots, two filled immediately. A higher-ranked (earlier) waiter
/// holds the pace-deferred third slot; when a lower-ranked newcomer connects it
/// must NOT inline-grant ahead of the queued waiter (RUST-PAR-021 GAP1 effect
/// (b)) -- the free slot goes to the best waiter via the paced promote.
#[test]
fn lower_ranked_newcomer_does_not_jump_higher_ranked_waiter() {
    let mut config = pacing_config();
    config.active_slots = 3;
    let mut state = Ed2kUploadQueueState::new(config);
    let t0 = Instant::now();

    let (_p1, s1) = begin(&mut state, 1, t0);
    let (_p2, s2) = begin(&mut state, 2, t0);
    assert_eq!(s1, Ed2kUploadSessionStatus::Granted);
    assert_eq!(s2, Ed2kUploadSessionStatus::Granted);

    // The earlier-queued waiter H holds the pace-deferred third slot.
    let (h, h_status) = begin(&mut state, 3, t0);
    assert_eq!(h_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    // A newcomer L connects 1.5 s later: the pace now allows a new open, but H
    // outranks L, so L must not jump. Admitting L runs the paced promote, which
    // hands the free slot to H (the best candidate), leaving L queued at rank 1.
    let (l, l_status) = begin(&mut state, 4, t0 + Duration::from_millis(1_500));
    assert_eq!(
        l_status,
        Ed2kUploadSessionStatus::Waiting { rank: 1 },
        "newcomer must not jump the higher-ranked waiter"
    );
    assert_eq!(
        state.poll_session(&h, t0 + Duration::from_millis(1_500), false),
        Ed2kUploadSessionStatus::Granted,
        "the free slot must go to the higher-ranked waiter"
    );
    assert!(matches!(
        state.poll_session(&l, t0 + Duration::from_millis(1_500), false),
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    ));
}

/// A re-ask from an existing waiter re-attaches to its persisted queue entry and
/// keeps its real rank (oracle `AddClientToQueue` `cur_client == client` ->
/// `SendRankingInfo`, UploadQueue.cpp:1865-1868): it is NOT treated as a
/// brand-new inline grant that jumps the queue.
#[test]
fn reasking_waiter_keeps_its_rank() {
    let mut config = pacing_config();
    config.active_slots = 1;
    let mut state = Ed2kUploadQueueState::new(config);
    let t0 = Instant::now();

    let (_active, active_status) = begin(&mut state, 1, t0);
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    let (first, first_status) = begin(&mut state, 2, t0);
    assert_eq!(first_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
    let (_second, second_status) = begin(&mut state, 3, t0);
    assert_eq!(second_status, Ed2kUploadSessionStatus::Waiting { rank: 2 });

    // The rank-1 waiter re-asks 5 s later: it keeps rank 1 (its wait-start and
    // sequence survive) and is not promoted ahead of the still-active slot.
    let (_first_again, reask_status) = begin(&mut state, 2, t0 + Duration::from_secs(5));
    assert_eq!(
        reask_status,
        Ed2kUploadSessionStatus::Waiting { rank: 1 },
        "a re-asking waiter keeps its rank, not a fresh tail position"
    );
    assert!(matches!(
        state.poll_session(&first, t0 + Duration::from_secs(5), false),
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    ));
}
