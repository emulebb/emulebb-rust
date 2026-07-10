//! RUST-PAR-021 Upload-GAP6: the slot-scarcity anti-abuse must stay live under
//! UNLIMITED upload (`upload_limit_bytes_per_sec == 0`). The oracle always
//! derives slot control from a finite `GetConfiguredUploadBudgetBytesPerSec`
//! (UploadQueue.cpp:981-986) so its no-request/idle recycle is always active;
//! this fork has an unlimited mode where the byte-budget underfill can never be
//! computed. The faithful behaviour is to treat infinite bandwidth as
//! permanently underfilled and key the recycle/strike/cooldown/ban on the finite
//! SLOT count: an idle no-request holder that denies a waiter a slot is still
//! recycled + struck + cooled + banned. A productive uploader is untouched, and
//! the bandwidth-limited window (covered by `upload_slot_recycle_window` and
//! `upload_cooldown`) is unchanged.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::ban_store::BanStore;
use crate::ed2k_transfer::{
    Ed2kUploadPeerIdentity, Ed2kUploadQueueConfig, Ed2kUploadSessionHandle,
    Ed2kUploadSessionStatus, upload_queue::Ed2kUploadQueueState,
};

use super::upload_queue_support::upload_peer;

const FILE_HASH: &str = "00112233445566778899aabbccddeeff";

/// One base slot, UNLIMITED upload (`upload_limit_bytes_per_sec == 0`), a 1 s
/// granted-idle timer, and disabled session caps: the minimal fixture that drives
/// the no-request recycle under unlimited bandwidth. There is no configured
/// budget, so the recycle keys purely on slot occupancy + waiter presence.
fn unlimited_config() -> Ed2kUploadQueueConfig {
    Ed2kUploadQueueConfig {
        active_slots: 1,
        elastic_percent: 0,
        upload_limit_bytes_per_sec: 0,
        elastic_underfill_bytes_per_sec: 0,
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
    peer: Ed2kUploadPeerIdentity,
    connection_id: u64,
    now: Instant,
) -> (Ed2kUploadSessionHandle, Ed2kUploadSessionStatus) {
    let handle = Ed2kUploadSessionHandle::new(peer, FILE_HASH.to_string(), connection_id);
    let status = state.begin_session(
        handle.key().clone(),
        connection_id,
        now,
        7,     // default file priority score
        1_000, // neutral credit ratio (permille)
        1_000, // all-time upload ratio at/above the low-ratio threshold
        0,     // file size unknown (session caps disabled)
    );
    (handle, status)
}

fn is_waiting(status: Ed2kUploadSessionStatus) -> bool {
    matches!(status, Ed2kUploadSessionStatus::Waiting { .. })
}

/// Under UNLIMITED upload, a no-request slot-holder that denies a waiter its slot
/// is still recycled AND its IP cooled: the anti-abuse is no longer inert just
/// because there is no bandwidth-underfill signal to compute. The recycled peer
/// is demoted, the waiter promoted, and a fresh non-cooled waiter is then
/// preferred over the recycled (cooled) peer -- proving both the recycle and the
/// strike/cooldown fired.
#[test]
fn unlimited_no_request_slot_is_recycled_and_cooled_when_a_waiter_is_denied() {
    let mut state = Ed2kUploadQueueState::new(unlimited_config());
    let t0 = Instant::now();

    let (a, a_status) = begin(&mut state, upload_peer(1, 1, 0x0A00_0001), 1, t0);
    assert_eq!(a_status, Ed2kUploadSessionStatus::Granted);
    let (b, b_status) = begin(&mut state, upload_peer(2, 2, 0x0A00_0002), 2, t0);
    assert!(is_waiting(b_status));

    // +3 s: past the 1 s granted-idle timer. With no budget the recycle signal is
    // slot scarcity (A holds the only slot, B is waiting), so A (0 bytes served)
    // is recycled and B takes the freed slot. A's IP is now cooled.
    let t3 = t0 + Duration::from_secs(3);
    assert!(
        is_waiting(state.poll_session(&a, t3, false)),
        "an idle no-request holder must be recycled under unlimited upload"
    );
    assert_eq!(
        state.poll_session(&b, t3, false),
        Ed2kUploadSessionStatus::Granted
    );

    // A fresh, non-cooled waiter C behind the full slot.
    let (c, c_status) = begin(&mut state, upload_peer(3, 3, 0x0A00_0003), 3, t3);
    assert!(is_waiting(c_status));

    // Free the slot: the non-cooled C is promoted, the cooled A is skipped --
    // confirming the recycle seeded a cooldown, not just a bare demotion.
    let t3b = t3 + Duration::from_millis(500);
    state.release_session(&b, t3b);
    assert_eq!(
        state.poll_session(&c, t3b, false),
        Ed2kUploadSessionStatus::Granted
    );
    assert!(
        is_waiting(state.poll_session(&a, t3b, false)),
        "the recycled peer's IP must be cooled under unlimited upload"
    );

    // Past A's 30 s standard cooldown (seeded at +3 s) A is promotable again.
    let t34 = t0 + Duration::from_secs(34);
    state.release_session(&c, t34);
    assert_eq!(
        state.poll_session(&a, t34, false),
        Ed2kUploadSessionStatus::Granted
    );
}

/// Under UNLIMITED upload, a PRODUCTIVE uploader that keeps serving payload is NOT
/// recycled or penalised: the slow path only fires past the upload timeout with a
/// sub-threshold rate, and a busy uploader trips neither. The waiter stays queued
/// behind the productive base slot.
#[test]
fn unlimited_productive_uploader_is_not_penalized() {
    let mut state = Ed2kUploadQueueState::new(unlimited_config());
    let t0 = Instant::now();

    let (a, a_status) = begin(&mut state, upload_peer(1, 1, 0x0A00_0001), 1, t0);
    assert_eq!(a_status, Ed2kUploadSessionStatus::Granted);
    // A serves payload (productive, upload-started clock set).
    state.note_uploaded_bytes(&a, 512 * 1024, t0);
    let (b, b_status) = begin(&mut state, upload_peer(2, 2, 0x0A00_0002), 2, t0);
    assert!(is_waiting(b_status));

    // +3 s: well past the granted-idle timer, but A is productive and inside its
    // (100000 s) upload timeout, so it is retained -- the waiter stays queued.
    let t3 = t0 + Duration::from_secs(3);
    assert_eq!(
        state.poll_session(&a, t3, false),
        Ed2kUploadSessionStatus::Granted,
        "a productive uploader must not be recycled under unlimited upload"
    );
    assert!(is_waiting(state.poll_session(&b, t3, false)));
}

/// Under UNLIMITED upload the full repeat-offender apparatus is live: eight
/// no-request recycles of the same peer within the 4 h window ban it by user hash
/// via the shared `BanStore` (standard threshold 8 -- a 0 budget is below the
/// 4 MiB/s broadband threshold, so the standard tier applies). Two peers alternate
/// through the single slot; each recycle re-promotes the other via the cooldown
/// probe, so the target accrues its eight strikes.
#[test]
fn unlimited_eight_no_request_strikes_ban_the_peer() {
    let mut state = Ed2kUploadQueueState::new(unlimited_config());
    let ban_store = Arc::new(BanStore::new());
    state.set_ban_store(Arc::clone(&ban_store));
    let t0 = Instant::now();

    let hash_a = [0xAAu8; 16];
    let mut peer_a = upload_peer(1, 1, 0x0A00_0001);
    peer_a.user_hash = Some(hash_a);
    let mut peer_b = upload_peer(2, 2, 0x0A00_0002);
    peer_b.user_hash = Some([0xBBu8; 16]);

    let (a, a_status) = begin(&mut state, peer_a, 1, t0);
    assert_eq!(a_status, Ed2kUploadSessionStatus::Granted);
    let (b, _) = begin(&mut state, peer_b, 2, t0);

    let mut banned = false;
    for tick in 1..=20u64 {
        let now = t0 + Duration::from_secs(3 * tick);
        let _ = state.poll_session(&a, now, false);
        let _ = state.poll_session(&b, now, false);
        if ban_store.is_hash_banned_at(&hash_a, now) {
            banned = true;
            break;
        }
    }
    assert!(
        banned,
        "peer A must be banned after eight no-request strikes under unlimited upload"
    );
}
