//! RUST-PAR-020 U-GAP3 upload anti-abuse cooldown / repeat-offender ban wiring
//! at the queue-state level: a never-requested slot cools its IP and is skipped
//! for promotion until the cooldown expires, repeated offences ban the peer via
//! the shared `BanStore`, the cooldown probe re-promotes a cooled peer when a
//! base slot would otherwise idle, and a failed promote-connect cools the peer.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::ban_store::BanStore;
use crate::ed2k_transfer::{
    Ed2kUploadPeerIdentity, Ed2kUploadQueueConfig, Ed2kUploadSessionHandle, Ed2kUploadSessionStatus,
    upload_queue::Ed2kUploadQueueState,
};

use super::upload_queue_support::upload_peer;

const FILE_HASH: &str = "00112233445566778899aabbccddeeff";
/// Standard (non-broadband) upload budget: below the 4 MiB/s broadband
/// threshold, so the standard cooldown tiers + 8-strike ban apply.
const STANDARD_BUDGET: u64 = 100 * 1024;

/// One base slot, no elastic room, a standard underfilled budget, a 1 s
/// granted-idle timer, and disabled session caps: the minimal fixture that
/// drives the no-request recycle (and hence the cooldown/strike/ban path).
fn cooldown_config() -> Ed2kUploadQueueConfig {
    Ed2kUploadQueueConfig {
        active_slots: 1,
        elastic_percent: 0,
        upload_limit_bytes_per_sec: STANDARD_BUDGET,
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

/// A no-request recycle cools the recycled peer's IP, so when a slot frees the
/// queue prefers a NON-cooled waiter over the cooled peer -- until the cooldown
/// expires, after which the peer is promotable again.
#[test]
fn no_request_recycle_cools_ip_and_skips_it_until_expiry() {
    let mut state = Ed2kUploadQueueState::new(cooldown_config());
    let t0 = Instant::now();

    let (a, a_status) = begin(&mut state, upload_peer(1, 1, 0x0A00_0001), 1, t0);
    assert_eq!(a_status, Ed2kUploadSessionStatus::Granted);
    let (b, _) = begin(&mut state, upload_peer(2, 2, 0x0A00_0002), 2, t0);

    // +3 s: the sustained-underfill no-request recycle demotes A (0 bytes served)
    // and promotes B into the freed slot. A's IP is now on a cooldown.
    let t3 = t0 + Duration::from_secs(3);
    assert!(is_waiting(state.poll_session(&a, t3, false)));
    assert_eq!(state.poll_session(&b, t3, false), Ed2kUploadSessionStatus::Granted);

    // A fresh, non-cooled waiter C behind the full slot.
    let (c, c_status) = begin(&mut state, upload_peer(3, 3, 0x0A00_0003), 3, t3);
    assert!(is_waiting(c_status));

    // Free the slot: the non-cooled C is promoted, the cooled A is skipped.
    let t3b = t3 + Duration::from_millis(500);
    state.release_session(&b, t3b);
    assert_eq!(state.poll_session(&c, t3b, false), Ed2kUploadSessionStatus::Granted);
    assert!(is_waiting(state.poll_session(&a, t3b, false)));

    // Past A's 30 s standard cooldown (seeded at +3 s), A is promotable again.
    let t34 = t0 + Duration::from_secs(34);
    state.release_session(&c, t34);
    assert_eq!(state.poll_session(&a, t34, false), Ed2kUploadSessionStatus::Granted);
}

/// Eight no-request recycles of the same peer within the 4 h window ban it by
/// user hash via the shared `BanStore` (standard threshold 8,
/// `kNoRequestRepeatBanThreshold`). Two peers alternate through the single slot
/// (each recycle re-promotes the other via the cooldown probe), so the target
/// peer accrues its eight strikes and is banned.
#[test]
fn eight_no_request_strikes_ban_the_peer_via_ban_store() {
    let mut state = Ed2kUploadQueueState::new(cooldown_config());
    let ban_store = Arc::new(BanStore::new());
    state.set_ban_store(Arc::clone(&ban_store));
    let t0 = Instant::now();

    let hash_a = [0xAAu8; 16];
    let mut peer_a = upload_peer(1, 1, 0x0A00_0001);
    peer_a.user_hash = Some(hash_a);
    let mut peer_b = upload_peer(2, 2, 0x0A00_0002);
    peer_b.user_hash = Some([0xBBu8; 16]);
    let a_ip = peer_a.ip;

    let (a, a_status) = begin(&mut state, peer_a, 1, t0);
    assert_eq!(a_status, Ed2kUploadSessionStatus::Granted);
    let (b, _) = begin(&mut state, peer_b, 2, t0);

    // Drive 3 s ticks: each poll recycles the active peer and the cooldown probe
    // re-promotes the other. A accrues a strike every other tick.
    let mut banned_at = None;
    for tick in 1..=20u64 {
        let now = t0 + Duration::from_secs(3 * tick);
        let _ = state.poll_session(&a, now, false);
        let _ = state.poll_session(&b, now, false);
        if ban_store.is_hash_banned_at(&hash_a, now) {
            banned_at = Some(now);
            break;
        }
    }

    let banned_at = banned_at.expect("peer A must be banned after eight no-request strikes");
    // The ban is by hash (standard threshold, valid hash present) and also
    // reachable by the `is_banned` OR-of-keys lookup.
    assert!(ban_store.is_hash_banned_at(&hash_a, banned_at));
    let a_ip_v4 = match a_ip {
        std::net::IpAddr::V4(v4) => v4,
        _ => unreachable!("test peers are IPv4"),
    };
    assert!(ban_store.is_banned_at(Some(a_ip_v4), Some(&hash_a), banned_at));
}

/// When every eligible waiter is cooled down and a base slot would otherwise
/// idle, the cooldown probe re-promotes the best (lowest-remaining) cooled
/// waiter rather than starving the slot.
#[test]
fn cooldown_probe_repromotes_when_all_cooled_and_slot_idle() {
    let mut state = Ed2kUploadQueueState::new(cooldown_config());
    let t0 = Instant::now();

    let (a, a_status) = begin(&mut state, upload_peer(1, 1, 0x0A00_0001), 1, t0);
    assert_eq!(a_status, Ed2kUploadSessionStatus::Granted);
    let (b, _) = begin(&mut state, upload_peer(2, 2, 0x0A00_0002), 2, t0);

    // +3 s: A recycled + cooled, B promoted.
    let t3 = t0 + Duration::from_secs(3);
    assert!(is_waiting(state.poll_session(&a, t3, false)));
    assert_eq!(state.poll_session(&b, t3, false), Ed2kUploadSessionStatus::Granted);

    // +6 s: B recycled + cooled too. Now both waiters are cooled and the slot is
    // idle -- the probe re-promotes A (the lower-remaining cooldown).
    let t6 = t0 + Duration::from_secs(6);
    assert!(is_waiting(state.poll_session(&b, t6, false)));
    assert_eq!(state.poll_session(&a, t6, false), Ed2kUploadSessionStatus::Granted);
}

/// A failed promote-connect seeds the churn cooldown for that peer, so a
/// subsequent slot request is queued (gated) rather than granted inline even
/// though a slot is free -- and it is promotable again once the cooldown
/// expires. Mirrors the fork's failed-admission / no-socket removal.
#[test]
fn failed_promotion_cools_the_peer_and_gates_inline_grant() {
    let mut state = Ed2kUploadQueueState::new(cooldown_config());
    let t0 = Instant::now();
    let peer = upload_peer(1, 1, 0x0A00_0001);

    state.note_failed_promotion(&peer, t0);

    // A fresh admission for the cooled peer is queued, not granted, even with a
    // free slot (the cooldown gate applies to the inline grant too).
    let (handle, status) = begin(&mut state, peer, 1, t0 + Duration::from_secs(1));
    assert!(is_waiting(status), "a cooled peer must not be granted inline");

    // A different, non-cooled peer would take the free slot.
    let (other, other_status) = begin(&mut state, upload_peer(2, 2, 0x0A00_0002), 2, t0);
    assert_eq!(other_status, Ed2kUploadSessionStatus::Granted);
    state.release_session(&other, t0 + Duration::from_secs(2));

    // Past the 30 s churn cooldown the original peer is promotable again.
    let t31 = t0 + Duration::from_secs(31);
    assert_eq!(
        state.poll_session(&handle, t31, false),
        Ed2kUploadSessionStatus::Granted
    );
}

/// RUST-PAR-021 GAP2: an ACTIVE upload slot torn down young (<= 30 s) after
/// serving little (<= 1 MB) while a replacement waiter was denied its turn is the
/// "grabbed a slot then bailed" churn signal, so its IP is put on the churn
/// cooldown; a same-IP re-request is then gated even with a free slot (oracle
/// `ShouldCooldownShortFailedUploadSlot`, UploadQueueSeams.h:644-659, applied in
/// RemoveFromUploadQueue).
#[test]
fn short_failed_disconnect_cools_the_ip() {
    let mut state = Ed2kUploadQueueState::new(cooldown_config());
    let t0 = Instant::now();
    let churner = upload_peer(1, 1, 0x0A00_0001);
    let (a, a_status) = begin(&mut state, churner.clone(), 1, t0);
    assert_eq!(a_status, Ed2kUploadSessionStatus::Granted);

    // A distinct-IP waiter is denied its turn by the churn: this is the
    // replacement pressure the short-failed cooldown protects.
    let (w, w_status) = begin(&mut state, upload_peer(2, 2, 0x0A00_0002), 2, t0);
    assert!(is_waiting(w_status));

    // Disconnect at +2 s having served nothing: short-failed -> cool the IP; the
    // denied waiter takes the freed slot.
    state.release_session(&a, t0 + Duration::from_secs(2));
    assert_eq!(
        state.poll_session(&w, t0 + Duration::from_secs(2), false),
        Ed2kUploadSessionStatus::Granted
    );

    // Free the slot again (W is now the sole peer, so its own release is not
    // cooled -- no replacement was denied).
    state.release_session(&w, t0 + Duration::from_secs(3));

    // The churner's same-IP re-request finds a free slot but is gated by its
    // short-failed cooldown, proving the cooldown took hold.
    let (a2, a2_status) = begin(&mut state, churner, 11, t0 + Duration::from_secs(3));
    assert!(is_waiting(a2_status), "short-failed IP must be cooled");

    // Past the 30 s churn cooldown (seeded at +2 s) the peer is promotable again.
    assert_eq!(
        state.poll_session(&a2, t0 + Duration::from_secs(33), false),
        Ed2kUploadSessionStatus::Granted
    );
}

/// A productive session (> 1 MB served) ending young is NOT churn: no cooldown,
/// so the same IP is immediately re-grantable -- and a legit sibling behind a
/// shared NAT IP that uploads normally is never suppressed.
#[test]
fn productive_disconnect_does_not_cool_the_ip() {
    let mut state = Ed2kUploadQueueState::new(cooldown_config());
    let t0 = Instant::now();
    let peer = upload_peer(1, 1, 0x0A00_0001);
    let (a, a_status) = begin(&mut state, peer.clone(), 1, t0);
    assert_eq!(a_status, Ed2kUploadSessionStatus::Granted);

    // 2 MB served (> the 1 MB short-failed ceiling) before a young disconnect.
    state.note_uploaded_bytes(&a, 2 * 1024 * 1024, t0 + Duration::from_secs(1));
    state.release_session(&a, t0 + Duration::from_secs(2));

    let (_a2, a2_status) = begin(&mut state, peer, 11, t0 + Duration::from_secs(3));
    assert_eq!(
        a2_status,
        Ed2kUploadSessionStatus::Granted,
        "a productive disconnect must not cool the IP"
    );
}

/// A long-lived session (aged past 30 s) ending is NOT churn even with little
/// served: no cooldown.
#[test]
fn long_low_served_disconnect_does_not_cool_the_ip() {
    let mut state = Ed2kUploadQueueState::new(cooldown_config());
    let t0 = Instant::now();
    let peer = upload_peer(1, 1, 0x0A00_0001);
    let (a, a_status) = begin(&mut state, peer.clone(), 1, t0);
    assert_eq!(a_status, Ed2kUploadSessionStatus::Granted);

    // Disconnect only after 31 s (> the 30 s short-failed age).
    state.release_session(&a, t0 + Duration::from_secs(31));
    let (_a2, a2_status) = begin(&mut state, peer, 11, t0 + Duration::from_secs(32));
    assert_eq!(
        a2_status,
        Ed2kUploadSessionStatus::Granted,
        "a long-lived disconnect must not cool the IP"
    );
}

/// RUST-PAR-021 GAP3: when every waiter is cooled with a hard (non-probeable)
/// cooldown and none is admissible, an idle no-request slot is RETAINED with no
/// strike, matching the oracle's HasNoRequestUploadReplacementPressure retain
/// (UploadQueue.cpp:1570-1584) -- rust must not strike (and escalate toward a
/// ban) a slot it has no candidate to replace.
#[test]
fn idle_no_request_slot_is_retained_when_all_waiters_are_hard_cooled() {
    let mut state = Ed2kUploadQueueState::new(cooldown_config());
    let t0 = Instant::now();

    let (a, a_status) = begin(&mut state, upload_peer(1, 1, 0x0A00_0001), 1, t0);
    assert_eq!(a_status, Ed2kUploadSessionStatus::Granted);

    // The only waiter carries a churn cooldown: a hard, non-probeable gate, so it
    // is neither an admissible nor a probeable replacement.
    let peer_b = upload_peer(2, 2, 0x0A00_0002);
    state.note_failed_promotion(&peer_b, t0);
    let (_b, b_status) = begin(&mut state, peer_b, 2, t0);
    assert!(is_waiting(b_status));

    // +3 s: past the grant-idle timer and the 2 s underfill window, A has served
    // nothing -- but the sole waiter cannot replace it, so A is retained, NOT
    // recycled/struck.
    assert_eq!(
        state.poll_session(&a, t0 + Duration::from_secs(3), false),
        Ed2kUploadSessionStatus::Granted,
        "an unreplaceable idle no-request slot must be retained, not struck"
    );
}

/// Direct unit coverage of the `UploadCooldownTracker` policy (tiers, strike
/// thresholds, rolling window, probe eligibility), confirmed against
/// `UploadQueueSeams.h`.
mod tracker {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::{Duration, Instant},
    };

    use crate::ed2k_transfer::upload_cooldown::{CooldownBan, UploadCooldownTracker};

    const STANDARD_BUDGET: u64 = 100 * 1024;
    const BROADBAND_BUDGET: u64 = 8 * 1024 * 1024;
    const STRIKE_WINDOW: Duration = Duration::from_secs(4 * 60 * 60);

    fn ip(octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
    }

    #[test]
    fn no_request_recycle_seeds_cooldown_and_gates_selection() {
        let mut tracker = UploadCooldownTracker::new();
        let t0 = Instant::now();
        let peer = ip(1);
        let outcome =
            tracker.register_no_request_recycle(peer, Some([1u8; 16]), false, STANDARD_BUDGET, t0, false);
        assert_eq!(outcome.strikes, 1);
        assert_eq!(outcome.ban, CooldownBan::None);
        // Strike 1 standard cooldown = base 30s.
        assert!(tracker.is_cooled(peer, false, t0 + Duration::from_secs(29)));
        assert!(!tracker.is_cooled(peer, false, t0 + Duration::from_secs(31)));
        // A friend is never suppressed.
        assert!(!tracker.is_cooled(peer, true, t0 + Duration::from_secs(1)));
    }

    #[test]
    fn standard_hash_offender_is_banned_at_eight_strikes() {
        let mut tracker = UploadCooldownTracker::new();
        let t0 = Instant::now();
        let peer = ip(2);
        let hash = [7u8; 16];
        for strike in 1..8u32 {
            let outcome =
                tracker.register_no_request_recycle(peer, Some(hash), false, STANDARD_BUDGET, t0, false);
            assert_eq!(outcome.strikes, strike);
            assert_eq!(outcome.ban, CooldownBan::None, "strike {strike} must not ban");
        }
        let outcome =
            tracker.register_no_request_recycle(peer, Some(hash), false, STANDARD_BUDGET, t0, false);
        assert_eq!(outcome.strikes, 8);
        assert_eq!(outcome.ban, CooldownBan::ByHash);
    }

    #[test]
    fn broadband_hash_offender_is_banned_at_sixteen_strikes() {
        let mut tracker = UploadCooldownTracker::new();
        let t0 = Instant::now();
        let peer = ip(3);
        let hash = [9u8; 16];
        for strike in 1..16u32 {
            let outcome =
                tracker.register_no_request_recycle(peer, Some(hash), false, BROADBAND_BUDGET, t0, false);
            assert_eq!(outcome.ban, CooldownBan::None, "strike {strike} must not ban");
        }
        let outcome =
            tracker.register_no_request_recycle(peer, Some(hash), false, BROADBAND_BUDGET, t0, false);
        assert_eq!(outcome.strikes, 16);
        assert_eq!(outcome.ban, CooldownBan::ByHash);
    }

    #[test]
    fn hash_rotation_bans_both_keys_at_three_hashes_and_five_strikes() {
        let mut tracker = UploadCooldownTracker::new();
        let t0 = Instant::now();
        let peer = ip(4);
        // Five recycles from one IP across three distinct rotated hashes: the
        // rotation ban (>=3 distinct AND >=5 strikes) fires on the fifth, well
        // before the per-hash 8-strike threshold.
        let hashes = [[1u8; 16], [2u8; 16], [3u8; 16], [1u8; 16], [2u8; 16]];
        let mut banned = CooldownBan::None;
        for (index, hash) in hashes.into_iter().enumerate() {
            let outcome =
                tracker.register_no_request_recycle(peer, Some(hash), false, STANDARD_BUDGET, t0, false);
            if index < 4 {
                assert_eq!(outcome.ban, CooldownBan::None, "recycle {index} must not ban");
            } else {
                banned = outcome.ban;
            }
        }
        assert_eq!(banned, CooldownBan::Both);
    }

    #[test]
    fn no_hash_offender_bans_by_ip() {
        let mut tracker = UploadCooldownTracker::new();
        let t0 = Instant::now();
        let peer = ip(5);
        for _ in 1..8u32 {
            tracker.register_no_request_recycle(peer, None, false, STANDARD_BUDGET, t0, false);
        }
        let outcome = tracker.register_no_request_recycle(peer, None, false, STANDARD_BUDGET, t0, false);
        assert_eq!(outcome.strikes, 8);
        assert_eq!(outcome.ban, CooldownBan::ByIp);
    }

    #[test]
    fn strikes_reset_after_the_four_hour_window() {
        let mut tracker = UploadCooldownTracker::new();
        let t0 = Instant::now();
        let peer = ip(6);
        let hash = [4u8; 16];
        let first =
            tracker.register_no_request_recycle(peer, Some(hash), false, STANDARD_BUDGET, t0, false);
        assert_eq!(first.strikes, 1);
        // Past the 4h window the counter resets to a fresh strike 1.
        let later = t0 + STRIKE_WINDOW + Duration::from_secs(1);
        let reset =
            tracker.register_no_request_recycle(peer, Some(hash), false, STANDARD_BUDGET, later, false);
        assert_eq!(reset.strikes, 1);
    }

    #[test]
    fn productive_recycle_is_not_penalized() {
        let mut tracker = UploadCooldownTracker::new();
        let t0 = Instant::now();
        let peer = ip(7);
        let outcome =
            tracker.register_no_request_recycle(peer, Some([5u8; 16]), false, STANDARD_BUDGET, t0, true);
        assert_eq!(outcome.strikes, 0);
        assert_eq!(outcome.ban, CooldownBan::None);
        // Productive standard cap is 10s, shorter than the base 30s.
        assert!(tracker.is_cooled(peer, false, t0 + Duration::from_secs(9)));
        assert!(!tracker.is_cooled(peer, false, t0 + Duration::from_secs(11)));
    }

    #[test]
    fn churn_cooldown_gates_but_is_not_probeable() {
        let mut tracker = UploadCooldownTracker::new();
        let t0 = Instant::now();
        let peer = ip(8);
        tracker.set_churn_cooldown(peer, false, STANDARD_BUDGET, t0);
        assert!(tracker.is_cooled(peer, false, t0 + Duration::from_secs(29)));
        // A pure churn/retry cooldown is a hard gate: never probeable.
        assert!(!tracker.can_probe(peer, t0 + Duration::from_secs(1), true));
    }

    #[test]
    fn no_request_cooldown_is_probeable_only_under_open_base_slot_underfill() {
        let mut tracker = UploadCooldownTracker::new();
        let t0 = Instant::now();
        let peer = ip(9);
        tracker.register_no_request_recycle(peer, Some([6u8; 16]), false, STANDARD_BUDGET, t0, false);
        let probe_at = t0 + Duration::from_secs(1);
        assert!(!tracker.can_probe(peer, probe_at, false));
        assert!(tracker.can_probe(peer, probe_at, true));
        // Once the cooldown expires there is nothing to probe.
        assert!(!tracker.can_probe(peer, t0 + Duration::from_secs(31), true));
    }

    #[test]
    fn repeat_cooldown_backoff_doubles_and_caps() {
        let tracker = UploadCooldownTracker::new();
        // Standard: 30, 60, 120, capped at 180.
        assert_eq!(tracker.repeat_cooldown_secs(1, STANDARD_BUDGET), 30);
        assert_eq!(tracker.repeat_cooldown_secs(2, STANDARD_BUDGET), 60);
        assert_eq!(tracker.repeat_cooldown_secs(3, STANDARD_BUDGET), 120);
        assert_eq!(tracker.repeat_cooldown_secs(4, STANDARD_BUDGET), 180);
        assert_eq!(tracker.repeat_cooldown_secs(9, STANDARD_BUDGET), 180);
        // Broadband caps at 45.
        assert_eq!(tracker.repeat_cooldown_secs(1, BROADBAND_BUDGET), 30);
        assert_eq!(tracker.repeat_cooldown_secs(2, BROADBAND_BUDGET), 45);
        assert_eq!(tracker.repeat_cooldown_secs(5, BROADBAND_BUDGET), 45);
    }
}
