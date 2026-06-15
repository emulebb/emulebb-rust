//! Inbound upload-queue admission gates.
//!
//! Mirrors the queue-capping logic of the master `CUploadQueue::AddClientToQueue`
//! (`UploadQueue.cpp`):
//!  - per-IP cap: at most 3 waiting clients from the same IP (`cSameIP >= 3`),
//!  - soft/hard queue split: the configured queue size is a soft limit; the hard
//!    limit is `soft + max(soft, 800) / 4`. Past the hard limit nobody is
//!    admitted; between soft and hard only friend-slot clients or clients whose
//!    combined file-priority-and-credit score beats the current waiting average
//!    are admitted (`RejectSoftQueueCandidateByCombinedScore`).
//!
//! Already-granted/uploading peers and re-asks of an existing waiter bypass these
//! gates (handled by the caller before admission).

/// Per-IP waiting cap (master `cSameIP >= 3`).
const MAX_WAITERS_PER_IP: usize = 3;
/// Master waiting-queue length above which the firewalled-LowID callback guard
/// engages (`GetWaitingUserCount() > 50`).
const FIREWALLED_CALLBACK_QUEUE_THRESHOLD: u64 = 50;
/// Floor used by the hard-limit margin (master `max(softQueueLimit, 800)`).
const HARD_LIMIT_MARGIN_FLOOR: u64 = 800;

/// Compute the hard queue limit from the soft limit
/// (`softQueueLimit + max(softQueueLimit, 800) / 4`).
#[must_use]
pub(super) fn hard_queue_limit(soft_queue_size: u32) -> u64 {
    let soft = u64::from(soft_queue_size);
    soft + soft.max(HARD_LIMIT_MARGIN_FLOOR) / 4
}

/// Inputs for the soft/hard combined-score admission gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SoftQueueAdmission {
    /// Current number of waiting clients.
    pub(super) waiting_count: u64,
    /// Configured soft queue size (`thePrefs.GetQueueSize()`).
    pub(super) soft_queue_size: u32,
    /// Whether the candidate holds a friend slot (admitted past the soft limit).
    pub(super) has_friend_slot: bool,
    /// Candidate combined file-priority-and-credit score.
    pub(super) candidate_combined_score: i128,
    /// Average combined score across current admission-candidate waiters.
    pub(super) average_combined_score: i128,
}

/// Returns `true` when the soft/hard queue policy blocks the candidate from
/// joining the waiting queue (master `RejectSoftQueueCandidateByCombinedScore`).
#[must_use]
pub(super) fn reject_soft_queue_candidate(admission: SoftQueueAdmission) -> bool {
    let hard_limit = hard_queue_limit(admission.soft_queue_size);
    let soft_limit = u64::from(admission.soft_queue_size);
    let hard_reached = admission.waiting_count >= hard_limit;
    let soft_reached = admission.waiting_count >= soft_limit;
    hard_reached
        || (soft_reached
            && !admission.has_friend_slot
            && admission.candidate_combined_score < admission.average_combined_score)
}

/// Combined file-priority-and-credit score (master
/// `ComputeCombinedFilePrioAndCredit = 10 * creditRatio * filePrio`). The
/// constant `10/1000` scale is dropped because the value is only ever compared
/// against the same-scaled average, so `filePrio * creditPermille` preserves the
/// ordering while staying in integer arithmetic.
#[must_use]
pub(super) fn combined_file_prio_and_credit(
    file_priority_score: i128,
    credit_score_permille: i128,
) -> i128 {
    file_priority_score.saturating_mul(credit_score_permille)
}

/// Returns `true` when admitting another waiter from `candidate_ip` would exceed
/// the per-IP cap, given how many waiters already share that IP.
#[must_use]
pub(super) fn reject_per_ip_cap(same_ip_waiters: usize) -> bool {
    same_ip_waiters >= MAX_WAITERS_PER_IP
}

/// Inputs for the firewalled-LowID callback admission guard (master
/// `CUploadQueue::AddClientToQueue` opening check, `UploadQueue.cpp:1815-1825`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FirewalledCallbackAdmission {
    /// We are connected to any network (`theApp.IsConnected()`).
    pub(super) we_are_connected: bool,
    /// We are firewalled / LowID (`theApp.IsFirewalled()`).
    pub(super) we_are_firewalled: bool,
    /// The candidate peer is Kad-reachable (`client->GetKadPort()` non-zero); a
    /// Kad-reachable peer is exempt (all Kad callbacks are allowed).
    pub(super) peer_has_kad_port: bool,
    /// The candidate peer is currently downloading from us (`GetDownloadState()
    /// != DS_NONE`); a peer that helps us is exempt. An inbound queued uploader
    /// is requesting, not downloading, so this is normally `false`.
    pub(super) peer_is_downloading_from_us: bool,
    /// The candidate peer is a friend (`IsFriend()`); friends are exempt.
    pub(super) peer_is_friend: bool,
    /// The candidate peer is on the same server we are connected to
    /// (`serverconnect->IsLocalServer(...)`); same-server TCP LowID callbacks are
    /// allowed. An inbound peer whose server we do not know is treated as a
    /// different server (master `GetServerIP()` 0 -> `IsLocalServer` false).
    pub(super) peer_on_same_server: bool,
    /// Current number of waiting clients (`GetWaitingUserCount()`).
    pub(super) waiting_count: u64,
}

/// Returns `true` when the firewalled-LowID callback guard blocks the candidate
/// (master `AddClientToQueue` early `return`): we are connected AND firewalled,
/// the peer is not Kad-reachable, not downloading from us, not a friend, not on
/// our server, and the waiting queue already holds more than 50 clients.
#[must_use]
pub(super) fn reject_firewalled_callback(admission: FirewalledCallbackAdmission) -> bool {
    admission.we_are_connected
        && admission.we_are_firewalled
        && !admission.peer_has_kad_port
        && !admission.peer_is_downloading_from_us
        && !admission.peer_is_friend
        && !admission.peer_on_same_server
        && admission.waiting_count > FIREWALLED_CALLBACK_QUEUE_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_limit_uses_master_margin() {
        // soft 10000 -> hard 10000 + 2500 = 12500.
        assert_eq!(hard_queue_limit(10_000), 12_500);
        // small soft uses the 800 floor: soft 100 -> 100 + 200 = 300.
        assert_eq!(hard_queue_limit(100), 300);
    }

    #[test]
    fn admits_below_soft_limit() {
        assert!(!reject_soft_queue_candidate(SoftQueueAdmission {
            waiting_count: 5,
            soft_queue_size: 10,
            has_friend_slot: false,
            candidate_combined_score: 0,
            average_combined_score: 1_000,
        }));
    }

    #[test]
    fn blocks_low_score_candidate_past_soft_limit() {
        assert!(reject_soft_queue_candidate(SoftQueueAdmission {
            waiting_count: 10,
            soft_queue_size: 10,
            has_friend_slot: false,
            candidate_combined_score: 500,
            average_combined_score: 1_000,
        }));
    }

    #[test]
    fn admits_high_score_candidate_past_soft_limit() {
        assert!(!reject_soft_queue_candidate(SoftQueueAdmission {
            waiting_count: 10,
            soft_queue_size: 10,
            has_friend_slot: false,
            candidate_combined_score: 2_000,
            average_combined_score: 1_000,
        }));
    }

    #[test]
    fn admits_friend_slot_past_soft_limit() {
        assert!(!reject_soft_queue_candidate(SoftQueueAdmission {
            waiting_count: 11,
            soft_queue_size: 10,
            has_friend_slot: true,
            candidate_combined_score: 0,
            average_combined_score: 1_000,
        }));
    }

    #[test]
    fn blocks_everyone_past_hard_limit() {
        // soft 10 -> hard 10 + max(10,800)/4 = 10 + 200 = 210.
        assert!(reject_soft_queue_candidate(SoftQueueAdmission {
            waiting_count: 210,
            soft_queue_size: 10,
            has_friend_slot: true,
            candidate_combined_score: 1_000_000,
            average_combined_score: 0,
        }));
    }

    #[test]
    fn per_ip_cap_blocks_fourth_waiter() {
        assert!(!reject_per_ip_cap(2));
        assert!(reject_per_ip_cap(3));
        assert!(reject_per_ip_cap(4));
    }

    fn firewalled_callback_blocking() -> FirewalledCallbackAdmission {
        FirewalledCallbackAdmission {
            we_are_connected: true,
            we_are_firewalled: true,
            peer_has_kad_port: false,
            peer_is_downloading_from_us: false,
            peer_is_friend: false,
            peer_on_same_server: false,
            waiting_count: 51,
        }
    }

    #[test]
    fn firewalled_callback_blocks_when_all_conditions_hold() {
        assert!(reject_firewalled_callback(firewalled_callback_blocking()));
    }

    #[test]
    fn firewalled_callback_requires_more_than_fifty_waiters() {
        let mut admission = firewalled_callback_blocking();
        admission.waiting_count = 50;
        assert!(!reject_firewalled_callback(admission));
        admission.waiting_count = 51;
        assert!(reject_firewalled_callback(admission));
    }

    #[test]
    fn firewalled_callback_exempts_when_not_firewalled() {
        let mut admission = firewalled_callback_blocking();
        admission.we_are_firewalled = false;
        assert!(!reject_firewalled_callback(admission));
    }

    #[test]
    fn firewalled_callback_exempts_kad_friend_same_server_and_downloader() {
        for tweak in [
            |a: &mut FirewalledCallbackAdmission| a.peer_has_kad_port = true,
            |a: &mut FirewalledCallbackAdmission| a.peer_is_friend = true,
            |a: &mut FirewalledCallbackAdmission| a.peer_on_same_server = true,
            |a: &mut FirewalledCallbackAdmission| a.peer_is_downloading_from_us = true,
            |a: &mut FirewalledCallbackAdmission| a.we_are_connected = false,
        ] {
            let mut admission = firewalled_callback_blocking();
            tweak(&mut admission);
            assert!(!reject_firewalled_callback(admission));
        }
    }
}
