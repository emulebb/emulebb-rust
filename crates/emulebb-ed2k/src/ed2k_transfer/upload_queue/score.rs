//! Upload-queue waiting-score shaping, mirroring the master `CUpDownClient`
//! score path (`UploadClient.cpp` `GetScoreBreakdown` +
//! `UploadScoreSeams::BuildUploadScoreBreakdown`).
//!
//! The master computes a float working score:
//!   1. `score = baseValueSeconds`
//!   2. `*= creditRatio`            (credit system)
//!   3. `*= filePrio / 10`          (file priority)
//!   4. `+= lowRatioBonus`          (low all-time-upload-ratio additive bonus)
//!   5. `/= lowIdDivisor`           (LowID deprioritisation)
//!   6. `*= 0.5`                    (old-client penalty)
//!      and zeroes the score entirely for a friend slot's fast path (handled by
//!      the caller), an `IS_IDBADGUY` peer, a banned peer, or a `GPLEvildoer`.
//!
//! We keep the queue's integer score contract: the additive low-ratio bonus is
//! scaled into the same `seconds * filePrio * permille / 1000` integer units the
//! rest of the queue uses, preserving the master's *relative* weighting (the
//! bonus is added after the priority multiply, before the divisor and penalty).

use super::{DEFAULT_CREDIT_SCORE_PERMILLE, Ed2kUploadPeerIdentity, FRIEND_SLOT_SCORE_BONUS};

/// Master old-client threshold: a peer whose eMule version byte is at or below
/// this value gets the old-client penalty (`m_byEmuleVersion <= 0x19`).
pub(super) const OLD_CLIENT_EMULE_VERSION_THRESHOLD: u8 = 0x19;
/// eMule default LowID score divisor (`PreferenceValidationSeams::kDefaultLowIDDivisor`):
/// a LowID waiter's score is divided by this to deprioritise unreachable peers
/// (master `inputs.uLowIdDivisor`, applied when `HasLowID() && divisor > 1`).
pub(super) const LOW_ID_SCORE_DIVISOR: i128 = 2;
/// eMule old-client score penalty: the effective working score is multiplied by
/// 0.5 (`UploadScoreSeams::BuildUploadScoreBreakdown` `fWorkingScore *= 0.5f`)
/// for an old eMule client (`m_byEmuleVersion <= 0x19`).
const OLD_CLIENT_PENALTY_NUMERATOR: i128 = 1;
const OLD_CLIENT_PENALTY_DENOMINATOR: i128 = 2;

/// eMule default low-ratio additive bonus (`PreferenceValidationSeams::
/// kDefaultLowRatioBonus`, `thePrefs.GetLowRatioBonus()`). Added to the working
/// score (in seconds-equivalent units) for a file whose all-time upload ratio is
/// below the configured threshold.
pub(super) const DEFAULT_LOW_RATIO_BONUS: i128 = 50;

/// eMule default low-ratio threshold (`kDefaultLowRatioThreshold`, 0.5), scaled
/// by 1000: the all-time upload ratio (also permille-scaled) must be below this
/// for the bonus to apply.
pub(super) const DEFAULT_LOW_RATIO_THRESHOLD_PERMILLE: i128 = 500;

/// Per-session upload-score modifiers, captured from the peer identity + the
/// requested file at admission time (mirroring the master inputs assembled in
/// `GetScoreBreakdown`). These are stable for the lifetime of one queued waiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UploadScoreModifiers {
    /// Peer is a LowID client (`HasLowID()`): apply the LowID divisor.
    pub(super) low_id: bool,
    /// Peer's secure-ident signature failed verification (`IS_IDBADGUY`): zero.
    pub(super) ident_bad_guy: bool,
    /// Peer is a known GPL-breaker mod (`m_bGPLEvildoer`): zero.
    pub(super) gpl_evildoer: bool,
    /// Peer is on the local ban list (`IsBanned()`): zero.
    pub(super) banned: bool,
    /// Old eMule client (`(IsEmuleClient() || GetClientSoft() < 10) &&
    /// m_byEmuleVersion <= 0x19`): apply the x0.5 penalty.
    pub(super) old_client: bool,
    /// The requested file's all-time upload ratio is below the low-ratio
    /// threshold: apply the additive low-ratio bonus.
    pub(super) low_ratio_bonus: bool,
}

impl UploadScoreModifiers {
    /// Derive the per-session modifiers from the admitting peer identity and the
    /// requested file's all-time upload ratio (permille-scaled, `uploaded * 1000
    /// / file_size`; master `CKnownFile::GetAllTimeUploadRatio`).
    pub(super) fn from_peer(
        peer: &Ed2kUploadPeerIdentity,
        low_id: bool,
        all_time_upload_ratio_permille: i128,
    ) -> Self {
        // Master: (IsEmuleClient() || GetClientSoft() < 10) && m_byEmuleVersion <= 0x19.
        // A non-mule client reports emule_version 0, which is <= 0x19; the
        // `is_emule_client` flag carries the IsEmuleClient() leg.
        let old_client =
            peer.is_emule_client && peer.emule_version <= OLD_CLIENT_EMULE_VERSION_THRESHOLD;
        Self {
            low_id,
            ident_bad_guy: peer.ident_bad_guy,
            gpl_evildoer: peer.gpl_evildoer,
            banned: peer.banned,
            old_client,
            low_ratio_bonus: all_time_upload_ratio_permille < DEFAULT_LOW_RATIO_THRESHOLD_PERMILLE,
        }
    }

    /// Whether any zeroing verdict applies (master early returns to score 0).
    fn zeroes_score(self) -> bool {
        self.ident_bad_guy || self.gpl_evildoer || self.banned
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UploadScoreInputs {
    pub(super) waiting_seconds: i128,
    pub(super) friend_slot: bool,
    pub(super) file_priority_score: i128,
    pub(super) credit_score_permille: i128,
    pub(super) modifiers: UploadScoreModifiers,
}

/// Compute the integer waiting score, applying the full master score shaping.
pub(super) fn waiting_score(inputs: UploadScoreInputs) -> i128 {
    // Master: banned / IS_IDBADGUY / GPLEvildoer -> score 0 (early return). The
    // friend-slot fast path is handled by the caller (and excludes LowID), so it
    // is not re-checked here.
    if inputs.modifiers.zeroes_score() {
        return 0;
    }

    // Master step 1-3: seconds * creditRatio * (filePrio/10). We keep the queue's
    // integer units (seconds * filePrio * permille / 1000); the /10 priority scale
    // is a constant factor that drops out of the relative ordering, so the
    // additive low-ratio bonus below is scaled into these same units.
    let mut score =
        inputs.waiting_seconds * inputs.file_priority_score * inputs.credit_score_permille
            / DEFAULT_CREDIT_SCORE_PERMILLE;

    // Master step 4: additive low-ratio bonus. The master adds `uLowRatioBonus`
    // (default 50) to a working score expressed in seconds-equivalent units, so
    // we scale the bonus by the same `filePrio * permille / 1000` factor used
    // above to keep its weight equivalent to ~50s of waiting at this peer's
    // priority/credit.
    if inputs.modifiers.low_ratio_bonus {
        score +=
            DEFAULT_LOW_RATIO_BONUS * inputs.file_priority_score * inputs.credit_score_permille
                / DEFAULT_CREDIT_SCORE_PERMILLE;
    }

    // Master step 5: LowID divisor (below the friend-slot fast path).
    if inputs.modifiers.low_id {
        score /= LOW_ID_SCORE_DIVISOR;
    }

    // Master step 6: old-client penalty (x0.5 on the effective score).
    if inputs.modifiers.old_client {
        score = score * OLD_CLIENT_PENALTY_NUMERATOR / OLD_CLIENT_PENALTY_DENOMINATOR;
    }

    score + friend_slot_bonus(inputs.friend_slot)
}

pub(super) const fn low_ratio_bonus_value(applies: bool) -> u32 {
    if applies {
        DEFAULT_LOW_RATIO_BONUS as u32
    } else {
        0
    }
}

pub(super) const fn low_id_divisor_value(applies: bool) -> u32 {
    if applies {
        LOW_ID_SCORE_DIVISOR as u32
    } else {
        1
    }
}

const fn friend_slot_bonus(friend_slot: bool) -> i128 {
    if friend_slot {
        FRIEND_SLOT_SCORE_BONUS
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_modifiers() -> UploadScoreModifiers {
        UploadScoreModifiers {
            low_id: false,
            ident_bad_guy: false,
            gpl_evildoer: false,
            banned: false,
            old_client: false,
            low_ratio_bonus: false,
        }
    }

    fn base_inputs() -> UploadScoreInputs {
        UploadScoreInputs {
            waiting_seconds: 100,
            friend_slot: false,
            file_priority_score: 7,
            credit_score_permille: DEFAULT_CREDIT_SCORE_PERMILLE,
            modifiers: base_modifiers(),
        }
    }

    #[test]
    fn neutral_score_is_seconds_times_priority() {
        // 100s * prio 7 * 1.0 credit = 700.
        assert_eq!(waiting_score(base_inputs()), 700);
    }

    #[test]
    fn bad_guy_zeroes_score() {
        let mut inputs = base_inputs();
        inputs.modifiers.ident_bad_guy = true;
        assert_eq!(waiting_score(inputs), 0);
    }

    #[test]
    fn gpl_evildoer_zeroes_score() {
        let mut inputs = base_inputs();
        inputs.modifiers.gpl_evildoer = true;
        assert_eq!(waiting_score(inputs), 0);
    }

    #[test]
    fn banned_zeroes_score() {
        let mut inputs = base_inputs();
        inputs.modifiers.banned = true;
        assert_eq!(waiting_score(inputs), 0);
    }

    #[test]
    fn old_client_halves_score() {
        let mut inputs = base_inputs();
        inputs.modifiers.old_client = true;
        // 700 * 1 / 2 = 350.
        assert_eq!(waiting_score(inputs), 350);
    }

    #[test]
    fn low_ratio_bonus_is_additive() {
        let mut inputs = base_inputs();
        inputs.modifiers.low_ratio_bonus = true;
        // base 700 + bonus(50 * 7 * 1.0) = 700 + 350 = 1050.
        assert_eq!(waiting_score(inputs), 1050);
    }

    #[test]
    fn low_id_divisor_then_old_client_penalty_order() {
        let mut inputs = base_inputs();
        inputs.modifiers.low_id = true;
        inputs.modifiers.old_client = true;
        // 700 / 2 (LowID) = 350, then * 1/2 (old client) = 175.
        assert_eq!(waiting_score(inputs), 175);
    }

    #[test]
    fn from_peer_derives_old_client_only_for_low_emule_version() {
        let mut peer = crate::ed2k_transfer::upload_queue::test_support_peer();
        peer.is_emule_client = true;
        peer.emule_version = 0x10;
        assert!(UploadScoreModifiers::from_peer(&peer, false, 0).old_client);
        peer.emule_version = 0x99;
        assert!(!UploadScoreModifiers::from_peer(&peer, false, 0).old_client);
        // A non-mule client (is_emule_client false) is never old-client penalised
        // here even with version 0, matching the IsEmuleClient() leg.
        peer.is_emule_client = false;
        peer.emule_version = 0;
        assert!(!UploadScoreModifiers::from_peer(&peer, false, 0).old_client);
    }

    #[test]
    fn from_peer_low_ratio_bonus_below_threshold() {
        let peer = crate::ed2k_transfer::upload_queue::test_support_peer();
        // ratio 0.4 (permille 400) < threshold 0.5 -> bonus applies.
        assert!(UploadScoreModifiers::from_peer(&peer, false, 400).low_ratio_bonus);
        // ratio 0.6 (permille 600) >= threshold -> no bonus.
        assert!(!UploadScoreModifiers::from_peer(&peer, false, 600).low_ratio_bonus);
    }
}
