//! Per-IP upload anti-abuse cooldown and no-request repeat-offender strike/ban
//! tracking (RUST-PAR-020 U-GAP3), porting the eMuleBB fork's upload-slot abuse
//! layer (`UploadQueue.cpp:1117-1779`, `UploadQueueSeams.h`). The fork keeps
//! IP-scoped retry/no-request cooldown maps plus rolling-window strike counters
//! (per user hash, per IP, and per-IP hash-rotation) and, past a strike
//! threshold, hands the offender to the client ban list.
//!
//! This module is the self-contained state + policy. The upload queue wires it
//! in: it gates slot promotion on `is_cooled`, keeps a cooled-down peer on the
//! waiting list (skipped, not dropped), re-promotes via the cooldown probe when
//! capacity would otherwise idle, and applies the returned ban to the shared
//! `BanStore` (which owns the 4h TTL, matching `CClientList::AddBannedClient`).
//!
//! Values are confirmed against `UploadQueueSeams.h`:
//! - no-request cooldown caps: standard 60s / broadband 15s
//!   (`kNoRequestUploadCooldownMaxSeconds`,
//!   `kBroadbandNoRequestUploadCooldownMaxSeconds`);
//! - productive no-request caps: standard 10s / broadband 5s;
//! - repeated no-request caps: standard 180s / broadband 45s (exponential
//!   backoff from the base, `GetNoRequestRepeatCooldownSeconds`);
//! - churn/slow retry cap: broadband 90s, churn ceiling 120s;
//! - strike window: 4h (`kNoRequestRepeatStrikeWindowSeconds`);
//! - ban thresholds: standard 8 / broadband 16 strikes
//!   (`kNoRequestRepeatBanThreshold`, `kBroadbandNoRequestRepeatBanThreshold`);
//! - hash-rotation ban: >=3 distinct hashes AND >=5 rotation strikes from one IP
//!   (`kNoRequestRepeatHashRotationBanThreshold`,
//!   `kNoRequestRepeatHashRotationStrikeThreshold`);
//! - broadband budget threshold: 4 MiB/s
//!   (`kBroadbandNoRequestCooldownBudgetBytesPerSec` /
//!   `kBroadbandAggressiveUploadPolicyBudgetBytesPerSec`);
//! - base configured cooldown default 30s
//!   (`PreferenceValidationSeams.h:kDefaultSlowUploadCooldownSeconds`).

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::{Duration, Instant},
};

/// Configured base cooldown, `thePrefs.GetSlowUploadCooldownSeconds()` default
/// (`PreferenceValidationSeams.h:35 kDefaultSlowUploadCooldownSeconds`).
pub(super) const DEFAULT_SLOW_UPLOAD_COOLDOWN_SECS: u32 = 30;

/// Upload budget (bytes/sec) at/above which the broadband cooldown caps + ban
/// threshold apply (`kBroadbandNoRequestCooldownBudgetBytesPerSec` and
/// `kBroadbandAggressiveUploadPolicyBudgetBytesPerSec`, both 4 MiB/s).
pub(super) const BROADBAND_UPLOAD_BUDGET_BYTES_PER_SEC: u64 = 4 * 1024 * 1024;

/// No-request cooldown ceilings (`UploadQueueSeams.h:15,21`).
const NO_REQUEST_COOLDOWN_MAX_SECS: u32 = 60;
const BROADBAND_NO_REQUEST_COOLDOWN_MAX_SECS: u32 = 15;
/// Productive no-request cooldown ceilings (`:16,22`).
const PRODUCTIVE_NO_REQUEST_COOLDOWN_MAX_SECS: u32 = 10;
const BROADBAND_PRODUCTIVE_NO_REQUEST_COOLDOWN_MAX_SECS: u32 = 5;
/// Repeated no-request cooldown ceilings (`:18,23`).
const REPEATED_NO_REQUEST_COOLDOWN_MAX_SECS: u32 = 180;
const BROADBAND_REPEATED_NO_REQUEST_COOLDOWN_MAX_SECS: u32 = 45;
/// Churn ceiling + broadband slow-retry ceiling (`:17,27`).
const CHURN_RETRY_COOLDOWN_MAX_SECS: u32 = 120;
const BROADBAND_SLOW_UPLOAD_RETRY_COOLDOWN_MAX_SECS: u32 = 90;

/// Rolling window for no-request strike accrual, 4h (`:28`).
const STRIKE_WINDOW: Duration = Duration::from_secs(4 * 60 * 60);
/// Strike thresholds that trigger a hash-scoped ban (`:29,30`).
const BAN_THRESHOLD_STANDARD: u32 = 8;
const BAN_THRESHOLD_BROADBAND: u32 = 16;
/// Hash-rotation ban predicate: >=3 distinct hashes AND >=5 rotation strikes
/// from one IP (`:31,32`).
const HASH_ROTATION_BAN_THRESHOLD: u32 = 3;
const HASH_ROTATION_STRIKE_THRESHOLD: u32 = 5;
/// Absolute repeat-cooldown ceiling for the exponential backoff (`:33`).
const REPEAT_COOLDOWN_MAX_SECS: u32 = 60 * 60;
/// Strike-map cleanup cadence (`:34`).
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Which ban the shared `BanStore` should apply for a no-request offender,
/// mirroring `CClientList::AddBannedClient` scope resolution
/// (`ClientList.cpp:361-373`): a hash-scoped threshold ban targets the hash
/// (or the IP when no valid hash is present), while a hash-rotation ban targets
/// both keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CooldownBan {
    /// No ban -- a cooldown was applied instead.
    None,
    /// Ban the user hash only (`clientBanScopeHash` with a valid hash).
    ByHash,
    /// Ban the IP only (`clientBanScopeHash` degenerate case, no valid hash).
    ByIp,
    /// Ban both IP and hash (`clientBanScopeBoth`, hash rotation).
    Both,
}

/// Outcome of registering one non-productive no-request recycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NoRequestRecycleOutcome {
    /// The offender's strike count in the current rolling window.
    pub strikes: u32,
    /// The ban the caller must apply (or `None` when only a cooldown was set).
    pub ban: CooldownBan,
}

#[derive(Debug, Clone, Copy)]
struct RetryCooldownState {
    until: Instant,
    track_until: Instant,
}

#[derive(Debug, Clone, Copy)]
struct NoRequestCooldownState {
    until: Instant,
    track_until: Instant,
    productive: bool,
}

#[derive(Debug, Clone, Copy)]
struct StrikeState {
    strikes: u32,
    window_until: Instant,
}

#[derive(Debug, Clone)]
struct IpHashRotationState {
    hash_keys: HashSet<[u8; 16]>,
    total_strikes: u32,
    window_until: Instant,
}

/// Per-IP upload cooldown + no-request strike/ban tracker.
#[derive(Debug)]
pub(super) struct UploadCooldownTracker {
    base_cooldown_secs: u32,
    retry_by_ip: HashMap<IpAddr, RetryCooldownState>,
    no_request_by_ip: HashMap<IpAddr, NoRequestCooldownState>,
    strikes_by_hash: HashMap<[u8; 16], StrikeState>,
    strikes_by_ip: HashMap<IpAddr, StrikeState>,
    hash_rotation_by_ip: HashMap<IpAddr, IpHashRotationState>,
    last_cleanup: Option<Instant>,
}

impl UploadCooldownTracker {
    pub(super) fn new() -> Self {
        Self {
            base_cooldown_secs: DEFAULT_SLOW_UPLOAD_COOLDOWN_SECS,
            retry_by_ip: HashMap::new(),
            no_request_by_ip: HashMap::new(),
            strikes_by_hash: HashMap::new(),
            strikes_by_ip: HashMap::new(),
            hash_rotation_by_ip: HashMap::new(),
            last_cleanup: None,
        }
    }

    /// Whether `ip` is under an active upload cooldown (retry OR no-request),
    /// mirroring `ApplyUploadRetryCooldown` + `IsInSlowUploadCooldown` used to
    /// gate `FindBestClientInQueue` (`UploadQueue.cpp:228`). A friend slot is
    /// never suppressed (`ShouldApplyUploadRetryCooldown` `!bFriendSlot`).
    pub(super) fn is_cooled(&self, ip: IpAddr, friend: bool, now: Instant) -> bool {
        self.cooldown_until(ip, friend, now).is_some()
    }

    /// Remaining time on the strongest active cooldown for `ip`, for cooldown-
    /// probe ordering (`GetSlowUploadCooldownRemaining`, lowest-remaining first).
    pub(super) fn cooldown_remaining(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        self.cooldown_until(ip, false, now)
            .map(|until| until.saturating_duration_since(now))
    }

    /// Whether a cooled-down `ip` may be re-promoted as a last-resort underfill
    /// refill (`CanProbeUploadCooldownCandidate` +
    /// `ShouldProbeNoRequestCooldownCandidate`, `UploadQueue.cpp:1212-1239`):
    /// only an IP under an ACTIVE no-request cooldown is probeable, and only
    /// while `open_base_slot_underfill` (spare room below the base slot target).
    /// A pure retry/slow/churn cooldown is a hard gate and is never probed.
    pub(super) fn can_probe(&self, ip: IpAddr, now: Instant, open_base_slot_underfill: bool) -> bool {
        if self.cooldown_until(ip, false, now).is_none() {
            return false;
        }
        self.no_request_by_ip
            .get(&ip)
            .is_some_and(|state| state.until > now)
            && open_base_slot_underfill
    }

    /// Seed the short churn cooldown used by the failed-admission, no-socket,
    /// and short-failed / remote-cancelled paths
    /// (`GetUploadChurnRetryCooldownSecondsForBudget`, `UploadQueue.cpp:335,855,2188`).
    pub(super) fn set_churn_cooldown(&mut self, ip: IpAddr, friend: bool, budget: u64, now: Instant) {
        let secs = self.churn_retry_cooldown_secs(budget);
        self.apply_retry_cooldown(ip, friend, secs, now);
    }

    /// Seed the slow-upload recycle cooldown
    /// (`GetSlowUploadRetryCooldownSecondsForBudget`, `UploadQueue.cpp:2358`).
    pub(super) fn set_slow_cooldown(&mut self, ip: IpAddr, friend: bool, budget: u64, now: Instant) {
        let secs = self.slow_retry_cooldown_secs(budget);
        self.apply_retry_cooldown(ip, friend, secs, now);
    }

    /// Register one no-request upload-slot recycle for `(ip, hash)` and return
    /// whether the offender must be banned (past a strike threshold) or was put
    /// on a cooldown. Mirrors `TrackNoRequestRepeatOffender` +
    /// `ShouldBanNoRequestRepeatOffender` + the cooldown application
    /// (`UploadQueue.cpp:1305-1656`). `productive` short-circuits the strike
    /// path with a short productive cooldown (a client that made a burst then
    /// drained is not a repeat offender).
    pub(super) fn register_no_request_recycle(
        &mut self,
        ip: IpAddr,
        hash: Option<[u8; 16]>,
        friend: bool,
        budget: u64,
        now: Instant,
        productive: bool,
    ) -> NoRequestRecycleOutcome {
        if productive {
            let secs = self.min_base(self.productive_no_request_cap(budget));
            self.apply_no_request_cooldown(ip, friend, secs, now, true);
            return NoRequestRecycleOutcome {
                strikes: 0,
                ban: CooldownBan::None,
            };
        }

        let window_until = now + STRIKE_WINDOW;
        let valid_hash = hash.filter(|h| h != &[0u8; 16]);
        let mut should_ip_ban = false;
        let strikes = if let Some(h) = valid_hash {
            let state = self
                .strikes_by_hash
                .entry(h)
                .or_insert(StrikeState { strikes: 0, window_until });
            if state.window_until <= now {
                state.strikes = 0;
            }
            state.window_until = window_until;
            state.strikes += 1;
            let strikes = state.strikes;

            let rotation = self
                .hash_rotation_by_ip
                .entry(ip)
                .or_insert_with(|| IpHashRotationState {
                    hash_keys: HashSet::new(),
                    total_strikes: 0,
                    window_until,
                });
            if rotation.window_until <= now {
                rotation.hash_keys.clear();
                rotation.total_strikes = 0;
            }
            rotation.window_until = window_until;
            rotation.total_strikes += 1;
            rotation.hash_keys.insert(h);
            should_ip_ban = rotation.hash_keys.len() as u32 >= HASH_ROTATION_BAN_THRESHOLD
                && rotation.total_strikes >= HASH_ROTATION_STRIKE_THRESHOLD;
            strikes
        } else {
            let state = self
                .strikes_by_ip
                .entry(ip)
                .or_insert(StrikeState { strikes: 0, window_until });
            if state.window_until <= now {
                state.strikes = 0;
            }
            state.window_until = window_until;
            state.strikes += 1;
            state.strikes
        };

        let should_ban = strikes >= self.ban_threshold(budget);
        if should_ban || should_ip_ban {
            // Banned: no cooldown is seeded; the caller drops the peer and bans
            // it (`client->Ban(...); return true;`, UploadQueue.cpp:1639-1650).
            let ban = if should_ip_ban {
                CooldownBan::Both
            } else if valid_hash.is_some() {
                CooldownBan::ByHash
            } else {
                CooldownBan::ByIp
            };
            return NoRequestRecycleOutcome { strikes, ban };
        }

        let secs = self.repeat_cooldown_secs(strikes, budget);
        self.apply_no_request_cooldown(ip, friend, secs, now, false);
        NoRequestRecycleOutcome {
            strikes,
            ban: CooldownBan::None,
        }
    }

    /// Reclaim expired cooldown entries and, on a throttled cadence, expired
    /// strike-window entries (`PurgeExpiredUploadRetryCooldowns`,
    /// `UploadQueue.cpp:1456-1495`). Cooldown lookups already treat an expired
    /// `until` as not-cooled, so this is a memory reclaim.
    pub(super) fn purge_expired(&mut self, now: Instant) {
        self.retry_by_ip.retain(|_, state| state.track_until > now);
        self.no_request_by_ip.retain(|_, state| state.track_until > now);
        if self
            .last_cleanup
            .is_some_and(|last| now < last + CLEANUP_INTERVAL)
        {
            return;
        }
        self.last_cleanup = Some(now);
        self.strikes_by_hash.retain(|_, state| state.window_until > now);
        self.strikes_by_ip.retain(|_, state| state.window_until > now);
        self.hash_rotation_by_ip
            .retain(|_, state| state.window_until > now);
    }

    fn cooldown_until(&self, ip: IpAddr, friend: bool, now: Instant) -> Option<Instant> {
        if friend {
            return None;
        }
        let retry = self
            .retry_by_ip
            .get(&ip)
            .map(|state| state.until)
            .filter(|until| *until > now);
        let no_request = self
            .no_request_by_ip
            .get(&ip)
            .map(|state| state.until)
            .filter(|until| *until > now);
        match (retry, no_request) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    fn apply_retry_cooldown(&mut self, ip: IpAddr, friend: bool, secs: u32, now: Instant) {
        if friend || secs == 0 {
            return;
        }
        let until = now + Duration::from_secs(u64::from(secs));
        self.retry_by_ip.insert(
            ip,
            RetryCooldownState {
                until,
                track_until: until,
            },
        );
    }

    fn apply_no_request_cooldown(
        &mut self,
        ip: IpAddr,
        friend: bool,
        secs: u32,
        now: Instant,
        productive: bool,
    ) {
        if friend || secs == 0 {
            return;
        }
        let until = now + Duration::from_secs(u64::from(secs));
        // Track window extends past the cooldown by the base cooldown so a
        // repeat within `secs + base` is still detected as recent
        // (`GetNoRequestUploadRetryTrackSeconds`, UploadQueueSeams.h:492-497).
        let track_until =
            now + Duration::from_secs(u64::from(secs) + u64::from(self.base_cooldown_secs));
        self.retry_by_ip.insert(
            ip,
            RetryCooldownState {
                until,
                track_until: until,
            },
        );
        self.no_request_by_ip.insert(
            ip,
            NoRequestCooldownState {
                until,
                track_until,
                productive,
            },
        );
    }

    fn min_base(&self, cap: u32) -> u32 {
        self.base_cooldown_secs.min(cap)
    }

    fn is_broadband(budget: u64) -> bool {
        budget >= BROADBAND_UPLOAD_BUDGET_BYTES_PER_SEC
    }

    fn productive_no_request_cap(&self, budget: u64) -> u32 {
        if Self::is_broadband(budget) {
            BROADBAND_PRODUCTIVE_NO_REQUEST_COOLDOWN_MAX_SECS
        } else {
            PRODUCTIVE_NO_REQUEST_COOLDOWN_MAX_SECS
        }
    }

    fn repeat_no_request_cap(budget: u64) -> u32 {
        if Self::is_broadband(budget) {
            BROADBAND_REPEATED_NO_REQUEST_COOLDOWN_MAX_SECS
        } else {
            REPEATED_NO_REQUEST_COOLDOWN_MAX_SECS
        }
    }

    fn ban_threshold(&self, budget: u64) -> u32 {
        if Self::is_broadband(budget) {
            BAN_THRESHOLD_BROADBAND
        } else {
            BAN_THRESHOLD_STANDARD
        }
    }

    /// `GetSlowUploadRetryCooldownSecondsForBudget`: broadband caps the base at
    /// 90s, otherwise the base passes through (`UploadQueueSeams.h:228-238`).
    fn slow_retry_cooldown_secs(&self, budget: u64) -> u32 {
        if Self::is_broadband(budget) {
            self.base_cooldown_secs
                .min(BROADBAND_SLOW_UPLOAD_RETRY_COOLDOWN_MAX_SECS)
        } else {
            self.base_cooldown_secs
        }
    }

    /// `GetUploadChurnRetryCooldownSecondsForBudget`: the slow-retry value, then
    /// clamped to the 120s churn ceiling (`UploadQueueSeams.h:240-250`).
    fn churn_retry_cooldown_secs(&self, budget: u64) -> u32 {
        self.slow_retry_cooldown_secs(budget)
            .min(CHURN_RETRY_COOLDOWN_MAX_SECS)
    }

    /// `GetNoRequestRepeatCooldownSeconds`: exponential doubling from the base,
    /// capped at the smaller of the budget repeat cap and the 3600s absolute
    /// ceiling (`UploadQueueSeams.h:499-511`).
    pub(super) fn repeat_cooldown_secs(&self, strikes: u32, budget: u64) -> u32 {
        let cap = Self::repeat_no_request_cap(budget).min(REPEAT_COOLDOWN_MAX_SECS);
        if strikes == 0 || self.base_cooldown_secs == 0 || cap == 0 {
            return 0;
        }
        let mut secs = u64::from(self.base_cooldown_secs);
        let cap64 = u64::from(cap);
        let mut strike = 1u32;
        while strike < strikes && secs < cap64 {
            secs *= 2;
            strike += 1;
        }
        secs.min(cap64) as u32
    }
}
