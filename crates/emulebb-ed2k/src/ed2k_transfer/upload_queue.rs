use std::{
    collections::{HashMap, VecDeque},
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use super::upload_cooldown::{CooldownBan, UploadCooldownTracker};
use crate::ban_store::BanStore;

const DEFAULT_FILE_PRIORITY_SCORE: i128 = 7;
const VERY_LOW_FILE_PRIORITY_SCORE: i128 = 2;
const LOW_FILE_PRIORITY_SCORE: i128 = 6;
const HIGH_FILE_PRIORITY_SCORE: i128 = 9;
const RELEASE_FILE_PRIORITY_SCORE: i128 = 18;
const FRIEND_SLOT_SCORE_BONUS: i128 = 1_000_000_000;
const UPLOAD_SESSION_SERVED_RANGE_HISTORY: usize = 128;
pub(super) const DEFAULT_CREDIT_SCORE_PERMILLE: i128 = 1_000;

/// Sentinel all-time upload ratio (permille) used for an unknown requested file:
/// at/above the low-ratio threshold so the low-ratio score bonus is NOT applied,
/// mirroring eMule's `GetScoreBreakdown` early return for `pRequestedFile ==
/// NULL` (an unknown file never reaches the bonus).
pub(super) const LOW_RATIO_BONUS_DISABLED_RATIO_PERMILLE: i128 = 1_000;

/// eMule default soft queue size (`PreferenceValidationSeams::kDefaultQueueSize`),
/// the threshold the reask QUEUEFULL margin compares against.
pub(crate) const DEFAULT_SOFT_QUEUE_SIZE: u32 = 10_000;
/// eMule `MAX_PURGEQUEUETIME` (`Opcodes.h`) for stale waiting upload clients.
const DEFAULT_WAITING_TIMEOUT_SECS: u64 = 60 * 60;
/// Oracle default per-session transfer cap: 90% of the requested file
/// (`PreferenceValidationSeams::kDefaultSessionTransferPercent`, percent-of-file
/// session-transfer mode).
const DEFAULT_SESSION_TRANSFER_PERCENT: u32 = 90;
/// Oracle default per-session slot time cap: 7200 s
/// (`PreferenceValidationSeams::kDefaultSessionTimeLimitSeconds`).
const DEFAULT_SESSION_TIME_LIMIT_SECS: u64 = 7_200;

/// Minimum concurrent upload slots that always open immediately, regardless of
/// the slot-open pacing gate (oracle `MIN_UP_CLIENTS_ALLOWED`, Opcodes.h:107):
/// `ForceNewClient` returns true below this count before it reaches the 1/sec
/// gate (UploadQueue.cpp:969-970), so the base slots fill without pacing.
const MIN_UP_CLIENTS_ALLOWED: usize = 2;
/// Minimum interval between opening successive upload slots while the aggregate
/// upload datarate is below the busy-pipe threshold (oracle `m_nLastStartUpload
/// + SEC2MS(1)` gate, UploadQueue.cpp:972): at most one new slot per second.
const UPLOAD_SLOT_OPEN_MIN_INTERVAL: Duration = Duration::from_secs(1);
/// Aggregate upload datarate (bytes/sec) at/above which the 1/sec slot-open
/// pacing gate is bypassed and new slots may burst open (oracle `datarate <
/// 102400` short-circuit, UploadQueue.cpp:972): once the pipe is already busy the
/// fork stops throttling slot opens.
const UPLOAD_SLOT_OPEN_BURST_DATARATE_BYTES_PER_SEC: u64 = 102_400;
/// Sustained-underfill window before a slow/idle active upload slot is RECYCLED
/// (oracle `HasSustainedBroadbandUnderfill` = `m_ullBroadbandUnderfillSince +
/// SEC2MS(2)`, UploadQueue.cpp:1047-1050): the slow/idle recycle path
/// (`ShouldTrackSlowUploadSlots`, UploadQueue.cpp:1114) fires at 2 s. This is a
/// FIXED constant matching the fork's `SEC2MS(2)`, distinct from the config-driven
/// 10 s elastic slot-OPEN window (`HasSustainedElasticBroadbandUnderfill`,
/// UploadQueue.cpp:1052-1055; the `elastic_underfill` config).
const SLOW_RECYCLE_UNDERFILL_WINDOW: Duration = Duration::from_secs(2);

/// Short-failed upload-slot churn thresholds (oracle
/// `ShouldCooldownShortFailedUploadSlot`, UploadQueueSeams.h:644-659 with
/// `kShortFailedUploadCooldownMaxAgeMs` = 30000 and
/// `kShortFailedUploadCooldownMaxPayloadBytes` = 1 MiB): an ACTIVE upload slot
/// removed by a disconnect that was aged <= 30 s AND had served <= 1 MB is the
/// "grabbed a slot then bailed" churn signal, and its IP is put on the churn
/// retry cooldown. The 90 s `kRemoteCancelledUploadCooldownMaxAgeMs` age variant
/// only extends the window for a distinct "remote client cancelled transfer"
/// removal; rust's connection-per-op teardown surfaces every disconnect through
/// the same path with no separate cancel signal, so we apply the base 30 s
/// short-failed criteria only (a stricter subset -- it never over-cools).
const SHORT_FAILED_UPLOAD_COOLDOWN_MAX_AGE: Duration = Duration::from_secs(30);
const SHORT_FAILED_UPLOAD_COOLDOWN_MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;

/// Upload-slot and waiting-queue policy used by the inbound ED2K listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ed2kUploadQueueConfig {
    /// Baseline number of concurrently granted upload sessions.
    pub active_slots: usize,
    /// Percent of additional elastic slots allowed above the baseline.
    pub elastic_percent: u32,
    /// Global upload payload budget. Zero disables rate-aware elasticity.
    pub upload_limit_bytes_per_sec: u64,
    /// Required spare upload budget before opening elastic slots.
    pub elastic_underfill_bytes_per_sec: u64,
    /// Sustained underfill window before elastic slots may open.
    pub elastic_underfill: Duration,
    /// Maximum number of queued waiters retained at once (structural cap).
    pub waiting_capacity: usize,
    /// Configured soft queue size (`thePrefs.GetQueueSize()`, eMule default
    /// 10000): the threshold the reask QUEUEFULL margin compares against
    /// (`GetWaitingUserCount() + 50 > GetQueueSize()`). Distinct from the
    /// structural `waiting_capacity`, which is a much smaller retention bound.
    pub soft_queue_size: u32,
    /// Maximum idle time for a queued waiter before it is discarded.
    pub waiting_timeout: Duration,
    /// Maximum stall time after grant before the peer requests data.
    pub granted_timeout: Duration,
    /// Maximum idle time while a peer already has an active upload slot.
    pub upload_timeout: Duration,
    /// Per-session transferred-bytes cap as a percent of the requested file's
    /// size (oracle session-transfer limit, percent-of-file mode,
    /// `ResolveSessionTransferLimitBytes`, UploadQueue.cpp:137-149). A capped
    /// session rotates back to the waiting queue (`CheckForTimeOver`,
    /// UploadQueue.cpp:2407-2438). 0 disables the byte cap.
    pub session_transfer_percent: u32,
    /// Per-session wall-clock slot time cap (oracle session time limit,
    /// `CheckForTimeOver`, UploadQueue.cpp:2440-2467). Zero disables the cap.
    pub session_time_limit: Duration,
}

impl Default for Ed2kUploadQueueConfig {
    fn default() -> Self {
        Self {
            active_slots: 3,
            elastic_percent: 0,
            upload_limit_bytes_per_sec: 0,
            elastic_underfill_bytes_per_sec: 0,
            elastic_underfill: Duration::from_secs(10),
            waiting_capacity: 512,
            soft_queue_size: DEFAULT_SOFT_QUEUE_SIZE,
            waiting_timeout: Duration::from_secs(DEFAULT_WAITING_TIMEOUT_SECS),
            granted_timeout: Duration::from_secs(30),
            upload_timeout: Duration::from_secs(90),
            session_transfer_percent: DEFAULT_SESSION_TRANSFER_PERCENT,
            session_time_limit: Duration::from_secs(DEFAULT_SESSION_TIME_LIMIT_SECS),
        }
    }
}

/// Stable peer identity used to keep uploader queue decisions deterministic.
#[derive(Debug, Clone)]
pub(crate) struct Ed2kUploadPeerIdentity {
    /// Remote peer IP address.
    pub ip: IpAddr,
    /// Remote peer TCP port advertised in hello or observed on the socket.
    pub tcp_port: u16,
    /// Peer eD2k client UDP port (low 16 of `CT_EMULE_UDPPORTS`), when advertised:
    /// correlates inbound reask by `(ip, udp_port)` (eMule `GetWaitingClientByIP_UDP`).
    pub udp_port: Option<u16>,
    /// Peer eD2k UDP version (`OP_EMULEINFO` ET_UDPVER); gates reask-ack partstatus.
    pub udp_version: u8,
    /// Obfuscate UDP reasks to this peer (its TCP session was obfuscated).
    pub should_crypt: bool,
    /// Remote peer user hash when known.
    pub user_hash: Option<[u8; 16]>,
    /// Remote peer client-id when known.
    pub client_id: Option<u32>,
    /// Whether local policy has granted this peer the stock friend-slot fast path.
    pub friend_slot: bool,
    /// Whether the peer's secure-ident signature was RSA-verified (eMule
    /// `IS_IDENTIFIED`); only a verified peer's credit ratio benefits its score
    /// (`GetScoreRatio` neutral 1.0 otherwise). Excluded from identity eq/hash.
    pub ident_verified: bool,
    /// Whether the peer presented a secure-ident public key + signature that
    /// FAILED RSA verification (eMule `IS_IDBADGUY`): its upload score is zeroed
    /// (`GetScoreBreakdown` early return). Distinct from `!ident_verified`, which
    /// merely denies the credit benefit; a bad-guy is actively penalised.
    /// Excluded from identity eq/hash.
    pub ident_bad_guy: bool,
    /// Whether the peer's advertised mod-version matches the known GPL-breaker
    /// blacklist (eMule `m_bGPLEvildoer`, `CheckForGPLEvilDoer`): its upload
    /// score is zeroed. Excluded from identity eq/hash.
    pub gpl_evildoer: bool,
    /// Whether the peer is on the local ban list (eMule `IsBanned()`): its upload
    /// score is zeroed. Excluded from identity eq/hash.
    pub banned: bool,
    /// Peer eMule compatibility version byte (eMule `m_byEmuleVersion`, from the
    /// OP_EMULEINFO leading byte; `0x99` for a CT_EMULE_VERSION-only mule hello,
    /// `0` for a non-mule client). Feeds the old-client score penalty. Excluded
    /// from identity eq/hash.
    pub emule_version: u8,
    /// Whether the peer identified as an eMule-family client (sent a mule hello /
    /// OP_EMULEINFO). Part of the old-client penalty predicate (eMule
    /// `IsEmuleClient() || GetClientSoft() < 10`). Excluded from identity eq/hash.
    pub is_emule_client: bool,
    /// Peer's Kad UDP port (eMule `GetKadPort()`, high 16 of CT_EMULE_UDPPORTS);
    /// `0` when not Kad-reachable. A Kad-reachable peer is exempt from the
    /// firewalled-LowID callback admission guard. Excluded from identity eq/hash.
    pub kad_port: u16,
    /// Whether the peer advertised MISCOPTIONS2 bit 12 (eMule
    /// `SupportsDirectUDPCallback()`): a firewalled peer whose UDP is open+verified,
    /// reachable via `OP_DIRECTCALLBACKREQ`. Lets the upload-promote driver hand a
    /// slot to a LowID waiter by asking it to TCP-connect back (master
    /// `TryToConnect` CCS_DIRECTCALLBACK, BaseClient.cpp:1478). Excluded from
    /// identity eq/hash.
    pub supports_direct_udp_callback: bool,
    /// Our-side firewalled-LowID callback admission context, set per-connection by
    /// the listener from the live server/Kad firewall state (master
    /// `AddClientToQueue` opening guard). Transient; excluded from identity
    /// eq/hash. Defaults to a non-firewalled state, so the guard never fires until
    /// the listener supplies real state.
    pub firewall_context: Ed2kUploadFirewallContext,
    /// Peer software string from the HELLO CT_EMULE_VERSION tag (e.g.
    /// `eMule v0.60.0`); display-only, excluded from identity eq/hash.
    pub client_software: Option<String>,
}

impl PartialEq for Ed2kUploadPeerIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip
            && self.tcp_port == other.tcp_port
            && self.user_hash == other.user_hash
            && self.client_id == other.client_id
    }
}

impl Eq for Ed2kUploadPeerIdentity {}

impl Hash for Ed2kUploadPeerIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip.hash(state);
        self.tcp_port.hash(state);
        self.user_hash.hash(state);
        self.client_id.hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct Ed2kUploadSessionKey {
    peer: Ed2kUploadPeerIdentity,
    file_hash: String,
}

/// Opaque handle bound to one live uploader transport session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ed2kUploadSessionHandle {
    key: Ed2kUploadSessionKey,
    connection_id: u64,
}

impl Ed2kUploadSessionHandle {
    pub(super) fn new(peer: Ed2kUploadPeerIdentity, file_hash: String, connection_id: u64) -> Self {
        Self {
            key: Ed2kUploadSessionKey { peer, file_hash },
            connection_id,
        }
    }

    pub(super) const fn key(&self) -> &Ed2kUploadSessionKey {
        &self.key
    }

    /// Hex file-hash this session's slot/waiter is keyed on. Used at session
    /// release to drain any parked shared-catalog demand-upload bytes for the
    /// served file (RUST-PAR-025 Note-1).
    pub(super) fn file_hash_hex(&self) -> &str {
        &self.key.file_hash
    }
}

/// One granted upload slot whose peer had no live connection at promotion:
/// the promote-connect driver must dial the peer's advertised endpoint and
/// push OP_ACCEPTUPLOADREQ after the handshake (master `AddUpNextClient`,
/// UploadQueue.cpp:327-361; `ConnectionEstablished`, BaseClient.cpp:1634-1641).
/// The handle owns the session: releasing it on a failed connect drops the
/// grant like the master's failed `TryToConnect` path.
#[derive(Debug, Clone)]
pub(crate) struct Ed2kUploadPendingPromotion {
    pub(crate) peer: Ed2kUploadPeerIdentity,
    pub(crate) file_hash: String,
    pub(crate) handle: Ed2kUploadSessionHandle,
}

/// Queue-visible state of one inbound upload session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ed2kUploadSessionStatus {
    /// The peer is queued and should see a rank.
    Waiting { rank: u16 },
    /// The peer currently owns an upload slot.
    Granted,
    /// The session expired, was cancelled, or was replaced by a reconnect.
    Stale,
    /// Admission was refused (queue full at the hard limit, a low-score
    /// candidate past the soft limit, or too many waiters from the same IP),
    /// mirroring the master `CUploadQueue::AddClientToQueue` early returns. The
    /// listener treats this like `Stale` and closes the session.
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ed2kUploadRangeAdmission {
    Accepted,
    DuplicateDone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ed2kUploadSessionPhase {
    Waiting,
    Granted,
    Uploading,
}

/// Queue-visible upload session phase for management surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed2kUploadSessionPhaseSnapshot {
    Waiting,
    Granted,
    Uploading,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ed2kUploadServedRange {
    start: u64,
    end: u64,
}

/// Read-only snapshot of one inbound upload queue session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kUploadQueueSnapshotEntry {
    pub ip: IpAddr,
    pub tcp_port: u16,
    /// Reask correlation/framing mirrored from the peer identity (see that struct).
    pub udp_port: Option<u16>,
    pub udp_version: u8,
    pub should_crypt: bool,
    pub user_hash: Option<[u8; 16]>,
    pub client_id: Option<u32>,
    pub friend_slot: bool,
    pub file_hash: String,
    /// Whether a live connection currently owns this entry: a disconnected
    /// waiter is kept on the queue (BaseClient.cpp:1229) with `connected: false`
    /// until it re-asks or is dialed for a slot grant.
    pub connected: bool,
    pub phase: Ed2kUploadSessionPhaseSnapshot,
    pub queue_rank: Option<u16>,
    pub wait_time_ms: u64,
    pub uploaded_bytes: u64,
    pub upload_speed_bytes_per_sec: u64,
    /// Computed upload-queue score for this peer.
    pub score: i128,
    /// File-priority component of the score.
    pub file_priority_score: i128,
    /// Credit-ratio component, in permille (1000 == neutral 1.0x).
    pub credit_score_permille: i128,
    pub low_ratio_applied: bool,
    pub low_ratio_bonus: u32,
    pub low_id_penalty_applied: bool,
    pub low_id_divisor: u32,
    pub old_client_penalty_applied: bool,
    /// Peer software string (HELLO CT_EMULE_VERSION), display-only.
    pub client_software: Option<String>,
}

#[derive(Debug, Clone)]
struct Ed2kUploadSessionEntry {
    phase: Ed2kUploadSessionPhase,
    connection_id: u64,
    /// Whether a live connection currently owns this session. A waiter whose
    /// connection dropped keeps its queue entry (master `Disconnected` keeps
    /// US_ONUPLOADQUEUE clients, BaseClient.cpp:1229) but is `connected = false`
    /// until it re-asks or the promote-connect driver dials it for a slot grant.
    connected: bool,
    queued_at: Instant,
    last_activity: Instant,
    waiting_sequence: u64,
    file_priority_score: i128,
    credit_score_permille: i128,
    /// Per-session upload-score modifiers (LowID, bad-guy/banned/GPL zeroing,
    /// old-client penalty, low-ratio bonus), captured at admission.
    score_modifiers: UploadScoreModifiers,
    /// Size of the requested file, feeding the per-session transfer cap
    /// (oracle `ResolveSessionTransferLimitBytes` reads
    /// `CKnownFile::GetFileSize`, UploadQueue.cpp:137-149). 0 = unknown file,
    /// which disables the byte cap like the oracle's NULL-file early return.
    file_size: u64,
    uploaded_bytes: u64,
    upload_started_at: Option<Instant>,
    served_ranges: VecDeque<Ed2kUploadServedRange>,
    /// Per-slot sliding-window upload datarate meter (RUST-PAR-024 GAP-1): the
    /// 10 s per-client window (oracle `m_AverageUDR_hist`,
    /// UploadClient.cpp:860-878). Reset on recycle so a re-promoted slot starts a
    /// fresh window.
    rate_meter: WindowedRateMeter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ed2kUploadRecycleDiagnostics {
    reason: &'static str,
    slot_age_ms: u64,
    idle_ms: u64,
    uploaded_bytes: u64,
    slot_rate_bytes_per_sec: u64,
}

/// Rate-aware upload slot capacity state for diagnostics and policy tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed2kUploadQueueCapacitySnapshot {
    pub base_slots: usize,
    pub elastic_slots: usize,
    pub active_slots: usize,
    pub active_sessions: usize,
    pub waiting_sessions: usize,
    pub active_granted_sessions: usize,
    pub active_uploading_sessions: usize,
    pub active_never_uploaded_sessions: usize,
    pub active_productive_sessions: usize,
    pub upload_rate_bytes_per_sec: u64,
    pub upload_limit_bytes_per_sec: u64,
    pub elastic_underfill_bytes_per_sec: u64,
    pub elastic_underfill: bool,
    pub underfill_since_ms: Option<u64>,
}

/// Global upload-rate reservation result for listener payload writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed2kUploadThrottleReservation {
    pub delay: Duration,
}

/// Our-side network state for the firewalled-LowID callback admission guard
/// (master `AddClientToQueue` opening check). Plumbed from the listener: whether
/// we are connected to any network, whether we are TCP-firewalled (LowID), and
/// whether the candidate peer is on the same server we are connected to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Ed2kUploadFirewallContext {
    pub we_are_connected: bool,
    pub we_are_firewalled: bool,
    pub peer_on_same_server: bool,
}

#[derive(Debug)]
pub(super) struct Ed2kUploadQueueState {
    config: Ed2kUploadQueueConfig,
    sessions: HashMap<Ed2kUploadSessionKey, Ed2kUploadSessionEntry>,
    waiting_order: Vec<Ed2kUploadSessionKey>,
    /// Slots granted to waiters with no live connection, awaiting the
    /// promote-connect driver's outbound connect + OP_ACCEPTUPLOADREQ (master
    /// AddUpNextClient connect-out, UploadQueue.cpp:327-361).
    pending_promotions: Vec<Ed2kUploadSessionKey>,
    next_waiting_sequence: u64,
    underfill_since: Option<Instant>,
    /// Wall-clock instant of the most recent slot open (grant or promotion): the
    /// analog of the oracle `m_nLastStartUpload` stamped on every AddUpNextClient
    /// (UploadQueue.cpp:370). Drives the 1/sec slot-open pacing gate.
    last_slot_open: Option<Instant>,
    throttle_next_send_at: Option<Instant>,
    /// Per-IP upload anti-abuse cooldown + no-request repeat-offender strike
    /// tracker (RUST-PAR-020 U-GAP3). Gates slot promotion and drives the
    /// repeat-offender ban.
    cooldown: UploadCooldownTracker,
    /// Shared client ban list the no-request repeat-offender ban is wired to
    /// (`client->Ban(...)` -> `CClientList::AddBannedClient`, UploadQueue.cpp:1640).
    /// `None` in the queue-state unit tests that do not exercise banning.
    ban_store: Option<Arc<BanStore>>,
    /// Aggregate sliding-window upload datarate meter (RUST-PAR-024 GAP-1): the
    /// 30 s whole-queue window (oracle `average_ur_hist` + `datarate`,
    /// UploadQueue.cpp:923-931/2761-2764). Fed on every payload note across all
    /// slots; read by the slot-open pace gate and the elastic-underfill gate.
    aggregate_rate_meter: WindowedRateMeter,
}

impl Ed2kUploadQueueState {
    pub(super) fn new(config: Ed2kUploadQueueConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            waiting_order: Vec::new(),
            pending_promotions: Vec::new(),
            next_waiting_sequence: 1,
            underfill_since: None,
            last_slot_open: None,
            throttle_next_send_at: None,
            cooldown: UploadCooldownTracker::new(),
            ban_store: None,
            aggregate_rate_meter: WindowedRateMeter::new(AGGREGATE_RATE_WINDOW),
        }
    }

    /// Attach the shared ban store so a no-request repeat offender that crosses
    /// the strike threshold is added to the client ban list.
    pub(super) fn set_ban_store(&mut self, ban_store: Arc<BanStore>) {
        self.ban_store = Some(ban_store);
    }

    pub(super) fn configure(&mut self, config: Ed2kUploadQueueConfig) {
        self.config = config;
        self.throttle_next_send_at = None;
        let now = Instant::now();
        self.reap_expired_sessions(now);
        self.trim_waiting_queue(now);
        self.promote_waiters(now);
    }

    pub(super) const fn config(&self) -> Ed2kUploadQueueConfig {
        self.config
    }

    pub(super) fn capacity_snapshot(&mut self, now: Instant) -> Ed2kUploadQueueCapacitySnapshot {
        self.reap_expired_sessions(now);
        self.refresh_elastic_underfill(now);
        let snapshot = Ed2kUploadQueueCapacitySnapshot {
            base_slots: self.config.active_slots.max(1),
            elastic_slots: self.elastic_slot_allowance(),
            active_slots: self.effective_active_slot_limit(now),
            active_sessions: self.active_session_count(),
            waiting_sessions: self.waiting_session_count(),
            active_granted_sessions: self.active_granted_session_count(),
            active_uploading_sessions: self.active_uploading_session_count(),
            active_never_uploaded_sessions: self.active_never_uploaded_session_count(),
            active_productive_sessions: self.active_productive_session_count(),
            upload_rate_bytes_per_sec: self.upload_rate_bytes_per_sec(now),
            upload_limit_bytes_per_sec: self.config.upload_limit_bytes_per_sec,
            elastic_underfill_bytes_per_sec: self.config.elastic_underfill_bytes_per_sec,
            elastic_underfill: self.elastic_underfill_ready(now),
            underfill_since_ms: self.underfill_since.map(|since| {
                now.saturating_duration_since(since)
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX)
            }),
        };
        super::diag_sched::capacity_snapshot(
            snapshot.base_slots,
            snapshot.elastic_slots,
            snapshot.active_slots,
            snapshot.active_sessions,
            snapshot.waiting_sessions,
            snapshot.active_granted_sessions,
            snapshot.active_uploading_sessions,
            snapshot.active_never_uploaded_sessions,
            snapshot.active_productive_sessions,
            snapshot.upload_rate_bytes_per_sec,
            snapshot.upload_limit_bytes_per_sec,
            snapshot.elastic_underfill_bytes_per_sec,
            snapshot.elastic_underfill,
            snapshot.underfill_since_ms,
        );
        snapshot
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "flat protocol or runtime boundary"
    )] // flat per-admission inputs, mirroring the oracle call
    pub(super) fn begin_session(
        &mut self,
        key: Ed2kUploadSessionKey,
        connection_id: u64,
        now: Instant,
        file_priority_score: i128,
        credit_score_permille: i128,
        all_time_upload_ratio_permille: i128,
        file_size: u64,
    ) -> Ed2kUploadSessionStatus {
        self.reap_expired_sessions(now);
        // Banned-peer admission gate (master `AddClientToQueue`, UploadQueue.cpp:1854
        // `if (client->IsBanned()) return;`): a banned client is refused BEFORE any
        // queue entry is created or ranking reply is emitted -- the master returns
        // silently ahead of the duplicate/re-ask loop. Rejected keeps the listener
        // silent and retains no session. This is the earlier admission gate; the
        // round-17 banned-recycle path (d83c02b) separately suppresses
        // OP_OUTOFPARTREQS for a banned peer already holding a slot.
        if key.peer.banned {
            return Ed2kUploadSessionStatus::Rejected;
        }
        let low_id = key.peer.client_id.is_some_and(is_low_id_client_id);
        let score_modifiers =
            UploadScoreModifiers::from_peer(&key.peer, low_id, all_time_upload_ratio_permille);
        if let Some(existing_key) = self.session_key_for_peer(&key.peer) {
            let Some(mut session) = self.sessions.remove(&existing_key) else {
                unreachable!("existing peer queue key missing from session map");
            };
            if session.phase == Ed2kUploadSessionPhase::Waiting {
                self.replace_waiting_key(&existing_key, &key);
            }
            if existing_key.file_hash != key.file_hash {
                session.served_ranges.clear();
            }
            session.connection_id = connection_id;
            // Re-ask on a persisted entry: rebind the live connection and refresh
            // the last-request time, but keep `queued_at` (wait-start) so the
            // accumulated waiting score survives a reconnect (master re-ask on the
            // same queue entry, UploadQueue.cpp:1865-1869).
            session.connected = true;
            session.last_activity = now;
            session.file_priority_score = file_priority_score;
            session.credit_score_permille = credit_score_permille;
            session.score_modifiers = score_modifiers;
            session.file_size = file_size;
            self.sessions.insert(key.clone(), session);
            return self.status_for_key(&key, now);
        }

        self.refresh_elastic_underfill(now);
        // RUST-PAR-020 U-GAP3: a cooled-down peer is NOT granted a slot inline
        // even when one is free -- the fork routes every requester through the
        // waiting list and `FindBestClientInQueue` skips a cooled client
        // (UploadQueue.cpp:228), so a reconnecting abuser cannot bypass its
        // cooldown by racing a free slot. It joins the queue and is gated by the
        // same cooldown (or re-promoted via the cooldown probe) until it expires.
        let slot_free = self.active_session_count() < self.effective_active_slot_limit(now);
        let cooled = self
            .cooldown
            .is_cooled(key.peer.ip, key.peer.friend_slot, now);
        // RUST-PAR-021 GAP1 (corrects the round-20 U-GAP1 residual): the inline
        // grant to a just-connecting peer must respect BOTH the 1/sec slot-open
        // pace AND the ranked waiting queue, exactly like the oracle's paced+ranked
        // `ForceNewClient` -> `AddUpNextClient` in `Process`
        // (UploadQueue.cpp:811-823,960-979), which opens ONE slot per tick for the
        // BEST waiting client (`FindBestClientInQueue`). The fork never inline-grants
        // a just-connected client ahead of the queue and never opens faster than the
        // pace. So a free slot is granted inline only when the pace allows a new open
        // now (`slot_open_paced`) AND no higher-ranked admissible waiter is already
        // queued (`best_admissible_waiting_key` is empty). Otherwise this peer is
        // admitted to the waiting queue at its ranked position and the paced
        // `promote_waiters` picks the best candidate -- so a pace-deferred slot can
        // never be opened early by an arrival, and a low-ranked newcomer can never
        // jump a higher-ranked paced waiter.
        let inline_grant = slot_free
            && !cooled
            && self.slot_open_paced(now)
            && self.best_admissible_waiting_key(now).is_none();
        let phase = if inline_grant {
            Ed2kUploadSessionPhase::Granted
        } else {
            // No inline grant: this peer joins the waiting queue, so apply the master
            // AddClientToQueue admission gates. First the firewalled-LowID
            // callback guard (opening check), then the per-IP cap + soft/hard
            // combined-score limit.
            if self.reject_firewalled_callback_admission(&key) {
                return Ed2kUploadSessionStatus::Rejected;
            }
            if self.reject_queue_admission(&key, file_priority_score, credit_score_permille, now) {
                return Ed2kUploadSessionStatus::Rejected;
            }
            self.waiting_order.push(key.clone());
            Ed2kUploadSessionPhase::Waiting
        };
        let waiting_sequence = self.take_waiting_sequence();
        self.sessions.insert(
            key.clone(),
            Ed2kUploadSessionEntry {
                phase,
                connection_id,
                connected: true,
                queued_at: now,
                last_activity: now,
                waiting_sequence,
                file_priority_score,
                credit_score_permille,
                score_modifiers,
                file_size,
                uploaded_bytes: 0,
                upload_started_at: None,
                served_ranges: VecDeque::new(),
                rate_meter: WindowedRateMeter::new(PER_SLOT_RATE_WINDOW),
            },
        );
        // Stamp the slot-open pacing clock on the inline grant, mirroring the
        // oracle stamping `m_nLastStartUpload` on every slot open
        // (UploadQueue.cpp:370): a fresh grant paces the next slot open.
        if phase == Ed2kUploadSessionPhase::Granted {
            self.last_slot_open = Some(now);
        }
        self.trim_waiting_queue(now);
        // A newcomer admitted to the waiting queue may have left a free slot that
        // the BEST existing waiter should take now, not this arrival (oracle
        // Process promotes via the paced+ranked path, never inline for the
        // newcomer). Run the paced promote so a free slot goes to the best
        // candidate -- which is this peer only when it genuinely outranks every
        // queued waiter (RUST-PAR-021 GAP1).
        if phase == Ed2kUploadSessionPhase::Waiting {
            self.promote_waiters(now);
        }
        self.status_for_key(&key, now)
    }

    pub(super) fn poll_session(
        &mut self,
        handle: &Ed2kUploadSessionHandle,
        now: Instant,
        refresh_activity: bool,
    ) -> Ed2kUploadSessionStatus {
        self.reap_expired_sessions(now);
        let Some(session) = self.sessions.get_mut(&handle.key) else {
            return Ed2kUploadSessionStatus::Stale;
        };
        if session.connection_id != handle.connection_id {
            return Ed2kUploadSessionStatus::Stale;
        }
        if refresh_activity {
            session.last_activity = now;
        }
        self.status_for_key(&handle.key, now)
    }

    pub(super) fn note_request_parts(
        &mut self,
        handle: &Ed2kUploadSessionHandle,
        now: Instant,
    ) -> Ed2kUploadSessionStatus {
        self.reap_expired_sessions(now);
        let Some(session) = self.sessions.get_mut(&handle.key) else {
            return Ed2kUploadSessionStatus::Stale;
        };
        if session.connection_id != handle.connection_id {
            return Ed2kUploadSessionStatus::Stale;
        }
        session.last_activity = now;
        if matches!(
            session.phase,
            Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading
        ) {
            session.phase = Ed2kUploadSessionPhase::Uploading;
            return Ed2kUploadSessionStatus::Granted;
        }
        self.status_for_key(&handle.key, now)
    }

    /// RUST-PAR-021 GAP4: a cooled WAITING peer that sends a valid OP_REQUESTPARTS
    /// block request clears its retry / slow / no-request cooldown once per window,
    /// proving genuine renewed demand (oracle `ClearUploadRetryCooldown` invoked
    /// from `AddReqBlock` for a US_ONUPLOADQUEUE client with a valid range,
    /// UploadQueue.cpp:1348-1424, UploadClient.cpp:613-627). Only a peer currently
    /// on the waiting queue attempts the clear; an already-granted peer has no
    /// cooldown to escape. Returns whether a cooldown was cleared; a cleared waiter
    /// is then eligible for the paced promote. Repeat-offender bans are untouched.
    pub(super) fn note_queued_block_request(
        &mut self,
        peer: &Ed2kUploadPeerIdentity,
        now: Instant,
    ) -> bool {
        let is_waiting = self.sessions.iter().any(|(key, session)| {
            session.phase == Ed2kUploadSessionPhase::Waiting && same_upload_client(&key.peer, peer)
        });
        if !is_waiting {
            return false;
        }
        let open_base_slot_underfill = self.open_base_slot_underfill();
        let cleared = self.cooldown.clear_retry_cooldown_on_queued_request(
            peer.ip,
            open_base_slot_underfill,
            now,
        );
        if cleared {
            self.promote_waiters(now);
        }
        cleared
    }

    pub(super) fn note_requested_range(
        &mut self,
        handle: &Ed2kUploadSessionHandle,
        start: u64,
        end: u64,
        now: Instant,
    ) -> (Ed2kUploadSessionStatus, Ed2kUploadRangeAdmission) {
        self.reap_expired_sessions(now);
        let Some(session) = self.sessions.get_mut(&handle.key) else {
            return (
                Ed2kUploadSessionStatus::Stale,
                Ed2kUploadRangeAdmission::Accepted,
            );
        };
        if session.connection_id != handle.connection_id {
            return (
                Ed2kUploadSessionStatus::Stale,
                Ed2kUploadRangeAdmission::Accepted,
            );
        }
        session.last_activity = now;
        if !matches!(
            session.phase,
            Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading
        ) {
            return (
                self.status_for_key(&handle.key, now),
                Ed2kUploadRangeAdmission::Accepted,
            );
        }
        if session
            .served_ranges
            .iter()
            .any(|range| range.start == start && range.end == end)
        {
            return (
                Ed2kUploadSessionStatus::Granted,
                Ed2kUploadRangeAdmission::DuplicateDone,
            );
        }
        (
            Ed2kUploadSessionStatus::Granted,
            Ed2kUploadRangeAdmission::Accepted,
        )
    }

    pub(super) fn note_served_range(
        &mut self,
        handle: &Ed2kUploadSessionHandle,
        start: u64,
        end: u64,
        now: Instant,
    ) -> Ed2kUploadSessionStatus {
        self.reap_expired_sessions(now);
        let Some(session) = self.sessions.get_mut(&handle.key) else {
            return Ed2kUploadSessionStatus::Stale;
        };
        if session.connection_id != handle.connection_id {
            return Ed2kUploadSessionStatus::Stale;
        }
        session.last_activity = now;
        if start < end
            && !session
                .served_ranges
                .iter()
                .any(|range| range.start == start && range.end == end)
        {
            if session.served_ranges.len() == UPLOAD_SESSION_SERVED_RANGE_HISTORY {
                session.served_ranges.pop_front();
            }
            session
                .served_ranges
                .push_back(Ed2kUploadServedRange { start, end });
        }
        self.status_for_key(&handle.key, now)
    }

    pub(super) fn note_uploaded_bytes(
        &mut self,
        handle: &Ed2kUploadSessionHandle,
        byte_count: u64,
        now: Instant,
    ) -> Ed2kUploadSessionStatus {
        self.reap_expired_sessions(now);
        let Some(session) = self.sessions.get_mut(&handle.key) else {
            return Ed2kUploadSessionStatus::Stale;
        };
        if session.connection_id != handle.connection_id {
            return Ed2kUploadSessionStatus::Stale;
        }
        session.last_activity = now;
        if byte_count != 0 {
            session.upload_started_at.get_or_insert(now);
        }
        session.uploaded_bytes = session.uploaded_bytes.saturating_add(byte_count);
        // Feed both sliding-window datarate meters (RUST-PAR-024 GAP-1): the
        // per-slot 10 s window (oracle m_AverageUDR_hist, UploadClient.cpp:864) and
        // the aggregate 30 s window (oracle average_ur_hist, UploadQueue.cpp:924-926).
        session.rate_meter.record(byte_count, now);
        self.aggregate_rate_meter.record(byte_count, now);
        self.refresh_elastic_underfill(now);
        self.promote_waiters(now);
        self.status_for_key(&handle.key, now)
    }

    /// Handle a connection teardown (or explicit cancel) for one session.
    /// Mirrors the master disconnect split: only an ACTIVE upload slot is
    /// removed from the queue (`CUpDownClient::Disconnected` removes
    /// US_UPLOADING/US_CONNECTING clients, BaseClient.cpp:1172-1175), while a
    /// US_ONUPLOADQUEUE waiter KEEPS its queue entry with its wait-start time
    /// (BaseClient.cpp:1229 `bDelete = (m_eUploadState != US_ONUPLOADQUEUE)`)
    /// and ages out via the waiting timeout (MAX_PURGEQUEUETIME,
    /// UploadQueue.cpp:223) unless the peer re-asks first.
    pub(super) fn release_session(&mut self, handle: &Ed2kUploadSessionHandle, now: Instant) {
        let Some(session) = self.sessions.get_mut(&handle.key) else {
            return;
        };
        if session.connection_id != handle.connection_id {
            return;
        }
        if session.phase == Ed2kUploadSessionPhase::Waiting {
            // Waiter: keep the queue entry, drop only the connection binding. A
            // waiter never held a slot, so there is no short-failed slot to cool.
            session.connected = false;
        } else {
            // RUST-PAR-021 GAP2: an ACTIVE upload slot torn down by a disconnect
            // that was young AND had served little payload is the "grabbed a slot
            // then bailed" churn signal (oracle ShouldCooldownShortFailedUploadSlot
            // in RemoveFromUploadQueue, UploadQueue.cpp:2170-2192,
            // UploadQueueSeams.h:644-659). Seed the IP-scoped churn retry cooldown
            // so the peer stops re-winning slot selection. U-GAP3 folded the
            // short-failed cooldown onto the failed-promote-connect path only; this
            // is the genuine inbound-disconnect churn path it left open. Scoped
            // narrowly to the short-failed criteria (aged <= 30 s AND <= 1 MB
            // served) exactly like the oracle, so a normal, long, or productive
            // session ending never cools -- and a legit sibling behind a shared NAT
            // IP that completes a normal session is not suppressed. `queued_at` is
            // the slot-grant time for an active session (reset on promotion), the
            // analog of the oracle's GetUpStartTimeDelay.
            let short_failed = !handle.key.peer.friend_slot
                && now.saturating_duration_since(session.queued_at)
                    <= SHORT_FAILED_UPLOAD_COOLDOWN_MAX_AGE
                && session.uploaded_bytes <= SHORT_FAILED_UPLOAD_COOLDOWN_MAX_PAYLOAD_BYTES;
            self.sessions.remove(&handle.key);
            // NAT-sibling guard: the churn cooldown is IP-scoped, so seeding it
            // while ANOTHER peer still shares the disconnecter's IP would suppress
            // an innocent sibling behind the same NAT (the failure the round-20
            // agent hit on the shared-loopback tests). Only cool when the
            // disconnecter is the sole holder of its IP, so a shared-IP sibling is
            // never collateral-suppressed.
            let has_ip_sibling = self
                .sessions
                .keys()
                .any(|other| other.peer.ip == handle.key.peer.ip);
            // Replacement-pressure gate: the short-failed cooldown exists so a
            // churner "cannot keep winning queue selection and consume replacement
            // attempts" (oracle WHY, UploadQueue.cpp:2182-2187). With no waiter it
            // denied no one -- and a lone peer that simply reconnects or resumes is
            // not churn -- so cool only when a replacement waiter is actually
            // present. This never over-cools relative to the oracle and keeps a
            // lone disconnect/reconnect (and a stale-entry drop) from being gated.
            let replacement_waiting = self.waiting_session_count() > 0;
            if short_failed && !has_ip_sibling && replacement_waiting {
                let budget = self.config.upload_limit_bytes_per_sec;
                self.cooldown
                    .set_churn_cooldown(handle.key.peer.ip, false, budget, now);
            }
        }
        self.reap_expired_sessions(now);
        self.promote_waiters(now);
    }

    /// Seed the churn cooldown for a promoted waiter whose outbound
    /// promote-connect could NOT be established (RUST-PAR-020 U-GAP3): the fork's
    /// failed-admission (`AddUpNextClient` `TryToConnect` failure,
    /// UploadQueue.cpp:330-339) and no-socket (`Process`, :841-856) removals both
    /// seed the IP-scoped churn cooldown so a peer that consumes slot-open
    /// attempts without ever accepting an upload connection stops winning
    /// selection. rust's connection-per-op model surfaces exactly this signal as
    /// a failed promote-connect, and -- unlike a plain socket disconnect -- it
    /// never fires on a normal slot handover, so it does not cool an unrelated
    /// sibling behind a shared source IP.
    pub(super) fn note_failed_promotion(&mut self, peer: &Ed2kUploadPeerIdentity, now: Instant) {
        if peer.friend_slot {
            return;
        }
        let budget = self.config.upload_limit_bytes_per_sec;
        self.cooldown
            .set_churn_cooldown(peer.ip, false, budget, now);
    }

    pub(super) fn release_client(
        &mut self,
        client_id: &str,
        waiting_queue: bool,
        now: Instant,
    ) -> bool {
        self.reap_expired_sessions(now);
        let Some(key) = self
            .sessions
            .iter()
            .find(|(key, session)| {
                let is_waiting = session.phase == Ed2kUploadSessionPhase::Waiting;
                is_waiting == waiting_queue && upload_client_id_matches(&key.peer, client_id)
            })
            .map(|(key, _session)| key.clone())
        else {
            return false;
        };
        let Some(session) = self.sessions.remove(&key) else {
            return false;
        };
        if session.phase == Ed2kUploadSessionPhase::Waiting {
            self.waiting_order.retain(|queued| queued != &key);
        }
        self.reap_expired_sessions(now);
        self.promote_waiters(now);
        true
    }

    /// Refresh the last-request time of the WAITING entry matched by a UDP
    /// reask (oracle `SetLastUpRequest` on OP_REASKFILEPING,
    /// ClientUDPSocket.cpp:307): a disconnected waiter that keeps re-asking
    /// over UDP must not be purged by the waiting timeout (MAX_PURGEQUEUETIME).
    pub(super) fn refresh_waiting_activity_by_udp(
        &mut self,
        ip: IpAddr,
        udp_port: u16,
        now: Instant,
    ) {
        for (key, session) in &mut self.sessions {
            if session.phase == Ed2kUploadSessionPhase::Waiting
                && key.peer.ip == ip
                && key.peer.udp_port == Some(udp_port)
            {
                session.last_activity = now;
            }
        }
    }

    /// Drain the queued promote-connect grants: sessions promoted to an active
    /// slot while their peer had no live connection. Each returned grant is
    /// rebound to a fresh connection id from `next_connection_id` so the
    /// outbound connect owns the session (a failed connect releases it). A
    /// grant whose peer re-attached inbound in the meantime (or whose session
    /// is gone) is skipped: the inbound connection already owns the slot.
    pub(super) fn take_pending_promotions(
        &mut self,
        mut next_connection_id: impl FnMut() -> u64,
    ) -> Vec<Ed2kUploadPendingPromotion> {
        if self.pending_promotions.is_empty() {
            return Vec::new();
        }
        let keys = std::mem::take(&mut self.pending_promotions);
        let mut grants = Vec::new();
        for key in keys {
            let Some(session) = self.sessions.get_mut(&key) else {
                continue;
            };
            if session.connected || session.phase != Ed2kUploadSessionPhase::Granted {
                continue;
            }
            let connection_id = next_connection_id();
            session.connection_id = connection_id;
            session.connected = true;
            grants.push(Ed2kUploadPendingPromotion {
                peer: key.peer.clone(),
                file_hash: key.file_hash.clone(),
                handle: Ed2kUploadSessionHandle::new(
                    key.peer.clone(),
                    key.file_hash.clone(),
                    connection_id,
                ),
            });
        }
        grants
    }

    pub(super) fn snapshot(&mut self, now: Instant) -> Vec<Ed2kUploadQueueSnapshotEntry> {
        self.reap_expired_sessions(now);
        let mut entries = self
            .sessions
            .iter()
            .map(|(key, session)| Ed2kUploadQueueSnapshotEntry {
                ip: key.peer.ip,
                tcp_port: key.peer.tcp_port,
                udp_port: key.peer.udp_port,
                udp_version: key.peer.udp_version,
                should_crypt: key.peer.should_crypt,
                user_hash: key.peer.user_hash,
                client_id: key.peer.client_id,
                friend_slot: key.peer.friend_slot,
                file_hash: key.file_hash.clone(),
                connected: session.connected,
                phase: phase_snapshot(session.phase),
                queue_rank: (session.phase == Ed2kUploadSessionPhase::Waiting)
                    .then(|| self.rank_for_key(key, now)),
                wait_time_ms: now
                    .saturating_duration_since(session.queued_at)
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
                uploaded_bytes: session.uploaded_bytes,
                upload_speed_bytes_per_sec: upload_speed_bytes_per_sec(session, now),
                score: self.waiting_score(key, session, now),
                file_priority_score: session.file_priority_score,
                credit_score_permille: session.credit_score_permille,
                low_ratio_applied: session.score_modifiers.low_ratio_bonus,
                low_ratio_bonus: score::low_ratio_bonus_value(
                    session.score_modifiers.low_ratio_bonus,
                ),
                low_id_penalty_applied: session.score_modifiers.low_id,
                low_id_divisor: score::low_id_divisor_value(session.score_modifiers.low_id),
                old_client_penalty_applied: session.score_modifiers.old_client,
                client_software: key.peer.client_software.clone(),
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            upload_snapshot_sort_key(left)
                .cmp(&upload_snapshot_sort_key(right))
                .then_with(|| left.client_id.cmp(&right.client_id))
                .then_with(|| left.ip.cmp(&right.ip))
                .then_with(|| left.tcp_port.cmp(&right.tcp_port))
                .then_with(|| left.file_hash.cmp(&right.file_hash))
        });
        entries
    }

    pub(super) fn update_file_priority(&mut self, file_hash: &str, file_priority_score: i128) {
        for (key, session) in &mut self.sessions {
            if key.file_hash == file_hash {
                session.file_priority_score = file_priority_score;
            }
        }
    }

    pub(super) fn reserve_upload_payload(
        &mut self,
        byte_count: u64,
        now: Instant,
    ) -> Ed2kUploadThrottleReservation {
        if byte_count == 0 || self.config.upload_limit_bytes_per_sec == 0 {
            return Ed2kUploadThrottleReservation {
                delay: Duration::ZERO,
            };
        }
        let interval = upload_payload_interval(byte_count, self.config.upload_limit_bytes_per_sec);
        let scheduled_at = self
            .throttle_next_send_at
            .filter(|next_send_at| *next_send_at > now)
            .unwrap_or(now);
        self.throttle_next_send_at = Some(scheduled_at + interval);
        Ed2kUploadThrottleReservation {
            delay: scheduled_at.saturating_duration_since(now),
        }
    }

    fn status_for_key(&self, key: &Ed2kUploadSessionKey, now: Instant) -> Ed2kUploadSessionStatus {
        match self.sessions.get(key).map(|session| session.phase) {
            Some(Ed2kUploadSessionPhase::Waiting) => Ed2kUploadSessionStatus::Waiting {
                rank: self.rank_for_key(key, now),
            },
            Some(Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading) => {
                Ed2kUploadSessionStatus::Granted
            }
            None => Ed2kUploadSessionStatus::Stale,
        }
    }

    fn rank_for_key(&self, key: &Ed2kUploadSessionKey, now: Instant) -> u16 {
        let ranked = self.ranked_waiting_keys(now);
        let Some(position) = ranked.iter().position(|queued| *queued == key) else {
            return 0;
        };
        u16::try_from(position.saturating_add(1)).unwrap_or(u16::MAX)
    }

    fn active_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|session| {
                matches!(
                    session.phase,
                    Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading
                )
            })
            .count()
    }

    /// Resolve the queue entry of a (possibly reconnecting) peer the way the
    /// oracle resolves the same client (`CUpDownClient::Compare`,
    /// DownloadClient.cpp:275): when both sides know a user hash, the hash alone
    /// decides; otherwise fall back to the endpoint (IP + advertised TCP port).
    /// A returning peer may present a new server-assigned client id or connect
    /// from a new source port and must still re-attach to its persisted waiting
    /// entry (re-ask on the same queue entry, UploadQueue.cpp:1865-1869).
    fn session_key_for_peer(&self, peer: &Ed2kUploadPeerIdentity) -> Option<Ed2kUploadSessionKey> {
        self.sessions
            .keys()
            .find(|existing_key| same_upload_client(&existing_key.peer, peer))
            .cloned()
    }

    fn replace_waiting_key(
        &mut self,
        existing_key: &Ed2kUploadSessionKey,
        new_key: &Ed2kUploadSessionKey,
    ) {
        for queued in &mut self.waiting_order {
            if *queued == *existing_key {
                *queued = new_key.clone();
                return;
            }
        }
    }

    /// Apply the master `AddClientToQueue` firewalled-LowID callback guard
    /// (`UploadQueue.cpp:1815-1825`): when we are connected and firewalled, reject
    /// a non-Kad, non-downloading, non-friend, different-server candidate once the
    /// waiting queue already exceeds 50, to limit LowID-callback abuse.
    fn reject_firewalled_callback_admission(&self, key: &Ed2kUploadSessionKey) -> bool {
        let firewall_context = key.peer.firewall_context;
        admission::reject_firewalled_callback(admission::FirewalledCallbackAdmission {
            we_are_connected: firewall_context.we_are_connected,
            we_are_firewalled: firewall_context.we_are_firewalled,
            peer_has_kad_port: key.peer.kad_port != 0,
            // An inbound queued uploader is requesting from us, not downloading
            // from us, so it is never DS_NONE-exempt here (master DS_NONE check).
            peer_is_downloading_from_us: false,
            peer_is_friend: key.peer.friend_slot,
            peer_on_same_server: firewall_context.peer_on_same_server,
            waiting_count: self.waiting_session_count() as u64,
        })
    }

    /// Apply the master `AddClientToQueue` waiting-admission gates: the per-IP
    /// waiter cap and the soft/hard combined-score queue limit. Returns `true`
    /// when the candidate must be refused.
    fn reject_queue_admission(
        &self,
        key: &Ed2kUploadSessionKey,
        file_priority_score: i128,
        credit_score_permille: i128,
        now: Instant,
    ) -> bool {
        // Per-IP cap: count existing waiters from the same IP (different
        // port/hash), mirroring `cSameIP`.
        let candidate_ip = key.peer.ip;
        let same_ip_waiters = self
            .waiting_order
            .iter()
            .filter(|queued| queued.peer.ip == candidate_ip && **queued != *key)
            .count();
        if admission::reject_per_ip_cap(same_ip_waiters) {
            return true;
        }

        let candidate_combined =
            admission::combined_file_prio_and_credit(file_priority_score, credit_score_permille);
        admission::reject_soft_queue_candidate(admission::SoftQueueAdmission {
            waiting_count: self.waiting_session_count() as u64,
            soft_queue_size: self.config.soft_queue_size,
            has_friend_slot: key.peer.friend_slot,
            candidate_combined_score: candidate_combined,
            average_combined_score: self.average_combined_waiting_score(now),
        })
    }

    /// Average combined file-priority-and-credit score across current waiters
    /// (master `GetAverageCombinedFilePrioAndCredit`). Returns 0 with no waiters.
    fn average_combined_waiting_score(&self, now: Instant) -> i128 {
        let _ = now;
        let mut sum: i128 = 0;
        let mut count: i128 = 0;
        for queued in &self.waiting_order {
            let Some(session) = self.sessions.get(queued) else {
                continue;
            };
            if session.phase != Ed2kUploadSessionPhase::Waiting {
                continue;
            }
            sum = sum.saturating_add(admission::combined_file_prio_and_credit(
                session.file_priority_score,
                session.credit_score_permille,
            ));
            count += 1;
        }
        if count == 0 { 0 } else { sum / count }
    }

    /// Drop waiting entries whose requested file is no longer shared (master
    /// `FindBestClientInQueue` waiting-list walk, UploadQueue.cpp:223: the purge
    /// condition also fires on `!GetFileByID(client->GetUploadFileID())`). Only
    /// the waiting queue is walked — the master never purges an active
    /// (`uploadinglist`) slot here — and the drop emits no slot event, mirroring
    /// the plain `RemoveFromWaitingQueue`. `shared_file_hashes` holds the
    /// lowercase-hex hashes we currently serve. Returns the purged waiter count.
    pub(super) fn purge_waiters_for_unshared_files(
        &mut self,
        shared_file_hashes: &std::collections::HashSet<String>,
    ) -> usize {
        let stale: Vec<Ed2kUploadSessionKey> = self
            .waiting_order
            .iter()
            .filter(|key| {
                self.sessions
                    .get(*key)
                    .is_some_and(|session| session.phase == Ed2kUploadSessionPhase::Waiting)
                    && !shared_file_hashes.contains(&key.file_hash.to_ascii_lowercase())
            })
            .cloned()
            .collect();
        for key in &stale {
            self.sessions.remove(key);
        }
        if !stale.is_empty() {
            self.waiting_order.retain(|key| !stale.contains(key));
        }
        stale.len()
    }

    fn trim_waiting_queue(&mut self, now: Instant) {
        while self.waiting_order.len() > self.config.waiting_capacity {
            let Some(evicted) = self.worst_waiting_key(now) else {
                return;
            };
            self.remove_waiting_key(&evicted);
        }
    }

    fn reap_expired_sessions(&mut self, now: Instant) {
        self.refresh_elastic_underfill(now);
        self.cooldown.purge_expired(now);
        let active_before = self.active_session_count();
        let waiting_before = self.waiting_session_count();
        let expired = self
            .sessions
            .iter()
            .filter_map(|(key, session)| {
                // Active slots (Granted/Uploading) are reaped ONLY by the sustained-
                // underfill idle/slow recycle (MFC ShouldRecycleIdleUploadSlot), never
                // on a plain last-activity timer: the master keeps a live-but-idle
                // active client granted and drops a dead one via socket teardown (the
                // rust listener does the same via its connection idle timeout ->
                // release_session). Waiting entries are reaped on the waiting timeout.
                match session.phase {
                    Ed2kUploadSessionPhase::Waiting => (now
                        .saturating_duration_since(session.last_activity)
                        > self.config.waiting_timeout)
                        .then(|| (key.clone(), None)),
                    Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading => self
                        .underfilled_active_recycle_diagnostics(session, now)
                        .or_else(|| self.session_cap_rotation_diagnostics(key, session, now))
                        .map(|diag| (key.clone(), Some(diag))),
                }
            })
            .collect::<Vec<_>>();
        for (key, recycle) in expired {
            let Some(recycle) = recycle else {
                // Waiting entry past the waiting timeout: a plain queue purge with no
                // slot event (mirrors MFC RemoveFromWaitingQueue).
                self.sessions.remove(&key);
                self.waiting_order.retain(|queued| queued != &key);
                continue;
            };
            // An idle/slow active slot reclaimed under sustained underfill (MFC
            // activeNoRequestRecycle* / CheckForTimeOver): emit the recycle, then
            // requeue the peer -- unless it is banned (master bRequeue=false) or no
            // longer passes the queue-admission gates (AddClientToQueue re-gating),
            // which the master drops instead of re-queuing.
            super::diag_sched::upload_slot_recycled(
                &super::diag_sched::peer_label(key.peer.ip, key.peer.tcp_port),
                key.peer.user_hash,
                &key.file_hash,
                recycle.reason,
                recycle.slot_age_ms,
                recycle.idle_ms,
                recycle.uploaded_bytes,
                recycle.slot_rate_bytes_per_sec,
                active_before,
                waiting_before,
            );
            // Only the underfill recycles are bad-peer-shaped; a session-cap
            // rotation is fair scheduling of a productive slot (MFC logs those as
            // plain UlDl events, UploadQueue.cpp:2422/2452, with no bad-peer emit).
            if matches!(recycle.reason, "noRequestUnderfill" | "slowUnderfill") {
                super::diag_bad_peer::upload_recycle(
                    &super::diag_sched::peer_label(key.peer.ip, key.peer.tcp_port),
                    key.peer.user_hash,
                    &key.file_hash,
                    recycle.reason,
                );
            }
            // RUST-PAR-020 U-GAP3: seed the upload anti-abuse cooldown for a
            // recycled slot. A never-requested slot (noRequestUnderfill, 0 bytes
            // served) accrues a rolling-window strike and either a bounded
            // no-request cooldown or, past the threshold, a repeat-offender ban
            // (TrackNoRequestRepeatOffender + client->Ban, UploadQueue.cpp:1586-1656);
            // a productive-but-slow slot (slowUnderfill) gets the slow-upload
            // retry cooldown only (UploadQueue.cpp:2358-2366). A session-cap
            // rotation is fair scheduling and is never penalised.
            let budget = self.config.upload_limit_bytes_per_sec;
            let mut force_drop = false;
            match recycle.reason {
                "noRequestUnderfill" => {
                    // noRequestUnderfill fires only for a 0-byte slot, so the
                    // recycle is always non-productive (the fork's productive
                    // no-request path corresponds to slowUnderfill here).
                    let outcome = self.cooldown.register_no_request_recycle(
                        key.peer.ip,
                        key.peer.user_hash,
                        key.peer.friend_slot,
                        budget,
                        now,
                        false,
                    );
                    if outcome.ban != CooldownBan::None {
                        self.apply_cooldown_ban(&key.peer, outcome.ban, now);
                        force_drop = true;
                    }
                }
                "slowUnderfill" => {
                    self.cooldown
                        .set_slow_cooldown(key.peer.ip, key.peer.friend_slot, budget, now);
                }
                _ => {}
            }
            let (file_priority_score, credit_score_permille) = self
                .sessions
                .get(&key)
                .map(|session| (session.file_priority_score, session.credit_score_permille))
                .unwrap_or_default();
            // A banned offender is dropped, not requeued (oracle bRequeue=false
            // for `client->Ban(...); return true;`). The cooldown itself does NOT
            // drop the peer: it stays on the waiting list, just skipped for
            // promotion until the cooldown expires.
            let requeue = !force_drop
                && !key.peer.banned
                && !self.reject_queue_admission(
                    &key,
                    file_priority_score,
                    credit_score_permille,
                    now,
                )
                && !self.reject_firewalled_callback_admission(&key);
            if !requeue {
                self.sessions.remove(&key);
                self.waiting_order.retain(|queued| queued != &key);
                continue;
            }
            // Demote to the BACK of the waiting queue (mirroring MFC
            // SendOutOfPartReqsAndAddToWaitingQueue): the slot is freed for a waiter,
            // but the peer keeps its queue entry + open connection (the listener sees
            // Waiting, not Stale, so it sends OP_OUTOFPARTREQS + queue rankings rather
            // than closing and shedding upload demand). upload_slot_closed(reason =
            // slot_recycled) mirrors the master's per-recycle RemoveFromUploadQueue
            // close. queued_at/last_activity reset so a re-promotion earns a fresh
            // granted window and the waiting timeout counts from the requeue; a fresh
            // sequence orders it after existing waiters; the finished upload stint is
            // cleared so it does not skew the active upload-rate accounting.
            super::diag_sched::upload_slot_closed(
                &super::diag_sched::peer_label(key.peer.ip, key.peer.tcp_port),
                key.peer.user_hash,
                &key.file_hash,
                "slot_recycled",
            );
            let waiting_sequence = self.take_waiting_sequence();
            if let Some(session) = self.sessions.get_mut(&key) {
                session.phase = Ed2kUploadSessionPhase::Waiting;
                session.queued_at = now;
                session.last_activity = now;
                session.upload_started_at = None;
                session.uploaded_bytes = 0;
                session.served_ranges.clear();
                session.rate_meter.reset();
                session.waiting_sequence = waiting_sequence;
            }
            self.waiting_order.push(key);
        }
        self.trim_waiting_queue(now);
        self.promote_waiters(now);
    }

    /// Apply a no-request repeat-offender ban to the shared ban list, mirroring
    /// `client->Ban(reason, scope)` -> `CClientList::AddBannedClient`
    /// (ClientList.cpp:361-373): a hash-scoped ban targets the user hash (or the
    /// IP when no valid hash is present), a hash-rotation ban targets both keys.
    /// The `BanStore` owns the 4h TTL, matching `CLIENTBANTIME`.
    fn apply_cooldown_ban(&self, peer: &Ed2kUploadPeerIdentity, ban: CooldownBan, now: Instant) {
        let Some(store) = self.ban_store.as_ref() else {
            return;
        };
        // IPv4-only client policy: a non-IPv4 peer bans by hash only.
        let ip_v4 = match peer.ip {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        };
        match ban {
            CooldownBan::None => {}
            CooldownBan::ByHash => store.ban_at(None, peer.user_hash, now),
            CooldownBan::ByIp => store.ban_at(ip_v4, None, now),
            CooldownBan::Both => store.ban_at(ip_v4, peer.user_hash, now),
        }
    }

    fn underfilled_active_recycle_diagnostics(
        &self,
        session: &Ed2kUploadSessionEntry,
        now: Instant,
    ) -> Option<Ed2kUploadRecycleDiagnostics> {
        if !matches!(
            session.phase,
            Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading
        ) {
            return None;
        }
        // The slow/idle recycle path keys off the 2 s sustained-underfill window
        // (oracle HasSustainedBroadbandUnderfill, UploadQueue.cpp:1047-1050 via
        // ShouldTrackSlowUploadSlots, :1114), NOT the 10 s elastic-open window: a
        // slow/idle uploader is recycled + sent OP_OUTOFPARTREQS ~8 s sooner.
        //
        // RUST-PAR-021 Upload-GAP6: the recycle signal is SLOT scarcity, not
        // merely a spare byte budget. The oracle always derives from a finite
        // GetConfiguredUploadBudgetBytesPerSec = GetMaxUpload()*1024
        // (UploadQueue.cpp:981-986, which explicitly notes "no ... unlimited
        // upload mode left in slot control"), so ShouldRecycleIdleUploadSlot's
        // HasSustainedBroadbandUnderfill gate is effectively always satisfied
        // under sparse public demand and the decision falls to the waiter/slot
        // scarcity of HasNoRequestUploadReplacementPressure (:1570). This fork DOES
        // have an unlimited mode (upload_limit == 0); there the byte-budget
        // underfill can never be computed, so `recycle_underfill_signal_ready`
        // treats infinite bandwidth as PERMANENTLY underfilled -- the faithful
        // reading of the oracle's underfill line when the budget is unbounded --
        // and the anti-abuse keys purely on slot occupancy (an active slot-holder,
        // guaranteed by the phase above) plus waiter presence (the count guard
        // below). This restores the no-request/slow recycle + strike/cooldown/ban
        // path under unlimited upload without touching the bandwidth-limited case.
        if self.waiting_session_count() == 0 || !self.recycle_underfill_signal_ready(now) {
            return None;
        }
        if session.uploaded_bytes == 0 {
            // RUST-PAR-021 GAP3: strike + recycle a no-request idle slot only when
            // a genuine replacement exists (oracle
            // HasNoRequestUploadReplacementPressure, UploadQueue.cpp:1570 /
            // UploadQueueSeams.h:162). When every waiter is cooled with a hard
            // (churn/slow) cooldown and none is probeable, the oracle RETAINS the
            // idle holder with NO strike (:1571-1584) rather than recycling it
            // toward a repeat-offender ban. The outer `waiting_session_count() == 0`
            // guard alone is coarser: it strikes even when no waiter can take the
            // freed slot.
            if !self.has_no_request_replacement_pressure(now) {
                return None;
            }
            return (now.saturating_duration_since(session.queued_at)
                > self.config.granted_timeout)
                .then(|| self.recycle_diagnostics(session, now, "noRequestUnderfill"));
        }
        let started_at = session.upload_started_at?;
        if now.saturating_duration_since(started_at) < self.config.upload_timeout {
            return None;
        }
        (upload_speed_bytes_per_sec(session, now) < self.slow_upload_threshold_bytes_per_sec())
            .then(|| self.recycle_diagnostics(session, now, "slowUnderfill"))
    }

    /// Whether a drained no-request slot has a concrete replacement to recycle
    /// toward (oracle `HasNoRequestUploadReplacementPressure`, UploadQueue.cpp:1570
    /// / UploadQueueSeams.h:162): a non-cooled ADMISSIBLE waiter, OR a cooldown-
    /// PROBE candidate (a waiter under an active probeable no-request cooldown).
    /// When every waiter carries only a hard churn/slow cooldown (never probeable)
    /// and none is admissible -- or the queue is empty -- there is no replacement
    /// pressure and the caller retains the idle holder unstricken. The probe
    /// existence is checked with `open_base_slot_underfill = true` because a
    /// no-request recycle frees exactly the slot the probe would fill, so the
    /// candidate's existence must not be gated on the slot the recycle is about to
    /// open.
    fn has_no_request_replacement_pressure(&self, now: Instant) -> bool {
        if self.waiting_session_count() == 0 {
            return false;
        }
        self.ranked_waiting_keys(now).into_iter().any(|key| {
            !self
                .cooldown
                .is_cooled(key.peer.ip, key.peer.friend_slot, now)
                || self.cooldown.can_probe(key.peer.ip, now, true)
        })
    }

    /// Session rotation caps (oracle `CheckForTimeOver`, UploadQueue.cpp:2407-2467):
    /// a slot past its per-session transferred-bytes cap (default 90% of the file)
    /// or wall-clock time cap (default 7200 s) is recycled through the shared
    /// OUTOFPARTREQS + requeue-at-tail path. Gating mirrors the fork's broadband
    /// slot controller: rotate only when a queued replacement is available, and
    /// retain a productive slot while the upload line is underfilled
    /// (`ShouldRotateBroadbandLimitedUploadSession`, UploadQueueSeams.h:677-685).
    fn session_cap_rotation_diagnostics(
        &self,
        key: &Ed2kUploadSessionKey,
        session: &Ed2kUploadSessionEntry,
        now: Instant,
    ) -> Option<Ed2kUploadRecycleDiagnostics> {
        // Friend slots are exempt from every session rotation (oracle
        // CheckForTimeOver early return, UploadQueue.cpp:2303-2304).
        if key.peer.friend_slot {
            return None;
        }
        // Byte cap: one session may transfer up to the configured percent of the
        // file (trigger `GetQueueSessionPayloadUp() > limit`, UploadQueue.cpp:2411).
        let over_transfer = self
            .session_transfer_limit_bytes(session)
            .is_some_and(|limit| session.uploaded_bytes > limit);
        // Time cap: rotate a slot session past the configured wall-clock age
        // (`GetUpStartTimeDelay() > SEC2MS(limit)`, UploadQueue.cpp:2441).
        // `queued_at` is the slot-grant time for an active session (reset on
        // promotion), the analog of the oracle's per-session UpStartTime.
        let over_time = !self.config.session_time_limit.is_zero()
            && now.saturating_duration_since(session.queued_at) > self.config.session_time_limit;
        if !over_transfer && !over_time {
            return None;
        }
        // Oracle bNeedsReplacement is `ForceNewClient()` (a waiting admission
        // candidate exists and slot policy would start another upload,
        // UploadQueue.cpp:2412/2442). Under this queue's eager `promote_waiters`
        // model the capacity half is saturated by construction (active == the
        // effective limit whenever a waiter exists), so the surviving condition
        // is replacement availability. A cooled-only waiting queue is NOT a
        // replacement -- rotating a productive capped slot for a peer that cannot
        // be promoted (all cooled, no probe) would idle the slot -- so the
        // admissible selection gates the rotation (RUST-PAR-020 U-GAP3).
        self.best_admissible_waiting_key(now)?;
        // Retain a productive capped slot while the upload line is underfilled:
        // rotating known throughput for an unknown replacement would widen the
        // underfill (UploadQueueSeams.h:683-684). `underfill_since` is refreshed
        // by the caller, so `is_some` is the instantaneous underfill state
        // (oracle IsBroadbandUploadUnderfilled).
        if self.underfill_since.is_some()
            && upload_speed_bytes_per_sec(session, now)
                >= self.productive_upload_threshold_bytes_per_sec()
        {
            return None;
        }
        Some(self.recycle_diagnostics(
            session,
            now,
            if over_transfer {
                "sessionTransferLimit"
            } else {
                "sessionTimeLimit"
            },
        ))
    }

    /// Per-session transferred-bytes cap (oracle
    /// `ResolveSessionTransferLimitBytes` percent-of-file mode,
    /// UploadQueue.cpp:137-149): `ceil(file_size * percent / 100)`. `None` when
    /// the cap is disabled or the file size is unknown (the oracle's NULL-file
    /// early return).
    fn session_transfer_limit_bytes(&self, session: &Ed2kUploadSessionEntry) -> Option<u64> {
        let percent = u64::from(self.config.session_transfer_percent.min(100));
        if percent == 0 || session.file_size == 0 {
            return None;
        }
        Some(session.file_size.saturating_mul(percent).saturating_add(99) / 100)
    }

    /// Productive-rate bar a capped session must beat to be retained while the
    /// upload line is underfilled (oracle `GetSlowUploadRateThreshold`,
    /// UploadQueue.cpp:1070-1078: target-per-slot x the default slow-upload
    /// threshold factor 0.75, floored at 1 KiB/s).
    fn productive_upload_threshold_bytes_per_sec(&self) -> u64 {
        // REG-7: with no configured upload budget the oracle returns a flat
        // 3 KiB/s (`if (uTargetPerSlot == 0) return 3 * 1024;`,
        // UploadQueue.cpp:1073-1074) -- NOT the 0.75-factored 2304 the general
        // path would degenerate to. This arm is UNREACHABLE from the retention
        // caller (it only fires under tracked underfill, which cannot occur at
        // upload_limit 0, since `refresh_elastic_underfill` clears
        // `underfill_since` there), but the constant is spelled to match the
        // oracle. The nonzero path below is left exactly as before.
        if self.config.upload_limit_bytes_per_sec == 0 {
            return 3 * 1024;
        }
        let base_slots = self.config.active_slots.max(1) as u64;
        let target_per_slot = (self.config.upload_limit_bytes_per_sec / base_slots).max(3 * 1024);
        (target_per_slot.saturating_mul(3) / 4).max(1024)
    }

    fn timeout_recycle_diagnostics(
        &self,
        session: &Ed2kUploadSessionEntry,
        now: Instant,
    ) -> Ed2kUploadRecycleDiagnostics {
        let reason = match session.phase {
            Ed2kUploadSessionPhase::Waiting => "waitingTimeout",
            Ed2kUploadSessionPhase::Granted => "grantedTimeout",
            Ed2kUploadSessionPhase::Uploading => "uploadTimeout",
        };
        self.recycle_diagnostics(session, now, reason)
    }

    fn recycle_diagnostics(
        &self,
        session: &Ed2kUploadSessionEntry,
        now: Instant,
        reason: &'static str,
    ) -> Ed2kUploadRecycleDiagnostics {
        Ed2kUploadRecycleDiagnostics {
            reason,
            slot_age_ms: now
                .saturating_duration_since(session.queued_at)
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            idle_ms: now
                .saturating_duration_since(session.last_activity)
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            uploaded_bytes: session.uploaded_bytes,
            slot_rate_bytes_per_sec: upload_speed_bytes_per_sec(session, now),
        }
    }

    fn promote_waiters(&mut self, now: Instant) {
        self.refresh_elastic_underfill(now);
        while self.active_session_count() < self.effective_active_slot_limit(now) {
            // Slot-open pacing: below the busy-pipe datarate the fork opens at most
            // one new slot per second (oracle Process opens ONE client per tick via
            // ForceNewClient, UploadQueue.cpp:821-823/972). Defer the remaining free
            // slots to a later tick instead of bursting the whole backlog at once.
            if !self.slot_open_paced(now) {
                break;
            }
            let Some(next_key) = self.best_admissible_waiting_key(now) else {
                break;
            };
            self.waiting_order.retain(|queued| queued != &next_key);
            let Some(next_session) = self.sessions.get_mut(&next_key) else {
                continue;
            };
            next_session.phase = Ed2kUploadSessionPhase::Granted;
            next_session.last_activity = now;
            // Fresh granted window on promotion: without this a waiter promoted long
            // after it queued is immediately eligible for the no-request recycle
            // (which keys off queued_at), which — now that a recycled peer is demoted
            // back to the queue rather than dropped — would thrash promote/recycle
            // between the two peers.
            next_session.queued_at = now;
            if !next_session.connected && !self.pending_promotions.contains(&next_key) {
                // Slot granted to a waiter with no live connection: it needs an
                // OUTBOUND connect + OP_ACCEPTUPLOADREQ (master AddUpNextClient
                // US_CONNECTING -> TryToConnect, UploadQueue.cpp:327-361). Queue
                // it for the promote-connect driver; a failed connect drops the
                // grant like the master's failed TryToConnect path.
                self.pending_promotions.push(next_key);
            }
            // Stamp the slot-open pacing clock (oracle m_nLastStartUpload,
            // UploadQueue.cpp:370): stamped for the connect-out grant too, so the
            // disconnected-waiter promotions stagger 1/sec just like inline grants.
            self.last_slot_open = Some(now);
        }
    }

    /// One-slot-per-second slot-open pacing (oracle `ForceNewClient` gate,
    /// UploadQueue.cpp:969-972). Returns whether a NEW upload slot may open now:
    /// - always while below `MIN_UP_CLIENTS_ALLOWED` base slots (the fork fills the
    ///   minimum immediately, before the 1/sec gate);
    /// - always once the aggregate upload datarate is at/above the busy-pipe
    ///   threshold (the fork bypasses the 1/sec cap and lets slots burst);
    /// - otherwise only once at least one second has elapsed since the last grant
    ///   (`m_nLastStartUpload + SEC2MS(1)`).
    fn slot_open_paced(&self, now: Instant) -> bool {
        if self.active_session_count() < MIN_UP_CLIENTS_ALLOWED {
            return true;
        }
        if self.upload_rate_bytes_per_sec(now) >= UPLOAD_SLOT_OPEN_BURST_DATARATE_BYTES_PER_SEC {
            return true;
        }
        match self.last_slot_open {
            None => true,
            Some(last) => now.saturating_duration_since(last) >= UPLOAD_SLOT_OPEN_MIN_INTERVAL,
        }
    }

    fn ranked_waiting_keys(&self, now: Instant) -> Vec<&Ed2kUploadSessionKey> {
        let mut ranked = self
            .waiting_order
            .iter()
            .filter(|key| {
                self.sessions
                    .get(*key)
                    .is_some_and(|session| session.phase == Ed2kUploadSessionPhase::Waiting)
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            let left_session = self
                .sessions
                .get(*left)
                .expect("ranked waiter must exist in session map");
            let right_session = self
                .sessions
                .get(*right)
                .expect("ranked waiter must exist in session map");
            self.waiting_score(right, right_session, now)
                .cmp(&self.waiting_score(left, left_session, now))
                .then_with(|| {
                    left_session
                        .waiting_sequence
                        .cmp(&right_session.waiting_sequence)
                })
        });
        ranked
    }

    /// Best waiter eligible for a slot grant, applying the RUST-PAR-020 U-GAP3
    /// cooldown gate (oracle `FindBestClientInQueue`, UploadQueue.cpp:201-257):
    /// the highest-score waiter whose IP is NOT under an active upload cooldown.
    /// When every eligible waiter is cooled down, fall back to the cooldown
    /// PROBE -- the best probeable no-request-cooldown waiter -- but only while a
    /// base slot would otherwise idle behind the cooled-only queue
    /// (`cooldownProbeClient`, :235-243,257). Rank display is unaffected: a
    /// cooled waiter keeps its queue rank, it is only skipped for promotion.
    fn best_admissible_waiting_key(&self, now: Instant) -> Option<Ed2kUploadSessionKey> {
        let ranked = self.ranked_waiting_keys(now);
        for key in &ranked {
            if !self
                .cooldown
                .is_cooled(key.peer.ip, key.peer.friend_slot, now)
            {
                return Some((*key).clone());
            }
        }
        // Everyone eligible is cooled down: probe only while a base slot idles.
        if !self.open_base_slot_underfill() {
            return None;
        }
        let mut best: Option<(&&Ed2kUploadSessionKey, Duration)> = None;
        for key in &ranked {
            if !self.cooldown.can_probe(key.peer.ip, now, true) {
                continue;
            }
            let remaining = self
                .cooldown
                .cooldown_remaining(key.peer.ip, now)
                .unwrap_or_default();
            // `ranked` is score-descending, so on an equal remaining cooldown the
            // earlier (higher-score) waiter is kept -- only a strictly-lower
            // remaining replaces it (fork PreferHigherUploadQueueScore tie-break).
            if best.is_none_or(|(_, best_remaining)| remaining < best_remaining) {
                best = Some((key, remaining));
            }
        }
        best.map(|(key, _)| (**key).clone())
    }

    /// Whether a base upload slot would idle behind an all-cooled waiting queue,
    /// gating the cooldown probe (oracle
    /// `HasOpenBaseUploadSlotDuringBroadbandUnderfill`, UploadQueueSeams.h:129).
    /// Requires spare room below the base slot target AND an underfilled pipe;
    /// with no configured budget any idle base slot qualifies, so an all-cooled
    /// queue never permanently starves an open slot.
    fn open_base_slot_underfill(&self) -> bool {
        let base_slots = self.config.active_slots.max(1);
        if self.active_session_count() >= base_slots {
            return false;
        }
        self.config.upload_limit_bytes_per_sec == 0 || self.underfill_since.is_some()
    }

    fn worst_waiting_key(&self, now: Instant) -> Option<Ed2kUploadSessionKey> {
        self.ranked_waiting_keys(now)
            .last()
            .map(|key| (*key).clone())
    }

    fn remove_waiting_key(&mut self, key: &Ed2kUploadSessionKey) {
        self.sessions.remove(key);
        self.waiting_order.retain(|queued| queued != key);
    }

    fn waiting_score(
        &self,
        key: &Ed2kUploadSessionKey,
        session: &Ed2kUploadSessionEntry,
        now: Instant,
    ) -> i128 {
        let low_id = key.peer.client_id.is_some_and(is_low_id_client_id);
        score::waiting_score(score::UploadScoreInputs {
            waiting_seconds: now.saturating_duration_since(session.queued_at).as_secs() as i128,
            // Master friend-slot fast path excludes LowID; the friend-slot bonus
            // is added by the score function, the zeroing modifiers take priority.
            friend_slot: key.peer.friend_slot && !low_id,
            file_priority_score: session.file_priority_score,
            credit_score_permille: session.credit_score_permille,
            modifiers: session.score_modifiers,
        })
    }

    fn take_waiting_sequence(&mut self) -> u64 {
        let sequence = self.next_waiting_sequence;
        self.next_waiting_sequence = self.next_waiting_sequence.saturating_add(1);
        sequence
    }

    fn waiting_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|session| session.phase == Ed2kUploadSessionPhase::Waiting)
            .count()
    }

    /// The number of clients associated with a shared file's upload set, the
    /// oracle's `CKnownFile::GetQueuedCount()` = `m_ClientUploadList.GetCount()`
    /// (KnownFile.h:77). Every peer that has requested this file is on that list
    /// (`SetUploadFileID` -> `AddUploadingClient`, UploadClient.cpp:583-585),
    /// whether waiting for a slot or actively uploading, so we count all sessions
    /// for the hash regardless of phase. Feeds the auto-upload-priority dynamic
    /// tier (`UpdateAutoUpPriority`, KnownFile.cpp:1377-1392).
    pub(super) fn upload_client_count_for_file(&self, file_hash: &str) -> u64 {
        self.sessions
            .keys()
            .filter(|key| key.file_hash == file_hash)
            .count() as u64
    }

    fn active_granted_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|session| session.phase == Ed2kUploadSessionPhase::Granted)
            .count()
    }

    fn active_uploading_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|session| session.phase == Ed2kUploadSessionPhase::Uploading)
            .count()
    }

    fn active_never_uploaded_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|session| {
                matches!(
                    session.phase,
                    Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading
                ) && session.uploaded_bytes == 0
            })
            .count()
    }

    fn active_productive_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|session| {
                matches!(
                    session.phase,
                    Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading
                ) && session.uploaded_bytes != 0
            })
            .count()
    }

    fn elastic_slot_allowance(&self) -> usize {
        let percent = self.config.elastic_percent.min(100) as usize;
        self.config
            .active_slots
            .max(1)
            .saturating_mul(percent)
            .div_ceil(100)
    }

    fn effective_active_slot_limit(&self, now: Instant) -> usize {
        let base_slots = self.config.active_slots.max(1);
        if self.elastic_underfill_ready(now) {
            base_slots.saturating_add(self.elastic_slot_allowance())
        } else {
            base_slots
        }
    }

    fn elastic_underfill_ready(&self, now: Instant) -> bool {
        self.elastic_slot_allowance() != 0 && self.sustained_upload_underfill_ready(now)
    }

    fn sustained_upload_underfill_ready(&self, now: Instant) -> bool {
        self.config.upload_limit_bytes_per_sec != 0
            && self.underfill_since.is_some_and(|underfill_since| {
                now.saturating_duration_since(underfill_since) >= self.config.elastic_underfill
            })
    }

    /// Sustained-underfill readiness for the slow/idle active-slot RECYCLE path
    /// (oracle `HasSustainedBroadbandUnderfill`, UploadQueue.cpp:1047-1050): the
    /// same underfill-since clock as the elastic-open window, but at the fork's
    /// fixed 2 s threshold (`SLOW_RECYCLE_UNDERFILL_WINDOW`) instead of the 10 s
    /// elastic-open window, so a slow/idle uploader is recycled ~8 s sooner.
    fn sustained_recycle_underfill_ready(&self, now: Instant) -> bool {
        self.config.upload_limit_bytes_per_sec != 0
            && self.underfill_since.is_some_and(|underfill_since| {
                now.saturating_duration_since(underfill_since) >= SLOW_RECYCLE_UNDERFILL_WINDOW
            })
    }

    /// Whether the slow/idle active-slot RECYCLE signal is ready (RUST-PAR-021
    /// Upload-GAP6). Under a configured upload budget this is exactly the oracle's
    /// 2 s sustained bandwidth underfill (`sustained_recycle_underfill_ready`,
    /// `HasSustainedBroadbandUnderfill`, UploadQueue.cpp:1047-1050) -- the
    /// bandwidth-limited case is unchanged. Under this fork's unlimited upload
    /// mode (`upload_limit == 0`, which the oracle never has: it always derives
    /// from a finite `GetConfiguredUploadBudgetBytesPerSec`, UploadQueue.cpp:981-986)
    /// the spare byte budget cannot be computed, so infinite bandwidth is treated
    /// as permanently underfilled. The real scarcity is then the finite slot count
    /// (`GetSoftMaxUploadSlots`): an idle/no-request holder occupying a slot a
    /// waiter wants is always replacement-pressured. The caller has already
    /// established the active (slot-holding) phase and the non-empty waiting queue,
    /// so returning `true` here confines the unlimited-mode recycle to precisely
    /// the slot-scarcity case (a waiter denied a slot by an idle holder), matching
    /// the oracle's waiter-driven `HasNoRequestUploadReplacementPressure` (:1570).
    fn recycle_underfill_signal_ready(&self, now: Instant) -> bool {
        if self.config.upload_limit_bytes_per_sec == 0 {
            return true;
        }
        self.sustained_recycle_underfill_ready(now)
    }

    fn refresh_elastic_underfill(&mut self, now: Instant) {
        if self.config.upload_limit_bytes_per_sec == 0 {
            self.underfill_since = None;
            return;
        }
        let spare_budget = self
            .config
            .upload_limit_bytes_per_sec
            .saturating_sub(self.upload_rate_bytes_per_sec(now));
        if spare_budget >= self.config.elastic_underfill_bytes_per_sec {
            self.underfill_since.get_or_insert(now);
        } else {
            self.underfill_since = None;
        }
    }

    /// Aggregate upload datarate: the 30 s sliding-window meter (oracle
    /// `CUploadQueue::datarate` computed from `average_ur_hist`,
    /// UploadQueue.cpp:2761-2764). This is the value the oracle's `ForceNewClient`
    /// pace gate (`datarate < 102400`, UploadQueue.cpp:972) and
    /// `IsBroadbandUploadUnderfilled` (via `GetToNetworkDatarate`,
    /// UploadQueue.cpp:1034) read -- NOT a lifetime cumulative average.
    fn upload_rate_bytes_per_sec(&self, now: Instant) -> u64 {
        self.aggregate_rate_meter.rate_bytes_per_sec(now)
    }

    fn slow_upload_threshold_bytes_per_sec(&self) -> u64 {
        let base_slots = self.config.active_slots.max(1) as u64;
        let target_per_slot = self.config.upload_limit_bytes_per_sec / base_slots;
        target_per_slot.saturating_div(20).max(1024)
    }
}

/// Oracle same-client resolution (`CUpDownClient::Compare`,
/// DownloadClient.cpp:275): when both peers present a user hash, the hash alone
/// decides (two same-endpoint clients with different hashes stay distinct);
/// otherwise the connection endpoint (IP + advertised TCP port) identifies the
/// client.
fn same_upload_client(left: &Ed2kUploadPeerIdentity, right: &Ed2kUploadPeerIdentity) -> bool {
    if let (Some(left_hash), Some(right_hash)) = (left.user_hash, right.user_hash) {
        return left_hash == right_hash;
    }
    left.ip == right.ip && left.tcp_port == right.tcp_port
}

fn upload_payload_interval(byte_count: u64, limit_bytes_per_sec: u64) -> Duration {
    let nanos = (u128::from(byte_count) * 1_000_000_000u128)
        .div_ceil(u128::from(limit_bytes_per_sec.max(1)));
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

mod admission;
mod helpers;
mod rate_meter;
mod score;
pub(crate) use helpers::is_low_id_client_id;
pub(super) use helpers::{credit_score_permille, upload_priority_score};
use helpers::{
    phase_snapshot, upload_client_id_matches, upload_snapshot_sort_key, upload_speed_bytes_per_sec,
};
use rate_meter::{AGGREGATE_RATE_WINDOW, PER_SLOT_RATE_WINDOW, WindowedRateMeter};
use score::UploadScoreModifiers;

/// Construct a minimal default upload peer identity for the score module's unit
/// tests (all flags false / zero, no LowID).
#[cfg(test)]
pub(super) fn test_support_peer() -> Ed2kUploadPeerIdentity {
    use std::net::Ipv4Addr;
    Ed2kUploadPeerIdentity {
        ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        tcp_port: 4662,
        udp_port: None,
        udp_version: 0,
        should_crypt: false,
        user_hash: Some([1; 16]),
        client_id: Some(0x0102_0304),
        friend_slot: false,
        ident_verified: false,
        ident_bad_guy: false,
        gpl_evildoer: false,
        banned: false,
        emule_version: 0,
        is_emule_client: false,
        kad_port: 0,
        supports_direct_udp_callback: false,
        firewall_context: Ed2kUploadFirewallContext::default(),
        client_software: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_waiting_timeout_matches_emule_purge_window() {
        assert_eq!(
            Ed2kUploadQueueConfig::default().waiting_timeout.as_secs(),
            DEFAULT_WAITING_TIMEOUT_SECS
        );
    }

    #[test]
    fn default_session_caps_match_oracle_rotation_defaults() {
        // Oracle defaults: rotate a slot session after 90% of the file
        // (PreferenceValidationSeams.h:48) or 7200 s (:53).
        let config = Ed2kUploadQueueConfig::default();
        assert_eq!(config.session_transfer_percent, 90);
        assert_eq!(config.session_time_limit.as_secs(), 7_200);
    }

    #[test]
    fn upload_priority_score_resolves_auto_like_publish_ranker() {
        // Explicit tiers = CUpDownClient::GetFilePrioAsNumber (UploadClient.cpp
        // :401-425): VERYLOW->2, LOW->6, NORMAL->7, HIGH->9, VERYHIGH->18.
        assert_eq!(upload_priority_score("verylow", false, 0), 2);
        assert_eq!(upload_priority_score("low", false, 0), 6);
        assert_eq!(upload_priority_score("normal", false, 0), 7);
        assert_eq!(upload_priority_score("high", false, 0), 9);
        assert_eq!(upload_priority_score("veryhigh", false, 0), 18);
        assert_eq!(upload_priority_score("release", false, 0), 18);
        // Auto empty/short queue -> HIGH (9), matching the publish ranker's HIGH
        // resolution, NOT the NORMAL (7) it used to collapse to.
        assert_eq!(upload_priority_score("normal", true, 0), 9);
        assert_eq!(upload_priority_score("auto", false, 1), 9);
        // GetQueuedCount() > 1 -> NORMAL (7); > 20 -> LOW (6).
        assert_eq!(upload_priority_score("normal", true, 2), 7);
        assert_eq!(upload_priority_score("normal", true, 21), 6);
    }

    #[test]
    fn upload_client_count_for_file_counts_sessions_per_hash() {
        let mut queue = Ed2kUploadQueueState::new(Ed2kUploadQueueConfig::default());
        let now = Instant::now();
        let mut peer_a = test_support_peer();
        peer_a.client_id = Some(0x0102_0304);
        peer_a.user_hash = Some([1; 16]);
        let mut peer_b = test_support_peer();
        peer_b.client_id = Some(0x0102_0305);
        peer_b.user_hash = Some([2; 16]);
        peer_b.tcp_port = 4663;
        let hash_x = "aa".repeat(16);
        let hash_y = "bb".repeat(16);
        queue.begin_session(
            Ed2kUploadSessionKey {
                peer: peer_a,
                file_hash: hash_x.clone(),
            },
            1,
            now,
            7,
            1_000,
            5_000,
            1_000,
        );
        queue.begin_session(
            Ed2kUploadSessionKey {
                peer: peer_b,
                file_hash: hash_x.clone(),
            },
            2,
            now,
            7,
            1_000,
            5_000,
            1_000,
        );
        assert_eq!(queue.upload_client_count_for_file(&hash_x), 2);
        assert_eq!(queue.upload_client_count_for_file(&hash_y), 0);
    }
}
