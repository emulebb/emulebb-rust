use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    net::IpAddr,
    time::{Duration, Instant},
};

const DEFAULT_FILE_PRIORITY_SCORE: i128 = 7;
const VERY_LOW_FILE_PRIORITY_SCORE: i128 = 2;
const LOW_FILE_PRIORITY_SCORE: i128 = 6;
const HIGH_FILE_PRIORITY_SCORE: i128 = 9;
const RELEASE_FILE_PRIORITY_SCORE: i128 = 18;
const FRIEND_SLOT_SCORE_BONUS: i128 = 1_000_000_000;
pub(super) const DEFAULT_CREDIT_SCORE_PERMILLE: i128 = 1_000;
/// eMule default LowID score divisor (`PreferenceValidationSeams::kDefaultLowIDDivisor`):
/// a LowID waiter's score is divided by this to deprioritise unreachable peers
/// (master `inputs.uLowIdDivisor`, applied when `HasLowID() && divisor > 1`).
const LOW_ID_SCORE_DIVISOR: i128 = 2;
/// eMule old-client score penalty: the effective working score is multiplied by
/// 0.5 (`UploadScoreSeams::BuildUploadScoreBreakdown` `fWorkingScore *= 0.5f`)
/// for an old eMule client (`m_byEmuleVersion <= 0x19`).
const OLD_CLIENT_PENALTY_NUMERATOR: i128 = 1;
const OLD_CLIENT_PENALTY_DENOMINATOR: i128 = 2;

/// Sentinel all-time upload ratio (permille) used for an unknown requested file:
/// at/above the low-ratio threshold so the low-ratio score bonus is NOT applied,
/// mirroring eMule's `GetScoreBreakdown` early return for `pRequestedFile ==
/// NULL` (an unknown file never reaches the bonus).
pub(super) const LOW_RATIO_BONUS_DISABLED_RATIO_PERMILLE: i128 = 1_000;

/// eMule default soft queue size (`PreferenceValidationSeams::kDefaultQueueSize`),
/// the threshold the reask QUEUEFULL margin compares against.
pub(crate) const DEFAULT_SOFT_QUEUE_SIZE: u32 = 10_000;

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
            waiting_timeout: Duration::from_secs(180),
            granted_timeout: Duration::from_secs(30),
            upload_timeout: Duration::from_secs(90),
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
    /// Our-side firewalled-LowID callback admission context, set per-connection by
    /// the listener from the live server/Kad firewall state (master
    /// `AddClientToQueue` opening guard). Transient; excluded from identity
    /// eq/hash. Defaults to a non-firewalled state, so the guard never fires until
    /// the listener supplies real state.
    pub firewall_context: Ed2kUploadFirewallContext,
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
}

#[derive(Debug, Clone)]
struct Ed2kUploadSessionEntry {
    phase: Ed2kUploadSessionPhase,
    connection_id: u64,
    queued_at: Instant,
    last_activity: Instant,
    waiting_sequence: u64,
    file_priority_score: i128,
    credit_score_permille: i128,
    /// Per-session upload-score modifiers (LowID, bad-guy/banned/GPL zeroing,
    /// old-client penalty, low-ratio bonus), captured at admission.
    score_modifiers: UploadScoreModifiers,
    uploaded_bytes: u64,
    upload_started_at: Option<Instant>,
}

/// Rate-aware upload slot capacity state for diagnostics and policy tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed2kUploadQueueCapacitySnapshot {
    pub base_slots: usize,
    pub elastic_slots: usize,
    pub active_slots: usize,
    pub active_sessions: usize,
    pub waiting_sessions: usize,
    pub upload_rate_bytes_per_sec: u64,
    pub elastic_underfill: bool,
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
    next_waiting_sequence: u64,
    underfill_since: Option<Instant>,
    throttle_next_send_at: Option<Instant>,
}

impl Ed2kUploadQueueState {
    pub(super) fn new(config: Ed2kUploadQueueConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            waiting_order: Vec::new(),
            next_waiting_sequence: 1,
            underfill_since: None,
            throttle_next_send_at: None,
        }
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
            upload_rate_bytes_per_sec: self.upload_rate_bytes_per_sec(now),
            elastic_underfill: self.elastic_underfill_ready(now),
        };
        super::diag_sched::capacity_snapshot(
            snapshot.base_slots,
            snapshot.elastic_slots,
            snapshot.active_slots,
            snapshot.active_sessions,
            snapshot.waiting_sessions,
        );
        snapshot
    }

    pub(super) fn begin_session(
        &mut self,
        key: Ed2kUploadSessionKey,
        connection_id: u64,
        now: Instant,
        file_priority_score: i128,
        credit_score_permille: i128,
        all_time_upload_ratio_permille: i128,
    ) -> Ed2kUploadSessionStatus {
        self.reap_expired_sessions(now);
        let low_id = key.peer.client_id.is_some_and(is_low_id_client_id);
        let score_modifiers = UploadScoreModifiers::from_peer(
            &key.peer,
            low_id,
            all_time_upload_ratio_permille,
        );
        if let Some(existing_key) = self.session_key_for_peer(&key.peer) {
            let Some(mut session) = self.sessions.remove(&existing_key) else {
                unreachable!("existing peer queue key missing from session map");
            };
            if session.phase == Ed2kUploadSessionPhase::Waiting {
                self.replace_waiting_key(&existing_key, &key);
            }
            session.connection_id = connection_id;
            session.last_activity = now;
            session.file_priority_score = file_priority_score;
            session.credit_score_permille = credit_score_permille;
            session.score_modifiers = score_modifiers;
            self.sessions.insert(key.clone(), session);
            return self.status_for_key(&key, now);
        }

        self.refresh_elastic_underfill(now);
        let phase = if self.active_session_count() < self.effective_active_slot_limit(now) {
            Ed2kUploadSessionPhase::Granted
        } else {
            // No free slot: this peer would join the waiting queue, so apply the
            // master AddClientToQueue admission gates. First the firewalled-LowID
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
                queued_at: now,
                last_activity: now,
                waiting_sequence,
                file_priority_score,
                credit_score_permille,
                score_modifiers,
                uploaded_bytes: 0,
                upload_started_at: None,
            },
        );
        self.trim_waiting_queue(now);
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
        self.refresh_elastic_underfill(now);
        self.promote_waiters(now);
        self.status_for_key(&handle.key, now)
    }

    pub(super) fn release_session(&mut self, handle: &Ed2kUploadSessionHandle, now: Instant) {
        let Some(session) = self.sessions.get(&handle.key) else {
            return;
        };
        if session.connection_id != handle.connection_id {
            return;
        }
        let phase = session.phase;
        self.sessions.remove(&handle.key);
        if phase == Ed2kUploadSessionPhase::Waiting {
            self.waiting_order.retain(|key| key != &handle.key);
        }
        self.reap_expired_sessions(now);
        self.promote_waiters(now);
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

    fn session_key_for_peer(&self, peer: &Ed2kUploadPeerIdentity) -> Option<Ed2kUploadSessionKey> {
        self.sessions
            .keys()
            .find(|existing_key| existing_key.peer == *peer)
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

    fn trim_waiting_queue(&mut self, now: Instant) {
        while self.waiting_order.len() > self.config.waiting_capacity {
            let Some(evicted) = self.worst_waiting_key(now) else {
                return;
            };
            self.remove_waiting_key(&evicted);
        }
    }

    fn reap_expired_sessions(&mut self, now: Instant) {
        let expired = self
            .sessions
            .iter()
            .filter_map(|(key, session)| {
                let timeout = match session.phase {
                    Ed2kUploadSessionPhase::Waiting => self.config.waiting_timeout,
                    Ed2kUploadSessionPhase::Granted => self.config.granted_timeout,
                    Ed2kUploadSessionPhase::Uploading => self.config.upload_timeout,
                };
                (now.saturating_duration_since(session.last_activity) > timeout)
                    .then(|| (key.clone(), session.phase))
            })
            .collect::<Vec<_>>();
        for (key, phase) in expired {
            // An idle active slot reclaimed by the queue is a `recycle` (master
            // activeNoRequestRecycle*), distinct from a peer-initiated close; a
            // reaped waiter is a plain queue drop and is not emitted here.
            if matches!(
                phase,
                Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading
            ) {
                super::diag_sched::upload_slot_recycled(
                    &super::diag_sched::peer_label(key.peer.ip, key.peer.tcp_port),
                    key.peer.user_hash,
                    &key.file_hash,
                );
            }
            self.sessions.remove(&key);
            self.waiting_order.retain(|queued| queued != &key);
        }
        self.promote_waiters(now);
    }

    fn promote_waiters(&mut self, now: Instant) {
        self.refresh_elastic_underfill(now);
        while self.active_session_count() < self.effective_active_slot_limit(now) {
            let Some(next_key) = self.best_waiting_key(now) else {
                break;
            };
            self.waiting_order.retain(|queued| queued != &next_key);
            let Some(next_session) = self.sessions.get_mut(&next_key) else {
                continue;
            };
            next_session.phase = Ed2kUploadSessionPhase::Granted;
            next_session.last_activity = now;
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

    fn best_waiting_key(&self, now: Instant) -> Option<Ed2kUploadSessionKey> {
        self.ranked_waiting_keys(now)
            .first()
            .map(|key| (*key).clone())
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
        self.elastic_slot_allowance() != 0
            && self.underfill_since.is_some_and(|underfill_since| {
                now.saturating_duration_since(underfill_since) >= self.config.elastic_underfill
            })
    }

    fn refresh_elastic_underfill(&mut self, now: Instant) {
        if self.elastic_slot_allowance() == 0 || self.config.upload_limit_bytes_per_sec == 0 {
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

    fn upload_rate_bytes_per_sec(&self, now: Instant) -> u64 {
        self.sessions
            .values()
            .filter_map(|session| {
                let elapsed = session
                    .upload_started_at
                    .map(|started_at| now.saturating_duration_since(started_at).as_secs())
                    .unwrap_or(0);
                if elapsed == 0 {
                    None
                } else {
                    Some(session.uploaded_bytes / elapsed)
                }
            })
            .sum()
    }
}

fn upload_payload_interval(byte_count: u64, limit_bytes_per_sec: u64) -> Duration {
    let nanos = (u128::from(byte_count) * 1_000_000_000u128)
        .div_ceil(u128::from(limit_bytes_per_sec.max(1)));
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

mod admission;
mod helpers;
mod score;
pub(super) use helpers::{credit_score_permille, upload_priority_score};
use helpers::{
    is_low_id_client_id, phase_snapshot, upload_client_id_matches, upload_snapshot_sort_key,
    upload_speed_bytes_per_sec,
};
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
        firewall_context: Ed2kUploadFirewallContext::default(),
    }
}
