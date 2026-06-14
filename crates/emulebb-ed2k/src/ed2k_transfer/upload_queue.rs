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

/// Upload-slot and waiting-queue policy used by the inbound ED2K listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ed2kUploadQueueConfig {
    /// Maximum number of concurrently granted upload sessions.
    pub active_slots: usize,
    /// Maximum number of queued waiters retained at once.
    pub waiting_capacity: usize,
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
            waiting_capacity: 512,
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
    uploaded_bytes: u64,
    upload_started_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UploadScoreInputs {
    waiting_seconds: i128,
    friend_slot: bool,
    file_priority_score: i128,
    credit_score_permille: i128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UploadScorePolicy;

impl UploadScorePolicy {
    fn waiting_score(inputs: UploadScoreInputs) -> i128 {
        inputs.waiting_seconds * inputs.file_priority_score * inputs.credit_score_permille
            / DEFAULT_CREDIT_SCORE_PERMILLE
            + friend_slot_score(inputs.friend_slot)
    }
}

#[derive(Debug)]
pub(super) struct Ed2kUploadQueueState {
    config: Ed2kUploadQueueConfig,
    sessions: HashMap<Ed2kUploadSessionKey, Ed2kUploadSessionEntry>,
    waiting_order: Vec<Ed2kUploadSessionKey>,
    next_waiting_sequence: u64,
}

impl Ed2kUploadQueueState {
    pub(super) fn new(config: Ed2kUploadQueueConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            waiting_order: Vec::new(),
            next_waiting_sequence: 1,
        }
    }

    pub(super) fn configure(&mut self, config: Ed2kUploadQueueConfig) {
        self.config = config;
        let now = Instant::now();
        self.reap_expired_sessions(now);
        self.trim_waiting_queue(now);
        self.promote_waiters(now);
    }

    pub(super) const fn config(&self) -> Ed2kUploadQueueConfig {
        self.config
    }

    pub(super) fn begin_session(
        &mut self,
        key: Ed2kUploadSessionKey,
        connection_id: u64,
        now: Instant,
        file_priority_score: i128,
        credit_score_permille: i128,
    ) -> Ed2kUploadSessionStatus {
        self.reap_expired_sessions(now);
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
            self.sessions.insert(key.clone(), session);
            return self.status_for_key(&key, now);
        }

        let phase = if self.active_session_count() < self.config.active_slots {
            Ed2kUploadSessionPhase::Granted
        } else {
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
                (now.duration_since(session.last_activity) > timeout).then(|| key.clone())
            })
            .collect::<Vec<_>>();
        for key in expired {
            self.sessions.remove(&key);
            self.waiting_order.retain(|queued| queued != &key);
        }
        self.promote_waiters(now);
    }

    fn promote_waiters(&mut self, now: Instant) {
        while self.active_session_count() < self.config.active_slots {
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
        UploadScorePolicy::waiting_score(UploadScoreInputs {
            waiting_seconds: now.saturating_duration_since(session.queued_at).as_secs() as i128,
            friend_slot: key.peer.friend_slot
                && !key.peer.client_id.is_some_and(is_low_id_client_id),
            file_priority_score: session.file_priority_score,
            credit_score_permille: session.credit_score_permille,
        })
    }

    fn take_waiting_sequence(&mut self) -> u64 {
        let sequence = self.next_waiting_sequence;
        self.next_waiting_sequence = self.next_waiting_sequence.saturating_add(1);
        sequence
    }
}

mod helpers;
pub(super) use helpers::{credit_score_permille, upload_priority_score};
use helpers::{
    friend_slot_score, is_low_id_client_id, phase_snapshot, upload_client_id_matches,
    upload_snapshot_sort_key, upload_speed_bytes_per_sec,
};
