use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use num_bigint::BigUint;
use rand::{Rng, RngExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    sync::RwLock,
};
use tracing::{debug, warn};

use crate::ed2k_tcp::MAX_ED2K_PACKET_LEN;

use super::Ed2kServerFailure;
#[cfg(feature = "packet-diagnostics")]
use super::diagnostics::{Ed2kServerPacketCapture, Ed2kServerSendAttempt};
use super::offer_policy::{
    OFFER_FILES_LEGACY_MIN_INTERVAL, OFFER_FILES_NEGOTIATION_WAIT,
    OfferFilesCapabilityAdvertisement, OfferFilesPolicy,
};
use super::startup::OfferedFileEntry;
use super::{
    EMULE_ENCRYPTION_METHOD_OBFUSCATION, EMULE_TCP_CRYPT_MAGIC_REQUESTER,
    EMULE_TCP_CRYPT_MAGIC_SERVER, EMULE_TCP_CRYPT_MAGIC_SYNC, Ed2kServerState, OP_EDONKEYPROT,
    OP_PACKEDPROT, Rc4KeyStream, SERVER_OBFUSCATION_MAX_PADDING_LEN,
    SERVER_OBFUSCATION_PRIME_BYTES, SERVER_OBFUSCATION_PUBLIC_KEY_LEN,
    SERVER_OBFUSCATION_RANDOM_EXPONENT_LEN, SERVER_TCP_FLAG_COMPRESSION, TCP_PACKET_HEADER_LEN,
    biguint_to_fixed_be, decode_server_payload, derive_server_cipher, dump_ed2k_server_meta,
    dump_ed2k_server_packet, encode_packet, random_non_protocol_marker, random_nonzero_biguint,
    server_opcode_allows_compression,
};

static NEXT_SERVER_SESSION_TRACE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(super) struct Ed2kPacket {
    pub(super) opcode: u8,
    pub(super) payload: Vec<u8>,
}

enum ServerPacketRead {
    Packet(Ed2kPacket),
    Eof,
    DroppedPackedFrame,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ServerSessionPhase {
    Connecting,
    AwaitingIdChange,
    Connected,
    OfferFilesSent,
    SearchActive,
    AwaitingMore,
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum OfferFilesPacingMode {
    AwaitingCapability,
    FallbackReconnect { reason: String },
    Legacy { reason: String },
    Negotiated(OfferFilesPolicy),
}

impl ServerSessionPhase {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::AwaitingIdChange => "awaiting_idchange",
            Self::Connected => "connected",
            Self::OfferFilesSent => "offer_files_sent",
            Self::SearchActive => "search_active",
            Self::AwaitingMore => "awaiting_more",
            Self::Completed => "completed",
        }
    }
}

#[derive(Debug)]
pub(super) struct ServerSession {
    stream: TcpStream,
    pub(super) endpoint: SocketAddr,
    pub(super) state: Arc<RwLock<Ed2kServerState>>,
    pub(super) trace_id: u64,
    pub(super) trace_role: &'static str,
    pub(super) last_tx: Instant,
    pub(super) receive_cipher: Option<Rc4KeyStream>,
    pub(super) send_cipher: Option<Rc4KeyStream>,
    /// Absolute stock `CONSERVTIMEOUT` deadline for this pending transport
    /// attempt. It starts before TCP connect and is cleared only after a valid,
    /// non-zero `OP_IDCHANGE` accepts the login.
    pub(super) pending_login_deadline: Option<Instant>,
    pub(super) login_accepted: bool,
    pub(super) probe_search_sent: bool,
    pub(super) offer_files_sent: bool,
    pub(super) offer_files_sent_at: Option<Instant>,
    pub(super) offer_files_catalog_fingerprint: Option<u64>,
    pub(super) offer_files_catalog_cursor: usize,
    pub(super) offer_files_published_hashes: HashSet<[u8; 16]>,
    pub(super) offer_files_distinct_published_hashes: HashSet<[u8; 16]>,
    pub(super) offer_files_ranked_catalog: Vec<OfferedFileEntry>,
    pub(super) offer_files_refresh_catalog: bool,
    pub(super) offer_files_pacing: OfferFilesPacingMode,
    pub(super) offer_files_capability_enabled: bool,
    pub(super) offer_files_capability_snapshot: Option<OfferFilesCapabilityAdvertisement>,
    pub(super) offer_files_negotiation_deadline: Option<Instant>,
    pub(super) offer_files_next_publish_at: Option<Instant>,
    pub(super) offer_files_publish_requested: bool,
    pub(super) offer_files_last_batch_entries: usize,
    pub(super) assigned_client_id: Option<u32>,
    pub(super) server_flags: Option<u32>,
    /// Soft file limit of the connected server (from the resolved entry); 0 when
    /// unknown. Caps the OP_OFFERFILES batch size together with
    /// `server_hard_files` (see `server_offer_file_limit`).
    pub(super) server_soft_files: u32,
    pub(super) server_hard_files: u32,
    pub(super) server_list_requested: bool,
    pub(super) phase: ServerSessionPhase,
}

impl ServerSession {
    pub(super) async fn connect(
        bind_ip: Ipv4Addr,
        endpoint: SocketAddr,
        state: Arc<RwLock<Ed2kServerState>>,
        trace_role: &'static str,
        timeout: Duration,
    ) -> Result<Self> {
        Self::connect_until(
            bind_ip,
            endpoint,
            state,
            trace_role,
            Instant::now() + timeout,
        )
        .await
    }

    pub(super) async fn connect_until(
        bind_ip: Ipv4Addr,
        endpoint: SocketAddr,
        state: Arc<RwLock<Ed2kServerState>>,
        trace_role: &'static str,
        pending_login_deadline: Instant,
    ) -> Result<Self> {
        {
            let mut guard = state.write().await;
            guard.connecting = true;
            guard.connected = false;
            guard.endpoint = Some(endpoint);
        }
        let stream = match async {
            let socket = TcpSocket::new_v4().map_err(|error| {
                Ed2kServerFailure::local_socket(format!(
                    "failed to create ED2K server TCP socket: {error}"
                ))
            })?;
            socket
                .bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
                .map_err(|error| {
                    Ed2kServerFailure::local_socket(format!(
                        "failed to bind ED2K server socket to {bind_ip}: {error}"
                    ))
                })?;
            let bind_if_index =
                crate::networking::require_bind_if_index(bind_ip, "ED2K server TCP").map_err(
                    |error| {
                        Ed2kServerFailure::local_socket(format!(
                            "failed to resolve ED2K server bind interface for {bind_ip}: {error}"
                        ))
                    },
                )?;
            // Egress-pin to the VPN tunnel interface (IP_UNICAST_IF) before connect
            // so the server session leaves via the tunnel — solid VPN binding.
            emulebb_kad_dht::socket_opts::pin_egress_to_interface(
                socket2::SockRef::from(&socket),
                Some(bind_if_index),
            )
            .map_err(|error| {
                Ed2kServerFailure::local_socket(format!(
                    "failed to pin ED2K server egress for {bind_ip}: {error}"
                ))
            })?;
            let stream = match tokio::time::timeout_at(
                tokio::time::Instant::from_std(pending_login_deadline),
                socket.connect(endpoint),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    return Err(anyhow::Error::new(Ed2kServerFailure::connect_io(
                        endpoint, &error,
                    )));
                }
                Err(error) => {
                    return Err(anyhow::Error::new(Ed2kServerFailure::connect_timeout(
                        format!("timed out connecting to ED2K server {endpoint}: {error}"),
                    )));
                }
            };
            stream.set_nodelay(true).map_err(|error| {
                Ed2kServerFailure::local_socket(format!(
                    "failed to enable TCP_NODELAY for ED2K server {endpoint}: {error}"
                ))
            })?;
            Ok::<TcpStream, anyhow::Error>(stream)
        }
        .await
        {
            Ok(stream) => stream,
            Err(error) => {
                let mut guard = state.write().await;
                if guard.connecting && guard.endpoint == Some(endpoint) {
                    guard.connecting = false;
                    guard.endpoint = None;
                }
                return Err(error);
            }
        };
        let trace_id = NEXT_SERVER_SESSION_TRACE_ID.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            stream,
            endpoint,
            state,
            trace_id,
            trace_role,
            last_tx: Instant::now(),
            receive_cipher: None,
            send_cipher: None,
            pending_login_deadline: Some(pending_login_deadline),
            login_accepted: false,
            probe_search_sent: false,
            offer_files_sent: false,
            offer_files_sent_at: None,
            offer_files_catalog_fingerprint: None,
            offer_files_catalog_cursor: 0,
            offer_files_published_hashes: HashSet::new(),
            offer_files_distinct_published_hashes: HashSet::new(),
            offer_files_ranked_catalog: Vec::new(),
            offer_files_refresh_catalog: true,
            offer_files_pacing: OfferFilesPacingMode::AwaitingCapability,
            offer_files_capability_enabled: true,
            offer_files_capability_snapshot: None,
            offer_files_negotiation_deadline: None,
            offer_files_next_publish_at: None,
            offer_files_publish_requested: false,
            offer_files_last_batch_entries: 0,
            assigned_client_id: None,
            server_flags: None,
            server_soft_files: 0,
            server_hard_files: 0,
            server_list_requested: false,
            phase: ServerSessionPhase::Connecting,
        })
    }

    #[cfg(test)]
    pub(super) fn from_stream_for_test(stream: TcpStream, endpoint: SocketAddr) -> Self {
        let trace_id = NEXT_SERVER_SESSION_TRACE_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            stream,
            endpoint,
            state: Arc::new(RwLock::new(Ed2kServerState::default())),
            trace_id,
            trace_role: "test",
            last_tx: Instant::now(),
            receive_cipher: None,
            send_cipher: None,
            pending_login_deadline: None,
            login_accepted: false,
            probe_search_sent: false,
            offer_files_sent: false,
            offer_files_sent_at: None,
            offer_files_catalog_fingerprint: None,
            offer_files_catalog_cursor: 0,
            offer_files_published_hashes: HashSet::new(),
            offer_files_distinct_published_hashes: HashSet::new(),
            offer_files_ranked_catalog: Vec::new(),
            offer_files_refresh_catalog: true,
            offer_files_pacing: OfferFilesPacingMode::AwaitingCapability,
            offer_files_capability_enabled: true,
            offer_files_capability_snapshot: None,
            offer_files_negotiation_deadline: None,
            offer_files_next_publish_at: None,
            offer_files_publish_requested: false,
            offer_files_last_batch_entries: 0,
            assigned_client_id: None,
            server_flags: None,
            server_soft_files: 0,
            server_hard_files: 0,
            server_list_requested: false,
            phase: ServerSessionPhase::Connecting,
        }
    }

    pub(super) fn set_phase(&mut self, phase: ServerSessionPhase, note: impl Into<String>) {
        self.phase = phase;
        dump_ed2k_server_meta(self, note);
    }

    pub(super) fn configure_offer_files_capability(&mut self, enabled: bool) {
        self.offer_files_capability_enabled = enabled;
        if !enabled {
            self.configure_offer_files_legacy("disabled by client setting");
        }
    }

    pub(super) fn configure_offer_files_legacy(&mut self, reason: impl Into<String>) {
        self.offer_files_capability_enabled = false;
        self.offer_files_pacing = OfferFilesPacingMode::Legacy {
            reason: reason.into(),
        };
        self.offer_files_negotiation_deadline = None;
    }

    fn reset_offer_files_publication_epoch(&mut self) {
        self.offer_files_sent = false;
        self.offer_files_sent_at = None;
        self.offer_files_catalog_fingerprint = None;
        self.offer_files_catalog_cursor = 0;
        self.offer_files_published_hashes.clear();
        self.offer_files_distinct_published_hashes.clear();
        self.offer_files_ranked_catalog.clear();
        self.offer_files_refresh_catalog = true;
        self.offer_files_negotiation_deadline = None;
        self.offer_files_next_publish_at = None;
        self.offer_files_publish_requested = false;
        self.offer_files_last_batch_entries = 0;
    }

    pub(super) async fn begin_offer_files_publishing(&mut self) {
        self.reset_offer_files_publication_epoch();
        self.offer_files_publish_requested = true;
        if !self.offer_files_capability_enabled {
            self.offer_files_next_publish_at = Some(Instant::now());
            self.publish_offer_files_pacing_state().await;
            return;
        }
        if let Some(advertisement) = self.offer_files_capability_snapshot.clone() {
            self.lock_offer_files_capability(advertisement);
            if self.offer_files_pacing_allows_publication() {
                self.offer_files_next_publish_at = Some(Instant::now());
            }
        } else {
            self.offer_files_pacing = OfferFilesPacingMode::AwaitingCapability;
            self.offer_files_negotiation_deadline =
                Some(Instant::now() + OFFER_FILES_NEGOTIATION_WAIT);
            // A client that requested v1 is bound by the server's advertised
            // limits. Wait briefly for the first OP_SERVERIDENT so a queued
            // welcome frame cannot lose a race with an immediate publication.
            self.offer_files_next_publish_at = None;
        }
        self.publish_offer_files_pacing_state().await;
    }

    pub(super) async fn observe_offer_files_capability(
        &mut self,
        advertisement: OfferFilesCapabilityAdvertisement,
    ) {
        if self.offer_files_capability_snapshot.is_some() {
            debug!(
                "ignoring repeated ED2K offer-files capability from {} after the connection snapshot was fixed",
                self.endpoint
            );
            return;
        }
        self.offer_files_capability_snapshot = Some(advertisement.clone());
        if self.offer_files_capability_enabled
            && matches!(
                self.offer_files_pacing,
                OfferFilesPacingMode::AwaitingCapability
            )
        {
            self.lock_offer_files_capability(advertisement);
            if self.login_accepted
                && self.offer_files_publish_requested
                && self.offer_files_pacing_allows_publication()
            {
                self.schedule_offer_files_after_pacing_resolution();
            }
        } else if self.login_accepted {
            debug!(
                "ignoring late ED2K offer-files capability from {} after pacing mode was locked",
                self.endpoint
            );
        }
        self.publish_offer_files_pacing_state().await;
    }

    pub(super) fn has_server_ident_snapshot(&self) -> bool {
        self.offer_files_capability_snapshot.is_some()
    }

    fn lock_offer_files_capability(&mut self, advertisement: OfferFilesCapabilityAdvertisement) {
        self.offer_files_negotiation_deadline = None;
        self.offer_files_pacing = match advertisement {
            OfferFilesCapabilityAdvertisement::Supported(policy) => {
                OfferFilesPacingMode::Negotiated(policy)
            }
            OfferFilesCapabilityAdvertisement::Absent => OfferFilesPacingMode::Legacy {
                reason: "capability absent".to_string(),
            },
            OfferFilesCapabilityAdvertisement::Invalid(reason) => {
                OfferFilesPacingMode::FallbackReconnect {
                    reason: format!("invalid capability: {reason}"),
                }
            }
        };
    }

    fn offer_files_pacing_allows_publication(&self) -> bool {
        matches!(
            self.offer_files_pacing,
            OfferFilesPacingMode::Legacy { .. } | OfferFilesPacingMode::Negotiated(_)
        )
    }

    fn schedule_offer_files_after_pacing_resolution(&mut self) {
        if !self.offer_files_publish_requested {
            self.offer_files_next_publish_at = None;
            return;
        }
        let now = Instant::now();
        let due = match (self.offer_files_sent_at, &self.offer_files_pacing) {
            (Some(sent_at), OfferFilesPacingMode::Legacy { .. }) => {
                sent_at + OFFER_FILES_LEGACY_MIN_INTERVAL
            }
            (Some(sent_at), OfferFilesPacingMode::Negotiated(policy)) => {
                sent_at + policy.next_batch_delay(self.offer_files_last_batch_entries.max(1))
            }
            _ => now,
        };
        self.offer_files_next_publish_at = Some(due.max(now));
    }

    pub(super) fn offer_files_negotiation_timeout_due(&self) -> bool {
        matches!(
            self.offer_files_pacing,
            OfferFilesPacingMode::AwaitingCapability
        ) && self
            .offer_files_negotiation_deadline
            .is_some_and(|deadline| deadline <= Instant::now())
    }

    pub(super) async fn request_offer_files_negotiation_fallback(&mut self) {
        if matches!(
            self.offer_files_pacing,
            OfferFilesPacingMode::AwaitingCapability
        ) {
            self.offer_files_pacing = OfferFilesPacingMode::FallbackReconnect {
                reason: "OP_SERVERIDENT capability timeout".to_string(),
            };
            self.offer_files_negotiation_deadline = None;
            self.offer_files_next_publish_at = None;
            self.publish_offer_files_pacing_state().await;
        }
    }

    pub(super) fn offer_files_fallback_reconnect_reason(&self) -> Option<&str> {
        match &self.offer_files_pacing {
            OfferFilesPacingMode::FallbackReconnect { reason } => Some(reason),
            _ => None,
        }
    }

    pub(super) fn request_offer_files_publish(&mut self) {
        self.offer_files_publish_requested = true;
        self.offer_files_refresh_catalog = true;
        if !self.offer_files_pacing_allows_publication() {
            return;
        }
        let due = match (self.offer_files_sent_at, &self.offer_files_pacing) {
            (Some(sent_at), OfferFilesPacingMode::Legacy { .. }) => {
                sent_at + OFFER_FILES_LEGACY_MIN_INTERVAL
            }
            (Some(sent_at), OfferFilesPacingMode::Negotiated(policy)) => {
                sent_at + policy.next_batch_delay(self.offer_files_last_batch_entries.max(1))
            }
            _ => Instant::now(),
        };
        self.offer_files_next_publish_at = Some(
            self.offer_files_next_publish_at
                .map_or(due, |current| current.max(due)),
        );
    }

    pub(super) fn offer_files_wakeup_at(&self) -> Option<Instant> {
        let publish_deadline = self
            .offer_files_publish_requested
            .then_some(self.offer_files_next_publish_at)
            .flatten();
        match self.offer_files_pacing {
            OfferFilesPacingMode::FallbackReconnect { .. } => Some(Instant::now()),
            OfferFilesPacingMode::AwaitingCapability => {
                match (publish_deadline, self.offer_files_negotiation_deadline) {
                    (Some(publish), Some(negotiation)) => Some(publish.min(negotiation)),
                    (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
                    (None, None) => None,
                }
            }
            OfferFilesPacingMode::Legacy { .. } | OfferFilesPacingMode::Negotiated(_) => {
                publish_deadline
            }
        }
    }

    pub(super) fn offer_files_publish_due(&self) -> bool {
        self.login_accepted
            && self.offer_files_publish_requested
            && self.offer_files_pacing_allows_publication()
            && self
                .offer_files_next_publish_at
                .is_some_and(|due| due <= Instant::now())
    }

    pub(super) fn offer_files_batch_limit(&self) -> usize {
        match self.offer_files_pacing {
            OfferFilesPacingMode::Negotiated(policy) => policy.packet_max(),
            OfferFilesPacingMode::Legacy { .. } => super::server_entry::server_offer_file_limit(
                self.server_soft_files,
                self.server_hard_files,
            ),
            OfferFilesPacingMode::AwaitingCapability
            | OfferFilesPacingMode::FallbackReconnect { .. } => 0,
        }
    }

    pub(super) fn offer_files_new_candidate_limit(&self) -> usize {
        match self.offer_files_pacing {
            OfferFilesPacingMode::Negotiated(policy) => {
                policy.effective_batch_max(self.offer_files_distinct_published_hashes.len())
            }
            OfferFilesPacingMode::Legacy { .. } => self.offer_files_batch_limit(),
            OfferFilesPacingMode::AwaitingCapability
            | OfferFilesPacingMode::FallbackReconnect { .. } => 0,
        }
    }

    fn has_publishable_offer_files(&self) -> bool {
        let mut new_candidate_slots = self.offer_files_new_candidate_limit();
        self.offer_files_ranked_catalog.iter().any(|entry| {
            if self.offer_files_published_hashes.contains(&entry.0) {
                return false;
            }
            if self
                .offer_files_distinct_published_hashes
                .contains(&entry.0)
            {
                return true;
            }
            if new_candidate_slots == 0 {
                return false;
            }
            new_candidate_slots -= 1;
            true
        })
    }

    pub(super) fn finish_offer_files_batch(
        &mut self,
        entries_sent: usize,
        pending_entries: usize,
        skipped_duplicate_batch: bool,
    ) {
        if entries_sent > 0 {
            self.offer_files_last_batch_entries = entries_sent;
        }
        let has_budgeted_pending = match self.offer_files_pacing {
            OfferFilesPacingMode::Negotiated(_) => self.has_publishable_offer_files(),
            _ => true,
        };
        let continue_pump = pending_entries > 0
            && has_budgeted_pending
            && self.offer_files_batch_limit() > 0
            && !skipped_duplicate_batch
            && entries_sent > 0;
        self.offer_files_publish_requested = continue_pump;
        self.offer_files_next_publish_at =
            if continue_pump && self.offer_files_pacing_allows_publication() {
                match self.offer_files_pacing {
                    OfferFilesPacingMode::Negotiated(policy) => {
                        Some(Instant::now() + policy.next_batch_delay(entries_sent))
                    }
                    OfferFilesPacingMode::Legacy { .. } => {
                        Some(Instant::now() + OFFER_FILES_LEGACY_MIN_INTERVAL)
                    }
                    OfferFilesPacingMode::AwaitingCapability
                    | OfferFilesPacingMode::FallbackReconnect { .. } => None,
                }
            } else {
                None
            };
    }

    async fn publish_offer_files_pacing_state(&self) {
        let (mode, batch_max, min_interval_ms, fallback_reason) = match &self.offer_files_pacing {
            OfferFilesPacingMode::AwaitingCapability => ("awaitingCapability", None, None, None),
            OfferFilesPacingMode::FallbackReconnect { reason } => {
                ("fallbackReconnect", None, None, Some(reason.clone()))
            }
            OfferFilesPacingMode::Legacy { reason } => (
                "legacy",
                Some(super::server_entry::server_offer_file_limit(
                    self.server_soft_files,
                    self.server_hard_files,
                ) as u32),
                Some(OFFER_FILES_LEGACY_MIN_INTERVAL.as_millis() as u32),
                Some(reason.clone()),
            ),
            OfferFilesPacingMode::Negotiated(policy) => (
                "negotiatedV1",
                Some(policy.packet_max() as u32),
                Some(policy.min_interval_ms),
                None,
            ),
        };
        let mut state = self.state.write().await;
        state.offer_files_mode = Some(mode.to_string());
        state.offer_files_batch_max = batch_max;
        state.offer_files_min_interval_ms = min_interval_ms;
        state.offer_files_fallback_reason = fallback_reason;
        if let OfferFilesPacingMode::Negotiated(policy) = &self.offer_files_pacing {
            state.server_soft_files = Some(policy.soft_files);
            state.server_hard_files = Some(policy.hard_files);
        }
    }

    pub(super) async fn publish_offer_files_progress(
        &self,
        published_entries: usize,
        pending_entries: usize,
    ) {
        let mut state = self.state.write().await;
        state.offer_files_published_entries = published_entries;
        state.offer_files_pending_entries = pending_entries;
    }

    pub(super) async fn send_packet(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        // Only OP_OFFERFILES is packed on the server-TCP path, and only when the
        // server advertised SRV_TCPFLG_COMPRESSION; every other server-bound opcode
        // (OP_SEARCHREQUEST, OP_GETSOURCES, OP_GETSERVERLIST, OP_QUERY_MORE_RESULT,
        // OP_CALLBACKREQUEST, OP_LOGINREQUEST, keepalive) is sent uncompressed as
        // OP_EDONKEYPROT (0xE3). Matches CSharedFileList::SendListToServer
        // (SharedFileList.cpp:2723-2725), the sole server-bound PackPacket() call.
        let use_compression =
            server_opcode_allows_compression(opcode) && self.server_supports_compression();
        let mut packet = encode_packet(opcode, payload, use_compression)?;
        #[cfg(feature = "packet-diagnostics")]
        let clear_frame = packet.clone();
        // The wire may still be OP_EDONKEYPROT even when compression was permitted
        // (keep-if-smaller left the packet raw): report the actual protocol byte.
        let packed = packet[0] == OP_PACKEDPROT;
        debug!(
            "ED2K trace id={} role={} phase={} dir=tx endpoint={} opcode=0x{:02X} payload_len={} wire_len={} compressed={}",
            self.trace_id,
            self.trace_role,
            self.phase.as_str(),
            self.endpoint,
            opcode,
            payload.len(),
            packet.len(),
            packed
        );
        let protocol_marker = packet[0];
        #[cfg(feature = "packet-diagnostics")]
        let transport_mode = if self.send_cipher.is_some() {
            "obfuscated"
        } else {
            "plaintext"
        };
        if let Some(cipher) = self.send_cipher.as_mut() {
            cipher.apply(&mut packet);
        }
        #[cfg(feature = "packet-diagnostics")]
        let send_attempt = Ed2kServerSendAttempt::tcp(
            self,
            Ed2kServerPacketCapture {
                direction: "tx",
                transport_mode,
                obfuscated: Some(transport_mode == "obfuscated"),
                protocol_marker: Some(protocol_marker),
                opcode: Some(opcode),
                raw: &packet,
                clear_frame: Some(&clear_frame),
                payload: Some(payload),
                outcome: "attempted",
                note: None,
            },
        );
        #[cfg(not(feature = "packet-diagnostics"))]
        dump_ed2k_server_packet(self, "tx", protocol_marker, opcode, payload);
        let send_result =
            self.stream.write_all(&packet).await.with_context(|| {
                format!("failed to send opcode=0x{opcode:02X} to {}", self.endpoint)
            });
        match send_result {
            Ok(()) => {
                #[cfg(feature = "packet-diagnostics")]
                send_attempt.succeeded();
                self.last_tx = Instant::now();
                Ok(())
            }
            Err(error) => {
                #[cfg(feature = "packet-diagnostics")]
                send_attempt.failed(format!("{error:#}"));
                Err(error)
            }
        }
    }

    pub(super) async fn send_encoded_packet(
        &mut self,
        packet: &[u8],
        context: impl Into<String>,
    ) -> Result<()> {
        self.stream
            .write_all(packet)
            .await
            .with_context(|| context.into())?;
        self.last_tx = Instant::now();
        Ok(())
    }

    fn server_supports_compression(&self) -> bool {
        self.server_flags.unwrap_or_default() & SERVER_TCP_FLAG_COMPRESSION != 0
    }

    pub(super) async fn negotiate_obfuscation_and_send(
        &mut self,
        first_packet: &[u8],
    ) -> Result<()> {
        let prime = BigUint::from_bytes_be(&SERVER_OBFUSCATION_PRIME_BYTES);
        let generator = BigUint::from(2u8);
        let secret = random_nonzero_biguint(SERVER_OBFUSCATION_RANDOM_EXPONENT_LEN);
        let public = generator.modpow(&secret, &prime);
        let public_bytes = biguint_to_fixed_be(&public, SERVER_OBFUSCATION_PUBLIC_KEY_LEN)?;

        let mut request = Vec::with_capacity(1 + SERVER_OBFUSCATION_PUBLIC_KEY_LEN + 16);
        request.push(random_non_protocol_marker());
        request.extend_from_slice(&public_bytes);
        let initial_padding_len = rand::rng().random_range(0..=SERVER_OBFUSCATION_MAX_PADDING_LEN);
        request.push(u8::try_from(initial_padding_len).expect("padding length fits in u8"));
        let mut initial_padding = vec![0u8; initial_padding_len];
        rand::rng().fill_bytes(&mut initial_padding);
        request.extend_from_slice(&initial_padding);
        self.stream.write_all(&request).await.with_context(|| {
            format!(
                "failed to send ED2K server obfuscation request to {}",
                self.endpoint
            )
        })?;

        let mut remote_public_bytes = [0u8; SERVER_OBFUSCATION_PUBLIC_KEY_LEN];
        self.stream
            .read_exact(&mut remote_public_bytes)
            .await
            .with_context(|| {
                format!(
                    "failed to read ED2K server obfuscation DH answer from {}",
                    self.endpoint
                )
            })?;
        let remote_public = BigUint::from_bytes_be(&remote_public_bytes);
        let shared_secret = remote_public.modpow(&secret, &prime);
        let shared_secret_bytes =
            biguint_to_fixed_be(&shared_secret, SERVER_OBFUSCATION_PUBLIC_KEY_LEN)?;
        let mut send_cipher =
            derive_server_cipher(&shared_secret_bytes, EMULE_TCP_CRYPT_MAGIC_REQUESTER);
        let mut receive_cipher =
            derive_server_cipher(&shared_secret_bytes, EMULE_TCP_CRYPT_MAGIC_SERVER);

        let mut encrypted_header = [0u8; 7];
        self.stream
            .read_exact(&mut encrypted_header)
            .await
            .with_context(|| {
                format!(
                    "failed to read ED2K server obfuscation header from {}",
                    self.endpoint
                )
            })?;
        receive_cipher.apply(&mut encrypted_header);
        let magic = u32::from_le_bytes(encrypted_header[..4].try_into().unwrap());
        if magic != EMULE_TCP_CRYPT_MAGIC_SYNC {
            anyhow::bail!(
                "unexpected ED2K server obfuscation magic 0x{magic:08X} from {}",
                self.endpoint
            );
        }
        let server_preferred = encrypted_header[5];
        if server_preferred != EMULE_ENCRYPTION_METHOD_OBFUSCATION {
            debug!(
                "ED2K server {} preferred unsupported obfuscation method {}",
                self.endpoint, server_preferred
            );
        }
        let server_padding_len = usize::from(encrypted_header[6]);
        if server_padding_len > SERVER_OBFUSCATION_MAX_PADDING_LEN {
            debug!(
                "ED2K server {} sent {} obfuscation padding bytes",
                self.endpoint, server_padding_len
            );
        }
        if server_padding_len > 0 {
            let mut encrypted_padding = vec![0u8; server_padding_len];
            self.stream
                .read_exact(&mut encrypted_padding)
                .await
                .with_context(|| {
                    format!(
                        "failed to read ED2K server obfuscation padding from {}",
                        self.endpoint
                    )
                })?;
            receive_cipher.apply(&mut encrypted_padding);
        }

        let response_padding_len = rand::rng().random_range(0..=SERVER_OBFUSCATION_MAX_PADDING_LEN);
        let mut response = Vec::with_capacity(6 + response_padding_len + first_packet.len());
        response.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
        response.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        response.push(u8::try_from(response_padding_len).expect("padding length fits in u8"));
        let mut response_padding = vec![0u8; response_padding_len];
        rand::rng().fill_bytes(&mut response_padding);
        response.extend_from_slice(&response_padding);
        #[cfg(feature = "packet-diagnostics")]
        let first_packet_offset = response.len();
        response.extend_from_slice(first_packet);
        send_cipher.apply(&mut response);
        if first_packet.len() >= TCP_PACKET_HEADER_LEN {
            #[cfg(feature = "packet-diagnostics")]
            dump_ed2k_server_packet(
                self,
                Ed2kServerPacketCapture {
                    direction: "tx",
                    transport_mode: "obfuscated",
                    obfuscated: Some(true),
                    protocol_marker: Some(first_packet[0]),
                    opcode: Some(first_packet[5]),
                    raw: &response[first_packet_offset..],
                    clear_frame: Some(first_packet),
                    payload: Some(&first_packet[TCP_PACKET_HEADER_LEN..]),
                    outcome: "accepted",
                    note: None,
                },
            );
            #[cfg(not(feature = "packet-diagnostics"))]
            dump_ed2k_server_packet(
                self,
                "tx",
                first_packet[0],
                first_packet[5],
                &first_packet[TCP_PACKET_HEADER_LEN..],
            );
        }
        self.stream.write_all(&response).await.with_context(|| {
            format!(
                "failed to send ED2K server obfuscation response to {}",
                self.endpoint
            )
        })?;

        self.receive_cipher = Some(receive_cipher);
        self.send_cipher = Some(send_cipher);
        self.last_tx = Instant::now();
        dump_ed2k_server_meta(self, "server obfuscation negotiated");
        Ok(())
    }

    pub(super) async fn read_packet(&mut self) -> Result<Option<Ed2kPacket>> {
        loop {
            match self.read_framed_packet().await? {
                ServerPacketRead::Packet(packet) => return Ok(Some(packet)),
                ServerPacketRead::Eof => return Ok(None),
                ServerPacketRead::DroppedPackedFrame => {}
            }
        }
    }

    async fn read_framed_packet(&mut self) -> Result<ServerPacketRead> {
        let mut header = [0u8; TCP_PACKET_HEADER_LEN];
        match self.stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                debug!(
                    "ED2K trace id={} role={} phase={} dir=rx endpoint={} eof=true",
                    self.trace_id,
                    self.trace_role,
                    self.phase.as_str(),
                    self.endpoint
                );
                dump_ed2k_server_meta(self, "server session drop reason=eof");
                return Ok(ServerPacketRead::Eof);
            }
            Err(error) => {
                dump_ed2k_server_meta(
                    self,
                    format!("server session drop reason=read_error detail={error}"),
                );
                return Err(error.into());
            }
        }
        #[cfg(feature = "packet-diagnostics")]
        let raw_header = header;
        if let Some(cipher) = self.receive_cipher.as_mut() {
            cipher.apply(&mut header);
        }
        #[cfg(feature = "packet-diagnostics")]
        let transport_mode = if self.receive_cipher.is_some() {
            "obfuscated"
        } else {
            "plaintext"
        };

        if !matches!(header[0], OP_EDONKEYPROT | OP_PACKEDPROT) {
            let note = format!(
                "server session drop reason=read_error detail=unsupported_protocol_0x{:02X}",
                header[0]
            );
            #[cfg(feature = "packet-diagnostics")]
            dump_ed2k_server_packet(
                self,
                Ed2kServerPacketCapture {
                    direction: "rx",
                    transport_mode,
                    obfuscated: Some(transport_mode == "obfuscated"),
                    protocol_marker: Some(header[0]),
                    opcode: Some(header[5]),
                    raw: &raw_header,
                    clear_frame: Some(&header),
                    payload: None,
                    outcome: "dropped",
                    note: Some(note),
                },
            );
            #[cfg(not(feature = "packet-diagnostics"))]
            dump_ed2k_server_meta(self, note);
            anyhow::bail!(
                "unsupported ED2K server protocol 0x{:02X} from {}",
                header[0],
                self.endpoint
            );
        }

        let packet_length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
        if packet_length == 0 {
            let note = "server session drop reason=read_error detail=invalid_packet_length_0";
            #[cfg(feature = "packet-diagnostics")]
            dump_ed2k_server_packet(
                self,
                Ed2kServerPacketCapture {
                    direction: "rx",
                    transport_mode,
                    obfuscated: Some(transport_mode == "obfuscated"),
                    protocol_marker: Some(header[0]),
                    opcode: Some(header[5]),
                    raw: &raw_header,
                    clear_frame: Some(&header),
                    payload: None,
                    outcome: "dropped",
                    note: Some(note.to_string()),
                },
            );
            #[cfg(not(feature = "packet-diagnostics"))]
            dump_ed2k_server_meta(self, note);
            anyhow::bail!("invalid ED2K server packet length 0");
        }
        let payload_len = match usize::try_from(packet_length - 1) {
            Ok(payload_len) => payload_len,
            Err(error) => {
                let note =
                    format!("server session drop reason=read_error detail=length_overflow {error}");
                #[cfg(feature = "packet-diagnostics")]
                dump_ed2k_server_packet(
                    self,
                    Ed2kServerPacketCapture {
                        direction: "rx",
                        transport_mode,
                        obfuscated: Some(transport_mode == "obfuscated"),
                        protocol_marker: Some(header[0]),
                        opcode: Some(header[5]),
                        raw: &raw_header,
                        clear_frame: Some(&header),
                        payload: None,
                        outcome: "dropped",
                        note: Some(note),
                    },
                );
                #[cfg(not(feature = "packet-diagnostics"))]
                dump_ed2k_server_meta(self, note);
                anyhow::bail!("server packet length overflow");
            }
        };
        if payload_len > MAX_ED2K_PACKET_LEN {
            let note = format!(
                "server session drop reason=read_error detail=oversized_packet payload_len={payload_len} max={MAX_ED2K_PACKET_LEN}"
            );
            #[cfg(feature = "packet-diagnostics")]
            dump_ed2k_server_packet(
                self,
                Ed2kServerPacketCapture {
                    direction: "rx",
                    transport_mode,
                    obfuscated: Some(transport_mode == "obfuscated"),
                    protocol_marker: Some(header[0]),
                    opcode: Some(header[5]),
                    raw: &raw_header,
                    clear_frame: Some(&header),
                    payload: None,
                    outcome: "dropped",
                    note: Some(note),
                },
            );
            #[cfg(not(feature = "packet-diagnostics"))]
            dump_ed2k_server_meta(self, note);
            anyhow::bail!(
                "oversized ED2K server packet length {} exceeds {} from {}",
                payload_len,
                MAX_ED2K_PACKET_LEN,
                self.endpoint
            );
        }
        let mut payload = vec![0u8; payload_len];
        if let Err(error) = self.stream.read_exact(&mut payload).await {
            dump_ed2k_server_meta(
                self,
                format!("server session drop reason=read_error detail=payload_read {error}"),
            );
            return Err(error.into());
        }
        #[cfg(feature = "packet-diagnostics")]
        let raw_payload = payload.clone();
        if let Some(cipher) = self.receive_cipher.as_mut() {
            cipher.apply(&mut payload);
        }
        #[cfg(feature = "packet-diagnostics")]
        let clear_payload = payload.clone();
        #[cfg(feature = "packet-diagnostics")]
        let (raw_frame, clear_frame) = {
            let mut raw_frame = Vec::with_capacity(TCP_PACKET_HEADER_LEN + raw_payload.len());
            raw_frame.extend_from_slice(&raw_header);
            raw_frame.extend_from_slice(&raw_payload);
            let mut clear_frame = Vec::with_capacity(TCP_PACKET_HEADER_LEN + clear_payload.len());
            clear_frame.extend_from_slice(&header);
            clear_frame.extend_from_slice(&clear_payload);
            (raw_frame, clear_frame)
        };
        let payload = match decode_server_payload(header[0], payload) {
            Ok(payload) => payload,
            Err(error) if header[0] == OP_PACKEDPROT => {
                warn!(
                    "dropping malformed bounded ED2K packed frame from {} opcode=0x{:02X} compressed_len={}: {error}",
                    self.endpoint, header[5], payload_len
                );
                let note = format!(
                    "server packet drop reason=packed_decode opcode=0x{:02X} compressed_len={} detail={error}",
                    header[5], payload_len
                );
                #[cfg(feature = "packet-diagnostics")]
                dump_ed2k_server_packet(
                    self,
                    Ed2kServerPacketCapture {
                        direction: "rx",
                        transport_mode,
                        obfuscated: Some(transport_mode == "obfuscated"),
                        protocol_marker: Some(header[0]),
                        opcode: Some(header[5]),
                        raw: &raw_frame,
                        clear_frame: Some(&clear_frame),
                        payload: None,
                        outcome: "dropped",
                        note: Some(note),
                    },
                );
                #[cfg(not(feature = "packet-diagnostics"))]
                dump_ed2k_server_meta(self, note);
                return Ok(ServerPacketRead::DroppedPackedFrame);
            }
            Err(error) => {
                let note = format!("server session drop reason=read_error detail=decode {error}");
                #[cfg(feature = "packet-diagnostics")]
                dump_ed2k_server_packet(
                    self,
                    Ed2kServerPacketCapture {
                        direction: "rx",
                        transport_mode,
                        obfuscated: Some(transport_mode == "obfuscated"),
                        protocol_marker: Some(header[0]),
                        opcode: Some(header[5]),
                        raw: &raw_frame,
                        clear_frame: Some(&clear_frame),
                        payload: None,
                        outcome: "dropped",
                        note: Some(note),
                    },
                );
                #[cfg(not(feature = "packet-diagnostics"))]
                dump_ed2k_server_meta(self, note);
                return Err(error).with_context(|| {
                    format!("failed to decode ED2K server packet from {}", self.endpoint)
                });
            }
        };
        debug!(
            "ED2K trace id={} role={} phase={} dir=rx endpoint={} prot=0x{:02X} opcode=0x{:02X} payload_len={}",
            self.trace_id,
            self.trace_role,
            self.phase.as_str(),
            self.endpoint,
            header[0],
            header[5],
            payload.len()
        );
        #[cfg(feature = "packet-diagnostics")]
        {
            dump_ed2k_server_packet(
                self,
                Ed2kServerPacketCapture {
                    direction: "rx",
                    transport_mode,
                    obfuscated: Some(transport_mode == "obfuscated"),
                    protocol_marker: Some(header[0]),
                    opcode: Some(header[5]),
                    raw: &raw_frame,
                    clear_frame: Some(&clear_frame),
                    payload: Some(&payload),
                    outcome: "accepted",
                    note: None,
                },
            );
        }
        #[cfg(not(feature = "packet-diagnostics"))]
        dump_ed2k_server_packet(self, "rx", header[0], header[5], &payload);
        Ok(ServerPacketRead::Packet(Ed2kPacket {
            opcode: header[5],
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A peer that declares an oversized server packet length must be dropped
    /// before the payload buffer is allocated (raw-length cap mirroring
    /// `sizeof GlobalReadBuffer`), preventing an OOM denial of service.
    #[tokio::test]
    async fn server_read_rejects_oversized_declared_length() {
        let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = tokio::spawn(async move {
            let mut peer = TcpStream::connect(addr).await.unwrap();
            // OP_EDONKEYPROT header declaring packet_length = 0xFFFFFFFF (~4GB).
            let mut header = vec![OP_EDONKEYPROT];
            header.extend_from_slice(&u32::MAX.to_le_bytes());
            header.push(OP_EDONKEYPROT); // opcode byte (value irrelevant)
            peer.write_all(&header).await.unwrap();
            // Keep the peer alive so the server reads the header, not EOF.
            peer
        });
        let (stream, peer_addr) = listener.accept().await.unwrap();
        let _peer = writer.await.unwrap();
        let mut session = ServerSession::from_stream_for_test(stream, peer_addr);
        let err = session
            .read_packet()
            .await
            .expect_err("oversized server packet length must be rejected");
        assert!(
            err.to_string()
                .contains("oversized ED2K server packet length"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn server_read_drops_malformed_packed_frame_and_keeps_stream_aligned() {
        let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = tokio::spawn(async move {
            let mut peer = TcpStream::connect(addr).await.unwrap();
            let malformed_payload = [0x01, 0x02, 0x03];
            let mut wire = vec![OP_PACKEDPROT];
            wire.extend_from_slice(
                &u32::try_from(malformed_payload.len() + 1)
                    .unwrap()
                    .to_le_bytes(),
            );
            wire.push(super::super::OP_SEARCHRESULT);
            wire.extend_from_slice(&malformed_payload);

            let mut status_payload = 123u32.to_le_bytes().to_vec();
            status_payload.extend_from_slice(&456u32.to_le_bytes());
            wire.extend_from_slice(
                &encode_packet(super::super::OP_SERVERSTATUS, &status_payload, false).unwrap(),
            );
            peer.write_all(&wire).await.unwrap();
            peer
        });
        let (stream, peer_addr) = listener.accept().await.unwrap();
        let _peer = writer.await.unwrap();
        let mut session = ServerSession::from_stream_for_test(stream, peer_addr);

        let packet = session
            .read_packet()
            .await
            .unwrap()
            .expect("valid frame after malformed packed frame must remain readable");

        assert_eq!(packet.opcode, super::super::OP_SERVERSTATUS);
        assert_eq!(packet.payload[..4], 123u32.to_le_bytes());
        assert_eq!(packet.payload[4..], 456u32.to_le_bytes());
    }

    #[tokio::test]
    async fn server_read_keeps_invalid_raw_marker_transport_fatal() {
        let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = tokio::spawn(async move {
            let mut peer = TcpStream::connect(addr).await.unwrap();
            peer.write_all(&[0x01, 1, 0, 0, 0, 0x42]).await.unwrap();
            peer
        });
        let (stream, peer_addr) = listener.accept().await.unwrap();
        let _peer = writer.await.unwrap();
        let mut session = ServerSession::from_stream_for_test(stream, peer_addr);

        let error = session
            .read_packet()
            .await
            .expect_err("invalid raw protocol marker must remain transport-fatal");

        assert!(
            error
                .to_string()
                .contains("unsupported ED2K server protocol")
        );
    }

    #[tokio::test]
    async fn server_connect_rolls_back_connecting_state_on_setup_failure() {
        let state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4661);

        let err = ServerSession::connect(
            Ipv4Addr::new(203, 0, 113, 200),
            endpoint,
            Arc::clone(&state),
            "test",
            Duration::from_millis(10),
        )
        .await
        .expect_err("non-local bind IP should fail before a session is established");

        let failure = err
            .chain()
            .find_map(|cause| cause.downcast_ref::<Ed2kServerFailure>())
            .expect("setup failure should retain its classification");
        assert_eq!(
            failure.phase,
            crate::ed2k_server::Ed2kServerFailurePhase::SocketSetup
        );
        assert_eq!(
            failure.reason,
            crate::ed2k_server::Ed2kServerFailureReason::LocalBindInterface
        );
        assert!(!failure.counts_toward_dead_server());

        let guard = state.read().await;
        assert!(
            !guard.connecting,
            "failed setup left server state connecting after {err}"
        );
        assert!(!guard.connected);
        assert!(guard.endpoint.is_none());
    }

    #[tokio::test]
    async fn server_connect_classifies_closed_local_port_without_string_matching() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let endpoint = listener.local_addr().unwrap();
        drop(listener);
        let state = Arc::new(RwLock::new(Ed2kServerState::default()));

        let error = ServerSession::connect(
            Ipv4Addr::LOCALHOST,
            endpoint,
            state,
            "test",
            Duration::from_secs(1),
        )
        .await
        .expect_err("closed listener should refuse the connection");
        let failure = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<Ed2kServerFailure>())
            .expect("connect failure should retain its classification");
        assert_eq!(
            failure.phase,
            crate::ed2k_server::Ed2kServerFailurePhase::Connect
        );
        assert!(matches!(
            failure.reason,
            crate::ed2k_server::Ed2kServerFailureReason::ConnectionRefused
                | crate::ed2k_server::Ed2kServerFailureReason::TimeoutUnreachable
        ));
        assert_eq!(
            failure.counts_toward_dead_server(),
            failure.reason == crate::ed2k_server::Ed2kServerFailureReason::ConnectionRefused
        );
    }

    /// Establish a connected `ServerSession` (from the accepted end of a local
    /// pair) plus the remote peer stream that receives whatever the session sends.
    async fn connected_test_session_with_peer() -> (ServerSession, TcpStream) {
        let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = TcpStream::connect(addr).await.unwrap();
        let (stream, peer_addr) = listener.accept().await.unwrap();
        (ServerSession::from_stream_for_test(stream, peer_addr), peer)
    }

    #[tokio::test]
    async fn capability_discovery_holds_first_offer_until_server_ident() {
        let (mut session, _peer) = connected_test_session_with_peer().await;
        session.login_accepted = true;
        session.configure_offer_files_capability(true);

        session.begin_offer_files_publishing().await;

        assert!(matches!(
            session.offer_files_pacing,
            OfferFilesPacingMode::AwaitingCapability
        ));
        assert!(!session.offer_files_publish_due());
        assert_eq!(session.offer_files_next_publish_at, None);
        assert_eq!(
            session.offer_files_wakeup_at(),
            session.offer_files_negotiation_deadline
        );

        session
            .observe_offer_files_capability(OfferFilesCapabilityAdvertisement::Supported(
                OfferFilesPolicy::validate(1, 200, 1, 1_000, 201).unwrap(),
            ))
            .await;

        assert!(matches!(
            session.offer_files_pacing,
            OfferFilesPacingMode::Negotiated(_)
        ));
        assert!(session.offer_files_publish_due());
    }

    #[tokio::test]
    async fn capability_timeout_requires_a_fresh_legacy_connection() {
        let (mut session, _peer) = connected_test_session_with_peer().await;
        session.login_accepted = true;
        session.configure_offer_files_capability(true);
        session.begin_offer_files_publishing().await;

        session.request_offer_files_negotiation_fallback().await;

        assert!(matches!(
            session.offer_files_pacing,
            OfferFilesPacingMode::FallbackReconnect { .. }
        ));
        assert_eq!(
            session.offer_files_fallback_reconnect_reason(),
            Some("OP_SERVERIDENT capability timeout")
        );
        assert!(!session.offer_files_publish_due());
        assert!(session.offer_files_wakeup_at().is_some());
    }

    #[tokio::test]
    async fn explicit_absence_uses_legacy_publication_on_current_connection() {
        let (mut session, _peer) = connected_test_session_with_peer().await;
        session.login_accepted = true;
        session.configure_offer_files_capability(true);
        session.begin_offer_files_publishing().await;

        session
            .observe_offer_files_capability(OfferFilesCapabilityAdvertisement::Absent)
            .await;

        assert!(matches!(
            session.offer_files_pacing,
            OfferFilesPacingMode::Legacy { .. }
        ));
        assert_eq!(session.offer_files_fallback_reconnect_reason(), None);
        assert!(session.offer_files_publish_due());
    }

    #[tokio::test]
    async fn first_server_ident_snapshot_cannot_be_replaced() {
        let (mut session, _peer) = connected_test_session_with_peer().await;
        session.login_accepted = true;
        session.configure_offer_files_capability(true);
        session.begin_offer_files_publishing().await;
        let first =
            OfferFilesCapabilityAdvertisement::Invalid("malformed OP_SERVERIDENT".to_string());

        session.observe_offer_files_capability(first.clone()).await;
        session
            .observe_offer_files_capability(OfferFilesCapabilityAdvertisement::Supported(
                OfferFilesPolicy::validate(1, 25, 250, 1_000, 201).unwrap(),
            ))
            .await;

        assert_eq!(session.offer_files_capability_snapshot, Some(first));
        assert!(matches!(
            session.offer_files_pacing,
            OfferFilesPacingMode::FallbackReconnect { .. }
        ));
        assert!(!session.offer_files_publish_due());
    }

    #[tokio::test]
    async fn publish_request_never_shortens_negotiated_local_rate_limit() {
        let (mut session, _peer) = connected_test_session_with_peer().await;
        session.offer_files_pacing = OfferFilesPacingMode::Negotiated(
            OfferFilesPolicy::validate(1, 200, 1, 1_000, 201).unwrap(),
        );
        let sent_at = Instant::now();
        session.offer_files_sent_at = Some(sent_at);
        session.offer_files_last_batch_entries = 200;

        session.request_offer_files_publish();
        assert!(
            session.offer_files_next_publish_at.unwrap() >= sent_at + Duration::from_millis(500)
        );

        let existing_deadline = sent_at + Duration::from_millis(750);
        session.offer_files_next_publish_at = Some(existing_deadline);
        session.request_offer_files_publish();
        assert_eq!(
            session.offer_files_next_publish_at,
            Some(existing_deadline),
            "a re-trigger must preserve a later in-flight pacing deadline"
        );
    }

    #[tokio::test]
    async fn legacy_mode_keeps_large_catalog_rotation_on_the_session_timer() {
        let (mut session, _peer) = connected_test_session_with_peer().await;
        session.offer_files_pacing = OfferFilesPacingMode::Legacy {
            reason: "capability absent".to_string(),
        };
        let before = Instant::now();

        session.finish_offer_files_batch(200, 800, false);

        assert!(session.offer_files_publish_requested);
        assert!(
            session.offer_files_next_publish_at.unwrap()
                >= before + OFFER_FILES_LEGACY_MIN_INTERVAL
        );
    }

    /// Read just the eD2k packet header (protocol + length + opcode) the session
    /// wrote to the wire.
    async fn read_wire_header(peer: &mut TcpStream) -> [u8; TCP_PACKET_HEADER_LEN] {
        let mut header = [0u8; TCP_PACKET_HEADER_LEN];
        peer.read_exact(&mut header).await.unwrap();
        header
    }

    /// RUST-PAR-019 R19-3: every server-bound opcode except OP_OFFERFILES is sent
    /// uncompressed (OP_EDONKEYPROT / 0xE3) even when the server advertised
    /// SRV_TCPFLG_COMPRESSION — eMule packs only OP_OFFERFILES toward the server
    /// (SharedFileList.cpp:2723-2725). The 512-zero payload is highly compressible,
    /// so a 0xE3 here proves the opcode gate rather than keep-if-smaller.
    #[tokio::test]
    async fn server_bound_non_offer_packets_stay_uncompressed_with_compression_flag() {
        use super::super::{OP_GETSOURCES, OP_SEARCHREQUEST};

        for opcode in [OP_SEARCHREQUEST, OP_GETSOURCES] {
            let (mut session, mut peer) = connected_test_session_with_peer().await;
            session.server_flags = Some(SERVER_TCP_FLAG_COMPRESSION);
            session.send_packet(opcode, &vec![0u8; 512]).await.unwrap();
            let header = read_wire_header(&mut peer).await;
            assert_eq!(
                header[0], OP_EDONKEYPROT,
                "opcode 0x{opcode:02X} must be sent as 0xE3, not packed",
            );
            assert_eq!(header[5], opcode);
        }
    }

    /// RUST-PAR-019 R19-3: OP_OFFERFILES is packed (0xD4) when the server supports
    /// compression and the packed form is strictly smaller (keep-if-smaller,
    /// Packets.cpp:259). A 512-zero payload compresses well below its raw size.
    #[tokio::test]
    async fn offer_files_is_packed_when_smaller_on_compression_server() {
        use super::super::OP_OFFERFILES;

        let (mut session, mut peer) = connected_test_session_with_peer().await;
        session.server_flags = Some(SERVER_TCP_FLAG_COMPRESSION);
        session
            .send_packet(OP_OFFERFILES, &vec![0u8; 512])
            .await
            .unwrap();
        let header = read_wire_header(&mut peer).await;
        assert_eq!(
            header[0], OP_PACKEDPROT,
            "compressible OP_OFFERFILES must pack"
        );
        assert_eq!(header[5], OP_OFFERFILES);
    }

    /// RUST-PAR-019 R19-3: the empty-share OP_OFFERFILES keepalive (a 4-byte
    /// zero-count payload) is NOT emitted as a larger packed packet — zlib expands
    /// it, so keep-if-smaller leaves it as OP_EDONKEYPROT (0xE3).
    #[tokio::test]
    async fn empty_offer_files_keepalive_is_not_packed() {
        use super::super::OP_OFFERFILES;

        let (mut session, mut peer) = connected_test_session_with_peer().await;
        session.server_flags = Some(SERVER_TCP_FLAG_COMPRESSION);
        session
            .send_packet(OP_OFFERFILES, &0u32.to_le_bytes())
            .await
            .unwrap();
        let header = read_wire_header(&mut peer).await;
        assert_eq!(
            header[0], OP_EDONKEYPROT,
            "0-file OP_OFFERFILES keepalive must stay uncompressed",
        );
        assert_eq!(header[5], OP_OFFERFILES);
    }
}
