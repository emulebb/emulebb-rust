use tokio::time::Instant;

use super::super::super::{ED2K_SOURCE_EXCHANGE2_VERSION, Ed2kPeerSecureIdentState};
use super::super::ActiveDownloadPiece;
use super::super::stale_guard::StaleBlockPacketGuard;

pub(super) struct DownloadSessionState {
    pub(super) peer_secure_ident: Ed2kPeerSecureIdentState,
    pub(super) hello_complete: bool,
    pub(super) secure_ident_started: bool,
    pub(super) remote_supports_aich: bool,
    pub(super) remote_supports_secure_ident: bool,
    pub(super) remote_supports_file_identifiers: bool,
    pub(super) remote_supports_multipacket: bool,
    pub(super) remote_supports_ext_multipacket: bool,
    pub(super) remote_source_exchange_version: u8,
    pub(super) remote_supports_source_exchange: bool,
    pub(super) remote_supports_source_exchange2: bool,
    pub(super) source_exchange_allowed: bool,
    pub(super) startup_file_requests_sent: bool,
    pub(super) startup_file_response_received: bool,
    pub(super) source_request_sent: bool,
    /// Whether a peer's file identifier / startup metadata has advertised an
    /// AICH root for this file. Gates the OP_HASHSETREQUEST2 `request_aich`
    /// flag: we only fetch the AICH hashset when a peer signalled it has one.
    /// This is just a "has the peer offered AICH" signal, NOT a trust decision
    /// -- a network-learned root still needs IP corroboration before it can
    /// authorize salvage (see `record_network_aich_root`).
    pub(super) peer_advertised_aich_root: bool,
    pub(super) aich_file_hash_requested: bool,
    pub(super) hashset_requested: bool,
    pub(super) hashset_requested_at: Option<Instant>,
    pub(super) upload_requested: bool,
    pub(super) upload_accepted: bool,
    pub(super) upload_accepted_at: Option<Instant>,
    pub(super) part_response_deadline: Option<Instant>,
    pub(super) queued_until: Option<Instant>,
    pub(super) active_piece_request: Option<ActiveDownloadPiece>,
    pub(super) completed_block_count: usize,
    pub(super) session_payload_down: u64,
    pub(super) peer_user_hash: Option<[u8; 16]>,
    pub(super) peer_connect_options: Option<u8>,
    /// Peer's advertised eD2k UDP port (from OP_EMULEINFO ET_UDPPORT), 0 if none.
    /// Used to detach a queued source onto UDP reask.
    pub(super) peer_udp_port: u16,
    /// Peer's advertised eD2k UDP version (OP_EMULEINFO ET_UDPVER), 0 if unknown.
    pub(super) peer_udp_version: u8,
    /// Whether the connected source is a firewalled LowID client (oracle
    /// `HasLowID()`: client_id below the HighID floor). Set from the hello identity.
    pub(super) peer_low_id: bool,
    /// The source's Kad buddy endpoint (ip, udp_port) decoded from its hello
    /// `CT_EMULE_BUDDYIP`/`CT_EMULE_BUDDYUDP`; `None` unless it advertised a buddy.
    pub(super) peer_buddy_endpoint: Option<(std::net::Ipv4Addr, u16)>,
    /// Connected peer's advertised per-part availability (OP_FILESTATUS), `None`
    /// until a status frame is seen. Gates part picking so we only request parts
    /// the peer holds (master `sender->IsPartAvailable`).
    pub(super) peer_part_bitmap: Option<Vec<bool>>,
    /// Parts whose MD4 verification just failed and which need an OP_AICHREQUEST
    /// to drive ICH block salvage. Drained by the session once a trusted AICH
    /// root is known and the peer supports AICH.
    pub(super) pending_aich_recovery_parts: Vec<u16>,
    /// Parts with an OP_AICHREQUEST already sent and awaiting an OP_AICHANSWER,
    /// so a part is not re-requested while a request is outstanding (master
    /// `CAICHRecoveryHashSet::IsClientRequestPending`).
    pub(super) aich_requests_inflight: Vec<u16>,
    /// Rolling 32-in-15s stale block-packet cancel guard (oracle
    /// `ShouldAbortAfterStaleBlockPacket`, DownloadClient.cpp:2690-2712): stale
    /// / duplicate block payload is dropped and counted here instead of ending
    /// the session; only a sustained burst cancels the transfer.
    pub(super) stale_block_guard: StaleBlockPacketGuard,
}

impl DownloadSessionState {
    pub(super) fn new(
        initial_hello_complete: bool,
        initial_secure_ident_started: bool,
        source_exchange_allowed: bool,
        peer_user_hash: Option<[u8; 16]>,
        peer_connect_options: Option<u8>,
    ) -> Self {
        Self {
            peer_secure_ident: Ed2kPeerSecureIdentState::default(),
            hello_complete: initial_hello_complete,
            secure_ident_started: initial_secure_ident_started,
            remote_supports_aich: initial_hello_complete,
            remote_supports_secure_ident: initial_hello_complete,
            remote_supports_file_identifiers: false,
            remote_supports_multipacket: initial_hello_complete,
            remote_supports_ext_multipacket: initial_hello_complete,
            remote_source_exchange_version: if initial_hello_complete {
                ED2K_SOURCE_EXCHANGE2_VERSION
            } else {
                0
            },
            remote_supports_source_exchange: initial_hello_complete,
            remote_supports_source_exchange2: initial_hello_complete,
            source_exchange_allowed,
            startup_file_requests_sent: false,
            startup_file_response_received: false,
            source_request_sent: false,
            peer_advertised_aich_root: false,
            aich_file_hash_requested: false,
            hashset_requested: false,
            hashset_requested_at: None,
            upload_requested: false,
            upload_accepted: false,
            upload_accepted_at: None,
            part_response_deadline: None,
            queued_until: None,
            active_piece_request: None,
            completed_block_count: 0,
            session_payload_down: 0,
            peer_user_hash,
            peer_connect_options,
            peer_udp_port: 0,
            peer_udp_version: 0,
            peer_low_id: false,
            peer_buddy_endpoint: None,
            peer_part_bitmap: None,
            pending_aich_recovery_parts: Vec::new(),
            aich_requests_inflight: Vec::new(),
            stale_block_guard: StaleBlockPacketGuard::default(),
        }
    }

    /// Capture the connected source's firewalled-LowID flag + its Kad buddy
    /// endpoint from its decoded hello, so a queued LowID source can later be
    /// reasked through its buddy (`OP_REASKCALLBACKUDP`). The buddy *id* is not in
    /// the hello (the oracle only learns it via Kad source-finding), so only the
    /// endpoint + LowID flag are captured here.
    pub(super) fn capture_peer_buddy(
        &mut self,
        profile: &super::super::super::hello::DecodedHelloProfile,
    ) {
        // Oracle HasLowID(): a client id below the HighID floor (0x01000000).
        self.peer_low_id = profile.identity.client_id < 0x0100_0000;
        if let Some(buddy) = profile.buddy {
            self.peer_buddy_endpoint = Some((buddy.ip, buddy.udp_port));
        }
    }

    /// The peer user hash to attribute download credit to. Returns `Some` when
    /// the eMule `CClientCredits::AddDownloaded` gate permits accrual
    /// (ClientCredits.cpp:83-91): the peer's secure identity is verified
    /// (IS_IDENTIFIED) or the peer is a legacy client with no secure-ident
    /// capability (IS_NOTAVAILABLE). A crypto-capable-but-unverified peer
    /// (IS_IDNEEDED/IDFAILED/IDBADGUY) is skipped because its user hash is
    /// spoofable. Mirrors the upload path's identical gate.
    pub(super) fn verified_credit_user_hash(&self) -> Option<[u8; 16]> {
        if super::super::super::credit_accrual_allowed(
            self.peer_secure_ident.peer_ident_verified,
            self.remote_supports_secure_ident,
        ) {
            self.peer_user_hash
        } else {
            None
        }
    }
}
