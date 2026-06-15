use tokio::time::Instant;

use super::super::super::{ED2K_SOURCE_EXCHANGE2_VERSION, Ed2kPeerSecureIdentState};
use super::super::ActiveDownloadPiece;

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
    /// Peer's advertised eD2k UDP port (from OP_EMULEINFO ET_UDPPORT), 0 if none.
    /// Used to detach a queued source onto UDP reask.
    pub(super) peer_udp_port: u16,
    /// Peer's advertised eD2k UDP version (OP_EMULEINFO ET_UDPVER), 0 if unknown.
    pub(super) peer_udp_version: u8,
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
}

impl DownloadSessionState {
    pub(super) fn new(
        initial_hello_complete: bool,
        initial_secure_ident_started: bool,
        source_exchange_allowed: bool,
        peer_user_hash: Option<[u8; 16]>,
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
            peer_udp_port: 0,
            peer_udp_version: 0,
            peer_part_bitmap: None,
            pending_aich_recovery_parts: Vec::new(),
            aich_requests_inflight: Vec::new(),
        }
    }

    pub(super) fn waiting_for_peer_secure_ident(&self) -> bool {
        self.secure_ident_started
            && (self.peer_secure_ident.pending_signature
                || (self.peer_secure_ident.requested_peer_key
                    && self.peer_secure_ident.peer_public_key.is_none())
                || (self.peer_secure_ident.challenge_for.is_some()
                    && !self.peer_secure_ident.peer_signature_received))
    }
}

#[cfg(test)]
mod tests {
    use super::DownloadSessionState;

    #[test]
    fn secure_ident_wait_allows_peer_signature_without_peer_challenge() {
        let mut state = DownloadSessionState::new(false, true, false, None);
        state.peer_secure_ident.requested_peer_key = true;
        state.peer_secure_ident.peer_public_key = Some(vec![1, 2, 3]);
        state.peer_secure_ident.challenge_for = Some(1234);
        state.peer_secure_ident.peer_signature_received = true;

        assert!(!state.waiting_for_peer_secure_ident());
    }

    #[test]
    fn secure_ident_wait_blocks_while_local_signature_is_pending() {
        let mut state = DownloadSessionState::new(false, true, false, None);
        state.peer_secure_ident.requested_peer_key = true;
        state.peer_secure_ident.peer_public_key = Some(vec![1, 2, 3]);
        state.peer_secure_ident.challenge_for = Some(1234);
        state.peer_secure_ident.peer_signature_received = true;
        state.peer_secure_ident.peer_challenge_from = Some(5678);
        state.peer_secure_ident.pending_signature = true;

        assert!(state.waiting_for_peer_secure_ident());
    }
}
