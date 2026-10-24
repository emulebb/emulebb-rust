use std::net::SocketAddr;

use emulebb_kad_dht::{DhtError, DhtNode};

use super::outbound::ClientUdpDatagram;

/// Semantic role of one eD2K client-UDP socket write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClientUdpSendRole {
    ReaskRequest,
    BuddyRelayRequest,
    ReciprocityReply,
    BuddyRelayReply,
    DirectCallbackRequest,
}

impl ClientUdpSendRole {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::ReaskRequest => "reask_request",
            Self::BuddyRelayRequest => "buddy_relay_request",
            Self::ReciprocityReply => "reciprocity_reply",
            Self::BuddyRelayReply => "buddy_relay_reply",
            Self::DirectCallbackRequest => "direct_callback_request",
        }
    }

    pub(super) const fn state_id(self) -> &'static str {
        match self {
            Self::ReaskRequest | Self::ReciprocityReply => "client_udp.reask",
            Self::BuddyRelayRequest | Self::BuddyRelayReply => "client_udp.buddy_relay",
            Self::DirectCallbackRequest => "client_udp.direct_callback",
        }
    }

    pub(super) const fn state_label(self) -> &'static str {
        match self {
            Self::ReaskRequest | Self::ReciprocityReply => "reask",
            Self::BuddyRelayRequest | Self::BuddyRelayReply => "buddy relay",
            Self::DirectCallbackRequest => "direct callback",
        }
    }

    pub(super) const fn phase(self) -> &'static str {
        match self {
            Self::ReaskRequest => "reask_request",
            Self::BuddyRelayRequest => "buddy_relay_request",
            Self::ReciprocityReply => "reciprocity_reply",
            Self::BuddyRelayReply => "buddy_relay_reply",
            Self::DirectCallbackRequest => "direct_callback_request",
        }
    }
}

#[cfg(feature = "packet-diagnostics")]
struct ClientUdpSendAttempt<'a> {
    remote_addr: SocketAddr,
    role: ClientUdpSendRole,
    datagram: &'a ClientUdpDatagram,
    attempt_id: u64,
    completed: bool,
}

#[cfg(feature = "packet-diagnostics")]
impl<'a> ClientUdpSendAttempt<'a> {
    fn new(
        remote_addr: SocketAddr,
        role: ClientUdpSendRole,
        datagram: &'a ClientUdpDatagram,
    ) -> Self {
        let attempt_id = super::dump::next_client_udp_send_attempt_id();
        super::dump::dump_client_udp_send_attempt(remote_addr, role, datagram, attempt_id);
        Self {
            remote_addr,
            role,
            datagram,
            attempt_id,
            completed: false,
        }
    }

    fn settle(
        &mut self,
        outcome: super::dump::ClientUdpDumpOutcome,
        delivery_known: bool,
        note: Option<String>,
    ) {
        self.completed = true;
        super::dump::emit_client_udp_send_outcome(
            self.remote_addr,
            self.role,
            self.datagram,
            self.attempt_id,
            outcome,
            delivery_known,
            note,
        );
    }

    fn succeeded(mut self) {
        self.settle(super::dump::ClientUdpDumpOutcome::SendSucceeded, true, None);
    }

    fn failed(mut self, error: String) {
        self.settle(
            super::dump::ClientUdpDumpOutcome::SendFailed,
            true,
            Some(error),
        );
    }
}

#[cfg(feature = "packet-diagnostics")]
impl Drop for ClientUdpSendAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.settle(
                super::dump::ClientUdpDumpOutcome::SendCancelled,
                false,
                Some("client UDP send future cancelled before completion".to_string()),
            );
        }
    }
}

#[cfg(not(feature = "packet-diagnostics"))]
struct ClientUdpSendAttempt;

#[cfg(not(feature = "packet-diagnostics"))]
impl ClientUdpSendAttempt {
    fn new(
        _remote_addr: SocketAddr,
        _role: ClientUdpSendRole,
        _datagram: &ClientUdpDatagram,
    ) -> Self {
        Self
    }

    fn succeeded(self) {}

    fn failed(self, _error: String) {}
}

/// Single transport boundary for every eD2K client-UDP datagram.
pub(super) async fn send_client_udp_datagram(
    dht: &DhtNode,
    remote_addr: SocketAddr,
    role: ClientUdpSendRole,
    datagram: &ClientUdpDatagram,
) -> Result<(), DhtError> {
    let attempt = ClientUdpSendAttempt::new(remote_addr, role, datagram);
    match dht.send_raw_datagram(remote_addr, &datagram.bytes).await {
        Ok(()) => {
            attempt.succeeded();
            Ok(())
        }
        Err(error) => {
            attempt.failed(error.to_string());
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_roles_have_stable_diagnostic_states() {
        assert_eq!(
            ClientUdpSendRole::ReaskRequest.state_id(),
            "client_udp.reask"
        );
        assert_eq!(
            ClientUdpSendRole::ReciprocityReply.phase(),
            "reciprocity_reply"
        );
        assert_eq!(
            ClientUdpSendRole::BuddyRelayRequest.state_id(),
            "client_udp.buddy_relay"
        );
        assert_eq!(
            ClientUdpSendRole::BuddyRelayReply.phase(),
            "buddy_relay_reply"
        );
        assert_eq!(
            ClientUdpSendRole::DirectCallbackRequest.state_id(),
            "client_udp.direct_callback"
        );
    }
}
