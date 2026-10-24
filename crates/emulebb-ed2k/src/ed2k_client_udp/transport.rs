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

/// Single transport boundary for every eD2K client-UDP datagram.
pub(super) async fn send_client_udp_datagram(
    dht: &DhtNode,
    remote_addr: SocketAddr,
    _role: ClientUdpSendRole,
    datagram: &ClientUdpDatagram,
) -> Result<(), DhtError> {
    dht.send_raw_datagram(remote_addr, &datagram.bytes).await
}
