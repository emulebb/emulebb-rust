use std::{
    net::SocketAddr,
    ops::{Deref, DerefMut},
};

use anyhow::Result;

use super::{Ed2kTransport, Ed2kTransportMode, EmuleTcpPacket};

/// Which side created the physical peer TCP connection.
///
/// eD2K protocol roles are intentionally not derived from this value: once the
/// HELLO exchange completes, stock clients may upload and download over either
/// connection direction. The origin is retained only for admission,
/// diagnostics, and duplicate-connection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ed2k_tcp) enum Ed2kPeerConnectionOrigin {
    InboundAccepted,
    OutboundEstablished,
}

/// Connection-scoped owner for one established eD2K peer transport.
///
/// Keeping the transport whole under one task avoids split-half coordination,
/// preserves RC4 stream ordering, and gives inbound and outbound-established
/// sessions the same ownership boundary. Protocol-specific state machines may
/// temporarily borrow the transport through `DerefMut`, but cannot duplicate
/// the socket owner.
#[derive(Debug)]
pub(in crate::ed2k_tcp) struct Ed2kPeerDispatcher {
    transport: Ed2kTransport,
    peer_addr: SocketAddr,
    origin: Ed2kPeerConnectionOrigin,
}

impl Ed2kPeerDispatcher {
    pub(in crate::ed2k_tcp) fn new(
        transport: Ed2kTransport,
        peer_addr: SocketAddr,
        origin: Ed2kPeerConnectionOrigin,
    ) -> Self {
        Self {
            transport,
            peer_addr,
            origin,
        }
    }

    pub(in crate::ed2k_tcp) const fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub(in crate::ed2k_tcp) const fn origin(&self) -> Ed2kPeerConnectionOrigin {
        self.origin
    }

    pub(in crate::ed2k_tcp) const fn mode(&self) -> Ed2kTransportMode {
        self.transport.mode
    }

    pub(in crate::ed2k_tcp) async fn read_packet_diagnostic(
        &mut self,
        flow: &'static str,
        remote_addr: SocketAddr,
        phase: &str,
    ) -> Result<Option<EmuleTcpPacket>> {
        self.require_peer_addr(remote_addr)?;
        self.transport
            .read_packet_diagnostic(flow, remote_addr, phase)
            .await
    }

    pub(in crate::ed2k_tcp) async fn write_all_diagnostic(
        &mut self,
        flow: &'static str,
        remote_addr: SocketAddr,
        phase: &str,
        bytes: &[u8],
    ) -> Result<()> {
        self.require_peer_addr(remote_addr)?;
        self.transport
            .write_all_diagnostic(flow, remote_addr, phase, bytes)
            .await
    }

    fn require_peer_addr(&self, remote_addr: SocketAddr) -> Result<()> {
        if remote_addr != self.peer_addr {
            anyhow::bail!(
                "eD2K peer dispatcher for {} cannot access connection {}",
                self.peer_addr,
                remote_addr
            );
        }
        Ok(())
    }
}

impl Deref for Ed2kPeerDispatcher {
    type Target = Ed2kTransport;

    fn deref(&self) -> &Self::Target {
        &self.transport
    }
}

impl DerefMut for Ed2kPeerDispatcher {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.transport
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::ed2k_tcp::{OP_EDONKEYPROT, OP_EMULEPROT, encode_packet};

    #[tokio::test]
    async fn one_socket_dispatches_frames_in_both_directions() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let outbound = TcpStream::connect(listener_addr).await.unwrap();
        let outbound_peer = outbound.peer_addr().unwrap();
        let (inbound, inbound_peer) = listener.accept().await.unwrap();

        let mut outbound = Ed2kPeerDispatcher::new(
            plaintext_transport(outbound),
            outbound_peer,
            Ed2kPeerConnectionOrigin::OutboundEstablished,
        );
        let mut inbound = Ed2kPeerDispatcher::new(
            plaintext_transport(inbound),
            inbound_peer,
            Ed2kPeerConnectionOrigin::InboundAccepted,
        );

        let request = encode_packet(OP_EDONKEYPROT, 0x58, b"request");
        outbound
            .write_all_diagnostic("dispatcher_test", outbound_peer, "request", &request)
            .await
            .unwrap();
        let received = inbound
            .read_packet_diagnostic("dispatcher_test", inbound_peer, "request")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.protocol, OP_EDONKEYPROT);
        assert_eq!(received.opcode, 0x58);
        assert_eq!(received.payload, b"request");

        let response = encode_packet(OP_EMULEPROT, 0x59, b"response");
        inbound
            .write_all_diagnostic("dispatcher_test", inbound_peer, "response", &response)
            .await
            .unwrap();
        let received = outbound
            .read_packet_diagnostic("dispatcher_test", outbound_peer, "response")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.protocol, OP_EMULEPROT);
        assert_eq!(received.opcode, 0x59);
        assert_eq!(received.payload, b"response");

        assert_eq!(inbound.origin(), Ed2kPeerConnectionOrigin::InboundAccepted);
        assert_eq!(
            outbound.origin(),
            Ed2kPeerConnectionOrigin::OutboundEstablished
        );
        assert_eq!(inbound.peer_addr(), inbound_peer);
        assert_eq!(outbound.peer_addr(), outbound_peer);
        assert_eq!(inbound.mode(), Ed2kTransportMode::Plaintext);
        assert_eq!(outbound.mode(), Ed2kTransportMode::Plaintext);
    }

    #[tokio::test]
    async fn dispatcher_rejects_a_different_connection_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let outbound = TcpStream::connect(listener_addr).await.unwrap();
        let outbound_peer = outbound.peer_addr().unwrap();
        let (_inbound, _) = listener.accept().await.unwrap();
        let mut dispatcher = Ed2kPeerDispatcher::new(
            plaintext_transport(outbound),
            outbound_peer,
            Ed2kPeerConnectionOrigin::OutboundEstablished,
        );
        let wrong_peer = SocketAddr::new(outbound_peer.ip(), outbound_peer.port() + 1);

        let error = dispatcher
            .write_all_diagnostic("dispatcher_test", wrong_peer, "wrong_peer", b"frame")
            .await
            .unwrap_err();

        assert!(error.to_string().contains("cannot access connection"));
    }

    fn plaintext_transport(stream: TcpStream) -> Ed2kTransport {
        Ed2kTransport::from_parts(
            stream,
            VecDeque::new(),
            None,
            None,
            Ed2kTransportMode::Plaintext,
        )
    }
}
