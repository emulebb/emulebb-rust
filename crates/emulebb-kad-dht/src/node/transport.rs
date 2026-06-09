use super::DhtNode;
use crate::error::DhtError;
use emulebb_kad_net::RpcWorkClass;
use emulebb_kad_proto::KadPacket;
use std::net::SocketAddr;
use std::time::Duration;

impl DhtNode {
    /// Send a packet without waiting for a response.
    pub async fn send_packet(&self, addr: SocketAddr, packet: &KadPacket) -> Result<(), DhtError> {
        self.send_packet_with_class(addr, packet, RpcWorkClass::Interactive)
            .await
    }

    /// Send a packet without waiting for a response under an explicit work class.
    pub async fn send_packet_with_class(
        &self,
        addr: SocketAddr,
        packet: &KadPacket,
        work_class: RpcWorkClass,
    ) -> Result<(), DhtError> {
        self.inner
            .rpc
            .send_with_class(addr, packet, work_class)
            .await?;
        Ok(())
    }

    /// Send one Kad request and wait for the exact response opcode.
    ///
    /// This is the transport-level escape hatch for protocol families such as
    /// HELLO-adjacent firewall checks where the caller needs the typed response
    /// packet rather than the higher-level traversal/search abstractions.
    pub async fn request_packet(
        &self,
        addr: SocketAddr,
        packet: &KadPacket,
        expected_opcode: u8,
        timeout: Duration,
    ) -> Result<KadPacket, DhtError> {
        self.request_packet_with_class(
            addr,
            packet,
            expected_opcode,
            timeout,
            RpcWorkClass::Interactive,
        )
        .await
    }

    /// Send one Kad request and wait for the exact response opcode under an explicit work class.
    pub async fn request_packet_with_class(
        &self,
        addr: SocketAddr,
        packet: &KadPacket,
        expected_opcode: u8,
        timeout: Duration,
        work_class: RpcWorkClass,
    ) -> Result<KadPacket, DhtError> {
        Ok(self
            .inner
            .rpc
            .request_with_class(addr, packet, expected_opcode, timeout, work_class)
            .await?)
    }

    /// Register a peer's announced receiver verify key for obfuscated replies.
    pub fn register_peer_key(&self, addr: SocketAddr, udp_key: u32) {
        self.inner.rpc.register_peer_key(addr, udp_key);
    }
}
