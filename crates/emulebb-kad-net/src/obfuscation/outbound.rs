use crate::obfuscation::crypto::{derive_kad_receiver_key, derive_kad_request_key, rc4};
use crate::obfuscation::peer_state::ResolvedPeerCryptoState;
use crate::obfuscation::{
    KAD_MARKER_RECEIVER_KEY, KadKeyMode, MAGICVALUE_UDP_SYNC_CLIENT, ObfuscationLayer,
    OutboundKadEncryptionInfo, OutboundKadEncryptionMode, UDP_PADDING_LEN,
};
use emulebb_kad_proto::constants::opcode;
use rand::Rng;
use std::net::{IpAddr, SocketAddr};

fn can_use_node_id_mode(peer: &ResolvedPeerCryptoState) -> bool {
    peer.node_id.is_some() && peer.kad_version.is_none_or(|version| version >= 6)
}

fn should_prefer_receiver_verify_key(opcode_value: u8) -> bool {
    // Firewalled recheck requests are an oracle exception to the usual
    // NodeID-first request rule: once we learned the peer's receiver verify
    // key, eMule sends KADEMLIA2_FIREWALLED2_REQ in receiver-key mode.
    opcode_value == opcode::FIREWALLED2_REQ
}

fn is_plain_protocol_marker(byte: u8) -> bool {
    // eMule EncryptedDatagramSocket re-rolls the semi-random obfuscation marker
    // only when it collides with a real plaintext protocol byte: OP_EMULEPROT
    // (0xC5), OP_PACKEDPROT (0xD4), OP_KADEMLIAHEADER (0xE4),
    // OP_KADEMLIAPACKEDPROT (0xE5), OP_UDPRESERVEDPROT1 (0xA3),
    // OP_UDPRESERVEDPROT2 (0xB2). It does NOT reserve OP_EDONKEYPROT (0xE3), and it
    // DOES reserve 0xB2 — which the low-2-bits-even Kad marker can actually hit, so
    // omitting it let a stock receiver misread ~1/256 obfuscated Kad datagrams.
    matches!(byte, 0xC5 | 0xD4 | 0xE4 | 0xE5 | 0xA3 | 0xB2)
}

fn select_marker(mode: KadKeyMode) -> u8 {
    let mut rng = rand::thread_rng();
    loop {
        let mut marker: u8 = rng.r#gen();
        marker &= !0x03;
        if matches!(mode, KadKeyMode::ReceiverVerifyKey) {
            marker |= KAD_MARKER_RECEIVER_KEY;
        }
        if !is_plain_protocol_marker(marker) {
            return marker;
        }
    }
}

impl ObfuscationLayer {
    /// Describe the outbound Kad UDP transport shape currently selected for a peer.
    #[must_use]
    pub fn inspect_outbound(
        &self,
        addr: SocketAddr,
        opcode_value: u8,
    ) -> OutboundKadEncryptionInfo {
        let peer = self.peer_state_for_addr(addr);
        let mode = if !self.enabled {
            OutboundKadEncryptionMode::Plaintext
        } else if should_prefer_receiver_verify_key(opcode_value)
            && peer.receiver_verify_key.is_some()
        {
            OutboundKadEncryptionMode::ReceiverVerifyKey
        } else if can_use_node_id_mode(&peer) {
            OutboundKadEncryptionMode::NodeId
        } else if peer.receiver_verify_key.is_some() {
            OutboundKadEncryptionMode::ReceiverVerifyKey
        } else {
            OutboundKadEncryptionMode::Plaintext
        };
        let sender_verify_key = match (mode, addr.ip()) {
            (OutboundKadEncryptionMode::Plaintext, _) => None,
            (_, IpAddr::V4(ip)) => Some(self.verify_key_for_ip(ip)),
            (_, IpAddr::V6(_)) => None,
        };

        OutboundKadEncryptionInfo {
            mode,
            peer_node_id: peer.node_id,
            peer_kad_version: peer.kad_version,
            receiver_verify_key: peer.receiver_verify_key,
            sender_verify_key,
        }
    }

    /// Encrypt a Kad packet for sending to `addr`.
    ///
    /// The caller still passes the opcode for tracing/call-site symmetry, but
    /// the oracle sender chooses transport shape from peer capability state:
    /// NodeID remains the primary Kad crypt target for peers that advertised a
    /// usable Kad `v6+` identity, except for the firewalled recheck request
    /// family where live oracle traces prefer the learned receiver verify key.
    /// Other request families still only use the receiver verify key when the
    /// NodeID context is missing.
    pub fn encrypt(&self, addr: SocketAddr, opcode_value: u8, plaintext: &[u8]) -> Vec<u8> {
        let outbound = self.inspect_outbound(addr, opcode_value);
        if matches!(outbound.mode, OutboundKadEncryptionMode::Plaintext) {
            return plaintext.to_vec();
        }

        let peer = self.peer_state_for_addr(addr);
        let preferred_mode = match outbound.mode {
            OutboundKadEncryptionMode::Plaintext => None,
            OutboundKadEncryptionMode::NodeId => Some(KadKeyMode::NodeId),
            OutboundKadEncryptionMode::ReceiverVerifyKey => Some(KadKeyMode::ReceiverVerifyKey),
        };

        let Some(mode) = preferred_mode else {
            return plaintext.to_vec();
        };

        let random_key_part: u16 = rand::thread_rng().r#gen();
        let rc4_key = match mode {
            KadKeyMode::NodeId => derive_kad_request_key(peer.node_id.unwrap(), random_key_part),
            KadKeyMode::ReceiverVerifyKey => {
                derive_kad_receiver_key(peer.receiver_verify_key.unwrap(), random_key_part)
            }
        };

        let sender_verify_key = match addr.ip() {
            IpAddr::V4(ip) => self.verify_key_for_ip(ip),
            IpAddr::V6(_) => return plaintext.to_vec(),
        };

        let mut encrypted_tail = Vec::with_capacity(13 + plaintext.len());
        encrypted_tail.extend_from_slice(&MAGICVALUE_UDP_SYNC_CLIENT.to_le_bytes());
        encrypted_tail.push(UDP_PADDING_LEN);
        encrypted_tail
            .extend_from_slice(&peer.receiver_verify_key.unwrap_or_default().to_le_bytes());
        encrypted_tail.extend_from_slice(&sender_verify_key.to_le_bytes());
        encrypted_tail.extend_from_slice(plaintext);
        rc4(&rc4_key, &mut encrypted_tail);

        let mut result = Vec::with_capacity(3 + encrypted_tail.len());
        result.push(select_marker(mode));
        result.extend_from_slice(&random_key_part.to_le_bytes());
        result.extend_from_slice(&encrypted_tail);
        result
    }
}

#[cfg(test)]
mod marker_tests {
    use super::{KadKeyMode, is_plain_protocol_marker, select_marker};

    #[test]
    fn reserved_marker_set_matches_stock() {
        // Stock EncryptedDatagramSocket re-roll set: C5 D4 E4 E5 A3 B2.
        for reserved in [0xC5u8, 0xD4, 0xE4, 0xE5, 0xA3, 0xB2] {
            assert!(
                is_plain_protocol_marker(reserved),
                "{reserved:#04x} must be reserved like stock"
            );
        }
        // OP_EDONKEYPROT (0xE3) is NOT reserved by stock (was a rust over-reservation).
        assert!(!is_plain_protocol_marker(0xE3));
    }

    #[test]
    fn select_marker_never_emits_a_reserved_byte() {
        for _ in 0..4096 {
            for mode in [KadKeyMode::NodeId, KadKeyMode::ReceiverVerifyKey] {
                assert!(!is_plain_protocol_marker(select_marker(mode)));
            }
        }
    }
}
