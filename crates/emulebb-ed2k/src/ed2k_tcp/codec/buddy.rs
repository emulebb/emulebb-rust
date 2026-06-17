//! eD2k TCP encoders for the Kad LowID buddy / firewalled-callback relay.
//!
//! These are the wire frames a buddy relationship carries over the persistent
//! buddy TCP connection:
//! - `OP_CALLBACK` (under `OP_EMULEPROT`): a buddy relays a third party's
//!   `KADEMLIA_CALLBACK_REQ` to the firewalled client it serves. Oracle layout
//!   (`KademliaUDPListener.cpp` `Process_KADEMLIA_CALLBACK_REQ`):
//!   `[uCheck u128][uFile u128][uIP u32][uTCP u16]`. `uCheck` is the callback
//!   check id echoed unchanged from the inbound request; `uIP` is the requester
//!   IP written by `WriteUInt32(uIP)` where the oracle holds the address in host
//!   byte order, so on the little-endian wire the field is the host-order value
//!   serialized LE. The receiving firewalled client reads it back and applies
//!   `ntohl` (`ListenSocket.cpp` OP_CALLBACK), recovering the dotted address.
//! - `OP_BUDDYPING` / `OP_BUDDYPONG` (under `OP_EMULEPROT`): zero-length keepalive
//!   frames (`ClientList.cpp` sends `OP_BUDDYPING`; `ListenSocket.cpp` answers
//!   with `OP_BUDDYPONG`).
//!
//! Oracle references (do not modify):
//! - `srchybrid/kademlia/net/KademliaUDPListener.cpp` `Process_KADEMLIA_CALLBACK_REQ`
//! - `srchybrid/ListenSocket.cpp` `OP_CALLBACK` / `OP_BUDDYPING` / `OP_BUDDYPONG`
//! - `srchybrid/ClientList.cpp` buddy upkeep (`OP_BUDDYPING` send)

use std::net::Ipv4Addr;

use emulebb_kad_proto::Ed2kHash;

use super::super::{OP_BUDDYPING, OP_BUDDYPONG, OP_CALLBACK, OP_EMULEPROT};
use super::encode_packet;

/// Encode the `OP_CALLBACK` relay payload a buddy sends to the firewalled client.
///
/// `check` is the 16-byte callback check id echoed unchanged from the inbound
/// `KADEMLIA_CALLBACK_REQ`. `file_hash` is the requested file. `requester_ip` /
/// `requester_tcp_port` are the callback requester's TCP endpoint.
///
/// The IP field mirrors the oracle `WriteUInt32(uIP)` with `uIP` in host byte
/// order: on the little-endian wire that is `u32::from_be_bytes(octets)`
/// serialized as little-endian, which is the exact inverse of
/// [`super::decode_kad_callback_payload`].
#[must_use]
pub(in crate::ed2k_tcp) fn encode_kad_callback_relay(
    check: [u8; 16],
    file_hash: &Ed2kHash,
    requester_ip: Ipv4Addr,
    requester_tcp_port: u16,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16 + 16 + 4 + 2);
    payload.extend_from_slice(&check);
    payload.extend_from_slice(&file_hash.0);
    // Oracle host-order uIP serialized little-endian on the wire.
    let host_order_ip = u32::from_be_bytes(requester_ip.octets());
    payload.extend_from_slice(&host_order_ip.to_le_bytes());
    payload.extend_from_slice(&requester_tcp_port.to_le_bytes());
    encode_packet(OP_EMULEPROT, OP_CALLBACK, &payload)
}

/// Encode a zero-length `OP_BUDDYPING` keepalive (oracle `ClientList.cpp`
/// `OP_BUDDYPING` send each buddy upkeep cycle while firewalled).
#[must_use]
pub(in crate::ed2k_tcp) fn encode_buddy_ping() -> Vec<u8> {
    encode_packet(OP_EMULEPROT, OP_BUDDYPING, &[])
}

/// Encode a zero-length `OP_BUDDYPONG` reply (oracle `ListenSocket.cpp`
/// `OP_BUDDYPING` -> `OP_BUDDYPONG`).
#[must_use]
pub(in crate::ed2k_tcp) fn encode_buddy_pong() -> Vec<u8> {
    encode_packet(OP_EMULEPROT, OP_BUDDYPONG, &[])
}

#[cfg(test)]
mod tests {
    use super::super::super::TCP_PACKET_HEADER_LEN;
    use super::super::decode_kad_callback_payload;
    use super::*;
    use emulebb_kad_proto::Ed2kHash;

    /// Split an encoded eD2k TCP frame into (protocol, opcode, payload). The
    /// header is `[protocol u8][len u32 LE][opcode u8]`; `len` counts the opcode
    /// plus payload.
    fn parse_frame(frame: &[u8]) -> (u8, u8, &[u8]) {
        let protocol = frame[0];
        let declared_len = u32::from_le_bytes(frame[1..5].try_into().unwrap()) as usize;
        let opcode = frame[5];
        let payload = &frame[TCP_PACKET_HEADER_LEN..];
        assert_eq!(
            declared_len,
            payload.len() + 1,
            "framed length includes opcode"
        );
        (protocol, opcode, payload)
    }

    #[test]
    fn callback_relay_round_trips_through_decoder() {
        let check = [0x5Au8; 16];
        let file_hash = Ed2kHash::from_bytes([0xC3; 16]);
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let port = 4662u16;

        let frame = encode_kad_callback_relay(check, &file_hash, ip, port);
        let (protocol, opcode, payload) = parse_frame(&frame);
        assert_eq!(protocol, OP_EMULEPROT);
        assert_eq!(opcode, OP_CALLBACK);

        let decoded = decode_kad_callback_payload(payload).expect("decode relay payload");
        assert_eq!(decoded.buddy_check, check);
        assert_eq!(decoded.file_hash, file_hash);
        assert_eq!(decoded.peer_ip, ip);
        assert_eq!(decoded.peer_tcp_port, port);
        assert_eq!(decoded.trailing_len, 0);
    }

    #[test]
    fn callback_relay_byte_layout_matches_master() {
        // Master Process_KADEMLIA_CALLBACK_REQ:
        //   fileIO2.WriteUInt128(uCheck);   // 16 bytes, written as-is
        //   fileIO2.WriteUInt128(uFile);    // 16 bytes, written as-is
        //   fileIO2.WriteUInt32(uIP);       // host-order IP, little-endian wire
        //   fileIO2.WriteUInt16(uTCP);      // little-endian
        let check = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let file_hash = Ed2kHash::from_bytes([
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0x01,
        ]);
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let port = 0x1234u16;

        let frame = encode_kad_callback_relay(check, &file_hash, ip, port);
        let payload = &frame[TCP_PACKET_HEADER_LEN..];

        let mut expected = Vec::new();
        expected.extend_from_slice(&check);
        expected.extend_from_slice(&file_hash.0);
        // uIP host-order value for 1.2.3.4 is 0x01020304; WriteUInt32 emits it
        // little-endian: [0x04, 0x03, 0x02, 0x01].
        expected.extend_from_slice(&[0x04, 0x03, 0x02, 0x01]);
        // uTCP 0x1234 little-endian: [0x34, 0x12].
        expected.extend_from_slice(&[0x34, 0x12]);
        assert_eq!(payload, expected.as_slice());
        assert_eq!(payload.len(), 38);
    }

    #[test]
    fn buddy_ping_and_pong_are_zero_length_emuleprot() {
        let ping = encode_buddy_ping();
        let (protocol, opcode, payload) = parse_frame(&ping);
        assert_eq!(protocol, OP_EMULEPROT);
        assert_eq!(opcode, OP_BUDDYPING);
        assert!(payload.is_empty());

        let pong = encode_buddy_pong();
        let (protocol, opcode, payload) = parse_frame(&pong);
        assert_eq!(protocol, OP_EMULEPROT);
        assert_eq!(opcode, OP_BUDDYPONG);
        assert!(payload.is_empty());
    }
}
