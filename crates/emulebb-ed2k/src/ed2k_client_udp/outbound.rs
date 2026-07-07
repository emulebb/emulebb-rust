//! Outbound client-UDP reask datagram builders — the send-side counterpart to
//! [`super::dispatch`]. Each builder encodes the opcode body ([`super::codec`]),
//! prepends the `[OP_EMULEPROT][opcode]` header, and either obfuscates it under
//! the destination's user hash + our public IP
//! ([`crate::ed2k_client_udp_obfuscation`]) or leaves it plaintext. Pure and
//! transport-free; the per-transfer ticker / reciprocity path does the actual
//! socket send. `docs/design/udp-source-reask.md` §4.2-§4.5.

use emulebb_kad_proto::Ed2kHash;

use super::codec::{
    OP_DIRECTCALLBACKREQ, OP_FILENOTFOUND, OP_QUEUEFULL, OP_REASKACK, OP_REASKCALLBACKUDP,
    OP_REASKFILEPING, encode_direct_callback_req, encode_reask_ack, encode_reask_callback_udp,
    encode_reask_file_ping,
};
use crate::ed2k_client_udp_obfuscation::obfuscate_client_udp;

/// The eD2k protocol marker that prefixes client UDP packets (`OP_EMULEPROT`).
const OP_EMULEPROT: u8 = 0xC5;

/// A built client-UDP datagram plus the plaintext frame metadata used by packet
/// diagnostics. `bytes` is the exact on-wire datagram, which may be obfuscated;
/// `payload` is the plaintext opcode body before optional obfuscation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientUdpDatagram {
    pub bytes: Vec<u8>,
    pub protocol_marker: u8,
    pub opcode: u8,
    pub payload: Vec<u8>,
    pub obfuscated: bool,
}

/// Where to send and whether to obfuscate. eMule obfuscates client UDP toward a
/// peer when `ShouldReceiveCryptUDPPackets()` (keyed on the peer user hash);
/// otherwise the packet is plaintext.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OutboundReaskTarget {
    /// The destination client's 16-byte user hash (obfuscation key material).
    pub dest_user_hash: [u8; 16],
    /// Our public IPv4 octets (`a.b.c.d`), mixed into the obfuscation key.
    pub our_public_ip: [u8; 4],
    /// Whether to obfuscate (peer supports/wants crypt UDP), else send plaintext.
    pub obfuscate: bool,
}

/// Wrap an opcode body in the `[OP_EMULEPROT][opcode]` header, then obfuscate or
/// leave plaintext per `target`.
fn frame_packet(opcode: u8, body: &[u8], target: &OutboundReaskTarget) -> ClientUdpDatagram {
    let mut plain = Vec::with_capacity(2 + body.len());
    plain.push(OP_EMULEPROT);
    plain.push(opcode);
    plain.extend_from_slice(body);
    let bytes = if target.obfuscate {
        obfuscate_client_udp(&target.dest_user_hash, target.our_public_ip, &plain)
    } else {
        plain
    };
    ClientUdpDatagram {
        bytes,
        protocol_marker: OP_EMULEPROT,
        opcode,
        payload: body.to_vec(),
        obfuscated: target.obfuscate,
    }
}

/// Build an `OP_DIRECTCALLBACKREQ` datagram (downloader -> firewalled type-6
/// source): asks the source to TCP-connect back to us. Obfuscated toward the
/// source per `target` exactly like a reask ping (oracle sends it through
/// `SendPacket(..., ShouldReceiveCryptUDPPackets(), GetUserHash(), ...)`).
pub(crate) fn build_direct_callback_req_datagram(
    our_tcp_port: u16,
    our_user_hash: &[u8; 16],
    connect_options: u8,
    target: &OutboundReaskTarget,
) -> ClientUdpDatagram {
    let body = encode_direct_callback_req(our_tcp_port, our_user_hash, connect_options);
    frame_packet(OP_DIRECTCALLBACKREQ, &body, target)
}

/// Build an `OP_REASKFILEPING` datagram (downloader -> source).
pub(crate) fn build_reask_file_ping_datagram(
    file_hash: &Ed2kHash,
    part_status: Option<&[bool]>,
    complete_source_count: u16,
    our_udp_version: u8,
    target: &OutboundReaskTarget,
) -> Vec<u8> {
    build_reask_file_ping_packet(
        file_hash,
        part_status,
        complete_source_count,
        our_udp_version,
        target,
    )
    .bytes
}

/// Build an `OP_REASKFILEPING` datagram with packet-diagnostic metadata.
pub(crate) fn build_reask_file_ping_packet(
    file_hash: &Ed2kHash,
    part_status: Option<&[bool]>,
    complete_source_count: u16,
    our_udp_version: u8,
    target: &OutboundReaskTarget,
) -> ClientUdpDatagram {
    let body = encode_reask_file_ping(
        file_hash,
        part_status,
        complete_source_count,
        our_udp_version,
    );
    frame_packet(OP_REASKFILEPING, &body, target)
}

/// Build an `OP_REASKACK` datagram (uploader -> downloader). `peer_udp_version`
/// is the downloader's version (gates the leading partstatus).
pub(crate) fn build_reask_ack_datagram(
    part_status: Option<&[bool]>,
    queue_position: u16,
    peer_udp_version: u8,
    target: &OutboundReaskTarget,
) -> Vec<u8> {
    build_reask_ack_packet(part_status, queue_position, peer_udp_version, target).bytes
}

/// Build an `OP_REASKACK` datagram with packet-diagnostic metadata.
pub(crate) fn build_reask_ack_packet(
    part_status: Option<&[bool]>,
    queue_position: u16,
    peer_udp_version: u8,
    target: &OutboundReaskTarget,
) -> ClientUdpDatagram {
    let body = encode_reask_ack(part_status, queue_position, peer_udp_version);
    frame_packet(OP_REASKACK, &body, target)
}

/// Build an empty-body `OP_QUEUEFULL` datagram (uploader -> downloader).
pub(crate) fn build_queue_full_datagram(target: &OutboundReaskTarget) -> Vec<u8> {
    build_queue_full_packet(target).bytes
}

/// Build an empty-body `OP_QUEUEFULL` datagram with packet-diagnostic metadata.
pub(crate) fn build_queue_full_packet(target: &OutboundReaskTarget) -> ClientUdpDatagram {
    frame_packet(OP_QUEUEFULL, &[], target)
}

/// Build an empty-body `OP_FILENOTFOUND` datagram (uploader -> downloader).
pub(crate) fn build_file_not_found_datagram(target: &OutboundReaskTarget) -> Vec<u8> {
    build_file_not_found_packet(target).bytes
}

/// Build an empty-body `OP_FILENOTFOUND` datagram with packet-diagnostic metadata.
pub(crate) fn build_file_not_found_packet(target: &OutboundReaskTarget) -> ClientUdpDatagram {
    frame_packet(OP_FILENOTFOUND, &[], target)
}

/// Build an `OP_REASKCALLBACKUDP` datagram (downloader -> source's buddy). eMule
/// always sends this **plaintext** (the buddy's Kad version is unknown), so this
/// ignores `target.obfuscate` and never encrypts.
pub(crate) fn build_reask_callback_udp_datagram(
    buddy_id: &Ed2kHash,
    file_hash: &Ed2kHash,
    part_status: Option<&[bool]>,
    complete_source_count: u16,
    our_udp_version: u8,
) -> Vec<u8> {
    build_reask_callback_udp_packet(
        buddy_id,
        file_hash,
        part_status,
        complete_source_count,
        our_udp_version,
    )
    .bytes
}

/// Build a plaintext `OP_REASKCALLBACKUDP` datagram with packet-diagnostic metadata.
pub(crate) fn build_reask_callback_udp_packet(
    buddy_id: &Ed2kHash,
    file_hash: &Ed2kHash,
    part_status: Option<&[bool]>,
    complete_source_count: u16,
    our_udp_version: u8,
) -> ClientUdpDatagram {
    let body = encode_reask_callback_udp(
        buddy_id,
        file_hash,
        part_status,
        complete_source_count,
        our_udp_version,
    );
    let mut datagram = Vec::with_capacity(2 + body.len());
    datagram.push(OP_EMULEPROT);
    datagram.push(OP_REASKCALLBACKUDP);
    datagram.extend_from_slice(&body);
    ClientUdpDatagram {
        bytes: datagram,
        protocol_marker: OP_EMULEPROT,
        opcode: OP_REASKCALLBACKUDP,
        payload: body,
        obfuscated: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_client_udp::dispatch::{InboundReaskMessage, parse_inbound_reask_datagram};

    const DEST_HASH: [u8; 16] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30,
    ];
    const OUR_IP: [u8; 4] = [203, 0, 113, 9];

    fn file_hash() -> Ed2kHash {
        Ed2kHash::from_bytes([
            0x9e, 0xce, 0xd4, 0x7d, 0xf2, 0xed, 0xfb, 0xd7, 0x2f, 0x29, 0xf9, 0x34, 0x47, 0xd6,
            0x0b, 0x7b,
        ])
    }

    fn plaintext_target() -> OutboundReaskTarget {
        OutboundReaskTarget {
            dest_user_hash: DEST_HASH,
            our_public_ip: OUR_IP,
            obfuscate: false,
        }
    }

    fn obfuscated_target() -> OutboundReaskTarget {
        OutboundReaskTarget {
            dest_user_hash: DEST_HASH,
            our_public_ip: OUR_IP,
            obfuscate: true,
        }
    }

    /// The receiver of a packet we built toward DEST_HASH keys on its own hash
    /// (== DEST_HASH) + our IP (the sender IP it sees) — so a build->parse
    /// round-trip uses DEST_HASH as the receiver hash and OUR_IP as the sender IP.
    #[test]
    fn file_ping_round_trips_plaintext_and_obfuscated() {
        let parts = [true, false, true, true];
        for target in [plaintext_target(), obfuscated_target()] {
            let datagram =
                build_reask_file_ping_datagram(&file_hash(), Some(&parts), 5, 4, &target);
            let msg = parse_inbound_reask_datagram(&datagram, OUR_IP, &DEST_HASH, 4).unwrap();
            match msg {
                InboundReaskMessage::FilePing(ping) => {
                    assert_eq!(ping.file_hash, file_hash());
                    assert_eq!(ping.part_status.unwrap(), parts);
                    assert_eq!(ping.complete_source_count, Some(5));
                }
                other => panic!("expected FilePing, got {other:?}"),
            }
        }
    }

    #[test]
    fn ack_round_trips_obfuscated() {
        let datagram = build_reask_ack_datagram(None, 13, 4, &obfuscated_target());
        let msg = parse_inbound_reask_datagram(&datagram, OUR_IP, &DEST_HASH, 4).unwrap();
        match msg {
            InboundReaskMessage::Ack(ack) => assert_eq!(ack.queue_position, 13),
            other => panic!("expected Ack, got {other:?}"),
        }
    }

    #[test]
    fn empty_body_opcodes_round_trip() {
        let qf = build_queue_full_datagram(&plaintext_target());
        assert_eq!(
            parse_inbound_reask_datagram(&qf, OUR_IP, &DEST_HASH, 4),
            Some(InboundReaskMessage::QueueFull)
        );
        let fnf = build_file_not_found_datagram(&obfuscated_target());
        assert_eq!(
            parse_inbound_reask_datagram(&fnf, OUR_IP, &DEST_HASH, 4),
            Some(InboundReaskMessage::FileNotFound)
        );
    }

    #[test]
    fn callback_udp_is_always_plaintext() {
        let buddy = Ed2kHash::from_bytes([0x55; 16]);
        let datagram = build_reask_callback_udp_datagram(&buddy, &file_hash(), None, 2, 4);
        // Always plaintext: starts with the OP_EMULEPROT marker (never obfuscated).
        assert_eq!(datagram[0], OP_EMULEPROT);
        assert_eq!(datagram[1], OP_REASKCALLBACKUDP);
        // The buddy (receiver) parses it without any key (plaintext path).
        let msg = parse_inbound_reask_datagram(&datagram, OUR_IP, &[0u8; 16], 4).unwrap();
        match msg {
            InboundReaskMessage::CallbackUdp(cb) => {
                assert_eq!(cb.buddy_id, buddy);
                assert_eq!(cb.file_hash, file_hash());
            }
            other => panic!("expected CallbackUdp, got {other:?}"),
        }
    }
}
