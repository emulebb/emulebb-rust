//! Inbound client-UDP reask parsing — the typed entry point the (shared Kad UDP
//! socket) recv loop calls to turn a raw datagram into a reask message.
//!
//! Composes the obfuscation layer ([`crate::ed2k_client_udp_obfuscation`]) and
//! the wire [`super::codec`]: it handles both plaintext eD2k client packets
//! (first byte `OP_EMULEPROT`, used when crypt is off and for buddy relays) and
//! obfuscated ones (deobfuscated under our user hash + the sender IP), then
//! decodes the reask opcode. Pure and transport-free; `docs/design/udp-source-reask.md`
//! §4.3-§4.5.
//!
//! Demux ordering note: on the shared socket the recv loop tries Kad decode
//! first and only falls back to this for datagrams Kad does not own. That is
//! safe because the two key spaces do not collide — a Kad packet will not
//! decrypt to the eD2k client sync magic under our user-hash key (returns
//! `None`), and an obfuscated eD2k client packet will not validate as Kad.

use std::borrow::Cow;

use super::codec::{
    DirectCallbackReq, OP_DIRECTCALLBACKREQ, OP_FILENOTFOUND, OP_QUEUEFULL, OP_REASKACK,
    OP_REASKCALLBACKUDP, OP_REASKFILEPING, ReaskAck, ReaskCallbackUdp, ReaskFilePing,
    decode_direct_callback_req, decode_reask_ack, decode_reask_callback_udp,
    decode_reask_file_ping,
};
use crate::ed2k_client_udp_obfuscation::deobfuscate_client_udp;

/// The eD2k protocol marker that prefixes client UDP packets (`OP_EMULEPROT`).
const OP_EMULEPROT: u8 = 0xC5;

/// A decoded inbound reask message, discriminated by opcode + role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InboundReaskMessage {
    /// `OP_REASKFILEPING` — a peer queued on us is refreshing its slot (uploader
    /// side; answer via [`super::answer_inbound_reask`]).
    FilePing(ReaskFilePing),
    /// `OP_REASKACK` — a source answered our reask with our queue rank
    /// (downloader side; feed [`super::apply_reask_reply`]).
    Ack(ReaskAck),
    /// `OP_QUEUEFULL` — a source's queue is full (downloader side).
    QueueFull,
    /// `OP_FILENOTFOUND` — a source no longer has the file (downloader side).
    FileNotFound,
    /// `OP_REASKCALLBACKUDP` — a LowID buddy relay (we are the buddy).
    CallbackUdp(ReaskCallbackUdp),
    /// `OP_DIRECTCALLBACKREQ` — a peer that cannot reach us over TCP (we are the
    /// firewalled LowID side that advertised direct UDP callback) asks us to
    /// connect out to it (oracle `ClientUDPSocket.cpp` `OP_DIRECTCALLBACKREQ`).
    DirectCallbackReq(DirectCallbackReq),
}

/// Parse a raw inbound datagram as a client-UDP reask message, or `None` if it
/// is not one addressed to us (junk, a Kad packet, or an unknown opcode).
///
/// - `datagram`: the raw UDP payload.
/// - `sender_ip`: the sender's IPv4 octets (`a.b.c.d`) from `recvfrom` — keys the
///   deobfuscation, and must match the IP the sender used as its public IP.
/// - `our_user_hash`: our 16-byte user hash (the obfuscation key for packets
///   addressed to us).
/// - `our_udp_version`: our advertised eD2k UDP version (gates the optional
///   partstatus/complete-count tails in the decoders).
pub(crate) fn parse_inbound_reask_datagram(
    datagram: &[u8],
    sender_ip: [u8; 4],
    our_user_hash: &[u8; 16],
    our_udp_version: u8,
) -> Option<InboundReaskMessage> {
    // Plaintext eD2k client packets start with the OP_EMULEPROT marker; obfuscated
    // ones never do (it is a reserved byte excluded from the crypt marker), so try
    // to deobfuscate those under our user-hash key.
    let frame: Cow<'_, [u8]> = if datagram.first() == Some(&OP_EMULEPROT) {
        Cow::Borrowed(datagram)
    } else {
        Cow::Owned(deobfuscate_client_udp(our_user_hash, sender_ip, datagram)?)
    };

    // After the [OP_EMULEPROT][opcode] header, the rest is the opcode body.
    if frame.len() < 2 || frame[0] != OP_EMULEPROT {
        return None;
    }
    let body = &frame[2..];
    match frame[1] {
        OP_REASKFILEPING => decode_reask_file_ping(body, our_udp_version)
            .ok()
            .map(InboundReaskMessage::FilePing),
        OP_REASKACK => decode_reask_ack(body, our_udp_version)
            .ok()
            .map(InboundReaskMessage::Ack),
        OP_QUEUEFULL => Some(InboundReaskMessage::QueueFull),
        OP_FILENOTFOUND => Some(InboundReaskMessage::FileNotFound),
        OP_REASKCALLBACKUDP => decode_reask_callback_udp(body, our_udp_version)
            .ok()
            .map(InboundReaskMessage::CallbackUdp),
        OP_DIRECTCALLBACKREQ => decode_direct_callback_req(body)
            .ok()
            .map(InboundReaskMessage::DirectCallbackReq),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_client_udp::codec::{encode_reask_ack, encode_reask_file_ping};
    use crate::ed2k_client_udp_obfuscation::obfuscate_client_udp_with;
    use emulebb_kad_proto::Ed2kHash;

    const OUR_HASH: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    const SENDER_IP: [u8; 4] = [198, 51, 100, 23];

    fn file_hash() -> Ed2kHash {
        Ed2kHash::from_bytes([
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ])
    }

    fn frame(opcode: u8, body: &[u8]) -> Vec<u8> {
        let mut f = vec![OP_EMULEPROT, opcode];
        f.extend_from_slice(body);
        f
    }

    #[test]
    fn parses_plaintext_file_ping() {
        let body = encode_reask_file_ping(&file_hash(), Some(&[true, false, true]), 4, 4);
        let datagram = frame(OP_REASKFILEPING, &body);
        let msg = parse_inbound_reask_datagram(&datagram, SENDER_IP, &OUR_HASH, 4).unwrap();
        match msg {
            InboundReaskMessage::FilePing(ping) => assert_eq!(ping.file_hash, file_hash()),
            other => panic!("expected FilePing, got {other:?}"),
        }
    }

    #[test]
    fn parses_obfuscated_ack() {
        // A source (keying on our hash + its own IP == SENDER_IP) answers our reask.
        let body = encode_reask_ack(None, 9, 4);
        let plain = frame(OP_REASKACK, &body);
        let datagram = obfuscate_client_udp_with(&OUR_HASH, SENDER_IP, &plain, 0x2468, 0x40);
        let msg = parse_inbound_reask_datagram(&datagram, SENDER_IP, &OUR_HASH, 4).unwrap();
        assert_eq!(
            msg,
            InboundReaskMessage::Ack(ReaskAck {
                part_status: None,
                queue_position: 9
            })
        );
    }

    #[test]
    fn parses_plaintext_direct_callback_req() {
        // <TCPPort u16 LE><Userhash 16><ConnectOptions u8>.
        let mut body = Vec::new();
        body.extend_from_slice(&4662u16.to_le_bytes());
        body.extend_from_slice(&[0x5A; 16]);
        body.push(0x01);
        let datagram = frame(0x95, &body); // OP_DIRECTCALLBACKREQ
        let msg = parse_inbound_reask_datagram(&datagram, SENDER_IP, &OUR_HASH, 4).unwrap();
        match msg {
            InboundReaskMessage::DirectCallbackReq(req) => {
                assert_eq!(req.tcp_port, 4662);
                assert_eq!(req.user_hash, [0x5A; 16]);
                assert_eq!(req.connect_options, 0x01);
            }
            other => panic!("expected DirectCallbackReq, got {other:?}"),
        }
    }

    #[test]
    fn parses_obfuscated_direct_callback_req() {
        // The oracle obfuscates it under our hash + its own IP when we accept crypt.
        let mut body = Vec::new();
        body.extend_from_slice(&5000u16.to_le_bytes());
        body.extend_from_slice(&[0x77; 16]);
        body.push(0x00);
        let plain = frame(0x95, &body);
        let datagram = obfuscate_client_udp_with(&OUR_HASH, SENDER_IP, &plain, 0x1357, 0x40);
        let msg = parse_inbound_reask_datagram(&datagram, SENDER_IP, &OUR_HASH, 4).unwrap();
        match msg {
            InboundReaskMessage::DirectCallbackReq(req) => assert_eq!(req.tcp_port, 5000),
            other => panic!("expected DirectCallbackReq, got {other:?}"),
        }
    }

    #[test]
    fn parses_empty_body_status_opcodes() {
        assert_eq!(
            parse_inbound_reask_datagram(&frame(OP_QUEUEFULL, &[]), SENDER_IP, &OUR_HASH, 4),
            Some(InboundReaskMessage::QueueFull)
        );
        assert_eq!(
            parse_inbound_reask_datagram(&frame(OP_FILENOTFOUND, &[]), SENDER_IP, &OUR_HASH, 4),
            Some(InboundReaskMessage::FileNotFound)
        );
    }

    #[test]
    fn non_reask_emuleprot_opcode_is_ignored() {
        // Plaintext OP_EMULEPROT but an opcode we don't handle here.
        assert!(
            parse_inbound_reask_datagram(&frame(0x01, &[1, 2, 3]), SENDER_IP, &OUR_HASH, 4)
                .is_none()
        );
    }

    #[test]
    fn obfuscated_packet_under_wrong_hash_is_ignored() {
        let plain = frame(OP_REASKACK, &encode_reask_ack(None, 1, 4));
        let datagram = obfuscate_client_udp_with(&OUR_HASH, SENDER_IP, &plain, 0x1111, 0x40);
        let mut other_hash = OUR_HASH;
        other_hash[0] ^= 0xFF;
        // Not addressed to us (different key) -> let the recv loop fall through to Kad.
        assert!(parse_inbound_reask_datagram(&datagram, SENDER_IP, &other_hash, 4).is_none());
    }

    #[test]
    fn junk_and_short_datagrams_are_ignored() {
        assert!(parse_inbound_reask_datagram(&[], SENDER_IP, &OUR_HASH, 4).is_none());
        assert!(parse_inbound_reask_datagram(&[OP_EMULEPROT], SENDER_IP, &OUR_HASH, 4).is_none());
        // Random non-OP_EMULEPROT bytes that don't decrypt to our sync magic.
        assert!(parse_inbound_reask_datagram(&[0x42; 24], SENDER_IP, &OUR_HASH, 4).is_none());
    }
}
