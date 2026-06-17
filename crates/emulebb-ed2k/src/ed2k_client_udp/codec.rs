//! Wire codec for the client-to-client eD2k UDP reask opcodes
//! (`OP_REASKFILEPING` family), framed exactly as `emulebb-main` does (see
//! `docs/design/udp-source-reask.md`). All four are `OP_EMULEPROT` opcodes on the
//! *client UDP* socket, disambiguated from the same numeric opcodes on other
//! sockets purely by socket + protocol byte.
//!
//! Wire bodies (after the `[OP_EMULEPROT][opcode]` UDP header, pre-obfuscation):
//! - `OP_REASKFILEPING` (downloader -> source):
//!   `hash16` + (sender udp_version > 3: partstatus) + (sender udp_version > 2:
//!   `u16` complete-source count).
//! - `OP_REASKACK` (source -> downloader): (source udp_version > 3: partstatus)
//!   + `u16` queue position.
//! - `OP_QUEUEFULL`, `OP_FILENOTFOUND`: empty body.
//!
//! `partstatus` is `u16 part_count` + a `ceil(part_count / 8)` bitfield, LSB-first
//! within each byte (the same layout as OP_FILESTATUS). A `part_count` of 0 means
//! "no partfile" (request) or "complete file" (answer).

use anyhow::{Result, bail};
use emulebb_kad_proto::Ed2kHash;

/// `OP_EMULEPROT` reask opcodes on the client UDP socket.
pub(crate) const OP_REASKFILEPING: u8 = 0x90;
pub(crate) const OP_REASKACK: u8 = 0x91;
pub(crate) const OP_FILENOTFOUND: u8 = 0x92;
pub(crate) const OP_QUEUEFULL: u8 = 0x93;
/// LowID buddy-relayed reask (`OP_REASKCALLBACKUDP`): sent to the source's Kad
/// buddy when the source is LowID. Phase 2 — codec only; the transport that
/// relays it (and which eMule sends *unencrypted*, since the buddy's Kad version
/// is unknown) is deferred with the rest of the reask transport.
pub(crate) const OP_REASKCALLBACKUDP: u8 = 0x94;
/// Direct-UDP-callback request (`OP_DIRECTCALLBACKREQ`): a peer that cannot reach
/// us over TCP (we are the firewalled LowID side that advertised MISCOPTIONS2 bit
/// 12) asks us to connect out to it. Body
/// `<TCPPort u16 LE><Userhash 16><ConnectOptions u8>` (oracle `Opcodes.h` /
/// `BaseClient.cpp:1481` `OP_DIRECTCALLBACKREQ`).
pub(crate) const OP_DIRECTCALLBACKREQ: u8 = 0x95;

/// Decoded `OP_REASKFILEPING` request (uploader/reciprocity side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReaskFilePing {
    pub file_hash: Ed2kHash,
    /// Sender's part availability, when it advertised one (udp_version > 3 and it
    /// holds a partfile). `None` means no partfile / not advertised.
    pub part_status: Option<Vec<bool>>,
    /// Sender's reported complete-source count (udp_version > 2), else `None`.
    pub complete_source_count: Option<u16>,
}

/// Decoded `OP_REASKACK` reply (downloader side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReaskAck {
    /// Uploader's part availability, when advertised (peer udp_version > 3).
    pub part_status: Option<Vec<bool>>,
    /// Our position in the uploader's queue.
    pub queue_position: u16,
}

/// Decoded `OP_REASKCALLBACKUDP` request (LowID buddy-relayed reask). Same as
/// `OP_REASKFILEPING` with the source's buddy Kad id prepended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReaskCallbackUdp {
    /// The source's buddy Kad id (`GetBuddyID`), which relays the reask.
    pub buddy_id: Ed2kHash,
    pub file_hash: Ed2kHash,
    pub part_status: Option<Vec<bool>>,
    pub complete_source_count: Option<u16>,
}

/// Decoded `OP_DIRECTCALLBACKREQ` request (we are the firewalled LowID source the
/// requester cannot reach over TCP; we connect out to it). The requester's IP is
/// the UDP sender IP (not in the body); the TCP port to connect to is `tcp_port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectCallbackReq {
    /// The requester's listen TCP port to connect back to.
    pub tcp_port: u16,
    /// The requester's user hash (passed to the outbound hello for secure ident).
    pub user_hash: [u8; 16],
    /// The requester's advertised connect options byte (`GetMyConnectOptions`).
    pub connect_options: u8,
}

/// Decodes an `OP_DIRECTCALLBACKREQ` body
/// `<TCPPort u16 LE><Userhash 16><ConnectOptions u8>` (oracle
/// `ClientUDPSocket.cpp:438-442` + `ProtocolGuards.h HasUdpDirectCallbackRequest`
/// which requires `>= 19` bytes).
pub(crate) fn decode_direct_callback_req(body: &[u8]) -> Result<DirectCallbackReq> {
    if body.len() < 19 {
        bail!("short OP_DIRECTCALLBACKREQ body ({})", body.len());
    }
    let tcp_port = u16::from_le_bytes([body[0], body[1]]);
    let user_hash: [u8; 16] = body[2..18].try_into()?;
    let connect_options = body[18];
    Ok(DirectCallbackReq {
        tcp_port,
        user_hash,
        connect_options,
    })
}

/// Encodes a `partstatus` field: `u16 count` + LSB-first bitfield. `None` (no
/// partfile / complete file) encodes as `u16 0`.
fn encode_part_status(part_status: Option<&[bool]>) -> Vec<u8> {
    let Some(parts) = part_status else {
        return 0u16.to_le_bytes().to_vec();
    };
    let count = u16::try_from(parts.len()).unwrap_or(u16::MAX);
    let mut out = count.to_le_bytes().to_vec();
    let mut current = 0u8;
    for (index, &present) in parts.iter().enumerate() {
        if present {
            current |= 1 << (index % 8);
        }
        if index % 8 == 7 {
            out.push(current);
            current = 0;
        }
    }
    if parts.len() % 8 != 0 {
        out.push(current);
    }
    out
}

/// Decodes a `partstatus` field, returning the bitmap (`None` when count is 0)
/// and the remaining bytes.
fn decode_part_status(buf: &[u8]) -> Result<(Option<Vec<bool>>, &[u8])> {
    if buf.len() < 2 {
        bail!("short reask partstatus header");
    }
    let count = usize::from(u16::from_le_bytes([buf[0], buf[1]]));
    if count == 0 {
        return Ok((None, &buf[2..]));
    }
    let bitfield_len = count.div_ceil(8);
    let end = 2 + bitfield_len;
    if buf.len() < end {
        bail!("short reask partstatus bitfield ({count} parts)");
    }
    let bitfield = &buf[2..end];
    let bitmap = (0..count)
        .map(|index| (bitfield[index / 8] >> (index % 8)) & 1 == 1)
        .collect();
    Ok((Some(bitmap), &buf[end..]))
}

/// Encodes the `OP_REASKFILEPING` body. `sender_udp_version` is *our* advertised
/// UDP version (gates the optional tails, matching eMule's `UDPReaskForDownload`).
pub(crate) fn encode_reask_file_ping(
    file_hash: &Ed2kHash,
    part_status: Option<&[bool]>,
    complete_source_count: u16,
    sender_udp_version: u8,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(16 + 4);
    body.extend_from_slice(&file_hash.0);
    if sender_udp_version > 3 {
        body.extend_from_slice(&encode_part_status(part_status));
    }
    if sender_udp_version > 2 {
        body.extend_from_slice(&complete_source_count.to_le_bytes());
    }
    body
}

/// Decodes an `OP_REASKFILEPING` body. `sender_udp_version` is the *peer's*
/// advertised UDP version (learned at hello time).
pub(crate) fn decode_reask_file_ping(body: &[u8], sender_udp_version: u8) -> Result<ReaskFilePing> {
    if body.len() < 16 {
        bail!("short OP_REASKFILEPING body ({})", body.len());
    }
    let file_hash = Ed2kHash::from_bytes(body[..16].try_into()?);
    let mut rest = &body[16..];
    let mut part_status = None;
    if sender_udp_version > 3 {
        let (bitmap, tail) = decode_part_status(rest)?;
        part_status = bitmap;
        rest = tail;
    }
    let mut complete_source_count = None;
    if sender_udp_version > 2 {
        if rest.len() < 2 {
            bail!("short OP_REASKFILEPING complete-source count");
        }
        complete_source_count = Some(u16::from_le_bytes([rest[0], rest[1]]));
    }
    Ok(ReaskFilePing {
        file_hash,
        part_status,
        complete_source_count,
    })
}

/// Encodes the `OP_REASKACK` body. `peer_udp_version` is the *downloader's*
/// version (we are the uploader answering): it gates the leading partstatus.
pub(crate) fn encode_reask_ack(
    part_status: Option<&[bool]>,
    queue_position: u16,
    peer_udp_version: u8,
) -> Vec<u8> {
    let mut body = Vec::new();
    if peer_udp_version > 3 {
        body.extend_from_slice(&encode_part_status(part_status));
    }
    body.extend_from_slice(&queue_position.to_le_bytes());
    body
}

/// Decodes an `OP_REASKACK` body. `our_udp_version` is our advertised version
/// (the source gated the leading partstatus on it).
pub(crate) fn decode_reask_ack(body: &[u8], our_udp_version: u8) -> Result<ReaskAck> {
    let mut rest = body;
    let mut part_status = None;
    if our_udp_version > 3 {
        let (bitmap, tail) = decode_part_status(rest)?;
        part_status = bitmap;
        rest = tail;
    }
    if rest.len() < 2 {
        bail!("short OP_REASKACK queue position");
    }
    let queue_position = u16::from_le_bytes([rest[0], rest[1]]);
    Ok(ReaskAck {
        part_status,
        queue_position,
    })
}

/// Encodes the `OP_REASKCALLBACKUDP` body: `buddy_id16` + `file_hash16` + the same
/// `sender_udp_version`-gated partstatus/complete-count tail as `OP_REASKFILEPING`.
pub(crate) fn encode_reask_callback_udp(
    buddy_id: &Ed2kHash,
    file_hash: &Ed2kHash,
    part_status: Option<&[bool]>,
    complete_source_count: u16,
    sender_udp_version: u8,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(16 + 16 + 4);
    body.extend_from_slice(&buddy_id.0);
    body.extend_from_slice(&file_hash.0);
    if sender_udp_version > 3 {
        body.extend_from_slice(&encode_part_status(part_status));
    }
    if sender_udp_version > 2 {
        body.extend_from_slice(&complete_source_count.to_le_bytes());
    }
    body
}

/// Decodes an `OP_REASKCALLBACKUDP` body. `sender_udp_version` is the relaying
/// downloader's advertised UDP version (gates the optional tails).
pub(crate) fn decode_reask_callback_udp(
    body: &[u8],
    sender_udp_version: u8,
) -> Result<ReaskCallbackUdp> {
    if body.len() < 32 {
        bail!("short OP_REASKCALLBACKUDP body ({})", body.len());
    }
    let buddy_id = Ed2kHash::from_bytes(body[..16].try_into()?);
    let file_hash = Ed2kHash::from_bytes(body[16..32].try_into()?);
    let mut rest = &body[32..];
    let mut part_status = None;
    if sender_udp_version > 3 {
        let (bitmap, tail) = decode_part_status(rest)?;
        part_status = bitmap;
        rest = tail;
    }
    let mut complete_source_count = None;
    if sender_udp_version > 2 {
        if rest.len() < 2 {
            bail!("short OP_REASKCALLBACKUDP complete-source count");
        }
        complete_source_count = Some(u16::from_le_bytes([rest[0], rest[1]]));
    }
    Ok(ReaskCallbackUdp {
        buddy_id,
        file_hash,
        part_status,
        complete_source_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash() -> Ed2kHash {
        Ed2kHash::from_bytes([
            0x9e, 0xce, 0xd4, 0x7d, 0xf2, 0xed, 0xfb, 0xd7, 0x2f, 0x29, 0xf9, 0x34, 0x47, 0xd6,
            0x0b, 0x7b,
        ])
    }

    #[test]
    fn direct_callback_req_decodes_oracle_layout() {
        // <TCPPort u16 LE><Userhash 16><ConnectOptions u8> (oracle BaseClient.cpp:1481).
        let mut body = Vec::new();
        body.extend_from_slice(&4662u16.to_le_bytes());
        let user_hash = [0x5Au8; 16];
        body.extend_from_slice(&user_hash);
        body.push(0x03);
        let decoded = decode_direct_callback_req(&body).unwrap();
        assert_eq!(decoded.tcp_port, 4662);
        assert_eq!(decoded.user_hash, user_hash);
        assert_eq!(decoded.connect_options, 0x03);
    }

    #[test]
    fn direct_callback_req_rejects_short_body() {
        // 18 bytes is one short of the oracle HasUdpDirectCallbackRequest >= 19 gate.
        assert!(decode_direct_callback_req(&[0u8; 18]).is_err());
        assert!(decode_direct_callback_req(&[]).is_err());
    }

    #[test]
    fn part_status_round_trip_lsb_first() {
        // 10 parts: have 0,1,3,9 -> byte0 = 0b0000_1011, byte1 = 0b0000_0010.
        let parts = [
            true, true, false, true, false, false, false, false, false, true,
        ];
        let encoded = encode_part_status(Some(&parts));
        assert_eq!(encoded[0..2], 10u16.to_le_bytes());
        assert_eq!(encoded[2], 0b0000_1011);
        assert_eq!(encoded[3], 0b0000_0010);
        let (decoded, rest) = decode_part_status(&encoded).unwrap();
        assert_eq!(decoded.unwrap(), parts);
        assert!(rest.is_empty());
    }

    #[test]
    fn part_status_none_is_u16_zero() {
        assert_eq!(encode_part_status(None), vec![0, 0]);
        let (decoded, rest) = decode_part_status(&[0, 0, 0xAB]).unwrap();
        assert!(decoded.is_none());
        assert_eq!(rest, &[0xAB]);
    }

    #[test]
    fn reask_file_ping_v4_round_trip_with_partstatus_and_count() {
        let parts = [true, false, true];
        let body = encode_reask_file_ping(&hash(), Some(&parts), 7, 4);
        let decoded = decode_reask_file_ping(&body, 4).unwrap();
        assert_eq!(decoded.file_hash, hash());
        assert_eq!(decoded.part_status.unwrap(), parts);
        assert_eq!(decoded.complete_source_count, Some(7));
    }

    #[test]
    fn reask_file_ping_v2_has_count_but_no_partstatus() {
        // udp_version 3: > 2 (count present) but not > 3 (no partstatus).
        let body = encode_reask_file_ping(&hash(), Some(&[true]), 2, 3);
        assert_eq!(body.len(), 16 + 2); // hash + u16 count only
        let decoded = decode_reask_file_ping(&body, 3).unwrap();
        assert!(decoded.part_status.is_none());
        assert_eq!(decoded.complete_source_count, Some(2));
    }

    #[test]
    fn reask_file_ping_v1_is_hash_only() {
        let body = encode_reask_file_ping(&hash(), Some(&[true]), 9, 2);
        assert_eq!(body.len(), 16);
        let decoded = decode_reask_file_ping(&body, 2).unwrap();
        assert!(decoded.part_status.is_none());
        assert!(decoded.complete_source_count.is_none());
    }

    #[test]
    fn reask_ack_v4_round_trip() {
        let parts = [false, true, true, false, true];
        let body = encode_reask_ack(Some(&parts), 42, 4);
        let decoded = decode_reask_ack(&body, 4).unwrap();
        assert_eq!(decoded.part_status.unwrap(), parts);
        assert_eq!(decoded.queue_position, 42);
    }

    #[test]
    fn reask_ack_low_version_is_position_only() {
        let body = encode_reask_ack(Some(&[true]), 5, 3);
        assert_eq!(body, 5u16.to_le_bytes());
        let decoded = decode_reask_ack(&body, 3).unwrap();
        assert!(decoded.part_status.is_none());
        assert_eq!(decoded.queue_position, 5);
    }

    #[test]
    fn short_bodies_are_rejected() {
        assert!(decode_reask_file_ping(&[0u8; 4], 4).is_err());
        assert!(decode_reask_ack(&[], 2).is_err());
        assert!(decode_part_status(&[1]).is_err());
        assert!(decode_reask_callback_udp(&[0u8; 20], 4).is_err()); // < 32 (two hashes)
    }

    fn buddy() -> Ed2kHash {
        Ed2kHash::from_bytes([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ])
    }

    #[test]
    fn reask_callback_udp_v4_round_trip_prepends_buddy_id() {
        let parts = [true, false, false, true];
        let body = encode_reask_callback_udp(&buddy(), &hash(), Some(&parts), 5, 4);
        // buddy(16) + file(16) + partstatus(u16 count + 1 byte) + count(u16).
        assert_eq!(&body[..16], &buddy().0);
        assert_eq!(&body[16..32], &hash().0);
        let decoded = decode_reask_callback_udp(&body, 4).unwrap();
        assert_eq!(decoded.buddy_id, buddy());
        assert_eq!(decoded.file_hash, hash());
        assert_eq!(decoded.part_status.unwrap(), parts);
        assert_eq!(decoded.complete_source_count, Some(5));
    }

    #[test]
    fn reask_callback_udp_low_version_is_two_hashes_only() {
        let body = encode_reask_callback_udp(&buddy(), &hash(), Some(&[true]), 9, 2);
        assert_eq!(body.len(), 32); // udp_version 2: no tail
        let decoded = decode_reask_callback_udp(&body, 2).unwrap();
        assert_eq!(decoded.buddy_id, buddy());
        assert_eq!(decoded.file_hash, hash());
        assert!(decoded.part_status.is_none());
        assert!(decoded.complete_source_count.is_none());
    }
}
