//! Kad2 packet codecs and typed wire layouts.
//!
//! Several Kad packets reuse 16-byte fields for different logical identities.
//! Field names in this module therefore document the oracle meaning of each
//! slot, not just the raw byte width.

mod codec;
mod types;

pub use types::{
    BootstrapReq, BootstrapRes, CallbackReq, ContactEntry, FindBuddyReq, FindBuddyRes, FirewallUdp,
    Firewalled2Req, FirewalledAckRes, FirewalledReq, FirewalledRes, HelloReq, HelloRes,
    HelloResAck, Ping, Pong, PublishEntry, PublishKeyReq, PublishNotesReq, PublishRes,
    PublishResAck, PublishSourceReq, Req, Res, SearchKeyReq, SearchNotesReq, SearchRes,
    SearchResultEntry, SearchSourceReq,
};

use binrw::{BinReaderExt, BinWriterExt};
use std::io::{Cursor, Write};

use crate::constants::{OP_KADEMLIAHEADER, OP_KADEMLIAPACKEDPROT, opcode};
use crate::error::ProtoError;
#[cfg(test)]
use crate::hash::Ed2kHash;
#[cfg(test)]
use crate::node_id::NodeId;
use codec::{
    read_find_buddy_res, read_publish_res, read_search_key_req, read_search_res,
    read_search_source_req, write_find_buddy_res, write_publish_res, write_search_key_req,
    write_search_res, write_search_source_req,
};

/// Hard cap on the inflated size of a `0xE5` (OP_KADEMLIAPACKEDPROT) Kad2
/// packet. Kad UDP datagrams (and thus the compressed input) are bounded by the
/// recv buffer at roughly 8 KB, and the largest legitimately decoded Kad2 packet
/// is a SEARCH_RES batch that stays well under a few KB. 64 KB is a generous but
/// bounded ceiling that no legitimate Kad packet reaches, while preventing a
/// crafted zlib bomb from expanding into an unbounded allocation.
const MAX_DECOMPRESSED_KAD_PACKET_LEN: usize = 64 * 1024;

/// eMule `Packet::PackPacket` for Kad: when the full cleartext Kad packet exceeds
/// 200 bytes, zlib-deflate the body (everything after the 2-byte
/// `[OP_KADEMLIAHEADER][opcode]` header) at best compression and — only if it
/// shrinks — flip the header to `OP_KADEMLIAPACKEDPROT` (0xE4 → 0xE5), keeping the
/// opcode byte uncompressed. Mirrors the `if (uLenData > 200) PackPacket()` gate
/// in every `CKademliaUDPListener::SendPacket` overload; a stock Kad node always
/// packs its oversized BOOTSTRAP_RES / KADEMLIA2_RES / SEARCH_RES / PUBLISH
/// datagrams, so never packing is a passive fingerprint. Applied to the cleartext
/// packet before obfuscation (the 0xE4/0xE5 byte rides inside the encrypted body).
#[must_use]
pub fn pack_kad_packet(encoded: Vec<u8>) -> Vec<u8> {
    use std::io::Write;

    const KAD_PACK_THRESHOLD: usize = 200;
    if encoded.len() <= KAD_PACK_THRESHOLD {
        return encoded;
    }
    let body = &encoded[2..];
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    if encoder.write_all(body).is_err() {
        return encoded;
    }
    let compressed = match encoder.finish() {
        Ok(compressed) => compressed,
        Err(_) => return encoded,
    };
    // Stock only keeps the packed form when it is actually smaller (`newsize < size`).
    if compressed.len() >= body.len() {
        return encoded;
    }
    let mut packed = Vec::with_capacity(2 + compressed.len());
    packed.push(OP_KADEMLIAPACKEDPROT);
    packed.push(encoded[1]);
    packed.extend_from_slice(&compressed);
    packed
}

fn require_body_len(opcode: u8, body: &[u8], expected: usize) -> Result<(), ProtoError> {
    if body.len() == expected {
        Ok(())
    } else {
        Err(ProtoError::InvalidPacketSize {
            opcode,
            expected,
            actual: body.len(),
        })
    }
}

fn require_min_body_len(opcode: u8, body: &[u8], expected_min: usize) -> Result<(), ProtoError> {
    if body.len() >= expected_min {
        Ok(())
    } else {
        Err(ProtoError::InvalidPacketSize {
            opcode,
            expected: expected_min,
            actual: body.len(),
        })
    }
}

// ── KadPacket ────────────────────────────────────────────────────────────────

/// The top-level Kad2 packet enum.
#[derive(Debug, Clone)]
pub enum KadPacket {
    BootstrapReq,
    BootstrapRes(BootstrapRes),
    HelloReq(HelloReq),
    HelloRes(HelloRes),
    HelloResAck(HelloResAck),
    Req(Req),
    Res(Res),
    SearchKeyReq(SearchKeyReq),
    SearchSourceReq(SearchSourceReq),
    SearchNotesReq(SearchNotesReq),
    SearchRes(SearchRes),
    PublishKeyReq(PublishKeyReq),
    PublishSourceReq(PublishSourceReq),
    PublishNotesReq(PublishNotesReq),
    PublishRes(PublishRes),
    PublishResAck,
    FirewalledReq(FirewalledReq),
    Firewalled2Req(Firewalled2Req),
    FirewalledRes(FirewalledRes),
    FirewalledAckRes,
    FirewallUdp(FirewallUdp),
    FindBuddyReq(FindBuddyReq),
    FindBuddyRes(FindBuddyRes),
    CallbackReq(CallbackReq),
    Ping,
    Pong(Pong),
    // KAD1_IGNORED: Kad1 packets dropped silently. See KADKAD.md §6 Kad1 Policy.
    Unknown { opcode: u8, payload: Vec<u8> },
}

impl KadPacket {
    /// Decode a Kad2 packet from a raw buffer.
    /// Handles both plain (0xE4) and zlib-compressed (0xE5) packets.
    ///
    /// # Errors
    ///
    /// Returns [`ProtoError`] when the buffer is too short, the protocol header
    /// is invalid, decompression fails, or the packet body cannot be decoded.
    pub fn decode(buf: &[u8]) -> Result<KadPacket, ProtoError> {
        if buf.len() < 2 {
            return Err(ProtoError::BufferTooShort);
        }

        // 0xE5 = OP_KADEMLIAPACKEDPROT: zlib-compressed body, same opcode byte.
        let (op, body_cow): (u8, std::borrow::Cow<[u8]>) = if buf[0] == OP_KADEMLIAPACKEDPROT {
            use flate2::read::ZlibDecoder;
            use std::io::Read;
            // Decompression-bomb guard: the compressed body fits the Kad UDP recv
            // buffer (~8 KB), and the largest legitimate decoded Kad2 packet
            // (a full SEARCH_RES batch) stays well under a few KB. Cap the
            // inflated output at MAX_DECOMPRESSED_KAD_PACKET_LEN so a crafted
            // input cannot expand ~1000:1 into an unbounded allocation. Reading
            // one byte past the cap proves overflow and is rejected.
            let mut decoder =
                ZlibDecoder::new(&buf[2..]).take(MAX_DECOMPRESSED_KAD_PACKET_LEN as u64 + 1);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|_| ProtoError::DecompressError)?;
            if decompressed.len() > MAX_DECOMPRESSED_KAD_PACKET_LEN {
                return Err(ProtoError::DecompressError);
            }
            (buf[1], std::borrow::Cow::Owned(decompressed))
        } else if buf[0] == OP_KADEMLIAHEADER {
            (buf[1], std::borrow::Cow::Borrowed(&buf[2..]))
        } else {
            return Err(ProtoError::InvalidProtocol(buf[0]));
        };

        let body: &[u8] = &body_cow;
        let mut cursor = Cursor::new(body);

        let packet = match op {
            opcode::BOOTSTRAP_REQ => KadPacket::BootstrapReq,
            opcode::BOOTSTRAP_RES => {
                let p = cursor.read_le::<BootstrapRes>()?;
                KadPacket::BootstrapRes(p)
            }
            opcode::HELLO_REQ => {
                let p = cursor.read_le::<HelloReq>()?;
                KadPacket::HelloReq(p)
            }
            opcode::HELLO_RES => {
                let p = cursor.read_le::<HelloRes>()?;
                KadPacket::HelloRes(p)
            }
            opcode::HELLO_RES_ACK => {
                let p = cursor.read_le::<HelloResAck>()?;
                KadPacket::HelloResAck(p)
            }
            opcode::REQ => {
                let p = cursor.read_le::<Req>()?;
                KadPacket::Req(p)
            }
            opcode::RES => {
                let p = cursor.read_le::<Res>()?;
                KadPacket::Res(p)
            }
            opcode::SEARCH_KEY_REQ => {
                let p = read_search_key_req(&mut cursor)?;
                KadPacket::SearchKeyReq(p)
            }
            opcode::SEARCH_SOURCE_REQ => {
                let p = read_search_source_req(&mut cursor)?;
                KadPacket::SearchSourceReq(p)
            }
            opcode::SEARCH_NOTES_REQ => {
                let p = cursor.read_le::<SearchNotesReq>()?;
                KadPacket::SearchNotesReq(p)
            }
            opcode::SEARCH_RES => {
                let p = read_search_res(&mut cursor)?;
                KadPacket::SearchRes(p)
            }
            opcode::PUBLISH_KEY_REQ => {
                let p = cursor.read_le::<PublishKeyReq>()?;
                KadPacket::PublishKeyReq(p)
            }
            opcode::PUBLISH_SOURCE_REQ => {
                let p = cursor.read_le::<PublishSourceReq>()?;
                KadPacket::PublishSourceReq(p)
            }
            opcode::PUBLISH_NOTES_REQ => {
                let p = cursor.read_le::<PublishNotesReq>()?;
                KadPacket::PublishNotesReq(p)
            }
            opcode::PUBLISH_RES => {
                require_min_body_len(op, body, 17)?;
                let p = read_publish_res(&mut cursor)?;
                KadPacket::PublishRes(p)
            }
            opcode::PUBLISH_RES_ACK => KadPacket::PublishResAck,
            opcode::FIREWALLED_REQ => {
                require_body_len(op, body, 2)?;
                let p = cursor.read_le::<FirewalledReq>()?;
                KadPacket::FirewalledReq(p)
            }
            opcode::FIREWALLED2_REQ => {
                let p = cursor.read_le::<Firewalled2Req>()?;
                KadPacket::Firewalled2Req(p)
            }
            opcode::FIREWALLED_RES => {
                require_body_len(op, body, 4)?;
                let p = cursor.read_le::<FirewalledRes>()?;
                KadPacket::FirewalledRes(p)
            }
            opcode::FIREWALLED_ACK_RES => {
                require_body_len(op, body, 0)?;
                KadPacket::FirewalledAckRes
            }
            opcode::FIREWALLUDP => {
                require_min_body_len(op, body, 3)?;
                let p = cursor.read_le::<FirewallUdp>()?;
                KadPacket::FirewallUdp(p)
            }
            opcode::FINDBUDDY_REQ => {
                require_min_body_len(op, body, 34)?;
                let p = cursor.read_le::<FindBuddyReq>()?;
                KadPacket::FindBuddyReq(p)
            }
            opcode::FINDBUDDY_RES => {
                require_min_body_len(op, body, 34)?;
                let p = read_find_buddy_res(&mut cursor)?;
                KadPacket::FindBuddyRes(p)
            }
            opcode::CALLBACK_REQ => {
                require_min_body_len(op, body, 34)?;
                let p = cursor.read_le::<CallbackReq>()?;
                KadPacket::CallbackReq(p)
            }
            opcode::PING => KadPacket::Ping,
            opcode::PONG => {
                require_min_body_len(op, body, 2)?;
                let p = cursor.read_le::<Pong>()?;
                KadPacket::Pong(p)
            }
            other => KadPacket::Unknown {
                opcode: other,
                payload: body.to_vec(),
            },
        };

        Ok(packet)
    }

    /// Encode a `KadPacket` to a byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ProtoError`] when writing the packet body fails.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let mut buf = Cursor::new(Vec::new());
        buf.write_le(&OP_KADEMLIAHEADER)?;
        let op = self.opcode();
        buf.write_le(&op)?;

        match self {
            KadPacket::BootstrapRes(p) => buf.write_le(p)?,
            KadPacket::HelloReq(p) => buf.write_le(p)?,
            KadPacket::HelloRes(p) => buf.write_le(p)?,
            KadPacket::HelloResAck(p) => buf.write_le(p)?,
            KadPacket::Req(p) => buf.write_le(p)?,
            KadPacket::Res(p) => buf.write_le(p)?,
            KadPacket::SearchKeyReq(p) => write_search_key_req(&mut buf, p)?,
            KadPacket::SearchSourceReq(p) => write_search_source_req(&mut buf, p)?,
            KadPacket::SearchNotesReq(p) => buf.write_le(p)?,
            KadPacket::SearchRes(p) => write_search_res(&mut buf, p)?,
            KadPacket::PublishKeyReq(p) => buf.write_le(p)?,
            KadPacket::PublishSourceReq(p) => buf.write_le(p)?,
            KadPacket::PublishNotesReq(p) => buf.write_le(p)?,
            KadPacket::PublishRes(p) => write_publish_res(&mut buf, p)?,
            KadPacket::FirewalledReq(p) => buf.write_le(p)?,
            KadPacket::Firewalled2Req(p) => buf.write_le(p)?,
            KadPacket::FirewalledRes(p) => buf.write_le(p)?,
            KadPacket::FirewallUdp(p) => buf.write_le(p)?,
            KadPacket::FindBuddyReq(p) => buf.write_le(p)?,
            KadPacket::FindBuddyRes(p) => write_find_buddy_res(&mut buf, p)?,
            KadPacket::CallbackReq(p) => buf.write_le(p)?,
            KadPacket::Pong(p) => buf.write_le(p)?,
            KadPacket::BootstrapReq
            | KadPacket::PublishResAck
            | KadPacket::FirewalledAckRes
            | KadPacket::Ping => {}
            KadPacket::Unknown { payload, .. } => {
                buf.write_all(payload).map_err(ProtoError::Io)?;
            }
        }

        Ok(buf.into_inner())
    }

    /// Returns the opcode byte for this packet.
    #[must_use]
    pub fn opcode(&self) -> u8 {
        match self {
            KadPacket::BootstrapReq => opcode::BOOTSTRAP_REQ,
            KadPacket::BootstrapRes(_) => opcode::BOOTSTRAP_RES,
            KadPacket::HelloReq(_) => opcode::HELLO_REQ,
            KadPacket::HelloRes(_) => opcode::HELLO_RES,
            KadPacket::HelloResAck(_) => opcode::HELLO_RES_ACK,
            KadPacket::Req(_) => opcode::REQ,
            KadPacket::Res(_) => opcode::RES,
            KadPacket::SearchKeyReq(_) => opcode::SEARCH_KEY_REQ,
            KadPacket::SearchSourceReq(_) => opcode::SEARCH_SOURCE_REQ,
            KadPacket::SearchNotesReq(_) => opcode::SEARCH_NOTES_REQ,
            KadPacket::SearchRes(_) => opcode::SEARCH_RES,
            KadPacket::PublishKeyReq(_) => opcode::PUBLISH_KEY_REQ,
            KadPacket::PublishSourceReq(_) => opcode::PUBLISH_SOURCE_REQ,
            KadPacket::PublishNotesReq(_) => opcode::PUBLISH_NOTES_REQ,
            KadPacket::PublishRes(_) => opcode::PUBLISH_RES,
            KadPacket::PublishResAck => opcode::PUBLISH_RES_ACK,
            KadPacket::FirewalledReq(_) => opcode::FIREWALLED_REQ,
            KadPacket::Firewalled2Req(_) => opcode::FIREWALLED2_REQ,
            KadPacket::FirewalledRes(_) => opcode::FIREWALLED_RES,
            KadPacket::FirewalledAckRes => opcode::FIREWALLED_ACK_RES,
            KadPacket::FirewallUdp(_) => opcode::FIREWALLUDP,
            KadPacket::FindBuddyReq(_) => opcode::FINDBUDDY_REQ,
            KadPacket::FindBuddyRes(_) => opcode::FINDBUDDY_RES,
            KadPacket::CallbackReq(_) => opcode::CALLBACK_REQ,
            KadPacket::Ping => opcode::PING,
            KadPacket::Pong(_) => opcode::PONG,
            KadPacket::Unknown { opcode, .. } => *opcode,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
