use binrw::{BinRead, BinWrite, binrw};

use crate::hash::Ed2kHash;
use crate::node_id::NodeId;
use crate::tag::Tag;

// ── ContactEntry ──────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct ContactEntry {
    pub node_id: NodeId,
    /// IPv4 as little-endian u32 (eMule host byte order)
    pub ip: u32,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub version: u8,
}

impl ContactEntry {
    #[must_use]
    pub fn ip_addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(self.ip.to_be_bytes())
    }
}

// ── BootstrapReq ─────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct BootstrapReq;

// ── BootstrapRes ─────────────────────────────────────────────────────────────

/// Real on-wire format (from eMule source
/// `CKademliaUDPListener::ProcessBootstrapRequest`):
///   `sender_id` (`NodeId`, 16 bytes)
///   `tcp_port` (`u16`, 2 bytes)
///   `version` (`u8`, 1 byte)
///   `count` (`u16`, 2 bytes)
///   `contacts` (`count × 25` bytes each)
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct BootstrapRes {
    pub sender_id: NodeId,
    pub sender_tcp_port: u16,
    pub sender_version: u8,
    #[br(temp)]
    #[bw(calc = u16::try_from(contacts.len()).expect("contact count exceeds u16"))]
    count: u16,
    #[br(count = count)]
    pub contacts: Vec<ContactEntry>,
}

// ── HelloReq ─────────────────────────────────────────────────────────────────

/// Real on-wire format (from eMule source `CKademliaUDPListener::SendMyDetails`):
///   `node_id` (`NodeId`, 16 bytes)
///   `tcp_port` (`u16`, 2 bytes)
///   `version` (`u8`, 1 byte)
///   `tag_count` (`u8`, 1 byte)
///   `tags` (`tag_count × variable`)
///
/// Kad2 HELLO packets do not carry an explicit TCP IP nor a UDP verify key in
/// the payload. The sender verify key is recovered from the Kad UDP
/// obfuscation trailer instead.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct HelloReq {
    pub node_id: NodeId,
    pub tcp_port: u16,
    pub version: u8,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── HelloRes ─────────────────────────────────────────────────────────────────

/// Real on-wire format matches [`HelloReq`].
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct HelloRes {
    pub node_id: NodeId,
    pub tcp_port: u16,
    pub version: u8,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── HelloResAck ──────────────────────────────────────────────────────────────

/// Kad hello acknowledgment payload used by the three-way hello handshake.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct HelloResAck {
    /// Node ID that confirms the ACK sender's identity.
    pub node_id: NodeId,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    /// Reserved tag list. eMule currently sends an empty list here.
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── Req ──────────────────────────────────────────────────────────────────────
//
// eMule wire format (KADEMLIA2_REQ):
//   count_to_return: u8   — KADEMLIA_FIND_VALUE(2), KADEMLIA_FIND_NODE(0x0B), KADEMLIA_STORE(4)
//   target:          NodeId (16 bytes)
//   recipient_id:    NodeId (16 bytes) — the ID we believe the recipient has (sanity check)

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct Req {
    /// How many closest contacts to return (`KADEMLIA_FIND_VALUE/FIND_NODE/STORE`).
    pub count: u8,
    pub target: NodeId,
    /// The `NodeId` we believe the recipient has. Recipient drops packet if mismatch.
    pub recipient_id: NodeId,
}

// ── Res ──────────────────────────────────────────────────────────────────────

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct Res {
    pub target: NodeId,
    #[br(temp)]
    #[bw(calc = u8::try_from(contacts.len()).expect("contact count exceeds u8"))]
    count: u8,
    #[br(count = count)]
    pub contacts: Vec<ContactEntry>,
}

// ── SearchKeyReq ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchKeyReq {
    pub target: NodeId,
    pub start_position: u16,
    /// Raw trailing bytes preserved for restrictive keyword searches.
    ///
    /// eMule/aMule append the serialized search expression tree here when the
    /// high bit of `start_position` is set. We keep the payload opaque so the
    /// runtime can harvest and replay the exact wire shape without attempting
    /// to parse it yet.
    pub restrictive_payload: Vec<u8>,
}

// ── SearchSourceReq ──────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct SearchSourceReq {
    pub target: NodeId,
    /// Legacy source-page offset that still remains on the classic eMule wire.
    ///
    /// The oracle expects `KADEMLIA2_SEARCH_SOURCE_REQ` to carry this `u16`
    /// field immediately before the 64-bit file size.
    pub start_position: u16,
    pub size: u64,
}

// ── SearchNotesReq ───────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct SearchNotesReq {
    pub target: NodeId,
    pub size: u64,
}

// ── SearchResultEntry ────────────────────────────────────────────────────────
//
// eMule CEntry::WriteTagListInc writes: [tag_count:u8][tags...]
// So each result in SearchRes is: [entry_id:16][tag_count:u8][tags...]

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResultEntry {
    /// Generic per-entry identity from the oracle `SEARCH_RES` layout.
    ///
    /// Keyword results carry the file hash here. Source results carry the
    /// source/client identity. Notes results carry the note author/source
    /// identity.
    pub entry_id: Ed2kHash,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── SearchRes ────────────────────────────────────────────────────────────────
//
// eMule Indexed.cpp SendValidKeywordResult wire format:
//   sender_id: NodeId (16 bytes) — the responder's Kad ID
//   target:    NodeId (16 bytes) — echoed request target
//   count:     u16               — number of results in this packet
//   count × SearchResultEntry

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct SearchRes {
    /// The Kad ID of the node sending this response.
    pub sender_id: NodeId,
    /// Echoed search target from the request.
    ///
    /// Keyword searches echo the keyword hash here, while source and notes
    /// searches echo the searched file hash in the same 16-byte slot.
    pub target: NodeId,
    #[br(temp)]
    #[bw(calc = u16::try_from(results.len()).expect("result count exceeds u16"))]
    count: u16,
    #[br(count = count)]
    pub results: Vec<SearchResultEntry>,
}

// ── PublishEntry ─────────────────────────────────────────────────────────────

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct PublishEntry {
    pub hash: Ed2kHash,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── PublishKeyReq ────────────────────────────────────────────────────────────

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct PublishKeyReq {
    pub target: NodeId,
    #[br(temp)]
    #[bw(calc = u16::try_from(entries.len()).expect("entry count exceeds u16"))]
    count: u16,
    #[br(count = count)]
    pub entries: Vec<PublishEntry>,
}

// ── PublishSourceReq ─────────────────────────────────────────────────────────

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct PublishSourceReq {
    /// File-hash target being published.
    pub target: NodeId,
    /// Publisher/source identity carried in the second 16-byte slot.
    ///
    /// eMule uses a source-publish client identity here rather than another
    /// file hash. The Rust type stays `NodeId` because the wire slot is just 16
    /// opaque bytes.
    pub publisher_id: NodeId,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── PublishNotesReq ──────────────────────────────────────────────────────────

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct PublishNotesReq {
    /// File hash target of the notes publish operation.
    pub target: NodeId,
    /// Publisher Kad node identity written into the second 128-bit field.
    ///
    /// The wire width is still 16 bytes, but the semantic meaning is publisher
    /// identity rather than a note-specific hash.
    pub publisher_id: NodeId,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    /// Note payload tags such as filename, filesize, rating, and description.
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── PublishRes ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct PublishRes {
    pub target: NodeId,
    pub load: u8,
    /// Optional future-use byte. eMule currently treats bit 0 as a request for
    /// an empty `KADEMLIA2_PUBLISH_RES_ACK` when the response used a UDP key.
    pub options: Option<u8>,
}

// ── PublishResAck ────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct PublishResAck;

// ── FirewalledReq ────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct FirewalledReq {
    pub tcp_port: u16,
}

// ── Firewalled2Req ───────────────────────────────────────────────────────────

/// Extended TCP firewall-check request used by Kad version 7+ peers.
#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct Firewalled2Req {
    pub tcp_port: u16,
    pub user_hash: Ed2kHash,
    pub connect_options: u8,
}

// ── FirewalledRes ────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct FirewalledRes {
    pub ip: u32,
}

// ── FirewalledAckRes ─────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct FirewalledAckRes;

// ── FirewallUdp ──────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct FirewallUdp {
    pub error_code: u8,
    pub udp_port: u16,
}

// ── FindBuddyReq / FindBuddyRes / CallbackReq ───────────────────────────────

/// Buddy-discovery request sent by a firewalled Kad node.
///
/// Oracle semantics from eMule `Search.cpp` and `KademliaUDPListener.cpp`:
/// `buddy_id` is the Kad search target used to find a relay node, while
/// `client_hash` is the requester's eD2k client hash used for later TCP
/// callback routing.
#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct FindBuddyReq {
    pub buddy_id: NodeId,
    pub client_hash: Ed2kHash,
    pub tcp_port: u16,
}

/// Buddy-discovery response returned by the selected relay candidate.
///
/// The optional `connect_options` byte is appended by newer oracle versions so
/// the requester can decide whether future buddy traffic should prefer an
/// obfuscated TCP connection.
#[derive(Debug, Clone, PartialEq)]
pub struct FindBuddyRes {
    pub buddy_id: NodeId,
    pub client_hash: Ed2kHash,
    pub tcp_port: u16,
    pub connect_options: Option<u8>,
}

/// Buddy callback request asking the relay node to initiate a TCP callback.
///
/// `buddy_id` is the buddy-search target originally used by the remote low-ID
/// client, while `file_hash` identifies the shared file that motivated the
/// callback in the common source-search flow.
#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct CallbackReq {
    pub buddy_id: NodeId,
    pub file_hash: Ed2kHash,
    pub tcp_port: u16,
}

// ── Ping / Pong ──────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct Ping;

/// Kad liveness response carrying the UDP source port observed by the responder.
///
/// eMule uses this packet not only as a reply-to-ping marker, but also as an
/// external-port hint for Kad firewall probing.
#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct Pong {
    pub udp_port: u16,
}
