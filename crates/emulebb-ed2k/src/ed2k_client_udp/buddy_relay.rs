//! Buddy-relay framing for `OP_REASKCALLBACKUDP` (we are the LowID source's Kad
//! buddy). When a downloader cannot reach a firewalled source over client UDP it
//! sends `OP_REASKCALLBACKUDP` (buddy-id prefixed) to the source's buddy; the
//! buddy verifies the leading buddy-id against the buddy it serves and relays the
//! reask to that firewalled client over the held buddy TCP socket as
//! `OP_REASKCALLBACKTCP`.
//!
//! This module is the pure framing for the relay: it turns a decoded
//! [`super::codec::ReaskCallbackUdp`] plus the requester's UDP endpoint into the
//! `OP_REASKCALLBACKTCP` TCP frame the held buddy socket forwards. It mirrors the
//! oracle `ClientUDPSocket.cpp` `OP_REASKCALLBACKUDP` relay exactly:
//!
//! ```text
//!   PokeUInt32(buffer,     ip);                 // requester UDP source IP
//!   PokeUInt16(buffer + 4, port);               // requester UDP source port
//!   memcpy(buffer + 6, packet + 16, size - 16); // file_hash + udp-version tail
//! ```
//!
//! i.e. the relayed TCP body is `[requester_ip u32][requester_port u16]` followed
//! by the inbound `OP_REASKCALLBACKUDP` body with its leading 16-byte buddy-id
//! stripped (so `[file_hash 16][partstatus?][complete_count?]`). The buddy never
//! reinterprets the tail — it forwards it verbatim, exactly like the oracle.
//!
//! Oracle reference (do not modify): `srchybrid/ClientUDPSocket.cpp`
//! `CClientUDPSocket::ProcessPacket` `case OP_REASKCALLBACKUDP`.

use std::net::{Ipv4Addr, SocketAddr};

use emulebb_kad_dht::DhtNode;
use emulebb_kad_proto::{Ed2kHash, NodeId};
use tracing::trace;

use emulebb_kad_proto::Ed2kHash as KadEd2kHash;

use super::codec::OP_REASKCALLBACKUDP;
use super::outbound::{ClientUdpDatagram, build_reask_callback_udp_packet};
use super::state::ReaskSource;
use crate::buddy_socket::BuddySocketRegistry;
use crate::ed2k_transfer::Ed2kTransferRuntime;

/// The eD2k protocol marker that prefixes eMule TCP packets (`OP_EMULEPROT`).
const OP_EMULEPROT: u8 = 0xC5;
/// `OP_REASKCALLBACKTCP` opcode (the buddy-relayed reask over TCP).
const OP_REASKCALLBACKTCP: u8 = 0x9A;

/// Build the `OP_REASKCALLBACKTCP` TCP frame a buddy forwards to the firewalled
/// client it serves, from the decoded inbound `OP_REASKCALLBACKUDP` and the
/// requester's UDP source endpoint.
///
/// `callback` is the decoded inbound request (its buddy-id is *not* forwarded —
/// the oracle strips it). `requester_ip` / `requester_port` are the UDP source
/// of the inbound datagram (the downloader to answer). The returned bytes are a
/// complete eD2k TCP frame `[OP_EMULEPROT][len u32 LE][OP_REASKCALLBACKTCP][body]`
/// ready to write down the held buddy socket.
#[must_use]
pub(crate) fn encode_reask_callback_tcp_relay(
    callback: &super::codec::ReaskCallbackUdp,
    requester_ip: Ipv4Addr,
    requester_port: u16,
) -> Vec<u8> {
    // The oracle strips the leading 16-byte buddy-id and forwards everything after
    // it (`packet + 16` = `[file_hash 16][udp-version tail]`) verbatim, never
    // re-parsing or re-encoding the version-gated tail. `forwarded_tail` is exactly
    // those raw inbound bytes, so a legacy udp_version <= 3 sender's tail is passed
    // through unaltered instead of being misparsed or dropped.
    let forwarded_tail = callback.forwarded_tail.as_slice();

    let mut body = Vec::with_capacity(4 + 2 + forwarded_tail.len());
    // PokeUInt32(ip): the oracle passes the requester's IP as sockAddr.sin_addr.s_addr
    // — already in network byte order — and PokeUInt32 writes those bytes to the wire
    // as-is (ClientUDPSocket.cpp OP_REASKCALLBACKUDP relay). The firewalled source
    // reads it straight back as network order (ListenSocket.cpp OP_REASKCALLBACKTCP),
    // so emit the octets in natural network order (a.b.c.d -> [a,b,c,d]). This is the
    // client-UDP order; contrast the sibling OP_CALLBACK IP, which is Kad host order.
    body.extend_from_slice(&requester_ip.octets());
    body.extend_from_slice(&requester_port.to_le_bytes());
    body.extend_from_slice(forwarded_tail);

    // Frame as a standard eD2k TCP packet: [protocol][len u32 LE][opcode][body],
    // where len counts the opcode byte plus the body.
    let mut frame = Vec::with_capacity(6 + body.len());
    frame.push(OP_EMULEPROT);
    frame.extend_from_slice(
        &u32::try_from(body.len() + 1)
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    frame.push(OP_REASKCALLBACKTCP);
    frame.extend_from_slice(&body);
    frame
}

/// Downloader-origination of `OP_REASKCALLBACKUDP` (oracle
/// `DownloadClient.cpp:1840-1862` `UDPReaskForDownload` LowID branch). When a
/// queued source is a firewalled LowID client we cannot reach over direct client
/// UDP, but we know its Kad buddy (`HasLowID() && GetBuddyIP() && GetBuddyPort()
/// && HasValidBuddyID()`), build the buddy-relayed reask `[buddy_id][file_hash]
/// [reask tail]` and target it at the source's **buddy** endpoint, which relays
/// it on to the firewalled source as `OP_REASKCALLBACKTCP`.
///
/// Returns `(buddy_socket_addr, datagram)` when the source qualifies, else `None`
/// (HighID, or buddy endpoint/id unknown — the caller then uses the direct ping /
/// TCP path unchanged). The datagram is always **plaintext** (the buddy's Kad
/// version is unknown — oracle sends it unencrypted, `SendPacket(..., false, ...)`);
/// [`build_reask_callback_udp_datagram`] enforces this.
#[must_use]
pub(super) fn build_downloader_callback_origination(
    source: &ReaskSource,
    our_part_status: Option<&[bool]>,
    complete_source_count: u16,
) -> Option<(SocketAddr, ClientUdpDatagram)> {
    let ((buddy_ip, buddy_port), buddy_id) = source.buddy_reask_target()?;
    // Tail gating keys on the firewalled SOURCE's advertised UDP version
    // (oracle UDPReaskForDownload buddy branch: `GetUDPVersion()` of the
    // source client, not ours).
    let datagram = build_reask_callback_udp_packet(
        &KadEd2kHash::from_bytes(buddy_id),
        &source.file_hash,
        our_part_status,
        complete_source_count,
        source.udp_version,
    );
    Some((SocketAddr::new(buddy_ip.into(), buddy_port), datagram))
}

/// Relay an inbound `OP_REASKCALLBACKUDP` to the firewalled client we serve as a
/// buddy, mirroring `ClientUDPSocket.cpp` `OP_REASKCALLBACKUDP`: match the leading
/// buddy-id against the held inbound buddy socket and, on a match, forward an
/// `OP_REASKCALLBACKTCP` frame (requester endpoint + file_hash/tail) down it.
///
/// IPv4-only: a non-V4 requester is dropped (it can never be a client source).
/// The buddy-id match is performed by [`BuddySocketRegistry::relay_to_inbound`],
/// which only delivers when the held inbound buddy socket's id matches — exactly
/// the oracle `md4equ(packet, buddy->GetBuddyID())` guard.
pub(super) fn relay_buddy_reask_callback(
    buddy_registry: &BuddySocketRegistry,
    callback: &super::codec::ReaskCallbackUdp,
    from: SocketAddr,
) {
    let SocketAddr::V4(v4) = from else {
        trace!("ed2k udp reask: dropping OP_REASKCALLBACKUDP from non-IPv4 requester {from}");
        return;
    };
    let frame = encode_reask_callback_tcp_relay(callback, *v4.ip(), v4.port());
    // The registry relays only when the buddy-id matches the held inbound buddy
    // socket (oracle GetBuddyID guard). NodeId and Ed2kHash share the 16-byte
    // wire layout, so the buddy-id field keys the registry directly.
    let buddy_id = NodeId::from_bytes(callback.buddy_id.0);
    if buddy_registry.relay_to_inbound(buddy_id, frame) {
        trace!(
            "ed2k udp reask: relayed OP_REASKCALLBACKTCP to served buddy for requester {from} \
             (file {})",
            callback.file_hash
        );
    } else {
        trace!(
            "ed2k udp reask: OP_REASKCALLBACKUDP from {from} matched no held buddy socket \
             (buddy-id mismatch or no served buddy); dropping"
        );
    }
}

/// Answer a buddy-relayed `OP_REASKCALLBACKTCP` over UDP (source side). Builds the
/// uploader reply from our live upload-queue + shared-catalog state (the same
/// reciprocity reply as an inbound `OP_REASKFILEPING`) and sends it to the
/// downloader's UDP endpoint `dest`, mirroring the oracle `ListenSocket.cpp`
/// `OP_REASKCALLBACKTCP` handler which answers via `clientudp->SendPacket(...,
/// destip, destport, ...)`. A deliberate-silence reciprocity verdict sends nothing.
pub(super) async fn answer_buddy_relayed_reask(
    dht: &DhtNode,
    transfer_runtime: &Ed2kTransferRuntime,
    our_public_ip: [u8; 4],
    dest: SocketAddr,
    file_hash: Ed2kHash,
) {
    // The reciprocity answer only consults our live upload-queue/catalog state
    // keyed on the file hash, so a hash-only ping reproduces the oracle reply.
    let ping = super::codec::ReaskFilePing {
        file_hash,
        part_status: None,
        complete_source_count: None,
    };
    match transfer_runtime
        .reask_reciprocity_reply(&ping, dest, our_public_ip)
        .await
    {
        Some(reply) => {
            if let Err(err) = dht.send_raw_datagram(dest, &reply.bytes).await {
                trace!("ed2k udp reask: buddy-relayed reask answer to {dest} failed: {err}");
            } else {
                super::dump::dump_client_udp_send(dest, &reply);
                trace!(
                    "ed2k udp reask: answered buddy-relayed reask for {file_hash} over UDP to {dest}"
                );
            }
        }
        None => trace!(
            "ed2k udp reask: buddy-relayed reask for {file_hash} from {dest} answered with silence"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_client_udp::codec::ReaskCallbackUdp;

    fn buddy() -> Ed2kHash {
        Ed2kHash::from_bytes([0x11; 16])
    }

    fn file() -> Ed2kHash {
        Ed2kHash::from_bytes([0xAB; 16])
    }

    /// Build a decoded inbound callback whose forwarded tail is `[file_hash]` plus
    /// the given opaque trailer bytes. The buddy relay forwards this tail verbatim
    /// (oracle `ClientUDPSocket.cpp` `memcpy(packet + 16)`), so `extra_tail` stands
    /// in for whatever the relaying downloader appended (any udp-version shape).
    fn callback(extra_tail: &[u8]) -> ReaskCallbackUdp {
        let mut forwarded_tail = file().0.to_vec();
        forwarded_tail.extend_from_slice(extra_tail);
        ReaskCallbackUdp {
            buddy_id: buddy(),
            file_hash: file(),
            forwarded_tail,
        }
    }

    #[test]
    fn relay_frame_strips_buddy_id_and_prepends_requester_endpoint() {
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let port = 4672u16;
        let frame = encode_reask_callback_tcp_relay(&callback(&[0x07, 0x00, 0x05, 0x00]), ip, port);

        // Header: [OP_EMULEPROT][len u32 LE][OP_REASKCALLBACKTCP].
        assert_eq!(frame[0], OP_EMULEPROT);
        assert_eq!(frame[5], OP_REASKCALLBACKTCP);
        let declared_len = u32::from_le_bytes(frame[1..5].try_into().unwrap()) as usize;
        let body = &frame[6..];
        assert_eq!(declared_len, body.len() + 1, "len counts opcode + body");

        // Body: [ip 4 network-order][port u16 LE][file_hash 16][tail].
        assert_eq!(&body[..4], &ip.octets());
        assert_eq!(&body[4..6], &port.to_le_bytes());
        // The buddy-id must NOT appear; the file hash leads the forwarded tail.
        assert_eq!(&body[6..22], &file().0);
        // No buddy-id bytes anywhere in the forwarded body.
        assert!(!body.windows(16).any(|w| w == buddy().0));
    }

    #[test]
    fn relay_body_matches_oracle_layout_for_low_version() {
        // A legacy (udp_version 2) inbound body is two hashes only (no tail), so the
        // relayed body is [ip][port][file_hash] with nothing after the hash.
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let port = 0x1234u16;
        let frame = encode_reask_callback_tcp_relay(&callback(&[]), ip, port);
        let body = &frame[6..];
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // 1.2.3.4 network order
        expected.extend_from_slice(&[0x34, 0x12]); // port LE
        expected.extend_from_slice(&file().0);
        assert_eq!(body, expected.as_slice());
    }

    #[test]
    fn relay_forwards_opaque_tail_verbatim() {
        // The relay never re-parses the post-buddy-id tail: whatever bytes followed
        // the file hash inbound (here a deliberately non-conforming, short trailer)
        // must appear byte-identical after the relayed [ip][port][file_hash] prefix.
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let port = 4672u16;
        let opaque = [0xDE, 0xAD, 0xBE];
        let frame = encode_reask_callback_tcp_relay(&callback(&opaque), ip, port);
        let body = &frame[6..];
        assert_eq!(&body[..4], &ip.octets());
        assert_eq!(&body[4..6], &port.to_le_bytes());
        assert_eq!(&body[6..22], &file().0);
        assert_eq!(&body[22..], &opaque, "opaque tail forwarded verbatim");
    }

    #[test]
    fn relay_forwards_callback_to_matching_held_buddy_socket() {
        // We are the source's buddy: an OP_REASKCALLBACKUDP whose leading buddy-id
        // matches our held inbound buddy socket is relayed as OP_REASKCALLBACKTCP
        // down that socket; a mismatching buddy-id is dropped.
        use tokio::sync::mpsc;
        let registry = BuddySocketRegistry::new();
        let served_buddy_id = NodeId::from_bytes([0x11; 16]);
        let (tx, mut relay_rx) = mpsc::unbounded_channel();
        assert!(registry.attach_inbound(served_buddy_id, tx));

        let requester: SocketAddr = "198.51.100.7:4672".parse().unwrap();
        // Matching buddy-id (== buddy()) -> relayed.
        relay_buddy_reask_callback(&registry, &callback(&[0x03, 0x00]), requester);
        let frame = relay_rx
            .try_recv()
            .expect("a relayed OP_REASKCALLBACKTCP frame");
        assert_eq!(frame[0], OP_EMULEPROT);
        assert_eq!(frame[5], OP_REASKCALLBACKTCP);
        let body = &frame[6..];
        assert_eq!(u16::from_le_bytes(body[4..6].try_into().unwrap()), 4672);
        assert_eq!(&body[6..22], &file().0);

        // Mismatching buddy-id -> nothing relayed.
        let mut mismatch = callback(&[]);
        mismatch.buddy_id = Ed2kHash::from_bytes([0x99; 16]);
        relay_buddy_reask_callback(&registry, &mismatch, requester);
        assert!(
            relay_rx.try_recv().is_err(),
            "mismatched buddy-id must not relay"
        );
    }

    #[test]
    fn relay_drops_non_ipv4_requester() {
        use tokio::sync::mpsc;
        let registry = BuddySocketRegistry::new();
        let (tx, mut relay_rx) = mpsc::unbounded_channel();
        assert!(registry.attach_inbound(NodeId::from_bytes([0x11; 16]), tx));
        let v6: SocketAddr = "[2001:db8::1]:4672".parse().unwrap();
        relay_buddy_reask_callback(&registry, &callback(&[]), v6);
        assert!(
            relay_rx.try_recv().is_err(),
            "non-IPv4 requester must be dropped"
        );
    }

    #[test]
    fn relayed_body_decodes_through_the_source_side_decoder() {
        // The relayed OP_REASKCALLBACKTCP body must parse with the source-side
        // decoder (ed2k_tcp::codec::decode_reask_callback_tcp_payload): it reads
        // [dest_ip u32][dest_port u16][file_hash 16][tail].
        let ip = Ipv4Addr::new(198, 51, 100, 9);
        let port = 5000u16;
        let frame = encode_reask_callback_tcp_relay(&callback(&[0x02, 0x00]), ip, port);
        let body = &frame[6..];
        // Manually mirror the source-side decode of the leading fixed fields
        // (dest IP is natural network order).
        let dest_ip = Ipv4Addr::from(<[u8; 4]>::try_from(&body[..4]).unwrap());
        let dest_port = u16::from_le_bytes(body[4..6].try_into().unwrap());
        let file_hash = Ed2kHash(body[6..22].try_into().unwrap());
        assert_eq!(dest_ip, ip);
        assert_eq!(dest_port, port);
        assert_eq!(file_hash, file());
    }
}
