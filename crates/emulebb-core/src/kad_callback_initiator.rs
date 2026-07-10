//! Initiator role for the Kad LowID buddy callback (`KADEMLIA_CALLBACK_REQ`,
//! opcode `0x52`).
//!
//! When a wanted download source is a firewalled LowID Kad peer reachable only
//! through its Kad buddy (oracle source types 3/5) and that buddy's UDP relay
//! endpoint is known, we cannot dial the source directly. Instead we send a
//! `KADEMLIA_CALLBACK_REQ` to the buddy, which relays an `OP_CALLBACK` down its
//! held TCP link to the firewalled source; the source then TCP-connects back to
//! us so the download can start. This is the outbound counterpart to the relay
//! role rust already has ([`crate::handle_kad_callback_req`]) and to the
//! firewalled-self buddy-acquisition path.
//!
//! Oracle references (wire parity is LOCKED — do not change the byte layout):
//! - `srchybrid/BaseClient.cpp` `CUpDownClient::TryToConnect` `CCS_KADCALLBACK`
//!   branch (lines ~1517-1531): the direct callback taken when
//!   `GetBuddyIP()`/`GetBuddyPort()` are known. It serializes
//!   `WriteUInt128(GetBuddyID())` + `WriteUInt128(m_reqfile->GetFileHash())` +
//!   `WriteUInt16(thePrefs.GetPort())` and sends `KADEMLIA_CALLBACK_REQ`
//!   unencrypted to the buddy, then enters `DS_WAITCALLBACKKAD`.
//! - `srchybrid/kademlia/net/KademliaUDPListener.cpp`
//!   `Process_KADEMLIA_CALLBACK_REQ`: the buddy relay side (already mirrored in
//!   rust) that reads the same `[uCheck u128][uFile u128][uTCP u16]` body.
//! - `srchybrid/kademlia/net/PacketTracking.cpp`: `KADEMLIA_CALLBACK_REQ` is
//!   rate-limited to one per minute per IP (`InTrackListIsAllowedPacket`
//!   `token = MIN2MS(1) / 1`); the sender additionally never re-issues while a
//!   source sits in `DS_WAITCALLBACKKAD` (reaped at `SEC2MS(45)`).
//!
//! When the buddy endpoint is unknown, the same request is sent through the
//! bounded `CSearch::FINDSOURCE`-shaped Kad traversal.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use emulebb_ed2k::{
    ed2k_server::Ed2kFoundSource,
    ed2k_transfer::{Ed2kCallbackIntent, Ed2kSourceHint},
};
use emulebb_kad_dht::RpcWorkClass;
use emulebb_kad_proto::{CallbackReq, Ed2kHash, KadPacket, NodeId};

use super::{Ed2kNetworkConfig, EmulebbCore, Transfer};

/// How long we suppress a repeat `KADEMLIA_CALLBACK_REQ` for the same
/// (source, file). This mirrors the oracle's `DS_WAITCALLBACKKAD` reap window
/// (`ClientList.cpp` `SEC2MS(45)`): once a callback is sent, the source has that
/// long to connect back, so re-issuing sooner would only duplicate the request
/// (and, on the receiving buddy, be dropped by its `KADEMLIA_CALLBACK_REQ`
/// one-per-minute flood token). We take the 45s callback wait as the floor.
///
/// WHY: without this cooldown, every download requery round (seconds apart) would
/// re-send a callback for the same buddy-only source, which the buddy's flood
/// tracker would start dropping and which never speeds up the connect-back.
pub(crate) const KAD_CALLBACK_INITIATOR_COOLDOWN: Duration = Duration::from_secs(45);

/// Dedup/rate-limit key for an outbound Kad callback: the firewalled source's own
/// eD2k endpoint plus the file we want. Keyed on the source (not the buddy) so two
/// different files served by the same firewalled peer each get their own callback,
/// matching the oracle per-`CUpDownClient`/per-`m_reqfile` wait state.
pub(crate) type KadCallbackKey = (Ipv4Addr, u16, Ed2kHash);

/// The dedup/rate-limit key for a source+file, or `None` when the source is not a
/// direct-callback candidate (not a firewalled buddy source, or the buddy relay
/// endpoint / port is unusable).
pub(crate) fn kad_callback_key(
    source: &Ed2kFoundSource,
    file_hash: Ed2kHash,
) -> Option<KadCallbackKey> {
    if !is_kad_callback_candidate(source) {
        return None;
    }
    Some((source.ip, source.tcp_port, file_hash))
}

/// Whether the source has the identity required for either direct callback or
/// the FINDSOURCE fallback.
#[must_use]
pub(crate) fn is_kad_callback_candidate(source: &Ed2kFoundSource) -> bool {
    source.low_id && source.buddy_id.is_some()
}

/// Whether `source` can be reached with a *direct* Kad callback right now: it is a
/// firewalled LowID buddy source (types 3/5) whose buddy id AND buddy relay
/// endpoint (with a non-zero port) are known. Mirrors the oracle
/// `BaseClient.cpp` precondition `HasValidBuddyID() && GetBuddyIP() && GetBuddyPort()`.
#[must_use]
pub(crate) fn is_direct_kad_callback_candidate(source: &Ed2kFoundSource) -> bool {
    source.has_kad_buddy_reask_target()
        && matches!(source.buddy_endpoint, Some((_, port)) if port != 0)
}

/// Whether a callback may be sent given the last time one was sent for this key.
/// `None` (never sent) always allows; otherwise the cooldown must have elapsed.
#[must_use]
pub(crate) fn should_send_kad_callback(
    last_sent: Option<Instant>,
    now: Instant,
    cooldown: Duration,
) -> bool {
    match last_sent {
        None => true,
        Some(sent_at) => now.duration_since(sent_at) >= cooldown,
    }
}

/// Build the `KADEMLIA_CALLBACK_REQ` (`0x52`) body for the direct callback,
/// byte-identical to oracle `BaseClient.cpp` `CCS_KADCALLBACK`:
/// `[buddy_id u128][file_hash u128][our_tcp_port u16]`.
///
/// - `buddy_id` is the firewalled source's published buddy id (`FT_BUDDYHASH`,
///   the ID it used to find its buddy). The oracle writes it via
///   `WriteUInt128(GetBuddyID())`, which serializes the `CUInt128`'s raw storage
///   (populated by `md4cpy` from the hex string), i.e. the exact `FT_BUDDYHASH`
///   bytes. So we pass the 16 buddy bytes straight into `NodeId`.
/// - `file_hash` is written by the oracle as `WriteUInt128(CUInt128(GetFileHash()))`.
///   The `CUInt128(const byte*)` constructor is `SetValueBE`, which byte-reverses
///   each 32-bit chunk of the big-endian MD4, so the value on the wire is the
///   file's Kad-identity form — exactly `NodeId::from_be_bytes(md4)`. The
///   firewalled receiver runs `ToByteArray` (`ListenSocket.cpp` `OP_CALLBACK`) to
///   invert it back to the raw MD4 before `GetFileByID`. We therefore convert the
///   raw MD4 to its Kad-identity layout here so the packet matches stock eMule.
/// - `tcp_port` is our advertised external eD2k TCP port (the address the source
///   connects back to). The oracle uses `thePrefs.GetPort()`; behind NAT/UPnP the
///   externally reachable port is what the source must dial, so we pass the
///   advertised port.
#[must_use]
pub(crate) fn build_kad_callback_req(
    buddy_id: [u8; 16],
    file_hash: Ed2kHash,
    our_tcp_port: u16,
) -> CallbackReq {
    // Raw MD4 -> Kad-identity (per-chunk big-endian) layout, matching the oracle
    // CUInt128(GetFileHash()) SetValueBE serialization on the wire.
    let kad_file_id = NodeId::from_be_bytes(file_hash.0);
    CallbackReq {
        buddy_id: NodeId::from_bytes(buddy_id),
        file_hash: Ed2kHash::from_bytes(kad_file_id.0),
        tcp_port: our_tcp_port,
    }
}

impl EmulebbCore {
    /// Originate direct or FINDSOURCE-assisted Kad callbacks for LowID sources.
    pub(super) async fn send_kad_buddy_callbacks(
        &self,
        network: &Ed2kNetworkConfig,
        transfer: &Transfer,
        file_hash: Ed2kHash,
        sources: &[Ed2kFoundSource],
    ) {
        if !sources.iter().any(is_kad_callback_candidate) || self.ed2k_self_tcp_firewalled().await {
            return;
        }
        let Some(dht) = self
            .ed2k_dht_node()
            .await
            .filter(|dht| dht.is_bootstrapped())
        else {
            return;
        };
        let our_tcp_port = self
            .ed2k_reachability
            .advertised_tcp_port(network.listen_port);
        for source in sources.iter().filter(|s| is_kad_callback_candidate(s)) {
            let Some(buddy_id) = source.buddy_id else {
                continue;
            };
            let Some(key) = kad_callback_key(source, file_hash) else {
                continue;
            };
            let now = Instant::now();
            {
                let mut state = self.state.lock().await;
                if !should_send_kad_callback(
                    state.ed2k_kad_callback_last_sent.get(&key).copied(),
                    now,
                    KAD_CALLBACK_INITIATOR_COOLDOWN,
                ) {
                    continue;
                }
                state.ed2k_kad_callback_last_sent.insert(key, now);
            }
            self.ed2k_transfers
                .register_callback_intent(Ed2kCallbackIntent {
                    client_id: source.client_id,
                    file_hash: transfer.hash.clone(),
                    canonical_name: transfer.name.clone(),
                    file_size: transfer.size_bytes,
                    source: Ed2kSourceHint {
                        ip: source.ip.to_string(),
                        tcp_port: source.tcp_port,
                        user_hash: source.user_hash.map(hex::encode),
                    },
                })
                .await;
            let source_peer = SocketAddr::new(IpAddr::V4(source.ip), source.tcp_port);
            let request = build_kad_callback_req(buddy_id, file_hash, our_tcp_port);
            if !is_direct_kad_callback_candidate(source) {
                let dht = dht.clone();
                let transfer_hash = transfer.hash.clone();
                let buddy_id_hex = hex::encode(buddy_id);
                tokio::spawn(async move {
                    tracing::info!(
                        "starting Kad FINDSOURCE callback walk file_hash={transfer_hash} source={source_peer} buddy_id={buddy_id_hex}"
                    );
                    dht.find_source_search(request, RpcWorkClass::Interactive)
                        .await;
                });
                continue;
            }
            let Some((buddy_ip, buddy_port)) = source.buddy_endpoint else {
                continue;
            };
            let buddy_peer = SocketAddr::new(IpAddr::V4(buddy_ip), buddy_port);
            let outcome = dht
                .send_packet(buddy_peer, &KadPacket::CallbackReq(request))
                .await;
            let milestone = if outcome.is_ok() {
                "sent"
            } else {
                "send_failed"
            };
            crate::diag_kad_event::callback(milestone, buddy_peer, source_peer, &transfer.hash);
            match outcome {
                Ok(()) => tracing::info!(
                    "sent Kad KADEMLIA_CALLBACK_REQ file_hash={} source={source_peer} buddy={buddy_peer} our_tcp_port={our_tcp_port}",
                    transfer.hash
                ),
                Err(error) => tracing::warn!(
                    "Kad KADEMLIA_CALLBACK_REQ send failed file_hash={} source={source_peer} buddy={buddy_peer}: {error}",
                    transfer.hash
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulebb_kad_proto::KadPacket;
    use std::net::Ipv4Addr;

    fn buddy_source(file_hash: Ed2kHash) -> Ed2kFoundSource {
        Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::new(192, 0, 2, 77),
            tcp_port: 4662,
            client_id: u32::from(Ipv4Addr::new(192, 0, 2, 77)),
            low_id: true,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
            buddy_id: Some([0x5a; 16]),
            buddy_endpoint: Some((Ipv4Addr::new(198, 51, 100, 9), 5000)),
            source_udp_port: Some(4672),
        }
    }

    #[test]
    fn candidate_requires_buddy_id_endpoint_and_nonzero_port() {
        let file_hash = Ed2kHash::from_bytes([0x4b; 16]);
        let source = buddy_source(file_hash);
        assert!(is_direct_kad_callback_candidate(&source));
        assert_eq!(
            kad_callback_key(&source, file_hash),
            Some((Ipv4Addr::new(192, 0, 2, 77), 4662, file_hash))
        );

        // A zero buddy port is not dialable.
        let mut zero_port = buddy_source(file_hash);
        zero_port.buddy_endpoint = Some((Ipv4Addr::new(198, 51, 100, 9), 0));
        assert!(!is_direct_kad_callback_candidate(&zero_port));
        assert_eq!(
            kad_callback_key(&zero_port, file_hash),
            Some((Ipv4Addr::new(192, 0, 2, 77), 4662, file_hash))
        );

        let mut unknown_endpoint = buddy_source(file_hash);
        unknown_endpoint.buddy_endpoint = None;
        assert!(is_kad_callback_candidate(&unknown_endpoint));
        assert!(!is_direct_kad_callback_candidate(&unknown_endpoint));
        assert!(kad_callback_key(&unknown_endpoint, file_hash).is_some());

        // A HighID (direct-dialable) source is never a callback candidate.
        let mut high_id = buddy_source(file_hash);
        high_id.low_id = false;
        high_id.buddy_id = None;
        high_id.buddy_endpoint = None;
        assert!(!is_direct_kad_callback_candidate(&high_id));
    }

    #[test]
    fn cooldown_gate_allows_first_send_then_suppresses_within_window() {
        let now = Instant::now();
        // Never sent -> always allowed.
        assert!(should_send_kad_callback(
            None,
            now,
            KAD_CALLBACK_INITIATOR_COOLDOWN
        ));
        // Just sent -> suppressed until the cooldown elapses.
        assert!(!should_send_kad_callback(
            Some(now),
            now,
            KAD_CALLBACK_INITIATOR_COOLDOWN
        ));
        assert!(!should_send_kad_callback(
            Some(now),
            now + Duration::from_secs(44),
            KAD_CALLBACK_INITIATOR_COOLDOWN
        ));
        // At/after the cooldown -> allowed again.
        assert!(should_send_kad_callback(
            Some(now),
            now + KAD_CALLBACK_INITIATOR_COOLDOWN,
            KAD_CALLBACK_INITIATOR_COOLDOWN
        ));
    }

    #[test]
    fn callback_req_round_trips_through_the_relay_side_decoder() {
        // Serialize in the initiator, parse with the existing relay-side decoder
        // (KadPacket::decode / CallbackReq) — the two must agree field-for-field.
        let buddy_id = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let file_hash = Ed2kHash::from_bytes([
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0x01,
        ]);
        let req = build_kad_callback_req(buddy_id, file_hash, 4662);

        let frame = KadPacket::CallbackReq(req.clone()).encode().unwrap();
        let decoded = KadPacket::decode(&frame).unwrap();
        match decoded {
            KadPacket::CallbackReq(back) => assert_eq!(back, req),
            other => panic!("expected CallbackReq, got {other:?}"),
        }
    }

    #[test]
    fn callback_req_byte_layout_matches_stock_serializer() {
        // Oracle BaseClient.cpp CCS_KADCALLBACK:
        //   WriteUInt128(GetBuddyID());                 // raw FT_BUDDYHASH bytes
        //   WriteUInt128(CUInt128(GetFileHash()));       // SetValueBE per-chunk swap
        //   WriteUInt16(thePrefs.GetPort());             // little-endian
        let buddy_id = [
            0xA1, 0xA2, 0xA3, 0xA4, 0xB1, 0xB2, 0xB3, 0xB4, 0xC1, 0xC2, 0xC3, 0xC4, 0xD1, 0xD2,
            0xD3, 0xD4,
        ];
        // Raw MD4 as parsed from a hash hex string, chunk boundaries every 4 bytes.
        let file_hash = Ed2kHash::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]);
        let req = build_kad_callback_req(buddy_id, file_hash, 0x1234);
        let frame = KadPacket::CallbackReq(req).encode().unwrap();
        // Header: [OP_KADEMLIAHEADER][opcode 0x52], then the 34-byte body.
        assert_eq!(frame[1], 0x52, "opcode KADEMLIA_CALLBACK_REQ");
        let body = &frame[2..];

        let mut expected = Vec::new();
        // buddy_id: raw bytes, unchanged.
        expected.extend_from_slice(&buddy_id);
        // file_hash: each 4-byte chunk reversed (SetValueBE / from_be_bytes).
        expected.extend_from_slice(&[
            0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x0C, 0x0B, 0x0A, 0x09, 0x10, 0x0F,
            0x0E, 0x0D,
        ]);
        // tcp_port 0x1234 little-endian.
        expected.extend_from_slice(&[0x34, 0x12]);

        assert_eq!(body, expected.as_slice());
        assert_eq!(body.len(), 34);
    }
}
