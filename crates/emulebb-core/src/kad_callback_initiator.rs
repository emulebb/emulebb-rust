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

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use emulebb_ed2k::{
    ed2k_server::Ed2kFoundSource,
    ed2k_transfer::{
        Ed2kCallbackDispatchGuard, Ed2kCallbackDownload, Ed2kCallbackReservation,
        Ed2kCallbackTicketRequest, Ed2kSourceHint,
    },
};
use emulebb_kad_dht::{DhtNode, KadCallbackSearchDispatchOutcome, RpcWorkClass};
use emulebb_kad_proto::{CallbackReq, Ed2kHash, KadPacket, NodeId};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::{Ed2kNetworkConfig, EmulebbCore, Transfer};

/// How long we suppress a repeat `KADEMLIA_CALLBACK_REQ` for the same peer and
/// callback route. This mirrors the oracle's `DS_WAITCALLBACKKAD` reap window
/// (`ClientList.cpp` `SEC2MS(45)`): once a callback is sent, the source has that
/// long to connect back, so re-issuing sooner would only duplicate the request
/// (and, on the receiving buddy, be dropped by its `KADEMLIA_CALLBACK_REQ`
/// one-per-minute flood token). We take the 45s callback wait as the floor.
///
/// WHY: without this cooldown, every download requery round (seconds apart) would
/// re-send a callback for the same buddy-only source, which the buddy's flood
/// tracker would start dropping and which never speeds up the connect-back.
pub(crate) const KAD_CALLBACK_INITIATOR_COOLDOWN: Duration = Duration::from_secs(45);

/// Peer/route identity of one Kad callback wait. One inbound callback TCP
/// session can negotiate every A4AF file for the same remote peer, so file
/// identity is deliberately absent. The optional endpoint remains part of the
/// route: a FINDSOURCE ticket must not suppress a later direct buddy request
/// which cannot join that ticket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct KadCallbackKey {
    buddy_id: [u8; 16],
    buddy_endpoint: Option<SocketAddr>,
    user_hash: [u8; 16],
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct KadCallbackCooldownPermit {
    key: KadCallbackKey,
    claimed_at: Instant,
}

/// Normalize a published buddy endpoint into the exact direct callback route.
/// Zero-port and unspecified addresses are not dialable and therefore use the
/// FINDSOURCE route (`None`).
#[must_use]
fn normalized_buddy_endpoint(source: &Ed2kFoundSource) -> Option<SocketAddr> {
    source
        .buddy_endpoint
        .filter(|(ip, port)| !ip.is_unspecified() && *port != 0)
        .map(|(ip, port)| SocketAddr::new(IpAddr::V4(ip), port))
}

/// The cooldown key for a callback-capable source with a usable peer identity.
pub(crate) fn kad_callback_key(source: &Ed2kFoundSource) -> Option<KadCallbackKey> {
    if !is_kad_callback_candidate(source) {
        return None;
    }
    Some(KadCallbackKey {
        buddy_id: source.buddy_id?,
        buddy_endpoint: normalized_buddy_endpoint(source),
        user_hash: source.user_hash?,
    })
}

/// Whether the source has the identity required for either direct callback or
/// the FINDSOURCE fallback.
#[must_use]
pub(crate) fn is_kad_callback_candidate(source: &Ed2kFoundSource) -> bool {
    source.low_id && source.buddy_id.is_some()
}

pub(crate) fn claim_kad_callback_request(
    last_sent: &mut HashMap<KadCallbackKey, Instant>,
    key: KadCallbackKey,
    now: Instant,
) -> Option<KadCallbackCooldownPermit> {
    last_sent.retain(|_, sent_at| {
        now.saturating_duration_since(*sent_at) < KAD_CALLBACK_INITIATOR_COOLDOWN
    });
    if last_sent.get(&key).is_some_and(|sent_at| {
        now.saturating_duration_since(*sent_at) < KAD_CALLBACK_INITIATOR_COOLDOWN
    }) {
        return None;
    }
    last_sent.insert(key.clone(), now);
    Some(KadCallbackCooldownPermit {
        key,
        claimed_at: now,
    })
}

/// Roll back only the exact provisional cooldown whose callback request is
/// proven not to have reached the local UDP socket.
pub(crate) fn cancel_kad_callback_request(
    last_sent: &mut HashMap<KadCallbackKey, Instant>,
    permit: KadCallbackCooldownPermit,
) -> bool {
    if last_sent.get(&permit.key) != Some(&permit.claimed_at) {
        return false;
    }
    last_sent.remove(&permit.key);
    true
}

/// Start the callback wait at successful or ambiguous dispatch settlement,
/// without allowing a stale settlement to refresh a newer claim.
pub(crate) fn commit_kad_callback_request(
    last_sent: &mut HashMap<KadCallbackKey, Instant>,
    permit: KadCallbackCooldownPermit,
    now: Instant,
) -> bool {
    if last_sent.get(&permit.key) != Some(&permit.claimed_at) {
        return false;
    }
    last_sent.insert(permit.key, now);
    true
}

enum KadCallbackDispatch {
    Sent { request_count: usize },
    KnownNotSent(String),
    DeliveryUnknown(String),
}

struct KadCallbackDispatchContext {
    guard: Ed2kCallbackDispatchGuard,
    cooldown: KadCallbackCooldownPermit,
    source_peer: SocketAddr,
    buddy_peer: Option<SocketAddr>,
    transfer_hash: String,
    our_tcp_port: u16,
}

async fn send_direct_kad_callback(
    dht: &DhtNode,
    buddy_peer: SocketAddr,
    request: CallbackReq,
    deadline: Instant,
    cancel: &CancellationToken,
) -> KadCallbackDispatch {
    if cancel.is_cancelled() {
        return KadCallbackDispatch::KnownNotSent(
            "Kad callback cancelled before direct dispatch".to_string(),
        );
    }
    if Instant::now() >= deadline {
        return KadCallbackDispatch::KnownNotSent(
            "Kad callback ticket expired before direct dispatch".to_string(),
        );
    }

    let packet = KadPacket::CallbackReq(request);
    let send = dht.send_packet(buddy_peer, &packet);
    tokio::pin!(send);
    tokio::select! {
        biased;
        outcome = &mut send => match outcome {
            Ok(()) => KadCallbackDispatch::Sent { request_count: 1 },
            Err(error) => KadCallbackDispatch::KnownNotSent(error.to_string()),
        },
        () = cancel.cancelled() => KadCallbackDispatch::DeliveryUnknown(
            "Kad callback cancelled after direct dispatch began".to_string(),
        ),
        () = tokio::time::sleep_until(deadline.into()) => KadCallbackDispatch::DeliveryUnknown(
            "Kad callback deadline elapsed after direct dispatch began".to_string(),
        ),
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
    async fn settle_kad_callback_dispatch(
        &self,
        context: KadCallbackDispatchContext,
        dispatch: KadCallbackDispatch,
    ) {
        let KadCallbackDispatchContext {
            guard,
            cooldown,
            source_peer,
            buddy_peer,
            transfer_hash,
            our_tcp_port,
        } = context;
        match dispatch {
            KadCallbackDispatch::Sent { request_count } => {
                let ticket_outcome = guard.mark_dispatched();
                let cooldown_committed = {
                    let mut state = self.state.lock().await;
                    commit_kad_callback_request(
                        &mut state.ed2k_kad_callback_last_sent,
                        cooldown,
                        Instant::now(),
                    )
                };
                crate::diag_kad_event::callback("sent", buddy_peer, source_peer, &transfer_hash);
                tracing::debug!(
                    "sent Kad KADEMLIA_CALLBACK_REQ file_hash={transfer_hash} source={source_peer} buddy={} request_count={request_count} our_tcp_port={our_tcp_port} ticket_outcome={ticket_outcome:?} cooldown_committed={cooldown_committed}",
                    buddy_peer.map_or_else(|| "FINDSOURCE".to_string(), |peer| peer.to_string()),
                );
            }
            KadCallbackDispatch::KnownNotSent(reason) => {
                let ticket_cancelled = guard.cancel();
                let cooldown_cancelled = {
                    let mut state = self.state.lock().await;
                    cancel_kad_callback_request(&mut state.ed2k_kad_callback_last_sent, cooldown)
                };
                crate::diag_kad_event::callback(
                    "send_failed",
                    buddy_peer,
                    source_peer,
                    &transfer_hash,
                );
                tracing::warn!(
                    "Kad KADEMLIA_CALLBACK_REQ not sent file_hash={transfer_hash} source={source_peer} buddy={} ticket_cancelled={ticket_cancelled} cooldown_cancelled={cooldown_cancelled}: {reason}",
                    buddy_peer.map_or_else(|| "FINDSOURCE".to_string(), |peer| peer.to_string()),
                );
            }
            KadCallbackDispatch::DeliveryUnknown(reason) => {
                let ticket_outcome = guard.mark_dispatched();
                let cooldown_committed = {
                    let mut state = self.state.lock().await;
                    commit_kad_callback_request(
                        &mut state.ed2k_kad_callback_last_sent,
                        cooldown,
                        Instant::now(),
                    )
                };
                crate::diag_kad_event::callback(
                    "delivery_unknown",
                    buddy_peer,
                    source_peer,
                    &transfer_hash,
                );
                tracing::warn!(
                    "Kad KADEMLIA_CALLBACK_REQ delivery unknown file_hash={transfer_hash} source={source_peer} buddy={} ticket_outcome={ticket_outcome:?} cooldown_committed={cooldown_committed}: {reason}",
                    buddy_peer.map_or_else(|| "FINDSOURCE".to_string(), |peer| peer.to_string()),
                );
            }
        }
    }

    /// Originate direct or FINDSOURCE-assisted Kad callbacks for LowID sources.
    pub(super) async fn send_kad_buddy_callbacks(
        &self,
        network: &Ed2kNetworkConfig,
        transfer: &Transfer,
        sources: &[Ed2kFoundSource],
        callback_window: Duration,
        cancel: &CancellationToken,
        findsource_tasks: &mut JoinSet<()>,
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
        let file_hash = match transfer.hash.parse::<Ed2kHash>() {
            Ok(hash) => hash,
            Err(error) => {
                tracing::warn!(
                    "Kad callback skipped for invalid file hash {}: {error}",
                    transfer.hash,
                );
                return;
            }
        };
        let our_tcp_port = self
            .ed2k_reachability
            .advertised_tcp_port(network.listen_port);
        for source in sources.iter().filter(|s| is_kad_callback_candidate(s)) {
            if cancel.is_cancelled() {
                break;
            }
            let Some(buddy_id) = source.buddy_id else {
                continue;
            };
            let Some(source_user_hash) = source.user_hash else {
                tracing::warn!(
                    "Kad callback source lacks a user hash file_hash={} source={}:{}",
                    transfer.hash,
                    source.ip,
                    source.tcp_port,
                );
                continue;
            };
            let buddy_endpoint = normalized_buddy_endpoint(source);
            let source_peer = SocketAddr::new(IpAddr::V4(source.ip), source.tcp_port);
            let callback_download = Ed2kCallbackDownload {
                file_hash,
                display_name: transfer.name.clone(),
                file_size: transfer.size_bytes,
                source: Ed2kSourceHint {
                    ip: source.ip.to_string(),
                    tcp_port: source.tcp_port,
                    user_hash: Some(hex::encode(source_user_hash)),
                    connect_options: source.obfuscation_options,
                    file_comment: String::new(),
                    file_rating: 0,
                },
            };
            let callback_ticket = match Ed2kCallbackTicketRequest::kad_buddy(
                buddy_id,
                buddy_endpoint,
                source.client_id,
                source_user_hash,
                source.ip,
                source.tcp_port,
                callback_download,
                callback_window,
            ) {
                Ok(ticket) => ticket,
                Err(error) => {
                    tracing::warn!(
                        "Kad callback ticket rejected file_hash={} source={source_peer} buddy={}: {error}",
                        transfer.hash,
                        buddy_endpoint
                            .map_or_else(|| "FINDSOURCE".to_string(), |peer| peer.to_string()),
                    );
                    continue;
                }
            };
            let callback_dispatch_permit = match self
                .ed2k_transfers
                .reserve_callback_ticket(callback_ticket)
                .await
            {
                Ok(Ed2kCallbackReservation::Dispatch(permit)) => permit,
                Ok(Ed2kCallbackReservation::Joined { .. }) => {
                    tracing::debug!(
                        "Kad callback joined pending peer session file_hash={} source={source_peer} buddy={}",
                        transfer.hash,
                        buddy_endpoint
                            .map_or_else(|| "FINDSOURCE".to_string(), |peer| peer.to_string()),
                    );
                    continue;
                }
                Err(error) => {
                    tracing::warn!(
                        "Kad callback reservation failed file_hash={} source={source_peer}: {error}",
                        transfer.hash,
                    );
                    continue;
                }
            };
            let key = kad_callback_key(source)
                .expect("validated Kad callback ticket has a cooldown identity");
            let callback_cooldown_permit = {
                let mut state = self.state.lock().await;
                claim_kad_callback_request(
                    &mut state.ed2k_kad_callback_last_sent,
                    key,
                    Instant::now(),
                )
            };
            let Some(callback_cooldown_permit) = callback_cooldown_permit else {
                let _ = self
                    .ed2k_transfers
                    .cancel_callback_ticket(callback_dispatch_permit)
                    .await;
                tracing::debug!(
                    "Kad callback suppressed by cooldown file_hash={} source={source_peer} buddy={}",
                    transfer.hash,
                    buddy_endpoint
                        .map_or_else(|| "FINDSOURCE".to_string(), |peer| peer.to_string()),
                );
                continue;
            };
            let Some(callback_dispatch_guard) = self
                .ed2k_transfers
                .begin_callback_ticket_dispatch(callback_dispatch_permit)
            else {
                let cooldown_cancelled = {
                    let mut state = self.state.lock().await;
                    cancel_kad_callback_request(
                        &mut state.ed2k_kad_callback_last_sent,
                        callback_cooldown_permit,
                    )
                };
                tracing::debug!(
                    "Kad callback settled before dispatch file_hash={} source={source_peer} cooldown_cancelled={cooldown_cancelled}",
                    transfer.hash,
                );
                continue;
            };
            let callback_deadline = callback_dispatch_guard.expires_at();
            let request = build_kad_callback_req(buddy_id, file_hash, our_tcp_port);
            let context = KadCallbackDispatchContext {
                guard: callback_dispatch_guard,
                cooldown: callback_cooldown_permit,
                source_peer,
                buddy_peer: buddy_endpoint,
                transfer_hash: transfer.hash.clone(),
                our_tcp_port,
            };
            let Some(buddy_peer) = buddy_endpoint else {
                let core = self.clone();
                let dht = dht.clone();
                let cancel = cancel.clone();
                let buddy_id_hex = hex::encode(buddy_id);
                findsource_tasks.spawn(async move {
                    tracing::debug!(
                        "starting Kad FINDSOURCE callback walk file_hash={} source={source_peer} buddy_id={buddy_id_hex}",
                        context.transfer_hash,
                    );
                    let dispatch = match dht
                        .find_source_search_until(
                            request,
                            RpcWorkClass::Interactive,
                            callback_deadline,
                            &cancel,
                        )
                        .await
                    {
                        KadCallbackSearchDispatchOutcome::Dispatched { request_count } => {
                            KadCallbackDispatch::Sent { request_count }
                        }
                        KadCallbackSearchDispatchOutcome::NotDispatched { reason } => {
                            KadCallbackDispatch::KnownNotSent(format!(
                                "Kad FINDSOURCE callback not dispatched: {reason:?}"
                            ))
                        }
                    };
                    core.settle_kad_callback_dispatch(context, dispatch).await;
                });
                continue;
            };
            let dispatch =
                send_direct_kad_callback(&dht, buddy_peer, request, callback_deadline, cancel)
                    .await;
            self.settle_kad_callback_dispatch(context, dispatch).await;
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
            user_hash: Some([0x6b; 16]),
            source_server: None,
            buddy_id: Some([0x5a; 16]),
            buddy_endpoint: Some((Ipv4Addr::new(198, 51, 100, 9), 5000)),
            source_udp_port: Some(4672),
        }
    }

    #[test]
    fn candidate_normalizes_direct_and_findsource_routes() {
        let file_hash = Ed2kHash::from_bytes([0x4b; 16]);
        let source = buddy_source(file_hash);
        assert!(normalized_buddy_endpoint(&source).is_some());
        assert_eq!(
            kad_callback_key(&source),
            Some(KadCallbackKey {
                buddy_id: [0x5a; 16],
                buddy_endpoint: Some("198.51.100.9:5000".parse().unwrap()),
                user_hash: [0x6b; 16],
            })
        );

        // An unusable buddy endpoint falls back to route discovery rather than
        // being treated as a direct datagram destination.
        let mut zero_port = buddy_source(file_hash);
        zero_port.buddy_endpoint = Some((Ipv4Addr::new(198, 51, 100, 9), 0));
        assert_eq!(normalized_buddy_endpoint(&zero_port), None);
        assert_eq!(
            kad_callback_key(&zero_port),
            Some(KadCallbackKey {
                buddy_id: [0x5a; 16],
                buddy_endpoint: None,
                user_hash: [0x6b; 16],
            })
        );

        let mut unspecified_ip = buddy_source(file_hash);
        unspecified_ip.buddy_endpoint = Some((Ipv4Addr::UNSPECIFIED, 5000));
        assert_eq!(normalized_buddy_endpoint(&unspecified_ip), None);

        let mut unknown_endpoint = buddy_source(file_hash);
        unknown_endpoint.buddy_endpoint = None;
        assert!(is_kad_callback_candidate(&unknown_endpoint));
        assert_eq!(normalized_buddy_endpoint(&unknown_endpoint), None);
        assert!(kad_callback_key(&unknown_endpoint).is_some());

        let mut missing_user_hash = buddy_source(file_hash);
        missing_user_hash.user_hash = None;
        assert!(is_kad_callback_candidate(&missing_user_hash));
        assert!(kad_callback_key(&missing_user_hash).is_none());

        // A HighID (direct-dialable) source is never a callback candidate.
        let mut high_id = buddy_source(file_hash);
        high_id.low_id = false;
        high_id.buddy_id = None;
        high_id.buddy_endpoint = None;
        assert!(!is_kad_callback_candidate(&high_id));
    }

    #[test]
    fn cooldown_is_peer_route_scoped_and_not_file_scoped() {
        let now = Instant::now();
        let first_file = buddy_source(Ed2kHash::from_bytes([0x11; 16]));
        let second_file = buddy_source(Ed2kHash::from_bytes([0x22; 16]));
        let direct_key = kad_callback_key(&first_file).unwrap();
        assert_eq!(kad_callback_key(&second_file), Some(direct_key.clone()));

        let mut last_sent = HashMap::new();
        let permit = claim_kad_callback_request(&mut last_sent, direct_key.clone(), now).unwrap();
        assert!(
            claim_kad_callback_request(
                &mut last_sent,
                direct_key.clone(),
                now + Duration::from_secs(44),
            )
            .is_none()
        );

        // A FINDSOURCE route cannot join the direct-route ticket and therefore
        // owns an independent cooldown identity.
        let mut findsource = first_file.clone();
        findsource.buddy_endpoint = None;
        let findsource_key = kad_callback_key(&findsource).unwrap();
        assert_ne!(findsource_key, direct_key);
        assert!(claim_kad_callback_request(&mut last_sent, findsource_key, now).is_some());

        assert!(commit_kad_callback_request(
            &mut last_sent,
            permit,
            now + Duration::from_secs(2),
        ));
        assert!(
            claim_kad_callback_request(&mut last_sent, direct_key, now + Duration::from_secs(46),)
                .is_none()
        );
    }

    #[test]
    fn cooldown_rollback_is_exact_and_linear() {
        let now = Instant::now();
        let key = kad_callback_key(&buddy_source(Ed2kHash::from_bytes([0x33; 16]))).unwrap();
        let mut last_sent = HashMap::new();
        let stale = claim_kad_callback_request(&mut last_sent, key.clone(), now).unwrap();
        let current = claim_kad_callback_request(
            &mut last_sent,
            key.clone(),
            now + KAD_CALLBACK_INITIATOR_COOLDOWN,
        )
        .unwrap();

        assert!(!cancel_kad_callback_request(&mut last_sent, stale));
        assert!(last_sent.contains_key(&key));
        assert!(cancel_kad_callback_request(&mut last_sent, current));
        assert!(!last_sent.contains_key(&key));
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
