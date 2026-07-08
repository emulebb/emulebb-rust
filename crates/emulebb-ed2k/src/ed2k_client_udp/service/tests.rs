use super::*;
use crate::ed2k_client_udp::outbound::{OutboundReaskTarget, build_reask_ack_datagram};

const OUR_HASH: [u8; 16] = [0x10; 16];
const PEER_HASH: [u8; 16] = [0x55; 16];

fn file_hash() -> Ed2kHash {
    Ed2kHash::from_bytes([0xAB; 16])
}

fn peer_addr() -> SocketAddr {
    "198.51.100.7:4672".parse().unwrap()
}

fn peer_v4() -> (Ipv4Addr, u16) {
    (Ipv4Addr::new(198, 51, 100, 7), 4672)
}

/// The peer's TCP endpoint — core's lease key, distinct from the UDP routing
/// endpoint so tests catch a release addressed to the wrong keyspace.
fn peer_lease_v4() -> (Ipv4Addr, u16) {
    (Ipv4Addr::new(198, 51, 100, 7), 4662)
}

fn service() -> ReaskService {
    let public_ip = ExternalReachability::new();
    public_ip.set(Ipv4Addr::new(203, 0, 113, 9));
    ReaskService::new(OUR_HASH, 4, public_ip)
}

fn register(svc: &mut ReaskService, now: Instant) {
    let src = ReaskSource::new(peer_v4(), file_hash(), 4, now)
        .with_lease_endpoint(peer_lease_v4())
        .with_obfuscation(PEER_HASH, true);
    svc.register_source(file_hash(), src);
}

#[test]
fn tick_originates_buddy_callback_udp_for_a_low_id_buddy_source() {
    use super::super::codec::{OP_REASKCALLBACKUDP, decode_reask_callback_udp};
    use super::super::state::ReaskSource;

    let now = Instant::now();
    let mut svc = service();
    let source_endpoint = (Ipv4Addr::new(198, 51, 100, 50), 4672);
    let buddy_endpoint = (Ipv4Addr::new(203, 0, 113, 80), 5000);
    let buddy_id = [0x99u8; 16];
    let src = ReaskSource::new(source_endpoint, file_hash(), 4, now).with_buddy(
        true,
        Some(buddy_endpoint),
        Some(buddy_id),
    );
    svc.register_source(file_hash(), src);

    let out = svc.tick(now, Duration::from_secs(20), |_| TransferReaskInfo {
        part_status: Some(vec![true, false]),
        complete_source_count: 4,
    });
    assert_eq!(out.send.len(), 1);
    let (dest, datagram) = &out.send[0];
    assert_eq!(
        *dest,
        SocketAddr::new(buddy_endpoint.0.into(), buddy_endpoint.1)
    );
    assert_eq!(datagram.bytes[0], 0xC5);
    assert_eq!(datagram.bytes[1], OP_REASKCALLBACKUDP);
    assert_eq!(datagram.opcode, OP_REASKCALLBACKUDP);
    assert!(!datagram.obfuscated);
    let decoded = decode_reask_callback_udp(&datagram.payload).unwrap();
    assert_eq!(decoded.buddy_id.0, buddy_id);
    assert_eq!(decoded.file_hash, file_hash());
}

#[test]
fn tick_emits_due_ping_then_routes_the_ack() {
    let now = Instant::now();
    let mut svc = service();
    register(&mut svc, now);

    let out = svc.tick(now, Duration::from_secs(20), |_| TransferReaskInfo {
        part_status: Some(vec![true, false]),
        complete_source_count: 1,
    });
    assert_eq!(out.send.len(), 1);
    assert_eq!(out.send[0].0, peer_addr());

    let ack = build_reask_ack_datagram(
        None,
        12,
        4,
        &OutboundReaskTarget {
            dest_user_hash: OUR_HASH,
            our_public_ip: peer_v4().0.octets(),
            obfuscate: true,
        },
    );
    let outcome = svc.handle_inbound(&ack, peer_addr(), now);
    assert_eq!(
        outcome,
        ReaskInboundOutcome::RoutedReply {
            file_hash: file_hash(),
            endpoint: peer_v4(),
            lease_endpoint: peer_lease_v4(),
            action: ReaskAction::UpdatedRank(12),
        }
    );
}

#[test]
fn tick_paced_suppresses_sends_when_the_udp_cap_denies_a_file() {
    let now = Instant::now();
    let mut svc = service();
    register(&mut svc, now);
    let deny = |_h: &Ed2kHash, _n: usize| false;
    let out = svc.tick_paced(
        now,
        Duration::from_secs(20),
        |_| TransferReaskInfo {
            part_status: Some(vec![true, false]),
            complete_source_count: 1,
        },
        &ReaskTickPacing {
            rotate_offset: 0,
            admit: Some(&deny),
        },
    );
    assert!(out.send.is_empty());

    let allow = |_h: &Ed2kHash, _n: usize| true;
    let out = svc.tick_paced(
        now,
        Duration::from_secs(20),
        |_| TransferReaskInfo {
            part_status: Some(vec![true, false]),
            complete_source_count: 1,
        },
        &ReaskTickPacing {
            rotate_offset: 0,
            admit: Some(&allow),
        },
    );
    assert_eq!(out.send.len(), 1);
}

#[test]
fn unsolicited_reply_without_pending_is_ignored() {
    let now = Instant::now();
    let mut svc = service();
    register(&mut svc, now);
    let ack = build_reask_ack_datagram(
        None,
        1,
        4,
        &OutboundReaskTarget {
            dest_user_hash: OUR_HASH,
            our_public_ip: peer_v4().0.octets(),
            obfuscate: true,
        },
    );
    assert_eq!(
        svc.handle_inbound(&ack, peer_addr(), now),
        ReaskInboundOutcome::Ignored
    );
}

#[test]
fn inbound_file_ping_is_handed_back_for_the_caller_to_answer() {
    use crate::ed2k_client_udp::outbound::build_reask_file_ping_datagram;
    let now = Instant::now();
    let mut svc = service();
    let ping = build_reask_file_ping_datagram(
        &file_hash(),
        None,
        0,
        4,
        &OutboundReaskTarget {
            dest_user_hash: OUR_HASH,
            our_public_ip: peer_v4().0.octets(),
            obfuscate: true,
        },
    );
    match svc.handle_inbound(&ping, peer_addr(), now) {
        ReaskInboundOutcome::AnswerNeeded { ping, from } => {
            assert_eq!(ping.file_hash, file_hash());
            assert_eq!(from, peer_addr());
        }
        other => panic!("expected AnswerNeeded, got {other:?}"),
    }
}

#[test]
fn file_not_found_drops_source_and_clears_routing() {
    let now = Instant::now();
    let mut svc = service();
    register(&mut svc, now);
    let _ = svc.tick(now, Duration::from_secs(20), |_| TransferReaskInfo {
        part_status: None,
        complete_source_count: 0,
    });
    let fnf = vec![0xC5u8, 0x92];
    let outcome = svc.handle_inbound(&fnf, peer_addr(), now);
    assert_eq!(
        outcome,
        ReaskInboundOutcome::RoutedReply {
            file_hash: file_hash(),
            endpoint: peer_v4(),
            lease_endpoint: peer_lease_v4(),
            action: ReaskAction::DropSource,
        }
    );
    assert_eq!(svc.source_count(), 0);
    assert_eq!(
        svc.handle_inbound(&fnf, peer_addr(), now),
        ReaskInboundOutcome::Ignored
    );
}

#[test]
fn inbound_callback_udp_is_handed_back_for_buddy_relay() {
    use crate::ed2k_client_udp::outbound::build_reask_callback_udp_datagram;
    let now = Instant::now();
    let mut svc = service();
    let buddy_id = Ed2kHash::from_bytes([0x77; 16]);
    let datagram =
        build_reask_callback_udp_datagram(&buddy_id, &file_hash(), Some(&[true, false]), 3, 4);
    match svc.handle_inbound(&datagram, peer_addr(), now) {
        ReaskInboundOutcome::BuddyRelay { callback, from } => {
            assert_eq!(callback.buddy_id, buddy_id);
            assert_eq!(callback.file_hash, file_hash());
            assert_eq!(from, peer_addr());
        }
        other => panic!("expected BuddyRelay, got {other:?}"),
    }
}

#[test]
fn inbound_direct_callback_req_is_handed_back_for_connect_out() {
    use crate::ed2k_client_udp::codec::OP_DIRECTCALLBACKREQ;
    let now = Instant::now();
    let mut svc = service();
    let mut body = Vec::new();
    body.extend_from_slice(&4662u16.to_le_bytes());
    body.extend_from_slice(&PEER_HASH);
    body.push(0x01);
    let mut datagram = vec![0xC5u8, OP_DIRECTCALLBACKREQ];
    datagram.extend_from_slice(&body);
    match svc.handle_inbound(&datagram, peer_addr(), now) {
        ReaskInboundOutcome::DirectCallbackReq { req, from } => {
            assert_eq!(req.tcp_port, 4662);
            assert_eq!(req.user_hash, PEER_HASH);
            assert_eq!(from, peer_addr());
        }
        other => panic!("expected DirectCallbackReq, got {other:?}"),
    }
}

#[test]
fn junk_and_non_ipv4_are_ignored() {
    let now = Instant::now();
    let mut svc = service();
    register(&mut svc, now);
    assert_eq!(
        svc.handle_inbound(&[0x42; 30], peer_addr(), now),
        ReaskInboundOutcome::Ignored
    );
    let v6: SocketAddr = "[2001:db8::1]:4672".parse().unwrap();
    assert_eq!(
        svc.handle_inbound(&[0xC5, 0x93], v6, now),
        ReaskInboundOutcome::Ignored
    );
}

#[test]
fn mark_no_needed_parts_routes_by_endpoint_and_doubles_the_cadence() {
    use crate::ed2k_client_udp::state::FILE_REASK_TIME;
    let now = Instant::now();
    let mut svc = service();
    register(&mut svc, now);
    let (ip, port) = peer_v4();

    assert!(svc.mark_no_needed_parts(ip, port, now));
    // Not due at the single interval: no ping goes out.
    let out = svc.tick(now + FILE_REASK_TIME, Duration::from_secs(20), |_| {
        TransferReaskInfo {
            part_status: None,
            complete_source_count: 0,
        }
    });
    assert!(out.send.is_empty());
    // Due after the doubled interval (oracle FILEREASKTIME * 2).
    let out = svc.tick(now + FILE_REASK_TIME * 2, Duration::from_secs(20), |_| {
        TransferReaskInfo {
            part_status: None,
            complete_source_count: 0,
        }
    });
    assert_eq!(out.send.len(), 1);
    // Unknown endpoint is a no-op.
    assert!(!svc.mark_no_needed_parts(Ipv4Addr::new(198, 51, 100, 99), port, now));
}

#[test]
fn timed_out_reask_surfaces_in_tick_output() {
    let now = Instant::now();
    let timeout = Duration::from_secs(20);
    let mut svc = service();
    register(&mut svc, now);
    let _ = svc.tick(now, timeout, |_| TransferReaskInfo {
        part_status: None,
        complete_source_count: 0,
    });
    let later = now + timeout + Duration::from_secs(1);
    let out = svc.tick(later, timeout, |_| TransferReaskInfo {
        part_status: None,
        complete_source_count: 0,
    });
    assert_eq!(out.timed_out.len(), 1);
    assert_eq!(out.timed_out[0].0, peer_addr());
}
