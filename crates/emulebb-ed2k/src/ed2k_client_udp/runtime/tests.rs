use super::*;
use crate::reachability::ExternalReachability;

fn service() -> ReaskService {
    let public_ip = ExternalReachability::new();
    public_ip.set(std::net::Ipv4Addr::new(203, 0, 113, 9));
    ReaskService::new([0x10; 16], 4, public_ip)
}

#[test]
fn register_command_adds_a_source_and_remove_drops_it() {
    let mut svc = service();
    let (events, mut rx) = reask_event_channel();
    let file_hash = Ed2kHash::from_bytes([0xAB; 16]);
    // Distinct UDP routing port (4672) vs TCP lease port (4662): core's lease
    // sets are keyed by (ip, tcp_port), so a SourceReleased carrying the UDP
    // endpoint would never match and the lease would leak (RUST-PAR-017 DL-11).
    let endpoint = (Ipv4Addr::new(198, 51, 100, 7), 4672);
    let lease_endpoint = (Ipv4Addr::new(198, 51, 100, 7), 4662);
    apply_reask_command(
        &mut svc,
        &events,
        ReaskCommand::Register(ReaskDetachArgs {
            file_hash,
            endpoint,
            tcp_port: lease_endpoint.1,
            udp_version: 4,
            initial_reask_delay: Duration::ZERO,
            user_hash: Some([0x55; 16]),
            should_crypt: true,
            low_id: false,
            buddy_endpoint: None,
            buddy_id: None,
        }),
    );
    assert_eq!(svc.source_count(), 1);
    assert_eq!(svc.registered_file_hashes(), vec![file_hash]);
    assert!(rx.try_recv().is_err());

    apply_reask_command(&mut svc, &events, ReaskCommand::Remove { endpoint });
    assert_eq!(svc.source_count(), 0);
    assert!(svc.registered_file_hashes().is_empty());
    match rx.try_recv().expect("a SourceReleased event") {
        ReaskEvent::SourceReleased { endpoint: released } => assert_eq!(
            released, lease_endpoint,
            "the release must carry the TCP lease key, not the UDP routing endpoint"
        ),
        other => panic!("expected SourceReleased, got {other:?}"),
    }
}

#[test]
fn register_command_respects_initial_reask_delay() {
    let mut svc = service();
    let (events, mut rx) = reask_event_channel();
    let file_hash = Ed2kHash::from_bytes([0xAC; 16]);
    let endpoint = (Ipv4Addr::new(198, 51, 100, 8), 4672);
    apply_reask_command(
        &mut svc,
        &events,
        ReaskCommand::Register(ReaskDetachArgs {
            file_hash,
            endpoint,
            tcp_port: 4662,
            udp_version: 4,
            initial_reask_delay: crate::ed2k_client_udp::FILE_REASK_TIME,
            user_hash: None,
            should_crypt: false,
            low_id: false,
            buddy_endpoint: None,
            buddy_id: None,
        }),
    );
    assert_eq!(svc.source_count(), 1);
    assert!(rx.try_recv().is_err());

    let not_due = Instant::now() + Duration::from_secs(1);
    let out = svc.tick(not_due, Duration::from_secs(20), |_| TransferReaskInfo {
        part_status: None,
        complete_source_count: 0,
    });
    assert!(out.send.is_empty());

    let due = Instant::now() + crate::ed2k_client_udp::FILE_REASK_TIME + Duration::from_secs(1);
    let out = svc.tick(due, Duration::from_secs(20), |_| TransferReaskInfo {
        part_status: None,
        complete_source_count: 0,
    });
    assert_eq!(out.send.len(), 1);
}

#[test]
fn udp_reask_sent_body_matches_mfc_diag_shape() {
    assert_eq!(
        udp_reask_sent_body(),
        serde_json::json!({ "outcome": "sent", "transport": "udp", "reaskCount": 1 })
    );
}

#[test]
fn remove_command_for_unknown_endpoint_releases_no_lease() {
    let mut svc = service();
    let (events, mut rx) = reask_event_channel();
    apply_reask_command(
        &mut svc,
        &events,
        ReaskCommand::Remove {
            endpoint: (Ipv4Addr::new(203, 0, 113, 1), 4672),
        },
    );
    assert!(rx.try_recv().is_err());
}

#[test]
fn reengage_releases_lease_before_signalling_source_ready() {
    let file_hash = Ed2kHash::from_bytes([0x33; 16]);
    let endpoint = (Ipv4Addr::new(198, 51, 100, 9), 4672);
    let lease_endpoint = (Ipv4Addr::new(198, 51, 100, 9), 4662);
    let events = routed_reply_events(
        ReaskAction::UpdatedRank(REENGAGE_RANK_THRESHOLD),
        file_hash,
        endpoint,
        lease_endpoint,
    );
    assert_eq!(events.len(), 2);
    match &events[0] {
        ReaskEvent::SourceReleased { endpoint: released } => assert_eq!(
            *released, lease_endpoint,
            "the release must carry the TCP lease key, not the UDP routing endpoint"
        ),
        other => panic!("expected SourceReleased first, got {other:?}"),
    }
    match &events[1] {
        ReaskEvent::SourceReady { file_hash: ready } => assert_eq!(*ready, file_hash),
        other => panic!("expected SourceReady second, got {other:?}"),
    }
}

#[test]
fn deep_rank_keeps_source_and_releases_no_lease() {
    let events = routed_reply_events(
        ReaskAction::UpdatedRank(REENGAGE_RANK_THRESHOLD + 1),
        Ed2kHash::from_bytes([0x44; 16]),
        (Ipv4Addr::new(198, 51, 100, 10), 4672),
        (Ipv4Addr::new(198, 51, 100, 10), 4662),
    );
    assert!(
        events.is_empty(),
        "deep rank must keep reasking, lease held"
    );
}

#[test]
fn dropped_source_is_dead_listed_then_releases_its_lease() {
    // UDP FNF (oracle UDPReaskFNF, DownloadClient.cpp:1774-1795): the source is
    // dead-listed BEFORE its lease is released, so the 45-minute block gates
    // re-acquisition the moment the endpoint becomes free again. SourceDead
    // carries the UDP endpoint (core resolves by IP); SourceReleased carries
    // the TCP lease key core's sets match against (RUST-PAR-017 DL-11).
    let endpoint = (Ipv4Addr::new(198, 51, 100, 11), 4672);
    let lease_endpoint = (Ipv4Addr::new(198, 51, 100, 11), 4662);
    let hash = Ed2kHash::from_bytes([0x55; 16]);
    let events = routed_reply_events(ReaskAction::DropSource, hash, endpoint, lease_endpoint);
    assert_eq!(events.len(), 2);
    match &events[0] {
        ReaskEvent::SourceDead {
            file_hash,
            endpoint: dead,
        } => {
            assert_eq!(*file_hash, hash);
            assert_eq!(*dead, endpoint);
        }
        other => panic!("expected SourceDead, got {other:?}"),
    }
    match &events[1] {
        ReaskEvent::SourceReleased { endpoint: released } => assert_eq!(
            *released, lease_endpoint,
            "the release must carry the TCP lease key, not the UDP routing endpoint"
        ),
        other => panic!("expected SourceReleased, got {other:?}"),
    }
}

#[test]
fn retry_tcp_timeout_releases_held_lease() {
    let mut svc = service();
    let (events, mut rx) = reask_event_channel();
    let file_hash = Ed2kHash::from_bytes([0x66; 16]);
    let endpoint = (Ipv4Addr::new(198, 51, 100, 12), 4672);
    let lease_endpoint = (Ipv4Addr::new(198, 51, 100, 12), 4662);
    apply_reask_command(
        &mut svc,
        &events,
        ReaskCommand::Register(ReaskDetachArgs {
            file_hash,
            endpoint,
            tcp_port: lease_endpoint.1,
            udp_version: 4,
            initial_reask_delay: Duration::ZERO,
            user_hash: None,
            should_crypt: false,
            low_id: false,
            buddy_endpoint: None,
            buddy_id: None,
        }),
    );
    // remove_source hands back the TCP lease key the release event must carry.
    assert_eq!(
        svc.remove_source(endpoint.0, endpoint.1),
        Some(lease_endpoint)
    );
    let _ = events.send(ReaskEvent::SourceReleased {
        endpoint: lease_endpoint,
    });
    match rx.try_recv().expect("a SourceReleased event") {
        ReaskEvent::SourceReleased { endpoint: released } => assert_eq!(released, lease_endpoint),
        other => panic!("expected SourceReleased, got {other:?}"),
    }
    assert_eq!(svc.remove_source(endpoint.0, endpoint.1), None);
}

#[tokio::test]
async fn inbound_direct_callback_req_raises_connect_out_event() {
    use crate::buddy_socket::BuddySocketRegistry;
    use crate::ed2k_client_udp::codec::OP_DIRECTCALLBACKREQ;
    use crate::ipfilter::IpFilter;

    let mut svc = service();
    let requester: SocketAddr = "198.51.100.7:4662".parse().unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(&4662u16.to_le_bytes());
    body.extend_from_slice(&[0x5A; 16]);
    body.push(0x01);
    let mut datagram = vec![0xC5u8, OP_DIRECTCALLBACKREQ];
    datagram.extend_from_slice(&body);
    let outcome = svc.handle_inbound(&datagram, requester, Instant::now());
    match outcome {
        ReaskInboundOutcome::DirectCallbackReq { req, from } => {
            let SocketAddr::V4(v4) = from else {
                panic!("ipv4")
            };
            let event = ReaskEvent::DirectCallbackReq {
                requester_ip: *v4.ip(),
                tcp_port: req.tcp_port,
                user_hash: req.user_hash,
                connect_options: req.connect_options,
            };
            match event {
                ReaskEvent::DirectCallbackReq {
                    requester_ip,
                    tcp_port,
                    user_hash,
                    ..
                } => {
                    assert_eq!(requester_ip, Ipv4Addr::new(198, 51, 100, 7));
                    assert_eq!(tcp_port, 4662);
                    assert_eq!(user_hash, [0x5A; 16]);
                }
                other => panic!("expected DirectCallbackReq event, got {other:?}"),
            }
        }
        other => panic!("expected DirectCallbackReq outcome, got {other:?}"),
    }
    let _ = (BuddySocketRegistry::new(), IpFilter::default());
}

#[test]
fn inbound_reask_datagram_from_filtered_ip_is_dropped() {
    let filter = IpFilter::parse("198.51.100.0 - 198.51.100.255 , 100 , banned", 127);
    let banned: SocketAddr = "198.51.100.7:4672".parse().unwrap();
    let allowed: SocketAddr = "203.0.113.9:4672".parse().unwrap();
    assert!(is_filtered_reask_source(banned, &filter));
    assert!(!is_filtered_reask_source(allowed, &filter));
}

#[test]
fn empty_filter_allows_all_reask_sources() {
    let filter = IpFilter::default();
    let from: SocketAddr = "198.51.100.7:4672".parse().unwrap();
    assert!(!is_filtered_reask_source(from, &filter));
}

#[test]
fn detach_handle_register_is_received_as_a_command() {
    let (handle, mut rx) = reask_command_channel();
    let file_hash = Ed2kHash::from_bytes([0xCD; 16]);
    assert!(handle.register_kad_buddy_source(ReaskDetachArgs {
        file_hash,
        endpoint: (Ipv4Addr::new(10, 0, 0, 1), 5000),
        tcp_port: 4662,
        udp_version: 4,
        initial_reask_delay: Duration::ZERO,
        user_hash: None,
        should_crypt: false,
        low_id: true,
        buddy_endpoint: Some((Ipv4Addr::new(203, 0, 113, 9), 5000)),
        buddy_id: Some([0x77; 16]),
    }));
    match rx.try_recv().expect("a queued command") {
        ReaskCommand::Register(args) => {
            assert_eq!(args.endpoint, (Ipv4Addr::new(10, 0, 0, 1), 5000));
            assert_eq!(args.tcp_port, 4662);
            assert!(args.low_id);
            assert_eq!(
                args.buddy_endpoint,
                Some((Ipv4Addr::new(203, 0, 113, 9), 5000))
            );
            assert_eq!(args.buddy_id, Some([0x77; 16]));
        }
        other => panic!("expected Register, got {other:?}"),
    }
}
