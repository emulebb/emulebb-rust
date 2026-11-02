use super::*;
use crate::reachability::{ReachabilityRuntimeAuthority, ReachabilityRuntimeLease};

fn service() -> (ReaskService, ReachabilityRuntimeLease) {
    let authority = ReachabilityRuntimeAuthority::new();
    let public_ip = authority.reader();
    let lease = authority.begin_runtime();
    lease
        .writer()
        .set_fallback_public_ip(std::net::Ipv4Addr::new(203, 0, 113, 9));
    (ReaskService::new([0x10; 16], 4, public_ip), lease)
}

async fn unbootstrapped_dht(node_byte: u8) -> DhtNode {
    use emulebb_kad_dht::DhtConfig;
    use emulebb_kad_proto::NodeId;

    DhtNode::new(DhtConfig {
        bind_addr: Some(SocketAddr::from((crate::test_bind_ip(), 0))),
        node_id: NodeId::from_bytes([node_byte; 16]),
        udp_key: 0x1020_3040,
        ..DhtConfig::default()
    })
    .await
    .unwrap()
}

#[test]
fn v4_ack_status_resolves_complete_and_bitmap_source_availability() {
    let ours = [true, false, true];

    let complete =
        resolved_reask_ack_bitmap(&ReaskAckPartStatus::CompleteSource, Some(ours.len())).unwrap();
    assert_eq!(complete, vec![true, true, true]);
    assert!(!reask_source_has_no_needed_parts(&ours, &complete));

    let unavailable = ReaskAckPartStatus::Bitmap(vec![true, false, true]);
    let unavailable = resolved_reask_ack_bitmap(&unavailable, Some(ours.len())).unwrap();
    assert!(reask_source_has_no_needed_parts(&ours, &unavailable));

    assert_eq!(
        resolved_reask_ack_bitmap(&ReaskAckPartStatus::NotIncluded, Some(ours.len())),
        None
    );
}

#[test]
fn tcp_firewall_resolution_matches_mfc_connected_authority_or() {
    let low_id_server_with_open_kad =
        resolve_tcp_firewall_verdict(true, Some(true), true, Some(false));
    assert_eq!(
        low_id_server_with_open_kad,
        TcpFirewallVerdict {
            firewalled: false,
            authority: TcpFirewallAuthority::KadOpen,
            server_connected: true,
            server_firewalled: Some(true),
            kad_connected: true,
            kad_firewalled: Some(false),
        }
    );

    let high_id_server_with_firewalled_kad =
        resolve_tcp_firewall_verdict(true, Some(false), true, Some(true));
    assert_eq!(
        high_id_server_with_firewalled_kad,
        TcpFirewallVerdict {
            firewalled: false,
            authority: TcpFirewallAuthority::ServerHighId,
            server_connected: true,
            server_firewalled: Some(false),
            kad_connected: true,
            kad_firewalled: Some(true),
        }
    );

    let stale_disconnected_high_id = resolve_tcp_firewall_verdict(false, Some(false), false, None);
    assert_eq!(
        stale_disconnected_high_id,
        TcpFirewallVerdict {
            firewalled: true,
            authority: TcpFirewallAuthority::NoOpenAuthority,
            server_connected: false,
            server_firewalled: Some(false),
            kad_connected: false,
            kad_firewalled: None,
        }
    );

    assert_eq!(
        resolve_tcp_firewall_verdict(false, None, false, None),
        TcpFirewallVerdict {
            firewalled: true,
            authority: TcpFirewallAuthority::NoOpenAuthority,
            server_connected: false,
            server_firewalled: None,
            kad_connected: false,
            kad_firewalled: None,
        }
    );
}

#[tokio::test]
async fn bound_listener_without_a_connected_authority_remains_firewalled() {
    let _listener = tokio::net::TcpListener::bind((crate::test_bind_ip(), 0))
        .await
        .unwrap();
    let dht = unbootstrapped_dht(0x41).await;
    let server_state = RwLock::new(Ed2kServerState::default());
    let kad_firewall = Mutex::new(KadFirewallState::default());

    assert_eq!(
        current_tcp_firewall_verdict(&dht, &server_state, &kad_firewall).await,
        TcpFirewallVerdict {
            firewalled: true,
            authority: TcpFirewallAuthority::NoOpenAuthority,
            server_connected: false,
            server_firewalled: None,
            kad_connected: false,
            kad_firewalled: None,
        }
    );
}

#[tokio::test]
async fn tcp_firewall_verdict_tracks_live_server_transitions() {
    let dht = unbootstrapped_dht(0x42).await;
    let server_state = RwLock::new(Ed2kServerState::default());
    let kad_firewall = Mutex::new(KadFirewallState::default());

    {
        let mut server = server_state.write().await;
        server.client_id = Some(u32::from(Ipv4Addr::new(198, 51, 100, 7)));
        server.connected = false;
    }
    assert!(
        current_tcp_firewall_verdict(&dht, &server_state, &kad_firewall)
            .await
            .firewalled,
        "a disconnected HighID is stale and cannot prove reachability"
    );

    {
        let mut server = server_state.write().await;
        server.connected = true;
        server.client_id = Some(0x0000_1234);
    }
    assert_eq!(
        current_tcp_firewall_verdict(&dht, &server_state, &kad_firewall)
            .await
            .authority,
        TcpFirewallAuthority::ServerLowId
    );

    server_state.write().await.client_id = Some(u32::from(Ipv4Addr::new(198, 51, 100, 7)));
    assert_eq!(
        current_tcp_firewall_verdict(&dht, &server_state, &kad_firewall)
            .await
            .authority,
        TcpFirewallAuthority::ServerHighId
    );

    server_state.write().await.connected = false;
    let disconnected = current_tcp_firewall_verdict(&dht, &server_state, &kad_firewall).await;
    assert!(disconnected.firewalled);
    assert_eq!(
        disconnected.authority,
        TcpFirewallAuthority::NoOpenAuthority
    );
}

#[tokio::test]
async fn local_firewall_gate_blocks_buddy_reask_until_reachability_opens() {
    use emulebb_kad_dht::DhtConfig;
    use emulebb_kad_proto::NodeId;
    use tokio::net::UdpSocket;

    let bind_ip = crate::test_bind_ip();
    let dht = DhtNode::new(DhtConfig {
        bind_addr: Some(SocketAddr::from((bind_ip, 0))),
        node_id: NodeId::from_bytes([0x31; 16]),
        udp_key: 0x5566_7788,
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let receiver = UdpSocket::bind((bind_ip, 0)).await.unwrap();
    let buddy_addr = receiver.local_addr().unwrap();
    let SocketAddr::V4(buddy_addr) = buddy_addr else {
        panic!("test receiver must be IPv4");
    };
    let now = Instant::now();
    let file_hash = Ed2kHash::from_bytes([0xBC; 16]);
    let source_endpoint = (Ipv4Addr::new(198, 51, 100, 50), 4672);
    let (mut svc, _reachability) = service();
    svc.register_source(
        file_hash,
        ReaskSource::new(source_endpoint, file_hash, 4, now).with_buddy(
            true,
            Some((*buddy_addr.ip(), buddy_addr.port())),
            Some([0x99; 16]),
        ),
    );

    let mut scheduled = svc.tick(now, Duration::from_secs(20), |_| TransferReaskInfo {
        part_status: None,
        complete_source_count: 0,
    });
    assert_eq!(scheduled.send.len(), 1);
    dispatch_scheduled_reask(
        &mut svc,
        &dht,
        scheduled.send.remove(0),
        resolve_tcp_firewall_verdict(true, Some(true), false, None),
    )
    .await;

    let mut datagram = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(50), receiver.recv_from(&mut datagram))
            .await
            .is_err(),
        "a firewalled requester must not send OP_REASKCALLBACKUDP"
    );

    let mut rescheduled = svc.tick(now, Duration::from_secs(20), |_| TransferReaskInfo {
        part_status: None,
        complete_source_count: 0,
    });
    assert_eq!(
        rescheduled.send.len(),
        1,
        "the skipped source must stay due for a later live-state reevaluation"
    );
    dispatch_scheduled_reask(
        &mut svc,
        &dht,
        rescheduled.send.remove(0),
        resolve_tcp_firewall_verdict(true, Some(false), false, None),
    )
    .await;

    let (received, _) =
        tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut datagram))
            .await
            .expect("an open requester should send the relayed reask")
            .unwrap();
    assert_eq!(
        &datagram[..2],
        &[0xC5, super::super::codec::OP_REASKCALLBACKUDP]
    );
    assert!(received > 2);

    let pending = svc.tick(now, Duration::from_secs(20), |_| TransferReaskInfo {
        part_status: None,
        complete_source_count: 0,
    });
    assert!(pending.send.is_empty());
}

#[tokio::test]
async fn replaced_buddy_answer_command_sends_no_udp_response() {
    use emulebb_kad_dht::DhtConfig;
    use emulebb_kad_proto::NodeId;
    use tokio::net::UdpSocket;

    let bind_ip = crate::test_bind_ip();
    let dht = DhtNode::new(DhtConfig {
        bind_addr: Some(SocketAddr::from((bind_ip, 0))),
        node_id: NodeId::from_bytes([0x21; 16]),
        udp_key: 0x1122_3344,
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let receiver = UdpSocket::bind((bind_ip, 0)).await.unwrap();
    let destination = receiver.local_addr().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(temp_dir.path()).unwrap();
    let registry = BuddySocketRegistry::new();
    let stale = registry.register_outbound(bind_ip, [0x44; 16]);
    let replacement = registry.register_outbound(bind_ip, [0x44; 16]);
    let forwarded_reask =
        super::super::codec::encode_reask_file_ping(&Ed2kHash::from_bytes([0xAB; 16]), None, 0, 4);

    process_answer_callback_tcp(
        &dht,
        &transfer_runtime,
        bind_ip.octets(),
        &registry,
        stale,
        destination,
        &forwarded_reask,
        4,
    )
    .await;

    let mut datagram = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(50), receiver.recv_from(&mut datagram))
            .await
            .is_err()
    );
    assert!(registry.is_current_outbound(replacement));
}

#[test]
fn register_command_adds_a_source_and_remove_drops_it() {
    let (mut svc, _reachability) = service();
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
    let (mut svc, _reachability) = service();
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
fn reask_send_settlement_opens_pending_only_on_success() {
    let now = Instant::now();
    let timeout = Duration::from_secs(20);
    let file_hash = Ed2kHash::from_bytes([0xAD; 16]);
    let endpoint = (Ipv4Addr::new(198, 51, 100, 9), 4672);
    let (mut svc, _reachability) = service();
    svc.register_source(file_hash, ReaskSource::new(endpoint, file_hash, 4, now));

    let failed = svc.tick(now, timeout, |_| TransferReaskInfo {
        part_status: None,
        complete_source_count: 0,
    });
    assert_eq!(failed.send.len(), 1);
    assert_eq!(
        settle_reask_send(
            &mut svc,
            failed.send[0].source_endpoint,
            failed.send[0].request_part_status.clone(),
            Err::<(), _>("local send failed"),
            now,
        ),
        Err("local send failed")
    );

    let retry_at = now + timeout + Duration::from_secs(1);
    let retry = svc.tick(retry_at, timeout, |_| TransferReaskInfo {
        part_status: None,
        complete_source_count: 0,
    });
    assert!(retry.timed_out.is_empty());
    assert_eq!(retry.send.len(), 1);
    assert_eq!(
        settle_reask_send(
            &mut svc,
            retry.send[0].source_endpoint,
            retry.send[0].request_part_status.clone(),
            Ok::<(), &str>(()),
            retry_at,
        ),
        Ok(true)
    );

    let gated = svc.tick(retry_at, timeout, |_| TransferReaskInfo {
        part_status: None,
        complete_source_count: 0,
    });
    assert!(gated.send.is_empty());
}

#[test]
fn remove_command_for_unknown_endpoint_releases_no_lease() {
    let (mut svc, _reachability) = service();
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
    let lease_endpoint = (Ipv4Addr::new(198, 51, 100, 9), 4662);
    let events = routed_reply_events(
        ReaskAction::UpdatedRank(REENGAGE_RANK_THRESHOLD),
        file_hash,
        lease_endpoint,
        None,
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
        (Ipv4Addr::new(198, 51, 100, 10), 4662),
        None,
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
    // re-acquisition the moment the endpoint becomes free again. Both events
    // carry the TCP lease key; SourceDead also carries the learned hash.
    let lease_endpoint = (Ipv4Addr::new(198, 51, 100, 11), 4662);
    let source_user_hash = [0x56; 16];
    let hash = Ed2kHash::from_bytes([0x55; 16]);
    let events = routed_reply_events(
        ReaskAction::DropSource,
        hash,
        lease_endpoint,
        Some(source_user_hash),
    );
    assert_eq!(events.len(), 2);
    match &events[0] {
        ReaskEvent::SourceDead {
            file_hash,
            source_tcp_endpoint,
            source_user_hash: dead_user_hash,
        } => {
            assert_eq!(*file_hash, hash);
            assert_eq!(*source_tcp_endpoint, lease_endpoint);
            assert_eq!(*dead_user_hash, Some(source_user_hash));
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
    let (mut svc, _reachability) = service();
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

#[test]
fn inbound_direct_callback_req_raises_connect_out_event_when_reask_is_disabled() {
    use crate::ed2k_client_udp::codec::OP_DIRECTCALLBACKREQ;
    use crate::ed2k_client_udp_obfuscation::obfuscate_client_udp_with;
    use crate::port_test::PortTestRegistry;

    let requester: SocketAddr = "198.51.100.7:4662".parse().unwrap();
    let our_user_hash = [0x10; 16];
    let mut body = Vec::new();
    body.extend_from_slice(&4662u16.to_le_bytes());
    body.extend_from_slice(&[0x5A; 16]);
    body.push(0x01);
    let mut plain = vec![0xC5u8, OP_DIRECTCALLBACKREQ];
    plain.extend_from_slice(&body);
    let obfuscated =
        obfuscate_client_udp_with(&our_user_hash, [198, 51, 100, 7], &plain, 0x1357, 0x40);

    for datagram in [plain, obfuscated] {
        let (events, mut rx) = reask_event_channel();
        let disposition = handle_reask_disabled_datagram(
            &events,
            &PortTestRegistry::new(),
            our_user_hash,
            4,
            &datagram,
            requester,
        );
        assert_eq!(
            disposition,
            (
                ClientUdpDumpOutcome::Accepted,
                Some("direct_callback_raised".to_string())
            )
        );
        match rx.try_recv().expect("a direct callback event") {
            ReaskEvent::DirectCallbackReq {
                requester_ip,
                tcp_port,
                user_hash,
                connect_options,
            } => {
                assert_eq!(requester_ip, Ipv4Addr::new(198, 51, 100, 7));
                assert_eq!(tcp_port, 4662);
                assert_eq!(user_hash, [0x5A; 16]);
                assert_eq!(connect_options, 0x01);
            }
            other => panic!("expected DirectCallbackReq event, got {other:?}"),
        }
    }
}

#[test]
fn inbound_source_reask_remains_ignored_when_reask_is_disabled() {
    use crate::ed2k_client_udp::codec::OP_QUEUEFULL;
    use crate::port_test::PortTestRegistry;

    let (events, mut rx) = reask_event_channel();
    let disposition = handle_reask_disabled_datagram(
        &events,
        &PortTestRegistry::new(),
        [0x10; 16],
        4,
        &[0xC5, OP_QUEUEFULL],
        "198.51.100.7:4662".parse().unwrap(),
    );
    assert_eq!(
        disposition,
        (
            ClientUdpDumpOutcome::Ignored,
            Some("reask_disabled".to_string())
        )
    );
    assert!(rx.try_recv().is_err());
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

#[cfg(feature = "packet-diagnostics")]
#[tokio::test]
async fn diagnostic_wake_is_ordered_after_normal_registration() {
    let (handle, mut rx) = reask_command_channel();
    let file_hash = Ed2kHash::from_bytes([0xCD; 16]);
    assert!(handle.register_kad_buddy_source(ReaskDetachArgs {
        file_hash,
        endpoint: (Ipv4Addr::new(10, 0, 0, 1), 5000),
        tcp_port: 4662,
        udp_version: 4,
        initial_reask_delay: Duration::ZERO,
        user_hash: Some([0x66; 16]),
        should_crypt: false,
        low_id: true,
        buddy_endpoint: Some((Ipv4Addr::new(203, 0, 113, 9), 5000)),
        buddy_id: Some([0x77; 16]),
    }));

    let wake = tokio::spawn(async move { handle.diagnostic_wake_tick().await });

    match rx.recv().await.expect("the queued registration") {
        ReaskCommand::Register(args) => {
            assert_eq!(args.file_hash, file_hash);
            assert_eq!(args.endpoint, (Ipv4Addr::new(10, 0, 0, 1), 5000));
        }
        other => panic!("expected Register before the wake, got {other:?}"),
    }
    match rx.recv().await.expect("the queued diagnostics wake") {
        ReaskCommand::DiagnosticWakeTick { completed } => {
            completed.send(()).expect("wake completion receiver");
        }
        other => panic!("expected DiagnosticWakeTick after Register, got {other:?}"),
    }

    assert_eq!(wake.await.expect("wake task"), Ok(()));
}
