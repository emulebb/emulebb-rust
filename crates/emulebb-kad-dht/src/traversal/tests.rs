use super::*;
use emulebb_kad_net::MockTransport;
use emulebb_kad_net::{ObfuscationLayer, RpcConfig};
use emulebb_kad_proto::constants::OP_KADEMLIAHEADER;
use emulebb_kad_proto::{Ed2kHash, packet::SearchRes};
use emulebb_kad_proto::{KadPacket, NodeId};
use std::sync::Arc;

#[test]
fn test_traversal_kind_clone() {
    let k = TraversalKind::FindNode;
    let _ = k;
    let k2 = TraversalKind::Keyword {
        request: SearchKeyReq {
            target: NodeId::from_bytes([0x11; 16]),
            start_position: 5,
            restrictive_payload: Vec::new(),
        },
    };
    let _ = k2;
}

#[test]
fn test_candidate_sorting() {
    let target = NodeId::ZERO;
    let mut candidates = [
        TraversalCandidate {
            contact: TraversalContact {
                id: NodeId::from_bytes([0xFF; 16]),
                addr: "127.0.0.1:1".parse().unwrap(),
                tcp_port: 0,
                version: 9,
            },
            state: CandidateState::Pending,
            distance: target.distance(&NodeId::from_bytes([0xFF; 16])),
        },
        TraversalCandidate {
            contact: TraversalContact {
                id: NodeId::from_bytes([0x01; 16]),
                addr: "127.0.0.1:2".parse().unwrap(),
                tcp_port: 0,
                version: 9,
            },
            state: CandidateState::Pending,
            distance: target.distance(&NodeId::from_bytes([0x01; 16])),
        },
    ];
    candidates.sort_by_key(|candidate| candidate.distance);
    // 0x01... is closer to ZERO than 0xFF...
    assert_eq!(candidates[0].contact.id, NodeId::from_bytes([0x01; 16]));
}

#[test]
fn test_traversal_closest_limit_keeps_store_fanout_above_oracle_k() {
    assert_eq!(traversal_closest_limit(&TraversalKind::Store, 20), 20);
    assert_eq!(traversal_closest_limit(&TraversalKind::Store, 4), K);
}

#[test]
fn test_traversal_closest_limit_caps_non_store_walks_at_oracle_k() {
    assert_eq!(traversal_closest_limit(&TraversalKind::FindNode, 20), K);
    assert_eq!(
        traversal_closest_limit(
            &TraversalKind::Keyword {
                request: SearchKeyReq {
                    target: NodeId::ZERO,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
            },
            20,
        ),
        K
    );
}

#[test]
fn test_insert_response_contact_threads_res_tcp_port() {
    // A lookup-learned contact must keep the real eD2k TCP port carried by the
    // RES entry, distinct from the Kad UDP port, so a routing contact built from
    // it (node/search.rs) connects to the correct eD2k endpoint instead of the
    // UDP port.
    let mut candidates = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let entry = ContactEntry {
        node_id: NodeId::from_bytes([7; 16]),
        ip: 0x01020304,
        udp_port: 4672,
        tcp_port: 4662,
        version: 9,
    };

    insert_response_contact(&mut candidates, &mut seen, NodeId::ZERO, entry);

    assert_eq!(candidates.len(), 1);
    let contact = &candidates[0].contact;
    assert_eq!(contact.addr.port(), 4672, "UDP endpoint port preserved");
    assert_eq!(
        contact.tcp_port, 4662,
        "real eD2k TCP port threaded through"
    );
    assert_ne!(
        contact.tcp_port,
        contact.addr.port(),
        "the TCP port must not collapse onto the UDP port"
    );
}

#[test]
fn test_sanitize_res_contacts_rejects_overlarge_reply() {
    let contacts = vec![
        ContactEntry {
            node_id: NodeId::from_bytes([1; 16]),
            ip: 0x01020304,
            udp_port: 4672,
            tcp_port: 4662,
            version: 9,
        };
        3
    ];
    assert!(sanitize_res_contacts(&contacts, "2.3.4.5:4672".parse().unwrap(), 2, None).is_none());
}

#[test]
fn test_sanitize_res_contacts_drops_kad1_and_dns_port_contacts() {
    let contacts = vec![
        // Kad1 (version < 2) -> dropped.
        ContactEntry {
            node_id: NodeId::from_bytes([1; 16]),
            ip: 0x05060708,
            udp_port: 4672,
            tcp_port: 4662,
            version: 1,
        },
        // Legacy node on DNS port 53 (version <= 5) -> dropped.
        ContactEntry {
            node_id: NodeId::from_bytes([2; 16]),
            ip: 0x06070809,
            udp_port: 53,
            tcp_port: 4663,
            version: 5,
        },
        // Modern node on port 53 (version > 5) -> kept ("No DNS Port without
        // encryption" only blocks legacy versions).
        ContactEntry {
            node_id: NodeId::from_bytes([3; 16]),
            ip: 0x07080910,
            udp_port: 53,
            tcp_port: 4664,
            version: 8,
        },
        // Ordinary modern contact -> kept.
        ContactEntry {
            node_id: NodeId::from_bytes([4; 16]),
            ip: 0x08091011,
            udp_port: 4675,
            tcp_port: 4665,
            version: 9,
        },
    ];

    let sanitized = sanitize_res_contacts(&contacts, "9.9.9.9:4672".parse().unwrap(), 10, None)
        .expect("sanitized");
    assert_eq!(sanitized.len(), 2);
    assert_eq!(sanitized[0].ip_addr(), Ipv4Addr::new(7, 8, 9, 16));
    assert_eq!(sanitized[1].ip_addr(), Ipv4Addr::new(8, 9, 16, 17));
}

#[test]
fn test_sanitize_res_contacts_drops_ip_filtered_contacts() {
    // B10: the per-contact ip-filter hook must drop filtered/banned IPs from a RES
    // answer, mirroring KademliaUDPListener.cpp:830-857 `IsFiltered()`.
    let contacts = vec![
        // Banned IP -> dropped by the hook.
        ContactEntry {
            node_id: NodeId::from_bytes([1; 16]),
            ip: 0x0A0B0C0D, // 10.11.12.13
            udp_port: 4672,
            tcp_port: 4662,
            version: 9,
        },
        // Allowed IP -> kept.
        ContactEntry {
            node_id: NodeId::from_bytes([2; 16]),
            ip: 0x14151617, // 20.21.22.23
            udp_port: 4673,
            tcp_port: 4663,
            version: 9,
        },
    ];
    let banned = Ipv4Addr::new(10, 11, 12, 13);
    let filter: crate::traversal::KadIpFilter = std::sync::Arc::new(move |ip| ip == banned);

    let sanitized = sanitize_res_contacts(
        &contacts,
        "9.9.9.9:4672".parse().unwrap(),
        10,
        Some(&filter),
    )
    .expect("sanitized");
    assert_eq!(sanitized.len(), 1, "the banned contact must be dropped");
    assert_eq!(sanitized[0].ip_addr(), Ipv4Addr::new(20, 21, 22, 23));

    // Without the hook, both contacts are kept (filter disabled).
    let unfiltered = sanitize_res_contacts(&contacts, "9.9.9.9:4672".parse().unwrap(), 10, None)
        .expect("sanitized");
    assert_eq!(unfiltered.len(), 2);
}

#[test]
fn test_res_contacts_feed_the_addunfiltered_sink_as_they_arrive() {
    // Oracle AddUnfiltered (KademliaUDPListener.cpp:849): every good RES contact
    // is offered to the routing table as it arrives, independent of whether it
    // ends up in the final closest-set. Here we assert the sink fires once per
    // sanitized contact and is NOT called for the banned/clustered drops.
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let response = emulebb_kad_proto::packet::Res {
        target: NodeId::ZERO,
        contacts: vec![
            // Kept.
            ContactEntry {
                node_id: NodeId::from_bytes([1; 16]),
                ip: 0x14151617, // 20.21.22.23
                udp_port: 4672,
                tcp_port: 4662,
                version: 9,
            },
            // Banned -> dropped by the filter, sink must not fire.
            ContactEntry {
                node_id: NodeId::from_bytes([2; 16]),
                ip: 0x0A0B0C0D, // 10.11.12.13
                udp_port: 4673,
                tcp_port: 4663,
                version: 9,
            },
            // Kept (distinct /24).
            ContactEntry {
                node_id: NodeId::from_bytes([3; 16]),
                ip: 0x1E1F2021, // 30.31.32.33
                udp_port: 4674,
                tcp_port: 4664,
                version: 9,
            },
        ],
    };

    let banned = Ipv4Addr::new(10, 11, 12, 13);
    let filter: crate::traversal::KadIpFilter = Arc::new(move |ip| ip == banned);
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_clone = Arc::clone(&fired);
    let sink: crate::traversal::KadResContactSink = Arc::new(move |entry: &ContactEntry| {
        // The banned IP must never reach the sink.
        assert_ne!(entry.ip_addr(), Ipv4Addr::new(10, 11, 12, 13));
        fired_clone.fetch_add(1, Ordering::SeqCst);
    });

    let cancel = CancellationToken::new();
    let search_kind = TraversalKind::FindNode;
    let config = LookupPhaseConfig {
        target: NodeId::ZERO,
        search_kind: &search_kind,
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
        query_timeout: std::time::Duration::from_secs(1),
        closest_limit: K,
        req_count: 16,
        work_class: RpcWorkClass::Maintenance,
        cancel: &cancel,
        ip_filter: Some(&filter),
        res_contact_sink: Some(&sink),
    };

    let mut candidates = Vec::new();
    let mut seen = std::collections::HashSet::new();
    insert_response_contacts(
        &mut candidates,
        &mut seen,
        &config,
        NodeId::from_bytes([9; 16]),
        None,
        None,
        response,
    );

    // Two good contacts fed the sink; the banned one did not.
    assert_eq!(fired.load(Ordering::SeqCst), 2);
    // Both good contacts also became lookup candidates.
    assert_eq!(candidates.len(), 2);
}

#[test]
fn test_sanitize_res_contacts_filters_duplicate_ip_and_overpopulated_prefix() {
    let contacts = vec![
        ContactEntry {
            node_id: NodeId::from_bytes([1; 16]),
            ip: 0x01020304,
            udp_port: 4672,
            tcp_port: 4662,
            version: 9,
        },
        ContactEntry {
            node_id: NodeId::from_bytes([2; 16]),
            ip: 0x01020304,
            udp_port: 4673,
            tcp_port: 4663,
            version: 9,
        },
        ContactEntry {
            node_id: NodeId::from_bytes([3; 16]),
            ip: 0x01020355,
            udp_port: 4674,
            tcp_port: 4664,
            version: 9,
        },
        ContactEntry {
            node_id: NodeId::from_bytes([4; 16]),
            ip: 0x01020399,
            udp_port: 4675,
            tcp_port: 4665,
            version: 9,
        },
    ];

    let sanitized = sanitize_res_contacts(&contacts, "1.2.3.1:4672".parse().unwrap(), 10, None)
        .expect("sanitized");
    assert_eq!(sanitized.len(), 1);
    assert_eq!(sanitized[0].ip_addr(), Ipv4Addr::new(1, 2, 3, 4));
}

#[test]
fn test_passes_search_tolerance_with_lan_exemption() {
    let target = NodeId::ZERO;
    let contact = TraversalContact {
        id: NodeId::from_bytes([0xFF; 16]),
        addr: "192.168.1.10:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };
    assert!(passes_search_tolerance(target, &contact));
}

#[test]
fn test_passes_search_tolerance_rejects_far_contact() {
    let target = NodeId::ZERO;
    let contact = TraversalContact {
        id: NodeId::from_bytes([0xFF; 16]),
        addr: "8.8.8.8:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };
    assert!(!passes_search_tolerance(target, &contact));
}

#[test]
fn test_find_node_lookup_converged_ignores_farther_unfinished_candidates() {
    let mut candidates = (0u8..K as u8)
        .map(|n| TraversalCandidate {
            contact: TraversalContact {
                id: NodeId::from_bytes([n; 16]),
                addr: format!("127.0.0.1:{}", 4600 + u16::from(n))
                    .parse()
                    .unwrap(),
                tcp_port: 0,
                version: 9,
            },
            state: CandidateState::Responded,
            distance: NodeId::from_bytes([n; 16]),
        })
        .collect::<Vec<_>>();
    candidates.push(TraversalCandidate {
        contact: TraversalContact {
            id: NodeId::from_bytes([0xFF; 16]),
            addr: "127.0.0.1:4700".parse().unwrap(),
            tcp_port: 0,
            version: 9,
        },
        state: CandidateState::Pending,
        distance: NodeId::from_bytes([0xFF; 16]),
    });

    assert!(find_node_lookup_converged(&candidates));
}

#[test]
fn test_find_node_lookup_converged_waits_for_unfinished_closer_candidate() {
    let mut candidates = (1u8..=K as u8)
        .map(|n| TraversalCandidate {
            contact: TraversalContact {
                id: NodeId::from_bytes([n; 16]),
                addr: format!("127.0.0.1:{}", 4600 + u16::from(n))
                    .parse()
                    .unwrap(),
                tcp_port: 0,
                version: 9,
            },
            state: CandidateState::Responded,
            distance: NodeId::from_bytes([n; 16]),
        })
        .collect::<Vec<_>>();
    candidates.push(TraversalCandidate {
        contact: TraversalContact {
            id: NodeId::from_bytes([0; 16]),
            addr: "127.0.0.1:4701".parse().unwrap(),
            tcp_port: 0,
            version: 9,
        },
        state: CandidateState::Inflight,
        distance: NodeId::from_bytes([0; 16]),
    });

    assert!(!find_node_lookup_converged(&candidates));
}

#[test]
fn test_store_lookup_done_once_publish_fanout_has_responded() {
    let mut candidates = (1u8..=K as u8)
        .map(|n| TraversalCandidate {
            contact: TraversalContact {
                id: NodeId::from_bytes([n; 16]),
                addr: format!("127.0.0.1:{}", 4600 + u16::from(n))
                    .parse()
                    .unwrap(),
                tcp_port: 0,
                version: 9,
            },
            state: CandidateState::Responded,
            distance: NodeId::from_bytes([n; 16]),
        })
        .collect::<Vec<_>>();
    candidates.insert(
        0,
        TraversalCandidate {
            contact: TraversalContact {
                id: NodeId::from_bytes([0; 16]),
                addr: "127.0.0.1:4701".parse().unwrap(),
                tcp_port: 0,
                version: 9,
            },
            state: CandidateState::Pending,
            distance: NodeId::from_bytes([0; 16]),
        },
    );

    assert!(lookup_phase_done(&candidates, &TraversalKind::Store, K));
}

#[test]
fn test_keyword_lookup_still_waits_for_unfinished_closest_frontier() {
    let mut candidates = (1u8..=K as u8)
        .map(|n| TraversalCandidate {
            contact: TraversalContact {
                id: NodeId::from_bytes([n; 16]),
                addr: format!("127.0.0.1:{}", 4600 + u16::from(n))
                    .parse()
                    .unwrap(),
                tcp_port: 0,
                version: 9,
            },
            state: CandidateState::Responded,
            distance: NodeId::from_bytes([n; 16]),
        })
        .collect::<Vec<_>>();
    candidates.insert(
        0,
        TraversalCandidate {
            contact: TraversalContact {
                id: NodeId::from_bytes([0; 16]),
                addr: "127.0.0.1:4701".parse().unwrap(),
                tcp_port: 0,
                version: 9,
            },
            state: CandidateState::Pending,
            distance: NodeId::from_bytes([0; 16]),
        },
    );

    assert!(!lookup_phase_done(
        &candidates,
        &TraversalKind::Keyword {
            request: SearchKeyReq {
                target: NodeId::ZERO,
                start_position: 0,
                restrictive_payload: Vec::new(),
            },
        },
        K
    ));
}

#[test]
fn test_select_phase2_contacts_caps_fanout_at_oracle_k() {
    let target = NodeId::ZERO;
    let responded: Vec<TraversalContact> = (1u8..=20)
        .map(|n| TraversalContact {
            id: NodeId::from_bytes([0, 0, 0, 0, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            addr: format!("192.168.1.{}:4672", n).parse().unwrap(),
            tcp_port: 0,
            version: 9,
        })
        .collect();

    let selected = select_phase2_contacts(&responded, target, 15);
    assert_eq!(selected.len(), K);
}

#[test]
fn test_select_phase2_contacts_respects_fanout_ceiling() {
    let target = NodeId::ZERO;
    let responded: Vec<TraversalContact> = (1u8..=5)
        .map(|n| TraversalContact {
            id: NodeId::from_bytes([0, 0, 0, 0, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            addr: format!("192.168.1.{}:4672", n).parse().unwrap(),
            tcp_port: 0,
            version: 9,
        })
        .collect();

    let selected = select_phase2_contacts(&responded, target, 3);
    assert_eq!(selected.len(), 3);
}

/// Regression for the Kad keyword search returning 0 results on the live wire:
/// phase 2 must keep collecting SEARCH_RES for the full traversal `deadline`,
/// not just for one per-node `query_timeout` window. Here a SEARCH_RES arrives
/// well after `query_timeout` has elapsed but comfortably before `deadline`;
/// the previous code capped the phase at `query_timeout` and dropped it.
#[tokio::test]
async fn test_run_search_phase_collects_results_after_query_timeout_until_deadline() {
    let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
    let injector = transport.injector();
    let rpc = RpcManager::new(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig::default(),
    );
    let _handle = rpc.start();

    let target = NodeId::from_bytes([0x55; 16]);
    let contact = TraversalContact {
        id: NodeId::from_bytes([0x66; 16]),
        addr: "192.168.1.30:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };
    let (result_tx, mut result_rx) = mpsc::channel(8);

    tokio::spawn(async move {
        // Deliver the only SEARCH_RES *after* the old per-node query window
        // (40ms) would have closed the phase, but before the deadline (400ms).
        tokio::time::sleep(Duration::from_millis(120)).await;
        let res = KadPacket::SearchRes(SearchRes {
            sender_id: contact.id,
            target,
            results: vec![emulebb_kad_proto::packet::SearchResultEntry {
                entry_id: Ed2kHash::from_bytes([0x77; 16]),
                tags: vec![],
            }],
        });
        injector
            .send((res.encode().unwrap(), contact.addr))
            .await
            .unwrap();
    });

    let _ = run_search_phase(
        &rpc,
        SearchPhaseConfig {
            responded: std::slice::from_ref(&contact),
            kind: TraversalKind::Keyword {
                request: SearchKeyReq {
                    target,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
            },
            target,
            // Short per-node window: with the old `qt = query_timeout` cap the
            // phase would end at ~40ms and never see the 120ms response.
            query_timeout: Duration::from_millis(40),
            deadline: Instant::now() + Duration::from_millis(400),
            phase2_fanout: 1,
            last_lookup_response_at: None,
            jumpstart_idle_grace: Duration::ZERO,
            jumpstart_tick: Duration::from_millis(10),
            work_class: RpcWorkClass::Interactive,
            cancel: &CancellationToken::new(),
            result_tx: Some(result_tx),
        },
    )
    .await;

    let streamed = result_rx
        .recv()
        .await
        .expect("result collected after query_timeout");
    assert_eq!(streamed.0, Ed2kHash::from_bytes([0x77; 16]));
}

#[tokio::test]
async fn test_run_search_phase_collects_multiple_search_res_packets() {
    let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
    let injector = transport.injector();
    let rpc = RpcManager::new(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig::default(),
    );
    let _handle = rpc.start();

    let target = NodeId::from_bytes([0x22; 16]);
    let contact = TraversalContact {
        id: NodeId::from_bytes([0x11; 16]),
        addr: "192.168.1.10:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };
    let (result_tx, mut result_rx) = mpsc::channel(8);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let first = KadPacket::SearchRes(SearchRes {
            sender_id: contact.id,
            target,
            results: vec![emulebb_kad_proto::packet::SearchResultEntry {
                entry_id: Ed2kHash::from_bytes([1; 16]),
                tags: vec![],
            }],
        });
        injector
            .send((first.encode().unwrap(), contact.addr))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;
        let second = KadPacket::SearchRes(SearchRes {
            sender_id: contact.id,
            target,
            results: vec![emulebb_kad_proto::packet::SearchResultEntry {
                entry_id: Ed2kHash::from_bytes([2; 16]),
                tags: vec![],
            }],
        });
        injector
            .send((second.encode().unwrap(), contact.addr))
            .await
            .unwrap();
    });

    let search_entries = run_search_phase(
        &rpc,
        SearchPhaseConfig {
            responded: &[contact],
            kind: TraversalKind::Keyword {
                request: SearchKeyReq {
                    target,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
            },
            target,
            query_timeout: Duration::from_millis(100),
            deadline: Instant::now() + Duration::from_millis(300),
            phase2_fanout: 10,
            last_lookup_response_at: None,
            jumpstart_idle_grace: Duration::ZERO,
            jumpstart_tick: Duration::from_millis(10),
            work_class: RpcWorkClass::Interactive,
            cancel: &CancellationToken::new(),
            result_tx: Some(result_tx),
        },
    )
    .await;

    assert!(
        search_entries.is_empty(),
        "streaming searches should not duplicate raw SEARCH_RES storage"
    );
    let streamed_first = result_rx.recv().await.expect("first streamed result");
    let streamed_second = result_rx.recv().await.expect("second streamed result");
    assert_eq!(streamed_first.0, Ed2kHash::from_bytes([1; 16]));
    assert_eq!(streamed_second.0, Ed2kHash::from_bytes([2; 16]));
}

#[tokio::test]
async fn test_run_search_phase_replays_plain_keyword_request_shape() {
    let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
    let rpc = RpcManager::new(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig::default(),
    );
    let _handle = rpc.start();

    let target = NodeId::from_bytes([0x44; 16]);
    let contact = TraversalContact {
        id: NodeId::from_bytes([0x12; 16]),
        addr: "192.168.1.20:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };

    let _ = run_search_phase(
        &rpc,
        SearchPhaseConfig {
            responded: std::slice::from_ref(&contact),
            kind: TraversalKind::Keyword {
                request: SearchKeyReq {
                    target,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
            },
            target,
            query_timeout: Duration::from_millis(20),
            deadline: Instant::now() + Duration::from_millis(50),
            phase2_fanout: 1,
            last_lookup_response_at: None,
            jumpstart_idle_grace: Duration::ZERO,
            jumpstart_tick: Duration::from_millis(10),
            work_class: RpcWorkClass::Interactive,
            cancel: &CancellationToken::new(),
            result_tx: None,
        },
    )
    .await;

    let outgoing = transport.drain_outgoing();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].0, contact.addr);
    let packet = KadPacket::decode(&outgoing[0].1).unwrap();
    let KadPacket::SearchKeyReq(request) = packet else {
        panic!("expected SearchKeyReq");
    };
    assert_eq!(request.target, target);
    assert_eq!(request.start_position, 0);
    assert!(request.restrictive_payload.is_empty());
}

#[tokio::test]
async fn test_run_search_phase_replays_restrictive_keyword_payload() {
    let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
    let rpc = RpcManager::new(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig::default(),
    );
    let _handle = rpc.start();

    let target = NodeId::from_bytes([0x55; 16]);
    let contact = TraversalContact {
        id: NodeId::from_bytes([0x13; 16]),
        addr: "192.168.1.21:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };
    let restrictive_request = SearchKeyReq {
        target,
        start_position: 0x8000,
        restrictive_payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };

    let _ = run_search_phase(
        &rpc,
        SearchPhaseConfig {
            responded: std::slice::from_ref(&contact),
            kind: TraversalKind::Keyword {
                request: restrictive_request.clone(),
            },
            target,
            query_timeout: Duration::from_millis(20),
            deadline: Instant::now() + Duration::from_millis(50),
            phase2_fanout: 1,
            last_lookup_response_at: None,
            jumpstart_idle_grace: Duration::ZERO,
            jumpstart_tick: Duration::from_millis(10),
            work_class: RpcWorkClass::Interactive,
            cancel: &CancellationToken::new(),
            result_tx: None,
        },
    )
    .await;

    let outgoing = transport.drain_outgoing();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].0, contact.addr);
    let packet = KadPacket::decode(&outgoing[0].1).unwrap();
    let KadPacket::SearchKeyReq(request) = packet else {
        panic!("expected SearchKeyReq");
    };
    assert_eq!(request, restrictive_request);
}

#[tokio::test]
async fn test_run_search_phase_replays_source_request_wire_shape() {
    let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
    let rpc = RpcManager::new(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig::default(),
    );
    let _handle = rpc.start();

    let target = NodeId::from_bytes([0x77; 16]);
    let contact = TraversalContact {
        id: NodeId::from_bytes([0x14; 16]),
        addr: "192.168.1.22:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };
    let source_request = SearchSourceReq {
        target,
        start_position: 0x1234,
        size: 123_456,
    };

    let _ = run_search_phase(
        &rpc,
        SearchPhaseConfig {
            responded: std::slice::from_ref(&contact),
            kind: TraversalKind::Source {
                request: source_request.clone(),
            },
            target,
            query_timeout: Duration::from_millis(20),
            deadline: Instant::now() + Duration::from_millis(50),
            phase2_fanout: 1,
            last_lookup_response_at: None,
            jumpstart_idle_grace: Duration::ZERO,
            jumpstart_tick: Duration::from_millis(10),
            work_class: RpcWorkClass::Interactive,
            cancel: &CancellationToken::new(),
            result_tx: None,
        },
    )
    .await;

    let outgoing = transport.drain_outgoing();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].0, contact.addr);
    assert_eq!(outgoing[0].1[0], OP_KADEMLIAHEADER);
    assert_eq!(
        outgoing[0].1[1],
        emulebb_kad_proto::opcode::SEARCH_SOURCE_REQ
    );
    assert_eq!(&outgoing[0].1[2..18], &source_request.target.0);
    assert_eq!(
        &outgoing[0].1[18..20],
        &source_request.start_position.to_le_bytes()
    );
    assert_eq!(&outgoing[0].1[20..28], &source_request.size.to_le_bytes());

    let packet = KadPacket::decode(&outgoing[0].1).unwrap();
    let KadPacket::SearchSourceReq(request) = packet else {
        panic!("expected SearchSourceReq");
    };
    assert_eq!(request.target, source_request.target);
    // The source-page offset stays on the wire and the decoder preserves it.
    assert_eq!(request.start_position, source_request.start_position);
    assert_eq!(request.size, source_request.size);
}

#[tokio::test]
async fn test_run_search_phase_walks_one_contact_per_jumpstart_tick() {
    let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
    let rpc = RpcManager::new(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig::default(),
    );
    let _handle = rpc.start();

    let target = NodeId::from_bytes([0x66; 16]);
    let contacts = vec![
        TraversalContact {
            id: NodeId::from_bytes([0x21; 16]),
            addr: "192.168.1.31:4672".parse().unwrap(),
            tcp_port: 0,
            version: 9,
        },
        TraversalContact {
            id: NodeId::from_bytes([0x22; 16]),
            addr: "192.168.1.32:4672".parse().unwrap(),
            tcp_port: 0,
            version: 9,
        },
    ];
    let first_addr = contacts[0].addr;
    let second_addr = contacts[1].addr;
    let test_contacts = contacts.clone();

    let run = tokio::spawn({
        let rpc = rpc.clone();
        async move {
            run_search_phase(
                &rpc,
                SearchPhaseConfig {
                    responded: &test_contacts,
                    kind: TraversalKind::Keyword {
                        request: SearchKeyReq {
                            target,
                            start_position: 0,
                            restrictive_payload: Vec::new(),
                        },
                    },
                    target,
                    // This is a wall-clock test (the worker schedules on
                    // std::time::Instant), so the windows are sized generously to
                    // tolerate scheduler jitter when the suite runs under parallel
                    // load: first emit ~60ms (idle grace), second ~260ms (one
                    // jumpstart tick later). The two drains below sample at 150ms
                    // and 350ms, leaving ~90ms of slack on each side.
                    query_timeout: Duration::from_millis(640),
                    deadline: Instant::now() + Duration::from_millis(900),
                    phase2_fanout: 2,
                    last_lookup_response_at: Some(Instant::now()),
                    jumpstart_idle_grace: Duration::from_millis(60),
                    jumpstart_tick: Duration::from_millis(200),
                    work_class: RpcWorkClass::Interactive,
                    cancel: &CancellationToken::new(),
                    result_tx: None,
                },
            )
            .await
        }
    });

    tokio::time::sleep(Duration::from_millis(150)).await;
    let first_wave = transport.drain_outgoing();
    assert_eq!(first_wave.len(), 1);
    assert_eq!(first_wave[0].0, first_addr);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let second_wave = transport.drain_outgoing();
    assert_eq!(second_wave.len(), 1);
    assert_eq!(second_wave[0].0, second_addr);

    run.await.unwrap();
}

#[tokio::test]
async fn test_run_traversal_obfuscates_phase1_queries_for_fresh_contacts() {
    let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
    let injector = transport.injector();
    let rpc = RpcManager::new(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::from_bytes([0x10; 16]), 0x1122_3344, true),
        RpcConfig::default(),
    );
    let _handle = rpc.start();

    let target = NodeId::from_bytes([0x44; 16]);
    let contact = TraversalContact {
        id: NodeId::from_bytes([0x12; 16]),
        addr: "127.0.0.1:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };
    let reply_addr = contact.addr;

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let packet = KadPacket::Res(emulebb_kad_proto::packet::Res {
            target,
            contacts: Vec::new(),
        });
        injector
            .send((packet.encode().unwrap(), reply_addr))
            .await
            .unwrap();
    });

    let result = run_traversal(
        &rpc,
        vec![contact.clone()],
        TraversalConfig {
            target,
            search_kind: TraversalKind::FindNode,
            timeout: Duration::from_secs(1),
            query_timeout: Duration::from_millis(200),
            phase2_fanout: 1,
            cancel: CancellationToken::new(),
            result_tx: None,
            work_class: RpcWorkClass::Interactive,
            ip_filter: None,
            res_contact_sink: None,
        },
    )
    .await;

    let outgoing = transport.drain_outgoing();
    assert!(!outgoing.is_empty(), "expected traversal to send a query");
    assert_eq!(outgoing[0].0, contact.addr);
    assert_ne!(
        outgoing[0].1[0], OP_KADEMLIAHEADER,
        "phase1 query should already be obfuscated for a known Kad ID"
    );
    assert_eq!(result.closest.len(), 1);
    assert_eq!(result.closest[0].id, contact.id);
}

/// Regression for the live "Kad keyword search returns 0 results, zero
/// KADEMLIA2_SEARCH_KEY_REQ (0x33) on the wire" bug. When phase 1 consumes
/// nearly the whole shared search budget (a slow, rate-limited 0x21 walk can
/// eat almost all of `SEARCH_TIMEOUT`), the lookup's last response is recent
/// when phase 2 starts but only a sliver of the deadline remains. The
/// unclamped 3s jump-start idle grace then pushed the first emit to/past the
/// phase deadline, so the drain loop reached the deadline and broke having sent
/// nothing. The closest contact must still be queried with one SEARCH_KEY_REQ
/// while any budget remains (eMule `CSearch::JumpStart`/`SendFindValue`).
#[tokio::test]
async fn test_run_search_phase_emits_even_when_idle_grace_exceeds_remaining_budget() {
    let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
    let rpc = RpcManager::new(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig::default(),
    );
    let _handle = rpc.start();

    let target = NodeId::from_bytes([0x66; 16]);
    let contact = TraversalContact {
        id: NodeId::from_bytes([0x21; 16]),
        addr: "192.168.1.31:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };

    let _ = run_search_phase(
        &rpc,
        SearchPhaseConfig {
            responded: std::slice::from_ref(&contact),
            kind: TraversalKind::Keyword {
                request: SearchKeyReq {
                    target,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
            },
            target,
            query_timeout: Duration::from_millis(200),
            // Only ~300ms of budget remains, far shorter than the 3s idle grace.
            deadline: Instant::now() + Duration::from_millis(300),
            phase2_fanout: 10,
            // Lookup just responded -> grace would defer the first emit by 3s.
            last_lookup_response_at: Some(Instant::now()),
            jumpstart_idle_grace: Duration::from_secs(3),
            jumpstart_tick: Duration::from_secs(1),
            work_class: RpcWorkClass::Interactive,
            cancel: &CancellationToken::new(),
            result_tx: None,
        },
    )
    .await;

    let outgoing = transport.drain_outgoing();
    assert!(
        outgoing.iter().any(|(_, bytes)| KadPacket::decode(bytes)
            .map(|p| matches!(p, KadPacket::SearchKeyReq(_)))
            .unwrap_or(false)),
        "phase-2 must send at least one SEARCH_KEY_REQ even under a tight deadline; sent {} packets",
        outgoing.len()
    );
}

/// RUST-PAR-017 KAD-G1 guard: the NODE-lite refresh lookup must NOT change the
/// full traversal used by value lookups — a keyword walk still fans out
/// `ALPHA` initial `KADEMLIA2_REQ`s with the value contact-count byte (2).
#[tokio::test]
async fn test_value_lookup_phase_still_fans_out_alpha_initial_reqs() {
    let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
    let rpc = RpcManager::new(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig::default(),
    );
    let _handle = rpc.start();

    let target = NodeId::ZERO;
    let initial: Vec<TraversalContact> = (1u8..=4)
        .map(|n| TraversalContact {
            id: NodeId::from_bytes([n; 16]),
            addr: format!("192.168.1.{n}:4672").parse().unwrap(),
            tcp_port: 0,
            version: 9,
        })
        .collect();

    let _ = run_traversal(
        &rpc,
        initial,
        TraversalConfig {
            target,
            search_kind: TraversalKind::Keyword {
                request: SearchKeyReq {
                    target,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
            },
            timeout: Duration::from_millis(150),
            query_timeout: Duration::from_millis(150),
            phase2_fanout: 1,
            cancel: CancellationToken::new(),
            result_tx: None,
            work_class: RpcWorkClass::Interactive,
            ip_filter: None,
            res_contact_sink: None,
        },
    )
    .await;

    let reqs: Vec<_> = transport
        .drain_outgoing()
        .into_iter()
        .filter_map(|(addr, bytes)| match KadPacket::decode(&bytes) {
            Ok(KadPacket::Req(req)) => Some((addr, req)),
            _ => None,
        })
        .collect();
    assert!(
        reqs.len() >= ALPHA,
        "value lookups keep the ALPHA fan-out, sent {} REQs",
        reqs.len()
    );
    assert!(
        reqs.iter().all(|(_, req)| req.count == KADEMLIA_FIND_VALUE),
        "value lookups keep the FIND_VALUE contact-count byte"
    );
}

fn reask_candidate(last_octet: u8, state: CandidateState) -> TraversalCandidate {
    let id = NodeId::from_bytes([last_octet; 16]);
    TraversalCandidate {
        contact: TraversalContact {
            id,
            addr: format!("127.0.0.1:{}", 4000 + last_octet as u16)
                .parse()
                .unwrap(),
            tcp_port: 0,
            version: 9,
        },
        state,
        distance: NodeId::ZERO.distance(&id),
    }
}

#[test]
fn reask_more_fires_when_best_two_tried_are_dead_and_targets_closest_responder() {
    // Distance grows with the last octet (target ZERO), so 0x01 < 0x02 < ... The
    // two closest tried (0x01, 0x02) are Failed, a farther one (0x03) responded,
    // and >= 6 contacts have been tried: re-ask 0x03 for more.
    let candidates = vec![
        reask_candidate(0x01, CandidateState::Failed),
        reask_candidate(0x02, CandidateState::Failed),
        reask_candidate(0x03, CandidateState::Responded),
        reask_candidate(0x04, CandidateState::Failed),
        reask_candidate(0x05, CandidateState::Responded),
        reask_candidate(0x06, CandidateState::Failed),
    ];
    assert_eq!(
        select_reask_more_target(&candidates, KADEMLIA_FIND_VALUE),
        Some(NodeId::from_bytes([0x03; 16]))
    );
}

#[test]
fn reask_more_suppressed_when_a_best_two_contact_responded_or_too_few_tried() {
    // The closest tried (0x01) responded -> we already have a live closest node.
    let closest_alive = vec![
        reask_candidate(0x01, CandidateState::Responded),
        reask_candidate(0x02, CandidateState::Failed),
        reask_candidate(0x03, CandidateState::Responded),
        reask_candidate(0x04, CandidateState::Failed),
        reask_candidate(0x05, CandidateState::Failed),
        reask_candidate(0x06, CandidateState::Failed),
    ];
    assert_eq!(
        select_reask_more_target(&closest_alive, KADEMLIA_FIND_VALUE),
        None
    );

    // Fewer than 3 * KADEMLIA_FIND_VALUE (6) tried contacts.
    let too_few = vec![
        reask_candidate(0x01, CandidateState::Failed),
        reask_candidate(0x02, CandidateState::Failed),
        reask_candidate(0x03, CandidateState::Responded),
    ];
    assert_eq!(
        select_reask_more_target(&too_few, KADEMLIA_FIND_VALUE),
        None
    );

    // A node lookup (request count 11, not the value count 2) never re-asks.
    let node_lookup = vec![
        reask_candidate(0x01, CandidateState::Failed),
        reask_candidate(0x02, CandidateState::Failed),
        reask_candidate(0x03, CandidateState::Responded),
        reask_candidate(0x04, CandidateState::Failed),
        reask_candidate(0x05, CandidateState::Failed),
        reask_candidate(0x06, CandidateState::Failed),
    ];
    assert_eq!(
        select_reask_more_target(&node_lookup, KADEMLIA_FIND_NODE),
        None
    );
}

#[test]
fn reask_more_target_admits_eleven_contacts_only_from_that_contact() {
    // A RES from the re-ask target may carry up to KADEMLIA_FIND_VALUE_MORE (11)
    // contacts even on a value lookup; the same over-count from any other contact
    // is rejected as it exceeds the value request count.
    let target = NodeId::from_bytes([0x03; 16]);
    let contacts: Vec<ContactEntry> = (0u8..11)
        .map(|n| ContactEntry {
            node_id: NodeId::from_bytes([0x20 + n; 16]),
            ip: 0x0A00_0001 + u32::from(n),
            udp_port: 4672,
            tcp_port: 4662,
            version: 9,
        })
        .collect();
    let responder = "127.0.0.1:4003".parse().unwrap();

    // From the more-asked target: admitted (11 <= KADEMLIA_FIND_VALUE_MORE).
    assert!(
        sanitize_res_contacts(
            &contacts,
            responder,
            KADEMLIA_FIND_VALUE_MORE as usize,
            None,
        )
        .is_some()
    );
    // From an ordinary value-lookup contact: rejected (11 > KADEMLIA_FIND_VALUE).
    assert!(
        sanitize_res_contacts(&contacts, responder, KADEMLIA_FIND_VALUE as usize, None).is_none()
    );
    let _ = target;
}

// ── FINDBUDDY walk (oracle CSearch type FINDBUDDY) ──────────────────────────

fn find_buddy_request(target: NodeId) -> FindBuddyReq {
    FindBuddyReq {
        buddy_id: target,
        client_hash: Ed2kHash::from_bytes([0xC1; 16]),
        tcp_port: 4662,
    }
}

/// Oracle `CSearch::GetRequestContactCount` (Search.cpp:1653-1657) maps
/// FINDBUDDY together with the STORE searches to KADEMLIA_STORE (0x04).
#[test]
fn find_buddy_req_count_is_the_store_contact_count() {
    let kind = TraversalKind::FindBuddy {
        request: find_buddy_request(NodeId::from_bytes([0x55; 16])),
    };
    assert_eq!(req_count_for_kind(&kind), KADEMLIA_STORE);
    assert_eq!(KADEMLIA_STORE, 0x04);
}

/// Every KADEMLIA2_REQ of the buddy walk must carry the STORE contact count
/// byte on the wire (previously the walk was a FindNode lookup asking 0x0B).
#[tokio::test]
async fn test_find_buddy_walk_req_carries_store_contact_count() {
    let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
    let rpc = RpcManager::new(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig::default(),
    );
    let _handle = rpc.start();

    let target = NodeId::from_bytes([0x55; 16]);
    let contact = TraversalContact {
        id: NodeId::from_bytes([0x12; 16]),
        addr: "192.168.1.50:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };

    let _ = run_traversal(
        &rpc,
        vec![contact.clone()],
        TraversalConfig {
            target,
            search_kind: TraversalKind::FindBuddy {
                request: find_buddy_request(target),
            },
            timeout: Duration::from_millis(100),
            query_timeout: Duration::from_millis(40),
            phase2_fanout: emulebb_kad_proto::constants::SEARCHFINDBUDDY_TOTAL,
            cancel: CancellationToken::new(),
            result_tx: None,
            work_class: RpcWorkClass::Interactive,
            ip_filter: None,
            res_contact_sink: None,
        },
    )
    .await;

    let outgoing = transport.drain_outgoing();
    assert!(!outgoing.is_empty(), "expected the walk to send a REQ");
    assert_eq!(outgoing[0].0, contact.addr);
    let packet = KadPacket::decode(&outgoing[0].1).unwrap();
    let KadPacket::Req(req) = packet else {
        panic!("expected KADEMLIA2_REQ");
    };
    assert_eq!(req.count, KADEMLIA_STORE);
    assert_eq!(req.target, target);
    assert_eq!(req.recipient_id, contact.id);
}

/// Oracle `CSearch::StorePacket` FINDBUDDY (Search.cpp:864-896): as the walk
/// progresses, a KADEMLIA_FINDBUDDY_REQ with the verified payload (buddy
/// target id + own client hash + own TCP port) goes to EACH responded contact
/// that passes SEARCHTOLERANCE (Search.cpp:536); a too-distant responder is
/// never asked.
#[tokio::test]
async fn test_find_buddy_action_walk_targets_each_tolerated_responder() {
    let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
    let rpc = RpcManager::new(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig::default(),
    );
    let _handle = rpc.start();

    let target = NodeId::from_bytes([0x55; 16]);
    // LAN responder: tolerance-exempt (oracle IsLANIP).
    let lan_contact = TraversalContact {
        id: NodeId::from_bytes([0x11; 16]),
        addr: "192.168.1.60:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };
    // Public responder within tolerance: same high-32 chunk as the target.
    let mut close_id = [0xAA; 16];
    close_id[..4].copy_from_slice(&[0x55; 4]);
    let close_contact = TraversalContact {
        id: NodeId::from_bytes(close_id),
        addr: "8.8.8.10:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };
    // Public responder beyond tolerance: chunk-0 distance 0x55555555.
    let far_contact = TraversalContact {
        id: NodeId::ZERO,
        addr: "8.8.4.4:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };
    let request = find_buddy_request(target);
    let responded = vec![
        lan_contact.clone(),
        close_contact.clone(),
        far_contact.clone(),
    ];

    let _ = run_search_phase(
        &rpc,
        SearchPhaseConfig {
            responded: &responded,
            kind: TraversalKind::FindBuddy {
                request: request.clone(),
            },
            target,
            query_timeout: Duration::from_millis(30),
            deadline: Instant::now() + Duration::from_millis(200),
            phase2_fanout: emulebb_kad_proto::constants::SEARCHFINDBUDDY_TOTAL,
            last_lookup_response_at: None,
            jumpstart_idle_grace: Duration::ZERO,
            jumpstart_tick: Duration::from_millis(5),
            work_class: RpcWorkClass::Interactive,
            cancel: &CancellationToken::new(),
            result_tx: None,
        },
    )
    .await;

    let outgoing = transport.drain_outgoing();
    let mut asked = Vec::new();
    for (addr, bytes) in &outgoing {
        let packet = KadPacket::decode(bytes).unwrap();
        let KadPacket::FindBuddyReq(sent) = packet else {
            panic!("expected KADEMLIA_FINDBUDDY_REQ");
        };
        assert_eq!(sent, request, "FINDBUDDY_REQ payload must be the request");
        asked.push(*addr);
    }
    assert!(asked.contains(&lan_contact.addr), "LAN responder asked");
    assert!(
        asked.contains(&close_contact.addr),
        "tolerated public responder asked"
    );
    assert!(
        !asked.contains(&far_contact.addr),
        "beyond-tolerance responder must be skipped"
    );
    assert_eq!(asked.len(), 2);
}

/// The action walk stops at the oracle answer target: each FINDBUDDY_REQ sent
/// counts as one answer (Search.cpp:892) and the manager stops the search at
/// SEARCHFINDBUDDY_TOTAL (SearchManager.cpp:324), so at most 10 responders are
/// ever asked per search round.
#[tokio::test]
async fn test_find_buddy_action_walk_stops_at_the_oracle_answer_target() {
    let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
    let rpc = RpcManager::new(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig::default(),
    );
    let _handle = rpc.start();

    let target = NodeId::from_bytes([0x55; 16]);
    let responded: Vec<TraversalContact> = (1u8..=12)
        .map(|n| TraversalContact {
            id: NodeId::from_bytes([0, 0, 0, 0, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            addr: format!("192.168.1.{}:4672", n).parse().unwrap(),
            tcp_port: 0,
            version: 9,
        })
        .collect();

    let _ = run_search_phase(
        &rpc,
        SearchPhaseConfig {
            responded: &responded,
            kind: TraversalKind::FindBuddy {
                request: find_buddy_request(target),
            },
            target,
            query_timeout: Duration::from_millis(30),
            // Generous budget: OS timer granularity paces each jump-start emit
            // well above the nominal 1 ms tick; only the send count matters.
            deadline: Instant::now() + Duration::from_secs(2),
            phase2_fanout: emulebb_kad_proto::constants::SEARCHFINDBUDDY_TOTAL,
            last_lookup_response_at: None,
            jumpstart_idle_grace: Duration::ZERO,
            jumpstart_tick: Duration::from_millis(1),
            work_class: RpcWorkClass::Interactive,
            cancel: &CancellationToken::new(),
            result_tx: None,
        },
    )
    .await;

    let outgoing = transport.drain_outgoing();
    assert_eq!(
        outgoing.len(),
        emulebb_kad_proto::constants::SEARCHFINDBUDDY_TOTAL,
        "the walk must ask exactly SEARCHFINDBUDDY_TOTAL responders"
    );
}
