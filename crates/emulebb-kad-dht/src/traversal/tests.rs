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
                version: 9,
            },
            state: CandidateState::Pending,
            distance: target.distance(&NodeId::from_bytes([0xFF; 16])),
        },
        TraversalCandidate {
            contact: TraversalContact {
                id: NodeId::from_bytes([0x01; 16]),
                addr: "127.0.0.1:2".parse().unwrap(),
                version: 9,
            },
            state: CandidateState::Pending,
            distance: target.distance(&NodeId::from_bytes([0x01; 16])),
        },
    ];
    candidates.sort_by(|a, b| a.distance.cmp(&b.distance));
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

    let sanitized =
        sanitize_res_contacts(&contacts, "9.9.9.9:4672".parse().unwrap(), 10, Some(&filter))
            .expect("sanitized");
    assert_eq!(sanitized.len(), 1, "the banned contact must be dropped");
    assert_eq!(sanitized[0].ip_addr(), Ipv4Addr::new(20, 21, 22, 23));

    // Without the hook, both contacts are kept (filter disabled).
    let unfiltered =
        sanitize_res_contacts(&contacts, "9.9.9.9:4672".parse().unwrap(), 10, None)
            .expect("sanitized");
    assert_eq!(unfiltered.len(), 2);
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
            version: 9,
        },
        state: CandidateState::Inflight,
        distance: NodeId::from_bytes([0; 16]),
    });

    assert!(!find_node_lookup_converged(&candidates));
}

#[test]
fn test_select_phase2_contacts_caps_fanout_at_oracle_k() {
    let target = NodeId::ZERO;
    let responded: Vec<TraversalContact> = (1u8..=20)
        .map(|n| TraversalContact {
            id: NodeId::from_bytes([0, 0, 0, 0, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            addr: format!("192.168.1.{}:4672", n).parse().unwrap(),
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
            version: 9,
        })
        .collect();

    let selected = select_phase2_contacts(&responded, target, 3);
    assert_eq!(selected.len(), 3);
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
            version: 9,
        },
        TraversalContact {
            id: NodeId::from_bytes([0x22; 16]),
            addr: "192.168.1.32:4672".parse().unwrap(),
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
