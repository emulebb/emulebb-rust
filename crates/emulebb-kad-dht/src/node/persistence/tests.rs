use super::*;
use crate::DhtConfig;

fn contact(id: u8, ip: Ipv4Addr) -> Contact {
    Contact {
        id: NodeId::from_bytes([id; 16]),
        ip,
        udp_port: 20020,
        tcp_port: 20019,
        kad_version: 9,
        udp_key: KadUdpKey::new(0x1234_5678),
        udp_key_ip: Some(Ipv4Addr::new(198, 51, 100, 5)),
        hello_source_udp_port: Some(20021),
        udp_firewalled: true,
        tcp_firewalled: true,
        requests_hello_res_ack: true,
        received_hello_packet: true,
        verified: true,
        contact_type: ContactType::Active,
        probe_type: 1,
        bootstrap: true,
        expires_at: Some(UNIX_EPOCH + Duration::from_secs(1_900_000_000)),
        last_type_set_at: Some(UNIX_EPOCH + Duration::from_secs(1_700_000_010)),
        last_seen: UNIX_EPOCH + Duration::from_secs(1_700_000_005),
        created_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    }
}

async fn node() -> DhtNode {
    DhtNode::new(DhtConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        ..DhtConfig::default()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn compact_projection_ignores_unrelated_key_changes_and_tracks_bound_key() {
    let dht = node().await;
    let source = contact(1, Ipv4Addr::new(192, 0, 2, 1));
    dht.add_contact(source.clone()).await.unwrap();
    dht.set_public_ip_for_udp_keys(Some(Ipv4Addr::new(198, 51, 100, 6)))
        .await;
    let before = dht.capture_routing_projection().await.unwrap();
    dht.register_peer_key("192.0.2.2:20020".parse().unwrap(), 55);
    let unrelated = dht.capture_routing_projection().await.unwrap();
    assert_ne!(before.token.keys, unrelated.token.keys);
    assert!(!unrelated.differs_from(&before));
    dht.register_peer_key(SocketAddr::new(IpAddr::V4(source.ip), source.udp_port), 99);
    let changed = dht.capture_routing_projection().await.unwrap();
    assert!(changed.differs_from(&unrelated));
    assert_eq!(changed.keys[0].key, KadUdpKey::new(99));
    assert_eq!(
        changed.keys[0].binding,
        Some(Ipv4Addr::new(198, 51, 100, 6))
    );
    assert!(RoutingProjection::reservation_bytes(DEFAULT_MAX_SIZE).unwrap() < 8 * 1024 * 1024);
    assert_eq!(
        RoutingProjection::reservation_bytes(DEFAULT_MAX_SIZE + 1),
        None
    );
}

#[tokio::test]
async fn full_contact_roundtrips_and_learned_key_overlays_with_binding() {
    let source = contact(1, Ipv4Addr::new(192, 0, 2, 1));
    let record = RoutingSnapshotContact::try_from(&source).unwrap();
    let converted = Contact::try_from(&record).unwrap();
    assert_eq!(
        RoutingSnapshotContact::try_from(&converted).unwrap(),
        record
    );
    let dht = node().await;
    let outcome = dht
        .restore_routing_snapshot(
            std::slice::from_ref(&record),
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        )
        .await
        .unwrap();
    assert_eq!(
        outcome,
        RoutingRestoreOutcome {
            accepted: 1,
            expired: 0,
            rejected: 0
        }
    );
    assert_eq!(
        dht.capture_routing_snapshot().await.unwrap(),
        vec![record.clone()]
    );
    let public_ip = Ipv4Addr::new(198, 51, 100, 6);
    dht.set_public_ip_for_udp_keys(Some(public_ip)).await;
    dht.register_peer_key(
        SocketAddr::new(IpAddr::V4(source.ip), source.udp_port),
        0x5566_7788,
    );
    let saved = dht.capture_routing_snapshot().await.unwrap().pop().unwrap();
    assert_eq!(saved.udp_key, KadUdpKey::new(0x5566_7788));
    assert_eq!(saved.udp_key_ip, Some(public_ip));
    let mut stale = record.clone();
    stale.udp_key_ip = Some(public_ip);
    dht.restore_routing_snapshot(&[stale], UNIX_EPOCH + Duration::from_secs(1_800_000_000))
        .await
        .unwrap();
    let after_restore = dht.capture_routing_snapshot().await.unwrap().pop().unwrap();
    assert_eq!(after_restore.udp_key, KadUdpKey::new(0x5566_7788));
    assert_eq!(after_restore.udp_key_ip, Some(public_ip));
    dht.set_public_ip_for_udp_keys(None).await;
    let unbound = dht.capture_routing_snapshot().await.unwrap().pop().unwrap();
    assert_eq!(unbound.udp_key, record.udp_key);
    assert_eq!(unbound.udp_key_ip, record.udp_key_ip);
}

#[tokio::test]
async fn restore_rejects_expiry_collisions_and_preserves_stronger_live_state() {
    let dht = node().await;
    let live = contact(2, Ipv4Addr::new(192, 0, 2, 2));
    dht.add_contact(live.clone()).await.unwrap();
    let mut weaker = RoutingSnapshotContact::try_from(&live).unwrap();
    weaker.version = 1;
    weaker.udp_key = KadUdpKey::ZERO;
    weaker.udp_key_ip = None;
    weaker.verified = false;
    weaker.last_seen_at_seconds -= 100;
    let mut conflicting = RoutingSnapshotContact::try_from(&contact(3, live.ip)).unwrap();
    conflicting.udp_port += 1;
    let mut expired =
        RoutingSnapshotContact::try_from(&contact(4, Ipv4Addr::new(192, 0, 2, 4))).unwrap();
    expired.expires_at_seconds = Some(1_799_999_999);
    let result = dht
        .restore_routing_snapshot(
            &[weaker, conflicting, expired],
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        )
        .await
        .unwrap();
    assert_eq!(
        result,
        RoutingRestoreOutcome {
            accepted: 1,
            expired: 1,
            rejected: 1
        }
    );
    let saved = dht.capture_routing_snapshot().await.unwrap();
    assert_eq!(
        saved,
        vec![RoutingSnapshotContact::try_from(&live).unwrap()]
    );
}

#[tokio::test]
async fn bounds_and_invalid_records_fail_before_mutation() {
    let dht = node().await;
    let valid = RoutingSnapshotContact::try_from(&contact(5, Ipv4Addr::new(192, 0, 2, 5))).unwrap();
    let mut invalid = valid.clone();
    invalid.created_at_seconds = -1;
    assert!(matches!(
        dht.restore_routing_snapshot(&[valid.clone(), invalid], UNIX_EPOCH)
            .await,
        Err(DhtError::InvalidRoutingSnapshot)
    ));
    assert!(matches!(
        dht.restore_routing_snapshot(&vec![valid; DEFAULT_MAX_SIZE + 1], UNIX_EPOCH)
            .await,
        Err(DhtError::RoutingSnapshotTooLarge)
    ));
    assert!(dht.capture_routing_snapshot().await.unwrap().is_empty());
    let mut before_epoch = contact(6, Ipv4Addr::new(192, 0, 2, 6));
    before_epoch.created_at = UNIX_EPOCH - Duration::from_secs(1);
    assert!(matches!(
        RoutingSnapshotContact::try_from(&before_epoch),
        Err(DhtError::InvalidRoutingSnapshot)
    ));
}

#[tokio::test]
async fn capture_and_public_address_transition_share_a_binding_gate() {
    let dht = node().await;
    let peer = contact(7, Ipv4Addr::new(192, 0, 2, 7));
    dht.add_contact(peer.clone()).await.unwrap();
    let old = Ipv4Addr::new(198, 51, 100, 7);
    let new = Ipv4Addr::new(198, 51, 100, 8);
    dht.set_public_ip_for_udp_keys(Some(old)).await;
    dht.register_peer_key(
        SocketAddr::new(IpAddr::V4(peer.ip), peer.udp_port),
        0x1122_3344,
    );
    let guard = dht.inner.key_binding_gate.lock().await;
    let transition = {
        let dht = dht.clone();
        tokio::spawn(async move { dht.set_public_ip_for_udp_keys(Some(new)).await })
    };
    let capture = {
        let dht = dht.clone();
        tokio::spawn(async move { dht.capture_routing_snapshot().await.unwrap() })
    };
    tokio::task::yield_now().await;
    assert!(!transition.is_finished());
    assert!(!capture.is_finished());
    drop(guard);
    transition.await.unwrap();
    let saved = capture.await.unwrap().pop().unwrap();
    assert!(!(saved.udp_key == KadUdpKey::new(0x1122_3344) && saved.udp_key_ip == Some(new)));
}

#[tokio::test]
async fn compact_capture_cannot_mix_old_key_with_new_binding() {
    let dht = node().await;
    let peer = contact(8, Ipv4Addr::new(192, 0, 2, 8));
    dht.add_contact(peer.clone()).await.unwrap();
    let old = Ipv4Addr::new(198, 51, 100, 7);
    let new = Ipv4Addr::new(198, 51, 100, 8);
    dht.set_public_ip_for_udp_keys(Some(old)).await;
    dht.register_peer_key(SocketAddr::new(IpAddr::V4(peer.ip), peer.udp_port), 42);
    let guard = dht.inner.key_binding_gate.lock().await;
    let transition = {
        let dht = dht.clone();
        tokio::spawn(async move { dht.set_public_ip_for_udp_keys(Some(new)).await })
    };
    let capture = {
        let dht = dht.clone();
        tokio::spawn(async move { dht.capture_routing_projection().await.unwrap() })
    };
    tokio::task::yield_now().await;
    assert!(!transition.is_finished());
    assert!(!capture.is_finished());
    drop(guard);
    transition.await.unwrap();
    let projection = capture.await.unwrap();
    let key = &projection.keys[0];
    assert!(!(key.key == KadUdpKey::new(42) && key.binding == Some(new)));
}
