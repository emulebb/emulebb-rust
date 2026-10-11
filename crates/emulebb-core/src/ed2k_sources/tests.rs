use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use emulebb_ed2k::config::Ed2kRuntimeConfig;
use emulebb_ed2k::ed2k_server::Ed2kFoundSource;
use emulebb_kad_dht::SourceResult;
use emulebb_kad_proto::Ed2kHash;

use super::{
    ED2K_DIRECT_CALLBACK_COOLDOWN, ED2K_SERVER_CALLBACK_COOLDOWN,
    cancel_ed2k_direct_callback_request, cancel_ed2k_server_callback_request,
    claim_ed2k_direct_callback_request, claim_ed2k_server_callback_request,
    commit_ed2k_direct_callback_request, commit_ed2k_server_callback_request,
    configured_server_attempts, ed2k_server_callback_permitted,
    global_udp_source_batch_server_attempts, kad_source_result_to_ed2k_found_source,
    merge_download_sources,
};

fn kad_source(udp_port: u16) -> SourceResult {
    SourceResult {
        file_hash: Ed2kHash::from_bytes([0x31; 16]),
        source_id: Ed2kHash::from_bytes([0x32; 16]),
        ip: Ipv4Addr::new(198, 51, 100, 44),
        tcp_port: 4662,
        udp_port,
        obfuscation_options: Some(0x03),
        source_type: 1,
        buddy_id: None,
        buddy_ip: None,
        buddy_port: 0,
    }
}

#[test]
fn kad_high_id_source_preserves_nonzero_source_udp_port() {
    let source = kad_source_result_to_ed2k_found_source(kad_source(4672)).expect("mapped");

    assert!(!source.low_id);
    assert!(source.is_direct_dialable());
    assert_eq!(source.source_udp_port, Some(4672));
    assert_eq!(
        kad_source_result_to_ed2k_found_source(kad_source(0))
            .expect("mapped")
            .source_udp_port,
        None
    );
}

#[test]
fn kad_source_type_6_maps_to_direct_callback_only_and_gates_on_crypt_bit() {
    // Oracle KademliaSearchFile case 6: firewalled, reachable only by direct
    // UDP callback; dropped when the connect options lack bit 0x08.
    let mut result = kad_source(4672);
    result.source_type = 6;
    result.obfuscation_options = Some(0x0B);
    let source = kad_source_result_to_ed2k_found_source(result.clone()).expect("mapped");
    assert!(source.low_id, "type 6 must never be direct-dialed");
    assert!(!source.is_direct_dialable());
    assert!(!source.has_kad_buddy_reask_target());
    assert!(source.is_direct_callback_source());

    result.obfuscation_options = Some(0x03); // no direct-callback bit
    assert!(kad_source_result_to_ed2k_found_source(result).is_none());
}

#[test]
fn kad_source_type_2_is_dropped() {
    // Oracle: "Don't use this type... Some clients will process it wrong."
    let mut result = kad_source(4672);
    result.source_type = 2;
    assert!(kad_source_result_to_ed2k_found_source(result).is_none());
}

#[test]
fn global_udp_source_batch_attempts_cover_effective_server_list() {
    let mut config = Ed2kRuntimeConfig {
        source_server_attempt_budget: 1,
        server_endpoints: vec![
            "192.0.2.10:4661".to_string(),
            "192.0.2.20:4661".to_string(),
            "192.0.2.30:4661".to_string(),
        ],
        ..Ed2kRuntimeConfig::default()
    };

    assert_eq!(configured_server_attempts(&config), 3);
    assert_eq!(global_udp_source_batch_server_attempts(&config), 3);

    config.server_endpoints.clear();
    assert_eq!(global_udp_source_batch_server_attempts(&config), 1);
}

#[test]
fn server_callback_claim_is_peer_scoped_for_a4af_and_uses_twenty_minute_gate() {
    let mut last_sent = HashMap::new();
    let now = Instant::now();
    let server_a = "192.0.2.1:4661".parse().unwrap();
    let server_b = "192.0.2.2:4661".parse().unwrap();

    let first = claim_ed2k_server_callback_request(&mut last_sent, server_a, 0x1234, now).unwrap();
    assert!(
        claim_ed2k_server_callback_request(
            &mut last_sent,
            server_a,
            0x1234,
            now + Duration::from_secs(30)
        )
        .is_none()
    );
    assert!(
        claim_ed2k_server_callback_request(
            &mut last_sent,
            server_b,
            0x1234,
            now + Duration::from_secs(30)
        )
        .is_some()
    );
    assert!(
        claim_ed2k_server_callback_request(
            &mut last_sent,
            server_a,
            0x5678,
            now + Duration::from_secs(30)
        )
        .is_some()
    );
    let committed_at = now + Duration::from_secs(5 * 60);
    assert!(commit_ed2k_server_callback_request(
        &mut last_sent,
        first,
        committed_at,
    ));
    assert!(
        claim_ed2k_server_callback_request(
            &mut last_sent,
            server_a,
            0x1234,
            now + ED2K_SERVER_CALLBACK_COOLDOWN
        )
        .is_none()
    );
    assert!(
        claim_ed2k_server_callback_request(
            &mut last_sent,
            server_a,
            0x1234,
            committed_at + ED2K_SERVER_CALLBACK_COOLDOWN
        )
        .is_some()
    );
}

#[test]
fn server_callback_cooldown_cancel_releases_exact_linear_claim() {
    let mut last_sent = HashMap::new();
    let now = Instant::now();
    let server = "192.0.2.1:4661".parse().unwrap();
    let first = claim_ed2k_server_callback_request(&mut last_sent, server, 0x1234, now).unwrap();

    assert!(cancel_ed2k_server_callback_request(&mut last_sent, first));
    let replacement = claim_ed2k_server_callback_request(
        &mut last_sent,
        server,
        0x1234,
        now + Duration::from_secs(1),
    )
    .unwrap();
    assert!(
        claim_ed2k_server_callback_request(
            &mut last_sent,
            server,
            0x1234,
            now + Duration::from_secs(2),
        )
        .is_none()
    );
    assert!(cancel_ed2k_server_callback_request(
        &mut last_sent,
        replacement
    ));
    assert!(
        claim_ed2k_server_callback_request(
            &mut last_sent,
            server,
            0x1234,
            now + Duration::from_secs(3),
        )
        .is_some()
    );
}

#[test]
fn direct_callback_claim_is_peer_scoped_and_settles_from_dispatch_time() {
    let mut last_sent = HashMap::new();
    let now = Instant::now();
    let source_a = "198.51.100.40:4672".parse().unwrap();
    let source_b = "198.51.100.41:4672".parse().unwrap();
    let hash_a = [0x11; 16];
    let hash_b = [0x22; 16];

    let first = claim_ed2k_direct_callback_request(&mut last_sent, source_a, hash_a, now).unwrap();
    assert!(
        claim_ed2k_direct_callback_request(
            &mut last_sent,
            source_a,
            hash_a,
            now + Duration::from_secs(5),
        )
        .is_none(),
        "the same callback peer is one A4AF session regardless of file"
    );
    assert!(
        claim_ed2k_direct_callback_request(
            &mut last_sent,
            source_b,
            hash_a,
            now + Duration::from_secs(5),
        )
        .is_some(),
        "the UDP route is part of direct callback identity"
    );
    assert!(
        claim_ed2k_direct_callback_request(
            &mut last_sent,
            source_a,
            hash_b,
            now + Duration::from_secs(5),
        )
        .is_some(),
        "a different protocol user hash is a different peer"
    );

    let settled_at = now + Duration::from_secs(10);
    assert!(commit_ed2k_direct_callback_request(
        &mut last_sent,
        first,
        settled_at,
    ));
    assert!(
        claim_ed2k_direct_callback_request(
            &mut last_sent,
            source_a,
            hash_a,
            now + ED2K_DIRECT_CALLBACK_COOLDOWN,
        )
        .is_none(),
        "cooldown starts at dispatch settlement rather than reservation"
    );
    assert!(
        claim_ed2k_direct_callback_request(
            &mut last_sent,
            source_a,
            hash_a,
            settled_at + ED2K_DIRECT_CALLBACK_COOLDOWN,
        )
        .is_some()
    );
}

#[test]
fn direct_callback_cooldown_rollback_is_exact_and_linear() {
    let mut last_sent = HashMap::new();
    let now = Instant::now();
    let source = "198.51.100.40:4672".parse().unwrap();
    let user_hash = [0x11; 16];
    let first = claim_ed2k_direct_callback_request(&mut last_sent, source, user_hash, now).unwrap();

    assert!(cancel_ed2k_direct_callback_request(&mut last_sent, first));
    let stale = claim_ed2k_direct_callback_request(
        &mut last_sent,
        source,
        user_hash,
        now + Duration::from_secs(1),
    )
    .unwrap();
    let key = stale.key.clone();
    last_sent.insert(key, now + Duration::from_secs(2));
    assert!(
        !cancel_ed2k_direct_callback_request(&mut last_sent, stale),
        "an old failure must not clear a newer callback claim"
    );
}

#[test]
fn server_callback_requires_self_high_id_and_a_source_server() {
    use std::net::SocketAddr;

    let connected: SocketAddr = "203.0.113.5:4661".parse().unwrap();
    let other: SocketAddr = "203.0.113.9:4661".parse().unwrap();

    // HighID (not firewalled) + source registered on our connected server:
    // CanDoCallback passes and TryToConnect reaches CCS_SERVERCALLBACK.
    assert!(ed2k_server_callback_permitted(
        false,
        Some(connected),
        Some(connected)
    ));
    // LowID self (firewalled): CanDoCallback forbids the same-server callback
    // ("breaks the protocol and will get us banned") -> no OP_CALLBACKREQUEST.
    assert!(!ed2k_server_callback_permitted(
        true,
        Some(connected),
        Some(connected)
    ));
    // A different source server uses the legacy global UDP callback lane.
    assert!(ed2k_server_callback_permitted(
        false,
        Some(other),
        Some(connected)
    ));
    // Global UDP does not require a current TCP server session.
    assert!(ed2k_server_callback_permitted(false, Some(connected), None));
    // Without source-server provenance neither relay can be addressed.
    assert!(!ed2k_server_callback_permitted(
        false,
        None,
        Some(connected)
    ));
}

fn direct_source(file_hash: Ed2kHash, ip: Ipv4Addr, tcp_port: u16) -> Ed2kFoundSource {
    Ed2kFoundSource {
        file_hash,
        ip,
        tcp_port,
        client_id: u32::from(ip),
        low_id: false,
        obfuscated: false,
        obfuscation_options: None,
        user_hash: None,
        source_server: None,
        buddy_id: None,
        buddy_endpoint: None,
        source_udp_port: None,
    }
}

fn low_id_source(file_hash: Ed2kHash, client_id: u32, server: &str) -> Ed2kFoundSource {
    Ed2kFoundSource {
        file_hash,
        ip: Ipv4Addr::from(client_id.to_le_bytes()),
        tcp_port: 4662,
        client_id,
        low_id: true,
        obfuscated: false,
        obfuscation_options: None,
        user_hash: None,
        source_server: Some(server.parse().unwrap()),
        buddy_id: None,
        buddy_endpoint: None,
        source_udp_port: None,
    }
}

#[test]
fn download_source_merge_keeps_low_ids_from_different_servers() {
    let file_hash = Ed2kHash::from_bytes([0x34; 16]);
    let mut sources = vec![low_id_source(file_hash, 17, "192.0.2.1:4661")];

    merge_download_sources(
        &mut sources,
        vec![low_id_source(file_hash, 17, "192.0.2.2:4661")],
    );

    assert_eq!(sources.len(), 2);
}

#[test]
fn download_source_merge_deduplicates_high_ids_from_different_servers() {
    let file_hash = Ed2kHash::from_bytes([0x35; 16]);
    let mut first = direct_source(file_hash, Ipv4Addr::new(198, 51, 100, 10), 4662);
    first.source_server = Some("192.0.2.1:4661".parse().unwrap());
    let mut duplicate = first.clone();
    duplicate.source_server = Some("192.0.2.2:4661".parse().unwrap());
    let mut sources = vec![first];

    merge_download_sources(&mut sources, vec![duplicate]);

    assert_eq!(sources.len(), 1);
}

#[test]
fn remembered_sources_are_merged_with_non_empty_fresh_sources() {
    let file_hash = Ed2kHash::from_bytes([0x33; 16]);
    let fresh = direct_source(file_hash, Ipv4Addr::new(198, 51, 100, 10), 4662);
    let remembered = direct_source(file_hash, Ipv4Addr::new(198, 51, 100, 20), 4662);
    let duplicate = fresh.clone();
    let mut sources = vec![fresh];

    let before = sources.len();
    merge_download_sources(&mut sources, vec![remembered, duplicate]);

    assert_eq!(sources.len() - before, 1);
    assert_eq!(sources.len(), 2);
    assert!(
        sources
            .iter()
            .any(|source| source.ip == Ipv4Addr::new(198, 51, 100, 10))
    );
    assert!(
        sources
            .iter()
            .any(|source| source.ip == Ipv4Addr::new(198, 51, 100, 20))
    );
}
