use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use emulebb_ed2k::config::Ed2kConfig;
use emulebb_ed2k::ed2k_server::Ed2kFoundSource;
use emulebb_kad_dht::SourceResult;
use emulebb_kad_proto::Ed2kHash;

use super::{
    ED2K_SERVER_CALLBACK_COOLDOWN, claim_ed2k_server_callback_request, configured_server_attempts,
    ed2k_server_callback_permitted, global_udp_source_batch_server_attempts,
    kad_source_result_to_ed2k_found_source, merge_download_sources,
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
    let mut config = Ed2kConfig {
        source_server_attempt_budget: 1,
        server_endpoints: vec![
            "192.0.2.10:4661".to_string(),
            "192.0.2.20:4661".to_string(),
            "192.0.2.30:4661".to_string(),
        ],
        ..Ed2kConfig::default()
    };

    assert_eq!(configured_server_attempts(&config), 3);
    assert_eq!(global_udp_source_batch_server_attempts(&config), 3);

    config.server_endpoints.clear();
    assert_eq!(global_udp_source_batch_server_attempts(&config), 1);
}

#[test]
fn server_callback_claim_is_per_client_file_and_uses_twenty_minute_gate() {
    let mut last_sent = HashMap::new();
    let now = Instant::now();

    assert!(claim_ed2k_server_callback_request(
        &mut last_sent,
        0x1234,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        now
    ));
    assert!(!claim_ed2k_server_callback_request(
        &mut last_sent,
        0x1234,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        now + Duration::from_secs(30)
    ));
    assert!(claim_ed2k_server_callback_request(
        &mut last_sent,
        0x1234,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        now + Duration::from_secs(30)
    ));
    assert!(claim_ed2k_server_callback_request(
        &mut last_sent,
        0x5678,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        now + Duration::from_secs(30)
    ));
    assert!(claim_ed2k_server_callback_request(
        &mut last_sent,
        0x1234,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        now + ED2K_SERVER_CALLBACK_COOLDOWN
    ));
}

#[test]
fn server_callback_requires_self_high_id_and_same_server() {
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
    // HighID but the source is on a different server: TryToConnect never enters
    // the server-callback branch (IsLocalServer is false).
    assert!(!ed2k_server_callback_permitted(
        false,
        Some(other),
        Some(connected)
    ));
    // No connected server at all -> unavailable.
    assert!(!ed2k_server_callback_permitted(
        false,
        Some(connected),
        None
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
