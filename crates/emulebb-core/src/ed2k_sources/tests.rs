use std::net::Ipv4Addr;

use emulebb_ed2k::config::Ed2kConfig;
use emulebb_kad_dht::SourceResult;
use emulebb_kad_proto::Ed2kHash;

use super::{
    configured_server_attempts, global_udp_source_batch_server_attempts,
    kad_source_result_to_ed2k_found_source,
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
    let source = kad_source_result_to_ed2k_found_source(kad_source(4672));

    assert!(!source.low_id);
    assert!(source.is_direct_dialable());
    assert_eq!(source.source_udp_port, Some(4672));
    assert_eq!(
        kad_source_result_to_ed2k_found_source(kad_source(0)).source_udp_port,
        None
    );
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
