use std::net::{Ipv4Addr, SocketAddr};

use anyhow::Result;
use emulebb_kad_proto::Ed2kHash;

use super::Ed2kFoundSource;

pub(super) fn annotate_found_sources_server(
    mut results: Vec<Ed2kFoundSource>,
    server_endpoint: SocketAddr,
) -> Vec<Ed2kFoundSource> {
    for source in &mut results {
        source.source_server = Some(server_endpoint);
    }
    results
}

pub(super) fn ipv4_from_client_id(client_id: u32) -> Ipv4Addr {
    Ipv4Addr::from(client_id.to_le_bytes())
}

pub(super) fn validate_found_sources(
    results: &[Ed2kFoundSource],
    expected_file_hash: Ed2kHash,
) -> Result<()> {
    for source in results {
        if source.file_hash != expected_file_hash {
            anyhow::bail!(
                "ED2K found-sources reply referenced unexpected file hash {} expected {}",
                source.file_hash,
                expected_file_hash
            );
        }
    }
    Ok(())
}

pub(super) fn merge_found_sources(
    aggregated_results: &mut Vec<Ed2kFoundSource>,
    new_results: Vec<Ed2kFoundSource>,
) {
    for source in new_results {
        if let Some(existing) = aggregated_results
            .iter_mut()
            .find(|existing| existing.identity_key() == source.identity_key())
        {
            existing.merge_discovery_metadata_from(&source);
            continue;
        }
        aggregated_results.push(source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(low_id: bool, source_server: SocketAddr) -> Ed2kFoundSource {
        Ed2kFoundSource {
            file_hash: Ed2kHash::from_bytes([0x11; 16]),
            ip: Ipv4Addr::new(0, 0, 0, 17),
            tcp_port: 4662,
            client_id: 17,
            low_id,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: Some([0x22; 16]),
            source_server: Some(source_server),
            buddy_id: None,
            buddy_endpoint: None,
            source_udp_port: None,
        }
    }

    #[test]
    fn merge_keeps_low_ids_from_different_server_namespaces() {
        let server_a = "192.0.2.1:4661".parse().unwrap();
        let server_b = "192.0.2.2:4661".parse().unwrap();
        let mut sources = vec![source(true, server_a)];

        merge_found_sources(&mut sources, vec![source(true, server_b)]);

        assert_eq!(sources.len(), 2);
    }

    #[test]
    fn merge_deduplicates_high_ids_reported_by_different_servers() {
        let server_a = "192.0.2.1:4661".parse().unwrap();
        let server_b = "192.0.2.2:4661".parse().unwrap();
        let mut first = source(false, server_a);
        first.user_hash = None;
        first.obfuscation_options = None;
        let mut enriched = source(false, server_b);
        enriched.obfuscation_options = Some(0x03);
        let mut sources = vec![first];

        merge_found_sources(&mut sources, vec![enriched]);

        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].source_server, Some(server_a));
        assert_eq!(sources[0].user_hash, Some([0x22; 16]));
        assert_eq!(sources[0].obfuscation_options, Some(0x03));
    }
}
