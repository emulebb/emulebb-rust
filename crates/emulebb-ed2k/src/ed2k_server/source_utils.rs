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
        if let Some(existing) = aggregated_results.iter_mut().find(|existing| {
            existing.ip == source.ip
                && existing.tcp_port == source.tcp_port
                && existing.obfuscation_options == source.obfuscation_options
                && existing.user_hash == source.user_hash
        }) {
            if existing.source_server.is_none() && source.source_server.is_some() {
                existing.source_server = source.source_server;
            }
            continue;
        }
        aggregated_results.push(source);
    }
}
