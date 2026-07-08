//! Routing a firewalled LowID Kad source onto the UDP reask loop via its Kad
//! buddy.
//!
//! A Kad source of `FT_SOURCETYPE` 3 or 5 is a firewalled LowID peer reachable
//! only through its Kad **buddy** (oracle `CDownloadQueue::KademliaSearchFile`).
//! Such a source never gets a direct TCP session to detach from, so it is
//! registered straight onto the UDP reask loop here: the loop then originates an
//! `OP_REASKCALLBACKUDP` to the buddy on the normal reask cadence (oracle
//! `UDPReaskForDownload`'s LowID/buddy branch). The buddy id + buddy relay
//! endpoint ride on [`Ed2kFoundSource`] from the Kad source result (see
//! [`crate::ed2k_sources::kad_source_result_to_ed2k_found_source`]). Pure routing
//! glue: it builds the [`ReaskDetachArgs`] and hands them to the reask handle.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;

use emulebb_ed2k::{ReaskDetachArgs, ReaskSourceHandle, ed2k_server::Ed2kFoundSource};
use emulebb_kad_proto::Ed2kHash;

use crate::ed2k_sources::source_key;

/// Our eD2k client-UDP protocol version (oracle current `KADEMLIA_VERSION`-era
/// reask shape). Used to frame buddy-relayed reasks for Kad sources whose own UDP
/// version is unknown (only learned over a TCP `OP_EMULEINFO`, which never happens
/// for a firewalled-buddy Kad source).
const ED2K_DEFAULT_UDP_VERSION: u8 = 4;

type RequestedCallbackSources = HashSet<(Ipv4Addr, u16, Option<[u8; 16]>, Option<u8>)>;

/// Detach every firewalled LowID Kad source with a known buddy onto the UDP reask
/// loop so it originates an `OP_REASKCALLBACKUDP` to its buddy on the normal
/// cadence (oracle `CDownloadQueue::KademliaSearchFile` source types 3/5, reasked
/// via `UDPReaskForDownload`'s LowID/buddy branch). Each source is registered once:
/// it shares the `requested_callback_sources` dedup set with the eD2k-server
/// callback path so a buddy source is never also `OP_CALLBACKREQUEST`'d. Does
/// nothing when UDP reask is disabled (`reask_handle` is `None`).
pub(crate) fn detach_kad_buddy_sources_for_reask(
    reask_handle: Option<&ReaskSourceHandle>,
    file_hash: Ed2kHash,
    sources: &[Ed2kFoundSource],
    requested_callback_sources: &mut RequestedCallbackSources,
) {
    let Some(reask_handle) = reask_handle else {
        return; // UDP reask disabled
    };
    for source in sources
        .iter()
        .filter(|source| source.has_kad_buddy_reask_target())
    {
        let (Some(buddy_id), Some(buddy_endpoint)) = (source.buddy_id, source.buddy_endpoint)
        else {
            continue;
        };
        if !requested_callback_sources.insert(source_key(source)) {
            continue;
        }
        // The source UDP-answers from its own eD2k UDP endpoint after the buddy
        // relays our callback, so the reask pending gate keys on it. Fall back to
        // the TCP port only if the Kad result carried no UDP port.
        let endpoint = (source.ip, source.source_udp_port.unwrap_or(source.tcp_port));
        let registered = reask_handle.register_kad_buddy_source(ReaskDetachArgs {
            file_hash,
            endpoint,
            // Core's lease key port (source_endpoint_key). A buddy source holds
            // no direct-download lease, but its release events must still be
            // addressed consistently by the TCP key.
            tcp_port: source.tcp_port,
            udp_version: ED2K_DEFAULT_UDP_VERSION,
            // Kad buddy sources have no direct TCP file request to timestamp, so
            // the first buddy-relayed UDP reask is due immediately.
            initial_reask_delay: Duration::ZERO,
            user_hash: source.user_hash,
            should_crypt: source.obfuscation_options.is_some(),
            low_id: true,
            buddy_endpoint: Some(buddy_endpoint),
            buddy_id: Some(buddy_id),
        });
        tracing::info!(
            "ED2K Kad buddy source detached onto UDP reask file_hash={} source={}:{} buddy={}:{} registered={registered}",
            file_hash,
            endpoint.0,
            endpoint.1,
            buddy_endpoint.0,
            buddy_endpoint.1,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_sources::kad_source_result_to_ed2k_found_source;
    use emulebb_ed2k::{ReaskCommand, reask_command_channel};
    use emulebb_kad_dht::SourceResult;

    fn buddy_source(file_hash: Ed2kHash) -> Ed2kFoundSource {
        Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::new(192, 0, 2, 77),
            tcp_port: 4662,
            client_id: u32::from(Ipv4Addr::new(192, 0, 2, 77)),
            low_id: true,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
            buddy_id: Some([0x5a; 16]),
            buddy_endpoint: Some((Ipv4Addr::new(198, 51, 100, 9), 5000)),
            source_udp_port: Some(4672),
        }
    }

    #[test]
    fn kad_firewalled_buddy_source_maps_to_low_id_with_buddy_target() {
        // Oracle Kad source type 3: a firewalled LowID source carrying its buddy
        // id + buddy relay endpoint maps to a LowID source with a buddy reask target.
        let file_hash = Ed2kHash::from_bytes([0x4b; 16]);
        let source_id = Ed2kHash::from_bytes([0x4c; 16]);
        let buddy_id = [0x5a; 16];
        let source = kad_source_result_to_ed2k_found_source(SourceResult {
            file_hash,
            source_id,
            ip: Ipv4Addr::new(192, 0, 2, 77),
            tcp_port: 4662,
            udp_port: 4672,
            obfuscation_options: None,
            source_type: 3,
            buddy_id: Some(buddy_id),
            buddy_ip: Some(Ipv4Addr::new(198, 51, 100, 9)),
            buddy_port: 5000,
        })
        .expect("mapped source");

        assert!(source.low_id);
        assert_eq!(source.buddy_id, Some(buddy_id));
        assert_eq!(
            source.buddy_endpoint,
            Some((Ipv4Addr::new(198, 51, 100, 9), 5000))
        );
        assert_eq!(source.source_udp_port, Some(4672));
        assert!(source.has_kad_buddy_reask_target());
        assert!(!source.is_direct_dialable());
    }

    #[test]
    fn detaches_kad_buddy_source_with_buddy_args_and_dedups() {
        let file_hash = Ed2kHash::from_bytes([0x4d; 16]);
        let (handle, mut rx) = reask_command_channel();
        let sources = vec![buddy_source(file_hash)];
        let mut requested = HashSet::new();

        detach_kad_buddy_sources_for_reask(Some(&handle), file_hash, &sources, &mut requested);

        // Exactly one Register command carrying the buddy id + endpoint, keyed on
        // the source's own eD2k UDP endpoint.
        match rx.try_recv().expect("a buddy registration") {
            ReaskCommand::Register(args) => {
                assert_eq!(args.file_hash, file_hash);
                assert!(args.low_id);
                assert_eq!(args.endpoint, (Ipv4Addr::new(192, 0, 2, 77), 4672));
                assert_eq!(args.tcp_port, 4662);
                assert_eq!(args.buddy_id, Some([0x5a; 16]));
                assert_eq!(
                    args.buddy_endpoint,
                    Some((Ipv4Addr::new(198, 51, 100, 9), 5000))
                );
            }
            other => panic!("expected Register, got {other:?}"),
        }
        // The source is now in the dedup set, so a second pass registers nothing.
        detach_kad_buddy_sources_for_reask(Some(&handle), file_hash, &sources, &mut requested);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn skips_non_buddy_sources_and_a_disabled_reask_loop() {
        let file_hash = Ed2kHash::from_bytes([0x4e; 16]);
        let mut requested = HashSet::new();

        // A HighID source (no buddy) is never detached onto reask.
        let mut high_id = buddy_source(file_hash);
        high_id.low_id = false;
        high_id.buddy_id = None;
        high_id.buddy_endpoint = None;
        let (handle, mut rx) = reask_command_channel();
        detach_kad_buddy_sources_for_reask(Some(&handle), file_hash, &[high_id], &mut requested);
        assert!(rx.try_recv().is_err());
        assert!(requested.is_empty());

        // A buddy source is a no-op when UDP reask is disabled (no handle).
        detach_kad_buddy_sources_for_reask(
            None,
            file_hash,
            &[buddy_source(file_hash)],
            &mut requested,
        );
        assert!(requested.is_empty());
    }
}
