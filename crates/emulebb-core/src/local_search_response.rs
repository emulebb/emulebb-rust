//! Local Kad search-response paging.
//!
//! Helpers that answer an inbound Kad search (KADEMLIA2_SEARCH_*) from the local
//! store: `send_local_search_response` splits an oversized stock `SearchRes` into
//! UDP-sized pages (`split_stock_search_responses` + the per-page encoded-length
//! probe) and sends them. Moved verbatim out of `lib.rs` during the
//! maintainability restructuring; they carry no behavior beyond what they had
//! inline. Re-exported `pub(crate)` from the crate root so the inbound packet
//! dispatch and the test module reach them by their bare names.

use std::net::SocketAddr;

use emulebb_kad_dht::DhtNode;
use emulebb_kad_proto::{KadPacket, NodeId, SearchRes, SearchResultEntry};

/// Max stock-search response payload size before paging (eMule splits oversized
/// KADEMLIA2_SEARCH_RES into multiple UDP packets).
const LOCAL_SEARCH_RESPONSE_MAX_PACKET_BYTES: usize = 1420;

pub(crate) async fn send_local_search_response(
    dht: &DhtNode,
    to: SocketAddr,
    response: Option<SearchRes>,
) {
    let Some(response) = response else {
        return;
    };
    for response in split_stock_search_responses(response, LOCAL_SEARCH_RESPONSE_MAX_PACKET_BYTES) {
        let _ = dht.send_packet(to, &KadPacket::SearchRes(response)).await;
    }
}

pub(crate) fn split_stock_search_responses(
    response: SearchRes,
    max_packet_bytes: usize,
) -> Vec<SearchRes> {
    if max_packet_bytes == 0 || response.results.len() <= 1 {
        return vec![response];
    }

    let SearchRes {
        sender_id,
        target,
        results,
    } = response;
    let mut pages = Vec::new();
    let mut current = Vec::new();

    for result in results {
        if current.is_empty() {
            current.push(result);
            continue;
        }

        let mut candidate = current.clone();
        candidate.push(result.clone());
        if encoded_search_response_len(sender_id, target, &candidate) > max_packet_bytes {
            pages.push(SearchRes {
                sender_id,
                target,
                results: current,
            });
            current = vec![result];
        } else {
            current = candidate;
        }
    }

    if !current.is_empty() {
        pages.push(SearchRes {
            sender_id,
            target,
            results: current,
        });
    }

    pages
}

fn encoded_search_response_len(
    sender_id: NodeId,
    target: NodeId,
    results: &[SearchResultEntry],
) -> usize {
    KadPacket::SearchRes(SearchRes {
        sender_id,
        target,
        results: results.to_vec(),
    })
    .encode()
    .map(|packet| packet.len())
    .unwrap_or(usize::MAX)
}
