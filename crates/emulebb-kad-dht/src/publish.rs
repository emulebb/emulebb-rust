//! Kad publish flows built on top of the generic lookup traversal.
//!
//! Each helper in this module first resolves the closest contacts to the target
//! and then fans the publish packet out concurrently. The returned stats are
//! intentionally contact-oriented because acceptance on the live Kad network is
//! a per-contact outcome rather than a single transaction-wide success bit.

use crate::error::DhtError;
use crate::traversal::{TraversalConfig, TraversalContact, TraversalKind, run_traversal};
use emulebb_kad_net::{RpcManager, RpcWorkClass};
use emulebb_kad_proto::constants::{
    KAD_VERSION_AICH_KEYWORD_PUBLISH, SEARCHTOLERANCE, STORE_TIMEOUT_SECS,
};
use emulebb_kad_proto::{
    Ed2kHash, KadPacket, NodeId, Tag,
    constants::K,
    opcode,
    packet::{PublishEntry, PublishKeyReq, PublishNotesReq, PublishSourceReq},
};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const PUBLISH_TIMEOUT: Duration = Duration::from_secs(STORE_TIMEOUT_SECS);
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const PUBLISH_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Summarizes the outcome of a Kad publish fanout over the closest contacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PublishAttemptStats {
    pub closest_contacts_considered: u32,
    pub attempted_contacts: u32,
    pub acked_contacts: u32,
    pub timed_out_contacts: u32,
}

impl PublishAttemptStats {
    #[must_use]
    pub fn failed_contacts(self) -> u32 {
        self.attempted_contacts.saturating_sub(self.acked_contacts)
    }
}

/// Captures one in-flight publish RPC so the caller can log and aggregate the
/// result after the concurrent fanout completes.
#[derive(Debug, Clone)]
struct PublishAttempt {
    rank: u32,
    total: u32,
    contact: TraversalContact,
}

/// Full keyword publish payload and scheduler settings.
#[derive(Debug, Clone)]
pub struct KeywordPublishRequest {
    pub keyword_hash: NodeId,
    pub file_hash: Ed2kHash,
    pub tags: Vec<Tag>,
    pub aich_hash: Option<[u8; 20]>,
    pub publish_contact_fanout: usize,
    pub work_class: RpcWorkClass,
}

/// Send the publish RPC to all selected contacts concurrently so the live wire
/// shape stays bursty while the caller can widen contact coverage for harvest.
async fn execute_publish_fanout(
    rpc: &RpcManager,
    contacts: &[TraversalContact],
    packet: &KadPacket,
    work_class: RpcWorkClass,
) -> Vec<(PublishAttempt, Result<KadPacket, emulebb_kad_net::NetError>)> {
    let mut join_set = JoinSet::new();
    let total = contacts.len() as u32;

    for (index, contact) in contacts.iter().cloned().enumerate() {
        let rpc = rpc.clone();
        let packet = packet.clone();
        let attempt = PublishAttempt {
            rank: index as u32 + 1,
            total,
            contact,
        };
        join_set.spawn(async move {
            let result = rpc
                .request_with_class(
                    attempt.contact.addr,
                    &packet,
                    opcode::PUBLISH_RES,
                    PUBLISH_RESPONSE_TIMEOUT,
                    work_class,
                )
                .await;
            (attempt, result)
        });
    }

    let mut results = Vec::with_capacity(contacts.len());
    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok(result) => results.push(result),
            Err(error) => {
                tracing::warn!("publish request task failed to join: {error}");
            }
        }
    }

    results
}

/// Select the traversal contacts that should receive this publish round.
///
/// A zero configuration value falls back to one contact so a misconfigured
/// runtime still emits publishes instead of silently disabling them.
///
/// Publish receivers apply a much stricter target-distance gate than Kad
/// search phase 2. We therefore filter the traversal output here so the Rust
/// client only spends publish budget on contacts that the eMule harness would
/// accept.
fn select_publish_contacts(
    target: NodeId,
    contacts: &[TraversalContact],
    publish_contact_fanout: usize,
) -> Vec<TraversalContact> {
    contacts
        .iter()
        .filter(|contact| publish_target_is_within_tolerance(target, contact))
        .take(publish_contact_fanout.max(1))
        .cloned()
        .collect()
}

/// Return whether this contact would accept a Kad publish for `target`.
///
/// The stock eMule publish handlers reject requests whose XOR distance first
/// 32-bit chunk exceeds `SEARCHTOLERANCE`, but they bypass that gate for LAN
/// peers. Our local loopback parity clusters now deliberately run in that LAN
/// mode, so publish fanout has to mirror the same exemption instead of
/// suppressing loopback contacts before the packet is sent.
fn publish_target_is_within_tolerance(target: NodeId, contact: &TraversalContact) -> bool {
    match contact.addr.ip() {
        IpAddr::V4(ip) if ip.is_private() || ip.is_loopback() || ip.is_link_local() => true,
        IpAddr::V4(_) => publish_distance_high32(target.distance(&contact.id)) <= SEARCHTOLERANCE,
        IpAddr::V6(_) => false,
    }
}

fn publish_distance_high32(distance: NodeId) -> u32 {
    u32::from_le_bytes([distance.0[0], distance.0[1], distance.0[2], distance.0[3]])
}

/// Publish a keyword→file mapping.
/// Returns the number of nodes that acknowledged.
pub async fn publish_keyword(
    rpc: &RpcManager,
    routing_table: &tokio::sync::Mutex<emulebb_kad_routing::RoutingTable>,
    request: KeywordPublishRequest,
) -> Result<PublishAttemptStats, DhtError> {
    let KeywordPublishRequest {
        keyword_hash,
        file_hash,
        tags,
        aich_hash,
        publish_contact_fanout,
        work_class,
    } = request;
    let target = keyword_hash;
    let initial = get_initial(routing_table, &target).await;

    let traversal = run_traversal(
        rpc,
        initial,
        TraversalConfig {
            target,
            search_kind: TraversalKind::Store,
            timeout: PUBLISH_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout: publish_contact_fanout.max(K),
            cancel: CancellationToken::new(),
            result_tx: None,
            work_class,
        },
    )
    .await;

    if traversal.closest.is_empty() {
        return Err(DhtError::PublishFailed);
    }

    let publish_contacts =
        select_publish_contacts(target, &traversal.closest, publish_contact_fanout);
    let mut stats = PublishAttemptStats {
        closest_contacts_considered: traversal.closest.len() as u32,
        attempted_contacts: publish_contacts.len() as u32,
        ..PublishAttemptStats::default()
    };
    for contact in &publish_contacts {
        register_publish_contact(rpc, contact);
    }
    for (index, contact) in publish_contacts.iter().enumerate() {
        tracing::debug!(
            "kad publish contact family=keyword step=send rank={}/{} contact_addr={} contact_id={} contact_version={} target={} file_hash={}",
            index + 1,
            stats.attempted_contacts,
            contact.addr,
            contact.id,
            contact.version,
            target,
            file_hash,
        );
    }
    let mut join_set = JoinSet::new();
    let total = publish_contacts.len() as u32;
    for (index, contact) in publish_contacts.iter().cloned().enumerate() {
        let rpc = rpc.clone();
        let packet =
            build_keyword_publish_packet(target, file_hash, &tags, aich_hash, contact.version);
        let attempt = PublishAttempt {
            rank: index as u32 + 1,
            total,
            contact,
        };
        join_set.spawn(async move {
            let result = rpc
                .request_with_class(
                    attempt.contact.addr,
                    &packet,
                    opcode::PUBLISH_RES,
                    PUBLISH_RESPONSE_TIMEOUT,
                    work_class,
                )
                .await;
            (attempt, result)
        });
    }

    let mut results = Vec::with_capacity(publish_contacts.len());
    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok(result) => results.push(result),
            Err(error) => {
                tracing::warn!("publish request task failed to join: {error}");
            }
        }
    }

    for (attempt, result) in results {
        match result {
            Ok(KadPacket::PublishRes(response)) => {
                stats.acked_contacts += 1;
                tracing::debug!(
                    "kad publish contact family=keyword step=ack rank={}/{} contact_addr={} contact_id={} response_target={} response_load={}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    response.target,
                    response.load,
                );
            }
            Ok(other) => {
                stats.acked_contacts += 1;
                tracing::debug!(
                    "kad publish contact family=keyword step=ack rank={}/{} contact_addr={} contact_id={} response_opcode=0x{:02X}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    other.opcode(),
                );
            }
            Err(e) => {
                if matches!(e, emulebb_kad_net::NetError::Timeout { .. }) {
                    stats.timed_out_contacts += 1;
                }
                tracing::debug!(
                    "kad publish contact family=keyword step=fail rank={}/{} contact_addr={} contact_id={} error={}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    e,
                );
                tracing::debug!(
                    "publish_keyword ack failed from {}: {}",
                    attempt.contact.addr,
                    e
                );
            }
        }
    }

    Ok(stats)
}

/// Build the oracle-style keyword publish body for a specific target contact.
///
/// eMule appends the keyword-publish AICH tag only for Kad v9+ peers, so the
/// fanout cannot reuse a single keyword packet body across the whole contact set.
fn build_keyword_publish_packet(
    target: NodeId,
    file_hash: Ed2kHash,
    base_tags: &[Tag],
    aich_hash: Option<[u8; 20]>,
    contact_version: u8,
) -> KadPacket {
    let mut tags = base_tags.to_vec();
    if contact_version >= KAD_VERSION_AICH_KEYWORD_PUBLISH
        && let Some(aich_hash) = aich_hash
    {
        tags.push(Tag::kad_aich_hash_pub(aich_hash));
    }

    let entry = PublishEntry {
        hash: file_hash,
        tags,
    };
    KadPacket::PublishKeyReq(PublishKeyReq {
        target,
        entries: vec![entry],
    })
}

/// Publish source availability for a file.
pub async fn publish_source(
    rpc: &RpcManager,
    routing_table: &tokio::sync::Mutex<emulebb_kad_routing::RoutingTable>,
    publisher_id: NodeId,
    file_hash: Ed2kHash,
    tags: Vec<Tag>,
    publish_contact_fanout: usize,
    work_class: RpcWorkClass,
) -> Result<PublishAttemptStats, DhtError> {
    let target = NodeId::from_be_bytes(file_hash.0);
    let initial = get_initial(routing_table, &target).await;

    let traversal = run_traversal(
        rpc,
        initial,
        TraversalConfig {
            target,
            search_kind: TraversalKind::Store,
            timeout: PUBLISH_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout: publish_contact_fanout.max(K),
            cancel: CancellationToken::new(),
            result_tx: None,
            work_class,
        },
    )
    .await;

    if traversal.closest.is_empty() {
        return Err(DhtError::PublishFailed);
    }

    let packet = KadPacket::PublishSourceReq(PublishSourceReq {
        target,
        publisher_id,
        tags,
    });

    let publish_contacts =
        select_publish_contacts(target, &traversal.closest, publish_contact_fanout);
    let mut stats = PublishAttemptStats {
        closest_contacts_considered: traversal.closest.len() as u32,
        attempted_contacts: publish_contacts.len() as u32,
        ..PublishAttemptStats::default()
    };
    for contact in &publish_contacts {
        register_publish_contact(rpc, contact);
    }
    for (index, contact) in publish_contacts.iter().enumerate() {
        tracing::debug!(
            "kad publish contact family=source step=send rank={}/{} contact_addr={} contact_id={} contact_version={} target={} file_hash={} publisher_id={}",
            index + 1,
            stats.attempted_contacts,
            contact.addr,
            contact.id,
            contact.version,
            target,
            file_hash,
            publisher_id,
        );
    }
    for (attempt, result) in
        execute_publish_fanout(rpc, &publish_contacts, &packet, work_class).await
    {
        match result {
            Ok(KadPacket::PublishRes(response)) => {
                stats.acked_contacts += 1;
                tracing::debug!(
                    "kad publish contact family=source step=ack rank={}/{} contact_addr={} contact_id={} response_target={} response_load={}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    response.target,
                    response.load,
                );
            }
            Ok(other) => {
                stats.acked_contacts += 1;
                tracing::debug!(
                    "kad publish contact family=source step=ack rank={}/{} contact_addr={} contact_id={} response_opcode=0x{:02X}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    other.opcode(),
                );
            }
            Err(e) => {
                if matches!(e, emulebb_kad_net::NetError::Timeout { .. }) {
                    stats.timed_out_contacts += 1;
                }
                tracing::debug!(
                    "kad publish contact family=source step=fail rank={}/{} contact_addr={} contact_id={} error={}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    e,
                );
                tracing::debug!(
                    "publish_source ack failed from {}: {}",
                    attempt.contact.addr,
                    e
                );
            }
        }
    }

    Ok(stats)
}

/// Publish a note/rating for a file.
///
/// The oracle writes the publisher Kad node ID into the second 128-bit field of
/// `KADEMLIA2_PUBLISH_NOTES_REQ`. The wire width matches a file hash, but the
/// semantic meaning is publisher identity and must stay aligned across local
/// store, notes search results, and wire dumps.
pub async fn publish_notes(
    rpc: &RpcManager,
    routing_table: &tokio::sync::Mutex<emulebb_kad_routing::RoutingTable>,
    file_hash: Ed2kHash,
    publisher_id: NodeId,
    tags: Vec<Tag>,
    publish_contact_fanout: usize,
    work_class: RpcWorkClass,
) -> Result<PublishAttemptStats, DhtError> {
    let target = NodeId::from_be_bytes(file_hash.0);
    let initial = get_initial(routing_table, &target).await;

    let traversal = run_traversal(
        rpc,
        initial,
        TraversalConfig {
            target,
            search_kind: TraversalKind::Store,
            timeout: PUBLISH_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout: publish_contact_fanout.max(K),
            cancel: CancellationToken::new(),
            result_tx: None,
            work_class,
        },
    )
    .await;

    if traversal.closest.is_empty() {
        return Err(DhtError::PublishFailed);
    }

    let packet = KadPacket::PublishNotesReq(PublishNotesReq {
        target,
        publisher_id,
        tags,
    });

    let publish_contacts =
        select_publish_contacts(target, &traversal.closest, publish_contact_fanout);
    for contact in &publish_contacts {
        register_publish_contact(rpc, contact);
    }

    let mut stats = PublishAttemptStats {
        closest_contacts_considered: traversal.closest.len() as u32,
        attempted_contacts: publish_contacts.len() as u32,
        ..PublishAttemptStats::default()
    };
    for (attempt, result) in
        execute_publish_fanout(rpc, &publish_contacts, &packet, work_class).await
    {
        match result {
            Ok(KadPacket::PublishRes(response)) => {
                stats.acked_contacts += 1;
                tracing::debug!(
                    "kad publish contact family=notes step=ack rank={}/{} contact_addr={} contact_id={} response_target={} response_load={}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    response.target,
                    response.load
                );
            }
            Ok(response) => {
                tracing::debug!(
                    "kad publish contact family=notes step=ack rank={}/{} contact_addr={} contact_id={} response_opcode=0x{:02X}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    response.opcode()
                );
            }
            Err(e) if matches!(e, emulebb_kad_net::NetError::Timeout { .. }) => {
                stats.timed_out_contacts += 1;
                tracing::debug!(
                    "kad publish contact family=notes step=timeout rank={}/{} contact_addr={} contact_id={} error={}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    e
                );
            }
            Err(e) => {
                tracing::debug!(
                    "kad publish contact family=notes step=fail rank={}/{} contact_addr={} contact_id={} error={}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    e
                );
                tracing::debug!(
                    "publish_notes ack failed from {}: {}",
                    attempt.contact.addr,
                    e
                );
            }
        }
    }

    Ok(stats)
}

async fn get_initial(
    routing_table: &tokio::sync::Mutex<emulebb_kad_routing::RoutingTable>,
    target: &NodeId,
) -> Vec<TraversalContact> {
    let rt = routing_table.lock().await;
    rt.get_closest(target, K)
        .into_iter()
        .map(|c| TraversalContact {
            id: c.id,
            addr: SocketAddr::new(IpAddr::V4(c.ip), c.udp_port),
            version: c.kad_version,
        })
        .collect()
}

/// Register publish-target contact identity before sending the publish request.
///
/// Publish fanout works on traversal results directly, so these contacts may not have reached the
/// routing table yet even though their Kad IDs are already known.
fn register_publish_contact(rpc: &RpcManager, contact: &TraversalContact) {
    if contact.id != NodeId::ZERO {
        rpc.register_peer_identity(contact.addr, contact.id);
    }
    rpc.register_peer_version(contact.addr, contact.version);
}

#[cfg(test)]
mod tests;
