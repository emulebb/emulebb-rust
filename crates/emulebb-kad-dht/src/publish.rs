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
    KAD_VERSION_AICH_KEYWORD_PUBLISH, KADEMLIA_VERSION2_47A, SEARCHTOLERANCE,
    STORE_KEYWORD_TIMEOUT_SECS, STORE_NOTES_TIMEOUT_SECS, STORE_SOURCE_TIMEOUT_SECS,
    STORE_STOP_GRACE_SECS,
};
use emulebb_kad_proto::{
    Ed2kHash, KadPacket, NodeId, Tag, TagName,
    constants::K,
    opcode,
    packet::{PublishEntry, PublishKeyReq, PublishNotesReq, PublishSourceReq},
    tag_name,
};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const PUBLISH_KEYWORD_LOOKUP_TIMEOUT: Duration =
    Duration::from_secs(STORE_KEYWORD_TIMEOUT_SECS - STORE_STOP_GRACE_SECS);
const PUBLISH_SOURCE_LOOKUP_TIMEOUT: Duration =
    Duration::from_secs(STORE_SOURCE_TIMEOUT_SECS - STORE_STOP_GRACE_SECS);
const PUBLISH_NOTES_LOOKUP_TIMEOUT: Duration =
    Duration::from_secs(STORE_NOTES_TIMEOUT_SECS - STORE_STOP_GRACE_SECS);
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
    pub entries: Vec<KeywordPublishEntry>,
    pub publish_contact_fanout: usize,
    pub work_class: RpcWorkClass,
}

/// One file entry inside a stock Kad keyword publish request.
#[derive(Debug, Clone)]
pub struct KeywordPublishEntry {
    pub file_hash: Ed2kHash,
    pub tags: Vec<Tag>,
    pub aich_hash: Option<[u8; 20]>,
}

/// Send the publish RPC to all selected contacts concurrently so the live wire
/// shape stays bursty while the caller can widen contact coverage for harvest.
async fn execute_publish_fanout(
    rpc: &RpcManager,
    contacts: &[TraversalContact],
    packet: &KadPacket,
    work_class: RpcWorkClass,
) -> Vec<(PublishAttempt, Result<KadPacket, emulebb_kad_net::NetError>)> {
    execute_publish_fanout_for_contacts(rpc, contacts, work_class, |_| packet.clone()).await
}

async fn execute_publish_fanout_for_contacts(
    rpc: &RpcManager,
    contacts: &[TraversalContact],
    work_class: RpcWorkClass,
    mut build_packet: impl FnMut(&TraversalContact) -> KadPacket,
) -> Vec<(PublishAttempt, Result<KadPacket, emulebb_kad_net::NetError>)> {
    let mut join_set = JoinSet::new();
    let total = contacts.len() as u32;

    for (index, contact) in contacts.iter().cloned().enumerate() {
        let rpc = rpc.clone();
        let packet = build_packet(&contact);
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

#[allow(clippy::too_many_arguments)]
async fn resolve_publish_contacts(
    rpc: &RpcManager,
    routing_table: &tokio::sync::Mutex<emulebb_kad_routing::RoutingTable>,
    target: NodeId,
    publish_contact_fanout: usize,
    lookup_timeout: Duration,
    work_class: RpcWorkClass,
    ip_filter: Option<crate::traversal::KadIpFilter>,
    res_contact_sink: Option<crate::traversal::KadResContactSink>,
) -> Result<(Vec<TraversalContact>, PublishAttemptStats), DhtError> {
    let initial = get_initial(routing_table, &target).await;
    let traversal = run_traversal(
        rpc,
        initial,
        TraversalConfig {
            target,
            search_kind: TraversalKind::Store,
            timeout: lookup_timeout,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout: publish_contact_fanout.max(K),
            cancel: CancellationToken::new(),
            result_tx: None,
            work_class,
            ip_filter,
            res_contact_sink,
        },
    )
    .await;

    if traversal.closest.is_empty() {
        return Err(DhtError::PublishFailed);
    }

    let publish_contacts =
        select_publish_contacts(target, &traversal.closest, publish_contact_fanout);
    if publish_contacts.is_empty() {
        return Err(DhtError::PublishFailed);
    }
    for contact in &publish_contacts {
        register_publish_contact(rpc, contact);
    }
    let attempted_contacts = publish_contacts.len() as u32;

    Ok((
        publish_contacts,
        PublishAttemptStats {
            closest_contacts_considered: traversal.closest.len() as u32,
            attempted_contacts,
            ..PublishAttemptStats::default()
        },
    ))
}

fn record_publish_result(
    stats: &mut PublishAttemptStats,
    family: &str,
    failure_label: &str,
    count_unexpected_as_ack: bool,
    attempt: PublishAttempt,
    result: Result<KadPacket, emulebb_kad_net::NetError>,
) {
    match result {
        Ok(packet) => {
            record_publish_success(stats, family, count_unexpected_as_ack, attempt, packet)
        }
        Err(error) => record_publish_failure(stats, family, failure_label, attempt, error),
    }
}

fn record_publish_success(
    stats: &mut PublishAttemptStats,
    family: &str,
    count_unexpected_as_ack: bool,
    attempt: PublishAttempt,
    packet: KadPacket,
) {
    match packet {
        KadPacket::PublishRes(response) => {
            stats.acked_contacts += 1;
            log_publish_response_ack(family, &attempt, response.target, response.load);
        }
        other => {
            if count_unexpected_as_ack {
                stats.acked_contacts += 1;
            }
            log_publish_opcode_ack(family, &attempt, other.opcode());
        }
    }
}

fn record_publish_failure(
    stats: &mut PublishAttemptStats,
    family: &str,
    failure_label: &str,
    attempt: PublishAttempt,
    error: emulebb_kad_net::NetError,
) {
    if matches!(error, emulebb_kad_net::NetError::Timeout { .. }) {
        stats.timed_out_contacts += 1;
    }
    tracing::debug!(
        "kad publish contact family={} step={} rank={}/{} contact_addr={} contact_id={} error={}",
        family,
        publish_failure_step(&error),
        attempt.rank,
        attempt.total,
        attempt.contact.addr,
        attempt.contact.id,
        error,
    );
    tracing::debug!(
        "{} ack failed from {}: {}",
        failure_label,
        attempt.contact.addr,
        error
    );
}

fn log_publish_response_ack(
    family: &str,
    attempt: &PublishAttempt,
    response_target: NodeId,
    response_load: u8,
) {
    tracing::debug!(
        "kad publish contact family={} step=ack rank={}/{} contact_addr={} contact_id={} response_target={} response_load={}",
        family,
        attempt.rank,
        attempt.total,
        attempt.contact.addr,
        attempt.contact.id,
        response_target,
        response_load,
    );
}

fn log_publish_opcode_ack(family: &str, attempt: &PublishAttempt, opcode: u8) {
    tracing::debug!(
        "kad publish contact family={} step=ack rank={}/{} contact_addr={} contact_id={} response_opcode=0x{:02X}",
        family,
        attempt.rank,
        attempt.total,
        attempt.contact.addr,
        attempt.contact.id,
        opcode,
    );
}

fn publish_failure_step(error: &emulebb_kad_net::NetError) -> &'static str {
    if matches!(error, emulebb_kad_net::NetError::Timeout { .. }) {
        "timeout"
    } else {
        "fail"
    }
}

fn record_publish_results(
    stats: &mut PublishAttemptStats,
    family: &str,
    failure_label: &str,
    count_unexpected_as_ack: bool,
    results: Vec<(PublishAttempt, Result<KadPacket, emulebb_kad_net::NetError>)>,
) {
    for (attempt, result) in results {
        record_publish_result(
            stats,
            family,
            failure_label,
            count_unexpected_as_ack,
            attempt,
            result,
        );
    }
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
    ip_filter: Option<crate::traversal::KadIpFilter>,
    res_contact_sink: Option<crate::traversal::KadResContactSink>,
) -> Result<PublishAttemptStats, DhtError> {
    let KeywordPublishRequest {
        keyword_hash,
        entries,
        publish_contact_fanout,
        work_class,
    } = request;
    if entries.is_empty() {
        return Err(DhtError::PublishFailed);
    }
    let target = keyword_hash;
    let (publish_contacts, mut stats) = resolve_publish_contacts(
        rpc,
        routing_table,
        target,
        publish_contact_fanout,
        PUBLISH_KEYWORD_LOOKUP_TIMEOUT,
        work_class,
        ip_filter,
        res_contact_sink,
    )
    .await?;
    for (index, contact) in publish_contacts.iter().enumerate() {
        tracing::debug!(
            "kad publish contact family=keyword step=send rank={}/{} contact_addr={} contact_id={} contact_version={} target={} entry_count={} first_file_hash={}",
            index + 1,
            stats.attempted_contacts,
            contact.addr,
            contact.id,
            contact.version,
            target,
            entries.len(),
            entries[0].file_hash,
        );
    }
    let results =
        execute_publish_fanout_for_contacts(rpc, &publish_contacts, work_class, |contact| {
            build_keyword_publish_packet(target, &entries, contact.version)
        })
        .await;
    record_publish_results(&mut stats, "keyword", "publish_keyword", true, results);

    Ok(stats)
}

/// Build the oracle-style keyword publish body for a specific target contact.
///
/// eMule appends the keyword-publish AICH tag only for Kad v9+ peers, so the
/// fanout cannot reuse a single keyword packet body across the whole contact set.
fn build_keyword_publish_packet(
    target: NodeId,
    entries: &[KeywordPublishEntry],
    contact_version: u8,
) -> KadPacket {
    KadPacket::PublishKeyReq(PublishKeyReq {
        target,
        entries: entries
            .iter()
            .map(|entry| {
                let mut tags = entry.tags.clone();
                if contact_version >= KAD_VERSION_AICH_KEYWORD_PUBLISH
                    && let Some(aich_hash) = entry.aich_hash
                {
                    tags.push(Tag::kad_aich_hash_pub(aich_hash));
                }
                PublishEntry {
                    hash: entry.file_hash,
                    tags,
                }
            })
            .collect(),
    })
}

/// Publish source availability for a file.
#[allow(clippy::too_many_arguments)]
pub async fn publish_source(
    rpc: &RpcManager,
    routing_table: &tokio::sync::Mutex<emulebb_kad_routing::RoutingTable>,
    publisher_id: NodeId,
    file_hash: Ed2kHash,
    tags: Vec<Tag>,
    publish_contact_fanout: usize,
    work_class: RpcWorkClass,
    ip_filter: Option<crate::traversal::KadIpFilter>,
    res_contact_sink: Option<crate::traversal::KadResContactSink>,
) -> Result<PublishAttemptStats, DhtError> {
    let target = NodeId::from_be_bytes(file_hash.0);
    let (publish_contacts, mut stats) = resolve_publish_contacts(
        rpc,
        routing_table,
        target,
        publish_contact_fanout,
        PUBLISH_SOURCE_LOOKUP_TIMEOUT,
        work_class,
        ip_filter,
        res_contact_sink,
    )
    .await?;

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
    let results =
        execute_publish_fanout_for_contacts(rpc, &publish_contacts, work_class, |contact| {
            build_source_publish_packet(target, publisher_id, &tags, contact.version)
        })
        .await;
    record_publish_results(&mut stats, "source", "publish_source", true, results);

    Ok(stats)
}

/// Build the oracle-style source publish body for a specific target contact.
///
/// eMule sends the file-size tag only to contacts at `KADEMLIA_VERSION2_47a` or
/// newer. Older Kad2 peers still accept high-ID source publish without that tag.
fn build_source_publish_packet(
    target: NodeId,
    publisher_id: NodeId,
    tags: &[Tag],
    contact_version: u8,
) -> KadPacket {
    let tags = if contact_version >= KADEMLIA_VERSION2_47A {
        tags.to_vec()
    } else {
        tags.iter()
            .filter(|tag| tag.name != TagName::Short(tag_name::FILESIZE))
            .cloned()
            .collect()
    };
    KadPacket::PublishSourceReq(PublishSourceReq {
        target,
        publisher_id,
        tags,
    })
}

/// Publish a note/rating for a file.
///
/// The oracle writes the publisher Kad node ID into the second 128-bit field of
/// `KADEMLIA2_PUBLISH_NOTES_REQ`. The wire width matches a file hash, but the
/// semantic meaning is publisher identity and must stay aligned across local
/// store, notes search results, and wire dumps.
#[allow(clippy::too_many_arguments)]
pub async fn publish_notes(
    rpc: &RpcManager,
    routing_table: &tokio::sync::Mutex<emulebb_kad_routing::RoutingTable>,
    file_hash: Ed2kHash,
    publisher_id: NodeId,
    tags: Vec<Tag>,
    publish_contact_fanout: usize,
    work_class: RpcWorkClass,
    ip_filter: Option<crate::traversal::KadIpFilter>,
    res_contact_sink: Option<crate::traversal::KadResContactSink>,
) -> Result<PublishAttemptStats, DhtError> {
    let target = NodeId::from_be_bytes(file_hash.0);
    let (publish_contacts, mut stats) = resolve_publish_contacts(
        rpc,
        routing_table,
        target,
        publish_contact_fanout,
        PUBLISH_NOTES_LOOKUP_TIMEOUT,
        work_class,
        ip_filter,
        res_contact_sink,
    )
    .await?;

    let packet = KadPacket::PublishNotesReq(PublishNotesReq {
        target,
        publisher_id,
        tags,
    });

    let results = execute_publish_fanout(rpc, &publish_contacts, &packet, work_class).await;
    record_publish_results(&mut stats, "notes", "publish_notes", false, results);

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
            tcp_port: c.tcp_port,
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
