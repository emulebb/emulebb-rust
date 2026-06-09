//! Kad traversal state machine for lookup, search, and publish-preparation walks.
//!
//! The traversal owns the oracle-shaped `REQ` / `RES` phase, the jump-start
//! timing for search phase 2, and the candidate-state bookkeeping that decides
//! which contacts are still eligible to query.

use emulebb_kad_net::{RpcManager, RpcWorkClass};
use emulebb_kad_proto::{
    Ed2kHash, KadPacket, NodeId, Tag,
    constants::{
        ALPHA, K, KADEMLIA_FIND_NODE, KADEMLIA_FIND_VALUE, KADEMLIA_STORE, SEARCHTOLERANCE,
    },
    opcode,
    packet::{ContactEntry, Req, SearchKeyReq, SearchNotesReq, SearchSourceReq},
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateState {
    /// Candidate discovered but not yet queried.
    Pending,
    /// `REQ` sent and response still pending.
    Inflight,
    /// Candidate answered with a `RES` and remains eligible for phase 2.
    Responded,
    /// Candidate timed out or failed and should not be queried again in this traversal.
    Failed,
}

/// Minimal peer identity required to query one traversal candidate.
#[derive(Debug, Clone)]
pub struct TraversalContact {
    /// Kad node ID of the candidate.
    pub id: NodeId,
    /// UDP endpoint used for Kad traffic.
    pub addr: SocketAddr,
    /// Highest Kad version known for this candidate.
    pub version: u8,
}

/// One traversal candidate plus its current state and XOR distance.
#[derive(Debug, Clone)]
pub struct TraversalCandidate {
    /// Contact identity and endpoint.
    pub contact: TraversalContact,
    /// Current traversal state for this candidate.
    pub state: CandidateState,
    /// XOR distance from the candidate ID to the traversal target.
    pub distance: NodeId,
}

/// Phase-2 behavior that should follow once the closest contacts are known.
#[derive(Debug, Clone)]
pub enum TraversalKind {
    /// Pure node lookup — just find close nodes.
    FindNode,
    /// Store lookup — publish preparation should request the store fanout like the oracle.
    Store,
    /// Keyword search — after traversal, send SearchKeyReq to close nodes.
    Keyword { request: SearchKeyReq },
    /// Source search — after traversal, send the provided SearchSourceReq to close nodes.
    Source { request: SearchSourceReq },
    /// Notes search — after traversal, send SearchNotesReq to close nodes.
    Notes { size: u64 },
}

/// Inputs for one full traversal run.
pub struct TraversalConfig {
    /// Target ID being resolved or searched.
    pub target: NodeId,
    /// Traversal flavor and phase-2 behavior.
    pub search_kind: TraversalKind,
    /// Whole-traversal deadline.
    pub timeout: Duration,
    /// Per-node `REQ` timeout budget.
    pub query_timeout: Duration,
    /// Maximum number of close contacts to use in phase 2.
    pub phase2_fanout: usize,
    /// External cancellation token for the whole run.
    pub cancel: CancellationToken,
    /// Optional streaming hook for phase-2 SEARCH_RES entries.
    ///
    /// We keep `search_entries` in the final `TraversalResult` for callers that still
    /// want the collected batch, but the node/API path now consumes results
    /// incrementally from this channel as packets arrive.
    pub result_tx: Option<mpsc::Sender<(Ed2kHash, Vec<Tag>)>>,
    /// Outbound budget class used by this traversal.
    pub work_class: RpcWorkClass,
}

/// Final traversal outcome returned to the caller.
pub struct TraversalResult {
    /// K closest nodes that responded.
    pub closest: Vec<TraversalContact>,
    /// Raw SEARCH_RES entries collected for non-streaming callers.
    ///
    /// Stream-based search APIs consume results directly from `result_tx`, so
    /// they intentionally leave this buffer empty to avoid duplicating every
    /// inbound result page in memory.
    pub search_entries: Vec<(Ed2kHash, Vec<emulebb_kad_proto::Tag>)>,
}

fn traversal_closest_limit(search_kind: &TraversalKind, phase2_fanout: usize) -> usize {
    match search_kind {
        TraversalKind::Store => phase2_fanout.max(K),
        _ => K,
    }
}

/// Immutable inputs for the traversal phase-2 search pass.
struct SearchPhaseConfig<'a> {
    responded: &'a [TraversalContact],
    kind: TraversalKind,
    target: NodeId,
    query_timeout: Duration,
    deadline: Instant,
    phase2_fanout: usize,
    /// Timestamp of the last traversal `RES` response.
    ///
    /// eMule only starts `StorePacket()` once the lookup has been idle for a
    /// few seconds, so phase 2 needs this to mirror the oracle's jump-start
    /// gate instead of burst-sending immediately.
    last_lookup_response_at: Option<Instant>,
    /// Oracle-style idle grace before jump-start emits the first search packet.
    jumpstart_idle_grace: Duration,
    /// Oracle-style periodic tick for walking one closest responder at a time.
    jumpstart_tick: Duration,
    work_class: RpcWorkClass,
    cancel: &'a CancellationToken,
    result_tx: Option<mpsc::Sender<(Ed2kHash, Vec<Tag>)>>,
}

/// eMule checks stalled searches once per second.
const SEARCH_JUMPSTART_TICK: Duration = Duration::from_secs(1);
/// eMule only jump-starts once the last lookup response is at least 3 seconds old.
const SEARCH_JUMPSTART_IDLE_GRACE: Duration = Duration::from_secs(3);

/// Run one oracle-shaped Kad traversal from `REQ` fanout through optional search phase 2.
pub async fn run_traversal(
    rpc: &RpcManager,
    initial_candidates: Vec<TraversalContact>,
    config: TraversalConfig,
) -> TraversalResult {
    let TraversalConfig {
        target,
        search_kind,
        timeout,
        query_timeout,
        phase2_fanout,
        cancel,
        result_tx,
        work_class,
    } = config;
    let deadline = Instant::now() + timeout;
    let closest_limit = traversal_closest_limit(&search_kind, phase2_fanout);

    // Determine the count byte for Req based on search kind.
    let req_count = match search_kind {
        TraversalKind::FindNode => KADEMLIA_FIND_NODE,
        TraversalKind::Store => KADEMLIA_STORE,
        _ => KADEMLIA_FIND_VALUE,
    };

    // ── Phase 1: Req/Res traversal to find K closest nodes ──────────────────

    let mut candidates: Vec<TraversalCandidate> = initial_candidates
        .into_iter()
        .map(|c| {
            let distance = target.distance(&c.id);
            TraversalCandidate {
                contact: c,
                state: CandidateState::Pending,
                distance,
            }
        })
        .collect();
    candidates.sort_by(|a, b| a.distance.cmp(&b.distance));
    candidates.dedup_by(|a, b| a.contact.id == b.contact.id);

    let mut seen: HashSet<NodeId> = candidates.iter().map(|c| c.contact.id).collect();

    let mut join_set: JoinSet<(NodeId, Result<KadPacket, emulebb_kad_net::NetError>)> =
        JoinSet::new();
    let mut last_lookup_response_at = None;

    loop {
        if cancel.is_cancelled() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;

        // Launch ALPHA Req queries for closest pending candidates
        let inflight_count = candidates
            .iter()
            .filter(|c| c.state == CandidateState::Inflight)
            .count();
        let to_launch = ALPHA.saturating_sub(inflight_count);

        let pending_closest: Vec<usize> = candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| c.state == CandidateState::Pending)
            .take(to_launch)
            .map(|(i, _)| i)
            .collect();

        for idx in pending_closest {
            candidates[idx].state = CandidateState::Inflight;
            let contact = candidates[idx].contact.clone();
            register_traversal_identity(rpc, &contact);
            let rpc = rpc.clone();
            let query_timeout = query_timeout.min(remaining);

            join_set.spawn(async move {
                let packet = KadPacket::Req(Req {
                    count: req_count,
                    target,
                    recipient_id: contact.id,
                });
                let result = rpc
                    .request_with_class(
                        contact.addr,
                        &packet,
                        opcode::RES,
                        query_timeout,
                        work_class,
                    )
                    .await;
                (contact.id, result)
            });
        }

        if join_set.is_empty() {
            break;
        }

        let next = tokio::select! {
            _ = cancel.cancelled() => break,
            next = tokio::time::timeout(remaining, join_set.join_next()) => next,
        };

        let result = match next {
            Ok(Some(Ok(r))) => r,
            Ok(Some(Err(e))) => {
                warn!("traversal task panicked: {}", e);
                continue;
            }
            Ok(None) | Err(_) => break,
        };

        let (contact_id, query_result) = result;

        let candidate_idx = candidates.iter().position(|c| c.contact.id == contact_id);

        match query_result {
            Err(e) => {
                trace!("query failed for {}: {}", contact_id, e);
                if let Some(idx) = candidate_idx {
                    candidates[idx].state = CandidateState::Failed;
                }
            }
            Ok(KadPacket::Res(res)) => {
                last_lookup_response_at = Some(Instant::now());
                if let Some(idx) = candidate_idx {
                    candidates[idx].state = CandidateState::Responded;
                }
                let sanitized = match sanitize_res_contacts(
                    &res.contacts,
                    candidates
                        .get(candidate_idx.unwrap_or(usize::MAX))
                        .map(|c| c.contact.addr)
                        .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
                    req_count as usize,
                ) {
                    Some(contacts) => contacts,
                    None => {
                        trace!(
                            "dropping RES from {} because it exceeds requested contact count",
                            contact_id
                        );
                        continue;
                    }
                };
                for entry in sanitized {
                    if seen.contains(&entry.node_id) {
                        continue;
                    }
                    if entry.ip == 0 || entry.udp_port == 0 {
                        continue;
                    }
                    seen.insert(entry.node_id);
                    let addr = SocketAddr::new(IpAddr::V4(entry.ip_addr()), entry.udp_port);
                    let distance = target.distance(&entry.node_id);
                    let c = TraversalCandidate {
                        contact: TraversalContact {
                            id: entry.node_id,
                            addr,
                            version: entry.version,
                        },
                        state: CandidateState::Pending,
                        distance,
                    };
                    let pos = candidates.partition_point(|x| x.distance < distance);
                    candidates.insert(pos, c);
                }
            }
            Ok(other) => {
                trace!(
                    "unexpected packet during traversal from {}: {:?}",
                    contact_id,
                    other.opcode()
                );
                if let Some(idx) = candidate_idx {
                    candidates[idx].state = CandidateState::Failed;
                }
            }
        }

        if matches!(search_kind, TraversalKind::FindNode) && find_node_lookup_converged(&candidates)
        {
            break;
        }

        // Termination: the responder window this traversal cares about is done.
        let closest_goal_done = candidates
            .iter()
            .take(closest_limit)
            .all(|c| matches!(c.state, CandidateState::Responded | CandidateState::Failed));
        let any_inflight = candidates
            .iter()
            .any(|c| c.state == CandidateState::Inflight);

        if closest_goal_done && !any_inflight {
            break;
        }
    }

    join_set.abort_all();

    let responded: Vec<TraversalContact> = candidates
        .iter()
        .filter(|c| c.state == CandidateState::Responded)
        .map(|c| c.contact.clone())
        .collect();
    let closest: Vec<TraversalContact> = responded.iter().take(closest_limit).cloned().collect();

    let responded_count = candidates
        .iter()
        .filter(|c| c.state == CandidateState::Responded)
        .count();
    let failed_count = candidates
        .iter()
        .filter(|c| c.state == CandidateState::Failed)
        .count();
    info!(
        "traversal phase1 done: {} responded, {} failed, {} total candidates, {} in closest set",
        responded_count,
        failed_count,
        candidates.len(),
        closest.len()
    );

    // ── Phase 2: Send search packets to close nodes ──────────────────────────

    let search_entries = match search_kind {
        TraversalKind::FindNode => vec![],
        TraversalKind::Store => vec![],
        kind => {
            run_search_phase(
                rpc,
                SearchPhaseConfig {
                    responded: &responded,
                    kind,
                    target,
                    query_timeout,
                    deadline,
                    phase2_fanout,
                    last_lookup_response_at,
                    jumpstart_idle_grace: SEARCH_JUMPSTART_IDLE_GRACE,
                    jumpstart_tick: SEARCH_JUMPSTART_TICK,
                    work_class,
                    cancel: &cancel,
                    result_tx,
                },
            )
            .await
        }
    };

    TraversalResult {
        closest,
        search_entries,
    }
}

/// Send search packets to the selected responding nodes and collect results.
async fn run_search_phase(
    rpc: &RpcManager,
    config: SearchPhaseConfig<'_>,
) -> Vec<(Ed2kHash, Vec<emulebb_kad_proto::Tag>)> {
    let SearchPhaseConfig {
        responded,
        kind,
        target,
        query_timeout,
        deadline,
        phase2_fanout,
        last_lookup_response_at,
        jumpstart_idle_grace,
        jumpstart_tick,
        work_class,
        cancel,
        result_tx,
    } = config;
    if cancel.is_cancelled() {
        return vec![];
    }
    let now = Instant::now();
    if now >= deadline {
        return vec![];
    }
    let remaining = deadline - now;
    let qt = query_timeout.min(remaining);
    let phase_deadline = Instant::now() + qt;

    let send_to = select_phase2_contacts(responded, target, phase2_fanout);

    info!(
        "traversal phase2: walking search packets across {} nodes, qt={:.1}s",
        send_to.len(),
        qt.as_secs_f32()
    );

    let mut unsolicited = rpc.subscribe();
    let mut queried_addrs = HashSet::new();
    let mut pending_contacts = send_to.into_iter().collect::<VecDeque<_>>();
    let mut search_entries = Vec::new();
    let should_collect_search_entries = result_tx.is_none();
    let result_tx = result_tx;
    let mut next_emit_at = compute_initial_jumpstart_emit_at(
        last_lookup_response_at,
        Instant::now(),
        jumpstart_idle_grace,
    );

    loop {
        if cancel.is_cancelled() {
            break;
        }
        let now = Instant::now();
        if now >= phase_deadline {
            break;
        }
        let receive_until = if pending_contacts.is_empty() {
            phase_deadline
        } else {
            next_emit_at.min(phase_deadline)
        };
        collect_search_results_until(SearchResultDrain {
            unsolicited: &mut unsolicited,
            cancel,
            receive_until,
            target,
            queried_addrs: &queried_addrs,
            result_tx: &result_tx,
            collect_search_entries: should_collect_search_entries,
            search_entries: &mut search_entries,
        })
        .await;

        let now = Instant::now();
        if now >= phase_deadline {
            break;
        }
        if pending_contacts.is_empty() || now < next_emit_at {
            continue;
        }

        let Some(contact) = pending_contacts.pop_front() else {
            continue;
        };
        register_traversal_identity(rpc, contact);
        let packet = match kind {
            TraversalKind::Keyword { ref request } => KadPacket::SearchKeyReq(request.clone()),
            TraversalKind::Source { ref request } => KadPacket::SearchSourceReq(request.clone()),
            TraversalKind::Notes { size } => {
                KadPacket::SearchNotesReq(SearchNotesReq { target, size })
            }
            TraversalKind::FindNode => unreachable!(),
            TraversalKind::Store => unreachable!(),
        };

        debug!(
            "traversal phase2: jump-start send to {} remaining_contacts={}",
            contact.addr,
            pending_contacts.len()
        );
        if let Err(err) = rpc.send_with_class(contact.addr, &packet, work_class).await {
            trace!("search phase send failed for {}: {}", contact.id, err);
        }
        queried_addrs.insert(contact.addr);
        next_emit_at = Instant::now() + jumpstart_tick;
    }

    info!(
        "traversal phase2 done: {} total search entries collected",
        search_entries.len()
    );

    search_entries
}

/// Compute when the next phase-2 search packet is allowed to be emitted.
fn compute_initial_jumpstart_emit_at(
    last_lookup_response_at: Option<Instant>,
    now: Instant,
    jumpstart_idle_grace: Duration,
) -> Instant {
    let Some(last_lookup_response_at) = last_lookup_response_at else {
        return now;
    };
    let stalled_at = last_lookup_response_at + jumpstart_idle_grace;
    stalled_at.max(now)
}

struct SearchResultDrain<'a> {
    unsolicited: &'a mut tokio::sync::broadcast::Receiver<emulebb_kad_net::ReceivedKadPacket>,
    cancel: &'a CancellationToken,
    receive_until: Instant,
    target: NodeId,
    queried_addrs: &'a HashSet<SocketAddr>,
    result_tx: &'a Option<mpsc::Sender<(Ed2kHash, Vec<Tag>)>>,
    collect_search_entries: bool,
    search_entries: &'a mut Vec<(Ed2kHash, Vec<Tag>)>,
}

/// Drain unsolicited packets until the next jump-start emit slot or overall deadline.
async fn collect_search_results_until(drain: SearchResultDrain<'_>) {
    let SearchResultDrain {
        unsolicited,
        cancel,
        receive_until,
        target,
        queried_addrs,
        result_tx,
        collect_search_entries,
        search_entries,
    } = drain;
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let now = Instant::now();
        if now >= receive_until {
            break;
        }
        let remaining = receive_until - now;
        match tokio::select! {
            _ = cancel.cancelled() => break,
            result = tokio::time::timeout(remaining, unsolicited.recv()) => result,
        } {
            Ok(Ok(emulebb_kad_net::ReceivedKadPacket {
                packet: KadPacket::SearchRes(sr),
                from,
                ..
            })) => {
                if !queried_addrs.contains(&from) {
                    trace!("ignoring SEARCH_RES from unqueried sender {}", from);
                    continue;
                }
                if sr.target != target {
                    trace!(
                        "ignoring SEARCH_RES from {} for mismatched target {}",
                        from, sr.target
                    );
                    continue;
                }

                debug!(
                    "search phase got SearchRes: {} results from sender {}",
                    sr.results.len(),
                    sr.sender_id
                );
                for entry in sr.results {
                    if let Some(tx) = result_tx.as_ref() {
                        let _ = tx.send((entry.entry_id, entry.tags.clone())).await;
                    }
                    if collect_search_entries {
                        search_entries.push((entry.entry_id, entry.tags));
                    }
                }
            }
            Ok(Ok(emulebb_kad_net::ReceivedKadPacket {
                packet: other,
                from,
                ..
            })) => {
                if queried_addrs.contains(&from) {
                    trace!(
                        "search phase unexpected packet opcode=0x{:02X} from {}",
                        other.opcode(),
                        from
                    );
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped))) => {
                warn!(
                    "search phase broadcast receiver lagged; skipped {} packets",
                    skipped
                );
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            Err(_) => break,
        }
    }
}

/// Register traversal contact metadata with the RPC layer before sending.
///
/// Traversal frequently queries freshly discovered contacts before they are persisted in the
/// routing table, so the traversal itself must seed the RPC obfuscation cache with their Kad IDs.
fn register_traversal_identity(rpc: &RpcManager, contact: &TraversalContact) {
    if contact.id != NodeId::ZERO {
        rpc.register_peer_identity(contact.addr, contact.id);
    }
    rpc.register_peer_version(contact.addr, contact.version);
}

fn select_phase2_contacts(
    responded: &[TraversalContact],
    target: NodeId,
    phase2_fanout: usize,
) -> Vec<&TraversalContact> {
    // eMule stops phase 2 at the closest tolerated responders. We keep the
    // configurable ceiling for tests or explicit tightening, but never exceed
    // the oracle's closest-K contact window.
    let oracle_ceiling = phase2_fanout.min(K);
    responded
        .iter()
        .filter(|contact| passes_search_tolerance(target, contact))
        .take(oracle_ceiling)
        .collect()
}

/// Returns true once a pure node lookup has already locked in its closest `K` responders.
fn find_node_lookup_converged(candidates: &[TraversalCandidate]) -> bool {
    let closest_responded = candidates
        .iter()
        .filter(|candidate| candidate.state == CandidateState::Responded)
        .take(K)
        .collect::<Vec<_>>();
    let Some(threshold) = closest_responded.last().map(|candidate| candidate.distance) else {
        return false;
    };
    if closest_responded.len() < K {
        return false;
    }

    !candidates.iter().any(|candidate| {
        matches!(
            candidate.state,
            CandidateState::Pending | CandidateState::Inflight
        ) && candidate.distance <= threshold
    })
}

fn sanitize_res_contacts(
    contacts: &[ContactEntry],
    responder_addr: SocketAddr,
    max_contacts: usize,
) -> Option<Vec<ContactEntry>> {
    if contacts.len() > max_contacts {
        return None;
    }

    let mut seen_ips = HashSet::new();
    let mut prefix_counts = HashMap::<u32, usize>::new();

    if let IpAddr::V4(ip) = responder_addr.ip() {
        seen_ips.insert(ip);
        *prefix_counts.entry(ipv4_prefix_24(ip)).or_insert(0) += 1;
    }

    let mut sanitized = Vec::with_capacity(contacts.len());
    for entry in contacts {
        if entry.ip == 0 || entry.udp_port == 0 {
            continue;
        }

        let ip = entry.ip_addr();
        if !seen_ips.insert(ip) {
            continue;
        }

        // eMule rejects overly clustered RES answers by capping each /24 to two
        // contacts in one response and by treating the responder IP as already seen.
        // Reference: srchybrid/kademlia/kademlia/Search.cpp ProcessResponse.
        let prefix = ipv4_prefix_24(ip);
        let count = prefix_counts.entry(prefix).or_insert(0);
        if *count >= 2 {
            continue;
        }
        *count += 1;
        sanitized.push(entry.clone());
    }

    Some(sanitized)
}

fn passes_search_tolerance(target: NodeId, contact: &TraversalContact) -> bool {
    match contact.addr.ip() {
        IpAddr::V4(ip) if is_lan_ip(ip) => true,
        IpAddr::V4(_) => distance_high32(target.distance(&contact.id)) <= SEARCHTOLERANCE,
        IpAddr::V6(_) => false,
    }
}

fn distance_high32(distance: NodeId) -> u32 {
    // eMule compares SEARCHTOLERANCE against CUInt128::Get32BitChunk(0), and
    // our NodeId bytes are stored in the same little-endian-per-u32 chunk order
    // that goes on the wire. So the first chunk needs little-endian decoding.
    u32::from_le_bytes([distance.0[0], distance.0[1], distance.0[2], distance.0[3]])
}

fn is_lan_ip(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

fn ipv4_prefix_24(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets()) & 0xFFFF_FF00
}

#[cfg(test)]
mod tests;
