//! Kad traversal state machine for lookup, search, and publish-preparation walks.
//!
//! The traversal owns the oracle-shaped `REQ` / `RES` phase, the jump-start
//! timing for search phase 2, and the candidate-state bookkeeping that decides
//! which contacts are still eligible to query.
//!
//! The lightweight NODE-type bucket-refresh lookup (1 initial `REQ`, stop on
//! first `RES`) lives in [`refresh`]; the convergence walk here stays for
//! value/store/bootstrap lookups.

pub mod refresh;

use emulebb_kad_net::{RpcManager, RpcWorkClass};
use emulebb_kad_proto::{
    Ed2kHash, KadPacket, NodeId, Tag,
    constants::{
        ALPHA, K, KADEMLIA_FIND_NODE, KADEMLIA_FIND_VALUE, KADEMLIA_FIND_VALUE_MORE,
        KADEMLIA_STORE, KADEMLIA_VERSION2_47A, KADEMLIA_VERSION5_48A, SEARCHTOLERANCE,
    },
    opcode,
    packet::{
        CallbackReq, ContactEntry, FindBuddyReq, Req, SearchKeyReq, SearchNotesReq, SearchSourceReq,
    },
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
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
    /// eD2k TCP port carried by the RES contact entry, `0` when the source did
    /// not advertise one. Threaded through so a lookup-learned routing contact
    /// keeps its real eD2k TCP port instead of falling back to the UDP port.
    pub tcp_port: u16,
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

/// A lightweight, crate-external IP-filter hook for per-`RES`-contact dropping.
///
/// Returns `true` when the given IPv4 address is **filtered/banned** and the
/// contact must be dropped. The real [`IpFilter`](../../emulebb_ed2k) lives in
/// `emulebb-ed2k`, which depends on this crate, so it cannot be referenced here
/// directly (dependency inversion). Core — which depends on both crates — bridges
/// the live filter into this hook so traversal can enforce it without moving the
/// filter. Mirrors the oracle per-contact `theApp.ipfilter->IsFiltered()` drop in
/// `Process_KADEMLIA2_RES` (`KademliaUDPListener.cpp:830-857`).
pub type KadIpFilter = Arc<dyn Fn(Ipv4Addr) -> bool + Send + Sync>;

/// A sink fed every good `KADEMLIA2_RES` contact learned during traversal, the
/// moment it arrives — mirroring the oracle `Process_KADEMLIA2_RES` path which
/// `AddUnfiltered`s every answered contact to the routing zone regardless of
/// whether it ends up in the final closest-set (`KademliaUDPListener.cpp:849`).
///
/// The contacts have already passed the per-`RES` sanitation guards
/// (count cap, Kad1/DNS-port drop, ip-filter, per-`/24` clustering). The sink is
/// a fire-and-forget hook so it never blocks the lookup loop; the routing crate
/// cannot be referenced here, so core bridges the live routing table behind it.
pub type KadResContactSink = Arc<dyn Fn(&ContactEntry) + Send + Sync>;

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
    /// FINDBUDDY walk — after traversal, send the provided FindBuddyReq to each
    /// tolerance-passing responded contact (oracle `CSearch` type FINDBUDDY,
    /// `Search.cpp:864-896`).
    FindBuddy { request: FindBuddyReq },
    /// FINDSOURCE walk used when a LowID source's buddy ID is known but the
    /// buddy endpoint is not. Sends `KADEMLIA_CALLBACK_REQ` to close contacts.
    FindSource { request: CallbackReq },
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
    /// Optional IP-filter hook applied to each `RES`-returned contact (drops
    /// filtered/banned IPs), bridged from the live ed2k `IpFilter` by core.
    /// `None` disables per-contact ip-filtering (e.g. unit tests / no filter).
    pub ip_filter: Option<KadIpFilter>,
    /// Optional sink fed every good `RES` contact as it arrives (oracle
    /// `AddUnfiltered`). `None` disables routing-table population from traversal
    /// (e.g. unit tests). Bridged to the live routing table by core.
    pub res_contact_sink: Option<KadResContactSink>,
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

struct LookupPhaseConfig<'a> {
    target: NodeId,
    search_kind: &'a TraversalKind,
    deadline: Instant,
    query_timeout: Duration,
    closest_limit: usize,
    req_count: u8,
    work_class: RpcWorkClass,
    cancel: &'a CancellationToken,
    ip_filter: Option<&'a KadIpFilter>,
    res_contact_sink: Option<&'a KadResContactSink>,
}

struct LookupPhaseResult {
    responded: Vec<TraversalContact>,
    closest: Vec<TraversalContact>,
    last_lookup_response_at: Option<Instant>,
}

/// eMule checks stalled searches once per second.
const SEARCH_JUMPSTART_TICK: Duration = Duration::from_secs(1);
/// eMule only jump-starts once the last lookup response is at least 3 seconds old.
const SEARCH_JUMPSTART_IDLE_GRACE: Duration = Duration::from_secs(3);
/// Margin the first jump-start emit is backed off to so it still fires before
/// the phase-2 deadline check ends the loop (closest-contact 0x33 starvation).
const JUMPSTART_DEADLINE_MARGIN: Duration = Duration::from_millis(50);

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
        ip_filter,
        res_contact_sink,
    } = config;
    let deadline = Instant::now() + timeout;
    let closest_limit = traversal_closest_limit(&search_kind, phase2_fanout);

    // ── Phase 1: Req/Res traversal to find K closest nodes ──────────────────

    let LookupPhaseResult {
        responded,
        closest,
        last_lookup_response_at,
    } = run_lookup_phase(
        rpc,
        initial_candidates,
        LookupPhaseConfig {
            target,
            search_kind: &search_kind,
            deadline,
            query_timeout,
            closest_limit,
            req_count: req_count_for_kind(&search_kind),
            work_class,
            cancel: &cancel,
            ip_filter: ip_filter.as_ref(),
            res_contact_sink: res_contact_sink.as_ref(),
        },
    )
    .await;

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

fn req_count_for_kind(search_kind: &TraversalKind) -> u8 {
    match search_kind {
        TraversalKind::FindNode => KADEMLIA_FIND_NODE,
        // Oracle CSearch::GetRequestContactCount (Search.cpp:1653-1657) maps
        // FINDBUDDY together with the STORE-type searches to KADEMLIA_STORE.
        TraversalKind::Store | TraversalKind::FindBuddy { .. } => KADEMLIA_STORE,
        _ => KADEMLIA_FIND_VALUE,
    }
}

async fn run_lookup_phase(
    rpc: &RpcManager,
    initial_candidates: Vec<TraversalContact>,
    config: LookupPhaseConfig<'_>,
) -> LookupPhaseResult {
    let mut candidates = initial_traversal_candidates(initial_candidates, config.target);
    let mut seen: HashSet<NodeId> = candidates.iter().map(|c| c.contact.id).collect();
    let mut join_set = JoinSet::new();
    let mut last_lookup_response_at = None;
    // eMule `CSearch::JumpStart` FIND_VALUE_MORE re-ask: at most one per lookup.
    let mut more_asked: Option<NodeId> = None;

    loop {
        if lookup_deadline_reached(config.cancel, config.deadline) {
            break;
        }
        let remaining = config.deadline - Instant::now();
        launch_pending_queries(rpc, &mut candidates, &mut join_set, &config, remaining);
        // Stalled value lookup with its two closest tried contacts dead: re-ask
        // the closest responded contact for MORE close nodes (count 11 instead of
        // the value-lookup 2), so a duplicate-of-dead closest set does not hide
        // the truly-closest live node (eMule Search.cpp:288-304).
        if more_asked.is_none()
            && let Some(target_id) = select_reask_more_target(&candidates, config.req_count)
        {
            spawn_lookup_query_by_id(
                rpc,
                &mut join_set,
                &candidates,
                target_id,
                &config,
                KADEMLIA_FIND_VALUE_MORE,
                remaining,
            );
            more_asked = Some(target_id);
        }
        if join_set.is_empty() {
            break;
        }

        let Some((contact_id, query_result)) =
            wait_for_lookup_response(&mut join_set, config.cancel, remaining).await
        else {
            break;
        };
        if handle_lookup_response(
            &mut candidates,
            &mut seen,
            &config,
            contact_id,
            more_asked,
            query_result,
        ) {
            last_lookup_response_at = Some(Instant::now());
        }
        if lookup_phase_done(&candidates, config.search_kind, config.closest_limit) {
            break;
        }
    }

    join_set.abort_all();
    build_lookup_phase_result(candidates, config.closest_limit, last_lookup_response_at)
}

/// The closest responded contact to re-ask for MORE close nodes, when a value
/// lookup has stalled with its two closest tried contacts dead — mirroring
/// eMule `CSearch::JumpStart` (`Search.cpp:288-304`). Returns `None` unless: the
/// request count is the value-lookup count (2), at least `3 * KADEMLIA_FIND_VALUE`
/// (6) contacts have been tried, and the two closest tried contacts both failed
/// (neither responded). `candidates` is kept sorted by XOR distance, so the first
/// non-`Pending` entries are the closest tried ones.
fn select_reask_more_target(candidates: &[TraversalCandidate], req_count: u8) -> Option<NodeId> {
    if req_count != KADEMLIA_FIND_VALUE {
        return None;
    }
    let tried: Vec<&TraversalCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.state != CandidateState::Pending)
        .collect();
    if tried.len() < 3 * KADEMLIA_FIND_VALUE as usize {
        return None;
    }
    let best_two_all_dead = tried
        .iter()
        .take(KADEMLIA_FIND_VALUE as usize)
        .all(|candidate| candidate.state == CandidateState::Failed);
    if !best_two_all_dead {
        return None;
    }
    tried
        .iter()
        .find(|candidate| candidate.state == CandidateState::Responded)
        .map(|candidate| candidate.contact.id)
}

fn initial_traversal_candidates(
    contacts: Vec<TraversalContact>,
    target: NodeId,
) -> Vec<TraversalCandidate> {
    let mut candidates: Vec<TraversalCandidate> = contacts
        .into_iter()
        .map(|contact| TraversalCandidate {
            distance: target.distance(&contact.id),
            contact,
            state: CandidateState::Pending,
        })
        .collect();
    candidates.sort_by_key(|candidate| candidate.distance);
    candidates.dedup_by(|a, b| a.contact.id == b.contact.id);
    candidates
}

fn lookup_deadline_reached(cancel: &CancellationToken, deadline: Instant) -> bool {
    cancel.is_cancelled() || Instant::now() >= deadline
}

fn launch_pending_queries(
    rpc: &RpcManager,
    candidates: &mut [TraversalCandidate],
    join_set: &mut JoinSet<(NodeId, Result<KadPacket, emulebb_kad_net::NetError>)>,
    config: &LookupPhaseConfig<'_>,
    remaining: Duration,
) {
    let inflight_count = candidates
        .iter()
        .filter(|candidate| candidate.state == CandidateState::Inflight)
        .count();
    let pending_indexes = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.state == CandidateState::Pending)
        .take(ALPHA.saturating_sub(inflight_count))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();

    for index in pending_indexes {
        candidates[index].state = CandidateState::Inflight;
        spawn_lookup_query(
            rpc,
            join_set,
            candidates[index].contact.clone(),
            config,
            config.req_count,
            remaining,
        );
    }
}

/// Re-query an already-known candidate by id with an explicit request count (used
/// by the FIND_VALUE_MORE re-ask). No-op if the id is not among the candidates.
fn spawn_lookup_query_by_id(
    rpc: &RpcManager,
    join_set: &mut JoinSet<(NodeId, Result<KadPacket, emulebb_kad_net::NetError>)>,
    candidates: &[TraversalCandidate],
    contact_id: NodeId,
    config: &LookupPhaseConfig<'_>,
    req_count: u8,
    remaining: Duration,
) {
    if let Some(candidate) = candidates
        .iter()
        .find(|candidate| candidate.contact.id == contact_id)
    {
        spawn_lookup_query(
            rpc,
            join_set,
            candidate.contact.clone(),
            config,
            req_count,
            remaining,
        );
    }
}

fn spawn_lookup_query(
    rpc: &RpcManager,
    join_set: &mut JoinSet<(NodeId, Result<KadPacket, emulebb_kad_net::NetError>)>,
    contact: TraversalContact,
    config: &LookupPhaseConfig<'_>,
    req_count: u8,
    remaining: Duration,
) {
    register_traversal_identity(rpc, &contact);
    let rpc = rpc.clone();
    let query_timeout = config.query_timeout.min(remaining);
    let target = config.target;
    let work_class = config.work_class;

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

async fn wait_for_lookup_response(
    join_set: &mut JoinSet<(NodeId, Result<KadPacket, emulebb_kad_net::NetError>)>,
    cancel: &CancellationToken,
    remaining: Duration,
) -> Option<(NodeId, Result<KadPacket, emulebb_kad_net::NetError>)> {
    loop {
        let next = tokio::select! {
            _ = cancel.cancelled() => return None,
            next = tokio::time::timeout(remaining, join_set.join_next()) => next,
        };
        match next {
            Ok(Some(Ok(result))) => return Some(result),
            Ok(Some(Err(error))) => warn!("traversal task panicked: {}", error),
            Ok(None) | Err(_) => return None,
        }
    }
}

fn handle_lookup_response(
    candidates: &mut Vec<TraversalCandidate>,
    seen: &mut HashSet<NodeId>,
    config: &LookupPhaseConfig<'_>,
    contact_id: NodeId,
    more_asked: Option<NodeId>,
    query_result: Result<KadPacket, emulebb_kad_net::NetError>,
) -> bool {
    let candidate_idx = candidates
        .iter()
        .position(|candidate| candidate.contact.id == contact_id);
    match query_result {
        Err(error) => {
            trace!("query failed for {}: {}", contact_id, error);
            set_candidate_state(candidates, candidate_idx, CandidateState::Failed);
            false
        }
        Ok(KadPacket::Res(response)) => {
            set_candidate_state(candidates, candidate_idx, CandidateState::Responded);
            insert_response_contacts(
                candidates,
                seen,
                config,
                contact_id,
                candidate_idx,
                more_asked,
                response,
            );
            true
        }
        Ok(other) => {
            trace!(
                "unexpected packet during traversal from {}: {:?}",
                contact_id,
                other.opcode()
            );
            set_candidate_state(candidates, candidate_idx, CandidateState::Failed);
            false
        }
    }
}

fn set_candidate_state(
    candidates: &mut [TraversalCandidate],
    candidate_idx: Option<usize>,
    state: CandidateState,
) {
    if let Some(index) = candidate_idx {
        candidates[index].state = state;
    }
}

fn insert_response_contacts(
    candidates: &mut Vec<TraversalCandidate>,
    seen: &mut HashSet<NodeId>,
    config: &LookupPhaseConfig<'_>,
    contact_id: NodeId,
    candidate_idx: Option<usize>,
    more_asked: Option<NodeId>,
    response: emulebb_kad_proto::packet::Res,
) {
    let responder_addr = candidate_idx
        .and_then(|index| {
            candidates
                .get(index)
                .map(|candidate| candidate.contact.addr)
        })
        .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
    // The FIND_VALUE_MORE re-ask target may return up to KADEMLIA_FIND_NODE (11)
    // contacts even though the lookup's normal request count is the value-lookup
    // 2; admit the wider set only from that one contact (eMule ProcessResponse's
    // `pRequestedMoreNodesContact == pFromContact && size <= KADEMLIA_FIND_VALUE_MORE`
    // exception, Search.cpp:352).
    let max_contacts = if more_asked == Some(contact_id) {
        KADEMLIA_FIND_VALUE_MORE as usize
    } else {
        config.req_count as usize
    };
    let Some(sanitized) = sanitize_res_contacts(
        &response.contacts,
        responder_addr,
        max_contacts,
        config.ip_filter,
    ) else {
        trace!(
            "dropping RES from {} because it exceeds requested contact count",
            contact_id
        );
        return;
    };
    for entry in sanitized {
        // Oracle AddUnfiltered (KademliaUDPListener.cpp:849): feed every good RES
        // contact to the routing table as it arrives, independent of whether it
        // makes the final closest-set. The entry already passed sanitation.
        if let Some(sink) = config.res_contact_sink {
            sink(&entry);
        }
        insert_response_contact(candidates, seen, config.target, entry);
    }
}

fn insert_response_contact(
    candidates: &mut Vec<TraversalCandidate>,
    seen: &mut HashSet<NodeId>,
    target: NodeId,
    entry: ContactEntry,
) {
    if seen.contains(&entry.node_id) || entry.ip == 0 || entry.udp_port == 0 {
        return;
    }
    seen.insert(entry.node_id);
    let distance = target.distance(&entry.node_id);
    let candidate = TraversalCandidate {
        contact: TraversalContact {
            id: entry.node_id,
            addr: SocketAddr::new(IpAddr::V4(entry.ip_addr()), entry.udp_port),
            tcp_port: entry.tcp_port,
            version: entry.version,
        },
        state: CandidateState::Pending,
        distance,
    };
    let position = candidates.partition_point(|existing| existing.distance < distance);
    candidates.insert(position, candidate);
}

fn lookup_phase_done(
    candidates: &[TraversalCandidate],
    search_kind: &TraversalKind,
    closest_limit: usize,
) -> bool {
    if matches!(search_kind, TraversalKind::FindNode) && find_node_lookup_converged(candidates) {
        return true;
    }

    if matches!(search_kind, TraversalKind::Store)
        && store_lookup_has_publish_fanout(candidates, closest_limit)
    {
        return true;
    }

    candidates.iter().take(closest_limit).all(|candidate| {
        matches!(
            candidate.state,
            CandidateState::Responded | CandidateState::Failed
        )
    }) && !candidates
        .iter()
        .any(|candidate| candidate.state == CandidateState::Inflight)
}

fn store_lookup_has_publish_fanout(
    candidates: &[TraversalCandidate],
    closest_limit: usize,
) -> bool {
    candidates
        .iter()
        .filter(|candidate| candidate.state == CandidateState::Responded)
        .take(closest_limit)
        .count()
        >= closest_limit
}

fn build_lookup_phase_result(
    candidates: Vec<TraversalCandidate>,
    closest_limit: usize,
    last_lookup_response_at: Option<Instant>,
) -> LookupPhaseResult {
    let responded = candidates
        .iter()
        .filter(|candidate| candidate.state == CandidateState::Responded)
        .map(|candidate| candidate.contact.clone())
        .collect::<Vec<_>>();
    let closest: Vec<TraversalContact> = responded.iter().take(closest_limit).cloned().collect();
    log_lookup_phase_summary(&candidates, closest.len());
    LookupPhaseResult {
        responded,
        closest,
        last_lookup_response_at,
    }
}

fn log_lookup_phase_summary(candidates: &[TraversalCandidate], closest_count: usize) {
    let responded_count = candidates
        .iter()
        .filter(|candidate| candidate.state == CandidateState::Responded)
        .count();
    let failed_count = candidates
        .iter()
        .filter(|candidate| candidate.state == CandidateState::Failed)
        .count();
    info!(
        "traversal phase1 done: {} responded, {} failed, {} total candidates, {} in closest set",
        responded_count,
        failed_count,
        candidates.len(),
        closest_count
    );
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
    // Phase 2 must keep collecting SEARCH_RES for the FULL remaining search
    // budget, not just one per-node query window. `query_timeout` bounds an
    // individual lookup REQ/RES round-trip in phase 1; reusing it as the whole
    // phase-2 deadline starved result collection, because the jump-start walk
    // only emits one SEARCH_KEY_REQ per `jumpstart_tick` after a multi-second
    // idle grace — with a ~10s cap the furthest closest-set nodes were never
    // queried and the late ones had no window to answer, so every keyword
    // collected 0 entries even when results exist. eMule keeps a Kad search
    // alive for its whole lifetime (SEARCH_LIFETIME), walking and collecting in
    // parallel; mirror that by running until the traversal `deadline`.
    let phase_deadline = deadline;
    let qt = phase_deadline.saturating_duration_since(now);

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
        phase_deadline,
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
            // All closest nodes have been walked: keep draining until the full
            // phase deadline, but wake at least every `query_timeout` so the
            // cancel/deadline checks stay responsive instead of parking on one
            // long blocking receive.
            (now + query_timeout).min(phase_deadline)
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

        if let Some(next) = emit_next_search_packet(
            rpc,
            &kind,
            target,
            work_class,
            jumpstart_tick,
            &mut pending_contacts,
            &mut queried_addrs,
        )
        .await
        {
            next_emit_at = next;
        }
    }

    info!(
        "traversal phase2 done: {} total search entries collected",
        search_entries.len()
    );

    search_entries
}

async fn emit_next_search_packet(
    rpc: &RpcManager,
    kind: &TraversalKind,
    target: NodeId,
    work_class: RpcWorkClass,
    jumpstart_tick: Duration,
    pending_contacts: &mut VecDeque<&TraversalContact>,
    queried_addrs: &mut HashSet<SocketAddr>,
) -> Option<Instant> {
    let contact = pending_contacts.pop_front()?;
    register_traversal_identity(rpc, contact);
    let packet = search_phase_packet(kind, target);

    debug!(
        "traversal phase2: jump-start send to {} remaining_contacts={}",
        contact.addr,
        pending_contacts.len()
    );
    if let Err(err) = rpc.send_with_class(contact.addr, &packet, work_class).await {
        trace!("search phase send failed for {}: {}", contact.id, err);
    }
    queried_addrs.insert(contact.addr);
    Some(Instant::now() + jumpstart_tick)
}

fn search_phase_packet(kind: &TraversalKind, target: NodeId) -> KadPacket {
    match kind {
        TraversalKind::Keyword { request } => KadPacket::SearchKeyReq(request.clone()),
        TraversalKind::Source { request } => KadPacket::SearchSourceReq(request.clone()),
        TraversalKind::Notes { size } => KadPacket::SearchNotesReq(SearchNotesReq {
            target,
            size: *size,
        }),
        // Oracle CSearch::StorePacket FINDBUDDY (Search.cpp:864-896): buddy
        // target id + own client hash + own TCP port, sent to each
        // tolerance-passing responded contact as the walk progresses.
        TraversalKind::FindBuddy { request } => KadPacket::FindBuddyReq(request.clone()),
        TraversalKind::FindSource { request } => KadPacket::CallbackReq(request.clone()),
        TraversalKind::FindNode | TraversalKind::Store => unreachable!(),
    }
}

/// Compute when the first phase-2 search packet is allowed to be emitted.
///
/// The jump-start idle grace (`CSearch::JumpStart`) is a stall detector and must
/// never suppress the first `SEARCH_KEY_REQ`. When phase 1 ate almost the whole
/// shared `SEARCH_TIMEOUT` (slow rate-limited 0x21 walk), the unclamped grace
/// pushed the first emit to/past `phase_deadline`, so the loop broke having sent
/// zero 0x33 — the live "0 results, no 0x33 on the wire" bug. Clamp the first
/// emit before the deadline so the closest responders are always queried.
fn compute_initial_jumpstart_emit_at(
    last_lookup_response_at: Option<Instant>,
    now: Instant,
    jumpstart_idle_grace: Duration,
    phase_deadline: Instant,
) -> Instant {
    let Some(last_lookup_response_at) = last_lookup_response_at else {
        return now;
    };
    let stalled_at = (last_lookup_response_at + jumpstart_idle_grace).max(now);
    match phase_deadline.checked_sub(JUMPSTART_DEADLINE_MARGIN) {
        Some(slot) => stalled_at.min(slot).max(now),
        None => now,
    }
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
            Ok(Ok(packet)) => {
                handle_search_phase_packet(
                    packet,
                    target,
                    queried_addrs,
                    result_tx,
                    collect_search_entries,
                    search_entries,
                )
                .await;
            }
            Ok(Err(error)) => {
                if search_phase_receiver_closed(error) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

async fn handle_search_phase_packet(
    packet: emulebb_kad_net::ReceivedKadPacket,
    target: NodeId,
    queried_addrs: &HashSet<SocketAddr>,
    result_tx: &Option<mpsc::Sender<(Ed2kHash, Vec<Tag>)>>,
    collect_search_entries: bool,
    search_entries: &mut Vec<(Ed2kHash, Vec<Tag>)>,
) {
    let emulebb_kad_net::ReceivedKadPacket { packet, from, .. } = packet;
    match packet {
        KadPacket::SearchRes(response) => {
            handle_search_response(
                response,
                from,
                target,
                queried_addrs,
                result_tx,
                collect_search_entries,
                search_entries,
            )
            .await;
        }
        other if queried_addrs.contains(&from) => {
            trace!(
                "search phase unexpected packet opcode=0x{:02X} from {}",
                other.opcode(),
                from
            );
        }
        _ => {}
    }
}

async fn handle_search_response(
    response: emulebb_kad_proto::packet::SearchRes,
    from: SocketAddr,
    target: NodeId,
    queried_addrs: &HashSet<SocketAddr>,
    result_tx: &Option<mpsc::Sender<(Ed2kHash, Vec<Tag>)>>,
    collect_search_entries: bool,
    search_entries: &mut Vec<(Ed2kHash, Vec<Tag>)>,
) {
    if !search_response_matches(response.target, from, target, queried_addrs) {
        return;
    }

    debug!(
        "search phase got SearchRes: {} results from sender {}",
        response.results.len(),
        response.sender_id
    );
    for entry in response.results {
        forward_search_result_entry(entry, result_tx, collect_search_entries, search_entries).await;
    }
}

fn search_response_matches(
    response_target: NodeId,
    from: SocketAddr,
    target: NodeId,
    queried_addrs: &HashSet<SocketAddr>,
) -> bool {
    if !queried_addrs.contains(&from) {
        trace!("ignoring SEARCH_RES from unqueried sender {}", from);
        return false;
    }
    if response_target != target {
        trace!(
            "ignoring SEARCH_RES from {} for mismatched target {}",
            from, response_target
        );
        return false;
    }
    true
}

async fn forward_search_result_entry(
    entry: emulebb_kad_proto::packet::SearchResultEntry,
    result_tx: &Option<mpsc::Sender<(Ed2kHash, Vec<Tag>)>>,
    collect_search_entries: bool,
    search_entries: &mut Vec<(Ed2kHash, Vec<Tag>)>,
) {
    if let Some(tx) = result_tx.as_ref() {
        let _ = tx.send((entry.entry_id, entry.tags.clone())).await;
    }
    if collect_search_entries {
        search_entries.push((entry.entry_id, entry.tags));
    }
}

fn search_phase_receiver_closed(error: tokio::sync::broadcast::error::RecvError) -> bool {
    match error {
        tokio::sync::broadcast::error::RecvError::Lagged(skipped) => {
            warn!(
                "search phase broadcast receiver lagged; skipped {} packets",
                skipped
            );
            false
        }
        tokio::sync::broadcast::error::RecvError::Closed => true,
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
    ip_filter: Option<&KadIpFilter>,
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

        // Oracle Process_KADEMLIA2_RES per-contact filtering
        // (KademliaUDPListener.cpp:830-857): Kad1 nodes (version < 2) are no
        // longer accepted, and a contact on UDP port 53 is rejected unless it
        // is a modern (version > 5) crypto-capable node ("No DNS Port without
        // encryption").
        if entry.version < KADEMLIA_VERSION2_47A {
            continue;
        }
        if entry.udp_port == 53 && entry.version <= KADEMLIA_VERSION5_48A {
            continue;
        }

        let ip = entry.ip_addr();
        // Per-contact ip-filter drop (oracle KademliaUDPListener.cpp:830-857
        // `theApp.ipfilter->IsFiltered(...)`). The IpFilter lives in emulebb-ed2k
        // (which depends on this crate), so core bridges it via this hook; when no
        // hook is wired (tests / filter disabled) no contact is dropped here.
        if let Some(filter) = ip_filter
            && filter(ip)
        {
            continue;
        }
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
