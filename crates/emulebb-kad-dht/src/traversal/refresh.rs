//! NODE-type bucket-refresh lookup (oracle `CSearch` search type `NODE`).
//!
//! The hourly zone refresh (`CRoutingZone::RandomLookup`, RoutingZone.cpp:908-916)
//! creates a NODE search via `CSearchManager::FindNode(uRandom, false)`
//! (SearchManager.cpp:236-243). Unlike every other lookup, a NODE search is
//! deliberately feather-weight on the wire:
//!
//!   - `CSearch::Go` sends exactly ONE initial `KADEMLIA2_REQ` to the closest
//!     known contact (`iCount = (m_uType == NODE) ? 1 : min(ALPHA_QUERY, ...)`,
//!     Search.cpp:194), with the NODE contact-count byte `KADEMLIA_FIND_NODE`
//!     (0x0B, Search.cpp:1639-1647).
//!   - The FIRST `KADEMLIA2_RES` ends the walk: `ProcessResponse` clears
//!     `m_mapPossible` so the next jump-start tick stops the search
//!     (Search.cpp:373-387). The RES contacts are NOT walked to convergence;
//!     they reach the routing table through the UDP listener's `AddUnfiltered`
//!     path — mirrored here by the [`KadResContactSink`].
//!   - While no response has arrived, `CSearchManager::JumpStart` (1 s cadence,
//!     `SEARCH_JUMPSTART`) re-drives the search: once past the response-idle
//!     gate (est. max response time, Search.cpp:271-276) each tick sends one
//!     `KADEMLIA2_REQ` to the next-closest untried contact (Search.cpp:307-328),
//!     until a response arrives, the candidate pool is exhausted, or the search
//!     hits `SEARCHNODE_LIFETIME` (45 s, Defines.h:53; SearchManager.cpp:333-337
//!     deletes NODE searches on lifetime only).
//!
//! NODECOMPLETE (the 4-hour self-lookup, KAD-G4) is intentionally NOT this
//! shape: the oracle starts it with `iCount = ALPHA_QUERY` and walks it to
//! convergence, so it belongs on the full [`super::run_traversal`] machinery;
//! only its lifetime/termination bookkeeping differs. Keep the search-type
//! distinction at the caller (`DhtNode`) level.

use super::{
    CandidateState, KadIpFilter, KadResContactSink, SEARCH_JUMPSTART_IDLE_GRACE,
    SEARCH_JUMPSTART_TICK, TraversalCandidate, TraversalContact, initial_traversal_candidates,
    register_traversal_identity, sanitize_res_contacts,
};
use emulebb_kad_net::{NetError, RpcManager, RpcWorkClass};
use emulebb_kad_proto::{KadPacket, NodeId, constants::KADEMLIA_FIND_NODE, opcode, packet::Req};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{trace, warn};

/// Oracle NODE-search lifetime (`SEARCHNODE_LIFETIME`, Defines.h:53).
pub const NODE_REFRESH_LIFETIME: Duration = Duration::from_secs(45);

/// One completed refresh query: the queried contact id and its RPC result.
type RefreshQueryResult = (NodeId, Result<KadPacket, NetError>);

/// Inputs for one NODE-type refresh lookup.
pub struct NodeRefreshConfig {
    /// Random in-zone target being refreshed (oracle `RandomLookup` target).
    pub target: NodeId,
    /// Whole-search lifetime; late responses still count within it
    /// (`SEARCHNODE_LIFETIME`).
    pub lifetime: Duration,
    /// Response-idle gate before the first jump-start retry (oracle
    /// `m_tLastResponse + tMaxPendingSeconds`, Search.cpp:271-276).
    pub retry_gate: Duration,
    /// Jump-start cadence between subsequent retries (`SEARCH_JUMPSTART`, 1 s).
    pub retry_tick: Duration,
    /// External cancellation for the whole run.
    pub cancel: CancellationToken,
    /// Outbound budget class used by this lookup.
    pub work_class: RpcWorkClass,
    /// Optional per-`RES`-contact ip-filter hook (see [`KadIpFilter`]).
    pub ip_filter: Option<KadIpFilter>,
    /// Optional sink fed every good `RES` contact (oracle `AddUnfiltered`).
    pub res_contact_sink: Option<KadResContactSink>,
}

impl NodeRefreshConfig {
    /// Oracle-shaped defaults for a bucket-refresh NODE lookup.
    pub fn new(target: NodeId, work_class: RpcWorkClass) -> Self {
        Self {
            target,
            lifetime: NODE_REFRESH_LIFETIME,
            retry_gate: SEARCH_JUMPSTART_IDLE_GRACE,
            retry_tick: SEARCH_JUMPSTART_TICK,
            cancel: CancellationToken::new(),
            work_class,
            ip_filter: None,
            res_contact_sink: None,
        }
    }
}

/// Wire-facing summary of one NODE refresh lookup, for maintenance diagnostics.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NodeRefreshOutcome {
    /// Whether any queried contact answered with a `RES`.
    pub responded: bool,
    /// Total `KADEMLIA2_REQ` packets sent (oracle target: 1 typical, a few
    /// jump-start retries worst case).
    pub reqs_sent: usize,
    /// Good sanitized `RES` contacts offered to the routing-table sink.
    pub contacts_ingested: usize,
}

/// Run one oracle-shaped NODE refresh lookup: 1 initial `REQ` to the closest
/// candidate, jump-start retries while silent, stop on the first `RES`.
pub async fn run_node_refresh_lookup(
    rpc: &RpcManager,
    initial_candidates: Vec<TraversalContact>,
    config: NodeRefreshConfig,
) -> NodeRefreshOutcome {
    let mut outcome = NodeRefreshOutcome::default();
    let mut candidates = initial_traversal_candidates(initial_candidates, config.target);
    if candidates.is_empty() {
        return outcome;
    }
    let deadline = Instant::now() + config.lifetime;
    let mut join_set = JoinSet::new();

    // CSearch::Go (Search.cpp:194): exactly one initial REQ, to the closest
    // known candidate (m_mapPossible is distance-sorted; iCount = 1 takes its
    // first entry).
    send_next_refresh_req(rpc, &mut candidates, &mut join_set, &config, deadline);
    outcome.reqs_sent += 1;
    // The oracle jump-start gate compares against m_tLastResponse, which is
    // seeded to the creation time; with no response the first retry becomes
    // eligible retry_gate after the initial send (Search.cpp:80,271-276).
    let mut next_retry_at = Instant::now() + config.retry_gate;

    loop {
        if config.cancel.is_cancelled() || Instant::now() >= deadline {
            break;
        }
        let wake_at = next_retry_at.min(deadline);
        tokio::select! {
            _ = config.cancel.cancelled() => break,
            joined = join_set.join_next(), if !join_set.is_empty() => {
                if handle_refresh_join(joined, &mut candidates, &config, &mut outcome) {
                    // First RES: the oracle clears m_mapPossible and stops the
                    // walk (Search.cpp:385-387) — no further REQs.
                    break;
                }
                if pool_exhausted(&candidates) && join_set.is_empty() {
                    break;
                }
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(wake_at)) => {
                if Instant::now() >= deadline {
                    break;
                }
                // JumpStart tick (Search.cpp:307-328): one REQ to the
                // next-closest untried candidate per tick while silent.
                let sent = send_next_refresh_req(rpc, &mut candidates, &mut join_set, &config, deadline);
                if sent {
                    outcome.reqs_sent += 1;
                } else if join_set.is_empty() {
                    // Out of contacts with nothing outstanding: the oracle
                    // PrepareToStops on an empty possible map (Search.cpp:278-282).
                    break;
                }
                next_retry_at = Instant::now() + config.retry_tick;
            }
        }
    }

    join_set.abort_all();
    outcome
}

/// True when no candidate is left to try or await.
fn pool_exhausted(candidates: &[TraversalCandidate]) -> bool {
    !candidates.iter().any(|candidate| {
        matches!(
            candidate.state,
            CandidateState::Pending | CandidateState::Inflight
        )
    })
}

/// Send one `KADEMLIA2_REQ` (NODE contact-count 0x0B) to the closest untried
/// candidate. Returns false when every candidate has already been tried.
fn send_next_refresh_req(
    rpc: &RpcManager,
    candidates: &mut [TraversalCandidate],
    join_set: &mut JoinSet<RefreshQueryResult>,
    config: &NodeRefreshConfig,
    deadline: Instant,
) -> bool {
    // `candidates` is distance-sorted, so the first Pending entry is the
    // closest untried one (oracle m_mapPossible walk, Search.cpp:307-321).
    let Some(candidate) = candidates
        .iter_mut()
        .find(|candidate| candidate.state == CandidateState::Pending)
    else {
        return false;
    };
    candidate.state = CandidateState::Inflight;
    let contact = candidate.contact.clone();
    register_traversal_identity(rpc, &contact);

    let rpc = rpc.clone();
    let target = config.target;
    let work_class = config.work_class;
    // The oracle keeps listening for late RES packets until the search is
    // deleted at lifetime end, so each REQ waits out the remaining lifetime.
    let query_timeout = deadline.saturating_duration_since(Instant::now());
    join_set.spawn(async move {
        let packet = KadPacket::Req(Req {
            count: KADEMLIA_FIND_NODE,
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
    true
}

/// Fold one completed query into the candidate set. Returns true on the first
/// good `RES` (which ends the refresh walk).
fn handle_refresh_join(
    joined: Option<Result<RefreshQueryResult, tokio::task::JoinError>>,
    candidates: &mut [TraversalCandidate],
    config: &NodeRefreshConfig,
    outcome: &mut NodeRefreshOutcome,
) -> bool {
    let (contact_id, query_result) = match joined {
        Some(Ok(result)) => result,
        Some(Err(error)) => {
            warn!("refresh lookup task panicked: {}", error);
            return false;
        }
        None => return false,
    };
    let candidate = candidates
        .iter_mut()
        .find(|candidate| candidate.contact.id == contact_id);
    match query_result {
        Ok(KadPacket::Res(response)) => {
            let responder_addr = candidate
                .as_ref()
                .map(|candidate| candidate.contact.addr)
                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            // Same over-count / Kad1 / ip-filter / per-/24 sanitation as any
            // RES (Search.cpp:352, KademliaUDPListener.cpp:830-857). An
            // over-count answer is ignored wholesale like the oracle's
            // "too-many-contacts" reject, and the walk continues.
            let Some(sanitized) = sanitize_res_contacts(
                &response.contacts,
                responder_addr,
                KADEMLIA_FIND_NODE as usize,
                config.ip_filter.as_ref(),
            ) else {
                trace!("refresh lookup ignoring over-count RES from {}", contact_id);
                if let Some(candidate) = candidate {
                    candidate.state = CandidateState::Failed;
                }
                return false;
            };
            if let Some(candidate) = candidate {
                candidate.state = CandidateState::Responded;
            }
            for entry in &sanitized {
                // Oracle AddUnfiltered (KademliaUDPListener.cpp:849): the NODE
                // search itself ignores the results (Search.cpp:373-377); the
                // routing table still learns every good answered contact.
                if let Some(sink) = &config.res_contact_sink {
                    sink(entry);
                }
            }
            outcome.contacts_ingested += sanitized.len();
            outcome.responded = true;
            true
        }
        Ok(other) => {
            trace!(
                "refresh lookup unexpected packet from {}: 0x{:02X}",
                contact_id,
                other.opcode()
            );
            if let Some(candidate) = candidate {
                candidate.state = CandidateState::Failed;
            }
            false
        }
        Err(error) => {
            trace!("refresh lookup query failed for {}: {}", contact_id, error);
            if let Some(candidate) = candidate {
                candidate.state = CandidateState::Failed;
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulebb_kad_net::{MockTransport, ObfuscationLayer, RpcClassBudgetConfig, RpcConfig};
    use emulebb_kad_proto::packet::{ContactEntry, Res};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn make_rpc() -> (Arc<MockTransport>, RpcManager) {
        let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
        let rpc = RpcManager::new(
            Arc::clone(&transport),
            ObfuscationLayer::new(NodeId::ZERO, 0, false),
            RpcConfig {
                // These tests compress the oracle's 3s gate / 1s tick into
                // milliseconds, so lift the 1-pps Maintenance budget that would
                // otherwise stall the compressed retries — the refresh loop's
                // own pacing is what is under test here, not the limiter.
                class_budgets: RpcClassBudgetConfig {
                    maintenance_max_outbound_pps: 0,
                    ..RpcClassBudgetConfig::default()
                },
                ..RpcConfig::default()
            },
        );
        let _handle = rpc.start();
        (transport, rpc)
    }

    /// Distance to target ZERO grows with the id byte, so lower = closer.
    fn contact(id_byte: u8, port: u16) -> TraversalContact {
        TraversalContact {
            id: NodeId::from_bytes([id_byte; 16]),
            addr: format!("192.168.1.{id_byte}:{port}").parse().unwrap(),
            tcp_port: 0,
            version: 9,
        }
    }

    fn drain_reqs(transport: &MockTransport) -> Vec<(SocketAddr, Req)> {
        transport
            .drain_outgoing()
            .into_iter()
            .filter_map(|(addr, bytes)| match KadPacket::decode(&bytes) {
                Ok(KadPacket::Req(req)) => Some((addr, req)),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn refresh_sends_one_initial_req_and_stops_on_first_res() {
        let (transport, rpc) = make_rpc();
        let injector = transport.injector();
        let target = NodeId::ZERO;
        let closest = contact(1, 4672);
        let closest_addr = closest.addr;
        let candidates = vec![contact(3, 4674), closest.clone(), contact(2, 4673)];

        let ingested = Arc::new(AtomicUsize::new(0));
        let ingested_clone = Arc::clone(&ingested);
        let sink: KadResContactSink = Arc::new(move |_entry: &ContactEntry| {
            ingested_clone.fetch_add(1, Ordering::SeqCst);
        });

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            let res = KadPacket::Res(Res {
                target,
                contacts: vec![
                    ContactEntry {
                        node_id: NodeId::from_bytes([0x21; 16]),
                        ip: 0x14151617,
                        udp_port: 4675,
                        tcp_port: 4665,
                        version: 9,
                    },
                    ContactEntry {
                        node_id: NodeId::from_bytes([0x22; 16]),
                        ip: 0x1E1F2021,
                        udp_port: 4676,
                        tcp_port: 4666,
                        version: 9,
                    },
                ],
            });
            injector
                .send((res.encode().unwrap(), closest_addr))
                .await
                .unwrap();
        });

        let mut config = NodeRefreshConfig::new(target, RpcWorkClass::Maintenance);
        config.lifetime = Duration::from_secs(2);
        // Keep the retry gate beyond the injected response so a healthy zone
        // refresh stays at exactly one REQ.
        config.retry_gate = Duration::from_millis(500);
        config.retry_tick = Duration::from_millis(100);
        config.res_contact_sink = Some(sink);
        let outcome = run_node_refresh_lookup(&rpc, candidates, config).await;

        assert!(outcome.responded);
        assert_eq!(outcome.reqs_sent, 1, "NODE refresh sends one initial REQ");
        assert_eq!(outcome.contacts_ingested, 2);
        assert_eq!(
            ingested.load(Ordering::SeqCst),
            2,
            "RES contacts still reach the routing-table sink"
        );

        // Give any (buggy) extra retries time to surface, then assert the wire
        // saw exactly one REQ, to the closest candidate, with the NODE
        // contact-count byte (0x0B).
        tokio::time::sleep(Duration::from_millis(250)).await;
        let reqs = drain_reqs(&transport);
        assert_eq!(reqs.len(), 1, "no further REQs after the first RES");
        assert_eq!(reqs[0].0, closest_addr, "initial REQ goes to the closest");
        assert_eq!(reqs[0].1.count, KADEMLIA_FIND_NODE);
        assert_eq!(reqs[0].1.target, target);
    }

    #[tokio::test]
    async fn refresh_without_responses_walks_pool_and_respects_lifetime() {
        let (transport, rpc) = make_rpc();
        let target = NodeId::ZERO;
        let first = contact(1, 4672);
        let second = contact(2, 4673);
        let candidates = vec![second.clone(), first.clone()];

        let mut config = NodeRefreshConfig::new(target, RpcWorkClass::Maintenance);
        config.lifetime = Duration::from_millis(400);
        config.retry_gate = Duration::from_millis(100);
        config.retry_tick = Duration::from_millis(50);
        let started = Instant::now();
        let outcome = run_node_refresh_lookup(&rpc, candidates, config).await;
        let elapsed = started.elapsed();

        assert!(!outcome.responded);
        assert_eq!(
            outcome.reqs_sent, 2,
            "jump-start walks the whole (small) pool while silent"
        );
        assert!(
            elapsed >= Duration::from_millis(100),
            "no retry before the response-idle gate"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "the lookup ends at its lifetime, not the 45s default"
        );

        let reqs = drain_reqs(&transport);
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].0, first.addr, "initial REQ to the closest");
        assert_eq!(reqs[1].0, second.addr, "retry walks to the next-closest");
        assert!(reqs.iter().all(|(_, req)| req.count == KADEMLIA_FIND_NODE));
    }

    #[tokio::test]
    async fn refresh_with_no_candidates_sends_nothing() {
        let (transport, rpc) = make_rpc();
        let config = NodeRefreshConfig::new(NodeId::ZERO, RpcWorkClass::Maintenance);
        let outcome = run_node_refresh_lookup(&rpc, Vec::new(), config).await;
        assert_eq!(outcome, NodeRefreshOutcome::default());
        assert!(drain_reqs(&transport).is_empty());
    }
}
