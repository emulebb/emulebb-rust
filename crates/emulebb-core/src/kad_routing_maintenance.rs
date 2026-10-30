//! Periodic Kad routing-table maintenance loop (oracle `CRoutingZone` timers).
//!
//! The master keeps its routing tree healthy through two cadenced per-zone
//! callbacks driven by the Kad event scheduler:
//!   - `OnBigTimer` (~10 s/zone): a per-zone random-target NODE lookup (one
//!     initial REQ, stop on first RES) to refill/refresh buckets
//!     (`RoutingZone.cpp:802-810,908-916`, `Search.cpp:194,373-387`).
//!   - `OnSmallTimer` (~1 min/leaf): seed expiry windows, drop dead+expired
//!     contacts, and HELLO-probe the single lowest-quality expired contact per
//!     leaf to re-verify liveness (`RoutingZone.cpp:852-906`).
//!
//! `CKademlia::Process` additionally re-runs the NODECOMPLETE self-lookup on
//! its own KadID every 4 hours (`m_tNextSelfLookup`, Kademlia.cpp:261-264) to
//! keep the home-bucket neighborhood verified over long uptimes; that timer
//! also lives in this loop.
//!
//! This loop ports both onto the rust `DhtNode`: the heavy decisions (which
//! contacts are dead/stale, which leaves to refresh, the in-zone random target)
//! live in the routing crate; this loop only drives the wire side (sending the
//! re-probe HELLO and running the random lookups) and the cadence.

use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use emulebb_ed2k::{ed2k_server::Ed2kServerState, kad_firewall::KadFirewallState};
use emulebb_kad_dht::{DhtNode, RpcWorkClass};
use emulebb_kad_proto::{KadPacket, NodeId};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};

use crate::kad_hello::build_kad_hello_request;

/// Oracle `OnBigTimer` base cadence (`StartTimer` seeds `SEC(10)`): we run one
/// bucket-refresh pass per tick.
const BIG_TIMER_SECS: u64 = 10;
/// Oracle `OnSmallTimer` runs once per minute per leaf; we sweep the whole table
/// on this cadence.
const SMALL_TIMER_SECS: u64 = 60;
/// Oracle contact-consolidate timer (`CKademlia::m_tConsolidate`, seeded
/// `tNow + MIN2S(45)` and re-armed every 45 min in `CKademlia::Process`,
/// Kademlia.cpp:157,309-314): merge sparse sibling leaf zones back into their
/// parent to keep the tree compact over long uptimes.
const CONSOLIDATE_SECS: u64 = 45 * 60;
/// Bound the number of stale contacts we HELLO-probe per small-timer sweep so a
/// large table stays gentle (the master probes one per leaf; we cap the total).
const MAX_PROBES_PER_SWEEP: usize = 16;
/// Oracle self-lookup cadence (`m_tNextSelfLookup` re-armed `tNow + HR2S(4)`
/// each time it fires, Kademlia.cpp:261-264). The master seeds the first run
/// `MIN2S(3)` after Kad start (Kademlia.cpp:144-145); our bootstrap already
/// performs that first own-ID lookup, so the loop owes the NEXT one a full
/// period of connected uptime.
const SELF_LOOKUP_SECS: u64 = 4 * 60 * 60;

/// A re-probe target copied out of the routing crate's per-leaf candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProbeTarget {
    id: NodeId,
    ip: Ipv4Addr,
    udp_port: u16,
    kad_version: u8,
}

#[derive(Debug, Clone, Copy)]
struct QueuedProbe {
    target: ProbeTarget,
    enqueued_at: Instant,
    sequence: u64,
}

#[derive(Debug, Clone, Copy)]
struct ProbeCycle {
    tail_sequence: u64,
    started_at: Instant,
}

/// Persistent FIFO for due per-leaf probes.
///
/// The cycle marker captures the queue tail when a traversal starts. New work
/// may append behind it without delaying completion of the current traversal,
/// so the reported latency remains meaningful under sustained load.
#[derive(Debug, Default)]
struct ProbeScheduler {
    pending: VecDeque<QueuedProbe>,
    queued_ids: HashSet<NodeId>,
    next_sequence: u64,
    cycle: Option<ProbeCycle>,
}

#[derive(Debug, Clone, Copy)]
struct DequeuedProbe {
    queued: QueuedProbe,
    full_cycle_latency: Option<Duration>,
}

impl ProbeScheduler {
    fn enqueue_due(
        &mut self,
        targets: impl IntoIterator<Item = ProbeTarget>,
        now: Instant,
    ) -> usize {
        let mut due = 0usize;
        for target in targets {
            due += 1;
            if self.queued_ids.insert(target.id) {
                let sequence = self.take_sequence();
                self.pending.push_back(QueuedProbe {
                    target,
                    enqueued_at: now,
                    sequence,
                });
            }
        }
        self.ensure_cycle(now);
        due
    }

    fn take_next(&mut self, now: Instant) -> Option<DequeuedProbe> {
        let queued = self.pending.pop_front()?;
        self.queued_ids.remove(&queued.target.id);

        let full_cycle_latency = self
            .cycle
            .filter(|cycle| cycle.tail_sequence == queued.sequence)
            .map(|cycle| now.saturating_duration_since(cycle.started_at));
        if full_cycle_latency.is_some() {
            self.cycle = None;
            self.ensure_cycle(now);
        }

        Some(DequeuedProbe {
            queued,
            full_cycle_latency,
        })
    }

    fn requeue(&mut self, queued: QueuedProbe, now: Instant) {
        if self.queued_ids.insert(queued.target.id) {
            let sequence = self.take_sequence();
            self.pending.push_back(QueuedProbe {
                target: queued.target,
                enqueued_at: queued.enqueued_at,
                sequence,
            });
            self.ensure_cycle(now);
        }
    }

    fn len(&self) -> usize {
        self.pending.len()
    }

    fn oldest_deferred_age(&self, now: Instant) -> Option<Duration> {
        self.pending
            .iter()
            .map(|queued| now.saturating_duration_since(queued.enqueued_at))
            .max()
    }

    fn ensure_cycle(&mut self, now: Instant) {
        if self.cycle.is_none()
            && let Some(tail) = self.pending.back()
        {
            self.cycle = Some(ProbeCycle {
                tail_sequence: tail.sequence,
                started_at: now,
            });
        }
    }

    fn take_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        sequence
    }
}

/// Cadence bookkeeping for the 4-hour NODECOMPLETE self-lookup.
///
/// Only connected (bootstrapped) ticks advance toward the next run — the
/// oracle timer only ticks while Kad runs — and a reconnect re-arms the full
/// period, because the bootstrap self-lookup is the first run of a session
/// (oracle `Start()` re-seeds `m_tNextSelfLookup`, Kademlia.cpp:144-145).
struct SelfLookupTimer {
    period_ticks: u64,
    remaining_ticks: u64,
    was_connected: bool,
}

impl SelfLookupTimer {
    fn new(period_ticks: u64) -> Self {
        let period_ticks = period_ticks.max(1);
        Self {
            period_ticks,
            remaining_ticks: period_ticks,
            was_connected: false,
        }
    }

    /// Advance one maintenance tick. Returns true when the self-lookup is due,
    /// re-arming for a full period (oracle `m_tNextSelfLookup = tNow + HR2S(4)`).
    fn on_tick(&mut self, connected: bool) -> bool {
        if !connected {
            self.was_connected = false;
            return false;
        }
        if !self.was_connected {
            self.was_connected = true;
            self.remaining_ticks = self.period_ticks;
        }
        self.remaining_ticks -= 1;
        if self.remaining_ticks == 0 {
            self.remaining_ticks = self.period_ticks;
            true
        } else {
            false
        }
    }
}

/// Drive periodic routing-table maintenance for the life of the node.
pub(crate) async fn run_kad_routing_maintenance_loop(
    dht: DhtNode,
    ed2k_listener: Arc<TcpListener>,
    server_state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    shutdown: Arc<AtomicBool>,
) {
    let big_timer = Duration::from_secs(BIG_TIMER_SECS);
    let mut ticks_since_small_timer = 0u64;
    let small_timer_ticks = SMALL_TIMER_SECS / BIG_TIMER_SECS.max(1);
    let mut ticks_since_consolidate = 0u64;
    let consolidate_ticks = CONSOLIDATE_SECS / BIG_TIMER_SECS.max(1);
    let mut self_lookup_timer = SelfLookupTimer::new(SELF_LOOKUP_SECS / BIG_TIMER_SECS.max(1));
    let mut probe_scheduler = ProbeScheduler::default();

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(big_timer).await;
        if shutdown.load(Ordering::SeqCst) {
            continue;
        }

        // ── 4-hour NODECOMPLETE self-lookup (oracle m_tNextSelfLookup,
        // Kademlia.cpp:261-264). Never runs while disconnected. ──
        if self_lookup_timer.on_tick(dht.is_bootstrapped()) {
            run_self_lookup(&dht);
        }

        if !dht.is_bootstrapped() {
            continue;
        }

        // ── OnBigTimer: per-zone random-target lookups to refill buckets. ──
        run_bucket_refresh(&dht).await;

        // ── OnSmallTimer: roughly once a minute. ──
        ticks_since_small_timer += 1;
        if ticks_since_small_timer >= small_timer_ticks {
            ticks_since_small_timer = 0;
            run_small_timer_sweep(
                &dht,
                &ed2k_listener,
                &server_state,
                &kad_firewall,
                &mut probe_scheduler,
            )
            .await;
        }

        // ── Consolidate: roughly every 45 minutes. ──
        ticks_since_consolidate += 1;
        if ticks_since_consolidate >= consolidate_ticks {
            ticks_since_consolidate = 0;
            let merged = dht.routing_consolidate().await;
            if merged > 0 {
                tracing::debug!("kad routing consolidate merged {merged} sparse zones");
            }
        }
    }
}

/// Kick off at most one random-target NODE lookup per tick, into the next due
/// refreshable leaf zone, to keep buckets populated (oracle `RandomLookup`).
/// The master fires at most ONE zone's `OnBigTimer` per scheduler pass
/// (`tNow >= m_tBigTimer` + `m_tBigTimer = tNow + SEC(10)`,
/// Kademlia.cpp:289-294) and re-arms the fired zone one hour out
/// (`m_tNextBigTimer = tNow + HR2S(1)`); the per-zone re-arm lives in the
/// routing table, so ticks naturally rotate across due zones.
async fn run_bucket_refresh(dht: &DhtNode) {
    let Some(target) = dht.routing_take_due_random_lookup_target().await else {
        return;
    };
    let dht = dht.clone();
    tokio::spawn(async move {
        // Oracle NODE search (CSearchManager::FindNode(uRandom, false),
        // RoutingZone.cpp:915): ONE initial KADEMLIA2_REQ, jump-start retries
        // only while silent, stop on the first RES (Search.cpp:194,373-387) —
        // not a full convergence walk. The answered contacts are folded into
        // the routing table by the AddUnfiltered RES sink.
        let outcome = dht
            .refresh_node_lookup(&target, RpcWorkClass::Maintenance)
            .await;
        tracing::debug!(
            "kad routing refresh (NODE lookup) target={target} responded={} reqs_sent={} contacts_ingested={}",
            outcome.responded,
            outcome.reqs_sent,
            outcome.contacts_ingested
        );
    });
}

/// Kick off the 4-hour NODECOMPLETE self-lookup (oracle
/// `CSearchManager::FindNode(GetKadID(), true)` from `CKademlia::Process`,
/// Kademlia.cpp:261-264): a full ALPHA convergence walk on our own KadID —
/// every `KADEMLIA2_REQ` with the NODE-family contact-count byte 0x0B
/// (Search.cpp:1643-1647) — that re-verifies and refills the home-bucket
/// neighborhood. Runs detached like the bucket refresh so a slow walk (up to
/// the 45 s `SEARCHNODE_LIFETIME`) never stalls the timer loop.
fn run_self_lookup(dht: &DhtNode) {
    let dht = dht.clone();
    tokio::spawn(async move {
        let target = dht.own_id();
        match dht
            .self_node_complete_lookup(RpcWorkClass::Maintenance)
            .await
        {
            Ok(closest) => tracing::debug!(
                "kad self lookup (NODECOMPLETE) target={target} closest_responded={}",
                closest.len()
            ),
            Err(error) => {
                tracing::debug!("kad self lookup (NODECOMPLETE) target={target} failed: {error}");
            }
        }
    });
}

/// Run the small-timer sweep: drop dead+expired contacts and HELLO-probe the
/// lowest-quality expired contact of each leaf to re-verify liveness.
async fn run_small_timer_sweep(
    dht: &DhtNode,
    ed2k_listener: &TcpListener,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    probe_scheduler: &mut ProbeScheduler,
) {
    // Sweep the inbound flood tracker on the same minute cadence: its per-(IP,
    // bucket) token buckets and flood bans are only aged lazily on access, so
    // idle entries would otherwise accumulate without bound.
    dht.prune_packet_tracker();

    let now = Instant::now();
    let probes = dht.routing_small_timer_maintenance().await;
    let due = probe_scheduler.enqueue_due(
        probes.into_iter().map(|probe| ProbeTarget {
            id: probe.id,
            ip: probe.ip,
            udp_port: probe.udp_port,
            kad_version: probe.kad_version,
        }),
        now,
    );
    let local_ip = dht.bind_addr().ok().map(|addr| addr.ip());
    let mut sent = 0usize;
    let mut inspected = 0usize;
    let inspect_limit = probe_scheduler.len();
    let mut full_cycles_completed = 0usize;
    let mut full_cycle_latency = None;

    while sent < MAX_PROBES_PER_SWEEP && inspected < inspect_limit {
        let Some(dequeued) = probe_scheduler.take_next(Instant::now()) else {
            break;
        };
        inspected += 1;
        if let Some(latency) = dequeued.full_cycle_latency {
            full_cycles_completed += 1;
            full_cycle_latency =
                Some(full_cycle_latency.map_or(latency, |current: Duration| current.max(latency)));
        }

        let queued = dequeued.queued;
        let Some(probe) = revalidate_probe(dht, queued.target, local_ip).await else {
            continue;
        };
        let initial_addr = SocketAddr::new(IpAddr::V4(probe.ip), probe.udp_port);

        let hello = match build_kad_hello_request(
            dht,
            ed2k_listener,
            server_state,
            kad_firewall,
            // Request an ACK so a successful re-probe can re-verify the contact.
            true,
            // The contact's version gates the KADMISCOPTIONS tag (v8+ only).
            probe.kad_version,
        )
        .await
        {
            Ok(hello) => hello,
            Err(error) => {
                tracing::debug!("failed to build Kad re-probe HELLO for {initial_addr}: {error}");
                probe_scheduler.requeue(queued, Instant::now());
                continue;
            }
        };
        let Some(current_probe) = revalidate_probe(dht, probe, local_ip).await else {
            continue;
        };
        if current_probe.kad_version != probe.kad_version {
            probe_scheduler.requeue(
                QueuedProbe {
                    target: current_probe,
                    ..queued
                },
                Instant::now(),
            );
            continue;
        }
        let probe = current_probe;
        let addr = SocketAddr::new(IpAddr::V4(probe.ip), probe.udp_port);
        // Advance the staleness counter the way the oracle CheckingType does as
        // it sends the probe, so a contact we cannot reach still ages toward
        // removal on the next sweeps. A missing contact is a final just-in-time
        // revalidation failure and must not consume the outbound budget.
        if dht.routing_advance_checking_type(&probe.id).await.is_none() {
            continue;
        }
        tracing::debug!(
            "kad routing re-probe to={} contact_id={} contact_version={}",
            addr,
            probe.id,
            probe.kad_version
        );
        sent += 1;
        if let Err(error) = dht
            .send_packet_with_class(addr, &KadPacket::HelloReq(hello), RpcWorkClass::Maintenance)
            .await
        {
            tracing::debug!("failed to send Kad re-probe HELLO to {addr}: {error}");
        }
    }

    let diagnostic_at = Instant::now();
    let deferred = probe_scheduler.len();
    let oldest_deferred_ms = probe_scheduler
        .oldest_deferred_age(diagnostic_at)
        .map(|age| age.as_millis());
    let full_cycle_latency_ms = full_cycle_latency.map(|latency| latency.as_millis());
    tracing::debug!(
        due,
        sent,
        deferred,
        oldest_deferred_ms = ?oldest_deferred_ms,
        full_cycles_completed,
        full_cycle_latency_ms = ?full_cycle_latency_ms,
        "kad routing small-timer maintenance sweep"
    );
}

/// Refresh a deferred target from current routing state immediately before its
/// wire work. Contacts that disappeared, recovered, died, became local, or can
/// no longer speak Kad2 are discarded instead of consuming the send budget.
async fn revalidate_probe(
    dht: &DhtNode,
    queued: ProbeTarget,
    local_ip: Option<IpAddr>,
) -> Option<ProbeTarget> {
    let now = SystemTime::now();
    let contact = dht
        .routing_contacts()
        .await
        .into_iter()
        .find(|contact| contact.id == queued.id)?;
    let addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.udp_port);
    if contact.is_dead()
        || !contact.is_expired_at(now)
        || contact.kad_version < 2
        || local_ip == Some(addr.ip())
    {
        return None;
    }
    Some(ProbeTarget {
        id: contact.id,
        ip: contact.ip,
        udp_port: contact.udp_port,
        kad_version: contact.kad_version,
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use emulebb_kad_proto::NodeId;

    use super::{
        BIG_TIMER_SECS, MAX_PROBES_PER_SWEEP, ProbeScheduler, ProbeTarget, SELF_LOOKUP_SECS,
        SMALL_TIMER_SECS, SelfLookupTimer,
    };

    fn period_ticks() -> u64 {
        SELF_LOOKUP_SECS / BIG_TIMER_SECS
    }

    fn probe(index: u8) -> ProbeTarget {
        let mut id = [0u8; 16];
        id[0] = index;
        ProbeTarget {
            id: NodeId::from_bytes(id),
            ip: Ipv4Addr::new(192, 0, 2, index.saturating_add(1)),
            udp_port: 4_000 + u16::from(index),
            kad_version: 8,
        }
    }

    /// The self-lookup fires after exactly 4 hours of connected ticks and
    /// re-arms for another full 4-hour period on each fire (oracle
    /// `m_tNextSelfLookup = tNow + HR2S(4)`, Kademlia.cpp:261-264).
    #[test]
    fn self_lookup_timer_fires_at_four_hours_and_rearms() {
        let period = period_ticks();
        assert_eq!(period * BIG_TIMER_SECS, 4 * 60 * 60);

        let mut timer = SelfLookupTimer::new(period);
        for _ in 0..period - 1 {
            assert!(!timer.on_tick(true), "must not fire before the 4h mark");
        }
        assert!(timer.on_tick(true), "fires exactly at the 4h mark");
        for _ in 0..period - 1 {
            assert!(!timer.on_tick(true), "re-armed for a full second period");
        }
        assert!(timer.on_tick(true), "fires again a full period later");
    }

    /// Disconnected ticks never fire the self-lookup and never advance the
    /// cadence; a reconnect re-arms the full period, because the bootstrap
    /// self-lookup is the first run of a session (oracle `Start()` re-seeds
    /// `m_tNextSelfLookup`, Kademlia.cpp:144-145).
    #[test]
    fn self_lookup_timer_never_fires_disconnected_and_rearms_on_reconnect() {
        let period = period_ticks();
        let mut timer = SelfLookupTimer::new(period);

        // Almost due, then a disconnect.
        for _ in 0..period - 1 {
            assert!(!timer.on_tick(true));
        }
        for _ in 0..2 * period {
            assert!(!timer.on_tick(false), "never fires while disconnected");
        }

        // Reconnect: the accumulated progress is discarded — a full period of
        // connected uptime is owed again before the next self-lookup.
        for _ in 0..period - 1 {
            assert!(!timer.on_tick(true), "reconnect re-arms the full period");
        }
        assert!(timer.on_tick(true));
    }

    #[test]
    fn probe_scheduler_deduplicates_without_changing_fifo_order() {
        let now = Instant::now();
        let mut scheduler = ProbeScheduler::default();

        assert_eq!(
            scheduler.enqueue_due((0..20).map(probe).chain((0..20).rev().map(probe)), now),
            40
        );
        assert_eq!(scheduler.len(), 20);

        let drained = (0..20)
            .map(|_| scheduler.take_next(now).unwrap().queued.target)
            .collect::<Vec<_>>();
        assert_eq!(drained, (0..20).map(probe).collect::<Vec<_>>());
        assert_eq!(scheduler.len(), 0);
    }

    #[test]
    fn sustained_due_load_services_every_leaf_fairly_with_bounded_sweeps() {
        const DUE_LEAVES: u8 = 32;
        const SWEEPS: u64 = 20;

        let started_at = Instant::now();
        let mut scheduler = ProbeScheduler::default();
        let mut sent_per_leaf = [0usize; DUE_LEAVES as usize];
        let mut observed_full_cycle = None;

        for sweep in 0..SWEEPS {
            let now = started_at + Duration::from_secs(sweep * SMALL_TIMER_SECS);
            assert_eq!(
                scheduler.enqueue_due((0..DUE_LEAVES).map(probe), now),
                usize::from(DUE_LEAVES)
            );

            let mut sent_this_sweep = 0usize;
            while sent_this_sweep < MAX_PROBES_PER_SWEEP {
                let dequeued = scheduler.take_next(now).unwrap();
                sent_per_leaf[usize::from(dequeued.queued.target.id.0[0])] += 1;
                sent_this_sweep += 1;
                observed_full_cycle = observed_full_cycle.or(dequeued.full_cycle_latency);
            }
            assert_eq!(sent_this_sweep, MAX_PROBES_PER_SWEEP);
        }

        let least_serviced = *sent_per_leaf.iter().min().unwrap();
        let most_serviced = *sent_per_leaf.iter().max().unwrap();
        assert!(
            least_serviced > 0,
            "every continuously due leaf must progress"
        );
        assert_eq!(
            most_serviced - least_serviced,
            0,
            "FIFO rotation must not prefer earlier leaves under sustained load"
        );
        assert_eq!(
            observed_full_cycle,
            Some(Duration::from_secs(SMALL_TIMER_SECS)),
            "the first 32-leaf traversal completes on the second 16-probe sweep"
        );
    }

    #[test]
    fn oldest_deferred_age_survives_deduplication_and_requeue() {
        let started_at = Instant::now();
        let later = started_at + Duration::from_secs(30);
        let diagnostic_at = started_at + Duration::from_secs(90);
        let mut scheduler = ProbeScheduler::default();

        scheduler.enqueue_due([probe(1)], started_at);
        scheduler.enqueue_due([probe(1), probe(2)], later);
        let first = scheduler.take_next(later).unwrap().queued;
        scheduler.requeue(first, later);

        assert_eq!(
            scheduler.oldest_deferred_age(diagnostic_at),
            Some(Duration::from_secs(90))
        );
    }
}
