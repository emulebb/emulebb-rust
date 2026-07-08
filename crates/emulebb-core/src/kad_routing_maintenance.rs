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
//! This loop ports both onto the rust `DhtNode`: the heavy decisions (which
//! contacts are dead/stale, which leaves to refresh, the in-zone random target)
//! live in the routing crate; this loop only drives the wire side (sending the
//! re-probe HELLO and running the random lookups) and the cadence.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use emulebb_ed2k::{ed2k_server::Ed2kServerState, kad_firewall::KadFirewallState};
use emulebb_kad_dht::{DhtNode, RpcWorkClass};
use emulebb_kad_proto::KadPacket;
use std::net::{IpAddr, SocketAddr};
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

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(big_timer).await;
        if shutdown.load(Ordering::SeqCst) || !dht.is_bootstrapped() {
            continue;
        }

        // ── OnBigTimer: per-zone random-target lookups to refill buckets. ──
        run_bucket_refresh(&dht).await;

        // ── OnSmallTimer: roughly once a minute. ──
        ticks_since_small_timer += 1;
        if ticks_since_small_timer >= small_timer_ticks {
            ticks_since_small_timer = 0;
            run_small_timer_sweep(&dht, &ed2k_listener, &server_state, &kad_firewall).await;
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

/// Run the small-timer sweep: drop dead+expired contacts and HELLO-probe the
/// lowest-quality expired contact of each leaf to re-verify liveness.
async fn run_small_timer_sweep(
    dht: &DhtNode,
    ed2k_listener: &TcpListener,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
) {
    // Sweep the inbound flood tracker on the same minute cadence: its per-(IP,
    // bucket) token buckets and flood bans are only aged lazily on access, so
    // idle entries would otherwise accumulate without bound.
    dht.prune_packet_tracker();

    let mut probes = dht.routing_small_timer_maintenance().await;
    probes.truncate(MAX_PROBES_PER_SWEEP);
    let local_ip = dht.bind_addr().ok().map(|addr| addr.ip());

    for probe in probes {
        let addr = SocketAddr::new(IpAddr::V4(probe.ip), probe.udp_port);
        if local_ip == Some(addr.ip()) {
            continue;
        }
        // Pre-v2 contacts cannot be probed with a Kad2 HELLO; let them age out.
        if probe.kad_version < 2 {
            continue;
        }
        // Advance the staleness counter the way the oracle CheckingType does as
        // it sends the probe, so a contact we cannot reach still ages toward
        // removal on the next sweeps.
        let _ = dht.routing_advance_checking_type(&probe.id).await;

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
                tracing::debug!("failed to build Kad re-probe HELLO for {addr}: {error}");
                continue;
            }
        };
        tracing::debug!(
            "kad routing re-probe to={} contact_id={} contact_version={}",
            addr,
            probe.id,
            probe.kad_version
        );
        if let Err(error) = dht
            .send_packet_with_class(addr, &KadPacket::HelloReq(hello), RpcWorkClass::Maintenance)
            .await
        {
            tracing::debug!("failed to send Kad re-probe HELLO to {addr}: {error}");
        }
    }
}
