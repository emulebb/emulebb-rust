//! Requester-side Kad UDP firewall self-check driver (oracle `CUDPFirewallTester`).
//!
//! Lives in its own module to keep the orchestration in `lib.rs` lean. The driver
//! selects open Kad v6+ helper contacts, opens an eD2k TCP session to each and
//! sends `OP_FWCHECKUDPREQ`; each helper replies `KADEMLIA2_FIREWALLUDP` to our
//! intern (+extern) Kad UDP ports. The shared `KadFirewallState` correlates those
//! replies with the active round (recorded by the inbound Kad packet handler in
//! `lib.rs`); this loop waits for convergence, finalizes the verdict, and on an
//! open result pins the peer-observed external UDP port into `ExternalReachability`
//! (taking precedence over the UPnP mapping).

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::{
    net::TcpListener,
    sync::{Mutex, Notify, RwLock},
};

use emulebb_ed2k::ed2k_server::Ed2kServerState;
use emulebb_ed2k::{
    ed2k_tcp::{
        Ed2kHelloIdentity, FirewallCheckUdpRequest, KadHelloIdentityState,
        UdpFirewallHelperOutcome, emule_connect_options, enrich_hello_identity,
        request_udp_firewall_check,
    },
    kad_firewall::{KadFirewallState, UdpFirewallCheckSummary},
    reachability::RuntimeReachabilityWriter,
};
use emulebb_kad_dht::{DhtNode, RpcWorkClass};
use emulebb_kad_proto::{KadPacket, constants::K, opcode};

use crate::Ed2kNetworkConfig;

/// Per-helper eD2k TCP timeout for sending `OP_FWCHECKUDPREQ`.
const KAD_UDP_FIREWALL_CHECK_TCP_TIMEOUT_SECS: u64 = 20;
const EXTERNAL_PORT_REPORTER_LIMIT: usize = 3;
const EXTERNAL_PORT_REPORT_TIMEOUT: Duration = Duration::from_secs(3);
const USED_TESTER_RETENTION: Duration = Duration::from_secs(180);
const MAX_RECENT_TESTERS: usize = 1024;
/// How long one round waits for the helpers' `KADEMLIA2_FIREWALLUDP` replies to
/// converge before finalizing the verdict.
const KAD_UDP_FIREWALL_CHECK_RESULT_WAIT_SECS: u64 = 30;
/// Seconds before the requester driver runs its first round, giving the routing
/// table time to learn open v6+ helper contacts after bootstrap.
const KAD_UDP_FIREWALL_CHECK_WARMUP_SECS: u64 = 30;
/// Options for the requester-side Kad UDP firewall self-check driver.
pub(crate) struct KadUdpFirewallCheckOptions {
    pub(crate) dht: DhtNode,
    pub(crate) ed2k_listener: Arc<TcpListener>,
    pub(crate) server_state: Arc<RwLock<Ed2kServerState>>,
    pub(crate) kad_firewall: Arc<Mutex<KadFirewallState>>,
    pub(crate) reachability_writer: RuntimeReachabilityWriter,
    pub(crate) network: Ed2kNetworkConfig,
    /// Fired by `recheck_kad_firewall` to run a round immediately.
    pub(crate) recheck_signal: Arc<Notify>,
    pub(crate) shutdown: Arc<AtomicBool>,
}

/// Drive the eMule requester UDP firewall self-check (`CUDPFirewallTester`).
///
/// Once Kad is bootstrapped, this periodically (and on demand via the recheck
/// signal) selects open v6+ helper contacts, opens an eD2k TCP session to each
/// and sends `OP_FWCHECKUDPREQ`; each helper then replies `KADEMLIA2_FIREWALLUDP`
/// to our intern (+extern) Kad UDP ports. The inbound handler records those
/// replies against the active round in the shared firewall state; this loop waits
/// for convergence, finalizes the verdict, and -- on an open result -- feeds the
/// observed external UDP port into `ExternalReachability` (peer-confirmed, taking
/// precedence over the UPnP mapping). Gentle by design: a small helper count and
/// a wide interval, matching the oracle cadence.
pub(crate) async fn run_kad_udp_firewall_check_loop(options: KadUdpFirewallCheckOptions) {
    let KadUdpFirewallCheckOptions {
        dht,
        kad_firewall,
        reachability_writer,
        network,
        recheck_signal,
        shutdown,
        ..
    } = &options;
    let interval = Duration::from_secs(network.kad_udp_firewall_check_interval_secs.max(60));
    let mut warmed_up = false;
    let mut used_testers = HashMap::new();

    while !shutdown.load(Ordering::SeqCst) {
        // First round waits a short warmup; later rounds wait the full interval
        // or until a recheck is requested, whichever comes first.
        let wait = if warmed_up {
            interval
        } else {
            Duration::from_secs(KAD_UDP_FIREWALL_CHECK_WARMUP_SECS)
        };
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = recheck_signal.notified() => {}
        }
        warmed_up = true;
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        expire_stale_kad_udp_verification(kad_firewall, reachability_writer, Utc::now()).await;
        if !dht.is_running() || !dht.is_bootstrapped() {
            continue;
        }

        if let Err(error) = run_kad_udp_firewall_check_round(&options, &mut used_testers).await {
            tracing::debug!("Kad UDP firewall check round failed: {error:#}");
            kad_firewall
                .lock()
                .await
                .record_udp_check_inconclusive(format!(
                    "Kad UDP firewall-check driver failed: {error:#}"
                ));
        }
        expire_stale_kad_udp_verification(kad_firewall, reachability_writer, Utc::now()).await;
    }
}

/// Run one requester UDP firewall-check round end to end.
async fn run_kad_udp_firewall_check_round(
    options: &KadUdpFirewallCheckOptions,
    used_testers: &mut HashMap<Ipv4Addr, tokio::time::Instant>,
) -> Result<()> {
    let KadUdpFirewallCheckOptions {
        dht,
        ed2k_listener,
        server_state,
        kad_firewall,
        reachability_writer,
        network,
        shutdown,
        ..
    } = options;
    let bind_addr = dht
        .bind_addr()
        .context("failed to resolve Kad bind address for UDP firewall check")?;
    let internal_udp_port = bind_addr.port();
    if internal_udp_port == 0 {
        anyhow::bail!("Kad UDP bind port is unknown; cannot run firewall check");
    }
    let binding = dht.udp_probe_binding();
    let binding_is_current = || {
        !shutdown.load(Ordering::SeqCst) && dht.is_running() && dht.udp_probe_binding() == binding
    };
    let external_udp_port = discover_external_udp_port(dht, kad_firewall, bind_addr.ip()).await;
    if !binding_is_current() {
        return Ok(());
    }
    let external_udp_port = if external_udp_port == internal_udp_port {
        0
    } else {
        external_udp_port
    };

    let mut helpers = tokio::select! {
        helpers = dht.discover_udp_firewall_helpers() => helpers.into_iter().peekable(),
        () = wait_for_udp_check_binding_change(&binding_is_current) => return Ok(()),
    };
    let expected_ports = [internal_udp_port, external_udp_port];

    let listener_addr = ed2k_listener
        .local_addr()
        .context("failed to read eD2k listener address for UDP firewall check")?;
    let hello_identity = kad_udp_firewall_check_hello_identity(
        dht,
        listener_addr,
        internal_udp_port,
        server_state,
        kad_firewall,
        network,
    )
    .await;
    let tcp_timeout = Duration::from_secs(KAD_UDP_FIREWALL_CHECK_TCP_TIMEOUT_SECS);

    // Ask each helper over eD2k TCP. eMule keys the helper's UDP reply with the
    // per-helper Kad verify key we announce for that IP.
    used_testers.retain(|_, used_at| used_at.elapsed() < USED_TESTER_RETENTION);
    let mut round_started = false;
    let mut tester_reservations = Vec::new();
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(KAD_UDP_FIREWALL_CHECK_RESULT_WAIT_SECS);
    while binding_is_current() && tokio::time::Instant::now() < deadline {
        if round_started {
            let firewall = kad_firewall.lock().await;
            if !firewall.waiting_for_udp_probes(Utc::now()) {
                break;
            }
            if !firewall.udp_check_needs_helper() || helpers.peek().is_none() {
                drop(firewall);
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        }
        let Some(helper) = helpers.next() else { break };
        if used_testers.len() >= MAX_RECENT_TESTERS {
            break;
        }
        if used_testers.contains_key(&helper.ip) || dht.is_known_kad_ip(helper.ip).await {
            continue;
        }
        let helper_ip = IpAddr::V4(helper.ip);
        let Some(reservation) = dht.reserve_fresh_udp_probe(helper_ip) else {
            continue;
        };
        {
            let mut firewall = kad_firewall.lock().await;
            let armed = if round_started {
                firewall.add_udp_check_helper(helper_ip)
            } else {
                firewall.begin_udp_check_for_binding(
                    [helper_ip],
                    expected_ports,
                    Utc::now(),
                    binding,
                )
            };
            if !armed {
                break;
            }
            round_started = true;
        }
        tester_reservations.push(reservation);
        used_testers.insert(helper.ip, tokio::time::Instant::now());
        let request = FirewallCheckUdpRequest {
            internal_udp_port,
            external_udp_port,
            sender_udp_key: dht.verify_key_for_ip(helper.ip),
        };
        let helper_addr = SocketAddr::new(helper_ip, helper.tcp_port);
        let request_send = request_udp_firewall_check(
            Some(dht.clone()),
            emulebb_ed2k::networking::EgressBinding::new(network.bind_ip, network.egress_route),
            helper_addr,
            hello_identity,
            Arc::clone(&network.secure_ident),
            request,
            tcp_timeout,
        );
        let result = tokio::select! {
            result = request_send => result,
            () = wait_for_udp_check_binding_change(&binding_is_current) => break,
            () = tokio::time::sleep_until(deadline) => break,
        };
        match result {
            Ok(outcome) => {
                let mut firewall = kad_firewall.lock().await;
                if !binding_is_current() {
                    break;
                }
                firewall.record_udp_check_request_sent(helper_ip);
                if outcome == UdpFirewallHelperOutcome::PeerDisconnected {
                    firewall.record_helper_test_failed(
                        helper_ip,
                        "helper disconnected after UDP firewall-check request",
                    );
                }
                tracing::debug!(
                    "sent OP_FWCHECKUDPREQ to firewall-check helper {helper_addr} (kad v{})",
                    helper.kad_version
                );
            }
            Err(error) => {
                tracing::debug!(
                    "Kad UDP firewall-check request to {helper_addr} failed: {error:#}"
                );
                kad_firewall
                    .lock()
                    .await
                    .record_helper_request_failed(helper_ip, &error.to_string());
            }
        }
    }

    let summary = {
        let mut firewall = kad_firewall.lock().await;
        if !binding_is_current() {
            firewall.cancel_udp_check();
            return Ok(());
        }
        if !round_started {
            firewall.record_udp_check_inconclusive("no fresh UDP firewall-check helpers available");
            return Ok(());
        }
        firewall.finish_udp_check(Utc::now())
    };
    // A success on the external port near the round deadline still gets the
    // full stock grace for a delayed internal-port reply.
    while binding_is_current() && kad_firewall.lock().await.waiting_for_udp_probes(Utc::now()) {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    drop(tester_reservations);
    if binding_is_current() {
        apply_kad_udp_firewall_check_result(kad_firewall, reachability_writer, summary).await;
    }
    Ok(())
}

async fn wait_for_udp_check_binding_change(is_current: &impl Fn() -> bool) {
    while is_current() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Sample only distinct known reporters. The later unsolicited probe tests
/// reachability, whereas a PONG reports the source port of our outbound PING.
async fn discover_external_udp_port(
    dht: &DhtNode,
    firewall: &Mutex<KadFirewallState>,
    bind_ip: IpAddr,
) -> u16 {
    let binding = dht.udp_probe_binding();
    let public_ip = binding.0;
    let contacts = dht.closest_contacts(&dht.own_id(), K).await;
    let mut reporter_ips = HashSet::new();
    let reporters = contacts
        .into_iter()
        .filter_map(|contact| {
            let ip = IpAddr::V4(contact.ip);
            (contact.kad_version >= 6
                && !contact.udp_firewalled
                && contact.udp_port != 0
                && ip != bind_ip
                && public_ip != Some(contact.ip)
                && reporter_ips.insert(ip))
            .then(|| SocketAddr::new(ip, contact.udp_port))
        })
        .take(EXTERNAL_PORT_REPORTER_LIMIT);
    firewall
        .lock()
        .await
        .begin_external_port_discovery(Utc::now());
    for reporter in reporters {
        let response = dht
            .request_packet_with_class(
                reporter,
                &KadPacket::Ping,
                opcode::PONG,
                EXTERNAL_PORT_REPORT_TIMEOUT,
                RpcWorkClass::Maintenance,
            )
            .await;
        let mut state = firewall.lock().await;
        if !dht.is_running() || dht.udp_probe_binding() != binding {
            state.finish_external_port_discovery(Utc::now());
            return 0;
        }
        if let Ok(KadPacket::Pong(pong)) = response {
            state.record_external_port_candidate(reporter.ip(), pong.udp_port, Utc::now());
        }
        if !state.needs_external_port_discovery() {
            return state.external_udp_port_for_request();
        }
    }
    let mut state = firewall.lock().await;
    state.finish_external_port_discovery(Utc::now());
    state.external_udp_port_for_request()
}

/// Build the eD2k hello identity announced to firewall-check helpers, reusing the
/// shared firewall/IP enrichment so the hello flags match our current verdict.
async fn kad_udp_firewall_check_hello_identity(
    dht: &DhtNode,
    listener_addr: SocketAddr,
    internal_udp_port: u16,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    network: &Ed2kNetworkConfig,
) -> Ed2kHelloIdentity {
    let identity = Ed2kHelloIdentity {
        user_hash: network.user_hash,
        client_id: 0,
        tcp_port: listener_addr.port(),
        udp_port: internal_udp_port,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(network.ed2k.obfuscation_enabled),
        direct_udp_callback: false,
    };
    enrich_hello_identity(
        identity,
        server_state,
        kad_firewall,
        KadHelloIdentityState {
            running: dht.is_running(),
            connected: dht.has_had_contact(),
            public_ip: dht.public_ip_for_udp_keys(),
        },
    )
    .await
}

/// Apply a finalized UDP firewall-check verdict: log it and, on an open result
/// that discovered a distinct external UDP port, pin it as peer-confirmed.
async fn apply_kad_udp_firewall_check_result(
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    reachability_writer: &RuntimeReachabilityWriter,
    summary: Option<UdpFirewallCheckSummary>,
) {
    match summary {
        Some(summary) if summary.open => {
            // kad_event firewall milestone `open` (uniform-diagnostics-v2 §3.3).
            crate::diag_kad_event::firewall(false);
            if let Some(verified_udp_port) = summary.verified_udp_port {
                reachability_writer.set_peer_confirmed_udp_port(verified_udp_port);
                tracing::info!(
                    helpers_succeeded = summary.helpers_succeeded,
                    verified_udp_port,
                    "Kad UDP firewall check: open (UDP port confirmed by a fresh tester)"
                );
            } else {
                reachability_writer.clear_peer_confirmed_udp_port();
                tracing::info!(
                    helpers_succeeded = summary.helpers_succeeded,
                    "Kad UDP firewall check: open (internal UDP port reachable)"
                );
            }
        }
        Some(summary) => {
            // kad_event firewall milestone `firewalled` (uniform-diagnostics-v2 §3.3).
            crate::diag_kad_event::firewall(true);
            reachability_writer.clear_peer_confirmed_udp_port();
            let error = kad_firewall.lock().await.last_error.clone();
            tracing::info!(
                helpers_requested = summary.helpers_requested,
                helpers_failed = summary.helpers_failed,
                error = error.as_deref().unwrap_or(""),
                "Kad UDP firewall check: firewalled"
            );
        }
        None => {
            tracing::debug!("Kad UDP firewall check round produced no verdict");
        }
    }
}

/// Revoke a stale Kad UDP verdict and its peer-observed advertised port while
/// retaining any independently refreshed UPnP mapping as a fallback.
async fn expire_stale_kad_udp_verification(
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    reachability_writer: &RuntimeReachabilityWriter,
    now: chrono::DateTime<Utc>,
) -> bool {
    let expired = kad_firewall
        .lock()
        .await
        .expire_udp_verification_if_stale(now);
    if expired {
        reachability_writer.clear_peer_confirmed_udp_port();
        tracing::info!("Kad UDP firewall verification expired; peer-confirmed port revoked");
    }
    expired
}

#[cfg(test)]
mod tests {
    use super::{apply_kad_udp_firewall_check_result, expire_stale_kad_udp_verification};
    use chrono::Utc;
    use emulebb_ed2k::kad_firewall::{KadFirewallState, UdpFirewallCheckSummary};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn summary(open: bool, external_udp_port: Option<u16>) -> UdpFirewallCheckSummary {
        let now = Utc::now();
        UdpFirewallCheckSummary {
            open,
            helpers_selected: 2,
            helpers_requested: 2,
            helpers_succeeded: if open { 1 } else { 0 },
            helpers_failed: if open { 0 } else { 2 },
            started_at: now,
            completed_at: now,
            external_udp_port,
            verified_udp_port: open.then(|| external_udp_port.unwrap_or(4672)),
        }
    }

    #[tokio::test]
    async fn open_with_discovered_port_pins_peer_confirmed_reachability() {
        let firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let reachability_authority = emulebb_ed2k::ReachabilityRuntimeAuthority::new();
        let reachability = reachability_authority.reader();
        let reachability_lease = reachability_authority.begin_runtime();
        let reachability_writer = reachability_lease.writer();
        // A prior UPnP guess that must be overridden by the peer-confirmed result.
        reachability_writer.set_nat_mapped_ports(None, Some(45000));

        apply_kad_udp_firewall_check_result(
            &firewall,
            &reachability_writer,
            Some(summary(true, Some(53000))),
        )
        .await;

        assert!(reachability.udp_port_is_peer_confirmed());
        assert_eq!(reachability.advertised_udp_port(4672), 53000);
        // The UPnP sync can no longer clobber it.
        reachability_writer.set_nat_mapped_ports(None, Some(46000));
        assert_eq!(reachability.advertised_udp_port(4672), 53000);
    }

    #[tokio::test]
    async fn open_on_internal_port_takes_precedence_over_the_nat_mapping() {
        let firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let reachability_authority = emulebb_ed2k::ReachabilityRuntimeAuthority::new();
        let reachability = reachability_authority.reader();
        let reachability_lease = reachability_authority.begin_runtime();
        let reachability_writer = reachability_lease.writer();
        reachability_writer.set_nat_mapped_ports(None, Some(45000));
        reachability_writer.set_peer_confirmed_udp_port(53000);

        apply_kad_udp_firewall_check_result(
            &firewall,
            &reachability_writer,
            Some(summary(true, None)),
        )
        .await;

        assert!(reachability.udp_port_is_peer_confirmed());
        assert_eq!(reachability.advertised_udp_port(4672), 4672);
    }

    #[tokio::test]
    async fn conclusive_firewalled_verdict_revokes_peer_confirmed_port() {
        let firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let reachability_authority = emulebb_ed2k::ReachabilityRuntimeAuthority::new();
        let reachability = reachability_authority.reader();
        let reachability_lease = reachability_authority.begin_runtime();
        let reachability_writer = reachability_lease.writer();
        reachability_writer.set_nat_mapped_ports(None, Some(45000));
        reachability_writer.set_peer_confirmed_udp_port(53000);

        apply_kad_udp_firewall_check_result(
            &firewall,
            &reachability_writer,
            Some(summary(false, None)),
        )
        .await;

        assert!(!reachability.udp_port_is_peer_confirmed());
        assert_eq!(reachability.advertised_udp_port(4672), 45000);
    }

    #[tokio::test]
    async fn inconclusive_verdict_preserves_port_until_state_expires() {
        let now = Utc::now();
        let helper = "203.0.113.40".parse().unwrap();
        let mut state = KadFirewallState::default();
        assert!(state.begin_udp_check([helper], [4672], now));
        let _ = state.record_firewall_udp_packet(helper, 0, 4672, now);
        state.record_udp_check_inconclusive("first inconclusive check");
        state.record_udp_check_inconclusive("second inconclusive check");
        let firewall = Arc::new(Mutex::new(state));
        let reachability_authority = emulebb_ed2k::ReachabilityRuntimeAuthority::new();
        let reachability = reachability_authority.reader();
        let reachability_lease = reachability_authority.begin_runtime();
        let reachability_writer = reachability_lease.writer();
        reachability_writer.set_nat_mapped_ports(None, Some(45000));
        reachability_writer.set_peer_confirmed_udp_port(53000);

        apply_kad_udp_firewall_check_result(&firewall, &reachability_writer, None).await;
        assert_eq!(reachability.advertised_udp_port(4672), 53000);

        assert!(expire_stale_kad_udp_verification(&firewall, &reachability_writer, now).await);
        assert!(!reachability.udp_port_is_peer_confirmed());
        assert_eq!(reachability.advertised_udp_port(4672), 45000);
    }
}
