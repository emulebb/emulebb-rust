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
    net::{IpAddr, SocketAddr},
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

use emulebb_ed2k::{
    ed2k_tcp::{
        Ed2kHelloIdentity, FirewallCheckUdpRequest, emule_connect_options, enrich_hello_identity,
        request_udp_firewall_check,
    },
    kad_firewall::{KadFirewallState, UdpFirewallCheckSummary},
    reachability::ExternalReachability,
};
use emulebb_ed2k::ed2k_server::Ed2kServerState;
use emulebb_kad_dht::DhtNode;

use crate::Ed2kNetworkConfig;

/// Helpers asked per Kad UDP firewall-check round (oracle
/// `UDP_FIREWALLTEST_CLIENTSTOASK`): two corroborate without inviting false
/// positives.
const KAD_UDP_FIREWALL_CHECK_HELPERS: usize = 2;
/// Per-helper eD2k TCP timeout for sending `OP_FWCHECKUDPREQ`.
const KAD_UDP_FIREWALL_CHECK_TCP_TIMEOUT_SECS: u64 = 20;
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
    pub(crate) reachability: ExternalReachability,
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
        ed2k_listener,
        server_state,
        kad_firewall,
        reachability,
        network,
        recheck_signal,
        shutdown,
    } = options;
    let interval = Duration::from_secs(network.kad_udp_firewall_check_interval_secs.max(60));
    let mut warmed_up = false;

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
        if !dht.is_bootstrapped() {
            continue;
        }

        if let Err(error) = run_kad_udp_firewall_check_round(
            &dht,
            &ed2k_listener,
            &server_state,
            &kad_firewall,
            &reachability,
            &network,
        )
        .await
        {
            tracing::debug!("Kad UDP firewall check round failed: {error:#}");
        }
    }
}

/// Run one requester UDP firewall-check round end to end.
async fn run_kad_udp_firewall_check_round(
    dht: &DhtNode,
    ed2k_listener: &Arc<TcpListener>,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    reachability: &ExternalReachability,
    network: &Ed2kNetworkConfig,
) -> Result<()> {
    let bind_addr = dht
        .bind_addr()
        .context("failed to resolve Kad bind address for UDP firewall check")?;
    let internal_udp_port = bind_addr.port();
    if internal_udp_port == 0 {
        anyhow::bail!("Kad UDP bind port is unknown; cannot run firewall check");
    }
    // The external port we currently believe peers see (UPnP / prior discovery).
    // 0 / equal-to-internal means "test the internal port only".
    let advertised_udp_port = reachability.advertised_udp_port(internal_udp_port);
    let external_udp_port = if advertised_udp_port != internal_udp_port {
        advertised_udp_port
    } else {
        0
    };

    let helpers = dht
        .firewall_check_helpers(KAD_UDP_FIREWALL_CHECK_HELPERS)
        .await;
    if helpers.is_empty() {
        tracing::debug!("Kad UDP firewall check skipped: no eligible helper contacts yet");
        return Ok(());
    }

    let helper_ips = helpers
        .iter()
        .map(|helper| IpAddr::V4(helper.ip))
        .collect::<Vec<_>>();
    let expected_ports = [internal_udp_port, external_udp_port];
    {
        let mut firewall = kad_firewall.lock().await;
        if !firewall.begin_udp_check(
            helper_ips.iter().copied(),
            expected_ports.iter().copied(),
            Utc::now(),
        ) {
            let error = firewall.last_error.clone().unwrap_or_default();
            anyhow::bail!("could not begin Kad UDP firewall-check round: {error}");
        }
    }

    let listener_addr = ed2k_listener
        .local_addr()
        .context("failed to read eD2k listener address for UDP firewall check")?;
    let hello_identity = kad_udp_firewall_check_hello_identity(
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
    for helper in &helpers {
        let request = FirewallCheckUdpRequest {
            internal_udp_port,
            external_udp_port,
            sender_udp_key: dht.verify_key_for_ip(helper.ip),
        };
        let helper_addr = SocketAddr::new(IpAddr::V4(helper.ip), helper.tcp_port);
        match request_udp_firewall_check(
            Some(dht.clone()),
            network.bind_ip,
            helper_addr,
            hello_identity,
            Arc::clone(&network.secure_ident),
            request,
            tcp_timeout,
        )
        .await
        {
            Ok(()) => tracing::debug!(
                "sent OP_FWCHECKUDPREQ to firewall-check helper {helper_addr} (kad v{})",
                helper.kad_version
            ),
            Err(error) => {
                tracing::debug!("Kad UDP firewall-check request to {helper_addr} failed: {error:#}");
                kad_firewall
                    .lock()
                    .await
                    .record_helper_request_failed(IpAddr::V4(helper.ip), &error.to_string());
            }
        }
    }

    // Wait for the inbound KADEMLIA2_FIREWALLUDP replies to converge. The inbound
    // handler records them against the active round; poll the shared state.
    let deadline = tokio::time::Instant::now()
        + Duration::from_secs(KAD_UDP_FIREWALL_CHECK_RESULT_WAIT_SECS);
    while tokio::time::Instant::now() < deadline {
        if kad_firewall.lock().await.udp_verified {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let summary = kad_firewall.lock().await.finish_udp_check(Utc::now());
    apply_kad_udp_firewall_check_result(kad_firewall, reachability, summary).await;
    Ok(())
}

/// Build the eD2k hello identity announced to firewall-check helpers, reusing the
/// shared firewall/IP enrichment so the hello flags match our current verdict.
async fn kad_udp_firewall_check_hello_identity(
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
        connect_options: emule_connect_options(network.config.obfuscation_enabled),
        direct_udp_callback: false,
    };
    enrich_hello_identity(identity, server_state, kad_firewall).await
}

/// Apply a finalized UDP firewall-check verdict: log it and, on an open result
/// that discovered a distinct external UDP port, pin it as peer-confirmed.
async fn apply_kad_udp_firewall_check_result(
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    reachability: &ExternalReachability,
    summary: Option<UdpFirewallCheckSummary>,
) {
    match summary {
        Some(summary) if summary.open => {
            if let Some(external_udp_port) = summary.external_udp_port {
                reachability.set_peer_confirmed_udp_port(external_udp_port);
                tracing::info!(
                    helpers_succeeded = summary.helpers_succeeded,
                    external_udp_port,
                    "Kad UDP firewall check: open (external UDP port confirmed by peers)"
                );
            } else {
                tracing::info!(
                    helpers_succeeded = summary.helpers_succeeded,
                    "Kad UDP firewall check: open (internal UDP port reachable)"
                );
            }
        }
        Some(summary) => {
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

#[cfg(test)]
mod tests {
    use super::apply_kad_udp_firewall_check_result;
    use chrono::Utc;
    use emulebb_ed2k::kad_firewall::{KadFirewallState, UdpFirewallCheckSummary};
    use emulebb_ed2k::reachability::ExternalReachability;
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
        }
    }

    #[tokio::test]
    async fn open_with_discovered_port_pins_peer_confirmed_reachability() {
        let firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let reachability = ExternalReachability::new();
        // A prior UPnP guess that must be overridden by the peer-confirmed result.
        reachability.set_external_udp_port(45000);

        apply_kad_udp_firewall_check_result(&firewall, &reachability, Some(summary(true, Some(53000))))
            .await;

        assert!(reachability.udp_port_is_peer_confirmed());
        assert_eq!(reachability.advertised_udp_port(4672), 53000);
        // The UPnP sync can no longer clobber it.
        reachability.set_external_udp_port(46000);
        assert_eq!(reachability.advertised_udp_port(4672), 53000);
    }

    #[tokio::test]
    async fn open_on_internal_port_does_not_pin_a_port() {
        let firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let reachability = ExternalReachability::new();

        apply_kad_udp_firewall_check_result(&firewall, &reachability, Some(summary(true, None)))
            .await;

        assert!(!reachability.udp_port_is_peer_confirmed());
        assert_eq!(reachability.advertised_udp_port(4672), 4672);
    }

    #[tokio::test]
    async fn firewalled_or_no_verdict_leaves_reachability_untouched() {
        let firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let reachability = ExternalReachability::new();

        apply_kad_udp_firewall_check_result(&firewall, &reachability, Some(summary(false, None)))
            .await;
        apply_kad_udp_firewall_check_result(&firewall, &reachability, None).await;

        assert!(!reachability.udp_port_is_peer_confirmed());
        assert_eq!(reachability.advertised_udp_port(4672), 4672);
    }
}
