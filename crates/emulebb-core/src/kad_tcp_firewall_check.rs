//! Requester-side Kad TCP firewall recheck driver (oracle `FirewalledCheck` +
//! the `GetRecheckIP` budget in `CKademliaUDPListener`).
//!
//! eMule rechecks whether its eD2k/Kad TCP port is reachable by asking a small
//! set of open Kad v6+ helpers to connect back to it: it sends each a
//! `KADEMLIA2_FIREWALLED2_REQ` over UDP (carrying our TCP port + client hash +
//! connect options). A helper then TCP-connects to our eD2k listener and, on
//! success, sends `OP_KAD_FWTCPCHECK_ACK` (the open signal, oracle
//! `IncFirewalled`) and replies `KADEMLIA_FIREWALLED_RES` over UDP with our
//! externally observed IP. Two independent open acks settle the verdict as
//! "open"; otherwise, once the round ends, the verdict is "firewalled".
//!
//! The shared [`KadFirewallState`] holds the round + verdict; the inbound Kad
//! packet handler routes `FIREWALLED_RES` into `record_firewalled_response` and
//! the eD2k listener routes `OP_KAD_FWTCPCHECK_ACK` into `record_tcp_open_ack`.
//! This loop drives the rounds and finalizes the verdict, which then feeds the
//! buddy-seeking decision so a pure-Kad node (no eD2k server) still learns it is
//! TCP-firewalled and acquires a buddy. Gentle by design: a small helper count
//! and a wide interval, matching the oracle cadence.

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
    sync::{Mutex, RwLock},
};

use emulebb_ed2k::ed2k_server::Ed2kServerState;
use emulebb_ed2k::ed2k_tcp::emule_connect_options;
use emulebb_ed2k::kad_firewall::KadFirewallState;
use emulebb_kad_dht::DhtNode;
use emulebb_kad_proto::{Ed2kHash, Firewalled2Req, KadPacket};

use crate::Ed2kNetworkConfig;

/// Helpers asked per Kad TCP firewall recheck round. Two independent open acks
/// settle the verdict (oracle open threshold `m_uFirewalled >= 2`); a couple of
/// extra helpers cover non-responders without being noisy.
const KAD_TCP_FIREWALL_CHECK_HELPERS: usize = 4;
/// How long one round waits for the helpers' TCP connect-backs + replies before
/// finalizing the verdict.
const KAD_TCP_FIREWALL_CHECK_RESULT_WAIT_SECS: u64 = 30;
/// Seconds before the first round runs, giving the routing table time to learn
/// open v6+ helper contacts after bootstrap.
const KAD_TCP_FIREWALL_CHECK_WARMUP_SECS: u64 = 45;

/// Options for the requester-side Kad TCP firewall recheck driver.
pub(crate) struct KadTcpFirewallCheckOptions {
    pub(crate) dht: DhtNode,
    pub(crate) ed2k_listener: Arc<TcpListener>,
    pub(crate) server_state: Arc<RwLock<Ed2kServerState>>,
    pub(crate) kad_firewall: Arc<Mutex<KadFirewallState>>,
    pub(crate) network: Ed2kNetworkConfig,
    pub(crate) shutdown: Arc<AtomicBool>,
}

/// Drive the eMule requester TCP firewall recheck.
///
/// Periodically (once Kad is bootstrapped) starts a recheck round, asks open
/// v6+ helpers to connect back via `KADEMLIA2_FIREWALLED2_REQ`, waits for the
/// open acks / `FIREWALLED_RES` replies recorded by the inbound handlers, then
/// finalizes the TCP-firewalled verdict in the shared firewall state.
pub(crate) async fn run_kad_tcp_firewall_check_loop(options: KadTcpFirewallCheckOptions) {
    let KadTcpFirewallCheckOptions {
        dht,
        ed2k_listener,
        server_state,
        kad_firewall,
        network,
        shutdown,
    } = options;
    let interval = Duration::from_secs(network.kad_tcp_firewall_check_interval_secs.max(60));
    let mut warmed_up = false;

    while !shutdown.load(Ordering::SeqCst) {
        let wait = if warmed_up {
            interval
        } else {
            Duration::from_secs(KAD_TCP_FIREWALL_CHECK_WARMUP_SECS)
        };
        tokio::time::sleep(wait).await;
        warmed_up = true;
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        if !dht.is_bootstrapped() {
            continue;
        }
        // The eD2k server already gives an authoritative TCP-firewalled verdict
        // when connected (LowID flag); only self-check when we have no server
        // signal, matching eMule preferring the server result.
        if server_state.read().await.tcp_firewalled().is_some() {
            continue;
        }

        if let Err(error) =
            run_kad_tcp_firewall_check_round(&dht, &ed2k_listener, &kad_firewall, &network).await
        {
            tracing::debug!("Kad TCP firewall recheck round failed: {error:#}");
        }
    }
}

/// Run one requester TCP firewall recheck round end to end.
async fn run_kad_tcp_firewall_check_round(
    dht: &DhtNode,
    ed2k_listener: &Arc<TcpListener>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    network: &Ed2kNetworkConfig,
) -> Result<()> {
    let tcp_port = ed2k_listener
        .local_addr()
        .context("failed to read eD2k listener address for Kad TCP firewall recheck")?
        .port();
    if tcp_port == 0 {
        anyhow::bail!("eD2k listener TCP port is unknown; cannot run TCP firewall recheck");
    }

    let helpers = dht
        .firewall_check_helpers(KAD_TCP_FIREWALL_CHECK_HELPERS)
        .await;
    if helpers.is_empty() {
        tracing::debug!("Kad TCP firewall recheck skipped: no eligible helper contacts yet");
        return Ok(());
    }

    let connect_options = emule_connect_options(network.config.obfuscation_enabled);
    {
        let mut firewall = kad_firewall.lock().await;
        firewall.begin_tcp_recheck(Utc::now());
    }

    // Ask each helper over UDP to TCP-connect back to our listener.
    for helper in &helpers {
        let helper_ip = IpAddr::V4(helper.ip);
        let helper_udp = SocketAddr::new(helper_ip, helper.udp_port);
        let reserved = {
            let mut firewall = kad_firewall.lock().await;
            if !firewall.try_begin_tcp_firewall_probe(helper_ip, Utc::now()) {
                false
            } else {
                // Authenticate the helper's later connect-back / FIREWALLED_RES
                // (oracle AddKadFirewallRequest).
                firewall.add_tcp_firewall_check_ip(helper_ip, Utc::now());
                true
            }
        };
        if !reserved {
            continue;
        }

        let key = dht.verify_key_for_ip(helper.ip);
        if key != 0 {
            dht.register_peer_key(helper_udp, key);
        }
        let request = Firewalled2Req {
            tcp_port,
            user_hash: Ed2kHash::from_bytes(network.user_hash),
            connect_options,
        };
        match dht
            .send_packet(helper_udp, &KadPacket::Firewalled2Req(request))
            .await
        {
            Ok(()) => tracing::debug!(
                "sent KADEMLIA2_FIREWALLED2_REQ to firewall-check helper {helper_udp} (kad v{})",
                helper.kad_version
            ),
            Err(error) => {
                tracing::debug!(
                    "Kad TCP firewall recheck request to {helper_udp} failed: {error:#}"
                );
                kad_firewall
                    .lock()
                    .await
                    .record_tcp_firewall_probe_failed(helper_ip, &error.to_string());
            }
        }
    }

    // Wait for the inbound open acks / FIREWALLED_RES replies to settle. The
    // listener + Kad handler update the shared state; poll for an open verdict.
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(KAD_TCP_FIREWALL_CHECK_RESULT_WAIT_SECS);
    while tokio::time::Instant::now() < deadline {
        if kad_firewall.lock().await.tcp_firewalled() == Some(false) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Finalize: if the open threshold was not reached, the round concludes the
    // node is TCP-firewalled (oracle GetFirewalled after the recheck).
    kad_firewall.lock().await.finish_tcp_recheck(Utc::now());

    let verdict = kad_firewall.lock().await.tcp_firewalled();
    match verdict {
        Some(false) => tracing::info!("Kad TCP firewall recheck: open (helper connect-backs ok)"),
        Some(true) => tracing::info!("Kad TCP firewall recheck: firewalled (no open connect-back)"),
        None => tracing::debug!("Kad TCP firewall recheck produced no verdict"),
    }
    Ok(())
}
