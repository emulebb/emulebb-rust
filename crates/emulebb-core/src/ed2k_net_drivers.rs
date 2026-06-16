//! Background eD2k network reachability/sync drivers.
//!
//! The spawned loops that keep the eD2k network reachable: the STUN public-IP
//! fallback probe, the one-shot NAT mapping-behavior health probe, the
//! advertised TCP/UDP external-port sync (with rate-limited reactive re-login),
//! and the UDP-reask re-engage consumer; plus the URL fetch helper used for
//! server.met / nodes.dat import and the eD2k NAT mapping spec builder. Moved
//! verbatim out of `lib.rs` during the maintainability restructuring; they
//! carry no behavior beyond what they had inline. Re-exported `pub(crate)` from
//! the crate root so the network-startup spawn sites, the URL-import handlers,
//! and the test module reach them by their bare names.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use emulebb_ed2k::{
    MappedEndpoint, MappingExposure, MappingSpec, NatManager, TransportProtocol,
    reachability::ExternalReachability,
};
use emulebb_ed2k::stun::{
    DEFAULT_STUN_TIMEOUT, NatMappingBehavior, stun_probe, stun_probe_mapping_behavior,
};
use emulebb_ed2k::{ReaskEvent, ReaskEventReceiver};

use crate::{Ed2kNetworkConfig, EmulebbCore};

/// Fetches a URL body for server.met / nodes.dat import. A browser User-Agent
/// is required: public eMule list mirrors reject or redirect the default agent.
pub(crate) async fn fetch_url_bytes(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        )
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let response = client.get(url).send().await?.error_for_status()?;
    Ok(response.bytes().await?.to_vec())
}

/// Re-probe public IP via STUN while still unknown (gentle cadence).
const ED2K_PUBLIC_IP_PROBE_UNKNOWN_SECS: u64 = 120;
/// Re-check cadence once a public IP is known (in case it clears / the tunnel
/// rotates), so the fallback can refill it.
const ED2K_PUBLIC_IP_PROBE_KNOWN_SECS: u64 = 600;
/// Minimum spacing between reactive server re-logins triggered by an advertised
/// external-port change, so a flapping UPnP mapping cannot spam server reconnects
/// (server-ban-safe, in the spirit of the live-wire ≤1-connect/5min guard).
const ED2K_RELOGIN_MIN_INTERVAL: Duration = Duration::from_secs(300);

/// STUN-probe the data-plane egress and record the reflexive public IP when it is
/// otherwise unknown. The reask obfuscation key is our public IP (eMule
/// `EncryptSendClient`), normally learned from the server `OP_IDCHANGE`; in
/// Kad-only / pre-connect / LowID it is unknown, which blocks obfuscated reasks.
/// `set_if_unset` keeps the server path authoritative (eMule `GetPublicIP` order:
/// cached server/peer value, then the Kad/STUN fallback). Gentle: one STUN race
/// per interval, more often only while still unknown.
pub(crate) async fn run_ed2k_public_ip_probe(
    bind_ip: Ipv4Addr,
    public_ip: ExternalReachability,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        let known = public_ip.is_known();
        if !known
            && let Ok(ip) = stun_probe(bind_ip, DEFAULT_STUN_TIMEOUT).await
            && public_ip.set_if_unset(ip)
        {
            tracing::info!("ED2K public IP learned via STUN fallback: {ip}");
        }
        let secs = if known {
            ED2K_PUBLIC_IP_PROBE_KNOWN_SECS
        } else {
            ED2K_PUBLIC_IP_PROBE_UNKNOWN_SECS
        };
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }
}

/// One-shot NAT mapping-behavior probe (STUN, two servers) logged as a reachability
/// health signal at startup. Endpoint-independent (cone) → our advertised UDP port
/// matches what peers observe, so eD2k reask/HighID reachability is solid; symmetric
/// → each peer sees a different source port, so inbound reask is fragile and peers
/// fall back to TCP. Informational only (no behavior change): STUN reports the probe
/// socket's source-port mapping, not a listen port, so it is never used to advertise
/// a port — the advertised port stays UPnP-mapped / Kad-observed.
pub(crate) async fn run_ed2k_nat_type_probe(bind_ip: Ipv4Addr, shutdown: Arc<AtomicBool>) {
    if shutdown.load(Ordering::Relaxed) {
        return;
    }
    match stun_probe_mapping_behavior(bind_ip, DEFAULT_STUN_TIMEOUT).await {
        NatMappingBehavior::EndpointIndependent => tracing::info!(
            "NAT mapping behavior: endpoint-independent (cone) — eD2k reask/HighID reachability is solid"
        ),
        NatMappingBehavior::Symmetric => tracing::warn!(
            "NAT mapping behavior: symmetric — peers see a varying UDP source port; inbound reask is fragile (TCP fallback) and HighID may be unreliable"
        ),
        NatMappingBehavior::Inconclusive => tracing::debug!(
            "NAT mapping behavior: inconclusive (STUN mapping-behavior probe incomplete)"
        ),
    }
}

/// Keep the advertised external eD2k TCP + UDP ports (`advertised_ports`) in sync
/// with the live NAT mappings. eMule advertises the externally reachable ports,
/// not the internal ones: a UPnP gateway may grant different external ports, and
/// (a) a peer answers a UDP source-reask only when it can locate us by the
/// `(ip, udp_port)` we advertised (matching the reask datagram's source port, which
/// the gateway rewrites to the external port), and (b) peers/servers reach us for
/// incoming TCP connections + HighID callback on the advertised tcp_port. Polling
/// the NAT status reflects a mapping that appears after startup — or is remapped on
/// lease renewal — into subsequent hellos.
pub(crate) async fn run_advertised_ports_sync(
    nat: Arc<NatManager>,
    reachability: ExternalReachability,
    reconnect_signal: Arc<tokio::sync::Notify>,
    internal_tcp_port: u16,
    internal_udp_port: u16,
    shutdown: Arc<AtomicBool>,
) {
    // Baseline = the internal port the first login used before UPnP was ready; a
    // later external port (or a remap) is a change worth re-logging for to refresh
    // HighID, rate-limited so a flapping mapping cannot spam server reconnects.
    let mut last_advertised_tcp = internal_tcp_port;
    let mut last_relogin: Option<std::time::Instant> = None;
    while !shutdown.load(Ordering::Relaxed) {
        let status = nat.status().await;
        let external_for = |proto: TransportProtocol, internal: u16| -> Option<u16> {
            status.mappings.iter().find_map(|mapping: &MappedEndpoint| {
                (mapping.protocol == proto
                    && mapping.local_addr.port() == internal
                    && mapping.external_addr.port() != 0)
                    .then(|| mapping.external_addr.port())
            })
        };
        if let Some(external) = external_for(TransportProtocol::Tcp, internal_tcp_port) {
            reachability.set_external_tcp_port(external);
        }
        if let Some(external) = external_for(TransportProtocol::Udp, internal_udp_port) {
            reachability.set_external_udp_port(external);
        }
        // Reactive re-login: if the advertised TCP port (the HighID callback port)
        // changed and the rate limit allows, signal the server loop to reconnect.
        let advertised_tcp = reachability.advertised_tcp_port(internal_tcp_port);
        if advertised_tcp != last_advertised_tcp {
            let now = std::time::Instant::now();
            let allowed = last_relogin
                .is_none_or(|previous| now.duration_since(previous) >= ED2K_RELOGIN_MIN_INTERVAL);
            if allowed {
                tracing::info!(
                    "ED2K advertised TCP port changed {last_advertised_tcp} -> {advertised_tcp}; requesting server re-login"
                );
                reconnect_signal.notify_one();
                last_relogin = Some(now);
                last_advertised_tcp = advertised_tcp;
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// Re-engage consumer: drains [`ReaskEvent`]s the reask loop raises and reconnects
/// the named transfer over TCP *now*, reusing the normal download attempt (whose
/// `active_download_attempts` guard debounces duplicates). The loop only raises
/// `SourceReady` when a source's queue rank is imminent, so this claims the slot
/// instead of waiting for the periodic download cycle.
pub(crate) async fn run_ed2k_reask_reengage(
    core: EmulebbCore,
    mut events: ReaskEventReceiver,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        let Some(event) = events.recv().await else {
            break;
        };
        match event {
            ReaskEvent::SourceReleased { endpoint } => {
                // The reask loop dropped a detached source: free the lease it kept
                // (active_download_peer_endpoints + the registry) so the next
                // download cycle — or the SourceReady that follows — can re-acquire
                // and reconnect this endpoint over TCP. Without this the endpoint
                // stays leased forever and acquire_direct_download_source_leases
                // defers it, leaking the lease and killing re-engage.
                core.release_direct_download_source_leases(&[endpoint]).await;
            }
            ReaskEvent::SourceReady { file_hash } => {
                let hash = file_hash.to_string();
                let Some(transfer) = core.transfer(&hash).await else {
                    continue;
                };
                if transfer.state == "downloading" {
                    core.queue_ed2k_download_attempt(transfer);
                }
            }
        }
    }
}

pub(crate) fn ed2k_nat_mappings(network: &Ed2kNetworkConfig) -> Vec<MappingSpec> {
    vec![
        MappingSpec {
            name: "ed2k_tcp".to_string(),
            local_addr: SocketAddr::new(IpAddr::V4(network.bind_ip), network.listen_port),
            protocol: TransportProtocol::Tcp,
            exposure: MappingExposure::Required,
            preferred_external_port: Some(network.listen_port),
        },
        MappingSpec {
            name: "kad_udp".to_string(),
            local_addr: network.kad_bind_addr,
            protocol: TransportProtocol::Udp,
            exposure: MappingExposure::Preferred,
            preferred_external_port: Some(network.kad_bind_addr.port()),
        },
    ]
}
