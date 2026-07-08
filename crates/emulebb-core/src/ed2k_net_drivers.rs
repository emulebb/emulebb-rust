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
use emulebb_ed2k::ed2k_server::{
    Ed2kServerListEvent, Ed2kServerListEventReceiver, Ed2kServerState,
};
use emulebb_ed2k::ed2k_tcp::{Ed2kHelloIdentity, connect_callback_peer};
use emulebb_ed2k::kad_firewall::KadFirewallState;
use emulebb_ed2k::stun::{
    DEFAULT_STUN_TIMEOUT, NatMappingBehavior, stun_probe, stun_probe_mapping_behavior,
};
use emulebb_ed2k::{
    MappedEndpoint, MappingExposure, MappingSpec, NatManager, TransportProtocol,
    reachability::ExternalReachability,
};
use emulebb_ed2k::{ReaskEvent, ReaskEventReceiver};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};

use crate::{Ed2kNetworkConfig, EmulebbCore, current_tcp_firewalled};

/// Shared runtime state the reask re-engage consumer needs to act on an inbound
/// `OP_DIRECTCALLBACKREQ` (FIX 1): the firewalled-verdict inputs (oracle
/// `Kademlia::IsRunning() && IsFirewalled()` gate) plus the TCP-connect identity
/// to mirror `TryToConnectOrDelete`. Cloned cheaply (all `Arc`/`Copy`).
#[derive(Clone)]
pub(crate) struct ReaskReengageContext {
    /// Our eD2k bind IP for the outbound callback connection (egress-pinned).
    pub bind_ip: Ipv4Addr,
    /// Our advertised hello identity for the outbound `OP_HELLO`.
    pub hello_identity: Ed2kHelloIdentity,
    /// The eD2k TCP listener, for the last-resort firewalled fallback verdict.
    pub ed2k_listener: Arc<TcpListener>,
    /// The eD2k server state (authoritative LowID flag).
    pub server_state: Arc<RwLock<Ed2kServerState>>,
    /// The Kad TCP firewall verdict (pure-Kad LowID detection).
    pub kad_firewall: Arc<Mutex<KadFirewallState>>,
}

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
/// Finds the gateway-granted external port for one internal listener in a NAT
/// status snapshot. Matches on protocol + the internal port and ignores a zero
/// external port (an unmapped/placeholder entry). Pure so both the connect-time
/// await-once sync and the periodic poll share one matcher (no drift).
fn external_port_for(
    mappings: &[MappedEndpoint],
    proto: TransportProtocol,
    internal: u16,
) -> Option<u16> {
    mappings.iter().find_map(|mapping| {
        (mapping.protocol == proto
            && mapping.local_addr.port() == internal
            && mapping.external_addr.port() != 0)
            .then(|| mapping.external_addr.port())
    })
}

/// Pushes the gateway-granted external eD2k TCP + UDP ports from a NAT status
/// snapshot into reachability. Returned by [`run_advertised_ports_sync`]'s poll
/// and called once at connect time (after the awaited initial reconcile) so the
/// very first server login already announces the forwarded HighID callback port.
pub(crate) fn sync_advertised_ports_from_nat(
    status: &emulebb_ed2k::NatStatus,
    reachability: &ExternalReachability,
    internal_tcp_port: u16,
    internal_udp_port: u16,
) {
    if let Some(external) =
        external_port_for(&status.mappings, TransportProtocol::Tcp, internal_tcp_port)
    {
        reachability.set_external_tcp_port(external);
    }
    if let Some(external) =
        external_port_for(&status.mappings, TransportProtocol::Udp, internal_udp_port)
    {
        reachability.set_external_udp_port(external);
    }
}

pub(crate) async fn run_advertised_ports_sync(
    nat: Arc<NatManager>,
    reachability: ExternalReachability,
    reconnect_signal: Arc<tokio::sync::Notify>,
    internal_tcp_port: u16,
    internal_udp_port: u16,
    shutdown: Arc<AtomicBool>,
) {
    // Baseline = the external port already mapped by the awaited initial reconcile
    // (the port the first login announced); only a *later* remap is a change worth
    // re-logging for, rate-limited so a flapping mapping cannot spam reconnects.
    let mut last_advertised_tcp = reachability.advertised_tcp_port(internal_tcp_port);
    let mut last_relogin: Option<std::time::Instant> = None;
    while !shutdown.load(Ordering::Relaxed) {
        let status = nat.status().await;
        sync_advertised_ports_from_nat(
            &status,
            &reachability,
            internal_tcp_port,
            internal_udp_port,
        );
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
    direct_callback: ReaskReengageContext,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        let Some(event) = events.recv().await else {
            break;
        };
        // Isolate each event: a transient panic while handling one event must not
        // tear down the whole consumer, which would permanently stop source-lease
        // releases (leaking leases and killing re-engage) (FIX B4a). Handling runs
        // in a spawned task we await, so a panic surfaces as a JoinError we log and
        // skip, keeping the loop alive.
        let handler_core = core.clone();
        let handle = tokio::spawn(handle_reask_event(
            handler_core,
            event,
            direct_callback.clone(),
        ));
        if let Err(join_error) = handle.await {
            tracing::warn!("ED2K reask re-engage event handler panicked; continuing: {join_error}");
        }
    }
}

/// Handle a single reask re-engage event. Isolated so a panic here cannot tear
/// down [`run_ed2k_reask_reengage`].
async fn handle_reask_event(
    core: EmulebbCore,
    event: ReaskEvent,
    direct_callback: ReaskReengageContext,
) {
    match event {
        ReaskEvent::DirectCallbackReq {
            requester_ip,
            tcp_port,
            user_hash,
            connect_options,
        } => {
            handle_direct_callback_req(
                &direct_callback,
                requester_ip,
                tcp_port,
                user_hash,
                connect_options,
            )
            .await;
        }
        ReaskEvent::SourceDead {
            file_hash,
            endpoint,
        } => {
            // A detached source UDP-answered OP_FILENOTFOUND (oracle
            // UDPReaskFNF): dead-list the (source, file) pair for the 45-minute
            // block BEFORE the SourceReleased that follows frees its lease, so
            // the released endpoint is not immediately re-acquirable. The loop
            // only knows the peer's UDP endpoint; core resolves the full source
            // identity from the registry by (ip, file).
            core.dead_list_udp_fnf_source(&file_hash.to_string(), endpoint.0)
                .await;
        }
        ReaskEvent::SourceReleased { endpoint } => {
            // The reask loop dropped a detached source: free the lease it kept
            // (active_download_peer_endpoints + the registry) so the next
            // download cycle — or the SourceReady that follows — can re-acquire
            // and reconnect this endpoint over TCP. Without this the endpoint
            // stays leased forever and acquire_direct_download_source_leases
            // defers it, leaking the lease and killing re-engage.
            core.release_direct_download_source_leases(&[endpoint])
                .await;
        }
        ReaskEvent::SourceReady { file_hash } => {
            let hash = file_hash.to_string();
            let Some(transfer) = core.transfer(&hash).await else {
                return;
            };
            if transfer.state == "downloading" {
                core.queue_ed2k_download_attempt(transfer);
            }
        }
    }
}

/// Whether an inbound `OP_DIRECTCALLBACKREQ`'s connect-back endpoint is a usable
/// dialable IPv4:TCP target. Mirrors the oracle reject of an obviously invalid
/// requester (zero port / unspecified IP). Pure so the gate is unit-testable.
fn direct_callback_target_is_valid(requester_ip: Ipv4Addr, tcp_port: u16) -> bool {
    tcp_port != 0 && !requester_ip.is_unspecified() && !requester_ip.is_broadcast()
}

/// Handle an inbound `OP_DIRECTCALLBACKREQ` (FIX 1): a peer that cannot reach us
/// over TCP asks us — the firewalled LowID side that advertised direct UDP
/// callback (MISCOPTIONS2 bit 12) — to connect out to it. Mirrors the oracle
/// `ClientUDPSocket.cpp` `OP_DIRECTCALLBACKREQ` handler: gate on
/// `Kademlia::IsRunning() && Kademlia::IsFirewalled()`, then connect out to the
/// requester (`TryToConnectOrDelete`). The reask loop only runs with Kad up, so
/// the running half holds; we re-check the firewalled half live here (it can
/// change as our reachability is learned), only acting when we are still the
/// firewalled side we advertised.
async fn handle_direct_callback_req(
    ctx: &ReaskReengageContext,
    requester_ip: Ipv4Addr,
    tcp_port: u16,
    user_hash: [u8; 16],
    connect_options: u8,
) {
    if !direct_callback_target_is_valid(requester_ip, tcp_port) {
        tracing::debug!(
            "ignoring OP_DIRECTCALLBACKREQ: invalid connect-back endpoint {requester_ip}:{tcp_port}"
        );
        return;
    }
    // Only act when we are still the firewalled (LowID) side we advertised: a
    // non-firewalled node never advertised direct UDP callback, so a request to
    // it is stale/spurious (oracle gates on IsFirewalled()).
    let firewalled =
        current_tcp_firewalled(&ctx.ed2k_listener, &ctx.server_state, &ctx.kad_firewall).await;
    if !firewalled {
        tracing::debug!(
            "ignoring OP_DIRECTCALLBACKREQ from {requester_ip}:{tcp_port}: not firewalled (we do \
             not accept direct callbacks)"
        );
        return;
    }
    let peer_addr = SocketAddr::new(IpAddr::V4(requester_ip), tcp_port);
    let bind_ip = ctx.bind_ip;
    let hello_identity = ctx.hello_identity;
    // Connect out like the oracle TryToConnectOrDelete: open an outgoing eD2k
    // client connection and send OP_HELLO, carrying the requester's user hash +
    // connect options for the obfuscated handshake. Spawned so a slow connect
    // never stalls the event consumer.
    tokio::spawn(async move {
        match connect_callback_peer(
            bind_ip,
            peer_addr,
            hello_identity,
            Some(user_hash),
            Some(connect_options),
            Duration::from_secs(20),
        )
        .await
        {
            Ok(mode) => tracing::info!(
                "direct-UDP-callback connect-out to {peer_addr} completed transport={}",
                mode.as_str()
            ),
            Err(error) => {
                tracing::debug!("direct-UDP-callback connect-out to {peer_addr} failed: {error:#}")
            }
        }
    });
}

/// Consumer for server-list feedback raised by the ED2K server session loop
/// (eMule `CServerSocket`/`CServerList`): merges discovered servers into the
/// store (OP_SERVERLIST auto-add) and maintains the per-server fail-count with a
/// dead-server drop at `dead_server_retries`. Isolated per-event so a panic
/// handling one event cannot tear down the whole consumer.
pub(crate) async fn run_ed2k_server_list_events(
    core: EmulebbCore,
    mut events: Ed2kServerListEventReceiver,
    dead_server_retries: u32,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        let Some(event) = events.recv().await else {
            break;
        };
        match event {
            Ed2kServerListEvent::DiscoveredServers(servers) => {
                core.merge_discovered_ed2k_servers(servers).await;
            }
            Ed2kServerListEvent::ConnectFailed { endpoint } => {
                core.note_ed2k_server_connect_failed(&endpoint, dead_server_retries)
                    .await;
            }
            Ed2kServerListEvent::ConnectSucceeded { endpoint } => {
                core.note_ed2k_server_connect_succeeded(&endpoint).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn mapped(
        name: &str,
        proto: TransportProtocol,
        internal: u16,
        external: u16,
    ) -> MappedEndpoint {
        MappedEndpoint {
            name: name.to_string(),
            protocol: proto,
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), internal),
            external_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), external),
            lease_expires_in_secs: 0,
            backend: "test".to_string(),
        }
    }

    #[test]
    fn sync_advertised_ports_copies_gateway_granted_external_ports() {
        // The connect-time await-once sync must announce the gateway-granted external
        // ports (the HighID callback port), not the internal listener ports.
        let status = emulebb_ed2k::NatStatus {
            mappings: vec![
                mapped("ed2k_tcp", TransportProtocol::Tcp, 4662, 49662),
                mapped("kad_udp", TransportProtocol::Udp, 4672, 49672),
            ],
            ..Default::default()
        };
        let reachability = ExternalReachability::new();
        sync_advertised_ports_from_nat(&status, &reachability, 4662, 4672);
        assert_eq!(reachability.advertised_tcp_port(4662), 49662);
        assert_eq!(reachability.advertised_udp_port(4672), 49672);
    }

    #[test]
    fn sync_advertised_ports_ignores_nonmatching_internal_and_zero_external() {
        // A mapping for a different internal port, or a zero/placeholder external
        // port, must not overwrite the advertised port (it falls back to internal).
        let status = emulebb_ed2k::NatStatus {
            mappings: vec![
                mapped("ed2k_tcp", TransportProtocol::Tcp, 9999, 49662),
                mapped("kad_udp", TransportProtocol::Udp, 4672, 0),
            ],
            ..Default::default()
        };
        let reachability = ExternalReachability::new();
        sync_advertised_ports_from_nat(&status, &reachability, 4662, 4672);
        assert_eq!(reachability.advertised_tcp_port(4662), 4662);
        assert_eq!(reachability.advertised_udp_port(4672), 4672);
    }

    #[test]
    fn direct_callback_target_rejects_invalid_endpoints() {
        // Zero TCP port (oracle requires a dialable port) and the unspecified /
        // broadcast IPs are rejected; an ordinary HighID requester is accepted.
        assert!(!direct_callback_target_is_valid(
            Ipv4Addr::new(198, 51, 100, 7),
            0
        ));
        assert!(!direct_callback_target_is_valid(
            Ipv4Addr::UNSPECIFIED,
            4662
        ));
        assert!(!direct_callback_target_is_valid(Ipv4Addr::BROADCAST, 4662));
        assert!(direct_callback_target_is_valid(
            Ipv4Addr::new(198, 51, 100, 7),
            4662
        ));
    }
}
