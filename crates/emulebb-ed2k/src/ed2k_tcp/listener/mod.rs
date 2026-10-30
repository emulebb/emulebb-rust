use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tracing::{debug, warn};

use emulebb_kad_dht::DhtNode;

use crate::{
    buddy_socket::BuddySocketRegistry,
    ed2k_server::{Ed2kServerSearchHandle, Ed2kServerState},
    ed2k_transfer::Ed2kTransferRuntime,
    kad_firewall::KadFirewallState,
    tcp_error_flood::{TcpErrorFloodOutcome, TcpErrorFloodTracker},
};

use super::{Ed2kHelloIdentity, Ed2kSecureIdent};

mod callback;
pub(in crate::ed2k_tcp) mod session;

pub use callback::{
    Ed2kCallbackDispatchError, Ed2kCallbackSessionHandle, Ed2kCallbackSessionInbox,
    Ed2kCallbackSessionOrigin, Ed2kCallbackSessionRequest, ed2k_callback_session_channel,
};
#[cfg(test)]
pub(in crate::ed2k_tcp) use callback::{
    Ed2kCallbackSessionRuntime, run_callback_session_supervisor,
};
pub(crate) use session::reply_with_firewall_udp;
pub(in crate::ed2k_tcp) use session::{
    Ed2kConnectionContext, Ed2kSessionSource, handle_connection,
};

/// Inputs for the long-lived ED2K TCP listener task.
pub struct Ed2kListenerOptions {
    pub listener: Arc<TcpListener>,
    pub dht: DhtNode,
    pub server_state: Arc<RwLock<Ed2kServerState>>,
    /// Command path into the same long-lived server session represented by
    /// `server_state`; upload callbacks fence commands by endpoint + epoch.
    pub server_search: Ed2kServerSearchHandle,
    pub kad_firewall: Arc<Mutex<KadFirewallState>>,
    pub secure_ident: Arc<Ed2kSecureIdent>,
    pub transfer_runtime: Arc<Ed2kTransferRuntime>,
    pub hello_identity: Ed2kHelloIdentity,
    pub shutdown: Arc<AtomicBool>,
    /// IPv4 range filter; inbound connections from filtered peers are dropped.
    pub ip_filter: crate::ipfilter::IpFilter,
    /// External reachability (advertised external TCP/UDP ports), read per
    /// connection so a mapping learned after startup is reflected in hellos.
    pub reachability: crate::reachability::ExternalReachability,
    /// Persistent Kad buddy-socket registry: a matching inbound buddy connection
    /// is held open so the Kad callback handler can relay OP_CALLBACK down it.
    pub buddy_registry: BuddySocketRegistry,
    /// Cross-transport TCP/UDP external listener-test association.
    pub port_test_registry: crate::PortTestRegistry,
    /// Listener-owned consumer for outbound callback-session requests.
    pub callback_sessions: Ed2kCallbackSessionHandle,
    pub callback_session_inbox: Ed2kCallbackSessionInbox,
    /// Maximum grant-to-connect time for disconnected upload waiters.
    pub callback_timeout: Duration,
    pub detect_tcp_error_flooder: bool,
    pub tcp_error_flooder_interval: Duration,
    pub tcp_error_flooder_threshold: u32,
}

/// Run the minimal eD2k TCP listener needed for inbound hello parity and firewall checks.
pub async fn run_ed2k_listener(options: Ed2kListenerOptions) {
    let Ed2kListenerOptions {
        listener,
        dht,
        server_state,
        server_search,
        kad_firewall,
        secure_ident,
        transfer_runtime,
        hello_identity,
        shutdown,
        ip_filter,
        reachability,
        buddy_registry,
        port_test_registry,
        callback_sessions,
        callback_session_inbox,
        callback_timeout,
        detect_tcp_error_flooder,
        tcp_error_flooder_interval,
        tcp_error_flooder_threshold,
    } = options;
    let tcp_error_flood = Arc::new(TcpErrorFloodTracker::new(
        detect_tcp_error_flooder,
        tcp_error_flooder_interval,
        tcp_error_flooder_threshold,
    ));
    // Resolve the VPN bind interface index once (from the listener's local addr)
    // so each accepted socket can egress-pin to the tunnel (IP_UNICAST_IF) without
    // a per-connection interface lookup.
    let (bind_ip, bind_if_index) = match listener.local_addr() {
        Ok(addr) => match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                match crate::networking::require_bind_if_index(v4, "eD2K listener") {
                    Ok(index) => (v4, index),
                    Err(error) => {
                        warn!("eD2K listener disabled: {error:#}");
                        return;
                    }
                }
            }
            _ => {
                warn!("eD2K listener disabled: non-IPv4 listener addresses are not supported");
                return;
            }
        },
        Err(error) => {
            warn!("eD2K listener disabled: failed to read listener bind address: {error}");
            return;
        }
    };
    tokio::spawn(callback::run_callback_session_supervisor(
        callback_session_inbox,
        callback::Ed2kCallbackSessionRuntime {
            dht: dht.clone(),
            server_state: Arc::clone(&server_state),
            kad_firewall: Arc::clone(&kad_firewall),
            secure_ident: Arc::clone(&secure_ident),
            transfer_runtime: Arc::clone(&transfer_runtime),
            ip_filter: ip_filter.clone(),
            hello_identity,
            reachability: reachability.clone(),
            buddy_registry: buddy_registry.clone(),
            port_test_registry: port_test_registry.clone(),
            callback_sessions: callback_sessions.clone(),
            bind_ip,
            shutdown: Arc::clone(&shutdown),
        },
    ));
    // Outbound promote-connect driver: hands upload slots to waiters whose
    // connection is gone by dialing their advertised endpoint and pushing
    // OP_ACCEPTUPLOADREQ (master AddUpNextClient connect-out,
    // UploadQueue.cpp:327-361).
    tokio::spawn(
        super::upload_promote::UploadPromoteDriver {
            dht: dht.clone(),
            server_state: Arc::clone(&server_state),
            server_search,
            kad_firewall: Arc::clone(&kad_firewall),
            secure_ident: Arc::clone(&secure_ident),
            transfer_runtime: Arc::clone(&transfer_runtime),
            hello_identity,
            reachability: reachability.clone(),
            buddy_registry: buddy_registry.clone(),
            port_test_registry: port_test_registry.clone(),
            callback_sessions: callback_sessions.clone(),
            bind_ip,
            callback_timeout,
            shutdown: Arc::clone(&shutdown),
        }
        .run(),
    );
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                if let std::net::IpAddr::V4(ip) = peer_addr.ip() {
                    if ip_filter.is_filtered(ip) {
                        debug!(
                            "dropping inbound eD2k connection from IP-filtered peer {peer_addr}"
                        );
                        drop(stream);
                        continue;
                    }
                    // Reject inbound connections from a banned IP at accept, like
                    // eMule `CListenSocket::OnAccept` -> `IsBannedClient(sin_addr)`
                    // (ListenSocket.cpp:2362,2511). The user-hash half of the ban
                    // is enforced once the hello arrives.
                    if transfer_runtime.is_client_banned(Some(ip), None) {
                        debug!("dropping inbound eD2k connection from banned peer {peer_addr}");
                        drop(stream);
                        continue;
                    }
                }
                // Inbound-accept admission cap (eMule CListenSocket::OnAccept ->
                // TooManySockets): refuse a new inbound connection once the live
                // inbound count is at/over the concurrent-connection cap. The
                // returned guard decrements the counter on every handler exit
                // path; close (drop) the just-accepted socket when over the cap.
                let Some(inbound_guard) = transfer_runtime.try_admit_inbound_connection() else {
                    debug!(
                        "refusing inbound eD2k connection from {peer_addr}: at concurrent-connection cap"
                    );
                    drop(stream);
                    continue;
                };
                // WHY: accepted eD2K sockets still transmit P2P payloads. If the
                // per-socket egress pin cannot be applied, continuing would turn an
                // inbound connection into an unpinned data-plane leak.
                if let Err(error) = emulebb_kad_dht::socket_opts::pin_egress_to_interface(
                    socket2::SockRef::from(&stream),
                    Some(bind_if_index),
                ) {
                    debug!(
                        "dropping inbound eD2k connection from {peer_addr}: failed to pin egress: {error}"
                    );
                    drop(stream);
                    continue;
                }
                let dht = dht.clone();
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let reachability = reachability.clone();
                let buddy_registry = buddy_registry.clone();
                let port_test_registry = port_test_registry.clone();
                let callback_sessions = callback_sessions.clone();
                let tcp_error_flood = Arc::clone(&tcp_error_flood);
                tokio::spawn(async move {
                    // Hold the admission guard for the whole handler so the
                    // inbound slot is released on every exit path (Drop).
                    let _inbound_guard = inbound_guard;
                    if let Err(error) = session::handle_connection(
                        session::Ed2kSessionSource::Inbound(stream),
                        peer_addr,
                        session::Ed2kConnectionContext {
                            dht: &dht,
                            server_state: &server_state,
                            kad_firewall: &kad_firewall,
                            secure_ident: &secure_ident,
                            transfer_runtime: &transfer_runtime,
                            hello_identity,
                            reachability: &reachability,
                            buddy_registry: &buddy_registry,
                            port_test_registry: &port_test_registry,
                            callback_sessions,
                        },
                    )
                    .await
                    {
                        record_tcp_session_error(
                            &error,
                            peer_addr,
                            &tcp_error_flood,
                            &transfer_runtime,
                            tcp_error_flooder_interval,
                        );
                        debug!("eD2k connection handling failed from {peer_addr}: {error}");
                    }
                });
            }
            Err(error) if is_transient_accept_error(&error) => {
                debug!("ignoring transient eD2k accept failure: {error}");
            }
            Err(error) => {
                warn!("eD2k listener accept failed: {error}");
                break;
            }
        }
    }
}

fn record_tcp_session_error(
    error: &anyhow::Error,
    peer_addr: std::net::SocketAddr,
    tracker: &TcpErrorFloodTracker,
    transfer_runtime: &Ed2kTransferRuntime,
    interval: Duration,
) {
    let std::net::IpAddr::V4(ip) = peer_addr.ip() else {
        return;
    };
    if !error.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::TimedOut
            )
        })
    }) {
        return;
    }
    if let TcpErrorFloodOutcome::Banned { count } =
        tracker.record_error(ip, &transfer_runtime.ban_store())
    {
        crate::ed2k_transfer::diag_bad_peer::tcp_error_flooder_banned(ip, count, interval);
    }
}

fn is_transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::unique_test_dir;
    use std::net::Ipv4Addr;

    #[test]
    fn listener_tcp_error_seam_bans_at_configured_threshold() {
        let root = unique_test_dir("ed2k-listener-tcp-error-flood");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let tracker = TcpErrorFloodTracker::new(true, Duration::from_secs(60), 3);
        let peer = "203.0.113.19:4662".parse().unwrap();
        let error = anyhow::Error::new(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "synthetic reset",
        ));

        for _ in 0..3 {
            record_tcp_session_error(&error, peer, &tracker, &runtime, Duration::from_secs(60));
        }

        assert!(runtime.is_client_banned(Some(Ipv4Addr::new(203, 0, 113, 19)), None));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn listener_does_not_count_non_transport_session_errors() {
        let root = unique_test_dir("ed2k-listener-non-tcp-error");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let tracker = TcpErrorFloodTracker::new(true, Duration::from_secs(60), 1);
        let peer = "203.0.113.20:4662".parse().unwrap();

        record_tcp_session_error(
            &anyhow::anyhow!("malformed protocol frame"),
            peer,
            &tracker,
            &runtime,
            Duration::from_secs(60),
        );

        assert!(!runtime.is_client_banned(Some(Ipv4Addr::new(203, 0, 113, 20)), None));
        std::fs::remove_dir_all(root).ok();
    }
}
