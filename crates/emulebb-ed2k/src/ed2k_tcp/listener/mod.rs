use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tracing::{debug, warn};

use emulebb_kad_dht::DhtNode;

use crate::{
    buddy_socket::BuddySocketRegistry, ed2k_server::Ed2kServerState,
    ed2k_transfer::Ed2kTransferRuntime, kad_firewall::KadFirewallState,
};

use super::{Ed2kHelloIdentity, Ed2kSecureIdent};

mod session;

pub(crate) use session::reply_with_firewall_udp;
pub(in crate::ed2k_tcp) use session::{
    Ed2kConnectionContext, Ed2kSessionSource, handle_connection,
};

/// Inputs for the long-lived ED2K TCP listener task.
pub struct Ed2kListenerOptions {
    pub listener: Arc<TcpListener>,
    pub dht: DhtNode,
    pub server_state: Arc<RwLock<Ed2kServerState>>,
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
}

/// Run the minimal eD2k TCP listener needed for inbound hello parity and firewall checks.
pub async fn run_ed2k_listener(options: Ed2kListenerOptions) {
    let Ed2kListenerOptions {
        listener,
        dht,
        server_state,
        kad_firewall,
        secure_ident,
        transfer_runtime,
        hello_identity,
        shutdown,
        ip_filter,
        reachability,
        buddy_registry,
    } = options;
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
    // Outbound promote-connect driver: hands upload slots to waiters whose
    // connection is gone by dialing their advertised endpoint and pushing
    // OP_ACCEPTUPLOADREQ (master AddUpNextClient connect-out,
    // UploadQueue.cpp:327-361).
    tokio::spawn(
        super::upload_promote::UploadPromoteDriver {
            dht: dht.clone(),
            server_state: Arc::clone(&server_state),
            kad_firewall: Arc::clone(&kad_firewall),
            secure_ident: Arc::clone(&secure_ident),
            transfer_runtime: Arc::clone(&transfer_runtime),
            hello_identity,
            reachability: reachability.clone(),
            buddy_registry: buddy_registry.clone(),
            bind_ip,
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
                        },
                    )
                    .await
                    {
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

fn is_transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset | io::ErrorKind::TimedOut
    )
}
