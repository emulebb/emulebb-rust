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
    ed2k_server::Ed2kServerState, ed2k_transfer::Ed2kTransferRuntime,
    kad_firewall::KadFirewallState,
};

use super::{Ed2kHelloIdentity, Ed2kSecureIdent};

mod session;

pub(crate) use session::reply_with_firewall_udp;
#[cfg(test)]
pub(in crate::ed2k_tcp) use session::{Ed2kConnectionContext, handle_connection};

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
    } = options;
    // Resolve the VPN bind interface index once (from the listener's local addr)
    // so each accepted socket can egress-pin to the tunnel (IP_UNICAST_IF) without
    // a per-connection interface lookup.
    let bind_if_index = listener.local_addr().ok().and_then(|addr| {
        if let std::net::IpAddr::V4(v4) = addr.ip() {
            crate::networking::resolve_bind_if_index(v4)
        } else {
            None
        }
    });
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                if let std::net::IpAddr::V4(ip) = peer_addr.ip() {
                    if ip_filter.is_filtered(ip) {
                        debug!("dropping inbound eD2k connection from IP-filtered peer {peer_addr}");
                        drop(stream);
                        continue;
                    }
                }
                // Pin the accepted socket's egress to the VPN tunnel (IP_UNICAST_IF),
                // best-effort: the socket already sources from the VPN bind IP, so a
                // pin failure does not justify dropping an inbound connection.
                if let Err(error) = emulebb_kad_dht::socket_opts::pin_egress_to_interface(
                    socket2::SockRef::from(&stream),
                    bind_if_index,
                ) {
                    debug!("failed to pin inbound eD2k egress for {peer_addr}: {error}");
                }
                let dht = dht.clone();
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let reachability = reachability.clone();
                tokio::spawn(async move {
                    if let Err(error) = session::handle_connection(
                        stream,
                        peer_addr,
                        session::Ed2kConnectionContext {
                            dht: &dht,
                            server_state: &server_state,
                            kad_firewall: &kad_firewall,
                            secure_ident: &secure_ident,
                            transfer_runtime: &transfer_runtime,
                            hello_identity,
                            reachability: &reachability,
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
