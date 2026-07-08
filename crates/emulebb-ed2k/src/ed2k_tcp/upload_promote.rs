//! Outbound promote-connect driver for upload slots granted to waiters whose
//! connection has gone away.
//!
//! The oracle keeps a US_ONUPLOADQUEUE client across disconnects
//! (BaseClient.cpp:1229) and, when the upload queue grants that client a slot,
//! opens an OUTBOUND client connection and pushes OP_ACCEPTUPLOADREQ on it
//! (`CUploadQueue::AddUpNextClient`, UploadQueue.cpp:327-361;
//! `CUpDownClient::ConnectionEstablished`, BaseClient.cpp:1634-1641). A failed
//! connect drops the grant — the oracle deletes the client on a failed
//! `TryToConnect` — freeing the slot for the next waiter. A LowID peer cannot
//! be dialed directly; without a live callback path its grant is dropped the
//! same way.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info};

use emulebb_kad_dht::DhtNode;

use crate::{
    buddy_socket::BuddySocketRegistry,
    ed2k_client_udp::{OutboundReaskTarget, build_direct_callback_req_datagram},
    ed2k_server::Ed2kServerState,
    ed2k_transfer::{
        Ed2kTransferRuntime, Ed2kUploadPeerIdentity, Ed2kUploadPendingPromotion,
        is_low_id_client_id,
    },
    kad_firewall::KadFirewallState,
};

use super::listener::{Ed2kConnectionContext, Ed2kSessionSource, handle_connection};
use super::{
    ED2K_CONNECTION_IDLE_TIMEOUT, ED2K_UPLOAD_QUEUE_POLL_INTERVAL, EMULE_CRYPT_REQUESTS,
    EMULE_CRYPT_SUPPORTS, Ed2kHelloIdentity, Ed2kSecureIdent, Ed2kTransport,
};

/// Long-lived promote-connect driver, cloned from the eD2k listener runtime so
/// an outbound promoted-upload session serves with exactly the listener's
/// dispatch context.
pub(in crate::ed2k_tcp) struct UploadPromoteDriver {
    pub(in crate::ed2k_tcp) dht: DhtNode,
    pub(in crate::ed2k_tcp) server_state: Arc<RwLock<Ed2kServerState>>,
    pub(in crate::ed2k_tcp) kad_firewall: Arc<Mutex<KadFirewallState>>,
    pub(in crate::ed2k_tcp) secure_ident: Arc<Ed2kSecureIdent>,
    pub(in crate::ed2k_tcp) transfer_runtime: Arc<Ed2kTransferRuntime>,
    pub(in crate::ed2k_tcp) hello_identity: Ed2kHelloIdentity,
    pub(in crate::ed2k_tcp) reachability: crate::reachability::ExternalReachability,
    pub(in crate::ed2k_tcp) buddy_registry: BuddySocketRegistry,
    /// Local bind address for outbound connects (the listener's VPN-pinned IP).
    pub(in crate::ed2k_tcp) bind_ip: Ipv4Addr,
    pub(in crate::ed2k_tcp) shutdown: Arc<AtomicBool>,
}

impl UploadPromoteDriver {
    /// Poll-drain loop, paced like the listener's in-session queue poll
    /// (the master drives `AddUpNextClient` from its upload timer).
    pub(in crate::ed2k_tcp) async fn run(self) {
        let driver = Arc::new(self);
        while !driver.shutdown.load(Ordering::Relaxed) {
            tokio::time::sleep(ED2K_UPLOAD_QUEUE_POLL_INTERVAL).await;
            driver.promote_pending_once().await;
        }
    }

    /// Drain the pending grants once and dispatch one outbound connect task
    /// per dialable grant; an undialable grant (LowID without a callback path,
    /// unusable endpoint) is dropped immediately like the oracle's failed
    /// `TryToConnect` so the slot moves on to the next waiter.
    pub(in crate::ed2k_tcp) async fn promote_pending_once(self: &Arc<Self>) {
        let grants = self.transfer_runtime.take_pending_upload_promotions().await;
        if grants.is_empty() {
            return;
        }
        // Whether we can receive an inbound connect-back (master IsFirewalled(),
        // mirrored from the live server + Kad firewall state exactly like the
        // listener's upload_firewall_context). A firewalled node cannot originate a
        // direct callback because the peer's connect-back could not reach us.
        let we_are_firewalled = self.we_are_firewalled().await;
        for grant in grants {
            match plan_promotion(&grant.peer, we_are_firewalled) {
                PromoteAction::Dial(peer_endpoint) => {
                    let driver = Arc::clone(self);
                    tokio::spawn(async move {
                        driver.connect_promoted_upload(peer_endpoint, grant).await;
                    });
                }
                PromoteAction::DirectCallback(dest) => {
                    // Poke the firewalled LowID waiter so it TCP-connects back onto
                    // the granted slot; keep the queue entry (do NOT release) so the
                    // inbound connect-back is served, mirroring the master keeping the
                    // US_ONUPLOADQUEUE client through CCS_DIRECTCALLBACK
                    // (BaseClient.cpp:1478-1492).
                    self.send_direct_callback_req(dest, &grant.peer).await;
                }
                PromoteAction::Drop => {
                    debug!(
                        "dropping upload promotion for {}:{}: no direct-callback path",
                        grant.peer.ip, grant.peer.tcp_port
                    );
                    self.transfer_runtime
                        .release_upload_session(&grant.handle)
                        .await;
                }
            }
        }
    }

    /// Live `IsFirewalled()` verdict (master `theApp.IsFirewalled()`): a
    /// server-assigned LowID or a Kad TCP-firewalled result. Read fresh per drain
    /// so a mid-session firewall change is honoured.
    async fn we_are_firewalled(&self) -> bool {
        let server_low_id = {
            let state = self.server_state.read().await;
            state.tcp_firewalled().unwrap_or(false)
        };
        let kad_tcp_firewalled = {
            let firewall = self.kad_firewall.lock().await;
            firewall.tcp_firewalled().unwrap_or(false)
        };
        server_low_id || kad_tcp_firewalled
    }

    /// Originate one `OP_DIRECTCALLBACKREQ` over the shared eD2k/Kad UDP socket,
    /// asking a firewalled LowID waiter to TCP-connect back so it can take the
    /// granted slot. Mirrors the master `CCS_DIRECTCALLBACK` send (our TCP port +
    /// userhash + connect options, obfuscated toward the peer when its crypt key is
    /// known), reusing the client-UDP datagram builder that the type-6 download
    /// initiator uses.
    async fn send_direct_callback_req(&self, dest: SocketAddr, peer: &Ed2kUploadPeerIdentity) {
        let our_tcp_port = self
            .reachability
            .advertised_tcp_port(self.hello_identity.tcp_port);
        // Obfuscate only when the peer's session was obfuscated and we hold its
        // user hash for the key (master ShouldReceiveCryptUDPPackets).
        let obfuscate = peer.should_crypt && peer.user_hash.is_some();
        let target = OutboundReaskTarget {
            dest_user_hash: peer.user_hash.unwrap_or([0u8; 16]),
            our_public_ip: self.reachability.octets(),
            obfuscate,
        };
        let datagram = build_direct_callback_req_datagram(
            our_tcp_port,
            &self.hello_identity.user_hash,
            self.hello_identity.connect_options,
            &target,
        );
        match self.dht.send_raw_datagram(dest, &datagram.bytes).await {
            Ok(()) => info!(
                "sent OP_DIRECTCALLBACKREQ to promote LowID waiter {dest} onto its granted slot"
            ),
            Err(error) => debug!("OP_DIRECTCALLBACKREQ to {dest} failed: {error:#}"),
        }
    }

    async fn connect_promoted_upload(
        &self,
        peer_endpoint: SocketAddr,
        grant: Ed2kUploadPendingPromotion,
    ) {
        let handle = grant.handle.clone();
        if let Err(error) = self.serve_promoted_upload(peer_endpoint, grant).await {
            debug!("outbound upload promote-connect to {peer_endpoint} failed: {error:#}");
            // Drop the grant like the oracle's failed TryToConnect path; the
            // release is a no-op when the session loop already released it.
            self.transfer_runtime.release_upload_session(&handle).await;
        }
    }

    async fn serve_promoted_upload(
        &self,
        peer_endpoint: SocketAddr,
        grant: Ed2kUploadPendingPromotion,
    ) -> anyhow::Result<()> {
        // Obfuscate the outbound connect when the waiter's own session was
        // obfuscated (mirrors the oracle reusing the peer's crypt preference).
        let peer_connect_options = grant
            .peer
            .should_crypt
            .then_some(EMULE_CRYPT_SUPPORTS | EMULE_CRYPT_REQUESTS);
        let transport = Ed2kTransport::connect_outgoing(
            self.bind_ip,
            peer_endpoint,
            self.hello_identity.connect_options,
            grant.peer.user_hash,
            peer_connect_options,
            ED2K_CONNECTION_IDLE_TIMEOUT,
        )
        .await?;
        info!(
            "granting upload slot over outbound connect to {peer_endpoint} (file_hash={})",
            grant.file_hash
        );
        handle_connection(
            Ed2kSessionSource::PromotedUpload {
                transport: Box::new(transport),
                grant: Box::new(grant),
            },
            peer_endpoint,
            Ed2kConnectionContext {
                dht: &self.dht,
                server_state: &self.server_state,
                kad_firewall: &self.kad_firewall,
                secure_ident: &self.secure_ident,
                transfer_runtime: &self.transfer_runtime,
                hello_identity: self.hello_identity,
                reachability: &self.reachability,
                buddy_registry: &self.buddy_registry,
            },
        )
        .await
    }
}

/// How the promote driver should hand a granted slot to a waiter whose
/// connection went away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromoteAction {
    /// Dial the peer's advertised TCP endpoint and push OP_ACCEPTUPLOADREQ
    /// (HighID waiter; master `AddUpNextClient` outbound connect,
    /// UploadQueue.cpp:327-361).
    Dial(SocketAddr),
    /// Poke the peer's UDP endpoint with OP_DIRECTCALLBACKREQ so it TCP-connects
    /// back onto the granted slot (firewalled LowID waiter that learned-supports
    /// direct UDP callback; master `TryToConnect` CCS_DIRECTCALLBACK,
    /// BaseClient.cpp:1478-1492).
    DirectCallback(SocketAddr),
    /// No connect path at all: drop the grant like the master's failed
    /// `TryToConnect` (no callback available, BaseClient.cpp:1444-1452).
    Drop,
}

/// Decide how to promote one grant. A HighID waiter is dialed directly; a
/// firewalled LowID waiter is reachable only through a direct UDP callback,
/// and only when we can receive the connect-back (we are not ourselves
/// firewalled — the master rejects LowID<->LowID, BaseClient.cpp:1428-1432) and
/// the peer both advertised direct-callback support and has a usable UDP
/// endpoint (`SupportsDirectUDPCallback() && GetConnectIP() != 0`,
/// BaseClient.cpp:1444/1478). The other LowID callback lanes are out of scope for
/// a pure upload: a server callback needs a shared server and a Kad buddy
/// callback needs `m_reqfile`.
fn plan_promotion(peer: &Ed2kUploadPeerIdentity, we_are_firewalled: bool) -> PromoteAction {
    if !peer.client_id.is_some_and(is_low_id_client_id) {
        return match dialable_tcp_endpoint(peer) {
            Some(endpoint) => PromoteAction::Dial(endpoint),
            None => PromoteAction::Drop,
        };
    }
    if we_are_firewalled || !peer.supports_direct_udp_callback {
        return PromoteAction::Drop;
    }
    match direct_callback_endpoint(peer) {
        Some(endpoint) => PromoteAction::DirectCallback(endpoint),
        None => PromoteAction::Drop,
    }
}

/// The peer's dialable TCP endpoint, or `None` when the address or port is
/// unusable.
fn dialable_tcp_endpoint(peer: &Ed2kUploadPeerIdentity) -> Option<SocketAddr> {
    let IpAddr::V4(ip) = peer.ip else {
        return None;
    };
    if ip.is_unspecified() || peer.tcp_port == 0 {
        return None;
    }
    Some(SocketAddr::new(IpAddr::V4(ip), peer.tcp_port))
}

/// The peer's UDP endpoint for an `OP_DIRECTCALLBACKREQ` (master `GetConnectIP()`
/// + advertised UDP port), or `None` when it is unusable.
fn direct_callback_endpoint(peer: &Ed2kUploadPeerIdentity) -> Option<SocketAddr> {
    let udp_port = peer.udp_port?;
    if udp_port == 0 {
        return None;
    }
    let IpAddr::V4(ip) = peer.ip else {
        return None;
    };
    if ip.is_unspecified() {
        return None;
    }
    Some(SocketAddr::new(IpAddr::V4(ip), udp_port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_transfer::Ed2kUploadFirewallContext;

    /// A LowID waiter fixture; callers flip the direct-callback support and UDP
    /// endpoint to exercise the promote decision.
    fn low_id_waiter(
        supports_direct_udp_callback: bool,
        udp_port: Option<u16>,
    ) -> Ed2kUploadPeerIdentity {
        Ed2kUploadPeerIdentity {
            ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            tcp_port: 4662,
            udp_port,
            udp_version: 4,
            should_crypt: false,
            user_hash: Some([0x5A; 16]),
            // LowID client id (< 0x0100_0000): not directly dialable.
            client_id: Some(0x0000_1234),
            friend_slot: false,
            ident_verified: false,
            ident_bad_guy: false,
            gpl_evildoer: false,
            banned: false,
            emule_version: 0x99,
            is_emule_client: true,
            kad_port: 0,
            supports_direct_udp_callback,
            firewall_context: Ed2kUploadFirewallContext::default(),
            client_software: None,
        }
    }

    #[test]
    fn high_id_waiter_is_dialed_directly() {
        let mut peer = low_id_waiter(false, None);
        peer.client_id = Some(0x521B_5895); // HighID
        assert_eq!(
            plan_promotion(&peer, false),
            PromoteAction::Dial(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                4662
            ))
        );
    }

    #[test]
    fn low_id_waiter_with_direct_callback_support_and_udp_endpoint_is_poked() {
        // Learned direct-UDP-callback support (G5 bit 12) + a usable UDP endpoint
        // + we are connectable -> originate OP_DIRECTCALLBACKREQ (keep the grant).
        let peer = low_id_waiter(true, Some(41000));
        assert_eq!(
            plan_promotion(&peer, false),
            PromoteAction::DirectCallback(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                41000
            ))
        );
    }

    #[test]
    fn low_id_waiter_without_learned_support_is_dropped() {
        // Master no-callback-available drop (BaseClient.cpp:1444-1452).
        let peer = low_id_waiter(false, Some(41000));
        assert_eq!(plan_promotion(&peer, false), PromoteAction::Drop);
    }

    #[test]
    fn low_id_waiter_without_udp_endpoint_is_dropped() {
        // Supports direct callback but advertised no UDP port -> no path.
        let peer = low_id_waiter(true, None);
        assert_eq!(plan_promotion(&peer, false), PromoteAction::Drop);
        let peer_zero = low_id_waiter(true, Some(0));
        assert_eq!(plan_promotion(&peer_zero, false), PromoteAction::Drop);
    }

    #[test]
    fn firewalled_self_never_originates_a_direct_callback() {
        // We could not receive the connect-back (master lowid2lowid rejection),
        // so even a fully capable LowID waiter is dropped.
        let peer = low_id_waiter(true, Some(41000));
        assert_eq!(plan_promotion(&peer, true), PromoteAction::Drop);
    }
}
