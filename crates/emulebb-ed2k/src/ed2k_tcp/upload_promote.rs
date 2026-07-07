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
    ed2k_server::Ed2kServerState,
    ed2k_transfer::{Ed2kTransferRuntime, Ed2kUploadPendingPromotion, is_low_id_client_id},
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
        for grant in grants {
            let Some(peer_endpoint) = dialable_peer_endpoint(&grant) else {
                debug!(
                    "dropping upload promotion for {}:{}: peer is not directly connectable",
                    grant.peer.ip, grant.peer.tcp_port
                );
                self.transfer_runtime
                    .release_upload_session(&grant.handle)
                    .await;
                continue;
            };
            let driver = Arc::clone(self);
            tokio::spawn(async move {
                driver.connect_promoted_upload(peer_endpoint, grant).await;
            });
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

/// The peer's dialable TCP endpoint, or `None` when it cannot be connected
/// directly (LowID client id, unusable address or port).
fn dialable_peer_endpoint(grant: &Ed2kUploadPendingPromotion) -> Option<SocketAddr> {
    if grant.peer.client_id.is_some_and(is_low_id_client_id) {
        return None;
    }
    let IpAddr::V4(ip) = grant.peer.ip else {
        return None;
    };
    if ip.is_unspecified() || grant.peer.tcp_port == 0 {
        return None;
    }
    Some(SocketAddr::new(IpAddr::V4(ip), grant.peer.tcp_port))
}
