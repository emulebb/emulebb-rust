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
//! be dialed directly: it keeps its waiting entry and missed-turn entitlement
//! while a callback is attempted, so another ready waiter can use the base
//! slot in the meantime.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::sync::{Mutex, RwLock};
use tracing::debug;

use emulebb_kad_dht::DhtNode;

use crate::{
    buddy_socket::BuddySocketRegistry,
    ed2k_client_udp::{DirectCallbackArgs, DirectCallbackDispatchOutcome, DirectCallbackSender},
    ed2k_server::{
        Ed2kBackgroundCallbackDispatchOutcome, Ed2kServerSearchHandle, Ed2kServerState,
        request_callback_via_background_session,
    },
    ed2k_transfer::{
        Ed2kTransferRuntime, Ed2kUploadCallbackPermit, Ed2kUploadCallbackRoute,
        Ed2kUploadGrantedPromotion, Ed2kUploadPeerIdentity, Ed2kUploadPendingPromotion,
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
    pub(in crate::ed2k_tcp) server_search: Ed2kServerSearchHandle,
    pub(in crate::ed2k_tcp) kad_firewall: Arc<Mutex<KadFirewallState>>,
    pub(in crate::ed2k_tcp) secure_ident: Arc<Ed2kSecureIdent>,
    pub(in crate::ed2k_tcp) transfer_runtime: Arc<Ed2kTransferRuntime>,
    pub(in crate::ed2k_tcp) hello_identity: Ed2kHelloIdentity,
    pub(in crate::ed2k_tcp) reachability: crate::reachability::ExternalReachability,
    pub(in crate::ed2k_tcp) buddy_registry: BuddySocketRegistry,
    pub(in crate::ed2k_tcp) port_test_registry: crate::PortTestRegistry,
    pub(in crate::ed2k_tcp) callback_sessions: super::Ed2kCallbackSessionHandle,
    /// Local bind address for outbound connects (the listener's VPN-pinned IP).
    pub(in crate::ed2k_tcp) bind_ip: Ipv4Addr,
    /// Maximum time a granted disconnected waiter may take to attach a TCP
    /// connection (direct dial or callback) before its revocable slot expires.
    pub(in crate::ed2k_tcp) callback_timeout: Duration,
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

    /// Drain pending connection work once. HighID grants own a slot and are
    /// dialed directly; LowID callback permits remain waiting entitlements and
    /// therefore never release or cool an active upload session on failure.
    pub(in crate::ed2k_tcp) async fn promote_pending_once(self: &Arc<Self>) {
        // Run the complete queue maintenance pass before handing out slots:
        // purge unshared files, expire dead/revoked leases, and promote waiters.
        // This tick is Rust's analog of the master's upload timer walk.
        self.transfer_runtime.maintain_upload_queue().await;
        let grants = self
            .transfer_runtime
            .take_pending_upload_promotions_with_timeout(self.callback_timeout)
            .await;
        if grants.is_empty() {
            return;
        }
        // Capture one coherent routing view for this queue-maintenance pass.
        // The server-assigned HighID/LowID verdict is authoritative when known;
        // Kad is only a fallback. The connected-server route is fenced by both
        // its exact endpoint and login generation.
        let callback_routes = self.callback_route_snapshot().await;
        for promotion in grants {
            match promotion {
                Ed2kUploadPendingPromotion::DirectDial(grant) => {
                    if let Some(peer_endpoint) = dialable_tcp_endpoint(&grant.peer) {
                        let driver = Arc::clone(self);
                        tokio::spawn(async move {
                            driver.connect_promoted_upload(peer_endpoint, grant).await;
                        });
                    } else {
                        debug!(
                            "dropping direct-dial upload promotion for {}:{}: unusable endpoint",
                            grant.peer.ip, grant.peer.tcp_port
                        );
                        self.transfer_runtime
                            .release_upload_session(&grant.handle)
                            .await;
                    }
                }
                Ed2kUploadPendingPromotion::Callback(permit) => {
                    self.dispatch_upload_callback(permit, callback_routes).await;
                }
            }
        }
    }

    async fn dispatch_upload_callback(
        self: &Arc<Self>,
        permit: Ed2kUploadCallbackPermit,
        routes: UploadCallbackRouteSnapshot,
    ) {
        let action = plan_upload_callback(&permit.peer, routes);
        let armed_route = match action {
            UploadCallbackAction::DirectUdp { endpoint } => {
                Ed2kUploadCallbackRoute::DirectUdp { endpoint }
            }
            UploadCallbackAction::Server {
                endpoint,
                session_generation,
                client_id,
            } => Ed2kUploadCallbackRoute::Server {
                endpoint,
                session_generation,
                client_id,
            },
            UploadCallbackAction::Unavailable => {
                debug!(
                    "retaining LowID upload waiter {}:{} without a usable callback route",
                    permit.peer.ip, permit.peer.tcp_port
                );
                self.transfer_runtime
                    .cancel_upload_callback_known_not_sent(&permit)
                    .await;
                return;
            }
        };
        if !self
            .transfer_runtime
            .begin_upload_callback_dispatch(&permit, armed_route)
            .await
        {
            return;
        }

        match action {
            UploadCallbackAction::DirectUdp { endpoint } => {
                self.dispatch_direct_callback(endpoint, permit).await;
            }
            UploadCallbackAction::Server {
                endpoint,
                session_generation,
                client_id,
            } => {
                // A background server command may wait behind offer-file
                // settlement until the callback deadline. Keep the upload queue
                // maintenance loop non-blocking while the typed command owns the
                // permit and its cancellation token.
                tokio::spawn(dispatch_server_upload_callback(
                    self.server_search.clone(),
                    Arc::clone(&self.transfer_runtime),
                    endpoint,
                    session_generation,
                    client_id,
                    permit,
                ));
            }
            UploadCallbackAction::Unavailable => unreachable!("handled before route arming"),
        }
    }

    async fn callback_route_snapshot(&self) -> UploadCallbackRouteSnapshot {
        let (server_firewalled, shared_server) = {
            let state = self.server_state.read().await;
            (state.tcp_firewalled(), shared_server_callback_route(&state))
        };
        let kad_firewalled = if server_firewalled.is_none() {
            self.kad_firewall.lock().await.tcp_firewalled()
        } else {
            None
        };
        UploadCallbackRouteSnapshot {
            we_are_firewalled: effective_tcp_firewalled(server_firewalled, kad_firewalled),
            shared_server,
        }
    }

    async fn dispatch_direct_callback(
        &self,
        endpoint: SocketAddr,
        permit: Ed2kUploadCallbackPermit,
    ) {
        let our_tcp_port = self
            .reachability
            .advertised_tcp_port(self.hello_identity.tcp_port);
        let cancel = permit.cancellation_token();
        let outcome = DirectCallbackSender::new(self.dht.clone(), self.reachability.clone())
            .dispatch(
                DirectCallbackArgs {
                    dest: endpoint,
                    our_tcp_port,
                    our_user_hash: self.hello_identity.user_hash,
                    connect_options: self.hello_identity.connect_options,
                    dest_user_hash: permit.peer.user_hash,
                    obfuscate: permit.peer.should_crypt && permit.peer.user_hash.is_some(),
                },
                permit.expires_at,
                &cancel,
            )
            .await;
        match outcome {
            Ok(DirectCallbackDispatchOutcome::Sent) => {
                debug!("sent OP_DIRECTCALLBACKREQ to promote LowID waiter {endpoint}")
            }
            Ok(DirectCallbackDispatchOutcome::NotSent { reason }) => {
                debug!("OP_DIRECTCALLBACKREQ to {endpoint} was not sent: {reason}");
                self.transfer_runtime
                    .cancel_upload_callback_known_not_sent(&permit)
                    .await;
            }
            Err(error) => debug!(
                "OP_DIRECTCALLBACKREQ delivery to {endpoint} is unknown; retaining callback entitlement: {error:#}"
            ),
        }
    }

    async fn connect_promoted_upload(
        &self,
        peer_endpoint: SocketAddr,
        grant: Ed2kUploadGrantedPromotion,
    ) {
        let handle = grant.handle.clone();
        let peer = grant.peer.clone();
        if let Err(error) = self.serve_promoted_upload(peer_endpoint, grant).await {
            debug!("outbound upload promote-connect to {peer_endpoint} failed: {error:#}");
            // Seed the IP-scoped churn cooldown for a promoted waiter we could not
            // hand the slot to (RUST-PAR-020 U-GAP3: failed-admission / no-socket,
            // UploadQueue.cpp:330-339,841-856), then drop the grant like the
            // oracle's failed TryToConnect path. The release is a no-op when the
            // session loop already released it.
            self.transfer_runtime
                .note_failed_upload_promotion(&peer)
                .await;
            self.transfer_runtime.release_upload_session(&handle).await;
        }
    }

    async fn serve_promoted_upload(
        &self,
        peer_endpoint: SocketAddr,
        grant: Ed2kUploadGrantedPromotion,
    ) -> anyhow::Result<()> {
        // Obfuscate the outbound connect when the waiter's own session was
        // obfuscated (mirrors the oracle reusing the peer's crypt preference).
        let peer_connect_options = grant
            .peer
            .should_crypt
            .then_some(EMULE_CRYPT_SUPPORTS | EMULE_CRYPT_REQUESTS);
        let transport = tokio::select! {
            _ = grant.handle.cancelled() => {
                anyhow::bail!("upload promotion lease was revoked before connect completed");
            }
            result = Ed2kTransport::connect_outgoing(
                "upload_promote",
                self.bind_ip,
                peer_endpoint,
                self.hello_identity.connect_options,
                grant.peer.user_hash,
                peer_connect_options,
                ED2K_CONNECTION_IDLE_TIMEOUT,
            ) => result?,
        };
        debug!(
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
                port_test_registry: &self.port_test_registry,
                callback_sessions: self.callback_sessions.clone(),
            },
        )
        .await
    }
}

async fn dispatch_server_upload_callback(
    server_search: Ed2kServerSearchHandle,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    endpoint: SocketAddr,
    session_generation: u64,
    client_id: u32,
    permit: Ed2kUploadCallbackPermit,
) {
    let cancel = permit.cancellation_token();
    let outcome = request_callback_via_background_session(
        &server_search,
        endpoint,
        session_generation,
        client_id,
        permit.expires_at,
        &cancel,
    )
    .await;
    match outcome {
        Ok(Ed2kBackgroundCallbackDispatchOutcome::Sent) => {
            debug!("sent OP_CALLBACKREQUEST via shared server {endpoint} for LowID {client_id}")
        }
        Ok(Ed2kBackgroundCallbackDispatchOutcome::NotSent { reason }) => {
            debug!(
                "OP_CALLBACKREQUEST via shared server {endpoint} for LowID {client_id} was not sent: {reason}"
            );
            transfer_runtime
                .cancel_upload_callback_known_not_sent(&permit)
                .await;
        }
        Err(error) => debug!(
            "OP_CALLBACKREQUEST delivery via shared server {endpoint} for LowID {client_id} is unknown; retaining callback entitlement: {error:#}"
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedServerCallbackRoute {
    endpoint: SocketAddr,
    session_generation: u64,
}

/// One coherent view of local callback reachability and the current server
/// session. Capturing it once avoids mixing endpoint, HighID, and generation
/// observations from different login epochs within one maintenance pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UploadCallbackRouteSnapshot {
    we_are_firewalled: bool,
    shared_server: Option<SharedServerCallbackRoute>,
}

fn effective_tcp_firewalled(server: Option<bool>, kad: Option<bool>) -> bool {
    server.or(kad).unwrap_or(false)
}

fn shared_server_callback_route(state: &Ed2kServerState) -> Option<SharedServerCallbackRoute> {
    if !state.connected || state.tcp_firewalled() != Some(false) || state.session_generation == 0 {
        return None;
    }
    state.endpoint.map(|endpoint| SharedServerCallbackRoute {
        endpoint,
        session_generation: state.session_generation,
    })
}

/// How the promote driver should ask a disconnected LowID waiter to reconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadCallbackAction {
    /// Poke the peer's UDP endpoint with OP_DIRECTCALLBACKREQ so it TCP-connects
    /// back onto its retained entitlement (firewalled LowID waiter that learned-supports
    /// direct UDP callback; master `TryToConnect` CCS_DIRECTCALLBACK,
    /// BaseClient.cpp:1478-1492).
    DirectUdp { endpoint: SocketAddr },
    /// Ask the exact shared connected server to callback its server-local LowID.
    Server {
        endpoint: SocketAddr,
        session_generation: u64,
        client_id: u32,
    },
    /// No callback route is currently usable. The queue retains the waiter and
    /// its missed-turn entitlement for a future maintenance pass/reask.
    Unavailable,
}

/// Prefer the master's direct-UDP callback lane, then fall back to the exact
/// shared server session. LowID-to-LowID is impossible because neither route
/// can return a TCP connection when our own current verdict is firewalled.
fn plan_upload_callback(
    peer: &Ed2kUploadPeerIdentity,
    routes: UploadCallbackRouteSnapshot,
) -> UploadCallbackAction {
    let Some(client_id) = peer
        .client_id
        .filter(|id| is_low_id_client_id(*id) && *id != 0)
    else {
        return UploadCallbackAction::Unavailable;
    };
    if routes.we_are_firewalled {
        return UploadCallbackAction::Unavailable;
    }
    if peer.supports_direct_udp_callback
        && let Some(endpoint) = direct_callback_endpoint(peer)
    {
        return UploadCallbackAction::DirectUdp { endpoint };
    }
    let Some(route) = routes.shared_server else {
        return UploadCallbackAction::Unavailable;
    };
    if peer.server_endpoint != Some(route.endpoint) {
        return UploadCallbackAction::Unavailable;
    }
    UploadCallbackAction::Server {
        endpoint: route.endpoint,
        session_generation: route.session_generation,
        client_id,
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
    use crate::{
        ed2k_transfer::{
            Ed2kUploadCallbackClaim, Ed2kUploadFirewallContext, Ed2kUploadQueueConfig,
            Ed2kUploadSessionStatus,
        },
        paths::unique_test_dir,
    };
    use emulebb_kad_proto::Ed2kHash;

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
            server_endpoint: None,
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
            dialable_tcp_endpoint(&peer),
            Some(SocketAddr::new(
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
            plan_upload_callback(
                &peer,
                UploadCallbackRouteSnapshot {
                    we_are_firewalled: false,
                    shared_server: None,
                }
            ),
            UploadCallbackAction::DirectUdp {
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 41000)
            }
        );
    }

    #[test]
    fn low_id_waiter_without_learned_support_has_no_callback_route() {
        // Master no-callback-available drop (BaseClient.cpp:1444-1452).
        let peer = low_id_waiter(false, Some(41000));
        assert_eq!(
            plan_upload_callback(
                &peer,
                UploadCallbackRouteSnapshot {
                    we_are_firewalled: false,
                    shared_server: None,
                }
            ),
            UploadCallbackAction::Unavailable
        );
    }

    #[test]
    fn low_id_waiter_without_udp_endpoint_has_no_callback_route() {
        // Supports direct callback but advertised no UDP port -> no path.
        let peer = low_id_waiter(true, None);
        let routes = UploadCallbackRouteSnapshot {
            we_are_firewalled: false,
            shared_server: None,
        };
        assert_eq!(
            plan_upload_callback(&peer, routes),
            UploadCallbackAction::Unavailable
        );
        let peer_zero = low_id_waiter(true, Some(0));
        assert_eq!(
            plan_upload_callback(&peer_zero, routes),
            UploadCallbackAction::Unavailable
        );
    }

    #[test]
    fn firewalled_self_never_originates_a_callback() {
        // We could not receive the connect-back (master lowid2lowid rejection),
        // so even a fully capable LowID waiter is dropped.
        let peer = low_id_waiter(true, Some(41000));
        assert_eq!(
            plan_upload_callback(
                &peer,
                UploadCallbackRouteSnapshot {
                    we_are_firewalled: true,
                    shared_server: Some(SharedServerCallbackRoute {
                        endpoint: SocketAddr::from((Ipv4Addr::new(203, 0, 113, 8), 4661)),
                        session_generation: 7,
                    }),
                }
            ),
            UploadCallbackAction::Unavailable
        );
    }

    #[test]
    fn direct_udp_is_preferred_over_a_shared_server() {
        let server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 8), 4661));
        let mut peer = low_id_waiter(true, Some(41000));
        peer.server_endpoint = Some(server);
        assert!(matches!(
            plan_upload_callback(
                &peer,
                UploadCallbackRouteSnapshot {
                    we_are_firewalled: false,
                    shared_server: Some(SharedServerCallbackRoute {
                        endpoint: server,
                        session_generation: 7,
                    }),
                }
            ),
            UploadCallbackAction::DirectUdp { .. }
        ));
    }

    #[test]
    fn exact_shared_server_routes_a_low_id_without_direct_udp() {
        let server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 8), 4661));
        let mut peer = low_id_waiter(false, None);
        peer.server_endpoint = Some(server);
        let routes = UploadCallbackRouteSnapshot {
            we_are_firewalled: false,
            shared_server: Some(SharedServerCallbackRoute {
                endpoint: server,
                session_generation: 7,
            }),
        };
        assert_eq!(
            plan_upload_callback(&peer, routes),
            UploadCallbackAction::Server {
                endpoint: server,
                session_generation: 7,
                client_id: 0x1234,
            }
        );

        peer.server_endpoint = Some(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 4661)));
        assert_eq!(
            plan_upload_callback(&peer, routes),
            UploadCallbackAction::Unavailable
        );
    }

    #[test]
    fn server_tcp_verdict_is_authoritative_over_kad() {
        assert!(!effective_tcp_firewalled(Some(false), Some(true)));
        assert!(effective_tcp_firewalled(Some(true), Some(false)));
        assert!(effective_tcp_firewalled(None, Some(true)));
        assert!(!effective_tcp_firewalled(None, Some(false)));
    }

    #[test]
    fn shared_server_route_requires_connected_high_id_epoch() {
        let endpoint = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 8), 4661));
        let mut state = Ed2kServerState {
            endpoint: Some(endpoint),
            client_id: Some(u32::from_le_bytes([198, 51, 100, 2])),
            connected: true,
            session_generation: 7,
            ..Ed2kServerState::default()
        };
        assert_eq!(
            shared_server_callback_route(&state),
            Some(SharedServerCallbackRoute {
                endpoint,
                session_generation: 7,
            })
        );

        state.client_id = Some(0x1234);
        assert_eq!(shared_server_callback_route(&state), None);
        state.client_id = Some(u32::from_le_bytes([198, 51, 100, 2]));
        state.session_generation = 0;
        assert_eq!(shared_server_callback_route(&state), None);
        state.session_generation = 7;
        state.connected = false;
        assert_eq!(shared_server_callback_route(&state), None);
    }

    #[tokio::test]
    async fn confirmed_server_callback_retains_the_waiters_entitlement() {
        let runtime = Arc::new(
            Ed2kTransferRuntime::load_or_create(&unique_test_dir(
                "ed2k-upload-promote-server-callback",
            ))
            .unwrap(),
        );
        runtime
            .configure_upload_queue(Ed2kUploadQueueConfig {
                base_slots: 1,
                elastic_percent: 0,
                upload_limit_bytes_per_sec: 0,
                ..Ed2kUploadQueueConfig::default()
            })
            .await;
        let file_hash = Ed2kHash::from_bytes([0x91; 16]);
        let server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 8), 4661));

        let mut active_peer = low_id_waiter(false, None);
        active_peer.client_id = Some(u32::from_le_bytes([198, 51, 100, 44]));
        active_peer.user_hash = Some([0x44; 16]);
        let (active, active_status) = runtime.begin_upload_session(active_peer, &file_hash).await;
        assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);

        let mut callback_peer = low_id_waiter(false, None);
        callback_peer.server_endpoint = Some(server);
        callback_peer.friend_slot = true;
        let returning_peer = callback_peer.clone();
        let (waiting, waiting_status) = runtime
            .begin_upload_session(callback_peer, &file_hash)
            .await;
        assert_eq!(waiting_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
        runtime.release_upload_session(&waiting).await;
        runtime.release_upload_session(&active).await;

        let mut promotions = runtime.take_pending_upload_promotions().await;
        assert_eq!(promotions.len(), 1);
        let Ed2kUploadPendingPromotion::Callback(permit) = promotions.pop().unwrap() else {
            panic!("detached LowID waiter must produce a callback permit")
        };
        assert!(
            runtime
                .begin_upload_callback_dispatch(
                    &permit,
                    Ed2kUploadCallbackRoute::Server {
                        endpoint: server,
                        session_generation: 7,
                        client_id: 0x1234,
                    },
                )
                .await
        );

        let (server_search, mut server_inbox) =
            crate::ed2k_server::new_ed2k_server_search_channel(1);
        let confirmation =
            tokio::spawn(async move { server_inbox.confirm_callback_for_test().await });
        dispatch_server_upload_callback(
            server_search,
            Arc::clone(&runtime),
            server,
            7,
            0x1234,
            permit,
        )
        .await;
        assert_eq!(confirmation.await.unwrap(), (server, 7, 0x1234));

        assert!(matches!(
            runtime
                .claim_upload_callback_promotion(returning_peer)
                .await,
            Ed2kUploadCallbackClaim::Granted(_)
        ));
    }
}
