use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::{Mutex, RwLock, mpsc},
    task::JoinSet,
};
use tracing::debug;

use emulebb_kad_dht::DhtNode;

use crate::{
    PortTestRegistry, buddy_socket::BuddySocketRegistry, ed2k_server::Ed2kServerState,
    ed2k_transfer::Ed2kTransferRuntime, ipfilter::IpFilter, kad_firewall::KadFirewallState,
    reachability::ExternalReachability,
};

use super::super::{Ed2kHelloIdentity, Ed2kSecureIdent, Ed2kTransport};
use super::session::{Ed2kConnectionContext, Ed2kSessionSource, handle_connection};

/// Pending callback requests and active callback sessions are both bounded.
/// A callback session can live as long as an ordinary peer connection, so an
/// unbounded spawn-per-packet design would let control-plane traffic exhaust the
/// process even though each individual dial has a timeout.
const CALLBACK_SESSION_CAPACITY: usize = 64;

/// Which ED2K control-plane route requested a callback connect-out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed2kCallbackSessionOrigin {
    Server,
    Kad,
    DirectUdp,
}

impl Ed2kCallbackSessionOrigin {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Kad => "kad",
            Self::DirectUdp => "direct_udp",
        }
    }
}

/// One callback connect-out request. The peer hash and connect-options byte are
/// transport metadata supplied by the route that learned the endpoint; the
/// session still binds its live peer identity from HELLOANSWER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed2kCallbackSessionRequest {
    pub peer_addr: SocketAddr,
    pub expected_user_hash: Option<[u8; 16]>,
    pub peer_connect_options: Option<u8>,
    pub timeout: Duration,
    pub origin: Ed2kCallbackSessionOrigin,
}

/// Fail-fast callback-dispatch error. Callers must never wait on a full queue
/// while holding a server, buddy, or UDP control-plane handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed2kCallbackDispatchError {
    Full,
    Unavailable,
}

impl fmt::Display for Ed2kCallbackDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => formatter.write_str("callback session queue is full"),
            Self::Unavailable => formatter.write_str("callback session supervisor is unavailable"),
        }
    }
}

impl std::error::Error for Ed2kCallbackDispatchError {}

/// Cloneable producer for the listener-owned callback-session supervisor.
#[derive(Debug, Clone)]
pub struct Ed2kCallbackSessionHandle {
    sender: mpsc::Sender<Ed2kCallbackSessionRequest>,
}

impl Ed2kCallbackSessionHandle {
    pub fn try_start(
        &self,
        request: Ed2kCallbackSessionRequest,
    ) -> Result<(), Ed2kCallbackDispatchError> {
        self.sender.try_send(request).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => Ed2kCallbackDispatchError::Full,
            mpsc::error::TrySendError::Closed(_) => Ed2kCallbackDispatchError::Unavailable,
        })
    }
}

/// Single consumer half transferred to the ED2K listener runtime.
#[derive(Debug)]
pub struct Ed2kCallbackSessionInbox {
    receiver: mpsc::Receiver<Ed2kCallbackSessionRequest>,
}

/// Create the process callback-session command channel.
#[must_use]
pub fn ed2k_callback_session_channel() -> (Ed2kCallbackSessionHandle, Ed2kCallbackSessionInbox) {
    callback_session_channel_with_capacity(CALLBACK_SESSION_CAPACITY)
}

fn callback_session_channel_with_capacity(
    capacity: usize,
) -> (Ed2kCallbackSessionHandle, Ed2kCallbackSessionInbox) {
    let (sender, receiver) = mpsc::channel(capacity);
    (
        Ed2kCallbackSessionHandle { sender },
        Ed2kCallbackSessionInbox { receiver },
    )
}

/// Long-lived dependencies cloned into each adopted callback session.
#[derive(Clone)]
pub(in crate::ed2k_tcp) struct Ed2kCallbackSessionRuntime {
    pub dht: DhtNode,
    pub server_state: Arc<RwLock<Ed2kServerState>>,
    pub kad_firewall: Arc<Mutex<KadFirewallState>>,
    pub secure_ident: Arc<Ed2kSecureIdent>,
    pub transfer_runtime: Arc<Ed2kTransferRuntime>,
    /// Live shared IP filter, checked immediately before every callback dial.
    pub ip_filter: IpFilter,
    pub hello_identity: Ed2kHelloIdentity,
    pub reachability: ExternalReachability,
    pub buddy_registry: BuddySocketRegistry,
    pub port_test_registry: PortTestRegistry,
    pub callback_sessions: Ed2kCallbackSessionHandle,
    pub bind_ip: Ipv4Addr,
    pub shutdown: Arc<AtomicBool>,
}

/// Drain callback commands while keeping both queued and active work bounded.
pub(in crate::ed2k_tcp) async fn run_callback_session_supervisor(
    mut inbox: Ed2kCallbackSessionInbox,
    runtime: Ed2kCallbackSessionRuntime,
) {
    let mut sessions = JoinSet::new();
    let mut inbox_open = true;

    while !runtime.shutdown.load(Ordering::Relaxed) {
        tokio::select! {
            command = inbox.receiver.recv(),
                if inbox_open && sessions.len() < CALLBACK_SESSION_CAPACITY =>
            {
                match command {
                    Some(request) => {
                        let session_runtime = runtime.clone();
                        sessions.spawn(async move {
                            serve_callback_session(session_runtime, request).await
                        });
                    }
                    None => inbox_open = false,
                }
            }
            completed = sessions.join_next(), if !sessions.is_empty() => {
                match completed {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => {
                        debug!("ED2K callback session ended with error: {error:#}");
                    }
                    Some(Err(error)) => {
                        debug!("ED2K callback session task failed: {error}");
                    }
                    None => {}
                }
            }
            () = tokio::time::sleep(Duration::from_millis(250)) => {}
        }

        if !inbox_open && sessions.is_empty() {
            return;
        }
    }

    sessions.abort_all();
}

async fn serve_callback_session(
    runtime: Ed2kCallbackSessionRuntime,
    request: Ed2kCallbackSessionRequest,
) -> anyhow::Result<()> {
    if let Err(rejection) =
        callback_request_admission(&runtime.ip_filter, &runtime.transfer_runtime, &request)
    {
        debug!(
            "dropping ED2K {} callback before connect peer={} reason={}",
            request.origin.as_str(),
            request.peer_addr,
            rejection.as_str()
        );
        return Ok(());
    }
    let transport = Ed2kTransport::connect_outgoing(
        "listener_callback",
        runtime.bind_ip,
        request.peer_addr,
        runtime.hello_identity.connect_options,
        request.expected_user_hash,
        request.peer_connect_options,
        request.timeout,
    )
    .await?;
    debug!(
        "ED2K {} callback connected peer={} transport={}",
        request.origin.as_str(),
        request.peer_addr,
        transport.mode.as_str()
    );

    handle_connection(
        Ed2kSessionSource::CallbackUpload {
            transport: Box::new(transport),
            expected_user_hash: request.expected_user_hash,
        },
        request.peer_addr,
        Ed2kConnectionContext {
            dht: &runtime.dht,
            server_state: &runtime.server_state,
            kad_firewall: &runtime.kad_firewall,
            secure_ident: &runtime.secure_ident,
            transfer_runtime: &runtime.transfer_runtime,
            hello_identity: runtime.hello_identity,
            reachability: &runtime.reachability,
            buddy_registry: &runtime.buddy_registry,
            port_test_registry: &runtime.port_test_registry,
            callback_sessions: runtime.callback_sessions,
        },
    )
    .await
}

/// Shared callback connect-out admission. All server, Kad, and direct-UDP
/// callback routes converge here immediately before opening a TCP socket, so a
/// dynamically reloaded IP filter or newly recorded client ban cannot be
/// bypassed by a request which was already queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallbackAdmissionRejection {
    NonIpv4,
    IpFiltered,
    ClientBanned,
}

impl CallbackAdmissionRejection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NonIpv4 => "non-IPv4 endpoint",
            Self::IpFiltered => "IP-filtered endpoint",
            Self::ClientBanned => "banned client identity",
        }
    }
}

fn callback_request_admission(
    ip_filter: &IpFilter,
    transfer_runtime: &Ed2kTransferRuntime,
    request: &Ed2kCallbackSessionRequest,
) -> Result<(), CallbackAdmissionRejection> {
    let SocketAddr::V4(peer_addr) = request.peer_addr else {
        return Err(CallbackAdmissionRejection::NonIpv4);
    };
    let peer_ip = *peer_addr.ip();
    if ip_filter.is_filtered(peer_ip) {
        return Err(CallbackAdmissionRejection::IpFiltered);
    }
    if transfer_runtime.is_client_banned(Some(peer_ip), request.expected_user_hash.as_ref()) {
        return Err(CallbackAdmissionRejection::ClientBanned);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulebb_kad_dht::DhtConfig;
    use tokio::net::TcpListener;

    fn transfer_runtime() -> (tempfile::TempDir, Ed2kTransferRuntime) {
        let root = tempfile::tempdir().unwrap();
        let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
        (root, runtime)
    }

    async fn session_runtime(
        ip_filter: IpFilter,
    ) -> (tempfile::TempDir, Ed2kCallbackSessionRuntime) {
        let root = tempfile::tempdir().unwrap();
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(root.path()).unwrap());
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let (callback_sessions, _callback_inbox) = ed2k_callback_session_channel();
        let runtime = Ed2kCallbackSessionRuntime {
            dht,
            server_state: Arc::new(RwLock::new(Ed2kServerState::default())),
            kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
            secure_ident: Arc::new(Ed2kSecureIdent::generate().unwrap()),
            transfer_runtime,
            ip_filter,
            hello_identity: Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 4662,
                udp_port: 4672,
                server_ip: 0,
                server_port: 0,
                connect_options: 0,
                direct_udp_callback: false,
            },
            reachability: crate::reachability::ReachabilityRuntimeAuthority::new().reader(),
            buddy_registry: BuddySocketRegistry::new(),
            port_test_registry: PortTestRegistry::new(),
            callback_sessions,
            bind_ip: Ipv4Addr::LOCALHOST,
            shutdown: Arc::new(AtomicBool::new(false)),
        };
        (root, runtime)
    }

    fn request() -> Ed2kCallbackSessionRequest {
        Ed2kCallbackSessionRequest {
            peer_addr: "127.0.0.1:4662".parse().unwrap(),
            expected_user_hash: None,
            peer_connect_options: None,
            timeout: Duration::from_secs(1),
            origin: Ed2kCallbackSessionOrigin::Server,
        }
    }

    #[test]
    fn callback_session_handle_rejects_a_full_queue() {
        let (handle, _inbox) = callback_session_channel_with_capacity(1);
        handle.try_start(request()).unwrap();
        assert_eq!(
            handle.try_start(request()),
            Err(Ed2kCallbackDispatchError::Full)
        );
    }

    #[test]
    fn callback_session_handle_rejects_a_closed_queue() {
        let (handle, inbox) = callback_session_channel_with_capacity(1);
        drop(inbox);
        assert_eq!(
            handle.try_start(request()),
            Err(Ed2kCallbackDispatchError::Unavailable)
        );
    }

    #[test]
    fn callback_admission_rejects_filtered_endpoint_before_dial() {
        let (_root, runtime) = transfer_runtime();
        let filter = IpFilter::parse("127.0.0.1 - 127.0.0.1 , 100 , blocked", 127);

        assert_eq!(
            callback_request_admission(&filter, &runtime, &request()),
            Err(CallbackAdmissionRejection::IpFiltered)
        );
    }

    #[test]
    fn callback_admission_rejects_ip_or_hash_ban_before_dial() {
        let (_root, runtime) = transfer_runtime();
        let banned_ip = Ipv4Addr::new(198, 51, 100, 7);
        let banned_hash = [0xA5; 16];
        runtime.ban_client(Some(banned_ip), Some(banned_hash));

        let mut by_ip = request();
        by_ip.peer_addr = SocketAddr::from((banned_ip, 4662));
        assert_eq!(
            callback_request_admission(&IpFilter::default(), &runtime, &by_ip),
            Err(CallbackAdmissionRejection::ClientBanned)
        );

        let mut by_hash = request();
        by_hash.peer_addr = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 8), 4662));
        by_hash.expected_user_hash = Some(banned_hash);
        assert_eq!(
            callback_request_admission(&IpFilter::default(), &runtime, &by_hash),
            Err(CallbackAdmissionRejection::ClientBanned)
        );
    }

    #[test]
    fn callback_admission_accepts_unfiltered_unbanned_ipv4() {
        let (_root, runtime) = transfer_runtime();
        assert_eq!(
            callback_request_admission(&IpFilter::default(), &runtime, &request()),
            Ok(())
        );
    }

    #[tokio::test]
    async fn callback_supervisor_never_dials_a_filtered_peer_for_any_route() {
        let peer = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let filter = IpFilter::parse("127.0.0.1 - 127.0.0.1 , 100 , blocked", 127);
        let (_root, runtime) = session_runtime(filter).await;

        for origin in [
            Ed2kCallbackSessionOrigin::Server,
            Ed2kCallbackSessionOrigin::Kad,
            Ed2kCallbackSessionOrigin::DirectUdp,
        ] {
            let mut request = request();
            request.peer_addr = peer_addr;
            request.origin = origin;
            serve_callback_session(runtime.clone(), request)
                .await
                .unwrap();
        }

        assert!(
            tokio::time::timeout(Duration::from_millis(100), peer.accept())
                .await
                .is_err(),
            "no callback route may open a socket to an IP-filtered peer"
        );
    }

    #[tokio::test]
    async fn callback_supervisor_never_dials_a_hash_banned_peer() {
        let peer = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let banned_hash = [0xA5; 16];
        let (_root, runtime) = session_runtime(IpFilter::default()).await;
        runtime.transfer_runtime.ban_client(None, Some(banned_hash));
        let mut request = request();
        request.peer_addr = peer_addr;
        request.expected_user_hash = Some(banned_hash);

        serve_callback_session(runtime, request).await.unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(100), peer.accept())
                .await
                .is_err(),
            "a user-hash ban must prevent the callback socket from opening"
        );
    }
}
