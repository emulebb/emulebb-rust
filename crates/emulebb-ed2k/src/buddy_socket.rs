//! Persistent Kad buddy TCP socket registry.
//!
//! A Kad LowID buddy relationship is the one eD2k client-to-client relationship
//! that the oracle keeps *open* across operations: a buddy keeps a TCP socket to
//! the firewalled client it serves so it can relay an `OP_CALLBACK`, and the
//! firewalled client keeps the TCP socket to its buddy so callbacks can be
//! relayed back. The rest of this client is connection-per-operation, so this
//! registry is the single place that holds the long-lived buddy socket handles
//! without owning the sockets themselves.
//!
//! The oracle holds exactly one of each (`ClientList::m_pBuddy` is the single
//! outgoing buddy; an `IncomingBuddy` short-circuits once one is served), so the
//! registry stores at most one inbound slot (a peer we serve) and one outbound
//! slot (the buddy we acquired while firewalled).
//!
//! Ownership split:
//! - The held socket lives in its task (the listener session for the inbound
//!   leg, the outbound buddy task for the outbound leg). The registry only holds
//!   a write channel ([`tokio::sync::mpsc::UnboundedSender`]) plus identity, so
//!   `handle_kad_callback_req` (in `emulebb-core`) can push a framed
//!   `OP_CALLBACK` down the held inbound socket without owning it.
//! - The inbound slot is two-phase: the buddy-management layer first records the
//!   *expected* inbound buddy (when it accepts a `KADEMLIA_FINDBUDDY_REQ` and
//!   replies `FINDBUDDY_RES`), then the listener session that the expected buddy
//!   connects on *attaches* its writer once matched. This mirrors the oracle
//!   `KS_INCOMING_BUDDY` -> `KS_CONNECTED_BUDDY` transition.
//!
//! Oracle references (do not modify):
//! - `srchybrid/ClientList.cpp` buddy upkeep (`m_pBuddy`, `IncomingBuddy`,
//!   `RequestBuddy`, buddy-loss `SetFindBuddy`).
//! - `srchybrid/kademlia/net/KademliaUDPListener.cpp`
//!   `Process_KADEMLIA_CALLBACK_REQ` (`pBuddy->socket->SendPacket`).

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use emulebb_kad_proto::NodeId;
use tokio::sync::mpsc::UnboundedSender;

/// Identity of the inbound buddy we expect to connect to us (we are its buddy).
///
/// The firewalled client connects out to us after we reply `FINDBUDDY_RES`; we
/// recognize that connection by its source IP and the eD2k user hash it sent in
/// the `FINDBUDDY_REQ`, and key the relay on the `buddy_id` it derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedInboundBuddy {
    /// The firewalled client's source IP (the `FINDBUDDY_REQ` source address).
    pub ip: Ipv4Addr,
    /// The firewalled client's eD2k user hash (the `client_hash`/`userID` field).
    pub user_hash: [u8; 16],
    /// The buddy-search id the firewalled client used; callback requests echo it.
    pub buddy_id: NodeId,
}

/// The attached inbound buddy socket: a writer onto the held listener session.
#[derive(Debug)]
struct InboundBuddySocket {
    buddy_id: NodeId,
    sender: UnboundedSender<Vec<u8>>,
}

/// The outbound buddy (the buddy we acquired because *we* are firewalled). The
/// held socket lives in the outbound buddy task; the registry tracks identity so
/// "is this peer our buddy" checks and eviction are centralized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutboundBuddy {
    ip: Ipv4Addr,
    user_hash: [u8; 16],
}

#[derive(Debug, Default)]
struct RegistryInner {
    expected_inbound: Option<ExpectedInboundBuddy>,
    inbound: Option<InboundBuddySocket>,
    outbound: Option<OutboundBuddy>,
}

/// Shared, cheaply-cloneable handle to the single buddy-socket registry.
#[derive(Debug, Clone, Default)]
pub struct BuddySocketRegistry {
    inner: Arc<Mutex<RegistryInner>>,
}

impl BuddySocketRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RegistryInner> {
        self.inner.lock().expect("buddy socket registry poisoned")
    }

    /// Record the inbound buddy we expect to connect to us after we replied
    /// `FINDBUDDY_RES` (oracle `IncomingBuddy` -> `KS_INCOMING_BUDDY`). Replaces
    /// any prior expectation (the oracle serves only one buddy).
    pub fn set_expected_inbound(&self, expected: ExpectedInboundBuddy) {
        self.lock().expected_inbound = Some(expected);
    }

    /// Clear the inbound expectation and drop any attached inbound socket (oracle
    /// drops the served buddy when it becomes firewalled or loses the relation).
    pub fn clear_inbound(&self) {
        let mut inner = self.lock();
        inner.expected_inbound = None;
        inner.inbound = None;
    }

    /// Test whether a freshly-connected peer is the inbound buddy we expect, and
    /// we are not already holding an attached inbound socket. Returns the
    /// `buddy_id` to attach against on a match (oracle `KS_INCOMING_BUDDY`
    /// connection completing into `KS_CONNECTED_BUDDY`).
    #[must_use]
    pub fn match_connecting_peer(&self, ip: Ipv4Addr, user_hash: [u8; 16]) -> Option<NodeId> {
        let inner = self.lock();
        if inner.inbound.is_some() {
            return None;
        }
        inner
            .expected_inbound
            .filter(|expected| expected.ip == ip && expected.user_hash == user_hash)
            .map(|expected| expected.buddy_id)
    }

    /// Attach the held listener session's writer as the inbound buddy socket.
    /// Refuses (returns `false`) if a different inbound socket is already held,
    /// so only one inbound buddy socket exists (oracle single `m_pBuddy`).
    pub fn attach_inbound(&self, buddy_id: NodeId, sender: UnboundedSender<Vec<u8>>) -> bool {
        let mut inner = self.lock();
        if inner.inbound.is_some() {
            return false;
        }
        inner.inbound = Some(InboundBuddySocket { buddy_id, sender });
        true
    }

    /// Detach the inbound buddy socket if it is the one keyed by `buddy_id` (the
    /// held listener session closed). The expectation is left intact so a
    /// reconnect can re-attach.
    pub fn detach_inbound(&self, buddy_id: NodeId) {
        let mut inner = self.lock();
        if inner
            .inbound
            .as_ref()
            .is_some_and(|socket| socket.buddy_id == buddy_id)
        {
            inner.inbound = None;
        }
    }

    /// Push a framed packet down the held inbound buddy socket, keyed on the
    /// callback `buddy_id`. Returns `true` when an attached socket matched and
    /// accepted the bytes (oracle `pBuddy->socket->SendPacket`). A closed
    /// receiver (session gone) drops the stale socket and returns `false`.
    #[must_use]
    pub fn relay_to_inbound(&self, buddy_id: NodeId, frame: Vec<u8>) -> bool {
        let mut inner = self.lock();
        let Some(socket) = inner.inbound.as_ref() else {
            return false;
        };
        if socket.buddy_id != buddy_id {
            return false;
        }
        if socket.sender.send(frame).is_ok() {
            true
        } else {
            // Receiver dropped: the held session is gone. Evict the stale socket.
            inner.inbound = None;
            false
        }
    }

    /// Whether we currently hold an attached inbound buddy socket.
    #[must_use]
    pub fn has_inbound(&self) -> bool {
        self.lock().inbound.is_some()
    }

    /// Register the outbound buddy we acquired while firewalled (oracle
    /// `m_pBuddy` set on `KS_CONNECTED_BUDDY`). Replaces any prior outbound buddy.
    pub fn register_outbound(&self, ip: Ipv4Addr, user_hash: [u8; 16]) {
        self.lock().outbound = Some(OutboundBuddy { ip, user_hash });
    }

    /// Drop the outbound buddy (oracle buddy-loss: `m_pBuddy = NULL`).
    pub fn evict_outbound(&self) {
        self.lock().outbound = None;
    }

    /// Whether a peer (by IP + user hash) is our outbound buddy. Mirrors the
    /// oracle `buddy == client` identity check before answering buddy traffic.
    #[must_use]
    pub fn is_outbound_buddy(&self, ip: Ipv4Addr, user_hash: [u8; 16]) -> bool {
        self.lock()
            .outbound
            .is_some_and(|buddy| buddy.ip == ip && buddy.user_hash == user_hash)
    }

    /// Whether we currently hold an outbound buddy.
    #[must_use]
    pub fn has_outbound(&self) -> bool {
        self.lock().outbound.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn buddy_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 16])
    }

    fn expected(ip: Ipv4Addr, hash_byte: u8, id_byte: u8) -> ExpectedInboundBuddy {
        ExpectedInboundBuddy {
            ip,
            user_hash: [hash_byte; 16],
            buddy_id: buddy_id(id_byte),
        }
    }

    #[test]
    fn match_requires_expected_ip_and_hash() {
        let registry = BuddySocketRegistry::new();
        let ip = Ipv4Addr::new(198, 51, 100, 9);
        registry.set_expected_inbound(expected(ip, 0x11, 0x22));

        assert_eq!(
            registry.match_connecting_peer(ip, [0x11; 16]),
            Some(buddy_id(0x22))
        );
        // Wrong IP / wrong hash do not match.
        assert!(
            registry
                .match_connecting_peer(Ipv4Addr::new(10, 0, 0, 1), [0x11; 16])
                .is_none()
        );
        assert!(registry.match_connecting_peer(ip, [0x99; 16]).is_none());
    }

    #[test]
    fn attach_holds_single_inbound_and_evicts() {
        let registry = BuddySocketRegistry::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(registry.attach_inbound(buddy_id(0x22), tx));
        assert!(registry.has_inbound());

        // A second attach is refused (single inbound socket).
        let (tx2, _rx2) = mpsc::unbounded_channel();
        assert!(!registry.attach_inbound(buddy_id(0x33), tx2));

        // Once a socket is attached, a new connecting peer cannot match.
        let ip = Ipv4Addr::new(198, 51, 100, 9);
        registry.set_expected_inbound(expected(ip, 0x11, 0x22));
        assert!(registry.match_connecting_peer(ip, [0x11; 16]).is_none());

        // Detach by the wrong id is a no-op; the right id evicts.
        registry.detach_inbound(buddy_id(0x44));
        assert!(registry.has_inbound());
        registry.detach_inbound(buddy_id(0x22));
        assert!(!registry.has_inbound());
    }

    #[test]
    fn relay_delivers_only_to_matching_attached_socket() {
        let registry = BuddySocketRegistry::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(registry.attach_inbound(buddy_id(0x22), tx));

        // Wrong buddy_id does not deliver.
        assert!(!registry.relay_to_inbound(buddy_id(0x55), vec![1, 2, 3]));
        // Matching buddy_id delivers the exact frame.
        assert!(registry.relay_to_inbound(buddy_id(0x22), vec![9, 8, 7]));
        assert_eq!(rx.try_recv().unwrap(), vec![9, 8, 7]);
    }

    #[test]
    fn relay_to_closed_receiver_evicts_stale_socket() {
        let registry = BuddySocketRegistry::new();
        let (tx, rx) = mpsc::unbounded_channel();
        assert!(registry.attach_inbound(buddy_id(0x22), tx));
        drop(rx);
        assert!(!registry.relay_to_inbound(buddy_id(0x22), vec![1]));
        assert!(!registry.has_inbound());
    }

    #[test]
    fn relay_without_attached_socket_returns_false() {
        let registry = BuddySocketRegistry::new();
        assert!(!registry.relay_to_inbound(buddy_id(0x22), vec![1]));
    }

    #[test]
    fn outbound_register_match_and_evict() {
        let registry = BuddySocketRegistry::new();
        let ip = Ipv4Addr::new(192, 0, 2, 50);
        assert!(!registry.has_outbound());
        registry.register_outbound(ip, [0x77; 16]);
        assert!(registry.has_outbound());
        assert!(registry.is_outbound_buddy(ip, [0x77; 16]));
        assert!(!registry.is_outbound_buddy(ip, [0x00; 16]));
        assert!(!registry.is_outbound_buddy(Ipv4Addr::new(10, 0, 0, 1), [0x77; 16]));

        // Re-register replaces (single outbound buddy).
        let ip2 = Ipv4Addr::new(192, 0, 2, 51);
        registry.register_outbound(ip2, [0x88; 16]);
        assert!(!registry.is_outbound_buddy(ip, [0x77; 16]));
        assert!(registry.is_outbound_buddy(ip2, [0x88; 16]));

        registry.evict_outbound();
        assert!(!registry.has_outbound());
    }

    #[test]
    fn clear_inbound_drops_expectation_and_socket() {
        let registry = BuddySocketRegistry::new();
        let ip = Ipv4Addr::new(198, 51, 100, 9);
        registry.set_expected_inbound(expected(ip, 0x11, 0x22));
        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(registry.attach_inbound(buddy_id(0x22), tx));
        registry.clear_inbound();
        assert!(!registry.has_inbound());
        assert!(registry.match_connecting_peer(ip, [0x11; 16]).is_none());
    }
}
