//! Kad LowID buddy / firewalled-callback state machine.
//!
//! A TCP-firewalled (LowID) Kad node cannot be reached directly by peers that
//! want it as a source, so eMule's Kad uses a "buddy" relay: the firewalled node
//! searches Kad for a non-firewalled node near a derived target id, asks it to
//! be its buddy (`KADEMLIA_FINDBUDDY_REQ`), and keeps a TCP connection to that
//! buddy. A peer wanting the firewalled node then sends `KADEMLIA_CALLBACK_REQ`
//! to the buddy, which relays it to the firewalled node, which TCP-connects out
//! to the requester (the standard firewalled callback).
//!
//! This module holds the protocol-faithful *decisions and state*; the network
//! drivers (UDP dispatch arms, the buddy-management task, and the TCP callback
//! completion) live in the core runtime and the eD2k client-TCP layer. Keeping
//! the policy here makes every oracle-parity rule independently unit-testable.
//!
//! Oracle references (do not modify):
//! - `srchybrid/kademlia/net/KademliaUDPListener.cpp`
//!   `Process_KADEMLIA_FINDBUDDY_REQ` / `_RES` / `Process_KADEMLIA_CALLBACK_REQ`
//! - `srchybrid/kademlia/kademlia/Search.cpp` (the `FINDBUDDY` search type)
//! - `srchybrid/ClientList.cpp` `RequestBuddy` / `IncomingBuddy` / buddy upkeep
//! - `srchybrid/kademlia/kademlia/Kademlia.cpp` buddy timers
//!   (`m_tNextFindBuddy`, find-buddy delayed 5 min after a firewall recheck).

use std::net::SocketAddr;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use emulebb_kad_proto::{Ed2kHash, NodeId};

/// How long after the last firewall verdict change a freshly-firewalled node
/// waits before its first buddy search, mirroring the oracle's 5-minute guard
/// (`Kademlia.cpp`: `m_tNextFindBuddy` is pushed to at least firewall-check +
/// 5 min) so a transient firewalled status does not trigger a needless search.
pub const FIND_BUDDY_INITIAL_DELAY_SECS: i64 = 300;

/// Interval between buddy searches while we still need a buddy, mirroring the
/// oracle `MIN2S(20)` cadence on `m_tNextFindBuddy`.
pub const FIND_BUDDY_RETRY_SECS: i64 = 1_200;

/// Whether the local node currently believes it is TCP-firewalled (LowID) *and*
/// has a verified-firewalled UDP status, the exact condition under which the
/// oracle starts looking for a buddy (`ClientList.cpp` upkeep:
/// `IsFirewalled() && IsFirewalledUDP(true)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuddyNeedInput {
    /// We advertise the eD2k/Kad TCP-firewalled (LowID) bit.
    pub tcp_firewalled: bool,
    /// Our Kad UDP firewall check has converged on a firewalled verdict.
    pub udp_firewalled_verified: bool,
    /// Kad is bootstrapped/connected (a search would actually run).
    pub kad_connected: bool,
}

impl BuddyNeedInput {
    /// True when the oracle would actively try to acquire a buddy.
    #[must_use]
    pub fn needs_buddy(self) -> bool {
        self.tcp_firewalled && self.udp_firewalled_verified && self.kad_connected
    }
}

/// Derive the Kad buddy-search target from our own Kad id.
///
/// The oracle uses `CUInt128(true).Xor(GetKadID())` — `CUInt128(true)` is the
/// all-ones value, so the target is the bitwise complement of our id. Because
/// `NodeId` stores the raw Kad wire layout, complementing every byte is
/// representation-independent and matches the on-wire `m_uTarget`.
#[must_use]
pub fn buddy_search_target(own_id: NodeId) -> NodeId {
    let mut bytes = own_id.0;
    for byte in &mut bytes {
        *byte = !*byte;
    }
    NodeId(bytes)
}

/// Verify an inbound `FINDBUDDY_RES` `buddy_id` echo against our own Kad id.
///
/// The oracle reads the echoed value, XORs it with all-ones, and accepts the
/// response only when the result equals our Kad id
/// (`Process_KADEMLIA_FINDBUDDY_RES`). This is equivalent to checking that the
/// echoed value is exactly our buddy-search target.
#[must_use]
pub fn find_buddy_res_matches(own_id: NodeId, echoed_buddy_id: NodeId) -> bool {
    buddy_search_target(own_id) == echoed_buddy_id
}

/// A client we have agreed to be a buddy for (oracle `IncomingBuddy`).
///
/// We hold this so an inbound `KADEMLIA_CALLBACK_REQ` whose `buddy_id` matches
/// can be relayed to the right firewalled client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingBuddy {
    /// The firewalled client's contact id (its eD2k user hash, sent as the
    /// `client_hash`/`userID` field of the `FINDBUDDY_REQ`).
    pub client_hash: Ed2kHash,
    /// The buddy-search id the firewalled client used (the `buddy_id` field of
    /// its `FINDBUDDY_REQ`). Callback requests echo this so we can match.
    pub buddy_id: NodeId,
    /// The firewalled client's TCP endpoint (its source IP + advertised TCP
    /// port) for the relay/callback bookkeeping.
    pub tcp_addr: SocketAddr,
    /// The firewalled client's Kad UDP endpoint (request source address).
    pub udp_addr: SocketAddr,
    /// When the buddy relationship was registered.
    pub registered_at: DateTime<Utc>,
}

/// A buddy we acquired because *we* are firewalled (oracle `RequestBuddy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingBuddy {
    /// The buddy node's eD2k user hash (the `client_hash` it returned in
    /// `FINDBUDDY_RES`).
    pub client_hash: Ed2kHash,
    /// The buddy node's TCP endpoint (its source IP + the TCP port it returned).
    pub tcp_addr: SocketAddr,
    /// The buddy node's Kad UDP endpoint (`FINDBUDDY_RES` source address).
    pub udp_addr: SocketAddr,
    /// Connect-option byte the buddy advertised (0 when the legacy response had
    /// no trailing byte).
    pub connect_options: u8,
    /// When this buddy was accepted.
    pub acquired_at: DateTime<Utc>,
}

/// Process-local buddy/callback subsystem state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KadBuddyState {
    /// The single client we are currently a buddy for. The oracle is a buddy for
    /// at most one client at a time (`GetBuddyStatus() == Connected` short-circuits
    /// `Process_KADEMLIA_FINDBUDDY_REQ`).
    incoming: Option<IncomingBuddy>,
    /// The buddy we acquired for ourselves while firewalled. Also at most one.
    outgoing: Option<OutgoingBuddy>,
    /// Timestamp of our last buddy search attempt (rate-limiting the search).
    last_search_at: Option<DateTime<Utc>>,
}

/// Why an inbound `FINDBUDDY_REQ` was refused (so the caller knows to stay
/// silent, matching the oracle's early `return`s without a response).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindBuddyReqRefusal {
    /// We are firewalled ourselves, so we cannot serve as a relay.
    SelfFirewalled,
    /// We already have an incoming buddy (the oracle serves only one).
    AlreadyHaveBuddy,
}

impl KadBuddyState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The client we are currently a buddy for, if any.
    #[must_use]
    pub fn incoming(&self) -> Option<&IncomingBuddy> {
        self.incoming.as_ref()
    }

    /// The buddy we acquired for ourselves, if any.
    #[must_use]
    pub fn outgoing(&self) -> Option<&OutgoingBuddy> {
        self.outgoing.as_ref()
    }

    /// True when we already serve a client as its buddy.
    #[must_use]
    pub fn has_incoming_buddy(&self) -> bool {
        self.incoming.is_some()
    }

    /// True when we already hold a buddy of our own.
    #[must_use]
    pub fn has_outgoing_buddy(&self) -> bool {
        self.outgoing.is_some()
    }

    /// Decide whether to accept an inbound `FINDBUDDY_REQ` and become this
    /// client's buddy.
    ///
    /// Mirrors `Process_KADEMLIA_FINDBUDDY_REQ`: refuse (silently) if we are
    /// firewalled ourselves, or if we already have a buddy. On acceptance the
    /// caller registers the [`IncomingBuddy`] and replies `FINDBUDDY_RES`.
    ///
    /// # Errors
    ///
    /// Returns the [`FindBuddyReqRefusal`] reason when the request must be
    /// ignored without a response.
    pub fn accept_incoming_buddy(
        &mut self,
        self_firewalled: bool,
        buddy: IncomingBuddy,
    ) -> Result<(), FindBuddyReqRefusal> {
        if self_firewalled {
            return Err(FindBuddyReqRefusal::SelfFirewalled);
        }
        if self.incoming.is_some() {
            return Err(FindBuddyReqRefusal::AlreadyHaveBuddy);
        }
        self.incoming = Some(buddy);
        Ok(())
    }

    /// Drop the incoming-buddy relationship (the relayed client went away).
    pub fn clear_incoming_buddy(&mut self) {
        self.incoming = None;
    }

    /// Look up the incoming buddy a `CALLBACK_REQ` should be relayed to.
    ///
    /// The oracle relays any callback to its single current buddy
    /// (`Process_KADEMLIA_CALLBACK_REQ` uses `GetBuddy()` directly and only
    /// `JOHNTODO`-comments the buddy-id filter). We additionally require the
    /// echoed `buddy_id` to match the buddy we registered, which is strictly
    /// safer and never rejects a well-formed stock callback.
    #[must_use]
    pub fn callback_relay_target(&self, callback_buddy_id: NodeId) -> Option<&IncomingBuddy> {
        self.incoming
            .as_ref()
            .filter(|buddy| buddy.buddy_id == callback_buddy_id)
    }

    /// Record an accepted buddy of our own (after a verified `FINDBUDDY_RES`).
    pub fn set_outgoing_buddy(&mut self, buddy: OutgoingBuddy) {
        self.outgoing = Some(buddy);
    }

    /// Drop our own buddy (connection lost). The oracle immediately schedules a
    /// new search in this case; the caller does so via [`Self::should_search`].
    pub fn clear_outgoing_buddy(&mut self) {
        self.outgoing = None;
    }

    /// Whether we should launch a buddy search now.
    ///
    /// Mirrors the oracle upkeep: only when we need a buddy, do not already have
    /// one, and the per-search cooldown has elapsed. The initial delay is longer
    /// (`FIND_BUDDY_INITIAL_DELAY_SECS`) than the retry cadence so a freshly
    /// firewalled node does not chase a transient verdict.
    #[must_use]
    pub fn should_search(&self, need: BuddyNeedInput, now: DateTime<Utc>) -> bool {
        if !need.needs_buddy() || self.outgoing.is_some() {
            return false;
        }
        match self.last_search_at {
            None => true,
            Some(last) => now - last >= ChronoDuration::seconds(FIND_BUDDY_RETRY_SECS),
        }
    }

    /// Record that a buddy search was started now (rate-limit bookkeeping).
    pub fn mark_search_started(&mut self, now: DateTime<Utc>) {
        self.last_search_at = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(last: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)), port)
    }

    fn own() -> NodeId {
        NodeId::from_bytes([0xAB; 16])
    }

    #[test]
    fn buddy_target_is_bitwise_complement() {
        let target = buddy_search_target(own());
        assert_eq!(target.0, [!0xABu8; 16]);
    }

    #[test]
    fn find_buddy_res_accepts_complement_echo() {
        let echoed = buddy_search_target(own());
        assert!(find_buddy_res_matches(own(), echoed));
    }

    #[test]
    fn find_buddy_res_rejects_wrong_echo() {
        assert!(!find_buddy_res_matches(own(), NodeId::from_bytes([0x01; 16])));
        // Echoing our own id (instead of the complement) must be rejected.
        assert!(!find_buddy_res_matches(own(), own()));
    }

    #[test]
    fn needs_buddy_requires_all_three_conditions() {
        let base = BuddyNeedInput {
            tcp_firewalled: true,
            udp_firewalled_verified: true,
            kad_connected: true,
        };
        assert!(base.needs_buddy());
        assert!(!BuddyNeedInput { tcp_firewalled: false, ..base }.needs_buddy());
        assert!(!BuddyNeedInput { udp_firewalled_verified: false, ..base }.needs_buddy());
        assert!(!BuddyNeedInput { kad_connected: false, ..base }.needs_buddy());
    }

    fn incoming(buddy_id: NodeId) -> IncomingBuddy {
        IncomingBuddy {
            client_hash: Ed2kHash::from_bytes([0x11; 16]),
            buddy_id,
            tcp_addr: addr(5, 4662),
            udp_addr: addr(5, 4672),
            registered_at: Utc::now(),
        }
    }

    #[test]
    fn accept_incoming_buddy_refuses_when_self_firewalled() {
        let mut state = KadBuddyState::new();
        let result = state.accept_incoming_buddy(true, incoming(NodeId::from_bytes([0x22; 16])));
        assert_eq!(result, Err(FindBuddyReqRefusal::SelfFirewalled));
        assert!(!state.has_incoming_buddy());
    }

    #[test]
    fn accept_incoming_buddy_refuses_second_buddy() {
        let mut state = KadBuddyState::new();
        state
            .accept_incoming_buddy(false, incoming(NodeId::from_bytes([0x22; 16])))
            .unwrap();
        let result = state.accept_incoming_buddy(false, incoming(NodeId::from_bytes([0x33; 16])));
        assert_eq!(result, Err(FindBuddyReqRefusal::AlreadyHaveBuddy));
    }

    #[test]
    fn callback_relay_matches_registered_buddy_id_only() {
        let buddy_id = NodeId::from_bytes([0x44; 16]);
        let mut state = KadBuddyState::new();
        assert!(state.callback_relay_target(buddy_id).is_none());
        state.accept_incoming_buddy(false, incoming(buddy_id)).unwrap();
        assert!(state.callback_relay_target(buddy_id).is_some());
        assert!(
            state
                .callback_relay_target(NodeId::from_bytes([0x99; 16]))
                .is_none()
        );
    }

    fn outgoing() -> OutgoingBuddy {
        OutgoingBuddy {
            client_hash: Ed2kHash::from_bytes([0x55; 16]),
            tcp_addr: addr(7, 4662),
            udp_addr: addr(7, 4672),
            connect_options: 0,
            acquired_at: Utc::now(),
        }
    }

    #[test]
    fn should_search_only_when_needed_and_without_buddy() {
        let need = BuddyNeedInput {
            tcp_firewalled: true,
            udp_firewalled_verified: true,
            kad_connected: true,
        };
        let now = Utc::now();
        let mut state = KadBuddyState::new();
        assert!(state.should_search(need, now));

        state.set_outgoing_buddy(outgoing());
        assert!(!state.should_search(need, now));

        state.clear_outgoing_buddy();
        assert!(state.should_search(need, now));

        let not_needed = BuddyNeedInput { tcp_firewalled: false, ..need };
        assert!(!state.should_search(not_needed, now));
    }

    #[test]
    fn should_search_respects_retry_cooldown() {
        let need = BuddyNeedInput {
            tcp_firewalled: true,
            udp_firewalled_verified: true,
            kad_connected: true,
        };
        let now = Utc::now();
        let mut state = KadBuddyState::new();
        state.mark_search_started(now);
        assert!(!state.should_search(need, now));
        assert!(!state.should_search(need, now + ChronoDuration::seconds(FIND_BUDDY_RETRY_SECS - 1)));
        assert!(state.should_search(need, now + ChronoDuration::seconds(FIND_BUDDY_RETRY_SECS)));
    }
}
