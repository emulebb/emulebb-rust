//! Legacy pre-v8 Kad contact-verification challenge tracker.
//!
//! Mirrors `CPacketTracking::{AddLegacyChallenge, IsLegacyChallenge,
//! HasActiveLegacyChallenge}` (`kademlia/net/PacketTracking.cpp`). A contact
//! whose Kad version is below 8 (`KADEMLIA_VERSION7_49a`) does not support the
//! receiver-key handshake, so to confirm its source IP is not spoofed we send a
//! challenge packet and verify the contact only when the matching answer returns:
//!
//! - version 7 (`49a`): a `KADEMLIA2_PING` with challenge id `0`, verified by the
//!   matching `KADEMLIA2_PONG`.
//! - version < 7: a `KADEMLIA2_REQ` (FIND_VALUE) whose target is a random
//!   challenge id, verified by the matching `KADEMLIA2_RES` echoing that target.
//!
//! Each entry expires after 180s (`SEC2MS(180)`), like the oracle list.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use emulebb_kad_proto::{KadPacket, NodeId, Req, constants::KADEMLIA_FIND_VALUE, opcode};

use super::DhtNode;
use crate::error::DhtError;

/// Oracle challenge lifetime (`SEC2MS(180)`).
const LEGACY_CHALLENGE_TTL: Duration = Duration::from_secs(180);

/// One pending legacy challenge (oracle `TrackChallenge_Struct`).
#[derive(Debug, Clone)]
struct LegacyChallenge {
    inserted: Instant,
    ip: Ipv4Addr,
    contact_id: NodeId,
    /// The challenge id we expect echoed back. `NodeId::ZERO` for a PING
    /// challenge (oracle `uChallenge == 0`, matched by opcode only).
    challenge_id: NodeId,
    /// The response opcode that resolves this challenge: `KADEMLIA2_RES` for a
    /// REQ challenge, `KADEMLIA2_PONG` for a PING challenge.
    response_opcode: u8,
}

/// Bounded FIFO of pending legacy challenges (oracle `listChallengeRequests`).
#[derive(Debug, Default)]
pub(crate) struct LegacyChallengeTracker {
    entries: Vec<LegacyChallenge>,
}

impl LegacyChallengeTracker {
    /// Drop entries older than the 180s TTL (oracle tail-pruning).
    fn prune(&mut self, now: Instant) {
        self.entries
            .retain(|entry| now.duration_since(entry.inserted) < LEGACY_CHALLENGE_TTL);
    }

    /// Record a new pending challenge (oracle `AddLegacyChallenge`).
    pub(crate) fn add(
        &mut self,
        contact_id: NodeId,
        challenge_id: NodeId,
        ip: Ipv4Addr,
        response_opcode: u8,
        now: Instant,
    ) {
        self.prune(now);
        self.entries.push(LegacyChallenge {
            inserted: now,
            ip,
            contact_id,
            challenge_id,
            response_opcode,
        });
    }

    /// Whether a non-expired challenge is already pending for this IP (oracle
    /// `HasActiveLegacyChallenge`): the oracle sends at most one at a time.
    pub(crate) fn has_active(&self, ip: Ipv4Addr, now: Instant) -> bool {
        self.entries.iter().any(|entry| {
            entry.ip == ip && now.duration_since(entry.inserted) < LEGACY_CHALLENGE_TTL
        })
    }

    /// Resolve and consume a matching challenge (oracle `IsLegacyChallenge`):
    /// match by IP + response opcode, and (for a REQ challenge) the echoed
    /// challenge id. Returns the contact id to verify on a match. A PING
    /// challenge (`challenge_id == ZERO`) matches on opcode alone.
    pub(crate) fn resolve(
        &mut self,
        challenge_id: NodeId,
        ip: Ipv4Addr,
        response_opcode: u8,
        now: Instant,
    ) -> Option<NodeId> {
        self.prune(now);
        let position = self.entries.iter().position(|entry| {
            entry.ip == ip
                && entry.response_opcode == response_opcode
                && (entry.challenge_id == NodeId::ZERO || entry.challenge_id == challenge_id)
        })?;
        Some(self.entries.remove(position).contact_id)
    }
}

/// Kad version 7 (`KADEMLIA_VERSION7_49a`): supports sender/receiver keys but not
/// HELLO_RES_ACK, so it is verified with a PING challenge rather than a REQ.
const KAD_VERSION_7: u8 = 7;

impl DhtNode {
    /// Send a legacy verification challenge to a pre-v8 contact and track it
    /// (oracle `SendLegacyChallenge` / version-7 PING path). At most one
    /// challenge per IP is outstanding (oracle `HasActiveLegacyChallenge`).
    ///
    /// A version-7 contact is challenged with a `KADEMLIA2_PING` (verified by the
    /// `KADEMLIA2_PONG`); an older contact with a `KADEMLIA2_REQ` carrying a
    /// random challenge target (verified by the `KADEMLIA2_RES` echoing it).
    pub async fn send_legacy_challenge(
        &self,
        contact_id: NodeId,
        version: u8,
        addr: SocketAddr,
    ) -> Result<(), DhtError> {
        let SocketAddr::V4(v4) = addr else {
            return Ok(());
        };
        let ip = *v4.ip();
        let now = Instant::now();
        {
            // Oracle: don't send more than one challenge at a time per IP.
            let tracker = self.inner.legacy_challenges.lock().await;
            if tracker.has_active(ip, now) {
                return Ok(());
            }
        }

        if version == KAD_VERSION_7 {
            // Version 7 supports keys but not HELLO_RES_ACK: PING challenge.
            self.inner.legacy_challenges.lock().await.add(
                contact_id,
                NodeId::ZERO,
                ip,
                opcode::PONG,
                now,
            );
            self.send_packet(addr, &KadPacket::Ping).await?;
        } else {
            // Older versions: REQ (FIND_VALUE) with a random challenge target.
            let challenge_id = random_nonzero_node_id();
            self.inner.legacy_challenges.lock().await.add(
                contact_id,
                challenge_id,
                ip,
                opcode::RES,
                now,
            );
            self.send_packet(
                addr,
                &KadPacket::Req(Req {
                    count: KADEMLIA_FIND_VALUE,
                    target: challenge_id,
                    // Oracle puts the contact id as a sanity check in the recipient
                    // field of the legacy challenge REQ.
                    recipient_id: contact_id,
                }),
            )
            .await?;
        }
        Ok(())
    }

    /// Resolve an inbound `KADEMLIA2_RES` / `KADEMLIA2_PONG` against a pending
    /// legacy challenge and, on a match, verify the challenged contact (oracle
    /// `IsLegacyChallenge` -> `VerifyContact`). Returns `true` when a contact was
    /// verified. `challenge_id` is the RES target (or `ZERO` for a PONG).
    pub async fn resolve_legacy_challenge(
        &self,
        challenge_id: NodeId,
        ip: Ipv4Addr,
        response_opcode: u8,
    ) -> bool {
        let now = Instant::now();
        let contact_id = {
            let mut tracker = self.inner.legacy_challenges.lock().await;
            tracker.resolve(challenge_id, ip, response_opcode, now)
        };
        match contact_id {
            Some(contact_id) => self.verify_contact(&contact_id, ip).await,
            None => false,
        }
    }
}

/// A random non-zero 128-bit challenge id (oracle `SetValueRandom` with the
/// zero-value guard).
fn random_nonzero_node_id() -> NodeId {
    use rand::Rng;
    loop {
        let bytes: [u8; 16] = rand::thread_rng().r#gen();
        let id = NodeId::from_bytes(bytes);
        if id != NodeId::ZERO {
            return id;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 16])
    }

    #[test]
    fn req_challenge_resolves_on_matching_target() {
        let mut tracker = LegacyChallengeTracker::default();
        let now = Instant::now();
        let ip = Ipv4Addr::new(192, 0, 2, 7);
        tracker.add(id(1), id(0x55), ip, opcode::RES, now);
        // Wrong target: no match.
        assert!(tracker.resolve(id(0x66), ip, opcode::RES, now).is_none());
        // Correct target: resolves to the contact id and consumes the entry.
        assert_eq!(tracker.resolve(id(0x55), ip, opcode::RES, now), Some(id(1)));
        // Consumed: a second resolve finds nothing.
        assert!(tracker.resolve(id(0x55), ip, opcode::RES, now).is_none());
    }

    #[test]
    fn ping_challenge_matches_on_opcode_alone() {
        let mut tracker = LegacyChallengeTracker::default();
        let now = Instant::now();
        let ip = Ipv4Addr::new(192, 0, 2, 8);
        tracker.add(id(2), NodeId::ZERO, ip, opcode::PONG, now);
        // PONG carries no challenge id; any id matches a zero-challenge entry.
        assert_eq!(
            tracker.resolve(NodeId::ZERO, ip, opcode::PONG, now),
            Some(id(2))
        );
    }

    #[test]
    fn wrong_ip_or_opcode_does_not_resolve() {
        let mut tracker = LegacyChallengeTracker::default();
        let now = Instant::now();
        let ip = Ipv4Addr::new(192, 0, 2, 9);
        tracker.add(id(3), id(0x11), ip, opcode::RES, now);
        assert!(
            tracker
                .resolve(id(0x11), Ipv4Addr::new(192, 0, 2, 10), opcode::RES, now)
                .is_none()
        );
        assert!(tracker.resolve(id(0x11), ip, opcode::PONG, now).is_none());
        // Still pending for the correct IP+opcode.
        assert_eq!(tracker.resolve(id(0x11), ip, opcode::RES, now), Some(id(3)));
    }

    #[test]
    fn has_active_tracks_per_ip_and_expiry() {
        let mut tracker = LegacyChallengeTracker::default();
        let now = Instant::now();
        let ip = Ipv4Addr::new(192, 0, 2, 11);
        assert!(!tracker.has_active(ip, now));
        tracker.add(id(4), id(0x22), ip, opcode::RES, now);
        assert!(tracker.has_active(ip, now));
        // Past the TTL: expired.
        let later = now + LEGACY_CHALLENGE_TTL + Duration::from_secs(1);
        assert!(!tracker.has_active(ip, later));
        assert!(tracker.resolve(id(0x22), ip, opcode::RES, later).is_none());
    }

    #[tokio::test]
    async fn legacy_req_challenge_round_trip_verifies_contact() {
        use crate::node::DhtNode;
        use crate::node::config::DhtConfig;
        use emulebb_kad_routing::Contact;

        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(std::net::SocketAddr::new(
                std::net::IpAddr::V4(crate::test_bind_ip()),
                0,
            )),
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let node_id = id(0x42);
        // Fake peer at our LAN IP (never loopback; the send below must reach a
        // bindable/reachable address on the VPN split tunnel).
        let contact_ip = crate::test_bind_ip();
        // A pre-v7 contact already in the routing table, not yet verified.
        dht.add_contact(Contact::new(node_id, contact_ip, 42007, 42008, 6))
            .await
            .unwrap();
        assert!(!dht.routing_contacts().await[0].verified);

        // Send a legacy REQ challenge (version < 7).
        let addr = SocketAddr::from((contact_ip, 42007));
        dht.send_legacy_challenge(node_id, 6, addr).await.unwrap();

        // The tracked challenge target is what we must echo back. Read it out of
        // the tracker so the test can simulate the matching KADEMLIA2_RES.
        let challenge_id = {
            let tracker = dht.inner.legacy_challenges.lock().await;
            tracker
                .entries
                .iter()
                .find(|entry| entry.ip == contact_ip)
                .map(|entry| entry.challenge_id)
                .expect("challenge tracked")
        };
        assert_ne!(challenge_id, NodeId::ZERO);

        // A RES echoing the wrong target does not verify.
        assert!(
            !dht.resolve_legacy_challenge(id(0xFF), contact_ip, opcode::RES)
                .await
        );
        assert!(!dht.routing_contacts().await[0].verified);

        // The RES echoing our challenge target verifies the contact.
        assert!(
            dht.resolve_legacy_challenge(challenge_id, contact_ip, opcode::RES)
                .await
        );
        assert!(dht.routing_contacts().await[0].verified);
    }

    #[tokio::test]
    async fn one_challenge_per_ip_at_a_time() {
        use crate::node::DhtNode;
        use crate::node::config::DhtConfig;
        use emulebb_kad_routing::Contact;

        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(std::net::SocketAddr::new(
                std::net::IpAddr::V4(crate::test_bind_ip()),
                0,
            )),
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let node_id = id(0x43);
        // Fake peer at our LAN IP (never loopback; the send below must reach a
        // bindable/reachable address on the VPN split tunnel).
        let contact_ip = crate::test_bind_ip();
        dht.add_contact(Contact::new(node_id, contact_ip, 5000, 5001, 6))
            .await
            .unwrap();
        let addr = SocketAddr::from((contact_ip, 5000));
        dht.send_legacy_challenge(node_id, 6, addr).await.unwrap();
        dht.send_legacy_challenge(node_id, 6, addr).await.unwrap();
        // The second send is suppressed (oracle HasActiveLegacyChallenge): only
        // one entry exists for this IP.
        let count = dht
            .inner
            .legacy_challenges
            .lock()
            .await
            .entries
            .iter()
            .filter(|entry| entry.ip == contact_ip)
            .count();
        assert_eq!(count, 1);
    }
}
