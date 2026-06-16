//! Routing-table contact model and LAN/subnet helpers.
//!
//! The routing crate keeps enough peer metadata to mirror the oracle's
//! anti-clustering, HELLO-derived metadata, and UDP-key persistence rules.

use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use emulebb_kad_proto::{KadUdpKey, NodeId};

/// Liveness state of a routing table contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactType {
    /// Responded recently.
    Active,
    /// Has not responded but not yet dead.
    Inactive,
    /// Failed multiple pings, candidate for replacement.
    Dead,
}

/// A Kad2 routing table entry.
#[derive(Debug, Clone)]
pub struct Contact {
    /// Peer Kad node ID.
    pub id: NodeId,
    /// Peer IPv4 address.
    pub ip: Ipv4Addr,
    /// Peer Kad UDP port.
    pub udp_port: u16,
    /// Peer ED2K TCP port.
    pub tcp_port: u16,
    /// Highest Kad version observed for the peer.
    pub kad_version: u8,
    /// Latest persisted or learned UDP anti-spoofing key for this peer.
    pub udp_key: KadUdpKey,
    /// Peer-advertised Kad UDP port from `TAG_SOURCEUPORT`, if provided.
    pub hello_source_udp_port: Option<u16>,
    /// Whether the peer announced itself as UDP firewalled in hello metadata.
    pub udp_firewalled: bool,
    /// Whether the peer announced itself as TCP firewalled in hello metadata.
    pub tcp_firewalled: bool,
    /// Whether the peer requested a `HELLO_RES_ACK` packet.
    pub requests_hello_res_ack: bool,
    /// Whether we ever received a HELLO packet from this peer (oracle
    /// `m_bReceivedHelloPacket`): a positive sign of liveness that feeds the
    /// local quality score even before the contact is IP-verified.
    pub received_hello_packet: bool,
    /// Whether the contact has completed the stronger verified path in the routing table.
    pub verified: bool,
    /// Current routing-table liveness state.
    pub contact_type: ContactType,
    /// Oracle `CContact::m_byType` (0..=4): the staleness counter advanced by the
    /// small-timer probe path (`CheckingType`). 0 is the freshest/most trusted,
    /// 4 marks the contact dead and removable. This is distinct from the
    /// age-derived [`Contact::oracle_type`] freshness gate used for lookup
    /// answers; the rust upkeep loop drives this counter the way the master's
    /// per-bin small timer does.
    pub probe_type: u8,
    /// Oracle `CContact::m_tExpires`: the instant at which this contact's current
    /// liveness window lapses. `None` mirrors the oracle `m_tExpires == 0`
    /// (no window set yet); the small timer seeds it on first sweep.
    pub expires_at: Option<SystemTime>,
    /// Most recent successful observation time.
    pub last_seen: SystemTime,
    /// First insertion time for this contact.
    pub created_at: SystemTime,
}

/// Oracle `m_byType` value that marks a contact dead and removable.
pub const CONTACT_TYPE_DEAD: u8 = 4;

/// Minimum local quality score a contact must clear to escape the
/// "weak for replacement" classification (oracle `IsWeakForReplacement` 260).
pub const KAD_LOCAL_QUALITY_WEAK_THRESHOLD: u32 = 260;

/// Quality margin a newcomer must beat a weak contact by before it may evict it
/// (oracle `KAD_LOCAL_QUALITY_REPLACEMENT_MARGIN`).
pub const KAD_LOCAL_QUALITY_REPLACEMENT_MARGIN: u32 = 120;

impl Contact {
    /// Create a new contact with default liveness state.
    pub fn new(id: NodeId, ip: Ipv4Addr, udp_port: u16, tcp_port: u16, kad_version: u8) -> Self {
        let now = SystemTime::now();
        Contact {
            id,
            ip,
            udp_port,
            tcp_port,
            kad_version,
            udp_key: KadUdpKey::ZERO,
            hello_source_udp_port: None,
            udp_firewalled: false,
            tcp_firewalled: false,
            requests_hello_res_ack: false,
            received_hello_packet: false,
            verified: false,
            contact_type: ContactType::Inactive,
            probe_type: 2,
            expires_at: None,
            last_seen: now,
            created_at: now,
        }
    }

    /// Returns true if this IP is a LAN (RFC 1918) address.
    pub fn is_lan_ip(&self) -> bool {
        is_lan(self.ip)
    }

    /// The oracle age-based contact "type" used as a freshness gate.
    ///
    /// Mirrors `CContact::UpdateType` (Contact.cpp:215-230): bucketed by how
    /// many whole hours the contact has existed. Lower numbers are older and
    /// more trusted; `GetClosestTo(uMaxType, ...)` keeps only `type <= uMaxType`.
    ///   - < 1 hour old  -> 2
    ///   - 1..2 hours    -> 1
    ///   - >= 2 hours    -> 0
    #[must_use]
    pub fn oracle_type(&self) -> u8 {
        self.oracle_type_at(SystemTime::now())
    }

    /// [`Contact::oracle_type`] evaluated at an explicit instant (test seam).
    #[must_use]
    pub fn oracle_type_at(&self, now: SystemTime) -> u8 {
        let hours = now
            .duration_since(self.created_at)
            .map(|elapsed| elapsed.as_secs() / 3600)
            .unwrap_or(0);
        match hours {
            0 => 2,
            1 => 1,
            _ => 0,
        }
    }

    /// Mark the contact as alive (Active) and update last_seen.
    ///
    /// Mirrors the oracle refresh path (`CRoutingZone::Add` / `UpdateType` on a
    /// re-seen contact): the staleness counter resets to the freshest age bucket
    /// and a fresh liveness window opens, so a contact that answers a probe or
    /// HELLO is no longer a replacement candidate.
    pub fn mark_alive(&mut self) {
        let now = SystemTime::now();
        self.contact_type = ContactType::Active;
        self.last_seen = now;
        self.probe_type = self.oracle_type_at(now);
        self.expires_at = Some(now + Duration::from_secs(2 * 3600));
    }

    /// Mark the contact as dead.
    pub fn mark_dead(&mut self) {
        self.contact_type = ContactType::Dead;
        self.probe_type = CONTACT_TYPE_DEAD;
        self.expires_at = Some(SystemTime::now());
    }

    /// Advance the staleness counter the way the oracle small timer does before
    /// HELLO-probing a stale contact (`CContact::CheckingType`,
    /// Contact.cpp:205-213): while not yet dead, bump `probe_type` toward 4 and
    /// open a fresh two-minute expiry window. Returns the new counter value.
    pub fn checking_type(&mut self) -> u8 {
        self.checking_type_at(SystemTime::now())
    }

    /// [`Contact::checking_type`] evaluated at an explicit instant (test seam).
    pub fn checking_type_at(&mut self, now: SystemTime) -> u8 {
        if self.probe_type < CONTACT_TYPE_DEAD {
            self.probe_type += 1;
            self.expires_at = Some(now + Duration::from_secs(2 * 60));
        }
        self.probe_type
    }

    /// Whether this contact has reached the oracle dead state (`m_byType >= 4`).
    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.probe_type >= CONTACT_TYPE_DEAD
    }

    /// Whether the contact's current liveness window has lapsed at `now`
    /// (oracle `m_tExpires > 0 && m_tExpires <= tNow`).
    #[must_use]
    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        match self.expires_at {
            Some(expires) => expires <= now,
            None => false,
        }
    }

    /// Per-contact local quality score (oracle `CContact::GetLocalQualityScore`,
    /// Contact.cpp:250-297). Higher is healthier. A dead contact scores 0.
    #[must_use]
    pub fn local_quality_score(&self, now: SystemTime) -> u32 {
        if self.probe_type >= CONTACT_TYPE_DEAD {
            return 0;
        }
        let mut score = 0u32;
        if self.verified {
            score += 400;
        }
        if self.received_hello_packet {
            score += 240;
        }
        if self.udp_key != KadUdpKey::ZERO {
            score += 160;
        }
        score += match self.probe_type {
            0 => 120,
            1 => 90,
            2 => 60,
            3 => 20,
            _ => 0,
        };
        let age = now
            .duration_since(self.last_seen)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        if age <= 15 * 60 {
            score += 90;
        } else if age <= 3600 {
            score += 70;
        } else if age <= 4 * 3600 {
            score += 50;
        } else if age <= 12 * 3600 {
            score += 25;
        }
        score += kad_version_quality(self.kad_version);
        score
    }

    /// Whether this contact is a weak replacement candidate at `now`
    /// (oracle `CContact::IsWeakForReplacement`, Contact.cpp:299-312). The
    /// oracle `InUse()` guard has no rust analogue (we never pin contacts across
    /// an async lookup), so it is intentionally omitted.
    #[must_use]
    pub fn is_weak_for_replacement(&self, now: SystemTime) -> bool {
        if self.probe_type >= CONTACT_TYPE_DEAD {
            return true;
        }
        if self.is_expired_at(now) {
            return true;
        }
        if !self.verified && !self.received_hello_packet && self.udp_key == KadUdpKey::ZERO {
            return true;
        }
        self.local_quality_score(now) < KAD_LOCAL_QUALITY_WEAK_THRESHOLD
    }
}

/// Kad-version quality contribution (oracle `GetKadVersionQuality`,
/// Contact.cpp:57-68): newer protocol versions are scored higher.
#[must_use]
pub fn kad_version_quality(version: u8) -> u32 {
    // KADEMLIA_VERSION (current) = 10, V9_50a = 9, V8_49b = 8, V6_49aBETA = 6.
    if version >= 10 {
        12
    } else if version >= 9 {
        9
    } else if version >= 8 {
        6
    } else if version >= 6 {
        3
    } else {
        0
    }
}

/// Returns true for RFC 1918 private addresses and loopback.
pub fn is_lan(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 127.0.0.0/8 loopback
    if octets[0] == 127 {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lan_detection() {
        assert!(is_lan("10.0.0.1".parse().unwrap()));
        assert!(is_lan("172.16.5.5".parse().unwrap()));
        assert!(is_lan("172.31.255.255".parse().unwrap()));
        assert!(is_lan("192.168.1.100".parse().unwrap()));
        assert!(is_lan("127.0.0.1".parse().unwrap()));
        assert!(!is_lan("8.8.8.8".parse().unwrap()));
        assert!(!is_lan("1.2.3.4".parse().unwrap()));
        assert!(!is_lan("172.15.0.1".parse().unwrap()));
        assert!(!is_lan("172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn test_contact_new() {
        let id = NodeId::from_bytes([1u8; 16]);
        let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let c = Contact::new(id, ip, 4672, 4662, 9);
        assert_eq!(c.contact_type, ContactType::Inactive);
        assert!(!c.verified);
        assert_eq!(c.hello_source_udp_port, None);
        assert!(!c.udp_firewalled);
        assert!(!c.tcp_firewalled);
        assert!(!c.requests_hello_res_ack);
    }

    #[test]
    fn test_mark_alive_dead() {
        let id = NodeId::from_bytes([2u8; 16]);
        let ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let mut c = Contact::new(id, ip, 4672, 4662, 9);
        c.mark_alive();
        assert_eq!(c.contact_type, ContactType::Active);
        c.mark_dead();
        assert_eq!(c.contact_type, ContactType::Dead);
        assert!(c.is_dead());
    }

    #[test]
    fn test_checking_type_ages_toward_dead() {
        let mut c = Contact::new(NodeId::from_bytes([3u8; 16]), "8.8.8.8".parse().unwrap(), 1, 2, 9);
        c.probe_type = 0;
        let now = SystemTime::now();
        assert_eq!(c.checking_type_at(now), 1);
        assert_eq!(c.checking_type_at(now), 2);
        assert_eq!(c.checking_type_at(now), 3);
        assert_eq!(c.checking_type_at(now), 4);
        // Saturates at dead.
        assert_eq!(c.checking_type_at(now), 4);
        assert!(c.is_dead());
    }

    #[test]
    fn test_local_quality_score_factors() {
        let now = SystemTime::now();
        // Strong contact: verified(400) + hello(240) + key(160) + type0(120)
        // + fresh<=15min(90) + v10 quality(12) = 1022.
        let mut strong = Contact::new(NodeId::from_bytes([4u8; 16]), "1.2.3.4".parse().unwrap(), 1, 2, 10);
        strong.verified = true;
        strong.received_hello_packet = true;
        strong.udp_key = emulebb_kad_proto::KadUdpKey::new(0x11);
        strong.probe_type = 0;
        strong.last_seen = now;
        assert_eq!(strong.local_quality_score(now), 1022);

        // A dead contact always scores 0 regardless of other factors.
        let mut dead = strong.clone();
        dead.probe_type = CONTACT_TYPE_DEAD;
        assert_eq!(dead.local_quality_score(now), 0);
    }

    #[test]
    fn test_is_weak_for_replacement() {
        let now = SystemTime::now();
        // Unverified, no hello, no key -> weak.
        let mut bare = Contact::new(NodeId::from_bytes([5u8; 16]), "1.2.3.5".parse().unwrap(), 1, 2, 9);
        bare.last_seen = now;
        assert!(bare.is_weak_for_replacement(now));

        // Expired window -> weak even if otherwise OK.
        let mut expired = Contact::new(NodeId::from_bytes([6u8; 16]), "1.2.3.6".parse().unwrap(), 1, 2, 9);
        expired.received_hello_packet = true;
        expired.expires_at = Some(now - Duration::from_secs(1));
        assert!(expired.is_weak_for_replacement(now));

        // Strong, unexpired, high score -> not weak.
        let mut strong = Contact::new(NodeId::from_bytes([7u8; 16]), "1.2.3.7".parse().unwrap(), 1, 2, 10);
        strong.verified = true;
        strong.received_hello_packet = true;
        strong.udp_key = emulebb_kad_proto::KadUdpKey::new(0x22);
        strong.probe_type = 0;
        strong.last_seen = now;
        strong.expires_at = Some(now + Duration::from_secs(3600));
        assert!(!strong.is_weak_for_replacement(now));
    }

    #[test]
    fn test_kad_version_quality_buckets() {
        assert_eq!(kad_version_quality(10), 12);
        assert_eq!(kad_version_quality(9), 9);
        assert_eq!(kad_version_quality(8), 6);
        assert_eq!(kad_version_quality(6), 3);
        assert_eq!(kad_version_quality(5), 0);
    }
}
