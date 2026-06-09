//! Routing-table contact model and LAN/subnet helpers.
//!
//! The routing crate keeps enough peer metadata to mirror the oracle's
//! anti-clustering, HELLO-derived metadata, and UDP-key persistence rules.

use std::net::Ipv4Addr;
use std::time::SystemTime;

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
    /// Whether the contact has completed the stronger verified path in the routing table.
    pub verified: bool,
    /// Current routing-table liveness state.
    pub contact_type: ContactType,
    /// Most recent successful observation time.
    pub last_seen: SystemTime,
    /// First insertion time for this contact.
    pub created_at: SystemTime,
}

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
            verified: false,
            contact_type: ContactType::Inactive,
            last_seen: now,
            created_at: now,
        }
    }

    /// Returns true if this IP is a LAN (RFC 1918) address.
    pub fn is_lan_ip(&self) -> bool {
        is_lan(self.ip)
    }

    /// Mark the contact as alive (Active) and update last_seen.
    pub fn mark_alive(&mut self) {
        self.contact_type = ContactType::Active;
        self.last_seen = SystemTime::now();
    }

    /// Mark the contact as dead.
    pub fn mark_dead(&mut self) {
        self.contact_type = ContactType::Dead;
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
    }
}
