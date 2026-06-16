//! Process-wide buddy hello snapshot, the Rust analogue of the oracle
//! `BuddyHelloSnapshot` (`BaseClientFriendBuddySeams.h`) built from
//! `theApp.clientlist->GetBuddy()` while serializing the hello tag set.

use std::net::Ipv4Addr;
use std::sync::Mutex;

/// Buddy endpoint a firewalled client advertises in its hello so peers can reach
/// it through the buddy's UDP callback relay (`buddySnapshot.dwBuddyIP` /
/// `nBuddyPort`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloBuddySnapshot {
    /// Buddy IPv4 address (eMule `CUpDownClient::GetIP()`).
    pub ip: Ipv4Addr,
    /// Buddy UDP port (eMule `CUpDownClient::GetUDPPort()`).
    pub udp_port: u16,
}

/// Process-wide buddy hello snapshot, mirroring the oracle `BuddyHelloSnapshot`
/// built from `theApp.clientlist->GetBuddy()` at hello-serialize time. `Some`
/// only while we are firewalled AND hold an outgoing buddy: core sets it when a
/// Kad buddy is acquired and clears it when the buddy is dropped (which it does
/// as soon as we are no longer firewalled), so its presence is exactly the
/// oracle `bShouldAdvertise = IsFirewalled() && hasBuddy`.
static HELLO_BUDDY_SNAPSHOT: Mutex<Option<HelloBuddySnapshot>> = Mutex::new(None);

/// Publish (or clear with `None`) the buddy endpoint advertised in subsequent
/// hellos. Called by core from the Kad buddy subsystem when the outgoing buddy
/// is acquired or released.
pub fn set_hello_buddy_snapshot(snapshot: Option<HelloBuddySnapshot>) {
    *HELLO_BUDDY_SNAPSHOT
        .lock()
        .expect("hello buddy snapshot mutex poisoned") = snapshot;
}

/// Read the current buddy hello snapshot for the hello tag builder.
pub(super) fn hello_buddy_snapshot() -> Option<HelloBuddySnapshot> {
    *HELLO_BUDDY_SNAPSHOT
        .lock()
        .expect("hello buddy snapshot mutex poisoned")
}

/// A peer's buddy endpoint decoded from its eD2k hello tags `CT_EMULE_BUDDYIP`
/// (0xfc) and `CT_EMULE_BUDDYUDP` (0xfd), the oracle `m_nBuddyIP` / `m_nBuddyPort`
/// (decode at `BaseClient.cpp:492-510`). A firewalled (LowID) source advertises
/// these so a downloader can reach it through its Kad buddy's UDP callback relay.
///
/// The matching buddy *id* (`GetBuddyID`, used as the leading field of
/// `OP_REASKCALLBACKUDP`) is **not** carried in the hello — the oracle only ever
/// sets it from the Kad source-finding path (`DownloadQueue.cpp:2793`). So a
/// hello-decoded buddy yields the endpoint but no buddy-id; the downloader can
/// only originate the buddy-relayed reask once it also knows the buddy-id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DecodedHelloBuddy {
    /// Buddy IPv4 address (oracle `m_nBuddyIP`). The tag value is the `GetIP()`
    /// uint32; its octets read little-endian give the address (the inverse of the
    /// hello encode side, matching the other IP fields in the protocol).
    pub ip: std::net::Ipv4Addr,
    /// Buddy UDP port (low 16 bits of `CT_EMULE_BUDDYUDP`; oracle `m_nBuddyPort`).
    pub udp_port: u16,
}

impl DecodedHelloBuddy {
    /// Build a buddy endpoint from the raw `CT_EMULE_BUDDYIP` / `CT_EMULE_BUDDYUDP`
    /// tag values, returning `None` unless both an IP and a non-zero port are
    /// present (mirrors the oracle origination guard `GetBuddyIP() && GetBuddyPort()`).
    pub(crate) fn from_tag_values(buddy_ip: Option<u32>, buddy_udp: Option<u32>) -> Option<Self> {
        let ip = buddy_ip?;
        let udp_port = u16::try_from(buddy_udp? & 0xFFFF).ok()?;
        if ip == 0 || udp_port == 0 {
            return None;
        }
        Some(Self {
            ip: std::net::Ipv4Addr::from(ip.to_le_bytes()),
            udp_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::DecodedHelloBuddy;
    use std::net::Ipv4Addr;

    #[test]
    fn buddy_endpoint_decodes_ip_low16_port_and_requires_both() {
        // The IP tag is the GetIP() uint32 (octets read little-endian); the UDP
        // tag's low 16 bits are the buddy port, the high 16 reserved (oracle writes 0).
        let ip_tag = u32::from_le_bytes(Ipv4Addr::new(203, 0, 113, 7).octets());
        let decoded = DecodedHelloBuddy::from_tag_values(Some(ip_tag), Some(4672)).unwrap();
        assert_eq!(decoded.ip, Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(decoded.udp_port, 4672);

        // High 16 bits of the UDP tag are ignored (reserved).
        let decoded = DecodedHelloBuddy::from_tag_values(Some(ip_tag), Some(0xABCD_1234)).unwrap();
        assert_eq!(decoded.udp_port, 0x1234);

        // Missing either field, a zero IP, or a zero port yields no buddy.
        assert!(DecodedHelloBuddy::from_tag_values(None, Some(4672)).is_none());
        assert!(DecodedHelloBuddy::from_tag_values(Some(ip_tag), None).is_none());
        assert!(DecodedHelloBuddy::from_tag_values(Some(0), Some(4672)).is_none());
        assert!(DecodedHelloBuddy::from_tag_values(Some(ip_tag), Some(0)).is_none());
    }
}
