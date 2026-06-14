//! Shared public-IP cell mirroring eMule's `theApp.GetPublicIP()` /
//! `SetPublicIP()` (`Emule.cpp`).
//!
//! The eD2k client's own public IPv4 (HighID) is learned at runtime — primarily
//! from the server `OP_IDCHANGE` (the HighID `client_id` *is* our public IP), and
//! eMule also accepts a server-reported IP and a first peer-reported IP — and is
//! cleared on server disconnect. It is required as obfuscation key material for
//! client-to-client UDP reask (`EncryptedDatagramSocket` keys on
//! `theApp.GetPublicIP()`), and is generally useful wherever our external
//! address is needed.
//!
//! eMule's `GetPublicIP()` falls back to Kad's external IP when the cached value
//! is 0 and Kad is connected; rust's Kad does not yet surface an external IP, so
//! that fallback is a future enhancement (the primary server path is the HighID
//! case the reask transport needs). Cheap to clone (`Arc<AtomicU32>`); `0` means
//! unknown.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// A cheaply-clonable handle to the learned public IPv4 (`0` == unknown), shared
/// between the eD2k server session (which sets it) and consumers like the UDP
/// reask loop (which reads it).
#[derive(Clone, Default, Debug)]
pub struct SharedPublicIp {
    /// IPv4 as the big-endian numeric `u32` (`u32::from(Ipv4Addr)`); `0` = unknown.
    bits: Arc<AtomicU32>,
}

impl SharedPublicIp {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a learned public IPv4 (eMule `SetPublicIP`). Callers pass a HighID
    /// address; the server `OP_IDCHANGE` path always overrides.
    pub fn set(&self, ip: Ipv4Addr) {
        self.bits.store(u32::from(ip), Ordering::Relaxed);
    }

    /// Record a public IPv4 only if currently unknown — eMule's peer-reported
    /// path (`if GetPublicIP() == 0 && !IsLowID(dwIP) SetPublicIP(dwIP)`).
    /// Returns whether it was applied.
    pub fn set_if_unset(&self, ip: Ipv4Addr) -> bool {
        self.bits
            .compare_exchange(0, u32::from(ip), Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Clear the cached public IP (eMule `SetPublicIP(0)`; e.g. on server
    /// disconnect).
    pub fn clear(&self) {
        self.bits.store(0, Ordering::Relaxed);
    }

    /// Current public IPv4, or `None` if unknown (eMule `GetPublicIP() == 0`).
    pub fn get(&self) -> Option<Ipv4Addr> {
        match self.bits.load(Ordering::Relaxed) {
            0 => None,
            bits => Some(Ipv4Addr::from(bits)),
        }
    }

    /// Octets `a.b.c.d` for obfuscation key material; `[0,0,0,0]` when unknown
    /// (the reask loop must not send obfuscated reasks until this is known).
    pub fn octets(&self) -> [u8; 4] {
        self.get().map_or([0, 0, 0, 0], |ip| ip.octets())
    }

    /// Whether a public IP is known (HighID established).
    pub fn is_known(&self) -> bool {
        self.bits.load(Ordering::Relaxed) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_by_default() {
        let p = SharedPublicIp::new();
        assert!(!p.is_known());
        assert_eq!(p.get(), None);
        assert_eq!(p.octets(), [0, 0, 0, 0]);
    }

    #[test]
    fn set_and_read_octets_in_wire_order() {
        let p = SharedPublicIp::new();
        p.set(Ipv4Addr::new(203, 0, 113, 7));
        assert!(p.is_known());
        assert_eq!(p.get(), Some(Ipv4Addr::new(203, 0, 113, 7)));
        // Octets are a.b.c.d (the order the obfuscation key material expects).
        assert_eq!(p.octets(), [203, 0, 113, 7]);
    }

    #[test]
    fn server_path_overrides_but_peer_path_only_fills_unset() {
        let p = SharedPublicIp::new();
        // Peer-reported fills when unknown.
        assert!(p.set_if_unset(Ipv4Addr::new(198, 51, 100, 1)));
        assert_eq!(p.get(), Some(Ipv4Addr::new(198, 51, 100, 1)));
        // Peer-reported does NOT override a known value.
        assert!(!p.set_if_unset(Ipv4Addr::new(198, 51, 100, 2)));
        assert_eq!(p.get(), Some(Ipv4Addr::new(198, 51, 100, 1)));
        // The server OP_IDCHANGE path always overrides.
        p.set(Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(p.get(), Some(Ipv4Addr::new(203, 0, 113, 9)));
    }

    #[test]
    fn clear_resets_to_unknown() {
        let p = SharedPublicIp::new();
        p.set(Ipv4Addr::new(203, 0, 113, 7));
        p.clear();
        assert!(!p.is_known());
        assert_eq!(p.get(), None);
    }

    #[test]
    fn clones_share_one_cell() {
        let a = SharedPublicIp::new();
        let b = a.clone();
        a.set(Ipv4Addr::new(192, 0, 2, 5));
        // The clone observes the same underlying value.
        assert_eq!(b.get(), Some(Ipv4Addr::new(192, 0, 2, 5)));
        b.clear();
        assert_eq!(a.get(), None);
    }
}
