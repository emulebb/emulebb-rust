//! `ExternalReachability` — the single per-instance source of truth for how this
//! client is reachable from the outside: our public IPv4 and the externally-mapped
//! eD2k TCP + UDP ports. Read at send time by every hello/login-encode site, so a
//! value learned after startup (server `OP_IDCHANGE`, a STUN probe, a UPnP mapping
//! appearing or being remapped on lease renewal) is reflected in subsequent
//! advertisements without snapshotting it at startup.
//!
//! This consolidates the previously-scattered state (`SharedPublicIp` + the
//! process-wide advertised-port statics) that let the reask/HighID reachability
//! bugs slip in: a site could advertise an internal/stale value while the truth
//! lived elsewhere. One cheaply-clonable `Arc` cell, threaded where needed.
//!
//! Semantics mirror eMule:
//! - **Public IP** (`Emule.cpp` `GetPublicIP`/`SetPublicIP`): the obfuscation key
//!   material for client UDP (`EncryptSendClient`). The server-learned value is
//!   authoritative ([`set`]); STUN/Kad only fill it when unknown
//!   ([`set_if_unset`]); cleared on server disconnect/LowID ([`clear`]).
//! - **Ports**: a NAT/UPnP gateway may grant external ports different from the
//!   internal sockets; advertise the external port so peers/servers can reach us
//!   for incoming TCP + HighID callback (TCP) and locate us for UDP source-reask
//!   by `(ip, udp_port)` (UDP). [`advertised_tcp_port`]/[`advertised_udp_port`]
//!   return the learned external port when known, else the given internal port.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

#[derive(Debug, Default)]
struct ReachabilityInner {
    /// Public IPv4 as big-endian numeric `u32` (`u32::from(Ipv4Addr)`); `0` = unknown.
    public_ip: AtomicU32,
    /// Learned external eD2k TCP listener port; `0` = unknown / same as internal.
    external_tcp_port: AtomicU16,
    /// Learned external eD2k UDP port; `0` = unknown / same as internal.
    external_udp_port: AtomicU16,
    /// Whether the current external UDP port was confirmed by a remote peer (the
    /// Kad UDP firewall check). A peer-observed port is the most authoritative
    /// source for what the outside world actually sees, so once set it takes
    /// precedence over the locally-derived UPnP mapping (mirrors eMule preferring
    /// a firewall-check result over the gateway's announced external port).
    udp_port_peer_confirmed: AtomicBool,
}

/// Cheaply-clonable handle to this client's external reachability facts.
#[derive(Clone, Default, Debug)]
pub struct ExternalReachability {
    inner: Arc<ReachabilityInner>,
}

impl ExternalReachability {
    pub fn new() -> Self {
        Self::default()
    }

    // --- Public IP (eMule SetPublicIP / GetPublicIP); names kept identical to the
    // former SharedPublicIp so call sites are a pure type migration. ---

    /// Record a learned public IPv4 (eMule `SetPublicIP`); the server `OP_IDCHANGE`
    /// path always overrides. Callers pass a HighID address.
    pub fn set(&self, ip: Ipv4Addr) {
        self.inner.public_ip.store(u32::from(ip), Ordering::Relaxed);
    }

    /// Record a public IPv4 only if currently unknown — the STUN/Kad/peer-reported
    /// fallback (eMule `if GetPublicIP()==0 ... SetPublicIP`). Returns whether applied.
    pub fn set_if_unset(&self, ip: Ipv4Addr) -> bool {
        self.inner
            .public_ip
            .compare_exchange(0, u32::from(ip), Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Clear the cached public IP (eMule `SetPublicIP(0)`; e.g. on server disconnect).
    pub fn clear(&self) {
        self.inner.public_ip.store(0, Ordering::Relaxed);
    }

    /// Current public IPv4, or `None` if unknown (eMule `GetPublicIP() == 0`).
    pub fn get(&self) -> Option<Ipv4Addr> {
        match self.inner.public_ip.load(Ordering::Relaxed) {
            0 => None,
            bits => Some(Ipv4Addr::from(bits)),
        }
    }

    /// Octets `a.b.c.d` for obfuscation key material; `[0,0,0,0]` when unknown.
    pub fn octets(&self) -> [u8; 4] {
        self.get().map_or([0, 0, 0, 0], |ip| ip.octets())
    }

    /// Whether a public IP is known (HighID established).
    pub fn is_known(&self) -> bool {
        self.inner.public_ip.load(Ordering::Relaxed) != 0
    }

    // --- Advertised external ports. ---

    /// Record the externally-reachable eD2k TCP port (UPnP-granted). `0` clears.
    pub fn set_external_tcp_port(&self, port: u16) {
        self.inner.external_tcp_port.store(port, Ordering::Relaxed);
    }

    /// Record the externally-reachable eD2k UDP port from the UPnP mapping. This
    /// is the local/derived source, so it must not clobber a port that a remote
    /// peer already confirmed via the Kad UDP firewall check. `0` clears (only
    /// when no peer confirmation is in force).
    pub fn set_external_udp_port(&self, port: u16) {
        if self.inner.udp_port_peer_confirmed.load(Ordering::Relaxed) {
            return;
        }
        self.inner.external_udp_port.store(port, Ordering::Relaxed);
    }

    /// Record the externally-reachable eD2k/Kad UDP port confirmed by a remote
    /// peer during the Kad UDP firewall check. This is the most authoritative
    /// source and pins the value so the periodic UPnP sync cannot overwrite it.
    pub fn set_peer_confirmed_udp_port(&self, port: u16) {
        if port == 0 {
            return;
        }
        self.inner.external_udp_port.store(port, Ordering::Relaxed);
        self.inner
            .udp_port_peer_confirmed
            .store(true, Ordering::Relaxed);
    }

    /// Whether the external UDP port has been confirmed by a remote peer.
    #[must_use]
    pub fn udp_port_is_peer_confirmed(&self) -> bool {
        self.inner.udp_port_peer_confirmed.load(Ordering::Relaxed)
    }

    /// The eD2k TCP port to advertise: the learned external port when known, else
    /// the given internal socket port (hello `tcp_port` / server login port).
    pub fn advertised_tcp_port(&self, internal_port: u16) -> u16 {
        match self.inner.external_tcp_port.load(Ordering::Relaxed) {
            0 => internal_port,
            port => port,
        }
    }

    /// The eD2k UDP port to advertise: the learned external port when known, else
    /// the given internal socket port (`CT_EMULE_UDPPORTS` / `ET_UDPPORT`).
    pub fn advertised_udp_port(&self, internal_port: u16) -> u16 {
        match self.inner.external_udp_port.load(Ordering::Relaxed) {
            0 => internal_port,
            port => port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ip_unknown_by_default() {
        let r = ExternalReachability::new();
        assert!(!r.is_known());
        assert_eq!(r.get(), None);
        assert_eq!(r.octets(), [0, 0, 0, 0]);
    }

    #[test]
    fn server_path_overrides_but_fallback_only_fills_unset() {
        let r = ExternalReachability::new();
        assert!(r.set_if_unset(Ipv4Addr::new(198, 51, 100, 1)));
        assert!(!r.set_if_unset(Ipv4Addr::new(198, 51, 100, 2)));
        assert_eq!(r.get(), Some(Ipv4Addr::new(198, 51, 100, 1)));
        r.set(Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(r.octets(), [203, 0, 113, 9]);
        r.clear();
        assert!(!r.is_known());
    }

    #[test]
    fn ports_fall_back_to_internal_until_learned() {
        let r = ExternalReachability::new();
        assert_eq!(r.advertised_tcp_port(4662), 4662);
        assert_eq!(r.advertised_udp_port(4672), 4672);
        r.set_external_tcp_port(45000);
        r.set_external_udp_port(51000);
        assert_eq!(r.advertised_tcp_port(4662), 45000);
        assert_eq!(r.advertised_udp_port(4672), 51000);
        r.set_external_udp_port(0);
        assert_eq!(r.advertised_udp_port(4672), 4672);
    }

    #[test]
    fn peer_confirmed_udp_port_takes_precedence_over_upnp() {
        let r = ExternalReachability::new();
        // UPnP-derived value applies while no peer confirmation is in force.
        r.set_external_udp_port(45000);
        assert_eq!(r.advertised_udp_port(4672), 45000);
        assert!(!r.udp_port_is_peer_confirmed());
        // A peer-confirmed port pins the value.
        r.set_peer_confirmed_udp_port(51000);
        assert!(r.udp_port_is_peer_confirmed());
        assert_eq!(r.advertised_udp_port(4672), 51000);
        // Subsequent UPnP syncs (including a clear) must not clobber it.
        r.set_external_udp_port(46000);
        r.set_external_udp_port(0);
        assert_eq!(r.advertised_udp_port(4672), 51000);
        // A zero peer confirmation is a no-op.
        r.set_peer_confirmed_udp_port(0);
        assert_eq!(r.advertised_udp_port(4672), 51000);
    }

    #[test]
    fn clones_share_one_cell() {
        let a = ExternalReachability::new();
        let b = a.clone();
        a.set(Ipv4Addr::new(192, 0, 2, 5));
        a.set_external_udp_port(40000);
        assert_eq!(b.get(), Some(Ipv4Addr::new(192, 0, 2, 5)));
        assert_eq!(b.advertised_udp_port(4672), 40000);
    }
}
