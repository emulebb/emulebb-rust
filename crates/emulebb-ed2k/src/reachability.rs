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
//!   material for client UDP (`EncryptSendClient`). Server and fallback probes
//!   own independent evidence slots; the server slot wins while present and can
//!   be invalidated without erasing a concurrently refreshed STUN/Kad value.
//! - **Ports**: a NAT/UPnP gateway may grant external ports different from the
//!   internal sockets; advertise the external port so peers/servers can reach us
//!   for incoming TCP + HighID callback (TCP) and locate us for UDP source-reask
//!   by `(ip, udp_port)` (UDP). [`advertised_tcp_port`]/[`advertised_udp_port`]
//!   return the learned external port when known, else the given internal port.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

#[derive(Debug, Default)]
struct ReachabilityInner {
    /// Server-observed public IPv4; `0` = no current server-session evidence.
    server_public_ip: AtomicU32,
    /// Independently probed public IPv4; `0` = no current fallback evidence.
    fallback_public_ip: AtomicU32,
    /// NAT-mapped eD2k TCP listener port; `0` = no current mapping.
    nat_mapped_tcp_port: AtomicU16,
    /// NAT-mapped eD2k UDP port; `0` = no current mapping.
    nat_mapped_udp_port: AtomicU16,
    /// Remotely-observed external UDP port from the Kad firewall check; `0` = no
    /// current peer confirmation. Kept separately so expiring stale verification
    /// can reveal, rather than destroy, a concurrently refreshed UPnP mapping.
    peer_confirmed_udp_port: AtomicU16,
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

    // --- Public IP evidence. ---

    /// Record public IPv4 evidence owned by the current server session.
    pub fn set_server_public_ip(&self, ip: Ipv4Addr) {
        self.inner
            .server_public_ip
            .store(u32::from(ip), Ordering::Relaxed);
    }

    /// Revoke only server-session evidence, preserving any independent fallback.
    pub fn clear_server_public_ip(&self) -> bool {
        self.inner.server_public_ip.swap(0, Ordering::Relaxed) != 0
    }

    /// Record or refresh public IPv4 evidence from STUN/Kad/peer observation.
    /// Returns whether the fallback value changed.
    pub fn set_fallback_public_ip(&self, ip: Ipv4Addr) -> bool {
        self.inner
            .fallback_public_ip
            .swap(u32::from(ip), Ordering::Relaxed)
            != u32::from(ip)
    }

    /// Current public IPv4, preferring live server evidence over fallback probes.
    pub fn get(&self) -> Option<Ipv4Addr> {
        let server = self.inner.server_public_ip.load(Ordering::Relaxed);
        if server != 0 {
            return Some(Ipv4Addr::from(server));
        }
        match self.inner.fallback_public_ip.load(Ordering::Relaxed) {
            0 => None,
            fallback => Some(Ipv4Addr::from(fallback)),
        }
    }

    /// Octets `a.b.c.d` for obfuscation key material; `[0,0,0,0]` when unknown.
    pub fn octets(&self) -> [u8; 4] {
        self.get().map_or([0, 0, 0, 0], |ip| ip.octets())
    }

    /// Whether a public IP is known (HighID established).
    pub fn is_known(&self) -> bool {
        self.get().is_some()
    }

    // --- Advertised external ports. ---

    /// Replace the current NAT-mapped eD2k TCP port snapshot.
    pub fn set_nat_mapped_tcp_port(&self, port: Option<u16>) {
        self.inner
            .nat_mapped_tcp_port
            .store(port.unwrap_or(0), Ordering::Relaxed);
    }

    /// Record the externally-reachable eD2k UDP port from the UPnP mapping. This
    /// local evidence is retained while a peer-confirmed value takes precedence,
    /// so it is available immediately if that remote verification expires.
    /// `None` revokes a mapping that disappeared from the latest NAT snapshot.
    pub fn set_nat_mapped_udp_port(&self, port: Option<u16>) {
        self.inner
            .nat_mapped_udp_port
            .store(port.unwrap_or(0), Ordering::Relaxed);
    }

    /// Record the externally-reachable eD2k/Kad UDP port confirmed by a remote
    /// peer during the Kad UDP firewall check. This is the most authoritative
    /// source and pins the value so the periodic UPnP sync cannot overwrite it.
    pub fn set_peer_confirmed_udp_port(&self, port: u16) {
        if port == 0 {
            return;
        }
        self.inner
            .peer_confirmed_udp_port
            .store(port, Ordering::Relaxed);
    }

    /// Revoke the remotely-confirmed UDP port while preserving any independent
    /// UPnP mapping learned in parallel. Returns whether a confirmation existed.
    pub fn clear_peer_confirmed_udp_port(&self) -> bool {
        self.inner
            .peer_confirmed_udp_port
            .swap(0, Ordering::Relaxed)
            != 0
    }

    /// Whether the external UDP port has been confirmed by a remote peer.
    #[must_use]
    pub fn udp_port_is_peer_confirmed(&self) -> bool {
        self.inner.peer_confirmed_udp_port.load(Ordering::Relaxed) != 0
    }

    /// The eD2k TCP port to advertise: the learned external port when known, else
    /// the given internal socket port (hello `tcp_port` / server login port).
    pub fn advertised_tcp_port(&self, internal_port: u16) -> u16 {
        match self.inner.nat_mapped_tcp_port.load(Ordering::Relaxed) {
            0 => internal_port,
            port => port,
        }
    }

    /// The eD2k UDP port to advertise: the learned external port when known, else
    /// the given internal socket port (`CT_EMULE_UDPPORTS` / `ET_UDPPORT`).
    pub fn advertised_udp_port(&self, internal_port: u16) -> u16 {
        let peer_confirmed = self.inner.peer_confirmed_udp_port.load(Ordering::Relaxed);
        if peer_confirmed != 0 {
            return peer_confirmed;
        }
        match self.inner.nat_mapped_udp_port.load(Ordering::Relaxed) {
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
    fn server_evidence_overrides_independently_refreshed_fallback() {
        let r = ExternalReachability::new();
        assert!(r.set_fallback_public_ip(Ipv4Addr::new(198, 51, 100, 1)));
        assert!(!r.set_fallback_public_ip(Ipv4Addr::new(198, 51, 100, 1)));
        assert_eq!(r.get(), Some(Ipv4Addr::new(198, 51, 100, 1)));
        r.set_server_public_ip(Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(r.octets(), [203, 0, 113, 9]);
        r.set_fallback_public_ip(Ipv4Addr::new(198, 51, 100, 2));
        assert_eq!(r.octets(), [203, 0, 113, 9]);
        assert!(r.clear_server_public_ip());
        assert_eq!(r.get(), Some(Ipv4Addr::new(198, 51, 100, 2)));
        assert!(!r.clear_server_public_ip());
    }

    #[test]
    fn ports_fall_back_to_internal_until_learned() {
        let r = ExternalReachability::new();
        assert_eq!(r.advertised_tcp_port(4662), 4662);
        assert_eq!(r.advertised_udp_port(4672), 4672);
        r.set_nat_mapped_tcp_port(Some(45000));
        r.set_nat_mapped_udp_port(Some(51000));
        assert_eq!(r.advertised_tcp_port(4662), 45000);
        assert_eq!(r.advertised_udp_port(4672), 51000);
        r.set_nat_mapped_udp_port(None);
        assert_eq!(r.advertised_udp_port(4672), 4672);
    }

    #[test]
    fn peer_confirmed_udp_port_takes_precedence_over_upnp() {
        let r = ExternalReachability::new();
        // UPnP-derived value applies while no peer confirmation is in force.
        r.set_nat_mapped_udp_port(Some(45000));
        assert_eq!(r.advertised_udp_port(4672), 45000);
        assert!(!r.udp_port_is_peer_confirmed());
        // A peer-confirmed port pins the value.
        r.set_peer_confirmed_udp_port(51000);
        assert!(r.udp_port_is_peer_confirmed());
        assert_eq!(r.advertised_udp_port(4672), 51000);
        // Subsequent UPnP syncs are retained but cannot supersede it.
        r.set_nat_mapped_udp_port(Some(46000));
        assert_eq!(r.advertised_udp_port(4672), 51000);
        // A zero peer confirmation is a no-op.
        r.set_peer_confirmed_udp_port(0);
        assert_eq!(r.advertised_udp_port(4672), 51000);
        // Expiring the peer evidence reveals the latest UPnP mapping.
        assert!(r.clear_peer_confirmed_udp_port());
        assert!(!r.udp_port_is_peer_confirmed());
        assert_eq!(r.advertised_udp_port(4672), 46000);
        assert!(!r.clear_peer_confirmed_udp_port());
    }

    #[test]
    fn clones_share_one_cell() {
        let a = ExternalReachability::new();
        let b = a.clone();
        a.set_server_public_ip(Ipv4Addr::new(192, 0, 2, 5));
        a.set_nat_mapped_udp_port(Some(40000));
        assert_eq!(b.get(), Some(Ipv4Addr::new(192, 0, 2, 5)));
        assert_eq!(b.advertised_udp_port(4672), 40000);
    }
}
