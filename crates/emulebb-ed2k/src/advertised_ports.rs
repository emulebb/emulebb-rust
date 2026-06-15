//! Process-wide "advertised external eD2k ports" (TCP + UDP) — the ports rust
//! publishes so peers/servers can reach us, read at hello-encode time.
//!
//! eMule advertises the *externally reachable* ports, not the raw local socket
//! ports: behind a NAT/UPnP gateway the external port can differ from the internal
//! one (the gateway may remap it).
//!
//! * **UDP** (`CT_EMULE_UDPPORTS` / `ET_UDPPORT`): a peer answers an
//!   `OP_REASKFILEPING` only when it can locate the sender in its upload queue by
//!   `(ip, udp_port)` (`GetWaitingClientByIP_UDP`), matching the reask datagram's
//!   *source port* (which the gateway rewrites to the external port) against the
//!   UDP port we advertised. Advertise the internal port under a remap and the
//!   match fails -> the peer stays silent (the reask "no ack" symptom).
//! * **TCP** (hello `tcp_port` / server `OP_LOGINREQUEST`): a peer/server reaches
//!   us for incoming connections and the server's HighID callback on the port we
//!   advertised. Advertise the internal port under a remap and incoming connects
//!   and HighID fail.
//!
//! Each cell holds the learned external port (`0` == unknown / not remapped). Core
//! syncs them from the live NAT mapping ([`super::nat`]'s `external_addr`). The
//! hello-encode sites read [`advertised_tcp_port`] / [`advertised_udp_port`],
//! which return the external port when known and otherwise fall back to the given
//! internal port.
//!
//! Process-wide (`AtomicU16`s), mirroring [`super::ed2k_tcp::set_publish_rust_identity`]:
//! read lazily when each hello is encoded, so an update after NAT setup (or a
//! lease-renewal remap) is picked up by subsequent hellos without threading it
//! through every listener/connector/server option struct.
//!
//! NOTE: listener/server hello identities are currently captured once at startup,
//! so they only pick up an external port that was known by then; the per-download
//! connector hello and the per-connection listener override read these cells
//! dynamically. A single reachability source-of-truth read uniformly at send time
//! (plus a Kad/STUN public-IP fallback, eMule `GetPublicIP`) is the planned
//! consolidation.

use std::sync::atomic::{AtomicU16, Ordering};

/// Learned external eD2k TCP listener port (`0` == unknown / same as internal).
static ADVERTISED_EXTERNAL_TCP_PORT: AtomicU16 = AtomicU16::new(0);
/// Learned external eD2k UDP port (`0` == unknown / same as internal).
static ADVERTISED_EXTERNAL_UDP_PORT: AtomicU16 = AtomicU16::new(0);

/// Record the externally-reachable eD2k TCP port (UPnP-granted external port).
/// Pass `0` to clear (e.g. NAT mapping lost).
pub fn set_advertised_external_tcp_port(port: u16) {
    ADVERTISED_EXTERNAL_TCP_PORT.store(port, Ordering::Relaxed);
}

/// Record the externally-reachable eD2k UDP port (UPnP-granted external port, or
/// the Kad-discovered external port). Pass `0` to clear (e.g. NAT mapping lost).
pub fn set_advertised_external_udp_port(port: u16) {
    ADVERTISED_EXTERNAL_UDP_PORT.store(port, Ordering::Relaxed);
}

/// The currently-known external eD2k TCP port, or `None` when unknown.
pub fn advertised_external_tcp_port() -> Option<u16> {
    match ADVERTISED_EXTERNAL_TCP_PORT.load(Ordering::Relaxed) {
        0 => None,
        port => Some(port),
    }
}

/// The currently-known external eD2k UDP port, or `None` when unknown.
pub fn advertised_external_udp_port() -> Option<u16> {
    match ADVERTISED_EXTERNAL_UDP_PORT.load(Ordering::Relaxed) {
        0 => None,
        port => Some(port),
    }
}

/// The eD2k TCP port to advertise: the learned external port when known, else the
/// given internal socket port. Used by every hello `tcp_port` / login-port site.
pub fn advertised_tcp_port(internal_port: u16) -> u16 {
    advertised_external_tcp_port().unwrap_or(internal_port)
}

/// The eD2k UDP port to advertise: the learned external port when known, else the
/// given internal socket port. Used by every `CT_EMULE_UDPPORTS` / `ET_UDPPORT`
/// hello-encode site.
pub fn advertised_udp_port(internal_port: u16) -> u16 {
    advertised_external_udp_port().unwrap_or(internal_port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The cells are process-wide; serialize the tests that mutate them.
    static GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn udp_falls_back_to_internal_when_unknown() {
        let _g = GUARD.lock().unwrap();
        set_advertised_external_udp_port(0);
        assert_eq!(advertised_external_udp_port(), None);
        assert_eq!(advertised_udp_port(4672), 4672);
    }

    #[test]
    fn udp_external_port_overrides_internal() {
        let _g = GUARD.lock().unwrap();
        set_advertised_external_udp_port(51000);
        assert_eq!(advertised_external_udp_port(), Some(51000));
        // Even when the gateway remapped to a different external port, that is
        // what we advertise so peers match our reask source port.
        assert_eq!(advertised_udp_port(4672), 51000);
        set_advertised_external_udp_port(0); // reset for other tests
    }

    #[test]
    fn tcp_falls_back_to_internal_when_unknown() {
        let _g = GUARD.lock().unwrap();
        set_advertised_external_tcp_port(0);
        assert_eq!(advertised_external_tcp_port(), None);
        assert_eq!(advertised_tcp_port(4662), 4662);
    }

    #[test]
    fn tcp_external_port_overrides_internal() {
        let _g = GUARD.lock().unwrap();
        set_advertised_external_tcp_port(45000);
        assert_eq!(advertised_external_tcp_port(), Some(45000));
        assert_eq!(advertised_tcp_port(4662), 45000);
        set_advertised_external_tcp_port(0); // reset for other tests
    }
}
