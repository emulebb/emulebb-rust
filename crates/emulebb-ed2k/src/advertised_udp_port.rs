//! Process-wide "advertised external eD2k UDP port" — the port rust publishes in
//! `CT_EMULE_UDPPORTS` / `ET_UDPPORT` so peers can locate us for UDP source-reask.
//!
//! eMule advertises the *externally reachable* UDP port, not the raw local socket
//! port: behind a NAT/UPnP gateway the external port can differ from the internal
//! one (the gateway may remap it). A peer answers an `OP_REASKFILEPING` only when
//! it can locate the sender in its upload queue by `(ip, udp_port)`
//! (`GetWaitingClientByIP_UDP`), matching the reask datagram's *source port*
//! (which the gateway rewrites to the external port) against the UDP port we
//! advertised. If we advertise the internal port but the gateway remapped it, the
//! match fails and the peer stays silent — the reask "no ack" symptom.
//!
//! This cell holds the learned external UDP port (`0` == unknown / not remapped).
//! Core sets it after NAT setup (from the UPnP-granted external port) and may
//! refine it from the Kad firewall-check discovered port (what peers actually
//! observed). The hello-encode sites read [`advertised_udp_port`], which returns
//! the external port when known and otherwise falls back to the internal port.
//!
//! Process-wide (an `AtomicU16`), mirroring [`super::ed2k_tcp::set_publish_rust_identity`]:
//! the value is read lazily when each hello is encoded, so an update after NAT
//! setup is picked up by subsequent hellos without threading it through every
//! listener/connector/server option struct.

use std::sync::atomic::{AtomicU16, Ordering};

/// Learned external eD2k UDP port (`0` == unknown / same as internal).
static ADVERTISED_EXTERNAL_UDP_PORT: AtomicU16 = AtomicU16::new(0);

/// Record the externally-reachable eD2k UDP port (UPnP-granted external port, or
/// the Kad-discovered external port). Pass `0` to clear (e.g. NAT mapping lost).
pub fn set_advertised_external_udp_port(port: u16) {
    ADVERTISED_EXTERNAL_UDP_PORT.store(port, Ordering::Relaxed);
}

/// The currently-known external eD2k UDP port, or `None` when unknown.
pub fn advertised_external_udp_port() -> Option<u16> {
    match ADVERTISED_EXTERNAL_UDP_PORT.load(Ordering::Relaxed) {
        0 => None,
        port => Some(port),
    }
}

/// The eD2k UDP port to advertise: the learned external port when known, else the
/// given internal socket port. This is what every `CT_EMULE_UDPPORTS` /
/// `ET_UDPPORT` hello-encode site should publish.
pub fn advertised_udp_port(internal_port: u16) -> u16 {
    advertised_external_udp_port().unwrap_or(internal_port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The cell is process-wide; serialize the tests that mutate it.
    static GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn falls_back_to_internal_when_unknown() {
        let _g = GUARD.lock().unwrap();
        set_advertised_external_udp_port(0);
        assert_eq!(advertised_external_udp_port(), None);
        assert_eq!(advertised_udp_port(4672), 4672);
    }

    #[test]
    fn external_port_overrides_internal() {
        let _g = GUARD.lock().unwrap();
        set_advertised_external_udp_port(51000);
        assert_eq!(advertised_external_udp_port(), Some(51000));
        // Even when the gateway remapped to a different external port, that is
        // what we advertise so peers match our reask source port.
        assert_eq!(advertised_udp_port(4672), 51000);
        set_advertised_external_udp_port(0); // reset for other tests
    }
}
