//! Keep a candidate's UDP path untouched until its unsolicited probe completes.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::NetError;

use super::{RpcInner, RpcManager};

const RECENT_UDP_WINDOW: Duration = Duration::from_secs(180);
const MAX_RECENT_UDP_DESTINATIONS: usize = 16_384;

#[derive(Default)]
pub(super) struct RecentUdp {
    destinations: HashMap<IpAddr, Instant>,
    reservations: HashSet<IpAddr>,
    overflowed_at: Option<Instant>,
}

impl RecentUdp {
    pub(super) fn record_send(&mut self, ip: IpAddr) -> Result<(), NetError> {
        if self.reservations.contains(&ip) {
            return Err(NetError::FirewallTesterReserved(ip));
        }
        let now = Instant::now();
        if let Some(sent_at) = self.destinations.get_mut(&ip) {
            *sent_at = now;
        } else if self.destinations.len() < MAX_RECENT_UDP_DESTINATIONS {
            self.destinations.insert(ip, now);
        } else {
            // WHY: after dropping history no candidate can be proven fresh.
            // Keep ordinary traffic moving and decline tests for one window.
            self.overflowed_at = Some(now);
        }
        Ok(())
    }

    pub(super) fn prune(&mut self) {
        self.destinations
            .retain(|_, sent_at| sent_at.elapsed() < RECENT_UDP_WINDOW);
    }

    fn reserve(&mut self, ip: IpAddr) -> bool {
        if self
            .overflowed_at
            .is_some_and(|time| time.elapsed() < RECENT_UDP_WINDOW)
            || self
                .destinations
                .get(&ip)
                .is_some_and(|time| time.elapsed() < RECENT_UDP_WINDOW)
        {
            return false;
        }
        self.reservations.insert(ip)
    }
}

/// Holds an IPv4 peer out of outbound UDP until a firewall check completes.
pub struct KadUdpProbeReservation {
    inner: Arc<RpcInner>,
    ip: IpAddr,
}

impl Drop for KadUdpProbeReservation {
    fn drop(&mut self) {
        self.inner.recent_udp.lock().reservations.remove(&self.ip);
    }
}

impl RpcManager {
    /// Reserve an IP only if no UDP was sent there during the recent window.
    pub fn reserve_fresh_udp_probe(&self, ip: IpAddr) -> Option<KadUdpProbeReservation> {
        self.inner
            .recent_udp
            .lock()
            .reserve(ip)
            .then(|| KadUdpProbeReservation {
                inner: Arc::clone(&self.inner),
                ip,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_fresh_ip_can_be_held_out_of_udp() {
        let known = "192.0.2.1".parse().unwrap();
        let fresh = "192.0.2.2".parse().unwrap();
        let mut traffic = RecentUdp::default();
        traffic.record_send(known).unwrap();
        assert!(!traffic.reserve(known));
        assert!(traffic.reserve(fresh));
        assert!(matches!(
            traffic.record_send(fresh),
            Err(NetError::FirewallTesterReserved(_))
        ));
        assert!(!traffic.reserve(fresh));
    }
}
