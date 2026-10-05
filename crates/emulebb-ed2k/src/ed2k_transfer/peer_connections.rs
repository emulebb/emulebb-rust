//! Process-local registry of live ED2K peer TCP connections.
//!
//! Upload admission must consider every client connection from an IP, not only
//! entries already present in the upload waiting list.  The registry is owned
//! by one transfer runtime and uses RAII guards so cancellation and error exits
//! cannot leak counts.

use std::{collections::HashMap, net::IpAddr, sync::Arc};

#[derive(Debug, Clone, Default)]
pub(super) struct Ed2kPeerConnectionRegistry {
    counts: Arc<parking_lot::Mutex<HashMap<IpAddr, usize>>>,
}

impl Ed2kPeerConnectionRegistry {
    pub(super) fn register(&self, ip: IpAddr) -> Ed2kPeerConnectionGuard {
        let mut counts = self.counts.lock();
        *counts.entry(ip).or_default() += 1;
        Ed2kPeerConnectionGuard {
            registry: self.clone(),
            ip,
        }
    }

    pub(super) fn count(&self, ip: IpAddr) -> usize {
        self.counts.lock().get(&ip).copied().unwrap_or_default()
    }
}

#[derive(Debug)]
pub(crate) struct Ed2kPeerConnectionGuard {
    registry: Ed2kPeerConnectionRegistry,
    ip: IpAddr,
}

impl Drop for Ed2kPeerConnectionGuard {
    fn drop(&mut self) {
        let mut counts = self.registry.counts.lock();
        let Some(count) = counts.get_mut(&self.ip) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&self.ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_tracks_and_releases_each_ip_independently() {
        let registry = Ed2kPeerConnectionRegistry::default();
        let first_ip: IpAddr = "198.51.100.7".parse().unwrap();
        let second_ip: IpAddr = "203.0.113.9".parse().unwrap();

        let first = registry.register(first_ip);
        let second = registry.register(first_ip);
        let other = registry.register(second_ip);
        assert_eq!(registry.count(first_ip), 2);
        assert_eq!(registry.count(second_ip), 1);

        drop(second);
        assert_eq!(registry.count(first_ip), 1);
        drop(first);
        drop(other);
        assert_eq!(registry.count(first_ip), 0);
        assert_eq!(registry.count(second_ip), 0);
    }
}
