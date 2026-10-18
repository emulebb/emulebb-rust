use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use crate::ban_store::BanStore;

const MAX_TRACKED_IPS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpErrorFloodOutcome {
    Disabled,
    Counted { count: u32 },
    Banned { count: u32 },
}

#[derive(Debug, Clone, Copy)]
struct TcpErrorWindow {
    first_seen: Instant,
    last_seen: Instant,
    count: u32,
}

#[derive(Debug)]
pub struct TcpErrorFloodTracker {
    enabled: bool,
    interval: Duration,
    threshold: u32,
    windows: Mutex<HashMap<Ipv4Addr, TcpErrorWindow>>,
}

impl TcpErrorFloodTracker {
    #[must_use]
    pub fn new(enabled: bool, interval: Duration, threshold: u32) -> Self {
        Self {
            enabled,
            interval: interval.max(Duration::from_secs(1)),
            threshold: threshold.max(1),
            windows: Mutex::new(HashMap::new()),
        }
    }

    pub fn record_error(&self, ip: Ipv4Addr, ban_store: &BanStore) -> TcpErrorFloodOutcome {
        self.record_error_at(ip, ban_store, Instant::now())
    }

    pub fn record_error_at(
        &self,
        ip: Ipv4Addr,
        ban_store: &BanStore,
        now: Instant,
    ) -> TcpErrorFloodOutcome {
        if !self.enabled || ip.is_unspecified() {
            return TcpErrorFloodOutcome::Disabled;
        }
        let mut windows = self.windows.lock();
        windows.retain(|_, window| now.saturating_duration_since(window.last_seen) < self.interval);
        if windows.len() >= MAX_TRACKED_IPS
            && !windows.contains_key(&ip)
            && let Some(oldest_ip) = windows
                .iter()
                .min_by_key(|(_, window)| window.last_seen)
                .map(|(ip, _)| *ip)
        {
            windows.remove(&oldest_ip);
        }
        let window = windows.entry(ip).or_insert(TcpErrorWindow {
            first_seen: now,
            last_seen: now,
            count: 0,
        });
        if now.saturating_duration_since(window.first_seen) >= self.interval {
            *window = TcpErrorWindow {
                first_seen: now,
                last_seen: now,
                count: 0,
            };
        }
        window.last_seen = now;
        window.count = window.count.saturating_add(1);
        let count = window.count;
        if count < self.threshold {
            return TcpErrorFloodOutcome::Counted { count };
        }
        windows.remove(&ip);
        drop(windows);
        ban_store.ban(Some(ip), None);
        TcpErrorFloodOutcome::Banned { count }
    }

    pub fn prune(&self) -> usize {
        self.prune_at(Instant::now())
    }

    pub fn prune_at(&self, now: Instant) -> usize {
        let mut windows = self.windows.lock();
        let before = windows.len();
        windows.retain(|_, window| now.saturating_duration_since(window.last_seen) < self.interval);
        before.saturating_sub(windows.len())
    }

    #[must_use]
    pub fn retained_count(&self) -> usize {
        self.windows.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_bans_ip_only_and_interval_resets_count() {
        let tracker = TcpErrorFloodTracker::new(true, Duration::from_secs(60), 3);
        let bans = BanStore::new();
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let now = Instant::now();

        assert_eq!(
            tracker.record_error_at(ip, &bans, now),
            TcpErrorFloodOutcome::Counted { count: 1 }
        );
        assert_eq!(
            tracker.record_error_at(ip, &bans, now + Duration::from_secs(61)),
            TcpErrorFloodOutcome::Counted { count: 1 }
        );
        assert_eq!(
            tracker.record_error_at(ip, &bans, now + Duration::from_secs(62)),
            TcpErrorFloodOutcome::Counted { count: 2 }
        );
        assert_eq!(
            tracker.record_error_at(ip, &bans, now + Duration::from_secs(63)),
            TcpErrorFloodOutcome::Banned { count: 3 }
        );
        assert!(bans.is_ip_banned(ip));
        assert!(!bans.is_hash_banned(&[0x44; 16]));
    }

    #[test]
    fn stale_windows_are_pruned_and_disabled_policy_does_not_track() {
        let bans = BanStore::new();
        let now = Instant::now();
        let tracker = TcpErrorFloodTracker::new(true, Duration::from_secs(10), 5);
        tracker.record_error_at(Ipv4Addr::LOCALHOST, &bans, now);
        assert_eq!(tracker.prune_at(now + Duration::from_secs(10)), 1);
        assert_eq!(tracker.retained_count(), 0);

        let disabled = TcpErrorFloodTracker::new(false, Duration::from_secs(10), 1);
        assert_eq!(
            disabled.record_error_at(Ipv4Addr::LOCALHOST, &bans, now),
            TcpErrorFloodOutcome::Disabled
        );
        assert_eq!(disabled.retained_count(), 0);
    }
}
