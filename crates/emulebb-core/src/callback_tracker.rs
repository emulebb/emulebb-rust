//! Per-IP rate limiter for inbound `OP_DIRECTCALLBACKREQ` (the request a peer
//! that cannot reach us over TCP sends so we — the firewalled LowID side —
//! connect out to it).
//!
//! The oracle accepts at most one direct-callback request per source IP per
//! 180 seconds: `CClientList::AllowCalbackRequest` refuses when a tracked entry
//! for that IP is still within the window, and `AddTrackCallbackRequests`
//! records an accepted request while evicting entries older than the window
//! (`ClientList.cpp:1089-1106`, gated in `ClientUDPSocket.cpp:431-437`). Without
//! this, repeat/spam requests each spawn a connect-out the oracle suppresses.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Oracle window: `SEC2MS(180)` (`ClientList.cpp:1093,1102`).
const DIRECT_CALLBACK_WINDOW: Duration = Duration::from_secs(180);

/// Tracks recently-accepted direct-callback source IPs so repeats within the
/// 180-second window are suppressed. Interior mutability so the reask re-engage
/// context can share one instance behind an `Arc` across event handlers.
#[derive(Default)]
pub(crate) struct DirectCallbackRateLimiter {
    /// Newest-first, mirroring the oracle `AddHead` list; each entry is the
    /// accepted source IP and the instant it was tracked.
    entries: Mutex<VecDeque<(Ipv4Addr, Instant)>>,
}

impl DirectCallbackRateLimiter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Whether a direct-callback request from `ip` may be acted on now (oracle
    /// `AllowCalbackRequest`): refuse while a tracked entry for the same IP is
    /// still within the 180s window.
    pub(crate) fn allow(&self, ip: Ipv4Addr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    /// Record an accepted request from `ip` (oracle `AddTrackCallbackRequests`),
    /// pruning entries older than the window as the oracle does on insert.
    pub(crate) fn track(&self, ip: Ipv4Addr) {
        self.track_at(ip, Instant::now());
    }

    fn allow_at(&self, ip: Ipv4Addr, now: Instant) -> bool {
        let entries = self
            .entries
            .lock()
            .expect("direct-callback tracker poisoned");
        !entries.iter().any(|(entry_ip, at)| {
            *entry_ip == ip && now.saturating_duration_since(*at) < DIRECT_CALLBACK_WINDOW
        })
    }

    fn track_at(&self, ip: Ipv4Addr, now: Instant) {
        let mut entries = self
            .entries
            .lock()
            .expect("direct-callback tracker poisoned");
        entries.push_front((ip, now));
        // Oracle removes tail entries whose age has reached the window.
        while let Some((_, at)) = entries.back() {
            if now.saturating_duration_since(*at) >= DIRECT_CALLBACK_WINDOW {
                entries.pop_back();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    #[test]
    fn first_request_allowed_repeat_within_window_suppressed() {
        let limiter = DirectCallbackRateLimiter::new();
        let base = Instant::now();
        // First request from an IP is allowed, then tracked.
        assert!(limiter.allow_at(ip(1), base));
        limiter.track_at(ip(1), base);
        // A second request from the same IP within 180s is suppressed.
        assert!(!limiter.allow_at(ip(1), base + Duration::from_secs(1)));
        assert!(!limiter.allow_at(ip(1), base + Duration::from_secs(179)));
    }

    #[test]
    fn request_allowed_again_after_window_elapses() {
        let limiter = DirectCallbackRateLimiter::new();
        let base = Instant::now();
        limiter.track_at(ip(1), base);
        // At/after the 180s window the IP is allowed again (oracle: entry expired).
        assert!(limiter.allow_at(ip(1), base + Duration::from_secs(180)));
        assert!(limiter.allow_at(ip(1), base + Duration::from_secs(181)));
    }

    #[test]
    fn distinct_ips_are_tracked_independently() {
        let limiter = DirectCallbackRateLimiter::new();
        let base = Instant::now();
        limiter.track_at(ip(1), base);
        // A different IP is unaffected by the first IP's tracked entry.
        assert!(limiter.allow_at(ip(2), base + Duration::from_secs(1)));
    }

    #[test]
    fn tracking_prunes_entries_older_than_the_window() {
        let limiter = DirectCallbackRateLimiter::new();
        let base = Instant::now();
        limiter.track_at(ip(1), base);
        // A later insert past the window evicts the stale entry, so the first IP
        // is allowed again.
        limiter.track_at(ip(2), base + Duration::from_secs(181));
        assert_eq!(limiter.entries.lock().unwrap().len(), 1);
        assert!(limiter.allow_at(ip(1), base + Duration::from_secs(181)));
    }
}
