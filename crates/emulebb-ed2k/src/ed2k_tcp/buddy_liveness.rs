use std::time::Duration;

use tokio::time::Instant;

pub(super) const BUDDY_PING_INTERVAL: Duration = Duration::from_secs(10 * 60);
pub(super) const BUDDY_RECEIVE_TIMEOUT: Duration = Duration::from_secs(25 * 60);

#[derive(Debug, Clone, Copy)]
pub(super) struct BuddyLiveness {
    last_received_at: Instant,
    next_ping_at: Instant,
}

impl BuddyLiveness {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            last_received_at: now,
            next_ping_at: now + BUDDY_PING_INTERVAL,
        }
    }

    pub(super) fn receive_deadline(self) -> Instant {
        self.last_received_at + BUDDY_RECEIVE_TIMEOUT
    }

    pub(super) fn next_ping_at(self) -> Instant {
        self.next_ping_at
    }

    pub(super) fn record_received(&mut self, now: Instant) {
        self.last_received_at = now;
    }

    pub(super) fn record_ping_sent(&mut self, now: Instant) {
        self.next_ping_at = now + BUDDY_PING_INTERVAL;
    }

    pub(super) fn record_keepalive_received(&mut self, now: Instant) {
        self.record_received(now);
        self.next_ping_at = now + BUDDY_PING_INTERVAL;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outgoing_pings_do_not_extend_receive_liveness() {
        let start = Instant::now();
        let mut liveness = BuddyLiveness::new(start);
        liveness.record_ping_sent(start + BUDDY_PING_INTERVAL);
        assert_eq!(liveness.receive_deadline(), start + BUDDY_RECEIVE_TIMEOUT);
        assert_eq!(
            liveness.next_ping_at(),
            start + BUDDY_PING_INTERVAL + BUDDY_PING_INTERVAL
        );
    }

    #[test]
    fn received_activity_refreshes_only_the_receive_deadline() {
        let start = Instant::now();
        let mut liveness = BuddyLiveness::new(start);
        let received_at = start + Duration::from_secs(4 * 60);
        liveness.record_received(received_at);
        assert_eq!(
            liveness.receive_deadline(),
            received_at + BUDDY_RECEIVE_TIMEOUT
        );
        assert_eq!(liveness.next_ping_at(), start + BUDDY_PING_INTERVAL);
    }

    #[test]
    fn keepalive_activity_refreshes_and_defers_the_next_ping() {
        let start = Instant::now();
        let mut liveness = BuddyLiveness::new(start);
        let received_at = start + Duration::from_secs(4 * 60);
        liveness.record_keepalive_received(received_at);
        assert_eq!(
            liveness.receive_deadline(),
            received_at + BUDDY_RECEIVE_TIMEOUT
        );
        assert_eq!(liveness.next_ping_at(), received_at + BUDDY_PING_INTERVAL);
    }
}
