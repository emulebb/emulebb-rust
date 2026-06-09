use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Tracks incoming Kad request counts per IP and opcode family to detect flooding.
///
/// This mirrors the oracle `PacketTracking.cpp` intent more closely than a
/// generic packet-per-IP limiter: only request families are throttled here,
/// while reply validation is handled by [`OutboundRequestTracker`].
pub struct PacketTracker {
    /// (packet_count, window_start)
    counts: HashMap<PacketTrackerKey, (u32, Instant)>,
    limits: HashMap<PacketTrackerBucket, PacketTrackerLimit>,
    default_limit: PacketTrackerLimit,
}

/// Flood-tracking key for one inbound packet family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketTrackerKey {
    /// Source IP that owns this budget.
    pub ip: IpAddr,
    /// Kad packet family that owns this budget.
    pub bucket: PacketTrackerBucket,
}

/// Inbound Kad request family with distinct oracle-shaped rate limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketTrackerBucket {
    /// `KADEMLIA2_BOOTSTRAP_REQ`.
    BootstrapReq,
    /// `KADEMLIA2_HELLO_REQ`.
    HelloReq,
    /// `KADEMLIA2_REQ`.
    FindNodeReq,
    /// Search request families share the oracle 3/min budget.
    SearchReq,
    /// Keyword publish requests use the eMule 4/min budget.
    PublishKeyReq,
    /// Source publish requests use the eMule 3/min budget.
    PublishSourceReq,
    /// Notes publish requests use the eMule 2/min budget.
    PublishNotesReq,
    /// Firewall-check requests share the oracle 2/min budget.
    FirewalledReq,
    /// Buddy lookup requests share the oracle 2/min budget.
    FindBuddyReq,
    /// Callback requests use the oracle 1/min budget.
    CallbackReq,
    /// Ping requests use the oracle 2/min budget.
    PingReq,
    /// Search responses keep the relaxed harvest budget used by the current runtime.
    SearchRes,
    /// Fallback bucket for any packet family not classified explicitly.
    Default,
}

impl PacketTrackerBucket {
    /// Stable human-readable label used in logs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::BootstrapReq => "bootstrap_req",
            Self::HelloReq => "hello_req",
            Self::FindNodeReq => "find_node_req",
            Self::SearchReq => "search_req",
            Self::PublishKeyReq => "publish_key_req",
            Self::PublishSourceReq => "publish_source_req",
            Self::PublishNotesReq => "publish_notes_req",
            Self::FirewalledReq => "firewalled_req",
            Self::FindBuddyReq => "find_buddy_req",
            Self::CallbackReq => "callback_req",
            Self::PingReq => "ping_req",
            Self::Default => "default",
            Self::SearchRes => "search_res",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PacketTrackerLimit {
    max_packets: u32,
    window: Duration,
}

impl PacketTrackerLimit {
    fn new(max_packets: u32, window: Duration) -> Self {
        Self {
            max_packets,
            window,
        }
    }
}

/// Result of recording one inbound Kad packet against a tracker bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketTrackerDecision {
    /// Oracle-shaped action for this packet after applying the current bucket budget.
    pub action: PacketTrackerAction,
    /// Whether the packet is still within the bucket's configured budget.
    pub allowed: bool,
    /// Number of packets observed for this bucket within the active window.
    pub observed_packets: u32,
    /// Maximum packets allowed for this bucket within the active window.
    pub max_packets: u32,
    /// Active rate-limit window used for the bucket.
    pub window: Duration,
}

/// Oracle-shaped disposition for one inbound tracked packet.
///
/// eMule uses a three-state return code in `PacketTracking.cpp`:
/// allow, ordinary flood drop, and massive-flood drop with higher punishment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketTrackerAction {
    /// The packet stays within the configured per-bucket budget.
    Allow,
    /// The packet exceeded the ordinary bucket budget and should be dropped.
    Drop,
    /// The packet exceeded the oracle's "massive flood" threshold and should
    /// trigger the harsher contact-expiry path.
    MassiveDrop,
}

impl PacketTrackerAction {
    /// Stable machine-friendly label used in logs and JSONL dump output.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Drop => "drop",
            Self::MassiveDrop => "massive_drop",
        }
    }
}

impl PacketTracker {
    /// Creates a tracker with oracle-shaped budgets for search/publish requests
    /// and configurable flood budgets for general traffic and `SEARCH_RES`.
    pub fn new(
        max_per_window: u32,
        search_res_max_per_window: u32,
        window: Duration,
        request_window: Duration,
    ) -> Self {
        let default_limit = PacketTrackerLimit::new(max_per_window, window);
        let limits = HashMap::from([
            (
                PacketTrackerBucket::BootstrapReq,
                PacketTrackerLimit::new(2, request_window),
            ),
            (
                PacketTrackerBucket::HelloReq,
                PacketTrackerLimit::new(3, request_window),
            ),
            (
                PacketTrackerBucket::FindNodeReq,
                PacketTrackerLimit::new(10, request_window),
            ),
            (
                PacketTrackerBucket::SearchReq,
                PacketTrackerLimit::new(3, request_window),
            ),
            (
                PacketTrackerBucket::PublishKeyReq,
                PacketTrackerLimit::new(4, request_window),
            ),
            (
                PacketTrackerBucket::PublishSourceReq,
                PacketTrackerLimit::new(3, request_window),
            ),
            (
                PacketTrackerBucket::PublishNotesReq,
                PacketTrackerLimit::new(2, request_window),
            ),
            (
                PacketTrackerBucket::FirewalledReq,
                PacketTrackerLimit::new(2, request_window),
            ),
            (
                PacketTrackerBucket::FindBuddyReq,
                PacketTrackerLimit::new(2, request_window),
            ),
            (
                PacketTrackerBucket::CallbackReq,
                PacketTrackerLimit::new(1, request_window),
            ),
            (
                PacketTrackerBucket::PingReq,
                PacketTrackerLimit::new(2, request_window),
            ),
            (
                PacketTrackerBucket::SearchRes,
                PacketTrackerLimit::new(search_res_max_per_window, window),
            ),
        ]);
        Self {
            counts: HashMap::new(),
            limits,
            default_limit,
        }
    }

    /// Record an incoming packet from this IP.
    /// Returns the full decision so callers can log the exact bucket budget that applied.
    pub fn record_and_check(&mut self, key: PacketTrackerKey) -> PacketTrackerDecision {
        let now = Instant::now();
        let limit = self.limit_for_bucket(key.bucket);
        let entry = self.counts.entry(key).or_insert((0, now));

        // Reset window if expired
        if now.duration_since(entry.1) >= limit.window {
            *entry = (0, now);
        }

        entry.0 += 1;
        let action = if entry.0 > limit.max_packets.saturating_mul(4) {
            PacketTrackerAction::MassiveDrop
        } else if entry.0 > limit.max_packets {
            PacketTrackerAction::Drop
        } else {
            PacketTrackerAction::Allow
        };
        PacketTrackerDecision {
            action,
            allowed: matches!(action, PacketTrackerAction::Allow),
            observed_packets: entry.0,
            max_packets: limit.max_packets,
            window: limit.window,
        }
    }

    /// Prune stale entries (call periodically to prevent memory growth).
    pub fn prune(&mut self) {
        let now = Instant::now();
        let limits = self.limits.clone();
        let default_limit = self.default_limit;
        self.counts.retain(|key, (_, window_start)| {
            let limit = limits.get(&key.bucket).copied().unwrap_or(default_limit);
            now.duration_since(*window_start) < limit.window.saturating_mul(2)
        });
    }

    fn limit_for_bucket(&self, bucket: PacketTrackerBucket) -> PacketTrackerLimit {
        self.limits
            .get(&bucket)
            .copied()
            .unwrap_or(self.default_limit)
    }
}

/// Tracks outbound Kad requests by IP and opcode for the oracle's "did we ask
/// for this response?" validation.
pub struct OutboundRequestTracker {
    entries: VecDeque<OutboundRequestEntry>,
    window: Duration,
}

#[derive(Debug, Clone, Copy)]
struct OutboundRequestEntry {
    inserted_at: Instant,
    ip: IpAddr,
    opcode: u8,
}

impl OutboundRequestTracker {
    /// Create a new outbound request tracker with the given retention window.
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            entries: VecDeque::new(),
            window,
        }
    }

    /// Record an outbound request if the oracle would track it.
    pub fn record(&mut self, ip: IpAddr, opcode: u8) {
        self.prune();
        if !tracks_outbound_request_opcode(opcode) {
            return;
        }
        self.entries.push_front(OutboundRequestEntry {
            inserted_at: Instant::now(),
            ip,
            opcode,
        });
    }

    /// Find a matching tracked request by IP and opcode.
    ///
    /// When `remove` is true the newest matching request is consumed, mirroring
    /// the oracle's list walk.
    #[must_use]
    pub fn contains(&mut self, ip: IpAddr, opcode: u8, remove: bool) -> bool {
        self.prune();
        for index in 0..self.entries.len() {
            let Some(entry) = self.entries.get(index).copied() else {
                continue;
            };
            if entry.ip == ip && entry.opcode == opcode {
                if remove {
                    let _ = self.entries.remove(index);
                }
                return true;
            }
        }
        false
    }

    /// Find the first matching opcode from the provided oracle-ordered set.
    #[must_use]
    pub fn find_any(&mut self, ip: IpAddr, opcodes: &[u8], remove: bool) -> Option<u8> {
        for opcode in opcodes {
            if self.contains(ip, *opcode, remove) {
                return Some(*opcode);
            }
        }
        None
    }

    fn prune(&mut self) {
        let now = Instant::now();
        while self
            .entries
            .back()
            .is_some_and(|entry| now.duration_since(entry.inserted_at) >= self.window)
        {
            let _ = self.entries.pop_back();
        }
    }
}

fn tracks_outbound_request_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        emulebb_kad_proto::constants::opcode::BOOTSTRAP_REQ
            | emulebb_kad_proto::constants::opcode::HELLO_REQ
            | emulebb_kad_proto::constants::opcode::HELLO_RES
            | emulebb_kad_proto::constants::opcode::REQ
            | emulebb_kad_proto::constants::opcode::SEARCH_NOTES_REQ
            | emulebb_kad_proto::constants::opcode::PUBLISH_KEY_REQ
            | emulebb_kad_proto::constants::opcode::PUBLISH_SOURCE_REQ
            | emulebb_kad_proto::constants::opcode::PUBLISH_NOTES_REQ
            | emulebb_kad_proto::constants::opcode::FINDBUDDY_REQ
            | emulebb_kad_proto::constants::opcode::CALLBACK_REQ
            | emulebb_kad_proto::constants::opcode::PING
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn key(ip: &str, bucket: PacketTrackerBucket) -> PacketTrackerKey {
        PacketTrackerKey {
            ip: parse_ip(ip),
            bucket,
        }
    }

    #[test]
    fn test_normal_traffic_passes() {
        let mut tracker =
            PacketTracker::new(10, 100, Duration::from_secs(1), Duration::from_secs(60));
        let addr = key("1.2.3.4", PacketTrackerBucket::Default);
        for _ in 0..10 {
            assert!(tracker.record_and_check(addr).allowed);
        }
    }

    #[test]
    fn test_flood_over_limit_blocked() {
        let mut tracker =
            PacketTracker::new(5, 100, Duration::from_secs(1), Duration::from_secs(60));
        let addr = key("1.2.3.4", PacketTrackerBucket::Default);
        // First 5 pass
        for _ in 0..5 {
            assert!(tracker.record_and_check(addr).allowed);
        }
        // 6th and beyond are blocked
        assert!(!tracker.record_and_check(addr).allowed);
        assert!(!tracker.record_and_check(addr).allowed);
    }

    #[test]
    fn test_window_reset() {
        // Use a very short window to test expiry
        let mut tracker =
            PacketTracker::new(2, 100, Duration::from_millis(50), Duration::from_secs(60));
        let addr = key("5.6.7.8", PacketTrackerBucket::Default);
        assert!(tracker.record_and_check(addr).allowed);
        assert!(tracker.record_and_check(addr).allowed);
        assert!(!tracker.record_and_check(addr).allowed); // over limit

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(60));

        // Window should be reset — packets allowed again
        assert!(tracker.record_and_check(addr).allowed);
    }

    #[test]
    fn test_search_res_uses_higher_limit_than_default_bucket() {
        let mut tracker =
            PacketTracker::new(5, 50, Duration::from_secs(1), Duration::from_secs(60));
        let default_key = key("1.2.3.4", PacketTrackerBucket::FindNodeReq);
        let search_res_key = key("1.2.3.4", PacketTrackerBucket::SearchRes);

        for _ in 0..10 {
            assert!(tracker.record_and_check(default_key).allowed);
        }
        assert!(!tracker.record_and_check(default_key).allowed);

        for _ in 0..50 {
            assert!(tracker.record_and_check(search_res_key).allowed);
        }
        assert!(!tracker.record_and_check(search_res_key).allowed);
    }

    #[test]
    fn test_search_requests_use_oracle_minute_budget() {
        let mut tracker =
            PacketTracker::new(20, 50, Duration::from_secs(1), Duration::from_secs(1));
        let search_key = key("1.2.3.4", PacketTrackerBucket::SearchReq);

        for _ in 0..3 {
            assert!(tracker.record_and_check(search_key).allowed);
        }
        let decision = tracker.record_and_check(search_key);
        assert!(!decision.allowed);
        assert_eq!(decision.max_packets, 3);
        assert_eq!(decision.window, Duration::from_secs(1));
    }

    #[test]
    fn test_publish_buckets_have_distinct_limits() {
        let mut tracker =
            PacketTracker::new(20, 50, Duration::from_secs(1), Duration::from_secs(60));
        let publish_key = key("1.2.3.4", PacketTrackerBucket::PublishKeyReq);
        let publish_source = key("1.2.3.4", PacketTrackerBucket::PublishSourceReq);
        let publish_notes = key("1.2.3.4", PacketTrackerBucket::PublishNotesReq);

        for _ in 0..4 {
            assert!(tracker.record_and_check(publish_key).allowed);
        }
        assert!(!tracker.record_and_check(publish_key).allowed);

        for _ in 0..3 {
            assert!(tracker.record_and_check(publish_source).allowed);
        }
        assert!(!tracker.record_and_check(publish_source).allowed);

        for _ in 0..2 {
            assert!(tracker.record_and_check(publish_notes).allowed);
        }
        assert!(!tracker.record_and_check(publish_notes).allowed);
    }

    #[test]
    fn test_massive_flood_uses_oracle_four_x_threshold() {
        let mut tracker =
            PacketTracker::new(20, 50, Duration::from_secs(1), Duration::from_secs(60));
        let publish_key = key("1.2.3.4", PacketTrackerBucket::PublishKeyReq);

        for _ in 0..4 {
            let decision = tracker.record_and_check(publish_key);
            assert_eq!(decision.action, PacketTrackerAction::Allow);
        }

        let ordinary_drop = tracker.record_and_check(publish_key);
        assert_eq!(ordinary_drop.action, PacketTrackerAction::Drop);

        for _ in 0..11 {
            let _ = tracker.record_and_check(publish_key);
        }

        let massive_drop = tracker.record_and_check(publish_key);
        assert_eq!(massive_drop.action, PacketTrackerAction::MassiveDrop);
    }

    #[test]
    fn test_request_buckets_follow_oracle_minute_limits() {
        let mut tracker =
            PacketTracker::new(20, 50, Duration::from_secs(1), Duration::from_secs(60));

        for _ in 0..2 {
            assert!(
                tracker
                    .record_and_check(key("1.2.3.4", PacketTrackerBucket::BootstrapReq))
                    .allowed
            );
        }
        assert!(
            !tracker
                .record_and_check(key("1.2.3.4", PacketTrackerBucket::BootstrapReq))
                .allowed
        );

        for _ in 0..2 {
            assert!(
                tracker
                    .record_and_check(key("1.2.3.5", PacketTrackerBucket::PingReq))
                    .allowed
            );
        }
        assert!(
            !tracker
                .record_and_check(key("1.2.3.5", PacketTrackerBucket::PingReq))
                .allowed
        );

        assert!(
            tracker
                .record_and_check(key("1.2.3.6", PacketTrackerBucket::CallbackReq))
                .allowed
        );
        assert!(
            !tracker
                .record_and_check(key("1.2.3.6", PacketTrackerBucket::CallbackReq))
                .allowed
        );
    }

    #[test]
    fn outbound_request_tracker_matches_newest_request_by_ip_and_opcode() {
        let mut tracker = OutboundRequestTracker::new(Duration::from_secs(180));
        let ip = parse_ip("1.2.3.4");

        tracker.record(ip, emulebb_kad_proto::constants::opcode::PUBLISH_KEY_REQ);
        tracker.record(ip, emulebb_kad_proto::constants::opcode::PUBLISH_KEY_REQ);

        assert!(tracker.contains(
            ip,
            emulebb_kad_proto::constants::opcode::PUBLISH_KEY_REQ,
            true
        ));
        assert!(tracker.contains(
            ip,
            emulebb_kad_proto::constants::opcode::PUBLISH_KEY_REQ,
            true
        ));
        assert!(!tracker.contains(
            ip,
            emulebb_kad_proto::constants::opcode::PUBLISH_KEY_REQ,
            true
        ));
    }

    #[test]
    fn outbound_request_tracker_ignores_untracked_opcodes() {
        let mut tracker = OutboundRequestTracker::new(Duration::from_secs(180));
        let ip = parse_ip("1.2.3.4");

        tracker.record(ip, emulebb_kad_proto::constants::opcode::PUBLISH_RES);

        assert!(!tracker.contains(ip, emulebb_kad_proto::constants::opcode::PUBLISH_RES, false));
    }
}
