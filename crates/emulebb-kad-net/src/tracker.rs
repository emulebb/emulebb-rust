use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Tracks incoming Kad requests per IP and opcode family to detect flooding.
///
/// This mirrors the oracle `CPacketTracking::InTrackListIsAllowedPacket`
/// (`PacketTracking.cpp`): a continuous **token bucket** per (IP, opcode) rather
/// than a fixed counting window. Each bucket holds up to `MIN2MS(1)` (= one
/// window's worth of) millisecond-tokens; idle time refills tokens 1:1, and each
/// request spends `window / max_packets` tokens (i.e. `MIN2MS(1) / N` for the
/// oracle's N-per-minute budgets). A request whose post-spend balance is negative
/// is dropped; a balance below `-3 * cap` (oracle `MIN2MS(-3)`) is a massive
/// flood that also bans the source IP. Only request families are throttled here;
/// reply validation is handled by [`OutboundRequestTracker`].
pub struct PacketTracker {
    /// Per-(IP, bucket) token-bucket state.
    buckets: HashMap<PacketTrackerKey, TokenBucketState>,
    limits: HashMap<PacketTrackerBucket, PacketTrackerLimit>,
    default_limit: PacketTrackerLimit,
    /// IPs banned after a massive request flood (oracle
    /// `theApp.clientlist->AddBannedClient`), with the instant the ban lifts.
    /// While banned, every inbound Kad packet from the IP is dropped.
    banned_until: HashMap<IpAddr, Instant>,
}

/// How long a massive-flood ban holds an IP (oracle client-ban duration,
/// `CClientList::AddBannedClient` -> `CLIENTBANTIME` = 1 hour).
const MASSIVE_FLOOD_BAN: Duration = Duration::from_secs(60 * 60);

/// Continuous token-bucket state for one (IP, opcode) request stream (oracle
/// `TrackedRequestIn_Struct`).
#[derive(Debug, Clone, Copy)]
struct TokenBucketState {
    /// Remaining millisecond-tokens (oracle `m_tokens`); may go negative.
    tokens: i64,
    /// When this bucket was last charged (oracle `m_dwLatest`).
    last_tick: Instant,
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
            buckets: HashMap::new(),
            limits,
            default_limit,
            banned_until: HashMap::new(),
        }
    }

    /// Whether `ip` is currently flood-banned (oracle banned-client check). A
    /// banned IP's packets are dropped before any per-bucket accounting.
    #[must_use]
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.banned_until
            .get(&ip)
            .is_some_and(|&until| Instant::now() < until)
    }

    /// Record an incoming packet from this IP against its token bucket and return
    /// the oracle-shaped decision. Mirrors `InTrackListIsAllowedPacket`: refill by
    /// elapsed time (capped at the bucket cap), spend the per-packet cost, then
    /// drop on a negative balance (massive-drop + ban below `-3 * cap`).
    pub fn record_and_check(&mut self, key: PacketTrackerKey) -> PacketTrackerDecision {
        let now = Instant::now();
        let limit = self.limit_for_bucket(key.bucket);
        let cap = bucket_cap_ms(limit);
        let cost = per_packet_token_cost_ms(limit);
        let massive_floor = -3 * cap;

        let state = self.buckets.entry(key).or_insert(TokenBucketState {
            // Oracle: a fresh entry starts at `MIN2MS(1) - token`, i.e. as if it
            // were full and had just spent one packet's cost.
            tokens: cap - cost,
            last_tick: now,
        });

        if state.last_tick != now || state.tokens != cap - cost {
            // Existing bucket: refill by elapsed ms (cap at `cap`), then spend.
            let elapsed_ms = i64::try_from(now.duration_since(state.last_tick).as_millis())
                .unwrap_or(i64::MAX);
            state.tokens = (state.tokens.saturating_add(elapsed_ms)).min(cap);
            state.tokens = state.tokens.saturating_sub(cost);
        }
        state.last_tick = now;
        let tokens = state.tokens;

        // Oracle: a negative balance drops; far below the limit is a massive
        // flood that also bans the IP (handled by the caller via MassiveDrop).
        let action = if tokens < massive_floor {
            // Oracle: a sustained flood far past the limit bans the source IP.
            self.banned_until
                .insert(key.ip, now + MASSIVE_FLOOD_BAN);
            PacketTrackerAction::MassiveDrop
        } else if tokens < 0 {
            PacketTrackerAction::Drop
        } else {
            PacketTrackerAction::Allow
        };
        PacketTrackerDecision {
            action,
            allowed: matches!(action, PacketTrackerAction::Allow),
            // Surface the token balance as a signed millisecond deficit/credit for
            // diagnostics. `observed_packets`/`max_packets` are retained for the
            // dump schema: report the remaining whole-packet allowance and the
            // per-window budget.
            observed_packets: max_u32(0, (cap - tokens) / cost.max(1)),
            max_packets: limit.max_packets,
            window: limit.window,
        }
    }

    /// Prune idle buckets (call periodically to prevent memory growth). A bucket
    /// that has been idle long enough to fully refill past its cap carries no
    /// deficit and can be dropped.
    pub fn prune(&mut self) {
        let now = Instant::now();
        let limits = self.limits.clone();
        let default_limit = self.default_limit;
        self.buckets.retain(|key, state| {
            let limit = limits.get(&key.bucket).copied().unwrap_or(default_limit);
            let cap = bucket_cap_ms(limit);
            // Idle for >= one full refill window since last charge: the bucket
            // would be back at its cap, so it holds no state worth keeping.
            now.duration_since(state.last_tick) < Duration::from_millis(cap.max(0) as u64)
        });
        // Drop expired flood bans.
        self.banned_until.retain(|_, until| now < *until);
    }

    fn limit_for_bucket(&self, bucket: PacketTrackerBucket) -> PacketTrackerLimit {
        self.limits
            .get(&bucket)
            .copied()
            .unwrap_or(self.default_limit)
    }
}

/// The token-bucket cap in milliseconds (oracle `MIN2MS(1)` = one window's worth
/// of tokens). Generalised to the bucket's configured window so non-minute
/// buckets keep the same "one window of credit" semantics.
fn bucket_cap_ms(limit: PacketTrackerLimit) -> i64 {
    i64::try_from(limit.window.as_millis()).unwrap_or(i64::MAX)
}

/// Per-packet token cost (oracle `MIN2MS(1) / N` for an N-per-window budget).
fn per_packet_token_cost_ms(limit: PacketTrackerLimit) -> i64 {
    let cap = bucket_cap_ms(limit);
    let max_packets = i64::from(limit.max_packets.max(1));
    (cap / max_packets).max(1)
}

const fn max_u32(a: u32, b: i64) -> u32 {
    if b < a as i64 { a } else { b as u32 }
}

mod outbound;
pub use outbound::OutboundRequestTracker;

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
    fn token_bucket_refills_continuously_after_partial_idle() {
        // Short window so the refill is observable in a unit test: max 2 per
        // 100ms -> cap 100ms, cost 50ms.
        let mut tracker =
            PacketTracker::new(20, 50, Duration::from_secs(1), Duration::from_millis(100));
        let addr = key("9.9.9.9", PacketTrackerBucket::BootstrapReq);
        // Override BootstrapReq to the small window for this test by using the
        // PingReq-style budget is not possible; instead use the configured
        // request_window buckets which all share 100ms here. BootstrapReq is 2.
        // Spend the whole bucket: 2 allowed (tokens 50 -> 0), 3rd drops to -50.
        assert!(tracker.record_and_check(addr).allowed);
        assert!(tracker.record_and_check(addr).allowed);
        assert!(!tracker.record_and_check(addr).allowed);
        // Idle ~130ms: refills ~130ms (capped at the 100ms cap), clearing the
        // -50 deficit, so one packet is allowed again (continuous refill, not a
        // hard window reset).
        std::thread::sleep(Duration::from_millis(130));
        assert!(tracker.record_and_check(addr).allowed);
        // The bucket is back near empty after that spend, so a tight follow-up
        // drops again (the deficit is continuous, not reset to a full window).
        assert!(!tracker.record_and_check(addr).allowed);
    }

    #[test]
    fn token_bucket_bans_at_massive_flood_threshold() {
        // CallbackReq: 1 per minute -> cap 60000ms, cost 60000ms. The massive
        // threshold is tokens < -3*cap = -180000, reached once the deficit
        // exceeds three full windows.
        let mut tracker =
            PacketTracker::new(20, 50, Duration::from_secs(1), Duration::from_secs(60));
        let addr = key("8.8.8.8", PacketTrackerBucket::CallbackReq);
        // Packet 1: starts at cap-cost = 0 -> Allow.
        assert_eq!(
            tracker.record_and_check(addr).action,
            PacketTrackerAction::Allow
        );
        // Packets 2..=4: tokens go -60000, -120000, -180000. -180000 is NOT
        // strictly below -180000, so still an ordinary drop.
        for _ in 0..3 {
            assert_eq!(
                tracker.record_and_check(addr).action,
                PacketTrackerAction::Drop
            );
        }
        // Packet 5: tokens -240000 < -180000 -> massive flood, ban the IP.
        assert_eq!(
            tracker.record_and_check(addr).action,
            PacketTrackerAction::MassiveDrop
        );
        // The IP is now flood-banned (oracle AddBannedClient), so further
        // inbound packets from it are dropped wholesale by is_banned.
        assert!(tracker.is_banned(addr.ip));
        assert!(!tracker.is_banned(parse_ip("8.8.4.4")));
    }
}
