use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Token bucket rate limiter.
/// `max_pps = 0` means unlimited.
pub struct RateLimiter {
    max_pps: u32,
    state: Mutex<RateState>,
}

struct RateState {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(max_pps: u32) -> Self {
        Self {
            max_pps,
            state: Mutex::new(RateState {
                tokens: max_pps as f64,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Returns true immediately if a token is available (non-blocking).
    pub fn try_acquire(&self) -> bool {
        if self.max_pps == 0 {
            return true;
        }
        let mut s = self.state.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(s.last_refill).as_secs_f64();
        s.tokens = (s.tokens + elapsed * self.max_pps as f64).min(self.max_pps as f64);
        s.last_refill = now;
        if s.tokens >= 1.0 {
            s.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Wait until a token is available.
    pub async fn acquire(&self) {
        if self.max_pps == 0 {
            return;
        }
        loop {
            if self.try_acquire() {
                return;
            }
            // Wait for 1/pps seconds before trying again
            let wait = Duration::from_secs_f64(1.0 / self.max_pps as f64);
            sleep(wait).await;
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_acquire_tokens_available() {
        let rl = RateLimiter::new(10);
        // Should succeed immediately since bucket starts full
        assert!(rl.try_acquire());
    }

    #[test]
    fn test_try_acquire_bucket_empty() {
        let rl = RateLimiter::new(2);
        // Drain the bucket (starts with 2 tokens)
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        // Now empty
        assert!(!rl.try_acquire());
    }

    #[test]
    fn test_unlimited_always_true() {
        let rl = RateLimiter::new(0);
        for _ in 0..1000 {
            assert!(rl.try_acquire());
        }
    }
}
