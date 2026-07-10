//! Sliding-window upload datarate meters (RUST-PAR-024 GAP-1).
//!
//! The oracle measures upload throughput over bounded time windows, NOT as a
//! lifetime cumulative average:
//!
//! - Per upload slot: a 10 s window (`CUpDownClient::m_AverageUDR_hist`,
//!   UploadClient.cpp:860-878). A byte sample `{sentBytesFile, curTick}` is
//!   appended on each send, old samples are dropped once
//!   `curTick >= head.timestamp + SEC2MS(10)`, and the rate is
//!   `SEC2MS(sum) / (curTick - head.timestamp)` -- the in-window byte sum divided
//!   by the span from the oldest retained sample to now.
//! - Aggregate (whole queue): a 30 s window (`CUploadQueue::average_ur_hist`,
//!   fed in `Process` at UploadQueue.cpp:923-931, pruned to
//!   `head.timestamp + SEC2MS(30)`, averaged in `UpdateDatarates`,
//!   UploadQueue.cpp:2761-2764).
//!
//! This fork feeds bytes on send EVENTS (`note_uploaded_bytes`) rather than on a
//! periodic `Process` cycle, so both meters compute the rate lazily on read
//! against `now`, pruning to the window span. Reading against `now` reproduces
//! the oracle's decay-to-zero on a stall (the oracle achieves the same via the
//! zero-byte samples its periodic feed keeps appending) without needing a
//! periodic tick. Both windows use the per-slot averaging formula
//! (`sum / (now - oldest)`, UploadClient.cpp:876); at steady state it converges
//! to the same value as the oracle's aggregate `(sum - head) / (tail - head)`
//! form, and unlike that form it reports a single-burst window correctly instead
//! of zero (the oracle's `count > 1` guard assumes a periodic multi-sample feed
//! this fork's event feed does not provide).
//!
//! The oracle's `GetUpStartTimeDelay() > SEC2MS(2)` trustworthiness floor
//! (UploadClient.cpp:875, which suppresses the per-slot rate for the first 2 s)
//! is intentionally NOT reproduced here: every consumer of the per-slot rate (the
//! slow-slot recycle and the productive-slot retention) is already gated behind
//! `upload_timeout` / the session cap age, both far larger than 2 s, so the floor
//! is behaviorally moot for slot decisions, and omitting it keeps the REST/display
//! rate non-flaky for a freshly started slot.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Per-slot averaging window (oracle `m_AverageUDR_hist` 10 s,
/// UploadClient.cpp:869 `SEC2MS(10)`).
pub(super) const PER_SLOT_RATE_WINDOW: Duration = Duration::from_secs(10);

/// Aggregate averaging window (oracle `average_ur_hist` 30 s,
/// UploadQueue.cpp:928 `SEC2MS(30)`).
pub(super) const AGGREGATE_RATE_WINDOW: Duration = Duration::from_secs(30);

/// Coalescing quantum: fold same-clock-tick sends into one sample. The oracle
/// records at millisecond tick granularity (`GetTickCount64`), so folding
/// sub-millisecond fragment sends into the tail sample matches its quantization
/// and hard-bounds the buffer to at most one sample per elapsed millisecond in
/// the window.
const SAMPLE_QUANTUM: Duration = Duration::from_millis(1);

#[derive(Debug, Clone, Copy)]
struct RateSample {
    at: Instant,
    bytes: u64,
}

/// A bounded sliding-window byte-rate meter.
#[derive(Debug, Clone)]
pub(super) struct WindowedRateMeter {
    window: Duration,
    samples: VecDeque<RateSample>,
    sum_bytes: u64,
}

impl WindowedRateMeter {
    pub(super) fn new(window: Duration) -> Self {
        Self {
            window,
            samples: VecDeque::new(),
            sum_bytes: 0,
        }
    }

    /// Record a byte sample at `now` (oracle `AddTail(TransferredData{...})` +
    /// `m_nSumForAvgUpDataRate += sentBytesFile`, UploadClient.cpp:864-865).
    /// Zero-byte notes carry no information for a sum-based window and are ignored
    /// (the oracle appends a zero sample only to advance a stalled window, which
    /// the lazy read-against-`now` prune already handles).
    pub(super) fn record(&mut self, bytes: u64, now: Instant) {
        if bytes == 0 {
            return;
        }
        self.prune(now);
        if let Some(tail) = self.samples.back_mut() {
            // Same-tick send: fold into the tail sample (keeping its timestamp as
            // the bucket tick), or a monotonicity slip -- never push out of order.
            if now.saturating_duration_since(tail.at) < SAMPLE_QUANTUM {
                tail.bytes = tail.bytes.saturating_add(bytes);
                self.sum_bytes = self.sum_bytes.saturating_add(bytes);
                return;
            }
        }
        self.samples.push_back(RateSample { at: now, bytes });
        self.sum_bytes = self.sum_bytes.saturating_add(bytes);
    }

    /// Drop stored samples older than the window relative to `now` (oracle
    /// "remove old entries from the list" loop, UploadClient.cpp:869-872 /
    /// UploadQueue.cpp:928-931).
    fn prune(&mut self, now: Instant) {
        while let Some(head) = self.samples.front() {
            if now.saturating_duration_since(head.at) >= self.window {
                self.sum_bytes = self.sum_bytes.saturating_sub(head.bytes);
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    /// Windowed byte rate at `now` (oracle `SEC2MS(sum) / (curTick -
    /// head.timestamp)`, UploadClient.cpp:876): the in-window byte sum divided by
    /// the span from the oldest retained sample to `now`. Read-only (the slot
    /// gates borrow `&self`); the stored buffer is pruned lazily on the next
    /// `record`, so a stalled slot's samples are filtered here against `now` and
    /// its rate decays to zero as they age past the window.
    pub(super) fn rate_bytes_per_sec(&self, now: Instant) -> u64 {
        let mut sum: u64 = 0;
        let mut oldest: Option<Instant> = None;
        for sample in &self.samples {
            if now.saturating_duration_since(sample.at) >= self.window {
                // Ordered oldest-first: a stale head means this sample is stale;
                // keep scanning for the first in-window sample.
                continue;
            }
            oldest.get_or_insert(sample.at);
            sum = sum.saturating_add(sample.bytes);
        }
        let Some(oldest) = oldest else {
            return 0;
        };
        // Zero (or non-positive) span: reading at the exact instant of the only
        // sample is "not enough data to calculate a trustworthy speed" -- the
        // oracle returns 0 here via its strict `curTick > head.timestamp` guard
        // (UploadClient.cpp:875) rather than dividing by a zero span. Without this
        // a single fresh sample would read an absurd bytes/0 ms spike.
        if sum == 0 || now <= oldest {
            return 0;
        }
        let span_ms = now.saturating_duration_since(oldest).as_millis().max(1);
        u64::try_from(u128::from(sum) * 1_000 / span_ms).unwrap_or(u64::MAX)
    }

    /// Reset the window (oracle fresh-slot state: a recycled/demoted slot starts a
    /// new `m_AverageUDR_hist`). Used when a session's per-slot counters are
    /// cleared on recycle.
    pub(super) fn reset(&mut self) {
        self.samples.clear();
        self.sum_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_rate_converges_to_steady_state() {
        // 100 KB/s fed as 10 KB every 100 ms for 10 s: the windowed rate settles
        // at ~100 KB/s, matching the oracle steady-state (no lifetime skew).
        let mut meter = WindowedRateMeter::new(PER_SLOT_RATE_WINDOW);
        let t0 = Instant::now();
        for step in 1..=100u64 {
            meter.record(10_240, t0 + Duration::from_millis(100 * step));
        }
        let rate = meter.rate_bytes_per_sec(t0 + Duration::from_millis(100 * 100));
        // Oldest in-window sample is at +100 ms (span 9.9 s), 99 retained samples
        // of 10 240 B -> ~102 400 B/s. Allow a small boundary tolerance.
        assert!(
            (100_000..=106_000).contains(&rate),
            "steady-state rate {rate} out of band"
        );
    }

    #[test]
    fn stalled_window_decays_to_zero() {
        // A burst then silence: within the window the rate is high; once every
        // sample ages out past 10 s the rate is zero (the lifetime meter would
        // still report bytes/elapsed forever).
        let mut meter = WindowedRateMeter::new(PER_SLOT_RATE_WINDOW);
        let t0 = Instant::now();
        meter.record(1_000_000, t0 + Duration::from_secs(1));
        assert!(meter.rate_bytes_per_sec(t0 + Duration::from_secs(3)) > 0);
        assert_eq!(meter.rate_bytes_per_sec(t0 + Duration::from_secs(12)), 0);
    }

    #[test]
    fn single_burst_reads_nonzero() {
        // One sample must read a rate (the oracle aggregate `count > 1` guard would
        // read zero; the unified per-slot form does not).
        let mut meter = WindowedRateMeter::new(AGGREGATE_RATE_WINDOW);
        let t0 = Instant::now();
        meter.record(500_000, t0);
        assert_eq!(
            meter.rate_bytes_per_sec(t0 + Duration::from_secs(2)),
            250_000
        );
    }

    #[test]
    fn same_tick_sends_coalesce() {
        // Fragments in the same millisecond fold into one sample (bounded buffer)
        // without changing the summed rate.
        let mut meter = WindowedRateMeter::new(PER_SLOT_RATE_WINDOW);
        let t0 = Instant::now();
        meter.record(1_000, t0 + Duration::from_secs(1));
        meter.record(1_000, t0 + Duration::from_secs(1));
        assert_eq!(meter.samples.len(), 1);
        // 2 000 B with oldest at +1 s, read at +3 s (span 2 s) -> 1 000 B/s.
        assert_eq!(meter.rate_bytes_per_sec(t0 + Duration::from_secs(3)), 1_000);
    }
}
