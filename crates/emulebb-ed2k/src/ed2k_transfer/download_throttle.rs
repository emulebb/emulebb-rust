//! Global (cross-transfer) download-rate throttle.
//!
//! The downloader runs one independent task per transfer, each consuming inbound
//! `OP_SENDINGPART`/compressed-part payload on its own socket. Without a shared
//! limiter the aggregate inbound rate is unbounded, unlike eMule's
//! `CDownloadQueue::Process`, which derives a global `downspeed` budget from
//! `GetMaxDownloadInBytesPerSec` and paces every socket against it.
//!
//! This module is the symmetric counterpart to the upload-side rate limiter in
//! `upload_queue.rs` (`reserve_upload_payload`): a single shared token-bucket
//! limiter, held once per `Ed2kTransferRuntime` and consulted by every transfer
//! task before it consumes a received block, so the SUM of all concurrent
//! transfers' inbound payload respects the cap.
//!
//! The pacing math is identical to the upload side
//! (`upload_payload_interval`): each reservation advances a shared
//! "next admissible read" instant by `byte_count / limit` seconds, and returns
//! the delay the caller must await before that instant. A limit of `0` means
//! unlimited and every reservation is an instant no-op, preserving today's
//! behavior.

use std::time::{Duration, Instant};

/// Global download-rate reservation result for transfer block reads.
///
/// Mirrors `Ed2kUploadThrottleReservation`: the caller awaits `delay` before (or
/// around) consuming the reserved inbound payload so concurrent transfers pace
/// together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed2kDownloadThrottleReservation {
    pub delay: Duration,
}

impl Ed2kDownloadThrottleReservation {
    /// A no-op reservation (no delay), used when the limiter is unlimited or the
    /// reserved byte count is zero.
    pub(super) const fn instant() -> Self {
        Self {
            delay: Duration::ZERO,
        }
    }
}

/// Shared cross-transfer download-rate limiter (token bucket).
///
/// One instance per runtime, shared across all download tasks via an
/// `Arc<Mutex<_>>`. `limit_bytes_per_sec == 0` disables throttling.
#[derive(Debug)]
pub(super) struct Ed2kDownloadThrottle {
    limit_bytes_per_sec: u64,
    /// Shared cursor for the next admissible read instant. The bucket is paced
    /// by advancing this cursor per reservation, identical to the upload side's
    /// `throttle_next_send_at`.
    next_read_at: Option<Instant>,
}

impl Ed2kDownloadThrottle {
    pub(super) const fn new(limit_bytes_per_sec: u64) -> Self {
        Self {
            limit_bytes_per_sec,
            next_read_at: None,
        }
    }

    /// Replace the active download rate limit. Resets the shared cursor so a new
    /// limit takes effect from now (mirrors `Ed2kUploadQueueState::configure`,
    /// which clears `throttle_next_send_at`).
    pub(super) fn set_limit(&mut self, limit_bytes_per_sec: u64) {
        self.limit_bytes_per_sec = limit_bytes_per_sec;
        self.next_read_at = None;
    }

    pub(super) const fn limit_bytes_per_sec(&self) -> u64 {
        self.limit_bytes_per_sec
    }

    /// Reserve global download budget for `byte_count` inbound payload bytes and
    /// return the delay the caller must await before consuming them.
    ///
    /// Identical pacing to `Ed2kUploadQueueState::reserve_upload_payload`: a
    /// zero byte count or an unlimited limiter returns an instant no-op;
    /// otherwise the shared cursor is advanced by the byte interval and the
    /// returned delay is the wait until the (current) cursor.
    pub(super) fn reserve_download_payload(
        &mut self,
        byte_count: u64,
        now: Instant,
    ) -> Ed2kDownloadThrottleReservation {
        if byte_count == 0 || self.limit_bytes_per_sec == 0 {
            return Ed2kDownloadThrottleReservation::instant();
        }
        let interval = download_payload_interval(byte_count, self.limit_bytes_per_sec);
        let scheduled_at = self
            .next_read_at
            .filter(|next_read_at| *next_read_at > now)
            .unwrap_or(now);
        self.next_read_at = Some(scheduled_at + interval);
        Ed2kDownloadThrottleReservation {
            delay: scheduled_at.saturating_duration_since(now),
        }
    }
}

/// Time one block of `byte_count` bytes occupies at `limit_bytes_per_sec`.
///
/// Identical to the upload side's `upload_payload_interval`: rounds up so the
/// limiter never overshoots the configured rate.
fn download_payload_interval(byte_count: u64, limit_bytes_per_sec: u64) -> Duration {
    let nanos = (u128::from(byte_count) * 1_000_000_000u128)
        .div_ceil(u128::from(limit_bytes_per_sec.max(1)));
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_throttle_is_instant_no_op() {
        let mut throttle = Ed2kDownloadThrottle::new(0);
        let now = Instant::now();

        let first = throttle.reserve_download_payload(184_320, now);
        let second = throttle.reserve_download_payload(184_320, now);

        assert_eq!(first.delay, Duration::ZERO);
        assert_eq!(second.delay, Duration::ZERO);
    }

    #[test]
    fn zero_byte_reservation_is_instant() {
        let mut throttle = Ed2kDownloadThrottle::new(1024);
        let now = Instant::now();

        let reservation = throttle.reserve_download_payload(0, now);

        assert_eq!(reservation.delay, Duration::ZERO);
    }

    #[test]
    fn limited_throttle_paces_successive_reads() {
        let mut throttle = Ed2kDownloadThrottle::new(1024);
        let now = Instant::now();

        let first = throttle.reserve_download_payload(1024, now);
        let second = throttle.reserve_download_payload(1024, now);

        assert_eq!(first.delay, Duration::ZERO);
        assert_eq!(second.delay, Duration::from_secs(1));
    }

    #[test]
    fn set_limit_resets_the_shared_cursor() {
        let mut throttle = Ed2kDownloadThrottle::new(1024);
        let now = Instant::now();

        let _ = throttle.reserve_download_payload(1024, now);
        // Reconfigure: a fresh limit starts pacing from now, so the next
        // reservation is admissible immediately.
        throttle.set_limit(2048);
        let after = throttle.reserve_download_payload(1024, now);

        assert_eq!(after.delay, Duration::ZERO);
    }
}
