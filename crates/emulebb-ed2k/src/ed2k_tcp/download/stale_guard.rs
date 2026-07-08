//! Stale block-packet cancel guard for the download session.
//!
//! Mirrors the oracle's runaway-sender guard (`DownloadClient.cpp:2684-2712`,
//! constants at `DownloadClient.cpp:70-71`): a stale / duplicate / out-of-order
//! block payload is DROPPED and counted, never fatal on its own. Only a
//! sustained burst -- `kDownloadStaleBlockPacketThreshold` (32) stale packets
//! inside one `kDownloadStaleBlockPacketWindowMs` (15 s) window while block
//! requests are outstanding -- cancels the transfer, guarding a scarce
//! download slot against a sender that streams payload we can never use.

use std::time::Duration;

use tokio::time::Instant;

/// `kDownloadStaleBlockPacketThreshold` (DownloadClient.cpp:70).
pub(in crate::ed2k_tcp) const STALE_BLOCK_PACKET_THRESHOLD: u32 = 32;

/// `kDownloadStaleBlockPacketWindowMs` (DownloadClient.cpp:71).
pub(in crate::ed2k_tcp) const STALE_BLOCK_PACKET_WINDOW: Duration = Duration::from_secs(15);

/// Rolling-window stale block-packet counter, one per download session
/// (oracle members `m_ullDownloadStaleBlockPacketWindowStart` /
/// `m_uDownloadStaleBlockPacketWindowCount`).
#[derive(Debug, Default)]
pub(in crate::ed2k_tcp) struct StaleBlockPacketGuard {
    window_start: Option<Instant>,
    window_count: u32,
}

impl StaleBlockPacketGuard {
    /// Oracle `ResetDownloadStaleBlockPacketGuard` (DownloadClient.cpp:2684-2688):
    /// any useful download progress clears the window.
    pub(in crate::ed2k_tcp) fn reset(&mut self) {
        self.window_start = None;
        self.window_count = 0;
    }

    /// Count one stale block packet and decide whether the transfer must be
    /// cancelled, mirroring `ShouldAbortAfterStaleBlockPacket`
    /// (DownloadClient.cpp:2690-2712): the guard only arms while pending block
    /// requests exist (the `m_PendingBlocks_list.IsEmpty()` gate); a packet
    /// landing outside the current window restarts it (`IsTickInsideWindow`,
    /// DownloadClient.cpp:101-104, with the count reset BEFORE the increment);
    /// and the 32nd stale packet inside one window trips the cancel.
    pub(in crate::ed2k_tcp) fn note_stale_packet(
        &mut self,
        now: Instant,
        has_pending_blocks: bool,
    ) -> bool {
        if !has_pending_blocks {
            return false;
        }
        let inside_window = self
            .window_start
            .is_some_and(|start| now.duration_since(start) <= STALE_BLOCK_PACKET_WINDOW);
        if !inside_window {
            self.window_start = Some(now);
            self.window_count = 0;
        }
        self.window_count += 1;
        self.window_count >= STALE_BLOCK_PACKET_THRESHOLD
    }

    /// Stale packets counted in the current window, for the abort diagnostics
    /// (the oracle reason string reports the same counter).
    pub(in crate::ed2k_tcp) fn window_count(&self) -> u32 {
        self.window_count
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::Instant;

    use super::{STALE_BLOCK_PACKET_THRESHOLD, StaleBlockPacketGuard};

    #[test]
    fn stale_packets_below_threshold_never_cancel() {
        let mut guard = StaleBlockPacketGuard::default();
        let now = Instant::now();
        for _ in 0..STALE_BLOCK_PACKET_THRESHOLD - 1 {
            assert!(!guard.note_stale_packet(now, true));
        }
        assert_eq!(guard.window_count(), STALE_BLOCK_PACKET_THRESHOLD - 1);
    }

    #[test]
    fn threshold_reached_within_window_cancels() {
        let mut guard = StaleBlockPacketGuard::default();
        let now = Instant::now();
        for _ in 0..STALE_BLOCK_PACKET_THRESHOLD - 1 {
            assert!(!guard.note_stale_packet(now, true));
        }
        // The 32nd stale packet inside the 15 s window trips the cancel
        // (count incremented, then `count < threshold` fails).
        assert!(guard.note_stale_packet(now + Duration::from_secs(14), true));
    }

    #[test]
    fn window_expiry_restarts_the_count() {
        let mut guard = StaleBlockPacketGuard::default();
        let now = Instant::now();
        for _ in 0..STALE_BLOCK_PACKET_THRESHOLD - 1 {
            assert!(!guard.note_stale_packet(now, true));
        }
        // 16 s later the window has expired: the count restarts at 1 instead
        // of tripping on what would have been the 32nd packet.
        assert!(!guard.note_stale_packet(now + Duration::from_secs(16), true));
        assert_eq!(guard.window_count(), 1);
    }

    #[test]
    fn progress_reset_clears_the_window() {
        let mut guard = StaleBlockPacketGuard::default();
        let now = Instant::now();
        for _ in 0..STALE_BLOCK_PACKET_THRESHOLD - 1 {
            assert!(!guard.note_stale_packet(now, true));
        }
        guard.reset();
        for _ in 0..STALE_BLOCK_PACKET_THRESHOLD - 1 {
            assert!(!guard.note_stale_packet(now, true));
        }
    }

    #[test]
    fn stale_packets_without_pending_blocks_are_not_counted() {
        let mut guard = StaleBlockPacketGuard::default();
        let now = Instant::now();
        for _ in 0..STALE_BLOCK_PACKET_THRESHOLD * 2 {
            assert!(!guard.note_stale_packet(now, false));
        }
        assert_eq!(guard.window_count(), 0);
    }
}
