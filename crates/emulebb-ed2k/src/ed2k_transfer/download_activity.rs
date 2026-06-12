use std::time::{Duration, Instant};

use super::Ed2kTransferRuntime;

const DOWNLOAD_ACTIVITY_STALE_AFTER: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub(super) struct Ed2kDownloadActivity {
    started_at: Instant,
    last_seen_at: Instant,
    downloaded_bytes: u64,
}

impl Ed2kTransferRuntime {
    pub(crate) fn note_download_payload_bytes(&self, file_hash: &str, byte_count: u64) {
        self.note_download_payload_bytes_at(file_hash, byte_count, Instant::now());
    }

    pub(crate) fn note_download_payload_bytes_at(
        &self,
        file_hash: &str,
        byte_count: u64,
        now: Instant,
    ) {
        if byte_count == 0 {
            return;
        }
        let Ok(mut activity) = self.download_activity.lock() else {
            return;
        };
        let entry = activity
            .entry(file_hash.to_string())
            .or_insert_with(|| Ed2kDownloadActivity {
                started_at: now,
                last_seen_at: now,
                downloaded_bytes: 0,
            });
        entry.last_seen_at = now;
        entry.downloaded_bytes = entry.downloaded_bytes.saturating_add(byte_count);
    }

    pub fn download_speed_bytes_per_sec(&self, file_hash: &str) -> u64 {
        self.download_speed_bytes_per_sec_at(file_hash, Instant::now())
    }

    pub(crate) fn download_speed_bytes_per_sec_at(&self, file_hash: &str, now: Instant) -> u64 {
        let Ok(activity) = self.download_activity.lock() else {
            return 0;
        };
        let Some(entry) = activity.get(file_hash) else {
            return 0;
        };
        if now.saturating_duration_since(entry.last_seen_at) > DOWNLOAD_ACTIVITY_STALE_AFTER {
            return 0;
        }
        let elapsed_ms = now
            .saturating_duration_since(entry.started_at)
            .as_millis()
            .max(1);
        ((u128::from(entry.downloaded_bytes) * 1_000) / elapsed_ms)
            .try_into()
            .unwrap_or(u64::MAX)
    }
}
