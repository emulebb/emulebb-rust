use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::Ed2kTransferRuntime;

const DOWNLOAD_ACTIVITY_STALE_AFTER: Duration = Duration::from_secs(30);
/// A source counts as actively transferring when it delivered payload within
/// this window. Shorter than the live-source window so "transferring" reflects
/// genuinely active peers, not merely recently-seen ones.
const SOURCE_TRANSFERRING_AFTER: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub(super) struct Ed2kDownloadActivity {
    started_at: Instant,
    last_seen_at: Instant,
    downloaded_bytes: u64,
}

/// Live per-source download state for one peer of one file. In-memory only.
#[derive(Debug, Clone)]
pub(super) struct Ed2kSourceActivity {
    endpoint: SocketAddr,
    user_hash: Option<[u8; 16]>,
    first_seen_at: Instant,
    last_seen_at: Instant,
    last_payload_at: Option<Instant>,
    downloaded_bytes: u64,
    /// Per-part availability advertised by the peer (OP_FILESTATUS). `None`
    /// until a status frame is seen.
    part_bitmap: Option<Vec<bool>>,
}

/// Snapshot of one live source for the REST transfer-source/detail views.
#[derive(Debug, Clone)]
pub struct Ed2kLiveSource {
    pub endpoint: SocketAddr,
    pub user_hash: Option<[u8; 16]>,
    pub download_speed_bytes_per_sec: u64,
    pub transferring: bool,
    pub available_parts: u32,
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
        // Session-wide received-payload counter (oracle theStats.sessionReceivedBytes).
        self.session_downloaded_bytes
            .fetch_add(byte_count, std::sync::atomic::Ordering::Relaxed);
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

    /// Record live payload from a specific peer for the per-source registry.
    /// Called alongside `note_download_payload_bytes` from the download runtime.
    pub(crate) fn note_download_source_bytes(
        &self,
        file_hash: &str,
        peer: SocketAddr,
        user_hash: Option<[u8; 16]>,
        byte_count: u64,
    ) {
        self.note_download_source_bytes_at(file_hash, peer, user_hash, byte_count, Instant::now());
    }

    pub(crate) fn note_download_source_bytes_at(
        &self,
        file_hash: &str,
        peer: SocketAddr,
        user_hash: Option<[u8; 16]>,
        byte_count: u64,
        now: Instant,
    ) {
        let Ok(mut sources) = self.download_sources.lock() else {
            return;
        };
        let entry = sources
            .entry(file_hash.to_string())
            .or_default()
            .entry(peer.to_string())
            .or_insert_with(|| Ed2kSourceActivity {
                endpoint: peer,
                user_hash,
                first_seen_at: now,
                last_seen_at: now,
                last_payload_at: None,
                downloaded_bytes: 0,
                part_bitmap: None,
            });
        entry.endpoint = peer;
        if user_hash.is_some() {
            entry.user_hash = user_hash;
        }
        entry.last_seen_at = now;
        if byte_count > 0 {
            entry.last_payload_at = Some(now);
            entry.downloaded_bytes = entry.downloaded_bytes.saturating_add(byte_count);
        }
    }

    /// Record the peer's advertised per-part availability (OP_FILESTATUS).
    pub(crate) fn note_download_source_part_bitmap(
        &self,
        file_hash: &str,
        peer: SocketAddr,
        user_hash: Option<[u8; 16]>,
        bitmap: Vec<bool>,
    ) {
        let now = Instant::now();
        let Ok(mut sources) = self.download_sources.lock() else {
            return;
        };
        let entry = sources
            .entry(file_hash.to_string())
            .or_default()
            .entry(peer.to_string())
            .or_insert_with(|| Ed2kSourceActivity {
                endpoint: peer,
                user_hash,
                first_seen_at: now,
                last_seen_at: now,
                last_payload_at: None,
                downloaded_bytes: 0,
                part_bitmap: None,
            });
        entry.endpoint = peer;
        if user_hash.is_some() {
            entry.user_hash = user_hash;
        }
        entry.last_seen_at = now;
        entry.part_bitmap = Some(bitmap);
    }

    /// Drop the live-source registry for a file (e.g. on transfer removal).
    pub(crate) fn clear_download_sources(&self, file_hash: &str) {
        if let Ok(mut sources) = self.download_sources.lock() {
            sources.remove(file_hash);
        }
    }

    /// Live sources currently known for a file, pruned of stale entries.
    pub fn live_download_sources(&self, file_hash: &str) -> Vec<Ed2kLiveSource> {
        self.live_download_sources_at(file_hash, Instant::now())
    }

    pub(crate) fn live_download_sources_at(
        &self,
        file_hash: &str,
        now: Instant,
    ) -> Vec<Ed2kLiveSource> {
        let Ok(sources) = self.download_sources.lock() else {
            return Vec::new();
        };
        let Some(peers) = sources.get(file_hash) else {
            return Vec::new();
        };
        peers
            .values()
            .filter(|peer| !is_stale(peer.last_seen_at, now))
            .map(|peer| Ed2kLiveSource {
                endpoint: peer.endpoint,
                user_hash: peer.user_hash,
                download_speed_bytes_per_sec: source_speed_bytes_per_sec(peer, now),
                transferring: is_transferring(peer, now),
                available_parts: peer
                    .part_bitmap
                    .as_ref()
                    .map(|bitmap| bitmap.iter().filter(|present| **present).count() as u32)
                    .unwrap_or(0),
            })
            .collect()
    }

    /// Number of sources actively transferring payload for a file.
    pub fn transferring_source_count(&self, file_hash: &str) -> u32 {
        self.transferring_source_count_at(file_hash, Instant::now())
    }

    pub(crate) fn transferring_source_count_at(&self, file_hash: &str, now: Instant) -> u32 {
        let Ok(sources) = self.download_sources.lock() else {
            return 0;
        };
        let Some(peers) = sources.get(file_hash) else {
            return 0;
        };
        peers
            .values()
            .filter(|peer| is_transferring(peer, now))
            .count() as u32
    }

    /// Per-part count of live sources advertising each part (index 0..part_total).
    pub fn available_sources_per_part(&self, file_hash: &str, part_total: u32) -> Vec<u32> {
        self.available_sources_per_part_at(file_hash, part_total, Instant::now())
    }

    pub(crate) fn available_sources_per_part_at(
        &self,
        file_hash: &str,
        part_total: u32,
        now: Instant,
    ) -> Vec<u32> {
        let mut counts = vec![0u32; part_total as usize];
        let Ok(sources) = self.download_sources.lock() else {
            return counts;
        };
        let Some(peers) = sources.get(file_hash) else {
            return counts;
        };
        for peer in peers.values() {
            if is_stale(peer.last_seen_at, now) {
                continue;
            }
            let Some(bitmap) = peer.part_bitmap.as_ref() else {
                continue;
            };
            for (index, present) in bitmap.iter().enumerate() {
                if *present {
                    if let Some(slot) = counts.get_mut(index) {
                        *slot = slot.saturating_add(1);
                    }
                }
            }
        }
        counts
    }

    /// Number of parts available from at least one live source.
    pub fn available_part_count(&self, file_hash: &str, part_total: u32) -> u32 {
        self.available_sources_per_part(file_hash, part_total)
            .into_iter()
            .filter(|count| *count > 0)
            .count() as u32
    }

    pub fn download_speed_bytes_per_sec(&self, file_hash: &str) -> u64 {
        self.download_speed_bytes_per_sec_at(file_hash, Instant::now())
    }

    /// Aggregate live download rate across every active file (oracle
    /// `CDownloadQueue::GetDatarate`). Sums the per-file rates so the REST stats
    /// `downloadSpeedKiBps` reflects the whole download queue, not one transfer.
    pub fn aggregate_download_speed_bytes_per_sec(&self) -> u64 {
        self.aggregate_download_speed_bytes_per_sec_at(Instant::now())
    }

    pub(crate) fn aggregate_download_speed_bytes_per_sec_at(&self, now: Instant) -> u64 {
        let Ok(activity) = self.download_activity.lock() else {
            return 0;
        };
        activity
            .iter()
            .filter(|(_, entry)| {
                now.saturating_duration_since(entry.last_seen_at) <= DOWNLOAD_ACTIVITY_STALE_AFTER
            })
            .map(|(_, entry)| {
                let elapsed_ms = now
                    .saturating_duration_since(entry.started_at)
                    .as_millis()
                    .max(1);
                u64::try_from((u128::from(entry.downloaded_bytes) * 1_000) / elapsed_ms)
                    .unwrap_or(u64::MAX)
            })
            .fold(0u64, |acc, rate| acc.saturating_add(rate))
    }

    /// Total payload bytes received since the runtime started
    /// (`sessionDownloadedBytes`, oracle `theStats.sessionReceivedBytes`).
    pub fn session_downloaded_bytes(&self) -> u64 {
        self.session_downloaded_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total payload bytes sent since the runtime started
    /// (`sessionUploadedBytes`, oracle `theStats.sessionSentBytes`).
    pub fn session_uploaded_bytes(&self) -> u64 {
        self.session_uploaded_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record session-wide sent-payload bytes (oracle `theStats.sessionSentBytes`).
    pub(crate) fn note_session_uploaded_bytes(&self, byte_count: u64) {
        if byte_count == 0 {
            return;
        }
        self.session_uploaded_bytes
            .fetch_add(byte_count, std::sync::atomic::Ordering::Relaxed);
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

fn is_stale(last_seen_at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last_seen_at) > DOWNLOAD_ACTIVITY_STALE_AFTER
}

fn is_transferring(peer: &Ed2kSourceActivity, now: Instant) -> bool {
    peer.last_payload_at
        .is_some_and(|at| now.saturating_duration_since(at) <= SOURCE_TRANSFERRING_AFTER)
}

fn source_speed_bytes_per_sec(peer: &Ed2kSourceActivity, now: Instant) -> u64 {
    if !is_transferring(peer, now) {
        return 0;
    }
    let elapsed_ms = now
        .saturating_duration_since(peer.first_seen_at)
        .as_millis()
        .max(1);
    ((u128::from(peer.downloaded_bytes) * 1_000) / elapsed_ms)
        .try_into()
        .unwrap_or(u64::MAX)
}
