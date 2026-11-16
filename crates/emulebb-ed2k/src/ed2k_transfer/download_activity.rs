use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::Ed2kTransferRuntime;
use emulebb_metadata::JobToken;

const DOWNLOAD_ACTIVITY_STALE_AFTER: Duration = Duration::from_secs(30);
/// Retain source protocol knowledge through the stock per-source reask cadence.
/// Activity/rate views still expire after 30 seconds, but part availability must
/// survive long enough to build the next 29-minute UDP reask accurately.
const DOWNLOAD_SOURCE_PROTOCOL_STALE_AFTER: Duration = Duration::from_secs(40 * 60);
/// A source counts as actively transferring when it delivered payload within
/// this window. Shorter than the live-source window so "transferring" reflects
/// genuinely active peers, not merely recently-seen ones.
const SOURCE_TRANSFERRING_AFTER: Duration = Duration::from_secs(10);
/// Sliding-window span for the reported data rate (master
/// `CUpDownClient::CalculateDownloadRate`, which divides the summed history by
/// the elapsed time of the oldest retained sample). ~10s keeps the rate tracking
/// current throughput rather than the whole-transfer average.
const DATARATE_WINDOW: Duration = Duration::from_secs(10);

/// A short ring of recent `(timestamp, bytes)` payload samples used to compute a
/// sliding-window data rate (eMule `m_AverageDDR_hist`). Samples older than
/// [`DATARATE_WINDOW`] are pruned; the rate is summed bytes over the span from
/// the oldest retained sample, so it reflects current throughput.
#[derive(Debug, Clone, Default)]
struct DatarateWindow {
    samples: VecDeque<(Instant, u64)>,
}

impl DatarateWindow {
    fn record(&mut self, now: Instant, byte_count: u64) {
        self.samples.push_back((now, byte_count));
        self.prune(now);
    }

    fn prune(&mut self, now: Instant) {
        while let Some(&(ts, _)) = self.samples.front() {
            if now.saturating_duration_since(ts) > DATARATE_WINDOW {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    /// Bytes/sec over the window: summed bytes / span since the oldest retained
    /// sample (eMule divides the summed history by `now - head.timestamp`). The
    /// divisor is floored at 1ms so a burst whose samples collapse onto one
    /// instant still reports a rate rather than zero. Returns 0 with no samples.
    fn rate_bytes_per_sec(&self, now: Instant) -> u64 {
        let Some(&(oldest_ts, _)) = self.samples.front() else {
            return 0;
        };
        let span_ms = now.saturating_duration_since(oldest_ts).as_millis().max(1);
        let total: u128 = self
            .samples
            .iter()
            .map(|&(_, bytes)| u128::from(bytes))
            .sum();
        u64::try_from((total * 1_000) / span_ms).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone)]
pub(super) struct Ed2kDownloadActivity {
    last_seen_at: Instant,
    window: DatarateWindow,
    /// Total payload bytes received this session for the file (live, per-block).
    /// Lets the REST transfer surface in-flight progress before whole 9.28 MB
    /// parts verify (the persisted manifest only counts verified parts).
    session_bytes: u64,
}

/// Live per-source download state for one peer of one file. In-memory only.
#[derive(Debug, Clone)]
pub(super) struct Ed2kSourceActivity {
    endpoint: SocketAddr,
    user_hash: Option<[u8; 16]>,
    connect_options: Option<u8>,
    last_seen_at: Instant,
    last_payload_at: Option<Instant>,
    window: DatarateWindow,
    /// Per-part availability advertised by the peer (OP_FILESTATUS). `None`
    /// until a status frame is seen.
    part_bitmap: Option<Vec<bool>>,
    /// Our queue position at this peer (OP_QUEUERANK / OP_QUEUERANKING). `None`
    /// until the peer sends a ranking.
    queue_rank: Option<u32>,
    /// Peer software string from the HELLO CT_EMULE_VERSION tag (e.g.
    /// `eMule v0.60.0`). `None` until the peer's hello is seen.
    client_software: Option<String>,
}

/// Snapshot of one live source for the REST transfer-source/detail views.
#[derive(Debug, Clone)]
pub struct Ed2kLiveSource {
    pub endpoint: SocketAddr,
    pub user_hash: Option<[u8; 16]>,
    pub connect_options: Option<u8>,
    /// Exact per-part availability advertised by this source. Kept in the
    /// public snapshot so source exchange can apply the requester's part-needed
    /// filter instead of reducing the state to a count.
    pub part_bitmap: Option<Vec<bool>>,
    pub download_speed_bytes_per_sec: u64,
    pub transferring: bool,
    pub available_parts: u32,
    pub queue_rank: Option<u32>,
    pub client_software: Option<String>,
}

impl Ed2kTransferRuntime {
    pub(crate) fn note_download_payload_bytes(&self, token: JobToken, byte_count: u64) {
        self.note_download_payload_bytes_at(token, byte_count, Instant::now());
    }

    pub(crate) fn note_download_payload_bytes_at(
        &self,
        token: JobToken,
        byte_count: u64,
        now: Instant,
    ) {
        let Some(_session) = self.active_job_session(token) else {
            return;
        };
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
            .entry(token)
            .or_insert_with(|| Ed2kDownloadActivity {
                last_seen_at: now,
                window: DatarateWindow::default(),
                session_bytes: 0,
            });
        entry.last_seen_at = now;
        entry.window.record(now, byte_count);
        entry.session_bytes = entry.session_bytes.saturating_add(byte_count);
    }

    /// Total download payload bytes received this session for a file (live,
    /// per-block; resets on restart). Surfaced in the REST transfer so in-flight
    /// progress is visible even before whole parts verify.
    pub fn downloaded_session_bytes(&self, token: JobToken) -> u64 {
        self.download_activity
            .lock()
            .ok()
            .and_then(|activity| activity.get(&token).map(|entry| entry.session_bytes))
            .unwrap_or(0)
    }

    /// Record live payload from a specific peer for the per-source registry.
    /// Called alongside `note_download_payload_bytes` from the download runtime.
    pub(crate) fn note_download_source_bytes(
        &self,
        token: JobToken,
        peer: SocketAddr,
        user_hash: Option<[u8; 16]>,
        connect_options: Option<u8>,
        byte_count: u64,
    ) {
        self.note_download_source_bytes_at(
            token,
            peer,
            user_hash,
            connect_options,
            byte_count,
            Instant::now(),
        );
    }

    pub(crate) fn note_download_source_bytes_at(
        &self,
        token: JobToken,
        peer: SocketAddr,
        user_hash: Option<[u8; 16]>,
        connect_options: Option<u8>,
        byte_count: u64,
        now: Instant,
    ) {
        let Some(_session) = self.active_job_session(token) else {
            return;
        };
        let Ok(mut sources) = self.download_sources.lock() else {
            return;
        };
        let peers = sources.entry(token).or_default();
        // Opportunistically evict stale peers so a long-running transfer's inner
        // map stays bounded to the live set rather than growing with every
        // endpoint ever observed (entries were previously only freed on transfer
        // removal). The peer we are about to touch uses the freshest `now`, so it
        // is never a candidate for eviction here.
        evict_stale_sources(peers, now);
        let entry = peers
            .entry(peer.to_string())
            .or_insert_with(|| Ed2kSourceActivity {
                endpoint: peer,
                user_hash,
                connect_options,
                last_seen_at: now,
                last_payload_at: None,
                window: DatarateWindow::default(),
                part_bitmap: None,
                queue_rank: None,
                client_software: None,
            });
        entry.endpoint = peer;
        if user_hash.is_some() {
            entry.user_hash = user_hash;
        }
        if connect_options.is_some() {
            entry.connect_options = connect_options;
        }
        entry.last_seen_at = now;
        if byte_count > 0 {
            entry.last_payload_at = Some(now);
            entry.window.record(now, byte_count);
        }
        #[cfg(feature = "packet-diagnostics")]
        let software = entry.client_software.clone();
        drop(sources);
        #[cfg(feature = "packet-diagnostics")]
        if byte_count > 0 {
            // WHY: a discovered source or packet receive does not prove usable
            // cross-client transfer; record bytes only after the block path
            // accepted them, keyed to the same peer and file as its HELLO tag.
            crate::diag_event::emit(
                "sched",
                "download_payload_accepted",
                "info",
                serde_json::json!({ "jobId": token.job_id.to_string(), "generation": token.generation, "peer": peer.to_string() }),
                serde_json::json!({ "bytes": byte_count, "clientSoftware": software }),
            );
        }
    }

    /// Record the peer's advertised per-part availability (OP_FILESTATUS).
    /// Returns whether the live-source registry accepted the update.
    pub(crate) fn note_download_source_part_bitmap(
        &self,
        token: JobToken,
        peer: SocketAddr,
        user_hash: Option<[u8; 16]>,
        connect_options: Option<u8>,
        bitmap: Vec<bool>,
    ) -> bool {
        self.note_download_source_part_bitmap_at(
            token,
            peer,
            user_hash,
            connect_options,
            bitmap,
            Instant::now(),
        )
    }

    pub(crate) fn note_download_source_part_bitmap_at(
        &self,
        token: JobToken,
        peer: SocketAddr,
        user_hash: Option<[u8; 16]>,
        connect_options: Option<u8>,
        bitmap: Vec<bool>,
        now: Instant,
    ) -> bool {
        let Some(_session) = self.active_job_session(token) else {
            return false;
        };
        let Ok(mut sources) = self.download_sources.lock() else {
            return false;
        };
        let peers = sources.entry(token).or_default();
        evict_stale_sources(peers, now);
        let entry = peers
            .entry(peer.to_string())
            .or_insert_with(|| Ed2kSourceActivity {
                endpoint: peer,
                user_hash,
                connect_options,
                last_seen_at: now,
                last_payload_at: None,
                window: DatarateWindow::default(),
                part_bitmap: None,
                queue_rank: None,
                client_software: None,
            });
        entry.endpoint = peer;
        if user_hash.is_some() {
            entry.user_hash = user_hash;
        }
        if connect_options.is_some() {
            entry.connect_options = connect_options;
        }
        entry.last_seen_at = now;
        entry.part_bitmap = Some(bitmap);
        true
    }

    /// Count sources whose retained protocol status advertises every file part.
    /// This deliberately outlives the 30-second activity view: stock includes
    /// queued, TCP-detached sources in the complete-source count carried by the
    /// next client-UDP reask.
    pub(crate) fn known_complete_source_count(&self, token: JobToken, total_parts: usize) -> u16 {
        self.known_complete_source_count_at(token, total_parts, Instant::now())
    }

    pub(crate) fn known_complete_source_count_at(
        &self,
        token: JobToken,
        total_parts: usize,
        now: Instant,
    ) -> u16 {
        if total_parts == 0 {
            return 0;
        }
        let Ok(sources) = self.download_sources.lock() else {
            return 0;
        };
        let Some(peers) = sources.get(&token) else {
            return 0;
        };
        peers
            .values()
            .filter(|peer| !is_protocol_stale(peer.last_seen_at, now))
            .filter(|peer| {
                peer.part_bitmap.as_ref().is_some_and(|bitmap| {
                    bitmap.len() == total_parts && bitmap.iter().all(|present| *present)
                })
            })
            .count()
            .min(usize::from(u16::MAX)) as u16
    }

    /// Record our queue position at a peer (OP_QUEUERANK / OP_QUEUERANKING) so the
    /// REST source list can show it. The session entry usually already exists from
    /// a payload/status frame; create a minimal one if the ranking arrives first.
    /// Returns whether the live-source registry accepted the update.
    pub(crate) fn note_download_source_queue_rank(
        &self,
        token: JobToken,
        peer: SocketAddr,
        rank: u32,
    ) -> bool {
        let Some(_session) = self.active_job_session(token) else {
            return false;
        };
        let now = Instant::now();
        let Ok(mut sources) = self.download_sources.lock() else {
            return false;
        };
        let peers = sources.entry(token).or_default();
        evict_stale_sources(peers, now);
        let entry = peers
            .entry(peer.to_string())
            .or_insert_with(|| Ed2kSourceActivity {
                endpoint: peer,
                user_hash: None,
                connect_options: None,
                last_seen_at: now,
                last_payload_at: None,
                window: DatarateWindow::default(),
                part_bitmap: None,
                queue_rank: None,
                client_software: None,
            });
        entry.last_seen_at = now;
        entry.queue_rank = Some(rank);
        true
    }

    /// Record the peer's software string (from the HELLO CT_EMULE_VERSION tag) so
    /// the REST source list can show which client each source runs.
    pub(crate) fn note_download_source_software(
        &self,
        token: JobToken,
        peer: SocketAddr,
        software: String,
    ) {
        let Some(_session) = self.active_job_session(token) else {
            return;
        };
        let now = Instant::now();
        let Ok(mut sources) = self.download_sources.lock() else {
            return;
        };
        let peers = sources.entry(token).or_default();
        evict_stale_sources(peers, now);
        let entry = peers
            .entry(peer.to_string())
            .or_insert_with(|| Ed2kSourceActivity {
                endpoint: peer,
                user_hash: None,
                connect_options: None,
                last_seen_at: now,
                last_payload_at: None,
                window: DatarateWindow::default(),
                part_bitmap: None,
                queue_rank: None,
                client_software: None,
            });
        entry.last_seen_at = now;
        #[cfg(feature = "packet-diagnostics")]
        let diagnostic_software = software.clone();
        entry.client_software = Some(software);
        drop(sources);
        #[cfg(feature = "packet-diagnostics")]
        crate::diag_event::emit(
            "sched",
            "download_source_software",
            "info",
            serde_json::json!({ "jobId": token.job_id.to_string(), "generation": token.generation, "peer": peer.to_string() }),
            serde_json::json!({ "clientSoftware": diagnostic_software }),
        );
    }

    /// Drop the live-source registry for a file (e.g. on transfer removal).
    pub(crate) fn clear_download_sources(&self, token: JobToken) {
        if let Ok(mut sources) = self.download_sources.lock() {
            sources.remove(&token);
        }
    }

    /// Borrow protocol evidence while constructing one bounded outgoing list.
    /// The visitor performs no I/O, awaits or reentry and returns false to stop.
    pub(crate) fn visit_live_source_protocol(
        &self,
        token: JobToken,
        mut visit: impl FnMut(SocketAddr, Option<[u8; 16]>, Option<u8>, Option<&[bool]>) -> bool,
    ) {
        let Ok(sources) = self.download_sources.lock() else {
            return;
        };
        let Some(peers) = sources.get(&token) else {
            return;
        };
        let now = Instant::now();
        for peer in peers
            .values()
            .filter(|peer| !is_activity_stale(peer.last_seen_at, now))
        {
            if !visit(
                peer.endpoint,
                peer.user_hash,
                peer.connect_options,
                peer.part_bitmap.as_deref(),
            ) {
                break;
            }
        }
    }

    /// Live sources currently known for a file, pruned of stale entries.
    pub fn live_download_sources(&self, token: JobToken) -> Vec<Ed2kLiveSource> {
        self.live_download_sources_at(token, Instant::now())
    }

    pub(crate) fn live_download_sources_at(
        &self,
        token: JobToken,
        now: Instant,
    ) -> Vec<Ed2kLiveSource> {
        let Ok(sources) = self.download_sources.lock() else {
            return Vec::new();
        };
        let Some(peers) = sources.get(&token) else {
            return Vec::new();
        };
        peers
            .values()
            .filter(|peer| !is_activity_stale(peer.last_seen_at, now))
            .map(|peer| Ed2kLiveSource {
                endpoint: peer.endpoint,
                user_hash: peer.user_hash,
                connect_options: peer.connect_options,
                part_bitmap: peer.part_bitmap.clone(),
                download_speed_bytes_per_sec: source_speed_bytes_per_sec(peer, now),
                transferring: is_transferring(peer, now),
                available_parts: peer
                    .part_bitmap
                    .as_ref()
                    .map(|bitmap| bitmap.iter().filter(|present| **present).count() as u32)
                    .unwrap_or(0),
                queue_rank: peer.queue_rank,
                client_software: peer.client_software.clone(),
            })
            .collect()
    }

    /// Number of sources actively transferring payload for a file.
    pub fn transferring_source_count(&self, token: JobToken) -> u32 {
        self.transferring_source_count_at(token, Instant::now())
    }

    pub(crate) fn transferring_source_count_at(&self, token: JobToken, now: Instant) -> u32 {
        let Ok(sources) = self.download_sources.lock() else {
            return 0;
        };
        let Some(peers) = sources.get(&token) else {
            return 0;
        };
        peers
            .values()
            .filter(|peer| is_transferring(peer, now))
            .count() as u32
    }

    /// Per-part count of live sources advertising each part (index 0..part_total).
    pub fn available_sources_per_part(&self, token: JobToken, part_total: u32) -> Vec<u32> {
        self.available_sources_per_part_at(token, part_total, Instant::now())
    }

    pub(crate) fn available_sources_per_part_at(
        &self,
        token: JobToken,
        part_total: u32,
        now: Instant,
    ) -> Vec<u32> {
        let mut counts = vec![0u32; part_total as usize];
        let Ok(sources) = self.download_sources.lock() else {
            return counts;
        };
        let Some(peers) = sources.get(&token) else {
            return counts;
        };
        for peer in peers.values() {
            if is_activity_stale(peer.last_seen_at, now) {
                continue;
            }
            let Some(bitmap) = peer.part_bitmap.as_ref() else {
                continue;
            };
            for (index, present) in bitmap.iter().enumerate() {
                if *present && let Some(slot) = counts.get_mut(index) {
                    *slot = slot.saturating_add(1);
                }
            }
        }
        counts
    }

    /// Number of parts available from at least one live source.
    pub fn available_part_count(&self, token: JobToken, part_total: u32) -> u32 {
        self.available_sources_per_part(token, part_total)
            .into_iter()
            .filter(|count| *count > 0)
            .count() as u32
    }

    pub fn download_speed_bytes_per_sec(&self, token: JobToken) -> u64 {
        self.download_speed_bytes_per_sec_at(token, Instant::now())
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
            .map(|(_, entry)| entry.window.rate_bytes_per_sec(now))
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

    pub(crate) fn download_speed_bytes_per_sec_at(&self, token: JobToken, now: Instant) -> u64 {
        let Ok(activity) = self.download_activity.lock() else {
            return 0;
        };
        let Some(entry) = activity.get(&token) else {
            return 0;
        };
        if now.saturating_duration_since(entry.last_seen_at) > DOWNLOAD_ACTIVITY_STALE_AFTER {
            return 0;
        }
        entry.window.rate_bytes_per_sec(now)
    }
}

fn is_activity_stale(last_seen_at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last_seen_at) > DOWNLOAD_ACTIVITY_STALE_AFTER
}

fn is_protocol_stale(last_seen_at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last_seen_at) > DOWNLOAD_SOURCE_PROTOCOL_STALE_AFTER
}

/// Drop per-source entries beyond the protocol-knowledge window. Activity views
/// independently hide entries after 30 seconds, while this longer bound keeps
/// file status available for the next stock-cadence UDP reask.
fn evict_stale_sources(peers: &mut HashMap<String, Ed2kSourceActivity>, now: Instant) {
    peers.retain(|_, peer| !is_protocol_stale(peer.last_seen_at, now));
}

fn is_transferring(peer: &Ed2kSourceActivity, now: Instant) -> bool {
    peer.last_payload_at
        .is_some_and(|at| now.saturating_duration_since(at) <= SOURCE_TRANSFERRING_AFTER)
}

fn source_speed_bytes_per_sec(peer: &Ed2kSourceActivity, now: Instant) -> u64 {
    if !is_transferring(peer, now) {
        return 0;
    }
    peer.window.rate_bytes_per_sec(now)
}
