//! Coarse adaptive admission; actual producers retain their existing budgets.
use emulebb_ed2k::ed2k_transfer::DownloadResourceSnapshot;

pub(crate) const SOFT_RESIDENT_BYTES: usize = 64 * 1024 * 1024;
const PEER_FRAME_BYTES: usize = 2_000_000;
const INITIAL_ACTIVE: usize = 16;
const INITIAL_PREPARING: usize = 2;

pub(crate) struct MemorySampler {
    system: Option<sysinfo::System>,
    #[cfg(test)]
    available: Option<u64>,
}
impl MemorySampler {
    pub(crate) fn new() -> Self {
        Self {
            system: None,
            #[cfg(test)]
            available: None,
        }
    }
    #[cfg(test)]
    pub(crate) fn with_available(bytes: u64) -> Self {
        Self {
            system: None,
            available: Some(bytes),
        }
    }
    pub(crate) async fn available(&mut self) -> Option<u64> {
        #[cfg(test)]
        if let Some(bytes) = self.available {
            return Some(bytes);
        }
        let previous = self.system.take();
        let (system, available) = tokio::task::spawn_blocking(move || {
            // Retry a failed initialization on the next sample.
            let mut system = previous.or_else(|| sysinfo::System::new().ok())?;
            system.refresh_memory();
            let available = if system.total_memory() == 0 {
                None
            } else {
                let host = system.available_memory();
                Some(system.cgroup_limits().map_or(host, |limit| {
                    cgroup_available_memory(
                        host,
                        limit.total_memory,
                        limit.free_memory,
                        reclaimable_cgroup_file_bytes(),
                    )
                }))
            };
            Some((system, available))
        })
        .await
        .ok()
        .flatten()?;
        self.system = Some(system);
        available
    }
}

fn cgroup_available_memory(host: u64, total: u64, free: u64, reclaimable: u64) -> u64 {
    host.min(free.saturating_add(reclaimable).min(total))
}

// File scans can fill a cgroup with clean cache without exhausting its working
// memory. Count only inactive file cache, conservatively excluding dirty and
// writeback bytes; never count anonymous memory or swap as available.
#[cfg(any(target_os = "linux", test))]
fn reclaimable_file_bytes(stat: &str, keys: [&str; 3]) -> u64 {
    let mut values = [None; 3];
    for line in stat.lines() {
        let mut fields = line.split_whitespace();
        if let Some(key) = fields.next()
            && let Some(index) = keys.iter().position(|candidate| *candidate == key)
        {
            values[index] = fields.next().and_then(|value| value.parse::<u64>().ok());
        }
    }
    match values {
        [Some(inactive), Some(dirty), Some(writeback)] => {
            inactive.saturating_sub(dirty.saturating_add(writeback))
        }
        _ => 0,
    }
}

#[cfg(target_os = "linux")]
fn reclaimable_cgroup_file_bytes() -> u64 {
    if let Ok(stat) = std::fs::read_to_string("/sys/fs/cgroup/memory.stat") {
        reclaimable_file_bytes(&stat, ["inactive_file", "file_dirty", "file_writeback"])
    } else if let Ok(stat) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.stat") {
        reclaimable_file_bytes(
            &stat,
            ["total_inactive_file", "total_dirty", "total_writeback"],
        )
    } else {
        0
    }
}

#[cfg(not(target_os = "linux"))]
fn reclaimable_cgroup_file_bytes() -> u64 {
    0
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AdmissionWindow {
    pub active: usize,
    pub burst: usize,
    pub preparing: usize,
    pub total: usize,
}
impl Default for AdmissionWindow {
    fn default() -> Self {
        Self {
            active: INITIAL_ACTIVE,
            burst: INITIAL_ACTIVE.div_ceil(4),
            preparing: INITIAL_PREPARING,
            total: INITIAL_ACTIVE + INITIAL_PREPARING,
        }
    }
}

pub(crate) fn construction_starts(native: DownloadResourceSnapshot) -> usize {
    let connection_free =
        native.connection_limit == 0 || native.connections < native.connection_limit;
    if connection_free {
        hydration_starts(native)
    } else {
        0
    }
}

/// A prepared socket already owns its connection; local hydration needs no new one.
pub(crate) fn hydration_starts(native: DownloadResourceSnapshot) -> usize {
    let transient_free =
        native.transient_bytes < native.transient_limit && native.free_work_units > 0;
    let headroom = native.construction_bytes.saturating_mul(4);
    let free = native
        .resident_limit
        .saturating_sub(native.resident_bytes)
        .saturating_sub(headroom);
    if transient_free {
        free / native.construction_bytes.max(1)
    } else {
        0
    }
}

pub(crate) fn next_window(
    previous: AdmissionWindow,
    native: DownloadResourceSnapshot,
    available: Option<u64>,
    peers: usize,
    active: usize,
) -> AdmissionWindow {
    let peers = peers.max(1);
    // Include maximum peer frames as well as construction workspace in the
    // host estimate. Keep half of currently available memory uncommitted.
    // This estimate cannot replace Native resident/packet/connection admission.
    let working = native
        .construction_bytes
        .saturating_add(peers.saturating_mul(PEER_FRAME_BYTES))
        .max(1);
    let host = available.map_or(INITIAL_ACTIVE + INITIAL_PREPARING, |bytes| {
        usize::try_from(bytes / 2).unwrap_or(usize::MAX) / working
    });
    let connections = if native.connection_limit == 0 {
        usize::MAX
    } else {
        (native.connection_limit / peers).max(1)
    };
    let total = host.min(connections);
    let mut target = previous.active.min(total);
    let connection_free =
        native.connection_limit == 0 || native.connections < native.connection_limit;
    let transient_free =
        native.transient_bytes < native.transient_limit && native.free_work_units > 0;
    let starts = construction_starts(native);
    let preparing = if connection_free && transient_free {
        INITIAL_PREPARING.min(total)
    } else {
        0
    };
    if native.resident_bytes > SOFT_RESIDENT_BYTES {
        target = target.saturating_sub(1);
    } else if starts > 0 && active >= target {
        target = target.saturating_add(1).min(total);
    }
    AdmissionWindow {
        active: target,
        burst: if hydration_starts(native) > 0 && native.resident_bytes <= SOFT_RESIDENT_BYTES {
            target.div_ceil(4)
        } else {
            0
        },
        preparing,
        total,
    }
}

#[cfg(test)]
mod tests;
