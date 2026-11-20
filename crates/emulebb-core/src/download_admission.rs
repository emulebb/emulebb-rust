//! Coarse adaptive admission; actual producers retain their existing budgets.
use emulebb_ed2k::ed2k_transfer::DownloadResourceSnapshot;

const SOFT_RESIDENT_BYTES: usize = 64 * 1024 * 1024;
const PEER_FRAME_BYTES: usize = 2_000_000;
const INITIAL_ACTIVE: usize = 16;
const INITIAL_PREPARING: usize = 2;

pub(crate) struct MemorySampler(Option<sysinfo::System>);
impl MemorySampler {
    pub(crate) fn new() -> Self {
        Self(Some(sysinfo::System::new()))
    }
    pub(crate) async fn available(&mut self) -> Option<u64> {
        let mut system = self.0.take()?;
        let result = tokio::task::spawn_blocking(move || {
            system.refresh_memory();
            let available = if system.total_memory() == 0 {
                None
            } else {
                let host = system.available_memory();
                Some(
                    system
                        .cgroup_limits()
                        .map_or(host, |limit| host.min(limit.free_memory)),
                )
            };
            (system, available)
        })
        .await;
        match result {
            Ok((system, available)) => {
                self.0 = Some(system);
                available
            }
            Err(_) => {
                self.0 = Some(sysinfo::System::new());
                None
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AdmissionWindow {
    pub active: usize,
    pub preparing: usize,
    pub total: usize,
}
impl Default for AdmissionWindow {
    fn default() -> Self {
        Self {
            active: INITIAL_ACTIVE,
            preparing: INITIAL_PREPARING,
            total: INITIAL_ACTIVE + INITIAL_PREPARING,
        }
    }
}

pub(crate) fn construction_starts(native: DownloadResourceSnapshot) -> usize {
    let connection_free =
        native.connection_limit == 0 || native.connections < native.connection_limit;
    let transient_free =
        native.transient_bytes < native.transient_limit && native.free_work_units > 0;
    let headroom = native.construction_bytes.saturating_mul(4);
    let free = native
        .resident_limit
        .saturating_sub(native.resident_bytes)
        .saturating_sub(headroom);
    if connection_free && transient_free {
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
        preparing,
        total,
    }
}

#[cfg(test)]
mod tests;
