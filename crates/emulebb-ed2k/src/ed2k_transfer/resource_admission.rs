//! Scalar admission inputs; these observations never grant allocation authority.
use super::Ed2kTransferRuntime;

#[derive(Debug, Clone, Copy)]
pub struct DownloadResourceSnapshot {
    pub resident_bytes: usize,
    pub resident_limit: usize,
    pub construction_bytes: usize,
    pub transient_bytes: usize,
    pub transient_limit: usize,
    pub free_work_units: usize,
    pub connections: usize,
    pub connection_limit: usize,
}

impl Ed2kTransferRuntime {
    /// Coarse scheduler sample only: every producer still needs its own Native
    /// reservation. Read independent short controls without a cache/SQL lock.
    pub fn download_resource_snapshot(&self) -> DownloadResourceSnapshot {
        let (resident_bytes, resident_limit, construction_bytes) =
            self.local_mutations.residents.budget_snapshot();
        let (transient_bytes, transient_limit, free_work_units) =
            self.local_mutations.resource_capacity();
        let coordinator = self.download_coordinator.lock();
        DownloadResourceSnapshot {
            resident_bytes,
            resident_limit,
            construction_bytes,
            transient_bytes,
            transient_limit,
            free_work_units,
            connections: coordinator.active_connections(),
            connection_limit: coordinator.config().max_connections,
        }
    }
}
