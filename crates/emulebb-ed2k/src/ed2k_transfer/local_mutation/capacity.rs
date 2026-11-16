//! Capacity ownership independent of the task set and runtime graph.
use super::*;
use std::sync::{
    Condvar,
    atomic::{AtomicU64, Ordering},
};

#[derive(Debug, Default)]
pub(in crate::ed2k_transfer) struct CapacityControl {
    state: Mutex<Usage>,
    available: Condvar,
    pub(super) changed: tokio::sync::Notify,
    revision: AtomicU64,
    #[cfg(test)]
    phase_waiting: Mutex<Option<oneshot::Sender<()>>>,
    #[cfg(test)]
    probe_gate: Mutex<Option<(oneshot::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Usage {
    pub bytes: usize,
    pub long_fs_units: usize,
    pub long_fs_bytes: usize,
}
#[derive(Debug)]
pub(in crate::ed2k_transfer) struct CapacityLease {
    control: Arc<CapacityControl>,
    bytes: usize,
    fs_bytes: usize,
    eligible: bool,
}
impl CapacityControl {
    pub(super) fn reserve(
        self: &Arc<Self>,
        bytes: usize,
        eligible: bool,
        physical: bool,
    ) -> Result<CapacityLease> {
        let mut usage = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        ensure!(
            usage
                .bytes
                .checked_add(bytes)
                .is_some_and(|n| n <= MAX_BYTES)
                && (!eligible || usage.long_fs_units < MAX_LONG_FS_UNITS)
                && (!physical
                    || usage
                        .long_fs_bytes
                        .checked_add(bytes)
                        .is_some_and(|n| n <= MAX_LONG_FS_BYTES)),
            LocalMutationError::Busy
        );
        usage.bytes += bytes;
        usage.long_fs_units += usize::from(eligible);
        let fs_bytes = if physical { bytes } else { 0 };
        usage.long_fs_bytes += fs_bytes;
        Ok(CapacityLease {
            control: Arc::clone(self),
            bytes,
            fs_bytes,
            eligible,
        })
    }
    pub(in crate::ed2k_transfer) fn wake(&self) {
        self.revision.fetch_add(1, Ordering::Release);
        self.available.notify_all();
        self.changed.notify_waiters();
    }
    #[cfg(test)]
    pub(super) fn install_probe_gate(
        &self,
        reached: oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        *self.probe_gate.lock().unwrap() = Some((reached, release));
    }
    #[cfg(test)]
    pub(super) fn phase_wait_signal(&self) -> oneshot::Receiver<()> {
        let (sender, receiver) = oneshot::channel();
        *self.phase_waiting.lock().unwrap() = Some(sender);
        receiver
    }
    pub(super) fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }
    #[cfg(test)]
    pub(super) fn usage(&self) -> Usage {
        *self.state.lock().unwrap()
    }
}
impl CapacityLease {
    /// Admit separately allocated result backing while the source stays charged.
    /// This reuses the same byte budget and grants no task or filesystem slot.
    pub(super) fn reserve_result(&self, bytes: usize) -> Result<Self> {
        ensure!(
            self.fs_bytes == 0 && !self.eligible,
            "result still owns filesystem admission"
        );
        self.control.reserve(bytes, false, false)
    }
    pub(super) fn is_filesystem(&self) -> bool {
        self.fs_bytes != 0
    }
    /// Caller must first drop the buffers represented by the released charge.
    /// This control contains no store, runtime, task handles or join gate.
    pub(super) fn shrink(&mut self, bytes: usize) -> Result<()> {
        ensure!(
            bytes <= self.bytes && self.fs_bytes == 0,
            "invalid capacity shrink"
        );
        let mut usage = self
            .control
            .state
            .lock()
            .map_err(|_| LocalMutationError::Unknown)?;
        usage.bytes -= self.bytes - bytes;
        self.bytes = bytes;
        drop(usage);
        self.control.wake();
        Ok(())
    }
    /// Called only after releasing content/job guards and large SQL buffers.
    /// The original tracked worker and receipt remain owned while capacity waits.
    pub(super) fn enter_filesystem(&mut self, retained: usize, workspace: usize) -> Result<()> {
        ensure!(
            self.eligible
                && self.fs_bytes == 0
                && retained <= workspace
                && workspace <= MAX_LONG_FS_BYTES,
            "invalid filesystem capacity transition"
        );
        self.shrink(retained)?;
        let mut usage = self
            .control
            .state
            .lock()
            .map_err(|_| LocalMutationError::Unknown)?;
        while usage.long_fs_bytes + workspace > MAX_LONG_FS_BYTES
            || usage.bytes - self.bytes + workspace > MAX_BYTES
        {
            #[cfg(test)]
            if let Some(sender) = self.control.phase_waiting.lock().unwrap().take() {
                let _ = sender.send(());
            }
            usage = self
                .control
                .available
                .wait(usage)
                .map_err(|_| LocalMutationError::Unknown)?;
        }
        usage.bytes = usage.bytes - self.bytes + workspace;
        usage.long_fs_bytes += workspace;
        self.bytes = workspace;
        self.fs_bytes = workspace;
        drop(usage);
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn pause_after_probe(&self) {
        #[cfg(test)]
        if let Some((reached, release)) = self.control.probe_gate.lock().unwrap().take() {
            let _ = reached.send(());
            let _ = release.recv();
        }
    }
    /// Convert fresh admission evidence without waiting or releasing its physical
    /// allowance first. A refused transition has no side effects on the ledger.
    pub(super) fn try_enter_publication(&mut self, workspace: usize) -> Result<()> {
        ensure!(
            self.eligible && self.fs_bytes != 0 && workspace <= MAX_BYTES,
            "invalid publication capacity transition"
        );
        let mut usage = self
            .control
            .state
            .lock()
            .map_err(|_| LocalMutationError::Unknown)?;
        ensure!(
            usage.bytes - self.bytes + workspace <= MAX_BYTES,
            LocalMutationError::Busy
        );
        usage.long_fs_bytes -= self.fs_bytes;
        usage.bytes = usage.bytes - self.bytes + workspace;
        self.bytes = workspace;
        self.fs_bytes = 0;
        drop(usage);
        self.control.wake();
        Ok(())
    }
    /// Transfer already admitted backing to its longer-lived owner. This does
    /// not add capacity or transfer the worker's filesystem eligibility.
    pub(in crate::ed2k_transfer) fn split_retained_bytes(&mut self, bytes: usize) -> Result<Self> {
        ensure!(
            self.fs_bytes == 0 && bytes <= self.bytes,
            "invalid retained capacity transfer"
        );
        self.bytes -= bytes;
        Ok(Self {
            control: Arc::clone(&self.control),
            bytes,
            fs_bytes: 0,
            eligible: false,
        })
    }
    /// End the physical-work reservation while keeping returned buffers charged.
    /// The resulting lease can move with a result and survive consumer conversion.
    pub(super) fn take_result(&mut self) -> Self {
        let mut usage = self.control.state.lock().unwrap_or_else(|p| p.into_inner());
        usage.long_fs_bytes -= self.fs_bytes;
        usage.long_fs_units -= usize::from(self.eligible);
        let result = Self {
            control: Arc::clone(&self.control),
            bytes: self.bytes,
            fs_bytes: 0,
            eligible: false,
        };
        self.bytes = 0;
        self.fs_bytes = 0;
        self.eligible = false;
        drop(usage);
        self.control.wake();
        result
    }
}
impl Drop for CapacityLease {
    fn drop(&mut self) {
        let mut usage = self.control.state.lock().unwrap_or_else(|p| p.into_inner());
        usage.bytes -= self.bytes;
        usage.long_fs_bytes -= self.fs_bytes;
        usage.long_fs_units -= usize::from(self.eligible);
        drop(usage);
        self.control.wake();
    }
}
