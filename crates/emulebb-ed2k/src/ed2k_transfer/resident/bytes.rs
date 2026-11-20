//! Shared table backing spends the existing resident budget without a job slot.
use super::*;

#[derive(Debug)]
pub(in crate::ed2k_transfer) struct ResidentBytes {
    control: Arc<ResidentControl>,
    bytes: usize,
}

impl ResidentControl {
    pub(in crate::ed2k_transfer) fn reserve_bytes(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<ResidentBytes> {
        let mut usage = self.usage.lock().map_err(|_| LocalMutationError::Unknown)?;
        let next = usage
            .bytes
            .checked_add(bytes)
            .ok_or(LocalMutationError::TooLarge)?;
        ensure!(next <= MAX_BYTES, LocalMutationError::Busy);
        usage.bytes = next;
        Ok(ResidentBytes {
            control: Arc::clone(self),
            bytes,
        })
    }
}

impl ResidentBytes {
    /// Reconcile staged storage to its actual capacity before installing it.
    pub(in crate::ed2k_transfer) fn resize(&mut self, bytes: usize) -> Result<()> {
        let mut usage = self
            .control
            .usage
            .lock()
            .map_err(|_| LocalMutationError::Unknown)?;
        let next = usage
            .bytes
            .checked_sub(self.bytes)
            .and_then(|v| v.checked_add(bytes))
            .ok_or(LocalMutationError::TooLarge)?;
        ensure!(next <= MAX_BYTES, LocalMutationError::Busy);
        let released = bytes < self.bytes;
        usage.bytes = next;
        self.bytes = bytes;
        drop(usage);
        if released {
            self.wake();
        }
        Ok(())
    }

    pub(in crate::ed2k_transfer) fn release(&mut self) {
        if self.bytes == 0 {
            return;
        }
        self.control
            .usage
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .bytes -= self.bytes;
        self.bytes = 0;
        self.wake();
    }

    pub(in crate::ed2k_transfer) fn wake(&self) {
        self.control.capacity.wake();
    }

    #[cfg(test)]
    pub(in crate::ed2k_transfer) fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for ResidentBytes {
    fn drop(&mut self) {
        self.release();
    }
}
