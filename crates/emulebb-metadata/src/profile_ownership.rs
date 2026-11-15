//! Descriptor ownership shared by profile loaders and their metadata handles.

use std::fs::{File, TryLockError};

/// An acquired exclusive profile lock, shared through `Arc` by logical owners.
///
/// Release never removes the persistent lock file. The acquiring process
/// explicitly unlocks its descriptor when the final owner drops, so transient
/// descriptors inherited by a spawning child cannot prolong profile ownership.
#[derive(Debug)]
pub struct ProfileLeaseGuard {
    file: File,
    acquisition_pid: u32,
}

impl ProfileLeaseGuard {
    /// Acquire the supplied lock-file descriptor without waiting.
    ///
    /// Contention, unsupported locks, and other I/O failures remain errors.
    /// Only a successfully acquired descriptor becomes an owned guard.
    pub fn try_lock(file: File) -> Result<Self, TryLockError> {
        file.try_lock()?;
        Ok(Self {
            file,
            acquisition_pid: std::process::id(),
        })
    }
}

impl Drop for ProfileLeaseGuard {
    fn drop(&mut self) {
        // WHY: a fork/spawn can temporarily retain the same open-file description
        // after the final logical owner drops. Unlock that acquired descriptor
        // explicitly, but never let an inherited child unlock its parent's lease.
        if self.acquisition_pid == std::process::id() {
            let _ = self.file.unlock();
        }
    }
}
