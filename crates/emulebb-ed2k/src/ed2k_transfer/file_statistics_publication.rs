//! Bounded absolute SQL publication, serialized with durable credit settlement.

use std::{collections::HashSet, sync::Arc};

use emulebb_metadata::{FILE_UPLOAD_CAPTURE_BATCH, MetadataFileUploadCapture};
use parking_lot::Mutex;

use super::credit_ledger::{ParkedCreditFlushParts, ParkedCreditLedger};

/// The dirty set is moved, never cloned. New captures use the owner's new set;
/// cancellation or failed publication restores every detached invalidation.
struct DirtyPublication {
    ledger: Arc<Mutex<ParkedCreditLedger>>,
    keys: HashSet<[u8; 16]>,
    complete: bool,
}

impl Drop for DirtyPublication {
    fn drop(&mut self) {
        if !self.complete {
            self.ledger
                .lock()
                .statistics_dirty
                .extend(self.keys.drain());
        }
    }
}

impl ParkedCreditFlushParts {
    /// Called only inside admitted blocking work. At most 128 fixed-size
    /// captures are copied at a time; no capture mutex is held during SQL.
    pub(super) fn publish_file_statistics(&self) -> anyhow::Result<()> {
        self.publish_file_statistics_with(|| {})
    }

    fn publish_file_statistics_with(&self, mut captured: impl FnMut()) -> anyhow::Result<()> {
        let _gate = self.flush_gate.lock();
        let mut batch = DirtyPublication {
            ledger: Arc::clone(&self.ledger),
            keys: std::mem::take(&mut self.ledger.lock().statistics_dirty),
            complete: false,
        };
        let mut keys = batch.keys.iter();
        loop {
            let mut captures = [MetadataFileUploadCapture::default(); FILE_UPLOAD_CAPTURE_BATCH];
            let count = {
                let owner = self.ledger.lock();
                let mut count = 0;
                for (slot, hash) in captures.iter_mut().zip(keys.by_ref()) {
                    *slot = owner.file_capture(*hash);
                    count += 1;
                }
                count
            };
            if count == 0 {
                break;
            }
            captured();
            // WHY: publish durable totals plus still-parked deltas, rather than
            // max(runtime watermark, durable), which loses pre-observation events.
            self.metadata
                .publish_file_upload_captures(&captures[..count])?;
        }
        // Durable seed/import facts can change without a process capture. Drain
        // their SQL-owned invalidations without allocating runtime counter rows.
        loop {
            let pending = self.metadata.pending_file_upload_captures()?;
            if pending.is_empty() {
                break;
            }
            let mut captures = [MetadataFileUploadCapture::default(); FILE_UPLOAD_CAPTURE_BATCH];
            {
                let owner = self.ledger.lock();
                for (slot, hash) in captures.iter_mut().zip(&pending) {
                    *slot = owner.file_capture(*hash);
                }
            }
            captured();
            self.metadata
                .publish_file_upload_captures(&captures[..pending.len()])?;
        }
        batch.complete = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
