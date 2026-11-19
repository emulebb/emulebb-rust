//! Durable watcher-loss state and scan admission, independent of filesystem I/O.

use std::path::Path;

use anyhow::Result;
use rusqlite::params;

use crate::{MetadataStore, NativePath};

/// Evidence captured before walking a root. Only that root incarnation and
/// losses observed before this watermark can be acknowledged by the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataRootScanWatermark {
    pub(crate) root_id: i64,
    pub(crate) watch_loss_revision: i64,
}

#[cfg(test)]
mod tests;

impl MetadataStore {
    /// Capture the active root's identity and loss revision before scanning it.
    pub fn shared_root_scan_watermark(&self, root: &Path) -> Result<MetadataRootScanWatermark> {
        let native = NativePath::from(root);
        Ok(self.connection()?.query_row(
            "SELECT r.id,r.watch_loss_revision FROM shared_directory_roots r
             JOIN local_paths p ON p.id=r.path_id
             WHERE p.platform=?1 AND p.native_path=?2 AND r.enabled=1 AND r.deleted_at_ms IS NULL",
            params![NativePath::platform(), native.storage_bytes()],
            |row| {
                Ok(MetadataRootScanWatermark {
                    root_id: row.get(0)?,
                    watch_loss_revision: row.get(1)?,
                })
            },
        )?)
    }

    /// Record one coalesced loss episode for an active immutable root ID.
    /// Missing or retired roots stay retired; no path-based replacement is used.
    pub fn mark_library_root_scan_required(&self, id: i64) -> Result<bool> {
        Ok(self.connection()?.execute(
            "UPDATE shared_directory_roots SET scan_required=1,
             watch_loss_revision=CASE WHEN watch_loss_revision<9223372036854775807
                THEN watch_loss_revision+1 ELSE watch_loss_revision END
             WHERE id=?1 AND enabled=1 AND deleted_at_ms IS NULL",
            [id],
        )? == 1)
    }
}
