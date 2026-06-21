//! Download free-space floor (pause vs fail-late write).
//!
//! Before a download attempt engages sources, check that the transfer-root
//! volume can hold the remaining payload. If it cannot, the attempt is paused
//! instead of running and failing late mid-write with a disk-full error (which
//! would otherwise churn-retry). Best-effort: an unknowable free space or
//! manifest never pauses (the write path stays the final authority).

use emulebb_ed2k::disk_space;

use crate::EmulebbCore;

impl EmulebbCore {
    /// Whether the transfer's remaining bytes cannot fit on the transfer-root
    /// volume (plus margin).
    pub(crate) async fn should_pause_download_for_disk_space(&self, file_hash: &str) -> bool {
        let Ok(manifest) = self.ed2k_transfers.manifest(file_hash).await else {
            return false;
        };
        let written: u64 = manifest
            .pieces
            .iter()
            .map(|piece| piece.bytes_written)
            .sum();
        let remaining = manifest.file_size.saturating_sub(written);
        if remaining == 0 {
            return false;
        }
        let available = disk_space::available_space(&self.transfer_root);
        disk_space::should_pause_for_disk_space(available, remaining)
    }
}
