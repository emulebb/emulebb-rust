//! Disk free-space query + the download free-space floor decision.
//!
//! Used to PAUSE a download before it starts when the destination volume cannot
//! hold the remaining payload, instead of letting the transfer run and fail
//! late mid-write with a disk-full error (and then churn-retry). The floor is a
//! conservative pre-check; the write path is still the final authority.

use std::path::Path;

/// Headroom kept free beyond the file's own bytes (one ED2K part) so the floor
/// does not green-light a download that would fill the volume to the last byte.
pub const DOWNLOAD_FREE_SPACE_MARGIN_BYTES: u64 = crate::ed2k_transfer::ED2K_PART_SIZE;

/// Best-effort available space (bytes) on the volume holding `path`, or `None`
/// when it cannot be determined (the caller then skips the floor rather than
/// blocking a download on an unknowable value).
#[must_use]
pub fn available_space(path: &Path) -> Option<u64> {
    fs4::available_space(path).ok()
}

/// Whether a download needing `needed_bytes` should be paused because `available`
/// (when known) cannot hold it plus [`DOWNLOAD_FREE_SPACE_MARGIN_BYTES`]. An
/// unknown `available` never pauses (returns `false`).
#[must_use]
pub fn should_pause_for_disk_space(available: Option<u64>, needed_bytes: u64) -> bool {
    match available {
        Some(available) => {
            available < needed_bytes.saturating_add(DOWNLOAD_FREE_SPACE_MARGIN_BYTES)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_available_never_pauses() {
        assert!(!should_pause_for_disk_space(None, u64::MAX));
    }

    #[test]
    fn pauses_only_when_below_need_plus_margin() {
        let need = 100 * 1024 * 1024;
        // Plenty of room.
        assert!(!should_pause_for_disk_space(
            Some(need + DOWNLOAD_FREE_SPACE_MARGIN_BYTES + 1),
            need
        ));
        // Exactly need + margin is still enough (not strictly below).
        assert!(!should_pause_for_disk_space(
            Some(need + DOWNLOAD_FREE_SPACE_MARGIN_BYTES),
            need
        ));
        // One byte short of need + margin pauses.
        assert!(should_pause_for_disk_space(
            Some(need + DOWNLOAD_FREE_SPACE_MARGIN_BYTES - 1),
            need
        ));
    }

    #[test]
    fn available_space_reports_for_a_real_dir() {
        // The workspace temp dir always exists; available space is a real value.
        let dir = std::env::temp_dir();
        assert!(available_space(&dir).is_some());
    }
}
