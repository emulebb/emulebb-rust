//! Disk free-space query for the core aggregate protected-volume policy.
//!
//! The core owns MFC-compatible floors and aggregate reservations. This module
//! only resolves the available bytes for a path's volume.

use std::path::Path;

/// Available space (bytes) on the volume holding `path`, or `None` when it
/// cannot be determined. The aggregate guard treats `None` as insufficient.
#[must_use]
pub fn available_space(path: &Path) -> Option<u64> {
    let mut anchor = Some(path);
    while let Some(candidate) = anchor {
        if candidate.exists() {
            return fs4::available_space(candidate).ok();
        }
        anchor = candidate.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_space_reports_for_a_real_dir() {
        // The workspace temp dir always exists; available space is a real value.
        let dir = std::env::temp_dir();
        assert!(available_space(&dir).is_some());
    }
}
