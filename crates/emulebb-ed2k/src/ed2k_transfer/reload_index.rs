//! Native filesystem identities for incremental shared-directory scans.
//! Persisted fingerprints are queried through metadata's indexed native paths;
//! matching safe identities let the scanner reuse verified content hashes.

use std::fs::Metadata;
use std::path::{Path, PathBuf};

use emulebb_metadata::NativeFileFingerprint;

use super::Ed2kTransferRuntime;

impl Ed2kTransferRuntime {
    /// Build the normalized incremental-reload identity from metadata already
    /// fetched by a directory walk. Reusing that metadata avoids a second
    /// filesystem lookup for every file in large shared libraries.
    #[must_use]
    pub fn scanned_source_identity_from_metadata(
        source_path: &Path,
        metadata: &Metadata,
    ) -> (PathBuf, u64, Option<NativeFileFingerprint>) {
        let normalized = crate::long_path::long_path(source_path);
        (
            normalized.clone(),
            metadata.len(),
            super::ingest::native_file_fingerprint(&normalized),
        )
    }

    /// Stat one scanned shared file for the incremental reload, returning its
    /// long-path-normalized key plus its on-disk native fingerprint. The key is
    /// produced with the same `long_path` normalization as indexed native-path
    /// lookups. A matching safe fingerprint skips rehashing. Returns `None` when the
    /// file cannot be stat-ed (treated as changed, so it is (re)hashed).
    #[must_use]
    pub fn scanned_source_identity(
        source_path: &Path,
    ) -> Option<(PathBuf, u64, Option<NativeFileFingerprint>)> {
        let normalized = crate::long_path::long_path(source_path);
        let metadata = std::fs::metadata(&normalized).ok()?;
        let size = metadata.len();
        let fingerprint = super::ingest::native_file_fingerprint(&normalized);
        Some((normalized, size, fingerprint))
    }
}
