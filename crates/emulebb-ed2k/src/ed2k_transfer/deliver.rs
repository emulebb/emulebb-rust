//! Finished-file delivery.
//!
//! When a transfer completes, its verified payload still lives only in the
//! internal hash-named piece store (`<root>/<hash>/pieces.bin`). This module
//! materializes that payload into an operator-facing file named by the
//! transfer's canonical name, under a destination directory chosen by the
//! caller (a category path, or the global incoming directory). This is the
//! eMule "move the finished file into Incoming/<category> by name" step
//! (`CPartFile::CompleteFile` / `PerformFileComplete`), expressed for the
//! headless piece-store model.
//!
//! MECHANICS. Same-volume delivery hard-links `pieces.bin` to the destination
//! (cheap, and it leaves the internal piece store intact for continued upload
//! seeding). Cross-volume delivery copies to a temp sibling and atomically
//! renames it into place. A name collision in the destination is resolved by
//! appending ` (1)`, ` (2)`, … before the extension, matching eMule.
//!
//! The destination directory and the final delivered file path are
//! operator-facing content paths, so every filesystem operation goes through
//! [`long_path`] (Windows long-path boundary; identity elsewhere). The source
//! `pieces.bin` is an internal short path and is used as-is.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::long_path::long_path;

use super::Ed2kTransferRuntime;

/// Outcome of a delivery attempt for one completed transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ed2kDeliveryOutcome {
    /// The transfer is not complete yet; nothing was delivered.
    NotCompleted,
    /// Already delivered; the recorded file still exists (idempotent no-op).
    AlreadyDelivered(PathBuf),
    /// The payload was materialized to this path.
    Delivered(PathBuf),
}

impl Ed2kTransferRuntime {
    /// Materialize a completed transfer's payload into `dest_dir` under its
    /// canonical name, recording the delivered path on the manifest so the
    /// operation is idempotent across restarts.
    ///
    /// Returns [`Ed2kDeliveryOutcome::NotCompleted`] when the transfer is not
    /// yet fully verified, [`Ed2kDeliveryOutcome::AlreadyDelivered`] when a
    /// previously recorded delivered file still exists, or
    /// [`Ed2kDeliveryOutcome::Delivered`] when a new file was created. The heavy
    /// link/copy runs WITHOUT the manifest IO lock held so a large cross-volume
    /// copy cannot stall other transfers' manifest checkpoints.
    pub async fn materialize_completed_payload(
        &self,
        file_hash: &str,
        dest_dir: &Path,
    ) -> Result<Ed2kDeliveryOutcome> {
        // Phase 1: snapshot what we need under the manifest IO lock, then
        // release it before touching the destination filesystem.
        let canonical_name = {
            let _guard = self.manifest_io.lock().await;
            let manifest = self.load_manifest_unlocked(file_hash).await?;
            if !manifest.completed {
                return Ok(Ed2kDeliveryOutcome::NotCompleted);
            }
            if let Some(recorded) = manifest.delivered_path.clone() {
                let recorded = PathBuf::from(recorded);
                if path_exists(&recorded).await {
                    return Ok(Ed2kDeliveryOutcome::AlreadyDelivered(recorded));
                }
                // A delivered path was recorded but the file is gone (the
                // operator moved or deleted it). Fall through and re-deliver.
            }
            manifest.canonical_name.clone()
        };

        let source = self.payload_path(file_hash);
        let final_path = deliver_payload_file(&source, dest_dir, &canonical_name)
            .await
            .with_context(|| format!("failed to deliver completed transfer {file_hash}"))?;

        // Phase 2: persist the delivered path under the lock.
        {
            let _guard = self.manifest_io.lock().await;
            let mut manifest = self.load_manifest_unlocked(file_hash).await?;
            manifest.delivered_path = Some(final_path.to_string_lossy().into_owned());
            self.store_manifest_unlocked(&manifest).await?;
        }
        Ok(Ed2kDeliveryOutcome::Delivered(final_path))
    }
}

/// Copy/link `source` (`pieces.bin`) into `dest_dir` under a collision-free
/// file name derived from `canonical_name`, returning the final path.
async fn deliver_payload_file(
    source: &Path,
    dest_dir: &Path,
    canonical_name: &str,
) -> Result<PathBuf> {
    tokio::fs::create_dir_all(long_path(dest_dir))
        .await
        .with_context(|| format!("failed to create delivery directory {}", dest_dir.display()))?;

    let file_name = sanitize_file_name(canonical_name);
    let target = pick_target(dest_dir, &file_name).await;
    link_or_copy(source, &target).await?;
    Ok(target)
}

/// Pick the first non-existing destination path: the bare name first, then
/// ` (1)`, ` (2)`, … inserted before the extension (eMule collision naming).
async fn pick_target(dest_dir: &Path, file_name: &str) -> PathBuf {
    let first = dest_dir.join(file_name);
    if !path_exists(&first).await {
        return first;
    }
    let (stem, extension) = split_stem_extension(file_name);
    for index in 1..=u32::MAX {
        let candidate_name = match &extension {
            Some(extension) => format!("{stem} ({index}).{extension}"),
            None => format!("{stem} ({index})"),
        };
        let candidate = dest_dir.join(candidate_name);
        if !path_exists(&candidate).await {
            return candidate;
        }
    }
    // Unreachable in practice (u32::MAX distinct candidates); keep deterministic.
    dest_dir.join(file_name)
}

/// Hard-link `source` to `dest` on the same volume; on any link failure fall
/// back to a copy-to-temp-then-atomic-rename. A completed zero-byte transfer
/// whose piece store was never created lands as an empty file.
async fn link_or_copy(source: &Path, dest: &Path) -> Result<()> {
    let source_lp = long_path(source);
    let dest_lp = long_path(dest);

    if !path_exists(source).await {
        // Empty-file transfer: no piece store on disk. Create an empty target.
        tokio::fs::File::create(&dest_lp)
            .await
            .with_context(|| format!("failed to create empty delivered file {}", dest.display()))?;
        return Ok(());
    }

    if tokio::fs::hard_link(&source_lp, &dest_lp).await.is_ok() {
        return Ok(());
    }

    // Cross-volume (or otherwise unlinkable): copy to a temp sibling, then
    // rename it into place so a partially-written file is never observable at
    // the final path.
    let temp = temp_sibling(dest);
    let temp_lp = long_path(&temp);
    tokio::fs::copy(&source_lp, &temp_lp)
        .await
        .with_context(|| {
            format!(
                "failed to copy payload {} -> {}",
                source.display(),
                temp.display()
            )
        })?;
    tokio::fs::rename(&temp_lp, &dest_lp)
        .await
        .with_context(|| format!("failed to finalize delivered file {}", dest.display()))?;
    Ok(())
}

/// A hidden temp path in the same directory as `dest` (so the final rename is
/// same-directory and atomic).
fn temp_sibling(dest: &Path) -> PathBuf {
    let name = dest
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".to_string());
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(".{name}.ed2k-delivering"))
}

async fn path_exists(path: &Path) -> bool {
    tokio::fs::metadata(long_path(path)).await.is_ok()
}

/// Replace filesystem-reserved characters in a canonical name so it is safe to
/// use as a single path component on Windows and POSIX. Strips trailing dots /
/// spaces (invalid as a Windows file name) and never returns an empty name.
fn sanitize_file_name(name: &str) -> String {
    let mut sanitized: String = name
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            ch if (ch as u32) < 0x20 => '_',
            ch => ch,
        })
        .collect();
    while sanitized.ends_with('.') || sanitized.ends_with(' ') {
        sanitized.pop();
    }
    let sanitized = sanitized.trim_start().to_string();
    if sanitized.is_empty() {
        "download".to_string()
    } else {
        sanitized
    }
}

/// Split a file name into `(stem, Some(extension))`, or `(name, None)` when
/// there is no usable extension (no dot, leading-dot dotfile, or empty tail).
fn split_stem_extension(file_name: &str) -> (String, Option<String>) {
    match file_name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() && !extension.is_empty() => {
            (stem.to_string(), Some(extension.to_string()))
        }
        _ => (file_name.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "emulebb-deliver-{}-{nanos}-{seq}",
            std::process::id()
        ))
    }

    #[test]
    fn sanitize_replaces_reserved_characters() {
        assert_eq!(sanitize_file_name("a/b\\c:d*e?.bin"), "a_b_c_d_e_.bin");
        assert_eq!(sanitize_file_name("name."), "name");
        assert_eq!(sanitize_file_name("trailing  "), "trailing");
        assert_eq!(sanitize_file_name(""), "download");
        assert_eq!(sanitize_file_name("Sample.Title.mkv"), "Sample.Title.mkv");
    }

    #[test]
    fn split_stem_extension_handles_edge_cases() {
        assert_eq!(
            split_stem_extension("movie.mkv"),
            ("movie".to_string(), Some("mkv".to_string()))
        );
        assert_eq!(
            split_stem_extension("archive.tar.gz"),
            ("archive.tar".to_string(), Some("gz".to_string()))
        );
        assert_eq!(split_stem_extension("noext"), ("noext".to_string(), None));
        assert_eq!(
            split_stem_extension(".dotfile"),
            (".dotfile".to_string(), None)
        );
    }

    #[tokio::test]
    async fn delivers_payload_with_canonical_name() {
        let dir = temp_dir();
        let source = dir.join("pieces.bin");
        let dest = dir.join("incoming");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(&source, b"payload-bytes").await.unwrap();

        let delivered = deliver_payload_file(&source, &dest, "Sample.Title.mkv")
            .await
            .unwrap();

        assert_eq!(delivered, dest.join("Sample.Title.mkv"));
        assert_eq!(tokio::fs::read(&delivered).await.unwrap(), b"payload-bytes");
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn collision_appends_numbered_suffix() {
        let dir = temp_dir();
        let source = dir.join("pieces.bin");
        let dest = dir.join("incoming");
        tokio::fs::create_dir_all(&dest).await.unwrap();
        tokio::fs::write(&source, b"data").await.unwrap();
        // Pre-existing file with the canonical name forces a suffix.
        tokio::fs::write(dest.join("clip.mkv"), b"old")
            .await
            .unwrap();

        let delivered = deliver_payload_file(&source, &dest, "clip.mkv")
            .await
            .unwrap();

        assert_eq!(delivered, dest.join("clip (1).mkv"));
        assert_eq!(tokio::fs::read(&delivered).await.unwrap(), b"data");
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn empty_payload_delivers_empty_file() {
        let dir = temp_dir();
        // No source file on disk: the zero-byte completed-transfer case.
        let source = dir.join("pieces.bin");
        let dest = dir.join("incoming");
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let delivered = deliver_payload_file(&source, &dest, "empty.dat")
            .await
            .unwrap();

        assert_eq!(delivered, dest.join("empty.dat"));
        assert_eq!(tokio::fs::read(&delivered).await.unwrap(), b"");
        tokio::fs::remove_dir_all(&dir).await.ok();
    }
}
