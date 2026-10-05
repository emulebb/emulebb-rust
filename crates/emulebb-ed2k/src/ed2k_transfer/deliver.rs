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

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use md4::{Digest, Md4};

use crate::long_path::long_path;

use super::{ED2K_PART_SIZE, Ed2kTransferRuntime};

const DELIVERY_PENDING_FILE_NAME: &str = "delivery.pending";
static DELIVERY_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

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
        let delivery_lock = {
            let mut locks = self.delivery_locks.lock().unwrap();
            Arc::clone(locks.entry(file_hash.to_ascii_lowercase()).or_default())
        };
        let _delivery_guard = delivery_lock.lock_owned().await;
        // Phase 1: snapshot what we need under the manifest IO lock, then
        // release it before touching the destination filesystem.
        let (display_name, expected_size, expected_hash) = {
            let _guard = self.lock_manifest(file_hash).await;
            let manifest = self.load_manifest_unlocked(file_hash).await?;
            if !manifest.completed || manifest.final_rehash_pending {
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
            (
                manifest.display_name.clone(),
                manifest.file_size,
                Ed2kHash::from_str(&manifest.file_hash)
                    .with_context(|| format!("invalid ED2K file hash {}", manifest.file_hash))?
                    .0,
            )
        };

        let source = self.payload_path(file_hash);
        let pending_path = self
            .transfer_dir(file_hash)
            .join(DELIVERY_PENDING_FILE_NAME);
        let final_path = deliver_payload_file(
            &source,
            dest_dir,
            &display_name,
            expected_size,
            expected_hash,
            &pending_path,
        )
        .await
        .with_context(|| format!("failed to deliver completed transfer {file_hash}"))?;

        // Phase 2: persist the delivered path under the lock.
        {
            let _guard = self.lock_manifest(file_hash).await;
            let mut manifest = self.load_manifest_unlocked(file_hash).await?;
            manifest.delivered_path = Some(final_path.to_string_lossy().into_owned());
            // Record the delivered file's mtime baseline so a later
            // shared-directory rescan that re-finds this file in a shared
            // Incoming/category dir reuses the download's already-computed
            // hashset instead of re-reading and re-hashing the whole payload
            // (HASH-2; oracle FindKnownFile, SharedFileList.cpp:2138). Only for a
            // real download (`source_path == None`); a share-in-place manifest
            // keeps its own source mtime and is never delivered. The mtime is
            // read AFTER the file is in place, through the same `long_path` stat
            // the reload uses, so an unchanged delivered file compares equal on
            // reload (a hard-link preserves the source mtime; a copy+rename sets
            // it once at delivery and it is stable thereafter).
            if manifest.source_path.is_none() {
                manifest.source_mtime_ms =
                    Ed2kTransferRuntime::scanned_source_identity(&final_path)
                        .and_then(|(_key, _size, mtime_ms)| mtime_ms);
            }
            self.store_manifest_unlocked(&manifest).await?;
        }
        remove_if_exists(&pending_path).await?;
        Ok(Ed2kDeliveryOutcome::Delivered(final_path))
    }
}

/// Copy/link `source` (`pieces.bin`) into `dest_dir` under a collision-free
/// file name derived from `display_name`, returning the final path.
async fn deliver_payload_file(
    source: &Path,
    dest_dir: &Path,
    display_name: &str,
    expected_size: u64,
    expected_hash: [u8; 16],
    pending_path: &Path,
) -> Result<PathBuf> {
    tokio::fs::create_dir_all(long_path(dest_dir))
        .await
        .with_context(|| format!("failed to create delivery directory {}", dest_dir.display()))?;

    let pending_candidate = read_pending_delivery_path(pending_path).await;
    if let Some(candidate) = pending_candidate.as_deref()
        && path_exists(candidate).await
        && delivered_file_matches(candidate, expected_size, expected_hash).await?
    {
        return Ok(candidate.to_path_buf());
    }

    let file_name = sanitize_file_name(display_name);
    let (stem, extension) = split_stem_extension(&file_name);
    for index in 0..=u32::MAX {
        let candidate_name = if index == 0 {
            file_name.clone()
        } else {
            match &extension {
                Some(extension) => format!("{stem} ({index}).{extension}"),
                None => format!("{stem} ({index})"),
            }
        };
        let candidate = dest_dir.join(candidate_name);
        if path_exists(&candidate).await {
            continue;
        }
        persist_pending_delivery_path(pending_path, &candidate).await?;
        match link_or_copy_noclobber(source, &candidate).await? {
            InstallOutcome::Installed => return Ok(candidate),
            InstallOutcome::AlreadyExists => {
                if delivered_file_matches(&candidate, expected_size, expected_hash).await? {
                    return Ok(candidate);
                }
            }
        }
    }
    anyhow::bail!(
        "exhausted collision-free delivery names in {}",
        dest_dir.display()
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallOutcome {
    Installed,
    AlreadyExists,
}

/// Install without replacing an existing destination. Same-volume delivery is
/// one atomic hard-link operation. Cross-volume delivery copies into a unique
/// temporary sibling and uses `persist_noclobber`, so two transfers selecting
/// the same visible name cannot overwrite or alias each other.
async fn link_or_copy_noclobber(source: &Path, dest: &Path) -> Result<InstallOutcome> {
    let source_lp = long_path(source);
    let dest_lp = long_path(dest);

    if !path_exists(source).await {
        // Empty-file transfer: no piece store on disk. Create an empty target.
        return match tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&dest_lp)
            .await
        {
            Ok(file) => {
                file.sync_all().await?;
                Ok(InstallOutcome::Installed)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Ok(InstallOutcome::AlreadyExists)
            }
            Err(error) => Err(error).with_context(|| {
                format!("failed to create empty delivered file {}", dest.display())
            }),
        };
    }

    match tokio::fs::hard_link(&source_lp, &dest_lp).await {
        Ok(()) => return Ok(InstallOutcome::Installed),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Ok(InstallOutcome::AlreadyExists);
        }
        Err(_) => {}
    }

    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    let prefix = format!(
        ".{}.ed2k-delivering-{}-",
        dest.file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_else(|| "download".into()),
        DELIVERY_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let parent_lp = long_path(parent);
    let named = tempfile::Builder::new()
        .prefix(&prefix)
        .tempfile_in(&parent_lp)
        .with_context(|| format!("failed to create delivery temp in {}", parent.display()))?;
    let (temp_file, temp_path) = named.into_parts();
    let mut output = tokio::fs::File::from_std(temp_file);
    let mut input = tokio::fs::File::open(&source_lp)
        .await
        .with_context(|| format!("failed to open delivery payload {}", source.display()))?;
    tokio::io::copy(&mut input, &mut output)
        .await
        .with_context(|| format!("failed to copy payload {}", source.display()))?;
    output.sync_all().await?;
    drop(output);

    let persist_target = dest_lp.clone();
    match tokio::task::spawn_blocking(move || temp_path.persist_noclobber(persist_target)).await {
        Ok(Ok(())) => Ok(InstallOutcome::Installed),
        Ok(Err(error)) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(InstallOutcome::AlreadyExists)
        }
        Ok(Err(error)) => Err(error.error)
            .with_context(|| format!("failed to finalize delivered file {}", dest.display())),
        Err(error) => Err(error).context("delivery temp persist task failed"),
    }
}

async fn read_pending_delivery_path(path: &Path) -> Option<PathBuf> {
    let text = tokio::fs::read_to_string(path).await.ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
}

async fn persist_pending_delivery_path(path: &Path, candidate: &Path) -> Result<()> {
    let sequence = DELIVERY_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = path.with_extension(format!("pending-{sequence}.tmp"));
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .await
        .with_context(|| format!("failed to create delivery intent {}", temp.display()))?;
    use tokio::io::AsyncWriteExt;
    file.write_all(candidate.to_string_lossy().as_bytes())
        .await?;
    file.sync_all().await?;
    drop(file);
    remove_if_exists(path).await?;
    tokio::fs::rename(&temp, path)
        .await
        .with_context(|| format!("failed to commit delivery intent {}", path.display()))?;
    Ok(())
}

async fn remove_if_exists(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

async fn delivered_file_matches(
    path: &Path,
    expected_size: u64,
    expected_hash: [u8; 16],
) -> Result<bool> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || compute_ed2k_hash(&path, expected_size))
        .await
        .context("delivered-file verification task failed")?
        .map(|hash| hash == Some(expected_hash))
}

fn compute_ed2k_hash(path: &Path, expected_size: u64) -> Result<Option<[u8; 16]>> {
    let metadata = match path.metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to stat {}", path.display()));
        }
    };
    if metadata.len() != expected_size {
        return Ok(None);
    }
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(0))?;
    let part_count = expected_size.div_ceil(ED2K_PART_SIZE);
    let mut part_hashes = Vec::with_capacity(usize::try_from(part_count).unwrap_or(0));
    let mut remaining = expected_size;
    for _ in 0..part_count {
        let mut hasher = Md4::new();
        let mut part_remaining = remaining.min(ED2K_PART_SIZE);
        let mut buffer = [0u8; 65_536];
        while part_remaining > 0 {
            let length = usize::try_from(part_remaining.min(buffer.len() as u64)).unwrap_or(0);
            file.read_exact(&mut buffer[..length])?;
            hasher.update(&buffer[..length]);
            part_remaining -= length as u64;
        }
        part_hashes.push(<[u8; 16]>::from(hasher.finalize()));
        remaining = remaining.saturating_sub(ED2K_PART_SIZE);
    }
    if expected_size == 0 {
        return Ok(Some(Md4::new().finalize().into()));
    }
    if expected_size < ED2K_PART_SIZE {
        return Ok(part_hashes.first().copied());
    }
    let mut composite = Md4::new();
    for hash in part_hashes {
        composite.update(hash);
    }
    if expected_size.is_multiple_of(ED2K_PART_SIZE) {
        composite.update(<[u8; 16]>::from(Md4::new().finalize()));
    }
    Ok(Some(composite.finalize().into()))
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
    let mut sanitized = sanitized.trim_start().to_string();
    if sanitized.is_empty() {
        return "download".to_string();
    }
    if is_reserved_windows_leaf(&sanitized) {
        let insertion = sanitized.find('.').unwrap_or(sanitized.len());
        sanitized.insert(insertion, '_');
    }
    sanitized
}

/// Windows treats these basenames as DOS devices even when an extension is
/// present. Protect them on every platform so a download profile remains
/// portable and the delivered file is manageable by ordinary Windows tools.
fn is_reserved_windows_leaf(name: &str) -> bool {
    let candidate = name.trim_end_matches([' ', '.']);
    let stem = candidate.split('.').next().unwrap_or(candidate);
    let upper = stem.to_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$") {
        return true;
    }
    let is_reserved_port = |prefix: &str| {
        let Some(suffix) = upper.strip_prefix(prefix) else {
            return false;
        };
        matches!(
            suffix,
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
    };
    is_reserved_port("COM") || is_reserved_port("LPT")
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
        assert_eq!(sanitize_file_name("CON"), "CON_");
        assert_eq!(sanitize_file_name("nul.txt"), "nul_.txt");
        assert_eq!(sanitize_file_name("COM1.tar.gz"), "COM1_.tar.gz");
        assert_eq!(sanitize_file_name("lpt².log"), "lpt²_.log");
        assert_eq!(sanitize_file_name("CLOCK$.bin"), "CLOCK$_.bin");
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
    async fn delivers_payload_with_display_name() {
        let dir = temp_dir();
        let source = dir.join("pieces.bin");
        let dest = dir.join("incoming");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(&source, b"payload-bytes").await.unwrap();

        let expected_hash = Md4::digest(b"payload-bytes").into();
        let delivered = deliver_payload_file(
            &source,
            &dest,
            "Sample.Title.mkv",
            13,
            expected_hash,
            &dir.join(DELIVERY_PENDING_FILE_NAME),
        )
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

        let expected_hash = Md4::digest(b"data").into();
        let delivered = deliver_payload_file(
            &source,
            &dest,
            "clip.mkv",
            4,
            expected_hash,
            &dir.join(DELIVERY_PENDING_FILE_NAME),
        )
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

        let expected_hash = Md4::new().finalize().into();
        let delivered = deliver_payload_file(
            &source,
            &dest,
            "empty.dat",
            0,
            expected_hash,
            &dir.join(DELIVERY_PENDING_FILE_NAME),
        )
        .await
        .unwrap();

        assert_eq!(delivered, dest.join("empty.dat"));
        assert_eq!(tokio::fs::read(&delivered).await.unwrap(), b"");
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn pending_intent_adopts_verified_file_after_crash_window() {
        let dir = temp_dir();
        let source = dir.join("pieces.bin");
        let dest = dir.join("incoming");
        let pending = dir.join(DELIVERY_PENDING_FILE_NAME);
        tokio::fs::create_dir_all(&dest).await.unwrap();
        tokio::fs::write(&source, b"recovered-payload")
            .await
            .unwrap();
        let installed = dest.join("recovered.bin");
        tokio::fs::write(&installed, b"recovered-payload")
            .await
            .unwrap();
        tokio::fs::write(&pending, installed.to_string_lossy().as_bytes())
            .await
            .unwrap();

        let delivered = deliver_payload_file(
            &source,
            &dest,
            "recovered.bin",
            17,
            Md4::digest(b"recovered-payload").into(),
            &pending,
        )
        .await
        .unwrap();

        assert_eq!(delivered, installed);
        assert!(!dest.join("recovered (1).bin").exists());
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn concurrent_same_name_deliveries_never_overwrite() {
        let dir = temp_dir();
        let dest = dir.join("incoming");
        let first_source = dir.join("first.bin");
        let second_source = dir.join("second.bin");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(&first_source, b"first-payload")
            .await
            .unwrap();
        tokio::fs::write(&second_source, b"second-payload")
            .await
            .unwrap();
        let first_pending = dir.join("first.pending");
        let second_pending = dir.join("second.pending");

        let first = deliver_payload_file(
            &first_source,
            &dest,
            "same.bin",
            13,
            Md4::digest(b"first-payload").into(),
            &first_pending,
        );
        let second = deliver_payload_file(
            &second_source,
            &dest,
            "same.bin",
            14,
            Md4::digest(b"second-payload").into(),
            &second_pending,
        );
        let (first_path, second_path) = tokio::join!(first, second);
        let first_path = first_path.unwrap();
        let second_path = second_path.unwrap();

        assert_ne!(first_path, second_path);
        assert_eq!(tokio::fs::read(first_path).await.unwrap(), b"first-payload");
        assert_eq!(
            tokio::fs::read(second_path).await.unwrap(),
            b"second-payload"
        );
        assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 2);
        tokio::fs::remove_dir_all(&dir).await.ok();
    }
}
