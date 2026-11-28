//! Name allocation for finished payloads on the destination filesystem.

use std::{io, path::Path};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::long_path::long_path;

pub(super) fn staging_leaf(attempt_id: Uuid) -> String {
    format!(".emulebb-delivery-{attempt_id}.tmp")
}

pub(super) struct DeliveryLeaf {
    sanitized: String,
    discriminator: String,
    max_units: usize,
    unit_width: fn(char) -> usize,
}

impl DeliveryLeaf {
    pub(super) async fn for_destination(directory: &Path, canonical: &str) -> Result<Self> {
        let native_path = long_path(directory);
        let limit = tokio::task::spawn_blocking(move || component_limit(&native_path))
            .await?
            .with_context(|| {
                format!(
                    "could not determine delivery filename limit in {}",
                    directory.display()
                )
            })?;
        let unit_width: fn(char) -> usize = if cfg!(windows) {
            char::len_utf16
        } else {
            char::len_utf8
        };
        Self::new(canonical, limit, unit_width).with_context(|| {
            format!(
                "cannot allocate a delivery filename in {}",
                directory.display()
            )
        })
    }

    fn new(canonical: &str, max_units: usize, unit_width: fn(char) -> usize) -> Result<Self> {
        ensure!(
            max_units >= staging_leaf(Uuid::nil()).len(),
            "destination filename limit of {max_units} cannot accommodate delivery staging"
        );
        let digest = Sha256::digest(canonical.as_bytes());
        Ok(Self {
            sanitized: sanitize_file_name(canonical),
            discriminator: format!(
                "~{:016x}",
                u64::from_be_bytes(digest[..8].try_into().unwrap())
            ),
            max_units,
            unit_width,
        })
    }

    pub(super) fn candidate(&self, ordinal: u64) -> String {
        let file_name = self.sanitized.as_str();
        let (stem, extension) = split_stem_extension(file_name);
        let suffix = collision_suffix(ordinal);
        if self.units(file_name) + suffix.len() <= self.max_units {
            return match extension {
                Some(extension) => format!("{stem}{suffix}.{extension}"),
                None => format!("{stem}{suffix}"),
            };
        }

        // Keep a discriminator for truncated names before the ordinal, even
        // when different canonical names or case variants share their prefix.
        let budget = self.max_units - self.discriminator.len() - suffix.len();
        let extension = extension.filter(|extension| self.units(extension) + 1 < budget);
        let stem_budget = budget - extension.map_or(0, |extension| self.units(extension) + 1);
        let mut used = 0;
        let mut prefix = stem.trim_end_matches([' ', '.']);
        for (offset, ch) in stem.char_indices() {
            used += (self.unit_width)(ch);
            if used > stem_budget {
                prefix = stem[..offset].trim_end_matches([' ', '.']);
                break;
            }
        }
        // The nonempty discriminator prevents a shortened basename from
        // becoming a reserved device name or ending in a dot or space.
        let tag = &self.discriminator;
        match extension {
            Some(extension) => format!("{prefix}{tag}{suffix}.{extension}"),
            None => format!("{prefix}{tag}{suffix}"),
        }
    }

    fn units(&self, value: &str) -> usize {
        value.chars().map(self.unit_width).sum()
    }
}

fn collision_suffix(ordinal: u64) -> String {
    if ordinal == 0 {
        return String::new();
    }
    let mut index = ordinal;
    let mut width = 2usize;
    let mut limit = 99u64;
    while index > limit {
        index -= limit;
        width += 1;
        limit = limit.saturating_mul(10).saturating_add(9);
    }
    format!("_{index:0width$}")
}

#[cfg(windows)]
fn component_limit(directory: &Path) -> io::Result<usize> {
    use std::{
        fs::OpenOptions,
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        ptr::null_mut,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetVolumeInformationByHandleW,
    };

    let handle = OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(directory)?;
    let mut limit = 0u32;
    // SAFETY: the open directory and limit output remain valid for the call.
    // Every unused output is optional and supplied as null with a zero size.
    let success = unsafe {
        GetVolumeInformationByHandleW(
            handle.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            &mut limit,
            null_mut(),
            null_mut(),
            0,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(limit as usize)
}

#[cfg(unix)]
fn component_limit(directory: &Path) -> io::Result<usize> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let path = CString::new(directory.as_os_str().as_bytes())?;
    // SAFETY: path is a live NUL-terminated native path.
    let limit = unsafe { libc::pathconf(path.as_ptr(), libc::_PC_NAME_MAX) };
    usize::try_from(limit)
        .ok()
        .filter(|&limit| limit != 0)
        .ok_or_else(|| io::Error::other("filesystem did not report a positive name limit"))
}

/// Replace filesystem-reserved characters in a canonical name so it is safe to
/// use as a single path component on Windows and POSIX. Strips trailing dots /
/// spaces (invalid as a Windows file name) and never returns an empty name.
fn sanitize_file_name(name: &str) -> String {
    let mut sanitized: String = name
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            ch if ch.is_control() => '_',
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
fn split_stem_extension(file_name: &str) -> (&str, Option<&str>) {
    match file_name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() && !extension.is_empty() => {
            (stem, Some(extension))
        }
        _ => (file_name, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_native_units_for_the_extension_and_each_collision_suffix() {
        for width in [char::len_utf8 as fn(char) -> usize, char::len_utf16] {
            for ch in ['x', 'é', '漢', '🙂'] {
                let units = width(ch);
                let boundary = format!("{}.bin", ch.to_string().repeat(251 / units));
                let leaf = DeliveryLeaf::new(&boundary, 255, width).unwrap();
                assert_eq!(leaf.candidate(0), boundary);
                let oversized = format!("{}.bin", ch.to_string().repeat(251 / units + 1));
                let leaf = DeliveryLeaf::new(&oversized, 255, width).unwrap();
                for ordinal in [0, 1, 100, u64::MAX] {
                    let candidate = leaf.candidate(ordinal);
                    assert!(candidate.ends_with(".bin"));
                    assert!(candidate.chars().map(width).sum::<usize>() <= 255);
                    assert!(candidate.contains(&leaf.discriminator));
                }
                assert_ne!(leaf.candidate(1), leaf.candidate(100));
            }
        }
    }

    #[test]
    fn shortened_names_keep_their_identity_and_component_safety() {
        let prefix = "e\u{301}".repeat(100);
        let first = DeliveryLeaf::new(&format!("{prefix}a.bin"), 255, char::len_utf8).unwrap();
        let second = DeliveryLeaf::new(&format!("{prefix}b.bin"), 255, char::len_utf8).unwrap();
        assert_ne!(first.candidate(0), second.candidate(0));
        let long_extension =
            DeliveryLeaf::new(&format!("CON.{}", "x".repeat(300)), 255, char::len_utf8).unwrap();
        let name = long_extension.candidate(u64::MAX);
        assert!(name.starts_with("CON_"));
        assert!(!name.contains('.'));
        assert!(!is_reserved_windows_leaf(&name));
        assert!(DeliveryLeaf::new("file", 32, char::len_utf8).is_err());
        assert_eq!(sanitize_file_name("file\u{007f}\u{0085}.txt"), "file__.txt");
    }

    #[test]
    fn normalized_path_separators_cannot_escape_the_delivery_directory() {
        let canonical = crate::file_name::normalize_ed2k_file_name("%2e%2e%2f%2e%2e%5cfile.bin");
        let leaf = DeliveryLeaf::new(&canonical, 255, char::len_utf8).unwrap();
        let actual = leaf.candidate(0);
        assert_eq!(actual, ".._.._file.bin");
        assert_eq!(Path::new(&actual).components().count(), 1);
    }

    #[test]
    fn collision_suffixes_widen_after_each_full_group() {
        let leaf = DeliveryLeaf::new("abc.mp3", 255, char::len_utf8).unwrap();
        let name = |n| leaf.candidate(n);
        assert_eq!(name(0), "abc.mp3");
        assert_eq!(name(1), "abc_01.mp3");
        assert_eq!(name(99), "abc_99.mp3");
        assert_eq!(name(100), "abc_001.mp3");
        assert_eq!(name(1098), "abc_999.mp3");
        assert_eq!(name(1099), "abc_0001.mp3");
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
        assert_eq!(split_stem_extension("movie.mkv"), ("movie", Some("mkv")));
        assert_eq!(
            split_stem_extension("archive.tar.gz"),
            ("archive.tar", Some("gz"))
        );
        assert_eq!(split_stem_extension("noext"), ("noext", None));
        assert_eq!(split_stem_extension(".dotfile"), (".dotfile", None));
    }
}
