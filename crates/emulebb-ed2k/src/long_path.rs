//! Windows long-path (`\\?\` verbatim) normalization for operator-facing
//! content paths.
//!
//! SCOPE (the operator rule, recorded in `AGENTS.md` + `policy/rust-client.toml`):
//! [`long_path`] is applied ONLY at the three operator-facing content path
//! boundaries -- shared-directory trees, incoming downloads, and category
//! paths. It MUST NOT be applied to config, logs, the SQLite metadata DB, the
//! hash-named per-transfer piece-store directories, or any other internal path;
//! those stay short-path on purpose.
//!
//! MECHANISM. On Windows, an absolute path is rewritten into the verbatim
//! `\\?\` form so the standard library bypasses the legacy `MAX_PATH` (260)
//! limit. The process-global enabler is the `longPathAware` application manifest
//! embedded by the daemon's `build.rs`; this helper is the per-path complement
//! at the content boundaries. A verbatim path is NOT normalized by the OS, so we
//! must produce a clean absolute path first: components are resolved against the
//! current directory, `.`/`..` are removed, and separators are backslashes.
//!
//! On every non-Windows target [`long_path`] is the identity function.

use std::path::{Path, PathBuf};

/// Rewrite an operator-facing content path into a long-path-safe form.
///
/// On Windows: for an ABSOLUTE path, return the verbatim form
/// (`\\?\C:\...` for a drive path, `\\?\UNC\server\share\...` for a UNC
/// `\\server\share\...` path) with `.`/`..` resolved and `/` separators turned
/// into `\`. A path that is already verbatim (`\\?\`) or relative is returned
/// unchanged.
///
/// On non-Windows: identity (the input path is returned as-is).
#[must_use]
pub fn long_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        windows_long_path(path)
    }
    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
}

#[cfg(windows)]
fn windows_long_path(path: &Path) -> PathBuf {
    use std::path::{Component, Prefix};

    let Some(first) = path.components().next() else {
        // Empty path: nothing to rewrite.
        return path.to_path_buf();
    };

    // Already verbatim (`\\?\...` / `\\?\UNC\...`) -- leave untouched so we never
    // double-prefix or re-normalize a caller-supplied verbatim path.
    if let Component::Prefix(prefix) = first {
        match prefix.kind() {
            Prefix::VerbatimDisk(_) | Prefix::Verbatim(_) | Prefix::VerbatimUNC(_, _) => {
                return path.to_path_buf();
            }
            _ => {}
        }
    }

    // Relative paths are returned unchanged: a verbatim path must be absolute,
    // and silently anchoring a relative path to the cwd here would surprise the
    // caller. (The content boundaries pass absolute operator paths.)
    if !path.is_absolute() {
        return path.to_path_buf();
    }

    // Build a normalized absolute path: keep the prefix + root, drop `.`, and
    // pop on `..`, since the OS will NOT normalize a verbatim path for us.
    let mut prefix_text: Option<String> = None;
    let mut is_unc = false;
    let mut stack: Vec<std::ffi::OsString> = Vec::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(letter) => {
                    prefix_text = Some(format!("{}:", (letter as char).to_ascii_uppercase()));
                }
                Prefix::UNC(server, share) => {
                    is_unc = true;
                    prefix_text = Some(format!(
                        "{}\\{}",
                        server.to_string_lossy(),
                        share.to_string_lossy()
                    ));
                }
                // Drive-relative / device / already-verbatim prefixes are not
                // ones we rewrite; bail out to the original path untouched.
                _ => return path.to_path_buf(),
            },
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                stack.pop();
            }
            Component::Normal(part) => stack.push(part.to_os_string()),
        }
    }

    let Some(prefix_text) = prefix_text else {
        // No drive/UNC prefix (e.g. a rooted-but-prefixless `\foo` path): not a
        // form we can safely make verbatim, so leave it unchanged.
        return path.to_path_buf();
    };

    let body = stack
        .iter()
        .map(|part| part.to_string_lossy())
        .collect::<Vec<_>>()
        .join("\\");

    let verbatim = if is_unc {
        if body.is_empty() {
            format!("\\\\?\\UNC\\{prefix_text}")
        } else {
            format!("\\\\?\\UNC\\{prefix_text}\\{body}")
        }
    } else if body.is_empty() {
        format!("\\\\?\\{prefix_text}\\")
    } else {
        format!("\\\\?\\{prefix_text}\\{body}")
    };

    PathBuf::from(verbatim)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn drive_absolute_becomes_verbatim() {
        let out = long_path(Path::new("C:\\Users\\op\\shared\\file.bin"));
        assert_eq!(out, PathBuf::from("\\\\?\\C:\\Users\\op\\shared\\file.bin"));
    }

    #[cfg(windows)]
    #[test]
    fn forward_slashes_are_normalized_to_backslashes() {
        let out = long_path(Path::new("C:/Users/op/shared/file.bin"));
        assert_eq!(out, PathBuf::from("\\\\?\\C:\\Users\\op\\shared\\file.bin"));
    }

    #[cfg(windows)]
    #[test]
    fn lowercase_drive_letter_is_uppercased() {
        let out = long_path(Path::new("c:\\data\\x"));
        assert_eq!(out, PathBuf::from("\\\\?\\C:\\data\\x"));
    }

    #[cfg(windows)]
    #[test]
    fn dot_and_dotdot_components_are_resolved() {
        let out = long_path(Path::new("C:\\a\\.\\b\\..\\c\\file"));
        assert_eq!(out, PathBuf::from("\\\\?\\C:\\a\\c\\file"));
    }

    #[cfg(windows)]
    #[test]
    fn drive_root_only_keeps_trailing_separator() {
        let out = long_path(Path::new("C:\\"));
        assert_eq!(out, PathBuf::from("\\\\?\\C:\\"));
    }

    #[cfg(windows)]
    #[test]
    fn unc_path_becomes_verbatim_unc() {
        let out = long_path(Path::new("\\\\server\\share\\dir\\file.bin"));
        assert_eq!(
            out,
            PathBuf::from("\\\\?\\UNC\\server\\share\\dir\\file.bin")
        );
    }

    #[cfg(windows)]
    #[test]
    fn unc_share_root_only() {
        let out = long_path(Path::new("\\\\server\\share"));
        assert_eq!(out, PathBuf::from("\\\\?\\UNC\\server\\share"));
    }

    #[cfg(windows)]
    #[test]
    fn unicode_brackets_and_nested_components_are_preserved_verbatim() {
        // The shared-directory ingest boundary must build the verbatim path
        // WITHOUT altering non-ASCII characters, brackets, or nested-folder
        // components -- these are exactly the names that were being dropped.
        // (`\u{00e0}` = a-grave, plus a CJK component.)
        let out = long_path(Path::new(
            "C:\\lib\\Studio\\La citt\u{00e0} [tt0000001]\\\u{6620}\u{753b}\\file.mkv",
        ));
        assert_eq!(
            out,
            PathBuf::from(
                "\\\\?\\C:\\lib\\Studio\\La citt\u{00e0} [tt0000001]\\\u{6620}\u{753b}\\file.mkv"
            )
        );
    }

    #[cfg(windows)]
    #[test]
    fn already_verbatim_unicode_path_is_unchanged() {
        // A walk that already produced a verbatim Unicode/bracketed path must
        // pass through untouched (no double-prefix, no re-normalization).
        let input = Path::new("\\\\?\\C:\\lib\\La citt\u{00e0} [tt0000001]\\(2001) sample.mkv");
        assert_eq!(long_path(input), PathBuf::from(input));
    }

    #[cfg(windows)]
    #[test]
    fn already_verbatim_drive_is_unchanged() {
        let input = Path::new("\\\\?\\C:\\already\\verbatim\\file");
        assert_eq!(long_path(input), PathBuf::from(input));
    }

    #[cfg(windows)]
    #[test]
    fn already_verbatim_unc_is_unchanged() {
        let input = Path::new("\\\\?\\UNC\\server\\share\\file");
        assert_eq!(long_path(input), PathBuf::from(input));
    }

    #[cfg(windows)]
    #[test]
    fn relative_path_is_unchanged() {
        let input = Path::new("shared\\sub\\file.bin");
        assert_eq!(long_path(input), PathBuf::from(input));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_is_identity() {
        // On non-Windows the helper never rewrites: absolute or relative, the
        // path is returned exactly as given.
        let absolute = Path::new("/srv/shared/file.bin");
        assert_eq!(long_path(absolute), PathBuf::from(absolute));
        let relative = Path::new("shared/file.bin");
        assert_eq!(long_path(relative), PathBuf::from(relative));
    }
}
