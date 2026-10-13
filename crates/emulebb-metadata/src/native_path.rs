use std::{
    fmt,
    path::{Path, PathBuf},
};

use anyhow::{Result, ensure};
use rusqlite::{Row, types::Type};

/// Exact platform-native filesystem path used by durable metadata and runtime indexes.
///
/// Filesystem identity must not pass through Unicode normalization or a lossy
/// display conversion. SQLite stores [`NativePath::storage_bytes`], while UI and
/// wire surfaces use [`NativePath::display_path`] as a separate representation.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct NativePath(PathBuf);

impl NativePath {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    #[must_use]
    pub fn platform() -> &'static str {
        current_platform()
    }

    #[must_use]
    pub fn storage_bytes(&self) -> Vec<u8> {
        encode_native_path(&self.0)
    }

    pub fn from_storage(platform: &str, native_path: &[u8]) -> Result<Self> {
        ensure!(
            platform == current_platform(),
            "native path belongs to platform {platform:?}, current platform is {:?}",
            current_platform()
        );
        decode_native_path(native_path).map(Self)
    }

    /// Return a Unicode display form without using it as filesystem identity.
    ///
    /// Valid Unicode paths are unchanged. Invalid Unix bytes or Windows UTF-16
    /// code units are rendered as explicit escapes so they never disappear or
    /// become an empty file name in diagnostics, UI state, or wire metadata.
    #[must_use]
    pub fn display_path(&self) -> String {
        display_native_path(&self.0)
    }

    #[must_use]
    pub fn display_file_name(&self) -> Option<String> {
        self.0.file_name().map(display_native_os_str)
    }
}

impl AsRef<Path> for NativePath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl From<PathBuf> for NativePath {
    fn from(path: PathBuf) -> Self {
        Self::new(path)
    }
}

impl From<&Path> for NativePath {
    fn from(path: &Path) -> Self {
        Self::new(path)
    }
}

impl fmt::Debug for NativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("NativePath")
            .field(&self.display_path())
            .finish()
    }
}

#[must_use]
pub(crate) fn current_platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unix"
    }
}

pub(crate) fn path_from_row(
    row: &Row<'_>,
    platform_index: usize,
    native_path_index: usize,
) -> rusqlite::Result<PathBuf> {
    let platform = row.get::<_, String>(platform_index)?;
    let native_path = row.get::<_, Vec<u8>>(native_path_index)?;
    NativePath::from_storage(&platform, &native_path)
        .map(NativePath::into_path_buf)
        .map_err(|error| native_path_decode_error(native_path_index, error))
}

pub(crate) fn optional_path_from_row(
    row: &Row<'_>,
    platform_index: usize,
    native_path_index: usize,
) -> rusqlite::Result<Option<PathBuf>> {
    let platform = row.get::<_, Option<String>>(platform_index)?;
    let native_path = row.get::<_, Option<Vec<u8>>>(native_path_index)?;
    match (platform, native_path) {
        (None, None) => Ok(None),
        (Some(platform), Some(native_path)) => NativePath::from_storage(&platform, &native_path)
            .map(NativePath::into_path_buf)
            .map(Some)
            .map_err(|error| native_path_decode_error(native_path_index, error)),
        _ => Err(native_path_decode_error(
            native_path_index,
            anyhow::anyhow!("stored native path platform and bytes must both be null or present"),
        )),
    }
}

fn native_path_decode_error(index: usize, error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(index, Type::Blob, error.into())
}

#[cfg(unix)]
fn encode_native_path(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn encode_native_path(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(unix)]
fn decode_native_path(native_path: &[u8]) -> Result<PathBuf> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    Ok(PathBuf::from(OsString::from_vec(native_path.to_vec())))
}

#[cfg(windows)]
fn decode_native_path(native_path: &[u8]) -> Result<PathBuf> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};

    ensure!(
        native_path.len().is_multiple_of(2),
        "Windows native path byte length must be even"
    );
    let wide = native_path
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    Ok(PathBuf::from(OsString::from_wide(&wide)))
}

#[cfg(unix)]
fn display_native_os_str(value: &std::ffi::OsStr) -> String {
    use std::os::unix::ffi::OsStrExt;

    let bytes = value.as_bytes();
    if let Ok(value) = std::str::from_utf8(bytes) {
        return value.to_string();
    }

    let mut output = String::new();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                push_escaped_backslashes(&mut output, valid);
                break;
            }
            Err(error) => {
                let valid_length = error.valid_up_to();
                let valid = std::str::from_utf8(&remaining[..valid_length])
                    .expect("valid_up_to always ends at a UTF-8 boundary");
                push_escaped_backslashes(&mut output, valid);
                let invalid_length = error
                    .error_len()
                    .unwrap_or(remaining.len().saturating_sub(valid_length));
                for byte in &remaining[valid_length..valid_length + invalid_length] {
                    output.push_str(&format!("\\x{byte:02X}"));
                }
                remaining = &remaining[valid_length + invalid_length..];
            }
        }
    }
    output
}

#[cfg(windows)]
fn display_native_os_str(value: &std::ffi::OsStr) -> String {
    use std::os::windows::ffi::OsStrExt;

    let wide = value.encode_wide().collect::<Vec<_>>();
    if let Ok(value) = String::from_utf16(&wide) {
        return value;
    }

    let mut output = String::new();
    for decoded in char::decode_utf16(wide) {
        match decoded {
            Ok('\\') => output.push_str("\\\\"),
            Ok(character) => output.push(character),
            Err(error) => output.push_str(&format!(
                "\\u{{{:04X}}}",
                error.unpaired_surrogate()
            )),
        }
    }
    output
}

#[must_use]
fn display_native_path(path: &Path) -> String {
    display_native_os_str(path.as_os_str())
}

#[cfg(unix)]
fn push_escaped_backslashes(output: &mut String, value: &str) {
    for character in value.chars() {
        if character == '\\' {
            output.push_str("\\\\");
        } else {
            output.push(character);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NativePath;

    #[test]
    fn native_path_storage_round_trip() {
        let path = NativePath::new(std::path::PathBuf::from("Alpha/β/[Sample].bin"));
        let stored = path.storage_bytes();
        assert_eq!(
            NativePath::from_storage(NativePath::platform(), &stored).unwrap(),
            path
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_unix_path_round_trips_with_escaped_display() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};

        let path = NativePath::new(PathBuf::from(OsString::from_vec(vec![
            b'a', b'\\', 0xff, b'.', b'b', b'i', b'n',
        ])));
        assert_eq!(path.display_path(), r"a\\\xFF.bin");
        assert_eq!(
            NativePath::from_storage(NativePath::platform(), &path.storage_bytes()).unwrap(),
            path
        );
    }

    #[test]
    fn rejects_cross_platform_storage() {
        let other = if cfg!(windows) { "unix" } else { "windows" };
        let error = NativePath::from_storage(other, b"path").unwrap_err();
        assert!(error.to_string().contains("belongs to platform"));
    }
}
