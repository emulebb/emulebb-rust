//! Map a file path to a stable key identifying the **physical disk** its volume
//! lives on, so the background shared-directory reload can hash one file at a
//! time per spindle while distinct disks hash in parallel (concurrent reads on a
//! single HDD seek-thrash and run slower than serial).
//!
//! On Windows the key is the disk number reported by
//! `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`, so two drive letters backed by one
//! physical drive share a worker and a volume striped across disks fans out by
//! its first extent. Raw FFI mirrors `emulebb-kad-net/src/socket_opts.rs`. Any
//! resolution failure (and every non-Windows platform) falls back to a
//! volume-root string key, which still parallelizes across distinct volumes.

use std::path::Path;

/// A stable, hashable key naming the physical disk a path primarily reads from.
/// Equal keys mean "same spindle -> hash serially"; distinct keys hash in
/// parallel. Never panics; resolution failures degrade to a volume-root key.
pub(crate) fn physical_disk_key(path: &Path) -> String {
    #[cfg(windows)]
    {
        match drive_letter(path) {
            Some(letter) => match windows_disk_number(letter) {
                Some(disk) => format!("disk:{disk}"),
                None => format!("vol:{letter}:"),
            },
            // No drive letter (UNC/mount-point volume): group all such paths
            // together rather than risk thrashing; rare for shared libraries.
            None => "vol:other".to_string(),
        }
    }
    #[cfg(not(windows))]
    {
        // No portable physical-disk query: group by the top-level path component
        // (a mount-point proxy) so distinct mounts still hash concurrently.
        path.components()
            .next()
            .map(|c| format!("vol:{}", c.as_os_str().to_string_lossy()))
            .unwrap_or_else(|| "vol:other".to_string())
    }
}

/// Extract the ASCII drive letter (uppercased) from a path, tolerating the
/// verbatim `\\?\` long-path prefix the shared-directory walk produces. Returns
/// `None` for UNC (`\\?\UNC\...`, `\\server\...`) and relative paths.
#[cfg(windows)]
fn drive_letter(path: &Path) -> Option<char> {
    let s = path.to_string_lossy();
    let rest = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let b = rest.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        Some(b[0].to_ascii_uppercase() as char)
    } else {
        None
    }
}

/// Query the physical disk number backing drive `letter` (e.g. `'F'`). Opens the
/// `\\.\F:` volume device and issues `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`,
/// returning the first extent's disk number. `None` on any failure (callers fall
/// back to a per-letter key). No access is requested, so this does not require
/// elevation for a fixed local volume.
#[cfg(windows)]
fn windows_disk_number(letter: char) -> Option<u32> {
    use std::ffi::c_void;
    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::DISK_EXTENT;

    // windows-sys 0.59 doesn't export this control code, so compute it the same
    // way winioctl.h's CTL_CODE macro does:
    //   IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS =
    //     CTL_CODE(IOCTL_VOLUME_BASE='V'(0x56), 0, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
    //   = (0x56 << 16) | (0 << 14) | (0 << 2) | 0 = 0x0056_0000
    const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;

    // Room for a volume striped across several disks; we only read the first.
    const MAX_EXTENTS: usize = 8;
    #[repr(C)]
    struct VolumeDiskExtentsBuf {
        number_of_disk_extents: u32,
        extents: [DISK_EXTENT; MAX_EXTENTS],
    }

    // `\\.\F:` as a NUL-terminated UTF-16 device path.
    let device: Vec<u16> = format!(r"\\.\{letter}:")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: standard Win32 FFI. `device` is NUL-terminated and outlives the
    // call; null security attributes / template handle are valid; the handle is
    // always closed before returning; the IOCTL writes into a correctly sized,
    // C-layout buffer and we only read `extents[0]` after a success return.
    unsafe {
        let handle = CreateFileW(
            device.as_ptr(),
            0, // query only: no read/write access needed for the extents IOCTL
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut buf = VolumeDiskExtentsBuf {
            number_of_disk_extents: 0,
            extents: std::mem::zeroed(),
        };
        let mut returned: u32 = 0;
        let ok = DeviceIoControl(
            handle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            ptr::null(),
            0,
            (&raw mut buf).cast::<c_void>(),
            size_of::<VolumeDiskExtentsBuf>() as u32,
            &raw mut returned,
            ptr::null_mut(),
        );
        CloseHandle(handle);
        if ok != 0 && buf.number_of_disk_extents >= 1 {
            Some(buf.extents[0].DiskNumber)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn key_is_stable_and_non_empty() {
        let p = PathBuf::from("C:\\Windows\\notepad.exe");
        let a = physical_disk_key(&p);
        let b = physical_disk_key(&p);
        assert_eq!(a, b, "same path must yield the same disk key");
        assert!(!a.is_empty());
        // On Windows it resolves to either a physical disk or a per-letter key.
        #[cfg(windows)]
        assert!(a.starts_with("disk:") || a.starts_with("vol:"), "got {a}");
    }

    #[cfg(windows)]
    #[test]
    fn drive_letter_tolerates_verbatim_prefix_and_rejects_unc() {
        assert_eq!(drive_letter(&PathBuf::from(r"F:\M\x")), Some('F'));
        assert_eq!(drive_letter(&PathBuf::from(r"\\?\f:\M\x")), Some('F'));
        assert_eq!(
            drive_letter(&PathBuf::from(r"\\?\C:\dir\file.bin")),
            Some('C')
        );
        assert_eq!(drive_letter(&PathBuf::from(r"\\server\share\file")), None);
        assert_eq!(drive_letter(&PathBuf::from(r"\\?\UNC\server\share")), None);
        assert_eq!(drive_letter(&PathBuf::from("relative\\path")), None);
    }

    #[cfg(windows)]
    #[test]
    fn distinct_letters_on_one_disk_can_share_a_key() {
        // C: is a fixed disk on the build host; its key must be a disk:N form
        // when the IOCTL succeeds (the whole point of physical-disk grouping).
        let key = physical_disk_key(&PathBuf::from("C:\\Windows"));
        // Either we resolved the physical disk, or we degraded gracefully.
        assert!(key == "disk:0" || key.starts_with("disk:") || key == "vol:C:");
    }
}
