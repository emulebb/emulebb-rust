use std::{
    collections::HashMap,
    fs, io,
    path::{Component, Path, PathBuf},
};

use emulebb_ed2k::{
    ed2k_transfer::{NativeDirectoryScanIdentity, native_directory_scan_identity},
    long_path::long_path,
};

use super::should_ignore_shared_directory_name;

#[derive(Clone, Copy)]
enum DirectoryObservation {
    Directory(Option<NativeDirectoryScanIdentity>),
    Link(Option<NativeDirectoryScanIdentity>),
    Missing,
    Unknown,
}

impl DirectoryObservation {
    fn identity(self) -> Option<NativeDirectoryScanIdentity> {
        match self {
            Self::Directory(identity) | Self::Link(identity) => identity,
            Self::Missing | Self::Unknown => None,
        }
    }
}

/// Read-only evidence scoped to one comparison operation on a blocking worker.
#[derive(Default)]
pub(crate) struct SharedRootPaths {
    observations: HashMap<PathBuf, DirectoryObservation>,
}

impl SharedRootPaths {
    pub(crate) fn overlap(&mut self, left: &Path, right: &Path) -> bool {
        let left = long_path(left);
        let right = long_path(right);
        self.covers(&left, &right) || self.covers(&right, &left)
    }

    pub(super) fn covers(&mut self, parent: &Path, child: &Path) -> bool {
        if parent == child {
            return true;
        }
        let parent_observation = self.observe(parent);
        if matches!(parent_observation, DirectoryObservation::Unknown) {
            return false;
        }
        let parent_identity = parent_observation.identity();
        let exact_ancestry = child.starts_with(parent);
        if !exact_ancestry && parent_identity.is_none() {
            return false;
        }
        // WalkDir follows a link supplied as the scan root. The same link
        // below a root, or an ignored directory, cannot establish coverage.
        let child_observation = self.observe(child);
        if parent_identity.is_some() && child_observation.identity() == parent_identity {
            return true;
        }
        if child.components().any(|part| part == Component::ParentDir) {
            return false;
        }

        for path in child.ancestors() {
            if path == parent {
                return true;
            }
            match self.observe(path) {
                DirectoryObservation::Directory(Some(identity))
                    if Some(identity) == parent_identity =>
                {
                    return true;
                }
                DirectoryObservation::Directory(_) => {}
                DirectoryObservation::Missing if exact_ancestry => {}
                _ => return false,
            }
            if path
                .file_name()
                .is_some_and(|name| should_ignore_shared_directory_name(&name.to_string_lossy()))
            {
                return false;
            }
        }
        false
    }

    fn observe(&mut self, path: &Path) -> DirectoryObservation {
        if let Some(&observed) = self.observations.get(path) {
            return observed;
        }
        let observed = match fs::symlink_metadata(path) {
            Ok(metadata) if is_directory_link(&metadata) => fs::canonicalize(path)
                .ok()
                .map_or(DirectoryObservation::Unknown, |target| {
                    observe_directory(&target, DirectoryObservation::Link)
                }),
            Ok(metadata) if metadata.is_dir() => {
                observe_directory(path, DirectoryObservation::Directory)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => DirectoryObservation::Missing,
            _ => DirectoryObservation::Unknown,
        };
        self.observations.insert(path.to_path_buf(), observed);
        observed
    }
}

fn observe_directory(
    path: &Path,
    kind: fn(Option<NativeDirectoryScanIdentity>) -> DirectoryObservation,
) -> DirectoryObservation {
    let identity = native_directory_scan_identity(path);
    if identity.is_some() || fs::read_dir(path).is_ok() {
        kind(identity)
    } else {
        DirectoryObservation::Unknown
    }
}

fn is_directory_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inaccessible_scan_routes_do_not_hide_a_readable_child() {
        let parent = long_path(Path::new(if cfg!(windows) {
            r"C:\Library"
        } else {
            "/library"
        }));
        let intermediate = parent.join("search-only");
        let child = intermediate.join("readable");
        for inaccessible in [&parent, &intermediate] {
            let mut paths = SharedRootPaths::default();
            for path in [&parent, &intermediate, &child] {
                let state = if path == inaccessible {
                    DirectoryObservation::Unknown
                } else {
                    DirectoryObservation::Directory(None)
                };
                paths.observations.insert(path.clone(), state);
            }
            assert!(!paths.covers(&parent, &child));
        }
    }
}
