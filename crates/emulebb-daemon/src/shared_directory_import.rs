//! Small, native shared-directory text import; no stock hash parser is involved.
use anyhow::{Result, ensure};
use emulebb_metadata::{MetadataSharedDirectoryRoot, MetadataStore};
use std::path::{Path, PathBuf};

/// Decode UTF-8 or BOM-marked UTF-16 and collapse only listed descendant roots.
pub fn read_shared_directories(file: &Path) -> Result<Vec<MetadataSharedDirectoryRoot>> {
    let bytes = std::fs::read(file)?;
    let text = if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        ensure!(bytes.len() % 2 == 0, "truncated UTF-16 directory list");
        let little = bytes[0] == 0xff;
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|b| {
                if little {
                    u16::from_le_bytes([b[0], b[1]])
                } else {
                    u16::from_be_bytes([b[0], b[1]])
                }
            })
            .collect();
        String::from_utf16(&units)?
    } else {
        String::from_utf8(bytes)?
            .trim_start_matches('\u{feff}')
            .to_owned()
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with(['#', ';']))
    {
        let path = PathBuf::from(line);
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
            "shared directory must be an absolute path without traversal"
        );
        let path = path.canonicalize().unwrap_or(path);
        if paths.iter().any(|parent| path.starts_with(parent)) {
            continue;
        }
        paths.retain(|child| !child.starts_with(&path));
        paths.push(path);
    }
    ensure!(!paths.is_empty(), "directory list is empty");
    Ok(paths
        .into_iter()
        .map(|path| MetadataSharedDirectoryRoot {
            accessible: path.is_dir(),
            shareable: path.is_dir(),
            monitor_owned: false,
            path: emulebb_ed2k::long_path::normal_path_display(&path),
        })
        .collect())
}

/// Merge roots into live metadata before the caller invokes normal offline hashing.
pub fn import_shared_directories(store: &MetadataStore, file: &Path) -> Result<usize> {
    let roots = read_shared_directories(file)?;
    let canonical = |root: &MetadataSharedDirectoryRoot| {
        let path = PathBuf::from(&root.path);
        path.canonicalize().unwrap_or(path)
    };
    // This getter returns explicit roots only. Replacing that origin preserves
    // mandatory Incoming/category roots and all accepted content knowledge.
    let mut combined = store.shared_directory_roots()?;
    for root in roots {
        let key = canonical(&root);
        if combined
            .iter()
            .any(|old| old.shareable && old.accessible && key.starts_with(canonical(old)))
        {
            continue;
        }
        combined.retain(|old| !canonical(old).starts_with(&key));
        combined.push(root);
    }
    let mut writer = store.clone();
    writer.replace_shared_directory_roots(&combined)?;
    Ok(combined.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utf16_roots_collapse_without_synthesizing_parents_and_merge_idempotently() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("Shared");
        let child = parent.join("Child");
        let sibling = temp.path().join("Shared-Other");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::create_dir(&sibling).unwrap();
        let input = temp.path().join("shareddir.dat");
        let text = format!(
            "{}\r\n{}\r\n{}\r\n{}\r\n",
            child.display(),
            parent.display(),
            sibling.display(),
            child.display()
        );
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        std::fs::write(&input, bytes).unwrap();
        assert_eq!(read_shared_directories(&input).unwrap().len(), 2);
        let db = MetadataStore::in_memory().unwrap();
        import_shared_directories(&db, &input).unwrap();
        import_shared_directories(&db, &input).unwrap();
        assert_eq!(db.shared_directory_roots().unwrap().len(), 2);
        for root in db.shared_directory_roots().unwrap() {
            let runtime_path = emulebb_ed2k::long_path::normal_path_display(&root.path);
            db.replace_root_memberships(Path::new(&runtime_path), &[])
                .unwrap();
        }
    }
    #[test]
    fn invalid_text_or_relative_roots_fail_before_writing_live_state() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("shareddir.dat");
        for bytes in [vec![0xff, 0xfe, 0x61], b"relative/path\n".to_vec()] {
            std::fs::write(&input, bytes).unwrap();
            let db = MetadataStore::in_memory().unwrap();
            assert!(import_shared_directories(&db, &input).is_err());
            assert!(db.shared_directory_roots().unwrap().is_empty());
        }
    }
}
