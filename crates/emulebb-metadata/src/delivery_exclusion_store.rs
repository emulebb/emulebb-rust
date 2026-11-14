//! Durable sharing exclusions for incomplete direct delivery outputs.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::{MetadataStore, NativePath};

fn exclusion_path(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().context("delivery path has no parent")?;
    let name = path.file_name().context("delivery path has no filename")?;
    Ok(std::fs::canonicalize(parent)?.join(name))
}

pub(crate) fn is_excluded(conn: &Connection, path: &Path) -> Result<bool> {
    let any: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM delivery_exclusions)",
        [],
        |row| row.get(0),
    )?;
    if !any {
        return Ok(false);
    }
    let normalized = match exclusion_path(path) {
        Ok(path) => path,
        // WHY: If the parent cannot be resolved, an alias of a reserved path
        // cannot be ruled out. Do not admit it to the shared catalog.
        Err(_) => return Ok(true),
    };
    let native = NativePath::from(normalized.as_path());
    Ok(conn
        .query_row(
            "SELECT 1 FROM delivery_exclusions WHERE platform = ?1 AND native_path = ?2",
            params![NativePath::platform(), native.storage_bytes()],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

impl MetadataStore {
    /// Reserve a final name before exclusive creation; exclusions outlive transfers.
    pub fn reserve_delivery_output(&self, path: &Path, id: Uuid) -> Result<bool> {
        let normalized = exclusion_path(path)?;
        let native = NativePath::from(normalized.as_path());
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO delivery_exclusions(platform, native_path, reservation_id) VALUES (?1, ?2, ?3)",
            params![NativePath::platform(), native.storage_bytes(), id.to_string()],
        )? == 1;
        if inserted {
            // WHY: an old session may still advertise a removed file under an
            // alias of this name. Withdraw it before a new partial can exist.
            let paths = {
                let mut stmt = tx.prepare("SELECT local_paths.id, local_paths.platform, local_paths.native_path
                    FROM local_file_instances JOIN local_paths ON local_paths.id = local_file_instances.path_id
                    WHERE EXISTS (SELECT 1 FROM shared_file_memberships m
                                  WHERE m.path_id = local_paths.id AND m.removed_at_ms IS NULL)
                       OR EXISTS (SELECT 1 FROM temp.session_verified_local_paths v WHERE v.path_id = local_paths.id)")?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        crate::native_path::path_from_row(row, 1, 2)?,
                    ))
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            let mut parents: HashMap<PathBuf, Option<PathBuf>> = HashMap::new();
            for (path_id, known_path) in paths {
                let Some((parent, name)) = known_path.parent().zip(known_path.file_name()) else {
                    continue;
                };
                let resolved = parents
                    .entry(parent.to_path_buf())
                    .or_insert_with(|| std::fs::canonicalize(parent).ok());
                if resolved
                    .as_ref()
                    .is_some_and(|parent| parent.join(name) == normalized)
                {
                    tx.execute("UPDATE shared_file_memberships SET removed_at_ms = ?2 WHERE path_id = ?1 AND removed_at_ms IS NULL", params![path_id, crate::store::unix_ms()])?;
                    tx.execute(
                        "DELETE FROM temp.session_verified_local_paths WHERE path_id = ?1",
                        [path_id],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(inserted)
    }

    /// Release only a reservation whose exclusive creation did not succeed.
    pub fn release_delivery_output(&self, id: Uuid) -> Result<()> {
        self.connection()?.execute(
            "DELETE FROM delivery_exclusions WHERE reservation_id = ?1",
            [id.to_string()],
        )?;
        Ok(())
    }

    /// Return whether a path is barred from local sharing.
    pub fn delivery_output_is_excluded(&self, path: &Path) -> Result<bool> {
        let conn = self.connection()?;
        is_excluded(&conn, path)
    }

    /// A retained reservation indicates an interrupted direct-copy attempt.
    pub fn has_delivery_reservation(&self, id: Uuid) -> Result<bool> {
        Ok(self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM delivery_exclusions WHERE reservation_id = ?1)",
            [id.to_string()],
            |row| row.get(0),
        )?)
    }
}

pub(crate) fn ensure_not_excluded(conn: &Connection, path: &Path) -> Result<()> {
    ensure!(
        !is_excluded(conn, path)?,
        "local file is an incomplete delivery output"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_are_independent_and_prevent_duplicate_claims() {
        let root = std::env::temp_dir().join(format!("emulebb-exclusion-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("sample.bin");
        let store = MetadataStore::in_memory().unwrap();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        assert!(store.reserve_delivery_output(&path, first).unwrap());
        assert!(store.delivery_output_is_excluded(&path).unwrap());
        assert!(!store.reserve_delivery_output(&path, second).unwrap());
        store.release_delivery_output(second).unwrap();
        assert!(store.delivery_output_is_excluded(&path).unwrap());
        store.release_delivery_output(first).unwrap();
        assert!(!store.delivery_output_is_excluded(&path).unwrap());
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn reservation_survives_profile_reopen() {
        let root =
            std::env::temp_dir().join(format!("emulebb-exclusion-reopen-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("profile.db");
        let target = root.join("partial.bin");
        let id = Uuid::new_v4();
        {
            let store = MetadataStore::open(&database).unwrap();
            assert!(store.reserve_delivery_output(&target, id).unwrap());
        }
        let store = MetadataStore::open(&database).unwrap();
        assert!(store.has_delivery_reservation(id).unwrap());
        assert!(store.delivery_output_is_excluded(&target).unwrap());
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn exclusion_survives_reopen_and_resolves_parent_aliases() {
        let root =
            std::env::temp_dir().join(format!("emulebb-exclusion-reopen-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("alias")).unwrap();
        let database = root.join("profile.db");
        let canonical_target = root.join("real").join("partial.bin");
        let alias_target = root.join("alias").join("partial.bin");
        let id = Uuid::new_v4();
        {
            let store = MetadataStore::open(&database).unwrap();
            assert!(
                store
                    .reserve_delivery_output(&canonical_target, id)
                    .unwrap()
            );
            assert!(store.delivery_output_is_excluded(&alias_target).unwrap());
        }
        let store = MetadataStore::open(&database).unwrap();
        assert!(store.has_delivery_reservation(id).unwrap());
        assert!(store.delivery_output_is_excluded(&alias_target).unwrap());
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}
