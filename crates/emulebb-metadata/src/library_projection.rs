//! Incrementally maintained connection-local physical library index.

use anyhow::Result;
use rusqlite::{Connection, params};

pub(crate) fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TEMP TABLE session_library_catalog (
            known_file_id INTEGER PRIMARY KEY, path_id INTEGER NOT NULL,
            sort_key TEXT NOT NULL, ed2k_hash BLOB NOT NULL
         ) STRICT;
         CREATE INDEX temp.session_library_catalog_sort_idx ON session_library_catalog(sort_key, ed2k_hash);
         CREATE TEMP TABLE session_library_pending (
            known_file_id INTEGER PRIMARY KEY
         ) STRICT;
         CREATE TEMP TABLE session_library_revision (
            id INTEGER PRIMARY KEY CHECK(id = 1), cached_durable_revision INTEGER NOT NULL
         ) STRICT;
         INSERT INTO session_library_revision
            SELECT 1, revision FROM library_catalog_revision WHERE id = 1;",
    )?;
    // WHY: session evidence belongs to this connection. Durable changes use a
    // per-content clock index so another connection cannot consume our changes.
    for (event, versions) in [
        ("INSERT", &["new"][..]),
        ("DELETE", &["old"][..]),
        ("UPDATE", &["old", "new"][..]),
    ] {
        let select = versions
            .iter()
            .map(|v| {
                format!(
                    "SELECT known_file_id FROM local_file_instances WHERE path_id = {v}.path_id"
                )
            })
            .collect::<Vec<_>>()
            .join(" UNION ");
        let changed = if event == "UPDATE" {
            "WHEN old.path_id IS NOT new.path_id OR old.verified_fingerprint IS NOT new.verified_fingerprint"
        } else {
            ""
        };
        conn.execute_batch(&format!(
            "CREATE TEMP TRIGGER session_library_verified_{event}
             AFTER {event} ON session_verified_local_paths {changed}
             BEGIN INSERT OR IGNORE INTO session_library_pending {select}; END;"
        ))?;
    }
    Ok(())
}

/// Reconcile only changed content in the caller's read transaction. Policy,
/// statistics and tags are joined at read time and never rebuild this index.
pub(crate) fn refresh(conn: &Connection) -> Result<()> {
    let (durable, cached): (i64, i64) = conn.query_row(
        "SELECT d.revision, s.cached_durable_revision
         FROM library_catalog_revision d CROSS JOIN temp.session_library_revision s WHERE d.id = 1 AND s.id = 1",
        [], |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if durable < cached {
        // A clock rollover invalidates all representatives, including tombstones.
        conn.execute_batch(
            "INSERT OR IGNORE INTO temp.session_library_pending SELECT known_file_id FROM library_catalog_changes;
             INSERT OR IGNORE INTO temp.session_library_pending SELECT known_file_id FROM temp.session_library_catalog;",
        )?;
    } else if durable != cached {
        conn.execute(
            "INSERT OR IGNORE INTO temp.session_library_pending
             SELECT known_file_id FROM library_catalog_changes INDEXED BY library_catalog_changes_revision_idx WHERE revision > ?1 AND revision <= ?2",
            params![cached, durable],
        )?;
    }
    let representative = crate::local_catalog::representative_path(true);
    // Work is proportional to changed content and its aliases, not the entire
    // library on every mutation. SQLite owns pending keys; no full Rust snapshot.
    conn.execute_batch(&format!(
        "DELETE FROM temp.session_library_catalog
            WHERE known_file_id IN (SELECT known_file_id FROM temp.session_library_pending);
         INSERT INTO temp.session_library_catalog
            SELECT known_files.id, local_file_instances.path_id, local_paths.sort_key, known_files.ed2k_hash
            FROM temp.session_library_pending pending
            CROSS JOIN known_files ON known_files.id = pending.known_file_id
            CROSS JOIN verified_local_content ON verified_local_content.known_file_id = known_files.id
            CROSS JOIN local_file_instances ON local_file_instances.path_id = ({representative})
            CROSS JOIN local_paths ON local_paths.id = local_file_instances.path_id;
         DELETE FROM temp.session_library_pending;"
    ))?;
    conn.execute(
        "UPDATE temp.session_library_revision SET cached_durable_revision = ?1 WHERE id = 1",
        [durable],
    )?;
    Ok(())
}
