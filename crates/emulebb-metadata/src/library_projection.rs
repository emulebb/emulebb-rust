//! Connection-local library projection, invalidated by durable and session evidence.

use anyhow::Result;
use rusqlite::{Connection, params};

pub(crate) fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TEMP TABLE session_library_catalog (
            known_file_id INTEGER PRIMARY KEY, path_id INTEGER NOT NULL,
            sort_key TEXT NOT NULL, ed2k_hash BLOB NOT NULL
         ) STRICT;
         CREATE INDEX temp.session_library_catalog_sort_idx ON session_library_catalog(sort_key, ed2k_hash);
         CREATE TEMP TABLE session_library_revision (
            id INTEGER PRIMARY KEY CHECK(id = 1), revision INTEGER NOT NULL,
            cached_revision INTEGER NOT NULL, cached_durable_revision INTEGER NOT NULL
         ) STRICT;
         INSERT INTO session_library_revision VALUES(1, 0, -1, -1);
         CREATE TEMP TRIGGER session_library_verified_insert AFTER INSERT ON session_verified_local_paths
         BEGIN UPDATE session_library_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END; END;
         CREATE TEMP TRIGGER session_library_verified_delete AFTER DELETE ON session_verified_local_paths
         BEGIN UPDATE session_library_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END; END;
         CREATE TEMP TRIGGER session_library_verified_update AFTER UPDATE ON session_verified_local_paths
         WHEN old.path_id IS NOT new.path_id OR old.verified_fingerprint IS NOT new.verified_fingerprint
         BEGIN UPDATE session_library_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END; END;",
    )?;
    Ok(())
}

/// Refresh once for a changed evidence revision inside the caller's read
/// transaction. Unchanged pages seek the projection's sort index directly.
pub(crate) fn refresh(conn: &Connection) -> Result<()> {
    let (durable, session, cached_durable, cached_session): (i64, i64, i64, i64) = conn.query_row(
        "SELECT d.revision, s.revision, s.cached_durable_revision, s.cached_revision
         FROM library_catalog_revision d CROSS JOIN temp.session_library_revision s WHERE d.id = 1 AND s.id = 1",
        [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    if (durable, session) == (cached_durable, cached_session) {
        return Ok(());
    }
    // WHY: resolving once per content prevents quadratic alias work and keeps
    // successive pages independent of the full library's size. Both clocks are
    // read in the same SQLite snapshot as the projection and page rows.
    let representative = crate::local_catalog::representative_path(true);
    conn.execute("DELETE FROM temp.session_library_catalog", [])?;
    conn.execute_batch(&format!("INSERT INTO temp.session_library_catalog
        SELECT known_files.id, local_file_instances.path_id, local_paths.sort_key, known_files.ed2k_hash
        FROM known_files
        CROSS JOIN verified_local_content ON verified_local_content.known_file_id = known_files.id
        CROSS JOIN local_file_instances ON local_file_instances.path_id = ({representative})
        CROSS JOIN local_paths ON local_paths.id = local_file_instances.path_id;"))?;
    conn.execute("UPDATE temp.session_library_revision SET cached_durable_revision = ?1, cached_revision = ?2 WHERE id = 1", params![durable, session])?;
    Ok(())
}
