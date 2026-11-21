//! Incrementally maintained connection-local physical library index.

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};

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
    conn.execute_batch(
        "CREATE TEMP TABLE session_library_files (
            known_file_id INTEGER PRIMARY KEY, ed2k_hash BLOB NOT NULL UNIQUE,
            name_key TEXT, size_bytes INTEGER,
            size_key INTEGER GENERATED ALWAYS AS (coalesce(size_bytes,-1)) STORED,
            present INTEGER NOT NULL DEFAULT 0 CHECK(present IN (0,1)),
            sharing_enabled INTEGER NOT NULL CHECK(sharing_enabled IN (0,1))
         ) STRICT;
         CREATE INDEX temp.library_file_present_name_idx ON session_library_files(present,name_key,ed2k_hash);
         CREATE INDEX temp.library_file_present_size_idx ON session_library_files(present,size_key,ed2k_hash);
         CREATE INDEX temp.library_file_pending_name_idx ON session_library_files(known_file_id) WHERE name_key IS NULL;
         INSERT INTO session_library_files(known_file_id,ed2k_hash,size_bytes,sharing_enabled)
            SELECT k.id,k.ed2k_hash,k.size_bytes,k.sharing_enabled FROM library_files l
            CROSS JOIN known_files k ON k.id=l.known_file_id;
         CREATE TEMP TRIGGER library_file_accept AFTER INSERT ON main.library_files
         BEGIN
            INSERT INTO session_library_files(known_file_id,ed2k_hash,size_bytes,sharing_enabled)
                SELECT k.id,k.ed2k_hash,k.size_bytes,k.sharing_enabled FROM known_files k WHERE k.id=new.known_file_id;
         END;
         CREATE TEMP TRIGGER library_file_remove AFTER DELETE ON main.library_files
         BEGIN DELETE FROM session_library_files WHERE known_file_id=old.known_file_id; END;
         CREATE TEMP TRIGGER library_file_metadata_update
         AFTER UPDATE OF display_name,size_bytes,sharing_enabled,ed2k_hash ON main.known_files
         BEGIN
            UPDATE session_library_files SET
                name_key=CASE WHEN old.display_name IS NOT new.display_name THEN NULL ELSE name_key END,
                size_bytes=new.size_bytes,sharing_enabled=new.sharing_enabled,ed2k_hash=new.ed2k_hash
            WHERE known_file_id=new.id AND
                (old.display_name,old.size_bytes,old.sharing_enabled,old.ed2k_hash)
                  IS NOT (new.display_name,new.size_bytes,new.sharing_enabled,new.ed2k_hash);
         END;"
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
        // WHY: an outer UPSERT can override a trigger's OR IGNORE policy.
        // Give this deduplication its own conflict clause for changed evidence.
        conn.execute_batch(&format!(
            "CREATE TEMP TRIGGER session_library_verified_{event}
             AFTER {event} ON session_verified_local_paths {changed}
             BEGIN INSERT INTO session_library_pending
             SELECT known_file_id FROM ({select}) WHERE true
             ON CONFLICT(known_file_id) DO NOTHING; END;"
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
         UPDATE temp.session_library_files SET present=EXISTS(
            SELECT 1 FROM temp.session_library_catalog c WHERE c.known_file_id=session_library_files.known_file_id)
            WHERE known_file_id IN (SELECT known_file_id FROM temp.session_library_pending);
         UPDATE temp.session_file_upload_statistics SET present=(
            SELECT f.present FROM temp.session_library_files f WHERE f.known_file_id=session_file_upload_statistics.known_file_id)
            WHERE known_file_id IN (SELECT known_file_id FROM temp.session_library_pending)
              AND present IS NOT (SELECT f.present FROM temp.session_library_files f
                  WHERE f.known_file_id=session_file_upload_statistics.known_file_id);
         DELETE FROM temp.session_library_pending;"
    ))?;
    conn.execute(
        "UPDATE temp.session_library_revision SET cached_durable_revision = ?1 WHERE id = 1 AND cached_durable_revision IS NOT ?1",
        [durable],
    )?;
    Ok(())
}

/// Warm only missing/changed folded labels. Each iteration owns at most one
/// bounded name and its lowercase expansion; SQLite owns the complete index.
pub(crate) fn refresh_names(conn: &Connection) -> Result<()> {
    let mut pending = conn.prepare_cached(
        "SELECT f.known_file_id,length(CAST(k.display_name AS BLOB)),
                CASE WHEN length(CAST(k.display_name AS BLOB))<=65536 THEN k.display_name END
         FROM temp.session_library_files f INDEXED BY library_file_pending_name_idx
         CROSS JOIN known_files k ON k.id=f.known_file_id
         WHERE f.name_key IS NULL ORDER BY f.known_file_id LIMIT 1",
    )?;
    let mut update = conn.prepare_cached(
        "UPDATE temp.session_library_files SET name_key=?2 WHERE known_file_id=?1",
    )?;
    loop {
        let next = pending
            .query_row([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .optional()?;
        let Some((id, bytes, name)) = next else {
            break;
        };
        ensure!(bytes <= 65_536, "library display name exceeds allowance");
        let name = name.expect("bounded name was selected");
        update.execute(params![id, name.to_lowercase()])?;
    }
    Ok(())
}
