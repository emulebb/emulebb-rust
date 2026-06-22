//! Ordered, idempotent schema-migration ladder for the metadata store.
//!
//! The store is a long-lived on-disk SQLite database that holds the client's
//! durable state: transfers and resume manifests, MD4/AICH hashsets, peer
//! credits, servers, categories, preferences, and -- most critically -- the
//! persisted secure-ident keypair plus the eD2K user hash (the client's
//! on-network identity and all accumulated upload credit).
//!
//! Earlier code reset (DROP + recreate) the whole schema on ANY version
//! mismatch, silently destroying all of that on every binary upgrade that
//! bumped the schema version, and also wiping a newer DB opened by an older
//! binary. The ladder below replaces that with non-destructive, in-place
//! migrations.
//!
//! ## Reconstructed ladder (versions are the historical `SCHEMA_VERSION` bumps)
//!
//! - v1 -> v2: version-only bump (no schema.sql change), kept as a no-op step.
//! - v2 -> v3: relaxed three nullable foreign keys to `ON DELETE SET NULL`.
//!   SQLite cannot rewrite a foreign key with `ALTER TABLE`, and the change is
//!   purely behavioural (it does not move or drop any row), so this step is a
//!   deliberate data-preserving no-op: existing rows keep their values, only the
//!   stricter cascade behaviour is not retrofitted onto a pre-v3 file. A fresh
//!   DB created at the current version has the relaxed FKs from `schema.sql`.
//! - v3 -> v4: `transfer_pieces.block_bitmap TEXT` (nullable).
//! - v4 -> v5: `known_files.all_time_uploaded_bytes INTEGER NOT NULL DEFAULT 0`.
//! - v5 -> v6: `peers.secure_ident_pubkey BLOB` +
//!   `peers.secure_ident_pubkey_len INTEGER NOT NULL DEFAULT 0`.
//! - v6 -> v7: `transfers.delivered_path TEXT` (nullable) — the absolute path a
//!   completed payload was materialized to by its canonical name.
//! - v7 -> v8: `transfers.source_path TEXT` (nullable) — the original on-disk
//!   path of a shared, already-complete file seeded in place (added via a shared
//!   directory, never downloaded). NON-NULL marks a share-in-place transfer that
//!   is served directly from this path and never copied/delivered.
//!
//! Every column-adding step is expressed through [`add_column_if_missing`],
//! which checks `PRAGMA table_info` first, so the whole ladder is idempotent:
//! applying it to any real older DB (whatever intermediate shape it is in)
//! converges on the v8 shape without ever dropping user data. Each step runs in
//! its own transaction and bumps the stored marker only after the change
//! commits, so an interrupted upgrade resumes cleanly from the last good
//! version.

use anyhow::{Result, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::schema::{SCHEMA_ID, SCHEMA_VERSION};

/// Bring the database schema up to [`SCHEMA_VERSION`] in place, preserving all
/// user data. Assumes the `metadata_schema` marker table exists and holds a row
/// for [`SCHEMA_ID`]; the caller handles fresh/unmarked databases.
///
/// - stored == current: nothing to do.
/// - stored < current: run the ladder step-by-step, each step atomic.
/// - stored > current: refuse to open (an older binary must not touch a newer
///   DB, which would risk corrupting or wiping data it does not understand).
pub(crate) fn migrate_to_current(conn: &mut Connection) -> Result<()> {
    let stored = stored_version(conn)?.ok_or_else(|| {
        anyhow::anyhow!("metadata schema marker row is missing for schema_id {SCHEMA_ID}")
    })?;

    if stored == SCHEMA_VERSION {
        return Ok(());
    }
    if stored > SCHEMA_VERSION {
        bail!(
            "metadata database schema v{stored} is newer than this build (v{SCHEMA_VERSION}); \
             upgrade the client -- refusing to open so an older build cannot corrupt or wipe a \
             newer database"
        );
    }

    for target in (stored + 1)..=SCHEMA_VERSION {
        let tx = conn.transaction()?;
        apply_step(&tx, target)?;
        set_version(&tx, target)?;
        tx.commit()?;
    }
    Ok(())
}

/// Read the stored schema version from the marker table, if present.
pub(crate) fn stored_version(conn: &Connection) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT schema_version FROM metadata_schema WHERE schema_id = ?1",
        params![SCHEMA_ID],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map_err(Into::into)
}

fn set_version(tx: &Transaction<'_>, version: i64) -> Result<()> {
    tx.execute(
        "UPDATE metadata_schema SET schema_version = ?2 WHERE schema_id = ?1",
        params![SCHEMA_ID, version],
    )?;
    Ok(())
}

/// Apply the single migration step that upgrades the schema TO `target`
/// (i.e. the `target - 1 -> target` delta). Each step is idempotent.
fn apply_step(tx: &Transaction<'_>, target: i64) -> Result<()> {
    match target {
        // v1 -> v2: version-only bump, no schema change.
        2 => Ok(()),
        // v2 -> v3: foreign-key cascade relaxation only; not retrofittable via
        // ALTER TABLE and non-destructive, so intentionally a no-op on upgrade.
        3 => Ok(()),
        // v3 -> v4: per-part block presence bitmap.
        4 => add_column_if_missing(tx, "transfer_pieces", "block_bitmap", "TEXT"),
        // v4 -> v5: per-file lifetime upload counter for the upload score.
        5 => add_column_if_missing(
            tx,
            "known_files",
            "all_time_uploaded_bytes",
            "INTEGER NOT NULL DEFAULT 0",
        ),
        // v5 -> v6: verified secure-ident public key bound to a peer.
        6 => {
            add_column_if_missing(tx, "peers", "secure_ident_pubkey", "BLOB")?;
            add_column_if_missing(
                tx,
                "peers",
                "secure_ident_pubkey_len",
                "INTEGER NOT NULL DEFAULT 0",
            )
        }
        // v6 -> v7: absolute path a completed payload was delivered to by name.
        7 => add_column_if_missing(tx, "transfers", "delivered_path", "TEXT"),
        // v7 -> v8: original on-disk path of a shared, complete file seeded in
        // place (never copied/delivered). NULL for a real download.
        8 => add_column_if_missing(tx, "transfers", "source_path", "TEXT"),
        other => bail!("no metadata migration defined for schema version v{other}"),
    }
}

/// Add `column` to `table` only if it is not already present, deriving presence
/// from `PRAGMA table_info`. This makes the step safe to re-run and tolerant of
/// any intermediate on-disk shape. `definition` is the column type plus any
/// constraints/default (e.g. `INTEGER NOT NULL DEFAULT 0`).
fn add_column_if_missing(
    tx: &Transaction<'_>,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    if column_exists(tx, table, column)? {
        return Ok(());
    }
    // `table`/`column`/`definition` are all compile-time constants from this
    // module, never user input, so the formatted DDL is safe.
    tx.execute_batch(&format!(
        "ALTER TABLE \"{table}\" ADD COLUMN \"{column}\" {definition}"
    ))?;
    Ok(())
}

fn column_exists(tx: &Transaction<'_>, table: &str, column: &str) -> Result<bool> {
    let mut stmt = tx.prepare(&format!("PRAGMA table_info(\"{table}\")"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        // PRAGMA table_info columns: cid, name, type, notnull, dflt_value, pk.
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MetadataStore;
    use rusqlite::Connection;

    /// Build an on-disk database in the (approximate) v3 shape: the
    /// pre-migration variants of the three tables the ladder touches, plus the
    /// identity table, with the marker stamped at v3 and representative user
    /// data already present. This stands in for a real older client database.
    fn open_legacy_v3_db(conn: &Connection) {
        conn.execute_batch(
            r#"
            CREATE TABLE metadata_schema (
                schema_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            CREATE TABLE local_identities (
                id INTEGER PRIMARY KEY,
                kind TEXT NOT NULL UNIQUE,
                public_identity BLOB,
                private_secret BLOB,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE peers (
                id INTEGER PRIMARY KEY,
                user_hash BLOB UNIQUE,
                uploaded_bytes INTEGER NOT NULL DEFAULT 0,
                downloaded_bytes INTEGER NOT NULL DEFAULT 0,
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms INTEGER NOT NULL
            );
            CREATE TABLE known_files (
                id INTEGER PRIMARY KEY,
                ed2k_hash BLOB NOT NULL UNIQUE,
                size_bytes INTEGER NOT NULL,
                canonical_name TEXT NOT NULL,
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE transfers (
                id INTEGER PRIMARY KEY,
                known_file_id INTEGER NOT NULL,
                visible_state TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE transfer_pieces (
                id INTEGER PRIMARY KEY,
                transfer_id INTEGER NOT NULL,
                piece_index INTEGER NOT NULL,
                state TEXT NOT NULL,
                bytes_written INTEGER NOT NULL DEFAULT 0,
                updated_at_ms INTEGER NOT NULL
            );
            "#,
        )
        .unwrap();
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?1, 3, 0)",
            params![SCHEMA_ID],
        )
        .unwrap();
        // The client's on-network identity + secure-ident keypair.
        conn.execute(
            "INSERT INTO local_identities(kind, public_identity, private_secret, created_at_ms, updated_at_ms)
             VALUES ('ed2k-user-hash', ?1, NULL, 0, 0)",
            params![vec![0xABu8; 16]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO local_identities(kind, public_identity, private_secret, created_at_ms, updated_at_ms)
             VALUES ('ed2k-secure-ident', NULL, ?1, 0, 0)",
            params![vec![0xCDu8; 32]],
        )
        .unwrap();
        // A peer with accumulated upload credit.
        conn.execute(
            "INSERT INTO peers(user_hash, uploaded_bytes, downloaded_bytes, first_seen_ms, last_seen_ms)
             VALUES (?1, 123456, 654321, 0, 0)",
            params![vec![0x11u8; 16]],
        )
        .unwrap();
        // A known file + transfer + resume piece.
        conn.execute(
            "INSERT INTO known_files(id, ed2k_hash, size_bytes, canonical_name, first_seen_ms, last_seen_ms, updated_at_ms)
             VALUES (1, ?1, 9000000, 'Sample.Title.mkv', 0, 0, 0)",
            params![vec![0x22u8; 16]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transfers(id, known_file_id, visible_state, created_at_ms, updated_at_ms)
             VALUES (1, 1, 'downloading', 0, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transfer_pieces(transfer_id, piece_index, state, bytes_written, updated_at_ms)
             VALUES (1, 0, 'partial', 4096, 0)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn upgrade_from_v3_preserves_user_data_and_reaches_current() {
        let mut conn = Connection::open_in_memory().unwrap();
        open_legacy_v3_db(&conn);

        migrate_to_current(&mut conn).unwrap();

        // (b) The schema is now at the current version with the new columns
        // present and usable.
        assert_eq!(stored_version(&conn).unwrap(), Some(SCHEMA_VERSION));
        for (table, column) in [
            ("transfer_pieces", "block_bitmap"),
            ("known_files", "all_time_uploaded_bytes"),
            ("peers", "secure_ident_pubkey"),
            ("peers", "secure_ident_pubkey_len"),
            ("transfers", "delivered_path"),
            ("transfers", "source_path"),
        ] {
            let tx = conn.transaction().unwrap();
            assert!(
                column_exists(&tx, table, column).unwrap(),
                "{table}.{column} must exist after migration"
            );
            tx.commit().unwrap();
        }
        // New columns are writable/readable.
        conn.execute(
            "UPDATE peers SET secure_ident_pubkey = ?1, secure_ident_pubkey_len = 80",
            params![vec![0x99u8; 80]],
        )
        .unwrap();

        // (a) The pre-existing user data survived intact.
        let upload_credit: i64 = conn
            .query_row("SELECT uploaded_bytes FROM peers", [], |r| r.get(0))
            .unwrap();
        assert_eq!(upload_credit, 123456);
        let name: String = conn
            .query_row("SELECT canonical_name FROM known_files", [], |r| r.get(0))
            .unwrap();
        assert_eq!(name, "Sample.Title.mkv");
        let piece_bytes: i64 = conn
            .query_row("SELECT bytes_written FROM transfer_pieces", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(piece_bytes, 4096);
        let user_hash: Vec<u8> = conn
            .query_row(
                "SELECT public_identity FROM local_identities WHERE kind = 'ed2k-user-hash'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(user_hash, vec![0xABu8; 16]);
        let secret: Vec<u8> = conn
            .query_row(
                "SELECT private_secret FROM local_identities WHERE kind = 'ed2k-secure-ident'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(secret, vec![0xCDu8; 32]);

        // The new column defaulted correctly for the existing known_files row.
        let all_time: i64 = conn
            .query_row("SELECT all_time_uploaded_bytes FROM known_files", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(all_time, 0);
    }

    #[test]
    fn migration_ladder_is_idempotent() {
        let mut conn = Connection::open_in_memory().unwrap();
        open_legacy_v3_db(&conn);
        migrate_to_current(&mut conn).unwrap();
        // Running again must be a clean no-op (stored == current path) and not
        // error on the already-added columns.
        migrate_to_current(&mut conn).unwrap();
        assert_eq!(stored_version(&conn).unwrap(), Some(SCHEMA_VERSION));
    }

    #[test]
    fn newer_than_current_database_is_refused_not_wiped() {
        let mut conn = Connection::open_in_memory().unwrap();
        open_legacy_v3_db(&conn);
        // Stamp the marker to a version newer than this build understands.
        conn.execute(
            "UPDATE metadata_schema SET schema_version = ?2 WHERE schema_id = ?1",
            params![SCHEMA_ID, SCHEMA_VERSION + 1],
        )
        .unwrap();

        let err = migrate_to_current(&mut conn).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("newer than this build"),
            "expected a refuse-to-open error, got: {msg}"
        );
        // (c) Crucially the data is STILL THERE -- nothing was dropped.
        let credit: i64 = conn
            .query_row("SELECT uploaded_bytes FROM peers", [], |r| r.get(0))
            .unwrap();
        assert_eq!(credit, 123456);
        assert_eq!(stored_version(&conn).unwrap(), Some(SCHEMA_VERSION + 1));
    }

    /// End-to-end through the public store: a real upgrade path where an older
    /// marked file is opened by the current binary keeps every row.
    #[test]
    fn store_open_migrates_in_place_without_data_loss() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "emulebb-metadata-migrate-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        {
            let conn = Connection::open(&path).unwrap();
            open_legacy_v3_db(&conn);
        }
        let store = MetadataStore::open(&path).unwrap();
        // Data survived and the new secure-ident column is now usable through
        // the store's own credit/secure-ident path.
        let credit = store
            .peer_credit_by_hash("11111111111111111111111111111111")
            .unwrap()
            .expect("peer credit must survive the migration");
        assert_eq!(credit.uploaded_bytes, 123456);
        let wiped = store
            .record_verified_secure_ident("11111111111111111111111111111111", &[7u8; 80])
            .unwrap();
        assert!(!wiped, "first secure-ident verify must keep credits");
        drop(store);
        let _ = std::fs::remove_file(&path);
    }
}
