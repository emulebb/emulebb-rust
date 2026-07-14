use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard, TryLockError},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::{
    model::{MetadataIndexedFile, MetadataSharedDirectoryRoot},
    schema::{SCHEMA_ID, SCHEMA_SQL, SCHEMA_VERSION},
    text::{normalize_path_key, normalize_search_text},
};

/// Age cap for `transfer_sources` rows. A source last seen longer ago than this
/// almost certainly no longer carries the file, and a live transfer re-learns
/// its current sources from the network, so older rows are pruned on startup.
const TRANSFER_SOURCE_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct MetadataStore {
    conn: Arc<Mutex<Connection>>,
}

impl MetadataStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    pub fn in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    pub fn from_connection(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Crash-consistency: WAL's default `synchronous = NORMAL` does NOT fsync
        // the WAL on every commit, so a committed transfer-manifest transaction
        // (e.g. a piece marked Verified) can reach SQLite's cache while the
        // matching payload bytes are still in the OS cache. On an OS crash /
        // power loss this lets the manifest outrace the on-disk bytes and would
        // resurrect a "Verified" range whose bytes are stale/zero. FULL fsyncs
        // the WAL on commit so a committed manifest state is durable. Paired
        // with `sync_all()` on the payload before the piece-complete checkpoint
        // commit, neither side can outrace the other.
        conn.pragma_update(None, "synchronous", "FULL")?;
        // Defensive: bound contention waits instead of failing immediately with
        // SQLITE_BUSY (the persistence audit flagged the absent busy_timeout).
        conn.pragma_update(None, "busy_timeout", 5000)?;
        let mut store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.ensure_schema()?;
        Ok(store)
    }

    pub(crate) fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow::anyhow!("metadata database mutex poisoned"))
    }

    pub(crate) fn try_connection(&self) -> Result<Option<MutexGuard<'_, Connection>>> {
        match self.conn.try_lock() {
            Ok(conn) => Ok(Some(conn)),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Poisoned(_)) => {
                Err(anyhow::anyhow!("metadata database mutex poisoned"))
            }
        }
    }

    /// Ensure the database matches this development build's fresh schema.
    ///
    /// During the Rust dev phase there is no in-product schema migration path:
    /// a mismatched or unmarked database is dropped and recreated. Operator-local
    /// profile preservation belongs in explicit one-off SQLite/Python updates.
    fn ensure_schema(&mut self) -> Result<()> {
        if self.table_exists("metadata_schema")? {
            if self.stored_schema_version()? == Some(SCHEMA_VERSION) {
                self.prune_transfer_sources()?;
                return Ok(());
            }
            self.reset_schema()?;
            return Ok(());
        }
        if self.has_user_tables()? {
            self.reset_schema()?;
            return Ok(());
        }
        self.create_schema()
    }

    fn stored_schema_version(&self) -> Result<Option<i64>> {
        self.connection()?
            .query_row(
                "SELECT schema_version FROM metadata_schema WHERE schema_id = ?1",
                params![SCHEMA_ID],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Bound the `transfer_sources` table on startup. Source rows accumulate per
    /// transfer with no age cap of their own; this drops the rows that can no
    /// longer be useful: those belonging to a transfer that has been removed
    /// (`removed_at_ms` set), and those last seen beyond
    /// [`TRANSFER_SOURCE_TTL_MS`]. Removed-transfer rows would otherwise survive
    /// (a removed transfer's row is soft-kept) and stale rows describe peers that
    /// almost certainly no longer have the file. Correctness-neutral: a live
    /// transfer re-learns current sources from the network and rewrites them.
    fn prune_transfer_sources(&self) -> Result<()> {
        let cutoff = unix_ms().saturating_sub(TRANSFER_SOURCE_TTL_MS);
        let conn = self.connection()?;
        conn.execute(
            r#"
            DELETE FROM transfer_sources
            WHERE last_seen_ms < ?1
               OR transfer_id IN (
                   SELECT id FROM transfers WHERE removed_at_ms IS NOT NULL
               )
            "#,
            params![cutoff],
        )?;
        Ok(())
    }

    fn table_exists(&self, table: &str) -> Result<bool> {
        self.connection()?
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?1 LIMIT 1",
                params![table],
                |_| Ok(()),
            )
            .optional()
            .map(|value| value.is_some())
            .map_err(Into::into)
    }

    fn has_user_tables(&self) -> Result<bool> {
        let count: i64 = self.connection()?.query_row(
            r#"
            SELECT count(*)
            FROM sqlite_master
            WHERE type IN ('table', 'view', 'trigger')
              AND name NOT LIKE 'sqlite_%'
            "#,
            [],
            |row| row.get(0),
        )?;
        Ok(count != 0)
    }

    fn reset_schema(&mut self) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let objects = tx
            .prepare(
                r#"
                SELECT type, name
                FROM sqlite_master
                WHERE type IN ('table', 'view', 'trigger')
                  AND name NOT LIKE 'sqlite_%'
                ORDER BY CASE type WHEN 'trigger' THEN 0 WHEN 'view' THEN 1 ELSE 2 END, name
                "#,
            )?
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (object_type, name) in objects {
            let escaped = name.replace('"', "\"\"");
            match object_type.as_str() {
                "trigger" => tx.execute_batch(&format!("DROP TRIGGER IF EXISTS \"{escaped}\""))?,
                "view" => tx.execute_batch(&format!("DROP VIEW IF EXISTS \"{escaped}\""))?,
                _ => tx.execute_batch(&format!("DROP TABLE IF EXISTS \"{escaped}\""))?,
            }
        }
        tx.commit()?;
        drop(conn);
        self.create_schema()
    }

    fn create_schema(&mut self) -> Result<()> {
        let now = unix_ms();
        let profile_uuid = Uuid::new_v4().to_string();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute_batch(SCHEMA_SQL)?;
        tx.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?1, ?2, ?3)",
            params![SCHEMA_ID, SCHEMA_VERSION, now],
        )?;
        tx.execute(
            r#"
            INSERT INTO profile(id, uuid, created_by, created_at_ms, updated_at_ms)
            VALUES (1, ?1, 'emulebb-rust', ?2, ?2)
            "#,
            params![profile_uuid, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_indexed_file(&mut self, file: &MetadataIndexedFile) -> Result<()> {
        let hash = decode_fixed_hex(&file.ed2k_hash, 16, "ED2K hash")?;
        let normalized = normalize_search_text(&file.name);
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;

        tx.execute(
            r#"
            INSERT INTO known_files(
                ed2k_hash, size_bytes, display_name,
                content_type, availability_score, first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?6)
            ON CONFLICT(ed2k_hash) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                display_name = excluded.display_name,
                content_type = excluded.content_type,
                availability_score = max(known_files.availability_score, excluded.availability_score),
                last_seen_ms = excluded.last_seen_ms,
                updated_at_ms = excluded.updated_at_ms
            "#,
            params![
                hash,
                file.size_bytes as i64,
                file.name,
                file.content_type,
                file.availability_score,
                now,
            ],
        )?;
        let known_file_id: i64 = tx.query_row(
            "SELECT id FROM known_files WHERE ed2k_hash = ?1",
            params![decode_fixed_hex(&file.ed2k_hash, 16, "ED2K hash")?],
            |row| row.get(0),
        )?;

        tx.execute(
            r#"
            INSERT INTO file_names(known_file_id, name, normalized_name, seen_count, first_seen_ms, last_seen_ms)
            VALUES (?1, ?2, ?3, 1, ?4, ?4)
            ON CONFLICT(known_file_id, normalized_name) DO UPDATE SET
                name = excluded.name,
                seen_count = file_names.seen_count + 1,
                last_seen_ms = excluded.last_seen_ms
            "#,
            params![known_file_id, file.name, normalized, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn search_index(&self, query: &str, limit: usize) -> Result<Vec<MetadataIndexedFile>> {
        let normalized = normalize_search_text(query);
        if normalized.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash)), file_names.name, known_files.size_bytes,
                   known_files.content_type, known_files.availability_score
            FROM file_name_fts
            JOIN file_names ON file_names.id = file_name_fts.rowid
            JOIN known_files ON known_files.id = file_names.known_file_id
            WHERE file_name_fts MATCH ?1
            ORDER BY bm25(file_name_fts), known_files.availability_score DESC, file_names.seen_count DESC
            LIMIT ?2
            "#,
        )?;
        let rows = stmt.query_map(params![normalized, limit as i64], |row| {
            Ok(MetadataIndexedFile {
                ed2k_hash: row.get(0)?,
                name: row.get(1)?,
                size_bytes: row.get::<_, i64>(2)? as u64,
                content_type: row.get(3)?,
                availability_score: row.get(4)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn find_indexed_file_by_hash(
        &self,
        ed2k_hash: &str,
    ) -> Result<Option<MetadataIndexedFile>> {
        let hash = decode_fixed_hex(ed2k_hash, 16, "ED2K hash")?;
        self.connection()?
            .query_row(
                r#"
                SELECT lower(hex(known_files.ed2k_hash)), file_names.name, known_files.size_bytes,
                       known_files.content_type, known_files.availability_score
                FROM known_files
                JOIN file_names ON file_names.known_file_id = known_files.id
                WHERE known_files.ed2k_hash = ?1
                ORDER BY file_names.seen_count DESC, file_names.last_seen_ms DESC
                LIMIT 1
                "#,
                params![hash],
                |row| {
                    Ok(MetadataIndexedFile {
                        ed2k_hash: row.get(0)?,
                        name: row.get(1)?,
                        size_bytes: row.get::<_, i64>(2)? as u64,
                        content_type: row.get(3)?,
                        availability_score: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn replace_shared_directory_roots(
        &mut self,
        roots: &[MetadataSharedDirectoryRoot],
    ) -> Result<()> {
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE shared_directory_roots SET deleted_at_ms = ?1 WHERE deleted_at_ms IS NULL",
            params![now],
        )?;
        for root in roots {
            let path_id = upsert_local_path(&tx, &root.path, now)?;
            tx.execute(
                r#"
                INSERT INTO shared_directory_roots(
                    path_id, recursive, monitor_owned, shareable, accessible,
                    enabled, created_at_ms, deleted_at_ms
                )
                VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, NULL)
                ON CONFLICT(path_id) DO UPDATE SET
                    recursive = excluded.recursive,
                    monitor_owned = excluded.monitor_owned,
                    shareable = excluded.shareable,
                    accessible = excluded.accessible,
                    enabled = 1,
                    deleted_at_ms = NULL
                "#,
                params![
                    path_id,
                    bool_to_i64(root.recursive),
                    bool_to_i64(root.monitor_owned),
                    bool_to_i64(root.shareable),
                    bool_to_i64(root.accessible),
                    now,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn shared_directory_roots(&self) -> Result<Vec<MetadataSharedDirectoryRoot>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT local_paths.display_path,
                   shared_directory_roots.recursive,
                   shared_directory_roots.monitor_owned,
                   shared_directory_roots.shareable,
                   shared_directory_roots.accessible
            FROM shared_directory_roots
            JOIN local_paths ON local_paths.id = shared_directory_roots.path_id
            WHERE shared_directory_roots.enabled = 1
              AND shared_directory_roots.deleted_at_ms IS NULL
            ORDER BY shared_directory_roots.id
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataSharedDirectoryRoot {
                path: row.get(0)?,
                recursive: row.get::<_, i64>(1)? != 0,
                monitor_owned: row.get::<_, i64>(2)? != 0,
                shareable: row.get::<_, i64>(3)? != 0,
                accessible: row.get::<_, i64>(4)? != 0,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn table_count(&self, table_name: &str) -> Result<i64> {
        ensure!(
            table_name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'),
            "invalid table name"
        );
        self.connection()?
            .query_row(&format!("SELECT count(*) FROM {table_name}"), [], |row| {
                row.get(0)
            })
            .with_context(|| format!("failed to count {table_name}"))
    }
}

pub(crate) fn upsert_local_path(
    tx: &rusqlite::Transaction<'_>,
    display_path: &str,
    now: i64,
) -> Result<i64> {
    let normalized_key = normalize_path_key(display_path);
    let platform = current_platform();
    tx.execute(
        r#"
        INSERT INTO local_paths(
            display_path, native_path, canonical_display_path, normalized_key,
            platform, last_stat_ms
        )
        VALUES (?1, ?2, ?1, ?3, ?4, ?5)
        ON CONFLICT(platform, normalized_key) DO UPDATE SET
            display_path = excluded.display_path,
            native_path = excluded.native_path,
            canonical_display_path = excluded.canonical_display_path,
            last_stat_ms = excluded.last_stat_ms
        "#,
        params![
            display_path,
            display_path.as_bytes(),
            normalized_key,
            platform,
            now,
        ],
    )?;
    tx.query_row(
        "SELECT id FROM local_paths WHERE platform = ?1 AND normalized_key = ?2",
        params![platform, normalize_path_key(display_path)],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

pub(crate) fn current_platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unix"
    }
}

pub(crate) fn bool_to_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

pub(crate) fn decode_fixed_hex(value: &str, byte_len: usize, label: &str) -> Result<Vec<u8>> {
    let clean = value.trim();
    ensure!(
        clean.len() == byte_len * 2,
        "{label} must be {} hex characters",
        byte_len * 2
    );
    let mut out = Vec::with_capacity(byte_len);
    for index in (0..clean.len()).step_by(2) {
        out.push(u8::from_str_radix(&clean[index..index + 2], 16)?);
    }
    Ok(out)
}

pub(crate) fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn creates_clean_schema() {
        let store = MetadataStore::in_memory().unwrap();
        assert_eq!(store.table_count("metadata_schema").unwrap(), 1);
        assert_eq!(store.table_count("profile").unwrap(), 1);
    }

    #[test]
    fn connection_enables_durable_synchronous_and_busy_timeout() {
        // Crash-consistency guard: WAL alone defaults to synchronous = NORMAL,
        // which does not fsync the WAL on commit and would let a committed
        // transfer-manifest state outrace the on-disk payload bytes. The store
        // must raise it to FULL (2) and set a defensive busy_timeout.
        let store = MetadataStore::in_memory().unwrap();
        let conn = store.connection().unwrap();
        let synchronous: i64 = conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(synchronous, 2, "synchronous must be FULL (2)");
        let busy_timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(busy_timeout, 5000, "busy_timeout must be 5000ms");
    }

    #[test]
    fn resets_unmarked_existing_database() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE files(id INTEGER PRIMARY KEY)", [])
            .unwrap();
        let store = MetadataStore::from_connection(conn).unwrap();
        assert_eq!(store.table_count("metadata_schema").unwrap(), 1);
        assert!(!store.table_exists("files").unwrap());
    }

    #[test]
    fn resets_marked_database_with_noncurrent_schema_version() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE metadata_schema (
                schema_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            CREATE TABLE files(id INTEGER PRIMARY KEY);
            INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms)
            VALUES ('emulebb.metadata.clean-v2', 1, 0);
            INSERT INTO files(id) VALUES (7);
            "#,
        )
        .unwrap();

        let store = MetadataStore::from_connection(conn).unwrap();

        assert_eq!(store.table_count("metadata_schema").unwrap(), 1);
        assert!(!store.table_exists("files").unwrap());
    }

    #[test]
    fn file_index_roundtrips_unicode_names() {
        let mut store = MetadataStore::in_memory().unwrap();
        store
            .upsert_indexed_file(&MetadataIndexedFile {
                ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
                name: "Zażółć.Gęślą.Jaźń.2026.mkv".to_string(),
                size_bytes: 1024,
                content_type: "video".to_string(),
                availability_score: 7,
            })
            .unwrap();

        let results = store.search_index("gęślą jaźń", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ed2k_hash, "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn duplicate_normalized_name_updates_one_row() {
        let mut store = MetadataStore::in_memory().unwrap();
        let file = MetadataIndexedFile {
            ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Sample.Title.mkv".to_string(),
            size_bytes: 1024,
            content_type: "video".to_string(),
            availability_score: 1,
        };
        store.upsert_indexed_file(&file).unwrap();
        store.upsert_indexed_file(&file).unwrap();

        assert_eq!(store.table_count("file_names").unwrap(), 1);
    }

    #[test]
    fn prune_transfer_sources_drops_removed_transfer_and_stale_rows() {
        let store = MetadataStore::in_memory().unwrap();
        let now = unix_ms();
        {
            let conn = store.connection().unwrap();
            // Two known files + transfers: one live, one removed.
            conn.execute(
                "INSERT INTO known_files(id, ed2k_hash, size_bytes, display_name, first_seen_ms, last_seen_ms, updated_at_ms)
                 VALUES (1, ?1, 1, 'a.bin', 0, 0, 0), (2, ?2, 1, 'b.bin', 0, 0, 0)",
                params![vec![0x11u8; 16], vec![0x22u8; 16]],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO transfers(id, known_file_id, visible_state, created_at_ms, updated_at_ms, removed_at_ms)
                 VALUES (1, 1, 'downloading', 0, 0, NULL),
                        (2, 2, 'downloading', 0, 0, ?1)",
                params![now],
            )
            .unwrap();
            // Live transfer: one fresh source (kept) + one stale source (pruned).
            // Removed transfer: one fresh source (pruned by transfer removal).
            conn.execute(
                "INSERT INTO transfer_sources(transfer_id, ip, tcp_port, first_seen_ms, last_seen_ms)
                 VALUES (1, '10.0.0.1', 4662, 0, ?1),
                        (1, '10.0.0.2', 4662, 0, ?2),
                        (2, '10.0.0.3', 4662, 0, ?1)",
                params![now, now - TRANSFER_SOURCE_TTL_MS - 1],
            )
            .unwrap();
        }

        store.prune_transfer_sources().unwrap();

        let conn = store.connection().unwrap();
        let remaining: Vec<(i64, String)> = conn
            .prepare("SELECT transfer_id, ip FROM transfer_sources ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            remaining,
            vec![(1, "10.0.0.1".to_string())],
            "only the fresh source of the live transfer should survive"
        );
    }

    #[test]
    fn shared_directory_roots_roundtrip_and_replace() {
        let mut store = MetadataStore::in_memory().unwrap();
        store
            .replace_shared_directory_roots(&[
                MetadataSharedDirectoryRoot {
                    path: "/tmp/alpha".to_string(),
                    recursive: true,
                    monitor_owned: false,
                    shareable: true,
                    accessible: true,
                },
                MetadataSharedDirectoryRoot {
                    path: "/tmp/beta".to_string(),
                    recursive: false,
                    monitor_owned: false,
                    shareable: true,
                    accessible: true,
                },
            ])
            .unwrap();
        let roots = store.shared_directory_roots().unwrap();
        assert_eq!(roots.len(), 2);
        assert!(roots[0].recursive);

        store
            .replace_shared_directory_roots(&[MetadataSharedDirectoryRoot {
                path: "/tmp/beta".to_string(),
                recursive: true,
                monitor_owned: false,
                shareable: true,
                accessible: true,
            }])
            .unwrap();
        let roots = store.shared_directory_roots().unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].path, "/tmp/beta");
        assert!(roots[0].recursive);
    }
}
