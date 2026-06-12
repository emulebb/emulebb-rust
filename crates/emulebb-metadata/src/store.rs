use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
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

    fn ensure_schema(&mut self) -> Result<()> {
        if self.table_exists("metadata_schema")? {
            if self.schema_marker_matches()? {
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

    fn schema_marker_matches(&self) -> Result<bool> {
        let marker = self
            .connection()?
            .query_row(
                "SELECT schema_version FROM metadata_schema WHERE schema_id = ?1",
                params![SCHEMA_ID],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        Ok(marker == Some(SCHEMA_VERSION))
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
            INSERT INTO content_objects(
                kind, primary_hash_kind, primary_hash, display_name, size_bytes,
                first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES ('ed2k_file', 'ed2k', ?1, ?2, ?3, ?4, ?4, ?4)
            ON CONFLICT(kind, primary_hash_kind, primary_hash) DO UPDATE SET
                display_name = excluded.display_name,
                size_bytes = excluded.size_bytes,
                last_seen_ms = excluded.last_seen_ms,
                updated_at_ms = excluded.updated_at_ms
            "#,
            params![hash, file.name, file.size_bytes as i64, now],
        )?;
        let content_object_id: i64 = tx.query_row(
            r#"
            SELECT id FROM content_objects
            WHERE kind = 'ed2k_file' AND primary_hash_kind = 'ed2k' AND primary_hash = ?1
            "#,
            params![decode_fixed_hex(&file.ed2k_hash, 16, "ED2K hash")?],
            |row| row.get(0),
        )?;

        tx.execute(
            r#"
            INSERT INTO known_files(
                content_object_id, ed2k_hash, size_bytes, canonical_name,
                content_type, availability_score, first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?7)
            ON CONFLICT(ed2k_hash) DO UPDATE SET
                content_object_id = excluded.content_object_id,
                size_bytes = excluded.size_bytes,
                canonical_name = excluded.canonical_name,
                content_type = excluded.content_type,
                availability_score = max(known_files.availability_score, excluded.availability_score),
                last_seen_ms = excluded.last_seen_ms,
                updated_at_ms = excluded.updated_at_ms
            "#,
            params![
                content_object_id,
                decode_fixed_hex(&file.ed2k_hash, 16, "ED2K hash")?,
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
            INSERT INTO file_names(known_file_id, name, normalized_name, source_kind, seen_count, first_seen_ms, last_seen_ms)
            VALUES (?1, ?2, ?3, 'index', 1, ?4, ?4)
            ON CONFLICT(known_file_id, normalized_name, source_kind) DO UPDATE SET
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
    fn resets_unmarked_existing_database() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE files(id INTEGER PRIMARY KEY)", [])
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
