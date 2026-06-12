//! SQLite metadata store for the Rust eMuleBB client.

use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

pub const SCHEMA_ID: &str = "emulebb.metadata.clean-v1";
pub const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataIndexedFile {
    pub ed2k_hash: String,
    pub name: String,
    pub size_bytes: u64,
    pub content_type: String,
    pub availability_score: i64,
}

#[derive(Debug)]
pub struct MetadataStore {
    conn: Connection,
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
        let mut store = Self { conn };
        store.ensure_schema()?;
        Ok(store)
    }

    fn ensure_schema(&mut self) -> Result<()> {
        if self.table_exists("metadata_schema")? {
            self.verify_schema_marker()?;
            return Ok(());
        }
        if self.has_user_tables()? {
            bail!(
                "metadata database exists but is not {SCHEMA_ID} v{SCHEMA_VERSION}; remove or recreate the profile database"
            );
        }
        self.create_schema()
    }

    fn table_exists(&self, table: &str) -> Result<bool> {
        self.conn
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
        let count: i64 = self.conn.query_row(
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

    fn verify_schema_marker(&self) -> Result<()> {
        let marker = self
            .conn
            .query_row(
                "SELECT schema_version FROM metadata_schema WHERE schema_id = ?1",
                params![SCHEMA_ID],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        match marker {
            Some(SCHEMA_VERSION) => Ok(()),
            _ => bail!(
                "metadata database schema marker mismatch; expected {SCHEMA_ID} v{SCHEMA_VERSION}"
            ),
        }
    }

    fn create_schema(&mut self) -> Result<()> {
        let now = unix_ms();
        let profile_uuid = Uuid::new_v4().to_string();
        let tx = self.conn.transaction()?;
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
        let tx = self.conn.transaction()?;

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
        let mut stmt = self.conn.prepare(
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
        self.conn
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

    pub fn table_count(&self, table_name: &str) -> Result<i64> {
        ensure!(
            table_name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'),
            "invalid table name"
        );
        self.conn
            .query_row(&format!("SELECT count(*) FROM {table_name}"), [], |row| {
                row.get(0)
            })
            .with_context(|| format!("failed to count {table_name}"))
    }
}

pub fn normalize_search_text(value: &str) -> String {
    value
        .nfkc()
        .flat_map(char::to_lowercase)
        .map(|ch| if ch.is_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode_fixed_hex(value: &str, byte_len: usize, label: &str) -> Result<Vec<u8>> {
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

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

const SCHEMA_SQL: &str = r#"
CREATE TABLE metadata_schema (
    schema_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE profile (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    uuid TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE local_identities (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL UNIQUE,
    public_identity BLOB,
    private_secret BLOB,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    CHECK (public_identity IS NULL OR length(public_identity) IN (16, 20))
);

CREATE TABLE preferences (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE categories (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT,
    comment TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 0,
    color INTEGER,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    deleted_at_ms INTEGER
);

CREATE TABLE friends (
    id INTEGER PRIMARY KEY,
    user_hash BLOB NOT NULL UNIQUE CHECK(length(user_hash) = 16),
    name TEXT NOT NULL,
    last_address TEXT,
    last_port INTEGER NOT NULL DEFAULT 0,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER,
    deleted_at_ms INTEGER
);

CREATE TABLE content_objects (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    primary_hash_kind TEXT,
    primary_hash BLOB,
    display_name TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER,
    raw_metadata BLOB,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    deleted_at_ms INTEGER,
    UNIQUE(kind, primary_hash_kind, primary_hash),
    CHECK (primary_hash IS NULL OR length(primary_hash) IN (16, 20))
);

CREATE TABLE content_links (
    id INTEGER PRIMARY KEY,
    parent_object_id INTEGER NOT NULL REFERENCES content_objects(id) ON DELETE CASCADE,
    child_object_id INTEGER NOT NULL REFERENCES content_objects(id) ON DELETE CASCADE,
    link_kind TEXT NOT NULL,
    ordinal INTEGER NOT NULL DEFAULT 0,
    display_name TEXT NOT NULL DEFAULT '',
    raw_metadata BLOB,
    created_at_ms INTEGER NOT NULL,
    deleted_at_ms INTEGER,
    UNIQUE(parent_object_id, child_object_id, link_kind, ordinal)
);

CREATE TABLE known_files (
    id INTEGER PRIMARY KEY,
    content_object_id INTEGER NOT NULL REFERENCES content_objects(id) ON DELETE CASCADE,
    ed2k_hash BLOB NOT NULL UNIQUE CHECK(length(ed2k_hash) = 16),
    size_bytes INTEGER NOT NULL,
    canonical_name TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    part_size INTEGER,
    part_count INTEGER,
    completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1)),
    md4_hashset_acquired INTEGER NOT NULL DEFAULT 0 CHECK(md4_hashset_acquired IN (0, 1)),
    aich_hashset_acquired INTEGER NOT NULL DEFAULT 0 CHECK(aich_hashset_acquired IN (0, 1)),
    aich_root BLOB CHECK(aich_root IS NULL OR length(aich_root) = 20),
    upload_priority TEXT NOT NULL DEFAULT 'normal',
    auto_upload_priority INTEGER NOT NULL DEFAULT 0 CHECK(auto_upload_priority IN (0, 1)),
    comment TEXT NOT NULL DEFAULT '',
    rating INTEGER NOT NULL DEFAULT 0 CHECK(rating BETWEEN 0 AND 5),
    availability_score INTEGER NOT NULL DEFAULT 0,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE file_names (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    UNIQUE(known_file_id, normalized_name, source_kind)
);

CREATE VIRTUAL TABLE file_name_fts USING fts5(
    name,
    normalized_name,
    content='file_names',
    content_rowid='id',
    tokenize = 'unicode61 remove_diacritics 2 tokenchars ''.-_'''
);

CREATE TRIGGER file_names_ai AFTER INSERT ON file_names BEGIN
    INSERT INTO file_name_fts(rowid, name, normalized_name)
    VALUES (new.id, new.name, new.normalized_name);
END;

CREATE TRIGGER file_names_ad AFTER DELETE ON file_names BEGIN
    INSERT INTO file_name_fts(file_name_fts, rowid, name, normalized_name)
    VALUES('delete', old.id, old.name, old.normalized_name);
END;

CREATE TRIGGER file_names_au AFTER UPDATE ON file_names BEGIN
    INSERT INTO file_name_fts(file_name_fts, rowid, name, normalized_name)
    VALUES('delete', old.id, old.name, old.normalized_name);
    INSERT INTO file_name_fts(rowid, name, normalized_name)
    VALUES (new.id, new.name, new.normalized_name);
END;

CREATE TABLE ed2k_part_hashes (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL,
    md4_hash BLOB NOT NULL CHECK(length(md4_hash) = 16),
    UNIQUE(known_file_id, part_index)
);

CREATE TABLE aich_part_hashes (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL,
    aich_hash BLOB NOT NULL CHECK(length(aich_hash) = 20),
    UNIQUE(known_file_id, part_index)
);

CREATE TABLE verified_ranges (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    start_offset INTEGER NOT NULL,
    end_offset INTEGER NOT NULL,
    source_kind TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    CHECK(end_offset >= start_offset)
);

CREATE TABLE local_paths (
    id INTEGER PRIMARY KEY,
    display_path TEXT NOT NULL,
    native_path BLOB NOT NULL,
    canonical_display_path TEXT,
    normalized_key TEXT NOT NULL,
    platform TEXT NOT NULL,
    file_identity_kind TEXT,
    file_identity BLOB,
    size_bytes INTEGER,
    mtime_ms INTEGER,
    last_stat_ms INTEGER,
    UNIQUE(platform, normalized_key)
);

CREATE TABLE shared_directory_roots (
    id INTEGER PRIMARY KEY,
    path_id INTEGER NOT NULL REFERENCES local_paths(id),
    recursive INTEGER NOT NULL DEFAULT 0 CHECK(recursive IN (0, 1)),
    monitor_owned INTEGER NOT NULL DEFAULT 0 CHECK(monitor_owned IN (0, 1)),
    shareable INTEGER NOT NULL DEFAULT 1 CHECK(shareable IN (0, 1)),
    accessible INTEGER NOT NULL DEFAULT 1 CHECK(accessible IN (0, 1)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    last_scan_ms INTEGER,
    created_at_ms INTEGER NOT NULL,
    deleted_at_ms INTEGER,
    UNIQUE(path_id)
);

CREATE TABLE shared_file_memberships (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    root_id INTEGER NOT NULL REFERENCES shared_directory_roots(id),
    path_id INTEGER NOT NULL REFERENCES local_paths(id),
    relative_path TEXT NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    removed_at_ms INTEGER,
    UNIQUE(known_file_id, root_id, path_id)
);

CREATE TABLE unshared_files (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    reason TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL,
    UNIQUE(known_file_id)
);

CREATE TABLE transfers (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    visible_state TEXT NOT NULL,
    control_state TEXT,
    category_id INTEGER REFERENCES categories(id),
    priority TEXT NOT NULL DEFAULT 'normal',
    target_path_id INTEGER REFERENCES local_paths(id),
    payload_directory TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    removed_at_ms INTEGER,
    UNIQUE(known_file_id)
);

CREATE TABLE transfer_pieces (
    id INTEGER PRIMARY KEY,
    transfer_id INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
    piece_index INTEGER NOT NULL,
    state TEXT NOT NULL,
    bytes_written INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL,
    UNIQUE(transfer_id, piece_index)
);

CREATE TABLE servers (
    id INTEGER PRIMARY KEY,
    endpoint TEXT NOT NULL UNIQUE,
    address TEXT NOT NULL,
    port INTEGER NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    priority TEXT NOT NULL DEFAULT 'normal',
    static_server INTEGER NOT NULL DEFAULT 0 CHECK(static_server IN (0, 1)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    failed_count INTEGER NOT NULL DEFAULT 0,
    ping_ms INTEGER,
    users INTEGER,
    files INTEGER,
    soft_files INTEGER,
    hard_files INTEGER,
    version TEXT NOT NULL DEFAULT '',
    obfuscation_tcp_port INTEGER,
    udp_flags INTEGER,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    deleted_at_ms INTEGER
);

CREATE TABLE peers (
    id INTEGER PRIMARY KEY,
    user_hash BLOB CHECK(user_hash IS NULL OR length(user_hash) = 16),
    client_id TEXT,
    user_name TEXT NOT NULL DEFAULT '',
    client_software TEXT NOT NULL DEFAULT '',
    client_mod TEXT NOT NULL DEFAULT '',
    last_address TEXT,
    last_tcp_port INTEGER,
    last_udp_port INTEGER,
    low_id INTEGER NOT NULL DEFAULT 0 CHECK(low_id IN (0, 1)),
    secure_ident_state TEXT NOT NULL DEFAULT '',
    friend INTEGER NOT NULL DEFAULT 0 CHECK(friend IN (0, 1)),
    banned INTEGER NOT NULL DEFAULT 0 CHECK(banned IN (0, 1)),
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    UNIQUE(user_hash)
);

CREATE TABLE transfer_sources (
    id INTEGER PRIMARY KEY,
    transfer_id INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
    peer_id INTEGER REFERENCES peers(id),
    ip TEXT NOT NULL,
    tcp_port INTEGER NOT NULL,
    udp_port INTEGER,
    user_hash BLOB CHECK(user_hash IS NULL OR length(user_hash) = 16),
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    last_outcome TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX transfer_sources_identity_idx
ON transfer_sources(transfer_id, ip, tcp_port, coalesce(udp_port, 0));

CREATE TABLE peer_observations (
    id INTEGER PRIMARY KEY,
    peer_id INTEGER REFERENCES peers(id),
    endpoint TEXT NOT NULL DEFAULT '',
    protocol_family TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    known_file_id INTEGER REFERENCES known_files(id),
    raw_payload BLOB,
    observed_at_ms INTEGER NOT NULL
);

CREATE TABLE peer_file_history (
    id INTEGER PRIMARY KEY,
    peer_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    availability_parts INTEGER NOT NULL DEFAULT 0,
    queue_rank INTEGER,
    observation_count INTEGER NOT NULL DEFAULT 0,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    UNIQUE(peer_id, known_file_id)
);

CREATE TABLE kad_nodes (
    id INTEGER PRIMARY KEY,
    node_id BLOB NOT NULL UNIQUE CHECK(length(node_id) = 16),
    ip TEXT NOT NULL,
    tcp_port INTEGER NOT NULL,
    udp_port INTEGER NOT NULL,
    kad_version INTEGER,
    udp_key INTEGER,
    udp_key_ip TEXT,
    verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0, 1)),
    routing_bucket INTEGER,
    routing_state TEXT NOT NULL DEFAULT '',
    fail_count INTEGER NOT NULL DEFAULT 0,
    source_kind TEXT NOT NULL DEFAULT '',
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL
);

CREATE TABLE kad_node_observations (
    id INTEGER PRIMARY KEY,
    kad_node_id INTEGER REFERENCES kad_nodes(id),
    event_kind TEXT NOT NULL,
    raw_payload BLOB,
    observed_at_ms INTEGER NOT NULL
);

CREATE TABLE kad_keyword_publishes (
    id INTEGER PRIMARY KEY,
    target_node_id BLOB NOT NULL CHECK(length(target_node_id) = 16),
    file_hash BLOB NOT NULL CHECK(length(file_hash) = 16),
    known_file_id INTEGER REFERENCES known_files(id),
    raw_tags BLOB NOT NULL,
    load INTEGER,
    valid INTEGER NOT NULL DEFAULT 1 CHECK(valid IN (0, 1)),
    observed_at_ms INTEGER NOT NULL
);

CREATE TABLE kad_source_publishes (
    id INTEGER PRIMARY KEY,
    target_node_id BLOB NOT NULL CHECK(length(target_node_id) = 16),
    publisher_id BLOB NOT NULL CHECK(length(publisher_id) = 16),
    file_hash BLOB NOT NULL CHECK(length(file_hash) = 16),
    source_ip TEXT NOT NULL,
    source_tcp_port INTEGER NOT NULL,
    source_udp_port INTEGER NOT NULL,
    raw_tags BLOB NOT NULL,
    load INTEGER,
    valid INTEGER NOT NULL DEFAULT 1 CHECK(valid IN (0, 1)),
    observed_at_ms INTEGER NOT NULL
);

CREATE TABLE kad_note_publishes (
    id INTEGER PRIMARY KEY,
    target_node_id BLOB NOT NULL CHECK(length(target_node_id) = 16),
    publisher_id BLOB NOT NULL CHECK(length(publisher_id) = 16),
    publisher_ip TEXT NOT NULL,
    file_hash BLOB CHECK(file_hash IS NULL OR length(file_hash) = 16),
    raw_tags BLOB NOT NULL,
    load INTEGER,
    valid INTEGER NOT NULL DEFAULT 1 CHECK(valid IN (0, 1)),
    observed_at_ms INTEGER NOT NULL
);

CREATE TABLE kad_snoop_requests (
    id INTEGER PRIMARY KEY,
    family TEXT NOT NULL,
    target_hash BLOB CHECK(target_hash IS NULL OR length(target_hash) = 16),
    dedup_key TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_eligible_ms INTEGER,
    raw_request_metadata BLOB,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    UNIQUE(family, dedup_key)
);

CREATE TABLE search_sessions (
    id INTEGER PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    query TEXT NOT NULL,
    normalized_query TEXT NOT NULL,
    method TEXT NOT NULL,
    search_type TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER
);

CREATE TABLE search_results (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES search_sessions(id) ON DELETE CASCADE,
    known_file_id INTEGER REFERENCES known_files(id),
    source_method TEXT NOT NULL,
    file_hash BLOB CHECK(file_hash IS NULL OR length(file_hash) = 16),
    name TEXT NOT NULL,
    size_bytes INTEGER,
    source_count INTEGER NOT NULL DEFAULT 0,
    complete_source_count INTEGER NOT NULL DEFAULT 0,
    file_type TEXT NOT NULL DEFAULT '',
    complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0, 1)),
    known_type TEXT NOT NULL DEFAULT '',
    directory TEXT NOT NULL DEFAULT '',
    raw_metadata BLOB,
    observed_at_ms INTEGER NOT NULL
);

CREATE TABLE search_observations (
    id INTEGER PRIMARY KEY,
    session_id INTEGER REFERENCES search_sessions(id) ON DELETE CASCADE,
    source_method TEXT NOT NULL,
    raw_payload BLOB NOT NULL,
    observed_at_ms INTEGER NOT NULL
);

CREATE INDEX known_files_hash_idx ON known_files(ed2k_hash);
CREATE INDEX file_names_normalized_idx ON file_names(normalized_name);
CREATE INDEX shared_file_memberships_file_idx ON shared_file_memberships(known_file_id);
CREATE INDEX transfer_sources_transfer_idx ON transfer_sources(transfer_id);
CREATE INDEX peer_observations_peer_time_idx ON peer_observations(peer_id, observed_at_ms);
CREATE INDEX kad_nodes_last_seen_idx ON kad_nodes(last_seen_ms);
CREATE INDEX kad_keyword_target_idx ON kad_keyword_publishes(target_node_id, observed_at_ms);
CREATE INDEX kad_source_file_idx ON kad_source_publishes(file_hash, observed_at_ms);
CREATE INDEX kad_note_file_idx ON kad_note_publishes(file_hash, observed_at_ms);
CREATE INDEX search_results_session_idx ON search_results(session_id, observed_at_ms);
"#;

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
    fn rejects_unmarked_existing_database() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE files(id INTEGER PRIMARY KEY)", [])
            .unwrap();
        let error = MetadataStore::from_connection(conn)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not emulebb.metadata.clean-v1"));
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
}
