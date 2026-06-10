use std::path::Path;

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

mod kad_search_expr;
mod kad_store;
mod snoop_model;
mod snoop_queue;

pub use kad_search_expr::matches_restrictive_keyword_payload;
pub use kad_store::{KadLocalStore, KadLocalStoreConfig};
pub use snoop_model::{SnoopEntry, SnoopQueueConfig};
pub use snoop_queue::{
    ScheduledSnoopRequest, SnoopQueue, SnoopQueueFamilyCounts, SnoopRecordOutcome,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedFile {
    pub ed2k_hash: String,
    pub name: String,
    pub size_bytes: u64,
    pub content_type: String,
    pub availability_score: i64,
}

#[derive(Debug)]
pub struct FileIndex {
    conn: Connection,
}

impl FileIndex {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    pub fn in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let index = Self { conn };
        index.migrate()?;
        Ok(index)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                ed2k_hash BLOB NOT NULL UNIQUE,
                size_bytes INTEGER NOT NULL,
                content_type TEXT NOT NULL,
                availability_score INTEGER NOT NULL DEFAULT 0,
                first_seen INTEGER NOT NULL DEFAULT (unixepoch()),
                last_seen INTEGER NOT NULL DEFAULT (unixepoch())
            );

            CREATE TABLE IF NOT EXISTS file_names (
                id INTEGER PRIMARY KEY,
                file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                normalized_name TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 1,
                first_seen INTEGER NOT NULL DEFAULT (unixepoch()),
                last_seen INTEGER NOT NULL DEFAULT (unixepoch()),
                UNIQUE(file_id, normalized_name)
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS file_name_fts USING fts5(
                name,
                normalized_name,
                content='file_names',
                content_rowid='id',
                tokenize = 'unicode61 remove_diacritics 2 tokenchars ''.-_'''
            );

            CREATE TRIGGER IF NOT EXISTS file_names_ai AFTER INSERT ON file_names BEGIN
                INSERT INTO file_name_fts(rowid, name, normalized_name)
                VALUES (new.id, new.name, new.normalized_name);
            END;

            CREATE TRIGGER IF NOT EXISTS file_names_ad AFTER DELETE ON file_names BEGIN
                INSERT INTO file_name_fts(file_name_fts, rowid, name, normalized_name)
                VALUES('delete', old.id, old.name, old.normalized_name);
            END;

            CREATE TRIGGER IF NOT EXISTS file_names_au AFTER UPDATE ON file_names BEGIN
                INSERT INTO file_name_fts(file_name_fts, rowid, name, normalized_name)
                VALUES('delete', old.id, old.name, old.normalized_name);
                INSERT INTO file_name_fts(rowid, name, normalized_name)
                VALUES (new.id, new.name, new.normalized_name);
            END;
            "#,
        )?;
        Ok(())
    }

    pub fn upsert_file(&mut self, file: &IndexedFile) -> Result<()> {
        let hash = decode_ed2k_hash(&file.ed2k_hash)?;
        let normalized = normalize_file_name(&file.name);
        let tx = self.conn.transaction()?;
        tx.execute(
            r#"
            INSERT INTO files(ed2k_hash, size_bytes, content_type, availability_score)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(ed2k_hash) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                content_type = excluded.content_type,
                availability_score = max(files.availability_score, excluded.availability_score),
                last_seen = unixepoch()
            "#,
            params![
                hash,
                file.size_bytes as i64,
                file.content_type,
                file.availability_score
            ],
        )?;
        let file_id: i64 = tx.query_row(
            "SELECT id FROM files WHERE ed2k_hash = ?1",
            params![decode_ed2k_hash(&file.ed2k_hash)?],
            |row| row.get(0),
        )?;
        tx.execute(
            r#"
            INSERT INTO file_names(file_id, name, normalized_name)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(file_id, normalized_name) DO UPDATE SET
                name = excluded.name,
                seen_count = file_names.seen_count + 1,
                last_seen = unixepoch()
            "#,
            params![file_id, file.name, normalized],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<IndexedFile>> {
        let normalized = normalize_file_name(query);
        if normalized.is_empty() {
            return Ok(Vec::new());
        }
        let mut stmt = self.conn.prepare(
            r#"
            SELECT lower(hex(files.ed2k_hash)), file_names.name, files.size_bytes,
                   files.content_type, files.availability_score
            FROM file_name_fts
            JOIN file_names ON file_names.id = file_name_fts.rowid
            JOIN files ON files.id = file_names.file_id
            WHERE file_name_fts MATCH ?1
            ORDER BY bm25(file_name_fts), files.availability_score DESC, file_names.seen_count DESC
            LIMIT ?2
            "#,
        )?;
        let rows = stmt.query_map(params![normalized, limit as i64], |row| {
            Ok(IndexedFile {
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

    pub fn find_by_hash(&self, ed2k_hash: &str) -> Result<Option<IndexedFile>> {
        let hash = decode_ed2k_hash(ed2k_hash)?;
        self.conn
            .query_row(
                r#"
                SELECT lower(hex(files.ed2k_hash)), file_names.name, files.size_bytes,
                       files.content_type, files.availability_score
                FROM files
                JOIN file_names ON file_names.file_id = files.id
                WHERE files.ed2k_hash = ?1
                ORDER BY file_names.seen_count DESC, file_names.last_seen DESC
                LIMIT 1
                "#,
                params![hash],
                |row| {
                    Ok(IndexedFile {
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
}

pub fn normalize_file_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode_ed2k_hash(value: &str) -> Result<Vec<u8>> {
    let clean = value.trim();
    anyhow::ensure!(clean.len() == 32, "ED2K hash must be 32 hex characters");
    let mut out = Vec::with_capacity(16);
    for index in (0..clean.len()).step_by(2) {
        out.push(u8::from_str_radix(&clean[index..index + 2], 16)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fts_search_returns_indexed_file() {
        let mut index = FileIndex::in_memory().unwrap();
        index
            .upsert_file(&IndexedFile {
                ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
                name: "Example.Movie.2026.1080p.mkv".to_string(),
                size_bytes: 1024,
                content_type: "video".to_string(),
                availability_score: 7,
            })
            .unwrap();

        let results = index.search("example movie", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ed2k_hash, "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn duplicate_normalized_name_updates_one_row() {
        let mut index = FileIndex::in_memory().unwrap();
        let first = IndexedFile {
            ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Example.Movie.mkv".to_string(),
            size_bytes: 1024,
            content_type: "video".to_string(),
            availability_score: 1,
        };
        index.upsert_file(&first).unwrap();
        index.upsert_file(&first).unwrap();

        let results = index.search("example movie", 10).unwrap();
        assert_eq!(results.len(), 1);
    }
}
