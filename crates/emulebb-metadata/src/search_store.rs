use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use crate::{
    search_model::{MetadataSearch, MetadataSearchResult},
    store::{bool_to_i64, decode_fixed_hex, unix_ms},
    text::normalize_search_text,
};

impl super::MetadataStore {
    pub fn upsert_search(&self, search: &MetadataSearch) -> Result<()> {
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute(
            r#"
            INSERT INTO search_sessions(
                public_id, query, normalized_query, method, file_type_filter, status,
                created_at_ms, updated_at_ms, completed_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(public_id) DO UPDATE SET
                query = excluded.query,
                normalized_query = excluded.normalized_query,
                method = excluded.method,
                file_type_filter = excluded.file_type_filter,
                status = excluded.status,
                updated_at_ms = excluded.updated_at_ms,
                completed_at_ms = excluded.completed_at_ms
            "#,
            params![
                search.public_id,
                search.query,
                search.normalized_query,
                search.method,
                search.file_type_filter,
                search.status,
                search.created_at_ms,
                search.updated_at_ms,
                search.completed_at_ms,
            ],
        )?;
        let session_id: i64 = tx.query_row(
            "SELECT id FROM search_sessions WHERE public_id = ?1",
            params![search.public_id],
            |row| row.get(0),
        )?;
        tx.execute(
            "DELETE FROM search_results WHERE session_id = ?1",
            params![session_id],
        )?;
        for result in &search.results {
            let file_hash = optional_ed2k_hash(&result.file_hash)?;
            let known_file_id = match file_hash.as_ref() {
                Some(hash) => tx
                    .query_row(
                        "SELECT id FROM known_files WHERE ed2k_hash = ?1",
                        params![hash],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?,
                None => None,
            };
            tx.execute(
                r#"
                INSERT INTO search_results(
                    session_id, known_file_id, network, file_hash, name, size_bytes,
                    source_count, complete_source_count, file_type, complete, directory,
                    observed_at_ms
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                "#,
                params![
                    session_id,
                    known_file_id,
                    result.network,
                    file_hash,
                    result.name,
                    result.size_bytes as i64,
                    i64::from(result.source_count),
                    i64::from(result.complete_source_count),
                    result.file_type,
                    bool_to_i64(result.complete),
                    result.directory,
                    if result.observed_at_ms > 0 {
                        result.observed_at_ms
                    } else {
                        now
                    },
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_searches(&self) -> Result<Vec<MetadataSearch>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, public_id, query, normalized_query, method, file_type_filter,
                   status, created_at_ms, updated_at_ms, completed_at_ms
            FROM search_sessions
            ORDER BY created_at_ms, id
            "#,
        )?;
        let sessions = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    MetadataSearch {
                        public_id: row.get(1)?,
                        query: row.get(2)?,
                        normalized_query: row.get(3)?,
                        method: row.get(4)?,
                        file_type_filter: row.get(5)?,
                        status: row.get(6)?,
                        created_at_ms: row.get(7)?,
                        updated_at_ms: row.get(8)?,
                        completed_at_ms: row.get(9)?,
                        results: Vec::new(),
                    },
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut searches = Vec::with_capacity(sessions.len());
        for (session_id, mut search) in sessions {
            search.results = load_search_results(&conn, session_id)?;
            searches.push(search);
        }
        Ok(searches)
    }

    pub fn delete_search(&self, public_id: &str) -> Result<bool> {
        let deleted = self.connection()?.execute(
            "DELETE FROM search_sessions WHERE public_id = ?1",
            params![public_id],
        )?;
        Ok(deleted != 0)
    }

    pub fn clear_searches(&self) -> Result<()> {
        self.connection()?
            .execute("DELETE FROM search_sessions", [])?;
        Ok(())
    }
}

fn load_search_results(
    conn: &rusqlite::Connection,
    session_id: i64,
) -> Result<Vec<MetadataSearchResult>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT network,
               CASE WHEN file_hash IS NULL THEN '' ELSE lower(hex(file_hash)) END,
               name, size_bytes, source_count, complete_source_count, file_type,
               complete, directory, observed_at_ms
        FROM search_results
        WHERE session_id = ?1
        ORDER BY id
        "#,
    )?;
    let rows = stmt.query_map(params![session_id], |row| {
        Ok(MetadataSearchResult {
            network: row.get(0)?,
            file_hash: row.get(1)?,
            name: row.get(2)?,
            size_bytes: row.get::<_, Option<i64>>(3)?.unwrap_or_default() as u64,
            source_count: row.get::<_, i64>(4)? as u32,
            complete_source_count: row.get::<_, i64>(5)? as u32,
            file_type: row.get(6)?,
            complete: row.get::<_, i64>(7)? != 0,
            directory: row.get(8)?,
            observed_at_ms: row.get(9)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn optional_ed2k_hash(value: &str) -> Result<Option<Vec<u8>>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    decode_fixed_hex(value, 16, "search result ED2K hash").map(Some)
}

pub fn normalized_search_query(query: &str) -> String {
    normalize_search_text(query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_state_roundtrips_unicode_results() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        let search = sample_search("search-one");

        store.upsert_search(&search).unwrap();

        let searches = store.load_searches().unwrap();
        assert_eq!(searches.len(), 1);
        assert_eq!(searches[0].public_id, "search-one");
        assert_eq!(searches[0].results.len(), 1);
        assert_eq!(searches[0].results[0].name, "Zażółć Sample.bin");
    }

    #[test]
    fn delete_and_clear_searches_remove_results() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        store.upsert_search(&sample_search("search-one")).unwrap();
        store.upsert_search(&sample_search("search-two")).unwrap();

        assert!(store.delete_search("search-one").unwrap());
        assert_eq!(store.load_searches().unwrap().len(), 1);
        assert!(!store.delete_search("missing").unwrap());

        store.clear_searches().unwrap();
        assert!(store.load_searches().unwrap().is_empty());
        assert_eq!(store.table_count("search_results").unwrap(), 0);
    }

    fn sample_search(public_id: &str) -> MetadataSearch {
        MetadataSearch {
            public_id: public_id.to_string(),
            query: "zażółć".to_string(),
            normalized_query: normalized_search_query("zażółć"),
            method: "automatic".to_string(),
            file_type_filter: "video".to_string(),
            status: "completed".to_string(),
            created_at_ms: 1,
            updated_at_ms: 2,
            completed_at_ms: Some(2),
            results: vec![MetadataSearchResult {
                network: "automatic".to_string(),
                file_hash: "00112233445566778899aabbccddeeff".to_string(),
                name: "Zażółć Sample.bin".to_string(),
                size_bytes: 123,
                source_count: 4,
                complete_source_count: 3,
                file_type: "video".to_string(),
                complete: false,
                directory: String::new(),
                observed_at_ms: 2,
            }],
        }
    }
}
