use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use crate::{
    search_model::{MetadataSearch, MetadataSearchResult, MetadataSearchResultObservation},
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
                public_id, query, normalized_query, requested_method, resolved_method,
                file_type_filter, status, created_at_ms, updated_at_ms, completed_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(public_id) DO UPDATE SET
                query = excluded.query,
                normalized_query = excluded.normalized_query,
                requested_method = excluded.requested_method,
                resolved_method = excluded.resolved_method,
                file_type_filter = excluded.file_type_filter,
                status = excluded.status,
                updated_at_ms = excluded.updated_at_ms,
                completed_at_ms = excluded.completed_at_ms
            "#,
            params![
                search.public_id,
                search.query,
                search.normalized_query,
                search.requested_method,
                search.resolved_method,
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
            let file_hash = decode_fixed_hex(&result.file_hash, 16, "search result ED2K hash")?;
            let known_file_id = tx
                .query_row(
                    "SELECT id FROM known_files WHERE ed2k_hash = ?1",
                    params![file_hash],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            tx.execute(
                r#"
                INSERT INTO search_results(
                    session_id, known_file_id, file_hash, name, size_bytes,
                    source_count, complete_source_count, file_type, rating, aich_hash,
                    complete, directory
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                "#,
                params![
                    session_id,
                    known_file_id,
                    file_hash,
                    result.name,
                    result.size_bytes as i64,
                    i64::from(result.source_count),
                    i64::from(result.complete_source_count),
                    result.file_type,
                    i64::from(result.rating),
                    result.aich_hash,
                    bool_to_i64(result.complete),
                    result.directory,
                ],
            )?;
            let result_id = tx.last_insert_rowid();
            for observation in &result.observations {
                tx.execute(
                    r#"
                    INSERT INTO search_result_observations(
                        result_id, origin, name, size_bytes, source_count,
                        complete_source_count, source_client_id, source_client_port,
                        file_type, rating, aich_hash, complete, directory, observed_at_ms
                    )
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                    "#,
                    params![
                        result_id,
                        observation.origin,
                        observation.name,
                        observation.size_bytes as i64,
                        i64::from(observation.source_count),
                        i64::from(observation.complete_source_count),
                        observation.source_client_id.map(i64::from),
                        observation.source_client_port.map(i64::from),
                        observation.file_type,
                        i64::from(observation.rating),
                        observation.aich_hash,
                        bool_to_i64(observation.complete),
                        observation.directory,
                        if observation.observed_at_ms > 0 {
                            observation.observed_at_ms
                        } else {
                            now
                        },
                    ],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_searches(&self) -> Result<Vec<MetadataSearch>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, public_id, query, normalized_query, requested_method,
                   resolved_method, file_type_filter, status, created_at_ms,
                   updated_at_ms, completed_at_ms
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
                        requested_method: row.get(4)?,
                        resolved_method: row.get(5)?,
                        file_type_filter: row.get(6)?,
                        status: row.get(7)?,
                        created_at_ms: row.get(8)?,
                        updated_at_ms: row.get(9)?,
                        completed_at_ms: row.get(10)?,
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
        SELECT id, lower(hex(file_hash)),
               name, size_bytes, source_count, complete_source_count, file_type,
               rating, aich_hash, complete, directory
        FROM search_results
        WHERE session_id = ?1
        ORDER BY id
        "#,
    )?;
    let rows = stmt.query_map(params![session_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            MetadataSearchResult {
                file_hash: row.get(1)?,
                name: row.get(2)?,
                size_bytes: row.get::<_, i64>(3)? as u64,
                source_count: row.get::<_, i64>(4)? as u32,
                complete_source_count: row.get::<_, i64>(5)? as u32,
                file_type: row.get(6)?,
                rating: row.get::<_, i64>(7)? as u8,
                aich_hash: row.get(8)?,
                complete: row.get::<_, i64>(9)? != 0,
                directory: row.get(10)?,
                observations: Vec::new(),
            },
        ))
    })?;
    let mut results = Vec::new();
    for row in rows {
        let (result_id, mut result) = row?;
        result.observations = load_search_result_observations(conn, result_id)?;
        results.push(result);
    }
    Ok(results)
}

fn load_search_result_observations(
    conn: &rusqlite::Connection,
    result_id: i64,
) -> Result<Vec<MetadataSearchResultObservation>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT origin, name, size_bytes, source_count, complete_source_count,
               source_client_id, source_client_port, file_type, rating, aich_hash,
               complete, directory, observed_at_ms
        FROM search_result_observations
        WHERE result_id = ?1
        ORDER BY observed_at_ms, id
        "#,
    )?;
    let rows = stmt.query_map(params![result_id], |row| {
        Ok(MetadataSearchResultObservation {
            origin: row.get(0)?,
            name: row.get(1)?,
            size_bytes: row.get::<_, i64>(2)? as u64,
            source_count: row.get::<_, i64>(3)? as u32,
            complete_source_count: row.get::<_, i64>(4)? as u32,
            source_client_id: row.get::<_, Option<i64>>(5)?.map(|value| value as u32),
            source_client_port: row.get::<_, Option<i64>>(6)?.map(|value| value as u16),
            file_type: row.get(7)?,
            rating: row.get::<_, i64>(8)? as u8,
            aich_hash: row.get(9)?,
            complete: row.get::<_, i64>(10)? != 0,
            directory: row.get(11)?,
            observed_at_ms: row.get(12)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
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
        assert_eq!(searches[0].requested_method, "automatic");
        assert_eq!(searches[0].resolved_method.as_deref(), Some("global"));
        assert_eq!(searches[0].results.len(), 1);
        assert_eq!(searches[0].results[0].name, "Zażółć Sample.bin");
        assert_eq!(
            searches[0].results[0].observations[0].source_client_id,
            Some(u32::from_le_bytes([10, 20, 30, 40]))
        );
        assert_eq!(
            searches[0].results[0].observations[0].source_client_port,
            Some(4662)
        );
        assert_eq!(searches[0].results[0].rating, 4);
        assert_eq!(searches[0].results[0].aich_hash, "A".repeat(32));
        assert_eq!(searches[0].results[0].observations[0].origin, "server");
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
            requested_method: "automatic".to_string(),
            resolved_method: Some("global".to_string()),
            file_type_filter: "video".to_string(),
            status: "completed".to_string(),
            created_at_ms: 1,
            updated_at_ms: 2,
            completed_at_ms: Some(2),
            results: vec![MetadataSearchResult {
                file_hash: "00112233445566778899aabbccddeeff".to_string(),
                name: "Zażółć Sample.bin".to_string(),
                size_bytes: 123,
                source_count: 4,
                complete_source_count: 3,
                file_type: "video".to_string(),
                rating: 4,
                aich_hash: "A".repeat(32),
                complete: false,
                directory: String::new(),
                observations: vec![MetadataSearchResultObservation {
                    origin: "server".to_string(),
                    name: "Zażółć Sample.bin".to_string(),
                    size_bytes: 123,
                    source_count: 4,
                    complete_source_count: 3,
                    source_client_id: Some(u32::from_le_bytes([10, 20, 30, 40])),
                    source_client_port: Some(4662),
                    file_type: "video".to_string(),
                    rating: 4,
                    aich_hash: "A".repeat(32),
                    complete: false,
                    directory: String::new(),
                    observed_at_ms: 2,
                }],
            }],
        }
    }
}
