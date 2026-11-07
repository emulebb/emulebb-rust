use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use crate::{
    search_model::{
        MetadataSearch, MetadataSearchResult, MetadataSearchResultObservation, MetadataSearchSpec,
    },
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
                file_type_filter, extension_filter, min_size_bytes, max_size_bytes,
                min_availability, min_complete_sources, min_bitrate_kbps,
                min_length_seconds, codec_filter, title_filter, album_filter,
                artist_filter, status, status_reason, created_at_ms, updated_at_ms,
                completed_at_ms
            )
            VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22
            )
            ON CONFLICT(public_id) DO UPDATE SET
                query = excluded.query,
                normalized_query = excluded.normalized_query,
                requested_method = excluded.requested_method,
                resolved_method = excluded.resolved_method,
                file_type_filter = excluded.file_type_filter,
                extension_filter = excluded.extension_filter,
                min_size_bytes = excluded.min_size_bytes,
                max_size_bytes = excluded.max_size_bytes,
                min_availability = excluded.min_availability,
                min_complete_sources = excluded.min_complete_sources,
                min_bitrate_kbps = excluded.min_bitrate_kbps,
                min_length_seconds = excluded.min_length_seconds,
                codec_filter = excluded.codec_filter,
                title_filter = excluded.title_filter,
                album_filter = excluded.album_filter,
                artist_filter = excluded.artist_filter,
                status = excluded.status,
                status_reason = excluded.status_reason,
                updated_at_ms = excluded.updated_at_ms,
                completed_at_ms = excluded.completed_at_ms
            "#,
            params![
                search.public_id,
                search.spec.query,
                search.normalized_query,
                search.spec.method,
                search.resolved_method,
                search.spec.file_type,
                search.spec.extension,
                encode_optional_u64(search.spec.min_size_bytes),
                encode_optional_u64(search.spec.max_size_bytes),
                search.spec.min_availability.map(i64::from),
                search.spec.min_complete_sources.map(i64::from),
                search.spec.min_bitrate_kbps.map(i64::from),
                search.spec.min_length_seconds.map(i64::from),
                search.spec.codec,
                search.spec.title,
                search.spec.album,
                search.spec.artist,
                search.status,
                search.status_reason,
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
        tx.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS incoming_search_result_ids(id INTEGER PRIMARY KEY);
            DELETE FROM temp.incoming_search_result_ids;",
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
                    session_id, known_file_id, ed2k_hash, name, size_bytes,
                    source_count, complete_source_count, file_type, media_artist,
                    media_album, media_title, media_length_seconds, media_bitrate_kbps,
                    media_codec, rating, aich_root, complete, directory
                )
                VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                    ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18
                )
                ON CONFLICT(session_id, ed2k_hash) DO UPDATE SET
                    known_file_id = excluded.known_file_id,
                    name = excluded.name,
                    size_bytes = excluded.size_bytes,
                    source_count = excluded.source_count,
                    complete_source_count = excluded.complete_source_count,
                    file_type = excluded.file_type,
                    media_artist = excluded.media_artist,
                    media_album = excluded.media_album,
                    media_title = excluded.media_title,
                    media_length_seconds = excluded.media_length_seconds,
                    media_bitrate_kbps = excluded.media_bitrate_kbps,
                    media_codec = excluded.media_codec,
                    rating = excluded.rating,
                    aich_root = excluded.aich_root,
                    complete = excluded.complete,
                    directory = excluded.directory
                WHERE search_results.known_file_id IS NOT excluded.known_file_id OR
                    search_results.name IS NOT excluded.name OR
                    search_results.size_bytes IS NOT excluded.size_bytes OR
                    search_results.source_count IS NOT excluded.source_count OR
                    search_results.complete_source_count IS NOT excluded.complete_source_count OR
                    search_results.file_type IS NOT excluded.file_type OR
                    search_results.media_artist IS NOT excluded.media_artist OR
                    search_results.media_album IS NOT excluded.media_album OR
                    search_results.media_title IS NOT excluded.media_title OR
                    search_results.media_length_seconds IS NOT excluded.media_length_seconds OR
                    search_results.media_bitrate_kbps IS NOT excluded.media_bitrate_kbps OR
                    search_results.media_codec IS NOT excluded.media_codec OR
                    search_results.rating IS NOT excluded.rating OR
                    search_results.aich_root IS NOT excluded.aich_root OR
                    search_results.complete IS NOT excluded.complete OR
                    search_results.directory IS NOT excluded.directory
                "#,
                params![
                    session_id,
                    known_file_id,
                    file_hash,
                    result.name,
                    i64::try_from(result.size_bytes)?,
                    i64::from(result.source_count),
                    i64::from(result.complete_source_count),
                    result.file_type,
                    result.media_artist,
                    result.media_album,
                    result.media_title,
                    i64::from(result.media_length_seconds),
                    i64::from(result.media_bitrate_kbps),
                    result.media_codec,
                    i64::from(result.rating),
                    encode_aich_root(&result.aich_hash)?,
                    bool_to_i64(result.complete),
                    result.directory,
                ],
            )?;
            let result_id: i64 = tx.query_row(
                "SELECT id FROM search_results WHERE session_id = ?1 AND ed2k_hash = ?2",
                params![session_id, file_hash],
                |row| row.get(0),
            )?;
            tx.execute(
                "INSERT INTO temp.incoming_search_result_ids VALUES(?1)",
                [result_id],
            )?;
            let observations = result
                .observations
                .iter()
                .cloned()
                .map(|mut observation| {
                    if observation.observed_at_ms <= 0 {
                        observation.observed_at_ms = now;
                    }
                    observation
                })
                .collect::<Vec<_>>();
            let stored = load_search_result_observations(&tx, result_id)?;
            let retained = if observations.starts_with(&stored) {
                stored.len()
            } else {
                tx.execute(
                    "DELETE FROM search_result_observations WHERE result_id = ?1",
                    [result_id],
                )?;
                0
            };
            for observation in observations.iter().skip(retained) {
                tx.execute(
                    r#"
                    INSERT INTO search_result_observations(
                        result_id, origin, server_endpoint, name, size_bytes, source_count,
                        complete_source_count, source_client_id, source_client_port,
                        file_type, media_artist, media_album, media_title,
                        media_length_seconds, media_bitrate_kbps, media_codec,
                        rating, aich_root, complete, directory, observed_at_ms
                    )
                    VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                        ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
                    )
                    "#,
                    params![
                        result_id,
                        observation.origin,
                        observation.server_endpoint,
                        observation.name,
                        i64::try_from(observation.size_bytes)?,
                        i64::from(observation.source_count),
                        i64::from(observation.complete_source_count),
                        observation.source_client_id.map(i64::from),
                        observation.source_client_port.map(i64::from),
                        observation.file_type,
                        observation.media_artist,
                        observation.media_album,
                        observation.media_title,
                        i64::from(observation.media_length_seconds),
                        i64::from(observation.media_bitrate_kbps),
                        observation.media_codec,
                        i64::from(observation.rating),
                        encode_aich_root(&observation.aich_hash)?,
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
        tx.execute(
            "DELETE FROM search_results WHERE session_id = ?1
            AND id NOT IN (SELECT id FROM temp.incoming_search_result_ids)",
            [session_id],
        )?;
        tx.execute("DELETE FROM temp.incoming_search_result_ids", [])?;
        tx.commit()?;
        Ok(())
    }

    pub fn load_searches(&self) -> Result<Vec<MetadataSearch>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, public_id, query, normalized_query, requested_method,
                   resolved_method, file_type_filter, extension_filter,
                   min_size_bytes, max_size_bytes, min_availability,
                   min_complete_sources, min_bitrate_kbps, min_length_seconds,
                   codec_filter, title_filter, album_filter, artist_filter,
                   status, status_reason, created_at_ms, updated_at_ms,
                   completed_at_ms
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
                        normalized_query: row.get(3)?,
                        spec: MetadataSearchSpec {
                            query: row.get(2)?,
                            method: row.get(4)?,
                            file_type: row.get(6)?,
                            extension: row.get(7)?,
                            min_size_bytes: decode_optional_u64(row.get(8)?, 8)?,
                            max_size_bytes: decode_optional_u64(row.get(9)?, 9)?,
                            min_availability: decode_optional_u32(row.get(10)?, 10)?,
                            min_complete_sources: decode_optional_u32(row.get(11)?, 11)?,
                            min_bitrate_kbps: decode_optional_u32(row.get(12)?, 12)?,
                            min_length_seconds: decode_optional_u32(row.get(13)?, 13)?,
                            codec: row.get(14)?,
                            title: row.get(15)?,
                            album: row.get(16)?,
                            artist: row.get(17)?,
                        },
                        resolved_method: row.get(5)?,
                        status: row.get(18)?,
                        status_reason: row.get(19)?,
                        created_at_ms: row.get(20)?,
                        updated_at_ms: row.get(21)?,
                        completed_at_ms: row.get(22)?,
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
        SELECT id, lower(hex(ed2k_hash)),
               name, size_bytes, source_count, complete_source_count, file_type,
               media_artist, media_album, media_title, media_length_seconds,
               media_bitrate_kbps, media_codec, rating, aich_root, complete, directory
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
                size_bytes: crate::sql_value::unsigned::<u64>(row, 3)?,
                source_count: row.get::<_, u32>(4)?,
                complete_source_count: row.get::<_, u32>(5)?,
                file_type: row.get(6)?,
                media_artist: row.get(7)?,
                media_album: row.get(8)?,
                media_title: row.get(9)?,
                media_length_seconds: row.get::<_, u32>(10)?,
                media_bitrate_kbps: row.get::<_, u32>(11)?,
                media_codec: row.get(12)?,
                rating: row.get::<_, u8>(13)?,
                aich_hash: data_encoding::BASE32_NOPAD
                    .encode(&row.get::<_, Option<Vec<u8>>>(14)?.unwrap_or_default()),
                complete: row.get::<_, i64>(15)? != 0,
                directory: row.get(16)?,
                observations: Vec::new(),
            },
        ))
    })?;
    let mut results = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    let positions = results
        .iter()
        .enumerate()
        .map(|(position, (id, _))| (*id, position))
        .collect::<std::collections::HashMap<_, _>>();
    let mut observations = conn.prepare(
        "SELECT o.origin, o.server_endpoint, o.name, o.size_bytes, o.source_count, o.complete_source_count,
                o.source_client_id, o.source_client_port, o.file_type, o.media_artist,
                o.media_album, o.media_title, o.media_length_seconds, o.media_bitrate_kbps,
                o.media_codec, o.rating, o.aich_root, o.complete, o.directory, o.observed_at_ms, o.result_id
         FROM search_results r JOIN search_result_observations o ON o.result_id = r.id
         WHERE r.session_id = ?1 ORDER BY o.result_id, o.observed_at_ms, o.id")?;
    let mut rows = observations.query([session_id])?;
    while let Some(row) = rows.next()? {
        let result_id: i64 = row.get(20)?;
        let position = positions[&result_id];
        results[position]
            .1
            .observations
            .push(search_observation_from_row(row)?);
    }
    let results = results.into_iter().map(|(_, result)| result).collect();
    Ok(results)
}

fn load_search_result_observations(
    conn: &rusqlite::Connection,
    result_id: i64,
) -> Result<Vec<MetadataSearchResultObservation>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT origin, server_endpoint, name, size_bytes, source_count, complete_source_count,
               source_client_id, source_client_port, file_type, media_artist,
               media_album, media_title, media_length_seconds,
               media_bitrate_kbps, media_codec, rating, aich_root, complete,
               directory, observed_at_ms
        FROM search_result_observations
        WHERE result_id = ?1
        ORDER BY observed_at_ms, id
        "#,
    )?;
    let rows = stmt.query_map(params![result_id], search_observation_from_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn search_observation_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<MetadataSearchResultObservation> {
    Ok(MetadataSearchResultObservation {
        origin: row.get(0)?,
        server_endpoint: row.get(1)?,
        name: row.get(2)?,
        size_bytes: crate::sql_value::unsigned::<u64>(row, 3)?,
        source_count: row.get::<_, u32>(4)?,
        complete_source_count: row.get::<_, u32>(5)?,
        source_client_id: row.get::<_, Option<u32>>(6)?,
        source_client_port: row.get::<_, Option<u16>>(7)?,
        file_type: row.get(8)?,
        media_artist: row.get(9)?,
        media_album: row.get(10)?,
        media_title: row.get(11)?,
        media_length_seconds: row.get::<_, u32>(12)?,
        media_bitrate_kbps: row.get::<_, u32>(13)?,
        media_codec: row.get(14)?,
        rating: row.get::<_, u8>(15)?,
        aich_hash: data_encoding::BASE32_NOPAD
            .encode(&row.get::<_, Option<Vec<u8>>>(16)?.unwrap_or_default()),
        complete: row.get::<_, i64>(17)? != 0,
        directory: row.get(18)?,
        observed_at_ms: row.get(19)?,
    })
}

fn encode_aich_root(value: &str) -> Result<Option<Vec<u8>>> {
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = data_encoding::BASE32_NOPAD.decode(value.as_bytes())?;
    anyhow::ensure!(bytes.len() == 20, "AICH root must contain 20 bytes");
    Ok(Some(bytes))
}

fn encode_optional_u64(value: Option<u64>) -> Option<Vec<u8>> {
    value.map(|value| value.to_be_bytes().to_vec())
}

fn decode_optional_u64(value: Option<Vec<u8>>, column: usize) -> rusqlite::Result<Option<u64>> {
    value
        .map(|value| {
            let bytes: [u8; 8] = value.try_into().map_err(|value: Vec<u8>| {
                rusqlite::Error::FromSqlConversionFailure(
                    column,
                    rusqlite::types::Type::Blob,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "expected 8-byte unsigned integer, got {} bytes",
                            value.len()
                        ),
                    )
                    .into(),
                )
            })?;
            Ok(u64::from_be_bytes(bytes))
        })
        .transpose()
}

fn decode_optional_u32(value: Option<i64>, column: usize) -> rusqlite::Result<Option<u32>> {
    value
        .map(|value| {
            u32::try_from(value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    column,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

pub fn normalized_search_query(query: &str) -> String {
    normalize_search_text(query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_storage_has_binary_roots_and_ordered_unsigned_filter_bounds() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        let mut search = sample_search("typed-search");
        search.spec.min_size_bytes = Some(255);
        search.spec.max_size_bytes = Some(256);
        store.upsert_search(&search).unwrap();
        let conn = store.connection().unwrap();
        let (size, valid): (i64, bool) = conn.query_row(
            "SELECT (SELECT length(aich_root) FROM search_results), min_size_bytes < max_size_bytes FROM search_sessions",
            [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        assert_eq!(size, 20);
        assert!(valid);
        drop(conn);
        search.spec.min_size_bytes = Some(257);
        assert!(store.upsert_search(&search).is_err());
        search.spec.min_size_bytes = Some(255);
        search.results[0].aich_hash = "invalid-root".into();
        assert!(store.upsert_search(&search).is_err());
        assert_eq!(
            store.load_searches().unwrap()[0].spec.min_size_bytes,
            Some(255)
        );
    }

    #[test]
    fn search_snapshots_preserve_result_and_observation_identity() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        let mut search = sample_search("incremental");
        store.upsert_search(&search).unwrap();
        let ids = || {
            store.connection().unwrap().query_row(
            "SELECT r.id, o.id FROM search_results r JOIN search_result_observations o ON o.result_id=r.id",
            [], |r| Ok((r.get::<_,i64>(0)?, r.get::<_,i64>(1)?)),
        ).unwrap()
        };
        let original = ids();
        store.connection().unwrap().execute_batch(
            "CREATE TEMP TRIGGER reject_result_delete BEFORE DELETE ON main.search_results BEGIN SELECT RAISE(ABORT,'result identity lost'); END;
             CREATE TEMP TRIGGER reject_observation_delete BEFORE DELETE ON main.search_result_observations BEGIN SELECT RAISE(ABORT,'observation identity lost'); END;"
        ).unwrap();
        store.upsert_search(&search).unwrap();
        search.results[0].source_count += 1;
        let mut next = search.results[0].observations[0].clone();
        next.observed_at_ms += 1;
        search.results[0].observations.push(next);
        store.upsert_search(&search).unwrap();
        assert_eq!(ids(), original);
        assert_eq!(store.table_count("search_result_observations").unwrap(), 2);
        store
            .connection()
            .unwrap()
            .execute_batch(
                "DROP TRIGGER reject_result_delete; DROP TRIGGER reject_observation_delete;",
            )
            .unwrap();
        search.results.clear();
        store.upsert_search(&search).unwrap();
        assert_eq!(store.table_count("search_results").unwrap(), 0);
        assert_eq!(store.table_count("search_result_observations").unwrap(), 0);
    }

    #[test]
    fn search_state_roundtrips_unicode_results() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        let search = sample_search("search-one");

        store.upsert_search(&search).unwrap();

        let searches = store.load_searches().unwrap();
        assert_eq!(searches.len(), 1);
        assert_eq!(searches[0].public_id, "search-one");
        assert_eq!(searches[0].spec.method, "automatic");
        assert_eq!(searches[0].resolved_method.as_deref(), Some("global"));
        assert_eq!(searches[0].spec.min_size_bytes, Some(u64::MAX - 1));
        assert_eq!(searches[0].spec.max_size_bytes, Some(u64::MAX));
        assert_eq!(searches[0].spec.min_availability, Some(17));
        assert_eq!(searches[0].spec.artist, "Example Artist");
        assert_eq!(
            searches[0].status_reason.as_deref(),
            Some("synthetic-status-reason")
        );
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
        assert_eq!(searches[0].results[0].media_artist, "Example Artist");
        assert_eq!(searches[0].results[0].media_length_seconds, 321);
        assert_eq!(searches[0].results[0].media_bitrate_kbps, 192);
        assert_eq!(searches[0].results[0].media_codec, "AV1");
        assert_eq!(searches[0].results[0].observations[0].origin, "server");
        assert_eq!(
            searches[0].results[0].observations[0]
                .server_endpoint
                .as_deref(),
            Some("192.0.2.10:4661")
        );
        assert_eq!(
            searches[0].results[0].observations[0].media_album,
            "Example Album"
        );
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
            normalized_query: normalized_search_query("zażółć"),
            spec: MetadataSearchSpec {
                query: "zażółć".to_string(),
                method: "automatic".to_string(),
                file_type: "video".to_string(),
                extension: "mkv".to_string(),
                min_size_bytes: Some(u64::MAX - 1),
                max_size_bytes: Some(u64::MAX),
                min_availability: Some(17),
                min_complete_sources: Some(5),
                min_bitrate_kbps: Some(320),
                min_length_seconds: Some(90),
                codec: "av1".to_string(),
                title: "Example Title".to_string(),
                album: "Example Album".to_string(),
                artist: "Example Artist".to_string(),
            },
            resolved_method: Some("global".to_string()),
            status: "error".to_string(),
            status_reason: Some("synthetic-status-reason".to_string()),
            created_at_ms: 1,
            updated_at_ms: 2,
            completed_at_ms: None,
            results: vec![MetadataSearchResult {
                file_hash: "00112233445566778899aabbccddeeff".to_string(),
                name: "Zażółć Sample.bin".to_string(),
                size_bytes: 123,
                source_count: 4,
                complete_source_count: 3,
                file_type: "video".to_string(),
                media_artist: "Example Artist".to_string(),
                media_album: "Example Album".to_string(),
                media_title: "Example Title".to_string(),
                media_length_seconds: 321,
                media_bitrate_kbps: 192,
                media_codec: "AV1".to_string(),
                rating: 4,
                aich_hash: "A".repeat(32),
                complete: false,
                directory: String::new(),
                observations: vec![MetadataSearchResultObservation {
                    origin: "server".to_string(),
                    server_endpoint: Some("192.0.2.10:4661".to_string()),
                    name: "Zażółć Sample.bin".to_string(),
                    size_bytes: 123,
                    source_count: 4,
                    complete_source_count: 3,
                    source_client_id: Some(u32::from_le_bytes([10, 20, 30, 40])),
                    source_client_port: Some(4662),
                    file_type: "video".to_string(),
                    media_artist: "Example Artist".to_string(),
                    media_album: "Example Album".to_string(),
                    media_title: "Example Title".to_string(),
                    media_length_seconds: 321,
                    media_bitrate_kbps: 192,
                    media_codec: "AV1".to_string(),
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
