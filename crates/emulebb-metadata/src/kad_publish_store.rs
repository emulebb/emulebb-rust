use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use crate::{
    kad_publish_model::{
        MetadataKadKeywordPublish, MetadataKadNotePublish, MetadataKadPublishCache,
        MetadataKadSourcePublish,
    },
    store::decode_fixed_hex,
};

impl super::MetadataStore {
    pub fn replace_kad_publish_cache(&self, cache: &MetadataKadPublishCache) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM kad_keyword_publishes", [])?;
        tx.execute("DELETE FROM kad_source_publishes", [])?;
        tx.execute("DELETE FROM kad_note_publishes", [])?;

        for publish in &cache.keyword_publishes {
            let file_hash = decode_fixed_hex(&publish.file_hash, 16, "Kad keyword file hash")?;
            let known_file_id = known_file_id_by_hash(&tx, &file_hash)?;
            tx.execute(
                r#"
                INSERT INTO kad_keyword_publishes(
                    target_node_id, file_hash, known_file_id, raw_tags, load, valid, observed_at_ms
                )
                VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)
                "#,
                params![
                    decode_fixed_hex(&publish.target_node_id, 16, "Kad keyword target node ID")?,
                    file_hash,
                    known_file_id,
                    publish.raw_tags,
                    publish.load.map(i64::from),
                    publish.observed_at_ms,
                ],
            )?;
        }

        for publish in &cache.source_publishes {
            let file_hash = decode_fixed_hex(&publish.file_hash, 16, "Kad source file hash")?;
            tx.execute(
                r#"
                INSERT INTO kad_source_publishes(
                    target_node_id, publisher_id, file_hash, source_ip, source_tcp_port,
                    source_udp_port, raw_tags, load, valid, observed_at_ms
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)
                "#,
                params![
                    decode_fixed_hex(&publish.target_node_id, 16, "Kad source target node ID")?,
                    decode_fixed_hex(&publish.publisher_id, 16, "Kad source publisher ID")?,
                    file_hash,
                    publish.source_ip,
                    i64::from(publish.source_tcp_port),
                    i64::from(publish.source_udp_port),
                    publish.raw_tags,
                    publish.load.map(i64::from),
                    publish.observed_at_ms,
                ],
            )?;
        }

        for publish in &cache.note_publishes {
            tx.execute(
                r#"
                INSERT INTO kad_note_publishes(
                    target_node_id, publisher_id, publisher_ip, file_hash, raw_tags, load, valid,
                    observed_at_ms
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)
                "#,
                params![
                    decode_fixed_hex(&publish.target_node_id, 16, "Kad note target node ID")?,
                    decode_fixed_hex(&publish.publisher_id, 16, "Kad note publisher ID")?,
                    publish.publisher_ip,
                    optional_fixed_hex(publish.file_hash.as_deref(), 16, "Kad note file hash")?,
                    publish.raw_tags,
                    publish.load.map(i64::from),
                    publish.observed_at_ms,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn load_kad_publish_cache(&self) -> Result<MetadataKadPublishCache> {
        let conn = self.connection()?;
        Ok(MetadataKadPublishCache {
            keyword_publishes: load_keyword_publishes(&conn)?,
            source_publishes: load_source_publishes(&conn)?,
            note_publishes: load_note_publishes(&conn)?,
        })
    }
}

fn known_file_id_by_hash(tx: &rusqlite::Transaction<'_>, file_hash: &[u8]) -> Result<Option<i64>> {
    tx.query_row(
        "SELECT id FROM known_files WHERE ed2k_hash = ?1",
        params![file_hash],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

fn load_keyword_publishes(conn: &rusqlite::Connection) -> Result<Vec<MetadataKadKeywordPublish>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT lower(hex(target_node_id)), lower(hex(file_hash)), raw_tags, load, observed_at_ms
        FROM kad_keyword_publishes
        WHERE valid = 1
        ORDER BY observed_at_ms, id
        "#,
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(MetadataKadKeywordPublish {
            target_node_id: row.get(0)?,
            file_hash: row.get(1)?,
            raw_tags: row.get(2)?,
            load: row.get::<_, Option<i64>>(3)?.map(|value| value as u8),
            observed_at_ms: row.get(4)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn load_source_publishes(conn: &rusqlite::Connection) -> Result<Vec<MetadataKadSourcePublish>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT lower(hex(target_node_id)), lower(hex(publisher_id)), lower(hex(file_hash)),
               source_ip, source_tcp_port, source_udp_port, raw_tags, load, observed_at_ms
        FROM kad_source_publishes
        WHERE valid = 1
        ORDER BY observed_at_ms, id
        "#,
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(MetadataKadSourcePublish {
            target_node_id: row.get(0)?,
            publisher_id: row.get(1)?,
            file_hash: row.get(2)?,
            source_ip: row.get(3)?,
            source_tcp_port: row.get::<_, i64>(4)? as u16,
            source_udp_port: row.get::<_, i64>(5)? as u16,
            raw_tags: row.get(6)?,
            load: row.get::<_, Option<i64>>(7)?.map(|value| value as u8),
            observed_at_ms: row.get(8)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn load_note_publishes(conn: &rusqlite::Connection) -> Result<Vec<MetadataKadNotePublish>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT lower(hex(target_node_id)), lower(hex(publisher_id)), publisher_ip,
               CASE WHEN file_hash IS NULL THEN NULL ELSE lower(hex(file_hash)) END,
               raw_tags, load, observed_at_ms
        FROM kad_note_publishes
        WHERE valid = 1
        ORDER BY observed_at_ms, id
        "#,
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(MetadataKadNotePublish {
            target_node_id: row.get(0)?,
            publisher_id: row.get(1)?,
            publisher_ip: row.get(2)?,
            file_hash: row.get(3)?,
            raw_tags: row.get(4)?,
            load: row.get::<_, Option<i64>>(5)?.map(|value| value as u8),
            observed_at_ms: row.get(6)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn optional_fixed_hex(
    value: Option<&str>,
    byte_len: usize,
    label: &str,
) -> Result<Option<Vec<u8>>> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(|value| decode_fixed_hex(value, byte_len, label))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MetadataStore;

    #[test]
    fn kad_publish_cache_roundtrips_all_families() {
        let store = MetadataStore::in_memory().unwrap();
        let cache = MetadataKadPublishCache {
            keyword_publishes: vec![MetadataKadKeywordPublish {
                target_node_id: "00112233445566778899aabbccddeeff".to_string(),
                file_hash: "11112222333344445555666677778888".to_string(),
                raw_tags: b"keyword-tags".to_vec(),
                load: Some(2),
                observed_at_ms: 10,
            }],
            source_publishes: vec![MetadataKadSourcePublish {
                target_node_id: "22222222333333334444444455555555".to_string(),
                publisher_id: "aaaaaaaaaaaabbbbbbbbbbbbcccccccc".to_string(),
                file_hash: "99999999888888887777777766666666".to_string(),
                source_ip: "192.0.2.44".to_string(),
                source_tcp_port: 4662,
                source_udp_port: 4672,
                raw_tags: b"source-tags".to_vec(),
                load: Some(3),
                observed_at_ms: 20,
            }],
            note_publishes: vec![MetadataKadNotePublish {
                target_node_id: "33333333444444445555555566666666".to_string(),
                publisher_id: "bbbbbbbbbbbbccccccccccccdddddddd".to_string(),
                publisher_ip: "192.0.2.45".to_string(),
                file_hash: Some("1234567890abcdef1234567890abcdef".to_string()),
                raw_tags: "Zażółć note".as_bytes().to_vec(),
                load: Some(4),
                observed_at_ms: 30,
            }],
        };

        store.replace_kad_publish_cache(&cache).unwrap();

        assert_eq!(store.load_kad_publish_cache().unwrap(), cache);
    }

    #[test]
    fn replacing_kad_publish_cache_deletes_stale_rows() {
        let store = MetadataStore::in_memory().unwrap();
        store
            .replace_kad_publish_cache(&MetadataKadPublishCache {
                keyword_publishes: vec![MetadataKadKeywordPublish {
                    target_node_id: "00112233445566778899aabbccddeeff".to_string(),
                    file_hash: "11112222333344445555666677778888".to_string(),
                    raw_tags: Vec::new(),
                    load: None,
                    observed_at_ms: 1,
                }],
                source_publishes: Vec::new(),
                note_publishes: Vec::new(),
            })
            .unwrap();
        store
            .replace_kad_publish_cache(&MetadataKadPublishCache::default())
            .unwrap();

        assert_eq!(store.table_count("kad_keyword_publishes").unwrap(), 0);
    }
}
