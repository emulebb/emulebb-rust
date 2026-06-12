use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use crate::{
    peer_model::MetadataPeerCredit,
    store::{decode_fixed_hex, unix_ms},
};

impl super::MetadataStore {
    pub fn upsert_peer_credit(&self, credit: &MetadataPeerCredit) -> Result<()> {
        let user_hash = decode_fixed_hex(&credit.user_hash, 16, "peer user hash")?;
        let now = unix_ms();
        self.connection()?.execute(
            r#"
            INSERT INTO peers(
                user_hash, uploaded_bytes, downloaded_bytes, first_seen_ms, last_seen_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?4)
            ON CONFLICT(user_hash) DO UPDATE SET
                uploaded_bytes = excluded.uploaded_bytes,
                downloaded_bytes = excluded.downloaded_bytes,
                last_seen_ms = excluded.last_seen_ms
            "#,
            params![
                user_hash,
                u64_to_i64_saturating(credit.uploaded_bytes),
                u64_to_i64_saturating(credit.downloaded_bytes),
                now,
            ],
        )?;
        Ok(())
    }

    pub fn peer_credit_by_hash(&self, user_hash: &str) -> Result<Option<MetadataPeerCredit>> {
        let user_hash_bytes = decode_fixed_hex(user_hash, 16, "peer user hash")?;
        self.connection()?
            .query_row(
                r#"
                SELECT lower(hex(user_hash)), uploaded_bytes, downloaded_bytes
                FROM peers
                WHERE user_hash = ?1
                "#,
                params![user_hash_bytes],
                |row| {
                    Ok(MetadataPeerCredit {
                        user_hash: row.get(0)?,
                        uploaded_bytes: row.get::<_, i64>(1)? as u64,
                        downloaded_bytes: row.get::<_, i64>(2)? as u64,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn add_peer_credit_delta(
        &self,
        user_hash: &str,
        uploaded_delta: u64,
        downloaded_delta: u64,
    ) -> Result<()> {
        let user_hash_bytes = decode_fixed_hex(user_hash, 16, "peer user hash")?;
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let current = tx
            .query_row(
                r#"
                SELECT uploaded_bytes, downloaded_bytes
                FROM peers
                WHERE user_hash = ?1
                "#,
                params![user_hash_bytes],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
            )
            .optional()?
            .unwrap_or((0, 0));
        let uploaded_bytes = current.0.saturating_add(uploaded_delta);
        let downloaded_bytes = current.1.saturating_add(downloaded_delta);
        tx.execute(
            r#"
            INSERT INTO peers(
                user_hash, uploaded_bytes, downloaded_bytes, first_seen_ms, last_seen_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?4)
            ON CONFLICT(user_hash) DO UPDATE SET
                uploaded_bytes = excluded.uploaded_bytes,
                downloaded_bytes = excluded.downloaded_bytes,
                last_seen_ms = excluded.last_seen_ms
            "#,
            params![
                user_hash_bytes,
                u64_to_i64_saturating(uploaded_bytes),
                u64_to_i64_saturating(downloaded_bytes),
                now,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    value.try_into().unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MetadataStore;

    #[test]
    fn peer_credit_roundtrips_by_user_hash() {
        let store = MetadataStore::in_memory().unwrap();
        let credit = MetadataPeerCredit {
            user_hash: "00112233445566778899aabbccddeeff".to_string(),
            uploaded_bytes: 1024,
            downloaded_bytes: 4096,
        };

        store.upsert_peer_credit(&credit).unwrap();

        assert_eq!(
            store
                .peer_credit_by_hash("00112233445566778899aabbccddeeff")
                .unwrap(),
            Some(credit)
        );
    }

    #[test]
    fn peer_credit_delta_accumulates_existing_totals() {
        let store = MetadataStore::in_memory().unwrap();
        let user_hash = "00112233445566778899aabbccddeeff";

        store.add_peer_credit_delta(user_hash, 1024, 2048).unwrap();
        store.add_peer_credit_delta(user_hash, 4096, 8192).unwrap();

        assert_eq!(
            store.peer_credit_by_hash(user_hash).unwrap(),
            Some(MetadataPeerCredit {
                user_hash: user_hash.to_string(),
                uploaded_bytes: 5120,
                downloaded_bytes: 10240,
            })
        );
    }
}
