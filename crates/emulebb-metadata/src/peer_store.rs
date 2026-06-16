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

    /// Drop peer credit rows last seen more than 150 days ago, mirroring eMule
    /// `CClientCreditsList::LoadList` which discards entries with `tLastSeen <
    /// now - DAY2S(150)` (ClientCredits.cpp:240-251). Returns the number of rows
    /// pruned. The 150-day window is the master constant `DAY2S(150)`.
    pub fn prune_aged_peers(&self) -> Result<usize> {
        const CREDIT_AGE_LIMIT_MS: i64 = 150 * 24 * 60 * 60 * 1000;
        let cutoff = unix_ms().saturating_sub(CREDIT_AGE_LIMIT_MS);
        let pruned = self.connection()?.execute(
            "DELETE FROM peers WHERE last_seen_ms < ?1",
            params![cutoff],
        )?;
        Ok(pruned)
    }

    /// Bind a verified secure-ident public key to a peer, wiping its credits if
    /// a DIFFERENT key has been verified for the same user hash before (eMule
    /// `CClientCredits::Verified`, ClientCredits.cpp:338-356): the anti-takeover
    /// rule that a peer's accumulated credits cannot be inherited by a new key.
    ///
    /// - stored key empty: store the key, keep credits (first verify);
    /// - stored key == `public_key`: no change (the normal repeat verify);
    /// - stored key != `public_key`: reset uploaded/downloaded to the neutral
    ///   1-byte sentinel (matching eMule, which sets them to 1 so the row still
    ///   persists) and store the new key.
    ///
    /// Returns `true` when the key changed and credits were wiped.
    pub fn record_verified_secure_ident(
        &self,
        user_hash: &str,
        public_key: &[u8],
    ) -> Result<bool> {
        let user_hash_bytes = decode_fixed_hex(user_hash, 16, "peer user hash")?;
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                r#"
                SELECT secure_ident_pubkey
                FROM peers
                WHERE user_hash = ?1
                "#,
                params![user_hash_bytes],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten()
            .filter(|key| !key.is_empty());

        let key_len = i64::try_from(public_key.len()).unwrap_or(i64::MAX);
        let wiped = match existing {
            Some(stored) if stored == public_key => false,
            Some(_) => {
                // A different key verified for this user hash: wipe credits.
                tx.execute(
                    r#"
                    UPDATE peers
                    SET secure_ident_pubkey = ?2,
                        secure_ident_pubkey_len = ?3,
                        uploaded_bytes = 1,
                        downloaded_bytes = 1,
                        last_seen_ms = ?4
                    WHERE user_hash = ?1
                    "#,
                    params![user_hash_bytes, public_key, key_len, now],
                )?;
                true
            }
            None => {
                // First verify (or no prior key): bind the key, keep credits.
                tx.execute(
                    r#"
                    INSERT INTO peers(
                        user_hash, secure_ident_pubkey, secure_ident_pubkey_len,
                        first_seen_ms, last_seen_ms
                    )
                    VALUES (?1, ?2, ?3, ?4, ?4)
                    ON CONFLICT(user_hash) DO UPDATE SET
                        secure_ident_pubkey = excluded.secure_ident_pubkey,
                        secure_ident_pubkey_len = excluded.secure_ident_pubkey_len,
                        last_seen_ms = excluded.last_seen_ms
                    "#,
                    params![user_hash_bytes, public_key, key_len, now],
                )?;
                false
            }
        };
        tx.commit()?;
        Ok(wiped)
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
    fn first_verified_key_is_stored_and_credits_kept() {
        let store = MetadataStore::in_memory().unwrap();
        let user_hash = "00112233445566778899aabbccddeeff";
        store.add_peer_credit_delta(user_hash, 1000, 2000).unwrap();

        let wiped = store
            .record_verified_secure_ident(user_hash, &[9u8; 80])
            .unwrap();
        assert!(!wiped, "first key must not wipe credits");
        assert_eq!(
            store.peer_credit_by_hash(user_hash).unwrap(),
            Some(MetadataPeerCredit {
                user_hash: user_hash.to_string(),
                uploaded_bytes: 1000,
                downloaded_bytes: 2000,
            })
        );
    }

    #[test]
    fn same_verified_key_keeps_credits() {
        let store = MetadataStore::in_memory().unwrap();
        let user_hash = "00112233445566778899aabbccddeeff";
        store.add_peer_credit_delta(user_hash, 1000, 2000).unwrap();
        store
            .record_verified_secure_ident(user_hash, &[9u8; 80])
            .unwrap();

        let wiped = store
            .record_verified_secure_ident(user_hash, &[9u8; 80])
            .unwrap();
        assert!(!wiped, "the same key must not wipe credits");
        let credit = store.peer_credit_by_hash(user_hash).unwrap().unwrap();
        assert_eq!(credit.uploaded_bytes, 1000);
        assert_eq!(credit.downloaded_bytes, 2000);
    }

    #[test]
    fn different_verified_key_wipes_credits() {
        // eMule CClientCredits::Verified anti-takeover: a different key verifying
        // for the same user hash wipes the prior credits.
        let store = MetadataStore::in_memory().unwrap();
        let user_hash = "00112233445566778899aabbccddeeff";
        store.add_peer_credit_delta(user_hash, 5000, 9000).unwrap();
        store
            .record_verified_secure_ident(user_hash, &[1u8; 80])
            .unwrap();

        let wiped = store
            .record_verified_secure_ident(user_hash, &[2u8; 80])
            .unwrap();
        assert!(wiped, "a different key must wipe credits");
        let credit = store.peer_credit_by_hash(user_hash).unwrap().unwrap();
        // Master resets to the 1-byte sentinel rather than deleting the row.
        assert_eq!(credit.uploaded_bytes, 1);
        assert_eq!(credit.downloaded_bytes, 1);
    }

    #[test]
    fn prune_aged_peers_drops_only_stale_rows() {
        let store = MetadataStore::in_memory().unwrap();
        let fresh = "00112233445566778899aabbccddeeff";
        let stale = "ffeeddccbbaa99887766554433221100";
        store.add_peer_credit_delta(fresh, 1, 1).unwrap();
        store.add_peer_credit_delta(stale, 1, 1).unwrap();
        // Backdate the stale peer to 200 days ago (> the 150-day window).
        let two_hundred_days_ms: i64 = 200 * 24 * 60 * 60 * 1000;
        let cutoff = crate::store::unix_ms() - two_hundred_days_ms;
        let stale_bytes = crate::store::decode_fixed_hex(stale, 16, "peer user hash").unwrap();
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE peers SET last_seen_ms = ?1 WHERE user_hash = ?2",
                params![cutoff, stale_bytes],
            )
            .unwrap();

        let pruned = store.prune_aged_peers().unwrap();
        assert_eq!(pruned, 1);
        assert!(store.peer_credit_by_hash(fresh).unwrap().is_some());
        assert!(store.peer_credit_by_hash(stale).unwrap().is_none());
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
