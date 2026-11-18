use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};

use crate::{
    peer_model::MetadataPeerCredit,
    store::{decode_fixed_hex, unix_ms},
};

/// Committed upload facts for one known hash; optional times use Unix seconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetadataFileUploadTotals {
    pub uploaded_bytes: u64,
    pub upload_requests: u64,
    pub accepted_sessions: u64,
    pub last_requested_at_s: Option<i64>,
    pub last_uploaded_at_s: Option<i64>,
}

/// Demand facts distinguish client content from passive/index observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataFileUploadSnapshot {
    pub totals: MetadataFileUploadTotals,
    pub known_client: bool,
}

/// Retained file accounting deltas committed with the existing credit batch.
#[derive(Debug, Clone, Default)]
pub struct MetadataFileUploadDelta {
    pub file_hash: String,
    pub uploaded_bytes: u64,
    pub accepted_sessions: u64,
    pub upload_requests: u64,
    pub last_requested_at_s: Option<i64>,
    pub last_uploaded_at_s: Option<i64>,
}

impl super::MetadataStore {
    pub fn upsert_peer_credit(&self, credit: &MetadataPeerCredit) -> Result<()> {
        let user_hash = decode_fixed_hex(&credit.user_hash, 16, "peer user hash")?;
        let now = unix_ms();
        self.connection()?.execute(
            r#"
            INSERT INTO peers(
                user_hash, uploaded_bytes, downloaded_bytes, first_seen_at_ms, last_seen_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?4)
            ON CONFLICT(user_hash) DO UPDATE SET
                uploaded_bytes = excluded.uploaded_bytes,
                downloaded_bytes = excluded.downloaded_bytes,
                last_seen_at_ms = excluded.last_seen_at_ms
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
            .prepare_cached(
                r#"
                SELECT lower(hex(user_hash)), uploaded_bytes, downloaded_bytes
                FROM peers
                WHERE user_hash = ?1
                "#,
            )?
            .query_row(params![user_hash_bytes], |row| {
                Ok(MetadataPeerCredit {
                    user_hash: row.get(0)?,
                    uploaded_bytes: crate::sql_value::unsigned::<u64>(row, 1)?,
                    downloaded_bytes: crate::sql_value::unsigned::<u64>(row, 2)?,
                })
            })
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
            .prepare_cached(
                r#"
                SELECT uploaded_bytes, downloaded_bytes
                FROM peers
                WHERE user_hash = ?1
                "#,
            )?
            .query_row(params![user_hash_bytes], |row| {
                Ok((
                    crate::sql_value::unsigned::<u64>(row, 0)?,
                    crate::sql_value::unsigned::<u64>(row, 1)?,
                ))
            })
            .optional()?
            .unwrap_or((0, 0));
        let uploaded_bytes = current.0.saturating_add(uploaded_delta);
        let downloaded_bytes = current.1.saturating_add(downloaded_delta);
        tx.prepare_cached(
            r#"
            INSERT INTO peers(
                user_hash, uploaded_bytes, downloaded_bytes, first_seen_at_ms, last_seen_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?4)
            ON CONFLICT(user_hash) DO UPDATE SET
                uploaded_bytes = excluded.uploaded_bytes,
                downloaded_bytes = excluded.downloaded_bytes,
                last_seen_at_ms = excluded.last_seen_at_ms
            "#,
        )?
        .execute(params![
            user_hash_bytes,
            u64_to_i64_saturating(uploaded_bytes),
            u64_to_i64_saturating(downloaded_bytes),
            now,
        ])?;
        tx.commit()?;
        Ok(())
    }

    /// Apply a batch of parked peer-credit and file upload-accounting deltas
    /// in ONE transaction (one WAL fsync), the flush half of the in-memory
    /// credit parking that replaced the per-fragment/per-block commits.
    pub fn apply_credit_deltas(
        &self,
        peer_deltas: &[(String, u64, u64)],
        file_deltas: &[MetadataFileUploadDelta],
    ) -> Result<()> {
        if peer_deltas.is_empty() && file_deltas.is_empty() {
            return Ok(());
        }
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        for (user_hash, uploaded_delta, downloaded_delta) in peer_deltas {
            let user_hash_bytes = decode_fixed_hex(user_hash, 16, "peer user hash")?;
            let current = tx
                .prepare_cached(
                    r#"
                    SELECT uploaded_bytes, downloaded_bytes
                    FROM peers
                    WHERE user_hash = ?1
                    "#,
                )?
                .query_row(params![user_hash_bytes], |row| {
                    Ok((
                        crate::sql_value::unsigned::<u64>(row, 0)?,
                        crate::sql_value::unsigned::<u64>(row, 1)?,
                    ))
                })
                .optional()?
                .unwrap_or((0, 0));
            tx.prepare_cached(
                r#"
                INSERT INTO peers(
                    user_hash, uploaded_bytes, downloaded_bytes, first_seen_at_ms, last_seen_at_ms
                )
                VALUES (?1, ?2, ?3, ?4, ?4)
                ON CONFLICT(user_hash) DO UPDATE SET
                    uploaded_bytes = excluded.uploaded_bytes,
                    downloaded_bytes = excluded.downloaded_bytes,
                    last_seen_at_ms = excluded.last_seen_at_ms
                "#,
            )?
            .execute(params![
                user_hash_bytes,
                u64_to_i64_saturating(current.0.saturating_add(*uploaded_delta)),
                u64_to_i64_saturating(current.1.saturating_add(*downloaded_delta)),
                now,
            ])?;
        }
        for delta in file_deltas {
            ensure!(
                delta
                    .last_requested_at_s
                    .is_none_or(|at| at >= 0 && delta.upload_requests > 0),
                "invalid upload-request timestamp"
            );
            ensure!(
                delta
                    .last_uploaded_at_s
                    .is_none_or(|at| at >= 0 && delta.uploaded_bytes > 0),
                "invalid actual-upload timestamp"
            );
            let hash = decode_fixed_hex(&delta.file_hash, 16, "ED2K hash")?;
            tx.prepare_cached(
                r#"
                UPDATE known_files
                SET all_time_uploaded_bytes = all_time_uploaded_bytes + min(?2, 9223372036854775807 - all_time_uploaded_bytes),
                    all_time_upload_accepts = all_time_upload_accepts + min(?3, 9223372036854775807 - all_time_upload_accepts),
                    last_uploaded_at_s = CASE WHEN ?4 IS NULL THEN last_uploaded_at_s ELSE max(coalesce(last_uploaded_at_s,?4),?4) END,
                    all_time_upload_requests = all_time_upload_requests + min(?5, 9223372036854775807 - all_time_upload_requests),
                    last_upload_requested_at_s = CASE WHEN ?6 IS NULL THEN last_upload_requested_at_s ELSE max(coalesce(last_upload_requested_at_s,?6),?6) END
                WHERE ed2k_hash = ?1
                "#,
            )?
            .execute(params![hash, u64_to_i64_saturating(delta.uploaded_bytes), u64_to_i64_saturating(delta.accepted_sessions), delta.last_uploaded_at_s, u64_to_i64_saturating(delta.upload_requests), delta.last_requested_at_s])?;
        }
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
            "DELETE FROM peers WHERE last_seen_at_ms < ?1",
            params![cutoff],
        )?;
        Ok(pruned)
    }

    /// Return the pinned secure-ident public key for a peer, if one has been
    /// established by a successful verification.
    pub fn peer_secure_ident_public_key(&self, user_hash: &str) -> Result<Option<Vec<u8>>> {
        let user_hash_bytes = decode_fixed_hex(user_hash, 16, "peer user hash")?;
        self.connection()?
            .prepare_cached(
                r#"
                SELECT secure_ident_pubkey
                FROM peers
                WHERE user_hash = ?1
                "#,
            )?
            .query_row(params![user_hash_bytes], |row| row.get(0))
            .optional()
            .map(|key| key.flatten().filter(|key: &Vec<u8>| !key.is_empty()))
            .map_err(Into::into)
    }

    /// Pin a verified secure-ident public key to a peer, wiping unsecured
    /// accumulated credit on the first bind per eMule
    /// `CClientCredits::Verified` (ClientCredits.cpp:338-356).
    ///
    /// - no key bound yet (`nKeySize == 0`, first verify): bind the key, and if
    ///   the slot already holds accumulated credit (`GetDownloadedTotal() > 0`,
    ///   ClientCredits.cpp:345) reset uploaded/downloaded to the neutral 1-byte
    ///   sentinel (ClientCredits.cpp:347-350) so an attacker cannot spoof a
    ///   userhash that accrued credit via an unsecured peer and then claim it by
    ///   verifying with their own key. A fresh slot (no prior credit) keeps its
    ///   zero totals â€” there is nothing to wipe;
    /// - stored key == `public_key`: no change (the normal repeat verify);
    /// - stored key != `public_key`: retain the first verified key and all
    ///   credit totals. The caller must reject the mismatched identity.
    ///
    /// Returns `(first_bind, credit_wiped, pinned_key)`. The effective pinned
    /// key is returned so the ED2K runtime can classify a concurrent first-bind
    /// race without repeating a non-atomic read.
    pub fn pin_verified_secure_ident(
        &self,
        user_hash: &str,
        public_key: &[u8],
    ) -> Result<(bool, bool, Vec<u8>)> {
        let user_hash_bytes = decode_fixed_hex(user_hash, 16, "peer user hash")?;
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let existing: Option<(Option<Vec<u8>>, i64)> = tx
            .query_row(
                r#"
                SELECT secure_ident_pubkey, downloaded_bytes
                FROM peers
                WHERE user_hash = ?1
                "#,
                params![user_hash_bytes],
                |row| Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;

        let prior_downloaded = existing.as_ref().map(|(_, dl)| *dl).unwrap_or(0);
        let bound_key = existing
            .and_then(|(key, _)| key)
            .filter(|key| !key.is_empty());

        let key_len = i64::try_from(public_key.len()).unwrap_or(i64::MAX);
        let outcome = match bound_key {
            Some(stored) => (false, false, stored),
            None if prior_downloaded > 0 => {
                // First key bound to a slot that already accrued credit while
                // unsecured: wipe it (eMule Verified, ClientCredits.cpp:345-350).
                tx.execute(
                    r#"
                    UPDATE peers
                    SET secure_ident_pubkey = ?2,
                        secure_ident_pubkey_len = ?3,
                        uploaded_bytes = 1,
                        downloaded_bytes = 1,
                        last_seen_at_ms = ?4
                    WHERE user_hash = ?1
                    "#,
                    params![user_hash_bytes, public_key, key_len, now],
                )?;
                (true, true, public_key.to_vec())
            }
            None => {
                // First verify on a fresh slot: bind the key, keep the (zero)
                // credits â€” there is nothing accumulated to wipe.
                tx.execute(
                    r#"
                    INSERT INTO peers(
                        user_hash, secure_ident_pubkey, secure_ident_pubkey_len,
                        first_seen_at_ms, last_seen_at_ms
                    )
                    VALUES (?1, ?2, ?3, ?4, ?4)
                    ON CONFLICT(user_hash) DO UPDATE SET
                        secure_ident_pubkey = excluded.secure_ident_pubkey,
                        secure_ident_pubkey_len = excluded.secure_ident_pubkey_len,
                        last_seen_at_ms = excluded.last_seen_at_ms
                    "#,
                    params![user_hash_bytes, public_key, key_len, now],
                )?;
                (true, false, public_key.to_vec())
            }
        };
        tx.commit()?;
        Ok(outcome)
    }

    /// Compatibility helper for runtime code that only needs to know whether
    /// the first verified bind wiped unsecured accumulated credit.
    pub fn record_verified_secure_ident(&self, user_hash: &str, public_key: &[u8]) -> Result<bool> {
        self.pin_verified_secure_ident(user_hash, public_key)
            .map(|(_, credit_wiped, _)| credit_wiped)
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
    fn first_verified_key_wipes_prior_unsecured_credit() {
        // eMule CClientCredits::Verified anti-theft (ClientCredits.cpp:342-354):
        // the FIRST key bound to a slot that already accrued credit while
        // unsecured wipes that credit to the 1-byte sentinel.
        let store = MetadataStore::in_memory().unwrap();
        let user_hash = "00112233445566778899aabbccddeeff";
        store.add_peer_credit_delta(user_hash, 1000, 2000).unwrap();

        let wiped = store
            .record_verified_secure_ident(user_hash, &[9u8; 80])
            .unwrap();
        assert!(wiped, "first key on accrued credit must wipe it");
        assert_eq!(
            store.peer_credit_by_hash(user_hash).unwrap(),
            Some(MetadataPeerCredit {
                user_hash: user_hash.to_string(),
                uploaded_bytes: 1,
                downloaded_bytes: 1,
            })
        );
    }

    #[test]
    fn first_verified_key_on_fresh_slot_keeps_zero_credit() {
        // A first verify on a slot with no accumulated credit binds the key
        // without wiping (GetDownloadedTotal() == 0 gate, ClientCredits.cpp:345).
        let store = MetadataStore::in_memory().unwrap();
        let user_hash = "00112233445566778899aabbccddeeff";

        let wiped = store
            .record_verified_secure_ident(user_hash, &[9u8; 80])
            .unwrap();
        assert!(!wiped, "fresh slot has nothing to wipe");
        let credit = store.peer_credit_by_hash(user_hash).unwrap().unwrap();
        assert_eq!(credit.uploaded_bytes, 0);
        assert_eq!(credit.downloaded_bytes, 0);
    }

    #[test]
    fn same_verified_key_keeps_credits() {
        // Bind the key on a fresh slot, accrue credit under the verified key,
        // then re-verify the same key: credits are preserved.
        let store = MetadataStore::in_memory().unwrap();
        let user_hash = "00112233445566778899aabbccddeeff";
        store
            .record_verified_secure_ident(user_hash, &[9u8; 80])
            .unwrap();
        store.add_peer_credit_delta(user_hash, 1000, 2000).unwrap();

        let wiped = store
            .record_verified_secure_ident(user_hash, &[9u8; 80])
            .unwrap();
        assert!(!wiped, "the same key must not wipe credits");
        let credit = store.peer_credit_by_hash(user_hash).unwrap().unwrap();
        assert_eq!(credit.uploaded_bytes, 1000);
        assert_eq!(credit.downloaded_bytes, 2000);
    }

    #[test]
    fn different_verified_key_keeps_first_key_and_credits() {
        let store = MetadataStore::in_memory().unwrap();
        let user_hash = "00112233445566778899aabbccddeeff";
        store
            .record_verified_secure_ident(user_hash, &[1u8; 80])
            .unwrap();
        store.add_peer_credit_delta(user_hash, 5000, 9000).unwrap();

        let (first_bind, wiped, pinned_key) = store
            .pin_verified_secure_ident(user_hash, &[2u8; 80])
            .unwrap();
        assert!(!first_bind);
        assert!(!wiped, "a mismatched key must not mutate credits");
        assert_eq!(pinned_key, vec![1u8; 80]);
        assert_eq!(
            store.peer_secure_ident_public_key(user_hash).unwrap(),
            Some(vec![1u8; 80])
        );
        let credit = store.peer_credit_by_hash(user_hash).unwrap().unwrap();
        assert_eq!(credit.uploaded_bytes, 5000);
        assert_eq!(credit.downloaded_bytes, 9000);
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
                "UPDATE peers SET last_seen_at_ms = ?1 WHERE user_hash = ?2",
                params![cutoff, stale_bytes],
            )
            .unwrap();

        let pruned = store.prune_aged_peers().unwrap();
        assert_eq!(pruned, 1);
        assert!(store.peer_credit_by_hash(fresh).unwrap().is_some());
        assert!(store.peer_credit_by_hash(stale).unwrap().is_none());
    }

    #[test]
    fn upload_timestamps_are_optional_seconds_and_require_actual_byte_events() {
        let mut store = MetadataStore::in_memory().unwrap();
        let hash = "45".repeat(16);
        store
            .upsert_indexed_file(
                &crate::MetadataIndexedFile {
                    ed2k_hash: hash.clone(),
                    name: "Sample.bin".into(),
                    size_bytes: 1024,
                    content_type: String::new(),
                    availability_score: 0,
                },
                crate::MetadataIndexedFileOrigin::PassiveCache,
            )
            .unwrap();
        let times = || {
            store
                .connection()
                .unwrap()
                .query_row(
                    "SELECT last_upload_requested_at_s,last_uploaded_at_s FROM known_files",
                    [],
                    |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<i64>>(1)?)),
                )
                .unwrap()
        };
        assert_eq!(times(), (None, None));
        let request = |at| MetadataFileUploadDelta {
            file_hash: hash.clone(),
            upload_requests: 1,
            last_requested_at_s: Some(at),
            ..Default::default()
        };
        store.apply_credit_deltas(&[], &[request(0)]).unwrap();
        assert_eq!(times(), (Some(0), None));
        store
            .apply_credit_deltas(&[], &[request(1_700_000_010)])
            .unwrap();
        store
            .apply_credit_deltas(&[], &[request(1_700_000_001)])
            .unwrap();
        assert_eq!(times(), (Some(1_700_000_010), None));
        let bytes = |at| MetadataFileUploadDelta {
            file_hash: hash.clone(),
            uploaded_bytes: 5,
            last_uploaded_at_s: Some(at),
            ..Default::default()
        };
        store.apply_credit_deltas(&[], &[bytes(0)]).unwrap();
        assert_eq!(times(), (Some(1_700_000_010), Some(0)));
        store
            .apply_credit_deltas(&[], &[bytes(1_700_000_009)])
            .unwrap();
        store
            .apply_credit_deltas(&[], &[bytes(1_700_000_002)])
            .unwrap();
        store
            .apply_credit_deltas(
                &[],
                &[MetadataFileUploadDelta {
                    file_hash: hash.clone(),
                    accepted_sessions: 1,
                    ..Default::default()
                }],
            )
            .unwrap();
        assert_eq!(times(), (Some(1_700_000_010), Some(1_700_000_009)));
        assert!(store.apply_credit_deltas(&[], &[request(-1)]).is_err());
        assert!(
            store
                .apply_credit_deltas(&[("78".repeat(16), 1, 0)], &[bytes(-1)])
                .is_err()
        );
        assert!(
            store
                .apply_credit_deltas(
                    &[],
                    &[MetadataFileUploadDelta {
                        file_hash: hash.clone(),
                        last_uploaded_at_s: Some(1_700_000_011),
                        ..Default::default()
                    }]
                )
                .is_err()
        );
        assert_eq!(
            store
                .connection()
                .unwrap()
                .query_row("SELECT count(*) FROM peers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        store.set_library_sharing_enabled(&hash, false).unwrap();
        assert_eq!(times(), (Some(1_700_000_010), Some(1_700_000_009)));
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
