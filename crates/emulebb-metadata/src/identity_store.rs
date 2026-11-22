use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{identity_model::MetadataLocalIdentity, store::unix_s};

/// Durable nonzero Kad routing identity for one profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KadNodeId([u8; 16]);

impl TryFrom<[u8; 16]> for KadNodeId {
    type Error = anyhow::Error;

    fn try_from(bytes: [u8; 16]) -> Result<Self> {
        ensure!(bytes != [0; 16], "Kad node identity cannot be zero");
        Ok(Self(bytes))
    }
}

impl KadNodeId {
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl super::MetadataStore {
    /// Load or atomically create the profile's nonzero Kad identity.
    pub fn load_or_create_kad_node_id(&self) -> Result<KadNodeId> {
        use rand::RngExt;
        self.load_or_create_kad_node_id_with(|| {
            let value = rand::rng().random::<std::num::NonZeroU128>();
            KadNodeId::try_from(value.get().to_be_bytes())
        })
    }

    fn load_or_create_kad_node_id_with(
        &self,
        create: impl FnOnce() -> Result<KadNodeId>,
    ) -> Result<KadNodeId> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<[u8; 16]> = tx
            .query_row(
                "SELECT public_identity FROM local_identities WHERE identity_kind = 'kad-node-id'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let id = match stored {
            Some(bytes) => KadNodeId::try_from(bytes)?,
            None => {
                let id = create()?;
                let now = unix_s();
                tx.execute("INSERT INTO local_identities(identity_kind, public_identity, private_secret, created_at_s, updated_at_s) VALUES ('kad-node-id', ?1, NULL, ?2, ?2)", params![id.as_bytes().as_slice(), now])?;
                id
            }
        };
        tx.commit()?;
        Ok(id)
    }
    pub fn load_local_identity(
        &self,
        identity_kind: &str,
    ) -> Result<Option<MetadataLocalIdentity>> {
        self.connection()?
            .query_row(
                r#"
                SELECT identity_kind, public_identity, private_secret
                FROM local_identities
                WHERE identity_kind = ?1
                "#,
                params![identity_kind],
                |row| {
                    Ok(MetadataLocalIdentity {
                        identity_kind: row.get(0)?,
                        public_identity: row.get(1)?,
                        private_secret: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn upsert_local_identity(&self, identity: &MetadataLocalIdentity) -> Result<()> {
        ensure!(
            !identity.identity_kind.trim().is_empty(),
            "identity kind must not be empty"
        );
        ensure!(
            identity.identity_kind != "kad-node-id",
            "Kad identity is created only by its typed owner"
        );
        let now = unix_s();
        self.connection()?.execute(
            r#"
            INSERT INTO local_identities(identity_kind, public_identity, private_secret, created_at_s, updated_at_s)
            VALUES (?1, ?2, ?3, ?4, ?4)
            ON CONFLICT(identity_kind) DO UPDATE SET
                public_identity = excluded.public_identity,
                private_secret = excluded.private_secret,
                updated_at_s = excluded.updated_at_s
            "#,
            params![
                identity.identity_kind,
                identity.public_identity,
                identity.private_secret,
                now,
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_and_identity_calendar_times_are_seconds() {
        let before = unix_s();
        let store = super::super::MetadataStore::in_memory().unwrap();
        let identity = MetadataLocalIdentity {
            identity_kind: "ed2k-user-hash".into(),
            public_identity: Some(vec![0x11; 16]),
            private_secret: None,
        };
        store.upsert_local_identity(&identity).unwrap();
        store.load_or_create_kad_node_id().unwrap();
        let conn = store.connection().unwrap();
        let mut stmt = conn.prepare("SELECT created_at_s FROM metadata_schema UNION ALL SELECT created_at_s FROM profile UNION ALL SELECT updated_at_s FROM profile UNION ALL SELECT created_at_s FROM local_identities UNION ALL SELECT updated_at_s FROM local_identities").unwrap();
        let times = stmt
            .query_map([], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(times.len(), 7);
        assert!(
            times
                .into_iter()
                .all(|time| (before..=unix_s()).contains(&time))
        );
        conn.execute(
            "UPDATE local_identities SET created_at_s=1 WHERE identity_kind='ed2k-user-hash'",
            [],
        )
        .unwrap();
        drop(stmt);
        drop(conn);
        store.upsert_local_identity(&identity).unwrap();
        let (created, updated): (i64, i64) = store.connection().unwrap().query_row("SELECT created_at_s,updated_at_s FROM local_identities WHERE identity_kind='ed2k-user-hash'", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        assert_eq!(created, 1);
        assert!((before..=unix_s()).contains(&updated));
    }

    #[test]
    fn kad_identity_rejects_zero_and_never_replaces_existing() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        assert!(KadNodeId::try_from([0; 16]).is_err());
        assert!(
            store
                .load_or_create_kad_node_id_with(|| KadNodeId::try_from([0; 16]))
                .is_err()
        );
        assert!(store.load_local_identity("kad-node-id").unwrap().is_none());
        let expected = KadNodeId::try_from([7; 16]).unwrap();
        assert_eq!(
            store
                .load_or_create_kad_node_id_with(|| Ok(expected))
                .unwrap(),
            expected
        );
        assert_eq!(
            store
                .load_or_create_kad_node_id_with(|| panic!("existing identity was regenerated"))
                .unwrap(),
            expected
        );
        assert!(
            store
                .upsert_local_identity(&MetadataLocalIdentity {
                    identity_kind: "kad-node-id".into(),
                    public_identity: Some(vec![9; 16]),
                    private_secret: None,
                })
                .is_err()
        );
        assert!(store.connection().unwrap().execute("UPDATE local_identities SET public_identity = zeroblob(16) WHERE identity_kind = 'kad-node-id'", []).is_err());
        assert!(store.connection().unwrap().execute("UPDATE local_identities SET public_identity = x'01' WHERE identity_kind = 'kad-node-id'", []).is_err());
        assert!(store.connection().unwrap().execute("UPDATE local_identities SET private_secret = x'01' WHERE identity_kind = 'kad-node-id'", []).is_err());
    }

    #[test]
    fn kad_identity_concurrent_creators_converge_and_reopen() {
        let root = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
            .join("tmp/identity-tests")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("metadata.db");
        drop(super::super::MetadataStore::open(&path).unwrap());
        let first = super::super::MetadataStore::open(&path).unwrap();
        let second = super::super::MetadataStore::open(&path).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let run = |store: super::super::MetadataStore,
                   candidate: u8,
                   barrier: std::sync::Arc<std::sync::Barrier>| {
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .load_or_create_kad_node_id_with(|| KadNodeId::try_from([candidate; 16]))
                    .unwrap()
            })
        };
        let a = run(first, 1, barrier.clone());
        let b = run(second, 2, barrier);
        let id = a.join().unwrap();
        assert_eq!(id, b.join().unwrap());
        let reopened = super::super::MetadataStore::open(&path).unwrap();
        assert_eq!(reopened.load_or_create_kad_node_id().unwrap(), id);
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn kad_identity_insert_failure_rolls_back_and_can_retry() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let store = super::super::MetadataStore::from_connection(conn).unwrap();
        store.connection().unwrap().execute_batch("CREATE TEMP TRIGGER fail_kad_id BEFORE INSERT ON main.local_identities WHEN NEW.identity_kind = 'kad-node-id' AND NEW.public_identity = x'09090909090909090909090909090909' BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
        assert!(
            store
                .load_or_create_kad_node_id_with(|| KadNodeId::try_from([9; 16]))
                .is_err()
        );
        assert!(store.load_local_identity("kad-node-id").unwrap().is_none());
        let expected = KadNodeId::try_from([7; 16]).unwrap();
        assert_eq!(
            store
                .load_or_create_kad_node_id_with(|| Ok(expected))
                .unwrap(),
            expected
        );
    }

    #[test]
    fn local_identity_roundtrips() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        store
            .upsert_local_identity(&MetadataLocalIdentity {
                identity_kind: "ed2k-user-hash".to_string(),
                public_identity: Some(vec![0x11; 16]),
                private_secret: None,
            })
            .unwrap();
        store
            .upsert_local_identity(&MetadataLocalIdentity {
                identity_kind: "ed2k-secure-ident".to_string(),
                public_identity: None,
                private_secret: Some(vec![0x22; 32]),
            })
            .unwrap();

        assert_eq!(
            store
                .load_local_identity("ed2k-user-hash")
                .unwrap()
                .unwrap()
                .public_identity,
            Some(vec![0x11; 16])
        );
        assert_eq!(
            store
                .load_local_identity("ed2k-secure-ident")
                .unwrap()
                .unwrap()
                .private_secret,
            Some(vec![0x22; 32])
        );
    }
}
