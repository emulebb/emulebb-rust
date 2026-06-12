use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};

use crate::{identity_model::MetadataLocalIdentity, store::unix_ms};

impl super::MetadataStore {
    pub fn load_local_identity(&self, kind: &str) -> Result<Option<MetadataLocalIdentity>> {
        self.connection()?
            .query_row(
                r#"
                SELECT kind, public_identity, private_secret
                FROM local_identities
                WHERE kind = ?1
                "#,
                params![kind],
                |row| {
                    Ok(MetadataLocalIdentity {
                        kind: row.get(0)?,
                        public_identity: row.get(1)?,
                        private_secret: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn upsert_local_identity(&self, identity: &MetadataLocalIdentity) -> Result<()> {
        ensure!(!identity.kind.trim().is_empty(), "identity kind must not be empty");
        let now = unix_ms();
        self.connection()?.execute(
            r#"
            INSERT INTO local_identities(kind, public_identity, private_secret, created_at_ms, updated_at_ms)
            VALUES (?1, ?2, ?3, ?4, ?4)
            ON CONFLICT(kind) DO UPDATE SET
                public_identity = excluded.public_identity,
                private_secret = excluded.private_secret,
                updated_at_ms = excluded.updated_at_ms
            "#,
            params![
                identity.kind,
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
    fn local_identity_roundtrips() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        store
            .upsert_local_identity(&MetadataLocalIdentity {
                kind: "ed2k-user-hash".to_string(),
                public_identity: Some(vec![0x11; 16]),
                private_secret: None,
            })
            .unwrap();
        store
            .upsert_local_identity(&MetadataLocalIdentity {
                kind: "ed2k-secure-ident".to_string(),
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
