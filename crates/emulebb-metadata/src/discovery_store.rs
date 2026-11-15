//! Durable initialization state for independently owned discovery sources.

use anyhow::{Result, bail, ensure};
use rusqlite::Transaction;

use crate::MetadataStore;

/// Discovery data whose first initialization is tracked independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryDomain {
    Servers,
    Kad,
}

impl DiscoveryDomain {
    fn as_str(self) -> &'static str {
        match self {
            Self::Servers => "servers",
            Self::Kad => "kad",
        }
    }
}

/// Whether discovery initialization still needs an attempt on a future launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryInitializationStatus {
    Pending,
    Initialized,
}

impl MetadataStore {
    /// Read the initialization state, including when the collection is empty.
    pub fn discovery_initialization_status(
        &self,
        domain: DiscoveryDomain,
    ) -> Result<DiscoveryInitializationStatus> {
        let conn = self.connection()?;
        let status: String = conn.query_row(
            "SELECT status FROM discovery_initialization WHERE domain = ?1",
            [domain.as_str()],
            |row| row.get(0),
        )?;
        match status.as_str() {
            "pending" => Ok(DiscoveryInitializationStatus::Pending),
            "initialized" => Ok(DiscoveryInitializationStatus::Initialized),
            _ => bail!("invalid discovery initialization status"),
        }
    }

    /// Mark a domain initialized within the transaction that commits its data.
    ///
    /// An intentionally empty collection can also be initialized. Callers must
    /// commit this update together with the collection mutation or import.
    pub fn mark_discovery_initialized(tx: &Transaction<'_>, domain: DiscoveryDomain) -> Result<()> {
        let changed = tx.execute(
            "UPDATE discovery_initialization SET status = 'initialized' WHERE domain = ?1",
            [domain.as_str()],
        )?;
        ensure!(changed == 1, "discovery initialization state is missing");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_states_persist_even_for_empty_collections() {
        let path =
            std::env::temp_dir().join(format!("emulebb-discovery-{}.db", uuid::Uuid::new_v4()));
        let store = MetadataStore::open(&path).unwrap();
        for domain in [DiscoveryDomain::Servers, DiscoveryDomain::Kad] {
            assert_eq!(
                store.discovery_initialization_status(domain).unwrap(),
                DiscoveryInitializationStatus::Pending
            );
        }
        {
            let mut conn = store.connection().unwrap();
            let tx = conn.transaction().unwrap();
            MetadataStore::mark_discovery_initialized(&tx, DiscoveryDomain::Servers).unwrap();
            MetadataStore::mark_discovery_initialized(&tx, DiscoveryDomain::Servers).unwrap();
            tx.commit().unwrap();
        }
        assert!(store.load_servers().unwrap().is_empty());
        drop(store);
        let reopened = MetadataStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .discovery_initialization_status(DiscoveryDomain::Servers)
                .unwrap(),
            DiscoveryInitializationStatus::Initialized
        );
        assert_eq!(
            reopened
                .discovery_initialization_status(DiscoveryDomain::Kad)
                .unwrap(),
            DiscoveryInitializationStatus::Pending
        );
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn state_change_rolls_back_and_missing_rows_fail() {
        let store = MetadataStore::in_memory().unwrap();
        {
            let mut conn = store.connection().unwrap();
            let tx = conn.transaction().unwrap();
            MetadataStore::mark_discovery_initialized(&tx, DiscoveryDomain::Kad).unwrap();
            tx.rollback().unwrap();
            conn.execute(
                "DELETE FROM discovery_initialization WHERE domain = 'servers'",
                [],
            )
            .unwrap();
        }
        assert_eq!(
            store
                .discovery_initialization_status(DiscoveryDomain::Kad)
                .unwrap(),
            DiscoveryInitializationStatus::Pending
        );
        assert!(
            store
                .discovery_initialization_status(DiscoveryDomain::Servers)
                .is_err()
        );
        let mut conn = store.connection().unwrap();
        let tx = conn.transaction().unwrap();
        assert!(MetadataStore::mark_discovery_initialized(&tx, DiscoveryDomain::Servers).is_err());
    }
}
