//! ID-addressed server edits and deletion without read/modify/write snapshots.
use anyhow::{Result, ensure};
use rusqlite::{TransactionBehavior, params};

use crate::{MetadataServer, MetadataStore, store::unix_s};

/// Explicit creation cannot modify a resource already owning this live endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerEndpointConflict;

impl std::fmt::Display for ServerEndpointConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("server endpoint already exists")
    }
}
impl std::error::Error for ServerEndpointConflict {}

/// Saved operator fields; network observations and endpoint identity are separate.
#[derive(Debug, Clone, Default)]
pub struct MetadataServerUpdate {
    pub priority: Option<String>,
    pub static_server: Option<bool>,
    pub enabled: Option<bool>,
}

impl MetadataStore {
    /// Create a resource without import's merge semantics. The writer lock spans
    /// duplicate detection, insertion and discovery initialization.
    pub fn create_server_resource(&self, server: &MetadataServer) -> Result<i64> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // WHY: a duplicate request must not edit or enable the existing server.
        // Keep the live-endpoint check under the same SQLite writer lock as the
        // insertion so concurrent creators cannot both claim success.
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM servers WHERE address=?1 AND port=?2 AND deleted_at_s IS NULL)",
            params![server.address, server.port],
            |row| row.get(0),
        )?;
        ensure!(!exists, ServerEndpointConflict);
        let id = crate::profile_store::upsert_server_in_transaction(&transaction, server)?;
        Self::mark_discovery_initialized(&transaction, crate::DiscoveryDomain::Servers)?;
        transaction.commit()?;
        Ok(id)
    }

    /// Apply only selected fields to one live ID. False means no such resource.
    /// Unchanged values still acknowledge an existing resource.
    pub fn update_server_resource(&self, id: i64, update: &MetadataServerUpdate) -> Result<bool> {
        ensure!(id > 0, "invalid server ID");
        ensure!(
            update.priority.is_some() || update.static_server.is_some() || update.enabled.is_some(),
            "server update requires at least one field"
        );
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // WHY: an operator edit must not overwrite telemetry published since a
        // previous read. Update the selected columns directly under one write.
        let changed = transaction.execute(
            "UPDATE servers SET server_priority=coalesce(?2,server_priority),
             static_server=coalesce(?3,static_server),enabled=coalesce(?4,enabled)
             WHERE id=?1 AND deleted_at_s IS NULL",
            params![id, update.priority, update.static_server, update.enabled],
        )?;
        transaction.commit()?;
        Ok(changed != 0)
    }

    /// Retire one live resource. Re-import of its endpoint allocates a fresh ID.
    /// Repeated deletion or an unknown ID returns false without changing a row.
    pub fn delete_server_resource(&self, id: i64) -> Result<bool> {
        ensure!(id > 0, "invalid server ID");
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE servers SET enabled=0,deleted_at_s=?2 WHERE id=?1 AND deleted_at_s IS NULL",
            params![id, unix_s()],
        )?;
        transaction.commit()?;
        Ok(changed != 0)
    }
}
