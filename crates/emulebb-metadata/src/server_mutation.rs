//! ID-addressed server edits and deletion without read/modify/write snapshots.
use anyhow::{Result, ensure};
use rusqlite::{TransactionBehavior, params};

use crate::{MetadataStore, store::unix_s};

/// Saved operator fields; network observations and endpoint identity are separate.
#[derive(Debug, Clone, Default)]
pub struct MetadataServerUpdate {
    pub name: Option<String>,
    pub priority: Option<String>,
    pub static_server: Option<bool>,
    pub enabled: Option<bool>,
}

impl MetadataStore {
    /// Apply only selected fields to one live ID. False means no such resource.
    /// Unchanged values still acknowledge an existing resource.
    pub fn update_server_resource(&self, id: i64, update: &MetadataServerUpdate) -> Result<bool> {
        ensure!(id > 0, "invalid server ID");
        ensure!(
            update.name.is_some()
                || update.priority.is_some()
                || update.static_server.is_some()
                || update.enabled.is_some(),
            "server update requires at least one field"
        );
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // WHY: an operator edit must not overwrite telemetry published since a
        // previous read. Update the selected columns directly under one write.
        let changed = transaction.execute(
            "UPDATE servers SET name=coalesce(?2,name),server_priority=coalesce(?3,server_priority),
             static_server=coalesce(?4,static_server),enabled=coalesce(?5,enabled)
             WHERE id=?1 AND deleted_at_s IS NULL",
            params![id, update.name, update.priority, update.static_server, update.enabled],
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
