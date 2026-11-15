//! Typed, revision-guarded persistence for the bounded Kad routing table.

use anyhow::{Result, bail, ensure};
use rusqlite::{TransactionBehavior, params};

use crate::{DiscoveryDomain, DiscoveryInitializationStatus, MetadataStore};

#[cfg(test)]
mod tests;

/// The production routing table's current maximum accepted contact count.
pub const KAD_ROUTING_MAX_CONTACTS: usize = 12_000;

/// Persisted routing liveness classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KadRoutingContactType {
    Active,
    Inactive,
    Dead,
}

impl KadRoutingContactType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Dead => "dead",
        }
    }
}

/// Durable fields of an accepted routing contact. IPv4 values use network-order
/// numeric representation; calendar timestamps are Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KadRoutingContact {
    pub node_id: [u8; 16],
    pub ip: u32,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub version: u8,
    pub udp_key: u32,
    pub udp_key_ip: Option<u32>,
    pub hello_source_udp_port: Option<u16>,
    pub udp_firewalled: bool,
    pub tcp_firewalled: bool,
    pub requests_hello_res_ack: bool,
    pub received_hello_packet: bool,
    pub verified: bool,
    pub contact_type: KadRoutingContactType,
    pub probe_type: u8,
    pub bootstrap: bool,
    pub expires_at_seconds: Option<i64>,
    pub last_type_set_at_seconds: Option<i64>,
    pub last_seen_at_seconds: i64,
    pub created_at_seconds: i64,
}

/// One coherent database snapshot and its compare-and-set revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KadRoutingSnapshot {
    pub revision: i64,
    pub initialization: DiscoveryInitializationStatus,
    pub contacts: Vec<KadRoutingContact>,
}

impl MetadataStore {
    /// Read contact data, revision and initialization state from one transaction.
    pub fn load_kad_routing_snapshot(&self) -> Result<KadRoutingSnapshot> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let revision = tx.query_row(
            "SELECT revision FROM kad_routing_revision WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        let state: String = tx.query_row(
            "SELECT status FROM discovery_initialization WHERE domain = 'kad'",
            [],
            |row| row.get(0),
        )?;
        let initialization = match state.as_str() {
            "pending" => DiscoveryInitializationStatus::Pending,
            "initialized" => DiscoveryInitializationStatus::Initialized,
            _ => bail!("invalid Kad initialization status"),
        };
        let contacts = {
            let mut stmt = tx.prepare("SELECT node_id, ip, udp_port, tcp_port, version, udp_key, udp_key_ip, hello_source_udp_port, udp_firewalled, tcp_firewalled, requests_hello_res_ack, received_hello_packet, verified, contact_type, probe_type, bootstrap, expires_at_seconds, last_type_set_at_seconds, last_seen_at_seconds, created_at_seconds FROM kad_routing_contacts ORDER BY node_id LIMIT ?1")?;
            let rows = stmt.query_map([(KAD_ROUTING_MAX_CONTACTS + 1) as i64], |row| {
                let kind: String = row.get(13)?;
                let contact_type = match kind.as_str() {
                    "active" => KadRoutingContactType::Active,
                    "inactive" => KadRoutingContactType::Inactive,
                    "dead" => KadRoutingContactType::Dead,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                Ok(KadRoutingContact {
                    node_id: row.get(0)?,
                    ip: row.get(1)?,
                    udp_port: row.get(2)?,
                    tcp_port: row.get(3)?,
                    version: row.get(4)?,
                    udp_key: row.get(5)?,
                    udp_key_ip: row.get(6)?,
                    hello_source_udp_port: row.get(7)?,
                    udp_firewalled: row.get::<_, bool>(8)?,
                    tcp_firewalled: row.get::<_, bool>(9)?,
                    requests_hello_res_ack: row.get::<_, bool>(10)?,
                    received_hello_packet: row.get::<_, bool>(11)?,
                    verified: row.get::<_, bool>(12)?,
                    contact_type,
                    probe_type: row.get(14)?,
                    bootstrap: row.get::<_, bool>(15)?,
                    expires_at_seconds: row.get(16)?,
                    last_type_set_at_seconds: row.get(17)?,
                    last_seen_at_seconds: row.get(18)?,
                    created_at_seconds: row.get(19)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        ensure!(
            contacts.len() <= KAD_ROUTING_MAX_CONTACTS,
            "Kad routing snapshot exceeds contact limit"
        );
        tx.commit()?;
        Ok(KadRoutingSnapshot {
            revision,
            initialization,
            contacts,
        })
    }

    /// Replace the entire accepted snapshot and mark Kad initialized atomically.
    /// Returns `None` if the revision changed, or if `only_if_pending` is set
    /// and another operation has already initialized Kad. An empty snapshot is
    /// an explicit initialized state. Runtime callers must also order capture,
    /// imports and publication through the shared persistence owner.
    pub fn replace_kad_routing_snapshot(
        &self,
        expected_revision: i64,
        only_if_pending: bool,
        contacts: &[KadRoutingContact],
    ) -> Result<Option<i64>> {
        ensure!(expected_revision >= 0, "invalid Kad routing revision");
        ensure!(
            contacts.len() <= KAD_ROUTING_MAX_CONTACTS,
            "Kad routing snapshot exceeds contact limit"
        );
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: i64 = tx.query_row(
            "SELECT revision FROM kad_routing_revision WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        let state: String = tx.query_row(
            "SELECT status FROM discovery_initialization WHERE domain = 'kad'",
            [],
            |row| row.get(0),
        )?;
        ensure!(
            state == "pending" || state == "initialized",
            "invalid Kad initialization status"
        );
        if current != expected_revision || (only_if_pending && state != "pending") {
            return Ok(None);
        }
        let next = current
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Kad routing revision exhausted"))?;
        tx.execute("DELETE FROM kad_routing_contacts", [])?;
        {
            let mut insert = tx.prepare_cached("INSERT INTO kad_routing_contacts VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)")?;
            for c in contacts {
                insert.execute(params![
                    c.node_id.as_slice(),
                    c.ip,
                    c.udp_port,
                    c.tcp_port,
                    c.version,
                    c.udp_key,
                    c.udp_key_ip,
                    c.hello_source_udp_port,
                    c.udp_firewalled,
                    c.tcp_firewalled,
                    c.requests_hello_res_ack,
                    c.received_hello_packet,
                    c.verified,
                    c.contact_type.as_str(),
                    c.probe_type,
                    c.bootstrap,
                    c.expires_at_seconds,
                    c.last_type_set_at_seconds,
                    c.last_seen_at_seconds,
                    c.created_at_seconds
                ])?;
            }
        }
        Self::mark_discovery_initialized(&tx, DiscoveryDomain::Kad)?;
        tx.execute(
            "UPDATE kad_routing_revision SET revision = ?1 WHERE id = 1",
            [next],
        )?;
        tx.commit()?;
        Ok(Some(next))
    }
}
