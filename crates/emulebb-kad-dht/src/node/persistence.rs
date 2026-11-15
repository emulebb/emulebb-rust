//! Typed routing snapshots, independent of their durable storage owner.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use emulebb_kad_proto::{KadUdpKey, NodeId};
use emulebb_kad_routing::{Contact, ContactType, DEFAULT_MAX_SIZE};

use super::DhtNode;
use crate::DhtError;

#[cfg(test)]
mod tests;

/// Full routing evidence with calendar times represented as Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingSnapshotContact {
    pub node_id: NodeId,
    pub ip: Ipv4Addr,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub version: u8,
    pub udp_key: KadUdpKey,
    pub udp_key_ip: Option<Ipv4Addr>,
    pub hello_source_udp_port: Option<u16>,
    pub udp_firewalled: bool,
    pub tcp_firewalled: bool,
    pub requests_hello_res_ack: bool,
    pub received_hello_packet: bool,
    pub verified: bool,
    pub contact_type: ContactType,
    pub probe_type: u8,
    pub bootstrap: bool,
    pub expires_at_seconds: Option<i64>,
    pub last_type_set_at_seconds: Option<i64>,
    pub last_seen_at_seconds: i64,
    pub created_at_seconds: i64,
}

fn seconds(time: SystemTime) -> Result<i64, DhtError> {
    let elapsed = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DhtError::InvalidRoutingSnapshot)?;
    i64::try_from(elapsed.as_secs()).map_err(|_| DhtError::InvalidRoutingSnapshot)
}

fn time(seconds: i64) -> Result<SystemTime, DhtError> {
    let value = u64::try_from(seconds).map_err(|_| DhtError::InvalidRoutingSnapshot)?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(value))
        .ok_or(DhtError::InvalidRoutingSnapshot)
}

impl TryFrom<&Contact> for RoutingSnapshotContact {
    type Error = DhtError;

    fn try_from(c: &Contact) -> Result<Self, Self::Error> {
        let record = Self {
            node_id: c.id,
            ip: c.ip,
            udp_port: c.udp_port,
            tcp_port: c.tcp_port,
            version: c.kad_version,
            udp_key: c.udp_key,
            udp_key_ip: c.udp_key_ip,
            hello_source_udp_port: c.hello_source_udp_port,
            udp_firewalled: c.udp_firewalled,
            tcp_firewalled: c.tcp_firewalled,
            requests_hello_res_ack: c.requests_hello_res_ack,
            received_hello_packet: c.received_hello_packet,
            verified: c.verified,
            contact_type: c.contact_type,
            probe_type: c.probe_type,
            bootstrap: c.bootstrap,
            expires_at_seconds: c.expires_at.map(seconds).transpose()?,
            last_type_set_at_seconds: c.last_type_set_at.map(seconds).transpose()?,
            last_seen_at_seconds: seconds(c.last_seen)?,
            created_at_seconds: seconds(c.created_at)?,
        };
        record.validate()?;
        Ok(record)
    }
}

impl RoutingSnapshotContact {
    fn validate(&self) -> Result<(), DhtError> {
        if self.ip.is_unspecified()
            || self.udp_port == 0
            || self.probe_type > 4
            || self.hello_source_udp_port == Some(0)
            || self.udp_key_ip.is_some_and(|ip| ip.is_unspecified())
        {
            return Err(DhtError::InvalidRoutingSnapshot);
        }
        Ok(())
    }
}

impl TryFrom<&RoutingSnapshotContact> for Contact {
    type Error = DhtError;

    fn try_from(c: &RoutingSnapshotContact) -> Result<Self, Self::Error> {
        c.validate()?;
        Ok(Self {
            id: c.node_id,
            ip: c.ip,
            udp_port: c.udp_port,
            tcp_port: c.tcp_port,
            kad_version: c.version,
            udp_key: c.udp_key,
            udp_key_ip: c.udp_key_ip,
            hello_source_udp_port: c.hello_source_udp_port,
            udp_firewalled: c.udp_firewalled,
            tcp_firewalled: c.tcp_firewalled,
            requests_hello_res_ack: c.requests_hello_res_ack,
            received_hello_packet: c.received_hello_packet,
            verified: c.verified,
            contact_type: c.contact_type,
            probe_type: c.probe_type,
            bootstrap: c.bootstrap,
            expires_at: c.expires_at_seconds.map(time).transpose()?,
            last_type_set_at: c.last_type_set_at_seconds.map(time).transpose()?,
            last_seen: time(c.last_seen_at_seconds)?,
            created_at: time(c.created_at_seconds)?,
        })
    }
}

/// Result of applying a bounded snapshot through routing admission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoutingRestoreOutcome {
    pub accepted: usize,
    pub expired: usize,
    pub rejected: usize,
}

impl DhtNode {
    /// Capture the complete bounded table and currently bound learned UDP keys.
    /// The address and key overlay are captured under the binding gate.
    /// Routing-generation fencing belongs to the persistence integration.
    /// Persistence callers must reserve their contact and conversion memory
    /// before calling, because capture allocates up to the routing limit.
    pub async fn capture_routing_snapshot(&self) -> Result<Vec<RoutingSnapshotContact>, DhtError> {
        let contacts = {
            let table = self.inner.routing_table.lock().await;
            if table.len() > DEFAULT_MAX_SIZE {
                return Err(DhtError::RoutingSnapshotTooLarge);
            }
            table.all_contacts()
        };
        let _binding = self.inner.key_binding_gate.lock().await;
        let public_ip = self.public_ip_for_udp_keys();
        let mut snapshot = Vec::with_capacity(contacts.len());
        for contact in &contacts {
            let mut record = RoutingSnapshotContact::try_from(contact)?;
            if let Some(binding) = public_ip {
                let addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.udp_port);
                if let Some(key) = self
                    .known_peer_key(addr)
                    .filter(|key| *key != KadUdpKey::ZERO)
                {
                    record.udp_key = key;
                    record.udp_key_ip = Some(binding);
                }
            }
            snapshot.push(record);
        }
        Ok(snapshot)
    }

    /// Validate and merge a snapshot. Expired entries and routing-admission
    /// conflicts are counted; invalid records reject the batch before mutation.
    pub async fn restore_routing_snapshot(
        &self,
        records: &[RoutingSnapshotContact],
        now: SystemTime,
    ) -> Result<RoutingRestoreOutcome, DhtError> {
        if records.len() > DEFAULT_MAX_SIZE {
            return Err(DhtError::RoutingSnapshotTooLarge);
        }
        let contacts: Vec<Contact> = records
            .iter()
            .map(Contact::try_from)
            .collect::<Result<_, _>>()?;
        let mut outcome = RoutingRestoreOutcome::default();
        let mut accepted = Vec::new();
        let mut accepted_ids = HashSet::new();
        {
            let mut table = self.inner.routing_table.lock().await;
            for contact in contacts {
                if contact.expires_at.is_some_and(|expires| expires <= now) {
                    outcome.expired += 1;
                    continue;
                }
                if contact.contact_type == ContactType::Dead {
                    outcome.rejected += 1;
                    continue;
                }
                let id = contact.id;
                match table.merge_restored_contact(contact) {
                    Ok(true) => {
                        if accepted_ids.insert(id) {
                            outcome.accepted += 1;
                        }
                        if let Some(merged) = table.get(&id) {
                            accepted.push(merged.clone());
                        }
                    }
                    Ok(false) | Err(_) => outcome.rejected += 1,
                }
            }
        }
        let _binding = self.inner.key_binding_gate.lock().await;
        for contact in accepted {
            let addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.udp_port);
            self.inner
                .rpc
                .register_peer_identity_if_absent(addr, contact.id);
            self.inner
                .rpc
                .register_peer_version_if_higher(addr, contact.kad_version);
            if self.udp_key_matches_public_ip(contact.udp_key, contact.udp_key_ip) {
                self.inner
                    .rpc
                    .register_peer_key_if_absent(addr, contact.udp_key.value());
            }
        }
        Ok(outcome)
    }
}
