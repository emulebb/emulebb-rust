use super::{DhtNode, contact_helpers::addr_from_contact};
use crate::error::DhtError;
use crate::types::{HelloPeerMetadata, parse_hello_peer_metadata};
use emulebb_kad_proto::{KadUdpKey, NodeId, Tag};
use emulebb_kad_routing::{
    Contact, RoutingError, RoutingSplitDeniedReason, RoutingSubnetLimitScope,
};
use std::net::{IpAddr, SocketAddr};
use tracing::{debug, warn};

impl DhtNode {
    /// Snapshot currently known contacts.
    pub async fn routing_contacts(&self) -> Vec<Contact> {
        self.inner.routing_table.lock().await.all_contacts()
    }

    /// Parse a `nodes.dat` payload and upsert its contacts into the routing
    /// table. Returns the number of contacts accepted.
    pub async fn import_nodes_dat(&self, data: &[u8]) -> Result<usize, DhtError> {
        let contacts = crate::bootstrap::parse_nodes_dat(data)?;
        let mut added = 0usize;
        for bc in contacts {
            let mut contact =
                Contact::new(bc.node_id, bc.ip, bc.udp_port, bc.tcp_port, bc.version);
            contact.udp_key = bc.udp_key;
            if self.add_contact(contact).await.is_ok() {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Upsert a single contact into the routing table.
    pub async fn add_contact(&self, contact: Contact) -> Result<(), DhtError> {
        let mut contact = contact;
        let addr = addr_from_contact(&contact);
        if contact.udp_key == KadUdpKey::ZERO
            && let Some(known_udp_key) = self.known_peer_key(addr)
        {
            contact.udp_key = known_udp_key;
        }
        self.inner.rpc.register_peer_identity(addr, contact.id);
        self.inner
            .rpc
            .register_peer_version(addr, contact.kad_version);
        if contact.udp_key != KadUdpKey::ZERO {
            self.inner
                .rpc
                .register_peer_key(addr, contact.udp_key.value());
        }
        let contact_id = contact.id;
        let contact_ip = contact.ip;
        let contact_udp_port = contact.udp_port;
        match self.inner.routing_table.lock().await.add_contact(contact) {
            Ok(()) => Ok(()),
            Err(error) => {
                log_routing_rejection(&error, contact_id, contact_ip, contact_udp_port);
                Err(error.into())
            }
        }
    }

    /// Return the closest known contacts to the target.
    pub async fn closest_contacts(&self, target: &NodeId, limit: usize) -> Vec<Contact> {
        self.inner
            .routing_table
            .lock()
            .await
            .get_closest(target, limit)
    }

    /// Record a contact learned from a Kad HELLO request or response.
    pub async fn add_contact_from_hello(
        &self,
        from: SocketAddr,
        node_id: NodeId,
        tcp_port: u16,
        version: u8,
        tags: &[Tag],
    ) -> Result<HelloPeerMetadata, DhtError> {
        let mut metadata = parse_hello_peer_metadata(tags);
        if version < 8 {
            metadata.requests_hello_res_ack = false;
        }

        let IpAddr::V4(ip) = from.ip() else {
            return Ok(metadata);
        };
        let mut contact = Contact::new(
            node_id,
            ip,
            metadata.hello_source_udp_port.unwrap_or(from.port()),
            tcp_port,
            version,
        );
        contact.hello_source_udp_port = metadata.hello_source_udp_port;
        contact.udp_firewalled = metadata.udp_firewalled;
        contact.tcp_firewalled = metadata.tcp_firewalled;
        contact.requests_hello_res_ack = metadata.requests_hello_res_ack;
        if let Some(known_udp_key) = self.known_peer_key(from) {
            contact.udp_key = known_udp_key;
        }

        self.add_contact(contact).await?;
        Ok(metadata)
    }
}

fn log_routing_rejection(
    error: &RoutingError,
    contact_id: NodeId,
    contact_ip: std::net::Ipv4Addr,
    contact_udp_port: u16,
) {
    match error {
        RoutingError::SubnetLimitExceeded { prefix, scope } => {
            log_subnet_limit_rejection(contact_id, contact_ip, contact_udp_port, *prefix, scope);
        }
        RoutingError::SplitDenied { reason } => {
            log_split_denied_rejection(contact_id, contact_ip, contact_udp_port, reason);
        }
        RoutingError::IpLimitExceeded { .. } => {
            log_ip_limit_rejection(contact_id, contact_ip, contact_udp_port);
        }
        RoutingError::TableFull { max } => {
            log_table_full_rejection(contact_id, contact_ip, contact_udp_port, *max);
        }
    }
}

fn log_subnet_limit_rejection(
    contact_id: NodeId,
    contact_ip: std::net::Ipv4Addr,
    contact_udp_port: u16,
    prefix: u8,
    scope: &RoutingSubnetLimitScope,
) {
    warn!(
        target: "kad_routing",
        contact_id = %contact_id,
        contact_ip = %contact_ip,
        contact_udp_port,
        prefix,
        scope = routing_subnet_scope_label(scope),
        "routing contact rejected by subnet limit"
    );
}

fn log_split_denied_rejection(
    contact_id: NodeId,
    contact_ip: std::net::Ipv4Addr,
    contact_udp_port: u16,
    reason: &RoutingSplitDeniedReason,
) {
    warn!(
        target: "kad_routing",
        contact_id = %contact_id,
        contact_ip = %contact_ip,
        contact_udp_port,
        reason = routing_split_denied_reason_label(reason),
        "routing leaf split denied while inserting contact"
    );
}

fn log_ip_limit_rejection(
    contact_id: NodeId,
    contact_ip: std::net::Ipv4Addr,
    contact_udp_port: u16,
) {
    debug!(
        target: "kad_routing",
        contact_id = %contact_id,
        contact_ip = %contact_ip,
        contact_udp_port,
        "routing contact rejected by duplicate IP limit"
    );
}

fn log_table_full_rejection(
    contact_id: NodeId,
    contact_ip: std::net::Ipv4Addr,
    contact_udp_port: u16,
    max: usize,
) {
    warn!(
        target: "kad_routing",
        contact_id = %contact_id,
        contact_ip = %contact_ip,
        contact_udp_port,
        max,
        "routing table rejected contact because the destination bin is full"
    );
}

fn routing_subnet_scope_label(scope: &RoutingSubnetLimitScope) -> &'static str {
    match scope {
        RoutingSubnetLimitScope::Global => "global",
        RoutingSubnetLimitScope::BinLocal => "bin_local",
    }
}

fn routing_split_denied_reason_label(reason: &RoutingSplitDeniedReason) -> &'static str {
    match reason {
        RoutingSplitDeniedReason::DepthLimit => "depth_limit",
        RoutingSplitDeniedReason::MaxTableSize => "max_table_size",
        RoutingSplitDeniedReason::ZoneIndexCap => "zone_index_cap",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DhtConfig;
    use emulebb_kad_proto::{Tag, TagValue, tag_name};

    #[tokio::test]
    async fn hello_contact_uses_advertised_source_udp_port_and_metadata() {
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let node_id = NodeId::from_bytes([0x42; 16]);

        let metadata = dht
            .add_contact_from_hello(
                "198.51.100.22:41002".parse().unwrap(),
                node_id,
                41001,
                10,
                &[
                    Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(42002)),
                    Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x06)),
                ],
            )
            .await
            .unwrap();

        assert_eq!(metadata.hello_source_udp_port, Some(42002));
        assert!(!metadata.udp_firewalled);
        assert!(metadata.tcp_firewalled);
        assert!(metadata.requests_hello_res_ack);
        let contact = dht.routing_contacts().await.pop().unwrap();
        assert_eq!(contact.id, node_id);
        assert_eq!(contact.udp_port, 42002);
        assert_eq!(contact.tcp_port, 41001);
        assert_eq!(contact.hello_source_udp_port, Some(42002));
        assert!(!contact.udp_firewalled);
        assert!(contact.tcp_firewalled);
        assert!(contact.requests_hello_res_ack);
    }
}
