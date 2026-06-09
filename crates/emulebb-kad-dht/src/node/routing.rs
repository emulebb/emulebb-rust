use super::{DhtNode, contact_helpers::addr_from_contact};
use crate::error::DhtError;
use emulebb_kad_proto::{KadUdpKey, NodeId};
use emulebb_kad_routing::{
    Contact, RoutingError, RoutingSplitDeniedReason, RoutingSubnetLimitScope,
};
use tracing::{debug, warn};

impl DhtNode {
    /// Snapshot currently known contacts.
    pub async fn routing_contacts(&self) -> Vec<Contact> {
        self.inner.routing_table.lock().await.all_contacts()
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
}

fn log_routing_rejection(
    error: &RoutingError,
    contact_id: NodeId,
    contact_ip: std::net::Ipv4Addr,
    contact_udp_port: u16,
) {
    match error {
        RoutingError::SubnetLimitExceeded { prefix, scope } => {
            warn!(
                target: "kad_routing",
                contact_id = %contact_id,
                contact_ip = %contact_ip,
                contact_udp_port,
                prefix = *prefix,
                scope = match scope {
                    RoutingSubnetLimitScope::Global => "global",
                    RoutingSubnetLimitScope::BinLocal => "bin_local",
                },
                "routing contact rejected by subnet limit"
            );
        }
        RoutingError::SplitDenied { reason } => {
            warn!(
                target: "kad_routing",
                contact_id = %contact_id,
                contact_ip = %contact_ip,
                contact_udp_port,
                reason = match reason {
                    RoutingSplitDeniedReason::DepthLimit => "depth_limit",
                    RoutingSplitDeniedReason::MaxTableSize => "max_table_size",
                    RoutingSplitDeniedReason::ZoneIndexCap => "zone_index_cap",
                },
                "routing leaf split denied while inserting contact"
            );
        }
        RoutingError::IpLimitExceeded { .. } => {
            debug!(
                target: "kad_routing",
                contact_id = %contact_id,
                contact_ip = %contact_ip,
                contact_udp_port,
                "routing contact rejected by duplicate IP limit"
            );
        }
        RoutingError::TableFull { max } => {
            warn!(
                target: "kad_routing",
                contact_id = %contact_id,
                contact_ip = %contact_ip,
                contact_udp_port,
                max = *max,
                "routing table rejected contact because the destination bin is full"
            );
        }
    }
}
