use super::{
    DhtNode,
    contact_helpers::{addr_from_contact, bootstrap_ready_with_contacts},
};
use crate::bootstrap::{BootstrapContact, hardcoded_bootstrap, parse_nodes_dat, parse_nodes_text};
use crate::error::DhtError;
use emulebb_kad_net::RpcWorkClass;
use emulebb_kad_proto::{KadPacket, KadUdpKey, NodeId, opcode};
use emulebb_kad_routing::Contact;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing::{debug, info, warn};

impl DhtNode {
    /// Bootstrap from configured sources. Populates the routing table.
    pub async fn bootstrap(&self) -> Result<(), DhtError> {
        self.bootstrap_with_class(RpcWorkClass::Maintenance).await
    }

    /// Bootstrap from configured sources. Populates the routing table.
    pub async fn bootstrap_with_class(&self, work_class: RpcWorkClass) -> Result<(), DhtError> {
        let mut contacts = self.load_bootstrap_contacts();

        // eMule `CRoutingZone::Bootstrap` seeds the bootstrap self-lookup from the
        // routing table itself, not only from a separate configured node list. A
        // node restored from `nodes.dat` (contacts already in the table, no
        // configured `nodes_text`) must therefore still bootstrap: fold the live
        // routing-table contacts in as seeds so the self-lookup has live peers to
        // probe. Configured/hardcoded seeds are tried first, table contacts after.
        contacts.extend(self.routing_table_bootstrap_contacts().await);

        if contacts.is_empty() {
            return Err(DhtError::NoBootstrapNodes);
        }

        info!("bootstrapping from {} contacts", contacts.len());

        let mut responded = 0usize;

        // Send BOOTSTRAP_REQ to up to 10 contacts
        for bc in contacts.iter().take(10) {
            if self.bootstrap_contact(bc, work_class).await {
                responded += 1;
            }
        }

        if responded == 0 {
            return Err(DhtError::BootstrapFailed);
        }

        // Run node lookup for own ID to fill routing table
        self.lookup_nodes_with_class(&self.inner.own_id, work_class)
            .await?;

        let size = self.inner.routing_table.lock().await.len();
        info!("bootstrap complete - routing table has {} contacts", size);

        if bootstrap_ready_with_contacts(self.inner.config.bootstrap_min_routing_contacts, size) {
            self.inner
                .bootstrapped
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        Ok(())
    }

    fn load_bootstrap_contacts(&self) -> Vec<BootstrapContact> {
        let mut contacts = Vec::new();

        // 1. nodes.dat binary
        if let Some(ref data) = self.inner.config.nodes_dat {
            match parse_nodes_dat(data) {
                Ok(c) => contacts.extend(c),
                Err(e) => warn!("failed to parse nodes.dat: {}", e),
            }
        }

        // 2. Text format
        if let Some(ref text) = self.inner.config.nodes_text {
            contacts.extend(parse_nodes_text(text));
        }

        // 3. Hardcoded fallback
        if contacts.is_empty() {
            contacts.extend(hardcoded_bootstrap());
        }

        contacts
    }

    /// Bootstrap seeds taken from the live routing table (oracle
    /// `CRoutingZone::Bootstrap`, which walks the tree for bootstrap candidates).
    /// These are the contacts restored from `nodes.dat` or learned at runtime;
    /// folding them into the bootstrap seed set lets a node with a populated table
    /// but no configured `nodes_text` still run the bootstrap self-lookup.
    pub(crate) async fn routing_table_bootstrap_contacts(&self) -> Vec<BootstrapContact> {
        self.inner
            .routing_table
            .lock()
            .await
            .all_contacts()
            .into_iter()
            .filter(|c| c.udp_port != 0)
            .map(|c| BootstrapContact {
                node_id: c.id,
                ip: c.ip,
                udp_port: c.udp_port,
                tcp_port: c.tcp_port,
                version: c.kad_version,
                udp_key: c.udp_key,
            })
            .collect()
    }

    async fn bootstrap_contact(&self, bc: &BootstrapContact, work_class: RpcWorkClass) -> bool {
        let addr = SocketAddr::new(IpAddr::V4(bc.ip), bc.udp_port);
        self.register_bootstrap_contact(addr, bc);
        debug!("bootstrap attempt to {}", addr);

        match self
            .inner
            .rpc
            .request_with_class(
                addr,
                &KadPacket::BootstrapReq,
                opcode::BOOTSTRAP_RES,
                Duration::from_secs(5),
                work_class,
            )
            .await
        {
            Ok(KadPacket::BootstrapRes(res)) => {
                self.add_bootstrap_response_contacts(bc, addr, res).await;
                true
            }
            Ok(_) => {
                warn!("unexpected packet type during bootstrap from {}", addr);
                false
            }
            Err(e) => {
                debug!("bootstrap contact {} failed: {}", addr, e);
                false
            }
        }
    }

    fn register_bootstrap_contact(&self, addr: SocketAddr, bc: &BootstrapContact) {
        if bc.node_id != NodeId::ZERO {
            self.inner.rpc.register_peer_identity(addr, bc.node_id);
        }
        self.inner.rpc.register_peer_version(addr, bc.version);
        if bc.udp_key != KadUdpKey::ZERO {
            self.inner.rpc.register_peer_key(addr, bc.udp_key.value());
        }
    }

    async fn add_bootstrap_response_contacts(
        &self,
        bc: &BootstrapContact,
        addr: SocketAddr,
        res: emulebb_kad_proto::packet::BootstrapRes,
    ) {
        let mut rt = self.inner.routing_table.lock().await;
        let mut sender_contact = Contact::new(
            res.sender_id,
            bc.ip,
            bc.udp_port,
            res.sender_tcp_port,
            res.sender_version,
        );
        // This is the bootstrap node that answered our BootstrapReq (reachable),
        // so flag it for the oracle +10 bootstrap quality bonus
        // (Contact.cpp:293-294). The contacts it returns below are ordinary
        // learned peers, not bootstrap nodes, and stay unflagged.
        sender_contact.bootstrap = true;
        if let Some(known_udp_key) = self.known_peer_key(addr) {
            sender_contact.udp_key = known_udp_key;
        }
        if rt.add_contact(sender_contact).is_ok() {
            // kad_event bootstrap milestone bootstrap_contact_added (§3.3).
            emulebb_kad_net::diag_event::kad_event_bootstrap_contact_added(SocketAddr::new(
                IpAddr::V4(bc.ip),
                bc.udp_port,
            ));
        }
        for contact in res.contacts.into_iter().filter_map(bootstrap_contact_entry) {
            let contact_addr = addr_from_contact(&contact);
            self.inner
                .rpc
                .register_peer_identity(contact_addr, contact.id);
            self.inner
                .rpc
                .register_peer_version(contact_addr, contact.kad_version);
            if rt.add_contact(contact).is_ok() {
                // kad_event bootstrap milestone bootstrap_contact_added (§3.3).
                emulebb_kad_net::diag_event::kad_event_bootstrap_contact_added(contact_addr);
            }
        }
        info!(
            "bootstrap response from {} - routing table now {} contacts",
            addr,
            rt.len()
        );
    }
}

fn bootstrap_contact_entry(entry: emulebb_kad_proto::packet::ContactEntry) -> Option<Contact> {
    if entry.ip == 0 || entry.udp_port == 0 {
        return None;
    }
    Some(Contact::new(
        entry.node_id,
        entry.ip_addr(),
        entry.udp_port,
        entry.tcp_port,
        entry.version,
    ))
}

#[cfg(test)]
mod tests {
    use crate::{DhtConfig, DhtNode};
    use emulebb_kad_proto::NodeId;
    use emulebb_kad_routing::Contact;

    async fn empty_node() -> DhtNode {
        DhtNode::new(DhtConfig {
            bind_addr: Some(std::net::SocketAddr::new(
                std::net::IpAddr::V4(crate::test_bind_ip()),
                0,
            )),
            ..DhtConfig::default()
        })
        .await
        .unwrap()
    }

    /// A node restored from `nodes.dat` (contacts already in the routing table,
    /// no configured `nodes_text`) must surface those contacts as bootstrap
    /// seeds, so the bootstrap self-lookup has live peers to probe. Regression
    /// guard for the dormant-bootstrap bug where a nodes.dat-only node never
    /// bootstrapped because seeds were only drawn from the configured list.
    #[tokio::test]
    async fn routing_table_contacts_are_offered_as_bootstrap_seeds() {
        let dht = empty_node().await;
        assert!(dht.routing_table_bootstrap_contacts().await.is_empty());

        let contact = Contact::new(
            NodeId::from_bytes([0x33; 16]),
            "203.0.113.10".parse().unwrap(),
            4672,
            4662,
            10,
        );
        dht.add_contact(contact).await.unwrap();

        let seeds = dht.routing_table_bootstrap_contacts().await;
        assert_eq!(seeds.len(), 1);
        assert_eq!(
            seeds[0].ip,
            "203.0.113.10".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(seeds[0].udp_port, 4672);
        assert_eq!(seeds[0].tcp_port, 4662);
        assert_eq!(seeds[0].version, 10);
    }
}
