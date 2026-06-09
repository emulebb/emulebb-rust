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
        let contacts = self.load_bootstrap_contacts();

        if contacts.is_empty() {
            return Err(DhtError::NoBootstrapNodes);
        }

        info!("bootstrapping from {} contacts", contacts.len());

        let mut responded = 0usize;

        // Send BOOTSTRAP_REQ to up to 10 contacts
        for bc in contacts.iter().take(10) {
            let addr = SocketAddr::new(IpAddr::V4(bc.ip), bc.udp_port);
            if bc.node_id != NodeId::ZERO {
                self.inner.rpc.register_peer_identity(addr, bc.node_id);
            }
            self.inner.rpc.register_peer_version(addr, bc.version);
            if bc.udp_key != KadUdpKey::ZERO {
                self.inner.rpc.register_peer_key(addr, bc.udp_key.value());
            }
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
                    responded += 1;
                    let mut rt = self.inner.routing_table.lock().await;
                    let mut sender_contact = Contact::new(
                        res.sender_id,
                        bc.ip,
                        bc.udp_port,
                        res.sender_tcp_port,
                        res.sender_version,
                    );
                    if let Some(known_udp_key) = self.known_peer_key(addr) {
                        sender_contact.udp_key = known_udp_key;
                    }
                    let _ = rt.add_contact(sender_contact);
                    for entry in res.contacts {
                        if entry.ip == 0 || entry.udp_port == 0 {
                            continue;
                        }
                        let contact = Contact::new(
                            entry.node_id,
                            entry.ip_addr(),
                            entry.udp_port,
                            entry.tcp_port,
                            entry.version,
                        );
                        self.inner
                            .rpc
                            .register_peer_identity(addr_from_contact(&contact), contact.id);
                        self.inner.rpc.register_peer_version(
                            addr_from_contact(&contact),
                            contact.kad_version,
                        );
                        let _ = rt.add_contact(contact);
                    }
                    info!(
                        "bootstrap response from {} - routing table now {} contacts",
                        addr,
                        rt.len()
                    );
                }
                Ok(_) => warn!("unexpected packet type during bootstrap from {}", addr),
                Err(e) => debug!("bootstrap contact {} failed: {}", addr, e),
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
}
