use super::{
    DhtNode,
    contact_helpers::{addr_from_contact, bootstrap_ready_with_contacts},
};
use crate::bootstrap::{BootstrapContact, parse_nodes_text};
use crate::error::DhtError;
use emulebb_kad_net::{NetError, RpcWorkClass};
use emulebb_kad_proto::{KadPacket, KadUdpKey, NodeId, opcode};
use emulebb_kad_routing::Contact;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const BOOTSTRAP_ATTEMPTS_PER_ROUND: usize = 10;

#[derive(Default)]
pub(super) struct BootstrapSweep {
    generation: CancellationToken,
    pending: VecDeque<SocketAddrV4>,
    attempted: HashSet<SocketAddrV4>,
}

impl BootstrapSweep {
    pub(super) fn restart(&mut self) {
        self.generation.cancel();
        *self = Self::default();
    }

    fn plan_round(&mut self, contacts: Vec<BootstrapContact>) -> Vec<BootstrapContact> {
        let mut current = HashMap::with_capacity(contacts.len());
        let mut ordered = Vec::with_capacity(contacts.len());
        for contact in contacts {
            let endpoint = endpoint_of(&contact);
            if let std::collections::hash_map::Entry::Vacant(entry) = current.entry(endpoint) {
                entry.insert(contact);
                ordered.push(endpoint);
            }
        }
        self.pending
            .retain(|endpoint| current.contains_key(endpoint));
        self.attempted
            .retain(|endpoint| current.contains_key(endpoint));
        let queued: HashSet<_> = self.pending.iter().copied().collect();
        for endpoint in ordered {
            if !self.attempted.contains(&endpoint) && !queued.contains(&endpoint) {
                self.pending.push_back(endpoint);
            }
        }
        self.pending
            .iter()
            .take(BOOTSTRAP_ATTEMPTS_PER_ROUND)
            .map(|endpoint| current.remove(endpoint).expect("retained current endpoint"))
            .collect()
    }

    fn claim(&mut self, endpoint: SocketAddrV4) -> bool {
        let Some(position) = self
            .pending
            .iter()
            .position(|candidate| *candidate == endpoint)
        else {
            return false;
        };
        self.pending.remove(position);
        self.attempted.insert(endpoint)
    }
}

fn endpoint_of(contact: &BootstrapContact) -> SocketAddrV4 {
    SocketAddrV4::new(contact.ip, contact.udp_port)
}

impl DhtNode {
    pub(super) fn bootstrap_sweep(&self) -> std::sync::MutexGuard<'_, BootstrapSweep> {
        self.inner
            .bootstrap_sweep
            .lock()
            .expect("bootstrap sweep lock poisoned")
    }

    fn bootstrap_generation(&self) -> Result<CancellationToken, DhtError> {
        let sweep = self.bootstrap_sweep();
        self.check_bootstrap_generation(&sweep.generation)?;
        Ok(sweep.generation.clone())
    }

    fn check_bootstrap_generation(&self, generation: &CancellationToken) -> Result<(), DhtError> {
        if generation.is_cancelled() || !self.is_running() {
            return Err(NetError::KadStopped.into());
        }
        Ok(())
    }

    /// Join through the operator's chosen UDP endpoint, without substituting
    /// configured or hardcoded seeds. Learn its contacts and perform a self lookup.
    pub async fn bootstrap_from_endpoint(&self, endpoint: SocketAddrV4) -> Result<(), DhtError> {
        let generation = self.bootstrap_generation()?;
        let contact = BootstrapContact {
            node_id: NodeId::ZERO,
            ip: *endpoint.ip(),
            udp_port: endpoint.port(),
            tcp_port: 0,
            version: 0,
            udp_key: KadUdpKey::ZERO,
            udp_key_ip: None,
            verified: false,
        };
        if !self
            .bootstrap_contact(&contact, RpcWorkClass::Interactive, &generation)
            .await
        {
            self.check_bootstrap_generation(&generation)?;
            return Err(DhtError::BootstrapFailed);
        }
        self.finish_bootstrap(RpcWorkClass::Interactive, &generation)
            .await
    }

    /// Bootstrap from configured sources. Populates the routing table.
    pub async fn bootstrap(&self) -> Result<(), DhtError> {
        self.bootstrap_with_class(RpcWorkClass::Maintenance).await
    }

    /// Bootstrap from configured sources. Populates the routing table.
    pub async fn bootstrap_with_class(&self, work_class: RpcWorkClass) -> Result<(), DhtError> {
        let generation = self.bootstrap_generation()?;
        let mut contacts = self.load_bootstrap_contacts();

        // eMule `CRoutingZone::Bootstrap` seeds the bootstrap self-lookup from the
        // routing table itself, not only from a separate configured node list. A
        // node restored from `nodes.dat` (contacts already in the table, no
        // configured `nodes_text`) must therefore still bootstrap: fold the live
        // routing-table contacts in as seeds so the self-lookup has live peers to
        // probe. Configured seeds are tried first, table contacts after.
        contacts.extend(self.routing_table_bootstrap_contacts().await);

        let had_candidates = !contacts.is_empty();
        let round = {
            let mut sweep = self.bootstrap_sweep();
            self.check_bootstrap_generation(&generation)?;
            sweep.plan_round(contacts)
        };
        if !had_candidates {
            return Err(DhtError::NoBootstrapNodes);
        }
        if round.is_empty() {
            return Err(DhtError::BootstrapSweepExhausted);
        }
        info!(
            "bootstrapping from {} candidates in this round",
            round.len()
        );
        let mut responded = 0usize;
        for contact in &round {
            let claimed = {
                let mut sweep = self.bootstrap_sweep();
                self.check_bootstrap_generation(&generation)?;
                sweep.claim(endpoint_of(contact))
            };
            if claimed
                && self
                    .bootstrap_contact(contact, work_class, &generation)
                    .await
            {
                responded += 1;
            }
        }

        self.check_bootstrap_generation(&generation)?;
        if responded == 0 {
            return Err(DhtError::BootstrapFailed);
        }
        self.finish_bootstrap(work_class, &generation).await
    }

    async fn finish_bootstrap(
        &self,
        work_class: RpcWorkClass,
        generation: &CancellationToken,
    ) -> Result<(), DhtError> {
        tokio::select! {
            biased;
            _ = generation.cancelled() => return Err(NetError::KadStopped.into()),
            result = self.lookup_nodes_with_class(&self.inner.own_id, work_class) => { result?; }
        }
        let table = self.inner.routing_table.lock().await;
        let _sweep = self.bootstrap_sweep();
        self.check_bootstrap_generation(generation)?;
        let size = table.len();
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

        // Explicitly configured endpoints remain distinct from saved contacts.
        if let Some(ref text) = self.inner.config.nodes_text {
            contacts.extend(parse_nodes_text(text));
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
                udp_key_ip: c.udp_key_ip,
                verified: c.verified,
            })
            .collect()
    }

    async fn bootstrap_contact(
        &self,
        bc: &BootstrapContact,
        work_class: RpcWorkClass,
        generation: &CancellationToken,
    ) -> bool {
        let addr = SocketAddr::new(IpAddr::V4(bc.ip), bc.udp_port);
        {
            let _sweep = self.bootstrap_sweep();
            if self.check_bootstrap_generation(generation).is_err() {
                return false;
            }
            self.register_bootstrap_contact(addr, bc);
        }
        debug!("bootstrap attempt to {}", addr);

        let may_dispatch = || !generation.is_cancelled();
        let response = tokio::select! {
            biased;
            _ = generation.cancelled() => return false,
            response = self.inner.rpc.request_with_class_and_metadata_when(
                addr,
                &KadPacket::BootstrapReq,
                opcode::BOOTSTRAP_RES,
                Duration::from_secs(5),
                work_class,
                &may_dispatch,
            )
            => response.map(|response| response.packet),
        };
        match response {
            Ok(KadPacket::BootstrapRes(res)) => {
                self.add_bootstrap_response_contacts(bc, addr, res, generation)
                    .await
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
        if self.udp_key_matches_public_ip(bc.udp_key, bc.udp_key_ip) {
            self.inner.rpc.register_peer_key(addr, bc.udp_key.value());
        }
    }

    async fn add_bootstrap_response_contacts(
        &self,
        bc: &BootstrapContact,
        addr: SocketAddr,
        res: emulebb_kad_proto::packet::BootstrapRes,
        generation: &CancellationToken,
    ) -> bool {
        let mut rt = self.inner.routing_table.lock().await;
        let _sweep = self.bootstrap_sweep();
        if self.check_bootstrap_generation(generation).is_err() {
            return false;
        }
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
            sender_contact.udp_key_ip = self.public_ip_for_udp_keys();
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
        debug!(
            "bootstrap response from {} - routing table now {} contacts",
            addr,
            rt.len()
        );
        true
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
    use crate::{DhtConfig, DhtError, DhtNode};
    use emulebb_kad_proto::{
        KadPacket, NodeId,
        constants::KADEMLIA_FIND_NODE,
        packet::{BootstrapRes, Res as KadRes},
    };
    use emulebb_kad_routing::Contact;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    #[test]
    fn bootstrap_sweep_keeps_pending_endpoints_across_reorder_and_replacement() {
        let mut sweep = super::BootstrapSweep::default();
        let mut round_ports = |ports: Vec<u16>| {
            let endpoints = ports
                .iter()
                .map(|port| format!("192.0.2.20:{port}"))
                .collect::<Vec<_>>()
                .join("\n");
            let round = sweep.plan_round(super::parse_nodes_text(&endpoints));
            for contact in &round {
                assert!(sweep.claim(super::endpoint_of(contact)));
            }
            round
                .iter()
                .map(|contact| contact.udp_port)
                .collect::<Vec<_>>()
        };
        let original: Vec<_> = (4600..4621).collect();
        assert_eq!(round_ports(original), (4600..4610).collect::<Vec<_>>());
        // Move 4610 before the old cursor and replace 4611 at the same count.
        let mut changed: Vec<_> = (4600..4621).filter(|port| *port != 4611).collect();
        changed.swap(0, 10);
        changed.insert(1, 4621);
        let expected: Vec<_> = (4610..4621).filter(|port| *port != 4611).collect();
        assert_eq!(round_ports(changed.clone()), expected);
        assert_eq!(round_ports(changed.clone()), vec![4621]);
        assert!(round_ports(changed.clone()).is_empty());
        changed.reverse();
        assert!(round_ports(changed.clone()).is_empty());
        changed.push(4622);
        assert_eq!(round_ports(changed), vec![4622]);
        assert!(round_ports(Vec::new()).is_empty());
        assert_eq!(round_ports(vec![4621]), vec![4621]);
    }

    async fn receive_kad_packet(socket: &UdpSocket) -> (KadPacket, SocketAddr) {
        let mut buffer = [0; 512];
        let (length, sender) =
            tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
                .await
                .expect("expected a Kad packet")
                .unwrap();
        (KadPacket::decode(&buffer[..length]).unwrap(), sender)
    }

    #[tokio::test]
    async fn pausing_bootstrap_discards_the_inflight_round_and_rearms_on_resume() {
        let bind_addr = (crate::test_bind_ip(), 0);
        let first = UdpSocket::bind(bind_addr).await.unwrap();
        let second = UdpSocket::bind(bind_addr).await.unwrap();
        let nodes_text = format!(
            "{}\n{}",
            first.local_addr().unwrap(),
            second.local_addr().unwrap()
        );
        let node = DhtNode::new(DhtConfig {
            bind_addr: Some(bind_addr.into()),
            nodes_text: Some(nodes_text),
            obfuscation_enabled: false,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let receive_loop = node.start();
        let round = tokio::spawn({
            let node = node.clone();
            async move { node.bootstrap().await }
        });
        assert!(matches!(
            receive_kad_packet(&first).await.0,
            KadPacket::BootstrapReq
        ));
        node.set_running(false);
        assert!(matches!(
            node.bootstrap().await,
            Err(DhtError::Net(emulebb_kad_net::NetError::KadStopped))
        ));
        node.set_running(true);
        assert!(matches!(
            round.await.unwrap(),
            Err(DhtError::Net(emulebb_kad_net::NetError::KadStopped))
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), second.readable())
                .await
                .is_err()
        );

        let resumed = tokio::spawn({
            let node = node.clone();
            async move { node.bootstrap().await }
        });
        assert!(matches!(
            receive_kad_packet(&first).await.0,
            KadPacket::BootstrapReq
        ));
        node.set_running(false);
        assert!(matches!(
            resumed.await.unwrap(),
            Err(DhtError::Net(emulebb_kad_net::NetError::KadStopped))
        ));
        receive_loop.abort();
    }

    #[tokio::test]
    async fn bootstrap_reaches_eleventh_candidate_and_looks_up_own_id() {
        let bind_addr = (crate::test_bind_ip(), 0);
        let mut silent = Vec::new();
        for _ in 0..10 {
            silent.push(UdpSocket::bind(bind_addr).await.unwrap());
        }
        let responder = UdpSocket::bind(bind_addr).await.unwrap();
        let nodes_text = silent
            .iter()
            .chain(std::iter::once(&responder))
            .map(|peer| peer.local_addr().unwrap().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(bind_addr.into()),
            nodes_text: Some(nodes_text),
            obfuscation_enabled: false,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let receive_loop = dht.start();

        // Silent peers require only outbound datagrams and timeouts. Use real
        // time again before the round that depends on inbound socket readiness.
        tokio::time::pause();
        let first_round = dht.bootstrap().await;
        tokio::time::resume();
        assert!(matches!(first_round, Err(DhtError::BootstrapFailed)));
        for peer in &silent {
            let (packet, _) = receive_kad_packet(peer).await;
            assert!(matches!(packet, KadPacket::BootstrapReq));
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), responder.readable())
                .await
                .is_err(),
            "the eleventh candidate must be reserved for the next round"
        );

        let responder_id = NodeId::from_bytes([0x42; 16]);
        let (second_round, ()) = tokio::join!(dht.bootstrap(), async {
            let (packet, dht_addr) = receive_kad_packet(&responder).await;
            assert!(matches!(packet, KadPacket::BootstrapReq));
            let response = KadPacket::BootstrapRes(BootstrapRes {
                sender_id: responder_id,
                sender_tcp_port: 4662,
                sender_version: 9,
                contacts: Vec::new(),
            });
            responder
                .send_to(&response.encode().unwrap(), dht_addr)
                .await
                .unwrap();

            let (packet, sender) = receive_kad_packet(&responder).await;
            assert_eq!(sender, dht_addr);
            let KadPacket::Req(request) = packet else {
                panic!("bootstrap response must be followed by a node lookup");
            };
            assert_eq!(request.count, KADEMLIA_FIND_NODE);
            assert_eq!(request.target, dht.own_id());
            assert_eq!(request.recipient_id, responder_id);
            let response = KadPacket::Res(KadRes {
                target: request.target,
                contacts: Vec::new(),
            });
            responder
                .send_to(&response.encode().unwrap(), dht_addr)
                .await
                .unwrap();
        });
        second_round.unwrap();
        assert!(matches!(
            dht.bootstrap().await,
            Err(DhtError::BootstrapSweepExhausted)
        ));
        receive_loop.abort();
    }

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

    #[tokio::test]
    async fn empty_table_has_no_hidden_seeds_but_explicit_endpoints_remain() {
        let empty = empty_node().await;
        assert!(empty.load_bootstrap_contacts().is_empty());
        let configured = DhtNode::new(DhtConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            nodes_text: Some("192.0.2.20:4672".into()),
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let seeds = configured.load_bootstrap_contacts();
        assert_eq!(seeds.len(), 1);
        assert_eq!(
            seeds[0].ip,
            "192.0.2.20".parse::<std::net::Ipv4Addr>().unwrap()
        );
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
