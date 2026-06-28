use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use chrono::Utc;
use emulebb_index::{KadLocalStore, KadLocalStoreConfig};
use emulebb_kad_dht::{DhtConfig, DhtNode};
use emulebb_kad_proto::{
    BootstrapRes, ContactEntry, KAD_VERSION, KadPacket, NodeId, Pong, PublishRes, Res, constants::K,
};
use emulebb_kad_routing::Contact;
use tokio::{sync::Mutex, task::JoinHandle};

use super::fixtures::node_id;

const SEARCH_RESPONSE_LIMIT: usize = 50;

pub struct LocalKadSwarm {
    bind_ip: Ipv4Addr,
    pub nodes: Vec<LocalKadNode>,
}

impl LocalKadSwarm {
    pub async fn new() -> Self {
        Self {
            bind_ip: lan_bind_ip(),
            nodes: Vec::new(),
        }
    }

    pub async fn with_star_topology(count: u8) -> Self {
        let mut swarm = Self::new().await;
        for index in 0..count {
            swarm.add_seed(index + 1).await;
        }
        swarm.seed_star_contacts().await;
        swarm
    }

    pub fn bind_ip(&self) -> Ipv4Addr {
        self.bind_ip
    }

    pub async fn add_seed(&mut self, id_byte: u8) -> usize {
        let node = LocalKadNode::start(self.bind_ip, node_id(id_byte), None).await;
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    pub async fn add_bootstrap_node(&mut self, id_byte: u8, seed_index: usize) -> usize {
        let seed_addr = self.nodes[seed_index].addr;
        let nodes_text = Some(format!("{}:{}", self.bind_ip, seed_addr.port()));
        let node = LocalKadNode::start(self.bind_ip, node_id(id_byte), nodes_text).await;
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    async fn seed_star_contacts(&self) {
        let Some(seed) = self.nodes.first() else {
            return;
        };
        let seed_contact = seed.contact();
        for node in self.nodes.iter().skip(1) {
            node.dht
                .add_contact(seed_contact.clone())
                .await
                .expect("seed contact");
        }
    }
}

pub struct LocalKadNode {
    pub dht: DhtNode,
    pub addr: SocketAddr,
    rpc_task: JoinHandle<()>,
    handler_task: JoinHandle<()>,
}

impl LocalKadNode {
    async fn start(bind_ip: Ipv4Addr, own_id: NodeId, nodes_text: Option<String>) -> Self {
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(SocketAddr::new(IpAddr::V4(bind_ip), 0)),
            node_id: own_id,
            bootstrap_min_routing_contacts: 1,
            search_timeout: Duration::from_secs(5),
            publish_contact_fanout: 4,
            max_outbound_pps: 0,
            search_phase2_fanout: 4,
            obfuscation_enabled: false,
            nodes_text,
            ..DhtConfig::default()
        })
        .await
        .expect("create local Kad node");
        let addr = dht.bind_addr().expect("local Kad bind address");
        assert_eq!(addr.ip(), IpAddr::V4(bind_ip));

        let rpc_task = dht.start();
        let store = Arc::new(Mutex::new(KadLocalStore::new(KadLocalStoreConfig {
            enabled: true,
            ..KadLocalStoreConfig::default()
        })));
        let handler_task = spawn_handler(dht.clone(), Arc::clone(&store));

        Self {
            dht,
            addr,
            rpc_task,
            handler_task,
        }
    }

    fn contact(&self) -> Contact {
        let IpAddr::V4(ip) = self.addr.ip() else {
            panic!("local Kad test node must use IPv4");
        };
        Contact::new(
            self.dht.own_id(),
            ip,
            self.addr.port(),
            self.addr.port(),
            KAD_VERSION,
        )
    }
}

impl Drop for LocalKadNode {
    fn drop(&mut self) {
        self.handler_task.abort();
        self.rpc_task.abort();
    }
}

fn spawn_handler(dht: DhtNode, store: Arc<Mutex<KadLocalStore>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut packets = dht.subscribe_packets();
        while let Ok(received) = packets.recv().await {
            handle_packet(&dht, &store, received.packet, received.from).await;
        }
    })
}

async fn handle_packet(
    dht: &DhtNode,
    store: &Arc<Mutex<KadLocalStore>>,
    packet: KadPacket,
    from: SocketAddr,
) {
    match packet {
        KadPacket::BootstrapReq => {
            let contacts = contact_entries(dht, &dht.own_id(), K).await;
            let _ = dht
                .send_packet(
                    from,
                    &KadPacket::BootstrapRes(BootstrapRes {
                        sender_id: dht.own_id(),
                        sender_tcp_port: dht.bind_addr().map(|addr| addr.port()).unwrap_or(0),
                        sender_version: KAD_VERSION,
                        contacts,
                    }),
                )
                .await;
        }
        KadPacket::Req(req) => {
            if req.recipient_id != dht.own_id() {
                return;
            }
            let contacts = contact_entries(dht, &req.target, usize::from(req.count)).await;
            let _ = dht
                .send_packet(
                    from,
                    &KadPacket::Res(Res {
                        target: req.target,
                        contacts,
                    }),
                )
                .await;
        }
        KadPacket::SearchKeyReq(req) => {
            let response = store.lock().await.keyword_search_response(
                dht.own_id(),
                &req,
                SEARCH_RESPONSE_LIMIT,
                Utc::now(),
            );
            send_search_response(dht, from, response).await;
        }
        KadPacket::SearchSourceReq(req) => {
            let response = store.lock().await.source_search_response(
                dht.own_id(),
                &req,
                SEARCH_RESPONSE_LIMIT,
                Utc::now(),
            );
            send_search_response(dht, from, response).await;
        }
        KadPacket::SearchNotesReq(req) => {
            let response = store.lock().await.notes_search_response(
                dht.own_id(),
                &req,
                SEARCH_RESPONSE_LIMIT,
                Utc::now(),
            );
            send_search_response(dht, from, response).await;
        }
        KadPacket::PublishKeyReq(req) => {
            let load = store.lock().await.record_keyword_publish_batch(
                req.target,
                &req.entries,
                Utc::now(),
            );
            send_publish_response(dht, from, req.target, load).await;
        }
        KadPacket::PublishSourceReq(req) => {
            let IpAddr::V4(source_ip) = from.ip() else {
                return;
            };
            let load = store.lock().await.record_source_publish(
                req.target,
                req.publisher_id,
                source_ip,
                from.port(),
                &req.tags,
                Utc::now(),
            );
            if let Some(load) = load {
                send_publish_response(dht, from, req.target, load).await;
            }
        }
        KadPacket::PublishNotesReq(req) => {
            let IpAddr::V4(publisher_ip) = from.ip() else {
                return;
            };
            let load = store.lock().await.record_notes_publish(
                req.target,
                req.publisher_id,
                publisher_ip,
                &req.tags,
                Utc::now(),
            );
            if let Some(load) = load {
                send_publish_response(dht, from, req.target, load).await;
            }
        }
        KadPacket::Ping => {
            let _ = dht
                .send_packet(
                    from,
                    &KadPacket::Pong(Pong {
                        udp_port: dht.bind_addr().map(|addr| addr.port()).unwrap_or(0),
                    }),
                )
                .await;
        }
        _ => {}
    }
}

async fn contact_entries(dht: &DhtNode, target: &NodeId, limit: usize) -> Vec<ContactEntry> {
    dht.closest_contacts(target, limit)
        .await
        .into_iter()
        .map(|contact| ContactEntry {
            node_id: contact.id,
            ip: u32::from_be_bytes(contact.ip.octets()),
            udp_port: contact.udp_port,
            tcp_port: contact.tcp_port,
            version: contact.kad_version,
        })
        .collect()
}

async fn send_search_response(
    dht: &DhtNode,
    to: SocketAddr,
    response: Option<emulebb_kad_proto::SearchRes>,
) {
    if let Some(response) = response {
        let _ = dht.send_packet(to, &KadPacket::SearchRes(response)).await;
    }
}

async fn send_publish_response(dht: &DhtNode, to: SocketAddr, target: NodeId, load: u8) {
    let _ = dht
        .send_packet(
            to,
            &KadPacket::PublishRes(PublishRes {
                target,
                load,
                options: None,
            }),
        )
        .await;
}

fn lan_bind_ip() -> Ipv4Addr {
    let raw =
        std::env::var("X_LOCAL_IP").expect("X_LOCAL_IP must be set for local Kad swarm tests");
    let ip = raw
        .parse::<Ipv4Addr>()
        .expect("X_LOCAL_IP must be an IPv4 address");
    assert!(
        !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast(),
        "X_LOCAL_IP must be a LAN IPv4 address, got {ip}"
    );
    ip
}
