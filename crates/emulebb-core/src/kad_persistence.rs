//! Typed conversion between Kad routing evidence and its SQLite representation.

use emulebb_kad_dht::RoutingSnapshotContact;
use emulebb_kad_proto::{KadUdpKey, NodeId};
use emulebb_kad_routing::ContactType;
use emulebb_metadata::{KadRoutingContact, KadRoutingContactType};
use std::net::Ipv4Addr;

pub(crate) fn from_metadata(c: &KadRoutingContact) -> RoutingSnapshotContact {
    RoutingSnapshotContact {
        node_id: NodeId::from_bytes(c.node_id),
        ip: Ipv4Addr::from(c.ip),
        udp_port: c.udp_port,
        tcp_port: c.tcp_port,
        version: c.version,
        udp_key: KadUdpKey::new(c.udp_key),
        udp_key_ip: c.udp_key_ip.map(Ipv4Addr::from),
        hello_source_udp_port: c.hello_source_udp_port,
        udp_firewalled: c.udp_firewalled,
        tcp_firewalled: c.tcp_firewalled,
        requests_hello_res_ack: c.requests_hello_res_ack,
        received_hello_packet: c.received_hello_packet,
        verified: c.verified,
        contact_type: match c.contact_type {
            KadRoutingContactType::Active => ContactType::Active,
            KadRoutingContactType::Inactive => ContactType::Inactive,
            KadRoutingContactType::Dead => ContactType::Dead,
        },
        probe_type: c.probe_type,
        bootstrap: c.bootstrap,
        expires_at_seconds: c.expires_at_seconds,
        last_type_set_at_seconds: c.last_type_set_at_seconds,
        last_seen_at_seconds: c.last_seen_at_seconds,
        created_at_seconds: c.created_at_seconds,
    }
}

pub(crate) fn to_metadata(c: &RoutingSnapshotContact) -> KadRoutingContact {
    KadRoutingContact {
        node_id: c.node_id.0,
        ip: u32::from(c.ip),
        udp_port: c.udp_port,
        tcp_port: c.tcp_port,
        version: c.version,
        udp_key: c.udp_key.value(),
        udp_key_ip: c.udp_key_ip.map(u32::from),
        hello_source_udp_port: c.hello_source_udp_port,
        udp_firewalled: c.udp_firewalled,
        tcp_firewalled: c.tcp_firewalled,
        requests_hello_res_ack: c.requests_hello_res_ack,
        received_hello_packet: c.received_hello_packet,
        verified: c.verified,
        contact_type: match c.contact_type {
            ContactType::Active => KadRoutingContactType::Active,
            ContactType::Inactive => KadRoutingContactType::Inactive,
            ContactType::Dead => KadRoutingContactType::Dead,
        },
        probe_type: c.probe_type,
        bootstrap: c.bootstrap,
        expires_at_seconds: c.expires_at_seconds,
        last_type_set_at_seconds: c.last_type_set_at_seconds,
        last_seen_at_seconds: c.last_seen_at_seconds,
        created_at_seconds: c.created_at_seconds,
    }
}
