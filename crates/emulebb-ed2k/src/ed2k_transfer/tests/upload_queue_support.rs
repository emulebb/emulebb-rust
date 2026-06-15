use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use crate::ed2k_transfer::{Ed2kUploadPeerIdentity, Ed2kUploadQueueConfig};

pub(super) fn one_slot_config() -> Ed2kUploadQueueConfig {
    Ed2kUploadQueueConfig {
        active_slots: 1,
        elastic_percent: 0,
        upload_limit_bytes_per_sec: 0,
        elastic_underfill_bytes_per_sec: 0,
        elastic_underfill: Duration::from_secs(10),
        waiting_capacity: 8,
        soft_queue_size: 10_000,
        waiting_timeout: Duration::from_secs(30),
        granted_timeout: Duration::from_secs(30),
        upload_timeout: Duration::from_secs(30),
    }
}

pub(super) fn upload_peer(octet: u8, user_marker: u8, client_id: u32) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)),
        tcp_port: 4660 + u16::from(octet),
        udp_port: None,
        udp_version: 0,
        should_crypt: false,
        user_hash: Some([user_marker; 16]),
        client_id: Some(client_id),
        friend_slot: false,
    }
}
