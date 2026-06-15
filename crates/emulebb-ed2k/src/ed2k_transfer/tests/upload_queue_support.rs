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
        // Verified ident by default so credit-scoring fixtures exercise the real
        // ratio math; A4 has a dedicated test for the unverified neutral path.
        ident_verified: true,
        ident_bad_guy: false,
        gpl_evildoer: false,
        banned: false,
        // Modern mule client by default (not old-client penalised).
        emule_version: 0x99,
        is_emule_client: true,
        kad_port: 0,
        firewall_context: Default::default(),
    }
}

/// A peer on a fixed shared IP with a distinct port and user hash, used to
/// exercise the per-IP waiter cap (master `cSameIP`).
pub(super) fn same_ip_upload_peer(port_marker: u8) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        ip: IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)),
        tcp_port: 5000 + u16::from(port_marker),
        udp_port: None,
        udp_version: 0,
        should_crypt: false,
        user_hash: Some([port_marker; 16]),
        client_id: Some(0x0A09_0900 + u32::from(port_marker)),
        friend_slot: false,
        ident_verified: true,
        ident_bad_guy: false,
        gpl_evildoer: false,
        banned: false,
        emule_version: 0x99,
        is_emule_client: true,
        kad_port: 0,
        firewall_context: Default::default(),
    }
}

/// Like [`upload_peer`] but with the secure-ident verification state spelled out,
/// so a test can model an unverified (spoofable) peer whose credit ratio must
/// stay neutral (eMule `GetScoreRatio` IS_IDENTIFIED gating).
pub(super) fn upload_peer_with_ident(
    octet: u8,
    user_marker: u8,
    client_id: u32,
    ident_verified: bool,
) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        ident_verified,
        ..upload_peer(octet, user_marker, client_id)
    }
}
