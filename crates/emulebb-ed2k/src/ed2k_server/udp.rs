use std::net::{IpAddr, SocketAddr};

use md5::compute as md5_compute;
use rand::RngExt;

use super::obfuscation::Rc4KeyStream;
use super::{
    EMULE_UDP_CRYPT_HEADER_LEN, EMULE_UDP_CRYPT_MAGIC_CLIENT_SERVER,
    EMULE_UDP_CRYPT_MAGIC_SERVER_CLIENT, EMULE_UDP_CRYPT_MAGIC_SYNC_SERVER, OP_EDONKEYPROT,
    ResolvedServerEntry,
};

pub(super) fn server_udp_endpoint(server: &ResolvedServerEntry) -> SocketAddr {
    let port = if should_obfuscate_server_udp(server) {
        if server.entry.obfuscation_port_udp != 0 {
            server.entry.obfuscation_port_udp
        } else if server.entry.port <= u16::MAX - 12 {
            server.entry.port + 12
        } else {
            server.entry.port
        }
    } else if server.entry.port <= u16::MAX - 4 {
        server.entry.port + 4
    } else {
        server.entry.port
    };
    SocketAddr::new(IpAddr::V4(server.ip), port)
}

pub(super) fn encode_server_udp_datagram(
    server: &ResolvedServerEntry,
    opcode: u8,
    payload: &[u8],
) -> (SocketAddr, Vec<u8>) {
    let mut plain = Vec::with_capacity(2 + payload.len());
    plain.push(OP_EDONKEYPROT);
    plain.push(opcode);
    plain.extend_from_slice(payload);
    if !should_obfuscate_server_udp(server) {
        return (server_udp_endpoint(server), plain);
    }

    let random_key_part = rand::rng().random::<u16>();
    let mut packet = Vec::with_capacity(EMULE_UDP_CRYPT_HEADER_LEN + plain.len());
    packet.push(random_non_ed2k_udp_marker());
    packet.extend_from_slice(&random_key_part.to_le_bytes());
    packet.extend_from_slice(&EMULE_UDP_CRYPT_MAGIC_SYNC_SERVER.to_le_bytes());
    packet.push(0);
    packet.extend_from_slice(&plain);
    let mut cipher = derive_server_udp_cipher(
        server.entry.udp_key,
        random_key_part,
        EMULE_UDP_CRYPT_MAGIC_CLIENT_SERVER,
    );
    cipher.apply(&mut packet[3..]);
    (server_udp_endpoint(server), packet)
}

pub(super) fn decode_server_udp_datagram(
    server: &ResolvedServerEntry,
    packet: &[u8],
) -> Option<Vec<u8>> {
    if packet.first().copied() == Some(OP_EDONKEYPROT) {
        return Some(packet.to_vec());
    }
    if !should_obfuscate_server_udp(server) || packet.len() <= EMULE_UDP_CRYPT_HEADER_LEN {
        return None;
    }

    let random_key_part = u16::from_le_bytes([packet[1], packet[2]]);
    let mut decrypted = packet[3..].to_vec();
    let mut cipher = derive_server_udp_cipher(
        server.entry.udp_key,
        random_key_part,
        EMULE_UDP_CRYPT_MAGIC_SERVER_CLIENT,
    );
    cipher.apply(&mut decrypted);
    if decrypted.len() < 5 {
        return None;
    }
    let magic = u32::from_le_bytes(decrypted[..4].try_into().ok()?);
    if magic != EMULE_UDP_CRYPT_MAGIC_SYNC_SERVER {
        return None;
    }
    let padding_len = usize::from(decrypted[4] & 0x0F);
    let payload_offset = 5usize.checked_add(padding_len)?;
    if decrypted.len() <= payload_offset {
        return None;
    }
    Some(decrypted[payload_offset..].to_vec())
}

pub(super) fn derive_server_udp_cipher(
    server_udp_key: u32,
    random_key_part: u16,
    magic: u8,
) -> Rc4KeyStream {
    let mut key_material = Vec::with_capacity(7);
    key_material.extend_from_slice(&server_udp_key.to_le_bytes());
    key_material.push(magic);
    key_material.extend_from_slice(&random_key_part.to_le_bytes());
    Rc4KeyStream::new_without_discard(&md5_compute(key_material).0)
}

fn should_obfuscate_server_udp(server: &ResolvedServerEntry) -> bool {
    server.entry.udp_key != 0 && server.entry.supports_obfuscation_udp()
}

fn random_non_ed2k_udp_marker() -> u8 {
    loop {
        let marker = rand::rng().random::<u8>();
        if marker != OP_EDONKEYPROT {
            return marker;
        }
    }
}
